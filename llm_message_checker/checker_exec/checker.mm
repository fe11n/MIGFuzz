/* 
Copyright 2025 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include "../../harness.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <cstdint>
#include <cstring>

// Global variables
unsigned char *shm_data = NULL;
int verbose = 0;
int print_bytes_only = 0;
const char *verbose_log_file = NULL;
t_Dispatch_Routine Dispatch_Routines[MAX_SUBSYSTEMS_NUM] = {0};
int subsystem_count = 0;
t_ServerStarter ServerStarter = NULL;
std::vector<uint8_t> safari_audit_token;
Service *target_service = NULL;

// Message checker function
int check_message(uint32_t msg_id, const uint8_t* data, size_t size) {
    FuzzedDataProvider fuzz_data(data, size);
    
    verbose_print("\n*******CHECKING MESSAGE ID: %u*******\n", msg_id);

    // 根据消息ID选择对应的子系统
    int chosen_subsystem = 0;
    if (subsystem_count > 1) {
        bool found = false;
        for (int i = 0; i < subsystem_count; i++) {
            if (msg_id >= target_service->start_ids[i] && msg_id <= target_service->end_ids[i]) {
                chosen_subsystem = i;
                found = true;
                break;
            }
        }
        if (!found) {
            if (verbose) {
                printf("Warning: Message ID %u not found in any subsystem range. Defaulting to subsystem 0.\n", msg_id);
            }
            chosen_subsystem = 0;
        }
    }

    std::vector<std::pair<void*, uint32_t>> ool_buffers;
    std::vector<uint8_t> mach_msg;

    // 使用带消息ID参数的generate_message重载
    generate_message(msg_id, fuzz_data, mach_msg, ool_buffers);


    mach_msg_header_t *return_buffer = (mach_msg_header_t *)malloc(sizeof(mach_msg_header_t) + 10000);
    if (!return_buffer) {
        perror("Failed to allocate memory");
        for (const auto& buffer_pair : ool_buffers) {
            vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
        }
        return 1;
    }

    mach_msg_header_t *fuzz_mach_msg = (mach_msg_header_t *)mach_msg.data();

    if (verbose) {
        printf("Generated message size for ID %u: %zu bytes\n", msg_id, mach_msg.size());
        printf("Sending the following mach msg:\n");
        print_mach_msg((mach_message *)fuzz_mach_msg, mach_msg.size(), true);
    }

    uint64_t result = 0;
    if (chosen_subsystem >= 0 && chosen_subsystem < subsystem_count && Dispatch_Routines[chosen_subsystem]) {
        t_Mach_Processing_Function handler = Dispatch_Routines[chosen_subsystem](fuzz_mach_msg);
        if (handler) {
            result = handler(fuzz_mach_msg, return_buffer);
        } else {
            verbose_print("Dispatch routine returned NULL handler\n");
        }
    } else {
        verbose_print("Invalid subsystem index or dispatch routine is NULL\n");
    }

    verbose_print("Processing function result: %llu\n", result);
    if (verbose) {
        verbose_print("Return message:\n");
        print_mach_msg_no_trailer((mach_message*)return_buffer);
    }

    free(return_buffer);
    for (const auto& buffer_pair : ool_buffers) {
        vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
    }

    return 0;
}

// Read sample file
int read_sample_file(const char *file_path, uint8_t **data, size_t *size) {
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Error opening sample file");
        return 1;
    }

    fseek(file, 0, SEEK_END);
    *size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (*size > MAX_SAMPLE_SIZE) {
        *size = MAX_SAMPLE_SIZE;
    }

    *data = (uint8_t *)malloc(*size);
    if (!*data) {
        perror("Failed to allocate memory for sample data");
        fclose(file);
        return 1;
    }

    fread(*data, 1, *size, file);
    fclose(file);
    return 0;
}

int main(int argc, char *argv[]) {
    uint32_t msg_id = 0;
    char *service_name_arg = NULL;
    
    int opt;
    while ((opt = getopt(argc, argv, "i:vs:")) != -1) {
        switch (opt) {
            case 'i':
                msg_id = (uint32_t)strtoul(optarg, NULL, 0);
                break;
            case 'v':
                verbose = 1;
                break;
            case 's':
                service_name_arg = optarg;
                break;
            default:
                fprintf(stderr, "Usage: %s -i <message_id> [-s service_name] [-v]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (msg_id == 0) {
        fprintf(stderr, "Error: Message ID is required. Usage: %s -i <message_id> -s <service_name> [-v]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    if (!service_name_arg) {
        fprintf(stderr, "Error: Service name is required. Usage: %s -i <message_id> -s <service_name> [-v]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    // 初始化服务
    char service_name_buf[256];
    strcpy(service_name_buf, service_name_arg);
    // const char *service_name = service_name_buf;
    Service service;
    
    char service_info_path[256];
    snprintf(service_info_path, sizeof(service_info_path), "../../fuzz_exec/%s/service.json", service_name_buf);

    int count = load_single_service_from_json(service_info_path, &service);

    if (count != 1) {
        printf("Failed to load service from %s\n", service_info_path);
        exit(1);
    }

    // if (strcmp(service.name, service_name) != 0) {
    //     printf("Service '%s' not found in %s\n", service_name, service_info_path);
    //     exit(1);
    // }

    target_service = &service;

    const char *libraryPath = target_service->lib_path;
    const char *startFunction = target_service->start_function;
    subsystem_count = target_service->subsystem_num;

    const char* wait_for_debugger = std::getenv("WAIT_FOR_DEBUGGER");
    if (wait_for_debugger && std::string(wait_for_debugger) == "1") {
        printf("Waiting for debugger to attach...\n");
        sleep(20);
        printf("Debugger attached, continuing execution...\n");
    }

    if (strlen(startFunction) != 0) {
        if (!initServerStarterwithName(libraryPath, startFunction)) {
            printf("Failed to initialize Service\n");
            exit(1);
        }
    }
    
    if (!initMessageHandlerwithName(libraryPath, target_service->dispatch_routines, subsystem_count)) {
        printf("Failed to initialize MessageHandler with names, trying with offsets\n");
        if (!initMessageHandlerwithOffset(libraryPath, target_service->dispatch_routine_offsets, subsystem_count)) {
            printf("Failed to intialize MessageHandler with offsets %llx\n", target_service->dispatch_routine_offsets[0]);
            exit(1);
        }
    }

    printf("Initialized MessageHandler as %p\n", (void*)Dispatch_Routines[0]);

    safari_audit_token = get_safari_audit_token();
    if (safari_audit_token[0] == 0 && safari_audit_token[1] == 0 &&
        safari_audit_token[2] == 0 && safari_audit_token[3] == 0 &&
        safari_audit_token[4] == 0 && safari_audit_token[5] == 0 &&
        safari_audit_token[6] == 0 && safari_audit_token[7] == 0) {
        printf("Failed to get audit token for Safari\n");
        exit(1);
    }

    // 读取默认的sample文件作为随机种子
    uint8_t *sample_data;
    size_t sample_size;
    const char *sample_path = "sample";
    
    if (read_sample_file(sample_path, &sample_data, &sample_size) != 0) {
        fprintf(stderr, "Failed to read sample file: %s\n", sample_path);
        exit(EXIT_FAILURE);
    }

    printf("Checking message ID %u with sample data from %s (size: %zu bytes)\n", 
           msg_id, sample_path, sample_size);

    int result = check_message(msg_id, sample_data, sample_size);
    
    free(sample_data);
    return result;
}
