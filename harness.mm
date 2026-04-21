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

#include "harness.h"
#include "fuzz_helpers/services_manager.h"
// #import "SwizzleHelper.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <sys/shm.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <getopt.h>
#include <cstdint>
#include <cstring>
#include <vector>
#include <cstdlib>
#include <setjmp.h>

extern "C" jmp_buf server_start_env;

unsigned char *shm_data = NULL;
int verbose = 0;
int print_bytes_only = 0;
t_Dispatch_Routine Dispatch_Routines[MAX_SUBSYSTEMS_NUM] = {0};
int subsystem_count = 0;
t_ServerStarter ServerStarter = NULL;
std::vector<uint8_t> safari_audit_token;

Service *target_service = NULL; // 添加为全局变量
const char *current_file_path = "unknown";

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fuzz_data(data, size);

    while (fuzz_data.remaining_bytes() >= MACH_MSG_HEADER_SIZE) {
        verbose_print("\n*******NEW MESSAGE*******\n");

        std::vector<std::pair<void*, uint32_t>> ool_buffers;
        std::vector<uint8_t> mach_msg;

        // 尝试加载有效的消息ID列表
        size_t valid_ids_count = 0;
        uint32_t* valid_ids_ptr = load_valid_ids("check_result.json", &valid_ids_count);
        
        if (valid_ids_ptr != nullptr && valid_ids_count > 0) {
            // 成功加载有效ID列表，使用重载版本
            // printf("Loaded %zu valid message IDs from check_result.json\n", valid_ids_count);
            std::vector<uint32_t> valid_ids(valid_ids_ptr, valid_ids_ptr + valid_ids_count);
            generate_message(valid_ids, fuzz_data, mach_msg, ool_buffers);
            free(valid_ids_ptr); // 释放动态分配的内存
        } else {
            // 加载失败，使用原来的generate_message，让它内部随机选择消息ID
            // printf("No valid message IDs loaded, using random generation\n");
            generate_message(fuzz_data, mach_msg, ool_buffers);
        }
        

        mach_msg_header_t *return_buffer = (mach_msg_header_t *)malloc(sizeof(mach_msg_header_t) + 10000);
        if (!return_buffer) {
            perror("Failed to allocate memory");
            for (const auto& buffer_pair : ool_buffers) {
                vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
            }
            exit(EXIT_FAILURE);
        }

        mach_msg_header_t *fuzz_mach_msg = (mach_msg_header_t *)mach_msg.data();

        int chosen_subsystem = 0;
        if (subsystem_count > 1) {
            uint32_t msg_id = fuzz_mach_msg->msgh_id;
            for (int i = 0; i < subsystem_count; i++) {
                if (msg_id >= target_service->start_ids[i] && msg_id <= target_service->end_ids[i]) {
                    chosen_subsystem = i;
                    break;
                }
            }
        }

        if (verbose) {
            printf("Sending the following mach msg:\n");
            print_mach_msg((mach_message *)fuzz_mach_msg, mach_msg.size(), true);
            // Write to JSON before calling the handler so we still persist messages if the handler crashes.
            std::vector<nlohmann::json> one_message;
            one_message.push_back(create_message_json(fuzz_mach_msg, mach_msg.size()));
            log_run_to_json(current_file_path, one_message);
        }

        uint64_t result = 0;
        if (chosen_subsystem >= 0 && chosen_subsystem < subsystem_count && Dispatch_Routines[chosen_subsystem]) {
            t_Mach_Processing_Function handler = Dispatch_Routines[chosen_subsystem](fuzz_mach_msg);
            if (handler) {
                result = handler(fuzz_mach_msg, return_buffer);
            }
        } else {
            verbose_print("Invalid subsystem index or dispatch routine is NULL\n");
        }

        verbose_print("Processing function result: %llu\n", result);

        free(return_buffer);
        for (const auto& buffer_pair : ool_buffers) {
            vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
        }
    }

    return 0;
}

extern "C" int fuzz_shmem() {
    if (shm_data == NULL) {
        verbose_print("Error: Shared memory data pointer is NULL\n");
        return 1;
    }

    uint8_t *data = NULL;
    size_t size = 0;

    // Read the size from shared memory and check for validity
    size = (size_t)*(uint32_t *)(shm_data);
    if (size > MAX_SAMPLE_SIZE) {
        verbose_print("Warning: Size read from shared memory (%zu) exceeds MAX_SAMPLE_SIZE (%d). Truncating to MAX_SAMPLE_SIZE.\n", size, MAX_SAMPLE_SIZE);
        size = MAX_SAMPLE_SIZE;
    }

    // Allocate memory for data
    data = (uint8_t *)malloc(size);
    if (data == NULL) {
        verbose_print("Error: Failed to allocate memory for data of size %zu\n", size);
        return 1;
    }

    // Copy data from shared memory to the allocated buffer
    memcpy(data, shm_data + sizeof(uint32_t), size);
    verbose_print("Info: Successfully copied %zu bytes from shared memory to data buffer\n", size);

    // Pass the data to the fuzzer
    verbose_print("Info: Calling LLVMFuzzerTestOneInput with data size %zu\n", size);
    LLVMFuzzerTestOneInput((const uint8_t *)data, size);

    // Free the allocated memory
    free(data);
    verbose_print("Info: Freed allocated memory for data buffer\n");
    return 0;
}

extern "C" int fuzz(const char *file_path) {
    current_file_path = file_path;
    FILE *file = fopen(file_path, "rb");
    if (!file) {
        perror("Error opening file");
        printf("Faulty file: %s", file_path);
        exit(EXIT_FAILURE);
    }

    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fseek(file, 0, SEEK_SET);

    if (size > MAX_SAMPLE_SIZE) size = MAX_SAMPLE_SIZE;
    uint8_t *data = (uint8_t *)malloc(size);
    fread(data, 1, size, file);
    fclose(file);

    LLVMFuzzerTestOneInput(data, size);
    free(data);
    return 0;
}

int setup_shmem(char *name) {
    int fd;

    // get shared memory file descriptor (NOT a file)
    fd = shm_open(name, O_RDONLY, S_IRUSR | S_IWUSR);
    if (fd == -1)
    {
        perror("Error in shm_open\n");
        return 1;
    }

    // map shared memory to process address space
    shm_data = (unsigned char *)mmap(NULL, SHM_SIZE, PROT_READ, MAP_SHARED, fd, 0);
    if (shm_data == MAP_FAILED)
    {
        printf("Error in mmap\n");
        return 1;
    }

    return 0;
}

#ifndef TEST_RUNNING
int main(int argc, char *argv[]) {
    char *shmem_name = NULL;
    char *file_path = NULL;
    
    int opt;
    while ((opt = getopt(argc, argv, "m:f:vb")) != -1) {
        switch (opt) {
            case 'm':
                shmem_name = optarg;
                break;
            case 'f':
                file_path = optarg;
                break;
            case 'v':
                verbose = 1;
                break;
            case 'b':
                print_bytes_only = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s [-m shmem_name] [-f file_path] [-v] [-b]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    // 初始化服务
    static Service service;

    if (load_single_service_from_json("service.json", &service) != 1) {
        printf("Failed to load service from service.json\n");
        exit(1);
    }

    target_service = &service;

    const char *libraryPath = target_service->lib_path;
    const char *startFunction = target_service->start_function;
    uint64_t startFunctionOffset = target_service->start_function_offset;
    subsystem_count = target_service->subsystem_num;

    const char* wait_for_debugger = std::getenv("WAIT_FOR_DEBUGGER");
    if (wait_for_debugger && std::string(wait_for_debugger) == "1") {
        printf("Waiting for debugger to attach...\n");
        sleep(20);
        printf("Debugger attached, continuing execution...\n");
    }

    bool starter_founded = false;
    if (strlen(startFunction) != 0) {
        if (initServerStarterwithName(libraryPath, startFunction)) {
            starter_founded = true;
        }
    } 
    
    if (!starter_founded && startFunctionOffset != 0) {
        if (initServerStarterwithOffset(libraryPath, startFunctionOffset)) {
            starter_founded = true;
        }
    }

    if (starter_founded) {
        if (setjmp(server_start_env) == 0) {
            ServerStarter();
        } else {
            printf("Service initialized (hijacked control flow)\n");
        }
    } else if (strlen(startFunction) != 0 || startFunctionOffset != 0) {
        printf("Failed to initialize Service\n");
        exit(1);
    }
    
    if (!initMessageHandlerwithName(libraryPath, target_service->dispatch_routines, subsystem_count)) {
        // printf("Failed to initialize MessageHandler with names, trying with offsets\n");
        if (!initMessageHandlerwithOffset(libraryPath, target_service->dispatch_routine_offsets, subsystem_count)) {
            printf("Failed to initialize MessageHandler\n");
            exit(1);
        }
    } else {
        // printf("Initialized MessageHandler with names\n");
    }

    safari_audit_token = get_safari_audit_token();
    if (safari_audit_token[0] == 0 && safari_audit_token[1] == 0 &&
        safari_audit_token[2] == 0 && safari_audit_token[3] == 0 &&
        safari_audit_token[4] == 0 && safari_audit_token[5] == 0 &&
        safari_audit_token[6] == 0 && safari_audit_token[7] == 0) {
        printf("Failed to get audit token for Safari\n");
        exit(1);
    }

    // setupSwizzling();
    // ServerStarter();

    if (file_path) {
        fuzz(file_path);
    } else if (shmem_name) {
        if (!setup_shmem(shmem_name)) {
            perror("Error mapping shared memory\n");
            return 1;
        }
        fuzz_shmem();
    } else {
        fprintf(stderr, "Usage: %s [-m shmem_name] [-f file_path] [-v] [-b]\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    return 0;
}
#endif
