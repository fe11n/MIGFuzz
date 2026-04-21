#include <unistd.h>
#include <iostream>
#include <vector>
#include <mach/mach.h>
#include <bootstrap.h>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <fstream>
#include <iomanip>
#include "../nlohmann_json.hpp"
#include "fuzz_helpers/generate_message.h"

// 复制自 harness.mm 的 load_valid_ids 函数
uint32_t* load_valid_ids(const char* filename, size_t* count) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        return nullptr;
    }

    nlohmann::json json_data;
    file >> json_data;

    if (!json_data.contains("reg_result") || !json_data["reg_result"].contains("successful_ids")) {
        return nullptr;
    }

    auto& successful_ids = json_data["reg_result"]["successful_ids"];
    *count = successful_ids.size();
    uint32_t* ids = (uint32_t*)malloc(*count * sizeof(uint32_t));
    if (!ids) {
        return nullptr;
    }

    for (size_t i = 0; i < *count; ++i) {
        ids[i] = successful_ids[i];
    }

    return ids;
}

bool send_generated_message(const char* endpoint, const char* service_name, const uint8_t* data, size_t size, bool verbose, bool dry_run) {
    FuzzedDataProvider fuzz_data(data, size);
    kern_return_t kr;

    mach_port_t service_port = MACH_PORT_NULL;
    if (!dry_run) {
        kr = bootstrap_look_up(bootstrap_port, endpoint, &service_port);
        if (kr != KERN_SUCCESS) {
            std::cerr << "Failed to look up service port for " << endpoint << ": " << mach_error_string(kr) << std::endl;
            return false;
        }
    } else {
        if (verbose) std::cout << "Dry run: Skipping bootstrap_look_up" << std::endl;
    }

    // 加载 valid_ids，参考 harness
    std::string check_result_path = std::string("../fuzz_exec/") + service_name + "/check_result.json";
    
    // Convert to absolute path to be safe
    char cwd[1024];
    if (getcwd(cwd, sizeof(cwd)) != NULL) {
         // check_result_path is relative to cwd (poc_construct)
         // printf("Current working dir: %s\n", cwd);
    }
    
    size_t valid_ids_count = 0;
    uint32_t* valid_ids_ptr = load_valid_ids(check_result_path.c_str(), &valid_ids_count);
    
    if (valid_ids_ptr == nullptr) {
        if (verbose) {
             std::cerr << "Warning: Failed to load valid_ids from " << check_result_path << std::endl;
             std::cerr << "Attempting to use absolute path..." << std::endl;
        }
        // Try absolute path assuming typical structure
        std::string abs_path = std::string("/Users/fuzz_vr/Workspace/MachServerFuzz/fuzz_exec/") + service_name + "/check_result.json";
        valid_ids_ptr = load_valid_ids(abs_path.c_str(), &valid_ids_count);
        if (valid_ids_ptr == nullptr) {
             if (verbose) std::cerr << "Error: Failed to load valid_ids from absolute path " << abs_path << ". Using full random generation." << std::endl;
        } else {
             if (verbose) std::cout << "Successfully loaded " << valid_ids_count << " valid IDs from absolute path." << std::endl;
        }
    } else {
        if (verbose) std::cout << "Successfully loaded " << valid_ids_count << " valid IDs from " << check_result_path << std::endl;
    }
    
    std::vector<uint32_t> valid_ids;
    if (valid_ids_ptr != nullptr && valid_ids_count > 0) {
        valid_ids.assign(valid_ids_ptr, valid_ids_ptr + valid_ids_count);
        free(valid_ids_ptr);
    }

    int success_count = 0;

    while (fuzz_data.remaining_bytes() >= MACH_MSG_HEADER_SIZE) {
        // verbose_print("\n*******NEW MESSAGE*******\n");

        std::vector<std::pair<void*, uint32_t>> ool_buffers;
        std::vector<uint8_t> msg_data;

        if (!valid_ids.empty()) {
            generate_message(valid_ids, fuzz_data, msg_data, ool_buffers);
        } else {
            generate_message(fuzz_data, msg_data, ool_buffers);
        }

        mach_msg_header_t *fuzz_mach_msg = (mach_msg_header_t *)msg_data.data();

        // 设置 remote_port
        fuzz_mach_msg->msgh_remote_port = service_port;

        // 保存原始的 complex bit 与 local disposition
        bool is_complex = (fuzz_mach_msg->msgh_bits & MACH_MSGH_BITS_COMPLEX) != 0;
        mach_msg_type_name_t local_disp = MACH_MSGH_BITS_LOCAL(fuzz_mach_msg->msgh_bits);

        // 按原始 local_disp 生成匹配权限的端口，避免 invalid reply port
        mach_port_t reply_port = MACH_PORT_NULL;
        if (local_disp != 0) {
            reply_port = generate_granted_port(local_disp);
            if (reply_port == MACH_PORT_NULL) {
                std::cerr << "Failed to create reply port with disposition " << local_disp << std::endl;
                local_disp = 0; // 与 MACH_PORT_NULL 保持一致
            }
        }
        fuzz_mach_msg->msgh_local_port = reply_port;

        // 参考 send_poc.c 的 header 构造
        fuzz_mach_msg->msgh_bits = MACH_MSGH_BITS_SET(
            MACH_MSG_TYPE_COPY_SEND,      // remote bits - 发送到远程端口
            local_disp,                   // local bits - 使用原始生成的 disposition
            MACH_PORT_NULL,                // voucher bits - 不使用
            MACH_PORT_NULL);               // other bits

        if (is_complex) {
            fuzz_mach_msg->msgh_bits |= MACH_MSGH_BITS_COMPLEX;
        }

        // msgh_local_port 已经在上面处理了
        fuzz_mach_msg->msgh_voucher_port = MACH_PORT_NULL;  // 按照要求设置

        if (verbose) {
            std::cout << "\n=== Sending Generated Message ===" << std::endl;
            std::cout << "------ MACH MSG HEADER ------" << std::endl;
            std::cout << "msg_bits: 0x" << std::hex << fuzz_mach_msg->msgh_bits << std::dec << std::endl;
            std::cout << "msg_size: " << fuzz_mach_msg->msgh_size << std::endl;
            std::cout << "msg_remote_port: 0x" << std::hex << fuzz_mach_msg->msgh_remote_port << std::dec << std::endl;
            std::cout << "msg_local_port: 0x" << std::hex << fuzz_mach_msg->msgh_local_port << std::dec << std::endl;
            std::cout << "msg_voucher_port: 0x" << std::hex << fuzz_mach_msg->msgh_voucher_port << std::dec << std::endl;
            std::cout << "msg_id: " << fuzz_mach_msg->msgh_id << std::endl;

            std::cout << "------ MACH MSG HEADER IN BYTES ------" << std::endl;
            uint8_t *header_bytes = reinterpret_cast<uint8_t*>(fuzz_mach_msg);
            for (size_t i = 0; i < sizeof(mach_msg_header_t); i++) {
                std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(header_bytes[i]) << " ";
                if ((i + 1) % 4 == 0) std::cout << " ";
            }
            std::cout << std::dec << std::endl;

            size_t body_size = msg_data.size() - sizeof(mach_msg_header_t);
            std::cout << "------ MACH MSG BODY IN BYTES (" << body_size << " bytes) ------" << std::endl;
            uint8_t *body_bytes = msg_data.data() + sizeof(mach_msg_header_t);
            for (size_t i = 0; i < body_size; i++) {
                std::cout << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(body_bytes[i]) << " ";
                if ((i + 1) % 4 == 0) std::cout << " ";
                if ((i + 1) % 32 == 0) std::cout << std::endl;
            }
            std::cout << std::dec << std::endl;
        }

        if (!dry_run) {
            kr = mach_msg(fuzz_mach_msg, MACH_SEND_MSG, (mach_msg_size_t)msg_data.size(), 0, MACH_PORT_NULL, MACH_MSG_TIMEOUT_NONE, MACH_PORT_NULL);
            if (kr != KERN_SUCCESS) {
                std::cerr << "Failed to send message: " << mach_error_string(kr) << std::endl;
            } else {
                if (verbose) {
                    std::cout << "Message sent successfully!" << std::endl;
                }
                success_count++;
            }
        } else {
            if (verbose) {
                std::cout << "Dry run: Message generation successful (not sent)." << std::endl;
            }
            success_count++;
        }

        for (const auto& buffer_pair : ool_buffers) {
            vm_deallocate(mach_task_self(), (vm_address_t)buffer_pair.first, buffer_pair.second);
        }

        if (reply_port != MACH_PORT_NULL) {
            // 销毁我们为回复创建的端口
            mach_port_destroy(mach_task_self(), reply_port);
        }
    }

    if (dry_run) {
        // In dry run, we didn't allocate service_port
    } else {
        mach_port_deallocate(mach_task_self(), service_port);
    }
    return success_count > 0;
}

int main(int argc, char* argv[]) {
    bool verbose = false;
    bool dry_run = false;
    const char* endpoint = nullptr;
    const char* service_name = nullptr;
    const char* crash_file = nullptr;

    int arg_idx = 1;
    while (arg_idx < argc) {
        if (strcmp(argv[arg_idx], "-v") == 0) {
            verbose = true;
            arg_idx++;
        } else if (strcmp(argv[arg_idx], "--dry-run") == 0) {
            dry_run = true;
            arg_idx++;
        } else {
            if (!endpoint) endpoint = argv[arg_idx];
            else if (!service_name) service_name = argv[arg_idx];
            else if (!crash_file) crash_file = argv[arg_idx];
            arg_idx++;
        }
    }

    if (!endpoint || !service_name || !crash_file) {
        std::cerr << "Usage: " << argv[0] << " [-v] [--dry-run] <endpoint> <service_name> <crash_file>" << std::endl;
        std::cerr << "  -v: verbose mode (print message details)" << std::endl;
        std::cerr << "  --dry-run: generate messages but do not send them" << std::endl;
        return 1;
    }

    FILE* f = fopen(crash_file, "rb");
    if (!f) {
        std::cerr << "Failed to open file: " << crash_file << std::endl;
        return 1;
    }

    fseek(f, 0, SEEK_END);
    size_t size = ftell(f);
    fseek(f, 0, SEEK_SET);
    std::vector<uint8_t> data(size);
    fread(data.data(), 1, size, f);
    fclose(f);

    bool success = send_generated_message(endpoint, service_name, data.data(), size, verbose, dry_run);
    return success ? 0 : 1;
}