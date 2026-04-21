#include "tool_lib.h"
#include <iostream>
#include <sys/sysctl.h>
#include <libproc.h>
#include <string>
#include <unistd.h>
#include <filesystem>
#include <vector>
#include <random>
#include <optional>

// Helper function to append one vector to another
void append_vector(std::vector<uint8_t>& target, const std::vector<uint8_t>& source) {
    target.insert(target.end(), source.begin(), source.end());
}

// Function to get standard trailer for Mach messages
std::vector<uint8_t> get_standard_trailer() {
    std::vector<uint8_t> trailer(MACH_MSG_TRAILER_SIZE, 0x00);
    // Set trailer type and size at the beginning
    uint32_t trailer_type = MACH_MSG_TRAILER_FORMAT_0;
    uint32_t trailer_size = MACH_MSG_TRAILER_SIZE;
    memcpy(trailer.data(), &trailer_type, sizeof(uint32_t));
    memcpy(trailer.data() + 4, &trailer_size, sizeof(uint32_t));
    return trailer;
}

// Function to generate Mach message header
void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool) {
    header.resize(MACH_MSG_HEADER_SIZE);
    mach_msg_header_t* msg_header = reinterpret_cast<mach_msg_header_t*>(header.data());
    
    // Generate message bits
    uint32_t bits = fuzz_data.ConsumeIntegral<uint32_t>() & 0x7FFFFFFF; // Clear the complex bit
    if (is_ool) {
        bits |= MACH_MSGH_BITS_COMPLEX; // Set complex bit for OOL messages
    }
    
    msg_header->msgh_bits = bits;
    msg_header->msgh_size = msg_size;
    msg_header->msgh_remote_port = fuzz_data.ConsumeIntegral<uint32_t>();
    msg_header->msgh_local_port = fuzz_data.ConsumeIntegral<uint32_t>();
    msg_header->msgh_voucher_port = fuzz_data.ConsumeIntegral<uint32_t>();
    msg_header->msgh_id = msg_id;
}

// Overloaded version without is_ool parameter (defaults to false)
void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header) {
    generate_header(fuzz_data, msg_size, msg_id, header, false);
}

// Function to choose a random value from a given vector
uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices) {
    return choices[fuzz_data.ConsumeIntegralInRange<size_t>(0, choices.size() - 1)];
}

// Function to flip a weighted coin using FuzzedDataProvider::ConsumeProbability()
bool flip_weighted_coin(double probability, FuzzedDataProvider& fuzz_data) {
    return fuzz_data.ConsumeProbability<double>() < probability;
}

// Function to allocate OOL buffer using vm_allocate
void* allocate_ool_buffer(uint32_t size, FuzzedDataProvider& fuzz_data) {
    if (size == 0) {
        return nullptr;
    }
    
    vm_address_t address = 0;
    kern_return_t kr = vm_allocate(mach_task_self(), &address, size, VM_FLAGS_ANYWHERE);
    if (kr != KERN_SUCCESS) {
        return nullptr;
    }
    void* buffer = (void*)address;
    
    // Fill with random data
    uint8_t* byte_buffer = static_cast<uint8_t*>(buffer);
    for (uint32_t i = 0; i < size; ++i) {
        byte_buffer[i] = fuzz_data.ConsumeIntegral<uint8_t>();
    }
    
    return buffer;
}

mach_port_t create_mach_port_with_send_rights() {
    mach_port_t port;
    kern_return_t kr;

    // Allocate a port with receive rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to allocate port: %s\n", mach_error_string(kr));
        exit(1);
    }

    // Insert a send right for the port
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        fprintf(stderr, "Failed to insert send right: %s\n", mach_error_string(kr));
        exit(1);
    }

    return port; // Return the port with send rights
}

mach_port_t create_mach_port_with_send_and_receive_rights() {
    mach_port_t port = MACH_PORT_NULL;  // Initialize port variable
    kern_return_t kr;

    // Step 1: Allocate a port with receive rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        std::cerr << "Failed to allocate Mach port with receive rights: " << mach_error_string(kr) << std::endl;
        exit(1);  // Exit on failure to allocate the port
    }

    // Step 2: Insert a send right for the port
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        std::cerr << "Failed to insert send right into port: " << mach_error_string(kr) << std::endl;
        mach_port_deallocate(mach_task_self(), port);  // Deallocate the port if adding send right fails
        exit(1);
    }

    return port;
}

// Function to generate a port with granted rights
mach_port_t generate_granted_port(mach_msg_type_name_t disposition) {
    mach_port_t port = MACH_PORT_NULL;
    kern_return_t kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        std::cerr << "generate_granted_port: failed to allocate receive right: " << mach_error_string(kr) << std::endl;
        return MACH_PORT_NULL;
    }

    switch (disposition) {
        case MACH_MSG_TYPE_MAKE_SEND:
        case MACH_MSG_TYPE_MAKE_SEND_ONCE:
        case MACH_MSG_TYPE_MOVE_RECEIVE:
            // Already have receive right, nothing more to do
            break;

        case MACH_MSG_TYPE_COPY_SEND:
        case MACH_MSG_TYPE_MOVE_SEND:
            kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
            if (kr != KERN_SUCCESS) {
                std::cerr << "generate_granted_port: failed to insert send right: " << mach_error_string(kr) << std::endl;
                mach_port_destroy(mach_task_self(), port);
                return MACH_PORT_NULL;
            }
            break;

        case MACH_MSG_TYPE_MOVE_SEND_ONCE: {
            mach_port_t so_port = MACH_PORT_NULL;
            mach_msg_type_name_t acquired_type = 0;
            kr = mach_port_extract_right(mach_task_self(), port, MACH_MSG_TYPE_MAKE_SEND_ONCE, &so_port, &acquired_type);
            if (kr != KERN_SUCCESS) {
                std::cerr << "generate_granted_port: failed to extract send-once right: " << mach_error_string(kr) << std::endl;
                mach_port_destroy(mach_task_self(), port);
                return MACH_PORT_NULL;
            }
            // We return the new port name which holds the send-once right.
            // Note: 'port' (receive right) is leaked here, but it's necessary to keep the send-once right alive.
            return so_port;
        }

        default:
            break;
    }
    return port;
}

// Function to create OOL descriptor vector using FuzzedDataProvider
std::vector<uint8_t> set_ool_descriptor(FuzzedDataProvider& fuzz_data, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    uint32_t size = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, MAX_OOL_DATA_SIZE);
    
    // Allocate memory for the actual OOL data
    void* buffer;
    if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&buffer), size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
        printf("Failed to allocate memory buffer\n");
        // Return empty vector on failure
        return std::vector<uint8_t>();
    }
    
    // Generate random data and copy to allocated buffer
    size_t actual_size = fuzz_data.ConsumeData(buffer, size);
    if (actual_size < size) {
        // Fill remaining with zeros
        memset(static_cast<char*>(buffer) + actual_size, 0, size - actual_size);
    }
    
    // Store the allocated buffer
    ool_buffers.emplace_back(buffer, size);
    
    // Create descriptor vector
    std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_descriptor_t), 0x00);
    mach_msg_ool_descriptor_t* ool_descriptor = reinterpret_cast<mach_msg_ool_descriptor_t*>(descriptor_vec.data());
    
    // Populate the OOL descriptor fields
    ool_descriptor->address = buffer;
    ool_descriptor->size = size;
    ool_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
    ool_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 4);
    ool_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint8_t>();
    ool_descriptor->type = MACH_MSG_OOL_DESCRIPTOR;
    
    return descriptor_vec;
}

// Function to create port descriptor vector using FuzzedDataProvider
std::vector<uint8_t> set_port_descriptor(FuzzedDataProvider& fuzz_data) {
    // Create descriptor vector
    std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_port_descriptor_t), 0x00);
    mach_msg_port_descriptor_t* port_descriptor = reinterpret_cast<mach_msg_port_descriptor_t*>(descriptor_vec.data());
    
    // Populate the port descriptor fields
    port_descriptor->name = create_mach_port_with_send_rights();
    port_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint32_t>();
    port_descriptor->pad2 = fuzz_data.ConsumeIntegral<uint16_t>();
    // Set disposition to 0x00 to pass validation (offset 38 check)
    // Validation expects (disposition << 8 | type) << 16 == 0x110000
    // So we need disposition=0x00, type=0x11 (which gets set in generate_message.cc)
    port_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint32_t>(16, 26);
    // port_descriptor->disposition = 0x00;
    port_descriptor->type = MACH_MSG_PORT_DESCRIPTOR;
    
    return descriptor_vec;
}

// Function to create OOL ports descriptor vector using FuzzedDataProvider
std::vector<uint8_t> set_ool_ports_descriptor(FuzzedDataProvider& fuzz_data) {
    uint32_t count = fuzz_data.ConsumeIntegralInRange<uint32_t>(0, 4);
    
    // Create descriptor vector
    std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_ports_descriptor_t), 0x00);
    mach_msg_ool_ports_descriptor_t* ool_ports_descriptor = reinterpret_cast<mach_msg_ool_ports_descriptor_t*>(descriptor_vec.data());
    
    // Create array of ports if count > 0
    mach_port_t* port_array = nullptr;
    if (count > 0) {
        port_array = new mach_port_t[count];  // Allocate array of ports
        
        for (uint32_t j = 0; j < count; j++) {
            port_array[j] = create_mach_port_with_send_and_receive_rights();  // Create and store port
        }
    }
    
    // Populate the OOL ports descriptor fields
    ool_ports_descriptor->address = port_array;
    ool_ports_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
    ool_ports_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 4);
    ool_ports_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint8_t>(16, 26);
    ool_ports_descriptor->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
    ool_ports_descriptor->count = count;
    
    // Note: port_array memory will be managed by the caller or cleaned up when the message is sent
    // In the original generate_message.cc, it's deleted immediately, but here we keep it for the message
    
    return descriptor_vec;
}

// 为了能通过检测生成的特殊描述符构造函数
std::vector<uint8_t> set_special_descriptor(FuzzedDataProvider& fuzz_data) {
    // Create descriptor vector
    std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_port_descriptor_t), 0x00);
    mach_msg_port_descriptor_t* port_descriptor = reinterpret_cast<mach_msg_port_descriptor_t*>(descriptor_vec.data());
    
    // Populate the port descriptor fields
    port_descriptor->name = create_mach_port_with_send_rights();
    port_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint32_t>();
    port_descriptor->pad2 = fuzz_data.ConsumeIntegral<uint16_t>();
    // Set disposition to 0x00 to pass validation (offset 38 check)
    // Validation expects (disposition << 8 | type) << 16 == 0x110000
    // So we need disposition=0x00, type=0x11 (which gets set in generate_message.cc)
    // port_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint32_t>(16, 26);
    port_descriptor->disposition = 0x11;
    port_descriptor->type = MACH_MSG_PORT_DESCRIPTOR;
    
    return descriptor_vec;
}

// Audit token functions implementation

pid_t get_pid_of_safari() {
    size_t size;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

    // Get the size needed
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) {
        perror("sysctl (get size)");
        return -1;
    }

    // Allocate buffer
    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (!procs) {
        perror("malloc");
        return -1;
    }

    // Get the actual data
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        perror("sysctl (get data)");
        free(procs);
        return -1;
    }

    int num_procs = size / sizeof(struct kinfo_proc);
    pid_t safari_pid = -1;

    // Search for Safari process
    for (int i = 0; i < num_procs; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(procs[i].kp_proc.p_pid, path, sizeof(path)) > 0) {
            std::string pathStr(path);
            if (pathStr.find("Safari.app") != std::string::npos ||
                pathStr.find("com.apple.Safari") != std::string::npos) {
                safari_pid = procs[i].kp_proc.p_pid;
                // printf("Found Safari process: PID=%d, Path=%s\n", safari_pid, path);
                break;
            }
        }
    }

    free(procs);
    return safari_pid;
}

// Function to get the audit token for the Safari process
std::vector<uint8_t> get_safari_audit_token() {

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root! (To get the audit token of Safari)\n");
        exit(1);
    }

    pid_t pid = get_pid_of_safari();

    // If PID not found, return an empty audit_token_t
    if (pid == -1) {
        fprintf(stderr, "Safari not open\n");
        std::vector<uint8_t> empty_token(sizeof(audit_token_t), 0);
        return empty_token;
    }

    // Get the audit token for the process
    task_t task;
    audit_token_t audit_token;
    if (task_for_pid(mach_task_self(), pid, &task) == KERN_SUCCESS) {
        mach_msg_type_number_t count = TASK_AUDIT_TOKEN_COUNT;
        if (task_info(task, TASK_AUDIT_TOKEN, (task_info_t)&audit_token, &count) != KERN_SUCCESS) {
            memset(&audit_token, 0, sizeof(audit_token)); // Return empty audit_token if failed
        }
        mach_port_deallocate(mach_task_self(), task);
    } else {
        memset(&audit_token, 0, sizeof(audit_token)); // Return empty audit_token if failed
    }

    // Convert audit_token to std::vector<uint8_t>
    std::vector<uint8_t> result(sizeof(audit_token_t));
    memcpy(result.data(), &audit_token, sizeof(audit_token_t));
    return result;
}

// Using aliases for convenience
namespace fs = std::filesystem;

// Public-facing function to start the process
std::optional<std::string> generate_random_path(FuzzedDataProvider& fuzz_data, int max_depth) {
    const fs::path start_path = "/";  // Fixed starting directory: root

    if (!fs::exists(start_path) || !fs::is_directory(start_path)) {
        return std::nullopt;
    }

    // Helper lambda function that performs the random walk
    auto findRandomFileRecursive = [&](const fs::path& current_path, int current_depth, auto&& self) -> std::optional<fs::path> {
        // Base case: Stop if we've reached the maximum depth
        if (current_depth >= max_depth) {
            return std::nullopt;
        }

        std::vector<fs::path> subdirectories;
        std::vector<fs::path> files;

        // Use a try-catch block to handle potential permission errors
        try {
            // directory_options::skip_permission_denied is crucial for system-wide searches
            for (const auto& entry : fs::directory_iterator(current_path, fs::directory_options::skip_permission_denied)) {
                if (entry.is_directory() && !entry.is_symlink()) { // Avoid symlink loops
                    subdirectories.push_back(entry.path());
                } else if (entry.is_regular_file()) {
                    files.push_back(entry.path());
                }
            }
        } catch (const fs::filesystem_error& e) {
            // Silently ignore directories we can't access
            // std::cerr << "Could not access: " << current_path << " - " << e.what() << std::endl;
            return std::nullopt;
        }

        // Determine the next action based on what was found
        bool has_dirs = !subdirectories.empty();
        bool has_files = !files.empty();

        if (!has_dirs && !has_files) {
            // Dead end, nowhere to go
            return std::nullopt;
        }

        if (has_dirs && has_files) {
            // If both are available, make a random choice:
            // 0: Pick a file from here
            // 1: Go into a subdirectory
            if (fuzz_data.ConsumeBool()) {
                // Pick a file and we are done
                size_t file_index = fuzz_data.ConsumeIntegralInRange<size_t>(0, files.size() - 1);
                return files[file_index];
            } else {
                // Fall through to pick a directory
            }
        }

        if (has_dirs) {
            // If we only have directories, or we chose to go deeper
            size_t dir_index = fuzz_data.ConsumeIntegralInRange<size_t>(0, subdirectories.size() - 1);
            const auto& next_path = subdirectories[dir_index];
            return self(next_path, current_depth + 1, self);
        } else { // must have files
            // If we only have files, pick one
            size_t file_index = fuzz_data.ConsumeIntegralInRange<size_t>(0, files.size() - 1);
            return files[file_index];
        }
    };

    // Try a few times in case a random walk leads to a dead end
    for (int i = 0; i < 10; ++i) {
        auto result = findRandomFileRecursive(start_path, 0, findRandomFileRecursive);
        if (result) {
            return result->string(); // Found a file, return as string
        }
    }

    return std::nullopt; // Failed to find a file after several attempts
}

