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

// =============================================================================
// Category 1: Structural Design Tools
// Includes: append_vector, choose_one_of, flip_weighted_coin
// =============================================================================

/**
 * Purpose: Helper function to append the contents of one byte vector to another. 
 *          Equivalent to target.insert(target.end(), source.begin(), source.end()).
 *
 * Input Parameters:
 * - target: Reference to destination vector that will be modified
 * - source: Const reference to source vector to be appended
 *
 * Return Value:
 * - void (modifies target vector in-place)
 */
void append_vector(std::vector<uint8_t>& target, const std::vector<uint8_t>& source) {
    target.insert(target.end(), source.begin(), source.end());
}

/**
 * Purpose: Randomly selects one element from a provided vector of choices.
 *
 * Input Parameters:
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 * - choices: Const reference to a vector of available uint32_t choices
 *
 * Return Value:
 * - uint32_t: The selected random element from the choices vector
 */
uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices) {
    return choices[fuzz_data.ConsumeIntegralInRange<size_t>(0, choices.size() - 1)];
}

/**
 * Purpose: Generates a weighted random boolean decision using ConsumeProbability().
 *
 * Input Parameters:
 * - probability: Double value between 0.0 and 1.0 representing chance of true
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 *
 * Return Value:
 * - bool: true with the specified probability, false otherwise
 */
bool flip_weighted_coin(double probability, FuzzedDataProvider& fuzz_data) {
    return fuzz_data.ConsumeProbability<double>() < probability;
}


// =============================================================================
// Category 2: Component Generation Tools
// Includes: header/trailer/descriptors generation
// =============================================================================

/**
 * Purpose: Generates a complete 24-byte Mach message header with randomized bits, ports, and specified size/ID.
 *
 * Input Parameters:
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 * - msg_size: Total size of the message
 * - msg_id: Message ID to set in msgh_id
 * - header: Reference to vector to store the generated header (resized to 24 bytes)
 * - is_ool: Boolean flag to force MACH_MSGH_BITS_COMPLEX bit
 *
 * Return Value:
 * - void (modifies header vector in-place)
 */
void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool) {
    header.resize(MACH_MSG_HEADER_SIZE);
    mach_msg_header_t* msg_header = reinterpret_cast<mach_msg_header_t*>(header.data());
    
    std::vector<uint32_t> valid_disps = {16, 17, 18, 19, 20, 21, 24, 25};
    
    // Remote port and disp
    uint32_t remote_disp = 0;
    mach_port_t remote_port = MACH_PORT_NULL;
    if (fuzz_data.ConsumeBool()) {
        remote_disp = choose_one_of(fuzz_data, valid_disps);
        remote_port = fuzz_data.ConsumeIntegral<uint32_t>();
    }

    // Local port and disp
    uint32_t local_disp = 0;
    mach_port_t local_port = MACH_PORT_NULL;
    if (fuzz_data.ConsumeBool()) {
        local_disp = choose_one_of(fuzz_data, valid_disps);
        local_port = fuzz_data.ConsumeIntegral<uint32_t>();
    }

    // Voucher port and disp
    uint32_t voucher_disp = 0;
    mach_port_t voucher_port = MACH_PORT_NULL;
    if (fuzz_data.ConsumeBool()) {
        voucher_disp = choose_one_of(fuzz_data, valid_disps);
        voucher_port = fuzz_data.ConsumeIntegral<uint32_t>();
    }
    
    // Generate message bits
    // 根据结构: Voucher对应第16-23位(<<16), Local对应第8-15位(<<8), Remote对应最低8位(<<0)
    uint32_t bits = (remote_disp) | (local_disp << 8) | (voucher_disp << 16);
    if (is_ool) {
        bits |= MACH_MSGH_BITS_COMPLEX; // Set complex bit for OOL messages
    }
    
    msg_header->msgh_bits = bits;
    msg_header->msgh_size = msg_size;
    msg_header->msgh_remote_port = remote_port;
    msg_header->msgh_local_port = local_port;
    msg_header->msgh_voucher_port = voucher_port;
    msg_header->msgh_id = msg_id;
}

/**
 * Purpose: Generates the entire descriptors section including count and a sequence 
 *          of descriptor structures based on the specified types and constraints.
 *
 * Input Parameters:
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 * - descriptors: Reference to vector to store the generated descriptors
 * - descriptor_count: Number of descriptors to generate
 * - descriptor_types: Vector of target descriptor types (if empty or shorter than count, fuzzed randomly)
 * - ool_buffers: Reference to tracking vector for allocated OOL buffers
 */
void generate_descriptors(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& descriptors, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    if (descriptor_count < 1) {
        descriptor_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 4);
    }

    // Append descriptor_count
    std::vector<uint8_t> count_vec((uint8_t*)&descriptor_count, (uint8_t*)&descriptor_count + sizeof(uint32_t));
    append_vector(descriptors, count_vec);

    for (uint32_t i = 0; i < descriptor_count; i++) {
        mach_msg_descriptor_type_t type;
        if (i < descriptor_types.size()) {
            type = descriptor_types[i];
        } else {
            type = static_cast<mach_msg_descriptor_type_t>(fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 2));
        }

        switch (type) {
            case MACH_MSG_OOL_DESCRIPTOR: {
                // Allocate buffer with random size
                uint32_t size = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, MAX_OOL_DATA_SIZE);
                void* oolBuffer = nullptr;
                
                if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&oolBuffer), size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                    // Allocation failed, cleanup and return
                    for (const auto& buffer_pair : ool_buffers) {
                        vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(buffer_pair.first), buffer_pair.second);
                    }
                    return;
                }
                
                // Fill buffer with fuzzed data
                size_t actual_size = fuzz_data.ConsumeData(oolBuffer, size);
                if (actual_size < size) {
                    memset(static_cast<char*>(oolBuffer) + actual_size, 0, size - actual_size);
                }
                
                // Generate descriptor from the allocated buffer
                std::vector<uint8_t> descriptor_vec = generate_ool_descriptor(oolBuffer, size, ool_buffers);
                
                if (descriptor_vec.empty()) {
                    // Failed to generate descriptor, cleanup and return
                    vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(oolBuffer), size);
                    return;
                }
                
                append_vector(descriptors, descriptor_vec);
                break;
            }
            case MACH_MSG_PORT_DESCRIPTOR: {
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_port_descriptor_t), 0x00);
                mach_msg_port_descriptor_t* port_descriptor = reinterpret_cast<mach_msg_port_descriptor_t*>(descriptor_vec.data());

                uint8_t disp = fuzz_data.ConsumeIntegralInRange<uint8_t>(16, 25);
                port_descriptor->name = generate_granted_port(disp);
                port_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint32_t>();
                port_descriptor->pad2 = fuzz_data.ConsumeIntegral<uint16_t>();
                port_descriptor->disposition = disp;
                port_descriptor->type = MACH_MSG_PORT_DESCRIPTOR;

                append_vector(descriptors, descriptor_vec);
                break;
            }
            case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_ports_descriptor_t), 0x00);
                mach_msg_ool_ports_descriptor_t* ool_ports_descriptor = reinterpret_cast<mach_msg_ool_ports_descriptor_t*>(descriptor_vec.data());

                uint32_t port_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 4);
                uint8_t disp = fuzz_data.ConsumeIntegralInRange<uint8_t>(16, 25);
                
                mach_port_t* port_array = nullptr;
                uint32_t alloc_size = port_count * sizeof(mach_port_t);
                
                if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&port_array), alloc_size, VM_FLAGS_ANYWHERE) == KERN_SUCCESS) {
                    for (uint32_t j = 0; j < port_count; j++) {
                        port_array[j] = generate_granted_port(disp);
                    }
                    ool_buffers.push_back(std::make_pair(port_array, alloc_size));
                } else {
                    port_count = 0;
                }

                ool_ports_descriptor->address = port_array;
                ool_ports_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
                ool_ports_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(1, 2); // 1-2
                ool_ports_descriptor->disposition = disp;
                ool_ports_descriptor->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
                ool_ports_descriptor->count = port_count;

                append_vector(descriptors, descriptor_vec);
                break;
            }
            default:
                break;
        }
    }
}


/**
 * Purpose: Creates a standard Mach message trailer (52-byte vector) that includes
 *          an audit token from Safari.
 *          Note: The msg_trailer_size field within the trailer can be set independently 
 *          of the actual buffer size to test server-side validation.
 *
 * Input Parameters:
 * - msg_trailer_size: The value to be stored in the msgh_trailer_size field (default: 52)
 *
 * Return Value:
 * - std::vector<uint8_t>: 52-byte vector containing the audit trailer
 */
std::vector<uint8_t> generate_trailer(uint32_t msg_trailer_size) {
    std::vector<uint8_t> trailer;

    // 1. Trailer Type: 0x00000000
    uint32_t msg_trailer_type = 0;
    std::vector<uint8_t> type_vec((uint8_t*)&msg_trailer_type, (uint8_t*)&msg_trailer_type + sizeof(uint32_t));

    // 2. Trailer Size Field: Custom value (usually 52)
    std::vector<uint8_t> size_vec((uint8_t*)&msg_trailer_size, (uint8_t*)&msg_trailer_size + sizeof(uint32_t));

    // 3. Sequence Number: 0
    uint32_t msg_seqno = 0;
    std::vector<uint8_t> seqno_vec((uint8_t*)&msg_seqno, (uint8_t*)&msg_seqno + sizeof(uint32_t));

    // 4. Sender ID: 0 (8 bytes)
    uint64_t msg_sender = 0;
    std::vector<uint8_t> sender_vec((uint8_t*)&msg_sender, (uint8_t*)&msg_sender + sizeof(uint64_t));

    // 5. Audit Token: 32 bytes from Safari
    std::vector<uint8_t> trailer_body = get_safari_audit_token();

    // Assemble the trailer (Always 52 bytes in physical memory)
    append_vector(trailer, type_vec);
    append_vector(trailer, size_vec);
    append_vector(trailer, seqno_vec);
    append_vector(trailer, sender_vec);
    append_vector(trailer, trailer_body);

    return trailer;
}

/**
 * Purpose: Convenience overload for generate_trailer with default size.
 */
std::vector<uint8_t> generate_trailer() {
    return generate_trailer(MACH_MSG_TRAILER_SIZE);
}

// =============================================================================
// Category 3: Parameter Construction Tools
// Includes: port related, descriptor related, OOL buffer allocation, 
//           audit token retrieval, generate_random_path
// =============================================================================

/**
 * Purpose: Allocates a buffer in virtual memory using vm_allocate and fills it with random data.
 *
 * Input Parameters:
 * - size: Size of buffer to allocate in bytes
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 *
 * Return Value:
 * - void*: Pointer to the allocated buffer (nullptr if allocation fails or size is 0)
 */
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

/**
 * Purpose: Creates a new Mach port with both receive and send rights.
 *
 * Input Parameters:
 * - None
 *
 * Return Value:
 * - mach_port_t: The created Mach port name (exits on failure)
 */
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

    return port; 
}

/**
 * Purpose: Creates a port with both send and receive rights, with explicit error handling.
 *
 * Input Parameters:
 * - None
 *
 * Return Value:
 * - mach_port_t: The created Mach port name (exits on failure)
 */
mach_port_t create_mach_port_with_send_and_receive_rights() {
    mach_port_t port = MACH_PORT_NULL;  
    kern_return_t kr;

    // Step 1: Allocate a port with receive rights
    kr = mach_port_allocate(mach_task_self(), MACH_PORT_RIGHT_RECEIVE, &port);
    if (kr != KERN_SUCCESS) {
        std::cerr << "Failed to allocate Mach port with receive rights: " << mach_error_string(kr) << std::endl;
        exit(1);  
    }

    // Step 2: Insert a send right for the port
    kr = mach_port_insert_right(mach_task_self(), port, port, MACH_MSG_TYPE_MAKE_SEND);
    if (kr != KERN_SUCCESS) {
        std::cerr << "Failed to insert send right into port: " << mach_error_string(kr) << std::endl;
        mach_port_deallocate(mach_task_self(), port);  
        exit(1);
    }

    return port;
}

/**
 * Purpose: Creates a new Mach port and ensures it has the specific rights required for a given Mach message disposition.
 *
 * Input Parameters:
 * - disposition: The Mach message type name constant (e.g., MACH_MSG_TYPE_MAKE_SEND)
 *
 * Return Value:
 * - mach_port_t: The created Mach port or MACH_PORT_NULL on failure
 */
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

/**
 * Purpose: Creates an OOL descriptor from an existing buffer and size.
 *          Constructs the descriptor structure without allocating or tracking the buffer.
 *          (Caller is responsible for buffer allocation and cleanup tracking)
 *
 * Input Parameters:
 * - ool_data: Pointer to pre-allocated OOL buffer (already allocated and filled by caller)
 * - ool_size: Size of the OOL buffer (in bytes)
 * - ool_buffers: Reference to vector tracking buffer allocations (optional, for cases where tracking is needed)
 *
 * Return Value:
 * - std::vector<uint8_t>: Byte vector containing the serialized mach_msg_ool_descriptor_t
 */
std::vector<uint8_t> generate_ool_descriptor(const void* ool_data, uint32_t ool_size, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    if (ool_size == 0 || ool_data == nullptr) {
        return std::vector<uint8_t>();
    }
    
    // Create descriptor vector
    std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_descriptor_t), 0x00);
    mach_msg_ool_descriptor_t* ool_descriptor = reinterpret_cast<mach_msg_ool_descriptor_t*>(descriptor_vec.data());
    
    // Populate the OOL descriptor fields
    ool_descriptor->address = const_cast<void*>(ool_data);
    ool_descriptor->deallocate = 1;  // Standard deallocate value
    ool_descriptor->copy = 0;        // Standard copy value
    ool_descriptor->pad1 = 0;        // Padding
    ool_descriptor->type = MACH_MSG_OOL_DESCRIPTOR;
    ool_descriptor->size = ool_size;
    
    return descriptor_vec;
}

/**
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

/**
 * Purpose: Function to create port descriptor vector using FuzzedDataProvider.
 *
 * Input Parameters:
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 *
 * Return Value:
 * - std::vector<uint8_t>: Byte vector containing the serialized mach_msg_port_descriptor_t
 */
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

/**
 * Purpose: Function to create OOL ports descriptor vector using FuzzedDataProvider.
 *
 * Input Parameters:
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 *
 * Return Value:
 * - std::vector<uint8_t>: Byte vector containing the serialized mach_msg_ool_ports_descriptor_t
 */
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

/**
 * Purpose: Special descriptor constructor to pass specific validation checks (e.g. disposition 0x11).
 *
 * Input Parameters:
 * - port_descriptor: Pointer to existing mach_msg_port_descriptor_t structure to modify
 * - port: Mach port name to set in the descriptor
 *
 * Return Value:
 * - void (modifies port_descriptor in-place)
 */
void set_special_descriptor(mach_msg_port_descriptor_t* port_descriptor, mach_port_t port) {
    port_descriptor->name = port;
    port_descriptor->disposition = 0x11;
    port_descriptor->type = MACH_MSG_PORT_DESCRIPTOR;
}

/**
 * Purpose: Retrieves the 32-byte audit token from a running Safari process. 
 *          Requires Root privileges for task_for_pid().
 *
 * Input Parameters:
 * - None
 *
 * Return Value:
 * - std::vector<uint8_t>: 32-byte vector containing the audit token (or zeros if failed)
 */
std::vector<uint8_t> get_safari_audit_token() {

    if (geteuid() != 0) {
        fprintf(stderr, "This program must be run as root! (To get the audit token of Safari)\n");
        exit(1);
    }

    // Find Safari PID using sysctl
    size_t size;
    int mib[4] = {CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0};

    // Get the size needed
    if (sysctl(mib, 4, NULL, &size, NULL, 0) != 0) {
        perror("sysctl (get size)");
        std::vector<uint8_t> empty_token(sizeof(audit_token_t), 0);
        return empty_token;
    }

    // Allocate buffer
    struct kinfo_proc *procs = (struct kinfo_proc *)malloc(size);
    if (!procs) {
        perror("malloc");
        std::vector<uint8_t> empty_token(sizeof(audit_token_t), 0);
        return empty_token;
    }

    // Get the actual data
    if (sysctl(mib, 4, procs, &size, NULL, 0) != 0) {
        perror("sysctl (get data)");
        free(procs);
        std::vector<uint8_t> empty_token(sizeof(audit_token_t), 0);
        return empty_token;
    }

    int num_procs = size / sizeof(struct kinfo_proc);
    pid_t pid = -1;

    // Search for Safari process
    for (int i = 0; i < num_procs; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(procs[i].kp_proc.p_pid, path, sizeof(path)) > 0) {
            std::string pathStr(path);
            if (pathStr.find("Safari.app") != std::string::npos ||
                pathStr.find("com.apple.Safari") != std::string::npos) {
                pid = procs[i].kp_proc.p_pid;
                break;
            }
        }
    }

    free(procs);

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

/**
 * Purpose: Generates a random file path by performing a random walk starting from the root directory (/).
 *          Designed for fuzzing file-related Mach message operations.
 *
 * Input Parameters:
 * - fuzz_data: Reference to FuzzedDataProvider for entropy
 * - max_depth: Maximum directory depth to traverse (default: 30)
 *
 * Return Value:
 * - std::optional<std::string>: A randomly found file path string, or std::nullopt if none found
 */
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
            return std::nullopt;
        }

        // Determine the next action based on what was found
        bool has_dirs = !subdirectories.empty();
        bool has_files = !files.empty();

        if (!has_dirs && !has_files) {
            return std::nullopt;
        }

        if (has_dirs && has_files) {
            if (fuzz_data.ConsumeBool()) {
                size_t file_index = fuzz_data.ConsumeIntegralInRange<size_t>(0, files.size() - 1);
                return files[file_index];
            }
        }

        if (has_dirs) {
            size_t dir_index = fuzz_data.ConsumeIntegralInRange<size_t>(0, subdirectories.size() - 1);
            const auto& next_path = subdirectories[dir_index];
            return self(next_path, current_depth + 1, self);
        } else { // must have files
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

