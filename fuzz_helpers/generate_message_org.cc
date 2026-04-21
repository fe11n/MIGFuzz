#include "generate_message.h"

const std::vector<uint32_t> kValidSelectors = {
    'grup', 'agrp', 'acom', 'amst', 'apcd', 'tap#', 'atap', '****', 
    // HALS_DeviceManager::HasProperty 支持的选择器
    'boxs', 'bcn#', 'clos', 'cln#', 'dev#', 'devd', 'list',
    'owng', 'ownd', 'prod', 'serv', 'unkb', 'unkc', 'unkd',
    0
};

const std::vector<uint32_t> kValidScopes = {
    'glob', 'inpt', 'outp', 'ptru', '****', 0
};

const std::vector<uint32_t> kValidElements = {
    0xFFFFFFFF, 0 // Wildcard and Null
};

// Function to add selector information to mach_msg
void add_selector_information(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& body) {
    if (body.size() < 16) {
        return; // Ensure there's enough space to modify the last 16 bytes
    }

    if (flip_weighted_coin(0.95, fuzz_data)) {  // 95% probability
        size_t end = body.size();
        *reinterpret_cast<uint32_t*>(&body[end - 16]) = choose_one_of(fuzz_data, kValidSelectors);
        *reinterpret_cast<uint32_t*>(&body[end - 12]) = choose_one_of(fuzz_data, kValidScopes);
        *reinterpret_cast<uint32_t*>(&body[end - 8])  = choose_one_of(fuzz_data, kValidElements);
    }
}

// 新的添加选择器信息函数，按照指定顺序：对象ID、选择器、范围、元素
void add_selector_information_new(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& body) {
    // body是纯参数数据，不包含描述符
    // 我们将selector信息添加到body的尾部，确保不会覆盖其他重要数据
    
    // 检查body是否至少有20字节来容纳所有selector信息
    // 对象ID(4) + 属性地址(8) + 属性元素(8) = 20字节
    if (body.size() < 20) {
        return; 
    }
    
    if (flip_weighted_coin(0.95, fuzz_data)) {  // 95% probability
        // 对象ID：使用NextObjectID的值，如果为空则使用随机值
        uint32_t object_id;
        if (NextObjectID && *NextObjectID != 0) {
            // 使用NextObjectID的当前值并递增
            // object_id = (uint32_t)(*NextObjectID);
            object_id = (uint32_t)(0x23);
            (*NextObjectID)++; // 递增以模拟对象创建
        } else {
            // 如果NextObjectID不可用，使用随机值，避免0
            do {
                object_id = fuzz_data.ConsumeIntegral<uint32_t>();
            } while (object_id == 0);  // 确保不生成0
        }
        
        // 构造属性参数
        uint32_t selector = choose_one_of(fuzz_data, kValidSelectors);
        uint32_t scope = choose_one_of(fuzz_data, kValidScopes);
        uint64_t element = choose_one_of(fuzz_data, kValidElements); // 使用64位element
        
        size_t end = body.size();
        
        // 在body尾部设置selector信息（最后20字节）
        // body[end-20 to end-17]: 对象ID (4字节)
        *reinterpret_cast<uint32_t*>(&body[end - 20]) = object_id;
        
        // body[end-16 to end-9]: 属性地址 (8字节) - selector和scope的组合
        uint64_t property_address = ((uint64_t)selector << 32) | scope;
        *reinterpret_cast<uint64_t*>(&body[end - 16]) = property_address;
        
        // body[end-8 to end-1]: 属性元素 (8字节)
        *reinterpret_cast<uint64_t*>(&body[end - 8]) = element;
    }
}

void generate_body(uint32_t msg_id, FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& body, uint32_t body_size) {
    body = fuzz_data.ConsumeBytes<uint8_t>(body_size);

    if (body.size() < body_size) {
        body.resize(body_size, 0x00);
    }

    std::string msg_id_string = message_id_to_string(static_cast<message_id_enum>(msg_id));
    if (msg_id_string.find("SetProperty") != std::string::npos || 
        msg_id_string.find("GetProperty") != std::string::npos || 
        msg_id_string.find("GetObjectInfo") != std::string::npos) {
        // add_selector_information(fuzz_data, body);
        add_selector_information_new(fuzz_data, body);
    }
}

// Helper function to generate a normal message
std::vector<uint8_t> generate_normal_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, uint32_t msg_size, std::vector<uint8_t>& mach_msg) {
    // HEADER
    std::vector<uint8_t> header;
    generate_header(fuzz_data, msg_size, msg_id, header);

    // BODY
    std::vector<uint8_t> body;
    if (header.size() < msg_size) {
        uint32_t body_size = msg_size - header.size();
        generate_body(msg_id, fuzz_data, body, body_size);
    }

    // Combine header and body. Resize if necessary
    mach_msg.insert(mach_msg.end(), header.begin(), header.end());
    mach_msg.insert(mach_msg.end(), body.begin(), body.end());
    // Will either trim if too long, or pad with zeroes
    mach_msg.resize(msg_size, 0);

    // TRAILER
    std::vector<uint8_t> trailer = get_standard_trailer();
    mach_msg.insert(mach_msg.end(), trailer.begin(), trailer.end());

    return mach_msg;
}

void print_ool_buffer_contents(void *buffer, size_t size) {
    uint8_t *byteBuffer = (uint8_t *)buffer;  // Cast the buffer to a byte pointer

    // Print each byte in hexadecimal format
    printf("OOL Buffer contents (size = %zu bytes):\n", size);
    for (size_t i = 0; i < size; ++i) {
        printf("0x%02x ", byteBuffer[i]);
    }
    printf("\n");
}

// typedef union {
// 	mach_msg_port_descriptor_t            port;
// 	mach_msg_ool_descriptor_t             out_of_line;
// 	mach_msg_ool_ports_descriptor_t       ool_ports;
// 	mach_msg_type_descriptor_t            type;
// 	mach_msg_guarded_port_descriptor_t    guarded_port;
// } mach_msg_descriptor_t;

// Function to safely get a pointer to the element at the given index, or nullptr if out of bounds
template <typename T>
const T* safe_get(const std::vector<T>& vec, size_t index) {
    return (index < vec.size()) ? &vec[index] : nullptr;
}

void generate_descriptors(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& descriptors, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {

    // Consume a descriptor_count if it hasn't been hardcoded for the message
    if (descriptor_count < 1) {
        descriptor_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 4);
    }

    // Convert descriptor_count to a vector and append
    std::vector<uint8_t> descriptor_count_vec(reinterpret_cast<uint8_t*>(&descriptor_count), reinterpret_cast<uint8_t*>(&descriptor_count) + sizeof(uint32_t));
    append_vector(descriptors, descriptor_count_vec);

    for (uint32_t i = 0; i < descriptor_count; i++) {
        // Use safe_get to safely access the descriptor type
        const mach_msg_descriptor_type_t* type_ptr = safe_get(descriptor_types, i);
        
        // Check if the pointer is valid (not null)
        mach_msg_descriptor_type_t type;
        if (type_ptr != nullptr) {
            type = *type_ptr;
        } else {
            // If no descriptor type is found, use a default or fuzz one
            type = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 2);
        }

        switch (type) {
            case MACH_MSG_OOL_DESCRIPTOR: {
                void* oolBuffer = NULL;
                uint32_t size;
                if (flip_weighted_coin(0.5, fuzz_data)) {
                    // Place plist within OOL data
                    const char* data = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"><plist version=\"1.0\"><dict><key>name</key><string>Aggregate Device</string><key>uid</key><string>DillonFrankeAAAAADillonFrankeAAAAADillonFrankeAAAAAAAAAAAAAAAA21</string></dict></plist>";

                    size = strlen(data) + 1;

                    if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&oolBuffer), size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                        printf("Failed to allocate memory buffer\n");
                        // Deallocate previously allocated buffers if allocation fails
                        for (const auto& buffer_pair : ool_buffers) {
                            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(buffer_pair.first), buffer_pair.second);
                        }
                        return;
                    }
                    strncpy((char *)oolBuffer, data, size);
                } else {
                    // Generate random data from the fuzz input for the OOL data
                    uint32_t planned_size = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, MAX_OOL_DATA_SIZE);

                    if (vm_allocate(mach_task_self(), reinterpret_cast<vm_address_t*>(&oolBuffer), planned_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) {
                        printf("Failed to allocate memory buffer\n");
                        // Deallocate previously allocated buffers if allocation fails
                        for (const auto& buffer_pair : ool_buffers) {
                            vm_deallocate(mach_task_self(), reinterpret_cast<vm_address_t>(buffer_pair.first), buffer_pair.second);
                        }
                        return;
                    }
                    size = fuzz_data.ConsumeData(oolBuffer, planned_size);
                }

                // Store the allocated buffer and fill it with fuzzed data
                ool_buffers.push_back(std::make_pair(oolBuffer, size));

                if (verbose) {
                    printf("Allocated OOL Buffer contains:\n");
                    print_ool_buffer_contents(oolBuffer, size);
                }

                // Create a new vector that fits the size of the descriptor/get a pointer to raw data
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_descriptor_t), 0x00);
                mach_msg_ool_descriptor_t* ool_descriptor = reinterpret_cast<mach_msg_ool_descriptor_t*>(descriptor_vec.data());

                // Populate the OOL descriptor fields
                ool_descriptor->size = size;
                ool_descriptor->address = oolBuffer;
                ool_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
                ool_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 4);
                ool_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint8_t>();
                ool_descriptor->type = MACH_MSG_OOL_DESCRIPTOR;

                // Append to the descriptors vector
                append_vector(descriptors, descriptor_vec);

                break;
            }
            case MACH_MSG_PORT_DESCRIPTOR: {
                // Create a new vector that fits the size of the descriptor/get a pointer to raw data
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_port_descriptor_t), 0x00);
                mach_msg_port_descriptor_t* port_descriptor = reinterpret_cast<mach_msg_port_descriptor_t*>(descriptor_vec.data());

                port_descriptor->name = create_mach_port_with_send_rights();  // Ensure this function is defined
                port_descriptor->pad1 = fuzz_data.ConsumeIntegral<uint32_t>();
                port_descriptor->pad2 = fuzz_data.ConsumeIntegral<uint16_t>();
                port_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint32_t>(16, 26);
                port_descriptor->type = MACH_MSG_PORT_DESCRIPTOR;

                // Append to the descriptors vector
                append_vector(descriptors, descriptor_vec);

                break;
            }
            case MACH_MSG_OOL_PORTS_DESCRIPTOR: {
                // Create a new vector that fits the size of the descriptor/get a pointer to raw data
                std::vector<uint8_t> descriptor_vec(sizeof(mach_msg_ool_ports_descriptor_t), 0x00);
                mach_msg_ool_ports_descriptor_t* ool_ports_descriptor = reinterpret_cast<mach_msg_ool_ports_descriptor_t*>(descriptor_vec.data());

                uint32_t port_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(0, 4);
                mach_port_t* port_array = new mach_port_t[port_count];  // Allocate array of ports

                for (uint32_t j = 0; j < port_count; j++) {
                    port_array[j] = create_mach_port_with_send_and_receive_rights();  // Create and store port
                }

                ool_ports_descriptor->address = port_array;
                ool_ports_descriptor->deallocate = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 1);
                ool_ports_descriptor->copy = fuzz_data.ConsumeIntegralInRange<uint8_t>(0, 4);
                ool_ports_descriptor->disposition = fuzz_data.ConsumeIntegralInRange<uint8_t>(16, 26);
                ool_ports_descriptor->type = MACH_MSG_OOL_PORTS_DESCRIPTOR;
                ool_ports_descriptor->count = port_count;

                delete[] port_array;  // Ensure proper memory cleanup

                // Append to the descriptors vector
                append_vector(descriptors, descriptor_vec);

                break;
            }
            default:
                break;
        }
    }
}


// Helper function to generate an OOL message
void generate_ool_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<uint8_t>& mach_msg, std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    // HEADER
    std::vector<uint8_t> header;
    generate_header(fuzz_data, msg_size, msg_id, header, true);

    // DESCRIPTORS
    std::vector<uint8_t> descriptors;
    if (header.size() < msg_size) {
        generate_descriptors(fuzz_data, descriptors, descriptor_count, descriptor_types, ool_buffers);
    }

    // BODY
    std::vector<uint8_t> body;
    if (header.size() + descriptors.size() < msg_size) {
        uint32_t body_size = msg_size - (header.size() + descriptors.size());
        generate_body(msg_id, fuzz_data, body, body_size);
    }

    // Combine header, body, and descriptors. Resize if necessary
    mach_msg.insert(mach_msg.end(), header.begin(), header.end());
    mach_msg.insert(mach_msg.end(), descriptors.begin(), descriptors.end());
    mach_msg.insert(mach_msg.end(), body.begin(), body.end());
    // Will either trim if too long, or pad with zeroes
    mach_msg.resize(msg_size, 0);

    // TRAILER
    std::vector<uint8_t> trailer = get_standard_trailer();
    mach_msg.insert(mach_msg.end(), trailer.begin(), trailer.end());
}


void generate_message(
    uint32_t msg_id, 
    FuzzedDataProvider& fuzz_data, 
    std::vector<uint8_t>& mach_msg, 
    std::vector<std::pair<void*, uint32_t>>& ool_buffers, 
    bool is_ool_message) {
    switch (msg_id) {
        case XSystem_Open: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch condition to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x00;

            break;
        }
        case XObject_SetPropertyData_DCFString_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types,  mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 31] = 0x1;

            // Read descriptor sizes from the message body
            uint32_t descriptor_size_0, descriptor_size_1;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));
            memcpy(&descriptor_size_1, &mach_msg[DESCRIPTOR_OFFSET_1], sizeof(uint32_t));

            descriptor_size_0 = descriptor_size_0 >> 1;
            descriptor_size_1 = descriptor_size_1 >> 1;

            // Now write these sizes to the last 8 bytes of the body
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 60], &descriptor_size_0, sizeof(uint32_t));  // Write descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 64], &descriptor_size_1, sizeof(uint32_t));  // Write descriptor_size_1

            break;
        }
        case XObject_SetPropertyData: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types,  mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 31] = 0x1;

            // Read descriptor sizes from the message body
            uint32_t descriptor_size_0, descriptor_size_1;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));
            memcpy(&descriptor_size_1, &mach_msg[DESCRIPTOR_OFFSET_1], sizeof(uint32_t));

            // Now write these sizes to the last 8 bytes of the body
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 60], &descriptor_size_0, sizeof(uint32_t));  // Write descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 64], &descriptor_size_1, sizeof(uint32_t));  // Write descriptor_size_1

            break;
        }
        case XSystem_CreateIOContext: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types,  mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Set the proper value to descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 28], &descriptor_size_0, sizeof(uint32_t));

            break;
        }
        case XIOContext_Start: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch condition to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;

            break;
        }
        case XSystem_OpenWithBundleIDAndLinkage: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x54, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            break;
        }
        case XIOContext_StartAtTime_With_Shmem_SemaphoreTimeout: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x54, (uint32_t)0x03, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 26] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 38] = 0x11;

            break;
        }
        case XIOContext_StartAtTime_Shmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x3C, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;

            break;
        }
        case XIOContext_StartAtTime: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x3C, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;

            break;
        }
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupPropertiesAndShmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupPropertiesAndShmemAndTimeout: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        case XSystem_OpenWithBundleIDLinkageAndKindAndShmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        // FIXED (test-completed)
        case XSystem_OpenWithBundleIDLinkageAndKindAndSynchronousGroupProperties: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Branch conditions to satisfy
            mach_msg[MACH_MSG_HEADER_SIZE + 14] = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 27] = 0x01;

            // Get the value at a1 + 52 (i.e., mach_msg + 52)
            uint32_t ool_descriptor_size;
            memcpy(&ool_descriptor_size, &mach_msg[52], sizeof(uint32_t));

            uint32_t half_ool_descriptor_size = ool_descriptor_size >> 1;

            // Set offset 80 to half the descriptor size
            memcpy(&mach_msg[80], &half_ool_descriptor_size, sizeof(uint32_t));

            break;
        }
        // FIXED (pending)
        case XSystem_CreateMetaDevice: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};
            // Call the helper function to generate the OOL message structure
            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // To satisfy the condition, value_at_a1_39 must be 1
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = value_at_a1_39;

            // Condition 2: Get the value at a1 + 40 and set the same value at a1 + 52
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));

            // Set the value at a1 + 52 to be the same as a1 + 40
            memcpy(&mach_msg[52], &value_at_a1_40, sizeof(uint32_t));

            break;
        }
        // FIXED (pending)
        case XSystem_WriteSetting: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x4C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Set the value at a1 + 39 to avoid *(unsigned __int8 *)(a1 + 39) << 24 != 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Set the value at a1 + 55 to avoid *(unsigned __int8 *)(a1 + 55) << 24 != 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Set the value at a1 + 68 to be half of the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            uint32_t value_at_a1_68 = value_at_a1_40 >> 1;
            memcpy(&mach_msg[68], &value_at_a1_68, sizeof(uint32_t));

            // Set the value at a1 + 72 to be the same as the value at a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            memcpy(&mach_msg[72], &value_at_a1_56, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DCFString_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DCFString_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DPList_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DPList_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        case XIOContext_SetClientControlPort: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_With_WorkInterval_Shmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_Shmem: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_With_Shmem_SemaphoreTimeout: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x4C, (uint32_t)0x03, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XIOContext_Start_With_WorkInterval: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x34, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[38], &value_at_a1_38, sizeof(uint16_t));

            break;
        }
        case XObject_SetPropertyData_DPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_SetPropertyData_DPList_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x5C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Set the value at a1 + 55 so that *(unsigned __int8 *)(a1 + 55) << 24 == 0x1000000
            uint8_t value_at_a1_55 = 0x01;  // 0x01 << 24 == 0x1000000
            mach_msg[55] = value_at_a1_55;

            // Condition 3: Set the value at a1 + 84 to be the same as the value at a1 + 40
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));
            memcpy(&mach_msg[84], &value_at_a1_40, sizeof(uint32_t));

            // Condition 4: Set the value at a1 + 88 to be half the value of a1 + 56
            uint32_t value_at_a1_56;
            memcpy(&value_at_a1_56, &mach_msg[56], sizeof(uint32_t));
            uint32_t value_at_a1_88 = value_at_a1_56 >> 1;
            memcpy(&mach_msg[88], &value_at_a1_88, sizeof(uint32_t));

            break;
        }
        // FIXED (tested)
        case XSystem_ReadSetting: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            mach_msg[39] = value_at_a1_39;

            // Condition 2: Get the value at a1 + 40, (size) and set the value at a1 + 52 to be half of it
            uint32_t value_at_a1_40;
            memcpy(&value_at_a1_40, &mach_msg[40], sizeof(uint32_t));

            // Set the value at a1 + 52 to be half of a1 + 40
            uint32_t value_at_a1_52 = value_at_a1_40 >> 1;
            memcpy(&mach_msg[52], &value_at_a1_52, sizeof(uint32_t));

            break;
        }
        case XSystem_OpenWithBundleID: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x4C, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 39 so that *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_38 = 0x11;
            mach_msg[MACH_MSG_HEADER_SIZE + 38 - 24] = value_at_a1_38;

            // Condition 2: Ensure *(unsigned __int8 *)(a1 + 51) << 24 == 0x1000000
            uint8_t value_at_a1_51 = 0x01;
            mach_msg[MACH_MSG_HEADER_SIZE + 51 - 24] = value_at_a1_51;

            // Condition 3: Ensure (*(_DWORD *)(a1 + 52) >> 1) == *(_DWORD *)(a1 + 72)
            uint32_t value_at_a1_52;
            memcpy(&value_at_a1_52, &mach_msg[MACH_MSG_HEADER_SIZE + 52 - 24], sizeof(uint32_t));

            // Set the value at a1 + 72 to be half of the value at a1 + 52
            uint32_t value_at_a1_72 = value_at_a1_52 >> 1;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 72 - 24], &value_at_a1_72, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DI32_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) >> 1 == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 >> 1 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40 >> 1;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DCFString_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DPList_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }
        case XObject_GetPropertyData_DCFString_QPList: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) == *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are the different, adjust a1 + 68 to be the same
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }

        case XObject_GetPropertyData_DPList_QRaw: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Ensure *(unsigned __int8 *)(a1 + 39) << 24 == 0x1000000
            uint8_t value_at_a1_39 = 0x01;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 39 - 24], &value_at_a1_39, sizeof(uint8_t));

            // Condition 2: Ensure *(_DWORD *)(a1 + 40) != *(_DWORD *)(a1 + 68)
            uint32_t value_at_a1_40;
            uint32_t value_at_a1_68;

            // Read the current values of a1 + 40 and a1 + 68
            memcpy(&value_at_a1_40, &mach_msg[MACH_MSG_HEADER_SIZE + 40 - 24], sizeof(uint32_t));
            memcpy(&value_at_a1_68, &mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], sizeof(uint32_t));

            // If the values are not the same, adjust a1 + 68
            if (value_at_a1_40 != value_at_a1_68) {
                value_at_a1_68 = value_at_a1_40;
                memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 68 - 24], &value_at_a1_68, sizeof(uint32_t));
            }

            break;
        }

        case XSystem_OpenWithBundleIDLinkageAndKind: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_PORT_DESCRIPTOR, MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x58, (uint32_t)0x02, descriptor_types, mach_msg, ool_buffers);

            // Condition 1: Set the value at a1 + 38 so that *(unsigned __int16 *)(a1 + 38) << 16 == 1114112
            uint16_t value_at_a1_38 = 0x11;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 38 - 24], &value_at_a1_38, sizeof(uint16_t));

            // Condition 2: Set the value at a1 + 51 so that *(unsigned __int8 *)(a1 + 51) << 24 == 0x1000000
            uint8_t value_at_a1_51 = 0x01;
            mach_msg[MACH_MSG_HEADER_SIZE + 51 - 24] = value_at_a1_51;

            // Condition 3: Ensure (*(_DWORD *)(a1 + 52) >> 1) == *(_DWORD *)(a1 + 80)
            uint32_t value_at_a1_52;
            memcpy(&value_at_a1_52, &mach_msg[MACH_MSG_HEADER_SIZE + 52 - 24], sizeof(uint32_t));

            // Set the value at a1 + 80 to be half of the value at a1 + 52
            uint32_t value_at_a1_80 = value_at_a1_52 >> 1;
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 80 - 24], &value_at_a1_80, sizeof(uint32_t));

            break;
        }
        case XTransportManager_CreateDevice: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x3C, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Set the proper value to descriptor_size_0
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 32], &descriptor_size_0, sizeof(uint32_t));

            break;
        }
        case XSystem_DeleteSetting: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x38, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 28], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DPList_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DCFString_QCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DCFString: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 1;  // Shift right by 1 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DAI32_QAI32: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 2;  // Shift left by 2 

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_GetPropertyData_DAI64_QAI64: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 3;  // Shift right by 3 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DAI32: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 2;  // Shift right by 2 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        case XObject_SetPropertyData_DAI64: {
            std::vector<mach_msg_descriptor_type_t> descriptor_types = {MACH_MSG_OOL_DESCRIPTOR};

            generate_ool_message(msg_id, fuzz_data, (uint32_t)0x48, (uint32_t)0x01, descriptor_types, mach_msg, ool_buffers);

            // Dynamic assignment using fuzzed data for branch condition (must be 0x1)
            mach_msg[MACH_MSG_HEADER_SIZE + 15] = 0x1;

            uint32_t descriptor_size_0;
            memcpy(&descriptor_size_0, &mach_msg[DESCRIPTOR_OFFSET_0], sizeof(uint32_t));

            // Perform the shift operation (equivalent to dividing by 2)
            uint32_t descriptor_size_shifted = descriptor_size_0 >> 3;  // Shift right by 2 (shr)

            // Set the shifted value at the second memory location
            memcpy(&mach_msg[MACH_MSG_HEADER_SIZE + 44], &descriptor_size_shifted, sizeof(uint32_t));

            break;
        }
        // NORMAL MESSAGES
        case XSystem_Close: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x18, mach_msg);

            break;
        }
        case XSystem_DestroyIOContext: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XSystem_GetObjectInfo: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XSystem_DestroyMetaDevice: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DCFURL: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DCFString: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DF64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DI32_QI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DCFString_QI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DPList: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DAI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DF32_QF32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DF32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DAF64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_GetPropertyData_DAI64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_SetPropertyData_DI32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_SetPropertyData_DF32: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x34, mach_msg);

            break;
        }
        case XObject_SetPropertyData_DF64: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x38, mach_msg);

            break;
        }
        case XObject_AddPropertyListener: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_RemovePropertyListener: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XTransportManager_DestroyDevice: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x28, mach_msg);

            break;
        }
        case XIOContext_Fetch_Workgroup_Port: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XIOContext_WaitForTap: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XIOContext_StopWaitingForTap: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XIOContext_Stop: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x24, mach_msg);

            break;
        }
        case XObject_HasProperty: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        case XObject_IsPropertySettable: {
            generate_normal_message(msg_id, fuzz_data, (uint32_t)0x30, mach_msg);

            break;
        }
        default: {
            if (is_ool_message) {
                generate_ool_message(msg_id, fuzz_data, (uint32_t)0x00, (uint32_t)0x00, std::vector<mach_msg_descriptor_type_t>(), mach_msg, ool_buffers);
            } else {
                generate_normal_message(msg_id, fuzz_data, (uint32_t)0x00, mach_msg);
            }
            break;
        }    
    }
}