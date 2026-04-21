// ================================================================
// PART1: Header file inclusions, tool function declarations and definitions
// This part is used to include necessary headers, declare external tool functions or define custom tool functions.
// Tool functions will be used in subsequent message construction processes. Special structures can also be defined here.
// ================================================================

#include "generate_message.h"
#include <cstring>
#include <algorithm>
#include <mach/ndr.h>
#include <mach/message.h>
#include <mach/mach.h>

// External tool function declarations - from helpers module
extern void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool = false);
extern std::vector<uint8_t> generate_trailer(uint32_t msg_trailer_size = 52);
extern void generate_descriptors(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& descriptors, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<std::pair<void*, uint32_t>>& ool_buffers);
extern std::vector<uint8_t> generate_ool_descriptor(const void* ool_data, uint32_t ool_size, std::vector<std::pair<void*, uint32_t>>& ool_buffers);
extern uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices);
extern void* allocate_ool_buffer(uint32_t size, FuzzedDataProvider& fuzz_data);

// ================================================================
// Global variables for cross-component constraints
// SharedValue_{id}_{i}: i-th shared value for message ID {id}
// These are set during first component generation and used by subsequent components
// ================================================================

// Message ID 1010009: OOL data size (shared between descriptor and body)
// descriptor.size (offset 40) = body.string_char_count (offset 52) * 2
static uint32_t SharedValue_1010009_0 = 0;  // OOL data size

// ================================================================
// PART2: Message ID-based message construction functions for each part
// This part is used to define functions that construct different message content for different message IDs based on form_cons.json.
// Including: generate_message_{id} functions that call component generators like generate_header_{id}, generate_descriptor_{id}, etc.
// ================================================================

// 2.1 Component generation functions for message ID 47213

// Generate header for message 47213
static std::vector<uint8_t> generate_header_47213(FuzzedDataProvider& fuzz_data, uint32_t actual_msg_size) {
    std::vector<uint8_t> header_vec;
    
    // Based on form_cons.json: msg_size==24 (strict constraint), msg_id==47213
    // Non-OOL message, use library function to generate standard header
    generate_header(fuzz_data, 24, 47213, header_vec);
    
    return header_vec;
}

// Generate descriptor section for message 47213
// No descriptors needed - message 47213 is non-OOL, so return empty vector
static std::vector<uint8_t> generate_descriptor_47213() {
    return std::vector<uint8_t>();
}

// Generate body for message 47213
static std::vector<uint8_t> generate_body_47213(FuzzedDataProvider& fuzz_data) {
    std::vector<uint8_t> body_vec;
    
    // Based on form_cons.json: body offset 24, size 20
    // No specific fields to constrain in this example
    // Fill with arbitrary random data
    for (int i = 0; i < 5; ++i) {  // 5 * 4 bytes = 20 bytes
        uint32_t field = fuzz_data.ConsumeIntegral<uint32_t>();
        body_vec.insert(body_vec.end(), (uint8_t*)&field, (uint8_t*)&field + 4);
    }
    
    return body_vec;
}

// Generate trailer for message 47213
static std::vector<uint8_t> generate_trailer_47213(FuzzedDataProvider& fuzz_data) {
    // Use library function to generate standard 52-byte audit trailer
    // Even if no specific trailer constraints, always construct trailer
    return generate_trailer(52);
}

// Main generation function for message 47213
static void generate_message_47213(FuzzedDataProvider& fuzz_data, 
                                   std::vector<uint8_t>& mach_msg,
                                   std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    mach_msg.clear();
    
    // Generate components
    std::vector<uint8_t> descriptor_vec = generate_descriptor_47213();
    std::vector<uint8_t> body_vec = generate_body_47213(fuzz_data);
    std::vector<uint8_t> trailer_vec = generate_trailer_47213(fuzz_data);
    
    // Calculate actual message size
    uint32_t actual_msg_size = 24 + descriptor_vec.size() + body_vec.size() + trailer_vec.size();
    
    // Generate header after knowing actual size
    std::vector<uint8_t> header_vec = generate_header_47213(fuzz_data, actual_msg_size);
    
    // Concatenate complete message
    mach_msg.insert(mach_msg.end(), header_vec.begin(), header_vec.end());
    mach_msg.insert(mach_msg.end(), descriptor_vec.begin(), descriptor_vec.end());
    mach_msg.insert(mach_msg.end(), body_vec.begin(), body_vec.end());
    mach_msg.insert(mach_msg.end(), trailer_vec.begin(), trailer_vec.end());
}

// 2.2 Component generation functions for message ID 1010009
// Example: Demonstrating cross-component constraints using SharedValue_1010009_0

// Generate header for message 1010009
static std::vector<uint8_t> generate_header_1010009(FuzzedDataProvider& fuzz_data, uint32_t actual_msg_size) {
    std::vector<uint8_t> header_vec;
    
    // Based on form_cons.json: msg_size==56 (strict constraint), msg_id==1010009
    // OOL message with COMPLEX bit, use library function to generate standard header
    generate_header(fuzz_data, 56, 1010009, header_vec, true);
    
    return header_vec;
}

// Generate descriptor section for message 1010009
static std::vector<uint8_t> generate_descriptor_1010009(FuzzedDataProvider& fuzz_data, 
                                                      std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    std::vector<uint8_t> descriptor_section;
    
    // Based on form_cons.json: 1010009 is OOL message with 1 OOL data descriptor
    // Cross-component constraint: Use SharedValue_1010009_0 for OOL data size
    // The parent function (generate_message_1010009) should have set this value
    uint32_t ool_data_size = SharedValue_1010009_0;
    
    // If not set, generate a fallback value
    if (ool_data_size == 0) {
        uint32_t string_char_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 1024);
        ool_data_size = string_char_count * 2;
        SharedValue_1010009_0 = ool_data_size;
    }
    
    // Get the OOL buffer from ool_buffers (last entry should be the one allocated for this message)
    void* ool_buffer = ool_buffers.back().first;
    
    // Descriptor section: offset 24, consists of descriptor_count + descriptors
    
    // Descriptor count field (offset 24, size 4 bytes) - must be == 1
    uint32_t descriptor_count = 1;
    descriptor_section.insert(descriptor_section.end(), 
        (uint8_t*)&descriptor_count, (uint8_t*)&descriptor_count + 4);
    
    // Generate OOL descriptor using library function
    // This constructs the descriptor struct from the buffer and size
    std::vector<uint8_t> ool_desc_vec = generate_ool_descriptor(ool_buffer, ool_data_size, ool_buffers);
    descriptor_section.insert(descriptor_section.end(), ool_desc_vec.begin(), ool_desc_vec.end());
    
    return descriptor_section;
}

// Generate body for message 1010009
static std::vector<uint8_t> generate_body_1010009(FuzzedDataProvider& fuzz_data) {
    std::vector<uint8_t> body_vec;
    
    // Based on form_cons.json: body offset 44, size 12
    
    // Padding (offset 44, size 8 bytes)
    for (int i = 0; i < 2; ++i) {
        uint32_t padding = 0;
        body_vec.insert(body_vec.end(), (uint8_t*)&padding, (uint8_t*)&padding + 4);
    }
    
    // string_char_count (offset 52, size 4 bytes)
    // Cross-component constraint: string_char_count = SharedValue_1010009_0 / 2
    // This ensures the body field is consistent with the descriptor's OOL data size
    uint32_t string_char_count;
    if (SharedValue_1010009_0 > 0) {
        string_char_count = SharedValue_1010009_0 / 2;
    } else {
        // Fallback if shared value not set
        string_char_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 1024);
        SharedValue_1010009_0 = string_char_count * 2;
    }
    
    body_vec.insert(body_vec.end(), 
        (uint8_t*)&string_char_count, (uint8_t*)&string_char_count + 4);
    
    return body_vec;
}

// Generate trailer for message 1010009
static std::vector<uint8_t> generate_trailer_1010009(FuzzedDataProvider& fuzz_data) {
    // Use library function to generate standard 52-byte audit trailer
    // Even with cross-component constraints in descriptor/body, always construct trailer
    return generate_trailer(52);
}

// Main generation function for message 1010009
static void generate_message_1010009(FuzzedDataProvider& fuzz_data, 
                                   std::vector<uint8_t>& mach_msg,
                                   std::vector<std::pair<void*, uint32_t>>& ool_buffers) {
    mach_msg.clear();
    
    // Reset shared variable for this message
    SharedValue_1010009_0 = 0;
    
    // Step 1: Generate string_char_count for consistent OOL buffer size
    uint32_t string_char_count = fuzz_data.ConsumeIntegralInRange<uint32_t>(1, 1024);
    uint32_t ool_data_size = string_char_count * 2;
    
    // Step 2: Set shared variable BEFORE calling component generators
    // This ensures descriptor and body use the same value
    SharedValue_1010009_0 = ool_data_size;
    
    // Step 3: Allocate OOL buffer for UniChar string
    void* ool_buffer = allocate_ool_buffer(ool_data_size, fuzz_data);
    if (ool_buffer == nullptr) {
        ool_buffer = allocate_ool_buffer(2, fuzz_data);
        ool_data_size = 2;
        string_char_count = 1;
        // Update shared variable when allocation fails
        SharedValue_1010009_0 = ool_data_size;
    }
    
    // Step 4: Track OOL buffer for cleanup
    ool_buffers.push_back(std::make_pair(ool_buffer, ool_data_size));
    
    // Step 5: Generate components using the shared variable
    // The SharedValue_1010009_0 is set above, so descriptor and body use it consistently
    std::vector<uint8_t> descriptor_vec = generate_descriptor_1010009(fuzz_data, ool_buffers);
    std::vector<uint8_t> body_vec = generate_body_1010009(fuzz_data);
    std::vector<uint8_t> trailer_vec = generate_trailer_1010009(fuzz_data);
    
    // Calculate actual message size
    uint32_t actual_msg_size = 24 + descriptor_vec.size() + body_vec.size() + trailer_vec.size();
    
    // Generate header after knowing actual size
    std::vector<uint8_t> header_vec = generate_header_1010009(fuzz_data, actual_msg_size);
    
    // Concatenate complete message
    mach_msg.insert(mach_msg.end(), header_vec.begin(), header_vec.end());
    mach_msg.insert(mach_msg.end(), descriptor_vec.begin(), descriptor_vec.end());
    mach_msg.insert(mach_msg.end(), body_vec.begin(), body_vec.end());
    mach_msg.insert(mach_msg.end(), trailer_vec.begin(), trailer_vec.end());
}

// ================================================================
// PART3: Main function
// This part defines the generate_message function that will be called by this file,
// responsible for dispatching to message-specific generation functions
// ================================================================

// Main entry function - generate complete Mach message
void generate_message(
    uint32_t msg_id, 
    FuzzedDataProvider& fuzz_data, 
    std::vector<uint8_t>& mach_msg,
    std::vector<std::pair<void*, uint32_t>>& ool_buffers
) {
    switch (msg_id) {
        case 47213:
            generate_message_47213(fuzz_data, mach_msg, ool_buffers);
            break;
        case 1010009:
            generate_message_1010009(fuzz_data, mach_msg, ool_buffers);
            break;
        default:
            // Unsupported message ID, clear the message buffer
            mach_msg.clear();
            break;
    }
}

// Overloaded function: randomly choose msg_id
void generate_message(
    FuzzedDataProvider& fuzz_data, 
    std::vector<uint8_t>& mach_msg,
    std::vector<std::pair<void*, uint32_t>>& ool_buffers
) {
    std::vector<uint32_t> available_msg_ids = {47213, 1010009};
    
    // Randomly choose a message ID
    uint32_t msg_id = choose_one_of(fuzz_data, available_msg_ids);
    
    // Call original function
    generate_message(msg_id, fuzz_data, mach_msg, ool_buffers);
}
