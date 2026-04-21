#ifndef GENERATE_MESSAGE_H
#define GENERATE_MESSAGE_H

#include "../harness.h"
#include "tool_lib.h"
#include <vector>
#include <cstdint>

// Generate Mach message main entry
void generate_message(
    uint32_t msg_id,
    FuzzedDataProvider& fuzz_data,
    std::vector<uint8_t>& mach_msg,
    std::vector<std::pair<void*, uint32_t>>& ool_buffers
);

// Overloaded function: choose msg_id from valid_ids list
void generate_message(
    std::vector<uint32_t>& valid_ids,
    FuzzedDataProvider& fuzz_data,
    std::vector<uint8_t>& mach_msg,
    std::vector<std::pair<void*, uint32_t>>& ool_buffers
);

// Overloaded function: randomly choose msg_id
void generate_message(
    FuzzedDataProvider& fuzz_data,
    std::vector<uint8_t>& mach_msg,
    std::vector<std::pair<void*, uint32_t>>& ool_buffers
);

#endif // GENERATE_MESSAGE_H
