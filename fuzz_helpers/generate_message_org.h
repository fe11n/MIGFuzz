#ifndef GENERATE_MESSAGE_H
#define GENERATE_MESSAGE_H

#include "../harness.h"
#include "message_generate_tool.h"
#include <vector>
#include <cstdint>

// Function declarations
void generate_message(uint32_t msg_id, FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& mach_msg, std::vector<std::pair<void*, uint32_t>>& ool_buffers, bool is_ool_message);

#endif // GENERATE_MESSAGE_H