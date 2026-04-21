#ifndef MESSAGE_GENERATE_TOOL_H
#define MESSAGE_GENERATE_TOOL_H

#include "../harness.h"
#include <vector>
#include <cstdint>
#include <sys/sysctl.h>
#include <libproc.h>
#include <string>

// Helper function declarations
void append_vector(std::vector<uint8_t>& target, const std::vector<uint8_t>& source);
std::vector<uint8_t> get_standard_trailer();
void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool);
void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header);

uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices);
bool flip_weighted_coin(double probability, FuzzedDataProvider& fuzz_data);
mach_port_t create_mach_port_with_send_rights();
mach_port_t create_mach_port_with_send_and_receive_rights();
mach_port_t generate_granted_port(mach_msg_type_name_t disposition);

// Audit token functions
std::vector<uint8_t> get_safari_audit_token();

// Random path generation function
#include <optional>
#include <filesystem>
std::optional<std::string> generate_random_path(FuzzedDataProvider& fuzz_data, int max_depth);

void* allocate_ool_buffer(uint32_t size, FuzzedDataProvider& fuzz_data);

#endif // MESSAGE_GENERATE_TOOL_H
