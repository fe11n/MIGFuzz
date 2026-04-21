#ifndef TOOL_LIB_H
#define TOOL_LIB_H

#include "../harness.h"
#include <vector>
#include <cstdint>
#include <sys/sysctl.h>
#include <libproc.h>
#include <string>
#include <optional>
#include <filesystem>

/**
 * =============================================================================
 * Mach Message Generation Tool Functions Header
 * =============================================================================
 */

// =============================================================================
// Category 1: Structural Design Tools
// =============================================================================

void append_vector(std::vector<uint8_t>& target, const std::vector<uint8_t>& source);
uint32_t choose_one_of(FuzzedDataProvider& fuzz_data, const std::vector<uint32_t>& choices);
bool flip_weighted_coin(double probability, FuzzedDataProvider& fuzz_data);


// =============================================================================
// Category 2: Component Generation Tools
// =============================================================================

std::vector<uint8_t> generate_trailer(uint32_t msg_trailer_size);
std::vector<uint8_t> generate_trailer();
void generate_header(FuzzedDataProvider& fuzz_data, uint32_t msg_size, uint32_t msg_id, std::vector<uint8_t>& header, bool is_ool = false);


// =============================================================================
void generate_descriptors(FuzzedDataProvider& fuzz_data, std::vector<uint8_t>& descriptors, uint32_t descriptor_count, const std::vector<mach_msg_descriptor_type_t>& descriptor_types, std::vector<std::pair<void*, uint32_t>>& ool_buffers);


// Category 3: Parameter Construction Tools
// =============================================================================

void* allocate_ool_buffer(uint32_t size, FuzzedDataProvider& fuzz_data);
mach_port_t create_mach_port_with_send_rights();
mach_port_t create_mach_port_with_send_and_receive_rights();
mach_port_t generate_granted_port(mach_msg_type_name_t disposition);

std::vector<uint8_t> set_ool_descriptor(FuzzedDataProvider& fuzz_data, std::vector<std::pair<void*, uint32_t>>& ool_buffers);
std::vector<uint8_t> generate_ool_descriptor(const void* ool_data, uint32_t ool_size, std::vector<std::pair<void*, uint32_t>>& ool_buffers);
std::vector<uint8_t> set_port_descriptor(FuzzedDataProvider& fuzz_data);
std::vector<uint8_t> set_ool_ports_descriptor(FuzzedDataProvider& fuzz_data);
void set_special_descriptor(mach_msg_port_descriptor_t* port_descriptor, mach_port_t port);

std::vector<uint8_t> get_safari_audit_token();
std::optional<std::string> generate_random_path(FuzzedDataProvider& fuzz_data, int max_depth = 30);


#endif // TOOL_LIB_H
