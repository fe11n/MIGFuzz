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

#include "debug.h"
#include <stdio.h>
#include <stdarg.h>
#include "nlohmann_json.hpp"
#include <fstream>
#include <vector>
#include <iomanip>
#include <sstream>

void verbose_print(const char *format, ...) {
    if (verbose) {
        va_list args;
        va_start(args, format);
        vprintf(format, args);
        fflush(stdout);
        va_end(args);
    }
}

void print_mach_msg(mach_message *msg, size_t total_size, bool is_ool_message) {
    if (!verbose) return;
    (void)is_ool_message;
    verbose_print("------ MACH MSG HEADER ------\n");
    verbose_print("msg_bits: %u\n", msg->header.msgh_bits);
    verbose_print("msg_size: %u\n", msg->header.msgh_size);
    verbose_print("msg_remote_port: %u\n", msg->header.msgh_remote_port);
    verbose_print("msg_local_port: %u\n", msg->header.msgh_local_port);
    verbose_print("msg_voucher_port: %u\n", msg->header.msgh_voucher_port);
    verbose_print("msg_id: %u\n", msg->header.msgh_id);

    // Print header in bytes
    verbose_print("------ MACH MSG HEADER IN BYTES ------\n");
    uint8_t *header_bytes = (uint8_t *)&msg->header;
    for (size_t i = 0; i < sizeof(mach_msg_header_t); i++) {
        verbose_print("0x%02x ", header_bytes[i]);
        if ((i + 1) % 4 == 0) verbose_print(" ");
        if ((i + 1) % 32 == 0) verbose_print("\n");
    }
    if (sizeof(mach_msg_header_t) % 32 != 0) verbose_print("\n");

    size_t header_size = sizeof(mach_msg_header_t);
    size_t msg_body_size = total_size - header_size;
    verbose_print("------ MACH MSG BODY IN BYTES (%lu bytes) ------\n", msg_body_size);

    for (size_t i = 0; i < msg_body_size; i++) {
        verbose_print("0x%02x ", (unsigned char)msg->body[i]);
        if ((i + 1) % 4 == 0) verbose_print(" ");
        if ((i + 1) % 32 == 0) verbose_print("\n");
    }
    verbose_print("\n");

    // Calculate and print trailer if present
    // size_t trailer_size = total_size - msg->header.msgh_size;
    // if (trailer_size >= MACH_MSG_TRAILER_SIZE) {
    //     printf("------ MACH MSG TRAILER ------\n");
    //     uint8_t *trailer = (uint8_t *)(msg->body + msg_body_size);
    //     printf("msg_trailer_type: %u\n", *(uint32_t *)(trailer));
    //     uint32_t trailer_body_size = *(uint32_t *)(trailer + 4);
    //     printf("msg_trailer_size: %u\n", trailer_body_size);
    //     printf("msg_seqno: %u\n", *(uint32_t *)(trailer + 8));
    //     printf("msg_sender: %llu\n", *(uint64_t *)(trailer + 12));

    //     printf("------ MACH MSG TRAILER BODY (%u bytes) ------\n", trailer_body_size);
    //     for (size_t i = 0; i < trailer_body_size; i++) {
    //         printf("0x%02x ", trailer[MACH_MSG_TRAILER_HEADER_SIZE + i]);
    //     }
    //     printf("\n");
    // }

    // Append the full mach message in bytes if -b flag is set
    if (print_bytes_only) {
        verbose_print("\n------ FULL MESSAGE IN BYTES ------\n");
        uint8_t *full_msg = (uint8_t *)msg;  // Pointer to the full message
        for (size_t i = 0; i < total_size; i++) {
            verbose_print("0x%02x ", full_msg[i]);
            if ((i + 1) % 4 == 0) verbose_print(" ");
            if ((i + 1) % 32 == 0) verbose_print("\n");
        }
        if (total_size % 32 != 0) verbose_print("\n");
    }
}

void print_mach_msg_no_trailer(mach_message *msg) {
    if (!verbose) return;
    verbose_print("------ MACH MSG HEADER ------\n");
    verbose_print("msg_bits: %u\n", msg->header.msgh_bits);
    verbose_print("msg_size: %u\n", msg->header.msgh_size);
    verbose_print("msg_remote_port: %u\n", msg->header.msgh_remote_port);
    verbose_print("msg_local_port: %u\n", msg->header.msgh_local_port);
    verbose_print("msg_voucher_port: %u\n", msg->header.msgh_voucher_port);
    verbose_print("msg_id: %u\n", msg->header.msgh_id);

    size_t header_size = sizeof(mach_msg_header_t);
    size_t msg_body_size = msg->header.msgh_size - header_size;
    verbose_print("------ MACH MSG BODY (%lu bytes) ------\n", msg_body_size);

    for (size_t i = 0; i < msg_body_size; i++) {
        verbose_print("0x%02x ", (unsigned char)msg->body[i]);
    }
    verbose_print("\n");
}

nlohmann::json create_message_json(mach_msg_header_t *msg, size_t total_size) {
    nlohmann::json msg_obj;
    msg_obj["header"] = {
        {"msgh_bits", msg->msgh_bits},
        {"msgh_size", msg->msgh_size},
        {"msgh_remote_port", msg->msgh_remote_port},
        {"msgh_local_port", msg->msgh_local_port},
        {"msgh_voucher_port", msg->msgh_voucher_port},
        {"msgh_id", msg->msgh_id}
    };

    // Body as hex string
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    uint8_t *msg_bytes = (uint8_t *)msg;
    size_t header_size = sizeof(mach_msg_header_t);
    
    if (total_size > header_size) {
        for (size_t i = header_size; i < total_size; ++i) {
            ss << std::setw(2) << (int)msg_bytes[i];
        }
    }
    msg_obj["body"] = ss.str();
    return msg_obj;
}

void log_run_to_json(const char* filename, const std::vector<nlohmann::json>& messages) {
    std::string fname = filename ? filename : "unknown";
    
    // Read existing file
    nlohmann::json root;
    std::ifstream ifile("message_content.json");
    if (ifile.is_open()) {
        try {
            ifile >> root;
        } catch (...) {
            root = nlohmann::json::array();
        }
        ifile.close();
    } else {
        root = nlohmann::json::array();
    }
    
    if (!root.is_array()) {
        root = nlohmann::json::array();
    }

    // Find existing entry for this filename, or create it once.
    nlohmann::json* target_entry = nullptr;
    for (auto& entry : root) {
        if (entry.is_object() && entry.contains("filename") && entry["filename"].is_string() && entry["filename"] == fname) {
            target_entry = &entry;
            break;
        }
    }

    if (!target_entry) {
        nlohmann::json new_entry;
        new_entry["filename"] = fname;
        new_entry["messages"] = nlohmann::json::array();
        root.push_back(new_entry);
        target_entry = &root.back();
    }

    if (!(*target_entry)["messages"].is_array()) {
        (*target_entry)["messages"] = nlohmann::json::array();
    }

    for (const auto& msg : messages) {
        (*target_entry)["messages"].push_back(msg);
    }

    std::ofstream ofile("message_content.json");
    if (ofile.is_open()) {
        ofile << root.dump(4);
        ofile.close();
    }
}
