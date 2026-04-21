#include "services_manager.h"
#include <fstream>
#include <iostream>
#include <cstring>
#include <vector>
#include <cstdlib>
#include "../nlohmann_json.hpp"

using json = nlohmann::json;

int load_services_from_json(const char* filename, Service services[], int max_services) {
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open JSON file: " << filename << std::endl;
            return -1;
        }

        json j;
        file >> j;
        
        if (!j.is_array()) {
            std::cerr << "JSON file should contain an array of services" << std::endl;
            return -1;
        }
        
        int count = 0;
        for (const auto& service_json : j) {
            if (count >= max_services) {
                std::cerr << "Too many services in JSON file, maximum is " << max_services << std::endl;
                break;
            }
            
            Service& service = services[count];
            
            // 初始化默认值
            memset(service.name, 0, sizeof(service.name));
            memset(service.lib_path, 0, sizeof(service.lib_path));
            memset(service.start_function, 0, sizeof(service.start_function));
            service.subsystem_num = 0;
            for (int i = 0; i < MAX_SUBSYSTEMS_NUM; ++i) {
                memset(service.dispatch_functions[i], 0, sizeof(service.dispatch_functions[i]));
                service.dispatch_function_offsets[i] = 0;
                memset(service.dispatch_routines[i], 0, sizeof(service.dispatch_routines[i]));
                service.dispatch_routine_offsets[i] = 0;
            }
            
            // 读取服务名称
            if (service_json.contains("name")) {
                std::string name = service_json["name"];
                strncpy(service.name, name.c_str(), MAX_NAME_LENGTH - 1);
                service.name[MAX_NAME_LENGTH - 1] = '\0';
            }
            
            // 读取库路径
            if (service_json.contains("library_path")) {
                std::string lib_path = service_json["library_path"];
                strncpy(service.lib_path, lib_path.c_str(), MAX_PATH_LENGTH - 1);
                service.lib_path[MAX_PATH_LENGTH - 1] = '\0';
            }
            
            // 读取启动函数
            if (service_json.contains("start_function")) {
                std::string start_function = service_json["start_function"];
                strncpy(service.start_function, start_function.c_str(), MAX_NAME_LENGTH - 1);
                service.start_function[MAX_NAME_LENGTH - 1] = '\0';
            }

            // 读取启动函数偏移
            if (service_json.contains("start_function_offset")) {
                std::string offset_str = service_json["start_function_offset"];
                service.start_function_offset = strtoull(offset_str.c_str(), NULL, 16);
            }
            
            // 读取子系统数量
            if (service_json.contains("subsystem_num")) {
                service.subsystem_num = service_json["subsystem_num"];
                if (service.subsystem_num > MAX_SUBSYSTEMS_NUM) {
                    service.subsystem_num = MAX_SUBSYSTEMS_NUM;
                }
            }
            
            // 读取调度函数数组
            if (service_json.contains("dispatch_functions") && service_json["dispatch_functions"].is_array()) {
                auto dispatch_funcs = service_json["dispatch_functions"];
                for (int i = 0; i < service.subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_funcs.size(); i++) {
                    std::string func_name = dispatch_funcs[i];
                    strncpy(service.dispatch_functions[i], func_name.c_str(), MAX_NAME_LENGTH - 1);
                    service.dispatch_functions[i][MAX_NAME_LENGTH - 1] = '\0';
                }
            }
            
            // 读取调度函数偏移数组
            if (service_json.contains("dispatch_function_offsets") && service_json["dispatch_function_offsets"].is_array()) {
                auto dispatch_offsets = service_json["dispatch_function_offsets"];
                for (int i = 0; i < service.subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_offsets.size(); i++) {
                    std::string offset_str = dispatch_offsets[i];
                    service.dispatch_function_offsets[i] = strtoull(offset_str.c_str(), NULL, 16);
                }
            }

            // 读取调度例程数组
            if (service_json.contains("dispatch_routines") && service_json["dispatch_routines"].is_array()) {
                auto dispatch_routines = service_json["dispatch_routines"];
                for (int i = 0; i < service.subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_routines.size(); i++) {
                    std::string func_name = dispatch_routines[i];
                    strncpy(service.dispatch_routines[i], func_name.c_str(), MAX_NAME_LENGTH - 1);
                    service.dispatch_routines[i][MAX_NAME_LENGTH - 1] = '\0';
                }
            }

            // 读取调度例程偏移数组
            if (service_json.contains("dispatch_routine_offsets") && service_json["dispatch_routine_offsets"].is_array()) {
                auto dispatch_routine_offsets = service_json["dispatch_routine_offsets"];
                for (int i = 0; i < service.subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_routine_offsets.size(); i++) {
                    std::string offset_str = dispatch_routine_offsets[i];
                    service.dispatch_routine_offsets[i] = strtoull(offset_str.c_str(), NULL, 16);
                }
            }
            
            count++;
        }
        
        return count;
        
    } catch (const json::exception& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        return -1;
    } catch (const std::exception& e) {
        std::cerr << "Error loading services from JSON: " << e.what() << std::endl;
        return -1;
    }
}

// 加载单个服务的 JSON 配置
int load_single_service_from_json(const char* filename, Service* service) {
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open JSON file: " << filename << std::endl;
            return -1;
        }

        json j;
        file >> j;

        // 初始化默认值
        memset(service->name, 0, sizeof(service->name));
        memset(service->lib_path, 0, sizeof(service->lib_path));
        memset(service->start_function, 0, sizeof(service->start_function));
        service->subsystem_num = 0;
        for (int i = 0; i < MAX_SUBSYSTEMS_NUM; ++i) {
            memset(service->dispatch_functions[i], 0, sizeof(service->dispatch_functions[i]));
            service->dispatch_function_offsets[i] = 0;
        }

        // 读取服务名称
        if (j.contains("name")) {
            std::string name = j["name"];
            strncpy(service->name, name.c_str(), MAX_NAME_LENGTH - 1);
            service->name[MAX_NAME_LENGTH - 1] = '\0';
        }

        // 读取库路径
        if (j.contains("library_path")) {
            std::string lib_path = j["library_path"];
            strncpy(service->lib_path, lib_path.c_str(), MAX_PATH_LENGTH - 1);
            service->lib_path[MAX_PATH_LENGTH - 1] = '\0';
            // printf("Library path: %s\n", service->lib_path);
        }

        // 读取启动函数
        if (j.contains("start_function")) {
            std::string start_function = j["start_function"];
            strncpy(service->start_function, start_function.c_str(), MAX_NAME_LENGTH - 1);
            service->start_function[MAX_NAME_LENGTH - 1] = '\0';
        }

        // 读取启动函数偏移
        if (j.contains("start_function_offset")) {
            std::string offset_str = j["start_function_offset"];
            service->start_function_offset = strtoull(offset_str.c_str(), NULL, 16);
        }

        // 读取子系统数量
        if (j.contains("subsystem_num")) {
            service->subsystem_num = j["subsystem_num"];
            if (service->subsystem_num > MAX_SUBSYSTEMS_NUM) {
                service->subsystem_num = MAX_SUBSYSTEMS_NUM;
            }
        }

        // 读取调度函数数组
        if (j.contains("dispatch_functions") && j["dispatch_functions"].is_array()) {
            auto dispatch_funcs = j["dispatch_functions"];
            for (int i = 0; i < service->subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_funcs.size(); i++) {
                std::string func_name = dispatch_funcs[i];
                strncpy(service->dispatch_functions[i], func_name.c_str(), MAX_NAME_LENGTH - 1);
                service->dispatch_functions[i][MAX_NAME_LENGTH - 1] = '\0';
            }
        }

        // 读取调度函数偏移数组
        if (j.contains("dispatch_function_offsets") && j["dispatch_function_offsets"].is_array()) {
            auto dispatch_offsets = j["dispatch_function_offsets"];
            for (int i = 0; i < service->subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_offsets.size(); i++) {
                std::string offset_str = dispatch_offsets[i];
                service->dispatch_function_offsets[i] = strtoull(offset_str.c_str(), NULL, 16);
            }
        }

        // 读取调度例程数组
        if (j.contains("dispatch_routines") && j["dispatch_routines"].is_array()) {
            auto dispatch_routines = j["dispatch_routines"];
            for (int i = 0; i < service->subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_routines.size(); i++) {
                std::string func_name = dispatch_routines[i];
                strncpy(service->dispatch_routines[i], func_name.c_str(), MAX_NAME_LENGTH - 1);
                service->dispatch_routines[i][MAX_NAME_LENGTH - 1] = '\0';
            }
        }

        // 读取调度例程偏移数组
        if (j.contains("dispatch_routine_offsets") && j["dispatch_routine_offsets"].is_array()) {
            auto dispatch_routine_offsets = j["dispatch_routine_offsets"];
            for (int i = 0; i < service->subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)dispatch_routine_offsets.size(); i++) {
                std::string offset_str = dispatch_routine_offsets[i];
                service->dispatch_routine_offsets[i] = strtoull(offset_str.c_str(), NULL, 16);
            }
        }

        // 读取子系统起始ID
        if (j.contains("subsystem_start_ids") && j["subsystem_start_ids"].is_array()) {
            auto start_ids = j["subsystem_start_ids"];
            for (int i = 0; i < service->subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)start_ids.size(); i++) {
                service->start_ids[i] = start_ids[i];
            }
        }

        // 读取子系统结束ID
        if (j.contains("subsystem_end_ids") && j["subsystem_end_ids"].is_array()) {
            auto end_ids = j["subsystem_end_ids"];
            for (int i = 0; i < service->subsystem_num && i < MAX_SUBSYSTEMS_NUM && i < (int)end_ids.size(); i++) {
                service->end_ids[i] = end_ids[i];
            }
        }

        return 1; // 成功加载 1 个服务

    } catch (const json::exception& e) {
        std::cerr << "JSON parsing error: " << e.what() << std::endl;
        return -1;
    } catch (const std::exception& e) {
        std::cerr << "Error loading service from JSON: " << e.what() << std::endl;
        return -1;
    }
}

// 加载有效的消息ID列表
uint32_t* load_valid_ids(const char* filename, size_t* count) {
    if (count == nullptr) {
        std::cerr << "Error: count parameter cannot be null" << std::endl;
        return nullptr;
    }
    
    *count = 0; // 初始化计数
    
    try {
        std::ifstream file(filename);
        if (!file.is_open()) {
            std::cerr << "Failed to open JSON file: " << filename << std::endl;
            return nullptr;
        }

        json j;
        file >> j;

        std::vector<uint32_t> valid_ids;

        // 根据用户需求：如果有reg_result则获取reg_result的结果，否则获取org_result的结果
        if (j.contains("reg_result") && j["reg_result"].contains("successful_ids") && j["reg_result"]["successful_ids"].is_array()) {
            // 优先使用 reg_result
            for (const auto& id : j["reg_result"]["successful_ids"]) {
                if (id.is_number_unsigned()) {
                    valid_ids.push_back(id);
                }
            }
        } else if (j.contains("org_result") && j["org_result"].contains("successful_ids") && j["org_result"]["successful_ids"].is_array()) {
            // 如果没有 reg_result，使用 org_result
            for (const auto& id : j["org_result"]["successful_ids"]) {
                if (id.is_number_unsigned()) {
                    valid_ids.push_back(id);
                }
            }
        } else {
            std::cerr << "No valid successful_ids found in reg_result or org_result" << std::endl;
            return nullptr;
        }

        // 如果没有找到有效的ID，返回nullptr
        if (valid_ids.empty()) {
            return nullptr;
        }

        // 动态分配内存
        uint32_t* result = (uint32_t*)malloc(valid_ids.size() * sizeof(uint32_t));
        if (result == nullptr) {
            std::cerr << "Memory allocation failed" << std::endl;
            return nullptr;
        }

        // 复制数据
        for (size_t i = 0; i < valid_ids.size(); ++i) {
            result[i] = valid_ids[i];
        }

        *count = valid_ids.size();
        return result;

    } catch (const json::exception& e) {
        std::cerr << "JSON parsing error in load_valid_ids: " << e.what() << std::endl;
        return nullptr;
    } catch (const std::exception& e) {
        std::cerr << "Error loading valid IDs from JSON: " << e.what() << std::endl;
        return nullptr;
    }
}