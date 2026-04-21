#ifndef SERVICES_MANAGER_H
#define SERVICES_MANAGER_H

#include <stdint.h>
#include <vector>

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_NAME_LENGTH 256
#define MAX_PATH_LENGTH 512
#define MAX_SUBSYSTEMS_NUM 10

typedef struct {
    char name[MAX_NAME_LENGTH];
    char lib_path[MAX_PATH_LENGTH];
    char start_function[MAX_NAME_LENGTH];
    uint64_t start_function_offset;
    int subsystem_num;
    char dispatch_functions[MAX_SUBSYSTEMS_NUM][MAX_NAME_LENGTH];
    uint64_t dispatch_function_offsets[MAX_SUBSYSTEMS_NUM];
    char dispatch_routines[MAX_SUBSYSTEMS_NUM][MAX_NAME_LENGTH];
    uint64_t dispatch_routine_offsets[MAX_SUBSYSTEMS_NUM];
    uint32_t start_ids[MAX_SUBSYSTEMS_NUM];
    uint32_t end_ids[MAX_SUBSYSTEMS_NUM];
} Service;

int load_services_from_json(const char* filename, Service services[], int max_services);
int load_single_service_from_json(const char* filename, Service* service);

uint32_t* load_valid_ids(const char* filename, size_t* count);

#ifdef __cplusplus
}
#endif

#endif