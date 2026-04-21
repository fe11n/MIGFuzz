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

#include "initialization.h"

int initMessageHandlerwithOffset(const char *libraryPath, const uint64_t *dispatch_function_offsets, int subsystem_count) {
    void *lib_handle = LoadLibrary(libraryPath);
    if (!lib_handle) {
        printf("LoadLibrary failed: %s\n", libraryPath);
        return 0;
    }
    for (int i = 0; i < subsystem_count && i < MAX_SUBSYSTEMS_NUM; ++i) {
        if (dispatch_function_offsets[i] == 0) {
            Dispatch_Routines[i] = NULL;
            continue;
        }
        void *symbol_address = GetAddressFromFileOffset(lib_handle, dispatch_function_offsets[i]);
        if (!symbol_address) {
            // printf("Symbol lookup failed for offset %llu\n", dispatch_function_offsets[i]);
            Dispatch_Routines[i] = NULL;
            return 0;
        }
        Dispatch_Routines[i] = (t_Dispatch_Routine)symbol_address;
    }
    return 1;
}

int initMessageHandlerwithName(const char *libraryPath, const char (*dispatch_functions)[MAX_NAME_LENGTH], int subsystem_count) {
    void *lib_handle = LoadLibrary(libraryPath);
    if (!lib_handle) {
        printf("LoadLibrary failed: %s\n", libraryPath);
        return 0;
    }
    for (int i = 0; i < subsystem_count && i < MAX_SUBSYSTEMS_NUM; ++i) {
        if (strlen(dispatch_functions[i]) == 0) {
            Dispatch_Routines[i] = NULL;
            continue;
        }
        void *symbol_address = GetSymbolAddress(lib_handle, dispatch_functions[i]);
        if (!symbol_address) {
            // printf("Symbol lookup failed for %s\n", dispatch_functions[i]);
            Dispatch_Routines[i] = NULL;
            return 0;
        }
        Dispatch_Routines[i] = (t_Dispatch_Routine)symbol_address;
    }
    return 1;
}

int initServerStarterwithName(const char *libraryPath, const char *symbolName) {
    void *lib_handle = LoadLibrary(libraryPath);
    if (!lib_handle) {
        printf("LoadLibrary failed\n");
        return 0;
    }
    void *symbol_address = GetSymbolAddress(lib_handle, symbolName);
    if(!symbol_address) {
        printf("Symbol lookup failed\n");
        return 0;
    }
    ServerStarter = (t_ServerStarter)symbol_address;
    return 1;
}

int initServerStarterwithOffset(const char *libraryPath, uint64_t offset) {
    void *lib_handle = LoadLibrary(libraryPath);
    if (!lib_handle) {
        printf("LoadLibrary failed\n");
        return 0;
    }
    void *symbol_address = GetAddressFromFileOffset(lib_handle, offset);
    if(!symbol_address) {
        printf("Symbol lookup failed for offset %llu\n", offset);
        return 0;
    }
    ServerStarter = (t_ServerStarter)symbol_address;
    return 1;
}