# Copyright 2025 Google LLC

# Compilers
CC = clang
CXX = clang++

# Frameworks
FRAMEWORKS = -framework Foundation

# Compiler Flags
# -g: 包含调试信息
# -O0: 禁用优化，确保调试信息准确
# -fno-omit-frame-pointer: 保留帧指针，便于栈跟踪
# -fdebug-compilation-dir .: 设置编译目录为当前目录
# -w: 禁止所有警告
CFLAGS = -g -O0 -fno-omit-frame-pointer -w -std=c++17 -fdebug-compilation-dir .
CXXFLAGS = $(CFLAGS)

# Target service directory, can be overridden from the command line
# e.g. make TARGET_SERVICE_DIR=/path/to/your/service
# TARGET_SERVICE_DIR ?= ../../fuzz_exec/fskitd
TARGET_SERVICE_DIR ?= ../../fuzz_exec/filecoordinationd_1

# Include paths
INCLUDE_PATHS = -I../../fuzz_helpers -I. -I$(TARGET_SERVICE_DIR) -I.. -I../../

# Pass the service directory to the compiler
CFLAGS += -DSERVICE_DIR="\"$(TARGET_SERVICE_DIR)\""

# Source Files
SOURCES = checker.mm \
          ../../fuzz_helpers/debug.cc \
          ../../fuzz_helpers/initialization.cc \
          ../../fuzz_helpers/load_library.cc \
          ../../fuzz_helpers/services_manager.cc \
          $(TARGET_SERVICE_DIR)/generate_message.cc \
          ../../fuzz_helpers/tool_lib.cc

# Output
OUTPUT = checker
DSYM = $(OUTPUT).dSYM

all: $(OUTPUT) $(DSYM)

$(OUTPUT): $(SOURCES)
	$(CXX) $(CXXFLAGS) $(INCLUDE_PATHS) $(FRAMEWORKS) $(SOURCES) -o $(OUTPUT)

$(DSYM): $(OUTPUT)
	dsymutil $(OUTPUT)

debug: $(OUTPUT)
	@echo "=== 调试信息检查 ==="
	@file $(OUTPUT)
	@dwarfdump --debug-info $(OUTPUT) | head -20
	@if [ -d $(DSYM) ]; then echo "dSYM文件存在"; dwarfdump --debug-info $(DSYM) | head -10; fi

clean:
	rm -rf $(OUTPUT) $(DSYM)

.PHONY: all clean
