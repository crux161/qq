# Kyu Archiver Makefile
# Automatically handles dependencies via vendor.sh

# --- Configuration ---
TARGET      = kyu
SRC_DIR     = src
INC_DIR     = include
BUILD_DIR   = build
SCRIPT_DIR  = scripts

# Compiler Settings
CC          ?= gcc
CFLAGS      = -std=c99 -Wall -Wextra -Wpedantic -Wconversion -I$(INC_DIR)
LDFLAGS     = 

# Fuzzer Settings
FUZZ_CC     ?= afl-clang-fast
FUZZ_TARGET = kyu_fuzz
FUZZ_SRCS   = $(SRC_DIR)/core.c $(SRC_DIR)/fuzzer.c $(SRC_DIR)/monocypher.c

# Dependencies
MONO_SRC    = $(SRC_DIR)/monocypher.c
MONO_HDR    = $(INC_DIR)/monocypher.h

# Source Files for Main Binary
SRCS        = $(SRC_DIR)/core.c \
              $(SRC_DIR)/archive.c \
              $(SRC_DIR)/driver.c \
              $(SRC_DIR)/ustar.c \
              $(SRC_DIR)/password_utils.c \
              $(MONO_SRC)

# Object Files
OBJS        = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Detect OS
UNAME_S := $(shell uname -s)

# --- WASM Configuration ---
EMCC = emcc
WASM_OUT = libkyu.js
# WASM Flags
WASM_FLAGS = -O3 -s WASM=1 -s ALLOW_MEMORY_GROWTH=1 \
             -s MODULARIZE=1 -s EXPORT_ES6=1 \
             -s ALLOW_TABLE_GROWTH=1 \
             -s EXPORTED_FUNCTIONS='["_kyu_init", "_kyu_push", "_kyu_pull", "_malloc", "_free", "_kyu_get_sizeof_context"]' \
             -s EXPORTED_RUNTIME_METHODS='["cwrap", "getValue", "setValue", "HEAPU8", "addFunction", "removeFunction"]'

# --- Targets ---

.PHONY: all release debug clean audit help dependencies fuzz wasm docs

all: release

release: CFLAGS += -O3 -march=native -DNDEBUG
release: $(TARGET)

debug: CFLAGS += -O0 -g -DDEBUG
debug: $(TARGET)

audit: CFLAGS += -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
audit: LDFLAGS += -fsanitize=address,undefined
audit: $(TARGET)

fuzz: dependencies
	@echo "  [FUZZ]  Compiling fuzzer..."
	@mkdir -p $(BUILD_DIR)
	@$(FUZZ_CC) $(CFLAGS) -fsanitize=address,undefined -g $(FUZZ_SRCS) -o $(FUZZ_TARGET)

$(TARGET): $(OBJS)
	@echo "  [LINK]  $@"
	@$(CC) $(OBJS) $(LDFLAGS) -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR) dependencies
	@echo "  [CC]    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# WASM Target
wasm: $(SRC_DIR)/core.c $(SRC_DIR)/archive.c $(SRC_DIR)/monocypher.c
	@echo "  [WASM]  Compiling to WebAssembly..."
	$(EMCC) $(WASM_FLAGS) $^ -o $(WASM_OUT) -I$(INC_DIR)
	@cp libkyu.js $(SRC_DIR)/libkyu.js
	@echo "  [TS]    Compiling TypeScript wrapper..."
	@tsc --target es2020 --module esnext --lib es2020,dom $(SRC_DIR)/kyu.ts

# --- Dependency Management ---

dependencies:
	@if [ ! -f "$(MONO_SRC)" ] || [ ! -f "$(MONO_HDR)" ]; then \
		echo "  [DEP]   Monocypher missing. Running vendor.sh..."; \
		./$(SCRIPT_DIR)/vendor.sh || { echo "Vendor script failed"; exit 1; }; \
	fi

update-deps:
	@echo "  [DEP]   Forcing dependency update..."; \
	./$(SCRIPT_DIR)/vendor.sh

# --- Utilities ---

clean:
	@echo "  [CLEAN] Removing build artifacts..."
	@rm -rf $(BUILD_DIR) $(TARGET) $(TARGET).dSYM $(FUZZ_TARGET)
	@rm -rf ./live
	@rm -f libkyu.js libkyu.wasm
	@rm -f $(SRC_DIR)/*.d.ts
	@rm -rf ./*.dSYM
	@emcc --clear-cache 2>/dev/null || true

# Documentation
docs:
	@echo "  [DOCS]  Building Doxygen docs..."
	@mkdir -p docs/doxygen
	@doxygen ./Doxyfile

help:
	@echo "Kyu Build System"
	@echo "  make          - Build release binary"
	@echo "  make wasm     - Build WASM and TypeScript assets"
	@echo "  make docs     - Generate Doxygen documentation"
	@echo "  make fuzz     - Build fuzzer"
	@echo "  make clean    - Remove binary and objects"
