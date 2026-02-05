# Kyu Archiver Makefile
# Automatically handles dependencies via vendor.sh

# --- Configuration ---
TARGET      = kyu
SRC_DIR     = .
INC_DIR     = ./include
BUILD_DIR   = ./build

# Compiler Settings
CC          ?= gcc
CFLAGS      = -std=c99 -Wall -Wextra -Wpedantic -Wconversion -I$(INC_DIR)
LDFLAGS     = 

# Fuzzer Settings
FUZZ_CC     ?= afl-clang-fast
FUZZ_TARGET = kyu_fuzz
# Fuzzer uses core logic + fuzzer harness + crypto, but NOT the CLI driver
FUZZ_SRCS   = $(SRC_DIR)/core.c $(SRC_DIR)/fuzzer.c $(SRC_DIR)/monocypher.c

# Dependencies
MONO_SRC    = $(SRC_DIR)/monocypher.c
MONO_HDR    = $(INC_DIR)/monocypher.h

# Source Files for Main Binary
SRCS        = $(SRC_DIR)/core.c \
              $(SRC_DIR)/archive.c \
              $(SRC_DIR)/driver.c \
	      $(SRC_DIR)/ustar.c \
              $(MONO_SRC)

# Object Files
OBJS        = $(SRCS:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

# Detect OS for specific flags
UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
    # Linux specific flags if needed
endif
ifeq ($(UNAME_S),Darwin)
    # macOS specific flags if needed
endif

# --- Targets ---

.PHONY: all release debug clean audit help dependencies fuzz

all: release

# Release Build: Optimized, stripped symbols
release: CFLAGS += -O3 -march=native -DNDEBUG
release: $(TARGET)

# Debug Build: Symbols, no optimization
debug: CFLAGS += -O0 -g -DDEBUG
debug: $(TARGET)

# Audit Build: ASan and UBSan enabled
audit: CFLAGS += -O1 -g -fsanitize=address,undefined -fno-omit-frame-pointer
audit: LDFLAGS += -fsanitize=address,undefined
audit: $(TARGET)

# Fuzzer Build: Uses afl-clang-fast with ASan
fuzz: dependencies
	@echo "  [FUZZ]  Compiling fuzzer with $(FUZZ_CC)..."
	@mkdir -p $(BUILD_DIR)
	@$(FUZZ_CC) $(CFLAGS) -fsanitize=address,undefined -g $(FUZZ_SRCS) -o $(FUZZ_TARGET)
	@echo "  [INFO]  Fuzzer compiled. Run with:"
	@echo "          mkdir -p inputs && echo 'seed' > inputs/test.txt"
	@echo "          afl-fuzz -i inputs -o outputs -- ./$(FUZZ_TARGET) @@"

# Main Link Step
$(TARGET): $(OBJS)
	@echo "  [LINK]  $@"
	@$(CC) $(OBJS) $(LDFLAGS) -o $@

# Compile Step
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR) dependencies
	@echo "  [CC]    $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Directory Creation
$(BUILD_DIR):
	@mkdir -p $(BUILD_DIR)

# --- Dependency Management ---

# Smart Dependency Check:
# Only runs vendor.sh if monocypher.c or monocypher.h are missing.
dependencies:
	@if [ ! -f "$(MONO_SRC)" ] || [ ! -f "$(MONO_HDR)" ]; then \
		echo "  [DEP]   Monocypher missing. Running vendor.sh..."; \
		./vendor.sh || { echo "Vendor script failed"; exit 1; }; \
	fi

# Force update of dependencies
update-deps:
	@echo "  [DEP]   Forcing dependency update..."; \
	./vendor.sh

# --- Utilities ---

clean:
	@echo "  [CLEAN] Removing build artifacts..."
	@rm -rf $(BUILD_DIR) $(TARGET) $(TARGET).dSYM $(FUZZ_TARGET)
	@rm -rf ./*.o

# Clean everything including vendored files
distclean: clean
	@echo "  [CLEAN] Removing vendored dependencies..."
	@rm -f $(MONO_SRC) $(MONO_HDR)

help:
	@echo "Kyu Build System"
	@echo "Targets:"
	@echo "  make          - Build optimized binary (release)"
	@echo "  make debug    - Build with debug symbols"
	@echo "  make audit    - Build with ASan/UBSan"
	@echo "  make fuzz     - Build the fuzzer using afl-clang-fast"
	@echo "  make clean    - Remove binary and objects"
	@echo "  make distclean- Remove binary, objects, AND downloaded dependencies"

docs:
	@echo "Building Doxygen docs..."
	@mkdir -p docs/doxygen
	@doxygen ./Doxyfile
