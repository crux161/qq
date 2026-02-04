#!/bin/bash
echo "Building Kyu (Audit Mode)..."
# -fsanitize=address: Detects memory corruption
# -fsanitize=undefined: Detects integer overflows/shifts
# -g: Adds debug symbols for line numbers
clang -g -fsanitize=address,undefined -O1 -fno-omit-frame-pointer \
    core.c \
    monocypher.c \
    driver.c \
    -I./include \
    -o kyu_audit
