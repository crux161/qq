#!/bin/bash
echo "Building Kyu (Audit Mode)..."
CC=clang
CFLAGS="-g -fsanitize=address,undefined -O1 -fno-omit-frame-pointer -std=c99 -I./include"

$CC $CFLAGS -c core.c archive.c monocypher.c
ar rcs libkyu.a core.o archive.o monocypher.o

$CC $CFLAGS driver.c libkyu.a -o kyu_audit
