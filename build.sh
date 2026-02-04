#!/bin/bash
echo "Building Kyu Archiver (QQX5)..."

CC=clang
CFLAGS="-g -Wall -Wextra -O3 -std=c99 -I./include"

$CC $CFLAGS -c core.c archive.c monocypher.c
ar rcs libkyu.a core.o archive.o monocypher.o

$CC $CFLAGS driver.c libkyu.a -o kyu

if [ $? -eq 0 ]; then
    echo "Build Successful: ./kyu (libkyu.a)"
else
    echo "Build Failed."
    exit 1
fi
