/**
 * @file fuzzer.c
 * @brief LibFuzzer/AFL++ harness for Kyu Decompression Core.
 *
 * BYPASSES: Argon2id, ChaCha20, Poly1305.
 * TARGETS: LZ77 state machine, RLE decoding, Window buffer safety.
 */

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "kyu.h"

/* Fixed output buffer for fuzzing. */
#define FUZZ_OUT_CAP 262144
static uint8_t OUT_BUF[FUZZ_OUT_CAP];

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    kyu_stream strm;
    if (kyu_decompress_init(&strm) != KYU_SUCCESS) return 0;

    size_t in_len = size;
    size_t out_len = FUZZ_OUT_CAP;
    
    int ret = kyu_decompress_update(&strm, data, &in_len, OUT_BUF, &out_len);
    (void)ret; /* Suppress unused variable warning */

    kyu_decompress_free(&strm);
    return 0;
}

/* Standalone main for AFL */
int main(int argc, char **argv) {
    (void)argc; (void)argv;
    
    /* AFL default input buffer (via stdin) */
    static uint8_t buf[1024 * 1024]; /* 1MB input limit */
    size_t n = fread(buf, 1, sizeof(buf), stdin);
    
    LLVMFuzzerTestOneInput(buf, n);
    return 0;
}
