#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "kyu.h"

/* --- The Fuzz Target (Standard libFuzzer signature) --- */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    /* Reject tiny inputs to save time */
    if (Size < 4) return 0;

    /* Setup Stream */
    kyu_stream *strm = calloc(1, sizeof(kyu_stream));
    if (!strm) return 0;

    if (kyu_decompress_init(strm) != KYU_SUCCESS) {
        free(strm);
        return 0;
    }

    /* Output buffer (discarded) */
    /* We assume max expansion isn't infinite for fuzzing, 
       but ASan will catch us if we write past this bounds */
    size_t out_cap = Size * 10; 
    if (out_cap < 4096) out_cap = 4096;
    uint8_t *out_buf = malloc(out_cap);

    if (out_buf) {
        size_t out_len = out_cap;
        /* Run Decompressor */
        /* We don't care about the result, we care if it CRASHES */
        kyu_decompress_update(strm, Data, Size, out_buf, &out_len);
        free(out_buf);
    }

    free(strm);
    return 0;
}

/* --- AFL++ Wrapper (The "Shim" for standalone fuzzing) --- */
int main(int argc, char **argv) {
    /* 1. AFL passes the input file path as argv[1] */
    if (argc < 2) return 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

    /* 2. Read the entire file into a buffer */
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (len < 0) { fclose(f); return 1; }

    uint8_t *data = (uint8_t *)malloc(len);
    if (!data) { fclose(f); return 1; }

    if (fread(data, 1, len, f) != (size_t)len) {
        fclose(f);
        free(data);
        return 1;
    }
    fclose(f);

    /* 3. Call the Fuzz Target */
    /* This feeds the random junk from AFL into your Kyu decompressor */
    LLVMFuzzerTestOneInput(data, (size_t)len);

    free(data);
    return 0;
}
