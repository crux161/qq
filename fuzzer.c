/**
 * @file fuzzer.c
 * @brief libFuzzer-style harness for the Kyu decompressor.
 */

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "kyu.h"

/**
 * @brief libFuzzer entry point for fuzzing the decompressor.
 *
 * @param[in] Data Fuzz input bytes.
 * @param[in] Size Size of input.
 * @return 0 (ignored by libFuzzer).
 */
int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    if (Size < 4) return 0;

    kyu_stream *strm = calloc(1, sizeof(kyu_stream));
    if (!strm) return 0;

    if (kyu_decompress_init(strm) != KYU_SUCCESS) {
        free(strm);
        return 0;
    }

    size_t out_cap = Size * 10; 
    if (out_cap < 4096) out_cap = 4096;
    uint8_t *out_buf = malloc(out_cap);

    if (out_buf) {
        size_t out_len = out_cap;
        size_t in_len = Size;
        kyu_decompress_update(strm, Data, &in_len, out_buf, &out_len);
        free(out_buf);
    }

    free(strm);
    return 0;
}

/**
 * @brief Standalone driver to run the fuzzer against a file.
 *
 * @param[in] argc Argument count.
 * @param[in] argv Argument vector.
 * @return Exit code (0 on success).
 */
int main(int argc, char **argv) {
    if (argc < 2) return 1;

    FILE *f = fopen(argv[1], "rb");
    if (!f) return 1;

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

    LLVMFuzzerTestOneInput(data, (size_t)len);

    free(data);
    return 0;
}
