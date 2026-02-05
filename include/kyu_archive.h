/**
 * @file kyu_archive.h
 * @brief High-level archive API (QQX5 format with AEAD).
 */
#ifndef KYU_ARCHIVE_H
#define KYU_ARCHIVE_H

#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    uint32_t mode;
    uint64_t mtime;
    uint64_t size;
    char name[256];
} kyu_manifest;

#define KYU_KDF_ARGON2_D  0
#define KYU_KDF_ARGON2_I  1
#define KYU_KDF_ARGON2_ID 2

typedef struct {
    uint32_t algorithm;
    uint32_t nb_blocks;
    uint32_t nb_passes;
    uint32_t nb_lanes;
} kyu_kdf_params;

extern const kyu_kdf_params kyu_kdf_default_params;

/* --- Callback Type Definition (Must be before usage) --- */
/**
 * @brief Generic callback for processing output data.
 * @return 0 on success, error code otherwise.
 */
typedef int (*kyu_write_fn)(void *ctx, const void *buf, size_t len);

/* --- Incremental Write API --- */
typedef struct kyu_writer_t kyu_writer;

kyu_writer* kyu_writer_init(FILE *out_stream, const char *password, const kyu_kdf_params *kdf_params, int level);
int kyu_writer_update(kyu_writer *writer, const void *data, size_t len);
int kyu_writer_finalize(kyu_writer *writer, const kyu_manifest *manifest_template);
void kyu_writer_free(kyu_writer *writer);


/* --- Stream API --- */

int kyu_archive_compress_stream(FILE *in_stream,
                                FILE *out_stream,
                                const char *password,
                                const kyu_kdf_params *kdf_params,
                                const kyu_manifest *manifest_template,
                                kyu_manifest *manifest_out);

/* UPDATED SIGNATURE: Uses generic callback instead of FILE* */
int kyu_archive_decompress_stream(FILE *in_stream,
                                  kyu_write_fn write_fn,
                                  void *write_ctx,
                                  const char *password,
                                  const kyu_kdf_params *kdf_params,
                                  kyu_manifest *manifest_out,
                                  int *manifest_status);

/* --- Legacy Wrappers --- */
int kyu_archive_compress_file(const char *in, const char *out, const char *pass, kyu_manifest *man);
int kyu_archive_decompress_file(const char *in, const char *out, const char *pass, kyu_manifest *man, int *st);

#ifdef __cplusplus
}
#endif
#endif
