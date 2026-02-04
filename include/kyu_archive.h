/**
 * @file kyu_archive.h
 * @brief High-level archive API (QQX5 format with AEAD).
 */
#ifndef KYU_ARCHIVE_H
#define KYU_ARCHIVE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Archive metadata stored in the tail manifest.
 */
typedef struct {
    uint32_t mode;
    uint64_t mtime;
    uint64_t size;
    char name[256];
} kyu_manifest;

/**
 * @brief KDF algorithm identifiers (compatible with Monocypher).
 */
#define KYU_KDF_ARGON2_D  0
#define KYU_KDF_ARGON2_I  1
#define KYU_KDF_ARGON2_ID 2

/**
 * @brief Key-derivation parameters for archive encryption.
 */
typedef struct {
    uint32_t algorithm;
    uint32_t nb_blocks;
    uint32_t nb_passes;
    uint32_t nb_lanes;
} kyu_kdf_params;

/**
 * @brief Default KDF parameters (Argon2id, 1MB, 3 passes, 1 lane).
 */
extern const kyu_kdf_params kyu_kdf_default_params;

/**
 * @brief Compress and encrypt a file into a QQX5 archive (default KDF).
 *
 * @param[in]  in_path Input file path.
 * @param[in]  out_path Output archive path.
 * @param[in]  password Password for key derivation.
 * @param[out] manifest_out Optional output manifest (can be NULL).
 * @return 0 on success, negative error code on failure.
 */
int kyu_archive_compress_file(const char *in_path,
                              const char *out_path,
                              const char *password,
                              kyu_manifest *manifest_out);

/**
 * @brief Compress and encrypt a file with custom KDF parameters.
 *
 * @param[in]  in_path Input file path.
 * @param[in]  out_path Output archive path.
 * @param[in]  password Password for key derivation.
 * @param[in]  kdf_params Optional KDF params (NULL uses defaults).
 * @param[out] manifest_out Optional output manifest (can be NULL).
 * @return 0 on success, negative error code on failure.
 */
int kyu_archive_compress_file_ex(const char *in_path,
                                 const char *out_path,
                                 const char *password,
                                 const kyu_kdf_params *kdf_params,
                                 kyu_manifest *manifest_out);

/**
 * @brief Decrypt and decompress a QQX5 archive to a file (default KDF).
 *
 * @param[in]  in_path Input archive path.
 * @param[in]  out_path Output file path.
 * @param[in]  password Password for key derivation.
 * @param[out] manifest_out Optional output manifest (can be NULL).
 * @param[out] manifest_status Optional status:
 *             1 = manifest decrypted and parsed
 *             0 = manifest missing
 *            -1 = manifest present but authentication failed
 * @return 0 on success, negative error code on failure.
 */
int kyu_archive_decompress_file(const char *in_path,
                                const char *out_path,
                                const char *password,
                                kyu_manifest *manifest_out,
                                int *manifest_status);

/**
 * @brief Decrypt and decompress a QQX5 archive with custom KDF parameters.
 *
 * @param[in]  in_path Input archive path.
 * @param[in]  out_path Output file path.
 * @param[in]  password Password for key derivation.
 * @param[in]  kdf_params Optional KDF params (NULL uses defaults).
 * @param[out] manifest_out Optional output manifest (can be NULL).
 * @param[out] manifest_status Optional status:
 *             1 = manifest decrypted and parsed
 *             0 = manifest missing
 *            -1 = manifest present but authentication failed
 * @return 0 on success, negative error code on failure.
 */
int kyu_archive_decompress_file_ex(const char *in_path,
                                   const char *out_path,
                                   const char *password,
                                   const kyu_kdf_params *kdf_params,
                                   kyu_manifest *manifest_out,
                                   int *manifest_status);

#ifdef __cplusplus
}
#endif

#endif
