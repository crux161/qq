/**
 * @file archive.c
 * @brief High-level archive format (QQX5) with AEAD and metadata.
 */

#include "kyu.h"
#include "kyu_archive.h"
#include "monocypher.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define CHUNK_SIZE 65536
#define MAC_SIZE 16
#define NONCE_SIZE 24
#define KEY_SIZE 32
#define SALT_SIZE 16

#define MANIFEST_SIZE (4 + 8 + 8 + 256)

/**
 * @brief Crypto context for an archive session.
 */
typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t salt[SALT_SIZE];
} kyu_crypto;

/**
 * @brief Default KDF parameters (Argon2id, 1MB, 3 passes, 1 lane).
 */
const kyu_kdf_params kyu_kdf_default_params = {
    KYU_KDF_ARGON2_ID,
    1024,
    3,
    1
};

/**
 * @brief Increment the archive nonce in little-endian order.
 *
 * @param[in,out] nonce Nonce buffer (24 bytes).
 * @return None.
 */
static void increment_nonce(uint8_t *nonce) {
    for (int i = 0; i < 8; i++) {
        nonce[i]++;
        if (nonce[i] != 0) break;
    }
}

/**
 * @brief Fill a buffer with cryptographically secure random bytes.
 *
 * @param[out] buf Output buffer.
 * @param[in] len Number of bytes to generate.
 * @return 0 on success, negative error code on failure.
 */
static int secure_random(uint8_t *buf, size_t len) {
#if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
    arc4random_buf(buf, len);
    return KYU_SUCCESS;
#endif

    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return KYU_ERR_IO;
    if (fread(buf, 1, len, f) != len) {
        fclose(f);
        return KYU_ERR_IO;
    }
    fclose(f);
    return KYU_SUCCESS;
}

/**
 * @brief Derive an encryption key from a password and salt.
 *
 * @param[in] pass Password string.
 * @param[in] salt Salt bytes.
 * @param[in] params KDF parameters (NULL uses defaults).
 * @param[out] key Output key (32 bytes).
 * @return 0 on success, negative error code on failure.
 */
static int derive_key(const char *pass, const uint8_t *salt, const kyu_kdf_params *params, uint8_t *key) {
    if (!pass) return KYU_ERR_BAD_ARG;

    const kyu_kdf_params *p = params ? params : &kyu_kdf_default_params;
    crypto_argon2_config config = {
        .algorithm = p->algorithm,
        .nb_blocks = p->nb_blocks,
        .nb_passes = p->nb_passes,
        .nb_lanes = p->nb_lanes
    };

    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t*)pass,
        .pass_size = (uint32_t)strlen(pass),
        .salt = salt,
        .salt_size = SALT_SIZE
    };

    crypto_argon2_extras extras = {0};

    void *work_area = malloc((size_t)config.nb_blocks * 1024);
    if (!work_area) return KYU_ERR_MEMORY;

    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, extras);
    crypto_wipe(work_area, (size_t)config.nb_blocks * 1024);
    free(work_area);
    return KYU_SUCCESS;
}

/**
 * @brief Write the full buffer to a file.
 *
 * @param[in] f Output file handle.
 * @param[in] buf Buffer to write.
 * @param[in] len Number of bytes to write.
 * @return 0 on success, negative error code on failure.
 */
static int write_all(FILE *f, const void *buf, size_t len) {
    return (fwrite(buf, 1, len, f) == len) ? KYU_SUCCESS : KYU_ERR_IO;
}

/**
 * @brief Read the full buffer from a file.
 *
 * @param[in] f Input file handle.
 * @param[out] buf Buffer to fill.
 * @param[in] len Number of bytes to read.
 * @return 1 on success, 0 on failure/short read.
 */
static int read_all(FILE *f, void *buf, size_t len) {
    return (fread(buf, 1, len, f) == len);
}

/**
 * @brief Pack a 32-bit integer into a buffer (little-endian).
 *
 * @param[in,out] b Buffer pointer.
 * @param[in] v Value to pack.
 * @return None.
 */
static void pack_u32_le(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v & 0xFFu);
    b[1] = (uint8_t)((v >> 8) & 0xFFu);
    b[2] = (uint8_t)((v >> 16) & 0xFFu);
    b[3] = (uint8_t)((v >> 24) & 0xFFu);
}
/**
 * @brief Pack a 64-bit integer into a buffer (little-endian).
 *
 * @param[in,out] b Buffer pointer.
 * @param[in] v Value to pack.
 * @return None.
 */
static void pack_u64_le(uint8_t *b, uint64_t v) {
    b[0] = (uint8_t)(v & 0xFFu);
    b[1] = (uint8_t)((v >> 8) & 0xFFu);
    b[2] = (uint8_t)((v >> 16) & 0xFFu);
    b[3] = (uint8_t)((v >> 24) & 0xFFu);
    b[4] = (uint8_t)((v >> 32) & 0xFFu);
    b[5] = (uint8_t)((v >> 40) & 0xFFu);
    b[6] = (uint8_t)((v >> 48) & 0xFFu);
    b[7] = (uint8_t)((v >> 56) & 0xFFu);
}
/**
 * @brief Unpack a 32-bit integer from a buffer (little-endian).
 *
 * @param[in] b Buffer pointer.
 * @return The unpacked 32-bit value.
 */
static uint32_t unpack_u32_le(const uint8_t *b) {
    return (uint32_t)b[0]
         | ((uint32_t)b[1] << 8)
         | ((uint32_t)b[2] << 16)
         | ((uint32_t)b[3] << 24);
}
/**
 * @brief Unpack a 64-bit integer from a buffer (little-endian).
 *
 * @param[in] b Buffer pointer.
 * @return The unpacked 64-bit value.
 */
static uint64_t unpack_u64_le(const uint8_t *b) {
    return (uint64_t)b[0]
         | ((uint64_t)b[1] << 8)
         | ((uint64_t)b[2] << 16)
         | ((uint64_t)b[3] << 24)
         | ((uint64_t)b[4] << 32)
         | ((uint64_t)b[5] << 40)
         | ((uint64_t)b[6] << 48)
         | ((uint64_t)b[7] << 56);
}

/**
 * @brief Wipe sensitive data then free a heap buffer.
 *
 * @param[in] buf Heap buffer pointer.
 * @param[in] len Buffer length in bytes.
 * @return None.
 */
static void wipe_and_free(void *buf, size_t len) {
    if (!buf) return;
    crypto_wipe(buf, len);
    free(buf);
}

int kyu_archive_compress_file_ex(const char *in_path,
                                 const char *out_path,
                                 const char *password,
                                 const kyu_kdf_params *kdf_params,
                                 kyu_manifest *manifest_out);
int kyu_archive_decompress_file_ex(const char *in_path,
                                   const char *out_path,
                                   const char *password,
                                   const kyu_kdf_params *kdf_params,
                                   kyu_manifest *manifest_out,
                                   int *manifest_status);

/**
 * @brief Compress and encrypt a file into a QQX5 archive (default KDF).
 *
 * @param[in] in_path Input file path.
 * @param[in] out_path Output archive path.
 * @param[in] password Password for key derivation.
 * @param[out] manifest_out Optional output manifest (can be NULL).
 * @return 0 on success, negative error code on failure.
 */
int kyu_archive_compress_file(const char *in_path,
                              const char *out_path,
                              const char *password,
                              kyu_manifest *manifest_out) {
    return kyu_archive_compress_file_ex(in_path, out_path, password, NULL, manifest_out);
}

/**
 * @brief Compress and encrypt a file with custom KDF parameters.
 *
 * @param[in] in_path Input file path.
 * @param[in] out_path Output archive path.
 * @param[in] password Password for key derivation.
 * @param[in] kdf_params Optional KDF params (NULL uses defaults).
 * @param[out] manifest_out Optional output manifest (can be NULL).
 * @return 0 on success, negative error code on failure.
 */
int kyu_archive_compress_file_ex(const char *in_path,
                                 const char *out_path,
                                 const char *password,
                                 const kyu_kdf_params *kdf_params,
                                 kyu_manifest *manifest_out) {
    if (!in_path || !out_path || !password) return KYU_ERR_BAD_ARG;

    int ret = KYU_SUCCESS;
    FILE *f_in = NULL;
    FILE *f_out = NULL;
    kyu_stream *strm = NULL;
    uint8_t *io_buf = NULL;
    uint8_t *comp_buf = NULL;
    kyu_crypto ctx = {0};
    kyu_manifest manifest = {0};

    f_in = fopen(in_path, "rb");
    if (!f_in) return KYU_ERR_IO;

    f_out = fopen(out_path, "wb");
    if (!f_out) { fclose(f_in); return KYU_ERR_IO; }

    strm = calloc(1, sizeof(kyu_stream));
    io_buf = malloc(CHUNK_SIZE * 2 + 1024);
    comp_buf = malloc(CHUNK_SIZE * 2);
    if (!strm || !io_buf || !comp_buf) { ret = KYU_ERR_MEMORY; goto cleanup; }

    struct stat st;
    if (stat(in_path, &st) != 0) { ret = KYU_ERR_IO; goto cleanup; }

    manifest.mode = (uint32_t)st.st_mode;
    manifest.mtime = (uint64_t)st.st_mtime;
    manifest.size = (uint64_t)st.st_size;
    memset(manifest.name, 0, sizeof(manifest.name));
    const char *base = strrchr(in_path, '/');
    if (!base) base = in_path; else base++;
    strncpy(manifest.name, base, sizeof(manifest.name) - 1);

    if (manifest_out) *manifest_out = manifest;

    ret = secure_random(ctx.salt, SALT_SIZE);
    if (ret != KYU_SUCCESS) goto cleanup;
    ret = derive_key(password, ctx.salt, kdf_params, ctx.key);
    if (ret != KYU_SUCCESS) goto cleanup;

    if (write_all(f_out, "KYU5", 4) != KYU_SUCCESS ||
        write_all(f_out, ctx.salt, SALT_SIZE) != KYU_SUCCESS) {
        ret = KYU_ERR_IO;
        goto cleanup;
    }

    kyu_compress_init(strm);

    size_t n_read;
    while ((n_read = fread(io_buf, 1, CHUNK_SIZE, f_in)) > 0) {
        size_t n_comp = CHUNK_SIZE * 2;
        ret = kyu_compress_update(strm, io_buf, n_read, comp_buf, &n_comp);
        if (ret != KYU_SUCCESS) goto cleanup;

        if (n_comp > 0) {
            uint32_t chunk_len = (uint32_t)n_comp;
            uint8_t len_buf[4];
            pack_u32_le(len_buf, chunk_len);
            if (write_all(f_out, len_buf, 4) != KYU_SUCCESS) { ret = KYU_ERR_IO; goto cleanup; }

            uint8_t mac[MAC_SIZE];
            crypto_aead_lock(io_buf, mac, ctx.key, ctx.nonce, NULL, 0, comp_buf, n_comp);
            if (write_all(f_out, mac, MAC_SIZE) != KYU_SUCCESS ||
                write_all(f_out, io_buf, n_comp) != KYU_SUCCESS) {
                ret = KYU_ERR_IO;
                goto cleanup;
            }

            increment_nonce(ctx.nonce);
        }
    }
    if (ferror(f_in)) { ret = KYU_ERR_IO; goto cleanup; }

    size_t n_comp = CHUNK_SIZE * 2;
    ret = kyu_compress_end(strm, comp_buf, &n_comp);
    if (ret != KYU_SUCCESS) goto cleanup;
    if (n_comp > 0) {
        uint32_t chunk_len = (uint32_t)n_comp;
        uint8_t len_buf[4];
        pack_u32_le(len_buf, chunk_len);
        if (write_all(f_out, len_buf, 4) != KYU_SUCCESS) { ret = KYU_ERR_IO; goto cleanup; }
        uint8_t mac[MAC_SIZE];
        crypto_aead_lock(io_buf, mac, ctx.key, ctx.nonce, NULL, 0, comp_buf, n_comp);
        if (write_all(f_out, mac, MAC_SIZE) != KYU_SUCCESS ||
            write_all(f_out, io_buf, n_comp) != KYU_SUCCESS) {
            ret = KYU_ERR_IO;
            goto cleanup;
        }
        increment_nonce(ctx.nonce);
    }

    uint8_t eos_buf[4] = {0, 0, 0, 0};
    if (write_all(f_out, eos_buf, 4) != KYU_SUCCESS) { ret = KYU_ERR_IO; goto cleanup; }

    uint8_t man_buf[MANIFEST_SIZE];
    uint8_t man_enc[MANIFEST_SIZE];
    uint8_t mac[MAC_SIZE];
    memset(man_buf, 0, MANIFEST_SIZE);
    pack_u32_le(man_buf, manifest.mode);
    pack_u64_le(man_buf + 4, manifest.mtime);
    pack_u64_le(man_buf + 12, manifest.size);
    memcpy(man_buf + 20, manifest.name, sizeof(manifest.name));

    crypto_aead_lock(man_enc, mac, ctx.key, ctx.nonce, NULL, 0, man_buf, MANIFEST_SIZE);
    if (write_all(f_out, mac, MAC_SIZE) != KYU_SUCCESS ||
        write_all(f_out, man_enc, MANIFEST_SIZE) != KYU_SUCCESS) {
        ret = KYU_ERR_IO;
        goto cleanup;
    }

    ret = KYU_SUCCESS;

cleanup:
    crypto_wipe(man_buf, MANIFEST_SIZE);
    crypto_wipe(man_enc, MANIFEST_SIZE);
    crypto_wipe(mac, MAC_SIZE);
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    wipe_and_free(io_buf, CHUNK_SIZE * 2 + 1024);
    wipe_and_free(comp_buf, CHUNK_SIZE * 2);
    if (strm) {
        crypto_wipe(strm, sizeof(*strm));
        free(strm);
    }
    crypto_wipe(&ctx, sizeof(ctx));
    return ret;
}

/**
 * @brief Decrypt and decompress a QQX5 archive (default KDF).
 *
 * @param[in] in_path Input archive path.
 * @param[in] out_path Output file path.
 * @param[in] password Password for key derivation.
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
                                int *manifest_status) {
    return kyu_archive_decompress_file_ex(in_path, out_path, password, NULL, manifest_out, manifest_status);
}

/**
 * @brief Decrypt and decompress a QQX5 archive with custom KDF parameters.
 *
 * @param[in] in_path Input archive path.
 * @param[in] out_path Output file path.
 * @param[in] password Password for key derivation.
 * @param[in] kdf_params Optional KDF params (NULL uses defaults).
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
                                   int *manifest_status) {
    if (!in_path || !out_path || !password) return KYU_ERR_BAD_ARG;

    if (manifest_status) *manifest_status = 0;
    if (manifest_out) memset(manifest_out, 0, sizeof(*manifest_out));

    int ret = KYU_SUCCESS;
    FILE *f_in = NULL;
    FILE *f_out = NULL;
    kyu_stream *strm = NULL;
    uint8_t *io_buf = NULL;
    uint8_t *comp_buf = NULL;
    uint8_t *out_buf = NULL;
    kyu_crypto ctx = {0};

    f_in = fopen(in_path, "rb");
    if (!f_in) return KYU_ERR_IO;

    f_out = fopen(out_path, "wb");
    if (!f_out) { fclose(f_in); return KYU_ERR_IO; }

    strm = calloc(1, sizeof(kyu_stream));
    io_buf = malloc(CHUNK_SIZE * 2 + 1024);
    comp_buf = malloc(CHUNK_SIZE * 2);
    out_buf = malloc(CHUNK_SIZE * 4);
    if (!strm || !io_buf || !comp_buf || !out_buf) { ret = KYU_ERR_MEMORY; goto cleanup; }

    uint8_t sig[4];
    if (!read_all(f_in, sig, 4) || memcmp(sig, "KYU5", 4)) {
        ret = KYU_ERR_INVALID_HDR;
        goto cleanup;
    }
    if (!read_all(f_in, ctx.salt, SALT_SIZE)) { ret = KYU_ERR_INVALID_HDR; goto cleanup; }
    ret = derive_key(password, ctx.salt, kdf_params, ctx.key);
    if (ret != KYU_SUCCESS) goto cleanup;

    kyu_decompress_init(strm);

    while (1) {
        uint8_t len_buf[4];
        if (!read_all(f_in, len_buf, 4)) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }
        uint32_t chunk_len = unpack_u32_le(len_buf);
        if (chunk_len == 0) break;
        if (chunk_len > CHUNK_SIZE * 2) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }

        uint8_t mac[MAC_SIZE];
        if (!read_all(f_in, mac, MAC_SIZE)) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }
        if (!read_all(f_in, io_buf, chunk_len)) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }

        if (crypto_aead_unlock(comp_buf, mac, ctx.key, ctx.nonce, NULL, 0, io_buf, chunk_len)) {
            ret = KYU_ERR_CRC_MISMATCH;
            goto cleanup;
        }
        increment_nonce(ctx.nonce);

        size_t offset = 0;
        while (offset < chunk_len) {
            size_t in_rem = chunk_len - offset;
            size_t out_len = CHUNK_SIZE * 4;
            ret = kyu_decompress_update(strm, comp_buf + offset, &in_rem, out_buf, &out_len);
            if (out_len > 0 && write_all(f_out, out_buf, out_len) != KYU_SUCCESS) {
                ret = KYU_ERR_IO;
                goto cleanup;
            }
            offset += in_rem;
            if (ret == KYU_ERR_BUF_SMALL) {
                continue;
            }
            if (ret != KYU_SUCCESS) {
                goto cleanup;
            }
        }
    }

    uint8_t mac[MAC_SIZE];
    uint8_t man_enc[MANIFEST_SIZE];
    uint8_t man_buf[MANIFEST_SIZE];
    int local_status = 0;
    if (read_all(f_in, mac, MAC_SIZE) && read_all(f_in, man_enc, MANIFEST_SIZE)) {
        if (crypto_aead_unlock(man_buf, mac, ctx.key, ctx.nonce, NULL, 0, man_enc, MANIFEST_SIZE)) {
            local_status = -1;
        } else {
            kyu_manifest manifest;
            manifest.mode = unpack_u32_le(man_buf);
            manifest.mtime = unpack_u64_le(man_buf + 4);
            manifest.size = unpack_u64_le(man_buf + 12);
            memset(manifest.name, 0, sizeof(manifest.name));
            memcpy(manifest.name, man_buf + 20, sizeof(manifest.name) - 1);
            if (manifest_out) *manifest_out = manifest;
            local_status = 1;
        }
    } else {
        local_status = 0;
    }
    if (manifest_status) *manifest_status = local_status;

    ret = KYU_SUCCESS;

cleanup:
    crypto_wipe(man_buf, MANIFEST_SIZE);
    crypto_wipe(man_enc, MANIFEST_SIZE);
    crypto_wipe(mac, MAC_SIZE);
    if (strm) kyu_decompress_free(strm);
    free(strm);
    wipe_and_free(io_buf, CHUNK_SIZE * 2 + 1024);
    wipe_and_free(comp_buf, CHUNK_SIZE * 2);
    wipe_and_free(out_buf, CHUNK_SIZE * 4);
    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    crypto_wipe(&ctx, sizeof(ctx));
    return ret;
}
