/**
 * @file archive.c
 * @brief High-level archive format (QQX5) with Adaptive Compression.
 */

#include "kyu.h"
#include "kyu_archive.h"
#include "monocypher.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* Headers required for struct stat */
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK_SIZE 65536
#define MAC_SIZE 16
#define SALT_SIZE 16
#define KEY_SIZE 32
#define NONCE_SIZE 24
#define MANIFEST_SIZE (4 + 8 + 8 + 256)
#define KYU_CHUNK_FLAG_COMPRESSED 0x80000000

/* --- Types --- */

typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t salt[SALT_SIZE];
} kyu_crypto;

struct kyu_writer_t {
    FILE *out;
    kyu_stream *strm;
    uint8_t *comp_buf; 
    uint8_t *temp_buf; 
    kyu_crypto ctx;
    uint64_t total_in;
    int level;
};

const kyu_kdf_params kyu_kdf_default_params = { KYU_KDF_ARGON2_ID, 1024, 3, 1 };

/* --- Helpers --- */

static void increment_nonce(uint8_t *nonce) {
    for (int i = 0; i < 8; i++) {
        nonce[i]++;
        if (nonce[i] != 0) break;
    }
}

static int secure_random(uint8_t *buf, size_t len) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return KYU_ERR_IO;
    if (fread(buf, 1, len, f) != len) { fclose(f); return KYU_ERR_IO; }
    fclose(f);
    return KYU_SUCCESS;
}

static int derive_key(const char *pass, const uint8_t *salt, const kyu_kdf_params *params, uint8_t *key) {
    if (!pass) return KYU_ERR_BAD_ARG;
    const kyu_kdf_params *p = params ? params : &kyu_kdf_default_params;
    crypto_argon2_config config = { .algorithm = p->algorithm, .nb_blocks = p->nb_blocks, .nb_passes = p->nb_passes, .nb_lanes = p->nb_lanes };
    crypto_argon2_inputs inputs = { .pass = (const uint8_t*)pass, .pass_size = (uint32_t)strlen(pass), .salt = salt, .salt_size = SALT_SIZE };
    crypto_argon2_extras extras = {0};
    void *work_area = malloc((size_t)config.nb_blocks * 1024);
    if (!work_area) return KYU_ERR_MEMORY;
    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, extras);
    crypto_wipe(work_area, (size_t)config.nb_blocks * 1024);
    free(work_area);
    return KYU_SUCCESS;
}

static int write_all(FILE *f, const void *buf, size_t len) {
    return (fwrite(buf, 1, len, f) == len) ? KYU_SUCCESS : KYU_ERR_IO;
}

static int read_all(FILE *f, void *buf, size_t len) {
    return (fread(buf, 1, len, f) == len);
}

static void pack_u32_le(uint8_t *b, uint32_t v) {
    b[0] = (uint8_t)(v); b[1] = (uint8_t)(v >> 8); b[2] = (uint8_t)(v >> 16); b[3] = (uint8_t)(v >> 24);
}
static void pack_u64_le(uint8_t *b, uint64_t v) {
    pack_u32_le(b, (uint32_t)v); pack_u32_le(b + 4, (uint32_t)(v >> 32));
}
static uint32_t unpack_u32_le(const uint8_t *b) {
    return (uint32_t)b[0] | ((uint32_t)b[1] << 8) | ((uint32_t)b[2] << 16) | ((uint32_t)b[3] << 24);
}
static uint64_t unpack_u64_le(const uint8_t *b) {
    return (uint64_t)unpack_u32_le(b) | ((uint64_t)unpack_u32_le(b + 4) << 32);
}

static void wipe_and_free(void *buf, size_t len) {
    if (!buf) return;
    crypto_wipe(buf, len);
    free(buf);
}

static int file_write_wrapper(void *ctx, const void *buf, size_t len) {
    FILE *f = (FILE*)ctx;
    return (fwrite(buf, 1, len, f) == len) ? KYU_SUCCESS : KYU_ERR_IO;
}

/* --- Writer Implementation (Adaptive) --- */

kyu_writer* kyu_writer_init(FILE *out_stream, const char *password, const kyu_kdf_params *kdf_params, int level) {
    if (!out_stream || !password) return NULL;
    kyu_writer *w = calloc(1, sizeof(kyu_writer));
    if (!w) return NULL;
    w->out = out_stream;
    w->strm = calloc(1, sizeof(kyu_stream));
    w->comp_buf = malloc(CHUNK_SIZE * 2); 
    w->temp_buf = malloc(CHUNK_SIZE * 2 + 1024);
    w->level = (level < 1) ? 6 : level;
    if (!w->strm || !w->comp_buf || !w->temp_buf) { kyu_writer_free(w); return NULL; }

    if (secure_random(w->ctx.salt, SALT_SIZE) != 0) { kyu_writer_free(w); return NULL; }
    if (derive_key(password, w->ctx.salt, kdf_params, w->ctx.key) != 0) { kyu_writer_free(w); return NULL; }

    fwrite("KYU5", 1, 4, w->out);
    fwrite(w->ctx.salt, 1, SALT_SIZE, w->out);
    return w;
}

int kyu_writer_update(kyu_writer *w, const void *data, size_t len) {
    if (!w) return KYU_ERR_BAD_ARG;
    w->total_in += len;
    
    const uint8_t *src = (const uint8_t*)data;
    size_t rem = len;
    
    kyu_compress_init(w->strm, w->level); 

    /* 1. Try Compression */
    size_t comp_len = CHUNK_SIZE * 2;
    int ret = kyu_compress_update(w->strm, src, rem, w->comp_buf, &comp_len);
    if (ret != KYU_SUCCESS) return ret;
    
    size_t tail_len = CHUNK_SIZE * 2 - comp_len;
    ret = kyu_compress_end(w->strm, w->comp_buf + comp_len, &tail_len);
    if (ret != KYU_SUCCESS) return ret;
    comp_len += tail_len;

    /* 2. Adaptive Decision */
    int use_compressed = (comp_len < rem);
    
    /* 3. Header */
    uint32_t final_len = (uint32_t)(use_compressed ? comp_len : rem);
    uint32_t len_field = final_len;
    if (use_compressed) len_field |= KYU_CHUNK_FLAG_COMPRESSED;
    
    uint8_t len_buf[4];
    pack_u32_le(len_buf, len_field);
    if (write_all(w->out, len_buf, 4) != KYU_SUCCESS) return KYU_ERR_IO;

    /* 4. Encrypt */
    uint8_t mac[MAC_SIZE];
    const uint8_t *payload = use_compressed ? w->comp_buf : src;
    
    crypto_aead_lock(w->temp_buf, mac, w->ctx.key, w->ctx.nonce, NULL, 0, payload, final_len);
    
    if (write_all(w->out, mac, MAC_SIZE) != KYU_SUCCESS ||
        write_all(w->out, w->temp_buf, final_len) != KYU_SUCCESS) return KYU_ERR_IO;

    increment_nonce(w->ctx.nonce);
    return KYU_SUCCESS;
}

int kyu_writer_finalize(kyu_writer *w, const kyu_manifest *tmpl) {
    if (!w) return KYU_ERR_BAD_ARG;
    
    uint8_t eos[4] = {0};
    write_all(w->out, eos, 4);

    kyu_manifest man = {0};
    if (tmpl) man = *tmpl;
    man.size = w->total_in;

    uint8_t man_buf[MANIFEST_SIZE];
    uint8_t man_enc[MANIFEST_SIZE];
    uint8_t mac[MAC_SIZE];
    memset(man_buf, 0, MANIFEST_SIZE);
    pack_u32_le(man_buf, man.mode);
    pack_u64_le(man_buf + 4, man.mtime);
    pack_u64_le(man_buf + 12, man.size);
    strncpy(man.name, tmpl ? tmpl->name : "stream", 255);
    man.name[255] = '\0';
    memcpy(man_buf + 20, man.name, 256);

    crypto_aead_lock(man_enc, mac, w->ctx.key, w->ctx.nonce, NULL, 0, man_buf, MANIFEST_SIZE);
    write_all(w->out, mac, MAC_SIZE);
    write_all(w->out, man_enc, MANIFEST_SIZE);

    kyu_writer_free(w);
    return KYU_SUCCESS;
}

void kyu_writer_free(kyu_writer *w) {
    if (!w) return;
    if (w->strm) { crypto_wipe(w->strm, sizeof(kyu_stream)); free(w->strm); }
    if (w->comp_buf) { crypto_wipe(w->comp_buf, CHUNK_SIZE*2); free(w->comp_buf); }
    if (w->temp_buf) { crypto_wipe(w->temp_buf, CHUNK_SIZE*2); free(w->temp_buf); }
    crypto_wipe(&w->ctx, sizeof(kyu_crypto));
    free(w);
}

/* --- Decompression (Adaptive) --- */

int kyu_archive_decompress_stream(FILE *in_stream,
                                  kyu_write_fn write_fn,
                                  void *write_ctx,
                                  const char *password,
                                  const kyu_kdf_params *kdf_params,
                                  kyu_manifest *manifest_out,
                                  int *manifest_status) {
    if (!in_stream || !write_fn || !password) return KYU_ERR_BAD_ARG;

    if (manifest_status) *manifest_status = 0;
    if (manifest_out) memset(manifest_out, 0, sizeof(*manifest_out));

    int ret = KYU_SUCCESS;
    kyu_stream *strm = calloc(1, sizeof(kyu_stream));
    uint8_t *io_buf = malloc(CHUNK_SIZE * 2 + 1024);
    uint8_t *comp_buf = malloc(CHUNK_SIZE * 2);
    uint8_t *out_buf = malloc(CHUNK_SIZE * 4);
    kyu_crypto ctx = {0};

    if (!strm || !io_buf || !comp_buf || !out_buf) { ret = KYU_ERR_MEMORY; goto cleanup; }

    uint8_t sig[4];
    if (!read_all(in_stream, sig, 4) || memcmp(sig, "KYU5", 4)) { ret = KYU_ERR_INVALID_HDR; goto cleanup; }
    if (!read_all(in_stream, ctx.salt, SALT_SIZE)) { ret = KYU_ERR_INVALID_HDR; goto cleanup; }
    ret = derive_key(password, ctx.salt, kdf_params, ctx.key);
    if (ret != KYU_SUCCESS) goto cleanup;

    while (1) {
        uint8_t len_buf[4];
        if (!read_all(in_stream, len_buf, 4)) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }
        uint32_t raw_len_field = unpack_u32_le(len_buf);
        
        if (raw_len_field == 0) break;
        
        /* FIX: Boolean check avoids signedness warning */
        int is_compressed = (raw_len_field & KYU_CHUNK_FLAG_COMPRESSED) != 0;
        uint32_t chunk_len = raw_len_field & ~KYU_CHUNK_FLAG_COMPRESSED;

        if (chunk_len > CHUNK_SIZE * 2) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }

        uint8_t mac[MAC_SIZE];
        if (!read_all(in_stream, mac, MAC_SIZE)) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }
        if (!read_all(in_stream, io_buf, chunk_len)) { ret = KYU_ERR_DATA_CORRUPT; goto cleanup; }

        if (crypto_aead_unlock(comp_buf, mac, ctx.key, ctx.nonce, NULL, 0, io_buf, chunk_len)) {
            ret = KYU_ERR_CRC_MISMATCH; goto cleanup;
        }
        increment_nonce(ctx.nonce);

        if (is_compressed) {
            kyu_decompress_init(strm); 
            size_t offset = 0;
            while (offset < chunk_len) {
                size_t available_in = chunk_len - offset;
                size_t in_param = available_in;
                size_t out_len = CHUNK_SIZE * 4;

                ret = kyu_decompress_update(strm, comp_buf + offset, &in_param, out_buf, &out_len);
                
                size_t consumed = available_in - in_param;
                offset += consumed;

                if (out_len > 0) {
                    if (write_fn(write_ctx, out_buf, out_len) != KYU_SUCCESS) {
                        ret = KYU_ERR_IO; goto cleanup;
                    }
                }
                if (ret == KYU_ERR_BUF_SMALL) continue; 
                if (ret != KYU_SUCCESS) goto cleanup;
                if (consumed == 0 && out_len == 0) break;
            }
        } else {
            /* Raw */
            if (write_fn(write_ctx, comp_buf, chunk_len) != KYU_SUCCESS) {
                ret = KYU_ERR_IO; goto cleanup;
            }
        }
    }

    uint8_t mac[MAC_SIZE];
    uint8_t man_enc[MANIFEST_SIZE];
    uint8_t man_buf[MANIFEST_SIZE];
    if (read_all(in_stream, mac, MAC_SIZE) && read_all(in_stream, man_enc, MANIFEST_SIZE)) {
        if (crypto_aead_unlock(man_buf, mac, ctx.key, ctx.nonce, NULL, 0, man_enc, MANIFEST_SIZE)) {
            if (manifest_status) *manifest_status = -1;
        } else {
            if (manifest_out) {
                manifest_out->mode = unpack_u32_le(man_buf);
                manifest_out->mtime = unpack_u64_le(man_buf + 4);
                manifest_out->size = unpack_u64_le(man_buf + 12);
                memcpy(manifest_out->name, man_buf + 20, 256);
            }
            if (manifest_status) *manifest_status = 1;
        }
    }

cleanup:
    if (strm) { kyu_decompress_free(strm); free(strm); }
    wipe_and_free(io_buf, CHUNK_SIZE * 2 + 1024);
    wipe_and_free(comp_buf, CHUNK_SIZE * 2);
    wipe_and_free(out_buf, CHUNK_SIZE * 4);
    crypto_wipe(&ctx, sizeof(ctx));
    return ret;
}

int kyu_archive_compress_stream(FILE *in, FILE *out, const char *pass, 
                                const kyu_kdf_params *params, 
                                const kyu_manifest *tmpl, kyu_manifest *out_man) {
    kyu_writer *w = kyu_writer_init(out, pass, params, 6);
    if (!w) return KYU_ERR_MEMORY;
    uint8_t buf[CHUNK_SIZE];
    size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (kyu_writer_update(w, buf, n) != 0) { kyu_writer_free(w); return KYU_ERR_IO; }
    }
    if (out_man && tmpl) *out_man = *tmpl; 
    return kyu_writer_finalize(w, tmpl);
}

int kyu_archive_compress_file(const char *in, const char *out, const char *pass, kyu_manifest *man) {
    FILE *fi = fopen(in, "rb"); if (!fi) return KYU_ERR_IO;
    FILE *fo = fopen(out, "wb"); if (!fo) { fclose(fi); return KYU_ERR_IO; }
    
    /* FIX: Struct stat is now known thanks to sys/stat.h */
    kyu_manifest tmpl = {0};
    struct stat st;
    if (stat(in, &st) == 0) {
        tmpl.mode = (uint32_t)st.st_mode;
        tmpl.mtime = (uint64_t)st.st_mtime;
        const char *b = strrchr(in, '/');
        strncpy(tmpl.name, b ? b+1 : in, 255);
    }
    
    int r = kyu_archive_compress_stream(fi, fo, pass, NULL, &tmpl, man);
    fclose(fi); fclose(fo); return r;
}

int kyu_archive_decompress_file(const char *in, const char *out, const char *pass, kyu_manifest *man, int *st) {
    FILE *fi = fopen(in, "rb"); if (!fi) return KYU_ERR_IO;
    FILE *fo = fopen(out, "wb"); if (!fo) { fclose(fi); return KYU_ERR_IO; }
    int r = kyu_archive_decompress_stream(fi, file_write_wrapper, fo, pass, NULL, man, st);
    fclose(fi); fclose(fo); return r;
}
