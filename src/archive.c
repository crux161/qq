#include "kyu_archive.h"
#include "monocypher.h"
#include <stdlib.h>
#include <string.h>
#include <time.h> /* For seeding RNG (basic) */

#define CHUNK_MAX 65536
#define MAC_SIZE 16
#define SALT_SIZE 16
#define KEY_SIZE 32
#define HEADER_MAGIC "KYU5"

/* KDF Tuning: Balance Speed vs. Security */
/* 64MB Memory, 3 Iterations */
#define KDF_BLOCKS 64000 
#define KDF_ITERS 3

/* --- Internal Helpers --- */
static void pack_u64_le(uint8_t *b, uint64_t v) {
    for (int i = 0; i < 8; i++) b[i] = (v >> (i * 8)) & 0xFF;
}

static uint64_t unpack_u64_le(const uint8_t *b) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v |= ((uint64_t)b[i] << (i * 8));
    return v;
}

static int file_sink(void *user_data, const void *buf, size_t len) {
    FILE *f = (FILE*)user_data;
    return (fwrite(buf, 1, len, f) == len) ? KYU_SUCCESS : -1;
}

/* --- KDF Implementation --- */

/* Exposed for WASM to call */
void kyu_derive_key(const char *pass, const uint8_t *salt, uint8_t *out_key) {
    void *work_area = malloc(KDF_BLOCKS * 1024);
    if (!work_area) return; 

    /* Fix: Use Monocypher 4.x Struct API */
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_ID,
        .nb_blocks = KDF_BLOCKS,
        .nb_passes = KDF_ITERS,
        .nb_lanes  = 1
    };

    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t *)pass,
        .salt = salt,
        .pass_size = (uint32_t)strlen(pass),
        .salt_size = SALT_SIZE
    };

    crypto_argon2(out_key, KEY_SIZE, work_area, config, inputs, crypto_argon2_no_extras);
    
    free(work_area);
}

/* --- Core Library Logic --- */

int kyu_init(kyu_context *ctx, const uint8_t key[32], kyu_sink_fn sink, void *user_data, int level) {
    if (!ctx || !sink) return KYU_ERR_BAD_ARG;
    memset(ctx, 0, sizeof(kyu_context));
    
    memcpy(ctx->session.key, key, 32);
    ctx->sink = sink;
    ctx->user_data = user_data;
    ctx->level = level;
    
    size_t buf_size = (CHUNK_MAX * 4) + 1024;
    ctx->work_buffer = malloc(buf_size);
    
    kyu_compress_init(&ctx->strm, level);
    return ctx->work_buffer ? KYU_SUCCESS : KYU_ERR_MEMORY;
}

int kyu_push(kyu_context *ctx, const void *data, size_t len, uint32_t flags) {
    if (len > CHUNK_MAX) return KYU_ERR_BUF_SMALL;
    kyu_compress_init(&ctx->strm, ctx->level);

    uint8_t *payload_ptr = (uint8_t*)data;
    size_t payload_len = len;
    uint32_t active_flags = flags;

    size_t comp_len = CHUNK_MAX * 2;
    uint8_t *comp_buf = ctx->work_buffer; 
    
    if (kyu_compress_update(&ctx->strm, data, len, comp_buf, &comp_len) == KYU_SUCCESS) {
        size_t tail = (CHUNK_MAX * 2) - comp_len;
        kyu_compress_end(&ctx->strm, comp_buf + comp_len, &tail);
        comp_len += tail;
        if (comp_len < len) {
            payload_ptr = comp_buf;
            payload_len = comp_len;
            active_flags |= KYU_FLAG_COMPRESSED;
        }
    }

    uint8_t header[16];
    pack_u64_le(header, ctx->session.next_sequence_id);
    pack_u64_le(header + 8, ((uint64_t)active_flags << 32) | (uint32_t)payload_len);

    uint8_t mac[MAC_SIZE];
    uint8_t *encrypted_payload = ctx->work_buffer + (CHUNK_MAX * 2);
    
    crypto_aead_lock(encrypted_payload, mac, ctx->session.key, ctx->session.nonce, 
                     header, 16, payload_ptr, payload_len);

    ctx->sink(ctx->user_data, header, 16);
    ctx->sink(ctx->user_data, mac, MAC_SIZE);
    ctx->sink(ctx->user_data, encrypted_payload, payload_len);

    ctx->session.next_sequence_id++;
    for(int i=0; i<8; i++) if(++ctx->session.nonce[i]) break;

    return KYU_SUCCESS;
}

int kyu_pull(kyu_context *ctx, const void *packet, size_t packet_len) {
    if (packet_len < 32) return KYU_ERR_INVALID_HDR;

    const uint8_t *p = (const uint8_t*)packet;
    uint64_t seq = unpack_u64_le(p);
    uint64_t info = unpack_u64_le(p + 8);
    uint32_t flags = (uint32_t)(info >> 32);
    uint32_t payload_len = (uint32_t)(info & 0xFFFFFFFF);

    if (packet_len < 32 + payload_len) return KYU_ERR_BUF_SMALL;
    if (seq != ctx->session.next_sequence_id) return KYU_ERR_SEQ_MISMATCH;

    uint8_t *dec_buf = ctx->work_buffer; 
    const uint8_t *mac = p + 16;
    const uint8_t *enc_payload = p + 32;

    if (crypto_aead_unlock(dec_buf, mac, ctx->session.key, ctx->session.nonce, 
                           p, 16, enc_payload, payload_len)) {
        return KYU_ERR_CRYPTO_FAIL;
    }

    if (flags & KYU_FLAG_COMPRESSED) {
        kyu_decompress_init(&ctx->strm);
        size_t out_len = CHUNK_MAX * 2;
        uint8_t *out_buf = ctx->work_buffer + (CHUNK_MAX * 2); 
        size_t in_consumed = payload_len;
        int ret = kyu_decompress_update(&ctx->strm, dec_buf, &in_consumed, out_buf, &out_len);
        if (ret != KYU_SUCCESS) return ret;
        ctx->sink(ctx->user_data, out_buf, out_len);
    } else {
        ctx->sink(ctx->user_data, dec_buf, payload_len);
    }

    ctx->session.next_sequence_id++;
    for(int i=0; i<8; i++) if(++ctx->session.nonce[i]) break;

    return KYU_SUCCESS;
}

void kyu_free(kyu_context *ctx) {
    if (!ctx) return;
    if (ctx->work_buffer) {
        crypto_wipe(ctx->work_buffer, (CHUNK_MAX * 4) + 1024);
        free(ctx->work_buffer);
    }
    crypto_wipe(&ctx->session, sizeof(ctx->session));
    memset(ctx, 0, sizeof(kyu_context));
}

int kyu_get_sizeof_context(void) { return sizeof(kyu_context); }

/* --- Archiver High-Level API --- */

int kyu_archive_compress_stream(FILE *in, FILE *out, const char *pass, 
                                const void *params, int level, 
                                const kyu_manifest *tmpl, kyu_manifest *out_man) 
{
    (void)params; (void)tmpl; (void)out_man;
    kyu_context ctx;
    uint8_t salt[SALT_SIZE];
    uint8_t key[KEY_SIZE];

    srand((unsigned int)time(NULL)); 
    for(int i=0; i<SALT_SIZE; i++) salt[i] = (uint8_t)(rand() & 0xFF);

    fwrite(HEADER_MAGIC, 1, 4, out);
    fwrite(salt, 1, SALT_SIZE, out);

    kyu_derive_key(pass, salt, key);

    if (kyu_init(&ctx, key, file_sink, out, level) != KYU_SUCCESS) return KYU_ERR_MEMORY;

    uint8_t buf[CHUNK_MAX];
    size_t n;
    while ((n = fread(buf, 1, CHUNK_MAX, in)) > 0) {
        if (kyu_push(&ctx, buf, n, 0) != KYU_SUCCESS) {
            kyu_free(&ctx);
            return KYU_ERR_GENERIC;
        }
    }
    
    kyu_free(&ctx);
    return KYU_SUCCESS;
}

int kyu_archive_decompress_stream(FILE *in, kyu_write_fn write_cb, void *write_ctx,
                                  const char *pass, const void *params, 
                                  kyu_manifest *out_man, int *status) 
{
    (void)params; (void)out_man; 
    kyu_context ctx;
    uint8_t header[4];
    uint8_t salt[SALT_SIZE];
    uint8_t key[KEY_SIZE];

    if (fread(header, 1, 4, in) != 4 || memcmp(header, HEADER_MAGIC, 4) != 0) {
        rewind(in);
        return KYU_ERR_INVALID_HDR;
    }
    
    if (fread(salt, 1, SALT_SIZE, in) != SALT_SIZE) return KYU_ERR_INVALID_HDR;

    kyu_derive_key(pass, salt, key);

    if (kyu_init(&ctx, key, (kyu_sink_fn)write_cb, write_ctx, 0) != KYU_SUCCESS) {
        if (status) *status = KYU_ERR_MEMORY;
        return KYU_ERR_MEMORY;
    }

    uint8_t *packet_buf = malloc(CHUNK_MAX + 128);
    int err = KYU_SUCCESS;
    size_t header_size = 16;
    size_t mac_size = 16;
    
    while (1) {
        size_t n = fread(packet_buf, 1, header_size, in);
        if (n == 0) break; 
        if (n < header_size) { err = KYU_ERR_INVALID_HDR; break; }

        uint64_t info = unpack_u64_le(packet_buf + 8);
        uint32_t payload_len = (uint32_t)(info & 0xFFFFFFFF);
        size_t needed = mac_size + payload_len;
        
        if (fread(packet_buf + header_size, 1, needed, in) < needed) {
            err = KYU_ERR_BUF_SMALL; break;
        }
        
        int ret = kyu_pull(&ctx, packet_buf, header_size + needed);
        if (ret != KYU_SUCCESS) { err = ret; break; }
    }

    free(packet_buf);
    kyu_free(&ctx);
    if (status) *status = err;
    return err;
}

/* Legacy Shim */
kyu_writer* kyu_writer_init(FILE *out_stream, const char *password, const void *params, int level) {
    (void)params; /* Silenced unused parameter warning */
    kyu_writer *w = malloc(sizeof(kyu_writer));
    uint8_t salt[SALT_SIZE];
    uint8_t key[KEY_SIZE];

    srand((unsigned int)time(NULL)); 
    for(int i=0; i<SALT_SIZE; i++) salt[i] = (uint8_t)(rand() & 0xFF);
    
    fwrite(HEADER_MAGIC, 1, 4, out_stream);
    fwrite(salt, 1, SALT_SIZE, out_stream);
    
    kyu_derive_key(password, salt, key);
    
    if (kyu_init(w, key, file_sink, out_stream, level) != KYU_SUCCESS) {
        free(w); return NULL;
    }
    return w;
}
int kyu_writer_update(kyu_writer *w, const void *data, size_t len) { return kyu_push(w, data, len, 0); }
int kyu_writer_finalize(kyu_writer *w, const kyu_manifest *tmpl) { (void)tmpl; kyu_free(w); free(w); return KYU_SUCCESS; }
