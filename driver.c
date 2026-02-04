#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "kyu.h"
#include "monocypher.h"

#define CHUNK_SIZE 65536
#define MAC_SIZE 16
#define NONCE_SIZE 24
#define KEY_SIZE 32
#define SALT_SIZE 16

/* --- Manifest Structure (Serialized) --- */
#define MANIFEST_SIZE (4 + 8 + 8 + 256)

typedef struct {
    uint32_t mode;
    uint64_t mtime;
    uint64_t size;
    char name[256];
} kyu_manifest;

typedef struct {
    uint8_t key[KEY_SIZE];
    uint8_t nonce[NONCE_SIZE];
    uint8_t salt[SALT_SIZE];
} kyu_crypto;

/* --- Helpers --- */

static void increment_nonce(uint8_t *nonce) {
    for (int i = 0; i < 8; i++) {
        nonce[i]++;
        if (nonce[i] != 0) break;
    }
}

static void secure_random(uint8_t *buf, size_t len) {
    #if defined(__APPLE__) || defined(__OpenBSD__) || defined(__FreeBSD__)
        arc4random_buf(buf, len);
        return;
    #endif

    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) {
        fprintf(stderr, "CRITICAL: CSTP RNG Failure. Aborting.\n");
        exit(1);
    }
    if (fread(buf, 1, len, f) != len) {
        fprintf(stderr, "CRITICAL: RNG Short Read. Aborting.\n");
        exit(1);
    }
    fclose(f);
}

static void derive_key(const char *pass, uint8_t *salt, uint8_t *key) {
    if (!pass) {
        fprintf(stderr, "ERROR: Password required for Phase 3 security.\n");
        exit(1);
    }
    
    crypto_argon2_config config = {
        .algorithm = CRYPTO_ARGON2_I,
        .nb_blocks = 1024,
        .nb_passes = 3,
        .nb_lanes = 1
    };
    
    crypto_argon2_inputs inputs = {
        .pass = (const uint8_t*)pass,
        .pass_size = (uint32_t)strlen(pass),
        .salt = salt,
        .salt_size = SALT_SIZE
    };
    
    crypto_argon2_extras extras = {0};
    
    void *work_area = malloc(config.nb_blocks * 1024);
    if (!work_area) { fprintf(stderr, "Memory Error\n"); exit(1); }
    
    crypto_argon2(key, KEY_SIZE, work_area, config, inputs, extras);
    free(work_area);
}

/* --- Serialization Helpers --- */
static void pack_u32(uint8_t *b, uint32_t v) { memcpy(b, &v, 4); }
static void pack_u64(uint8_t *b, uint64_t v) { memcpy(b, &v, 8); }
static uint32_t unpack_u32(const uint8_t *b) { uint32_t v; memcpy(&v, b, 4); return v; }
static uint64_t unpack_u64(const uint8_t *b) { uint64_t v; memcpy(&v, b, 8); return v; }

/* --- Main Driver --- */

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("Kyu Archiver (QQX5) - Usage: %s -c|-d <in> <out> [password]\n", argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *in_path = argv[2];
    const char *out_path = argv[3];
    const char *pass = (argc >= 5) ? argv[4] : NULL;

    FILE *f_in = fopen(in_path, "rb");
    FILE *f_out = fopen(out_path, "wb");
    if (!f_in || !f_out) { perror("File Error"); return 1; }

    kyu_stream *strm = calloc(1, sizeof(kyu_stream));
    kyu_crypto ctx = {0};
    uint8_t *io_buf = malloc(CHUNK_SIZE * 2 + 1024); 
    uint8_t *comp_buf = malloc(CHUNK_SIZE * 2);

    if (strcmp(mode, "-c") == 0) {
        /* --- COMPRESS & ENCRYPT --- */
        
        struct stat st;
        if (stat(in_path, &st) != 0) { perror("Stat failed"); return 1; }
        
        secure_random(ctx.salt, SALT_SIZE);
        derive_key(pass, ctx.salt, ctx.key);

        fwrite("KYU5", 1, 4, f_out);
        fwrite(ctx.salt, 1, SALT_SIZE, f_out);
        
        kyu_compress_init(strm);
        
        size_t n_read;
        
        while ((n_read = fread(io_buf, 1, CHUNK_SIZE, f_in)) > 0) {
            size_t n_comp = CHUNK_SIZE * 2;
            int ret = kyu_compress_update(strm, io_buf, n_read, comp_buf, &n_comp);
            if (ret != KYU_SUCCESS) return 1;
            
            /* FIX: Only write non-empty chunks. Empty chunks (n_comp=0) are
               valid in streaming (buffering) but kill the decryptor which sees 0 as EOS. */
            if (n_comp > 0) {
                uint32_t chunk_len = (uint32_t)n_comp;
                fwrite(&chunk_len, 1, 4, f_out);
                
                uint8_t mac[MAC_SIZE];
                crypto_aead_lock(io_buf, mac, ctx.key, ctx.nonce, NULL, 0, comp_buf, n_comp);
                fwrite(mac, 1, MAC_SIZE, f_out);
                fwrite(io_buf, 1, n_comp, f_out);
                
                increment_nonce(ctx.nonce);
            }
        }
        
        size_t n_comp = CHUNK_SIZE * 2;
        kyu_compress_end(strm, comp_buf, &n_comp);
        if (n_comp > 0) {
            uint32_t chunk_len = (uint32_t)n_comp;
            fwrite(&chunk_len, 1, 4, f_out);
            uint8_t mac[MAC_SIZE];
            crypto_aead_lock(io_buf, mac, ctx.key, ctx.nonce, NULL, 0, comp_buf, n_comp);
            fwrite(mac, 1, MAC_SIZE, f_out);
            fwrite(io_buf, 1, n_comp, f_out);
            increment_nonce(ctx.nonce);
        }

        /* Write End-of-Stream Marker (Length 0) */
        uint32_t eos = 0;
        fwrite(&eos, 1, 4, f_out);

        /* Create & Write Tail Manifest */
        uint8_t man_buf[MANIFEST_SIZE];
        memset(man_buf, 0, MANIFEST_SIZE);
        
        const char *base = strrchr(in_path, '/');
        if (!base) base = in_path; else base++;
        strncpy((char*)(man_buf + 20), base, 255);
        
        pack_u32(man_buf, st.st_mode);
        pack_u64(man_buf + 4, (uint64_t)st.st_mtime);
        pack_u64(man_buf + 12, (uint64_t)st.st_size);

        uint8_t man_enc[MANIFEST_SIZE];
        uint8_t mac[MAC_SIZE];
        crypto_aead_lock(man_enc, mac, ctx.key, ctx.nonce, NULL, 0, man_buf, MANIFEST_SIZE);
        
        fwrite(mac, 1, MAC_SIZE, f_out);
        fwrite(man_enc, 1, MANIFEST_SIZE, f_out);

        printf("Archived: %s (Original: %llu bytes)\n", base, (unsigned long long)st.st_size);

    } else if (strcmp(mode, "-d") == 0) {
        /* --- DECRYPT & RESTORE --- */
        
        uint8_t sig[4];
        if (fread(sig, 1, 4, f_in) != 4 || memcmp(sig, "KYU5", 4)) {
            printf("Invalid Format.\n"); return KYU_ERR_INVALID_HDR;
        }
        
        if (fread(ctx.salt, 1, SALT_SIZE, f_in) != SALT_SIZE) return KYU_ERR_INVALID_HDR;
        derive_key(pass, ctx.salt, ctx.key);
        
        kyu_decompress_init(strm);
        
        while (1) {
            uint32_t chunk_len;
            if (fread(&chunk_len, 1, 4, f_in) != 4) break; 
            
            if (chunk_len == 0) {
                printf("End of Stream Reached. Reading Manifest...\n");
                break; 
            }
            if (chunk_len > CHUNK_SIZE * 2) return KYU_ERR_DATA_CORRUPT;
            
            uint8_t mac[MAC_SIZE];
            if (fread(mac, 1, MAC_SIZE, f_in) != MAC_SIZE) return KYU_ERR_DATA_CORRUPT;
            
            if (fread(io_buf, 1, chunk_len, f_in) != chunk_len) return KYU_ERR_DATA_CORRUPT;
            
            if (crypto_aead_unlock(comp_buf, mac, ctx.key, ctx.nonce, NULL, 0, io_buf, chunk_len)) {
                printf("SECURITY ALERT: MAC Mismatch in Data Stream!\n");
                return KYU_ERR_CRC_MISMATCH;
            }
            increment_nonce(ctx.nonce);
            
            size_t n_out = CHUNK_SIZE * 4;
            uint8_t *final_out = malloc(CHUNK_SIZE * 4); 
            int ret = kyu_decompress_update(strm, comp_buf, chunk_len, final_out, &n_out);
            if (ret != KYU_SUCCESS) return ret;
            if (n_out > 0) fwrite(final_out, 1, n_out, f_out);
            free(final_out);
        }

        uint8_t mac[MAC_SIZE];
        uint8_t man_enc[MANIFEST_SIZE];
        uint8_t man_buf[MANIFEST_SIZE];
        
        if (fread(mac, 1, MAC_SIZE, f_in) == MAC_SIZE && 
            fread(man_enc, 1, MANIFEST_SIZE, f_in) == MANIFEST_SIZE) {
            
            if (crypto_aead_unlock(man_buf, mac, ctx.key, ctx.nonce, NULL, 0, man_enc, MANIFEST_SIZE)) {
                 printf("SECURITY ALERT: Manifest Tampered!\n");
            } else {
                uint32_t mode = unpack_u32(man_buf);
                uint64_t mtime = unpack_u64(man_buf + 4);
                char *name = (char*)(man_buf + 20);
                
                printf("Restoring Metadata for: %s\n", name);
                
                chmod(out_path, mode & 0777);
                struct timeval times[2];
                times[0].tv_sec = mtime; times[0].tv_usec = 0; 
                times[1].tv_sec = mtime; times[1].tv_usec = 0; 
                utimes(out_path, times);
            }
        } else {
            printf("Warning: No Manifest Found.\n");
        }
    }

    free(io_buf);
    free(comp_buf);
    free(strm);
    fclose(f_in);
    fclose(f_out);
    return 0;
}
