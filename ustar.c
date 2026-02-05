#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <sys/stat.h>

#include "kyu_archive.h"

#define USTAR_BLOCK 512

/* --- Helpers (Defined at top to avoid implicit declaration errors) --- */

static void write_octal(char *dst, int width, uint64_t value) {
    char fmt[16];
    snprintf(fmt, sizeof(fmt), "%%0%dllo", width - 1);
    snprintf(dst, width, fmt, (unsigned long long)value);
}

static uint64_t parse_octal(const char *p, int len) {
    uint64_t v = 0;
    while (len > 0 && (*p == ' ' || *p == '0')) { p++; len--; } 
    while (len-- > 0 && *p >= '0' && *p <= '7') {
        v = (v << 3) | ((uint64_t)(*p++ - '0'));
    }
    return v;
}

/* --- Writer Functions --- */

int kyu_ustar_write_header(kyu_writer *w, const char *path, const struct stat *st) {
    uint8_t h[USTAR_BLOCK];
    memset(h, 0, USTAR_BLOCK);

    /* 1. Sanitize Path */
    char safe_path[100];
    strncpy(safe_path, path, 99);
    safe_path[99] = '\0';
    
    int is_dir = S_ISDIR(st->st_mode);
    
    /* Directories must have size 0 for TAR compatibility */
    uint64_t size = is_dir ? 0 : (uint64_t)st->st_size;

    /* Append trailing slash for directories if missing */
    if (is_dir) {
        size_t len = strlen(safe_path);
        if (len < 99 && safe_path[len-1] != '/') {
            safe_path[len] = '/';
            safe_path[len+1] = '\0';
        }
    }

    /* 2. Write Fields */
    strncpy((char*)h, safe_path, 100);
    write_octal((char*)h + 100, 8, (uint64_t)(st->st_mode & 0777));
    write_octal((char*)h + 108, 8, (uint64_t)st->st_uid);
    write_octal((char*)h + 116, 8, (uint64_t)st->st_gid);
    write_octal((char*)h + 124, 12, size);
    write_octal((char*)h + 136, 12, (uint64_t)st->st_mtime);

    /* Typeflag: '5' = Dir, '0' = File */
    h[156] = is_dir ? '5' : '0';

    memcpy(h + 257, "ustar", 6);
    memcpy(h + 263, "00", 2);

    /* 3. Checksum */
    memset(h + 148, ' ', 8);
    unsigned int sum = 0;
    for (int i=0; i<USTAR_BLOCK; i++) sum += h[i];
    write_octal((char*)h + 148, 7, sum);

    return kyu_writer_update(w, h, USTAR_BLOCK);
}

int kyu_ustar_write_padding(kyu_writer *w, size_t size) {
    size_t rem = size % USTAR_BLOCK;
    if (rem != 0) {
        size_t pad = USTAR_BLOCK - rem;
        uint8_t zeros[USTAR_BLOCK] = {0};
        return kyu_writer_update(w, zeros, pad);
    }
    return 0;
}

int kyu_ustar_write_end(kyu_writer *w) {
    uint8_t zeros[USTAR_BLOCK * 2] = {0};
    return kyu_writer_update(w, zeros, sizeof(zeros));
}

/* --- List/Reader Functions --- */

int kyu_ustar_list_callback(void *ctx, const void *buf, size_t len) {
    kyu_ustar_lister_ctx *l = (kyu_ustar_lister_ctx*)ctx;
    const uint8_t *p = (const uint8_t*)buf;
    
    while (len > 0) {
        /* Mode 1: Skipping file body */
        if (l->bytes_to_skip > 0) {
            size_t skip = (len > l->bytes_to_skip) ? (size_t)l->bytes_to_skip : len;
            l->bytes_to_skip -= skip;
            p += skip;
            len -= skip;
            continue;
        }

        /* Mode 2: Buffering header */
        size_t needed = 512 - l->buf_pos;
        size_t copy = (len > needed) ? needed : len;
        memcpy(l->buffer + l->buf_pos, p, copy);
        l->buf_pos += copy;
        p += copy;
        len -= copy;

        /* Process Header if full */
        if (l->buf_pos == 512) {
            l->buf_pos = 0; // Reset
            
            /* Check Magic */
            if (memcmp(l->buffer + 257, "ustar", 5) == 0) {
                char name[101];
                snprintf(name, 100, "%s", l->buffer);
                
                char size_str[12];
                memcpy(size_str, l->buffer + 124, 12);
                uint64_t size = parse_octal(size_str, 12);
                
                printf("%10llu  %s\n", (unsigned long long)size, name);
                
                /* Calculate padding to skip */
                uint64_t blocks = (size + 511) / 512;
                l->bytes_to_skip = blocks * 512;
            }
        }
    }
    return 0;
}

