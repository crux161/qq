/* kyu/include/kyu.h */
#ifndef KYU_H
#define KYU_H

#include <stddef.h>
#include <stdint.h>

/* Error Codes */
#define KYU_SUCCESS 0
#define KYU_ERR_BAD_ARG -1
#define KYU_ERR_MEMORY -2
#define KYU_ERR_BUF_SMALL -3
#define KYU_ERR_INVALID_HDR -4
#define KYU_ERR_DATA_CORRUPT -5
#define KYU_ERR_CRC_MISMATCH -6
#define KYU_ERR_IO -7

/* Internal State */
#define KYU_WINDOW_SIZE 32768
#define KYU_HASH_SIZE 32768

typedef struct {
    uint8_t window[KYU_WINDOW_SIZE];
    int32_t head[KYU_HASH_SIZE];
    int32_t prev[KYU_WINDOW_SIZE];
    size_t window_pos;
    
    /* Bitstream State */
    uint64_t bit_buf;
    int bit_count;

    /* RLE / Literal Buffer */
    uint8_t freq_buf[256]; /* Used for buffering literals */
    uint32_t pending_len;

    /* Configuration */
    int chain_max;    /* Max hash chain search depth */
    int lazy_match;   /* 0 = Greedy, 1 = Lazy */
} kyu_stream;

/* API */
/* CHANGED: Now accepts level (1-9) */
int kyu_compress_init(kyu_stream *strm, int level);
int kyu_compress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len);
int kyu_compress_end(kyu_stream *strm, uint8_t *out, size_t *out_len);

int kyu_decompress_init(kyu_stream *strm);
int kyu_decompress_update(kyu_stream *strm, const uint8_t *in, size_t *in_len, uint8_t *out, size_t *out_len);
void kyu_decompress_free(kyu_stream *strm);

#endif
