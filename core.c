/**
 * @file core.c
 * @brief Compression/decompression core for Kyu (LZ77 + Huffman).
 */

#include "kyu.h"
#include <stdlib.h>
#include <string.h>

/* --- Internal Structures --- */

/**
 * @brief Huffman tree node.
 */
typedef struct Node {
    int symbol; 
    uint32_t freq; 
    int seq; 
    struct Node *left, *right; 
} Node;

/**
 * @brief Minimal binary heap for building Huffman trees.
 */
typedef struct { 
    Node **nodes; 
    int size; 
} MinHeap;

enum { PENDING_NONE = 0, PENDING_LITERAL = 1, PENDING_MATCH = 2 };

/**
 * @brief Pack a 32-bit integer as little-endian.
 *
 * @param[out] out Output buffer (4 bytes).
 * @param[in] v Value to pack.
 * @return None.
 */
static void pack_u32_le(uint8_t out[4], uint32_t v) {
    out[0] = (uint8_t)(v & 0xFFu);
    out[1] = (uint8_t)((v >> 8) & 0xFFu);
    out[2] = (uint8_t)((v >> 16) & 0xFFu);
    out[3] = (uint8_t)((v >> 24) & 0xFFu);
}

/**
 * @brief Unpack a 32-bit integer from little-endian bytes.
 *
 * @param[in] in Input buffer (4 bytes).
 * @return Unpacked 32-bit value.
 */
static uint32_t unpack_u32_le(const uint8_t in[4]) {
    return (uint32_t)in[0]
         | ((uint32_t)in[1] << 8)
         | ((uint32_t)in[2] << 16)
         | ((uint32_t)in[3] << 24);
}

/**
 * @brief Compare two Huffman nodes by frequency, then deterministic sequence.
 *
 * @param[in] a Left node.
 * @param[in] b Right node.
 * @return Negative if a < b, positive if a > b, 0 if equal.
 */
static int compare_nodes(Node *a, Node *b) {
    if (a->freq < b->freq) return -1;
    if (a->freq > b->freq) return 1;
    return (a->seq < b->seq) ? -1 : 1;
}

/**
 * @brief Push a node into the min-heap.
 *
 * @param[in,out] h Heap to modify.
 * @param[in] n Node to insert.
 * @return None.
 */
static void push_heap(MinHeap *h, Node *n) {
    int i = h->size++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (compare_nodes(h->nodes[p], n) <= 0) break;
        h->nodes[i] = h->nodes[p]; i = p;
    }
    h->nodes[i] = n;
}

/**
 * @brief Pop the minimum-frequency node from the heap.
 *
 * @param[in,out] h Heap to modify.
 * @return The minimum node, or NULL if the heap is empty.
 */
static Node* pop_heap(MinHeap *h) {
    Node *ret = h->nodes[0];
    Node *last = h->nodes[--h->size];
    int i = 0;
    while (i * 2 + 1 < h->size) {
        int child = i * 2 + 1;
        if (child + 1 < h->size && compare_nodes(h->nodes[child + 1], h->nodes[child]) < 0) {
            child++;
        }
        if (compare_nodes(last, h->nodes[child]) <= 0) break;
        h->nodes[i] = h->nodes[child]; i = child;
    }
    h->nodes[i] = last;
    return ret;
}

/**
 * @brief Build a Huffman tree from symbol frequencies.
 *
 * @param[in] freqs Symbol frequency table.
 * @return Root node of the Huffman tree, or NULL on allocation failure.
 */
static Node* build_tree(uint32_t freqs[KYU_MAX_SYMBOLS]) {
    MinHeap h = { malloc(sizeof(Node*) * KYU_MAX_SYMBOLS * 2), 0 };
    if (!h.nodes) return NULL;
    
    int next_seq = KYU_MAX_SYMBOLS + 1; 

    for (int i = 0; i < KYU_MAX_SYMBOLS; i++) {
        if (freqs[i] > 0) {
            Node *n = calloc(1, sizeof(Node));
            n->symbol = i; n->freq = freqs[i];
            n->seq = i; 
            push_heap(&h, n);
        }
    }
    while (h.size > 1) {
        Node *a = pop_heap(&h), *b = pop_heap(&h);
        Node *p = calloc(1, sizeof(Node));
        p->symbol = -1; 
        p->freq = a->freq + b->freq;
        p->seq = next_seq++; 
        p->left = a; p->right = b;
        push_heap(&h, p);
    }
    Node *root = (h.size > 0) ? pop_heap(&h) : NULL;
    free(h.nodes);
    return root;
}

/**
 * @brief Generate Huffman codes and code lengths for each symbol.
 *
 * @param[in] r Current tree node.
 * @param[out] c Output code table.
 * @param[out] l Output code-length table.
 * @param[in] cur Current code bits.
 * @param[in] len Current code length.
 * @return None.
 */
static void gen_codes(Node *r, uint32_t *c, int *l, uint32_t cur, int len) {
    if (!r) return;
    if (r->symbol != -1) { c[r->symbol] = cur; l[r->symbol] = len; return; }
    gen_codes(r->left, c, l, (cur << 1), len + 1);
    gen_codes(r->right, c, l, (cur << 1) | 1, len + 1);
}

/**
 * @brief Free a Huffman tree recursively.
 *
 * @param[in] n Root node to free.
 * @return None.
 */
static void free_tree(Node *n) { if(n) { free_tree(n->left); free_tree(n->right); free(n); } }

/**
 * @brief Free internal decode resources held by the stream.
 *
 * @param[in,out] strm Stream state.
 * @return None.
 */
void kyu_decompress_free(kyu_stream *strm) {
    if (!strm) return;
    if (strm->root) {
        free_tree((Node*)strm->root);
        strm->root = NULL;
    }
}

/**
 * @brief Flush any pending literal/match output to the output buffer.
 *
 * @param[in,out] strm Stream state with pending output.
 * @param[out] out Output buffer.
 * @param[in,out] written Bytes already written to out.
 * @param[in] out_cap Total capacity of out in bytes.
 * @return 0 on success, KYU_ERR_BUF_SMALL if out is full.
 */
static int flush_pending(kyu_stream *strm, uint8_t *out, size_t *written, size_t out_cap) {
    if (strm->pending_type == PENDING_NONE) return KYU_SUCCESS;

    if (strm->pending_type == PENDING_LITERAL) {
        if (*written >= out_cap) return KYU_ERR_BUF_SMALL;
        uint8_t byte = strm->pending_literal;
        out[(*written)++] = byte;
        strm->window[strm->window_pos & KYU_WINDOW_MASK] = byte;
        strm->window_pos++;
        strm->pending_type = PENDING_NONE;
        return KYU_SUCCESS;
    }

    if (strm->pending_type == PENDING_MATCH) {
        while (strm->pending_len > 0) {
            if (*written >= out_cap) return KYU_ERR_BUF_SMALL;
            uint8_t byte = strm->window[(strm->window_pos + KYU_WINDOW_SIZE - strm->pending_dist) & KYU_WINDOW_MASK];
            out[(*written)++] = byte;
            strm->window[strm->window_pos & KYU_WINDOW_MASK] = byte;
            strm->window_pos++;
            strm->pending_len--;
        }
        strm->pending_type = PENDING_NONE;
        return KYU_SUCCESS;
    }

    return KYU_SUCCESS;
}

/**
 * @brief Write a variable number of bits into the output stream.
 *
 * @param[in,out] p_out Output cursor pointer.
 * @param[in,out] p_rem Remaining capacity in bytes.
 * @param[in,out] bit_buf Bit accumulator byte.
 * @param[in,out] bit_cnt Number of bits currently in bit_buf.
 * @param[in] val Bits to write (right-aligned).
 * @param[in] count Number of bits from val to write.
 * @return None.
 */
static void write_bits_buf(uint8_t **p_out, size_t *p_rem, uint8_t *bit_buf, int *bit_cnt, uint32_t val, int count) {
    val &= (1 << count) - 1; 
    while (count > 0) {
        int bits_free = 8 - *bit_cnt;
        int bits_to_write = (count < bits_free) ? count : bits_free;
        uint8_t chunk = (val >> (count - bits_to_write)); 
        *bit_buf |= (chunk << (bits_free - bits_to_write));
        *bit_cnt += bits_to_write;
        count -= bits_to_write;
        if (*bit_cnt == 8) {
            if (*p_rem > 0) { *(*p_out)++ = *bit_buf; (*p_rem)--; }
            *bit_buf = 0; *bit_cnt = 0;
        }
    }
}


/**
 * @brief Encode the current token buffer as a block.
 *
 * @param[in,out] strm Stream state with tokens and frequencies.
 * @param[out] out Output buffer.
 * @param[in,out] out_len Input: capacity of out. Output: bytes written.
 * @param[in] is_eof Non-zero if this is the final block.
 * @return 0 on success, negative error code on failure.
 */
static int kyu_flush_block(kyu_stream *strm, uint8_t *out, size_t *out_len, int is_eof) {
    size_t rem = *out_len;
    uint8_t *cur = out;
    size_t freq_bytes = KYU_MAX_SYMBOLS * 4;
    
    if (!is_eof) {
        strm->freqs[KYU_SYM_BLK_END]++;
        strm->tokens[strm->token_count++] = (Token){ KYU_SYM_BLK_END, 0, 0 };
    }

    Node *root = build_tree(strm->freqs);
    if (!root) return KYU_ERR_MEMORY;
    
    uint32_t codes[KYU_MAX_SYMBOLS]; 
    int lens[KYU_MAX_SYMBOLS];
    memset(lens, 0, sizeof(lens));
    gen_codes(root, codes, lens, 0, 0);

    if (rem < freq_bytes) { free_tree(root); return KYU_ERR_BUF_SMALL; }
    for (int i = 0; i < KYU_MAX_SYMBOLS; i++) {
        pack_u32_le(cur, strm->freqs[i]);
        cur += 4; rem -= 4;
    }

    for (int i = 0; i < strm->token_count; i++) {
        Token t = strm->tokens[i];
        if (rem < 8) { free_tree(root); return KYU_ERR_BUF_SMALL; }
        
        write_bits_buf(&cur, &rem, &strm->bit_buf, &strm->bit_count, codes[t.type], lens[t.type]);
        if (t.type == KYU_SYM_MATCH) {
            write_bits_buf(&cur, &rem, &strm->bit_buf, &strm->bit_count, t.dist, 15);
            write_bits_buf(&cur, &rem, &strm->bit_buf, &strm->bit_count, t.len, 4);
        }
    }

    if (strm->bit_count > 0) {
        if (rem < 1) { free_tree(root); return KYU_ERR_BUF_SMALL; }
        *cur++ = strm->bit_buf;
        rem--;
        strm->bit_buf = 0; strm->bit_count = 0;
    }

    strm->token_count = 0;
    memset(strm->freqs, 0, sizeof(strm->freqs));
    strm->freqs[KYU_SYM_EOF] = 1;
    strm->freqs[KYU_SYM_MATCH] = 1;
    strm->freqs[KYU_SYM_BLK_END] = 1;
    
    *out_len = (cur - out);
    free_tree(root);
    return KYU_SUCCESS;
}

/**
 * @brief Initialize a compression stream.
 *
 * @param[in,out] strm Stream state to initialize.
 * @return 0 on success, negative error code on failure.
 */
int kyu_compress_init(kyu_stream *strm) {
    if (!strm) return KYU_ERR_MEMORY;
    memset(strm, 0, sizeof(kyu_stream));
    memset(strm->head, 0, sizeof(strm->head)); 
    strm->window_pos = 0;
    strm->freqs[KYU_SYM_EOF] = 1;
    strm->freqs[KYU_SYM_MATCH] = 1;
    strm->freqs[KYU_SYM_BLK_END] = 1;
    return KYU_SUCCESS;
}

/**
 * @brief Compress a chunk of input data into the output buffer.
 *
 * @param[in,out] strm Stream state.
 * @param[in] in Input buffer.
 * @param[in,out] in_len Input: available bytes. Output: bytes consumed.
 * @param[out] out Output buffer.
 * @param[in,out] out_len Input: capacity of out. Output: bytes written.
 * @return 0 on success, negative error code on failure.
 */
int kyu_compress_update(kyu_stream *strm, const uint8_t *in, size_t in_len, uint8_t *out, size_t *out_len) {
    size_t written_total = 0;
    size_t rem_out = *out_len;
    uint8_t *out_ptr = out;
    
    for (size_t i = 0; i < in_len; ) {
        if (strm->token_count >= KYU_MAX_TOKENS - 2) {
            size_t n = rem_out;
            int ret = kyu_flush_block(strm, out_ptr, &n, 0);
            if (ret != KYU_SUCCESS) return ret;
            out_ptr += n; rem_out -= n; written_total += n;
        }

        uint32_t w_idx = strm->window_pos & KYU_WINDOW_MASK;
        strm->window[w_idx] = in[i];
        
        int m_len = 0, m_dist = 0;
        
        if (strm->window_pos >= 3 && i + 2 < in_len) {
             uint16_t h_curr = ((in[i] << 10) ^ (in[i+1] << 5) ^ in[i+2]) & 0xFFFF;
             
             int32_t stored_val = strm->head[h_curr];
             strm->head[h_curr] = (int32_t)(strm->window_pos + 1);
             strm->prev[w_idx] = stored_val;
             
             if (stored_val != 0) {
                 int32_t dist = (int32_t)(strm->window_pos + 1) - stored_val;
                 if (dist > 0 && dist < KYU_WINDOW_SIZE) {
                     int len = 0;
                     size_t match_idx = (size_t)(stored_val - 1);
                     
                     while (i + len < in_len && len < 18) {
                         uint8_t ref_byte;
                         if (len < dist) {
                             ref_byte = strm->window[(match_idx + len) & KYU_WINDOW_MASK];
                         } else {
                             ref_byte = in[i + len - dist];
                         }
                         
                         if (ref_byte != in[i+len]) break;
                         len++;
                     }
                     
                     if (len >= 3) { m_len = len; m_dist = dist; }
                 }
             }
        }

        if (m_len >= 3) {
            strm->tokens[strm->token_count++] = (Token){ KYU_SYM_MATCH, (uint16_t)m_dist, (uint16_t)(m_len - 3) };
            strm->freqs[KYU_SYM_MATCH]++;
            for (int k = 1; k < m_len; k++) {
                strm->window_pos++;
                strm->window[strm->window_pos & KYU_WINDOW_MASK] = in[i+k];
            }
            strm->window_pos++; i += m_len;
        } else {
            strm->tokens[strm->token_count++] = (Token){ in[i], 0, 0 };
            strm->freqs[in[i]]++;
            strm->window_pos++; i++;
        }
    }
    *out_len = written_total;
    return KYU_SUCCESS;
}

/**
 * @brief Finish compression and emit the final block.
 *
 * @param[in,out] strm Stream state.
 * @param[out] out Output buffer.
 * @param[in,out] out_len Input: capacity of out. Output: bytes written.
 * @return 0 on success, negative error code on failure.
 */
int kyu_compress_end(kyu_stream *strm, uint8_t *out, size_t *out_len) {
    strm->tokens[strm->token_count++] = (Token){ KYU_SYM_EOF, 0, 0 };
    strm->freqs[KYU_SYM_EOF]++;
    size_t n = *out_len;
    int ret = kyu_flush_block(strm, out, &n, 1);
    if (ret != KYU_SUCCESS) return ret;
    *out_len = n;
    return KYU_SUCCESS;
}


enum { ST_READ_FREQ, ST_DECODE };
enum { PHASE_SYM, PHASE_DIST, PHASE_LEN };

/**
 * @brief Initialize a decompression stream.
 *
 * @param[in,out] strm Stream state to initialize.
 * @return 0 on success, negative error code on failure.
 */
int kyu_decompress_init(kyu_stream *strm) {
    if (!strm) return KYU_ERR_MEMORY;
    memset(strm, 0, sizeof(kyu_stream));
    strm->state = ST_READ_FREQ;
    strm->bytes_needed = KYU_MAX_SYMBOLS * 4;
    strm->freq_len = 0;
    strm->root = NULL;
    return KYU_SUCCESS;
}

/**
 * @brief Read the next bit from the input stream.
 *
 * @param[in,out] strm Stream state with bit buffer.
 * @param[in,out] src Input cursor pointer.
 * @param[in,out] src_len Remaining input length in bytes.
 * @return 0 or 1 bit value, or -1 if no input is available.
 */
static int get_next_bit(kyu_stream *strm, const uint8_t **src, size_t *src_len) {
    if (strm->bit_count == 0) {
        if (*src_len == 0) return -1;
        strm->bit_buf = *(*src)++;
        (*src_len)--;
        strm->bit_count = 8;
    }
    int bit = (strm->bit_buf >> (strm->bit_count - 1)) & 1;
    strm->bit_count--;
    return bit;
}

/**
 * @brief Decompress a chunk of input data into the output buffer.
 *
 * @param[in,out] strm Stream state.
 * @param[in] in Input buffer.
 * @param[in,out] in_len Input: available bytes. Output: bytes consumed.
 * @param[out] out Output buffer.
 * @param[in,out] out_len Input: capacity of out. Output: bytes written.
 * @return 0 on success, negative error code on failure.
 */
int kyu_decompress_update(kyu_stream *strm, const uint8_t *in, size_t *in_len, uint8_t *out, size_t *out_len) {
    size_t written = 0;
    const uint8_t *src = in;
    size_t src_rem = *in_len;
    size_t in_total = *in_len;
    
    while (1) {
        if (strm->pending_type != PENDING_NONE) {
            int ret = flush_pending(strm, out, &written, *out_len);
            if (ret == KYU_ERR_BUF_SMALL) goto buf_small;
        }

        if (strm->state == ST_READ_FREQ) {
            size_t to_copy = strm->bytes_needed - strm->freq_len;
            if (to_copy > src_rem) to_copy = src_rem;
            
            memcpy(strm->freq_buf + strm->freq_len, src, to_copy);
            strm->freq_len += to_copy;
            src += to_copy; src_rem -= to_copy;
            
            if (strm->freq_len == strm->bytes_needed) {
                if (strm->root) free_tree((Node*)strm->root);
                for (int i = 0; i < KYU_MAX_SYMBOLS; i++) {
                    strm->freqs[i] = unpack_u32_le(strm->freq_buf + (i * 4));
                }
                strm->root = build_tree(strm->freqs);
                if (!strm->root) return KYU_ERR_MEMORY;
                
                strm->state = ST_DECODE;
                strm->phase = PHASE_SYM;
                strm->tree_curr = strm->root;
            } else {
                goto need_input;
            }
        }
        
        if (strm->state == ST_DECODE) {
            while (1) {
                if (strm->phase == PHASE_SYM) {
                    if (!strm->root) return KYU_ERR_DATA_CORRUPT;
                    Node *curr = (Node*)strm->tree_curr;
                    
                    while (curr->symbol == -1) {
                        int bit = get_next_bit(strm, &src, &src_rem);
                        if (bit == -1) {
                            strm->tree_curr = curr; 
                            goto need_input;
                        }
                        curr = (bit == 0) ? curr->left : curr->right;
                        if (!curr) return KYU_ERR_DATA_CORRUPT;
                    }
                    
                    strm->tree_curr = strm->root; 
                    
                    if (curr->symbol == KYU_SYM_EOF) {
                        *out_len = written;
                        *in_len = in_total - src_rem;
                        return KYU_SUCCESS;
                    }
                    else if (curr->symbol == KYU_SYM_BLK_END) {
                        strm->state = ST_READ_FREQ;
                        strm->freq_len = 0;
                        strm->bit_count = 0; 
                        break; 
                    }
                    else if (curr->symbol == KYU_SYM_MATCH) {
                        strm->phase = PHASE_DIST;
                        strm->partial_val = 0;
                        strm->partial_bits = 0;
                    }
                    else {
                        uint8_t byte = (uint8_t)curr->symbol;
                        strm->pending_type = PENDING_LITERAL;
                        strm->pending_literal = byte;
                        int ret = flush_pending(strm, out, &written, *out_len);
                        if (ret == KYU_ERR_BUF_SMALL) goto buf_small;
                    }
                }
                
                if (strm->phase == PHASE_DIST) {
                    while (strm->partial_bits < 15) {
                        int bit = get_next_bit(strm, &src, &src_rem);
                        if (bit == -1) goto need_input;
                        strm->partial_val = (strm->partial_val << 1) | bit;
                        strm->partial_bits++;
                    }
                    strm->match_dist = (int32_t)strm->partial_val; 
                    strm->phase = PHASE_LEN;
                    strm->partial_val = 0;
                    strm->partial_bits = 0;
                }
                
                if (strm->phase == PHASE_LEN) {
                    while (strm->partial_bits < 4) {
                        int bit = get_next_bit(strm, &src, &src_rem);
                        if (bit == -1) goto need_input;
                        strm->partial_val = (strm->partial_val << 1) | bit;
                        strm->partial_bits++;
                    }
                    
                    uint32_t dist = (uint32_t)strm->match_dist;
                    uint32_t len = strm->partial_val + 3;
                    strm->pending_type = PENDING_MATCH;
                    strm->pending_dist = dist;
                    strm->pending_len = len;
                    strm->phase = PHASE_SYM;
                    int ret = flush_pending(strm, out, &written, *out_len);
                    if (ret == KYU_ERR_BUF_SMALL) goto buf_small;
                }
            }
            if (strm->state == ST_READ_FREQ) continue;
            goto need_input;
        }
    }

need_input:
    *out_len = written;
    *in_len = in_total - src_rem;
    return KYU_SUCCESS;

buf_small:
    *out_len = written;
    *in_len = in_total - src_rem;
    return KYU_ERR_BUF_SMALL;
}
