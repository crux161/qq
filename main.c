#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/sysctl.h>

// --- CONSTANTS ---
const char QQ_SIGNATURE[4] = {'Q', 'Q', 'X', '3'};
#define WINDOW_SIZE 32768
#define WINDOW_MASK 32767

#define MAX_SYMBOLS 258 // 0-255 (Literals), 256 (Match Flag), 257 (EOF)
#define SYM_MATCH 256
#define SYM_EOF 257

uint32_t crc32_for_byte(uint32_t r) {
    for(int j = 0; j < 8; ++j) r = (r & 1? 0: (uint32_t)0xEDB88320L) ^ r >> 1;
    return r ^ (uint32_t)0xFF000000L;
}
uint32_t compute_crc32(const uint8_t *data, size_t n_bytes) {
    uint32_t crc = 0;
    static uint32_t table[0x100];
    static int table_computed = 0;
    if (!table_computed) {
        for(size_t i = 0; i < 0x100; ++i) table[i] = crc32_for_byte(i);
        table_computed = 1;
    }
    for(size_t i = 0; i < n_bytes; ++i) crc = table[(uint8_t)crc ^ data[i]] ^ crc >> 8;
    return crc;
}

uint64_t get_safe_ram_limit() {
    uint64_t memsize = 0;
    size_t len = sizeof(memsize);
    if (sysctlbyname("hw.memsize", &memsize, &len, NULL, 0) < 0) return 0;
    return (uint64_t)(memsize * 0.7);
}

typedef struct {
    uint16_t type; 
    uint16_t dist; 
    uint16_t len;  
} Token;


typedef struct Node {
    int symbol;       
    uint32_t freq;
    struct Node *left;
    struct Node *right;
} Node;

typedef struct {
    Node **nodes;
    int size;
    int capacity;
} MinHeap;

MinHeap* create_heap(int capacity) {
    MinHeap *h = malloc(sizeof(MinHeap));
    h->nodes = malloc(sizeof(Node*) * capacity);
    h->size = 0;
    h->capacity = capacity;
    return h;
}

void push_heap(MinHeap *h, Node *n) {
    int i = h->size++;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (h->nodes[p]->freq <= n->freq) break;
        h->nodes[i] = h->nodes[p];
        i = p;
    }
    h->nodes[i] = n;
}

Node* pop_heap(MinHeap *h) {
    Node *ret = h->nodes[0];
    Node *last = h->nodes[--h->size];
    int i = 0;
    while (i * 2 + 1 < h->size) {
        int child = i * 2 + 1;
        if (child + 1 < h->size && h->nodes[child + 1]->freq < h->nodes[child]->freq) {
            child++;
        }
        if (last->freq <= h->nodes[child]->freq) break;
        h->nodes[i] = h->nodes[child];
        i = child;
    }
    h->nodes[i] = last;
    return ret;
}

Node* build_huffman_tree(uint32_t freqs[MAX_SYMBOLS]) {
    MinHeap *h = create_heap(MAX_SYMBOLS * 2);
    
    for (int i = 0; i < MAX_SYMBOLS; i++) {
        if (freqs[i] > 0) {
            Node *n = calloc(1, sizeof(Node));
            n->symbol = i;
            n->freq = freqs[i];
            push_heap(h, n);
        }
    }

    if (h->size == 0) return NULL; 

    while (h->size > 1) {
        Node *a = pop_heap(h);
        Node *b = pop_heap(h);
        Node *parent = calloc(1, sizeof(Node));
        parent->symbol = -1;
        parent->freq = a->freq + b->freq;
        parent->left = a;
        parent->right = b;
        push_heap(h, parent);
    }
    
    Node *root = pop_heap(h);
    free(h->nodes);
    free(h);
    return root;
}

void generate_codes(Node *root, uint32_t codes[MAX_SYMBOLS], int lengths[MAX_SYMBOLS], uint32_t current_code, int len) {
    if (!root) return;
    if (root->symbol != -1) {
        codes[root->symbol] = current_code;
        lengths[root->symbol] = len;
        return;
    }
    generate_codes(root->left, codes, lengths, (current_code << 1) | 0, len + 1);
    generate_codes(root->right, codes, lengths, (current_code << 1) | 1, len + 1);
}

void free_tree(Node *n) {
    if (!n) return;
    free_tree(n->left);
    free_tree(n->right);
    free(n);
}


typedef struct {
    FILE *fp;
    uint8_t buffer;
    int bit_count;
} BitWriter;

void bit_writer_init(BitWriter *bw, FILE *fp) { bw->fp = fp; bw->buffer = 0; bw->bit_count = 0; }

void write_bits(BitWriter *bw, uint32_t value, int count) {
    value &= (1 << count) - 1; 
    while (count > 0) {
        int bits_free = 8 - bw->bit_count;
        int bits_to_write = (count < bits_free) ? count : bits_free;
        uint8_t chunk = (value >> (count - bits_to_write)); 
        bw->buffer |= (chunk << (bits_free - bits_to_write));
        bw->bit_count += bits_to_write;
        count -= bits_to_write;
        if (bw->bit_count == 8) { fputc(bw->buffer, bw->fp); bw->buffer = 0; bw->bit_count = 0; }
    }
}
void bit_writer_flush(BitWriter *bw) { if (bw->bit_count > 0) fputc(bw->buffer, bw->fp); }

typedef struct {
    FILE *fp;
    uint8_t buffer;
    int bit_count; 
} BitReader;

void bit_reader_init(BitReader *br, FILE *fp) { br->fp = fp; br->buffer = 0; br->bit_count = 0; }

uint32_t read_bits(BitReader *br, int count) {
    uint32_t value = 0;
    while (count > 0) {
        if (br->bit_count == 0) {
            int c = fgetc(br->fp);
            if (c == EOF) return 0; 
            br->buffer = (uint8_t)c;
            br->bit_count = 8;
        }
        int bits_available = br->bit_count;
        int bits_to_read = (count < bits_available) ? count : bits_available;
        uint8_t chunk = (br->buffer >> (bits_available - bits_to_read));
        chunk &= ((1 << bits_to_read) - 1);
        value = (value << bits_to_read) | chunk;
        br->bit_count -= bits_to_read;
        count -= bits_to_read;
    }
    return value;
}


#define HASH_SIZE 65536
int head[HASH_SIZE]; 
int prev[WINDOW_SIZE];

uint32_t hash_func(uint8_t *p) {
    return ((p[0] << 10) ^ (p[1] << 5) ^ p[2]) & (HASH_SIZE - 1);
}

void qq_compress(uint8_t *input, size_t length, const char *filename) {
    size_t max_tokens = length;
    uint64_t ram_needed = max_tokens * sizeof(Token);
    if (ram_needed > get_safe_ram_limit()) {
        fprintf(stderr, "⛔️ Not enough RAM for Huffman analysis.\n");
        return;
    }

    Token *tokens = malloc(ram_needed);
    size_t token_count = 0;
    
    printf("   Pass 1: LZ77 Analysis... ");
    memset(head, -1, sizeof(head));
    
    uint32_t freqs[MAX_SYMBOLS] = {0};
    freqs[SYM_EOF] = 1; 

    for (size_t i = 0; i < length; ) {
        if (i >= length - 3) {
            tokens[token_count++] = (Token){ input[i], 0, 0 };
            freqs[input[i]]++;
            i++;
            continue;
        }

        uint32_t h = hash_func(&input[i]);
        int match_index = head[h];
        prev[i & WINDOW_MASK] = head[h]; 
        head[h] = i;

        int match_len = 0;
        if (match_index != -1 && (i - match_index) < WINDOW_SIZE) {
            while(i + match_len < length && 
                  input[match_index + match_len] == input[i + match_len] && 
                  match_len < 18) { 
                match_len++;
            }
        }
        
        if (match_len >= 3) {
            tokens[token_count++] = (Token){ SYM_MATCH, (uint16_t)(i - match_index), (uint16_t)(match_len - 3) };
            freqs[SYM_MATCH]++;
            i += match_len;
        } else {
            tokens[token_count++] = (Token){ input[i], 0, 0 };
            freqs[input[i]]++;
            i++;
        }
    }
    tokens[token_count++] = (Token){ SYM_EOF, 0, 0 };
    printf("Done (%zu tokens).\n", token_count);

    printf("   Pass 2: Building Huffman Tree... ");
    Node *root = build_huffman_tree(freqs);
    
    uint32_t codes[MAX_SYMBOLS] = {0};
    int code_lens[MAX_SYMBOLS] = {0};
    generate_codes(root, codes, code_lens, 0, 0);
    printf("Done.\n");

    FILE *fp = fopen(filename, "wb");
    if (!fp) { perror("Output error"); free(tokens); free_tree(root); return; }

    uint32_t crc = compute_crc32(input, length);

    fwrite(QQ_SIGNATURE, 1, 4, fp);
    fwrite(&length, 4, 1, fp);
    fwrite(&crc, 4, 1, fp);
    
    fwrite(freqs, sizeof(uint32_t), MAX_SYMBOLS, fp);

    BitWriter bw;
    bit_writer_init(&bw, fp);

    printf("   Pass 3: Entropy Encoding... ");
    for (size_t i = 0; i < token_count; i++) {
        Token t = tokens[i];
        
        write_bits(&bw, codes[t.type], code_lens[t.type]);

        if (t.type == SYM_MATCH) {
            write_bits(&bw, t.dist, 15);
            write_bits(&bw, t.len, 4);
        }
    }
    
    bit_writer_flush(&bw);
    fclose(fp);
    free(tokens);
    free_tree(root);
}


void qq_decompress(const char *infile, const char *outfile) {
    FILE *fp_in = fopen(infile, "rb");
    if (!fp_in) { perror("Input error"); return; }

    char sig[4];
    uint32_t expected_size, expected_crc;
    if (fread(sig, 1, 4, fp_in) != 4 || memcmp(sig, QQ_SIGNATURE, 4) != 0) {
        fprintf(stderr, "❌ Error: Not a QQX3 file.\n"); fclose(fp_in); return;
    }
    fread(&expected_size, 4, 1, fp_in);
    fread(&expected_crc, 4, 1, fp_in);

    uint32_t freqs[MAX_SYMBOLS];
    fread(freqs, sizeof(uint32_t), MAX_SYMBOLS, fp_in);
    Node *root = build_huffman_tree(freqs);

    printf("   Metadata: %u bytes, CRC=0x%08X. Decoding...\n", expected_size, expected_crc);

    FILE *fp_out = fopen(outfile, "wb");
    BitReader br;
    bit_reader_init(&br, fp_in);

    uint8_t window[WINDOW_SIZE];
    size_t head = 0;
    size_t total_written = 0;

    while (total_written < expected_size) {
        Node *curr = root;
        while (curr->symbol == -1) {
            uint32_t bit = read_bits(&br, 1);
            if (bit == 0) curr = curr->left;
            else curr = curr->right;
            
            if (!curr) { fprintf(stderr, "❌ Huffman Tree Error\n"); goto cleanup; }
        }

        int sym = curr->symbol;

        if (sym == SYM_EOF) {
            break;
        } else if (sym == SYM_MATCH) {
            uint32_t dist = read_bits(&br, 15);
            uint32_t len = read_bits(&br, 4) + 3;
            for (uint32_t k = 0; k < len; k++) {
                if (total_written >= expected_size) break;
                size_t read_idx = (head + WINDOW_SIZE - dist) & WINDOW_MASK;
                uint8_t byte = window[read_idx];
                fputc(byte, fp_out);
                window[head] = byte;
                head = (head + 1) & WINDOW_MASK;
                total_written++;
            }
        } else {
            fputc(sym, fp_out);
            window[head] = sym;
            head = (head + 1) & WINDOW_MASK;
            total_written++;
        }
    }

cleanup:
    fclose(fp_out);
    fclose(fp_in);
    free_tree(root);

    printf("   Verifying... ");
    FILE *check_fp = fopen(outfile, "rb");
    uint8_t *check_buf = malloc(expected_size);
    if (check_buf) {
        fread(check_buf, 1, expected_size, check_fp);
        uint32_t actual_crc = compute_crc32(check_buf, expected_size);
        free(check_buf);
        if (actual_crc == expected_crc) printf("✅ Match.\n");
        else printf("❌ CRC Mismatch!\n");
    }
    fclose(check_fp);
}

int main(int argc, char *argv[]) {
    if (argc < 4) {
        printf("QQX3 Archiver (Huffman Edition)\n");
        printf("Usage: %s -c|-d <in> <out>\n", argv[0]);
        return 1;
    }
    if (strcmp(argv[1], "-c") == 0) {
        FILE *f = fopen(argv[2], "rb");
        fseek(f, 0, SEEK_END); size_t s = ftell(f); fseek(f, 0, SEEK_SET);
        uint8_t *buf = malloc(s);
        fread(buf, 1, s, f); fclose(f);
        qq_compress(buf, s, argv[3]);
        free(buf);
    } else {
        qq_decompress(argv[2], argv[3]);
    }
    return 0;
}
