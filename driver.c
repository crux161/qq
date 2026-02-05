/**
 * @file driver.c
 * @brief CLI entry point for the Kyu archiver.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <unistd.h>
#include <limits.h>
#include <dirent.h>

/* Headers required for struct stat on some platforms */
#include <sys/types.h>

#include "kyu.h"
#include "kyu_archive.h"
#include "password_utils.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* --- Constants --- */
#define KYU_DEFAULT_PASS "kyu-insecure-default"

/* --- Prototypes --- */
int kyu_ustar_write_header(kyu_writer *w, const char *path, const struct stat *st);
int kyu_ustar_write_padding(kyu_writer *w, size_t size);
int kyu_ustar_write_end(kyu_writer *w);
int kyu_ustar_list_callback(void *ctx, const void *buf, size_t len);

/* --- Helpers --- */

static void print_usage(const char *prog) {
    fprintf(stderr, "Kyu Archiver (QQX5)\n");
    fprintf(stderr, "Usage: %s -c|-d|-l [options] [input] [output]\n", prog);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -c          Compress (File or Directory)\n");
    fprintf(stderr, "  -d          Decompress\n");
    fprintf(stderr, "  -l          List contents\n");
    fprintf(stderr, "  -o <file>   Output file (optional)\n");
    fprintf(stderr, "  -p          Force password prompt (skip auto-detect)\n");
    fprintf(stderr, "  -1 ... -9   Compression Level (1=Fast, 9=Optimal)\n");
}

static const char *err_str(int code) {
    switch (code) {
        case KYU_SUCCESS: return "OK";
        case KYU_ERR_MEMORY: return "Out of memory";
        case KYU_ERR_INVALID_HDR: return "Invalid header";
        case KYU_ERR_CRC_MISMATCH: return "Authentication failed (Wrong Password)";
        case KYU_ERR_DATA_CORRUPT: return "Corrupted data";
        case KYU_ERR_IO: return "I/O error";
        case KYU_ERR_BUF_SMALL: return "Buffer too small";
        default: return "Unknown error";
    }
}

static void derive_filename(const char *in, char *out, size_t max, int is_comp, int is_dir_input) {
    char clean_in[PATH_MAX];
    strncpy(clean_in, in, PATH_MAX - 1);
    clean_in[PATH_MAX - 1] = '\0';
    size_t len = strlen(clean_in);
    if (len > 1 && clean_in[len - 1] == '/') clean_in[len - 1] = '\0';

    const char *base = strrchr(clean_in, '/');
    if (base) base++; else base = clean_in;

    if (is_comp) {
        if (is_dir_input) snprintf(out, max, "%s.tar.kyu", base);
        else snprintf(out, max, "%s.kyu", base);
    } else {
        size_t base_len = strlen(base);
        if (base_len > 8 && !strcmp(base+base_len-8, ".tar.kyu")) {
            snprintf(out, max, "%.*s.tar", (int)(base_len-8), base);
        } else if (base_len > 4 && !strcmp(base+base_len-4, ".kyu")) {
            snprintf(out, max, "%.*s", (int)(base_len-4), base);
        } else {
            snprintf(out, max, "%s.dec", base);
        }
    }
}

static int file_write_wrapper(void *ctx, const void *buf, size_t len) {
    FILE *f = (FILE*)ctx;
    return (fwrite(buf, 1, len, f) == len) ? KYU_SUCCESS : KYU_ERR_IO;
}

static int walk_dir(kyu_writer *w, const char *base_path, const char *rel_path) {
    char full_path[PATH_MAX];
    if (rel_path[0]) snprintf(full_path, PATH_MAX, "%s/%s", base_path, rel_path);
    else snprintf(full_path, PATH_MAX, "%s", base_path);

    DIR *d = opendir(full_path);
    if (!d) { perror(full_path); return -1; }

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, "..")) continue;

        char entry_rel[PATH_MAX];
        char entry_full[PATH_MAX];

        if (rel_path[0]) snprintf(entry_rel, PATH_MAX, "%s/%s", rel_path, ent->d_name);
        else snprintf(entry_rel, PATH_MAX, "%s", ent->d_name);

        snprintf(entry_full, PATH_MAX, "%s/%s", base_path, entry_rel);

        struct stat st;
        if (lstat(entry_full, &st) != 0) { perror(entry_full); continue; }

        if (kyu_ustar_write_header(w, entry_rel, &st) != KYU_SUCCESS) {
            closedir(d); return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            if (walk_dir(w, base_path, entry_rel) != 0) { closedir(d); return -1; }
        } else if (S_ISREG(st.st_mode)) {
            FILE *f = fopen(entry_full, "rb");
            if (f) {
                uint8_t buf[16384];
                size_t n;
                while ((n = fread(buf, 1, sizeof(buf), f)) > 0) {
                    if (kyu_writer_update(w, buf, n) != KYU_SUCCESS) {
                        fclose(f); closedir(d); return -1;
                    }
                }
                fclose(f);
                kyu_ustar_write_padding(w, (size_t)st.st_size);
            }
        }
    }
    closedir(d);
    return 0;
}

/* --- Main --- */

int main(int argc, char *argv[]) {
    if (argc < 2) { print_usage(argv[0]); return 1; }

    const char *mode = argv[1];
    const char *in_arg = NULL;
    const char *out_arg = NULL;
    char auto_out[PATH_MAX] = {0};
    int level = 6; /* Default level */
    int request_secure = 0;

    /* Argument Parsing */
    const char *pos[8]; int pos_cnt = 0;
    for (int i=2; i<argc; i++) {
        if (!strcmp(argv[i], "-o")) {
            if (++i < argc) out_arg = argv[i];
        } else if (!strcmp(argv[i], "-p")) {
            request_secure = 1;
        } else if (argv[i][0] == '-' && argv[i][1] >= '0' && argv[i][1] <= '9') {
            level = argv[i][1] - '0';
        } else {
            if (pos_cnt < 8) pos[pos_cnt++] = argv[i];
        }
    }
    if (pos_cnt > 0) in_arg = pos[0];
    if (pos_cnt > 1 && !out_arg) out_arg = pos[1];
    
    /* Stream/Dir Detection */
    int use_stdin = (!in_arg || strcmp(in_arg, "-") == 0);
    int is_list_mode = (!strcmp(mode, "-l"));
    int use_stdout = 0;
    int is_dir_input = 0;
    struct stat st_check;

    if (!use_stdin && in_arg && stat(in_arg, &st_check) == 0 && S_ISDIR(st_check.st_mode)) {
        is_dir_input = 1;
    }

    if (!is_list_mode) {
        if (out_arg && strcmp(out_arg, "-") == 0) use_stdout = 1;
        else if (!out_arg) {
            if (use_stdin || !isatty(fileno(stdout))) use_stdout = 1;
            else {
                derive_filename(in_arg, auto_out, PATH_MAX, !strcmp(mode, "-c"), is_dir_input);
                out_arg = auto_out;
                use_stdout = 0;
            }
        }
    }

    /* --- Password Logic --- */
    char password[1024] = {0};
    int used_default_pass = 0; /* Track if we are using the fallback */
    
    // 1. Check ENV (Highest priority for automation)
    if (getenv("KYU_PASSWORD")) {
        kyu_get_password(password, sizeof(password), "", 0);
    } 
    // 2. Check Flag (Explicit interaction)
    else if (request_secure) {
        int confirm = (!strcmp(mode, "-c"));
        kyu_get_password(password, sizeof(password), "Enter Password: ", confirm);
        if (confirm && strlen(password) > 0) {
             if (!kyu_password_check_strength(password)) return 1;
        }
    } 
    // 3. Default (Insecure/Optimistic)
    else {
        strcpy(password, KYU_DEFAULT_PASS);
        used_default_pass = 1;
        
        // Only warn on COMPRESSION. For decompression, we'll just try and see.
        if (!strcmp(mode, "-c") && !use_stdout) {
            fprintf(stderr, ">> Note: Using default insecure mode. Use -p to secure.\n");
        }
    }

    FILE *f_in = use_stdin ? stdin : fopen(in_arg, "rb");
    if (!f_in && !use_stdin && !is_dir_input) { perror("Input"); return 1; }

    FILE *f_out = NULL;
    if (!is_list_mode) {
        f_out = use_stdout ? stdout : fopen(out_arg, "wb");
        if (!f_out) { perror("Output"); if(f_in) fclose(f_in); return 1; }
    }

    if (!use_stdout && !is_list_mode) {
        printf("Processing: %s -> %s [L%d]\n", is_dir_input ? in_arg : (use_stdin ? "STDIN" : in_arg), out_arg, level);
    }

    int ret = 0;

    if (!strcmp(mode, "-c")) {
        /* COMPRESSION */
        if (is_dir_input) {
            if (f_in) fclose(f_in); 
            
            kyu_writer *w = kyu_writer_init(f_out, password, NULL, level);
            if (w) {
                // ... (directory walking logic omitted for brevity, same as before) ...
                char base_dir[PATH_MAX] = ".";
                char root_name[PATH_MAX] = {0};
                char clean_in[PATH_MAX];
                strncpy(clean_in, in_arg, PATH_MAX-1);
                size_t len = strlen(clean_in);
                if (len > 1 && clean_in[len-1] == '/') clean_in[len-1] = 0;
                char *slash = strrchr(clean_in, '/');
                if (slash) {
                    *slash = 0;
                    strncpy(base_dir, clean_in, PATH_MAX);
                    strncpy(root_name, slash+1, PATH_MAX);
                } else {
                    strncpy(root_name, clean_in, PATH_MAX);
                }

                if (kyu_ustar_write_header(w, root_name, &st_check) == 0) {
                    if (walk_dir(w, base_dir, root_name) == 0) {
                        kyu_ustar_write_end(w);
                        kyu_manifest man = {0};
                        snprintf(man.name, 255, "%s.tar", root_name);
                        man.mode = st_check.st_mode;
                        man.mtime = (uint64_t)st_check.st_mtime;
                        ret = kyu_writer_finalize(w, &man);
                    } else ret = KYU_ERR_IO;
                } else ret = KYU_ERR_IO;
            }
        } else {
            kyu_manifest tmpl = {0};
            if (!use_stdin && stat(in_arg, &st_check) == 0) {
                tmpl.mode = st_check.st_mode;
                tmpl.mtime = (uint64_t)st_check.st_mtime;
                const char *b = strrchr(in_arg, '/');
                strncpy(tmpl.name, b ? b+1 : in_arg, 255);
            }
            kyu_manifest man = {0};
            ret = kyu_archive_compress_stream(f_in, f_out, password, NULL, level, &tmpl, &man);
        }
    } 
    else if (!strcmp(mode, "-d")) {
        /* DECOMPRESSION (Optimistic) */
        kyu_manifest man = {0};
        int status = 0;
        
        while (1) {
            ret = kyu_archive_decompress_stream(f_in, file_write_wrapper, f_out, password, NULL, &man, &status);
            
            // Check for Auth Failure + Default Pass + Seekable File
            if (ret == KYU_ERR_CRC_MISMATCH && used_default_pass && !use_stdin) {
                fprintf(stderr, ">> Encrypted file detected. Password required.\n");
                
                // Prompt user
                if (kyu_get_password(password, sizeof(password), "Enter Password: ", 0) != 0) {
                    fprintf(stderr, "Aborted.\n");
                    break; 
                }
                
                // Rewind and Retry
                rewind(f_in);
                used_default_pass = 0; // Prevent infinite loop if user pass is also wrong
                continue;
            }
            break; // Success or other error
        }

        if (ret == 0 && !use_stdout && status == 1) {
            chmod(out_arg, man.mode & 0777);
            struct timeval t[2] = { {(time_t)man.mtime, 0}, {(time_t)man.mtime, 0} };
            utimes(out_arg, t);
            printf("Restored: %s\n", man.name);
        }
        if (status == -1) fprintf(stderr, "SECURITY WARNING: Manifest auth failed.\n");
    }
    else if (!strcmp(mode, "-l")) {
        /* LIST MODE (Optimistic) */
        kyu_ustar_lister_ctx lctx = {0};
        kyu_manifest man = {0};
        int status = 0;

        while (1) {
            ret = kyu_archive_decompress_stream(f_in, kyu_ustar_list_callback, &lctx, password, NULL, &man, &status);
            
            if (ret == KYU_ERR_CRC_MISMATCH && used_default_pass && !use_stdin) {
                fprintf(stderr, ">> Encrypted file detected. Password required.\n");
                if (kyu_get_password(password, sizeof(password), "Enter Password: ", 0) != 0) break;
                rewind(f_in);
                used_default_pass = 0;
                continue;
            }
            break;
        }

        if (ret == 0 && status == 1) {
            printf("\nArchive Name: %s\nSize: %llu\n", man.name, (unsigned long long)man.size);
        }
    }
    else {
        print_usage(argv[0]);
        ret = KYU_ERR_BAD_ARG;
    }

    if (f_in) fclose(f_in);
    if (f_out) fclose(f_out);
    memset(password, 0, sizeof(password));
    
    if (ret != KYU_SUCCESS) {
        fprintf(stderr, "Operation failed: %s (%d)\n", err_str(ret), ret);
        if (!use_stdout && out_arg && !is_list_mode) remove(out_arg);
        return 1;
    }
    return 0;
}
