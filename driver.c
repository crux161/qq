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

#include "kyu.h"
#include "kyu_archive.h"

/* Helper for secure password input */
#include "password_utils.c"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void print_usage(const char *prog) {
    printf("Kyu Archiver (QQX5)\n");
    printf("Usage: %s -c|-d <input_file> [output_file] [password]\n", prog);
    printf("   Or: %s -c|-d <input_file> -o <output_file> [password]\n", prog);
    printf("\n");
    printf("Options:\n");
    printf("  -c <file>   Compress file\n");
    printf("  -d <file>   Decompress archive\n");
    printf("  -o <file>   Explicitly specify output filename\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s -c big.txt              -> Creates big.txt.kyu (prompts for pass)\n", prog);
    printf("  %s -c big.txt archive.kyu  -> Creates archive.kyu (prompts for pass)\n", prog);
}

static const char *err_str(int code) {
    switch (code) {
        case KYU_SUCCESS: return "OK";
        case KYU_ERR_MEMORY: return "Out of memory";
        case KYU_ERR_INVALID_HDR: return "Invalid header or format";
        case KYU_ERR_CRC_MISMATCH: return "Authentication failed";
        case KYU_ERR_BUF_SMALL: return "Buffer too small";
        case KYU_ERR_DATA_CORRUPT: return "Corrupted data";
        case KYU_ERR_IO: return "I/O error";
        case KYU_ERR_BAD_ARG: return "Invalid argument";
        default: return "Unknown error";
    }
}

static void apply_manifest(const char *out_path, const kyu_manifest *man) {
    chmod(out_path, man->mode & 0777);
    struct timeval times[2];
    times[0].tv_sec = (time_t)man->mtime;
    times[0].tv_usec = 0;
    times[1].tv_sec = (time_t)man->mtime;
    times[1].tv_usec = 0;
    utimes(out_path, times);
}

/**
 * @brief Intelligently derive output filename from input.
 */
static void derive_filename(const char *in, char *out, size_t max, int is_compress) {
    if (is_compress) {
        snprintf(out, max, "%s.kyu", in);
    } else {
        size_t len = strlen(in);
        if (len > 4 && strcmp(in + len - 4, ".kyu") == 0) {
            size_t new_len = len - 4;
            if (new_len >= max) new_len = max - 1;
            strncpy(out, in, new_len);
            out[new_len] = '\0';
        } else {
            snprintf(out, max, "%s.dec", in);
        }
    }
}

int main(int argc, char *argv[]) {
    if (argc < 3) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *in_path = NULL;
    const char *out_path_arg = NULL;
    const char *pass_arg = NULL;
    
    char auto_out_path[PATH_MAX];
    const char *final_out_path = NULL;

    // --- 1. Separate Flags from Positional Arguments ---
    const char *pos_args[8];
    int pos_count = 0;

    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) {
                out_path_arg = argv[++i];
            } else {
                fprintf(stderr, "Error: -o requires a filename.\n");
                return 1;
            }
        } else {
            if (pos_count < 8) pos_args[pos_count++] = argv[i];
        }
    }

    // --- 2. Assign Logical Variables ---
    if (pos_count == 0) {
        fprintf(stderr, "Error: No input file specified.\n");
        return 1;
    }
    
    in_path = pos_args[0];

    if (out_path_arg) {
        // Logic: kyu -c in -o out [pass]
        if (pos_count > 1) pass_arg = pos_args[1];
    } else {
        // Logic: kyu -c in [out] [pass]
        if (pos_count > 1) {
            out_path_arg = pos_args[1];
            if (pos_count > 2) pass_arg = pos_args[2];
        }
    }

    // --- 3. Derive Output Filename (if needed) ---
    if (out_path_arg) {
        final_out_path = out_path_arg;
    } else {
        int is_compress = (strcmp(mode, "-c") == 0);
        derive_filename(in_path, auto_out_path, sizeof(auto_out_path), is_compress);
        final_out_path = auto_out_path;
    }

    // --- 4. Password Handling ---
    char password[1024]; 
    memset(password, 0, sizeof(password));

    if (pass_arg) {
        fprintf(stderr, "WARNING: Providing password via CLI is insecure (visible in history).\n");
        strncpy(password, pass_arg, sizeof(password) - 1);
    } else {
        // Secure Prompt (Default)
        if (kyu_read_password_secure(password, sizeof(password), "Enter Password: ") != 0) {
            fprintf(stderr, "Error reading password.\n");
            return 1;
        }
        
        // Confirm (Creation only)
        if (strcmp(mode, "-c") == 0) {
            char confirm[1024];
            if (kyu_read_password_secure(confirm, sizeof(confirm), "Confirm Password: ") != 0) {
                return 1;
            }
            if (strcmp(password, confirm) != 0) {
                fprintf(stderr, "Error: Passwords do not match.\n");
                memset(password, 0, sizeof(password)); 
                memset(confirm, 0, sizeof(confirm));
                return 1;
            }
            memset(confirm, 0, sizeof(confirm));
        }
    }

    // Enforce Policy (Creation only)
    if (strcmp(mode, "-c") == 0) {
        if (!kyu_password_check_strength(password)) {
            memset(password, 0, sizeof(password));
            return 1;
        }
    }

    // --- 5. Execution ---
    printf("Input:  %s\n", in_path);
    printf("Output: %s\n", final_out_path);

    if (strcmp(mode, "-c") == 0) {
        kyu_manifest manifest;
        int ret = kyu_archive_compress_file(in_path, final_out_path, password, &manifest);
        if (ret != KYU_SUCCESS) {
            fprintf(stderr, "Archive failed: %s (%d)\n", err_str(ret), ret);
            remove(final_out_path);
            memset(password, 0, sizeof(password));
            return 1;
        }
        printf("Archived: %s (Original: %llu bytes)\n",
               manifest.name, (unsigned long long)manifest.size);
    } 
    else if (strcmp(mode, "-d") == 0) {
        kyu_manifest manifest;
        int manifest_status = 0;
        int ret = kyu_archive_decompress_file(in_path, final_out_path, password, &manifest, &manifest_status);
        if (ret != KYU_SUCCESS) {
            fprintf(stderr, "Restore failed: %s (%d)\n", err_str(ret), ret);
            remove(final_out_path);
            memset(password, 0, sizeof(password));
            return 1;
        }

        if (manifest_status == 1) {
            printf("Restoring Metadata for: %s\n", manifest.name);
            apply_manifest(final_out_path, &manifest);
        } else if (manifest_status == -1) {
            printf("SECURITY ALERT: Manifest Tampered!\n");
        } else {
            printf("Warning: No Manifest Found.\n");
        }
    } 
    else {
        print_usage(argv[0]);
        memset(password, 0, sizeof(password));
        return 1;
    }

    memset(password, 0, sizeof(password));
    return 0;
}
