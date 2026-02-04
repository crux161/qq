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

#include "kyu.h"
#include "kyu_archive.h"

/**
 * @brief Print CLI usage.
 *
 * @param[in] prog Program name.
 * @return None.
 */
static void print_usage(const char *prog) {
    printf("Kyu Archiver (QQX5) - Usage: %s -c|-d <in> <out> [password]\n", prog);
}

/**
 * @brief Convert a Kyu error code to a short message.
 *
 * @param[in] code Error code.
 * @return Static string describing the error.
 */
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

/**
 * @brief Apply manifest metadata (mode and mtime) to output file.
 *
 * @param[in] out_path Output file path.
 * @param[in] man Manifest metadata.
 * @return None.
 */
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
 * @brief Program entry point.
 *
 * @param[in] argc Argument count.
 * @param[in] argv Argument vector.
 * @return Exit code (0 on success).
 */
int main(int argc, char *argv[]) {
    if (argc < 4) {
        print_usage(argv[0]);
        return 1;
    }

    const char *mode = argv[1];
    const char *in_path = argv[2];
    const char *out_path = argv[3];
    const char *pass = (argc >= 5) ? argv[4] : NULL;

    if (!pass) {
        fprintf(stderr, "ERROR: Password required.\n");
        return 1;
    }

    if (strcmp(mode, "-c") == 0) {
        kyu_manifest manifest;
        int ret = kyu_archive_compress_file(in_path, out_path, pass, &manifest);
        if (ret != KYU_SUCCESS) {
            fprintf(stderr, "Archive failed: %s (%d)\n", err_str(ret), ret);
            return 1;
        }
        printf("Archived: %s (Original: %llu bytes)\n",
               manifest.name, (unsigned long long)manifest.size);
        return 0;
    }

    if (strcmp(mode, "-d") == 0) {
        kyu_manifest manifest;
        int manifest_status = 0;
        int ret = kyu_archive_decompress_file(in_path, out_path, pass, &manifest, &manifest_status);
        if (ret != KYU_SUCCESS) {
            fprintf(stderr, "Restore failed: %s (%d)\n", err_str(ret), ret);
            return 1;
        }

        if (manifest_status == 1) {
            printf("Restoring Metadata for: %s\n", manifest.name);
            apply_manifest(out_path, &manifest);
        } else if (manifest_status == -1) {
            printf("SECURITY ALERT: Manifest Tampered!\n");
        } else {
            printf("Warning: No Manifest Found.\n");
        }
        return 0;
    }

    print_usage(argv[0]);
    return 1;
}
