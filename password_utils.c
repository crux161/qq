#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#include "password_utils.h"

#define KYU_PASS_MIN_LEN 14

/**
 * @brief Check password complexity (Length > Complexity).
 */
int kyu_password_check_strength(const char *pass) {
    if (strlen(pass) < KYU_PASS_MIN_LEN) {
        fprintf(stderr, "Error: Password too short (min %d).\n", KYU_PASS_MIN_LEN);
        return 0;
    }
    return 1;
}

/**
 * @brief Read password from /dev/tty (bypassing stdin) or KYU_PASSWORD env.
 * * @param[out] buf Output buffer.
 * @param[in] buflen Buffer capacity.
 * @param[in] prompt text to display.
 * @param[in] confirm 1 to ask for confirmation (creation), 0 otherwise.
 * @return 0 on success, -1 on failure.
 */
int kyu_get_password(char *buf, size_t buflen, const char *prompt, int confirm) {
    // 1. Check Environment Variable (Best for scripts/automation)
    const char *env_pass = getenv("KYU_PASSWORD");
    if (env_pass) {
        strncpy(buf, env_pass, buflen - 1);
        return 0;
    }

    // 2. Open the terminal directly (Bypasses stdin pipe)
    FILE *tty = fopen("/dev/tty", "r+");
    if (!tty) {
        fprintf(stderr, "Error: Cannot open terminal for password input (and KYU_PASSWORD not set).\n");
        return -1;
    }

    struct termios old_t, new_t;
    int ret = 0;

    // Disable Echo
    if (tcgetattr(fileno(tty), &old_t) != 0) { fclose(tty); return -1; }
    new_t = old_t;
    new_t.c_lflag &= ~((tcflag_t)ECHO);
    tcsetattr(fileno(tty), TCSAFLUSH, &new_t);

    fprintf(tty, "%s", prompt);
    if (fgets(buf, (int)buflen, tty)) {
        buf[strcspn(buf, "\n")] = 0;
    } else {
        ret = -1;
    }
    fprintf(tty, "\n");

    // Confirmation (if requested)
    if (ret == 0 && confirm) {
        char conf_buf[1024];
        fprintf(tty, "Confirm Password: ");
        if (fgets(conf_buf, sizeof(conf_buf), tty)) {
            conf_buf[strcspn(conf_buf, "\n")] = 0;
            if (strcmp(buf, conf_buf) != 0) {
                fprintf(tty, "Error: Passwords do not match.\n");
                ret = -1;
            }
        } else {
            ret = -1;
        }
        fprintf(tty, "\n");
        memset(conf_buf, 0, sizeof(conf_buf)); // Wipe confirmation
    }

    // Restore Echo
    tcsetattr(fileno(tty), TCSAFLUSH, &old_t);
    fclose(tty);
    return ret;
}
