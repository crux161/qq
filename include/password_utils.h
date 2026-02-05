#ifndef KYU_PASSWORD_UTILS_H
#define KYU_PASSWORD_UTILS_H

#include <stddef.h>

#define KYU_PASS_MIN_LEN 14

/**
 * @brief Check password complexity.
 * @return 1 if strong enough, 0 otherwise.
 */
int kyu_password_check_strength(const char *pass);

/**
 * @brief Read password from /dev/tty or KYU_PASSWORD env.
 * @param buf Output buffer
 * @param buflen Buffer size
 * @param prompt Text to display
 * @param confirm 1 to require confirmation (for new passwords)
 * @return 0 on success, -1 on failure
 */
int kyu_get_password(char *buf, size_t buflen, const char *prompt, int confirm);

#endif

