#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define KYU_PASS_MIN_LEN 14
#define KYU_PASS_MAX_LEN 1024

int kyu_password_check_strength(const char *pass) {
    size_t len = strlen(pass);
    if (len < KYU_PASS_MIN_LEN) {
        fprintf(stderr, "Error: Password is too short.\n");
        fprintf(stderr, "Policy: Must be at least %d characters.\n", KYU_PASS_MIN_LEN);
        fprintf(stderr, "Tip:    Try a passphrase like 'correct-horse-battery-staple'.\n");
        return 0; // Fail
    }
    return 1; // Pass
}

int kyu_read_password_secure(char *buf, size_t buflen, const char *prompt) {
    struct termios old_term, new_term;
    int ret = 0;

    FILE *fp = fopen("/dev/tty", "r+");
    if (!fp) fp = stdin; 

    if (prompt) {
        fprintf(stdout, "%s", prompt);
        fflush(stdout);
    }

    if (tcgetattr(fileno(fp), &old_term) != 0) {
        ret = -1; 
    } else {
        new_term = old_term;
        // FIX: Cast ECHO to tcflag_t to match c_lflag signedness
        new_term.c_lflag &= ~((tcflag_t)ECHO); 
        if (tcsetattr(fileno(fp), TCSAFLUSH, &new_term) != 0) {
            ret = -1;
        }
    }

    if (ret == 0) {
        if (fgets(buf, (int)buflen, fp) == NULL) {
            ret = -1;
        } else {
            buf[strcspn(buf, "\n")] = 0;
        }
    }

    if (tcsetattr(fileno(fp), TCSAFLUSH, &old_term) != 0) {
        ret = -1;
    }

    fprintf(stdout, "\n");
    if (fp != stdin) fclose(fp);
    
    return ret;
}
