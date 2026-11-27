#include <stdio.h>
#include <string.h>

static void normalize_name(char *dst, const char *first, const char *last) {
    /* The caller supplies space for both names, separator and terminator. */
    strcpy(dst, first);
    strcat(dst, " ");
    strcat(dst, last);
}

static void print_badge(const char *name, int level) {
    printf("[%02d] %s\n", level, name);
}

int main(void) {
    char display_name[sizeof("Alexandria Stone")];
    const char *first = "Alexandria";
    const char *last = "Stone";
    int account_level = 3;

    normalize_name(display_name, first, last);
    print_badge(display_name, account_level);

    return 0;
}
