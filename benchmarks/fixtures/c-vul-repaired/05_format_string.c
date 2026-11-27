#include <stdio.h>

static void write_log(const char *tag, const char *message) {
    printf("[%s] ", tag);
    /* User text is data, including percent conversions. */
    printf("%s", message);
    putchar('\n');
}

int main(int argc, char **argv) {
    const char *tag = "info";

    if (argc < 2) {
        printf("usage: %s '<message>'\n", argv[0]);
        return 1;
    }

    write_log(tag, argv[1]);

    return 0;
}
