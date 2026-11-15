#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int announce(const char *text) {
    /* Print the complete text directly; never interpret it as a shell command. */
    return puts(text) == EOF ? 1 : 0;
}

int main(int argc, char **argv) {
    if (argc < 2) {
        printf("usage: %s '<text to echo>'\n", argv[0]);
        return 1;
    }

    return announce(argv[1]);
}
