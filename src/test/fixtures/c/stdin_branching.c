#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
    char buf[64] = {0};

    if (argc > 1 && strcmp(argv[1], "secret") == 0) {
        puts("ARG_SECRET");
        return 2;
    }

    if (fgets(buf, sizeof(buf), stdin) && strcmp(buf, "open\n") == 0) {
        puts("STDIN_OPEN");
        return 3;
    }

    puts("DEFAULT");
    return 0;
}
