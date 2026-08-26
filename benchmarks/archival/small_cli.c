// SPDX-License-Identifier: CC0-1.0
#include <stdio.h>

int main(int argc, char **argv) {
    if (argc > 1) printf("arg:%s\n", argv[1]);
    else puts("arg:default");
    return argc > 2 ? 2 : 0;
}
