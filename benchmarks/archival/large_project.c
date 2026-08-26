// SPDX-License-Identifier: CC0-1.0
#include <stdio.h>
#include <string.h>

int archive_bias = 7;

#define STAGE(group, n) int group##_##n(void) { return n; }
STAGE(parse, 0)  STAGE(parse, 1)  STAGE(parse, 2)  STAGE(parse, 3)
STAGE(parse, 4)  STAGE(parse, 5)  STAGE(parse, 6)  STAGE(parse, 7)
STAGE(parse, 8)  STAGE(parse, 9)  STAGE(parse, 10) STAGE(parse, 11)
STAGE(render, 0) STAGE(render, 1) STAGE(render, 2) STAGE(render, 3)
STAGE(render, 4) STAGE(render, 5) STAGE(render, 6) STAGE(render, 7)
STAGE(render, 8) STAGE(render, 9) STAGE(render, 10) STAGE(render, 11)
STAGE(store, 0)  STAGE(store, 1)  STAGE(store, 2)  STAGE(store, 3)
STAGE(store, 4)  STAGE(store, 5)  STAGE(store, 6)  STAGE(store, 7)
STAGE(store, 8)  STAGE(store, 9)  STAGE(store, 10) STAGE(store, 11)
STAGE(util, 0)   STAGE(util, 1)   STAGE(util, 2)   STAGE(util, 3)
STAGE(util, 4)   STAGE(util, 5)   STAGE(util, 6)   STAGE(util, 7)
STAGE(util, 8)   STAGE(util, 9)   STAGE(util, 10)  STAGE(util, 11)

int main(int argc, char **argv) {
    char value[128] = {0};
    if (argc >= 3 && strcmp(argv[1], "--file") == 0) {
        FILE *input = fopen(argv[2], "r");
        if (input == NULL || fgets(value, sizeof(value), input) == NULL) return 4;
        fclose(input);
    } else if (argc > 1) {
        snprintf(value, sizeof(value), "%s", argv[1]);
    } else if (fgets(value, sizeof(value), stdin) == NULL) {
        strcpy(value, "default");
    }
    value[strcspn(value, "\r\n")] = '\0';
    printf("%s:%d\n", value, archive_bias + parse_3() + render_4() + store_5() + util_6());
    return argc > 3 ? 3 : 0;
}
