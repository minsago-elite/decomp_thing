#include "shared.h"
#include <stdio.h>
#include <string.h>

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
    printf("%s:%d\n", value, archive_bias + store_state_bias(&shared_archive_state) +
        parse_3() + render_4() + store_5() + util_6());
    return argc > 3 ? 3 : 0;
}
