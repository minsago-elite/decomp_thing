#include <stdio.h>
#include <stdlib.h>

static char *new_line(const char *text) {
    char *line = malloc(32);
    if (line != NULL) {
        snprintf(line, 32, "%s", text);
    }
    return line;
}

static void release_line(char *line) {
    /* One owner releases the allocation exactly once, including save failure. */
    free(line);
}

int main(void) {
    char *line = new_line("sample");

    if (line == NULL) {
        perror("malloc");
        return 1;
    }

    puts(line);
    release_line(line);

    return 0;
}
