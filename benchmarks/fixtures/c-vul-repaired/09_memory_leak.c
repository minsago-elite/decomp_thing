#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static char *make_note(const char *text) {
    char *note = malloc(128);
    if (note != NULL) {
        snprintf(note, 128, "%s", text);
    }
    return note;
}

static void send_note(const char *user, const char *note) {
    printf("%s: %s\n", user, note);
}

int main(void) {
    const char *user = "guest";
    char *note = make_note("sample data");

    if (note == NULL) {
        perror("malloc");
        return 1;
    }

    send_note(user, note);

    free(note);
    return 0;
}
