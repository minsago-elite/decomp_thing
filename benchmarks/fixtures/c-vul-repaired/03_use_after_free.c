#include <stdio.h>
#include <stdlib.h>

static int *load_counter(void) {
    int *counter = malloc(sizeof(*counter));
    if (counter != NULL) {
        *counter = 12;
    }
    return counter;
}

static void close_counter(int *counter) {
    free(counter);
}

int main(void) {
    int *counter = load_counter();
    if (counter == NULL) {
        perror("malloc");
        return 1;
    }

    printf("before = %d\n", *counter);

    /* Keep ownership until the final read and write are complete. */
    *counter = *counter + 1;

    printf("after = %d\n", *counter);
    close_counter(counter);
    return 0;
}
