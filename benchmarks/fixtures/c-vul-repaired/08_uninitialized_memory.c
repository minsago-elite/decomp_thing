#include <stdio.h>

static void apply_mode(int mode) {
    if (mode == 1) {
        puts("fast");
    } else if (mode == 2) {
        puts("safe");
    } else {
        puts("default");
    }
}

int main(void) {
    int mode = 0;
    int config_loaded = 0;

    if (config_loaded) {
        mode = 2;
    }

    /* Missing configuration uses the initialized default. */
    apply_mode(mode);

    return 0;
}
