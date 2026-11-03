/* SPDX-License-Identifier: CC0-1.0 */
#include "project.h"

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    char input[64];
    int value;
    if (argc > 1) {
        value = parse_value(argv[1]);
    } else if (fgets(input, sizeof(input), stdin) != NULL) {
        value = parse_value(input);
    } else {
        value = 1;
    }
    shared_state.visits++;
    shared_state.accumulated += render_value(value) + read_value();
    return report_value(measure_value((int)shared_state.accumulated));
}
