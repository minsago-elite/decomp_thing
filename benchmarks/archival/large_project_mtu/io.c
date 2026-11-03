/* SPDX-License-Identifier: CC0-1.0 */
#include "project.h"

#include <stdio.h>

int read_value(void) {
    int value = getchar();
    return value == EOF ? 0 : value & 15;
}
