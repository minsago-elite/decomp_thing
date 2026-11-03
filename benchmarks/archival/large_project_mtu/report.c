/* SPDX-License-Identifier: CC0-1.0 */
#include "project.h"

#include <stdio.h>

int report_value(long value) {
    printf("value=%ld visits=%u\n", value, shared_state.visits);
    return (int)(value & 3);
}
