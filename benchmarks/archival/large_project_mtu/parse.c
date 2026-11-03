/* SPDX-License-Identifier: CC0-1.0 */
#include "project.h"

#include <stdlib.h>

int parse_value(const char *text) {
    char *end = NULL;
    long value = strtol(text, &end, 10);
    return end == text ? project_bias : (int)value + project_bias;
}
