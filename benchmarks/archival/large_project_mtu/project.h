/* SPDX-License-Identifier: CC0-1.0 */
#ifndef ARCHIVAL_LARGE_PROJECT_MTU_PROJECT_H
#define ARCHIVAL_LARGE_PROJECT_MTU_PROJECT_H

#include <stddef.h>

typedef struct project_state {
    long accumulated;
    unsigned visits;
} project_state;

extern project_state shared_state;
extern int project_bias;

int parse_value(const char *text);
int render_value(int value);
int read_value(void);
long measure_value(int value);
int report_value(long value);

#endif
