/* SPDX-License-Identifier: CC0-1.0 */
#include "project.h"

int render_value(int value) {
    shared_state.visits += (unsigned)(value & 3);
    return value * 3 + project_bias;
}
