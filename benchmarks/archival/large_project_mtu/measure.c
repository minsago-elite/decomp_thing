/* SPDX-License-Identifier: CC0-1.0 */
#include "project.h"

long measure_value(int value) {
    shared_state.accumulated += value;
    return shared_state.accumulated + (long)shared_state.visits;
}
