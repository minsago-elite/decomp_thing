#include "shared.h"

int archive_bias = 7;
archive_state shared_archive_state = { 2, 0 };

int store_state_bias(archive_state *state) {
    state->runs++;
    return state->adjustment;
}
