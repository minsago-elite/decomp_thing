#include "shared.h"

#define STAGE(n) int render_##n(void) { return n; }
STAGE(0) STAGE(1) STAGE(2) STAGE(3) STAGE(4) STAGE(5)
STAGE(6) STAGE(7) STAGE(8) STAGE(9) STAGE(10) STAGE(11)
