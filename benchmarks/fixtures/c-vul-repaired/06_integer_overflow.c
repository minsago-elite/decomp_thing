#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static int bytes_for_items(uint32_t count, uint32_t *bytes) {
    if (count > UINT32_MAX / (uint32_t)sizeof(uint32_t)) {
        return 0;
    }
    *bytes = count * (uint32_t)sizeof(uint32_t);
    return 1;
}

static void fill_items(uint32_t *items) {
    items[0] = 0x11111111U;
    items[1] = 0x22222222U;
}

int main(void) {
    uint32_t count = UINT32_MAX / 4U + 2U;
    uint32_t bytes;
    uint32_t *items;

    printf("count = %u\n", count);
    if (!bytes_for_items(count, &bytes)) {
        puts("allocation size overflow");
        return 0;
    }
    printf("size = %zu\n", (size_t)bytes);
    items = malloc(bytes);
    if (items == NULL) {
        perror("malloc");
        return 1;
    }
    fill_items(items);
    printf("items[0] = 0x%x, items[1] = 0x%x\n", items[0], items[1]);
    free(items);
    return 0;
}
