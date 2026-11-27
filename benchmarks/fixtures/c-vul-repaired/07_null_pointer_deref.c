#include <stdio.h>

struct Record {
    int id;
    int score;
};

static struct Record *find_record(int id) {
    if (id == 100) {
        static struct Record record = {100, 41};
        return &record;
    }
    return NULL;
}

static void update_score(struct Record *record, int score) {
    /* The caller verifies that lookup succeeded. */
    record->score = score;
}

int main(void) {
    int requested_id = 200;
    struct Record *record = find_record(requested_id);

    if (record == NULL) {
        printf("record not found: %d\n", requested_id);
        return 0;
    }

    update_score(record, 42);
    printf("%d: %d\n", record->id, record->score);
    return 0;
}
