#include <stdio.h>

static int score_for_day(const int *scores, size_t count, int day, int *score) {
    if (day < 0 || (size_t)day >= count) {
        return 0;
    }
    *score = scores[day];
    return 1;
}

static void show_report(const char *name, int score) {
    printf("%s: %d\n", name, score);
}

int main(void) {
    int weekly_scores[4] = {81, 77, 92, 88};
    const char *user = "guest";
    int selected_day = 4;
    int score;
    if (!score_for_day(weekly_scores, sizeof(weekly_scores) / sizeof(weekly_scores[0]), selected_day, &score)) {
        printf("%s: invalid day\n", user);
        return 0;
    }

    show_report(user, score);

    return 0;
}
