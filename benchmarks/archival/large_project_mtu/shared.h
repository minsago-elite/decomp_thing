#ifndef ARCHIVAL_LARGE_PROJECT_SHARED_H
#define ARCHIVAL_LARGE_PROJECT_SHARED_H

typedef struct archive_state {
    int adjustment;
    unsigned runs;
} archive_state;

extern int archive_bias;
extern archive_state shared_archive_state;

int store_state_bias(archive_state *state);
int parse_3(void);
int render_4(void);
int store_5(void);
int util_6(void);
int parse_0(void);
int render_0(void);
int store_0(void);
int util_0(void);

#endif
