#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int visibility(const char *root, const char *host_file) {
    struct stat value;
    if (stat(root, &value) != 0 || !S_ISDIR(value.st_mode)) return 10;
    if (lstat(host_file, &value) == 0 || errno != ENOENT) return 11;
    return 0;
}

static int netns(void) {
    char value[256];
    ssize_t count = readlink("/proc/self/ns/net", value, sizeof(value) - 1);
    if (count <= 0) return 20;
    value[count] = '\0';
    puts(value);
    fflush(stdout);
    return 0;
}

static int escape(void) {
    pid_t child = fork();
    if (child < 0) return 30;
    if (child == 0) {
        if (setsid() < 0) _exit(31);
        signal(SIGTERM, SIG_IGN);
        signal(SIGHUP, SIG_IGN);
        for (;;) pause();
    }
    printf("%ld\n", (long) child);
    fflush(stdout);
    for (;;) pause();
}

static int create_many(const char *root, long count, int directories) {
    char path[4096];
    for (long index = 0; index < count; ++index) {
        if (snprintf(path, sizeof(path), "%s/%s-%ld", root, directories ? "dir" : "file", index) >= (int) sizeof(path)) return 40;
        if (directories) {
            if (mkdir(path, 0700) != 0) return errno == ENOSPC ? 0 : 41;
        } else {
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
            if (fd < 0) return errno == ENOSPC ? 0 : 42;
            if (write(fd, "x", 1) != 1) { close(fd); return errno == ENOSPC ? 0 : 43; }
            close(fd);
        }
    }
    return 44;
}

static int sparse(const char *root, long long size) {
    char path[4096];
    if (snprintf(path, sizeof(path), "%s/sparse", root) >= (int) sizeof(path)) return 50;
    int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return errno == ENOSPC ? 0 : 51;
    signal(SIGXFSZ, SIG_IGN);
    int result = ftruncate(fd, (off_t) size);
    if (result == 0) result = write(fd, "x", 1) == 1 ? 0 : -1;
    close(fd);
    return result == 0 ? 0 : (errno == ENOSPC || errno == EFBIG ? 0 : 52);
}

static int background_writer(const char *root) {
    pid_t child = fork();
    if (child < 0) return 60;
    if (child == 0) {
        char path[4096];
        for (long index = 0;; ++index) {
            snprintf(path, sizeof(path), "%s/background-%ld", root, index);
            int fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0600);
            if (fd < 0) _exit(errno == ENOSPC ? 0 : 61);
            char block[4096] = {0};
            while (write(fd, block, sizeof(block)) == (ssize_t) sizeof(block)) {}
            close(fd);
            if (errno == ENOSPC) _exit(0);
        }
    }
    printf("%ld\n", (long) child);
    fflush(stdout);
    for (;;) pause();
}

static int terminal_output(void) {
    if (write(STDOUT_FILENO, "0123456789abcdef", 16) != 16) return 70;
    return 0;
}

static int terminal_flood(void) {
    char block[4096];
    memset(block, 'x', sizeof(block));
    for (;;) {
        if (write(STDOUT_FILENO, block, sizeof(block)) < 0) return errno == EPIPE ? 0 : 71;
    }
}

static int terminal_burst_exit(void) {
    char block[4096];
    memset(block, 'b', sizeof(block));
    if (write(STDOUT_FILENO, block, sizeof(block)) != (ssize_t) sizeof(block)) return 72;
    return 0;
}

static int terminal_sleep(void) {
    for (;;) pause();
    return 0;
}

static int gate_protocol(void) {
    unsigned char value;
    const char *configured = getenv("PUBLIC_VALUE");
    if (configured == NULL || read(STDIN_FILENO, &value, 1) != 1) return 80;
    printf("%s:%c\n", configured, value);
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv) {
    if (argc >= 4 && strcmp(argv[1], "visibility") == 0) return visibility(argv[2], argv[3]);
    if (argc == 2 && strcmp(argv[1], "netns") == 0) return netns();
    if (argc == 2 && strcmp(argv[1], "escape") == 0) return escape();
    if (argc == 4 && strcmp(argv[1], "many-files") == 0) return create_many(argv[2], strtol(argv[3], NULL, 10), 0);
    if (argc == 4 && strcmp(argv[1], "many-dirs") == 0) return create_many(argv[2], strtol(argv[3], NULL, 10), 1);
    if (argc == 4 && strcmp(argv[1], "sparse") == 0) return sparse(argv[2], strtoll(argv[3], NULL, 10));
    if (argc == 3 && strcmp(argv[1], "background-writer") == 0) return background_writer(argv[2]);
    if (argc == 2 && strcmp(argv[1], "terminal-output") == 0) return terminal_output();
    if (argc == 2 && strcmp(argv[1], "terminal-flood") == 0) return terminal_flood();
    if (argc == 2 && strcmp(argv[1], "terminal-burst-exit") == 0) return terminal_burst_exit();
    if (argc == 2 && strcmp(argv[1], "terminal-sleep") == 0) return terminal_sleep();
    if (argc == 2 && strcmp(argv[1], "gate-protocol") == 0) return gate_protocol();
    return 2;
}
