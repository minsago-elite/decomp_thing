#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef AT_EMPTY_PATH
#define AT_EMPTY_PATH 0x1000
#endif

#define TARGET_FD 3
#define ENVIRONMENT_FD 4
#define MAX_ENVIRONMENT_BYTES (1024U * 1024U)
#define MAX_ENVIRONMENT_BINDINGS 1024U
#define STDIN_INHERITED "inherited"
#define STDIN_CLOSED_BEFORE_EXEC "closed-before-exec"

extern char **environ;

static void fail(int code) {
    _exit(code);
}

static int portable_name(const char *name, size_t length) {
    size_t index;
    if (length == 0 || !((name[0] >= 'A' && name[0] <= 'Z') ||
                         (name[0] >= 'a' && name[0] <= 'z') || name[0] == '_')) {
        return 0;
    }
    for (index = 1; index < length; ++index) {
        char value = name[index];
        if (!((value >= 'A' && value <= 'Z') || (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_')) {
            return 0;
        }
    }
    return 1;
}

static int equals_name(const char *name, size_t length, const char *expected) {
    return strlen(expected) == length && memcmp(name, expected, length) == 0;
}

static int reserved_name(const char *name, size_t length) {
    static const char *const exact[] = {
        "BASH_ENV", "BASHOPTS", "SHELLOPTS", "BASH_XTRACEFD", "ENV", "SHLVL",
        "PWD", "OLDPWD", "_", "IFS", "CDPATH", "GLOBIGNORE", "FIGNORE",
        "POSIXLY_CORRECT", "PROMPT_COMMAND", "PS0", "PS1", "PS2", "PS3", "PS4",
        "TIMEFORMAT", "TMOUT", "GCONV_PATH", "LOCPATH", "NLSPATH", "GLIBC_TUNABLES",
        "MALLOC_TRACE", "MALLOC_CHECK_", "TZDIR", "HOSTALIASES", "RES_OPTIONS", "LOCALDOMAIN"
    };
    size_t index;
    if ((length >= 3 && memcmp(name, "LD_", 3) == 0) ||
        (length >= 5 && memcmp(name, "BASH_", 5) == 0)) {
        return 1;
    }
    for (index = 0; index < sizeof(exact) / sizeof(exact[0]); ++index) {
        if (equals_name(name, length, exact[index])) return 1;
    }
    return 0;
}

static int lexical_name_order(
    const char *left,
    size_t left_length,
    const char *right,
    size_t right_length
) {
    size_t common = left_length < right_length ? left_length : right_length;
    int compared = memcmp(left, right, common);
    if (compared != 0) return compared;
    return left_length < right_length ? -1 : left_length > right_length ? 1 : 0;
}

static void normalize_signals(void) {
    struct sigaction action;
    sigset_t empty;
    int signal_number;
    memset(&action, 0, sizeof(action));
    action.sa_handler = SIG_DFL;
    sigemptyset(&action.sa_mask);
    for (signal_number = 1; signal_number < NSIG; ++signal_number) {
        if (signal_number != SIGKILL && signal_number != SIGSTOP) {
            if (sigaction(signal_number, &action, NULL) != 0 && errno != EINVAL) fail(100);
        }
    }
    sigemptyset(&empty);
    if (sigprocmask(SIG_SETMASK, &empty, NULL) != 0) fail(101);
}

static void close_surplus_descriptors(void) {
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 3U, UINT_MAX, 0U) == 0) return;
    if (errno != ENOSYS && errno != EINVAL) fail(102);
#endif
    {
        long maximum = sysconf(_SC_OPEN_MAX);
        int descriptor;
        if (maximum < 0 || maximum > 1048576L) maximum = 1048576L;
        for (descriptor = 3; descriptor < maximum; ++descriptor) close(descriptor);
    }
}

/*
 * bubblewrap deliberately synthesizes PWD after applying --chdir, even after --clearenv.  Accept
 * only that single, self-authenticating value (or no environment for the direct protocol probe),
 * and reject every caller-controlled bootstrap binding before opening the target or gate input.
 */
static void require_clean_bootstrap_environment(void) {
    char current_directory[PATH_MAX];
    static const char prefix[] = "PWD=";
    if (environ == NULL) fail(124);
    if (environ[0] == NULL) return;
    if (environ[1] != NULL || strncmp(environ[0], prefix, sizeof(prefix) - 1U) != 0 ||
        getcwd(current_directory, sizeof(current_directory)) == NULL ||
        strcmp(environ[0] + sizeof(prefix) - 1U, current_directory) != 0) {
        fail(124);
    }
}

static int open_exact(const char *path, int flags, int expected_fd) {
    int descriptor = open(path, flags, 0);
    if (descriptor < 0) fail(103);
    if (descriptor != expected_fd) {
        if (dup3(descriptor, expected_fd, O_CLOEXEC) < 0) fail(104);
        close(descriptor);
    }
    return expected_fd;
}

static char **read_environment(int descriptor) {
    struct stat status;
    char *content;
    char **bindings;
    size_t offset = 0;
    size_t count = 0;
    const char *previous_name = NULL;
    size_t previous_length = 0;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        (status.st_mode & 0777) != 0600 || status.st_nlink != 0 || status.st_size < 0 ||
        (uint64_t)status.st_size > MAX_ENVIRONMENT_BYTES) {
        fail(110);
    }
    content = malloc((size_t)status.st_size + 1U);
    bindings = calloc(MAX_ENVIRONMENT_BINDINGS + 1U, sizeof(char *));
    if (content == NULL || bindings == NULL) fail(111);
    while (offset < (size_t)status.st_size) {
        ssize_t amount = pread(descriptor, content + offset, (size_t)status.st_size - offset, (off_t)offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) fail(112);
        offset += (size_t)amount;
    }
    if (status.st_size > 0 && content[status.st_size - 1] != '\0') fail(113);
    offset = 0;
    while (offset < (size_t)status.st_size) {
        char *record = content + offset;
        size_t remaining = (size_t)status.st_size - offset;
        char *end = memchr(record, '\0', remaining);
        char *separator;
        size_t name_length;
        if (end == NULL || end == record || count >= MAX_ENVIRONMENT_BINDINGS) fail(114);
        separator = memchr(record, '=', (size_t)(end - record));
        if (separator == NULL) fail(115);
        name_length = (size_t)(separator - record);
        if (!portable_name(record, name_length) || reserved_name(record, name_length)) fail(116);
        if (previous_name != NULL &&
            lexical_name_order(previous_name, previous_length, record, name_length) >= 0) {
            fail(117);
        }
        bindings[count++] = record;
        previous_name = record;
        previous_length = name_length;
        offset += (size_t)(end - record) + 1U;
    }
    bindings[count] = NULL;
    return bindings;
}

int main(int argc, char **argv) {
    struct stat target_status;
    struct stat environment_status;
    unsigned char token;
    ssize_t amount;
    char **target_environment;
    int close_stdin_before_exec;
    if (argc < 4 || argv[2][0] != '/' || argv[3][0] != '/') {
        fail(120);
    }
    if (strcmp(argv[1], STDIN_INHERITED) == 0) {
        close_stdin_before_exec = 0;
    } else if (strcmp(argv[1], STDIN_CLOSED_BEFORE_EXEC) == 0) {
        close_stdin_before_exec = 1;
    } else {
        fail(125);
    }
    require_clean_bootstrap_environment();
    normalize_signals();
    close_surplus_descriptors();
    open_exact(argv[3], O_PATH | O_NOFOLLOW | O_CLOEXEC, TARGET_FD);
    open_exact(argv[2], O_RDONLY | O_NOFOLLOW | O_CLOEXEC, ENVIRONMENT_FD);
    if (fstat(TARGET_FD, &target_status) != 0 || !S_ISREG(target_status.st_mode) ||
        (target_status.st_mode & 0111) == 0 ||
        fstat(ENVIRONMENT_FD, &environment_status) != 0 || !S_ISREG(environment_status.st_mode)) {
        fail(121);
    }
    do {
        amount = read(STDIN_FILENO, &token, 1U);
    } while (amount < 0 && errno == EINTR);
    if (amount != 1 || token != (unsigned char)'G') fail(122);
    target_environment = read_environment(ENVIRONMENT_FD);
    close(ENVIRONMENT_FD);
    if (close_stdin_before_exec && close(STDIN_FILENO) != 0) fail(126);
#ifdef SYS_execveat
    syscall(SYS_execveat, TARGET_FD, "", &argv[3], target_environment, AT_EMPTY_PATH);
#else
#error "decomp ACP gate helper requires execveat"
#endif
    fail(123);
    return 123;
}
