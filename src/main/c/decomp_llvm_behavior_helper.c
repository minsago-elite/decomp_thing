#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <unistd.h>

#define FAILURE_EXIT 125
#define PROTOCOL "decomp-llvm-behavior-helper-v2"
#define PREEXEC_FRAME "behavior-preexec-v2:"
#define CASE_INPUTS_PATH "/case-inputs"
#define WORKSPACE_PATH "/workspace"
#define CASE_RESULTS_PATH "/case-results"
#define CGROUP_PATH "/sys/fs/cgroup"

#define MAXIMUM_ARGUMENTS 4096U
#define MAXIMUM_ARGUMENT_BYTES (1024U * 1024U)
#define MAXIMUM_ENVIRONMENT_BINDINGS 1024U
#define MAXIMUM_ENVIRONMENT_BYTES (1024U * 1024U)
#define MAXIMUM_TEXT_BYTES (1024U * 1024U)
#define MAXIMUM_WORKSPACE_BYTES (32ULL * 1024ULL * 1024ULL)
#define MAXIMUM_WORKSPACE_ENTRIES 1024ULL
#define MAXIMUM_TREE_DEPTH 64U
#define COPY_BUFFER_BYTES (1024U * 1024U)

extern char **environ;

/* Retained verbatim so build/install verification can bind the control-frame contract. */
__attribute__((used)) static const char preexec_frame_contract[] = PREEXEC_FRAME;

struct copy_budget {
    uint64_t maximum_bytes;
    uint64_t maximum_entries;
    uint64_t logical_bytes;
    uint64_t allocated_bytes;
    uint64_t entries;
};

struct name_list {
    char **items;
    size_t count;
};

static void fail(void) {
    static const char diagnostic[] = PROTOCOL ": rejected\n";
    size_t offset = 0U;
    while (offset < sizeof(diagnostic) - 1U) {
        ssize_t amount = write(STDERR_FILENO, diagnostic + offset, sizeof(diagnostic) - 1U - offset);
        if (amount > 0) {
            offset += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            break;
        }
    }
    _exit(FAILURE_EXIT);
}

static int checked_add_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (UINT64_MAX - left < right) return 0;
    *result = left + right;
    return 1;
}

static int checked_multiply_u64(uint64_t left, uint64_t right, uint64_t *result) {
    if (left != 0U && right > UINT64_MAX / left) return 0;
    *result = left * right;
    return 1;
}

static uint64_t parse_unsigned(const char *value, uint64_t minimum, uint64_t maximum) {
    uint64_t result = 0U;
    size_t index;
    size_t length;
    if (value == NULL) fail();
    length = strlen(value);
    if (length == 0U || length > 20U || (length > 1U && value[0] == '0')) fail();
    for (index = 0U; index < length; ++index) {
        unsigned int digit;
        if (value[index] < '0' || value[index] > '9') fail();
        digit = (unsigned int)(value[index] - '0');
        if (result > (UINT64_MAX - digit) / 10U) fail();
        result = result * 10U + digit;
    }
    if (result < minimum || result > maximum) fail();
    return result;
}

static int portable_environment_name(const char *value, size_t length) {
    size_t index;
    if (length == 0U || !((value[0] >= 'A' && value[0] <= 'Z') ||
                          (value[0] >= 'a' && value[0] <= 'z') || value[0] == '_')) {
        return 0;
    }
    for (index = 1U; index < length; ++index) {
        if (!((value[index] >= 'A' && value[index] <= 'Z') ||
              (value[index] >= 'a' && value[index] <= 'z') ||
              (value[index] >= '0' && value[index] <= '9') || value[index] == '_')) {
            return 0;
        }
    }
    return 1;
}

static size_t validate_environment(void) {
    size_t count = 0U;
    size_t total = 0U;
    size_t index;
    if (environ == NULL) fail();
    while (environ[count] != NULL) {
        const char *separator;
        size_t length;
        size_t name_length;
        if (count >= MAXIMUM_ENVIRONMENT_BINDINGS) fail();
        length = strnlen(environ[count], MAXIMUM_ENVIRONMENT_BYTES + 1U);
        uint64_t expanded_total;
        if (length == 0U || length > MAXIMUM_ENVIRONMENT_BYTES ||
            !checked_add_u64((uint64_t)total, (uint64_t)length + 1U, &expanded_total) ||
            expanded_total > MAXIMUM_ENVIRONMENT_BYTES) {
            fail();
        }
        total = (size_t)expanded_total;
        separator = memchr(environ[count], '=', length);
        if (separator == NULL) fail();
        name_length = (size_t)(separator - environ[count]);
        if (!portable_environment_name(environ[count], name_length)) fail();
        for (index = 0U; index < count; ++index) {
            const char *prior_separator = strchr(environ[index], '=');
            size_t prior_length;
            if (prior_separator == NULL) fail();
            prior_length = (size_t)(prior_separator - environ[index]);
            if (prior_length == name_length && memcmp(environ[index], environ[count], name_length) == 0) fail();
        }
        ++count;
    }
    return count;
}

static const char *exact_environment_value(const char *name) {
    size_t name_length = strlen(name);
    size_t index;
    const char *found = NULL;
    for (index = 0U; environ[index] != NULL; ++index) {
        if (strncmp(environ[index], name, name_length) == 0 && environ[index][name_length] == '=') {
            if (found != NULL) fail();
            found = environ[index] + name_length + 1U;
        }
    }
    if (found == NULL) fail();
    return found;
}

static void require_exact_environment(const char *const *names, size_t expected_count) {
    size_t actual_count = validate_environment();
    size_t index;
    if (actual_count != expected_count) fail();
    for (index = 0U; index < expected_count; ++index) (void)exact_environment_value(names[index]);
}

static int metadata_equal(const struct stat *left, const struct stat *right) {
    return left->st_dev == right->st_dev && left->st_ino == right->st_ino &&
           left->st_mode == right->st_mode && left->st_nlink == right->st_nlink &&
           left->st_uid == right->st_uid && left->st_gid == right->st_gid &&
           left->st_size == right->st_size && left->st_blocks == right->st_blocks &&
           left->st_mtim.tv_sec == right->st_mtim.tv_sec &&
           left->st_mtim.tv_nsec == right->st_mtim.tv_nsec &&
           left->st_ctim.tv_sec == right->st_ctim.tv_sec &&
           left->st_ctim.tv_nsec == right->st_ctim.tv_nsec;
}

static uint64_t descriptor_mount_id(int descriptor) {
    struct statx status;
    memset(&status, 0, sizeof(status));
    if (statx(descriptor, "", AT_EMPTY_PATH | AT_NO_AUTOMOUNT | AT_SYMLINK_NOFOLLOW,
              STATX_MNT_ID, &status) != 0 || (status.stx_mask & STATX_MNT_ID) == 0U) {
        fail();
    }
    return status.stx_mnt_id;
}

static void write_all(int descriptor, const unsigned char *content, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        ssize_t amount = write(descriptor, content + offset, length - offset);
        if (amount > 0) {
            offset += (size_t)amount;
        } else if (amount < 0 && errno == EINTR) {
            continue;
        } else {
            fail();
        }
    }
}

static size_t read_bounded_file(const char *path, unsigned char *content, size_t capacity) {
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    size_t offset = 0U;
    if (descriptor < 0) fail();
    while (offset < capacity) {
        ssize_t amount = read(descriptor, content + offset, capacity - offset);
        if (amount > 0) {
            offset += (size_t)amount;
        } else if (amount == 0) {
            close(descriptor);
            return offset;
        } else if (errno != EINTR) {
            close(descriptor);
            fail();
        }
    }
    {
        unsigned char extra;
        ssize_t amount;
        do {
            amount = read(descriptor, &extra, 1U);
        } while (amount < 0 && errno == EINTR);
        close(descriptor);
        if (amount != 0) fail();
    }
    return offset;
}

static int option_present(const char *options, const char *expected) {
    size_t expected_length = strlen(expected);
    const char *cursor = options;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ',');
        size_t length = end == NULL ? strlen(cursor) : (size_t)(end - cursor);
        if (length == expected_length && memcmp(cursor, expected, length) == 0) return 1;
        if (end == NULL) break;
        cursor = end + 1;
    }
    return 0;
}

static void require_mount(const char *mount_point, const char *filesystem, int require_read_only) {
    unsigned char content[MAXIMUM_TEXT_BYTES + 1U];
    size_t length = read_bounded_file("/proc/self/mountinfo", content, MAXIMUM_TEXT_BYTES);
    char *cursor;
    size_t matches = 0U;
    content[length] = '\0';
    cursor = (char *)content;
    while (*cursor != '\0') {
        char *line_end = strchr(cursor, '\n');
        char *tokens[64];
        size_t token_count = 0U;
        size_t separator = SIZE_MAX;
        char *token_cursor;
        if (line_end == NULL) fail();
        *line_end = '\0';
        token_cursor = cursor;
        while (*token_cursor != '\0') {
            char *space;
            if (token_count >= sizeof(tokens) / sizeof(tokens[0])) fail();
            tokens[token_count++] = token_cursor;
            space = strchr(token_cursor, ' ');
            if (space == NULL) break;
            *space = '\0';
            token_cursor = space + 1;
            if (*token_cursor == '\0') fail();
        }
        if (token_count < 10U) fail();
        if (strcmp(tokens[4], mount_point) == 0) {
            size_t index;
            ++matches;
            for (index = 6U; index < token_count; ++index) {
                if (strcmp(tokens[index], "-") == 0) {
                    separator = index;
                    break;
                }
            }
            if (separator == SIZE_MAX || separator + 3U >= token_count ||
                strcmp(tokens[separator + 1U], filesystem) != 0 ||
                (require_read_only && !option_present(tokens[5], "ro"))) {
                fail();
            }
            if (strcmp(mount_point, WORKSPACE_PATH) == 0) {
                const char *expected_access = require_read_only ? "ro" : "rw";
                if (!option_present(tokens[5], expected_access) || !option_present(tokens[5], "nosuid") ||
                    !option_present(tokens[5], "nodev") || !option_present(tokens[separator + 3U], "rw")) {
                    fail();
                }
            }
            if ((strcmp(mount_point, WORKSPACE_PATH) == 0 || strcmp(mount_point, CGROUP_PATH) == 0) &&
                strcmp(tokens[3], "/") != 0) {
                fail();
            }
        }
        cursor = line_end + 1;
    }
    if (matches != 1U) fail();
}

static size_t read_control(int root, const char *name, char *content, size_t capacity) {
    int descriptor = openat(root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    size_t offset = 0U;
    if (descriptor < 0) fail();
    while (offset + 1U < capacity) {
        ssize_t amount = read(descriptor, content + offset, capacity - offset - 1U);
        if (amount > 0) {
            offset += (size_t)amount;
        } else if (amount == 0) {
            break;
        } else if (errno != EINTR) {
            close(descriptor);
            fail();
        }
    }
    if (offset + 1U >= capacity) {
        char extra;
        ssize_t amount;
        do {
            amount = read(descriptor, &extra, 1U);
        } while (amount < 0 && errno == EINTR);
        if (amount != 0) {
            close(descriptor);
            fail();
        }
    }
    close(descriptor);
    while (offset > 0U && (content[offset - 1U] == '\n' || content[offset - 1U] == '\r')) --offset;
    content[offset] = '\0';
    return offset;
}

static void require_control(int root, const char *name, const char *expected) {
    char content[4096];
    size_t length = read_control(root, name, content, sizeof(content));
    if (strlen(expected) != length || memcmp(content, expected, length) != 0) fail();
}

static int control_exists(int root, const char *name) {
    struct stat status;
    if (fstatat(root, name, &status, AT_SYMLINK_NOFOLLOW) == 0) return 1;
    if (errno == ENOENT) return 0;
    fail();
    return 0;
}

static void require_control_not_writable(int root, const char *name) {
    int descriptor;
    errno = 0;
    if (faccessat(root, name, W_OK, AT_EACCESS) == 0) fail();
    if (errno != EACCES && errno != EPERM && errno != EROFS) fail();
    descriptor = openat(root, name, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor >= 0) {
        close(descriptor);
        fail();
    }
    if (errno != EACCES && errno != EPERM && errno != EROFS) fail();
}

static int word_present(const char *content, const char *word) {
    size_t word_length = strlen(word);
    const char *cursor = content;
    while (*cursor != '\0') {
        const char *end;
        while (*cursor == ' ') ++cursor;
        if (*cursor == '\0') break;
        end = strchr(cursor, ' ');
        if (end == NULL) end = cursor + strlen(cursor);
        if ((size_t)(end - cursor) == word_length && memcmp(cursor, word, word_length) == 0) return 1;
        cursor = end;
    }
    return 0;
}

static void require_no_cgroup_children(int root) {
    int duplicate = dup(root);
    DIR *directory;
    struct dirent *entry;
    if (duplicate < 0) fail();
    directory = fdopendir(duplicate);
    if (directory == NULL) {
        close(duplicate);
        fail();
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat status;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        if (fstatat(root, entry->d_name, &status, AT_SYMLINK_NOFOLLOW) != 0) {
            closedir(directory);
            fail();
        }
        if (S_ISDIR(status.st_mode)) {
            closedir(directory);
            fail();
        }
        errno = 0;
    }
    if (errno != 0 || closedir(directory) != 0) fail();
}

static void require_rlimit(int resource, uint64_t expected) {
    struct rlimit limit;
    if (getrlimit(resource, &limit) != 0 || (uint64_t)limit.rlim_cur != expected ||
        (uint64_t)limit.rlim_max != expected) {
        fail();
    }
}

static void pre_exec(int argc, char **argv) {
    static const char *const required_controls[] = {
        "memory.max", "memory.swap.max", "memory.high", "memory.low", "memory.min",
        "memory.oom.group", "pids.max", "cpu.max", "cpu.weight", "cgroup.subtree_control",
        "cgroup.type", "cgroup.procs"
    };
    static const char *const optional_names[] = {
        "cpu.idle", "cpu.weight.nice", "cpu.uclamp.min", "cpu.uclamp.max", "memory.swap.high",
        "memory.zswap.max", "memory.zswap.writeback", "io.max", "io.weight"
    };
    static const char *const optional_values[] = {
        "0", "0", "0.00", "max", "max", "max", "1", "", "default 100"
    };
    const char *role;
    const char *nonce;
    uint64_t memory_max;
    uint64_t pids_max;
    uint64_t cpu_quota;
    uint64_t cpu_period;
    uint64_t file_size;
    uint64_t open_files;
    uint64_t processes;
    uint64_t cpu_seconds;
    uint64_t oom_adjustment;
    int cgroup;
    char expected[128];
    char content[4096];
    size_t index;
    size_t total_argument_bytes = 0U;
    unsigned char marker[96];
    size_t marker_length = 0U;
    unsigned char cgroup_membership[16];
    size_t cgroup_membership_length;

    if (argc < 16 || argc > (int)MAXIMUM_ARGUMENTS || strcmp(argv[14], "--") != 0) fail();
    role = argv[3];
    nonce = argv[4];
    if (strcmp(role, "keeper") != 0 && strcmp(role, "setup") != 0 &&
        strcmp(role, "target") != 0 && strcmp(role, "collector") != 0) {
        fail();
    }
    if (strlen(nonce) != 32U) fail();
    for (index = 0U; index < 32U; ++index) {
        if (!((nonce[index] >= '0' && nonce[index] <= '9') || (nonce[index] >= 'a' && nonce[index] <= 'f'))) fail();
    }
    for (index = 15U; index < (size_t)argc; ++index) {
        size_t length = strnlen(argv[index], 4097U);
        uint64_t expanded_total;
        if (length == 0U || length > 4096U ||
            !checked_add_u64((uint64_t)total_argument_bytes, (uint64_t)length + 1U,
                             &expanded_total) ||
            expanded_total > MAXIMUM_ARGUMENT_BYTES) {
            fail();
        }
        total_argument_bytes = (size_t)expanded_total;
    }
    if (argv[15][0] != '/') fail();
    (void)validate_environment();

    memory_max = parse_unsigned(argv[5], 64ULL * 1024ULL * 1024ULL, 8ULL * 1024ULL * 1024ULL * 1024ULL);
    pids_max = parse_unsigned(argv[6], 1U, 4096U);
    cpu_quota = parse_unsigned(argv[7], 1U, 1000000U);
    cpu_period = parse_unsigned(argv[8], 1000U, 1000000U);
    file_size = parse_unsigned(argv[9], 1U, 16ULL * 1024ULL * 1024ULL);
    open_files = parse_unsigned(argv[10], 16U, 4096U);
    processes = parse_unsigned(argv[11], 1U, 4096U);
    cpu_seconds = parse_unsigned(argv[12], 1U, 30U);
    oom_adjustment = parse_unsigned(argv[13], 0U, 1000U);
    if (cpu_quota != 100000U || cpu_period != 100000U || oom_adjustment != 500U || pids_max != processes) fail();
    if (strcmp(role, "target") == 0) {
        if (memory_max != 1073741824U || file_size != 16777216U || open_files != 128U ||
            processes != 128U || cpu_seconds != 10U) {
            fail();
        }
    } else if (memory_max != 536870912U || file_size != 65536U || open_files != 128U ||
               processes != 64U || cpu_seconds != 30U) {
        fail();
    }

    cgroup_membership_length = read_bounded_file(
        "/proc/self/cgroup", cgroup_membership, sizeof(cgroup_membership)
    );
    if (cgroup_membership_length != 5U || memcmp(cgroup_membership, "0::/\n", 5U) != 0) fail();
    require_mount(CGROUP_PATH, "cgroup2", 1);
    cgroup = open(CGROUP_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (cgroup < 0) fail();

    (void)snprintf(expected, sizeof(expected), "%llu", (unsigned long long)memory_max);
    require_control(cgroup, "memory.max", expected);
    require_control(cgroup, "memory.swap.max", "0");
    require_control(cgroup, "memory.high", "max");
    require_control(cgroup, "memory.low", "0");
    require_control(cgroup, "memory.min", "0");
    require_control(cgroup, "memory.oom.group", "0");
    (void)snprintf(expected, sizeof(expected), "%llu", (unsigned long long)pids_max);
    require_control(cgroup, "pids.max", expected);
    (void)snprintf(expected, sizeof(expected), "%llu %llu",
                   (unsigned long long)cpu_quota, (unsigned long long)cpu_period);
    require_control(cgroup, "cpu.max", expected);
    require_control(cgroup, "cpu.weight", "100");
    require_control(cgroup, "cgroup.subtree_control", "");
    require_control(cgroup, "cgroup.type", "domain");
    require_control(cgroup, "cgroup.procs", "1");
    if (control_exists(cgroup, "cpu.max.burst")) require_control(cgroup, "cpu.max.burst", "0");
    for (index = 0U; index < sizeof(optional_names) / sizeof(optional_names[0]); ++index) {
        if (control_exists(cgroup, optional_names[index])) require_control(cgroup, optional_names[index], optional_values[index]);
    }
    if (control_exists(cgroup, "cpuset.cpus") != control_exists(cgroup, "cpuset.cpus.effective") ||
        control_exists(cgroup, "cpuset.mems") != control_exists(cgroup, "cpuset.mems.effective")) {
        close(cgroup);
        fail();
    }
    if (control_exists(cgroup, "cpuset.cpus")) {
        require_control(cgroup, "cpuset.cpus", "");
        if (read_control(cgroup, "cpuset.cpus.effective", content, sizeof(content)) == 0U) {
            close(cgroup);
            fail();
        }
    }
    if (control_exists(cgroup, "cpuset.mems")) {
        require_control(cgroup, "cpuset.mems", "");
        if (read_control(cgroup, "cpuset.mems.effective", content, sizeof(content)) == 0U) {
            close(cgroup);
            fail();
        }
    }
    (void)read_control(cgroup, "cgroup.controllers", content, sizeof(content));
    if (!word_present(content, "cpu") || !word_present(content, "memory") || !word_present(content, "pids")) {
        close(cgroup);
        fail();
    }
    require_no_cgroup_children(cgroup);
    if (faccessat(cgroup, ".", W_OK, AT_EACCESS) == 0 ||
        (errno != EACCES && errno != EPERM && errno != EROFS)) {
        close(cgroup);
        fail();
    }
    for (index = 0U; index < sizeof(required_controls) / sizeof(required_controls[0]); ++index) {
        require_control_not_writable(cgroup, required_controls[index]);
    }
    require_control_not_writable(cgroup, "cgroup.threads");
    close(cgroup);

    {
        unsigned char oom[32];
        size_t oom_length = read_bounded_file("/proc/self/oom_score_adj", oom, sizeof(oom));
        (void)snprintf(expected, sizeof(expected), "%llu\n", (unsigned long long)oom_adjustment);
        if (strlen(expected) != oom_length || memcmp(oom, expected, oom_length) != 0) fail();
    }
    require_rlimit(RLIMIT_CORE, 0U);
    require_rlimit(RLIMIT_FSIZE, file_size);
    require_rlimit(RLIMIT_NOFILE, open_files);
    require_rlimit(RLIMIT_NPROC, processes);
    require_rlimit(RLIMIT_CPU, cpu_seconds);

    marker[marker_length++] = 0U;
    memcpy(marker + marker_length, preexec_frame_contract, sizeof(preexec_frame_contract) - 1U);
    marker_length += sizeof(preexec_frame_contract) - 1U;
    memcpy(marker + marker_length, role, strlen(role));
    marker_length += strlen(role);
    marker[marker_length++] = ':';
    memcpy(marker + marker_length, nonce, 32U);
    marker_length += 32U;
    marker[marker_length++] = '\n';
    write_all(STDOUT_FILENO, marker, marker_length);
    execv(argv[15], &argv[15]);
    fail();
}

static int compare_names(const void *left, const void *right) {
    const char *const *left_name = (const char *const *)left;
    const char *const *right_name = (const char *const *)right;
    return strcmp(*left_name, *right_name);
}

static void free_names(struct name_list *names) {
    size_t index;
    for (index = 0U; index < names->count; ++index) free(names->items[index]);
    free(names->items);
    names->items = NULL;
    names->count = 0U;
}

static struct name_list list_names(int descriptor, uint64_t maximum) {
    struct name_list result;
    int duplicate;
    DIR *directory;
    struct dirent *entry;
    result.items = NULL;
    result.count = 0U;
    /* A dup shares the directory offset and would make a terminal rescan vacuous. */
    duplicate = openat(descriptor, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (duplicate < 0) fail();
    directory = fdopendir(duplicate);
    if (directory == NULL) {
        close(duplicate);
        fail();
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        size_t length;
        char **expanded;
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        length = strnlen(entry->d_name, NAME_MAX + 1U);
        if (length == 0U || length > NAME_MAX || strchr(entry->d_name, '/') != NULL ||
            result.count >= (size_t)maximum) {
            closedir(directory);
            free_names(&result);
            fail();
        }
        expanded = realloc(result.items, (result.count + 1U) * sizeof(char *));
        if (expanded == NULL) {
            closedir(directory);
            free_names(&result);
            fail();
        }
        result.items = expanded;
        result.items[result.count] = strdup(entry->d_name);
        if (result.items[result.count] == NULL) {
            closedir(directory);
            free_names(&result);
            fail();
        }
        ++result.count;
        errno = 0;
    }
    if (errno != 0 || closedir(directory) != 0) {
        free_names(&result);
        fail();
    }
    qsort(result.items, result.count, sizeof(char *), compare_names);
    return result;
}

static void require_same_names(int descriptor, const struct name_list *expected, uint64_t maximum) {
    struct name_list actual = list_names(descriptor, maximum);
    size_t index;
    if (actual.count != expected->count) {
        free_names(&actual);
        fail();
    }
    for (index = 0U; index < actual.count; ++index) {
        if (strcmp(actual.items[index], expected->items[index]) != 0) {
            free_names(&actual);
            fail();
        }
    }
    free_names(&actual);
}

static void account_entry(struct copy_budget *budget, const struct stat *status) {
    uint64_t logical;
    uint64_t allocated;
    uint64_t blocks;
    if (status->st_size < 0 || status->st_blocks < 0 || budget->entries >= budget->maximum_entries) fail();
    if (!checked_add_u64(budget->logical_bytes, (uint64_t)status->st_size, &logical) ||
        !checked_multiply_u64((uint64_t)status->st_blocks, 512U, &blocks) ||
        !checked_add_u64(budget->allocated_bytes, blocks, &allocated) ||
        logical > budget->maximum_bytes || allocated > budget->maximum_bytes) {
        fail();
    }
    budget->logical_bytes = logical;
    budget->allocated_bytes = allocated;
    ++budget->entries;
}

static void copy_regular(int source_root, int target_root, const char *name, const struct stat *before,
                         mode_t mode, uint64_t source_mount_id) {
    int source;
    int target;
    struct stat opened;
    struct stat after;
    struct stat target_status;
    unsigned char *buffer;
    uint64_t offset = 0U;
    source = openat(source_root, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source < 0 || fstat(source, &opened) != 0 || !metadata_equal(before, &opened) ||
        descriptor_mount_id(source) != source_mount_id) {
        if (source >= 0) close(source);
        fail();
    }
    target = openat(target_root, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (target < 0) {
        close(source);
        fail();
    }
    buffer = malloc(COPY_BUFFER_BYTES);
    if (buffer == NULL) {
        close(source);
        close(target);
        fail();
    }
    while (offset < (uint64_t)before->st_size) {
        size_t requested = (uint64_t)COPY_BUFFER_BYTES < (uint64_t)before->st_size - offset
            ? COPY_BUFFER_BYTES : (size_t)((uint64_t)before->st_size - offset);
        ssize_t amount;
        do {
            amount = pread(source, buffer, requested, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount <= 0) {
            free(buffer);
            close(source);
            close(target);
            fail();
        }
        write_all(target, buffer, (size_t)amount);
        offset += (uint64_t)amount;
    }
    {
        unsigned char extra;
        ssize_t amount;
        do {
            amount = pread(source, &extra, 1U, (off_t)offset);
        } while (amount < 0 && errno == EINTR);
        if (amount != 0) {
            free(buffer);
            close(source);
            close(target);
            fail();
        }
    }
    free(buffer);
    if (fstat(source, &after) != 0 || !metadata_equal(before, &after) ||
        descriptor_mount_id(source) != source_mount_id ||
        fchmod(target, mode & 0777U) != 0 || fstat(target, &target_status) != 0 ||
        !S_ISREG(target_status.st_mode) || target_status.st_nlink != 1 ||
        target_status.st_size != before->st_size || (target_status.st_mode & 0777U) != (mode & 0777U)) {
        close(source);
        close(target);
        fail();
    }
    if (close(source) != 0 || close(target) != 0) fail();
}

static void copy_tree(int source, int target, struct copy_budget *budget, unsigned int depth, int collection,
                      uint64_t source_mount_id) {
    struct stat directory_before;
    struct stat directory_after;
    struct name_list names;
    size_t index;
    if (depth > MAXIMUM_TREE_DEPTH || fstat(source, &directory_before) != 0 ||
        !S_ISDIR(directory_before.st_mode) || descriptor_mount_id(source) != source_mount_id) {
        fail();
    }
    names = list_names(source, budget->maximum_entries - budget->entries + 1U);
    for (index = 0U; index < names.count; ++index) {
        const char *name = names.items[index];
        struct stat status;
        if (fstatat(source, name, &status, AT_SYMLINK_NOFOLLOW) != 0 || (status.st_mode & 07000U) != 0U) {
            free_names(&names);
            fail();
        }
        account_entry(budget, &status);
        if (S_ISDIR(status.st_mode)) {
            int source_child;
            int target_child;
            if (mkdirat(target, name, 0700) != 0) {
                free_names(&names);
                fail();
            }
            source_child = openat(source, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            target_child = openat(target, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            if (source_child < 0 || target_child < 0) {
                if (source_child >= 0) close(source_child);
                if (target_child >= 0) close(target_child);
                free_names(&names);
                fail();
            }
            {
                struct stat opened;
                if (fstat(source_child, &opened) != 0 || !metadata_equal(&status, &opened)) {
                    close(source_child);
                    close(target_child);
                    free_names(&names);
                    fail();
                }
            }
            copy_tree(source_child, target_child, budget, depth + 1U, collection, source_mount_id);
            if (close(source_child) != 0 || close(target_child) != 0) {
                free_names(&names);
                fail();
            }
        } else if (S_ISREG(status.st_mode) && status.st_nlink == 1) {
            mode_t mode;
            if (collection) {
                if ((status.st_mode & 0400U) == 0U) {
                    free_names(&names);
                    fail();
                }
                mode = status.st_mode & 0777U;
            } else {
                mode = (status.st_mode & 0111U) != 0U ? 0500U : 0400U;
            }
            copy_regular(source, target, name, &status, mode, source_mount_id);
        } else {
            free_names(&names);
            fail();
        }
    }
    require_same_names(source, &names, budget->maximum_entries + 1U);
    if (fstat(source, &directory_after) != 0 || !metadata_equal(&directory_before, &directory_after) ||
        descriptor_mount_id(source) != source_mount_id) {
        free_names(&names);
        fail();
    }
    free_names(&names);
}

static void require_empty_directory(int descriptor) {
    struct name_list names = list_names(descriptor, 1U);
    if (names.count != 0U) {
        free_names(&names);
        fail();
    }
    free_names(&names);
}

static void stage_inputs(void) {
    static const char *const environment_names[] = {
        "TARGET_UID", "TARGET_GID", "WORKSPACE_BYTES", "WORKSPACE_ENTRIES"
    };
    struct copy_budget budget;
    uint64_t target_uid;
    uint64_t target_gid;
    int source;
    int target;
    struct stat source_status;
    struct stat target_status;
    struct statvfs filesystem;
    uint64_t capacity;
    require_exact_environment(environment_names, sizeof(environment_names) / sizeof(environment_names[0]));
    target_uid = parse_unsigned(exact_environment_value("TARGET_UID"), 0U, UINT32_MAX);
    target_gid = parse_unsigned(exact_environment_value("TARGET_GID"), 0U, UINT32_MAX);
    if ((uint64_t)geteuid() != target_uid || (uint64_t)getegid() != target_gid) fail();
    budget.maximum_bytes = parse_unsigned(exact_environment_value("WORKSPACE_BYTES"), 1U, MAXIMUM_WORKSPACE_BYTES);
    budget.maximum_entries = parse_unsigned(exact_environment_value("WORKSPACE_ENTRIES"), 1U, MAXIMUM_WORKSPACE_ENTRIES);
    budget.logical_bytes = 0U;
    budget.allocated_bytes = 0U;
    budget.entries = 0U;
    require_mount(WORKSPACE_PATH, "tmpfs", 0);
    source = open(CASE_INPUTS_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    target = open(WORKSPACE_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source < 0 || target < 0 || fstat(source, &source_status) != 0 ||
        fstat(target, &target_status) != 0 ||
        (source_status.st_dev == target_status.st_dev && source_status.st_ino == target_status.st_ino) ||
        target_status.st_uid != (uid_t)target_uid || target_status.st_gid != (gid_t)target_gid ||
        (target_status.st_mode & 07777U) != 0700U || fstatvfs(target, &filesystem) != 0 ||
        !checked_multiply_u64((uint64_t)filesystem.f_blocks, (uint64_t)filesystem.f_frsize, &capacity) ||
        capacity < budget.maximum_bytes || capacity >= budget.maximum_bytes + (uint64_t)filesystem.f_frsize ||
        (uint64_t)filesystem.f_files != budget.maximum_entries) {
        if (source >= 0) close(source);
        if (target >= 0) close(target);
        fail();
    }
    require_empty_directory(target);
    copy_tree(source, target, &budget, 0U, 0, descriptor_mount_id(source));
    if (close(source) != 0 || close(target) != 0) fail();
}

static void collect_workspace(void) {
    static const char *const environment_names[] = {
        "TARGET_UID", "TARGET_GID", "WORKSPACE_BYTES", "WORKSPACE_ENTRIES"
    };
    struct copy_budget budget;
    uint64_t target_uid;
    uint64_t target_gid;
    int source;
    int target;
    struct stat source_status;
    struct stat target_status;
    struct statvfs filesystem;
    uint64_t capacity;
    require_exact_environment(environment_names, sizeof(environment_names) / sizeof(environment_names[0]));
    target_uid = parse_unsigned(exact_environment_value("TARGET_UID"), 0U, UINT32_MAX);
    target_gid = parse_unsigned(exact_environment_value("TARGET_GID"), 0U, UINT32_MAX);
    budget.maximum_bytes = parse_unsigned(exact_environment_value("WORKSPACE_BYTES"), 1U, MAXIMUM_WORKSPACE_BYTES);
    budget.maximum_entries = parse_unsigned(exact_environment_value("WORKSPACE_ENTRIES"), 1U, MAXIMUM_WORKSPACE_ENTRIES);
    budget.logical_bytes = 0U;
    budget.allocated_bytes = 0U;
    budget.entries = 0U;
    require_mount(WORKSPACE_PATH, "tmpfs", 1);
    source = open(WORKSPACE_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    target = open(CASE_RESULTS_PATH, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (source < 0 || target < 0 || fstat(source, &source_status) != 0 ||
        fstat(target, &target_status) != 0 ||
        (source_status.st_dev == target_status.st_dev && source_status.st_ino == target_status.st_ino) ||
        source_status.st_uid != (uid_t)target_uid || source_status.st_gid != (gid_t)target_gid ||
        (source_status.st_mode & 07777U) != 0700U || target_status.st_uid != geteuid() ||
        target_status.st_gid != getegid() || (target_status.st_mode & 07777U) != 0700U ||
        fstatvfs(source, &filesystem) != 0 ||
        !checked_multiply_u64((uint64_t)filesystem.f_blocks, (uint64_t)filesystem.f_frsize, &capacity) ||
        capacity < budget.maximum_bytes || capacity >= budget.maximum_bytes + (uint64_t)filesystem.f_frsize ||
        (uint64_t)filesystem.f_files != budget.maximum_entries) {
        if (source >= 0) close(source);
        if (target >= 0) close(target);
        fail();
    }
    require_empty_directory(target);
    copy_tree(source, target, &budget, 0U, 1, descriptor_mount_id(source));
    if (close(source) != 0 || close(target) != 0) fail();
}

int main(int argc, char **argv) {
    if (argc < 3 || strcmp(argv[1], PROTOCOL) != 0) fail();
    if (strcmp(argv[2], "pre-exec") == 0) {
        pre_exec(argc, argv);
    } else if (strcmp(argv[2], "stage") == 0) {
        if (argc != 3) fail();
        stage_inputs();
    } else if (strcmp(argv[2], "collect") == 0) {
        if (argc != 3) fail();
        collect_workspace();
    } else {
        fail();
    }
    return 0;
}
