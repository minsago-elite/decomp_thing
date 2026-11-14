#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
#include <linux/stat.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* Landlock ABI 2/3 rights are stable UAPI bits, but older distro headers omit them.
   Runtime admission still requires ABI 3 before either bit is used. */
#ifndef LANDLOCK_ACCESS_FS_REFER
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#endif
#ifndef LANDLOCK_ACCESS_FS_TRUNCATE
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#endif

/*
 * A deliberately small, closed exec trampoline.  Policy bytes are authenticated and held
 * stable by the Kotlin worker before launch.  This process validates their framing and the
 * identity/type of every target, installs Landlock and seccomp, closes every setup descriptor,
 * and replaces itself with the requested compiler.  It never forks or supervises a child.
 */
#define POLICY_HEADER "DMLAND02"
#define POLICY_VERSION 2u
#define POLICY_MAX_BYTES (1024u * 1024u)
#define POLICY_MAX_RULES 8192u
#define POLICY_MAX_PATH 4096u
#define MOUNTINFO_MAX_BYTES (4u * 1024u * 1024u)
#define MOUNTINFO_MAX_LINE (64u * 1024u)
#define MOUNTINFO_MAX_RECORDS 8192u

#ifndef STATX_MNT_ID
#define STATX_MNT_ID 0x00001000U
#endif

enum rule_kind { RULE_RUNTIME_DIR = 1, RULE_SNAPSHOT_DIR = 2, RULE_SNAPSHOT_FILE = 3,
                 RULE_OUTPUT_FILE = 4, RULE_SCRATCH_DIR = 5, RULE_RUNTIME_EXEC_DIR = 6,
                 RULE_RUNTIME_EXEC_FILE = 7 };

static void fail(const char *message) {
    dprintf(STDERR_FILENO, "compiler confinement setup failed: %s (errno=%d)\n", message, errno);
    _exit(125);
}

static uint32_t u32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t u64le(const unsigned char *p) {
    return (uint64_t)u32le(p) | ((uint64_t)u32le(p + 4) << 32);
}

static uint64_t descriptor_mount_id(int fd) {
#ifdef SYS_statx
    struct statx status;
    memset(&status, 0, sizeof(status));
    if (syscall(SYS_statx, fd, "", AT_EMPTY_PATH | AT_STATX_SYNC_AS_STAT, STATX_MNT_ID, &status) != 0) return 0;
    if ((status.stx_mask & STATX_MNT_ID) == 0 || status.stx_mnt_id == 0) { errno = EOPNOTSUPP; return 0; }
    return status.stx_mnt_id;
#else
    (void)fd;
    errno = ENOSYS;
    return 0;
#endif
}

struct mount_record { uint64_t id; char *point; int read_only; };
struct mount_table { struct mount_record *records; size_t count; };

static int compare_mount_id(const void *left, const void *right) {
    const struct mount_record *a = left, *b = right;
    return a->id < b->id ? -1 : (a->id > b->id ? 1 : 0);
}

static int positive_decimal(const char *value, uint64_t *result) {
    if (value == NULL || *value == '\0') return 0;
    uint64_t number = 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9' || number > (UINT64_MAX - (uint64_t)(*cursor - '0')) / 10u) return 0;
        number = number * 10u + (uint64_t)(*cursor - '0');
    }
    if (number == 0) return 0;
    *result = number;
    return 1;
}

static int decimal(const char *value, uint64_t *result) {
    if (value == NULL || *value == '\0') return 0;
    uint64_t number = 0;
    for (const unsigned char *cursor = (const unsigned char *)value; *cursor != '\0'; ++cursor) {
        if (*cursor < '0' || *cursor > '9' || number > (UINT64_MAX - (uint64_t)(*cursor - '0')) / 10u) return 0;
        number = number * 10u + (uint64_t)(*cursor - '0');
    }
    *result = number;
    return 1;
}

static size_t split_fields(char *value, char **fields, size_t capacity) {
    if (value == NULL || *value == '\0' || value[0] == ' ' || value[strlen(value) - 1] == ' ') return 0;
    size_t count = 0;
    char *start = value;
    for (char *cursor = value;; ++cursor) {
        if (*cursor == ' ' || *cursor == '\0') {
            if (cursor == start || count == capacity) return 0;
            fields[count++] = start;
            if (*cursor == '\0') break;
            *cursor = '\0';
            start = cursor + 1;
            if (*start == ' ') return 0;
        }
    }
    return count;
}

static int canonical_mount_path(const char *path) {
    size_t length = strlen(path);
    if (length == 1) return path[0] == '/';
    if (length == 0 || length > POLICY_MAX_PATH || path[0] != '/' ||
        (length > 1 && path[length - 1] == '/')) return 0;
    size_t start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i == length || path[i] == '/') {
            size_t part = i - start;
            if (part == 0 || (part == 1 && path[start] == '.') ||
                (part == 2 && path[start] == '.' && path[start + 1] == '.')) return 0;
            start = i + 1;
        }
    }
    return 1;
}

static int decode_mount_path(char *value) {
    size_t read_index = 0, write_index = 0, length = strlen(value);
    while (read_index < length) {
        if (value[read_index] != '\\') {
            value[write_index++] = value[read_index++];
            continue;
        }
        if (length - read_index < 4) return 0;
        const char *escape = value + read_index + 1;
        char decoded;
        if (memcmp(escape, "040", 3) == 0) decoded = ' ';
        else if (memcmp(escape, "011", 3) == 0) decoded = '\t';
        else if (memcmp(escape, "012", 3) == 0) decoded = '\n';
        else if (memcmp(escape, "134", 3) == 0) decoded = '\\';
        else return 0;
        value[write_index++] = decoded;
        read_index += 4;
    }
    value[write_index] = '\0';
    return value[0] == '/' && write_index <= POLICY_MAX_PATH;
}

static int mount_access_mode(const char *options, int *read_only) {
    unsigned seen = 0;
    const char *start = options;
    for (const char *cursor = options;; ++cursor) {
        if (*cursor == ',' || *cursor == '\0') {
            size_t length = (size_t)(cursor - start);
            if (length == 0) return 0;
            if (length == 2 && memcmp(start, "ro", 2) == 0) ++seen;
            if (length == 2 && memcmp(start, "rw", 2) == 0) { ++seen; *read_only = 0; }
            if (length == 2 && memcmp(start, "ro", 2) == 0) *read_only = 1;
            if (*cursor == '\0') break;
            start = cursor + 1;
        }
    }
    return seen == 1;
}

static struct mount_table read_mount_table(void) {
    struct mount_table table = {0};
    int fd = open("/proc/self/mountinfo", O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) fail("could not open final-namespace mount table");
    char *bytes = malloc(MOUNTINFO_MAX_BYTES + 1u);
    if (bytes == NULL) { close(fd); fail("could not allocate bounded mount table"); }
    size_t length = 0;
    while (length <= MOUNTINFO_MAX_BYTES) {
        ssize_t amount = read(fd, bytes + length, MOUNTINFO_MAX_BYTES + 1u - length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { close(fd); free(bytes); fail("could not read final-namespace mount table"); }
        if (amount == 0) break;
        length += (size_t)amount;
        if (length > MOUNTINFO_MAX_BYTES) { close(fd); free(bytes); errno = E2BIG; fail("mount table exceeds its byte bound"); }
    }
    if (close(fd) != 0) { free(bytes); fail("could not close final-namespace mount table"); }
    if (length == 0 || bytes[length - 1] != '\n') { free(bytes); errno = EINVAL; fail("mount table is empty or unterminated"); }
    table.records = calloc(MOUNTINFO_MAX_RECORDS, sizeof(*table.records));
    if (table.records == NULL) { free(bytes); fail("could not allocate bounded mount records"); }
    size_t start = 0;
    while (start < length) {
        size_t end = start;
        while (end < length && bytes[end] != '\n') ++end;
        size_t line_length = end - start;
        if (line_length == 0 || line_length > MOUNTINFO_MAX_LINE || table.count == MOUNTINFO_MAX_RECORDS) {
            free(bytes); errno = E2BIG; fail("mount table record count or length exceeds its bound");
        }
        bytes[end] = '\0';
        char *separator = strstr(bytes + start, " - ");
        if (separator == NULL || strstr(separator + 3, " - ") != NULL) {
            free(bytes); errno = EINVAL; fail("mount table record separator is malformed");
        }
        *separator = '\0';
        char *right_text = separator + 3;
        char *left[128], *right[8];
        size_t left_count = split_fields(bytes + start, left, 128);
        size_t right_count = split_fields(right_text, right, 8);
        uint64_t id = 0, parent = 0;
        char *colon = left_count >= 3 ? strchr(left[2], ':') : NULL;
        if (colon != NULL) {
            *colon = '\0';
            uint64_t major = 0, minor = 0;
            if (!decimal(left[2], &major) || !decimal(colon + 1, &minor)) colon = NULL;
        }
        if (left_count < 6 || right_count < 3 || !positive_decimal(left[0], &id) ||
            !positive_decimal(left[1], &parent) || colon == NULL ||
            !decode_mount_path(left[3]) || !decode_mount_path(left[4]) || !canonical_mount_path(left[4])) {
            free(bytes); errno = EINVAL; fail("mount table record fields are malformed");
        }
        (void)parent;
        int read_only = 0;
        if (!mount_access_mode(left[5], &read_only)) { free(bytes); errno = EINVAL; fail("mount access mode is ambiguous"); }
        char *point = strdup(left[4]);
        if (point == NULL) { free(bytes); fail("could not retain bounded mount point"); }
        table.records[table.count++] = (struct mount_record){ .id = id, .point = point, .read_only = read_only };
        start = end + 1;
    }
    free(bytes);
    qsort(table.records, table.count, sizeof(*table.records), compare_mount_id);
    for (size_t index = 1; index < table.count; ++index) {
        if (table.records[index - 1].id == table.records[index].id) {
            errno = EINVAL; fail("mount table contains duplicate mount identities");
        }
    }
    return table;
}

static int path_is_at_or_beneath(const char *parent, const char *path) {
    size_t length = strlen(parent);
    if (length == 1 && parent[0] == '/') return path[0] == '/';
    return strncmp(parent, path, length) == 0 && (path[length] == '\0' || path[length] == '/');
}

static void require_read_only_mount(const struct mount_table *table, const char *path, uint64_t mount_id,
                                    int directory, int fd) {
    (void)fd;
    size_t best_length = 0, best_count = 0;
    const struct mount_record *best = NULL;
    for (size_t index = 0; index < table->count; ++index) {
        const struct mount_record *record = &table->records[index];
        if (!path_is_at_or_beneath(record->point, path)) continue;
        size_t candidate_length = strlen(record->point);
        if (candidate_length > best_length) { best_length = candidate_length; best_count = 1; best = record; }
        else if (candidate_length == best_length) { ++best_count; if (record->id == mount_id) best = record; }
    }
    if (best == NULL || best_count != 1 || best->id != mount_id || !best->read_only) {
        errno = ESTALE; fail("descriptor mount identity is absent, ambiguous, or writable");
    }
    if (directory) {
        for (size_t index = 0; index < table->count; ++index) {
            const struct mount_record *record = &table->records[index];
            if (path_is_at_or_beneath(path, record->point) && !record->read_only) {
                errno = EROFS; fail("read directory contains a writable nested mount");
            }
        }
    }
}

static void free_mount_table(struct mount_table *table) {
    if (table == NULL) return;
    for (size_t index = 0; index < table->count; ++index) free(table->records[index].point);
    free(table->records);
    table->records = NULL;
    table->count = 0;
}

static int canonical_absolute_path(const char *path, size_t length) {
    if (length < 2 || length > POLICY_MAX_PATH || path[0] != '/' || path[length - 1] == '/') return 0;
    if (memchr(path, '\0', length) != NULL) return 0;
    size_t start = 1;
    for (size_t i = 1; i <= length; ++i) {
        if (i == length || path[i] == '/') {
            size_t part = i - start;
            if (part == 0 || (part == 1 && path[start] == '.') ||
                (part == 2 && path[start] == '.' && path[start + 1] == '.')) return 0;
            start = i + 1;
        } else if ((unsigned char)path[i] < 0x20 || (unsigned char)path[i] == 0x7f) return 0;
    }
    return 1;
}

static int open_policy_target(const char *path) {
#ifdef SYS_openat2
    struct open_how how = {
        .flags = O_PATH | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) return -1;
    int fd = (int)syscall(SYS_openat2, root, path + 1, &how, sizeof(how));
    int saved = errno;
    close(root);
    errno = saved;
    return fd;
#else
    (void)path;
    errno = ENOSYS;
    return -1;
#endif
}

static uint64_t rights_for(uint32_t kind) {
    switch (kind) {
    case RULE_RUNTIME_DIR:
        return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    case RULE_RUNTIME_EXEC_DIR:
        return LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    case RULE_RUNTIME_EXEC_FILE:
        return LANDLOCK_ACCESS_FS_EXECUTE;
    case RULE_SNAPSHOT_DIR:
        return LANDLOCK_ACCESS_FS_READ_DIR;
    case RULE_SNAPSHOT_FILE:
        return LANDLOCK_ACCESS_FS_READ_FILE;
    case RULE_OUTPUT_FILE:
        /* GNU as opens a regular output O_RDWR even though it emits a fresh object.  This
           grant is confined to the pre-created empty, single-link output inode; scratch as a
           directory remains unreadable. */
        return LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE;
    case RULE_SCRATCH_DIR:
        return LANDLOCK_ACCESS_FS_WRITE_FILE | LANDLOCK_ACCESS_FS_TRUNCATE |
            LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_DIR |
            LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_REMOVE_DIR |
            LANDLOCK_ACCESS_FS_REFER;
    default:
        return 0;
    }
}

static int expected_type(uint32_t kind, mode_t mode) {
    if (kind == RULE_RUNTIME_DIR || kind == RULE_RUNTIME_EXEC_DIR || kind == RULE_SNAPSHOT_DIR || kind == RULE_SCRATCH_DIR) return S_ISDIR(mode);
    if (kind == RULE_SNAPSHOT_FILE || kind == RULE_OUTPUT_FILE || kind == RULE_RUNTIME_EXEC_FILE) return S_ISREG(mode);
    return 0;
}

static int compiler_output_fd = -1;

static int open_output_for_compiler(const char *path) {
#ifdef SYS_openat2
    struct open_how how = {
        .flags = O_WRONLY | O_CLOEXEC,
        .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
    };
    int root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC);
    if (root < 0) return -1;
    int fd = (int)syscall(SYS_openat2, root, path + 1, &how, sizeof(how));
    int saved = errno;
    close(root);
    errno = saved;
    return fd;
#else
    (void)path;
    errno = ENOSYS;
    return -1;
#endif
}

static int install_seccomp(void) {
#if defined(__x86_64__)
    const uint32_t arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__)
    const uint32_t arch = AUDIT_ARCH_AARCH64;
#else
    errno = ENOTSUP;
    return -1;
#endif
    struct sock_filter filter[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
#if defined(__x86_64__)
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, __X32_SYSCALL_BIT, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
#endif
#define DENY_SYSCALL(name) BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_##name, 0, 1), \
                           BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA))
        DENY_SYSCALL(socket), DENY_SYSCALL(socketpair), DENY_SYSCALL(connect), DENY_SYSCALL(bind),
        DENY_SYSCALL(listen), DENY_SYSCALL(accept), DENY_SYSCALL(accept4), DENY_SYSCALL(ptrace),
        DENY_SYSCALL(sendto), DENY_SYSCALL(recvfrom), DENY_SYSCALL(sendmsg), DENY_SYSCALL(recvmsg),
        DENY_SYSCALL(shutdown),
        DENY_SYSCALL(process_vm_readv), DENY_SYSCALL(process_vm_writev), DENY_SYSCALL(pidfd_getfd),
        DENY_SYSCALL(ioctl), DENY_SYSCALL(mount), DENY_SYSCALL(umount2), DENY_SYSCALL(pivot_root),
        DENY_SYSCALL(chroot), DENY_SYSCALL(setns), DENY_SYSCALL(unshare), DENY_SYSCALL(bpf),
        DENY_SYSCALL(perf_event_open), DENY_SYSCALL(open_by_handle_at), DENY_SYSCALL(name_to_handle_at),
#undef DENY_SYSCALL
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = { .len = (unsigned short)(sizeof(filter) / sizeof(filter[0])), .filter = filter };
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) != 0) return -1;
    return 0;
}

static void enforce_policy(const unsigned char *bytes, size_t length) {
    if (length < 16 || memcmp(bytes, POLICY_HEADER, 8) != 0 || u32le(bytes + 8) != POLICY_VERSION) {
        errno = EINVAL; fail("policy header or version is invalid");
    }
    uint32_t count = u32le(bytes + 12);
    if (count == 0 || count > POLICY_MAX_RULES) { errno = E2BIG; fail("policy rule count is invalid"); }
    int abi = (int)syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
    if (abi < 3) { errno = abi < 0 ? errno : EOPNOTSUPP; fail("Landlock ABI 3 with REFER and TRUNCATE is required"); }
    const uint64_t handled = LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_WRITE_FILE |
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_REMOVE_DIR |
        LANDLOCK_ACCESS_FS_REMOVE_FILE | LANDLOCK_ACCESS_FS_MAKE_CHAR | LANDLOCK_ACCESS_FS_MAKE_DIR |
        LANDLOCK_ACCESS_FS_MAKE_REG | LANDLOCK_ACCESS_FS_MAKE_SOCK | LANDLOCK_ACCESS_FS_MAKE_FIFO |
        LANDLOCK_ACCESS_FS_MAKE_BLOCK | LANDLOCK_ACCESS_FS_MAKE_SYM | LANDLOCK_ACCESS_FS_REFER |
        LANDLOCK_ACCESS_FS_TRUNCATE;
    struct landlock_ruleset_attr ruleset_attr = { .handled_access_fs = handled };
    int ruleset = (int)syscall(SYS_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
    if (ruleset < 0) fail("could not create Landlock ruleset");
    /* This is read from inside the completed worker namespace before Landlock is installed.
       The parser deliberately uses the per-mount options field, not superblock options. */
    struct mount_table mounts = read_mount_table();

    size_t offset = 16;
    for (uint32_t i = 0; i < count; ++i) {
        if (length - offset < 32) { errno = EINVAL; fail("policy entry is truncated"); }
        uint32_t kind = u32le(bytes + offset);
        uint32_t path_length = u32le(bytes + offset + 4);
        uint64_t device = u64le(bytes + offset + 8);
        uint64_t inode = u64le(bytes + offset + 16);
        uint64_t mount_id = u64le(bytes + offset + 24);
        offset += 32;
        if (path_length < 2 || path_length > POLICY_MAX_PATH || length - offset < path_length) {
            errno = EINVAL; fail("policy path length is invalid");
        }
        char path[POLICY_MAX_PATH + 1];
        memcpy(path, bytes + offset, path_length);
        path[path_length] = '\0';
        offset += path_length;
        if (!canonical_absolute_path(path, path_length)) { errno = EINVAL; fail("policy path is not canonical"); }
        uint64_t rights = rights_for(kind);
        if (rights == 0) { errno = EINVAL; fail("policy rule kind is unknown"); }
        int target = open_policy_target(path);
        if (target < 0) fail("policy target cannot be opened without symlink traversal");
        struct stat st;
        uint64_t actual_mount_id = descriptor_mount_id(target);
        if (fstat(target, &st) != 0 || (uint64_t)st.st_dev != device || (uint64_t)st.st_ino != inode ||
            actual_mount_id == 0 || actual_mount_id != mount_id ||
            !expected_type(kind, st.st_mode) || (kind == RULE_RUNTIME_EXEC_FILE && (st.st_mode & 0111) == 0)) {
            close(target); errno = ESTALE; fail("policy target identity or type changed");
        }
        if (kind != RULE_OUTPUT_FILE && kind != RULE_SCRATCH_DIR) {
            int directory = kind == RULE_RUNTIME_DIR || kind == RULE_RUNTIME_EXEC_DIR || kind == RULE_SNAPSHOT_DIR;
            require_read_only_mount(&mounts, path, mount_id, directory, target);
        }
        struct landlock_path_beneath_attr rule = { .allowed_access = rights, .parent_fd = target };
        if (syscall(SYS_landlock_add_rule, ruleset, LANDLOCK_RULE_PATH_BENEATH, &rule, 0) != 0) {
            close(target); fail("could not attach Landlock path rule");
        }
        if (close(target) != 0) fail("could not close Landlock path descriptor");
        if (kind == RULE_OUTPUT_FILE) {
            if (compiler_output_fd >= 0) { errno = EINVAL; fail("policy has multiple compiler outputs"); }
            compiler_output_fd = open_output_for_compiler(path);
            if (compiler_output_fd < 0) fail("compiler output cannot be opened write-only");
            if (fstat(compiler_output_fd, &st) != 0 || st.st_size != 0 || st.st_nlink != 1 ||
                !S_ISREG(st.st_mode) || (uint64_t)st.st_dev != device || (uint64_t)st.st_ino != inode) {
                errno = ESTALE; fail("compiler output is not the expected empty single-link file");
            }
        }
    }
    if (offset != length) { errno = EINVAL; fail("policy contains trailing bytes"); }
    if (compiler_output_fd < 0) { errno = EINVAL; fail("policy has no compiler output"); }
    free_mount_table(&mounts);
    /* Keep the ruleset at its original fd (normally 3) until restrict_self succeeds. */
    if (compiler_output_fd != 4) {
        if (dup3(compiler_output_fd, 4, O_CLOEXEC) < 0) fail("could not reserve compiler output descriptor");
        if (close(compiler_output_fd) != 0) fail("could not close original output descriptor");
        compiler_output_fd = 4;
    }
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) fail("could not set no_new_privs");
    if (syscall(SYS_landlock_restrict_self, ruleset, 0) != 0) fail("could not enforce Landlock ruleset");
    if (close(ruleset) != 0) fail("could not close Landlock ruleset descriptor");
    if (dup3(compiler_output_fd, 3, 0) < 0) fail("could not expose the write-only compiler output descriptor");
    if (close(compiler_output_fd) != 0) fail("could not close reserved compiler output descriptor");
    compiler_output_fd = 3;
    if (install_seccomp() != 0) fail("could not install seccomp restrictions");
}

int main(int argc, char **argv) {
    if (argc < 4 || strcmp(argv[2], "--") != 0 || argv[3][0] != '/') {
        errno = EINVAL; fail("usage: helper <policy-path> -- <absolute-compiler> [arguments...]");
    }
    int policy_fd = open(argv[1], O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (policy_fd < 0) fail("cannot open policy input");
    struct stat policy_stat;
    if (fstat(policy_fd, &policy_stat) != 0 || !S_ISREG(policy_stat.st_mode) || policy_stat.st_nlink != 1 ||
        policy_stat.st_size < 16 || (uint64_t)policy_stat.st_size > POLICY_MAX_BYTES) {
        errno = EINVAL; fail("policy input metadata is invalid");
    }
    size_t length = (size_t)policy_stat.st_size;
    unsigned char *policy = malloc(length);
    if (policy == NULL) fail("could not allocate bounded policy input");
    size_t read_bytes = 0;
    while (read_bytes < length) {
        ssize_t n = read(policy_fd, policy + read_bytes, length - read_bytes);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { errno = EIO; fail("policy input ended early"); }
        read_bytes += (size_t)n;
    }
    if (close(policy_fd) != 0) fail("could not close policy input");
    enforce_policy(policy, length);
    memset(policy, 0, length);
    free(policy);
    /* The process launcher already closes all inherited descriptors above stderr.  Require
       close_range as a second, local barrier before handing control to the compiler. */
#ifdef SYS_close_range
    if (syscall(SYS_close_range, 4u, ~0u, 0u) != 0) fail("could not close inherited descriptors");
#else
    errno = ENOSYS; fail("close_range is required");
#endif
    execve(argv[3], &argv[3], environ);
    fail("compiler exec failed");
    return 125;
}
