#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/landlock.h>
#include <linux/openat2.h>
#include <linux/seccomp.h>
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

/*
 * A deliberately small, closed exec trampoline.  Policy bytes are authenticated and held
 * stable by the Kotlin worker before launch.  This process validates their framing and the
 * identity/type of every target, installs Landlock and seccomp, closes every setup descriptor,
 * and replaces itself with the requested compiler.  It never forks or supervises a child.
 */
#define POLICY_HEADER "DMLAND01"
#define POLICY_VERSION 1u
#define POLICY_MAX_BYTES (1024u * 1024u)
#define POLICY_MAX_RULES 8192u
#define POLICY_MAX_PATH 4096u

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

    size_t offset = 16;
    for (uint32_t i = 0; i < count; ++i) {
        if (length - offset < 24) { errno = EINVAL; fail("policy entry is truncated"); }
        uint32_t kind = u32le(bytes + offset);
        uint32_t path_length = u32le(bytes + offset + 4);
        uint64_t device = u64le(bytes + offset + 8);
        uint64_t inode = u64le(bytes + offset + 16);
        offset += 24;
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
        if (fstat(target, &st) != 0 || (uint64_t)st.st_dev != device || (uint64_t)st.st_ino != inode ||
            !expected_type(kind, st.st_mode) || (kind == RULE_RUNTIME_EXEC_FILE && (st.st_mode & 0111) == 0)) {
            close(target); errno = ESTALE; fail("policy target identity or type changed");
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
