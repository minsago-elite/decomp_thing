#define _GNU_SOURCE

#include <errno.h>
#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Fixture-only: no interface, command, path, or address is caller selectable. */
enum { RECEIPT_SIZE = 48 };

_Static_assert(sizeof(dev_t) <= sizeof(uint64_t), "namespace device width");
_Static_assert(sizeof(ino_t) <= sizeof(uint64_t), "namespace inode width");

static int parse_u64(const char *text, uint64_t *result)
{
    uint64_t value = 0;
    size_t length = 0;

    if (text[0] == '\0' || (text[0] == '0' && text[1] != '\0')) {
        return 0;
    }
    for (; text[length] != '\0'; ++length) {
        unsigned int digit;

        if (length >= 20 || text[length] < '0' || text[length] > '9') {
            return 0;
        }
        digit = (unsigned int)(text[length] - '0');
        if (value > (UINT64_MAX - digit) / UINT64_C(10)) {
            return 0;
        }
        value = value * UINT64_C(10) + digit;
    }
    *result = value;
    return 1;
}

static int expected_capabilities(void)
{
    struct __user_cap_header_struct header = {
        .version = _LINUX_CAPABILITY_VERSION_3,
        .pid = 0
    };
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    const uint64_t required = (UINT64_C(1) << CAP_NET_ADMIN) |
                              (UINT64_C(1) << CAP_NET_BIND_SERVICE);
    uint64_t effective;

    if (syscall(SYS_capget, &header, data) != 0) {
        return 0;
    }
    effective = ((uint64_t)data[1].effective << 32) | data[0].effective;
    return effective == required;
}

static int exact_state(uint32_t active, int no_new_privileges)
{
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    if (syscall(SYS_capget, &header, data) != 0 ||
        data[0].effective != active || data[0].permitted != active || data[0].inheritable != active ||
        data[1].effective || data[1].permitted || data[1].inheritable ||
        (no_new_privileges && prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1)) return 0;
    for (unsigned int bit = 0; bit < 64; ++bit) {
        int bound = prctl(PR_CAPBSET_READ, bit, 0, 0, 0);
        if (bound < 0) return errno == EINVAL && bit > CAP_NET_ADMIN;
        if (bound != (int)((UINT64_C(0x1400) >> bit) & 1) ||
            prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, bit, 0, 0) != (int)(((uint64_t)active >> bit) & 1)) return 0;
    }
    return 0;
}

static int bootstrap(int argc, char **argv, int dropped)
{
    uint64_t deadline;
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct zero[2] = {{0}, {0}};
    if (argc != 4 || (strcmp(argv[2], "cancel") != 0 && strcmp(argv[2], "deadline") != 0) ||
        !parse_u64(argv[3], &deadline) || deadline == 0 || deadline > INT64_MAX ||
        geteuid() != 0 || getegid() != 0 || !exact_state(dropped ? 0 : 0x1400, dropped)) return 1;
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 ||
        prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) != 0 ||
        syscall(SYS_capset, &header, zero) != 0 || !exact_state(0, 1)) return 1;
    char *const command[] = {"/fixture-input/jdk/bin/java", "-Xms16m", "-Xmx96m", "-Xint",
        "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:+DisableAttachMechanism",
        "-XX:-UsePerfData", "-XX:+ErrorFileToStderr", "-XX:-CreateCoredumpOnCrash",
        "-XX:-DumpReplayDataOnError", "-Djava.io.tmpdir=/fixture-output", "-Duser.home=/fixture-output",
        "-cp", "/fixture-input/control.jar:/fixture-input/kotlin-stdlib.jar",
        "decompengine.acp.AcpProviderNativeDnsControl", "inner", argv[2], argv[3], NULL};
    char *const environment[] = {NULL};
    execve(command[0], command, environment);
    return 1;
}

static void put_u64(unsigned char *output, uint64_t value)
{
    for (unsigned int index = 0; index < 8; ++index) {
        output[index] = (unsigned char)(value >> (56 - 8 * index));
    }
}

static void put_u32(unsigned char *output, uint32_t value)
{
    for (unsigned int index = 0; index < 4; ++index) {
        output[index] = (unsigned char)(value >> (24 - 8 * index));
    }
}

static int write_receipt(const unsigned char receipt[RECEIPT_SIZE])
{
    size_t written = 0;

    while (written < RECEIPT_SIZE) {
        ssize_t count = write(STDOUT_FILENO, receipt + written,
                              RECEIPT_SIZE - written);

        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            return 0;
        }
        written += (size_t)count;
    }
    return 1;
}

static int legacy_loopback(int argc, char **argv)
{
    uint64_t parent[4];
    struct stat net_namespace;
    struct stat user_namespace;
    struct ifreq request = {0};
    unsigned char receipt[RECEIPT_SIZE] = {0};
    uint32_t before;
    uint32_t after;
    int descriptor;

    if (argc != 5) {
        return 1;
    }
    for (unsigned int index = 0; index < 4; ++index) {
        if (!parse_u64(argv[index + 1], &parent[index]) || parent[index] == 0) {
            return 1;
        }
    }
    if (stat("/proc/self/ns/net", &net_namespace) != 0 ||
        stat("/proc/self/ns/user", &user_namespace) != 0 ||
        net_namespace.st_ino == 0 || user_namespace.st_ino == 0 ||
        ((uint64_t)net_namespace.st_dev == parent[0] &&
         (uint64_t)net_namespace.st_ino == parent[1]) ||
        ((uint64_t)user_namespace.st_dev == parent[2] &&
         (uint64_t)user_namespace.st_ino == parent[3]) ||
        geteuid() != 0 || getegid() != 0 || !expected_capabilities()) {
        return 1;
    }

    descriptor = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) {
        return 1;
    }
    memcpy(request.ifr_name, "lo", sizeof("lo"));
    if (ioctl(descriptor, SIOCGIFFLAGS, &request) != 0) {
        (void)close(descriptor);
        return 1;
    }
    before = (uint32_t)(unsigned short)request.ifr_flags;
    if ((before & IFF_LOOPBACK) == 0) {
        (void)close(descriptor);
        return 1;
    }
    request.ifr_flags = (short)(before | IFF_UP);
    if (ioctl(descriptor, SIOCSIFFLAGS, &request) != 0 ||
        ioctl(descriptor, SIOCGIFFLAGS, &request) != 0) {
        (void)close(descriptor);
        return 1;
    }
    after = (uint32_t)(unsigned short)request.ifr_flags;
    int closed = close(descriptor);
    if ((after & (IFF_UP | IFF_LOOPBACK)) != (IFF_UP | IFF_LOOPBACK) ||
        closed != 0) {
        return 1;
    }

    /* PDNSLO01, four namespace identity u64s, then two flag u32s; all BE. */
    memcpy(receipt, "PDNSLO01", 8);
    put_u64(receipt + 8, (uint64_t)net_namespace.st_dev);
    put_u64(receipt + 16, (uint64_t)net_namespace.st_ino);
    put_u64(receipt + 24, (uint64_t)user_namespace.st_dev);
    put_u64(receipt + 32, (uint64_t)user_namespace.st_ino);
    put_u32(receipt + 40, before);
    put_u32(receipt + 44, after);
    return write_receipt(receipt) ? 0 : 1;
}

/* #1521 fixture owner. All commands, filter and limits are source-owned, never
 * supplied by an ACP/provider/candidate. No inherited descriptor above stdio is
 * accepted, including io_uring and UNIX-socket capabilities. */
#if !defined(__x86_64__) || defined(__ILP32__)
#error "owned DNS fixture requires the reviewed Linux x86_64 syscall ABI"
#endif
#define OWNED_NEWNS_MASK UINT32_C(0x7e020080)
#define OWNED_DENY_SYSCALLS(X) \
    X(53) X(101) X(155) X(165) X(166) X(272) X(304) X(308) \
    X(310) X(311) X(425) X(426) X(427) X(428) X(429) X(430) \
    X(431) X(432) X(438) X(442)
#define OWNED_NOFILE UINT64_C(128)
#define OWNED_FSIZE UINT64_C(67108864)
#define OWNED_AS UINT64_C(2147483648)
#define OWNED_CPU UINT64_C(120)
#define OWNED_MAX_OUTPUT 256

static uint64_t clock_ms(clockid_t kind) {
    struct timespec value;
    if (clock_gettime(kind, &value)) return UINT64_MAX;
    return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
static int all_write(int fd, const void *raw, size_t size) {
    const unsigned char *bytes = raw;
    while (size) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return -1;
        bytes += n; size -= (size_t)n;
    }
    return 0;
}
/* Fixed diagnostic vocabulary only. Never emit argv, paths, input bytes or strerror.
 * Five progress records plus at most one failure record remain well below the
 * unchanged 256-byte host stream ceiling, including existing gate/terminal markers.
 * error is immediate errno from a known failed syscall, or zero for a predicate. */
static void owned_diag(unsigned stage, int error) {
    char bytes[32];
    int size = snprintf(bytes, sizeof bytes, "ND1:%u:%d\n", stage, error);
    if (size > 0 && size < (int)sizeof bytes) (void)all_write(2, bytes, (size_t)size);
}
static int owned_diag_failure(unsigned stage, int error) {
    owned_diag(stage, error);
    return 1;
}
static int fixed_file(const char *path, const char *bytes, size_t size) {
    if (size > 16384) return -1;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return -1;
    int result = all_write(fd, bytes, size);
    if (close(fd)) result = -1;
    return result;
}
static int exact_limits(uint64_t nproc, int apply) {
    const int names[] = {RLIMIT_NPROC, RLIMIT_NOFILE, RLIMIT_FSIZE, RLIMIT_CORE, RLIMIT_AS, RLIMIT_CPU};
    const uint64_t values[] = {nproc, OWNED_NOFILE, OWNED_FSIZE, 0, OWNED_AS, OWNED_CPU};
    if (nproc < 32 || nproc > INT_MAX) return -1;
    for (unsigned i = 0; i < sizeof names / sizeof *names; ++i) {
        struct rlimit wanted = {(rlim_t)values[i], (rlim_t)values[i]}, actual;
        if ((apply && setrlimit(names[i], &wanted)) || getrlimit(names[i], &actual) ||
            actual.rlim_cur != wanted.rlim_cur || actual.rlim_max != wanted.rlim_max) return -1;
    }
    return 0;
}
static int gate_byte(unsigned char expected, uint64_t end) {
    for (;;) {
        uint64_t now = clock_ms(CLOCK_MONOTONIC);
        if (now >= end) return -1;
        struct pollfd p = {.fd = 0, .events = POLLIN};
        int result = poll(&p, 1, (int)(end - now));
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0 || !(p.revents & POLLIN)) return -1;
        unsigned char byte;
        if (read(0, &byte, 1) != 1 || byte != expected || clock_ms(CLOCK_MONOTONIC) >= end) return -1;
        return 0;
    }
}
static int inherited_closed(void) {
    /* A bounded fixed vector is not an inherited-FD allowlist. The syscall
     * closes the entire table, and failure refuses rather than falling back. */
    return (int)syscall(SYS_close_range, 3U, ~0U, 0);
}
static int host_gate(int argc, char **argv) {
    uint64_t nproc, epoch;
    if (argc < 8 || argc > 256 || strcmp(argv[4], "--") || strcmp(argv[5], "/usr/bin/bwrap") ||
        !parse_u64(argv[2], &nproc) || !parse_u64(argv[3], &epoch)) return 1;
    size_t total = 0;
    for (int i = 5; i < argc; ++i) {
        size_t n = strnlen(argv[i], 8193);
        if (n > 8192 || (total += n + 1) > 65536) return 1;
    }
    uint64_t wall = clock_ms(CLOCK_REALTIME), mono = clock_ms(CLOCK_MONOTONIC);
    if (wall >= epoch || epoch - wall > 30000 || inherited_closed() || exact_limits(nproc, 1)) return 1;
    uint64_t end = mono + (epoch - wall);
    if (all_write(1, "OWNED_HOST_GATE_V2\n", 19) || gate_byte('H', end - 5000)) return owned_diag_failure(10, 0);
    owned_diag(11, 0); /* H consumed; not proof that bwrap exec/setup succeeded. */
    char *const env[] = {NULL};
    execve(argv[5], &argv[5], env);
    return owned_diag_failure(12, errno);
}

static int install_owned_filter(void) {
    struct sock_filter filter[128]; unsigned n = 0;
#define ST(code_, k_) (filter[n++] = (struct sock_filter)BPF_STMT(code_, k_))
#define JP(code_, k_, t_, f_) (filter[n++] = (struct sock_filter)BPF_JUMP(code_, k_, t_, f_))
    ST(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch));
    JP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0);
    ST(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    ST(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr));
    JP(BPF_JMP | BPF_JSET | BPF_K, UINT32_C(0xc0000000), 0, 1);
    ST(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS);
    JP(BPF_JMP | BPF_JEQ | BPF_K, 435, 0, 1); /* clone3: libc compatibility fallback */
    ST(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | ENOSYS);
#define DENY(number) JP(BPF_JMP | BPF_JEQ | BPF_K, number, 0, 1); ST(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    OWNED_DENY_SYSCALLS(DENY)
#undef DENY
    JP(BPF_JMP | BPF_JEQ | BPF_K, 41, 0, 6); /* socket */
    ST(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    JP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET, 3, 0);
    JP(BPF_JMP | BPF_JEQ | BPF_K, AF_INET6, 2, 0);
    ST(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    ST(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS); /* deliberately unreachable */
    ST(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    JP(BPF_JMP | BPF_JEQ | BPF_K, 56, 0, 6); /* clone: permit JVM threads, no namespace bits */
    ST(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]) + 4);
    JP(BPF_JMP | BPF_JEQ | BPF_K, 0, 0, 3);
    ST(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[0]));
    JP(BPF_JMP | BPF_JSET | BPF_K, OWNED_NEWNS_MASK, 1, 0);
    ST(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
    ST(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EPERM);
    ST(BPF_RET | BPF_K, SECCOMP_RET_ALLOW);
#undef JP
#undef ST
    struct sock_fprog program = {.len = (unsigned short)n, .filter = filter};
    return prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
           syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) ||
           prctl(PR_GET_SECCOMP, 0, 0, 0, 0) != SECCOMP_MODE_FILTER ? -1 : 0;
}
static int denial_canaries(void) {
    const long denied[] = {53, 101, 155, 165, 166, 272, 304, 308, 310, 311,
                           425, 426, 427, 428, 429, 430, 431, 432, 438, 442};
    for (unsigned i = 0; i < sizeof denied / sizeof *denied; ++i) {
        errno = 0;
        if (syscall(denied[i], 0, 0, 0, 0, 0, 0) != -1 || errno != EPERM) return -1;
    }
    const uint64_t namespace_flags[] = {UINT64_C(0x80), UINT64_C(0x20000), UINT64_C(0x2000000), UINT64_C(0x4000000),
        UINT64_C(0x8000000), UINT64_C(0x10000000), UINT64_C(0x20000000), UINT64_C(0x40000000), UINT64_C(0x100000000)};
    for (unsigned i = 0; i < sizeof namespace_flags / sizeof *namespace_flags; ++i) {
        errno = 0;
        if (syscall(56, namespace_flags[i], 0, 0, 0, 0) != -1 || errno != EPERM) return -1;
    }
    errno = 0;
    if (syscall(435, 0, 0) != -1 || errno != ENOSYS) return -1;
    errno = 0;
    if (socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0) != -1 || errno != EPERM) return -1;
    /* No service request or actual off-tree unit is ever made. A UNIX endpoint
     * cannot be created, including abstract/filesystem sockets and FD export. */
    const char *outside[] = {"/sys/fs/cgroup/cgroup.procs", "/run/user/1001/bus", "/host-only-canary"};
    for (unsigned i = 0; i < sizeof outside / sizeof *outside; ++i) {
        errno = 0; int fd = open(outside[i], O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd >= 0) { (void)close(fd); return -1; }
        if (errno != ENOENT && errno != ENOTDIR) return -1;
    }
    return 0;
}
static int namespace_reference(const char *name, int expected, struct stat *identity) {
    char path[64];
    if (snprintf(path, sizeof path, "/proc/self/ns/%s", name) <= 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd != expected) { if (fd >= 0) (void)close(fd); return -1; }
    return fstat(fd, identity);
}
static int standard_only(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int collector = dirfd(directory), ok = 1;
    struct dirent *entry; unsigned count = 0;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] == '.') continue;
        uint64_t fd;
        if (!parse_u64(entry->d_name, &fd) || ++count > 128 || (fd > 2 && fd != (uint64_t)collector)) ok = 0;
    }
    if (errno) ok = 0;
    if (closedir(directory)) ok = 0;
    return ok ? 0 : -1;
}
static unsigned owned_scans, owned_work, owned_pids;
static uint64_t owned_bytes;
/* This is the attested private procfs, not the ambient host population.
 * Every numeric entry is charged and any process other than this PID1 refuses. */
static int private_proc_alone(void) {
    if (++owned_scans > 128 || ++owned_work > 32768) return -1;
    DIR *directory = opendir("/proc");
    if (!directory) return -1;
    struct dirent *entry; unsigned count = 0; int seen = 0, alone = 1;
    errno = 0;
    while ((entry = readdir(directory))) {
        if (entry->d_name[0] < '0' || entry->d_name[0] > '9') continue;
        uint64_t pid;
        if (!parse_u64(entry->d_name, &pid) || ++count > 4096 || ++owned_pids > 16384 || ++owned_work > 32768) { alone = -1; break; }
        if (pid == 1) seen = 1;
        else alone = 0;
    }
    int saved = errno, closed = closedir(directory);
    if (saved || closed) return -1;
    return alone == 1 && seen ? 1 : alone == 0 ? 0 : -1;
}
static int children_empty(void) {
    if (++owned_scans > 128 || ++owned_work > 32768) return -1;
    char path[96], bytes[4096];
    if (snprintf(path, sizeof path, "/proc/self/task/%ld/children", (long)getpid()) <= 0) return -1;
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, bytes, sizeof bytes);
    int closed = close(fd);
    if (n < 0 || n == (ssize_t)sizeof bytes || closed) return -1;
    owned_bytes += (uint64_t)n; if (owned_bytes > UINT64_C(33554432)) return -1;
    for (ssize_t i = 0; i < n; ++i) if (bytes[i] != ' ' && bytes[i] != '\n') return 0;
    return 1;
}
/* Only this single-threaded PID1 calls waitpid. A listed child cannot be reaped
 * concurrently and reused before its pidfd is opened. No ambient PID scan. */
static int reap_all(uint64_t end) {
    for (;;) {
        int status; pid_t pid;
        do { pid = waitpid(-1, &status, WNOHANG | __WALL); } while (pid > 0);
        if (pid < 0 && errno == ECHILD) return children_empty() == 1 && clock_ms(CLOCK_MONOTONIC) < end ? 0 : -1;
        if (pid < 0 || clock_ms(CLOCK_MONOTONIC) >= end) return -1;
        if (++owned_scans > 128 || ++owned_work > 32768) return -1;
        char path[96], bytes[4096];
        if (snprintf(path, sizeof path, "/proc/self/task/%ld/children", (long)getpid()) <= 0) return -1;
        int fd = open(path, O_RDONLY | O_CLOEXEC);
        if (fd < 0) return -1;
        ssize_t n = read(fd, bytes, sizeof bytes - 1); int rc = close(fd);
        if (n < 0 || n == (ssize_t)sizeof bytes - 1 || rc) return -1;
        owned_bytes += (uint64_t)n; if (owned_bytes > UINT64_C(33554432)) return -1;
        bytes[n] = 0; char *cursor = bytes; unsigned count = 0;
        while (*cursor) {
            while (*cursor == ' ' || *cursor == '\n') ++cursor;
            if (!*cursor) break;
            char *tail; errno = 0; long child = strtol(cursor, &tail, 10);
            if (errno || tail == cursor || child <= 0 || child > INT_MAX || ++count > 32 || ++owned_pids > 16384 || ++owned_work > 32768) return -1;
            int handle = (int)syscall(SYS_pidfd_open, (pid_t)child, 0);
            if (handle < 0) { if (errno != ESRCH) return -1; }
            else {
                int signalled = (int)syscall(SYS_pidfd_send_signal, handle, SIGKILL, NULL, 0), saved = errno;
                if (close(handle) || (signalled && saved != ESRCH)) return -1;
            }
            cursor = tail;
        }
        (void)poll(NULL, 0, 1);
    }
}
static int question_type(const unsigned char *bytes, size_t size) {
    /* Preserve the prior fixture's exact chatgpt.com IN A/AAAA request, flags,
     * single question and zero answer/authority conditions. Bounded optional
     * additional records retain the prior parser's compatibility. */
    static const unsigned char name[] = {7, 'c', 'h', 'a', 't', 'g', 'p', 't', 3, 'c', 'o', 'm', 0};
    if (size < 12 + sizeof name + 4 || size > 512 || bytes[2] & 0xf8 || bytes[4] || bytes[5] != 1 ||
        bytes[6] || bytes[7] || bytes[8] || bytes[9] || memcmp(bytes + 12, name, sizeof name)) return -1;
    size_t cursor = 12 + sizeof name;
    if (bytes[cursor + 2] || bytes[cursor + 3] != 1) return -1;
    int type = ((int)bytes[cursor] << 8) | bytes[cursor + 1];
    return type == 1 || type == 28 ? type : -1;
}
static pid_t launch_inner(int *output, int *handle, const char *case_name, const char *epoch) {
    int pipes[2], gate[2];
    if (pipe2(pipes, O_CLOEXEC)) return -1;
    if (pipe2(gate, O_CLOEXEC)) { close(pipes[0]); close(pipes[1]); return -1; }
    pid_t parent = getpid(), child = fork();
    if (child < 0) { close(pipes[0]); close(pipes[1]); close(gate[0]); close(gate[1]); return -1; }
    if (!child) {
        close(gate[1]); unsigned char released;
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent ||
            read(gate[0], &released, 1) != 1 || released != 'R' || dup2(pipes[1], 1) < 0 || dup2(pipes[1], 2) < 0) _exit(121);
        close(0); if (open("/dev/null", O_RDONLY | O_CLOEXEC) != 0 || inherited_closed()) _exit(121);
        char *const command[] = {"/fixture-input/loopback-helper", "bootstrap-dropped", (char *)case_name, (char *)epoch, NULL};
        char *const environment[] = {NULL}; execve(command[0], command, environment); _exit(122);
    }
    close(pipes[1]); close(gate[0]);
    *handle = (int)syscall(SYS_pidfd_open, child, 0);
    int rc = *handle < 0 ? -1 : all_write(gate[1], "R", 1);
    if (close(gate[1])) rc = -1;
    if (rc || fcntl(pipes[0], F_SETFL, O_NONBLOCK)) { close(pipes[0]); return -1; }
    *output = pipes[0]; return child;
}

static int owned_metadata(pid_t pid, uint64_t *started, char uid[64], char gid[64]) {
    if (++owned_pids > 16384 || owned_work > 32766) return -1;
    owned_work += 2;
    char path[96], bytes[4096];
    snprintf(path, sizeof path, "/proc/%ld/stat", (long)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t n = read(fd, bytes, sizeof bytes - 1); int rc = close(fd);
    if (n <= 0 || n == (ssize_t)sizeof bytes - 1 || rc) return -1;
    owned_bytes += (uint64_t)n; if (owned_bytes > UINT64_C(33554432)) return -1;
    bytes[n] = 0; char *tail = strrchr(bytes, ')');
    if (!tail || tail[1] != ' ') return -1;
    char *save = NULL, *token = strtok_r(tail + 2, " ", &save);
    for (unsigned field = 0; field < 19 && token; ++field) token = strtok_r(NULL, " ", &save);
    if (!token || !parse_u64(token, started)) return -1;
    snprintf(path, sizeof path, "/proc/%ld/status", (long)pid);
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    n = read(fd, bytes, sizeof bytes - 1); rc = close(fd);
    if (n <= 0 || n == (ssize_t)sizeof bytes - 1 || rc) return -1;
    owned_bytes += (uint64_t)n; if (owned_bytes > UINT64_C(33554432)) return -1;
    bytes[n] = 0;
    char *u = strstr(bytes, "\nUid:"), *g = strstr(bytes, "\nGid:");
    unsigned a, b, c, d;
    if (!u || !g || sscanf(u + 5, "%u %u %u %u", &a, &b, &c, &d) != 4) return -1;
    if (snprintf(uid, 64, "%u,%u,%u,%u", a, b, c, d) <= 0) return -1;
    if (sscanf(g + 5, "%u %u %u %u", &a, &b, &c, &d) != 4) return -1;
    return snprintf(gid, 64, "%u,%u,%u,%u", a, b, c, d) > 0 ? 0 : -1;
}

static int supervisor(int argc, char **argv) {
    owned_diag(20, 0); /* Entered PID1 helper, before any setup authority check. */
    uint64_t epoch, nproc, parent[4];
    if (argc != 10 || getpid() != 1 || (strcmp(argv[2], "cancel") && strcmp(argv[2], "deadline")) ||
        !parse_u64(argv[3], &epoch) || !parse_u64(argv[4], &nproc) ||
        (strcmp(argv[9], "positive") && strcmp(argv[9], "retained-child") && strcmp(argv[9], "retained-reference") && strcmp(argv[9], "inaccessible-owned"))) return owned_diag_failure(21, 0);
    for (unsigned i = 0; i < 4; ++i) if (!parse_u64(argv[i + 5], &parent[i])) return owned_diag_failure(22, 0);
    uint64_t wall = clock_ms(CLOCK_REALTIME), mono = clock_ms(CLOCK_MONOTONIC);
    if (epoch <= wall || epoch - wall > 30000 || inherited_closed() || exact_limits(nproc, 0) ||
        !exact_state(0x1400, 0)) return owned_diag_failure(23, 0);
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)) return owned_diag_failure(25, errno);
    uint64_t end = mono + epoch - wall, execution_end = end - 5000;
    struct stat ns[4], proc;
    int setup[2];
    if (pipe2(setup, O_CLOEXEC)) return owned_diag_failure(30, errno);
    /* The legacy helper's exact48-byte setup receipt is consumed here, not on
     * the host control stream. No child or JVM runs in this setup interval. */
    int saved_stdout = dup(1);
    if (saved_stdout < 0) return owned_diag_failure(31, errno);
    if (dup2(setup[1], 1) < 0) return owned_diag_failure(31, errno);
    char numbers[4][24]; char *setup_argv[5] = {argv[0], numbers[0], numbers[1], numbers[2], numbers[3]};
    for (unsigned i = 0; i < 4; ++i) snprintf(numbers[i], sizeof numbers[i], "%" PRIu64, parent[i]);
    int configured = legacy_loopback(5, setup_argv);
    if (dup2(saved_stdout, 1) < 0) return owned_diag_failure(33, errno);
    if (close(saved_stdout)) return owned_diag_failure(33, errno);
    if (close(setup[1])) return owned_diag_failure(33, errno);
    unsigned char setup_receipt[48]; ssize_t received = read(setup[0], setup_receipt, sizeof setup_receipt);
    int received_error = received < 0 ? errno : 0;
    if (close(setup[0])) return owned_diag_failure(34, errno);
    if (received < 0) return owned_diag_failure(34, received_error);
    if (configured || received != 48) return owned_diag_failure(35, 0);
    owned_diag(36, 0);
    int blackhole = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (blackhole < 0) return owned_diag_failure(40, errno);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_port = htons(53), .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (blackhole != 3) return owned_diag_failure(40, 0);
    if (bind(blackhole, (struct sockaddr *)&address, sizeof address)) return owned_diag_failure(41, errno);
    if (namespace_reference("pid", 4, &ns[0]) || namespace_reference("user", 5, &ns[1]) ||
        namespace_reference("net", 6, &ns[2]) || namespace_reference("mnt", 7, &ns[3])) return owned_diag_failure(42, 0);
    char own_proc[16];
    ssize_t own_proc_length = readlink("/proc/self", own_proc, sizeof own_proc);
    if (own_proc_length < 0) return owned_diag_failure(43, errno);
    if (own_proc_length != 1 || own_proc[0] != '1') return owned_diag_failure(43, 0);
    int procfd = open("/proc", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (procfd < 0) return owned_diag_failure(44, errno);
    struct statx proc_mount;
    if (procfd != 8) return owned_diag_failure(44, 0);
    if (fstat(procfd, &proc)) return owned_diag_failure(45, errno);
    if (statx(procfd, "", AT_EMPTY_PATH, STATX_MNT_ID, &proc_mount)) return owned_diag_failure(45, errno);
    if (!(proc_mount.stx_mask & STATX_MNT_ID) || !proc_mount.stx_mnt_id) return owned_diag_failure(46, 0);
    owned_diag(50, 0);
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct zero[2] = {{0}, {0}};
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) return owned_diag_failure(51, errno);
    if (prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)) return owned_diag_failure(52, errno);
    if (syscall(SYS_capset, &header, zero)) return owned_diag_failure(53, errno);
    if (!exact_state(0, 1)) return owned_diag_failure(54, 0);
    if (install_owned_filter()) return owned_diag_failure(55, 0);
    if (denial_canaries()) return owned_diag_failure(56, 0);
    if (private_proc_alone() != 1) return owned_diag_failure(57, 0);
    owned_diag(58, 0);
    uint64_t inner_start; char own_uid[64], own_gid[64];
    if (owned_metadata(1, &inner_start, own_uid, own_gid)) return owned_diag_failure(60, 0);
    char gate_record[2048];
    int length = snprintf(gate_record, sizeof gate_record,
        "schema=2\ncaseName=%s\ncontrol=%s\ninnerPid=1\ninnerStart=%" PRIu64 "\nactiveCapabilitiesZero=true\nboundingMask=1400\nnoNewPrivileges=true\nseccomp=2\nescapeCanariesPassed=true\nprivateProcOnlyPid1=true\nnproc=%" PRIu64 "\nnofile=128\nfsize=67108864\nas=2147483648\ncpu=120\ncore=0\n"
        "pidDev=%ju\npidIno=%ju\nuserDev=%ju\nuserIno=%ju\nnetDev=%ju\nnetIno=%ju\nmntDev=%ju\nmntIno=%ju\nprocDev=%ju\nprocIno=%ju\nprocMountId=%" PRIu64 "\n",
        argv[2], argv[9], inner_start, nproc, (uintmax_t)ns[0].st_dev, (uintmax_t)ns[0].st_ino,
        (uintmax_t)ns[1].st_dev, (uintmax_t)ns[1].st_ino, (uintmax_t)ns[2].st_dev, (uintmax_t)ns[2].st_ino,
        (uintmax_t)ns[3].st_dev, (uintmax_t)ns[3].st_ino, (uintmax_t)proc.st_dev, (uintmax_t)proc.st_ino, (uint64_t)proc_mount.stx_mnt_id);
    if (length <= 0 || length >= (int)sizeof gate_record) return owned_diag_failure(61, 0);
    if (fixed_file("/fixture-output/gate.properties", gate_record, (size_t)length)) return owned_diag_failure(62, 0);
    if (children_empty() != 1) return owned_diag_failure(63, 0);
    if (all_write(1, "OWNED_PID1_GATE_V2\n", 19) || gate_byte('P', execution_end)) return owned_diag_failure(64, 0);
    int child_output = -1, child_handle = -1, status = 0, failure = 0, child_reaped = 0, eof = 0, query_count = 0, qtype = 0;
    char child_bytes[OWNED_MAX_OUTPUT + 1]; size_t child_count = 0;
    pid_t child = launch_inner(&child_output, &child_handle, argv[2], argv[3]);
    if (child < 0) failure = 1;
    while (!failure && !(child_reaped && eof)) {
        if (clock_ms(CLOCK_MONOTONIC) >= execution_end) { failure = 1; break; }
        struct pollfd events[] = {{3, POLLIN, 0}, {child_output, POLLIN, 0}, {0, POLLIN, 0}};
        if (poll(events, 3, 50) < 0 && errno != EINTR) { failure = 1; break; }
        if (events[2].revents & (POLLHUP | POLLERR | POLLNVAL)) { failure = 1; break; }
        if (events[2].revents & POLLIN) { failure = 1; break; } /* no later release/command */
        if (events[0].revents & POLLIN) {
            unsigned char bytes[513]; struct sockaddr_in from; socklen_t size = sizeof from;
            ssize_t n = recvfrom(3, bytes, sizeof bytes, 0, (struct sockaddr *)&from, &size);
            int type = n > 0 ? question_type(bytes, (size_t)n) : -1;
            if (type < 0 || size != sizeof from || from.sin_family != AF_INET || from.sin_addr.s_addr != htonl(INADDR_LOOPBACK) || ++query_count > 64) { failure = 1; break; }
            if (!qtype) qtype = type;
            if (query_count == 1 && fixed_file("/fixture-output/query-observed", "NATIVE_DNS_QUERY_V1\n", 20)) { failure = 1; break; }
        }
        if (events[1].revents & (POLLIN | POLLHUP)) {
            ssize_t n = read(child_output, child_bytes + child_count, sizeof child_bytes - child_count);
            if (n > 0) child_count += (size_t)n;
            else if (!n) eof = 1;
            else if (errno != EAGAIN && errno != EINTR) failure = 1;
            if (child_count > OWNED_MAX_OUTPUT) failure = 1;
        }
        if (!child_reaped) {
            pid_t result = waitpid(child, &status, WNOHANG);
            if (result == child) child_reaped = 1;
            else if (result < 0) failure = 1;
        }
    }
    if (!child_reaped || !WIFEXITED(status) || WEXITSTATUS(status) || !eof || child_count != 20 ||
        memcmp(child_bytes, "NATIVE_DNS_INNER_V1\n", 20) || !query_count) failure = 1;
    int negative_observed = 0; pid_t negative_pid = 0;
    if (!failure && (!strcmp(argv[9], "retained-child") || !strcmp(argv[9], "inaccessible-owned"))) {
        int ready[2];
        if (pipe2(ready, O_CLOEXEC)) failure = 1;
        else {
            pid_t retained = fork();
            if (!retained) {
                close(ready[0]);
                if (!strcmp(argv[9], "inaccessible-owned") && prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) _exit(121);
                if (dup2(ready[1], 3) < 0 || syscall(SYS_close_range, 4U, ~0U, 0) || all_write(3, "D", 1) || close(3)) _exit(121);
                for (;;) pause();
            }
            close(ready[1]);
            if (retained > 0) {
                struct pollfd p = {ready[0], POLLIN, 0}; unsigned char byte;
                uint64_t now = clock_ms(CLOCK_MONOTONIC);
                if (now < execution_end && poll(&p, 1, (int)(execution_end - now)) > 0 && read(ready[0], &byte, 1) == 1 && byte == 'D') {
                    if (!strcmp(argv[9], "retained-child")) negative_observed = children_empty() == 0;
                    else {
                        char path[96]; snprintf(path, sizeof path, "/proc/%ld/ns/net", (long)retained);
                        uint64_t before = 0, after = 0, caller_start = 0;
                        char caller_uid[64], caller_gid[64], target_uid[64], target_gid[64], after_uid[64], after_gid[64];
                        int known = !owned_metadata(getpid(), &caller_start, caller_uid, caller_gid) &&
                                    !owned_metadata(retained, &before, target_uid, target_gid);
                        errno = 0; int denied = open(path, O_RDONLY | O_CLOEXEC); int denied_errno = errno;
                        negative_observed = denied < 0 && (denied_errno == EACCES || denied_errno == EPERM);
                        if (denied >= 0 && close(denied)) failure = 1;
                        known = known && !owned_metadata(retained, &after, after_uid, after_gid) && before == after &&
                                !strcmp(target_uid, after_uid) && !strcmp(target_gid, after_gid);
                        if (negative_observed) {
                            char witness[1024];
                            int size = known ? snprintf(witness, sizeof witness,
                                "schema=2\npid=%ld\ncallerPid=1\nkind=net\nphase=OUTER_CLEANUP\ncallerUid=%s\ncallerGid=%s\ntargetUid=%s\ntargetGid=%s\nstartBefore=%" PRIu64 "\nstartAfter=%" PRIu64 "\nnamespaceRead=ACCESS_DENIED\n",
                                (long)retained, caller_uid, caller_gid, target_uid, target_gid, before, after) :
                                snprintf(witness, sizeof witness, "schema=2\npid=%ld\ncallerPid=1\nkind=net\nphase=OUTER_CLEANUP\nnamespaceRead=ACCESS_DENIED\nidentity=UNAVAILABLE\n", (long)retained);
                            if (size <= 0 || size >= (int)sizeof witness || fixed_file("/fixture-output/witness.properties", witness, (size_t)size)) failure = 1;
                        }
                    }
                }
            }
            if (negative_observed) negative_pid = retained;
            if (close(ready[0])) failure = 1;
            if (!negative_observed) failure = 1;
        }
    }
    if (child_output >= 0 && close(child_output)) failure = 1;
    if (child_handle >= 0 && close(child_handle)) failure = 1;
    int reaped = reap_all(end) == 0;
    int private_alone = private_proc_alone() == 1;
    if (!reaped || !private_alone) failure = 1;
    int references_closed = 1;
    for (int fd = 3; fd <= 8; ++fd) if (close(fd)) references_closed = 0;
    if (!references_closed || standard_only() || clock_ms(CLOCK_MONOTONIC) >= end) failure = 1;
    char terminal[2048];
    length = snprintf(terminal, sizeof terminal,
        "schema=2\ncaseName=%s\ncontrol=%s\ninnerPid=1\nchildInnerPid=%ld\nchildRawStatus=%d\nchildReaped=%s\nfinalEchild=%s\nownedChildrenZero=%s\nprivateProcOnlyPid1=%s\nfixedReferencesClosed=%s\nblackholeJoined=%s\nqueryCount=%d\nqueryType=%d\nobserverScans=%u\nobserverWork=%u\nobserverPids=%u\nobserverBytes=%" PRIu64 "\nnegativeObserved=%s\nnegativeInnerPid=%ld\nprimaryFailure=%s\n",
        argv[2], argv[9], (long)child, status, child_reaped ? "true" : "false", reaped ? "true" : "false", reaped ? "true" : "false", private_alone ? "true" : "false",
        references_closed ? "true" : "false", references_closed ? "true" : "false", query_count, qtype, owned_scans, owned_work, owned_pids, owned_bytes,
        negative_observed ? "true" : "false", (long)negative_pid, negative_observed ? (!strcmp(argv[9], "inaccessible-owned") ? "POSSIBLE_OWNED_VISIBILITY" : "RETAINED_OWNED_CHILD") : failure ? "OWNED_FIXTURE_FAILURE" : "NONE");
    if (length <= 0 || length >= (int)sizeof terminal || fixed_file("/fixture-output/owner.properties", terminal, (size_t)length) ||
        clock_ms(CLOCK_MONOTONIC) >= end) return 1;
    const char *marker = failure || negative_observed ? "NATIVE_DNS_CONTROL_FAILED_OWNED_DOMAIN\n" : "NATIVE_DNS_OUTER_V1\n";
    return all_write(1, marker, strlen(marker)) || failure || negative_observed ? 1 : 0;
}
int main(int argc, char **argv) {
    if (argc > 1 && !strcmp(argv[1], "host-gate")) return host_gate(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "supervise")) return supervisor(argc, argv);
    if (argc > 1 && !strcmp(argv[1], "bootstrap")) return bootstrap(argc, argv, 0);
    if (argc > 1 && !strcmp(argv[1], "bootstrap-dropped")) return bootstrap(argc, argv, 1);
    return legacy_loopback(argc, argv);
}
