#define _GNU_SOURCE

#include <errno.h>
#include <inttypes.h>
#include <linux/capability.h>
#include <net/if.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
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

static int bootstrap(int argc, char **argv)
{
    uint64_t deadline;
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
    struct __user_cap_data_struct zero[2] = {{0}, {0}};
    if (argc != 4 || (strcmp(argv[2], "cancel") != 0 && strcmp(argv[2], "deadline") != 0) ||
        !parse_u64(argv[3], &deadline) || deadline == 0 || deadline > INT64_MAX ||
        geteuid() != 0 || getegid() != 0 || !exact_state(0x1400, 0)) return 1;
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

int main(int argc, char **argv)
{
    uint64_t parent[4];
    struct stat net_namespace;
    struct stat user_namespace;
    struct ifreq request = {0};
    unsigned char receipt[RECEIPT_SIZE] = {0};
    uint32_t before;
    uint32_t after;
    int descriptor;

    if (argc > 1 && strcmp(argv[1], "bootstrap") == 0) return bootstrap(argc, argv);
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
