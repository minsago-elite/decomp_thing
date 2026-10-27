#define _GNU_SOURCE
#include <assert.h>
#include <stdarg.h>
#include <sys/ioctl.h>

static int fixture_ioctl(int descriptor, unsigned long operation, ...);
#define ioctl fixture_ioctl
#define main fixture_helper_main
#include "provider_dns_loopback_fixture.c"
#undef main
#undef ioctl

static unsigned gets, sets, fail_get;
static unsigned initial_flags, final_flags;
static int set_error;

static int fixture_ioctl(int descriptor, unsigned long operation, ...)
{
    assert(descriptor == 123);
    va_list args;
    va_start(args, operation);
    struct ifreq *request = va_arg(args, struct ifreq *);
    va_end(args);
    assert(strcmp(request->ifr_name, "lo") == 0);
    if (operation == SIOCGIFFLAGS) {
        ++gets;
        if (gets == fail_get) { errno = EIO; return -1; }
        request->ifr_flags = (short)(gets == 1 ? initial_flags : final_flags);
        return 0;
    }
    assert(operation == SIOCSIFFLAGS);
    ++sets;
    assert((unsigned short)request->ifr_flags == (initial_flags | IFF_UP));
    if (set_error) { errno = set_error; return -1; }
    return 0;
}

static void control(unsigned before, unsigned after, unsigned failed_get, int failed_set,
                    unsigned stage, int error, unsigned expected_gets, unsigned expected_sets)
{
    gets = sets = 0;
    initial_flags = before; final_flags = after;
    fail_get = failed_get; set_error = failed_set;
    uint32_t observed_before = 0, observed_after = 0;
    struct legacy_diagnostic diagnostic = {0};
    int result = loopback_flags(123, &observed_before, &observed_after, &diagnostic);
    assert(result == (stage != 0));
    assert(diagnostic.stage == stage && diagnostic.error == error);
    assert(gets == expected_gets && sets == expected_sets);
    if (!result) assert(observed_before == before && observed_after == after);
}

int main(void)
{
    const unsigned up = IFF_UP | IFF_LOOPBACK | IFF_RUNNING;
    /* EPERM would be returned by a redundant write; none is attempted. */
    control(up, up, 0, EPERM, 0, 0, 2, 0);
    control(IFF_LOOPBACK, up, 0, 0, 0, 0, 2, 1);
    /* A needed mutation must still succeed, and both reads remain mandatory. */
    control(IFF_LOOPBACK, up, 0, EPERM, 85, EPERM, 1, 1);
    control(up, up, 1, 0, 83, EIO, 1, 0);
    control(up, up, 2, 0, 86, EIO, 2, 0);
    control(IFF_LOOPBACK, up, 2, 0, 86, EIO, 2, 1);
    control(IFF_UP, up, 0, 0, 84, 0, 1, 0);
    control(up, IFF_LOOPBACK, 0, 0, 87, 0, 2, 0);
    control(up, IFF_UP, 0, 0, 87, 0, 2, 0);
    control(IFF_LOOPBACK, IFF_LOOPBACK, 0, 0, 87, 0, 2, 1);
    puts("10 loopback flag controls passed");
    return 0;
}
