#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include <linux/audit.h>
#include <linux/ptrace.h>

static void allwrite(int fd, const char *p, size_t n) {
    while (n) {
        ssize_t w = write(fd, p, n);
        if (w < 1)
            _exit(90);
        p += w;
        n -= (size_t)w;
    }
}
static void pause_ms(int ms) { (void)poll(NULL, 0, ms); }
static void marker(const char *s) { allwrite(1, s, strlen(s)); }
static volatile sig_atomic_t term_received;
static void handle_term(int sig) {
    (void)sig;
    term_received = 1;
}
static int wait_for_reader_release(void) {
    struct timespec started, current;
    if (clock_gettime(CLOCK_MONOTONIC, &started))
        return -1;
    for (;;) {
        int fd = open("release-read", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (fd >= 0) {
            struct stat st;
            int valid = !fstat(fd, &st) && S_ISREG(st.st_mode) && st.st_size == 0 &&
                        st.st_uid == geteuid() && (st.st_mode & 0777) == 0600;
            close(fd);
            return valid ? 0 : -1;
        }
        if (errno != ENOENT || clock_gettime(CLOCK_MONOTONIC, &current))
            return -1;
        long elapsed_ms = (current.tv_sec - started.tv_sec) * 1000L +
                          (current.tv_nsec - started.tv_nsec) / 1000000L;
        if (elapsed_ms >= 5000)
            return -1;
        pause_ms(5);
    }
}
/* These trusted-test delays stop the guardian itself. Its forked target is never
 * traced, so the guardian still owns the real child and its real wait result. */
static long long monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now))
        return -1;
    return (long long)now.tv_sec * 1000 + now.tv_nsec / 1000000;
}
static int trace_wait(pid_t child, int *status, long long deadline) {
    for (;;) {
        long long now = monotonic_ms();
        if (now < 0 || now >= deadline)
            return -1;
        pid_t result = waitpid(child, status, WNOHANG | __WALL);
        if (result == child)
            return 0;
        if (result < 0 && errno != EINTR)
            return -1;
        (void)sched_yield();
    }
}
static int trace_syscall_info(pid_t child, struct ptrace_syscall_info *info) {
    memset(info, 0, sizeof *info);
    long bytes = ptrace(PTRACE_GET_SYSCALL_INFO, child, (void *)sizeof *info, info);
    size_t header = offsetof(struct ptrace_syscall_info, arch) + sizeof info->arch;
    if (bytes < 0 || (size_t)bytes < header)
        return -1;
#if defined(__x86_64__) && !defined(__ILP32__)
    const uint32_t native_arch = AUDIT_ARCH_X86_64;
#elif defined(__aarch64__) && !defined(__AARCH64EB__) && !defined(__ILP32__)
    const uint32_t native_arch = AUDIT_ARCH_AARCH64;
#else
    /* Other native ABIs are unsupported by this trusted ptrace fixture. */
    const uint32_t native_arch = 0;
#endif
    if (!native_arch || info->arch != native_arch)
        return -1;
    size_t required;
    if (info->op == PTRACE_SYSCALL_INFO_ENTRY)
        required = offsetof(struct ptrace_syscall_info, entry.args) + sizeof info->entry.args;
    else if (info->op == PTRACE_SYSCALL_INFO_EXIT)
        required = offsetof(struct ptrace_syscall_info, exit.is_error) + sizeof info->exit.is_error;
    else
        return -1;
    return (size_t)bytes >= required ? 0 : -1;
}
static int trace_fork_syscall(uint64_t nr) {
#ifdef SYS_fork
    if (nr == SYS_fork)
        return 1;
#endif
#ifdef SYS_vfork
    if (nr == SYS_vfork)
        return 1;
#endif
#ifdef SYS_clone
    if (nr == SYS_clone)
        return 1;
#endif
#ifdef SYS_clone3
    if (nr == SYS_clone3)
        return 1;
#endif
    return 0;
}
static int trace_pipe_fd(pid_t child, uint64_t address, unsigned index) {
    int pair[2];
    unsigned char *bytes = (unsigned char *)pair;
    for (size_t copied = 0; copied < sizeof pair;) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *)(uintptr_t)(address + copied), NULL);
        if (word == -1 && errno)
            return -1;
        size_t amount = sizeof pair - copied;
        if (amount > sizeof word)
            amount = sizeof word;
        memcpy(bytes + copied, &word, amount);
        copied += amount;
    }
    if (index > 1 || pair[0] < 3 || pair[1] < 3 || pair[0] == pair[1] ||
        pair[0] >= 128 || pair[1] >= 128)
        return -1;
    return pair[index];
}
static int trace_signal_mask(pid_t child, uint64_t *mask) {
    return ptrace(PTRACE_GETSIGMASK, child, (void *)sizeof *mask, mask) ? -1 : 0;
}
static int trace_mask_at(pid_t child, uint64_t address, uint64_t *mask) {
    unsigned char *bytes = (unsigned char *)mask;
    for (size_t copied = 0; copied < sizeof *mask;) {
        errno = 0;
        long word = ptrace(PTRACE_PEEKDATA, child, (void *)(uintptr_t)(address + copied), NULL);
        if (word == -1 && errno)
            return -1;
        size_t amount = sizeof *mask - copied;
        if (amount > sizeof word)
            amount = sizeof word;
        memcpy(bytes + copied, &word, amount);
        copied += amount;
    }
    return 0;
}
static int trace_cancellation_blocked(pid_t child) {
    uint64_t mask;
    if (trace_signal_mask(child, &mask))
        return -1;
    uint64_t cancellation = (UINT64_C(1) << (SIGTERM - 1)) | (UINT64_C(1) << (SIGINT - 1));
    return (mask & cancellation) == cancellation ? 1 : !(mask & cancellation) ? 0 : -1;
}
static void trace_close_pidfds(int *owned, size_t count) {
    for (size_t i = 0; i < count; i++)
        close(owned[i]);
}
static void trace_abort(pid_t child, int *owned, size_t count) {
    /* Give the guardian an opportunity to execute its ordinary cleanup path.
     * The fallback addresses only processes whose identities this tracer owns. */
    (void)kill(child, SIGTERM);
    (void)ptrace(PTRACE_CONT, child, NULL, NULL);
    long long now = monotonic_ms();
    long long deadline = now < 0 ? 0 : now + 1000;
    int status;
    int reaped = 0;
    while (!trace_wait(child, &status, deadline)) {
        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            reaped = 1;
            break;
        }
        if (WIFSTOPPED(status)) {
            int sig = WSTOPSIG(status);
            if (sig == SIGTRAP || sig == (SIGTRAP | 0x80))
                sig = 0;
            (void)ptrace(PTRACE_CONT, child, NULL, (void *)(intptr_t)sig);
        }
    }
    for (size_t i = 0; i < count; i++)
        (void)syscall(SYS_pidfd_send_signal, owned[i], SIGKILL, NULL, 0);
    if (!reaped) {
        (void)kill(child, SIGKILL);
        (void)ptrace(PTRACE_CONT, child, NULL, NULL);
        now = monotonic_ms();
        deadline = now < 0 ? 0 : now + 1000;
        while (!trace_wait(child, &status, deadline)) {
            if (WIFEXITED(status) || WIFSIGNALED(status))
                break;
            if (WIFSTOPPED(status))
                (void)ptrace(PTRACE_CONT, child, NULL, (void *)(intptr_t)SIGKILL);
        }
    }
    trace_close_pidfds(owned, count);
    /* Abort always returns failure, even if a bounded kill/reap attempt expires.
     * This subreaper sweep is abort cleanup only, never qualification evidence:
     * consume only already-exited children adopted from the guardian. */
    while (waitpid(-1, NULL, WNOHANG | __WALL) > 0) {
    }
}
static int trace_guardian(pid_t child, int *status, int mode) {
    int owned[16];
    size_t owned_count = 0;
    unsigned fork_count = 0, plain_pipes = 0, gate_release_writes = 0, cleanup_signals = 0;
    int held = 0, exec_read_fd = -1, gate_write_fd = -1, interrupt_forwarded = 0;
    int critical_mask_entered = 0, mask_restored = 0;
    pid_t direct_child_pid = -1;
    int startup_pidfd_attempted = 0, startup_pidfd_observed = 0, startup_pidfd_call = 0;
    int mask_block_call = 0, mask_restore_call = 0, own_mask_active = 0;
    uint64_t entry_previous_mask = 0, own_previous_mask = 0;
    const uint64_t cancellation_mask = (UINT64_C(1) << (SIGTERM - 1)) |
                                       (UINT64_C(1) << (SIGINT - 1));
    uint64_t syscall_nr = 0, syscall_args[6] = {0};
    int syscall_pending = 0;
    int interrupt_signal = mode >= 3 && mode <= 12 ? ((mode <= 5 || (mode >= 9 && mode <= 10)) ? SIGTERM : SIGINT) : 0;
    int target = mode == 13 ? 6 : mode >= 9 ? (mode % 2 ? 4 : 5) :
                 mode >= 3 ? (mode - 3) % 3 + 1 : (mode == 1 ? 1 : 3);
    const char *point = target == 1 ? "state-mkdir" : target == 2 ? "child-pidfd" :
                        target == 3 ? "exec-read" : target == 4 ? "pending" :
                        target == 5 ? "post-admission" : "cleanup-adoption";
    long long began = monotonic_ms();
    if (began < 0)
        goto fail;
    long long deadline = began + 3000;
    if (trace_wait(child, status, deadline))
        goto fail;
    if (WIFEXITED(*status) || WIFSIGNALED(*status))
        return -1;
    if (!WIFSTOPPED(*status) || WSTOPSIG(*status) != SIGSTOP)
        goto fail;
    /* Deliberately omit TRACEFORK, TRACEVFORK, and TRACECLONE. */
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC;
    if (ptrace(PTRACE_SETOPTIONS, child, NULL, (void *)options) ||
        ptrace(PTRACE_SYSCALL, child, NULL, NULL))
        goto fail;
    for (;;) {
        if (trace_wait(child, status, deadline))
            goto fail;
        if (WIFEXITED(*status) || WIFSIGNALED(*status)) {
            trace_close_pidfds(owned, owned_count);
            if (!held || (interrupt_signal && !interrupt_forwarded) || (mode == 13 && cleanup_signals < 3))
                return -1;
            char message[256];
            int n = interrupt_signal
                ? snprintf(message, sizeof message,
                           "TRACE_SUMMARY point=%s held=1 signal=%d forwarded=1 forkCloneCount=%u gateReleaseWrites=%u criticalMaskEntered=%d maskRestored=%d\n",
                           point, interrupt_signal, fork_count, gate_release_writes,
                           critical_mask_entered, mask_restored)
                : snprintf(message, sizeof message,
                           "TRACE_SUMMARY point=%s held=1 forkCloneCount=%u\n", point, fork_count);
            allwrite(2, message, (size_t)n);
            return 0;
        }
        if (!WIFSTOPPED(*status))
            goto fail;
        int sig = WSTOPSIG(*status), forward = sig;
        int delay = 0, forward_interrupt = 0;
        if (sig == (SIGTRAP | 0x80)) {
            struct ptrace_syscall_info info;
            if (trace_syscall_info(child, &info))
                goto fail;
            forward = 0;
            if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
                syscall_pending = 1;
                syscall_nr = info.entry.nr;
                memcpy(syscall_args, info.entry.args, sizeof syscall_args);
                startup_pidfd_call = mask_block_call = mask_restore_call = 0;
                if (!startup_pidfd_attempted && direct_child_pid > 0 &&
                    syscall_nr == SYS_pidfd_open && syscall_args[0] == (uint64_t)direct_child_pid &&
                    syscall_args[1] == 0) {
                    startup_pidfd_attempted = startup_pidfd_call = 1;
                }
                /* libc fork() also masks signals. Only the guardian's exact
                 * post-pidfd cancellation mask can identify this interval. */
                if (startup_pidfd_observed && syscall_nr == SYS_rt_sigprocmask &&
                    syscall_args[1] && syscall_args[3] == sizeof(uint64_t)) {
                    uint64_t requested;
                    if (trace_mask_at(child, syscall_args[1], &requested))
                        goto fail;
                    if (syscall_args[0] == SIG_BLOCK && requested == cancellation_mask && syscall_args[2]) {
                        if (own_mask_active || trace_signal_mask(child, &entry_previous_mask))
                            goto fail;
                        mask_block_call = 1;
                    } else if (own_mask_active && syscall_args[0] == SIG_SETMASK &&
                               requested == own_previous_mask) {
                        mask_restore_call = 1;
                    }
                }
                if (trace_fork_syscall(syscall_nr))
                    fork_count++;
                if (!held && target == 1 && syscall_nr == SYS_mkdirat)
                    delay = 1;
                if (!held && ((target == 4 && syscall_nr == SYS_rt_sigpending) ||
                    (target == 5 && syscall_nr == SYS_write &&
                     syscall_args[0] == (uint64_t)gate_write_fd && syscall_args[2] == 1))) {
                    if (!own_mask_active || trace_cancellation_blocked(child) != 1)
                        goto fail;
                    delay = 1;
                }
            } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && syscall_pending) {
                if (!info.exit.is_error && info.exit.rval == 0 && mask_block_call) {
                    uint64_t saved_previous, actual;
                    if (trace_mask_at(child, syscall_args[2], &saved_previous) ||
                        trace_signal_mask(child, &actual) || saved_previous != entry_previous_mask ||
                        actual != (entry_previous_mask | cancellation_mask))
                        goto fail;
                    own_previous_mask = entry_previous_mask;
                    critical_mask_entered = own_mask_active = 1;
                }
                if (!info.exit.is_error && info.exit.rval == 0 && mask_restore_call) {
                    uint64_t actual;
                    if (trace_signal_mask(child, &actual) || actual != own_previous_mask)
                        goto fail;
                    mask_restored = 1;
                    own_mask_active = 0;
                }
                if (!info.exit.is_error && startup_pidfd_call && info.exit.rval >= 0) {
                    startup_pidfd_observed = 1;
                }
                if (!info.exit.is_error && trace_fork_syscall(syscall_nr) &&
                    info.exit.rval > 0) {
                    if (owned_count == sizeof owned / sizeof *owned)
                        goto fail;
                    if (direct_child_pid < 0)
                        direct_child_pid = (pid_t)info.exit.rval;
                    int pidfd = (int)syscall(SYS_pidfd_open, (pid_t)info.exit.rval, 0);
                    if (pidfd < 0)
                        goto fail;
                    owned[owned_count++] = pidfd;
                }
                if (!info.exit.is_error && syscall_nr == SYS_pipe2 && info.exit.rval == 0) {
                    if (syscall_args[1] == O_CLOEXEC) {
                        if (++plain_pipes == 4) {
                            gate_write_fd = trace_pipe_fd(child, syscall_args[0], 1);
                            if (gate_write_fd < 0)
                                goto fail;
                        }
                    } else if (syscall_args[1] == (O_CLOEXEC | O_NONBLOCK)) {
                        if (exec_read_fd >= 0)
                            goto fail;
                        exec_read_fd = trace_pipe_fd(child, syscall_args[0], 0);
                        if (exec_read_fd < 0)
                            goto fail;
                    }
                }
                if (!info.exit.is_error && syscall_nr == SYS_write &&
                    syscall_args[0] == (uint64_t)gate_write_fd && syscall_args[2] == 1 &&
                    info.exit.rval == 1)
                    gate_release_writes++;
                if (!held && target == 2 && startup_pidfd_call &&
                    !info.exit.is_error && info.exit.rval >= 0)
                    delay = 1;
                if (!held && target == 3 && syscall_nr == SYS_read &&
                    syscall_args[0] == (uint64_t)exec_read_fd && syscall_args[2] == 1 &&
                    !info.exit.is_error && info.exit.rval == 0)
                    delay = 1;
                if (mode == 13 && syscall_nr == SYS_pidfd_send_signal && !info.exit.is_error && info.exit.rval == 0) {
                    /* Root TERM succeeds, then hold beyond the old global grace while it
                     * exits/reparents. The newly adopted identity must get TERM, then KILL. */
                    unsigned expected = cleanup_signals < 2 ? SIGTERM : SIGKILL;
                    if (syscall_args[1] != expected)
                        goto fail;
                    cleanup_signals++;
                    if (cleanup_signals == 1)
                        delay = 1;
                }
                syscall_pending = 0;
            }
        } else if (sig == SIGTRAP && (unsigned)*status >> 16 == PTRACE_EVENT_EXEC) {
            forward = 0;
        } else if (interrupt_signal && held && !interrupt_forwarded && sig == interrupt_signal) {
            siginfo_t delivery;
            if (ptrace(PTRACE_GETSIGINFO, child, NULL, &delivery) ||
                delivery.si_signo != interrupt_signal || delivery.si_pid != getpid())
                goto fail;
            forward_interrupt = 1;
        }
        if (delay) {
            if (interrupt_signal) {
                if (kill(child, interrupt_signal))
                    goto fail;
                held = 1;
                char message[160];
                int n = snprintf(message, sizeof message,
                                 "TRACE_INTERRUPT point=%s signal=%d queued=1 forkCloneCount=%u\n",
                                 point, interrupt_signal, fork_count);
                allwrite(2, message, (size_t)n);
            } else {
                long long start = monotonic_ms(), current;
                if (start < 0)
                    goto fail;
                do {
                    current = monotonic_ms();
                    if (current < 0 || current >= deadline)
                        goto fail;
                    if (current - start < 200)
                        pause_ms((int)(200 - (current - start)));
                } while (current - start < 200);
                if (mode == 13) {
                    if (owned_count != 1)
                        goto fail;
                    struct pollfd root = {.fd = owned[0], .events = POLLIN};
                    if (poll(&root, 1, 0) != 1 || !(root.revents & POLLIN))
                        goto fail;
                    allwrite(2, "TRACE_ADOPTION rootExitedDuringHold=1\n", sizeof "TRACE_ADOPTION rootExitedDuringHold=1\n" - 1);
                }
                held = 1;
                char message[160];
                int n = snprintf(message, sizeof message,
                                 "TRACE_HOLD point=%s elapsedMillis=%lld forkCloneCount=%u\n",
                                 point, current - start, fork_count);
                allwrite(2, message, (size_t)n);
            }
        }
        if (ptrace(PTRACE_SYSCALL, child, NULL, (void *)(intptr_t)forward))
            goto fail;
        if (forward_interrupt) {
            interrupt_forwarded = 1;
            char message[128];
            int n = snprintf(message, sizeof message,
                             "TRACE_SIGNAL point=%s signal=%d forwarded=1\n", point, interrupt_signal);
            allwrite(2, message, (size_t)n);
        }
    }
fail:
    trace_abort(child, owned, owned_count);
    return -1;
}
static int supervise(int argc, char **argv, int trace_mode) {
    if (argc < 3 || prctl(PR_SET_CHILD_SUBREAPER, 1))
        return 80;
    struct rlimit fd = {128, 128}, as = {2UL * 1024 * 1024 * 1024, 2UL * 1024 * 1024 * 1024};
    if (setrlimit(RLIMIT_NOFILE, &fd) || setrlimit(RLIMIT_AS, &as))
        return 81;
    pid_t child = fork();
    if (child < 0)
        return 82;
    if (!child) {
        if (trace_mode && (ptrace(PTRACE_TRACEME, 0, NULL, NULL) || raise(SIGSTOP)))
            _exit(97);
        execv(argv[2], argv + 2);
        _exit(83);
    }
    int status;
    if (trace_mode ? trace_guardian(child, &status, trace_mode)
                   : waitpid(child, &status, 0) != child)
        return 84;
    pid_t other = waitpid(-1, NULL, WNOHANG | __WALL);
    int clean = other < 0 && errno == ECHILD;
    char msg[128];
    int n = snprintf(msg, sizeof msg, "SUPERVISOR guardian=%d cleanup=%s namespace-still-live\n",
                     WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status),
                     clean ? "ECHILD" : "FAILED");
    allwrite(2, msg, (size_t)n);
    /* Deliberately keep the namespace alive so its teardown cannot mask a leak. */
    static const char release[] = "\x1e" "DECOMP_SUPERVISOR_RELEASE" "\x1f";
    struct timespec began, current;
    if (clock_gettime(CLOCK_MONOTONIC, &began))
        return 96;
    size_t matched = 0;
    for (;;) {
        if (clock_gettime(CLOCK_MONOTONIC, &current))
            return 96;
        long elapsed = (current.tv_sec - began.tv_sec) * 1000L +
                       (current.tv_nsec - began.tv_nsec) / 1000000L;
        if (elapsed >= 5000)
            break;
        struct pollfd p = {.fd = 0, .events = POLLIN};
        if (poll(&p, 1, (int)(5000 - elapsed)) <= 0)
            break;
        char bytes[256];
        ssize_t r = read(0, bytes, sizeof bytes);
        if (r <= 0) {
            if (r == 0)
                pause_ms(1000);
            break;
        }
        /* Invalid frame payload may remain unread after header rejection.
         * It must not release the namespace before the host observes ECHILD. */
        for (ssize_t i = 0; i < r; i++) {
            matched = bytes[i] == release[matched] ? matched + 1 : 0;
            if (matched == sizeof release - 1)
                return clean ? 0 : 85;
        }
    }
    return clean ? 0 : 85;
}
static int connect_gateway(const char *mode) {
    const char *v = getenv("DEFAULT_AUTH_REQUEST");
    if (!v)
        return -1;
    const char *portp = strstr(v, "http://127.0.0.1:"), *token = strstr(v, "Bearer ");
    if (!portp || !token)
        return -1;
    int port = atoi(portp + 17); /* strlen("http://127.0.0.1:") is 17 */
    char bearer[72];
    memcpy(bearer, token, 71);
    bearer[71] = 0;
    if (!strcmp(mode, "wrong-auth"))
        bearer[8] = bearer[8] == 'a' ? 'b' : 'a';
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a = {.sin_family = AF_INET,
                            .sin_port = htons((unsigned short)port),
                            .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    if (fd < 0)
        return -1;
    if (!strcmp(mode, "backpressure")) {
        int small = 1024;
        if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &small, sizeof small))
            return -1;
    }
    if (connect(fd, (struct sockaddr *)&a, sizeof a))
        return -1;
    const char *body = "{\"model\":\"fixture\",\"input\":\"ping\"}";
    const char *method = !strcmp(mode, "method") ? "GET" : "POST";
    const char *path = !strcmp(mode, "path")       ? "/v1/models"
                       : !strcmp(mode, "query")    ? "/v1/responses?x=1"
                       : !strcmp(mode, "absolute") ? "http://example.invalid/v1/responses"
                                                   : "/v1/responses";
    char request[2048], extra[128] = "";
    if (!strcmp(mode, "duplicate-length"))
        snprintf(extra, sizeof extra, "Content-Length: %zu\r\n", strlen(body));
    if (!strcmp(mode, "transfer-encoding"))
        strcpy(extra, "Transfer-Encoding: chunked\r\n");
    if (!strcmp(mode, "routing-header"))
        strcpy(extra, "X-Forwarded-Host: example.invalid\r\n");
    if (!strcmp(mode, "bare-cr"))
        strcpy(extra, "User-Agent: x\ry\r\n");
    if (!strcmp(mode, "duplicate-agent"))
        strcpy(extra, "User-Agent: x\r\nUser-Agent: y\r\n");
    const char *host = !strcmp(mode, "host") ? "example.invalid" : "127.0.0.1";
    int n = snprintf(request, sizeof request,
                     "%s %s HTTP/1.1\r\nHost: %s:%d\r\nAuthorization: %s\r\nContent-Type: "
                     "application/json\r\nContent-Length: %zu\r\n%s\r\n%s",
                     method, path, host, port, bearer, strlen(body), extra, body);
    allwrite(fd, request, (size_t)n);
    return fd;
}
int main(int argc, char **argv) {
    if (argc >= 2 && !strcmp(argv[1], "supervise"))
        return supervise(argc, argv, 0);
    if (argc >= 2 && (!strcmp(argv[1], "supervise-delay-state") ||
                      !strcmp(argv[1], "supervise-delay-open")))
        return supervise(argc, argv, 1);
    if (argc >= 2 && !strcmp(argv[1], "supervise-delay-exec-read"))
        return supervise(argc, argv, 2);
    if (argc >= 2 && !strcmp(argv[1], "supervise-delay-cleanup-adoption"))
        return supervise(argc, argv, 13);
    const char *interrupt_modes[] = {
        "supervise-interrupt-term-state", "supervise-interrupt-term-pidfd",
        "supervise-interrupt-term-exec-read", "supervise-interrupt-int-state",
        "supervise-interrupt-int-pidfd", "supervise-interrupt-int-exec-read",
        "supervise-interrupt-term-pending", "supervise-interrupt-term-post-admission",
        "supervise-interrupt-int-pending", "supervise-interrupt-int-post-admission",
    };
    if (argc >= 2)
        for (unsigned i = 0; i < sizeof interrupt_modes / sizeof *interrupt_modes; i++)
            if (!strcmp(argv[1], interrupt_modes[i]))
                return supervise(argc, argv, 3 + (int)i);
    const char *mode = argc > 1 ? argv[1] : "success";
    /* Child receives only standard FDs and the explicitly defined, credential-free environment. */
    for (int i = 3; i < 128; i++)
        if (fcntl(i, F_GETFD) >= 0)
            return 77;
    if (getenv("OPENAI_API_KEY") || getenv("APP_SERVER_LOGS") || getenv("UNTRUSTED_SENTINEL"))
        return 78;
    if (!strcmp(mode, "stderr-flood")) {
        const char *auth = getenv("DEFAULT_AUTH_REQUEST");
        if (!auth)
            return 91;
        for (;;)
            allwrite(2, auth, strlen(auth));
    }
    if (!strcmp(mode, "stderr-exit")) {
        close(1);
        const char *auth = getenv("DEFAULT_AUTH_REQUEST");
        if (!auth)
            return 91;
        allwrite(2, auth, strlen(auth));
        allwrite(2, "\n", 1);
        return 0;
    }
    if (!strcmp(mode, "term-exit") || !strcmp(mode, "ignore-term")) {
        struct sigaction action = {.sa_handler = !strcmp(mode, "term-exit") ? handle_term : SIG_IGN};
        sigemptyset(&action.sa_mask);
        if (sigaction(SIGTERM, &action, NULL))
            return 92;
        marker("SIGNAL_READY\n");
        while (!term_received)
            pause();
        return 23;
    }
    if (!strcmp(mode, "other-signal")) {
        if (raise(SIGUSR1))
            return 93;
        return 94;
    }
    if (!strcmp(mode, "nonempty-state")) {
        int fd = open("tmp/owned-file", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (fd < 0 || close(fd))
            return 95;
        marker("STATE_NONEMPTY\n");
        return 0;
    }
    if (!strcmp(mode, "descendant") || !strcmp(mode, "descendant-exit") || !strcmp(mode, "late-adoption")) {
        int late_adoption = !strcmp(mode, "late-adoption");
        int sync[2];
        if (pipe(sync))
            return 70;
        pid_t p = fork();
        if (p < 0)
            return 71;
        if (!p) {
            close(sync[0]);
            if (setsid() < 0)
                _exit(72);
            if (!late_adoption) {
                pid_t q = fork();
                if (q < 0)
                    _exit(73);
                if (q)
                    _exit(0);
            }
            signal(SIGTERM, SIG_IGN);
            signal(SIGHUP, SIG_IGN);
            close(0);
            close(1);
            close(2);
            allwrite(sync[1], "R", 1);
            close(sync[1]);
            for (;;)
                pause();
        }
        close(sync[1]);
        char b;
        if (read(sync[0], &b, 1) != 1)
            return 74;
        close(sync[0]);
        if (!late_adoption && waitpid(p, NULL, 0) != p)
            return 75;
        marker("DESCENDANT_READY\n");
        if (!strcmp(mode, "descendant-exit"))
            return 0;
        for (;;)
            pause();
    }
    if (!strcmp(mode, "exit-soon")) {
        marker("EXIT_READY\n");
        pause_ms(200);
        return 0;
    }
    if (!strcmp(mode, "echo")) {
        char b[4096];
        marker("ECHO_READY\n");
        ssize_t n = read(0, b, sizeof b);
        if (n > 0)
            allwrite(1, b, (size_t)n);
        return n > 0 ? 0 : 76;
    }
    if (!strcmp(mode, "smuggle")) {
        const char bytes[] = "ACPP\1\2\0\0\0\0\0\0\0\1\0\0\0\1X";
        allwrite(1, bytes, sizeof bytes - 1);
        return 0;
    }
    if (!strcmp(mode, "flood")) {
        char b[65536];
        memset(b, 'x', sizeof b);
        for (;;)
            allwrite(1, b, sizeof b);
    }
    if (!strcmp(mode, "idle")) {
        marker("IDLE_READY\n");
        for (;;)
            pause();
    }
    marker("FIXTURE_READY\n");
    unsigned rounds = (!strcmp(mode, "twice") ? 2 : 1);
    for (unsigned round = 0; round < rounds; round++) {
        int fd = connect_gateway(mode);
        if (fd < 0)
            return 79;
        if (!strcmp(mode, "disconnect")) {
            pause_ms(120);
            close(fd);
            pause_ms(300);
            return 0;
        }
        if (!strcmp(mode, "backpressure") && wait_for_reader_release())
            return 89;
        static char response[2 * 1024 * 1024];
        size_t used = 0;
        ssize_t n;
        while ((n = read(fd, response + used, sizeof response - used - 1)) > 0) {
            used += (size_t)n;
            if (used == sizeof response - 1)
                return 86;
        }
        close(fd);
        response[used] = 0;
        if (!strncmp(response, "HTTP/1.1 200 OK\r\n", 17) &&
            strstr(response, "data: fixture\n\n") && strstr(response, "0\r\n\r\n")) {
            marker("HTTP_OK\n");
            if (round + 1 == rounds)
                return 0;
            continue;
        }
        if (!strncmp(response, "HTTP/1.1 400", 12)) {
            marker("HTTP_DENIED\n");
            return 0;
        }
        if (!strncmp(response, "HTTP/1.1 502", 12) || !strncmp(response, "HTTP/1.1 401", 12)) {
            marker("HTTP_TYPED_FAILURE\n");
            return 0;
        }
        marker("HTTP_INCOMPLETE\n");
        return 87;
    }
    return 88;
}
