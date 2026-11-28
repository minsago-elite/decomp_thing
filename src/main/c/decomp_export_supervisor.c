#define _GNU_SOURCE

/*
 * decomp-export-supervisor-v1: owns one bundled Ghidra export worker and its whole process tree.
 *
 * Usage: decomp-export-supervisor <leftover-grace-millis> /absolute/worker [worker arguments...]
 *
 * The supervisor becomes a child subreaper before it starts the worker, so every descendant the
 * worker orphans is reparented here instead of to init. It signals only its own children, found by
 * their parent PID in its own procfs: before the permit it requires /proc to be procfs whose
 * /proc/self is this process, so /proc belongs to this PID namespace. Each signal goes through a pidfd
 * opened for that PID and is sent only if the PID's parent is still this supervisor. A child keeps its
 * PID until this process reaps it, and this process reaps only in its own loop, so the pidfd names
 * that child and a signal can never reach a process that reused a PID.
 *
 * Standard input is the parent's control channel:
 *   "1\n"  the launch permit. The worker starts only after it and receives the same two bytes on a
 *          fresh standard input, then end of file.
 *   'T'    send SIGTERM to every current child.
 *   'K'    from now on, send SIGKILL to every child until none remain. Any other byte does the same.
 *   EOF    the same as 'K', so the tree cannot outlive its parent.
 * SIGTERM to the supervisor acts as 'T'; SIGINT and SIGHUP act as 'K'. Standard output and error are
 * inherited by the worker. Once the worker has been reaped, remaining descendants receive SIGTERM and,
 * after the leftover grace (0 to 1000 milliseconds), SIGKILL. The parent bounds that wait by its own
 * deadline and can send 'K' at any time.
 *
 * The supervisor exits only before it starts the worker or after it has no children left. A live
 * descendant always has a live ancestor chain that ends at one of this process's children, so an exit
 * below 128 proves that the whole tree is absent. Exit status:
 *   0..99  the worker's exit code      100  the worker's exit code was 100 or more
 *   101    a signal ended the worker   120  no launch permit; the worker never started
 *   121    supervisor failure; any worker was killed and reaped first
 *   254    no children remain, but the worker's own termination was never observed
 * A status of 128 or more proves nothing: 254, or the supervisor itself was killed.
 *
 * Only the worker's first termination report counts; a later child that reuses its PID cannot change
 * it. Stop and continue reports, such as those of a child that called PTRACE_TRACEME, are ignored.
 */

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/signalfd.h>
#include <sys/statfs.h>
#include <sys/syscall.h>
#include <time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define SUPERVISOR_NAME "decomp-export-supervisor-v1"
#define EXIT_LARGE_STATUS 100
#define EXIT_SIGNALLED_WORKER 101
#define EXIT_NO_PERMIT 120
#define EXIT_SUPERVISOR_FAILURE 121
#define EXIT_WORKER_UNOBSERVED 254
#ifndef PROC_SUPER_MAGIC
#define PROC_SUPER_MAGIC 0x9fa0
#endif
/* The same numbers on both admitted LP64 ABIs (x86-64 and the generic table used by aarch64). */
#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif
#define RESCAN_MILLIS 20
#define MAXIMUM_LEFTOVER_GRACE_MILLIS 1000

static pid_t self_pid;

static void report(const char *what) {
    /* Standard error belongs to the worker's diagnostics; keep one bounded line. */
    dprintf(STDERR_FILENO, SUPERVISOR_NAME ": %s\n", what);
}

/* Only for failures before any worker exists. */
static void fail_before_worker(int code, const char *what) {
    report(what);
    _exit(code);
}

/* The parent PID of [pid] from /proc, or -1 when it cannot be read. */
static pid_t parent_of(pid_t pid) {
    char path[64];
    char stat[512];
    snprintf(path, sizeof path, "/proc/%d/stat", (int)pid);
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    ssize_t count;
    do count = read(fd, stat, sizeof stat - 1); while (count < 0 && errno == EINTR);
    close(fd);
    if (count <= 0) return -1;
    stat[count] = '\0';
    /* The command name may contain ')'; every field after the last one is numeric or a state. */
    char *end = strrchr(stat, ')');
    char state;
    int parent;
    if (end == NULL || sscanf(end + 1, " %c %d", &state, &parent) != 2) return -1;
    return (pid_t)parent;
}

static int open_pidfd(pid_t pid) {
    return (int)syscall(SYS_pidfd_open, pid, 0);
}

static int pidfd_signal(int pidfd, int signal_number) {
    return (int)syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0);
}

/*
 * Signals every process whose parent is this supervisor. The pidfd is opened for the PID first and
 * used only if that PID's parent is still this supervisor: an unreaped child keeps its PID, so the
 * descriptor then names that child. Returns -1 if /proc cannot be enumerated.
 */
static int signal_children(int signal_number) {
    DIR *proc = opendir("/proc");
    if (proc == NULL) return -1;
    struct dirent *entry;
    while ((entry = readdir(proc)) != NULL) {
        char *end;
        long pid = strtol(entry->d_name, &end, 10);
        if (*end != '\0' || pid <= 0 || pid == self_pid) continue;
        if (parent_of((pid_t)pid) != self_pid) continue;
        int pidfd = open_pidfd((pid_t)pid);
        if (pidfd < 0) continue;
        if (parent_of((pid_t)pid) == self_pid) pidfd_signal(pidfd, signal_number);
        close(pidfd);
    }
    closedir(proc);
    return 0;
}

/* /proc must be procfs for this PID namespace, and pidfd signalling must work, before any permit. */
static void require_own_procfs_and_pidfd(void) {
    struct statfs filesystem;
    if (statfs("/proc", &filesystem) != 0 || filesystem.f_type != PROC_SUPER_MAGIC) {
        fail_before_worker(EXIT_SUPERVISOR_FAILURE, "/proc is not procfs");
    }
    char link[32];
    char expected[32];
    ssize_t count = readlink("/proc/self", link, sizeof link - 1);
    if (count <= 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "/proc/self cannot be read");
    link[count] = '\0';
    snprintf(expected, sizeof expected, "%d", (int)self_pid);
    if (strcmp(link, expected) != 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "/proc belongs to another PID namespace");
    int pidfd = open_pidfd(self_pid);
    if (pidfd < 0 || pidfd_signal(pidfd, 0) != 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "pidfd signalling is unavailable");
    close(pidfd);
}

static long long monotonic_millis(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return -1;
    return (long long)now.tv_sec * 1000LL + now.tv_nsec / 1000000L;
}

/* A decimal 0..MAXIMUM_LEFTOVER_GRACE_MILLIS, or -1. */
static long parse_grace(const char *text) {
    if (text[0] == '\0' || strlen(text) > 4) return -1;
    long value = 0;
    for (const char *cursor = text; *cursor != '\0'; cursor++) {
        if (*cursor < '0' || *cursor > '9') return -1;
        value = value * 10 + (*cursor - '0');
    }
    return value <= MAXIMUM_LEFTOVER_GRACE_MILLIS ? value : -1;
}

static int encode_worker_status(int status) {
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        return code < EXIT_LARGE_STATUS ? code : EXIT_LARGE_STATUS;
    }
    return EXIT_SIGNALLED_WORKER;
}

static void write_permit(int fd) {
    static const char permit[2] = {'1', '\n'};
    size_t written = 0;
    while (written < sizeof permit) {
        ssize_t count = write(fd, permit + written, sizeof permit - written);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return; /* The worker already exited; its status is reaped below. */
        written += (size_t)count;
    }
}

/* Waits for the two-byte permit; any signal or other input refuses the launch. */
static void await_permit(int events) {
    char permit[2];
    size_t received = 0;
    while (received < sizeof permit) {
        struct pollfd ready[2] = {{events, POLLIN, 0}, {STDIN_FILENO, POLLIN, 0}};
        if (poll(ready, 2, -1) < 0) {
            if (errno == EINTR) continue;
            fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot wait for the launch permit");
        }
        if (ready[0].revents != 0) fail_before_worker(EXIT_NO_PERMIT, "stopped before the launch permit");
        if (ready[1].revents == 0) continue;
        ssize_t count = read(STDIN_FILENO, permit + received, sizeof permit - received);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) fail_before_worker(EXIT_NO_PERMIT, "control channel closed before the launch permit");
        received += (size_t)count;
    }
    if (permit[0] != '1' || permit[1] != '\n') fail_before_worker(EXIT_NO_PERMIT, "invalid launch permit");
}

int main(int argc, char **argv) {
    long leftover_grace = argc < 3 ? -1 : parse_grace(argv[1]);
    if (leftover_grace < 0 || argv[2][0] != '/') {
        fail_before_worker(EXIT_SUPERVISOR_FAILURE,
            "usage: decomp-export-supervisor <leftover-grace-millis> /absolute/worker [arguments...]");
    }
    self_pid = getpid();
    if (prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) != 0) {
        fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot become a child subreaper");
    }
    require_own_procfs_and_pidfd();

    /* An inherited SIG_IGN or SA_NOCLDWAIT would let the kernel reap children and free their PIDs. */
    struct sigaction child_default;
    memset(&child_default, 0, sizeof child_default);
    child_default.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &child_default, NULL) != 0) {
        fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot restore SIGCHLD");
    }

    sigset_t handled;
    sigset_t original;
    sigemptyset(&handled);
    sigaddset(&handled, SIGCHLD);
    sigaddset(&handled, SIGTERM);
    sigaddset(&handled, SIGINT);
    sigaddset(&handled, SIGHUP);
    if (sigprocmask(SIG_BLOCK, &handled, &original) != 0) {
        fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot block supervisor signals");
    }
    struct sigaction ignore;
    memset(&ignore, 0, sizeof ignore);
    ignore.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &ignore, NULL) != 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot ignore SIGPIPE");
    int events = signalfd(-1, &handled, SFD_CLOEXEC | SFD_NONBLOCK);
    if (events < 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot open a signal descriptor");

    await_permit(events);

    int permit_pipe[2];
    if (pipe2(permit_pipe, O_CLOEXEC) != 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot create the worker permit pipe");
    pid_t worker = fork();
    if (worker < 0) fail_before_worker(EXIT_SUPERVISOR_FAILURE, "cannot start the worker");
    if (worker == 0) {
        /* If the supervisor is killed, the worker must not run on unsupervised. */
        if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0 || getppid() != self_pid) _exit(127);
        struct sigaction restore;
        memset(&restore, 0, sizeof restore);
        restore.sa_handler = SIG_DFL;
        if (dup2(permit_pipe[0], STDIN_FILENO) < 0 || sigaction(SIGPIPE, &restore, NULL) != 0 ||
            sigprocmask(SIG_SETMASK, &original, NULL) != 0) _exit(127);
        execv(argv[2], argv + 2);
        _exit(127);
    }
    /* The unreaped worker cannot have been recycled, so this descriptor names it until it is reaped. */
    int worker_pidfd = open_pidfd(worker);
    close(permit_pipe[0]);
    write_permit(permit_pipe[1]);
    close(permit_pipe[1]);

    int worker_status = 0;
    int worker_reaped = 0;
    int terminating = 0;
    int draining = 0;
    long long drain_deadline = 0;
    int killing = 0;
    int failed = 0;
    int control_open = 1;
    for (;;) {
        int status;
        pid_t reaped;
        for (;;) {
            reaped = waitpid(-1, &status, WNOHANG | __WALL);
            if (reaped > 0) {
                /* A stop or continue report, for example from a traced child, is not a termination. */
                if (!WIFEXITED(status) && !WIFSIGNALED(status)) continue;
                /* Only the worker's first termination counts; a later child may reuse its PID. */
                if (reaped == worker && !worker_reaped) {
                    worker_status = status;
                    worker_reaped = 1;
                    if (worker_pidfd >= 0) close(worker_pidfd);
                    worker_pidfd = -1;
                }
                continue;
            }
            if (reaped < 0 && errno == EINTR) continue;
            break;
        }
        if (reaped < 0 && errno == ECHILD) {
            /* No children: the whole tree is absent. Without the worker's own report, prove nothing. */
            if (!worker_reaped) _exit(EXIT_WORKER_UNOBSERVED);
            _exit(failed ? EXIT_SUPERVISOR_FAILURE : encode_worker_status(worker_status));
        }
        if (reaped < 0) {
            failed = 1;
            killing = 1;
        }
        if (worker_reaped && !killing && !draining) {
            /* Leftovers get SIGTERM and a bounded grace before SIGKILL. */
            draining = 1;
            long long now = monotonic_millis();
            if (leftover_grace == 0 || now < 0 || signal_children(SIGTERM) != 0) killing = 1;
            else drain_deadline = now + leftover_grace;
        }
        long long drain_remaining = -1;
        if (draining && !killing) {
            long long now = monotonic_millis();
            if (now < 0 || now >= drain_deadline) killing = 1;
            else drain_remaining = drain_deadline - now;
        }
        if (killing && signal_children(SIGKILL) != 0) {
            /* Without /proc the worker itself can still be killed; adopted children wait for it. */
            failed = 1;
            if (worker_pidfd >= 0) pidfd_signal(worker_pidfd, SIGKILL);
        }

        struct pollfd ready[2] = {{events, POLLIN, 0}, {control_open ? STDIN_FILENO : -1, POLLIN, 0}};
        /* Adoption sends no SIGCHLD, so a killing supervisor rescans for newly adopted children. */
        int timeout = killing ? RESCAN_MILLIS : drain_remaining >= 0 ? (int)drain_remaining : -1;
        if (poll(ready, 2, timeout) < 0) {
            if (errno == EINTR) continue;
            failed = 1;
            killing = 1;
            continue;
        }
        if (ready[0].revents != 0) {
            struct signalfd_siginfo signal_info;
            while (read(events, &signal_info, sizeof signal_info) == (ssize_t)sizeof signal_info) {
                if (signal_info.ssi_signo == SIGTERM && !terminating && !killing) {
                    terminating = 1;
                    if (signal_children(SIGTERM) != 0) failed = killing = 1;
                } else if (signal_info.ssi_signo == SIGINT || signal_info.ssi_signo == SIGHUP) {
                    killing = 1;
                }
            }
        }
        if (control_open && ready[1].revents != 0) {
            char command;
            ssize_t count = read(STDIN_FILENO, &command, 1);
            if (count < 0 && errno == EINTR) continue;
            if (count == 1 && command == 'T') {
                if (!terminating && !killing) {
                    terminating = 1;
                    if (signal_children(SIGTERM) != 0) failed = killing = 1;
                }
            } else {
                if (count <= 0) control_open = 0;
                killing = 1;
            }
        }
    }
}
