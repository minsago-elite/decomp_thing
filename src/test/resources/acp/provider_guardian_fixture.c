#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

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
static int supervise(int argc, char **argv) {
    if (argc < 3 || prctl(PR_SET_CHILD_SUBREAPER, 1))
        return 80;
    struct rlimit fd = {128, 128}, as = {2UL * 1024 * 1024 * 1024, 2UL * 1024 * 1024 * 1024};
    if (setrlimit(RLIMIT_NOFILE, &fd) || setrlimit(RLIMIT_AS, &as))
        return 81;
    pid_t child = fork();
    if (child < 0)
        return 82;
    if (!child) {
        execv(argv[2], argv + 2);
        _exit(83);
    }
    int status;
    if (waitpid(child, &status, 0) != child)
        return 84;
    pid_t other = waitpid(-1, NULL, WNOHANG | __WALL);
    int clean = other < 0 && errno == ECHILD;
    char msg[128];
    int n = snprintf(msg, sizeof msg, "SUPERVISOR guardian=%d cleanup=%s namespace-still-live\n",
                     WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status),
                     clean ? "ECHILD" : "FAILED");
    allwrite(2, msg, (size_t)n);
    /* Deliberately keep the namespace alive so its teardown cannot mask a leak. */
    struct pollfd p = {.fd = 0, .events = POLLIN};
    if (poll(&p, 1, 5000) > 0) {
        char b;
        ssize_t r = read(0, &b, 1);
        if (r == 0)
            pause_ms(1000);
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
        return supervise(argc, argv);
    const char *mode = argc > 1 ? argv[1] : "success";
    if (!strcmp(mode, "descendant")) {
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
            pid_t q = fork();
            if (q < 0)
                _exit(73);
            if (q)
                _exit(0);
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
        if (waitpid(p, NULL, 0) != p)
            return 75;
        marker("DESCENDANT_READY\n");
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
    /* Child receives only standard FDs and the explicitly defined, credential-free environment. */
    for (int i = 3; i < 128; i++)
        if (fcntl(i, F_GETFD) >= 0)
            return 77;
    if (getenv("OPENAI_API_KEY") || getenv("APP_SERVER_LOGS") || getenv("UNTRUSTED_SENTINEL"))
        return 78;
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
