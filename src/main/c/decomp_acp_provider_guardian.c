/*
 * Credential-free provider guardian candidate, ACPP wire version 1.
 *
 * This is deliberately not wired into the production gate. Its caller must supply
 * an isolated network/PID namespace, the existing cgroup/resource ceilings and an
 * immutable, authenticated runtime snapshot. Gate attestation of this executable
 * alone does not authenticate the child runtime. The gateway capability is visible
 * to the agent and its descendants; prompt-only configuration is NOT proof of
 * descendant capability separation. No upstream provider credential is accepted.
 *
 * Public launch arguments: --state-root ABS --codex-path ABS -- CHILD_ABS [ARGS...]
 * The first stdin frame is CHANNEL_OPEN. No additional gate byte is consumed.
 * All diagnostics are fixed strings: neither raw ACP/HTTP bytes nor capabilities
 * may be written to stderr. ACP is opaque and uses independent child pipe FDs.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

enum { ACP = 1, REQUEST = 2, HEADERS = 3, CHUNK = 4, END = 5, CANCEL = 6, OPEN = 7 };
enum { FRAME_HEADER = 18, SETUP_BYTES = 152, ABS_FRAME = 8 * 1024 * 1024, ABS_CHUNK = 65536 };
typedef struct {
    unsigned char *data;
    size_t off, len, cap, chunk_ends[16];
    unsigned chunks;
} Queue;
typedef struct {
    unsigned char header[FRAME_HEADER], *body;
    size_t used, received;
    uint32_t length;
    uint64_t seq;
    unsigned tag;
    bool validated;
} Frame;
typedef struct {
    uint32_t request, response, header, fields, chunk, queued, requests, tokens;
    uint64_t overall, idle, cleanup;
    unsigned char capability[32];
} Limits;
typedef struct {
    Limits lim;
    Queue host, child, http;
    Frame frame;
    int listener, connection, childin, childout, childerr, childpidfd;
    pid_t childpid;
    unsigned port;
    uint64_t started, last_progress, sequence, response_bytes;
    unsigned char *request;
    size_t request_used, header_length, content_length;
    bool opened, active, response_headers, cancelled, http_finish, child_eof;
    bool child_reaped, http_rejected;
    unsigned response_status;
    int child_status;
    const char *state_root, *codex_path;
    char **child_argv;
} Guardian;
static volatile sig_atomic_t interrupted;
static void on_signal(int sig) {
    (void)sig;
    interrupted = 1;
}
static uint64_t now_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts))
        _exit(120);
    return (uint64_t)ts.tv_sec * 1000U + (uint64_t)ts.tv_nsec / 1000000U;
}
static uint32_t be32(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}
static uint64_t be64(const unsigned char *p) { return ((uint64_t)be32(p) << 32) | be32(p + 4); }
static void put32(unsigned char *p, uint32_t n) {
    p[0] = (unsigned char)(n >> 24);
    p[1] = (unsigned char)(n >> 16);
    p[2] = (unsigned char)(n >> 8);
    p[3] = (unsigned char)n;
}
static void put64(unsigned char *p, uint64_t n) {
    put32(p, (uint32_t)(n >> 32));
    put32(p + 4, (uint32_t)n);
}
static int nonblock(int fd) {
    int f = fcntl(fd, F_GETFL);
    return f < 0 ? -1 : fcntl(fd, F_SETFL, f | O_NONBLOCK);
}
static void closefd(int *fd) {
    if (*fd >= 0) {
        close(*fd);
        *fd = -1;
    }
}
static int queue_init(Queue *q, size_t cap) {
    q->data = malloc(cap);
    q->cap = cap;
    return q->data ? 0 : -1;
}
static size_t queue_space(const Queue *q) { return q->cap - q->len; }
static int queue_add(Queue *q, const void *p, size_t n) {
    if (n > queue_space(q))
        return 0;
    if (q->off + q->len + n > q->cap) {
        memmove(q->data, q->data + q->off, q->len);
        q->off = 0;
    }
    memcpy(q->data + q->off + q->len, p, n);
    q->len += n;
    return 1;
}
static int queue_write(Queue *q, int fd, Guardian *g) {
    if (!q->len)
        return 0;
    ssize_t n = write(fd, q->data + q->off, q->len);
    if (n > 0) {
        unsigned kept = 0;
        for (unsigned i = 0; i < q->chunks; i++)
            if (q->chunk_ends[i] > (size_t)n)
                q->chunk_ends[kept++] = q->chunk_ends[i] - (size_t)n;
        q->chunks = kept;
        q->off += (size_t)n;
        q->len -= (size_t)n;
        if (!q->len)
            q->off = 0;
        g->last_progress = now_ms();
        return 1;
    }
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return 0;
    return -1;
}
static int emit(Guardian *g, unsigned tag, uint64_t seq, const void *p, size_t n) {
    unsigned char h[FRAME_HEADER] = {'A', 'C', 'P', 'P', 1, 0};
    if (queue_space(&g->host) < FRAME_HEADER + n || (tag == ACP && g->host.chunks >= g->lim.queued))
        return 0;
    h[5] = (unsigned char)tag;
    put64(h + 6, seq);
    put32(h + 14, (uint32_t)n);
    (void)queue_add(&g->host, h, sizeof h);
    (void)queue_add(&g->host, p, n);
    if (tag == ACP)
        g->host.chunk_ends[g->host.chunks++] = g->host.len;
    return 1;
}
static int parse_setup(Guardian *g, const unsigned char *p) {
    Limits *l = &g->lim;
    memcpy(l->capability, p, 32);
    l->request = be32(p + 96);
    l->response = be32(p + 100);
    l->header = be32(p + 104);
    l->fields = be32(p + 108);
    l->chunk = be32(p + 112);
    l->queued = be32(p + 116);
    l->requests = be32(p + 120);
    l->tokens = be32(p + 124);
    l->overall = be64(p + 128);
    l->idle = be64(p + 136);
    l->cleanup = be64(p + 144);
    if (!l->request || l->request > ABS_FRAME - 32 || !l->response ||
        l->response > 64U * 1024 * 1024 || !l->header || l->header > 65536 || !l->fields ||
        l->fields > 256 || !l->chunk || l->chunk > ABS_CHUNK || l->chunk > l->response ||
        !l->queued || l->queued > 16 || !l->requests || l->requests > 64 || !l->tokens ||
        l->tokens > 65536 || !l->overall || l->overall > 1800000 || !l->idle || l->idle > 1800000 ||
        !l->cleanup || l->cleanup > 1800000)
        return -1;
    /* Two bounded framing/header slots in addition to the configured data queue. */
    size_t window = (size_t)l->chunk * l->queued;
    if (queue_init(&g->host, (size_t)l->request + 32 + FRAME_HEADER + window + 2 * FRAME_HEADER) ||
        queue_init(&g->child, window) || queue_init(&g->http, window + 1024))
        return -1;
    g->request = malloc((size_t)l->header + l->request + 1);
    return g->request ? 0 : -1;
}
static int executable_fd(const char *path) {
    struct stat st;
    if (!path || path[0] != '/')
        return -1;
    int fd = open(path, O_PATH | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || !(st.st_mode & 0111)) {
        close(fd);
        return -1;
    }
    return fd;
}
static int private_dirs(const char *root) {
    char canonical[PATH_MAX];
    struct stat st;
    if (!root || root[0] != '/' || !realpath(root, canonical) || strcmp(root, canonical))
        return -1;
    int fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) || st.st_uid != geteuid() || (st.st_mode & 0777) != 0700) {
        close(fd);
        return -1;
    }
    DIR *dir = fdopendir(dup(fd));
    if (!dir) {
        close(fd);
        return -1;
    }
    struct dirent *ent;
    bool empty = true;
    errno = 0;
    while ((ent = readdir(dir)))
        if (strcmp(ent->d_name, ".") && strcmp(ent->d_name, "..")) {
            empty = false;
            break;
        }
    if (errno)
        empty = false;
    closedir(dir);
    const char *names[] = {"home", "codex", "config", "cache", "data", "tmp"};
    if (empty)
        for (size_t i = 0; i < sizeof names / sizeof *names; i++)
            if (mkdirat(fd, names[i], 0700)) {
                empty = false;
                break;
            }
    close(fd);
    return empty ? 0 : -1;
}
static int launch(Guardian *g) {
    int exe = -1, codex = -1, pin[2] = {-1, -1}, pout[2] = {-1, -1}, perr[2] = {-1, -1},
        exec_gate[2] = {-1, -1};
    exe = executable_fd(g->child_argv[0]);
    codex = executable_fd(g->codex_path);
    if (exe < 0 || codex < 0 || private_dirs(g->state_root))
        goto fail;
    closefd(&codex);
    g->listener = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t address_size = sizeof address;
    if (g->listener < 0 || bind(g->listener, (struct sockaddr *)&address, sizeof address) ||
        getsockname(g->listener, (struct sockaddr *)&address, &address_size) ||
        listen(g->listener, 1))
        goto fail;
    g->port = ntohs(address.sin_port);
    if (pipe2(pin, O_CLOEXEC) || pipe2(pout, O_CLOEXEC) || pipe2(perr, O_CLOEXEC) ||
        pipe2(exec_gate, O_CLOEXEC))
        goto fail;
    char home[PATH_MAX + 16], codexhome[PATH_MAX + 20], config[PATH_MAX + 20], cache[PATH_MAX + 20];
    char data[PATH_MAX + 20], tmp[PATH_MAX + 20], codexenv[PATH_MAX + 20], gateway[512], hex[65];
    for (unsigned i = 0; i < 32; i++)
        snprintf(hex + 2 * i, 3, "%02x", g->lim.capability[i]);
    if (snprintf(home, sizeof home, "HOME=%s/home", g->state_root) >= (int)sizeof home ||
        snprintf(codexhome, sizeof codexhome, "CODEX_HOME=%s/codex", g->state_root) >=
            (int)sizeof codexhome ||
        snprintf(config, sizeof config, "XDG_CONFIG_HOME=%s/config", g->state_root) >=
            (int)sizeof config ||
        snprintf(cache, sizeof cache, "XDG_CACHE_HOME=%s/cache", g->state_root) >=
            (int)sizeof cache ||
        snprintf(data, sizeof data, "XDG_DATA_HOME=%s/data", g->state_root) >= (int)sizeof data ||
        snprintf(tmp, sizeof tmp, "TMPDIR=%s/tmp", g->state_root) >= (int)sizeof tmp ||
        snprintf(codexenv, sizeof codexenv, "CODEX_PATH=%s", g->codex_path) >= (int)sizeof codexenv)
        goto fail;
    int n = snprintf(
        gateway, sizeof gateway,
        "DEFAULT_AUTH_REQUEST={\"methodId\":\"gateway\",\"_meta\":{\"gateway\":{\"baseUrl\":\"http:"
        "//127.0.0.1:%u/v1\",\"headers\":{\"Authorization\":\"Bearer %s\"}}}}",
        g->port, hex);
    if (n < 0 || n >= (int)sizeof gateway)
        goto fail;
    char *env[] = {home,
                   codexhome,
                   config,
                   cache,
                   data,
                   tmp,
                   codexenv,
                   gateway,
                   "PATH=/usr/bin:/bin",
                   "LANG=C.UTF-8",
                   "TOKIO_WORKER_THREADS=2",
                   "INITIAL_AGENT_MODE=read-only",
                   "CODEX_CONFIG={\"features\":{\"shell_tool\":false,\"view_image\":false},\"web_"
                   "search\":\"disabled\",\"tools\":{\"update_plan\":{\"enabled\":false},"
                   "\"experimental_request_user_input\":{\"enabled\":false}}}",
                   NULL};
    pid_t parent = getpid();
    g->childpid = fork();
    if (g->childpid < 0)
        goto fail;
    if (g->childpid == 0) {
        close(exec_gate[1]);
        if (prctl(PR_SET_PDEATHSIG, SIGKILL) || getppid() != parent || setpgid(0, 0) ||
            dup2(pin[0], 0) < 0 || dup2(pout[1], 1) < 0 || dup2(perr[1], 2) < 0)
            _exit(121);
        char released;
        if (read(exec_gate[0], &released, 1) != 1 || released != 'R')
            _exit(121);
        close(exec_gate[0]);
        /* Keep only the executable descriptor across this pre-exec cleanup. */
        int keep = fcntl(exe, F_DUPFD_CLOEXEC, 3);
        if (keep < 0)
            _exit(121);
        if (keep != 3) {
            if (dup3(keep, 3, O_CLOEXEC) < 0)
                _exit(121);
            close(keep);
        }
        if (syscall(SYS_close_range, 4U, ~0U, 0))
            _exit(121);
        struct sigaction sa = {.sa_handler = SIG_DFL};
        sigemptyset(&sa.sa_mask);
        (void)sigaction(SIGPIPE, &sa, NULL);
        (void)sigaction(SIGTERM, &sa, NULL);
        (void)sigaction(SIGINT, &sa, NULL);
        if (chdir(g->state_root) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0))
            _exit(121);
        syscall(SYS_execveat, 3, "", g->child_argv, env, AT_EMPTY_PATH);
        _exit(122);
    }
    (void)setpgid(g->childpid, g->childpid);
    g->childpidfd = (int)syscall(SYS_pidfd_open, g->childpid, 0);
    closefd(&exec_gate[0]);
    /* The target cannot run before its parent holds the direct-child pidfd. */
    if (g->childpidfd < 0) {
        closefd(&exec_gate[1]);
        goto fail;
    }
    ssize_t released = write(exec_gate[1], "R", 1);
    closefd(&exec_gate[1]);
    if (released != 1)
        goto fail;
    closefd(&exe);
    closefd(&pin[0]);
    closefd(&pout[1]);
    closefd(&perr[1]);
    g->childin = pin[1];
    g->childout = pout[0];
    g->childerr = perr[0];
    if (g->childpidfd < 0 || nonblock(g->childin) || nonblock(g->childout) || nonblock(g->childerr))
        return -1;
    explicit_bzero(hex, sizeof hex);
    explicit_bzero(gateway, sizeof gateway);
    return 0;
fail:
    closefd(&exe);
    closefd(&codex);
    for (unsigned i = 0; i < 2; i++) {
        closefd(&pin[i]);
        closefd(&pout[i]);
        closefd(&perr[i]);
        closefd(&exec_gate[i]);
    }
    return -1;
}
static void reset_http(Guardian *g) {
    closefd(&g->connection);
    g->request_used = 0;
    g->header_length = 0;
    g->content_length = 0;
    g->http.off = g->http.len = 0;
    g->http.chunks = 0;
    g->http_finish = false;
    g->http_rejected = false;
}
static void reject_http(Guardian *g) {
    static const char response[] =
        "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
    g->http_rejected = true;
    g->http_finish = true;
    (void)queue_add(&g->http, response, sizeof response - 1);
}
static int parse_http_header(Guardian *g) {
    /* No obs-fold, control characters, whitespace before colon, or alternate line endings. */
    unsigned char *p = g->request;
    size_t n = g->header_length;
    if (n < 4 || memchr(p, 0, n))
        return -1;
    for (size_t i = 0; i < n; i++)
        if ((p[i] < 32 && p[i] != '\r' && p[i] != '\n') || p[i] > 126)
            return -1;
    p[n - 2] = 0;
    char *line = (char *)p, *end = strstr(line, "\r\n");
    if (!end)
        return -1;
    *end = 0;
    if (strcmp(line, "POST /v1/responses HTTP/1.1"))
        return -1;
    bool host = false, auth = false, length = false, type = false, accept = false,
         connection = false, agent = false;
    unsigned fields = 0;
    char expected_host[48], expected_auth[72];
    snprintf(expected_host, sizeof expected_host, "127.0.0.1:%u", g->port);
    memcpy(expected_auth, "Bearer ", 7);
    for (unsigned i = 0; i < 32; i++)
        snprintf(expected_auth + 7 + 2 * i, 3, "%02x", g->lim.capability[i]);
    for (line = end + 2; *line; line = end + 2) {
        end = strstr(line, "\r\n");
        if (!end)
            return -1;
        *end = 0;
        if (++fields > g->lim.fields)
            return -1;
        char *colon = strchr(line, ':');
        if (!colon || colon == line)
            return -1;
        for (char *s = line; s < colon; s++)
            if (!((*s >= 'A' && *s <= 'Z') || (*s >= 'a' && *s <= 'z') || *s == '-'))
                return -1;
        *colon = 0;
        char *value = colon + 1;
        while (*value == ' ')
            value++;
        size_t len = strlen(value);
        if (!len || value[len - 1] == ' ')
            return -1;
        if (strchr(value, '\r') || strchr(value, '\n'))
            return -1;
        if (!strcasecmp(line, "Host")) {
            if (host || strcmp(value, expected_host))
                return -1;
            host = true;
        } else if (!strcasecmp(line, "Authorization")) {
            if (auth || len != 71)
                return -1;
            unsigned diff = 0;
            for (unsigned i = 0; i < 71; i++)
                diff |= (unsigned char)value[i] ^ (unsigned char)expected_auth[i];
            if (diff)
                return -1;
            auth = true;
        } else if (!strcasecmp(line, "Content-Length")) {
            if (length || value[0] < '1' || value[0] > '9')
                return -1;
            size_t total = 0;
            for (char *s = value; *s; s++) {
                if (*s < '0' || *s > '9' || total > g->lim.request / 10U)
                    return -1;
                total = total * 10U + (unsigned)(*s - '0');
                if (total > g->lim.request)
                    return -1;
            }
            g->content_length = total;
            length = true;
        } else if (!strcasecmp(line, "Content-Type")) {
            if (type || strcmp(value, "application/json"))
                return -1;
            type = true;
        } else if (!strcasecmp(line, "Accept")) {
            if (accept || (strcmp(value, "text/event-stream") && strcmp(value, "*/*")))
                return -1;
            accept = true;
        } else if (!strcasecmp(line, "Connection")) {
            if (connection || (strcmp(value, "close") && strcmp(value, "keep-alive")))
                return -1;
            connection = true;
        } else if (!strcasecmp(line, "User-Agent")) {
            if (agent)
                return -1;
            agent = true;
        } else
            return -1;
    }
    explicit_bzero(expected_auth, sizeof expected_auth);
    return host && auth && length && type ? 0 : -1;
}
static int valid_utf8(const unsigned char *p, size_t n) {
    size_t i = 0;
    while (i < n) {
        unsigned c = p[i++];
        if (c < 0x80) {
            if (c == 0)
                return 0;
            continue;
        }
        unsigned extra, min, cp;
        if (c >= 0xc2 && c <= 0xdf) {
            extra = 1;
            min = 0x80;
            cp = c & 31;
        } else if (c >= 0xe0 && c <= 0xef) {
            extra = 2;
            min = 0x800;
            cp = c & 15;
        } else if (c >= 0xf0 && c <= 0xf4) {
            extra = 3;
            min = 0x10000;
            cp = c & 7;
        } else
            return 0;
        if (n - i < extra)
            return 0;
        while (extra--) {
            c = p[i++];
            if ((c & 0xc0) != 0x80)
                return 0;
            cp = (cp << 6) | (c & 63);
        }
        if (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))
            return 0;
    }
    return 1;
}
static int submit_request(Guardian *g) {
    if (g->active || g->http_rejected || g->http_finish || !g->header_length ||
        !g->content_length || g->request_used < g->header_length + g->content_length)
        return 0;
    if (g->request_used != g->header_length + g->content_length || g->sequence >= g->lim.requests ||
        !valid_utf8(g->request + g->header_length, g->content_length)) {
        reject_http(g);
        return 1;
    }
    size_t n = 32 + g->content_length;
    if (queue_space(&g->host) < FRAME_HEADER + n)
        return 0;
    unsigned char h[FRAME_HEADER] = {'A', 'C', 'P', 'P', 1, REQUEST};
    put64(h + 6, ++g->sequence);
    put32(h + 14, (uint32_t)n);
    (void)queue_add(&g->host, h, sizeof h);
    (void)queue_add(&g->host, g->lim.capability, 32);
    (void)queue_add(&g->host, g->request + g->header_length, g->content_length);
    g->active = true;
    g->response_headers = false;
    g->cancelled = false;
    g->response_status = 0;
    return 1;
}
static int http_read(Guardian *g) {
    unsigned char peek;
    if (g->active) {
        ssize_t n = recv(g->connection, &peek, 1, MSG_PEEK);
        if (n < 0 && (errno == EAGAIN || errno == EINTR))
            return 0;
        /* Any pipelining, half-close or disconnect revokes this request. */
        if (!g->cancelled && !emit(g, CANCEL, g->sequence, "", 0))
            return 0;
        g->cancelled = true;
        reset_http(g);
        return 1;
    }
    size_t bound = (size_t)g->lim.header + g->lim.request;
    if (g->request_used >= bound) {
        reject_http(g);
        return 1;
    }
    ssize_t n = read(g->connection, g->request + g->request_used, bound - g->request_used);
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return 0;
    if (n <= 0) {
        reset_http(g);
        return 1;
    }
    g->request_used += (size_t)n;
    g->request[g->request_used] = 0;
    g->last_progress = now_ms();
    if (!g->header_length) {
        unsigned char *end = memmem(g->request, g->request_used, "\r\n\r\n", 4);
        if (!end) {
            if (g->request_used >= g->lim.header)
                reject_http(g);
            return 1;
        }
        g->header_length = (size_t)(end - g->request) + 4;
        if (g->header_length > g->lim.header || parse_http_header(g)) {
            reject_http(g);
            return 1;
        }
    }
    return submit_request(g) < 0 ? -1 : 1;
}
static int validate_header(Guardian *g) {
    Frame *f = &g->frame;
    if (memcmp(f->header, "ACPP", 4) || f->header[4] != 1)
        return -1;
    f->tag = f->header[5];
    f->seq = be64(f->header + 6);
    f->length = be32(f->header + 14);
    if (!g->opened) {
        if (f->tag != OPEN || f->seq || f->length != SETUP_BYTES)
            return -1;
    } else {
        if (f->tag == ACP) {
            if (f->seq || !f->length || f->length > g->lim.chunk)
                return -1;
        } else {
            if (f->seq == 0 || f->seq > INT64_MAX || !g->active || f->seq != g->sequence)
                return -1;
            switch (f->tag) {
            case HEADERS:
                if (g->response_headers || g->cancelled || f->length < 4 ||
                    f->length > g->lim.header)
                    return -1;
                break;
            case CHUNK:
                if (!g->response_headers || g->response_status != 200 || g->cancelled ||
                    !f->length || f->length > g->lim.chunk ||
                    f->length > g->lim.response - g->response_bytes)
                    return -1;
                break;
            case END:
                if (f->length != 1)
                    return -1;
                break;
            case CANCEL:
                if (f->length || g->cancelled)
                    return -1;
                break;
            default:
                return -1;
            }
        }
    }
    f->body = malloc(f->length ? f->length : 1);
    if (!f->body)
        return -1;
    f->validated = true;
    return 0;
}
static int apply_frame(Guardian *g) {
    Frame *f = &g->frame;
    /* A local socket cancellation may occur between the fixed header and body. */
    if (g->opened && f->tag != ACP &&
        (!g->active || f->seq != g->sequence || (g->cancelled && f->tag != END)))
        return -1;
    if (f->tag == OPEN) {
        if (parse_setup(g, f->body) || launch(g))
            return -1;
        g->opened = true;
        g->started = now_ms();
    } else if (f->tag == ACP) {
        if (g->child.chunks >= g->lim.queued || !queue_add(&g->child, f->body, f->length))
            return 0;
        g->child.chunk_ends[g->child.chunks++] = g->child.len;
    } else if (f->tag == HEADERS) {
        unsigned status = ((unsigned)f->body[0] << 8) | f->body[1],
                 n = ((unsigned)f->body[2] << 8) | f->body[3];
        if (f->length != 4 + n ||
            !((status == 200 && n == 17 && !memcmp(f->body + 4, "text/event-stream", 17)) ||
              (status >= 400 && status <= 599 && n == 0)))
            return -1;
        if (status == 200) {
            static const char h[] =
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: "
                "chunked\r\nConnection: close\r\n\r\n";
            if (!queue_add(&g->http, h, sizeof h - 1))
                return 0;
        }
        g->response_status = status;
        g->response_headers = true;
    } else if (f->tag == CHUNK) {
        char chunk_header[24];
        int n = snprintf(chunk_header, sizeof chunk_header, "%x\r\n", f->length);
        if (g->http.chunks >= g->lim.queued || queue_space(&g->http) < (size_t)n + f->length + 2)
            return 0;
        (void)queue_add(&g->http, chunk_header, (size_t)n);
        (void)queue_add(&g->http, f->body, f->length);
        (void)queue_add(&g->http, "\r\n", 2);
        g->http.chunk_ends[g->http.chunks++] = g->http.len;
        g->response_bytes += f->length;
    } else if (f->tag == CANCEL) {
        g->cancelled = true;
        reset_http(g);
    } else if (f->tag == END) {
        unsigned kind = f->body[0];
        if (kind > 12 || (g->cancelled && kind != 5 && kind != 11))
            return -1;
        if (kind == 0) {
            if (!g->response_headers || g->response_status != 200 || g->cancelled)
                return -1;
            if (!queue_add(&g->http, "0\r\n\r\n", 5))
                return 0;
        } else if (!g->cancelled && g->response_status != 200) {
            char response[96];
            unsigned status = g->response_status ? g->response_status : 502;
            int n = snprintf(
                response, sizeof response,
                "HTTP/1.1 %u Provider Failure\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                status);
            if (!queue_add(&g->http, response, (size_t)n))
                return 0;
        }
        g->active = false;
        g->http_finish = true;
    }
    free(f->body);
    memset(f, 0, sizeof *f);
    g->last_progress = now_ms();
    return 1;
}
static int host_read(Guardian *g) {
    Frame *f = &g->frame;
    if (f->validated && f->received == f->length)
        return apply_frame(g);
    unsigned char *where = f->validated ? f->body + f->received : f->header + f->used;
    size_t amount = f->validated ? f->length - f->received : FRAME_HEADER - f->used;
    ssize_t n = read(0, where, amount);
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return 0;
    if (n <= 0)
        return -1;
    g->last_progress = now_ms();
    if (f->validated)
        f->received += (size_t)n;
    else {
        f->used += (size_t)n;
        if (f->used == FRAME_HEADER && validate_header(g))
            return -1;
    }
    if (f->validated && f->received == f->length)
        return apply_frame(g);
    return 1;
}
static int drain_child(Guardian *g, int *fd, bool acp) {
    unsigned char bytes[ABS_CHUNK];
    size_t cap = acp ? g->lim.chunk : sizeof bytes;
    if (acp && (g->host.chunks >= g->lim.queued || queue_space(&g->host) < cap + FRAME_HEADER))
        return 0;
    ssize_t n = read(*fd, bytes, cap);
    if (n > 0) {
        g->last_progress = now_ms();
        if (acp && !emit(g, ACP, 0, bytes, (size_t)n))
            return -1;
        return 1;
    }
    if (n < 0 && (errno == EAGAIN || errno == EINTR))
        return 0;
    if (n < 0)
        return -1;
    closefd(fd);
    if (acp)
        g->child_eof = true;
    return 1;
}
/* Only direct children reported by our own proc task are considered. Open pidfds
 * before signalling and repeat after reparenting; no ambient PID/cmdline scan. */
static int terminate_owned_children(void) {
    char path[96], bytes[4096];
    snprintf(path, sizeof path, "/proc/self/task/%ld/children", (long)getpid());
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    ssize_t n = read(fd, bytes, sizeof bytes - 1);
    close(fd);
    if (n < 0 || n == (ssize_t)sizeof bytes - 1)
        return -1;
    bytes[n] = 0;
    char *cursor = bytes;
    unsigned count = 0;
    while (*cursor) {
        while (*cursor == ' ' || *cursor == '\n')
            cursor++;
        if (!*cursor)
            break;
        char *end;
        errno = 0;
        long pid = strtol(cursor, &end, 10);
        if (errno || end == cursor || pid <= 0 || pid > INT_MAX || ++count > 32)
            return -1;
        int pidfd = (int)syscall(SYS_pidfd_open, (pid_t)pid, 0);
        if (pidfd >= 0) {
            int rc = (int)syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
            int saved = errno;
            close(pidfd);
            if (rc && saved != ESRCH)
                return -1;
        } else if (errno != ESRCH)
            return -1;
        cursor = end;
    }
    return (int)count;
}
static int cleanup(Guardian *g) {
    closefd(&g->listener);
    closefd(&g->connection);
    closefd(&g->childin);
    closefd(&g->childout);
    closefd(&g->childerr);
    explicit_bzero(g->lim.capability, sizeof g->lim.capability);
    uint64_t deadline = now_ms() + (g->lim.cleanup ? g->lim.cleanup : 1000);
    if (g->childpidfd >= 0)
        (void)syscall(SYS_pidfd_send_signal, g->childpidfd, SIGTERM, NULL, 0);
    closefd(&g->childpidfd);
    bool verified = false;
    do {
        int count = terminate_owned_children();
        if (count < 0)
            break;
        int status;
        pid_t pid;
        do {
            pid = waitpid(-1, &status, WNOHANG | __WALL);
        } while (pid > 0);
        if (pid < 0 && errno == ECHILD && count == 0) {
            verified = true;
            break;
        }
        (void)poll(NULL, 0, 5);
    } while (now_ms() < deadline);
    free(g->frame.body);
    free(g->host.data);
    free(g->child.data);
    free(g->http.data);
    free(g->request);
    return verified ? 0 : -1;
}
static int run(Guardian *g) {
    while (!interrupted) {
        uint64_t now = now_ms(), overall = g->opened ? g->lim.overall : 5000,
                 idle = g->opened ? g->lim.idle : 5000;
        if (now - g->started >= overall || now - g->last_progress >= idle)
            return 124;
        if (g->opened) {
            if (g->http_finish && !g->http.len)
                reset_http(g);
            if (!g->child_reaped) {
                pid_t p = waitpid(g->childpid, &g->child_status, WNOHANG);
                if (p == g->childpid)
                    g->child_reaped = true;
                else if (p < 0)
                    return 125;
            }
            if (g->child_reaped && g->child_eof && !g->host.len) {
                if (g->active || g->frame.used || g->child.len || g->connection >= 0)
                    return 126;
                return WIFEXITED(g->child_status) ? WEXITSTATUS(g->child_status)
                                                  : 128 + WTERMSIG(g->child_status);
            }
            if (submit_request(g) < 0)
                return 126;
        }
        Frame *f = &g->frame;
        bool pending = f->validated && f->received == f->length;
        if (pending) {
            int r = apply_frame(g);
            if (r < 0)
                return 126;
            if (r > 0)
                continue;
        }
        struct pollfd p[7] = {
            {.fd = 0, .events = pending ? 0 : POLLIN},
            {.fd = g->host.len ? 1 : -1, .events = POLLOUT},
            {.fd = g->opened && g->host.chunks < g->lim.queued &&
                           queue_space(&g->host) >= g->lim.chunk + FRAME_HEADER
                       ? g->childout
                       : -1,
             .events = POLLIN},
            {.fd = g->opened ? g->childerr : -1, .events = POLLIN},
            {.fd = g->child.len ? g->childin : -1, .events = POLLOUT},
            {.fd = g->opened ? g->listener : -1, .events = POLLIN},
            {.fd = g->connection,
             .events = (short)((!g->http_rejected && !g->http_finish ? POLLIN : 0) |
                               (g->http.len ? POLLOUT : 0))}};
        uint64_t remain = overall - (now - g->started),
                 idle_remain = idle - (now - g->last_progress);
        if (idle_remain < remain)
            remain = idle_remain;
        int timeout = (int)(remain < 20 ? remain : 20);
        int ready = poll(p, 7, timeout);
        if (ready < 0) {
            if (errno == EINTR)
                continue;
            return 126;
        }
        if (p[0].revents & (POLLHUP | POLLERR | POLLNVAL))
            return 126;
        if ((p[0].revents & POLLIN) && (host_read(g) < 0))
            return 126;
        if (p[1].revents && queue_write(&g->host, 1, g) < 0)
            return 126;
        if (p[2].revents && drain_child(g, &g->childout, true) < 0)
            return 126;
        if (p[3].revents && drain_child(g, &g->childerr, false) < 0)
            return 126;
        if (p[4].revents && queue_write(&g->child, g->childin, g) < 0)
            return 126;
        if (p[5].revents) {
            int fd = accept4(g->listener, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
            if (fd < 0 && errno != EAGAIN && errno != EINTR)
                return 126;
            if (fd >= 0) {
                if (g->active || g->connection >= 0)
                    close(fd);
                else {
                    /* Bound kernel output buffering as well as the user-space queue.
                     * Linux doubles SO_SNDBUF for bookkeeping; this is at most 128 KiB. */
                    unsigned window = g->lim.chunk * g->lim.queued;
                    int send_buffer = (int)(window < 4096 ? 4096 : window > 65536 ? 65536 : window);
                    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &send_buffer, sizeof send_buffer)) {
                        close(fd);
                        return 126;
                    }
                    g->connection = fd;
                }
            }
        }
        if (p[6].revents & (POLLIN | POLLHUP | POLLERR)) {
            if (http_read(g) < 0)
                return 126;
        }
        if (g->connection >= 0 && (p[6].revents & POLLOUT) &&
            queue_write(&g->http, g->connection, g) < 0) {
            if (g->active && !g->cancelled) {
                if (!emit(g, CANCEL, g->sequence, "", 0))
                    return 126;
                g->cancelled = true;
            }
            reset_http(g);
        }
    }
    return 130;
}
int main(int argc, char **argv) {
    Guardian g = {.listener = -1,
                  .connection = -1,
                  .childin = -1,
                  .childout = -1,
                  .childerr = -1,
                  .childpidfd = -1,
                  .childpid = -1};
    if (argc < 7 || strcmp(argv[1], "--state-root") || strcmp(argv[3], "--codex-path") ||
        strcmp(argv[5], "--"))
        return 120;
    g.state_root = argv[2];
    g.codex_path = argv[4];
    g.child_argv = argv + 6;
    if (syscall(SYS_close_range, 3U, ~0U, 0) || prctl(PR_SET_CHILD_SUBREAPER, 1) || nonblock(0) ||
        nonblock(1) || nonblock(2))
        return 120;
    struct sigaction sa = {.sa_handler = on_signal};
    sigemptyset(&sa.sa_mask);
    if (sigaction(SIGTERM, &sa, NULL) || sigaction(SIGINT, &sa, NULL))
        return 120;
    sa.sa_handler = SIG_IGN;
    if (sigaction(SIGPIPE, &sa, NULL))
        return 120;
    sa.sa_handler = SIG_DFL;
    if (sigaction(SIGCHLD, &sa, NULL))
        return 120;
    sigset_t mask;
    sigemptyset(&mask);
    if (sigprocmask(SIG_SETMASK, &mask, NULL))
        return 120;
    g.started = g.last_progress = now_ms();
    int result = run(&g);
    if (cleanup(&g)) {
        ssize_t ignored = write(2, "guardian: cleanup unverified\n", 29);
        (void)ignored;
        return 127;
    }
    if (result) {
        ssize_t ignored = write(2, "guardian: bounded session failed\n", 33);
        (void)ignored;
    }
    return result;
}
