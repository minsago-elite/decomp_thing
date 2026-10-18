/* Protected own-child exec/wait observer. Linux only. No candidate API tracing.
 * Source checkpoint ONLY until compiler, exact bwrap handoff, proc permissions,
 * loader closure, adversarial controls and all native phases are qualified.
 * No test/host-direct/bypass mode. Original absolute execve argv/env are kept.
 */
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <time.h>
#include <unistd.h>

#define PROC_MAGIC 0x9fa0
#define META_LIMIT 4096
#define FD_LIMIT 64
#define PROC_ENTRIES 256
#define FD_ENTRIES 66
#define BARRIER_ATTEMPTS 100
#define BARRIER_NS UINT64_C(1000000000)
#define POLL_NS 10000000L
/* Fixed Linux UAPI045958acaa75205b31578cb22c4345e28dd2e4bf; no weak fallback. */
#ifndef F_SEAL_EXEC
#define F_SEAL_EXEC 0x0020
#elif F_SEAL_EXEC != 0x0020
#error conflicting F_SEAL_EXEC UAPI
#endif
#if F_SEAL_SEAL != 0x0001 || F_SEAL_SHRINK != 0x0002 || F_SEAL_GROW != 0x0004 || F_SEAL_WRITE != 0x0008
#error conflicting helper seal UAPI
#endif
#ifdef F_SEAL_FUTURE_WRITE
#if F_SEAL_FUTURE_WRITE != 0x0010
#error conflicting F_SEAL_FUTURE_WRITE UAPI
#endif
#endif
#define HELPER_REQUIRED_SEALS 0x002f
#define HELPER_KNOWN_SEALS 0x003f
#define RECORD_LIMIT 512
#define PROOF_LIMIT 1024

extern char **environ;
struct identity { uint64_t dev, ino; };
struct config {
    const char *attempt, *phase;
    struct identity report, reaper, outer_pidns;
    char **worker;
    bool library;
    struct identity library_id;
    uint64_t library_size;
};
struct barrier { uint64_t start; struct identity pidns; unsigned scans, fds; };
static struct config cfg;
static unsigned records, written_bytes;
static bool channel_failed;
static const char *stage = "arguments";
static pid_t owned_child = -1;
static bool child_reaped;
static struct identity stdio_ids[3];

static struct identity identity(const struct stat *st) {
    return (struct identity){(uint64_t)st->st_dev, (uint64_t)st->st_ino};
}
static bool same(struct identity a, struct identity b) {
    return a.dev == b.dev && a.ino == b.ino;
}
static int stat_id(const char *path, struct identity *out) {
    struct stat st;
    if (stat(path, &st) < 0) return -1;
    *out = identity(&st);
    return 0;
}
static int number(const char *s, uint64_t *out) {
    uint64_t n = 0;
    if (!s || !*s || (s[0] == '0' && s[1])) return -1;
    for (; *s; ++s) {
        if (*s < '0' || *s > '9' || n > (UINT64_MAX - (unsigned)(*s-'0')) / 10) return -1;
        n = n * 10 + (unsigned)(*s-'0');
    }
    *out = n;
    return 0;
}
static bool phase_ok(const char *s) {
    static const char *const phases[] = {"compiler","probe","runtime","elf-inspection",
        "caller-build","helper-build","toolchain-inspection","unspecified"};
    for (size_t i=0;i<sizeof(phases)/sizeof(phases[0]);++i)
        if (!strcmp(s, phases[i])) return true;
    return false;
}
static int arguments(int argc, char **argv) {
    static const char *const flags[] = {"--attempt","--phase","--report-fd",
        "--report-device","--report-inode","--reaper-device","--reaper-inode",
        "--outer-pidns-device","--outer-pidns-inode"};
    if (argc < 21) return -1;
    for (unsigned i=0;i<9;++i) if (strcmp(argv[1+2*i],flags[i])) return -1;
    if (strlen(argv[2]) != 32 || strspn(argv[2],"0123456789abcdef") != 32 ||
        !phase_ok(argv[4]) || strcmp(argv[6],"4")) return -1;
    uint64_t ids[6];
    for (unsigned i=0;i<6;++i) if (number(argv[8+2*i],&ids[i]) < 0) return -1;
    cfg.attempt=argv[2]; cfg.phase=argv[4];
    unsigned end=19;
    if (!strcmp(argv[19],"--library-device")) {
        if (argc < 27 || strcmp(argv[21],"--library-inode") || strcmp(argv[23],"--library-size") ||
            number(argv[20],&cfg.library_id.dev)<0 || number(argv[22],&cfg.library_id.ino)<0 ||
            number(argv[24],&cfg.library_size)<0 || !cfg.library_size || cfg.library_size>16777216 ||
            strcmp(cfg.phase,"runtime")) return -1;
        cfg.library=true; end=25;
    }
    if (strcmp(argv[end],"--") || argv[end+1][0]!='/' || !argv[end+1][1]) return -1;
    cfg.worker=argv+end+1;
    cfg.report=(struct identity){ids[0],ids[1]};
    cfg.reaper=(struct identity){ids[2],ids[3]};
    cfg.outer_pidns=(struct identity){ids[4],ids[5]};
    return 0;
}
/* Monotonic deadlines never reset on EINTR/retry. Outer phase/cgroup deadline
 * also covers all monitor waits and kills/reaps after transport/controller loss. */
static int now_ns(uint64_t *out) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t) < 0 || t.tv_sec < 0) return -1;
    *out=(uint64_t)t.tv_sec*UINT64_C(1000000000)+(uint64_t)t.tv_nsec;
    return 0;
}
static int read_meta(const char *path, char buffer[META_LIMIT+1]) {
    int fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd < 0) return -1;
    size_t used=0;
    while (used <= META_LIMIT) {
        ssize_t n=read(fd,buffer+used,META_LIMIT+1-used);
        if (n<0 && errno==EINTR) continue;
        if (n<0) { int e=errno; close(fd); errno=e; return -1; }
        if (!n) break;
        used+=(size_t)n;
        if (used>META_LIMIT) { close(fd); errno=EOVERFLOW; return -1; }
    }
    int saved=errno;
    if (close(fd)<0) return -1;
    errno=saved;
    buffer[used]='\0';
    if (memchr(buffer,'\0',used)) { errno=EINVAL; return -1; }
    return (int)used;
}
static int proc_start(const char *path, pid_t expected, uint64_t *start) {
    char b[META_LIMIT+1];
    if (read_meta(path,b)<0) return -1;
    char *end;
    errno=0;
    long pid=strtol(b,&end,10);
    if (errno || pid!=expected || *end!=' ' || end[1]!='(') { errno=EINVAL; return -1; }
    /* comm may contain spaces or ')'; the final ')' precedes fixed numeric fields. */
    char *tail=strrchr(end,')');
    if (!tail || tail[1]!=' ' || !tail[2] || tail[3]!=' ') { errno=EINVAL; return -1; }
    tail+=4; /* field4 ppid; starttime is field22, the19th token here. */
    for (unsigned field=4;field<=22;++field) {
        char *stop=strchr(tail,' ');
        if (!stop) { errno=EINVAL; return -1; }
        if (field==22) {
            *stop='\0';
            if (number(tail,start)<0 || !*start) { errno=EINVAL; return -1; }
            return 0;
        }
        if (stop==tail) { errno=EINVAL; return -1; }
        tail=stop+1;
    }
    errno=EINVAL; return -1;
}
static int no_capabilities(void) {
    char b[META_LIMIT+1];
    if (read_meta("/proc/self/status",b)<0) return -1;
    const char *names[]={"CapInh:\t","CapPrm:\t","CapEff:\t","CapAmb:\t"};
    for (unsigned i=0;i<4;++i) {
        char *p=strstr(b,names[i]);
        if (!p || (p!=b && p[-1]!='\n')) { errno=EINVAL; return -1; }
        p+=strlen(names[i]);
        unsigned digits=0;
        while (*p && *p!='\n') { if (*p++!='0' || ++digits>16) { errno=EPERM; return -1; } }
        if (digits!=16) { errno=EINVAL; return -1; }
    }
    return 0;
}
static int namespaces(struct identity *pidns) {
    const char *names[]={"pid","user","mnt"};
    char a[64],b[64];
    for (unsigned i=0;i<3;++i) {
        struct identity one,self;
        if (snprintf(a,sizeof(a),"/proc/1/ns/%s",names[i])<0 ||
            snprintf(b,sizeof(b),"/proc/self/ns/%s",names[i])<0 ||
            stat_id(a,&one)<0 || stat_id(b,&self)<0) return -1;
        if (!same(one,self)) { errno=EPERM; return -1; }
        if (!i) *pidns=self;
    }
    if (same(*pidns,cfg.outer_pidns)) { errno=EPERM; return -1; }
    return 0;
}
static int visibility(struct barrier *out) {
    struct statfs fs;
    uint64_t self_start;
    struct identity reaper;
    if (getpid()<=1 || getppid()!=1 || getuid()!=geteuid() || getgid()!=getegid()) {
        errno=EPERM; return -1;
    }
    if (statfs("/proc",&fs)<0) return -1;
    if ((unsigned long)fs.f_type != PROC_MAGIC) { errno=EPERM; return -1; }
    if (proc_start("/proc/self/stat",getpid(),&self_start)<0 ||
        namespaces(&out->pidns)<0 || proc_start("/proc/1/stat",1,&out->start)<0 ||
        stat_id("/proc/1/exe",&reaper)<0 || no_capabilities()<0) return -1;
    if (!same(reaper,cfg.reaper)) { errno=ESTALE; return -1; }
    return 0;
}
static int stable_parent(const struct barrier *initial) {
    struct barrier check={0};
    if (visibility(&check)<0) return -1;
    if (check.start!=initial->start || !same(check.pidns,initial->pidns)) {
        errno=ESTALE; return -1;
    }
    return 0;
}
static bool dots(const char *s) { return !strcmp(s,".") || !strcmp(s,".."); }
/* Charge before inspecting/materializing each entry. Never scan unverified host proc. */
static int process_set(void) {
    DIR *dir=opendir("/proc");
    if (!dir) return -1;
    unsigned entries=0,found=0;
    int error=0;
    for (;;) {
        errno=0;
        struct dirent *de=readdir(dir);
        if (!de) { error=errno; break; }
        if (++entries>PROC_ENTRIES) { error=EOVERFLOW; break; }
        uint64_t pid;
        if (de->d_name[0]<'0' || de->d_name[0]>'9') continue;
        if (number(de->d_name,&pid)<0 || (pid!=1 && pid!=(uint64_t)getpid())) {
            error=EPERM; break;
        }
        ++found;
    }
    if (closedir(dir)<0 && !error) error=errno;
    if (!error && found!=2) error=ESTALE;
    if (error) { errno=error; return -1; }
    return 0;
}
static int eventfd_metadata(int fd) {
    char path[64],link[64],b[META_LIMIT+1];
    int n=snprintf(path,sizeof(path),"/proc/1/fd/%d",fd);
    if (n<0 || (size_t)n>=sizeof(path)) { errno=EOVERFLOW; return -1; }
    ssize_t size=readlink(path,link,sizeof(link));
    if (size<0) return -1;
    const char expected[]="anon_inode:[eventfd]";
    if ((size_t)size!=strlen(expected) || memcmp(link,expected,(size_t)size)) return 0;
    n=snprintf(path,sizeof(path),"/proc/1/fdinfo/%d",fd);
    if (n<0 || (size_t)n>=sizeof(path)) { errno=EOVERFLOW; return -1; }
    if (read_meta(path,b)<0) return -1;
    /* These fields are generated by eventfd's kernel show_fdinfo operation. */
    if (!strstr(b,"\neventfd-count:") || !strstr(b,"\neventfd-id:") ||
        !strstr(b,"\neventfd-semaphore:")) { errno=EINVAL; return -1; }
    return 1;
}
/* 1 complete safe table; 0 bootstrap still closing (including ENOENT); -1 unsafe/error.
 * Unknown extra handles are not accepted: they must close before the finite deadline.
 * An extra proc/old-root directory remains blocking even after all report aliases close. */
static int reaper_fds(unsigned *final_count) {
    DIR *dir=opendir("/proc/1/fd");
    if (!dir) return -1;
    unsigned entries=0,count=0,stdio_seen=0,eventfds=0;
    bool pending=false;
    int error=0;
    for (;;) {
        errno=0;
        struct dirent *de=readdir(dir);
        if (!de) { error=errno; break; }
        if (++entries>FD_ENTRIES) { error=EOVERFLOW; break; }
        if (dots(de->d_name)) continue;
        uint64_t fd;
        if (number(de->d_name,&fd)<0 || fd>=FD_LIMIT || ++count>FD_LIMIT) {
            error=EOVERFLOW; break;
        }
        char path[64];
        int n=snprintf(path,sizeof(path),"/proc/1/fd/%u",(unsigned)fd);
        if (n<0 || (size_t)n>=sizeof(path)) { error=EOVERFLOW; break; }
        struct stat st;
        if (stat(path,&st)<0) {
            if (errno==ENOENT) { pending=true; continue; }
            error=errno; break;
        }
        if (same(identity(&st),cfg.report)) { pending=true; continue; }
        if (fd<=2) {
            if (!same(identity(&st),stdio_ids[fd]) || S_ISDIR(st.st_mode)) { error=EPERM; break; }
            stdio_seen|=1U<<(unsigned)fd;
        } else {
            int event=eventfd_metadata((int)fd);
            if (event<0) {
                if (errno==ENOENT) { pending=true; continue; }
                error=errno; break;
            }
            if (!event || ++eventfds>1) pending=true;
        }
    }
    if (closedir(dir)<0 && !error) error=errno;
    if (error) { errno=error; return -1; }
    if (pending || stdio_seen!=7 || count<3 || count>4) return 0;
    *final_count=count;
    return 1;
}
static int barrier_wait(struct barrier *out) {
    stage="visibility";
    if (visibility(out)<0) return -1;
    uint64_t begin,now;
    if (now_ns(&begin)<0) return -1;
    stage="barrier";
    for (unsigned attempt=1;attempt<=BARRIER_ATTEMPTS;++attempt) {
        if (now_ns(&now)<0) return -1;
        if (now-begin>=BARRIER_NS) { errno=ETIMEDOUT; return -1; }
        if (stable_parent(out)<0 || process_set()<0) return -1;
        int scan=reaper_fds(&out->fds);
        if (scan<0) return -1;
        if (stable_parent(out)<0) return -1;
        if (scan==1) {
            if (now_ns(&now)<0) return -1;
            if (now-begin>=BARRIER_NS) { errno=ETIMEDOUT; return -1; }
            out->scans=attempt;
            return 0;
        }
        /* One bounded sleep; EINTR returns to deadline check, never resets it. */
        struct timespec poll={0,POLL_NS};
        if (nanosleep(&poll,NULL)<0 && errno!=EINTR) return -1;
    }
    errno=ETIMEDOUT; return -1;
}
static int protection(void) {
    struct stat st;
    struct rlimit limit;
    if (getrlimit(RLIMIT_NOFILE,&limit)<0) return -1;
    if (limit.rlim_cur!=FD_LIMIT || limit.rlim_max!=FD_LIMIT) { errno=EPERM; return -1; }
    if (fstat(4,&st)<0) return -1;
    int flags=fcntl(4,F_GETFL);
    if (flags<0) return -1;
    if (!S_ISREG(st.st_mode) || (st.st_mode&0777)!=0600 || st.st_uid!=geteuid() ||
        st.st_nlink!=1 || st.st_size!=0 || !same(identity(&st),cfg.report) ||
        (flags&O_ACCMODE)!=O_WRONLY || !(flags&O_APPEND)) { errno=EPERM; return -1; }
    if (prctl(PR_SET_DUMPABLE,0)<0 || prctl(PR_GET_DUMPABLE)!=0) { errno=EPERM; return -1; }
    if (prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1) { errno=EPERM; return -1; }
    struct sigaction child_action;
    if (sigaction(SIGCHLD,NULL,&child_action)<0) return -1;
    if (child_action.sa_handler!=SIG_DFL || (child_action.sa_flags&SA_NOCLDWAIT)) {
        errno=EPERM; return -1;
    }
    for (int fd=0;fd<3;++fd) {
        if (fstat(fd,&st)<0) return -1;
        stdio_ids[fd]=identity(&st);
        if (same(stdio_ids[fd],cfg.report) || S_ISDIR(st.st_mode)) { errno=EPERM; return -1; }
    }
    for (int fd=3;fd<FD_LIMIT;++fd) if (fd!=4) {
        if (close(fd)<0 && errno!=EBADF) return -1;
    }
    /* NOFILE hard64 does not imply inherited FDs were <=63. Enumerate own table
     * charged and reject anything beyond it, keeping only our temporary proc FD. */
    DIR *dir=opendir("/proc/self/fd");
    if (!dir) return -1;
    unsigned entries=0,seen=0;
    int error=0,own=dirfd(dir);
    for (;;) {
        errno=0; struct dirent *de=readdir(dir);
        if (!de) { error=errno; break; }
        if (++entries>FD_ENTRIES) { error=EOVERFLOW; break; }
        if (dots(de->d_name)) continue;
        uint64_t fd;
        if (number(de->d_name,&fd)<0 || fd>=FD_LIMIT) { error=EOVERFLOW; break; }
        if ((int)fd==own) continue;
        if (fd!=0 && fd!=1 && fd!=2 && fd!=4) { error=EPERM; break; }
        seen|=1U<<(unsigned)fd;
    }
    if (closedir(dir)<0 && !error) error=errno;
    if (!error && seen!=23) error=EPERM; /* bits0,1,2,4 */
    if (error) { errno=error; return -1; }
    return 0;
}
static int nonprivileged_elf(int fd, struct identity *out) {
    struct stat st;
    unsigned char magic[4];
    if (fstat(fd,&st)<0) return -1;
    if (!S_ISREG(st.st_mode) || st.st_mode&(S_ISUID|S_ISGID)) { errno=EPERM; return -1; }
    bool helper=!strcmp(cfg.phase,"probe");
    if (helper) {
        int seals=fcntl(fd,F_GET_SEALS);
        /* Content/size and execute bits are sealed; full mode is only observed. */
        if (st.st_size<=0 || (uint64_t)st.st_size>16777216 || (st.st_mode&07777)!=0500 ||
            seals<0 || (seals&HELPER_REQUIRED_SEALS)!=HELPER_REQUIRED_SEALS || (seals&~HELPER_KNOWN_SEALS)) {
            if (seals>=0) errno=EPERM;
            return -1;
        }
    }
    ssize_t cap=fgetxattr(fd,"security.capability",NULL,0);
    if (cap>=0) { errno=EPERM; return -1; }
    if (errno!=ENODATA && (helper || errno!=ENOTSUP)) return -1;
    ssize_t n;
    do { n=pread(fd,magic,sizeof(magic),0); } while (n<0 && errno==EINTR);
    if (n<0) return -1;
    if (n!=4 || memcmp(magic,"\177ELF",4)) { errno=ENOEXEC; return -1; }
    *out=identity(&st);
    return 0;
}
static int write_record(const char *b,int length) {
    if (channel_failed || length<=0 || length>RECORD_LIMIT || records>=2 || written_bytes+(unsigned)length>PROOF_LIMIT) {
        errno=EOVERFLOW; return -1;
    }
    unsigned done=0;
    while (done<(unsigned)length) {
        ssize_t n=write(4,b+done,(unsigned)length-done);
        if (n<0 && errno==EINTR) continue;
        if (n<=0) { if (!n) errno=EIO; channel_failed=true; return -1; }
        done+=(unsigned)n; written_bytes+=(unsigned)n;
    }
    ++records;
    return 0;
}
static int error_record(const char *where,int error) {
    if (!cfg.attempt || !cfg.phase || records>=2) return -1;
    char b[RECORD_LIMIT+1],e[32];
    if (error>0) (void)snprintf(e,sizeof(e),"%d",error); else memcpy(e,"null",5);
    int n=snprintf(b,sizeof(b),"{\"v\":1,\"t\":\"error\",\"s\":%u,\"a\":\"%s\",\"p\":\"%s\",\"g\":\"%s\",\"e\":%s}\n",
        records+1,cfg.attempt,cfg.phase,where,e);
    return write_record(b,n);
}
/* Bind the namespace object to controller-held immutable content, not its old pathname. */
static int library_identity(void) {
    if (!cfg.library) return 0;
    int fd=open("/library.so",O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    struct stat st;
    int seals=F_SEAL_WRITE|F_SEAL_GROW|F_SEAL_SHRINK|F_SEAL_SEAL;
    int observed=fcntl(fd,F_GET_SEALS);
    int error=0;
    if (fstat(fd,&st)<0 || !S_ISREG(st.st_mode) || !same(identity(&st),cfg.library_id) ||
        st.st_size<0 || (uint64_t)st.st_size!=cfg.library_size || observed<0 || (observed&seals)!=seals)
        error=ESTALE;
    if (close(fd)<0 && !error) error=errno;
    if (error) { errno=error; return -1; }
    return 0;
}
static int exec_record(pid_t child,int status,struct identity target,struct barrier barrier) {
    char b[RECORD_LIMIT+1],library[100]="";
    if (cfg.library) (void)snprintf(library,sizeof(library),",\"l\":[%" PRIu64 ",%" PRIu64 ",%" PRIu64 "]",cfg.library_id.dev,cfg.library_id.ino,cfg.library_size);
    int n=snprintf(b,sizeof(b),"{\"v\":1,\"t\":\"exec\",\"s\":1,\"a\":\"%s\",\"p\":\"%s\",\"c\":%ld,\"ed\":%" PRIu64 ",\"ei\":%" PRIu64 ",\"od\":%" PRIu64 ",\"oi\":%" PRIu64 ",\"w\":%u,\"cf\":1,\"dp\":0,\"rd\":%" PRIu64 ",\"ri\":%" PRIu64 ",\"b\":[1,%" PRIu64 ",%" PRIu64 ",%" PRIu64 ",%u,%u]%s}\n",
        cfg.attempt,cfg.phase,(long)child,target.dev,target.ino,target.dev,target.ino,
        (unsigned)status,cfg.reaper.dev,cfg.reaper.ino,barrier.start,barrier.pidns.dev,
        barrier.pidns.ino,barrier.scans,barrier.fds,library);
    return write_record(b,n);
}
static int term_record(pid_t child,int status) {
    const char *kind; int value;
    if (WIFEXITED(status)) { kind="exit"; value=WEXITSTATUS(status); }
    else if (WIFSIGNALED(status)) { kind="signal"; value=WTERMSIG(status); }
    else { errno=EINVAL; return -1; }
    char b[RECORD_LIMIT+1];
    int n=snprintf(b,sizeof(b),"{\"v\":1,\"t\":\"term\",\"s\":2,\"a\":\"%s\",\"p\":\"%s\",\"c\":%ld,\"r\":%u,\"k\":\"%s\",\"n\":%d}\n",
        cfg.attempt,cfg.phase,(long)child,(unsigned)status,kind,value);
    return write_record(b,n);
}
static int wait_owned(int *status) {
    pid_t got;
    do { got=waitpid(owned_child,status,0); } while (got<0 && errno==EINTR);
    if (got!=owned_child) { if (got>=0) errno=ECHILD; return -1; }
    if (WIFEXITED(*status) || WIFSIGNALED(*status)) child_reaped=true;
    return 0;
}
static int child_fds(pid_t child) {
    char path[64];
    int n=snprintf(path,sizeof(path),"/proc/%ld/fd",(long)child);
    if (n<0 || (size_t)n>=sizeof(path)) { errno=EOVERFLOW; return -1; }
    DIR *dir=opendir(path);
    if (!dir) return -1;
    unsigned entries=0,mask=0;
    int error=0;
    for (;;) {
        errno=0; struct dirent *de=readdir(dir);
        if (!de) { error=errno; break; }
        if (++entries>5) { error=EOVERFLOW; break; } /* dot,dotdot,0,1,2 */
        if (dots(de->d_name)) continue;
        uint64_t fd;
        if (number(de->d_name,&fd)<0 || fd>2) { error=EPERM; break; }
        mask|=1U<<(unsigned)fd;
    }
    if (closedir(dir)<0 && !error) error=errno;
    if (!error && mask!=7) error=EPERM;
    if (error) { errno=error; return -1; }
    return 0;
}
static void child_exec(pid_t parent) {
    for (int fd=3;fd<FD_LIMIT;++fd) if (close(fd)<0 && errno!=EBADF) _exit(120);
    errno=0;
    if (fcntl(4,F_GETFD)!=-1 || errno!=EBADF) _exit(120);
    if (prctl(PR_SET_PDEATHSIG,SIGKILL)<0 || getppid()!=parent) _exit(121);
    int death=0;
    if (prctl(PR_GET_PDEATHSIG,&death)<0 || death!=SIGKILL ||
        prctl(PR_SET_DUMPABLE,1)<0 || prctl(PR_GET_DUMPABLE)!=1) _exit(121);
    if (ptrace(PTRACE_TRACEME,0,NULL,NULL)<0 || raise(SIGSTOP)!=0) _exit(122);
    execve(cfg.worker[0],cfg.worker,environ);
    _exit(123); /* Not an errno claim or a candidate termination proof. */
}
int main(int argc,char **argv) {
    if (arguments(argc,argv)<0) return 125; /* No trusted report binding yet. */
    stage="protection";
    if (protection()<0) return 125; /* Channel not authenticated/protected: no write. */
    struct barrier barrier={0};
    struct identity target;
    int target_fd=-1,status=0;
    stage="library";
    if (library_identity()<0) goto fail;
    stage="barrier";
    if (barrier_wait(&barrier)<0) goto fail;
    stage="target";
    target_fd=open(cfg.worker[0],O_RDONLY|O_CLOEXEC);
    if (target_fd<0 || nonprivileged_elf(target_fd,&target)<0) goto fail;
    if (same(target,cfg.report)) { errno=EPERM; goto fail; }
    /* The only worker fork is dominated by the complete no-worker barrier.
     * Recheck PID1 immediately before it; target open introduced no host handle. */
    stage="barrier";
    if (stable_parent(&barrier)<0) goto fail;
    stage="fork";
    pid_t parent=getpid();
    owned_child=fork();
    if (owned_child<0) goto fail;
    if (!owned_child) child_exec(parent);
    stage="trace";
    if (wait_owned(&status)<0) goto fail;
    if (!WIFSTOPPED(status) || WSTOPSIG(status)!=SIGSTOP || (unsigned)status>>16) {
        errno=0; goto fail;
    }
    if (ptrace(PTRACE_SETOPTIONS,owned_child,NULL,(void *)(uintptr_t)(PTRACE_O_TRACEEXEC|PTRACE_O_EXITKILL))<0 ||
        ptrace(PTRACE_CONT,owned_child,NULL,NULL)<0 || wait_owned(&status)<0) goto fail;
    stage="exec";
    if (!WIFSTOPPED(status) || WSTOPSIG(status)!=SIGTRAP ||
        (unsigned)status>>16!=PTRACE_EVENT_EXEC) { errno=0; goto fail; }
    char path[64]; struct identity observed;
    int n=snprintf(path,sizeof(path),"/proc/%ld/exe",(long)owned_child);
    if (n<0 || (size_t)n>=sizeof(path)) { errno=EOVERFLOW; goto fail; }
    if (stat_id(path,&observed)<0) goto fail;
    if (!same(target,observed)) { errno=ESTALE; goto fail; }
    stage="child-fds";
    if (child_fds(owned_child)<0 || prctl(PR_GET_DUMPABLE)!=0) goto fail;
    stage="channel";
    if (exec_record(owned_child,status,target,barrier)<0) goto fail;
    stage="detach";
    if (ptrace(PTRACE_DETACH,owned_child,NULL,NULL)<0) goto fail;
    stage="wait";
    if (wait_owned(&status)<0) goto fail;
    if (!child_reaped) { errno=0; goto fail; }
    stage="channel";
    if (term_record(owned_child,status)<0 || close(4)<0) goto fail;
    if (close(target_fd)<0) return 125;
    return 0;
fail:
    /* Kill only our exact direct child. No host PID scan; outer owned scope
     * deadline/absence verification is mandatory if wait cannot finish here. */
    if (owned_child>0 && !child_reaped) {
        (void)kill(owned_child,SIGKILL);
        (void)wait_owned(&status);
    }
    /* Stages distinguish controller failure; do not invent a syscall errno
     * for a logical guard or an opaque child bootstrap exit. This conservative
     * monitor emits null errno; the closed wire also permits actual known errno. */
    if (!channel_failed) (void)error_record(stage,0);
    if (target_fd>=0) (void)close(target_fd);
    (void)close(4);
    return 125;
}
