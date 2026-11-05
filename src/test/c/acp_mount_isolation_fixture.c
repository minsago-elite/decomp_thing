#define _GNU_SOURCE
/* Test-only. Never installed. Run only in the driver's fresh synthetic rootless O.
 * O owns external mounts and A's pidfd. A owns hostile mounts and Java's pidfd.
 * Neither owner exits its normal/error path before bounded reap + mount cleanup.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <sched.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdatomic.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define MAX_FRAMES 32
#define MAX_FRAME 4096
#define CLEANUP_MS 3000
static const char *scenario, *java_path, *classpath;
static int64_t deadline;
static bool inside_mutation(void) { return !strcmp(scenario,"hostile") || !strcmp(scenario,"cleanup-failure"); }
static int handles[8]; /* O mnt/root/user/pid, A mnt/root/user/pid */
static int mounted; /* 0 absent, 1 target, 2 moved: updated immediately on success */
static const char *role = "O";
static int controller_fd = -1;
/* Shared before O forks A: one nonrenewable cleanup budget for the whole tree. */
static _Atomic int64_t *cleanup_deadline;
struct child_owner {
    const char *kind;
    pid_t pid;
    int fd, status;
    bool reaped, private_group, disposition;
    unsigned id;
};
static unsigned next_owner;
#define CHILD(kind_) ((struct child_owner){.kind=(kind_),.pid=-1,.fd=-1})
struct channel { int fd; pid_t peer; unsigned frames; };
static int64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC, &t)) _exit(110);
    return (int64_t)t.tv_sec * 1000 + t.tv_nsec / 1000000;
}
static void event(const char *name, int rc, int error) {
    dprintf(STDOUT_FILENO, "ACP_FIXTURE {\"role\":\"%s\",\"event\":\"%s\",\"rc\":%d,\"errno\":%d}\n", role, name, rc, error);
}
static int fail(const char *name) { event(name, -1, errno); return -1; }
static int wait_fd(int fd, short events, int64_t end) {
    int64_t left = end - now_ms();
    if (left <= 0 || left > INT_MAX) { errno = ETIMEDOUT; return -1; }
    struct pollfd p[2] = {{fd, events, 0}, {controller_fd, 0, 0}};
    int rc = poll(p, controller_fd >= 0 && controller_fd != fd ? 2 : 1, (int)left);
    if (controller_fd >= 0 && (p[1].revents & (POLLHUP | POLLERR | POLLNVAL))) { errno=EPIPE; return -1; } /* EINTR is failure, never an implicit retry. */
    if (rc != 1 || !(p[0].revents & events) || (p[0].revents & (POLLERR | POLLNVAL))) {
        errno = rc == 0 ? ETIMEDOUT : EPIPE; return -1;
    }
    return 0;
}
static int pair(int fds[2]) {
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds)) return -1;
    int yes = 1;
    if (setsockopt(fds[0], SOL_SOCKET, SO_PASSCRED, &yes, sizeof yes) ||
        setsockopt(fds[1], SOL_SOCKET, SO_PASSCRED, &yes, sizeof yes)) return -1;
    return 0;
}
static int64_t protocol_end(void) {
    int64_t cleanup=cleanup_deadline?atomic_load(cleanup_deadline):0;
    return cleanup && cleanup<deadline?cleanup:deadline;
}
static int send_frame(struct channel *c, int seq, const char *who, const char *op) {
    char b[128];
    int len = snprintf(b, sizeof b, "1 %d %s %s\n", seq, who, op);
    if (++c->frames > MAX_FRAMES || wait_fd(c->fd, POLLOUT, protocol_end())) return fail("send_bound");
    if (send(c->fd, b, (size_t)len, MSG_NOSIGNAL) != len) return fail("send");
    return 0;
}
static int receive(struct channel *c, int seq, const char *who, const char *op) {
    char b[MAX_FRAME], expected[128], control[CMSG_SPACE(sizeof(struct ucred)) + CMSG_SPACE(16*sizeof(int))];
    struct iovec iov = {b, sizeof b};
    struct msghdr msg = {.msg_iov=&iov, .msg_iovlen=1, .msg_control=control, .msg_controllen=sizeof control};
    if (++c->frames > MAX_FRAMES || wait_fd(c->fd, POLLIN, protocol_end())) return fail("receive_bound");
    ssize_t n = recvmsg(c->fd, &msg, MSG_CMSG_CLOEXEC | MSG_DONTWAIT);
    int len = snprintf(expected, sizeof expected, "1 %d %s %s\n", seq, who, op);
    bool unexpected_rights=false;
    if(n>=0) for(struct cmsghdr *h=CMSG_FIRSTHDR(&msg);h;h=CMSG_NXTHDR(&msg,h)) {
        if(h->cmsg_level==SOL_SOCKET && h->cmsg_type==SCM_RIGHTS && h->cmsg_len>=CMSG_LEN(0)) {
            size_t count=(h->cmsg_len-CMSG_LEN(0))/sizeof(int);
            for(size_t i=0;i<count;i++) { int fd; memcpy(&fd,(char *)CMSG_DATA(h)+i*sizeof(int),sizeof fd); close(fd); }
            unexpected_rights=true;
        }
    }
    if (unexpected_rights || n <= 0 || n > MAX_FRAME || (msg.msg_flags & (MSG_TRUNC | MSG_CTRUNC))) {
        errno = EPROTO; return fail("frame_truncated_or_eof");
    }
    struct cmsghdr *h = CMSG_FIRSTHDR(&msg);
    if (!h || h->cmsg_level != SOL_SOCKET || h->cmsg_type != SCM_CREDENTIALS ||
        h->cmsg_len != CMSG_LEN(sizeof(struct ucred)) || CMSG_NXTHDR(&msg,h)) {
        errno = EPROTO; return fail("frame_ancillary");
    }
    struct ucred cred; memcpy(&cred,CMSG_DATA(h),sizeof cred);
    if (cred.pid != c->peer || cred.uid != 0 || cred.gid != 0 || n != len || memcmp(b,expected,(size_t)len)) {
        errno = EPROTO; return fail("frame_role_sequence_peer");
    }
    event(op, 0, 0);
    return 0;
}
static int open_handle(const char *path) { return open(path, O_RDONLY | O_CLOEXEC); }
static int pin_self(int offset) {
    const char *paths[] = {"/proc/self/ns/mnt", "/proc/self/root", "/proc/self/ns/user", "/proc/self/ns/pid"};
    for (int i=0;i<4;i++) if ((handles[offset+i]=open_handle(paths[i]))<0) return fail("pin");
    return 0;
}
static int same(int a, int b) {
    struct stat x,y;
    if (fstat(a,&x) || fstat(b,&y)) return -1;
    return x.st_dev==y.st_dev && x.st_ino==y.st_ino;
}
static int pidfd(pid_t p) { return (int)syscall(SYS_pidfd_open,p,0); }
static int64_t cleanup_end(void) {
    int64_t end=atomic_load(cleanup_deadline);
    if(!end) {
        int64_t candidate=now_ms()+CLEANUP_MS, expected=0;
        if(candidate>deadline+CLEANUP_MS) candidate=deadline+CLEANUP_MS;
        atomic_compare_exchange_strong(cleanup_deadline,&expected,candidate);
        end=atomic_load(cleanup_deadline);
    }
    return end;
}
static int exit_code(int status) { return WIFEXITED(status)?WEXITSTATUS(status):128+WTERMSIG(status); }
static void child_record(const char *name, const struct child_owner *c, int rc) {
    dprintf(1,"ACP_FIXTURE {\"role\":\"%s\",\"event\":\"%s\",\"rc\":%d,\"errno\":0,\"ownerId\":%u,\"kind\":\"%s\",\"pid\":%d,\"pidfd\":%d,\"reaped\":%d,\"status\":%d}\n",
        role,name,rc,c->id,c->kind,c->pid,c->fd>=0,c->reaped,c->reaped?c->status:-1);
}
static void own_child(struct child_owner *c, pid_t p) {
    c->pid=p; c->id=++next_owner;
    child_record("child_owned",c,0); /* publish ownership before pidfd can fail */
    c->fd=pidfd(p);
    if(c->fd<0) fail("child_pidfd");
}
static int collect_child(struct child_owner *c) {
    int status=0;
    pid_t got=waitpid(c->pid,&status,WNOHANG);
    if(got==0) return 1;
    if(got!=c->pid || (!WIFEXITED(status) && !WIFSIGNALED(status))) return fail("child_wait");
    c->reaped=true; c->status=status;
    child_record("child_reaped",c,exit_code(status));
    return 0;
}
static int await_child(struct child_owner *c, int64_t end) {
    if(c->reaped) return 0;
    if(c->pid<=0) return -1;
    /* No blocking waitpid after poll. Without a pidfd, bounded WNOHANG waits
     * remain safe because this single-threaded owner is the only waiter. */
    while(now_ms()<end) {
        int rc=collect_child(c);
        if(rc<=0) return rc;
        if(c->fd>=0) { if(wait_fd(c->fd,POLLIN,end)) return fail("reap_deadline"); }
        else {
            int64_t left=end-now_ms();
            if(left<=0) break;
            struct pollfd p={controller_fd,0,0};
            if(poll(&p,controller_fd>=0?1:0,(int)(left<10?left:10))<0 || p.revents) return fail("reap_peer");
        }
    }
    errno=ETIMEDOUT; return fail("reap_deadline");
}
static int terminate_child(struct child_owner *c) {
    if(c->reaped || c->pid<=0) return 0;
    /* The group leader is still our unreaped child: its PID/PGID cannot be reused.
     * Signal the private group only before reaping that leader. */
    int failed=0;
    if(c->private_group && kill(-c->pid,SIGKILL) && errno!=ESRCH) failed=fail("group_kill");
    int rc=c->fd>=0?(int)syscall(SYS_pidfd_send_signal,c->fd,SIGKILL,NULL,0):kill(c->pid,SIGKILL);
    if(rc && errno!=ESRCH) return fail("child_kill");
    event("child_termination_requested",0,0);
    return failed;
}
static int dispose_child(struct child_owner *c) {
    if(c->pid<=0) return 0;
    c->disposition=true;
    child_record(c->reaped?"child_ledger":"child_UNVERIFIED",c,c->reaped?0:-1);
    /* Retain pidfd through actual reap or an explicit truthful UNVERIFIED record. */
    int rc=c->reaped?0:-1;
    if(c->fd>=0 && close(c->fd)) rc=-1;
    c->fd=-1; return rc;
}
static int subreaper(void) {
    int enabled=0;
    if(prctl(PR_SET_CHILD_SUBREAPER,1) || prctl(PR_GET_CHILD_SUBREAPER,&enabled) || enabled!=1) return fail("subreaper");
    event("subreaper_ready",0,0); return 0;
}
static int drain_descendants(int64_t end, unsigned *adopted) {
    /* Only called once direct owners have been reaped. Orphans are adopted
     * synchronously on parent exit. ECHILD, not a /proc snapshot, proves absence. */
    for(unsigned round=0;round<32 && now_ms()<end;round++) {
        siginfo_t info={0};
        if(waitid(P_ALL,0,&info,WEXITED|WNOHANG|WNOWAIT)<0) {
            if(errno==ECHILD) { event("descendants_absent",0,0); return 0; }
            return fail("descendant_waitid");
        }
        /* Snapshot only our direct children. No other thread/waiter reaps them.
         * Process-group escape is not treated as absence: adoption still owns it. */
        int fd=open("/proc/thread-self/children",O_RDONLY|O_CLOEXEC);
        if(fd<0) return fail("descendant_children");
        char buf[4096]; ssize_t n=read(fd,buf,sizeof buf-1); int closed=close(fd);
        if(n<=0 || n==(ssize_t)sizeof buf-1 || closed) return fail("descendant_snapshot");
        buf[n]=0; char *pos=buf;
        struct child_owner children[32]; unsigned count=0; int failed=0;
        while(*pos) {
            while(*pos==' ' || *pos=='\n') pos++;
            if(!*pos) break;
            char *tail; errno=0; long p=strtol(pos,&tail,10);
            if(errno || tail==pos || p<=0 || p>INT_MAX || (*tail && *tail!=' ' && *tail!='\n') || *adopted>=32) {
                failed=fail("descendant_bound"); break;
            }
            pos=tail;
            children[count]=CHILD("adopted-helper");
            own_child(&children[count++],(pid_t)p); ++*adopted;
        }
        /* Publish every bounded snapshot owner before waiting any of them. A
         * failed wait never discards the other children already discovered. */
        for(unsigned i=0;i<count;i++) if(terminate_child(&children[i])) failed=-1;
        for(unsigned i=0;i<count;i++) {
            int waited=await_child(&children[i],end), disposed=dispose_child(&children[i]);
            if(waited || disposed) failed=-1;
        }
        if(failed) return -1;

    }
    errno=ETIMEDOUT; return fail("descendant_deadline");
}
static int make_bind(void) {
    int rc=mount("injected","target",NULL,MS_BIND,NULL), e=rc?errno:0;
    if (!rc) mounted=1;
    event("bind",rc,e); return rc;
}
static int move_bind(bool back) {
    int rc=mount(back?"moved":"target",back?"target":"moved",NULL,MS_MOVE,NULL), e=rc?errno:0;
    if (!rc) mounted=back?1:2;
    event(back?"move_back":"move_away",rc,e); return rc;
}
static int release_mount(void) {
    if (!mounted) return 0;
    int rc=umount2(mounted==1?"target":"moved",0), e=rc?errno:0;
    if (!rc) mounted=0;
    event("unmount",rc,e); return rc;
}
static int bytes_are(const char *path, const char *value) {
    char b[32]; int fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    if (fd<0) return -1;
    ssize_t n=read(fd,b,sizeof b); int rc=close(fd);
    return !rc && n==(ssize_t)strlen(value) && !memcmp(b,value,(size_t)n) ? 0 : -1;
}
static int read_observer(int fd) {
    char b[4096]; size_t total=0; ssize_t n;
    while ((n=read(fd,b,sizeof b))>0) { total+=(size_t)n; if(total>4*1024*1024) return -1; }
    return n==0 && total ? 0 : -1;
}
static int outer_event(int fd) {
    struct pollfd p={fd,POLLPRI|POLLERR,0};
    int rc=poll(&p,1,0), e=rc<0?errno:0;
    dprintf(1,"ACP_FIXTURE {\"role\":\"O\",\"event\":\"outer_event\",\"rc\":%d,\"errno\":%d,\"revents\":%d}\n",rc,e,p.revents);
    return rc==1 && (p.revents&(POLLPRI|POLLERR)) && !(p.revents&(POLLNVAL|POLLHUP)) ? 0 : -1;
}
static void exec_java(int socket, pid_t cleaner, int cleaner_fd, bool nested) {
    char tmp[PATH_MAX],home[PATH_MAX],nested_base[PATH_MAX], cwd[PATH_MAX], tmpopt[PATH_MAX+64],jnaopt[PATH_MAX+64],homeopt[PATH_MAX+64];
    if (!getcwd(cwd,sizeof cwd)) _exit(111);
    if (snprintf(tmp,sizeof tmp,"%s/tmp",cwd)>=(int)sizeof tmp || snprintf(home,sizeof home,"%s/home",cwd)>=(int)sizeof home) _exit(111);
    snprintf(tmpopt,sizeof tmpopt,"-Djava.io.tmpdir=%s",tmp);
    snprintf(jnaopt,sizeof jnaopt,"-Djna.tmpdir=%s",tmp);
    if(snprintf(nested_base,sizeof nested_base,"%s/nested",cwd)>=(int)sizeof nested_base) _exit(111);
    snprintf(homeopt,sizeof homeopt,"-Duser.home=%s",home);
    if (setenv("TMPDIR",tmp,1)) _exit(111);
    unsetenv("JAVA_TOOL_OPTIONS"); unsetenv("JDK_JAVA_OPTIONS"); unsetenv("_JAVA_OPTIONS");
    if (!nested) {
        int originals[10]={socket,handles[0],handles[1],handles[2],handles[3],handles[4],handles[5],handles[6],handles[7],cleaner_fd};
        int copies[10];
        for(int i=0;i<10;i++) if((copies[i]=fcntl(originals[i],F_DUPFD_CLOEXEC,200))<0) _exit(111);
        for(int i=0;i<10;i++) if(dup2(copies[i],100+i)<0) _exit(111);
    }
    if(syscall(SYS_close_range,3,nested?~0U:99U,0) || (!nested && syscall(SYS_close_range,110,~0U,0))) _exit(111);
    char parent[32],end[32]; snprintf(parent,sizeof parent,"%d",cleaner); snprintf(end,sizeof end,"%lld",(long long)deadline);
    if(nested) {
        execlp("unshare","unshare","--user","--map-root-user","--mount","--",java_path,
            "-XX:-UsePerfData",tmpopt,jnaopt,homeopt,"-cp",classpath,"decompengine.acp.LinuxBubblewrapBoundaryTest","private-control-bind-probe",nested_base,NULL);
    } else {
        execl(java_path,java_path,"-XX:-UsePerfData","-XX:-CreateCoredumpOnCrash",tmpopt,jnaopt,homeopt,"-cp",classpath,
            "decompengine.acp.AcpMountIsolationFixtureMain",scenario,parent,end,NULL);
    }
    _exit(111);
}
static int nested_probe(struct child_owner *c) {
    pid_t creator=getpid();
    pid_t p=fork(); if(p<0) return fail("nested_fork");
    if(!p) {
        if(setpgid(0,0) || getpgrp()!=getpid() || prctl(PR_SET_PDEATHSIG,SIGKILL) || getppid()!=creator) _exit(111);
        int log=open("nested.log",O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
        if(log<0 || dup2(log,1)<0 || dup2(log,2)<0) _exit(111);
        /* Without --fork, unshare execs the unchanged JVM in this owned PID. */
        exec_java(-1,0,-1,true);
    }
    own_child(c,p);
    int grouped=setpgid(p,p);
    if((grouped && errno!=EACCES) || getpgid(p)!=p) return fail("nested_group");
    c->private_group=true;
    if(c->fd<0) return -1; /* common cleanup retains PID even if pidfd_open failed */
    int rc=await_child(c,deadline);
    if(!rc) { event("reaped",exit_code(c->status),0); if(exit_code(c->status)!=0) rc=-1; }
    event("nested_probe",rc,0); return rc;
}
static int cleaner(struct channel outer) {
    role="A"; mounted=0; controller_fd=outer.fd;
    struct child_owner subject=CHILD("manifest-jvm"), nested=CHILD("nested-unshare-jvm");
    pid_t child=-1; int self_fd=-1, sockets[2]={-1,-1};
    int result=-1, cleanup=0;
    if(subreaper()) goto done;
    if(strcmp(scenario,"sensitivity") && (unshare(CLONE_NEWNS) || mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL))) goto done;
    if(pin_self(4)) goto done;
    int relation=same(handles[0],handles[4]);
    if(relation!=(strcmp(scenario,"sensitivity")==0) || same(handles[1],handles[5])!=1 || same(handles[2],handles[6])!=1 || same(handles[3],handles[7])!=1) goto done;
    event(relation?"namespace_equal":"namespace_distinct",0,0);
    if(inside_mutation() && make_bind()) goto done;
    if(send_frame(&outer,0,"A","READY") || receive(&outer,0,"O","VERSION")) goto done;
    if(pair(sockets) || (self_fd=pidfd(getpid()))<0) goto done;
    child=fork(); if(child<0) goto done;
    if(!child) { exec_java(sockets[1],getppid(),self_fd,false); }
    own_child(&subject,child);
    if(close(sockets[1])) goto done;
    sockets[1]=-1;
    if(subject.fd<0) goto done;
    struct channel j={sockets[0],child,0};
    if(send_frame(&j,0,"A","VERSION") || receive(&j,0,"J","READY")) goto done;
    if(!strcmp(scenario,"cancel-pre")) {
        if(send_frame(&j,1,"A","CANCEL") || receive(&j,1,"J","CANCELLED")) goto done;
        goto cancelled;
    }
    if(send_frame(&j,1,"A","BEGIN") || receive(&j,2,"J","AT_DESCRIPTOR")) goto done;
    if(!strcmp(scenario,"eof")) { shutdown(j.fd,SHUT_WR); goto expected_fault; }
    if(!strcmp(scenario,"death")) {
        if(syscall(SYS_pidfd_send_signal,subject.fd,SIGKILL,NULL,0)) goto done;
        event("injected_death",0,0); goto expected_fault;
    }
    if(!strcmp(scenario,"malformed") || !strcmp(scenario,"oversize") || !strcmp(scenario,"order")) {
        char bad[MAX_FRAME+1]; memset(bad,'x',sizeof bad);
        ssize_t size=!strcmp(scenario,"oversize")?sizeof bad:3;
        if(!strcmp(scenario,"order")) { if(send_frame(&j,19,"A","ACK")) goto done; }
        else if(send(j.fd,bad,(size_t)size,MSG_NOSIGNAL)!=size) goto done;
        event("injected_frame",0,0); goto expected_fault;
    }
    if(!strcmp(scenario,"cancel-descriptor")) {
        if(send_frame(&j,2,"A","CANCEL") || receive(&j,2,"J","CANCELLED")) goto done;
        goto cancelled;
    }
    if(inside_mutation()) {
        if(move_bind(false) || move_bind(true)) goto done;
    } else {
        if(send_frame(&outer,1,"A","MUTATE") || receive(&outer,1,"O","ACK")) goto done;
    }
    if(send_frame(&j,2,"A","ACK") || receive(&j,3,"J","OBSERVED")) goto done;
    if(send_frame(&outer,2,"A","RESTORE") || receive(&outer,2,"O","RESTORED")) goto done;
    if(!strcmp(scenario,"hostile") && release_mount()) goto done;
    if(!strcmp(scenario,"cancel-restore") || !strcmp(scenario,"cleanup-failure")) {
        if(send_frame(&j,3,"A","CANCEL") || receive(&j,3,"J","CANCELLED")) goto done;
        goto cancelled;
    }
    if(send_frame(&j,3,"A","RESTORED") || receive(&j,4,"J","CLOSE")) goto done;
    if(!strcmp(scenario,"cancel-close")) {
        if(send_frame(&j,4,"A","CANCEL") || receive(&j,4,"J","CANCELLED")) goto done;
        goto cancelled;
    }
    if(send_frame(&j,4,"A","CLOSED")) goto done;
    if(await_child(&subject,deadline)) goto done;
    event("reaped",exit_code(subject.status),0);
    if(exit_code(subject.status)!=0) goto done;
    if(!strcmp(scenario,"hostile") && nested_probe(&nested)) goto done;
    result=0; goto done;
expected_fault:
    /* A real failed Java process is required; no success inferred from injecting a fault. */
    if(await_child(&subject,deadline)) goto done;
    event("fault_subject_exit",exit_code(subject.status),0);
    if(exit_code(subject.status)==0) goto done;
    event("expected_fault_observed",0,0); result=2; goto done;
cancelled:
    if(await_child(&subject,deadline)) goto done;
    event("reaped",exit_code(subject.status),0);
    if(exit_code(subject.status)!=0) goto done;
    event("expected_cancel_observed",0,0); result=!strcmp(scenario,"cleanup-failure")?-1:2;
done:
    event("cleanup_begin",result,0);
    controller_fd=-1;
    int64_t end=cleanup_end();
    if(subject.pid>0 && !subject.reaped) {
        if(sockets[0]>=0) shutdown(sockets[0],SHUT_RDWR);
        /* Grace consumes at most half the remaining shared allowance. */
        int64_t grace=now_ms()+(end-now_ms())/2;
        if(subject.fd<0 || await_child(&subject,grace)) {
            int killed=terminate_child(&subject), waited=await_child(&subject,end);
            if(killed || waited) cleanup=-1;
            result=-1;
        }
    }
    if(nested.pid>0 && !nested.reaped) {
        int killed=terminate_child(&nested), waited=await_child(&nested,end);
        if(killed || waited) cleanup=-1;
        result=-1;
    }
    unsigned adopted=0; bool absent=false;
    if((subject.pid<=0 || subject.reaped) && (nested.pid<=0 || nested.reaped)) {
        absent=drain_descendants(end,&adopted)==0;
    }
    if(!absent) cleanup=-1;
    if(adopted) result=-1;
    int subject_disposed=dispose_child(&subject), nested_disposed=dispose_child(&nested);
    if(subject_disposed || nested_disposed) cleanup=-1;
    if(!strcmp(scenario,"cleanup-failure") && mounted) {
        int rc=umount2(mounted==1?"target":"moved",0x40000000), e=rc?errno:0;
        if(!rc) mounted=0;
        event("cleanup_fault_syscall",rc,e);
        result=-1; /* Preserve cleanup failure even if owned remediation below succeeds. */
    }
    if(release_mount() || bytes_are("target/marker","original\n")) cleanup=-1;
    for(int i=0;i<2;i++) if(sockets[i]>=0 && close(sockets[i])) cleanup=-1;
    if(self_fd>=0 && close(self_fd)) cleanup=-1;
    for(int i=0;i<8;i++) if(handles[i]>=0 && close(handles[i])) cleanup=-1;
    if(now_ms()>end) cleanup=-1;
    dprintf(1,"ACP_FIXTURE {\"role\":\"A\",\"event\":\"cleanup_ledger\",\"rc\":%d,\"errno\":0,\"mountsRemaining\":%d,\"childReaped\":%d,\"descendantsAbsent\":%d,\"adopted\":%u,\"cleanupDeadline\":%lld,\"operationDeadline\":%lld}\n",cleanup,mounted,subject.pid<=0 || subject.reaped,absent,adopted,(long long)end,(long long)deadline);
    event(cleanup?"cleanup_UNVERIFIED":"cleanup_VERIFIED",cleanup,0);
    if(!cleanup && send_frame(&outer,3,"A",result==0?"PASS":result==2?"EXPECTED_FAILURE":"FAIL")) result=-1;
    int control_close=close(outer.fd), close_errno=control_close?errno:0;
    event("control_closed",control_close,close_errno);
    if(control_close) { event("cleanup_UNVERIFIED",-1,close_errno); result=-1; }
    return cleanup || result<0 ? 1 : result;
}
int main(int argc,char **argv) {
    if(argc!=5) return 64;
    scenario=argv[1]; java_path=argv[3]; classpath=argv[4];
    const char *allowed[]={"external","sensitivity","hostile","eof","death","malformed","oversize","order","cancel-pre","cancel-descriptor","cancel-restore","cancel-close","restore-failure","cleanup-failure"};
    bool known=false; for(size_t i=0;i<sizeof allowed/sizeof *allowed;i++) if(!strcmp(scenario,allowed[i])) known=true;
    if(!known || geteuid()!=0 || getegid()!=0) return 64;
    for(int i=0;i<8;i++) handles[i]=-1;
    /* Require a one-entry rootless mapping; no host-root/production interpretation. */
    FILE *map=fopen("/proc/self/uid_map","r"); unsigned long in,out,count; char extra;
    if(!map || fscanf(map,"%lu %lu %lu %c",&in,&out,&count,&extra)!=3 || in!=0 || out==0 || count!=1) return 65;
    if(fclose(map)) return 65;
    char cwd[PATH_MAX],base[PATH_MAX],prefix[PATH_MAX]; struct stat st;
    if(!getcwd(cwd,sizeof cwd) || !realpath(argv[2],base) || snprintf(prefix,sizeof prefix,"%s/build/acp-isolation-fixture/",cwd)>=(int)sizeof prefix ||
       strncmp(base,prefix,strlen(prefix)) || lstat(base,&st) || !S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&0777)!=0700 || chdir(base)) return 65;
    const char *dirs[]={"closure","target","injected","moved","tmp","home","nested"};
    for(size_t i=0;i<sizeof dirs/sizeof *dirs;i++) {
        if(lstat(dirs[i],&st) || !S_ISDIR(st.st_mode) || st.st_uid!=0 || (st.st_mode&0777)!=0700) return 65;
    }
    if(bytes_are("target/marker","original\n") || bytes_are("injected/marker","injected\n")) return 65;
    deadline=now_ms()+60000;
    cleanup_deadline=mmap(NULL,sizeof *cleanup_deadline,PROT_READ|PROT_WRITE,MAP_SHARED|MAP_ANONYMOUS,-1,0);
    if(cleanup_deadline==MAP_FAILED) return 66;
    atomic_init(cleanup_deadline,0);
    if(!atomic_is_lock_free(cleanup_deadline)) return 66;
    if(signal(SIGPIPE,SIG_IGN)==SIG_ERR || signal(SIGCHLD,SIG_DFL)==SIG_ERR) return 66;
    if(subreaper()) return 66;
    if(mount(NULL,"/",NULL,MS_REC|MS_PRIVATE,NULL) || pin_self(0)) return 66;
    event("synthetic_rootless_O",0,0);
    int observer=open_handle("/proc/self/mountinfo"),sockets[2];
    if(observer<0 || read_observer(observer) || pair(sockets)) return 66;
    pid_t child=fork(); if(child<0) return 66;
    if(!child) { close(sockets[0]); close(observer); struct channel c={sockets[1],getppid(),0}; _exit(cleaner(c)); }
    struct child_owner cleaner_child=CHILD("cleaner"); own_child(&cleaner_child,child);
    close(sockets[1]); int ans=-1,aroot=-1;
    struct channel a={sockets[0],child,0}; int result=1,cleanup=0;
    if(cleaner_child.fd<0 || receive(&a,0,"A","READY")) goto done;
    char proc[64]; snprintf(proc,sizeof proc,"/proc/%d/ns/mnt",child); ans=open_handle(proc);
    snprintf(proc,sizeof proc,"/proc/%d/root",child); aroot=open_handle(proc);
    if(ans<0 || aroot<0 || same(handles[0],ans)!=(strcmp(scenario,"sensitivity")==0) || same(handles[1],aroot)!=1) goto done;
    if(send_frame(&a,0,"O","VERSION")) goto done;
    bool early=!strcmp(scenario,"cancel-pre") || !strcmp(scenario,"cancel-descriptor") || !strcmp(scenario,"eof") || !strcmp(scenario,"death") || !strcmp(scenario,"malformed") || !strcmp(scenario,"oversize") || !strcmp(scenario,"order");
    if(!early) {
        if(!inside_mutation()) {
            if(receive(&a,1,"A","MUTATE") || make_bind() || bytes_are("target/marker","injected\n") || outer_event(observer) || send_frame(&a,1,"O","ACK")) goto done;
        }
        if(receive(&a,2,"A","RESTORE")) goto done;
        if(!strcmp(scenario,"restore-failure")) {
            int rc=umount2("target",0x40000000), e=rc?errno:0;
            if(!rc) mounted=0;
            event("restore_fault_syscall",rc,e); goto done;
        }
        if(release_mount() || bytes_are("target/marker","original\n") || send_frame(&a,2,"O","RESTORED")) goto done;
    }
    const bool expected=early || !strcmp(scenario,"cancel-restore") || !strcmp(scenario,"cancel-close");
    if(receive(&a,3,"A",!strcmp(scenario,"cleanup-failure")?"FAIL":expected?"EXPECTED_FAILURE":"PASS")) goto done;
    if(await_child(&cleaner_child,deadline)) goto done;
    event("reaped",exit_code(cleaner_child.status),0);
    if(!WIFEXITED(cleaner_child.status) || WEXITSTATUS(cleaner_child.status)!=(!strcmp(scenario,"cleanup-failure")?1:expected?2:0)) goto done;
    result=!strcmp(scenario,"cleanup-failure")?1:expected?2:0;
done:
    event("cleanup_begin",result,0);
    controller_fd=-1;
    int64_t end=cleanup_end();
    shutdown(a.fd,SHUT_RDWR);
    if(!cleaner_child.reaped) {
        int64_t grace=now_ms()+3*(end-now_ms())/4;
        if(cleaner_child.fd<0 || await_child(&cleaner_child,grace)) {
            (void)terminate_child(&cleaner_child);
            (void)await_child(&cleaner_child,end);
            cleanup=-1; /* killing A cannot prove its private mount cleanup */
        }
    }
    unsigned adopted=0;
    bool absent=cleaner_child.reaped && drain_descendants(end,&adopted)==0;
    int cleaner_disposed=dispose_child(&cleaner_child);
    if(!absent || adopted || cleaner_disposed) cleanup=-1;
    if(release_mount() || bytes_are("target/marker","original\n")) cleanup=-1;
    int owned[]={a.fd,ans,aroot,observer,handles[0],handles[1],handles[2],handles[3]};
    for(size_t i=0;i<sizeof owned/sizeof *owned;i++) if(owned[i]>=0 && close(owned[i])) cleanup=-1;
    if(now_ms()>end) cleanup=-1;
    dprintf(1,"ACP_FIXTURE {\"role\":\"O\",\"event\":\"cleanup_ledger\",\"rc\":%d,\"errno\":0,\"mountsRemaining\":%d,\"childReaped\":%d,\"descendantsAbsent\":%d,\"adopted\":%u,\"cleanupDeadline\":%lld,\"operationDeadline\":%lld}\n",cleanup,mounted,cleaner_child.reaped,absent,adopted,(long long)end,(long long)deadline);
    if(munmap(cleanup_deadline,sizeof *cleanup_deadline)) cleanup=-1;
    event(cleanup?"cleanup_UNVERIFIED":"cleanup_VERIFIED",cleanup,0);
    event("result",cleanup?1:result,0);
    return cleanup?1:result;
}
