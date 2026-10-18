/* Qualification-only dumpable PID1 surrogate. Never a production worker recipe.
 * No proof writing, fake monitor mode, ptrace interference or native test bypass.
 * Host gate supplies private control3/report4/ack5, none mounted into sandbox.
 */
#include <errno.h>
#include <fcntl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sys/syscall.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static int byte(int fd,char value) {
    ssize_t n;
    do { n=write(fd,&value,1); } while (n<0 && errno==EINTR);
    return n==1 ? 0 : -1;
}
static long long clock_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_MONOTONIC,&t)<0) return -1;
    return (long long)t.tv_sec*1000 + t.tv_nsec/1000000;
}
static int request(char expected,long long deadline) {
    for (;;) {
        long long now=clock_ms();
        if (now<0 || now>=deadline) return -1;
        struct pollfd p={3,POLLIN,0};
        int n=poll(&p,1,(int)(deadline-now));
        if (n<0 && errno==EINTR) continue;
        if (n<=0 || !(p.revents&POLLIN)) return -1;
        char value;
        ssize_t size=read(3,&value,1);
        if (size<0 && (errno==EAGAIN || errno==EINTR)) continue;
        return size==1 && value==expected ? 0 : -1;
    }
}
int main(int argc,char **argv) {
    if (argc<5 || strcmp(argv[1],"--mode") ||
        (strcmp(argv[2],"release") && strcmp(argv[2],"hold") && strcmp(argv[2],"deny-trace")) ||
        strcmp(argv[3],"--") || strcmp(argv[4],"/_worker_exec_monitor") ||
        getpid()!=1 || prctl(PR_SET_DUMPABLE,1)<0 || prctl(PR_GET_DUMPABLE)!=1) return 125;
    /* Fixed fixture FD identities: alias7 and directory8 cannot be mistaken for
     * report4 closing. Even control3/ack5 must disappear before monitor releases. */
    if (dup2(4,7)!=7) return 125;
    int root=open("/",O_RDONLY|O_DIRECTORY|O_CLOEXEC);
    if (root<0) return 125;
    if (root!=8) { if (dup2(root,8)!=8) return 125; close(root); }
    if (fcntl(8,F_SETFD,FD_CLOEXEC)<0) return 125;
    pid_t monitor=fork();
    if (monitor<0) return 125;
    if (!monitor) {
        if (!strcmp(argv[2],"deny-trace")) {
            /* Qualification-only finite seccomp launcher: deny ptrace before
             * monitor exec, including its child's PTRACE_TRACEME. No fake proof. */
            struct sock_filter rules[]={
                BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
                BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,__NR_ptrace,0,1),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM),
                BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
            };
            struct sock_fprog program={(unsigned short)(sizeof(rules)/sizeof(rules[0])),rules};
            if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)<0 ||
                prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&program)<0) _exit(125);
        }
        execv(argv[4],argv+4); _exit(125);
    }
    long long begin=clock_ms();
    if (begin<0 || byte(5,'H')<0) goto failed;
    if (strcmp(argv[2],"hold")) {
        if (request('A',begin+750)<0 || close(4)<0 || byte(5,'A')<0 ||
            request('B',begin+900)<0) goto failed;
    } else {
        /* Deliberately hold all aliases/path/control handles past the fixed1s
         * barrier. No sleep-driven release can fake a successful barrier. */
        for (;;) {
            long long now=clock_ms();
            if (now<0) goto failed;
            if (now-begin>=1200) break;
            struct timespec delay={0,10000000};
            if (nanosleep(&delay,NULL)<0 && errno!=EINTR) goto failed;
        }
        if (close(4)<0) goto failed;
    }
    if (close(7)<0 || close(8)<0 || close(3)<0 || close(5)<0) goto failed;
    /* Thereafter only stdio + trusted wait: no reacquisition of report/path. */
    for (;;) {
        int status; pid_t got=waitpid(monitor,&status,0);
        if (got<0 && errno==EINTR) continue;
        if (got!=monitor) return 125;
        return WIFEXITED(status) && WEXITSTATUS(status)==0 ? 0 : 125;
    }
failed:
    (void)kill(monitor,SIGKILL);
    for (;;) {
        pid_t got=waitpid(monitor,NULL,0);
        if (got>=0 || errno!=EINTR) break;
    }
    return 125;
}
