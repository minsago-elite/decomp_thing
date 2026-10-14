#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/utsname.h>
#include <unistd.h>

#define REPORT_MAGIC UINT32_C(0x53544752)
#define OPENING UINT32_C(0x4f50454e)
#define CREATED UINT32_C(0x43524541)
#define COMPLETE UINT32_C(0x434f4d50)
#define MODEL_MAGIC UINT32_C(0x4d4f444c)
#define MODEL_END UINT32_C(0x454e444d)
#define MIB UINT64_C(1048576)
#define PAYLOAD_NAME "decomp-analysis-io-helper-payload-v1"

extern char **environ;

static void fail(void) {
    static const char message[] = "decomp-analysis-io-helper-v1: rejected\n";
    size_t offset = 0;
    while (offset < sizeof(message) - 1) {
        ssize_t n = write(STDERR_FILENO, message + offset, sizeof(message) - 1 - offset);
        if (n > 0) offset += (size_t)n;
        else if (n < 0 && errno == EINTR) continue;
        else break;
    }
    _exit(2);
}

static void write_all(int fd, const void *bytes, size_t count) {
    const unsigned char *p = bytes;
    while (count != 0) {
        ssize_t n = write(fd, p, count);
        if (n > 0) { p += n; count -= (size_t)n; }
        else if (n < 0 && errno == EINTR) continue;
        else fail();
    }
}

static void read_all(int fd, void *bytes, size_t count) {
    unsigned char *p = bytes;
    while (count != 0) {
        ssize_t n = read(fd, p, count);
        if (n > 0) { p += n; count -= (size_t)n; }
        else if (n < 0 && errno == EINTR) continue;
        else fail();
    }
}

static void require_eof(int fd) {
    unsigned char byte;
    ssize_t n;
    do { n = read(fd, &byte, 1); } while (n < 0 && errno == EINTR);
    if (n != 0) fail();
}

static uint32_t read_u32(int fd) {
    unsigned char b[4];
    read_all(fd, b, sizeof(b));
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | b[3];
}

static uint64_t read_u64(int fd) {
    uint32_t high = read_u32(fd);
    uint32_t low = read_u32(fd);
    return ((uint64_t)high << 32) | low;
}

static void write_u32(uint32_t value) {
    unsigned char b[4] = { (unsigned char)(value >> 24), (unsigned char)(value >> 16),
                          (unsigned char)(value >> 8), (unsigned char)value };
    write_all(STDOUT_FILENO, b, sizeof(b));
}

static void write_u64(uint64_t value) {
    write_u32((uint32_t)(value >> 32));
    write_u32((uint32_t)value);
}

/* Fixed-storage SHA-256; neither endpoint allocates an input-sized object. */
struct sha256 { uint32_t h[8]; uint64_t bytes; size_t used; unsigned char block[64]; };

static uint32_t rotate(uint32_t value, unsigned int bits) {
    return (value >> bits) | (value << (32U - bits));
}

static void sha_block(struct sha256 *s, const unsigned char *b) {
    static const uint32_t k[64] = {
        0x428a2f98U,0x71374491U,0xb5c0fbcfU,0xe9b5dba5U,0x3956c25bU,0x59f111f1U,0x923f82a4U,0xab1c5ed5U,
        0xd807aa98U,0x12835b01U,0x243185beU,0x550c7dc3U,0x72be5d74U,0x80deb1feU,0x9bdc06a7U,0xc19bf174U,
        0xe49b69c1U,0xefbe4786U,0x0fc19dc6U,0x240ca1ccU,0x2de92c6fU,0x4a7484aaU,0x5cb0a9dcU,0x76f988daU,
        0x983e5152U,0xa831c66dU,0xb00327c8U,0xbf597fc7U,0xc6e00bf3U,0xd5a79147U,0x06ca6351U,0x14292967U,
        0x27b70a85U,0x2e1b2138U,0x4d2c6dfcU,0x53380d13U,0x650a7354U,0x766a0abbU,0x81c2c92eU,0x92722c85U,
        0xa2bfe8a1U,0xa81a664bU,0xc24b8b70U,0xc76c51a3U,0xd192e819U,0xd6990624U,0xf40e3585U,0x106aa070U,
        0x19a4c116U,0x1e376c08U,0x2748774cU,0x34b0bcb5U,0x391c0cb3U,0x4ed8aa4aU,0x5b9cca4fU,0x682e6ff3U,
        0x748f82eeU,0x78a5636fU,0x84c87814U,0x8cc70208U,0x90befffaU,0xa4506cebU,0xbef9a3f7U,0xc67178f2U
    };
    uint32_t w[64], a=s->h[0], c=s->h[2], b0=s->h[1], d=s->h[3], e=s->h[4], f=s->h[5], g=s->h[6], h=s->h[7];
    size_t i;
    for (i=0; i<16; ++i) w[i]=((uint32_t)b[4*i]<<24)|((uint32_t)b[4*i+1]<<16)|((uint32_t)b[4*i+2]<<8)|b[4*i+3];
    for (i=16; i<64; ++i) {
        uint32_t x=w[i-15], y=w[i-2];
        w[i]=(rotate(x,7)^rotate(x,18)^(x>>3))+w[i-16]+(rotate(y,17)^rotate(y,19)^(y>>10))+w[i-7];
    }
    for (i=0; i<64; ++i) {
        uint32_t t1=h+(rotate(e,6)^rotate(e,11)^rotate(e,25))+((e&f)^((~e)&g))+k[i]+w[i];
        uint32_t t2=(rotate(a,2)^rotate(a,13)^rotate(a,22))+((a&b0)^(a&c)^(b0&c));
        h=g; g=f; f=e; e=d+t1; d=c; c=b0; b0=a; a=t1+t2;
    }
    s->h[0]+=a; s->h[1]+=b0; s->h[2]+=c; s->h[3]+=d;
    s->h[4]+=e; s->h[5]+=f; s->h[6]+=g; s->h[7]+=h;
}

static void sha_init(struct sha256 *s) {
    static const uint32_t initial[8]={0x6a09e667U,0xbb67ae85U,0x3c6ef372U,0xa54ff53aU,0x510e527fU,0x9b05688cU,0x1f83d9abU,0x5be0cd19U};
    memcpy(s->h,initial,sizeof(initial)); s->bytes=0; s->used=0;
}

static void sha_update(struct sha256 *s, const unsigned char *b, size_t count) {
    s->bytes += count;
    while (count != 0) {
        size_t n=64-s->used;
        if (n>count) n=count;
        memcpy(s->block+s->used,b,n); s->used+=n; b+=n; count-=n;
        if (s->used==64) { sha_block(s,s->block); s->used=0; }
    }
}

static void sha_finish(struct sha256 *s, unsigned char digest[32]) {
    uint64_t bits=s->bytes*8;
    size_t i;
    s->block[s->used++]=0x80;
    if (s->used>56) { memset(s->block+s->used,0,64-s->used); sha_block(s,s->block); s->used=0; }
    memset(s->block+s->used,0,56-s->used);
    for (i=0;i<8;++i) s->block[63-i]=(unsigned char)(bits>>(8*i));
    sha_block(s,s->block);
    for (i=0;i<32;++i) digest[i]=(unsigned char)(s->h[i/4]>>(24-8*(i%4)));
}

static uint64_t parse_number(const char *text, uint64_t minimum, uint64_t maximum) {
    uint64_t n=0;
    size_t i, length=strnlen(text,21);
    if (length==0 || length>20 || (length>1 && text[0]=='0')) fail();
    for (i=0;i<length;++i) {
        unsigned int digit;
        if (text[i]<'0' || text[i]>'9') fail();
        digit=(unsigned int)(text[i]-'0');
        if (n>(UINT64_MAX-digit)/10) fail();
        n=n*10+digit;
    }
    if (n<minimum || n>maximum) fail();
    return n;
}

static void require_host(void) {
#if defined(__linux__) && defined(__x86_64__) && !defined(__ILP32__)
    struct utsname host;
    if (sizeof(void *)!=8 || sizeof(long)!=8 || sizeof(rlim_t)!=8 ||
        uname(&host)!=0 || strcmp(host.sysname,"Linux")!=0 || strcmp(host.machine,"x86_64")!=0) fail();
#else
    fail();
#endif
}

static void require_limits(uint64_t bytes) {
    struct rlimit address, core;
    if (getrlimit(RLIMIT_AS,&address)!=0 || address.rlim_cur!=(rlim_t)bytes || address.rlim_max!=(rlim_t)bytes ||
        getrlimit(RLIMIT_CORE,&core)!=0 || core.rlim_cur!=0 || core.rlim_max!=0) fail();
}

static void disable_dumping(void) {
    if (prctl(PR_SET_DUMPABLE,0,0,0,0)!=0 || prctl(PR_GET_DUMPABLE,0,0,0,0)!=0) fail();
}

/* The architecture check rejects x32 syscall numbers as well as non-x86-64 ABIs. */
static void restrict_payload(void) {
#if defined(__linux__) && defined(__x86_64__) && !defined(__ILP32__)
#define DENY(number) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,(number),0,1), BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ERRNO|EPERM)
    struct sock_filter instructions[]={
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,arch)),
        BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K,AUDIT_ARCH_X86_64,1,0),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD|BPF_W|BPF_ABS,offsetof(struct seccomp_data,nr)),
        BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K,0x40000000U,0,1),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_KILL_PROCESS),
        DENY(SYS_fork), DENY(SYS_vfork), DENY(SYS_clone), DENY(SYS_clone3),
        DENY(SYS_execve), DENY(SYS_execveat), DENY(SYS_setrlimit), DENY(SYS_prlimit64),
        DENY(SYS_rename), DENY(SYS_renameat), DENY(SYS_renameat2),
        BPF_STMT(BPF_RET|BPF_K,SECCOMP_RET_ALLOW)
    };
    struct sock_fprog filter={ (unsigned short)(sizeof(instructions)/sizeof(instructions[0])),instructions };
    if (prctl(PR_SET_NO_NEW_PRIVS,1,0,0,0)!=0 || prctl(PR_GET_NO_NEW_PRIVS,0,0,0,0)!=1 ||
        prctl(PR_SET_SECCOMP,SECCOMP_MODE_FILTER,&filter)!=0) fail();
#undef DENY
#else
    fail();
#endif
}

static void require_path(const char *path, int report) {
    size_t length=strnlen(path,PATH_MAX);
    if (length<2 || length>=PATH_MAX || path[0]!='/') fail();
    if (report) {
        const char *base=strrchr(path,'/')+1;
        static const char prefix[]=".json-report-stage-";
        size_t i;
        if (strlen(base)!=sizeof(prefix)-1+36+4 || strncmp(base,prefix,sizeof(prefix)-1)!=0 ||
            strcmp(base+sizeof(prefix)-1+36,".tmp")!=0) fail();
        for (i=0;i<36;++i) {
            char c=base[sizeof(prefix)-1+i];
            if (i==8 || i==13 || i==18 || i==23) { if (c!='-') fail(); }
            else if (!((c>='0' && c<='9') || (c>='a' && c<='f'))) fail();
        }
    }
}

/* Prefixes retain the supplied host traversal, including symlinks followed by '..'. */
static void create_parents(const char *candidate) {
    char parent[PATH_MAX];
    char *p, *last;
    struct stat status;
    memcpy(parent,candidate,strlen(candidate)+1);
    last=strrchr(parent,'/');
    if (last==parent) return;
    *last='\0';
    for (p=parent+1;;++p) {
        char saved=*p;
        if (saved!='/' && saved!='\0') continue;
        *p='\0';
        if (mkdir(parent,0700)!=0 && errno!=EEXIST) fail();
        if (stat(parent,&status)!=0 || !S_ISDIR(status.st_mode)) fail();
        *p=saved;
        if (saved=='\0') break;
    }
}

static int same_model(const struct stat *a, const struct stat *b) {
    return S_ISREG(a->st_mode) && S_ISREG(b->st_mode) && a->st_dev==b->st_dev && a->st_ino==b->st_ino &&
        a->st_size==b->st_size && a->st_mtim.tv_sec==b->st_mtim.tv_sec && a->st_mtim.tv_nsec==b->st_mtim.tv_nsec;
}

static void stage_report(const char *candidate, uint64_t maximum) {
    unsigned char buffer[8192], actual[32], expected[32];
    uint64_t total=0;
    struct sha256 digest;
    struct stat status;
    char identity[256];
    int fd, identity_length;
    if (read_u32(STDIN_FILENO)!=REPORT_MAGIC || read_u32(STDIN_FILENO)!=1) fail();
    write_u32(REPORT_MAGIC); write_u32(1); write_u32(OPENING);
    create_parents(candidate);
    fd=open(candidate,O_WRONLY|O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK,0600);
    if (fd<0 || fstat(fd,&status)!=0 || !S_ISREG(status.st_mode) || (status.st_mode&0777)!=0600) fail();
    identity_length=snprintf(identity,sizeof(identity),"(dev=%" PRIx64 ",ino=%" PRId64 ")",
        (uint64_t)status.st_dev,(int64_t)(uint64_t)status.st_ino);
    if (identity_length<1 || (size_t)identity_length>=sizeof(identity)) fail();
    write_u32(CREATED); write_u32((uint32_t)identity_length); write_all(STDOUT_FILENO,identity,(size_t)identity_length);
    sha_init(&digest);
    for (;;) {
        uint32_t count=read_u32(STDIN_FILENO);
        if (count==0) break;
        if (count>sizeof(buffer) || (uint64_t)count>maximum-total) fail();
        read_all(STDIN_FILENO,buffer,count);
        write_all(fd,buffer,count); sha_update(&digest,buffer,count); total+=count;
    }
    if (total==0 || read_u64(STDIN_FILENO)!=total) fail();
    read_all(STDIN_FILENO,expected,sizeof(expected)); require_eof(STDIN_FILENO);
    sha_finish(&digest,actual);
    if (memcmp(actual,expected,sizeof(actual))!=0) fail();
    while (fsync(fd)!=0) { if (errno!=EINTR) fail(); }
    /* close is not retried: EINTR cannot establish successful descriptor closure. */
    if (close(fd)!=0) fail();
    write_u32(COMPLETE); write_u64(total); write_all(STDOUT_FILENO,actual,sizeof(actual));
}

static void read_model(const char *path, uint64_t maximum) {
    struct stat before, opened, after, named;
    struct sha256 digest;
    unsigned char buffer[65536], actual[32];
    uint64_t remaining;
    int fd;
    if (lstat(path,&before)!=0 || !S_ISREG(before.st_mode) || before.st_size<1 || (uint64_t)before.st_size>maximum) fail();
    fd=open(path,O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    if (fd<0 || fstat(fd,&opened)!=0 || !same_model(&before,&opened)) fail();
    write_u32(MODEL_MAGIC); write_u32(1); write_u64((uint64_t)before.st_size);
    sha_init(&digest); remaining=(uint64_t)before.st_size;
    while (remaining!=0) {
        size_t count=remaining>sizeof(buffer)?sizeof(buffer):(size_t)remaining;
        read_all(fd,buffer,count); sha_update(&digest,buffer,count); write_all(STDOUT_FILENO,buffer,count); remaining-=count;
    }
    require_eof(fd);
    if (fstat(fd,&after)!=0 || lstat(path,&named)!=0 || !same_model(&before,&after) || !same_model(&before,&named)) fail();
    if (close(fd)!=0) fail();
    sha_finish(&digest,actual);
    write_u32(MODEL_END); write_all(STDOUT_FILENO,actual,sizeof(actual));
}

int main(int argc, char **argv) {
    uint64_t maximum, limit;
    int report, self;
    require_host();
    if (argc<2) fail();
    report=strcmp(argv[1],"report")==0;
    if ((!report && strcmp(argv[1],"model")!=0) || argc!=(report?4:5)) fail();
    require_path(argv[2],report);
    maximum=parse_number(argv[3],1,(report?32:512)*MIB);
    limit=report?64*MIB:parse_number(argv[4],64*MIB,256*MIB);
    if (strcmp(argv[0],PAYLOAD_NAME)!=0) {
        struct rlimit address={ (rlim_t)limit,(rlim_t)limit };
        struct rlimit core={0,0};
        char *empty_environment[]={NULL};
        if (setrlimit(RLIMIT_CORE,&core)!=0 || setrlimit(RLIMIT_AS,&address)!=0) fail();
        disable_dumping();
        require_limits(limit);
        self=open("/proc/self/exe",O_RDONLY|O_CLOEXEC);
        if (self<0) fail();
        argv[0]=(char *)PAYLOAD_NAME;
        fexecve(self,argv,empty_environment);
        fail();
    }
    /* An exec can reset dumpability even though the exact resource limits survive. */
    disable_dumping();
    if (environ==NULL || environ[0]!=NULL) fail();
    require_limits(limit);
    if (signal(SIGPIPE,SIG_IGN)==SIG_ERR) fail();
    umask(077);
    restrict_payload();
    if (report) stage_report(argv[2],maximum);
    else read_model(argv[2],maximum);
    return 0;
}
