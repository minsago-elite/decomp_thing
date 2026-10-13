package decompengine.analysis

import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Uses the actual static build artifact; no production helper mode or authority is injected. */
class AnalysisIoHelperNativeTest {
    @Test
    fun `real traced endpoint denies allocation process exec limit and publication syscalls`() = fixture { root ->
        val source = Files.writeString(root.resolve("native-kernel-controls.c"), NATIVE_KERNEL_CONTROLS)
        val launcher = root.resolve("native-kernel-controls")
        val compiler = Path.of(requireNotNull(System.getProperty("decompengine.analysis.io.testCompiler")) {
            "actual native analysis helper test compiler is not configured"
        }).toRealPath()
        val command = listOf(compiler.toString(), "-std=c11", "-O2", "-static", "-no-pie", "-Wall", "-Wextra",
            "-Werror", "-Wformat=2", "-Wl,--build-id=none", source.toString(), "-o", launcher.toString())
        val compile = testProcess(command, root, 30)
        assertEquals(0, compile.first, compile.second)
        val controls = testProcess(listOf(launcher.toString(), helper().toString(), root.toString()), root, 45)
        assertEquals(0, controls.first, controls.second)
        assertEquals("native-kernel-controls-v1: PASS denied=11 anonymous=2 warmed-shared=2 " +
            "core-zero=3 dumpable-zero=6 model-preio=2\n", controls.second)
    }

    @Test
    fun `report payload has exact kernel limits and cannot touch candidate before input`() = fixture { root ->
        val parent = root.resolve("not-created/child")
        val candidate = candidate(parent)
        withChild(listOf("report", candidate.toString(), "1024")) { child ->
            awaitPayload(child)
            assertKernelLimit(child, 64L * MIB)
            assertFalse(Files.exists(parent, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(candidate, LinkOption.NOFOLLOW_LINKS))
            val bytes = "{\"native\":true}\n".toByteArray()
            child.outputStream.use { it.write(reportFrame(bytes)) }
            val receipt = DataInputStream(child.inputStream)
            assertReportReceipt(receipt, candidate, bytes)
            assertSuccess(child)
        }
    }

    @Test
    fun `report creates private exact bytes with Java filesystem identity and preserves raw traversal`() = fixture { root ->
        val outer = Files.createDirectory(root.resolve("outer"))
        val target = Files.createDirectory(root.resolve("target"))
        val childDirectory = Files.createDirectory(target.resolve("child"))
        val link = Files.createSymbolicLink(outer.resolve("link"), childDirectory)
        for (parent in listOf(link.resolve(".."), Files.createSymbolicLink(root.resolve("parent-link"), target))) {
            val candidate = candidate(parent)
            val bytes = ByteArray(131_089) { ((it * 31 + 7) and 255).toByte() }
            withChild(listOf("report", candidate.toString(), bytes.size.toString())) { child ->
                child.outputStream.use { it.write(reportFrame(bytes)) }
                assertReportReceipt(DataInputStream(child.inputStream), candidate, bytes)
                assertSuccess(child)
            }
            assertTrue(Files.isSameFile(candidate, target.resolve(candidate.fileName)))
            assertFalse(Files.exists(outer.resolve(candidate.fileName), LinkOption.NOFOLLOW_LINKS))
            Files.delete(candidate)
        }
    }

    @Test
    fun `report rejects malformed terminal records chunks and create collisions without completion`() = fixture { root ->
        val bytes = "bounded report\n".toByteArray()
        val valid = reportFrame(bytes)
        val cases = listOf(
            "wrong-version" to valid.clone().also { it[7] = 2 },
            "too-large-chunk" to encoded { writeInt(STGR); writeInt(1); writeInt(8193) },
            "byte-allowance" to valid,
            "zero-content" to reportFrame(byteArrayOf()),
            "wrong-total" to valid.clone().also { it[it.size - 33] = (bytes.size + 1).toByte() },
            "wrong-digest" to valid.clone().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
            "trailing-byte" to (valid + byteArrayOf(1)),
            "truncated" to valid.copyOf(valid.size - 1),
        )
        for ((name, frame) in cases) {
            val parent = root.resolve(name)
            val candidate = candidate(parent)
            val allowance = if (name == "byte-allowance") bytes.size - 1 else 1024
            withChild(listOf("report", candidate.toString(), allowance.toString())) { child ->
                child.outputStream.use { it.write(frame) }
                val receipt = child.inputStream.readBytes()
                assertRejected(child)
                if (name == "wrong-version") {
                    assertTrue(receipt.isEmpty())
                    assertFalse(Files.exists(parent, LinkOption.NOFOLLOW_LINKS))
                } else {
                    val input = DataInputStream(receipt.inputStream())
                    assertEquals(STGR, input.readInt()); assertEquals(1, input.readInt()); assertEquals(OPEN, input.readInt())
                    assertEquals(CREA, input.readInt())
                    val key = input.readInt(); assertTrue(key in 1..256); input.skipNBytes(key.toLong())
                    assertEquals(-1, input.read(), "failed transfer must not issue a completion receipt")
                }
            }
        }
        for (symlink in listOf(false, true)) {
            val candidate = candidate(root)
            val original = "existing authority\n".toByteArray()
            val existing = if (symlink) root.resolve("symlink-target") else candidate
            Files.write(existing, original)
            if (symlink) Files.createSymbolicLink(candidate, existing)
            withChild(listOf("report", candidate.toString(), "1024")) { child ->
                child.outputStream.use { it.write(valid) }
                val receipt = DataInputStream(child.inputStream)
                assertEquals(STGR, receipt.readInt()); assertEquals(1, receipt.readInt()); assertEquals(OPEN, receipt.readInt())
                assertEquals(-1, receipt.read()); assertRejected(child)
            }
            assertContentEquals(original, Files.readAllBytes(existing))
            Files.delete(candidate)
        }
    }

    @Test
    fun `model streams exact bytes under selected hard address limit and authenticates footer`() = fixture { root ->
        val bytes = ByteArray(2 * 1024 * 1024 + 17) { ((it * 17 + 91) and 255).toByte() }
        val target = Files.createDirectory(root.resolve("physical"))
        val outer = Files.createDirectory(root.resolve("outer"))
        val nested = Files.createDirectory(target.resolve("nested"))
        val path = Files.write(target.resolve("model.json"), bytes)
        Files.write(outer.resolve("model.json"), "wrong lexical file".toByteArray())
        val rawPath = Files.createSymbolicLink(outer.resolve("link"), nested).resolve("../model.json")
        assertEquals(outer.resolve("model.json"), rawPath.normalize())
        assertTrue(Files.isSameFile(rawPath, path))
        val before = Files.readAttributes(path, "unix:dev,ino,size,lastModifiedTime")
        for (limit in listOf(64L * MIB, 256L * MIB)) {
            withChild(listOf("model", rawPath.toString(), bytes.size.toString(), limit.toString())) { child ->
                child.outputStream.close()
                val input = DataInputStream(child.inputStream)
                assertEquals(MODL, input.readInt()); assertEquals(1, input.readInt()); assertEquals(bytes.size.toLong(), input.readLong())
                awaitPayload(child)
                assertKernelLimit(child, limit)
                val actual = ByteArray(bytes.size); input.readFully(actual)
                assertContentEquals(bytes, actual)
                assertEquals(ENDM, input.readInt())
                val digest = ByteArray(32); input.readFully(digest)
                assertContentEquals(sha(bytes), digest); assertEquals(-1, input.read())
                assertSuccess(child)
            }
        }
        assertEquals(before, Files.readAttributes(path, "unix:dev,ino,size,lastModifiedTime"))
    }

    @Test
    fun `model refuses symlink empty special excessive and invalid budget inputs`() = fixture { root ->
        val ordinary = Files.write(root.resolve("ordinary"), byteArrayOf(1, 2, 3))
        val link = Files.createSymbolicLink(root.resolve("link"), ordinary)
        val empty = Files.createFile(root.resolve("empty"))
        val directory = Files.createDirectory(root.resolve("directory"))
        val commands = listOf(
            listOf("model", link.toString(), "3", (64L * MIB).toString()),
            listOf("model", empty.toString(), "3", (64L * MIB).toString()),
            listOf("model", directory.toString(), "3", (64L * MIB).toString()),
            listOf("model", ordinary.toString(), "2", (64L * MIB).toString()),
            listOf("model", ordinary.toString(), "3", (64L * MIB - 1).toString()),
            listOf("model", ordinary.toString(), "3", (256L * MIB + 1).toString()),
            listOf("model", ordinary.toString(), "03", (64L * MIB).toString()),
            listOf("report", root.resolve("public.json").toString(), "3"),
        )
        for (command in commands) withChild(command) { child ->
            child.outputStream.close()
            assertTrue(child.inputStream.readBytes().isEmpty())
            assertRejected(child)
        }
    }

    @Test
    fun `model mutation during actual pipe backpressure suppresses terminal authority`() = fixture { root ->
        val bytes = ByteArray(2 * 1024 * 1024) { 65 }
        val path = Files.write(root.resolve("changing-model"), bytes)
        withChild(listOf("model", path.toString(), bytes.size.toString(), (64L * MIB).toString())) { child ->
            child.outputStream.close()
            val input = DataInputStream(child.inputStream)
            assertEquals(MODL, input.readInt()); assertEquals(1, input.readInt()); assertEquals(bytes.size.toLong(), input.readLong())
            Files.write(path, bytes + byteArrayOf(1))
            val remaining = input.readBytes()
            assertTrue(remaining.size <= bytes.size, "a changed source must not receive its END digest footer")
            assertRejected(child)
        }
    }

    private fun assertReportReceipt(input: DataInputStream, candidate: Path, bytes: ByteArray) {
        assertEquals(STGR, input.readInt()); assertEquals(1, input.readInt()); assertEquals(OPEN, input.readInt())
        assertEquals(CREA, input.readInt())
        val keyLength = input.readInt(); assertTrue(keyLength in 1..256)
        val key = ByteArray(keyLength); input.readFully(key)
        assertEquals(Files.readAttributes(candidate, java.nio.file.attribute.BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS).fileKey().toString(), String(key, Charsets.US_ASCII))
        assertEquals(COMP, input.readInt()); assertEquals(bytes.size.toLong(), input.readLong())
        val digest = ByteArray(32); input.readFully(digest)
        assertContentEquals(sha(bytes), digest); assertEquals(-1, input.read())
        assertContentEquals(bytes, Files.readAllBytes(candidate))
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(candidate))
    }

    private fun awaitPayload(child: Process) {
        val inheritedFilters = filterCount(Files.readString(Path.of("/proc/self/status")))
        val cutoff = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (true) {
            assertTrue(child.isAlive, "native payload exited before observation")
            val status = Files.readString(Path.of("/proc/${child.pid()}/status"))
            val arguments = Files.readAllBytes(Path.of("/proc/${child.pid()}/cmdline"))
            val firstArgument = String(arguments.takeWhile { it != 0.toByte() }.toByteArray(), Charsets.US_ASCII)
            if (status.lineSequence().any { it.matches(Regex("NoNewPrivs:\\s+1")) } &&
                status.lineSequence().any { it.matches(Regex("Seccomp:\\s+2")) } &&
                filterCount(status) == inheritedFilters + 1 &&
                firstArgument == "decomp-analysis-io-helper-payload-v1") return
            assertTrue(System.nanoTime() < cutoff, "native payload did not install its kernel policy")
            Thread.sleep(5)
        }
    }

    private fun filterCount(status: String): Int = status.lineSequence()
        .single { it.startsWith("Seccomp_filters:") }.substringAfter(':').trim().toInt()

    private fun assertKernelLimit(child: Process, expected: Long) {
        val limits = Files.readString(Path.of("/proc/${child.pid()}/limits"))
        val fields = limits.lineSequence()
            .single { it.startsWith("Max address space") }.trim().split(Regex("\\s+"))
        assertEquals(expected.toString(), fields[3]); assertEquals(expected.toString(), fields[4])
        assertEquals("bytes", fields[5])
        val core = limits.lineSequence().single { it.startsWith("Max core file size") }.trim().split(Regex("\\s+"))
        assertEquals("0", core[4]); assertEquals("0", core[5]); assertEquals("bytes", core[6])
        assertEquals(1L, Files.list(Path.of("/proc/${child.pid()}/task")).use { it.count() }, "the endpoint owns one native task")
    }

    private fun testProcess(command: List<String>, root: Path, seconds: Long): Pair<Int, String> {
        val home = Files.createDirectory(root.resolve("test-home-${UUID.randomUUID()}"))
        val tmp = Files.createDirectory(root.resolve("test-tmp-${UUID.randomUUID()}"))
        val child = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true).apply {
            environment().clear()
            environment()["HOME"] = home.toString(); environment()["TMPDIR"] = tmp.toString()
            environment()["LC_ALL"] = "C"; environment()["PATH"] = "/usr/bin:/bin"
        }.start()
        val output = CompletableFuture.supplyAsync { child.inputStream.readNBytes(65_537) }
        try {
            assertTrue(child.waitFor(seconds, TimeUnit.SECONDS), "native test process did not settle")
            val bytes = output.get(5, TimeUnit.SECONDS)
            assertTrue(bytes.size <= 65_536, "native test diagnostics exceed their bound")
            return child.exitValue() to String(bytes, Charsets.US_ASCII)
        } finally {
            if (child.isAlive) child.destroyForcibly()
            assertTrue(child.waitFor(5, TimeUnit.SECONDS), "native test launcher remains alive")
        }
    }

    private fun assertSuccess(child: Process) {
        assertTrue(child.waitFor(5, TimeUnit.SECONDS)); assertEquals(0, child.exitValue())
        assertTrue(child.errorStream.readBytes().isEmpty())
    }

    private fun assertRejected(child: Process) {
        assertTrue(child.waitFor(5, TimeUnit.SECONDS)); assertEquals(2, child.exitValue())
        val diagnostic = child.errorStream.readBytes()
        assertTrue(diagnostic.size in 1..128)
        assertEquals("decomp-analysis-io-helper-v1: rejected\n", String(diagnostic, Charsets.US_ASCII))
    }

    private fun <T> withChild(arguments: List<String>, action: (Process) -> T): T {
        val child = ProcessBuilder(listOf(helper().toString()) + arguments).apply {
            environment().clear()
            // The bootstrap must erase inherited bindings before its own payload exec.
            environment()["DECOMP_ANALYSIS_UNTRUSTED_INHERITED"] = "must-not-reach-payload"
        }.start()
        val watchdog = CompletableFuture.runAsync {
            if (!child.waitFor(15, TimeUnit.SECONDS)) child.destroyForcibly()
        }
        try { return action(child) }
        finally {
            if (child.isAlive) child.destroyForcibly()
            assertTrue(child.waitFor(5, TimeUnit.SECONDS), "native child remains live")
            watchdog.get(5, TimeUnit.SECONDS)
        }
    }

    private fun fixture(action: (Path) -> Unit) {
        val owner = helper().parent.resolve("native-test-fixtures")
        Files.createDirectories(owner)
        val root = Files.createTempDirectory(owner, "endpoint-")
        try { action(root) }
        finally { Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private fun helper(): Path {
        val helper = Path.of(requireNotNull(System.getProperty("decompengine.analysis.io.testHelper")) {
            "actual native analysis helper test artifact is not configured"
        }).toAbsolutePath()
        require(Files.isRegularFile(helper, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(helper))
        return helper
    }

    private fun candidate(parent: Path) = parent.resolve(".json-report-stage-${UUID.randomUUID()}.tmp")
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
    private fun encoded(write: DataOutputStream.() -> Unit): ByteArray = ByteArrayOutputStream().also {
        DataOutputStream(it).use(write)
    }.toByteArray()
    private fun reportFrame(bytes: ByteArray): ByteArray = encoded {
        writeInt(STGR); writeInt(1)
        var offset = 0
        while (offset < bytes.size) {
            val count = minOf(8192, bytes.size - offset)
            writeInt(count); write(bytes, offset, count); offset += count
        }
        writeInt(0); writeLong(bytes.size.toLong()); write(sha(bytes))
    }

    companion object {
        private val NATIVE_KERNEL_CONTROLS = """
#define _GNU_SOURCE
#define _FILE_OFFSET_BITS 64
#include <errno.h>
#include <elf.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/ptrace.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t active=-1;
static int output_fd=-1, input_fd=-1, helper_fd=-1, warm_fd=-1;
static char proc_helper[128];
static unsigned int core_checks=0, dump_checks=0;

static void reap(void) {
    int status;
    if (active>0) {
        (void)kill(active,SIGKILL);
        for (;;) {
            pid_t got=waitpid(active,&status,0);
            if (got<0 && errno==EINTR) continue;
            if (got<0 || WIFEXITED(status) || WIFSIGNALED(status)) break;
            (void)ptrace(PTRACE_CONT,active,NULL,(void *)(uintptr_t)SIGKILL);
        }
        active=-1;
    }
    if (input_fd>=0) { (void)close(input_fd); input_fd=-1; }
    if (output_fd>=0) { (void)close(output_fd); output_fd=-1; }
}

static void fail(const char *detail) {
    fprintf(stderr,"native-kernel-controls-v1: %s\n",detail);
    reap(); exit(2);
}

static int wait_stopped(void) {
    int status;
    pid_t got;
    do { got=waitpid(active,&status,0); } while (got<0 && errno==EINTR);
    if (got==active && (WIFEXITED(status) || WIFSIGNALED(status))) { active=-1; fail("trace child terminated"); }
    if (got<0 && errno==ECHILD) active=-1;
    if (got<0 || got!=active || !WIFSTOPPED(status)) fail("trace child did not stop");
    return status;
}

static long trace(enum __ptrace_request request, void *address, void *data) {
    long result;
    errno=0; result=ptrace(request,active,address,data);
    if (result==-1 && errno!=0) { fprintf(stderr,"request=%d errno=%d\n",request,errno); fail("own-child ptrace failed"); }
    return result;
}

static void read_registers(struct user_regs_struct *regs) {
    (void)trace(PTRACE_GETREGS,NULL,regs);
}

static void check_limits(uint64_t expected) {
    struct rlimit address,core;
    if (prlimit(active,RLIMIT_AS,NULL,&address)!=0 || address.rlim_cur!=expected || address.rlim_max!=expected ||
        prlimit(active,RLIMIT_CORE,NULL,&core)!=0 || core.rlim_cur!=0 || core.rlim_max!=0) fail("exact hard limits unavailable");
    ++core_checks;
}

static void check_empty_environment(void) {
    char path[128],byte;
    int fd;
    if (snprintf(path,sizeof(path),"/proc/%ld/environ",(long)active)<1) fail("environment path");
    fd=open(path,O_RDONLY|O_CLOEXEC);
    if (fd<0 || read(fd,&byte,1)!=0 || close(fd)!=0) fail("payload environment is not empty at exec-stop");
}

/* Dumpable0 deliberately denies PEEKTEXT. ET_EXEC lets the tracer inspect the
 * same syscall instruction through its retained immutable artifact descriptor. */
static void require_syscall_instruction(uint64_t address) {
    Elf64_Ehdr header;
    Elf64_Phdr segment;
    unsigned int i;
    unsigned char opcode[2];
    if (pread(helper_fd,&header,sizeof(header),0)!=(ssize_t)sizeof(header) ||
        memcmp(header.e_ident,ELFMAG,SELFMAG)!=0 || header.e_ident[EI_CLASS]!=ELFCLASS64 ||
        header.e_ident[EI_DATA]!=ELFDATA2LSB || header.e_type!=ET_EXEC || header.e_machine!=EM_X86_64 ||
        header.e_phentsize!=sizeof(segment) || header.e_phnum<1 || header.e_phnum>128) fail("fixed ET_EXEC artifact");
    for (i=0;i<header.e_phnum;++i) {
        if (pread(helper_fd,&segment,sizeof(segment),(off_t)(header.e_phoff+i*sizeof(segment)))!=(ssize_t)sizeof(segment)) fail("ELF program header");
        if (segment.p_type==PT_LOAD && (segment.p_flags&PF_X)!=0 && segment.p_filesz>=2 &&
            address>=segment.p_vaddr && address-segment.p_vaddr<=segment.p_filesz-2) {
            if (pread(helper_fd,opcode,2,(off_t)(segment.p_offset+address-segment.p_vaddr))!=2 ||
                opcode[0]!=0x0f || opcode[1]!=0x05) fail("actual fixed x86 syscall instruction");
            return;
        }
    }
    fail("syscall address is outside the artifact executable segment");
}

static void start_child(const char *mode,const char *path,uint64_t limit,int inherited_warm) {
    int input[2],output[2];
    char limit_text[32];
    pid_t parent=getpid();
    if (pipe(input)!=0 || pipe(output)!=0 || snprintf(limit_text,sizeof(limit_text),"%llu",(unsigned long long)limit)<1) fail("child pipes");
    active=fork();
    if (active<0) fail("external test fork");
    if (active==0) {
        char *args[]={proc_helper,(char *)mode,(char *)path,"1024",limit_text,NULL};
        char *env[]={"DECOMP_ANALYSIS_UNTRUSTED_INHERITED=bootstrap-only",NULL};
        if (prctl(PR_SET_PDEATHSIG,SIGKILL,0,0,0)!=0 || getppid()!=parent ||
            dup2(input[0],STDIN_FILENO)<0 || dup2(output[1],STDOUT_FILENO)<0 || dup2(output[1],STDERR_FILENO)<0) _exit(121);
        (void)close(input[0]); (void)close(input[1]); (void)close(output[0]); (void)close(output[1]);
        if (inherited_warm && dup2(warm_fd,99)<0) _exit(122);
        (void)close(warm_fd);
        if (strcmp(mode,"report")==0) args[4]=NULL;
        if (ptrace(PTRACE_TRACEME,0,NULL,NULL)!=0) _exit(123);
        execve(proc_helper,args,env); _exit(124);
    }
    (void)close(input[0]); (void)close(output[1]); input_fd=input[1]; output_fd=output[0];
    if (WSTOPSIG(wait_stopped())!=SIGTRAP) fail("initial helper exec-stop");
    (void)trace(PTRACE_SETOPTIONS,NULL,(void *)(uintptr_t)(PTRACE_O_TRACEEXEC|PTRACE_O_TRACESYSGOOD));
}

static struct user_regs_struct before_io(const char *mode,uint64_t limit) {
    unsigned int stage=0, dumps[2]={0,0}, policy=0, steps;
    struct user_regs_struct regs;
    for (steps=0;steps<20000;++steps) {
        int status;
        (void)trace(PTRACE_SYSCALL,NULL,NULL); status=wait_stopped();
        if ((unsigned int)status>>16==PTRACE_EVENT_EXEC) {
            if (stage!=0 || dumps[0]!=1) fail("bootstrap dumpability or self-exec contract");
            stage=1; check_limits(limit); check_empty_environment();
            continue;
        }
        if (WSTOPSIG(status)!=(SIGTRAP|0x80)) fail("unexpected trace signal");
        read_registers(&regs);
        if (regs.orig_rax==SYS_prctl && regs.rdi==PR_GET_DUMPABLE && regs.rax==0) ++dumps[stage];
        if (stage==1 && regs.orig_rax==SYS_prctl && regs.rdi==PR_SET_SECCOMP && regs.rax==0) policy=1;
        if (stage==1 && policy==1 && regs.rax==(uint64_t)-(int64_t)ENOSYS &&
            ((strcmp(mode,"report")==0 && regs.orig_rax==SYS_read && regs.rdi==STDIN_FILENO) ||
             (strcmp(mode,"model")==0 && regs.orig_rax==SYS_newfstatat && (int)regs.rdi==AT_FDCWD && regs.r10==AT_SYMLINK_NOFOLLOW))) {
            if (dumps[1]!=1) fail("payload dumpability readback before I/O");
            dump_checks+=dumps[0]+dumps[1];
            return regs;
        }
    }
    fail("bounded trace did not reach first untrusted I/O");
    return regs;
}

static int64_t inject(const struct user_regs_struct *saved,long number,uint64_t a,uint64_t b,uint64_t c,uint64_t d,uint64_t e,uint64_t f) {
    struct user_regs_struct regs=*saved;
    require_syscall_instruction(regs.rip-2);
    regs.rip-=2; regs.rax=(uint64_t)number; regs.orig_rax=UINT64_MAX;
    regs.rdi=a; regs.rsi=b; regs.rdx=c; regs.r10=d; regs.r8=e; regs.r9=f;
    (void)trace(PTRACE_SETREGS,NULL,&regs); (void)trace(PTRACE_SINGLESTEP,NULL,NULL);
    if (WSTOPSIG(wait_stopped())!=SIGTRAP) fail("injected syscall did not stop");
    read_registers(&regs); return (int64_t)regs.rax;
}

static void report_controls(const char *candidate) {
    struct user_regs_struct saved;
    static const long denied[]={SYS_fork,SYS_vfork,SYS_clone,SYS_clone3,SYS_execve,SYS_execveat,SYS_setrlimit,SYS_prlimit64,SYS_rename,SYS_renameat,SYS_renameat2};
    size_t i;
    int64_t allocated;
    start_child("report",candidate,64ULL*1024*1024,1);
    saved=before_io("report",64ULL*1024*1024);
    if (access(candidate,F_OK)==0) fail("candidate exists before protocol input");
    /* Replace the intercepted read with allowed getpid; negative syscall numbers
     * are correctly rejected by the payload architecture filter. */
    saved.orig_rax=SYS_getpid; (void)trace(PTRACE_SETREGS,NULL,&saved);
    (void)trace(PTRACE_SYSCALL,NULL,NULL);
    if (WSTOPSIG(wait_stopped())!=(SIGTRAP|0x80)) fail("skipped read exit-stop");
    read_registers(&saved);
    if (inject(&saved,SYS_prctl,PR_GET_DUMPABLE,0,0,0,0,0)!=0) fail("parked payload dumpability");
    for (i=0;i<sizeof(denied)/sizeof(denied[0]);++i) {
        if (inject(&saved,denied[i],0,0,0,0,0,0)!=-EPERM) fail("forbidden payload syscall was not denied");
    }
    if (inject(&saved,SYS_mmap,0,128ULL*1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0)!=-ENOMEM) fail("anonymous allocation bypassed hard address cap");
    allocated=inject(&saved,SYS_mmap,0,4096,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,UINT64_MAX,0);
    if (allocated<=0 || inject(&saved,SYS_munmap,(uint64_t)allocated,4096,0,0,0,0)!=0) fail("small anonymous allocation positive control");
    if (inject(&saved,SYS_mmap,0,128ULL*1024*1024,PROT_READ,MAP_SHARED,99,0)!=-ENOMEM) fail("warmed shared mapping bypassed hard address cap");
    allocated=inject(&saved,SYS_mmap,0,4096,PROT_READ,MAP_SHARED,99,0);
    if (allocated<=0 || inject(&saved,SYS_munmap,(uint64_t)allocated,4096,0,0,0,0)!=0) fail("small warmed shared mapping positive control");
    reap();
}

static void model_control(const char *model,uint64_t limit) {
    unsigned char bytes[128];
    size_t total=0;
    int status,fd;
    start_child("model",model,limit,0);
    (void)before_io("model",limit);
    (void)trace(PTRACE_DETACH,NULL,NULL);
    (void)close(input_fd); input_fd=-1;
    for (;;) {
        ssize_t n=read(output_fd,bytes+total,sizeof(bytes)-total);
        if (n>0) { total+=(size_t)n; if (total==sizeof(bytes)) fail("model frame exceeded test bound"); }
        else if (n==0) break;
        else if (errno!=EINTR) fail("model output read");
    }
    do { fd=waitpid(active,&status,0); } while (fd<0 && errno==EINTR);
    if (fd==active && (WIFEXITED(status) || WIFSIGNALED(status))) active=-1;
    else if (fd<0 && errno==ECHILD) active=-1;
    if (fd<0 || !WIFEXITED(status) || WEXITSTATUS(status)!=0) fail("normal model protocol after trace");
    (void)close(output_fd); output_fd=-1;
    if (total!=55 || memcmp(bytes,"MODL\0\0\0\1\0\0\0\0\0\0\0\3{}\nENDM",23)!=0) fail("normal model frame after pre-I/O trace");
}

int main(int argc,char **argv) {
    char candidate[PATH_MAX], model[PATH_MAX], warm[PATH_MAX];
    unsigned char *mapping;
    size_t i;
    int fd;
    if (argc!=3 || snprintf(candidate,sizeof(candidate),"%s/.json-report-stage-01234567-89ab-cdef-0123-456789abcdef.tmp",argv[2])<1 ||
        snprintf(model,sizeof(model),"%s/preio-model.json",argv[2])<1 || snprintf(warm,sizeof(warm),"%s/warmed-shared.bin",argv[2])<1) fail("external test arguments");
    helper_fd=open(argv[1],O_RDONLY|O_CLOEXEC);
    if (helper_fd<0 || snprintf(proc_helper,sizeof(proc_helper),"/proc/%ld/fd/%d",(long)getpid(),helper_fd)<1) fail("verified artifact descriptor path");
    fd=open(model,O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC,0600);
    if (fd<0 || write(fd,"{}\n",3)!=3 || close(fd)!=0) fail("model fixture");
    warm_fd=open(warm,O_RDWR|O_CREAT|O_EXCL,0600);
    if (warm_fd<0 || ftruncate(warm_fd,128LL*1024*1024)!=0) fail("shared mapping fixture");
    mapping=mmap(NULL,128ULL*1024*1024,PROT_READ|PROT_WRITE,MAP_SHARED,warm_fd,0);
    if (mapping==MAP_FAILED) fail("external warm mapping");
    for (i=0;i<128ULL*1024*1024;i+=4096) mapping[i]=1;
    report_controls(candidate);
    model_control(model,64ULL*1024*1024); model_control(model,256ULL*1024*1024);
    if (core_checks!=3 || dump_checks!=6 || munmap(mapping,128ULL*1024*1024)!=0 || close(warm_fd)!=0 || close(helper_fd)!=0) fail("final native control accounting");
    puts("native-kernel-controls-v1: PASS denied=11 anonymous=2 warmed-shared=2 core-zero=3 dumpable-zero=6 model-preio=2");
    return 0;
}
""".trimIndent()
        private const val MIB = 1024L * 1024
        private const val STGR = 0x53544752
        private const val OPEN = 0x4f50454e
        private const val CREA = 0x43524541
        private const val COMP = 0x434f4d50
        private const val MODL = 0x4d4f444c
        private const val ENDM = 0x454e444d
    }
}
