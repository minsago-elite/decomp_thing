package decompengine.project

import decompengine.oracle.fulltree.OracleNativeLibraries
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Real child/process fixtures, deliberately without a keeper receipt or acceptance authority. */
class ContainedModuleCompilerWorkerTest {
    @Test
    fun `real native compiler produces exact profile bound ET_REL observation for built ins and budget variants`() = withRoot { root ->
        val profiles = ReconstructionProfiles.builtIn.flatMap { base -> listOf(base,
            ReconstructionProfile(base.schemaVersion, base.id, base.layout,
                base.budgets.copy(buildWallClockMillis = 12_345, buildMaximumOutputBytes = 65536,
                    reconstructionMaximumContextCharacters = 4096), base.adapterConfiguration)) }
        for ((index, profile) in profiles.withIndex()) {
            val fixture = fixture(root.resolve("profile-$index"), profile = profile)
            val execution = launch(fixture)
            assertEquals(0, execution.exitCode, execution.stderr)
            val result = ContainedModuleCompilerResult.parse(execution.stdout)
            result.requireBinding(fixture.request)
            assertEquals("compiled-object", result.outcome)
            assertEquals(0, result.exitCode)
            assertEquals(null, result.signal)
            val objectBytes = Files.readAllBytes(fixture.request.outputDirectory.resolve("module.o"))
            assertEquals(result.objectBytes, objectBytes.size.toLong())
            assertEquals(result.objectSha256, sha256(objectBytes))
            assertEquals("relocatable", decompengine.binary.ElfMetadataReader.read(objectBytes).objectType)
            verifyLogs(fixture, result)
        }
    }

    @Test
    fun `compiler executes the exact request path while retaining its digest binding`() = withRoot { root ->
        val compiler = script(root.resolve("compiler"), "printf '%s' \"\$0\"; exit 0")
        val fixture = fixture(root.resolve("run"), compiler = compiler)
        val execution = launch(fixture)
        assertEquals(0, execution.exitCode, execution.stderr)
        val result = ContainedModuleCompilerResult.parse(execution.stdout)
        result.requireBinding(fixture.request)
        assertEquals("object-invalid", result.outcome,
            "exit=${result.exitCode}, compiler stderr=${Files.readString(fixture.request.outputDirectory.resolve("compiler.stderr"))}")
        val privateCompiler = fixture.request.compilerPath
        assertEquals(privateCompiler.toString(), Files.readString(fixture.request.outputDirectory.resolve("compiler.stdout")))
        assertEquals(fixture.request.compilerSha256, sha256(Files.readAllBytes(privateCompiler)))
        assertEquals(Files.getAttribute(fixture.request.outputDirectory, "unix:uid"), Files.getAttribute(privateCompiler, "unix:uid"))
        assertEquals(PosixFilePermissions.fromString("r-x------"), Files.getPosixFilePermissions(privateCompiler))
        assertEquals(1, Files.getAttribute(privateCompiler, "unix:nlink"))
        verifyLogs(fixture, result)
    }

    @Test
    fun `direct worker refuses transient source or transitive header includes before compiler launch`() = withRoot { root ->
        val cases = listOf(
            "#include \"/tmp/transient-reports.h\"\nint alpha(void) { return 1; }" to "int alpha(void);\n",
            "#include \"modules/alpha.h\"\nint alpha(void) { return 1; }" to
                "#ifndef ALPHA_H\n#define ALPHA_H\n#include \"/tmp/transient-tmp.h\"\n#endif\n",
        )
        for ((index, pair) in cases.withIndex()) {
            val (source, header) = pair
            val marker = root.resolve("compiler-launched-$index")
            val compiler = script(root.resolve("compiler-$index"), "printf launched > '$marker'; exit 0")
            val fixture = fixture(root.resolve("fixture-$index"), compiler = compiler, source = source,
                headerSource = header)
            val execution = launch(fixture)
            assertTrue(execution.exitCode != 0)
            assertTrue(execution.stderr.contains("generated-C source policy"), execution.stderr)
            assertTrue(execution.stdout.isEmpty())
            assertFalse(Files.exists(marker), "compiler started before direct-worker source policy refusal")
            assertFalse(Files.exists(fixture.request.outputDirectory.resolve("tmp")))
        }
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `host root compiler is materialized without trusting its foreign namespace owner`() = withRoot { root ->
        val compiler = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
        assertEquals(0, Files.getAttribute(compiler, "unix:uid"), "this regression requires the installed root-owned compiler")
        for ((index, profile) in ReconstructionProfiles.builtIn.withIndex()) {
            // As in deployment, put cc1/as beside the compiler. Overlay only the compiler
            // with the actual host-root inode in the namespace; no privileged chown is needed.
            val fixture = fixture(root.resolve("profile-$index"), profile = profile)
            val execution = launch(fixture, rootCompiler = compiler)
            assertEquals(0, execution.exitCode, execution.stderr)
            val result = ContainedModuleCompilerResult.parse(execution.stdout)
            result.requireBinding(fixture.request)
            assertEquals("compiled-object", result.outcome, Files.readString(fixture.request.outputDirectory.resolve("compiler.stderr")))
            val copy = fixture.root.resolve("owned-compiler")
            assertEquals(fixture.request.compilerSha256, sha256(Files.readAllBytes(copy)))
            assertEquals(Files.getAttribute(fixture.request.outputDirectory, "unix:uid"), Files.getAttribute(copy, "unix:uid"))
            assertEquals(0, Files.getAttribute(compiler, "unix:uid"), "materialization must not change the installed compiler")
            val identity = Files.readString(fixture.root.resolve("namespace-identity"))
            assertEquals("65534", identity.lineSequence().first(), "host root must actually be unmapped in this regression")
            assertEquals(Files.getAttribute(fixture.request.outputDirectory, "unix:uid").toString(), identity.lineSequence().drop(1).first(),
                "the pinned runtime path must expose only the controller-owned executable snapshot")
            assertEquals(PosixFilePermissions.fromString("r-x------"), Files.getPosixFilePermissions(copy))
            println("root-owned compiler namespace regression ${profile.id}: sha256=${fixture.request.compilerSha256}\n$identity")
            verifyLogs(fixture, result)

            val unaliased = fixture(root.resolve("unaliased-$index"), profile = profile)
            val foreignRefused = launch(unaliased, rootCompiler = compiler, useExecutableAlias = false)
            assertTrue(foreignRefused.exitCode != 0, "unmapped foreign compiler was trusted without the owned handoff")
            assertTrue(foreignRefused.stderr.contains("unsupported foreign non-root owner"), foreignRefused.stderr)
            assertTrue(foreignRefused.stdout.isEmpty())

            val substituted = fixture(root.resolve("substituted-$index"), profile = profile)
            val foreignSubstitute = Path.of("/usr/bin/true").toRealPath()
            assertEquals(0, Files.getAttribute(foreignSubstitute, "unix:uid"))
            val refused = launch(substituted, rootCompiler = foreignSubstitute)
            assertTrue(refused.exitCode != 0, "foreign runtime substitution reached compiler execution")
            assertTrue(refused.stderr.contains("module compiler executable digest differs"), refused.stderr)
            assertTrue(refused.stdout.isEmpty())
            assertFalse(Files.exists(substituted.request.outputDirectory.resolve("module.o")))
        }
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `host executable handoff compiles while output remains noexec under a different uid map`() = withRoot { root ->
        val compiler = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
        for ((index, profile) in ReconstructionProfiles.builtIn.withIndex()) {
            val fixture = fixture(root.resolve("noexec-$index"), profile = profile)
            val execution = launch(fixture, rootCompiler = compiler, noexecOutput = true)
            assertEquals(0, execution.exitCode, execution.stderr)
            val result = ContainedModuleCompilerResult.parse(execution.stdout)
            result.requireBinding(fixture.request)
            assertEquals("compiled-object", result.outcome)
            val identity = Files.readString(fixture.root.resolve("namespace-identity"))
            assertEquals("65534", identity.lineSequence().first())
            assertEquals("0", identity.lineSequence().drop(1).first(), "outer namespace must exercise a different UID map")
            assertTrue(Files.readString(fixture.root.resolve("output-mount-options")).split(',').any { it.trim() == "noexec" })
            println("noexec output compiler regression ${profile.id}: $identity")
            verifyLogs(fixture, result)
        }
    }

    @Test
    fun `compiler rejection records real exit and diagnostic bytes without an object identity`() = withRoot { root ->
        val fixture = fixture(root, source = "#include \"modules/alpha.h\"\nint alpha(void) { return missing; }\n")
        val execution = launch(fixture)
        assertEquals(0, execution.exitCode, execution.stderr)
        val result = ContainedModuleCompilerResult.parse(execution.stdout)
        result.requireBinding(fixture.request)
        assertEquals("compiler-failed", result.outcome)
        assertTrue(requireNotNull(result.exitCode) != 0)
        assertTrue(result.stderrBytes > 0)
        assertEquals(null, result.objectSha256)
        assertEquals(null, result.objectBytes)
        verifyLogs(fixture, result)
    }

    @Test
    fun `native signal timeout output overflow and missing object remain distinct failures`() = withRoot { root ->
        val scripts = listOf(
            Triple("signal", "kill -TERM \$\$", "compiler-signaled"),
            Triple("timeout", "exec /usr/bin/sleep 2", "timed-out"),
            Triple("overflow", "while :; do printf 0123456789; done", "output-limit-exceeded"),
            Triple("no-object", "exit 0", "object-invalid"),
        )
        for ((name, body, expected) in scripts) {
            val parent = Files.createDirectory(root.resolve(name))
            val compiler = script(parent.resolve("compiler"), body)
            val fixture = fixture(parent.resolve("run"), compiler = compiler,
                maximumWallMillis = if (name == "timeout") 100 else 3000, maximumOutputBytes = 128)
            val execution = launch(fixture)
            assertEquals(0, execution.exitCode, execution.stderr)
            val result = ContainedModuleCompilerResult.parse(execution.stdout)
            result.requireBinding(fixture.request)
            assertEquals(expected, result.outcome,
                "$name exit=${result.exitCode}, compiler stderr=${Files.readString(fixture.request.outputDirectory.resolve("compiler.stderr"))}")
            assertEquals(null, result.objectSha256)
            if (name == "signal") {
                assertEquals(15, result.signal)
                assertEquals(null, result.exitCode)
            }
            if (name in setOf("timeout", "overflow")) {
                assertEquals(null, result.exitCode)
                assertEquals(null, result.signal)
            }
            verifyLogs(fixture, result)
        }
    }

    @Test
    fun `changed source compiler digest unexpected file symlink and hardlink never reach compiler execution`() = withRoot { root ->
        for (kind in listOf("source", "header", "compiler", "compiler-writable", "compiler-hardlink", "unexpected", "symlink", "hardlink", "stale-object")) {
            val parent = Files.createDirectory(root.resolve(kind))
            val marker = parent.resolve("launched")
            val compiler = script(parent.resolve("compiler"), "printf launched > '$marker'; exit 0")
            val fixture = fixture(parent.resolve("run"), compiler = compiler)
            val source = fixture.request.snapshotRoot.resolve(fixture.request.sourcePath)
            when (kind) {
                "source" -> {
                    Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rw-------"))
                    Files.writeString(source, "changed source\n")
                }
                "header" -> {
                    val header = fixture.request.snapshotRoot.resolve("include/modules/alpha.h")
                    Files.setPosixFilePermissions(header, PosixFilePermissions.fromString("rw-------"))
                    Files.writeString(header, "changed header bytes\n")
                }
                "compiler" -> {
                    Files.setPosixFilePermissions(compiler, PosixFilePermissions.fromString("rwx------"))
                    Files.writeString(compiler, "#!/bin/sh\nprintf changed > '$marker'\n")
                }
                "compiler-writable" -> Files.setPosixFilePermissions(compiler, PosixFilePermissions.fromString("r-x-w----"))
                "compiler-hardlink" -> Files.createLink(parent.resolve("compiler-alias"), compiler)
                "unexpected" -> Files.writeString(fixture.request.snapshotRoot.resolve("unexpected.h"), "extra\n")
                "symlink" -> { Files.delete(source); Files.createSymbolicLink(source, compiler) }
                "hardlink" -> Files.createLink(parent.resolve("source-alias"), source)
                "stale-object" -> Files.writeString(fixture.request.outputDirectory.resolve("module.o"), "stale\n")
            }
            val execution = launch(fixture)
            assertTrue(execution.exitCode != 0, "$kind unexpectedly completed")
            assertFalse(Files.exists(marker), "$kind launched the compiler")
            assertTrue(execution.stdout.isEmpty(), "$kind emitted a structured result")
        }
    }

    @Test
    fun `compiler cannot write a forged result through its nondumpable worker parent descriptor`() = withRoot { root ->
        val compiler = script(root.resolve("compiler"), "printf forged > /proc/\$PPID/fd/1")
        val fixture = fixture(root.resolve("run"), compiler = compiler)
        val execution = launch(fixture)
        assertEquals(0, execution.exitCode, execution.stderr)
        val result = ContainedModuleCompilerResult.parse(execution.stdout)
        assertEquals("compiler-failed", result.outcome)
        assertFalse(execution.stdout.decodeToString().startsWith("forged"))
        assertTrue(result.stderrBytes > 0)
    }

    @Test
    fun `compiler cannot read host files or reopen a file it created in scratch`() = withRoot { root ->
        val parent = Files.createDirectory(root.resolve("read-boundary"))
        val secret = parent.resolve("host-canary")
        Files.writeString(secret, "HOST_CANARY_MUST_NOT_APPEAR")
        val compiler = script(parent.resolve("compiler"), """
            printf 'SCRATCH_CANARY_MUST_NOT_APPEAR' > "${'$'}TMPDIR/created"
            /usr/bin/cat "${'$'}TMPDIR/created"
            /usr/bin/cat '$secret'
            exit 0
        """.trimIndent())
        val fixture = fixture(parent.resolve("run"), compiler = compiler)
        val execution = launch(fixture)
        assertEquals(0, execution.exitCode, execution.stderr)
        val result = ContainedModuleCompilerResult.parse(execution.stdout)
        result.requireBinding(fixture.request)
        assertEquals("object-invalid", result.outcome,
            "exit=${result.exitCode}, compiler stderr=${Files.readString(fixture.request.outputDirectory.resolve("compiler.stderr"))}")
        assertTrue(Files.exists(fixture.request.outputDirectory.resolve("tmp/created")),
            "the compiler should retain its write-only scratch output")
        val stdout = Files.readString(fixture.request.outputDirectory.resolve("compiler.stdout"))
        val stderr = Files.readString(fixture.request.outputDirectory.resolve("compiler.stderr"))
        assertFalse(stdout.contains("SCRATCH_CANARY_MUST_NOT_APPEAR"), stdout)
        assertFalse(stdout.contains("HOST_CANARY_MUST_NOT_APPEAR"), stdout)
        assertTrue(stderr.isNotEmpty(), "denied read attempts must leave diagnostic evidence")
    }

    @Test
    @org.junit.jupiter.api.Tag("ci-live")
    fun `native compiler read syscalls cannot access scratch or off-snapshot canaries`() = withRoot { root ->
        val parent = Files.createDirectory(root.resolve("native-read-boundary"))
        val secret = parent.resolve("host-canary")
        Files.writeString(secret, "HOST_CANARY_MUST_NOT_APPEAR")
        val runtime = Files.createDirectory(parent.resolve("native-runtime"))
        val source = runtime.resolve("probe.c")
        val compiler = runtime.resolve("probe")
        Files.writeString(source, """
            #define _GNU_SOURCE
            #include <errno.h>
            #include <fcntl.h>
            #include <stdio.h>
            #include <stdlib.h>
            #include <string.h>
            #include <sys/mman.h>
            #include <sys/stat.h>
            #include <sys/syscall.h>
#include <sys/wait.h>
            #include <unistd.h>
            #include <linux/openat2.h>
            static int denied(int fd, const char *canary) {
                if (fd < 0) return errno == EACCES || errno == EPERM;
                struct stat status;
                if (fstat(fd, &status) == 0 && status.st_size > 0) {
                    size_t length = status.st_size > 4096 ? 4096 : (size_t)status.st_size;
                    void *mapping = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, 0);
                    if (mapping != MAP_FAILED) {
                        fwrite(mapping, 1, length, stdout);
                        munmap(mapping, length);
                    }
                }
                close(fd);
                (void)canary;
                return 0;
            }
            static int child_checks(const char *host, const char *scratchFile) {
                int host_fd = open(host, O_RDONLY | O_CLOEXEC);
                int scratch_fd = openat(AT_FDCWD, scratchFile, O_RDONLY | O_CLOEXEC);
                int ok = (host_fd < 0 && (errno == EACCES || errno == EPERM)) &&
                    (scratch_fd < 0 && (errno == EACCES || errno == EPERM));
                if (host_fd >= 0) close(host_fd);
                if (scratch_fd >= 0) close(scratch_fd);
                return ok;
            }
            int main(int argc, char **argv) {
                if (argc == 4 && strcmp(argv[1], "--child") == 0) {
                    return child_checks(argv[2], argv[3]) ? 0 : 93;
                }
                const char *scratch = getenv("TMPDIR");
                char created[4096];
                if (scratch == NULL || snprintf(created, sizeof(created), "%s/native-canary", scratch) < 0) return 90;
                int output = open(created, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
                if (output < 0 || write(output, "SCRATCH_CANARY_MUST_NOT_APPEAR", 30) != 30) return 91;
                close(output);
                int first = denied(open(created, O_RDONLY | O_CLOEXEC), "scratch");
                int second = denied(openat(AT_FDCWD, created, O_RDONLY | O_CLOEXEC), "scratch");
                struct open_how how = {.flags = O_RDONLY | O_CLOEXEC};
                int third = denied((int)syscall(SYS_openat2, AT_FDCWD, "$secret", &how, sizeof(how)), "host");
                pid_t child = fork();
                if (child == 0) {
                    if (setsid() < 0) _exit(94);
                    char *const child_argv[] = {argv[0], "--child", (char *)"$secret", created, NULL};
                    execv(argv[0], child_argv);
                    _exit(95);
                }
                int child_status = 0;
                int child_ok = child > 0 && waitpid(child, &child_status, 0) == child &&
                    WIFEXITED(child_status) && WEXITSTATUS(child_status) == 0;
                puts(first ? "open-denied" : "open-allowed");
                puts(second ? "openat-denied" : "openat-allowed");
                puts(third ? "openat2-denied" : "openat2-allowed");
                puts(child_ok ? "fork-exec-setsid-denied" : "fork-exec-setsid-allowed");
                return first && second && third && child_ok ? 0 : 92;
            }
        """.trimIndent())
        val hostCompiler = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
        val build = ProcessBuilder(hostCompiler.toString(), "-O2", "-Wall", "-Wextra", "-Werror", "-std=c11",
            source.toString(), "-o", compiler.toString()).redirectErrorStream(true).start()
        val buildOutput = build.inputStream.readBytes().decodeToString()
        assertTrue(build.waitFor(30, TimeUnit.SECONDS), "native probe build timed out")
        assertEquals(0, build.exitValue(), buildOutput)
        Files.setPosixFilePermissions(compiler, PosixFilePermissions.fromString("r-x------"))
        val fixture = fixture(parent.resolve("run"), compiler = compiler)
        val execution = launch(fixture)
        assertEquals(0, execution.exitCode, execution.stderr)
        val result = ContainedModuleCompilerResult.parse(execution.stdout)
        result.requireBinding(fixture.request)
        assertEquals("object-invalid", result.outcome)
        val stdout = Files.readString(fixture.request.outputDirectory.resolve("compiler.stdout"))
        assertTrue(stdout.contains("open-denied") && stdout.contains("openat-denied") && stdout.contains("openat2-denied"), stdout)
        assertTrue(stdout.contains("fork-exec-setsid-denied"), stdout)
        assertFalse(stdout.contains("SCRATCH_CANARY_MUST_NOT_APPEAR"), stdout)
        assertFalse(stdout.contains("HOST_CANARY_MUST_NOT_APPEAR"), stdout)
    }

    @Test
    fun synchronizedPolicyAdmittedTransientHeaderMutationReturnsInputChanged() = withRoot { root ->
        val parent = Files.createDirectory(root.resolve("transient"))
        val realCompiler = stageCompiler(parent)
        val ready = parent.resolve("run/output/tmp/ready")
        val started = parent.resolve("run/output/tmp/started")
        val restored = parent.resolve("run/output/tmp/restored")
        val shim = script(realCompiler.parent.resolve("shim"), """
            wait_for() {
                tries=0
                while [ ! -e "${'$'}1" ]; do
                    tries=${'$'}((tries + 1))
                    [ "${'$'}tries" -le 1000 ] || exit 125
                    /usr/bin/sleep 0.01
                done
            }
            printf ready > '$ready'
            /usr/bin/sleep 0.1
            printf started > '$started'
            wait_for '$restored'
            '$realCompiler' "${'$'}@"
            status=${'$'}?
            exit "${'$'}status"
        """.trimIndent())
        for (name in listOf("cc1", "as")) {
            Files.copy(realCompiler.parent.resolve(name), shim.parent.resolve(name))
            Files.setPosixFilePermissions(shim.parent.resolve(name), PosixFilePermissions.fromString("r-x------"))
        }
        val source = """
            #include "modules/alpha.h"
            #include "modules/transient.h"
            int alpha(void) { return 7; }
        """.trimIndent() + "\n"
        val originalTransient = "int alpha(void);\n"
        val fixture = fixture(parent.resolve("run"), compiler = shim, source = source,
            extraContent = mapOf("include/modules/transient.h" to originalTransient), maximumWallMillis = 30_000)
        val transient = fixture.request.snapshotRoot.resolve("include/modules/transient.h")
        fun replaceInput(content: String) {
            val replacement = Files.createTempFile(transient.parent, "replacement-", ".h")
            Files.writeString(replacement, content)
            Files.setPosixFilePermissions(replacement, PosixFilePermissions.fromString("r--------"))
            Files.move(replacement, transient, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
        }
        val execution = launch(fixture) {
            try {
                await(ready)
                replaceInput("int beta(void);\n")
                await(started)
                replaceInput(originalTransient)
            } finally {
                Files.writeString(restored, "restored")
            }
        }
        assertEquals(0, execution.exitCode, execution.stderr)
        val result = ContainedModuleCompilerResult.parse(execution.stdout)
        result.requireBinding(fixture.request)
        assertEquals("input-changed", result.outcome)
        assertEquals(null, result.objectSha256)
        assertEquals(originalTransient, Files.readString(transient))
        verifyLogs(fixture, result)
    }

    @Test
    fun `compiler include probes are refused before an authenticated compiler can launch`() = withRoot { root ->
        val marker = root.resolve("compiler-launched")
        val compiler = script(root.resolve("compiler"), "printf launched > '$marker'; exit 0")
        val fixture = fixture(root.resolve("run"), compiler = compiler, source = """
            #include "modules/alpha.h"
            #if __has_include("modules/transient.h")
            #include "modules/transient.h"
            #endif
            int alpha(void) { return 7; }
        """.trimIndent() + "\n")
        val execution = launch(fixture)
        assertTrue(execution.exitCode != 0)
        assertTrue(execution.stderr.contains("unsupported preprocessing operator"), execution.stderr)
        assertTrue(execution.stdout.isEmpty())
        assertFalse(Files.exists(marker), "unsupported include probe launched the compiler")
        assertFalse(Files.exists(fixture.request.outputDirectory.resolve("tmp")))
    }

    private data class Fixture(val root: Path, val request: ContainedModuleCompilerRequest)
    private data class Execution(val exitCode: Int, val stdout: ByteArray, val stderr: String)

    private fun fixture(root: Path, profile: ReconstructionProfile = ReconstructionProfiles.default,
        compiler: Path = stageCompiler(root),
        source: String = "#include \"modules/alpha.h\"\n#include \"alpha_internal.h\"\nint alpha(void) { return VALUE; }\n",
        headerSource: String = "int alpha(void);\n",
        extraContent: Map<String, String> = emptyMap(),
        maximumWallMillis: Long = 10000, maximumOutputBytes: Long = 65536): Fixture {
        Files.createDirectories(root)
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        val snapshot = Files.createDirectory(root.resolve("snapshot"))
        val output = Files.createDirectory(root.resolve("output"))
        val content = mapOf("src/modules/alpha.c" to source, "include/modules/alpha.h" to headerSource,
            "src/modules/alpha_internal.h" to "#define VALUE 7\n", "include/decomp_types.h" to "") + extraContent
        val inputs = content.map { (relative, text) ->
            val path = snapshot.resolve(relative)
            Files.createDirectories(path.parent)
            Files.writeString(path, text)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
            ContainedModuleCompilerInput(relative, sha256(text.toByteArray()), text.toByteArray().size.toLong())
        }
        val helper = Path.of(requireNotNull(System.getProperty("decompengine.module.compiler.execHelper"))).toRealPath()
        val compilerRoots = listOfNotNull(compiler.parent,
            compiler.parent.parent.takeIf { compiler.parent.fileName.toString() == "test-compiler-runtime" &&
                compiler.parent.parent.fileName.toString() == "toolchain" },
            helper.parent, Path.of("/usr/bin"), Path.of("/usr/include"),
            Path.of("/usr/lib/gcc"), Path.of("/usr/lib/x86_64-linux-gnu"), Path.of("/lib/x86_64-linux-gnu"),
            Path.of("/lib64")).filter { Files.exists(it, LinkOption.NOFOLLOW_LINKS) }.map { it.toRealPath() }.distinct()
        val loaderPath = when (System.getProperty("os.arch")) {
            "amd64", "x86_64" -> Path.of("/lib64/ld-linux-x86-64.so.2")
            "aarch64", "arm64" -> Path.of("/lib/ld-linux-aarch64.so.1")
            else -> error("worker compiler test has no reviewed ELF interpreter mapping")
        }.toRealPath()
        val request = ContainedModuleCompilerRequest("a".repeat(64), profile.id, profile.sha256, snapshot,
            "src/modules/alpha.c", inputs, compiler, sha256(Files.readAllBytes(compiler)), output,
            maximumWallMillis, maximumOutputBytes, OracleJson.parse(profile.canonicalJson().toByteArray()) as JsonObject,
            schemaVersion = 2, trampolinePath = helper, trampolineSha256 = sha256(Files.readAllBytes(helper)),
            runtimeReadRoots = compilerRoots,
            runtimeExecuteRoots = listOf(compiler.parent, Path.of("/usr/bin").toRealPath()).distinct(),
            runtimeExecuteFiles = listOf(loaderPath))
        return Fixture(root, request)
    }

    private fun launch(fixture: Fixture, rootCompiler: Path? = null, useExecutableAlias: Boolean = true,
        noexecOutput: Boolean = false, duringExecution: () -> Unit = {}): Execution {
        val root = fixture.root
        val requestFile = root.resolve("request.json")
        Files.write(requestFile, fixture.request.canonicalBytes)
        Files.setPosixFilePermissions(requestFile, PosixFilePermissions.fromString("r--------"))
        val temporary = Files.createDirectory(root.resolve("jvm-tmp"))
        val native = Path.of(requireNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory"))).toRealPath()
        val classpath = System.getProperty("java.class.path").split(File.pathSeparator).filter(String::isNotEmpty)
            .joinToString(File.pathSeparator) { Path.of(it).toAbsolutePath().normalize().toString() }
        val arguments = listOf(Path.of(System.getProperty("java.home"), "bin", "java").toRealPath().toString(),
            "-Xmx192m", "-XX:+DisableAttachMechanism", "-XX:-UsePerfData", "-Djava.io.tmpdir=$temporary", "-Duser.home=$temporary") +
            OracleNativeLibraries.jvmArguments(native) + listOf("-cp", classpath, ContainedModuleCompilerWorker::class.java.name,
                requestFile.toString(), fixture.request.sha256)
        val stdout = root.resolve("worker.stdout")
        val stderr = root.resolve("worker.stderr")
        val ownedCompiler = rootCompiler?.let { original ->
            val input = decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput(original, Files.size(original), sha256(Files.readAllBytes(original)))
            materializeOwnedModuleCompilerSnapshot(input, root.resolve("owned-compiler"))
        }
        val command = if (rootCompiler == null) arguments else listOf("/usr/bin/bwrap", "--die-with-parent", "--new-session",
            "--unshare-all", "--unshare-user", "--disable-userns", "--assert-userns-disabled", "--cap-drop", "ALL",
            "--ro-bind", "/", "/", "--bind", root.toString(), root.toString(),
            "--ro-bind", rootCompiler.toString(), fixture.request.compilerPath.toString()) +
            (if (useExecutableAlias) listOf("--ro-bind", requireNotNull(ownedCompiler).path.toString(), fixture.request.compilerPath.toString()) else emptyList()) +
            listOf("--proc", "/proc", "--dev", "/dev", "--",
            "/bin/sh", "-c", "{ /usr/bin/stat -c '%u' '$rootCompiler'; /usr/bin/stat -c '%u' '${fixture.request.compilerPath}'; /usr/bin/id; " +
                "/bin/cat /proc/self/uid_map /proc/self/gid_map; } > '$root/namespace-identity'; exec \"\$@\"", "worker") + arguments
        val mountedCommand = if (!noexecOutput) command else listOf("/usr/bin/unshare", "--user", "--map-root-user", "--mount", "--",
            "/bin/sh", "-c", "set -eu; /bin/mount --bind '${fixture.request.outputDirectory}' '${fixture.request.outputDirectory}'; " +
                "/bin/mount -o remount,bind,noexec '${fixture.request.outputDirectory}'; " +
                "/usr/bin/findmnt -n -o VFS-OPTIONS --target '${fixture.request.outputDirectory}' > '$root/output-mount-options'; exec \"\$@\"", "noexec-fixture") + command
        val process = ProcessBuilder(mountedCommand).directory(root.toFile()).redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).apply {
            environment().clear()
            environment()["TMPDIR"] = temporary.toString()
        }.start()
        process.outputStream.close()
        try {
            var callbackFailure: Throwable? = null
            try { duringExecution() } catch (failure: Throwable) { callbackFailure = failure }
            // Give the worker's bounded native command its normal cleanup opportunity even
            // when a synchronization callback failed, before deleting the fixture tree.
            assertTrue(process.waitFor(40, TimeUnit.SECONDS), "module compiler test worker timed out")
            callbackFailure?.let { throw it }
            assertTrue(Files.size(stdout) <= ContainedModuleCompilerResult.MAXIMUM_RESULT_BYTES)
            assertTrue(Files.size(stderr) <= 64 * 1024)
            return Execution(process.exitValue(), Files.readAllBytes(stdout), Files.readString(stderr))
        } finally {
            if (process.isAlive) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
        }
    }

    private fun verifyLogs(fixture: Fixture, result: ContainedModuleCompilerResult) {
        for ((path, size, digest) in listOf(Triple("compiler.stdout", result.stdoutBytes, result.stdoutSha256),
            Triple("compiler.stderr", result.stderrBytes, result.stderrSha256))) {
            val bytes = Files.readAllBytes(fixture.request.outputDirectory.resolve(path))
            assertEquals(size, bytes.size.toLong())
            assertEquals(digest, sha256(bytes))
        }
    }

    private fun script(path: Path, body: String): Path {
        val runtime = Files.createDirectories(path.parent.resolve("test-compiler-runtime"))
        val selected = runtime.resolve(path.fileName)
        val shell = Path.of("/bin/sh").toRealPath()
        Files.writeString(selected, "#!$shell\n$body\n")
        Files.setPosixFilePermissions(selected, PosixFilePermissions.fromString("r-x------"))
        return selected
    }

    private fun await(path: Path, timeoutSeconds: Long = 10) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
        while (!Files.exists(path) && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue(Files.exists(path), "compiler handshake timed out: $path")
    }

    private fun stageCompiler(root: Path): Path {
        Files.createDirectories(root)
        val compiler = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
        val tools = Files.createDirectory(root.resolve("toolchain"))
        for (name in listOf("cc1", "as")) {
            val probe = ProcessBuilder(compiler.toString(), "-print-prog-name=$name").redirectErrorStream(true).start()
            assertTrue(probe.waitFor(5, TimeUnit.SECONDS), "compiler tool discovery timed out")
            val selected = probe.inputStream.readNBytes(4097).decodeToString().trim()
            assertEquals(0, probe.exitValue())
            assertTrue(selected.length in 1..4096)
            val path = Path.of(selected).let { if (it.isAbsolute) it else Path.of("/usr/bin", selected) }.toRealPath()
            Files.copy(path, tools.resolve(name))
            Files.setPosixFilePermissions(tools.resolve(name), PosixFilePermissions.fromString("r-x------"))
        }
        return Files.copy(compiler, tools.resolve("compiler")).also {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r-x------"))
        }
    }

    private fun withRoot(action: (Path) -> Unit) {
        val parent = Path.of("build/test-work/module-compiler-worker").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "fixture-")
        try { action(root) } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
