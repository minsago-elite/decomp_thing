package decompengine.project

import decompengine.oracle.fulltree.OracleNativeLibraries
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
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
            assertEquals(expected, result.outcome)
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
        for (kind in listOf("source", "compiler", "unexpected", "symlink", "hardlink", "stale-object")) {
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
                "compiler" -> {
                    Files.setPosixFilePermissions(compiler, PosixFilePermissions.fromString("rwx------"))
                    Files.writeString(compiler, "#!/bin/sh\nprintf changed > '$marker'\n")
                }
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
    fun `synchronized transient header shadow header and sidecar changes refuse a successful compiler`() = withRoot { root ->
        for (kind in listOf("header", "shadow", "sidecar")) {
            val parent = Files.createDirectory(root.resolve(kind))
            val realCompiler = stageCompiler(parent)
            val sidecar = if (kind == "sidecar") precompiledHeader(parent, realCompiler) else null
            val ready = parent.resolve("ready")
            val proceed = parent.resolve("proceed")
            val compiled = parent.resolve("compiled")
            val restored = parent.resolve("restored")
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
                wait_for '$proceed'
                '$realCompiler' "${'$'}@"
                status=${'$'}?
                printf compiled > '$compiled'
                wait_for '$restored'
                exit "${'$'}status"
            """.trimIndent())
            val source = """
                #include "modules/alpha.h"
                #if __has_include("modules/transient.h")
                #include "modules/transient.h"
                #endif
                #ifdef TRANSIENT_PCH
                #pragma message("transient-sidecar-consumed")
                #endif
                int alpha(void) { return 7; }
            """.trimIndent() + "\n"
            val fixture = fixture(parent.resolve("run"), compiler = shim, source = source)
            // The shadow search directory exists before the first inventory/watch registration.
            Files.createDirectories(fixture.request.snapshotRoot.resolve("src/modules/modules"))
            val relative = when (kind) {
                "header" -> "include/modules/transient.h"
                "shadow" -> "src/modules/modules/alpha.h"
                else -> "include/modules/alpha.h.gch"
            }
            val transient = fixture.request.snapshotRoot.resolve(relative)
            val execution = launch(fixture) {
                try {
                    await(ready)
                    // A pragma message is a note (not a -Werror diagnostic). Require its retained
                    // marker below to prove each transient compiler-search input was consumed.
                    if (sidecar != null) Files.copy(sidecar, transient)
                    else Files.writeString(transient, "#pragma message(\"transient-$kind-consumed\")\nint alpha(void);\n")
                    Files.writeString(proceed, "go")
                    await(compiled)
                    Files.delete(transient)
                } finally {
                    // A failed assertion/setup must not strand a gated native child when the
                    // worker is torn down. The shim also has its own finite wait ceiling.
                    Files.writeString(proceed, "go")
                    Files.writeString(restored, "restored")
                }
            }
            assertEquals(0, execution.exitCode, execution.stderr)
            val result = ContainedModuleCompilerResult.parse(execution.stdout)
            result.requireBinding(fixture.request)
            assertEquals(0, result.exitCode, "$kind compiler must have succeeded before refusal")
            assertEquals("input-changed", result.outcome)
            assertEquals(null, result.objectSha256)
            assertTrue(Files.size(fixture.request.outputDirectory.resolve("module.o")) >= 52)
            assertTrue(Files.readString(fixture.request.outputDirectory.resolve("compiler.stderr"))
                .contains("transient-$kind-consumed"), "$kind was not consumed by the compiler")
            assertFalse(Files.exists(transient))
            verifyLogs(fixture, result)
        }
    }

    private fun precompiledHeader(parent: Path, compiler: Path): Path {
        val header = Files.writeString(parent.resolve("pch.h"), "#define TRANSIENT_PCH 1\nint alpha(void);\n")
        val output = parent.resolve("pch.gch")
        val diagnostics = parent.resolve("pch.log")
        val process = ProcessBuilder(compiler.toString(), "-B${compiler.parent}/", "-std=c11", "-g", "-Wall", "-Wextra", "-Werror",
            "-x", "c-header", header.toString(), "-o", output.toString())
            .redirectErrorStream(true).redirectOutput(diagnostics.toFile()).start()
        process.outputStream.close()
        try {
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "sidecar fixture compilation timed out")
            assertTrue(Files.size(diagnostics) <= 65536)
            assertEquals(0, process.exitValue(), Files.readString(diagnostics))
        } finally {
            if (process.isAlive) { process.destroyForcibly(); process.waitFor(5, TimeUnit.SECONDS) }
        }
        return output
    }

    private fun await(path: Path) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
        while (!Files.exists(path) && System.nanoTime() < deadline) Thread.sleep(10)
        assertTrue(Files.exists(path), "compiler handshake timed out: $path")
    }

    private data class Fixture(val root: Path, val request: ContainedModuleCompilerRequest)
    private data class Execution(val exitCode: Int, val stdout: ByteArray, val stderr: String)

    private fun fixture(root: Path, profile: ReconstructionProfile = ReconstructionProfiles.default,
        compiler: Path = stageCompiler(root),
        source: String = "#include \"modules/alpha.h\"\n#include \"alpha_internal.h\"\nint alpha(void) { return VALUE; }\n",
        maximumWallMillis: Long = 10000, maximumOutputBytes: Long = 65536): Fixture {
        Files.createDirectories(root)
        val snapshot = Files.createDirectory(root.resolve("snapshot"))
        val output = Files.createDirectory(root.resolve("output"))
        val content = mapOf("src/modules/alpha.c" to source, "include/modules/alpha.h" to "int alpha(void);\n",
            "src/modules/alpha_internal.h" to "#define VALUE 7\n", "include/decomp_types.h" to "")
        val inputs = content.map { (relative, text) ->
            val path = snapshot.resolve(relative)
            Files.createDirectories(path.parent)
            Files.writeString(path, text)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
            ContainedModuleCompilerInput(relative, sha256(text.toByteArray()), text.toByteArray().size.toLong())
        }
        val request = ContainedModuleCompilerRequest("a".repeat(64), profile.id, profile.sha256, snapshot,
            "src/modules/alpha.c", inputs, compiler, sha256(Files.readAllBytes(compiler)), output,
            maximumWallMillis, maximumOutputBytes, OracleJson.parse(profile.canonicalJson().toByteArray()) as JsonObject)
        return Fixture(root, request)
    }

    private fun launch(fixture: Fixture, duringExecution: () -> Unit = {}): Execution {
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
        val process = ProcessBuilder(arguments).directory(root.toFile()).redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).apply {
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
        Files.writeString(path, "#!/bin/sh\n$body\n")
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r-x------"))
        return path
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
