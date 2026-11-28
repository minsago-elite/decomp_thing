package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.util.Properties
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class OracleNativeLibrariesTest {
    private val staged: Path
        get() = Path.of(checkNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory")))
    private val policy = Properties().apply {
        OracleNativeLibrariesTest::class.java.getResourceAsStream("/oracle-native-libraries-v1.properties")!!.use(::load)
    }
    private val artifactDigests = listOf("jna", "sqlite").map { policy.getProperty("$it.artifactSha256") }

    @Test
    fun `native libraries match the frozen JAR resources and require each dependency exactly once`() {
        OracleNativeLibraries.requireCurrent(staged, artifactDigests)
        assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(staged, artifactDigests.take(1)) }
        assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(staged, artifactDigests + artifactDigests.first()) }
        assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(staged, listOf("0".repeat(64))) }
    }

    @Test
    fun `native provisioning rejects missing corrupted linked and extra libraries`() {
        withRoot(createTempDirectory("oracle-native-validation-")) { root ->
            val native = root.resolve("native").createDirectories()
            listOf("libjnidispatch.so", "libsqlitejdbc.so").forEach { name ->
                Files.copy(staged.resolve(name), native.resolve(name))
            }
            OracleNativeLibraries.requireCurrent(native, artifactDigests)
            val selected = native.resolve("libjnidispatch.so")
            Files.write(selected, byteArrayOf(0))
            assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(native, artifactDigests) }
            Files.copy(staged.resolve("libjnidispatch.so"), selected, StandardCopyOption.REPLACE_EXISTING)
            val extra = Files.write(native.resolve("unknown.so"), byteArrayOf(0))
            assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(native, artifactDigests) }
            Files.delete(extra)
            Files.delete(selected)
            assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(native, artifactDigests) }
            Files.createSymbolicLink(selected, staged.resolve("libjnidispatch.so"))
            assertFailsWith<IllegalArgumentException> { OracleNativeLibraries.requireCurrent(native, artifactDigests) }
        }
    }

    @Test
    fun `native JVM bootstrap forbids libraries in writable scratch and disables JNA fallback`() {
        val run = Path.of("/private/run")
        assertFailsWith<IllegalArgumentException> { isolatedObservationJvmTemporaryArguments(run, run.resolve("native")) }
        assertFailsWith<IllegalArgumentException> { isolatedObservationJvmTemporaryArguments(run, run.parent) }
        val arguments = isolatedObservationJvmTemporaryArguments(run, staged)
        assertTrue("-Djna.nosys=true" in arguments && "-Djna.nounpack=true" in arguments)
        assertTrue("-Djna.boot.library.path=$staged" in arguments)
        assertTrue("-Dorg.sqlite.lib.path=$staged" in arguments)
        assertTrue("-Djava.io.tmpdir=/private/run/tmp" in arguments)
    }

    @Test
    fun `fresh pinned native bootstrap authenticates descriptor input and disables fallback`() {
        withRoot(createTempDirectory("oracle-native-descriptor-")) { root ->
            val temporary = root.resolve("tmp").createDirectories()
            val bytes = "pinned contained worker request".toByteArray()
            val request = Files.write(root.resolve("request.json"), bytes)
            val suffix = listOf("-classpath", System.getProperty("java.class.path"),
                OracleNativeDescriptorProbe::class.java.name, request.toString(), bytes.size.toString())
            val pinned = isolatedObservationJvmTemporaryArguments(root, staged)
            val positive = runJava(root, pinned + suffix + OracleArtifacts.sha256(bytes))
            assertEquals(0, positive.first, positive.second)
            assertTrue(positive.second.contains("descriptor-bootstrap-ok"), positive.second)
            val substituted = runJava(root, pinned + suffix + "0".repeat(64))
            assertTrue(substituted.first != 0 && substituted.second.contains("descriptor request digest changed"), substituted.second)
            // No ambient system library or JAR extraction may repair a missing admitted native path.
            val missingNative = staged.resolveSibling("missing-native-${root.fileName}")
            check(!Files.exists(missingNative))
            val missing = runJava(root, isolatedObservationJvmTemporaryArguments(root, missingNative) +
                suffix + OracleArtifacts.sha256(bytes))
            assertTrue(missing.first != 0 && missing.second.contains("UnsatisfiedLinkError"), missing.second)
            assertTrue(Files.newDirectoryStream(temporary).use { !it.iterator().hasNext() })
            OracleNativeLibraries.requireCurrent(staged, artifactDigests)
        }
    }

    @Test
    fun `fresh JNA and SQLite bootstrap succeeds on noexec scratch without extracting native code`() {
        // A repository-local scratch directory is bind-remounted noexec inside an unprivileged user and
        // mount namespace for each child JVM, so no scratch is created on host-wide noexec mounts (#2001).
        withRoot(createTempDirectory("oracle-native-noexec-")) { root ->
            val noexec = noexecNamespace(root)
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertNotNull(noexec, "required CI noexec native-library regression cannot remount scratch noexec")
            }
            assumeTrue(noexec != null, "an unprivileged user and mount namespace is required for noexec scratch")
            val temporary = root.resolve("tmp").createDirectories()
            val jna = Path.of(com.sun.jna.Native::class.java.protectionDomain.codeSource.location.toURI())
            val baseline = runJava(root, listOf(
                "-Djna.nosys=true", "-Djna.tmpdir=$temporary", "-Djava.io.tmpdir=$temporary",
                "-classpath", jna.toString(), "com.sun.jna.Native",
            ), checkNotNull(noexec))
            assertTrue(baseline.first != 0 && baseline.second.contains("UnsatisfiedLinkError"), baseline.second)
            val corrected = runJava(root, isolatedObservationJvmTemporaryArguments(root, staged) + listOf(
                "-classpath", System.getProperty("java.class.path"), OracleNativeLibrariesProbe::class.java.name,
                root.resolve("database.sqlite").toString(),
            ), noexec)
            assertEquals(0, corrected.first, corrected.second)
            assertTrue(corrected.second.contains("native-bootstrap-ok"), corrected.second)
            assertTrue(Files.newDirectoryStream(temporary).use { !it.iterator().hasNext() })
            OracleNativeLibraries.requireCurrent(staged, artifactDigests)
        }
    }

    /** Returns a command prefix that runs its command with [root] remounted noexec, or null if unavailable. */
    private fun noexecNamespace(root: Path): List<String>? {
        val tools = listOf("unshare", "mount", "findmnt").map { name ->
            System.getenv("PATH").orEmpty().split(':').filter(String::isNotEmpty).map { Path.of(it, name) }
                .firstOrNull(Files::isExecutable) ?: return null
        }
        val target = root.toRealPath().toString()
        // $0 is the scratch root and $1 is mount; the remaining arguments are the command to run.
        val prefix = listOf(tools[0].toString(), "--user", "--map-root-user", "--mount", "--propagation", "private",
            "/bin/sh", "-c", "set -e; \"\$1\" --bind \"\$0\" \"\$0\"; \"\$1\" -o remount,bind,noexec \"\$0\"; shift; exec \"\$@\"",
            target, tools[1].toString())
        val process = ProcessBuilder(prefix + listOf(tools[2].toString(), "--noheadings", "--output", "TARGET,OPTIONS",
            "--target", target)).redirectErrorStream(true).start()
        try {
            process.outputStream.close()
            if (!process.waitFor(5, TimeUnit.SECONDS) || process.exitValue() != 0) return null
            val fields = process.inputStream.readNBytes(4096).toString(Charsets.UTF_8).trim().split(Regex("\\s+"))
            return prefix.takeIf { fields.size == 2 && fields[0] == target && "noexec" in fields[1].split(',') }
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor()
        }
    }

    private fun runJava(root: Path, arguments: List<String>, prefix: List<String> = emptyList()): Pair<Int, String> {
        val process = ProcessBuilder(prefix + listOf(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-XX:-UsePerfData", "-Duser.home=$root") + arguments).directory(root.toFile()).redirectErrorStream(true).apply {
            environment().clear()
            environment()["HOME"] = root.toString()
            environment()["TMPDIR"] = root.resolve("tmp").toString()
        }.start()
        try {
            process.outputStream.close()
            assertTrue(process.waitFor(30, TimeUnit.SECONDS), "native bootstrap timed out")
            val output = process.inputStream.readNBytes(8193)
            assertTrue(output.size <= 8192, "native bootstrap exceeded its output bound")
            return process.exitValue() to output.toString(Charsets.UTF_8)
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor()
        }
    }

    private fun withRoot(root: Path, action: (Path) -> Unit) {
        try {
            action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}

object OracleNativeLibrariesProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        check(com.sun.jna.Native.POINTER_SIZE == 8)
        java.sql.DriverManager.getConnection("jdbc:sqlite:${arguments.single()}").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("select 42").use { result -> check(result.next() && result.getInt(1) == 42) }
            }
        }
        println("native-bootstrap-ok")
    }
}

object OracleNativeDescriptorProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        check(arguments.size == 3)
        val root = Path.of(arguments[0]).parent
        val temporary = root.resolve("tmp").toString()
        check(System.getProperty("user.home") == root.toString())
        check(System.getProperty("java.io.tmpdir") == temporary && System.getProperty("jna.tmpdir") == temporary)
        check(System.getenv() == mapOf("HOME" to root.toString(), "TMPDIR" to temporary))
        check("-XX:-UsePerfData" in java.lang.management.ManagementFactory.getRuntimeMXBean().inputArguments)
        val bytes = arguments[1].toInt().also { check(it in 1..1024) }
        StableControlFile.open(Path.of(arguments[0]), bytes.toLong(), "native bootstrap request").use { file ->
            check(file.size == bytes.toLong() && file.authenticatedSha256 == arguments[2]) {
                "descriptor request digest changed"
            }
            check(OracleArtifacts.sha256(file.readExactly(0, bytes, "native bootstrap request")) == arguments[2])
            file.verifyUnchanged("native bootstrap request")
        }
        println("descriptor-bootstrap-ok")
    }
}
