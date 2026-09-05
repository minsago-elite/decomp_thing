package decompengine.oracle.fulltree

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
    fun `fresh JNA and SQLite bootstrap succeeds on noexec scratch without extracting native code`() {
        val parent = noexecParent()
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
            assertNotNull(parent, "required CI noexec native-library regression has no writable noexec filesystem")
        }
        assumeTrue(parent != null, "a writable noexec filesystem is required")
        withRoot(Files.createTempDirectory(checkNotNull(parent), "decomp-native-noexec-")) { root ->
            val temporary = root.resolve("tmp").createDirectories()
            val jna = Path.of(com.sun.jna.Native::class.java.protectionDomain.codeSource.location.toURI())
            val baseline = runJava(root, listOf(
                "-Djna.nosys=true", "-Djna.tmpdir=$temporary", "-Djava.io.tmpdir=$temporary",
                "-classpath", jna.toString(), "com.sun.jna.Native",
            ))
            assertTrue(baseline.first != 0 && baseline.second.contains("UnsatisfiedLinkError"), baseline.second)
            val corrected = runJava(root, isolatedObservationJvmTemporaryArguments(root, staged) + listOf(
                "-classpath", System.getProperty("java.class.path"), OracleNativeLibrariesProbe::class.java.name,
                root.resolve("database.sqlite").toString(),
            ))
            assertEquals(0, corrected.first, corrected.second)
            assertTrue(corrected.second.contains("native-bootstrap-ok"), corrected.second)
            assertTrue(Files.newDirectoryStream(temporary).use { !it.iterator().hasNext() })
            OracleNativeLibraries.requireCurrent(staged, artifactDigests)
        }
    }

    private fun noexecParent(): Path? = listOfNotNull(
        Path.of("/run/lock"), Path.of("/dev/shm"), System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")?.let(Path::of),
    ).firstOrNull { parent ->
        if (!Files.isDirectory(parent) || !Files.isWritable(parent)) return@firstOrNull false
        val process = ProcessBuilder("findmnt", "--noheadings", "--output", "OPTIONS", "--target", parent.toString())
            .redirectErrorStream(true).start()
        try {
            process.waitFor(3, TimeUnit.SECONDS) && process.exitValue() == 0 &&
                process.inputStream.readNBytes(4096).toString(Charsets.UTF_8).trim().split(',').contains("noexec")
        } finally {
            if (process.isAlive) process.destroyForcibly().waitFor()
        }
    }

    private fun runJava(root: Path, arguments: List<String>): Pair<Int, String> {
        val process = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin", "java").toString(),
            "-Duser.home=$root") + arguments).directory(root.toFile()).redirectErrorStream(true).apply {
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
