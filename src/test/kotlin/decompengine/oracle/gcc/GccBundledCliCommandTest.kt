package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleJson
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledCliCommandTest {
    @Test
    fun `options select explicit scratch policy and same-owner checkpoint resume`() = fixture { root ->
        val args = arguments(root)
        val fresh = GccBundledCliOptions.parse(args)
        assertEquals("cc1", fresh.engineId)
        assertEquals(null, fresh.resumeAfterCheckpoint)
        assertEquals(8L * 1024 * 1024 * 1024, fresh.diskPolicy.requiredAvailableBytes)
        val resumed = GccBundledCliOptions.parse(args + listOf("--resume-after-checkpoint", "1024",
            "--scratch-min-bytes", "1048576", "--scratch-max-bytes", "2097152",
            "--scratch-min-inodes", "128", "--scratch-max-inodes", "256"))
        assertEquals(1024L, resumed.resumeAfterCheckpoint)
        assertEquals(2097152L, resumed.diskPolicy.maximumFilesystemBytes)
        assertEquals(256L, resumed.diskPolicy.maximumFilesystemInodes)
    }

    @Test
    fun `reject duplicate missing conflicting unknown and detached resume options`() = fixture { root ->
        val args = arguments(root)
        val invalid = listOf(args + listOf("--profile", root.resolve("profile").toString()),
            args + listOf("--unknown", "value"), args + "--resume-after-checkpoint",
            args + listOf("--resume", "receipt.json"), args + listOf("--resume-after-checkpoint", "513"),
            args + listOf("--resume-after-checkpoint", "0"), args + listOf("--scratch-max-bytes", "1e9"),
            args + listOf("--scratch-min-inodes", "-1"), args + listOf("--scratch-min-bytes", "99999999999999999999999"),
            args + listOf("--scratch-max-bytes", "1"), args + "extra", listOf("driver") + args.drop(1),
            args.dropLast(2), args.map { if (it == root.resolve("scratch").toString()) root.resolve("output").toString() else it })
        invalid.forEach { candidate -> assertFails { GccBundledCliOptions.parse(candidate) } }
    }

    @Test
    fun `bound invocation rejects directory replacement and inconsistent argv`() = fixture { root ->
        val args = arguments(root)
        val options = GccBundledCliOptions.parse(args)
        val children = listOf(options.output, privateDirectory(options.output.resolve("inputs")), privateDirectory(options.output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(options, args, identities)
        invocation.requireCurrent()
        val document = OracleJson.parseCanonical(invocation.canonicalBytes).jsonObject
        assertEquals("fresh", document.getValue("resumeMode").jsonPrimitive.content)
        assertFails { GccBundledCliInvocation(options, args + listOf("--resume-after-checkpoint", "512"), identities) }
        Files.move(options.output.resolve("inputs"), options.output.resolve("old-inputs"))
        privateDirectory(options.output.resolve("inputs"))
        assertFails { invocation.requireCurrent() }
    }

    @Test
    fun `command records selection but refuses a mismatched binary before staging or leasing`() = fixture { root ->
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines.json").toRealPath()
        val args = arguments(root).map { if (it == root.resolve("profile").toString()) profile.toString() else it }
        val options = GccBundledCliOptions.parse(args)
        val failure = assertFails { GccBundledCliCommand.run(options, args) }
        assertTrue(failure.message.orEmpty().contains("binary differs from selected profile engine"), failure.toString())
        assertTrue(Files.isRegularFile(options.output.resolve("invocation.json")))
        for (path in listOf(options.output.resolve("inputs"), options.output.resolve("journal"), options.scratch)) {
            Files.list(path).use { assertEquals(0L, it.count()) }
        }
        assertFalse(Files.exists(options.output.resolve("result.json")))
        assertFails { GccBundledCliCommand.run(options, args) }
    }

    @Test
    fun `actual CLI rejects duplicate options and nonempty output without overwriting files`() = fixture { root ->
        val args = arguments(root)
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            parseBootClassPathManifest(reference.invocationManifestBytes(), root, emptySet()).joinToString(File.pathSeparator) { it.path.toString() }
        }
        fun invoke(arguments: List<String>): Pair<Int, String> {
            val log = Files.createTempFile(root, "cli-", ".log")
            val process = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx256m",
                "-cp", classpath, "decompengine.MainKt", "gcc-engine-plan") + arguments)
                .redirectErrorStream(true).redirectOutput(log.toFile()).start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS))
                return process.exitValue() to Files.readString(log).take(8192)
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            }
        }
        val duplicate = invoke(args + listOf("--profile", root.resolve("profile").toString()))
        assertEquals(2, duplicate.first)
        assertTrue(duplicate.second.contains("duplicate option"), duplicate.second)
        val prior = Files.writeString(root.resolve("output/prior"), "preserve me")
        val nonempty = invoke(args)
        assertTrue(nonempty.first != 0)
        assertTrue(nonempty.second.contains("existing empty private directory"), nonempty.second)
        assertEquals("preserve me", Files.readString(prior))
        Files.list(root.resolve("output")).use { assertEquals(1L, it.count()) }
    }

    private fun arguments(root: Path) = listOf("cc1", root.resolve("binary").toString(), "--profile", root.resolve("profile").toString(),
        "--ghidra-archive", root.resolve("archive").toString(), "--output", root.resolve("output").toString(), "--scratch", root.resolve("scratch").toString())
    private fun privateDirectory(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun fixture(action: (Path) -> Unit) {
        val root = Files.createTempDirectory("gcc-contained-cli-").toRealPath()
        try {
            listOf("binary", "profile", "archive").forEach { Files.writeString(root.resolve(it), "fixture") }
            listOf("output", "scratch").forEach { privateDirectory(root.resolve(it)) }
            action(root)
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
