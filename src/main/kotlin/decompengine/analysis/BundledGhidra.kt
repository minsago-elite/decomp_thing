package decompengine.analysis

import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Properties

internal data class GhidraPostScript(val name: String, val arguments: List<String>)

internal data class GhidraInvocation(
    val project: Path,
    val projectName: String,
    val input: Path,
    val scripts: Path,
    val postScripts: List<GhidraPostScript>,
) {
    fun arguments(): List<String> = listOf(
        "analyze", project.absolute(), projectName, input.absolute(), scripts.absolute(),
    ) + postScripts.flatMap { listOf(it.name, it.arguments.size.toString()) + it.arguments }
}

class BundledGhidra private constructor(val root: Path) {
    val release: Path = root.resolve("ghidra_${VERSION}_PUBLIC")

    fun probeCommand(): List<String> = probeCommand {}

    internal fun probeCommand(checkpoint: (String) -> Unit): List<String> {
        val command = workerCommand(checkpoint) + "probe"
        checkpoint("before returning bundled Ghidra probe command")
        return command
    }

    internal fun analysisCommand(invocation: GhidraInvocation): List<String> = analysisCommand(invocation) {}

    /** The internal callback may abort preparation; it cannot supply verification results. */
    internal fun analysisCommand(invocation: GhidraInvocation, checkpoint: (String) -> Unit): List<String> {
        val command = workerCommand(checkpoint) + invocation.arguments()
        checkpoint("before returning bundled Ghidra analysis command")
        return command
    }

    private fun workerCommand(checkpoint: (String) -> Unit): List<String> {
        verify(checkpoint)
        val bridge = root.resolve("decomp-ghidra-bridge.jar")
        val jars = mutableListOf<Path>()
        visitPaths(release.resolve("Ghidra"), "library inventory", checkpoint) { path ->
            if (path.parent.fileName.toString() == "lib" && path.fileName.toString().endsWith(".jar")) {
                jars.add(path)
            }
        }
        checkpoint("before sorting bundled Ghidra libraries")
        jars.sort()
        checkpoint("after sorting bundled Ghidra libraries")
        require(jars.isNotEmpty()) { "Bundled Ghidra libraries are missing; rebuild installDist" }
        checkpoint("before checking bundled Ghidra Java worker")
        val java = Path.of(System.getProperty("java.home"), "bin", if (File.separatorChar == '\\') "java.exe" else "java")
        require(Files.isExecutable(java)) { "The application JDK has no executable Java worker: $java" }
        checkpoint("after checking bundled Ghidra Java worker")
        val command = GhidraWorkerCommand.prefix(java, release, listOf(bridge) + jars)
        checkpoint("after preparing bundled Ghidra worker command")
        return command
    }

    internal fun verify() = verify {}

    /** Cooperative cancellation only; all bundle validation remains local to this method. */
    internal fun verify(checkpoint: (String) -> Unit) {
        checkpoint("before bundled Ghidra verification")
        val manifest = root.resolve("bundle.sha256")
        require(Files.isRegularFile(manifest, LinkOption.NOFOLLOW_LINKS) && Files.size(manifest) <= 4L * 1024 * 1024) {
            "Bundled Ghidra is missing at $root; rebuild or reinstall the complete application distribution"
        }
        val expectedPaths = mutableSetOf<String>()
        checkpoint("before reading bundled Ghidra checksum manifest")
        val records = Files.readAllLines(manifest)
        checkpoint("after reading bundled Ghidra checksum manifest")
        records.forEach { record ->
            checkpoint("before checking bundled Ghidra checksum record")
            require(record.length > 66 && record.substring(0, 64).matches(Regex("[0-9a-f]{64}")) && record.substring(64, 66) == "  ") {
                "Invalid bundled Ghidra checksum record"
            }
            val relative = record.substring(66)
            val path = root.resolve(relative).normalize()
            require(!Path.of(relative).isAbsolute && path.startsWith(root) && path != root && expectedPaths.add(relative)) {
                "Unsafe or duplicate bundled Ghidra path"
            }
            var component = path
            while (component != root) {
                checkpoint("before checking bundled Ghidra path component")
                require(!Files.isSymbolicLink(component)) { "Linked bundled Ghidra file: $relative" }
                component = checkNotNull(component.parent)
                checkpoint("after checking bundled Ghidra path component")
            }
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "Missing bundled Ghidra file: $relative" }
            val digest = MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
                val buffer = ByteArray(65536)
                while (true) {
                    checkpoint("before reading bundled Ghidra file: $relative")
                    val count = input.read(buffer)
                    checkpoint("after reading bundled Ghidra file: $relative")
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            require(digest.digest().joinToString("") { "%02x".format(it) } == record.substring(0, 64)) {
                "Corrupt bundled Ghidra file: $relative"
            }
            checkpoint("after checking bundled Ghidra checksum record")
        }
        val actualPaths = mutableSetOf<String>()
        visitPaths(root, "file inventory", checkpoint) { path ->
            if (!Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && path != manifest) {
                actualPaths += root.relativize(path).joinToString("/")
            }
        }
        require(actualPaths == expectedPaths && "decomp-ghidra-bridge.jar" in expectedPaths) { "Bundled Ghidra file inventory changed" }
        checkpoint("before reading bundled Ghidra application properties")
        val properties = Properties().apply {
            Files.newInputStream(release.resolve("Ghidra/application.properties")).use { input ->
                load(CheckpointInputStream(input, checkpoint))
            }
        }
        checkpoint("after reading bundled Ghidra application properties")
        require(properties.getProperty("application.version") == VERSION && properties.getProperty("application.release.name") == "PUBLIC") {
            "Bundled Ghidra version does not match the application"
        }
        checkpoint("after bundled Ghidra verification")
    }

    private fun visitPaths(path: Path, label: String, checkpoint: (String) -> Unit, visit: (Path) -> Unit) {
        checkpoint("before opening bundled Ghidra $label")
        Files.walk(path).use { paths ->
            val iterator = paths.iterator()
            while (true) {
                checkpoint("before advancing bundled Ghidra $label")
                val hasNext = iterator.hasNext()
                checkpoint("after advancing bundled Ghidra $label")
                if (!hasNext) break
                visit(iterator.next())
                checkpoint("after visiting bundled Ghidra $label path")
            }
        }
        checkpoint("after reading bundled Ghidra $label")
    }

    companion object {
        const val VERSION = "12.1.3"
        const val ARCHIVE_SHA256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54"
        const val WORKER_CLASS = "decompengine.ghidra.BundledGhidraWorker"

        fun locate(): BundledGhidra {
            val developmentBundle = System.getProperty("decompengine.ghidra.bundle")
            val location = Path.of(BundledGhidra::class.java.protectionDomain.codeSource.location.toURI())
            return at(developmentBundle?.let(Path::of) ?: location.parent.parent.resolve("libexec/ghidra"))
        }

        internal fun at(root: Path): BundledGhidra = BundledGhidra(root.toAbsolutePath().normalize())
    }
}

/** Bounds each properties read; the owning use block closes the underlying stream without callbacks. */
private class CheckpointInputStream(
    private val input: InputStream,
    private val checkpoint: (String) -> Unit,
) : InputStream() {
    override fun read(): Int {
        checkpoint("before reading bundled Ghidra application properties bytes")
        val value = input.read()
        checkpoint("after reading bundled Ghidra application properties bytes")
        return value
    }

    override fun read(bytes: ByteArray, offset: Int, length: Int): Int {
        checkpoint("before reading bundled Ghidra application properties bytes")
        val count = input.read(bytes, offset, minOf(length, 65536))
        checkpoint("after reading bundled Ghidra application properties bytes")
        return count
    }
}

private fun Path.absolute(): String = toAbsolutePath().normalize().toString()
