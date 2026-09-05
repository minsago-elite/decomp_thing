package decompengine.analysis

import java.io.File
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

    fun probeCommand(): List<String> = workerCommand() + "probe"

    internal fun analysisCommand(invocation: GhidraInvocation): List<String> = workerCommand() + invocation.arguments()

    private fun workerCommand(): List<String> {
        verify()
        val bridge = root.resolve("decomp-ghidra-bridge.jar")
        val jars = Files.walk(release.resolve("Ghidra")).use { paths ->
            paths.filter { it.parent.fileName.toString() == "lib" && it.fileName.toString().endsWith(".jar") }
                .sorted().toList()
        }
        require(jars.isNotEmpty()) { "Bundled Ghidra libraries are missing; rebuild installDist" }
        val java = Path.of(System.getProperty("java.home"), "bin", if (File.separatorChar == '\\') "java.exe" else "java")
        require(Files.isExecutable(java)) { "The application JDK has no executable Java worker: $java" }
        return GhidraWorkerCommand.prefix(java, release, listOf(bridge) + jars)
    }

    internal fun verify() {
        val manifest = root.resolve("bundle.sha256")
        require(Files.isRegularFile(manifest, LinkOption.NOFOLLOW_LINKS) && Files.size(manifest) <= 4L * 1024 * 1024) {
            "Bundled Ghidra is missing at $root; rebuild or reinstall the complete application distribution"
        }
        val expectedPaths = mutableSetOf<String>()
        Files.readAllLines(manifest).forEach { record ->
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
                require(!Files.isSymbolicLink(component)) { "Linked bundled Ghidra file: $relative" }
                component = checkNotNull(component.parent)
            }
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "Missing bundled Ghidra file: $relative" }
            val digest = MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
                val buffer = ByteArray(65536)
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    digest.update(buffer, 0, count)
                }
            }
            require(digest.digest().joinToString("") { "%02x".format(it) } == record.substring(0, 64)) {
                "Corrupt bundled Ghidra file: $relative"
            }
        }
        val actualPaths = Files.walk(root).use { paths ->
            paths.filter { !Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) && it != manifest }
                .map { root.relativize(it).joinToString("/") }.toList().toSet()
        }
        require(actualPaths == expectedPaths && "decomp-ghidra-bridge.jar" in expectedPaths) { "Bundled Ghidra file inventory changed" }
        val properties = Properties().apply { Files.newInputStream(release.resolve("Ghidra/application.properties")).use(::load) }
        require(properties.getProperty("application.version") == VERSION && properties.getProperty("application.release.name") == "PUBLIC") {
            "Bundled Ghidra version does not match the application"
        }
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

private fun Path.absolute(): String = toAbsolutePath().normalize().toString()
