package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Properties

internal object OracleNativeLibraries {
    private val policyBytes = checkNotNull(javaClass.getResourceAsStream("/oracle-native-libraries-v1.properties"))
        .use { it.readNBytes(8193) }.also { require(it.size in 1..8192) }
    private val policy = Properties().apply { policyBytes.inputStream().use(::load) }
    val policySha256: String = OracleArtifacts.sha256(policyBytes)
    val relativeDirectory: String = property("relativeDirectory")

    private data class Library(val name: String, val bytes: Long, val sha256: String, val artifactSha256: String)

    private val libraries = listOf("jna", "sqlite").map { prefix ->
        Library(property("$prefix.name"), property("$prefix.bytes").toLong(),
            property("$prefix.sha256"), property("$prefix.artifactSha256"))
    }

    init {
        require(property("schemaVersion") == "1" && property("platform") == "linux-x86-64")
        require(relativeDirectory == "lib/decomp-oracle-native")
        require(libraries.map { it.name } == listOf("libjnidispatch.so", "libsqlitejdbc.so"))
        libraries.forEach {
            require(it.bytes in 1..MAXIMUM_LIBRARY_BYTES && it.sha256.matches(Regex("[0-9a-f]{64}")))
            require(it.artifactSha256.matches(Regex("[0-9a-f]{64}")))
        }
    }

    fun requireCurrent(nativeDirectory: Path, classPathDigests: List<String>) {
        require(System.getProperty("os.name").lowercase().contains("linux") &&
            System.getProperty("os.arch") in setOf("amd64", "x86_64")) { "Oracle native profile requires Linux x86-64" }
        libraries.forEach { library ->
            require(classPathDigests.count { it == library.artifactSha256 } == 1) {
                "Oracle native library does not have exactly one pinned dependency JAR: ${library.name}"
            }
        }
        require(Files.isDirectory(nativeDirectory, LinkOption.NOFOLLOW_LINKS) && nativeDirectory.toRealPath() == nativeDirectory) {
            "Provision the authenticated oracle native libraries at $nativeDirectory; scratch must remain noexec"
        }
        val names = Files.newDirectoryStream(nativeDirectory).use { entries -> entries.map { it.fileName.toString() }.toSet() }
        require(names == libraries.map { it.name }.toSet()) { "Oracle native library directory membership changed" }
        libraries.forEach { library ->
            StableControlFile.open(nativeDirectory.resolve(library.name), MAXIMUM_LIBRARY_BYTES, "oracle native ${library.name}").use { file ->
                require(file.size == library.bytes && file.authenticatedSha256 == library.sha256) {
                    "Oracle native library differs from its pinned dependency resource: ${library.name}"
                }
            }
        }
    }

    fun jvmArguments(nativeDirectory: Path): List<String> {
        require(nativeDirectory.isAbsolute && nativeDirectory.normalize() == nativeDirectory)
        return listOf(
            "-Djna.nosys=true", "-Djna.nounpack=true", "-Djna.boot.library.path=$nativeDirectory",
            "-Dorg.sqlite.lib.path=$nativeDirectory", "-Dorg.sqlite.lib.name=libsqlitejdbc.so",
        )
    }

    private fun property(name: String): String = checkNotNull(policy.getProperty(name)) { "Missing oracle native profile field: $name" }
    private const val MAXIMUM_LIBRARY_BYTES = 16L * 1024 * 1024
}
