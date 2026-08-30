package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlinx.serialization.json.JsonObject

internal data class FullTreeControlFixture(
    val root: Path,
    val richArtifact: Path,
    val sourceArchive: Path,
    val sourceLock: Path,
    val buildRecord: Path,
    val manifest: Path,
    val scope: Path,
    val inventory: Path,
    val sourceInventory: Path,
) {
    fun authenticatedScope(limits: FullTreeControlLimits = FullTreeControlLimits()): AuthenticatedFullTreeScope =
        FullTreeScopeControl.load(scope, sourceLock, manifest, limits)
}

internal fun createFullTreeControlFixture(root: Path): FullTreeControlFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    fun write(name: String, bytes: ByteArray): Path = root.resolve(name).also { path ->
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
    }
    val rich = write("rich.elf", Base64.getMimeDecoder().decode(fullTreeControlResource("rich.elf.b64")))
    val archive = write(
        "source.tar.xz",
        Base64.getMimeDecoder().decode(fullTreeControlResource("source.tar.xz.b64")),
    )
    return FullTreeControlFixture(
        root,
        rich,
        archive,
        write("source-lock.json", fullTreeControlResource("source-lock.json")),
        write("build-record.json", fullTreeControlResource("build-record.json")),
        write("manifest.json", fullTreeControlResource("manifest.json")),
        write("scope.json", fullTreeControlResource("scope.json")),
        write("inventory.json", fullTreeControlResource("inventory.json")),
        write("source-inventory.json", fullTreeControlResource("source-inventory.json")),
    )
}

internal fun fullTreeControlResource(name: String): ByteArray = checkNotNull(
    FullTreeControlFixture::class.java.getResourceAsStream("/oracle/control-plane-v1/$name"),
) { "control-plane fixture $name is unavailable" }.use { it.readAllBytes() }

internal fun parseControlObject(path: Path, maximumBytes: Int = 64 * 1024 * 1024): JsonObject =
    OracleJson.parseCanonical(Files.readAllBytes(path), controlJsonLimits(maximumBytes)) as JsonObject

internal fun writeControlObject(path: Path, value: JsonObject, maximumBytes: Int = 64 * 1024 * 1024) {
    Files.write(path, OracleJson.canonicalBytes(value, controlJsonLimits(maximumBytes)))
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
}

internal fun fixtureSha256(path: Path): String = OracleArtifacts.sha256(Files.readAllBytes(path))

internal fun authenticatedScopeWithDocument(
    original: AuthenticatedFullTreeScope,
    document: JsonObject,
): AuthenticatedFullTreeScope = AuthenticatedFullTreeScope(
    document = document,
    sha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(document)),
    sourceLock = original.sourceLock,
    sourceLockSha256 = original.sourceLockSha256,
    artifactManifest = original.artifactManifest,
    artifactManifestSha256 = original.artifactManifestSha256,
)

internal inline fun <T> inControlTemporaryDirectory(block: (Path) -> T): T {
    val directory = kotlin.io.path.createTempDirectory("full-tree-control-")
    return try {
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        block(directory)
    } finally {
        if (Files.exists(directory)) {
            val paths = Files.walk(directory).use { it.toList() }
            paths.filter { path -> Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) }.forEach { path ->
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }
}
