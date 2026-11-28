package decompengine.analysis

import java.nio.file.FileSystems
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.util.jar.JarFile

/**
 * The packaged decomp-export-supervisor, authenticated against the reference this application was
 * built with and pinned by descriptor for one launch, as the analysis I/O helper is.
 *
 * Linux is the production platform: there the supervisor is mandatory, and a missing or mismatched
 * helper fails the launch. Other hosts cannot run it and keep the retained-handle cleanup.
 */
internal object ExportSupervisorHelper {
    internal const val BINARY_NAME = "decomp-export-supervisor"
    internal const val HELPER_PROPERTY = "decompengine.export.supervisor"
    internal const val MAXIMUM_LEFTOVER_GRACE_MILLIS = 1000L
    private const val RESOURCE_DIRECTORY = "export-supervisor"
    private const val PROPERTIES_NAME = "decomp-export-supervisor-v1.properties"
    private const val MAXIMUM_HELPER_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_PROPERTIES_BYTES = 4 * 1024
    private val propertyKeys = setOf("schemaVersion", "binaryName", "architecture", "helperBytes", "helperSha256", "sourceSha256")
    private val sha256Pattern = Regex("[0-9a-f]{64}")
    private val pins = AnalysisNativeIoExecutablePins()

    /** Whether exports on this host must run under the supervisor. */
    fun required(operatingSystem: String = System.getProperty("os.name", "")): Boolean =
        operatingSystem.equals("Linux", ignoreCase = true)

    /** The pinned supervisor command for [worker]; see [AnalysisNativeIoHelper.beforeLaunch] for its lifecycle. */
    fun command(worker: List<String>, leftoverGraceMillis: Long): List<String> = commandAt(null, worker, leftoverGraceMillis)

    /** Fixed verification seam: an alternate path is still checked against this application's reference. */
    internal fun commandAt(override: Path?, worker: List<String>, leftoverGraceMillis: Long): List<String> {
        AnalysisNativeIoHelper.requireSupportedHost()
        require(leftoverGraceMillis in 0..MAXIMUM_LEFTOVER_GRACE_MILLIS) { "export supervisor leftover grace is out of range" }
        require(worker.isNotEmpty() && worker.all { it.isNotEmpty() && '\u0000' !in it } && Path.of(worker.first()).isAbsolute) {
            "export supervisor requires an absolute worker executable"
        }
        val origin = codeOrigin()
        val reference = readReference(origin)
        val helper = override ?: selectedHelper(origin)
        return AnalysisNativeIoHelper.pinExecutable(helper, "export supervisor", MAXIMUM_HELPER_BYTES, pins,
            listOf(leftoverGraceMillis.toString()) + worker) { bytes, opened -> verifyArtifact(helper, reference, bytes, opened) }
    }

    /** Read-only installed-artifact seam; no descriptor or execution permission is transferred. */
    internal fun verifiedDefaultArtifact(): Path {
        AnalysisNativeIoHelper.requireSupportedHost()
        val origin = codeOrigin()
        val helper = selectedHelper(origin)
        verifyArtifact(helper, readReference(origin), AnalysisNativeIoHelper.readStableFile(helper, MAXIMUM_HELPER_BYTES))
        return helper
    }

    private fun codeOrigin(): Path =
        Path.of(ExportSupervisorHelper::class.java.protectionDomain.codeSource.location.toURI()).toAbsolutePath()

    private fun selectedHelper(origin: Path): Path {
        val configured = System.getProperty(HELPER_PROPERTY)
        return if (configured != null) {
            require(configured.isNotBlank()) { "export supervisor override is empty" }
            Path.of(configured).toAbsolutePath()
        } else if (Files.isDirectory(origin, LinkOption.NOFOLLOW_LINKS)) {
            val build = AnalysisNativeIoHelper.developmentBuildRoot(origin)
                ?: throw IllegalArgumentException("export supervisor requires its packaged application resources")
            build.resolve("native/export").resolve(BINARY_NAME)
        } else {
            requireNotNull(origin.parent?.parent).resolve("libexec").resolve(BINARY_NAME)
        }
    }

    private fun readReference(origin: Path): Map<String, String> {
        val bytes = if (Files.isDirectory(origin, LinkOption.NOFOLLOW_LINKS)) {
            // Only the sibling of this exact main output; classpath lookup could accept a shadow.
            val included = origin.resolve(RESOURCE_DIRECTORY)
            val root = if (Files.isDirectory(included, LinkOption.NOFOLLOW_LINKS)) included
                else AnalysisNativeIoHelper.developmentBuildRoot(origin)?.resolve("resources/main/$RESOURCE_DIRECTORY")
                    ?: throw IllegalArgumentException("export supervisor reference is outside its defining code origin")
            AnalysisNativeIoHelper.readStableFile(root.resolve(PROPERTIES_NAME), MAXIMUM_PROPERTIES_BYTES)
        } else {
            val before = AnalysisNativeIoHelper.regularAttributes(origin)
            require(before.size() in 1..(256L * 1024 * 1024)) { "application JAR exceeds its reference read bound" }
            val read = JarFile(origin.toFile(), false).use { jar ->
                val entry = jar.getJarEntry("$RESOURCE_DIRECTORY/$PROPERTIES_NAME")
                    ?: throw IllegalArgumentException("application JAR omits the export supervisor reference")
                require(!entry.isDirectory && entry.size in 1..MAXIMUM_PROPERTIES_BYTES.toLong())
                jar.getInputStream(entry).use { input ->
                    input.readNBytes(MAXIMUM_PROPERTIES_BYTES + 1).also { bytes ->
                        require(bytes.size.toLong() == entry.size && input.read() == -1)
                    }
                }
            }
            require(AnalysisNativeIoHelper.sameFile(before, AnalysisNativeIoHelper.regularAttributes(origin))) {
                "application JAR changed while reading the export supervisor reference"
            }
            read
        }
        val properties = AnalysisNativeIoHelper.parseProperties(bytes)
        require(properties.keys == propertyKeys && properties.getValue("schemaVersion") == "1" &&
            properties.getValue("binaryName") == BINARY_NAME && properties.getValue("architecture") == "linux-x86-64" &&
            sha256Pattern.matches(properties.getValue("helperSha256")) && sha256Pattern.matches(properties.getValue("sourceSha256")) &&
            properties.getValue("helperBytes").matches(Regex("[1-9][0-9]{0,7}"))) {
            "export supervisor reference has an unsupported identity"
        }
        return properties
    }

    private fun verifyArtifact(helper: Path, reference: Map<String, String>, bytes: ByteArray, opened: Path = helper) {
        require(helper.fileSystem === FileSystems.getDefault() && helper.isAbsolute && helper.fileName.toString() == BINARY_NAME) {
            "export supervisor path is not the packaged helper"
        }
        require(Files.isExecutable(opened)) { "export supervisor is not executable" }
        // Production follows only our /proc descriptor link, so these permissions belong to the opened image.
        val permissions = Files.getPosixFilePermissions(opened)
        require(PosixFilePermission.GROUP_WRITE !in permissions && PosixFilePermission.OTHERS_WRITE !in permissions) {
            "export supervisor is writable outside its owner"
        }
        require(bytes.size.toLong() == reference.getValue("helperBytes").toLong() &&
            AnalysisNativeIoHelper.digest(bytes) == reference.getValue("helperSha256")) {
            "export supervisor does not match the defining application's build"
        }
        AnalysisNativeIoHelper.verifyStaticElf(bytes, "export supervisor")
    }
}
