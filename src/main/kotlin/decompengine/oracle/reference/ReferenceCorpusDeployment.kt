package decompengine.oracle.reference

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeFunctionObservationClassPathEntry
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeMount
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Explicit deployment pins; parsing bytes alone does not authenticate their deployment authority. */
internal class ReferenceCorpusDeployment private constructor(
    val configuration: FullTreeFunctionObservationIsolationConfiguration,
    val expectedCgroupParent: String,
) {
    companion object {
        private const val MAXIMUM_BYTES = 256 * 1024
        private val LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_BYTES,
            maximumCanonicalBytes = MAXIMUM_BYTES, maximumDepth = 8, maximumNodes = 4096,
            maximumStringBytes = 4096, maximumTotalStringBytes = 192 * 1024)

        /** Production entry: the provisioner, not the current caller's host discovery, supplies pins. */
        fun open(path: Path): ReferenceCorpusDeployment {
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path) {
                "reference deployment must be a canonical absolute regular file"
            }
            requireTrustedPath(path)
            return StableControlFile.open(path, MAXIMUM_BYTES.toLong(), "reference deployment").use { file ->
                file.requireSingleLink("reference deployment")
                val deployment = parseCanonical(file.readExactly(0, file.size.toInt(), "reference deployment"))
                requireTrustedPath(path)
                file.verifyUnchanged("reference deployment")
                deployment
            }
        }

        /** Syntax-only helper. It never measures files or confers runtime admission. */
        internal fun parseCanonical(bytes: ByteArray): ReferenceCorpusDeployment {
            val root = OracleJson.parseCanonical(bytes, LIMITS).objectValue("deployment")
            root.fields("schemaVersion", "configuration", "expectedCgroupParent")
            require(root.string("schemaVersion") == "reference-corpus-deployment-v1") { "unsupported reference deployment schema" }
            val parent = ReferenceCorpusCoordinator.canonicalControlGroupParent(root.string("expectedCgroupParent"))
            val config = root.getValue("configuration").objectValue("configuration")
            config.fields("javaExecutable", "javaRuntime", "systemLibraryMounts", "bubblewrapExecutable",
                "resourceLimiterExecutable", "scopeSupervisorExecutable", "scopeInspectorExecutable",
                "systemdBusControllerExecutable", "systemdUserRuntimeDirectory", "workerClassPath",
                "expectedJavaSha256", "expectedBubblewrapSha256", "expectedResourceLimiterSha256",
                "expectedScopeSupervisorSha256", "expectedScopeInspectorSha256", "expectedSystemdBusControllerSha256")
            val mounts = config.array("systemLibraryMounts", 1, 16).map { mount(it) }
            val classPath = config.array("workerClassPath", 1, 512).map {
                val entry = it.objectValue("class path entry")
                entry.fields("path", "expectedSha256")
                FullTreeFunctionObservationClassPathEntry(entry.path("path"), entry.digest("expectedSha256"))
            }
            require(classPath.map { it.path }.distinct().size == classPath.size) { "reference deployment repeats a class path entry" }
            return ReferenceCorpusDeployment(FullTreeFunctionObservationIsolationConfiguration(
                javaExecutable = config.path("javaExecutable"), javaRuntime = mount(config.getValue("javaRuntime")),
                systemLibraryMounts = mounts, bubblewrapExecutable = config.path("bubblewrapExecutable"),
                resourceLimiterExecutable = config.path("resourceLimiterExecutable"),
                scopeSupervisorExecutable = config.path("scopeSupervisorExecutable"),
                scopeInspectorExecutable = config.path("scopeInspectorExecutable"),
                systemdBusControllerExecutable = config.path("systemdBusControllerExecutable"),
                systemdUserRuntimeDirectory = config.path("systemdUserRuntimeDirectory"), workerClassPath = classPath,
                expectedJavaSha256 = config.digest("expectedJavaSha256"),
                expectedBubblewrapSha256 = config.digest("expectedBubblewrapSha256"),
                expectedResourceLimiterSha256 = config.digest("expectedResourceLimiterSha256"),
                expectedScopeSupervisorSha256 = config.digest("expectedScopeSupervisorSha256"),
                expectedScopeInspectorSha256 = config.digest("expectedScopeInspectorSha256"),
                expectedSystemdBusControllerSha256 = config.digest("expectedSystemdBusControllerSha256"),
            ), parent)
        }

        private fun mount(value: JsonElement): FullTreeFunctionObservationRuntimeMount {
            val entry = value.objectValue("runtime mount")
            entry.fields("source", "destination", "expectedManifestSha256")
            return FullTreeFunctionObservationRuntimeMount(entry.path("source"), entry.path("destination"),
                entry.digest("expectedManifestSha256"))
        }

        private fun requireTrustedPath(path: Path) {
            var current: Path? = path
            while (current != null) {
                val attributes = Files.readAttributes(current, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
                val uid = (Files.getAttribute(current, "unix:uid", NOFOLLOW_LINKS) as Number).toLong()
                val mode = (Files.getAttribute(current, "unix:mode", NOFOLLOW_LINKS) as Number).toInt()
                require(!attributes.isSymbolicLink && uid == 0L && mode and 0x12 == 0 &&
                    if (current == path) attributes.isRegularFile else attributes.isDirectory) {
                    "reference deployment requires root ownership and nonwritable trusted ancestry: $current"
                }
                current = current.parent
            }
        }
    }
}

private fun JsonElement.objectValue(label: String): JsonObject = this as? JsonObject
    ?: error("reference $label must be an object")
private fun JsonObject.fields(vararg names: String) = require(keys == names.toSet()) { "reference deployment fields differ" }
private fun JsonObject.string(name: String): String = (getValue(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: error("reference deployment $name must be a string")
private fun JsonObject.path(name: String): Path {
    val raw = string(name)
    require(raw.length in 1..4096 && raw.none { it.code < 32 || it.code == 127 }) { "invalid reference deployment path" }
    val path = Path.of(raw)
    require(path.isAbsolute && path.normalize() == path && path.toString() == raw && path != Path.of("/")) {
        "reference deployment $name must be an exact normalized absolute non-root path"
    }
    return path
}
private fun JsonObject.digest(name: String): String = string(name).also {
    require(it.matches(Regex("[0-9a-f]{64}"))) { "reference deployment $name must be an explicit SHA-256 pin" }
}
private fun JsonObject.array(name: String, minimum: Int, maximum: Int): JsonArray =
    (getValue(name) as? JsonArray)?.also { require(it.size in minimum..maximum) { "reference deployment $name exceeds its entry bound" } }
        ?: error("reference deployment $name must be an array")
