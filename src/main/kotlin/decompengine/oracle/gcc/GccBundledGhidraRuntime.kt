package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraInvocation
import decompengine.analysis.GhidraPostScript
import decompengine.analysis.GhidraWorkerCommand
import java.nio.file.Path
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal data class GccBundledGhidraClassPathEntry(val path: Path, val bytes: Long, val sha256: String) {
    init {
        requireRuntimePath(path)
        require(bytes in 1..128L * 1024 * 1024) { "bundled Ghidra classpath entry exceeds its byte bound" }
        require(sha256.matches(Regex("[a-f0-9]{64}"))) { "bundled Ghidra classpath digest is invalid" }
    }
}

internal class GccBundledGhidraRuntime(val root: Path, classPath: List<GccBundledGhidraClassPathEntry>) {
    val classPath: List<GccBundledGhidraClassPathEntry>
    val release: Path

    init {
        requireRuntimePath(root)
        val copied = ArrayList<GccBundledGhidraClassPathEntry>()
        for (entry in classPath) {
            require(copied.size < 512) { "bundled Ghidra classpath exceeds its entry bound" }
            copied.add(entry)
        }
        require(copied.size >= 2 && copied.sumOf { it.bytes } <= 2L * 1024 * 1024 * 1024) {
            "bundled Ghidra classpath is incomplete or exceeds its aggregate byte bound"
        }
        require(copied.map { it.path }.distinct().size == copied.size) { "bundled Ghidra classpath contains duplicates" }
        release = root.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC")
        require(copied.first().path == root.resolve("decomp-ghidra-bridge.jar")) { "bundled Ghidra bridge must lead its classpath" }
        val libraries = copied.drop(1).map { it.path }
        require(libraries == libraries.sorted() && libraries.all {
            it.startsWith(release.resolve("Ghidra")) && it.parent.fileName.toString() == "lib" && it.fileName.toString().endsWith(".jar")
        }) { "bundled Ghidra library classpath is not canonical" }
        this.classPath = Collections.unmodifiableList(copied)
    }

    fun command(
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        state: GccCompilerEngineAnalysisStateIdentity,
        lease: GccCompilerEngineOutputLeaseIdentity,
    ): List<String> {
        require(state.mode == GccCompilerEngineAnalysisStateMode.FRESH_EMPTY) {
            "bundled Ghidra runtime has no authenticated saved-state resume invocation"
        }
        val byRole = artifacts.associateBy { it.role }
        fun artifact(role: GccCompilerEngineContainmentArtifactRole) = byRole.getValue(role)
        val bridge = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR)
        val guard = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD)
        val exporter = artifact(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE)
        val archive = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)
        require(classPath.first() == GccBundledGhidraClassPathEntry(bridge.path, bridge.bytes, bridge.sha256)) {
            "bundled Ghidra bridge identity differs from its classpath"
        }
        require(guard.path == root.resolve("scripts/RunBundledExports.class")) { "bundled Ghidra export guard path is invalid" }
        require(artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST).path == root.resolve("bundle.sha256")) {
            "bundled Ghidra inventory must belong to the selected application bundle"
        }
        require(archive.sha256 == BundledGhidra.ARCHIVE_SHA256) { "bundled Ghidra release archive differs from the reviewed runtime" }
        require(exporter.path.fileName.toString() == "ExportProgramModel.java") { "bundled Ghidra exporter source path is invalid" }
        require(!root.startsWith(lease.path) && !lease.path.startsWith(root)) { "bundled Ghidra runtime overlaps writable output" }
        require(artifacts.none { it.path.startsWith(root) && it.role !in BUNDLE_ROLES }) {
            "non-bundle input overlaps the bundled Ghidra runtime"
        }
        val invocation = GhidraInvocation(
            state.path, "archival_reconstruction",
            artifact(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path,
            exporter.path.parent,
            listOf(GhidraPostScript("ExportProgramModel.java", listOf(
                exporter.sha256, archive.sha256, "planning", lease.path.resolve("reports/program_model.json").toString(),
            ))),
        )
        return GhidraWorkerCommand.prefix(
            artifact(GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE).path,
            release, classPath.map { it.path },
        ) + invocation.arguments()
    }

    fun toJson(): JsonObject = JsonObject(mapOf(
        "provider" to JsonPrimitive(PROVIDER),
        "root" to JsonPrimitive(root.toString()),
        "classPath" to JsonArray(classPath.map { entry -> JsonObject(mapOf(
            "path" to JsonPrimitive(entry.path.toString()),
            "bytes" to JsonPrimitive(entry.bytes),
            "sha256" to JsonPrimitive(entry.sha256),
        )) }),
    ))

    companion object {
        private const val PROVIDER = "bundled-ghidra-java-api-runtime-v1"
        private val BUNDLE_ROLES = setOf(
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST,
        )

        fun parse(document: JsonObject): GccBundledGhidraRuntime {
            require(document.keys == setOf("provider", "root", "classPath")) { "bundled Ghidra runtime fields are invalid" }
            require(document.strictString("provider") == PROVIDER) { "bundled Ghidra runtime provider is invalid" }
            val entries = document["classPath"] as? JsonArray
                ?: throw IllegalArgumentException("bundled Ghidra classpath must be an array")
            require(entries.size in 2..512) { "bundled Ghidra classpath count is invalid" }
            return GccBundledGhidraRuntime(Path.of(document.strictString("root")), entries.map { value ->
                val entry = value as? JsonObject ?: throw IllegalArgumentException("bundled Ghidra classpath entry must be an object")
                require(entry.keys == setOf("path", "bytes", "sha256")) { "bundled Ghidra classpath fields are invalid" }
                val size = entry["bytes"] as? JsonPrimitive
                require(size != null && !size.isString) { "bundled Ghidra classpath size must be an integer" }
                GccBundledGhidraClassPathEntry(
                    Path.of(entry.strictString("path")), requireNotNull(size.longOrNull), entry.strictString("sha256"),
                )
            })
        }
    }
}

private fun requireRuntimePath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path != Path.of("/") && path.nameCount <= 32 &&
        path.toString().length <= 4096 && path.toString().none { it.code < 32 || it.code == 127 || it == ':' || it == '\\' }
    ) { "bundled Ghidra runtime path is not canonical" }
}

private fun JsonObject.strictString(name: String): String {
    val value = this[name] as? JsonPrimitive
    require(value != null && value.isString) { "bundled Ghidra runtime $name must be a string" }
    return value.content
}
