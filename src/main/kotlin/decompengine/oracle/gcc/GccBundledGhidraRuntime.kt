package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraInvocation
import decompengine.analysis.GhidraPostScript
import decompengine.analysis.GhidraWorkerCommand
import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Path
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Candidate metadata only; the retained deployment independently authenticates both identities. */
internal data class GccBundledNativeCallCollectorIdentityV1(
    val sourceBytes: Long, val sourceSha256: String, val classBytes: Long, val classSha256: String,
) {
    init {
        require(sourceBytes in 1..4L * 1024 * 1024 && classBytes in 1..128L * 1024 * 1024) {
            "native call collector identity exceeds its byte bound"
        }
        require(listOf(sourceSha256, classSha256).all { it.matches(Regex("[a-f0-9]{64}")) }) {
            "native call collector digest is invalid"
        }
    }

    fun toJson(): JsonObject = JsonObject(mapOf(
        "sourceBytes" to JsonPrimitive(sourceBytes), "sourceSha256" to JsonPrimitive(sourceSha256),
        "classBytes" to JsonPrimitive(classBytes), "classSha256" to JsonPrimitive(classSha256),
    ))
}

internal data class GccBundledGhidraClassPathEntry(val path: Path, val bytes: Long, val sha256: String) {
    init {
        requireRuntimePath(path)
        require(bytes in 1..128L * 1024 * 1024) { "bundled Ghidra classpath entry exceeds its byte bound" }
        require(sha256.matches(Regex("[a-f0-9]{64}"))) { "bundled Ghidra classpath digest is invalid" }
    }
}

internal class GccBundledGhidraRuntime(
    val root: Path,
    classPath: List<GccBundledGhidraClassPathEntry>,
    val invocationVersion: Int = 3,
    val nativeCallCollector: GccBundledNativeCallCollectorIdentityV1? = null,
    val interfaceCollector: GccBundledInterfaceRuntimeIdentityV1? = null,
) {
    val recoveryMode: String = if (invocationVersion >= 5) "full" else "planning"
    val runtimeDiagnostics: Boolean = invocationVersion == 7
    val workerOperation: String = if (runtimeDiagnostics) "analyze-diagnostics-v1" else "analyze"
    val diagnosticPolicy: String? = if (runtimeDiagnostics) "jvm-mxbean-stdout-v1" else null
    val maximumJavaHeapBytes: Long = 2L * 1024 * 1024 * 1024
    private val parallelRecovery: Boolean = invocationVersion in setOf(6, 7)
    val processorCount: Int = if (parallelRecovery) 4 else 1
    val analysisThreadCount: Int = if (parallelRecovery) 4 else 1
    val decompilerWorkerCount: Int = if (parallelRecovery) 4 else 1
    val classPath: List<GccBundledGhidraClassPathEntry>
    val release: Path

    init {
        require(invocationVersion in 1..9) { "bundled Ghidra invocation version is unsupported" }
        require((invocationVersion == 8) == (nativeCallCollector != null)) {
            "native call collector identity requires its distinct runtime invocation"
        }
        require((invocationVersion == 9) == (interfaceCollector != null)) {
            "interface collector identity requires its distinct runtime invocation"
        }
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

    fun requireArtifacts(artifacts: List<GccCompilerEngineContainmentArtifactIdentity>) {
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
        require(artifacts.none { it.path.startsWith(root) && it.role !in BUNDLE_ROLES }) {
            "non-bundle input overlaps the bundled Ghidra runtime"
        }
    }

    /** Fresh leg only: choose before command hashing to avoid a self-referential JVM temp path. */
    fun freshControlDirectoryName(outputRoot: Path): String? {
        require(invocationVersion != 4) { "resume runtime cannot select a fresh-leg control directory" }
        requireRuntimePath(outputRoot)
        if (invocationVersion < 3) return null
        val digest = OracleArtifacts.sha256("gcc-bundled-fresh-control-v1\n$outputRoot".toByteArray(Charsets.UTF_8))
        return "control-$digest"
    }

    /** Definition construction only; the retained owner must authenticate the manifest before START. */
    fun resumeControlDirectoryName(
        state: GccCompilerEngineAnalysisStateIdentity,
        lease: GccCompilerEngineOutputLeaseIdentity,
    ): String {
        require(invocationVersion == 4 && state.mode == GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST) {
            "resume control selection requires the explicit reanalysis invocation and stopped manifest"
        }
        require(state.path == lease.path.resolve("state")) { "resume manifest must describe the original analysis-state directory" }
        val digest = OracleArtifacts.sha256(
            "gcc-bundled-resume-control-v1\n${lease.path}\n${state.manifestSha256}".toByteArray(Charsets.UTF_8),
        )
        return "control-$digest"
    }

    fun command(
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        state: GccCompilerEngineAnalysisStateIdentity,
        lease: GccCompilerEngineOutputLeaseIdentity,
        runKind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
    ): List<String> {
        require(!runtimeDiagnostics || runKind == GccCompilerEngineContainmentRunKind.FRESH_CONTROL) {
            "bundled Ghidra runtime diagnostics require fresh uninterrupted execution"
        }
        val resumed = invocationVersion == 4
        require(state.mode == if (resumed) GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST
            else GccCompilerEngineAnalysisStateMode.FRESH_EMPTY) {
            "bundled Ghidra state mode differs from its versioned invocation"
        }
        requireArtifacts(artifacts)
        require(!root.startsWith(lease.path) && !lease.path.startsWith(root)) { "bundled Ghidra runtime overlaps writable output" }
        val byRole = artifacts.associateBy { it.role }
        val exporter = byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE)
        val archive = byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)
        require(invocationVersion < 5 || runKind != GccCompilerEngineContainmentRunKind.INTERRUPTED) {
            "full-recovery export does not support planning checkpoint interruption"
        }
        require(invocationVersion !in setOf(8, 9) || runKind == GccCompilerEngineContainmentRunKind.FRESH_CONTROL) {
            "native call observations require a fresh uninterrupted operation"
        }
        val controlName = if (resumed) resumeControlDirectoryName(state, lease) else freshControlDirectoryName(lease.path)
        val controlRoot = controlName?.let(lease.path::resolve) ?: lease.path
        val project = if (resumed) controlRoot.resolve("state") else state.path
        val exporterArguments = listOf(
            exporter.sha256, archive.sha256, recoveryMode,
            lease.path.resolve("reports/program_model.json").toString(),
        ) + if (runKind == GccCompilerEngineContainmentRunKind.INTERRUPTED && invocationVersion >= 3) {
            listOf("hold-first-planning-checkpoint-v1")
        } else if (parallelRecovery) {
            listOf("full-recovery-workers-v1:$decompilerWorkerCount")
        } else emptyList()
        interfaceCollector?.let { require(it.exporterSha256 == exporter.sha256 && it.source("model").bytes == exporter.bytes) {
            "interface runtime source closure differs from the paired exporter"
        } }
        val postScripts = listOf(GhidraPostScript("ExportProgramModel.java", exporterArguments)) +
            if (invocationVersion == 8) listOf(GhidraPostScript("ExportNativeCallsV1.class", listOf(
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256,
                exporter.sha256, archive.sha256, checkNotNull(nativeCallCollector).sourceSha256,
                lease.path.resolve("reports/program_model.json").toString(),
                lease.path.resolve("reports/native-calls-v1").toString(),
            ))) else if (invocationVersion == 9) {
                val identity = checkNotNull(interfaceCollector)
                val input = byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256
                val model = lease.path.resolve("reports/program_model.json").toString()
                val listing = lease.path.resolve("reports/native-interfaces-v1").toString()
                listOf(GhidraPostScript("ExportNativeInterfacesV1.class", listOf(input, exporter.sha256,
                    archive.sha256, identity.listingCollectorSha256, model, listing)),
                    GhidraPostScript("ExportInferredInterfacesV1.class", listOf(input, exporter.sha256,
                        archive.sha256, identity.listingCollectorSha256, identity.inferredCollectorSha256,
                        identity.typeGraphSha256, identity.wrapperSha256, identity.nativeDecompilerSha256,
                        model, listing, lease.path.resolve("reports/native-inferred-interfaces-v1").toString())))
            } else emptyList()
        val invocation = GhidraInvocation(
            project, "archival_reconstruction",
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path,
            exporter.path.parent,
            postScripts,
        )
        val prefix = GhidraWorkerCommand.prefix(
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE).path,
            release, classPath.map { it.path },
        )
        val temporaryDirectory = controlRoot.resolve("tmp")
        val isolatedPrefix = if (invocationVersion >= 2) {
            listOf(
                prefix.first(), "-Duser.home=${temporaryDirectory}", "-Djava.io.tmpdir=${temporaryDirectory}",
                "-XX:ActiveProcessorCount=$processorCount", "-XX:+DisableAttachMechanism",
            ) + (if (parallelRecovery) listOf("-Dcpu.core.override=$analysisThreadCount") else emptyList()) + prefix.drop(1)
        } else {
            prefix
        }
        val arguments = invocation.arguments()
        return isolatedPrefix + if (runtimeDiagnostics) listOf(workerOperation) + arguments.drop(1) else arguments
    }

    fun toJson(): JsonObject = JsonObject(mapOf(
        "provider" to JsonPrimitive("$PROVIDER_PREFIX$invocationVersion"),
        "root" to JsonPrimitive(root.toString()),
        "classPath" to JsonArray(classPath.map { entry -> JsonObject(mapOf(
            "path" to JsonPrimitive(entry.path.toString()),
            "bytes" to JsonPrimitive(entry.bytes),
            "sha256" to JsonPrimitive(entry.sha256),
        )) }),
    ) + (if (parallelRecovery) mapOf(
        "processorCount" to JsonPrimitive(processorCount),
        "analysisThreadCount" to JsonPrimitive(analysisThreadCount),
        "decompilerWorkerCount" to JsonPrimitive(decompilerWorkerCount),
    ) else emptyMap()) + (if (runtimeDiagnostics) mapOf(
        "workerOperation" to JsonPrimitive(workerOperation),
        "diagnosticPolicy" to JsonPrimitive(diagnosticPolicy),
        "maximumJavaHeapBytes" to JsonPrimitive(maximumJavaHeapBytes),
    ) else emptyMap()) + (nativeCallCollector?.let { mapOf("nativeCallCollector" to it.toJson()) } ?: emptyMap()) + (interfaceCollector?.let { mapOf("interfaceCollector" to it.toJson()) } ?: emptyMap()))

    companion object {
        private const val PROVIDER_PREFIX = "bundled-ghidra-java-api-runtime-v"
        private val BUNDLE_ROLES = setOf(
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST,
        )

        fun parse(document: JsonObject): GccBundledGhidraRuntime {
            val version = when (document.strictString("provider")) {
                "${PROVIDER_PREFIX}1" -> 1
                "${PROVIDER_PREFIX}2" -> 2
                "${PROVIDER_PREFIX}3" -> 3
                "${PROVIDER_PREFIX}4" -> 4
                "${PROVIDER_PREFIX}5" -> 5
                "${PROVIDER_PREFIX}6" -> 6
                "${PROVIDER_PREFIX}7" -> 7
                "${PROVIDER_PREFIX}8" -> 8
                "${PROVIDER_PREFIX}9" -> 9
                else -> throw IllegalArgumentException("bundled Ghidra runtime provider is invalid")
            }
            val throughputFields = setOf("processorCount", "analysisThreadCount", "decompilerWorkerCount")
            val diagnosticFields = setOf("workerOperation", "diagnosticPolicy", "maximumJavaHeapBytes")
            require(document.keys == setOf("provider", "root", "classPath") +
                (if (version in setOf(6, 7)) throughputFields else emptySet()) +
                (if (version == 7) diagnosticFields else emptySet()) +
                (if (version == 8) setOf("nativeCallCollector") else emptySet()) +
                (if (version == 9) setOf("interfaceCollector") else emptySet())) { "bundled Ghidra runtime fields are invalid" }
            if (version in setOf(6, 7)) throughputFields.forEach { name ->
                val value = document[name] as? JsonPrimitive
                require(value != null && !value.isString && value.content == "4") {
                    "bundled Ghidra runtime throughput count is unsupported"
                }
            }
            if (version == 7) {
                require(document.strictString("workerOperation") == "analyze-diagnostics-v1" &&
                    document.strictString("diagnosticPolicy") == "jvm-mxbean-stdout-v1" &&
                    document["maximumJavaHeapBytes"] == JsonPrimitive(2L * 1024 * 1024 * 1024)
                ) { "bundled Ghidra diagnostic policy is unsupported" }
            }
            val collector = if (version == 8) {
                val value = document["nativeCallCollector"] as? JsonObject
                    ?: throw IllegalArgumentException("native call collector identity must be an object")
                require(value.keys == setOf("sourceBytes", "sourceSha256", "classBytes", "classSha256")) {
                    "native call collector identity fields are invalid"
                }
                fun number(name: String): Long {
                    val item = value[name] as? JsonPrimitive
                    require(item != null && !item.isString) { "native call collector size must be an integer" }
                    return requireNotNull(item.longOrNull)
                }
                GccBundledNativeCallCollectorIdentityV1(number("sourceBytes"), value.strictString("sourceSha256"),
                    number("classBytes"), value.strictString("classSha256"))
            } else null
            val interfaces = if (version == 9) GccBundledInterfaceRuntimeIdentityV1.parse(
                document["interfaceCollector"] as? JsonObject
                    ?: throw IllegalArgumentException("interface collector identity must be an object")) else null
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
            }, version, collector, interfaces)
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
