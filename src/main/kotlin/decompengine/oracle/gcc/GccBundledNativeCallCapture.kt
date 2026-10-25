package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.*
import decompengine.oracle.structural.FrozenNativeRecoveredCallPopulationV1
import decompengine.oracle.structural.NativeRecoveredCallPopulationLimitsV1
import decompengine.oracle.structural.NativeRecoveredCallPopulationV1
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import kotlinx.serialization.json.*

/** A descriptor capture is byte evidence. Only the retained coordinator can issue an operation. */
internal class GccBundledNativeCallSnapshot internal constructor(
    summary: NativeCallObservationSummaryV1,
    target: GccBundledNativeCallTargetEvidenceV1,
    val reportsIdentity: LinuxFileIdentity,
    val nativeIdentity: LinuxFileIdentity,
    val exportIdentity: LinuxFileIdentity,
    val controlName: String,
    val controlIdentity: LinuxFileIdentity,
    files: Map<String, GccNativeCallCapturedFile>,
    manifestBytes: ByteArray,
    assessmentBytes: ByteArray,
) {
    val summary = summary.copy(addressSpaces = java.util.List.copyOf(summary.addressSpaces))
    val target = target.copy(executableRanges = java.util.List.copyOf(target.executableRanges))
    internal val files: Map<String, GccNativeCallCapturedFile> = java.util.Collections.unmodifiableMap(
        files.mapValues { (_, file) -> file.copy(metadata = java.util.Collections.unmodifiableMap(HashMap(file.metadata))) },
    )
    val complete = false
    val scored = false
    val releaseEligible = false
    private val manifest = manifestBytes.copyOf()
    private val assessment = assessmentBytes.copyOf()
    val manifestBytes: ByteArray get() = manifest.copyOf()
    val assessmentBytes: ByteArray get() = assessment.copyOf()
}

internal data class GccNativeCallCapturedFile(
    val identity: LinuxFileIdentity,
    val metadata: Map<String, Any>,
)

/** Caller retains the run lease and has already proved worker and cgroup absence. */
internal object GccBundledNativeCallCapture {
    private const val DIRECTORY = "native-calls-v1"
    private val REPORT_NAMES = setOf("program_model.json.export", "program_model.json", "program_model.json.progress.json", DIRECTORY)
    private val NATIVE_NAMES = setOf("manifest.json", "native-calls.json")

    fun capture(
        run: LinuxDescriptor,
        expectedReports: LinuxFileIdentity,
        controlName: String,
        expectedControl: LinuxFileIdentity,
        model: GccBundledFullExportSnapshot,
        collectorSha256: String,
        target: GccBundledNativeCallTargetEvidenceV1,
        limits: NativeCallObservationLimitsV1 = NativeCallObservationLimitsV1(),
        checkpoint: () -> Unit,
    ): GccBundledNativeCallSnapshot {
        checkpoint()
        require(controlName.matches(Regex("control-[a-f0-9]{64}")))
        require(target.inputSha256 == model.inputSha256 && target.inputBytes == model.inputBytes &&
            target.languageId == model.language && target.compilerSpecId == model.compilerSpec) {
            "native capture target differs from its admitted model and pinned binary"
        }
        val runIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        require(runIdentity.copy(linkCount = run.identity.linkCount) == run.identity)
        requirePrivateDirectory(runIdentity, runIdentity)
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
            require(control.identity == expectedControl) { "native control differs from completed execution" }
            requirePrivateDirectory(control.identity, runIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                require(reports.identity.copy(linkCount = expectedReports.linkCount) == expectedReports)
                requirePrivateDirectory(reports.identity, runIdentity)
                LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, DIRECTORY).use { native ->
                    requirePrivateDirectory(native.identity, reports.identity)
                    LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "program_model.json.export").use { export ->
                        require(export.identity.isDirectory && !export.identity.isSymbolicLink &&
                            export.identity.uid == reports.identity.uid && export.identity.mountId == reports.identity.mountId &&
                            export.identity.mode.permissions and 0x12 == 0) {
                            "native paired model directory violates the existing full-export ownership policy"
                        }
                        fun verifyDirectories() {
                            checkpoint()
                            require(LinuxFilesystemSyscalls.identity(run.fd) == runIdentity)
                            requireNamedDirectory(run, controlName, control.identity)
                            requireNamedDirectory(run, "reports", reports.identity)
                            requireNamedDirectory(reports, DIRECTORY, native.identity)
                            requireNamedDirectory(reports, "program_model.json.export", export.identity)
                            requireNames(reports, REPORT_NAMES)
                            requireNames(native, NATIVE_NAMES)
                        }
                        verifyDirectories()
                        val pins = linkedMapOf<String, GccNativeCallCapturedFile>()
                        for ((directory, name, key, digest) in listOf(
                            FileToPin(reports, "program_model.json", "programModel", model.programModelSha256),
                            FileToPin(reports, "program_model.json.progress.json", "progress", model.progressSha256),
                            FileToPin(export, "state.json", "state", model.stateSha256),
                        )) {
                            pins[key] = pinFile(directory, name).also { pin ->
                                requireDigest(directory, name, pin, digest, checkpoint)
                            }
                        }
                        val manifestPin = pinFile(native, "manifest.json")
                        val observationPin = pinFile(native, "native-calls.json")
                        val manifestSize = size(manifestPin)
                        val observationSize = size(observationPin)
                        require(manifestSize in 1..limits.maximumManifestBytes.toLong() && observationSize > 0 &&
                            model.capturedBytes <= limits.maximumCombinedBytes - manifestSize &&
                            observationSize <= limits.maximumCombinedBytes - manifestSize - model.capturedBytes) {
                            "native inventory exceeds its combined file bound"
                        }
                        val manifest = readSmallFile(native, "manifest.json", manifestPin, limits.maximumManifestBytes, checkpoint)
                        var defaultIndex: Int? = null
                        val remainingFunctions = model.functionEntryOffsets.toMutableSet()
                        require(remainingFunctions.size.toLong() == model.functionCount) {
                            "native capture requires the exact admitted model function inventory"
                        }
                        val summary = NativeCallObservationsV1.validateBoundToSpaces(
                            manifest,
                            expectedBindings = { spaces ->
                                val default = spaces.singleOrNull { space ->
                                    val expected = target.defaultAddressSpace
                                    space.name == expected.name && space.type == expected.type && space.sizeBits == expected.sizeBits &&
                                        space.addressableUnitSize == expected.addressableUnitSize && space.overlay == expected.overlay &&
                                        space.signedOffsets == expected.signedOffsets
                                } ?: error("native address table lacks the independently admitted default RAM space")
                                defaultIndex = default.index
                                NativeCallBindingsV1(collectorSha256, target.compilerSpecId, model.analysisToolSha256,
                                    NativeCallAddressV1(default.index, target.imageBase.toString(16).padStart(16, '0')),
                                    model.inputSha256, target.languageId, model.programModelBytes,
                                    model.exporterSha256, model.programModelSha256)
                            },
                            limits = limits,
                            checkpoint = checkpoint,
                            openObservations = {
                                val selected = openPinnedFile(native, "native-calls.json", observationPin)
                                val readable = try { LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(selected) }
                                    finally { selected.close() }
                                try {
                                    val channel = FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), StandardOpenOption.READ)
                                    readable.close()
                                    Channels.newInputStream(channel)
                                } catch (failure: Throwable) {
                                    readable.close()
                                    throw failure
                                }
                            },
                            consume = { record ->
                                if (record is NativeCallFunctionRecordV1) {
                                    // Loader-generated import shims may be outside the file-backed ELF
                                    // executable ranges. Retain them as native observations, never identities.
                                    if (!record.isThunk) {
                                        require(record.entry.spaceIndex == defaultIndex) {
                                            "native non-thunk function is outside the admitted model address space"
                                        }
                                        val entry = record.entry.offsetBits!!.toULong(16)
                                        require(remainingFunctions.remove(entry)) {
                                            "native non-thunk function is absent from the admitted model"
                                        }
                                    }
                                }
                            },
                        )
                        require(remainingFunctions.isEmpty()) { "native function coverage omits admitted model functions" }
                        require(summary.observationsBytes == observationSize)
                        pins["manifest"] = manifestPin
                        pins["observations"] = observationPin
                        pins.forEach { (key, pin) ->
                            val (directory, name) = locate(key, reports, native, export)
                            requireFileUnchanged(directory, name, pin)
                        }
                        verifyDirectories()
                        val assessment = assessment(model, summary, target, controlName,
                            control.identity, reports.identity, native.identity, pins, manifest)
                        GccBundledNativeCallSnapshot(summary, target, reports.identity, native.identity,
                            export.identity, controlName, control.identity, pins.toMap(), manifest, assessment)
                    }
                }
            }
        }
    }

    fun requireUnchanged(
        run: LinuxDescriptor,
        captured: GccBundledNativeCallSnapshot,
        model: GccBundledFullExportSnapshot,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        checkpoint: () -> Unit,
    ) {
        checkpoint()
        val current = GccBundledFullExportCapture.captureWithNativeCallSibling(run, captured.reportsIdentity, artifacts,
            checkpoint = checkpoint)
        require(current.assessmentBytes.contentEquals(model.assessmentBytes) &&
            current.sidecarManifest.contentEquals(model.sidecarManifest)) { "native paired model tree changed" }
        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
            requireNamedDirectory(run, "reports", captured.reportsIdentity)
            requireNamedDirectory(run, captured.controlName, captured.controlIdentity)
            requireNames(reports, REPORT_NAMES)
            LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, DIRECTORY).use { native ->
                requireNamedDirectory(reports, DIRECTORY, captured.nativeIdentity)
                requireNames(native, NATIVE_NAMES)
                LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "program_model.json.export").use { export ->
                    requireNamedDirectory(reports, "program_model.json.export", captured.exportIdentity)
                    captured.files.forEach { (key, pin) ->
                        checkpoint()
                        val (directory, name) = locate(key, reports, native, export)
                        requireFileUnchanged(directory, name, pin)
                    }
                    requireDigest(native, "native-calls.json", captured.files.getValue("observations"),
                        captured.summary.observationsSha256, checkpoint)
                    requireDigest(native, "manifest.json", captured.files.getValue("manifest"),
                        OracleArtifacts.sha256(captured.manifestBytes), checkpoint)
                }
            }
        }
        checkpoint()
    }

    /** Recovery-only freeze from the original owned capture; this reader grants no capability. */
    fun freezeRecoveredClaims(
        run: LinuxDescriptor,
        captured: GccBundledNativeCallSnapshot,
        model: GccBundledFullExportSnapshot,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        limits: NativeRecoveredCallPopulationLimitsV1 = NativeRecoveredCallPopulationLimitsV1(),
        checkpoint: () -> Unit,
    ): FrozenNativeRecoveredCallPopulationV1 {
        require(captured.summary.observationsBytes in 1..limits.maximumObservationBytes.toLong() &&
            size(captured.files.getValue("observations")) == captured.summary.observationsBytes &&
            model.programModelBytes in 1..limits.maximumModelBytes.toLong() &&
            captured.summary.scanSummary.sites <= limits.maximumSites) { "native claim freeze exceeds its selected population bounds" }
        val frozenRunIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        require(frozenRunIdentity.copy(linkCount = run.identity.linkCount) == run.identity)
        requirePrivateDirectory(frozenRunIdentity, frozenRunIdentity)
        checkpoint()
        requireUnchanged(run, captured, model, artifacts, checkpoint)
        val observations = LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
            requireNamedDirectory(run, "reports", captured.reportsIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, DIRECTORY).use { native ->
                requireNamedDirectory(reports, DIRECTORY, captured.nativeIdentity)
                requireNames(native, NATIVE_NAMES)
                readSmallFile(native, "native-calls.json", captured.files.getValue("observations"),
                    limits.maximumObservationBytes, checkpoint).also { bytes ->
                    require(OracleArtifacts.sha256(bytes) == captured.summary.observationsSha256) {
                        "native claim freeze substitutes the retained observation bytes"
                    }
                }
            }
        }
        val frozen = NativeRecoveredCallPopulationV1.freeze(captured.manifestBytes, observations,
            model.programModel, captured.summary.bindings, limits, checkpoint)
        require(frozen.rawRecordCount == captured.summary.records &&
            frozen.rawSiteCount.toLong() == captured.summary.scanSummary.sites) { "native claim freeze loses source census" }
        requireUnchanged(run, captured, model, artifacts, checkpoint)
        // No mutation-capable checkpoint follows this final named-identity/metadata check.
        // The coordinator retains the lease and separately rechecks the snapshot during replay.
        requirePinnedMetadata(run, captured, frozenRunIdentity)
        return frozen
    }

    private fun requirePinnedMetadata(run: LinuxDescriptor, captured: GccBundledNativeCallSnapshot,
        frozenRunIdentity: LinuxFileIdentity) {
        require(LinuxFilesystemSyscalls.identity(run.fd) == frozenRunIdentity) { "native claim run root changed" }
        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
            requireNamedDirectory(run, "reports", captured.reportsIdentity)
            requireNamedDirectory(run, captured.controlName, captured.controlIdentity)
            requireNames(reports, REPORT_NAMES)
            LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, DIRECTORY).use { native ->
                requireNamedDirectory(reports, DIRECTORY, captured.nativeIdentity)
                requireNames(native, NATIVE_NAMES)
                LinuxFilesystemSyscalls.openDirectoryAt(reports.fd, "program_model.json.export").use { export ->
                    requireNamedDirectory(reports, "program_model.json.export", captured.exportIdentity)
                    captured.files.forEach { (key, pin) ->
                        val (directory, name) = locate(key, reports, native, export)
                        requireFileUnchanged(directory, name, pin)
                    }
                }
            }
        }
    }

    private data class FileToPin(val directory: LinuxDescriptor, val name: String, val key: String, val digest: String)
    private fun locate(key: String, reports: LinuxDescriptor, native: LinuxDescriptor, export: LinuxDescriptor): Pair<LinuxDescriptor, String> = when(key) {
        "programModel" -> reports to "program_model.json"
        "progress" -> reports to "program_model.json.progress.json"
        "state" -> export to "state.json"
        "manifest" -> native to "manifest.json"
        "observations" -> native to "native-calls.json"
        else -> error("unknown native pinned file")
    }
    private fun requirePrivateDirectory(id: LinuxFileIdentity, parent: LinuxFileIdentity) {
        require(id.isDirectory && !id.isSymbolicLink && id.uid == parent.uid && id.mountId == parent.mountId &&
            id.mode.permissions == 448) { "native capture requires a private owned directory on the retained mount" }
    }
    private fun requireNames(directory: LinuxDescriptor, names: Set<String>) {
        require(LinuxFilesystemSyscalls.directoryEntryNames(directory, names.size + 1).toSet() == names) {
            "native capture directory has missing or unexpected entries"
        }
    }
    private fun requireNamedDirectory(parent: LinuxDescriptor, name: String, expected: LinuxFileIdentity) {
        LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { named ->
            require(named.identity == expected && LinuxFilesystemSyscalls.identity(named.fd) == expected) {
                "native capture directory changed identity"
            }
        }
    }
    private fun pinFile(directory: LinuxDescriptor, name: String): GccNativeCallCapturedFile =
        requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)).use { file ->
            val id = file.identity
            require(id.isRegularFile && !id.isSymbolicLink && id.linkCount == 1 && id.uid == directory.identity.uid &&
                id.mountId == directory.identity.mountId && id.mode.permissions and 0x12 == 0) {
                "native output is not an owned single-link file on the retained mount"
            }
            GccNativeCallCapturedFile(id, metadata(file))
        }
    private fun metadata(file: LinuxDescriptor): Map<String, Any> =
        Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(file.fd), "unix:size,lastModifiedTime,ctime")
    private fun size(file: GccNativeCallCapturedFile) = file.metadata.getValue("size") as Long
    private fun openPinnedFile(directory: LinuxDescriptor, name: String, expected: GccNativeCallCapturedFile): LinuxDescriptor {
        val file = requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name))
        try {
            require(file.identity == expected.identity && metadata(file) == expected.metadata) {
                "native capture file changed identity or metadata"
            }
            return file
        } catch (failure: Throwable) { file.close(); throw failure }
    }
    private fun requireFileUnchanged(directory: LinuxDescriptor, name: String, expected: GccNativeCallCapturedFile) {
        openPinnedFile(directory, name, expected).use { }
    }
    private fun readSmallFile(directory: LinuxDescriptor, name: String, expected: GccNativeCallCapturedFile,
        maximumBytes: Int, checkpoint: () -> Unit): ByteArray = openPinnedFile(directory, name, expected).use { file ->
        LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(file).use { readable ->
            LinuxFilesystemSyscalls.read(readable, maximumBytes, checkpoint).also { bytes ->
                require(bytes.size.toLong() == size(expected))
                requireFileUnchanged(directory, name, expected)
            }
        }
    }
    private fun requireDigest(directory: LinuxDescriptor, name: String, pin: GccNativeCallCapturedFile,
        expectedDigest: String, checkpoint: () -> Unit) {
        openPinnedFile(directory, name, pin).use { file ->
            LinuxFilesystemSyscalls.openReadableWithoutAtimeFrom(file).use { readable ->
                FileChannel.open(LinuxFilesystemSyscalls.stableDescriptorPath(readable.fd), StandardOpenOption.READ).use { channel ->
                    val digest = java.security.MessageDigest.getInstance("SHA-256")
                    val buffer = java.nio.ByteBuffer.allocate(64 * 1024)
                    var total = 0L
                    while (true) {
                        checkpoint()
                        val count = channel.read(buffer)
                        if (count == -1) break
                        require(count > 0)
                        total = Math.addExact(total, count.toLong())
                        require(total <= size(pin)) { "native file grew during validation" }
                        digest.update(buffer.array(), 0, count)
                        buffer.clear()
                    }
                    require(total == size(pin) && digest.digest().joinToString("") { "%02x".format(it) } == expectedDigest) {
                        "native paired output digest changed"
                    }
                }
            }
        }
        requireFileUnchanged(directory, name, pin)
    }
    private fun assessment(model: GccBundledFullExportSnapshot, summary: NativeCallObservationSummaryV1,
        target: GccBundledNativeCallTargetEvidenceV1, controlName: String, control: LinuxFileIdentity,
        reports: LinuxFileIdentity, native: LinuxFileIdentity, pins: Map<String, GccNativeCallCapturedFile>,
        manifest: ByteArray): ByteArray {
        val fields = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-descriptor-native-call-assessment-v1"),
            "schemaVersion" to JsonPrimitive(1), "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false), "byteAssessmentAuthority" to JsonPrimitive("non-authoritative-byte-assessment"),
            "compilerEngineProfileSha256" to JsonPrimitive(target.profileSha256),
            "inputSha256" to JsonPrimitive(model.inputSha256), "inputBytes" to JsonPrimitive(model.inputBytes),
            "programModelSha256" to JsonPrimitive(model.programModelSha256), "programModelBytes" to JsonPrimitive(model.programModelBytes),
            "outputTreeSha256" to JsonPrimitive(model.outputTreeSha256),
            "modelAssessmentSha256" to JsonPrimitive(OracleArtifacts.sha256(model.assessmentBytes)),
            "collectorSha256" to JsonPrimitive(summary.bindings.collectorSha256),
            "observationsSha256" to JsonPrimitive(summary.observationsSha256), "observationsBytes" to JsonPrimitive(summary.observationsBytes),
            "manifestSha256" to JsonPrimitive(OracleArtifacts.sha256(manifest)), "manifestBytes" to JsonPrimitive(manifest.size),
            "functionCount" to JsonPrimitive(summary.scanSummary.functions), "thunkCount" to JsonPrimitive(summary.scanSummary.thunks),
            "siteCount" to JsonPrimitive(summary.scanSummary.sites), "records" to JsonPrimitive(summary.records),
            "coverage" to JsonPrimitive(summary.scanSummary.coverage),
            "controlName" to JsonPrimitive(controlName), "controlIdentity" to identity(control),
            "reportsIdentity" to identity(reports), "nativeIdentity" to identity(native),
            "fileIdentities" to JsonObject(pins.mapValues { (_, pin) -> JsonObject(mapOf(
                "identity" to identity(pin.identity), "metadata" to JsonObject(pin.metadata.mapValues { JsonPrimitive(it.value.toString()) }))) }),
        ))
        return OracleJson.canonicalBytes(JsonObject(fields + ("assessmentSha256" to
            JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(fields))))))
    }
    private fun identity(id: LinuxFileIdentity) = JsonObject(mapOf(
        "device" to JsonPrimitive(id.key.device), "inode" to JsonPrimitive(id.key.inode), "mountId" to JsonPrimitive(id.mountId),
        "uid" to JsonPrimitive(id.uid), "gid" to JsonPrimitive(id.gid), "mode" to JsonPrimitive(id.mode.permissions),
        "linkCount" to JsonPrimitive(id.linkCount),
    ))
}
