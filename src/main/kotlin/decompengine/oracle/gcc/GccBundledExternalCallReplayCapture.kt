package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.externalcalls.*
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*

/** Immutable captured bytes and their original filesystem pins; this object grants no capability. */
internal class GccBundledExternalCallReplayCapture(
    val controlName: String, val controlIdentity: LinuxFileIdentity, val reportsIdentity: LinuxFileIdentity,
    files: Map<String, GccNativeCallCapturedFile>, report: ByteArray, assessment: ByteArray,
) {
    internal val files = java.util.Collections.unmodifiableMap(files.mapValues { (_, pin) ->
        pin.copy(metadata = java.util.Collections.unmodifiableMap(HashMap(pin.metadata))) })
    private val report = report.copyOf()
    private val assessment = assessment.copyOf()
    val reportBytes: ByteArray get() = report.copyOf()
    val assessmentBytes: ByteArray get() = assessment.copyOf()
}

/** The caller retains the lease and proves child/cgroup absence before entering these fixed paths. */
internal object GccBundledExternalCallReplayOutputCapture {
    const val INDEPENDENT_NAME = "independent-external-call-observations.json"
    const val RECOVERED_NAME = "recovered-external-call-observations.json"
    private const val MAXIMUM_LOG_BYTES = 1024 * 1024
    private val JSON_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024,
        maximumCanonicalBytes = 64 * 1024 * 1024, maximumNodes = 1_000_000,
        maximumDepth = 32, maximumStringBytes = 4 * 1024 * 1024, maximumTotalStringBytes = 64 * 1024 * 1024)

    fun captureIndependent(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: IndependentExternalCallRequestV1, checkpoint: () -> Unit): GccBundledExternalCallReplayCapture =
        capture(run, controlName, expectedControl, request.outputPath, INDEPENDENT_NAME,
            request.canonicalBytes, request.limits.maximumOutputBytes, checkpoint) { report ->
            IndependentExternalCallReportV1.validateWorker(OracleJson.parseCanonical(report, JSON_LIMITS).jsonObject,
                OracleArtifacts.sha256(request.canonicalBytes), request)
        }

    fun captureRecovered(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        request: RecoveredExternalNamespaceRequestV1, frozen: FrozenNativeExternalClaimsSnapshotV1,
        pair: ElfExternalNamespacePairV1, checkpoint: () -> Unit): GccBundledExternalCallReplayCapture =
        capture(run, controlName, expectedControl, request.outputPath, RECOVERED_NAME,
            request.canonicalBytes, request.limits.maximumOutputBytes, checkpoint) { bytes ->
            require(request.expectedNativeBindings == frozen.bindings &&
                request.nativeManifest.sha256 == frozen.manifestSha256 && request.nativeManifest.bytes == frozen.manifestBytes &&
                request.nativeObservations.sha256 == frozen.observationsSha256 && request.nativeObservations.bytes == frozen.observationBytes)
            // Re-derive from the complete original bytes; a saved binding or DTO alone is insufficient.
            val refrozen = FrozenNativeExternalClaimsV1.freeze(frozen.rawManifestBytes, frozen.rawObservationBytes,
                request.expectedNativeBindings, checkpoint = checkpoint)
            require(refrozen.canonicalEvidenceBytes.contentEquals(frozen.canonicalEvidenceBytes) &&
                refrozen.rawSiteCount == frozen.rawSiteCount && refrozen.rawRecordCount == frozen.rawRecordCount)
            val report = OracleJson.parseCanonical(bytes, recoveryNamespaceJsonLimits(request.limits)).jsonObject
            validateRecoveredExternalWorkerCommitmentsV1(report, OracleArtifacts.sha256(request.canonicalBytes), request) { checkpoint() }
            val component = JsonObject(report - setOf("requestSha256", "runtime", "containmentStatus") +
                ("decoderAuthentication" to JsonPrimitive("external-worker-required")))
            RecoveredExternalNamespaceV1.validate(component, refrozen, pair, request.limits) { checkpoint() }
            pair.requireCurrent()
        }

    fun requireUnchanged(run: LinuxDescriptor, capture: GccBundledExternalCallReplayCapture) {
        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, capture.controlName).use { control ->
            require(control.identity == capture.controlIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                require(reports.identity == capture.reportsIdentity)
                require(LinuxFilesystemSyscalls.directoryEntryNames(reports, capture.files.size + 1).toSet() == capture.files.keys)
                capture.files.forEach { (name, expected) -> require(pin(reports, name) == expected) }
            }
        }
    }

    private fun capture(run: LinuxDescriptor, controlName: String, expectedControl: LinuxFileIdentity,
        outputPath: Path, reportName: String, requestBytes: ByteArray, maximumBytes: Int,
        checkpoint: () -> Unit, validate: (ByteArray) -> Unit): GccBundledExternalCallReplayCapture {
        check(!Thread.currentThread().isInterrupted)
        require(controlName.matches(Regex("control-[a-f0-9]{64}")))
        val runIdentity = LinuxFilesystemSyscalls.identity(run.fd)
        val runPath = LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath()
        require(outputPath == runPath.resolve(controlName).resolve("reports").resolve(reportName))
        return LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
            require(control.identity == expectedControl)
            requirePrivate(control.identity, runIdentity)
            LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                requirePrivate(reports.identity, control.identity)
                val names = setOf(reportName, "contained-command.stdout", "contained-command.stderr")
                fun directories() {
                    require(LinuxFilesystemSyscalls.identity(run.fd) == runIdentity)
                    require(LinuxFilesystemSyscalls.stableDescriptorPath(run.fd).toRealPath() == runPath)
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { require(it.identity == control.identity) }
                    LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { require(it.identity == reports.identity) }
                    require(LinuxFilesystemSyscalls.directoryEntryNames(reports, names.size + 1).toSet() == names)
                }
                directories()
                val pins = names.associateWith { pin(reports, it) }
                checkpoint()
                var callbacks = true
                val files = GccBoundExportFiles(maximumBytes.toLong() + 2L * MAXIMUM_LOG_BYTES) { if (callbacks) checkpoint() }
                val report = files.read(reports, reportName, maximumBytes)
                val stdout = files.read(reports, "contained-command.stdout", MAXIMUM_LOG_BYTES)
                val stderr = files.read(reports, "contained-command.stderr", MAXIMUM_LOG_BYTES)
                validate(report)
                val assessment = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive("descriptor-external-call-replay-capture-v1"),
                    "schemaVersion" to JsonPrimitive(1), "reportName" to JsonPrimitive(reportName),
                    "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(requestBytes)),
                    "reportSha256" to JsonPrimitive(OracleArtifacts.sha256(report)), "reportBytes" to JsonPrimitive(report.size),
                    "capturedBytes" to JsonPrimitive(files.bytes),
                    "stdoutBytes" to JsonPrimitive(stdout.size), "stdoutSha256" to JsonPrimitive(OracleArtifacts.sha256(stdout)),
                    "stderrBytes" to JsonPrimitive(stderr.size), "stderrSha256" to JsonPrimitive(OracleArtifacts.sha256(stderr)),
                    "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
                    "negativeCompleteness" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false))))
                checkpoint()
                // No caller callback follows this complete final identity and membership pass.
                callbacks = false
                files.verify()
                directories()
                pins.forEach { (name, expected) -> require(pin(reports, name) == expected) }
                GccBundledExternalCallReplayCapture(controlName, control.identity, reports.identity, pins, report, assessment)
            }
        }
    }

    private fun pin(directory: LinuxDescriptor, name: String): GccNativeCallCapturedFile =
        requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(directory.fd, name)).use { file ->
            val identity = file.identity
            require(identity.isRegularFile && !identity.isSymbolicLink && identity.linkCount == 1 &&
                identity.uid == directory.identity.uid && identity.mountId == directory.identity.mountId &&
                identity.mode.permissions and 0x12 == 0)
            GccNativeCallCapturedFile(identity, Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(file.fd),
                "unix:size,lastModifiedTime,ctime"))
        }
    private fun requirePrivate(identity: LinuxFileIdentity, parent: LinuxFileIdentity) {
        require(identity.isDirectory && !identity.isSymbolicLink && identity.mode.permissions == 448 &&
            identity.uid == parent.uid && identity.mountId == parent.mountId)
    }
}
