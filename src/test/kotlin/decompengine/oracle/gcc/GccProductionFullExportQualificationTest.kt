package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.project.NativeCallAddressV1
import decompengine.project.NativeCallBindingsV1
import decompengine.project.NativeCallObservationsV1
import decompengine.project.NativeCallObservationLimitsV1
import decompengine.project.NativeCallSiteRecordV1
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.KotlinContainedCommandRequest
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandResources
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.READ
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.io.TempDir

/** Opt-in evidence capture for a real contained GCC full export; this does not score the model. */
@Tag("ci-live")
class GccProductionFullExportQualificationTest {
    @Test
    fun `live cc1 runtime diagnostics retain bounded logs and available operation evidence`() {
        assumeTrue(System.getenv("DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS") == "true",
            "real cc1 runtime diagnostics are opt-in")
        require(System.getenv("DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT") != "true") {
            "runtime diagnostics and qualification must be selected separately"
        }
        require((System.getenv("DECOMP_GCC_CLI_FULL_EXPORT_ENGINE") ?: "cc1") == "cc1")
        val installation = configured("DECOMP_GCC_CLI_INSTALLATION")
        val profile = configured("DECOMP_GCC_CLI_PROFILE")
        val scratch = configured("DECOMP_GCC_CLI_EXPORT_SCRATCH", "DECOMP_GCC_CLI_CC1_FRESH_SCRATCH")
        val evidence = configured("DECOMP_GCC_CLI_EVIDENCE_ROOT")
        require(isEmptyDirectory(scratch) && isEmptyDirectory(evidence))
        require(Files.getPosixFilePermissions(evidence) == PosixFilePermissions.fromString("rwx------"))
        val output = privateDirectory(evidence.resolve("cli-output"))
        val launcher = privateDirectory(evidence.resolve("launcher"))
        val arguments = listOf("cc1", configured("DECOMP_GCC_CLI_EXPORT_BINARY", "DECOMP_GCC_CLI_CC1_BINARY").toString(),
            "--profile", profile.toString(), "--ghidra-archive", configured("DECOMP_GCC_CLI_ARCHIVE").toString(),
            "--output", output.toString(), "--scratch", scratch.toString())
        val options = GccBundledCliOptions.parse(arguments, fullRecoveryExport = true, runtimeDiagnostics = true)
        var exitCode: Int? = null
        withBootAlignedDiagnosticCapture(
            expectedReference = { readStable(configuredDiagnosticBootReference(), MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES) },
            installedReference = { readStable(installation.resolve("lib/kotlin-boot-classpath-reference-v1.json"),
                MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES) },
            capture = { failure ->
                captureRuntimeDiagnostics(options, arguments, installation, evidence, exitCode, failure)
            },
        ) {
            exitCode = invokeInstalledGccCli(arguments, launcher, timeoutSeconds = 9900,
                installation = installation, command = options.commandName)
            assertEquals(0, exitCode, "installed cc1 diagnostic CLI failed; original outcome and bounded diagnostics retained")
            verifyInstalledCliEvidence(launcher, arguments, installation, expectedExit = 0, command = options.commandName)
        }
        assertFalse(Files.exists(evidence.resolve("qualification.json")))
        assertFalse(Files.exists(output.resolve("result.json")))
        assertFalse(Files.exists(output.resolve("structural-full-export-binding.json")))
    }

    /** Byte alignment only; no JAR, runtime, generation or qualification authority. */
    private inline fun <T> withBootAlignedDiagnosticCapture(expectedReference: () -> ByteArray,
        installedReference: () -> ByteArray, capture: (Throwable?) -> Unit, operation: () -> T): T =
        withDiagnosticCapture(capture) {
            requireDiagnosticBootAlignment(expectedReference(), installedReference())
            operation()
        }

    private fun configuredDiagnosticBootReference(): Path =
        Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathReference")))

    private class DiagnosticBootReferenceMismatch(expected: ByteArray, installed: ByteArray) : IllegalArgumentException(
        "diagnostic BOOT reference bytes differ") {
        // Only bounded typed facts survive; never paths, raw reference bytes or parser messages.
        val facts = JsonObject(mapOf(
            "reason" to JsonPrimitive("BOOT_REFERENCE_BYTE_MISMATCH"),
            "expectedBytes" to JsonPrimitive(expected.size), "installedBytes" to JsonPrimitive(installed.size),
            "expectedSha256" to JsonPrimitive(OracleArtifacts.sha256(expected)),
            "installedSha256" to JsonPrimitive(OracleArtifacts.sha256(installed)),
        ))
    }

    private fun requireDiagnosticBootAlignment(expected: ByteArray, installed: ByteArray) {
        require(expected.size in 1..MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES &&
            installed.size in 1..MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES) { "diagnostic BOOT reference exceeds its byte bound" }
        if (!expected.contentEquals(installed)) throw DiagnosticBootReferenceMismatch(expected, installed)
    }

    private fun diagnosticBootMismatchFacts(primary: Throwable?, authentication: Throwable?): JsonElement =
        ((primary as? DiagnosticBootReferenceMismatch) ?: (authentication as? DiagnosticBootReferenceMismatch))?.facts ?: JsonNull

    private inline fun <T> withDiagnosticCapture(capture: (Throwable?) -> Unit, operation: () -> T): T {
        var original: Throwable? = null
        try {
            return operation()
        } catch (failure: Throwable) {
            original = failure
            throw failure
        } finally {
            try { capture(original) } catch (failure: Throwable) {
                if (original == null) throw failure
                if (failure !== original) original.addSuppressed(failure)
            }
        }
    }

    private fun captureRuntimeDiagnostics(options: GccBundledCliOptions, arguments: List<String>, installation: Path,
        evidence: Path, exitCode: Int?, originalFailure: Throwable?) {
        val captured = privateDirectory(evidence.resolve("diagnostic-captured"))
        val availability = linkedMapOf<String, JsonElement>()
        val records = linkedMapOf<String, ByteArray>()
        var metadataBytes = 0L
        fun retain(key: String, source: Path, maximum: Int) {
            try {
                if (!Files.exists(source, LinkOption.NOFOLLOW_LINKS)) {
                    availability[key] = JsonObject(mapOf("status" to JsonPrimitive("absent")))
                    return
                }
                val bytes = readStable(source, maximum)
                metadataBytes += bytes.size
                require(metadataBytes <= 16L * 1024 * 1024) { "diagnostic metadata exceeds its aggregate bound" }
                publish(captured.resolve(key), bytes)
                records[key] = bytes
                availability[key] = JsonObject(mapOf("status" to JsonPrimitive("captured"),
                    "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))
            } catch (failure: Exception) {
                availability[key] = JsonObject(mapOf("status" to JsonPrimitive("capture-failed"),
                    "failure" to JsonPrimitive(failure.javaClass.simpleName)))
            }
        }
        retain("invocation.json", options.output.resolve("invocation.json"), 256 * 1024)
        retain("compiler-engines.json", options.profile, 1024 * 1024)
        retain("gcc-bundled-ghidra-reference-v1.json", installation.resolve("lib/gcc-bundled-ghidra-reference-v1.json"), 8 * 1024 * 1024)
        retain("kotlin-boot-classpath-reference-v1.json", installation.resolve("lib/kotlin-boot-classpath-reference-v1.json"),
            MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES)
        retain("boot-classpath.json", options.output.resolve("inputs/boot-classpath.json"), 1024 * 1024)
        var operationId: String? = null
        var discoveryFailure: Throwable? = null
        try {
            LinuxFilesystemSyscalls.openRoot(options.output.resolve("journal")).use { root ->
                val names = LinuxFilesystemSyscalls.directoryEntryNames(root, 1)
                if (names.isNotEmpty()) {
                    val name = names.single()
                    require(name.matches(Regex("\\.gcc-bundled-operation-[a-f0-9]{64}")))
                    operationId = name.removePrefix(".gcc-bundled-operation-")
                    // Opening the directory rejects a substituted symbolic link before any file read.
                    LinuxFilesystemSyscalls.openDirectoryAt(root.fd, name).use {
                        for (file in DIAGNOSTIC_JOURNAL_FILES) {
                            retain(file, options.output.resolve("journal/$name/$file"),
                                if (file == "definition.json") 1024 * 1024 else 256 * 1024)
                        }
                    }
                }
            }
        } catch (failure: Exception) { discoveryFailure = failure }
        val expectedControl = records["definition.json"]?.let { bytes -> runCatching {
            val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(bytes)
            definition.bundledRuntime?.freshControlDirectoryName(definition.outputLease.path)
        }.getOrNull() }
        val logCapture = runCatching { captureRuntimeLogPrefixes(options.scratch, captured, operationId, expectedControl) }
        val stdout = logCapture.getOrNull()?.get("stdout")
        val telemetry = parseRuntimeTelemetry(stdout ?: byteArrayOf(), stdout?.size == MAXIMUM_DIAGNOSTIC_STDOUT_BYTES)
        publish(captured.resolve("telemetry.json"), OracleJson.canonicalBytes(telemetry, DIAGNOSTIC_TELEMETRY_LIMITS))
        val authentication = runCatching {
            require(operationId != null) { "operation journal is unavailable" }
            requireDiagnosticRecordAvailability(availability, originalFailure == null && exitCode == 0)
            requireDiagnosticJournal(records, operationId, options, arguments, installation, ::retain)
        }
        val summary = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-cc1-runtime-diagnostic-capture-v1"),
            "authority" to JsonPrimitive("diagnostic-only"), "engine" to JsonPrimitive("cc1"),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "benchmarkAccepted" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "referenceWallBudgetSeconds" to JsonPrimitive(1800), "diagnosticWallBudgetSeconds" to JsonPrimitive(14400),
            "launcherExitCode" to JsonPrimitive(exitCode),
            "originalFailureClass" to JsonPrimitive(originalFailure?.javaClass?.name),
            "operationId" to JsonPrimitive(operationId), "metadataBytes" to JsonPrimitive(metadataBytes),
            "metadata" to JsonObject(availability),
            "journalDiscoveryFailure" to JsonPrimitive(discoveryFailure?.javaClass?.simpleName),
            "provenanceStatus" to JsonPrimitive(if (authentication.isSuccess) "checked-existing-chain" else "unavailable-or-invalid"),
            "provenanceFailure" to JsonPrimitive(authentication.exceptionOrNull()?.message?.take(512)),
            "bootReferenceMismatch" to diagnosticBootMismatchFacts(originalFailure, authentication.exceptionOrNull()),
            "logCaptureFailure" to JsonPrimitive(logCapture.exceptionOrNull()?.javaClass?.simpleName),
            "logStreams" to JsonObject(listOf("stdout", "stderr").associateWith { name ->
                JsonPrimitive(if (logCapture.isFailure) "capture-failed" else when (logCapture.getOrNull()?.get(name)?.size) {
                    null -> "absent"; 0 -> "captured-empty"; else -> "captured"
                })
            }),
            "telemetryComplete" to telemetry.getValue("telemetryComplete"),
            "terminalObserved" to telemetry.getValue("terminalObserved"),
            "shutdownDrainUnconfirmed" to telemetry.getValue("shutdownDrainUnconfirmed"),
            "limitation" to JsonPrimitive("retained records do not prove START delivery; stdout markers and parsed metrics are unauthenticated diagnostics even when receipt byte counts match"),
        ))
        publish(evidence.resolve("diagnostic.json"), OracleJson.canonicalBytes(summary))
        if (originalFailure == null) {
            authentication.getOrThrow()
            logCapture.getOrThrow()
        }
    }

    private fun requireDiagnosticJournal(records: Map<String, ByteArray>, operationId: String,
        options: GccBundledCliOptions, arguments: List<String>, installation: Path,
        retain: (String, Path, Int) -> Unit) {
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(records.getValue("definition.json"))
        val runtime = requireNotNull(definition.bundledRuntime)
        require(runtime.invocationVersion == 7 && runtime.processorCount == 4 && runtime.decompilerWorkerCount == 4)
        require(definition.engineId == "cc1" && definition.runKind == GccCompilerEngineContainmentRunKind.FRESH_CONTROL)
        require(definition.budgets == GccCompilerEngineContainmentBudgets(14_400_000, 16L * 1024 * 1024 * 1024, 128))
        val directories = listOf(options.output, options.output.resolve("inputs"), options.output.resolve("journal"))
            .associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(options, arguments, directories)
        require(invocation.canonicalBytes.contentEquals(records.getValue("invocation.json")))
        GccRetainedCompilerEngineProfile.open(options.profile, "cc1").use { profile ->
            require(records.getValue("compiler-engines.json").contentEquals(readStable(options.profile, 1024 * 1024)))
            val intent = GccBundledOperationIntent(operationId, "cc1", GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                definition.artifacts, runtime, definition.budgets, options.diskPolicy, profile, invocation)
            require(intent.canonicalBytes.contentEquals(records.getValue("intent.json"))) { "retained intent differs from actual selected inputs" }
            val bootArtifact = intent.artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH }
            require(records.getValue("boot-classpath.json").size.toLong() == bootArtifact.bytes &&
                OracleArtifacts.sha256(records.getValue("boot-classpath.json")) == bootArtifact.sha256)
            requireDiagnosticBootAlignment(
                readStable(configuredDiagnosticBootReference(), MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES),
                records.getValue("kotlin-boot-classpath-reference-v1.json"))
            require(definition.environment == intent.environment)
            val lease = FullTreeDiskScratchEvidence.parseCanonical(records.getValue("lease-evidence.json"))
            require(lease.operationId == operationId && lease.requestSha256 == intent.requestSha256 &&
                lease.shardId == "cc1" && lease.scopeSha256 == intent.workScopeSha256)
            require(lease.requiredAvailableBytes == options.diskPolicy.requiredAvailableBytes &&
                lease.maximumFilesystemBytes == options.diskPolicy.maximumFilesystemBytes &&
                lease.requiredAvailableInodes == options.diskPolicy.requiredAvailableInodes &&
                lease.maximumFilesystemInodes == options.diskPolicy.maximumFilesystemInodes)
            val expectedRun = options.scratch.resolve(".decomp-oracle-lease-$operationId/.function-observation-run-$operationId")
            require(definition.outputLease.path == expectedRun)
            val prepared = OracleJson.parseCanonical(records.getValue("prepared.json")).jsonObject
            require(prepared.keys == setOf("provider", "schemaVersion", "operationId", "intentSha256", "diskEvidenceSha256",
                "definitionSha256", "definitionBindingSha256", "deploymentClosureSha256", "preparedSha256"))
            require(prepared["provider"] == JsonPrimitive("gcc-bundled-prepared-operation-v1") && prepared["schemaVersion"] == JsonPrimitive(1))
            require(prepared["operationId"] == JsonPrimitive(operationId) && prepared["intentSha256"] == JsonPrimitive(intent.requestSha256))
            require(prepared["diskEvidenceSha256"] == JsonPrimitive(lease.evidenceSha256))
            require(prepared["definitionSha256"] == JsonPrimitive(OracleArtifacts.sha256(records.getValue("definition.json"))))
            require(prepared["definitionBindingSha256"] == JsonPrimitive(definition.bindingSha256))
            require(prepared["preparedSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(prepared - "preparedSha256")))))
            GccBundledOperationInputs.open(intent, listOf(options.output.resolve("journal"), options.scratch)).use { inputs ->
                require(prepared["deploymentClosureSha256"] == JsonPrimitive(inputs.deploymentClosureSha256))
                val configuredReference = Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bundledGhidraReference")))
                requireDiagnosticRuntimeSelection(installation, runtime, definition.artifacts,
                    records.getValue("gcc-bundled-ghidra-reference-v1.json"), configuredReference)
                var previous = "prepared.json"
                for (name in listOf("attachment.json", "start-authorized.json", "execution.json")) {
                    val bytes = records[name] ?: break
                    requireGccCliLinkedRecord(bytes, name, operationId, intent.requestSha256,
                        OracleArtifacts.sha256(records.getValue(previous)))
                    previous = name
                }
                require(records["execution.json"] == null || records["start-authorized.json"] != null)
                require(records["start-authorized.json"] == null || records["attachment.json"] != null)
                records["attachment.json"]?.let { bytes ->
                    val attachment = OracleJson.parseCanonical(bytes).jsonObject.getValue("attachment").jsonObject
                    requireDiagnosticAttachmentRecord(attachment)
                    require(attachment["unitName"] == JsonPrimitive(definition.unitName) &&
                        attachment["nonce"] == JsonPrimitive(definition.bindingSha256) &&
                        attachment["controlGroup"] == JsonPrimitive(definition.expectedControlGroup) &&
                        attachment["deploymentClosureSha256"] == JsonPrimitive(inputs.deploymentClosureSha256))
                    require(attachment["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(attachment - "attachmentSha256")))))
                    val resources = attachment.getValue("resources").jsonObject
                    val wall = resources.getValue("wallClockMillis").jsonPrimitive.long
                    require(wall in 1000..definition.budgets.wallClockMillis && wall % 1000L == 0L)
                    val expected = KotlinSystemdCgroupCommandResources(wall, definition.budgets.maximumResidentBytes,
                        definition.budgets.pidsMax, minOf(options.diskPolicy.maximumFilesystemBytes, 1024L * 1024 * 1024), processorCount = 4)
                    require(resources["processorCount"] == JsonPrimitive(4) &&
                        resources["maximumResidentBytes"] == JsonPrimitive(expected.maximumResidentBytes) &&
                        resources["pidsMax"] == JsonPrimitive(expected.pidsMax) &&
                        resources["maximumFileBytes"] == JsonPrimitive(expected.maximumFileBytes) &&
                        resources["cpuSeconds"] == JsonPrimitive(expected.aggregateCpuSeconds) &&
                        resources["serviceRuntimeSeconds"] == JsonPrimitive(expected.aggregateCpuSeconds) &&
                        resources["maximumAddressSpaceBytes"] == JsonPrimitive(64L * 1024 * 1024 * 1024))
                    val capacity = attachment.getValue("hostCpuCapacity").jsonObject
                    require(capacity["controlGroup"] == attachment["controlGroup"] &&
                        capacity.getValue("affinityProcessors").jsonPrimitive.long >= 4)
                    require(capacity["quotaProcessors"] == JsonNull || capacity.getValue("quotaProcessors").jsonPrimitive.long >= 4)
                    val control = expectedRun.resolve(requireNotNull(runtime.freshControlDirectoryName(expectedRun)))
                    retain("contained-command-request.json", control.resolve("runtime/contained-command-request.json"), 256 * 1024)
                    val request = KotlinContainedCommandRequest.parse(records.getValue("contained-command-request.json"))
                    require(request.runDirectory == control && request.nonce == definition.bindingSha256 &&
                        request.command == definition.command && request.environment == definition.environment &&
                        request.maximumWallSeconds == wall / 1000 && !request.allowInterruption &&
                        request.maximumStartWaitSeconds == minOf(expected.aggregateCpuSeconds, 300) &&
                        request.maximumStdoutBytes == minOf(expected.maximumFileBytes, 64L * 1024 * 1024) &&
                        request.maximumStderrBytes == minOf(expected.maximumFileBytes, 64L * 1024 * 1024))
                    require(attachment["requestSha256"] == JsonPrimitive(request.sha256))
                    records["execution.json"]?.let { executionBytes ->
                        val execution = OracleJson.parseCanonical(executionBytes).jsonObject.getValue("execution").jsonObject
                        requireDiagnosticExecutionRecord(execution, attachment, request, inputs.deploymentClosureSha256,
                            control, expected, definition.budgets.wallClockMillis)
                    }
                }
                inputs.verify("after diagnostic provenance capture")
                profile.requireCurrent()
            }
        }
    }

    private fun requireDiagnosticRuntimeSelection(installation: Path, runtime: GccBundledGhidraRuntime,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>, retainedReference: ByteArray,
        configuredReference: Path) {
        require(installation.isAbsolute && installation.normalize() == installation && installation.toRealPath() == installation) {
            "diagnostic installation is not canonical"
        }
        val selectedRoot = installation.resolve("libexec/ghidra")
        require(selectedRoot.toRealPath() == selectedRoot && runtime.root == selectedRoot) {
            "diagnostic runtime differs from the selected installed application"
        }
        require(retainedReference.contentEquals(readStable(configuredReference, 8 * 1024 * 1024))) {
            "diagnostic deployment reference differs from the independent configured reference"
        }
        GccBundledGhidraReference.parse(retainedReference).requireCandidate(runtime, artifacts)
    }

    private fun requireDiagnosticRecordAvailability(availability: Map<String, JsonElement>, requireExecution: Boolean) {
        val statuses = DIAGNOSTIC_JOURNAL_FILES.map { name ->
            name to availability[name]?.jsonObject?.get("status")?.jsonPrimitive?.content
        }
        require(statuses.none { it.second == "capture-failed" }) { "a present journal record could not be safely captured" }
        if (requireExecution) require(statuses.all { it.second == "captured" }) {
            "successful diagnostic CLI did not retain its complete execution chain"
        }
        var absent = false
        for ((_, status) in statuses) {
            if (status != "captured") absent = true
            else require(!absent) { "diagnostic journal has a gap before a retained record" }
        }
    }

    private fun requireDiagnosticAttachmentRecord(attachment: JsonObject) {
        require(attachment.keys == setOf("schemaVersion", "provider", "unitName", "nonce", "bootId", "invocationId",
            "controlGroup", "cgroupDevice", "cgroupInode", "cgroupMountId", "requestSha256", "deploymentClosureSha256",
            "runtimeClosureSha256", "resources", "releaseEligible", "processes", "hostCpuCapacity", "attachmentSha256"))
        require(attachment["schemaVersion"] == JsonPrimitive(2) &&
            attachment["provider"] == JsonPrimitive("kotlin-lease-contained-command-attachment-v2") &&
            attachment["releaseEligible"] == JsonPrimitive(false))
        require(attachment["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(attachment - "attachmentSha256")))))
        for (name in listOf("nonce", "requestSha256", "deploymentClosureSha256", "runtimeClosureSha256")) {
            require(attachment.requiredText(name).matches(Regex("[a-f0-9]{64}")))
        }
        require(attachment.requiredText("bootId").matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")))
        require(attachment.requiredText("invocationId").matches(Regex("[a-f0-9]{32}")))
        require(attachment.getValue("cgroupDevice").jsonPrimitive.long >= 0 &&
            attachment.getValue("cgroupInode").jsonPrimitive.long > 0 && attachment.getValue("cgroupMountId").jsonPrimitive.long > 0)
        val resources = attachment.getValue("resources").jsonObject
        require(resources.keys == setOf("wallClockMillis", "maximumResidentBytes", "pidsMax", "maximumFileBytes",
            "processorCount", "maximumAddressSpaceBytes", "cpuSeconds", "serviceRuntimeSeconds"))
        require(resources.values.all { it.jsonPrimitive.long > 0 })
        val capacity = attachment.getValue("hostCpuCapacity").jsonObject
        require(capacity.keys == setOf("provider", "affinityProcessors", "quotaProcessors", "controlGroup", "maximumAdmittedProcessors"))
        require(capacity["provider"] == JsonPrimitive("linux-affinity-cgroup-capacity-v1") &&
            capacity["maximumAdmittedProcessors"] == JsonPrimitive(4) && capacity["controlGroup"] == attachment["controlGroup"])
        require(capacity.getValue("affinityProcessors").jsonPrimitive.long in 4..65_536 &&
            (capacity["quotaProcessors"] == JsonNull || capacity.getValue("quotaProcessors").jsonPrimitive.long in 4..Int.MAX_VALUE))
        val roles = listOf("outer-bubblewrap", "namespace-init-bubblewrap", "supervisor-jvm")
        val processes = attachment.getValue("processes").jsonArray
        require(processes.size == roles.size)
        val hostPids = hashSetOf<Long>()
        for ((index, value) in processes.withIndex()) {
            val process = value.jsonObject
            require(process.keys == setOf("role", "hostPid", "startTimeTicks", "parentRole", "namespacePids",
                "executableDevice", "executableInode", "executableMountId"))
            require(process["role"] == JsonPrimitive(roles[index]) && process["parentRole"] ==
                if (index == 0) JsonNull else JsonPrimitive(roles[index - 1]))
            val pid = process.getValue("hostPid").jsonPrimitive.long
            require(pid in 1..Int.MAX_VALUE.toLong() && hostPids.add(pid))
            require(process.getValue("startTimeTicks").jsonPrimitive.long > 0 && process.getValue("executableDevice").jsonPrimitive.long >= 0 &&
                process.getValue("executableInode").jsonPrimitive.long > 0 && process.getValue("executableMountId").jsonPrimitive.long > 0)
            val namespacePids = process.getValue("namespacePids").jsonArray
            require(namespacePids.size in 1..32 && namespacePids.all { it.jsonPrimitive.long in 1..Int.MAX_VALUE.toLong() })
        }
    }

    /** Validates retained record consistency; no secret is available to authenticate the outcome HMAC. */
    private fun requireDiagnosticExecutionRecord(execution: JsonObject, attachment: JsonObject,
        request: KotlinContainedCommandRequest, deploymentSha256: String, control: Path,
        resources: KotlinSystemdCgroupCommandResources, operationWallMillis: Long) {
        require(execution.keys == setOf("schemaVersion", "provider", "attachmentSha256", "requestSha256",
            "deploymentClosureSha256", "outcomeSha256", "outcome", "childExitCode", "derivationWallNanos",
            "unitAbsent", "cgroupAbsent", "processesAbsent", "releaseEligible", "cgroup", "controlDirectory",
            "controlDirectoryIdentity", "operationWallTime", "executionSha256"))
        require(execution["schemaVersion"] == JsonPrimitive(2) &&
            execution["provider"] == JsonPrimitive("kotlin-lease-contained-command-execution-v2"))
        require(execution["executionSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(execution - "executionSha256")))))
        require(execution["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(attachment))))
        require(execution["requestSha256"] == JsonPrimitive(request.sha256) &&
            execution["deploymentClosureSha256"] == JsonPrimitive(deploymentSha256))
        require(execution["releaseEligible"] == JsonPrimitive(false) && execution["childExitCode"] == JsonPrimitive(0))
        for (name in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) require(execution[name] == JsonPrimitive(true))
        require(execution["controlDirectory"] == JsonPrimitive(control.toString()))
        LinuxFilesystemSyscalls.openRoot(control).use { directory ->
            require(execution["controlDirectoryIdentity"] == decompengine.oracle.fulltree.containedControlIdentityJson(
                control.fileName.toString(), directory.identity))
        }
        require(execution.getValue("derivationWallNanos").jsonPrimitive.long in 0..resources.wallClockMillis * 1_000_000L)
        val outcome = execution.getValue("outcome").jsonObject
        require(outcome.keys == setOf("schemaVersion", "provider", "event", "nonce", "requestSha256", "keeperPid",
            "childPid", "exitCode", "elapsedMillis", "stdoutBytes", "stderrBytes", "status", "hmacSha256"))
        require(outcome["schemaVersion"] == JsonPrimitive(1) && outcome["provider"] == JsonPrimitive("kotlin-contained-command-protocol-v1"))
        require(outcome["event"] == JsonPrimitive("OUTCOME") && outcome["status"] == JsonPrimitive("EXITED") && outcome["exitCode"] == JsonPrimitive(0))
        require(outcome["requestSha256"] == JsonPrimitive(request.sha256) && outcome["nonce"] == JsonPrimitive(request.nonce))
        require(outcome.requiredText("hmacSha256").matches(Regex("[a-f0-9]{64}")))
        require(execution["outcomeSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(outcome))))
        val keeperPid = outcome.getValue("keeperPid").jsonPrimitive.long
        val childPid = outcome.getValue("childPid").jsonPrimitive.long
        require(keeperPid in 1..Int.MAX_VALUE.toLong() && childPid in 1..Int.MAX_VALUE.toLong() && keeperPid != childPid)
        require(outcome.getValue("elapsedMillis").jsonPrimitive.long in 0..resources.wallClockMillis + 15_000)
        require(outcome.getValue("stdoutBytes").jsonPrimitive.long in 0..request.maximumStdoutBytes &&
            outcome.getValue("stderrBytes").jsonPrimitive.long in 0..request.maximumStderrBytes)
        val cgroup = execution.getValue("cgroup").jsonObject
        require(cgroup.keys == setOf("peakResidentBytes", "cpuNanos", "memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents"))
        require(cgroup.values.all { it.jsonPrimitive.long >= 0 })
        require(listOf("memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents").all { cgroup[it] == JsonPrimitive(0) })
        require(cgroup.getValue("peakResidentBytes").jsonPrimitive.long in 1..resources.maximumResidentBytes &&
            cgroup.getValue("cpuNanos").jsonPrimitive.long <= resources.aggregateCpuSeconds * 1_000_000_000L)
        val wall = execution.getValue("operationWallTime").jsonObject
        require(wall.keys == setOf("provider", "maximumWallMillis", "startedMonotonicNanos", "elapsedNanos", "remainingNanos"))
        require(wall["provider"] == JsonPrimitive("kotlin-contained-operation-wall-deadline-v1") &&
            wall["maximumWallMillis"] == JsonPrimitive(operationWallMillis))
        wall.getValue("startedMonotonicNanos").jsonPrimitive.long
        val elapsed = wall.getValue("elapsedNanos").jsonPrimitive.long
        val remaining = wall.getValue("remainingNanos").jsonPrimitive.long
        require(elapsed in 0 until operationWallMillis * 1_000_000L && remaining == operationWallMillis * 1_000_000L - elapsed)
    }

    /** Prefix snapshots can be taken during an outer timeout, so they grant no execution authority. */
    private fun captureRuntimeLogPrefixes(scratch: Path, captured: Path, expectedOperationId: String? = null,
        expectedControl: String? = null): Map<String, ByteArray> {
        val result = linkedMapOf<String, ByteArray>()
        LinuxFilesystemSyscalls.openRoot(scratch).use { root ->
            val name = LinuxFilesystemSyscalls.directoryEntryNames(root, 1).singleOrNull() ?: return result
            require(name.matches(Regex("\\.decomp-oracle-lease-[a-f0-9]{64}")))
            val id = name.removePrefix(".decomp-oracle-lease-")
            require(expectedOperationId == null || id == expectedOperationId) { "diagnostic log belongs to another operation" }
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, name).use { lease ->
                LinuxFilesystemSyscalls.openDirectoryAt(lease.fd, ".function-observation-run-$id").use { run ->
                    val controlName = LinuxFilesystemSyscalls.directoryEntryNames(run, 16)
                        .filter { it.matches(Regex("control-[a-f0-9]{64}")) }.singleOrNull() ?: return result
                    require(expectedControl == null || controlName == expectedControl) { "diagnostic log control differs from selected runtime" }
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
                        LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                            for (stream in listOf("stdout", "stderr")) {
                                LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, "contained-command.$stream")?.use { file ->
                                    val bytes = LinuxFilesystemSyscalls.readPrefix(file, MAXIMUM_DIAGNOSTIC_STDOUT_BYTES)
                                    if (bytes.isNotEmpty()) publish(captured.resolve("diagnostic-$stream.bin"), bytes)
                                    result[stream] = bytes
                                    publish(captured.resolve("diagnostic-$stream.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                                        "authority" to JsonPrimitive("diagnostic-only"),
                                        "source" to JsonPrimitive("$name/.function-observation-run-$id/$controlName/reports/contained-command.$stream"),
                                        "operationId" to JsonPrimitive(id), "controlDirectory" to JsonPrimitive(controlName),
                                        "capturedBytes" to JsonPrimitive(bytes.size),
                                        "capturedSha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
                                        "captureLimitReached" to JsonPrimitive(bytes.size == MAXIMUM_DIAGNOSTIC_STDOUT_BYTES),
                                        "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                                    ))))
                                }
                            }
                        }
                    }
                }
            }
        }
        return result
    }

    private fun parseRuntimeTelemetry(stdout: ByteArray, prefixLimitReached: Boolean): JsonObject {
        require(stdout.size <= MAXIMUM_DIAGNOSTIC_STDOUT_BYTES)
        val records = arrayListOf<JsonElement>()
        val problems = linkedSetOf<String>()
        var expectedSequence = 0L
        var previousElapsed = -1L
        var telemetryBytes = 0
        var sawInitial = false
        var sawTerminal = false
        var malformedFrames = 0
        var markedFrames = 0
        var position = 0
        if (prefixLimitReached) problems += "stdout_prefix_limit"
        while (position < stdout.size) {
            var end = position
            while (end < stdout.size && stdout[end] != '\n'.code.toByte()) end++
            val length = end - position
            val prefix = DIAGNOSTIC_PREFIX.toByteArray()
            fun matches(offset: Int) = offset >= position && offset + prefix.size <= end &&
                prefix.indices.all { stdout[offset + it] == prefix[it] }
            val marker = (position..maxOf(position, end - prefix.size)).firstOrNull(::matches)
            if (marker != null) {
                markedFrames++
                if (marker != position) problems += "interleaved_frame"
                if (end == stdout.size) problems += "truncated_frame"
                if (sawTerminal) problems += "record_after_terminal"
                if (markedFrames > 640 || telemetryBytes + length + 1 > 5 * 1024 * 1024) {
                    problems += "capture_record_limit"
                } else if (marker != position || end == stdout.size || length + 2 > 4096) {
                    malformedFrames++
                    problems += "malformed_frame"
                } else {
                    telemetryBytes += length + 1
                    try {
                        val record = OracleJson.parse(stdout.copyOfRange(position + prefix.size, end), DIAGNOSTIC_FRAME_LIMITS).jsonObject
                        requireTelemetryRecord(record)
                        val sequence = record.getValue("sequence").jsonPrimitive.long
                        val elapsed = record.getValue("elapsedNanos").jsonPrimitive.long
                        val kind = record.requiredText("kind")
                        if (sequence != expectedSequence) problems += "sequence_gap_or_reorder"
                        expectedSequence = sequence + 1
                        if (elapsed < previousElapsed) problems += "elapsed_regression"
                        previousElapsed = elapsed
                        if (kind == "initial") {
                            if (sawInitial || sequence != 0L || records.isNotEmpty()) problems += "conflicting_initial"
                            sawInitial = true
                        } else if (!sawInitial) problems += "missing_initial"
                        if (kind == "truncation") problems += "producer_truncation"
                        if (kind == "terminal") {
                            if (sawTerminal) problems += "duplicate_terminal"
                            sawTerminal = true
                            if (!record.getValue("priorRecordsComplete").jsonPrimitive.boolean) problems += "producer_incomplete"
                        }
                        if (kind in setOf("terminal", "truncation")) {
                            if (record.getValue("lossReasons").jsonArray.isNotEmpty() ||
                                record.getValue("droppedRecords").jsonPrimitive.long != 0L) problems += "producer_loss"
                        }
                        records += record
                    } catch (_: Exception) {
                        malformedFrames++
                        problems += "malformed_frame"
                    }
                }
            } else if (length > 0 && end == stdout.size) {
                val tail = stdout.copyOfRange(position, minOf(end, position + DIAGNOSTIC_PREFIX.length))
                    .toString(Charsets.UTF_8)
                if (tail.startsWith("DECOMP_GHIDRA_DIAGNOSTICS") || DIAGNOSTIC_PREFIX.startsWith(tail)) {
                    problems += "truncated_frame"
                }
            }
            position = end + 1
        }
        if (!sawInitial) problems += "missing_initial"
        if (!sawTerminal) problems += "missing_terminal"
        return JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-cc1-runtime-telemetry-snapshot-v1"),
            "authority" to JsonPrimitive("diagnostic-only"), "complete" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false), "benchmarkAccepted" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "telemetryComplete" to JsonPrimitive(false),
            "terminalObserved" to JsonPrimitive(sawTerminal),
            "priorRecordsConsistent" to JsonPrimitive(problems.isEmpty()),
            "shutdownDrainUnconfirmed" to JsonPrimitive(true),
            "problems" to JsonArray(problems.map(::JsonPrimitive)), "markedFrames" to JsonPrimitive(markedFrames),
            "malformedFrames" to JsonPrimitive(malformedFrames), "retainedFrameBytes" to JsonPrimitive(telemetryBytes),
            "records" to JsonArray(records),
        ))
    }

    private fun requireTelemetryRecord(record: JsonObject) {
        fun nonnegative(value: JsonElement, nullable: Boolean = false) {
            require(nullable && value == JsonNull || value is JsonPrimitive && !value.isString &&
                value.longOrNull?.let { it >= 0L } == true)
        }
        fun text(value: JsonElement, nullable: Boolean = false) {
            require(nullable && value == JsonNull || value is JsonPrimitive && value.isString &&
                value.content.toByteArray().size in 1..256)
        }
        fun usage(value: JsonElement) {
            if (value == JsonNull) return
            val fields = value.jsonObject
            require(fields.keys == setOf("initBytes", "usedBytes", "committedBytes", "maxBytes"))
            fields.values.forEach { nonnegative(it, true) }
        }
        val kind = record.requiredText("kind")
        val phase = record.requiredText("phase")
        val extras = when (kind) {
            "initial" -> setOf("jvmName", "jvmVendor", "jvmVersion", "javaVersion", "processors", "heap", "collectors")
            "sample" -> setOf("jvmCpuNanos", "heap", "pools", "collectors")
            "phase" -> setOf("exporter")
            "truncation" -> setOf("lossReasons", "droppedRecords")
            "terminal" -> setOf("priorRecordsComplete", "shutdownDrainConfirmed", "lossReasons", "droppedRecords", "outcome")
            else -> error("unknown telemetry kind")
        }
        require(record.keys == setOf("policy", "sequence", "elapsedNanos", "kind", "phase") + extras)
        require(record["policy"] == JsonPrimitive("jvm-mxbean-stdout-v1"))
        nonnegative(record.getValue("sequence")); nonnegative(record.getValue("elapsedNanos"))
        require(record.getValue("sequence").jsonPrimitive.long < Long.MAX_VALUE)
        require(phase in setOf("init", "import-and-analysis", "guard", "exporter", "finalization", "terminal"))
        when (kind) {
            "initial" -> {
                require(phase == "init")
                listOf("jvmName", "jvmVendor", "jvmVersion", "javaVersion").forEach { text(record.getValue(it), true) }
                val processors = record.getValue("processors")
                nonnegative(processors, true)
                require(processors == JsonNull || processors.jsonPrimitive.long > 0L)
                usage(record.getValue("heap"))
                record.getValue("collectors").takeIf { it != JsonNull }?.jsonArray?.let { collectors ->
                    require(collectors.size <= 32); collectors.forEach { text(it) }
                }
            }
            "sample" -> {
                nonnegative(record.getValue("jvmCpuNanos"), true); usage(record.getValue("heap"))
                record.getValue("pools").takeIf { it != JsonNull }?.jsonArray?.let { pools ->
                    require(pools.size <= 32)
                    pools.forEach { value ->
                        val pool = value.jsonObject
                        require(pool.keys == setOf("name", "type", "valid", "usage", "postGc"))
                        text(pool.getValue("name")); require(pool["type"] in setOf(JsonPrimitive("HEAP"), JsonPrimitive("NON_HEAP")))
                        require(pool.getValue("valid").jsonPrimitive.booleanOrNull != null)
                        usage(pool.getValue("usage")); usage(pool.getValue("postGc"))
                    }
                }
                record.getValue("collectors").takeIf { it != JsonNull }?.jsonArray?.let { collectors ->
                    require(collectors.size <= 32)
                    collectors.forEach { value ->
                        val collector = value.jsonObject
                        require(collector.keys == setOf("name", "count", "timeMillis")); text(collector.getValue("name"))
                        nonnegative(collector.getValue("count"), true); nonnegative(collector.getValue("timeMillis"), true)
                    }
                }
            }
            "phase" -> {
                val exporter = record.getValue("exporter")
                require(exporter == JsonNull || phase == "exporter" && exporter in setOf(JsonPrimitive("ExportProgramModel.java"),
                    JsonPrimitive("ExportRecoveredCallSites.java"), JsonPrimitive("ExportDecompiledC.java")))
            }
            "terminal", "truncation" -> {
                val reasons = record.getValue("lossReasons").jsonArray
                require(reasons.size <= DIAGNOSTIC_LOSS_REASONS.size && reasons.distinct().size == reasons.size)
                reasons.forEach { require(it.jsonPrimitive.isString && it.jsonPrimitive.content in DIAGNOSTIC_LOSS_REASONS) }
                nonnegative(record.getValue("droppedRecords"))
                if (kind == "terminal") {
                    require(phase == "terminal" && record.getValue("priorRecordsComplete").jsonPrimitive.booleanOrNull != null)
                    require(record["shutdownDrainConfirmed"] == JsonPrimitive(false))
                    require(record["outcome"] in setOf(JsonPrimitive("success"), JsonPrimitive("failure")))
                }
            }
        }
    }

    @Test
    fun `diagnostic provenance accepts provisioned copy and rejects foreign runtime or mutated manifest`(@TempDir root: Path) {
        val configuredReference = Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bundledGhidraReference")))
        val referenceBytes = readStable(configuredReference, 8 * 1024 * 1024)
        val reference = GccBundledGhidraReference.parse(referenceBytes)
        val installation = privateDirectory(root.resolve("provisioned-application"))
        val selectedRoot = Files.createDirectories(installation.resolve("libexec/ghidra")).toRealPath()
        val copiedReference = Files.createDirectories(installation.resolve("lib"))
            .resolve("gcc-bundled-ghidra-reference-v1.json")
        Files.write(copiedReference, referenceBytes, CREATE_NEW)
        fun runtime(bundleRoot: Path) = GccBundledGhidraRuntime(bundleRoot, reference.classPath.map { relative ->
            val entry = reference.entries.getValue(relative)
            GccBundledGhidraClassPathEntry(bundleRoot.resolve(relative), requireNotNull(entry.bytes), requireNotNull(entry.sha256))
        }, invocationVersion = 7)
        val selected = runtime(selectedRoot)
        // This fixture checks selection and reference consistency; it creates no execution authority.
        val artifacts = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.mapIndexed { index, role ->
            val relative = when (role) {
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> "decomp-ghidra-bridge.jar"
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> "scripts/RunBundledExports.class"
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> "bundle.sha256"
                else -> null
            }
            val entry = relative?.let(reference.entries::getValue)
            GccCompilerEngineContainmentArtifactIdentity(role,
                relative?.let(selectedRoot::resolve) ?: root.resolve(
                    if (role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE) "ExportProgramModel.java" else role.wireName),
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> reference.exporterBytes
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> 569445154L
                    else -> entry?.bytes ?: index + 1L
                },
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> reference.exporterSha256
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> decompengine.analysis.BundledGhidra.ARCHIVE_SHA256
                    else -> entry?.sha256 ?: "a".repeat(64)
                })
        }
        fun verify(candidate: GccBundledGhidraRuntime = selected,
            identities: List<GccCompilerEngineContainmentArtifactIdentity> = artifacts,
            retained: ByteArray = readStable(copiedReference, 8 * 1024 * 1024)) =
            requireDiagnosticRuntimeSelection(installation, candidate, identities, retained, configuredReference)
        assertTrue(selectedRoot != Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bundledGhidraRoot"))))
        verify()
        val foreignRoot = Files.createDirectories(root.resolve("foreign-application/libexec/ghidra")).toRealPath()
        val foreignArtifacts = artifacts.map { identity ->
            if (identity.path.startsWith(selectedRoot))
                identity.copy(path = foreignRoot.resolve(selectedRoot.relativize(identity.path))) else identity
        }
        val foreignRuntime = runtime(foreignRoot)
        reference.requireCandidate(foreignRuntime, foreignArtifacts)
        assertFailsWith<IllegalArgumentException> { verify(candidate = foreignRuntime, identities = foreignArtifacts) }
        val changedManifest = artifacts.map { identity ->
            if (identity.role == GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST)
                identity.copy(sha256 = "0".repeat(64)) else identity
        }
        assertFailsWith<IllegalArgumentException> { verify(identities = changedManifest) }
        Files.write(copiedReference, referenceBytes + byteArrayOf(10))
        assertFailsWith<IllegalArgumentException> { verify() }
        Files.write(copiedReference, referenceBytes)
        verify()
    }

    @Test
    fun `BOOT generation mismatch prevents launch and preserves preflight primary through capture failure`() {
        val expected = "generation-A".toByteArray()
        val installed = "generation-B".toByteArray()
        val captureFailure = IllegalStateException("injected capture failure")
        var launches = 0
        var captures = 0
        var capturedPrimary: Throwable? = null
        val mismatch = assertFailsWith<DiagnosticBootReferenceMismatch> {
            withBootAlignedDiagnosticCapture({ expected }, { installed }, { primary ->
                captures++; capturedPrimary = primary; throw captureFailure
            }) { launches++; 0 }
        }
        assertEquals(0, launches); assertEquals(1, captures)
        assertSame(mismatch, capturedPrimary)
        assertEquals(listOf(captureFailure), mismatch.suppressed.toList())
        assertEquals(setOf("reason", "expectedBytes", "installedBytes", "expectedSha256", "installedSha256"), mismatch.facts.keys)
        assertEquals(JsonPrimitive("BOOT_REFERENCE_BYTE_MISMATCH"), mismatch.facts["reason"])
        assertEquals(JsonPrimitive(expected.size), mismatch.facts["expectedBytes"])
        assertEquals(JsonPrimitive(installed.size), mismatch.facts["installedBytes"])
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(expected)), mismatch.facts["expectedSha256"])
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(installed)), mismatch.facts["installedSha256"])
        assertEquals(mismatch.facts, diagnosticBootMismatchFacts(mismatch, captureFailure))
        assertTrue(OracleJson.canonicalBytes(mismatch.facts).size < 512)
    }

    @Test
    fun `equal BOOT reference bytes launch exactly once and retain postcapture comparison`() {
        val expected = "generation-A".toByteArray()
        val installed = expected.copyOf()
        var launches = 0
        var captures = 0
        val result = withBootAlignedDiagnosticCapture({ expected }, { installed }, { primary ->
            captures++; assertTrue(primary == null)
            requireDiagnosticBootAlignment(expected, installed)
        }) { launches++; 17 }
        assertEquals(17, result); assertEquals(1, launches); assertEquals(1, captures)
        assertEquals(JsonNull, diagnosticBootMismatchFacts(null, null))
    }

    @Test
    fun `postlaunch BOOT mutation is still refused by the shared strict comparator`() {
        val expected = "generation-A".toByteArray()
        var installed = expected.copyOf()
        var launches = 0
        var captures = 0
        val mismatch = assertFailsWith<DiagnosticBootReferenceMismatch> {
            withBootAlignedDiagnosticCapture({ expected }, { installed }, { primary ->
                captures++; assertTrue(primary == null)
                requireDiagnosticBootAlignment(expected, installed)
            }) { launches++; installed = "generation-B".toByteArray(); 0 }
        }
        assertEquals(1, launches); assertEquals(1, captures)
        assertEquals(mismatch.facts, diagnosticBootMismatchFacts(null, mismatch))
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(installed)), mismatch.facts["installedSha256"])
    }

    @Test
    fun `BOOT alignment keeps each existing byte ceiling and refuses before launch`() {
        // These are byte-alignment controls, not parsed reference or runtime authority.
        val exact = ByteArray(MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES)
        var launches = 0
        withBootAlignedDiagnosticCapture({ exact }, { exact.copyOf() }, {}) { launches++ }
        assertEquals(1, launches)
        val over = ByteArray(MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES + 1)
        for ((expected, installed) in listOf(over to exact, exact to over, byteArrayOf() to exact, exact to byteArrayOf())) {
            var captures = 0
            assertFailsWith<IllegalArgumentException> {
                withBootAlignedDiagnosticCapture({ expected }, { installed }, { primary ->
                    captures++; assertTrue(primary is IllegalArgumentException)
                }) { launches++ }
            }
            assertEquals(1, captures)
        }
        assertEquals(1, launches)
    }

    @Test
    fun `launched primary failure survives a later BOOT mismatch during capture`() {
        val expected = "generation-A".toByteArray()
        var installed = expected.copyOf()
        val original = IllegalStateException("injected command failure")
        var launches = 0
        val retained = assertFailsWith<IllegalStateException> {
            withBootAlignedDiagnosticCapture({ expected }, { installed }, { primary ->
                assertSame(original, primary)
                requireDiagnosticBootAlignment(expected, installed)
            }) { launches++; installed = "generation-B".toByteArray(); throw original }
        }
        assertEquals(1, launches); assertSame(original, retained)
        assertEquals(1, original.suppressed.size)
        assertTrue(original.suppressed.single() is DiagnosticBootReferenceMismatch)
    }

    @Test
    fun `runtime diagnostic capture preserves original failure and records missing terminal`() {
        val original = IllegalStateException("original command failed")
        val captureFailure = IllegalArgumentException("capture failed")
        assertSame(original, assertFailsWith<IllegalStateException> {
            withDiagnosticCapture({ failure -> assertSame(original, failure); throw captureFailure }) { throw original }
        })
        assertTrue(original.suppressed.contains(captureFailure))
        assertSame(captureFailure, assertFailsWith<IllegalArgumentException> {
            withDiagnosticCapture({ throw captureFailure }) { 0 }
        })
        val empty = parseRuntimeTelemetry(byteArrayOf(), false)
        assertEquals(JsonPrimitive(false), empty["telemetryComplete"])
        assertTrue(JsonPrimitive("missing_terminal") in empty.getValue("problems").jsonArray)
    }

    @Test
    fun `failed runtime capture records missing metadata without synthesizing receipts`(@TempDir root: Path) {
        val scratch = privateDirectory(root.resolve("scratch"))
        val evidence = privateDirectory(root.resolve("evidence"))
        val output = privateDirectory(evidence.resolve("cli-output"))
        privateDirectory(output.resolve("journal"))
        privateDirectory(output.resolve("inputs"))
        val installation = privateDirectory(root.resolve("installation"))
        val profile = Files.writeString(root.resolve("profile.json"), "invalid profile")
        val args = listOf("cc1", root.resolve("binary").toString(), "--profile", profile.toString(),
            "--ghidra-archive", root.resolve("archive").toString(), "--output", output.toString(), "--scratch", scratch.toString())
        val options = GccBundledCliOptions.parse(args, true, true)
        val original = AssertionError("CLI rejected input before START")
        assertSame(original, assertFailsWith<AssertionError> {
            withDiagnosticCapture({ failure -> captureRuntimeDiagnostics(options, args, installation, evidence, 1, failure) }) {
                throw original
            }
        })
        val summary = OracleJson.parseCanonical(Files.readAllBytes(evidence.resolve("diagnostic.json"))).jsonObject
        assertEquals(JsonPrimitive("unavailable-or-invalid"), summary["provenanceStatus"])
        assertEquals(JsonPrimitive(1), summary["launcherExitCode"])
        assertEquals(JsonPrimitive("absent"), summary.getValue("metadata").jsonObject.getValue("invocation.json").jsonObject["status"])
        assertEquals(JsonPrimitive("absent"), summary.getValue("logStreams").jsonObject["stdout"])
        assertFalse(Files.exists(evidence.resolve("qualification.json")))
        assertFalse(Files.exists(evidence.resolve("diagnostic-captured/execution.json")))
        assertFalse(Files.exists(output.resolve("result.json")))
        assertEquals(JsonPrimitive(false), summary["complete"])
    }

    @Test
    fun `runtime log capture retains both bounded streams and refuses substituted symlinks`(@TempDir root: Path) {
        val scratch = privateDirectory(root.resolve("scratch"))
        val stdout = failureStdoutFixture(scratch)
        Files.writeString(stdout, "stdout", CREATE_NEW)
        Files.writeString(stdout.resolveSibling("contained-command.stderr"), "stderr", CREATE_NEW)
        val captured = privateDirectory(root.resolve("captured"))
        val logs = captureRuntimeLogPrefixes(scratch, captured)
        assertTrue(logs.getValue("stdout").contentEquals("stdout".toByteArray()))
        assertTrue(logs.getValue("stderr").contentEquals("stderr".toByteArray()))
        Files.delete(stdout)
        Files.createSymbolicLink(stdout, stdout.resolveSibling("contained-command.stderr"))
        val rejected = privateDirectory(root.resolve("rejected"))
        assertFailsWith<java.io.IOException> { captureRuntimeLogPrefixes(scratch, rejected) }
        assertFalse(Files.exists(rejected.resolve("diagnostic-stdout.bin")))
    }

    @Test
    fun `diagnostic journal gaps and unreadable records cannot become successful provenance`() {
        fun status(value: String) = JsonObject(mapOf("status" to JsonPrimitive(value)))
        val all = DIAGNOSTIC_JOURNAL_FILES.associateWith { status("captured") }
        requireDiagnosticRecordAvailability(all, true)
        val missingExecution = all + ("execution.json" to status("absent"))
        assertFailsWith<IllegalArgumentException> { requireDiagnosticRecordAvailability(missingExecution, true) }
        requireDiagnosticRecordAvailability(missingExecution, false)
        for (name in DIAGNOSTIC_JOURNAL_FILES) {
            assertFailsWith<IllegalArgumentException> {
                requireDiagnosticRecordAvailability(all + (name to status("capture-failed")), false)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            requireDiagnosticRecordAvailability(all + ("start-authorized.json" to status("absent")), false)
        }
    }

    @Test
    fun `diagnostic execution rejects internally altered receipts despite recomputed outer links`(@TempDir root: Path) {
        val control = privateDirectory(root.resolve("control"))
        val request = KotlinContainedCommandRequest(control, "a".repeat(64), listOf("/usr/bin/java", "-version"),
            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 300, 14400, 65536, 65536)
        val resources = KotlinSystemdCgroupCommandResources(14_400_000, 16L * 1024 * 1024 * 1024, 128, 1024 * 1024, 4)
        val roles = listOf("outer-bubblewrap", "namespace-init-bubblewrap", "supervisor-jvm")
        fun attachChecksum(fields: Map<String, JsonElement>) = JsonObject(fields + ("attachmentSha256" to
            JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))))
        val attachmentFields = mapOf("schemaVersion" to JsonPrimitive(2), "provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v2"),
            "unitName" to JsonPrimitive("diagnostic.scope"), "nonce" to JsonPrimitive(request.nonce),
            "bootId" to JsonPrimitive("11111111-1111-1111-1111-111111111111"), "invocationId" to JsonPrimitive("1".repeat(32)),
            "controlGroup" to JsonPrimitive("/diagnostic.scope"), "cgroupDevice" to JsonPrimitive(1),
            "cgroupInode" to JsonPrimitive(1), "cgroupMountId" to JsonPrimitive(1),
            "requestSha256" to JsonPrimitive(request.sha256), "deploymentClosureSha256" to JsonPrimitive("b".repeat(64)),
            "runtimeClosureSha256" to JsonPrimitive("d".repeat(64)), "releaseEligible" to JsonPrimitive(false),
            "resources" to JsonObject(resources.json() + mapOf("maximumAddressSpaceBytes" to JsonPrimitive(64L * 1024 * 1024 * 1024),
                "cpuSeconds" to JsonPrimitive(resources.aggregateCpuSeconds), "serviceRuntimeSeconds" to JsonPrimitive(resources.aggregateCpuSeconds))),
            "hostCpuCapacity" to JsonObject(mapOf("provider" to JsonPrimitive("linux-affinity-cgroup-capacity-v1"),
                "affinityProcessors" to JsonPrimitive(4), "quotaProcessors" to JsonNull, "controlGroup" to JsonPrimitive("/diagnostic.scope"),
                "maximumAdmittedProcessors" to JsonPrimitive(4))),
            "processes" to JsonArray(roles.mapIndexed { index, role -> JsonObject(mapOf(
                "role" to JsonPrimitive(role), "hostPid" to JsonPrimitive(index + 100), "startTimeTicks" to JsonPrimitive(1),
                "parentRole" to (if (index == 0) JsonNull else JsonPrimitive(roles[index - 1])),
                "namespacePids" to JsonArray(listOf(JsonPrimitive(index + 100))), "executableDevice" to JsonPrimitive(1),
                "executableInode" to JsonPrimitive(1), "executableMountId" to JsonPrimitive(1))) }))
        val attachment = attachChecksum(attachmentFields)
        requireDiagnosticAttachmentRecord(attachment)
        for ((name, value) in mapOf("schemaVersion" to JsonPrimitive(1), "releaseEligible" to JsonPrimitive(true),
            "runtimeClosureSha256" to JsonPrimitive("invalid"))) {
            assertFailsWith<IllegalArgumentException> { requireDiagnosticAttachmentRecord(attachChecksum(attachmentFields + (name to value))) }
        }
        assertFailsWith<IllegalArgumentException> { requireDiagnosticAttachmentRecord(attachChecksum(attachmentFields - "processes")) }
        val deployment = "b".repeat(64)
        val outcome = JsonObject(mapOf("schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("kotlin-contained-command-protocol-v1"),
            "event" to JsonPrimitive("OUTCOME"), "nonce" to JsonPrimitive(request.nonce), "requestSha256" to JsonPrimitive(request.sha256),
            "keeperPid" to JsonPrimitive(100), "childPid" to JsonPrimitive(101), "exitCode" to JsonPrimitive(0),
            "elapsedMillis" to JsonPrimitive(1), "stdoutBytes" to JsonPrimitive(0), "stderrBytes" to JsonPrimitive(0),
            "status" to JsonPrimitive("EXITED"), "hmacSha256" to JsonPrimitive("c".repeat(64))))
        val identity = LinuxFilesystemSyscalls.openRoot(control).use {
            decompengine.oracle.fulltree.containedControlIdentityJson("control", it.identity)
        }
        val unsigned = mapOf("schemaVersion" to JsonPrimitive(2), "provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v2"),
            "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(attachment))),
            "requestSha256" to JsonPrimitive(request.sha256), "deploymentClosureSha256" to JsonPrimitive(deployment),
            "outcomeSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(outcome))), "outcome" to outcome,
            "childExitCode" to JsonPrimitive(0), "derivationWallNanos" to JsonPrimitive(1),
            "unitAbsent" to JsonPrimitive(true), "cgroupAbsent" to JsonPrimitive(true), "processesAbsent" to JsonPrimitive(true),
            "releaseEligible" to JsonPrimitive(false), "controlDirectory" to JsonPrimitive(control.toString()), "controlDirectoryIdentity" to identity,
            "cgroup" to JsonObject(listOf("peakResidentBytes", "cpuNanos", "memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents")
                .associateWith { JsonPrimitive(if (it == "peakResidentBytes") 1 else 0) }),
            "operationWallTime" to JsonObject(mapOf("provider" to JsonPrimitive("kotlin-contained-operation-wall-deadline-v1"),
                "maximumWallMillis" to JsonPrimitive(14_400_000), "startedMonotonicNanos" to JsonPrimitive(1),
                "elapsedNanos" to JsonPrimitive(1), "remainingNanos" to JsonPrimitive(14_399_999_999_999L))))
        fun checksum(fields: Map<String, JsonElement>) = JsonObject(fields + ("executionSha256" to
            JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))))
        fun validate(record: JsonObject) = requireDiagnosticExecutionRecord(record, attachment, request, deployment,
            control, resources, 14_400_000)
        // These in-memory bytes exercise consistency only; no HMAC secret or execution authority exists.
        validate(checksum(unsigned))
        for ((name, value) in mapOf("provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v1"),
            "schemaVersion" to JsonPrimitive(1), "deploymentClosureSha256" to JsonPrimitive("d".repeat(64)),
            "releaseEligible" to JsonPrimitive(true), "unitAbsent" to JsonPrimitive(false), "childExitCode" to JsonPrimitive(1))) {
            assertFailsWith<IllegalArgumentException> { validate(checksum(unsigned + (name to value))) }
        }
        assertFailsWith<IllegalArgumentException> { validate(JsonObject(checksum(unsigned) + ("executionSha256" to JsonPrimitive("0".repeat(64))))) }
        val badOutcome = JsonObject(outcome + ("status" to JsonPrimitive("TIMED_OUT")))
        assertFailsWith<IllegalArgumentException> { validate(checksum(unsigned + mapOf("outcome" to badOutcome,
            "outcomeSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(badOutcome)))))) }
    }

    @Test
    fun `telemetry markers never grant authority and damaged streams remain incomplete`() {
        val initial = telemetryFixture("initial", 0)
        val terminal = telemetryFixture("terminal", 1)
        val complete = parseRuntimeTelemetry(initial + terminal, false)
        assertEquals(JsonPrimitive(false), complete["telemetryComplete"])
        assertEquals(JsonPrimitive(true), complete["priorRecordsConsistent"], complete.toString())
        assertEquals(JsonPrimitive(true), complete["terminalObserved"])
        assertEquals(JsonPrimitive(true), complete["shutdownDrainUnconfirmed"])
        for (field in listOf("complete", "scored", "benchmarkAccepted", "releaseEligible")) {
            assertEquals(JsonPrimitive(false), complete[field])
        }
        val cases = listOf(
            initial, initial + terminal.dropLast(1), initial + telemetryFixture("terminal", 2),
            initial + initial + terminal, initial + terminal + terminal,
            initial + "other output".toByteArray() + terminal,
            initial + (DIAGNOSTIC_PREFIX + "{broken}\n").toByteArray() + terminal,
            initial + telemetryFixture("terminal", 1, listOf("queue_saturation")),
        )
        cases.forEach { bytes -> assertEquals(JsonPrimitive(false), parseRuntimeTelemetry(bytes, false)["priorRecordsConsistent"]) }
        assertEquals(JsonPrimitive(false), parseRuntimeTelemetry(initial + terminal, true)["priorRecordsConsistent"])
        val bounded = parseRuntimeTelemetry((0..640).fold(byteArrayOf()) { bytes, i -> bytes + telemetryFixture("initial", i.toLong()) }, false)
        assertTrue(bounded.getValue("records").jsonArray.size <= 640)
        assertEquals(JsonPrimitive(false), bounded["telemetryComplete"])
    }

    @Test
    fun `telemetry parser accepts bounded Unicode fields and reports oversized values`() {
        fun named(value: String) = telemetryFixture("initial", 0).toString(Charsets.UTF_8)
            .replace("\"jvmName\":null", "\"jvmName\":" + JsonPrimitive(value)).toByteArray()
        for (value in listOf("界".repeat(80), "é".repeat(128), "λ\"\\".repeat(32))) {
            val snapshot = parseRuntimeTelemetry(named(value) + telemetryFixture("terminal", 1), false)
            assertEquals(JsonPrimitive(true), snapshot["priorRecordsConsistent"], snapshot.toString())
            assertEquals(JsonPrimitive(false), snapshot["telemetryComplete"])
        }
        val oversized = parseRuntimeTelemetry(named("界".repeat(128)) + telemetryFixture("terminal", 1), false)
        assertEquals(JsonPrimitive(false), oversized["priorRecordsConsistent"])
        assertTrue(JsonPrimitive("malformed_frame") in oversized.getValue("problems").jsonArray)
    }

    private fun telemetryFixture(kind: String, sequence: Long, reasons: List<String> = emptyList()): ByteArray {
        val fields = mutableMapOf<String, JsonElement>("policy" to JsonPrimitive("jvm-mxbean-stdout-v1"),
            "sequence" to JsonPrimitive(sequence), "elapsedNanos" to JsonPrimitive(sequence), "kind" to JsonPrimitive(kind),
            "phase" to JsonPrimitive(if (kind == "initial") "init" else "terminal"))
        if (kind == "initial") {
            for (name in listOf("jvmName", "jvmVendor", "jvmVersion", "javaVersion", "processors", "heap", "collectors")) fields[name] = JsonNull
        } else {
            fields += mapOf("priorRecordsComplete" to JsonPrimitive(reasons.isEmpty()), "shutdownDrainConfirmed" to JsonPrimitive(false), "lossReasons" to JsonArray(reasons.map(::JsonPrimitive)),
                "droppedRecords" to JsonPrimitive(reasons.size), "outcome" to JsonPrimitive("failure"))
        }
        return (DIAGNOSTIC_PREFIX + JsonObject(fields).toString() + "\n").toByteArray()
    }

    @Test
    fun `checked serial default refuses the parallel qualification before any CLI launch`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            requireParallelCc1QualificationProfile(Path.of("oracle/gcc/16.2.0/compiler-engines-exporter17.json").toAbsolutePath().normalize())
        }
        assertEquals(
            "cc1 parallel qualification requires an explicit reviewed runtime6 profile; checked serial default is unqualified",
            failure.message,
        )
    }

    @Test
    fun `the explicit parallel runtime6 profile satisfies the qualification precondition`() {
        requireParallelCc1QualificationProfile(Path.of("oracle/gcc/16.2.0/compiler-engines-exporter17-parallel.json").toAbsolutePath().normalize())
    }

    private fun requireParallelCc1QualificationProfile(profilePath: Path) {
        GccRetainedCompilerEngineProfile.open(profilePath).use { retained ->
            require(retained.suite.fullRecoveryCc1Throughput != null && retained.invocationVersion("cc1", true) == 6) {
                "cc1 parallel qualification requires an explicit reviewed runtime6 profile; checked serial default is unqualified"
            }
        }
    }

    @Test
    fun `live selected GCC full export retains its profile-bound model and receipt evidence`() {
        assumeTrue(
            System.getenv("DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT") == "true",
            "real GCC full-export qualification is opt-in",
        )
        val engine = System.getenv("DECOMP_GCC_CLI_FULL_EXPORT_ENGINE") ?: "cc1"
        require(engine in setOf("cc1", "driver")) { "qualification requires cc1 or driver" }
        val profilePath = configured("DECOMP_GCC_CLI_PROFILE")
        // Refuse before preparing output or launching a CLI; serial success cannot qualify runtime6.
        if (engine == "cc1") requireParallelCc1QualificationProfile(profilePath)
        val installation = configured("DECOMP_GCC_CLI_INSTALLATION")
        val archive = configured("DECOMP_GCC_CLI_ARCHIVE")
        val binary = configured("DECOMP_GCC_CLI_EXPORT_BINARY", "DECOMP_GCC_CLI_CC1_BINARY")
        val scratch = configured("DECOMP_GCC_CLI_EXPORT_SCRATCH", "DECOMP_GCC_CLI_CC1_FRESH_SCRATCH")
        val evidenceRoot = configured("DECOMP_GCC_CLI_EVIDENCE_ROOT")
        assertTrue(Files.isDirectory(scratch, LinkOption.NOFOLLOW_LINKS))
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(evidenceRoot))
        assertTrue(isEmptyDirectory(scratch), "GCC fresh-export scratch must begin empty")
        assertTrue(isEmptyDirectory(evidenceRoot), "GCC export evidence root must begin empty")
        for (input in listOf(installation, profilePath, archive, binary, evidenceRoot)) {
            assertFalse(input.startsWith(scratch) || scratch.startsWith(input), "inputs/evidence must be outside scratch")
        }

        val output = privateDirectory(evidenceRoot.resolve("cli-output"))
        val launcherEvidence = privateDirectory(evidenceRoot.resolve("launcher"))
        val arguments = listOf(
            engine, binary.toString(),
            "--profile", profilePath.toString(),
            "--ghidra-archive", archive.toString(),
            "--output", output.toString(),
            "--scratch", scratch.toString(),
        )
        withFailedCommandStdout(scratch, evidenceRoot) {
            assertEquals(
                0,
                invokeInstalledGccCli(
                    arguments,
                    launcherEvidence,
                    timeoutSeconds = if (engine == "driver") 2100 else 9900,
                    installation = installation,
                    command = "gcc-engine-full-export",
                ),
                "installed GCC full-export CLI failed; inspect retained launcher evidence",
            )
            val launcherSummary = verifyInstalledCliEvidence(
                launcherEvidence, arguments, installation, expectedExit = 0, command = "gcc-engine-full-export",
            )

            val resultBytes = readStable(output.resolve("result.json"), MAXIMUM_RESULT_BYTES)
            val result = OracleJson.parseCanonical(resultBytes).jsonObject
            assertEquals(if (engine == "driver") RESULT_KEYS + setOf("boundaryScore", "functionAccuracy") else RESULT_KEYS, result.keys)
            assertEquals(if (engine == "driver") "gcc-bundled-cli-full-export-result-v3" else "gcc-bundled-cli-full-export-result-v2",
                result.requiredText("provider"))
            assertEquals(if (engine == "driver") 3L else 2L, result.getValue("schemaVersion").jsonPrimitive.long)
            assertFalse(result.getValue("complete").jsonPrimitive.boolean)
            assertFalse(result.getValue("scored").jsonPrimitive.boolean)
            assertFalse(result.getValue("releaseEligible").jsonPrimitive.boolean)

            val operationId = result.requiredText("operationId")
            assertTrue(operationId.matches(Regex("[a-f0-9]{64}")))
            val journal = Path.of(result.requiredText("journal"))
            assertEquals(output.resolve("journal").toRealPath(), journal.parent.toRealPath())
            assertEquals(".gcc-bundled-operation-$operationId", journal.fileName.toString())
            val intentBytes = readStable(journal.resolve("intent.json"), MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(intentBytes), result.requiredText("requestSha256"))
            val executionBytes = readStable(journal.resolve("execution.json"), MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(executionBytes), result.requiredText("executionReceiptSha256"))
            val assessmentBytes = readStable(journal.resolve("export-assessment.json"), MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(assessmentBytes), result.requiredText("exportAssessmentReceiptSha256"))
            val attachmentBytes = readStable(journal.resolve("attachment.json"), MAXIMUM_RECEIPT_BYTES)
            val attachmentRecord = OracleJson.parseCanonical(attachmentBytes).jsonObject
            val attachment = attachmentRecord.getValue("attachment").jsonObject
            val execution = OracleJson.parseCanonical(executionBytes).jsonObject.getValue("execution").jsonObject
            assertEquals(operationId, attachmentRecord.requiredText("operationId"))
            assertEquals(result.requiredText("requestSha256"), attachmentRecord.requiredText("intentSha256"))
            assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(attachmentRecord - "recordSha256"))),
                attachmentRecord.requiredText("recordSha256"))
            assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(attachment)), attachmentRecord.requiredText("attachmentSha256"))
            assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(attachment - "attachmentSha256"))),
                attachment.requiredText("attachmentSha256"))
            assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(attachment)), execution.requiredText("attachmentSha256"))

            val modelPath = Path.of(result.requiredText("programModel"))
            assertTrue(modelPath.startsWith(scratch) && modelPath.toRealPath() == modelPath)
            val modelBytes = result.getValue("programModelBytes").jsonPrimitive.long
            val modelSha256 = result.requiredText("programModelSha256")
            val functionCount = result.getValue("functionCount").jsonPrimitive.long
            assertTrue(modelBytes > 0L && modelBytes <= MAXIMUM_MODEL_BYTES)
            assertTrue(functionCount > 0L)

            val bindingPath = Path.of(result.requiredText("structuralBinding"))
            val manifestPath = Path.of(result.requiredText("outputTreeManifest"))
            assertEquals(output, bindingPath.parent)
            assertEquals(output, manifestPath.parent)
            assertEquals("structural-full-export-binding.json", bindingPath.fileName.toString())
            assertEquals(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME, manifestPath.fileName.toString())
            val bindingBytes = readStable(bindingPath, MAXIMUM_BINDING_BYTES)
            assertEquals(OracleArtifacts.sha256(bindingBytes), result.requiredText("structuralBindingSha256"))
            val binding = OracleJson.parseCanonical(bindingBytes).jsonObject
            assertEquals("gcc-compiler-engine-structural-full-export-binding-v2", binding.requiredText("provider"))
            assertEquals(engine, binding.getValue("receiptLineage").jsonObject.requiredText("engineId"))
            assertEquals(operationId, binding.getValue("receiptLineage").jsonObject.requiredText("operationId"))
            assertEquals(result.requiredText("requestSha256"), binding.getValue("receiptLineage").jsonObject.requiredText("intentSha256"))
            assertEquals(result.requiredText("executionReceiptSha256"), binding.getValue("receiptLineage").jsonObject.requiredText("executionReceiptSha256"))
            assertEquals(result.requiredText("exportAssessmentReceiptSha256"), binding.getValue("receiptLineage").jsonObject.requiredText("exportAssessmentReceiptSha256"))
            assertEquals(result.requiredText("outputTreeSha256"), binding.requiredText("outputTreeSha256"))

            val structural = GccDriverStructuralInputsV1.load(profilePath.parent, engine, profilePath.fileName.toString() == "compiler-engines-exporter17-parallel.json")
            assertEquals(structural.profileId, binding.requiredText("profileId"))
            assertEquals(structural.version, binding.requiredText("profileVersion"))
            assertEquals(structural.sourceRevision, binding.requiredText("sourceRevision"))
            assertEquals(structural.compilerEngineProfileSha256, binding.requiredText("compilerEngineProfileSha256"))
            assertEquals(structural.artifactManifestSha256, binding.requiredText("artifactManifestSha256"))
            val input = binding.getValue("inputBinary").jsonObject
            assertEquals(structural.strippedBinary.sha256, input.requiredText("sha256"))
            assertEquals(structural.strippedBinary.bytes, input.getValue("bytes").jsonPrimitive.long)
            val target = binding.getValue("targetDescriptor").jsonObject
            assertEquals(structural.targetAbi.id, target.requiredText("id"))
            assertEquals(structural.targetAbi.ghidraLanguage, target.requiredText("ghidraLanguage"))
            assertEquals(structural.targetAbi.ghidraCompilerSpec, target.requiredText("ghidraCompilerSpec"))
            assertEquals("0x${structural.imageBase.toString(16)}", target.requiredText("imageBase"))
            assertEquals(structural.inputBinary.executableRangesSha256, target.requiredText("executableRangesSha256"))

            val analysis = GccRetainedCompilerEngineProfile.open(profilePath).use { it.suite.analysis }
            val exporter = binding.getValue("exporter").jsonObject
            assertEquals(analysis.exporterSha256, exporter.requiredText("sha256"))
            assertEquals("full", exporter.requiredText("recoveryMode"))
            val exporterBytes = GccCompilerEngineProfiles::class.java
                .getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")!!.use {
                    it.readNBytes(4 * 1024 * 1024 + 1)
                }
            assertTrue(exporterBytes.size <= 4 * 1024 * 1024)
            assertEquals(exporterBytes.size.toLong(), exporter.getValue("bytes").jsonPrimitive.long)
            val archiveBinding = binding.getValue("ghidraArchive").jsonObject
            assertEquals(analysis.ghidraArchive.sha256, archiveBinding.requiredText("sha256"))
            assertEquals(analysis.ghidraArchive.bytes, archiveBinding.getValue("bytes").jsonPrimitive.long)

            val programModel = binding.getValue("programModel").jsonObject
            assertEquals(modelSha256, programModel.requiredText("sha256"))
            assertEquals(modelBytes, programModel.getValue("bytes").jsonPrimitive.long)
            assertEquals(functionCount, programModel.getValue("functionCount").jsonPrimitive.long)
            val manifestBytes = readStable(manifestPath, MAXIMUM_TREE_MANIFEST_BYTES)
            assertEquals(OracleArtifacts.sha256(manifestBytes), result.requiredText("outputTreeManifestSha256"))
            val treeManifest = OracleJson.parseCanonical(manifestBytes, TREE_MANIFEST_LIMITS).jsonObject
            assertEquals(result.requiredText("outputTreeSha256"), treeManifest.requiredText("outputTreeSha256"))
            assertEquals(
                binding.requiredText("outputTreeSha256"),
                OracleArtifacts.sha256(OracleJson.canonicalBytes(treeManifest.getValue("tree").jsonObject, TREE_MANIFEST_LIMITS)),
            )

            val captured = privateDirectory(evidenceRoot.resolve("captured"))
            copyStable(modelPath, captured.resolve("program_model.json"), MAXIMUM_MODEL_BYTES, modelBytes, modelSha256)
            captureFailureDiagnostics(modelPath, treeManifest, binding.requiredText("outputTreeSha256"), captured)
            val diagnosticStdout = captureCommandStdout(executionBytes, scratch, captured)
            publish(captured.resolve("result.json"), resultBytes)
            publish(captured.resolve("structural-full-export-binding.json"), bindingBytes)
            publish(captured.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME), manifestBytes)
            publish(captured.resolve("intent.json"), intentBytes)
            publish(captured.resolve("attachment.json"), attachmentBytes)
            publish(captured.resolve("execution.json"), executionBytes)
            publish(captured.resolve("export-assessment.json"), assessmentBytes)
            publish(captured.resolve("launcher-summary.json"), OracleJson.canonicalBytes(launcherSummary))
            val boundaryFields = if (engine == "driver") {
                val observationName = GccDriverStructuralBoundaryEvidenceV1.OBSERVATION_NAME
                val boundaryName = GccDriverStructuralBoundaryEvidenceV1.BINDING_NAME
                val observationBytes = readStable(output.resolve(observationName),
                    GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_OBSERVATION_BYTES)
                val boundaryBytes = readStable(output.resolve(boundaryName),
                    GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_BINDING_BYTES)
                val capturedModel = readStable(captured.resolve("program_model.json"), MAXIMUM_MODEL_BYTES.toInt())
                GccDriverStructuralBoundaryEvidenceV1.verifyRetained(
                    structural, bindingBytes, capturedModel, observationBytes, boundaryBytes,
                )
                val detachedBinding = OracleJson.canonicalBytes(JsonObject(binding +
                    ("outputTreeSha256" to JsonPrimitive("0".repeat(64)))))
                assertFailsWith<IllegalArgumentException>("boundary evidence must reject a substituted full-export tree") {
                    GccDriverStructuralBoundaryEvidenceV1.verifyRetained(
                        structural, detachedBinding, capturedModel, observationBytes, boundaryBytes,
                    )
                }
                publish(captured.resolve(observationName), observationBytes)
                publish(captured.resolve(boundaryName), boundaryBytes)
                val scorePointer = result.getValue("boundaryScore").jsonObject
                assertEquals(setOf("path", "sha256", "bytes", "scope"), scorePointer.keys)
                assertEquals("model-provenance-and-selected-function-boundaries", scorePointer.requiredText("scope"))
                val scorePath = Path.of(scorePointer.requiredText("path"))
                assertEquals(output.resolve(GccBundledFullExportCliResultV2.PRODUCTION_BOUNDARY_SCORE_NAME), scorePath)
                val scoreBytes = readStable(scorePath, GccBundledStructuralReplayOutputCapture.MAXIMUM_OBSERVATION_BYTES)
                assertEquals(scorePointer.requiredText("sha256"), OracleArtifacts.sha256(scoreBytes))
                assertEquals(scorePointer.getValue("bytes").jsonPrimitive.long, scoreBytes.size.toLong())
                val score = OracleJson.parseCanonical(scoreBytes, TREE_MANIFEST_LIMITS).jsonObject
                assertEquals("structural-selected-boundary-production-score-v1", score.requiredText("provider"))
                assertTrue(score.getValue("productionVerified").jsonPrimitive.boolean)
                assertTrue(score.getValue("scored").jsonPrimitive.boolean)
                assertFalse(score.getValue("complete").jsonPrimitive.boolean)
                assertFalse(score.getValue("releaseEligible").jsonPrimitive.boolean)
                assertEquals(setOf("model-provenance", "function-boundaries", "surviving-symbol-identities"),
                    score.getValue("admittedDomains").jsonArray.map { it.jsonPrimitive.content }.toSet())
                assertEquals(setOf("interfaces", "calls", "globals", "types", "calibration"),
                    score.getValue("unavailableDomains").jsonArray.map { it.jsonPrimitive.content }.toSet())
                assertEquals(modelSha256, score.requiredText("programModelSha256"))
                assertEquals(OracleArtifacts.sha256(bindingBytes), score.requiredText("fullExportBindingSha256"))
                assertEquals(binding, score.getValue("fullExportBinding"))
                assertEquals(OracleArtifacts.sha256(observationBytes), score.requiredText("boundaryObservationSha256"))
                assertEquals(OracleJson.parse(observationBytes, TREE_MANIFEST_LIMITS), score.getValue("boundaryObservation"))
                val replayNames = mapOf("structural-replay-request.json" to "replayRequestSha256",
                    "structural-replay-attachment.json" to "replayAttachmentSha256",
                    "structural-replay-execution.json" to "replayExecutionSha256",
                    "structural-replay-output.json" to "replayMetadataSha256",
                    "structural-replay-capture.json" to "replayCaptureSha256")
                for ((name, digestField) in replayNames) {
                    val retained = readStable(output.resolve(name), MAXIMUM_RECEIPT_BYTES)
                    assertEquals(score.requiredText(digestField), OracleArtifacts.sha256(retained))
                    publish(captured.resolve(name), retained)
                }
                val replayExecution = OracleJson.parseCanonical(readStable(output.resolve("structural-replay-execution.json"),
                    MAXIMUM_RECEIPT_BYTES)).jsonObject
                assertEquals(0L, replayExecution.getValue("childExitCode").jsonPrimitive.long)
                for (absent in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) {
                    assertTrue(replayExecution.getValue(absent).jsonPrimitive.boolean)
                }
                val replayAttachment = OracleJson.parseCanonical(readStable(output.resolve("structural-replay-attachment.json"),
                    MAXIMUM_RECEIPT_BYTES)).jsonObject
                val replayLimits = replayAttachment.getValue("resources").jsonObject
                assertTrue(replayLimits.getValue("maximumResidentBytes").jsonPrimitive.long <= 4L * 1024 * 1024 * 1024)
                assertTrue(replayLimits.getValue("wallClockMillis").jsonPrimitive.long <= 300_000)
                publish(captured.resolve(GccBundledFullExportCliResultV2.PRODUCTION_BOUNDARY_SCORE_NAME), scoreBytes)
                val accuracyPointer = result.getValue("functionAccuracy").jsonObject
                assertEquals(setOf("path", "sha256", "bytes", "scope"), accuracyPointer.keys)
                assertEquals(GccDriverProductionFunctionAccuracyV1.SCOPE, accuracyPointer.requiredText("scope"))
                val accuracyPath = Path.of(accuracyPointer.requiredText("path"))
                assertEquals(output.resolve(GccDriverProductionFunctionAccuracyV1.SCORE_NAME), accuracyPath)
                val accuracyBytes = readStable(accuracyPath, GccBundledStructuralReplayOutputCapture.MAXIMUM_OBSERVATION_BYTES)
                assertEquals(accuracyPointer.requiredText("sha256"), OracleArtifacts.sha256(accuracyBytes))
                assertEquals(accuracyPointer.getValue("bytes").jsonPrimitive.long, accuracyBytes.size.toLong())
                val accuracy = OracleJson.parseCanonical(accuracyBytes, TREE_MANIFEST_LIMITS).jsonObject
                assertEquals("gcc-driver-production-function-accuracy-v1", accuracy.requiredText("provider"))
                assertTrue(accuracy.getValue("benchmarkAccepted").jsonPrimitive.boolean)
                assertFalse(accuracy.getValue("complete").jsonPrimitive.boolean)
                assertFalse(accuracy.getValue("releaseEligible").jsonPrimitive.boolean)
                val accuracyScore = accuracy.getValue("score").jsonObject
                assertEquals(modelSha256, accuracyScore.requiredText("programModelSha256"))
                assertEquals(OracleArtifacts.sha256(scoreBytes), accuracyScore.requiredText("boundaryScoreSha256"))
                assertEquals(OracleArtifacts.sha256(observationBytes), accuracyScore.requiredText("boundaryObservationSha256"))
                assertTrue(accuracyScore.getValue("productionVerified").jsonPrimitive.boolean)
                val measurements = accuracyScore.getValue("measurements").jsonObject
                val starts = measurements.getValue("functionStarts").jsonObject
                val exact = starts.getValue("exactMatches").jsonPrimitive.long
                assertTrue(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(exact,
                    starts.getValue("scoredRecoveredCount").jsonPrimitive.long))
                assertTrue(GccDriverProductionFunctionAccuracyV1.meetsExactStartThreshold(exact,
                    starts.getValue("referenceCount").jsonPrimitive.long))
                val identities = measurements.getValue("survivingSymbolIdentity").jsonObject
                assertEquals(6L, identities.getValue("population").jsonPrimitive.long)
                assertEquals(6L, identities.getValue("exact").jsonPrimitive.long)
                assertEquals(6, identities.getValue("symbols").jsonArray.size)
                assertTrue(identities.getValue("symbols").jsonArray.all { it.jsonObject.requiredText("outcome") == "exact" })
                assertEquals(setOf("_obstack_begin", "_obstack_begin_1", "_obstack_newchunk", "_obstack_allocated_p",
                    "_obstack_free", "_obstack_memory_used"), identities.getValue("symbols").jsonArray
                    .map { it.jsonObject.requiredText("name") }.toSet())
                val independentlyDerived = decompengine.oracle.structural.StructuralFunctionAccuracyV1.derive(
                    OracleJson.parse(observationBytes, TREE_MANIFEST_LIMITS).jsonObject)
                assertEquals(independentlyDerived, measurements)
                publish(captured.resolve(GccDriverProductionFunctionAccuracyV1.SCORE_NAME), accuracyBytes)
                mapOf(
                    "boundaryObservationSha256" to JsonPrimitive(OracleArtifacts.sha256(observationBytes)),
                    "boundaryBindingSha256" to JsonPrimitive(OracleArtifacts.sha256(boundaryBytes)),
                    "productionBoundaryScoreSha256" to JsonPrimitive(OracleArtifacts.sha256(scoreBytes)),
                    "productionFunctionAccuracySha256" to JsonPrimitive(OracleArtifacts.sha256(accuracyBytes)),
                )
            } else emptyMap()
            val throughputFields = if (engine == "cc1") {
                val intent = OracleJson.parseCanonical(intentBytes).jsonObject
                val runtime = intent.getValue("bundledRuntime").jsonObject
                assertEquals("bundled-ghidra-java-api-runtime-v6", runtime.requiredText("provider"))
                for (field in listOf("processorCount", "analysisThreadCount", "decompilerWorkerCount")) {
                    assertEquals(4L, runtime.getValue(field).jsonPrimitive.long)
                }
                assertEquals("kotlin-lease-contained-command-attachment-v2", attachment.requiredText("provider"))
                val resources = attachment.getValue("resources").jsonObject
                assertEquals(4L, resources.getValue("processorCount").jsonPrimitive.long)
                val capacity = attachment.getValue("hostCpuCapacity").jsonObject
                assertTrue(capacity.getValue("affinityProcessors").jsonPrimitive.long >= 4)
                assertTrue(capacity.getValue("quotaProcessors") == JsonNull || capacity.getValue("quotaProcessors").jsonPrimitive.long >= 4)
                assertEquals(attachment.requiredText("controlGroup"), capacity.requiredText("controlGroup"))
                val accounting = execution.getValue("cgroup").jsonObject
                val cpuNanos = accounting.getValue("cpuNanos").jsonPrimitive.long
                val residentBytes = accounting.getValue("peakResidentBytes").jsonPrimitive.long
                assertTrue(cpuNanos <= Math.multiplyExact(resources.getValue("cpuSeconds").jsonPrimitive.long, 1_000_000_000L))
                assertTrue(residentBytes <= 16L * 1024 * 1024 * 1024)
                val assessment = OracleJson.parseCanonical(assessmentBytes).jsonObject.getValue("assessment").jsonObject
                val wallNanos = assessment.getValue("operationWallTime").jsonObject.getValue("elapsedNanos").jsonPrimitive.long
                mapOf(
                    "processorCount" to JsonPrimitive(4),
                    "operationWallNanos" to JsonPrimitive(wallNanos),
                    "cpuNanos" to JsonPrimitive(cpuNanos),
                    "peakResidentBytes" to JsonPrimitive(residentBytes),
                    "referenceWallBudgetSeconds" to JsonPrimitive(1_800),
                    "referenceBudgetPassed" to JsonPrimitive(wallNanos <= 1_800_000_000_000L),
                )
            } else emptyMap()
            val summary = JsonObject(mapOf(
                "provider" to JsonPrimitive(if (engine == "driver") "gcc-driver-live-full-export-capture-v1" else "gcc-live-full-export-capture-v1"),
                "engine" to JsonPrimitive(engine),
                "operationId" to JsonPrimitive(operationId),
                "requestSha256" to JsonPrimitive(result.requiredText("requestSha256")),
                "programModelSha256" to JsonPrimitive(modelSha256),
                "programModelBytes" to JsonPrimitive(modelBytes),
                "functionCount" to JsonPrimitive(functionCount),
                "outputTreeSha256" to JsonPrimitive(result.requiredText("outputTreeSha256")),
                "diagnosticStdoutBytes" to JsonPrimitive(diagnosticStdout.first),
                "diagnosticStdoutSha256" to JsonPrimitive(diagnosticStdout.second),
                "diagnosticStdoutAuthority" to JsonPrimitive("diagnostic-only"),
                "complete" to JsonPrimitive(false),
                "scored" to JsonPrimitive(false),
                "benchmarkAccepted" to JsonPrimitive(false),
                "releaseEligible" to JsonPrimitive(false),
                "limitation" to JsonPrimitive(if (engine == "driver")
                    "live contained driver export and selected function-boundary replay only; structural identity admission and production scoring remain open"
                    else "live contained export only; independent identity replay and production scoring remain open"),
            ) + boundaryFields + throughputFields)
            publish(evidenceRoot.resolve("qualification.json"), OracleJson.canonicalBytes(summary))
            if (engine == "cc1") assertTrue(summary.getValue("referenceBudgetPassed").jsonPrimitive.boolean,
                "cc1 export exceeded the 30-minute reference budget; completed diagnostic evidence was retained")
            println("Retained unscored live $engine full-export evidence at $captured (${modelBytes} model bytes, $functionCount functions)")
        }
    }

    @Test
    fun `live selected GCC native call observations retain profile-bound capture evidence`() {
        assumeTrue(
            System.getenv("DECOMP_REQUIRE_GCC_NATIVE_CALLS") == "true",
            "real GCC native-call collection is opt-in",
        )
        require(System.getenv("DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT") != "true" &&
            System.getenv("DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS") != "true") {
            "native-call collection must run alone"
        }
        val engine = System.getenv("DECOMP_GCC_CLI_FULL_EXPORT_ENGINE") ?: "cc1"
        require(engine in setOf("cc1", "driver")) { "native calls require cc1 or driver" }
        val profilePath = configured("DECOMP_GCC_CLI_PROFILE")
        require(profilePath.fileName.toString() == "compiler-engines-exporter17.json") {
            "native calls require the serial exporter17 profile"
        }
        val (selectedProfile, selectedAnalysis) = GccRetainedCompilerEngineProfile.open(profilePath, engine).use {
            it.requireNativeCallProfile() to it.suite.analysis
        }
        assertEquals(engine, selectedProfile.engineId)
        val installation = configured("DECOMP_GCC_CLI_INSTALLATION")
        val archive = configured("DECOMP_GCC_CLI_ARCHIVE")
        val binary = configured("DECOMP_GCC_CLI_EXPORT_BINARY", "DECOMP_GCC_CLI_CC1_BINARY")
        val scratch = configured("DECOMP_GCC_CLI_EXPORT_SCRATCH", "DECOMP_GCC_CLI_CC1_FRESH_SCRATCH")
        val evidenceRoot = configured("DECOMP_GCC_CLI_EVIDENCE_ROOT")
        assertTrue(Files.isDirectory(scratch, LinkOption.NOFOLLOW_LINKS))
        assertEquals(PosixFilePermissions.fromString("rwx------"), Files.getPosixFilePermissions(evidenceRoot))
        assertTrue(isEmptyDirectory(scratch), "GCC native-call scratch must begin empty")
        assertTrue(isEmptyDirectory(evidenceRoot), "GCC native-call evidence root must begin empty")
        for (input in listOf(installation, profilePath, archive, binary, evidenceRoot)) {
            assertFalse(input.startsWith(scratch) || scratch.startsWith(input), "inputs/evidence must be outside scratch")
        }

        val output = privateDirectory(evidenceRoot.resolve("cli-output"))
        val launcherEvidence = privateDirectory(evidenceRoot.resolve("launcher"))
        val arguments = listOf(
            engine, binary.toString(),
            "--profile", profilePath.toString(),
            "--ghidra-archive", archive.toString(),
            "--output", output.toString(),
            "--scratch", scratch.toString(),
        )
        withFailedCommandStdout(scratch, evidenceRoot) {
            assertEquals(
                0,
                invokeInstalledGccCli(
                    arguments,
                    launcherEvidence,
                    timeoutSeconds = 9900,
                    installation = installation,
                    command = "gcc-engine-native-calls",
                ),
                "installed GCC native-call CLI failed; inspect retained launcher evidence",
            )
            val launcherSummary = verifyInstalledCliEvidence(
                launcherEvidence, arguments, installation, expectedExit = 0, command = "gcc-engine-native-calls",
            )

            val resultBytes = readStable(output.resolve("result.json"), MAXIMUM_RESULT_BYTES)
            val result = OracleJson.parseCanonical(resultBytes).jsonObject
            assertEquals("gcc-bundled-cli-native-call-result-v1", result.requiredText("provider"))
            assertEquals(1L, result.getValue("schemaVersion").jsonPrimitive.long)
            assertFalse(result.getValue("complete").jsonPrimitive.boolean)
            assertFalse(result.getValue("scored").jsonPrimitive.boolean)
            assertFalse(result.getValue("releaseEligible").jsonPrimitive.boolean)

            val operationId = result.requiredText("operationId")
            assertTrue(operationId.matches(Regex("[a-f0-9]{64}")))
            val journal = Path.of(result.requiredText("journal"))
            assertEquals(".gcc-bundled-operation-$operationId", journal.fileName.toString())
            val intentBytes = readStable(journal.resolve("intent.json"), MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(intentBytes), result.requiredText("requestSha256"))
            val executionBytes = readStable(journal.resolve("execution.json"), MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(executionBytes), result.requiredText("executionReceiptSha256"))
            val assessmentBytes = readStable(journal.resolve("export-assessment.json"), MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(assessmentBytes), result.requiredText("nativeAssessmentReceiptSha256"))
            val retainedIntent = OracleJson.parseCanonical(intentBytes).jsonObject
            assertEquals(engine, retainedIntent.requiredText("engineId"))
            val runtime = retainedIntent.getValue("bundledRuntime").jsonObject
            val executionRecord = OracleJson.parseCanonical(executionBytes).jsonObject
            assertEquals(OracleArtifacts.sha256(intentBytes), executionRecord.requiredText("intentSha256"))
            val executed = executionRecord.getValue("execution").jsonObject
            assertEquals(0L, executed.getValue("childExitCode").jsonPrimitive.long)
            for (absent in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) {
                assertTrue(executed.getValue(absent).jsonPrimitive.boolean)
            }
            val nativeAssessment = OracleJson.parseCanonical(assessmentBytes).jsonObject
            assertEquals(OracleArtifacts.sha256(executionBytes), nativeAssessment.requiredText("previousSha256"))
            assertEquals(OracleArtifacts.sha256(intentBytes), nativeAssessment.requiredText("intentSha256"))
            assertEquals("bundled-ghidra-java-api-runtime-v8", runtime.requiredText("provider"))

            val modelPath = Path.of(result.requiredText("programModel"))
            assertTrue(modelPath.startsWith(scratch) && modelPath.toRealPath() == modelPath)
            val modelBytes = result.getValue("programModelBytes").jsonPrimitive.long
            val modelSha256 = result.requiredText("programModelSha256")
            val functionCount = result.getValue("functionCount").jsonPrimitive.long
            assertTrue(modelBytes > 0L && modelBytes <= MAXIMUM_MODEL_BYTES)
            assertTrue(functionCount > 0L)

            val bindingPath = Path.of(result.requiredText("nativeBinding"))
            assertEquals(output.resolve("native-call-observation-binding.json"), bindingPath)
            val bindingBytes = readStable(bindingPath, MAXIMUM_BINDING_BYTES)
            assertEquals(OracleArtifacts.sha256(bindingBytes), result.requiredText("nativeBindingSha256"))
            val binding = OracleJson.parseCanonical(bindingBytes).jsonObject
            assertEquals("gcc-bundled-native-call-observation-binding-v1", binding.requiredText("provider"))
            assertEquals(result.requiredText("outputTreeSha256"), binding.requiredText("outputTreeSha256"))
            val boundModel = binding.getValue("programModel").jsonObject
            assertEquals(modelSha256, boundModel.requiredText("sha256"))
            assertEquals(modelBytes, boundModel.getValue("bytes").jsonPrimitive.long)
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(profilePath)), binding.requiredText("compilerEngineProfileSha256"))
            assertEquals(selectedProfile.strippedBinary.sha256, binding.getValue("inputBinary").jsonObject.requiredText("sha256"))
            assertEquals(selectedProfile.strippedBinary.bytes, binding.getValue("inputBinary").jsonObject.getValue("bytes").jsonPrimitive.long)
            assertEquals(selectedAnalysis.exporterSha256, binding.getValue("programModelExporter").jsonObject.requiredText("sha256"))
            assertEquals(selectedAnalysis.ghidraArchive.sha256, binding.getValue("ghidraArchive").jsonObject.requiredText("sha256"))
            val collectorSource = readStable(Path.of("ghidra-bridge/src/main/java/ExportNativeCallsV1.java").toAbsolutePath().normalize(),
                MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(collectorSource), runtime.getValue("nativeCallCollector").jsonObject.requiredText("sourceSha256"))
            val lineage = binding.getValue("receiptLineage").jsonObject
            assertEquals(OracleArtifacts.sha256(intentBytes), lineage.requiredText("intentSha256"))
            assertEquals(OracleArtifacts.sha256(executionBytes), lineage.requiredText("executionReceiptSha256"))
            assertEquals(OracleArtifacts.sha256(assessmentBytes), lineage.requiredText("nativeAssessmentReceiptSha256"))

            val manifestPath = Path.of(result.requiredText("outputTreeManifest"))
            assertEquals(output, manifestPath.parent)
            val manifestBytes = readStable(manifestPath, MAXIMUM_TREE_MANIFEST_BYTES)
            assertEquals(OracleArtifacts.sha256(manifestBytes), result.requiredText("outputTreeManifestSha256"))
            val treeManifest = OracleJson.parseCanonical(manifestBytes, TREE_MANIFEST_LIMITS).jsonObject
            assertEquals(result.requiredText("outputTreeSha256"), treeManifest.requiredText("outputTreeSha256"))

            val observationsPath = Path.of(result.requiredText("nativeObservations"))
            val nativeManifestPath = Path.of(result.requiredText("nativeManifest"))
            assertTrue(observationsPath.startsWith(scratch) && nativeManifestPath.startsWith(scratch))
            val nativeManifestBytes = readStable(nativeManifestPath, MAXIMUM_RECEIPT_BYTES)
            assertEquals(OracleArtifacts.sha256(nativeManifestBytes), result.requiredText("nativeManifestSha256"))

            val captured = privateDirectory(evidenceRoot.resolve("captured"))
            copyStable(modelPath, captured.resolve("program_model.json"), MAXIMUM_MODEL_BYTES, modelBytes, modelSha256)
            val observationsBytes = result.getValue("nativeObservationsBytes").jsonPrimitive.long
            copyStable(observationsPath, captured.resolve("native-calls.json"), NativeCallObservationLimitsV1().maximumCombinedBytes,
                observationsBytes, result.requiredText("nativeObservationsSha256"))
            // Replay the entire frozen raw stream. No site is selected from independent oracle findings.
            fun replayPopulation(): JsonObject {
                var sites = 0L
                var unownedSites = 0L
                var externalEvidenceSites = 0L
                val prototypeFlows = sortedMapOf<String, Long>()
                val kinds = sortedMapOf<String, Long>()
                val summary = NativeCallObservationsV1.validateBoundToSpaces(nativeManifestBytes,
                    expectedBindings = { spaces ->
                        val ram = spaces.single { it.name == "ram" && it.type == 1 && it.sizeBits == 64 &&
                            it.addressableUnitSize == 1 && !it.overlay && !it.signedOffsets }
                        NativeCallBindingsV1(runtime.getValue("nativeCallCollector").jsonObject.requiredText("sourceSha256"),
                            selectedProfile.targetAbi.ghidraCompilerSpec,
                            selectedAnalysis.ghidraArchive.sha256,
                            NativeCallAddressV1(ram.index, selectedProfile.imageBase.toString(16).padStart(16, '0')),
                            selectedProfile.strippedBinary.sha256, selectedProfile.targetAbi.ghidraLanguage, modelBytes,
                            selectedAnalysis.exporterSha256, modelSha256)
                    }, checkpoint = {}, openObservations = { Files.newInputStream(captured.resolve("native-calls.json")) },
                    consume = { record ->
                        if (record is NativeCallSiteRecordV1) {
                            sites++
                            if (record.owner == null) unownedSites++
                            val targets = record.prototypeTargets + record.references.map { it.target } +
                                record.referenceNeighborhoods.flatMap { it.references.map { reference -> reference.target } }
                            if (targets.any { it.external != null }) externalEvidenceSites++
                            val flow = "${record.prototypeFlow.code}:${record.prototypeFlow.name}"
                            prototypeFlows[flow] = (prototypeFlows[flow] ?: 0) + 1
                            kinds[record.observationKind] = (kinds[record.observationKind] ?: 0) + 1
                        }
                    })
                assertEquals(observationsBytes, summary.observationsBytes)
                assertEquals(result.requiredText("nativeObservationsSha256"), summary.observationsSha256)
                assertEquals(binding.getValue("nativeSiteCount").jsonPrimitive.long, sites)
                assertEquals(sites, summary.scanSummary.sites)
                assertEquals(binding.requiredText("coverage"), summary.scanSummary.coverage)
                assertEquals(binding.getValue("nativeFunctionCount").jsonPrimitive.long, summary.scanSummary.functions)
                assertEquals(binding.getValue("nativeThunkCount").jsonPrimitive.long, summary.scanSummary.thunks)
                assertTrue(sites > 0)
                assertFalse(summary.authoritativeOracleEvidence)
                assertFalse(summary.recoveredModelScored)
                return JsonObject(mapOf(
                    "provider" to JsonPrimitive("gcc-native-retained-population-replay-v1"), "schemaVersion" to JsonPrimitive(1),
                    "authority" to JsonPrimitive("byte-replay-only"), "engine" to JsonPrimitive(engine),
                    "rawPopulationSha256" to JsonPrimitive(summary.observationsSha256),
                    "rawPopulationBytes" to JsonPrimitive(summary.observationsBytes),
                    "programModelSha256" to JsonPrimitive(modelSha256), "records" to JsonPrimitive(summary.records),
                    "functions" to JsonPrimitive(summary.scanSummary.functions), "thunks" to JsonPrimitive(summary.scanSummary.thunks),
                    "sites" to JsonPrimitive(sites), "unownedSites" to JsonPrimitive(unownedSites),
                    "externalMetadataSites" to JsonPrimitive(externalEvidenceSites),
                    "prototypeFlows" to JsonObject(prototypeFlows.mapValues { JsonPrimitive(it.value) }),
                    "observationKinds" to JsonObject(kinds.mapValues { JsonPrimitive(it.value) }),
                    "addressSpaces" to JsonPrimitive(summary.addressSpaces.size),
                    "oracleEvidence" to JsonPrimitive(false), "producerRegenerated" to JsonPrimitive(false),
                    "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                ))
            }
            val populationBytes = OracleJson.canonicalBytes(replayPopulation())
            assertTrue(populationBytes.contentEquals(OracleJson.canonicalBytes(replayPopulation())),
                "independent complete native stream replays differ")
            publish(captured.resolve("native-population-replay.json"), populationBytes)
            val diagnosticStdout = captureCommandStdout(executionBytes, scratch, captured)
            publish(captured.resolve("result.json"), resultBytes)
            publish(captured.resolve("native-call-observation-binding.json"), bindingBytes)
            publish(captured.resolve("native-calls-manifest.json"), nativeManifestBytes)
            publish(captured.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME), manifestBytes)
            publish(captured.resolve("intent.json"), intentBytes)
            publish(captured.resolve("execution.json"), executionBytes)
            publish(captured.resolve("export-assessment.json"), assessmentBytes)
            publish(captured.resolve("launcher-summary.json"), OracleJson.canonicalBytes(launcherSummary))
            val wallNanos = result.getValue("operationWallTime").jsonObject.getValue("elapsedNanos").jsonPrimitive.long
            val summary = JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-live-native-call-capture-v1"),
                "engine" to JsonPrimitive(engine),
                "operationId" to JsonPrimitive(operationId),
                "requestSha256" to JsonPrimitive(result.requiredText("requestSha256")),
                "programModelSha256" to JsonPrimitive(modelSha256),
                "programModelBytes" to JsonPrimitive(modelBytes),
                "functionCount" to JsonPrimitive(functionCount),
                "outputTreeSha256" to JsonPrimitive(result.requiredText("outputTreeSha256")),
                "nativeObservationsSha256" to JsonPrimitive(result.requiredText("nativeObservationsSha256")),
                "nativeObservationsBytes" to JsonPrimitive(observationsBytes),
                "nativeBindingSha256" to JsonPrimitive(result.requiredText("nativeBindingSha256")),
                "nativeSiteCount" to binding.getValue("nativeSiteCount"),
                "coverage" to binding.getValue("coverage"),
                "nativePopulationReplaySha256" to JsonPrimitive(OracleArtifacts.sha256(populationBytes)),
                "rawPopulationRetained" to JsonPrimitive(true),
                "operationWallNanos" to JsonPrimitive(wallNanos),
                "referenceWallBudgetSeconds" to JsonPrimitive(1_800),
                "referenceBudgetPassed" to JsonPrimitive(wallNanos <= 1_800_000_000_000L),
                "diagnosticStdoutBytes" to JsonPrimitive(diagnosticStdout.first),
                "diagnosticStdoutSha256" to JsonPrimitive(diagnosticStdout.second),
                "complete" to JsonPrimitive(false),
                "scored" to JsonPrimitive(false),
                "releaseEligible" to JsonPrimitive(false),
                "limitation" to JsonPrimitive("live contained raw native-call collection and deterministic complete byte replay only; independent producer regeneration, oracle identity mapping and call scoring remain open"),
            ))
            publish(evidenceRoot.resolve("qualification.json"), OracleJson.canonicalBytes(summary))
            println("Retained unscored live $engine native-call evidence at $captured ($observationsBytes observation bytes)")
        }
    }

    @Test
    fun `failure diagnostics are retained only when the output tree commits their bytes`(@TempDir root: Path) {
        val modelPath = root.resolve("program_model.json")
        val source = privateDirectory(root.resolve("program_model.json.export"))
        val failures = privateDirectory(source.resolve("failures"))
        val id = "fn_000000000081832b"
        val original = "{\"schemaVersion\":1,\"functionId\":\"$id\",\"status\":\"failed\",\"message\":\"decompilation timed out\"}\n".toByteArray()
        Files.write(failures.resolve("$id.json"), original, CREATE_NEW, WRITE)
        val tree = JsonObject(mapOf("sidecars" to JsonObject(mapOf(
            "failures/$id.json" to JsonObject(mapOf(
                "bytes" to JsonPrimitive(original.size),
                "sha256" to JsonPrimitive(OracleArtifacts.sha256(original)),
            )),
        ))))
        val outputTreeSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(tree, TREE_MANIFEST_LIMITS))
        val treeManifest = JsonObject(mapOf(
            "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
            "tree" to tree,
        ))
        val captured = privateDirectory(root.resolve("captured"))
        assertEquals(1, captureFailureDiagnostics(modelPath, treeManifest, outputTreeSha256, captured))
        assertTrue(Files.readAllBytes(captured.resolve("failure-diagnostics/$id.json")).contentEquals(original))

        val tampered = "tampered".toByteArray()
        Files.write(failures.resolve("$id.json"), tampered)
        val rejected = privateDirectory(root.resolve("rejected"))
        assertFailsWith<IllegalArgumentException> {
            captureFailureDiagnostics(modelPath, treeManifest, outputTreeSha256, rejected)
        }
        assertFalse(Files.exists(rejected.resolve("failure-diagnostics/$id.json")))

        val substitutedSidecars = JsonObject(mapOf("failures/$id.json" to JsonObject(mapOf(
            "bytes" to JsonPrimitive(tampered.size),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(tampered)),
        ))))
        val substitutedTree = JsonObject(tree + ("sidecars" to substitutedSidecars))
        val substitutedManifest = JsonObject(mapOf(
            "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
            "tree" to substitutedTree,
        ))
        val rejectedReplacement = privateDirectory(root.resolve("rejected-manifest-replacement"))
        assertFailsWith<IllegalArgumentException> {
            captureFailureDiagnostics(modelPath, substitutedManifest, outputTreeSha256, rejectedReplacement)
        }
        assertFalse(Files.exists(rejectedReplacement.resolve("failure-diagnostics/$id.json")))
    }

    @Test
    fun `command stdout capture is bounded to its retained control directory and reported size`(@TempDir root: Path) {
        val scratch = privateDirectory(root.resolve("scratch"))
        val control = privateDirectory(scratch.resolve("control"))
        val reports = privateDirectory(control.resolve("reports"))
        val stdout = "program-model export 1/1 fn_000000000081832b status=recovered elapsedNanos=123\n".toByteArray()
        Files.write(reports.resolve("contained-command.stdout"), stdout, CREATE_NEW, WRITE)
        fun execution(directory: Path, size: Int) = OracleJson.canonicalBytes(JsonObject(mapOf(
            "execution" to JsonObject(mapOf(
                "controlDirectory" to JsonPrimitive(directory.toString()),
                "outcome" to JsonObject(mapOf("stdoutBytes" to JsonPrimitive(size))),
            )),
        )))
        val captured = privateDirectory(root.resolve("captured"))
        assertEquals(stdout.size.toLong() to OracleArtifacts.sha256(stdout),
            captureCommandStdout(execution(control, stdout.size), scratch, captured))
        assertTrue(Files.readAllBytes(captured.resolve("diagnostic-stdout.bin")).contentEquals(stdout))

        assertFailsWith<IllegalArgumentException> {
            captureCommandStdout(execution(control, stdout.size + 1), scratch, privateDirectory(root.resolve("wrong-size")))
        }
        assertFailsWith<IllegalArgumentException> {
            captureCommandStdout(execution(root, stdout.size), scratch, privateDirectory(root.resolve("wrong-root")))
        }
    }

    @Test
    fun `failed and timed out exports retain stdout without an execution receipt`(@TempDir root: Path) {
        for ((name, failure) in listOf(
            "nonzero" to AssertionError("installed cc1 full-export CLI failed"),
            "deadline" to IllegalStateException("installed CLI exceeded outer qualification deadline"),
        )) {
            val scratch = privateDirectory(root.resolve("$name-scratch"))
            val stdoutPath = failureStdoutFixture(scratch)
            val stdout = "program-model export 1/2 elapsedNanos=123\n".toByteArray()
            val evidence = privateDirectory(root.resolve("$name-evidence"))
            // Keep a writer open: timeout diagnostics must not require a finalized execution receipt or read lease.
            FileChannel.open(stdoutPath, CREATE_NEW, WRITE).use { writer ->
                writer.write(ByteBuffer.wrap(stdout))
                val observed = assertFailsWith<Throwable> {
                    withFailedCommandStdout(scratch, evidence) { throw failure }
                }
                assertSame(failure, observed)
            }
            assertTrue(Files.readAllBytes(evidence.resolve("failed-command-stdout.bin")).contentEquals(stdout))
            val diagnostic = OracleJson.parseCanonical(
                Files.readAllBytes(evidence.resolve("failed-command-stdout.json")),
            ).jsonObject
            assertEquals(JsonPrimitive("diagnostic-only"), diagnostic["authority"])
            assertEquals(JsonPrimitive(false), diagnostic["complete"])
            assertEquals(JsonPrimitive(false), diagnostic["releaseEligible"])
            assertFalse(Files.exists(evidence.resolve("qualification.json")))
        }
    }

    @Test
    fun `failure diagnostic capture cannot replace the original failure or follow stdout symlinks`(@TempDir root: Path) {
        val scratch = privateDirectory(root.resolve("scratch"))
        val stdoutPath = failureStdoutFixture(scratch)
        val unrelated = root.resolve("unrelated")
        Files.writeString(unrelated, "must not be copied", CREATE_NEW)
        Files.createSymbolicLink(stdoutPath, unrelated)
        val evidence = privateDirectory(root.resolve("evidence"))
        val failure = AssertionError("original CLI failure")
        val observed = assertFailsWith<AssertionError> {
            withFailedCommandStdout(scratch, evidence) { throw failure }
        }
        assertSame(failure, observed)
        assertEquals(1, observed.suppressed.size)
        assertFalse(Files.exists(evidence.resolve("failed-command-stdout.bin")))
    }

    @Test
    fun `failure diagnostic stdout is limited to its bounded prefix`(@TempDir root: Path) {
        val scratch = privateDirectory(root.resolve("scratch"))
        val stdoutPath = failureStdoutFixture(scratch)
        FileChannel.open(stdoutPath, CREATE_NEW, WRITE).use {
            it.position(MAXIMUM_DIAGNOSTIC_STDOUT_BYTES.toLong())
            it.write(ByteBuffer.wrap(byteArrayOf(1)))
        }
        val evidence = privateDirectory(root.resolve("evidence"))
        val failure = AssertionError("original CLI failure")
        assertSame(failure, assertFailsWith<AssertionError> {
            withFailedCommandStdout(scratch, evidence) { throw failure }
        })
        assertEquals(MAXIMUM_DIAGNOSTIC_STDOUT_BYTES.toLong(), Files.size(evidence.resolve("failed-command-stdout.bin")))
        val diagnostic = OracleJson.parseCanonical(
            Files.readAllBytes(evidence.resolve("failed-command-stdout.json")),
        ).jsonObject
        assertEquals(JsonPrimitive(true), diagnostic["captureLimitReached"])
    }

    private fun failureStdoutFixture(scratch: Path): Path {
        val operationId = "a".repeat(64)
        val lease = privateDirectory(scratch.resolve(".decomp-oracle-lease-$operationId"))
        val run = privateDirectory(lease.resolve(".function-observation-run-$operationId"))
        val control = privateDirectory(run.resolve("control-${"b".repeat(64)}"))
        return privateDirectory(control.resolve("reports")).resolve("contained-command.stdout")
    }

    private inline fun <T> withFailedCommandStdout(scratch: Path, evidenceRoot: Path, operation: () -> T): T = try {
        operation()
    } catch (failure: Throwable) {
        try {
            captureFailedCommandStdout(scratch, evidenceRoot)
        } catch (captureFailure: Throwable) {
            failure.addSuppressed(captureFailure)
        }
        throw failure
    }

    /** A bounded diagnostic snapshot only: an outer timeout may leave no execution receipt or stopped writer. */
    private fun captureFailedCommandStdout(scratch: Path, evidenceRoot: Path) {
        require(scratch.isAbsolute && scratch.normalize() == scratch && scratch.toRealPath() == scratch)
        LinuxFilesystemSyscalls.openRoot(scratch).use { root ->
            val leaseName = LinuxFilesystemSyscalls.directoryEntryNames(root, 1).singleOrNull() ?: return
            require(leaseName.matches(Regex("\\.decomp-oracle-lease-[a-f0-9]{64}")))
            val operationId = leaseName.removePrefix(".decomp-oracle-lease-")
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, leaseName).use { lease ->
                LinuxFilesystemSyscalls.openDirectoryAt(lease.fd, ".function-observation-run-$operationId").use { run ->
                    val controlName = LinuxFilesystemSyscalls.directoryEntryNames(run, 16)
                        .filter { it.matches(Regex("control-[a-f0-9]{64}")) }.singleOrNull() ?: return
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
                        LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                            LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, "contained-command.stdout")?.use { stdout ->
                                val bytes = LinuxFilesystemSyscalls.readPrefix(stdout, MAXIMUM_DIAGNOSTIC_STDOUT_BYTES)
                                if (bytes.isEmpty()) return
                                publish(evidenceRoot.resolve("failed-command-stdout.bin"), bytes)
                                publish(evidenceRoot.resolve("failed-command-stdout.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                                    "provider" to JsonPrimitive("gcc-failed-command-stdout-snapshot-v1"),
                                    "authority" to JsonPrimitive("diagnostic-only"),
                                    "source" to JsonPrimitive("$leaseName/.function-observation-run-$operationId/$controlName/reports/contained-command.stdout"),
                                    "capturedBytes" to JsonPrimitive(bytes.size),
                                    "capturedSha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
                                    "captureLimitReached" to JsonPrimitive(bytes.size == MAXIMUM_DIAGNOSTIC_STDOUT_BYTES),
                                    "complete" to JsonPrimitive(false),
                                    "scored" to JsonPrimitive(false),
                                    "releaseEligible" to JsonPrimitive(false),
                                ))))
                            }
                        }
                    }
                }
            }
        }
    }

    private fun captureCommandStdout(executionBytes: ByteArray, scratch: Path, captured: Path): Pair<Long, String> {
        val execution = OracleJson.parseCanonical(executionBytes).jsonObject.getValue("execution").jsonObject
        val control = Path.of(execution.requiredText("controlDirectory"))
        require(control.isAbsolute && control.normalize() == control && control.startsWith(scratch) &&
            control.toRealPath() == control
        ) { "cc1 diagnostic stdout control directory is outside the retained scratch tree" }
        val expectedBytes = execution.getValue("outcome").jsonObject.getValue("stdoutBytes").jsonPrimitive.long
        require(expectedBytes in 1..MAXIMUM_DIAGNOSTIC_STDOUT_BYTES.toLong()) {
            "cc1 diagnostic stdout exceeds its capture bound"
        }
        val stdout = readStable(control.resolve("reports/contained-command.stdout"), MAXIMUM_DIAGNOSTIC_STDOUT_BYTES)
        require(stdout.size.toLong() == expectedBytes) { "cc1 diagnostic stdout differs from the execution byte count" }
        publish(captured.resolve("diagnostic-stdout.bin"), stdout)
        return stdout.size.toLong() to OracleArtifacts.sha256(stdout)
    }

    private fun captureFailureDiagnostics(
        modelPath: Path,
        treeManifest: JsonObject,
        authenticatedOutputTreeSha256: String,
        captured: Path,
    ): Int {
        require(treeManifest.requiredText("outputTreeSha256") == authenticatedOutputTreeSha256) {
            "cc1 output tree manifest differs from the structural binding"
        }
        val tree = treeManifest.getValue("tree").jsonObject
        require(OracleArtifacts.sha256(OracleJson.canonicalBytes(tree, TREE_MANIFEST_LIMITS)) == authenticatedOutputTreeSha256) {
            "cc1 output tree contents differ from the structural binding"
        }
        val sidecars = tree.getValue("sidecars").jsonObject
        val failures = sidecars.filterKeys { it.startsWith("failures/") }.toSortedMap()
        require(failures.size <= MAXIMUM_FAILURE_DIAGNOSTICS) { "cc1 failure diagnostic count exceeds its capture bound" }
        if (failures.isEmpty()) return 0
        val source = modelPath.resolveSibling(modelPath.fileName.toString() + ".export")
        var totalBytes = 0L
        val verified = ArrayList<Pair<String, ByteArray>>(failures.size)
        for ((name, entry) in failures) {
            val id = name.removePrefix("failures/").removeSuffix(".json")
            require(id.matches(Regex("fn_[0-9a-f]{16}")) && name == "failures/$id.json") {
                "cc1 failure diagnostic path is invalid"
            }
            val commitment = entry.jsonObject
            require(commitment.keys == setOf("bytes", "sha256")) { "cc1 failure commitment is invalid" }
            val expectedBytes = commitment.getValue("bytes").jsonPrimitive.long
            val expectedSha256 = commitment.getValue("sha256").jsonPrimitive.content
            require(expectedBytes in 1..MAXIMUM_FAILURE_DIAGNOSTIC_BYTES.toLong() &&
                expectedSha256.matches(Regex("[0-9a-f]{64}"))
            ) { "cc1 failure diagnostic commitment exceeds its bound" }
            totalBytes += expectedBytes
            require(totalBytes <= MAXIMUM_FAILURE_DIAGNOSTIC_TOTAL_BYTES) {
                "cc1 failure diagnostics exceed their aggregate capture bound"
            }
            val bytes = readStable(source.resolve(name), MAXIMUM_FAILURE_DIAGNOSTIC_BYTES)
            require(bytes.size.toLong() == expectedBytes && OracleArtifacts.sha256(bytes) == expectedSha256) {
                "cc1 failure diagnostic differs from the committed output tree"
            }
            verified += id to bytes
        }
        val destination = privateDirectory(captured.resolve("failure-diagnostics"))
        verified.forEach { (id, bytes) -> publish(destination.resolve("$id.json"), bytes) }
        return failures.size
    }

    private fun configured(name: String, vararg alternatives: String): Path {
        val value = (listOf(name) + alternatives).firstNotNullOfOrNull { System.getenv(it)?.takeIf(String::isNotBlank) }
            ?: throw AssertionError("required live GCC full-export input is missing: $name")
        val path = Path.of(value)
        require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path) { "$name must be canonical" }
        return path
    }

    private fun readStable(path: Path, maximumBytes: Int): ByteArray =
        StableControlFile.open(path, maximumBytes.toLong(), "GCC production evidence").use { guard ->
            require(guard.size in 1..maximumBytes.toLong()) { "GCC production evidence exceeds its bound: $path" }
            guard.readExactly(0L, guard.size.toInt(), "GCC production evidence").also {
                guard.verifyUnchanged("after GCC production evidence capture")
            }
        }

    private fun copyStable(source: Path, destination: Path, maximumBytes: Long, expectedBytes: Long, expectedSha256: String) {
        StableControlFile.open(source, maximumBytes, "GCC production model").use { guard ->
            require(guard.size == expectedBytes && guard.size in 1..maximumBytes) { "captured GCC model size differs" }
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(COPY_BUFFER_BYTES)
            FileChannel.open(destination, CREATE_NEW, WRITE).use { output ->
                var offset = 0L
                while (offset < guard.size) {
                    val requested = minOf(buffer.size.toLong(), guard.size - offset).toInt()
                    val count = guard.readAt(offset, buffer, 0, requested)
                    require(count > 0) { "captured GCC model ended early" }
                    digest.update(buffer, 0, count)
                    val chunk = ByteBuffer.wrap(buffer, 0, count)
                    while (chunk.hasRemaining()) output.write(chunk)
                    offset += count
                }
                guard.verifyUnchanged("after cc1 model evidence copy")
                output.force(true)
            }
            val observedSha256 = digest.digest().joinToString("") { "%02x".format(it) }
            require(observedSha256 == expectedSha256) { "copied cc1 model differs from the authenticated result" }
            Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r--------"))
            FileChannel.open(destination.parent, READ).use { it.force(true) }
        }
    }

    private fun publish(path: Path, bytes: ByteArray) {
        require(bytes.isNotEmpty())
        Files.write(path, bytes, CREATE_NEW, WRITE)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        FileChannel.open(path, READ).use { it.force(true) }
        FileChannel.open(path.parent, READ).use { it.force(true) }
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(
        path, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")),
    )

    private fun isEmptyDirectory(path: Path): Boolean = Files.newDirectoryStream(path).use { !it.iterator().hasNext() }

    private fun JsonObject.requiredText(name: String): String = getValue(name).jsonPrimitive.content.also {
        require(getValue(name).jsonPrimitive.isString) { "cc1 evidence $name must be text" }
    }

    private companion object {
        const val DIAGNOSTIC_PREFIX = "DECOMP_GHIDRA_DIAGNOSTICS_V1 "
        val DIAGNOSTIC_LOSS_REASONS = setOf("queue_saturation", "record_limit", "byte_limit", "frame_limit", "output_failure", "drain_timeout", "internal_failure")
        val DIAGNOSTIC_JOURNAL_FILES = listOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json", "attachment.json", "start-authorized.json", "execution.json")
        val DIAGNOSTIC_FRAME_LIMITS = StrictJsonLimits(maximumInputBytes = 8192, maximumCanonicalBytes = 8192,
            maximumDepth = 8, maximumNodes = 512, maximumStringBytes = 256, maximumTotalStringBytes = 4096)
        val DIAGNOSTIC_TELEMETRY_LIMITS = StrictJsonLimits(maximumInputBytes = 5 * 1024 * 1024,
            maximumCanonicalBytes = 5 * 1024 * 1024, maximumDepth = 12, maximumNodes = 400_000,
            maximumStringBytes = 256, maximumTotalStringBytes = 4 * 1024 * 1024)
        const val MAXIMUM_RESULT_BYTES = 256 * 1024
        const val MAXIMUM_RECEIPT_BYTES = 1024 * 1024
        const val MAXIMUM_BINDING_BYTES = 256 * 1024
        const val MAXIMUM_TREE_MANIFEST_BYTES = GccBundledFullExportCliResultV2.MAXIMUM_TREE_MANIFEST_BYTES
        const val MAXIMUM_MODEL_BYTES = 512L * 1024 * 1024
        const val MAXIMUM_FAILURE_DIAGNOSTICS = 1024
        const val MAXIMUM_FAILURE_DIAGNOSTIC_BYTES = 64 * 1024
        const val MAXIMUM_FAILURE_DIAGNOSTIC_TOTAL_BYTES = 8L * 1024 * 1024
        const val MAXIMUM_DIAGNOSTIC_STDOUT_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_DIAGNOSTIC_BOOT_REFERENCE_BYTES = 256 * 1024
        const val COPY_BUFFER_BYTES = 1024 * 1024
        val RESULT_KEYS = setOf(
            "provider", "schemaVersion", "complete", "releaseEligible", "scored", "operationId", "requestSha256",
            "journal", "programModel", "programModelSha256", "programModelBytes", "functionCount", "outputTreeSha256",
            "outputTreeManifest", "outputTreeManifestSha256", "exportAssessmentReceiptSha256", "executionReceiptSha256",
            "structuralBinding", "structuralBindingSha256", "operationWallTime", "scratchDisposition",
        )
        val TREE_MANIFEST_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAXIMUM_TREE_MANIFEST_BYTES,
            maximumCanonicalBytes = MAXIMUM_TREE_MANIFEST_BYTES,
            maximumNodes = 1_000_000,
            maximumStringBytes = 4 * 1024 * 1024,
            maximumTotalStringBytes = 32 * 1024 * 1024,
        )
    }
}
