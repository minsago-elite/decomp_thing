package decompengine.project

import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.acp.AcpNegotiatedAgentEvidence
import decompengine.acp.AcpNegotiatedCapabilitiesEvidence
import decompengine.acp.AcpProcessDiagnostics
import decompengine.acp.AcpProducedOutputEvidence
import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.acpSandboxCanonicalStringDigest
import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.ModuleRevisionAttempt
import decompengine.repair.ModuleRevisionGraph
import decompengine.repair.ModuleRevisionNode
import decompengine.repair.RepairEvidence
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairValidationProof
import decompengine.repair.RevisionRepairMetadata
import decompengine.repair.open
import decompengine.repair.repairCandidateSourceSha256
import decompengine.repair.repairRegressionCorpusSha256
import decompengine.validation.ProcessInput
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/** Synthetic archive admission fixtures only; none of these records qualifies a provider. */
class RepairAcpEvidenceArchiveVerifierTest {
    @Test
    fun `release archive retains rejected failed and refused schema v2 invocations`() {
        withScratch { scratch ->
            for (refused in listOf(false, true)) {
                val fixture = releaseFixture(scratch.resolve(if (refused) "refused" else "failed"), refused)
                val retained = Json.parseToJsonElement(fixture.project.resolve(fixture.rejectedReceiptPath).readText()).jsonObject
                val verified = verifyAcpExecutionReceiptDocument(
                    fixture.project.resolve(fixture.rejectedReceiptPath).readBytes(), KIND, TASK_FIELD, fixture.rejectedId)
                assertFalse(verified.releaseComplete)
                assertEquals(if (refused) "returned-refused" else "failed-protocol", verified.terminalOutcome)
                assertEquals(JsonPrimitive(2), retained.getValue("schemaVersion"))
                val lineage = verifyRelease(fixture)
                assertEquals(1, lineage.acceptedAcpContributions.size)
                assertEquals(fixture.acceptedReceiptPath, lineage.acceptedAcpContributions.single().receiptPath)
                assertEquals("repair", lineage.acceptedAcpContributions.single().workflow)
            }
        }
    }

    @Test
    fun `release archive rejects rehashed provider v6 and mixed transport in rejected node`() {
        withScratch { scratch ->
            for (mixed in listOf(false, true)) {
                val fixture = releaseFixture(scratch.resolve(if (mixed) "mixed" else "v5"), refused = false)
                assertEquals(1, verifyRelease(fixture).acceptedAcpContributions.size)
                val document = failedReceiptDocument(fixture.project, fixture.rejectedId, providerFixture = true)
                assertEquals(6, document.schemaVersion)
                assertFalse(document.releaseComplete)
                // Actual renderer output must first pass the workflow-independent v5 verifier.
                val verified = verifyAcpExecutionReceiptDocument(document.json.toByteArray(), KIND, TASK_FIELD, fixture.rejectedId)
                assertEquals("failed-protocol", verified.terminalOutcome)
                assertFalse(verified.releaseComplete)
                val provider = Json.parseToJsonElement(document.json).jsonObject
                assertTrue("providerTransport" in provider)
                val replacement = if (!mixed) document.json.toByteArray() else {
                    val v2 = Json.parseToJsonElement(fixture.project.resolve(fixture.rejectedReceiptPath).readText()).jsonObject
                    OracleJson.canonicalBytes(JsonObject(v2 + ("providerTransport" to provider.getValue("providerTransport"))), StrictJsonLimits())
                }
                val oldDigest = sha256(fixture.project.resolve(fixture.rejectedReceiptPath).readBytes())
                fixture.project.resolve(fixture.rejectedReceiptPath).writeBytes(replacement)
                val newDigest = sha256(replacement)
                for (path in listOf("reports/repair-revisions/graph.json", "reports/repair_history.json")) {
                    val evidence = fixture.project.resolve(path)
                    val before = evidence.readText()
                    assertTrue(oldDigest in before, "fixture must retain the rejected receipt commitment in $path")
                    evidence.writeText(before.replace(oldDigest, newDigest))
                }
                // Recompute archive maps after the mutation; digest checks cannot explain refusal.
                val failure = assertFailsWith<IllegalArgumentException> { verifyRelease(fixture) }
                assertTrue(failure.message.orEmpty().contains(if (mixed) "provider transport" else "schema-v2"), failure.message)
            }
        }
    }

    private data class Fixture(val project: Path, val rejectedId: String,
        val rejectedReceiptPath: String, val acceptedReceiptPath: String)

    private fun releaseFixture(project: Path, refused: Boolean): Fixture {
        SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
            RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)"),
            RecoveredFunction("fn_beta", "beta_read", 0x2000UL, "int beta_read(void)"))), project)
        val relative = "src/modules/alpha.c"
        val before = project.resolve(relative).readBytes()
        val after = before + "\n/* synthetic archive repair */\n".toByteArray()
        lateinit var rejected: ModuleRevisionNode
        lateinit var accepted: ModuleRevisionNode
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
            graph.beginRun(2, 60_000)
            fun metadata(index: Int) = RevisionRepairMetadata(index, "compile", PROMPT, null,
                corpus.inputs.map(ProcessInput::id), null, corpus.sha256)
            val failed = graph.beginAttempt(listOf(relative), metadata(1))
            graph.persistAndBindAgentInvocation(failed, failedReceiptDocument(project, failed.id, refused))
            rejected = graph.reject(failed, RepairEvidence("agent-failure", "synthetic non-release invocation"))
            val attempt = graph.beginAttempt(listOf(relative), metadata(2))
            graph.persistAndBindAgentInvocation(attempt, completeAcpReceiptDocument(project, attempt, relative, before, after))
            graph.installCandidate(attempt, mapOf(relative to after))
            val proof = archiveValidationProofFixture(graph, attempt, project, corpus.inputs)
            graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
            graph.bindExpectedObservations(sha256(buildString {
                append(proof.originalBinarySha256).append('\n')
                corpus.inputs.forEach { input -> append(input.id.length).append(':').append(input.id).append(":0:")
                    .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n') }
            }.toByteArray()))
            accepted = graph.accept(attempt, RepairEvidence("valid", "synthetic archive observations matched"), proof)
            graph.synchronizeRepairHistory()
        }
        return Fixture(project, rejected.id, requireNotNull(rejected.repairMetadata?.agentInvocation).receiptPath,
            requireNotNull(accepted.repairMetadata?.agentInvocation).receiptPath)
    }

    private fun verifyRelease(fixture: Fixture): ArchivedRepairReleaseLineage {
        val files = Files.walk(fixture.project).use { paths -> paths.filter {
            Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && !it.fileName.toString().endsWith(".lock")
        }.toList() }
        val bytes = files.associate { fixture.project.relativize(it).toString().replace('\\', '/') to it.readBytes() }
        return RepairAcpEvidenceArchiveVerifier.verifyIfPresent(fixture.project,
            bytes.mapValues { sha256(it.value) }, bytes.mapValues { it.value.size.toLong() },
            SourceTreeManifestReader.read(fixture.project, GeneratedCMakeReconstructionProfile.descriptor),
            GeneratedCMakeReconstructionProfile.descriptor)
    }

    private fun failedReceiptDocument(project: Path, attemptId: String, refused: Boolean = false,
        providerFixture: Boolean = false): AcpExecutionReceiptDocument {
        val request = AgentExecutionRequest(PROMPT_OBJECTIVE,
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)), accessPolicy = AgentAccessPolicy(emptyList()))
        val binding = AgentExecutionRequestBinding.capture(request)
        val invocation = if (providerFixture) providerDataFixtureInvocationForTest(request,
            AcpHarnessProvenance("acp", "provider-fixture", AGENT_EXECUTION_CONTRACT_VERSION,
                ACP_STABLE_PROTOCOL_VERSION, ACP_KOTLIN_SDK_VERSION, "1".repeat(64), false))
        else AcpInvocationEvidenceSnapshot(null, AcpExecutionLifecyclePhase.REQUEST_BOUND,
            AcpExecutionCleanupDisposition.NOT_REQUIRED, null, null, null,
            emptyList(), emptyList(), emptyList(), null, AcpExecutionEvidenceCompleteness(true, true, true), null)
        val outcome = if (refused) AgentExecutionOutcome.Returned(AgentExecutionResult(AgentStopReason.REFUSED,
            "synthetic refused invocation", emptyList(), AgentSessionReference("repair-test-acp", "repair-session")))
        else AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.PROTOCOL, "synthetic protocol failure",
            session = if (providerFixture) AgentSessionReference("provider-fixture", "provider-data-session") else null))
        return requireNotNull(AcpExecutionReceiptDocument.captureOrNull(request, sha256(PROMPT.toByteArray()),
            AgentExecutionReceipt(binding, outcome, invocation), BoundedAgentExecutionEventRecorder().receiptSnapshot(),
            KIND, TASK_FIELD, attemptId))
    }

    private fun withScratch(body: (Path) -> Unit) {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize().createDirectories()
        val temp = Files.createTempDirectory(scratch, "repair-release-provider-gate-")
        try { body(temp) } finally {
            Files.walk(temp).use { paths -> paths.sorted(java.util.Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }

    /** Synthetic serialization fixture only; this never qualifies the real validation provider. */
    private fun archiveValidationProofFixture(
        graph: ModuleRevisionGraph,
        attempt: ModuleRevisionAttempt,
        project: Path,
        inputs: List<ProcessInput>,
    ): RepairValidationProof {
        fun element(value: Any?): JsonElement = when (value) {
            null -> JsonNull
            is JsonElement -> value
            is String -> JsonPrimitive(value)
            is Boolean -> JsonPrimitive(value)
            is Number -> JsonPrimitive(value)
            is List<*> -> JsonArray(value.map(::element))
            else -> error("unsupported archive fixture JSON type")
        }
        fun obj(vararg fields: Pair<String, Any?>) = JsonObject(fields.associate { it.first to element(it.second) })
        fun canonical(value: JsonElement) = OracleJson.canonicalBytes(value, StrictJsonLimits())
        val snapshot = graph.snapshot
        val sources = graph.candidateSources(attempt)
        val sourceDigest = repairCandidateSourceSha256(sources)
        val referenceDigest = sha256("synthetic archive reference".toByteArray())
        val rebuiltDigest = sha256("synthetic archive rebuilt".toByteArray())
        val referenceManifest = sha256("synthetic reference runtime manifest".toByteArray())
        val rebuiltManifest = sha256("synthetic rebuilt runtime manifest".toByteArray())
        val tools = JsonObject(GeneratedCRepairRuntimeConfiguration.TOOL_NAMES.mapValues { (role, name) ->
            obj("source" to "/fixture/tools/$name", "destination" to "/decomp-generated-c-tools/$name",
                "sha256" to sha256("synthetic tool $role".toByteArray()))
        })
        val runtime = obj("runtime" to obj("schemaVersion" to 1, "profileId" to GeneratedCRepairIndexProfile.profileId(),
            "sandboxConfigurationFile" to "/fixture/sandbox.json", "tools" to tools,
            "buildRuntimeMounts" to emptyList<JsonElement>(), "programRuntimeMounts" to emptyList<JsonElement>(),
            "sourceTmpfs" to "/fixture/source", "outputTmpfs" to "/fixture/output"),
            "sandboxConfigurationSha256" to sha256("synthetic sandbox configuration".toByteArray()))
        val runtimeDigest = sha256(canonical(runtime))
        fun quota(mount: Int, target: String) = obj("provider" to "dedicated-tmpfs-size+nr_inodes",
            "mountId" to mount, "maximumBytes" to 1_048_576, "maximumEntries" to 512,
            "mountPathSha256" to sha256(target.toByteArray()))
        val outputQuota = quota(102, "/fixture/output")
        val files = JsonArray(sources.toSortedMap().map { (path, bytes) -> obj("path" to path,
            "role" to if (path == "Makefile") "build-file" else "source", "mode" to 292,
            "bytes" to bytes.size, "sha256" to sha256(bytes)) })
        fun executable(digest: String, manifest: String, role: String) = obj("sha256" to digest,
            "runtimeManifestSha256" to manifest, "bytes" to 64, "mode" to 320, "role" to role)
        fun scope(role: String, input: ProcessInput?, manifest: String?): JsonObject {
            val command = listOf("/fixture/$role") + input?.args.orEmpty()
            val fields = linkedMapOf("provider" to "bubblewrap+systemd-cgroup-v2",
                "launch[0].purpose" to "CANDIDATE_VALIDATION", "launch[0].mergeError" to "false",
                "launch[0].command" to acpSandboxCanonicalStringDigest(command),
                "launch[0].writableMountClosure" to sha256("synthetic mount closure".toByteArray()),
                "authority[0].mode" to "READ_WRITE")
            listOf("cgroup.pids", "cgroup.memory", "cgroup.cpu", "network", "nestedUserns", "newSession",
                "dieWithParent", "launch[0].gate.positiveByte").forEach { fields[it] = "true" }
            mapOf("provider" to "provider", "mount" to "mountId", "bytes" to "maximumBytes",
                "entries" to "maximumEntries", "path" to "mountPathSha256").forEach { (field, key) ->
                fields["authority[0].quota.$field"] = (outputQuota.getValue(key) as JsonPrimitive).content
            }
            manifest?.let {
                fields["launch[0].executable.manifest"] = it
                fields["launch[0].executable.configuredManifest"] = it
            }
            val sandboxDigest = sha256(buildString {
                fields.forEach { (name, value) -> append(name.length).append(':').append(name)
                    .append(value.length).append(':').append(value).append(';') }
            }.toByteArray())
            return obj("role" to role, "inputId" to input?.id,
                "output" to obj("command" to command, "exitCode" to 0, "stdoutBase64" to "",
                    "stderrBase64" to "",
                    "networkIsolated" to true), "sandboxSha256" to sandboxDigest,
                "sandboxFields" to fields.map { listOf(it.key, it.value) }, "writableQuota" to outputQuota,
                "cleanupVerified" to true)
        }
        val receipt = obj("schemaVersion" to 2, "provider" to "generated-c-linux-bubblewrap-cgroup-v1",
            "profileId" to GeneratedCRepairIndexProfile.profileId(), "profileSha256" to snapshot.profileSha256,
            "indexSha256" to snapshot.indexSha256, "sourceRevisionSha256" to sourceDigest,
            "regressionCorpusSha256" to repairRegressionCorpusSha256(inputs), "runtimeSha256" to runtimeDigest,
            "runtimeConfiguration" to runtime,
            "behaviorBudgetEvidence" to GeneratedCValidationBudgetPolicy.DEFAULT.admit(RepairResourceBudget()),
            "sourceSnapshot" to obj("manifestSha256" to sha256(canonical(files)), "files" to files,
                "quota" to quota(101, "/fixture/source")),
            "buildOutputLink" to obj("path" to "build", "role" to "application-owned-output-link",
                "target" to "/fixture/output/staging", "quota" to outputQuota),
            "originalExecutable" to executable(referenceDigest, referenceManifest, "reference"),
            "rebuiltExecutable" to executable(rebuiltDigest, rebuiltManifest, "candidate"),
            "inputs" to inputs.map { obj("id" to it.id, "args" to it.args,
                "stdinBase64" to java.util.Base64.getEncoder().encodeToString(it.stdin)) },
            "scopes" to listOf(scope("build", null, null)) + inputs.flatMap {
                listOf(scope("reference", it, referenceManifest), scope("candidate", it, rebuiltManifest)) },
            "outcome" to "behavior-checked", "caseCount" to inputs.size, "matches" to true,
            "cleanupVerified" to true, "assurance" to "strict-contained")
        val bytes = canonical(receipt)
        project.resolve("reports/archive-fixture.validation.json").writeBytes(bytes)
        return RepairValidationProof(sourceDigest, snapshot.profileSha256, snapshot.indexSha256,
            repairRegressionCorpusSha256(inputs), referenceDigest, rebuiltDigest, runtimeDigest, sha256(bytes), true,
            RepairValidationAssurance.STRICT_CONTAINED)
    }

    private fun completeAcpReceiptDocument(
        project: Path,
        attempt: ModuleRevisionAttempt,
        relativePath: String,
        before: ByteArray,
        after: ByteArray,
    ): AcpExecutionReceiptDocument {
        val workspacePath = AgentWorkspacePath("project", relativePath)
        val request = AgentExecutionRequest(
            objective = "repair one module",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(
                listOf(AgentPathRule(workspacePath, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE))),
            ),
        )
        val change = AgentFileChange(
            workspacePath,
            AgentFileChangeKind.MODIFIED,
            sha256(before),
            sha256(after),
            after.size.toLong(),
        )
        val implementationId = "repair-test-acp"
        val factory = AcpHarnessProvenance(
            harness = "acp",
            implementationId = implementationId,
            agentExecutionContractVersion = 1,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = "a".repeat(64),
            deprecated = false,
        )
        val negotiated = AcpNegotiatedAgentEvidence(
            ACP_STABLE_PROTOCOL_VERSION,
            "repair test agent",
            "1",
            null,
            AcpNegotiatedCapabilitiesEvidence(false, false, false, false, false, false, false),
        )
        val diagnostics = AcpProcessDiagnostics(
            pid = 123,
            exitCode = 0,
            stderr = "",
            stderrTruncated = false,
            producedOutputBytes = 0,
            producedOutputLimitBytes = 1_024,
            outputLimitExceeded = false,
            forcedTermination = false,
            rootTerminationRequested = false,
            remainingProcessIds = emptyList(),
            containment = "linux-bubblewrap",
            networkIsolated = true,
            sandboxCleanupVerified = true,
        )
        val sandbox = AcpSandboxEvidence(
            provider = "sandbox-evidence-v1",
            providerVersion = "1",
            providerExecutableSha256 = "b".repeat(64),
            providerExecutableMode = 365,
            resourceLimiterSha256 = "c".repeat(64),
            scopeSupervisorSha256 = "d".repeat(64),
            scopeInspectorSha256 = "e".repeat(64),
            environmentFdOpenerSha256 = "f".repeat(64),
            securityExecutables = emptyList(),
            outerAgentLimits = AcpSandboxResourceLimits(),
            runtimeClosureLimits = AcpRuntimeClosureLimits(),
            cgroupV2PidsLimited = true,
            cgroupV2MemoryLimited = true,
            cgroupV2CpuLimited = true,
            networkIsolated = true,
            outerAgentContained = true,
            nestedUserNamespacesDisabled = true,
            newSession = true,
            dieWithParent = true,
            policySha256 = "1".repeat(64),
            terminalLimits = null,
            launches = emptyList(),
            authorities = emptyList(),
            terminalAudit = emptyList(),
            outerProcessOutput = AcpProducedOutputEvidence(1_024, 0, false),
        )
        val complete = AcpExecutionEvidenceSnapshot(
            factory,
            negotiated,
            "2".repeat(64),
            diagnostics,
            emptyList(),
            emptyList(),
            emptyList(),
            sandbox,
        )
        val result = AgentExecutionResult(
            AgentStopReason.COMPLETED,
            "peer completion summary",
            listOf(change),
            AgentSessionReference(implementationId, "repair-session"),
        )
        val recorder = BoundedAgentExecutionEventRecorder().also {
            it.record(AgentFileChangeEvent(0, change))
        }
        val receipt = AgentExecutionReceipt(
            AgentExecutionRequestBinding.capture(request),
            AgentExecutionOutcome.Returned(result),
            AcpInvocationEvidenceSnapshot(
                factory,
                AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT,
                AcpExecutionCleanupDisposition.VERIFIED,
                negotiated,
                complete.wirePromptSha256,
                diagnostics,
                emptyList(),
                emptyList(),
                emptyList(),
                sandbox,
                AcpExecutionEvidenceCompleteness(true, true, true),
                complete,
            ),
        )
        return requireNotNull(
            AcpExecutionReceiptDocument.captureOrNull(
                request,
                sha256("bounded failure".toByteArray()),
                receipt,
                recorder.receiptSnapshot(),
                "decomp-engine.trace-repair-acp-execution-receipt",
                "attemptId",
                attempt.id,
            ),
        )
    }
    companion object {
        private const val KIND = "decomp-engine.trace-repair-acp-execution-receipt"
        private const val TASK_FIELD = "attemptId"
        private const val PROMPT = "bounded failure"
        private const val PROMPT_OBJECTIVE = "repair one module"
    }
}
