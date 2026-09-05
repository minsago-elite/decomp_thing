package decompengine.project

import com.agentclientprotocol.model.PermissionOptionKind
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpCgroupControllerEvidence
import decompengine.acp.AcpFilesystemAuditOutcome
import decompengine.acp.AcpFilesystemAuditReason
import decompengine.acp.AcpFilesystemAuditRecord
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.acp.AcpNegotiatedAgentEvidence
import decompengine.acp.AcpNegotiatedCapabilitiesEvidence
import decompengine.acp.AcpPermissionAuditOutcome
import decompengine.acp.AcpPermissionAuditReason
import decompengine.acp.AcpPermissionAuditRecord
import decompengine.acp.AcpProcessDiagnostics
import decompengine.acp.AcpProducedOutputEvidence
import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.AcpSandboxEnvironmentEvidence
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxLaunchEvidence
import decompengine.acp.AcpSandboxLaunchPurpose
import decompengine.acp.AcpSandboxMountEvidence
import decompengine.acp.AcpSandboxRlimitEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.acp.AcpSandboxStartGateEvidence
import decompengine.acp.AcpTerminalAuditOutcome
import decompengine.acp.AcpTerminalAuditReason
import decompengine.acp.AcpTerminalAuditRecord
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentPermissionDecision
import decompengine.agent.AgentPermissionEvent
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentToolEvent
import decompengine.agent.AgentToolStatus
import decompengine.agent.AgentUsage
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import decompengine.oracle.behavior.LlvmBehaviorCandidateAcpLineageIndexV2Publisher
import decompengine.oracle.behavior.LlvmBehaviorCandidateAcpLineageIndexV2Verifier
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import java.time.Duration
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createTempDirectory
import kotlin.io.path.createDirectories
import kotlin.io.path.deleteIfExists
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class AgentExecutionEvidenceTest {
    @Test
    fun `schema v1 launch JSON retains every field bound by sandbox evidence`() {
        val temp = createTempDirectory("acp-v1-launch-evidence-")
        val root = AgentWorkspaceRoot("root", temp)
        val request = AgentExecutionRequest(
            objective = "retain complete launch evidence",
            workspaceRoots = listOf(root),
            accessPolicy = AgentAccessPolicy(emptyList()),
        )
        val resources = AcpSandboxResourceLimits()
        val executable = AcpSandboxMountEvidence(
            sourcePathSha256 = "1".repeat(64),
            destinationPathSha256 = "2".repeat(64),
            manifestSha256 = "3".repeat(64),
            device = 11,
            inode = 12,
            mode = 0x8180,
            directory = false,
            configuredManifestSha256 = "4".repeat(64),
        )
        val runtime = AcpSandboxMountEvidence(
            sourcePathSha256 = "5".repeat(64),
            destinationPathSha256 = "6".repeat(64),
            manifestSha256 = "7".repeat(64),
            device = 21,
            inode = 22,
            mode = 0x4160,
            directory = true,
            configuredManifestSha256 = "8".repeat(64),
        )
        val launch = AcpSandboxLaunchEvidence(
            purpose = AcpSandboxLaunchPurpose.TERMINAL,
            resourceLimits = resources,
            controllers = AcpCgroupControllerEvidence(
                pidsMax = resources.maximumProcesses.toLong(),
                memoryMaxBytes = resources.maximumAddressSpaceBytes,
                memorySwapMaxBytes = 0,
                cpuQuotaMicros = 100_000,
                cpuPeriodMicros = 100_000,
                memoryOomGroup = true,
                runtimeMaxMicros = 10_000_000,
                timeoutStopMicros = 3_000_000,
            ),
            commandSha256 = "9".repeat(64),
            startGate = AcpSandboxStartGateEvidence(
                descriptor = 0,
                waiterExecutableSha256 = "a".repeat(64),
                helperProtocolSha256 = "b".repeat(64),
                positiveByteRequired = true,
            ),
            environment = AcpSandboxEnvironmentEvidence(
                sandboxPathSha256 = "c".repeat(64),
                bindingNamesSha256 = "d".repeat(64),
                bindingCount = 2,
                encodedBytes = 32,
                device = 31,
                inode = 32,
                mountId = 33,
                mode = 0x8180,
                linkCount = 0,
                contentSha256 = "e".repeat(64),
            ),
            effectiveRlimits = AcpSandboxRlimitEvidence(
                processesSoft = resources.maximumProcesses.toLong(),
                processesHard = resources.maximumProcesses.toLong(),
                openFilesSoft = resources.maximumOpenFiles.toLong(),
                openFilesHard = resources.maximumOpenFiles.toLong(),
                fileBytesSoft = resources.maximumFileBytes,
                fileBytesHard = resources.maximumFileBytes,
                coreBytesSoft = 0,
                coreBytesHard = 0,
                addressSpaceSoft = resources.maximumAddressSpaceBytes,
                addressSpaceHard = resources.maximumAddressSpaceBytes,
                cpuSecondsSoft = resources.maximumCpuSeconds.toLong(),
                cpuSecondsHard = resources.maximumCpuSeconds.toLong(),
            ),
            executableMount = executable,
            runtimeMounts = listOf(runtime),
            workingDirectorySha256 = "f".repeat(64),
            mergeError = true,
            stagingRootsSha256 = "0".repeat(64),
            stagingRootCount = 2,
            emptyDirectoriesSha256 = "1".repeat(64),
            emptyDirectoryCount = 3,
            stdinDisposition = "inherited",
        )
        val sandbox = AcpSandboxEvidence(
            provider = "sandbox-evidence-v1",
            providerVersion = "1",
            providerExecutableSha256 = "2".repeat(64),
            providerExecutableMode = 365,
            resourceLimiterSha256 = "3".repeat(64),
            scopeSupervisorSha256 = "4".repeat(64),
            scopeInspectorSha256 = "5".repeat(64),
            environmentFdOpenerSha256 = "6".repeat(64),
            securityExecutables = emptyList(),
            outerAgentLimits = resources,
            runtimeClosureLimits = AcpRuntimeClosureLimits(),
            cgroupV2PidsLimited = true,
            cgroupV2MemoryLimited = true,
            cgroupV2CpuLimited = true,
            networkIsolated = true,
            outerAgentContained = true,
            nestedUserNamespacesDisabled = true,
            newSession = true,
            dieWithParent = true,
            policySha256 = "7".repeat(64),
            terminalLimits = null,
            launches = listOf(launch),
            authorities = emptyList(),
            terminalAudit = emptyList(),
        )
        val provenance = AcpHarnessProvenance(
            harness = "acp",
            implementationId = IMPLEMENTATION_ID,
            agentExecutionContractVersion = 1,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = "8".repeat(64),
            deprecated = false,
        )
        val acp = AcpExecutionEvidenceSnapshot(
            factoryProvenance = provenance,
            negotiatedAgent = AcpNegotiatedAgentEvidence(
                ACP_STABLE_PROTOCOL_VERSION,
                "test-agent",
                "1",
                null,
                AcpNegotiatedCapabilitiesEvidence(false, false, false, false, false, false, false),
            ),
            wirePromptSha256 = "9".repeat(64),
            diagnostics = AcpProcessDiagnostics(
                pid = 123,
                exitCode = 0,
                stderr = "",
                stderrTruncated = false,
                producedOutputBytes = 0,
                producedOutputLimitBytes = 1024,
                outputLimitExceeded = false,
                forcedTermination = false,
                rootTerminationRequested = false,
                remainingProcessIds = emptyList(),
                containment = "linux-bubblewrap",
                networkIsolated = true,
                sandboxCleanupVerified = true,
            ),
            filesystemAudit = emptyList(),
            terminalAudit = emptyList(),
            permissionAudit = emptyList(),
            sandboxEvidence = sandbox,
        )
        val result = AgentExecutionResult(
            stopReason = AgentStopReason.NO_CHANGES,
            session = AgentSessionReference(IMPLEMENTATION_ID, "session"),
        )
        val json = BoundedAcpExecutionArtifact.capture(
            request = request,
            promptSha256 = "a".repeat(64),
            result = result,
            events = emptyList(),
            acp = acp,
        ).toValidatedJson(
            AcpExecutionOutcomeBinding(
                evidenceKind = "test.acp-evidence",
                taskIdentityField = "taskId",
                taskId = "task",
                accepted = true,
                artifactDigestField = "artifactSha256",
                artifactSha256 = "b".repeat(64),
            ),
        )

        val rootJson = Json.parseToJsonElement(json).jsonObject
        val launchJson = rootJson.getValue("sandbox").jsonObject
            .getValue("launches").jsonArray.single().jsonObject
        assertEquals(sandbox.evidenceSha256, rootJson.getValue("sandbox").jsonObject
            .getValue("evidenceSha256").jsonPrimitive.content)
        assertEquals("e".repeat(64), launchJson.getValue("environment").jsonObject
            .getValue("contentSha256").jsonPrimitive.content)
        assertEquals("3".repeat(64), launchJson.getValue("executableMount").jsonObject
            .getValue("manifestSha256").jsonPrimitive.content)
        assertEquals("4".repeat(64), launchJson.getValue("executableMount").jsonObject
            .getValue("configuredManifestSha256").jsonPrimitive.content)
        assertEquals("7".repeat(64), launchJson.getValue("runtimeMounts").jsonArray.single().jsonObject
            .getValue("manifestSha256").jsonPrimitive.content)
        assertEquals("8".repeat(64), launchJson.getValue("runtimeMounts").jsonArray.single().jsonObject
            .getValue("configuredManifestSha256").jsonPrimitive.content)
        assertEquals("f".repeat(64), launchJson.getValue("workingDirectorySha256").jsonPrimitive.content)
        assertTrue(launchJson.getValue("mergeError").jsonPrimitive.boolean)
        assertEquals("0".repeat(64), launchJson.getValue("stagingRootsSha256").jsonPrimitive.content)
        assertEquals(2, launchJson.getValue("stagingRootCount").jsonPrimitive.int)
        assertEquals("1".repeat(64), launchJson.getValue("emptyDirectoriesSha256").jsonPrimitive.content)
        assertEquals(3, launchJson.getValue("emptyDirectoryCount").jsonPrimitive.int)
        assertEquals("inherited", launchJson.getValue("stdinDisposition").jsonPrimitive.content)
    }

    @Test
    fun `tool detail commitments cannot move delimiters between keys and values`() {
        assertNotEquals(
            digestCanonicalEvidenceMap(mapOf("a" to "b\u0000c")),
            digestCanonicalEvidenceMap(mapOf("a\u0000b" to "c")),
        )
    }

    @Test
    fun `event recorder retains an explicit bounded incomplete prefix`() {
        val recorder = BoundedAgentExecutionEventRecorder(maximumEvents = 1)
        recorder.record(AgentMessageEvent(0, "first", AgentMessageRole.ASSISTANT, "one"))

        assertFailsWith<IllegalArgumentException> {
            recorder.record(AgentMessageEvent(1, "second", AgentMessageRole.ASSISTANT, "two"))
        }

        val snapshot = recorder.receiptSnapshot()
        assertFalse(snapshot.complete)
        assertEquals(2, snapshot.observedEventCount)
        assertEquals(1, snapshot.events.size)
        assertEquals("event-count-limit", snapshot.truncationReason)
    }

    @Test
    fun `ACP reconstruction archives bounded execution and validation evidence`() {
        val temp = createTempDirectory("acp-execution-evidence-")
        val project = temp.resolve("project")
        val sessionId = "session-secret-must-not-be-archived"
        val message = "peer assistant text must be represented by digest"
        val toolTitle = "peer tool title must be represented by digest"
        val harness = EvidenceHarness(sessionId, message, toolTitle)
        val factoryProvenance = harness.factoryProvenance

        val manifest = SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = "a".repeat(64),
                functions = listOf(
                    RecoveredFunction(
                        "fn_0000000000401000",
                        "parse_input",
                        0x401000UL,
                        "int parse_input(void)",
                    ),
                ),
                globals = emptyList(),
                types = emptyList(),
            ),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = factoryProvenance.stableDescriptor,
            ),
        )

        val evidencePath = "reports/agent-executions/parse.json"
        val evidenceFile = project.resolve(evidencePath)
        assertTrue(evidenceFile.exists())
        val text = evidenceFile.readText()
        val evidence = Json.parseToJsonElement(text).jsonObject
        assertEquals(2, evidence.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("acp", evidence.getValue("factoryProvenance").jsonObject.getValue("harness").jsonPrimitive.content)
        assertEquals(ACP_STABLE_PROTOCOL_VERSION, evidence.getValue("protocol").jsonObject.getValue("version").jsonPrimitive.int)
        val negotiatedImplementation = evidence.getValue("agent").jsonObject
            .getValue("negotiatedImplementation").jsonObject
        assertEquals(
            digest("fake-acp-agent"),
            negotiatedImplementation.getValue("name").jsonObject.getValue("sha256").jsonPrimitive.content,
        )
        assertEquals(
            14,
            negotiatedImplementation.getValue("name").jsonObject.getValue("encodedBytes").jsonPrimitive.int,
        )
        assertTrue(
            evidence.getValue("agent").jsonObject
                .getValue("negotiatedCapabilities").jsonObject.getValue("promptEmbeddedContext").jsonPrimitive.boolean,
        )
        assertEquals(4, evidence.getValue("events").jsonObject.getValue("records").jsonArray.size)
        val turn = evidence.getValue("request").jsonObject
        assertEquals(digest("exact wire prompt bytes"), turn.getValue("wirePromptSha256").jsonPrimitive.content)
        assertEquals(harness.requestBinding.requestSha256, turn.getValue("requestSha256").jsonPrimitive.content)
        assertEquals(
            harness.requestBinding.accessPolicySha256,
            turn.getValue("accessPolicySha256").jsonPrimitive.content,
        )
        listOf(
            "requestSha256",
            "wirePromptSha256",
            "accessPolicySha256",
        ).forEach { field ->
            assertTrue(turn.getValue(field).jsonPrimitive.content.matches(Regex("[0-9a-f]{64}")), field)
        }
        val bounds = evidence.getValue("request").jsonObject
        assertEquals("null", bounds.getValue("maximumInputTokens").toString())
        assertEquals("null", bounds.getValue("maximumOutputTokens").toString())
        assertEquals(
            1,
            evidence.getValue("outcome").jsonObject.getValue("result").jsonObject
                .getValue("changes").jsonObject.getValue("records").jsonArray.size,
        )
        assertEquals(
            1,
            evidence.getValue("policyAudits").jsonObject.getValue("filesystem").jsonObject
                .getValue("records").jsonArray.size,
        )
        assertEquals(
            1,
            evidence.getValue("policyAudits").jsonObject.getValue("terminal").jsonObject
                .getValue("records").jsonArray.size,
        )
        assertEquals(
            1,
            evidence.getValue("policyAudits").jsonObject.getValue("permission").jsonObject
                .getValue("records").jsonArray.size,
        )
        assertEquals(
            digest("sandbox-evidence-v1"),
            evidence.getValue("sandbox").jsonObject.getValue("provider").jsonObject
                .getValue("sha256").jsonPrimitive.content,
        )
        assertTrue(evidence.getValue("lifecycle").jsonObject.getValue("releaseComplete").jsonPrimitive.boolean)
        assertFalse(text.contains(sessionId))
        assertFalse(text.contains(message))
        assertFalse(text.contains(toolTitle))
        assertFalse(text.contains("stderr peer output"))

        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("\"schemaVersion\": 5"))
        assertTrue(checkpoint.contains("\"executionEvidencePath\": \"$evidencePath\""))
        assertTrue(checkpoint.contains(sha256(evidenceFile.readBytes())))
        val manifestEntry = manifest.files.single { it.path == evidencePath }
        assertEquals(sha256(evidenceFile.readBytes()), manifestEntry.sha256)
        assertEquals("acp-execution-receipt:v2", manifestEntry.generator)

        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val bundle = ArchivalPackager.create(project, temp.resolve("source-tree.zip"))
        assertTrue(evidencePath in bundle.payloadFiles)
        val extracted = temp.resolve("extracted")
        val candidateLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(
            bundle.archivePath,
            extracted,
        )
        assertEquals(text, extracted.resolve(evidencePath).readText())
        val contribution = candidateLineage.source.acceptedAcpContributions.single()
        assertEquals("reconstruction", contribution.workflow)
        assertEquals("parse", contribution.taskId)
        assertEquals(evidencePath, contribution.receiptPath)
        assertEquals(sha256(evidenceFile.readBytes()), contribution.receiptSha256)
        assertEquals(harness.requestBinding.requestSha256, contribution.requestSha256)
        assertEquals(digest(sessionId), contribution.session.sessionId.sha256)
        assertEquals("src/modules/parse.c", contribution.changes.single().path)
        assertEquals(
            captureBuildSourceRevision(extracted).sha256,
            candidateLineage.source.sourceRevision.sha256,
        )
        assertEquals(null, candidateLineage.source.repairGraphHeadId)
        assertFailsWith<UnsupportedOperationException> {
            (candidateLineage.source.acceptedAcpContributions as MutableList).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (contribution.changes as MutableList).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (contribution.session.negotiatedCapabilities as MutableMap).clear()
        }
        assertFailsWith<UnsupportedOperationException> {
            (candidateLineage.source.sourceRevision.inputs as MutableList).clear()
        }

        val lineageParent = temp.resolve("lineage-index").createDirectories()
        Files.setPosixFilePermissions(lineageParent, OWNER_DIRECTORY_PERMISSIONS)
        val lineageIndex = lineageParent.resolve("candidate-acp-lineage-index-v2.json")
        val publishedLineage = LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
            bundle.archivePath,
            lineageIndex,
        )
        assertTrue(publishedLineage.candidateLineageBound)
        assertFalse(publishedLineage.hostedBuildBound)
        assertFalse(publishedLineage.admittedArtifactBound)
        assertFalse(publishedLineage.prepared)
        assertFalse(publishedLineage.candidateStarted)
        assertFalse(publishedLineage.scoringAuthority)
        assertFalse(publishedLineage.certificationAuthority)
        assertFalse(publishedLineage.releaseEligible)
        assertEquals(1, publishedLineage.acceptedAcpCount)
        assertEquals(1, publishedLineage.reconstructionCount)
        assertEquals(0, publishedLineage.repairCount)
        assertEquals(bundle.archiveSha256, publishedLineage.archiveSha256)
        assertEquals(candidateLineage.source.sourceRevision.sha256, publishedLineage.sourceRevisionSha256)

        val lineageText = lineageIndex.readText()
        val lineageDocument = Json.parseToJsonElement(lineageText).jsonObject
        assertEquals(
            "first-class-candidate-producer-operator",
            lineageDocument.getValue("acpBoundary").jsonObject.getValue("role").jsonPrimitive.content,
        )
        val boundary = lineageDocument.getValue("acpBoundary").jsonObject
        assertEquals(
            "authenticated-session-change-provenance",
            boundary.getValue("candidateContribution").jsonPrimitive.content,
        )
        listOf(
            "oracleAuthority",
            "referenceAuthoringAuthority",
            "policyAuthoringAuthority",
            "validationAuthority",
            "observationAuthoringAuthority",
            "startAuthority",
            "containmentAuthority",
            "terminalAbsenceAuthority",
            "scoringAuthority",
            "certificationAuthority",
            "releaseAuthority",
        ).forEach { field -> assertFalse(boundary.getValue(field).jsonPrimitive.boolean, field) }
        val claims = lineageDocument.getValue("claims").jsonObject
        assertTrue(claims.getValue("candidateLineageBound").jsonPrimitive.boolean)
        claims.filterKeys { it != "candidateLineageBound" }.forEach { (field, value) ->
            assertFalse(value.jsonPrimitive.boolean, field)
        }
        assertFalse(lineageText.lowercase().contains("python"))
        assertFalse(lineageText.contains("behavior-preexec-v1"))
        assertFalse(lineageText.contains("build_contract.json"))

        val retry = LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(bundle.archivePath, lineageIndex)
        assertEquals(publishedLineage.indexSha256, retry.indexSha256)
        val secondParent = temp.resolve("lineage-index-second").createDirectories()
        Files.setPosixFilePermissions(secondParent, OWNER_DIRECTORY_PERMISSIONS)
        val secondIndex = secondParent.resolve("candidate-acp-lineage-index-v2.json")
        LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(bundle.archivePath, secondIndex)
        assertContentEquals(lineageIndex.readBytes(), secondIndex.readBytes())

        val otherHarness = EvidenceHarness(
            "other-session-secret",
            "other peer message",
            "other tool title",
        )
        val otherProject = temp.resolve("other-project")
        SourceTreeGenerator.generate(
            evidenceModel(),
            otherProject,
            reconstructor = BoundedLlmModuleReconstructor(
                otherHarness,
                harnessProvenanceDescriptor = otherHarness.factoryProvenance.stableDescriptor,
            ),
        )
        MakeProjectBuilder.build(otherProject)
        val otherBundle = ArchivalPackager.create(otherProject, temp.resolve("other-source-tree.zip"))
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(otherBundle.archivePath, lineageIndex)
        }
        val originalLineageBytes = lineageIndex.readBytes()
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(otherBundle.archivePath, lineageIndex)
        }
        assertContentEquals(originalLineageBytes, lineageIndex.readBytes())

        val recoveryParent = temp.resolve("lineage-index-recovery").createDirectories()
        Files.setPosixFilePermissions(recoveryParent, OWNER_DIRECTORY_PERMISSIONS)
        val recoveredIndex = recoveryParent.resolve("candidate-acp-lineage-index-v2.json")
        val recoveryTemporary = recoveryParent.resolve(
            DescriptorBoundAtomicStateFile.temporaryName(recoveredIndex.fileName.toString()),
        )
        Files.write(recoveryTemporary, lineageIndex.readBytes())
        Files.setPosixFilePermissions(recoveryTemporary, OWNER_READ_ONLY_PERMISSIONS)
        val recovered = LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
            bundle.archivePath,
            recoveredIndex,
        )
        assertEquals(publishedLineage.indexSha256, recovered.indexSha256)
        assertFalse(recoveryTemporary.exists())

        val malformedParent = temp.resolve("lineage-index-malformed").createDirectories()
        Files.setPosixFilePermissions(malformedParent, OWNER_DIRECTORY_PERMISSIONS)
        val malformedIndex = malformedParent.resolve("candidate-acp-lineage-index-v2.json")
        Files.write(malformedIndex, lineageIndex.readBytes() + '\n'.code.toByte())
        Files.setPosixFilePermissions(malformedIndex, OWNER_READ_ONLY_PERMISSIONS)
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(bundle.archivePath, malformedIndex)
        }

        val mutatedParent = temp.resolve("lineage-index-mutated").createDirectories()
        Files.setPosixFilePermissions(mutatedParent, OWNER_DIRECTORY_PERMISSIONS)
        val mutatedIndex = mutatedParent.resolve("candidate-acp-lineage-index-v2.json")
        val lineageDigest = lineageDocument.getValue("candidateSourceLineageSha256").jsonPrimitive.content
        val mutatedDigest = (if (lineageDigest.first() == '0') "1" else "0") + lineageDigest.drop(1)
        Files.write(mutatedIndex, lineageText.replace(lineageDigest, mutatedDigest).toByteArray())
        Files.setPosixFilePermissions(mutatedIndex, OWNER_READ_ONLY_PERMISSIONS)
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(bundle.archivePath, mutatedIndex)
        }

        val oversizedParent = temp.resolve("lineage-index-oversized").createDirectories()
        Files.setPosixFilePermissions(oversizedParent, OWNER_DIRECTORY_PERMISSIONS)
        val oversizedIndex = oversizedParent.resolve("candidate-acp-lineage-index-v2.json")
        Files.write(oversizedIndex, ByteArray(64 * 1024 + 1) { 'x'.code.toByte() })
        Files.setPosixFilePermissions(oversizedIndex, OWNER_READ_ONLY_PERMISSIONS)
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(bundle.archivePath, oversizedIndex)
        }

        val contaminatedParent = temp.resolve("lineage-index-contaminated").createDirectories()
        Files.setPosixFilePermissions(contaminatedParent, OWNER_DIRECTORY_PERMISSIONS)
        contaminatedParent.resolve("unexpected").writeText("occupied")
        val contaminatedIndex = contaminatedParent.resolve("candidate-acp-lineage-index-v2.json")
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(bundle.archivePath, contaminatedIndex)
        }
        assertFalse(contaminatedIndex.exists())

        val wrongModeParent = temp.resolve("lineage-index-wrong-mode").createDirectories()
        Files.setPosixFilePermissions(
            wrongModeParent,
            OWNER_DIRECTORY_PERMISSIONS + PosixFilePermission.GROUP_READ,
        )
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
                bundle.archivePath,
                wrongModeParent.resolve("candidate-acp-lineage-index-v2.json"),
            )
        }

        val archiveHardLink = temp.resolve("candidate-archive-hard-link.zip")
        Files.createLink(archiveHardLink, bundle.archivePath)
        try {
            val hardLinkOutputParent = temp.resolve("lineage-index-hard-archive").createDirectories()
            Files.setPosixFilePermissions(hardLinkOutputParent, OWNER_DIRECTORY_PERMISSIONS)
            assertFailsWith<IllegalArgumentException> {
                LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
                    bundle.archivePath,
                    hardLinkOutputParent.resolve("candidate-acp-lineage-index-v2.json"),
                )
            }
        } finally {
            Files.delete(archiveHardLink)
        }

        val indexHardLinkParent = temp.resolve("lineage-index-hard-link").createDirectories()
        Files.setPosixFilePermissions(indexHardLinkParent, OWNER_DIRECTORY_PERMISSIONS)
        val indexHardLink = indexHardLinkParent.resolve("candidate-acp-lineage-index-v2.json")
        Files.createLink(indexHardLink, lineageIndex)
        try {
            assertFailsWith<IllegalArgumentException> {
                LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(bundle.archivePath, indexHardLink)
            }
        } finally {
            Files.delete(indexHardLink)
        }

        listOf(
            LlvmBehaviorCandidateAcpLineageIndexV2Publisher::class.java to "publish",
            LlvmBehaviorCandidateAcpLineageIndexV2Verifier::class.java to "verify",
        ).forEach { (owner, methodName) ->
            val method = owner.declaredMethods.single { it.name == methodName && !it.isSynthetic }
            assertEquals(listOf(Path::class.java, Path::class.java), method.parameterTypes.toList())
        }

        val sessionCommitment = evidence.getValue("session").jsonObject
            .getValue("sessionId").jsonObject.getValue("sha256").jsonPrimitive.content
        val filesystemOffset = text.indexOf("\"filesystem\"")
        assertTrue(filesystemOffset >= 0)
        val tamperedAuditSession = text.substring(0, filesystemOffset) +
            text.substring(filesystemOffset).replaceFirst(
                "\"sha256\":\"$sessionCommitment\"",
                "\"sha256\":\"${"0".repeat(64)}\"",
            )
        assertFailsWith<IllegalArgumentException> {
            verifyAcpExecutionReceiptDocument(
                tamperedAuditSession.toByteArray(),
                "decomp-engine.reconstruction-acp-execution-receipt",
                "moduleId",
                "parse",
            )
        }
    }

    @Test
    fun `candidate lineage index rejects archives without an accepted ACP contribution`() {
        val temp = createTempDirectory("candidate-lineage-without-acp-")
        val project = temp.resolve("project")
        SourceTreeGenerator.generate(evidenceModel(), project)
        MakeProjectBuilder.build(project)
        val archive = ArchivalPackager.create(project, temp.resolve("candidate.zip"))
        val outputParent = temp.resolve("lineage-index").createDirectories()
        Files.setPosixFilePermissions(outputParent, OWNER_DIRECTORY_PERMISSIONS)

        val failure = assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
                archive.archivePath,
                outputParent.resolve("candidate-acp-lineage-index-v2.json"),
            )
        }
        assertTrue(failure.message.orEmpty().contains("no accepted first-class ACP contribution"), failure.message)
    }

    @Test
    fun `agent candidate changed by publication normalization is rejected`() {
        val temp = createTempDirectory("acp-normalization-binding-")
        val project = temp.resolve("project")
        val harness = EvidenceHarness("session", "message", "tool", appendFinalNewline = false)

        val manifest = SourceTreeGenerator.generate(
            evidenceModel(),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            ),
        )

        val checkpoint = project.resolve("reports/modules/parse.json").readText()
        assertTrue(checkpoint.contains("\"accepted\": false"))
        assertTrue(checkpoint.contains("agent-source-normalization-changed-bytes"))
        assertTrue("fn_0000000000401000" in manifest.unresolvedImplementationIds)
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("rejected.zip"))
        }
    }

    @Test
    fun `receipt persistence failure never becomes an evidence-free fallback and can retry`() {
        val temp = createTempDirectory("acp-receipt-persistence-")
        val project = temp.resolve("project")
        var blockPersistence = true
        val harness = EvidenceHarness("session", "message", "tool", beforeReturn = { request ->
            if (blockPersistence) {
                val blocker = request.workspaceRoots.single().path.resolve("reports/agent-executions")
                blocker.parent.createDirectories()
                blocker.writeText("not a directory")
            }
        })
        val reconstructor = BoundedLlmModuleReconstructor(
            harness,
            harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
        )

        repeat(2) {
            assertFailsWith<Exception> {
                SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
            }
            assertFalse(project.resolve("reports/modules/parse.json").exists())
            assertFalse(project.resolve("src/modules/parse.c").exists())
        }

        project.resolve("reports/agent-executions").deleteIfExists()
        blockPersistence = false
        val manifest = SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
        assertTrue(manifest.unresolvedImplementationIds.isEmpty())
        assertTrue(project.resolve("reports/agent-executions/parse.json").exists())
    }

    @Test
    fun `ordinary refused cancelled limit and typed failure outcomes persist invocation receipts`() {
        val temp = createTempDirectory("acp-terminal-receipts-")
        val scenarios = listOf(
            "refused" to EvidenceHarness(
                "session-refused", "message", "tool", terminalStopReason = AgentStopReason.REFUSED,
            ),
            "cancelled" to EvidenceHarness(
                "session-cancelled", "message", "tool", terminalStopReason = AgentStopReason.CANCELLED,
            ),
            "limit-exhausted" to EvidenceHarness(
                "session-limit", "message", "tool", terminalStopReason = AgentStopReason.LIMIT_EXHAUSTED,
            ),
            "failed-protocol" to EvidenceHarness(
                "session-failed", "message", "tool", failWithProtocolOutcome = true,
            ),
        )

        scenarios.forEach { (name, harness) ->
            val project = temp.resolve(name)
            val reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            )
            if (name in setOf("cancelled", "limit-exhausted")) {
                assertFailsWith<ModuleReconstructionInterruptedException> {
                    SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
                }
            } else {
                val manifest = SourceTreeGenerator.generate(evidenceModel(), project, reconstructor = reconstructor)
                assertTrue("fn_0000000000401000" in manifest.unresolvedImplementationIds)
            }
            val evidence = project.resolve("reports/agent-executions/parse.json")
            assertTrue(evidence.exists(), name)
            val text = evidence.readText()
            assertTrue(text.contains("\"releaseComplete\": false"), name)
            assertTrue(
                text.contains("\"stopReason\":\"${name.removePrefix("failed-")}\"") ||
                    text.contains("\"kind\":\"protocol\""),
                name,
            )
            assertFalse(text.contains("typed protocol failure"), name)
        }
    }

    @Test
    fun `malformed peer text persists as an injective partial v2 commitment`() {
        val temp = createTempDirectory("acp-malformed-receipt-")
        val project = temp.resolve("project")
        val malformed = "peer-\uD800-text"
        val harness = EvidenceHarness("session", malformed, "tool")

        val manifest = SourceTreeGenerator.generate(
            evidenceModel(),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            ),
        )

        val text = project.resolve("reports/agent-executions/parse.json").readText()
        assertTrue(text.contains("\"encoding\":\"jvm-utf16be\""))
        assertTrue(text.contains("\"releaseComplete\": false"))
        assertFalse(text.contains(malformed))
        assertTrue("fn_0000000000401000" in manifest.unresolvedImplementationIds)
        assertFailsWith<Exception> {
            ArchivalPackager.create(project, temp.resolve("malformed.zip"))
        }

        val root = AgentWorkspaceRoot("root", temp.resolve("binding-root"))
        val path = AgentWorkspacePath(root.id, "candidate.c")
        fun binding(objective: String): AgentExecutionRequestBinding = AgentExecutionRequestBinding.capture(
            AgentExecutionRequest(
                objective = objective,
                workspaceRoots = listOf(root),
                accessPolicy = AgentAccessPolicy(
                    listOf(AgentPathRule(path, setOf(AgentOperation.READ_FILE))),
                ),
            ),
        )
        val first = binding("objective-\uD800")
        assertEquals(first, binding("objective-\uD800"))
        assertNotEquals(first.requestSha256, binding("objective-\uDFFF").requestSha256)
    }

    @Test
    fun `compact receipt fallback and exposed assessment share false release marker`() {
        val temp = createTempDirectory("acp-compact-receipt-")
        temp.resolve("src/modules").createDirectories()
        val root = AgentWorkspaceRoot("project", temp)
        val target = AgentWorkspacePath(root.id, "src/modules/parse.c")
        val request = AgentExecutionRequest(
            objective = "reconstruct",
            workspaceRoots = listOf(root),
            accessPolicy = AgentAccessPolicy(
                listOf(
                    AgentPathRule(
                        target,
                        setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE),
                    ),
                ),
            ),
        )
        val harness = EvidenceHarness("session", "message", "tool")
        val recorder = BoundedAgentExecutionEventRecorder()
        val receipt = harness.executeReceipt(request, recorder::record)

        val evidence = requireNotNull(
            ReconstructionAgentExecutionEvidence.captureOrNull(
                request = request,
                moduleId = "parse",
                promptSha256 = "a".repeat(64),
                receipt = receipt,
                events = recorder.receiptSnapshot(),
                maximumFullArtifactBytes = 1,
            ),
        )
        val text = evidence.toReceiptJson("parse")
        assertFalse(evidence.releaseComplete)
        assertTrue(text.contains("\"releaseComplete\": false"))
        assertTrue(text.contains("\"truncationReason\": \"artifact-byte-limit\""))
    }

    private class EvidenceHarness(
        private val sessionId: String,
        private val message: String,
        private val toolTitle: String,
        private val appendFinalNewline: Boolean = true,
        private val beforeReturn: (AgentExecutionRequest) -> Unit = {},
        private val terminalStopReason: AgentStopReason = AgentStopReason.COMPLETED,
        private val failWithProtocolOutcome: Boolean = false,
    ) : AgentHarness {
        private var evidence: AcpExecutionEvidenceSnapshot? = null
        lateinit var requestBinding: AgentExecutionRequestBinding
            private set
        val factoryProvenance = AcpHarnessProvenance(
            harness = "acp",
            implementationId = IMPLEMENTATION_ID,
            agentExecutionContractVersion = 1,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = "b".repeat(64),
            deprecated = false,
        )

        override fun implementationIdentifier(): String = IMPLEMENTATION_ID

        override fun execute(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult {
            requestBinding = AgentExecutionRequestBinding.capture(request)
            val target = request.accessPolicy.pathRules.single { rule ->
                decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
            }.path
            val source = """
                #include "modules/parse.h"
                /* fn_0000000000401000 */
                int parse_input(void) { return 17; }
            """.trimIndent() + if (appendFinalNewline) "\n" else ""
            val changes = if (terminalStopReason == AgentStopReason.COMPLETED) {
                target.resolve(request.workspaceRoots).writeText(source)
                listOf(
                    AgentFileChange(
                        target,
                        AgentFileChangeKind.CREATED,
                        beforeSha256 = null,
                        afterSha256 = sha256(source.toByteArray()),
                        sizeBytes = source.toByteArray().size.toLong(),
                    ),
                )
            } else {
                emptyList()
            }
            onEvent(AgentMessageEvent(0, "message-1", AgentMessageRole.ASSISTANT, message, completed = true))
            onEvent(AgentToolEvent(1, "tool-1", toolTitle, AgentToolStatus.SUCCEEDED, mapOf("kind" to "edit")))
            onEvent(
                AgentPermissionEvent(
                    2,
                    "permission-1",
                    AgentPermissionDecision.ALLOW_ONCE,
                    selectedOptionId = "allow-1",
                    reason = "selected",
                ),
            )
            changes.singleOrNull()?.let { change -> onEvent(AgentFileChangeEvent(3, change)) }
            evidence = snapshot(target)
            beforeReturn(request)
            return AgentExecutionResult(
                terminalStopReason,
                "peer completion summary",
                changes,
                AgentSessionReference(IMPLEMENTATION_ID, sessionId),
                AgentUsage(10, 20, 3, 1, Duration.ofMillis(250)),
            )
        }

        override fun executeReceipt(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionReceipt {
            if (failWithProtocolOutcome) {
                requestBinding = AgentExecutionRequestBinding.capture(request)
                val target = request.accessPolicy.pathRules.single { rule ->
                    decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
                }.path
                onEvent(AgentMessageEvent(0, "failed-message", AgentMessageRole.ASSISTANT, message))
                evidence = snapshot(target)
                beforeReturn(request)
                return AgentExecutionReceipt(
                    requestBinding = requestBinding,
                    outcome = AgentExecutionOutcome.Failed(
                        AgentFailure(
                            AgentFailureKind.PROTOCOL,
                            "typed protocol failure must remain committed but redacted",
                            retryable = true,
                            session = AgentSessionReference(IMPLEMENTATION_ID, sessionId),
                        ),
                    ),
                    providerEvidence = requireNotNull(evidence).asInvocationEvidence(),
                )
            }
            val result = execute(request, onEvent)
            val complete = requireNotNull(evidence)
            return AgentExecutionReceipt(
                requestBinding = requestBinding,
                outcome = AgentExecutionOutcome.Returned(result),
                providerEvidence = complete.asInvocationEvidence(),
            )
        }

        private fun snapshot(target: decompengine.agent.AgentWorkspacePath): AcpExecutionEvidenceSnapshot {
            val terminal = AcpTerminalAuditRecord(
                sequence = 0,
                sessionId = sessionId,
                method = "terminal/create",
                requestSha256 = digest("terminal request"),
                terminalIdSha256 = digest("terminal-1"),
                toolCallIdSha256 = digest("tool-1"),
                outcome = AcpTerminalAuditOutcome.ALLOWED,
                reason = AcpTerminalAuditReason.CREATED,
                networkIsolated = true,
                retainedOutputBytes = 12,
                producedOutputBytes = 12,
                outputTruncated = false,
            )
            return AcpExecutionEvidenceSnapshot(
                factoryProvenance = factoryProvenance,
                negotiatedAgent = AcpNegotiatedAgentEvidence(
                    ACP_STABLE_PROTOCOL_VERSION,
                    "fake-acp-agent",
                    "1.2.3",
                    "Fake ACP Agent",
                    AcpNegotiatedCapabilitiesEvidence(
                        loadSession = false,
                        promptImage = false,
                        promptAudio = false,
                        promptEmbeddedContext = true,
                        mcpHttp = false,
                        mcpSse = false,
                        sessionAdditionalDirectories = false,
                    ),
                ),
                wirePromptSha256 = digest("exact wire prompt bytes"),
                diagnostics = AcpProcessDiagnostics(
                    pid = 123,
                    exitCode = 0,
                    stderr = "stderr peer output",
                    stderrTruncated = false,
                    producedOutputBytes = 512,
                    producedOutputLimitBytes = 1_024,
                    outputLimitExceeded = false,
                    forcedTermination = false,
                    rootTerminationRequested = false,
                    remainingProcessIds = emptyList(),
                    containment = "linux-bubblewrap",
                    networkIsolated = true,
                    sandboxCleanupVerified = true,
                ),
                filesystemAudit = listOf(
                    AcpFilesystemAuditRecord(
                        0,
                        sessionId,
                        "fs/write_text_file",
                        digest(target.relativePath),
                        target,
                        AcpFilesystemAuditOutcome.ALLOWED,
                        AcpFilesystemAuditReason.COMPLETED,
                    ),
                ),
                terminalAudit = listOf(terminal),
                permissionAudit = listOf(
                    AcpPermissionAuditRecord(
                        0,
                        sessionId,
                        digest("tool-1"),
                        2,
                        digest("allow-1"),
                        PermissionOptionKind.ALLOW_ONCE,
                        AcpPermissionAuditOutcome.ALLOWED,
                        AcpPermissionAuditReason.SELECTED,
                        authorityExpanded = false,
                    ),
                ),
                sandboxEvidence = AcpSandboxEvidence(
                    provider = "sandbox-evidence-v1",
                    providerVersion = "1",
                    providerExecutableSha256 = "c".repeat(64),
                    providerExecutableMode = 365,
                    resourceLimiterSha256 = "d".repeat(64),
                    scopeSupervisorSha256 = "e".repeat(64),
                    scopeInspectorSha256 = "f".repeat(64),
                    environmentFdOpenerSha256 = "1".repeat(64),
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
                    policySha256 = "2".repeat(64),
                    terminalLimits = null,
                    launches = emptyList(),
                    authorities = emptyList(),
                    terminalAudit = listOf(terminal),
                    outerProcessOutput = AcpProducedOutputEvidence(1_024, 512, false),
                ),
            )
        }
    }

    private companion object {
        const val IMPLEMENTATION_ID = "test-acp"

        val OWNER_DIRECTORY_PERMISSIONS = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
        val OWNER_READ_ONLY_PERMISSIONS = setOf(PosixFilePermission.OWNER_READ)

        fun digest(value: String): String = java.security.MessageDigest.getInstance("SHA-256")
            .digest(value.toByteArray())
            .joinToString("") { "%02x".format(it) }
    }

    private fun evidenceModel(): RecoveredProgramModel = RecoveredProgramModel(
        inputSha256 = "a".repeat(64),
        functions = listOf(
            RecoveredFunction(
                "fn_0000000000401000",
                "parse_input",
                0x401000UL,
                "int parse_input(void)",
            ),
        ),
    )
}

private fun AcpExecutionEvidenceSnapshot.asInvocationEvidence(): AcpInvocationEvidenceSnapshot =
    AcpInvocationEvidenceSnapshot(
        factoryProvenance = factoryProvenance,
        phaseReached = AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT,
        cleanupDisposition = AcpExecutionCleanupDisposition.VERIFIED,
        negotiatedAgent = negotiatedAgent,
        wirePromptSha256 = wirePromptSha256,
        diagnostics = diagnostics,
        filesystemAudit = filesystemAudit,
        terminalAudit = terminalAudit,
        permissionAudit = permissionAudit,
        sandboxEvidence = sandboxEvidence,
        completeness = AcpExecutionEvidenceCompleteness(true, true, true),
        completeExecutionEvidence = this,
    )
