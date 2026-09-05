package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.project.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.io.path.*
import kotlin.test.*

class BuiltinRepairPersistenceTest {
    @TempDir lateinit var directory: Path
    private val relative = "src/modules/alpha.c"
    private fun project(name: String = "project"): Path = directory.resolve(name).also {
        SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
            RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)"),
        )), it)
    }
    private fun begin(graph: ModuleRevisionGraph): ModuleRevisionAttempt {
        val corpus = graph.retainedRegressionCorpus()
        return graph.beginAttempt(listOf(relative), RevisionRepairMetadata(graph.snapshot.nodes.count { it.repairMetadata != null } + 1, "compile", "bounded failure", null,
            corpus.inputs.map { it.id }, null, corpus.sha256))
    }
    private fun document(graph: ModuleRevisionGraph, attempt: ModuleRevisionAttempt, project: Path,
        ending: String = "completed"): RepairAgentInvocationDocument {
        val workflow = graph.invocationIdentity(attempt)
        val journals = Files.createTempDirectory(directory, "journals-")
        Files.setPosixFilePermissions(journals, PosixFilePermissions.fromString("rwx------"))
        val before = graph.candidateSources(attempt).getValue(relative)
        var turns = 0
        val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ ->
            if (turns++ == 0) ModelResponse("", listOf(ModelToolCall("write1", "write_text", buildJsonObject {
                put("root", "project"); put("path", relative); put("content", before.decodeToString() + "\n/* candidate */\n")
            })), ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, false), 1)
            else if (ending == "failed") throw ModelProviderException(ModelFailureKind.TRANSPORT)
            else ModelResponse("", emptyList(), if (ending == "refused") ModelFinishReason.REFUSED else ModelFinishReason.STOP,
                ModelUsage(100, 10, false), 1)
        }, journalFactory = BuiltinRepairJournalFactory(journals, "fixture", "scripted-v1"))
        lateinit var request: AgentExecutionRequest
        val events = BoundedAgentExecutionEventRecorder()
        val execution = CapturedRepairStagingAuthority.executeReceipt(harness, mapOf(relative to before), setOf(relative),
            RepairResourceBudget(), { root -> AgentExecutionRequest("bounded failure", listOf(root),
                accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(AgentWorkspacePath(root.id, relative),
                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))), workflowIdentity = workflow).also { request = it }
            }, events::record)
        assertEquals(2, turns)
        assertEquals(1, assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence).candidateChanges.size)
        return assertNotNull(RepairAgentInvocationDocument.captureOrNull(request, workflow.promptSha256, execution.receipt,
            events.receiptSnapshot(), attempt.id))
    }

    @Test fun `terminal builtin attempts persist immutable evidence and rejected history without accepting candidates`() {
        for (ending in listOf("completed", "refused", "failed")) {
            val project = project(ending)
            val before = project.resolve(relative).readBytes()
            lateinit var binding: RepairAgentInvocationBinding
            lateinit var raw: ByteArray
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val attempt = begin(graph)
                val document = document(graph, attempt, project, ending)
                raw = document.bytes
                binding = graph.persistAndBindAgentInvocation(attempt, document)
                assertEquals(RepairAgentAssessmentStatus.PENDING, binding.assessmentStatus)
                assertEquals(document.builtinArchive, binding.builtinArchive)
                assertEquals(if (ending == "failed") "failed-protocol" else "returned-$ending", binding.terminalOutcome)
                assertContentEquals(raw, project.resolve(binding.receiptPath).readBytes())
                assertFailsWith<IllegalArgumentException> { graph.accept(attempt, RepairEvidence("valid", "unqualified")) }
                assertFailsWith<IllegalArgumentException> { binding.copy(receiptReleaseComplete = true) }
                graph.reject(attempt, RepairEvidence("unqualified-invocation", "candidate was not accepted"))
                graph.synchronizeRepairHistory()
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val reopened = assertNotNull(graph.snapshot.nodes.last().repairMetadata?.agentInvocation)
                assertEquals(binding.copy(assessmentStatus = RepairAgentAssessmentStatus.REJECTED), reopened)
                assertEquals(reopened, RepairHistory(project.resolve("reports/repair_history.json")).all().single().agentInvocation)
            }
            assertContentEquals(before, project.resolve(relative).readBytes())
            assertContentEquals(raw, project.resolve(binding.receiptPath).readBytes())
        }
    }

    @Test fun `provisional input remains distinct from accepted baseline through invocation persistence and reload`() {
        val project = project()
        val before = project.resolve(relative).readBytes()
        lateinit var workflow: AgentWorkflowIdentity
        lateinit var binding: RepairAgentInvocationBinding
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainedRegressionCorpus()
            graph.beginRun(2, 60_000)
            val metadata = RevisionRepairMetadata(graph.snapshot.nodes.count { it.repairMetadata != null } + 1, "compile", "bounded failure", null,
                corpus.inputs.map { it.id }, null, corpus.sha256,
                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
            val baseline = graph.snapshot.nodes.single().sourceRevisionSha256
            val first = graph.beginAttempt(listOf(relative), metadata)
            assertEquals(baseline, graph.invocationIdentity(first).inputRevisionSha256)
            graph.installCandidate(first, mapOf(relative to before + "\n/* provisional */\n".toByteArray()))
            val provisional = graph.recordProvisional(first, RepairEvidence("compile", "compile only"),
                RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(first)), graph.snapshot.profileSha256,
                    graph.snapshot.indexSha256, corpus.sha256, null, sha256("rebuilt".toByteArray()),
                    sha256("runtime".toByteArray()), sha256("evidence".toByteArray()), true,
                    RepairValidationAssurance.TEST_ONLY_HOST_PROCESS))
            val second = graph.beginAttempt(listOf(relative), metadata.copy(iterationIndex = 2))
            workflow = graph.invocationIdentity(second)
            assertEquals(2, workflow.schemaVersion)
            assertEquals(baseline, workflow.acceptedRevisionSha256)
            assertEquals(provisional.sourceRevisionSha256, workflow.inputRevisionSha256)
            assertNotEquals(workflow.acceptedRevisionSha256, workflow.inputRevisionSha256)
            val document = document(graph, second, project)
            val reference = assertNotNull(document.builtinArchive)
            reference.requireWorkflow(workflow)
            for (wrong in listOf(workflow.copy(inputRevisionSha256 = null),
                workflow.copy(inputRevisionSha256 = baseline),
                workflow.copy(acceptedRevisionSha256 = provisional.sourceRevisionSha256))) {
                assertFails { reference.requireWorkflow(wrong) }
            }
            binding = graph.persistAndBindAgentInvocation(second, document)
            graph.reject(second, RepairEvidence("unqualified", "built-in candidate is not accepted"))
            graph.finishRun(RepairRunStatus.REJECTED, RepairEvidence("unqualified", "stopped"))
            graph.synchronizeRepairHistory()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val reopened = assertNotNull(graph.snapshot.nodes.last().repairMetadata?.agentInvocation)
            assertEquals(binding.copy(assessmentStatus = RepairAgentAssessmentStatus.REJECTED), reopened)
            assertNotNull(reopened.builtinArchive).requireWorkflow(workflow)
            assertNull(graph.snapshot.fullyAcceptedHeadId)
        }
        assertContentEquals(before, project.resolve(relative).readBytes())
    }

    @Test fun `graph reload independently checks artifact bytes journal commitment and accepted parent identity`() {
        val project = project()
        lateinit var binding: RepairAgentInvocationBinding
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = begin(graph)
            binding = graph.persistAndBindAgentInvocation(attempt, document(graph, attempt, project))
            graph.reject(attempt, RepairEvidence("unqualified", "rejected"))
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val originalGraph = graphPath.readText()
        val reference = assertNotNull(binding.builtinArchive)
        for (old in listOf(reference.commitment.headSha256, reference.identity.journal.acceptedRevisionSha256)) {
            // Change only the reference occurrence, not the graph's independently reconstructed parent.
            val field = if (old == reference.commitment.headSha256) "headSha256" else "acceptedRevisionSha256"
            graphPath.writeText(originalGraph.replace("\"$field\":\"$old\"", "\"$field\":\"${"f".repeat(64)}\""))
            assertFails { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close() }
            graphPath.writeText(originalGraph)
        }
        val receipt = project.resolve(binding.receiptPath)
        val originalReceipt = receipt.readBytes()
        receipt.writeBytes(originalReceipt.copyOf(originalReceipt.size - 1))
        assertFails { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close() }
        receipt.writeBytes(originalReceipt)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close()
    }

    @Test fun `failure before graph publication recovers the immutable builtin orphan without executing again`() {
        val project = project()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(project, GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync && point.scope == "revision-state") {
                    error("injected before graph publication")
                }
            })
        val attempt = begin(graph)
        val document = document(graph, attempt, project)
        armed = true
        assertFailsWith<RepairAgentEvidencePersistenceException> { graph.persistAndBindAgentInvocation(attempt, document) }
        val receiptPath = project.resolve("reports/repair-revisions/${attempt.id}.builtin-receipt.json")
        assertContentEquals(document.bytes, receiptPath.readBytes())
        assertFalse(project.resolve("reports/repair-revisions/graph.json").readText().contains("builtinArchive"))
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            val node = recovered.snapshot.nodes.last()
            assertTrue(node.recoveredAfterCrash)
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            assertEquals(document.builtinArchive, node.repairMetadata?.agentInvocation?.builtinArchive)
            assertEquals(RepairAgentAssessmentStatus.REJECTED, node.repairMetadata?.agentInvocation?.assessmentStatus)
        }
        assertContentEquals(document.bytes, receiptPath.readBytes())
    }

    @Test fun `ambiguous provider orphans stop recovery until the conflicting artifact is removed`() {
        val project = project()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val attempt = begin(graph)
        val document = document(graph, attempt, project)
        val root = project.resolve("reports/repair-revisions")
        root.resolve("${attempt.id}.builtin-receipt.json").writeBytes(document.bytes)
        val conflict = root.resolve("${attempt.id}.acp-receipt.json")
        conflict.writeText("{}")
        graph.close()
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close() }
        conflict.deleteExisting()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(document.sha256, recovered.snapshot.nodes.last().repairMetadata?.agentInvocation?.receiptSha256)
        }
    }

    @Test fun `project archive retains rejected builtin evidence and independently rejects a changed journal reference`() {
        lateinit var binding: RepairAgentInvocationBinding
        val project = ModuleRevisionGraphTest().releaseProjectWithRejectedInvocation { graph, project ->
            val attempt = begin(graph)
            binding = graph.persistAndBindAgentInvocation(attempt, document(graph, attempt, project))
            graph.reject(attempt, RepairEvidence("unqualified", "rejected"))
            graph.synchronizeRepairHistory()
        }
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val bundle = ArchivalPackager.create(project, directory.resolve("valid.zip"))
        val target = directory.resolve("verified")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, target)
        assertEquals(2, lineage.source.acceptedAcpContributions.size)
        assertTrue(lineage.source.acceptedAcpContributions.none { it.receiptPath == binding.receiptPath })
        assertContentEquals(project.resolve(binding.receiptPath).readBytes(), target.resolve(binding.receiptPath).readBytes())
        val entries = linkedMapOf<String, ByteArray>()
        ZipInputStream(Files.newInputStream(bundle.archivePath)).use { zip ->
            while (true) { val entry = zip.nextEntry ?: break; if (!entry.isDirectory) entries[entry.name] = zip.readBytes() }
        }
        val oldHead = assertNotNull(binding.builtinArchive).commitment.headSha256
        for (path in listOf("reports/repair-revisions/graph.json", "reports/repair_history.json")) {
            entries[path] = entries.getValue(path).decodeToString().replace(oldHead, "f".repeat(64)).toByteArray()
        }
        entries.remove("ARCHIVE_MANIFEST.sha256")
        entries["ARCHIVE_MANIFEST.sha256"] = entries.toSortedMap().entries.joinToString("") { (path, bytes) ->
            "${sha256(bytes)}  $path\n"
        }.toByteArray()
        val tampered = directory.resolve("tampered.zip")
        ZipOutputStream(Files.newOutputStream(tampered)).use { zip ->
            entries.forEach { (path, bytes) -> zip.putNextEntry(ZipEntry(path)); zip.write(bytes); zip.closeEntry() }
        }
        assertFails { ArchivalBundleVerifier.extractAndVerifyCandidateLineage(tampered, directory.resolve("tampered")) }
    }

    @Test fun `persisted journal reference rejects unknown fields type substitutions and unbounded commitments`() {
        val project = project()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val attempt = begin(graph)
        val reference = assertNotNull(document(graph, attempt, project).builtinArchive)
        val json = reference.json()
        assertEquals(reference, parseBuiltinInvocationArchiveReference(json))
        val commitment = json.getValue("commitment").jsonObject
        fun changedRecords(value: JsonPrimitive) = JsonObject(json + ("commitment" to JsonObject(commitment + ("records" to value))))
        for (bad in listOf(JsonObject(json + ("extra" to JsonNull)),
            changedRecords(JsonPrimitive("2")), changedRecords(JsonPrimitive(100_001)))) {
            assertFails { parseBuiltinInvocationArchiveReference(bad) }
        }
        graph.reject(attempt, RepairEvidence("test", "no publication")); graph.close()
    }
}
