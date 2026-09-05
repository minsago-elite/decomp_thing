package decompengine.repair

import decompengine.acp.LinuxFilesystemSyscalls
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
import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
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
import decompengine.project.AcpExecutionReceiptDocument
import decompengine.project.BoundedAgentExecutionEventRecorder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.ArchivalPackager
import decompengine.project.captureBuildSourceRevision
import decompengine.project.MakeProjectBuilder
import decompengine.project.GeneratedCRepairIndexProfile
import decompengine.project.sha256
import decompengine.oracle.behavior.LlvmBehaviorCandidateAcpLineageIndexV2Publisher
import decompengine.validation.ProcessInput
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.acp.acpSandboxCanonicalStringDigest
import kotlinx.serialization.json.jsonObject
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipInputStream
import java.util.zip.ZipOutputStream
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readLines
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ModuleRevisionGraphTest {
    @Test
    fun `repair graph persists failed ACP receipt before rejection and detects later tampering`() {
        val project = generatedProject()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf("src/modules/alpha.c"),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        val document = failedAcpReceiptDocument(project, attempt)

        val pending = graph.persistAndBindAgentInvocation(attempt, document)
        assertEquals(RepairAgentAssessmentStatus.PENDING, pending.assessmentStatus)
        assertFalse(pending.receiptReleaseComplete)
        val receiptPath = project.resolve(pending.receiptPath)
        assertTrue(receiptPath.exists())
        assertFalse(receiptPath.readText().contains("peer-controlled failure text"))
        val acceptanceFailure = assertFailsWith<IllegalArgumentException> {
            graph.accept(attempt, RepairEvidence("valid", "must not accept failed invocation"))
        }
        assertTrue(acceptanceFailure.message.orEmpty().contains("incomplete ACP"))
        val rejected = graph.reject(attempt, RepairEvidence("agent-failure-protocol", "provider invocation failed"))
        assertEquals(
            RepairAgentAssessmentStatus.REJECTED,
            rejected.repairMetadata?.agentInvocation?.assessmentStatus,
        )
        graph.close()

        receiptPath.writeText(receiptPath.readText().replaceFirst("\"schemaVersion\": 2", "\"schemaVersion\": 1"))
        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(failure.message.orEmpty().contains("digest"))
    }

    @Test
    fun `accepted agent repair is bound to one release-complete ACP receipt`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val after = before + "\n/* receipt-bound candidate */\n".toByteArray()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf(relative),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )

        val document = completeAcpReceiptDocument(project, attempt, relative, before, after)
        assertTrue(document.releaseComplete)
        graph.persistAndBindAgentInvocation(attempt, document)
        graph.installCandidate(attempt, mapOf(relative to after))
        val accepted = graph.accept(attempt, RepairEvidence("valid", "candidate passed validation"))

        val binding = requireNotNull(accepted.repairMetadata?.agentInvocation)
        assertEquals(RepairAgentAssessmentStatus.ACCEPTED, binding.assessmentStatus)
        assertEquals("returned-completed", binding.terminalOutcome)
        assertTrue(binding.receiptReleaseComplete)
        assertEquals(document.requestSha256, binding.requestSha256)
        assertEquals(document.resultChangesSha256, binding.resultChangesSha256)
        assertEquals(document.sha256, binding.receiptSha256)
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            val iteration = reopened.derivedRepairIterations().single()
            assertFalse(iteration.releaseComplete)
            assertEquals(RepairAttemptDisposition.LEGACY_UNVERIFIED, iteration.disposition)
            assertEquals(RepairPublicationMode.ACP_RELEASE, iteration.publicationMode)
            assertEquals(binding, iteration.agentInvocation)
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(
            graphPath.readText().replaceFirst(
                "\"requestSha256\":\"${binding.requestSha256}\"",
                "\"requestSha256\":\"${"9".repeat(64)}\"",
            ),
        )
        val crossPair = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(crossPair.message.orEmpty().contains("cross-paired"))
    }

    @Test
    fun `repair candidate cannot differ from the exact ACP result change set`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val declaredAfter = before + "\n/* agent-declared candidate */\n".toByteArray()
        val installedAfter = before + "\n/* cross-paired candidate */\n".toByteArray()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf(relative),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        graph.persistAndBindAgentInvocation(
            attempt,
            completeAcpReceiptDocument(project, attempt, relative, before, declaredAfter),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            graph.installCandidate(attempt, mapOf(relative to installedAfter))
        }

        assertTrue(
            failure.message.orEmpty().contains("differ from the bound ACP result"),
            failure.message.orEmpty(),
        )
        assertContentEquals(before, target.readBytes())
        graph.reject(attempt, RepairEvidence("candidate-error", "cross-paired change rejected"))
        graph.close()
    }

    @Test
    fun `forged release marker cannot hide incomplete ACP process evidence`() {
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val after = before + "\n/* forged-release regression */\n".toByteArray()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf(relative),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        val document = completeAcpReceiptDocument(project, attempt, relative, before, after)
        graph.persistAndBindAgentInvocation(attempt, document)
        graph.installCandidate(attempt, mapOf(relative to after))
        val accepted = graph.accept(attempt, RepairEvidence("valid", "candidate passed validation"))
        val binding = requireNotNull(accepted.repairMetadata?.agentInvocation)
        graph.close()

        val receiptPath = project.resolve(binding.receiptPath)
        val tampered = receiptPath.readText().replaceFirst(
            "\"networkIsolated\":true",
            "\"networkIsolated\":false",
        )
        receiptPath.writeText(tampered)
        val tamperedSha256 = sha256(tampered.toByteArray())
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(
            graphPath.readText().replaceFirst(binding.receiptSha256, tamperedSha256),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }
        assertTrue(failure.message.orEmpty().contains("network isolation"))
    }

    @Test
    fun `pending assessment failure preserves raw ACP receipt without fallback finalization`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
                ) {
                    throw IllegalStateException("injected pending-assessment persistence failure")
                }
            },
        )
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf("src/modules/alpha.c"),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        armed = true

        val failure = assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentInvocation(attempt, failedAcpReceiptDocument(project, attempt))
        }

        assertTrue(failure.message.orEmpty().contains("preserved"))
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        val receiptPath = project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json")
        assertTrue(receiptPath.exists())
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            val recovered = reopened.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.status)
            assertTrue(recovered.recoveredAfterCrash)
            assertEquals(
                RepairAgentAssessmentStatus.REJECTED,
                recovered.repairMetadata?.agentInvocation?.assessmentStatus,
            )
        }
        assertTrue(receiptPath.exists())
    }

    @Test
    fun `raw receipt persistence failure cannot be converted into a repair rejection`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-invocation-evidence"
                ) {
                    throw IllegalStateException("injected raw-receipt persistence failure")
                }
            },
        )
        val corpus = graph.retainedRegressionCorpus()
        val attempt = graph.beginAttempt(
            listOf("src/modules/alpha.c"),
            RevisionRepairMetadata(
                1,
                "compile",
                "bounded failure",
                null,
                emptyList(),
                null,
                corpus.sha256,
            ),
        )
        armed = true

        val failure = assertFailsWith<RepairAgentEvidencePersistenceException> {
            graph.persistAndBindAgentInvocation(attempt, failedAcpReceiptDocument(project, attempt))
        }

        assertTrue(failure.message.orEmpty().contains("before assessment"))
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        assertEquals(1, graph.snapshot.nodes.size)
        assertFalse(project.resolve("reports/repair-revisions/${attempt.id}.acp-receipt.json").exists())
        graph.close()
    }

    @Test
    fun `multi-module diagnostics select only dependency-indexed context`() {
        val project = generatedProject()
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)

        val selection = index.select(
            "compile",
            "src/modules/alpha.c:12: error: bad declaration\nsrc/modules/charlie.c:3: error: missing expression",
        )

        assertEquals(listOf("alpha", "charlie"), selection.seedModules)
        assertEquals(listOf("beta"), selection.dependencyModules)
        assertTrue("src/modules/alpha.c" in selection.writablePaths)
        assertTrue("include/modules/alpha.h" in selection.writablePaths)
        assertTrue("src/modules/alpha_internal.h" in selection.writablePaths)
        assertTrue("src/modules/charlie.c" in selection.writablePaths)
        assertTrue("include/modules/beta.h" in selection.readablePaths)
        assertFalse("src/modules/beta.c" in selection.readablePaths)
        assertFalse(selection.readablePaths.any { "delta" in it })
    }

    @Test
    fun `source-bound build owners select context when aggregate output has no source path`() {
        val project = generatedProject()
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        project.resolve("reports/build_contract.json").writeText(
            "{\"schemaVersion\":2,\"sourceStableDuringBuild\":true," +
                "\"sourceRevisionSha256\":\"${index.sourceRevisionSha256}\"," +
                "\"failedOwners\":[\"charlie\"],\"modules\":[{\"id\":\"charlie\"}]}",
        )

        val selection = index.select("compile", "make: *** [all] Error 2")

        assertEquals(listOf("charlie"), selection.seedModules)
        assertTrue("src/modules/charlie.c" in selection.writablePaths)
        assertFalse(selection.readablePaths.any { "alpha" in it || "delta" in it })

        val boundSelection = index.select(
            "compile",
            "src/modules/alpha.c:1: error: unauthenticated text must not widen the build owner",
        )
        assertEquals(listOf("charlie"), boundSelection.seedModules)
        assertFalse("src/modules/alpha.c" in boundSelection.readablePaths)
    }

    @Test
    fun `present generated C build ownership evidence is validated and bounded without fallback`() {
        run {
            val project = generatedProject()
            val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
            project.resolve("reports/build_contract.json").writeText("{}")

            val failure = assertFailsWith<IllegalArgumentException> {
                index.select("compile", "src/modules/alpha.c: error: exact path must not bypass bad evidence")
            }

            assertTrue(failure.message.orEmpty().contains("schemaVersion"))
        }
        run {
            val project = generatedProject()
            val budget = RepairResourceBudget(maximumContextModules = 1)
            val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile, budget)
            project.resolve("reports/build_contract.json").writeText(
                "{\"schemaVersion\":2,\"sourceStableDuringBuild\":true," +
                    "\"sourceRevisionSha256\":\"${index.sourceRevisionSha256}\"," +
                    "\"failedOwners\":[\"alpha\",\"beta\"]," +
                    "\"modules\":[{\"id\":\"alpha\"},{\"id\":\"beta\"}]}",
            )

            val failure = assertFailsWith<RepairBudgetExceededException> {
                index.select("compile", "aggregate failure")
            }

            assertTrue(failure.message.orEmpty().contains("failed owners"))
        }
    }

    @Test
    fun `rejected candidate restores byte-identical files and records downstream invalidation`() {
        val project = generatedProject()
        val alpha = project.resolve("src/modules/alpha.c")
        val beta = project.resolve("src/modules/beta.c")
        val alphaBefore = alpha.readBytes()
        val betaBefore = beta.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c", "src/modules/beta.c"))
            graph.installCandidate(
                attempt,
                mapOf(
                    "src/modules/alpha.c" to alphaBefore + byteArrayOf(0, 1, 2, 3),
                    "src/modules/beta.c" to betaBefore + "\n/* candidate beta */\n".toByteArray(),
                ),
            )
            assertFalse(alpha.readBytes().contentEquals(alphaBefore))

            val rejected = graph.reject(attempt, RepairEvidence("compile", "candidate did not compile"))

            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(listOf("alpha", "beta"), rejected.changedModules)
            assertContentEquals(alphaBefore, alpha.readBytes())
            assertContentEquals(betaBefore, beta.readBytes())
            assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
        }
    }

    @Test
    fun `accepted change explicitly invalidates all transitive dependents and restart is stable`() {
        val project = generatedProject()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        lateinit var acceptedId: String
        lateinit var acceptedSha256: String

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
            val candidate = project.resolve("src/modules/beta.c").readBytes() + "\n/* accepted beta */\n".toByteArray()
            acceptedSha256 = sha256(candidate)
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))
            val accepted = graph.accept(attempt, RepairEvidence("behavior", "retained cases matched", "reports/case.json"))
            acceptedId = accepted.id

            assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
            assertEquals(listOf("beta"), accepted.changedModules)
            assertEquals(listOf("alpha"), accepted.invalidatedModules)
            assertEquals(accepted.id, graph.snapshot.headId)
        }
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains(acceptedSha256))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains("repair-revision"))
        val graphBytes = graphPath.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(acceptedId, reopened.snapshot.headId)
            assertEquals(2, reopened.snapshot.nodes.size)
        }

        assertContentEquals(graphBytes, graphPath.readBytes())
    }

    @Test
    fun `restart recovers an installed pending candidate to the exact parent revision`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val acceptedBytes = target.readBytes()

        val interrupted = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val attempt = interrupted.beginAttempt(listOf("src/modules/alpha.c"))
        interrupted.installCandidate(
            attempt,
            mapOf("src/modules/alpha.c" to acceptedBytes + "\n/* interrupted candidate */\n".toByteArray()),
        )
        interrupted.close()
        assertFalse(target.readBytes().contentEquals(acceptedBytes))
        val legitimateRepairFile = project.resolve("src/modules/.legitimate.repair")
        legitimateRepairFile.writeText("user-owned repair notes")

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertContentEquals(acceptedBytes, target.readBytes())
            assertEquals("user-owned repair notes", legitimateRepairFile.readText())
            val node = recovered.snapshot.nodes.last()
            assertEquals(ModuleRevisionStatus.REJECTED, node.status)
            assertTrue(node.recoveredAfterCrash)
            assertEquals("crash-recovery", node.evidenceKind)
            assertEquals(recovered.snapshot.nodes.first().id, recovered.snapshot.headId)
        }
        val recoveredGraph = project.resolve("reports/repair-revisions/graph.json").readText()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        assertEquals(recoveredGraph, project.resolve("reports/repair-revisions/graph.json").readText())
    }

    @Test
    fun `opening the graph preserves arbitrary user-owned repair-suffixed files`() {
        val project = generatedProject()
        val notes = project.resolve("src/modules/.legitimate.repair")
        notes.writeText("keep these user notes byte-for-byte\n")
        val before = notes.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }

        assertContentEquals(before, notes.readBytes())
    }

    @Test
    fun `pre-candidate rejection preserves source identity metadata and bytes`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val beforeBytes = target.readBytes()
        val beforeAttributes = Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        val beforeMode = Files.getAttribute(target, "unix:mode", LinkOption.NOFOLLOW_LINKS)

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.reject(attempt, RepairEvidence("agent-error", "agent failed before candidate installation"))
        }

        val afterAttributes = Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        assertContentEquals(beforeBytes, target.readBytes())
        assertEquals(beforeAttributes.fileKey(), afterAttributes.fileKey())
        assertEquals(beforeAttributes.lastModifiedTime(), afterAttributes.lastModifiedTime())
        assertEquals(beforeMode, Files.getAttribute(target, "unix:mode", LinkOption.NOFOLLOW_LINKS))
    }

    @Test
    fun `declarative profile supports arbitrary source layout without C conventions`() {
        val project = createTempDirectory("repair-declarative-").resolve("project")
        project.resolve("code").createDirectories()
        project.resolve("config").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("code/unit.rs").writeText("pub fn answer() -> i32 { 41 }\n")
        project.resolve("config/build.toml").writeText("entry = \"code/unit.rs\"\n")
        project.resolve("reports/module_plan.json").writeText(
            "{\"modules\":[{\"id\":\"wrong\",\"sourcePath\":\"missing.c\",\"headerPath\":\"missing.h\"}]}",
        )
        project.resolve("reports/program_model.json").writeText(
            "{\"functions\":[{\"id\":\"wrong\",\"calls\":[\"missing\"]}]}",
        )
        val profile = DeclarativeRepairIndexProfile(
            "rust-layout-fixture-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/unit.rs", "config/build.toml"),
                editablePaths = listOf("code/unit.rs"),
                modules = listOf(
                    RepairModuleEvidence(
                        id = "rust_unit",
                        ownedPaths = listOf("code/unit.rs", "config/build.toml"),
                    ),
                ),
                sharedContextPaths = listOf("config/build.toml"),
                pathDependencies = mapOf(
                    "code/unit.rs" to emptyList(),
                    "config/build.toml" to listOf("code/unit.rs"),
                ),
                behaviorRootModuleIds = listOf("rust_unit"),
            ),
        )

        val index = ModuleRepairIndex.load(project, profile)
        val selection = index.select("compile", "config/build.toml:1: failure")
        assertEquals(listOf("rust_unit"), selection.seedModules)
        assertEquals(listOf("code/unit.rs"), selection.writablePaths)
        assertTrue("config/build.toml" in selection.readablePaths)
        ModuleRevisionGraph.open(project, profile).use { graph ->
            val attempt = graph.beginAttempt(selection.writablePaths)
            graph.installCandidate(attempt, mapOf("code/unit.rs" to "pub fn answer() -> i32 { 42 }\n".toByteArray()))
            graph.accept(attempt, RepairEvidence("valid", "layout-independent validation passed"))
        }
        assertEquals("pub fn answer() -> i32 { 42 }\n", project.resolve("code/unit.rs").readText())

        val wrongProfile = DeclarativeRepairIndexProfile(
            "rust-layout-fixture-v2",
            profile.resolve(project, RepairResourceBudget()),
        )
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, wrongProfile) }
    }

    @Test
    fun `compile selection requires exact ownership and never widens writable authority`() {
        val project = genericProject(
            "repair-exact-ownership-",
            mapOf(
                "code/unit.src" to "editable unit\n",
                "code/unrelated.src" to "unrelated editable\n",
                "config/only.cfg" to "read only owner\n",
                "config/unit.cfg" to "unit configuration\n",
            ),
        )
        val profile = DeclarativeRepairIndexProfile(
            "exact-ownership-v1",
            RepairIndexLayout(
                sourcePaths = listOf(
                    "code/unit.src",
                    "code/unrelated.src",
                    "config/only.cfg",
                    "config/unit.cfg",
                ),
                editablePaths = listOf("code/unit.src", "code/unrelated.src"),
                modules = listOf(
                    RepairModuleEvidence("read_only", listOf("config/only.cfg")),
                    RepairModuleEvidence("unit", listOf("code/unit.src", "config/unit.cfg")),
                    RepairModuleEvidence("unrelated", listOf("code/unrelated.src")),
                ),
            ),
        )
        val index = ModuleRepairIndex.load(project, profile)

        val selected = index.select("compile", "config/unit.cfg:1: failure")

        assertEquals(listOf("unit"), selected.seedModules)
        assertEquals(listOf("code/unit.src", "config/unit.cfg"), selected.readablePaths)
        assertEquals(listOf("code/unit.src"), selected.writablePaths)
        assertFalse("code/unrelated.src" in selected.readablePaths)
        val missing = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "aggregate tool failure with no indexed owner")
        }
        assertTrue(missing.message.orEmpty().contains("exact"))
        val readOnly = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "config/only.cfg: failure")
        }
        assertTrue(readOnly.message.orEmpty().contains("editable"))
    }

    @Test
    fun `profile failure ownership rejects unknown module IDs instead of dropping them`() {
        val project = genericProject("repair-unknown-owner-", mapOf("code/unit.src" to "unit\n"))
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/unit.src"),
            editablePaths = listOf("code/unit.src"),
            modules = listOf(RepairModuleEvidence("unit", listOf("code/unit.src"))),
        )
        val profile = object : RepairIndexProfile {
            override fun profileId() = "unknown-failure-owner-v1"
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget) = layout
            override fun failureOwnership(
                projectRoot: Path,
                sourceRevisionSha256: String,
                budget: RepairResourceBudget,
            ) = RepairFailureOwnership(listOf("missing_owner"))
        }
        val index = ModuleRepairIndex.load(project, profile)

        val failure = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "aggregate failure")
        }

        assertTrue(failure.message.orEmpty().contains("unknown modules"))
    }

    @Test
    fun `ambiguous diagnostic basenames fail closed instead of selecting multiple owners`() {
        val project = genericProject(
            "repair-ambiguous-diagnostic-",
            mapOf("first/unit.src" to "first\n", "second/unit.src" to "second\n"),
        )
        val profile = DeclarativeRepairIndexProfile(
            "ambiguous-diagnostic-v1",
            RepairIndexLayout(
                sourcePaths = listOf("first/unit.src", "second/unit.src"),
                editablePaths = listOf("first/unit.src", "second/unit.src"),
                modules = listOf(
                    RepairModuleEvidence("first", listOf("first/unit.src")),
                    RepairModuleEvidence("second", listOf("second/unit.src")),
                ),
            ),
        )
        val index = ModuleRepairIndex.load(project, profile)

        val failure = assertFailsWith<IllegalArgumentException> {
            index.select("compile", "unit.src: failure")
        }
        assertTrue(failure.message.orEmpty().contains("ambiguous"))
        assertEquals(
            listOf("first/unit.src"),
            index.select("compile", "first/unit.src: failure").writablePaths,
        )
    }

    @Test
    fun `exact indexed paths outrank raw tokens while ambiguous token evidence cannot widen writes`() {
        val project = genericProject(
            "repair-token-authority-",
            mapOf(
                "code/alpha + 한글.src" to "alpha\n",
                "code/beta.src" to "beta\n",
            ),
        )
        val profile = DeclarativeRepairIndexProfile(
            "token-authority-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/alpha + 한글.src", "code/beta.src"),
                editablePaths = listOf("code/alpha + 한글.src", "code/beta.src"),
                modules = listOf(
                    RepairModuleEvidence(
                        id = "alpha",
                        ownedPaths = listOf("code/alpha + 한글.src"),
                        entityIds = listOf("entity_alpha"),
                    ),
                    RepairModuleEvidence(
                        id = "beta",
                        ownedPaths = listOf("code/beta.src"),
                        entityIds = listOf("entity_beta"),
                    ),
                ),
                entities = listOf(
                    RepairEntityEvidence("entity_alpha", listOf("shared_token", "token_alpha")),
                    RepairEntityEvidence("entity_beta", listOf("alpha", "shared_token", "token_beta")),
                ),
            ),
        )
        val index = ModuleRepairIndex.load(project, profile)

        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                index.select("compile", "shared_token")
            }.message.orEmpty().contains("ambiguous"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                index.select("compile", "token_alpha token_beta")
            }.message.orEmpty().contains("multiple"),
        )
        assertTrue(
            assertFailsWith<IllegalArgumentException> {
                index.select("compile", "alpha")
            }.message.orEmpty().contains("ambiguous"),
        )

        val exact = index.select(
            "compile",
            "code/alpha + 한글.src:1: error: shared_token token_beta",
        )
        assertEquals(listOf("alpha"), exact.seedModules)
        assertEquals(listOf("code/alpha + 한글.src"), exact.writablePaths)
        assertFalse("code/beta.src" in exact.readablePaths)

        val exactMultiFile = index.select(
            "compile",
            "code/alpha + 한글.src:1: error: first\ncode/beta.src:2: error: second",
        )
        assertEquals(listOf("alpha", "beta"), exactMultiFile.seedModules)
        assertEquals(listOf("code/alpha + 한글.src", "code/beta.src"), exactMultiFile.writablePaths)
    }

    @Test
    fun `profile transformed diagnostics are rebound before indexing`() {
        val project = genericProject("repair-filtered-diagnostic-budget-", mapOf("code/unit.src" to "unit\n"))
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/unit.src"),
            editablePaths = listOf("code/unit.src"),
            modules = listOf(RepairModuleEvidence("unit", listOf("code/unit.src"))),
        )
        val profile = object : RepairIndexProfile {
            override fun profileId() = "filtered-diagnostic-budget-v1"
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget) = layout
            override fun diagnosticEvidence(hint: String) = "x".repeat(9)
        }
        val index = ModuleRepairIndex.load(
            project,
            profile,
            RepairResourceBudget(maximumDiagnosticCharacters = 8),
        )

        val failure = assertFailsWith<RepairBudgetExceededException> {
            index.select("compile", "x")
        }

        assertTrue(failure.message.orEmpty().contains("profile-filtered"))
    }

    @Test
    fun `shared readable context grants writes only through explicit invalidation ownership`() {
        val project = genericProject("repair-shared-authority-", mapOf("config/shared.cfg" to "shared\n"))
        fun profile(id: String, layout: RepairIndexLayout) = object : RepairIndexProfile {
            override fun profileId() = id
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget) = layout
            override fun failureOwnership(
                projectRoot: Path,
                sourceRevisionSha256: String,
                budget: RepairResourceBudget,
            ) = RepairFailureOwnership(includesSharedContext = true)
        }
        val readOnlyShared = profile(
            "shared-read-only-v1",
            RepairIndexLayout(
                sourcePaths = listOf("config/shared.cfg"),
                editablePaths = listOf("config/shared.cfg"),
                sharedContextPaths = listOf("config/shared.cfg"),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, readOnlyShared).select("compile", "aggregate failure")
        }

        val explicitlyInvalidating = profile(
            "shared-invalidation-v1",
            RepairIndexLayout(
                sourcePaths = listOf("config/shared.cfg"),
                editablePaths = listOf("config/shared.cfg"),
                sharedContextPaths = listOf("config/shared.cfg"),
                sharedInvalidationPaths = listOf("config/shared.cfg"),
            ),
        )
        val selection = ModuleRepairIndex.load(project, explicitlyInvalidating)
            .select("compile", "aggregate failure")
        assertEquals(emptyList(), selection.seedModules)
        assertEquals(listOf("config/shared.cfg"), selection.readablePaths)
        assertEquals(listOf("config/shared.cfg"), selection.writablePaths)
    }

    @Test
    fun `fallback IDs and declared behavior roots must resolve exactly`() {
        val sources = listOf("code/a.src", "code/b.src")
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                modules = listOf(RepairModuleEvidence("explicit", listOf("code/a.src"))),
                fallbackModuleIdsByPath = mapOf("code/a.src" to "fallback"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                fallbackModuleIdsByPath = mapOf("code/a.src" to "same", "code/b.src" to "same"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                modules = listOf(RepairModuleEvidence("claimed", listOf("code/a.src"))),
                fallbackModuleIdsByPath = mapOf("code/b.src" to "claimed"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                sharedContextPaths = listOf("code/a.src"),
                fallbackModuleIdsByPath = mapOf("code/a.src" to "shared_context_fallback"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                sharedInvalidationPaths = listOf("code/a.src"),
                fallbackModuleIdsByPath = mapOf("code/a.src" to "shared_fallback"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                behaviorRootModuleIds = listOf("unknown_root"),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                behaviorRootEntityIds = listOf("unknown_entity"),
            )
        }

        val declared = RepairIndexLayout(
            sourcePaths = listOf("code/a.src"),
            editablePaths = listOf("code/a.src"),
            fallbackModuleIdsByPath = mapOf("code/a.src" to "declared_root"),
            behaviorRootModuleIds = listOf("declared_root"),
        )
        assertEquals(listOf("declared_root"), declared.behaviorRootModuleIds)
    }

    @Test
    fun `partial ownership requires complete explicit fallback coverage`() {
        val project = genericProject(
            "repair-explicit-fallback-",
            mapOf("code/a.src" to "owned\n", "code/b.src" to "fallback\n"),
        )
        val incomplete = DeclarativeRepairIndexProfile(
            "incomplete-fallback-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src", "code/b.src"),
                editablePaths = listOf("code/a.src", "code/b.src"),
                modules = listOf(RepairModuleEvidence("explicit_a", listOf("code/a.src"))),
            ),
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, incomplete)
        }
        assertTrue(failure.message.orEmpty().contains("explicitly and exactly"))

        val complete = DeclarativeRepairIndexProfile(
            "complete-fallback-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src", "code/b.src"),
                editablePaths = listOf("code/a.src", "code/b.src"),
                modules = listOf(RepairModuleEvidence("explicit_a", listOf("code/a.src"))),
                fallbackModuleIdsByPath = mapOf("code/b.src" to "declared_b"),
            ),
        )
        val index = ModuleRepairIndex.load(project, complete)
        assertEquals(listOf("declared_b", "explicit_a"), index.moduleIds)
        assertEquals(listOf("declared_b"), index.select("compile", "code/b.src: failure").seedModules)
    }

    @Test
    fun `generated C fallback roots do not collide with explicitly owned entry sources`() {
        val project = genericProject(
            "repair-generated-entry-owner-",
            mapOf(
                "Makefile" to "all:\n\t@true\n",
                "include/decomp_types.h" to "#pragma once\n",
                "include/main.h" to "#pragma once\nint main(void);\n",
                "src/main.c" to "#include \"main.h\"\nint main(void) { return 0; }\n",
                "reports/module_plan.json" to
                    "{\"schemaVersion\":1,\"modules\":[{\"id\":\"owned_entry\"," +
                    "\"sourcePath\":\"src/main.c\",\"headerPath\":\"include/main.h\"," +
                    "\"functionIds\":[\"fn_main\"],\"globalIds\":[],\"boundaryEvidence\":[]}]," +
                    "\"dependencyCycles\":[]}",
                "reports/program_model.json" to
                    "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[{" +
                    "\"id\":\"fn_main\",\"name\":\"main\",\"address\":\"0x1\"," +
                    "\"prototype\":\"int main(void)\",\"status\":\"recovered\",\"calls\":[]," +
                    "\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}]," +
                    "\"globals\":[],\"types\":[]}",
            ),
        )

        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        val selection = index.select("behavior", "")

        assertEquals(listOf("owned_entry"), selection.seedModules)
        assertFalse("entrypoint" in index.moduleIds)
        assertEquals(listOf("include/main.h", "src/main.c"), selection.writablePaths)
    }

    @Test
    fun `present generated C index evidence requires its complete versioned shape`() {
        val project = minimalGeneratedCProject(
            "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[{" +
                "\"id\":\"fn_main\",\"name\":\"main\",\"address\":\"0x1\"," +
                "\"prototype\":\"int main(void)\",\"status\":\"recovered\"," +
                "\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}]," +
                "\"globals\":[],\"types\":[]}",
        )

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        }

        assertTrue(failure.message.orEmpty().contains("calls"))
    }

    @Test
    fun `generated C nested evidence is structurally bounded before collection transforms`() {
        val project = minimalGeneratedCProject(
            "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[{" +
                "\"id\":\"fn_main\",\"name\":\"main\",\"address\":\"0x1\"," +
                "\"prototype\":\"int main(void)\",\"status\":\"recovered\"," +
                "\"calls\":[\"fn_main\",\"fn_main\"],\"referencedGlobals\":[]," +
                "\"strings\":[],\"decompiledC\":null}],\"globals\":[],\"types\":[]}",
        )

        val failure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                GeneratedCRepairIndexProfile,
                RepairResourceBudget(maximumDependencyEdges = 2),
            )
        }

        assertTrue(failure.message.orEmpty().contains("structural entries"))
    }

    @Test
    fun `behavior selection requires explicit roots and keeps the declared frontier exact`() {
        val project = genericProject(
            "repair-behavior-roots-",
            mapOf(
                "code/dep.src" to "dependency\n",
                "code/isolated.src" to "disconnected\n",
                "code/root.src" to "root\n",
            ),
        )
        val modules = listOf(
            RepairModuleEvidence("dep", listOf("code/dep.src"), dependencyModuleIds = listOf("root")),
            RepairModuleEvidence("isolated", listOf("code/isolated.src")),
            RepairModuleEvidence("root", listOf("code/root.src"), dependencyModuleIds = listOf("dep")),
        )
        val sources = listOf("code/dep.src", "code/isolated.src", "code/root.src")
        val withoutRoots = DeclarativeRepairIndexProfile(
            "behavior-no-roots-v1",
            RepairIndexLayout(sourcePaths = sources, editablePaths = sources, modules = modules),
        )

        val noRootFailure = assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(project, withoutRoots).select("behavior", "")
        }
        assertTrue(noRootFailure.message.orEmpty().contains("explicit profile-declared roots"))

        val withRoot = DeclarativeRepairIndexProfile(
            "behavior-explicit-root-v1",
            RepairIndexLayout(
                sourcePaths = sources,
                editablePaths = sources,
                modules = modules,
                behaviorRootModuleIds = listOf("root"),
            ),
        )
        val index = ModuleRepairIndex.load(project, withRoot)
        val frontier = index.select("behavior", "")
        assertEquals(listOf("root"), frontier.seedModules)
        assertEquals(listOf("dep"), frontier.dependencyModules)
        assertEquals(listOf("code/root.src"), frontier.writablePaths)
        assertTrue("code/dep.src" in frontier.readablePaths)
        assertFalse("code/dep.src" in frontier.writablePaths)
        assertFalse("code/isolated.src" in frontier.readablePaths)

        val diagnosed = index.select("behavior", "code/dep.src: mismatch")
        assertEquals(listOf("dep"), diagnosed.seedModules)
        assertEquals(listOf("code/dep.src"), diagnosed.writablePaths)
        assertTrue("code/root.src" in diagnosed.readablePaths)
    }

    @Test
    fun `layout canonicalization is bounded after structural count preflight`() {
        val project = genericProject(
            "repair-layout-budget-",
            mapOf("code/a.src" to "a\n", "code/b.src" to "b\n"),
        )
        val oneModule = DeclarativeRepairIndexProfile(
            "canonical-budget-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src"),
                editablePaths = listOf("code/a.src"),
                modules = listOf(RepairModuleEvidence("a", listOf("code/a.src"))),
            ),
        )
        val canonicalFailure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                oneModule,
                RepairResourceBudget(maximumIndexEvidenceBytes = 64),
            )
        }
        assertTrue(canonicalFailure.message.orEmpty().contains("canonical bytes"))

        val twoModules = DeclarativeRepairIndexProfile(
            "count-before-canonical-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.src", "code/b.src"),
                editablePaths = listOf("code/a.src", "code/b.src"),
                modules = listOf(
                    RepairModuleEvidence("a", listOf("code/a.src")),
                    RepairModuleEvidence("b", listOf("code/b.src")),
                ),
            ),
        )
        val countFailure = assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                twoModules,
                RepairResourceBudget(
                    maximumIndexedModules = 1,
                    maximumIndexEvidenceBytes = 1,
                    maximumContextModules = 1,
                ),
            )
        }
        assertTrue(countFailure.message.orEmpty().contains("2 modules"))
    }

    @Test
    fun `begin attempt preflights aggregate preimage bytes before retaining captured bodies`() {
        val project = genericProject(
            "repair-preimage-preflight-",
            mapOf("code/a.bin" to "a".repeat(40), "code/b.bin" to "b".repeat(40)),
        )
        val profile = DeclarativeRepairIndexProfile(
            "preimage-preflight-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/a.bin", "code/b.bin"),
                editablePaths = listOf("code/a.bin", "code/b.bin"),
            ),
        )
        val budget = RepairResourceBudget(
            maximumContextBytes = 64,
            maximumStagingBytes = 64,
            maximumPatchBytes = 64,
        )
        var preimageRead = false
        ModuleRevisionGraph.openForTesting(
            project,
            profile,
            budget,
            ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) preimageRead = true
            },
        ).use { graph ->
            val oversizedWithoutSafeIteration = object : AbstractCollection<String>() {
                override val size: Int = 257
                override fun iterator(): Iterator<String> = error("oversized path collection was iterated")
            }
            assertFailsWith<RepairBudgetExceededException> {
                graph.beginAttempt(oversizedWithoutSafeIteration)
            }
            val failure = assertFailsWith<RepairBudgetExceededException> {
                graph.beginAttempt(listOf("code/a.bin", "code/b.bin"))
            }
            assertTrue(failure.message.orEmpty().contains("80 bytes"))
            assertFalse(preimageRead)
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }
        assertEquals("a".repeat(40), project.resolve("code/a.bin").readText())
        assertEquals("b".repeat(40), project.resolve("code/b.bin").readText())
    }

    @Test
    fun `startup restores a dirty candidate before invoking a content-sensitive profile`() {
        val project = createTempDirectory("repair-content-profile-").resolve("project")
        project.resolve("code").createDirectories()
        val source = project.resolve("code/program.bin")
        val parent = byteArrayOf(1, 3, 5, 7)
        val candidate = byteArrayOf(2, 4, 6, 8)
        source.writeBytes(parent)
        val profile = object : RepairIndexProfile {
            override fun profileId() = "content-sensitive-binary-v1"
            override fun configurationSha256() = "7".repeat(64)
            override fun authorizesRecoveryLayout(
                sourcePaths: List<String>,
                editablePaths: List<String>,
                budget: RepairResourceBudget,
            ) = sourcePaths == listOf("code/program.bin") && editablePaths == sourcePaths
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout {
                require(!projectRoot.resolve("code/program.bin").readBytes().contentEquals(candidate)) {
                    "profile cannot resolve a dirty candidate"
                }
                return RepairIndexLayout(
                    sourcePaths = listOf("code/program.bin"),
                    editablePaths = listOf("code/program.bin"),
                    fallbackModuleIdsByPath = mapOf("code/program.bin" to "program"),
                )
            }
        }
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            profile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationMove && point.phase == "candidate") {
                    throw SimulatedRepairCrash()
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("code/program.bin"))
        assertFailsWith<SimulatedRepairCrash> {
            graph.installCandidate(attempt, mapOf("code/program.bin" to candidate))
        }
        graph.close()
        assertContentEquals(candidate, source.readBytes())

        ModuleRevisionGraph.open(project, profile).use { recovered ->
            assertContentEquals(parent, source.readBytes())
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `pending recovery remains valid when staging budget is below context budget`() {
        val project = createTempDirectory("repair-staging-context-recovery-").resolve("project")
        project.resolve("code").createDirectories()
        val source = project.resolve("code/program.bin")
        val parent = byteArrayOf(1, 2, 3, 4)
        val candidate = byteArrayOf(5, 6, 7, 8)
        source.writeBytes(parent)
        val profile = DeclarativeRepairIndexProfile(
            "staging-below-context-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/program.bin"),
                editablePaths = listOf("code/program.bin"),
            ),
        )
        val budget = RepairResourceBudget(
            maximumContextBytes = 16,
            maximumStagingBytes = 8,
            maximumPatchBytes = 8,
        )
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            profile,
            budget,
            ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterPublicationMove && point.phase == "candidate") {
                    throw SimulatedRepairCrash()
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("code/program.bin"))
        assertFailsWith<SimulatedRepairCrash> {
            graph.installCandidate(attempt, mapOf("code/program.bin" to candidate))
        }
        graph.close()
        assertContentEquals(candidate, source.readBytes())

        ModuleRevisionGraph.open(project, profile, budget).use { recovered ->
            assertContentEquals(parent, source.readBytes())
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `identical repairs produce byte-identical revision graphs in different roots`() {
        val first = generatedProject()
        val second = generatedProject()

        listOf(first, second).forEach { project ->
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
                val before = project.resolve("src/modules/beta.c").readBytes()
                graph.installCandidate(
                    attempt,
                    mapOf("src/modules/beta.c" to before + "\n/* portable candidate */\n".toByteArray()),
                )
                graph.accept(attempt, RepairEvidence("behavior", "same evidence", project.resolve("reports/result.json").toString()))
            }
        }

        assertContentEquals(
            first.resolve("reports/repair-revisions/graph.json").readBytes(),
            second.resolve("reports/repair-revisions/graph.json").readBytes(),
        )
        assertContentEquals(
            first.resolve("source_tree_manifest.json").readBytes(),
            second.resolve("source_tree_manifest.json").readBytes(),
        )
    }

    @Test
    fun `out-of-band source edits cannot be attached to the accepted graph head`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        val graphBytes = project.resolve("reports/repair-revisions/graph.json").readBytes()
        val alpha = project.resolve("src/modules/alpha.c")
        alpha.writeBytes(alpha.readBytes() + "\n/* unbound external edit */\n".toByteArray())

        val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile) }

        assertTrue(failure.message.orEmpty().contains("do not match revision graph head"))
        assertContentEquals(graphBytes, project.resolve("reports/repair-revisions/graph.json").readBytes())
    }

    @Test
    fun `source inputs added after indexing cannot enter an atomic attempt`() {
        val project = generatedProject()
        val added = project.resolve("src/modules/unbound.c")

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            added.writeText("int unbound(void) { return 0; }\n")

            val failure = assertFailsWith<IllegalArgumentException> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }

            assertTrue(failure.message.orEmpty().contains("source input set changed"))
        }
    }

    @Test
    fun `local include dependencies drive minimal context and downstream invalidation`() {
        val project = dependencyOnlyProject(includeDependency = true, globalDependency = false)
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)

        val selection = index.select("compile", "src/modules/consumer.c:3: error: invalid expression")

        assertEquals(listOf("consumer"), selection.seedModules)
        assertEquals(listOf("provider"), selection.dependencyModules)
        assertTrue("include/modules/provider.h" in selection.readablePaths)
        assertEquals(listOf("consumer"), index.downstreamInvalidations(listOf("src/modules/provider.c")))
    }

    @Test
    fun `referenced global ownership drives dependencies without a function call or include`() {
        val project = dependencyOnlyProject(includeDependency = false, globalDependency = true)
        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)

        val selection = index.select("compile", "src/modules/consumer.c:3: error: invalid expression")

        assertEquals(listOf("consumer"), selection.seedModules)
        assertEquals(listOf("provider"), selection.dependencyModules)
        assertEquals(listOf("consumer"), index.downstreamInvalidations(listOf("src/modules/provider.c")))
    }

    @Test
    fun `unknown semantic references are rejected instead of silently dropped`() {
        val project = dependencyOnlyProject(includeDependency = false, globalDependency = true)
        val model = project.resolve("reports/program_model.json")
        model.writeText(model.readText().replace("\"referencedGlobals\":[\"global_state\"]", "\"referencedGlobals\":[\"missing_global\"]"))

        val failure = assertFailsWith<IllegalArgumentException> { ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile) }

        assertTrue(failure.message.orEmpty().contains("unknown global"))
    }

    @Test
    fun `candidate that changes include dependency evidence is restored and rejected`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val before = target.readBytes()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
            val candidate = "#include \"modules/delta.h\"\n" + target.readText()
            val failure = assertFailsWith<IllegalArgumentException> {
                graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate.toByteArray()))
            }
            assertTrue(failure.message.orEmpty().contains("dependency evidence"))
            graph.reject(attempt, RepairEvidence("dependency-change", failure.message.orEmpty()))
        }

        assertContentEquals(before, target.readBytes())
    }

    @Test
    fun `candidate publication CAS preserves a concurrent replacement at the commit gap`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val held = project.resolve("src/modules/.alpha-original.repair")
        val parent = target.readBytes()
        val concurrent = parent + "\n/* concurrent external replacement */\n".toByteArray()
        val candidate = parent + "\n/* graph candidate */\n".toByteArray()
        var injected = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                    point.phase == "candidate" && point.path == "src/modules/alpha.c"
                ) {
                    Files.move(target, held)
                    target.writeBytes(concurrent)
                    injected = true
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))

        val failure = assertFailsWith<IllegalArgumentException> {
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        }

        assertTrue(failure.message.orEmpty().contains("exchange") || failure.suppressed.isNotEmpty())
        assertContentEquals(concurrent, target.readBytes())
        Files.delete(target)
        Files.move(held, target)
        graph.reject(attempt, RepairEvidence("cas-conflict", "concurrent candidate publication rejected"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `rollback publication CAS preserves a concurrent replacement at the commit gap`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val held = project.resolve("src/modules/.alpha-candidate.repair")
        val parent = target.readBytes()
        val candidate = parent + "\n/* graph candidate */\n".toByteArray()
        val concurrent = parent + "\n/* concurrent rollback replacement */\n".toByteArray()
        var injected = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point is ModuleRevisionFaultPoint.BeforePublicationExchange &&
                    point.phase == "rollback" && point.path == "src/modules/alpha.c"
                ) {
                    Files.move(target, held)
                    target.writeBytes(concurrent)
                    injected = true
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))

        assertFailsWith<IllegalArgumentException> {
            graph.reject(attempt, RepairEvidence("test", "exercise rollback CAS"))
        }

        assertContentEquals(concurrent, target.readBytes())
        Files.delete(target)
        Files.move(held, target)
        graph.reject(attempt, RepairEvidence("cas-conflict", "concurrent rollback publication rejected"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `CAS compensation preserves a replacement introduced at the actual rollback exchange gap`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val heldCandidate = project.resolve("src/modules/alpha.concurrent-held")
        val parent = target.readBytes()
        val candidate = parent + "\n/* graph candidate */\n".toByteArray()
        val concurrent = parent + "\n/* concurrent final-gap replacement */\n".toByteArray()
        var forceRollback = true
        var racedRollback = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                when {
                    forceRollback && point is ModuleRevisionFaultPoint.AfterPublicationExchange &&
                        point.phase == "candidate" && point.path == "src/modules/alpha.c" -> {
                        forceRollback = false
                        throw IllegalStateException("force publication rollback")
                    }
                    !racedRollback && point is ModuleRevisionFaultPoint.BeforeRollbackExchange &&
                        point.phase == "candidate" && point.path == "src/modules/alpha.c" -> {
                        Files.move(target, heldCandidate)
                        target.writeBytes(concurrent)
                        racedRollback = true
                    }
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))

        val failure = assertFailsWith<IllegalStateException> {
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        }

        assertTrue(racedRollback)
        assertTrue(failure.suppressed.isNotEmpty())
        assertContentEquals(concurrent, target.readBytes())
        assertContentEquals(candidate, heldCandidate.readBytes())
        val journal = Files.list(target.parent).use { entries ->
            entries.iterator().asSequence().single {
                val name = it.fileName.toString()
                name.startsWith(".alpha.c.") && name.endsWith(".repair")
            }
        }
        assertContentEquals(parent, journal.readBytes())

        Files.delete(target)
        Files.move(journal, target)
        Files.delete(heldCandidate)
        graph.reject(attempt, RepairEvidence("cas-conflict", "rollback gap replacement was preserved"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `forged pending preimage is rejected before any source mutation`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val beforeBytes = target.readBytes()
        val beforeKey = Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        graph.beginAttempt(listOf("src/modules/alpha.c"))
        graph.close()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val payload = graphPath.readText()
        val pendingOffset = payload.indexOf("\"pending\": {")
        assertTrue(pendingOffset >= 0)
        val prefix = payload.substring(0, pendingOffset)
        val pending = payload.substring(pendingOffset)
        val originalDigest = Regex("\"beforeSha256\":\"([0-9a-f]{64})\"")
            .find(pending)?.groupValues?.get(1) ?: error("pending preimage digest missing")
        val otherDigest = Regex("\"afterSha256\":\"([0-9a-f]{64})\"")
            .findAll(prefix).map { it.groupValues[1] }.first { it != originalDigest }
        graphPath.writeText(pending.replaceFirst(originalDigest, otherDigest).let(prefix::plus))

        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }

        assertContentEquals(beforeBytes, target.readBytes())
        assertEquals(beforeKey, Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
    }

    @Test
    fun `self-consistent graph paths outside the current profile cannot trigger recovery writes`() {
        val project = createTempDirectory("repair-forged-layout-").resolve("project")
        project.resolve("code").createDirectories()
        project.resolve("code/main.txt").writeText("main\n")
        val privatePath = project.resolve("private.txt")
        privatePath.writeText("private parent\n")
        val profileId = "layout-binding-test-v1"
        val profileSha = "b".repeat(64)
        val graphLayout = RepairIndexLayout(
            sourcePaths = listOf("code/main.txt", "private.txt"),
            editablePaths = listOf("code/main.txt", "private.txt"),
            fallbackModuleIdsByPath = mapOf(
                "code/main.txt" to "main",
                "private.txt" to "private",
            ),
        )
        val currentLayout = RepairIndexLayout(
            sourcePaths = listOf("code/main.txt"),
            editablePaths = listOf("code/main.txt"),
            fallbackModuleIdsByPath = mapOf("code/main.txt" to "main"),
        )
        fun profile(layout: RepairIndexLayout) = object : RepairIndexProfile {
            override fun profileId(): String = profileId
            override fun configurationSha256(): String = profileSha
            override fun authorizesRecoveryLayout(
                sourcePaths: List<String>,
                editablePaths: List<String>,
                budget: RepairResourceBudget,
            ) = sourcePaths == layout.sourcePaths && editablePaths == layout.editablePaths
            override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout = layout
        }
        val graph = ModuleRevisionGraph.open(project, profile(graphLayout))
        val attempt = graph.beginAttempt(listOf("private.txt"))
        val candidate = "forged graph candidate\n".toByteArray()
        graph.installCandidate(attempt, mapOf("private.txt" to candidate))
        graph.close()
        val candidateKey = Files.readAttributes(
            privatePath,
            BasicFileAttributes::class.java,
            LinkOption.NOFOLLOW_LINKS,
        ).fileKey()

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, profile(currentLayout))
        }

        assertTrue(failure.message.orEmpty().contains("source paths"))
        assertContentEquals(candidate, privatePath.readBytes())
        assertEquals(
            candidateKey,
            Files.readAttributes(privatePath, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey(),
        )
    }

    @Test
    fun `duplicate unknown and noncanonical graph encodings fail closed without source mutation`() {
        listOf<(String) -> String>(
            { canonical -> canonical.replaceFirst("\"schemaVersion\": 2,", "\"schemaVersion\": 2,\n  \"schemaVersion\": 2,") },
            { canonical -> canonical.replaceFirst("\"schemaVersion\": 2,", "\"schemaVersion\": 2,\n  \"unexpected\": true,") },
            { canonical -> " \n$canonical" },
        ).forEach { tamper ->
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val before = target.readBytes()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            graphPath.writeText(tamper(graphPath.readText()))

            assertFailsWith<IllegalArgumentException> {
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
            }

            assertContentEquals(before, target.readBytes())
        }
    }

    @Test
    fun `legacy schema graph remains readable but cannot begin an agent repair`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(
            graphPath.readText().replaceFirst("\"schemaVersion\": 2,", "\"schemaVersion\": 1,"),
        )

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            assertEquals(1, graph.snapshot.schemaVersion)
            val corpus = graph.retainedRegressionCorpus()
            val failure = assertFailsWith<IllegalArgumentException> {
                graph.beginAttempt(
                    listOf("src/modules/alpha.c"),
                    RevisionRepairMetadata(
                        1,
                        "compile",
                        "legacy compatibility must not create a release record",
                        null,
                        emptyList(),
                        null,
                        corpus.sha256,
                    ),
                )
            }
            assertTrue(failure.message.orEmpty().contains("non-release"))
        }
    }

    @Test
    fun `unbound extra ACP receipt cannot enter repair history`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        project.resolve("reports/repair-revisions/revision_stale.acp-receipt.json")
            .writeText("{}\n")

        val failure = assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }

        assertTrue(failure.message.orEmpty().contains("extra, or stale"))
    }

    @Test
    fun `accept revalidates current dependency evidence before persisting the head`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val parent = target.readBytes()
        val candidate = parent + "\n/* candidate */\n".toByteArray()
        val model = project.resolve("reports/program_model.json")
        val originalEvidence = model.readText()
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
        graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))
        model.writeText(originalEvidence.replaceFirst("alpha_run", "alpha_run_changed"))

        val failure = assertFailsWith<IllegalArgumentException> {
            graph.accept(attempt, RepairEvidence("valid", "must not commit stale index evidence"))
        }

        assertTrue(failure.message.orEmpty().contains("evidence"))
        assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        model.writeText(originalEvidence)
        graph.reject(attempt, RepairEvidence("evidence-changed", "fresh index rejected the candidate"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `accept repeats full evidence validation at the final head commit boundary`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/beta.c")
        val parent = target.readBytes()
        val model = project.resolve("reports/program_model.json")
        val originalEvidence = model.readText()
        var injected = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (!injected && point == ModuleRevisionFaultPoint.AfterHeadIndexValidation) {
                    model.writeText(originalEvidence.replaceFirst("alpha_run", "alpha_commit_gap"))
                    injected = true
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
        graph.installCandidate(
            attempt,
            mapOf("src/modules/beta.c" to (parent + "\n/* candidate */\n".toByteArray())),
        )

        assertFailsWith<IllegalArgumentException> {
            graph.accept(attempt, RepairEvidence("valid", "must not commit across stale evidence"))
        }

        assertTrue(injected)
        assertEquals(graph.snapshot.nodes.first().id, graph.snapshot.headId)
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        model.writeText(originalEvidence)
        graph.reject(attempt, RepairEvidence("evidence-changed", "final index validation rejected the candidate"))
        graph.close()
        assertContentEquals(parent, target.readBytes())
    }

    @Test
    fun `oversized metadata is rejected before canonical graph persistence and remains reopenable`() {
        val budget = RepairResourceBudget(
            maximumRegressionInputBytes = 32,
            maximumRequestBytes = 64,
        )
        run {
            val project = generatedProject()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val before = project.resolve("reports/repair-revisions/graph.json").readBytes()
                val corpus = graph.retainedRegressionCorpus()
                assertFailsWith<IllegalArgumentException> {
                    graph.beginAttempt(
                        listOf("src/modules/alpha.c"),
                        RevisionRepairMetadata(1, "compile", "x".repeat(65), null, emptyList(), null, corpus.sha256),
                    )
                }
                assertContentEquals(before, project.resolve("reports/repair-revisions/graph.json").readBytes())
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        }
        run {
            val project = generatedProject()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                val attempt = graph.beginAttempt(
                    listOf("src/modules/alpha.c"),
                    RevisionRepairMetadata(1, "compile", "short", null, emptyList(), null, corpus.sha256),
                )
                val before = project.resolve("reports/repair-revisions/graph.json").readBytes()
                assertFailsWith<IllegalArgumentException> { graph.annotateAttempt(attempt, "s".repeat(65)) }
                assertContentEquals(before, project.resolve("reports/repair-revisions/graph.json").readBytes())
                graph.reject(attempt, RepairEvidence("rejected", "bounded"))
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        }
        run {
            val project = generatedProject()
            val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            val before = project.resolve("reports/repair-revisions/graph.json").readBytes()
            assertFailsWith<IllegalArgumentException> {
                graph.reject(attempt, RepairEvidence("rejected", "e".repeat(65)))
            }
            assertContentEquals(before, project.resolve("reports/repair-revisions/graph.json").readBytes())
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        }
    }

    @Test
    fun `forged root projection cannot trigger pending recovery writes`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        val candidate = target.readBytes() + "\n/* pending */\n".toByteArray()
        graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
        graph.close()
        val candidateKey = Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText(graphPath.readText().replaceFirst("\"changedModules\": []", "\"changedModules\": [\"forged\"]"))

        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        }

        assertContentEquals(candidate, target.readBytes())
        assertEquals(candidateKey, Files.readAttributes(target, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS).fileKey())
    }

    @Test
    fun `repair profiles cannot claim graph-owned source or projection paths`() {
        listOf(
            "source_tree_manifest.json",
            "reports/source_revisions.jsonl",
            "reports/repair_history.json",
            "reports/repair-revisions/graph.json",
        ).forEach { reserved ->
            assertFailsWith<IllegalArgumentException> {
                RepairIndexLayout(sourcePaths = listOf(reserved), editablePaths = listOf(reserved))
            }
        }
    }

    @Test
    fun `independent graph owners merge and persist a deterministic full regression corpus`() {
        val first = generatedProject()
        val second = generatedProject()
        listOf(first, second).forEachIndexed { index, project ->
            val batches = if (index == 0) {
                listOf(listOf(ProcessInput("z", listOf("2"), byteArrayOf(2))), listOf(ProcessInput("a", stdin = byteArrayOf(1))))
            } else {
                listOf(listOf(ProcessInput("a", stdin = byteArrayOf(1))), listOf(ProcessInput("z", listOf("2"), byteArrayOf(2))))
            }
            batches.forEach { batch ->
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                    graph.retainRegressionInputs(batch)
                }
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                assertEquals(listOf("a", "z"), corpus.inputs.map { it.id })
                assertEquals(corpus.sha256, graph.snapshot.regressionCorpusSha256)
            }
        }
        assertContentEquals(
            first.resolve("reports/repair-revisions/graph.json").readBytes(),
            second.resolve("reports/repair-revisions/graph.json").readBytes(),
        )
    }

    @Test
    fun `regression corpus bounds empty case and argv structural amplification before persistence`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(
            maximumRegressionInputs = 2,
            maximumRegressionArguments = 2,
        )
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val before = graphPath.readBytes()

            assertFailsWith<RepairBudgetExceededException> {
                graph.retainRegressionInputs(listOf(ProcessInput("a"), ProcessInput("b"), ProcessInput("c")))
            }
            assertContentEquals(before, graphPath.readBytes())
            assertFailsWith<RepairBudgetExceededException> {
                graph.retainRegressionInputs(listOf(ProcessInput("a", listOf("", "", ""))))
            }
            assertContentEquals(before, graphPath.readBytes())
            assertTrue(graph.retainedRegressionCorpus().inputs.isEmpty())
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
    }

    @Test
    fun `history projection fails from aggregate accounting before decoding retained blobs`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumProjectionBytes = 512)
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
        val corpus = graph.retainedRegressionCorpus()
        val unrelated = graph.snapshot.nodes.first().changes.single { it.path == "src/modules/delta.c" }
        val digest = unrelated.afterBlobSha256
        val blob = project.resolve("reports/repair-revisions/blobs/$digest")
        val originalBlob = blob.readBytes()
        blob.writeText("corrupt only after graph open")

        val failure = assertFailsWith<RepairBudgetExceededException> {
            graph.beginAttempt(
                listOf("src/modules/alpha.c"),
                RevisionRepairMetadata(1, "compile", "bounded", null, emptyList(), null, corpus.sha256),
            )
        }

        assertTrue(failure.message.orEmpty().contains("projection"))
        assertEquals(null, graph.snapshot.pendingAttemptId)
        blob.writeBytes(originalBlob)
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
    }

    @Test
    fun `compatibility log emits one bounded evidence record for a multi-file revision`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
            val attempt = graph.beginAttempt(paths)
            graph.installCandidate(
                attempt,
                paths.associateWith { path -> project.resolve(path).readBytes() + "\n/* candidate */\n".toByteArray() },
            )
            graph.reject(attempt, RepairEvidence("compile", "one revision-level evidence value"))
            graph.synchronizeCompatibilityLog()
        }

        val record = project.resolve("reports/source_revisions.jsonl").readLines().single()
        assertEquals(1, Regex("\\\"evidenceKind\\\"").findAll(record).count())
        assertEquals(2, Regex("\\\"path\\\"").findAll(record).count())
        assertTrue(record.contains("\"changes\":["))
    }

    @Test
    fun `pending recovery enforces context and patch cardinality before source restoration`() {
        val project = generatedProject()
        val highBudget = RepairResourceBudget(maximumContextFiles = 2, maximumPatchFiles = 2)
        val lowBudget = RepairResourceBudget(maximumContextFiles = 1, maximumPatchFiles = 1)
        val paths = listOf("src/modules/alpha.c", "src/modules/beta.c")
        val candidates = paths.associateWith { path ->
            project.resolve(path).readBytes() + "\n/* oversized pending shape */\n".toByteArray()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, highBudget).use { graph ->
            val attempt = graph.beginAttempt(paths)
            graph.installCandidate(attempt, candidates)
        }
        val keys = paths.associateWith { path ->
            Files.readAttributes(
                project.resolve(path),
                BasicFileAttributes::class.java,
                LinkOption.NOFOLLOW_LINKS,
            ).fileKey()
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val reducedGraph = graphPath.readText()
            .replace("\"maximumContextFiles\":2", "\"maximumContextFiles\":1")
            .replace("\"maximumPatchFiles\":2", "\"maximumPatchFiles\":1")
        graphPath.writeText(reducedGraph)
        val reducedBudgetJson = Json.parseToJsonElement(reducedGraph).jsonObject.getValue("budget").toString()
        val bindingPath = project.resolve("reports/repair-revisions/recovery-binding.json")
        bindingPath.writeText(
            bindingPath.readText().replace(
                Regex("(?<=\\\"budgetSha256\\\": \\\")[0-9a-f]{64}"),
                sha256(reducedBudgetJson.toByteArray()),
            ),
        )

        assertFailsWith<IllegalArgumentException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, lowBudget)
        }

        paths.forEach { path ->
            assertContentEquals(candidates.getValue(path), project.resolve(path).readBytes())
            assertEquals(
                keys.getValue(path),
                Files.readAttributes(
                    project.resolve(path),
                    BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                ).fileKey(),
            )
        }
    }

    @Test
    fun `generated C discovery counts excluded repair entries and directory depth`() {
        val project = createTempDirectory("repair-discovery-budget-").resolve("project")
        project.resolve("src").createDirectories()
        project.resolve("include").createDirectories()
        project.resolve("Makefile").writeText("all:\n\t@true\n")
        project.resolve("src/program.c").writeText("int main(void) { return 0; }\n")
        repeat(12) { project.resolve("src/.note-$it.repair").writeText("ignored") }

        assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(
                project,
                GeneratedCRepairIndexProfile,
                RepairResourceBudget(maximumDiscoveryEntries = 8, maximumDiscoveryDirectories = 8),
            )
        }

        val deep = project.resolve("src/a/b/c").createDirectories()
        deep.resolve("leaf.h").writeText("#define LEAF 1\n")
        assertFailsWith<IllegalArgumentException> {
            ModuleRepairIndex.load(
                project,
                GeneratedCRepairIndexProfile,
                RepairResourceBudget(maximumDiscoveryDepth = 2),
            )
        }
    }

    @Test
    fun `source replacement preserves exact mode and rejects unsupported metadata`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val originalMode = setOf(
            java.nio.file.attribute.PosixFilePermission.OWNER_READ,
            java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
            java.nio.file.attribute.PosixFilePermission.GROUP_READ,
        )
        Files.setPosixFilePermissions(target, originalMode)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to (target.readBytes() + "\n/* mode */\n".toByteArray())))
            assertEquals(originalMode, Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS))
            graph.reject(attempt, RepairEvidence("test", "restore mode"))
            assertEquals(originalMode, Files.getPosixFilePermissions(target, LinkOption.NOFOLLOW_LINKS))
        }

        val linkedProject = generatedProject()
        val linkedTarget = linkedProject.resolve("src/modules/alpha.c")
        Files.createLink(linkedProject.resolve("src/modules/alpha-hardlink.c"), linkedTarget)
        ModuleRevisionGraph.open(linkedProject, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertFailsWith<IllegalArgumentException> {
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to (linkedTarget.readBytes() + byteArrayOf(1))))
            }
            graph.reject(attempt, RepairEvidence("metadata", "hard link rejected"))
        }
    }

    @Test
    fun `ordinary derived-view failures after head commit still return committed success`() {
        listOf(
            ModuleRevisionFaultPoint.AfterHeadPersist,
            ModuleRevisionFaultPoint.BeforeSourceManifestSync,
            ModuleRevisionFaultPoint.BeforeCompatibilityLogSync,
        ).forEach { injectedPoint ->
            val project = generatedProject()
            val target = project.resolve("src/modules/beta.c")
            val candidate = target.readBytes() + "\n/* accepted despite projection failure */\n".toByteArray()
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point == injectedPoint) throw IllegalStateException("injected derived-view I/O failure")
                },
            )
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to candidate))

            val accepted = graph.accept(attempt, RepairEvidence("valid", "canonical commit succeeded"))

            assertEquals(ModuleRevisionStatus.ACCEPTED, accepted.status)
            assertEquals(accepted.id, graph.snapshot.headId)
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                assertEquals(accepted.id, reopened.snapshot.headId)
            }
        }
    }

    @Test
    fun `project-root paths in repair metadata are portable across equivalent roots`() {
        val first = generatedProject()
        val second = generatedProject()
        listOf(first, second).forEach { project ->
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                val corpus = graph.retainRegressionInputs(listOf(ProcessInput("case")))
                val attempt = graph.beginAttempt(
                    listOf("src/modules/beta.c"),
                    RevisionRepairMetadata(
                        1,
                        "compile",
                        "command failed in $project/src/modules/beta.c",
                        null,
                        listOf("case"),
                        RepairEvidence("compile", "working directory was $project", "$project/reports/build.log"),
                        corpus.sha256,
                    ),
                )
                graph.annotateAttempt(attempt, "diagnostic rooted at $project")
                graph.reject(attempt, RepairEvidence("agent-error", "agent log was under $project"))
            }
        }

        val firstGraph = first.resolve("reports/repair-revisions/graph.json").readBytes()
        val secondGraph = second.resolve("reports/repair-revisions/graph.json").readBytes()
        assertContentEquals(firstGraph, secondGraph)
        assertFalse(firstGraph.toString(Charsets.UTF_8).contains(first.toString()))
        assertTrue(firstGraph.toString(Charsets.UTF_8).contains("\${PROJECT_ROOT}"))
    }

    @Test
    fun `publication and rollback crashes after each file move recover every preimage on restart`() {
        listOf("after-exchange", "before-unlink", "after-move").forEach { crashStage ->
            listOf("candidate", "rollback").forEach { failingPhase ->
                repeat(2) { failingMove ->
                val project = generatedProject()
                val alpha = project.resolve("src/modules/alpha.c")
                val beta = project.resolve("src/modules/beta.c")
                val alphaBefore = alpha.readBytes()
                val betaBefore = beta.readBytes()
                val graph = ModuleRevisionGraph.openForTesting(
                    project,
                    GeneratedCRepairIndexProfile,
                    faultInjector = ModuleRevisionFaultInjector { point ->
                        val matches = when (point) {
                            is ModuleRevisionFaultPoint.AfterPublicationExchange ->
                                crashStage == "after-exchange" && point.phase == failingPhase && point.index == failingMove
                            is ModuleRevisionFaultPoint.AfterPublicationMove ->
                                crashStage == "after-move" && point.phase == failingPhase && point.index == failingMove
                            is ModuleRevisionFaultPoint.BeforeOwnedEntryUnlink ->
                                crashStage == "before-unlink" && point.phase == failingPhase && point.index == failingMove
                            else -> false
                        }
                        if (matches) {
                            throw SimulatedRepairCrash()
                        }
                    },
                )
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c", "src/modules/beta.c"))

                if (failingPhase == "candidate") {
                    assertFailsWith<SimulatedRepairCrash> {
                        graph.installCandidate(
                            attempt,
                            mapOf(
                                "src/modules/alpha.c" to alphaBefore + "\n/* crash alpha */\n".toByteArray(),
                                "src/modules/beta.c" to betaBefore + "\n/* crash beta */\n".toByteArray(),
                            ),
                        )
                    }
                } else {
                    graph.installCandidate(
                        attempt,
                        mapOf(
                            "src/modules/alpha.c" to alphaBefore + "\n/* crash alpha */\n".toByteArray(),
                            "src/modules/beta.c" to betaBefore + "\n/* crash beta */\n".toByteArray(),
                        ),
                    )
                    assertFailsWith<SimulatedRepairCrash> {
                        graph.reject(attempt, RepairEvidence("rejected", "exercise rollback crash"))
                    }
                }
                graph.close()

                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
                    assertContentEquals(alphaBefore, alpha.readBytes())
                    assertContentEquals(betaBefore, beta.readBytes())
                    assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
                }
            }
            }
        }
    }

    @Test
    fun `content-addressed blobs are rehashed and corruption prevents graph open`() {
        val project = generatedProject()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
        val graphText = project.resolve("reports/repair-revisions/graph.json").readText()
        val digest = Regex("\\\"afterBlobSha256\\\":\\\"([0-9a-f]{64})\\\"")
            .find(graphText)?.groupValues?.get(1) ?: error("root graph did not reference a blob")
        project.resolve("reports/repair-revisions/blobs/$digest").writeText("corrupt")

        val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile) }

        assertTrue(failure.message.orEmpty().contains("blob"))
    }

    @Test
    fun `preimage mutation between head check and descriptor read cannot enter the journal`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val graphBytesBefore = run {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
            project.resolve("reports/repair-revisions/graph.json").readBytes()
        }
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) target.writeText("raced preimage\n")
            },
        ).use { graph ->
            val failure = assertFailsWith<IllegalArgumentException> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertTrue(failure.message.orEmpty().contains("preimage"))
            assertEquals(null, graph.snapshot.pendingAttemptId)
        }
        assertContentEquals(graphBytesBefore, project.resolve("reports/repair-revisions/graph.json").readBytes())
    }

    @Test
    fun `descriptor-bound preimage read cannot be redirected by a swap and restore around open`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val held = project.resolve("src/modules/alpha-held.c.repair")
        val substitute = project.resolve("src/modules/alpha-substitute.c.repair")
        val original = target.readBytes()
        val different = original.copyOf().also { bytes -> bytes[0] = (bytes[0].toInt() xor 1).toByte() }
        substitute.writeBytes(different)
        var swapped = false
        var restored = false

        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                when (point) {
                    is ModuleRevisionFaultPoint.BeforeDescriptorBoundRead -> {
                        Files.move(target, held)
                        Files.move(substitute, target)
                        swapped = true
                    }
                    is ModuleRevisionFaultPoint.AfterDescriptorBoundRead -> {
                        Files.move(target, substitute)
                        Files.move(held, target)
                        restored = true
                    }
                    else -> Unit
                }
            },
        ).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertTrue(swapped && restored)
            graph.reject(attempt, RepairEvidence("test", "descriptor identity remained pinned"))
        }

        assertContentEquals(original, target.readBytes())
        assertContentEquals(different, substitute.readBytes())
    }

    @Test
    fun `accepted non-ACP repair remains explicitly non-release at the archive gate`() {
        val project = generatedProject()
        val betaPath = project.resolve("src/modules/beta.c")
        val repaired = betaPath.readText() + "\n/* accepted repair revision */\n"
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/beta.c"))
            graph.installCandidate(attempt, mapOf("src/modules/beta.c" to repaired.toByteArray()))
            graph.accept(attempt, RepairEvidence("valid", "compile and retained behavior accepted"))
            graph.synchronizeRepairHistory()
        }

        MakeProjectBuilder.build(project)
        val archive = project.parent.resolve("repaired-project.zip")
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(project, archive)
        }

        assertTrue(failure.message.orEmpty().contains("legacy schema-v1/v2 repair evidence is non-release"))
        assertTrue(project.resolve("source_tree_manifest.json").readText().contains(sha256(repaired.toByteArray())))
    }

    @Test
    fun `accepted ACP repair archives and extracts through its historical reconstruction lineage`() {
        val fixture = releaseRepairFixture()
        val archive = fixture.project.parent.resolve("repair-release.zip")

        val bundle = ArchivalPackager.create(fixture.project, archive)
        val extracted = fixture.project.parent.resolve("repair-release-extracted")
        val candidateLineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(
            bundle.archivePath,
            extracted,
        )

        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        assertTrue(extracted.resolve("reports/repair_history.json").exists())
        assertTrue(extracted.resolve(fixture.receiptPath).exists())
        val contribution = candidateLineage.source.acceptedAcpContributions.single()
        assertEquals("repair", contribution.workflow)
        assertEquals(fixture.receiptPath, contribution.receiptPath)
        assertEquals(fixture.relativePath, contribution.changes.single().path)
        assertEquals(candidateLineage.source.repairGraphHeadRevisionSha256, contribution.resultSourceRevisionSha256)
        assertEquals(
            captureBuildSourceRevision(extracted).sha256,
            candidateLineage.source.sourceRevision.sha256,
        )
        val lineageParent = fixture.project.parent.resolve("repair-lineage-index").createDirectories()
        Files.setPosixFilePermissions(
            lineageParent,
            setOf(
                java.nio.file.attribute.PosixFilePermission.OWNER_READ,
                java.nio.file.attribute.PosixFilePermission.OWNER_WRITE,
                java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE,
            ),
        )
        val publishedLineage = LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(
            bundle.archivePath,
            lineageParent.resolve("candidate-acp-lineage-index-v2.json"),
        )
        assertEquals(1, publishedLineage.acceptedAcpCount)
        assertEquals(0, publishedLineage.reconstructionCount)
        assertEquals(1, publishedLineage.repairCount)
        assertEquals(candidateLineage.source.sourceRevision.sha256, publishedLineage.sourceRevisionSha256)
    }

    @Test
    fun `archive includes provisional contributions only through a fully accepted composed revision`() {
        val fixture = releaseRepairFixture(includeProvisional = true)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("composed-repair.zip"))
        val extracted = fixture.project.parent.resolve("composed-repair-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        val contributions = lineage.source.acceptedAcpContributions
        assertEquals(2, contributions.size)
        assertEquals(listOf("src/modules/beta.c", fixture.relativePath), contributions.map { it.changes.single().path })
        assertEquals(contributions[0].resultSourceRevisionSha256, contributions[1].parentSourceRevisionSha256)
        assertEquals(lineage.source.repairGraphHeadRevisionSha256, contributions[1].resultSourceRevisionSha256)
        assertTrue(extracted.resolve("src/modules/beta.c").readText().contains("provisional archive improvement"))
        assertContentEquals(fixture.after, extracted.resolve(fixture.relativePath).readBytes())
        val manifest = Json.parseToJsonElement(extracted.resolve("source_tree_manifest.json").readText()).jsonObject
        val touched = (manifest.getValue("files") as JsonArray).map { it.jsonObject }
            .filter { (it.getValue("path") as JsonPrimitive).content in setOf("src/modules/beta.c", fixture.relativePath) }
        assertEquals(2, touched.size)
        val acceptedPrompt = sha256("revision:${contributions[1].taskId}".toByteArray())
        touched.forEach { assertEquals(acceptedPrompt, (it.getValue("promptSha256") as JsonPrimitive).content) }
        val graph = Json.parseToJsonElement(extracted.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        assertEquals(listOf("root", "provisional", "accepted"), (graph.getValue("nodes") as JsonArray).map {
            (it.jsonObject.getValue("status") as JsonPrimitive).content
        })
    }

    @Test
    fun `archive retains exhausted provisional evidence without accepting its abandoned source changes`() {
        val fixture = releaseRepairFixture(includeProvisional = true, abandonProvisional = true)
        val bundle = ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("abandoned-repair.zip"))
        val extracted = fixture.project.parent.resolve("abandoned-repair-extracted")
        val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, extracted)
        assertEquals(listOf(fixture.relativePath), lineage.source.acceptedAcpContributions.map { it.changes.single().path })
        assertFalse(extracted.resolve("src/modules/beta.c").readText().contains("provisional archive improvement"))
        assertTrue(extracted.resolve("reports/archive-provisional.validation.json").exists())
        val graph = Json.parseToJsonElement(extracted.resolve("reports/repair-revisions/graph.json").readText()).jsonObject
        assertEquals(listOf("iteration_exhausted", "fully_accepted"), (graph.getValue("runs") as JsonArray).map {
            (it.jsonObject.getValue("status") as JsonPrimitive).content
        })
        assertEquals(listOf("root", "provisional", "accepted"), (graph.getValue("nodes") as JsonArray).map {
            (it.jsonObject.getValue("status") as JsonPrimitive).content
        })
    }

    @Test
    fun `archive creation rejects missing extra stale and cross-paired repair evidence`() {
        data class Mutation(val label: String, val expected: String, val apply: (ReleaseRepairFixture) -> Unit)
        val mutations = listOf(
            Mutation("missing-graph", "missing repair_history", { fixture ->
                Files.delete(fixture.project.resolve("reports/repair-revisions/graph.json"))
            }),
            Mutation("missing-history", "missing repair_history", { fixture ->
                Files.delete(fixture.project.resolve("reports/repair_history.json"))
            }),
            Mutation("missing-receipt", "missing, extra, or stale ACP receipts", { fixture ->
                Files.delete(fixture.project.resolve(fixture.receiptPath))
            }),
            Mutation("extra-receipt", "missing, extra, or stale ACP receipts", { fixture ->
                Files.copy(
                    fixture.project.resolve(fixture.receiptPath),
                    fixture.project.resolve("reports/repair-revisions/revision_99999999_stale.acp-receipt.json"),
                )
            }),
            Mutation("cross-paired", "cross-paired", { fixture ->
                val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
                graph.writeText(
                    graph.readText().replaceFirst(
                        "\"requestSha256\":\"${fixture.requestSha256}\"",
                        "\"requestSha256\":\"${"0".repeat(64)}\"",
                    ),
                )
            }),
            Mutation("stale-history", "history is cross-paired", { fixture ->
                val history = fixture.project.resolve("reports/repair_history.json")
                history.writeText(
                    history.readText().replaceFirst(
                        "\"assessmentStatus\":\"accepted\"",
                        "\"assessmentStatus\":\"rejected\"",
                    ),
                )
            }),
            Mutation("legacy-schema", "schema-v1/v2 repair evidence is non-release", { fixture ->
                val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
                graph.writeText(graph.readText().replaceFirst("\"schemaVersion\": 3", "\"schemaVersion\": 1"))
            }),
            Mutation("receipt-record-cross-pair", "records differ from the exact workflow change set", { fixture ->
                val receipt = fixture.project.resolve(fixture.receiptPath)
                val oldReceiptSha256 = sha256(receipt.readBytes())
                val expectedPathCommitment = sha256(fixture.relativePath.toByteArray())
                val otherSameLengthPath = "src/modules/bravo.c"
                check(otherSameLengthPath.toByteArray().size == fixture.relativePath.toByteArray().size)
                receipt.writeText(
                    receipt.readText().replace(
                        expectedPathCommitment,
                        sha256(otherSameLengthPath.toByteArray()),
                    ),
                )
                val newReceiptSha256 = sha256(receipt.readBytes())
                listOf(
                    "reports/repair-revisions/graph.json",
                    "reports/repair_history.json",
                ).forEach { relative ->
                    val path = fixture.project.resolve(relative)
                    path.writeText(path.readText().replace(oldReceiptSha256, newReceiptSha256))
                }
            }),
        )

        mutations.forEach { mutation ->
            val fixture = releaseRepairFixture()
            mutation.apply(fixture)
            val failure = assertFailsWith<IllegalArgumentException>(mutation.label) {
                ArchivalPackager.create(
                    fixture.project,
                    fixture.project.parent.resolve("${mutation.label}.zip"),
                )
            }
            assertTrue(failure.message.orEmpty().contains(mutation.expected), failure.message)
        }
    }

    @Test
    fun `archive creation rejects a pending repair assessment`() {
        val fixture = releaseRepairFixture()
        ModuleRevisionGraph.open(fixture.project, GeneratedCRepairIndexProfile).use { graph ->
            val corpus = graph.retainedRegressionCorpus()
            graph.beginRun(1, 60_000)
            graph.beginAttempt(
                listOf(fixture.relativePath),
                RevisionRepairMetadata(
                    iterationIndex = 2,
                    failureKind = "compile",
                    prompt = "second bounded failure",
                    summary = null,
                    retainedRegressionIds = corpus.inputs.map(ProcessInput::id),
                    before = null,
                    regressionCorpusSha256 = corpus.sha256,
                ),
            )
            graph.synchronizeRepairHistory()
        }

        val failure = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("pending.zip"))
        }
        assertTrue(failure.message.orEmpty().contains("pending workflow assessment"), failure.message)
    }

    @Test
    fun `archive validation recomputes source corpus runtime and behavior authority from receipt bytes`() {
        fun JsonObject.changed(field: String, value: JsonElement) = JsonObject(toMutableMap().apply { put(field, value) })
        fun JsonObject.scopeChanged(index: Int, change: (JsonObject) -> JsonObject): JsonObject {
            val scopes = (getValue("scopes") as JsonArray).toMutableList()
            scopes[index] = change(scopes[index].jsonObject)
            return changed("scopes", JsonArray(scopes))
        }
        data class Mutation(val label: String, val expected: String, val change: (JsonObject) -> JsonObject)
        val mutations = listOf(
            Mutation("snapshot", "source manifest", { receipt -> receipt.changed("sourceSnapshot",
                receipt.getValue("sourceSnapshot").jsonObject.changed("manifestSha256", JsonPrimitive("0".repeat(64)))) }),
            Mutation("runtime", "runtime configuration", { it.changed("runtimeConfiguration", JsonObject(emptyMap())) }),
            Mutation("corpus", "retained corpus", { it.changed("inputs", JsonArray(emptyList())) }),
            Mutation("omitted-scope", "scope inventory", { it.changed("scopes", JsonArray((it.getValue("scopes") as JsonArray).dropLast(1))) }),
            Mutation("case-count", "scope inventory", { it.changed("caseCount", JsonPrimitive(0)) }),
            Mutation("cleanup", "contained validation authority", { it.changed("cleanupVerified", JsonPrimitive(false)) }),
            Mutation("reference-binary", "executable identity", { receipt -> receipt.changed("originalExecutable",
                receipt.getValue("originalExecutable").jsonObject.changed("sha256", JsonPrimitive("0".repeat(64)))) }),
            Mutation("forged-match", "every retained observation", { receipt -> receipt.scopeChanged(2) { scope ->
                scope.changed("output", scope.getValue("output").jsonObject.changed("stderrBase64", JsonPrimitive("YQ=="))) } }),
            Mutation("changed-reference", "reference observations", { receipt ->
                var changed = receipt
                listOf(1, 2).forEach { index -> changed = changed.scopeChanged(index) { scope ->
                    scope.changed("output", scope.getValue("output").jsonObject.changed("stdoutBase64", JsonPrimitive("YQ=="))) } }
                changed
            }),
            Mutation("unbounded-quota", "finite dedicated", { receipt -> receipt.scopeChanged(0) { scope ->
                scope.changed("writableQuota", scope.getValue("writableQuota").jsonObject.changed("maximumEntries", JsonPrimitive(0))) } }),
        )
        mutations.forEach { mutation ->
            val fixture = releaseRepairFixture()
            val receipt = fixture.project.resolve("reports/archive-fixture.validation.json")
            val oldDigest = sha256(receipt.readBytes())
            receipt.writeBytes(OracleJson.canonicalBytes(mutation.change(Json.parseToJsonElement(receipt.readText()).jsonObject), StrictJsonLimits()))
            val newDigest = sha256(receipt.readBytes())
            // Update the outer proof commitment to reach independent receipt-content admission.
            val graph = fixture.project.resolve("reports/repair-revisions/graph.json")
            graph.writeText(graph.readText().replace(oldDigest, newDigest))
            val failure = assertFailsWith<IllegalArgumentException>(mutation.label) {
                ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("${mutation.label}.zip"))
            }
            assertTrue(failure.message.orEmpty().contains(mutation.expected), "${mutation.label}: ${failure.message}")
        }
        val fixture = releaseRepairFixture()
        Files.delete(fixture.project.resolve("reports/archive-fixture.validation.json"))
        val missing = assertFailsWith<IllegalArgumentException> {
            ArchivalPackager.create(fixture.project, fixture.project.parent.resolve("missing-validation.zip"))
        }
        assertTrue(missing.message.orEmpty().contains("validation receipt is missing"), missing.message)
    }

    @Test
    fun `archive extraction independently rejects missing and stale repair assessments`() {
        listOf("missing-receipt", "stale-history").forEach { mutation ->
            val fixture = releaseRepairFixture()
            val valid = ArchivalPackager.create(
                fixture.project,
                fixture.project.parent.resolve("valid-$mutation.zip"),
            )
            val tampered = fixture.project.parent.resolve("tampered-$mutation.zip")
            rewriteArchive(valid.archivePath, tampered) { entries ->
                when (mutation) {
                    "missing-receipt" -> entries.remove(fixture.receiptPath)
                    "stale-history" -> {
                        val path = "reports/repair_history.json"
                        entries[path] = requireNotNull(entries[path]).toString(Charsets.UTF_8)
                            .replaceFirst(
                                "\"assessmentStatus\":\"accepted\"",
                                "\"assessmentStatus\":\"rejected\"",
                            ).toByteArray()
                    }
                }
            }

            val failure = assertFailsWith<IllegalArgumentException>(mutation) {
                ArchivalBundleVerifier.extractAndVerify(
                    tampered,
                    fixture.project.parent.resolve("extract-$mutation"),
                )
            }
            val expected = if (mutation == "missing-receipt") {
                "missing, extra, or stale ACP receipts"
            } else {
                "history is cross-paired"
            }
            assertTrue(failure.message.orEmpty().contains(expected), failure.message)
        }
    }

    @Test
    fun `context and patch resource budgets are enforced`() {
        val contextProject = generatedProject()
        val tinyContext = RepairResourceBudget(maximumContextBytes = 64, maximumPatchBytes = 32)
        assertFailsWith<RepairBudgetExceededException> {
            ModuleRepairIndex.load(contextProject, GeneratedCRepairIndexProfile, tinyContext).select("compile", "src/modules/alpha.c: error")
        }

        val patchProject = generatedProject()
        val tinyPatch = RepairResourceBudget(maximumPatchBytes = 8)
        ModuleRevisionGraph.open(patchProject, GeneratedCRepairIndexProfile, tinyPatch).use { graph ->
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertFailsWith<RepairBudgetExceededException> {
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to ByteArray(9)))
            }
            graph.reject(attempt, RepairEvidence("budget", "candidate exceeded patch budget"))
        }
    }

    @Test
    fun `sparse index selects bounded context for more than five thousand functions`() {
        val project = createTempDirectory("repair-index-scale-").resolve("project")
        createScaleProject(project, moduleCount = 256, functionsPerModule = 20)

        val index = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        val selection = index.select("compile", "src/modules/module_0255.c:99: error: invalid initializer")

        assertEquals(256, index.moduleIds.size)
        assertEquals(listOf("module_0255"), selection.seedModules)
        assertEquals(listOf("module_0254"), selection.dependencyModules)
        assertTrue(selection.readablePaths.size <= 6)
        assertFalse(selection.readablePaths.any { "module_0000" in it })
        assertTrue(selection.totalBytes < RepairResourceBudget().maximumContextBytes)

        val bounded = RepairResourceBudget(maximumContextModules = 3)
        val behavior = ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile, bounded).select("behavior", "module_0255")
        assertEquals(listOf("module_0253", "module_0254"), behavior.dependencyModules)
        assertTrue("module_0252" in behavior.deferredModules)
        assertEquals(
            listOf("include/modules/module_0255.h", "src/modules/module_0255.c", "src/modules/module_0255_internal.h"),
            behavior.writablePaths,
        )
    }

    @Test
    fun `same JVM aliases wait and a graph opened on one thread can close on another`() {
        val project = generatedProject()
        val aliasContainer = createTempDirectory("repair-root-alias-")
        val parentAlias = aliasContainer.resolve("project-parent")
        Files.createSymbolicLink(parentAlias, project.parent)
        val alias = parentAlias.resolve(project.fileName)
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val started = CountDownLatch(1)
        val acquired = CountDownLatch(1)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val waiter = executor.submit<ModuleRevisionGraph> {
                started.countDown()
                ModuleRevisionGraph.open(alias, GeneratedCRepairIndexProfile).also { acquired.countDown() }
            }
            assertTrue(started.await(5, TimeUnit.SECONDS))
            assertFalse(acquired.await(200, TimeUnit.MILLISECONDS), "same-root alias bypassed JVM coordination")

            val closeFailure = AtomicReference<Throwable?>()
            val closer = Thread({
                runCatching(first::close).exceptionOrNull()?.let(closeFailure::set)
            }, "repair-graph-cross-thread-close")
            closer.start()
            closer.join(5_000)
            assertFalse(closer.isAlive, "cross-thread graph close did not finish")
            assertEquals(null, closeFailure.get())

            assertTrue(acquired.await(5, TimeUnit.SECONDS), "same-JVM waiter did not progress after close")
            waiter.get(5, TimeUnit.SECONDS).close()
        } finally {
            runCatching(first::close)
            executor.shutdownNow()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
    }

    @Test
    fun `open graph remains bound to renamed root while replacement root uses independent locks`() {
        val original = generatedProject()
        val replacementSeed = generatedProject()
        val renamed = original.parent.resolve("renamed-project")
        val graph = ModuleRevisionGraph.open(original, GeneratedCRepairIndexProfile)
        Files.move(original, renamed)
        Files.move(replacementSeed, original)
        val originalTarget = renamed.resolve("src/modules/alpha.c")
        val replacementTarget = original.resolve("src/modules/alpha.c")
        val parent = originalTarget.readBytes()
        val replacementBytes = replacementTarget.readBytes()

        val contender = Executors.newSingleThreadExecutor()
        try {
            val replacementGraph = contender.submit<ModuleRevisionGraph> {
                ModuleRevisionGraph.open(original, GeneratedCRepairIndexProfile)
            }.get(5, TimeUnit.SECONDS)
            replacementGraph.close()

            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            val candidate = parent + "\n/* pinned renamed root */\n".toByteArray()
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            assertContentEquals(candidate, originalTarget.readBytes())
            assertContentEquals(replacementBytes, replacementTarget.readBytes())
            graph.reject(attempt, RepairEvidence("test", "renamed root stayed pinned"))
            assertContentEquals(parent, originalTarget.readBytes())
            assertContentEquals(replacementBytes, replacementTarget.readBytes())
        } finally {
            runCatching(graph::close)
            contender.shutdownNow()
        }
    }

    @Test
    fun `durable graph publication crash points recover an exact pending attempt`() {
        val stages: List<(ModuleRevisionFaultPoint) -> Boolean> = listOf(
            { point ->
                point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
            },
            { point ->
                point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json"
            },
        )
        stages.forEachIndexed { stageIndex, matches ->
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            var armed = false
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (armed && matches(point)) throw SimulatedRepairCrash()
                },
            )
            armed = true

            assertFailsWith<SimulatedRepairCrash>("state publication stage $stageIndex") {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertFailsWith<IllegalStateException> {
                graph.snapshot
            }
            graph.close()
            assertContentEquals(accepted, target.readBytes())

            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
                assertEquals(null, recovered.snapshot.pendingAttemptId)
                assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
                assertContentEquals(accepted, target.readBytes())
            }
            assertFalse(
                project.resolve("reports/repair-revisions/.graph.json.repair-atomic.tmp").exists(),
                "state publication stage $stageIndex left its exact recovery name",
            )
        }
    }

    @Test
    fun `non-exception termination preserves crash residue and poisons the live graph`() {
        val project = generatedProject()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                    point.scope == "revision-state" && point.name == "graph.json"
                ) {
                    throw SimulatedRepairTermination()
                }
            },
        )
        armed = true

        assertFailsWith<SimulatedRepairTermination> {
            graph.beginAttempt(listOf("src/modules/alpha.c"))
        }
        assertTrue(project.resolve("reports/repair-revisions/.graph.json.repair-atomic.tmp").exists())
        assertFailsWith<IllegalStateException> { graph.snapshot }
        graph.close()

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
        }
    }

    @Test
    fun `ordinary state publication faults agree with the durable commit boundary`() {
        run {
            val project = generatedProject()
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            var armed = false
            var injected = false
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (armed && !injected &&
                        point is ModuleRevisionFaultPoint.AfterStatePublicationExchange &&
                        point.scope == "revision-state" && point.name == "graph.json"
                    ) {
                        injected = true
                        throw IllegalStateException("ordinary precommit publication fault")
                    }
                },
            )
            val before = graphPath.readBytes()
            armed = true

            assertFailsWith<IllegalStateException> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertEquals(null, graph.snapshot.pendingAttemptId)
            assertContentEquals(before, graphPath.readBytes())
            assertFalse(project.resolve("reports/repair-revisions/.graph.json.repair-atomic.tmp").exists())
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                assertEquals(null, reopened.snapshot.pendingAttemptId)
            }
        }

        run {
            val project = generatedProject()
            var armed = false
            var injected = false
            val graph = ModuleRevisionGraph.openForTesting(
                project,
                GeneratedCRepairIndexProfile,
                faultInjector = ModuleRevisionFaultInjector { point ->
                    if (armed && !injected &&
                        point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == "revision-state" && point.name == "graph.json"
                    ) {
                        injected = true
                        throw IllegalStateException("ordinary postcommit publication fault")
                    }
                },
            )
            armed = true

            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
            assertTrue(project.resolve("reports/repair-revisions/graph.json").readText().contains(attempt.id))
            graph.reject(attempt, RepairEvidence("test", "postcommit fault was a committed success"))
            graph.close()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
            }
        }
    }

    @Test
    fun `projection capacity is reserved before pending and completed state commits`() {
        run {
            val project = generatedProject()
            val budget = RepairResourceBudget(maximumProjectionBytes = 512)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                assertFailsWith<RepairBudgetExceededException> {
                    graph.beginAttempt(
                        listOf("src/modules/alpha.c"),
                        RevisionRepairMetadata(
                            1,
                            "compile",
                            "bounded failure",
                            null,
                            emptyList(),
                            null,
                            corpus.sha256,
                        ),
                    )
                }
                assertEquals(null, graph.snapshot.pendingAttemptId)
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { reopened ->
                assertEquals(null, reopened.snapshot.pendingAttemptId)
            }
        }

        run {
            val project = generatedProject()
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            val budget = RepairResourceBudget(maximumProjectionBytes = 16L * 1024)
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { graph ->
                val corpus = graph.retainedRegressionCorpus()
                val attempt = graph.beginAttempt(
                    listOf("src/modules/alpha.c"),
                    RevisionRepairMetadata(
                        1,
                        "compile",
                        "repair one module",
                        "bounded summary",
                        emptyList(),
                        null,
                        corpus.sha256,
                        publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE,
                    ),
                )
                graph.installCandidate(
                    attempt,
                    mapOf("src/modules/alpha.c" to accepted + "\n/* candidate */\n".toByteArray()),
                )

                assertFailsWith<RepairBudgetExceededException> {
                    graph.accept(attempt, RepairEvidence("valid", "x".repeat(5_000)))
                }
                assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
                graph.reject(attempt, RepairEvidence("projection-budget", "oversized acceptance evidence rejected"))
                assertEquals(ModuleRevisionStatus.REJECTED, graph.snapshot.nodes.last().status)
                assertContentEquals(accepted, target.readBytes())
            }
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { reopened ->
                assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
                assertEquals(null, reopened.snapshot.pendingAttemptId)
            }
        }
    }

    @Test
    fun `pending candidate reserves graph bytes for deterministic recovery`() {
        val project = genericProject("repair-recovery-graph-budget-", mapOf("code/unit.src" to "unit\n"))
        val modules = (0 until 256).map { index ->
            val id = "module_${index.toString().padStart(3, '0')}"
            RepairModuleEvidence(
                id = id,
                ownedPaths = if (index == 0) listOf("code/unit.src") else emptyList(),
                dependencyModuleIds = if (index == 0) {
                    emptyList()
                } else {
                    listOf("module_${(index - 1).toString().padStart(3, '0')}")
                },
            )
        }
        val profile = DeclarativeRepairIndexProfile(
            "recovery-graph-budget-v1",
            RepairIndexLayout(
                sourcePaths = listOf("code/unit.src"),
                editablePaths = listOf("code/unit.src"),
                modules = modules,
            ),
        )
        val budget = RepairResourceBudget(maximumGraphBytes = 6L * 1024)
        val target = project.resolve("code/unit.src")
        val before = target.readBytes()

        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            val attempt = graph.beginAttempt(listOf("code/unit.src"))
            val failure = assertFailsWith<RepairBudgetExceededException> {
                graph.installCandidate(attempt, mapOf("code/unit.src" to "changed\n".toByteArray()))
            }
            assertTrue(failure.message.orEmpty().contains("graph"))
            assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
            assertContentEquals(before, target.readBytes())
        }

        ModuleRevisionGraph.open(project, profile, budget).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertContentEquals(before, target.readBytes())
        }
    }

    @Test
    fun `startup removes a bounded crashed blob atomic before graph recovery`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val accepted = target.readBytes()
        var armed = false
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (armed && point is ModuleRevisionFaultPoint.AfterStateTemporaryDirectorySync &&
                    point.scope == "revision-blob"
                ) {
                    throw SimulatedRepairCrash()
                }
            },
        )
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        armed = true

        assertFailsWith<SimulatedRepairCrash> {
            graph.installCandidate(
                attempt,
                mapOf("src/modules/alpha.c" to accepted + "\n/* interrupted blob */\n".toByteArray()),
            )
        }
        graph.close()
        assertContentEquals(accepted, target.readBytes())
        val blobs = project.resolve("reports/repair-revisions/blobs")
        assertTrue(Files.list(blobs).use { entries ->
            entries.anyMatch { it.fileName.toString().matches(Regex("\\.[0-9a-f]{64}\\.repair-atomic\\.tmp")) }
        })

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { recovered ->
            assertEquals(null, recovered.snapshot.pendingAttemptId)
            assertTrue(recovered.snapshot.nodes.last().recoveredAfterCrash)
            assertContentEquals(accepted, target.readBytes())
        }
        assertFalse(Files.list(blobs).use { entries ->
            entries.anyMatch { it.fileName.toString().endsWith(".repair-atomic.tmp") }
        })
    }

    @Test
    fun `invalid state targets do not leak descriptors across rejected writes`() {
        val project = createTempDirectory("repair-invalid-state-fd-").resolve("project")
        project.resolve("reports/repair-revisions/blobs").createDirectories()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        graphPath.writeText("invalid")
        Files.createLink(project.resolve("reports/repair-revisions/graph.alias"), graphPath)

        LinuxFilesystemSyscalls.openRoot(project).use { root ->
            RepairStateStore.open(root).use { store ->
                val before = Files.list(Path.of("/proc/self/fd")).use { it.count() }
                repeat(128) {
                    assertFailsWith<IllegalArgumentException> { store.writeGraph("state".toByteArray()) }
                }
                val after = Files.list(Path.of("/proc/self/fd")).use { it.count() }
                assertEquals(before, after)
            }
        }
    }

    @Test
    fun `open graph keeps all repair state bound when the reports name is replaced`() {
        val project = generatedProject()
        val reports = project.resolve("reports")
        val heldReports = project.resolve("reports-held")
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val heldGraph = reports.resolve("repair-revisions/graph.json")
        val before = heldGraph.readBytes()

        Files.move(reports, heldReports)
        reports.resolve("repair-revisions/blobs").createDirectories()
        val replacementGraph = reports.resolve("repair-revisions/graph.json")
        val canary = "replacement state must remain untouched\n".toByteArray()
        replacementGraph.writeBytes(canary)

        try {
            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            graph.reject(attempt, RepairEvidence("test", "descriptor-pinned state stayed bound"))
            assertContentEquals(canary, replacementGraph.readBytes())
            assertFalse(reports.resolve("source_revisions.jsonl").exists())
            assertFalse(before.contentEquals(heldReports.resolve("repair-revisions/graph.json").readBytes()))
        } finally {
            graph.close()
        }

        Files.delete(replacementGraph)
        Files.delete(reports.resolve("repair-revisions/blobs"))
        Files.delete(reports.resolve("repair-revisions"))
        Files.delete(reports)
        Files.move(heldReports, reports)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertEquals(null, reopened.snapshot.pendingAttemptId)
            assertEquals(ModuleRevisionStatus.REJECTED, reopened.snapshot.nodes.last().status)
        }
    }

    @Test
    fun `ancestor retarget cannot redirect an open graph or share replacement locks`() {
        val original = generatedProject()
        val replacement = generatedProject()
        val aliasContainer = createTempDirectory("repair-ancestor-retarget-")
        val parentAlias = aliasContainer.resolve("parent")
        Files.createSymbolicLink(parentAlias, original.parent)
        val alias = parentAlias.resolve(original.fileName)
        val graph = ModuleRevisionGraph.open(alias, GeneratedCRepairIndexProfile)
        Files.delete(parentAlias)
        Files.createSymbolicLink(parentAlias, replacement.parent)
        val originalTarget = original.resolve("src/modules/alpha.c")
        val replacementTarget = replacement.resolve("src/modules/alpha.c")
        val parent = originalTarget.readBytes()
        val replacementBytes = replacementTarget.readBytes()

        val contender = Executors.newSingleThreadExecutor()
        try {
            val replacementGraph = contender.submit<ModuleRevisionGraph> {
                ModuleRevisionGraph.open(alias, GeneratedCRepairIndexProfile)
            }.get(5, TimeUnit.SECONDS)
            replacementGraph.close()

            val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
            val candidate = parent + "\n/* pinned ancestor */\n".toByteArray()
            graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            assertContentEquals(candidate, originalTarget.readBytes())
            assertContentEquals(replacementBytes, replacementTarget.readBytes())
            graph.reject(attempt, RepairEvidence("test", "ancestor retarget stayed pinned"))
        } finally {
            runCatching(graph::close)
            contender.shutdownNow()
        }
        assertContentEquals(parent, originalTarget.readBytes())
        assertContentEquals(replacementBytes, replacementTarget.readBytes())
    }

    @Test
    fun `reentrant close and same-root open cannot release or bypass an active operation`() {
        val project = generatedProject()
        val closeFailure = AtomicReference<Throwable?>()
        val openFailure = AtomicReference<Throwable?>()
        lateinit var graph: ModuleRevisionGraph
        graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) {
                    closeFailure.set(runCatching(graph::close).exceptionOrNull())
                    openFailure.set(
                        runCatching {
                            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).close()
                        }.exceptionOrNull(),
                    )
                }
            },
        )

        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        assertTrue(closeFailure.get() is IllegalStateException)
        assertTrue(openFailure.get() is IllegalStateException)
        assertEquals(attempt.id, graph.snapshot.pendingAttemptId)
        graph.reject(attempt, RepairEvidence("test", "reentrant close/open rejected"))
        graph.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
    }

    @Test
    fun `close and contender remain blocked until an in-flight graph operation exits`() {
        val project = generatedProject()
        val target = project.resolve("src/modules/alpha.c")
        val before = target.readBytes()
        val operationEntered = CountDownLatch(1)
        val releaseOperation = CountDownLatch(1)
        val closeStarted = CountDownLatch(1)
        val closeCompleted = CountDownLatch(1)
        val contenderStarted = CountDownLatch(1)
        val contenderAcquired = CountDownLatch(1)
        val graph = ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforePreimageRead) {
                    operationEntered.countDown()
                    assertTrue(releaseOperation.await(10, TimeUnit.SECONDS), "operation callback was not released")
                }
            },
        )
        val executor = Executors.newFixedThreadPool(3)
        try {
            val operation = executor.submit<ModuleRevisionAttempt> {
                graph.beginAttempt(listOf("src/modules/alpha.c"))
            }
            assertTrue(operationEntered.await(5, TimeUnit.SECONDS))
            val close = executor.submit {
                closeStarted.countDown()
                graph.close()
                closeCompleted.countDown()
            }
            val contender = executor.submit<ModuleRevisionGraphSnapshot> {
                contenderStarted.countDown()
                ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
                    contenderAcquired.countDown()
                    reopened.snapshot
                }
            }
            assertTrue(closeStarted.await(5, TimeUnit.SECONDS))
            assertTrue(contenderStarted.await(5, TimeUnit.SECONDS))
            assertFalse(closeCompleted.await(200, TimeUnit.MILLISECONDS), "close escaped the active operation monitor")
            assertFalse(contenderAcquired.await(200, TimeUnit.MILLISECONDS), "contender bypassed the active graph lease")

            releaseOperation.countDown()
            operation.get(5, TimeUnit.SECONDS)
            close.get(5, TimeUnit.SECONDS)
            val recovered = contender.get(10, TimeUnit.SECONDS)
            assertTrue(closeCompleted.await(1, TimeUnit.SECONDS))
            assertTrue(contenderAcquired.await(1, TimeUnit.SECONDS))
            assertEquals(null, recovered.pendingAttemptId)
            assertEquals(ModuleRevisionStatus.REJECTED, recovered.nodes.last().status)
            assertTrue(recovered.nodes.last().recoveredAfterCrash)
            assertContentEquals(before, target.readBytes())
        } finally {
            releaseOperation.countDown()
            runCatching(graph::close)
            executor.shutdownNow()
        }
    }

    @Test
    fun `interrupted same JVM waiter releases its coordinator reference`() {
        val project = generatedProject()
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val started = CountDownLatch(1)
        val failure = AtomicReference<Throwable?>()
        val interruptRestored = AtomicReference(false)
        val waiter = Thread({
            started.countDown()
            failure.set(runCatching { ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile) }.exceptionOrNull())
            interruptRestored.set(Thread.currentThread().isInterrupted)
        }, "repair-graph-interrupted-waiter")
        waiter.start()
        assertTrue(started.await(5, TimeUnit.SECONDS))
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        while (waiter.state !in setOf(Thread.State.WAITING, Thread.State.TIMED_WAITING) &&
            System.nanoTime() < deadline
        ) Thread.onSpinWait()
        waiter.interrupt()
        waiter.join(5_000)
        assertFalse(waiter.isAlive)
        assertTrue(failure.get() is IllegalStateException)
        assertTrue(interruptRestored.get())
        first.close()
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { }
    }

    @Test
    fun `same JVM and operating system graph lock waits are budgeted`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumGraphLockWaitMillis = 100)
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget)
        val executor = Executors.newSingleThreadExecutor()
        try {
            val failure = executor.submit<Throwable?> {
                runCatching {
                    ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
                }.exceptionOrNull()
            }.get(5, TimeUnit.SECONDS)
            assertTrue(failure is RepairGraphLockTimeoutException, failure.toString())
        } finally {
            first.close()
            executor.shutdownNow()
        }
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
    }

    @Test
    fun `blob cleanup charges directory entries before materializing or deleting them`() {
        val project = generatedProject()
        val budget = RepairResourceBudget(maximumStateDirectoryEntries = 128)
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).use { }
        val blobs = project.resolve("reports/repair-revisions/blobs")
        repeat(129) { index ->
            blobs.resolve("unowned-${index.toString().padStart(3, '0')}").writeText("preserve")
        }

        assertFailsWith<decompengine.acp.LinuxResourceLimitException> {
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile, budget).close()
        }
        assertEquals(129L, Files.list(blobs).use { entries ->
            entries.filter { it.fileName.toString().startsWith("unowned-") }.count()
        })
    }

    @Test
    fun `blob publication cannot create a graph that exceeds its own reopen traversal budget`() {
        val project = genericProject(
            "repair-blob-publication-budget-",
            mapOf("code/first.src" to "first\n", "code/second.src" to "second\n"),
        )
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/first.src", "code/second.src"),
            editablePaths = listOf("code/first.src", "code/second.src"),
            modules = listOf(
                RepairModuleEvidence("first", listOf("code/first.src")),
                RepairModuleEvidence("second", listOf("code/second.src")),
            ),
        )
        val profile = DeclarativeRepairIndexProfile("blob-publication-budget-v1", layout)
        val budget = RepairResourceBudget(maximumStateDirectoryEntries = 2)
        val blobs = project.resolve("reports/repair-revisions/blobs")

        assertFailsWith<RepairBudgetExceededException> {
            ModuleRevisionGraph.open(
                project,
                profile,
                RepairResourceBudget(maximumStateDirectoryEntries = 1),
            ).close()
        }
        assertTrue(project.resolve("reports/repair-revisions/recovery-binding.json").exists())
        assertFalse(project.resolve("reports/repair-revisions/graph.json").exists())
        assertEquals(0L, Files.list(blobs).use { it.count() })

        ModuleRevisionGraph.open(project, profile, budget).use { graph ->
            val attempt = graph.beginAttempt(layout.editablePaths)
            assertFailsWith<RepairBudgetExceededException> {
                graph.installCandidate(
                    attempt,
                    mapOf(
                        "code/first.src" to "changed first\n".toByteArray(),
                        "code/second.src" to "changed second\n".toByteArray(),
                    ),
                )
            }
            assertEquals(2L, Files.list(blobs).use { it.count() })
        }

        ModuleRevisionGraph.open(project, profile, budget).use { reopened ->
            assertEquals(null, reopened.snapshot.pendingAttemptId)
            assertTrue(reopened.snapshot.nodes.last().recoveredAfterCrash)
        }
        assertEquals(2L, Files.list(blobs).use { it.count() })
    }

    @Test
    fun `graphless initialization retry removes bounded orphan blobs before rebinding`() {
        val project = genericProject(
            "repair-orphan-initialization-",
            mapOf("code/first.src" to "first\n", "code/second.src" to "second\n"),
        )
        val layout = RepairIndexLayout(
            sourcePaths = listOf("code/first.src", "code/second.src"),
            editablePaths = listOf("code/first.src", "code/second.src"),
            modules = listOf(
                RepairModuleEvidence("first", listOf("code/first.src")),
                RepairModuleEvidence("second", listOf("code/second.src")),
            ),
        )
        val profile = DeclarativeRepairIndexProfile("orphan-initialization-v1", layout)
        val failedBudget = RepairResourceBudget(
            maximumStateDirectoryEntries = 2,
            maximumProjectionBytes = 1,
        )
        val blobs = project.resolve("reports/repair-revisions/blobs")

        assertFailsWith<RepairBudgetExceededException> {
            ModuleRevisionGraph.open(project, profile, failedBudget).close()
        }
        assertFalse(project.resolve("reports/repair-revisions/graph.json").exists())
        assertEquals(2L, Files.list(blobs).use { it.count() })
        project.resolve("code/first.src").writeText("changed first\n")
        project.resolve("code/second.src").writeText("changed second\n")

        val validBudget = RepairResourceBudget(maximumStateDirectoryEntries = 2)
        ModuleRevisionGraph.open(project, profile, validBudget).use { reopened ->
            assertEquals(null, reopened.snapshot.pendingAttemptId)
        }
        assertEquals(2L, Files.list(blobs).use { it.count() })
        assertTrue(Files.list(blobs).use { entries ->
            entries.map { it.fileName.toString() }.allMatch { digest ->
                digest == sha256("changed first\n".toByteArray()) ||
                    digest == sha256("changed second\n".toByteArray())
            }
        })
    }

    @Test
    fun `separate JVM cannot acquire the project graph until the OS lock is released`() {
        val project = generatedProject()
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            ModuleRevisionGraphLockProbe::class.java.name,
            project.toString(),
        ).redirectErrorStream(true).start()
        val reader = process.inputStream.bufferedReader()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            assertEquals("READY", outputReader.submit<String?> { reader.readLine() }.get(10, TimeUnit.SECONDS))
            val acquired = outputReader.submit<String?> { reader.readLine() }
            assertFailsWith<TimeoutException> { acquired.get(500, TimeUnit.MILLISECONDS) }

            first.close()
            assertEquals("ACQUIRED", acquired.get(10, TimeUnit.SECONDS))
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "separate-JVM graph probe did not exit")
            assertEquals(0, process.exitValue())
        } finally {
            runCatching(first::close)
            outputReader.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    @Test
    fun `separate JVM cannot bypass the root lock by replacing reports`() {
        val project = generatedProject()
        val reports = project.resolve("reports")
        val heldReports = project.resolve("reports-held")
        val first = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        Files.move(reports, heldReports)
        reports.createDirectories()
        Files.copy(heldReports.resolve("program_model.json"), reports.resolve("program_model.json"))
        Files.copy(heldReports.resolve("module_plan.json"), reports.resolve("module_plan.json"))

        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            ModuleRevisionGraphLockProbe::class.java.name,
            project.toString(),
        ).redirectErrorStream(true).start()
        val reader = process.inputStream.bufferedReader()
        val outputReader = Executors.newSingleThreadExecutor()
        try {
            assertEquals("READY", outputReader.submit<String?> { reader.readLine() }.get(10, TimeUnit.SECONDS))
            val acquired = outputReader.submit<String?> { reader.readLine() }
            assertFailsWith<TimeoutException> { acquired.get(500, TimeUnit.MILLISECONDS) }

            first.close()
            assertEquals("ACQUIRED", acquired.get(10, TimeUnit.SECONDS))
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "replacement-reports graph probe did not exit")
            assertEquals(0, process.exitValue())
        } finally {
            runCatching(first::close)
            outputReader.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    @Test
    fun `graph ingress and every caller-visible snapshot are deeply detached and Java immutable`() {
        val project = generatedProject()
        val mutableArgs = arrayListOf("original")
        val mutableStdin = byteArrayOf(1, 2, 3)
        val graph = ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile)
        val retained = graph.retainRegressionInputs(listOf(ProcessInput("case", mutableArgs, mutableStdin)))
        mutableArgs[0] = "mutated"
        mutableStdin[0] = 99

        assertEquals(listOf("original"), retained.inputs.single().args)
        assertContentEquals(byteArrayOf(1, 2, 3), retained.inputs.single().stdin)
        val detachedStdin = retained.inputs.single().stdin
        detachedStdin[1] = 88
        assertContentEquals(byteArrayOf(1, 2, 3), retained.inputs.single().stdin)
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (retained.inputs as MutableList<ProcessInput>).clear()
        }

        val context = graph.selectContext("compile", "src/modules/alpha.c: error")
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (context.readablePaths as MutableList<String>).add("forged.c")
        }
        val target = project.resolve("src/modules/alpha.c")
        val replacement = target.readBytes() + "\n/* detached candidate */\n".toByteArray()
        val installedBytes = replacement.copyOf()
        val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
        val deltas = graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to replacement))
        replacement.fill(0)
        assertContentEquals(installedBytes, target.readBytes())
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (deltas as MutableList<RevisionFileDelta>).clear()
        }

        val accepted = graph.accept(attempt, RepairEvidence("valid", "detached acceptance"))
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (accepted.changes as MutableList<RevisionFileDelta>).clear()
        }
        val snapshot = graph.snapshot
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (snapshot.nodes as MutableList<ModuleRevisionNode>).clear()
        }
        graph.close()
        assertFailsWith<IllegalStateException> { graph.snapshot }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (snapshot.nodes.first().changedModules as MutableList<String>).add("forged")
        }

        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { reopened ->
            assertContentEquals(installedBytes, target.readBytes())
            assertEquals(listOf("original"), reopened.retainedRegressionCorpus().inputs.single().args)
            assertContentEquals(byteArrayOf(1, 2, 3), reopened.retainedRegressionCorpus().inputs.single().stdin)
        }
    }

    private fun generatedProject(): Path {
        val project = createTempDirectory("module-revision-").resolve("project")
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = "a".repeat(64),
                functions = listOf(
                    RecoveredFunction(
                        id = "fn_alpha",
                        name = "alpha_run",
                        address = 0x1000UL,
                        prototype = "int alpha_run(void)",
                        calls = setOf("fn_beta"),
                    ),
                    RecoveredFunction("fn_beta", "beta_read", 0x2000UL, "int beta_read(void)"),
                    RecoveredFunction("fn_charlie", "charlie_emit", 0x3000UL, "int charlie_emit(void)"),
                    RecoveredFunction("fn_delta", "delta_idle", 0x4000UL, "int delta_idle(void)"),
                ),
            ),
            project,
        )
        return project
    }

    private data class ReleaseRepairFixture(
        val project: Path,
        val relativePath: String,
        val after: ByteArray,
        val receiptPath: String,
        val requestSha256: String,
    )

    /** Reuses synthetic qualified ACP/validation evidence; does not qualify a real provider. */
    internal fun releaseProjectWithRejectedInvocation(record: (ModuleRevisionGraph, Path) -> Unit): Path =
        releaseRepairFixture(includeProvisional = true, beforeAcceptedAttempt = record).project

    private fun releaseRepairFixture(
        includeProvisional: Boolean = false,
        abandonProvisional: Boolean = false,
        beforeAcceptedAttempt: ((ModuleRevisionGraph, Path) -> Unit)? = null,
    ): ReleaseRepairFixture {
        require(!abandonProvisional || includeProvisional)
        val project = generatedProject()
        val relative = "src/modules/alpha.c"
        val target = project.resolve(relative)
        val before = target.readBytes()
        val after = before + "\n/* archive release ACP repair */\n".toByteArray()
        lateinit var binding: RepairAgentInvocationBinding
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("archive-case", emptyList(), byteArrayOf())))
            graph.beginRun((if (includeProvisional && !abandonProvisional) 2 else 1) +
                (if (beforeAcceptedAttempt != null) 1 else 0), 60_000)
            fun bindObservations(proof: RepairValidationProof) {
                graph.bindOriginalBinary(requireNotNull(proof.originalBinarySha256))
                graph.bindExpectedObservations(sha256(buildString {
                    append(proof.originalBinarySha256).append('\n')
                    corpus.inputs.forEach { input ->
                        append(input.id.length).append(':').append(input.id).append(":0:")
                            .append(sha256(byteArrayOf())).append(':').append(sha256(byteArrayOf())).append('\n')
                    }
                }.toByteArray()))
            }
            if (includeProvisional) {
                val path = "src/modules/beta.c"
                val betaBefore = project.resolve(path).readBytes()
                val betaAfter = betaBefore + "\n/* provisional archive improvement */\n".toByteArray()
                val provisional = graph.beginAttempt(listOf(path), RevisionRepairMetadata(
                    iterationIndex = 1, failureKind = "compile", prompt = "bounded failure", summary = null,
                    retainedRegressionIds = corpus.inputs.map(ProcessInput::id), before = null,
                    regressionCorpusSha256 = corpus.sha256))
                graph.persistAndBindAgentInvocation(provisional,
                    completeAcpReceiptDocument(project, provisional, path, betaBefore, betaAfter))
                graph.installCandidate(provisional, mapOf(path to betaAfter))
                val proof = archiveValidationProofFixture(graph, provisional, project, corpus.inputs,
                    matched = false, receiptName = "archive-provisional.validation.json")
                bindObservations(proof)
                graph.recordProvisional(provisional, RepairEvidence("behavior", "synthetic retained mismatch"), proof)
                assertContentEquals(betaBefore, project.resolve(path).readBytes())
                if (abandonProvisional) {
                    graph.finishRun(RepairRunStatus.ITERATION_EXHAUSTED, RepairEvidence("exhausted", "synthetic attempt budget exhausted"))
                    graph.beginRun(1, 60_000)
                }
            }
            beforeAcceptedAttempt?.invoke(graph, project)
            val attempt = graph.beginAttempt(
                listOf(relative),
                RevisionRepairMetadata(
                    iterationIndex = graph.snapshot.nodes.count { it.repairMetadata != null } + 1,
                    failureKind = "compile",
                    prompt = "bounded failure",
                    summary = null,
                    retainedRegressionIds = corpus.inputs.map(ProcessInput::id),
                    before = null,
                    regressionCorpusSha256 = corpus.sha256,
                ),
            )
            val document = completeAcpReceiptDocument(project, attempt, relative, before, after)
            graph.persistAndBindAgentInvocation(attempt, document)
            graph.installCandidate(attempt, mapOf(relative to after))
            val proof = archiveValidationProofFixture(graph, attempt, project, corpus.inputs)
            bindObservations(proof)
            val accepted = graph.accept(attempt, RepairEvidence("valid", "synthetic archive fixture observations matched"), proof)
            binding = requireNotNull(accepted.repairMetadata?.agentInvocation)
            graph.synchronizeRepairHistory()
        }
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        return ReleaseRepairFixture(project, relative, after, binding.receiptPath, binding.requestSha256)
    }

    /** Synthetic serialization fixture only; this never qualifies the real validation provider. */
    private fun archiveValidationProofFixture(
        graph: ModuleRevisionGraph,
        attempt: ModuleRevisionAttempt,
        project: Path,
        inputs: List<ProcessInput>,
        matched: Boolean = true,
        receiptName: String = "archive-fixture.validation.json",
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
        val tools = JsonObject(decompengine.project.GeneratedCRepairRuntimeConfiguration.TOOL_NAMES.mapValues { (role, name) ->
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
                    "stderrBase64" to if (!matched && role == "candidate") "ZGlmZg==" else "",
                    "networkIsolated" to true), "sandboxSha256" to sandboxDigest,
                "sandboxFields" to fields.map { listOf(it.key, it.value) }, "writableQuota" to outputQuota,
                "cleanupVerified" to true)
        }
        val receipt = obj("schemaVersion" to 1, "provider" to "generated-c-linux-bubblewrap-cgroup-v1",
            "profileId" to GeneratedCRepairIndexProfile.profileId(), "profileSha256" to snapshot.profileSha256,
            "indexSha256" to snapshot.indexSha256, "sourceRevisionSha256" to sourceDigest,
            "regressionCorpusSha256" to repairRegressionCorpusSha256(inputs), "runtimeSha256" to runtimeDigest,
            "runtimeConfiguration" to runtime,
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
            "outcome" to "behavior-checked", "caseCount" to inputs.size, "matches" to matched,
            "cleanupVerified" to true, "assurance" to "strict-contained")
        val bytes = canonical(receipt)
        project.resolve("reports/$receiptName").writeBytes(bytes)
        return RepairValidationProof(sourceDigest, snapshot.profileSha256, snapshot.indexSha256,
            repairRegressionCorpusSha256(inputs), referenceDigest, rebuiltDigest, runtimeDigest, sha256(bytes), true,
            RepairValidationAssurance.STRICT_CONTAINED)
    }

    private fun rewriteArchive(
        source: Path,
        target: Path,
        mutation: (MutableMap<String, ByteArray>) -> Unit,
    ) {
        val entries = linkedMapOf<String, ByteArray>()
        ZipInputStream(Files.newInputStream(source)).use { zip ->
            while (true) {
                val entry = zip.nextEntry ?: break
                entries[entry.name] = zip.readBytes()
                zip.closeEntry()
            }
        }
        entries.remove("ARCHIVE_MANIFEST.sha256")
        mutation(entries)
        entries["ARCHIVE_MANIFEST.sha256"] = entries.toSortedMap().entries.joinToString("") { (path, bytes) ->
            "${sha256(bytes)}  $path\n"
        }.toByteArray()
        ZipOutputStream(Files.newOutputStream(target)).use { zip ->
            entries.toSortedMap().forEach { (path, bytes) ->
                val crc = CRC32().apply { update(bytes) }
                val entry = ZipEntry(path).apply {
                    method = ZipEntry.STORED
                    size = bytes.size.toLong()
                    compressedSize = size
                    this.crc = crc.value
                    time = 0L
                }
                zip.putNextEntry(entry)
                zip.write(bytes)
                zip.closeEntry()
            }
        }
    }

    private fun genericProject(prefix: String, files: Map<String, String>): Path {
        val project = createTempDirectory(prefix).resolve("project")
        files.forEach { (relative, content) ->
            val target = project.resolve(relative)
            target.parent.createDirectories()
            target.writeText(content)
        }
        return project
    }

    private fun minimalGeneratedCProject(programModelJson: String): Path = genericProject(
        "repair-generated-evidence-",
        mapOf(
            "Makefile" to "all:\n\t@true\n",
            "include/decomp_types.h" to "#pragma once\n",
            "include/main.h" to "#pragma once\nint main(void);\n",
            "src/main.c" to "#include \"main.h\"\nint main(void) { return 0; }\n",
            "reports/module_plan.json" to
                "{\"schemaVersion\":1,\"modules\":[{\"id\":\"main_module\"," +
                "\"sourcePath\":\"src/main.c\",\"headerPath\":\"include/main.h\"," +
                "\"functionIds\":[\"fn_main\"],\"globalIds\":[],\"boundaryEvidence\":[]}]," +
                "\"dependencyCycles\":[]}",
            "reports/program_model.json" to programModelJson,
        ),
    )

    private fun dependencyOnlyProject(includeDependency: Boolean, globalDependency: Boolean): Path {
        val project = createTempDirectory("repair-dependency-").resolve("project")
        project.resolve("src/modules").createDirectories()
        project.resolve("include/modules").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("Makefile").writeText("all:\n\t@true\n")
        project.resolve("include/decomp_types.h").writeText("#pragma once\n")
        project.resolve("include/modules/consumer.h").writeText("#pragma once\n")
        project.resolve("include/modules/provider.h").writeText("#pragma once\n")
        project.resolve("src/modules/consumer_internal.h").writeText("#pragma once\n")
        project.resolve("src/modules/provider_internal.h").writeText("#pragma once\n")
        val providerInclude = if (includeDependency) "#include \"modules/provider.h\"\n" else ""
        project.resolve("src/modules/consumer.c").writeText(
            "#include \"modules/consumer.h\"\n${providerInclude}int consumer_run(void) { return 0; }\n",
        )
        project.resolve("src/modules/provider.c").writeText(
            "#include \"modules/provider.h\"\nint provider_run(void) { return 0; }\n",
        )
        val providerGlobals = if (globalDependency) "[\"global_state\"]" else "[]"
        val globals = if (globalDependency) {
            "[{\"id\":\"global_state\",\"name\":\"global_state\",\"address\":\"0x3000\",\"type\":\"int\",\"initializer\":null,\"status\":\"recovered\"}]"
        } else {
            "[]"
        }
        val references = if (globalDependency) "[\"global_state\"]" else "[]"
        project.resolve("reports/module_plan.json").writeText(
            "{\"schemaVersion\":1,\"modules\":[" +
                "{\"id\":\"consumer\",\"sourcePath\":\"src/modules/consumer.c\",\"headerPath\":\"include/modules/consumer.h\",\"functionIds\":[\"fn_consumer\"],\"globalIds\":[],\"boundaryEvidence\":[]}," +
                "{\"id\":\"provider\",\"sourcePath\":\"src/modules/provider.c\",\"headerPath\":\"include/modules/provider.h\",\"functionIds\":[\"fn_provider\"],\"globalIds\":$providerGlobals,\"boundaryEvidence\":[]}],\"dependencyCycles\":[]}",
        )
        project.resolve("reports/program_model.json").writeText(
            "{\"schemaVersion\":1,\"inputSha256\":\"fixture\",\"functions\":[" +
                "{\"id\":\"fn_consumer\",\"name\":\"consumer_run\",\"address\":\"0x1\",\"prototype\":\"int consumer_run(void)\",\"status\":\"recovered\",\"calls\":[],\"referencedGlobals\":$references,\"strings\":[],\"decompiledC\":null}," +
                "{\"id\":\"fn_provider\",\"name\":\"provider_run\",\"address\":\"0x2\",\"prototype\":\"int provider_run(void)\",\"status\":\"recovered\",\"calls\":[],\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}],\"globals\":$globals,\"types\":[]}",
        )
        return project
    }

    private fun failedAcpReceiptDocument(
        project: Path,
        attempt: ModuleRevisionAttempt,
    ): AcpExecutionReceiptDocument {
        val request = AgentExecutionRequest(
            objective = "repair one module",
            workspaceRoots = listOf(AgentWorkspaceRoot("project", project)),
            accessPolicy = AgentAccessPolicy(emptyList()),
        )
        val receipt = AgentExecutionReceipt(
            requestBinding = AgentExecutionRequestBinding.capture(request),
            outcome = AgentExecutionOutcome.Failed(
                AgentFailure(AgentFailureKind.PROTOCOL, "peer-controlled failure text"),
            ),
            providerEvidence = AcpInvocationEvidenceSnapshot(
                factoryProvenance = null,
                phaseReached = AcpExecutionLifecyclePhase.REQUEST_BOUND,
                cleanupDisposition = AcpExecutionCleanupDisposition.NOT_REQUIRED,
                negotiatedAgent = null,
                wirePromptSha256 = null,
                diagnostics = null,
                filesystemAudit = emptyList(),
                terminalAudit = emptyList(),
                permissionAudit = emptyList(),
                sandboxEvidence = null,
                completeness = AcpExecutionEvidenceCompleteness(true, true, true),
                completeExecutionEvidence = null,
            ),
        )
        return requireNotNull(
            AcpExecutionReceiptDocument.captureOrNull(
                request,
                sha256("bounded failure".toByteArray()),
                receipt,
                BoundedAgentExecutionEventRecorder().receiptSnapshot(),
                "decomp-engine.trace-repair-acp-execution-receipt",
                "attemptId",
                attempt.id,
            ),
        )
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

    private class SimulatedRepairCrash : Error("simulated repair process crash")
    private class SimulatedRepairTermination : Throwable("simulated non-exception process termination")

    private fun createScaleProject(project: Path, moduleCount: Int, functionsPerModule: Int) {
        project.resolve("src/modules").createDirectories()
        project.resolve("include/modules").createDirectories()
        project.resolve("reports").createDirectories()
        project.resolve("Makefile").writeText("all:\n\t@true\n")
        project.resolve("include/decomp_types.h").writeText("#pragma once\n")

        val modules = (0 until moduleCount).map { index -> "module_${index.toString().padStart(4, '0')}" }
        modules.forEach { module ->
            project.resolve("src/modules/$module.c").writeText("#include \"modules/$module.h\"\n")
            project.resolve("src/modules/${module}_internal.h").writeText("#pragma once\n")
            project.resolve("include/modules/$module.h").writeText("#pragma once\n")
        }
        val functionIds = modules.associateWith { module ->
            (0 until functionsPerModule).map { offset -> "fn_${module}_$offset" }
        }
        project.resolve("reports/module_plan.json").writeText(
            buildString {
                append("{\"schemaVersion\":1,\"modules\":[")
                append(modules.joinToString(",") { module ->
                    "{\"id\":\"$module\",\"sourcePath\":\"src/modules/$module.c\"," +
                        "\"headerPath\":\"include/modules/$module.h\",\"functionIds\":" +
                        functionIds.getValue(module).joinToString(prefix = "[", postfix = "]") { "\"$it\"" } +
                        ",\"globalIds\":[],\"boundaryEvidence\":[]}"
                })
                append("],\"dependencyCycles\":[]}")
            },
        )
        project.resolve("reports/program_model.json").writeText(
            buildString {
                append("{\"schemaVersion\":1,\"inputSha256\":\"scale\",\"functions\":[")
                append(modules.flatMapIndexed { moduleIndex, module ->
                    functionIds.getValue(module).mapIndexed { functionIndex, id ->
                        val calls = if (functionIndex == 0 && moduleIndex > 0) {
                            "[\"${functionIds.getValue(modules[moduleIndex - 1]).first()}\"]"
                        } else {
                            "[]"
                        }
                        "{\"id\":\"$id\",\"name\":\"${module}_function_$functionIndex\"," +
                            "\"address\":\"0x1\",\"prototype\":\"int f(void)\",\"status\":\"recovered\"," +
                            "\"calls\":$calls,\"referencedGlobals\":[],\"strings\":[],\"decompiledC\":null}"
                    }
                }.joinToString(","))
                append("],\"globals\":[],\"types\":[]}")
            },
        )
    }
}
