package decompengine.repair

import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentWorkspacePath
import decompengine.project.agentFileChangeSetSha256
import decompengine.project.sha256
import decompengine.validation.ProcessInput
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.*
import kotlinx.serialization.json.*

/** Authored controls are test-only and do not qualify native execution or reader authority. */
class RepairHistorySnapshotTest {
    private val budget = RepairResourceBudget()
    private val profile = DeclarativeRepairIndexProfile("PRIVATE-profile-canary",
        RepairIndexLayout(listOf("code.c"), listOf("code.c"),
            modules = listOf(RepairModuleEvidence("PRIVATE-module-canary", listOf("code.c")))))
    private val inputs = listOf(ProcessInput("PRIVATE-case-<script>", listOf("PRIVATE-argv"), "PRIVATE-stdin".toByteArray()),
        ProcessInput("PRIVATE-other-case", emptyList(), byteArrayOf()))

    @Test
    fun recordedPagesKeepOneCaptureDisjointRowsPendingAndBoundedCaseReferences() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            graph.retainRegressionInputs(List(25) { ProcessInput("PRIVATE-case-${it.toString().padStart(3, '0')}") })
            repeat(3) { index ->
                val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph, index + 1))
                graph.installCandidate(attempt, mapOf("code.c" to "candidate-$index".toByteArray()))
                graph.reject(attempt)
            }
            val pending = graph.beginAttempt(listOf("code.c"), metadata(graph, 4))
            val snapshot = view(capture(root))
            val latest = RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 2)
            val older = RepairRecordedHistoryPage.select(snapshot,
                RepairRecordedHistorySelection(2, expectedGraphSha256 = snapshot.graphSha256), 2)
            assertEquals(2, latest.totalPages)
            assertEquals(listOf(2, 3, 4), latest.attempts.map { it.iterationIndex })
            assertEquals(listOf(1), older.attempts.map { it.iterationIndex })
            assertTrue(older.attempts.none { it.kind == RepairRecordedAttemptKind.PENDING })
            val pendingEvidence = RepairRecordedHistoryPage.select(snapshot,
                RepairRecordedHistorySelection(expectedGraphSha256 = snapshot.graphSha256, evidenceAttempt = pending.id), 2)
            assertEquals(listOf(pending.id), pendingEvidence.evidenceAttempts.map { it.identity.value })
            assertEquals(RepairRecordedAttemptKind.PENDING, pendingEvidence.evidenceAttempts.single().kind)
            assertEquals(snapshot.attempts.map { it.identity }, (older.attempts +
                latest.attempts.filter { it.kind == RepairRecordedAttemptKind.FINALIZED }).map { it.identity })
            val secondCases = RepairRecordedHistoryPage.select(snapshot,
                RepairRecordedHistorySelection(1, 2, snapshot.graphSha256), 2)
            val attempt = latest.attempts.first()
            assertEquals(20, latest.caseReferences(attempt).size)
            assertEquals(5, secondCases.caseReferences(attempt).size)
            assertEquals(attempt.retainedCases, latest.caseReferences(attempt) + secondCases.caseReferences(attempt))
            assertFailsWith<IllegalArgumentException> { latest.caseReferences(older.attempts.single()) }
            assertFailsWith<IllegalArgumentException> {
                RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 101)
            }
            for (selection in listOf(RepairRecordedHistorySelection(Int.MAX_VALUE, 1, snapshot.graphSha256),
                RepairRecordedHistorySelection(1, Int.MAX_VALUE, snapshot.graphSha256))) {
                val failure = assertFailsWith<RepairRecordedSelectionFailure> {
                    RepairRecordedHistoryPage.select(snapshot, selection, 2)
                }
                assertEquals(RepairRecordedSelectionProblem.OUT_OF_RANGE, failure.problem)
            }
            val changed = assertFailsWith<RepairRecordedSelectionFailure> {
                RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(1, 1, "0".repeat(64)), 2)
            }
            assertEquals(RepairRecordedSelectionProblem.CHANGED, changed.problem)
            graph.reject(pending)
            assertEquals(pending.id, latest.attempts.last().identity.value) // Capture remains immutable after producer writes.
        }
    }

    @Test
    fun recordedRunPagesReachEveryRunWhenNoAttemptsWereMadeAndEmptyHistoryHasOnePage() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            val empty = RepairRecordedHistoryPage.select(view(capture(root)), RepairRecordedHistorySelection(), 2)
            assertEquals(1, empty.totalPages)
            assertTrue(empty.attempts.isEmpty() && empty.runs.isEmpty())
            repeat(5) {
                graph.beginRun(1, 60_000)
                graph.finishRun(RepairRunStatus.CANCELLED, RepairEvidence("cancelled", "authored before execution"))
            }
            val snapshot = view(capture(root))
            val pages = (1..3).map { number -> RepairRecordedHistoryPage.select(snapshot,
                RepairRecordedHistorySelection(number, 1, snapshot.graphSha256), 2) }
            assertTrue(pages.all { it.totalPages == 3 && it.attempts.isEmpty() && it.runs.size <= 2 })
            assertEquals(snapshot.runs.map { it.identity }, pages.reversed().flatMap { it.runs }.map { it.identity })
        }
    }

    @Test
    fun historicalAttemptRetainsItsOwnCorpusAndCaseReferencesAfterCorpusGrowth() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            graph.retainRegressionInputs(inputs.take(1))
            val firstCorpus = graph.retainedRegressionCorpus()
            val first = graph.beginAttempt(listOf("code.c"), metadata(graph, 1))
            graph.installCandidate(first, mapOf("code.c" to "first candidate".toByteArray()))
            graph.reject(first, RepairEvidence("rejected", "PRIVATE-peer"))
            val firstView = view(capture(root)).attempts.single()
            assertEquals(firstCorpus.sha256, firstView.corpusSha256)
            val firstReference = firstView.retainedCases.single()

            graph.retainRegressionInputs(inputs)
            val expanded = graph.retainedRegressionCorpus()
            assertNotEquals(firstCorpus.sha256, expanded.sha256)
            val second = graph.beginAttempt(listOf("code.c"), metadata(graph, 2))
            graph.installCandidate(second, mapOf("code.c" to "second candidate".toByteArray()))
            graph.reject(second, RepairEvidence("rejected", "PRIVATE-peer"))
            val captured = view(capture(root))
            val historical = captured.attempts.first()
            val latest = captured.attempts.last()
            assertEquals(firstCorpus.sha256, historical.corpusSha256)
            assertEquals(firstReference, historical.retainedCases.single())
            assertEquals(expanded.sha256, latest.corpusSha256)
            assertEquals(expanded.sha256, captured.corpusSha256)
            val expandedReference = RepairHistoryIdentityReferences(expanded.sha256).case(firstCorpus.inputs.single().id)
            assertTrue(expandedReference in latest.retainedCases)
            assertNotEquals(firstReference, expandedReference)
            assertFalse("PRIVATE" in publicSurface(captured))
            assertEquals("base", root.resolve("code.c").readText())
        }
    }

    @Test
    fun actualPendingAndOrdinaryRestorationRetainCompleteRecords() {
        val root = root()
        val progress = mutableListOf<Captured>()
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                point.scope == "revision-state" && point.name == "graph.json") {
                val captured = capture(root)
                val pending = Json.parseToJsonElement(captured.graph.decodeToString()).jsonObject["pending"] as? JsonObject
                if ((pending?.get("rollbackRecord") as? JsonObject)?.get("state")?.jsonPrimitive?.content == "restore_in_progress") {
                    progress += captured
                }
            }
        }).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            assertEquals(attempt.id, view(capture(root)).pending?.identity?.value)
            assertEquals("pending", recordedRepairAttemptLabel(requireNotNull(view(capture(root)).pending)))
            assertNull(view(capture(root)).pending?.rollback)
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            val rejected = graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-peer"))
            val snapshot = view(capture(root))
            val record = requireNotNull(snapshot.attempts.last().rollback)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, record.state)
            assertEquals(attempt.id, record.attempt.value)
            assertEquals(rejected.rollbackRecord?.expectedSourceRevisionSha256, record.expectedSourceRevisionSha256)
            assertEquals(record.expectedSourceRevisionSha256, record.observedSourceRevisionSha256)
            assertEquals(snapshot.publishedHead, record.target)
            assertEquals(true, record.candidateSourceInstallStarted)
            assertFalse(record.legacyPendingStateUnknown)
            assertNull(record.failureCode)
            assertNull(snapshot.pending)
            assertNull(snapshot.fullyAcceptedHead)
            assertNotEquals(snapshot.publishedHead, snapshot.attempts.last().identity)
        }
        assertTrue(progress.isNotEmpty())
        val record = requireNotNull(view(progress.last()).pending?.rollback)
        assertEquals(RepairRollbackState.RESTORE_IN_PROGRESS, record.state)
        assertNull(record.observedSourceRevisionSha256)
        assertEquals("base", root.resolve("code.c").readText())
    }

    @Test
    fun actualStandaloneFailureAndRecoveryRetainTheFailure() {
        val root = root()
        var armed = false
        var id = ""
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (armed && point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "rollback") throw RestoreFailure()
        }).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c")); id = attempt.id
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            armed = true
            assertFailsWith<RestoreFailure> { graph.reject(attempt) }
            val snapshot = view(capture(root))
            assertTrue(snapshot.runs.isEmpty())
            assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, snapshot.pending?.rollback?.state)
            assertNotNull(snapshot.pending?.rollback?.failureCode)
        }
        ModuleRevisionGraph.open(root, profile).close()
        val snapshot = view(capture(root))
        assertNull(snapshot.pending)
        val record = requireNotNull(snapshot.attempts.last().rollback)
        assertEquals(id, record.attempt.value)
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, record.state)
        assertNotNull(record.failureStage); assertNotNull(record.failureCode)
        assertEquals(record.expectedSourceRevisionSha256, record.observedSourceRevisionSha256)
        assertEquals("base", root.resolve("code.c").readText())
    }

    @Test
    fun actualDetachedRejectionProvesNotRequiredWithoutPromotion() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            startRun(graph)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            assertEquals("base", root.resolve("code.c").readText())
            graph.reject(attempt)
            val record = requireNotNull(view(capture(root)).attempts.last().rollback)
            assertEquals(RepairRollbackState.NOT_REQUIRED_VERIFIED, record.state)
            assertEquals(false, record.candidateSourceInstallStarted)
            assertEquals(record.expectedSourceRevisionSha256, record.observedSourceRevisionSha256)
            assertEquals("base", root.resolve("code.c").readText())
        }
    }

    @Test
    fun actualRunFailureKeepsItsHistoricalOutcomeAfterRecovery() {
        val root = root()
        var armed = false
        var id = ""
        ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
            if (point is ModuleRevisionFaultPoint.AfterPublicationExchange && point.phase == "promotion") throw PromotionFailure()
            if (point is ModuleRevisionFaultPoint.BeforeRollbackExchange && point.phase == "promotion") throw PromotionRollbackFailure()
            if (armed && point is ModuleRevisionFaultPoint.BeforePublicationExchange && point.phase == "promotion-rollback") throw RestoreFailure()
        }).use { graph ->
            startRun(graph)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph)); id = attempt.id
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            assertFailsWith<PromotionFailure> { graph.accept(attempt, RepairEvidence("valid", "fixture"), proof(graph, attempt)) }
            armed = true
            assertFailsWith<RestoreFailure> { graph.reject(attempt) }
            val snapshot = view(capture(root))
            assertEquals(RepairRunStatus.ROLLBACK_FAILED, snapshot.runs.single().status)
            assertEquals(snapshot.pending?.identity, snapshot.runs.single().rollbackFailureAttempt)
            assertEquals(RepairRollbackState.RESTORE_FAILED_UNRESOLVED, snapshot.runs.single().rollbackResolution)
            assertEquals(1, snapshot.runs.single().attemptedCount)
            assertEquals(1, snapshot.runs.single().remainingAttempts)
            assertNull(snapshot.fullyAcceptedHead)
            assertTrue(snapshot.attempts.isEmpty())
            val failedBytes = capture(root)
            refuse(reseal(failedBytes) { json ->
                val runs = json.getValue("runs").jsonArray.toMutableList()
                runs[0] = JsonObject(runs[0].jsonObject + ("rollbackFailureAttemptId" to JsonPrimitive("revision_99999999_aaaaaaaaaaaaaaaa")))
                JsonObject(json + ("runs" to JsonArray(runs)))
            })
            refuse(reseal(failedBytes) { json ->
                val runs = json.getValue("runs").jsonArray.toMutableList()
                val downgraded = runs[0].jsonObject - "rollbackFailureAttemptId" - "rollbackResolution"
                runs[0] = JsonObject(downgraded + mapOf("schemaVersion" to JsonPrimitive(1), "status" to JsonPrimitive("validation_failed")))
                JsonObject(json + ("runs" to JsonArray(runs)))
            })
        }
        ModuleRevisionGraph.open(root, profile).close()
        val snapshot = view(capture(root))
        assertEquals(RepairRunStatus.ROLLBACK_FAILED, snapshot.runs.single().status)
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, snapshot.runs.single().rollbackResolution)
        assertEquals(id, snapshot.runs.single().rollbackFailureAttempt?.value)
        assertEquals(snapshot.attempts.last().identity, snapshot.runs.single().rollbackFailureAttempt)
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, snapshot.attempts.last().rollback?.state)
        ModuleRevisionGraph.open(root, profile).use { graph ->
            startRun(graph)
            val later = graph.beginAttempt(listOf("code.c"), metadata(graph, 2))
            graph.installCandidate(later, mapOf("code.c" to "later-accepted".toByteArray()))
            graph.accept(later, RepairEvidence("valid", "later fixture"), proof(graph, later))
        }
        val later = view(capture(root))
        assertEquals(RepairRunStatus.ROLLBACK_FAILED, later.runs.first().status)
        assertEquals(RepairRollbackState.RESTORED_AFTER_FAILURE, later.runs.first().rollbackResolution)
        assertEquals(id, later.runs.first().rollbackFailureAttempt?.value)
        assertEquals(RepairRunStatus.FULLY_ACCEPTED, later.runs.last().status)
        assertNotEquals(later.runs.first().rollbackFailureAttempt, later.fullyAcceptedHead)
    }

    @Test
    fun genuineLegacyMigrationRetainsUnknownChangedAndKnownUnchangedMarkers() {
        for (changed in listOf(false, true)) {
            val root = root()
            ModuleRevisionGraph.open(root, profile).use { graph ->
                val attempt = graph.beginAttempt(listOf("code.c")) // Actual pre-marker schema2.
                if (changed) graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            }
            assertFailsWith<MarkerCrash> {
                ModuleRevisionGraph.openForTesting(root, profile, faultInjector = ModuleRevisionFaultInjector { point ->
                    if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                        point.scope == "revision-state" && point.name == "graph.json") throw MarkerCrash()
                }).close()
            }
            val pending = requireNotNull(view(capture(root)).pending?.rollback)
            assertTrue(pending.legacyPendingStateUnknown)
            assertEquals(if (changed) null else false, pending.candidateSourceInstallStarted)
            ModuleRevisionGraph.open(root, profile).close()
            val final = requireNotNull(view(capture(root)).attempts.last().rollback)
            assertTrue(final.legacyPendingStateUnknown)
            assertEquals(if (changed) null else false, final.candidateSourceInstallStarted)
            assertEquals(if (changed) RepairRollbackState.RESTORED_VERIFIED else RepairRollbackState.NOT_REQUIRED_VERIFIED, final.state)
        }
    }

    @Test
    fun actualProvisionalAndAcceptedHeadsRemainDifferentClaims() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            startRun(graph)
            val first = graph.beginAttempt(listOf("code.c"), metadata(graph))
            graph.installCandidate(first, mapOf("code.c" to "candidate".toByteArray()))
            graph.recordProvisional(first, RepairEvidence("behavior", "PRIVATE-peer"), proof(graph, first))
            val provisional = view(capture(root))
            assertEquals(first.id, provisional.provisionalHead?.value)
            assertEquals("provisional", recordedRepairAttemptLabel(provisional.attempts.last()))
            assertNull(provisional.fullyAcceptedHead)
            assertNotEquals(provisional.publishedHead, provisional.provisionalHead)
            val second = graph.beginAttempt(listOf("code.c"), metadata(graph, 2))
            graph.installCandidate(second, mapOf("code.c" to "accepted".toByteArray()))
            graph.accept(second, RepairEvidence("valid", "PRIVATE-peer"), proof(graph, second))
            val accepted = view(capture(root))
            assertEquals(second.id, accepted.fullyAcceptedHead?.value)
            assertEquals(accepted.publishedHead, accepted.fullyAcceptedHead)
            assertNull(accepted.provisionalHead)
            assertEquals(RepairRunStatus.FULLY_ACCEPTED, accepted.runs.single().status)
            assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY, accepted.qualification)
            assertEquals(RepairPublicationMode.TEST_ONLY_NON_RELEASE, accepted.attempts.last().publicationMode)
            assertEquals("accepted", recordedRepairAttemptLabel(accepted.attempts.last()))
        }
    }

    @Test
    fun genuinePreContractAcceptedNodeRemainsExplicitlyUnverified() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "legacy-candidate".toByteArray()))
            graph.accept(attempt, RepairEvidence("valid", "historical fixture"))
        }
        val snapshot = view(capture(root))
        assertEquals(2, snapshot.graphSchemaVersion)
        assertNull(snapshot.fullyAcceptedHead)
        assertEquals(ModuleRevisionStatus.LEGACY_UNVERIFIED, snapshot.attempts.single().status)
        assertEquals("unverified", recordedRepairAttemptLabel(snapshot.attempts.single()))
        assertEquals(snapshot.publishedHead, snapshot.attempts.single().identity)
        assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY, snapshot.qualification)
    }

    @Test
    fun immutableViewWithholdsPrivateTextAndRetainsDistinctCorpusReferences() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            startRun(graph)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph))
            graph.installCandidate(attempt, mapOf("code.c" to "PRIVATE-source-body".toByteArray()))
            graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-peer"))
        }
        val captured = capture(root)
        val sourceBefore = root.resolve("code.c").readBytes()
        val snapshot = view(captured)
        val surface = publicSurface(snapshot)
        for (text in listOf("PRIVATE-", "code.c", "reports/", "bounded private prompt")) assertFalse(surface.contains(text), surface)
        assertEquals(inputs.size, snapshot.retainedCases.size)
        assertEquals(inputs.size, snapshot.retainedCases.toSet().size)
        assertTrue(snapshot.retainedCases.all { it.rawIdentityWithheld && it.value.startsWith("case_") })
        assertEquals(snapshot.retainedCases, snapshot.attempts.last().retainedCases)
        val bytes = inputs.first().id.toByteArray()
        val expected = "case_" + sha256(("decompengine.repair.public-case.v1\n" + snapshot.corpusSha256 + "\n" + bytes.size + ":").toByteArray() + bytes)
        assertEquals(expected, snapshot.retainedCases.first().value)
        assertFailsWith<UnsupportedOperationException> { (snapshot.attempts as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (snapshot.runs as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (snapshot.retainedCases as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (snapshot.attempts.last().retainedCases as MutableList<*>).clear() }
        captured.graph.fill(0); captured.binding.fill(0)
        assertEquals(surface, publicSurface(snapshot))
        assertContentEquals(sourceBefore, root.resolve("code.c").readBytes())
    }

    @Test
    fun publicArtifactAndTerminalReferencesWithholdPrivateStringsAndBindTheCapturedCorpus() {
        val root = root()
        val beforePath = "reports/PRIVATE-before.json"
        val afterPath = "reports/PRIVATE-after.json"
        ModuleRevisionGraph.open(root, profile).use { graph ->
            startRun(graph)
            val metadata = metadata(graph).copy(before = RepairEvidence("compile", "PRIVATE-diagnostic", beforePath))
            val attempt = graph.beginAttempt(listOf("code.c"), metadata)
            graph.installCandidate(attempt, mapOf("code.c" to "PRIVATE-source".toByteArray()))
            graph.reject(attempt, RepairEvidence("private-evidence-kind-canary", "PRIVATE-peer", afterPath))
        }
        val bound = bindNode(capture(root), "rejected")
        val privateTerminal = "failed-private-terminal-canary"
        val captured = reseal(bound) { json -> editLastMetadata(json) { metadata ->
            val invocation = metadata.getValue("agentInvocation").jsonObject
            JsonObject(metadata + ("agentInvocation" to JsonObject(invocation + mapOf(
                "terminalOutcome" to JsonPrimitive(privateTerminal), "receiptReleaseComplete" to JsonPrimitive(false),
            ))))
        } }
        val snapshot = view(captured)
        val attempt = snapshot.attempts.single()
        assertEquals(4, snapshot.viewSchemaVersion)
        assertEquals(1, attempt.iterationIndex)
        assertEquals(RepairRecordedFailureKind.COMPILE, attempt.failureKind)
        assertEquals(RepairRecordedEvidenceKind.BUILD, attempt.before?.kind)
        assertEquals(RepairRecordedEvidenceKind.OTHER, attempt.after?.kind)
        val expected = recordedRepairArtifactReference(snapshot.corpusSha256, beforePath)
        assertEquals(expected, attempt.before?.artifact)
        assertNotEquals(expected, attempt.after?.artifact)
        assertNotEquals(expected, recordedRepairArtifactReference("0".repeat(64), beforePath))
        assertNotEquals(expected, recordedRepairArtifactReference(snapshot.corpusSha256, beforePath + "x"))
        val invocation = requireNotNull(attempt.invocation)
        assertEquals(RepairRecordedTerminal.OTHER, invocation.terminal)
        assertEquals(recordedRepairTerminalSha256(privateTerminal), invocation.terminalSha256)
        assertEquals(RepairRecordedReceiptStatus.NOT_READ, invocation.receiptStatus)
        assertEquals("rejected", recordedRepairAttemptLabel(attempt))
        assertEquals(recordedRepairArtifactReference(snapshot.corpusSha256,
            "reports/repair-revisions/${attempt.identity.value}.acp-receipt.json"), invocation.artifact)
        val surface = publicSurface(snapshot)
        for (private in listOf("PRIVATE-", privateTerminal, "private-evidence-kind-canary", "code.c", "reports/", "bounded private prompt"))
            assertFalse(private in surface, surface)
    }

    @Test
    fun opaqueReferenceCollisionRefusesWithoutLeakingPrivateValues() {
        val table = RepairHistoryIdentityReferences("a".repeat(64))
        assertTrue(table.revision("revision_PRIVATE_legacy").rawIdentityWithheld)
        assertNotEquals(table.revision("revision_PRIVATE_one"), table.revision("revision_PRIVATE_two"))
        val method = table.javaClass.getDeclaredMethod("register", String::class.java, String::class.java).also { it.isAccessible = true }
        method.invoke(table, "opaque_authored_collision", "PRIVATE-first")
        method.invoke(table, "opaque_authored_collision", "PRIVATE-first")
        val failure = assertFailsWith<InvocationTargetException> { method.invoke(table, "opaque_authored_collision", "PRIVATE-second") }.targetException
        assertIs<IllegalArgumentException>(failure)
        assertEquals("Recorded identity reference collision.", failure.message)
        assertFalse(failure.message.orEmpty().contains("PRIVATE-"))
    }

    @Test
    fun recordedRollbackLabelsDistinguishAllStatesAndNeverCompleteUnknownLegacyRestoration() {
        val restored = requireNotNull(view(restored()).attempts.last().rollback)
        val labels = RepairRollbackState.entries.associateWith { state ->
            recordedRepairRollbackLabel(restored.copy(state = state))
        }
        assertEquals(RepairRollbackState.entries.size, labels.values.toSet().size)
        assertTrue(labels.getValue(RepairRollbackState.RESTORE_IN_PROGRESS).contains("in progress"))
        assertTrue(labels.getValue(RepairRollbackState.RESTORE_FAILED_UNRESOLVED).contains("failed and remains unresolved"))
        assertTrue(labels.getValue(RepairRollbackState.RESTORED_VERIFIED).contains("completed and was verified"))
        assertTrue(labels.getValue(RepairRollbackState.RESTORED_AFTER_FAILURE).contains("earlier failure is retained"))
        assertTrue(labels.getValue(RepairRollbackState.NOT_REQUIRED_VERIFIED).contains("did not begin"))
        for (state in RepairRollbackState.entries) {
            val label = recordedRepairRollbackLabel(restored.copy(state = state, legacyPendingStateUnknown = true))
            assertTrue(label.startsWith("Unverified;"))
            assertFalse("completed" in label)
        }
        assertTrue(recordedRepairRollbackLabel(null).startsWith("Unverified;"))
    }

    @Test
    fun underCapFacadeNeverTouchesDeclaredInputCollection() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { it.enableRunContract() }
        val captured = capture(root)
        val denied = object : AbstractList<RepairHistoryDeclaredGraph>() {
            override val size: Int get() = error("PRIVATE-declared scan forbidden")
            override fun get(index: Int): RepairHistoryDeclaredGraph = error("PRIVATE-declared read forbidden")
        }
        val snapshot = recordedRepairHistorySnapshot(captured.graph, captured.binding, budget, denied)
        assertTrue(snapshot.runs.isEmpty()); assertNull(snapshot.pending); assertNull(snapshot.fullyAcceptedHead)
        assertEquals(sha256(captured.graph), snapshot.graphSha256)
    }

    @Test
    fun rawWireBindingAndCompleteRollbackTamperingHaveClosedRefusals() {
        val captured = restored()
        val canonical = captured.graph.decodeToString()
        refuse(reseal(captured) { root ->
            val nodes = root.getValue("nodes").jsonArray.toMutableList()
            val row = nodes.last().jsonObject
            val record = row.getValue("rollbackRecord").jsonObject
            nodes[nodes.lastIndex] = JsonObject(row + ("rollbackRecord" to JsonObject(record +
                ("targetRevisionId" to JsonPrimitive("root_" + "0".repeat(24))))))
            JsonObject(root + ("nodes" to JsonArray(nodes)))
        })
        refuse(captured.copy(graph = (canonical + " ").toByteArray()))
        refuse(captured.copy(graph = canonical.replaceFirst("\"schemaVersion\": 4,", "\"schemaVersion\": 4,\n  \"unknown\": true,").toByteArray()))
        refuse(captured.copy(binding = captured.binding.decodeToString().replaceFirst("\"budgetSha256\": \"", "\"budgetSha256\": \"0").toByteArray()))
        val expected = Json.parseToJsonElement(canonical).jsonObject.getValue("nodes").jsonArray.last().jsonObject
            .getValue("rollbackRecord").jsonObject.getValue("expectedSourceRevisionSha256").jsonPrimitive.content
        val replacement = "0".repeat(64)
        refuse(captured.copy(graph = canonical.replace("\"expectedSourceRevisionSha256\":\"$expected\"", "\"expectedSourceRevisionSha256\":\"$replacement\"").toByteArray()))
        refuse(captured.copy(graph = canonical.replace("\"candidateSourceInstallStarted\":true", "\"candidateSourceInstallStarted\":false").toByteArray()))
        refuse(captured.copy(graph = canonical.replace("\"observedSourceRevisionSha256\":\"$expected\"", "\"observedSourceRevisionSha256\":null").toByteArray()))
        assertFailsWith<RepairHistorySnapshotRefusal> { recordedRepairHistorySnapshot(captured.graph, captured.binding, budget.copy(maximumGraphBytes = 1024)) }
    }

    @Test
    fun resealedTopologyCorpusAndRunProofMismatchesReachSemanticChecks() {
        val captured = accepted()
        refuse(reseal(captured) { root ->
            val proof = root.getValue("acceptedProof").jsonObject
            JsonObject(root + ("acceptedProof" to JsonObject(proof + ("sourceRevisionSha256" to JsonPrimitive("0".repeat(64))))))
        })
        refuse(reseal(captured) { JsonObject(it + ("regressionCorpusSha256" to JsonPrimitive("0".repeat(64)))) })
        refuse(reseal(captured) { root ->
            val runs = root.getValue("runs").jsonArray.toMutableList()
            runs[0] = JsonObject(runs[0].jsonObject + ("attemptedCount" to JsonPrimitive(0)))
            JsonObject(root + ("runs" to JsonArray(runs)))
        })
        refuse(reseal(captured) { root ->
            val nodes = root.getValue("nodes").jsonArray.toMutableList()
            nodes[1] = JsonObject(nodes[1].jsonObject + ("parentId" to JsonPrimitive("root_" + "0".repeat(24))))
            JsonObject(root + ("nodes" to JsonArray(nodes)))
        })
    }

    @Test
    fun ACPAssociationIsValidatedButReceiptContentsRemainUnread() {
        val captured = restored(withMetadata = true)
        val associated = bindNode(captured, "rejected")
        val invocation = requireNotNull(view(associated).attempts.last().invocation)
        assertEquals(RepairRecordedReceiptStatus.NOT_READ, invocation.receiptStatus)
        assertEquals(RepairAgentAssessmentStatus.REJECTED, invocation.assessment)
        refuse(bindNode(captured, "rejected", wrongPath = true))
        refuse(bindNode(captured, "pending"))
        refuse(reseal(accepted()) { root -> editLastMetadata(root) { metadata ->
            JsonObject(metadata + ("publicationMode" to JsonPrimitive("acp_release")))
        } })
    }

    @Test
    fun pendingAndProvisionalACPResultDigestsMatchTheirExactDelta() {
        for (provisional in listOf(false, true)) {
            val root = root()
            ModuleRevisionGraph.open(root, profile).use { graph ->
                startRun(graph)
                val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph))
                graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
                if (provisional) graph.recordProvisional(attempt, RepairEvidence("behavior", "fixture"), proof(graph, attempt))
                val good = bindNode(capture(root), if (provisional) "provisional" else "pending", pending = !provisional)
                val snapshot = view(good)
                assertEquals(RepairRecordedReceiptStatus.NOT_READ,
                    (if (provisional) snapshot.attempts.last() else requireNotNull(snapshot.pending)).invocation?.receiptStatus)
                refuse(reseal(good) { json -> editMetadata(json, !provisional) { metadata ->
                    val binding = metadata.getValue("agentInvocation").jsonObject
                    JsonObject(metadata + ("agentInvocation" to JsonObject(binding + ("resultChangesSha256" to JsonPrimitive("0".repeat(64))))))
                } })
            }
        }
    }

    @Test
    fun genuineMigrationCreditUsesAdmittedOriginalBytesAndRejectsMissingChangedOrDuplicateInputs() {
        val small = budget.copy(maximumGraphBytes = 16 * 1024)
        val root = root()
        ModuleRevisionGraph.open(root, profile, small).use { graph ->
            val corpus = graph.retainRegressionInputs(inputs)
            val attempt = graph.beginAttempt(listOf("code.c"), RevisionRepairMetadata(1, "compile", "bounded private prompt",
                "LEGACY_PADDING", corpus.inputs.map { it.id }, null, corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        val path = root.resolve("reports/repair-revisions/graph.json")
        val original = path.readText()
        val padding = (small.maximumGraphBytes - original.toByteArray().size).toInt()
        assertTrue(padding > 0)
        path.writeText(original.replace("LEGACY_PADDING", "x".repeat("LEGACY_PADDING".length + padding)))
        assertEquals(small.maximumGraphBytes, path.readBytes().size.toLong())
        assertFailsWith<MarkerCrash> {
            ModuleRevisionGraph.openForTesting(root, profile, small, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync && point.scope == "revision-state" && point.name == "graph.json") throw MarkerCrash()
            }).close()
        }
        val captured = capture(root, small)
        assertTrue(captured.graph.size > small.maximumGraphBytes)
        assertTrue(captured.declared.isNotEmpty())
        assertTrue(view(captured).pending?.rollback?.legacyPendingStateUnknown == true)
        refuse(captured.copy(declared = emptyList()))
        val first = captured.declared.first()
        refuse(captured.copy(declared = listOf(RepairHistoryDeclaredGraph(first.name, first.bytes + byteArrayOf(0)))))
        refuse(captured.copy(declared = captured.declared + first))
    }

    @Test
    fun recoveryWrapperStillChecksProfileThenLayoutThenFreshBlob() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        val captured = capture(root)
        val seen = mutableListOf<String>()
        val denied = object : RepairIndexProfile by profile {
            override fun authorizesRecoveryLayout(sourcePaths: List<String>, editablePaths: List<String>, budget: RepairResourceBudget): Boolean {
                seen += "layout"; return false
            }
        }
        val wrongProfile = object : RepairIndexProfile by denied {
            override fun configurationSha256(budget: RepairResourceBudget): String = "0".repeat(64)
        }
        assertTrue(recoveryFailure(captured, wrongProfile, root).message.orEmpty().contains("fingerprint"))
        assertTrue(seen.isEmpty())
        assertTrue(recoveryFailure(captured, denied, root).message.orEmpty().contains("authorize"))
        assertEquals(listOf("layout"), seen)
        val json = Json.parseToJsonElement(captured.graph.decodeToString()).jsonObject
        val digest = json.getValue("nodes").jsonArray.first().jsonObject.getValue("changes").jsonArray.first().jsonObject
            .getValue("afterBlobSha256").jsonPrimitive.content
        root.resolve("reports/repair-revisions/blobs/$digest").writeText("corrupt")
        assertTrue(recoveryFailure(captured, profile, root).message.orEmpty().contains("blob is corrupt"))
        assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY, view(captured).qualification)
    }

    private data class Captured(val graph: ByteArray, val binding: ByteArray, val budget: RepairResourceBudget,
        val declared: List<RepairHistoryDeclaredGraph> = emptyList())
    private class MarkerCrash : Error()
    private class PromotionFailure : IllegalStateException("authored promotion failure")
    private class PromotionRollbackFailure : IllegalStateException("authored promotion rollback refusal")
    private class RestoreFailure : IllegalStateException("authored restoration refusal")
    @Test
    fun evidenceFocusKeepsMetadataRowsAndRequiresItsCapturedGraphAndVisibleAttempt() {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            graph.enableRunContract()
            repeat(3) { index ->
                val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph, index + 1))
                graph.installCandidate(attempt, mapOf("code.c" to "candidate-$index".toByteArray()))
                graph.reject(attempt)
            }
            val snapshot = view(capture(root))
            val latest = RepairRecordedHistoryPage.select(snapshot, RepairRecordedHistorySelection(), 2)
            val target = latest.attempts.last()
            val selection = RepairRecordedHistorySelection(expectedGraphSha256 = snapshot.graphSha256,
                evidenceAttempt = target.identity.value)
            val focused = RepairRecordedHistoryPage.select(snapshot, selection, 2)
            assertEquals(latest.attempts, focused.attempts)
            assertEquals(latest.runs, focused.runs)
            assertEquals(latest.attempts, latest.evidenceAttempts)
            assertEquals(listOf(target), focused.evidenceAttempts)
            assertEquals(selection, parseRecordedRepairSelection(null, null, snapshot.graphSha256, target.identity.value))
            assertFailsWith<IllegalArgumentException> { RepairRecordedHistorySelection(evidenceAttempt = target.identity.value) }
            for (invalid in listOf("", "../PRIVATE", "%31", "a".repeat(129))) {
                val failure = assertFailsWith<IllegalArgumentException> {
                    RepairRecordedHistorySelection(expectedGraphSha256 = snapshot.graphSha256, evidenceAttempt = invalid)
                }
                assertFalse("PRIVATE" in failure.message.orEmpty())
            }
            val foreign = assertFailsWith<RepairRecordedSelectionFailure> {
                RepairRecordedHistoryPage.select(snapshot, selection.copy(evidenceAttempt = snapshot.attempts.first().identity.value), 2)
            }
            assertEquals(RepairRecordedSelectionProblem.OUT_OF_RANGE, foreign.problem)
            val stale = assertFailsWith<RepairRecordedSelectionFailure> {
                RepairRecordedHistoryPage.select(snapshot, selection.copy(expectedGraphSha256 = "0".repeat(64)), 2)
            }
            assertEquals(RepairRecordedSelectionProblem.CHANGED, stale.problem)
            val absent = assertFailsWith<RepairRecordedSelectionFailure> {
                recordedRepairHistoryPage(RepairHistoryReadResult.absent(), selection, 100)
            }
            assertEquals(RepairRecordedSelectionProblem.UNAVAILABLE, absent.problem)
        }
    }

    private fun root(): Path {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        return Files.createTempDirectory(parent, "recorded-history-").also { it.resolve("code.c").writeText("base") }
    }
    private fun startRun(graph: ModuleRevisionGraph) {
        graph.enableRunContract(); graph.retainRegressionInputs(inputs); graph.beginRun(2, 60_000)
        graph.bindOriginalBinary(sha256("reference".toByteArray())); graph.bindExpectedObservations(sha256("expected".toByteArray()))
    }
    private fun metadata(graph: ModuleRevisionGraph, index: Int = 1): RevisionRepairMetadata {
        val corpus = graph.retainedRegressionCorpus()
        return RevisionRepairMetadata(index, "compile", "bounded private prompt", "PRIVATE-summary", corpus.inputs.map { it.id },
            RepairEvidence("compile", "PRIVATE-diagnostic"), corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE)
    }
    private fun proof(graph: ModuleRevisionGraph, attempt: ModuleRevisionAttempt): RepairValidationProof {
        val state = graph.snapshot
        return RepairValidationProof(repairCandidateSourceSha256(graph.candidateSources(attempt)), state.profileSha256, state.indexSha256,
            graph.retainedRegressionCorpus().sha256, sha256("reference".toByteArray()), sha256("rebuilt".toByteArray()),
            sha256("runtime".toByteArray()), sha256("evidence".toByteArray()), true, RepairValidationAssurance.TEST_ONLY_HOST_PROCESS)
    }
    private fun capture(root: Path, selectedBudget: RepairResourceBudget = budget): Captured {
        val revisions = root.resolve("reports/repair-revisions")
        val declared = Files.newDirectoryStream(revisions, "legacy-graph-*.json").use { stream ->
            stream.map { RepairHistoryDeclaredGraph(it.fileName.toString(), it.readBytes()) }.toList()
        }
        return Captured(revisions.resolve("graph.json").readBytes(), revisions.resolve("recovery-binding.json").readBytes(), selectedBudget, declared)
    }
    private fun view(captured: Captured) = recordedRepairHistorySnapshot(captured.graph, captured.binding, captured.budget, captured.declared)
    private fun restored(withMetadata: Boolean = false): Captured {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            if (withMetadata) startRun(graph) else graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"), if (withMetadata) metadata(graph) else null)
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray())); graph.reject(attempt, RepairEvidence("rejected", "PRIVATE-peer"))
        }
        return capture(root)
    }
    private fun accepted(): Captured {
        val root = root()
        ModuleRevisionGraph.open(root, profile).use { graph ->
            startRun(graph)
            val attempt = graph.beginAttempt(listOf("code.c"), metadata(graph))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray())); graph.accept(attempt, RepairEvidence("valid", "fixture"), proof(graph, attempt))
        }
        return capture(root)
    }
    private fun refuse(captured: Captured) {
        val failure = assertFailsWith<RepairHistorySnapshotRefusal> { view(captured) }
        assertEquals("Recorded repair metadata is invalid or exceeds its bound.", failure.message)
        assertNull(failure.cause); assertTrue(failure.suppressed.isEmpty()); assertTrue(failure.stackTrace.isEmpty())
    }
    // Trusted-host reflection keeps private parsers private and reseals negatives so they reach semantic checks.
    private val graphFunctions get() = Class.forName("decompengine.repair.ModuleRevisionGraphKt")
    private fun privateCall(name: String, vararg args: Any): Any = graphFunctions.declaredMethods
        .single { it.name == name && it.parameterCount == args.size }.also { it.isAccessible = true }.invoke(null, *args)
    private fun reseal(captured: Captured, edit: (JsonObject) -> JsonObject): Captured {
        val json = edit(Json.parseToJsonElement(captured.graph.decodeToString()).jsonObject)
        val state = privateCall("parseGraph", json.toString())
        val type = graphFunctions.declaredMethods.single { it.name == "renderGraph" && it.parameterCount == 2 }.parameterTypes[1]
        val wire = type.enumConstants.single { (it as Enum<*>).name == "COMPACT" }
        return captured.copy(graph = privateCall("renderGraph", state, wire).toString().toByteArray())
    }
    private fun editMetadata(root: JsonObject, pending: Boolean, edit: (JsonObject) -> JsonObject): JsonObject {
        if (!pending) return editLastMetadata(root, edit)
        val row = root.getValue("pending").jsonObject
        return JsonObject(root + ("pending" to JsonObject(row + ("repairMetadata" to edit(row.getValue("repairMetadata").jsonObject)))))
    }
    private fun editLastMetadata(root: JsonObject, edit: (JsonObject) -> JsonObject): JsonObject {
        val nodes = root.getValue("nodes").jsonArray.toMutableList()
        val row = nodes.last().jsonObject
        nodes[nodes.lastIndex] = JsonObject(row + ("repairMetadata" to edit(row.getValue("repairMetadata").jsonObject)))
        return JsonObject(root + ("nodes" to JsonArray(nodes)))
    }
    private fun bindNode(captured: Captured, assessment: String, wrongPath: Boolean = false, pending: Boolean = false): Captured = reseal(captured) { root ->
        val row = if (pending) root.getValue("pending").jsonObject else root.getValue("nodes").jsonArray.last().jsonObject
        val id = row.getValue("id").jsonPrimitive.content
        val changes = row.getValue(if (pending) "candidateChanges" else "changes").jsonArray
        val digest = agentFileChangeSetSha256(changes.map { element ->
            val change = element.jsonObject
            AgentFileChange(AgentWorkspacePath("project", change.getValue("path").jsonPrimitive.content), AgentFileChangeKind.MODIFIED,
                change.getValue("beforeSha256").jsonPrimitive.content, change.getValue("afterSha256").jsonPrimitive.content,
                change.getValue("afterBytes").jsonPrimitive.content.toLong())
        })
        val binding = buildJsonObject {
            put("receiptPath", "reports/repair-revisions/" + (if (wrongPath) "revision_99999999_aaaaaaaaaaaaaaaa" else id) + ".acp-receipt.json")
            put("receiptSha256", "a".repeat(64)); put("receiptSchemaVersion", 2); put("requestSha256", "b".repeat(64)); put("resultChangesSha256", digest)
            put("terminalOutcome", "returned-completed"); put("receiptReleaseComplete", true); put("assessmentStatus", assessment)
        }
        editMetadata(root, pending) { JsonObject(it + ("agentInvocation" to binding)) }
    }
    private fun recoveryFailure(captured: Captured, selectedProfile: RepairIndexProfile, root: Path): Throwable {
        val state = privateCall("parseGraph", captured.graph.decodeToString())
        val binding = privateCall("parseCanonicalRecoveryBinding", captured.binding)
        return assertFailsWith<InvocationTargetException> {
            privateCall("validateGraphBeforeRecovery", state, selectedProfile, binding, root.resolve("reports/repair-revisions/blobs"), captured.budget)
        }.targetException
    }
    private fun publicSurface(value: Any?): String = when (value) {
        null -> "null"
        is String, is Number, is Boolean -> value.toString()
        is Enum<*> -> value.name
        is Collection<*> -> value.joinToString("|", transform = ::publicSurface)
        is ByteArray -> error("raw payload escaped into public DTO")
        else -> {
            require(value.javaClass.simpleName.startsWith("RepairRecorded") || value is RepairHistorySnapshot)
            value.javaClass.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }.joinToString("|") { field ->
                field.isAccessible = true; publicSurface(field.get(value))
            }
        }
    }
}
