package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.TreeMap
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.boolean

class GccCompilerEngineResumeEvidenceValidationTest {
    @Test
    fun `live progress triggers only a nonterminal full batch and stopped validation binds its state`() {
        val fixture = transitionFixture(twoBatchFixture()).interrupted
        withDescriptorExportFixture(fixture, includeModel = false) { captured ->
            val trigger = GccBundledCheckpointTrigger(512)
            assertEquals(null, trigger.observe(null))
            val observation = GccBundledExportCapture.observeProgress(captured.root, captured.reportsIdentity, captured.artifacts)
            val decision = checkNotNull(trigger.observe(observation))
            val document = OracleJson.parseCanonical(decision).jsonObject
            assertEquals(sha(fixture.state), document.getValue("stateSha256").jsonPrimitive.content)
            assertEquals(sha(fixture.progress), document.getValue("progressSha256").jsonPrimitive.content)
            assertFails { trigger.observe(observation) }
            val prefix = GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts)
            val assessment = OracleJson.parseCanonical(trigger.assessStoppedPrefix(prefix)).jsonObject
            assertFalse(assessment.getValue("complete").jsonPrimitive.boolean)
            assertFalse(assessment.getValue("releaseEligible").jsonPrimitive.boolean)
            assertEquals(prefix.progressSha256, assessment.getValue("progressSha256").jsonPrimitive.content)
            assertEquals(sha(OracleJson.canonicalBytes(kotlinx.serialization.json.JsonObject(assessment - "assessmentSha256"))),
                assessment.getValue("assessmentSha256").jsonPrimitive.content)
        }
        withDescriptorExportFixture { captured ->
            val completed = GccBundledExportCapture.observeProgress(captured.root, captured.reportsIdentity, captured.artifacts)
            assertEquals(null, GccBundledCheckpointTrigger(512).observe(completed))
        }
        for (threshold in listOf(-512L, 0L, 1L, 511L, 513L)) assertFails { GccBundledCheckpointTrigger(threshold) }
    }

    @Test
    fun `stopped prefix may advance across committed batches but cannot move backward or change state`() {
        val full = threeBatchFixture()
        val first = transitionFixture(full, interruptedBatchCount = 1).interrupted
        val second = transitionFixture(full, interruptedBatchCount = 2).interrupted
        val firstObservation = GccCompilerEngineResumeByteValidator.assessExportProgress(first.state, first.progress)
        val secondObservation = GccCompilerEngineResumeByteValidator.assessExportProgress(second.state, second.progress)
        val firstPrefix = assessInterrupted(first)
        val secondPrefix = assessInterrupted(second)
        val forward = GccBundledCheckpointTrigger(512)
        forward.observe(firstObservation)
        forward.assessStoppedPrefix(secondPrefix)
        val backward = GccBundledCheckpointTrigger(1024)
        assertEquals(null, backward.observe(firstObservation))
        backward.observe(secondObservation)
        assertFails { backward.assessStoppedPrefix(firstPrefix) }
        assertFails { forward.assessStoppedPrefix(assessInterrupted(transitionFixture(twoBatchFixture()).interrupted)) }
        assertFails { GccBundledCheckpointTrigger(512).assessStoppedPrefix(firstPrefix) }
    }

    @Test
    fun `live progress waits for absent files but rejects substituted invocation and oversized records`() {
        val fixture = transitionFixture(twoBatchFixture()).interrupted
        withDescriptorExportFixture(fixture, includeModel = false) { captured ->
            val progress = captured.directory.resolve("reports/program_model.json.progress.json")
            val original = captured.directory.resolve("saved-progress")
            Files.move(progress, original)
            assertEquals(null, GccBundledExportCapture.observeProgress(captured.root, captured.reportsIdentity, captured.artifacts))
            Files.move(original, progress)
            for (role in captured.artifacts.map { it.role }) {
                val wrong = captured.artifacts.map { if (it.role == role) it.copy(sha256 = SHA_F) else it }
                assertFails { GccBundledExportCapture.observeProgress(captured.root, captured.reportsIdentity, wrong) }
            }
            assertFails { GccBundledExportCapture.observeProgress(captured.root, captured.reportsIdentity, captured.artifacts,
                GccResumeByteValidationLimits(progressBytes = fixture.progress.size - 1)) }
            Files.move(progress, original)
            Files.createSymbolicLink(progress, original)
            assertFails { GccBundledExportCapture.observeProgress(captured.root, captured.reportsIdentity, captured.artifacts) }
            assertContentEquals(fixture.progress, Files.readAllBytes(original))
        }
    }

    @Test
    fun `interrupted descriptor capture validates the committed prefix without a final model`() {
        val prefix = transitionFixture(twoBatchFixture()).interrupted
        withDescriptorExportFixture(prefix, includeModel = false) { captured ->
            val result = GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts)
            assertEquals("non-authoritative-byte-assessment", result.authority)
            assertEquals(513L, result.functionCount)
            assertEquals(512L, result.completed)
            assertEquals(1L, result.observedBatchCount)
            assertEquals(sha(prefix.state), result.stateSha256)
            assertEquals(sha(prefix.progress), result.progressSha256)
            assertFails { GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts) }
        }
    }

    @Test
    fun `interrupted descriptor capture rejects final models and unfinished batch residue without removing it`() {
        val prefix = transitionFixture(twoBatchFixture()).interrupted
        withDescriptorExportFixture(prefix) { captured ->
            assertFails { GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts) }
            assertContentEquals(prefix.model, Files.readAllBytes(captured.directory.resolve("reports/program_model.json")))
        }
        withDescriptorExportFixture(prefix, includeModel = false) { captured ->
            val residue = captured.directory.resolve("reports/program_model.json.export/planning-batches/batch-00000512-00000513.checkpoint.tmp")
            Files.writeString(residue, "unfinished")
            assertFails { GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts) }
            assertEquals("unfinished", Files.readString(residue))
        }
        withDescriptorExportFixture(includeModel = false) { captured ->
            assertFails { GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts) }
        }
    }

    @Test
    fun `interrupted descriptor capture enforces invocation commitments and aggregate bounds`() {
        val prefix = transitionFixture(twoBatchFixture()).interrupted
        withDescriptorExportFixture(prefix, includeModel = false) { captured ->
            for (role in captured.artifacts.map { it.role }) {
                val changed = captured.artifacts.map { if (it.role == role) it.copy(sha256 = SHA_F) else it }
                assertFails { GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, changed) }
            }
            val total = prefix.state.size.toLong() + prefix.progress.size + prefix.batches.sumOf {
                it.checkpoint.size.toLong() + it.functions.size + it.globals.size + it.types.size + it.failures.size
            }
            assertFails {
                GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts,
                    GccResumeByteValidationLimits(transitionAggregateBytes = total - 1))
            }
            assertEquals(512L, GccBundledExportCapture.captureInterruptedPrefix(captured.root, captured.reportsIdentity, captured.artifacts,
                GccResumeByteValidationLimits(transitionAggregateBytes = total)).completed)
        }
    }

    @Test
    fun `descriptor capture preserves report inode admission across legitimate child directory creation`() {
        withDescriptorExportFixture { captured ->
            LinuxFilesystemSyscalls.openDirectoryAt(captured.root.fd, "reports").use { current ->
                assertTrue(current.identity.linkCount > captured.reportsIdentity.linkCount)
                assertEquals(captured.reportsIdentity.key, current.identity.key)
            }
            val result = GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts)
            assertEquals(sha(captured.fixture.model), result.assessment.programModelSha256)
            assertEquals("non-authoritative-byte-assessment", result.assessment.authority)
            val original = result.canonicalBytes
            result.canonicalBytes[0] = '!'.code.toByte()
            assertContentEquals(original, result.canonicalBytes)
            val receipt = OracleJson.parseCanonical(original).jsonObject
            assertFalse(receipt.getValue("complete").jsonPrimitive.boolean)
            assertFalse(receipt.getValue("releaseEligible").jsonPrimitive.boolean)
        }
    }

    @Test
    fun `descriptor export capture rejects changed declared input exporter and archive identities`() {
        withDescriptorExportFixture { captured ->
            for (role in captured.artifacts.map { it.role }) {
                val changed = captured.artifacts.map { artifact -> if (artifact.role == role) artifact.copy(sha256 = SHA_F) else artifact }
                val failure = assertFailsWith<IllegalArgumentException> {
                    GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, changed)
                }
                assertTrue(failure.message.orEmpty().contains("authenticated invocation"))
            }
            assertEquals(sha(captured.fixture.model), GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts).assessment.programModelSha256)
        }
    }

    @Test
    fun `descriptor export capture rejects hardlinked and symbolic file substitutions`() {
        for (symbolic in listOf(false, true)) {
            withDescriptorExportFixture { captured ->
                val model = captured.directory.resolve("reports/program_model.json")
                val alias = captured.directory.resolve("model-alias.json")
                if (symbolic) {
                    Files.move(model, alias)
                    Files.createSymbolicLink(model, alias)
                } else {
                    Files.createLink(alias, model)
                }
                assertFails { GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts) }
                assertContentEquals(captured.fixture.model, Files.readAllBytes(alias))
            }
        }
    }

    @Test
    fun `descriptor export capture rejects linked directories and changed report inode bindings`() {
        for (relative in listOf("reports", "reports/program_model.json.export", "reports/program_model.json.export/planning-batches")) {
            withDescriptorExportFixture { captured ->
                val selected = captured.directory.resolve(relative)
                val moved = captured.directory.resolve("moved-directory")
                Files.move(selected, moved)
                Files.createSymbolicLink(selected, moved)
                assertFails { GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts) }
                assertTrue(Files.isDirectory(moved))
            }
        }
        withDescriptorExportFixture { captured ->
            Files.move(captured.directory.resolve("reports"), captured.directory.resolve("original-reports"))
            Files.createDirectory(captured.directory.resolve("reports"))
            assertFailsWith<IllegalArgumentException> {
                GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts)
            }
        }
    }

    @Test
    fun `descriptor export capture rejects unexpected planning batch files without deleting residue`() {
        withDescriptorExportFixture { captured ->
            val residue = captured.directory.resolve("reports/program_model.json.export/planning-batches/unexpected.checkpoint")
            Files.writeString(residue, "retained-unexpected-residue")
            assertFailsWith<IllegalArgumentException> {
                GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts)
            }
            assertEquals("retained-unexpected-residue", Files.readString(residue))
        }
    }

    @Test
    fun `descriptor export capture enforces metadata model and aggregate byte bounds`() {
        withDescriptorExportFixture { captured ->
            val fixture = captured.fixture
            val total = fixture.state.size.toLong() + fixture.progress.size + fixture.model.size + fixture.batches.sumOf { batch ->
                batch.checkpoint.size.toLong() + batch.functions.size + batch.globals.size + batch.types.size + batch.failures.size
            }
            for (limits in listOf(
                GccResumeByteValidationLimits(exporterStateBytes = fixture.state.size - 1),
                GccResumeByteValidationLimits(assembledModelBytes = fixture.model.size - 1),
                GccResumeByteValidationLimits(transitionAggregateBytes = total - 1),
            )) {
                val failure = assertFailsWith<IllegalArgumentException> {
                    GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts, limits)
                }
                assertTrue(failure.message.orEmpty().contains("byte bound"))
            }
            assertEquals(sha(fixture.model), GccBundledExportCapture.capture(captured.root, captured.reportsIdentity, captured.artifacts).assessment.programModelSha256)
        }
    }

    @Test
    fun `state-bound progress retains raw digest and rejects impossible prefix positions`() {
        val fixture = oneBatchFixture()
        val state = GccCompilerEngineResumeByteValidator.assessExporterState(fixture.state)
        val progress = GccCompilerEngineResumeByteValidator.assessExportProgress(fixture.state, fixture.progress)
        assertEquals("non-authoritative-byte-assessment", state.authority)
        assertEquals("non-authoritative-byte-assessment", progress.authority)
        assertEquals(fixture.progress.size, progress.artifactBytes)
        assertEquals(sha(fixture.progress), progress.artifactSha256)
        assertEquals(sha(fixture.state), progress.stateSha256)

        val impossible = listOf(
            progress(total = 3, completed = 2, partial = 1, failed = 1),
            progress(total = 2, completed = 2, recovered = 1, partial = 0, failed = 1),
            progress(total = 2, completed = 1, partial = 1, failed = 0),
            progress(total = 2, completed = 2, partial = 1, failed = 1, reused = 1),
        )
        impossible.forEach { bytes ->
            assertFailsWith<GccCompilerEngineResumeEvidenceException> {
                GccCompilerEngineResumeByteValidator.assessExportProgress(fixture.state, bytes)
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExportProgress(
                fixture.state,
                progress(phase = "publishing", total = 2, completed = 2, partial = 1, failed = 1),
            )
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExporterState(
                fixture.state.decodeToString().replace("\"recoveryMode\":\"planning\"", "\"recoveryMode\":\"full\"")
                    .toByteArray(),
            )
        }
        val twoBatches = twoBatchFixture()
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExportProgress(twoBatches.state, fixture.progress)
        }
        val alignedButIncompleteComplete = progress(
            total = 513,
            completed = 512,
            partial = 512,
            failed = 0,
        )
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExportProgress(
                twoBatches.state,
                alignedButIncompleteComplete,
            )
        }
        val planningZero = progress(
            phase = "planning",
            total = 2,
            completed = 0,
            partial = 0,
            failed = 0,
        )
        GccCompilerEngineResumeByteValidator.assessExportProgress(fixture.state, planningZero)
    }

    @Test
    fun `one-shot raw run reproduces inventory commitments semantics and framed model`() {
        val fixture = oneBatchFixture()
        val result = assess(fixture)
        assertEquals("non-authoritative-byte-assessment", result.authority)
        assertEquals(2L, result.functionCount)
        assertEquals(1L, result.planningBatchCount)
        assertEquals(fixture.inventorySha256, result.inventorySha256)
        assertEquals(fixture.semantic.canonicalBytes, result.semanticCanonicalBytes)
        assertEquals(fixture.semantic.sha256, result.semanticSha256)
        assertEquals(fixture.batchCommitmentSha256, result.batchCommitmentSha256)
        assertEquals(1L, result.partial)
        assertEquals(1L, result.failed)
        assertEquals(fixture.model.size, result.programModelBytes)
        assertEquals(sha(fixture.model), result.programModelSha256)
    }

    @Test
    fun `assessment objects are never accepted as authority or copy tokens`() {
        val assessmentClasses = listOf(
            GccExporterStateAssessment::class.java,
            GccExportProgressAssessment::class.java,
            GccCompletedRunAssessment::class.java,
            GccInterruptedPrefixAssessment::class.java,
            GccResumeEquivalenceAssessment::class.java,
        )
        assessmentClasses.forEach { type ->
            assertFalse(type.declaredMethods.any { it.name == "copy" || it.name.startsWith("component") })
        }
        GccCompilerEngineResumeByteValidator::class.java.declaredMethods.forEach { method ->
            assertFalse(method.parameterTypes.any { parameter -> parameter in assessmentClasses })
        }
        assertFailsWith<ClassNotFoundException> {
            Class.forName("decompengine.oracle.gcc.GccExporterStateSummary")
        }
        assertFailsWith<ClassNotFoundException> {
            Class.forName("decompengine.oracle.gcc.GccPlanningBatchSummary")
        }
        assertFalse(
            GccCompilerEngineResumeByteValidator::class.java.declaredMethods.any {
                Modifier.isPublic(it.modifiers) && it.name.contains("validateAssembledModel")
            },
        )
        val bytecode = (assessmentClasses + GccCompilerEngineResumeByteValidator::class.java)
            .joinToString("\n", transform = ::javap)
        assertFalse(bytecode.contains("GccExporterStateSummary"))
        assertFalse(bytecode.contains("GccPlanningBatchSummary"))
        assertFalse(bytecode.contains("validateAssembledModel"))
        assertFalse(bytecode.lineSequence().any { line -> line.contains(" copy(") })
    }

    @Test
    fun `interrupted 513-function prefix and resumed fresh outputs compare only as raw bytes`() {
        val fixture = transitionFixture(twoBatchFixture())
        val prefix = assessInterrupted(fixture.interrupted)
        assertEquals("non-authoritative-byte-assessment", prefix.authority)
        assertEquals(513L, prefix.functionCount)
        assertEquals(512L, prefix.completed)
        assertEquals(1L, prefix.observedBatchCount)
        assertEquals(fixture.interrupted.inventorySha256, prefix.declaredInventorySha256)
        assertEquals(512L, prefix.partial)
        assertEquals(0L, prefix.failed)
        assertEquals(0L, prefix.reused)

        val result = assessTransition(fixture)
        assertEquals("non-authoritative-byte-assessment", result.authority)
        assertEquals(sha(fixture.interrupted.state), result.stateSha256)
        assertEquals(512L, result.interruptedCompleted)
        assertEquals(513L, result.functionCount)
        assertEquals(2L, result.planningBatchCount)
        assertEquals(fixture.resumed.model.size, result.programModelBytes)
        assertEquals(sha(fixture.resumed.model), result.programModelSha256)
        assertEquals(fixture.resumedPlan.size, result.modulePlanBytes)
        assertEquals(sha(fixture.resumedPlan), result.modulePlanSha256)
    }

    @Test
    fun `interrupted prefixes reject missing reordered substituted and internally drifting bytes`() {
        val transition = transitionFixture(twoBatchFixture())
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(transition.interrupted.copy(batches = emptyList()))
        }

        val threeBatch = transitionFixture(threeBatchFixture(), interruptedBatchCount = 2)
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(threeBatch.interrupted.copy(batches = threeBatch.interrupted.batches.reversed()))
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(
                transition.interrupted.copy(
                    batches = listOf(transition.resumed.batches[1]),
                ),
            )
        }

        val countDrift = transition.interrupted.copy(
            progress = progress(
                phase = "planning",
                total = 513,
                completed = 512,
                partial = 511,
                failed = 1,
            ),
        )
        assertFailsWith<GccCompilerEngineResumeEvidenceException> { assessInterrupted(countDrift) }
        val statusDrift = transition.interrupted.batches.single().functions.decodeToString()
            .replaceFirst("\"status\": \"partial\"", "\"status\": \"failed\"")
            .toByteArray()
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(
                transition.interrupted.copy(
                    batches = listOf(transition.interrupted.batches.single().withFunctions(statusDrift)),
                ),
            )
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(
                transition.interrupted.copy(
                    state = transition.interrupted.state.decodeToString().replace(SHA_B, SHA_F).toByteArray(),
                ),
            )
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(
                transition.interrupted.copy(
                    progress = progress(
                        phase = "planning",
                        total = 513,
                        completed = 512,
                        partial = 512,
                        failed = 0,
                        reused = 512,
                    ),
                ),
            )
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessInterrupted(threeBatchPrefixWithDuplicateFirstOwner())
        }
    }

    @Test
    fun `resume equivalence rejects frozen-prefix inventory reuse and final-output drift`() {
        val fixture = transitionFixture(twoBatchFixture())
        val inventoryDrift = fixture.interrupted.batches.single().checkpoint.decodeToString()
            .replace("inventorySha256=${fixture.interrupted.inventorySha256}", "inventorySha256=$SHA_F")
            .toByteArray()
        val substitutedPrefix = fixture.copy(
            interrupted = fixture.interrupted.copy(
                batches = listOf(fixture.interrupted.batches.single().withCheckpoint(inventoryDrift)),
            ),
        )
        assertEquals(SHA_F, assessInterrupted(substitutedPrefix.interrupted).declaredInventorySha256)
        assertTransitionRejected(substitutedPrefix)

        assertTransitionRejected(
            fixture.copy(
                resumed = fixture.resumed.copy(
                    progress = progress(
                        total = 513,
                        completed = 513,
                        partial = 513,
                        failed = 0,
                        reused = 0,
                    ),
                ),
            ),
        )
        assertTransitionRejected(
            fixture.copy(
                fresh = fixture.fresh.copy(
                    progress = progress(
                        total = 513,
                        completed = 513,
                        partial = 513,
                        failed = 0,
                        reused = 512,
                    ),
                ),
            ),
        )
        assertTransitionRejected(
            fixture.copy(
                fresh = fixture.fresh.copy(model = fixture.fresh.model.copyOf(fixture.fresh.model.size - 1)),
            ),
        )
        assertTransitionRejected(fixture.copy(freshPlan = "different-plan\n".toByteArray()))
        assertTransitionRejected(
            fixture.copy(
                fresh = fixture.fresh.copy(
                    state = fixture.fresh.state.decodeToString().replace(SHA_B, SHA_F).toByteArray(),
                ),
            ),
        )
    }

    @Test
    fun `raw function fragments reject arbitrary bytes reordering and swapped embedded IDs`() {
        val fixture = oneBatchFixture()
        assertRejected(fixture.copy(batches = listOf(fixture.batches.single().withFunctions("not-json".toByteArray()))))

        val records = fixture.specs.single().functions.map { it.bytes }
        val reordered = fragment(records.reversed())
        assertRejected(fixture.copy(batches = listOf(fixture.batches.single().withFunctions(reordered))))

        val firstId = fixture.specs.single().functions[0].id
        val secondId = fixture.specs.single().functions[1].id
        val swappedId = fixture.batches.single().functions.decodeToString()
            .replaceFirst("\"id\": \"$firstId\"", "\"id\": \"$secondId\"")
            .toByteArray()
        assertRejected(fixture.copy(batches = listOf(fixture.batches.single().withFunctions(swappedId))))
    }

    @Test
    fun `evidence fragments reject arbitrary bytes and checkpoint embedded ID drift`() {
        val fixture = oneBatchFixture()
        val batch = fixture.batches.single()
        assertRejected(fixture.copy(batches = listOf(batch.withGlobals("not-json".toByteArray()))))
        assertRejected(fixture.copy(batches = listOf(batch.withTypes("not-json".toByteArray()))))

        val globalId = fixture.specs.single().globals.single().id
        val wrongGlobal = globalId(2)
        val globalDrift = batch.globals.decodeToString().replace(globalId, wrongGlobal).toByteArray()
        assertRejected(fixture.copy(batches = listOf(batch.withGlobals(globalDrift))))

        val typeId = fixture.specs.single().types.single().id
        val wrongType = typeId(2)
        val typeDrift = batch.types.decodeToString().replace(typeId, wrongType).toByteArray()
        assertRejected(fixture.copy(batches = listOf(batch.withTypes(typeDrift))))

        val failureId = fixture.specs.single().failures.single().id
        val wrongFailure = fixture.specs.single().functions.first().id
        val failureDrift = batch.failures.decodeToString().replace(failureId, wrongFailure).toByteArray()
        assertRejected(fixture.copy(batches = listOf(batch.withFailures(failureDrift))))
    }

    @Test
    fun `full run rejects reordered batches and duplicate cross-batch first owners`() {
        val fixture = twoBatchFixture()
        val valid = assess(fixture)
        assertEquals(2L, valid.planningBatchCount)
        assertEquals(513L, valid.functionCount)
        assertRejected(fixture.copy(batches = fixture.batches.reversed()))

        assertRejected(twoBatchFixture(duplicateGlobalOwner = true))
        assertRejected(twoBatchFixture(duplicateTypeOwner = true))
    }

    @Test
    fun `state inventory commitment and semantic drift all fail independently`() {
        val base = oneBatchFixture()
        val stateMismatch = base.state.decodeToString().replace(SHA_B, SHA_F).toByteArray()
        assertRejected(base.copy(state = stateMismatch))

        assertRejected(oneBatchFixture(inventoryOverride = SHA_F))
        assertRejected(oneBatchFixture(batchCommitmentOverride = SHA_F))
        assertRejected(oneBatchFixture(semanticShaOverride = SHA_F))
        assertRejected(oneBatchFixture(semanticBytesOverride = base.semantic.canonicalBytes + 1L))
    }

    @Test
    fun `raw capture is detached from caller mutation and run-wide bytes are charged`() {
        val fixture = oneBatchFixture()
        val result = assess(fixture)
        val expectedState = result.stateSha256
        val expectedProgress = result.progressSha256
        val expectedModel = result.programModelSha256

        fixture.state.fill(0)
        fixture.progress.fill(0)
        fixture.model.fill(0)
        fixture.batches.forEach { batch ->
            batch.checkpoint.fill(0)
            batch.functions.fill(0)
            batch.globals.fill(0)
            batch.types.fill(0)
            batch.failures.fill(0)
        }
        assertEquals(expectedState, result.stateSha256)
        assertEquals(expectedProgress, result.progressSha256)
        assertEquals(expectedModel, result.programModelSha256)

        val fresh = oneBatchFixture()
        val retained = fresh.batches.sumOf { batch ->
            batch.checkpoint.size.toLong() + batch.functions.size + batch.globals.size +
                batch.types.size + batch.failures.size
        }
        assess(fresh, GccResumeByteValidationLimits(aggregateFragmentBytes = retained))
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assess(fresh, GccResumeByteValidationLimits(aggregateFragmentBytes = retained - 1L))
        }

        val batch = fresh.batches.single()
        var hasNextCalls = 0
        var nextCalls = 0
        val unboundedIterator = object : AbstractList<GccPlanningBatchBytes>() {
            override val size: Int = 1
            override fun get(index: Int): GccPlanningBatchBytes = batch
            override fun iterator(): Iterator<GccPlanningBatchBytes> = object : Iterator<GccPlanningBatchBytes> {
                override fun hasNext(): Boolean {
                    hasNextCalls++
                    return true
                }

                override fun next(): GccPlanningBatchBytes {
                    nextCalls++
                    return batch
                }
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fresh.state,
                fresh.progress,
                unboundedIterator,
                fresh.model,
            )
        }
        assertEquals(257, hasNextCalls)
        assertEquals(256, nextCalls)

        val declaredCountDrift = object : AbstractList<GccPlanningBatchBytes>() {
            override val size: Int = 1
            override fun get(index: Int): GccPlanningBatchBytes = batch
            override fun iterator(): Iterator<GccPlanningBatchBytes> = listOf(batch, batch).iterator()
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fresh.state,
                fresh.progress,
                declaredCountDrift,
                fresh.model,
            )
        }
    }

    @Test
    fun `transition capture snapshots every array and enforces hostile-list and aggregate bounds`() {
        val fixture = transitionFixture(twoBatchFixture())
        val expectedState = sha(fixture.interrupted.state)
        val expectedModel = sha(fixture.resumed.model)
        val expectedPlan = sha(fixture.resumedPlan)
        val result = assessTransition(fixture)

        mutableArrays(fixture).forEach { it.fill(0) }
        assertEquals(expectedState, result.stateSha256)
        assertEquals(expectedModel, result.programModelSha256)
        assertEquals(expectedPlan, result.modulePlanSha256)

        val bounded = transitionFixture(twoBatchFixture())
        val retained = transitionCaptureBytes(bounded)
        assessTransition(
            bounded,
            GccResumeByteValidationLimits(transitionAggregateBytes = retained),
        )
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessTransition(
                bounded,
                GccResumeByteValidationLimits(transitionAggregateBytes = retained - 1L),
            )
        }
        assessTransition(
            bounded,
            GccResumeByteValidationLimits(modulePlanBytes = bounded.resumedPlan.size),
        )
        assertByteBoundFailure("resumed module plan") {
            assessTransition(
                bounded,
                GccResumeByteValidationLimits(modulePlanBytes = bounded.resumedPlan.size - 1),
            )
        }

        val rawBatch = bounded.interrupted.batches.single()
        var hasNextCalls = 0
        var nextCalls = 0
        val unboundedIterator = object : AbstractList<GccPlanningBatchBytes>() {
            override val size: Int = 1
            override fun get(index: Int): GccPlanningBatchBytes = rawBatch
            override fun iterator(): Iterator<GccPlanningBatchBytes> = object : Iterator<GccPlanningBatchBytes> {
                override fun hasNext(): Boolean {
                    hasNextCalls++
                    return true
                }

                override fun next(): GccPlanningBatchBytes {
                    nextCalls++
                    return rawBatch
                }
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessTransition(bounded.copy(interrupted = bounded.interrupted.copy(batches = unboundedIterator)))
        }
        assertEquals(257, hasNextCalls)
        assertEquals(256, nextCalls)

        val declaredCountDrift = object : AbstractList<GccPlanningBatchBytes>() {
            override val size: Int = bounded.resumed.batches.size
            override fun get(index: Int): GccPlanningBatchBytes = bounded.resumed.batches[index]
            override fun iterator(): Iterator<GccPlanningBatchBytes> =
                (bounded.resumed.batches + bounded.resumed.batches.last()).iterator()
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assessTransition(bounded.copy(resumed = bounded.resumed.copy(batches = declaredCountDrift)))
        }
    }

    @Test
    fun `pre-decode and final framing limits remain fail closed`() {
        val invalidUtf8 = byteArrayOf(0x80.toByte(), 0x80.toByte())
        assertByteBoundFailure("exporter state") {
            GccCompilerEngineResumeByteValidator.assessExporterState(
                invalidUtf8,
                GccResumeByteValidationLimits(exporterStateBytes = 1),
            )
        }
        val fixture = oneBatchFixture()
        assertByteBoundFailure("export progress") {
            GccCompilerEngineResumeByteValidator.assessExportProgress(
                fixture.state,
                invalidUtf8,
                GccResumeByteValidationLimits(progressBytes = 1),
            )
        }
        val valid = fixture.batches.single()
        assertByteBoundFailure("planning checkpoint") {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fixture.state,
                fixture.progress,
                listOf(GccPlanningBatchBytes(invalidUtf8, valid.functions, valid.globals, valid.types, valid.failures)),
                fixture.model,
                GccResumeByteValidationLimits(checkpointBytes = 1),
            )
        }
        val fragmentCases = listOf(
            "function fragment" to GccPlanningBatchBytes(valid.checkpoint, invalidUtf8, byteArrayOf(), byteArrayOf(), byteArrayOf()),
            "global fragment" to GccPlanningBatchBytes(valid.checkpoint, byteArrayOf('x'.code.toByte()), invalidUtf8, byteArrayOf(), byteArrayOf()),
            "type fragment" to GccPlanningBatchBytes(valid.checkpoint, byteArrayOf('x'.code.toByte()), byteArrayOf(), invalidUtf8, byteArrayOf()),
            "failure fragment" to GccPlanningBatchBytes(valid.checkpoint, byteArrayOf('x'.code.toByte()), byteArrayOf(), byteArrayOf(), invalidUtf8),
        )
        fragmentCases.forEach { (label, batch) ->
            assertByteBoundFailure(label) {
                GccCompilerEngineResumeByteValidator.assessCompletedRun(
                    fixture.state,
                    fixture.progress,
                    listOf(batch),
                    fixture.model,
                    GccResumeByteValidationLimits(planningFragmentBytes = 1),
                )
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assess(fixture, GccResumeByteValidationLimits(assembledModelBytes = fixture.model.size - 1))
        }
        val truncatedModel = fixture.model.copyOf(fixture.model.size - 1)
        val framingFailure = assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fixture.state,
                fixture.progress,
                fixture.batches,
                truncatedModel,
                GccResumeByteValidationLimits(assembledModelBytes = truncatedModel.size),
            )
        }
        assertTrue(framingFailure.message?.contains("framing exceeds") == true)
    }

    private fun withDescriptorExportFixture(
        fixture: RunFixture = oneBatchFixture(),
        includeModel: Boolean = true,
        action: (DescriptorExportFixture) -> Unit,
    ) {
        val directory = Files.createTempDirectory("gcc-descriptor-export-")
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        try {
            fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
            }
            fun write(path: Path, bytes: ByteArray) {
                Files.write(path, bytes)
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
            }
            val reports = privateDirectory(directory.resolve("reports"))
            val expectedReports = LinuxFilesystemSyscalls.openRoot(reports).use { it.identity }
            val export = privateDirectory(reports.resolve("program_model.json.export"))
            val batches = privateDirectory(export.resolve("planning-batches"))
            if (includeModel) write(reports.resolve("program_model.json"), fixture.model)
            write(reports.resolve("program_model.json.progress.json"), fixture.progress)
            write(export.resolve("state.json"), fixture.state)
            for ((index, batch) in fixture.batches.withIndex()) {
                val start = index * 512
                val end = start + fixture.specs[index].functions.size
                val base = String.format(java.util.Locale.ROOT, "batch-%08d-%08d", start, end)
                for ((suffix, bytes) in mapOf(
                "checkpoint" to batch.checkpoint, "functions.fragment" to batch.functions,
                "globals.fragment" to batch.globals, "types.fragment" to batch.types,
                "failures.fragment" to batch.failures,
                )) write(batches.resolve("$base.$suffix"), bytes)
            }
            val artifacts = listOf(
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY to SHA_A,
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE to SHA_B,
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE to SHA_C,
            ).map { (role, digest) ->
                GccCompilerEngineContainmentArtifactIdentity(role, directory.resolve("declared-${role.wireName}"), 1, digest)
            }
            LinuxFilesystemSyscalls.openRoot(directory).use { root ->
                action(DescriptorExportFixture(directory, root, expectedReports, artifacts, fixture))
            }
        } finally {
            Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private data class DescriptorExportFixture(
        val directory: Path,
        val root: LinuxDescriptor,
        val reportsIdentity: LinuxFileIdentity,
        val artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        val fixture: RunFixture,
    )

    private fun assess(
        fixture: RunFixture,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccCompletedRunAssessment = GccCompilerEngineResumeByteValidator.assessCompletedRun(
        fixture.state,
        fixture.progress,
        fixture.batches,
        fixture.model,
        limits,
    )

    private fun assessInterrupted(
        fixture: RunFixture,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccInterruptedPrefixAssessment = GccCompilerEngineResumeByteValidator.assessInterruptedPrefix(
        fixture.state,
        fixture.progress,
        fixture.batches,
        limits,
    )

    private fun assessTransition(
        fixture: TransitionFixture,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccResumeEquivalenceAssessment = GccCompilerEngineResumeByteValidator.assessResumeEquivalence(
        fixture.interrupted.state,
        fixture.interrupted.progress,
        fixture.interrupted.batches,
        fixture.resumed.state,
        fixture.resumed.progress,
        fixture.resumed.batches,
        fixture.resumed.model,
        fixture.resumedPlan,
        fixture.fresh.state,
        fixture.fresh.progress,
        fixture.fresh.batches,
        fixture.fresh.model,
        fixture.freshPlan,
        limits,
    )

    private fun assertTransitionRejected(fixture: TransitionFixture) {
        assertFailsWith<GccCompilerEngineResumeEvidenceException> { assessTransition(fixture) }
    }

    private fun assertRejected(fixture: RunFixture) {
        assertFailsWith<GccCompilerEngineResumeEvidenceException> { assess(fixture) }
    }

    private fun assertByteBoundFailure(label: String, operation: () -> Unit) {
        val failure = assertFailsWith<GccCompilerEngineResumeEvidenceException>(block = operation)
        assertTrue(failure.message?.contains(label) == true)
        assertTrue(failure.message?.contains("byte bound") == true)
    }

    private fun oneBatchFixture(
        inventoryOverride: String? = null,
        batchCommitmentOverride: String? = null,
        semanticShaOverride: String? = null,
        semanticBytesOverride: Long? = null,
    ): RunFixture {
        val globalId = globalId(1)
        val typeId = typeId(1)
        val first = function(functionId(0), "first", "partial", referencedGlobals = listOf(globalId))
        val second = function(functionId(1), "second", "failed")
        val spec = BatchSpec(
            functions = listOf(first, second),
            globals = listOf(record(globalId, globalRecord(globalId, "counter"))),
            types = listOf(record(typeId, typeRecord(typeId, "typedef int value_t;"))),
            failures = listOf(record(second.id, failureRecord(second.id, "decompilation failed"))),
        )
        return buildFixture(
            listOf(spec),
            inventoryOverride,
            batchCommitmentOverride,
            semanticShaOverride,
            semanticBytesOverride,
        )
    }

    private fun twoBatchFixture(
        duplicateGlobalOwner: Boolean = false,
        duplicateTypeOwner: Boolean = false,
    ): RunFixture {
        val global = record(globalId(1), globalRecord(globalId(1), "shared"))
        val type = record(typeId(1), typeRecord(typeId(1), "typedef int shared_t;"))
        val firstFunctions = (0 until 512).map { index -> function(functionId(index), "function_$index", "partial") }
        val secondFunction = function(functionId(512), "last", "partial")
        return buildFixture(
            listOf(
                BatchSpec(firstFunctions, globals = listOf(global), types = listOf(type)),
                BatchSpec(
                    listOf(secondFunction),
                    globals = if (duplicateGlobalOwner) listOf(global) else emptyList(),
                    types = if (duplicateTypeOwner) listOf(type) else emptyList(),
                ),
            ),
        )
    }

    private fun threeBatchFixture(duplicateFirstOwner: Boolean = false): RunFixture {
        val sharedGlobal = record(globalId(1), globalRecord(globalId(1), "shared"))
        val specs = (0 until 1025).chunked(512).mapIndexed { batchIndex, indices ->
            BatchSpec(
                functions = indices.map { index -> function(functionId(index), "function_$index", "partial") },
                globals = if (duplicateFirstOwner && batchIndex < 2) listOf(sharedGlobal) else emptyList(),
            )
        }
        return buildFixture(specs)
    }

    private fun threeBatchPrefixWithDuplicateFirstOwner(): RunFixture =
        transitionFixture(threeBatchFixture(duplicateFirstOwner = true), interruptedBatchCount = 2).interrupted

    private fun transitionFixture(
        completed: RunFixture,
        interruptedBatchCount: Int = completed.batches.size - 1,
    ): TransitionFixture {
        require(interruptedBatchCount in 1 until completed.batches.size)
        val interruptedFunctions = completed.specs.take(interruptedBatchCount).flatMap { it.functions }
        val allFunctions = completed.specs.flatMap { it.functions }
        val interruptedCompleted = interruptedFunctions.size.toLong()
        val interrupted = completed.copy(
            progress = progress(
                phase = "planning",
                total = allFunctions.size.toLong(),
                completed = interruptedCompleted,
                partial = interruptedFunctions.count { it.status == "partial" }.toLong(),
                failed = interruptedFunctions.count { it.status == "failed" }.toLong(),
            ),
            batches = completed.batches.take(interruptedBatchCount),
        )
        val resumed = completed.copy(
            progress = progress(
                total = allFunctions.size.toLong(),
                completed = allFunctions.size.toLong(),
                partial = allFunctions.count { it.status == "partial" }.toLong(),
                failed = allFunctions.count { it.status == "failed" }.toLong(),
                reused = interruptedCompleted,
            ),
        )
        val fresh = buildFixture(completed.specs)
        val modulePlan = "{\"schemaVersion\":1,\"modules\":[]}\n".toByteArray()
        return TransitionFixture(interrupted, resumed, fresh, modulePlan, modulePlan.copyOf())
    }

    private fun transitionCaptureBytes(fixture: TransitionFixture): Long =
        planningLegBytes(fixture.interrupted, includeModel = false) +
            planningLegBytes(fixture.resumed, includeModel = true) + fixture.resumedPlan.size +
            planningLegBytes(fixture.fresh, includeModel = true) + fixture.freshPlan.size

    private fun planningLegBytes(fixture: RunFixture, includeModel: Boolean): Long =
        fixture.state.size.toLong() + fixture.progress.size +
            fixture.batches.sumOf { batch ->
                batch.checkpoint.size.toLong() + batch.functions.size + batch.globals.size +
                    batch.types.size + batch.failures.size
            } + if (includeModel) fixture.model.size else 0

    private fun mutableArrays(fixture: TransitionFixture): List<ByteArray> = buildList {
        fun addRun(run: RunFixture, includeModel: Boolean) {
            add(run.state)
            add(run.progress)
            run.batches.forEach { batch ->
                add(batch.checkpoint)
                add(batch.functions)
                add(batch.globals)
                add(batch.types)
                add(batch.failures)
            }
            if (includeModel) add(run.model)
        }
        addRun(fixture.interrupted, includeModel = false)
        addRun(fixture.resumed, includeModel = true)
        add(fixture.resumedPlan)
        addRun(fixture.fresh, includeModel = true)
        add(fixture.freshPlan)
    }

    private fun buildFixture(
        specs: List<BatchSpec>,
        inventoryOverride: String? = null,
        batchCommitmentOverride: String? = null,
        semanticShaOverride: String? = null,
        semanticBytesOverride: Long? = null,
    ): RunFixture {
        val rawFragments = specs.map { spec ->
            RawFragments(
                functions = fragment(spec.functions.map { it.bytes }),
                globals = fragment(spec.globals.map { it.bytes }),
                types = fragment(spec.types.map { it.bytes }),
                failures = fragment(spec.failures.map { it.bytes }),
            )
        }
        val allFunctions = specs.flatMap { it.functions }
        val inventory = inventoryOverride ?: sha(
            (allFunctions.joinToString("\n") { it.id } + "\n").toByteArray(),
        )
        val commitment = batchCommitmentOverride ?: batchCommitment(specs, rawFragments)
        val semantic = semanticBinding(specs)
        val state = state(
            functionCount = allFunctions.size,
            planningBatchCount = specs.size,
            canonicalBytes = semanticBytesOverride ?: semantic.canonicalBytes,
            semanticSha256 = semanticShaOverride ?: semantic.sha256,
            batchCommitmentSha256 = commitment,
        )
        val stateSha = sha(state)
        var start = 0
        val batches = specs.zip(rawFragments).map { (spec, raw) ->
            val end = start + spec.functions.size
            val checkpoint = checkpoint(stateSha, inventory, start, end, spec, raw)
            start = end
            GccPlanningBatchBytes(checkpoint, raw.functions, raw.globals, raw.types, raw.failures)
        }
        val partial = allFunctions.count { it.status == "partial" }.toLong()
        val failed = allFunctions.count { it.status == "failed" }.toLong()
        val progress = progress(
            total = allFunctions.size.toLong(),
            completed = allFunctions.size.toLong(),
            partial = partial,
            failed = failed,
        )
        val globals = TreeMap<String, Record>()
        val types = TreeMap<String, Record>()
        specs.forEach { spec ->
            spec.globals.forEach { globals.putIfAbsent(it.id, it) }
            spec.types.forEach { types.putIfAbsent(it.id, it) }
        }
        val model = model(allFunctions.map { it.bytes }, globals.values.map { it.bytes }, types.values.map { it.bytes })
        return RunFixture(state, progress, batches, model, specs, inventory, semantic, commitment)
    }

    private fun checkpoint(
        stateSha: String,
        inventorySha: String,
        start: Int,
        end: Int,
        spec: BatchSpec,
        raw: RawFragments,
    ): ByteArray = buildString {
        val partial = spec.functions.count { it.status == "partial" }
        val failed = spec.functions.count { it.status == "failed" }
        append("schemaVersion=1\n")
        append("exporterVersion=9\n")
        append("recoveryMode=planning\n")
        append("stateSha256=$stateSha\n")
        append("inventorySha256=$inventorySha\n")
        append("startIndex=$start\n")
        append("endExclusive=$end\n")
        appendFragment("function", raw.functions)
        append("recovered=0\npartial=$partial\nfailed=$failed\n")
        append("functionIds=${spec.functions.joinToString(",") { it.id }}\n")
        appendFragment("global", raw.globals)
        append("globalIds=${spec.globals.joinToString(",") { it.id }}\n")
        appendFragment("type", raw.types)
        append("typeIds=${spec.types.joinToString(",") { it.id }}\n")
        appendFragment("failure", raw.failures)
        append("failureIds=${spec.failures.joinToString(",") { it.id }}\n")
    }.toByteArray()

    private fun StringBuilder.appendFragment(prefix: String, bytes: ByteArray) {
        append("${prefix}FragmentBytes=${bytes.size}\n")
        append("${prefix}FragmentSha256=${sha(bytes)}\n")
    }

    private fun state(
        functionCount: Int,
        planningBatchCount: Int,
        canonicalBytes: Long,
        semanticSha256: String,
        batchCommitmentSha256: String,
    ): ByteArray = (
        "{\"schemaVersion\":2,\"exporterVersion\":9,\"exporterSha256\":\"$SHA_B\"," +
            "\"analysisToolSha256\":\"$SHA_C\",\"recoveryMode\":\"planning\"," +
            "\"inputSha256\":\"$SHA_A\",\"language\":\"x86:LE:64:default\",\"compilerSpec\":\"gcc\"," +
            "\"semanticStateBinding\":{\"schemaVersion\":1,\"scope\":\"planning-exporter-visible-program\"," +
            "\"functionCount\":$functionCount,\"planningBatchCount\":$planningBatchCount," +
            "\"canonicalBytes\":$canonicalBytes,\"sha256\":\"$semanticSha256\"," +
            "\"batchCommitmentSha256\":\"$batchCommitmentSha256\"}}\n"
        ).toByteArray()

    private fun progress(
        phase: String = "complete",
        total: Long,
        completed: Long,
        recovered: Long = 0,
        partial: Long,
        failed: Long,
        reused: Long = 0,
    ): ByteArray = (
        "{\"schemaVersion\":1,\"phase\":\"$phase\",\"completed\":$completed,\"total\":$total," +
            "\"recovered\":$recovered,\"partial\":$partial,\"failed\":$failed,\"reused\":$reused," +
            "\"currentFunction\":null}\n"
        ).toByteArray()

    private fun batchCommitment(specs: List<BatchSpec>, raw: List<RawFragments>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("decomp-thing/planning-batch-commitments/v1\n".toByteArray(StandardCharsets.US_ASCII))
        var start = 0L
        specs.zip(raw).forEach { (spec, fragments) ->
            val end = start + spec.functions.size
            updateLong(digest, start)
            updateLong(digest, end)
            listOf(fragments.functions, fragments.globals, fragments.types, fragments.failures).forEach { bytes ->
                updateLong(digest, bytes.size.toLong())
                digest.update(sha(bytes).toByteArray(StandardCharsets.US_ASCII))
            }
            start = end
        }
        return digest.digest().hex()
    }

    private fun semanticBinding(specs: List<BatchSpec>): Semantic {
        val digest = MessageDigest.getInstance("SHA-256")
        val domain = "decomp-thing/program-semantic-fingerprint/v1\n".toByteArray(StandardCharsets.US_ASCII)
        digest.update(domain)
        var bytes = domain.size.toLong()
        fun frame(tag: Byte, record: Record) {
            val id = record.id.toByteArray(StandardCharsets.UTF_8)
            digest.update(tag)
            updateLong(digest, id.size.toLong())
            digest.update(id)
            updateLong(digest, record.bytes.size.toLong())
            digest.update(record.bytes)
            bytes += 17L + id.size + record.bytes.size
        }
        specs.flatMap { it.functions }.forEach { frame(1, record(it.id, it.bytes)) }
        val failures = TreeMap<String, Record>()
        val globals = TreeMap<String, Record>()
        val types = TreeMap<String, Record>()
        specs.forEach { spec ->
            spec.failures.forEach { failures.putIfAbsent(it.id, it) }
            spec.globals.forEach { globals.putIfAbsent(it.id, it) }
            spec.types.forEach { types.putIfAbsent(it.id, it) }
        }
        failures.values.forEach { frame(4, it) }
        globals.values.forEach { frame(2, it) }
        types.values.forEach { frame(3, it) }
        frame(5, record("functions", specs.sumOf { it.functions.size }.toString().toByteArray()))
        return Semantic(bytes, digest.digest().hex())
    }

    private fun updateLong(digest: MessageDigest, value: Long) {
        for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
    }

    private fun function(
        id: String,
        name: String,
        status: String,
        referencedGlobals: List<String> = emptyList(),
    ): FunctionRecord = FunctionRecord(
        id,
        status,
        buildString {
            append("    {\n")
            append("      \"id\": \"$id\",\n")
            append("      \"name\": \"$name\",\n")
            append("      \"address\": \"${addressForId(id)}\",\n")
            append("      \"prototype\": \"void $name(void)\",\n")
            append("      \"status\": \"$status\",\n")
            append("      \"calls\": [],\n")
            append("      \"referencedGlobals\": [${quoted(referencedGlobals)}],\n")
            append("      \"strings\": [],\n")
            append("      \"decompiledC\": null\n")
            append("    }")
        }.toByteArray(),
    )

    private fun globalRecord(id: String, name: String): ByteArray = buildString {
        append("    {\n")
        append("      \"id\": \"$id\",\n")
        append("      \"name\": \"$name\",\n")
        append("      \"address\": \"${addressForId(id)}\",\n")
        append("      \"type\": \"int\",\n")
        append("      \"initializer\": null,\n")
        append("      \"status\": \"recovered\"\n")
        append("    }")
    }.toByteArray()

    private fun typeRecord(id: String, declaration: String): ByteArray = buildString {
        append("    {\n")
        append("      \"id\": \"$id\",\n")
        append("      \"declaration\": \"$declaration\",\n")
        append("      \"sourceAddress\": \"0x1\",\n")
        append("      \"status\": \"partial\"\n")
        append("    }")
    }.toByteArray()

    private fun failureRecord(id: String, message: String): ByteArray = buildString {
        append("    {\n")
        append("      \"id\": \"$id\",\n")
        append("      \"status\": \"failed\",\n")
        append("      \"message\": \"$message\"\n")
        append("    }")
    }.toByteArray()

    private fun model(functions: List<ByteArray>, globals: List<ByteArray>, types: List<ByteArray>): ByteArray =
        buildString {
            append("{\n  \"schemaVersion\": 1,\n  \"inputSha256\": \"$SHA_A\",\n  \"functions\": [\n")
            append(modelRecords(functions))
            append("  ],\n  \"globals\": [\n")
            append(modelRecords(globals))
            append("  ],\n  \"types\": [\n")
            append(modelRecords(types))
            append("  ]\n}\n")
        }.toByteArray()

    private fun fragment(records: List<ByteArray>): ByteArray =
        records.joinToString(",\n") { it.decodeToString() }.toByteArray()

    private fun modelRecords(records: List<ByteArray>): String =
        if (records.isEmpty()) "" else records.joinToString(",\n", postfix = "\n") { it.decodeToString() }

    private fun record(id: String, bytes: ByteArray) = Record(id, bytes)
    private fun sha(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun quoted(values: List<String>) = values.joinToString(", ") { "\"$it\"" }
    private fun functionId(index: Int) = "fn_${index.toString(16).padStart(16, '0')}"
    private fun globalId(index: Int) = "global_${index.toString(16).padStart(16, '0')}"
    private fun typeId(index: Int) = "type_${index.toString(16).padStart(64, '0')}"
    private fun addressForId(id: String) = "0x${id.substringAfter('_').trimStart('0').ifEmpty { "0" }}"

    private data class Record(val id: String, val bytes: ByteArray)
    private data class FunctionRecord(val id: String, val status: String, val bytes: ByteArray)
    private data class BatchSpec(
        val functions: List<FunctionRecord>,
        val globals: List<Record> = emptyList(),
        val types: List<Record> = emptyList(),
        val failures: List<Record> = emptyList(),
    )
    private data class RawFragments(
        val functions: ByteArray,
        val globals: ByteArray,
        val types: ByteArray,
        val failures: ByteArray,
    )
    private data class Semantic(val canonicalBytes: Long, val sha256: String)
    private data class RunFixture(
        val state: ByteArray,
        val progress: ByteArray,
        val batches: List<GccPlanningBatchBytes>,
        val model: ByteArray,
        val specs: List<BatchSpec>,
        val inventorySha256: String,
        val semantic: Semantic,
        val batchCommitmentSha256: String,
    )

    private data class TransitionFixture(
        val interrupted: RunFixture,
        val resumed: RunFixture,
        val fresh: RunFixture,
        val resumedPlan: ByteArray,
        val freshPlan: ByteArray,
    )

    private fun GccPlanningBatchBytes.withCheckpoint(replacement: ByteArray) =
        GccPlanningBatchBytes(replacement, functions, globals, types, failures)

    private fun GccPlanningBatchBytes.withFunctions(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, replacement, globals, types, failures)

    private fun GccPlanningBatchBytes.withGlobals(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, functions, replacement, types, failures)

    private fun GccPlanningBatchBytes.withTypes(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, functions, globals, replacement, failures)

    private fun GccPlanningBatchBytes.withFailures(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, functions, globals, types, replacement)

    private fun javap(type: Class<*>): String {
        val executable = Path.of(System.getProperty("java.home"), "bin", "javap")
        val process = ProcessBuilder(
            executable.toString(),
            "-classpath",
            System.getProperty("java.class.path"),
            "-p",
            type.name,
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        assertTrue(process.waitFor(10, TimeUnit.SECONDS), "javap timed out")
        assertEquals(0, process.exitValue(), output)
        return output
    }

    private companion object {
        val SHA_A = "a".repeat(64)
        val SHA_B = "b".repeat(64)
        val SHA_C = "c".repeat(64)
        val SHA_F = "f".repeat(64)
    }
}
