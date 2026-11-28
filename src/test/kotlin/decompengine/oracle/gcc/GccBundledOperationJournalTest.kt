package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.BundledGhidra
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskMount
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.FullTreeDiskScratchOperation
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertFails
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledOperationJournalTest {
    @Test
    fun `resume chain preserves stopped evidence and links every second-leg transition`() = withStoppedJournal { journal, resumed ->
        val original = names(journal.path).associateWith { Files.readAllBytes(journal.path.resolve(it)) }
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        journal.recordResumePrepared(resumed)
        journal.recordResumeAttachment(payload)
        journal.recordResumeStartAuthorization()
        journal.recordResumeExecution(payload)
        journal.recordResumeExportAssessment(payload)
        var previous = original.getValue("analysis-state-captured.json")
        for (name in listOf("resume-prepared.json", "resume-attachment.json", "resume-start-authorized.json",
            "resume-execution.json", "resume-export-assessment.json")) {
            val bytes = Files.readAllBytes(journal.path.resolve(name))
            val record = OracleJson.parseCanonical(bytes).jsonObject
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(previous)), record["previousSha256"])
            assertEquals(JsonPrimitive(false), record["complete"])
            assertEquals(JsonPrimitive(false), record["releaseEligible"])
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256")))), record["recordSha256"])
            assertEquals("r--------", permissions(journal.path.resolve(name)))
            previous = bytes
        }
        assertContentEquals(resumed, Files.readAllBytes(journal.path.resolve("resume-definition.json")))
        assertEquals(17, names(journal.path).size)
        original.forEach { (name, bytes) -> assertContentEquals(bytes, Files.readAllBytes(journal.path.resolve(name))) }
        journal.verify("after resume chain")
        assertFails { journal.recordResumeStartAuthorization() }
        assertFails { journal.verify("after rejected repeated START") }
    }

    @Test
    fun `resume transitions reject missing predecessor without publishing new records`() {
        val payload = OracleJson.canonicalBytes(JsonObject(emptyMap()))
        for (step in 0..3) withStoppedJournal { journal, _ ->
            val originalNames = names(journal.path)
            assertFails {
                when (step) {
                    0 -> journal.recordResumeAttachment(payload)
                    1 -> journal.recordResumeStartAuthorization()
                    2 -> journal.recordResumeExecution(payload)
                    else -> journal.recordResumeExportAssessment(payload)
                }
            }
            assertEquals(originalNames, names(journal.path))
            assertFails { journal.verify("poisoned out-of-order resume") }
        }
    }

    @Test
    fun `resume preparation rejects substituted manifest and larger budgets before publication`() {
        for (changedField in listOf("manifest", "count", "budget", "engine", "lease", "input", "runtime")) withStoppedJournal { journal, bytes ->
            val originalNames = names(journal.path)
            val parsed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(bytes)
            val originalRuntime = checkNotNull(parsed.bundledRuntime)
            val runtime = if (changedField == "runtime") GccBundledGhidraRuntime(originalRuntime.root,
                originalRuntime.classPath.mapIndexed { index, entry -> if (index == 1) entry.copy(sha256 = "e".repeat(64)) else entry },
                invocationVersion = 4) else originalRuntime
            val artifacts = if (changedField == "input") parsed.artifacts.map {
                if (it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) it.copy(sha256 = "d".repeat(64)) else it
            } else parsed.artifacts
            val state = when (changedField) {
                "manifest" -> parsed.analysisState.copy(manifestSha256 = "a".repeat(64))
                "count" -> parsed.analysisState.copy(entryCount = 2)
                else -> parsed.analysisState
            }
            val lease = if (changedField == "lease") parsed.outputLease.copy(inode = 100) else parsed.outputLease
            val changed = GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
                if (changedField == "engine") "lto1" else parsed.engineId, parsed.runKind, artifacts, state,
                runtime.command(artifacts, state, lease), parsed.environment, lease,
                if (changedField == "budget") parsed.budgets.copy(wallClockMillis = parsed.budgets.wallClockMillis + 1000) else parsed.budgets,
                runtime,
            )).canonicalBytes
            assertFails(changedField) { journal.recordResumePrepared(changed) }
            assertEquals(originalNames, names(journal.path))
        }
    }

    @Test
    fun `resume preparation requires stopped-state capture and detects later definition replacement`() {
        withJournalRoot { root ->
            val intent = intent()
            GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                journal.recordLease(evidence(intent))
                journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
                assertFails { journal.recordResumePrepared(definition()) }
                assertFalse(Files.exists(journal.path.resolve("resume-definition.json")))
            }
        }
        withStoppedJournal { journal, resumed ->
            journal.recordResumePrepared(resumed)
            val file = journal.path.resolve("resume-definition.json")
            Files.move(file, journal.path.parent.resolve("retained-resume-definition"))
            immutableFile(file, resumed)
            assertFails { journal.verify("same bytes with replaced resume definition inode") }
        }
    }

    private fun withStoppedJournal(intentBytes: ByteArray = intent(), action: (GccBundledOperationJournal, ByteArray) -> Unit) = withJournalRoot { root ->
        val intent = intentBytes
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        val originalBytes = definition(runKind = GccCompilerEngineContainmentRunKind.INTERRUPTED)
        val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(originalBytes)
        val oldRuntime = checkNotNull(original.bundledRuntime)
        val runtime = GccBundledGhidraRuntime(oldRuntime.root, oldRuntime.classPath, invocationVersion = 4)
        val snapshot = GccBundledAnalysisStateSnapshot(1, 3, payload)
        val state = original.analysisState.copy(mode = GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
            manifestSha256 = snapshot.sha256, entryCount = 1, totalBytes = 3)
        val resumed = GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
            original.engineId, GccCompilerEngineContainmentRunKind.RESUMED, original.artifacts, state,
            runtime.command(original.artifacts, state, original.outputLease), original.environment, original.outputLease,
            original.budgets, runtime,
        )).canonicalBytes
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(originalBytes, DEPLOYMENT_SHA256)
            journal.recordAttachment(payload)
            journal.recordStartAuthorization()
            journal.recordInterruptionAuthorization(payload)
            journal.recordInterruptedExecution(payload)
            journal.recordInterruptedPrefixAssessment(payload)
            journal.recordInterruptedAnalysisState(snapshot) { wallSnapshot(elapsedNanos = STOPPED_ELAPSED_NANOS) }
            action(journal, resumed)
        }
    }

    @Test
    fun `later invocation reopens a stopped chain only after the earlier owner releases both journal locks`() = withJournalRoot { root ->
        val intent = intent()
        val earlier = recoverableStoppedJournal(root, intent)
        val stoppedNames = names(earlier.path)
        val stoppedBytes = stoppedNames.associateWith { Files.readAllBytes(earlier.path.resolve(it)).toList() }
        // The earlier owner is still live: both of its cooperative locks are held.
        val live = assertFails { GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256) }
        assertTrue(live.message.orEmpty().contains("held by a live owner"), live.toString())
        assertEquals(stoppedNames, names(earlier.path))
        earlier.verify("after a refused later-invocation recovery")
        earlier.close()
        val path = root.resolve(operationName())
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
            assertEquals(path, later.path)
            assertEquals(null, later.recoveryRecordBytes)
            val stopped = later.recoveredStoppedEvidence
            assertContentEquals(Files.readAllBytes(path.resolve("definition.json")), stopped.definitionBytes)
            assertContentEquals(Files.readAllBytes(path.resolve("interrupted-execution.json")), stopped.interruptedRecordBytes)
            assertContentEquals(Files.readAllBytes(path.resolve("analysis-state-manifest.json")), stopped.stateManifestBytes)
            assertEquals(1L, stopped.stateEntryCount)
            assertEquals(3L, stopped.stateTotalBytes)
            assertEquals(OPERATION_ID, stopped.diskEvidence.operationId)
            assertEquals(null, stopped.retainedAdoptionPayloadBytes)
            // The allowance is the stopped commit's remaining budget, not the earlier execution receipt's.
            assertEquals(STOPPED_REMAINING_NANOS, stopped.stoppedRemainingNanos)
            assertEquals(RECOVERY_CAP_MILLIS, stopped.recoveryWallCapMillis)
            assertEquals(RECOVERY_CAP_MILLIS, stopped.resumeAllowanceMillis)
            // While this later owner holds the journal, a third invocation is refused in turn.
            val third = assertFails { GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256) }
            assertTrue(third.message.orEmpty().contains("held by a live owner"), third.toString())
            val stateRecord = Files.readAllBytes(path.resolve("analysis-state-captured.json"))
            val adopted = later.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS)
            val record = OracleJson.parseCanonical(adopted).jsonObject
            assertEquals(JsonPrimitive("gcc-bundled-later-invocation-recovery-adopted-v1"), record["provider"])
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(stateRecord)), record["previousSha256"])
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(intent)), record["intentSha256"])
            assertContentEquals(adopted, later.recoveryRecordBytes)
            continueRecoveredResume(later)
            val resumed = OracleJson.parseCanonical(Files.readAllBytes(path.resolve("resume-prepared.json"))).jsonObject
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(adopted)), resumed["previousSha256"])
            assertEquals(stoppedNames + "recovery-adopted.json" + RESUME_NAMES, names(path))
            stoppedBytes.forEach { (name, bytes) -> assertEquals(bytes, Files.readAllBytes(path.resolve(name)).toList(), name) }
            later.verify("after the recovered resume chain")
        }
        // A history that reached resume START is never adopted again.
        assertFails { GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256) }
    }

    @Test
    fun `a later owner that crashed after adopting resumes from the same single adoption and allowance`() = withJournalRoot { root ->
        val intent = intent()
        recoverableStoppedJournal(root, intent).close()
        val path = root.resolve(operationName())
        val stateRecord = Files.readAllBytes(path.resolve("analysis-state-captured.json"))
        val adopted = GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { first ->
            first.recordRecoveryAdopted(emptyList(), 40_000)
        }
        val payload = OracleJson.canonicalBytes(OracleJson.parseCanonical(adopted).jsonObject.getValue("recovery"))
        // The first later owner is gone before any resume definition was written.
        val names = names(path)
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { second ->
            assertContentEquals(adopted, second.recoveryRecordBytes)
            assertContentEquals(payload, second.recoveredStoppedEvidence.retainedAdoptionPayloadBytes)
            // The recorded allowance is kept, not refreshed to the commit cap.
            assertEquals(40_000L, second.recoveredStoppedEvidence.resumeAllowanceMillis)
            assertEquals(RECOVERY_CAP_MILLIS, second.recoveredStoppedEvidence.recoveryWallCapMillis)
            // A second, possibly larger, allowance can never be published over the retained one.
            assertFails { second.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS) }
        }
        assertEquals(names, names(path))
        // Resume staging is held to the retained 40 s allowance, not the 52 s commit cap.
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { second ->
            assertContentEquals(adopted, second.completeRetainedRecoveryAdoption())
            val refused = assertFails { second.recordResumePrepared(recoverableResumeDefinition(41_000)) }
            assertTrue(refused.message.orEmpty().contains("exceeds its adopted wall allowance"), refused.toString())
        }
        assertEquals(names, names(path))
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { second ->
            assertContentEquals(adopted, second.completeRetainedRecoveryAdoption())
            continueRecoveredResume(second, 40_000)
        }
        assertEquals(names + RESUME_NAMES, names(path))
    }

    @Test
    fun `a crash between linking and renaming the adoption is completed without new bytes`() = withJournalRoot { root ->
        val intent = intent()
        recoverableStoppedJournal(root, intent).close()
        val path = root.resolve(operationName())
        val stateRecord = Files.readAllBytes(path.resolve("analysis-state-captured.json"))
        val adopted = GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { first ->
            first.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS)
        }
        // Model the atomic publisher's crash window: the complete named temporary exists, the final name does not.
        Files.move(path.resolve("recovery-adopted.json"), path.resolve(".recovery-adopted.json.atomic"))
        val temporaryInode = Files.getAttribute(path.resolve(".recovery-adopted.json.atomic"), "unix:ino")
        // Resume is still refused until the retained adoption is completed.
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { second ->
            assertEquals(null, second.recoveryRecordBytes)
            assertFails { second.recordResumePrepared(recoverableResumeDefinition()) }
        }
        assertTrue(Files.exists(path.resolve(".recovery-adopted.json.atomic")))
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { second ->
            assertFails { second.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS) }
        }
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { second ->
            assertContentEquals(adopted, second.completeRetainedRecoveryAdoption())
            assertFalse(Files.exists(path.resolve(".recovery-adopted.json.atomic")))
            assertEquals(temporaryInode, Files.getAttribute(path.resolve("recovery-adopted.json"), "unix:ino"))
            continueRecoveredResume(second)
        }
        // Both names at once, or an invalid temporary, stay fail-closed.
        for (case in listOf("both", "invalid")) withJournalRoot { other ->
            recoverableStoppedJournal(other, intent).close()
            val operation = other.resolve(operationName())
            GccBundledOperationJournal.openStoppedForRecovery(other, OPERATION_ID, intent, DEPLOYMENT_SHA256).use {
                it.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS)
            }
            if (case == "both") Files.copy(operation.resolve("recovery-adopted.json"), operation.resolve(".recovery-adopted.json.atomic"))
            else {
                Files.delete(operation.resolve("recovery-adopted.json"))
                immutableFile(operation.resolve(".recovery-adopted.json.atomic"), "{}".encodeToByteArray())
            }
            val before = names(operation)
            assertFails(case) { GccBundledOperationJournal.openStoppedForRecovery(other, OPERATION_ID, intent, DEPLOYMENT_SHA256) }
            assertEquals(before, names(operation), case)
        }
    }

    @Test
    fun `a retained adoption is rebuilt in full from verified evidence and foreign bytes are refused under either name`() {
        val otherUnit = "decomp-gcc-cc1-${"7".repeat(32)}.scope"
        fun absence(change: (MutableMap<String, JsonElement>) -> Unit): (MutableMap<String, JsonElement>) -> Unit = { payload ->
            payload["priorOwnerAbsence"] = JsonObject(payload.getValue("priorOwnerAbsence").jsonObject.toMutableMap().also(change))
        }
        val foreign = linkedMapOf<String, (MutableMap<String, JsonElement>) -> Unit>(
            "unrelated-argv" to { it["recoveryArgv"] = JsonArray(listOf(JsonPrimitive("gcc-engine-plan"), JsonPrimitive("unrelated"))) },
            "absence-record" to absence { it["stoppedWorkerAbsenceRecordSha256"] = JsonPrimitive("e".repeat(64)) },
            "missing-journal-lock" to absence { it.remove("journalRootLock") },
            "missing-mount-lock" to absence { it.remove("scratchMountLock") },
            "missing-cgroup-assertion" to absence { it.remove("interruptedUnitCgroupAbsent") },
            "cgroup-present" to absence { it["interruptedUnitCgroupAbsent"] = JsonPrimitive(false) },
            "other-unit" to absence { it["interruptedUnit"] = JsonPrimitive(otherUnit) },
            "other-run-root" to { it["runRoot"] = JsonObject(mapOf("device" to JsonPrimitive(7), "inode" to JsonPrimitive(100),
                "mountId" to JsonPrimitive(42))) },
            "other-lease" to { it["leaseRecordSha256"] = JsonPrimitive("e".repeat(64)) },
            "idle-charged" to { it["idleWallTimeBetweenOwnersCharged"] = JsonPrimitive(true) },
            "extra-field" to { it["fixtureOnly"] = JsonPrimitive(true) },
            "over-cap" to { it["resumeWallBudgetMillis"] = JsonPrimitive(RECOVERY_CAP_MILLIS + 1_000) },
        )
        for (name in listOf("recovery-adopted.json", ".recovery-adopted.json.atomic")) {
            // Control: the test encoder reproduces a valid adoption exactly, so each refusal below is about content.
            withJournalRoot { root ->
                val intent = intent()
                recoverableStoppedJournal(root, intent).close()
                val path = root.resolve(operationName())
                val record = linkedAdoptionRecord(intent, path, expectedAdoption(intent, path, budget = 30_000))
                immutableFile(path.resolve(name), record)
                GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                    assertEquals(30_000L, later.recoveredStoppedEvidence.resumeAllowanceMillis, name)
                    assertContentEquals(record, later.completeRetainedRecoveryAdoption(), name)
                }
            }
            for ((case, change) in foreign) withJournalRoot { root ->
                val intent = intent()
                recoverableStoppedJournal(root, intent).close()
                val path = root.resolve(operationName())
                immutableFile(path.resolve(name),
                    linkedAdoptionRecord(intent, path, expectedAdoption(intent, path).also(change)))
                val failure = requireRefusedUnchanged(root, path, intent, "$name $case")
                assertTrue(failure.message.orEmpty().contains("recovery"), "$name $case: $failure")
            }
        }
    }

    @Test
    fun `a CLI-bound adoption records exactly the original argv plus one recovery selector`() {
        val original = listOf("gcc-engine-plan", "cc1", "/record-only-test/cc1", "--profile", "/record-only-test/profile.json",
            "--ghidra-archive", "/record-only-test/ghidra.zip", "--output", "/record-only-test/output",
            "--scratch", "/record-only-test/scratch", "--resume-after-checkpoint", "512")
        val intent = OracleJson.canonicalBytes(JsonObject(mapOf("testIntent" to JsonPrimitive("cli"),
            "cliInvocation" to JsonObject(mapOf("argv" to JsonArray(original.map(::JsonPrimitive)))))))
        val selector = listOf("--recover-operation", OPERATION_ID)
        val accepted = listOf(original + selector, original.take(3) + selector + original.drop(3))
        val refused = mapOf(
            "none" to emptyList(), "no-selector" to original, "other-operation" to original + listOf("--recover-operation", SECOND_OPERATION_ID),
            "two-selectors" to original + selector + selector, "selector-first" to selector + original,
            "changed-original" to original.dropLast(1) + "1024" + selector, "dangling-selector" to original + "--recover-operation",
            // Removing these selectors restores the original, but the recorded argv itself does not parse.
            "inside-checkpoint-option" to original.dropLast(1) + selector + original.last(),
            "inside-profile-option" to original.take(4) + selector + original.drop(4),
        )
        for (argv in accepted) withJournalRoot { root ->
            recoverableStoppedJournal(root, intent).close()
            GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                val record = OracleJson.parseCanonical(later.recordRecoveryAdopted(argv, RECOVERY_CAP_MILLIS)).jsonObject
                assertEquals(JsonArray(argv.map(::JsonPrimitive)), record.getValue("recovery").jsonObject["recoveryArgv"])
            }
        }
        for ((case, argv) in refused) {
            withJournalRoot { root ->
                recoverableStoppedJournal(root, intent).close()
                GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                    assertFails(case) { later.recordRecoveryAdopted(argv, RECOVERY_CAP_MILLIS) }
                }
                assertFalse(Files.exists(root.resolve(operationName()).resolve("recovery-adopted.json")), case)
            }
            // The same foreign argv is refused when a crashed owner left it behind under either name.
            for (name in listOf("recovery-adopted.json", ".recovery-adopted.json.atomic")) withJournalRoot { root ->
                recoverableStoppedJournal(root, intent).close()
                val path = root.resolve(operationName())
                immutableFile(path.resolve(name), linkedAdoptionRecord(intent, path, expectedAdoption(intent, path, argv = argv)))
                requireRefusedUnchanged(root, path, intent, "retained $name $case")
            }
        }
    }

    @Test
    fun `a freshly adopted allowance bounds resume staging`() = withJournalRoot { root ->
        val intent = intent()
        recoverableStoppedJournal(root, intent).close()
        val path = root.resolve(operationName())
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
            later.recordRecoveryAdopted(emptyList(), 30_000)
            val refused = assertFails { later.recordResumePrepared(recoverableResumeDefinition(31_000)) }
            assertTrue(refused.message.orEmpty().contains("exceeds its adopted wall allowance"), refused.toString())
        }
        assertFalse(Files.exists(path.resolve("resume-definition.json")))
        GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
            later.completeRetainedRecoveryAdoption()
            continueRecoveredResume(later, 30_000)
        }
    }

    @Test
    fun `later invocation refuses changed lineage tampered records residue and unproved absence without mutation`() {
        for (case in listOf("intent", "deployment", "operation", "rewritten-attachment", "flipped-prefix", "manifest",
            "residue", "absence", "authorization")) withJournalRoot { root ->
            val intent = intent()
            recoverableStoppedJournal(root, intent, unitAbsent = case != "absence",
                foreign = if (case == "authorization") "authorization-digest" else null).close()
            val path = root.resolve(operationName())
            when (case) {
                "rewritten-attachment" -> replaceImmutable(path.resolve("attachment.json")) { bytes ->
                    // A self-consistent rewrite still breaks the successor's predecessor digest.
                    val record = OracleJson.parseCanonical(bytes).jsonObject
                    val payload = JsonObject(mapOf("substituted" to JsonPrimitive(true)))
                    val fields = record - "recordSha256" + mapOf("attachment" to payload,
                        "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(payload))))
                    OracleJson.canonicalBytes(JsonObject(fields + ("recordSha256" to
                        JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields)))))))
                }
                "flipped-prefix" -> replaceImmutable(path.resolve("interrupted-prefix-assessment.json")) { bytes ->
                    val text = bytes.decodeToString()
                    check(text.contains("\"fixtureOnly\": true")) { "prefix record lacks its fixture payload: $text" }
                    text.replace("\"fixtureOnly\": true", "\"fixtureOnly\": false").encodeToByteArray()
                }
                "manifest" -> replaceImmutable(path.resolve("analysis-state-manifest.json")) {
                    recoverableManifest(totalBytes = 4)
                }
                "residue" -> Files.writeString(path.resolve("unexpected.json"), "{}")
            }
            requireRefusedUnchanged(root, path, intent, case,
                operationId = if (case == "operation") SECOND_OPERATION_ID else OPERATION_ID,
                expectedIntent = if (case == "intent") intent("changed later intent") else intent,
                deployment = if (case == "deployment") "b".repeat(64) else DEPLOYMENT_SHA256)
        }
    }

    @Test
    fun `later invocation refuses an otherwise consistent chain whose absence receipt names another command`() {
        for (foreign in listOf("attachment-unit", "attachment-cgroup", "attachment-nonce", "attachment-deployment", "keeper",
            "authorization-request", "execution-attachment", "execution-request", "outcome-status", "outcome-keeper",
            "outcome-nonce")) withJournalRoot { root ->
            val intent = intent()
            // Every record is published through the journal writer, so the linked chain itself is consistent.
            recoverableStoppedJournal(root, intent, foreign = foreign).close()
            val failure = requireRefusedUnchanged(root, root.resolve(operationName()), intent, foreign)
            assertTrue(failure.message.orEmpty().contains("not bound to this operation's interrupted command"), "$foreign: $failure")
        }
    }

    @Test
    fun `the resume allowance is the budget committed with the stopped state and never outlives it`() {
        // A deadline that expired before the stopped commit leaves no recoverable stopped state.
        withJournalRoot { root ->
            val intent = intent()
            assertFails { recoverableStoppedJournal(root, intent, stoppedWall = { error("operation wall deadline expired") }) }
            val path = root.resolve(operationName())
            assertFalse(Files.exists(path.resolve("analysis-state-captured.json")))
            requireRefusedUnchanged(root, path, intent, "expired-before-commit")
        }
        // A commit snapshot that is not this operation's own later snapshot is refused.
        for ((case, wall) in listOf(
            "foreign-deadline" to wallSnapshot(started = 2_000, elapsedNanos = STOPPED_ELAPSED_NANOS),
            "before-execution" to wallSnapshot(elapsedNanos = EXECUTION_ELAPSED_NANOS - 1),
            "other-budget" to wallSnapshot(maximumMillis = 61_000, elapsedNanos = STOPPED_ELAPSED_NANOS),
        )) withJournalRoot { root ->
            val intent = intent()
            recoverableStoppedJournal(root, intent, stoppedWall = { wall }).close()
            requireRefusedUnchanged(root, root.resolve(operationName()), intent, case)
        }
        // An adoption cannot credit back the time spent after the worker exited.
        withJournalRoot { root ->
            val intent = intent()
            recoverableStoppedJournal(root, intent).close()
            val path = root.resolve(operationName())
            val stateRecord = Files.readAllBytes(path.resolve("analysis-state-captured.json"))
            val executionAllowance = (60_000L * 1_000_000L - EXECUTION_ELAPSED_NANOS) / 1_000_000_000L * 1_000L
            assertTrue(executionAllowance > RECOVERY_CAP_MILLIS)
            for (budget in listOf(executionAllowance, RECOVERY_CAP_MILLIS + 1_000, 1_000L, RECOVERY_CAP_MILLIS - 1)) {
                GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                    assertFails("$budget") { later.recordRecoveryAdopted(emptyList(), budget) }
                }
            }
            assertFalse(Files.exists(path.resolve("recovery-adopted.json")))
            GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                later.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS)
            }
        }
    }

    @Test
    fun `later invocation refuses admitted fresh completed and resume-started histories`() {
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        for (history in listOf("prepared", "fresh-exported", "resume-started", "adopted-resume-started")) withJournalRoot { root ->
            val intent = intent()
            when (history) {
                "resume-started" -> recoverableStoppedJournal(root, intent).use { it.recordResumePrepared(recoverableResumeDefinition()) }
                "adopted-resume-started" -> {
                    recoverableStoppedJournal(root, intent).close()
                    GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                        later.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS)
                        later.recordResumePrepared(recoverableResumeDefinition())
                    }
                }
                else -> GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                    journal.recordLease(evidence(intent))
                    journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
                    if (history == "fresh-exported") {
                        journal.recordAttachment(payload)
                        journal.recordStartAuthorization()
                        journal.recordExecution(payload)
                        journal.recordExportAssessment(payload)
                    }
                }
            }
            requireRefusedUnchanged(root, root.resolve(operationName()), intent, history)
        }
    }

    @Test
    fun `same-owner and reopened journals cannot skip or forge the later-owner record`() {
        // A same-owner stopped journal never contains a recovery record, so it cannot record one.
        withStoppedJournal { journal, _ ->
            val before = names(journal.path)
            assertFails { journal.recordRecoveryAdopted(emptyList(), RECOVERY_CAP_MILLIS) }
            assertEquals(before, names(journal.path))
        }
        withJournalRoot { root ->
            val intent = intent()
            recoverableStoppedJournal(root, intent).close()
            val path = root.resolve(operationName())
            val before = names(path)
            // A reopened journal must name its later owner before any resume record.
            GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                val skipped = assertFails { later.recordResumePrepared(recoverableResumeDefinition()) }
                assertTrue(skipped.message.orEmpty().contains("must record its later-invocation owner before resume"), skipped.toString())
            }
            assertEquals(before, names(path))
            GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                // An operation without a CLI invocation records no argv; a forged one is refused.
                assertFails { later.recordRecoveryAdopted(listOf("gcc-engine-plan", "forged"), RECOVERY_CAP_MILLIS) }
            }
            assertEquals(before, names(path))
            GccBundledOperationJournal.openStoppedForRecovery(root, OPERATION_ID, intent, DEPLOYMENT_SHA256).use { later ->
                assertFails { later.completeRetainedRecoveryAdoption() }
            }
            assertEquals(before, names(path))
        }
    }

    private fun requireRefusedUnchanged(root: Path, path: Path, intent: ByteArray, case: String,
        operationId: String = OPERATION_ID, expectedIntent: ByteArray = intent, deployment: String = DEPLOYMENT_SHA256): Throwable {
        val before = names(path).associateWith { Files.readAllBytes(path.resolve(it)).toList() }
        val failure = assertFails(case) { GccBundledOperationJournal.openStoppedForRecovery(root, operationId, expectedIntent, deployment) }
        assertEquals(before, names(path).associateWith { Files.readAllBytes(path.resolve(it)).toList() }, case)
        // A refused recovery releases both locks it took.
        LinuxFilesystemSyscalls.openRoot(root).use { assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(it), case); LinuxFilesystemSyscalls.unlock(it) }
        LinuxFilesystemSyscalls.openRoot(path).use { assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(it), case); LinuxFilesystemSyscalls.unlock(it) }
        return failure
    }

    private fun continueRecoveredResume(journal: GccBundledOperationJournal, allowance: Long = RECOVERY_CAP_MILLIS) {
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        journal.recordResumePrepared(recoverableResumeDefinition(allowance))
        journal.recordResumeAttachment(payload)
        journal.recordResumeStartAuthorization()
        journal.recordResumeExecution(payload)
        journal.recordResumeExportAssessment(payload)
    }

    /** The full adoption payload expected for [path]'s stopped evidence, as a mutable tree for foreign variants. */
    private fun expectedAdoption(intent: ByteArray, path: Path, argv: List<String> = emptyList(),
        budget: Long = RECOVERY_CAP_MILLIS): MutableMap<String, JsonElement> = linkedMapOf(
        "provider" to JsonPrimitive(RECOVERY_PAYLOAD_PROVIDER), "schemaVersion" to JsonPrimitive(1),
        "operationId" to JsonPrimitive(OPERATION_ID), "intentSha256" to JsonPrimitive(OracleArtifacts.sha256(intent)),
        "recoveryArgv" to JsonArray(argv.map(::JsonPrimitive)),
        "stoppedStateRecordSha256" to JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(path.resolve("analysis-state-captured.json")))),
        "priorOwnerAbsence" to JsonObject(mapOf(
            "journalRootLock" to JsonPrimitive("acquired-without-blocking"),
            "operationJournalLock" to JsonPrimitive("acquired-without-blocking"),
            "scratchMountLock" to JsonPrimitive("acquired-without-blocking"),
            "stoppedWorkerAbsenceRecordSha256" to JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(path.resolve("interrupted-execution.json")))),
            "interruptedUnit" to JsonPrimitive(GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
                Files.readAllBytes(path.resolve("definition.json"))).unitName),
            "interruptedUnitCgroupAbsent" to JsonPrimitive(true),
        )),
        "diskEvidenceSha256" to JsonPrimitive(evidence(intent).evidenceSha256),
        "leaseRecordSha256" to JsonPrimitive(evidence(intent).leaseRecordSha256),
        "runRoot" to JsonObject(mapOf("device" to JsonPrimitive(7), "inode" to JsonPrimitive(99), "mountId" to JsonPrimitive(42))),
        "resumeWallBudgetMillis" to JsonPrimitive(budget), "idleWallTimeBetweenOwnersCharged" to JsonPrimitive(false),
        "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
    )

    /** A self-consistent linked adoption record, written exactly as the journal writer would encode it. */
    private fun linkedAdoptionRecord(intent: ByteArray, path: Path, payload: Map<String, JsonElement>): ByteArray {
        val payloadBytes = OracleJson.canonicalBytes(JsonObject(payload))
        val fields = linkedMapOf<String, JsonElement>(
            "provider" to JsonPrimitive("gcc-bundled-later-invocation-recovery-adopted-v1"), "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive(OPERATION_ID), "intentSha256" to JsonPrimitive(OracleArtifacts.sha256(intent)),
            "previousSha256" to JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(path.resolve("analysis-state-captured.json")))),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "recovery" to JsonObject(payload), "recoverySha256" to JsonPrimitive(OracleArtifacts.sha256(payloadBytes)),
        )
        fields["recordSha256"] = JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))
        return OracleJson.canonicalBytes(JsonObject(fields))
    }

    private fun recoverableManifest(totalBytes: Long = 3) = OracleJson.canonicalBytes(JsonObject(mapOf(
        "entryCount" to JsonPrimitive(1), "totalBytes" to JsonPrimitive(totalBytes), "fixtureOnly" to JsonPrimitive(true),
    )))

    private fun recoverableResumeDefinition(wallClockMillis: Long = RECOVERY_CAP_MILLIS): ByteArray {
        val original = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
            definition(runKind = GccCompilerEngineContainmentRunKind.INTERRUPTED))
        val runtime = GccBundledGhidraRuntime(checkNotNull(original.bundledRuntime).root, checkNotNull(original.bundledRuntime).classPath,
            invocationVersion = 4)
        val state = original.analysisState.copy(mode = GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
            manifestSha256 = OracleArtifacts.sha256(recoverableManifest()), entryCount = 1, totalBytes = 3)
        return GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
            original.engineId, GccCompilerEngineContainmentRunKind.RESUMED, original.artifacts, state,
            runtime.command(original.artifacts, state, original.outputLease), original.environment, original.outputLease,
            original.budgets.copy(wallClockMillis = wallClockMillis), runtime,
        )).canonicalBytes
    }

    private fun wallSnapshot(maximumMillis: Long = 60_000, started: Long = 1_000, elapsedNanos: Long) = JsonObject(mapOf(
        "provider" to JsonPrimitive("kotlin-contained-operation-wall-deadline-v1"),
        "maximumWallMillis" to JsonPrimitive(maximumMillis), "startedMonotonicNanos" to JsonPrimitive(started),
        "elapsedNanos" to JsonPrimitive(elapsedNanos), "remainingNanos" to JsonPrimitive(maximumMillis * 1_000_000L - elapsedNanos),
    ))

    private fun selfHashed(fields: Map<String, JsonElement>, field: String): JsonObject =
        JsonObject(fields + (field to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(fields))))))

    /**
     * The earlier owner's exact stopped chain with receipts bound to its definition, returned while that owner
     * still holds both journal locks. [foreign] substitutes one receipt field while keeping every record linked.
     */
    private fun recoverableStoppedJournal(root: Path, intent: ByteArray, unitAbsent: Boolean = true, foreign: String? = null,
        stoppedWall: () -> JsonObject = { wallSnapshot(elapsedNanos = STOPPED_ELAPSED_NANOS) }): GccBundledOperationJournal {
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        val definitionBytes = definition(runKind = GccCompilerEngineContainmentRunKind.INTERRUPTED)
        val selected = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definitionBytes)
        val request = "5".repeat(64)
        val other = "6".repeat(64)
        fun pick(case: String, value: String, substitute: String) = JsonPrimitive(if (foreign == case) substitute else value)
        val attachment = selfHashed(mapOf(
            "provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v1"),
            "unitName" to pick("attachment-unit", selected.unitName, "decomp-gcc-cc1-${"7".repeat(32)}.scope"),
            "controlGroup" to pick("attachment-cgroup", selected.expectedControlGroup, "/foreign.slice/unit.scope"),
            "nonce" to pick("attachment-nonce", selected.bindingSha256, other),
            "requestSha256" to JsonPrimitive(request),
            "deploymentClosureSha256" to pick("attachment-deployment", DEPLOYMENT_SHA256, other),
            "processes" to JsonArray(listOf(JsonObject(mapOf(
                "role" to JsonPrimitive("supervisor-jvm"),
                "namespacePids" to JsonArray(listOf(JsonPrimitive(1), JsonPrimitive(if (foreign == "keeper") 43 else KEEPER_PID)))),
            ))),
        ), "attachmentSha256")
        val authorization = selfHashed(mapOf(
            "provider" to JsonPrimitive("kotlin-contained-command-interrupt-authorization-v1"),
            "requestSha256" to JsonPrimitive(if (foreign == "authorization-request") other else request),
            "keeperPid" to JsonPrimitive(KEEPER_PID), "fixtureOnly" to JsonPrimitive(true),
        ), "authorizationSha256")
        val outcome = JsonObject(mapOf(
            "event" to JsonPrimitive("OUTCOME"), "status" to JsonPrimitive(if (foreign == "outcome-status") "EXITED" else "INTERRUPTED"),
            "keeperPid" to JsonPrimitive(if (foreign == "outcome-keeper") 44 else KEEPER_PID), "requestSha256" to JsonPrimitive(request),
            "nonce" to JsonPrimitive(if (foreign == "outcome-nonce") other else selected.bindingSha256),
        ))
        val attachmentBytes = OracleJson.canonicalBytes(attachment)
        val authorizationBytes = OracleJson.canonicalBytes(authorization)
        val execution = OracleJson.canonicalBytes(selfHashed(mapOf(
            "provider" to JsonPrimitive("kotlin-lease-contained-command-interrupted-v1"),
            "attachmentSha256" to JsonPrimitive(if (foreign == "execution-attachment") other else OracleArtifacts.sha256(attachmentBytes)),
            "requestSha256" to JsonPrimitive(if (foreign == "execution-request") other else request),
            "deploymentClosureSha256" to JsonPrimitive(DEPLOYMENT_SHA256),
            "outcome" to outcome, "outcomeSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(outcome))),
            "unitAbsent" to JsonPrimitive(unitAbsent), "cgroupAbsent" to JsonPrimitive(true), "processesAbsent" to JsonPrimitive(true),
            "interruptionAuthorization" to authorization,
            "interruptionAuthorizationSha256" to JsonPrimitive(
                if (foreign == "authorization-digest") other else OracleArtifacts.sha256(authorizationBytes)),
            "operationWallTime" to wallSnapshot(elapsedNanos = EXECUTION_ELAPSED_NANOS),
        ), "executionSha256"))
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
        try {
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definitionBytes, DEPLOYMENT_SHA256)
            journal.recordAttachment(attachmentBytes)
            journal.recordStartAuthorization()
            journal.recordInterruptionAuthorization(authorizationBytes)
            journal.recordInterruptedExecution(execution)
            journal.recordInterruptedPrefixAssessment(payload)
            journal.recordInterruptedAnalysisState(GccBundledAnalysisStateSnapshot(1, 3, recoverableManifest()), stoppedWall)
            return journal
        } catch (failure: Throwable) {
            journal.close()
            throw failure
        }
    }

    private fun replaceImmutable(path: Path, change: (ByteArray) -> ByteArray) {
        val changed = change(Files.readAllBytes(path))
        Files.delete(path)
        immutableFile(path, changed)
    }

    @Test
    fun `stopped state manifest is durably named and linked only after prefix assessment`() = withJournalRoot { root ->
        val intent = intent()
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            journal.recordAttachment(payload)
            journal.recordStartAuthorization()
            journal.recordInterruptionAuthorization(payload)
            journal.recordInterruptedExecution(payload)
            val prefix = journal.recordInterruptedPrefixAssessment(payload)
            val snapshot = GccBundledAnalysisStateSnapshot(1, 3, payload)
            val receipt = journal.recordInterruptedAnalysisState(snapshot) { wallSnapshot(elapsedNanos = STOPPED_ELAPSED_NANOS) }
            val document = OracleJson.parseCanonical(receipt).jsonObject
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(prefix)), document["previousSha256"])
            assertEquals(JsonPrimitive(snapshot.sha256), document.getValue("analysisState").jsonObject["manifestSha256"])
            assertContentEquals(payload, Files.readAllBytes(journal.path.resolve("analysis-state-manifest.json")))
            assertEquals(11, names(journal.path).size)
            assertEquals("r--------", permissions(journal.path.resolve("analysis-state-manifest.json")))
            journal.verify("after stopped-state publication")
            val manifest = journal.path.resolve("analysis-state-manifest.json")
            Files.setPosixFilePermissions(manifest, PosixFilePermissions.fromString("rw-------"))
            Files.writeString(manifest, "changed")
            assertFails { journal.verify("after altered state manifest") }
        }
    }

    @Test
    fun `state manifest without an interrupted prefix never publishes`() = withJournalRoot { root ->
        val intent = intent()
        val payload = OracleJson.canonicalBytes(JsonObject(emptyMap()))
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            assertFails { journal.recordInterruptedAnalysisState(GccBundledAnalysisStateSnapshot(1, 3, payload)) { wallSnapshot(elapsedNanos = STOPPED_ELAPSED_NANOS) } }
            assertFalse(Files.exists(journal.path.resolve("analysis-state-manifest.json")))
        }
    }

    @Test
    fun `interruption records form a separate durable chain and cannot become completed execution`() = withJournalRoot { root ->
        val intent = intent()
        val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            journal.recordAttachment(payload)
            journal.recordStartAuthorization()
            journal.recordInterruptionAuthorization(payload)
            journal.recordInterruptedExecution(payload)
            val prefix = journal.recordInterruptedPrefixAssessment(payload)
            var previous = Files.readAllBytes(journal.path.resolve("start-authorized.json"))
            for (name in listOf("interrupt-authorized.json", "interrupted-execution.json", "interrupted-prefix-assessment.json")) {
                val bytes = Files.readAllBytes(journal.path.resolve(name))
                val record = OracleJson.parseCanonical(bytes).jsonObject
                assertEquals(JsonPrimitive(OracleArtifacts.sha256(previous)), record["previousSha256"])
                assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256")))), record["recordSha256"])
                assertEquals(JsonPrimitive(false), record["complete"])
                assertEquals(JsonPrimitive(false), record["releaseEligible"])
                assertEquals("r--------", permissions(journal.path.resolve(name)))
                previous = bytes
            }
            assertContentEquals(previous, prefix)
            assertEquals(9, names(journal.path).size)
            journal.verify("retained interrupted chain")
            assertFalse(Files.exists(journal.path.resolve("execution.json")))
            assertFalse(Files.exists(journal.path.resolve("export-assessment.json")))
            assertFailsWith<IllegalStateException> { journal.recordExecution(payload) }
        }
    }

    @Test
    fun `interrupted execution without durable authorization preserves START residue`() = withJournalRoot { root ->
        val intent = intent()
        val payload = OracleJson.canonicalBytes(JsonObject(emptyMap()))
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            journal.recordAttachment(payload)
            journal.recordStartAuthorization()
            assertFailsWith<IllegalStateException> { journal.recordInterruptedExecution(payload) }
            assertEquals(6, names(journal.path).size)
            assertFalse(Files.exists(journal.path.resolve("interrupted-execution.json")))
        }
    }

    @Test
    fun `altered interruption authorization prevents any interrupted execution publication`() = withJournalRoot { root ->
        val intent = intent()
        val payload = OracleJson.canonicalBytes(JsonObject(emptyMap()))
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            journal.recordAttachment(payload)
            journal.recordStartAuthorization()
            journal.recordInterruptionAuthorization(payload)
            val path = journal.path.resolve("interrupt-authorized.json")
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            Files.writeString(path, "{}")
            assertFails { journal.recordInterruptedExecution(payload) }
            assertFalse(Files.exists(journal.path.resolve("interrupted-execution.json")))
            assertFailsWith<IllegalStateException> { journal.verify("after altered interruption authorization") }
        }
    }

    @Test
    fun `execution journal records attachment before START and chains absent execution and export assessment`() = withJournalRoot { root ->
        val intent = intent()
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            val prepared = journal.preparedBytes
            val attachment = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureAttachment" to JsonPrimitive(true))))
            journal.recordAttachment(attachment)
            assertFalse(Files.exists(journal.path.resolve("start-authorized.json")))
            journal.recordStartAuthorization()
            val execution = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureExecution" to JsonPrimitive(true))))
            val receipt = journal.recordExecution(execution)
            execution.fill(0)
            val assessment = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureAssessment" to JsonPrimitive(true))))
            val assessed = journal.recordExportAssessment(assessment)
            assessment.fill(0)
            assertContentEquals(prepared, journal.preparedBytes)
            assertContentEquals(receipt, Files.readAllBytes(journal.path.resolve("execution.json")))
            assertContentEquals(assessed, Files.readAllBytes(journal.path.resolve("export-assessment.json")))
            var previous = prepared
            for (name in listOf("attachment.json", "start-authorized.json", "execution.json", "export-assessment.json")) {
                val bytes = Files.readAllBytes(journal.path.resolve(name))
                val document = OracleJson.parseCanonical(bytes).jsonObject
                assertEquals(OracleArtifacts.sha256(previous), document.getValue("previousSha256").jsonPrimitive.content)
                assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(document - "recordSha256"))),
                    document.getValue("recordSha256").jsonPrimitive.content)
                assertEquals(JsonPrimitive(false), document["complete"])
                assertEquals(JsonPrimitive(false), document["releaseEligible"])
                assertEquals("r--------", permissions(journal.path.resolve(name)))
                previous = bytes
            }
            assertEquals(8, names(journal.path).size)
            journal.verify("after fixture-only record lifecycle")
        }
    }

    @Test
    fun `START without attachment poisons the prepared journal and preserves all residue`() = withJournalRoot { root ->
        val intent = intent()
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            assertFailsWith<IllegalStateException> { journal.recordStartAuthorization() }
            assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(journal.path))
            assertFailsWith<IllegalStateException> { journal.verify("after out-of-order START") }
        }
    }

    @Test
    fun `altered durable START cannot acquire an execution record`() = withJournalRoot { root ->
        val intent = intent()
        GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            val payload = OracleJson.canonicalBytes(JsonObject(mapOf("fixture" to JsonPrimitive(true))))
            journal.recordAttachment(payload)
            journal.recordStartAuthorization()
            val start = journal.path.resolve("start-authorized.json")
            Files.setPosixFilePermissions(start, PosixFilePermissions.fromString("rw-------"))
            Files.writeString(start, "{}")
            assertFailsWith<java.io.IOException> { journal.recordExecution(payload) }
            assertFalse(Files.exists(journal.path.resolve("execution.json")))
            assertFailsWith<IllegalStateException> { journal.verify("after altered START") }
        }
    }

    @Test
    fun `new journal retains private canonical intent and close preserves its residue`() = withJournalRoot { root ->
        val original = intent()
        val supplied = original.copyOf()
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, supplied)
        val path = journal.path
        try {
            supplied.fill(0)
            assertEquals(root.resolve(operationName()), path)
            assertEquals(setOf("intent.json"), names(path))
            assertContentEquals(original, Files.readAllBytes(path.resolve("intent.json")))
            assertEquals("rwx------", permissions(path))
            assertEquals("r--------", permissions(path.resolve("intent.json")))
            assertFailsWith<IllegalStateException> { journal.preparedBytes }
            journal.verify("retained original intent")
        } finally {
            journal.close()
        }
        journal.close()
        assertEquals(setOf("intent.json"), names(path))
        assertFailsWith<IllegalStateException> { journal.verify("after close") }
        assertFailsWith<IllegalArgumentException> {
            GccBundledOperationJournal.create(root, OPERATION_ID, original).close()
        }
        GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, original).use { it.verify("released root lock") }
    }

    @Test
    fun `prepared record links exact intent evidence v2 definition and deployment closure`() = withJournalRoot { root ->
        val intent = intent()
        val evidence = evidence(intent)
        val definition = definition()
        val originalDefinition = definition.copyOf()
        val parsed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
        val path = journal.path
        try {
            journal.recordLease(evidence)
            assertEquals(setOf("intent.json", "lease-evidence.json"), names(path))
            assertContentEquals(evidence.canonicalBytes(), Files.readAllBytes(path.resolve("lease-evidence.json")))
            journal.recordPrepared(definition, DEPLOYMENT_SHA256)
            definition.fill(0)
            val prepared = journal.preparedBytes
            val document = OracleJson.parseCanonical(prepared).jsonObject
            assertEquals(setOf(
                "provider", "schemaVersion", "operationId", "intentSha256", "diskEvidenceSha256",
                "definitionSha256", "definitionBindingSha256", "deploymentClosureSha256", "preparedSha256",
            ), document.keys)
            assertEquals("gcc-bundled-prepared-operation-v1", document.getValue("provider").jsonPrimitive.content)
            assertEquals(JsonPrimitive(1), document.getValue("schemaVersion"))
            assertEquals(OPERATION_ID, document.getValue("operationId").jsonPrimitive.content)
            assertEquals(OracleArtifacts.sha256(intent), document.getValue("intentSha256").jsonPrimitive.content)
            assertEquals(evidence.evidenceSha256, document.getValue("diskEvidenceSha256").jsonPrimitive.content)
            assertEquals(OracleArtifacts.sha256(originalDefinition), document.getValue("definitionSha256").jsonPrimitive.content)
            assertEquals(parsed.bindingSha256, document.getValue("definitionBindingSha256").jsonPrimitive.content)
            assertEquals(DEPLOYMENT_SHA256, document.getValue("deploymentClosureSha256").jsonPrimitive.content)
            assertEquals(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(document - "preparedSha256"))),
                document.getValue("preparedSha256").jsonPrimitive.content,
            )
            prepared.fill(0)
            assertContentEquals(Files.readAllBytes(path.resolve("prepared.json")), journal.preparedBytes)
            assertContentEquals(originalDefinition, Files.readAllBytes(path.resolve("definition.json")))
            assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(path))
            names(path).forEach { assertEquals("r--------", permissions(path.resolve(it))) }
            assertEquals(JsonPrimitive(false), OracleJson.parseCanonical(originalDefinition).jsonObject.getValue("startAuthorized"))
            assertEquals(JsonPrimitive(false), OracleJson.parseCanonical(originalDefinition).jsonObject.getValue("releaseEligible"))
            journal.verify("prepared immutable records")
        } finally {
            journal.close()
        }
        assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(path))
        assertFailsWith<IllegalStateException> { journal.preparedBytes }
    }

    @Test
    fun `invalid intent canonicality shape bounds and operation IDs fail before creating residue`() = withJournalRoot { root ->
        for (bytes in listOf(
            byteArrayOf(), intent() + '\n'.code.toByte(), "[]\n".encodeToByteArray(),
            "{\"a\":1,\"a\":2}".encodeToByteArray(), byteArrayOf(0xc3.toByte(), 0x28),
            ByteArray(256 * 1024 + 1),
        )) {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, bytes).close() }
            assertTrue(names(root).isEmpty())
        }
        for (operationId in listOf("", "../escape", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, operationId, intent()).close() }
            assertTrue(names(root).isEmpty())
        }
    }

    @Test
    fun `journal root must already exist and be canonical private and below a trusted parent`() = withJournalRoot { root ->
        val alias = root.parent.resolve("alias")
        Files.createSymbolicLink(alias, root)
        for (candidate in listOf(root.resolve("missing"), alias, root.resolve(".."), Path.of("."), Path.of("/"))) {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(candidate, OPERATION_ID, intent()).close() }
        }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, intent()).close() }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(root.parent, PosixFilePermissions.fromString("rwxrwx---"))
        try {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, intent()).close() }
        } finally {
            Files.setPosixFilePermissions(root.parent, PosixFilePermissions.fromString("rwx------"))
        }
        assertTrue(names(root).isEmpty())
        GccBundledOperationJournal.create(root, OPERATION_ID, intent()).use { it.verify("restored parent policy") }
    }

    @Test
    fun `root lock excludes a second operation and is released without journal deletion`() = withJournalRoot { root ->
        val first = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
        try {
            assertFailsWith<IllegalArgumentException> {
                GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
            }
            assertEquals(setOf(operationName()), names(root))
            first.verify("after competing root acquisition")
        } finally {
            first.close()
        }
        GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).use { it.verify("second independent operation") }
        assertEquals(setOf(operationName(), operationName(SECOND_OPERATION_ID)), names(root))
    }

    @Test
    fun `existing empty or staged operation directories cannot be adopted`() {
        for (withTemporary in listOf(false, true)) withJournalRoot { root ->
            val path = Files.createDirectory(root.resolve(operationName()))
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            if (withTemporary) immutableFile(path.resolve(DescriptorBoundAtomicStateFile.temporaryName("intent.json")), intent())
            val before = names(path)
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, intent()).close() }
            assertEquals(before, names(path))
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        }
    }

    @Test
    fun `cross paired lease operation or intent digest poisons owner without publishing evidence`() {
        for (wrongOperation in listOf(false, true)) withJournalRoot { root ->
            val intent = intent()
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
            try {
                val evidence = evidence(
                    intent,
                    operationId = if (wrongOperation) SECOND_OPERATION_ID else OPERATION_ID,
                    requestSha256 = if (wrongOperation) OracleArtifacts.sha256(intent) else DEPLOYMENT_SHA256,
                )
                assertFailsWith<IllegalArgumentException> { journal.recordLease(evidence) }
                assertEquals(setOf("intent.json"), names(journal.path))
                assertFailsWith<IllegalStateException> { journal.verify("after rejected evidence") }
            } finally {
                journal.close()
            }
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent).close()
        }
    }

    @Test
    fun `lease and prepared publication are strictly sequential single use transitions`() {
        for (mode in listOf("prepare-first", "repeat-lease", "repeat-prepared")) withJournalRoot { root ->
            val intent = intent()
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
            try {
                when (mode) {
                    "prepare-first" -> assertFailsWith<IllegalStateException> { journal.recordPrepared(definition(), DEPLOYMENT_SHA256) }
                    "repeat-lease" -> {
                        journal.recordLease(evidence(intent))
                        assertFailsWith<IllegalStateException> { journal.recordLease(evidence(intent)) }
                    }
                    "repeat-prepared" -> {
                        journal.recordLease(evidence(intent))
                        journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
                        assertFailsWith<IllegalStateException> { journal.recordPrepared(definition(), DEPLOYMENT_SHA256) }
                    }
                }
                assertFailsWith<IllegalStateException> { journal.verify("after illegal stage transition") }
                assertFalse(names(journal.path).any { it.endsWith(".atomic") })
            } finally {
                journal.close()
            }
        }
    }

    @Test
    fun `prepared publication rejects legacy malformed noncanonical and oversized definitions`() {
        for (bytes in listOf(definition(legacy = true), definition() + '\n'.code.toByte(), intent(), ByteArray(1024 * 1024 + 1))) {
            withJournalRoot { root ->
                val intent = intent()
                GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                    journal.recordLease(evidence(intent))
                    assertFailsWith<IllegalArgumentException> { journal.recordPrepared(bytes, DEPLOYMENT_SHA256) }
                    assertEquals(setOf("intent.json", "lease-evidence.json"), names(journal.path))
                    assertFailsWith<IllegalStateException> { journal.preparedBytes }
                }
            }
        }
    }

    @Test
    fun `prepared publication rejects invalid deployment closure digests before writing definition`() {
        for (digest in listOf("", "a".repeat(63), "A".repeat(64), "g".repeat(64), "a".repeat(65))) withJournalRoot { root ->
            val intent = intent()
            GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                journal.recordLease(evidence(intent))
                assertFailsWith<IllegalArgumentException> { journal.recordPrepared(definition(), digest) }
                assertEquals(setOf("intent.json", "lease-evidence.json"), names(journal.path))
            }
        }
    }

    @Test
    fun `journal may not overlap the definition writable output`() {
        for (nestedOutput in listOf(false, true)) withJournalRoot { root ->
            val intent = intent()
            GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                journal.recordLease(evidence(intent))
                val output = if (nestedOutput) journal.path.resolve("output") else root
                assertFailsWith<IllegalArgumentException> { journal.recordPrepared(definition(output), DEPLOYMENT_SHA256) }
                assertEquals(setOf("intent.json", "lease-evidence.json"), names(journal.path))
            }
        }
    }

    @Test
    fun `same bytes on a replacement inode are rejected while closing still releases locks`() = withJournalRoot { root ->
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
        val original = journal.path.resolve("intent.json")
        Files.move(original, root.parent.resolve("original-intent.json"))
        immutableFile(original, intent())
        assertFailsWith<IllegalArgumentException> { journal.verify("same-byte inode substitution") }
        journal.close()
        journal.close()
        GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        assertContentEquals(intent(), Files.readAllBytes(original))
    }

    @Test
    fun `changed bytes permissions links and extra temporary residue fail closed`() {
        for (mutation in listOf("bytes", "mode", "hardlink", "symlink", "temporary", "extra")) withJournalRoot { root ->
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
            val target = journal.path.resolve("intent.json")
            try {
                when (mutation) {
                    "bytes" -> {
                        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                        Files.write(target, intent("changed"))
                        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                    }
                    "mode" -> Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                    "hardlink" -> Files.createLink(root.parent.resolve("extra-link"), target)
                    "symlink" -> {
                        val moved = Files.move(target, root.parent.resolve("moved-intent.json"))
                        Files.createSymbolicLink(target, moved)
                    }
                    "temporary" -> immutableFile(journal.path.resolve(DescriptorBoundAtomicStateFile.temporaryName("lease-evidence.json")), intent())
                    "extra" -> immutableFile(journal.path.resolve("unknown.json"), intent())
                }
                val before = names(journal.path)
                assertFailsWith<Exception> { journal.verify("mutation $mutation") }
                assertFailsWith<IllegalStateException> { journal.verify("poison remains") }
                assertEquals(before, names(journal.path))
            } finally {
                journal.close()
            }
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        }
    }

    @Test
    fun `root and operation directory replacement are rejected without cleanup of old or new trees`() {
        for (replaceRoot in listOf(false, true)) withJournalRoot { root ->
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
            val selected = if (replaceRoot) root else journal.path
            val moved = selected.resolveSibling("retained-original")
            Files.move(selected, moved)
            Files.createDirectory(selected)
            Files.setPosixFilePermissions(selected, PosixFilePermissions.fromString("rwx------"))
            try {
                assertFailsWith<Exception> { journal.verify("directory replacement") }
            } finally {
                journal.close()
            }
            assertTrue(Files.isDirectory(moved))
            assertTrue(Files.isDirectory(selected))
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        }
    }

    @Test
    fun `prepared file substitution is detected and cannot be repaired into a reusable owner`() = withJournalRoot { root ->
        val intent = intent()
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
        try {
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            val preparedPath = journal.path.resolve("prepared.json")
            val original = Files.readAllBytes(preparedPath)
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("rw-------"))
            Files.write(preparedPath, intent)
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<IllegalArgumentException> { journal.verify("changed prepared record") }
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("rw-------"))
            Files.write(preparedPath, original)
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<IllegalStateException> { journal.preparedBytes }
            assertFailsWith<IllegalStateException> { journal.verify("restored bytes do not unpoison") }
        } finally {
            journal.close()
        }
        assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(journal.path))
    }

    @Test
    fun `planner journal extends fresh and resumed evidence with an immutable ordered chain`() {
        for (resumed in listOf(false, true)) withPlannerReadyJournal(resumed) { journal, request ->
            val old = names(journal.path).associateWith { Files.readAllBytes(journal.path.resolve(it)) }
            val requestBytes = request.canonicalBytes
            journal.recordPlannerPrepared(requestBytes)
            requestBytes.fill(0)
            journal.recordPlannerAttachment(intent("planner attachment"))
            journal.recordPlannerStartAuthorization()
            journal.recordPlannerExecution(intent("planner execution"))
            journal.recordPlannerAssessment(plannerAssessment(request))
            old.forEach { (name, bytes) -> assertContentEquals(bytes, Files.readAllBytes(journal.path.resolve(name))) }
            assertContentEquals(request.canonicalBytes, Files.readAllBytes(journal.path.resolve("planner-request.json")))
            var previous = old.getValue(if (resumed) "resume-export-assessment.json" else "export-assessment.json")
            for (name in listOf("planner-prepared.json", "planner-attachment.json", "planner-start-authorized.json",
                "planner-execution.json", "planner-assessment.json")) {
                val bytes = Files.readAllBytes(journal.path.resolve(name))
                val record = OracleJson.parseCanonical(bytes).jsonObject
                assertEquals(OracleArtifacts.sha256(previous), record.getValue("previousSha256").jsonPrimitive.content)
                assertEquals(JsonPrimitive(false), record["complete"])
                assertEquals(JsonPrimitive(false), record["releaseEligible"])
                assertEquals("r--------", permissions(journal.path.resolve(name)))
                previous = bytes
            }
            assertEquals(if (resumed) 23 else 14, names(journal.path).size)
            val allRecords = names(journal.path).associateWith { Files.readAllBytes(journal.path.resolve(it)) }
            val hashes = allRecords.values.map(OracleArtifacts::sha256).toSet()
            val rawFiles = setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json",
                "analysis-state-manifest.json", "resume-definition.json", "planner-request.json")
            allRecords.filterKeys { it !in rawFiles }.forEach { (name, bytes) ->
                val previousHash = OracleJson.parseCanonical(bytes).jsonObject.getValue("previousSha256").jsonPrimitive.content
                assertTrue(previousHash in hashes)
                requireGccCliLinkedRecord(bytes, name, OPERATION_ID, request.operationRequestSha256, previousHash)
            }
            journal.verify("planner lifecycle")
            assertFails { journal.recordPlannerPrepared(request.canonicalBytes) }
        }
    }

    @Test
    fun `planner preparation rejects request policy path and model substitutions before publication`() {
        val mutations = mapOf(
            "operationRequestSha256" to JsonPrimitive("f".repeat(64)),
            "profilePolicySha256" to JsonPrimitive("f".repeat(64)),
            "modelSha256" to JsonPrimitive("f".repeat(64)),
            "inputSha256" to JsonPrimitive("f".repeat(64)),
            "modelBytes" to JsonPrimitive(129), "functionCount" to JsonPrimitive(3),
            "maximumFunctionsPerModule" to JsonPrimitive(25), "maximumWorkUnits" to JsonPrimitive(10001),
            "maximumPlanBytes" to JsonPrimitive(8193),
            "modelPath" to JsonPrimitive("/other/model.json"), "outputDirectory" to JsonPrimitive("/other/reports"),
        )
        for ((field, value) in mutations) withPlannerReadyJournal(false) { journal, request ->
            val altered = OracleJson.canonicalBytes(JsonObject(OracleJson.parseCanonical(request.canonicalBytes).jsonObject + (field to value)))
            assertFails { journal.recordPlannerPrepared(altered) }
            assertFalse(Files.exists(journal.path.resolve("planner-request.json")))
            assertFails { journal.verify("poisoned planner request") }
        }
    }

    @Test
    fun `planner journal denies missing predecessors changed request identity and wrong output lineage`() {
        val outOfOrder: List<(GccBundledOperationJournal, GccBundledPlannerRequest) -> Unit> = listOf(
            { journal, _ -> journal.recordPlannerStartAuthorization() },
            { journal, _ -> journal.recordPlannerExecution(intent("early execution")) },
            { journal, request -> journal.recordPlannerAssessment(plannerAssessment(request)) },
        )
        for (attempt in outOfOrder) withPlannerReadyJournal(false) { journal, request ->
            journal.recordPlannerPrepared(request.canonicalBytes)
            assertFails { attempt(journal, request) }
            assertEquals(10, names(journal.path).size)
        }
        withPlannerReadyJournal(false) { journal, request ->
            journal.recordPlannerPrepared(request.canonicalBytes)
            val path = journal.path.resolve("planner-request.json")
            Files.move(path, journal.path.parent.resolve("original-planner-request"))
            immutableFile(path, request.canonicalBytes)
            assertFails { journal.recordPlannerAttachment(intent("changed request")) }
        }
        for ((field, value) in mapOf("requestSha256" to JsonPrimitive("f".repeat(64)), "planBytes" to JsonPrimitive(8193),
            "operationRequestSha256" to JsonPrimitive("f".repeat(64)), "profilePolicySha256" to JsonPrimitive("f".repeat(64)),
            "functionCount" to JsonPrimitive(3), "planSha256" to JsonPrimitive(java.math.BigInteger("1".repeat(64))))) {
            withPlannerReadyJournal(false) { journal, request ->
                journal.recordPlannerPrepared(request.canonicalBytes)
                journal.recordPlannerAttachment(intent("attachment"))
                journal.recordPlannerStartAuthorization()
                journal.recordPlannerExecution(intent("execution"))
                val altered = JsonObject(OracleJson.parseCanonical(plannerAssessment(request)).jsonObject + (field to value))
                assertFails { journal.recordPlannerAssessment(OracleJson.canonicalBytes(altered)) }
                assertFalse(Files.exists(journal.path.resolve("planner-assessment.json")))
            }
        }
    }

    private fun plannerAssessment(request: GccBundledPlannerRequest) = OracleJson.canonicalBytes(JsonObject(mapOf(
        "fixtureOnly" to JsonPrimitive(true), "requestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
        "modelSha256" to JsonPrimitive(request.modelSha256), "planSha256" to JsonPrimitive(DEPLOYMENT_SHA256),
        "planBytes" to JsonPrimitive(32), "operationRequestSha256" to JsonPrimitive(request.operationRequestSha256),
        "profilePolicySha256" to JsonPrimitive(request.profilePolicySha256), "functionCount" to JsonPrimitive(request.functionCount),
    )))

    private fun withPlannerReadyJournal(resumed: Boolean, action: (GccBundledOperationJournal, GccBundledPlannerRequest) -> Unit) {
        val layout = GeneratedCMakeReconstructionProfile.descriptor.layout
        val policy = JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true), "reconstructionProfile" to JsonObject(mapOf(
            "layout" to OracleJson.parse(layout.canonicalJson().toByteArray()), "budgets" to JsonObject(mapOf(
                "maximumFunctionsPerModule" to JsonPrimitive(24), "plannerMaximumEntities" to JsonPrimitive(100),
                "plannerMaximumDependencyEdges" to JsonPrimitive(1000), "plannerMaximumWorkUnits" to JsonPrimitive(10000),
            )),
        ))))
        val intent = OracleJson.canonicalBytes(JsonObject(mapOf("schemaVersion" to JsonPrimitive(2),
            "provider" to JsonPrimitive("gcc-bundled-operation-intent-v2"), "plannerProfile" to policy)))
        val payload = intent("fixture execution")
        val assessment = OracleJson.canonicalBytes(JsonObject(mapOf("programModelSha256" to JsonPrimitive(DEPLOYMENT_SHA256),
            "programModelBytes" to JsonPrimitive(128), "functionCount" to JsonPrimitive(2))))
        fun ready(journal: GccBundledOperationJournal) {
            val export = if (resumed) journal.recordResumeExportAssessment(assessment) else journal.recordExportAssessment(assessment)
            val operationSha = OracleArtifacts.sha256(intent)
            val output = Path.of("/record-only-test/run")
            val request = GccBundledPlannerRequest(output.resolve("reports/program_model.json"),
                output.resolve(gccBundledPlannerControlName(operationSha, OracleArtifacts.sha256(export))).resolve("reports"),
                128, DEPLOYMENT_SHA256, DEPLOYMENT_SHA256, 2, operationSha, OracleArtifacts.sha256(OracleJson.canonicalBytes(policy)),
                layout, 24, 100, 1000, 10000, 8192)
            action(journal, request)
        }
        if (resumed) withStoppedJournal(intent) { journal, definition ->
            journal.recordResumePrepared(definition)
            journal.recordResumeAttachment(payload)
            journal.recordResumeStartAuthorization()
            journal.recordResumeExecution(payload)
            ready(journal)
        } else withJournalRoot { root ->
            GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                journal.recordLease(evidence(intent))
                journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
                journal.recordAttachment(payload)
                journal.recordStartAuthorization()
                journal.recordExecution(payload)
                ready(journal)
            }
        }
    }

    private fun intent(value: String = "record-only-test"): ByteArray = OracleJson.canonicalBytes(
        JsonObject(mapOf("testIntent" to JsonPrimitive(value))),
    )

    private fun evidence(
        intent: ByteArray,
        operationId: String = OPERATION_ID,
        requestSha256: String = OracleArtifacts.sha256(intent),
    ): FullTreeDiskScratchEvidence = FullTreeDiskScratchEvidence.create(
        operation = FullTreeDiskScratchOperation(operationId, requestSha256, "cc1-fresh-control", "b".repeat(64)),
        policy = FullTreeDiskScratchPolicy(1024, 8192, 128, 256),
        mountPathSha256 = "c".repeat(64),
        mount = FullTreeDiskMount(
            42, 36, "7:1", Path.of("/"), Path.of("/record-only-test/scratch"),
            listOf("noatime", "nodev", "noexec", "nosuid", "rw"), "ext4",
        ),
        mountIdentity = diskIdentity(2),
        capacity = LinuxFilesystemCapacity(4096, 8192, 4096, 256, 200, 255, false),
        leaseIdentity = diskIdentity(12),
        leaseRecordSha256 = "d".repeat(64),
    )

    private fun diskIdentity(inode: Long): LinuxFileIdentity = LinuxFileIdentity(
        LinuxFileKey(7, inode), 0x41c0, 1000, 1000, 2, 42,
        isRegularFile = false, isDirectory = true, isSymbolicLink = false,
    )

    private fun definition(output: Path = Path.of("/record-only-test/run"), legacy: Boolean = false, runKind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.FRESH_CONTROL): ByteArray {
        val bundle = Path.of("/record-only-test/bundle")
        val runtime = GccBundledGhidraRuntime(bundle, listOf(
            GccBundledGhidraClassPathEntry(bundle.resolve("decomp-ghidra-bridge.jar"), 32, DEPLOYMENT_SHA256),
            GccBundledGhidraClassPathEntry(
                bundle.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Framework/Core/lib/Core.jar"),
                64, DEPLOYMENT_SHA256,
            ),
        ))
        val roles = if (legacy) GCC_LEGACY_CONTAINMENT_ARTIFACT_ROLES else GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES
        val artifacts = roles.map { role ->
            GccCompilerEngineContainmentArtifactIdentity(
                role,
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> bundle.resolve("decomp-ghidra-bridge.jar")
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> bundle.resolve("bundle.sha256")
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> bundle.resolve("scripts/RunBundledExports.class")
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/record-only-test/ExportProgramModel.java")
                    else -> Path.of("/record-only-test/${role.wireName}")
                },
                32,
                if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE) BundledGhidra.ARCHIVE_SHA256 else DEPLOYMENT_SHA256,
            )
        }
        val state = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, output.resolve("state"), null, 0, 0,
        )
        val lease = GccCompilerEngineOutputLeaseIdentity(output, 7, 99, 42, 1000, 1000, 0x1c0, 1024, 8192, 128, 256)
        val byRole = artifacts.associateBy { it.role }
        val command = if (legacy) listOf(
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS).path.toString(),
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE).path.toString(),
            state.path.toString(), lease.path.toString(),
        ) else runtime.command(artifacts, state, lease, runKind)
        return GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
            engineId = "cc1",
            runKind = runKind,
            artifacts = artifacts,
            analysisState = state,
            command = command,
            environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
            outputLease = lease,
            budgets = GccCompilerEngineContainmentBudgets(60_000, 1024L * 1024 * 1024, 64),
            bundledRuntime = if (legacy) null else runtime,
        )).canonicalBytes
    }

    private fun immutableFile(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private fun names(path: Path): Set<String> = Files.list(path).use { entries ->
        entries.map { it.fileName.toString() }.toList().toSet()
    }

    private fun permissions(path: Path): String = PosixFilePermissions.toString(Files.getPosixFilePermissions(path))

    private fun operationName(operationId: String = OPERATION_ID): String = ".gcc-bundled-operation-$operationId"

    private inline fun withJournalRoot(action: (Path) -> Unit) {
        val container = createTempDirectory("gcc-bundled-journal-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(container, PosixFilePermissions.fromString("rwx------"))
        val root = Files.createDirectory(container.resolve("root"))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            if (Files.exists(container, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(container).use { entries -> entries.sorted(Comparator.reverseOrder()).toList() }
                    .forEach(Files::deleteIfExists)
            }
        }
    }

    private companion object {
        val OPERATION_ID = "1".repeat(64)
        val SECOND_OPERATION_ID = "2".repeat(64)
        const val KEEPER_PID = 42L
        const val EXECUTION_ELAPSED_NANOS = 5_000_000_000L
        const val STOPPED_ELAPSED_NANOS = 8_000_000_000L
        const val STOPPED_REMAINING_NANOS = 52_000_000_000L
        const val RECOVERY_CAP_MILLIS = 52_000L
        val RESUME_NAMES = setOf("resume-definition.json", "resume-prepared.json", "resume-attachment.json",
            "resume-start-authorized.json", "resume-execution.json", "resume-export-assessment.json")
        val DEPLOYMENT_SHA256 = "a".repeat(64)
    }
}
