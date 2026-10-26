package decompengine.web

import decompengine.jobs.*
import decompengine.project.*
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.CancellationException
import kotlin.io.path.createTempDirectory
import kotlin.test.*
import kotlinx.serialization.json.*

/** Actual production adapter and pinned store reads over tiny synthetic inputs; no workflow executes. */
class WebArtifactInventoryBudgetTest {
    @Test fun `production inventory accounts for input and repeated metadata reads including failure and cancellation`() {
        val parent = Files.createDirectories(Path.of("build/test-tmp/web-artifact-inventory").toAbsolutePath())
        val root = createTempDirectory(parent, "budget-")
        try {
            val store = JobStore(root)
            val input = elfFixture()
            val job = store.createFromUpload("inert.elf", input)
            val profile = GeneratedCMakeReconstructionProfile.descriptor
            val path = "Makefile"
            val sha = "a".repeat(64)
            val sourceSha = revisionSourceDigest("${path.length}:$path:0:$sha\n")
            val run = WorkflowAttemptStore.open(root).use { owner ->
                val snapshot = (owner.inspect(job.id) as WorkflowJobInspection.Available).snapshot
                val queued = owner.create(job.id, snapshot.version, NewWorkflowAttempt(WorkflowKind.RECONSTRUCT,
                    WorkflowExecutionLimits(60000u, 15000u, 1048576u, 16u))).attempt
                val started = owner.transition(job.id, queued.runId, queued.version, WorkflowTransition.Start).attempt
                owner.transition(job.id, started.runId, started.version, WorkflowTransition.Finish(
                    WorkflowRunState.COMPLETED, WorkflowTerminalReason.COMPLETED, WorkflowCandidate("revision_1", sourceSha))).attempt
            }
            val declaration = profile.layout.declarationForPath(path)
            val manifest = SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256,
                inputSha256 = WebExplorationArtifact.sha256(input), files = listOf(GeneratedFileEvidence(
                    path, sha, "fixture", roles = declaration.roles, contentKind = declaration.contentKind)),
                unresolvedEntityIds = emptyList()).toJson().toByteArray()
            val contract = buildJsonObject {
                put("schemaVersion", 3); put("sourceRevisionSha256", sourceSha)
                put("sourceInputs", buildJsonArray { add(buildJsonObject {
                    put("path", path); put("bytes", 0); put("sha256", sha)
                }) })
            }.toString().toByteArray()
            val reports = Files.createDirectories(root.resolve(job.id).resolve("reports/runs/${run.runId}/source-tree/reports"))
            val manifestPath = reports.parent.resolve("source_tree_manifest.json")
            Files.write(manifestPath, manifest)
            Files.write(reports.resolve("build_contract.json"), contract)
            WebJobService(store, JobAnalyzer { _, _ -> error("unexpected analysis") },
                JobReconstructor { _, _ -> error("unexpected reconstruction") }, sourceProfiles = listOf(profile)).use { service ->
                service.initializeExistingStorage()
                val adapter = WebJobArtifactStore(service)
                val completeBytes = 2L * (input.size + manifest.size + contract.size)
                val budget = WebArtifactReadBudget(completeBytes) {
                    assertFalse(Thread.holdsLock(service), "inventory IO/cancellation must not hold the service monitor")
                }
                assertEquals(WebExplorationArtifact.sha256(manifest) to WebExplorationArtifact.sha256(contract),
                    adapter.revisionCommitments(job.id, run.runId, "revision_1", budget))
                assertEquals(completeBytes, budget.reservedBytes)

                // A denied second input capture cannot exceed the budget or claim an inventory check.
                val short = WebArtifactReadBudget(completeBytes - 1) {}
                assertNull(adapter.revisionCommitments(job.id, run.runId, "revision_1", short))
                assertEquals(completeBytes - input.size, short.reservedBytes)

                lateinit var cancelled: WebArtifactReadBudget
                cancelled = WebArtifactReadBudget(completeBytes) {
                    if (cancelled.reservedBytes > 0) throw CancellationException("closed after input admission")
                }
                assertFailsWith<CancellationException> {
                    adapter.revisionCommitments(job.id, run.runId, "revision_1", cancelled)
                }
                assertEquals(input.size.toLong(), cancelled.reservedBytes)

                Files.delete(manifestPath)
                val failed = WebArtifactReadBudget(completeBytes) {}
                assertNull(adapter.revisionCommitments(job.id, run.runId, "revision_1", failed))
                assertEquals(input.size.toLong(), failed.reservedBytes) // Missing manifest still charged the input read.
                assertNull(adapter.revisionCommitments(job.id, run.runId, "revision_1", WebArtifactReadBudget(1) {}))
            }
        } finally { root.toFile().deleteRecursively() }
    }
}
