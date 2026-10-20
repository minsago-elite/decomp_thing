package decompengine.web

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ModulePlan
import decompengine.project.PlannedModule
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.SourceTreeManifest
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.StableRegularFile
import kotlinx.serialization.json.*
import kotlin.test.*

/** DTOs and strings only: no store, checkpoint, source body, listener, process or browser. */
class WebRecordedModuleProvenanceTest {
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val privateText = "UNREGISTERED-PROVENANCE-SECRET /private/checkpoint/path"
    private val moduleId = "module_1"
    private val inputBytes = byteArrayOf(1, 2, 3)
    private val inputSha = WebExplorationArtifact.sha256(inputBytes)
    private val implementationSha = "b".repeat(64)
    private data class Captured(val manifest: SourceTreeManifest, val selected: WebRevisionSourceFile,
        val plan: ByteArray, val generation: ByteArray)

    private fun captured(change: (JsonObject) -> JsonObject = { it }, planChange: (ModulePlan) -> ModulePlan = { it },
        accepted: Boolean = true, counts: Boolean = true): Captured {
        val sourcePath = profile.layout.declaration("module-implementation").materialize(mapOf("module" to moduleId))
        val headerPath = profile.layout.declaration("module-interface").materialize(mapOf("module" to moduleId))
        val selected = WebRevisionSourceFile(GeneratedFileEvidence(sourcePath, implementationSha, privateText,
            acceptedImplementation = accepted, roles = profile.layout.declaration("module-implementation").roles,
            contentKind = ProjectContentKind.UTF8_TEXT), 12)
        val plan = planChange(ModulePlan(modules = listOf(PlannedModule(moduleId, sourcePath, headerPath,
            emptyList(), emptyList(), emptyList(), listOf(privateText))))).toJson().toByteArray(Charsets.UTF_8)
        val generation = change(buildJsonObject {
            put("schemaVersion", 2); put("raw", privateText)
            put("modules", buildJsonArray { add(buildJsonObject {
                put("id", moduleId)
                put("revisionEvidence", buildJsonObject {
                    put("sourcePath", sourcePath); put("sourceSha256", implementationSha)
                    put("inputBinarySha256", inputSha); put("acceptedImplementation", accepted)
                    put("checkpointPath", privateText); put("compilation", buildJsonObject { put("log", privateText) })
                })
            }) })
            put("sourceGenerationBudgetEvidence", buildJsonObject {
                put("schemaVersion", 1)
                put("selectedProfile", buildJsonObject { put("id", profile.id); put("sha256", profile.sha256); put("raw", privateText) })
                put("modules", buildJsonArray { add(buildJsonObject {
                    put("moduleId", moduleId); put("sourceBytes", 12); put("outcome", if (accepted) "accepted" else "unresolved")
                    put("promptCharacters", if (counts) JsonPrimitive(7) else JsonNull)
                    put("promptBudgetCharacters", if (counts) JsonPrimitive(10) else JsonNull)
                }) })
            })
        }).toString().toByteArray(Charsets.UTF_8)
        fun evidence(id: String, bytes: ByteArray) = GeneratedFileEvidence(profile.layout.declaration(id).materialize(),
            WebExplorationArtifact.sha256(bytes), "fixture", roles = profile.layout.declaration(id).roles, contentKind = ProjectContentKind.UTF8_TEXT)
        val build = GeneratedFileEvidence(profile.layout.declaration("build-definition").materialize(), "f".repeat(64), "fixture",
            roles = profile.layout.declaration("build-definition").roles, contentKind = ProjectContentKind.UTF8_TEXT)
        val manifest = SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = inputSha,
            files = listOf(build, selected.evidence, evidence("module-plan-evidence", plan), evidence("confidence-evidence", generation)),
            unresolvedEntityIds = emptyList())
        return Captured(manifest, selected, plan, generation)
    }

    private fun project(value: Captured): JsonObject? = WebRecordedModuleProvenance.project(
        profile, value.manifest, value.selected, value.plan, value.generation)
    private fun changeBudget(root: JsonObject, change: (JsonObject) -> JsonObject): JsonObject {
        val generation = root.getValue("sourceGenerationBudgetEvidence").jsonObject
        return JsonObject(root + ("sourceGenerationBudgetEvidence" to JsonObject(generation +
            ("modules" to JsonArray(listOf(change(generation.getValue("modules").jsonArray.single().jsonObject)))))))
    }

    @Test fun `joined generation scalars exclude raw labels prompts checkpoint paths and compiler text`() {
        val value = captured(); val record = assertNotNull(project(value))
        assertEquals(setOf("authority", "moduleId", "implementationSha256", "planSha256", "generationEvidenceSha256",
            "promptCharacters", "promptBudgetCharacters"), record.keys)
        assertEquals("reported-generation", record.getValue("authority").jsonPrimitive.content)
        assertEquals(moduleId, record.getValue("moduleId").jsonPrimitive.content)
        assertEquals(implementationSha, record.getValue("implementationSha256").jsonPrimitive.content)
        assertEquals("7", record.getValue("promptCharacters").jsonPrimitive.content)
        assertTrue(record.getValue("promptCharacters").jsonPrimitive.isString)
        assertEquals("10", record.getValue("promptBudgetCharacters").jsonPrimitive.content)
        assertEquals(WebExplorationArtifact.sha256(value.plan), record.getValue("planSha256").jsonPrimitive.content)
        assertFalse(record.toString().contains(privateText))
    }

    @Test fun `unreported prompt use remains null for accepted and unresolved module declarations`() {
        for (accepted in listOf(true, false)) {
            val record = assertNotNull(project(captured(accepted = accepted, counts = false)))
            assertEquals(JsonNull, record["promptCharacters"])
            assertEquals(JsonNull, record["promptBudgetCharacters"])
            assertFalse(record.containsKey("acceptance")); assertFalse(record.containsKey("harness"))
        }
    }

    @Test fun `manifest digest and explicit module source binding refuse stale or ambiguous joins`() {
        val value = captured()
        assertNull(project(value.copy(plan = value.plan + byteArrayOf(32))))
        assertNull(project(value.copy(generation = value.generation + byteArrayOf(32))))
        assertNull(project(captured(planChange = { it.copy(modules = it.modules + it.modules.single()) })))
        assertNull(project(captured(planChange = { it.copy(modules = listOf(it.modules.single().copy(sourcePath = "other.cpp"))) })))
        for ((key, wrong) in listOf("sourceSha256" to "c".repeat(64), "sourcePath" to "other.cpp", "inputBinarySha256" to "c".repeat(64))) {
            assertNull(project(captured(change = { root ->
                val row = root.getValue("modules").jsonArray.single().jsonObject
                val revision = row.getValue("revisionEvidence").jsonObject
                JsonObject(root + ("modules" to JsonArray(listOf(JsonObject(row +
                    ("revisionEvidence" to JsonObject(revision + (key to JsonPrimitive(wrong)))))))))
            })))
        }
    }

    @Test fun `counts require exact nonnegative integers complete pairing and admitted profile bounds`() {
        val invalid = listOf(JsonPrimitive(-1), JsonPrimitive("7"), JsonPrimitive(1.5), JsonPrimitive(Long.MAX_VALUE))
        for (count in invalid) assertNull(project(captured(change = { root -> changeBudget(root) {
            JsonObject(it + ("promptCharacters" to count))
        } })))
        for (maximum in listOf(JsonNull, JsonPrimitive(0), JsonPrimitive(6),
            JsonPrimitive(profile.budgets.reconstructionMaximumContextCharacters.toLong() + 1))) {
            assertNull(project(captured(change = { root -> changeBudget(root) {
                JsonObject(it + ("promptBudgetCharacters" to maximum))
            } })))
        }
        for ((key, wrong) in listOf("sourceBytes" to JsonPrimitive(13), "outcome" to JsonPrimitive("accepted-other"))) {
            assertNull(project(captured(change = { root -> changeBudget(root) { JsonObject(it + (key to wrong)) } })))
        }
    }

    @Test fun `profile and generation row identity are checked independently of valid JSON and file hashes`() {
        assertNull(project(captured(change = { root ->
            val generation = root.getValue("sourceGenerationBudgetEvidence").jsonObject
            JsonObject(root + ("sourceGenerationBudgetEvidence" to JsonObject(generation +
                ("selectedProfile" to buildJsonObject { put("id", profile.id); put("sha256", "c".repeat(64)) }))))
        })))
        assertNull(project(captured(change = { root ->
            val rows = root.getValue("modules").jsonArray
            JsonObject(root + ("modules" to JsonArray(rows + rows.single())))
        })))
        assertNull(project(captured(change = { root -> changeBudget(root) { JsonObject(it + ("moduleId" to JsonPrimitive("other"))) } })))
        assertNull(project(captured(change = { root ->
            val row = root.getValue("modules").jsonArray.single().jsonObject
            JsonObject(root + ("modules" to JsonArray(listOf(JsonObject(row + ("revisionEvidence" to
                JsonObject(row.getValue("revisionEvidence").jsonObject + ("acceptedImplementation" to JsonPrimitive(false)))))))))
        })))
    }

    @Test fun `selected metadata carries the projection without another read or changing file identity`() {
        val value = captured(); val record = assertNotNull(project(value))
        val reference = WebRevisionSourceReference("a".repeat(32), "run_1", "revision_1", "c".repeat(64), "version_1")
        val snapshot = WebRevisionSourceSnapshot(reference, "d".repeat(64), "e".repeat(64), listOf(value.selected))
        val id = revisionSourceFileId(reference, 0, value.selected.evidence.path); var reads = 0
        val response = WebRevisionFileMetadata { job, run, revision, file ->
            assertEquals(reference.jobId, job); assertEquals(reference.runId, run)
            assertEquals(reference.revisionId, revision); assertEquals(id, file); reads++
            WebRevisionFileMetadataSnapshot(snapshot, record)
        }.read(reference.jobId, reference.runId, reference.revisionId, id)
        assertEquals(1, reads); assertEquals(record, response["recordedModule"])
        assertEquals("not-performed", response.getValue("contentVerification").jsonPrimitive.content)
        assertEquals(implementationSha, response.getValue("item").jsonObject.getValue("sha256").jsonPrimitive.content)
        assertFalse(response.toString().contains(privateText))
    }

    private data class CaptureControl(val source: WebSourceCatalogEvidence, val reference: WebRevisionSourceReference,
        val fileId: String, val reads: MutableMap<String, Int>)

    /** Existing capture machinery with memory-only callbacks; no filesystem or native identity sampling. */
    private fun captureControl(change: (String, Int, StableRegularFile) -> StableRegularFile = { _, _, value -> value }): CaptureControl {
        val value = captured(); val job = "a".repeat(32); val run = "run_1"
        val inputs = value.manifest.files.filter { ProjectFileRole.BUILD_INPUT in it.roles }
        fun size(file: GeneratedFileEvidence): Long = if (file === value.selected.evidence) 12 else 0
        val canonical = inputs.joinToString("") { "${it.path.length}:${it.path}:${size(it)}:${it.sha256}\n" }
        val reference = WebRevisionSourceReference(job, run, "revision_1", revisionSourceDigest(canonical), "version_1")
        val descriptor = buildJsonObject {
            put("schemaVersion", 3); put("sourceRevisionSha256", reference.sourceSha256)
            put("sourceInputs", buildJsonArray { inputs.forEach { file -> add(buildJsonObject {
                put("path", file.path); put("bytes", size(file)); put("sha256", file.sha256)
            }) } })
        }.toString().toByteArray(Charsets.UTF_8)
        fun stable(bytes: ByteArray, inode: Long) = StableRegularFile(bytes, WebExplorationArtifact.sha256(bytes),
            LinuxFileIdentity(LinuxFileKey(1, inode), 0x8180, 1000, 1000, 1, 1, true, false, false))
        val prefix = "reports/runs/$run/source-tree/"
        val records = mapOf(
            prefix + "source_tree_manifest.json" to stable(value.manifest.toJson().toByteArray(Charsets.UTF_8), 1),
            prefix + "reports/build_contract.json" to stable(descriptor, 2),
            prefix + profile.layout.declaration("module-plan-evidence").materialize() to stable(value.plan, 3),
            prefix + profile.layout.declaration("confidence-evidence").materialize() to stable(value.generation, 4),
        )
        val reads = mutableMapOf<String, Int>()
        val source = WebSourceCatalogEvidence(listOf(profile), { selectedJob ->
            assertEquals(job, selectedJob); reads["input"] = (reads["input"] ?: 0) + 1
            stable(inputBytes, 5)
        }, { selectedJob, path, maximum ->
            assertEquals(job, selectedJob)
            val count = (reads[path] ?: 0) + 1; reads[path] = count
            val record = records[path] ?: error("Unselected artifact read")
            assertEquals(WebRecordedModuleProvenance.MAXIMUM_BYTES.toLong(), maximum)
            change(path, count, record)
        })
        val index = inputs.indexOfFirst { it === value.selected.evidence }
        return CaptureControl(source, reference, revisionSourceFileId(reference, index, value.selected.evidence.path), reads)
    }

    @Test fun `memory-only capture rechecks both declared evidence files without checkpoint or source reads`() {
        val control = captureControl()
        val result = control.source.readFileMetadata(control.reference, control.fileId)
        assertNotNull(result.recordedModule)
        assertEquals(5, control.reads.size)
        assertTrue(control.reads.values.all { it == 2 })
        assertTrue(control.reads.keys.none { it.contains("modules/") || it.contains("agent-executions/") })
        assertEquals(control.reference, result.source.reference)
    }

    @Test fun `memory-only evidence identity or bytes replacement withholds the entire captured projection`() {
        for (replaceBytes in listOf(false, true)) {
            val control = captureControl { path, count, record ->
                if (path.endsWith("/reports/confidence.json") && count == 2) {
                    if (replaceBytes) {
                        val changed = record.bytes + byteArrayOf(32)
                        record.copy(bytes = changed, sha256 = WebExplorationArtifact.sha256(changed))
                    } else record.copy(identity = record.identity.copy(key = LinuxFileKey(1, 99)))
                } else record
            }
            val failure = assertFailsWith<WebAccessDenied> { control.source.readFileMetadata(control.reference, control.fileId) }
            assertEquals(if (replaceBytes) "SOURCE_REVISION_CHANGED" else "SOURCE_CATALOG_CHANGED", failure.code)
        }
    }

    @Test fun `nonmodule metadata does not request generation reports or fabricate module ownership`() {
        val control = captureControl()
        val buildPath = profile.layout.declaration("build-definition").materialize()
        val id = revisionSourceFileId(control.reference, 0, buildPath)
        val result = control.source.readFileMetadata(control.reference, id)
        assertNull(result.recordedModule)
        assertEquals(3, control.reads.size)
        assertTrue(control.reads.values.all { it == 2 })
        assertFalse(control.reads.keys.any { it.endsWith("/reports/module_plan.json") || it.endsWith("/reports/confidence.json") })
    }

    @Test fun `optional report byte refusals preserve committed metadata during first read or recheck`() {
        for (name in listOf("module_plan.json", "confidence.json")) for (refusedRead in 1..2) {
            val control = captureControl { path, count, record ->
                if (path.endsWith("/reports/$name") && count == refusedRead) throw RepairBudgetExceededException(privateText)
                record
            }
            val result = control.source.readFileMetadata(control.reference, control.fileId)
            assertNull(result.recordedModule)
            assertEquals(control.reference, result.source.reference)
            assertEquals(implementationSha, resolveRevisionSourceFile(result.source, control.fileId).evidence.sha256)
            assertEquals(2, control.reads["input"])
            assertEquals(2, control.reads["reports/runs/run_1/source-tree/source_tree_manifest.json"])
            assertEquals(2, control.reads["reports/runs/run_1/source-tree/reports/build_contract.json"])
        }
    }

    @Test fun `optional capture fallback never swallows unrelated failures cancellation interruption or fatal errors`() {
        for (failure in listOf(IllegalStateException(privateText), WebAccessDenied(409, "SOURCE_CATALOG_CHANGED", "Changed"),
            java.util.concurrent.CancellationException(privateText), InterruptedException(privateText), AssertionError(privateText))) {
            val control = captureControl { path, _, record ->
                if (path.endsWith("/reports/confidence.json")) throw failure
                record
            }
            assertSame(failure, assertFails { control.source.readFileMetadata(control.reference, control.fileId) })
        }
    }
}
