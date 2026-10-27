package decompengine.web

import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ModulePlan
import decompengine.project.PlannedModule
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import decompengine.project.SourceTreeManifest
import kotlinx.serialization.json.*
import kotlin.test.*

/** Pure metadata controls: no checkpoint payload, source body, filesystem, controller or process. */
class WebRecordedModuleValidationTest {
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val moduleId = "module_1"
    private val implementationSha = "b".repeat(64)
    private val checkpointSha = "c".repeat(64)
    private val diagnosticsSha = "d".repeat(64)
    private val inputSha = "a".repeat(64)
    private val privateText = "PRIVATE-COMPILER-COMMAND /private/checkpoint diagnostic text"
    private val sourcePath = profile.layout.declaration("module-implementation").materialize(mapOf("module" to moduleId))
    private val checkpointPath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to moduleId))

    private fun changedCheckpoint(original: GeneratedFileEvidence, path: String = original.path,
        sha256: String = original.sha256, roles: Set<ProjectFileRole> = original.roles,
        contentKind: ProjectContentKind = original.contentKind): GeneratedFileEvidence = GeneratedFileEvidence(
        path, sha256, original.generator, original.promptSha256, original.entityIds,
        original.acceptedImplementation, roles, contentKind,
    )

    private fun compilerRecord(outcome: String = "passed", code: JsonElement = JsonPrimitive(0)): JsonObject = buildJsonObject {
        put("sourceSha256", implementationSha); put("outcome", outcome); put("returnCode", code)
        put("diagnosticsSha256", diagnosticsSha); put("diagnosticsBytes", 7)
        put("command", buildJsonArray { add(privateText) }); put("rawOutput", privateText)
    }

    private fun revision(root: JsonObject, change: (JsonObject) -> JsonObject): JsonObject {
        val row = root.getValue("modules").jsonArray.single().jsonObject
        return JsonObject(root + ("modules" to JsonArray(listOf(JsonObject(row +
            ("revisionEvidence" to change(row.getValue("revisionEvidence").jsonObject)))))))
    }

    private fun record(change: (JsonObject) -> JsonObject = { it },
        checkpointChange: (GeneratedFileEvidence) -> GeneratedFileEvidence = { it }, accepted: Boolean = false): JsonObject {
        val selected = WebRevisionSourceFile(GeneratedFileEvidence(sourcePath, implementationSha, privateText,
            acceptedImplementation = accepted, roles = profile.layout.declaration("module-implementation").roles,
            contentKind = ProjectContentKind.UTF8_TEXT), 12)
        val headerPath = profile.layout.declaration("module-interface").materialize(mapOf("module" to moduleId))
        val plan = ModulePlan(modules = listOf(PlannedModule(moduleId, sourcePath, headerPath,
            emptyList(), emptyList(), emptyList(), emptyList()))).toJson().toByteArray(Charsets.UTF_8)
        val generation = change(buildJsonObject {
            put("schemaVersion", 2)
            put("modules", buildJsonArray { add(buildJsonObject {
                put("id", moduleId)
                put("revisionEvidence", buildJsonObject {
                    put("sourcePath", sourcePath); put("sourceSha256", implementationSha)
                    put("inputBinarySha256", inputSha); put("acceptedImplementation", accepted)
                    put("checkpointPath", checkpointPath); put("checkpointSha256", checkpointSha)
                    put("compilation", compilerRecord()); put("raw", privateText)
                })
            }) })
            put("sourceGenerationBudgetEvidence", buildJsonObject {
                put("schemaVersion", 1)
                put("selectedProfile", buildJsonObject { put("id", profile.id); put("sha256", profile.sha256) })
                put("modules", buildJsonArray { add(buildJsonObject {
                    put("moduleId", moduleId); put("sourceBytes", 12)
                    put("outcome", if (accepted) "accepted" else "unresolved")
                    put("promptCharacters", JsonNull); put("promptBudgetCharacters", JsonNull)
                }) })
            })
        }).toString().toByteArray(Charsets.UTF_8)
        fun evidence(id: String, bytes: ByteArray) = GeneratedFileEvidence(profile.layout.declaration(id).materialize(),
            WebExplorationArtifact.sha256(bytes), "fixture", roles = profile.layout.declaration(id).roles,
            contentKind = ProjectContentKind.UTF8_TEXT)
        val checkpoint = checkpointChange(GeneratedFileEvidence(checkpointPath, checkpointSha, privateText,
            roles = profile.layout.declaration("module-evidence").roles, contentKind = ProjectContentKind.UTF8_TEXT))
        val manifest = SourceTreeManifest(profileId = profile.id, profileSha256 = profile.sha256, inputSha256 = inputSha,
            files = listOf(selected.evidence, checkpoint, evidence("module-plan-evidence", plan), evidence("confidence-evidence", generation)),
            unresolvedEntityIds = emptyList())
        return assertNotNull(WebRecordedModuleProvenance.project(profile, manifest, selected, plan, generation))
    }

    @Test fun `bound checkpoint and closed compiler facts expose no command output or checkpoint path`() {
        val result = record(accepted = true)
        val validation = result.getValue("validation").jsonObject
        assertEquals(setOf("authority", "checkpointSha256", "compilation"), validation.keys)
        assertEquals("reported-module-validation", validation.getValue("authority").jsonPrimitive.content)
        assertEquals(checkpointSha, validation.getValue("checkpointSha256").jsonPrimitive.content)
        val compilation = validation.getValue("compilation").jsonObject
        assertEquals(setOf("sourceSha256", "outcome", "returnCode", "diagnosticsSha256", "diagnosticsBytes"), compilation.keys)
        assertEquals(implementationSha, compilation.getValue("sourceSha256").jsonPrimitive.content)
        assertEquals("passed", compilation.getValue("outcome").jsonPrimitive.content)
        assertEquals(0, compilation.getValue("returnCode").jsonPrimitive.int)
        assertEquals(diagnosticsSha, compilation.getValue("diagnosticsSha256").jsonPrimitive.content)
        assertEquals("7", compilation.getValue("diagnosticsBytes").jsonPrimitive.content)
        assertTrue(compilation.getValue("diagnosticsBytes").jsonPrimitive.isString)
        assertFalse(result.toString().contains(privateText)); assertFalse(result.toString().contains(checkpointPath))
        assertFalse(result.containsKey("acceptance")); assertFalse(result.containsKey("harness"))
    }

    @Test fun `unavailable or contradictory checkpoint declarations leave original generation metadata intact`() {
        for ((key, value) in listOf("checkpointPath" to JsonPrimitive("other/checkpoint.json"),
            "checkpointSha256" to JsonPrimitive("e".repeat(64)), "checkpointSha256" to JsonNull)) {
            assertFalse(record(change = { revision(it) { row -> JsonObject(row + (key to value)) } }).containsKey("validation"))
        }
        assertFalse(record(change = { revision(it) { row -> JsonObject(row - "checkpointSha256") } }).containsKey("validation"))
        for (change in listOf<(GeneratedFileEvidence) -> GeneratedFileEvidence>(
            { changedCheckpoint(it, sha256 = "e".repeat(64)) }, { changedCheckpoint(it, path = "other/checkpoint.json") },
            { changedCheckpoint(it, roles = setOf(ProjectFileRole.EVIDENCE, ProjectFileRole.BUILD_INPUT)) },
            { changedCheckpoint(it, roles = setOf(ProjectFileRole.ARCHIVE_PAYLOAD)) },
            { changedCheckpoint(it, contentKind = ProjectContentKind.BINARY) })) {
            val result = record(checkpointChange = change)
            assertFalse(result.containsKey("validation")); assertEquals(implementationSha, result.getValue("implementationSha256").jsonPrimitive.content)
        }
    }

    @Test fun `all producer compiler outcomes retain exact signed codes without implying acceptance`() {
        for ((outcome, code) in listOf("passed" to JsonPrimitive(0), "failed" to JsonPrimitive(1),
            "failed" to JsonPrimitive(Int.MIN_VALUE), "failed-to-start" to JsonNull, "timed-out" to JsonPrimitive(143),
            "output-limit-exceeded" to JsonPrimitive(137), "source-changed" to JsonPrimitive(0))) {
            val result = record(change = { revision(it) { row -> JsonObject(row + ("compilation" to compilerRecord(outcome, code))) } })
            val compilation = result.getValue("validation").jsonObject.getValue("compilation").jsonObject
            assertEquals(outcome, compilation.getValue("outcome").jsonPrimitive.content)
            assertEquals(code, compilation.getValue("returnCode"))
        }
    }

    @Test fun `invalid optional compiler facts preserve the bound checkpoint and original generation scalars`() {
        val invalid = listOf(
            "sourceSha256" to JsonPrimitive("e".repeat(64)), "outcome" to JsonPrimitive("verified"),
            "returnCode" to JsonPrimitive(1), "returnCode" to JsonPrimitive("0"), "returnCode" to JsonPrimitive(0.5),
            "returnCode" to JsonPrimitive(2147483648L), "returnCode" to JsonPrimitive(-2147483649L),
            "diagnosticsSha256" to JsonPrimitive(privateText), "diagnosticsBytes" to JsonPrimitive(-1),
            "diagnosticsBytes" to JsonPrimitive("7"),
            "diagnosticsBytes" to JsonPrimitive(profile.budgets.buildMaximumOutputBytes + 1),
        )
        for ((key, value) in invalid) {
            val result = record(change = { revision(it) { row ->
                JsonObject(row + ("compilation" to JsonObject(compilerRecord() + (key to value))))
            } })
            val validation = result.getValue("validation").jsonObject
            assertEquals(checkpointSha, validation.getValue("checkpointSha256").jsonPrimitive.content)
            assertEquals(JsonNull, validation["compilation"])
            assertEquals(implementationSha, result.getValue("implementationSha256").jsonPrimitive.content)
        }
        for (compilation in listOf(JsonNull, JsonPrimitive(privateText), JsonObject(compilerRecord() - "returnCode"),
            compilerRecord("failed-to-start", JsonPrimitive(1)))) {
            assertEquals(JsonNull, record(change = { revision(it) { row -> JsonObject(row + ("compilation" to compilation)) } })
                .getValue("validation").jsonObject["compilation"])
        }
        assertEquals(JsonNull, record(accepted = true, change = { revision(it) { row ->
            JsonObject(row + ("compilation" to compilerRecord("failed", JsonPrimitive(1))))
        } }).getValue("validation").jsonObject["compilation"])
    }
}
