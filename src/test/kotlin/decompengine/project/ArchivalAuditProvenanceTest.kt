package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ArchivalAuditProvenanceTest {
    @Test
    fun `schema two compiled entities remain unassessed in every reconstruction report`() {
        val project = Files.createTempDirectory("unassessed-model-reports-")
        val model = RecoveredProgramModel(
            schemaVersion = 2,
            inputSha256 = "a".repeat(64),
            functions = listOf(RecoveredFunction("fn_10", "compute", 0x1000UL,
                "int compute(void)", "int compute(void) { return 3; }")),
            globals = listOf(RecoveredGlobal("global_10", "counter", 0x2000UL, "int", "3")),
            types = listOf(RecoveredType("type_10", "typedef int result_t;")),
        )
        val expected = listOf("fn_10", "global_10", "type_10")
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor(true))
        assertTrue(manifest.unresolvedImplementationIds.isEmpty())
        assertEquals(expected, manifest.unresolvedEntityIds.sorted())
        val confidence = Json.parseToJsonElement(project.resolve("reports/confidence.json").readText()).jsonObject
        assertEquals("1.0000", confidence.getValue("projectScore").jsonPrimitive.content)
        assertEquals(expected, confidence.getValue("unresolvedRecoveryEntityIds").jsonArray.map { it.jsonPrimitive.content })
        val human = project.resolve("UNRESOLVED.md").readText()
        for (id in expected) assertTrue("`$id` | unassessed (extraction: recovered)" in human)
        val audit = ArchivalProjectAuditor.audit(project)
        assertTrue(audit.provenanceComplete)
        assertTrue(audit.moduleCompilationEvidenceProblems.isEmpty())
        assertEquals(expected, audit.unresolvedEntityIds)
        assertEquals(null, audit.behaviorMatched)
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val archive = project.parent.resolve(project.fileName.toString() + ".zip")
        ArchivalPackager.create(project, archive)
        val extracted = project.parent.resolve(project.fileName.toString() + "-extracted")
        ArchivalBundleVerifier.extractAndVerify(archive, extracted)
        assertEquals(expected, ArchivalProjectAuditor.audit(extracted).unresolvedEntityIds)
    }

    @Test
    fun `accepted flags cannot hide missing or mismatched compiler evidence`() {
        for (change in listOf("missing", "foreign-source", "failed", "foreign-command", "old-schema", "future-schema",
            "foreign-entity", "missing-entity", "duplicate-entity", "unresolved-entity", "unresolved-issue")) {
            val project = fixture(accepted = true)
            assertTrue(ArchivalProjectAuditor.audit(project).moduleCompilationEvidenceProblems.isEmpty())
            val plan = Json.parseToJsonElement(project.resolve("reports/module_plan.json").readText()).jsonObject
            val module = plan.getValue("modules").jsonArray.first().jsonObject
            val id = module.getValue("id").jsonPrimitive.content
            val path = "reports/modules/$id.json"
            val checkpoint = Json.parseToJsonElement(project.resolve(path).readText()).jsonObject
            val compilation = checkpoint.getValue("compilation").jsonObject
            val statuses = checkpoint.getValue("entityStatuses").jsonArray
            val changed = when (change) {
                "missing" -> JsonObject(checkpoint.filterKeys { it != "compilation" })
                "foreign-source" -> checkpoint.withField("compilation", compilation.withField("sourceSha256", JsonPrimitive("0".repeat(64))))
                "failed" -> checkpoint.withField("compilation", compilation.withField("outcome", JsonPrimitive("failed")))
                "old-schema" -> checkpoint.withField("schemaVersion", JsonPrimitive(4))
                "future-schema" -> checkpoint.withField("schemaVersion", JsonPrimitive(6))
                "foreign-entity" -> checkpoint.withField("entityStatuses", JsonArray(listOf(
                    statuses.first().jsonObject.withField("id", JsonPrimitive("foreign-entity")))))
                "missing-entity" -> checkpoint.withField("entityStatuses", JsonArray(emptyList()))
                "duplicate-entity" -> checkpoint.withField("entityStatuses", JsonArray(statuses + statuses.first()))
                "unresolved-entity" -> checkpoint.withField("entityStatuses", JsonArray(listOf(
                    statuses.first().jsonObject.withField("status", JsonPrimitive("unresolved")))))
                "unresolved-issue" -> checkpoint.withField("issues", JsonArray(listOf(JsonObject(mapOf(
                    "code" to JsonPrimitive("unresolved-implementation"), "message" to JsonPrimitive("pending"),
                    "entityIds" to JsonArray(statuses.map { it.jsonObject.getValue("id") }),
                )))))
                else -> checkpoint.withField("compilation", compilation.withField("command", JsonArray(listOf(JsonPrimitive("other-compiler")))))
            }
            writeBoundFile(project, path, changed.toString())
            val audit = ArchivalProjectAuditor.audit(project)
            assertEquals(setOf(id), audit.moduleCompilationEvidenceProblems.keys, change)
            assertEquals(module.getValue("functionIds").jsonArray.map { it.jsonPrimitive.content }.sorted(), audit.unresolvedEntityIds, change)
            val report = Json.parseToJsonElement(audit.toJson()).jsonObject
            assertEquals(setOf(id), report.getValue("moduleCompilationEvidenceProblems").jsonObject.keys)
        }
    }

    @Test
    fun `recovered model cannot hide evidence-only implementations even when unresolved list is omitted`() {
        val project = fixture()
        rewriteManifest(project) { it.withField("unresolvedImplementationIds", JsonArray(emptyList())) }

        val audit = ArchivalProjectAuditor.audit(project)

        assertTrue(audit.provenanceComplete)
        assertEquals(listOf("fn_10", "fn_100"), audit.unresolvedEntityIds)
    }

    @Test
    fun `accepted source and explicit unresolved facts are reconciled independently`() {
        val project = fixture(accepted = true)
        assertEquals(emptyList(), ArchivalProjectAuditor.audit(project).unresolvedEntityIds)
        rewriteManifest(project) {
            it.withField("unresolvedImplementationIds", JsonArray(listOf(JsonPrimitive("fn_10"))))
        }
        assertEquals(listOf("fn_10"), ArchivalProjectAuditor.audit(project).unresolvedEntityIds)
    }

    @Test
    fun `free text containing an entity ID cannot replace parsed module ownership`() {
        val project = fixture()
        val relative = "reports/module_plan.json"
        val plan = Json.parseToJsonElement(project.resolve(relative).readText()).jsonObject
        val modules = plan.getValue("modules").jsonArray.map { it.jsonObject }
        val retained = modules.filterNot { module ->
            module.getValue("functionIds").jsonArray.any { it.jsonPrimitive.content == "fn_10" }
        }.map { it.withField("boundaryEvidence", JsonArray(listOf(JsonPrimitive("fn_10")))) }
        assertTrue(retained.isNotEmpty())
        writeBoundFile(project, relative, plan.withField("modules", JsonArray(retained)).toString())

        val audit = ArchivalProjectAuditor.audit(project)

        assertEquals(listOf("fn_10"), audit.missingModelProvenance)
        assertTrue("fn_10" in audit.unresolvedEntityIds)
    }

    @Test
    fun `stale or missing source cannot receive current provenance or replace a prior audit`() {
        for (remove in listOf(false, true)) {
            val project = fixture(accepted = true)
            ArchivalProjectAuditor.audit(project)
            val priorAudit = project.resolve("reports/archival_audit.json").readText()
            val source = implementationPath(project)
            if (remove) Files.delete(project.resolve(source))
            else project.resolve(source).writeText("changed source bytes")

            assertFails { ArchivalProjectAuditor.audit(project) }
            assertEquals(priorAudit, project.resolve("reports/archival_audit.json").readText())
        }
    }

    @Test
    fun `audit rejects source indirection and unknown manifest identities`() {
        val linked = fixture()
        val source = linked.resolve(implementationPath(linked))
        val retained = Files.move(source, source.resolveSibling("retained-source"))
        Files.createSymbolicLink(source, retained.fileName)
        assertFails { ArchivalProjectAuditor.audit(linked) }

        val foreign = fixture()
        rewriteManifest(foreign) {
            it.withField("unresolvedImplementationIds", JsonArray(listOf(JsonPrimitive("foreign-entity"))))
        }
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(foreign) }
    }

    @Test
    fun `manifest and plan cross-pairs are rejected even after their file hashes are recomputed`() {
        val project = fixture()
        val relative = "reports/module_plan.json"
        val plan = Json.parseToJsonElement(project.resolve(relative).readText()).jsonObject
        val modules = plan.getValue("modules").jsonArray.map { it.jsonObject }
        val changed = modules.mapIndexed { index, module ->
            if (index == 0) module.withField("sourcePath", modules.last().getValue("sourcePath")) else module
        }
        writeBoundFile(project, relative, plan.withField("modules", JsonArray(changed)).toString())
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(project) }

        val foreign = fixture()
        rewriteManifest(foreign) { it.withField("inputSha256", JsonPrimitive("b".repeat(64))) }
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(foreign) }
    }

    @Test
    fun `duplicate plan keys are rejected even with a matching manifest hash`() {
        val project = fixture()
        val relative = "reports/module_plan.json"
        val text = project.resolve(relative).readText().replaceFirst("{", "{\"schemaVersion\":2,")
        writeBoundFile(project, relative, text)
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(project) }
    }

    @Test
    fun `audit follows declared implementation roles rather than C suffixes`() {
        val project = fixture()
        val original = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(
            original.schemaVersion, "audit-role-fixture-v1",
            ProjectLayoutProfile(original.layout.schemaVersion, original.layout.declarations.map { declaration ->
                if (ProjectFileRole.MODULE_IMPLEMENTATION in declaration.roles) ProjectFileDeclaration(
                    declaration.id, declaration.pathTemplate.removeSuffix(".c") + ".body", declaration.roles, declaration.contentKind,
                ) else declaration
            }), original.budgets, original.adapterConfiguration,
        )
        val manifest = SourceTreeManifestReader.read(project, original)
        val relocated = manifest.files.filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            .associate { it.path to it.path.removeSuffix(".c") + ".body" }
        relocated.forEach { (before, after) -> Files.move(project.resolve(before), project.resolve(after)) }
        val relative = "reports/module_plan.json"
        val plan = Json.parseToJsonElement(project.resolve(relative).readText()).jsonObject
        val modules = plan.getValue("modules").jsonArray.map { element ->
            val module = element.jsonObject
            module.withField("sourcePath", JsonPrimitive(relocated.getValue(module.getValue("sourcePath").jsonPrimitive.content)))
        }
        writeBoundFile(project, relative, plan.withField("modules", JsonArray(modules)).toString())
        rewriteManifest(project) { root ->
            root.withField("profileId", JsonPrimitive(profile.id)).withField("profileSha256", JsonPrimitive(profile.sha256))
                .withField("files", JsonArray(root.getValue("files").jsonArray.map { element ->
                    val file = element.jsonObject
                    relocated[file.getValue("path").jsonPrimitive.content]?.let { file.withField("path", JsonPrimitive(it)) } ?: file
                }.sortedBy { it.getValue("path").jsonPrimitive.content }))
        }
        assertTrue(ArchivalProjectAuditor.audit(project, profile).provenanceComplete)
        assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(project) }
    }

    @Test
    fun `global implementations and shared types retain their independent unresolved facts`() {
        val project = Files.createTempDirectory("archival-audit-globals-")
        val model = RecoveredProgramModel(
            inputSha256 = "a".repeat(64),
            functions = listOf(RecoveredFunction("fn_entry", "entry", 0x1000UL, "int entry(void)")),
            globals = listOf(RecoveredGlobal("global_state", "state", 0x2000UL, "int", "0")),
            types = listOf(RecoveredType("type_state", "typedef struct state_s { int value; } state_s;", status = RecoveryStatus.PARTIAL)),
        )
        SourceTreeGenerator.generate(model, project)
        val audit = ArchivalProjectAuditor.audit(project)
        assertTrue(audit.provenanceComplete)
        assertEquals(listOf("fn_entry", "global_state", "type_state"), audit.unresolvedEntityIds)
    }

    @Test
    fun `audit serialization escapes entity module and report identifiers`() {
        val identifier = "identifier\"\\\n"
        val audit = ArchivalAudit(
            1, listOf(identifier), listOf(identifier), listOf(identifier), 0, null, false,
            emptySet(), mapOf(identifier to "a".repeat(64)), listOf(identifier),
        )
        val document = Json.parseToJsonElement(audit.toJson()).jsonObject
        for (field in listOf("missingModelProvenance", "missingSourceProvenance", "unresolvedEntityIds", "unresolvedBehaviorReportIds")) {
            assertEquals(identifier, document.getValue(field).jsonArray.single().jsonPrimitive.content)
        }
        assertEquals(identifier, document.getValue("moduleSourceRevisions").jsonArray.single().jsonObject.getValue("moduleId").jsonPrimitive.content)
        assertTrue(document.getValue("moduleBehaviorEvidence").jsonArray.isEmpty())
    }

    private fun fixture(accepted: Boolean = false): Path {
        val project = Files.createTempDirectory("archival-audit-provenance-")
        val model = RecoveredProgramModel(
            inputSha256 = "a".repeat(64),
            functions = listOf(
                RecoveredFunction("fn_10", "parse_one", 0x1000UL, "int parse_one(void)", "int parse_one(void) { return 1; }"),
                RecoveredFunction("fn_100", "render_two", 0x2000UL, "int render_two(void)", "int render_two(void) { return 2; }"),
            ),
        )
        SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor(accepted))
        return project
    }

    private fun implementationPath(project: Path): String = SourceTreeManifestReader.read(
        project, GeneratedCMakeReconstructionProfile.descriptor,
    ).files.first { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }.path

    private fun rewriteManifest(project: Path, transform: (JsonObject) -> JsonObject) {
        val path = project.resolve("source_tree_manifest.json")
        path.writeText(transform(Json.parseToJsonElement(path.readText()).jsonObject).toString() + "\n")
    }

    private fun writeBoundFile(project: Path, relative: String, text: String) {
        project.resolve(relative).writeText(text)
        rewriteManifest(project) { root -> root.withField("files", JsonArray(root.getValue("files").jsonArray.map { element ->
            val file = element.jsonObject
            if (file.getValue("path").jsonPrimitive.content == relative) file.withField("sha256", JsonPrimitive(sha256(text.toByteArray())))
            else file
        })) }
    }

    private fun JsonObject.withField(name: String, value: kotlinx.serialization.json.JsonElement): JsonObject =
        JsonObject(toMutableMap().apply { put(name, value) })
}
