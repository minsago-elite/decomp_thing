package decompengine.project

import decompengine.repair.ModuleRevisionGraph
import decompengine.repair.ModuleRevisionStatus
import decompengine.repair.open
import decompengine.validation.BehaviorEvidenceCapture
import decompengine.validation.BehaviorProjectContext
import decompengine.validation.BehaviorComparator
import decompengine.validation.ProcessInput
import decompengine.validation.SandboxRunner
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GeneratedCEvidenceCarrierTest {
    @Test
    fun `carrier type commitments follow canonical model order without mutating caller facts`() = fixture { root ->
        val unsorted = rawModel().copy(types = listOf(
            RecoveredType("type_z", "typedef struct last_raw { undefined8 member; } last_raw;"),
            RecoveredType("type_a", "typedef struct first_raw { pointer member; } first_raw;"),
        ))
        val ordered = unsorted.copy(types = unsorted.types.sortedBy { it.id })
        assertEquals(ordered.toJson(), unsorted.toJson())
        for ((index, base) in BASE_PROFILES.withIndex()) {
            val profile = GeneratedCEvidenceCarrier.profile(base)
            val unorderedProject = root.resolve("unsorted-$index")
            val orderedProject = root.resolve("ordered-$index")
            val first = SourceTreeGenerator.generate(unsorted, unorderedProject, profile = profile,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
            val second = SourceTreeGenerator.generate(ordered, orderedProject, profile = profile,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
            assertEquals(listOf("type_z", "type_a"), unsorted.types.map { it.id })
            assertEquals(first.toJson(), second.toJson())
            first.files.forEach { file ->
                assertContentEquals(orderedProject.resolve(file.path).readBytes(), unorderedProject.resolve(file.path).readBytes(), file.path)
            }
            val adapter = ReconstructionAdapters.resolve(profile)
            assertEquals(0, adapter.build(unorderedProject, profile).returnCode)
            assertEquals(0, adapter.build(orderedProject, profile).returnCode)
            ArchivalProjectAuditor.audit(unorderedProject, profile)
            ArchivalProjectAuditor.audit(orderedProject, profile)
            // Independent parallel builds retain their actual scheduling/progress logs.
            // Generated evidence is identical above; each retained payload must archive deterministically.
            for ((label, project) in listOf("unsorted" to unorderedProject, "ordered" to orderedProject)) {
                val firstArchive = ArchivalPackager.create(project, root.resolve("$label-$index.zip"), profile = profile)
                val repeatedArchive = ArchivalPackager.create(project, root.resolve("$label-$index-repeat.zip"), profile = profile)
                assertEquals(firstArchive.archiveSha256, repeatedArchive.archiveSha256)
                val extracted = root.resolve("extracted-$label-$index")
                ArchivalBundleVerifier.extractAndVerify(firstArchive.archivePath, extracted, profile = profile)
                assertEquals(0, adapter.build(extracted, profile).returnCode)
                assertAllUnresolved(extracted, unsorted, profile)
            }
        }
    }

    @Test
    fun `direct carrier audits reject unmanifested authority evidence and preserve prior audit`() = fixture { root ->
        val base = BASE_PROFILES.first()
        val relocated = ReconstructionProfile(base.schemaVersion, base.id,
            ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
                if (declaration.id == "module-agent-execution-evidence") ProjectFileDeclaration(
                    declaration.id, "retained/custom-receipts/{module}.json", declaration.roles, declaration.contentKind)
                else declaration
            }), base.budgets, base.adapterConfiguration)
        for ((index, selected) in listOf(base, relocated).withIndex()) {
            val profile = GeneratedCEvidenceCarrier.profile(selected)
            val project = root.resolve("project-$index")
            val manifest = SourceTreeGenerator.generate(rawModel(), project, profile = profile,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
            assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
            ArchivalProjectAuditor.audit(project, profile)
            val auditPath = project.resolve("reports/archival_audit.json")
            val previousAudit = auditPath.readBytes()
            val manifestBytes = project.resolve("source_tree_manifest.json").readBytes()
            val receipt = profile.layout.declaration("module-agent-execution-evidence")
                .materialize(mapOf("module" to "unlisted"))
            for ((case, relative) in listOf("reports/repair-revisions/graph.json", "reports/repair_history.json", receipt).withIndex()) {
                assertTrue(manifest.files.none { it.path == relative })
                val forbidden = project.resolve(relative)
                forbidden.parent.createDirectories()
                forbidden.writeText("{\"unmanifested\":true}\n")
                val failure = assertFailsWith<IllegalArgumentException>(relative) { ArchivalProjectAuditor.audit(project, profile) }
                assertTrue(failure.message.orEmpty().contains("execution or repair evidence"), failure.message)
                assertContentEquals(previousAudit, auditPath.readBytes(), "a failed publishing audit must preserve its predecessor")
                assertContentEquals(manifestBytes, project.resolve("source_tree_manifest.json").readBytes())
                val rejectedArchive = root.resolve("rejected-$index-$case.zip")
                assertFailsWith<IllegalArgumentException> { ArchivalPackager.create(project, rejectedArchive, profile = profile) }
                assertFalse(rejectedArchive.exists())
                Files.delete(forbidden)
                ArchivalProjectAuditor.audit(project, profile)
                assertContentEquals(previousAudit, auditPath.readBytes())
            }
        }
    }

    @Test
    fun `unsupported recovered evidence has deterministic strict Make and Ninja carrier archives without implementation acceptance`() = fixture { root ->
        val model = rawModel()
        val canonical = model.toJson().toByteArray()
        for ((index, base) in BASE_PROFILES.withIndex()) {
            val profile = GeneratedCEvidenceCarrier.profile(base)
            assertEquals(base.id, profile.id)
            assertNotEquals(base.sha256, profile.sha256)
            assertEquals(base.layout, profile.layout)
            assertEquals(base.budgets, profile.budgets)
            assertEquals(base.adapterConfiguration["compiler-flags"], profile.adapterConfiguration["compiler-flags"])
            val project = root.resolve("project-$index")
            val manifest = SourceTreeGenerator.generate(model, project, profile = profile,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
            assertContentEquals(canonical, model.toJson().toByteArray())
            assertContentEquals(canonical, project.resolve("reports/program_model.json").readBytes())
            assertAllUnresolved(project, model, profile)
            val plan = json(project.resolve("reports/module_plan.json"))
            assertEquals(Json.parseToJsonElement(DeterministicModulePlanner().plan(model, OWNERS).toJson()), plan)
            val retainedOwners = plan.getValue("modules").jsonArray.flatMap { value ->
                val module = value.jsonObject
                (module.getValue("functionIds").jsonArray + module.getValue("globalIds").jsonArray)
                    .map { it.jsonPrimitive.content to module.getValue("id").jsonPrimitive.content }
            }.toMap()
            assertEquals(OWNERS, retainedOwners)
            assertEquals(model.ids(), manifest.files.flatMap { it.entityIds }.toSet())
            assertTrue(manifest.files.filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
                .all { it.acceptedImplementation == false })

            val adapter = ReconstructionAdapters.resolve(profile)
            val built = adapter.build(project, profile)
            assertEquals(0, built.returnCode)
            val contract = json(project.resolve("reports/build_contract.json"))
            assertEquals("true", contract.getValue("warningsAsErrors").jsonPrimitive.content)
            assertEquals("true", contract.getValue("sourceStableDuringBuild").jsonPrimitive.content)
            val first = ArchivalPackager.create(project, root.resolve("first-$index.zip"), profile = profile)
            val second = ArchivalPackager.create(project, root.resolve("second-$index.zip"), profile = profile)
            assertEquals(first.archiveSha256, second.archiveSha256)
            val extracted = root.resolve("extracted-$index")
            ArchivalBundleVerifier.extractAndVerify(first.archivePath, extracted, profile = profile)
            assertContentEquals(canonical, extracted.resolve("reports/program_model.json").readBytes())
            assertEquals(0, adapter.build(extracted, profile).returnCode)
            assertAllUnresolved(extracted, model, profile)

            val process = ProcessBuilder(extracted.resolve("build/reconstructed").toString())
                .directory(extracted.toFile()).redirectErrorStream(true).start()
            try {
                assertTrue(process.waitFor(5, TimeUnit.SECONDS), "carrier must terminate promptly")
                val output = process.inputStream.readNBytes(4096).decodeToString()
                assertEquals(1, process.exitValue())
                assertTrue(output.contains("evidence-only") && output.contains("unresolved"), output)
                assertFalse(output.contains("RECOVERED_ENTRY_EXECUTED"), output)
            } finally { if (process.isAlive) process.destroyForcibly() }
        }
    }

    @Test
    fun `carrier purpose cannot be selected by a reconstructor label or mixed with implementation reconstruction`() = fixture { root ->
        val base = BASE_PROFILES.first()
        val carrier = GeneratedCEvidenceCarrier.profile(base)
        assertTrue(GeneratedCEvidenceCarrier.isSelected(carrier))
        assertFalse(GeneratedCEvidenceCarrier.isSelected(base))
        assertEquals(GeneratedCEvidenceCarrier.IDENTITY, GeneratedCEvidenceCarrier.reconstructor.cacheIdentity())
        for (values in listOf(emptyList(), listOf("strict"), listOf("evidence-carrier-v2"),
            listOf(GeneratedCEvidenceCarrier.PURPOSE, GeneratedCEvidenceCarrier.PURPOSE))) {
            assertFailsWith<IllegalArgumentException> {
                val changed = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
                    base.adapterConfiguration + (GeneratedCEvidenceCarrier.PURPOSE_KEY to values))
                GeneratedCEvidenceCarrier.isSelected(changed)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            SourceTreeGenerator.generate(rawModel(), root.resolve("strict-with-carrier"), profile = base,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor)
        }
        val labelledCarrier = object : ModuleReconstructor {
            override fun reconstruct(request: ModuleReconstructionRequest) = GeneratedCEvidenceCarrier.reconstructor.reconstruct(request)
            override fun cacheIdentity() = GeneratedCEvidenceCarrier.IDENTITY
        }
        for ((index, reconstructor) in listOf(EvidenceModuleReconstructor(), RecoveredCModuleReconstructor(),
            labelledCarrier).withIndex()) {
            assertFailsWith<IllegalArgumentException> {
                SourceTreeGenerator.generate(rawModel(), root.resolve("carrier-with-other-$index"), profile = carrier,
                    reconstructor = reconstructor)
            }
        }
    }

    @Test
    fun `the same raw model still fails strict declaration compilation and cannot be published`() = fixture { root ->
        val model = rawModel()
        val project = root.resolve("strict")
        val manifest = SourceTreeGenerator.generate(model, project, reconstructor = EvidenceModuleReconstructor(), overrides = OWNERS)
        assertTrue(manifest.unresolvedImplementationIds.containsAll(model.functions.map { it.id } + model.globals.map { it.id }))
        assertContentEquals(model.toJson().toByteArray(), project.resolve("reports/program_model.json").readBytes())
        assertFailsWith<BuildException> { MakeProjectBuilder.build(project) }
        val log = project.resolve("reports/build.log").readText()
        assertTrue(log.contains("undefined8") && log.contains("pointer"), log)
        assertFailsWith<IllegalArgumentException> { ArchivalPackager.create(project, root.resolve("strict.zip")) }
        assertFalse(root.resolve("strict.zip").exists())
    }

    @Test
    fun `carrier builds cannot enter behavior evidence capture or strict candidate admission`() = fixture { root ->
        val model = rawModel()
        val profile = GeneratedCEvidenceCarrier.profile(BASE_PROFILES.first())
        val project = root.resolve("carrier")
        SourceTreeGenerator.generate(model, project, profile = profile,
            reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
        ReconstructionAdapters.resolve(profile).build(project, profile)
        val failure = assertFailsWith<IllegalArgumentException> {
            BehaviorEvidenceCapture().project(BehaviorProjectContext(project, profile),
                JsonObject(mapOf("sha256" to JsonPrimitive(model.inputSha256))), project.resolve("build/reconstructed"))
        }
        assertTrue(failure.message.orEmpty().contains("carrier"), failure.message)
        val comparisonReports = root.resolve("behavior-not-created")
        val comparison = assertFailsWith<IllegalArgumentException> {
            BehaviorComparator(SandboxRunner(networkIsolation = false)).evaluate("carrier",
                root.resolve("original-not-executed"), project.resolve("build/reconstructed"),
                listOf(ProcessInput("authored-case")), comparisonReports, BehaviorProjectContext(project, profile))
        }
        assertTrue(comparison.message.orEmpty().contains("carrier"), comparison.message)
        assertFalse(comparisonReports.exists(), "carrier comparison must reject before output or execution setup")
        assertFailsWith<IllegalArgumentException> {
            ReconstructionAdapters.resolve(profile).behaviorBuild.parseContract(json(project.resolve("reports/build_contract.json")), profile)
        }
        assertFailsWith<IllegalArgumentException> { GeneratedCRepairSourcePolicy(profile) }
        val plan = DeterministicModulePlanner().plan(model, OWNERS)
        for (module in plan.modules.filter { it.functionIds.isNotEmpty() || it.globalIds.isNotEmpty() }) {
            val source = project.resolve(module.sourcePath).readText()
            val issues = GeneratedCCandidateValidation.assess(module, model, "scripted-agent", source)
            assertTrue(issues.isNotEmpty(), module.id)
            assertTrue(issues.flatMap { it.entityIds }.containsAll(module.functionIds + module.globalIds), issues.toString())
        }
        val emptyModule = PlannedModule("empty", "src/modules/empty.c", "include/modules/empty.h",
            emptyList(), emptyList(), boundaryEvidence = emptyList())
        val emptyModel = RecoveredProgramModel(inputSha256 = "empty-carrier-candidate", functions = emptyList())
        val markedSource = " \n/* harmless prefix */\n/* decomp-evidence-carrier-v1\n*/\nint retained_diagnostic;\n"
        for (strict in BASE_PROFILES) {
            val issues = ReconstructionAdapters.resolve(strict).assess(emptyModule, emptyModel, "custom", markedSource, strict)
            assertTrue(issues.any { it.code == "evidence-only-carrier" }, issues.toString())
            assertTrue(issues.all { it.entityIds.isEmpty() })
        }
    }

    @Test
    fun `carrier and implementation purposes cannot reuse one another's workspace checkpoints`() = fixture { root ->
        val base = BASE_PROFILES.first()
        val carrier = GeneratedCEvidenceCarrier.profile(base)
        val model = RecoveredProgramModel(inputSha256 = "workspace-purpose",
            functions = listOf(RecoveredFunction("fn_main", "main", 0x1000UL,
                "int main(void)", "int main(void) { return 17; }")))
        val carrierProject = root.resolve("carrier")
        SourceTreeGenerator.generate(model, carrierProject, profile = carrier, reconstructor = GeneratedCEvidenceCarrier.reconstructor)
        val retainedCarrier = carrierProject.resolve("source_tree_manifest.json").readBytes()
        assertFailsWith<IllegalArgumentException> {
            SourceTreeGenerator.generate(model, carrierProject, profile = base, reconstructor = RecoveredCModuleReconstructor())
        }
        assertContentEquals(retainedCarrier, carrierProject.resolve("source_tree_manifest.json").readBytes())
        val strictProject = root.resolve("strict")
        val strict = SourceTreeGenerator.generate(model, strictProject, profile = base, reconstructor = RecoveredCModuleReconstructor())
        assertTrue(strict.unresolvedImplementationIds.isEmpty())
        val retainedStrict = strictProject.resolve("source_tree_manifest.json").readBytes()
        assertFailsWith<IllegalArgumentException> {
            SourceTreeGenerator.generate(model, strictProject, profile = carrier, reconstructor = GeneratedCEvidenceCarrier.reconstructor)
        }
        assertContentEquals(retainedStrict, strictProject.resolve("source_tree_manifest.json").readBytes())
    }

    @Test
    fun `rehashing changed carrier source header entry or checkpoint cannot promote or publish it`() = fixture { root ->
        val model = rawModel()
        val profile = GeneratedCEvidenceCarrier.profile(BASE_PROFILES.first())
        for (mutation in listOf("source", "header", "entry", "checkpoint", "manifest", "header-acceptance", "entry-acceptance")) {
            val project = root.resolve(mutation)
            val manifest = SourceTreeGenerator.generate(model, project, profile = profile,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
            assertEquals(0, ReconstructionAdapters.resolve(profile).build(project, profile).returnCode)
            ArchivalPackager.create(project, root.resolve("$mutation-baseline.zip"), profile = profile)
            val modulePath = manifest.files.first { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }.path
            when (mutation) {
                "source", "header", "entry" -> {
                    val path = when (mutation) {
                        "source" -> modulePath
                        "header" -> manifest.files.first { ProjectFileRole.PUBLIC_INTERFACE in it.roles }.path
                        else -> manifest.files.first { ProjectFileRole.ENTRYPOINT_IMPLEMENTATION in it.roles }.path
                    }
                    writeBoundFile(project, path, project.resolve(path).readText() + "\n/* rehashed alteration */\n")
                }
                "checkpoint" -> {
                    val moduleId = modulePath.substringAfterLast('/').removeSuffix(".c")
                    val path = "reports/modules/$moduleId.json"
                    val checkpoint = json(project.resolve(path))
                    writeBoundFile(project, path, JsonObject(checkpoint + mapOf(
                        "accepted" to JsonPrimitive(true), "generator" to JsonPrimitive("recovered-c"),
                        "reconstructorIdentity" to JsonPrimitive("recovered-c:v5"), "issues" to JsonArray(emptyList()),
                    )).toString())
                }
                "header-acceptance", "entry-acceptance" -> {
                    val role = if (mutation == "header-acceptance") ProjectFileRole.PUBLIC_INTERFACE
                        else ProjectFileRole.ENTRYPOINT_IMPLEMENTATION
                    val path = manifest.files.first { role in it.roles }.path
                    assertEquals(null, manifest.files.single { it.path == path }.acceptedImplementation)
                    rewriteManifest(project) { document -> JsonObject(document + ("files" to JsonArray(
                        document.getValue("files").jsonArray.map { value ->
                            val file = value.jsonObject
                            if (file.getValue("path").jsonPrimitive.content == path)
                                JsonObject(file + ("acceptedImplementation" to JsonPrimitive(true))) else file
                        },
                    ))) }
                }
                else -> rewriteManifest(project) { document -> JsonObject(document + mapOf(
                    "unresolvedEntityIds" to JsonArray(emptyList()), "unresolvedImplementationIds" to JsonArray(emptyList()),
                    "files" to JsonArray(document.getValue("files").jsonArray.map { value ->
                        val file = value.jsonObject
                        if (file.getValue("acceptedImplementation") == JsonNull) file
                        else JsonObject(file + ("acceptedImplementation" to JsonPrimitive(true)))
                    }),
                )) }
            }
            assertFailsWith<IllegalArgumentException>(mutation) { ArchivalProjectAuditor.audit(project, profile) }
            assertFailsWith<IllegalArgumentException>(mutation) {
                ArchivalPackager.create(project, root.resolve("$mutation.zip"), profile = profile)
            }
            assertFalse(root.resolve("$mutation.zip").exists())
            if (mutation == "checkpoint") {
                assertFailsWith<IllegalArgumentException> {
                    SourceTreeGenerator.generate(model, project, profile = profile,
                        reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
                }
            }
        }
    }

    @Test
    fun `stripping carrier profile labels cannot turn carrier bytes into strict recovery or behavior evidence`() = fixture { root ->
        val model = rawModel()
        val base = BASE_PROFILES.first()
        val carrier = GeneratedCEvidenceCarrier.profile(base)
        val project = root.resolve("carrier")
        val manifest = SourceTreeGenerator.generate(model, project, profile = carrier,
            reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
        ReconstructionAdapters.resolve(carrier).build(project, carrier)
        for (file in manifest.files.filter { ProjectFileRole.BUILD_INPUT in it.roles }) {
            val text = project.resolve(file.path).readText()
            if (text.startsWith("/* decomp-evidence-carrier-v1\n")) {
                writeBoundFile(project, file.path, " \n/* harmless prefix */\n" + text)
            }
        }
        rewriteManifest(project) { document -> JsonObject(document + mapOf(
            "profileId" to JsonPrimitive(base.id), "profileSha256" to JsonPrimitive(base.sha256),
            "unresolvedEntityIds" to JsonArray(emptyList()), "unresolvedImplementationIds" to JsonArray(emptyList()),
            "files" to JsonArray(document.getValue("files").jsonArray.map { value ->
                val file = value.jsonObject
                if (file.getValue("acceptedImplementation") == JsonNull) file
                else JsonObject(file + mapOf("acceptedImplementation" to JsonPrimitive(true), "generator" to JsonPrimitive("recovered-c")))
            }),
        )) }
        val failure = assertFailsWith<IllegalArgumentException> { ArchivalProjectAuditor.audit(project, base) }
        assertTrue(failure.message.orEmpty().contains("carrier"), failure.message)
        val behavior = assertFailsWith<IllegalArgumentException> {
            BehaviorEvidenceCapture().project(BehaviorProjectContext(project, base),
                JsonObject(mapOf("sha256" to JsonPrimitive(model.inputSha256))), project.resolve("build/reconstructed"))
        }
        assertTrue(behavior.message.orEmpty().contains("carrier"), behavior.message)
    }

    @Test
    fun `mutable roles and generator labels cannot hide a carrier workspace from strict generation`() = fixture { root ->
        val model = rawModel()
        val base = BASE_PROFILES.first()
        val carrier = GeneratedCEvidenceCarrier.profile(base)
        for (mutation in listOf("remove-roles", "omit-marked-inputs", "delete-manifest")) {
            val project = root.resolve(mutation)
            val manifest = SourceTreeGenerator.generate(model, project, profile = carrier,
                reconstructor = GeneratedCEvidenceCarrier.reconstructor, overrides = OWNERS)
            val markedInputs = manifest.files.filter { ProjectFileRole.BUILD_INPUT in it.roles &&
                project.resolve(it.path).readText().startsWith("/* decomp-evidence-carrier-v1\n") }.map { it.path }.toSet()
            assertTrue(markedInputs.isNotEmpty())
            if (mutation == "delete-manifest") Files.delete(project.resolve("source_tree_manifest.json"))
            else rewriteManifest(project) { document -> JsonObject(document + mapOf(
                "profileId" to JsonPrimitive(base.id), "profileSha256" to JsonPrimitive(base.sha256),
                "files" to JsonArray(document.getValue("files").jsonArray.mapNotNull { value ->
                    val file = value.jsonObject
                    if (mutation == "omit-marked-inputs" && file.getValue("path").jsonPrimitive.content in markedInputs) null
                    else JsonObject(file + mapOf("roles" to JsonArray(emptyList()), "generator" to JsonPrimitive("recovered-c")))
                }),
            )) }
            val preserved = (manifest.files.map { it.path } +
                if (mutation == "delete-manifest") emptyList() else listOf("source_tree_manifest.json"))
                .associateWith { project.resolve(it).readBytes() }
            val failure = assertFailsWith<IllegalArgumentException> {
                SourceTreeGenerator.generate(model, project, profile = base, reconstructor = RecoveredCModuleReconstructor())
            }
            assertTrue(failure.message.orEmpty().contains("carrier"), failure.message)
            preserved.forEach { (path, bytes) -> assertContentEquals(bytes, project.resolve(path).readBytes(), path) }
            if (mutation == "delete-manifest") assertFalse(project.resolve("source_tree_manifest.json").exists())
        }
    }

    @Test
    fun `many empty retained modules must fit the manifest inventory before carrier rendering`() = fixture { root ->
        val profile = GeneratedCEvidenceCarrier.profile(BASE_PROFILES.first())
        val model = RecoveredProgramModel(inputSha256 = "empty-inventory", functions = emptyList())
        val project = root.resolve("empty-modules")
        SourceTreeGenerator.generate(model, project, profile = profile, reconstructor = GeneratedCEvidenceCarrier.reconstructor)
        val plan = ModulePlan(modules = (0 until 64).map { index ->
            val id = "empty_$index"
            PlannedModule(id, profile.layout.declaration("module-implementation").materialize(mapOf("module" to id)),
                profile.layout.declaration("module-interface").materialize(mapOf("module" to id)),
                emptyList(), emptyList(), boundaryEvidence = emptyList())
        })
        writeBoundFile(project, "reports/module_plan.json", plan.toJson())
        val manifest = SourceTreeManifestReader.read(project, profile)
        val failure = assertFailsWith<IllegalArgumentException> {
            GeneratedCEvidenceCarrier.verifyProject(project, profile, manifest)
        }
        assertTrue(failure.message.orEmpty().contains("complete build inventory exceeds"), failure.message)
        assertContentEquals(plan.toJson().toByteArray(), project.resolve("reports/module_plan.json").readBytes())
        assertFalse(project.resolve(plan.modules.first().sourcePath).exists())
    }

    @Test
    fun `empty and type-only carrier services remain unresolved after successful archive publication`() = fixture { root ->
        for ((index, template) in listOf(RecoveredProgramModel(inputSha256 = "empty", functions = emptyList()),
            RecoveredProgramModel(inputSha256 = "types", functions = emptyList(), types = rawModel().types)).withIndex()) {
            val profile = GeneratedCEvidenceCarrier.profile(BASE_PROFILES.first())
            val input = root.resolve("input-$index").also { it.writeText("authored carrier fixture") }
            val model = template.copy(inputSha256 = sha256(input.readBytes()))
            val output = root.resolve("result-$index")
            val result = ArchivalReconstructionService(ProgramModelAnalyzer { _, _ -> model },
                GeneratedCEvidenceCarrier.reconstructor, profile = profile).reconstruct(input, output)
            assertEquals(0, result.build.returnCode)
            assertTrue(result.bundle.archivePath.exists())
            assertEquals("unresolved", json(output.resolve("reconstruction.json")).getValue("implementationStatus").jsonPrimitive.content)
            assertEquals("unresolved", json(output.resolve("reconstruction_progress.json")).getValue("phase").jsonPrimitive.content)
            assertAllUnresolved(result.projectDir, model, profile)
        }
    }

    @Test
    fun `strict repair rejects carrier bytes before persistence and remains usable`() = fixture { root ->
        val project = root.resolve("strict-repair")
        val manifest = SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
            RecoveredFunction("fn_target", "repair_target", 0x1000UL, "int repair_target(void)"),
        )), project)
        val relative = manifest.files.single { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }.path
        val target = project.resolve(relative)
        val original = target.readBytes()
        val marked = " \n/* harmless prefix */\n/* decomp-evidence-carrier-v1\n*/\n".toByteArray() + original
        val ordinary = original + "\n/* ordinary repair candidate */\n".toByteArray()
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val markedBlob = project.resolve("reports/repair-revisions/blobs/${sha256(marked)}")
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
            val attempt = graph.beginAttempt(listOf(relative))
            val before = graph.snapshot
            val persistedBefore = graphPath.readBytes()
            val failure = assertFailsWith<IllegalArgumentException> { graph.installCandidate(attempt, mapOf(relative to marked)) }
            assertTrue(failure.message.orEmpty().contains("evidence-carrier"), failure.message)
            assertEquals(before, graph.snapshot)
            assertContentEquals(persistedBefore, graphPath.readBytes())
            assertContentEquals(original, target.readBytes())
            assertFalse(markedBlob.exists())
            val changes = graph.installCandidate(attempt, mapOf(relative to ordinary))
            assertEquals(listOf(relative), changes.map { it.path })
            assertContentEquals(ordinary, target.readBytes())
            val rejected = graph.reject(attempt)
            assertEquals(ModuleRevisionStatus.REJECTED, rejected.status)
            assertEquals(listOf(relative), rejected.changes.map { it.path })
            assertEquals(before.headId, graph.snapshot.headId)
            assertEquals(null, graph.snapshot.pendingAttemptId)
            assertContentEquals(original, target.readBytes())
        }
    }

    private fun assertAllUnresolved(project: Path, model: RecoveredProgramModel, profile: ReconstructionProfile) {
        val manifest = SourceTreeManifestReader.read(project, profile)
        val unresolved = manifest.unresolvedEntityIds.toSet() + manifest.unresolvedImplementationIds
        assertEquals(model.ids(), unresolved)
        assertTrue(manifest.files.none { it.acceptedImplementation == true })
        assertEquals(model.ids(), ArchivalProjectAuditor.audit(project, profile).unresolvedEntityIds.toSet())
        Files.walk(project.resolve("reports/modules")).use { paths ->
            paths.filter { it.fileName.toString().endsWith(".json") }.forEach { path ->
                val checkpoint = json(path)
                assertEquals("false", checkpoint.getValue("accepted").jsonPrimitive.content, path.toString())
                assertEquals(JsonNull, checkpoint.getValue("compilation"), path.toString())
                assertEquals(GeneratedCEvidenceCarrier.IDENTITY, checkpoint.getValue("reconstructorIdentity").jsonPrimitive.content)
            }
        }
    }

    private fun rawModel() = RecoveredProgramModel(schemaVersion = 2, inputSha256 = "a".repeat(64),
        functions = listOf(
            RecoveredFunction("fn_main", "main", 0x1000UL, "undefined8 main(void)",
                "undefined8 main(void) { puts(\"RECOVERED_ENTRY_EXECUTED\"); return 99; }", calls = setOf("fn_worker"),
                referencedGlobals = setOf("global_pointer")),
            RecoveredFunction("fn_worker", "worker", 0x2000UL, "undefined worker(EVP_PKEY_CTX *ctx)",
                referencedGlobals = setOf("global_byte")),
        ),
        globals = listOf(
            RecoveredGlobal("global_pointer", "PTR_00103fe8", 0x3000UL, "pointer", initializer = "00105048"),
            RecoveredGlobal("global_byte", "DAT_0010200b", 0x4000UL, "undefined", initializer = "72h    r"),
        ),
        types = listOf(RecoveredType("type_partial", "typedef struct raw_type { undefined8 member; } raw_type;")),
    )

    private fun RecoveredProgramModel.ids(): Set<String> = (functions.map { it.id } + globals.map { it.id } + types.map { it.id }).toSet()
    private fun json(path: Path): JsonObject = Json.parseToJsonElement(path.readText()).jsonObject
    private fun rewriteManifest(project: Path, update: (JsonObject) -> JsonObject) {
        val path = project.resolve("source_tree_manifest.json")
        path.writeText(update(json(path)).toString() + "\n")
    }
    private fun writeBoundFile(project: Path, relative: String, text: String) {
        project.resolve(relative).writeText(text)
        val hashes = linkedMapOf(relative to sha256(text.toByteArray()))
        if (relative.startsWith("reports/modules/") && relative.endsWith(".json")) {
            val id = relative.substringAfterLast('/').removeSuffix(".json")
            val path = project.resolve("reports/confidence.json")
            val confidence = json(path)
            val modules = confidence.getValue("modules").jsonArray.map { value ->
                val module = value.jsonObject
                if (module.getValue("id").jsonPrimitive.content != id) module else JsonObject(module +
                    ("revisionEvidence" to JsonObject(module.getValue("revisionEvidence").jsonObject +
                        ("checkpointSha256" to JsonPrimitive(hashes.getValue(relative))))))
            }
            val updated = JsonObject(confidence + ("modules" to JsonArray(modules))).toString()
            path.writeText(updated)
            hashes["reports/confidence.json"] = sha256(updated.toByteArray())
        }
        rewriteManifest(project) { document -> JsonObject(document + ("files" to JsonArray(
            document.getValue("files").jsonArray.map { value ->
                val file = value.jsonObject
                hashes[file.getValue("path").jsonPrimitive.content]?.let { JsonObject(file + ("sha256" to JsonPrimitive(it))) } ?: file
            },
        ))) }
    }
    private fun fixture(block: (Path) -> Unit) {
        val root = Files.createTempDirectory(Path.of("build", "generated-c-carrier-tests").createDirectories(), "case-").toAbsolutePath()
        try { block(root) } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) }
        }
    }
    private companion object {
        val BASE_PROFILES = listOf(GeneratedCMakeReconstructionProfile.descriptor, GeneratedCNinjaReconstructionProfile.descriptor)
        val OWNERS = mapOf("fn_main" to "entry", "fn_worker" to "worker", "global_pointer" to "entry", "global_byte" to "worker")
    }
}
