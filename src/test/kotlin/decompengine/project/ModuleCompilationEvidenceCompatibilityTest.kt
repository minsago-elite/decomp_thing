package decompengine.project

import decompengine.agent.AgentStopReason
import decompengine.agent.AgentWorkflowPhase
import decompengine.agent.AgentWorkflowProgress
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.NoSuchFileException
import java.util.zip.ZipInputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Retained local compiler fixtures are historical provenance, not fresh acceptance authority. */
class ModuleCompilationEvidenceCompatibilityTest {
    @Test
    fun `historical six field compiler records round trip without acquiring current authority`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val checkpoint = historicalCheckpoint(profile)
            assertEquals(JsonPrimitive(6), checkpoint.getValue("schemaVersion"))
            val original = checkpoint.getValue("compilation").jsonObject
            val sourceSha256 = checkpoint.getValue("sourceSha256").jsonPrimitive.content
            val decoded = ModuleCompilationEvidence.decode(original, 6, profile, SOURCE_PATH, sourceSha256, accepted = true)
            assertTrue(decoded.passed)
            assertEquals(original.toString(), decoded.toJson())
            assertEquals(HISTORICAL_FIELDS, Json.parseToJsonElement(decoded.toJson()).jsonObject.keys)
            assertEquals("historical-local-host", decoded.recordedAssurance)
            assertNull(decoded.containedProof)
            assertNull(decoded.liveAuthority)
            assertFalse(decoded.authorizesAcceptance(sourceSha256, profile.sha256,
                ReconstructionCompilationPolicies.resolve(profile).id))
        }
    }

    @Test
    fun `historical checkpoint cannot gain contained proof by adding fields`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val checkpoint = historicalCheckpoint(profile)
            val local = checkpoint.getValue("compilation").jsonObject
            val forged = JsonObject(local + ("containedProof" to JsonObject(emptyMap())))
            val failure = assertFailsWith<IllegalArgumentException> {
                ModuleCompilationEvidence.decode(forged, 6, profile, SOURCE_PATH,
                    checkpoint.getValue("sourceSha256").jsonPrimitive.content, accepted = true)
            }
            assertEquals("module compiler evidence has unsupported fields", failure.message)
        }
    }

    @Test
    fun `current accepted checkpoint requires contained proof even with current exact command`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val checkpoint = historicalCheckpoint(profile)
            val local = checkpoint.getValue("compilation").jsonObject
            val currentCommand = ReconstructionCompilationPolicies.resolve(profile).command(profile, SOURCE_PATH)
            val relabeled = JsonObject(local + ("command" to JsonArray(currentCommand.map(::JsonPrimitive))))
            val failure = assertFailsWith<IllegalArgumentException> {
                ModuleCompilationEvidence.decode(relabeled, 7, profile, SOURCE_PATH,
                    checkpoint.getValue("sourceSha256").jsonPrimitive.content, accepted = true)
            }
            assertEquals("current accepted module lacks contained compiler proof", failure.message)
        }
    }

    @Test
    fun `compiler command matching selects the checkpoint version and binds exact source path`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val checkpoint = historicalCheckpoint(profile)
            val local = checkpoint.getValue("compilation").jsonObject
            val sourceSha256 = checkpoint.getValue("sourceSha256").jsonPrimitive.content
            val policy = ReconstructionCompilationPolicies.resolve(profile)
            val historicalCommand = policy.commandForCheckpoint(profile, SOURCE_PATH, 6)
            val currentCommand = policy.commandForCheckpoint(profile, SOURCE_PATH, 7)
            assertTrue(historicalCommand != currentCommand)
            assertEquals(JsonArray(historicalCommand.map(::JsonPrimitive)), local.getValue("command"))
            for ((version, wrongCommand) in listOf(6 to currentCommand, 7 to historicalCommand)) {
                val changed = JsonObject(local + ("command" to JsonArray(wrongCommand.map(::JsonPrimitive))))
                val failure = assertFailsWith<IllegalArgumentException> {
                    ModuleCompilationEvidence.decode(changed, version, profile, SOURCE_PATH, sourceSha256, accepted = false)
                }
                assertEquals("module compiler command differs from its reconstruction profile", failure.message)
            }
            assertFailsWith<IllegalArgumentException> {
                ModuleCompilationEvidence.decode(local, 6, profile, "src/modules/other.c", sourceSha256, accepted = true)
            }
            assertFailsWith<IllegalArgumentException> {
                ModuleCompilationEvidence.decode(local, 6, profile, SOURCE_PATH, "0".repeat(64), accepted = true)
            }
        }
    }

    @Test
    fun `historical accepted archives expose local assurance without changing retained compiler facts`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "module-compiler-history-")
        try {
            for (profile in ReconstructionProfiles.builtIn) {
                val archive = temp.resolve("${profile.id}.zip")
                Files.write(archive, fixtureBytes(profile))
                val project = temp.resolve(profile.id)
                ArchivalBundleVerifier.extractAndVerify(archive, project, profile = profile)
                val audit = ArchivalProjectAuditor.audit(project, profile, publish = false)
                assertTrue(audit.moduleCompilationEvidenceProblems.isEmpty())
                val record = audit.moduleCompilationEvidence.getValue("parse")
                assertEquals(JsonPrimitive("historical-local-host"), record.getValue("recordedAssurance"))
                assertEquals(historicalCheckpoint(profile).getValue("compilation"), record.getValue("compilation"))
            }
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    @Test
    fun `historical v4 prompt compiler command replays pinned schema six commitments`() {
        for (profile in ReconstructionProfiles.builtIn) withHistoricalProject(profile) { project ->
            val model = ProgramModelJson.read(Files.readString(project.resolve(
                profile.layout.declaration("program-model-evidence").materialize())))
            val plan = ModulePlanJson.readCanonical(Files.readAllBytes(project.resolve(
                profile.layout.declaration("module-plan-evidence").materialize())), 4 * 1024 * 1024)
            val request = ProfileModulePromptInputs(model, plan, profile).request("parse", project, null)
            val historical = modulePromptEvidence(request.copy(compilationCheckpointVersion = 6)).text
            val current = modulePromptEvidence(request).text
            assertEquals(historicalCheckpoint(profile).getValue("promptSha256"),
                JsonPrimitive(sha256(historical.toByteArray())))
            assertNotEquals(historical, current)
            assertTrue(GeneratedCModuleValidation.command(profile, SOURCE_PATH).joinToString(" ") in historical)
            assertTrue(ContainedModuleCompilationPolicy.command(profile, SOURCE_PATH).joinToString(" ") in current)
        }
    }

    @Test
    fun `validation read failure restores historical accepted source checkpoint and ACP receipt`() {
        for (profile in ReconstructionProfiles.builtIn) verifyHistoricalRestoration(profile, cancelled = false)
    }

    @Test
    fun `validation cancellation restores historical accepted bytes without upgrading their authority`() {
        for (profile in ReconstructionProfiles.builtIn) verifyHistoricalRestoration(profile, cancelled = true)
    }

    private fun verifyHistoricalRestoration(profile: ReconstructionProfile, cancelled: Boolean) {
        withHistoricalProject(profile) { project ->
            val modelPath = profile.layout.declaration("program-model-evidence").materialize()
            val planPath = profile.layout.declaration("module-plan-evidence").materialize()
            val model = ProgramModelJson.read(Files.readString(project.resolve(modelPath)))
            val plan = ModulePlanJson.readCanonical(Files.readAllBytes(project.resolve(planPath)), 4 * 1024 * 1024)
            val module = plan.modules.single()
            assertEquals("parse", module.id)
            val checkpointPath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to module.id))
            val checkpoint = Json.parseToJsonElement(Files.readString(project.resolve(checkpointPath))).jsonObject
            val receiptPath = checkpoint.getValue("executionEvidencePath").jsonPrimitive.content
            val preserved = listOf(module.sourcePath, checkpointPath, receiptPath, "source_tree_manifest.json")
                .associateWith { Files.readAllBytes(project.resolve(it)) }
            val originalSource = preserved.getValue(module.sourcePath).decodeToString()
            val candidateSource = originalSource.replace("return 17;", "return 18;")
            assertNotEquals(originalSource, candidateSource)
            val originalSha256 = sha256(preserved.getValue(module.sourcePath))
            var calls = 0
            var validationReached = false
            var rollbackReached = false
            val reconstructor = ModuleReconstructor { request ->
                calls++
                assertEquals(module.id, request.module.id)
                assertEquals(originalSha256, request.acceptedSourceSha256)
                ReconstructedModule(candidateSource, "historical-restoration-fixture",
                    checkpoint.getValue("promptSha256").jsonPrimitive.content)
            }
            assertFalse(reconstructor.requiresExecutionEvidenceForCheckpointReuse())
            val source = project.resolve(module.sourcePath)
            val progress = object : AgentWorkflowProgress by AgentWorkflowProgress.NONE {
                override fun phase(phase: AgentWorkflowPhase, taskId: String?, acceptedRevisionSha256: String?) {
                    when (phase) {
                        AgentWorkflowPhase.BUILD_VALIDATING -> {
                            validationReached = true
                            assertEquals(candidateSource, Files.readString(source))
                            if (cancelled) throw InterruptedException("historical validation boundary cancellation")
                            Files.delete(source)
                            // Exercise the actual written-source read failure before runtime loading.
                            Files.readAllBytes(source)
                        }
                        AgentWorkflowPhase.ROLLED_BACK -> {
                            rollbackReached = true
                            assertEquals(originalSha256, acceptedRevisionSha256)
                        }
                        else -> Unit
                    }
                }
            }
            if (cancelled) {
                try {
                    val failure = assertFailsWith<ModuleReconstructionInterruptedException> {
                        SourceTreeGenerator.generate(model, project, profile = profile,
                            reconstructor = reconstructor, progress = progress)
                    }
                    assertEquals(AgentStopReason.CANCELLED, failure.stopReason)
                    assertTrue(failure.cause is InterruptedException)
                    assertTrue(Thread.currentThread().isInterrupted)
                } finally {
                    Thread.interrupted()
                }
            } else {
                val failure = assertFailsWith<NoSuchFileException> {
                    SourceTreeGenerator.generate(model, project, profile = profile,
                        reconstructor = reconstructor, progress = progress)
                }
                assertEquals(source.toString(), failure.file)
                assertFalse(Thread.currentThread().isInterrupted)
            }
            assertEquals(1, calls)
            assertTrue(validationReached)
            assertTrue(rollbackReached)
            preserved.forEach { (path, bytes) ->
                assertTrue(bytes.contentEquals(Files.readAllBytes(project.resolve(path))), path)
            }
            val restored = Json.parseToJsonElement(Files.readString(project.resolve(checkpointPath))).jsonObject
            assertEquals(JsonPrimitive(6), restored.getValue("schemaVersion"))
            val compilation = ModuleCompilationEvidence.decode(restored.getValue("compilation").jsonObject,
                6, profile, module.sourcePath, originalSha256, accepted = true)
            assertEquals("historical-local-host", compilation.recordedAssurance)
            assertNull(compilation.liveAuthority)
            assertFalse(compilation.authorizesAcceptance(originalSha256, profile.sha256,
                ReconstructionCompilationPolicies.resolve(profile).id))
            val attempt = Json.parseToJsonElement(Files.readString(
                project.resolve("reports/modules/${module.id}.attempt.json"))).jsonObject
            assertEquals(JsonPrimitive(if (cancelled) "interrupted" else "validation-failed"), attempt.getValue("status"))
            assertEquals(JsonPrimitive(originalSha256), attempt.getValue("previousAcceptedSourceSha256"))
            assertEquals(JsonNull, attempt.getValue("executionEvidencePath"))
            assertFalse("compilation" in attempt)
            if (!cancelled) {
                assertEquals(JsonPrimitive("module-compilation-failure"), attempt.getValue("kind"))
                assertEquals(JsonPrimitive(sha256(candidateSource.toByteArray())), attempt.getValue("candidateSourceSha256"))
                assertEquals(JsonPrimitive(NoSuchFileException::class.java.name), attempt.getValue("failureType"))
            }
        }
    }

    private fun withHistoricalProject(profile: ReconstructionProfile, action: (Path) -> Unit) {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val temp = Files.createTempDirectory(scratch, "module-compiler-restoration-")
        try {
            val archive = temp.resolve("${profile.id}.zip")
            Files.write(archive, fixtureBytes(profile))
            val project = temp.resolve("project")
            ArchivalBundleVerifier.extractAndVerify(archive, project, profile = profile)
            action(project)
        } finally {
            Files.walk(temp).use { paths ->
                paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
            }
        }
    }

    private fun historicalCheckpoint(profile: ReconstructionProfile): JsonObject {
        ZipInputStream(fixtureBytes(profile).inputStream()).use { archive ->
            while (true) {
                val entry = archive.nextEntry ?: error("historical module checkpoint is missing")
                if (entry.name == "reports/modules/parse.json") {
                    return Json.parseToJsonElement(archive.readBytes().decodeToString()).jsonObject
                }
            }
        }
    }

    private fun fixtureBytes(profile: ReconstructionProfile): ByteArray = requireNotNull(javaClass.getResourceAsStream(
        "/project/historical-module-local-v6/${profile.id}.zip")) { "historical module fixture is missing" }.use { it.readBytes() }

    private companion object {
        const val SOURCE_PATH = "src/modules/parse.c"
        val HISTORICAL_FIELDS = setOf("sourceSha256", "command", "outcome", "returnCode", "diagnosticsSha256", "diagnosticsBytes")
    }
}
