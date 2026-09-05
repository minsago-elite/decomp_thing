package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.DeterministicModulePlanner
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.ProjectLayoutProfile
import decompengine.project.ProjectFileDeclaration
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledPlannerWorkerTest {
    @Test
    fun `worker JVM derives deterministic ownership from a retained profile request`() = fixture { root ->
        val profilePath = Path.of(System.getProperty("user.dir")).resolve("oracle/gcc/16.2.0/compiler-engines.json")
        GccRetainedCompilerEngineProfile.open(profilePath).use { profile ->
            val model = model(profile.suite.engine("cc1").strippedArtifact.sha256)
            val bytes = model.toJson().toByteArray()
            val modelPath = root.resolve("program_model.json")
            Files.write(modelPath, bytes)
            val output = Files.createDirectory(root.resolve("output"))
            // Synthetic assessments test worker computation, not authenticated export/containment.
            val assessment = GccCompletedRunAssessment("non-authoritative-byte-assessment", SHA, SHA, bytes.size,
                OracleArtifacts.sha256(bytes), 2, 1, SHA, 1, SHA, SHA, 2, 0, 0)
            val exported = GccBundledExecutedOperation("{}".toByteArray(), "{}".toByteArray(),
                GccBundledExportAssessment(assessment, "{}".toByteArray(), bytes))
            val request = GccBundledPlannerRequest.fromProfile(profile, "cc1", exported, SHA, modelPath, output)
            val requestPath = root.resolve("request.json")
            Files.write(requestPath, request.canonicalBytes)
            assertContentEquals(request.canonicalBytes, GccBundledPlannerRequest.parse(request.canonicalBytes).canonicalBytes)
            val bootRoot = Path.of(checkNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot")))
            val classpath = GccKotlinBootClasspathReference.open().use { reference ->
                reference.entries.joinToString(File.pathSeparator) { bootRoot.resolve(it.logicalName).toString() }
            }
            val log = root.resolve("worker.log")
            val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx256m",
                "-XX:+DisableAttachMechanism", "-cp", classpath, GccBundledPlannerWorker::class.java.name,
                requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes))
                .redirectErrorStream(true).redirectOutput(log.toFile()).start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS))
                assertEquals(0, process.exitValue(), Files.readString(log).take(4096))
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            }
            val expected = DeterministicModulePlanner(maximumFunctionsPerModule = request.maximumFunctionsPerModule,
                layout = request.layout, maximumEntities = request.maximumEntities,
                maximumDependencyEdges = request.maximumDependencyEdges, maximumWorkUnits = request.maximumWorkUnits).plan(model)
            val plan = Files.readAllBytes(output.resolve("module_plan.json"))
            assertContentEquals(expected.toJson().toByteArray(), plan)
            val metadata = OracleJson.parseCanonical(Files.readAllBytes(output.resolve("planner-output.json"))).jsonObject
            assertEquals(OracleArtifacts.sha256(profile.policyBytes()), metadata.getValue("profilePolicySha256").jsonPrimitive.content)
            assertEquals(OracleArtifacts.sha256(plan), metadata.getValue("planSha256").jsonPrimitive.content)
            assertEquals("false", metadata.getValue("complete").jsonPrimitive.content)
            assertEquals("false", metadata.getValue("releaseEligible").jsonPrimitive.content)
            assertFails { GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes))) }
            assertContentEquals(plan, Files.readAllBytes(output.resolve("module_plan.json")))
        }
    }

    @Test
    fun `worker rejects wrong bindings and exceeded limits before publishing a plan`() = fixture { root ->
        val bytes = model(SHA).toJson().toByteArray()
        val path = root.resolve("model.json")
        Files.write(path, bytes)
        val output = Files.createDirectory(root.resolve("output"))
        fun request(modelSha: String = OracleArtifacts.sha256(bytes), inputSha: String = SHA, count: Long = 2,
            work: Long = 10000, planBound: Int = 1024 * 1024) = GccBundledPlannerRequest(path, output, bytes.size,
            modelSha, inputSha, count, SHA, SHA, GeneratedCMakeReconstructionProfile.descriptor.layout,
            24, 100, 1000, work, planBound)
        val requestPath = root.resolve("request.json")
        for (invalid in listOf(request(modelSha = "b".repeat(64)), request(inputSha = "b".repeat(64)),
            request(count = 3), request(work = 1), request(planBound = 1))) {
            Files.write(requestPath, invalid.canonicalBytes)
            assertFails { GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(invalid.canonicalBytes))) }
            assertFalse(Files.exists(output.resolve("module_plan.json")))
        }
        val valid = request()
        Files.write(requestPath, valid.canonicalBytes)
        assertFails { GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), "b".repeat(64))) }
        val unknown = OracleJson.parseCanonical(valid.canonicalBytes).jsonObject + ("unexpected" to JsonPrimitive(1))
        assertFails { GccBundledPlannerRequest.parse(OracleJson.canonicalBytes(JsonObject(unknown))) }
        Files.move(path, root.resolve("original-model.json"))
        Files.createSymbolicLink(path, root.resolve("original-model.json"))
        assertFails { GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(valid.canonicalBytes))) }
        assertFalse(Files.exists(output.resolve("module_plan.json")))
    }

    @Test
    fun `worker preserves declared layouts and does not overwrite partial output records`() = fixture { root ->
        val model = model(SHA)
        val bytes = model.toJson().toByteArray()
        val path = root.resolve("model.json")
        Files.write(path, bytes)
        val output = Files.createDirectory(root.resolve("output"))
        val layout = ProjectLayoutProfile(1, GeneratedCMakeReconstructionProfile.descriptor.layout.declarations.map {
            ProjectFileDeclaration(it.id, "alternate/${it.pathTemplate}", it.roles, it.contentKind)
        })
        val request = GccBundledPlannerRequest(path, output, bytes.size, OracleArtifacts.sha256(bytes), SHA, 2,
            SHA, SHA, layout, 24, 100, 1000, 10000)
        val parsed = GccBundledPlannerRequest.parse(request.canonicalBytes)
        assertEquals(layout.canonicalJson(), parsed.layout.canonicalJson())
        val requestPath = root.resolve("request.json")
        Files.write(requestPath, request.canonicalBytes)
        val prior = "prior incomplete invocation".toByteArray()
        Files.write(output.resolve("planner-output.json"), prior)
        assertFails { GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes))) }
        assertContentEquals(prior, Files.readAllBytes(output.resolve("planner-output.json")))
        val plan = Files.readAllBytes(output.resolve("module_plan.json"))
        assertContentEquals(DeterministicModulePlanner(layout = layout).plan(model).toJson().toByteArray(), plan)
        assertTrue(plan.decodeToString().contains("alternate/"))
        assertFails { GccBundledPlannerWorker.main(arrayOf(requestPath.toString(), OracleArtifacts.sha256(request.canonicalBytes))) }
        assertContentEquals(plan, Files.readAllBytes(output.resolve("module_plan.json")))
    }

    private fun model(sha: String) = RecoveredProgramModel(inputSha256 = sha, functions = listOf(
        RecoveredFunction("entry", "api_entry", 1UL, "int entry(void)", calls = setOf("helper"), referencedGlobals = setOf("global")),
        RecoveredFunction("helper", "api_helper", 2UL, "int helper(void)"),
    ), globals = listOf(RecoveredGlobal("global", "value", 3UL, "int")),
        types = listOf(RecoveredType("type", "typedef int value_t;", 1UL)))

    private fun fixture(action: (Path) -> Unit) {
        val root = Files.createTempDirectory("gcc-planner-worker-")
        try { action(root) } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private companion object { const val SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" }
}
