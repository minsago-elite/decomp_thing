package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.nio.channels.FileChannel
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Opt-in real-engine CLI equivalence, not authored-profile or whole-resource qualification. */
class GccBundledCliQualificationTest {
    @Test fun `cc1 normal CLI fresh and same-owner resume produce identical model and plan`() = qualify("cc1")
    @Test fun `lto1 normal CLI fresh and same-owner resume produce identical model and plan`() = qualify("lto1")

    private fun qualify(engine: String) {
        assumeTrue(System.getenv("DECOMP_REQUIRE_GCC_ENGINE_CLI") == "true", "real-engine CLI qualification is opt-in")
        fun configured(name: String): Path {
            val path = Path.of(requireNotNull(System.getenv(name)) { "required qualification input is missing: $name" })
            require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path) { "$name must be canonical" }
            return path
        }
        val profile = configured("DECOMP_GCC_CLI_PROFILE")
        val archive = configured("DECOMP_GCC_CLI_ARCHIVE")
        val binary = configured("DECOMP_GCC_CLI_${engine.uppercase()}_BINARY")
        val allMounts = listOf("CC1", "LTO1").flatMap { name ->
            listOf("FRESH", "RESUME").map { mode -> configured("DECOMP_GCC_CLI_${name}_${mode}_SCRATCH") }
        }
        require(allMounts.toSet().size == 4 && allMounts.indices.all { i -> allMounts.indices.all { j ->
            i == j || !allMounts[i].startsWith(allMounts[j])
        } }) { "qualification requires four disjoint scratch mounts" }
        val freshScratch = configured("DECOMP_GCC_CLI_${engine.uppercase()}_FRESH_SCRATCH")
        val resumedScratch = configured("DECOMP_GCC_CLI_${engine.uppercase()}_RESUME_SCRATCH")
        require(freshScratch != resumedScratch)
        listOf(freshScratch, resumedScratch).forEach { mount -> Files.list(mount).use { require(it.findAny().isEmpty) } }
        val evidenceRoot = configured("DECOMP_GCC_CLI_EVIDENCE_ROOT")
        require(Files.getPosixFilePermissions(evidenceRoot) == PosixFilePermissions.fromString("rwx------"))
        require((allMounts + listOf(binary, profile, archive)).none { it.startsWith(evidenceRoot) || evidenceRoot.startsWith(it) })
        val destination = Files.createTempDirectory(evidenceRoot, "$engine-")
        println("Real-engine CLI qualification evidence retained at $destination")
        val outputs = listOf(freshScratch, resumedScratch).mapIndexed { index, scratch ->
            val output = Files.createDirectory(destination.resolve(if (index == 0) "fresh" else "resumed"), PRIVATE_DIRECTORY)
            val arguments = listOf(engine, binary.toString(), "--profile", profile.toString(), "--ghidra-archive", archive.toString(),
                "--output", output.toString(), "--scratch", scratch.toString()) +
                if (index == 0) emptyList() else listOf("--resume-after-checkpoint", "512")
            // Invoke the normal CLI entry point with production inputs; no authored intent or analyzer seam.
            decompengine.main((listOf("gcc-engine-plan") + arguments).toTypedArray())
            retainAndCheck(output, scratch, profile, arguments, resumed = index != 0)
        }
        assertEquals(-1L, Files.mismatch(outputs[0].first, outputs[1].first), "fresh/resumed model bytes differ")
        assertEquals(-1L, Files.mismatch(outputs[0].second, outputs[1].second), "fresh/resumed planner bytes differ")
        publish(destination.resolve("comparison.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-real-engine-cli-comparison-v1"), "engine" to JsonPrimitive(engine),
            "modelByteIdentical" to JsonPrimitive(true), "planByteIdentical" to JsonPrimitive(true),
            "benchmarkAccepted" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "entryPoint" to JsonPrimitive("decompengine.MainKt.main in the Gradle test JVM"),
            "testJvmMaximumHeapBytes" to JsonPrimitive(Runtime.getRuntime().maxMemory()),
            "limitation" to JsonPrimitive("does not qualify installed launcher, cold recovery, or whole-operation resource accounting"),
        ))))
    }

    private fun retainAndCheck(output: Path, scratch: Path, profile: Path, arguments: List<String>, resumed: Boolean): Pair<Path, Path> {
        val result = OracleJson.parseCanonical(read(output.resolve("result.json"), 256 * 1024)).jsonObject
        fun text(name: String) = result.getValue(name).jsonPrimitive.content
        assertEquals(JsonPrimitive(false), result.getValue("complete"))
        assertEquals(JsonPrimitive(false), result.getValue("releaseEligible"))
        val journal = Path.of(text("journal"))
        assertEquals(output.resolve("journal"), journal.parent)
        assertEquals(".gcc-bundled-operation-${text("operationId")}", journal.fileName.toString())
        val base = if (resumed) listOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json", "attachment.json",
            "start-authorized.json", "interrupt-authorized.json", "interrupted-execution.json", "interrupted-prefix-assessment.json",
            "analysis-state-manifest.json", "analysis-state-captured.json", "resume-definition.json", "resume-prepared.json",
            "resume-attachment.json", "resume-start-authorized.json", "resume-execution.json", "resume-export-assessment.json")
        else listOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json", "attachment.json", "start-authorized.json",
            "execution.json", "export-assessment.json")
        val expected = base + listOf("planner-request.json", "planner-prepared.json", "planner-attachment.json",
            "planner-start-authorized.json", "planner-execution.json", "planner-assessment.json")
        Files.list(journal).use { assertEquals(expected.toSet(), it.map { path -> path.fileName.toString() }.toList().toSet()) }
        var aggregate = 0L
        val records = expected.associateWith { name ->
            val bytes = read(journal.resolve(name), if (name == "analysis-state-manifest.json") 64 * 1024 * 1024 else 1024 * 1024)
            aggregate += bytes.size
            require(aggregate <= 128L * 1024 * 1024)
            bytes
        }
        val hashes = records.mapValues { OracleArtifacts.sha256(it.value) }
        assertEquals(hashes.getValue("intent.json"), text("requestSha256"))
        val intent = OracleJson.parseCanonical(records.getValue("intent.json")).jsonObject
        assertEquals(JsonPrimitive(arguments.first()), intent.getValue("engineId"))
        val invocationBytes = read(output.resolve("invocation.json"), 256 * 1024)
        assertEquals(OracleJson.parseCanonical(invocationBytes), intent.getValue("cliInvocation"))
        assertEquals(JsonArray((listOf("gcc-engine-plan") + arguments).map(::JsonPrimitive)), intent.getValue("cliInvocation").jsonObject.getValue("argv"))
        GccRetainedCompilerEngineProfile.open(profile).use { retained ->
            assertEquals(OracleJson.parseCanonical(retained.policyBytes()), intent.getValue("plannerProfile"))
        }
        records.filterKeys { it != "analysis-state-manifest.json" }.forEach { (_, bytes) ->
            val record = OracleJson.parseCanonical(bytes).jsonObject
            record["recordSha256"]?.let { digest ->
                assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256")))), digest)
                assertEquals(JsonPrimitive(text("requestSha256")), record.getValue("intentSha256"))
                assertEquals(JsonPrimitive(text("operationId")), record.getValue("operationId"))
                assertTrue(record.getValue("previousSha256").jsonPrimitive.content in hashes.values)
                assertEquals(JsonPrimitive(false), record.getValue("complete"))
                assertEquals(JsonPrimitive(false), record.getValue("releaseEligible"))
            }
        }
        val exportedName = if (resumed) "resume-export-assessment.json" else "export-assessment.json"
        val chain = listOf("prepared.json", "attachment.json", "start-authorized.json") +
            (if (resumed) listOf("interrupt-authorized.json", "interrupted-execution.json", "interrupted-prefix-assessment.json",
                "analysis-state-captured.json", "resume-prepared.json", "resume-attachment.json", "resume-start-authorized.json",
                "resume-execution.json", "resume-export-assessment.json") else listOf("execution.json", "export-assessment.json")) +
            listOf("planner-prepared.json", "planner-attachment.json", "planner-start-authorized.json", "planner-execution.json", "planner-assessment.json")
        chain.zipWithNext().forEach { (previous, current) ->
            assertEquals(JsonPrimitive(hashes.getValue(previous)), OracleJson.parseCanonical(records.getValue(current)).jsonObject.getValue("previousSha256"))
        }
        assertEquals(hashes.getValue(exportedName), text("exportReceiptSha256"))
        assertEquals(hashes.getValue("planner-execution.json"), text("plannerExecutionReceiptSha256"))
        assertEquals(hashes.getValue("planner-assessment.json"), text("plannerAssessmentReceiptSha256"))
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(records.getValue("definition.json"))
        assertEquals(scratch, definition.outputLease.path.parent.parent)
        val request = GccBundledPlannerRequest.parse(records.getValue("planner-request.json"))
        assertEquals(text("requestSha256"), request.operationRequestSha256)
        assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(intent.getValue("plannerProfile"))), request.profilePolicySha256)
        val exported = OracleJson.parseCanonical(records.getValue(exportedName)).jsonObject.getValue("assessment").jsonObject
        assertEquals(JsonPrimitive(request.modelSha256), exported.getValue("programModelSha256"))
        assertEquals(JsonPrimitive(request.functionCount), exported.getValue("functionCount"))
        if (resumed) {
            val prefix = OracleJson.parseCanonical(records.getValue("interrupted-prefix-assessment.json")).jsonObject.getValue("assessment").jsonObject
            assertTrue(prefix.getValue("completed").jsonPrimitive.content.toLong() >= 512)
            assertEquals(prefix.getValue("completed"), exported.getValue("reused"))
        } else assertEquals(JsonPrimitive(0), exported.getValue("reused"))
        assertEquals(definition.outputLease.path.resolve("reports/program_model.json"), request.modelPath)
        assertEquals(definition.outputLease.path.resolve(gccBundledPlannerControlName(text("requestSha256"), hashes.getValue(exportedName))).resolve("reports"), request.outputDirectory)
        assertEquals(request.modelPath.toString(), text("programModel"))
        assertEquals(request.outputDirectory.resolve("module_plan.json").toString(), text("modulePlan"))
        val model = read(request.modelPath, request.modelBytes)
        val plan = read(request.outputDirectory.resolve("module_plan.json"), request.maximumPlanBytes)
        val workerMetadata = read(request.outputDirectory.resolve("planner-output.json"), 256 * 1024)
        val assessed = GccBundledPlannerOutputAssessment.assess(request, model, plan, workerMetadata)
        assertContentEquals(plan, assessed.planBytes)
        assertEquals(OracleArtifacts.sha256(model), text("programModelSha256"))
        assertEquals(OracleArtifacts.sha256(plan), text("modulePlanSha256"))
        val execution = OracleJson.parseCanonical(records.getValue("planner-execution.json")).jsonObject.getValue("execution").jsonObject
        for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) assertEquals(JsonPrimitive(true), execution.getValue(field))
        val start = result.getValue("operationWallTime").jsonObject.getValue("startedMonotonicNanos")
        for (name in chain.filter { it.endsWith("execution.json") }) {
            val run = OracleJson.parseCanonical(records.getValue(name)).jsonObject.getValue("execution").jsonObject
            assertEquals(start, run.getValue("operationWallTime").jsonObject.getValue("startedMonotonicNanos"))
            for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) assertEquals(JsonPrimitive(true), run.getValue(field))
        }
        val modelCopy = output.resolve("captured-program-model.json")
        val planCopy = output.resolve("captured-module-plan.json")
        publish(modelCopy, model)
        publish(planCopy, plan)
        publish(output.resolve("captured-planner-output.json"), workerMetadata)
        return modelCopy to planCopy
    }

    private fun read(path: Path, maximum: Int): ByteArray = StableControlFile.open(path, maximum.toLong(), "CLI qualification evidence").use { guard ->
        guard.readExactly(0, guard.size.toInt(), "CLI qualification evidence").also { guard.verifyUnchanged("after qualification capture") }
    }
    private fun publish(path: Path, bytes: ByteArray) {
        Files.write(path, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
        FileChannel.open(path.parent, StandardOpenOption.READ).use { it.force(true) }
    }
    private companion object {
        val PRIVATE_DIRECTORY = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    }
}
