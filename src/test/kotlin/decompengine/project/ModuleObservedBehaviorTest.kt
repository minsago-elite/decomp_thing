package decompengine.project

import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateObservation
import decompengine.exploration.CandidateSource
import decompengine.exploration.ConfidenceScore
import decompengine.exploration.CoverageReport
import decompengine.exploration.ExplorationReport
import decompengine.exploration.ModuleObservationAttributor
import decompengine.exploration.writeModuleObservations
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

class ModuleObservedBehaviorTest {
    private val inputSha256 = "1".repeat(64)
    private val traceSha256 = "2".repeat(64)
    private val model = RecoveredProgramModel(inputSha256 = inputSha256, functions = listOf(
        RecoveredFunction("owned", "owned", 1uL, "void owned(void)"),
        RecoveredFunction("other", "other", 2uL, "void other(void)"),
    ))
    private val module = PlannedModule("module", "src/module.c", "include/module.h", listOf("owned"),
        emptyList(), boundaryEvidence = emptyList())

    @Test
    fun `producer file handoff selects module cases and excludes unrelated behavior from identity`() {
        val root = directory()
        root.resolve("exploration.json").writeText("legacy-secret-payload")
        ModuleObservedBehavior.write(root, inputSha256, listOf(case("owned-case", "owned", "selected"),
            case("unrelated-case", "other", "unrelated-secret")))
        // Corpus size is independent of the complete selected prompt budget, enforced by dispatch.
        val observed = ReconstructionExplorationInput.read(root, maximumCharacters = 16)
        val selected = selectModuleObservedBehavior(observed, module, model)
        assertTrue("selected" in selected)
        assertTrue("Non-authoritative" in selected && "not an authenticated oracle" in selected)
        assertFalse("unrelated-secret" in selected || "unrelated-case" in selected || "legacy-secret" in selected)
        val fingerprint = sha256(selected.toByteArray())

        ModuleObservedBehavior.write(root, inputSha256, listOf(case("owned-case", "owned", "selected"),
            case("different-other-case", "other", "different-unrelated-secret")))
        assertEquals(fingerprint, sha256(selectModuleObservedBehavior(
            ReconstructionExplorationInput.read(root, 16), module, model).toByteArray()))
        ModuleObservedBehavior.write(root, inputSha256, listOf(case("owned-case", "owned", "changed")))
        assertFalse(fingerprint == sha256(selectModuleObservedBehavior(
            ReconstructionExplorationInput.read(root, 16), module, model).toByteArray()))
    }

    @Test
    fun `retained exploration report producer joins inputs outputs and explicit trace attribution before reader selection`() {
        val root = directory()
        val candidates = listOf(CandidateInput("traced", CandidateSource.SEED, listOf("real-argument"), byteArrayOf(0x41)),
            CandidateInput("unscoped", CandidateSource.SEED, listOf("never-guess-this")))
        val observations = listOf(
            CandidateObservation("traced", "7:42:43", 7, "42", "43", true),
            CandidateObservation("unscoped", "0::", 0, "", "", true),
        )
        val report = ExplorationReport(candidates, CoverageReport(2, 2, emptySet(), emptySet(), observations),
            ConfidenceScore(0.0, 2, 1, 2, true), root.resolve("exploration.json"))
        val attributionCalls = mutableListOf<String>()
        report.writeModuleObservations(inputSha256, ModuleObservationAttributor { hash, input, observation ->
            assertEquals(inputSha256, hash)
            assertEquals(input.id, observation.candidateId)
            attributionCalls += input.id
            if (input.id == "traced") ModuleObservationAttribution(listOf("owned"), traceSha256) else null
        })
        val selected = selectModuleObservedBehavior(ReconstructionExplorationInput.read(root, 10000), module, model)
        val selectedCase = Json.parseToJsonElement(selected.substringAfter('\n')).jsonObject
            .getValue("cases").jsonArray.single().jsonObject
        assertEquals(listOf("traced", "unscoped"), attributionCalls)
        assertEquals(JsonArray(listOf(JsonPrimitive("real-argument"))), selectedCase.getValue("input").jsonObject.getValue("args"))
        assertEquals(JsonPrimitive("41"), selectedCase.getValue("input").jsonObject.getValue("stdinHex"))
        assertEquals(JsonObject(mapOf("exitCode" to JsonPrimitive(7), "stdoutHex" to JsonPrimitive("42"),
            "stderrHex" to JsonPrimitive("43"))), selectedCase.getValue("observed"))
        assertTrue(traceSha256 in selected && "observed-function-entry-trace" in selected)
        assertFalse("unscoped" in selected || "never-guess-this" in selected)
    }

    @Test
    fun `legacy opaque and absent evidence never invent attribution or expose global payload`() {
        val root = directory()
        val opaque = "{\"observations\":[{\"stdoutHex\":\"secret-global-output\"}]}"
        root.resolve("exploration.json").writeText(opaque)
        val selected = selectModuleObservedBehavior(ReconstructionExplorationInput.read(root, 1000), module, model)
        assertTrue("unscoped" in selected)
        assertFalse("secret-global-output" in selected)
        assertEquals(selected, selectModuleObservedBehavior("opaque different global text", module, model))
        assertTrue("unavailable" in selectModuleObservedBehavior(null, module, model))
        assertTrue("no supplied traced case" in selectModuleObservedBehavior(document(listOf(case("other-case", "other"))), module, model))
    }

    @Test
    fun `wrong input and unknown IDs are rejected even for cases outside this module`() {
        val good = document(listOf(case("owned-case", "owned")))
        assertFailsWith<IllegalArgumentException> {
            selectModuleObservedBehavior(good.replace(inputSha256, "3".repeat(64)), module, model)
        }
        assertFailsWith<IllegalArgumentException> {
            selectModuleObservedBehavior(document(listOf(case("owned-case", "owned"), case("unknown-case", "unknown"))), module, model)
        }
        assertFailsWith<IllegalArgumentException> {
            selectModuleObservedBehavior(good, module.copy(functionIds = listOf("unknown")), model)
        }
    }

    @Test
    fun `duplicate malformed unsupported and overlong cases fail closed in preferred file`() {
        val root = directory()
        root.resolve("exploration.json").writeText("legacy fallback must not hide invalid preferred evidence")
        val good = document(listOf(case("owned-case", "owned")))
        val objectValue = Json.parseToJsonElement(good).jsonObject
        val compact = objectValue.toString()
        val oneCase = objectValue.getValue("cases").jsonArray.single()
        val duplicateCases = JsonObject(objectValue + ("cases" to JsonArray(listOf(oneCase, oneCase)))).toString()
        val invalid = listOf(
            duplicateCases,
            compact.replace("\"schemaVersion\":1", "\"schemaVersion\":2"),
            compact.replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
            compact.replace("\"stdinHex\":\"\"", "\"stdinHex\":\"0\""),
            compact.replace("observed-function-entry-trace", "guessed-from-argument"),
            JsonObject(objectValue + ("cases" to JsonArray(List(1025) { oneCase }))).toString(),
            JsonObject(objectValue + ("kind" to JsonPrimitive("not-a-module-envelope"))).toString(),
            compact.replace("\"args\":[]", "\"args\":[\"${"x".repeat(1025)}\"]"),
        )
        invalid.forEachIndexed { index, text ->
            assertFalse(text == compact, "invalid fixture $index must actually mutate the envelope")
            root.resolve(ModuleObservedBehavior.FILE_NAME).writeText(text)
            assertFailsWith<IllegalArgumentException>("invalid fixture $index") { ReconstructionExplorationInput.read(root, 1000000) }
        }
    }

    @Test
    fun `producer snapshots mutable collections and enforces case bounds before writing`() {
        val ids = mutableListOf("owned")
        val args = mutableListOf("initial")
        val attribution = ModuleObservationAttribution(ids, traceSha256)
        val observation = ModuleObservedCase("case", attribution, args, "", 0, "", "")
        ids[0] = "other"
        args[0] = "mutated"
        assertEquals(listOf("owned"), attribution.functionIds)
        assertEquals(listOf("initial"), observation.args)
        assertFailsWith<UnsupportedOperationException> { (observation.args as MutableList<String>)[0] = "changed" }
        assertFailsWith<IllegalArgumentException> {
            ModuleObservedBehavior.write(directory(), inputSha256, listOf(observation, observation))
        }
        assertFailsWith<IllegalArgumentException> { ModuleObservationAttribution(emptyList(), traceSha256) }
        assertFailsWith<IllegalArgumentException> { ModuleObservationAttribution(listOf("owned", "owned"), traceSha256) }
        assertFailsWith<IllegalArgumentException> { ModuleObservationAttribution(listOf("owned"), "invalid") }
        assertFailsWith<IllegalArgumentException> { ModuleObservedCase("large", attribution, emptyList(), "00".repeat(16385), 0, "", "") }
    }

    @Test
    fun `strict preferred file rejects symlink and legacy read still enforces original character cap`() {
        val root = directory()
        root.resolve("exploration.json").writeText("123456789")
        assertFailsWith<IllegalArgumentException> { ReconstructionExplorationInput.read(root, 8) }
        val target = root.resolve("target.json").also { it.writeText(document(listOf(case("case", "owned")))) }
        Files.createSymbolicLink(root.resolve(ModuleObservedBehavior.FILE_NAME), target.toAbsolutePath())
        assertFailsWith<IllegalArgumentException> { ReconstructionExplorationInput.read(root, 10000) }
    }

    private fun case(id: String, functionId: String, argument: String? = null) = ModuleObservedCase(
        id, ModuleObservationAttribution(listOf(functionId), traceSha256), listOfNotNull(argument), "", 0, "", "",
    )

    private fun document(cases: List<ModuleObservedCase>): String {
        val root = directory()
        return ModuleObservedBehavior.write(root, inputSha256, cases).readText()
    }

    private fun directory(): Path = Files.createTempDirectory(
        Path.of("build", "test-work", "module-observations").createDirectories(), "case-",
    )
}
