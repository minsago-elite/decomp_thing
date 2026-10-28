package decompengine.project

import decompengine.exploration.CandidateInput
import decompengine.exploration.CandidateObservation
import decompengine.exploration.CandidateSource
import decompengine.exploration.ConfidenceScore
import decompengine.exploration.CoverageReport
import decompengine.exploration.ExplorationReport
import decompengine.exploration.ModuleObservationAttributor
import decompengine.exploration.writeModuleObservations
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

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

    @Test
    fun `retained observations preserve small raw bytes and distinguish current and historical replay`() {
        val raw = encoded(listOf(case("owned-case", "owned", "é")))
        val exact = raw + " ".repeat(MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES - raw.toByteArray().size)
        for (observed in listOf(null, "opaque legacy evidence", "opaque module-observation-retention-v1 note",
            "{\"note\":\"module-observation-retention-v1\"}", raw, exact)) {
            assertEquals(observed, ModuleObservationRetention.retain(retentionRequest(observed)))
            for (legacy in listOf(false, true)) {
                assertEquals(observed, ModuleObservationRetention.replay(observed, module, model, legacy))
            }
        }
        val historicalMention = "opaque ${ModuleObservationRetention.KIND} note"
        assertEquals(historicalMention, ModuleObservationRetention.replay(historicalMention, module, model, legacy = true))
        assertFailsWith<IllegalArgumentException> {
            ModuleObservationRetention.replay(historicalMention, module, model, legacy = false)
        }
        val largerPadded = exact + " "
        val retained = requireNotNull(ModuleObservationRetention.retain(retentionRequest(largerPadded)))
        assertTrue(retained.toByteArray().size < MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES)
        assertEquals(selectModuleObservedBehavior(largerPadded, module, model), selectModuleObservedBehavior(
            ModuleObservationRetention.replay(retained, module, model, legacy = false), module, model))
        assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.replay(retained, module, model, legacy = true) }
        assertFailsWith<IllegalArgumentException> {
            ModuleObservationRetention.retain(retentionRequest("opaque " + "x".repeat(MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES)))
        }
    }

    @Test
    fun `oversized corpus retains only whole selected cases with explicit raw provenance`() {
        val raw = largeCorpus()
        assertTrue(raw.toByteArray().size in (MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES + 1)..ModuleObservedBehavior.MAXIMUM_BYTES)
        val retained = requireNotNull(ModuleObservationRetention.retain(retentionRequest(raw)))
        val wrapper = Json.parseToJsonElement(retained).jsonObject
        assertEquals(JsonPrimitive("module-selected"), wrapper["scope"])
        assertEquals(JsonPrimitive(false), wrapper["originalCorpusRetained"])
        assertEquals(JsonPrimitive(module.id), wrapper["moduleId"])
        assertEquals(JsonArray(listOf(JsonPrimitive("owned"))), wrapper["functionIds"])
        assertEquals(JsonObject(mapOf("sha256" to JsonPrimitive(sha256(raw.toByteArray())),
            "bytes" to JsonPrimitive(raw.toByteArray().size), "caseCount" to JsonPrimitive(22))), wrapper["sourceCorpus"])
        val selected = wrapper.getValue("selected").jsonObject.getValue("cases").jsonArray
        assertEquals(listOf("owned-case", "shared-case"), selected.map { it.jsonObject.getValue("caseId").jsonPrimitive.content })
        assertEquals(JsonArray(listOf(JsonPrimitive("other"), JsonPrimitive("owned"))),
            selected[1].jsonObject.getValue("functionIds"))
        assertFalse(retained.contains("unrelated-"))
        val replayed = ModuleObservationRetention.replay(retained, module, model, legacy = false)
        assertEquals(selectModuleObservedBehavior(raw, module, model), selectModuleObservedBehavior(replayed, module, model))

        val changedRaw = largeCorpus("cd")
        val changed = Json.parseToJsonElement(requireNotNull(ModuleObservationRetention.retain(retentionRequest(changedRaw)))).jsonObject
        assertNotEquals(wrapper["sourceCorpus"], changed["sourceCorpus"])
        assertEquals(wrapper["selected"], changed["selected"])
        assertEquals(selectModuleObservedBehavior(raw, module, model), selectModuleObservedBehavior(changedRaw, module, model))
        // Missing original bytes cannot authenticate a well-formed source digest declaration.
        val source = wrapper.getValue("sourceCorpus").jsonObject
        val changedDeclaredDigest = JsonObject(wrapper + ("sourceCorpus" to JsonObject(source +
            ("sha256" to JsonPrimitive("f".repeat(64))))))
        assertEquals(replayed, ModuleObservationRetention.replay(canonical(changedDeclaredDigest), module, model, legacy = false))
    }

    @Test
    fun `empty selected corpus stays distinct from absent evidence and unrelated invalid IDs still fail`() {
        val raw = encoded(largeUnrelatedCases())
        val retained = requireNotNull(ModuleObservationRetention.retain(retentionRequest(raw)))
        val replayed = ModuleObservationRetention.replay(retained, module, model, legacy = false)
        assertEquals(0, ModuleObservedBehavior.parse(requireNotNull(replayed)).cases.size)
        assertEquals(selectModuleObservedBehavior(raw, module, model), selectModuleObservedBehavior(replayed, module, model))
        assertNotEquals(selectModuleObservedBehavior(null, module, model), selectModuleObservedBehavior(replayed, module, model))
        val bad = encoded(largeUnrelatedCases() + case("unknown-case", "unknown"))
        assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.retain(retentionRequest(bad)) }
    }

    @Test
    fun `closed retained wrapper rejects identity scope field and selected population substitutions`() {
        val retained = requireNotNull(ModuleObservationRetention.retain(retentionRequest(largeCorpus())))
        val value = Json.parseToJsonElement(retained).jsonObject
        assertEquals(selectModuleObservedBehavior(largeCorpus(), module, model), selectModuleObservedBehavior(
            ModuleObservationRetention.replay(retained, module, model, legacy = false), module, model))
        fun reject(changed: JsonObject) {
            val bytes = canonical(changed)
            assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.replay(bytes, module, model, legacy = false) }
        }
        for (key in value.keys) reject(JsonObject(value - key))
        reject(JsonObject(value + ("extra" to JsonPrimitive(true))))
        for ((key, replacement) in listOf(
            "kind" to JsonPrimitive(ModuleObservationRetention.KIND + "-future"),
            "provider" to JsonPrimitive("other"), "schemaVersion" to JsonPrimitive(2),
            "scope" to JsonPrimitive("complete-corpus"), "originalCorpusRetained" to JsonPrimitive(true),
            "inputSha256" to JsonPrimitive("3".repeat(64)), "moduleId" to JsonPrimitive("other-module"),
            "functionIds" to JsonArray(listOf(JsonPrimitive("other"))),
            "functionIds" to JsonArray(listOf(JsonPrimitive("owned"), JsonPrimitive("owned"))),
        )) reject(JsonObject(value + (key to replacement)))
        val source = value.getValue("sourceCorpus").jsonObject
        fun sourceChange(changed: JsonObject) = reject(JsonObject(value + ("sourceCorpus" to changed)))
        for (key in source.keys) sourceChange(JsonObject(source - key))
        sourceChange(JsonObject(source + ("extra" to JsonPrimitive(1))))
        for (bad in listOf(JsonNull, JsonPrimitive("NOT_A_DIGEST"), JsonPrimitive(1))) {
            sourceChange(JsonObject(source + ("sha256" to bad)))
        }
        for (bad in listOf(JsonPrimitive(0), JsonPrimitive(MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES),
            JsonPrimitive(ModuleObservedBehavior.MAXIMUM_BYTES + 1), JsonPrimitive("600000"), JsonPrimitive(600000.5), JsonNull)) {
            sourceChange(JsonObject(source + ("bytes" to bad)))
        }
        for (bad in listOf(JsonPrimitive(1), JsonPrimitive(1025), JsonPrimitive(-1), JsonPrimitive("22"), JsonPrimitive(true))) {
            sourceChange(JsonObject(source + ("caseCount" to bad)))
        }
        reject(JsonObject(value + ("selected" to ModuleObservedBehavior.envelope(inputSha256,
            listOf(case("other-only", "other"))))))
        reject(JsonObject(value + ("selected" to ModuleObservedBehavior.envelope("3".repeat(64),
            listOf(case("owned-case", "owned"))))))
        assertFailsWith<IllegalArgumentException> {
            ModuleObservationRetention.replay(value.toString(), module, model, legacy = false)
        }
        assertFailsWith<IllegalArgumentException> {
            ModuleObservationRetention.replay(retained.dropLast(2), module, model, legacy = false)
        }
        assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.replay(retained, module, model, legacy = true) }
        assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.requireRawInput(retained) }
        assertFailsWith<IllegalArgumentException> { selectModuleObservedBehavior(retained, module, model) }
        val escaped = retained.replace(ModuleObservationRetention.KIND, "module-observed-behavior-selectio\\u006e")
            .replace("module-observation-retention-v1", "module-observation-retention-v\\u0031")
        assertFalse(ModuleObservationRetention.KIND in escaped || "module-observation-retention-v1" in escaped)
        assertEquals(value, Json.parseToJsonElement(escaped).jsonObject)
        assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.requireRawInput(escaped) }
        for (legacy in listOf(false, true)) {
            assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.replay(escaped, module, model, legacy) }
        }
        val root = directory()
        root.resolve(ModuleObservedBehavior.FILE_NAME).writeText(retained)
        assertFailsWith<IllegalArgumentException> { ReconstructionExplorationInput.read(root, 4096) }
    }

    @Test
    fun `whole wrapper byte bound includes provenance and compact small inputs retain their original bytes`() {
        fun cases(characters: Int, includeUnrelated: Boolean): List<ModuleObservedCase> {
            require(characters in 0..32 * 1024)
            var remaining = characters
            val args = List(32) { "x".repeat(minOf(remaining, 1024)).also { remaining -= it.length } }
            val selected = List(5) { index -> ModuleObservedCase("owned-$index",
                ModuleObservationAttribution(listOf("owned"), traceSha256), if (index == 0) args else emptyList(),
                "00".repeat(16384), 0, "11".repeat(16384), "22".repeat(16384)) }
            return selected + if (includeUnrelated) listOf(ModuleObservedCase("unrelated-boundary",
                ModuleObservationAttribution(listOf("other"), traceSha256), emptyList(), "", 0, "33".repeat(16384), "")) else emptyList()
        }
        val baseRaw = encoded(cases(0, includeUnrelated = true))
        val baseRetained = requireNotNull(ModuleObservationRetention.retain(retentionRequest(baseRaw)))
        val additional = MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES - baseRetained.toByteArray().size
        assertTrue(additional in 1 until 32 * 1024)
        val exactRaw = encoded(cases(additional, includeUnrelated = true))
        val exact = requireNotNull(ModuleObservationRetention.retain(retentionRequest(exactRaw)))
        assertEquals(MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES, exact.toByteArray().size)
        assertEquals(selectModuleObservedBehavior(exactRaw, module, model), selectModuleObservedBehavior(
            ModuleObservationRetention.replay(exact, module, model, legacy = false), module, model))
        val overRaw = encoded(cases(additional + 1, includeUnrelated = true))
        val overSelection = requireNotNull(selectModuleObservationCases(overRaw, module, model))
        val exactObject = Json.parseToJsonElement(exact).jsonObject
        val expectedOver = JsonObject(exactObject + mapOf(
            "selected" to ModuleObservedBehavior.envelope(inputSha256, overSelection.cases),
            "sourceCorpus" to JsonObject(mapOf("sha256" to JsonPrimitive(sha256(overRaw.toByteArray())),
                "bytes" to JsonPrimitive(overRaw.toByteArray().size), "caseCount" to JsonPrimitive(6))),
        ))
        assertEquals(MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES + 1, canonical(expectedOver).toByteArray().size)
        assertFailsWith<IllegalArgumentException> { ModuleObservationRetention.retain(retentionRequest(overRaw)) }

        val compactBase = ModuleObservedBehavior.envelope(inputSha256, cases(0, includeUnrelated = false)).toString()
        val compactAdditional = MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES - compactBase.toByteArray().size
        assertTrue(compactAdditional in 1..32 * 1024)
        val compact = ModuleObservedBehavior.envelope(inputSha256, cases(compactAdditional, includeUnrelated = false)).toString()
        assertEquals(MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES, compact.toByteArray().size)
        assertTrue(canonical(ModuleObservedBehavior.parseObject(compact)).toByteArray().size > MAXIMUM_RETAINED_MODULE_OBSERVATION_BYTES)
        assertEquals(compact, ModuleObservationRetention.retain(retentionRequest(compact)))
        assertEquals(compact, ModuleObservationRetention.replay(compact, module, model, legacy = false))
    }

    private fun retentionRequest(observed: String?) = ModuleReconstructionRequest(module, model, "", "", "",
        emptyMap(), Path.of("unused-retention-workspace"), observedBehavior = observed)

    private fun largeUnrelatedCases(hex: String = "ab") = List(20) { index -> ModuleObservedCase("unrelated-$index",
        ModuleObservationAttribution(listOf("other"), traceSha256), emptyList(), "", 0, hex.repeat(16384), "") }

    private fun largeCorpus(hex: String = "ab") = encoded(listOf(case("owned-case", "owned", "selected"),
        ModuleObservedCase("shared-case", ModuleObservationAttribution(listOf("owned", "other"), traceSha256),
            listOf("shared whole execution"), "41", 7, "42", "43")) + largeUnrelatedCases(hex))

    private fun canonical(value: JsonObject): String = OracleJson.canonicalBytes(value, ModuleObservedBehavior.limits).decodeToString()
    private fun encoded(cases: List<ModuleObservedCase>): String = canonical(ModuleObservedBehavior.envelope(inputSha256, cases))

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
