package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class ModulePlanJsonTest {
    private val layout = GeneratedCMakeReconstructionProfile.descriptor.layout
    private val model = RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
        RecoveredFunction("f1", "alpha_first", 1u, "void alpha_first(void)", calls = setOf("f2")),
        RecoveredFunction("f2", "beta_second", 2u, "void beta_second(void)", calls = setOf("f1")),
    ), globals = listOf(RecoveredGlobal("g", "counter", 3u, "int")),
        types = listOf(RecoveredType("t", "typedef int number;")))
    private val plan = DeterministicModulePlanner(1, layout).plan(model)

    @Test
    fun `module plan renderer preserves canonical bytes while escaping directly`() {
        val input = ModulePlan(
            modules = listOf(
                PlannedModule(
                    id = "z\"ed",
                    sourcePath = "src\\\n\t\u0001é.c",
                    headerPath = "include/core.h",
                    functionIds = listOf("fn\"1", "fn\\2"),
                    globalIds = emptyList(),
                    typeIds = listOf("τ"),
                    boundaryEvidence = listOf("line\nnext", "tab\tcarriage\r"),
                ),
                PlannedModule("a", "a.c", "a.h", emptyList(), listOf("g0"), emptyList(), emptyList()),
            ),
            dependencyCycles = listOf(listOf("a", "z\"ed")),
        )

        val expected = """
{
  "schemaVersion": 2,
  "modules": [    {
      "id": "a",
      "sourcePath": "a.c",
      "headerPath": "a.h",
      "functionIds": [],
      "globalIds": ["g0"],
      "typeIds": [],
      "boundaryEvidence": []
    },    {
      "id": "z\"ed",
      "sourcePath": "src\\\n\t\u0001é.c",
      "headerPath": "include/core.h",
      "functionIds": ["fn\"1", "fn\\2"],
      "globalIds": [],
      "typeIds": ["τ"],
      "boundaryEvidence": ["line\nnext", "tab\tcarriage\r"]
    }
  ],
  "dependencyCycles": [["a","z\"ed"]]
}
""".trimIndent() + "\n"

        assertEquals(expected, input.toJson())
    }

    @Test
    fun `canonical planner output preserves ownership cycles and escaped evidence`() {
        val withEvidence = plan.copy(modules = plan.modules.map {
            it.copy(boundaryEvidence = it.boundaryEvidence + "braces {[ and quote \" and slash \\")
        })
        val bytes = withEvidence.toJson().toByteArray()
        val parsed = ModulePlanJson.readCanonical(bytes, bytes.size)
        assertEquals(withEvidence, parsed)
        ModulePlanJson.requireExactOwnership(parsed, model, layout, 1)
        val empty = model.copy(functions = emptyList(), globals = emptyList(), types = emptyList())
        ModulePlanJson.requireExactOwnership(DeterministicModulePlanner().plan(empty), empty, layout, 1)
    }

    @Test
    fun `reject noncanonical schema types fields ordering encodings and excessive nesting`() {
        val text = plan.toJson()
        listOf(text + " ", text.replace("\"schemaVersion\": 2", "\"schemaVersion\": \"2\""),
            text.replace("\"schemaVersion\": 2", "\"schemaVersion\": 1"),
            text.replace("\"schemaVersion\": 2", "\"extra\": 0, \"schemaVersion\": 2"),
            text.replace("\"schemaVersion\": 2", "\"schemaVersion\": 2, \"schemaVersion\": 2"),
            text.replace("\"f1\"", "1"),
            "[".repeat(10000) + "]".repeat(10000),
            text.replace("\"modules\": [", "\"modules\": [null,"),
        ).forEach { invalid -> assertFails { ModulePlanJson.readCanonical(invalid.toByteArray(), 1024 * 1024) } }
        val bytes = text.toByteArray()
        assertFails { ModulePlanJson.readCanonical(bytes, bytes.size - 1) }
        assertFails { ModulePlanJson.readCanonical(bytes + byteArrayOf(0xc0.toByte()), 1024 * 1024) }
    }

    @Test
    fun `streaming plan reader matches the previous DOM reader on canonical and malformed inputs`() {
        val rich = plan.copy(modules = plan.modules.map { module ->
            module.copy(boundaryEvidence = listOf("plain", "café", "supplementary 😀", "control\t\n\u0001", "quoted \" and \\"))
        })
        val canonical = rich.toJson()
        val validBytes = canonical.toByteArray(Charsets.UTF_8)
        val invalid = listOf(
            canonical + " ",
            canonical.replace("\"schemaVersion\": 2", "\"schemaVersion\": \"2\""),
            canonical.replace("\"schemaVersion\": 2", "\"schemaVersion\": 2.0"),
            canonical.replace("\"schemaVersion\": 2", "\"schemaVersion\": 2, \"schemaVersion\": 2"),
            canonical.replace("\"schemaVersion\"", "\"schema\\u0056ersion\""),
            "{\"schemaVersion\":2}",
            canonical.replace("\"schemaVersion\": 2,", "\"schemaVersion\": 2, \"unknown\": 0,"),
            canonical.replace("\"id\": ", "\"id\": null, \"unused\": "),
            canonical.replace("\"functionIds\": [", "\"functionIds\": [["),
            canonical.replace("\"plain\"", "\"" + "\\" + "uD800" + "\""),
            canonical.replace("\"plain\"", "\"" + "\\" + "uDC00" + "\""),
            "{\"schemaVersion\":2,\"modules\":[],\"dependencyCycles\":[[[[]]]]}",
            canonical.dropLast(2),
        )
        val cases = listOf(validBytes) + invalid.map { it.toByteArray(Charsets.UTF_8) } +
            listOf(validBytes + byteArrayOf(0xc0.toByte()), byteArrayOf(0xff.toByte()))

        cases.forEachIndexed { index, bytes ->
            val maximum = 16 * 1024 * 1024
            val expected = runCatching { legacyReadCanonical(bytes, maximum) }
            val actual = runCatching { ModulePlanJson.readCanonical(bytes, maximum) }
            assertEquals(expected.isSuccess, actual.isSuccess, "acceptance mismatch for differential case $index")
            if (expected.isSuccess) assertEquals(expected.getOrThrow(), actual.getOrThrow())
        }
        assertEquals(rich, ModulePlanJson.readCanonical(validBytes, validBytes.size))
        assertFailsWith<IllegalArgumentException> { ModulePlanJson.readCanonical(validBytes, validBytes.size - 1) }
    }

    @Test
    fun `reject missing invented duplicate ownership and layout substitution`() {
        fun changed(transform: (PlannedModule) -> PlannedModule) = plan.copy(
            modules = listOf(transform(plan.modules.first())) + plan.modules.drop(1))
        val ownerGlobal = plan.modules.indexOfFirst { it.globalIds.isNotEmpty() }
        val ownerType = plan.modules.indexOfFirst { it.typeIds.isNotEmpty() }
        val invalid = listOf(
            changed { it.copy(functionIds = emptyList()) },
            changed { it.copy(functionIds = listOf("unknown")) },
            changed { it.copy(functionIds = it.functionIds + it.functionIds) },
            plan.copy(modules = plan.modules + plan.modules.first()),
            changed { it.copy(sourcePath = "../outside.c") },
            changed { it.copy(headerPath = it.sourcePath) },
            plan.copy(modules = plan.modules.mapIndexed { i, module ->
                if (i == ownerGlobal) module.copy(globalIds = emptyList()) else module }),
            plan.copy(modules = plan.modules.mapIndexed { i, module ->
                if (i == ownerType) module.copy(typeIds = module.typeIds + module.typeIds) else module }),
            changed { it.copy(globalIds = it.globalIds + "invented") },
            changed { it.copy(typeIds = it.typeIds + "invented") },
        )
        invalid.forEach { candidate ->
            // These have canonical bytes: format checks alone cannot establish ownership.
            val parsed = ModulePlanJson.readCanonical(candidate.toJson().toByteArray(), 1024 * 1024)
            assertFails { ModulePlanJson.requireExactOwnership(parsed, model, layout, 10) }
        }
    }

    @Test
    fun `checkpoint aware plan validation preserves canonical bytes ownership and old entries`() {
        val candidate = plan.copy(modules = plan.modules.map {
            it.copy(boundaryEvidence = it.boundaryEvidence + "long quoted { evidence \\\n".repeat(5000))
        })
        val bytes = candidate.toJson().toByteArray()
        val stages = mutableSetOf<String>()
        val parsed = ModulePlanJson.readCanonical(bytes, bytes.size) { stages += it }
        assertEquals(candidate, parsed)
        assertEquals(ModulePlanJson.readCanonical(bytes, bytes.size), parsed)
        assertEquals(bytes.toList(), parsed.toJson().toByteArray().toList())
        ModulePlanJson.requireExactOwnership(parsed, model, layout, 1) { stages += it }
        assertTrue(stages.any { it.startsWith("scanning module plan after ") })
        assertTrue("reading module plan module" in stages)
        assertTrue("consuming module plan function" in stages)
        assertTrue("after module plan ownership" in stages)
    }

    @Test
    fun `checkpoint refusal interrupts long plan traversal and propagates the exact failure`() {
        val candidate = plan.copy(modules = plan.modules.map {
            it.copy(boundaryEvidence = it.boundaryEvidence + "bounded traversal".repeat(5000))
        })
        val bytes = candidate.toJson().toByteArray()
        for (target in listOf("scanning module plan after ", "reading module plan module",
            "reading module plan string", "before rendering canonical module plan", "before returning module plan")) {
            val expected = IllegalStateException("controlled plan checkpoint refusal")
            val actual = assertFailsWith<IllegalStateException> {
                ModulePlanJson.readCanonical(bytes, bytes.size) { stage -> if (stage.startsWith(target)) throw expected }
            }
            assertSame(expected, actual)
            assertEquals(candidate, ModulePlanJson.readCanonical(bytes, bytes.size))
        }
    }

    @Test
    fun `ownership interruption never mutates the model or later ownership validation`() {
        val before = plan.toJson()
        val functions = model.functions.toList()
        val expected = InterruptedException("independent ownership cancellation")
        var visited = 0
        val actual = assertFailsWith<InterruptedException> {
            ModulePlanJson.requireExactOwnership(plan, model, layout, 1) { stage ->
                if (stage == "consuming module plan function" && ++visited == 2) throw expected
            }
        }
        assertSame(expected, actual)
        assertEquals(2, visited)
        assertEquals(before, plan.toJson()); assertEquals(functions, model.functions)
        ModulePlanJson.requireExactOwnership(plan, model, layout, 1)
    }

    private fun legacyReadCanonical(bytes: ByteArray, maximumBytes: Int): ModulePlan {
        require(maximumBytes in 1..512 * 1024 * 1024 && bytes.size in 1..maximumBytes)
        val text = bytes.toString(Charsets.UTF_8)
        require(bytes.contentEquals(text.toByteArray(Charsets.UTF_8)))
        var depth = 0
        var quoted = false
        var escaped = false
        text.forEach { char ->
            if (quoted) {
                if (escaped) escaped = false
                else if (char == '\\') escaped = true
                else if (char == '"') quoted = false
            } else when (char) {
                '"' -> quoted = true
                '{', '[' -> { depth++; require(depth <= 4) }
                '}', ']' -> { depth--; require(depth >= 0) }
            }
        }
        require(depth == 0 && !quoted)
        val root = Json.parseToJsonElement(text).jsonObject
        val version = root.getValue("schemaVersion").jsonPrimitive
        require(!version.isString && version.content == "2")
        val parsed = ModulePlan(
            modules = root.getValue("modules").jsonArray.map { element ->
                val entry = element.jsonObject
                PlannedModule(entry.getValue("id").legacyString(), entry.getValue("sourcePath").legacyString(),
                    entry.getValue("headerPath").legacyString(), entry.getValue("functionIds").legacyStrings(),
                    entry.getValue("globalIds").legacyStrings(), entry.getValue("typeIds").legacyStrings(),
                    entry.getValue("boundaryEvidence").legacyStrings())
            },
            dependencyCycles = root.getValue("dependencyCycles").jsonArray.map { it.legacyStrings() },
        )
        require(bytes.contentEquals(parsed.toJson().toByteArray(Charsets.UTF_8)))
        return parsed
    }

    private fun JsonElement.legacyString(): String = jsonPrimitive.let { require(it.isString); it.content }
    private fun JsonElement.legacyStrings(): List<String> = jsonArray.map { it.legacyString() }

    @Test
    fun `reject invalid cycle references and function population ceiling`() {
        val ids = plan.modules.map { it.id }
        listOf(listOf(listOf(ids.first())), listOf(listOf(ids.first(), "unknown")),
            listOf(ids, ids), listOf(listOf(ids.first(), ids.first())), listOf(ids.reversed())).forEach { cycles ->
            assertFails { ModulePlanJson.requireExactOwnership(plan.copy(dependencyCycles = cycles), model, layout, 1) }
        }
        val oneModule = plan.modules.first().copy(functionIds = listOf("f1", "f2"), globalIds = listOf("g"), typeIds = listOf("t"))
        assertFails { ModulePlanJson.requireExactOwnership(ModulePlan(modules = listOf(oneModule)), model, layout, 1) }
    }
}
