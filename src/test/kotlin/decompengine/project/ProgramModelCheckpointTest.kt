package decompengine.project

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ProgramModelCheckpointTest {
    @Test
    fun `schema one and two checkpoints preserve complete canonical model round trips`() {
        for (schemaVersion in 1..2) {
            val model = fixture(schemaVersion)
            val stages = mutableListOf<String>()
            val canonical = model.toJson { stages += it }
            assertContentEquals(model.toJson().toByteArray(), canonical.toByteArray())
            assertEquals("after rendering program model", stages.last())

            stages.clear()
            val parsed = ProgramModelJson.readCanonical(canonical.toByteArray()) { stages += it }
            assertEquals(listOf("fn_a", "fn_b", "fn_z"), parsed.functions.map { it.id })
            assertEquals(listOf("global_a", "global_b"), parsed.globals.map { it.id })
            assertEquals(listOf("type_a", "type_z"), parsed.types.map { it.id })
            assertEquals(model.copy(
                functions = listOf(model.functions[2], model.functions[1], model.functions[0]),
                globals = model.globals.reversed(),
                types = model.types.reversed(),
            ), parsed)
            assertEquals(ProgramModelJson.readCanonical(canonical.toByteArray()), parsed)
            assertEquals("before returning canonical program model", stages.last())
            assertTrue("after constructing program model" in stages)
            assertTrue("after comparing canonical program model" in stages)

            stages.clear()
            assertEquals(ProgramModelJson.read(canonical), ProgramModelJson.read(canonical) { stages += it })
            assertEquals("after constructing program model", stages.last())
        }
    }

    @Test
    fun `small fixed canonical records retain schema fields indentation and escaping`() {
        val expectedOne = """
            {
              "schemaVersion": 1,
              "inputSha256": "fixture",
              "functions": [
                {
                  "id": "fn",
                  "name": "line\n\"",
                  "address": "0x10",
                  "prototype": "int fixture(void)",
                  "status": "partial",
                  "calls": ["other"],
                  "referencedGlobals": [],
                  "strings": ["tab\tbackslash\\"],
                  "decompiledC": null
                }
              ],
              "globals": [
              ],
              "types": [
              ]
            }
        """.trimIndent() + "\n"
        val expectedTwo = """
            {
              "schemaVersion": 2,
              "inputSha256": "fixture",
              "functions": [
                {
                  "id": "fn",
                  "name": "line\n\"",
                  "address": "0x10",
                  "prototype": "int fixture(void)",
                  "extractionStatus": "partial",
                  "recoveryAssessment": "unassessed",
                  "calls": ["other"],
                  "referencedGlobals": [],
                  "strings": ["tab\tbackslash\\"],
                  "decompiledC": null
                }
              ],
              "globals": [
              ],
              "types": [
              ]
            }
        """.trimIndent() + "\n"
        for ((schemaVersion, expected) in listOf(1 to expectedOne, 2 to expectedTwo)) {
            val model = RecoveredProgramModel(
                schemaVersion = schemaVersion,
                inputSha256 = "fixture",
                functions = listOf(RecoveredFunction(
                    id = "fn", name = "line\n\"", address = 0x10UL, prototype = "int fixture(void)",
                    calls = setOf("other"), strings = setOf("tab\tbackslash\\"), status = RecoveryStatus.PARTIAL,
                )),
            )
            assertEquals(expected, model.toJson())
            assertEquals(expected, model.toJson {})
            assertEquals(model, ProgramModelJson.readCanonical(expected.toByteArray()) {})
        }
    }

    @Test
    fun `entity and set traversal cancellation propagates without completing the model`() {
        val model = fixture(2)
        val canonical = model.toJson()
        for (stage in listOf(
            "before reading program model function",
            "before reading program model set entry",
            "before rendering program model function",
            "before rendering program model set entry",
        )) {
            val cancellation = InterruptedException("caller cancelled $stage")
            val stages = mutableListOf<String>()
            var visits = 0
            val checkpoint: (String) -> Unit = { current ->
                stages += current
                if (current == stage && ++visits == 2) throw cancellation
            }

            val failure = assertFailsWith<InterruptedException> {
                if (stage.startsWith("before reading")) ProgramModelJson.read(canonical, checkpoint)
                else model.toJson(checkpoint)
            }

            assertSame(cancellation, failure)
            assertEquals(2, visits)
            assertEquals(stage, stages.last())
            assertFalse("after constructing program model" in stages)
            assertFalse("after rendering program model" in stages)
        }
    }

    @Test
    fun `long string escaping can be cancelled between character chunks`() {
        val model = RecoveredProgramModel(
            schemaVersion = 2,
            inputSha256 = "fixture",
            functions = listOf(RecoveredFunction(
                id = "fn", name = "authored name ".repeat(400), address = 0x10UL, prototype = "void fixture(void)",
            )),
        )
        val canonical = model.toJson().toByteArray()
        for (canonicalRead in listOf(false, true)) {
            val cancellation = InterruptedException("caller cancelled string rendering")
            val stages = mutableListOf<String>()
            val checkpoint: (String) -> Unit = { stage ->
                stages += stage
                if (stage == "escaping program model string after 1024 characters") throw cancellation
            }

            val failure = assertFailsWith<InterruptedException> {
                if (canonicalRead) ProgramModelJson.readCanonical(canonical, checkpoint)
                else model.toJson(checkpoint)
            }

            assertSame(cancellation, failure)
            assertEquals("escaping program model string after 1024 characters", stages.last())
            assertFalse("after rendering program model" in stages)
            assertFalse("before returning canonical program model" in stages)
        }
    }

    private fun fixture(schemaVersion: Int) = RecoveredProgramModel(
        schemaVersion = schemaVersion,
        inputSha256 = "authored fixture identity",
        functions = listOf(
            RecoveredFunction(
                id = "fn_z", name = "last", address = 0x20UL, prototype = "void last(void)",
                status = RecoveryStatus.FAILED,
            ),
            RecoveredFunction(
                id = "fn_b", name = "second", address = 0x10UL, prototype = "void second(void)",
                status = RecoveryStatus.SYNTHETIC,
            ),
            RecoveredFunction(
                id = "fn_a", name = "first 雪😀", address = 0x10UL, prototype = "int first(void)",
                decompiledC = "int first(void) {\n\treturn 0;\n}\n",
                calls = linkedSetOf("fn_z", "fn_b"),
                referencedGlobals = linkedSetOf("global_b", "global_a"),
                strings = linkedSetOf("z", "quote\" slash\\ tab\t return\r newline\n control\u0001 雪😀"),
                status = RecoveryStatus.PARTIAL,
            ),
        ),
        globals = listOf(
            RecoveredGlobal("global_b", "second", 0x30UL, "int", status = RecoveryStatus.FAILED),
            RecoveredGlobal("global_a", "first", 0x30UL, "int", "1", RecoveryStatus.RECOVERED),
        ),
        types = listOf(
            RecoveredType("type_z", "typedef int last_t;", status = RecoveryStatus.SYNTHETIC),
            RecoveredType("type_a", "typedef int first_t;", 0x10UL, RecoveryStatus.PARTIAL),
        ),
    )
}
