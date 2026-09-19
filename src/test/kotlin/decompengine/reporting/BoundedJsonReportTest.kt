package decompengine.reporting

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.listDirectoryEntries
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class BoundedJsonReportTest {
    @Test
    fun `streamed report preserves JSON strings types order nesting and final newline`() = inControlTemporaryDirectory { root ->
        val target = root.resolve("report.json")
        val text = "café λ 😀 \"quoted\" \\ \b\u000c\n\r\t\u0001"
        val fieldName = "display\"\\\nλ"

        JsonReportPublisher.write(target) {
            objectValue {
                field(fieldName, text)
                field("signed", Long.MIN_VALUE)
                field("unsigned", ULong.MAX_VALUE)
                field("ready", true)
                objectField("details") { field("label", "hello") }
                arrayField("values") {
                    value(text)
                    value(-7L)
                    value(ULong.MAX_VALUE)
                    value(false)
                    objectValue { field("ordinal", 1L) }
                    arrayValue { value("nested") }
                }
            }
        }

        val encoded = target.readText()
        assertTrue(encoded.endsWith("\n"))
        assertFalse(encoded.endsWith("\n\n"))
        val report = Json.parseToJsonElement(encoded).jsonObject
        assertEquals(listOf(fieldName, "signed", "unsigned", "ready", "details", "values"), report.keys.toList())
        assertEquals(text, report.getValue(fieldName).jsonPrimitive.content)
        assertEquals(Long.MIN_VALUE, report.getValue("signed").jsonPrimitive.long)
        assertEquals(ULong.MAX_VALUE.toString(), report.getValue("unsigned").jsonPrimitive.content)
        assertFalse(report.getValue("unsigned").jsonPrimitive.isString)
        assertTrue(report.getValue("ready").jsonPrimitive.boolean)
        assertEquals("hello", report.getValue("details").jsonObject.getValue("label").jsonPrimitive.content)
        val values = report.getValue("values").jsonArray
        assertEquals(6, values.size)
        assertEquals(text, values[0].jsonPrimitive.content)
        assertEquals(-7L, values[1].jsonPrimitive.long)
        assertEquals(ULong.MAX_VALUE.toString(), values[2].jsonPrimitive.content)
        assertFalse(values[2].jsonPrimitive.isString)
        assertFalse(values[3].jsonPrimitive.boolean)
        assertEquals(1L, values[4].jsonObject.getValue("ordinal").jsonPrimitive.long)
        assertEquals("nested", values[5].jsonArray.single().jsonPrimitive.content)
        assertEquals(PosixFilePermissions.fromString("rw-------"), Files.getPosixFilePermissions(target))
        assertOnlyReportRemains(root, target)
    }

    @Test
    fun `byte ceiling includes UTF8 encoding and final newline before replacement`() = inControlTemporaryDirectory { root ->
        val target = root.resolve("report.json")
        val expected = "[\n  \"é\"\n]\n".toByteArray(Charsets.UTF_8)
        val render: BoundedJsonReportWriter.() -> Unit = { arrayValue { value("é") } }

        JsonReportPublisher.write(target, JsonReportLimits(maximumBytes = expected.size.toLong()), render = render)
        assertContentEquals(expected, target.readBytes())

        val previous = "previous complete report\n"
        target.writeText(previous)
        val failure = assertFailsWith<JsonReportLimitException> {
            JsonReportPublisher.write(target, JsonReportLimits(maximumBytes = expected.size.toLong() - 1), render = render)
        }

        assertTrue(failure.message.orEmpty().contains("byte limit"))
        assertEquals(previous, target.readText())
        assertOnlyReportRemains(root, target)
    }

    @Test
    fun `small independent string aggregate collection and depth caps preserve prior report`() = inControlTemporaryDirectory { root ->
        val target = root.resolve("report.json")
        val cases = listOf(
            LimitedReport(JsonReportLimits(maximumStringCharacters = 3), "character limit") {
                objectValue { field("a", "four") }
            },
            LimitedReport(JsonReportLimits(maximumStringCharacters = 3), "character limit") {
                objectValue { field("name", "a") }
            },
            LimitedReport(JsonReportLimits(maximumCollectionItems = 2), "collection-item limit") {
                objectValue {
                    arrayField("a") { value(1L) }
                    field("b", true)
                }
            },
            LimitedReport(JsonReportLimits(maximumDepth = 1), "nesting-depth limit") {
                arrayValue { objectValue {} }
            },
        )

        for ((index, report) in cases.withIndex()) {
            val previous = "complete report $index\n"
            target.writeText(previous)
            val failure = assertFailsWith<JsonReportLimitException> {
                JsonReportPublisher.write(target, report.limits, render = report.render)
            }
            assertTrue(failure.message.orEmpty().contains(report.message), failure.message)
            assertEquals(previous, target.readText())
            assertOnlyReportRemains(root, target)
        }
    }

    @Test
    fun `caller cancellation immediately before publication preserves report and original cause`() = inControlTemporaryDirectory { root ->
        val target = root.resolve("report.json")
        val previous = "previous complete report\n"
        target.writeText(previous)
        val cancellation = InterruptedException("caller cancelled report publication")
        val stages = mutableListOf<String>()

        val failure = assertFailsWith<InterruptedException> {
            JsonReportPublisher.write(target, checkpoint = { stage ->
                stages += stage
                if (stage == "before publishing JSON report") throw cancellation
            }) {
                objectValue { field("complete", true) }
            }
        }

        assertSame(cancellation, failure)
        assertEquals("before publishing JSON report", stages.last())
        assertEquals(1, stages.count { it == "before publishing JSON report" })
        assertEquals(previous, target.readText())
        assertOnlyReportRemains(root, target)
    }

    @Test
    fun `rendering a normal long label delivers cooperative cancellation checkpoints`() = inControlTemporaryDirectory { root ->
        val target = root.resolve("report.json")
        target.writeText("previous report\n")
        val cancellation = InterruptedException("caller cancelled rendering")
        var renderingCheckpointReached = false

        val failure = assertFailsWith<InterruptedException> {
            JsonReportPublisher.write(target, checkpoint = { stage ->
                if (stage == "while rendering JSON report") {
                    renderingCheckpointReached = true
                    throw cancellation
                }
            }) {
                objectValue { field("label", "ordinary label ".repeat(100)) }
            }
        }

        assertTrue(renderingCheckpointReached)
        assertSame(cancellation, failure)
        assertEquals("previous report\n", target.readText())
        assertOnlyReportRemains(root, target)
    }

    @Test
    fun `elapsed time is rechecked after the final caller checkpoint`() = inControlTemporaryDirectory { root ->
        val target = root.resolve("report.json")
        target.writeText("previous report\n")
        var publicationCheckpointReached = false

        val failure = assertFailsWith<JsonReportLimitException> {
            JsonReportPublisher.write(target, JsonReportLimits(maximumWallClockMillis = 1_000), checkpoint = { stage ->
                if (stage == "before publishing JSON report") {
                    publicationCheckpointReached = true
                    Thread.sleep(1_100)
                }
            }) {
                objectValue { field("complete", true) }
            }
        }

        assertTrue(publicationCheckpointReached)
        assertTrue(failure.message.orEmpty().contains("elapsed-time limit before publishing JSON report"))
        assertEquals("previous report\n", target.readText())
        assertOnlyReportRemains(root, target)
    }

    private data class LimitedReport(
        val limits: JsonReportLimits,
        val message: String,
        val render: BoundedJsonReportWriter.() -> Unit,
    )

    private fun assertOnlyReportRemains(root: Path, target: Path) {
        assertEquals(listOf(target), root.listDirectoryEntries())
    }
}
