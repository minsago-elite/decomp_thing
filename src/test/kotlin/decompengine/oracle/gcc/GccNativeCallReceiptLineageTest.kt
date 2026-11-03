package decompengine.oracle.gcc

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccNativeCallReceiptLineageTest {
    @Test
    fun `native receipt accepts options before either supported engine`() {
        for (engine in listOf("cc1", "driver")) {
            val arguments = options() + listOf(engine, path("binary"))
            GccNativeCallReceiptLineage.requireCliSelection(invocation(engine, arguments), engine)
        }
    }

    @Test
    fun `native receipt preserves positional-first and interleaved option selections`() {
        for (engine in listOf("cc1", "driver")) {
            for (arguments in listOf(
                listOf(engine, path("binary")) + options(),
                options().take(2) + engine + options().drop(2) + path("binary"),
            )) {
                GccNativeCallReceiptLineage.requireCliSelection(invocation(engine, arguments), engine)
            }
        }
    }

    @Test
    fun `native receipt rejects substituted bound and argument engines`() {
        for (engine in listOf("cc1", "driver")) {
            val other = if (engine == "cc1") "driver" else "cc1"
            val arguments = options() + listOf(engine, path("binary"))
            assertFailsWith<IllegalArgumentException> {
                GccNativeCallReceiptLineage.requireCliSelection(invocation(other, arguments), engine)
            }
            assertFailsWith<IllegalArgumentException> {
                GccNativeCallReceiptLineage.requireCliSelection(invocation(engine,
                    options() + listOf(other, path("binary"))), engine)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            GccNativeCallReceiptLineage.requireCliSelection(invocation("lto1",
                options() + listOf("lto1", path("binary"))), "lto1")
        }
    }

    @Test
    fun `native receipt rejects other command kinds`() {
        for (command in listOf("gcc-engine-plan", "gcc-engine-full-export", "gcc-engine-runtime-diagnostic")) {
            assertFailsWith<IllegalArgumentException> {
                GccNativeCallReceiptLineage.requireCliSelection(invocation("cc1",
                    options() + listOf("cc1", path("binary")), command), "cc1")
            }
        }
    }

    @Test
    fun `native receipt enforces the same fresh command argument grammar`() {
        val arguments = options() + listOf("cc1", path("binary"))
        for (invalid in listOf(
            arguments + listOf("--resume-after-checkpoint", "512"),
            arguments + listOf("--profile", path("substituted-profile")),
            arguments + listOf("--collector", path("collector")),
            arguments + "extra-positional",
        )) {
            assertFailsWith<IllegalArgumentException> {
                GccNativeCallReceiptLineage.requireCliSelection(invocation("cc1", invalid), "cc1")
            }
        }
    }

    private fun invocation(engine: String, arguments: List<String>, command: String = "gcc-engine-native-calls") =
        JsonObject(mapOf("engineId" to JsonPrimitive(engine),
            "argv" to JsonArray((listOf(command) + arguments).map(::JsonPrimitive))))

    private fun options() = listOf("--profile", path("profile"), "--ghidra-archive", path("archive"),
        "--output", path("output"), "--scratch", path("scratch"))

    private fun path(name: String) = Path.of(System.getProperty("user.dir"), ".omo", "native-receipt-selection", name).toString()
}
