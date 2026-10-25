package decompengine.web

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class WebRedactionPolicyTest {
    private val canary = "CANARYtoken0123456789abcdef"
    private val policy = WebRedactionPolicy.create(
        environment = mapOf(
            "DECOMP_TEST_API_TOKEN" to canary,
            "AWS_SECRET_ACCESS_KEY" to "shortish9",
            "NODE_ENV" to "development",
            "SHLVL" to "1",
            "LANG" to "en_US.UTF-8",
        ),
        sensitiveValues = listOf(canary, "development", "1", "en_US.UTF-8", "LongOpaqueValue0123456789XYZ"),
        privateRoots = listOf(Path.of("/srv/decomp-private-store")),
    )

    @Test fun `credential literals, syntax and private paths are replaced while public vocabulary is untouched`() {
        assertEquals("key [redacted] end", policy.text("key $canary end"))
        assertEquals("[redacted]", policy.text("shortish9"))
        assertEquals("[redacted]", policy.text("LongOpaqueValue0123456789XYZ"))
        // Short generic environment values must never corrupt DTO vocabulary.
        assertEquals("development", policy.text("development"))
        assertEquals("1 of 1 en_US.UTF-8", policy.text("1 of 1 en_US.UTF-8"))
        assertEquals("Authorization: [redacted]", policy.text("Authorization: Bearer abcdefghijkl"))
        assertEquals("password=[redacted]&next", policy.text("password=hunter2&next"))
        assertEquals("use [redacted] now", policy.text("use sk-abcdefghijklmnopqrstuvwx now"))
        assertEquals("https://[redacted]@example.test/x", policy.text("https://user:pa55@example.test/x"))
        assertEquals("open [private-path] failed", policy.text("open /srv/decomp-private-store/abc/input.elf failed"))
        assertEquals("[private-path]", policy.text("/home/someone/.config/agent.json"))
        assertEquals("see file://[private-path]", policy.text("see file:///home/someone/x.txt"))
        assertEquals("https://example.test/home/page", policy.text("https://example.test/home/page"))
        assertEquals("at [private-path]: denied", policy.text("at /tmp/decomp-123/work: denied"))
        assertEquals("[private-path]", policy.text("C:\\Users\\someone\\AppData\\token.txt"))
        // Relative and API paths are public.
        assertEquals("src/home/main.c", policy.text("src/home/main.c"))
        assertEquals("/workbench/api/v1/jobs/abc/runs", policy.text("/workbench/api/v1/jobs/abc/runs"))
        assertEquals("/rootkit/notes", policy.text("/rootkit/notes"))
        assertEquals("Context tokens: 5", policy.text("Context tokens: 5"))
    }

    @Test fun `redaction is stable when reapplied and never leaves a configured literal`() {
        val inputs = listOf("Authorization: Bearer $canary", "x${canary}y /home/a/b token=$canary", "[redacted]X")
        for (input in inputs) {
            val once = policy.text(input)
            assertEquals(once, policy.text(once), input)
            assertFalse(once.contains(canary))
            assertFalse(policy.leaks(once), once)
        }
    }

    @Test fun `opaque protocol fields keep exact bytes unless they carry a configured literal`() {
        val document = buildJsonObject {
            put("nextCursor", "sk-abcdefghijklmnopqrstuvwxyz012345")
            put("csrfToken", "token=abcdef")
            put("writerId", "writer_$canary")
            put("sha256", "a".repeat(64))
            put("message", "failed at /home/a/b with sk-abcdefghijklmnopqrstuvwxyz012345")
            put("items", buildJsonArray { add(JsonPrimitive("/tmp/x")); add(JsonPrimitive(3)) })
            put("nested", buildJsonObject { put("runId", "/home/escape") })
        }
        val safe = policy.json(document).jsonObject
        assertEquals("sk-abcdefghijklmnopqrstuvwxyz012345", safe.getValue("nextCursor").jsonPrimitive.content)
        assertEquals("token=abcdef", safe.getValue("csrfToken").jsonPrimitive.content)
        assertEquals("[redacted]", safe.getValue("writerId").jsonPrimitive.content)
        assertEquals("a".repeat(64), safe.getValue("sha256").jsonPrimitive.content)
        assertEquals("failed at [private-path] with [redacted]", safe.getValue("message").jsonPrimitive.content)
        assertEquals("[\"[private-path]\",3]", safe.getValue("items").toString())
        // An opaque key does not exempt a value outside closed token syntax.
        assertEquals("[private-path]", safe.getValue("nested").jsonObject.getValue("runId").jsonPrimitive.content)
        assertFalse(safe.toString().contains(canary))
    }

    @Test fun `downloads keep identical bytes when clean and are rewritten structurally otherwise`() {
        val clean = "{\n  \"candidateCount\": 3,\n  \"note\": \"ok\"\n}\n".toByteArray()
        assertSame(clean, policy.document(clean))
        val dirty = "{\"note\": \"read /home/a/x\", \"count\": 18446744073709551615}".toByteArray()
        val rewritten = Json.parseToJsonElement(policy.document(dirty).decodeToString()).jsonObject
        assertEquals("read [private-path]", rewritten.getValue("note").jsonPrimitive.content)
        assertEquals("18446744073709551615", rewritten.getValue("count").toString())
        assertEquals("line [redacted]\n", policy.document("line $canary\n".toByteArray()).decodeToString())
        val binary = byteArrayOf(0xff.toByte(), 0xfe.toByte(), 1)
        assertContentEquals(binary, policy.document(binary))
    }

    @Test fun `persisted diagnostics also redact short configured values before storage`() {
        val diagnostic = WebRedactionPolicy.create(emptyMap(), listOf("s3cr"), emptyList())
        assertEquals("value [redacted] at [private-path]", diagnostic.diagnostic("value s3cr at /home/x/y"))
        assertTrue(diagnostic.diagnostic("x".repeat(1000)).length < 600)
    }
}
