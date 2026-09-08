package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class KotlinContainedCommandInterruptionTest {
    @Test
    fun `host durably authorizes before token publication and delivers only once`() {
        val policy = canonical()
        val trigger = OracleJson.canonicalBytes(JsonObject(mapOf("completed" to JsonPrimitive(512))))
        var ready = false
        val events = mutableListOf<String>()
        val controller = KotlinContainedCommandInterruption(policy, {
            events += "poll"
            if (ready) trigger else null
        }, { bytes ->
            events += "durable"
            val record = OracleJson.parseCanonical(bytes) as JsonObject
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(trigger)), record["triggerSha256"])
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(policy)), record["policySha256"])
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "authorizationSha256")))), record["authorizationSha256"])
            bytes.fill(0)
        })
        val request = request()
        controller.bind(request)
        controller.pollAndDeliver(request, secret, 123L) { error("premature delivery") }
        assertEquals(listOf("poll"), events)
        ready = true
        controller.pollAndDeliver(request, secret, 123L) { token ->
            assertEquals(listOf("poll", "poll", "durable"), events)
            KotlinContainedCommandProtocol.requireInterrupt(token, secret, request, 123L)
            events += "delivered"
            token.fill(0)
        }
        controller.pollAndDeliver(request, secret, 123L) { error("duplicate delivery") }
        assertEquals(listOf("poll", "poll", "durable", "delivered"), events)
        val receipt = controller.requireInterruptedOutcome(outcome())
        assertContentEquals(receipt, controller.requireInterruptedOutcome(outcome()))
        assertFails { controller.requireInterruptedOutcome(outcome().copy(status = "EXITED", exitCode = 0)) }
        assertFails { controller.requireInterruptedOutcome(outcome().copy(keeperPid = 124)) }
        assertFails { controller.bind(request) }
    }

    @Test
    fun `failed authorization or delivery poisons the controller without retrying tokens`() {
        for (failAuthorization in listOf(true, false)) {
            var calls = 0
            var deliveries = 0
            val controller = KotlinContainedCommandInterruption(canonical(), { canonical() }, {
                calls++
                if (failAuthorization) error("journal fsync failed")
            })
            val request = request()
            controller.bind(request)
            assertFails { controller.pollAndDeliver(request, secret, 123) { deliveries++; error("publication failed") } }
            assertFails { controller.pollAndDeliver(request, secret, 123) { deliveries++ } }
            assertFails { controller.requireInterruptedOutcome(outcome()) }
            assertEquals(1, calls)
            assertEquals(if (failAuthorization) 0 else 1, deliveries)
        }
    }

    @Test
    fun `host control rejects unbound legacy foreign and oversized or malformed triggers`() {
        val request = request()
        for (invalid in listOf("[]".toByteArray(), "{}".toByteArray(), ByteArray(4097) { 32 })) {
            assertFails { KotlinContainedCommandInterruption(invalid, { null }, {}) }
            var published = false
            var authorized = false
            val controller = KotlinContainedCommandInterruption(canonical(), { invalid }, { authorized = true })
            controller.bind(request)
            assertFails { controller.pollAndDeliver(request, secret, 123) { published = true } }
            assertFalse(authorized)
            assertFalse(published)
        }
        val controller = KotlinContainedCommandInterruption(canonical(), { null }, {})
        assertFails { controller.pollAndDeliver(request, secret, 123) {} }
        assertFails { controller.bind(request(false)) }
        controller.bind(request)
        assertFails { controller.pollAndDeliver(request(false), secret, 123) {} }
        assertFails { controller.requireInterruptedOutcome(outcome()) }
        assertTrue(request.allowInterruption)
    }

    private fun canonical() = OracleJson.canonicalBytes(JsonObject(emptyMap()))

    private fun request(interruptible: Boolean = true) = KotlinContainedCommandRequest(
        Path.of("/srv/authored-fixture"), "a".repeat(64), listOf("/usr/bin/java", "-version"),
        mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 30, 30, 4096, 4096, interruptible,
    )
    private fun outcome() = KotlinContainedCommandOutcome(123, 125, 137, 100, 0, 0, "INTERRUPTED")
    private val secret = ByteArray(32) { it.toByte() }
}
