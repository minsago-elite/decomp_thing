package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test

/** Authored codec/HMAC controls only; no process, limit observation, filesystem admission or live authority. */
class ContainedCommandFileDescriptorProtocolTest {
    @Test
    fun `closed module policy retains the independently authored identity and exact limit`() {
        val expected = ("""
            {
              "hardLimit": 7678,
              "provider": "contained-module-compilation-file-descriptor-policy-v1",
              "schemaVersion": 1,
              "scope": "module-object",
              "softLimit": 7678
            }
        """.trimIndent() + "\n").toByteArray()
        OracleJson.parseCanonical(expected)
        assertEquals(FD_SHA256, OracleArtifacts.sha256(expected))
        assertEquals(FD_SHA256, POLICY.sha256)
        assertEquals(7678L, POLICY.maximumOpenFiles)
        assertContentEquals(expected, OracleJson.canonicalBytes(POLICY.canonicalIdentity()))
    }

    @Test
    fun `v5 without visibility preserves authored false and true request bytes`() {
        for (interruption in listOf(false, true)) assertV5(interruption, null)
    }

    @Test
    fun `v5 selected visibility preserves authored false and true request bytes`() {
        for (interruption in listOf(false, true)) assertV5(interruption, SELECTED_SHA256)
    }

    @Test
    fun `v5 explicit empty visibility preserves authored false and true request bytes`() {
        for (interruption in listOf(false, true)) assertV5(interruption, EMPTY_SHA256)
    }

    @Test
    fun `all six v5 declarations have distinct hashes and defensive canonical bytes`() {
        val requests = variants()
        assertEquals(6, requests.map { it.sha256 }.toSet().size)
        for (request in requests) {
            val expected = request.canonicalBytes
            val exposed = request.canonicalBytes
            exposed[0] = '!'.code.toByte()
            assertContentEquals(expected, request.canonicalBytes)
            assertEquals(OracleArtifacts.sha256(expected), request.sha256)
        }
    }

    @Test
    fun `v5 requires an explicit Boolean interruption field`() {
        for (visibility in VISIBILITIES) {
            val base = document(authoredRequest(false, visibility))
            reject(JsonObject(base - "allowInterruption"), "missing interruption")
            for (value in listOf(JsonNull, JsonPrimitive("false"), JsonPrimitive("true"), JsonPrimitive(0))) {
                reject(changed(base, "allowInterruption", value), "interruption=$value")
            }
        }
    }

    @Test
    fun `v5 rejects either missing descriptor field and a missing pair in every variant`() {
        for (interruption in listOf(false, true)) for (visibility in VISIBILITIES) {
            val base = document(authoredRequest(interruption, visibility))
            for (fields in listOf(setOf("fileDescriptorPolicySha256"), setOf("maximumOpenFiles"),
                setOf("fileDescriptorPolicySha256", "maximumOpenFiles"))) {
                reject(JsonObject(base - fields), "missing $fields, interruption=$interruption, visibility=$visibility")
            }
        }
    }

    @Test
    fun `v5 rejects unknown malformed and nonstring descriptor policies`() {
        val base = document(authoredRequest(false, null))
        for (value in listOf(JsonPrimitive("f".repeat(64)), JsonPrimitive(FD_SHA256.uppercase()), JsonPrimitive(""),
            JsonNull, JsonPrimitive(7678), JsonPrimitive(true), JsonObject(emptyMap()))) {
            reject(changed(base, "fileDescriptorPolicySha256", value), "descriptor policy=$value")
        }
    }

    @Test
    fun `v5 rejects a changed limit and every noninteger limit representation`() {
        val base = document(authoredRequest(false, null))
        for (value in listOf(JsonPrimitive(512), JsonPrimitive(7677), JsonPrimitive(7679), JsonPrimitive(0),
            JsonPrimitive(-1), JsonPrimitive(Long.MAX_VALUE), JsonPrimitive(7678.0), JsonPrimitive(7678.5),
            JsonPrimitive("7678"), JsonNull, JsonPrimitive(true), JsonArray(emptyList()))) {
            reject(changed(base, "maximumOpenFiles", value), "maximumOpenFiles=$value")
        }
    }

    @Test
    fun `v5 requires the exact terminal policy with descriptor and optional visibility fields`() {
        for (visibility in VISIBILITIES) {
            val base = document(authoredRequest(false, visibility))
            reject(JsonObject(base - "terminalResourcePolicySha256"), "missing terminal")
            for (value in listOf(JsonPrimitive(FD_SHA256), JsonPrimitive("f".repeat(64)), JsonNull,
                JsonPrimitive(false), JsonPrimitive(3))) {
                reject(changed(base, "terminalResourcePolicySha256", value), "terminal=$value")
            }
        }
    }

    @Test
    fun `v5 rejects mismatched provider version and additional fields`() {
        val base = document(authoredRequest(false, null))
        reject(changed(base, "provider", JsonPrimitive("kotlin-contained-command-request-v3")), "old provider")
        reject(changed(base, "provider", JsonNull), "null provider")
        reject(changed(base, "schemaVersion", JsonPrimitive(6)), "unknown version")
        reject(changed(base, "schemaVersion", JsonPrimitive("5")), "string version")
        reject(changed(base, "trustedHostMaximumOpenFiles", JsonPrimitive(7678)), "caller supplied ceiling")
        reject(changed(base, "fileDescriptorPolicy", POLICY.canonicalIdentity()), "extra policy preimage")
    }

    @Test
    fun `v5 optional visibility rejects null malformed and nonstring declarations`() {
        val base = document(authoredRequest(false, null))
        for (value in listOf(JsonNull, JsonPrimitive(""), JsonPrimitive(SELECTED_SHA256.uppercase()),
            JsonPrimitive("a".repeat(63)), JsonPrimitive(4), JsonPrimitive(false), JsonObject(emptyMap()))) {
            reject(changed(base, "retainedInputVisibilitySha256", value), "visibility=$value")
        }
    }

    @Test
    fun `typed descriptor selection requires terminal policy for all visibility and interruption choices`() {
        for (interruption in listOf(false, true)) for (visibility in VISIBILITIES) {
            assertFailsWith<IllegalArgumentException> {
                request(interruption, visibility, terminal = null)
            }
            assertFailsWith<IllegalArgumentException> {
                request(interruption, visibility, terminal = FD_SHA256)
            }
        }
    }

    @Test
    fun `absent descriptor selection still rejects combined legacy terminal and visibility policies`() {
        for (interruption in listOf(false, true)) for (visibility in listOf(SELECTED_SHA256, EMPTY_SHA256)) {
            assertFailsWith<IllegalArgumentException> {
                request(interruption, visibility, policy = null)
            }
        }
    }

    @Test
    fun `every legacy fixture rejects either descriptor field and the complete pair`() {
        val additions = listOf(mapOf("fileDescriptorPolicySha256" to JsonPrimitive(FD_SHA256)),
            mapOf("maximumOpenFiles" to JsonPrimitive(7678)),
            mapOf("fileDescriptorPolicySha256" to JsonPrimitive(FD_SHA256), "maximumOpenFiles" to JsonPrimitive(7678)))
        for (name in LEGACY_VALID) {
            val base = document(resource("valid/$name.json"))
            for (extra in additions) reject(JsonObject(base + extra), "$name with ${extra.keys}")
        }
    }

    @Test
    fun `all literal legacy valid and reject fixtures retain their original meanings`() {
        val manifest = OracleJson.parse(resource("manifest.json")) as JsonObject
        val rows = (manifest.getValue("fixtures") as JsonArray).map { it as JsonObject }
        val valid = rows.filter { it["kind"] == JsonPrimitive("valid") }
        val invalid = rows.filter { it["kind"] == JsonPrimitive("reject") }
        assertEquals(LEGACY_VALID.map { "valid/$it.json" }.sorted(), valid.map { it.string("path") })
        assertEquals(19, invalid.size)
        for (row in valid + invalid) {
            val bytes = resource(row.string("path"))
            assertEquals(JsonPrimitive(bytes.size), row["bytes"])
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(bytes)), row["sha256"])
            OracleJson.parseCanonical(bytes)
            if (row in valid) {
                val parsed = KotlinContainedCommandRequest.parse(bytes)
                assertContentEquals(bytes, parsed.canonicalBytes)
                assertNull(parsed.fileDescriptorPolicy)
                assertNull(parsed.fileDescriptorPolicySha256)
                assertNull(parsed.maximumOpenFiles)
            } else {
                assertFails(row.string("path")) { KotlinContainedCommandRequest.parse(bytes) }
            }
        }
    }

    @Test
    fun `descriptor-only selection changes the request and cannot reuse strict v3 HMAC events`() {
        for (interruption in listOf(false, true)) {
            val legacy = request(interruption, policy = null)
            val selected = request(interruption)
            assertEquals(JsonPrimitive(3), document(legacy.canonicalBytes)["schemaVersion"])
            assertEquals(JsonPrimitive(5), document(selected.canonicalBytes)["schemaVersion"])
            assertEquals(legacy.command, selected.command)
            assertEquals(legacy.environment, selected.environment)
            assertEquals(legacy.runDirectory, selected.runDirectory)
            assertEquals(legacy.nonce, selected.nonce)
            assertEquals(legacy.allowInterruption, selected.allowInterruption)
            assertEquals(legacy.terminalResourcePolicySha256, selected.terminalResourcePolicySha256)
            assertCannotReuseEvents(legacy, selected)
            assertCannotReuseEvents(selected, legacy)
        }
    }

    @Test
    fun `same-wire v5 visibility changes cannot reuse HMAC even with a rewritten request hash`() {
        for (interruption in listOf(false, true)) {
            val requests = VISIBILITIES.map { request(interruption, it) }
            for (source in requests) for (target in requests.filter { it !== source }) {
                assertCannotReuseEvents(source, target)
            }
        }
    }

    @Test
    fun `all v5 variants retain strict pipe hashes and refuse absent or incorrect empty hashes`() {
        assertEquals("contained-command-v1", KotlinContainedCommandProtocol.VERSION)
        for (request in variants()) {
            val expected = outcome()
            val bytes = KotlinContainedCommandProtocol.outcome(SECRET, request, expected)
            assertEquals(expected, KotlinContainedCommandProtocol.requireOutcome(bytes, SECRET, request, KEEPER_PID))
            assertEquals(JsonPrimitive(OUT_SHA256), document(bytes)["stdoutSha256"])
            assertEquals(JsonPrimitive(ERR_SHA256), document(bytes)["stderrSha256"])
            for (event in listOf(KotlinContainedCommandProtocol.boot(SECRET, request, KEEPER_PID),
                KotlinContainedCommandProtocol.start(SECRET, request, KEEPER_PID), bytes)) {
                val decoded = document(event)
                assertEquals(JsonPrimitive(2), decoded["schemaVersion"])
                assertEquals(JsonPrimitive("kotlin-contained-command-protocol-v2"), decoded["provider"])
                assertEquals(JsonPrimitive(request.sha256), decoded["requestSha256"])
                assertTrue("stdoutSha256" in decoded && "stderrSha256" in decoded)
            }
            for (invalid in listOf(expected.copy(stdoutSha256 = null), expected.copy(stderrSha256 = null),
                expected.copy(stdoutBytes = 0L), expected.copy(stderrBytes = 0L))) {
                assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.outcome(SECRET, request, invalid) }
            }
            val empty = expected.copy(stdoutBytes = 0L, stderrBytes = 0L, stdoutSha256 = EMPTY_OUTPUT_SHA256,
                stderrSha256 = EMPTY_OUTPUT_SHA256)
            val emptyBytes = KotlinContainedCommandProtocol.outcome(SECRET, request, empty)
            assertEquals(empty, KotlinContainedCommandProtocol.requireOutcome(emptyBytes, SECRET, request, KEEPER_PID))
        }
    }

    @Test
    fun `v5 interruption admission preserves interrupt and interrupted-outcome refusal`() {
        for (visibility in VISIBILITIES) {
            val denied = request(false, visibility)
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.interrupt(SECRET, denied, KEEPER_PID) }
            assertFailsWith<IllegalArgumentException> {
                KotlinContainedCommandProtocol.outcome(SECRET, denied, outcome().copy(status = "INTERRUPTED"))
            }
            val admitted = request(true, visibility)
            val interrupt = KotlinContainedCommandProtocol.interrupt(SECRET, admitted, KEEPER_PID)
            KotlinContainedCommandProtocol.requireInterrupt(interrupt, SECRET, admitted, KEEPER_PID)
            val expected = outcome().copy(status = "INTERRUPTED")
            val bytes = KotlinContainedCommandProtocol.outcome(SECRET, admitted, expected)
            assertEquals(expected, KotlinContainedCommandProtocol.requireOutcome(bytes, SECRET, admitted, KEEPER_PID))
        }
    }

    private fun assertV5(interruption: Boolean, visibility: String?) {
        val expected = authoredRequest(interruption, visibility)
        OracleJson.parseCanonical(expected)
        val constructed = request(interruption, visibility)
        val parsed = KotlinContainedCommandRequest.parse(expected)
        for (actual in listOf(constructed, parsed)) {
            assertContentEquals(expected, actual.canonicalBytes)
            assertEquals(OracleArtifacts.sha256(expected), actual.sha256)
            assertEquals(POLICY, actual.fileDescriptorPolicy)
            assertEquals(FD_SHA256, actual.fileDescriptorPolicySha256)
            assertEquals(7678L, actual.maximumOpenFiles)
            assertEquals(TERMINAL_SHA256, actual.terminalResourcePolicySha256)
            assertEquals(visibility, actual.retainedInputVisibilitySha256)
            assertEquals(interruption, actual.allowInterruption)
        }
    }

    private fun assertCannotReuseEvents(source: KotlinContainedCommandRequest, target: KotlinContainedCommandRequest) {
        assertNotEquals(source.sha256, target.sha256)
        val boot = KotlinContainedCommandProtocol.boot(SECRET, source, KEEPER_PID)
        val start = KotlinContainedCommandProtocol.start(SECRET, source, KEEPER_PID)
        val outcomeBytes = KotlinContainedCommandProtocol.outcome(SECRET, source, outcome())
        for (bytes in listOf(boot, start, outcomeBytes)) {
            assertEquals(JsonPrimitive(2), document(bytes)["schemaVersion"])
            assertEquals(JsonPrimitive("kotlin-contained-command-protocol-v2"), document(bytes)["provider"])
        }
        assertEquals(KEEPER_PID, KotlinContainedCommandProtocol.requireBoot(boot, SECRET, source))
        KotlinContainedCommandProtocol.requireStart(start, SECRET, source, KEEPER_PID)
        assertEquals(outcome(), KotlinContainedCommandProtocol.requireOutcome(outcomeBytes, SECRET, source, KEEPER_PID))
        for (rewrite in listOf(false, true)) {
            fun substitute(bytes: ByteArray) = if (!rewrite) bytes else OracleJson.canonicalBytes(
                changed(document(bytes), "requestSha256", JsonPrimitive(target.sha256)))
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(substitute(boot), SECRET, target) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(substitute(start), SECRET, target, KEEPER_PID) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(substitute(outcomeBytes), SECRET, target, KEEPER_PID) }
        }
    }

    private fun request(
        interruption: Boolean = false,
        visibility: String? = null,
        terminal: String? = TERMINAL_SHA256,
        policy: ContainedCommandFileDescriptorPolicy? = POLICY,
    ) = KotlinContainedCommandRequest(Path.of(RUN_DIRECTORY), NONCE, listOf("/usr/bin/java", "-version"),
        mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 30L, 30L, 1024L, 1024L,
        allowInterruption = interruption, terminalResourcePolicySha256 = terminal,
        retainedInputVisibilitySha256 = visibility, fileDescriptorPolicy = policy)

    private fun variants() = listOf(false, true).flatMap { interruption -> VISIBILITIES.map { request(interruption, it) } }

    private fun outcome() = KotlinContainedCommandOutcome(KEEPER_PID, 124L, 0, 1L, 1L, 1L, "EXITED", OUT_SHA256, ERR_SHA256)

    private fun reject(value: JsonObject, message: String) {
        val bytes = OracleJson.canonicalBytes(value)
        OracleJson.parseCanonical(bytes)
        assertFails(message) { KotlinContainedCommandRequest.parse(bytes) }
    }

    private fun changed(value: JsonObject, field: String, replacement: JsonElement) = JsonObject(value + (field to replacement))
    private fun document(bytes: ByteArray) = OracleJson.parseCanonical(bytes) as JsonObject
    private fun JsonObject.string(field: String) = (getValue(field) as JsonPrimitive).content

    private fun resource(path: String): ByteArray = checkNotNull(javaClass.getResourceAsStream(
        "/oracle/contained-command-compatibility-v1/$path")) { "missing unchanged compatibility fixture: $path" }.use {
        val bytes = it.readNBytes(32 * 1024 + 1)
        assertTrue(bytes.size <= 32 * 1024)
        bytes
    }

    /** Literal authored JSON, independent of the production request renderer and policy preimage renderer. */
    private fun authoredRequest(interruption: Boolean, visibility: String?): ByteArray {
        val text = """
            {
              "allowInterruption": $interruption,
              "command": [
                "/usr/bin/java",
                "-version"
              ],
              "environment": {
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "TZ": "UTC"
              },
              "fileDescriptorPolicySha256": "$FD_SHA256",
              "maximumOpenFiles": 7678,
              "maximumStartWaitSeconds": 30,
              "maximumStderrBytes": 1024,
              "maximumStdoutBytes": 1024,
              "maximumWallSeconds": 30,
              "nonce": "$NONCE",
              "provider": "kotlin-contained-command-request-v5",
              "retainedInputVisibilitySha256": "${visibility ?: "absent"}",
              "runDirectory": "$RUN_DIRECTORY",
              "schemaVersion": 5,
              "terminalResourcePolicySha256": "$TERMINAL_SHA256"
            }
        """.trimIndent()
        return ((if (visibility == null) text.replace("  \"retainedInputVisibilitySha256\": \"absent\",\n", "") else text) + "\n")
            .toByteArray()
    }

    private companion object {
        val POLICY = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION
        val NONCE = "a".repeat(64)
        val RUN_DIRECTORY = "/srv/contained/control-$NONCE"
        val SECRET = ByteArray(KotlinContainedCommandProtocol.SECRET_BYTES) { 7 }
        val OUT_SHA256 = OracleArtifacts.sha256(byteArrayOf(42))
        val ERR_SHA256 = OracleArtifacts.sha256(byteArrayOf(43))
        val EMPTY_OUTPUT_SHA256 = OracleArtifacts.sha256(byteArrayOf())
        const val KEEPER_PID = 123L
        const val FD_SHA256 = "b75fa01e0ae402ab7db53e24ede656d0bec06748e27b758296b9f436d1e24d4b"
        const val TERMINAL_SHA256 = "0ec1e4b96307285671feb32a2af352c8e410635b0a7255328ba0f745f7450ddd"
        const val SELECTED_SHA256 = "1ac48539e63eb1f264ee497f706db11c37c8bca65df212b9fdf5bdd1c081bb45"
        const val EMPTY_SHA256 = "432f7700999c3c9e74215a14dc4ed31d239b4ac3c61232c55115b3661a9959b1"
        val VISIBILITIES = listOf(null, SELECTED_SHA256, EMPTY_SHA256)
        val LEGACY_VALID = listOf("v1-ordinary-interruption-omitted", "v2-interruption-true", "v3-terminal-interruption-omitted",
            "v3-terminal-interruption-true", "v4-visibility-interruption-false", "v4-visibility-interruption-true")
    }
}
