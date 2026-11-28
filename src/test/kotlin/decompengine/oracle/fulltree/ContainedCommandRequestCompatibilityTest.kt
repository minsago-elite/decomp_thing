package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test

/** Authored codec controls only: no process, filesystem admission, receipt or live authority. */
class ContainedCommandRequestCompatibilityTest {
    @Test
    fun `authored fixture inventory retains all exact source-derived bytes and provenance`() {
        val manifest = OracleJson.parse(resource("manifest.json")) as JsonObject
        assertEquals(JsonPrimitive(1), manifest["schemaVersion"])
        assertEquals(JsonPrimitive("contained-command-authored-compatibility-fixtures-v1"), manifest["provider"])
        val provenance = manifest.getValue("provenance") as JsonObject
        assertEquals(JsonPrimitive(".omo/a-series-20261025/module-compile-nofile-a46/integration-sequence/compatibility-fixtures"),
            provenance["sourcePacket"])
        assertEquals(JsonObject(mapOf(
            "a46" to JsonPrimitive("a46d25423c72ead7dc68db8ad473fddb90c8e576"),
            "b85" to JsonPrimitive("b85cbbc8a875546a3dc833ffa7379dd8f2a76059"),
        )), provenance["pinnedSourceCommits"])
        val rows = (manifest.getValue("fixtures") as JsonArray).map { it as JsonObject }
        val expected = VALID.map { "valid/$it.json" } + REJECT.map { "reject/$it.json" } +
            listOf("policies/terminal-policy.json", "policies/visibility-selected.json", "policies/visibility-empty.json")
        assertEquals(expected.sorted(), rows.map { (it.getValue("path") as JsonPrimitive).content })
        for (row in rows) {
            val path = (row.getValue("path") as JsonPrimitive).content
            val bytes = resource(path)
            assertEquals(setOf("path", "bytes", "sha256", "kind"), row.keys)
            assertEquals(JsonPrimitive(bytes.size), row["bytes"], path)
            assertEquals(JsonPrimitive(OracleArtifacts.sha256(bytes)), row["sha256"], path)
            assertEquals(JsonPrimitive(if (path.startsWith("policies/")) "policy" else path.substringBefore('/')),
                row["kind"], path)
            assertContentEquals(bytes, OracleJson.canonicalBytes(OracleJson.parseCanonical(bytes)), path)
        }
    }

    @Test
    fun `v1 ordinary request preserves authored bytes with interruption omitted`() {
        assertValid("v1-ordinary-interruption-omitted", version = 1, interruption = false)
    }

    @Test
    fun `v2 interruption request preserves authored bytes with explicit true`() {
        assertValid("v2-interruption-true", version = 2, interruption = true)
    }

    @Test
    fun `v3 terminal request preserves authored bytes with interruption omitted`() {
        assertValid("v3-terminal-interruption-omitted", version = 3, interruption = false, terminal = true)
    }

    @Test
    fun `v3 terminal request preserves authored bytes with explicit interruption true`() {
        assertValid("v3-terminal-interruption-true", version = 3, interruption = true, terminal = true)
    }

    @Test
    fun `v4 visibility request preserves authored bytes with explicit interruption false`() {
        assertValid("v4-visibility-interruption-false", version = 4, interruption = false, visibility = true)
    }

    @Test
    fun `v4 visibility request preserves authored bytes with explicit interruption true`() {
        assertValid("v4-visibility-interruption-true", version = 4, interruption = true, visibility = true)
    }

    @Test
    fun `v1 rejects explicit interruption false`() {
        assertRejected("v1-explicit-false")
    }

    @Test
    fun `v1 rejects explicit interruption true`() {
        assertRejected("v1-explicit-true")
    }

    @Test
    fun `v1 rejects a terminal policy under its old version`() {
        assertRejected("v1-terminal-with-old-version")
    }

    @Test
    fun `v2 rejects missing interruption`() {
        assertRejected("v2-missing-interruption")
    }

    @Test
    fun `v2 rejects false interruption`() {
        assertRejected("v2-false-interruption")
    }

    @Test
    fun `v2 rejects visibility under its old version`() {
        assertRejected("v2-visibility-with-old-version")
    }

    @Test
    fun `v3 rejects explicit interruption false`() {
        assertRejected("v3-explicit-false")
    }

    @Test
    fun `v3 rejects missing terminal policy`() {
        assertRejected("v3-missing-terminal")
    }

    @Test
    fun `v3 rejects unsupported terminal policy`() {
        assertRejected("v3-wrong-terminal")
    }

    @Test
    fun `v3 rejects mismatched provider`() {
        assertRejected("v3-provider-mismatch")
    }

    @Test
    fun `v3 rejects combined terminal and visibility policies without interruption`() {
        assertRejected("v3-terminal-plus-visibility")
    }

    @Test
    fun `v3 rejects combined terminal and visibility policies with interruption`() {
        assertRejected("v3-terminal-plus-visibility-interruption-true")
    }

    @Test
    fun `v4 rejects missing interruption`() {
        assertRejected("v4-missing-interruption")
    }

    @Test
    fun `v4 rejects string interruption`() {
        assertRejected("v4-string-interruption")
    }

    @Test
    fun `v4 rejects missing visibility digest`() {
        assertRejected("v4-missing-visibility")
    }

    @Test
    fun `v4 rejects invalid visibility digest`() {
        assertRejected("v4-invalid-visibility")
    }

    @Test
    fun `v4 rejects combined terminal and visibility policies with false interruption`() {
        assertRejected("v4-terminal-plus-visibility")
    }

    @Test
    fun `v4 rejects combined terminal and visibility policies with true interruption`() {
        assertRejected("v4-terminal-plus-visibility-interruption-true")
    }

    @Test
    fun `v4 rejects unexpected fields`() {
        assertRejected("v4-unexpected-field")
    }

    @Test
    fun `three authored policy preimages retain their exact production identities`() {
        assertEquals(TERMINAL_SHA256, OracleArtifacts.sha256(resource("policies/terminal-policy.json")))
        assertEquals(TERMINAL_SHA256, ContainedCommandTerminalResourceEvidence.policySha256)
        val selected = ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"),
            listOf(KotlinContainedCommandRetainedInput("reports/a", 1L, NONCE)))
        val empty = ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"), emptyList())
        assertContentEquals(resource("policies/visibility-selected.json"), OracleJson.canonicalBytes(selected.canonicalIdentity()))
        assertContentEquals(resource("policies/visibility-empty.json"), OracleJson.canonicalBytes(empty.canonicalIdentity()))
        assertEquals(SELECTED_SHA256, OracleArtifacts.sha256(OracleJson.canonicalBytes(selected.canonicalIdentity())))
        assertEquals(EMPTY_SHA256, OracleArtifacts.sha256(OracleJson.canonicalBytes(empty.canonicalIdentity())))
        assertNotEquals(SELECTED_SHA256, EMPTY_SHA256)
    }

    @Test
    fun `constructor refuses both named policies for either interruption state`() {
        for (interruption in listOf(false, true)) {
            assertFailsWith<IllegalArgumentException>("interruption=$interruption") {
                request(interruption = interruption, terminal = TERMINAL_SHA256, visibility = SELECTED_SHA256)
            }
        }
    }

    @Test
    fun `named digest slots retain separate meaning rather than inferring a mode from hash bytes`() {
        val terminal = request(terminal = TERMINAL_SHA256)
        // v4 accepts a digest's syntax, not evidence that any selected file exists.
        val visibility = request(visibility = TERMINAL_SHA256)
        assertEquals(JsonPrimitive(3), document(terminal.canonicalBytes)["schemaVersion"])
        assertEquals(JsonPrimitive(4), document(visibility.canonicalBytes)["schemaVersion"])
        assertEquals(TERMINAL_SHA256, visibility.retainedInputVisibilitySha256)
        assertEquals(null, visibility.terminalResourcePolicySha256)
        assertNotEquals(terminal.sha256, visibility.sha256)
        assertFailsWith<IllegalArgumentException> { request(terminal = SELECTED_SHA256) }
    }

    @Test
    fun `legacy runtime policy fields remain empty or exact interruption-only v2 fields`() {
        val ordinary = containedCommandRuntimePolicyFields(null, null, null)
        assertEquals(emptyMap<String, JsonElement>(), ordinary)
        assertContentEquals("{}\n".toByteArray(), OracleJson.canonicalBytes(JsonObject(ordinary)))
        assertRuntimeFields(mapOf(
            "interruptionPolicySha256" to JsonPrimitive(INTERRUPTION_SHA256),
            "commandRequestProvider" to JsonPrimitive("kotlin-contained-command-request-v2"),
        ), containedCommandRuntimePolicyFields(INTERRUPTION_SHA256, null, null))
    }

    @Test
    fun `terminal runtime fields preserve v3 provider and exact policy with optional interruption`() {
        for (interruption in listOf(null, INTERRUPTION_SHA256)) {
            val expected = mapOf(
                "terminalResourcePolicySha256" to JsonPrimitive(TERMINAL_SHA256),
                "commandRequestProvider" to JsonPrimitive("kotlin-contained-command-request-v3"),
            ) + interruptionFields(interruption)
            assertRuntimeFields(expected, containedCommandRuntimePolicyFields(interruption, TERMINAL_SHA256, null))
        }
    }

    @Test
    fun `visibility runtime fields preserve v4 provider full selected preimage and request digest`() {
        val policy = document(resource("policies/visibility-selected.json"))
        for (interruption in listOf(null, INTERRUPTION_SHA256)) {
            val actual = containedCommandRuntimePolicyFields(interruption, null, policy)
            assertRuntimeFields(mapOf(
                "retainedInputVisibility" to policy,
                "commandRequestProvider" to JsonPrimitive("kotlin-contained-command-request-v4"),
            ) + interruptionFields(interruption), actual)
            val bytes = OracleJson.canonicalBytes(actual.getValue("retainedInputVisibility"))
            assertContentEquals(resource("policies/visibility-selected.json"), bytes)
            assertEquals(request(interruption = interruption != null, visibility = SELECTED_SHA256)
                .retainedInputVisibilitySha256, OracleArtifacts.sha256(bytes))
        }
    }

    @Test
    fun `explicit empty visibility retains v4 fields and distinct runtime commitment from legacy and selected`() {
        val empty = document(resource("policies/visibility-empty.json"))
        val actual = containedCommandRuntimePolicyFields(null, null, empty)
        assertRuntimeFields(mapOf(
            "retainedInputVisibility" to empty,
            "commandRequestProvider" to JsonPrimitive("kotlin-contained-command-request-v4"),
        ), actual)
        assertEquals(EMPTY_SHA256, OracleArtifacts.sha256(OracleJson.canonicalBytes(actual.getValue("retainedInputVisibility"))))
        val hash = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(actual)))
        assertNotEquals(hash, OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(
            containedCommandRuntimePolicyFields(null, null, null)))))
        assertNotEquals(hash, OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(
            containedCommandRuntimePolicyFields(null, null, document(resource("policies/visibility-selected.json")))))))
    }

    @Test
    fun `runtime helper refuses combined policies with and without interruption`() {
        for (name in listOf("visibility-selected", "visibility-empty")) {
            val visibility = document(resource("policies/$name.json"))
            for (interruption in listOf(null, INTERRUPTION_SHA256)) {
                assertFailsWith<IllegalArgumentException>("$name, interruption=${interruption != null}") {
                    containedCommandRuntimePolicyFields(interruption, TERMINAL_SHA256, visibility)
                }
            }
        }
    }

    @Test
    fun `all old request modes retain their HMAC wire and reject cross-request boot start and outcome`() {
        // Every request shares command, path, nonce and budgets, isolating the policy/interruption distinction.
        val requests = listOf(request(), request(interruption = true), request(terminal = TERMINAL_SHA256),
            request(interruption = true, terminal = TERMINAL_SHA256), request(visibility = SELECTED_SHA256),
            request(interruption = true, visibility = SELECTED_SHA256))
        assertEquals(6, requests.map { it.sha256 }.toSet().size)
        for (source in requests) {
            val boot = KotlinContainedCommandProtocol.boot(SECRET, source, KEEPER_PID)
            val start = KotlinContainedCommandProtocol.start(SECRET, source, KEEPER_PID)
            val expectedOutcome = outcome(source)
            val outcome = KotlinContainedCommandProtocol.outcome(SECRET, source, expectedOutcome)
            assertEquals(KEEPER_PID, KotlinContainedCommandProtocol.requireBoot(boot, SECRET, source))
            KotlinContainedCommandProtocol.requireStart(start, SECRET, source, KEEPER_PID)
            assertEquals(expectedOutcome, KotlinContainedCommandProtocol.requireOutcome(outcome, SECRET, source, KEEPER_PID))
            val wire = if (source.terminalResourcePolicySha256 == null) 1 else 2
            for (bytes in listOf(boot, start, outcome)) {
                val decoded = document(bytes)
                assertEquals(JsonPrimitive(wire), decoded["schemaVersion"])
                assertEquals(JsonPrimitive("kotlin-contained-command-protocol-v$wire"), decoded["provider"])
                assertEquals(JsonPrimitive(source.sha256), decoded["requestSha256"])
                assertEquals(wire == 2, "stdoutSha256" in decoded)
                assertEquals(wire == 2, "stderrSha256" in decoded)
            }
            for (target in requests.filter { it !== source }) {
                assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(boot, SECRET, target) }
                assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(start, SECRET, target, KEEPER_PID) }
                assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(outcome, SECRET, target, KEEPER_PID) }
            }
        }
    }

    @Test
    fun `same-wire visibility policy substitution cannot reuse HMAC even after request hash replacement`() {
        val selected = request(visibility = SELECTED_SHA256)
        val empty = request(visibility = EMPTY_SHA256)
        assertNotEquals(selected.sha256, empty.sha256)
        for ((source, target) in listOf(selected to empty, empty to selected)) {
            val boot = KotlinContainedCommandProtocol.boot(SECRET, source, KEEPER_PID)
            val start = KotlinContainedCommandProtocol.start(SECRET, source, KEEPER_PID)
            val outcome = KotlinContainedCommandProtocol.outcome(SECRET, source, outcome(source))
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(boot, SECRET, target) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(start, SECRET, target, KEEPER_PID) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(outcome, SECRET, target, KEEPER_PID) }
            assertFailsWith<IllegalArgumentException> {
                KotlinContainedCommandProtocol.requireBoot(rebindRequestHash(boot, target), SECRET, target)
            }
            assertFailsWith<IllegalArgumentException> {
                KotlinContainedCommandProtocol.requireStart(rebindRequestHash(start, target), SECRET, target, KEEPER_PID)
            }
            assertFailsWith<IllegalArgumentException> {
                KotlinContainedCommandProtocol.requireOutcome(rebindRequestHash(outcome, target), SECRET, target, KEEPER_PID)
            }
        }
    }

    private fun assertValid(name: String, version: Int, interruption: Boolean, terminal: Boolean = false, visibility: Boolean = false) {
        val bytes = resource("valid/$name.json")
        val expected = request(interruption, if (terminal) TERMINAL_SHA256 else null, if (visibility) SELECTED_SHA256 else null,
            if (visibility) Path.of("/srv/contained/$ACTIVE") else Path.of("/srv/contained-run"), if (visibility) 10L else 30L)
        assertContentEquals(bytes, expected.canonicalBytes, "constructor: $name")
        val parsed = KotlinContainedCommandRequest.parse(bytes)
        assertContentEquals(bytes, parsed.canonicalBytes, "parser: $name")
        assertEquals(OracleArtifacts.sha256(bytes), parsed.sha256)
        assertEquals(expected.sha256, parsed.sha256)
        assertEquals(expected.runDirectory, parsed.runDirectory)
        assertEquals(expected.nonce, parsed.nonce)
        assertEquals(expected.command, parsed.command)
        assertEquals(expected.environment, parsed.environment)
        assertEquals(expected.maximumStartWaitSeconds, parsed.maximumStartWaitSeconds)
        assertEquals(expected.maximumWallSeconds, parsed.maximumWallSeconds)
        assertEquals(expected.maximumStdoutBytes, parsed.maximumStdoutBytes)
        assertEquals(expected.maximumStderrBytes, parsed.maximumStderrBytes)
        assertEquals(interruption, parsed.allowInterruption)
        assertEquals(expected.terminalResourcePolicySha256, parsed.terminalResourcePolicySha256)
        assertEquals(expected.retainedInputVisibilitySha256, parsed.retainedInputVisibilitySha256)
        val encoded = document(parsed.canonicalBytes)
        assertEquals(JsonPrimitive(version), encoded["schemaVersion"])
        assertEquals(JsonPrimitive("kotlin-contained-command-request-v$version"), encoded["provider"])
        assertEquals(if (version == 4 || interruption) JsonPrimitive(interruption) else null, encoded["allowInterruption"])
    }

    private fun assertRejected(name: String) {
        val bytes = resource("reject/$name.json")
        // The byte form is valid; the actual request decoder must reject its contract violation.
        OracleJson.parseCanonical(bytes)
        assertFails(name) { KotlinContainedCommandRequest.parse(bytes) }
    }

    private fun request(
        interruption: Boolean = false,
        terminal: String? = null,
        visibility: String? = null,
        directory: Path = Path.of("/srv/contained-run"),
        seconds: Long = 30L,
    ) = KotlinContainedCommandRequest(directory, NONCE, listOf("/usr/bin/java", "-version"),
        mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), seconds, seconds, 1024L, 1024L,
        allowInterruption = interruption, terminalResourcePolicySha256 = terminal, retainedInputVisibilitySha256 = visibility)

    private fun outcome(request: KotlinContainedCommandRequest): KotlinContainedCommandOutcome {
        val hash = if (request.terminalResourcePolicySha256 == null) null else OracleArtifacts.sha256(byteArrayOf(42))
        return KotlinContainedCommandOutcome(KEEPER_PID, 124L, 0, 1L, 1L, 1L, "EXITED", hash, hash)
    }

    private fun rebindRequestHash(bytes: ByteArray, target: KotlinContainedCommandRequest): ByteArray =
        OracleJson.canonicalBytes(JsonObject(document(bytes) + ("requestSha256" to JsonPrimitive(target.sha256))))

    private fun interruptionFields(hash: String?): Map<String, JsonElement> =
        hash?.let { mapOf("interruptionPolicySha256" to JsonPrimitive(it)) } ?: emptyMap()

    private fun assertRuntimeFields(expected: Map<String, JsonElement>, actual: Map<String, JsonElement>) {
        assertEquals(expected, actual)
        val expectedBytes = OracleJson.canonicalBytes(JsonObject(expected))
        val actualBytes = OracleJson.canonicalBytes(JsonObject(actual))
        assertContentEquals(expectedBytes, actualBytes)
        assertEquals(OracleArtifacts.sha256(expectedBytes), OracleArtifacts.sha256(actualBytes))
    }

    private fun document(bytes: ByteArray): JsonObject = OracleJson.parseCanonical(bytes) as JsonObject

    private fun resource(path: String): ByteArray = checkNotNull(javaClass.getResourceAsStream("/oracle/contained-command-compatibility-v1/$path")) {
        "missing authored compatibility resource: $path"
    }.use { stream ->
        val bytes = stream.readNBytes(32 * 1024 + 1)
        assertTrue(bytes.size <= 32 * 1024, "authored compatibility resource exceeds its bound: $path")
        bytes
    }

    private companion object {
        val NONCE = "a".repeat(64)
        val ACTIVE = "control-$NONCE"
        val SECRET = ByteArray(KotlinContainedCommandProtocol.SECRET_BYTES) { 7 }
        val INTERRUPTION_SHA256 = "b".repeat(64)
        const val KEEPER_PID = 123L
        const val TERMINAL_SHA256 = "0ec1e4b96307285671feb32a2af352c8e410635b0a7255328ba0f745f7450ddd"
        const val SELECTED_SHA256 = "1ac48539e63eb1f264ee497f706db11c37c8bca65df212b9fdf5bdd1c081bb45"
        const val EMPTY_SHA256 = "432f7700999c3c9e74215a14dc4ed31d239b4ac3c61232c55115b3661a9959b1"
        val VALID = listOf("v1-ordinary-interruption-omitted", "v2-interruption-true", "v3-terminal-interruption-omitted",
            "v3-terminal-interruption-true", "v4-visibility-interruption-false", "v4-visibility-interruption-true")
        val REJECT = listOf("v1-explicit-false", "v1-explicit-true", "v1-terminal-with-old-version", "v2-missing-interruption",
            "v2-false-interruption", "v2-visibility-with-old-version", "v3-explicit-false", "v3-missing-terminal", "v3-wrong-terminal",
            "v3-provider-mismatch", "v3-terminal-plus-visibility", "v3-terminal-plus-visibility-interruption-true",
            "v4-missing-interruption", "v4-string-interruption", "v4-missing-visibility", "v4-invalid-visibility",
            "v4-terminal-plus-visibility", "v4-terminal-plus-visibility-interruption-true", "v4-unexpected-field")
    }
}
