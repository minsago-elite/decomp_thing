package decompengine.acp

import com.agentclientprotocol.model.AuthMethod
import com.agentclientprotocol.model.AuthMethodId
import java.util.concurrent.TimeUnit
import kotlin.test.*
import kotlinx.serialization.json.*

class AcpAuthenticationInventoryTest {
    @Test fun `long private fragments are withheld at every alignment in operator previews`() {
        val secret = "0123456789abcdefghijklmnopqrstuvwxyzABCD"
        val fragments = listOf(secret.dropLast(1), secret.drop(1)) +
            (0..secret.length - 15).map { secret.substring(it, it + 15) }
        for (fragment in fragments) {
            val method = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("id-$fragment"), "Name $fragment", "Description $fragment")),
                listOf(secret)).methods.single()
            assertEquals("", method.namePreview)
            assertEquals("", method.descriptionPreview)
        }
        val controlSplit = secret.take(12) + '\u0001' + secret.drop(12)
        val normalized = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("id"), secret.dropLast(1), null)), listOf(controlSplit))
        assertEquals("", normalized.methods.single().namePreview)
    }

    @Test fun `fragment filtering retains unrelated text at the full private value budget`() {
        val values = List(4096) { it.toString().padStart(256, 'x') }
        val method = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("public"), "Public login", "Use your account")), values).methods.single()
        assertEquals("Public login", method.namePreview)
        assertEquals("Use your account", method.descriptionPreview)
    }

    @Test fun `control normalization precedes literal and credential preview redaction`() {
        val secret = "private-credential-fixture"
        for (control in listOf('\u0000', '\u0001', '\r', '\u007f')) {
            val splitSecret = secret.take(8) + control + secret.drop(8)
            val inventory = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("fixture"), splitSecret,
                    "Bearer" + control + " credential-pattern-fixture")), listOf(secret))
            assertFalse(inventory.methods.single().namePreview.contains(secret))
            assertTrue(inventory.methods.single().namePreview.contains("[redacted]"))
            assertFalse(inventory.methods.single().descriptionPreview.orEmpty().contains("credential-pattern-fixture"))
            assertTrue(inventory.methods.single().descriptionPreview.orEmpty().contains("[redacted]"))
            val normalizedPrivate = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("fixture"), secret, null)), listOf(splitSecret))
            assertFalse(normalizedPrivate.methods.single().namePreview.contains(secret))
            assertTrue(normalizedPrivate.methods.single().namePreview.contains("[redacted]"))
        }
    }

    @Test fun `preview truncation preserves supplementary Unicode boundaries`() {
        val key = "\ud83d\udd11"
        for (prefixLength in listOf(126, 127, 128)) {
            val idAndName = "x".repeat(prefixLength) + key + "tail"
            val description = "x".repeat(prefixLength + 128) + key + "tail"
            val method = AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId(idAndName), idAndName, description),
            ), emptyList()).methods.single()
            for (preview in listOf(method.namePreview, method.descriptionPreview!!)) {
                assertTrue(Charsets.UTF_8.newEncoder().canEncode(preview))
                assertTrue(preview.endsWith("… [preview truncated]"))
                assertEquals(prefixLength == 126, preview.contains(key))
            }
        }
    }

    @Test fun `replacement-marker matches cannot cause unbounded intermediate preview growth`() {
        val inventory = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("id"), "r".repeat(512), "r".repeat(2048)),
        ), listOf("r", "e", "d", "a", "c", "t", "[", "]"))
        val method = inventory.methods.single()
        assertEquals("[oversized text omitted]", method.namePreview)
        assertEquals("[oversized text omitted]", method.descriptionPreview)
    }

    @Test fun `unpaired surrogates fail as authentication inventory errors`() {
        for (invalid in listOf("\ud800", "\udc00", "\ud800x")) {
            for (method in listOf(
                AuthMethod.AgentAuth(AuthMethodId(invalid), "name", null),
                AuthMethod.AgentAuth(AuthMethodId("id"), invalid, null),
                AuthMethod.AgentAuth(AuthMethodId("id"), "name", invalid),
            )) {
                val failure = assertFailsWith<AcpProtocolFailure> {
                    AcpAuthenticationInventory.capture(listOf(method), emptyList())
                }
                assertEquals("ACP authentication inventory contains invalid Unicode", failure.message)
            }
        }
        val valid = AuthMethod.AgentAuth(AuthMethodId("id-\ud83d\udd11"), "name", "description")
        assertEquals(valid.id.value, AcpAuthenticationInventory.capture(listOf(valid), emptyList()).methods.single().id)
    }

    @Test fun `inventory commitment scope changes across JVM restarts`() {
        fun isolated(): List<String> {
            val process = ProcessBuilder(
                java.nio.file.Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-cp", System.getProperty("java.class.path"), AuthenticationCommitmentProcessFixture::class.java.name,
            ).apply {
                // Launcher diagnostics must never become part of the commitment protocol.
                // Exercise all supported launcher-option channels even in a clean parent JVM.
                environment()["JAVA_TOOL_OPTIONS"] = "-Ddecomp.fixture.javaToolOptions=true"
                environment()["JDK_JAVA_OPTIONS"] = "-Ddecomp.fixture.jdkJavaOptions=true"
                environment()["_JAVA_OPTIONS"] = "-Ddecomp.fixture.javaOptions=true"
                redirectError(ProcessBuilder.Redirect.DISCARD)
            }.start()
            try {
                assertTrue(process.waitFor(10, java.util.concurrent.TimeUnit.SECONDS))
                assertEquals(0, process.exitValue())
                val lines = process.inputStream.bufferedReader().readLines()
                assertEquals(2, lines.size)
                java.util.UUID.fromString(lines[0])
                assertTrue(lines[1].matches(Regex("[a-f0-9]{64}")))
                return lines
            } finally {
                if (process.isAlive) process.destroyForcibly()
                process.waitFor(5, java.util.concurrent.TimeUnit.SECONDS)
            }
        }
        val first = isolated()
        val second = isolated()
        assertNotEquals(first[0], second[0])
        assertNotEquals(first[1], second[1])
    }

    @Test fun `public commitments hide sensitive text while preserving same-scope comparisons`() {
        val marker = "private-fixture-value"
        val methods = listOf(
            AuthMethod.AgentAuth(AuthMethodId("agent"), "Name $marker", "Description $marker"),
            AuthMethod.TerminalAuth(AuthMethodId("terminal"), "Terminal", null,
                listOf("fixture"), mapOf("FIXTURE_VALUE" to marker)),
            AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "Future", null, "future",
                buildJsonObject { put("retained_field", marker) }),
        )
        val inventory = AcpAuthenticationInventory.capture(methods, listOf(marker))
        val repeated = AcpAuthenticationInventory.capture(methods, listOf(marker))
        assertEquals(inventory.commitment, repeated.commitment)
        assertEquals(inventory.commitmentScope, repeated.commitmentScope)
        java.util.UUID.fromString(inventory.commitmentScope)
        assertTrue(inventory.commitment.matches(Regex("[a-f0-9]{64}")))
        val payload = decompengine.oracle.core.OracleJson.canonicalBytes(buildJsonArray {
            methods.forEach { add(com.agentclientprotocol.rpc.ACPJson.encodeToJsonElement(AuthMethod.serializer(), it)) }
        })
        for (format in listOf("sdk-auth-methods-v1", inventory.commitmentFormat)) {
            val unkeyed = java.security.MessageDigest.getInstance("SHA-256").apply {
                update(format.toByteArray()); update(0.toByte())
            }.digest(payload).joinToString("") { "%02x".format(it) }
            assertNotEquals(unkeyed, inventory.commitment)
            assertFalse(inventory.toString().contains(unkeyed))
        }
        assertFalse(inventory.toString().contains(marker))
        inventory.methods.forEach {
            assertFalse(it.namePreview.contains(marker))
            assertFalse(it.descriptionPreview.orEmpty().contains(marker))
        }
    }

    @Test fun `numeric payload policy applies at the exact limit to metadata and unknown variants`() {
        // Preserve the token through SDK serialization so this tests the post-SDK admission boundary.
        fun methods(token: String): List<AuthMethod> {
            val payload = buildJsonObject { put("number", JsonUnquotedLiteral(token)) }
            return listOf(
                AuthMethod.AgentAuth(AuthMethodId("agent"), "name", null, payload),
                AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "name", null, "future", payload),
            )
        }
        for (token in listOf("1".repeat(256), "-" + "1".repeat(255), "1.25")) {
            for (method in methods(token)) {
                assertEquals(1, AcpAuthenticationInventory.capture(listOf(method), emptyList()).methods.size)
            }
        }
        for (token in listOf("1".repeat(257), "-" + "1".repeat(256), "1e309", "1e-310")) {
            for (method in methods(token)) {
                val failure = assertFailsWith<AcpAuthenticationInventoryFailure> {
                    AcpAuthenticationInventory.capture(listOf(method), emptyList())
                }
                assertEquals("ACP authentication inventory exceeds its payload limits", failure.message)
            }
        }
    }

    @Test fun `logout advertisement remains independent of methods and execution support`() {
        val absent = AcpAuthenticationInventory.capture(emptyList(), emptyList())
        val advertised = AcpAuthenticationInventory.capture(emptyList(), emptyList(), logoutAdvertised = true)
        assertFalse(absent.logoutAdvertised)
        assertTrue(advertised.logoutAdvertised)
        assertFalse(absent.logoutSupported)
        assertFalse(advertised.logoutSupported)
        assertTrue(advertised.methods.isEmpty())
        // The existing commitment describes method metadata, not logout authority.
        assertEquals(absent.commitment, advertised.commitment)
    }

    @Test fun `commitment covers variant payloads metadata and unknown raw fields`() {
        fun capture(method: AuthMethod) = AcpAuthenticationInventory.capture(listOf(method), emptyList())
        val environment = mutableMapOf("FIXTURE_CONTEXT" to "one")
        val terminal = AuthMethod.TerminalAuth(AuthMethodId("id"), "name", null, listOf("fixture"), environment)
        val initial = capture(terminal)
        assertEquals("sdk-auth-methods-hmac-sha256-v2", initial.commitmentFormat)
        assertNotEquals(initial.commitment, capture(terminal.copy(args = listOf("changed"))).commitment)
        environment["FIXTURE_CONTEXT"] = "two"
        assertNotEquals(initial.commitment, capture(terminal).commitment)
        assertEquals(capture(terminal).commitment,
            AcpAuthenticationInventory.capture(listOf(terminal), listOf("two")).commitment)
        val agent = AuthMethod.AgentAuth(AuthMethodId("id"), "name", null,
            buildJsonObject { put("a", 1); put("b", 2) })
        assertEquals(capture(agent).commitment, capture(agent.copy(_meta =
            buildJsonObject { put("b", 2); put("a", 1) })).commitment)
        assertNotEquals(capture(agent).commitment, capture(agent.copy(_meta =
            buildJsonObject { put("a", 2); put("b", 2) })).commitment)
        fun unknown(type: String, hint: String): AuthMethod = com.agentclientprotocol.rpc.ACPJson
            .decodeFromJsonElement(AuthMethod.serializer(), buildJsonObject {
                put("id", "id"); put("name", "name"); put("type", type); put("hint", hint)
            })
        assertNotEquals(capture(unknown("future-a", "one")).commitment, capture(unknown("future-b", "one")).commitment)
        assertNotEquals(capture(unknown("future-a", "one")).commitment, capture(unknown("future-a", "two")).commitment)
        assertFalse(initial.toString().contains("FIXTURE_CONTEXT"))
    }

    @Test fun `unknown authentication variants stay unsupported`() {
        val method = AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "future method", null,
            "future-type", kotlinx.serialization.json.JsonObject(emptyMap()))
        val inventory = AcpAuthenticationInventory.capture(listOf(method), emptyList())
        assertEquals("unknown", inventory.methods.single().variant)
        assertFalse(inventory.methods.single().loginSupported)
    }

    @Test fun `operator inventory preserves exact IDs but redacts display previews`() {
        val source = mutableListOf<AuthMethod>(AuthMethod.AgentAuth(AuthMethodId("method-id"),
            "login private-value", "Bearer private-value"))
        val inventory = AcpAuthenticationInventory.capture(source, listOf("private-value"))
        source.clear()
        val method = inventory.methods.single()
        assertEquals("method-id", method.id)
        assertEquals("agent", method.variant)
        assertFalse(method.loginSupported)
        assertFalse(method.namePreview.contains("private-value"))
        assertFalse(method.descriptionPreview!!.contains("private-value"))
        assertFalse(method.toString().contains("method-id"))
        assertFalse(inventory.toString().contains("private-value"))
        assertFailsWith<UnsupportedOperationException> { (inventory.methods as MutableList).clear() }
    }

    @Test fun `empty and changed inventories have deterministic commitments`() {
        val empty = AcpAuthenticationInventory.capture(emptyList(), emptyList())
        assertTrue(empty.methods.isEmpty())
        assertEquals(empty.commitment, AcpAuthenticationInventory.capture(emptyList(), emptyList()).commitment)
        val method = AuthMethod.AgentAuth(AuthMethodId("id"), "name", null)
        assertNotEquals(empty.commitment, AcpAuthenticationInventory.capture(listOf(method), emptyList()).commitment)
    }

    @Test fun `invisible format characters cannot hide configured credentials from previews`() {
        val secret = "credential-fixture"
        val obfuscated = secret.chunked(7).joinToString("\u200b")
        assertTrue(!obfuscated.contains(secret))
        val splitValue = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("fixture"), obfuscated, "Prefix $obfuscated")), listOf(secret))
        assertEquals("", splitValue.methods.single().namePreview)
        assertEquals("", splitValue.methods.single().descriptionPreview)
        val splitPrivate = AcpAuthenticationInventory.capture(listOf(
            AuthMethod.AgentAuth(AuthMethodId("fixture"), secret, null)), listOf(obfuscated))
        assertEquals("", splitPrivate.methods.single().namePreview)
    }

    @Test fun `complete inventory limits include metadata unsupported payloads depth and aggregate size`() {
        fun agent(index: Int, payload: JsonElement): AuthMethod = AuthMethod.AgentAuth(
            AuthMethodId("method-$index"), "name", null, payload)
        val oversized = buildJsonObject { put("private-key", "private-value".repeat(1500)) }
        var nested: JsonElement = JsonPrimitive("private-value")
        repeat(20) { nested = buildJsonArray { add(nested) } }
        val cases = listOf(
            listOf(agent(0, oversized)),
            listOf(AuthMethod.UnknownAuthMethod(AuthMethodId("future"), "name", null,
                "future", buildJsonObject { put("type", "future"); put("payload", oversized) })),
            listOf(agent(0, nested)),
            List(8) { agent(it, JsonPrimitive("x".repeat(9000))) },
            listOf(agent(0, buildJsonArray { repeat(4096) { add(0) } })),
        )
        for (methods in cases) {
            val error = assertFailsWith<AcpAuthenticationInventoryFailure> {
                AcpAuthenticationInventory.capture(methods, emptyList())
            }
            assertEquals("ACP authentication inventory exceeds its payload limits", error.message)
        }
        val accepted = AcpAuthenticationInventory.capture(listOf(agent(0,
            buildJsonObject { put("hint", "private-value") })), listOf("private-value"))
        assertEquals(1, accepted.methods.size)
        assertFalse(accepted.toString().contains("private-value"))
    }

    @Test fun `large flat metadata is rejected at the node cap before canonical sorting`() {
        val meta = buildJsonObject { repeat(400_000) { index -> put("k$index", index) } }
        assertTrue(meta.toString().toByteArray().size < 8 * 1024 * 1024)
        val startedAt = System.nanoTime()
        val failure = assertFailsWith<AcpAuthenticationInventoryFailure> {
            AcpAuthenticationInventory.capture(listOf(
                AuthMethod.AgentAuth(AuthMethodId("agent"), "name", null, meta)), emptyList())
        }
        val elapsedMillis = TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedAt)
        assertEquals("ACP authentication inventory exceeds its payload limits", failure.message)
        assertTrue(elapsedMillis < 2_000, "flat metadata validation unexpectedly blocked for ${elapsedMillis}ms")
    }

    @Test fun `ambiguous and excessive advertisements fail with fixed diagnostics`() {
        val method = AuthMethod.AgentAuth(AuthMethodId("secret-id"), "name", null)
        for (methods in listOf(listOf(method, method), List(33) { method },
            listOf(AuthMethod.AgentAuth(AuthMethodId("x".repeat(257)), "name", null)),
            listOf(AuthMethod.AgentAuth(AuthMethodId("id"), "x".repeat(513), null)))) {
            val error = assertFailsWith<AcpProtocolFailure> { AcpAuthenticationInventory.capture(methods, emptyList()) }
            assertFalse(error.message!!.contains("secret-id"))
        }
    }
}

/** A fresh JVM captures only an empty inventory; no ACP agent or authentication action runs. */
object AuthenticationCommitmentProcessFixture {
    @JvmStatic fun main(args: Array<String>) {
        val inventory = AcpAuthenticationInventory.capture(emptyList(), emptyList())
        println(inventory.commitmentScope)
        println(inventory.commitment)
    }
}
