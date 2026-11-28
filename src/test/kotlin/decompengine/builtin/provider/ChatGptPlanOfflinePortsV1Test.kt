package decompengine.builtin.provider

import decompengine.builtin.AccountBindingV2
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test
import java.time.Instant
import java.util.UUID

class ChatGptPlanOfflinePortsV1Test {
    @Test fun registryRevisionReadsAreStableAndCallbackFree() {
        val secrets = registry("abcdef")
        var deliveries = 0
        val guard = secrets.displayGuard { deliveries++ }
        guard.append("abc")
        val revision = secrets.registryRevision()
        repeat(8) { assertEquals(revision, secrets.registryRevision()) }
        synchronized(secrets) { assertEquals(revision, secrets.registryRevision()) }
        assertEquals(0, deliveries)
        guard.finishValidatedCompletion()
        assertEquals(1, deliveries)
        assertEquals(revision, secrets.registryRevision())
    }

    @Test fun registryRevisionChangesOnlyForAcceptedDistinctAdditions() {
        val secrets = registry()
        val initial = secrets.registryRevision()
        secrets.registerSynthetic("first")
        assertEquals(initial + 1, secrets.registryRevision())
        secrets.registerSynthetic("first")
        assertEquals(initial + 1, secrets.registryRevision())
        fixed(ModelFailureKind.MALFORMED_RESPONSE) { secrets.registerSynthetic("") }
        fixed(ModelFailureKind.RESOURCE_EXHAUSTED) { secrets.registerSynthetic("x".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES + 1)) }
        assertEquals(initial + 1, secrets.registryRevision())
        secrets.registerSynthetic("second")
        assertEquals(initial + 2, secrets.registryRevision())
    }

    @Test fun registryRevisionIsAcceptedBeforeReentrantSinkAndSurvivesItsFailure() {
        val secrets = registry("abcdef")
        val before = secrets.registryRevision()
        var callbacks = 0
        val guard = secrets.displayGuard {
            callbacks++
            assertEquals(before + 1, secrets.registryRevision())
            assertTrue(Thread.holdsLock(secrets))
            throw IllegalStateException("synthetic-cause")
        }
        guard.append("abc")
        fixed(ModelFailureKind.TRANSPORT) { secrets.registerSynthetic("abc") }
        assertEquals(before + 1, secrets.registryRevision())
        secrets.registerSynthetic("abc")
        assertEquals(before + 1, secrets.registryRevision())
        assertEquals(1, callbacks)
    }

    @Test fun credentialAndCatalogBindingsAreExplicitAndRedacted() {
        val binding = binding()
        val credential = OfflinePlanCredentialV1(binding, 7, Instant.parse("2030-01-01T00:00:00Z"), setOf("resource.invoke", "chatgpt.tokens.use.direct"), FakeBearer())
        assertEquals(setOf("resource.invoke", "chatgpt.tokens.use.direct"), credential.scopes)
        assertThrows(UnsupportedOperationException::class.java) { (credential.scopes as MutableSet).add("admin") }
        assertFalse(credential.toString().contains("FakeBearer"))
        val catalog = ChatGptCatalogSnapshotV1(binding.commitment(), 7, ChatGptCatalogV1(emptyList()))
        catalog.requireFor(credential)
        val otherBinding = AccountBindingV2(UUID.fromString("00000000-0000-0000-0000-000000000003"),
            binding.issuer, binding.hostId, binding.issuedClient, binding.verifiedSubjectCommitment, binding.authEpoch, binding.modelSlug)
        assertEquals(ModelFailureKind.AUTHORIZATION, assertThrows(ModelProviderException::class.java) {
            ChatGptCatalogSnapshotV1(otherBinding.commitment(), credential.generation, ChatGptCatalogV1(emptyList())).requireFor(credential)
        }.kind)
        assertEquals(ModelFailureKind.AUTHORIZATION,
            assertThrows(ModelProviderException::class.java) {
                ChatGptCatalogSnapshotV1(binding.commitment(), 8, ChatGptCatalogV1(emptyList())).requireFor(credential)
            }.kind)
    }

    @Test fun offlineCredentialValidationAndAcquisitionAreBounded() {
        val binding = binding()
        val tooMany = (0..OfflinePlanCredentialV1.MAX_SCOPES).map { "s$it" }.toSet()
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE, assertThrows(ModelProviderException::class.java) {
            OfflinePlanCredentialV1(binding, 0, Instant.EPOCH, tooMany, FakeBearer())
        }.kind)
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE, assertThrows(ModelProviderException::class.java) {
            OfflinePlanCredentialV1(binding, -1, Instant.EPOCH, emptySet(), FakeBearer())
        }.kind)
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE, assertThrows(ModelProviderException::class.java) {
            OfflinePlanCredentialV1(binding, 0, Instant.EPOCH, setOf("bad scope"), FakeBearer())
        }.kind)
        assertThrows(ModelProviderException::class.java) {
            OfflinePlanCredentialV1(binding, 0, Instant.EPOCH, setOf("bad\uD800"), FakeBearer())
        }
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE, assertThrows(ModelProviderException::class.java) {
            OfflineCredentialAcquisitionV1.Expired("bad", 0)
        }.kind)
        val ready = OfflineCredentialAcquisitionV1.Ready(OfflinePlanCredentialV1(binding, 1, Instant.EPOCH, OfflineCredentialAcquisitionV1.REQUIRED_SCOPES, FakeBearer()))
        assertEquals(OfflineCredentialAcquisitionV1.REQUIRED_SCOPES, ready.credential.scopes)
        assertTrue(OfflineCredentialAcquisitionV1.Expired("a".repeat(64), 1).toString().contains("redacted"))
        assertEquals(ModelFailureKind.AUTHORIZATION, assertThrows(ModelProviderException::class.java) {
            OfflineCredentialAcquisitionV1.Ready(OfflinePlanCredentialV1(binding, 1, Instant.EPOCH, setOf("resource.invoke"), FakeBearer()))
        }.kind)
    }

    @Test fun secretRegistryChecksBoundariesAndDoesNotEvict() {
        assertEquals(128, ChatGptPlanSecretsV1.MAX_ENTRIES)
        assertEquals(16 * 1024, ChatGptPlanSecretsV1.MAX_SECRET_BYTES)
        assertEquals(1024 * 1024, ChatGptPlanSecretsV1.MAX_TOTAL_BYTES)
        val secrets = ChatGptPlanSecretsV1()
        secrets.registerSynthetic("x".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES))
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertThrows(ModelProviderException::class.java) {
            secrets.registerSynthetic("y".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES + 1))
        }.kind)
        val empty = assertThrows(ModelProviderException::class.java) { secrets.registerSynthetic("") }
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE, empty.kind)
        assertEquals("ChatGptPlanSecretsV1(redacted)", secrets.toString())
        assertThrows(ModelProviderException::class.java) { secrets.registerSynthetic("\uD800") }
        repeat(ChatGptPlanSecretsV1.MAX_ENTRIES - 1) { secrets.registerSynthetic("s${it}z") }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { secrets.registerSynthetic("last-new") }.kind)

        val totalBound = ChatGptPlanSecretsV1()
        repeat(ChatGptPlanSecretsV1.MAX_TOTAL_BYTES / ChatGptPlanSecretsV1.MAX_SECRET_BYTES) { index ->
            totalBound.registerSynthetic("a".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES - 2) + index.toString().padStart(2, '0'))
        }
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED,
            assertThrows(ModelProviderException::class.java) { totalBound.registerSynthetic("overflow") }.kind)
    }

    @Test fun privateJsonRejectsDecodedKeyValueAndEscapedSecretsWithoutMutation() {
        val secrets = ChatGptPlanSecretsV1().also { it.registerSynthetic("fixture-token-😀") }
        val inputs = listOf(
            """{"fixture-token-\ud83d\ude00":"ordinary"}""",
            """{"k":"prefix fixture-token-😀 suffix"}""",
            """{"k":"fixture-token-\uD83D\uDE00"}""",
            """{"k":"fixture\u002dtoken-\ud83d\ude00"}""",
            """{"access_token":"harmless"}""",
        )
        inputs.forEach { raw ->
            val json = Json.parseToJsonElement(raw)
            val before = json.toString()
            assertEquals(ModelFailureKind.SECRET_EXPOSURE,
                assertThrows(ModelProviderException::class.java) { secrets.rejectCredentialsInPrivateJson(json) }.kind)
            assertEquals(before, json.toString())
        }
        secrets.rejectCredentialsInPrivateJson(Json.parseToJsonElement("""{"prompt":"normal text","count":0}"""))
        secrets.rejectCredentialsInPrivateJson(Json.parseToJsonElement("""{"nested":[{"note":"still ordinary"}]}"""))
    }

    @Test fun displayGuardRedactsFragmentedOverlappingRepeatedAndRotatedSecrets() {
        val secrets = ChatGptPlanSecretsV1().apply { registerSynthetic("aba"); registerSynthetic("bab") }
        val output = StringBuilder()
        val guard = secrets.displayGuard(output::append)
        assertEquals("ChatGptDisplayGuardV1(redacted)", guard.toString())
        guard.append("ok ab")
        guard.append("ab and bab then 😀 ")
        guard.append("ab") // held pending suffix is reconsidered after registration
        secrets.registerSynthetic("ab tail")
        guard.append(" tail")
        guard.finishValidatedCompletion()
        assertEquals("ok [REDACTED] and [REDACTED] then 😀 [REDACTED]", output.toString())
        assertFalse(output.toString().contains("aba"))
        assertFalse(output.toString().endsWith("b"))
        assertEquals(ModelFailureKind.TRANSPORT, assertThrows(ModelProviderException::class.java) { guard.append("after") }.kind)
    }


    @Test fun reentrantSecretAdditionCannotRestoreAnOlderSnapshot() {
        val secrets = ChatGptPlanSecretsV1().apply { registerSynthetic("abcd") }
        lateinit var secondOutput: StringBuilder
        val first = secrets.displayGuard { emitted ->
            if (emitted.startsWith("[REDACTED]")) secrets.registerSynthetic("b")
        }
        secondOutput = StringBuilder()
        val second = secrets.displayGuard(secondOutput::append)
        first.append("abc")
        second.append("a")
        secrets.registerSynthetic("a")
        second.append("!")
        second.append("b")
        second.finishValidatedCompletion()
        first.finishValidatedCompletion()
        assertEquals("[REDACTED]![REDACTED]", secondOutput.toString())
    }

    @Test fun completionFlushesOnlyValidatedTailFailureDiscardsAndCallbackFailureIsFixed() {
        val secrets = ChatGptPlanSecretsV1().apply { registerSynthetic("secret") }
        val out = StringBuilder()
        val failed = secrets.displayGuard(out::append)
        failed.append("visible sec")
        failed.discardOnFailure()
        assertEquals("visible ", out.toString())

        val completed = secrets.displayGuard(out::append)
        completed.append("secret")
        completed.finishValidatedCompletion()
        assertTrue(out.endsWith("[REDACTED]"))

        val throwing = secrets.displayGuard { throw IllegalStateException("secret") }
        val e = assertThrows(ModelProviderException::class.java) { throwing.append("abcdef") }
        assertEquals(ModelFailureKind.TRANSPORT, e.kind)
        assertNull(e.cause)
        assertFalse(e.toString().contains("secret"))
        assertThrows(ModelProviderException::class.java) { throwing.append("again") }
    }

    @Test fun displayGuardAcceptsNormalTextAndBoundsChunks() {
        val output = StringBuilder()
        val guard = ChatGptPlanSecretsV1().displayGuard(output::append)
        guard.append("ordinary ")
        guard.append("text 🙂")
        guard.finishValidatedCompletion()
        assertEquals("ordinary text 🙂", output.toString())
        val split = StringBuilder()
        val splitGuard = ChatGptPlanSecretsV1().apply { registerSynthetic("token-😀") }.displayGuard(split::append)
        splitGuard.append("token-\uD83D")
        splitGuard.append("\uDE00!")
        splitGuard.finishValidatedCompletion()
        assertEquals("[REDACTED]!", split.toString())
        val malformedOutput = StringBuilder()
        val malformed = ChatGptPlanSecretsV1().displayGuard(malformedOutput::append)
        malformed.append("prefix\uD800")
        assertEquals(ModelFailureKind.MALFORMED_RESPONSE,
            assertThrows(ModelProviderException::class.java) { malformed.finishValidatedCompletion() }.kind)
        assertEquals("prefix", malformedOutput.toString())
        assertEquals(ModelFailureKind.RESOURCE_EXHAUSTED, assertThrows(ModelProviderException::class.java) {
            ChatGptPlanSecretsV1().displayGuard {}.append("a".repeat(ChatGptPlanSecretsV1.MAX_DISPLAY_CHUNK_CHARS + 1))
        }.kind)
    }

    @Test fun reentrantCrossGuardAppendSeesAcceptedSecretBeforeAnySink() {
        val secrets = registry("abcdef")
        val output = StringBuilder()
        lateinit var second: ChatGptDisplayGuardV1
        val first = secrets.displayGuard { second.append("abc!") }
        second = secrets.displayGuard(output::append)
        first.append("abc")
        secrets.registerSynthetic("abc")
        first.finishValidatedCompletion()
        second.finishValidatedCompletion()
        assertEquals("[REDACTED]!", output.toString())
    }

    @Test fun registrationCallbackFailureFollowsAcceptanceAndLeavesSurvivorsCurrent() {
        val secrets = registry("abcdef")
        val first = secrets.displayGuard { throw AssertionError("synthetic-cause") }
        val output = StringBuilder()
        val second = secrets.displayGuard(output::append)
        first.append("abc")
        fixed(ModelFailureKind.TRANSPORT) { secrets.registerSynthetic("abc") }
        fixed(ModelFailureKind.SECRET_EXPOSURE) { secrets.rejectCredentialsInPrivateJson(JsonPrimitive("abc")) }
        secrets.registerSynthetic("abc")
        fixed(ModelFailureKind.TRANSPORT) { first.append("x") }
        second.append("abc!")
        second.finishValidatedCompletion()
        assertEquals("[REDACTED]!", output.toString())
    }

    @Test fun nestedPublicationSurvivesFailureAndReentrantGuardCreationCompletionAndDiscard() {
        val secrets = registry("abcdef")
        lateinit var second: ChatGptDisplayGuardV1
        lateinit var discarded: ChatGptDisplayGuardV1
        val late = StringBuilder()
        val secondOut = StringBuilder()
        val survivorOut = StringBuilder()
        val first = secrets.displayGuard {
            secrets.registerSynthetic("b")
            discarded.discardOnFailure()
            secrets.displayGuard(late::append).also { it.append("b!"); it.finishValidatedCompletion() }
            second.append("abc!b")
            second.finishValidatedCompletion()
            throw AssertionError("synthetic-cause")
        }
        second = secrets.displayGuard(secondOut::append)
        discarded = secrets.displayGuard { fail<Unit>("Discarded guard must never emit") }
        val survivor = secrets.displayGuard(survivorOut::append)
        first.append("abc")
        fixed(ModelFailureKind.TRANSPORT) { secrets.registerSynthetic("abc") }
        survivor.append("abc!b")
        survivor.finishValidatedCompletion()
        assertEquals("[REDACTED]![REDACTED]", secondOut.toString())
        assertEquals(secondOut.toString(), survivorOut.toString())
        assertEquals("[REDACTED]!", late.toString())
        fixed(ModelFailureKind.TRANSPORT) { discarded.append("b") }
    }

    @Test fun sameGuardReentryCommitsCoverageBeforeCallbackAndKeepsLatestSnapshot() {
        val secrets = registry("abcdef")
        val output = StringBuilder()
        lateinit var guard: ChatGptDisplayGuardV1
        var once = false
        guard = secrets.displayGuard {
            output.append(it)
            if (!once) {
                once = true
                secrets.registerSynthetic("def!")
                guard.append("def!")
            }
        }
        guard.append("abc")
        secrets.registerSynthetic("a")
        guard.finishValidatedCompletion()
        assertEquals("[REDACTED]", output.toString())
    }

    @Test fun laterPublicationSinkFailureStillUpdatesUnvisitedPendingSurvivor() {
        val secrets = registry("abcdef")
        val firstOut = StringBuilder()
        val first = secrets.displayGuard(firstOut::append)
        val failing = secrets.displayGuard { throw IllegalStateException("synthetic-cause") }
        val lastOut = StringBuilder()
        val last = secrets.displayGuard(lastOut::append)
        listOf(first, failing, last).forEach { it.append("abc") }
        fixed(ModelFailureKind.TRANSPORT) { secrets.registerSynthetic("abc") }
        last.finishValidatedCompletion() // no append or duplicate registration to repair the survivor
        first.finishValidatedCompletion()
        assertEquals("[REDACTED]", firstOut.toString())
        assertEquals("[REDACTED]", lastOut.toString())
        assertRevokedAndCleared(failing)
        assertRevokedAndCleared(last)
    }

    @Test fun failureDiscardClearsHeldCoverageAndLateRegistrationDoesNotRecallEmittedText() {
        val secrets = registry("abcdef")
        val output = StringBuilder()
        val guard = secrets.displayGuard(output::append)
        guard.append("abc")
        secrets.registerSynthetic("a")
        guard.discardOnFailure()
        guard.discardOnFailure()
        assertEquals("[REDACTED]", output.toString())
        assertRevokedAndCleared(guard)

        val late = registry()
        val visible = StringBuilder()
        val next = late.displayGuard(visible::append)
        next.append("previously visible!")
        late.registerSynthetic("previously visible")
        next.append("previously visible!")
        next.finishValidatedCompletion()
        assertEquals("previously visible![REDACTED]!", visible.toString())
    }

    @Test fun overlapCrossingCompletedMatchStaysEntirelyCovered() {
        assertEquals("[REDACTED]", display(listOf("aba", "bab"), listOf("aba", "b")))
    }

    @Test fun longerSecretSharingCompletedPrefixStaysEntirelyCovered() {
        assertEquals("[REDACTED]", display(listOf("abc", "abcdef"), listOf("abc", "def")))
    }

    @Test fun supplementaryOverlapCrossingCompletedMatchStaysEntirelyCovered() {
        assertEquals("[REDACTED]", display(listOf("é😀é"), listOf("é😀é", "😀é")))
    }

    @Test fun lateShorterRegistrationPreservesOriginalLongerMatchCoverage() {
        val secrets = registry("abcdef")
        val output = StringBuilder()
        val guard = secrets.displayGuard(output::append)
        guard.append("abc")
        secrets.registerSynthetic("a")
        guard.append("def")
        guard.finishValidatedCompletion()
        assertEquals("[REDACTED]", output.toString())
    }

    @Test fun everyPartitionAgreesWithIndependentCoverageOracleIncludingSurrogateSplits() {
        val fixtures = listOf(
            listOf("aba", "bab") to "!ababab?",
            listOf("abc", "abcdef") to "!abcdefabc?",
            listOf("é😀é") to "!é😀é😀é?",
            listOf("a", "aa", "aaa") to "!aaaaaa?",
            listOf("ab", "ba", "abab") to "!abababa?",
            listOf("😀", "😀é", "é😀") to "!😀é😀?",
            listOf("aba", "ababx") to "!ababz?",
            listOf("ab", "x") to "!abxab?",
        )
        for ((values, input) in fixtures) {
            val expected = coverageOracle(values, input)
            for (chunks in partitions(input)) {
                assertEquals(expected, display(values, listOf("") + chunks + ""), "partition=$chunks secrets=$values")
            }
        }
    }

    @Test fun lateRegistrationsArePartitionInvariantForStillHeldOrCoveredText() {
        for (added in listOf("a", "ab", "abc", "bc", "bcdef", "cde")) {
            for (before in partitions("abc")) for (after in partitions("def!")) {
                val secrets = registry("abcdef")
                val output = StringBuilder()
                val guard = secrets.displayGuard(output::append)
                before.forEach(guard::append)
                secrets.registerSynthetic(added)
                after.forEach(guard::append)
                guard.finishValidatedCompletion()
                assertEquals("[REDACTED]!", output.toString(), "addition=$added before=$before after=$after")
            }
        }
        // Already covered prefixes still participate in a newly registered longer secret.
        val secrets = registry("abc")
        val output = StringBuilder()
        val guard = secrets.displayGuard(output::append)
        guard.append("ab")
        secrets.registerSynthetic("abcdef")
        guard.append("c")
        guard.append("def")
        guard.finishValidatedCompletion()
        assertEquals("[REDACTED]", output.toString())
    }

    @Test fun coveragePersistsAfterPartialMatchDiesAndAcrossManyTrimmedChunks() {
        assertEquals("[REDACTED]bz", display(listOf("aba", "ababx"), listOf("aba", "b", "z")))
        val input = "ab".repeat(20_000)
        assertEquals("[REDACTED]", display(listOf("aba", "bab"), input.chunked(127)))
        val long = "a".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES)
        assertEquals("[REDACTED]!", display(listOf("a", long), (long + "!").chunked(1021)))
    }

    @Test fun rawLookbehindIsBoundedAndAllowsArbitraryMultibyteContext() {
        val secrets = registry("a".repeat(ChatGptPlanSecretsV1.MAX_SECRET_BYTES))
        val output = StringBuilder()
        val guard = secrets.displayGuard {
            assertNotNull(ChatGptPlanWireJsonV1.scalarUtf8Length(it, Int.MAX_VALUE))
            output.append(it)
        }
        val chunks = listOf("漢".repeat(8192), "漢".repeat(8192), "😀".repeat(4096), "漢".repeat(8192))
        for (chunk in chunks) {
            guard.append(chunk)
            // Inspect retention, not just final output: this must not buffer the whole invocation.
            val tail = guard.javaClass.getDeclaredField("tail").also { it.isAccessible = true }.get(guard) as String
            val covered = guard.javaClass.getDeclaredField("covered").also { it.isAccessible = true }.get(guard) as BooleanArray
            assertTrue(tail.length <= ChatGptPlanSecretsV1.MAX_SECRET_BYTES)
            assertEquals(tail.length, covered.size)
            assertNotNull(ChatGptPlanWireJsonV1.scalarUtf8Length(tail, 3 * ChatGptPlanSecretsV1.MAX_SECRET_BYTES))
        }
        guard.finishValidatedCompletion()
        assertEquals(chunks.joinToString(""), output.toString())
    }

    @Test fun numericPrivateSecretRejectsWithoutRewriting() {
        val secrets = registry("8675309")
        val value = Json.parseToJsonElement("""{"pin":8675309}""")
        val before = value.toString()
        fixed(ModelFailureKind.SECRET_EXPOSURE) { secrets.rejectCredentialsInPrivateJson(value) }
        assertEquals(before, value.toString())
    }

    @Test fun booleanPrivateSecretRejects() {
        fixed(ModelFailureKind.SECRET_EXPOSURE) { registry("true").rejectCredentialsInPrivateJson(JsonPrimitive(true)) }
    }

    @Test fun oversizedNonStringPrivateScalarRejects() {
        val value = Json.parseToJsonElement("1".repeat(ChatGptPlanSecretsV1.MAX_JSON_SCALAR_CHARS + 1))
        fixed(ModelFailureKind.RESOURCE_EXHAUSTED) { registry().rejectCredentialsInPrivateJson(value) }
    }

    @Test fun allPrimitiveContentsUseSecretAndAggregateBudgets() {
        for ((secret, raw) in listOf("null" to "null", "false" to "false", "e+4" to "1e+40", "125" to "-0.125")) {
            val value = Json.parseToJsonElement(raw)
            fixed(ModelFailureKind.SECRET_EXPOSURE) { registry(secret).rejectCredentialsInPrivateJson(value) }
            assertEquals(raw, value.toString())
        }
        val max = Json.parseToJsonElement("1".repeat(ChatGptPlanSecretsV1.MAX_JSON_SCALAR_CHARS))
        val secrets = registry()
        secrets.rejectCredentialsInPrivateJson(max)
        secrets.rejectCredentialsInPrivateJson(JsonArray(List(4) { max }))
        for (extra in listOf(JsonNull, JsonPrimitive(true), JsonPrimitive(false), JsonPrimitive(0))) {
            fixed(ModelFailureKind.RESOURCE_EXHAUSTED) { secrets.rejectCredentialsInPrivateJson(JsonArray(List(4) { max } + extra)) }
        }
        secrets.rejectCredentialsInPrivateJson(Json.parseToJsonElement("""[0,-12,1e+2,true,false,null,"ordinary"]"""))
    }

    private fun registry(vararg secrets: String) = ChatGptPlanSecretsV1().apply { secrets.forEach(::registerSynthetic) }

    private fun assertRevokedAndCleared(guard: ChatGptDisplayGuardV1) {
        fixed(ModelFailureKind.TRANSPORT) { guard.append("") }
        fixed(ModelFailureKind.TRANSPORT) { guard.finishValidatedCompletion() }
        val tail = guard.javaClass.getDeclaredField("tail").also { it.isAccessible = true }.get(guard)
        val covered = guard.javaClass.getDeclaredField("covered").also { it.isAccessible = true }.get(guard) as BooleanArray
        assertEquals("", tail)
        assertEquals(0, covered.size)
    }

    private fun fixed(kind: ModelFailureKind, action: () -> Unit) {
        val failure = assertThrows(ModelProviderException::class.java, action)
        assertEquals(kind, failure.kind)
        assertNull(failure.cause)
        assertEquals(0, failure.suppressed.size)
        assertEquals(ModelProviderException(kind).message, failure.message)
    }

    private fun display(secrets: List<String>, chunks: List<String>): String {
        val output = StringBuilder()
        val guard = registry(*secrets.toTypedArray()).displayGuard {
            assertNotNull(ChatGptPlanWireJsonV1.scalarUtf8Length(it, Int.MAX_VALUE))
            output.append(it)
        }
        chunks.forEach(guard::append)
        guard.finishValidatedCompletion()
        return output.toString()
    }

    /** Independent whole-input oracle: mark every character of every match, then union coverage. */
    private fun coverageOracle(secrets: List<String>, input: String): String {
        val covered = BooleanArray(input.length)
        for (start in input.indices) for (secret in secrets) {
            if (input.startsWith(secret, start)) for (i in start until start + secret.length) covered[i] = true
        }
        return buildString {
            for (i in input.indices) {
                if (!covered[i]) append(input[i])
                else if (i == 0 || !covered[i - 1]) append("[REDACTED]")
            }
        }
    }

    /** Enumerate every partition, including cuts between surrogate halves; input is test bounded. */
    private fun partitions(input: String): Sequence<List<String>> = sequence {
        require(input.length in 1..16)
        for (mask in 0 until (1 shl (input.length - 1))) {
            val chunks = ArrayList<String>()
            var start = 0
            for (i in 1 until input.length) if (mask and (1 shl (i - 1)) != 0) {
                chunks.add(input.substring(start, i))
                start = i
            }
            chunks.add(input.substring(start))
            yield(chunks)
        }
    }

    private class FakeBearer : OfflineBearerV1 { override fun toString() = "FakeBearer(redacted)" }
    private fun binding() = AccountBindingV2(UUID.fromString("00000000-0000-0000-0000-000000000001"),
        "https://auth.openai.com", UUID.fromString("00000000-0000-0000-0000-000000000002"), "oaiapp_fixture",
        "a".repeat(64), 3, "gpt-fixture")
}
