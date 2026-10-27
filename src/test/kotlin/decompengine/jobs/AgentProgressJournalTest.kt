package decompengine.jobs

import decompengine.agent.*
import kotlinx.serialization.json.*
import java.nio.file.Files
import kotlin.io.path.createTempDirectory
import kotlin.io.path.fileSize
import kotlin.test.*

class AgentProgressJournalTest {

    @Test
    fun `historical replay withholds old prose while preserving typed facts and commitments`() {
        val record = buildJsonObject {
            put("sequence", 19); put("runId", "writer-1"); put("workflow", "repair")
            put("time", "2026-10-18T00:00:00Z"); put("kind", "message"); put("agentSequence", 7)
            put("taskId", "PRIVATE_TASK"); put("workflowRunId", "PRIVATE_RUN")
            put("revisionId", "PRIVATE_REVISION"); put("path", "/PRIVATE_ROOT/input")
            put("text", "Authorization: [redacted] old-private-tail")
            put("entries", buildJsonArray { add(buildJsonObject { put("text", "PRIVATE_PLAN") }) })
            put("future_PRIVATE_FIELD", "PRIVATE_VALUE")
            put("taskIdSha256", "a".repeat(64)); put("workflowRunIdSha256", "b".repeat(64))
            put("revisionIdSha256", "c".repeat(64)); put("requestSha256", "d".repeat(64))
            put("inputTokens", 11); put("contextWindowTokens", "9007199254740993")
            put("reportedCostAmount", "-0.0"); put("reportedCostCurrency", "USD")
            put("phase", "provisional"); put("role", "assistant"); put("completed", true)
            put("validationPending", true); put("textOmitted", false); put("entriesTruncated", false)
        }
        val expected = buildJsonObject {
            put("sequence", 19); put("runId", "writer-1"); put("workflow", "repair")
            put("time", "2026-10-18T00:00:00Z"); put("kind", "message"); put("agentSequence", 7)
            put("taskIdSha256", "a".repeat(64)); put("workflowRunIdSha256", "b".repeat(64))
            put("revisionIdSha256", "c".repeat(64)); put("requestSha256", "d".repeat(64))
            put("inputTokens", 11); put("contextWindowTokens", "9007199254740993")
            put("reportedCostAmount", "-0.0"); put("reportedCostCurrency", "USD")
            put("phase", "provisional"); put("role", "assistant"); put("completed", true)
            put("validationPending", true); put("textOmitted", true); put("entriesTruncated", false)
            put("replayOmittedFields", 7)
        }
        val replay = replayProgressRecord(record)
        assertEquals(expected, replay)
        assertEquals(replay, replayProgressRecord(replay))
        assertEquals(publicProgressRecord(record), publicProgressRecord(replay))
        assertTrue(record.toString().contains("old-private-tail"))
        for (privateText in listOf("PRIVATE_", "old-private-tail", "Authorization", "[redacted]")) {
            assertFalse(replay.toString().contains(privateText))
        }
        assertFalse("acceptedRevisionSha256" in replay)
    }

    @Test
    fun `historical replay bounds fields and omission counts without inventing legacy metadata`() {
        val sparse = buildJsonObject { put("sequence", 0) }
        assertEquals(sparse, replayProgressRecord(sparse))
        val maximal = buildJsonObject {
            put("sequence", 0)
            repeat(127) { put("private-$it", "PRIVATE_VALUE") }
        }
        assertEquals(buildJsonObject { put("sequence", 0); put("replayOmittedFields", 127) }, replayProgressRecord(maximal))
        assertFailsWith<IllegalArgumentException> {
            replayProgressRecord(JsonObject(maximal + ("one-more" to JsonPrimitive("PRIVATE_VALUE"))))
        }
        val base = buildJsonObject { put("sequence", 0); put("kind", "message") }
        for (invalid in listOf(JsonPrimitive(-1), JsonPrimitive("1"), JsonPrimitive(true), JsonObject(emptyMap()))) {
            assertFailsWith<IllegalArgumentException> {
                replayProgressRecord(JsonObject(base + ("replayOmittedFields" to invalid)))
            }
        }
        val maximum = JsonObject(base + ("replayOmittedFields" to JsonPrimitive(Int.MAX_VALUE)))
        assertEquals(maximum, replayProgressRecord(maximum))
        assertEquals(maximum, replayProgressRecord(replayProgressRecord(maximum)))
        for (record in listOf(JsonObject(maximum + ("text" to JsonPrimitive("PRIVATE_VALUE"))),
            JsonObject(base + mapOf("text" to JsonPrimitive("PRIVATE_VALUE"), "replayOmittedFields" to JsonPrimitive(Int.MAX_VALUE))))) {
            assertFailsWith<ArithmeticException> { replayProgressRecord(record) }
        }
        for ((key, value) in listOf("requestSha256" to JsonPrimitive("PRIVATE_INVALID_DIGEST"),
            "inputTokens" to JsonPrimitive("1e3"), "completed" to JsonPrimitive("true"),
            "reportedCostAmount" to JsonPrimitive("-0.1"), "reportedCostAmount" to JsonPrimitive("NaN"),
            "reportedCostAmount" to JsonPrimitive("Infinity"), "reportedCostAmount" to JsonPrimitive("-0.00"))) {
            assertFailsWith<IllegalArgumentException> { replayProgressRecord(JsonObject(base + (key to value))) }
        }
        for (key in listOf("time", "wallClock")) {
            val failure = assertFailsWith<IllegalArgumentException> {
                replayProgressRecord(JsonObject(base + (key to JsonPrimitive("PRIVATE_INVALID_TIME"))))
            }
            assertFalse(failure.message.orEmpty().contains("PRIVATE_INVALID_TIME"))
            assertNull(failure.cause)
        }
        val unknown = replayProgressRecord(JsonObject(base + mapOf(
            "workflow" to JsonPrimitive("PRIVATE_WORKFLOW"), "kind" to JsonPrimitive("PRIVATE_KIND"),
            "role" to JsonPrimitive("PRIVATE_ROLE"))))
        assertEquals("unknown", unknown.getValue("workflow").jsonPrimitive.content)
        assertEquals("unknown", unknown.getValue("kind").jsonPrimitive.content)
        assertEquals(1, unknown.getValue("replayOmittedFields").jsonPrimitive.int)
        assertFalse(unknown.toString().contains("PRIVATE"))
    }

    @Test
    fun `complete configured diagnostic secrets survive format matching only as masked coverage`() {
        for (secret in listOf("top secret", "top,secret", "top;secret", "top\nsecret", "top\u0001 secret")) {
            for (redactor in listOf(ProgressRedactor(listOf(secret)), ProgressRedactor(emptyList(), listOf(secret)))) {
                for (prefix in listOf("password=", "Bearer ", "Authorization: Basic ")) {
                    val safe = redactor.text(prefix + secret + "; public tail")
                    assertFalse(safe.contains("top"))
                    assertFalse(safe.contains("secret"))
                    assertTrue(safe.contains("public tail"))
                }
            }
        }
        val cases = listOf("ababa" to "aba", "aaaaaa" to "aa", "abc" to "abc", "ab" to "abcd",
            "😀😀" to "😀", "a\uD800b\uD800" to "\uD800")
        for ((source, literal) in cases) {
            val starts = IntArray(source.length + 1)
            val ends = IntArray(source.length + 1)
            ProgressLiteralSecret(literal).markCoverage(source, starts, ends)
            val expected = BooleanArray(source.length)
            for (position in 0..source.length - literal.length) if (source.startsWith(literal, position)) {
                for (offset in literal.indices) expected[position + offset] = true
            }
            var active = 0
            for (index in source.indices) {
                active += starts[index] - ends[index]
                assertEquals(expected[index], active > 0)
            }
        }
        val labelAndValue = ProgressRedactor(listOf("Bearer", "top secret"))
        val safe = labelAndValue.text("Bearer top secret; public")
        assertFalse(safe.contains("Bearer"))
        assertFalse(safe.contains("top"))
        assertFalse(safe.contains("secret"))
        assertTrue(safe.contains("public"))
        val token = "unconfigured-private-credential"
        for (separator in listOf('\u000b', '\u000c', '\r')) {
            for (prefix in listOf("Bearer$separator", "Authorization:${separator}Basic$separator", "password=$separator")) {
                assertFalse(ProgressRedactor(emptyList()).text("before; $prefix$token; public").contains(token))
            }
        }
        val raw = "Bearer\u000cfirst; Bearer\u000bsecond"
        val cursor = OriginalCredentialSpanCursor(raw, Regex("(?i)(bearer\\s+)[^\\s,;]+"), true)
        for (value in listOf("first", "second")) {
            assertTrue(cursor.advance())
            val rawStart = raw.indexOf(value)
            val expectedStart = raw.substring(0, rawStart).replace(Regex("[\\p{Cntrl}&&[^\\n\\t]]"), "").length
            assertEquals(expectedStart, cursor.start)
            assertEquals(expectedStart + value.length, cursor.end)
        }
        assertFalse(cursor.advance())
    }

    @Test
    fun `indexed literal redaction preserves bounded replacement and UTF16 matching`(): Unit {
        val sources = mutableListOf("")
        var layer = listOf("")
        repeat(6) {
            layer = layer.flatMap { listOf(it + "a", it + "b") }
            sources.addAll(layer)
        }
        val high = 0xd800.toChar().toString()
        val low = 0xdc00.toChar().toString()
        val nul = 0.toChar().toString()
        val slash = 0x5c.toChar().toString()
        val dollar = 0x24.toChar().toString()
        sources.addAll(listOf(high, low, high + low, low + high, "a" + high + "b",
            high + high + low, "a" + nul + "b", "[a]", slash + "aba", dollar + "1"))
        val patterns = listOf("a", "b", "aa", "ab", "aba", "aab", "aaa", "abab", "baab", "bbbb",
            high, low, high + low, nul, "[", slash, dollar)
        val replacements = listOf("", "x", "aa", "[redacted]", dollar + "1")
        for (pattern in patterns) {
            val indexed = ProgressLiteralSecret(pattern)
            for (source in sources) {
                assertEquals(source.contains(pattern), indexed.occursIn(source))
                for (replacement in replacements) {
                    // The JDK's literal implementation is an independent small-input oracle.
                    val expected = source.replace(pattern, replacement)
                    for (limit in listOf(0, 1, 4, 16, 16_384)) {
                        assertEquals(expected.takeIf { it.length <= limit },
                            indexed.replaceBounded(source, replacement, limit))
                    }
                }
            }
        }
        val repeatedPrefix = "a".repeat(4095) + "b"
        val repeatedSource = "a".repeat(16_383) + "b"
        val indexed = ProgressLiteralSecret(repeatedPrefix)
        assertTrue(indexed.occursIn(repeatedSource))
        assertFalse(indexed.occursIn(repeatedSource.dropLast(1)))
        assertEquals(repeatedSource.replace(repeatedPrefix, "x"),
            indexed.replaceBounded(repeatedSource, "x", 16_384))
        val expanding = ProgressLiteralSecret("q")
        val exact = "q".repeat(1638) + "1234"
        assertEquals(16_384, assertNotNull(expanding.replaceBounded(exact, "[redacted]", 16_384)).length)
        assertNull(expanding.replaceBounded(exact + "5", "[redacted]", 16_384))
        assertEquals("", ProgressLiteralSecret("aa").replaceBounded("aaaaaaaa", "", 0))
        assertFailsWith<IllegalArgumentException> { ProgressLiteralSecret("") }
        assertFailsWith<IllegalArgumentException> { indexed.replaceBounded("", "x", -1) }
    }

    @Test
    fun `display commitments keep malformed UTF16 identities and interleaved messages distinct`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-identities").toAbsolutePath())
        val root = createTempDirectory(parent, "journal-")
        val identities = listOf(0xd800.toChar().toString(), 0xd801.toChar().toString(),
            0xdc00.toChar().toString(), "?", 0xfffd.toChar().toString(),
            charArrayOf(0xd83d.toChar(), 0xde00.toChar()).concatToString())
        // Independent commitment vectors: malformed UTF-16 uses ff + its raw big-endian units;
        // valid text keeps ordinary UTF-8, including literal question/replacement characters.
        val encoded = listOf(
            byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0x00),
            byteArrayOf(0xff.toByte(), 0xd8.toByte(), 0x01),
            byteArrayOf(0xff.toByte(), 0xdc.toByte(), 0x00),
            byteArrayOf(0x3f),
            byteArrayOf(0xef.toByte(), 0xbf.toByte(), 0xbd.toByte()),
            byteArrayOf(0xf0.toByte(), 0x9f.toByte(), 0x98.toByte(), 0x80.toByte()),
        )
        val commitments = encoded.map { bytes -> java.security.MessageDigest.getInstance("SHA-256")
            .digest(bytes).joinToString("") { "%02x".format(it) } }
        assertEquals(identities.size, commitments.distinct().size)
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("task", request(root))
            identities.forEachIndexed { index, id ->
                task.event(AgentMessageEvent(index.toLong(), id, AgentMessageRole.ASSISTANT, "message-$index"))
            }
            identities.forEachIndexed { index, id ->
                task.event(AgentMessageEvent((identities.size + index).toLong(), id,
                    AgentMessageRole.ASSISTANT, "-done", completed = true))
            }
            // Incomplete chunks publish only a commitment, never an invalid raw preview.
            identities.forEachIndexed { index, text ->
                task.event(AgentMessageEvent((2 * identities.size + index).toLong(), "content-$index",
                    AgentMessageRole.SYSTEM, text))
            }
        }
        val messages = assertNotNull(AgentProgressJournal.read(root)).getValue("events").jsonArray
            .map { it.jsonObject }.filter { it["kind"]?.jsonPrimitive?.content == "message" }
        assertEquals(3 * identities.size, messages.size)
        identities.indices.forEach { index ->
            assertEquals(commitments[index], messages[index].getValue("messageIdSha256").jsonPrimitive.content)
            val completed = messages[identities.size + index]
            assertEquals(commitments[index], completed.getValue("messageIdSha256").jsonPrimitive.content)
            assertEquals("message-$index-done", completed.getValue("text").jsonPrimitive.content)
            assertFalse(completed.getValue("textOmitted").jsonPrimitive.boolean)
            val content = messages[2 * identities.size + index]
            assertEquals(commitments[index], content.getValue("contentSha256").jsonPrimitive.content)
            assertFalse("text" in content)
        }
    }

    @Test
    fun `redaction bounds raw configuration and intermediate replacement work`(): Unit {
        val marker = "[oversized text omitted]"
        val redactor = ProgressRedactor(listOf("q"))
        val largeToken = "q".repeat(2000)
        // Budget literal replacement work even when no credential format consumes the input.
        assertEquals(marker, redactor.text("plain: $largeToken"))
        val exact = "plain: " + "q".repeat(1637) + "1234567"
        // 7 prefix + 1637 ten-character replacements + 7 suffix = 16384 exactly.
        val exactReplacement = "plain: " + "[redacted]".repeat(1637) + "1234567"
        assertEquals(16_384, exactReplacement.length)
        assertEquals(exactReplacement, redactor.text(exact, 16_384))
        assertEquals(marker, redactor.text(exact + "8"))
        // Format masking consumes credentials before literal replacement can expand them.
        assertEquals("Authorization: [redacted]", redactor.text("Authorization: Basic $largeToken"))
        assertEquals("Bearer [redacted]", redactor.text("Bearer $largeToken"))
        assertEquals("api_key=[redacted]", redactor.text("api_key=$largeToken"))
        assertEquals("Bearer [redacted]", redactor.text("Bearer ordinary-token"))
        val privateMarker = ProgressRedactor(listOf("q", marker))
        assertEquals("", privateMarker.text("plain: $largeToken"))
        assertEquals("", privateMarker.text(exact + "8"))
        assertRawRedactionBudgetAdmission()
    }

    private fun assertRawRedactionBudgetAdmission() {
        val tooManyWithoutIteration = object : AbstractCollection<String>() {
            override val size: Int get() = 4097
            override fun iterator(): Iterator<String> = error("oversized configuration must be refused before iteration")
        }
        val countFailure = assertFailsWith<IllegalArgumentException> { ProgressRedactor(tooManyWithoutIteration) }
        assertEquals("progress redaction values exceed the configured limit", countFailure.message)
        assertFailsWith<IllegalArgumentException> { ProgressRedactor(List(4097) { "q" }) }
        val oversizedBlank = " ".repeat(1024 * 1024 + 1)
        val lengthFailure = assertFailsWith<IllegalArgumentException> { ProgressRedactor(listOf(oversizedBlank)) }
        assertEquals("progress redaction values exceed the configured limit", lengthFailure.message)
        assertEquals("ordinary", ProgressRedactor(listOf(oversizedBlank.dropLast(1))).text("ordinary"))
        val fullPrimaryAndAdditional = ProgressRedactor(List(4096) { "q" }, List(130) { "mode" })
        assertEquals("[redacted] [redacted]", fullPrimaryAndAdditional.text("q mode"))
    }

    @Test
    fun `snapshot size planning preserves exact maximal suffix across Unicode gaps and counter boundaries`(): Unit {
        val fixtures = listOf(
            List(31) { it.toLong() },
            List(31) { it.toLong() * 3 },
            List(31) { 7L + it.toLong() * 3 },
            List(31) { Long.MAX_VALUE - 100 + it.toLong() * 2 },
            emptyList<Long>(),
            listOf(1L),
        )
        fixtures.forEachIndexed { fixture, sequences ->
            val next = listOf(31L, 94L, 101L, Long.MAX_VALUE - 1, 2L, 2L)[fixture]
            val initialHistory = listOf(0L, 0L, 7L, Long.MAX_VALUE - 100, 2L, 1L)[fixture]
            val queueLoss = next - initialHistory - sequences.size
            val records = sequences.mapIndexed { index, sequence -> buildJsonObject {
                put("sequence", sequence); put("runId", "fixture"); put("workflow", "repair")
                put("time", "2026-10-18T00:00:00Z"); put("kind", "message")
                put("text", when {
                    fixture == 2 && index == 30 -> "界\n\"\\😀".repeat(512)
                    index % 4 == 0 -> "界\n\"\\😀".repeat(128)
                    else -> "plain-$index".repeat(index % 5 + 1)
                })
            } }
            // Independent brute-force encoding is the previous eviction rule's byte oracle.
            fun candidate(removed: Int): JsonObject {
                val kept = records.drop(removed)
                var cursor = 0L
                val ranges = buildJsonArray {
                    for (record in kept) {
                        val sequence = record.getValue("sequence").jsonPrimitive.long
                        if (cursor < sequence) add(buildJsonObject {
                            put("startInclusive", cursor.toString()); put("endExclusive", sequence.toString())
                        })
                        cursor = sequence + 1
                    }
                    if (cursor < next) add(buildJsonObject {
                        put("startInclusive", cursor.toString()); put("endExclusive", next.toString())
                    })
                }
                return buildJsonObject {
                    put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", next)
                    put("queueDropped", queueLoss); put("historyDropped", initialHistory + removed)
                    put("truncated", queueLoss > 0 || initialHistory + removed > 0)
                    put("events", JsonArray(kept)); put("omittedSequenceRanges", ranges)
                }
            }
            val original = candidate(0)
            val originalBytes = original.toString().toByteArray(Charsets.UTF_8).size
            val budgets = (listOf(4096, 6144, 8192, 65_536, originalBytes - 1, originalBytes))
                .filter { it in 4096..AgentProgressJournal.MAXIMUM_READ_BYTES }.distinct()
            budgets.forEach { budget ->
                val expected = (0..records.size).first {
                    candidate(it).toString().toByteArray(Charsets.UTF_8).size <= budget
                }
                assertEquals(expected, AgentProgressJournal.prefixEvictionsToFit(original, budget), "fixture=$fixture budget=$budget")
                val retained = candidate(expected)
                val encoded = retained.toString().toByteArray(Charsets.UTF_8)
                assertTrue(encoded.size <= budget)
                assertEquals(retained, AgentProgressJournal.decode(encoded))
                if (expected > 0) assertTrue(candidate(expected - 1).toString().toByteArray(Charsets.UTF_8).size > budget)
            }
        }
    }

    @Test
    fun `saturated queue retains the last terminal phase and exact loss through the CLI projection`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-terminal").toAbsolutePath())
        val terminals = listOf(AgentWorkflowPhase.COMPLETED, AgentWorkflowPhase.UNRESOLVED, AgentWorkflowPhase.FAILED)
        for (limit in listOf(1, 128)) for (phases in terminals.map { listOf(it) } + listOf(terminals)) {
            val root = createTempDirectory(parent, "journal-")
            val entered = java.util.concurrent.CountDownLatch(1)
            val release = java.util.concurrent.CountDownLatch(1)
            val first = java.util.concurrent.atomic.AtomicBoolean(true)
            val journal = AgentProgressJournal.withSnapshotEncodeHooks(root, "reconstruction", {
                if (first.compareAndSet(true, false)) {
                    entered.countDown()
                    check(release.await(10, java.util.concurrent.TimeUnit.SECONDS))
                }
            }, {}, maximumQueuedEvents = limit)
            try {
                assertTrue(entered.await(10, java.util.concurrent.TimeUnit.SECONDS))
                val normalCount = limit + 128
                repeat(normalCount) { journal.phase(AgentWorkflowPhase.AGENT_RUNNING) }
                phases.forEach { journal.phase(it) }
                release.countDown()
                journal.close()
                val snapshot = assertNotNull(AgentProgressJournal.read(root))
                val lastSequence = (normalCount + phases.size).toLong()
                assertEquals(lastSequence + 1, snapshot.getValue("nextSequence").jsonPrimitive.long)
                assertEquals((128 + phases.size - 1).toLong(), snapshot.getValue("queueDropped").jsonPrimitive.long)
                assertEquals(0L, snapshot.getValue("historyDropped").jsonPrimitive.long)
                val events = snapshot.getValue("events").jsonArray.map { it.jsonObject }
                assertEquals((0L..limit.toLong()).toList() + lastSequence,
                    events.map { it.getValue("sequence").jsonPrimitive.long })
                assertEquals(phases.last().name.lowercase(), events.last().getValue("phase").jsonPrimitive.content)
                val range = snapshot.getValue("omittedSequenceRanges").jsonArray.single().jsonObject
                assertEquals((limit + 1).toString(), range.getValue("startInclusive").jsonPrimitive.content)
                assertEquals(lastSequence.toString(), range.getValue("endExclusive").jsonPrimitive.content)
                val cursor = decompengine.RepairCliProgressCursor(null, decompengine.CliProgressWorkflow.RECONSTRUCTION)
                val output = cursor.advance(snapshot, journal.journalRunId)
                assertEquals("reconstruction: ${phases.last().name.lowercase().replace('_', ' ')}", output.last())
                assertTrue(output.any { it.startsWith("reconstruction progress omitted ") })
                AgentProgressJournal(root, "reconstruction").use { }
                val restarted = assertNotNull(AgentProgressJournal.read(root))
                assertEquals(lastSequence + 2, restarted.getValue("nextSequence").jsonPrimitive.long)
                assertEquals(snapshot.getValue("queueDropped"), restarted.getValue("queueDropped"))
                assertEquals(events.map { it.getValue("sequence") },
                    restarted.getValue("events").jsonArray.dropLast(1).map { it.jsonObject.getValue("sequence") })
            } finally {
                release.countDown()
                journal.close()
                // Retain repository-local fixtures rather than deleting under an owned writer.
            }
        }
    }

    @Test
    fun `snapshot encoding releases producers and publishes one coherent loss boundary`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-encoding").toAbsolutePath())
        val root = createTempDirectory(parent, "journal-")
        val encoding = List(2) { java.util.concurrent.CountDownLatch(1) }
        val releaseEncoding = List(2) { java.util.concurrent.CountDownLatch(1) }
        val published = List(2) { java.util.concurrent.CountDownLatch(1) }
        val releasePublication = List(2) { java.util.concurrent.CountDownLatch(1) }
        val encodingCount = java.util.concurrent.atomic.AtomicInteger()
        val publicationCount = java.util.concurrent.atomic.AtomicInteger()
        val producers = mutableListOf<Thread>()
        val journal = AgentProgressJournal.withSnapshotEncodeHooks(root, "repair", {
            val cut = encodingCount.getAndIncrement()
            if (cut < 2) {
                encoding[cut].countDown()
                check(releaseEncoding[cut].await(10, java.util.concurrent.TimeUnit.SECONDS))
            }
        }, {
            val cut = publicationCount.getAndIncrement()
            if (cut < 2) {
                published[cut].countDown()
                check(releasePublication[cut].await(10, java.util.concurrent.TimeUnit.SECONDS))
            }
        }, maximumSnapshotBytes = 4096)
        var secondHistoryLoss = 0L
        try {
            for (cut in 0..1) {
                assertTrue(encoding[cut].await(10, java.util.concurrent.TimeUnit.SECONDS))
                val done = java.util.concurrent.CountDownLatch(1)
                val failure = java.util.concurrent.atomic.AtomicReference<Throwable?>()
                producers += Thread({
                    try {
                        repeat(if (cut == 0) 200 else 20) { journal.phase(AgentWorkflowPhase.AGENT_RUNNING) }
                    } catch (problem: Throwable) { failure.set(problem) }
                    finally { done.countDown() }
                }, "progress-producer-control-$cut").apply { isDaemon = true; start() }
                // Each coherent cut is still held; producer completion cannot depend on release.
                assertTrue(done.await(2, java.util.concurrent.TimeUnit.SECONDS))
                assertNull(failure.get())
                releaseEncoding[cut].countDown()
                assertTrue(published[cut].await(10, java.util.concurrent.TimeUnit.SECONDS))
                val snapshot = assertNotNull(AgentProgressJournal.read(root))
                val sequences = snapshot.getValue("events").jsonArray.map {
                    it.jsonObject.getValue("sequence").jsonPrimitive.long
                }
                val ranges = snapshot.getValue("omittedSequenceRanges").jsonArray.map {
                    it.jsonObject.getValue("startInclusive").jsonPrimitive.content to
                        it.jsonObject.getValue("endExclusive").jsonPrimitive.content
                }
                if (cut == 0) {
                    assertEquals(1L, snapshot.getValue("nextSequence").jsonPrimitive.long)
                    assertEquals(0L, snapshot.getValue("queueDropped").jsonPrimitive.long)
                    assertEquals(0L, snapshot.getValue("historyDropped").jsonPrimitive.long)
                    assertEquals(listOf(0L), sequences)
                    assertTrue(ranges.isEmpty())
                } else {
                    assertEquals(201L, snapshot.getValue("nextSequence").jsonPrimitive.long)
                    assertEquals(72L, snapshot.getValue("queueDropped").jsonPrimitive.long)
                    secondHistoryLoss = snapshot.getValue("historyDropped").jsonPrimitive.long
                    assertTrue(secondHistoryLoss in 1L..128L)
                    assertEquals((secondHistoryLoss..128L).toList(), sequences)
                    assertEquals(listOf("0" to secondHistoryLoss.toString(), "129" to "201"), ranges)
                    assertTrue(root.resolve(AgentProgressJournal.FILE_NAME).fileSize() <= 4096)
                }
                releasePublication[cut].countDown()
            }
            journal.close()
            val final = assertNotNull(AgentProgressJournal.read(root))
            assertEquals(221L, final.getValue("nextSequence").jsonPrimitive.long)
            assertEquals(72L, final.getValue("queueDropped").jsonPrimitive.long)
            val historyLoss = final.getValue("historyDropped").jsonPrimitive.long
            assertTrue(historyLoss in secondHistoryLoss..148L)
            val sequences = final.getValue("events").jsonArray.map {
                it.jsonObject.getValue("sequence").jsonPrimitive.long
            }
            val admitted = (0L..128L).toList() + (201L..220L).toList()
            assertEquals(admitted.drop(historyLoss.toInt()), sequences)
            val omitted = final.getValue("omittedSequenceRanges").jsonArray.flatMap {
                val range = it.jsonObject
                (range.getValue("startInclusive").jsonPrimitive.content.toLong() until
                    range.getValue("endExclusive").jsonPrimitive.content.toLong()).toList()
            }
            assertEquals((0L until 221L).toList(), (omitted + sequences).sorted())
            assertEquals(72L + historyLoss, omitted.size.toLong())
            assertTrue(root.resolve(AgentProgressJournal.FILE_NAME).fileSize() <= 4096)
            AgentProgressJournal(root, "repair").use { }
            val restarted = assertNotNull(AgentProgressJournal.read(root))
            assertEquals(222L, restarted.getValue("nextSequence").jsonPrimitive.long)
            assertEquals(72L, restarted.getValue("queueDropped").jsonPrimitive.long)
            assertEquals(historyLoss, restarted.getValue("historyDropped").jsonPrimitive.long)
            assertEquals(sequences + 221L, restarted.getValue("events").jsonArray.map {
                it.jsonObject.getValue("sequence").jsonPrimitive.long
            })
        } finally {
            releaseEncoding.forEach { it.countDown() }
            releasePublication.forEach { it.countDown() }
            producers.forEach { it.join(5000) }
            journal.close()
            // Keep the bounded repository-local fixture; do not delete under an owned writer.
        }
    }

    @Test
    fun `writer retires ownership after a timed out close once publication has stopped`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-late-writer").toAbsolutePath())
        val root = createTempDirectory(parent, "journal-")
        val entered = java.util.concurrent.CountDownLatch(1)
        val release = java.util.concurrent.CountDownLatch(1)
        val first = java.util.concurrent.atomic.AtomicBoolean(true)
        val ownedThread = java.util.concurrent.atomic.AtomicReference<Thread>()
        val journal = AgentProgressJournal.withSnapshotWriteHook(root, "repair") {
            if (first.compareAndSet(true, false)) {
                ownedThread.set(Thread.currentThread())
                entered.countDown()
                while (release.count > 0) try {
                    release.await()
                } catch (_: InterruptedException) { /* Model a noninterruptible owned publication. */ }
            }
        }
        try {
            assertTrue(entered.await(10, java.util.concurrent.TimeUnit.SECONDS))
            journal.phase(AgentWorkflowPhase.BUILD_VALIDATING)
            val failure = assertFailsWith<IllegalStateException> { journal.close() }
            assertEquals("progress writer did not stop within five seconds", failure.message)
            val contender = runCatching { AgentProgressJournal(root, "repair") }
            // Close an unexpectedly admitted owner before reporting the regression.
            contender.getOrNull()?.close()
            assertEquals("another workflow owns the progress journal",
                assertIs<IllegalArgumentException>(contender.exceptionOrNull()).message)
            release.countDown()
            val writer = assertNotNull(ownedThread.get())
            writer.join(5000)
            assertFalse(writer.isAlive)
            val flushed = assertNotNull(AgentProgressJournal.read(root))
            assertTrue(flushed.getValue("events").jsonArray.any {
                it.jsonObject["phase"]?.jsonPrimitive?.content == "build_validating"
            })
            // No retry of the original close occurs before this independent acquisition.
            AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.COMPLETED) }
            assertNotNull(AgentProgressJournal.read(root))
        } finally {
            release.countDown()
            ownedThread.get()?.join(5000)
            journal.close()
            // Keep the repository-local fixture; never delete under an unretired writer.
        }
    }

    @Test
    fun `sequence exhaustion preserves a readable boundary and releases rejected startup ownership`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-sequence-exhaustion").toAbsolutePath())
        val root = createTempDirectory(parent, "journal-")
        try {
            val initial = buildJsonObject {
                put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", Long.MAX_VALUE - 2)
                put("queueDropped", 0); put("historyDropped", Long.MAX_VALUE - 3); put("truncated", true)
                put("events", buildJsonArray { add(buildJsonObject { put("sequence", Long.MAX_VALUE - 3) }) })
            }
            Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), initial.toString())
            assertNotNull(AgentProgressJournal.read(root))
            AgentProgressJournal(root, "repair").use { journal ->
                val failure = assertFailsWith<IllegalStateException> { journal.phase(AgentWorkflowPhase.AGENT_RUNNING) }
                assertEquals("progress sequence space is exhausted", failure.message)
            }
            val snapshot = assertNotNull(AgentProgressJournal.read(root))
            assertEquals(Long.MAX_VALUE - 1, snapshot.getValue("nextSequence").jsonPrimitive.long)
            assertEquals(listOf(Long.MAX_VALUE - 3, Long.MAX_VALUE - 2), snapshot.getValue("events").jsonArray.map {
                it.jsonObject.getValue("sequence").jsonPrimitive.long
            })
            assertEquals(0L, snapshot.getValue("queueDropped").jsonPrimitive.long)
            assertEquals(Long.MAX_VALUE - 3, snapshot.getValue("historyDropped").jsonPrimitive.long)
            val lastReadable = Files.readAllBytes(root.resolve(AgentProgressJournal.FILE_NAME))
            repeat(2) {
                val attempt = runCatching { AgentProgressJournal(root, "repair") }
                // Close an unexpectedly admitted writer before reporting a regression failure.
                attempt.getOrNull()?.close()
                assertEquals("progress sequence space is exhausted", assertIs<IllegalStateException>(attempt.exceptionOrNull()).message)
                assertContentEquals(lastReadable, Files.readAllBytes(root.resolve(AgentProgressJournal.FILE_NAME)))
            }
        } finally { root.toFile().deleteRecursively() }
    }

    @Test
    fun `omission ranges preserve prefix interior and trailing gaps across legacy restart`() {
        val root = createTempDirectory("progress-ranges-")
        val legacy = buildJsonObject {
            put("schemaVersion", 1); put("displayOnly", true); put("nextSequence", 7)
            put("queueDropped", 3); put("historyDropped", 2); put("truncated", true)
            put("events", buildJsonArray {
                for (sequence in listOf(2, 4)) add(buildJsonObject { put("sequence", sequence) })
            })
        }
        Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), legacy.toString())
        AgentProgressJournal(root, "repair").use { }
        val snapshot = AgentProgressJournal.read(root)!!
        val ranges = snapshot.getValue("omittedSequenceRanges").jsonArray
        assertEquals(listOf("0" to "2", "3" to "4", "5" to "7"), ranges.map {
            it.jsonObject.getValue("startInclusive").jsonPrimitive.content to
                it.jsonObject.getValue("endExclusive").jsonPrimitive.content
        })
        val corrupted = JsonObject(snapshot + ("omittedSequenceRanges" to JsonArray(emptyList())))
        Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), corrupted.toString())
        assertFailsWith<IllegalArgumentException> { AgentProgressJournal.read(root) }
    }

    @Test
    fun `persisted history rejects unexplained loss and inconsistent omission counters`() {
        val root = createTempDirectory("progress-loss-")
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.AGENT_RUNNING) }
        val original = AgentProgressJournal.read(root)!!
        val corruptions = listOf(
            mapOf("events" to JsonArray(original.getValue("events").jsonArray.take(1)),
                "historyDropped" to JsonPrimitive(1), "truncated" to JsonPrimitive(true)),
            mapOf("events" to JsonArray(original.getValue("events").jsonArray.drop(1))),
            mapOf("queueDropped" to JsonPrimitive(1)),
            mapOf("queueDropped" to JsonPrimitive(Long.MAX_VALUE), "historyDropped" to JsonPrimitive(Long.MAX_VALUE)),
            mapOf("truncated" to JsonPrimitive(true)),
            mapOf("events" to JsonArray(emptyList()), "queueDropped" to JsonPrimitive(2), "truncated" to JsonPrimitive(false)),
            mapOf("events" to JsonArray(original.getValue("events").jsonArray.drop(1)),
                "queueDropped" to JsonPrimitive(1), "truncated" to JsonPrimitive(true)),
            mapOf("events" to JsonArray(emptyList()), "queueDropped" to JsonPrimitive(2),
                "truncated" to JsonPrimitive(true)),
            mapOf("events" to JsonArray(emptyList()), "queueDropped" to JsonPrimitive(1),
                "historyDropped" to JsonPrimitive(1), "truncated" to JsonPrimitive(true)),
        )
        corruptions.forEach { changes ->
            // Omit the optional range projection so counter checks must reject these legacy records.
            val malformed = JsonObject(original.filterKeys { it != "omittedSequenceRanges" } + changes).toString()
            Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), malformed)
            assertFailsWith<IllegalArgumentException> { AgentProgressJournal.read(root) }
            assertFailsWith<IllegalArgumentException> { AgentProgressJournal(root, "repair") }
            assertEquals(malformed, Files.readString(root.resolve(AgentProgressJournal.FILE_NAME)))
        }
        // Failed restart validation releases ownership and never overwrites the rejected history.
        Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), original.toString())
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.ROLLED_BACK) }
        assertEquals(4, AgentProgressJournal.read(root)!!.getValue("nextSequence").jsonPrimitive.int)
    }

    @Test
    fun `history eviction precedes retained events while queue loss may follow them`() {
        val root = createTempDirectory("progress-prefix-")
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.AGENT_RUNNING) }
        val original = AgentProgressJournal.read(root)!!
        val events = original.getValue("events").jsonArray
        assertEquals(2, events.size)
        listOf(
            mapOf("events" to JsonArray(events.takeLast(1)), "historyDropped" to JsonPrimitive(1)),
            mapOf("events" to JsonArray(events.take(1)), "queueDropped" to JsonPrimitive(1)),
            mapOf("events" to JsonArray(emptyList()), "historyDropped" to JsonPrimitive(2)),
        ).forEach { changes ->
            // These fixtures exercise legacy snapshots; explicit omission ranges have separate validation tests.
            val valid = JsonObject(original - "omittedSequenceRanges" + changes + ("truncated" to JsonPrimitive(true)))
            Files.writeString(root.resolve(AgentProgressJournal.FILE_NAME), valid.toString())
            assertEquals(valid, AgentProgressJournal.read(root))
        }
    }

    @Test
    fun `completion preserves available usage including zero cache and exact elapsed duration`() {
        val root = createTempDirectory("progress-usage-")
        val request = request(root)
        AgentProgressJournal(root, "repair").use { journal ->
            journal.beginTask("with-usage", request).complete(AgentExecutionReceipt(
                AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                    AgentExecutionResult(AgentStopReason.NO_CHANGES, usage = AgentUsage(
                        inputTokens = 12, outputTokens = 3, cachedInputTokens = 0, toolCalls = 2,
                        wallClock = java.time.Duration.ofSeconds(4, 123456789))))))
            journal.beginTask("without-usage", request).complete(AgentExecutionReceipt(
                AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                    AgentExecutionResult(AgentStopReason.NO_CHANGES))))
        }
        val finished = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["kind"]?.jsonPrimitive?.content == "agent_finished"
        }
        assertEquals(12L, finished[0].getValue("inputTokens").jsonPrimitive.long)
        assertEquals(3L, finished[0].getValue("outputTokens").jsonPrimitive.long)
        assertEquals(0L, finished[0].getValue("cachedInputTokens").jsonPrimitive.long)
        assertEquals(2, finished[0].getValue("toolCalls").jsonPrimitive.int)
        assertEquals("PT4.123456789S", finished[0].getValue("wallClock").jsonPrimitive.content)
        listOf("inputTokens", "outputTokens", "cachedInputTokens", "toolCalls", "wallClock").forEach {
            assertFalse(it in finished[1])
        }
        assertTrue(finished.all { it.getValue("validationPending").jsonPrimitive.boolean })
    }

    @Test
    fun `source sequence loss suppresses incomplete message previews`() {
        val root = createTempDirectory("progress-message-loss-")
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module", request(root))
            task.event(AgentMessageEvent(0, "tracked", AgentMessageRole.ASSISTANT, "private-"))
            task.event(AgentMessageEvent(2, "tracked", AgentMessageRole.ASSISTANT, " tail", true))
            task.event(AgentMessageEvent(3, "unseen", AgentMessageRole.ASSISTANT, "credential", true))
        }
        val snapshot = AgentProgressJournal.read(root)!!
        assertFalse(snapshot.toString().contains("private-"))
        assertFalse(snapshot.toString().contains("credential"))
        val completed = snapshot.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["completed"]?.jsonPrimitive?.booleanOrNull == true
        }
        assertEquals(2, completed.size)
        assertTrue(completed.first().getValue("sourceSequenceGap").jsonPrimitive.boolean)
        completed.forEach {
            assertTrue(it.getValue("textOmitted").jsonPrimitive.boolean)
            assertFalse("text" in it)
        }
    }

    @Test
    fun `message tracking overflow never admits a continuation after capacity is released`() {
        val root = createTempDirectory("progress-message-overflow-")
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module", request(root))
            repeat(16) { index ->
                task.event(AgentMessageEvent(index.toLong(), "tracked-$index", AgentMessageRole.ASSISTANT, "safe"))
            }
            task.event(AgentMessageEvent(16, "omitted", AgentMessageRole.ASSISTANT, "private-"))
            task.event(AgentMessageEvent(17, "tracked-0", AgentMessageRole.ASSISTANT, " complete", true))
            task.event(AgentMessageEvent(18, "omitted", AgentMessageRole.ASSISTANT, "credential", true))
            task.event(AgentMessageEvent(19, "later", AgentMessageRole.ASSISTANT, "new message", true))
        }
        val snapshot = AgentProgressJournal.read(root)!!
        assertFalse(snapshot.toString().contains("credential"))
        assertFalse(snapshot.toString().contains("private-"))
        val messages = snapshot.getValue("events").jsonArray.map { it.jsonObject }.filter {
            it["kind"]?.jsonPrimitive?.content == "message"
        }
        assertEquals("safe complete", messages[17].getValue("text").jsonPrimitive.content)
        messages.takeLast(2).forEach {
            assertTrue(it.getValue("textOmitted").jsonPrimitive.boolean)
            assertTrue(it.getValue("messageTrackingExhausted").jsonPrimitive.boolean)
            assertFalse("text" in it)
        }
        AgentProgressJournal(root, "reconstruction").use { journal ->
            journal.beginTask("next-task", request(root)).event(
                AgentMessageEvent(0, "new", AgentMessageRole.ASSISTANT, "next task is unaffected", true))
        }
        assertTrue(AgentProgressJournal.read(root).toString().contains("next task is unaffected"))
    }

    @Test
    fun `durable run and revision correlation survives writer restart without promoting provisional state`() {
        val root = createTempDirectory("progress-run-test")
        val request = request(root)
        AgentProgressJournal(root, "repair", listOf("private-run"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("attempt-1", request, "private-run")
            task.event(AgentPlanEvent(0, listOf(AgentPlanEntry("step-1", "continue repair", AgentPlanStatus.IN_PROGRESS))))
            task.complete(AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.COMPLETED))))
            journal.runState(AgentWorkflowRunObservation("private-run", AgentWorkflowPhase.PROVISIONAL, "revision-1", "attempt-1"))
            journal.runState(AgentWorkflowRunObservation("private-run", AgentWorkflowPhase.EXHAUSTED, "revision-1"))
        }
        val before = AgentProgressJournal.read(root)!!
        assertFalse(before.toString().contains("private-run"))
        assertFalse(before.toString().contains("acceptedRevisionSha256"))
        AgentProgressJournal(root, "repair", listOf("private-run")).use { journal ->
            journal.runState(AgentWorkflowRunObservation("next-run", AgentWorkflowPhase.ACCEPTED,
                "revision-2", "attempt-2", "a".repeat(64)))
        }
        val events = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }
        val commitment = java.security.MessageDigest.getInstance("SHA-256").digest("private-run".toByteArray(Charsets.UTF_8))
            .joinToString("") { "%02x".format(it) }
        val firstRun = events.filter { it["workflowRunIdSha256"]?.jsonPrimitive?.content == commitment }
        assertEquals(5, firstRun.size)
        assertTrue(firstRun.all { "workflowRunId" !in it && it.getValue("replayOmittedFields").jsonPrimitive.int > 0 })
        assertEquals(1, firstRun.map { it.getValue("workflowRunIdSha256") }.distinct().size)
        assertEquals(setOf("task_started", "plan", "agent_finished", "workflow_run_state"), firstRun.map { it.getValue("kind").jsonPrimitive.content }.toSet())
        assertEquals(listOf("provisional", "exhausted", "accepted"), events.filter {
            it["kind"]?.jsonPrimitive?.content == "workflow_run_state"
        }.map { it.getValue("phase").jsonPrimitive.content })
        assertEquals(2, events.map { it.getValue("runId") }.distinct().size)
        assertEquals("a".repeat(64), events.last().getValue("acceptedRevisionSha256").jsonPrimitive.content)
        assertEquals("revision-2", events.last().getValue("revisionId").jsonPrimitive.content)
    }

    @Test
    fun `nonaccepted run observations cannot carry accepted source identity`() {
        assertFailsWith<IllegalArgumentException> {
            AgentWorkflowRunObservation("run", AgentWorkflowPhase.PROVISIONAL, acceptedRevisionSha256 = "a".repeat(64))
        }
        assertFailsWith<IllegalArgumentException> {
            AgentWorkflowRunObservation("run", AgentWorkflowPhase.ACCEPTED)
        }
        assertFailsWith<IllegalArgumentException> {
            AgentWorkflowRunObservation("x".repeat(4097), AgentWorkflowPhase.CANCELLED)
        }
    }

    @Test
    fun `messages redact split secrets and completion remains distinct from acceptance`() {
        val root = createTempDirectory("progress-test")
        val request = request(root)
        AgentProgressJournal(root, "reconstruction", listOf("private-credential"), maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("module-1", request)
            task.event(AgentMessageEvent(0, "peer-session-secret", AgentMessageRole.ASSISTANT, "hello private-"))
            task.event(AgentMessageEvent(1, "peer-session-secret", AgentMessageRole.ASSISTANT, "credential done", true))
            task.complete(AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Returned(
                AgentExecutionResult(AgentStopReason.COMPLETED, session = AgentSessionReference("acp", "peer-session-secret")),
            )))
            journal.phase(AgentWorkflowPhase.BUILD_VALIDATING, "module-1")
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val text = snapshot.toString()
        assertFalse(text.contains("private-"))
        assertFalse(text.contains("credential"))
        assertFalse(text.contains("peer-session-secret"))
        assertTrue(text.contains("hello [redacted] done"))
        assertTrue(text.contains("sessionIdSha256"))
        assertTrue(text.contains("\"validationPending\":true"))
        assertFalse(text.contains("acceptedRevisionSha256"))
        val events = snapshot.getValue("events").jsonArray
        assertEquals("build_validating", events.last().jsonObject["phase"]!!.jsonPrimitive.content)
        assertEquals(events.indices.map { it.toLong() }, events.map { it.jsonObject["sequence"]!!.jsonPrimitive.long })
    }

    @Test
    fun `restart retains events and allocates a new run without repeating sequence numbers`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.BEHAVIOR_VALIDATING) }
        val previous = AgentProgressJournal.read(root)!!
        AgentProgressJournal(root, "repair").use { it.phase(AgentWorkflowPhase.ROLLED_BACK) }
        val current = AgentProgressJournal.read(root)!!
        val events = current.getValue("events").jsonArray
        assertEquals(previous.getValue("events").jsonArray, JsonArray(events.take(2)))
        assertEquals(2, events.map { it.jsonObject.getValue("runId").jsonPrimitive.content }.distinct().size)
        assertEquals(4, current.getValue("nextSequence").jsonPrimitive.int)
    }

    @Test
    fun `noisy stream remains bounded and records exact omission counts`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair", maximumEvents = 8, maximumQueuedEvents = 2, maximumSnapshotBytes = 4096).use { journal ->
            repeat(2_000) { journal.phase(AgentWorkflowPhase.AGENT_RUNNING, "task-$it") }
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val next = snapshot.getValue("nextSequence").jsonPrimitive.long
        val dropped = snapshot.getValue("queueDropped").jsonPrimitive.long + snapshot.getValue("historyDropped").jsonPrimitive.long
        assertEquals(2_001, next)
        assertEquals(next, dropped + snapshot.getValue("events").jsonArray.size)
        assertTrue(snapshot.getValue("truncated").jsonPrimitive.boolean)
        val omitted = snapshot.getValue("omittedSequenceRanges").jsonArray.flatMap {
            val range = it.jsonObject
            (range.getValue("startInclusive").jsonPrimitive.content.toLong() until
                range.getValue("endExclusive").jsonPrimitive.content.toLong()).toList()
        }
        val retained = snapshot.getValue("events").jsonArray.map { it.jsonObject.getValue("sequence").jsonPrimitive.long }
        assertEquals((0L until next).toList(), (omitted + retained).sorted())
        assertTrue(snapshot.getValue("omittedSequenceRanges").jsonArray.size <= retained.size + 1)
        assertTrue(root.resolve(AgentProgressJournal.FILE_NAME).fileSize() <= 4096)
    }

    @Test
    fun `concurrent tasks retain invocation identity and failures carry no exception text`() {
        val root = createTempDirectory("progress-test")
        val request = request(root)
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val workers = (1..8).map { n -> Thread {
                val task = journal.beginTask("task-$n", request)
                task.event(AgentToolEvent(0, "tool-$n", "compile", AgentToolStatus.SUCCEEDED))
                task.complete(AgentExecutionReceipt(AgentExecutionRequestBinding.capture(request), AgentExecutionOutcome.Failed(
                    AgentFailure(AgentFailureKind.PROCESS_CRASH, "sensitive exception content"),
                )))
            }.apply { start() } }
            workers.forEach { it.join() }
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val events = snapshot["events"]!!.jsonArray.map { it.jsonObject }
        assertEquals(8, events.mapNotNull { it["turnId"]?.jsonPrimitive?.content }.distinct().size)
        assertEquals(8, events.count { it["failureKind"]?.jsonPrimitive?.content == "process_crash" })
        assertFalse(snapshot.toString().contains("sensitive exception"))
        assertEquals(25, events.size)
    }

    @Test
    fun `oversized messages omit the entire preview and cannot publish partial secrets`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("task", request(root))
            task.event(AgentMessageEvent(0, "id", AgentMessageRole.ASSISTANT, "x".repeat(9_000), true))
        }
        val event = AgentProgressJournal.read(root)!!["events"]!!.jsonArray.last().jsonObject
        assertTrue(event["textOmitted"]!!.jsonPrimitive.boolean)
        assertNull(event["text"])
    }

    @Test
    fun `second writer is rejected and oversized persisted data fails bounded read`() {
        val root = createTempDirectory("progress-test")
        AgentProgressJournal(root, "repair").use {
            assertFails { AgentProgressJournal(root, "repair") }
        }
        Files.write(root.resolve(AgentProgressJournal.FILE_NAME), ByteArray(2 * 1024 * 1024 + 1))
        assertFailsWith<IllegalArgumentException> { AgentProgressJournal.read(root) }
    }

    @Test
    fun `redactor handles credential fields and removes terminal control codes`() {
        val redactor = ProgressRedactor(listOf("abc123"))
        assertEquals("api_key=[redacted] Bearer [redacted] [redacted]", redactor.text("api_key=some-value Bearer token-value abc123"))
        assertFalse(redactor.text("\u001b[31mhello").contains('\u001b'))
    }

    @Test
    fun `configured literals cannot erase credential indicators before format masking`() {
        val credential = "UNREGISTERED-CREDENTIAL-7Z"
        val cases = listOf(
            "Bearer" to "Bearer $credential",
            "earer" to "Bearer $credential",
            "Authorization" to "Authorization: Bearer $credential",
            "api_key" to "api_key=$credential",
            "api" to "api-key=$credential",
            "access_token" to "access_token=$credential",
            "password" to "password=$credential",
            "secret" to "secret=$credential",
            "ghp_" to "ghp_$credential",
            "sk-" to "sk-$credential",
            "github_pat_" to "github_pat_$credential",
        )
        for ((literal, input) in cases) {
            val safe = ProgressRedactor(listOf(literal)).text("before; $input; after")
            assertFalse(safe.contains(credential), "credential survived configured literal $literal")
            assertFalse(safe.contains(literal), "configured literal survived redaction")
            assertTrue(safe.startsWith("before; "))
            assertTrue(safe.endsWith("; after"))
            assertTrue(safe.contains("[redacted]"))
        }
        assertEquals("", ProgressRedactor(listOf("Bearer", "[redacted]", "[unredactable text omitted]"))
            .text("Bearer $credential"))
    }

    @Test
    fun `basic authorization credentials are removed without a configured token`() {
        val token = "c3ludGhldGljOnNlbnRpbmVsIQ=="
        val redactor = ProgressRedactor(emptyList())
        for (prefix in listOf("Authorization: ", "aUtHoRiZaTiOn :\t", "Proxy-Authorization\t=\t")) {
            for (scheme in listOf("Basic ", "bAsIc\t")) {
                val input = "before; " + prefix + scheme + token + "; after"
                assertEquals("before; " + prefix + "[redacted]; after", redactor.text(input))
                assertFalse(redactor.text(input).contains(token))
            }
        }
        for (secret in listOf("Basic", "Authorization", token.take(8))) {
            val safe = ProgressRedactor(listOf(secret)).text("Authorization: Basic $token")
            assertFalse(safe.contains(token))
            assertFalse(safe.contains(token.drop(8)))
        }
        val publicText = "Basic examples use placeholders; authorization policy remains public."
        assertEquals(publicText, redactor.text(publicText))
        val markerSecrets = listOf("[redacted]", "[unredactable text omitted]")
        assertEquals("", ProgressRedactor(markerSecrets).text("Authorization: Basic $token"))
    }

    @Test
    fun `split basic authorization is never previewed raw or persisted with its token`() {
        val root = Files.createTempDirectory(
            Files.createDirectories(java.nio.file.Path.of("build", "progress-basic-authorization-tests")), "journal-",
        )
        val tokenPrefix = "c3ludGhl"
        val tokenSuffix = "dGljOnNlbnRpbmVs"
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("task", request(root))
            task.event(AgentMessageEvent(0, "basic", AgentMessageRole.ASSISTANT, "Authorization: Ba", false))
            task.event(AgentMessageEvent(1, "basic", AgentMessageRole.ASSISTANT, "sic $tokenPrefix", false))
            task.event(AgentMessageEvent(2, "basic", AgentMessageRole.ASSISTANT, tokenSuffix, true))
        }
        val messages = AgentProgressJournal.read(root)!!.getValue("events").jsonArray.map { it.jsonObject }
            .filter { it["kind"]?.jsonPrimitive?.content == "message" }
        assertEquals(3, messages.size)
        messages.take(2).forEach {
            assertFalse(it.getValue("completed").jsonPrimitive.boolean)
            assertFalse("text" in it)
        }
        val completed = messages.last()
        assertTrue(completed.getValue("completed").jsonPrimitive.boolean)
        assertFalse(completed.getValue("textOmitted").jsonPrimitive.boolean)
        assertEquals("Authorization: [redacted]", completed.getValue("text").jsonPrimitive.content)
        val persisted = Files.readString(root.resolve(AgentProgressJournal.FILE_NAME))
        listOf(tokenPrefix, tokenSuffix, tokenPrefix + tokenSuffix).forEach { assertFalse(persisted.contains(it)) }
    }

    @Test
    fun `replacement output cannot synthesize a reordered secret`() {
        val redactor = ProgressRedactor(listOf("foo", "[redacted]X"))
        assertEquals("[redacted]", redactor.text("fooX"))
        val marker = ProgressRedactor(listOf("[redacted]"))
        assertFalse(marker.text("hello [redacted] world").contains("[redacted]"))
    }

    @Test
    fun `fixed omission markers cannot disclose configured secrets`() {
        val oversized = "[oversized text omitted]"
        val unredactable = "[unredactable text omitted]"
        assertEquals("", ProgressRedactor(listOf(oversized)).text("x".repeat(16_385)))
        assertEquals("", ProgressRedactor(listOf("[redacted]", unredactable)).text("[redacted]"))
        // Replacement expansion crosses the same bound even though the original input fits.
        assertEquals("", ProgressRedactor(listOf("x", oversized)).text("x".repeat(2_000)))
        // The truncation suffix must not bypass the final fallback check either.
        assertEquals("", ProgressRedactor(listOf("preview truncated", unredactable)).text("abcdef", 3))

        val ordinary = ProgressRedactor(emptyList())
        assertEquals(oversized, ordinary.text("x".repeat(16_385)))
        assertEquals(unredactable, ProgressRedactor(listOf("[redacted]")).text("[redacted]"))
        assertEquals("a… [preview truncated]", ordinary.text("a\uD83D\uDE00b", 2))
        assertEquals("unchanged", ordinary.text("unchanged"))
    }

    @Test
    fun `journal persists safe empty previews when omission markers are sensitive`() {
        val root = Files.createTempDirectory(
            Files.createDirectories(java.nio.file.Path.of("build", "progress-redactor-fallback-tests")), "journal-",
        )
        val secrets = listOf("[oversized text omitted]", "[redacted]", "[unredactable text omitted]")
        AgentProgressJournal(root, "repair", sensitiveValues = secrets, maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("task", request(root))
            task.event(AgentToolEvent(0, "tool", "x".repeat(16_385), AgentToolStatus.FAILED))
            task.event(AgentMessageEvent(1, "message", AgentMessageRole.ASSISTANT, "[reda", false))
            task.event(AgentMessageEvent(2, "message", AgentMessageRole.ASSISTANT, "cted]", true))
        }
        val snapshot = AgentProgressJournal.read(root)!!
        val events = snapshot.getValue("events").jsonArray.map { it.jsonObject }
        val tool = events.single { it["kind"]?.jsonPrimitive?.content == "tool" }
        val message = events.last { it["kind"]?.jsonPrimitive?.content == "message" }
        assertEquals("", tool.getValue("text").jsonPrimitive.content)
        assertEquals("", message.getValue("text").jsonPrimitive.content)
        assertFalse(message.getValue("textOmitted").jsonPrimitive.boolean)
        val persisted = Files.readString(root.resolve(AgentProgressJournal.FILE_NAME))
        secrets.forEach { assertFalse(persisted.contains(it)) }
    }

    @Test
    fun `streamed display commitments preserve whole text encoding across bounded chunks`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-streamed-hash").toAbsolutePath())
        val root = createTempDirectory(parent, "journal-")
        val high = 0xd800.toChar().toString()
        val low = 0xdc00.toChar().toString()
        val pair = charArrayOf(0xd83d.toChar(), 0xde00.toChar()).concatToString()
        val cases = listOf("", "ordinary", 0xfffd.toChar().toString(), high, low,
            "a".repeat(4_095) + pair + "b".repeat(4_096),
            "a".repeat(4_096) + pair + "b".repeat(4_095),
            "a".repeat(4_095) + high + "x" + "b".repeat(4_096),
            "a".repeat(8_192) + low,
            pair.repeat(5_000), pair.repeat(5_000) + high,
            "a".repeat(16_384) + high)
        val expected = cases.map { text -> java.security.MessageDigest.getInstance("SHA-256")
            .digest(receiptCommitmentBytes(text)).joinToString("") { "%02x".format(it) } }
        cases.forEachIndexed { index, text ->
            assertEquals(expected[index], AgentProgressJournal.displayCommitment(text), "case=$index")
        }
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("streamed-hash-task", request(root))
            cases.forEachIndexed { index, text ->
                task.event(AgentMessageEvent(index.toLong(), "case-$index", AgentMessageRole.SYSTEM, text))
            }
        }
        val messages = assertNotNull(AgentProgressJournal.read(root)).getValue("events").jsonArray
            .map { it.jsonObject }.filter { it["kind"]?.jsonPrimitive?.content == "message" }
        assertEquals(cases.size, messages.size)
        messages.forEachIndexed { index, record ->
            assertEquals(expected[index], record.getValue("contentSha256").jsonPrimitive.content)
            assertEquals(cases[index].length, record.getValue("chunkCharacters").jsonPrimitive.int)
            assertFalse("text" in record)
        }
    }

    @Test
    fun `private reasoning is neither retained measured nor committed`(): Unit {
        val parent = Files.createDirectories(java.nio.file.Path.of("build/test-tmp/progress-reasoning").toAbsolutePath())
        val root = createTempDirectory(parent, "journal-")
        AgentProgressJournal(root, "repair", maximumQueuedEvents = 1024).use { journal ->
            val task = journal.beginTask("reasoning-task", request(root))
            task.event(AgentMessageEvent(0, "reasoning", AgentMessageRole.THOUGHT, "PRIVATE_REASONING_PREFIX "))
            task.event(AgentMessageEvent(1, "reasoning", AgentMessageRole.THOUGHT, "PRIVATE_REASONING_TAIL", completed = true))
            task.event(AgentMessageEvent(2, "answer", AgentMessageRole.ASSISTANT, "public answer", completed = true))
        }
        val journal = assertNotNull(AgentProgressJournal.read(root))
        assertFalse(journal.toString().contains("PRIVATE_REASONING"))
        val messages = journal.getValue("events").jsonArray.map { it.jsonObject }
            .filter { it["kind"]?.jsonPrimitive?.content == "message" }
        assertEquals(3, messages.size)
        messages.take(2).forEach { record ->
            assertEquals("thought", record.getValue("role").jsonPrimitive.content)
            assertTrue(record.getValue("textOmitted").jsonPrimitive.boolean)
            listOf("text", "contentSha256", "chunkCharacters", "messageIdSha256").forEach { assertFalse(it in record, it) }
        }
        assertTrue(messages[1].getValue("completed").jsonPrimitive.boolean)
        assertEquals("public answer", messages[2].getValue("text").jsonPrimitive.content)
        assertEquals(AgentProgressJournal.displayCommitment("public answer"), messages[2].getValue("contentSha256").jsonPrimitive.content)
        // Records written before this policy keep their sequence, but public replay withholds the measurements.
        val legacy = buildJsonObject {
            put("sequence", 4); put("kind", "message"); put("role", "thought"); put("text", "PRIVATE_REASONING")
            put("contentSha256", "a".repeat(64)); put("chunkCharacters", 17); put("completed", true)
        }
        val public = publicProgressRecord(legacy)
        assertEquals(setOf("role", "completed", "textOmitted"), public.fields.keys)
        assertEquals(3, public.omittedFieldCount)
        assertTrue(public.fields.getValue("textOmitted").jsonPrimitive.boolean)
    }

    private fun request(root: java.nio.file.Path) = AgentExecutionRequest(
        "fixture task", listOf(AgentWorkspaceRoot("project", root.toAbsolutePath().normalize())),
        accessPolicy = AgentAccessPolicy(emptyList()),
    )
}
