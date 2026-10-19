package decompengine.mvp

import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import decompengine.repair.RepairClient
import decompengine.repair.RepairClientAgentHarness
import decompengine.repair.RepairClientInvocation
import decompengine.repair.RepairRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
import decompengine.repair.RepairResponse
import decompengine.repair.SourcePatch
import decompengine.validation.ProcessInput
import java.nio.file.Path
import java.nio.file.Files
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class MvpPatchWorkflowTest {
    @Test
    fun `public refusal details retain only a validated producer commitment and fixed path`() {
        val evidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to "1"), "PRIVATE_HARNESS", "PRIVATE_PROFILE", "a".repeat(64))
        val artifacts = MvpSummaryArtifact.entries.map { MvpSummaryArtifactFact(it, null, false) }
        val details = MvpSummaryDetailsFact("1".repeat(64))
        val text = MvpSummaryFacts.capture("FAIL", true, false, artifacts, evidence, details).render(MVP_SUMMARY_FACTS_BYTES)
        assertTrue(text.contains("Report detail: redacted details retained"))
        assertTrue(text.contains("| Redacted report details | `$MVP_SUMMARY_DETAILS_PATH` | `${details.sha256}` |"))
        assertTrue(text.contains("Explanation is retained in the redacted report details"))
        assertFalse(text.contains("PRIVATE"))
        val withheld = MvpSummaryFacts.capture("FAIL", true, false, artifacts, evidence).render(MVP_SUMMARY_FACTS_BYTES)
        assertTrue(withheld.contains("Report detail: withheld"))
        assertFalse(withheld.contains("| Redacted report details |"))
        for (value in listOf("PRIVATE", "A".repeat(64), "a".repeat(65), "Bearer " + "a".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { MvpSummaryDetailsFact(value) }
        }
    }

    @Test
    fun `public refusal facts retain producer categories and commitments without private prose or paths`() {
        val profile = MvpSummaryProfile.MAKE
        val evidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to "PRIVATE_VALUE"), "Bearer PRIVATE_HARNESS",
            profile.id, profile.sha256)
        evidence.passPhase("verify", "PRIVATE_DETAIL")
        evidence.passPhase("PRIVATE_PHASE", "PRIVATE_DETAIL")
        evidence.check("behavior validation", true, "PRIVATE_DETAIL")
        evidence.check("PRIVATE_CHECK", false, "PRIVATE_DETAIL")
        evidence.approvalDecision = "approved interactively"
        evidence.patchDiff = "PRIVATE_DIFF"
        evidence.patchExplanation = "PRIVATE_EXPLANATION"
        evidence.findingSourceLocation = "decompiled.c:12:3"
        val artifacts = MvpSummaryArtifact.entries.map { kind ->
            MvpSummaryArtifactFact(kind, "a".repeat(64), kind.publicRelativePath != null)
        }.toMutableList()
        val facts = MvpSummaryFacts.capture("PASS", false, true, artifacts, evidence)
        val text = facts.render(MVP_SUMMARY_FACTS_BYTES)
        assertTrue(text.contains("- Result: PASS"))
        assertTrue(text.contains("approved interactively"))
        assertTrue(text.contains("| verify | PASS |"))
        assertTrue(text.contains("| withheld phase label | PASS |"))
        assertTrue(text.contains("| behavior validation | PASS |"))
        assertTrue(text.contains("| withheld check label | FAIL |"))
        assertTrue(text.contains("decompile/decompiled.c:12:3"))
        assertTrue(text.contains("| Input ELF | withheld | `${"a".repeat(64)}` |"))
        assertTrue(text.contains("Reconstruction profile: `${profile.id}` (`${profile.sha256}`)"))
        assertFalse(text.contains("PRIVATE"))
        for (heading in listOf("Executed Phases", "Artifact Hashes", "CWE-787 Evidence and Source Mapping",
            "Approved Source Change", "Build and Validation Results", "Output Paths", "Residual Risks")) {
            assertTrue(text.contains("## $heading"))
        }
        artifacts.clear()
        evidence.phases.clear()
        evidence.verification.clear()
        assertEquals(text, facts.render(MVP_SUMMARY_FACTS_BYTES))
        assertFailsWith<UnsupportedOperationException> { (facts.artifacts as MutableList<*>).clear() }
        assertFailsWith<UnsupportedOperationException> { (facts.phases as MutableList<*>).clear() }
        val unknown = MvpRunEvidence(emptyMap(), "PRIVATE_HARNESS", "PRIVATE_PROFILE", "f".repeat(64))
        unknown.approvalDecision = "PRIVATE_APPROVAL"
        unknown.findingSourceLocation = "/PRIVATE/decompiled.c:12"
        val hidden = MvpSummaryFacts.capture("PRIVATE_RESULT", true, true, facts.artifacts, unknown).render(MVP_SUMMARY_FACTS_BYTES)
        assertTrue(hidden.contains("- Result: UNAVAILABLE"))
        assertTrue(hidden.contains("Verified final binary: not published"))
        assertFalse(hidden.contains("PRIVATE"))
        assertNull(MvpSummaryProfile.recognize(profile.id, "f".repeat(64)))
        assertNull(MvpSummarySourceFact.recognize("decompiled.c:2147483648"))
    }

    @Test
    fun `public refusal fact admission rejects forged hashes missing slots and oversized collections`() {
        val evidence = MvpRunEvidence(emptyMap(), "fixture", "fixture", "a".repeat(64))
        val artifacts = MvpSummaryArtifact.entries.map { MvpSummaryArtifactFact(it, null, false) }
        for (value in listOf("PRIVATE", "A".repeat(64), "a".repeat(65), "Bearer " + "a".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { MvpSummaryArtifactFact(MvpSummaryArtifact.INPUT, value, false) }
        }
        assertFailsWith<IllegalArgumentException> { MvpSummaryArtifactFact(MvpSummaryArtifact.INPUT, "a".repeat(64), true) }
        assertFailsWith<IllegalArgumentException> { MvpSummaryFacts.capture("FAIL", true, false, artifacts.dropLast(1), evidence) }
        assertFailsWith<IllegalArgumentException> { MvpSummaryFacts.capture("FAIL", true, false, List(15) { artifacts.first() }, evidence) }
        val rejected = object : AbstractCollection<MvpSummaryArtifactFact>() {
            override val size: Int = 16
            override fun iterator(): Iterator<MvpSummaryArtifactFact> = error("oversized facts must not be iterated")
        }
        assertFailsWith<IllegalArgumentException> { MvpSummaryFacts.capture("FAIL", true, false, rejected, evidence) }
        val deceptive = object : Collection<MvpSummaryArtifactFact> by artifacts {
            override fun iterator(): Iterator<MvpSummaryArtifactFact> = (artifacts + artifacts.first()).iterator()
        }
        assertFailsWith<IllegalArgumentException> { MvpSummaryFacts.capture("FAIL", true, false, deceptive, evidence) }
        repeat(33) { evidence.passPhase("phase-$it", "PRIVATE") }
        assertFailsWith<IllegalArgumentException> { MvpSummaryFacts.capture("FAIL", true, false, artifacts, evidence) }
        for (capacity in listOf(0L, MVP_SUMMARY_FACTS_BYTES - 1, MAXIMUM_REPAIR_PROJECTION_BYTES + 1)) {
            assertFailsWith<IllegalArgumentException> { requireMvpSummaryCapacity(capacity) }
        }
        requireMvpSummaryCapacity(MVP_SUMMARY_FACTS_BYTES)
        requireMvpSummaryCapacity(MAXIMUM_REPAIR_PROJECTION_BYTES)
    }

    @Test
    fun `complete public refusal envelope fits the reserved configured capacity without truncation`() {
        val profile = MvpSummaryProfile.NINJA
        val evidence = MvpRunEvidence(emptyMap(), "PRIVATE_HARNESS", profile.id, profile.sha256)
        repeat(32) { index ->
            evidence.phases["PRIVATE-$index"] = PhaseEvidence("PRIVATE_PHASE", if (index == 31) EvidenceStatus.FAIL else EvidenceStatus.NOT_RUN, "PRIVATE")
            evidence.verification += VerificationEvidence(MvpSummaryCheck.RECONSTRUCTION.label, EvidenceStatus.NOT_RUN, "PRIVATE")
        }
        evidence.findingSourceLocation = "decompiled.c:2147483647:2147483647"
        evidence.approvalDecision = "approved by --yes automation"
        evidence.patchDiff = "PRIVATE_DIFF"
        val artifacts = MvpSummaryArtifact.entries.map { MvpSummaryArtifactFact(it, "a".repeat(64), it.publicRelativePath != null) }
        val facts = MvpSummaryFacts.capture("PASS", true, true, artifacts, evidence, MvpSummaryDetailsFact("a".repeat(64)))
        val text = facts.render(MVP_SUMMARY_FACTS_BYTES)
        assertTrue(text.toByteArray(Charsets.UTF_8).size <= MVP_SUMMARY_FACTS_BYTES)
        assertTrue(text.endsWith("publication decisions.\n"))
        assertEquals(16, Regex("`" + "a".repeat(64) + "`").findAll(text).count())
        assertTrue(text.contains("decompile/decompiled.c:2147483647:2147483647"))
        assertFalse(text.contains("PRIVATE") || text.contains("truncated"))
        assertFailsWith<IllegalArgumentException> { facts.render(MVP_SUMMARY_FACTS_BYTES - 1) }
    }

    @Test
    fun `public commitments preserve exact digits through normalization and repeated private masking`() {
        val digest = "0123456789abcdef".repeat(4)
        val reverse = digest.reversed()
        val redactor = MvpArtifactRedactor(listOf("1", "private-value", "[REDACTED]X"), 4096)
        val rendered = redactor.project {
            append("\u0001private-value 1\n").appendSha256(digest)
            append("\r\nprivate-valueX").appendSha256(reverse).append("\r\n1")
        }
        assertEquals("[REDACTED] [REDACTED]\n$digest\n[REDACTED]$reverse\n[REDACTED]", rendered)
        assertEquals("[REDACTED]", redactor.text("1"))
        assertEquals("[REDACTED]$digest[REDACTED]", redactor.project {
            append("1").appendSha256(digest).append("1")
        })
        assertFailsWith<MvpPatchException> {
            MvpArtifactRedactor(listOf("x" + digest.take(2)), 4096).project {
                append("x").appendSha256(digest)
            }
        }
        assertFailsWith<MvpPatchException> {
            MvpArtifactRedactor(listOf(digest.takeLast(2) + "x"), 4096).project {
                appendSha256(digest).append("x")
            }
        }
        for (prefix in listOf("Bearer ", "Bearer\u000c")) {
            assertFailsWith<MvpPatchException> {
                MvpArtifactRedactor(emptyList(), 4096).project { append(prefix).appendSha256(digest) }
            }
        }
        assertFailsWith<IllegalArgumentException> {
            redactor.project { appendSha256("not a public digest") }
        }
        assertFailsWith<IllegalArgumentException> {
            redactor.project { repeat(33) { appendSha256(digest) } }
        }
        assertFailsWith<MvpPatchException> {
            MvpArtifactRedactor(emptyList(), 64).project { appendSha256(digest).append("x") }
        }
    }


    @Test
    fun `incremental command capture matches the retained line contract across every split`() {
        val inputs = listOf("", "\n", "\r", "\r\n", "\n\n", "\r\r\n\r", "public", "a\rb\nc\r\nd",
            "\r\nfirst\r\n\r\nlast\r", "é中\uD83D\uDE00", "\uD83Dx\uDE00\uD83D\uD83D\uDE00",
            "left\u0000\u000c\u0085\u2028right\r\nend")
        for (input in inputs) {
            val lines = input.reader().buffered().readLines() // Independent, in-memory old JDK contract.
            val expected = if (lines.isEmpty()) "" else lines.joinToString("\n", postfix = "\n")
            val prefixes = lines.indices.map { lines.take(it + 1).joinToString("\n", postfix = "\n") }
            for (split in 0..input.length) {
                val captured = StringBuilder()
                val budget = MvpCommandCaptureBudget(maxOf(1, expected.toByteArray(Charsets.UTF_8).size).toLong())
                val collector = MvpCommandCapture(captured, budget)
                val published = mutableListOf<String>()
                val chunks = listOf(input.substring(0, split), "", input.substring(split))
                for (chunk in chunks) collector.feed(chunk.toCharArray(), chunk.length) { published += captured.toString() }
                collector.finish { published += captured.toString() }
                assertEquals(expected, captured.toString())
                assertEquals(prefixes, published)
                assertFailsWith<IllegalStateException> { collector.feed(charArrayOf('x'), 1) {} }
                assertFailsWith<IllegalStateException> { collector.finish {} }
            }
        }
    }

    @Test
    fun `command capture charges the aggregate normalized bytes before mutation and latches overflow`() {
        assertFailsWith<IllegalArgumentException> { MvpCommandCaptureBudget(0) }
        assertFailsWith<IllegalArgumentException> { MvpCommandCaptureBudget(Long.MAX_VALUE) }
        val shared = MvpCommandCaptureBudget(6)
        val stdout = StringBuilder()
        val stderr = StringBuilder()
        val out = MvpCommandCapture(stdout, shared)
        val err = MvpCommandCapture(stderr, shared)
        out.feed("abcd".toCharArray(), 4) {}
        val overflow = assertFailsWith<MvpPatchException> { err.feed("efg".toCharArray(), 3) {} }
        assertEquals("abcd", stdout.toString())
        assertEquals("", stderr.toString())
        assertTrue(assertFailsWith<MvpPatchException> { out.finish {} } === overflow)
        assertEquals("abcd", stdout.toString()) // Even a smaller later charge cannot resume acceptance.

        val pair = StringBuilder()
        val surrogate = MvpCommandCapture(pair, MvpCommandCaptureBudget(3))
        surrogate.feed(charArrayOf('\uD83D'), 1) {}
        assertFailsWith<MvpPatchException> { surrogate.feed(charArrayOf('\uDE00'), 1) {} }
        assertEquals("\uD83D", pair.toString())
        val finalLine = StringBuilder()
        val ending = MvpCommandCapture(finalLine, MvpCommandCaptureBudget(2))
        ending.feed("é".toCharArray(), 1) {}
        assertFailsWith<MvpPatchException> { ending.finish {} }
        assertEquals("é", finalLine.toString()) // Charge the synthesized final newline too.

        val pending = StringBuilder()
        val bounded = MvpCommandCapture(pending, MvpCommandCaptureBudget(1024))
        assertFailsWith<MvpPatchException> { bounded.feed(CharArray(4096) { 'x' }, 4096) {} }
        assertEquals(0, pending.length) // No intermediate whole line or partial span was appended.
        val invalid = MvpCommandCapture(StringBuilder(), MvpCommandCaptureBudget(16))
        assertFailsWith<IllegalArgumentException> { invalid.feed(charArrayOf('a'), -1) {} }
        assertFailsWith<IllegalArgumentException> { invalid.feed(charArrayOf('a'), 2) {} }
        assertFailsWith<IllegalArgumentException> { MvpCommandCapture(StringBuilder("existing"), shared) }
    }

    @Test
    fun `fixed command chunks preserve private display and cannot accept a failed partial capture`() {
        val privacy = MvpLogPrivacy(MvpArtifactRedactor(emptyList(), 8192))
        val captures = arrayOf(StringBuilder(), StringBuilder())
        val budget = MvpCommandCaptureBudget(8192)
        val collectors = captures.map { MvpCommandCapture(it, budget) }
        val shared = privacy.lines()
        val frames = mutableListOf<MvpLogFrame>()
        val latch = MvpLogFailure()
        val display = MvpLiveCommandDisplay(privacy) { value, error, pipe ->
            frames += privacy.frame(privacy.message(value, shared, pipe), error)
        }
        fun feed(error: Boolean, text: String) {
            val slot = if (error) 1 else 0
            latch.attempt {
                collectors[slot].feed(text.toCharArray(), text.length) {
                    latch.attempt { display.line(error, captures[slot]) }
                }
            }
        }
        fun complete(error: Boolean) {
            val slot = if (error) 1 else 0
            latch.attempt { collectors[slot].finish { latch.attempt { display.line(error, captures[slot]) } } }
            latch.attempt { display.complete(error, captures[slot]) }
        }
        feed(true, "Bearer ") // No completed line or display callback yet.
        feed(false, "synthetic-chunk-private\r")
        feed(false, "\npublic-after\n")
        assertTrue(frames.none { it.console.contains("synthetic-chunk-private") })
        complete(true)
        complete(false)
        latch.requireSuccess()
        display.finish(captures[0], captures[1])
        assertEquals("synthetic-chunk-private\npublic-after\n", captures[0].toString())
        assertEquals("Bearer \n", captures[1].toString())
        assertTrue(frames.none { it.console.contains("synthetic-chunk-private") || it.retained.contains("synthetic-chunk-private") })

        val retained = StringBuilder()
        val limited = MvpCommandCapture(retained, MvpCommandCaptureBudget(6))
        val failed = MvpLogFailure()
        failed.attempt { limited.feed("public".toCharArray(), 6) {} }
        failed.attempt { limited.feed(charArrayOf('!'), 1) {} }
        val original = assertFailsWith<MvpPatchException> { failed.requireSuccess() }
        failed.attempt { limited.feed("unretained".toCharArray(), 10) { error("must not publish") } }
        failed.attempt { limited.finish { error("must not publish") } }
        assertEquals("public", retained.toString())
        assertTrue(assertFailsWith<MvpPatchException> { failed.requireSuccess() } === original)
    }

    @Test
    fun `live command display waits for complete peer grammar in either reader order`() {
        for (prefix in listOf("Bearer ", "Authorization: Basic ", "password=", "ghp_",
            "public metadata; Bearer already-complete; public-tail")) {
            for (prefixError in listOf(false, true)) for (privateFirst in listOf(false, true)) {
                for (prefixClosesFirst in listOf(false, true)) {
                    val privacy = MvpLogPrivacy(MvpArtifactRedactor(emptyList(), 8192))
                    val shared = privacy.lines()
                    val frames = mutableListOf<MvpLogFrame>()
                    val display = MvpLiveCommandDisplay(privacy) { value, error, pipe ->
                        frames += privacy.frame(privacy.message(value, shared, pipe), error)
                    }
                    val captures = arrayOf(StringBuilder(), StringBuilder())
                    val privateValue = "synthetic-live-private"
                    fun deliver(error: Boolean, value: String) {
                        val capture = captures[if (error) 1 else 0]
                        capture.appendLine(value)
                        display.line(error, capture)
                    }
                    if (privateFirst) {
                        // This also represents a peer prefix still held inside readLine until EOF.
                        deliver(!prefixError, "public head; $privateValue; public tail")
                        deliver(prefixError, prefix)
                    } else {
                        deliver(prefixError, prefix)
                        deliver(!prefixError, "public head; $privateValue; public tail")
                    }
                    assertEquals(2, frames.size)
                    assertTrue(frames.all { it.console.contains("progress: captured_lines=1") })
                    assertTrue(frames.none { it.console.contains(privateValue) || it.retained.contains(privateValue) })
                    val first = if (prefixClosesFirst) prefixError else !prefixError
                    display.complete(first, captures[if (first) 1 else 0])
                    display.complete(!first, captures[if (first) 0 else 1])
                    display.finish(captures[0], captures[1])
                    assertTrue(frames.any { it.console.contains("[REDACTED]") })
                    assertTrue(frames.none { it.console.contains(privateValue) || it.retained.contains(privateValue) })
                    val published = frames.toList()
                    display.finish(captures[0], captures[1])
                    assertEquals(published, frames)
                }
            }
        }
    }

    @Test
    fun `live command display releases public records before local EOF and bounds pending work`() {
        val privacy = MvpLogPrivacy(MvpArtifactRedactor(emptyList(), 8192))
        val shared = privacy.lines()
        val frames = mutableListOf<MvpLogFrame>()
        val records = mutableListOf<String>()
        val progress = mutableListOf<String>()
        val display = MvpLiveCommandDisplay(privacy) { value, error, pipe ->
            if (pipe == null) progress += value else records += value
            frames += privacy.frame(privacy.message(value, shared, pipe), error)
        }
        val stdout = StringBuilder()
        val publicLines = (1..10).map { "public diagnostic $it" }
        for (line in publicLines.take(9)) {
            stdout.appendLine(line)
            display.line(false, stdout)
        }
        assertEquals(listOf(1, 2, 4, 8), progress.map {
            it.substringAfter("captured_lines=").substringBefore(' ').toInt()
        })
        assertTrue(records.isEmpty())
        display.complete(true, "")
        stdout.appendLine(publicLines.last())
        display.line(false, stdout)
        assertEquals(publicLines, records) // Published while stdout is still open.
        assertTrue(frames.any { it.console == publicLines.first() })
        display.complete(false, stdout)
        display.finish(stdout, "")
        assertEquals(publicLines, records)
        assertEquals(publicLines.joinToString("\n", postfix = "\n"), stdout.toString())

        val ticks = mutableListOf<String>()
        val noisy = MvpLiveCommandDisplay(privacy) { value, _, pipe -> if (pipe == null) ticks += value }
        val captured = StringBuilder()
        repeat(1025) {
            captured.appendLine("public")
            noisy.line(false, captured)
        }
        assertEquals(11, ticks.size)
        noisy.complete(false, captured)
        assertEquals(12, ticks.size) // Powers of two plus the distinct final total.
        assertTrue(ticks.last().contains("captured_lines=1025 captured_utf16_units=7175"))
        noisy.complete(true, "")
        noisy.finish(captured, "")
        assertEquals(12, ticks.size)

        val small = MvpLogPrivacy(MvpArtifactRedactor(emptyList(), 1024))
        val oversized = object : CharSequence {
            override val length: Int = 1025
            override fun get(index: Int): Char = if (index == length - 1) '\n' else 'x'
            override fun subSequence(startIndex: Int, endIndex: Int): CharSequence = error("unexpected capture copy")
            override fun toString(): String = error("unexpected capture copy")
        }
        val bounded = MvpLiveCommandDisplay(small) { _, _, _ -> }
        bounded.line(false, oversized)
        assertFailsWith<MvpPatchException> { bounded.complete(false, oversized) }
        assertFailsWith<IllegalStateException> { bounded.finish(oversized, "") }
        val wide = StringBuilder().appendLine("é".repeat(600))
        val encoded = MvpLiveCommandDisplay(small) { _, _, _ -> }
        encoded.line(false, wide)
        assertFailsWith<MvpPatchException> { encoded.complete(false, wide) }

        val original = IllegalStateException("synthetic display failure")
        val failed = MvpLiveCommandDisplay(privacy) { _, _, _ -> throw original }
        val latch = MvpLogFailure()
        latch.attempt { failed.line(false, "public\n") }
        assertTrue(assertFailsWith<IllegalStateException> { latch.requireSuccess() } === original)
    }

    @Test
    fun `MVP log continuations conceal credential values across blank lines and independent pipes`() {
        val evidence = MvpRunEvidence(mapOf("PLAIN_SCHEME" to "Bearer", "PLAIN_HEADER" to "Authorization"),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        val lines = evidence.logPrivacy.lines()
        val rendered = listOf("public start", "Authorization:", "", "Basic", "synthetic-basic; public suffix",
            "Bearer", "synthetic-bearer, public tail", "api_key=", "synthetic-key; after", "ghp_",
            "synthetic-prefix", "public end").joinToString("\n") { lines.next(it) }
        for (value in listOf("synthetic-basic", "synthetic-bearer", "synthetic-key", "synthetic-prefix")) {
            assertFalse(rendered.contains(value))
        }
        assertTrue(rendered.contains("public start"))
        assertTrue(rendered.contains("public suffix"))
        assertTrue(rendered.contains("public end"))
        val stdout = evidence.logPrivacy.lines()
        val stderr = evidence.logPrivacy.lines()
        stdout.next("Bearer")
        assertEquals("public unrelated", stderr.next("public unrelated"))
        assertFalse(stdout.next("synthetic-next; public").contains("synthetic-next"))
        stdout.next("password=")
        assertEquals("; public remains", stdout.next("; public remains"))
        assertEquals("public remains", stdout.next("public remains"))
        val ordered = evidence.logPrivacy.lines()
        ordered.next("Bearer")
        assertFalse(ordered.next("synthetic-other-channel").contains("synthetic-other-channel"))
        val normalized = evidence.logPrivacy.lines()
        normalized.next("Bea\u0001rer")
        assertFalse(normalized.next("synthetic-control-token").contains("synthetic-control-token"))
        val messages = evidence.logPrivacy.lines()
        evidence.logPrivacy.message("Bearer", messages)
        assertFalse(evidence.logPrivacy.message("synthetic-message-token", messages).contains("synthetic-message-token"))
        val shared = evidence.logPrivacy.lines()
        val outPipe = evidence.logPrivacy.lines()
        val errPipe = evidence.logPrivacy.lines()
        evidence.logPrivacy.message("Bearer", shared, outPipe)
        assertFalse(evidence.logPrivacy.message("synthetic-cross-pipe", shared, errPipe).contains("synthetic-cross-pipe"))
        evidence.logPrivacy.message("Bearer", shared, outPipe)
        evidence.logPrivacy.message("public diagnostic", shared, errPipe)
        assertFalse(evidence.logPrivacy.message("synthetic-original-pipe", shared, outPipe).contains("synthetic-original-pipe"))
        val phrases = MvpRunEvidence(mapOf("PLAIN_PHRASE" to "top secret"), "fixture-harness", "fixture-profile", "a".repeat(64))
        val phraseLines = phrases.logPrivacy.lines()
        phraseLines.next("password=")
        val phrase = phraseLines.next("top secret; public")
        assertFalse(phrase.contains("top"))
        assertFalse(phrase.contains("secret"))
        assertTrue(phrase.contains("public"))
        fun captured(stdoutCapture: String, stderrCapture: String): Pair<String, String> {
            val captures = evidence.logPrivacy.lines()
            val out = evidence.logPrivacy.linesWithUnorderedPeer(stderrCapture)
            val err = evidence.logPrivacy.linesWithUnorderedPeer(stdoutCapture)
            fun render(value: String, pipe: MvpLogPrivacy.Lines) = value.lineSequence()
                .filter(String::isNotEmpty).joinToString("\n") { evidence.logPrivacy.message(it, captures, pipe) }
            return render(stdoutCapture, out) to render(stderrCapture, err)
        }
        for (introducer in listOf("Bearer", "Authorization: Basic", "Authorization:", "password=", "ghp_", "Bea\u0001rer",
            "Bearer public", "Authorization: Basic public", "Authorization: public", "password=public", "ghp_public", "Bea\u0001rer public")) {
            val source = "$introducer\npublic source line"
            val peer = "public-prefix synthetic-binary-early; visible suffix\n, public separator\npublic-prefix synthetic-binary-late; visible suffix"
            for ((out, err) in listOf(captured(source, peer), captured(peer, source))) {
                val text = "$out\n$err"
                assertFalse(text.contains("synthetic-binary-early"))
                assertFalse(text.contains("synthetic-binary-late"))
                assertFalse(text.contains("visible suffix"))
                assertFalse(text.contains("public separator"))
                assertFalse(text.contains("public-prefix"))
            }
        }
        val authorization = captured("Bearer\npublic\nAuthorization:\npublic", "Basic synthetic-binary-basic; visible suffix")
        assertFalse(authorization.second.contains("synthetic-binary-basic"))
        assertEquals("public stdout" to "public stderr", captured("public stdout", "public stderr"))
        for (separator in listOf('\u000b', '\u000c', '\r')) {
            val state = evidence.logPrivacy.lines()
            val rendered = evidence.logPrivacy.message("Bearer${separator}synthetic-control-separated-token", state)
            assertFalse(rendered.contains("synthetic-control-separated-token"))
        }
    }

    @Test
    fun `MVP log projections mask derived private line fragments and complete destination prefixes`() {
        val environment = mutableMapOf("PLAIN_MULTILINE" to "left-private\nright-private",
            "PLAIN_CR" to "first-private\rsecond-private", "PLAIN_PREFIX" to "[stderr] public-payload",
            "PLAIN_STAMP" to "[fixed-stamp] public-payload")
        val evidence = MvpRunEvidence(environment, "fixture-harness", "fixture-profile", "a".repeat(64))
        environment.clear()
        for (fragment in listOf("left-private", "right-private", "first-private", "second-private")) {
            assertFalse(evidence.logPrivacy.project("before $fragment after").contains(fragment))
        }
        val frame = evidence.logPrivacy.frame("public-payload", true)
        assertTrue(frame.error)
        assertEquals("public-payload", frame.console)
        assertFalse(frame.retained.contains("[stderr] public-payload"))
        val stamped = evidence.logPrivacy.frame("public-payload", false, "fixed-stamp")
        assertFalse(stamped.retained.contains("[fixed-stamp] public-payload"))
        val manyFragments = List(5000) { "private-fragment-$it" }.joinToString("\n")
        val many = MvpRunEvidence(mapOf("PLAIN_MULTILINE" to manyFragments), "fixture-harness", "fixture-profile", "a".repeat(64))
        assertFalse(many.logPrivacy.project("private-fragment-4999").contains("private-fragment-4999"))
        assertFailsWith<IllegalArgumentException> {
            MvpArtifactRedactor((0..4096).map { "private-$it" }, 1024)
        }
        val collision = MvpRunEvidence(mapOf("PLAIN_MULTILINE" to "other\n[REDACTED]"),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        assertFailsWith<MvpPatchException> { collision.logPrivacy.project("password=synthetic") }
    }

    @Test
    fun `MVP logger admits console and retained records before output without launching a command`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-log-privacy")), "records-")
        val environment = mapOf("PLAIN_SETTING" to "plain-private", "PLAIN_MULTILINE" to "left-private\nright-private",
            "PLAIN_SCHEME" to "Bearer")
        val evidence = MvpRunEvidence(environment, "fixture-harness", "fixture-profile", "a".repeat(64))
        val refusal = MvpPatchException("synthetic display refusal")
        val latch = MvpLogFailure()
        latch.attempt { throw refusal }
        latch.attempt { error("refused display work must not continue") }
        assertTrue(assertFailsWith<MvpPatchException> { latch.requireSuccess() } === refusal)
        val ordinary = MvpLogFailure()
        var admitted = 0
        ordinary.attempt { admitted++ }
        ordinary.requireSuccess()
        assertEquals(1, admitted)
        val interrupted = InterruptedException("synthetic interruption")
        ordinary.attempt { throw interrupted }
        assertTrue(assertFailsWith<InterruptedException> { ordinary.requireSuccess() } === interrupted)
        val fatal = LinkageError("synthetic fatal failure")
        val failed = MvpLogFailure()
        failed.attempt { throw fatal }
        assertTrue(assertFailsWith<LinkageError> { failed.requireSuccess() } === fatal)
        val readFailure = java.io.IOException("synthetic private reader detail")
        val reading = MvpLogFailure()
        reading.record(readFailure)
        reading.record(refusal)
        assertTrue(assertFailsWith<java.io.IOException> { reading.requireSuccess() } === readFailure)
        val output = java.io.ByteArrayOutputStream()
        val errors = java.io.ByteArrayOutputStream()
        java.io.PrintStream(output, true, Charsets.UTF_8).use { out ->
            java.io.PrintStream(errors, true, Charsets.UTF_8).use { err ->
                StreamingLogger(root.resolve("events.log"), evidence, out, err, { "fixed-stamp" }).use { logger ->
                    logger.phase("plain-private")
                    logger.info("Bearer")
                    logger.info("synthetic-unregistered")
                    logger.info("Bea\u0001rer")
                    logger.info("synthetic-control-unregistered")
                    logger.info("left-private")
                    logger.info("right-private")
                    val outPipe = evidence.logPrivacy.lines()
                    val errPipe = evidence.logPrivacy.lines()
                    logger.outputLine("Bearer", false, outPipe)
                    logger.outputLine("synthetic-cross-pipe", true, errPipe)
                    logger.outputLine("Bearer", false, outPipe)
                    logger.outputLine("public diagnostic", true, errPipe)
                    logger.outputLine("synthetic-original-pipe", false, outPipe)
                    fun displayCaptures(stdout: String, stderr: String) {
                        val capturedOut = evidence.logPrivacy.linesWithUnorderedPeer(stderr)
                        val capturedErr = evidence.logPrivacy.linesWithUnorderedPeer(stdout)
                        stdout.lineSequence().forEach { logger.outputLine(it, false, capturedOut) }
                        stderr.lineSequence().forEach { logger.outputLine(it, true, capturedErr) }
                    }
                    displayCaptures("Bearer public\npublic replay", "public-prefix synthetic-replay-early; suffix\n, separator\npublic-prefix synthetic-replay-late; suffix")
                    displayCaptures("public-prefix synthetic-reverse-replay; suffix", "Authorization: Basic public\npublic replay")
                    logger.info("public output")
                }
            }
        }
        val console = output.toString(Charsets.UTF_8)
        val retained = root.resolve("events.log").readText()
        for (value in listOf("plain-private", "left-private", "right-private", "synthetic-unregistered", "synthetic-control-unregistered",
            "synthetic-cross-pipe", "synthetic-original-pipe", "synthetic-replay-early", "synthetic-replay-late", "synthetic-reverse-replay")) {
            assertFalse(console.contains(value))
            assertFalse(retained.contains(value))
            assertFalse(errors.toString(Charsets.UTF_8).contains(value))
        }
        assertTrue(console.contains("public output"))
        assertTrue(retained.contains("[fixed-stamp] public output"))
        assertTrue(errors.toString(Charsets.UTF_8).contains("[REDACTED]"))
        for ((name, rejected) in listOf(
            "prefix-budget" to MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64), 16),
            "marker" to MvpRunEvidence(mapOf("PLAIN_SETTING" to "[REDACTED]"), "fixture-harness", "fixture-profile", "a".repeat(64)),
        )) {
            val withheld = java.io.ByteArrayOutputStream()
            java.io.PrintStream(withheld, true, Charsets.UTF_8).use { out ->
                StreamingLogger(root.resolve("$name.log"), rejected, out, out, { "fixed-stamp" }).use { logger ->
                    assertFailsWith<MvpPatchException> {
                        logger.info(if (name == "marker") "password=synthetic" else "public message")
                    }
                }
            }
            assertEquals(0, withheld.size())
            assertEquals("", root.resolve("$name.log").readText())
        }
    }

    @Test
    fun `default MVP approval renders complete private safe content before reading a decision`() {
        val evidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to "plain-private",
            "PLAIN_MULTILINE" to "left-private\nright-private", "PLAIN_FORMAT" to "Patch summary: public-heading"),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        val complete = "public complete explanation line;\n".repeat(2000)
        val summary = "public-heading; plain-private; Authorization: Basic synthetic-basic; left-private\nright-private;\n" + complete
        val prompt = renderMvpApprovalPrompt(summary, evidence)
        for (value in listOf("plain-private", "left-private", "right-private", "synthetic-basic", "Patch summary: public-heading")) {
            assertFalse(prompt.contains(value))
        }
        assertTrue(prompt.contains(complete))
        assertTrue(prompt.endsWith("Apply this patch? [y/N] "))
        assertTrue(summary.contains("plain-private"))
        val privateQuestion = MvpRunEvidence(mapOf("PLAIN_SETTING" to "Apply this patch? [y/N] "),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        assertFailsWith<MvpPatchException> { renderMvpApprovalPrompt("public", privateQuestion) }
        assertFailsWith<MvpPatchException> {
            renderMvpApprovalPrompt("public", MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64), 16))
        }
    }

    @Test
    fun `complete artifact literal index agrees with independent overlapping span coverage`() {
        fun expected(source: String, values: List<String>): String {
            val covered = BooleanArray(source.length)
            for (value in values) for (position in 0..source.length - value.length) {
                if (source.startsWith(value, position)) for (offset in value.indices) covered[position + offset] = true
            }
            return buildString {
                var position = 0
                while (position < source.length) {
                    if (!covered[position]) append(source[position++]) else {
                        append("[REDACTED]")
                        while (position < source.length && covered[position]) position++
                    }
                }
            }
        }
        val random = java.util.Random(7568)
        val alphabet = charArrayOf('a', 'b', 'c', 'é', '\uD800', '\uDC00')
        repeat(400) {
            val values = List(1 + random.nextInt(8)) {
                buildString { repeat(1 + random.nextInt(6)) { append(alphabet[random.nextInt(alphabet.size)]) } }
            }
            val source = buildString { repeat(random.nextInt(50)) { append(alphabet[random.nextInt(alphabet.size)]) } }
            val index = MvpArtifactLiteralIndex(values)
            assertEquals(expected(source, values), index.replace(source, 1024))
            assertEquals(values.any { source.contains(it) }, index.contains(source))
        }
        for ((source, values) in listOf(
            "abcdeZ" to listOf("ab", "bcde", "de"),
            "aaaaaaa!" to listOf("a", "aa", "aaaa"),
            "cababa!" to listOf("ab", "baba", "cab"),
            "abXYcd" to listOf("ab", "cd"),
        )) assertEquals(expected(source, values), MvpArtifactLiteralIndex(values).replace(source, 1024))
        val broad = List(4096) { (it + 256).toChar().toString() }
        assertEquals(List(4096) { "[REDACTED]" }.joinToString(","),
            MvpArtifactLiteralIndex(broad).replace(broad.joinToString(","), 65_536))
        val prefixValues = List(256) { "a".repeat(it + 1) + "b" }
        val prefixSource = "a".repeat(100_000) + "b; public tail"
        assertEquals("a".repeat(100_000 - 256) + "[REDACTED]; public tail",
            MvpArtifactLiteralIndex(prefixValues).replace(prefixSource, 200_000))
    }

    @Test
    fun `complete artifact inventory is immutable and credential formats precede literal masking`() {
        val configured = "ordinary-setting-sensitive-value"
        val environment = mutableMapOf("PLAIN_SETTING" to configured, "PLAIN_SCHEME" to "Bearer",
            "PLAIN_FIELD" to "api_key", "PLAIN_CONTROL" to "left\u0001right")
        val evidence = MvpRunEvidence(environment, "fixture-harness", "fixture-profile", "a".repeat(64))
        environment.clear()
        environment["PLAIN_SETTING"] = "later-public-value"
        val text = evidence.redact("public; $configured; Bearer unregistered-bearer; Authorization: Basic synthetic-basic; " +
            "api_key=synthetic-api; password=synthetic-password; ghp_syntheticToken; left\u0002right; later-public-value")
        for (privateValue in listOf(configured, "Bearer", "api_key", "unregistered-bearer", "synthetic-basic",
            "synthetic-api", "synthetic-password", "syntheticToken", "leftright")) assertFalse(text.contains(privateValue))
        assertTrue(text.contains("later-public-value"))
        assertTrue(text.contains("[REDACTED]"))
        assertFalse(evidence.redactDiagnostic(configured).contains(configured))
        assertTrue(evidence.redactDiagnostic("later-public-value").contains("later-public-value"))
        val prefixCredential = "synthetic-key-prefix"
        val completeCredential = "$prefixCredential-private-suffix"
        for (orderedCredentials in listOf(
            linkedMapOf("API_KEY" to prefixCredential, "ACP_TOKEN" to completeCredential),
            linkedMapOf("ACP_TOKEN" to completeCredential, "API_KEY" to prefixCredential),
        )) {
            val overlapping = MvpRunEvidence(orderedCredentials, "fixture-harness", "fixture-profile", "a".repeat(64))
            assertEquals("before; [REDACTED]; after", overlapping.redact("before; $completeCredential; after"))
        }
        for (separator in listOf('\u000b', '\u000c', '\r')) {
            for (prefix in listOf("Bearer$separator", "Authorization:${separator}Basic$separator", "password=$separator")) {
                val raw = "before; ${prefix}synthetic-separated-credential; public"
                assertFalse(evidence.redact(raw).contains("synthetic-separated-credential"))
                assertFalse(evidence.redactDiagnostic(raw).contains("synthetic-separated-credential"))
            }
        }
        val publicContent = "public complete code line;\n".repeat(2_000)
        assertTrue(publicContent.length > 16_384)
        assertEquals(publicContent, evidence.redact(publicContent))
        for (secret in listOf("top secret", "top,secret", "top;secret", "top\nsecret", "top\u0001 secret")) {
            val policy = MvpArtifactRedactor(listOf(secret), 4096)
            for (prefix in listOf("password=", "Bearer ", "Authorization: Basic ")) {
                val masked = policy.text(prefix + secret + "; public tail")
                assertFalse(masked.contains("top"))
                assertFalse(masked.contains("secret"))
                assertTrue(masked.contains("public tail"))
            }
        }
        val forcedSource = "top secret; public"
        val forced = MvpArtifactRedactor(listOf("top secret"), 4096).text(forcedSource, 0..2)
        assertFalse(forced.contains("top"))
        assertFalse(forced.contains("secret"))
        assertTrue(forced.contains("public"))
    }

    @Test
    fun `complete request and response projections mask paths and formatting without changing captured inputs`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-artifact-privacy")), "transcript-")
        val privateValue = "ordinary-setting-sensitive-value"
        val pathValue = "private-segment"
        val renderedHeader = "## target.c"
        val evidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to privateValue, "PLAIN_PATH" to pathValue,
            "PLAIN_FORMAT" to renderedHeader), "fixture-harness", "fixture-profile", "a".repeat(64))
        val complete = "public complete code line;\n".repeat(2_000)
        val source = complete + "/* $privateValue; Authorization: Basic synthetic-basic */\n"
        val request = RepairRequest("fixture", "public $privateValue", mapOf("target.c" to source,
            "$pathValue.c" to "public extra code"), listOf(ProcessInput(privateValue)))
        val target = root.resolve("request.md")
        val admitted = retainMvpCapturedRequest(target, request, "target.c", RepairResourceBudget(), evidence)
        assertEquals(source, admitted.request.projectFiles.getValue("target.c"))
        assertTrue(admitted.initialFiles.getValue("target.c").contentEquals(source.toByteArray(Charsets.UTF_8)))
        val requestText = target.readText()
        for (value in listOf(privateValue, pathValue, renderedHeader, "synthetic-basic")) assertFalse(requestText.contains(value))
        assertTrue(requestText.contains(complete.trimEnd()))
        val response = RepairResponse("public $privateValue", listOf(SourcePatch("$pathValue.c", source)))
        val responsePath = root.resolve("response.md")
        retainMvpCapturedResponse(responsePath, response, RepairResourceBudget(), evidence)
        val responseText = responsePath.readText()
        for (value in listOf(privateValue, pathValue, "synthetic-basic")) assertFalse(responseText.contains(value))
        assertTrue(responseText.contains(complete.trimEnd()))
        assertEquals(source, response.patches.single().replacement)

        // Every retained field is encoded before opening an existing or absent transcript.
        val encodingSecret = "a?b"
        val encodingEvidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to encodingSecret),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        val publicRequest = RepairRequest("fixture", "public objective", mapOf("target.c" to "public body"), emptyList())
        val publicResponse = RepairResponse("public summary", listOf(SourcePatch("target.c", "public body")))
        val beforeRequest = Files.readAllBytes(target)
        val beforeResponse = Files.readAllBytes(responsePath)
        val absentRequest = root.resolve("refused-request.md")
        val absentResponse = root.resolve("refused-response.md")
        for (payload in listOf("a\uD800b", "a\uDC00b", "x".repeat(20_000) + "a\uD800b",
            "x".repeat(20_000) + "a\uDC00b")) {
            assertTrue(String(payload.toByteArray(Charsets.UTF_8), Charsets.UTF_8).contains(encodingSecret))
            for (candidate in listOf(publicRequest.copy(prompt = payload), publicRequest.copy(failureKind = payload),
                publicRequest.copy(projectFiles = publicRequest.projectFiles + ("$payload.c" to "public extra")),
                publicRequest.copy(projectFiles = mapOf("target.c" to payload)),
                publicRequest.copy(regressionInputs = listOf(ProcessInput(payload))))) {
                for (path in listOf(target, absentRequest)) assertFailsWith<MvpPatchException> {
                    retainMvpCapturedRequest(path, candidate, "target.c", RepairResourceBudget(), encodingEvidence)
                }
                assertTrue(Files.readAllBytes(target).contentEquals(beforeRequest))
                assertFalse(absentRequest.exists())
            }
            for (candidate in listOf(publicResponse.copy(summary = payload),
                publicResponse.copy(patches = listOf(SourcePatch("$payload.c", "public body"))),
                publicResponse.copy(patches = listOf(SourcePatch("target.c", payload))))) {
                for (path in listOf(responsePath, absentResponse)) assertFailsWith<MvpPatchException> {
                    retainMvpCapturedResponse(path, candidate, RepairResourceBudget(), encodingEvidence)
                }
                assertTrue(Files.readAllBytes(responsePath).contentEquals(beforeResponse))
                assertFalse(absentResponse.exists())
            }
        }
        val artifactDirectory = Files.createDirectories(root.resolve("evidence"))
        val retainedRequest = artifactDirectory.resolve("reconstruction-request.md")
        val retainedResponse = artifactDirectory.resolve("reconstruction-response.md")
        val validRequest = publicRequest.copy(prompt = "public a€b 😀 $encodingSecret",
            projectFiles = mapOf("target.c" to "public λ $encodingSecret"))
        val validResponse = publicResponse.copy(summary = "public a€b 😀 $encodingSecret",
            patches = listOf(SourcePatch("target.c", "public λ $encodingSecret")))
        val unicodeAdmitted = retainMvpCapturedRequest(retainedRequest, validRequest, "target.c", RepairResourceBudget(), encodingEvidence)
        retainMvpCapturedResponse(retainedResponse, validResponse, RepairResourceBudget(), encodingEvidence)
        assertEquals(validRequest.prompt, unicodeAdmitted.request.prompt)
        assertEquals(validRequest.projectFiles, unicodeAdmitted.request.projectFiles)
        for (path in listOf(retainedRequest, retainedResponse)) {
            val text = path.readText()
            assertTrue(text.contains("public a€b 😀") && text.contains("public λ"))
            assertFalse(text.contains(encodingSecret))
        }
        fun commitment(path: Path): String = java.security.MessageDigest.getInstance("SHA-256")
            .digest(Files.readAllBytes(path)).joinToString("") { "%02x".format(it) }
        val summary = root.resolve("SUMMARY-transcripts.md")
        val missing = root.resolve("not-produced")
        writeMvpSummary(summary, root, missing, missing, missing, missing, missing, "FAIL", "not run", encodingEvidence)
        assertTrue(summary.readText().contains("| Reconstruction request | `evidence/reconstruction-request.md` | `${commitment(retainedRequest)}` |"))
        assertTrue(summary.readText().contains("| Reconstruction response | `evidence/reconstruction-response.md` | `${commitment(retainedResponse)}` |"))
    }

    @Test
    fun `complete summary projects artifact paths phase names and source mapping with full public diffs`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-artifact-privacy")), "summary-")
        val privateValue = "private-segment"
        val source = root.resolve("$privateValue.c").also { it.writeText("public code") }
        val evidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to privateValue, "SHLVL" to "1"), "fixture-harness", privateValue, "a".repeat(64))
        evidence.passPhase(privateValue, "public success")
        evidence.check(privateValue, true, "public validation")
        evidence.findingSourceLocation = "$privateValue.c:12"
        evidence.findingPath = source
        val full = "--- a/public.c\n+++ b/public.c\n" + " public complete context\n".repeat(2_000)
        evidence.patchDiff = full
        evidence.patchDiffPath = root.resolve("$privateValue.patch").also { it.writeText(full) }
        val summary = root.resolve("SUMMARY.md")
        writeMvpSummary(summary, root, source, source, source, source, source, "PASS", null, evidence)
        val text = summary.readText()
        assertFalse(text.contains(privateValue))
        assertTrue(text.contains("Result: PASS"))
        assertTrue(text.contains("| PASS | public success |"))
        assertTrue(text.contains(full.trimEnd()))
        assertTrue(text.contains("| Input ELF | `[REDACTED].c` | " +
            "`0508a9dc283c9336ac0dc82b721dbf328fa7bc1195988d1dfa61d6a4822113a8` |"))
        assertEquals("public code", source.readText())
        assertEquals(full, evidence.patchDiffPath!!.readText())
        val profile = MvpSummaryProfile.MAKE
        val conflict = profile.id + "` (`" + profile.sha256.take(4)
        val refused = MvpRunEvidence(mapOf("PLAIN_SETTING" to conflict, "PRIVATE" to privateValue),
            "PRIVATE_HARNESS", profile.id, profile.sha256)
        refused.patchDiff = full
        refused.patchDiffPath = evidence.patchDiffPath
        refused.patchExplanation = "public source-change explanation $privateValue"
        refused.approvalDecision = "approved interactively"
        refused.findingPath = source
        refused.findingSourceLocation = "decompiled.c:12:3"
        val retained = root.resolve("SUMMARY-refused-detail.md")
        for (result in listOf("PASS", "FAIL", "NON_RELEASE")) {
            if (result == "FAIL") refused.failPhase("verify", "public phase detail $privateValue")
            else refused.passPhase("verify", "public phase detail $privateValue")
            refused.verification.clear()
            refused.check("behavior validation", result != "FAIL", "public validation detail $privateValue")
            writeMvpSummary(retained, root, source, source, source, source, source, result,
                "verify: public failure $privateValue".takeIf { result == "FAIL" }, refused)
            val fallback = retained.readText()
            assertTrue(fallback.contains("- Result: $result"))
            assertTrue(fallback.contains("Report detail: redacted details retained"))
            assertTrue(fallback.contains("| Input ELF | withheld | `0508a9dc283c9336ac0dc82b721dbf328fa7bc1195988d1dfa61d6a4822113a8` |"))
            assertTrue(fallback.contains("Reconstruction profile: `${profile.id}` (`${profile.sha256}`)"))
            assertFalse(fallback.contains(privateValue) || fallback.contains("PRIVATE_HARNESS"))
            val details = root.resolve(MVP_SUMMARY_DETAILS_PATH).readText()
            val detailHash = java.security.MessageDigest.getInstance("SHA-256").digest(details.toByteArray(Charsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            assertTrue(fallback.contains("| Redacted report details | `$MVP_SUMMARY_DETAILS_PATH` | `$detailHash` |"))
            assertTrue(details.contains("public source-change explanation [redacted]"))
            assertTrue(details.contains("public phase detail [redacted]"))
            assertTrue(details.contains("public validation detail [redacted]"))
            if (result == "FAIL") assertTrue(details.contains("verify: public failure [redacted]"))
            assertFalse(details.contains(privateValue) || details.contains("PRIVATE_HARNESS") || details.contains(conflict))
            assertEquals("public code", source.readText())
            assertEquals(full, refused.patchDiffPath!!.readText())
        }
        val retainedDetails = root.resolve(MVP_SUMMARY_DETAILS_PATH).readText()
        refused.patchExplanation = "unpaired \uD800 detail"
        writeMvpSummary(retained, root, source, source, source, source, source, "FAIL", "public failure", refused)
        assertTrue(retained.readText().contains("Report detail: withheld"))
        assertFalse(retained.readText().contains("| Redacted report details |"))
        assertEquals(retainedDetails, root.resolve(MVP_SUMMARY_DETAILS_PATH).readText())

        // Replacement encoding must never form a configured secret after private projection.
        val encodingSecret = "a?b"
        val encodingEvidence = MvpRunEvidence(mapOf("PLAIN_SETTING" to encodingSecret),
            "fixture-harness", profile.id, profile.sha256)
        encodingEvidence.patchDiffPath = evidence.patchDiffPath
        val encodedSummary = root.resolve("SUMMARY-encoding.md")
        for (payload in listOf("a\uD800b", "a\uDC00b", "a\uD800b" + "x".repeat(1_024),
            "a\uDC00b" + "x".repeat(1_024))) {
            assertTrue(String(payload.toByteArray(Charsets.UTF_8), Charsets.UTF_8).contains(encodingSecret))
            encodingEvidence.patchDiff = if (payload.length < 1_024) null else full
            encodingEvidence.patchExplanation = "public explanation $payload"
            writeMvpSummary(encodedSummary, root, source, source, source, source, source, "PASS", null, encodingEvidence)
            val encodedText = encodedSummary.readText()
            assertFalse(encodedText.contains(encodingSecret))
            assertTrue(encodedText.contains("- Result: PASS"))
            assertTrue(encodedText.contains("Report detail: withheld"))
            assertFalse(encodedText.contains("| Redacted report details |"))
            assertTrue(encodedText.contains("| Input ELF | withheld | `0508a9dc283c9336ac0dc82b721dbf328fa7bc1195988d1dfa61d6a4822113a8` |"))
            assertEquals(retainedDetails, root.resolve(MVP_SUMMARY_DETAILS_PATH).readText())
            assertEquals("public code", source.readText())
            assertEquals(full, evidence.patchDiffPath!!.readText())
        }
        encodingEvidence.patchDiff = full
        for (prefixLength in listOf(1_024, 20_000)) for (omittedTail in listOf("a\uD800b", "a\uDC00b")) {
            encodingEvidence.patchExplanation = "public explanation " + "x".repeat(prefixLength) + omittedTail
            writeMvpSummary(encodedSummary, root, source, source, source, source, source, "PASS", null, encodingEvidence)
            val boundedSummary = encodedSummary.readText()
            assertFalse(boundedSummary.contains(encodingSecret))
            assertFalse(boundedSummary.contains("Report detail:"))
            if (prefixLength < 16_384) assertTrue(boundedSummary.contains("public explanation " + "x".repeat(128)))
            else assertTrue(boundedSummary.contains("[oversized text omitted]"))
            assertTrue(boundedSummary.contains(full.trimEnd()))
            assertEquals("public code", source.readText())
            assertEquals(full, evidence.patchDiffPath!!.readText())
        }
        encodingEvidence.patchExplanation = "public explanation a€b 😀 λ"
        writeMvpSummary(encodedSummary, root, source, source, source, source, source, "PASS", null, encodingEvidence)
        assertTrue(encodedSummary.readText().contains(encodingEvidence.patchExplanation))
        assertFalse(encodedSummary.readText().contains("Report detail:"))
    }

    @Test
    fun `complete artifact byte admission handles UTF8 boundaries markers inventory rejection and interruption`() {
        for (sample in listOf("a", "é", "€", "😀", "\uD800", "\uDC00", "x\uD800y")) {
            val bytes = sample.toByteArray(Charsets.UTF_8).size.toLong()
            assertEquals(sample, MvpArtifactRedactor(emptyList(), bytes).text(sample))
            if (bytes > 1) assertFailsWith<MvpPatchException> { MvpArtifactRedactor(emptyList(), bytes - 1).text(sample) }
        }
        assertEquals("😀", MvpArtifactText(4).append("\uD83D").append("\uDE00").build())
        assertFailsWith<MvpPatchException> { MvpArtifactText(3).append("\uD83D").append("\uDE00") }
        assertFailsWith<MvpPatchException> { MvpArtifactRedactor(emptyList(), 3).text("\uD83D\u0001\uDE00") }
        assertEquals("[REDACTED]", MvpArtifactRedactor(listOf("x"), 10).text("x"))
        assertFailsWith<MvpPatchException> { MvpArtifactRedactor(listOf("x"), 9).text("x") }
        assertFailsWith<MvpPatchException> { MvpArtifactRedactor(listOf("[REDACTED]"), 1024).text("password=synthetic") }
        val oversized = object : AbstractCollection<String>() {
            override val size: Int = 4097
            override fun iterator(): Iterator<String> = error("oversized inventory must not be iterated")
        }
        assertFailsWith<IllegalArgumentException> { MvpArtifactRedactor(oversized, 1024) }
        assertFailsWith<IllegalArgumentException> { MvpArtifactRedactor(listOf("x".repeat(1024 * 1024 + 1)), 1024) }
        assertEquals("public", MvpArtifactRedactor(listOf("x".repeat(1024 * 1024)), 1024).text("public"))
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-artifact-privacy")), "refusal-")
        val target = root.resolve("request.md").also { it.writeText("existing public transcript") }
        val request = RepairRequest("fixture", "public objective", mapOf("target.c" to "public code"), emptyList())
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64), 16)
        assertFailsWith<MvpPatchException> { retainMvpCapturedRequest(target, request, "target.c", RepairResourceBudget(), evidence) }
        assertEquals("existing public transcript", target.readText())
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> { evidence.redact("public") }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    @Test
    fun `captured regression payloads obey aggregate byte and argument limits before transcript writes`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "regression-")
        val path = root.resolve("request.md")
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val arguments = mutableListOf("é", "x")
        val stdin = byteArrayOf(1, 2, 3)
        val inputs = mutableListOf(ProcessInput("case", arguments, stdin))
        val request = RepairRequest("fixture", "public objective", mapOf("target.c" to "public code"), inputs)
        val exact = "case".toByteArray(Charsets.UTF_8).size + arguments.sumOf { it.toByteArray(Charsets.UTF_8).size } + stdin.size
        val budget = RepairResourceBudget(maximumRegressionInputBytes = exact.toLong(), maximumRegressionArguments = 2)
        val admitted = retainMvpCapturedRequest(path, request, "target.c", budget, evidence)
        arguments.clear(); stdin.fill(9); inputs.clear()
        val retained = admitted.request.regressionInputs.single()
        assertEquals(listOf("é", "x"), retained.args)
        assertTrue(retained.stdin.contentEquals(byteArrayOf(1, 2, 3)))
        fun refused(input: List<ProcessInput>, limits: RepairResourceBudget = budget) {
            path.writeText("existing public transcript")
            assertFailsWith<MvpPatchException> {
                retainMvpCapturedRequest(path, request.copy(regressionInputs = input), "target.c", limits, evidence)
            }
            assertEquals("existing public transcript", path.readText())
        }
        refused(listOf(ProcessInput("case", listOf("é", "x"), byteArrayOf(1, 2, 3))),
            budget.copy(maximumRegressionInputBytes = exact - 1L))
        refused(listOf(ProcessInput("case", stdin = ByteArray(exact))))
        refused(listOf(ProcessInput("case", listOf("€".repeat(exact)))))
        val oversizedArguments = object : AbstractList<String>() {
            override val size: Int = 3
            override fun get(index: Int): String = error("oversized argument list must not be iterated")
        }
        refused(listOf(ProcessInput("case", oversizedArguments)))
        val separate = listOf(ProcessInput("a", listOf("x"), byteArrayOf(1)),
            ProcessInput("b", listOf("x"), byteArrayOf(2)))
        refused(separate, budget.copy(maximumRegressionInputBytes = 5))
        refused(separate, budget.copy(maximumRegressionArguments = 1))
        val payload = ProcessInput("case", stdin = ByteArray(256))
        refused(listOf(payload), budget.copy(maximumRegressionInputBytes = 260, maximumRequestBytes = 260))
    }

    @Test
    fun `captured request admission rejects raw padding and entry excess before replacing transcripts`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "request-")
        val path = root.resolve("request.md")
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val budget = RepairResourceBudget(maximumRegressionInputBytes = 1, maximumRequestBytes = 256)
        val request = RepairRequest("fixture", "public objective", mapOf("target.c" to "public code"), emptyList())
        fun refused(value: RepairRequest, limits: RepairResourceBudget = budget) {
            path.writeText("existing public transcript")
            assertFailsWith<MvpPatchException> {
                retainMvpCapturedRequest(path, value, "target.c", limits, evidence)
            }
            assertEquals("existing public transcript", path.readText())
        }
        val padded = request.copy(prompt = " ".repeat(1_024) + request.prompt)
        assertEquals(request.prompt, padded.prompt.trim())
        refused(padded)
        refused(request.copy(regressionInputs = listOf(ProcessInput("x".repeat(256)))))
        refused(request.copy(projectFiles = request.projectFiles + ("extra.c" to "public code")),
            budget.copy(maximumContextFiles = 1, maximumPatchFiles = 1))
        refused(request.copy(regressionInputs = listOf(ProcessInput("first"), ProcessInput("second"))),
            budget.copy(maximumRegressionInputs = 1))
    }

    @Test
    fun `captured request UTF8 boundaries match encoded bytes and frozen code remains complete`() {
        for (sample in listOf("a", "é", "€", "😀", "\uD800", "\uDC00", "x\uD800y", "\uD800\uDC00")) {
            val request = RepairRequest("fixture", "public $sample", mapOf("target.c" to "body$sample"), emptyList())
            val objective = request.prompt.trim() + "\n\nEdit target.c in place. Do not create, delete, or modify any other file."
            val common = listOf("project", RepairClientAgentHarness.FAILURE_KIND_CONTEXT_ID,
                request.failureKind, "target.c", request.projectFiles.getValue("target.c"))
                .sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
            val exact = common + maxOf(request.prompt.toByteArray(Charsets.UTF_8).size,
                objective.toByteArray(Charsets.UTF_8).size)
            val budget = RepairResourceBudget(maximumRegressionInputBytes = 1, maximumRequestBytes = exact)
            val admitted = prepareMvpCapturedRequest(request, "target.c", budget)
            assertEquals(objective, admitted.objective)
            assertTrue(admitted.initialFiles.getValue("target.c").contentEquals(
                request.projectFiles.getValue("target.c").toByteArray(Charsets.UTF_8)))
            assertFailsWith<MvpPatchException> {
                prepareMvpCapturedRequest(request, "target.c", budget.copy(maximumRequestBytes = exact - 1))
            }
        }
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "complete-")
        val path = root.resolve("request.md")
        val code = "int public_value = 7; // λ\n".repeat(1_200)
        val files = linkedMapOf("target.c" to code)
        val inputs = mutableListOf(ProcessInput("original"))
        val request = RepairRequest("fixture", "  public objective  ", files, inputs)
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val admitted = retainMvpCapturedRequest(path, request, "target.c", RepairResourceBudget(), evidence)
        files["target.c"] = "later mutation"
        files["extra.c"] = "later file"
        inputs.clear()
        assertEquals(mapOf("target.c" to code), admitted.request.projectFiles)
        assertEquals(listOf("original"), admitted.request.regressionInputs.map { it.id })
        assertTrue(admitted.initialFiles.getValue("target.c").contentEquals(code.toByteArray(Charsets.UTF_8)))
        val text = path.readText()
        assertTrue(text.length > 16_384 && text.contains(code.trimEnd()))
        assertTrue(text.contains("## Objective\n\n  public objective  \n"))
        assertFalse(text.contains("preview truncated"))
    }

    @Test
    fun `captured staging bytes are admitted before retaining request content`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "staging-")
        val path = root.resolve("request.md")
        val request = RepairRequest("fixture", "public objective", mapOf("target.c" to "€😀"), emptyList())
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val bytes = request.projectFiles.getValue("target.c").toByteArray(Charsets.UTF_8).size.toLong()
        val budget = RepairResourceBudget(maximumStagingBytes = bytes)
        val admitted = retainMvpCapturedRequest(path, request, "target.c", budget, evidence)
        assertEquals(bytes, admitted.initialFiles.values.sumOf { it.size.toLong() })
        path.writeText("existing public transcript")
        assertFailsWith<MvpPatchException> {
            retainMvpCapturedRequest(path, request, "target.c", budget.copy(maximumStagingBytes = bytes - 1), evidence)
        }
        assertEquals("existing public transcript", path.readText())
    }

    @Test
    fun `captured response admission protects transcripts and preserves complete replacements`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "response-")
        val path = root.resolve("response.md")
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val response = RepairResponse("é", listOf(SourcePatch("target.c", "€")))
        val exact = listOf(response.summary, "target.c", "€").sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
        val budget = RepairResourceBudget(maximumResponseBytes = exact, maximumPatchBytes = 3)
        retainMvpCapturedResponse(path, response, budget, evidence)
        assertTrue(path.readText().contains("é") && path.readText().contains("€"))
        fun refused(value: RepairResponse, limits: RepairResourceBudget) {
            path.writeText("existing public transcript")
            assertFailsWith<MvpPatchException> { retainMvpCapturedResponse(path, value, limits, evidence) }
            assertEquals("existing public transcript", path.readText())
        }
        refused(response, budget.copy(maximumResponseBytes = exact - 1))
        refused(response, budget.copy(maximumPatchBytes = 2))
        refused(response.copy(patches = response.patches + SourcePatch("extra.c", "public")),
            RepairResourceBudget(maximumPatchFiles = 1))
        assertFailsWith<MvpPatchException> {
            prepareMvpCapturedResponse(" ".repeat(256) + "public", "target.c", "x",
                RepairResourceBudget(maximumResponseBytes = 64))
        }
        assertFailsWith<MvpPatchException> {
            prepareMvpCapturedResponse(null, "target.c", "x", RepairResourceBudget(maximumResponseBytes = 9))
        }
        assertEquals("agent supplied a captured full-file replacement",
            prepareMvpCapturedResponse(null, "target.c", "x", RepairResourceBudget()).summary)
        val code = "int public_value = 7; // λ\n".repeat(1_200)
        val complete = prepareMvpCapturedResponse("  public summary  ", "target.c", code, RepairResourceBudget())
        assertEquals("public summary", complete.summary)
        retainMvpCapturedResponse(path, complete, RepairResourceBudget(), evidence)
        val text = path.readText()
        assertTrue(text.length > 16_384 && text.contains(code.trimEnd()))
        assertFalse(text.contains("preview truncated"))
    }

    @Test
    fun `patch summary diagnostic fields share credential masking without shortening complete public diffs`() {
        val root = createTempDirectory(
            Files.createDirectories(Path.of("build/test-tmp/mvp-summary-privacy")), "summary-",
        )
        val configured = "ordinary-setting-sensitive-value"
        val bearer = "unregistered-summary-bearer"
        val basic = "c3ludGhldGljOnNlbnRpbmVs"
        val api = "unregistered-summary-api"
        val password = "unregistered-summary-password"
        val token = "unregistered-summary-token"
        val diagnostic = "before; $configured; Bearer $bearer; Authorization: Basic $basic; " +
            "api_key=$api; password=$password; ghp_$token; after"
        val environment = mapOf("PLAIN_SETTING" to configured, "PLAIN_INDICATOR" to "Bearer", "PLAIN_FIELD" to "api_key")
        val evidence = MvpRunEvidence(environment, diagnostic, "fixture-profile", "a".repeat(64)).apply {
            failPhase("reconstruct", diagnostic)
            check("validation", false, diagnostic)
            patchExplanation = diagnostic
            approvalDecision = diagnostic
            isolation = diagnostic
        }
        val fullDiff = "--- a/public.c\n+++ b/public.c\n" + " public approved context line\n".repeat(1000)
        assertTrue(fullDiff.length > 16_384)
        evidence.patchDiff = fullDiff
        evidence.patchDiffPath = root.resolve("approved.patch").also { it.writeText(fullDiff) }
        val summary = root.resolve("SUMMARY.md")
        writeMvpSummary(summary, root, root.resolve("input.elf"), root.resolve("raw.c"),
            root.resolve("source.c"), root.resolve("patched.c"), root.resolve("binary"), "FAIL", diagnostic, evidence)
        val text = summary.readText()
        listOf(configured, bearer, basic, api, password, token, "Bearer", "api_key").forEach {
            assertFalse(text.contains(it), "diagnostic value survived summary redaction")
        }
        assertTrue(text.contains("[redacted]"))
        assertTrue(text.contains("| reconstruct | FAIL | before; "))
        assertTrue(text.contains("| validation | FAIL | before; "))
        assertTrue(text.contains("Result: FAIL"))
        assertTrue(text.contains(fullDiff.trimEnd()))
        assertEquals(fullDiff, root.resolve("approved.patch").readText())
        assertTrue(text.contains("| Approved patch | `approved.patch` | " +
            "`adc753498270d3d87d1ee4e3034b0a25805bb4337bf7805dff9bf8964c7f3796` |"))
    }

    @Test
    fun `patch diagnostic previews keep shared bounds and sensitive omission markers safe`() {
        val markers = listOf("[oversized text omitted]", "[redacted]", "[unredactable text omitted]")
        val evidence = MvpRunEvidence(markers.mapIndexed { index, value -> "PLAIN_$index" to value }.toMap(),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        assertEquals("", evidence.redactDiagnostic("x".repeat(16_385)))
        assertEquals("", evidence.redactDiagnostic("Authorization: Basic synthetic-encoded-value"))
        val ordinary = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val preview = ordinary.redactDiagnostic("public ".repeat(200))
        assertTrue(preview.endsWith("… [preview truncated]"))
        assertTrue(preview.length <= 512 + "… [preview truncated]".length)
        assertFailsWith<IllegalArgumentException> {
            MvpRunEvidence((0..4096).associate { "PLAIN_$it" to "value-$it" },
                "fixture-harness", "fixture-profile", "a".repeat(64))
        }
        val root = createTempDirectory(
            Files.createDirectories(Path.of("build/test-tmp/mvp-summary-privacy")), "normalization-",
        )
        val privateFallback = "No source patch was generated before the workflow stopped."
        val secrets = markers + listOf(privateFallback, "alpha beta", "<br>", "\\|")
        val safe = MvpRunEvidence(secrets.mapIndexed { index, value -> "PLAIN_$index" to value }.toMap(),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        safe.failPhase("reconstruct", "before\nafter|end")
        for ((index, explanation) in listOf("", "alpha\tbeta").withIndex()) {
            safe.patchExplanation = explanation
            val summary = root.resolve("summary-$index.md")
            writeMvpSummary(summary, root, root.resolve("input.elf"), root.resolve("raw.c"),
                root.resolve("source.c"), root.resolve("patched.c"), root.resolve("binary"), "FAIL", "fixture failure", safe)
            val text = summary.readText()
            secrets.forEach { assertFalse(text.contains(it), "formatting synthesized a private diagnostic value") }
        }
    }

    @Test
    fun `runs patch workflow and publishes verified artifacts`() {
        val tempDir = createTempDirectory("mvp-patch-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        output.resolve("stale/nested").createDirectories()
        output.resolve("stale/nested/old.txt").writeText("old output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy to the local buffer without exposing top-secret-value", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            harness = RepairClientAgentHarness(client),
            environment = mapOf("API_KEY" to "top-secret-value"),
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* ghidra */ }\n") },
            binaryExecution = testExecutionBoundary(),
            publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
        ).run(MvpPatchOptions(input, output))

        assertEquals(2, client.requests.size)
        assertEquals(setOf("decompiled.c", "ghidra_decompiled.c"), client.requests.first().projectFiles.keys)
        assertTrue(client.requests.first().projectFiles.getValue("ghidra_decompiled.c").contains("ghidra"))
        assertEquals(setOf("decompile/decompiled.c", "patched.c"), client.requests.last().projectFiles.keys)
        assertTrue(output.resolve("decompile/decompiled.c").readText().contains("badge[i]"))
        assertFalse(output.resolve("stale/nested/old.txt").exists())
        assertTrue(output.resolve("patched_c/patched.c").readText().contains("return 0;"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: NON_RELEASE"))
        assertTrue(summary.contains("## CWE-787 Evidence and Source Mapping"))
        assertTrue(summary.contains("decompiled.c:"))
        assertTrue(summary.contains("## Approved Source Change"))
        assertTrue(summary.contains("bound copy to the local buffer"))
        assertFalse(summary.contains("top-secret-value"))
        assertTrue(summary.contains("[redacted]"))
        assertTrue(summary.contains("approved interactively"))
        assertTrue(summary.contains("Agent harness: `agent-harness-unprovisioned`"))
        assertTrue(summary.contains("Reconstruction profile: `generated-c-make-v1`"))
        assertTrue(summary.contains("| verify | PASS |"))
        assertTrue(summary.contains("binary hardening inspection | PASS"))
        assertTrue(summary.contains("behavior validation | PASS"))
        assertTrue(summary.contains("evidence/approved.patch"))
        assertTrue(output.resolve("evidence/approved.patch").exists())
        assertTrue(output.resolve("evidence/cwe-787-sanitizer.txt").exists())
        assertTrue(output.resolve("evidence/reconstruction-request.md").readText().contains("Binary-derived context"))
        assertTrue(output.resolve("evidence/reconstruction-response.md").readText().contains("badge[i]"))
        assertTrue(output.resolve("evidence/patch-request.md").readText().contains("Sanitizer evidence"))
        assertTrue(output.resolve("evidence/patch-response.md").readText().contains("[REDACTED]"))
        assertTrue(Regex("`[0-9a-f]{64}`").containsMatchIn(summary))

        val patched = ProcessBuilder(output.resolve(".work/patched_release").pathString).start()
        assertEquals(0, patched.waitFor())
        assertEquals("[03] Alexandria Stone\n", patched.inputStream.bufferedReader().readText())
    }

    @Test
    fun `MVP compiler comes from the admitted Make or Ninja profile`() {
        val source = Path.of("/private/source.c")
        val target = Path.of("/private/output")
        for (profile in ReconstructionProfiles.builtIn) {
            val compiler = ReconstructionAdapters.resolve(profile).mvpPatchCompiler
            val sanitizer = compiler.command(profile, source, target, sanitizer = true, warningsAsErrors = false)
            val release = compiler.command(profile, source, target, sanitizer = false, warningsAsErrors = true)
            assertEquals(profile.adapterConfiguration.getValue("compiler-driver").single(), sanitizer.first())
            assertEquals(sanitizer.first(), release.first())
            assertTrue("-fsanitize=address,undefined" in sanitizer)
            assertTrue("-Werror" in release)
            assertTrue("-Wl,-z,relro,-z,now" in release)
        }
    }

    @Test
    fun `MVP rejects a forged compiler profile before touching output`() {
        val builtIn = ReconstructionProfiles.default
        val forged = ReconstructionProfile(
            builtIn.schemaVersion,
            builtIn.id,
            builtIn.layout,
            builtIn.budgets,
            builtIn.adapterConfiguration + ("compiler-driver" to listOf("false")),
        )
        val output = createTempDirectory("mvp-forged-profile-").resolve("output")
        val failure = assertFailsWith<IllegalArgumentException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(QueueRepairClient()),
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(Path.of("/absent/input"), output), forged)
        }
        assertTrue(failure.message.orEmpty().contains("not admitted"))
        assertFalse(output.exists())
    }

    @Test
    fun `does not publish binary when patch is not approved`() {
        val tempDir = createTempDirectory("mvp-reject-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy to the local buffer", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(client),
                approve = { false },
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("decompiled c") },
                binaryExecution = testExecutionBoundary(),
                publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
            ).run(MvpPatchOptions(input, output))
        }

        assertTrue(failure.message.orEmpty().contains("not approved"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: FAIL"))
        assertTrue(summary.contains("Failure phase and reason: patch: patch was not approved"))
        assertTrue(summary.contains("rejected interactively"))
        assertTrue(summary.contains("Verified final binary: `not published`"))
    }

    @Test
    fun `rejects non ELF input before decompilation`() {
        val tempDir = createTempDirectory("mvp-invalid-")
        val input = tempDir.resolve("not-elf")
        input.writeText("not an elf")
        val output = tempDir.resolve("output")

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(QueueRepairClient()),
                decompiler = BinaryDecompiler { _, _, _, _ -> error("must not run") },
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("64-bit ELF"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
    }

    @Test
    fun `yes automation records approval without prompting`() {
        val tempDir = createTempDirectory("mvp-yes-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            harness = RepairClientAgentHarness(client),
            approve = { error("--yes must bypass the interactive prompt") },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("decompiled c") },
            binaryExecution = testExecutionBoundary(),
            publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
        ).run(MvpPatchOptions(input, output, assumeYes = true))

        assertTrue(output.resolve("summary/SUMMARY.md").readText().contains("approved by --yes automation"))
    }

    @Test
    fun `explicit legacy provenance validates only as non release compatibility`() {
        val tempDir = createTempDirectory("mvp-legacy-non-release-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bounded compatibility patch", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            harness = RepairClientAgentHarness(client),
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* ghidra */ }\n") },
            binaryExecution = testExecutionBoundary(),
            harnessProvenance = "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-none:deprecated",
        ).run(MvpPatchOptions(input, output))

        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: NON_RELEASE"))
        assertTrue(summary.contains("legacy-openai"))
        assertFalse(output.resolve("evidence/$RECONSTRUCTION_AGENT_EVIDENCE").exists())
        assertFalse(output.resolve("evidence/$PATCH_AGENT_EVIDENCE").exists())
    }

    @Test
    fun `rejects placeholder reconstruction before compilation`() {
        val tempDir = createTempDirectory("mvp-placeholder-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("placeholder", listOf(SourcePatch("decompiled.c", "int main(void) { return 0; }\n"))),
        )

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(client),
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("binary-derived ghidra context") },
                binaryExecution = testExecutionBoundary(),
                publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("placeholder"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        assertTrue(output.resolve("evidence/reconstruction-request.md").exists())
        assertTrue(output.resolve("evidence/reconstruction-response.md").exists())
    }

    @Test
    fun `allows top level docker output mount`() {
        val output = Path.of("/output")
        val input = Path.of("/input/binary_01")

        assertTrue(output.root != null)
        assertTrue(output != output.root)
        assertTrue(output != input.parent)
    }

    private class QueueRepairClient(vararg responses: RepairResponse) : RepairClient {
        private val responses = ArrayDeque(responses.toList())
        val requests = mutableListOf<RepairRequest>()

        override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
            requests += request
            return responses.removeFirst()
        }
    }

    private fun testExecutionBoundary() = BinaryExecutionBoundary { executable, directory, environment ->
        val process = ProcessBuilder(executable.toAbsolutePath().toString())
            .directory(directory.toFile())
            .apply { environment().putAll(environment) }
            .start()
        BinaryExecutionResult(
            process.waitFor(),
            process.inputStream.bufferedReader().readText(),
            process.errorStream.bufferedReader().readText(),
            BinaryIsolation("deterministic test boundary", networkIsolated = true, credentialsIsolated = true),
        )
    }

    private fun compileC(tempDir: Path, name: String, source: String): Path {
        val sourcePath = tempDir.resolve("$name.c")
        val binary = tempDir.resolve(name)
        sourcePath.writeText(source)
        val process = ProcessBuilder("gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", sourcePath.pathString, "-o", binary.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { output }
        return binary
    }

    private fun originalSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent()

    private fun vulnerableSource() = """
        #include <stdio.h>
        int main(void) {
            char badge[8];
            const char *message = "[03] Alexandria Stone";
            for (volatile int i = 0; message[i] != '\0'; i++) {
                badge[i] = message[i];
            }
            puts("[03] Alexandria Stone");
            return badge[0] == 0;
        }
    """.trimIndent() + "\n"

    private fun patchedSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent() + "\n"
}
