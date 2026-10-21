package decompengine.web

import decompengine.acp.acpSandboxCanonicalStringDigest
import decompengine.binary.ElfMetadata
import decompengine.jobs.Job
import decompengine.oracle.core.OracleJson
import decompengine.project.sha256
import decompengine.repair.*
import decompengine.validation.ProcessInput
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.*
import kotlin.test.*

/** Authored receipt DTOs and rendered strings only. No validation, process, server or browser trial. */
class RecordedRepairValidationCasesTest {
    private val graph = "a".repeat(64)
    private val nonce = "validation_" + "b".repeat(32)
    private data class Fixture(val binding: RepairRecordedValidationObservation, val root: JsonObject, val bytes: ByteArray,
        val diffBytes: ByteArray? = null)
    private fun encoded(bytes: ByteArray) = JsonPrimitive(Base64.getEncoder().encodeToString(bytes))
    private fun executableManifest(role: String): String? = when (role) {
        "reference" -> "1".repeat(64)
        "candidate" -> "2".repeat(64)
        else -> null
    }
    private fun sandboxFields(fields: List<Pair<String, String>>) = JsonArray(fields.map { (name, value) ->
        JsonArray(listOf(JsonPrimitive(name), JsonPrimitive(value)))
    })
    private fun sandboxDigest(fields: List<Pair<String, String>>) = sha256(buildString {
        fields.forEach { (name, value) -> append(name.length).append(':').append(name)
            .append(value.length).append(':').append(value).append(';') }
    }.toByteArray(Charsets.UTF_8))
    private fun scope(role: String, id: String?, exit: Int = 0, stdout: ByteArray = byteArrayOf(0, -1),
        stderr: ByteArray = byteArrayOf(10)): JsonObject = buildJsonObject {
        put("role", role); put("inputId", id?.let(::JsonPrimitive) ?: JsonNull)
        val command = listOf("PRIVATE-command")
        put("output", buildJsonObject {
            put("command", JsonArray(command.map(::JsonPrimitive)))
            put("exitCode", exit); put("stdoutBase64", encoded(stdout)); put("stderrBase64", encoded(stderr)); put("networkIsolated", true)
        })
        val quota = buildJsonObject {
            put("provider", "dedicated-tmpfs-size+nr_inodes"); put("mountId", 1); put("maximumBytes", 4096)
            put("maximumEntries", 20); put("mountPathSha256", "7".repeat(64))
        }
        put("writableQuota", quota)
        val fields = linkedMapOf("provider" to "bubblewrap+systemd-cgroup-v2",
            "launch[0].purpose" to "CANDIDATE_VALIDATION", "launch[0].mergeError" to "false",
            "launch[0].writableMountClosure" to "9".repeat(64),
            "launch[0].command" to acpSandboxCanonicalStringDigest(command),
            "authority[0].mode" to "READ_WRITE", "PRIVATE-host-field" to "PRIVATE-peer-path")
        for (name in listOf("cgroup.pids", "cgroup.memory", "cgroup.cpu", "network", "nestedUserns", "newSession",
                "dieWithParent", "launch[0].gate.positiveByte")) fields[name] = "true"
        executableManifest(role)?.let {
            fields["launch[0].executable.manifest"] = it; fields["launch[0].executable.configuredManifest"] = it
        }
        for ((field, key) in mapOf("provider" to "provider", "mount" to "mountId", "bytes" to "maximumBytes",
                "entries" to "maximumEntries", "path" to "mountPathSha256"))
            fields["authority[0].quota.$field"] = quota.getValue(key).jsonPrimitive.content
        put("sandboxSha256", sandboxDigest(fields.toList())); put("sandboxFields", sandboxFields(fields.toList()))
        put("cleanupVerified", true)
    }
    private fun fixture(count: Int = 2, outcome: RepairValidationObservedOutcome = RepairValidationObservedOutcome.BEHAVIOR_CHECKED,
        mismatch: Boolean = false, exit: Int = 0): Fixture {
        val ids = (0 until count).map { "PRIVATE-case-" + it.toString().padStart(4, '0') }
        val corpus = repairRegressionCorpusSha256(ids.map { ProcessInput(it) })
        val original = "6".repeat(64).takeUnless { outcome == RepairValidationObservedOutcome.COMPILE_VALID }
        val rebuilt = "7".repeat(64).takeUnless { outcome == RepairValidationObservedOutcome.COMPILE_FAILED }
        val scopes = listOf(scope("build", null, if (outcome == RepairValidationObservedOutcome.COMPILE_FAILED) 2 else 0)) +
            if (outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED) ids.flatMapIndexed { index, id ->
                listOf(scope("reference", id, exit), scope("candidate", id, exit,
                    if (mismatch && index == 0) byteArrayOf(0, 1) else byteArrayOf(0, -1)))
            } else emptyList()
        val root = buildJsonObject {
            put("schemaVersion", 2); put("provider", "generated-c-linux-bubblewrap-cgroup-v1"); put("profileId", "authored")
            for ((name, digit) in listOf("sourceRevisionSha256" to '2', "profileSha256" to '3', "indexSha256" to '4', "runtimeSha256" to '8'))
                put(name, digit.toString().repeat(64))
            put("regressionCorpusSha256", corpus); put("runtimeConfiguration", JsonObject(emptyMap()))
            put("behaviorBudgetEvidence", JsonObject(emptyMap())); put("sourceSnapshot", JsonNull); put("buildOutputLink", JsonNull)
            fun executable(hash: String?, role: String) = hash?.let { buildJsonObject {
                put("sha256", it); put("runtimeManifestSha256", requireNotNull(executableManifest(role)))
            } } ?: JsonNull
            put("originalExecutable", executable(original, "reference")); put("rebuiltExecutable", executable(rebuilt, "candidate"))
            put("inputs", JsonArray(ids.map { buildJsonObject { put("id", it); put("args", JsonArray(emptyList())); put("stdinBase64", "") } }))
            put("scopes", JsonArray(scopes)); put("outcome", outcome.name.lowercase().replace('_', '-'))
            put("caseCount", if (outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED) count else 0)
            put("matches", outcome == RepairValidationObservedOutcome.BEHAVIOR_CHECKED && !mismatch && count > 0)
            put("cleanupVerified", true); put("assurance", "strict-contained")
        }
        val bytes = OracleJson.canonicalBytes(root)
        val proof = RepairValidationProof("2".repeat(64), "3".repeat(64), "4".repeat(64), corpus,
            original, rebuilt, "8".repeat(64), sha256(bytes), true, RepairValidationAssurance.STRICT_CONTAINED)
        val identity = RepairRecordedIdentity("root_" + "1".repeat(24), false)
        val invocation = RepairValidationInvocation(nonce, "run_00000001", identity.value,
            proof.sourceRevisionSha256, proof.profileSha256, proof.indexSha256, corpus)
        return rebind(Fixture(RepairRecordedValidationObservation(invocation.commitmentSha256(), identity, proof, outcome,
            RepairRecordedValidationObservedArtifact(recordedRepairArtifactReference(corpus, repairValidationReceiptPath(nonce, sha256(bytes))),
                sha256(bytes), bytes.size.toLong()), null), root, bytes), root)
    }
    private fun rebind(f: Fixture, root: JsonObject): Fixture {
        val bytes = OracleJson.canonicalBytes(root)
        val diffBytes = if (root["outcome"]?.jsonPrimitive?.content == "behavior-checked" &&
            root["matches"]?.jsonPrimitive?.booleanOrNull == false) OracleJson.canonicalBytes(buildJsonObject {
            put("id", "PRIVATE-derived-label"); put("matches", false)
            put("cases", JsonArray(root.getValue("inputs").jsonArray.map { input ->
                buildJsonObject { put("id", input.jsonObject.getValue("id")) }
            }))
        }) else null
        val diff = diffBytes?.let { RepairRecordedValidationObservedArtifact(recordedRepairArtifactReference(
            f.binding.proof.regressionCorpusSha256, repairValidationDiffPath(sha256(it))), sha256(it), it.size.toLong()) }
        return f.copy(root = root, bytes = bytes, diffBytes = diffBytes,
            binding = f.binding.copy(proof = f.binding.proof.copy(evidenceSha256 = sha256(bytes)),
                primary = f.binding.primary.copy(artifact = recordedRepairArtifactReference(
                    f.binding.proof.regressionCorpusSha256, repairValidationReceiptPath(nonce, sha256(bytes))),
                    sha256 = sha256(bytes), bytes = bytes.size.toLong()), diff = diff))
    }
    private fun scopes(f: Fixture, values: List<JsonElement>) = rebind(f, JsonObject(f.root + ("scopes" to JsonArray(values))))
    private fun output(f: Fixture, index: Int, fields: Map<String, JsonElement>): Fixture {
        val rows = f.root.getValue("scopes").jsonArray.toMutableList()
        val scope = rows[index].jsonObject
        rows[index] = JsonObject(scope + ("output" to JsonObject(scope.getValue("output").jsonObject + fields)))
        return scopes(f, rows)
    }
    private fun checked(f: Fixture, page: Int = 1) = checkedRecordedRepairValidationObservation(f.binding, f.bytes, f.diffBytes, page)
    private fun page(f: Fixture, number: Int = 1) = requireNotNull(checked(f, number).casePage)
    private fun corrupt(f: Fixture) {
        assertEquals(RepairEvidenceArtifactState.AVAILABLE, checked(f).primaryState)
        assertEquals(RecordedRepairValidationCaseState.CORRUPT, page(f).state)
        assertTrue(page(f).cases.isEmpty())
    }

    private fun fields(f: Fixture, index: Int = 1): List<Pair<String, String>> =
        f.root.getValue("scopes").jsonArray[index].jsonObject.getValue("sandboxFields").jsonArray.map {
            it.jsonArray[0].jsonPrimitive.content to it.jsonArray[1].jsonPrimitive.content
        }
    private fun sandbox(f: Fixture, values: List<Pair<String, String>>, index: Int = 1,
        digest: String = sandboxDigest(values)): Fixture {
        val rows = f.root.getValue("scopes").jsonArray.toMutableList()
        rows[index] = JsonObject(rows[index].jsonObject + mapOf("sandboxFields" to sandboxFields(values),
            "sandboxSha256" to JsonPrimitive(digest)))
        return scopes(f, rows)
    }

    @Test fun `hash bound receipts with stale sandbox digests cannot expose case comparisons`() {
        val f = fixture()
        assertEquals(RecordedRepairValidationCaseState.AVAILABLE, page(f).state)
        for (index in 0 until f.root.getValue("scopes").jsonArray.size)
            corrupt(sandbox(f, fields(f, index), index, "0".repeat(64)))
    }
    @Test fun `empty and duplicate sandbox field inventories fail even after both hashes are rebound`() {
        val f = fixture(); val valid = fields(f)
        corrupt(sandbox(f, emptyList()))
        corrupt(sandbox(f, valid + valid.first()))
    }
    @Test fun `sandbox command bindings and a nonempty command remain required after receipt rebinding`() {
        val f = fixture()
        corrupt(output(f, 1, mapOf("command" to JsonArray(listOf(JsonPrimitive("PRIVATE-forged-command"))))))
        corrupt(sandbox(f, fields(f).map { if (it.first == "launch[0].command") it.first to "0".repeat(64) else it }))
        val empty = output(f, 1, mapOf("command" to JsonArray(emptyList())))
        corrupt(sandbox(empty, fields(empty).map { if (it.first == "launch[0].command")
            it.first to acpSandboxCanonicalStringDigest(emptyList()) else it }))
    }
    @Test fun `case executable manifests must match both contained runtime bindings`() {
        val f = fixture()
        for (index in listOf(1, 2)) for (field in listOf("launch[0].executable.manifest", "launch[0].executable.configuredManifest"))
            corrupt(sandbox(f, fields(f, index).map { if (it.first == field) field to "9".repeat(64) else it }, index))
        for (name in listOf("originalExecutable", "rebuiltExecutable")) {
            val executable = f.root.getValue(name).jsonObject
            for (changed in listOf(executable - "runtimeManifestSha256",
                    executable + ("runtimeManifestSha256" to JsonPrimitive("PRIVATE-not-a-digest")),
                    executable + ("runtimeManifestSha256" to JsonPrimitive("9".repeat(64)))))
                corrupt(rebind(f, JsonObject(f.root + (name to JsonObject(changed)))))
        }
    }
    @Test fun `sandbox writable quota fields must match the scope quota after digest rebinding`() {
        val f = fixture()
        for ((field, changed) in mapOf("provider" to "other", "mount" to "2", "bytes" to "4097", "entries" to "21", "path" to "9".repeat(64)))
            corrupt(sandbox(f, fields(f).map { if (it.first == "authority[0].quota.$field") it.first to changed else it }))
    }
    @Test fun `complete contained launch and exactly one writable authority are required for case evidence`() {
        val f = fixture(); val values = fields(f)
        for ((field, changed) in mapOf("provider" to "other", "launch[0].purpose" to "other", "network" to "false",
                "launch[0].gate.positiveByte" to "false", "launch[0].mergeError" to "true",
                "launch[0].writableMountClosure" to "PRIVATE-not-a-digest", "authority[0].mode" to "READ_ONLY"))
            corrupt(sandbox(f, values.map { if (it.first == field) field to changed else it }))
        corrupt(sandbox(f, values.filterNot { it.first == "cgroup.memory" }))
        corrupt(sandbox(f, values + ("launch[1].purpose" to "CANDIDATE_VALIDATION")))
        corrupt(sandbox(f, values + ("authority[1].mode" to "READ_WRITE")))
    }

    @Test fun `ordered receipt scopes derive exact exit stdout and stderr comparisons`() {
        val result = page(fixture(mismatch = true))
        assertEquals(RecordedRepairValidationCaseState.AVAILABLE, result.state)
        assertEquals(1, result.matchedCount)
        assertEquals(listOf(RecordedRepairValidationCaseOutcome.MISMATCH, RecordedRepairValidationCaseOutcome.MATCHED), result.cases.map { it.outcome })
        assertEquals(listOf(1, 2), result.cases.map { it.ordinal })
        assertEquals(false, result.cases.first().stdoutMatches)
        assertEquals(true, result.cases.first().stderrMatches)
        assertEquals(2L, result.cases.first().originalStdoutBytes)
    }
    @Test fun `matching ordinary nonzero exits remain matching byte comparisons`() {
        val result = page(fixture(exit = 7))
        assertEquals(2, result.matchedCount)
        assertTrue(result.cases.all { it.outcome == RecordedRepairValidationCaseOutcome.MATCHED && it.exitCodeMatches == true })
    }
    @Test fun `exit and stderr differences cannot be concealed by equal stdout`() {
        val f = fixture()
        for (fields in listOf(mapOf("exitCode" to JsonPrimitive(3)), mapOf("stderrBase64" to encoded(byteArrayOf(0))))) {
            val changed = output(f, 2, fields)
            val bound = rebind(changed, JsonObject(changed.root + ("matches" to JsonPrimitive(false))))
            assertEquals(RecordedRepairValidationCaseOutcome.MISMATCH, page(bound).cases.first().outcome)
            assertEquals(true, page(bound).cases.first().stdoutMatches)
        }
    }
    @Test fun `global receipt matches must equal all recomputed case comparisons`() {
        val f = fixture(mismatch = true)
        corrupt(rebind(f, JsonObject(f.root + ("matches" to JsonPrimitive(true)))))
        val matched = fixture()
        corrupt(rebind(matched, JsonObject(matched.root + ("matches" to JsonPrimitive(false)))))
    }
    @Test fun `missing duplicate reordered and foreign role scopes produce no case outcomes`() {
        val f = fixture(); val rows = f.root.getValue("scopes").jsonArray
        val bad = listOf(rows.dropLast(1), rows + rows.last(), listOf(rows[0], rows[2], rows[1], rows[3], rows[4]),
            rows.toMutableList().also { it[2] = rows[1] }, rows.toMutableList().also {
                it[1] = JsonObject(rows[1].jsonObject + ("inputId" to JsonPrimitive("PRIVATE-foreign"))) })
        bad.forEach { corrupt(scopes(f, it)) }
    }
    @Test fun `a normal comparison cannot accept a failed or misidentified build scope`() {
        val f = fixture(); corrupt(output(f, 0, mapOf("exitCode" to JsonPrimitive(1))))
        val rows = f.root.getValue("scopes").jsonArray.toMutableList()
        rows[0] = JsonObject(rows[0].jsonObject + ("inputId" to JsonPrimitive("PRIVATE-case-0000")))
        corrupt(scopes(f, rows))
    }
    @Test fun `compile failure and compile only validation never invent completed case pairs`() {
        for (kind in listOf(RepairValidationObservedOutcome.COMPILE_FAILED, RepairValidationObservedOutcome.COMPILE_VALID)) {
            val result = page(fixture(outcome = kind))
            assertEquals(RecordedRepairValidationCaseState.AVAILABLE, result.state)
            assertNull(result.matchedCount)
            assertEquals(2, result.cases.size)
            assertTrue(result.cases.all { it.exitCodeMatches == null && it.stdoutMatches == null && it.originalStdoutBytes == null })
            assertEquals(if (kind == RepairValidationObservedOutcome.COMPILE_FAILED) RecordedRepairValidationCaseOutcome.COMPILE_FAILED
                else RecordedRepairValidationCaseOutcome.COMPILE_ONLY, result.cases.first().outcome)
        }
    }
    @Test fun `missing scope evidence stays unavailable without changing the recorded operation label`() {
        val f = scopes(fixture(), emptyList()); assertEquals(RepairEvidenceArtifactState.AVAILABLE, checked(f).primaryState)
        assertEquals(RecordedRepairValidationCaseState.UNAVAILABLE, page(f).state)
        assertTrue(page(f).cases.isEmpty())
    }
    @Test fun `ambiguous exits bad output types and isolation flags withhold case outcomes`() {
        val f = fixture()
        for (fields in listOf(mapOf("exitCode" to JsonPrimitive(128)), mapOf("exitCode" to JsonPrimitive("0")),
                mapOf("networkIsolated" to JsonPrimitive(false)), mapOf("stdoutBase64" to JsonPrimitive(2)),
                mapOf("extra" to JsonPrimitive("PRIVATE")))) corrupt(output(f, 1, fields))
    }
    @Test fun `scope cleanup and finite quota metadata are required before exposing a comparison`() {
        val f = fixture(); val rows = f.root.getValue("scopes").jsonArray
        val first = rows[1].jsonObject
        val quota = first.getValue("writableQuota").jsonObject
        val edits = listOf(first + ("cleanupVerified" to JsonPrimitive(false)), first - "sandboxFields",
            first + ("extra" to JsonPrimitive("PRIVATE")),
            first + ("writableQuota" to JsonObject(quota + ("maximumBytes" to JsonPrimitive(0)))),
            first + ("writableQuota" to JsonObject(quota + ("mountId" to JsonPrimitive("1")))))
        for (edit in edits) corrupt(scopes(f, rows.toMutableList().also { it[1] = JsonObject(edit) }))
    }
    @Test fun `noncanonical and malformed base64 cannot compare equal after rebinding receipt bytes`() {
        val f = fixture()
        for (bad in listOf("A", "AA", "AA=A", "AB==", "AAB=", "AA-_", "AA\n=", "====", "AA==AAAA"))
            corrupt(output(f, 1, mapOf("stdoutBase64" to JsonPrimitive(bad))))
    }
    @Test fun `canonical binary output length and equality cover empty and padding boundaries`() {
        for (size in listOf(0, 1, 2, 3, 4, 8193)) {
            val bytes = ByteArray(size) { (it * 31).toByte() }; val f = fixture()
            val original = output(f, 1, mapOf("stdoutBase64" to encoded(bytes)))
            val both = output(original, 2, mapOf("stdoutBase64" to encoded(bytes)))
            assertEquals(size.toLong(), page(both).cases.first().originalStdoutBytes)
            assertEquals(true, page(both).cases.first().stdoutMatches)
        }
    }
    @Test fun `case windows preserve ordinals and expose only twenty immutable rows`() {
        val f = fixture(count = 41)
        val pages = (1..3).map { page(f, it) }
        assertEquals(listOf(20, 20, 1), pages.map { it.cases.size })
        assertEquals((1..41).toList(), pages.flatMap { it.cases.map { c -> c.ordinal } })
        assertEquals(41, pages.last().matchedCount)
        assertFailsWith<UnsupportedOperationException> { (pages.first().cases as MutableList<RecordedRepairValidationCase>).clear() }
        assertEquals(RecordedRepairValidationCaseState.OUT_OF_RANGE, page(f, Int.MAX_VALUE).state)
        assertTrue(page(f, Int.MAX_VALUE).cases.isEmpty())
        assertFailsWith<IllegalArgumentException> { checked(f, 0) }
    }
    @Test fun `case identities are corpus bound stable across pages and private text is not projected`() {
        val f = fixture(count = 21); val identities = RepairHistoryIdentityReferences(f.binding.proof.regressionCorpusSha256)
        assertEquals(identities.case("PRIVATE-case-0020"), page(f, 2).cases.single().identity)
        val nextBytes = rebind(f, JsonObject(f.root + ("sourceRevisionSha256" to JsonPrimitive("9".repeat(64)))))
        val candidate = RepairRecordedIdentity("revision_00000001_" + "c".repeat(16), false)
        val nextInvocation = RepairValidationInvocation("validation_" + "c".repeat(32), "run_00000002", candidate.value,
            "9".repeat(64), f.binding.proof.profileSha256, f.binding.proof.indexSha256, f.binding.proof.regressionCorpusSha256)
        val next = nextBytes.copy(binding = nextBytes.binding.copy(candidate = candidate,
            invocationSha256 = nextInvocation.commitmentSha256(),
            primary = nextBytes.binding.primary.copy(artifact = recordedRepairArtifactReference(
                f.binding.proof.regressionCorpusSha256, repairValidationReceiptPath(nextInvocation.id, nextBytes.binding.primary.sha256))),
            proof = nextBytes.binding.proof.copy(sourceRevisionSha256 = "9".repeat(64))))
        assertEquals(page(f).cases.first().identity, page(next).cases.first().identity)
        assertNotEquals(page(fixture(count = 2)).cases.first().identity, page(f).cases.first().identity)
        val text = page(f).cases.toString(); assertFalse("PRIVATE" in text); assertFalse("AA==" in text)
    }
    @Test fun `changed receipt bindings withhold the entire comparison projection`() {
        val f = fixture(); val bad = f.copy(binding = f.binding.copy(primary = f.binding.primary.copy(sha256 = "0".repeat(64))))
        assertEquals(RepairEvidenceArtifactState.CORRUPT, checked(bad).primaryState); assertNull(checked(bad).casePage)
    }

    private fun stdoutPair(original: ByteArray, rebuilt: ByteArray = original): Fixture {
        val first = output(fixture(), 1, mapOf("stdoutBase64" to encoded(original)))
        val second = output(first, 2, mapOf("stdoutBase64" to encoded(rebuilt)))
        return rebind(second, JsonObject(second.root + ("matches" to JsonPrimitive(original.contentEquals(rebuilt)))))
    }

    @Test fun `UTF8 previews escape controls while hexadecimal retains every original byte`() {
        val bytes = ("line\r\n\t\\" + 0.toChar() + 0x202e.toChar()).toByteArray(Charsets.UTF_8)
        val preview = requireNotNull(page(stdoutPair(bytes)).cases.first().originalStdoutPreview)
        assertEquals(bytes.size.toLong(), preview.totalBytes)
        assertEquals(bytes.size, preview.prefixBytes)
        assertEquals(bytes.size, preview.textBytes)
        assertEquals("line\\r\\n\n\\t\\\\\\u0000\\u202e", preview.text)
        assertEquals("6c 69 6e 65 0d 0a 09 5c 00 e2 80 ae", preview.hex)
        assertFalse(preview.truncated)
        for ((point, escaped) in listOf(0x2028 to "\\u2028", 0x2029 to "\\u2029", 0xe0001 to "\\U000e0001")) {
            val value = String(Character.toChars(point)).toByteArray(Charsets.UTF_8)
            assertEquals(escaped, page(stdoutPair(value)).cases.first().originalStdoutPreview?.text)
        }
    }
    @Test fun `invalid UTF8 stays hexadecimal without replacement characters or invented text`() {
        val preview = requireNotNull(page(stdoutPair(byteArrayOf(0, -1, -61, 40))).cases.first().originalStdoutPreview)
        assertNull(preview.text); assertNull(preview.textBytes)
        assertEquals("00 ff c3 28", preview.hex)
        assertEquals(4, preview.prefixBytes); assertFalse(preview.truncated)
    }
    @Test fun `a truncated multibyte character remains exact hex and is never replaced or falsely decoded`() {
        val bytes = ByteArray(127) { 65 } + "€Z".toByteArray(Charsets.UTF_8)
        val preview = requireNotNull(page(stdoutPair(bytes)).cases.first().originalStdoutPreview)
        assertEquals(131L, preview.totalBytes); assertEquals(128, preview.prefixBytes); assertTrue(preview.truncated)
        assertEquals(127, preview.textBytes); assertEquals("A".repeat(127), preview.text)
        assertTrue(preview.hex.endsWith("e2")); assertFalse(preview.hex.contains("82 ac"))
    }
    @Test fun `identical bounded prefixes cannot hide a mismatch after the preview boundary`() {
        val original = ByteArray(1024) { 65 }; val rebuilt = original.copyOf().also { it[it.lastIndex] = 66 }
        val f = stdoutPair(original, rebuilt); val value = page(f).cases.first()
        assertEquals(false, value.stdoutMatches); assertEquals(RecordedRepairValidationCaseOutcome.MISMATCH, value.outcome)
        val first = requireNotNull(value.originalStdoutPreview); val second = requireNotNull(value.rebuiltStdoutPreview)
        assertEquals(first.hex, second.hex); assertEquals(first.text, second.text)
        assertEquals(128, first.prefixBytes); assertTrue(first.truncated); assertTrue(second.truncated)
        val rendered = html(f)
        assertTrue("Showing first 128 of 1024 bytes; preview truncated." in rendered)
        assertTrue("Previews do not change the full-byte comparison." in rendered)
        assertTrue("Different" in rendered)
    }
    @Test fun `empty observed streams and unobserved compile cases have distinct preview states`() {
        val empty = stdoutPair(byteArrayOf()); val value = requireNotNull(page(empty).cases.first().originalStdoutPreview)
        assertEquals(0L, value.totalBytes); assertEquals(0, value.prefixBytes)
        assertEquals("", value.text); assertEquals("", value.hex); assertFalse(value.truncated)
        assertTrue("Original: empty output (0 bytes)." in html(empty))
        for (kind in listOf(RepairValidationObservedOutcome.COMPILE_FAILED, RepairValidationObservedOutcome.COMPILE_VALID)) {
            val row = page(fixture(outcome = kind)).cases.first()
            assertNull(row.originalStdoutPreview); assertNull(row.rebuiltStdoutPreview)
            assertNull(row.originalStderrPreview); assertNull(row.rebuiltStderrPreview)
        }
    }
    @Test fun `corrupt later scope evidence withholds every output preview from the page`() {
        val f = stdoutPair("PUBLIC-output-canary".toByteArray())
        val rows = f.root.getValue("scopes").jsonArray.toMutableList()
        rows[4] = JsonObject(rows[4].jsonObject + ("inputId" to JsonPrimitive("PRIVATE-foreign")))
        val changed = scopes(f, rows)
        assertEquals(RecordedRepairValidationCaseState.CORRUPT, page(changed).state)
        assertTrue(page(changed).cases.isEmpty())
        assertFalse("PUBLIC-output-canary" in html(changed))
    }
    @Test fun `only the selected twenty cases retain at most 128 bytes for each of four streams`() {
        val f = fixture(count = 41)
        val payload = encoded(ByteArray(2048) { 65 })
        val rows = f.root.getValue("scopes").jsonArray.map { row ->
            val scope = row.jsonObject
            JsonObject(scope + ("output" to JsonObject(scope.getValue("output").jsonObject +
                mapOf("stdoutBase64" to payload, "stderrBase64" to payload))))
        }
        val bound = scopes(f, rows)
        fun retainedBytes(number: Int) = page(bound, number).cases.sumOf { row ->
            listOfNotNull(row.originalStdoutPreview, row.rebuiltStdoutPreview,
                row.originalStderrPreview, row.rebuiltStderrPreview).sumOf { it.prefixBytes }
        }
        assertEquals(20, page(bound).cases.size); assertEquals(10_240, retainedBytes(1))
        assertEquals(10_240, retainedBytes(2)); assertEquals(512, retainedBytes(3))
    }
    @Test fun `selected HTML escapes output previews and labels byte normalization and truncation`() {
        val f = stdoutPair("<img src=x onerror=PUBLIC()>\r\n".toByteArray())
        val rendered = html(f)
        assertTrue("&lt;img src=x onerror=PUBLIC()&gt;" in rendered)
        assertFalse("<img src=x" in rendered)
        assertTrue("Escaped UTF-8 prefix" in rendered); assertTrue("Exact byte prefix (hexadecimal)." in rendered)
        assertTrue("preview complete." in rendered)
        assertTrue("Comparison uses every retained byte without normalization." in rendered)
        assertFalse("PRIVATE" in rendered); assertFalse("<form" in rendered)
    }
    @Test fun `case page query requires canonical spelling graph identity and an explicit owner`() {
        val suffix = "historyGraph=$graph&historyRunEvidence=run_00000001&historyValidationPage=2"
        assertEquals(2, parseRecordedRepairHistoryQuery(suffix).validationCasePageNumber)
        for (raw in listOf("historyValidationPage=2", "historyGraph=$graph&historyValidationPage=2",
                "historyRunEvidence=run_00000001&historyValidationPage=2", suffix + "&historyValidationPage=3",
                suffix.replace("=2", "=02"), suffix.replace("=2", "=0"), suffix.replace("=2", "=2147483648")))
            assertFailsWith<IllegalArgumentException> { parseRecordedRepairHistoryQuery(raw) }
        assertEquals(1, parseRecordedRepairHistoryQuery(null).validationCasePageNumber)
    }

    private fun html(f: Fixture, number: Int = 1): String {
        val corpus = f.binding.proof.regressionCorpusSha256
        val run = RepairRecordedRun(4, RepairRecordedIdentity("run_00000001", false), RepairRunStatus.RUNNING,
            f.binding.candidate, null, null, corpus, 2, 0, 1, 100, null, null, baselineValidationObservation = f.binding)
        val snapshot = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, corpus, f.binding.candidate,
            null, null, listOf(run), emptyList(), null, emptyList())
        val selected = RepairRecordedHistoryPage.select(snapshot,
            RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = run.identity.value), 20)
        val target = "reports/runs/run_selected/source-tree/" + repairValidationReceiptPath(nonce, f.binding.primary.sha256)
        val job = Job("a".repeat(32), "authored.elf", "complete", "2026-01-01T00:00:00Z", sizeBytes = 0,
            binaryPath = Path.of("authored.elf"), metadata = ElfMetadata("ELF64", "little-endian", 1u, "System V",
                "EXEC", "x86-64", 0uL, 64.toUShort(), 0.toUShort(), 0.toUShort(), 0.toUShort()))
        return renderRecordedRepairHistory(job, RecordedRepairHistoryView(RepairHistoryReadResult.recorded(snapshot),
            targets = mapOf(f.binding.primary.artifact to target), page = selected, runId = "run_selected",
            validationObservations = mapOf(run.identity to checked(f, number)), validationCasePageNumber = number))
    }
    @Test fun `accessible comparison table uses opaque case IDs exact flags and finite byte counts`() {
        val rendered = html(fixture(mismatch = true))
        assertTrue("<caption>Recorded exact-byte comparisons</caption>" in rendered)
        assertTrue("class=\"table-wrap\" role=\"region\"" in rendered)
        assertTrue("aria-label=\"Recorded validation case comparisons\" tabindex=\"0\"" in rendered)
        assertTrue("<th scope=\"row\">" in rendered); assertTrue("<th scope=\"col\">" in rendered)
        assertTrue("Original: 2 B; rebuilt: 2 B" in rendered)
        assertTrue("1 matched; 1 mismatched" in rendered); assertTrue("Mismatch" in rendered)
        assertFalse("PRIVATE" in rendered); assertFalse("<form" in rendered)
    }
    @Test fun `case page links retain the selected graph run owner and report context`() {
        val rendered = html(fixture(count = 41), 2)
        assertTrue("Validation case page 2 of 3" in rendered)
        assertTrue("historyGraph=$graph" in rendered); assertTrue("historyRunEvidence=run_00000001" in rendered)
        assertTrue("historyValidationPage=3" in rendered); assertTrue("runId=run_selected" in rendered)
        assertTrue("Previous validation cases" in rendered); assertTrue("More validation cases" in rendered)
        assertEquals(20, Regex("<th scope=\"row\">").findAll(rendered).count())
    }
    @Test fun `corrupt scope evidence has no invented match outcome in HTML`() {
        val f = fixture(); val rendered = html(output(f, 1, mapOf("exitCode" to JsonPrimitive(255))))
        assertTrue("Case comparison evidence is corrupt or inconsistent" in rendered)
        assertFalse("Recorded exact-byte comparisons</caption>" in rendered); assertFalse("PRIVATE" in rendered)
    }
    @Test fun `out of range case pages provide a graph bound return to the first page`() {
        val rendered = html(fixture(), Int.MAX_VALUE)
        assertTrue("Recorded validation case page is out of range" in rendered)
        assertTrue("Show first validation case page" in rendered)
        assertTrue("historyGraph=$graph" in rendered); assertTrue("historyRunEvidence=run_00000001" in rendered)
        assertFalse("historyValidationPage=" in rendered); assertFalse("PRIVATE" in rendered)
    }
}
