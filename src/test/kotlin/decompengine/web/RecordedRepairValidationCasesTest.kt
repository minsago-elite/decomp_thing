package decompengine.web

import decompengine.acp.acpSandboxCanonicalStringDigest
import decompengine.binary.ElfMetadata
import decompengine.jobs.Job
import decompengine.oracle.core.OracleJson
import decompengine.project.sha256
import decompengine.project.requireRecordedRepairValidationSandbox
import decompengine.project.requireRecordedRepairValidationOutputQuota
import decompengine.repair.*
import decompengine.validation.ProcessInput
import java.nio.file.Path
import java.util.Base64
import kotlinx.serialization.json.*
import kotlin.test.*

/** In-memory retained metadata for authored reader controls; never touches a source tree or runtime. */
internal object AuthoredValidationReceiptMetadata {
    const val profileId = "generated-c-make-v1"
    val context = RepairRecordedValidationContext(profileId, RepairResourceBudget())
    private fun digest(text: String) = sha256(text.toByteArray(Charsets.UTF_8))
    private fun quota(id: Int, path: String) = buildJsonObject {
        put("provider", "dedicated-tmpfs-size+nr_inodes"); put("mountId", id); put("maximumBytes", 4096)
        put("maximumEntries", 20); put("mountPathSha256", digest(path))
    }
    val files = JsonArray(listOf("Makefile", "src/main.c").map { path -> buildJsonObject {
        put("path", path); put("role", if (path == "Makefile") "build-file" else "source")
        put("mode", 292); put("bytes", 1); put("sha256", digest(path))
    } })
    val snapshot = buildJsonObject {
        put("manifestSha256", sha256(OracleJson.canonicalBytes(files))); put("files", files)
        put("quota", quota(2, "/PRIVATE-source"))
    }
    val sourceSha256 = digest(files.joinToString("") { element ->
        val file = element.jsonObject; val path = file.getValue("path").jsonPrimitive.content
        "${path.length}:$path:1:${file.getValue("sha256").jsonPrimitive.content}\n"
    })
    val runtime = buildJsonObject {
        put("sandboxConfigurationSha256", "9".repeat(64))
        put("runtime", buildJsonObject {
            put("schemaVersion", 1); put("profileId", profileId); put("sandboxConfigurationFile", "/PRIVATE-runtime/config")
            put("sourceTmpfs", "/PRIVATE-source"); put("outputTmpfs", "/PRIVATE-output")
            put("tools", buildJsonObject {
                for ((role, name) in decompengine.project.GeneratedCRepairRuntimeConfiguration.TOOL_NAMES) put(role, buildJsonObject {
                    put("source", "/PRIVATE-runtime/$name"); put("destination", "/decomp-generated-c-tools/$name"); put("sha256", digest(name))
                })
            })
            put("buildRuntimeMounts", JsonArray(emptyList())); put("programRuntimeMounts", JsonArray(emptyList()))
        })
    }
    val runtimeSha256 = sha256(OracleJson.canonicalBytes(runtime))
}

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
    private fun outputQuota() = buildJsonObject {
        put("provider", "dedicated-tmpfs-size+nr_inodes"); put("mountId", 1); put("maximumBytes", 4096)
        put("maximumEntries", 20); put("mountPathSha256", sha256("/PRIVATE-output".toByteArray(Charsets.UTF_8)))
    }
    private fun scope(role: String, id: String?, exit: Int = 0, stdout: ByteArray = byteArrayOf(0, -1),
        stderr: ByteArray = byteArrayOf(10)): JsonObject = buildJsonObject {
        put("role", role); put("inputId", id?.let(::JsonPrimitive) ?: JsonNull)
        val command = listOf("PRIVATE-command")
        put("output", buildJsonObject {
            put("command", JsonArray(command.map(::JsonPrimitive)))
            put("exitCode", exit); put("stdoutBase64", encoded(stdout)); put("stderrBase64", encoded(stderr)); put("networkIsolated", true)
        })
        val quota = outputQuota()
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
            put("schemaVersion", 2); put("provider", "generated-c-linux-bubblewrap-cgroup-v1"); put("profileId", AuthoredValidationReceiptMetadata.profileId)
            for ((name, digit) in listOf("profileSha256" to '3', "indexSha256" to '4'))
                put(name, digit.toString().repeat(64))
            put("sourceRevisionSha256", AuthoredValidationReceiptMetadata.sourceSha256)
            put("runtimeSha256", AuthoredValidationReceiptMetadata.runtimeSha256)
            put("regressionCorpusSha256", corpus); put("runtimeConfiguration", AuthoredValidationReceiptMetadata.runtime)
            put("behaviorBudgetEvidence", JsonObject(emptyMap())); put("sourceSnapshot", AuthoredValidationReceiptMetadata.snapshot)
            put("buildOutputLink", buildJsonObject {
                put("path", "build"); put("role", "application-owned-output-link"); put("target", "/PRIVATE-output/program")
                put("quota", outputQuota())
            })
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
        val proof = RepairValidationProof(AuthoredValidationReceiptMetadata.sourceSha256, "3".repeat(64), "4".repeat(64), corpus,
            original, rebuilt, AuthoredValidationReceiptMetadata.runtimeSha256, sha256(bytes), true, RepairValidationAssurance.STRICT_CONTAINED)
        val identity = RepairRecordedIdentity("root_" + "1".repeat(24), false)
        val invocation = RepairValidationInvocation(nonce, "run_00000001", identity.value,
            proof.sourceRevisionSha256, proof.profileSha256, proof.indexSha256, corpus)
        return rebind(Fixture(RepairRecordedValidationObservation(invocation.commitmentSha256(), identity, proof, outcome,
            RepairRecordedValidationObservedArtifact(recordedRepairArtifactReference(corpus, repairValidationReceiptPath(nonce, sha256(bytes))),
                sha256(bytes), bytes.size.toLong()), null, context = AuthoredValidationReceiptMetadata.context), root, bytes), root)
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
        val expected = runCatching { sha256(buildString {
            append(f.binding.proof.originalBinarySha256).append('\n')
            root.getValue("inputs").jsonArray.forEachIndexed { index, input ->
                val id = input.jsonObject.getValue("id").jsonPrimitive.content
                val observed = root.getValue("scopes").jsonArray[1 + 2 * index].jsonObject.getValue("output").jsonObject
                fun hash(field: String) = sha256(Base64.getDecoder().decode(observed.getValue(field).jsonPrimitive.content))
                append(id.length).append(':').append(id).append(':').append(observed.getValue("exitCode").jsonPrimitive.content)
                    .append(':').append(hash("stdoutBase64")).append(':').append(hash("stderrBase64")).append('\n')
            }
        }.toByteArray(Charsets.UTF_8)) }.getOrNull() ?: f.binding.expectedObservationsSha256
        return f.copy(root = root, bytes = bytes, diffBytes = diffBytes,
            binding = f.binding.copy(expectedObservationsSha256 = expected, proof = f.binding.proof.copy(evidenceSha256 = sha256(bytes)),
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

    @Test fun `authority names require the literal separator before mode and quota bindings`() {
        val f = fixture()
        for (separator in listOf("X", "/", "_", "-", "", ":", "\n")) {
            val values = fields(f).map { (name, value) ->
                (if (name.startsWith("authority[0].")) "authority[0]$separator" + name.removePrefix("authority[0].") else name) to value
            }
            val changed = sandbox(f, values)
            corrupt(changed)
            assertFailsWith<IllegalArgumentException> { requireRecordedRepairValidationSandbox(
                changed.root.getValue("scopes").jsonArray[1].jsonObject, "1".repeat(64)) }
        }
    }
    @Test fun `lookalike writable fields cannot substitute for an actual read only authority`() {
        val f = fixture(); val original = fields(f)
        val readonly = original.map { if (it.first == "authority[0].mode") it.first to "READ_ONLY" else it }
        val lookalikes = original.filter { it.first.startsWith("authority[0].") }.map { (name, value) ->
            "authority[1]X" + name.removePrefix("authority[0].") to value
        }
        val changed = sandbox(f, readonly + lookalikes)
        corrupt(changed)
        assertFailsWith<IllegalArgumentException> { requireRecordedRepairValidationSandbox(
            changed.root.getValue("scopes").jsonArray[1].jsonObject, "1".repeat(64)) }
    }
    @Test fun `exact writable authority names retain valid command executable quota and comparison bindings`() {
        val f = fixture()
        for (index in listOf(0, 1, 19)) {
            val values = fields(f).map { (name, value) ->
                (if (name.startsWith("authority[0].")) "authority[$index]." + name.removePrefix("authority[0].") else name) to value
            }
            val changed = sandbox(f, values)
            requireRecordedRepairValidationSandbox(changed.root.getValue("scopes").jsonArray[1].jsonObject, "1".repeat(64))
            assertEquals(RecordedRepairValidationCaseState.AVAILABLE, page(changed).state)
            assertTrue(page(changed).cases.all { it.outcome == RecordedRepairValidationCaseOutcome.MATCHED })
        }
    }

    private fun withScopeQuota(f: Fixture, index: Int, quota: JsonObject): Fixture {
        val mapping = mapOf("provider" to "provider", "mount" to "mountId", "bytes" to "maximumBytes",
            "entries" to "maximumEntries", "path" to "mountPathSha256")
        val values = fields(f, index).map { (name, value) ->
            val key = if (name.startsWith("authority[0].quota.")) mapping[name.removePrefix("authority[0].quota.")] else null
            name to (key?.let { quota.getValue(it).jsonPrimitive.content } ?: value)
        }
        val rows = f.root.getValue("scopes").jsonArray.toMutableList()
        rows[index] = JsonObject(rows[index].jsonObject + mapOf("writableQuota" to quota,
            "sandboxFields" to sandboxFields(values), "sandboxSha256" to JsonPrimitive(sandboxDigest(values))))
        return scopes(f, rows)
    }
    @Test fun `recorded comparisons require a typed application owned build output quota link`() {
        val f = fixture(); val link = f.root.getValue("buildOutputLink").jsonObject
        val values = listOf(JsonNull, JsonArray(emptyList()), JsonObject(emptyMap()),
            JsonObject(link + ("path" to JsonPrimitive("PRIVATE-other"))),
            JsonObject(link + ("role" to JsonPrimitive("unrelated-output"))),
            JsonObject(link + ("target" to JsonPrimitive("PRIVATE-relative/program"))),
            JsonObject(link + ("target" to JsonPrimitive("/PRIVATE-output/../PRIVATE-other/program"))),
            JsonObject(link + ("target" to JsonPrimitive("/PRIVATE-other/program"))),
            JsonObject(link + ("quota" to JsonNull)), JsonObject(link + ("extra" to JsonPrimitive("PRIVATE"))))
        values.forEach { value ->
            corrupt(rebind(f, JsonObject(f.root + ("buildOutputLink" to value))))
            assertFails { requireRecordedRepairValidationOutputQuota(value) }
        }
    }
    @Test fun `self consistent scope quotas must equal the application owned output quota across every role`() {
        val f = fixture(); val quota = outputQuota()
        val variants = listOf(quota + ("mountId" to JsonPrimitive(2)), quota + ("maximumBytes" to JsonPrimitive(8192)),
            quota + ("maximumEntries" to JsonPrimitive(40)), quota + ("mountPathSha256" to JsonPrimitive("9".repeat(64))))
        for (index in 0 until f.root.getValue("scopes").jsonArray.size) for (variant in variants) {
            val changed = withScopeQuota(f, index, JsonObject(variant))
            val scope = changed.root.getValue("scopes").jsonArray[index].jsonObject
            requireRecordedRepairValidationSandbox(scope, executableManifest(scope.getValue("role").jsonPrimitive.content))
            corrupt(changed)
        }
    }
    @Test fun `a rebound output link cannot borrow independently consistent scopes from another staging area`() {
        val f = fixture(); val link = f.root.getValue("buildOutputLink").jsonObject
        val quota = JsonObject(outputQuota() + ("mountPathSha256" to JsonPrimitive(sha256("/PRIVATE-other".toByteArray(Charsets.UTF_8)))))
        val changedLink = JsonObject(link + mapOf("target" to JsonPrimitive("/PRIVATE-other/program"), "quota" to quota))
        assertEquals(quota, requireRecordedRepairValidationOutputQuota(changedLink))
        corrupt(rebind(f, JsonObject(f.root + ("buildOutputLink" to changedLink))))
    }
    @Test fun `coherent output link and every scope quota preserve existing normal case comparisons`() {
        val f = fixture(); val quota = JsonObject(outputQuota() + mapOf("mountId" to JsonPrimitive(2),
            "maximumBytes" to JsonPrimitive(8192), "maximumEntries" to JsonPrimitive(40),
            "mountPathSha256" to JsonPrimitive(sha256("/PRIVATE-other".toByteArray(Charsets.UTF_8)))))
        var changed = f
        for (index in 0 until f.root.getValue("scopes").jsonArray.size) changed = withScopeQuota(changed, index, quota)
        for (index in 0 until f.root.getValue("scopes").jsonArray.size) {
            assertEquals("bubblewrap+systemd-cgroup-v2", fields(changed, index).toMap().getValue("provider"))
            requireRecordedRepairValidationSandbox(changed.root.getValue("scopes").jsonArray[index].jsonObject,
                executableManifest(changed.root.getValue("scopes").jsonArray[index].jsonObject.getValue("role").jsonPrimitive.content))
        }
        val link = f.root.getValue("buildOutputLink").jsonObject
        changed = rebind(changed, JsonObject(changed.root + ("buildOutputLink" to JsonObject(link +
            mapOf("target" to JsonPrimitive("/PRIVATE-other/program"), "quota" to quota)))))
        assertEquals(RecordedRepairValidationCaseState.AVAILABLE, page(changed).state)
        assertTrue(page(changed).cases.all { it.outcome == RecordedRepairValidationCaseOutcome.MATCHED })
        assertFalse("PRIVATE" in page(changed).cases.toString())
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

    private val apiJob = "a".repeat(32)
    private val apiRun = "run_selected"
    private val apiQuery get() = "historyGraph=$graph&historyRunEvidence=run_00000001"
    private fun apiSnapshot(f: Fixture, digest: String = graph, owner: String = "run_00000001", normal: Boolean = true): RepairHistorySnapshot {
        val corpus = f.binding.proof.regressionCorpusSha256
        val run = RepairRecordedRun(4, RepairRecordedIdentity(owner, false), RepairRunStatus.RUNNING,
            f.binding.candidate, null, null, corpus, 2, 0, 1, 100, null, null,
            baselineValidationObservation = f.binding.takeIf { normal })
        return RepairHistorySnapshot(digest, 4, RepairRecordedGraphWire.COMPACT, corpus,
            f.binding.candidate, null, null, listOf(run), emptyList(), null, emptyList())
    }
    private fun apiCapture(f: Fixture, primary: ByteArray? = f.bytes, diff: ByteArray? = f.diffBytes,
        snapshot: RepairHistorySnapshot = apiSnapshot(f), query: String = apiQuery): WebRevisionValidationCapture =
        WebRevisionValidationCapture(RepairRecordedHistoryPage.select(snapshot, WebRevisionValidationQuery.parse(query).selection, 20), primary, diff)
    private fun apiReport(f: Fixture, primary: ByteArray? = f.bytes, diff: ByteArray? = f.diffBytes, casePage: Int = 1): JsonObject =
        WebRevisionValidationReports { _, _, _ -> apiCapture(f, primary, diff) }.read(apiJob, apiRun,
            apiQuery + if (casePage == 1) "" else "&historyValidationPage=$casePage")
    private fun apiArtifacts(f: Fixture): List<WebArtifactSummary> = listOf(
        WebArtifactSummary("reports/runs/$apiRun/source-tree/" + repairValidationReceiptPath(nonce, f.binding.primary.sha256),
            "PRIVATE-receipt-name", f.binding.primary.bytes)) + listOfNotNull(f.binding.diff?.let {
        WebArtifactSummary("reports/runs/$apiRun/source-tree/" + repairValidationDiffPath(it.sha256), "PRIVATE-diff-name", it.bytes)
    })
    private val apiContext get() = WebReportContext(Path.of("authored"), "reports/runs/$apiRun", apiRun)

    @Test fun `versioned validation selection requires one explicit graph and owner before capture`() {
        val invalid = listOf(null, "", "historyGraph=$graph", "historyRunEvidence=run_00000001", apiQuery + "&historyEvidence=revision_other",
            apiQuery + "&historyGraph=$graph", apiQuery + "&runId=run_other", apiQuery + "&historyCasesPage=1",
            apiQuery + "&historyValidationPage=02", apiQuery + "&historyPage=01", apiQuery + "&historyPage=2147483648",
            apiQuery.replace(graph, "9".repeat(63)), apiQuery.replace("run_00000001", "..%2FPRIVATE"))
        invalid.forEach { assertEquals(400, assertFailsWith<WebAccessDenied> { WebRevisionValidationQuery.parse(it) }.status) }
        assertEquals("run_00000001", WebRevisionValidationQuery.parse(apiQuery).selection.evidenceRun)
        assertEquals(2, WebRevisionValidationQuery.parse(apiQuery + "&historyValidationPage=2").casePageNumber)
    }
    @Test fun `actual validation report shape retains source identity counts and observation authority`() {
        val f = fixture(); val report = apiReport(f); val summary = report.getValue("summary").jsonObject
        assertEquals("available", report.getValue("state").jsonPrimitive.content)
        assertEquals("passed", summary.getValue("result").jsonPrimitive.content)
        assertEquals("2", summary.getValue("casesCompared").jsonPrimitive.content)
        assertEquals(f.binding.proof.sourceRevisionSha256, summary.getValue("sourceSha256").jsonPrimitive.content)
        assertEquals(f.binding.candidate.value, report.getValue("binding").jsonObject.getValue("revisionId").jsonPrimitive.content)
        assertEquals("observations", report.getValue("authority").jsonPrimitive.content)
        assertEquals("not-evaluated", report.getValue("acceptance").jsonPrimitive.content)
        assertEquals(JsonNull, report.getValue("sourceArtifact")); assertEquals(JsonNull, report.getValue("acceptanceArtifactId"))
        assertFalse("PRIVATE" in report.toString()); assertFalse("command" in report.toString())
    }
    @Test fun `normal mismatches produce a failed report without granting acceptance`() {
        val report = apiReport(fixture(mismatch = true))
        assertEquals("available", report.getValue("state").jsonPrimitive.content)
        assertEquals("failed", report.getValue("summary").jsonObject.getValue("result").jsonPrimitive.content)
        assertEquals("not-evaluated", report.getValue("acceptance").jsonPrimitive.content)
    }
    @Test fun `compile failure and compile only reports do not invent completed behavior pairs`() {
        for ((kind, expected) in listOf(RepairValidationObservedOutcome.COMPILE_FAILED to "failed",
                RepairValidationObservedOutcome.COMPILE_VALID to "unknown")) {
            val summary = apiReport(fixture(outcome = kind)).getValue("summary").jsonObject
            assertEquals(expected, summary.getValue("result").jsonPrimitive.content)
            assertEquals("0", summary.getValue("casesCompared").jsonPrimitive.content)
        }
    }
    @Test fun `unavailable incomplete and corrupt recorded reports remain distinct`() {
        val f = fixture()
        assertEquals("unknown", apiReport(f, primary = null).getValue("state").jsonPrimitive.content)
        assertEquals("unknown", apiReport(f, primary = byteArrayOf()).getValue("state").jsonPrimitive.content)
        val incomplete = apiReport(scopes(f, emptyList()))
        assertEquals("partial", incomplete.getValue("state").jsonPrimitive.content); assertEquals(JsonNull, incomplete.getValue("summary"))
        val invalid = apiReport(f, primary = byteArrayOf(1))
        assertEquals("invalid", invalid.getValue("state").jsonPrimitive.content); assertEquals(JsonNull, invalid.getValue("summary"))
    }
    @Test fun `digest bound unsupported producer versions are not treated as valid or malformed current reports`() {
        val f = fixture()
        val unsupported = apiReport(rebind(f, JsonObject(f.root + ("schemaVersion" to JsonPrimitive(3)))))
        assertEquals("unsupported", unsupported.getValue("state").jsonPrimitive.content)
        assertEquals(3, unsupported.getValue("producerSchemaVersion").jsonPrimitive.intOrNull)
        assertEquals(JsonNull, unsupported.getValue("summary"))
        val invalid = apiReport(rebind(f, JsonObject(f.root + ("schemaVersion" to JsonPrimitive("3")))))
        assertEquals("invalid", invalid.getValue("state").jsonPrimitive.content)
    }
    @Test fun `required derived diff bytes must be available and checked before a report result is exposed`() {
        val f = fixture(mismatch = true)
        val missing = apiReport(f, diff = null); val corrupt = apiReport(f, diff = byteArrayOf(1))
        assertEquals("partial", missing.getValue("state").jsonPrimitive.content)
        assertEquals("invalid", corrupt.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, missing.getValue("summary")); assertEquals(JsonNull, corrupt.getValue("summary"))
    }
    @Test fun `an owner without a normal receipt has no invented normal or fatal result`() {
        val f = fixture(); val report = recordedValidationReport(apiJob, apiRun,
            apiCapture(f, snapshot = apiSnapshot(f, normal = false)))
        assertEquals("unknown", report.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, report.getValue("producerSchemaVersion"))
        assertEquals(JsonNull, report.getValue("summary")); assertEquals(JsonNull, report.getValue("binding").jsonObject.getValue("revisionId"))
    }
    @Test fun `foreign captured graph owner and malformed job identities are refused before projection`() {
        val f = fixture(); var calls = 0
        val different = apiQuery.replace("run_00000001", "run_00000002")
        val reports = WebRevisionValidationReports { _, _, _ -> calls++; apiCapture(f,
            snapshot = apiSnapshot(f, owner = "run_00000002"), query = different) }
        assertEquals(409, assertFailsWith<WebAccessDenied> { reports.read(apiJob, apiRun, apiQuery) }.status)
        assertEquals(404, assertFailsWith<WebAccessDenied> { reports.read("PRIVATE/..", apiRun, apiQuery) }.status)
        assertEquals(1, calls)
        val changed = apiQuery.replace(graph, "9".repeat(64))
        assertEquals(409, assertFailsWith<WebAccessDenied> {
            WebRevisionValidationReports { _, _, _ -> apiCapture(f, snapshot = apiSnapshot(f, digest = "9".repeat(64)), query = changed) }
                .read(apiJob, apiRun, apiQuery)
        }.status)
    }
    @Test fun `capture admission rejects overlapping reads and releases after a callback failure`() {
        val f = fixture(); var fail = true; var busy = false
        lateinit var reports: WebRevisionValidationReports
        reports = WebRevisionValidationReports { _, _, _ ->
            if (fail) error("PRIVATE-callback-failure")
            busy = assertFailsWith<WebAccessDenied> { reports.read(apiJob, apiRun, apiQuery) }.status == 429
            apiCapture(f)
        }
        assertFailsWith<IllegalStateException> { reports.read(apiJob, apiRun, apiQuery) }
        fail = false; assertEquals("available", reports.read(apiJob, apiRun, apiQuery).getValue("state").jsonPrimitive.content)
        assertTrue(busy)
    }
    @Test fun `stale graph and foreign owner selection precede every report inventory or payload callback`() {
        val f = fixture(); val snapshot = apiSnapshot(f); var payloadCalls = 0
        for (selection in listOf(RepairRecordedHistorySelection(expectedGraphSha256 = "9".repeat(64), evidenceRun = "run_00000001"),
                RepairRecordedHistorySelection(expectedGraphSha256 = graph, evidenceRun = "run_foreign"))) {
            assertFailsWith<WebAccessDenied> { captureRecordedValidationReport(selection, apiContext, { "1" },
                { RepairHistoryReadResult.recorded(snapshot) }, { _, _ -> payloadCalls++; apiArtifacts(f) },
                { _, _ -> payloadCalls++; f.bytes }) }
        }
        assertEquals(0, payloadCalls)
    }
    @Test fun `changed attempt or graph after payload capture refuses a mixed report`() {
        val f = fixture(); val selection = WebRevisionValidationQuery.parse(apiQuery).selection
        for (changeGraph in listOf(false, true)) {
            var captured = false
            val failure = assertFailsWith<WebAccessDenied> { captureRecordedValidationReport(selection, apiContext,
                { if (captured && !changeGraph) "2" else "1" },
                { RepairHistoryReadResult.recorded(apiSnapshot(f, digest = if (captured && changeGraph) "9".repeat(64) else graph)) },
                { _, _ -> apiArtifacts(f) }, { _, _ -> captured = true; f.bytes }) }
            assertTrue(captured); assertEquals(409, failure.status)
        }
    }
    @Test fun `ambiguous artifact inventory and excessive commitments never admit a payload read`() {
        val original = fixture(); val selection = WebRevisionValidationQuery.parse(apiQuery).selection
        val oversized = original.copy(binding = original.binding.copy(primary = original.binding.primary.copy(
            bytes = MAXIMUM_RECORDED_REPAIR_EVIDENCE_REQUEST_BYTES + 1)))
        for (f in listOf(original, oversized)) {
            var reads = 0
            val capture = captureRecordedValidationReport(selection, apiContext, { "1" },
                { RepairHistoryReadResult.recorded(apiSnapshot(f)) },
                { _, _ -> apiArtifacts(f).let { if (f === original) it + it.single() else it } },
                { _, _ -> reads++; f.bytes })
            assertEquals(0, reads); assertNull(capture.primary)
        }
    }
    @Test fun `report identities bind the job run graph owner and exact primary receipt`() {
        val f = fixture(); val capture = apiCapture(f)
        fun identity(job: String = apiJob, run: String = apiRun, value: WebRevisionValidationCapture = capture) =
            recordedValidationReport(job, run, value).getValue("reportId").jsonPrimitive.content
        val base = identity(); assertEquals(base, identity())
        assertNotEquals(base, identity(job = "b".repeat(32))); assertNotEquals(base, identity(run = "run_other"))
        assertNotEquals(base, identity(value = apiCapture(stdoutPair(byteArrayOf(1)))))
        val query = apiQuery.replace(graph, "9".repeat(64))
        assertNotEquals(base, identity(value = apiCapture(f, snapshot = apiSnapshot(f, digest = "9".repeat(64)), query = query)))
        val ownerQuery = apiQuery.replace("run_00000001", "run_00000002")
        assertNotEquals(base, identity(value = apiCapture(f, snapshot = apiSnapshot(f, owner = "run_00000002"), query = ownerQuery)))
    }

    @Test fun `versioned case detail retains graph owner corpus source identity exact flags and byte prefixes`() {
        val f = fixture(); val report = apiReport(f); val detail = report.getValue("validationCases").jsonObject
        assertEquals(graph, detail.getValue("graphSha256").jsonPrimitive.content)
        assertEquals(f.binding.proof.sourceRevisionSha256, detail.getValue("sourceSha256").jsonPrimitive.content)
        assertEquals(f.binding.proof.regressionCorpusSha256, detail.getValue("corpusSha256").jsonPrimitive.content)
        assertEquals("run-baseline", detail.getValue("ownerKind").jsonPrimitive.content)
        assertEquals("run_00000001", detail.getValue("ownerId").jsonPrimitive.content)
        assertEquals("2", detail.getValue("totalInputs").jsonPrimitive.content)
        val rows = detail.getValue("items").jsonArray; assertEquals(2, rows.size)
        val first = rows.first().jsonObject
        assertEquals(page(f).cases.first().identity.value, first.getValue("caseId").jsonPrimitive.content)
        assertEquals("matched", first.getValue("outcome").jsonPrimitive.content)
        assertEquals(true, first.getValue("stdoutMatches").jsonPrimitive.booleanOrNull)
        val preview = first.getValue("originalStdoutPreview").jsonObject
        assertEquals("2", preview.getValue("totalBytes").jsonPrimitive.content)
        assertEquals("00 ff", preview.getValue("hex").jsonPrimitive.content)
        assertEquals(JsonNull, preview.getValue("text")); assertEquals(JsonNull, preview.getValue("textBytes"))
        assertFalse("PRIVATE" in report.toString()); assertEquals("not-evaluated", report.getValue("acceptance").jsonPrimitive.content)
    }
    @Test fun `versioned case pages preserve the same report and full counts across bounded windows`() {
        val f = fixture(count = 41); val reports = (1..3).map { apiReport(f, casePage = it) }
        assertEquals(1, reports.map { it.getValue("reportId") }.distinct().size)
        val details = reports.map { it.getValue("validationCases").jsonObject }
        assertEquals(listOf(20, 20, 1), details.map { it.getValue("items").jsonArray.size })
        assertEquals((1..41).map(Int::toString), details.flatMap { it.getValue("items").jsonArray.map { row -> row.jsonObject.getValue("ordinal").jsonPrimitive.content } })
        assertTrue(details.all { it.getValue("totalInputs").jsonPrimitive.content == "41" && it.getValue("matchedInputs").jsonPrimitive.content == "41" })
        assertEquals(JsonNull, details.first().getValue("previousPage")); assertEquals(JsonPrimitive(2), details.first().getValue("nextPage"))
        assertEquals(JsonPrimitive(2), details.last().getValue("previousPage")); assertEquals(JsonNull, details.last().getValue("nextPage"))
        assertEquals(400, assertFailsWith<WebAccessDenied> { apiReport(f, casePage = Int.MAX_VALUE) }.status)
    }
    @Test fun `versioned compilation cases preserve absent comparisons counts and all four previews`() {
        for (kind in listOf(RepairValidationObservedOutcome.COMPILE_FAILED, RepairValidationObservedOutcome.COMPILE_VALID)) {
            val detail = apiReport(fixture(outcome = kind)).getValue("validationCases").jsonObject
            assertEquals(JsonNull, detail.getValue("matchedInputs"))
            val expected = if (kind == RepairValidationObservedOutcome.COMPILE_FAILED) "compile-failed" else "compile-only"
            for (row in detail.getValue("items").jsonArray) {
                val item = row.jsonObject; assertEquals(expected, item.getValue("outcome").jsonPrimitive.content)
                for (name in listOf("exitCodeMatches", "stdoutMatches", "stderrMatches", "originalStdoutBytes", "rebuiltStdoutBytes",
                        "originalStderrBytes", "rebuiltStderrBytes", "originalStdoutPreview", "rebuiltStdoutPreview", "originalStderrPreview", "rebuiltStderrPreview"))
                    assertEquals(JsonNull, item.getValue(name))
            }
        }
    }
    @Test fun `corrupt later case scopes and missing required diffs withhold every versioned case row`() {
        val f = fixture(); val rows = f.root.getValue("scopes").jsonArray.toMutableList()
        rows[4] = JsonObject(rows[4].jsonObject + ("inputId" to JsonPrimitive("PRIVATE-foreign")))
        val corrupt = apiReport(scopes(f, rows)); val incomplete = apiReport(fixture(mismatch = true), diff = null)
        assertEquals("invalid", corrupt.getValue("state").jsonPrimitive.content)
        assertEquals("partial", incomplete.getValue("state").jsonPrimitive.content)
        for (report in listOf(corrupt, incomplete)) assertEquals(JsonNull, report.getValue("validationCases"))
    }
    @Test fun `versioned identical truncated prefixes retain a mismatch beyond their 128 byte boundary`() {
        val original = ByteArray(129) { 65 }; val rebuilt = original.copyOf().also { it[it.lastIndex] = 66 }
        val report = apiReport(stdoutPair(original, rebuilt))
        val row = report.getValue("validationCases").jsonObject.getValue("items").jsonArray.first().jsonObject
        val first = row.getValue("originalStdoutPreview").jsonObject; val second = row.getValue("rebuiltStdoutPreview").jsonObject
        assertEquals(first, second); assertEquals(true, first.getValue("truncated").jsonPrimitive.booleanOrNull)
        assertEquals(128, first.getValue("prefixBytes").jsonPrimitive.intOrNull)
        assertEquals("129", first.getValue("totalBytes").jsonPrimitive.content)
        assertEquals(false, row.getValue("stdoutMatches").jsonPrimitive.booleanOrNull)
        assertEquals("mismatch", row.getValue("outcome").jsonPrimitive.content)
        assertEquals("failed", report.getValue("summary").jsonObject.getValue("result").jsonPrimitive.content)
    }
    @Test fun `unknown and unsupported producer reports do not fabricate versioned case detail`() {
        val f = fixture(); val unknown = apiReport(f, primary = null)
        val unsupported = apiReport(rebind(f, JsonObject(f.root + ("schemaVersion" to JsonPrimitive(3)))))
        for (report in listOf(unknown, unsupported)) {
            assertEquals(JsonNull, report.getValue("validationCases")); assertEquals(JsonNull, report.getValue("summary"))
        }
        val absent = recordedValidationReport(apiJob, apiRun, apiCapture(f, snapshot = apiSnapshot(f, normal = false)))
        assertEquals("unknown", absent.getValue("state").jsonPrimitive.content)
        assertEquals(JsonNull, absent.getValue("validationCases")); assertEquals(JsonNull, absent.getValue("producerSchemaVersion"))
    }
    @Test fun `noncanonical or duplicate versioned case page queries fail before a capture callback`() {
        var captures = 0; val f = fixture()
        val reports = WebRevisionValidationReports { _, _, _ -> captures++; apiCapture(f) }
        for (value in listOf("0", "01", "-1", "2147483648", "%32", "1&historyValidationPage=2")) {
            assertEquals(400, assertFailsWith<WebAccessDenied> {
                reports.read(apiJob, apiRun, apiQuery + "&historyValidationPage=$value")
            }.status)
        }
        assertEquals(0, captures)
    }

    private fun html(f: Fixture, number: Int = 1, diffBytes: ByteArray? = f.diffBytes,
        diffTarget: Boolean = true, ownerWithheld: Boolean = false): String {
        val corpus = f.binding.proof.regressionCorpusSha256
        val run = RepairRecordedRun(4, RepairRecordedIdentity("run_00000001", ownerWithheld), RepairRunStatus.RUNNING,
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
            targets = mapOf(f.binding.primary.artifact to target) + listOfNotNull(f.binding.diff?.takeIf { diffTarget }?.let {
                it.artifact to "reports/runs/run_selected/source-tree/" + repairValidationDiffPath(it.sha256) }).toMap(),
            page = selected, runId = "run_selected",
            validationObservations = mapOf(run.identity to checkedRecordedRepairValidationObservation(f.binding, f.bytes, diffBytes, number)), validationCasePageNumber = number))
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

    private fun discoverySnapshot(f: Fixture, count: Int = 25, pending: Boolean = true,
        runBinding: RepairRecordedValidationObservation = f.binding): RepairHistorySnapshot {
        val base = apiSnapshot(f)
        fun attempt(index: Int, kind: RepairRecordedAttemptKind = RepairRecordedAttemptKind.FINALIZED) = RepairRecordedAttempt(
            kind = kind, identity = RepairRecordedIdentity("revision_$index", false), parent = null, ordinal = index,
            status = null, sourceRevisionSha256 = f.binding.proof.sourceRevisionSha256, run = null,
            publicationMode = null, rollback = null, invocation = null, retainedCases = emptyList(), iterationIndex = null,
            failureKind = RepairRecordedFailureKind.OTHER, before = null, after = null,
            corpusSha256 = f.binding.proof.regressionCorpusSha256, validationObservation = f.binding)
        return RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, "d".repeat(64), base.publishedHead,
            null, null, (1..count).map { base.runs.single().copy(identity = RepairRecordedIdentity("run_$it", false),
                baselineValidationObservation = runBinding) }, (1..count).map { attempt(it) },
            if (pending) attempt(count + 1, RepairRecordedAttemptKind.PENDING) else null, emptyList())
    }
    private fun discoveryCapture(snapshot: RepairHistorySnapshot, selection: RepairRecordedHistorySelection = RepairRecordedHistorySelection()) =
        WebValidationHistoryCapture(RepairHistoryReadResult.recorded(snapshot), RepairRecordedHistoryPage.select(snapshot, selection, 20))

    @Test fun `validation discovery rejects noncanonical selection before any capture`() {
        var captures = 0
        val reports = WebRevisionValidationReports { _, _, _ -> error("receipt must not be read") }
        for (query in listOf("", "historyPage=2", "historyPage=01", "historyPage=2147483648", "historyGraph=$graph&historyGraph=$graph",
            "historyGraph=$graph&historyEvidence=revision_1", "historyGraph=$graph&historyValidationPage=1", "PRIVATE=1")) {
            assertEquals(400, assertFailsWith<WebAccessDenied> { reports.history(apiJob, apiRun, query) { _, _, _ ->
                captures++; error("invalid selection was captured") } }.status)
        }
        assertEquals(404, assertFailsWith<WebAccessDenied> { reports.history("PRIVATE/..", apiRun, null) { _, _, _ ->
            captures++; error("invalid identity was captured") } }.status)
        assertEquals(0, captures)
        assertTrue(parseWebValidationHistoryQuery(null).isDefault)
        assertEquals(2, parseWebValidationHistoryQuery("historyGraph=$graph&historyPage=2").pageNumber)
    }
    @Test fun `validation discovery captures metadata twice with durable version bracketing`() {
        val snapshot = discoverySnapshot(fixture()); var histories = 0; var versions = 0
        val result = captureValidationHistory(RepairRecordedHistorySelection(), { versions++; "version_1" },
            { histories++; RepairHistoryReadResult.recorded(snapshot) })
        assertSame(snapshot, result.page!!.snapshot); assertEquals(2, histories); assertEquals(2, versions)
    }
    @Test fun `validation discovery pages both operation families with pending only on latest page`() {
        val snapshot = discoverySnapshot(fixture())
        val first = webValidationHistory(apiJob, apiRun, discoveryCapture(snapshot))
        val selection = parseWebValidationHistoryQuery("historyGraph=$graph&historyPage=2")
        val second = webValidationHistory(apiJob, apiRun, discoveryCapture(snapshot, selection))
        assertEquals(41, first.getValue("items").jsonArray.size); assertEquals(10, second.getValue("items").jsonArray.size)
        assertEquals(2, first.getValue("nextPage").jsonPrimitive.int); assertEquals(JsonNull, first.getValue("previousPage"))
        assertEquals(1, second.getValue("previousPage").jsonPrimitive.int); assertEquals(JsonNull, second.getValue("nextPage"))
        val identities = (first.getValue("items").jsonArray + second.getValue("items").jsonArray).map {
            val row = it.jsonObject; row.getValue("ownerKind") to row.getValue("ownerId") }
        assertEquals(51, identities.toSet().size)
        assertEquals(400, assertFailsWith<WebAccessDenied> { captureValidationHistory(
            RepairRecordedHistorySelection(pageNumber = 3, expectedGraphSha256 = graph), { "v1" },
            { RepairHistoryReadResult.recorded(snapshot) }) }.status)
    }
    @Test fun `validation discovery distinguishes absent and unavailable without invented zero population`() {
        val reports = WebRevisionValidationReports { _, _, _ -> error("no receipt capture") }
        for ((recorded, state) in listOf(RepairHistoryReadResult.absent() to "not-recorded", RepairHistoryReadResult.unavailable() to "unavailable")) {
            val result = reports.history(apiJob, apiRun, null) { _, _, selection -> captureValidationHistory(selection, { "v1" }, { recorded }) }
            assertEquals(state, result.getValue("state").jsonPrimitive.content)
            for (key in listOf("graphSha256", "corpusSha256", "page", "totalPages", "previousPage", "nextPage"))
                assertEquals(JsonNull, result.getValue(key))
            assertTrue(result.getValue("items").jsonArray.isEmpty())
        }
    }
    @Test fun `validation discovery refuses stale graph and mutation during metadata capture`() {
        val f = fixture(); val snapshot = apiSnapshot(f)
        assertEquals(409, assertFailsWith<WebAccessDenied> { captureValidationHistory(
            RepairRecordedHistorySelection(expectedGraphSha256 = "9".repeat(64)), { "v1" }, { RepairHistoryReadResult.recorded(snapshot) }) }.status)
        for (change in listOf("version", "graph", "status")) {
            var reads = 0
            assertEquals(409, assertFailsWith<WebAccessDenied> { captureValidationHistory(RepairRecordedHistorySelection(),
                { if (reads == 2 && change == "version") "v2" else "v1" }, {
                    reads++
                    if (reads == 2 && change == "status") RepairHistoryReadResult.unavailable()
                    else RepairHistoryReadResult.recorded(if (reads == 2 && change == "graph") apiSnapshot(f, digest = "9".repeat(64)) else snapshot)
                }) }.status)
        }
    }
    @Test fun `validation discovery withholds private owner and candidate references and all their commitments`() {
        val f = fixture(); val base = apiSnapshot(f)
        for (privateOwner in listOf(true, false)) {
            val run = base.runs.single().copy(identity = RepairRecordedIdentity(if (privateOwner) "/PRIVATE-owner" else "run_1", privateOwner),
                baselineValidationObservation = f.binding.copy(candidate = RepairRecordedIdentity("/PRIVATE-candidate", true)))
            val snapshot = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, base.corpusSha256,
                base.publishedHead, null, null, listOf(run), emptyList(), null, emptyList())
            val result = webValidationHistory(apiJob, apiRun, discoveryCapture(snapshot))
            assertFalse("PRIVATE" in result.toString())
            val row = result.getValue("items").jsonArray.single().jsonObject
            assertTrue(row.getValue("identityWithheld").jsonPrimitive.boolean)
            assertTrue(row.getValue("hasReceipt").jsonPrimitive.boolean); assertFalse(row.getValue("canInspect").jsonPrimitive.boolean)
            for (key in listOf("candidateId", "sourceSha256", "corpusSha256")) assertEquals(JsonNull, row.getValue(key))
        }
    }
    @Test fun `validation discovery retains selected historical corpus separately from current corpus`() {
        val f = fixture(); val result = webValidationHistory(apiJob, apiRun, discoveryCapture(discoverySnapshot(f, count = 1, pending = false)))
        assertEquals("d".repeat(64), result.getValue("corpusSha256").jsonPrimitive.content)
        for (row in result.getValue("items").jsonArray) {
            assertEquals(f.binding.proof.regressionCorpusSha256, row.jsonObject.getValue("corpusSha256").jsonPrimitive.content)
            assertTrue(row.jsonObject.getValue("canInspect").jsonPrimitive.boolean)
        }
        val base = apiSnapshot(f)
        val missing = RepairHistorySnapshot(graph, 4, RepairRecordedGraphWire.COMPACT, base.corpusSha256,
            base.publishedHead, null, null, listOf(base.runs.single().copy(baselineValidationObservation = null)),
            emptyList(), null, emptyList())
        val row = webValidationHistory(apiJob, apiRun, discoveryCapture(missing)).getValue("items").jsonArray.single().jsonObject
        assertFalse(row.getValue("hasReceipt").jsonPrimitive.boolean); assertFalse(row.getValue("canInspect").jsonPrimitive.boolean)
        for (key in listOf("candidateId", "sourceSha256", "corpusSha256", "normalOutcome")) assertEquals(JsonNull, row.getValue(key))
    }
    @Test fun `validation history and receipt reads share admission and release it after failure`() {
        val f = fixture(); lateinit var reports: WebRevisionValidationReports
        reports = WebRevisionValidationReports { _, _, _ ->
            assertEquals(429, assertFailsWith<WebAccessDenied> { reports.history(apiJob, apiRun, null) { _, _, _ -> error("busy") } }.status)
            apiCapture(f)
        }
        assertFailsWith<IllegalStateException> { reports.history(apiJob, apiRun, null) { _, _, _ ->
            assertEquals(429, assertFailsWith<WebAccessDenied> { reports.read(apiJob, apiRun, apiQuery) }.status)
            error("authored failure")
        } }
        assertEquals("available", reports.read(apiJob, apiRun, apiQuery).getValue("state").jsonPrimitive.content)
        val value = reports.history(apiJob, apiRun, null) { _, _, _ -> discoveryCapture(apiSnapshot(f)) }
        assertEquals("recorded", value.getValue("state").jsonPrimitive.content)
    }
    @Test fun `source inventory content manifest ordering roles and graph bounds precede comparison authority`() {
        val f = fixture(); val original = AuthoredValidationReceiptMetadata.snapshot
        val files = original.getValue("files").jsonArray
        fun snapshot(rows: JsonArray, manifest: String = sha256(OracleJson.canonicalBytes(rows))) =
            JsonObject(original + mapOf("files" to rows, "manifestSha256" to JsonPrimitive(manifest)))
        val changed = JsonArray(files.mapIndexed { index, element -> if (index == 0)
            JsonObject(element.jsonObject + ("sha256" to JsonPrimitive("a".repeat(64)))) else element })
        val invalid = listOf(snapshot(changed), snapshot(changed, original.getValue("manifestSha256").jsonPrimitive.content),
            snapshot(JsonArray(files.reversed())), snapshot(JsonArray(files + files.first())),
            snapshot(JsonArray(files.map { JsonObject(it.jsonObject + ("mode" to JsonPrimitive(420))) })),
            snapshot(JsonArray(files.map { JsonObject(it.jsonObject + ("role" to JsonPrimitive("source"))) })))
        for (value in invalid) {
            val bad = rebind(f, JsonObject(f.root + ("sourceSnapshot" to value)))
            corrupt(bad); assertEquals("invalid", apiReport(bad).getValue("state").jsonPrimitive.content)
            assertFalse("Recorded exact-byte comparisons</caption>" in html(bad))
        }
        val small = f.copy(binding = f.binding.copy(context = AuthoredValidationReceiptMetadata.context.copy(
            budget = RepairResourceBudget(maximumSourceFiles = 1))))
        corrupt(small)
    }
    @Test fun `runtime digest tools normalized mounts and profile bindings precede comparison authority`() {
        val f = fixture(); val original = AuthoredValidationReceiptMetadata.runtime
        val configuration = original.getValue("runtime").jsonObject
        fun configured(fields: Map<String, JsonElement>) = JsonObject(original +
            ("runtime" to JsonObject(configuration + fields)))
        val variants = listOf(JsonObject(original + ("sandboxConfigurationSha256" to JsonPrimitive("a".repeat(64)))),
            configured(mapOf("tools" to JsonObject(emptyMap()))),
            configured(mapOf("outputTmpfs" to JsonPrimitive("/PRIVATE-source/nested"))),
            configured(mapOf("sandboxConfigurationFile" to JsonPrimitive("relative"))),
            configured(mapOf("profileId" to JsonPrimitive("unrelated"))))
        for (runtime in variants) for (recompute in listOf(false, true)) {
            val digest = if (recompute) sha256(OracleJson.canonicalBytes(runtime)) else f.binding.proof.runtimeSha256
            val bad = rebind(f, JsonObject(f.root + mapOf("runtimeConfiguration" to runtime, "runtimeSha256" to JsonPrimitive(digest))))
                .let { it.copy(binding = it.binding.copy(proof = it.binding.proof.copy(runtimeSha256 = digest))) }
            // A changed but structurally valid configuration with its matching digest is valid metadata.
            if (runtime == variants.first() && recompute) assertEquals(RecordedRepairValidationCaseState.AVAILABLE, page(bad).state)
            else corrupt(bad)
        }
    }
    @Test fun `self consistent substituted reference and candidate outputs cannot replace the durable observations`() {
        val f = fixture(count = 21)
        val first = output(f, 41, mapOf("stdoutBase64" to encoded("unrelated".toByteArray())))
        val both = output(first, 42, mapOf("stdoutBase64" to encoded("unrelated".toByteArray())))
        val forged = both.copy(binding = both.binding.copy(expectedObservationsSha256 = f.binding.expectedObservationsSha256))
        for (number in listOf(1, 2)) {
            assertEquals(RecordedRepairValidationCaseState.CORRUPT, page(forged, number).state)
            val report = apiReport(forged, casePage = number)
            assertEquals("invalid", report.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, report.getValue("summary")); assertEquals(JsonNull, report.getValue("validationCases"))
        }
        assertFalse("Recorded exact-byte comparisons</caption>" in html(forged))
    }
    @Test fun `missing graph context and durable reference commitments cannot produce a validation result`() {
        val f = fixture()
        for (binding in listOf(f.binding.copy(context = null), f.binding.copy(expectedObservationsSha256 = null))) {
            val report = apiReport(f.copy(binding = binding))
            assertEquals("partial", report.getValue("state").jsonPrimitive.content)
            assertEquals(JsonNull, report.getValue("summary")); assertEquals(JsonNull, report.getValue("validationCases"))
        }
        val compilation = fixture(outcome = RepairValidationObservedOutcome.COMPILE_VALID)
        assertEquals("available", apiReport(compilation.copy(binding = compilation.binding.copy(expectedObservationsSha256 = null)))
            .getValue("state").jsonPrimitive.content)
    }
    @Test fun `HTML withholds case rows and previews for missing corrupt unlinked diffs or withheld identities`() {
        val f = fixture(mismatch = true)
        val pages = listOf(html(f, diffBytes = null), html(f, diffBytes = byteArrayOf(1)), html(f, diffTarget = false),
            html(f, ownerWithheld = true), html(f.copy(binding = f.binding.copy(candidate = f.binding.candidate.copy(rawIdentityWithheld = true)))))
        for (rendered in pages) {
            assertTrue("case comparisons are withheld" in rendered)
            assertFalse("Recorded exact-byte comparisons</caption>" in rendered)
            assertFalse("Exact byte prefix (hexadecimal)" in rendered)
            assertFalse("1 matched; 1 mismatched" in rendered)
        }
        assertTrue("Recorded exact-byte comparisons</caption>" in html(f))
    }

}
