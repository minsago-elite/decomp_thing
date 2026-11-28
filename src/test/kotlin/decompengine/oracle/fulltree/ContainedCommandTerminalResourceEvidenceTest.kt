package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test

class ContainedCommandTerminalResourceEvidenceTest {
    @Test
    fun `strict request authenticates its policy while default request bytes stay unchanged`() {
        val ordinary = request(strict = false)
        val oldFields = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("kotlin-contained-command-request-v1"),
            "runDirectory" to JsonPrimitive("/srv/contained-run"), "nonce" to JsonPrimitive("a".repeat(64)),
            "command" to JsonArray(listOf(JsonPrimitive("/usr/bin/java"), JsonPrimitive("-version"))),
            "environment" to JsonObject(mapOf("LANG" to JsonPrimitive("C.UTF-8"), "LC_ALL" to JsonPrimitive("C.UTF-8"), "TZ" to JsonPrimitive("UTC"))),
            "maximumStartWaitSeconds" to JsonPrimitive(30), "maximumWallSeconds" to JsonPrimitive(30),
            "maximumStdoutBytes" to JsonPrimitive(1024), "maximumStderrBytes" to JsonPrimitive(1024),
        ))
        assertContentEquals(OracleJson.canonicalBytes(oldFields), ordinary.canonicalBytes)
        val interrupted = request(strict = false, interruption = true)
        assertContentEquals(OracleJson.canonicalBytes(JsonObject(oldFields + mapOf(
            "schemaVersion" to JsonPrimitive(2), "provider" to JsonPrimitive("kotlin-contained-command-request-v2"),
            "allowInterruption" to JsonPrimitive(true),
        ))), interrupted.canonicalBytes)
        for (allowInterruption in listOf(false, true)) {
            val strict = request(interruption = allowInterruption)
            val document = document(strict.canonicalBytes)
            assertEquals(JsonPrimitive(3), document["schemaVersion"])
            assertEquals(JsonPrimitive(ContainedCommandTerminalResourceEvidence.policySha256), document["terminalResourcePolicySha256"])
            assertContentEquals(strict.canonicalBytes, KotlinContainedCommandRequest.parse(strict.canonicalBytes).canonicalBytes)
            assertNotEquals(ordinary.sha256, strict.sha256)
            val start = KotlinContainedCommandProtocol.start(ByteArray(32), strict, 123)
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(start, ByteArray(32), ordinary, 123) }
            for (changed in listOf(
                JsonObject(document - "terminalResourcePolicySha256"),
                JsonObject(document + ("terminalResourcePolicySha256" to JsonPrimitive("0".repeat(64)))),
                JsonObject(document + ("allowInterruption" to JsonPrimitive(false))),
                JsonObject(document + ("schemaVersion" to JsonPrimitive(2))),
            )) assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(OracleJson.canonicalBytes(changed)) }
        }
    }

    @Test
    fun `required counters are closed bounded nonnegative kernel records`() {
        val clean = counters()
        clean.requireNoLimitEvents()
        for (bad in listOf("", "max 0", "max 0\nmax 0\n", "max -1\n", "max 01\n", "max 9223372036854775808\n",
            "max 0 extra\n", "max  0\n", "max 0\n\n", "other 0\n")) {
            assertFailsWith<IllegalArgumentException>(bad) { ContainedCommandTerminalResourceEvidence.Counters.parseKernel(bad, memoryText()) }
        }
        for (key in listOf("low", "high", "max", "oom", "oom_kill", "oom_group_kill")) {
            assertFailsWith<IllegalArgumentException>(key) {
                ContainedCommandTerminalResourceEvidence.Counters.parseKernel("max 0\n",
                    memoryText().lineSequence().filter { it.isNotEmpty() && !it.startsWith("$key ") }.joinToString("\n", postfix = "\n"))
            }
        }
        for (value in listOf(JsonPrimitive("0"), JsonPrimitive(-1), JsonPrimitive(0.0), JsonPrimitive(true))) {
            val invalid = JsonObject(clean.json + ("pids" to JsonObject(mapOf("max" to value))))
            assertFailsWith<IllegalArgumentException> { ContainedCommandTerminalResourceEvidence.Counters.parse(invalid) }
        }
    }

    @Test
    fun `handled process refusal and every enforcing memory event reject successful child results`() {
        val clean = counters()
        for (controller in listOf("pids", "memory")) {
            val keys = if (controller == "pids") listOf("max") else listOf("high", "max", "oom", "oom_kill", "oom_group_kill")
            for (name in keys) {
                val dirty = changedCounter(clean, controller, name, 1)
                assertFailsWith<IllegalArgumentException>("$controller.$name") { dirty.requireMonotonicFrom(clean) }
                // Startup/attachment failures also cannot be hidden by subtracting a nonzero baseline.
                assertFailsWith<IllegalArgumentException>("baseline $controller.$name") { dirty.requireMonotonicFrom(dirty) }
            }
        }
        val baseline = changedCounter(clean, "memory", "low", 2)
        changedCounter(clean, "memory", "low", 3).requireMonotonicFrom(baseline)
        assertFailsWith<IllegalArgumentException> { clean.requireMonotonicFrom(baseline) }
        val unknownZero = changedCounter(clean, "memory", "future_event", 0)
        unknownZero.requireMonotonicFrom(unknownZero)
        assertFailsWith<IllegalArgumentException> { unknownZero.requireMonotonicFrom(clean) }
        assertFailsWith<IllegalArgumentException> { clean.requireMonotonicFrom(unknownZero) }
        assertFailsWith<IllegalArgumentException> { changedCounter(unknownZero, "memory", "future_event", 1).requireMonotonicFrom(unknownZero) }
    }

    @Test
    fun `strict receipt reopens exact scope baseline terminal barrier and cleanup and rejects rehashed tampering`() {
        val attachment = attachment()
        val execution = execution(attachment)
        val proof = ContainedCommandTerminalResourceEvidence.verifyExecution(execution, attachment)
        assertEquals(counters().json, proof["baseline"])
        assertEquals(counters().json, proof["final"])
        val document = document(execution)
        val corruptProofs = listOf(
            JsonObject(proof - "baseline"),
            JsonObject(proof + ("policySha256" to JsonPrimitive("0".repeat(64)))),
            JsonObject(proof + ("frozen" to JsonPrimitive(false))),
            JsonObject(proof + ("keeperOnly" to JsonPrimitive(false))),
            JsonObject(proof + ("keeperProcessesSha256" to JsonPrimitive("0".repeat(64)))),
            JsonObject(proof + ("scope" to JsonObject((proof.getValue("scope") as JsonObject) + ("cgroupInode" to JsonPrimitive(999))))),
            JsonObject(proof + ("cleanup" to JsonObject(mapOf("unitAbsent" to JsonPrimitive(true))))),
            JsonObject(proof + ("final" to changedCounter(counters(), "pids", "max", 1).json)),
            JsonObject(proof + ("final" to changedCounter(counters(), "memory", "high", 1).json)),
            JsonObject(proof + ("unrecorded" to JsonPrimitive(true))),
        )
        for (corrupt in corruptProofs) {
            assertFailsWith<IllegalArgumentException> {
                ContainedCommandTerminalResourceEvidence.verifyExecution(record(JsonObject(document +
                    ("terminalResourceEvidence" to corrupt)), "executionSha256"), attachment)
            }
        }
        for ((name, value) in mapOf(
            "unitAbsent" to JsonPrimitive(false), "cgroupAbsent" to JsonPrimitive(false), "processesAbsent" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(true), "requestSha256" to JsonPrimitive("0".repeat(64)),
            "childExitCode" to JsonPrimitive(137), "schemaVersion" to JsonPrimitive(1),
        )) assertFailsWith<IllegalArgumentException>(name) {
            ContainedCommandTerminalResourceEvidence.verifyExecution(record(JsonObject(document + (name to value)), "executionSha256"), attachment)
        }
        val otherScope = record(JsonObject(document(attachment) + ("invocationId" to JsonPrimitive("e".repeat(32)))), "attachmentSha256")
        assertFailsWith<IllegalArgumentException> { ContainedCommandTerminalResourceEvidence.verifyExecution(execution, otherScope) }
        val staleHash = OracleJson.canonicalBytes(JsonObject(document + ("unitAbsent" to JsonPrimitive(false))))
        assertFailsWith<IllegalArgumentException> { ContainedCommandTerminalResourceEvidence.verifyExecution(staleHash, attachment) }
    }

    @Test
    fun `strict evidence accepts only successful terminal classification`() {
        val attachment = attachment()
        for ((status, code) in listOf("EXITED" to 1, "EXITED" to 127, "EXITED" to 137, "EXITED" to 255,
            "TIMED_OUT" to 0, "OUTPUT_LIMIT" to 0)) {
            assertFailsWith<IllegalArgumentException>("$status/$code") {
                ContainedCommandTerminalResourceEvidence.verifyExecution(execution(attachment, status, code), attachment)
            }
        }
    }

    @Test
    fun `strict outcome pipe hashes bind exact captured bytes and cannot be downgraded`() {
        val stdout = "real-result".toByteArray()
        val stderr = "real-error".toByteArray()
        val strict = request()
        val signed = KotlinContainedCommandOutcome(123, 124, 0, 1, stdout.size.toLong(), stderr.size.toLong(), "EXITED",
            OracleArtifacts.sha256(stdout), OracleArtifacts.sha256(stderr))
        val bytes = KotlinContainedCommandProtocol.outcome(ByteArray(32), strict, signed)
        val outcome = document(bytes)
        assertEquals(JsonPrimitive(2), outcome["schemaVersion"])
        assertEquals(signed, KotlinContainedCommandProtocol.requireOutcome(bytes, ByteArray(32), strict, 123))
        ContainedCommandTerminalResourceEvidence.requireCapturedOutput(outcome, stdout, stderr)
        assertFailsWith<IllegalArgumentException> {
            ContainedCommandTerminalResourceEvidence.requireCapturedOutput(outcome, "fake-result".toByteArray(), stderr)
        }
        assertFailsWith<IllegalArgumentException> {
            ContainedCommandTerminalResourceEvidence.requireCapturedOutput(outcome, stdout, "fake-error".toByteArray())
        }
        for (field in listOf("stdoutSha256", "stderrSha256")) {
            val corrupt = JsonObject(outcome + (field to JsonPrimitive("0".repeat(64))))
            assertFailsWith<IllegalArgumentException> {
                KotlinContainedCommandProtocol.requireOutcome(OracleJson.canonicalBytes(corrupt), ByteArray(32), strict, 123)
            }
            assertFailsWith<IllegalArgumentException> {
                ContainedCommandTerminalResourceEvidence.requireCapturedOutput(JsonObject(outcome - field), stdout, stderr)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            KotlinContainedCommandProtocol.outcome(ByteArray(32), strict, signed.copy(stdoutSha256 = null))
        }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.outcome(ByteArray(32), request(strict = false), signed) }
        val legacy = document(KotlinContainedCommandProtocol.outcome(ByteArray(32), request(strict = false),
            signed.copy(stdoutSha256 = null, stderrSha256 = null)))
        assertEquals(JsonPrimitive(1), legacy["schemaVersion"])
        assertEquals(outcome.keys - setOf("stdoutSha256", "stderrSha256"), legacy.keys)
        assertFailsWith<IllegalArgumentException> { ContainedCommandTerminalResourceEvidence.requireCapturedOutput(legacy, stdout, stderr) }
    }

    // BEGIN authored v5 terminal verifier controls. These records are not live or complete module proofs.
    @Test
    fun `v5 authored successful evidence retains strict pipe proof and complete requested resources`() {
        val attachment = v5Attachment()
        val execution = v5Execution(attachment)
        val proof = ContainedCommandTerminalResourceEvidence.verifyExecution(execution, attachment)
        assertEquals(counters().json, proof["baseline"])
        assertEquals(counters().json, proof["final"])
        val resources = document(attachment).getValue("resources") as JsonObject
        assertEquals(setOf("wallClockMillis", "maximumResidentBytes", "pidsMax", "maximumFileBytes", "processorCount",
            "fileDescriptorPolicySha256", "maximumOpenFiles"), resources.keys)
        assertEquals(JsonPrimitive(7678), resources["maximumOpenFiles"])
        val outcome = document(execution).getValue("outcome") as JsonObject
        assertEquals(JsonPrimitive(2), outcome["schemaVersion"])
        assertEquals(JsonPrimitive("kotlin-contained-command-protocol-v2"), outcome["provider"])
        ContainedCommandTerminalResourceEvidence.requireCapturedOutput(outcome, v5Stdout(), v5Stderr())
        for ((stdout, stderr) in listOf("substituted".toByteArray() to v5Stderr(), v5Stdout() to "substituted".toByteArray())) {
            assertFailsWith<IllegalArgumentException> {
                ContainedCommandTerminalResourceEvidence.requireCapturedOutput(outcome, stdout, stderr)
            }
        }
    }

    @Test
    fun `v5 successful verifier rejects unsupported or mismatched outer versions after complete rehash`() {
        for ((attachmentVersion, executionVersion) in listOf(3 to 5, 5 to 3, 4 to 4, 6 to 6)) {
            val attachment = record(JsonObject(document(v5Attachment()) + mapOf(
                "schemaVersion" to JsonPrimitive(attachmentVersion),
                "provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v$attachmentVersion"))), "attachmentSha256")
            val execution = record(JsonObject(document(v5Execution(attachment)) + mapOf(
                "schemaVersion" to JsonPrimitive(executionVersion),
                "provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v$executionVersion"))), "executionSha256")
            assertRehashedV5Failure(attachment, execution, "contained command execution lacks strict terminal resource evidence")
        }
        val attachment = record(JsonObject(document(v5Attachment()) +
            ("provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v3"))), "attachmentSha256")
        assertRehashedV5Failure(attachment, v5Execution(attachment),
            "contained command execution lacks strict terminal resource evidence")
    }

    @Test
    fun `v5 interrupted provider and interrupted outcomes cannot pass the successful verifier`() {
        val request = v5Request(interruption = true)
        val attachment = v5Attachment(request)
        val interrupted = v5Execution(attachment, request, "INTERRUPTED")
        val outer = record(JsonObject(document(v5Execution(attachment, request)) +
            ("provider" to JsonPrimitive("kotlin-lease-contained-command-interrupted-v5"))), "executionSha256")
        assertRehashedV5Failure(attachment, outer, "contained command execution lacks strict terminal resource evidence")
        assertRehashedV5Failure(attachment, interrupted, "contained command strict execution was not successful")
    }

    @Test
    fun `v5 rehashed unknown descriptor policy cannot match the observed resource declaration`() {
        val attachment = document(v5Attachment())
        val resources = attachment.getValue("resources") as JsonObject
        for (digest in listOf("0".repeat(64), ContainedCommandTerminalResourceEvidence.policySha256)) {
            assertRehashedV5AttachmentFailure(JsonObject(attachment + ("resources" to JsonObject(resources +
                ("fileDescriptorPolicySha256" to JsonPrimitive(digest))))),
                "contained command FD resources differ from the actual observation")
        }
    }

    @Test
    fun `v5 rehashed resource limit and serial processor declarations must retain exact integer values`() {
        val attachment = document(v5Attachment())
        val resources = attachment.getValue("resources") as JsonObject
        val changes = listOf("maximumOpenFiles" to JsonPrimitive(7677), "maximumOpenFiles" to JsonPrimitive(7679),
            "maximumOpenFiles" to JsonPrimitive("7678"), "maximumOpenFiles" to JsonNull,
            "processorCount" to JsonPrimitive(2), "processorCount" to JsonPrimitive("1"))
        for ((field, value) in changes) {
            assertRehashedV5AttachmentFailure(JsonObject(attachment + ("resources" to JsonObject(resources + (field to value)))),
                "contained command FD resources differ from the actual observation")
        }
    }

    @Test
    fun `v5 rehashed observed limits reject finite mismatched pairs after numeric parsing`() {
        val attachment = document(v5Attachment())
        val observation = attachment.getValue("fileDescriptorLimits") as JsonObject
        for ((soft, hard) in listOf(7677 to 7678, 7678 to 7679, 512 to 512, 7679 to 7679)) {
            val changed = JsonObject(observation + mapOf("softLimit" to JsonPrimitive(soft), "hardLimit" to JsonPrimitive(hard)))
            assertRehashedV5AttachmentFailure(JsonObject(attachment + ("fileDescriptorLimits" to changed)),
                "actual process open-file limits differ from the selected finite pair")
        }
    }

    @Test
    fun `v5 rehashed observation must name the supervisor host PID from the unchanged population`() {
        val attachment = document(v5Attachment())
        val observation = attachment.getValue("fileDescriptorLimits") as JsonObject
        for (hostPid in listOf(1001, 7777)) {
            val changed = JsonObject(observation + ("hostPid" to JsonPrimitive(hostPid)))
            val mutated = JsonObject(attachment + ("fileDescriptorLimits" to changed))
            assertEquals(attachment["processes"], mutated["processes"])
            assertRehashedV5AttachmentFailure(mutated, "process open-file observation changed process generation")
        }
    }

    @Test
    fun `v5 rehashed observation must retain the supervisor start ticks from the unchanged population`() {
        val attachment = document(v5Attachment())
        val observation = attachment.getValue("fileDescriptorLimits") as JsonObject
        val mutated = JsonObject(attachment + ("fileDescriptorLimits" to JsonObject(observation +
            ("startTimeTicks" to JsonPrimitive(101)))))
        assertEquals(attachment["processes"], mutated["processes"])
        assertRehashedV5AttachmentFailure(mutated, "process open-file observation changed process generation")
    }

    @Test
    fun `v5 observation rejects extra missing and incorrect provider fields after complete rehash`() {
        val attachment = document(v5Attachment())
        val observation = attachment.getValue("fileDescriptorLimits") as JsonObject
        val malformed = listOf(JsonObject(observation + ("unrecorded" to JsonPrimitive(true))),
            JsonObject(observation + ("provider" to JsonPrimitive("linux-proc-nofile-observation-v2")))) +
            observation.keys.map { JsonObject(observation - it) }
        for (changed in malformed) {
            assertRehashedV5AttachmentFailure(JsonObject(attachment + ("fileDescriptorLimits" to changed)))
        }
        assertRehashedV5AttachmentFailure(JsonObject(attachment + ("fileDescriptorLimits" to JsonNull)),
            "contained command fileDescriptorLimits is not an object")
    }

    @Test
    fun `v5 observation rejects wrong integer types after complete rehash`() {
        val attachment = document(v5Attachment())
        val observation = attachment.getValue("fileDescriptorLimits") as JsonObject
        for (field in listOf("hostPid", "startTimeTicks", "softLimit", "hardLimit")) {
            for (value in listOf(JsonPrimitive("7678"), JsonPrimitive(7678.0), JsonPrimitive(true), JsonNull)) {
                assertRehashedV5AttachmentFailure(JsonObject(attachment + ("fileDescriptorLimits" to
                    JsonObject(observation + (field to value)))))
            }
        }
    }

    @Test
    fun `v5 rehashed successful records cannot discard either strict pipe hash`() {
        val attachment = v5Attachment()
        val execution = document(v5Execution(attachment))
        val outcome = execution.getValue("outcome") as JsonObject
        for (field in listOf("stdoutSha256", "stderrSha256")) {
            val changed = JsonObject(outcome - field)
            val mutated = record(JsonObject(execution + mapOf("outcome" to changed,
                "outcomeSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(changed))))), "executionSha256")
            assertRehashedV5Failure(attachment, mutated, "contained command strict outcome lacks authenticated pipe hashes")
        }
    }

    private fun v5Request(interruption: Boolean = false) = KotlinContainedCommandRequest(
        Path.of("/srv/contained-run"), "a".repeat(64), listOf("/usr/bin/java", "-version"),
        mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 30, 30, 1024, 1024,
        allowInterruption = interruption, terminalResourcePolicySha256 = ContainedCommandTerminalResourceEvidence.policySha256,
        fileDescriptorPolicy = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION,
    )

    private fun v5Attachment(request: KotlinContainedCommandRequest = v5Request()): ByteArray {
        val resources = KotlinSystemdCgroupCommandResources(30_000, 512L * 1024 * 1024, 128, 64L * 1024 * 1024,
            fileDescriptorPolicy = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION)
        return record(JsonObject(document(attachment()) + mapOf(
            "schemaVersion" to JsonPrimitive(5), "provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v5"),
            "requestSha256" to JsonPrimitive(request.sha256), "resources" to resources.json(),
            "fileDescriptorLimits" to JsonObject(mapOf(
                "provider" to JsonPrimitive("linux-proc-nofile-observation-v1"), "hostPid" to JsonPrimitive(1002),
                "startTimeTicks" to JsonPrimitive(100), "softLimit" to JsonPrimitive(7678), "hardLimit" to JsonPrimitive(7678),
            )),
        )), "attachmentSha256")
    }

    private fun v5Execution(attachment: ByteArray, request: KotlinContainedCommandRequest = v5Request(),
        status: String = "EXITED"): ByteArray {
        val stdout = v5Stdout()
        val stderr = v5Stderr()
        val outcome = KotlinContainedCommandProtocol.outcome(ByteArray(32), request,
            KotlinContainedCommandOutcome(123, 124, 0, 1, stdout.size.toLong(), stderr.size.toLong(), status,
                OracleArtifacts.sha256(stdout), OracleArtifacts.sha256(stderr)))
        return record(JsonObject(document(execution(attachment)) + mapOf(
            "schemaVersion" to JsonPrimitive(5), "provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v5"),
            "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(attachment)),
            "requestSha256" to JsonPrimitive(request.sha256), "outcome" to document(outcome),
            "outcomeSha256" to JsonPrimitive(OracleArtifacts.sha256(outcome)),
            "terminalResourceEvidence" to ContainedCommandTerminalResourceEvidence.create(attachment, counters()),
        )), "executionSha256")
    }

    private fun assertRehashedV5AttachmentFailure(value: JsonObject, expectedMessage: String? = null) {
        val attachment = record(value, "attachmentSha256")
        assertRehashedV5Failure(attachment, v5Execution(attachment), expectedMessage)
    }

    private fun assertRehashedV5Failure(attachment: ByteArray, execution: ByteArray, expectedMessage: String? = null) {
        // These checks prevent a stale self-hash or attachment/proof link from satisfying a semantic counterexample.
        assertContentEquals(attachment, record(document(attachment), "attachmentSha256"))
        val decoded = document(execution)
        assertContentEquals(execution, record(decoded, "executionSha256"))
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(attachment)), decoded["attachmentSha256"])
        assertEquals(ContainedCommandTerminalResourceEvidence.create(attachment, counters()), decoded["terminalResourceEvidence"])
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(decoded.getValue("outcome")))), decoded["outcomeSha256"])
        val failure = assertFailsWith<IllegalArgumentException> {
            ContainedCommandTerminalResourceEvidence.verifyExecution(execution, attachment)
        }
        if (expectedMessage != null) assertEquals(expectedMessage, failure.message)
        assertNotEquals("contained command evidence digest differs", failure.message)
    }

    private fun v5Stdout() = "authored-v5-result".toByteArray()
    private fun v5Stderr() = "authored-v5-diagnostic".toByteArray()
    // END authored v5 terminal verifier controls.

    private fun request(strict: Boolean = true, interruption: Boolean = false) = KotlinContainedCommandRequest(
        Path.of("/srv/contained-run"), "a".repeat(64), listOf("/usr/bin/java", "-version"),
        mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 30, 30, 1024, 1024,
        interruption, if (strict) ContainedCommandTerminalResourceEvidence.policySha256 else null,
    )

    private fun counters() = ContainedCommandTerminalResourceEvidence.Counters.parseKernel("max 0\n", memoryText())
    private fun memoryText() = "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\noom_group_kill 0\n"
    private fun changedCounter(counters: ContainedCommandTerminalResourceEvidence.Counters, controller: String, key: String, value: Long) =
        ContainedCommandTerminalResourceEvidence.Counters.parse(JsonObject(counters.json + (controller to
            JsonObject((counters.json.getValue(controller) as JsonObject) + (key to JsonPrimitive(value))))))

    private fun attachment(): ByteArray = record(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(3), "provider" to JsonPrimitive("kotlin-lease-contained-command-attachment-v3"),
        "unitName" to JsonPrimitive("decomp-kotlin-${"a".repeat(32)}.scope"), "nonce" to JsonPrimitive(request().nonce),
        "bootId" to JsonPrimitive("11111111-2222-3333-4444-555555555555"), "invocationId" to JsonPrimitive("b".repeat(32)),
        "controlGroup" to JsonPrimitive("/user.slice/decomp-kotlin-${"a".repeat(32)}.scope"),
        "cgroupDevice" to JsonPrimitive(10), "cgroupInode" to JsonPrimitive(20), "cgroupMountId" to JsonPrimitive(30),
        "requestSha256" to JsonPrimitive(request().sha256), "deploymentClosureSha256" to JsonPrimitive("c".repeat(64)),
        "releaseEligible" to JsonPrimitive(false), "processes" to keeperProcesses(),
        "terminalResourcePolicySha256" to JsonPrimitive(ContainedCommandTerminalResourceEvidence.policySha256),
        "terminalResourceBaseline" to counters().json,
    )), "attachmentSha256")

    private fun keeperProcesses(): JsonArray {
        val roles = listOf("outer-bubblewrap", "namespace-init-bubblewrap", "supervisor-jvm")
        return JsonArray(roles.mapIndexed { index, role -> JsonObject(mapOf(
            "role" to JsonPrimitive(role), "hostPid" to JsonPrimitive(1000 + index), "startTimeTicks" to JsonPrimitive(100),
            "parentRole" to if (index == 0) JsonNull else JsonPrimitive(roles[index - 1]),
            "namespacePids" to JsonArray((listOf(1000 + index) + when (index) { 1 -> listOf(1); 2 -> listOf(123); else -> emptyList() }).map(::JsonPrimitive)),
            "executableDevice" to JsonPrimitive(2), "executableInode" to JsonPrimitive(2000 + index), "executableMountId" to JsonPrimitive(3),
        )) })
    }

    private fun execution(attachment: ByteArray, status: String = "EXITED", code: Int = 0): ByteArray {
        val outcome = KotlinContainedCommandProtocol.outcome(ByteArray(32), request(),
            KotlinContainedCommandOutcome(123, 124, code, 1, 0, 0, status,
                OracleArtifacts.sha256(ByteArray(0)), OracleArtifacts.sha256(ByteArray(0))))
        return record(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(3), "provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v3"),
            "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(attachment)),
            "requestSha256" to JsonPrimitive(request().sha256), "deploymentClosureSha256" to JsonPrimitive("c".repeat(64)),
            "outcome" to document(outcome), "outcomeSha256" to JsonPrimitive(OracleArtifacts.sha256(outcome)),
            "childExitCode" to JsonPrimitive(code), "unitAbsent" to JsonPrimitive(true), "cgroupAbsent" to JsonPrimitive(true),
            "processesAbsent" to JsonPrimitive(true), "releaseEligible" to JsonPrimitive(false),
            "terminalResourceEvidence" to ContainedCommandTerminalResourceEvidence.create(attachment, counters()),
        )), "executionSha256")
    }

    private fun record(value: JsonObject, key: String): ByteArray {
        val unsigned = JsonObject(value - key)
        return OracleJson.canonicalBytes(JsonObject(unsigned + (key to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned))))))
    }
    private fun document(bytes: ByteArray) = OracleJson.parseCanonical(bytes) as JsonObject
}
