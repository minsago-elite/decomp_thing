package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Historical evidence validation only: decoded bytes never confer a live execution authority. */
internal object ContainedCommandTerminalResourceEvidence {
    private const val PROVIDER = "kotlin-contained-command-terminal-resources-v1"
    private val requiredMemoryEvents = setOf("low", "high", "max", "oom", "oom_kill", "oom_group_kill")
    private val scopeFields = setOf("unitName", "nonce", "bootId", "invocationId", "controlGroup",
        "cgroupDevice", "cgroupInode", "cgroupMountId")
    private val limits = StrictJsonLimits(maximumInputBytes = 256 * 1024, maximumCanonicalBytes = 256 * 1024,
        maximumDepth = 16, maximumNodes = 8192, maximumStringBytes = 64 * 1024,
        maximumTotalStringBytes = 192 * 1024, maximumNumberCharacters = 20)
    val policySha256: String = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive(PROVIDER),
        "baseline" to JsonPrimitive("exact-pinned-scope-before-authenticated-START"),
        "terminal" to JsonPrimitive("same-scope-frozen-with-only-retained-BOOT-keepers-before-kill"),
        "counters" to JsonPrimitive("pids.events:all;memory.events:all;required:low,high,max,oom,oom_kill,oom_group_kill"),
        "acceptance" to JsonPrimitive("unchanged-keysets;monotonic;all-except-memory.low-zero-at-both-samples"),
        "output" to JsonPrimitive("HMAC-protocol-v2;sha256-of-owned-pipe-bytes;captured-files-must-match-counts-and-hashes"),
        "cleanup" to JsonPrimitive("exact-unit-cgroup-and-retained-pidfds-absent"),
    ))))

    /** Every available kernel event is retained; unknown nonzero events fail closed. */
    internal class Counters private constructor(val json: JsonObject) {
        fun requireNoLimitEvents() {
            for (controller in listOf("pids", "memory")) {
                for ((name, value) in json.objectField(controller)) {
                    if (controller == "memory" && name == "low") continue
                    require(value == JsonPrimitive(0L)) {
                        "contained command terminal resource limit event: $controller.$name"
                    }
                }
            }
        }

        fun requireMonotonicFrom(baseline: Counters) {
            for (controller in listOf("pids", "memory")) {
                val before = baseline.json.objectField(controller)
                val after = json.objectField(controller)
                require(before.keys == after.keys) { "contained command terminal resource event keys changed" }
                for (name in before.keys) {
                    require(after.number(name) >= before.number(name)) {
                        "contained command terminal resource event counter decreased: $controller.$name"
                    }
                }
            }
            baseline.requireNoLimitEvents()
            requireNoLimitEvents()
        }

        override fun equals(other: Any?): Boolean = other is Counters && json == other.json
        override fun hashCode(): Int = json.hashCode()

        companion object {
            fun parseKernel(pids: String, memory: String): Counters = parse(JsonObject(mapOf(
                "pids" to parseKernelEvents(pids), "memory" to parseKernelEvents(memory),
            )))

            fun parse(value: JsonObject): Counters {
                require(value.keys == setOf("pids", "memory")) { "contained command counter fields differ" }
                for (controller in value.keys) {
                    val events = value.objectField(controller)
                    require(events.size in 1..32 && events.keys.all { it.matches(Regex("[a-z][a-z0-9_]{0,63}")) }) {
                        "contained command resource event names are malformed"
                    }
                    events.keys.forEach { require(events.number(it) >= 0L) { "contained command resource event is negative" } }
                    val required = if (controller == "pids") setOf("max") else requiredMemoryEvents
                    require(events.keys.containsAll(required)) { "contained command required $controller resource event is missing" }
                }
                return Counters(JsonObject(value.mapValues { (_, events) -> JsonObject(LinkedHashMap(events as JsonObject)) }))
            }

            private fun parseKernelEvents(text: String): JsonObject {
                require(text.length in 1..4096 && text.endsWith('\n')) { "contained command resource events are unbounded or incomplete" }
                val events = linkedMapOf<String, JsonPrimitive>()
                for (line in text.dropLast(1).split('\n')) {
                    val fields = line.split(' ')
                    require(fields.size == 2 && fields[0].matches(Regex("[a-z][a-z0-9_]{0,63}")) &&
                        fields[1].matches(Regex("0|[1-9][0-9]{0,18}"))) { "contained command resource event is malformed" }
                    val number = fields[1].toLongOrNull()
                    require(number != null && events.size < 32 && events.put(fields[0], JsonPrimitive(number)) == null) {
                        "contained command resource events are duplicate or outside their bounds"
                    }
                }
                return JsonObject(events)
            }
        }
    }

    internal fun create(attachmentBytes: ByteArray, terminal: Counters): JsonObject {
        val attachment = checkedRecord(attachmentBytes, "attachmentSha256")
        require(attachment["terminalResourcePolicySha256"] == JsonPrimitive(policySha256)) {
            "contained command attachment lacks the terminal resource policy"
        }
        val baseline = Counters.parse(attachment.objectField("terminalResourceBaseline"))
        terminal.requireMonotonicFrom(baseline)
        return JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive(PROVIDER),
            "policySha256" to JsonPrimitive(policySha256),
            "requestSha256" to attachment.getValue("requestSha256"),
            "attachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(attachmentBytes)),
            "scope" to scope(attachment), "baseline" to baseline.json, "final" to terminal.json,
            "keeperProcessesSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(attachment.getValue("processes")))),
            "frozen" to JsonPrimitive(true), "keeperOnly" to JsonPrimitive(true),
            "cleanup" to JsonObject(mapOf("unitAbsent" to JsonPrimitive(true), "cgroupAbsent" to JsonPrimitive(true),
                "processesAbsent" to JsonPrimitive(true))),
        ))
    }

    /** Reopen strict execution evidence against its retained attachment; old executions do not qualify. */
    fun verifyExecution(executionBytes: ByteArray, attachmentBytes: ByteArray): JsonObject {
        val attachment = checkedRecord(attachmentBytes, "attachmentSha256")
        val execution = checkedRecord(executionBytes, "executionSha256")
        val version = attachment.number("schemaVersion")
        require(version in setOf(3L, 5L) &&
            attachment["provider"] == JsonPrimitive("kotlin-lease-contained-command-attachment-v$version") &&
            execution["schemaVersion"] == JsonPrimitive(version) &&
            execution["provider"] == JsonPrimitive("kotlin-lease-contained-command-execution-v$version")) {
            "contained command execution lacks strict terminal resource evidence"
        }
        require(execution["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(attachmentBytes)) &&
            execution["requestSha256"] == attachment["requestSha256"] &&
            execution["deploymentClosureSha256"] == attachment["deploymentClosureSha256"]) {
            "contained command execution differs from its resource attachment"
        }
        val outcome = execution.objectField("outcome")
        requireStrictOutcomeHashes(outcome)
        require(outcome["status"] == JsonPrimitive("EXITED") && outcome["exitCode"] == JsonPrimitive(0) &&
            execution["childExitCode"] == JsonPrimitive(0)) { "contained command strict execution was not successful" }
        require(outcome["requestSha256"] == attachment["requestSha256"] &&
            outcome["nonce"] == attachment["nonce"]) { "contained command strict outcome belongs to another request" }
        val keeperNamespacePid = requireScopeAndKeeper(attachment)
        if (version == 5L) {
            val policy = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION
            val observation = ContainedCommandFileDescriptorObservation.parse(attachment.objectField("fileDescriptorLimits"))
            observation.requireSelected(policy)
            val keeper = (attachment["processes"] as JsonArray).map { it as JsonObject }
                .single { it["role"] == JsonPrimitive("supervisor-jvm") }
            observation.requireIdentity(keeper.number("hostPid"), keeper.number("startTimeTicks"))
            val resources = attachment.objectField("resources")
            require(resources["fileDescriptorPolicySha256"] == JsonPrimitive(policy.sha256) &&
                resources["maximumOpenFiles"] == JsonPrimitive(policy.maximumOpenFiles) &&
                resources["processorCount"] == JsonPrimitive(1)) { "contained command FD resources differ from the actual observation" }
        }
        require(outcome.number("keeperPid") == keeperNamespacePid && outcome.number("childPid") != keeperNamespacePid &&
            outcome.number("childPid") in 1L..Int.MAX_VALUE.toLong()) { "contained command strict outcome belongs to another keeper" }
        require(execution["outcomeSha256"] == JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(outcome)))) {
            "contained command strict outcome digest differs"
        }
        for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) {
            require(execution[field] == JsonPrimitive(true)) { "contained command strict cleanup is incomplete" }
        }
        require(execution["releaseEligible"] == JsonPrimitive(false) && attachment["releaseEligible"] == JsonPrimitive(false)) {
            "contained command historical evidence cannot authorize lease release"
        }
        val proof = execution.objectField("terminalResourceEvidence")
        val expected = create(attachmentBytes, Counters.parse(proof.objectField("final")))
        require(proof == expected) { "contained command terminal resource evidence differs from its frozen scope proof" }
        return proof
    }

    /** Compare retained captures only after authenticating the live outcome or reopening its execution proof. */
    fun requireCapturedOutput(outcome: JsonObject, stdout: ByteArray, stderr: ByteArray) {
        requireStrictOutcomeHashes(outcome)
        for ((stream, bytes) in listOf("stdout" to stdout, "stderr" to stderr)) {
            require(outcome.number("${stream}Bytes") == bytes.size.toLong() &&
                outcome["${stream}Sha256"] == JsonPrimitive(OracleArtifacts.sha256(bytes))) {
                "contained command captured $stream differs from its authenticated pipe bytes"
            }
        }
    }

    private fun requireStrictOutcomeHashes(outcome: JsonObject) {
        require(outcome.keys == setOf("schemaVersion", "provider", "event", "nonce", "requestSha256", "keeperPid",
            "childPid", "exitCode", "elapsedMillis", "stdoutBytes", "stderrBytes", "status", "hmacSha256",
            "stdoutSha256", "stderrSha256") && outcome["schemaVersion"] == JsonPrimitive(2) &&
            outcome["provider"] == JsonPrimitive("kotlin-contained-command-protocol-v2") &&
            outcome["event"] == JsonPrimitive("OUTCOME")) { "contained command strict outcome lacks authenticated pipe hashes" }
        for (stream in listOf("stdout", "stderr")) {
            val bytes = outcome.number("${stream}Bytes")
            val hash = outcome.string("${stream}Sha256")
            require(bytes in 0L..KotlinContainedCommandRequest.MAXIMUM_LOG_BYTES && hash.matches(Regex("[0-9a-f]{64}")) &&
                (bytes != 0L || hash == OracleArtifacts.sha256(ByteArray(0)))) {
                "contained command strict $stream pipe identity is malformed"
            }
        }
        require(outcome.string("hmacSha256").matches(Regex("[0-9a-f]{64}"))) {
            "contained command strict outcome authentication is malformed"
        }
    }

    private fun requireScopeAndKeeper(attachment: JsonObject): Long {
        val unit = attachment.string("unitName")
        require(unit.matches(Regex("[a-z][a-z0-9-]{0,95}-[0-9a-f]{32}\\.scope"))) { "contained command scope name is invalid" }
        val group = attachment.string("controlGroup")
        val path = Path.of(group)
        require(path.isAbsolute && path.normalize().toString() == group && path.fileName.toString() == unit) {
            "contained command scope path is invalid"
        }
        require(attachment.string("bootId").matches(Regex("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")) &&
            attachment.string("invocationId").matches(Regex("[0-9a-f]{32}"))) { "contained command scope invocation is invalid" }
        for (field in listOf("nonce", "requestSha256", "deploymentClosureSha256")) {
            require(attachment.string(field).matches(Regex("[0-9a-f]{64}"))) { "contained command $field is invalid" }
        }
        for (field in listOf("cgroupDevice", "cgroupInode", "cgroupMountId")) {
            require(attachment.number(field) > 0L) { "contained command cgroup identity is invalid" }
        }
        val processes = attachment["processes"] as? JsonArray
            ?: throw IllegalArgumentException("contained command keeper population is absent")
        val roles = listOf("outer-bubblewrap", "namespace-init-bubblewrap", "supervisor-jvm")
        require(processes.size == roles.size) { "contained command keeper population is incomplete" }
        val hostPids = hashSetOf<Long>()
        var keeperNamespacePid = 0L
        processes.forEachIndexed { index, value ->
            val process = value as? JsonObject ?: throw IllegalArgumentException("contained command keeper is not an object")
            require(process.string("role") == roles[index] &&
                process["parentRole"] == if (index == 0) JsonNull else JsonPrimitive(roles[index - 1])) {
                "contained command keeper topology differs"
            }
            val pid = process.number("hostPid")
            require(pid in 1L..Int.MAX_VALUE.toLong() && hostPids.add(pid) && process.number("startTimeTicks") > 0L) {
                "contained command keeper process identity is invalid"
            }
            for (field in listOf("executableDevice", "executableInode", "executableMountId")) {
                require(process.number(field) > 0L) { "contained command keeper executable identity is invalid" }
            }
            val namespacePids = process["namespacePids"] as? JsonArray
                ?: throw IllegalArgumentException("contained command keeper namespace identity is absent")
            require(namespacePids.size == if (index == 0) 1 else 2) { "contained command keeper namespace depth differs" }
            val parsed = namespacePids.map { element -> JsonObject(mapOf("pid" to element)).number("pid") }
            require(parsed.first() == pid && parsed.all { it in 1L..Int.MAX_VALUE.toLong() } &&
                (index != 1 || parsed.last() == 1L) && (index != 2 || parsed.last() > 1L)) {
                "contained command keeper namespace identity differs"
            }
            if (index == 2) keeperNamespacePid = parsed.last()
        }
        return keeperNamespacePid
    }

    private fun scope(attachment: JsonObject): JsonObject = JsonObject(scopeFields.associateWith { field ->
        requireNotNull(attachment[field]) { "contained command scope identity is incomplete" }
    })

    private fun checkedRecord(bytes: ByteArray, hashField: String): JsonObject {
        val value = OracleJson.parseCanonical(bytes, limits) as? JsonObject
            ?: throw IllegalArgumentException("contained command evidence must be an object")
        val expected = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(value - hashField), limits))
        require(value[hashField] == JsonPrimitive(expected)) { "contained command evidence digest differs" }
        return value
    }

    private fun JsonObject.objectField(name: String): JsonObject = this[name] as? JsonObject
        ?: throw IllegalArgumentException("contained command $name is not an object")

    private fun JsonObject.string(name: String): String {
        val value = this[name] as? JsonPrimitive
        require(value != null && value.isString) { "contained command $name is not a string" }
        return value.content
    }

    private fun JsonObject.number(name: String): Long {
        val value = this[name] as? JsonPrimitive
            ?: throw IllegalArgumentException("contained command $name is not an integer")
        require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]{0,18}"))) {
            "contained command $name is not a nonnegative integer"
        }
        return requireNotNull(value.content.toLongOrNull()) { "contained command $name exceeds its integer bound" }
    }
}
