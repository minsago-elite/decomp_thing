package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Closed source-owned selection; neither a parsed declaration nor this enum grants live authority. */
internal enum class ContainedCommandFileDescriptorPolicy(val maximumOpenFiles: Long) {
    MODULE_COMPILATION(7678L);

    fun canonicalIdentity() = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1),
        "provider" to JsonPrimitive("contained-module-compilation-file-descriptor-policy-v1"),
        "scope" to JsonPrimitive("module-object"),
        "softLimit" to JsonPrimitive(maximumOpenFiles), "hardLimit" to JsonPrimitive(maximumOpenFiles),
    ))
    val sha256: String get() = OracleArtifacts.sha256(OracleJson.canonicalBytes(canonicalIdentity()))
}

// This launcher ceiling is independently source-owned, never obtained from a request or receipt.
private const val TRUSTED_MODULE_MAXIMUM_OPEN_FILES = 7678L
internal const val DEFAULT_CONTAINED_COMMAND_MAXIMUM_OPEN_FILES = 512L
internal const val MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES = 64 * 1024

internal fun containedCommandMaximumOpenFiles(policy: ContainedCommandFileDescriptorPolicy?): Long =
    policy?.maximumOpenFiles ?: DEFAULT_CONTAINED_COMMAND_MAXIMUM_OPEN_FILES

internal data class ContainedCommandFileDescriptorLimits(val softLimit: Long, val hardLimit: Long) {
    init { require(softLimit >= 0L && hardLimit >= softLimit) }
}

/** Bounded kernel text only; unlimited and malformed values never become an inferred capacity. */
internal fun parseContainedCommandFileDescriptorLimits(text: String): ContainedCommandFileDescriptorLimits {
    require(text.length in 1..MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES && text.endsWith('\n') &&
        text.all { it == '\n' || it == '\t' || it in ' '..'~' }) { "process limits text is unbounded or malformed" }
    val lines = text.lineSequence().take(130).toList()
    require(lines.size <= 129) { "process limits row count exceeds its bound" }
    val candidates = lines.filter { it.startsWith("Max open files") || it.matches(Regex("Max[ \\t]+open[ \\t]+files(?:[ \\t].*)?")) }
    require(candidates.size == 1) { "process limits require exactly one Max open files row" }
    val match = Regex("Max[ \\t]+open[ \\t]+files[ \\t]+(0|[1-9][0-9]{0,18})[ \\t]+(0|[1-9][0-9]{0,18})[ \\t]+files[ \\t]*")
        .matchEntire(candidates.single()) ?: throw IllegalArgumentException("process open-file limits must be finite integer files")
    return ContainedCommandFileDescriptorLimits(
        requireNotNull(match.groupValues[1].toLongOrNull()), requireNotNull(match.groupValues[2].toLongOrNull()))
}

internal data class ContainedCommandFileDescriptorObservation(
    val hostPid: Long, val startTimeTicks: Long, val limits: ContainedCommandFileDescriptorLimits,
) {
    init { require(hostPid in 1L..Int.MAX_VALUE.toLong() && startTimeTicks > 0L) }
    fun requireIdentity(pid: Long, start: Long) {
        require(hostPid == pid && startTimeTicks == start) { "process open-file observation changed process generation" }
    }
    fun requireSelected(policy: ContainedCommandFileDescriptorPolicy) {
        require(limits.softLimit == policy.maximumOpenFiles && limits.hardLimit == policy.maximumOpenFiles) {
            "actual process open-file limits differ from the selected finite pair"
        }
    }
    fun json() = JsonObject(mapOf(
        "provider" to JsonPrimitive("linux-proc-nofile-observation-v1"),
        "hostPid" to JsonPrimitive(hostPid), "startTimeTicks" to JsonPrimitive(startTimeTicks),
        "softLimit" to JsonPrimitive(limits.softLimit), "hardLimit" to JsonPrimitive(limits.hardLimit),
    ))
    companion object {
        fun parse(value: JsonObject): ContainedCommandFileDescriptorObservation {
            require(value.keys == setOf("provider", "hostPid", "startTimeTicks", "softLimit", "hardLimit") &&
                value["provider"] == JsonPrimitive("linux-proc-nofile-observation-v1"))
            fun number(name: String): Long {
                val field = value[name] as? JsonPrimitive ?: throw IllegalArgumentException("missing limit observation $name")
                require(!field.isString && field.content.matches(Regex("0|[1-9][0-9]{0,18}")))
                return requireNotNull(field.content.toLongOrNull())
            }
            return ContainedCommandFileDescriptorObservation(number("hostPid"), number("startTimeTicks"),
                ContainedCommandFileDescriptorLimits(number("softLimit"), number("hardLimit")))
        }
    }
}

/** Pure admission calculation; production supplies its own stable launcher kernel observation. */
internal fun containedCommandFileDescriptorAdmission(
    policy: ContainedCommandFileDescriptorPolicy, launcher: ContainedCommandFileDescriptorObservation,
): JsonObject {
    require(policy == ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION)
    require(policy.maximumOpenFiles <= TRUSTED_MODULE_MAXIMUM_OPEN_FILES &&
        launcher.limits.hardLimit >= policy.maximumOpenFiles) { "launcher inherited hard limit cannot admit the closed file-descriptor policy" }
    return JsonObject(mapOf(
        "policySha256" to JsonPrimitive(policy.sha256),
        "trustedHostMaximumOpenFiles" to JsonPrimitive(TRUSTED_MODULE_MAXIMUM_OPEN_FILES),
        "launcherProcess" to JsonObject(mapOf(
            "hostPid" to JsonPrimitive(launcher.hostPid), "startTimeTicks" to JsonPrimitive(launcher.startTimeTicks),
            "inheritedSoftLimit" to JsonPrimitive(launcher.limits.softLimit),
            "inheritedHardLimit" to JsonPrimitive(launcher.limits.hardLimit),
        )),
    ))
}

internal fun containedCommandFileDescriptorLimitArgument(maximumOpenFiles: Long): String {
    require(maximumOpenFiles == DEFAULT_CONTAINED_COMMAND_MAXIMUM_OPEN_FILES ||
        maximumOpenFiles == ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION.maximumOpenFiles)
    return "--nofile=$maximumOpenFiles:$maximumOpenFiles"
}

/** Bound enumeration before accumulation; census cardinality and numeric range are separate checks. */
internal fun containedCommandDescriptorNumbers(names: Iterator<String>, maximumOpenFiles: Long): List<Int> {
    containedCommandFileDescriptorLimitArgument(maximumOpenFiles)
    val result = ArrayList<Int>()
    val seen = HashSet<Int>()
    while (names.hasNext()) {
        require(result.size.toLong() < maximumOpenFiles) { "isolated JVM exceeds its descriptor inventory bound" }
        val name = names.next()
        require(name.matches(Regex("0|[1-9][0-9]{0,9}"))) { "isolated JVM descriptor name is malformed" }
        val number = requireNotNull(name.toIntOrNull())
        require(number.toLong() in 0 until maximumOpenFiles && seen.add(number)) {
            "isolated JVM has an invalid, duplicate or out-of-policy descriptor number"
        }
        result += number
    }
    return result
}

private val FD_RUNTIME_LIMITS = StrictJsonLimits(maximumInputBytes = 4 * 1024 * 1024,
    maximumCanonicalBytes = 4 * 1024 * 1024, maximumDepth = 16, maximumNodes = 65_536,
    maximumStringBytes = 65_536, maximumTotalStringBytes = 4 * 1024 * 1024, maximumNumberCharacters = 20)

/** Passive canonical preimage construction, used only after the live owner supplied its observation. */
internal fun containedCommandFileDescriptorRuntimeFields(
    request: KotlinContainedCommandRequest, resources: KotlinSystemdCgroupCommandResources,
    admission: JsonObject, interruptionPolicySha256: String?, visibility: JsonObject?,
): Map<String, JsonElement> {
    val policy = requireNotNull(resources.fileDescriptorPolicy)
    require(request.fileDescriptorPolicySha256 == policy.sha256 && request.maximumOpenFiles == policy.maximumOpenFiles &&
        request.terminalResourcePolicySha256 == ContainedCommandTerminalResourceEvidence.policySha256)
    require(request.allowInterruption == (interruptionPolicySha256 != null))
    require(request.retainedInputVisibilitySha256 == visibility?.let { OracleArtifacts.sha256(OracleJson.canonicalBytes(it)) })
    require(admission.keys == setOf("policySha256", "trustedHostMaximumOpenFiles", "launcherProcess"))
    val process = admission["launcherProcess"] as? JsonObject ?: error("launcher process observation is missing")
    require(process.keys == setOf("hostPid", "startTimeTicks", "inheritedSoftLimit", "inheritedHardLimit"))
    fun number(name: String): Long {
        val value = process[name] as? JsonPrimitive ?: error("launcher process $name is missing")
        require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]{0,18}")))
        return requireNotNull(value.content.toLongOrNull())
    }
    require(admission == containedCommandFileDescriptorAdmission(policy, ContainedCommandFileDescriptorObservation(
        number("hostPid"), number("startTimeTicks"), ContainedCommandFileDescriptorLimits(
            number("inheritedSoftLimit"), number("inheritedHardLimit")))))
    return mapOf(
        "commandRequestProvider" to JsonPrimitive("kotlin-contained-command-request-v5"),
        "commandRequestSha256" to JsonPrimitive(request.sha256),
        "terminalResourcePolicySha256" to JsonPrimitive(ContainedCommandTerminalResourceEvidence.policySha256),
        "resources" to resources.json(), "fileDescriptorAdmission" to admission,
    ) + (interruptionPolicySha256?.let { mapOf("interruptionPolicySha256" to JsonPrimitive(it)) } ?: emptyMap()) +
        (visibility?.let { mapOf("retainedInputVisibility" to it) } ?: emptyMap())
}

internal fun containedCommandFileDescriptorRuntimeBytes(value: JsonObject): ByteArray {
    val required = setOf("provider", "configurationSha256", "deploymentClosureSha256", "runtimeMounts", "readOnlyInputs",
        "keeperEntryPoint", "requestVersion", "commandRequestProvider", "commandRequestSha256", "resources",
        "terminalResourcePolicySha256", "fileDescriptorAdmission")
    val optional = setOf("interruptionPolicySha256", "controlDirectory", "writableRoot", "readOnlyControlDirectories",
        "readOnlyStateDirectory", "readOnlyReportsDirectory", "operationWallDeadline", "retainedInputVisibility")
    require(value.keys.containsAll(required) && (value.keys - required).all { it in optional })
    require(value["provider"] == JsonPrimitive("kotlin-lease-contained-command-runtime-v5"))
    return OracleJson.canonicalBytes(value, FD_RUNTIME_LIMITS)
}
