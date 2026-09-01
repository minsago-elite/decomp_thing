package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import io.github.optimumcode.json.schema.JsonSchema
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorNativeSandboxPolicyV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Validation of five exact build-local files against the closed native-helper policy v2 draft.
 *
 * This is deliberately not reference evidence, a preparation receipt, execution authorization,
 * containment evidence, scoring authority, or release admission.
 */
sealed interface LlvmBehaviorNativeSandboxPolicyV2Validation {
    val authority: String
    val schemaVersion: Int
    val helperPolicyDraftValidated: Boolean
    val policySha256: String
    val schemaSha256: String
    val helperBytes: Long
    val helperSha256: String
    val checksumSha256: String
    val sourceSha256: String
    val buildRecordSha256: String
    val protocol: String
    val helperContainerPath: String
    val referencePinned: Boolean
    val candidateStarted: Boolean
    val startAuthorized: Boolean
    val scoringAuthority: Boolean
    val releaseEligible: Boolean
}

/**
 * Production validation accepts only five raw paths. No parser, runner, callback, claimed fact,
 * claimed digest, candidate artifact, reference token, or observation can be supplied.
 */
object LlvmBehaviorNativeSandboxPolicyV2Verifier {
    fun verify(
        policyPath: Path,
        helperPath: Path,
        checksumPath: Path,
        helperSourcePath: Path,
        helperBuildRecordPath: Path,
    ): LlvmBehaviorNativeSandboxPolicyV2Validation = VerifiedPolicy(
        policyPath,
        helperPath,
        checksumPath,
        helperSourcePath,
        helperBuildRecordPath,
    )

    /* Reflection cannot bypass verification or inject anything except the same five raw paths. */
    private class VerifiedPolicy(
        policyPath: Path,
        helperPath: Path,
        checksumPath: Path,
        helperSourcePath: Path,
        helperBuildRecordPath: Path,
    ) : LlvmBehaviorNativeSandboxPolicyV2Validation {
        override val authority = POLICY_AUTHORITY
        override val schemaVersion = POLICY_SCHEMA_VERSION
        override val helperPolicyDraftValidated = true
        override val policySha256: String
        override val schemaSha256: String
        override val helperBytes: Long
        override val helperSha256: String
        override val checksumSha256: String
        override val sourceSha256: String
        override val buildRecordSha256: String
        override val protocol = HELPER_PROTOCOL
        override val helperContainerPath = HELPER_CONTAINER_PATH
        override val referencePinned = false
        override val candidateStarted = false
        override val startAuthorized = false
        override val scoringAuthority = false
        override val releaseEligible = false

        init {
            val verified = verifyPolicy(
                policyPath,
                helperPath,
                checksumPath,
                helperSourcePath,
                helperBuildRecordPath,
            )
            policySha256 = verified.policySha256
            schemaSha256 = verified.schemaSha256
            helperBytes = verified.helperBytes
            helperSha256 = verified.helperSha256
            checksumSha256 = verified.checksumSha256
            sourceSha256 = verified.sourceSha256
            buildRecordSha256 = verified.buildRecordSha256
        }
    }
}

private fun verifyPolicy(
    policyPath: Path,
    helperPath: Path,
    checksumPath: Path,
    helperSourcePath: Path,
    helperBuildRecordPath: Path,
): VerifiedPolicyFacts {
    try {
        val paths = PolicyPaths(
            policy = exactRawPath(policyPath, POLICY_FILE_NAME, "native sandbox policy"),
            helper = exactRawPath(helperPath, HELPER_FILE_NAME, "native sandbox helper"),
            checksum = exactRawPath(checksumPath, CHECKSUM_FILE_NAME, "native sandbox helper checksum"),
            source = exactRawPath(helperSourcePath, SOURCE_FILE_NAME, "native sandbox helper source"),
            buildRecord = exactRawPath(
                helperBuildRecordPath,
                BUILD_RECORD_FILE_NAME,
                "native sandbox helper build record",
            ),
        )
        requireDistinctPaths(paths)
        if (paths.helper.parent != paths.checksum.parent) {
            policyFail("native sandbox helper and checksum must share one authenticated directory")
        }

        StableControlFile.open(paths.policy, MAXIMUM_POLICY_BYTES, "native sandbox policy").use { policyGuard ->
            StableControlFile.open(paths.helper, MAXIMUM_HELPER_BYTES, "native sandbox helper").use { helperGuard ->
                StableControlFile.open(
                    paths.checksum,
                    MAXIMUM_CHECKSUM_BYTES,
                    "native sandbox helper checksum",
                ).use { checksumGuard ->
                    StableControlFile.open(
                        paths.source,
                        MAXIMUM_SOURCE_BYTES,
                        "native sandbox helper source",
                    ).use { sourceGuard ->
                        StableControlFile.open(
                            paths.buildRecord,
                            MAXIMUM_BUILD_RECORD_BYTES,
                            "native sandbox helper build record",
                        ).use { buildGuard ->
                            val policyBytes = policyGuard.readAll("native sandbox policy")
                            val helperBytes = helperGuard.readAll("native sandbox helper")
                            val checksumBytes = checksumGuard.readAll("native sandbox helper checksum")
                            val sourceBytes = sourceGuard.readAll("native sandbox helper source")
                            val buildBytes = buildGuard.readAll("native sandbox helper build record")
                            rejectForbiddenRuntimeBytes(policyBytes, "native sandbox policy")
                            rejectForbiddenRuntimeBytes(helperBytes, "native sandbox helper")
                            rejectForbiddenRuntimeBytes(checksumBytes, "native sandbox helper checksum")
                            rejectForbiddenRuntimeBytes(sourceBytes, "native sandbox helper source")
                            rejectForbiddenRuntimeBytes(buildBytes, "native sandbox helper build record")

                            val helperAssessment = LlvmBehaviorNativeHelperArtifactVerifier.verify(
                                paths.helper,
                                paths.checksum,
                            )
                            requireBuildLocalHelper(helperAssessment)
                            requireLinuxAmd64Helper(helperBytes)
                            val facts = RawPolicyFacts(
                                policySha256 = OracleArtifacts.sha256(policyBytes),
                                helperBytes = helperGuard.size,
                                helperSha256 = OracleArtifacts.sha256(helperBytes),
                                checksumSha256 = OracleArtifacts.sha256(checksumBytes),
                                sourceBytes = sourceGuard.size,
                                sourceSha256 = OracleArtifacts.sha256(sourceBytes),
                                buildRecordBytes = buildGuard.size,
                                buildRecordSha256 = OracleArtifacts.sha256(buildBytes),
                            )
                            if (helperAssessment.helperBytes != facts.helperBytes ||
                                helperAssessment.helperSha256 != facts.helperSha256 ||
                                helperAssessment.checksumSha256 != facts.checksumSha256
                            ) {
                                policyFail("native sandbox helper assessment disagrees with the raw files")
                            }

                            val buildRecord = parseCanonicalObject(
                                buildBytes,
                                BUILD_RECORD_JSON_LIMITS,
                                "native sandbox helper build record",
                            )
                            rejectForbiddenRuntimeStrings(buildRecord, "native sandbox helper build record")
                            verifyBuildRecord(buildRecord, facts)

                            val policy = parseCanonicalObject(
                                policyBytes,
                                POLICY_JSON_LIMITS,
                                "native sandbox policy",
                            )
                            rejectForbiddenRuntimeStrings(policy, "native sandbox policy")
                            val schema = NativePolicySchema.loaded
                            schema.validate(policy)
                            schema.requireExactStaticValues(policy)
                            verifyPolicyBindings(policy, facts)

                            terminallyReauthenticate(
                                listOf(
                                    GuardedDigest(policyGuard, facts.policySha256, "native sandbox policy"),
                                    GuardedDigest(helperGuard, facts.helperSha256, "native sandbox helper"),
                                    GuardedDigest(
                                        checksumGuard,
                                        facts.checksumSha256,
                                        "native sandbox helper checksum",
                                    ),
                                    GuardedDigest(sourceGuard, facts.sourceSha256, "native sandbox helper source"),
                                    GuardedDigest(
                                        buildGuard,
                                        facts.buildRecordSha256,
                                        "native sandbox helper build record",
                                    ),
                                ),
                            )
                            val terminalHelper = LlvmBehaviorNativeHelperArtifactVerifier.verify(
                                paths.helper,
                                paths.checksum,
                            )
                            if (terminalHelper.helperBytes != facts.helperBytes ||
                                terminalHelper.helperSha256 != facts.helperSha256 ||
                                terminalHelper.checksumSha256 != facts.checksumSha256
                            ) {
                                policyFail("native sandbox helper changed during terminal verification")
                            }
                            return VerifiedPolicyFacts(
                                policySha256 = facts.policySha256,
                                schemaSha256 = schema.sha256,
                                helperBytes = facts.helperBytes,
                                helperSha256 = facts.helperSha256,
                                checksumSha256 = facts.checksumSha256,
                                sourceSha256 = facts.sourceSha256,
                                buildRecordSha256 = facts.buildRecordSha256,
                            )
                        }
                    }
                }
            }
        }
    } catch (failure: LlvmBehaviorNativeSandboxPolicyV2Exception) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmBehaviorNativeSandboxPolicyV2Exception(
            "LLVM behavior native sandbox policy v2 verification failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }
}

private fun exactRawPath(path: Path, requiredName: String, label: String): Path {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null || path.fileName == null) {
        policyFail("$label path must be exact, absolute, normalized, and name a file")
    }
    if (path.fileName.toString() != requiredName) policyFail("$label must use the fixed file name $requiredName")
    rejectForbiddenRuntimeText(path.toString(), "$label path")
    return path
}

private fun requireDistinctPaths(paths: PolicyPaths) {
    val named = listOf(
        "policy" to paths.policy,
        "helper" to paths.helper,
        "checksum" to paths.checksum,
        "source" to paths.source,
        "build record" to paths.buildRecord,
    )
    for (left in named.indices) {
        for (right in left + 1 until named.size) {
            val aliases = try {
                named[left].second == named[right].second || Files.isSameFile(named[left].second, named[right].second)
            } catch (failure: Exception) {
                throw LlvmBehaviorNativeSandboxPolicyV2Exception(
                    "cannot establish native sandbox path identity",
                    failure,
                )
            }
            if (aliases) policyFail("native sandbox ${named[left].first} and ${named[right].first} paths alias")
        }
    }
}

private fun requireBuildLocalHelper(helper: LlvmBehaviorNativeHelperArtifact) {
    if (helper.protocol != HELPER_PROTOCOL || !helper.staticElfVerified || helper.digestPinnedByReference ||
        helper.startAuthorized || helper.scoringAuthority || helper.releaseEligible
    ) {
        policyFail("native sandbox helper is not the required non-authoritative v2 artifact")
    }
}

private fun requireLinuxAmd64Helper(bytes: ByteArray) {
    if (bytes.size < ELF64_MACHINE_OFFSET + Short.SIZE_BYTES) {
        policyFail("native sandbox helper is too short to bind the fixed linux/amd64 platform")
    }
    val machine = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
        .getShort(ELF64_MACHINE_OFFSET).toInt() and 0xffff
    if (machine != ELF_MACHINE_X86_64) {
        policyFail("native sandbox helper ELF machine does not match the fixed linux/amd64 platform")
    }
}

private fun verifyBuildRecord(record: JsonObject, facts: RawPolicyFacts) {
    record.requireExactKeys(
        setOf("schemaVersion", "kind", "compiler", "argumentTemplate", "source", "output"),
        "native sandbox helper build record",
    )
    if (record.requiredLong("schemaVersion", "native sandbox helper build record") != POLICY_SCHEMA_VERSION.toLong() ||
        record.requiredString("kind", "native sandbox helper build record") != BUILD_RECORD_KIND
    ) {
        policyFail("native sandbox helper build record is not v2")
    }
    val compiler = record.requiredObject("compiler", "native sandbox helper build record")
    compiler.requireExactKeys(setOf("executable", "version"), "native sandbox helper compiler")
    val executable = compiler.requiredString("executable", "native sandbox helper compiler")
    val executablePath = try {
        Path.of(executable)
    } catch (_: Exception) {
        policyFail("native sandbox helper compiler executable is not a path")
    }
    if (!executablePath.isAbsolute || executablePath.normalize() != executablePath || executablePath.fileName == null) {
        policyFail("native sandbox helper compiler executable must be an exact absolute path")
    }
    val version = compiler.requiredString("version", "native sandbox helper compiler")
    if (version.isEmpty() || version.encodeToByteArray().size > MAXIMUM_COMPILER_VERSION_BYTES ||
        version.any { it.code < 0x20 || it.code == 0x7f }
    ) {
        policyFail("native sandbox helper compiler version is invalid")
    }
    rejectForbiddenRuntimeText(executable, "native sandbox helper compiler executable")
    rejectForbiddenRuntimeText(version, "native sandbox helper compiler version")
    val arguments = record.requiredArray("argumentTemplate", "native sandbox helper build record")
        .mapIndexed { index, element -> element.requiredString("native sandbox build argument $index") }
    if (arguments != BUILD_ARGUMENT_TEMPLATE) {
        policyFail("native sandbox helper build arguments differ from the fixed v2 recipe")
    }
    verifyFileRecord(
        record.requiredObject("source", "native sandbox helper build record"),
        SOURCE_FILE_NAME,
        facts.sourceBytes,
        facts.sourceSha256,
        "native sandbox build-record source",
    )
    verifyFileRecord(
        record.requiredObject("output", "native sandbox helper build record"),
        HELPER_FILE_NAME,
        facts.helperBytes,
        facts.helperSha256,
        "native sandbox build-record output",
    )
}

private fun verifyPolicyBindings(policy: JsonObject, facts: RawPolicyFacts) {
    policy.requireExactKeys(
        setOf(
            "schemaVersion", "kind", "authority", "acpBoundary", "backend", "helper", "environment",
            "container", "roles", "mountProfiles", "cgroup", "rlimits", "workspace", "captures",
            "unboundRuntimeInputs", "claims",
        ),
        "native sandbox policy",
    )
    if (policy.requiredLong("schemaVersion", "native sandbox policy") != POLICY_SCHEMA_VERSION.toLong() ||
        policy.requiredString("kind", "native sandbox policy") != POLICY_KIND ||
        policy.requiredString("authority", "native sandbox policy") != POLICY_AUTHORITY ||
        policy.requiredString("backend", "native sandbox policy") != BACKEND
    ) {
        policyFail("native sandbox policy carries a v1 or foreign identity")
    }
    val container = policy.requiredObject("container", "native sandbox policy")
    if (container.requiredString("platform", "native sandbox policy container") != POLICY_PLATFORM ||
        container.requiredString("pidNamespace", "native sandbox policy container") != PRIVATE_PID_NAMESPACE
    ) {
        policyFail("native sandbox policy does not bind the fixed platform and private PID namespace")
    }
    val helper = policy.requiredObject("helper", "native sandbox policy")
    helper.requireExactKeys(
        setOf(
            "fileName", "checksumFileName", "bytes", "sha256", "checksumSha256", "protocol",
            "containerPath", "preExecFrame", "source", "buildRecord",
        ),
        "native sandbox policy helper",
    )
    if (helper.requiredString("fileName", "native sandbox policy helper") != HELPER_FILE_NAME ||
        helper.requiredString("checksumFileName", "native sandbox policy helper") != CHECKSUM_FILE_NAME ||
        helper.requiredLong("bytes", "native sandbox policy helper") != facts.helperBytes ||
        helper.requiredString("sha256", "native sandbox policy helper") != facts.helperSha256 ||
        helper.requiredString("checksumSha256", "native sandbox policy helper") != facts.checksumSha256 ||
        helper.requiredString("protocol", "native sandbox policy helper") != HELPER_PROTOCOL ||
        helper.requiredString("containerPath", "native sandbox policy helper") != HELPER_CONTAINER_PATH ||
        helper.requiredString("preExecFrame", "native sandbox policy helper") != PREEXEC_FRAME
    ) {
        policyFail("native sandbox policy does not pin the exact v2 helper contract")
    }
    verifyFileRecord(
        helper.requiredObject("source", "native sandbox policy helper"),
        SOURCE_FILE_NAME,
        facts.sourceBytes,
        facts.sourceSha256,
        "native sandbox policy helper source",
    )
    verifyFileRecord(
        helper.requiredObject("buildRecord", "native sandbox policy helper"),
        BUILD_RECORD_FILE_NAME,
        facts.buildRecordBytes,
        facts.buildRecordSha256,
        "native sandbox policy helper build record",
    )
}

private fun verifyFileRecord(record: JsonObject, fileName: String, bytes: Long, sha256: String, label: String) {
    record.requireExactKeys(setOf("fileName", "bytes", "sha256"), label)
    if (record.requiredString("fileName", label) != fileName ||
        record.requiredLong("bytes", label) != bytes ||
        record.requiredString("sha256", label) != sha256
    ) {
        policyFail("$label does not bind the authenticated raw file")
    }
}

private object NativePolicySchema {
    val loaded: LoadedPolicySchema by lazy {
        val raw = LlvmBehaviorNativeSandboxPolicyV2Verifier::class.java.classLoader
            .getResourceAsStream("oracle/$SCHEMA_FILE_NAME")?.use { it.readNBytes(MAXIMUM_SCHEMA_BYTES + 1) }
            ?: policyFail("bundled native sandbox policy schema is unavailable")
        if (raw.isEmpty() || raw.size > MAXIMUM_SCHEMA_BYTES) {
            policyFail("bundled native sandbox policy schema exceeds its bounded byte limit")
        }
        val canonical = try {
            OracleJson.parseAndCanonicalize(raw, SCHEMA_JSON_LIMITS)
        } catch (failure: Exception) {
            throw LlvmBehaviorNativeSandboxPolicyV2Exception(
                "bundled native sandbox policy schema is not strict bounded JSON",
                failure,
            )
        }
        val compiled = try {
            JsonSchema.fromDefinition(canonical.decodeToString())
        } catch (failure: Exception) {
            throw LlvmBehaviorNativeSandboxPolicyV2Exception(
                "bundled native sandbox policy schema cannot be compiled",
                failure,
            )
        }
        val rawSha256 = OracleArtifacts.sha256(raw)
        if (rawSha256 != EXPECTED_SCHEMA_SHA256) {
            policyFail("bundled native sandbox policy schema differs from the reviewed v2 bytes")
        }
        val definition = try {
            OracleJson.parse(raw, SCHEMA_JSON_LIMITS) as? JsonObject
                ?: policyFail("bundled native sandbox policy schema root must be an object")
        } catch (failure: LlvmBehaviorNativeSandboxPolicyV2Exception) {
            throw failure
        } catch (failure: Exception) {
            throw LlvmBehaviorNativeSandboxPolicyV2Exception(
                "bundled native sandbox policy schema cannot supply exact static values",
                failure,
            )
        }
        val properties = definition.requiredObject("properties", "bundled native sandbox policy schema")
        val exactStaticValues = STATIC_POLICY_FIELDS.associateWith { name ->
            properties.requiredObject(name, "bundled native sandbox policy schema properties")["const"]
                ?: policyFail("bundled native sandbox policy schema property $name omits const")
        }
        LoadedPolicySchema(compiled, rawSha256, exactStaticValues)
    }
}

private class LoadedPolicySchema(
    private val schema: JsonSchema,
    val sha256: String,
    private val exactStaticValues: Map<String, JsonElement>,
) {
    fun validate(document: JsonObject) {
        val errors = ArrayList<String>()
        val valid = try {
            schema.validate(document) { error ->
                if (errors.size < MAXIMUM_SCHEMA_ERRORS) {
                    errors += error.toString().replace('\n', ' ').replace('\r', ' ')
                        .take(MAXIMUM_SCHEMA_ERROR_CHARS)
                }
            }
        } catch (failure: Exception) {
            throw LlvmBehaviorNativeSandboxPolicyV2Exception(
                "native sandbox policy could not be validated against its bundled schema",
                failure,
            )
        }
        if (!valid || errors.isNotEmpty()) {
            policyFail(
                "native sandbox policy fails its bundled v2 schema" +
                    if (errors.isEmpty()) "" else ": ${errors.joinToString("; ").take(MAXIMUM_ERROR_DETAIL_CHARS)}",
            )
        }
    }

    fun requireExactStaticValues(document: JsonObject) {
        exactStaticValues.forEach { (name, expected) ->
            if (document[name] != expected) {
                policyFail("native sandbox policy $name differs from the exact reviewed JSON value")
            }
        }
    }
}

private fun terminallyReauthenticate(guarded: List<GuardedDigest>) {
    guarded.forEach { item ->
        item.guard.verifyUnchanged(item.label)
        if (item.guard.sha256(label = item.label) != item.sha256) {
            policyFail("${item.label} changed bytes during terminal authentication")
        }
        item.guard.verifyUnchanged(item.label)
    }
}

private fun parseCanonicalObject(bytes: ByteArray, limits: StrictJsonLimits, label: String): JsonObject = try {
    OracleJson.parseCanonical(bytes, limits) as? JsonObject ?: policyFail("$label root must be an object")
} catch (failure: LlvmBehaviorNativeSandboxPolicyV2Exception) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorNativeSandboxPolicyV2Exception("$label is not strict canonical JSON", failure)
}

private fun rejectForbiddenRuntimeBytes(bytes: ByteArray, label: String) {
    FORBIDDEN_RUNTIME_MARKERS.forEach { marker ->
        val needle = marker.encodeToByteArray()
        if (bytes.size < needle.size) return@forEach
        outer@ for (start in 0..bytes.size - needle.size) {
            for (offset in needle.indices) {
                val actual = bytes[start + offset].toInt() and 0xff
                val lowercase = if (actual in 'A'.code..'Z'.code) actual + 32 else actual
                if (lowercase != needle[offset].toInt()) continue@outer
            }
            policyFail("$label contains the forbidden runtime marker $marker")
        }
    }
}

private fun rejectForbiddenRuntimeStrings(value: JsonElement, label: String) {
    when (value) {
        is JsonObject -> value.forEach { (name, child) ->
            rejectForbiddenRuntimeText(name, label)
            rejectForbiddenRuntimeStrings(child, label)
        }
        is JsonArray -> value.forEach { rejectForbiddenRuntimeStrings(it, label) }
        is JsonPrimitive -> if (value.isString) rejectForbiddenRuntimeText(value.content, label)
    }
}

private fun rejectForbiddenRuntimeText(value: String, label: String) {
    val lowercase = value.lowercase()
    FORBIDDEN_RUNTIME_MARKERS.forEach { marker ->
        if (lowercase.contains(marker)) {
            policyFail("$label contains the forbidden runtime marker $marker")
        }
    }
}

private fun StableControlFile.readAll(label: String): ByteArray =
    readExactly(0L, size.toIntBounded(label), label)

private fun Long.toIntBounded(label: String): Int =
    if (this in 1L..Int.MAX_VALUE.toLong()) toInt() else policyFail("$label exceeds JVM array bounds")

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) policyFail("$label fields differ from the closed v2 contract")
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: policyFail("$label $name must be an object")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray = this[name] as? JsonArray
    ?: policyFail("$label $name must be an array")

private fun JsonObject.requiredString(name: String, label: String): String =
    this[name]?.requiredString("$label $name") ?: policyFail("$label omits $name")

private fun JsonElement.requiredString(label: String): String {
    val value = this as? JsonPrimitive ?: policyFail("$label must be a string")
    if (!value.isString) policyFail("$label must be a string")
    return value.content
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val value = this[name] as? JsonPrimitive ?: policyFail("$label $name must be an integer")
    if (value.isString || value.content.any { it in ".eE" }) policyFail("$label $name must be an integer")
    return value.longOrNull ?: policyFail("$label $name exceeds the supported integer range")
}

private fun policyFail(message: String): Nothing = throw LlvmBehaviorNativeSandboxPolicyV2Exception(message)

private data class PolicyPaths(
    val policy: Path,
    val helper: Path,
    val checksum: Path,
    val source: Path,
    val buildRecord: Path,
)

private data class RawPolicyFacts(
    val policySha256: String,
    val helperBytes: Long,
    val helperSha256: String,
    val checksumSha256: String,
    val sourceBytes: Long,
    val sourceSha256: String,
    val buildRecordBytes: Long,
    val buildRecordSha256: String,
)

private data class GuardedDigest(val guard: StableControlFile, val sha256: String, val label: String)

private data class VerifiedPolicyFacts(
    val policySha256: String,
    val schemaSha256: String,
    val helperBytes: Long,
    val helperSha256: String,
    val checksumSha256: String,
    val sourceSha256: String,
    val buildRecordSha256: String,
)

private const val POLICY_SCHEMA_VERSION = 2
private const val POLICY_KIND = "llvm-behavior-native-sandbox-helper-policy-draft"
private const val POLICY_AUTHORITY = "non-authoritative-native-sandbox-helper-policy-v2-draft-validation"
private const val BACKEND = "oci-container-v2"
private const val POLICY_PLATFORM = "linux/amd64"
private const val PRIVATE_PID_NAMESPACE = "private"
private const val HELPER_PROTOCOL = "decomp-llvm-behavior-helper-v2"
private const val PREEXEC_FRAME = "behavior-preexec-v2:"
private const val HELPER_CONTAINER_PATH = "/decomp-llvm-behavior-helper"
private const val POLICY_FILE_NAME = "llvm-behavior-native-sandbox-policy-v2.json"
private const val SCHEMA_FILE_NAME = "llvm-behavior-native-sandbox-policy-v2.schema.json"
private const val HELPER_FILE_NAME = "decomp-llvm-behavior-helper"
private const val CHECKSUM_FILE_NAME = "decomp-llvm-behavior-helper.sha256"
private const val SOURCE_FILE_NAME = "decomp_llvm_behavior_helper.c"
private const val BUILD_RECORD_FILE_NAME = "decomp-llvm-behavior-helper-build-v2.json"
private const val BUILD_RECORD_KIND = "llvm-behavior-native-helper-build-record"
private const val ELF64_MACHINE_OFFSET = 18
private const val ELF_MACHINE_X86_64 = 62
private const val MAXIMUM_POLICY_BYTES = 256L * 1024L
private const val MAXIMUM_HELPER_BYTES = 4L * 1024L * 1024L
private const val MAXIMUM_CHECKSUM_BYTES = 256L
private const val MAXIMUM_SOURCE_BYTES = 2L * 1024L * 1024L
private const val MAXIMUM_BUILD_RECORD_BYTES = 128L * 1024L
private const val MAXIMUM_SCHEMA_BYTES = 256 * 1024
private const val MAXIMUM_COMPILER_VERSION_BYTES = 4096
private const val MAXIMUM_SCHEMA_ERRORS = 32
private const val MAXIMUM_SCHEMA_ERROR_CHARS = 512
private const val MAXIMUM_ERROR_DETAIL_CHARS = 4096
private const val EXPECTED_SCHEMA_SHA256 = "bdce127600546944a3545682c22983383a348aa5a453fa823292fd176bb6f079"

private val STATIC_POLICY_FIELDS = setOf(
    "schemaVersion",
    "kind",
    "authority",
    "acpBoundary",
    "backend",
    "environment",
    "container",
    "roles",
    "mountProfiles",
    "cgroup",
    "rlimits",
    "workspace",
    "captures",
    "unboundRuntimeInputs",
    "claims",
)

private val FORBIDDEN_RUNTIME_MARKERS = listOf(
    "python",
    "decomp-llvm-behavior-helper-v1",
    "behavior-preexec-v1",
    "oci-container-v1",
)

private val BUILD_ARGUMENT_TEMPLATE = listOf(
    "-std=c11",
    "-O2",
    "-static",
    "-Wall",
    "-Wextra",
    "-Werror",
    "-Wformat=2",
    "-Wl,--build-id=none",
    "\${SOURCE}",
    "-o",
    "\${OUTPUT}",
)

private val POLICY_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_POLICY_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_POLICY_BYTES.toInt(),
    maximumDepth = 64,
    maximumNodes = 20_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 192 * 1024,
)

private val BUILD_RECORD_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_BUILD_RECORD_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_BUILD_RECORD_BYTES.toInt(),
    maximumDepth = 16,
    maximumNodes = 1024,
    maximumStringBytes = 16 * 1024,
    maximumTotalStringBytes = 96 * 1024,
)

private val SCHEMA_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_SCHEMA_BYTES,
    maximumCanonicalBytes = MAXIMUM_SCHEMA_BYTES,
    maximumDepth = 96,
    maximumNodes = 50_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 192 * 1024,
)
