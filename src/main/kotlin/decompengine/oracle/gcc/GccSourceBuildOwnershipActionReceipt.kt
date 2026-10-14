package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject

/** Caller-lowerable bounds for one supplied offline observation, not the proposed capture operation. */
internal data class GccSourceBuildOwnershipObservationLimits(
    val maximumRecordBytes: Int = 8 * 1024 * 1024,
    val maximumRecordNodes: Int = 100_000,
    val maximumArgvWords: Int = 16_384,
    val maximumEnvironmentEntries: Int = 4_096,
    val maximumFileClaims: Int = 4_096,
    val maximumResponseFiles: Int = 256,
) {
    init {
        require(maximumRecordBytes in 1..8 * 1024 * 1024)
        require(maximumRecordNodes in 1..100_000)
        require(maximumArgvWords in 1..16_384)
        require(maximumEnvironmentEntries in 1..4_096)
        require(maximumFileClaims in 1..4_096)
        require(maximumResponseFiles in 0..256)
    }
}

/**
 * A structurally checked receipt INPUT. Supplied JSON cannot create an execution receipt, owner,
 * source signature, runtime bridge, collector completion, model binding or score.
 */
internal class GccSourceBuildOwnershipActionReceipt private constructor(
    val phase: String,
    val role: String,
    val target: String,
    val cwd: String,
    val effectiveImageIdClaim: String,
    argv: List<String>,
    environment: Map<String, String>,
    inputs: List<GccSourceBuildFileClaim>,
    outputs: List<GccSourceBuildFileClaim>,
    val actionCandidateId: String,
    val compileIdentityCandidateId: String?,
    private val encoded: ByteArray,
) {
    val argv = OwnershipJson.immutable(argv)
    val environment = OwnershipJson.immutableMap(environment)
    val inputs = OwnershipJson.immutable(inputs)
    val outputs = OwnershipJson.immutable(outputs)
    val isExecutionReceipt: Boolean get() = false
    val sourceAuthenticated: Boolean get() = false
    val runtimeAuthenticated: Boolean get() = false
    val captureAuthenticated: Boolean get() = false
    val ownershipComplete: Boolean get() = false
    val modelBound: Boolean get() = false
    val sealed: Boolean get() = false
    val scored: Boolean get() = false
    val productionVerified: Boolean get() = false
    val releaseEligible: Boolean get() = false
    fun canonicalBytes(): ByteArray = encoded.copyOf()

    companion object {
        const val SCHEMA = "gcc/source-build-ownership-action-receipt-v1"
        private val ROOTS = setOf("source", "generated", "build", "toolchain", "external")
        private val PHASES = setOf("configure", "compile", "install", "stage-full", "strip", "link-diagnostic")
        private val ROLES = setOf("source-compile", "generator-compile", "configure-probe", "assemble", "archive",
            "archive-index", "link", "generate", "install", "strip", "other-build-output")
        private val KINDS = setOf("source", "generated", "header", "tool", "runtime", "response", "script", "object", "archive", "other")
        private val AUTHORITY = setOf("sourceAuthenticated", "runtimeAuthenticated", "captureAuthenticated",
            "ownershipComplete", "modelBound", "sealed", "scored", "productionVerified", "releaseEligible")
        // Only reviewed public build configuration belongs in retained canonical observations.
        // This is not a credential detector; unknown names fail closed before values are retained.
        private val PUBLIC_BUILD_ENVIRONMENT_KEYS = setOf(
            "PATH", "LANG", "LC_ALL", "TZ", "SOURCE_DATE_EPOCH",
            "CFLAGS", "CXXFLAGS", "CPPFLAGS", "LDFLAGS",
        )

        fun parseObservation(
            bytes: ByteArray,
            profile: GccSourceBuildOwnershipProfile,
            metadata: GccSourceBuildOwnershipInputs,
            limits: GccSourceBuildOwnershipObservationLimits = GccSourceBuildOwnershipObservationLimits(),
        ): GccSourceBuildOwnershipActionReceipt = ownershipBoundary {
            ownershipRequire(metadata.profileSha256 == profile.canonicalSha256, "metadata/profile generations differ")
            val root = OwnershipJson.parseObject(bytes, limits.maximumRecordBytes, limits.maximumRecordNodes)
            OracleSchemas.validate(SCHEMA, root)
            OwnershipJson.exact(root, setOf("schemaVersion", "schema", "evidenceKind", "profileSha256", "metadataSetSha256", "phase",
                "role", "target", "cwd", "configurationSha256", "source", "tool", "runtime", "argv", "environment",
                "inputFiles", "outputFiles", "responseFiles", "exitCode", "completion", "authority"), "action observation")
            ownershipRequire(OwnershipJson.number(root, "schemaVersion") == 1L, "schema version differs")
            OwnershipJson.expect(root, "schema", "gcc-source-build-ownership-action-observation-v1")
            OwnershipJson.expect(root, "evidenceKind", "untrusted-offline-observation")
            ownershipRequire(OwnershipJson.text(root, "profileSha256") == profile.canonicalSha256 &&
                OwnershipJson.text(root, "metadataSetSha256") == metadata.metadataSetSha256, "action metadata binding differs")
            val phase = OwnershipJson.text(root, "phase").also { ownershipRequire(it in PHASES, "unsupported phase") }
            val role = OwnershipJson.text(root, "role").also { ownershipRequire(it in ROLES, "unsupported role") }
            val target = OwnershipJson.text(root, "target", 256)
            val cwd = OwnershipJson.path(OwnershipJson.text(root, "cwd"), setOf("build"))
            OwnershipJson.sha(OwnershipJson.text(root, "configurationSha256"))
            val tool = OwnershipJson.obj(root, "tool")
            OwnershipJson.exact(tool, setOf("path", "bytes", "sha256"), "tool")
            OwnershipJson.path(OwnershipJson.text(tool, "path"), ROOTS)
            OwnershipJson.number(tool, "bytes", 1)
            OwnershipJson.sha(OwnershipJson.text(tool, "sha256"))
            val runtime = OwnershipJson.obj(root, "runtime")
            OwnershipJson.exact(runtime, setOf("recordedOriginImageId", "effectiveImageIdClaim", "claimState", "bridgeReceipt"), "runtime")
            OwnershipJson.expect(runtime, "recordedOriginImageId", metadata.recordedOriginImageId)
            val image = OwnershipJson.text(runtime, "effectiveImageIdClaim")
            ownershipRequire(image in setOf(metadata.recordedOriginImageId, metadata.proposedReproducedImageId),
                "runtime claim is outside the historical/proposed generation")
            OwnershipJson.expect(runtime, "claimState", "unverified")
            OwnershipJson.nullValue(runtime, "bridgeReceipt")
            val words = OwnershipJson.array(root, "argv")
            ownershipRequire(words.isNotEmpty() && words.size <= limits.maximumArgvWords, "argv word count exceeds bounds")
            val argv = words.map { OwnershipJson.string(it, "argv word", 65_536, empty = true) }
            ownershipRequire(argv.first().isNotEmpty(), "argv executable is empty")
            val env = OwnershipJson.obj(root, "environment")
            ownershipRequire(env.size <= limits.maximumEnvironmentEntries, "environment count exceeds bounds")
            ownershipRequire(env.keys.all { it in PUBLIC_BUILD_ENVIRONMENT_KEYS },
                "environment name is outside the public build allowlist")
            val environment = env.mapValues { (_, value) ->
                OwnershipJson.string(value, "environment value", 65_536, empty = true)
            }
            val inputs = files(root, "inputFiles", limits)
            val outputs = files(root, "outputFiles", limits)
            val source = root["source"]
            if (source != JsonNull) {
                val value = source as? JsonObject ?: ownershipFail("source must be null or an object")
                OwnershipJson.exact(value, setOf("path", "sha256", "kind"), "source")
                val path = OwnershipJson.path(OwnershipJson.text(value, "path"), setOf("source", "generated", "external"))
                val sha = OwnershipJson.sha(OwnershipJson.text(value, "sha256"))
                val kind = OwnershipJson.text(value, "kind")
                ownershipRequire(kind in setOf("source", "generated"), "unsupported source kind")
                ownershipRequire(inputs.any { it.path == path && it.sha256 == sha && it.kind == kind },
                    "source lacks its exact input-file claim")
            }
            if (role in setOf("source-compile", "generator-compile")) {
                ownershipRequire(source != JsonNull && phase == "compile", "compile role lacks a source or compile phase")
            }
            val responses = OwnershipJson.array(root, "responseFiles")
            ownershipRequire(responses.size <= limits.maximumResponseFiles, "response-file count exceeds bounds")
            responses.forEachIndexed { ordinal, element ->
                val response = element as? JsonObject ?: ownershipFail("response file must be an object")
                OwnershipJson.exact(response, setOf("ordinal", "path", "bytes", "sha256", "bytesHex"), "response file")
                ownershipRequire(OwnershipJson.number(response, "ordinal") == ordinal.toLong(), "response-file order differs")
                val path = OwnershipJson.path(OwnershipJson.text(response, "path"), ROOTS)
                val count = OwnershipJson.number(response, "bytes", 0, (limits.maximumRecordBytes / 2).toLong())
                val sha = OwnershipJson.sha(OwnershipJson.text(response, "sha256"))
                val hex = OwnershipJson.text(response, "bytesHex", limits.maximumRecordBytes, empty = true)
                ownershipRequire(hex.length.toLong() == count * 2 && hex.all { it in '0'..'9' || it in 'a'..'f' },
                    "response bytes/hex length or encoding differs")
                val raw = ByteArray(count.toInt()) { i -> hex.substring(i * 2, i * 2 + 2).toInt(16).toByte() }
                ownershipRequire(OracleArtifacts.sha256(raw) == sha && inputs.any {
                    it.path == path && it.bytes == count && it.sha256 == sha && it.kind == "response"
                }, "response bytes lack their exact input binding")
            }
            OwnershipJson.number(root, "exitCode", 0, 255)
            val completion = OwnershipJson.obj(root, "completion")
            OwnershipJson.exact(completion, setOf("state", "collectorReceipt", "closureComplete"), "completion")
            OwnershipJson.expect(completion, "state", "not-authenticated")
            OwnershipJson.nullValue(completion, "collectorReceipt")
            OwnershipJson.falseValue(completion, "closureComplete")
            val authority = OwnershipJson.obj(root, "authority")
            OwnershipJson.exact(authority, AUTHORITY, "authority")
            AUTHORITY.forEach { OwnershipJson.falseValue(authority, it) }
            val encoded = OracleJson.canonicalBytes(root,
                OwnershipJson.limits(limits.maximumRecordBytes, limits.maximumRecordNodes))
            val candidate = OwnershipJson.domainSha("gcc-source-build-ownership-action-candidate-v1", encoded)
            // This descriptor has no semantic owner/join authority, even for source-compile.
            val compileCandidate = if (role == "source-compile")
                OwnershipJson.domainSha("gcc-source-build-ownership-compile-candidate-v1", encoded) else null
            GccSourceBuildOwnershipActionReceipt(phase, role, target, cwd, image, argv, environment,
                inputs, outputs, candidate, compileCandidate, encoded)
        }

        private fun files(root: JsonObject, field: String, limits: GccSourceBuildOwnershipObservationLimits): List<GccSourceBuildFileClaim> {
            val rows = OwnershipJson.array(root, field)
            ownershipRequire(rows.size <= limits.maximumFileClaims, "file-claim count exceeds bounds")
            val result = rows.map { element ->
                val row = element as? JsonObject ?: ownershipFail("file claim must be an object")
                OwnershipJson.exact(row, setOf("path", "bytes", "sha256", "kind"), "file claim")
                val kind = OwnershipJson.text(row, "kind").also { ownershipRequire(it in KINDS, "unsupported file kind") }
                GccSourceBuildFileClaim(OwnershipJson.path(OwnershipJson.text(row, "path"), ROOTS),
                    OwnershipJson.number(row, "bytes"), OwnershipJson.sha(OwnershipJson.text(row, "sha256")), kind)
            }
            ownershipRequire(result.map { it.path }.distinct().size == result.size,
                "duplicate path versions require a future versioned input relation")
            return result
        }
    }
}
