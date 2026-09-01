package decompengine.oracle.behavior

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateInspection
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorNativeSandboxPolicyV2OperationJournalException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/** The only two states this deliberately incomplete journal can represent. */
enum class LlvmBehaviorNativeSandboxPolicyV2OperationPhase(val wireName: String) {
    POLICY_DRAFT_BOUND("policy-draft-bound"),
    CLOSED_WITHOUT_START("closed-without-start"),
}

/**
 * One descriptor-locked, append-only policy-draft operation.
 *
 * [close] releases locks only. [closeWithoutStart] is the sole state mutation exposed by this
 * checkpoint, and is idempotent. This surface cannot represent preparation, START, execution,
 * observation, scoring, or release authority.
 */
sealed interface LlvmBehaviorNativeSandboxPolicyV2OperationJournalOwner : AutoCloseable {
    val authority: String
    val operationId: String
    val requestSha256: String
    val bindingSha256: String
    val latestTransitionSha256: String
    val phase: LlvmBehaviorNativeSandboxPolicyV2OperationPhase

    val policyAuthority: String
    val policySchemaVersion: Int
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

    val journalRootPathSha256: String
    val policyPathSha256: String
    val helperPathSha256: String
    val checksumPathSha256: String
    val helperSourcePathSha256: String
    val helperBuildRecordPathSha256: String

    val acpRole: String
    val acpCandidateContribution: String
    val acpCandidateProvenanceAccess: String
    val acpCandidateAdmissionOwner: String
    val acpCandidateLiveExecutionOwner: String
    val acpReferenceSubjectAdmission: String
    val candidateAcpSessionProvenance: String
    val candidateAcpChangeProvenance: String
    val candidateAcpBuildProvenance: String
    val candidateAcpArtifactProvenance: String
    val acpOracleAuthority: Boolean
    val acpReferenceAuthoringAuthority: Boolean
    val acpPolicyAuthoringAuthority: Boolean
    val acpValidationAuthority: Boolean
    val acpObservationAuthoringAuthority: Boolean
    val acpStartAuthority: Boolean
    val acpContainmentAuthority: Boolean
    val acpTerminalAbsenceAuthority: Boolean
    val acpScoringAuthority: Boolean
    val acpCertificationAuthority: Boolean
    val acpReleaseAuthority: Boolean

    val runtimeInputsBound: Boolean
    val candidateLineageBound: Boolean
    val prepared: Boolean
    val liveRuntimeIdentityVerified: Boolean
    val liveContainmentVerified: Boolean
    val executionClaimed: Boolean
    val referencePinned: Boolean
    val candidateStarted: Boolean
    val startAuthorized: Boolean
    val containmentAuthority: Boolean
    val terminalAbsenceAuthority: Boolean
    val observationAuthoringAuthority: Boolean
    val scoringAuthority: Boolean
    val certificationAuthority: Boolean
    val releaseEligible: Boolean

    /** Returns a defensive copy of the exact canonical binding persisted by this owner. */
    val canonicalBindingBytes: ByteArray

    fun closeWithoutStart(): LlvmBehaviorNativeSandboxPolicyV2OperationPhase

    override fun close()
}

/**
 * Opens one deterministic operation from six raw, already-absolute and normalized paths.
 *
 * No validation object, digest, parsed document, operation identifier, runner, or ACP receipt can
 * be supplied by the caller. The sealed v2 verifier is always invoked inside this boundary.
 */
object LlvmBehaviorNativeSandboxPolicyV2OperationJournal {
    fun open(
        journalRootPath: Path,
        policyPath: Path,
        helperPath: Path,
        checksumPath: Path,
        helperSourcePath: Path,
        helperBuildRecordPath: Path,
    ): LlvmBehaviorNativeSandboxPolicyV2OperationJournalOwner = translateJournalFailures(
        "open native sandbox policy v2 operation journal",
    ) {
        BoundOwner(
            journalRootPath,
            policyPath,
            helperPath,
            checksumPath,
            helperSourcePath,
            helperBuildRecordPath,
        )
    }

    /* The only implementation constructor repeats the same six raw paths and no claimed facts. */
    private class BoundOwner(
        private val journalRootPath: Path,
        private val policyPath: Path,
        private val helperPath: Path,
        private val checksumPath: Path,
        private val helperSourcePath: Path,
        private val helperBuildRecordPath: Path,
    ) : LlvmBehaviorNativeSandboxPolicyV2OperationJournalOwner {
        private val opened = openBoundOperation(
            journalRootPath,
            policyPath,
            helperPath,
            checksumPath,
            helperSourcePath,
            helperBuildRecordPath,
        )
        private var currentHistory = opened.history
        private var closed = false
        private var poisoned = false

        override val authority: String
            get() = JOURNAL_AUTHORITY
        override val operationId: String
            get() = opened.binding.operationId
        override val requestSha256: String
            get() = opened.binding.requestSha256
        override val bindingSha256: String
            get() = opened.binding.bindingSha256
        override val latestTransitionSha256: String
            @Synchronized get() = currentHistory.latest.transitionSha256
        override val phase: LlvmBehaviorNativeSandboxPolicyV2OperationPhase
            @Synchronized get() = currentHistory.latest.phase

        override val policyAuthority: String
            get() = opened.binding.policy.authority
        override val policySchemaVersion: Int
            get() = opened.binding.policy.schemaVersion
        override val helperPolicyDraftValidated: Boolean
            get() = opened.binding.policy.helperPolicyDraftValidated
        override val policySha256: String
            get() = opened.binding.policy.policySha256
        override val schemaSha256: String
            get() = opened.binding.policy.schemaSha256
        override val helperBytes: Long
            get() = opened.binding.policy.helperBytes
        override val helperSha256: String
            get() = opened.binding.policy.helperSha256
        override val checksumSha256: String
            get() = opened.binding.policy.checksumSha256
        override val sourceSha256: String
            get() = opened.binding.policy.sourceSha256
        override val buildRecordSha256: String
            get() = opened.binding.policy.buildRecordSha256
        override val protocol: String
            get() = opened.binding.policy.protocol
        override val helperContainerPath: String
            get() = opened.binding.policy.helperContainerPath

        override val journalRootPathSha256: String
            get() = opened.binding.paths.journalRoot
        override val policyPathSha256: String
            get() = opened.binding.paths.policy
        override val helperPathSha256: String
            get() = opened.binding.paths.helper
        override val checksumPathSha256: String
            get() = opened.binding.paths.checksum
        override val helperSourcePathSha256: String
            get() = opened.binding.paths.helperSource
        override val helperBuildRecordPathSha256: String
            get() = opened.binding.paths.helperBuildRecord

        override val acpRole: String
            get() = ACP_ROLE
        override val acpCandidateContribution: String
            get() = ACP_CANDIDATE_CONTRIBUTION
        override val acpCandidateProvenanceAccess: String
            get() = ACP_CANDIDATE_PROVENANCE_ACCESS
        override val acpCandidateAdmissionOwner: String
            get() = ACP_CANDIDATE_ADMISSION_OWNER
        override val acpCandidateLiveExecutionOwner: String
            get() = ACP_CANDIDATE_LIVE_EXECUTION_OWNER
        override val acpReferenceSubjectAdmission: String
            get() = ACP_REFERENCE_SUBJECT_ADMISSION
        override val candidateAcpSessionProvenance: String
            get() = CANDIDATE_ACP_SESSION_PROVENANCE
        override val candidateAcpChangeProvenance: String
            get() = CANDIDATE_ACP_CHANGE_PROVENANCE
        override val candidateAcpBuildProvenance: String
            get() = CANDIDATE_ACP_BUILD_PROVENANCE
        override val candidateAcpArtifactProvenance: String
            get() = CANDIDATE_ACP_ARTIFACT_PROVENANCE
        override val acpOracleAuthority: Boolean
            get() = false
        override val acpReferenceAuthoringAuthority: Boolean
            get() = false
        override val acpPolicyAuthoringAuthority: Boolean
            get() = false
        override val acpValidationAuthority: Boolean
            get() = false
        override val acpObservationAuthoringAuthority: Boolean
            get() = false
        override val acpStartAuthority: Boolean
            get() = false
        override val acpContainmentAuthority: Boolean
            get() = false
        override val acpTerminalAbsenceAuthority: Boolean
            get() = false
        override val acpScoringAuthority: Boolean
            get() = false
        override val acpCertificationAuthority: Boolean
            get() = false
        override val acpReleaseAuthority: Boolean
            get() = false

        override val runtimeInputsBound: Boolean
            get() = false
        override val candidateLineageBound: Boolean
            get() = false
        override val prepared: Boolean
            get() = false
        override val liveRuntimeIdentityVerified: Boolean
            get() = false
        override val liveContainmentVerified: Boolean
            get() = false
        override val executionClaimed: Boolean
            get() = false
        override val referencePinned: Boolean
            get() = false
        override val candidateStarted: Boolean
            get() = false
        override val startAuthorized: Boolean
            get() = false
        override val containmentAuthority: Boolean
            get() = false
        override val terminalAbsenceAuthority: Boolean
            get() = false
        override val observationAuthoringAuthority: Boolean
            get() = false
        override val scoringAuthority: Boolean
            get() = false
        override val certificationAuthority: Boolean
            get() = false
        override val releaseEligible: Boolean
            get() = false

        override val canonicalBindingBytes: ByteArray
            get() = opened.binding.canonicalBytes()

        @Synchronized
        override fun closeWithoutStart(): LlvmBehaviorNativeSandboxPolicyV2OperationPhase =
            translateJournalFailures("close native sandbox policy v2 operation without START") {
                checkOpen()
                try {
                    requireSamePolicyValidation(opened.binding.policy, verifyPolicyPaths())
                    currentHistory = opened.journal.closeWithoutStart()
                    requireSamePolicyValidation(opened.binding.policy, verifyPolicyPaths())
                    currentHistory.phase
                } catch (failure: Throwable) {
                    poisoned = true
                    throw failure
                }
            }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            var failure: Throwable? = null
            runCatching { opened.journal.close() }.exceptionOrNull()?.let { failure = it }
            runCatching { opened.authority.close() }.exceptionOrNull()?.let { closeFailure ->
                failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
            }
            failure?.let { throw it }
        }

        private fun verifyPolicyPaths(): PolicyValidationFacts = PolicyValidationFacts.from(
            LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(
                policyPath,
                helperPath,
                checksumPath,
                helperSourcePath,
                helperBuildRecordPath,
            ),
        )

        private fun checkOpen() {
            check(!closed) { "native sandbox policy v2 operation journal owner is closed" }
            check(!poisoned) { "native sandbox policy v2 operation journal owner is poisoned" }
        }
    }
}

private data class PolicyValidationFacts(
    val authority: String,
    val schemaVersion: Int,
    val helperPolicyDraftValidated: Boolean,
    val policySha256: String,
    val schemaSha256: String,
    val helperBytes: Long,
    val helperSha256: String,
    val checksumSha256: String,
    val sourceSha256: String,
    val buildRecordSha256: String,
    val protocol: String,
    val helperContainerPath: String,
    val referencePinned: Boolean,
    val candidateStarted: Boolean,
    val startAuthorized: Boolean,
    val scoringAuthority: Boolean,
    val releaseEligible: Boolean,
) {
    init {
        if (
            authority != POLICY_AUTHORITY || schemaVersion != POLICY_SCHEMA_VERSION ||
            !helperPolicyDraftValidated || helperBytes <= 0L ||
            listOf(
                policySha256,
                schemaSha256,
                helperSha256,
                checksumSha256,
                sourceSha256,
                buildRecordSha256,
            ).any { !it.matches(SHA256) } ||
            protocol != HELPER_PROTOCOL || helperContainerPath != HELPER_CONTAINER_PATH ||
            referencePinned || candidateStarted || startAuthorized || scoringAuthority || releaseEligible
        ) journalFail("native sandbox policy v2 validation facts are invalid")
    }

    fun json(): JsonObject = JsonObject(
        mapOf(
            "authority" to JsonPrimitive(authority),
            "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
            "candidateStarted" to JsonPrimitive(candidateStarted),
            "checksumSha256" to JsonPrimitive(checksumSha256),
            "helperBytes" to JsonPrimitive(helperBytes),
            "helperContainerPath" to JsonPrimitive(helperContainerPath),
            "helperPolicyDraftValidated" to JsonPrimitive(helperPolicyDraftValidated),
            "helperSha256" to JsonPrimitive(helperSha256),
            "policySha256" to JsonPrimitive(policySha256),
            "protocol" to JsonPrimitive(protocol),
            "referencePinned" to JsonPrimitive(referencePinned),
            "releaseEligible" to JsonPrimitive(releaseEligible),
            "schemaSha256" to JsonPrimitive(schemaSha256),
            "schemaVersion" to JsonPrimitive(schemaVersion),
            "scoringAuthority" to JsonPrimitive(scoringAuthority),
            "sourceSha256" to JsonPrimitive(sourceSha256),
            "startAuthorized" to JsonPrimitive(startAuthorized),
        ),
    )

    companion object {
        fun from(validation: LlvmBehaviorNativeSandboxPolicyV2Validation) = PolicyValidationFacts(
            validation.authority,
            validation.schemaVersion,
            validation.helperPolicyDraftValidated,
            validation.policySha256,
            validation.schemaSha256,
            validation.helperBytes,
            validation.helperSha256,
            validation.checksumSha256,
            validation.sourceSha256,
            validation.buildRecordSha256,
            validation.protocol,
            validation.helperContainerPath,
            validation.referencePinned,
            validation.candidateStarted,
            validation.startAuthorized,
            validation.scoringAuthority,
            validation.releaseEligible,
        )

        fun parse(root: JsonObject): PolicyValidationFacts {
            root.requireExactKeys(POLICY_FACT_FIELDS, "native sandbox policy v2 validation facts")
            return PolicyValidationFacts(
                root.requiredString("authority"),
                root.requiredInt("schemaVersion"),
                root.requiredBoolean("helperPolicyDraftValidated"),
                root.requiredString("policySha256"),
                root.requiredString("schemaSha256"),
                root.requiredLong("helperBytes"),
                root.requiredString("helperSha256"),
                root.requiredString("checksumSha256"),
                root.requiredString("sourceSha256"),
                root.requiredString("buildRecordSha256"),
                root.requiredString("protocol"),
                root.requiredString("helperContainerPath"),
                root.requiredBoolean("referencePinned"),
                root.requiredBoolean("candidateStarted"),
                root.requiredBoolean("startAuthorized"),
                root.requiredBoolean("scoringAuthority"),
                root.requiredBoolean("releaseEligible"),
            )
        }
    }
}

private data class PathCommitments(
    val journalRoot: String,
    val policy: String,
    val helper: String,
    val checksum: String,
    val helperSource: String,
    val helperBuildRecord: String,
) {
    init {
        if (listOf(journalRoot, policy, helper, checksum, helperSource, helperBuildRecord).any {
                !it.matches(SHA256)
            }
        ) journalFail("native sandbox policy v2 path commitment is invalid")
    }

    fun json(): JsonObject = JsonObject(
        mapOf(
            "checksumPathSha256" to JsonPrimitive(checksum),
            "helperBuildRecordPathSha256" to JsonPrimitive(helperBuildRecord),
            "helperPathSha256" to JsonPrimitive(helper),
            "helperSourcePathSha256" to JsonPrimitive(helperSource),
            "journalRootPathSha256" to JsonPrimitive(journalRoot),
            "policyPathSha256" to JsonPrimitive(policy),
        ),
    )

    companion object {
        fun create(
            journalRoot: Path,
            policy: Path,
            helper: Path,
            checksum: Path,
            helperSource: Path,
            helperBuildRecord: Path,
        ) = PathCommitments(
            pathCommitment(journalRoot),
            pathCommitment(policy),
            pathCommitment(helper),
            pathCommitment(checksum),
            pathCommitment(helperSource),
            pathCommitment(helperBuildRecord),
        )

        fun parse(root: JsonObject): PathCommitments {
            root.requireExactKeys(PATH_COMMITMENT_FIELDS, "native sandbox policy v2 path commitments")
            return PathCommitments(
                root.requiredString("journalRootPathSha256"),
                root.requiredString("policyPathSha256"),
                root.requiredString("helperPathSha256"),
                root.requiredString("checksumPathSha256"),
                root.requiredString("helperSourcePathSha256"),
                root.requiredString("helperBuildRecordPathSha256"),
            )
        }
    }
}

private class OperationBinding private constructor(
    val schemaVersion: Int,
    val provider: String,
    val authority: String,
    val operationId: String,
    val requestSha256: String,
    val journalDirectoryName: String,
    val policy: PolicyValidationFacts,
    val paths: PathCommitments,
    val bindingSha256: String,
) {
    init {
        if (
            schemaVersion != BINDING_SCHEMA_VERSION || provider != JOURNAL_PROVIDER ||
            authority != JOURNAL_AUTHORITY || !operationId.matches(SHA256) ||
            operationId != requestSha256 || !bindingSha256.matches(SHA256) ||
            journalDirectoryName != operationDirectoryName(operationId)
        ) journalFail("native sandbox policy v2 operation binding has invalid identities")
        if (requestSha256 != sha256(canonicalRequestBytes())) {
            journalFail("native sandbox policy v2 operation request hash is invalid")
        }
        if (bindingSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            journalFail("native sandbox policy v2 operation binding self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = canonical(
        JsonObject(
            buildMap {
                put("acpRequirements", STATIC_ACP_REQUIREMENTS)
                if (includeSelfHash) put("bindingSha256", JsonPrimitive(bindingSha256))
                put("claims", JOURNAL_CLAIMS)
                put("authority", JsonPrimitive(authority))
                put("journalDirectoryName", JsonPrimitive(journalDirectoryName))
                put("operationId", JsonPrimitive(operationId))
                put("pathCommitments", paths.json())
                put("policyValidation", policy.json())
                put("provider", JsonPrimitive(provider))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("schemaVersion", JsonPrimitive(schemaVersion))
            },
        ),
    )

    private fun canonicalRequestBytes(): ByteArray = canonical(requestDocument(policy, paths))

    companion object {
        fun create(policy: PolicyValidationFacts, paths: PathCommitments): OperationBinding {
            val requestSha256 = sha256(canonical(requestDocument(policy, paths)))
            val journalDirectoryName = operationDirectoryName(requestSha256)
            val withoutSelf = bindingDocument(
                policy,
                paths,
                requestSha256,
                journalDirectoryName,
                bindingSha256 = null,
            )
            return OperationBinding(
                BINDING_SCHEMA_VERSION,
                JOURNAL_PROVIDER,
                JOURNAL_AUTHORITY,
                requestSha256,
                requestSha256,
                journalDirectoryName,
                policy,
                paths,
                sha256(canonical(withoutSelf)),
            )
        }

        fun parseCanonical(bytes: ByteArray): OperationBinding = translateJournalFailures(
            "parse native sandbox policy v2 operation binding",
        ) {
            val root = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) as? JsonObject
                ?: journalFail("native sandbox policy v2 operation binding must be an object")
            root.requireExactKeys(BINDING_FIELDS, "native sandbox policy v2 operation binding")
            val acp = root.requiredObject("acpRequirements")
            if (acp != STATIC_ACP_REQUIREMENTS) {
                journalFail("native sandbox policy v2 operation binding has different ACP requirements")
            }
            val claims = root.requiredObject("claims")
            if (claims != JOURNAL_CLAIMS) {
                journalFail("native sandbox policy v2 operation binding has non-false journal claims")
            }
            OperationBinding(
                root.requiredInt("schemaVersion"),
                root.requiredString("provider"),
                root.requiredString("authority"),
                root.requiredString("operationId"),
                root.requiredString("requestSha256"),
                root.requiredString("journalDirectoryName"),
                PolicyValidationFacts.parse(root.requiredObject("policyValidation")),
                PathCommitments.parse(root.requiredObject("pathCommitments")),
                root.requiredString("bindingSha256"),
            )
        }

        private fun requestDocument(
            policy: PolicyValidationFacts,
            paths: PathCommitments,
        ): JsonObject = JsonObject(
            mapOf(
                "acpRequirements" to STATIC_ACP_REQUIREMENTS,
                "authority" to JsonPrimitive(JOURNAL_AUTHORITY),
                "claims" to JOURNAL_CLAIMS,
                "pathCommitments" to paths.json(),
                "policyValidation" to policy.json(),
                "provider" to JsonPrimitive(REQUEST_PROVIDER),
                "schemaVersion" to JsonPrimitive(REQUEST_SCHEMA_VERSION),
            ),
        )

        private fun bindingDocument(
            policy: PolicyValidationFacts,
            paths: PathCommitments,
            requestSha256: String,
            journalDirectoryName: String,
            bindingSha256: String?,
        ): JsonObject = JsonObject(
            buildMap {
                put("acpRequirements", STATIC_ACP_REQUIREMENTS)
                bindingSha256?.let { put("bindingSha256", JsonPrimitive(it)) }
                put("claims", JOURNAL_CLAIMS)
                put("authority", JsonPrimitive(JOURNAL_AUTHORITY))
                put("journalDirectoryName", JsonPrimitive(journalDirectoryName))
                put("operationId", JsonPrimitive(requestSha256))
                put("pathCommitments", paths.json())
                put("policyValidation", policy.json())
                put("provider", JsonPrimitive(JOURNAL_PROVIDER))
                put("requestSha256", JsonPrimitive(requestSha256))
                put("schemaVersion", JsonPrimitive(BINDING_SCHEMA_VERSION))
            },
        )
    }
}

private class OperationTransition private constructor(
    val schemaVersion: Int,
    val provider: String,
    val authority: String,
    val operationId: String,
    val bindingSha256: String,
    val sequence: Int,
    val phase: LlvmBehaviorNativeSandboxPolicyV2OperationPhase,
    val previousTransitionSha256: String,
    val transitionSha256: String,
) {
    val fileName: String
        get() = transitionFileName(sequence)

    init {
        if (
            schemaVersion != TRANSITION_SCHEMA_VERSION || provider != JOURNAL_PROVIDER ||
            authority != JOURNAL_AUTHORITY || !operationId.matches(SHA256) ||
            !bindingSha256.matches(SHA256) || !previousTransitionSha256.matches(SHA256) ||
            !transitionSha256.matches(SHA256)
        ) journalFail("native sandbox policy v2 operation transition has invalid identities")
        when (phase) {
            LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND -> if (
                sequence != 0 || previousTransitionSha256 != ZERO_SHA256
            ) journalFail("policy-draft-bound transition has an invalid chain position")

            LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START -> if (
                sequence != 1 || previousTransitionSha256 == ZERO_SHA256
            ) journalFail("closed-without-start transition has an invalid chain position")
        }
        if (transitionSha256 != sha256(canonicalBytes(includeSelfHash = false))) {
            journalFail("native sandbox policy v2 operation transition self hash is invalid")
        }
    }

    fun canonicalBytes(): ByteArray = canonicalBytes(includeSelfHash = true)

    private fun canonicalBytes(includeSelfHash: Boolean): ByteArray = canonical(
        JsonObject(
            buildMap {
                put("authority", JsonPrimitive(authority))
                put("bindingSha256", JsonPrimitive(bindingSha256))
                put("claims", JOURNAL_CLAIMS)
                put("operationId", JsonPrimitive(operationId))
                put("phase", JsonPrimitive(phase.wireName))
                put("previousTransitionSha256", JsonPrimitive(previousTransitionSha256))
                put("provider", JsonPrimitive(provider))
                put("schemaVersion", JsonPrimitive(schemaVersion))
                put("sequence", JsonPrimitive(sequence))
                if (includeSelfHash) put("transitionSha256", JsonPrimitive(transitionSha256))
            },
        ),
    )

    companion object {
        fun initial(binding: OperationBinding): OperationTransition = create(
            binding,
            0,
            LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND,
            ZERO_SHA256,
        )

        fun closed(binding: OperationBinding, previous: OperationTransition): OperationTransition = create(
            binding,
            1,
            LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START,
            previous.transitionSha256,
        )

        private fun create(
            binding: OperationBinding,
            sequence: Int,
            phase: LlvmBehaviorNativeSandboxPolicyV2OperationPhase,
            previousTransitionSha256: String,
        ): OperationTransition {
            val provisional = transitionDocument(
                binding.operationId,
                binding.bindingSha256,
                sequence,
                phase,
                previousTransitionSha256,
                transitionSha256 = null,
            )
            return OperationTransition(
                TRANSITION_SCHEMA_VERSION,
                JOURNAL_PROVIDER,
                JOURNAL_AUTHORITY,
                binding.operationId,
                binding.bindingSha256,
                sequence,
                phase,
                previousTransitionSha256,
                sha256(canonical(provisional)),
            )
        }

        fun parseCanonical(bytes: ByteArray): OperationTransition = translateJournalFailures(
            "parse native sandbox policy v2 operation transition",
        ) {
            val root = OracleJson.parseCanonical(bytes, JOURNAL_JSON_LIMITS) as? JsonObject
                ?: journalFail("native sandbox policy v2 operation transition must be an object")
            root.requireExactKeys(TRANSITION_FIELDS, "native sandbox policy v2 operation transition")
            if (root.requiredObject("claims") != JOURNAL_CLAIMS) {
                journalFail("native sandbox policy v2 operation transition has non-false journal claims")
            }
            val phaseName = root.requiredString("phase")
            val phase = LlvmBehaviorNativeSandboxPolicyV2OperationPhase.entries.singleOrNull {
                it.wireName == phaseName
            } ?: journalFail("native sandbox policy v2 operation transition has an unknown phase")
            OperationTransition(
                root.requiredInt("schemaVersion"),
                root.requiredString("provider"),
                root.requiredString("authority"),
                root.requiredString("operationId"),
                root.requiredString("bindingSha256"),
                root.requiredInt("sequence"),
                phase,
                root.requiredString("previousTransitionSha256"),
                root.requiredString("transitionSha256"),
            )
        }

        private fun transitionDocument(
            operationId: String,
            bindingSha256: String,
            sequence: Int,
            phase: LlvmBehaviorNativeSandboxPolicyV2OperationPhase,
            previousTransitionSha256: String,
            transitionSha256: String?,
        ): JsonObject = JsonObject(
            buildMap {
                put("authority", JsonPrimitive(JOURNAL_AUTHORITY))
                put("bindingSha256", JsonPrimitive(bindingSha256))
                put("claims", JOURNAL_CLAIMS)
                put("operationId", JsonPrimitive(operationId))
                put("phase", JsonPrimitive(phase.wireName))
                put("previousTransitionSha256", JsonPrimitive(previousTransitionSha256))
                put("provider", JsonPrimitive(JOURNAL_PROVIDER))
                put("schemaVersion", JsonPrimitive(TRANSITION_SCHEMA_VERSION))
                put("sequence", JsonPrimitive(sequence))
                transitionSha256?.let { put("transitionSha256", JsonPrimitive(it)) }
            },
        )
    }
}

private data class OperationHistory(
    val binding: OperationBinding,
    val transitions: List<OperationTransition>,
) {
    val latest: OperationTransition
        get() = transitions.lastOrNull()
            ?: journalFail("native sandbox policy v2 operation has no durable phase")
    val phase: LlvmBehaviorNativeSandboxPolicyV2OperationPhase
        get() = latest.phase

    companion object {
        fun validatePrefix(
            expectedBinding: OperationBinding,
            actualBinding: OperationBinding,
            transitions: List<OperationTransition>,
        ): OperationHistory {
            if (!actualBinding.canonicalBytes().contentEquals(expectedBinding.canonicalBytes())) {
                journalFail("native sandbox policy v2 operation journal is bound to a different request")
            }
            if (transitions.size > 2) {
                journalFail("native sandbox policy v2 operation journal has too many transitions")
            }
            val expected = buildList {
                if (transitions.isNotEmpty()) add(OperationTransition.initial(expectedBinding))
                if (transitions.size == 2) add(OperationTransition.closed(expectedBinding, first()))
            }
            transitions.zip(expected).forEach { (actual, wanted) ->
                if (!actual.canonicalBytes().contentEquals(wanted.canonicalBytes())) {
                    journalFail("native sandbox policy v2 operation transition chain is invalid")
                }
            }
            return OperationHistory(actualBinding, transitions.toList())
        }
    }
}

private data class OpenedOperation(
    val authority: JournalAuthority,
    val journal: DescriptorOperationJournal,
    val binding: OperationBinding,
    val history: OperationHistory,
)

private fun openBoundOperation(
    journalRootPath: Path,
    policyPath: Path,
    helperPath: Path,
    checksumPath: Path,
    helperSourcePath: Path,
    helperBuildRecordPath: Path,
): OpenedOperation {
    val inputs = listOf(
        "journal root" to journalRootPath,
        "native sandbox policy" to policyPath,
        "native sandbox helper" to helperPath,
        "native sandbox helper checksum" to checksumPath,
        "native sandbox helper source" to helperSourcePath,
        "native sandbox helper build record" to helperBuildRecordPath,
    )
    inputs.forEach { (label, path) -> requireExactRawPath(path, label) }
    val initialPolicy = PolicyValidationFacts.from(
        LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(
            policyPath,
            helperPath,
            checksumPath,
            helperSourcePath,
            helperBuildRecordPath,
        ),
    )
    listOf(policyPath, helperPath, checksumPath, helperSourcePath, helperBuildRecordPath).forEach { input ->
        if (input.startsWith(journalRootPath)) {
            journalFail("native sandbox policy v2 input must be outside the journal root")
        }
    }
    val binding = OperationBinding.create(
        initialPolicy,
        PathCommitments.create(
            journalRootPath,
            policyPath,
            helperPath,
            checksumPath,
            helperSourcePath,
            helperBuildRecordPath,
        ),
    )
    val authority = JournalAuthority.open(journalRootPath)
    var journal: DescriptorOperationJournal? = null
    try {
        journal = authority.openOperation(binding)
        journal.completeExactPendingPublication()
        val beforePublication = PolicyValidationFacts.from(
            LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(
                policyPath,
                helperPath,
                checksumPath,
                helperSourcePath,
                helperBuildRecordPath,
            ),
        )
        requireSamePolicyValidation(initialPolicy, beforePublication)
        val history = journal.initialize()
        val afterPublication = PolicyValidationFacts.from(
            LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(
                policyPath,
                helperPath,
                checksumPath,
                helperSourcePath,
                helperBuildRecordPath,
            ),
        )
        requireSamePolicyValidation(initialPolicy, afterPublication)
        return OpenedOperation(authority, journal, binding, history)
    } catch (failure: Throwable) {
        journal?.let { opened ->
            runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
        }
        runCatching { authority.close() }.exceptionOrNull()?.let(failure::addSuppressed)
        throw failure
    }
}

private class JournalAuthority private constructor(
    private val path: Path,
    private val parentPath: Path,
    private val parent: LinuxDescriptor,
    private val rootName: String,
    private val root: LinuxDescriptor,
) : AutoCloseable {
    private var activeOperations = 0
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun openOperation(binding: OperationBinding): DescriptorOperationJournal {
        checkOpen()
        requireRootBindingOrPoison()
        var child: LinuxDescriptor? = null
        var childLocked = false
        try {
            var created = false
            LinuxFilesystemSyscalls.openPathAtOrNull(root.fd, binding.journalDirectoryName).use { existing ->
                if (existing == null) {
                    try {
                        LinuxFilesystemSyscalls.createDirectory(
                            root.fd,
                            binding.journalDirectoryName,
                            OWNER_DIRECTORY_MODE,
                        )
                        created = true
                    } catch (failure: LinuxSyscallException) {
                        if (failure.errno != LinuxFilesystemSyscalls.EEXIST) throw failure
                    }
                }
            }
            child = LinuxFilesystemSyscalls.openDirectoryAt(root.fd, binding.journalDirectoryName)
            if (created) LinuxFilesystemSyscalls.chmod(child, OWNER_DIRECTORY_MODE)
            val childIdentity = LinuxFilesystemSyscalls.identity(child.fd)
            requireManagedChildDirectory(childIdentity, root.identity, "native sandbox policy v2 journal directory")
            requireNamedChild(binding.journalDirectoryName, childIdentity)
            LinuxFilesystemSyscalls.synchronize(child)
            LinuxFilesystemSyscalls.synchronize(root)
            if (!LinuxFilesystemSyscalls.tryExclusiveLock(child)) {
                journalFail("native sandbox policy v2 operation journal is already locked")
            }
            childLocked = true
            requireRootBindingOrPoison()
            requireNamedChild(binding.journalDirectoryName, childIdentity)
            activeOperations = Math.addExact(activeOperations, 1)
            return DescriptorOperationJournal(binding, this, child)
        } catch (failure: Throwable) {
            if (childLocked) {
                child?.let { locked ->
                    runCatching { LinuxFilesystemSyscalls.unlock(locked) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                }
            }
            child?.let { opened ->
                runCatching { opened.close() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            throw failure
        }
    }

    @Synchronized
    fun requireBound(name: String, expected: LinuxFileIdentity) {
        checkOpen()
        requireRootBindingOrPoison()
        requireNamedChild(name, expected)
    }

    @Synchronized
    fun releaseOperation() {
        check(activeOperations > 0) { "native sandbox policy v2 authority has no active operation" }
        activeOperations -= 1
    }

    private fun requireRootBinding() {
        requireTrustedParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
        if (!Files.isSameFile(parentPath, LinuxFilesystemSyscalls.descriptorPath(parent))) {
            journalFail("native sandbox policy v2 journal parent pathname changed")
        }
        val currentRoot = LinuxFilesystemSyscalls.identity(root.fd)
        requirePinnedManagedDirectory(currentRoot, root.identity, "native sandbox policy v2 journal root")
        val selected = try {
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, rootName)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT) {
                journalFail("native sandbox policy v2 journal root was detached")
            }
            throw failure
        }
        selected.use {
            if (!sameDirectory(LinuxFilesystemSyscalls.identity(selected.fd), currentRoot)) {
                journalFail("native sandbox policy v2 journal root changed identity")
            }
        }
        if (!Files.isSameFile(path, LinuxFilesystemSyscalls.descriptorPath(root))) {
            journalFail("native sandbox policy v2 journal root pathname changed")
        }
    }

    private fun requireRootBindingOrPoison() {
        try {
            requireRootBinding()
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun requireNamedChild(name: String, expected: LinuxFileIdentity) {
        val selected = try {
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, name)
        } catch (failure: LinuxSyscallException) {
            if (failure.errno == LinuxFilesystemSyscalls.ENOENT) {
                journalFail("native sandbox policy v2 operation journal was detached")
            }
            throw failure
        }
        selected.use {
            val current = LinuxFilesystemSyscalls.identity(selected.fd)
            requireManagedChildDirectory(current, root.identity, "native sandbox policy v2 journal directory")
            if (!sameDirectory(current, expected)) {
                journalFail("native sandbox policy v2 operation journal changed identity")
            }
        }
    }

    private fun checkOpen() {
        check(!closed) { "native sandbox policy v2 journal authority is closed" }
        check(!poisoned) { "native sandbox policy v2 journal authority is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        check(activeOperations == 0) { "native sandbox policy v2 authority still owns an operation" }
        closed = true
        var failure: Throwable? = null
        runCatching { LinuxFilesystemSyscalls.unlock(root) }.exceptionOrNull()?.let { failure = it }
        runCatching { root.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        runCatching { parent.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        failure?.let { throw it }
    }

    companion object {
        fun open(path: Path): JournalAuthority {
            if (
                !Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) || path.toRealPath() != path ||
                path.parent == null
            ) journalFail("native sandbox policy v2 journal root must be a canonical non-root directory")
            LinuxFilesystemSyscalls.requireSupported(path)
            val parentPath = path.parent
            if (parentPath.toRealPath() != parentPath) {
                journalFail("native sandbox policy v2 journal root parent must be canonical")
            }
            val parent = LinuxFilesystemSyscalls.openRoot(parentPath)
            val root = try {
                LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, path.fileName.toString())
            } catch (failure: Throwable) {
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
            var locked = false
            try {
                requireTrustedParent(LinuxFilesystemSyscalls.identity(parent.fd), parent.identity)
                requirePinnedManagedDirectory(
                    LinuxFilesystemSyscalls.identity(root.fd),
                    root.identity,
                    "native sandbox policy v2 journal root",
                )
                if (!LinuxFilesystemSyscalls.tryExclusiveLock(root)) {
                    journalFail("native sandbox policy v2 journal root is already locked")
                }
                locked = true
                LinuxFilesystemSyscalls.synchronize(root)
                LinuxFilesystemSyscalls.synchronize(parent)
                return JournalAuthority(path, parentPath, parent, path.fileName.toString(), root).also {
                    it.requireRootBinding()
                }
            } catch (failure: Throwable) {
                if (locked) {
                    runCatching { LinuxFilesystemSyscalls.unlock(root) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                }
                runCatching { root.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                runCatching { parent.close() }.exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}

private class DescriptorOperationJournal(
    private val expectedBinding: OperationBinding,
    private val authority: JournalAuthority,
    private val directory: LinuxDescriptor,
) : AutoCloseable {
    private var closed = false
    private var poisoned = false

    @Synchronized
    fun initialize(): OperationHistory = boundOperation {
        var current = loadPrefix()
        if (current == null) {
            DescriptorBoundAtomicStateFile.publishNoReplace(
                directory,
                BINDING_FILE,
                expectedBinding.canonicalBytes(),
                MAXIMUM_RECORD_BYTES,
            )
            current = loadPrefix()
                ?: journalFail("native sandbox policy v2 binding publication disappeared")
        }
        if (current.transitions.isEmpty()) {
            val initial = OperationTransition.initial(expectedBinding)
            DescriptorBoundAtomicStateFile.publishNoReplace(
                directory,
                initial.fileName,
                initial.canonicalBytes(),
                MAXIMUM_RECORD_BYTES,
            )
            current = loadPrefix()
                ?: journalFail("native sandbox policy v2 initial transition disappeared")
        }
        requirePhased(current)
    }

    @Synchronized
    fun closeWithoutStart(): OperationHistory = boundOperation {
        val current = requirePhased(
            loadPrefix() ?: journalFail("native sandbox policy v2 operation journal is empty"),
        )
        if (current.phase == LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START) {
            return@boundOperation current
        }
        val closedTransition = OperationTransition.closed(expectedBinding, current.latest)
        DescriptorBoundAtomicStateFile.publishNoReplace(
            directory,
            closedTransition.fileName,
            closedTransition.canonicalBytes(),
            MAXIMUM_RECORD_BYTES,
        )
        requirePhased(
            loadPrefix() ?: journalFail("native sandbox policy v2 close transition disappeared"),
        ).also { completed ->
            if (completed.phase != LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START) {
                journalFail("native sandbox policy v2 operation did not close without START")
            }
        }
    }

    /** Completes at most one exact, parsed immutable publication and touches no other resource. */
    @Synchronized
    fun completeExactPendingPublication() = boundOperation {
        val names = entryNames()
        val pendingNames = names.filter(::isAtomicStateName)
        if (pendingNames.size > 1) {
            journalFail("native sandbox policy v2 operation journal has multiple pending publications")
        }
        val pendingName = pendingNames.singleOrNull()
        if (pendingName == null) {
            loadPrefix()
            // Covers a process death after rename and before the final directory fsync.
            LinuxFilesystemSyscalls.synchronize(directory)
            return@boundOperation
        }
        val targetName = when (pendingName) {
            DescriptorBoundAtomicStateFile.temporaryName(BINDING_FILE) -> BINDING_FILE
            DescriptorBoundAtomicStateFile.temporaryName(transitionFileName(0)) -> transitionFileName(0)
            DescriptorBoundAtomicStateFile.temporaryName(transitionFileName(1)) -> transitionFileName(1)
            else -> journalFail("native sandbox policy v2 operation journal has an unknown pending publication")
        }
        if (targetName in names) {
            journalFail("native sandbox policy v2 operation journal has a target and its pending publication")
        }
        when (targetName) {
            BINDING_FILE -> {
                if (names != listOf(pendingName)) {
                    journalFail("pending native sandbox policy v2 binding has unbound residue")
                }
                inspectRequired(pendingName).use { pending ->
                    val actual = OperationBinding.parseCanonical(pending.bytes)
                    requireExactBinding(actual)
                    completePending(BINDING_FILE, pending)
                }
            }

            transitionFileName(0) -> {
                val prefix = loadPrefix(allowedAtomicTarget = targetName)
                    ?: journalFail("pending policy-draft-bound transition has no binding")
                if (prefix.transitions.isNotEmpty()) {
                    journalFail("pending policy-draft-bound transition has an invalid prefix")
                }
                val expected = OperationTransition.initial(expectedBinding)
                inspectRequired(pendingName).use { pending ->
                    requireExactTransition(pending, expected)
                    completePending(targetName, pending)
                }
            }

            transitionFileName(1) -> {
                val prefix = loadPrefix(allowedAtomicTarget = targetName)
                    ?: journalFail("pending closed-without-start transition has no binding")
                if (
                    prefix.transitions.size != 1 ||
                    prefix.phase != LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND
                ) journalFail("pending closed-without-start transition has an invalid prefix")
                val expected = OperationTransition.closed(expectedBinding, prefix.latest)
                inspectRequired(pendingName).use { pending ->
                    requireExactTransition(pending, expected)
                    completePending(targetName, pending)
                }
            }
        }
        loadPrefix() ?: journalFail("native sandbox policy v2 cold completion lost its journal")
    }

    private fun completePending(targetName: String, pending: DescriptorBoundStateInspection) {
        DescriptorBoundAtomicStateFile.completeExistingTemporaryNoReplace(
            directory,
            targetName,
            pending,
            MAXIMUM_RECORD_BYTES,
        )
    }

    private fun requireExactTransition(
        inspection: DescriptorBoundStateInspection,
        expected: OperationTransition,
    ) {
        val actual = OperationTransition.parseCanonical(inspection.bytes)
        if (
            actual.fileName != expected.fileName ||
            !actual.canonicalBytes().contentEquals(expected.canonicalBytes())
        ) journalFail("pending native sandbox policy v2 transition is not the exact next record")
    }

    private fun loadPrefix(allowedAtomicTarget: String? = null): OperationHistory? {
        val names = entryNames()
        if (names.isEmpty()) return null
        val allowedAtomicName = allowedAtomicTarget?.let(DescriptorBoundAtomicStateFile::temporaryName)
        val atomicNames = names.filter(::isAtomicStateName)
        if (atomicNames.any { it != allowedAtomicName }) {
            journalFail("native sandbox policy v2 operation journal requires exact cold recovery")
        }
        if (names.any { name ->
                name != BINDING_FILE && !name.matches(TRANSITION_FILE_NAME) && name != allowedAtomicName
            }
        ) journalFail("native sandbox policy v2 operation journal contains an unowned entry")
        val bindingSnapshot = DescriptorBoundAtomicStateFile.readOrNull(
            directory,
            BINDING_FILE,
            MAXIMUM_RECORD_BYTES,
        ) ?: journalFail("native sandbox policy v2 operation journal is missing its binding")
        val actualBinding = OperationBinding.parseCanonical(bindingSnapshot.bytes)
        requireExactBinding(actualBinding)
        val transitionNames = names.filter(TRANSITION_FILE_NAME::matches).sorted()
        val transitions = transitionNames.map { name ->
            val snapshot = DescriptorBoundAtomicStateFile.readOrNull(
                directory,
                name,
                MAXIMUM_RECORD_BYTES,
            ) ?: journalFail("native sandbox policy v2 operation transition disappeared")
            OperationTransition.parseCanonical(snapshot.bytes).also { transition ->
                if (transition.fileName != name) {
                    journalFail("native sandbox policy v2 operation transition occupies the wrong name")
                }
            }
        }
        return OperationHistory.validatePrefix(expectedBinding, actualBinding, transitions)
    }

    private fun entryNames(): List<String> {
        val names = LinuxFilesystemSyscalls.directoryEntryNames(directory, MAXIMUM_JOURNAL_ENTRIES + 1).sorted()
        if (names.size > MAXIMUM_JOURNAL_ENTRIES) {
            journalFail("native sandbox policy v2 operation journal exceeds its entry bound")
        }
        return names
    }

    private fun inspectRequired(name: String): DescriptorBoundStateInspection =
        DescriptorBoundAtomicStateFile.inspectOrNull(directory, name, MAXIMUM_RECORD_BYTES)
            ?: journalFail("native sandbox policy v2 operation journal entry disappeared: $name")

    private fun requireExactBinding(actual: OperationBinding) {
        if (!actual.canonicalBytes().contentEquals(expectedBinding.canonicalBytes())) {
            journalFail("native sandbox policy v2 operation journal is bound to a different request")
        }
        authority.requireBound(expectedBinding.journalDirectoryName, directory.identity)
    }

    private fun requirePhased(history: OperationHistory): OperationHistory {
        if (history.transitions.isEmpty()) {
            journalFail("native sandbox policy v2 operation journal is missing its initial phase")
        }
        return history
    }

    private inline fun <T> boundOperation(action: () -> T): T {
        checkOpen()
        return try {
            authority.requireBound(expectedBinding.journalDirectoryName, directory.identity)
            val result = action()
            authority.requireBound(expectedBinding.journalDirectoryName, directory.identity)
            result
        } catch (failure: Throwable) {
            poisoned = true
            throw failure
        }
    }

    private fun checkOpen() {
        check(!closed) { "native sandbox policy v2 operation journal is closed" }
        check(!poisoned) { "native sandbox policy v2 operation journal is poisoned" }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        runCatching { LinuxFilesystemSyscalls.unlock(directory) }.exceptionOrNull()?.let { failure = it }
        runCatching { directory.close() }.exceptionOrNull()?.let { closeFailure ->
            failure = failure?.also { it.addSuppressed(closeFailure) } ?: closeFailure
        }
        runCatching { authority.releaseOperation() }.exceptionOrNull()?.let { releaseFailure ->
            failure = failure?.also { it.addSuppressed(releaseFailure) } ?: releaseFailure
        }
        failure?.let { throw it }
    }
}

private fun requireExactRawPath(path: Path, label: String) {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null) {
        journalFail("$label path must already be absolute and normalized")
    }
}

private fun requireSamePolicyValidation(
    expected: PolicyValidationFacts,
    actual: PolicyValidationFacts,
) {
    if (actual != expected) {
        journalFail("native sandbox policy v2 validation facts changed during journal operation")
    }
}

private fun pathCommitment(path: Path): String = sha256(path.toString().toByteArray(Charsets.UTF_8))

private fun operationDirectoryName(operationId: String): String {
    if (!operationId.matches(SHA256)) journalFail("native sandbox policy v2 operation id is invalid")
    return ".llvm-behavior-native-sandbox-policy-v2-operation-$operationId"
}

private fun transitionFileName(sequence: Int): String = when (sequence) {
    0 -> "transition-0000.json"
    1 -> "transition-0001.json"
    else -> journalFail("native sandbox policy v2 transition sequence is out of range")
}

private fun isAtomicStateName(name: String): Boolean = name.startsWith('.') && name.endsWith(".atomic")

private fun requirePinnedManagedDirectory(
    actual: LinuxFileIdentity,
    expected: LinuxFileIdentity,
    label: String,
) {
    val uid = currentUid()
    if (
        !sameDirectory(actual, expected) || actual.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) journalFail("$label is not a pinned owner-only directory")
}

private fun requireManagedChildDirectory(
    actual: LinuxFileIdentity,
    parent: LinuxFileIdentity,
    label: String,
) {
    val uid = currentUid()
    if (
        !actual.isDirectory || actual.isRegularFile || actual.isSymbolicLink ||
        actual.mountId != parent.mountId || actual.uid != uid || parent.uid != uid ||
        actual.mode.permissions != OWNER_DIRECTORY_MODE
    ) journalFail("$label is not an owner-only directory on its authorized filesystem")
}

private fun requireTrustedParent(actual: LinuxFileIdentity, expected: LinuxFileIdentity) {
    val uid = currentUid()
    if (
        !sameDirectory(actual, expected) || actual.uid !in setOf(0, uid) ||
        actual.mode.permissions and GROUP_OR_OTHER_WRITE_MODE != 0
    ) journalFail("native sandbox policy v2 journal root has an untrusted parent")
}

private fun sameDirectory(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
    first.key == second.key && first.mountId == second.mountId &&
        first.uid == second.uid && first.gid == second.gid &&
        first.isDirectory && second.isDirectory &&
        !first.isRegularFile && !second.isRegularFile &&
        !first.isSymbolicLink && !second.isSymbolicLink

private fun currentUid(): Int = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun canonical(document: JsonObject): ByteArray = OracleJson.canonicalBytes(document, JOURNAL_JSON_LIMITS)

private fun sha256(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) journalFail("$label fields are not exact")
}

private fun JsonObject.requiredObject(name: String): JsonObject = this[name] as? JsonObject
    ?: journalFail("native sandbox policy v2 journal field is not an object: $name")

private fun JsonObject.requiredString(name: String): String {
    val value = this[name] as? JsonPrimitive
        ?: journalFail("native sandbox policy v2 journal field is not a string: $name")
    if (!value.isString) journalFail("native sandbox policy v2 journal field is not a string: $name")
    return value.content
}

private fun JsonObject.requiredBoolean(name: String): Boolean {
    val value = this[name] as? JsonPrimitive
        ?: journalFail("native sandbox policy v2 journal field is not a boolean: $name")
    if (value.isString) journalFail("native sandbox policy v2 journal field is not a boolean: $name")
    return value.booleanOrNull
        ?: journalFail("native sandbox policy v2 journal field is not a boolean: $name")
}

private fun JsonObject.requiredLong(name: String): Long {
    val value = this[name] as? JsonPrimitive
        ?: journalFail("native sandbox policy v2 journal field is not an integer: $name")
    if (value.isString) journalFail("native sandbox policy v2 journal field is not an integer: $name")
    return value.longOrNull
        ?: journalFail("native sandbox policy v2 journal field is not an integer: $name")
}

private fun JsonObject.requiredInt(name: String): Int {
    val value = this[name] as? JsonPrimitive
        ?: journalFail("native sandbox policy v2 journal field is not an integer: $name")
    if (value.isString) journalFail("native sandbox policy v2 journal field is not an integer: $name")
    return value.intOrNull
        ?: journalFail("native sandbox policy v2 journal field is not an integer: $name")
}

private inline fun <T> translateJournalFailures(label: String, action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorNativeSandboxPolicyV2OperationJournalException) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorNativeSandboxPolicyV2OperationJournalException(
        "$label failed: ${failure.message ?: failure::class.java.simpleName}",
        failure,
    )
}

private fun journalFail(message: String): Nothing =
    throw LlvmBehaviorNativeSandboxPolicyV2OperationJournalException(message)

private const val BINDING_SCHEMA_VERSION = 1
private const val REQUEST_SCHEMA_VERSION = 1
private const val TRANSITION_SCHEMA_VERSION = 1
private const val JOURNAL_PROVIDER = "kotlin-llvm-behavior-native-sandbox-policy-v2-operation-journal-v1"
private const val REQUEST_PROVIDER = "kotlin-llvm-behavior-native-sandbox-policy-v2-operation-request-v1"
private const val JOURNAL_AUTHORITY =
    "non-authoritative-llvm-behavior-native-sandbox-policy-v2-operation-journal-v1"
private const val POLICY_AUTHORITY =
    "non-authoritative-native-sandbox-helper-policy-v2-draft-validation"
private const val POLICY_SCHEMA_VERSION = 2
private const val HELPER_PROTOCOL = "decomp-llvm-behavior-helper-v2"
private const val HELPER_CONTAINER_PATH = "/decomp-llvm-behavior-helper"

private const val ACP_ROLE = "first-class-candidate-producer-operator"
private const val ACP_CANDIDATE_CONTRIBUTION =
    "authenticated-session-change-build-artifact-provenance"
private const val ACP_CANDIDATE_PROVENANCE_ACCESS = "read-only-oracle-input"
private const val ACP_CANDIDATE_ADMISSION_OWNER = "kotlin-jvm-host"
private const val ACP_CANDIDATE_LIVE_EXECUTION_OWNER = "separately-reviewed-kotlin-jvm-host"
private const val ACP_REFERENCE_SUBJECT_ADMISSION = "kotlin-jvm-host-only"
private const val CANDIDATE_ACP_SESSION_PROVENANCE =
    "candidate-only-required-from-authenticated-acp-session-receipt"
private const val CANDIDATE_ACP_CHANGE_PROVENANCE =
    "candidate-only-required-from-authenticated-acp-change-receipt"
private const val CANDIDATE_ACP_BUILD_PROVENANCE =
    "candidate-only-required-from-hosted-clean-build-receipt"
private const val CANDIDATE_ACP_ARTIFACT_PROVENANCE =
    "candidate-only-required-from-kotlin-candidate-admission"

private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val GROUP_OR_OTHER_WRITE_MODE = 0x12 // 0022
private const val MAXIMUM_RECORD_BYTES = 64 * 1024
private const val MAXIMUM_JOURNAL_ENTRIES = 4
private const val BINDING_FILE = "binding.json"
private val ZERO_SHA256 = "0".repeat(64)
private val SHA256 = Regex("[0-9a-f]{64}")
private val TRANSITION_FILE_NAME = Regex("transition-000[01]\\.json")

private val JOURNAL_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_RECORD_BYTES,
    maximumCanonicalBytes = MAXIMUM_RECORD_BYTES,
    maximumDepth = 8,
    maximumNodes = 256,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 48 * 1024,
    maximumNumberCharacters = 32,
)

private val STATIC_ACP_REQUIREMENTS = JsonObject(
    mapOf(
        "candidateAcpArtifactProvenance" to JsonPrimitive(CANDIDATE_ACP_ARTIFACT_PROVENANCE),
        "candidateAcpBuildProvenance" to JsonPrimitive(CANDIDATE_ACP_BUILD_PROVENANCE),
        "candidateAcpChangeProvenance" to JsonPrimitive(CANDIDATE_ACP_CHANGE_PROVENANCE),
        "candidateAcpSessionProvenance" to JsonPrimitive(CANDIDATE_ACP_SESSION_PROVENANCE),
        "candidateAdmissionOwner" to JsonPrimitive(ACP_CANDIDATE_ADMISSION_OWNER),
        "candidateContribution" to JsonPrimitive(ACP_CANDIDATE_CONTRIBUTION),
        "candidateLiveExecutionOwner" to JsonPrimitive(ACP_CANDIDATE_LIVE_EXECUTION_OWNER),
        "candidateProvenanceAccess" to JsonPrimitive(ACP_CANDIDATE_PROVENANCE_ACCESS),
        "certificationAuthority" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "observationAuthoringAuthority" to JsonPrimitive(false),
        "oracleAuthority" to JsonPrimitive(false),
        "policyAuthoringAuthority" to JsonPrimitive(false),
        "referenceAuthoringAuthority" to JsonPrimitive(false),
        "referenceSubjectAdmission" to JsonPrimitive(ACP_REFERENCE_SUBJECT_ADMISSION),
        "releaseAuthority" to JsonPrimitive(false),
        "role" to JsonPrimitive(ACP_ROLE),
        "scoringAuthority" to JsonPrimitive(false),
        "startAuthority" to JsonPrimitive(false),
        "terminalAbsenceAuthority" to JsonPrimitive(false),
        "validationAuthority" to JsonPrimitive(false),
    ),
)

private val JOURNAL_CLAIMS = JsonObject(
    mapOf(
        "candidateLineageBound" to JsonPrimitive(false),
        "candidateStarted" to JsonPrimitive(false),
        "certificationAuthority" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "executionClaimed" to JsonPrimitive(false),
        "liveContainmentVerified" to JsonPrimitive(false),
        "liveRuntimeIdentityVerified" to JsonPrimitive(false),
        "observationAuthoringAuthority" to JsonPrimitive(false),
        "prepared" to JsonPrimitive(false),
        "referencePinned" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
        "runtimeInputsBound" to JsonPrimitive(false),
        "scoringAuthority" to JsonPrimitive(false),
        "startAuthorized" to JsonPrimitive(false),
        "terminalAbsenceAuthority" to JsonPrimitive(false),
    ),
)

private val POLICY_FACT_FIELDS = setOf(
    "authority",
    "buildRecordSha256",
    "candidateStarted",
    "checksumSha256",
    "helperBytes",
    "helperContainerPath",
    "helperPolicyDraftValidated",
    "helperSha256",
    "policySha256",
    "protocol",
    "referencePinned",
    "releaseEligible",
    "schemaSha256",
    "schemaVersion",
    "scoringAuthority",
    "sourceSha256",
    "startAuthorized",
)
private val PATH_COMMITMENT_FIELDS = setOf(
    "checksumPathSha256",
    "helperBuildRecordPathSha256",
    "helperPathSha256",
    "helperSourcePathSha256",
    "journalRootPathSha256",
    "policyPathSha256",
)
private val BINDING_FIELDS = setOf(
    "acpRequirements",
    "authority",
    "bindingSha256",
    "claims",
    "journalDirectoryName",
    "operationId",
    "pathCommitments",
    "policyValidation",
    "provider",
    "requestSha256",
    "schemaVersion",
)
private val TRANSITION_FIELDS = setOf(
    "authority",
    "bindingSha256",
    "claims",
    "operationId",
    "phase",
    "previousTransitionSha256",
    "provider",
    "schemaVersion",
    "sequence",
    "transitionSha256",
)
