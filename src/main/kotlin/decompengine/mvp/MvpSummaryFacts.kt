package decompengine.mvp

import decompengine.project.ReconstructionProfiles
import decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
import java.util.Collections

/** Reserved capacity for a complete bounded report over producer facts when private detail refuses. */
internal const val MVP_SUMMARY_FACTS_BYTES = 16_384L
internal const val MVP_SUMMARY_DETAILS_PATH = "evidence/summary-details.md"

/** A commitment computed only after the producer writes the completely redacted detail artifact. */
internal data class MvpSummaryDetailsFact(val sha256: String) {
    init {
        require(sha256.length == 64 && sha256.all { it in "0123456789abcdef" }) {
            "invalid report detail commitment"
        }
    }
}

internal fun requireMvpSummaryCapacity(maximumBytes: Long) {
    require(maximumBytes in MVP_SUMMARY_FACTS_BYTES..MAXIMUM_REPAIR_PROJECTION_BYTES) {
        "MVP reporting requires at least 16384 projection bytes"
    }
}

internal enum class MvpSummaryArtifact(val label: String, val publicRelativePath: String?) {
    INPUT("Input ELF", null),
    RAW("Raw Ghidra export", ".work/ghidra_decompiled.c"),
    SOURCE("Reconstructed C", "decompile/decompiled.c"),
    DIFF("Approved patch", "evidence/approved.patch"),
    PATCHED_SOURCE("Patched C", "patched_c/patched.c"),
    BINARY("Patched binary", "patched_binary/patched_binary"),
    FINDING("Sanitizer finding", "evidence/cwe-787-sanitizer.txt"),
    RECONSTRUCTION_REQUEST("Reconstruction request", "evidence/reconstruction-request.md"),
    RECONSTRUCTION_RESPONSE("Reconstruction response", "evidence/reconstruction-response.md"),
    RECONSTRUCTION_EXECUTION("Reconstruction agent execution", "evidence/$RECONSTRUCTION_AGENT_EVIDENCE"),
    RECONSTRUCTION_ASSESSMENT("Reconstruction agent assessment", "evidence/$RECONSTRUCTION_AGENT_ASSESSMENT"),
    PATCH_REQUEST("Patch request", "evidence/patch-request.md"),
    PATCH_RESPONSE("Patch response", "evidence/patch-response.md"),
    PATCH_EXECUTION("Patch agent execution", "evidence/$PATCH_AGENT_EVIDENCE"),
    PATCH_ASSESSMENT("Patch agent assessment", "evidence/$PATCH_AGENT_ASSESSMENT"),
}

/** Hashes must be computed by the report producer over the retained file, never supplied by a peer. */
internal data class MvpSummaryArtifactFact(
    val artifact: MvpSummaryArtifact,
    val sha256: String?,
    val publicPath: Boolean,
) {
    init {
        require(sha256 == null || sha256.length == 64 && sha256.all { it in "0123456789abcdef" }) {
            "invalid public artifact commitment"
        }
        require(!publicPath || sha256 != null && artifact.publicRelativePath != null)
    }
}

internal enum class MvpSummaryResult { PASS, NON_RELEASE, FAIL, UNAVAILABLE }

internal enum class MvpSummaryPhase(val label: String) {
    INSPECT("inspect"), RECONSTRUCT("reconstruct"), COMPILE("compile"), REPRODUCE("reproduce"),
    PATCH("patch"), VERIFY("verify"), WITHHELD("withheld phase label");

    companion object {
        fun recognize(value: String): MvpSummaryPhase = entries.firstOrNull { it != WITHHELD && it.label == value } ?: WITHHELD
    }
}

internal enum class MvpSummaryCheck(val label: String) {
    ORIGINAL("original behavior observation"), RECONSTRUCTION("meaningful standalone reconstruction"),
    RECONSTRUCTED_BUILD("reconstructed sanitizer build"), REPRODUCTION("CWE-787 reproduction"),
    APPROVAL("source patch approval"), PATCHED_BUILD("patched sanitizer build"),
    SECURITY("sanitizer security validation"), RELEASE_BUILD("hardened release build"),
    HARDENING("binary hardening inspection"), BEHAVIOR("behavior validation"), WITHHELD("withheld check label");

    companion object {
        fun recognize(value: String): MvpSummaryCheck = entries.firstOrNull { it != WITHHELD && it.label == value } ?: WITHHELD
    }
}

internal enum class MvpSummaryApproval(val label: String) {
    NOT_REQUESTED("not requested"), REJECTED("rejected interactively"),
    AUTOMATED("approved by --yes automation"), INTERACTIVE("approved interactively"), WITHHELD("withheld or unavailable");

    companion object {
        fun recognize(value: String): MvpSummaryApproval = entries.firstOrNull { it != WITHHELD && it.label == value } ?: WITHHELD
    }
}

/** Only compiled built-in descriptors can appear as public profile facts. */
internal enum class MvpSummaryProfile(val id: String) {
    MAKE("generated-c-make-v1"), NINJA("generated-c-ninja-v1");

    private val descriptor get() = ReconstructionProfiles.named(id)
    val sha256: String get() = descriptor.sha256

    companion object {
        fun recognize(id: String, sha256: String): MvpSummaryProfile? =
            entries.firstOrNull { it.id == id && it.sha256 == sha256 }
    }
}

internal data class MvpSummaryPhaseFact(val phase: MvpSummaryPhase, val status: EvidenceStatus)
internal data class MvpSummaryCheckFact(val check: MvpSummaryCheck, val status: EvidenceStatus)

internal data class MvpSummarySourceFact(val line: Int, val column: Int?) {
    init { require(line > 0 && (column == null || column >= 0)) }

    companion object {
        fun recognize(value: String?): MvpSummarySourceFact? {
            if (value == null || value.length > 64) return null
            val match = Regex("decompiled\\.c:([1-9][0-9]{0,9})(?::([0-9]{1,10}))?").matchEntire(value) ?: return null
            val line = match.groupValues[1].toIntOrNull() ?: return null
            val column = match.groupValues[2].takeIf(String::isNotEmpty)?.toIntOrNull()
            if (match.groupValues[2].isNotEmpty() && column == null) return null
            return MvpSummarySourceFact(line, column)
        }
    }
}

/**
 * A display-only report of validated producer facts, like typed public progress records.
 * No environment, exception, prose, diff, arbitrary path or caller-supplied label is retained.
 * Coincidences between private values and these already public facts do not rewrite the facts.
 * This display projection does not validate a candidate or authorize publication or execution.
 */
internal class MvpSummaryFacts private constructor(
    val result: MvpSummaryResult,
    val profile: MvpSummaryProfile?,
    val approval: MvpSummaryApproval,
    val failureRecorded: Boolean,
    val diffProduced: Boolean,
    val finalBinaryPresent: Boolean,
    val source: MvpSummarySourceFact?,
    val details: MvpSummaryDetailsFact?,
    artifacts: Collection<MvpSummaryArtifactFact>,
    phases: Collection<MvpSummaryPhaseFact>,
    checks: Collection<MvpSummaryCheckFact>,
) {
    val artifacts: List<MvpSummaryArtifactFact> = Collections.unmodifiableList(
        snapshot(artifacts, MvpSummaryArtifact.entries.size).sortedBy { it.artifact.ordinal },
    )
    val phases = snapshot(phases, 32)
    val checks = snapshot(checks, 32)

    init {
        require(this.artifacts.map { it.artifact }.toSet() == MvpSummaryArtifact.entries.toSet()) {
            "public report must retain every artifact slot exactly once"
        }
        require(this.artifacts.size == MvpSummaryArtifact.entries.size)
    }

    fun render(maximumBytes: Long): String {
        requireMvpSummaryCapacity(maximumBytes)
        val document = MvpArtifactText(MVP_SUMMARY_FACTS_BYTES)
        with(document) {
            append("# MVP Patch Summary\n\n- Result: ").append(result.name)
            append(if (details == null) "\n- Report detail: withheld; only validated workflow facts are shown."
                else "\n- Report detail: redacted details retained; see the committed artifact below.")
            append("\n- Failure phase and reason: ")
            if (!failureRecorded && result != MvpSummaryResult.FAIL) append("none") else {
                append(phases.lastOrNull { it.status == EvidenceStatus.FAIL }?.phase?.label ?: "unavailable")
                append(if (details == null) "; private failure detail withheld or unavailable"
                    else "; reason retained in the redacted report details")
            }
            append("\n- Approval decision: ").append(approval.label)
            append("\n- Execution isolation: private detail withheld; consult retained evidence")
            append("\n- Agent harness: private detail withheld\n- Reconstruction profile: ")
            if (profile == null) append("withheld or unavailable") else {
                append("`").append(profile.id).append("` (`").appendSha256(profile.sha256).append("`)")
            }
            append("\n- Verified final binary: ")
            append(if (result == MvpSummaryResult.PASS && finalBinaryPresent) "present; see artifact table" else "not published")
            append("\n\n## Executed Phases\n\n| Phase | Status | Evidence |\n|---|---|---|\n")
            phases.forEach { append("| ").append(it.phase.label).append(" | ").append(it.status.name)
                .append(if (details == null) " | detail withheld |\n" else " | see retained report details |\n") }
            if (phases.isEmpty()) append("| unavailable | NOT_RUN | no phase facts recorded |\n")
            append("\n## Artifact Hashes\n\n| Artifact | Path | SHA-256 |\n|---|---|---|\n")
            artifacts.forEach { fact ->
                append("| ").append(fact.artifact.label).append(" | ")
                if (fact.sha256 == null) append("unavailable | unavailable |\n") else {
                    if (fact.publicPath) append("`").append(requireNotNull(fact.artifact.publicRelativePath)).append("`") else append("withheld")
                    append(" | `").appendSha256(fact.sha256).append("` |\n")
                }
            }
            if (details != null) {
                append("| Redacted report details | `").append(MVP_SUMMARY_DETAILS_PATH)
                    .append("` | `").appendSha256(details.sha256).append("` |\n")
            }
            append("\n## CWE-787 Evidence and Source Mapping\n\n")
            if (source == null) append("Source mapping withheld or unavailable.") else {
                append("Observed source mapping: `decompile/decompiled.c:").append(source.line.toString())
                source.column?.let { append(":").append(it.toString()) }
                append("`.")
            }
            append(" Sanitizer evidence availability and its safe retained link are in the artifact table. Reproduction and security outcomes are recorded separately below.")
            append("\n\n## Approved Source Change\n\nProposed diff: ").append(if (diffProduced) "produced; body withheld" else "not recorded")
            append(if (details == null) ". Explanation and private change detail withheld."
                else ". Explanation is retained in the redacted report details; the diff body is retained in the patch artifact when available.")
            append(" Approval is recorded above; retained patch availability and commitment are in the artifact table.")
            append("\n\n## Build and Validation Results\n\n| Check | Status | Evidence |\n|---|---|---|\n")
            checks.forEach { append("| ").append(it.check.label).append(" | ").append(it.status.name)
                .append(if (details == null) " | detail withheld |\n" else " | see retained report details |\n") }
            if (checks.isEmpty()) append("| unavailable | NOT_RUN | no verification facts recorded |\n")
            append("\n## Output Paths\n\nSafe producer-owned paths are in the artifact table; other paths are withheld. Logs: `logs/`; retained evidence: `evidence/`.")
            append("\n\n## Residual Risks\n\n")
            append(if (details == null) "Detailed text was withheld because a complete report could not be safely rendered. "
                else "The full report could not be safely rendered; available redacted detail is retained separately. ")
            append("Validation covers retained observations; unobserved inputs and broader semantic equivalence remain unproven. Artifact commitments identify retained evidence. This report does not change source, receipts or publication decisions.\n")
        }
        return document.build()
    }

    companion object {
        fun capture(
            result: String,
            failureRecorded: Boolean,
            finalBinaryPresent: Boolean,
            artifacts: Collection<MvpSummaryArtifactFact>,
            evidence: MvpRunEvidence,
            details: MvpSummaryDetailsFact? = null,
        ): MvpSummaryFacts {
            val artifactCopy = snapshot(artifacts, MvpSummaryArtifact.entries.size)
            val phaseCopy = snapshot(evidence.phases.values, 32).map { MvpSummaryPhaseFact(MvpSummaryPhase.recognize(it.name), it.status) }
            val checkCopy = snapshot(evidence.verification, 32).map { MvpSummaryCheckFact(MvpSummaryCheck.recognize(it.name), it.status) }
            val publicResult = MvpSummaryResult.entries.firstOrNull { it != MvpSummaryResult.UNAVAILABLE && it.name == result } ?: MvpSummaryResult.UNAVAILABLE
            return MvpSummaryFacts(publicResult, MvpSummaryProfile.recognize(evidence.profileId, evidence.profileSha256),
                MvpSummaryApproval.recognize(evidence.approvalDecision), failureRecorded, !evidence.patchDiff.isNullOrEmpty(),
                finalBinaryPresent && artifactCopy.any { it.artifact == MvpSummaryArtifact.BINARY && it.sha256 != null },
                evidence.findingSourceLocation.takeIf { artifactCopy.any { it.artifact == MvpSummaryArtifact.FINDING && it.sha256 != null } }
                    .let { MvpSummarySourceFact.recognize(it) }, details, artifactCopy, phaseCopy, checkCopy)
        }

        private fun <T> snapshot(values: Collection<T>, maximum: Int): List<T> {
            require(values.size in 0..maximum) { "public report fact count exceeds its limit" }
            val copy = ArrayList<T>()
            for (value in values) {
                require(copy.size < maximum) { "public report fact count exceeds its limit" }
                copy += value
            }
            return Collections.unmodifiableList(copy)
        }
    }
}
