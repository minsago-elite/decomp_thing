package decompengine.mvp

import java.nio.file.Path
import java.security.MessageDigest
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.writeText

internal enum class EvidenceStatus { RUNNING, PASS, FAIL, NOT_RUN }

internal data class PhaseEvidence(
    val name: String,
    var status: EvidenceStatus = EvidenceStatus.NOT_RUN,
    var detail: String = "not run",
)

internal data class VerificationEvidence(
    val name: String,
    val status: EvidenceStatus,
    val detail: String,
)

internal class MvpRunEvidence(
    private val environment: Map<String, String>,
    val harnessProvenance: String,
) {
    val phases = linkedMapOf<String, PhaseEvidence>()
    val verification = mutableListOf<VerificationEvidence>()
    var findingPath: Path? = null
    var findingSourceLocation: String? = null
    var patchDiffPath: Path? = null
    var patchDiff: String? = null
    var patchExplanation: String = "No source patch was generated before the workflow stopped."
    var approvalDecision: String = "not requested"
    var isolation: String = "not recorded"

    fun startPhase(name: String) {
        phases[name] = PhaseEvidence(name, EvidenceStatus.RUNNING, "started")
    }

    fun passPhase(name: String, detail: String) {
        phases.getOrPut(name) { PhaseEvidence(name) }.apply {
            status = EvidenceStatus.PASS
            this.detail = detail
        }
    }

    fun failPhase(name: String, detail: String) {
        phases.getOrPut(name) { PhaseEvidence(name) }.apply {
            status = EvidenceStatus.FAIL
            this.detail = detail
        }
    }

    fun check(name: String, passed: Boolean, detail: String) {
        verification += VerificationEvidence(name, if (passed) EvidenceStatus.PASS else EvidenceStatus.FAIL, detail)
    }

    fun redact(text: String): String {
        var redacted = text.replace(Regex("(?i)Bearer\\s+[A-Za-z0-9._~+/=-]+"), "Bearer [REDACTED]")
        environment.filterKeys { key ->
            val normalized = key.uppercase()
            normalized.contains("KEY") || normalized.contains("TOKEN") || normalized.contains("SECRET") ||
                normalized.contains("PASSWORD") || normalized.contains("AUTH")
        }.values.filter { it.isNotBlank() }.forEach { secret -> redacted = redacted.replace(secret, "[REDACTED]") }
        return redacted
    }
}

internal fun writeMvpSummary(
    summaryPath: Path,
    output: Path,
    input: Path,
    rawDecompilerOutput: Path,
    source: Path,
    patchedSource: Path,
    binary: Path,
    result: String,
    failure: String?,
    evidence: MvpRunEvidence,
) {
    val artifacts = linkedMapOf(
        "Input ELF" to input,
        "Raw Ghidra export" to rawDecompilerOutput,
        "Reconstructed C" to source,
        "Approved patch" to evidence.patchDiffPath,
        "Patched C" to patchedSource,
        "Patched binary" to binary,
        "Sanitizer finding" to evidence.findingPath,
        "Reconstruction request" to output.resolve("evidence/reconstruction-request.md"),
        "Reconstruction response" to output.resolve("evidence/reconstruction-response.md"),
        "Reconstruction agent execution" to output.resolve("evidence/$RECONSTRUCTION_AGENT_EVIDENCE"),
        "Patch request" to output.resolve("evidence/patch-request.md"),
        "Patch response" to output.resolve("evidence/patch-response.md"),
        "Patch agent execution" to output.resolve("evidence/$PATCH_AGENT_EVIDENCE"),
    )
    val phaseRows = evidence.phases.values.joinToString("\n") {
        "| ${it.name.escapeTable()} | ${it.status} | ${evidence.redact(it.detail).escapeTable()} |"
    }.ifBlank { "| none | NOT_RUN | workflow stopped before a phase began |" }
    val verificationRows = evidence.verification.joinToString("\n") {
        "| ${it.name.escapeTable()} | ${it.status} | ${evidence.redact(it.detail).escapeTable()} |"
    }.ifBlank { "| none | NOT_RUN | no verification completed |" }
    val artifactRows = artifacts.entries.joinToString("\n") { (name, path) ->
        if (path != null && path.exists()) {
            "| $name | `${path.relativeOrAbsolute(output)}` | `${path.sha256()}` |"
        } else {
            "| $name | unavailable | unavailable |"
        }
    }
    val sourceMapping = evidence.findingSourceLocation?.let {
        "AddressSanitizer mapped the observed out-of-bounds write to `$it` in `decompile/decompiled.c`."
    } ?: "No source location was captured before the workflow stopped."
    val approvedDiff = evidence.patchDiff?.takeIf(String::isNotBlank)?.let {
        "```diff\n${evidence.redact(it).trimEnd()}\n```"
    } ?: "No approved source diff is available."
    val normalizedFailure = evidence.redact(failure ?: "none")
    val normalizedPatch = evidence.redact(evidence.patchExplanation).toSummaryParagraph()

    summaryPath.writeText(
        """
        # MVP Patch Summary

        - Result: $result
        - Failure phase and reason: $normalizedFailure
        - Approval decision: ${evidence.redact(evidence.approvalDecision)}
        - Execution isolation: ${evidence.redact(evidence.isolation)}
        - Agent harness: `${evidence.redact(evidence.harnessProvenance)}`
        - Verified final binary: `${if (binary.exists() && result == "PASS") binary.relativeOrAbsolute(output) else "not published"}`

        ## Executed Phases

        | Phase | Status | Evidence |
        |---|---|---|
        $phaseRows

        ## Artifact Hashes

        | Artifact | Path | SHA-256 |
        |---|---|---|
        $artifactRows

        ## CWE-787 Evidence and Source Mapping

        $sourceMapping The unpatched reconstructed program is classified as CWE-787 only when its sanitizer run reports an out-of-bounds write. Exact retained output: `${evidence.findingPath?.takeIf(Path::exists)?.relativeOrAbsolute(output) ?: "unavailable"}`.

        ## Approved Source Change

        $normalizedPatch

        $approvedDiff

        ## Build and Validation Results

        | Check | Status | Evidence |
        |---|---|---|
        $verificationRows

        ## Output Paths

        - Reconstructed source: `${if (source.exists()) source.relativeOrAbsolute(output) else "unavailable"}`
        - Patched source: `${if (patchedSource.exists()) patchedSource.relativeOrAbsolute(output) else "unavailable"}`
        - Patched binary: `${if (binary.exists() && result == "PASS") binary.relativeOrAbsolute(output) else "not published"}`
        - Logs: `logs/`
        - Retained evidence: `evidence/`

        ## Residual Risks

        Validation covers the retained sanitizer reproducer and observed default behavior; it does not prove correctness for unobserved inputs. Decompiled names and source structure may differ from the original source. A final binary is published only after sanitizer, hardening, security, and behavior checks pass.
        """.trimIndent() + "\n",
    )
}

private fun Path.relativeOrAbsolute(root: Path): String =
    runCatching { root.toAbsolutePath().normalize().relativize(toAbsolutePath().normalize()).toString() }
        .getOrElse { toAbsolutePath().normalize().toString() }

private fun Path.sha256(): String =
    MessageDigest.getInstance("SHA-256").digest(readBytes()).joinToString("") { "%02x".format(it) }

private fun String.escapeTable(): String = replace("|", "\\|").replace("\n", "<br>")

private fun String.toSummaryParagraph(): String {
    val normalized = trim().replace(Regex("\\s+"), " ")
    return normalized.ifBlank { "No source patch was generated before the workflow stopped." }
}
