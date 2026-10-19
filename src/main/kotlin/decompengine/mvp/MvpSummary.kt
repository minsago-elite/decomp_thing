package decompengine.mvp

import decompengine.jobs.ProgressRedactor
import decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import kotlin.io.path.exists
import kotlin.io.path.createDirectories
import kotlin.io.path.inputStream

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
    environment: Map<String, String>,
    val harnessProvenance: String,
    val profileId: String,
    val profileSha256: String,
    val maximumProjectionBytes: Long = MAXIMUM_REPAIR_PROJECTION_BYTES,
) {
    private val artifactRedactor = MvpArtifactRedactor(environment.values, maximumProjectionBytes)
    private val diagnosticRedactor = ProgressRedactor(artifactRedactor.sensitiveValues)
    internal val logPrivacy: MvpLogPrivacy by lazy { MvpLogPrivacy(artifactRedactor) }
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

    fun redactDiagnostic(text: String): String = diagnosticRedactor.text(text)

    fun redactTableDiagnostic(text: String): String = redactDiagnostic(redactDiagnostic(text).escapeTable())

    fun redact(text: String): String = artifactRedactor.text(text)

    fun artifactText(render: MvpArtifactText.() -> Unit): String = artifactRedactor.project(render)
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
    requireMvpSummaryCapacity(evidence.maximumProjectionBytes)
    val artifacts = linkedMapOf(
        MvpSummaryArtifact.INPUT to input,
        MvpSummaryArtifact.RAW to rawDecompilerOutput,
        MvpSummaryArtifact.SOURCE to source,
        MvpSummaryArtifact.DIFF to evidence.patchDiffPath,
        MvpSummaryArtifact.PATCHED_SOURCE to patchedSource,
        MvpSummaryArtifact.BINARY to binary,
        MvpSummaryArtifact.FINDING to evidence.findingPath,
        MvpSummaryArtifact.RECONSTRUCTION_REQUEST to output.resolve("evidence/reconstruction-request.md"),
        MvpSummaryArtifact.RECONSTRUCTION_RESPONSE to output.resolve("evidence/reconstruction-response.md"),
        MvpSummaryArtifact.RECONSTRUCTION_EXECUTION to output.resolve("evidence/$RECONSTRUCTION_AGENT_EVIDENCE"),
        MvpSummaryArtifact.RECONSTRUCTION_ASSESSMENT to output.resolve("evidence/$RECONSTRUCTION_AGENT_ASSESSMENT"),
        MvpSummaryArtifact.PATCH_REQUEST to output.resolve("evidence/patch-request.md"),
        MvpSummaryArtifact.PATCH_RESPONSE to output.resolve("evidence/patch-response.md"),
        MvpSummaryArtifact.PATCH_EXECUTION to output.resolve("evidence/$PATCH_AGENT_EVIDENCE"),
        MvpSummaryArtifact.PATCH_ASSESSMENT to output.resolve("evidence/$PATCH_AGENT_ASSESSMENT"),
    )
    val artifactFacts = artifacts.map { (kind, path) ->
        if (Thread.currentThread().isInterrupted) throw InterruptedException("MVP summary interrupted")
        if (path == null || !path.exists()) MvpSummaryArtifactFact(kind, null, false) else {
            val publicPath = kind.publicRelativePath?.let { relative ->
                path.toAbsolutePath().normalize() == output.resolve(relative).toAbsolutePath().normalize()
            } == true
            MvpSummaryArtifactFact(kind, path.sha256(), publicPath)
        }
    }
    val summary = try {
        val phaseRows = evidence.artifactText {
            for (phase in evidence.phases.values) {
                append("| ").append(evidence.redactTableDiagnostic(phase.name)).append(" | ").append(phase.status.toString())
                    .append(" | ").append(evidence.redactTableDiagnostic(phase.detail)).append(" |\n")
            }
            if (evidence.phases.isEmpty()) append("| none | NOT_RUN | workflow stopped before a phase began |\n")
        }.trimEnd()
        val verificationRows = evidence.artifactText {
            for (check in evidence.verification) {
                append("| ").append(evidence.redactTableDiagnostic(check.name)).append(" | ").append(check.status.toString())
                    .append(" | ").append(evidence.redactTableDiagnostic(check.detail)).append(" |\n")
            }
            if (evidence.verification.isEmpty()) append("| none | NOT_RUN | no verification completed |\n")
        }.trimEnd()
        val sourceMapping = evidence.artifactText {
            val location = evidence.findingSourceLocation
            if (location != null) {
                append("AddressSanitizer mapped the observed out-of-bounds write to `").append(location)
                    .append("` in `decompile/decompiled.c`.")
            } else {
                append("No source location was captured before the workflow stopped.")
            }
        }
        val approvedDiff = evidence.patchDiff?.takeIf(String::isNotBlank)?.let {
            evidence.artifactText { append("```diff\n").append(evidence.redact(it).trimEnd()).append("\n```") }
        } ?: "No approved source diff is available."
        val normalizedFailure = evidence.redactDiagnostic(failure ?: "none")
        val patchPreview = evidence.redactDiagnostic(evidence.patchExplanation)
        val normalizedPatch = evidence.redactDiagnostic(patchPreview.toSummaryParagraph())

        val text = evidence.artifactText {
            append("# MVP Patch Summary\n\n- Result: ").append(result)
            append("\n- Failure phase and reason: ").append(normalizedFailure)
            append("\n- Approval decision: ").append(evidence.redactDiagnostic(evidence.approvalDecision))
            append("\n- Execution isolation: ").append(evidence.redactDiagnostic(evidence.isolation))
            append("\n- Agent harness: `").append(evidence.redactDiagnostic(evidence.harnessProvenance)).append("`")
            append("\n- Reconstruction profile: `").append(evidence.profileId).append("` (`").appendSha256(evidence.profileSha256).append("`)")
            append("\n- Verified final binary: `")
                .append(if (binary.exists() && result == "PASS") binary.relativeOrAbsolute(output) else "not published").append("`\n\n")
            append("## Executed Phases\n\n| Phase | Status | Evidence |\n|---|---|---|\n").append(phaseRows)
            append("\n\n## Artifact Hashes\n\n| Artifact | Path | SHA-256 |\n|---|---|---|\n")
            for ((index, entry) in artifacts.entries.withIndex()) {
                val (name, path) = entry
                if (index > 0) append("\n")
                val sha256 = artifactFacts[index].sha256
                append("| ").append(name.label).append(" | ")
                if (path != null && sha256 != null) {
                    append("`").append(path.relativeOrAbsolute(output)).append("` | `").appendSha256(sha256).append("` |")
                } else {
                    append("unavailable | unavailable |")
                }
            }
            append("\n\n## CWE-787 Evidence and Source Mapping\n\n").append(sourceMapping)
            append(" The unpatched reconstructed program is classified as CWE-787 only when its sanitizer run reports an out-of-bounds write. Exact retained output: `")
                .append(evidence.findingPath?.takeIf(Path::exists)?.relativeOrAbsolute(output) ?: "unavailable").append("`.\n\n")
            append("## Approved Source Change\n\n").append(normalizedPatch).append("\n\n").append(approvedDiff)
            append("\n\n## Build and Validation Results\n\n| Check | Status | Evidence |\n|---|---|---|\n").append(verificationRows)
            append("\n\n## Output Paths\n\n- Reconstructed source: `")
                .append(if (source.exists()) source.relativeOrAbsolute(output) else "unavailable").append("`")
            append("\n- Patched source: `").append(if (patchedSource.exists()) patchedSource.relativeOrAbsolute(output) else "unavailable").append("`")
            append("\n- Patched binary: `")
                .append(if (binary.exists() && result == "PASS") binary.relativeOrAbsolute(output) else "not published").append("`")
            append("\n- Logs: `logs/`\n- Retained evidence: `evidence/`\n\n## Residual Risks\n\n")
            append("Validation covers the retained sanitizer reproducer and observed default behavior; it does not prove correctness for unobserved inputs. Decompiled names and source structure may differ from the original source. A final binary is published only after sanitizer, hardening, security, and behavior checks pass.\n")
        }
        encodeMvpArtifactUtf8(text)
    } catch (_: MvpPatchException) {
        val details = retainMvpSummaryDetails(output, failure, evidence)
        MvpSummaryFacts.capture(result, failure != null, binary.exists() && result == "PASS", artifactFacts, evidence, details)
            .render(evidence.maximumProjectionBytes).let(::encodeMvpArtifactUtf8)
    }
    Files.write(summaryPath, summary)
}

/** No public hash fields enter this projection, so private prose can be retained independently. */
private fun retainMvpSummaryDetails(output: Path, failure: String?, evidence: MvpRunEvidence): MvpSummaryDetailsFact? {
    val detail = try {
        evidence.artifactText {
            append("# Redacted MVP Report Details\n\n")
            append("The result, public commitments, retained diff and publication status are recorded in SUMMARY.md.\n\n")
            append("- Failure phase and reason: ").append(evidence.redactDiagnostic(failure ?: "none"))
            append("\n- Source-change explanation: ").append(evidence.redactDiagnostic(evidence.patchExplanation))
            append("\n\n## Executed Phase Details\n\n| Phase | Status | Evidence |\n|---|---|---|\n")
            var count = 0
            for (phase in evidence.phases.values) {
                require(count++ < 32)
                append("| ").append(evidence.redactTableDiagnostic(MvpSummaryPhase.recognize(phase.name).label)).append(" | ").append(phase.status.name)
                    .append(" | ").append(evidence.redactTableDiagnostic(phase.detail)).append(" |\n")
            }
            append("\n## Separate Validation Details\n\n| Check | Status | Evidence |\n|---|---|---|\n")
            count = 0
            for (check in evidence.verification) {
                require(count++ < 32)
                append("| ").append(evidence.redactTableDiagnostic(MvpSummaryCheck.recognize(check.name).label)).append(" | ").append(check.status.name)
                    .append(" | ").append(evidence.redactTableDiagnostic(check.detail)).append(" |\n")
            }
        }
    } catch (_: MvpPatchException) {
        return null
    }
    val bytes = try {
        encodeMvpArtifactUtf8(detail)
    } catch (_: MvpPatchException) {
        return null
    }
    if (Thread.currentThread().isInterrupted) throw InterruptedException("MVP report detail interrupted")
    val path = output.resolve(MVP_SUMMARY_DETAILS_PATH)
    path.parent.createDirectories()
    Files.write(path, bytes, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING,
        StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS)
    return MvpSummaryDetailsFact(path.sha256())
}

private fun Path.relativeOrAbsolute(root: Path): String =
    runCatching { root.toAbsolutePath().normalize().relativize(toAbsolutePath().normalize()).toString() }
        .getOrElse { toAbsolutePath().normalize().toString() }

private fun Path.sha256(): String {
    val digest = MessageDigest.getInstance("SHA-256")
    inputStream().use { input ->
        val buffer = ByteArray(8192)
        while (true) {
            val count = input.read(buffer)
            if (count < 0) break
            if (count > 0) digest.update(buffer, 0, count)
        }
    }
    return digest.digest().joinToString("") { "%02x".format(it) }
}

private fun String.escapeTable(): String = replace("|", "\\|").replace("\n", "<br>")

private fun String.toSummaryParagraph(): String {
    val normalized = trim().replace(Regex("\\s+"), " ")
    return normalized.ifBlank { "No source patch was generated before the workflow stopped." }
}
