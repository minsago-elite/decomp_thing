package decompengine.oracle.behavior

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorCandidateExecutionAdmissionException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/**
 * Immutable host-owned binding for a candidate execution which has deliberately not started.
 *
 * This receipt authenticates the candidate and the reviewed execution declaration. It is not an
 * execution result, behavior evidence, a score, or a release decision.
 */
sealed interface LlvmBehaviorCandidateExecutionAdmission {
    val authority: String
    val phase: String
    val startAuthorized: Boolean
    val executionClaimed: Boolean
    val scoringAuthority: Boolean
    val releaseEligible: Boolean
    val candidateExecutableBytes: Long
    val candidateExecutableSha256: String
    val corpusSha256: String
    val referenceReportSha256: String
    val diagnosticMatrixSha256: String
    val diagnosticMatrixSelfSha256: String
    val artifactManifestSha256: String
    val inputProjectionSha256: String
    val sandboxSha256: String
    val executionLimitsSha256: String
    val caseCount: Int
    val admissionSha256: String
    val operatorSummary: String
    val canonicalBytes: ByteArray
}

/**
 * Fixed raw-path production entry point for the A15 pre-START boundary.
 *
 * No runner, process, callback, parsed document, claimed digest, result, score, or release token is
 * accepted. The output parent must already be a dedicated canonical mode-0700 directory.
 */
object LlvmBehaviorCandidateExecutionAdmissionPublisher {
    fun publish(
        corpusPath: Path,
        referenceReportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        candidateExecutablePath: Path,
        outputPath: Path,
    ): LlvmBehaviorCandidateExecutionAdmission = PublishedAdmission(
        corpusPath,
        referenceReportPath,
        diagnosticMatrixPath,
        artifactManifestPath,
        candidateExecutablePath,
        outputPath,
    )

    /*
     * Reflective construction can provide only the same six raw Paths. Construction performs the
     * complete authentication and immutable publication; no derived-state constructor exists.
     */
    private class PublishedAdmission(
        corpusPath: Path,
        referenceReportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        candidateExecutablePath: Path,
        outputPath: Path,
    ) : LlvmBehaviorCandidateExecutionAdmission {
        private val storedCanonicalBytes: ByteArray

        override val authority: String
        override val phase: String
        override val startAuthorized: Boolean
        override val executionClaimed: Boolean
        override val scoringAuthority: Boolean
        override val releaseEligible: Boolean
        override val candidateExecutableBytes: Long
        override val candidateExecutableSha256: String
        override val corpusSha256: String
        override val referenceReportSha256: String
        override val diagnosticMatrixSha256: String
        override val diagnosticMatrixSelfSha256: String
        override val artifactManifestSha256: String
        override val inputProjectionSha256: String
        override val sandboxSha256: String
        override val executionLimitsSha256: String
        override val caseCount: Int
        override val admissionSha256: String
        override val operatorSummary: String

        override val canonicalBytes: ByteArray
            get() = storedCanonicalBytes.copyOf()

        init {
            val derived = deriveAndPublishAdmission(
                corpusPath,
                referenceReportPath,
                diagnosticMatrixPath,
                artifactManifestPath,
                candidateExecutablePath,
                outputPath,
            )
            authority = PRE_START_AUTHORITY
            phase = PRE_START_PHASE
            startAuthorized = false
            executionClaimed = false
            scoringAuthority = false
            releaseEligible = false
            candidateExecutableBytes = derived.candidateBytes
            candidateExecutableSha256 = derived.candidateSha256
            corpusSha256 = derived.corpusSha256
            referenceReportSha256 = derived.referenceReportSha256
            diagnosticMatrixSha256 = derived.diagnosticMatrixSha256
            diagnosticMatrixSelfSha256 = derived.diagnosticMatrixSelfSha256
            artifactManifestSha256 = derived.artifactManifestSha256
            inputProjectionSha256 = derived.inputProjectionSha256
            sandboxSha256 = derived.sandboxSha256
            executionLimitsSha256 = derived.executionLimitsSha256
            caseCount = derived.caseCount
            storedCanonicalBytes = derived.canonicalBytes.copyOf()
            admissionSha256 = OracleArtifacts.sha256(storedCanonicalBytes)
            operatorSummary =
                "PRE-START ONLY: candidate=$candidateExecutableSha256; cases=$caseCount; " +
                    "started=false; executed=false; scored=false; releaseEligible=false; " +
                    "admissionSha256=$admissionSha256"
        }
    }
}

private fun deriveAndPublishAdmission(
    corpusPath: Path,
    referenceReportPath: Path,
    diagnosticMatrixPath: Path,
    artifactManifestPath: Path,
    candidateExecutablePath: Path,
    outputPath: Path,
): DerivedAdmission {
    try {
        val normalized = normalizePaths(
            corpusPath,
            referenceReportPath,
            diagnosticMatrixPath,
            artifactManifestPath,
            candidateExecutablePath,
            outputPath,
        )
        requireDistinctInputsAndOutput(normalized)
        requireDedicatedOutputParent(normalized.output)

        StableControlFile.open(
            normalized.corpus,
            MAXIMUM_CORPUS_BYTES.toLong(),
            "LLVM behavior corpus",
        ).use { corpusGuard ->
            StableControlFile.open(
                normalized.referenceReport,
                MAXIMUM_REFERENCE_REPORT_BYTES.toLong(),
                "LLVM behavior reference report",
            ).use { reportGuard ->
                StableControlFile.open(
                    normalized.diagnosticMatrix,
                    MAXIMUM_DIAGNOSTIC_MATRIX_BYTES.toLong(),
                    "LLVM diagnostic matrix",
                ).use { matrixGuard ->
                    StableControlFile.open(
                        normalized.artifactManifest,
                        MAXIMUM_ARTIFACT_MANIFEST_BYTES.toLong(),
                        "LLVM artifact manifest",
                    ).use { manifestGuard ->
                        StableControlFile.open(
                            normalized.candidateExecutable,
                            MAXIMUM_CANDIDATE_EXECUTABLE_BYTES,
                            "candidate executable",
                        ).use { candidateGuard ->
                            requireExecutableCandidate(normalized.candidateExecutable)
                            val candidateSha256 = candidateGuard.sha256(label = "candidate executable")
                            val corpusBytes = corpusGuard.readExactly(
                                0L,
                                corpusGuard.size.toBoundedInt("LLVM behavior corpus"),
                                "LLVM behavior corpus",
                            )
                            val corpus = parseCanonicalCorpus(corpusBytes)

                            val reference = LlvmBehaviorReferenceEvidenceVerifier.verify(
                                normalized.corpus,
                                normalized.referenceReport,
                                normalized.diagnosticMatrix,
                                normalized.artifactManifest,
                            )
                            val corpusSha256 = OracleArtifacts.sha256(corpusBytes)
                            if (corpusSha256 != reference.corpusSha256) {
                                admissionFail("authenticated corpus differs from the pinned corpus descriptor")
                            }

                            val rendered = renderAdmission(
                                corpus,
                                reference,
                                candidateGuard.size,
                                candidateSha256,
                            )

                            // Terminal checks occur before the receipt is made visible. The second
                            // verifier pass prevents a path substitution after plan derivation.
                            requireStableInputs(
                                corpusGuard,
                                reportGuard,
                                matrixGuard,
                                manifestGuard,
                                candidateGuard,
                                normalized.candidateExecutable,
                                candidateSha256,
                            )
                            val terminalReference = LlvmBehaviorReferenceEvidenceVerifier.verify(
                                normalized.corpus,
                                normalized.referenceReport,
                                normalized.diagnosticMatrix,
                                normalized.artifactManifest,
                            )
                            if (!sameReferenceEvidence(reference, terminalReference)) {
                                admissionFail("LLVM reference evidence changed before pre-START publication")
                            }
                            requireStableInputs(
                                corpusGuard,
                                reportGuard,
                                matrixGuard,
                                manifestGuard,
                                candidateGuard,
                                normalized.candidateExecutable,
                                candidateSha256,
                            )

                            val parent = normalized.output.parent
                                ?: admissionFail("admission output must have a parent")
                            LinuxFilesystemSyscalls.openRoot(parent).use { parentDescriptor ->
                                val published = DescriptorBoundAtomicStateFile.publishNoReplace(
                                    parentDescriptor,
                                    normalized.output.fileName.toString(),
                                    rendered.canonicalBytes,
                                    MAXIMUM_ADMISSION_BYTES,
                                )
                                if (!MessageDigest.isEqual(published.bytes, rendered.canonicalBytes)) {
                                    admissionFail("published pre-START receipt differs from derived bytes")
                                }
                            }
                            return DerivedAdmission(
                                candidateBytes = candidateGuard.size,
                                candidateSha256 = candidateSha256,
                                corpusSha256 = corpusSha256,
                                referenceReportSha256 = reference.reportSha256,
                                diagnosticMatrixSha256 = reference.diagnosticMatrixSha256,
                                diagnosticMatrixSelfSha256 = reference.diagnosticMatrixSelfSha256,
                                artifactManifestSha256 = reference.artifactManifestSha256,
                                inputProjectionSha256 = rendered.inputProjectionSha256,
                                sandboxSha256 = rendered.sandboxSha256,
                                executionLimitsSha256 = rendered.executionLimitsSha256,
                                caseCount = rendered.caseCount,
                                canonicalBytes = rendered.canonicalBytes,
                            )
                        }
                    }
                }
            }
        }
    } catch (failure: LlvmBehaviorCandidateExecutionAdmissionException) {
        throw failure
    } catch (failure: Exception) {
        admissionFail(
            "LLVM candidate execution admission failed: " +
                (failure.message ?: failure.javaClass.simpleName),
            failure,
        )
    }
}

private fun renderAdmission(
    corpus: JsonObject,
    reference: LlvmBehaviorReferenceEvidence,
    candidateBytes: Long,
    candidateSha256: String,
): RenderedAdmission {
    val corpusId = corpus.requiredString("id", "behavior corpus")
    if (corpusId != reference.corpusId) admissionFail("corpus identity differs from authenticated reference")
    val cases = corpus.requiredArray("cases", "behavior corpus")
    if (cases.size != reference.caseIds.size) admissionFail("corpus case count differs from authenticated reference")
    val directories = corpus.requiredArray("directories", "behavior corpus")
    val baseEnvironment = corpus.requiredObject("environment", "behavior corpus")
    val sandbox = corpus.requiredObject("sandbox", "behavior corpus")
    val limits = corpus.requiredObject("limits", "behavior corpus")

    val inputProjectionCases = ArrayList<JsonElement>(cases.size)
    val caseBindings = ArrayList<JsonElement>(cases.size)
    cases.forEachIndexed { index, rawCase ->
        val label = "behavior corpus case[$index]"
        val case = rawCase.asObject(label)
        val caseId = case.requiredString("id", label)
        if (caseId != reference.caseIds[index]) admissionFail("corpus case order changed during admission")
        val arguments = case.requiredArray("arguments", label)
        val caseEnvironment = case.requiredObject("environment", label)
        val stdin = case.requiredObject("stdin", label)
        val inputs = case.requiredArray("inputs", label)
        val artifactPaths = JsonArray(
            case.requiredObject("expected", label)
                .requiredArray("artifacts", "$label expected")
                .mapIndexed { artifactIndex, artifact ->
                    JsonPrimitive(
                        artifact.asObject("$label expected artifact[$artifactIndex]")
                            .requiredString("path", "$label expected artifact[$artifactIndex]"),
                    )
                },
        )

        val commandProjection = JsonObject(
            linkedMapOf(
                "arguments" to arguments,
                "baseEnvironment" to baseEnvironment,
                "candidateExecutableSha256" to JsonPrimitive(candidateSha256),
                "caseEnvironment" to caseEnvironment,
                "executableMountPath" to JsonPrimitive(CANDIDATE_MOUNT_PATH),
            ),
        )
        val inputProjection = JsonObject(
            linkedMapOf(
                "directories" to directories,
                "files" to inputs,
                "stdin" to stdin,
            ),
        )
        val commandSha256 = canonicalSha256(commandProjection)
        val inputSha256 = canonicalSha256(inputProjection)
        val declaredArtifactsSha256 = canonicalSha256(artifactPaths)
        caseBindings += JsonObject(
            linkedMapOf(
                "caseId" to JsonPrimitive(caseId),
                "commandSha256" to JsonPrimitive(commandSha256),
                "declaredArtifactsSha256" to JsonPrimitive(declaredArtifactsSha256),
                "inputsSha256" to JsonPrimitive(inputSha256),
            ),
        )
        inputProjectionCases += JsonObject(
            linkedMapOf(
                "arguments" to arguments,
                "caseEnvironment" to caseEnvironment,
                "caseId" to JsonPrimitive(caseId),
                "declaredArtifactPaths" to artifactPaths,
                "inputs" to inputs,
                "stdin" to stdin,
            ),
        )
    }

    val inputProjection = JsonObject(
        linkedMapOf(
            "baseEnvironment" to baseEnvironment,
            "cases" to JsonArray(inputProjectionCases),
            "corpusId" to JsonPrimitive(corpusId),
            "directories" to directories,
            "schemaVersion" to JsonPrimitive(1),
        ),
    )
    val inputProjectionSha256 = canonicalSha256(inputProjection)
    val sandboxSha256 = canonicalSha256(sandbox)
    if (sandboxSha256 != reference.sandboxSha256) {
        admissionFail("runtime sandbox declaration differs from authenticated reference")
    }
    val executionLimitsSha256 = canonicalSha256(limits)

    val controlClient = sandbox.requiredObject("controlClient", "behavior corpus sandbox")
    val engineProfile = sandbox.requiredObject("engineProfile", "behavior corpus sandbox")
    val document = JsonObject(
        linkedMapOf(
            "authority" to JsonPrimitive(PRE_START_AUTHORITY),
            "candidate" to JsonObject(
                linkedMapOf(
                    "bytes" to JsonPrimitive(candidateBytes),
                    "sha256" to JsonPrimitive(candidateSha256),
                ),
            ),
            "command" to JsonObject(
                linkedMapOf(
                    "caseBindings" to JsonArray(caseBindings),
                    "environmentMode" to JsonPrimitive("clear-inherited"),
                    "executableMountPath" to JsonPrimitive(CANDIDATE_MOUNT_PATH),
                ),
            ),
            "corpus" to JsonObject(
                linkedMapOf(
                    "caseCount" to JsonPrimitive(cases.size),
                    "id" to JsonPrimitive(corpusId),
                    "inputProjectionSha256" to JsonPrimitive(inputProjectionSha256),
                    "sha256" to JsonPrimitive(reference.corpusSha256),
                ),
            ),
            "execution" to JsonObject(
                linkedMapOf(
                    "candidateExecuted" to JsonPrimitive(false),
                    "candidateOutputsSha256" to JsonNull,
                    "capturedArtifactBytes" to JsonNull,
                    "capturedStderrBytes" to JsonNull,
                    "capturedStdoutBytes" to JsonNull,
                    "caseResults" to JsonNull,
                    "exitCode" to JsonNull,
                    "phase" to JsonPrimitive(PRE_START_PHASE),
                    "reason" to JsonPrimitive(PRE_START_REASON),
                    "resourceExhausted" to JsonNull,
                    "signal" to JsonNull,
                    "startAuthorized" to JsonPrimitive(false),
                    "timedOut" to JsonNull,
                ),
            ),
            "executionClaimed" to JsonPrimitive(false),
            "kind" to JsonPrimitive(ADMISSION_KIND),
            "oracleExpectationsExposed" to JsonPrimitive(false),
            "referenceAuthentication" to JsonObject(
                linkedMapOf(
                    "artifactManifestSha256" to JsonPrimitive(reference.artifactManifestSha256),
                    "diagnosticMatrixSelfSha256" to JsonPrimitive(reference.diagnosticMatrixSelfSha256),
                    "diagnosticMatrixSha256" to JsonPrimitive(reference.diagnosticMatrixSha256),
                    "referenceReportSha256" to JsonPrimitive(reference.reportSha256),
                ),
            ),
            "publication" to JsonObject(
                linkedMapOf(
                    "mechanism" to JsonPrimitive(PUBLICATION_MECHANISM),
                    "mode" to JsonPrimitive("0o400"),
                ),
            ),
            "releaseEligible" to JsonPrimitive(false),
            "runtime" to JsonObject(
                linkedMapOf(
                    "backend" to JsonPrimitive(sandbox.requiredString("backend", "behavior corpus sandbox")),
                    "containment" to JsonPrimitive(
                        sandbox.requiredString("isolation", "behavior corpus sandbox"),
                    ),
                    "controlClientBytes" to JsonPrimitive(
                        controlClient.requiredLong("bytes", "behavior corpus sandbox control client"),
                    ),
                    "controlClientSha256" to JsonPrimitive(
                        controlClient.requiredString("sha256", "behavior corpus sandbox control client"),
                    ),
                    "controlClientVersionSha256" to JsonPrimitive(
                        OracleArtifacts.sha256(
                            controlClient.requiredString("version", "behavior corpus sandbox control client")
                                .encodeToByteArray(),
                        ),
                    ),
                    "engineProfileSha256" to JsonPrimitive(canonicalSha256(engineProfile)),
                    "imageDigest" to JsonPrimitive(
                        sandbox.requiredString("imageDigest", "behavior corpus sandbox"),
                    ),
                    "liveContainmentVerified" to JsonPrimitive(false),
                    "liveRuntimeIdentityVerified" to JsonPrimitive(false),
                    "platform" to JsonPrimitive(sandbox.requiredString("platform", "behavior corpus sandbox")),
                    "resourcePolicyVersion" to JsonPrimitive(
                        sandbox.requiredLong("resourcePolicyVersion", "behavior corpus sandbox"),
                    ),
                    "sandboxSha256" to JsonPrimitive(sandboxSha256),
                ),
            ),
            "schemaVersion" to JsonPrimitive(1),
            "scoringAuthority" to JsonPrimitive(false),
            "limits" to JsonObject(
                linkedMapOf(
                    "artifactBytes" to limits.requiredElement("artifactBytes", "behavior corpus limits"),
                    "cpuSeconds" to limits.requiredElement("cpuSeconds", "behavior corpus limits"),
                    "fileBytes" to limits.requiredElement("fileBytes", "behavior corpus limits"),
                    "memoryBytes" to limits.requiredElement("memoryBytes", "behavior corpus limits"),
                    "openFiles" to limits.requiredElement("openFiles", "behavior corpus limits"),
                    "policySha256" to JsonPrimitive(executionLimitsSha256),
                    "processes" to limits.requiredElement("processes", "behavior corpus limits"),
                    "stderrBytes" to limits.requiredElement("stderrBytes", "behavior corpus limits"),
                    "stdoutBytes" to limits.requiredElement("stdoutBytes", "behavior corpus limits"),
                    "timeoutMilliseconds" to limits.requiredElement("timeoutMilliseconds", "behavior corpus limits"),
                    "workspaceBytes" to limits.requiredElement("workspaceBytes", "behavior corpus limits"),
                    "workspaceEntries" to limits.requiredElement("workspaceEntries", "behavior corpus limits"),
                ),
            ),
        ),
    )
    try {
        OracleSchemas.validate(ADMISSION_SCHEMA, document)
    } catch (failure: Exception) {
        admissionFail("derived pre-START receipt fails its bundled schema", failure)
    }
    val canonicalBytes = try {
        OracleJson.canonicalBytes(document, ADMISSION_JSON_LIMITS)
    } catch (failure: Exception) {
        admissionFail("derived pre-START receipt exceeds its canonical JSON bounds", failure)
    }
    if (canonicalBytes.size !in 1..MAXIMUM_ADMISSION_BYTES) {
        admissionFail("derived pre-START receipt exceeds its publication bound")
    }
    return RenderedAdmission(
        inputProjectionSha256,
        sandboxSha256,
        executionLimitsSha256,
        cases.size,
        canonicalBytes,
    )
}

private fun normalizePaths(
    corpusPath: Path,
    referenceReportPath: Path,
    diagnosticMatrixPath: Path,
    artifactManifestPath: Path,
    candidateExecutablePath: Path,
    outputPath: Path,
): AdmissionPaths = AdmissionPaths(
    corpus = requireAbsoluteNormalized(corpusPath, "behavior corpus"),
    referenceReport = requireAbsoluteNormalized(referenceReportPath, "reference report"),
    diagnosticMatrix = requireAbsoluteNormalized(diagnosticMatrixPath, "diagnostic matrix"),
    artifactManifest = requireAbsoluteNormalized(artifactManifestPath, "artifact manifest"),
    candidateExecutable = requireAbsoluteNormalized(candidateExecutablePath, "candidate executable"),
    output = requireAbsoluteNormalized(outputPath, "admission output"),
)

private fun requireAbsoluteNormalized(path: Path, label: String): Path {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        admissionFail("$label path must be absolute, normalized, and name a file")
    }
    return path
}

private fun requireDistinctInputsAndOutput(paths: AdmissionPaths) {
    val inputs = listOf(
        "behavior corpus" to paths.corpus,
        "reference report" to paths.referenceReport,
        "diagnostic matrix" to paths.diagnosticMatrix,
        "artifact manifest" to paths.artifactManifest,
        "candidate executable" to paths.candidateExecutable,
    )
    inputs.forEachIndexed { index, (leftLabel, left) ->
        inputs.drop(index + 1).forEach { (rightLabel, right) ->
            if (left == right || sameExistingFile(left, right)) {
                admissionFail("$leftLabel and $rightLabel must not alias")
            }
        }
        if (left == paths.output || sameExistingFile(left, paths.output)) {
            admissionFail("admission output must not alias $leftLabel")
        }
        if (left.parent == paths.output.parent) {
            admissionFail("dedicated admission output parent must not contain an input")
        }
    }
    val temporary = paths.output.parent.resolve(
        DescriptorBoundAtomicStateFile.temporaryName(paths.output.fileName.toString()),
    )
    inputs.forEach { (label, input) ->
        if (sameExistingFile(input, temporary)) admissionFail("admission temporary must not alias $label")
    }
}

private fun sameExistingFile(left: Path, right: Path): Boolean =
    Files.exists(left, LinkOption.NOFOLLOW_LINKS) &&
        Files.exists(right, LinkOption.NOFOLLOW_LINKS) &&
        try {
            Files.isSameFile(left, right)
        } catch (failure: Exception) {
            admissionFail("cannot establish path alias identity", failure)
        }

private fun requireDedicatedOutputParent(output: Path) {
    val parent = output.parent ?: admissionFail("admission output must have a parent")
    val parentAttributes = fileAttributes(parent, "admission output parent")
    if (!parentAttributes.isDirectory || parentAttributes.isSymbolicLink || parentAttributes.fileKey() == null) {
        admissionFail("admission output parent must be an identified real directory")
    }
    if (parent.toRealPath() != parent) {
        admissionFail("admission output parent path may not contain symbolic links")
    }
    val permissions = try {
        Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        admissionFail("admission output parent POSIX permissions are unavailable", failure)
    }
    if (permissions != OWNER_DIRECTORY_PERMISSIONS) {
        admissionFail("admission output parent must be dedicated mode 0700")
    }
    val allowed = setOf(
        output.fileName.toString(),
        DescriptorBoundAtomicStateFile.temporaryName(output.fileName.toString()),
    )
    val entries = try {
        Files.newDirectoryStream(parent).use { stream -> stream.map { it.fileName.toString() }.toList() }
    } catch (failure: Exception) {
        admissionFail("admission output parent cannot be enumerated", failure)
    }
    if (entries.any { it !in allowed } || entries.size > 1) {
        admissionFail("admission output parent is not dedicated to one receipt")
    }
}

private fun requireExecutableCandidate(path: Path) {
    val attributes = fileAttributes(path, "candidate executable")
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
        admissionFail("candidate executable must be an identified regular file")
    }
    val permissions = try {
        Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        admissionFail("candidate executable POSIX permissions are unavailable", failure)
    }
    if (PosixFilePermission.OWNER_EXECUTE !in permissions ||
        PosixFilePermission.GROUP_WRITE in permissions ||
        PosixFilePermission.OTHERS_WRITE in permissions
    ) {
        admissionFail("candidate executable must be owner-executable and not group/other writable")
    }
    val linkCount = try {
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
    } catch (failure: Exception) {
        admissionFail("candidate executable link count is unavailable", failure)
    }
    if (linkCount != 1L) admissionFail("candidate executable must have exactly one link")
}

private fun requireStableInputs(
    corpus: StableControlFile,
    report: StableControlFile,
    matrix: StableControlFile,
    manifest: StableControlFile,
    candidate: StableControlFile,
    candidatePath: Path,
    expectedCandidateSha256: String,
) {
    corpus.verifyUnchanged("LLVM behavior corpus")
    report.verifyUnchanged("LLVM behavior reference report")
    matrix.verifyUnchanged("LLVM diagnostic matrix")
    manifest.verifyUnchanged("LLVM artifact manifest")
    candidate.verifyUnchanged("candidate executable")
    requireExecutableCandidate(candidatePath)
    if (candidate.sha256(label = "candidate executable terminal authentication") != expectedCandidateSha256) {
        admissionFail("candidate executable bytes changed before pre-START publication")
    }
}

private fun parseCanonicalCorpus(bytes: ByteArray): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(bytes, CORPUS_JSON_LIMITS)
    } catch (failure: Exception) {
        admissionFail("LLVM behavior corpus is not strict canonical bounded JSON", failure)
    }
    return parsed as? JsonObject ?: admissionFail("LLVM behavior corpus root must be an object")
}

private fun sameReferenceEvidence(
    left: LlvmBehaviorReferenceEvidence,
    right: LlvmBehaviorReferenceEvidence,
): Boolean =
    left.corpusId == right.corpusId &&
        left.corpusSha256 == right.corpusSha256 &&
        left.reportSha256 == right.reportSha256 &&
        left.diagnosticMatrixSha256 == right.diagnosticMatrixSha256 &&
        left.diagnosticMatrixSelfSha256 == right.diagnosticMatrixSelfSha256 &&
        left.artifactManifestSha256 == right.artifactManifestSha256 &&
        left.executableBytes == right.executableBytes &&
        left.executableSha256 == right.executableSha256 &&
        left.sandboxSha256 == right.sandboxSha256 &&
        left.caseIds == right.caseIds &&
        left.diagnosticOwners == right.diagnosticOwners

private fun canonicalSha256(element: JsonElement): String = try {
    OracleArtifacts.sha256(OracleJson.canonicalBytes(element, PROJECTION_JSON_LIMITS))
} catch (failure: Exception) {
    admissionFail("candidate execution projection exceeds its canonical bounds", failure)
}

private fun fileAttributes(path: Path, label: String): BasicFileAttributes = try {
    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
} catch (failure: Exception) {
    admissionFail("$label metadata is unavailable", failure)
}

private fun Long.toBoundedInt(label: String): Int {
    if (this !in 1..Int.MAX_VALUE.toLong()) admissionFail("$label size exceeds the in-memory projection bound")
    return toInt()
}

private fun JsonElement.asObject(label: String): JsonObject =
    this as? JsonObject ?: admissionFail("$label must be an object")

private fun JsonObject.requiredElement(name: String, label: String): JsonElement =
    this[name] ?: admissionFail("$label is missing $name")

private fun JsonObject.requiredObject(name: String, label: String): JsonObject =
    requiredElement(name, label) as? JsonObject ?: admissionFail("$label $name must be an object")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray =
    requiredElement(name, label) as? JsonArray ?: admissionFail("$label $name must be an array")

private fun JsonObject.requiredString(name: String, label: String): String {
    val value = requiredElement(name, label) as? JsonPrimitive
        ?: admissionFail("$label $name must be a string")
    if (!value.isString) admissionFail("$label $name must be a string")
    return value.content
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val value = requiredElement(name, label) as? JsonPrimitive
        ?: admissionFail("$label $name must be an integer")
    if (value.isString || value.content.any { it in ".eE" }) admissionFail("$label $name must be an integer")
    return value.longOrNull ?: admissionFail("$label $name exceeds the integer range")
}

private fun admissionFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorCandidateExecutionAdmissionException(message, cause)

private data class AdmissionPaths(
    val corpus: Path,
    val referenceReport: Path,
    val diagnosticMatrix: Path,
    val artifactManifest: Path,
    val candidateExecutable: Path,
    val output: Path,
)

private data class RenderedAdmission(
    val inputProjectionSha256: String,
    val sandboxSha256: String,
    val executionLimitsSha256: String,
    val caseCount: Int,
    val canonicalBytes: ByteArray,
)

private data class DerivedAdmission(
    val candidateBytes: Long,
    val candidateSha256: String,
    val corpusSha256: String,
    val referenceReportSha256: String,
    val diagnosticMatrixSha256: String,
    val diagnosticMatrixSelfSha256: String,
    val artifactManifestSha256: String,
    val inputProjectionSha256: String,
    val sandboxSha256: String,
    val executionLimitsSha256: String,
    val caseCount: Int,
    val canonicalBytes: ByteArray,
)

private const val PRE_START_AUTHORITY = "kotlin-host-pre-start-binding-v1"
private const val PRE_START_PHASE = "pre-start"
private const val PRE_START_REASON = "authenticated-generic-kotlin-runner-unavailable"
private const val ADMISSION_KIND = "llvm-behavior-candidate-execution-admission"
private const val ADMISSION_SCHEMA = "llvm-behavior-candidate-execution-admission"
private const val PUBLICATION_MECHANISM = "descriptor-bound-no-replace-0400-v1"
private const val CANDIDATE_MOUNT_PATH = "/candidate/clang"
private const val MAXIMUM_CORPUS_BYTES = 16 * 1024 * 1024
private const val MAXIMUM_REFERENCE_REPORT_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_DIAGNOSTIC_MATRIX_BYTES = 1024 * 1024
private const val MAXIMUM_ARTIFACT_MANIFEST_BYTES = 4 * 1024 * 1024
private const val MAXIMUM_CANDIDATE_EXECUTABLE_BYTES = 128L * 1024L * 1024L
private const val MAXIMUM_ADMISSION_BYTES = 1024 * 1024
private val OWNER_DIRECTORY_PERMISSIONS: Set<PosixFilePermission> = Collections.unmodifiableSet(
    setOf(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
        PosixFilePermission.OWNER_EXECUTE,
    ),
)
private val CORPUS_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_CORPUS_BYTES,
    maximumCanonicalBytes = MAXIMUM_CORPUS_BYTES,
    maximumDepth = 64,
    maximumNodes = 250_000,
    maximumStringBytes = MAXIMUM_CORPUS_BYTES,
    maximumTotalStringBytes = MAXIMUM_CORPUS_BYTES,
    maximumNumberCharacters = 64,
)
private val PROJECTION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_CORPUS_BYTES,
    maximumCanonicalBytes = MAXIMUM_CORPUS_BYTES,
    maximumDepth = 64,
    maximumNodes = 250_000,
    maximumStringBytes = MAXIMUM_CORPUS_BYTES,
    maximumTotalStringBytes = MAXIMUM_CORPUS_BYTES,
    maximumNumberCharacters = 64,
)
private val ADMISSION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_ADMISSION_BYTES,
    maximumCanonicalBytes = MAXIMUM_ADMISSION_BYTES,
    maximumDepth = 32,
    maximumNodes = 16_384,
    maximumStringBytes = 16 * 1024,
    maximumTotalStringBytes = 512 * 1024,
    maximumNumberCharacters = 32,
)
