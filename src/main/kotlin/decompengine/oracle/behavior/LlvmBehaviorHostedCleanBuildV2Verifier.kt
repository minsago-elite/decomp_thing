package decompengine.oracle.behavior

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.provenance.BoundedElfTwinV1
import decompengine.oracle.provenance.BoundedElfTwinV1Limits
import decompengine.project.GeneratedCMakeReconstructionProfile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorHostedCleanBuildV2VerificationException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * Authenticates one immutable unsigned worker-receipt/executable pair.
 *
 * This verifier establishes canonical schema-conforming bytes, the exact receipt-to-executable
 * identity, and only the explicitly checked repeated-field equalities. Archive, lineage-index,
 * runtime, and build fields are opaque unsigned claims. With only these two raw paths it cannot
 * prove that a build ran, authenticate archive contents, authenticate a container or workflow,
 * admit the executable, or grant oracle authority.
 */
object LlvmBehaviorHostedCleanBuildV2Verifier {
    fun verify(receiptPath: Path, executablePath: Path): LlvmBehaviorHostedCleanBuildV2PairVerification =
        verifyPair(receiptPath, executablePath) {}

    internal fun verifyWithTerminalParentFaultForTest(
        receiptPath: Path,
        executablePath: Path,
        beforeTerminalParentAuthentication: () -> Unit,
    ): LlvmBehaviorHostedCleanBuildV2PairVerification =
        verifyPair(receiptPath, executablePath, beforeTerminalParentAuthentication)

    private fun verifyPair(
        receiptPath: Path,
        executablePath: Path,
        beforeTerminalParentAuthentication: () -> Unit,
    ): LlvmBehaviorHostedCleanBuildV2PairVerification =
        translateVerificationFailure {
            val paths = normalizeHostedPairPaths(receiptPath, executablePath)
            requireHostedPairDirectory(paths.parent)
            requireExactHostedPairEntries(paths.parent)
            if (Files.isSameFile(paths.receipt, paths.executable)) {
                verificationFail("hosted receipt and candidate executable alias")
            }

            LinuxFilesystemSyscalls.openRoot(paths.parent).use { parent ->
                val receiptInspection = DescriptorBoundAtomicStateFile.inspectOrNull(
                    parent,
                    RECEIPT_FILE_NAME,
                    MAXIMUM_RECEIPT_BYTES,
                ) ?: verificationFail("hosted worker receipt is missing")
                receiptInspection.use { pinnedReceipt ->
                    val executableInspection = DescriptorBoundAtomicStateFile.inspectExecutableDigestOrNull(
                        parent,
                        EXECUTABLE_FILE_NAME,
                        MAXIMUM_EXECUTABLE_BYTES,
                    ) ?: verificationFail("hosted candidate executable is missing")
                    executableInspection.use { pinnedExecutable ->
                        val receiptBytes = pinnedReceipt.bytes
                        val document = parseCanonicalReceipt(receiptBytes)
                        val schema = OracleSchemas.identity(RECEIPT_SCHEMA_NAME)
                        if (schema.sha256 != EXPECTED_RECEIPT_SCHEMA_SHA256) {
                            verificationFail("bundled hosted receipt schema differs from its reviewed identity")
                        }
                        OracleSchemas.validate(RECEIPT_SCHEMA_NAME, document)
                        val projection = verifyReceiptBindings(
                            document,
                            pinnedExecutable.bytes,
                            pinnedExecutable.sha256,
                            schema.sha256,
                        )
                        verifyExecutableElf(
                            paths.executable,
                            pinnedExecutable.bytes,
                            pinnedExecutable.sha256,
                            projection,
                        )
                        beforeTerminalParentAuthentication()
                        requireTerminalHostedPair(
                            parent,
                            pinnedReceipt.identity,
                            receiptBytes,
                            pinnedExecutable.identity,
                            pinnedExecutable.bytes,
                            pinnedExecutable.sha256,
                        )
                        requireHostedPairDirectory(paths.parent)
                        requireExactHostedPairEntries(paths.parent)
                        requireTerminalLexicalParent(paths.parent, parent)
                        VerifiedHostedCleanBuildPair(projection, receiptBytes)
                    }
                }
            }
        }
}

private data class HostedPairPaths(val receipt: Path, val executable: Path, val parent: Path)

private data class HostedReceiptProjection(
    val executableBytes: Long,
    val executableSha256: String,
    val schemaSha256: String,
)

private class VerifiedHostedCleanBuildPair(
    private val projection: HostedReceiptProjection,
    receipt: ByteArray,
) : LlvmBehaviorHostedCleanBuildV2PairVerification {
    private val storedReceipt = receipt.copyOf()

    override val schemaVersion = 2
    override val executableBytes: Long = projection.executableBytes
    override val executableSha256: String = projection.executableSha256
    override val receiptBytes: Long = storedReceipt.size.toLong()
    override val receiptSha256: String = OracleArtifacts.sha256(storedReceipt)
    override val schemaSha256: String = projection.schemaSha256
    override val canonicalReceiptBytes: ByteArray
        get() = storedReceipt.copyOf()
    override val exactExecutableBound = true
    override val receiptFactsAuthenticated = false
    override val candidateLineageAuthenticated = false
    override val buildExecutionAuthenticated = false
    override val runtimeClosureAuthenticated = false
    override val hostedWorkflowAuthenticated = false
    override val admittedArtifactBound = false
    override val candidateStarted = false
    override val oracleAuthority = false
    override val referenceAuthoringAuthority = false
    override val scoringAuthority = false
    override val certificationAuthority = false
    override val releaseEligible = false
}

private fun normalizeHostedPairPaths(receiptPath: Path, executablePath: Path): HostedPairPaths {
    val receipt = requireExactPairPath(receiptPath, RECEIPT_FILE_NAME, "hosted worker receipt")
    val executable = requireExactPairPath(executablePath, EXECUTABLE_FILE_NAME, "hosted candidate executable")
    if (receipt.parent != executable.parent) verificationFail("hosted pair must share one exact parent directory")
    return HostedPairPaths(receipt, executable, receipt.parent)
}

private fun requireExactPairPath(path: Path, fixedName: String, label: String): Path {
    if (!path.isAbsolute || path.normalize() != path || path.parent == null || path.fileName?.toString() != fixedName) {
        verificationFail("$label path must be absolute, normalized, non-root, and named $fixedName")
    }
    if (!Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(path)) {
        verificationFail("$label must be an existing non-symlink regular file")
    }
    return path
}

private fun requireHostedPairDirectory(parent: Path) {
    val attributes = readPairAttributes(parent, "hosted pair directory")
    val permissions = Files.getPosixFilePermissions(parent, LinkOption.NOFOLLOW_LINKS)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null ||
        parent.toRealPath() != parent || permissions != OWNER_DIRECTORY_PERMISSIONS
    ) {
        verificationFail("hosted pair directory must be an identified real mode-0700 directory")
    }
}

private fun requireExactHostedPairEntries(parent: Path) {
    val entries = Files.newDirectoryStream(parent).use { stream ->
        val bounded = ArrayList<String>(2)
        val iterator = stream.iterator()
        while (iterator.hasNext()) {
            if (bounded.size >= 2) verificationFail("hosted pair directory exceeds its entry bound")
            bounded.add(iterator.next().fileName.toString())
        }
        bounded.sorted()
    }
    if (entries != listOf(EXECUTABLE_FILE_NAME, RECEIPT_FILE_NAME).sorted()) {
        verificationFail("hosted pair directory must contain exactly the receipt and executable")
    }
}

private fun parseCanonicalReceipt(bytes: ByteArray): JsonObject {
    if (bytes.isEmpty() || bytes.size > MAXIMUM_RECEIPT_BYTES) {
        verificationFail("hosted worker receipt exceeds its byte bound")
    }
    val parsed = try {
        OracleJson.parseCanonical(bytes, RECEIPT_JSON_LIMITS)
    } catch (failure: Exception) {
        throw LlvmBehaviorHostedCleanBuildV2VerificationException(
            "hosted worker receipt is not strict canonical bounded JSON",
            failure,
        )
    }
    return parsed as? JsonObject ?: verificationFail("hosted worker receipt root must be an object")
}

private fun verifyReceiptBindings(
    root: JsonObject,
    actualExecutableBytes: Long,
    actualExecutableSha256: String,
    schemaSha256: String,
): HostedReceiptProjection {
    if (root.requiredLong("schemaVersion", "hosted receipt") != 2L ||
        root.requiredString("kind", "hosted receipt") != RECEIPT_KIND ||
        root.requiredString("authority", "hosted receipt") != RECEIPT_AUTHORITY
    ) {
        verificationFail("hosted receipt root identity is not the reviewed inner-worker v2 identity")
    }
    val schema = root.requiredObject("schema", "hosted receipt")
    if (schema.requiredString("name", "hosted receipt schema") != RECEIPT_SCHEMA_NAME ||
        schema.requiredString("sha256", "hosted receipt schema") != schemaSha256
    ) {
        verificationFail("hosted receipt does not bind the reviewed bundled schema")
    }

    val archive = root.requiredObject("archive", "hosted receipt")
    val lineage = root.requiredObject("candidateLineageIndex", "hosted receipt")
    if (lineage.requiredLong("schemaVersion", "candidate lineage index") != 2L) {
        verificationFail("hosted receipt lineage index is not schema v2")
    }
    val accepted = lineage.requiredObject("acceptedAcp", "candidate lineage index")
    if (accepted.requiredLong("receiptSchemaVersion", "accepted ACP") != 2L) {
        verificationFail("hosted receipt accepted ACP receipts are not schema v2")
    }
    val acceptedCount = accepted.requiredLong("count", "accepted ACP")
    val contributionCount = try {
        Math.addExact(
            accepted.requiredLong("reconstructionCount", "accepted ACP"),
            accepted.requiredLong("repairCount", "accepted ACP"),
        )
    } catch (failure: ArithmeticException) {
        throw LlvmBehaviorHostedCleanBuildV2VerificationException("accepted ACP counts overflow", failure)
    }
    if (acceptedCount != contributionCount) {
        verificationFail("accepted ACP count differs from reconstruction plus repair contributions")
    }

    val source = root.requiredObject("source", "hosted receipt")
    if (source.requiredString("profileId", "hosted receipt source") !=
        GeneratedCMakeReconstructionProfile.PROFILE_ID ||
        source.requiredString("profileSha256", "hosted receipt source") !=
        GeneratedCMakeReconstructionProfile.descriptor.sha256
    ) {
        verificationFail("hosted receipt source profile differs from the reviewed reconstruction profile")
    }
    val sourceInputCount = source.requiredLong("inputCount", "hosted receipt source")
    val sourceRevisionSha256 = source.requiredString("revisionSha256", "hosted receipt source")

    val builds = root.requiredArray("cleanBuilds", "hosted receipt")
    if (builds.size != 2) verificationFail("hosted receipt must contain exactly two clean builds")
    val first = builds[0] as? JsonObject ?: verificationFail("first clean build must be an object")
    val second = builds[1] as? JsonObject ?: verificationFail("second clean build must be an object")
    if (first.requiredLong("ordinal", "first clean build") != 1L ||
        second.requiredLong("ordinal", "second clean build") != 2L
    ) {
        verificationFail("hosted clean-build ordinals are not positional 1 and 2")
    }
    val firstSourceCount = first.requiredLong("sourceCount", "first clean build")
    val secondSourceCount = second.requiredLong("sourceCount", "second clean build")
    if (first.requiredString("sourceRevisionSha256", "first clean build") != sourceRevisionSha256 ||
        second.requiredString("sourceRevisionSha256", "second clean build") != sourceRevisionSha256 ||
        firstSourceCount != secondSourceCount || firstSourceCount !in 1L..sourceInputCount
    ) {
        verificationFail("hosted clean builds do not bind one plausible authenticated source revision")
    }
    REPRODUCIBILITY_FIELDS.forEach { field ->
        if (first[field] != second[field]) {
            verificationFail("hosted clean builds disagree on reproducibility field $field")
        }
    }
    if (first.requiredLong("dependencyCount", "first clean build") < firstSourceCount ||
        first.requiredLong("linkDependencyCount", "first clean build") < firstSourceCount
    ) {
        verificationFail("hosted clean-build dependency closure is smaller than its translation-unit set")
    }

    val candidate = root.requiredObject("candidateExecutable", "hosted receipt")
    val candidateBytes = candidate.requiredLong("bytes", "candidate executable")
    val candidateSha256 = candidate.requiredString("sha256", "candidate executable")
    listOf(first, second).forEachIndexed { index, build ->
        if (build.requiredLong("executableBytes", "clean build ${index + 1}") != candidateBytes ||
            build.requiredString("executableSha256", "clean build ${index + 1}") != candidateSha256
        ) {
            verificationFail("hosted clean-build executable identity differs from the projected candidate")
        }
    }
    if (candidate.requiredString("name", "candidate executable") != EXECUTABLE_FILE_NAME ||
        candidateBytes != actualExecutableBytes || candidateSha256 != actualExecutableSha256
    ) {
        verificationFail("hosted receipt candidate identity differs from the exact executable file")
    }

    val toolchain = root.requiredObject("lockedToolchain", "hosted receipt")
    val runtime = root.requiredObject("runtimeClosure", "hosted receipt")
    val inspectDigest = toolchain.requiredString("inspectArtifactImageDigest", "locked toolchain")
    if (runtime.requiredString("inspectArtifactImageDigest", "runtime closure") != inspectDigest ||
        runtime.requiredLong("buildCount", "runtime closure") != builds.size.toLong()
    ) {
        verificationFail("hosted receipt runtime projection does not cross-bind its inspect artifact and builds")
    }

    val attestation = root.requiredObject("attestationBoundary", "hosted receipt")
    val subjects = attestation.requiredArray("requiredSubjects", "attestation boundary")
        .mapIndexed { index, value ->
            (value as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
                ?: verificationFail("attestation subject $index must be a string")
        }
    if (subjects != listOf(RECEIPT_FILE_NAME, EXECUTABLE_FILE_NAME)) {
        verificationFail("hosted receipt attestation subjects differ from the exact pair")
    }
    val acp = root.requiredObject("acpBoundary", "hosted receipt")
    val claims = root.requiredObject("claims", "hosted receipt")
    requireEqualBoolean(attestation, "hostedWorkflowAuthenticated", claims, "hostedWorkflowAuthenticated")
    requireEqualBoolean(attestation, "sigstoreBundleVerified", claims, "sigstoreBundleVerified")
    requireEqualBoolean(runtime, "authenticated", claims, "runtimeClosureAuthenticated")
    requireEqualBoolean(acp, "oracleAuthority", claims, "oracleAuthority")
    requireEqualBoolean(acp, "referenceAuthoringAuthority", claims, "referenceAuthoringAuthority")
    requireEqualBoolean(acp, "scoringAuthority", claims, "scoringAuthority")
    requireEqualBoolean(acp, "certificationAuthority", claims, "certificationAuthority")
    requireEqualBoolean(acp, "releaseAuthority", claims, "releaseAuthority")
    listOf(
        "runtimeClosureAuthenticated",
        "hostedWorkflowAuthenticated",
        "sigstoreBundleVerified",
        "admittedArtifactBound",
        "candidateStarted",
        "oracleAuthority",
        "referenceAuthoringAuthority",
        "scoringAuthority",
        "certificationAuthority",
        "releaseEligible",
    ).forEach { claim ->
        if (claims.requiredBoolean(claim, "hosted receipt claims")) {
            verificationFail("unsigned hosted worker receipt must keep $claim false")
        }
    }

    return HostedReceiptProjection(
        executableBytes = candidateBytes,
        executableSha256 = candidateSha256,
        schemaSha256 = schemaSha256,
    )
}

private fun requireEqualBoolean(
    left: JsonObject,
    leftName: String,
    right: JsonObject,
    rightName: String,
) {
    if (left.requiredBoolean(leftName, leftName) != right.requiredBoolean(rightName, rightName)) {
        verificationFail("hosted receipt boolean projections $leftName and $rightName disagree")
    }
}

private fun verifyExecutableElf(
    executablePath: Path,
    executableBytes: Long,
    executableSha256: String,
    projection: HostedReceiptProjection,
) {
    val elf = BoundedElfTwinV1.inspect(
        executablePath,
        BoundedElfTwinV1Limits(
            maximumFileBytes = MAXIMUM_EXECUTABLE_BYTES.toLong(),
            maximumRangeBytes = MAXIMUM_EXECUTABLE_BYTES.toLong(),
            maximumExecutableBytes = MAXIMUM_EXECUTABLE_BYTES.toLong(),
            maximumAggregateHashedBytes = MAXIMUM_AGGREGATE_HASHED_BYTES,
        ),
    )
    val entryPoint = elf.elf.header.entryPoint
    val entryPointIsMemoryBackedExecutable = elf.elf.programHeaders.any { header ->
        header.type == ELF_PROGRAM_HEADER_LOAD_TYPE &&
            (header.flags and ELF_PROGRAM_HEADER_EXECUTE_FLAG) != 0UL &&
            entryPoint >= header.virtualAddress &&
            entryPoint - header.virtualAddress < header.fileSize
    }
    if (executableBytes != projection.executableBytes || executableSha256 != projection.executableSha256 ||
        elf.bytes != executableBytes || elf.sha256 != executableSha256 ||
        elf.elf.header.elfClass != "ELF64" || elf.elf.header.dataEncoding != "little-endian" ||
        elf.elf.header.machine != 62UL || elf.elf.header.type !in setOf(2UL, 3UL) ||
        entryPoint == 0UL || elf.elf.executableLoad.bytes <= 0L || !entryPointIsMemoryBackedExecutable
    ) {
        verificationFail("hosted candidate is not the exact required executable x86-64 ELF64 file")
    }
}

private fun requireTerminalHostedPair(
    parent: decompengine.acp.LinuxDescriptor,
    receiptIdentity: decompengine.acp.LinuxFileIdentity,
    receiptBytes: ByteArray,
    executableIdentity: decompengine.acp.LinuxFileIdentity,
    executableBytes: Long,
    executableSha256: String,
) {
    val terminalReceipt = DescriptorBoundAtomicStateFile.inspectOrNull(
        parent,
        RECEIPT_FILE_NAME,
        MAXIMUM_RECEIPT_BYTES,
    ) ?: verificationFail("hosted worker receipt disappeared")
    terminalReceipt.use { inspection ->
        if (inspection.identity != receiptIdentity || !MessageDigest.isEqual(inspection.bytes, receiptBytes)) {
            verificationFail("hosted worker receipt changed during verification")
        }
    }
    val terminalExecutable = DescriptorBoundAtomicStateFile.inspectExecutableDigestOrNull(
        parent,
        EXECUTABLE_FILE_NAME,
        MAXIMUM_EXECUTABLE_BYTES,
    ) ?: verificationFail("hosted candidate executable disappeared")
    terminalExecutable.use { inspection ->
        if (inspection.identity != executableIdentity || inspection.bytes != executableBytes ||
            inspection.sha256 != executableSha256
        ) {
            verificationFail("hosted candidate executable changed during verification")
        }
    }
}

private fun requireTerminalLexicalParent(
    parentPath: Path,
    pinnedParent: decompengine.acp.LinuxDescriptor,
) {
    LinuxFilesystemSyscalls.openRoot(parentPath).use { terminalParent ->
        if (terminalParent.identity != pinnedParent.identity) {
            verificationFail("hosted pair directory changed during verification")
        }
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: verificationFail("$label.$name must be an object")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: verificationFail("$label.$name must be an array")

private fun JsonObject.requiredString(name: String, label: String): String {
    val primitive = this[name] as? JsonPrimitive
        ?: verificationFail("$label.$name must be a string")
    if (!primitive.isString) verificationFail("$label.$name must be a string")
    return primitive.content
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive
        ?: verificationFail("$label.$name must be an integer")
    return primitive.longOrNull ?: verificationFail("$label.$name must be an integer")
}

private fun JsonObject.requiredBoolean(name: String, label: String): Boolean {
    val primitive = this[name] as? JsonPrimitive
        ?: verificationFail("$label.$name must be a boolean")
    return primitive.booleanOrNull ?: verificationFail("$label.$name must be a boolean")
}

private fun readPairAttributes(path: Path, label: String): BasicFileAttributes = try {
    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
} catch (failure: Exception) {
    throw LlvmBehaviorHostedCleanBuildV2VerificationException("$label attributes are unavailable", failure)
}

private inline fun <T> translateVerificationFailure(action: () -> T): T = try {
    action()
} catch (failure: LlvmBehaviorHostedCleanBuildV2VerificationException) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBehaviorHostedCleanBuildV2VerificationException(
        "hosted worker pair verification failed: ${failure.message ?: failure.javaClass.simpleName}",
        failure,
    )
}

private fun verificationFail(message: String): Nothing =
    throw LlvmBehaviorHostedCleanBuildV2VerificationException(message)

private const val RECEIPT_SCHEMA_NAME = "llvm-behavior-hosted-clean-build-v2"
private const val RECEIPT_KIND = "llvm-behavior-hosted-clean-build-v2"
private const val RECEIPT_AUTHORITY = "kotlin-jvm-unsigned-inner-clean-build-worker-v2"
private const val RECEIPT_FILE_NAME = "candidate-hosted-clean-build-v2.json"
private const val EXECUTABLE_FILE_NAME = "candidate-reconstructed"
private const val ELF_PROGRAM_HEADER_LOAD_TYPE = 1UL
private const val ELF_PROGRAM_HEADER_EXECUTE_FLAG = 1UL
private const val MAXIMUM_RECEIPT_BYTES = 128 * 1024
private const val MAXIMUM_EXECUTABLE_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_AGGREGATE_HASHED_BYTES = 2L * 1024L * 1024L * 1024L
private const val EXPECTED_RECEIPT_SCHEMA_SHA256 =
    "b7b00bdf9f14e119b353f905fe05c7a45adbca7730a3cec6b5688e1ad5b310b9"
private val OWNER_DIRECTORY_PERMISSIONS = setOf(
    PosixFilePermission.OWNER_READ,
    PosixFilePermission.OWNER_WRITE,
    PosixFilePermission.OWNER_EXECUTE,
)
private val RECEIPT_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_RECEIPT_BYTES,
    maximumCanonicalBytes = MAXIMUM_RECEIPT_BYTES,
    maximumDepth = 20,
    maximumNodes = 1024,
    maximumStringBytes = 4096,
    maximumTotalStringBytes = 64 * 1024,
)
private val REPRODUCIBILITY_FIELDS = listOf(
    "buildEnvironmentSha256",
    "compileCommandSetSha256",
    "dependencyCount",
    "dependencySetSha256",
    "objectSetSha256",
    "linkCommandSha256",
    "linkDependencyCount",
    "linkDependencySetSha256",
    "combinedOutputBytes",
    "combinedOutputSha256",
    "executableBytes",
    "executableSha256",
)
