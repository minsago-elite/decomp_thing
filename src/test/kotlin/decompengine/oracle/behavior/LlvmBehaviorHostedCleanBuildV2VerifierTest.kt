package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.GeneratedCMakeReconstructionProfile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorHostedCleanBuildV2VerifierTest {
    @Test
    fun `verifier reopens and cross-binds one exact canonical unsigned pair`() = withPairDirectory { root ->
        val executable = systemElf()
        val receipt = canonicalReceipt(receiptDocument(executable))
        writePair(root, receipt, executable)

        val verified = LlvmBehaviorHostedCleanBuildV2Verifier.verify(
            root.resolve(RECEIPT_FILE),
            root.resolve(EXECUTABLE_FILE),
        )

        assertEquals(2, verified.schemaVersion)
        assertEquals(OracleSchemas.identity(SCHEMA_NAME).sha256, verified.schemaSha256)
        assertEquals(OracleArtifacts.sha256(receipt), verified.receiptSha256)
        assertEquals(OracleArtifacts.sha256(executable), verified.executableSha256)
        assertEquals(executable.size.toLong(), verified.executableBytes)
        assertContentEquals(receipt, verified.canonicalReceiptBytes)
        assertTrue(verified.exactExecutableBound)
        assertFalse(verified.receiptFactsAuthenticated)
        assertFalse(verified.candidateLineageAuthenticated)
        assertFalse(verified.buildExecutionAuthenticated)
        assertFalse(verified.runtimeClosureAuthenticated)
        assertFalse(verified.hostedWorkflowAuthenticated)
        assertFalse(verified.admittedArtifactBound)
        assertFalse(verified.oracleAuthority)
        assertFalse(verified.referenceAuthoringAuthority)
        assertFalse(verified.scoringAuthority)
        assertFalse(verified.certificationAuthority)
        assertFalse(verified.releaseEligible)

        val exposed = verified.canonicalReceiptBytes
        exposed.fill(0)
        assertContentEquals(receipt, verified.canonicalReceiptBytes)
    }

    @Test
    fun `schema-valid cross-paired build and runtime projections are rejected`() = withPairDirectory { root ->
        val executable = systemElf()
        val baseline = receiptDocument(executable)
        val builds = baseline.getValue("cleanBuilds") as JsonArray
        val second = builds[1] as JsonObject
        val changedBuild = JsonObject(second + ("objectSetSha256" to JsonPrimitive("f".repeat(64))))
        val crossBuild = JsonObject(
            baseline + ("cleanBuilds" to JsonArray(listOf(builds[0], changedBuild))),
        )
        val runtime = baseline.getValue("runtimeClosure") as JsonObject
        val crossRuntime = JsonObject(
            baseline + (
                "runtimeClosure" to JsonObject(
                    runtime + ("inspectArtifactImageDigest" to JsonPrimitive("sha256:${"e".repeat(64)}")),
                )
                ),
        )

        listOf(crossBuild, crossRuntime).forEach { malformed ->
            clearPair(root)
            writePair(root, canonicalReceipt(malformed), executable)
            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    root.resolve(RECEIPT_FILE),
                    root.resolve(EXECUTABLE_FILE),
                )
            }
        }
    }

    @Test
    fun `verifier rejects executable cross-pairing malformed ELF extra state and wrong modes`() =
        withPairDirectory { root ->
            val executable = systemElf()
            val receipt = canonicalReceipt(receiptDocument(executable))
            val wrongExecutable = executable.copyOf().also { bytes -> bytes[0] = 0 }

            writePair(root, receipt, wrongExecutable)
            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    root.resolve(RECEIPT_FILE),
                    root.resolve(EXECUTABLE_FILE),
                )
            }

            clearPair(root)
            writePair(root, receipt, executable)
            Files.writeString(root.resolve("unexpected"), "residue")
            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    root.resolve(RECEIPT_FILE),
                    root.resolve(EXECUTABLE_FILE),
                )
            }
            Files.delete(root.resolve("unexpected"))

            Files.setPosixFilePermissions(
                root.resolve(EXECUTABLE_FILE),
                PosixFilePermissions.fromString("rwx------"),
            )
            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    root.resolve(RECEIPT_FILE),
                    root.resolve(EXECUTABLE_FILE),
                )
            }
        }

    @Test
    fun `verifier rejects an ELF entry point outside memory-backed executable load segments`() =
        withPairDirectory { root ->
            val malformedExecutable = systemElf().also { bytes ->
                for (index in ELF64_ENTRY_OFFSET until ELF64_ENTRY_OFFSET + Long.SIZE_BYTES) {
                    bytes[index] = 0
                }
                bytes[ELF64_ENTRY_OFFSET] = 1
            }
            val receipt = canonicalReceipt(receiptDocument(malformedExecutable))
            writePair(root, receipt, malformedExecutable)

            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    root.resolve(RECEIPT_FILE),
                    root.resolve(EXECUTABLE_FILE),
                )
            }
        }

    @Test
    fun `verifier rejects executable byte drift at terminal descriptor authentication`() =
        withPairDirectory { root ->
            val executable = systemElf()
            val receipt = canonicalReceipt(receiptDocument(executable))
            writePair(root, receipt, executable)
            val executablePath = root.resolve(EXECUTABLE_FILE)
            val drifted = executable.copyOf().also { bytes ->
                bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            }

            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verifyWithTerminalParentFaultForTest(
                    root.resolve(RECEIPT_FILE),
                    executablePath,
                ) {
                    Files.setPosixFilePermissions(
                        executablePath,
                        PosixFilePermissions.fromString("rwx------"),
                    )
                    Files.write(executablePath, drifted)
                    Files.setPosixFilePermissions(
                        executablePath,
                        PosixFilePermissions.fromString("r-x------"),
                    )
                }
            }
        }

    @Test
    fun `verifier rejects lexical parent replacement after descriptor-pinned pair checks`() {
        val container = createTempDirectory("hosted-pair-parent-race-").toAbsolutePath().normalize()
        val active = container.resolve("active")
        val displaced = container.resolve("displaced")
        Files.createDirectory(active)
        Files.setPosixFilePermissions(active, PosixFilePermissions.fromString("rwx------"))
        val executable = systemElf()
        val receipt = canonicalReceipt(receiptDocument(executable))
        writePair(active, receipt, executable)

        try {
            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verifyWithTerminalParentFaultForTest(
                    active.resolve(RECEIPT_FILE),
                    active.resolve(EXECUTABLE_FILE),
                ) {
                    Files.move(active, displaced)
                    Files.createDirectory(active)
                    Files.setPosixFilePermissions(active, PosixFilePermissions.fromString("rwx------"))
                    writePair(active, receipt, executable)
                }
            }
        } finally {
            listOf(active, displaced).forEach { directory ->
                clearPair(directory)
                Files.deleteIfExists(directory)
            }
            Files.deleteIfExists(container)
        }
    }

    @Test
    fun `verifier rejects noncanonical receipt and schema identity substitution`() = withPairDirectory { root ->
        val executable = systemElf()
        val document = receiptDocument(executable)
        val schema = document.getValue("schema") as JsonObject
        val wrongSchema = JsonObject(
            document + ("schema" to JsonObject(schema + ("sha256" to JsonPrimitive("0".repeat(64))))),
        )
        listOf(
            canonicalReceipt(document) + byteArrayOf('\n'.code.toByte()),
            canonicalReceipt(wrongSchema),
        ).forEach { malformed ->
            clearPair(root)
            writePair(root, malformed, executable)
            assertFailsWith<LlvmBehaviorHostedCleanBuildV2VerificationException> {
                LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                    root.resolve(RECEIPT_FILE),
                    root.resolve(EXECUTABLE_FILE),
                )
            }
        }
    }

    @Test
    fun `public verifier accepts only two raw paths`() {
        val methods = LlvmBehaviorHostedCleanBuildV2Verifier::class.java.declaredMethods
            .filter { it.name == "verify" && !it.isSynthetic }
        assertEquals(1, methods.size)
        assertEquals(listOf(Path::class.java, Path::class.java), methods.single().parameterTypes.toList())
    }

    @Test
    fun `reviewed hosted receipt schema identity is pinned`() {
        assertEquals(
            "b7b00bdf9f14e119b353f905fe05c7a45adbca7730a3cec6b5688e1ad5b310b9",
            OracleSchemas.identity(SCHEMA_NAME).sha256,
        )
    }

    private fun receiptDocument(executable: ByteArray): JsonObject {
        val executableSha256 = OracleArtifacts.sha256(executable)
        val inspectDigest = "sha256:${"a".repeat(64)}"
        val sourceRevision = "3".repeat(64)
        val buildOne = buildDocument(1, sourceRevision, executable.size.toLong(), executableSha256)
        val buildTwo = buildDocument(2, sourceRevision, executable.size.toLong(), executableSha256)
        return obj(
            "schemaVersion" to JsonPrimitive(2),
            "kind" to JsonPrimitive(SCHEMA_NAME),
            "authority" to JsonPrimitive("kotlin-jvm-unsigned-inner-clean-build-worker-v2"),
            "schema" to obj(
                "name" to JsonPrimitive(SCHEMA_NAME),
                "sha256" to JsonPrimitive(OracleSchemas.identity(SCHEMA_NAME).sha256),
            ),
            "archive" to obj(
                "bytes" to JsonPrimitive(1024),
                "sha256" to JsonPrimitive("1".repeat(64)),
                "archiveManifestBytes" to JsonPrimitive(128),
                "archiveManifestSha256" to JsonPrimitive("2".repeat(64)),
                "sourceTreeManifestBytes" to JsonPrimitive(96),
                "sourceTreeManifestSha256" to JsonPrimitive("4".repeat(64)),
                "verified" to JsonPrimitive(true),
            ),
            "candidateLineageIndex" to obj(
                "schemaVersion" to JsonPrimitive(2),
                "bytes" to JsonPrimitive(512),
                "sha256" to JsonPrimitive("5".repeat(64)),
                "candidateSourceLineageSha256" to JsonPrimitive("6".repeat(64)),
                "acceptedAcp" to obj(
                    "receiptSchemaVersion" to JsonPrimitive(2),
                    "count" to JsonPrimitive(1),
                    "reconstructionCount" to JsonPrimitive(1),
                    "repairCount" to JsonPrimitive(0),
                    "aggregateAlgorithm" to JsonPrimitive(
                        "domain-separated-length-prefixed-sorted-leaves-v2",
                    ),
                    "receiptSetSha256" to JsonPrimitive("7".repeat(64)),
                    "sessionSetSha256" to JsonPrimitive("8".repeat(64)),
                    "changeSetSha256" to JsonPrimitive("9".repeat(64)),
                    "lineageSetSha256" to JsonPrimitive("a".repeat(64)),
                ),
            ),
            "source" to obj(
                "profileId" to JsonPrimitive(GeneratedCMakeReconstructionProfile.PROFILE_ID),
                "profileSha256" to JsonPrimitive(GeneratedCMakeReconstructionProfile.descriptor.sha256),
                "revisionAlgorithm" to JsonPrimitive("length-prefixed-path-bytes-sha256-v1"),
                "inputCount" to JsonPrimitive(2),
                "revisionSha256" to JsonPrimitive(sourceRevision),
            ),
            "lockedToolchain" to obj(
                "sourceLockSha256" to JsonPrimitive(
                    "179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306",
                ),
                "reproductionLockSha256" to JsonPrimitive(
                    "14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f",
                ),
                "dockerfileSha256" to JsonPrimitive(
                    "97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291",
                ),
                "buildRecordSha256" to JsonPrimitive(
                    "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005",
                ),
                "recordedOriginImageDigest" to JsonPrimitive(
                    "sha256:73285d9a2dad159a7171fe4bbcac7d97d285402955d8c6fb8b44b101cf2df550",
                ),
                "inspectArtifactImageDigest" to JsonPrimitive(inspectDigest),
                "platform" to JsonPrimitive("linux/amd64"),
                "SOURCE_DATE_EPOCH" to JsonPrimitive("1779182222"),
                "compiler" to toolDocument(
                    "compiler",
                    "/usr/lib/llvm-22/bin/clang",
                    138184,
                    "9dff149140cff7484c1efd85a5cfe0e3f046edcf71c63b42b5501c4a2ee462ae",
                    "d6d146c61f5ba14a74f0cb00885d4068a7f1b41c88880f93d7c65187efb625ea",
                ),
                "linker" to toolDocument(
                    "linker",
                    "/usr/lib/llvm-22/bin/lld",
                    6059960,
                    "057e42c6104e20a7358a51fb9abb456d74ba37997331d99183e877539da95982",
                    "0b47969becd48b365d7fa9302efe7f9191742b5a3d761d008c5cf67132e78451",
                ),
            ),
            "cleanBuilds" to JsonArray(listOf(buildOne, buildTwo)),
            "candidateExecutable" to obj(
                "name" to JsonPrimitive(EXECUTABLE_FILE),
                "format" to JsonPrimitive("ELF"),
                "elfClass" to JsonPrimitive("ELF64"),
                "endianness" to JsonPrimitive("little-endian"),
                "machine" to JsonPrimitive("x86-64"),
                "bytes" to JsonPrimitive(executable.size),
                "sha256" to JsonPrimitive(executableSha256),
                "identicalAcrossBuilds" to JsonPrimitive(true),
            ),
            "runtimeClosure" to obj(
                "kind" to JsonPrimitive("container-image-closure"),
                "inspectArtifactImageDigest" to JsonPrimitive(inspectDigest),
                "platform" to JsonPrimitive("linux/amd64"),
                "buildCount" to JsonPrimitive(2),
                "authenticated" to JsonPrimitive(false),
            ),
            "attestationBoundary" to obj(
                "producerReceipt" to JsonPrimitive("unsigned-kotlin-jvm-facts"),
                "requiredMode" to JsonPrimitive("github-actions-default-slsa-v1-two-subjects"),
                "requiredSubjects" to JsonArray(
                    listOf(JsonPrimitive(RECEIPT_FILE), JsonPrimitive(EXECUTABLE_FILE)),
                ),
                "hostedWorkflowAuthenticated" to JsonPrimitive(false),
                "sigstoreBundleVerified" to JsonPrimitive(false),
            ),
            "acpBoundary" to acpBoundary(),
            "claims" to claims(),
        )
    }

    private fun buildDocument(
        ordinal: Int,
        sourceRevision: String,
        executableBytes: Long,
        executableSha256: String,
    ): JsonObject = obj(
        "ordinal" to JsonPrimitive(ordinal),
        "extractionMode" to JsonPrimitive("verified-archive-private-clean-extraction"),
        "compilerMode" to JsonPrimitive("direct-clang-per-source"),
        "linkerMode" to JsonPrimitive("direct-clang"),
        "makefileExecuted" to JsonPrimitive(false),
        "buildContractTrusted" to JsonPrimitive(false),
        "sourceRevisionSha256" to JsonPrimitive(sourceRevision),
        "sourceCount" to JsonPrimitive(2),
        "buildEnvironmentSha256" to JsonPrimitive("b".repeat(64)),
        "compileCommandSetSha256" to JsonPrimitive("c".repeat(64)),
        "dependencyCount" to JsonPrimitive(3),
        "dependencySetSha256" to JsonPrimitive("d".repeat(64)),
        "objectSetSha256" to JsonPrimitive("e".repeat(64)),
        "linkCommandSha256" to JsonPrimitive("1".repeat(64)),
        "linkDependencyCount" to JsonPrimitive(8),
        "linkDependencySetSha256" to JsonPrimitive("2".repeat(64)),
        "combinedOutputBytes" to JsonPrimitive(0),
        "combinedOutputSha256" to JsonPrimitive(OracleArtifacts.sha256(byteArrayOf())),
        "executableBytes" to JsonPrimitive(executableBytes),
        "executableSha256" to JsonPrimitive(executableSha256),
    )

    private fun toolDocument(
        role: String,
        path: String,
        bytes: Long,
        sha256: String,
        versionOutputSha256: String,
    ): JsonObject = obj(
        "role" to JsonPrimitive(role),
        "path" to JsonPrimitive(path),
        "bytes" to JsonPrimitive(bytes),
        "sha256" to JsonPrimitive(sha256),
        "versionOutputSha256" to JsonPrimitive(versionOutputSha256),
    )

    private fun acpBoundary(): JsonObject = obj(
        "role" to JsonPrimitive("first-class-candidate-producer-operator"),
        "candidateContribution" to JsonPrimitive("authenticated-session-change-provenance"),
        "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
        "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
        "candidateLiveExecutionOwner" to JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
        "referenceSubjectAdmission" to JsonPrimitive("kotlin-jvm-host-only"),
        "oracleAuthority" to JsonPrimitive(false),
        "referenceAuthoringAuthority" to JsonPrimitive(false),
        "policyAuthoringAuthority" to JsonPrimitive(false),
        "validationAuthority" to JsonPrimitive(false),
        "observationAuthoringAuthority" to JsonPrimitive(false),
        "startAuthority" to JsonPrimitive(false),
        "containmentAuthority" to JsonPrimitive(false),
        "terminalAbsenceAuthority" to JsonPrimitive(false),
        "scoringAuthority" to JsonPrimitive(false),
        "certificationAuthority" to JsonPrimitive(false),
        "releaseAuthority" to JsonPrimitive(false),
    )

    private fun claims(): JsonObject = obj(
        "verifiedArchiveBound" to JsonPrimitive(true),
        "candidateLineageBound" to JsonPrimitive(true),
        "sourceRevisionBound" to JsonPrimitive(true),
        "lockedToolchainBound" to JsonPrimitive(true),
        "runtimeInspectArtifactParsed" to JsonPrimitive(true),
        "runtimeImageInspected" to JsonPrimitive(false),
        "runtimeClosureAuthenticated" to JsonPrimitive(false),
        "twoCleanBuildsCompleted" to JsonPrimitive(true),
        "executableReproduced" to JsonPrimitive(true),
        "hostedWorkflowAuthenticated" to JsonPrimitive(false),
        "sigstoreBundleVerified" to JsonPrimitive(false),
        "admittedArtifactBound" to JsonPrimitive(false),
        "prepared" to JsonPrimitive(false),
        "liveRuntimeIdentityVerified" to JsonPrimitive(false),
        "liveContainmentVerified" to JsonPrimitive(false),
        "terminalAbsenceVerified" to JsonPrimitive(false),
        "observationsCaptured" to JsonPrimitive(false),
        "startAuthorized" to JsonPrimitive(false),
        "candidateStarted" to JsonPrimitive(false),
        "candidateExecuted" to JsonPrimitive(false),
        "oracleAuthority" to JsonPrimitive(false),
        "referenceAuthoringAuthority" to JsonPrimitive(false),
        "referenceTruthEstablished" to JsonPrimitive(false),
        "scoringAuthority" to JsonPrimitive(false),
        "certificationAuthority" to JsonPrimitive(false),
        "releaseAuthority" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false),
    )

    private fun canonicalReceipt(document: JsonObject): ByteArray =
        OracleJson.canonicalBytes(document, RECEIPT_LIMITS)

    private fun writePair(root: Path, receipt: ByteArray, executable: ByteArray) {
        Files.write(root.resolve(EXECUTABLE_FILE), executable)
        Files.setPosixFilePermissions(
            root.resolve(EXECUTABLE_FILE),
            PosixFilePermissions.fromString("r-x------"),
        )
        Files.write(root.resolve(RECEIPT_FILE), receipt)
        Files.setPosixFilePermissions(
            root.resolve(RECEIPT_FILE),
            PosixFilePermissions.fromString("r--------"),
        )
    }

    private fun systemElf(): ByteArray {
        val path = Path.of("/bin/true").toRealPath()
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        return Files.readAllBytes(path)
    }

    private inline fun withPairDirectory(action: (Path) -> Unit) {
        val root = createTempDirectory("hosted-pair-verifier-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            clearPair(root)
            Files.deleteIfExists(root)
        }
    }

    private fun clearPair(root: Path) {
        if (!Files.exists(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.list(root).use { entries -> entries.toList() }.forEach(Files::deleteIfExists)
    }

    private fun obj(vararg values: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*values))

    private companion object {
        const val SCHEMA_NAME = "llvm-behavior-hosted-clean-build-v2"
        const val RECEIPT_FILE = "candidate-hosted-clean-build-v2.json"
        const val EXECUTABLE_FILE = "candidate-reconstructed"
        const val ELF64_ENTRY_OFFSET = 24
        val RECEIPT_LIMITS = StrictJsonLimits(
            maximumInputBytes = 128 * 1024,
            maximumCanonicalBytes = 128 * 1024,
            maximumDepth = 20,
            maximumNodes = 1024,
            maximumStringBytes = 4096,
            maximumTotalStringBytes = 64 * 1024,
        )
    }
}
