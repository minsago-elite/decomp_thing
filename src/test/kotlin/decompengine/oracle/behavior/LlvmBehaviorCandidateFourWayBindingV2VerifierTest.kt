package decompengine.oracle.behavior

import decompengine.acp.ACP_KOTLIN_SDK_VERSION
import decompengine.acp.ACP_STABLE_PROTOCOL_VERSION
import decompengine.acp.AcpExecutionCleanupDisposition
import decompengine.acp.AcpExecutionEvidenceCompleteness
import decompengine.acp.AcpExecutionEvidenceSnapshot
import decompengine.acp.AcpExecutionLifecyclePhase
import decompengine.acp.AcpHarnessProvenance
import decompengine.acp.AcpInvocationEvidenceSnapshot
import decompengine.acp.AcpNegotiatedAgentEvidence
import decompengine.acp.AcpNegotiatedCapabilitiesEvidence
import decompengine.acp.AcpProcessDiagnostics
import decompengine.acp.AcpProducedOutputEvidence
import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.AcpSandboxEvidence
import decompengine.acp.AcpSandboxResourceLimits
import decompengine.agent.AgentExecutionEvent
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentExecutionResult
import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeEvent
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentHarness
import decompengine.agent.AgentMessageEvent
import decompengine.agent.AgentMessageRole
import decompengine.agent.AgentSessionReference
import decompengine.agent.AgentStopReason
import decompengine.agent.AgentUsage
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ArchivalPackager
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.MakeProjectBuilder
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import decompengine.project.SourceTreeGenerator
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class LlvmBehaviorCandidateFourWayBindingV2VerifierTest {
    @Test
    fun `four raw paths derive one defensive first-class ACP structural identity with no authority`() {
        val root = createTempDirectory("candidate-four-way-v2-success-").toAbsolutePath().normalize()
        val fixture = createFixture(root, "alpha", "/bin/true")

        val verified = verify(fixture)

        assertEquals(2, verified.schemaVersion)
        assertEquals("kotlin-jvm-candidate-four-way-structural-binding-v2", verified.verificationKind)
        assertEquals(64, verified.candidateStructuralIdentitySha256.length)
        assertEquals(sha256(verified.canonicalBindingBytes), verified.candidateStructuralIdentitySha256)
        assertEquals(fixture.archiveBytes.size.toLong(), verified.archiveBytes)
        assertEquals(sha256(fixture.archiveBytes), verified.archiveSha256)
        assertEquals(fixture.lineageBytes.size.toLong(), verified.lineageIndexBytes)
        assertEquals(sha256(fixture.lineageBytes), verified.lineageIndexSha256)
        assertEquals(fixture.receiptBytes.size.toLong(), verified.hostedReceiptBytes)
        assertEquals(sha256(fixture.receiptBytes), verified.hostedReceiptSha256)
        assertEquals(fixture.executableBytes.size.toLong(), verified.executableBytes)
        assertEquals(sha256(fixture.executableBytes), verified.executableSha256)
        assertTrue(verified.exactFourWayStructuralBinding)
        assertTrue(verified.acpRequired)
        assertTrue(verified.acpFirstClassCandidateProducerOperator)
        listOf(
            verified.acpOracleAuthority,
            verified.acpReferenceAuthoringAuthority,
            verified.acpPolicyAuthoringAuthority,
            verified.acpValidationAuthority,
            verified.acpObservationAuthoringAuthority,
            verified.acpStartAuthority,
            verified.acpContainmentAuthority,
            verified.acpTerminalAbsenceAuthority,
            verified.acpScoringAuthority,
            verified.acpCertificationAuthority,
            verified.acpReleaseAuthority,
            verified.hostedBuildExecutionAuthenticated,
            verified.admittedArtifactBound,
            verified.prepared,
            verified.startAuthorized,
            verified.candidateStarted,
            verified.scoringAuthority,
            verified.certificationAuthority,
            verified.releaseEligible,
        ).forEach(::assertFalse)

        val exposedLineage = verified.canonicalLineageIndexBytes
        val exposedReceipt = verified.canonicalHostedReceiptBytes
        val exposedBinding = verified.canonicalBindingBytes
        exposedLineage.fill(0)
        exposedReceipt.fill(0)
        exposedBinding.fill(0)
        assertContentEquals(fixture.lineageBytes, verified.canonicalLineageIndexBytes)
        assertContentEquals(fixture.receiptBytes, verified.canonicalHostedReceiptBytes)
        assertEquals(verified.candidateStructuralIdentitySha256, sha256(verified.canonicalBindingBytes))
        assertEquals(
            verified.candidateStructuralIdentitySha256,
            verify(fixture).candidateStructuralIdentitySha256,
        )
    }

    @Test
    fun `archive lineage hosted receipt and executable cannot be cross-paired`() {
        val root = createTempDirectory("candidate-four-way-v2-cross-pair-").toAbsolutePath().normalize()
        val first = createFixture(root, "first", "/bin/true")
        val second = createFixture(root, "second", "/bin/false")
        assertNotEquals(
            verify(first).candidateStructuralIdentitySha256,
            verify(second).candidateStructuralIdentitySha256,
        )

        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            LlvmBehaviorCandidateFourWayBindingV2Verifier.verify(
                first.archive,
                first.lineageIndex,
                second.hostedReceipt,
                second.executable,
            )
        }
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            LlvmBehaviorCandidateFourWayBindingV2Verifier.verify(
                first.archive,
                second.lineageIndex,
                second.hostedReceipt,
                second.executable,
            )
        }

        val crossPair = root.resolve("hosted-cross-pair").createDirectories()
        Files.setPosixFilePermissions(crossPair, OWNER_DIRECTORY_PERMISSIONS)
        writeImmutable(crossPair.resolve(HOSTED_RECEIPT_FILE), first.receiptBytes, OWNER_READ_ONLY_PERMISSIONS)
        writeImmutable(crossPair.resolve(EXECUTABLE_FILE), second.executableBytes, OWNER_READ_EXECUTE_PERMISSIONS)
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            LlvmBehaviorCandidateFourWayBindingV2Verifier.verify(
                first.archive,
                first.lineageIndex,
                crossPair.resolve(HOSTED_RECEIPT_FILE),
                crossPair.resolve(EXECUTABLE_FILE),
            )
        }
    }

    @Test
    fun `unsigned hosted session change and lineage association drift is rejected after pair verification`() {
        val root = createTempDirectory("candidate-four-way-v2-acp-drift-").toAbsolutePath().normalize()
        val fixture = createFixture(root, "drift", "/bin/true")
        val lineage = parseObject(fixture.lineageBytes)
        val accepted = lineage.getValue("acceptedAcp").jsonObject

        listOf("sessionSetSha256", "changeSetSha256", "lineageSetSha256").forEach { field ->
            val original = accepted.getValue(field).jsonPrimitive.content
            val replacement = (if (original.first() == '0') "1" else "0") + original.drop(1)
            val receipt = OracleJson.parseCanonical(fixture.receiptBytes, HOSTED_RECEIPT_LIMITS).jsonObject
            val receiptLineage = receipt.getValue("candidateLineageIndex").jsonObject
            val receiptAccepted = receiptLineage.getValue("acceptedAcp").jsonObject
            val mutated = OracleJson.canonicalBytes(
                JsonObject(
                    receipt + (
                        "candidateLineageIndex" to JsonObject(
                            receiptLineage + (
                                "acceptedAcp" to JsonObject(
                                    receiptAccepted + (field to JsonPrimitive(replacement)),
                                )
                                ),
                        )
                        ),
                ),
                HOSTED_RECEIPT_LIMITS,
            )
            assertNotEquals(fixture.receiptBytes.toList(), mutated.toList(), field)
            replaceImmutable(fixture.hostedReceipt, mutated, OWNER_READ_ONLY_PERMISSIONS)

            val pairOnly = LlvmBehaviorHostedCleanBuildV2Verifier.verify(
                fixture.hostedReceipt,
                fixture.executable,
            )
            assertFalse(pairOnly.candidateLineageAuthenticated, field)
            assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception>(field) { verify(fixture) }
        }
    }

    @Test
    fun `canonical bounds aliases and terminal source replacement are rejected`() {
        val root = createTempDirectory("candidate-four-way-v2-hostile-").toAbsolutePath().normalize()
        val fixture = createFixture(root, "hostile", "/bin/true")

        replaceImmutable(
            fixture.hostedReceipt,
            fixture.receiptBytes + byteArrayOf('\n'.code.toByte()),
            OWNER_READ_ONLY_PERMISSIONS,
        )
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> { verify(fixture) }

        replaceImmutable(
            fixture.hostedReceipt,
            ByteArray(128 * 1024 + 1) { 'x'.code.toByte() },
            OWNER_READ_ONLY_PERMISSIONS,
        )
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> { verify(fixture) }
        replaceImmutable(fixture.hostedReceipt, fixture.receiptBytes, OWNER_READ_ONLY_PERMISSIONS)

        val archiveAlias = root.resolve("archive-alias.zip")
        Files.createSymbolicLink(archiveAlias, fixture.archive)
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            LlvmBehaviorCandidateFourWayBindingV2Verifier.verify(
                archiveAlias,
                fixture.lineageIndex,
                fixture.hostedReceipt,
                fixture.executable,
            )
        }

        val displaced = root.resolve("hosted-displaced")
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            verifyWithPrivateMutationSeams(
                fixture.archive,
                fixture.lineageIndex,
                fixture.hostedReceipt,
                fixture.executable,
                beforeTerminalSourceAuthentication = {
                    Files.move(fixture.hostedReceipt.parent, displaced)
                    Files.createDirectory(fixture.hostedReceipt.parent)
                    Files.setPosixFilePermissions(fixture.hostedReceipt.parent, OWNER_DIRECTORY_PERMISSIONS)
                    writeImmutable(fixture.hostedReceipt, fixture.receiptBytes, OWNER_READ_ONLY_PERMISSIONS)
                    writeImmutable(fixture.executable, fixture.executableBytes, OWNER_READ_EXECUTE_PERMISSIONS)
                },
            )
        }
    }

    @Test
    fun `raw names and parents cannot be replaced after descriptor pinning`() {
        val root = createTempDirectory("candidate-four-way-v2-open-race-").toAbsolutePath().normalize()
        val fileFixture = createFixture(root, "file-race", "/bin/true")
        val archivePermissions = Files.getPosixFilePermissions(fileFixture.archive)
        val displacedArchive = root.resolve("candidate-file-race-displaced.zip")

        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            verifyWithPrivateMutationSeams(
                fileFixture.archive,
                fileFixture.lineageIndex,
                fileFixture.hostedReceipt,
                fileFixture.executable,
                rawOpenFaultInjector = { point ->
                    if (point == "AFTER_ARCHIVE_PINNED") {
                        Files.move(fileFixture.archive, displacedArchive)
                        writeImmutable(fileFixture.archive, fileFixture.archiveBytes, archivePermissions)
                    }
                },
            )
        }

        val parentFixture = createFixture(root, "parent-race", "/bin/false")
        val displacedHostedParent = root.resolve("hosted-parent-race-displaced")
        assertFailsWith<LlvmBehaviorCandidateFourWayBindingV2Exception> {
            verifyWithPrivateMutationSeams(
                parentFixture.archive,
                parentFixture.lineageIndex,
                parentFixture.hostedReceipt,
                parentFixture.executable,
                rawOpenFaultInjector = { point ->
                    if (point == "AFTER_PARENTS_PINNED") {
                        Files.move(parentFixture.hostedReceipt.parent, displacedHostedParent)
                        Files.createDirectory(parentFixture.hostedReceipt.parent)
                        Files.setPosixFilePermissions(
                            parentFixture.hostedReceipt.parent,
                            OWNER_DIRECTORY_PERMISSIONS,
                        )
                        writeImmutable(
                            parentFixture.hostedReceipt,
                            parentFixture.receiptBytes,
                            OWNER_READ_ONLY_PERMISSIONS,
                        )
                        writeImmutable(
                            parentFixture.executable,
                            parentFixture.executableBytes,
                            OWNER_READ_EXECUTE_PERMISSIONS,
                        )
                    }
                },
            )
        }
    }

    @Test
    fun `verifier surface accepts only four raw paths and no legacy admission artifacts`() {
        val verifierClass = LlvmBehaviorCandidateFourWayBindingV2Verifier::class.java
        val methods = verifierClass.declaredMethods.filter { method ->
            Modifier.isPublic(method.modifiers) || Modifier.isProtected(method.modifiers)
        }
        assertEquals(1, methods.size)
        assertEquals("verify", methods.single().name)
        assertFalse(methods.single().isSynthetic)
        assertEquals(List(4) { Path::class.java }, methods.single().parameterTypes.toList())
        val forbidden = listOf("corpus", "report", "matrix", "manifest", "admission", "v1")
        assertTrue(methods.single().parameterTypes.all { it == Path::class.java })
        assertTrue(
            LlvmBehaviorCandidateFourWayBindingV2Verification::class.java.declaredMethods.none { method ->
                forbidden.any { marker -> marker in method.name.lowercase() }
            },
        )

        val resultContract = LlvmBehaviorCandidateFourWayBindingV2Verification::class.java
        assertEquals(resultContract, methods.single().returnType)
        val fileFacade = Class.forName(
            "decompengine.oracle.behavior.LlvmBehaviorCandidateFourWayBindingV2VerifierKt",
        )
        assertTrue(
            fileFacade.declaredMethods.none { method ->
                (Modifier.isPublic(method.modifiers) || Modifier.isProtected(method.modifiers)) &&
                    resultContract.isAssignableFrom(method.returnType)
            },
        )
        val forbiddenSyntheticFactories = setOf("access\$verifiedResult", "access\$verifyFourWay")
        assertTrue(
            (verifierClass.declaredMethods + fileFacade.declaredMethods).none { method ->
                method.name in forbiddenSyntheticFactories
            },
        )
        assertTrue(resultContract.isSealed)
        val implementations = resultContract.permittedSubclasses.toList()
        assertEquals(1, implementations.size)
        val implementation = implementations.single()
        assertEquals(LlvmBehaviorCandidateFourWayBindingV2Verifier::class.java, implementation.enclosingClass)
        assertTrue(Modifier.isPrivate(implementation.modifiers))
        val constructor = implementation.declaredConstructors.single()
        assertTrue(Modifier.isPrivate(constructor.modifiers))
        assertFalse(constructor.isSynthetic)
        assertTrue(
            implementation.declaredMethods.none { method ->
                resultContract.isAssignableFrom(method.returnType)
            },
        )
    }

    private fun verifyWithPrivateMutationSeams(
        archivePath: Path,
        lineageIndexPath: Path,
        hostedReceiptPath: Path,
        executablePath: Path,
        beforeTerminalSourceAuthentication: () -> Unit = {},
        rawOpenFaultInjector: ((String) -> Unit)? = null,
    ): LlvmBehaviorCandidateFourWayBindingV2Verification {
        val privateVerify = LlvmBehaviorCandidateFourWayBindingV2Verifier::class.java.declaredMethods.single {
            it.name == "verifyFourWay" && Modifier.isPrivate(it.modifiers) && it.parameterCount == 6
        }
        assertTrue(privateVerify.trySetAccessible())
        val reflectedFaultInjector: ((Any) -> Unit)? = rawOpenFaultInjector?.let { inject ->
            { point -> inject((point as Enum<*>).name) }
        }
        return try {
            @Suppress("UNCHECKED_CAST")
            privateVerify.invoke(
                LlvmBehaviorCandidateFourWayBindingV2Verifier,
                archivePath,
                lineageIndexPath,
                hostedReceiptPath,
                executablePath,
                beforeTerminalSourceAuthentication,
                reflectedFaultInjector,
            ) as LlvmBehaviorCandidateFourWayBindingV2Verification
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private fun createFixture(root: Path, id: String, elfPath: String): FourWayFixture {
        val project = root.resolve("project-$id")
        val harness = FourWayEvidenceHarness(id)
        SourceTreeGenerator.generate(
            RecoveredProgramModel(
                inputSha256 = sha256("input-$id".toByteArray()),
                functions = listOf(
                    RecoveredFunction(
                        "fn_0000000000401000",
                        "parse_input",
                        0x401000UL,
                        "int parse_input(void)",
                    ),
                ),
            ),
            project,
            reconstructor = BoundedLlmModuleReconstructor(
                harness,
                harnessProvenanceDescriptor = harness.factoryProvenance.stableDescriptor,
            ),
        )
        assertEquals(0, MakeProjectBuilder.build(project).returnCode)
        val archive = ArchivalPackager.create(project, root.resolve("candidate-$id.zip")).archivePath
        val lineageParent = root.resolve("lineage-$id").createDirectories()
        Files.setPosixFilePermissions(lineageParent, OWNER_DIRECTORY_PERMISSIONS)
        val lineageIndex = lineageParent.resolve(LINEAGE_INDEX_FILE)
        LlvmBehaviorCandidateAcpLineageIndexV2Publisher.publish(archive, lineageIndex)
        val lineageBytes = Files.readAllBytes(lineageIndex)

        val executableBytes = Files.readAllBytes(Path.of(elfPath).toRealPath())
        val receiptBytes = canonicalHostedReceipt(parseObject(lineageBytes), executableBytes)
        val hostedParent = root.resolve("hosted-$id").createDirectories()
        Files.setPosixFilePermissions(hostedParent, OWNER_DIRECTORY_PERMISSIONS)
        val hostedReceipt = hostedParent.resolve(HOSTED_RECEIPT_FILE)
        val executable = hostedParent.resolve(EXECUTABLE_FILE)
        writeImmutable(hostedReceipt, receiptBytes, OWNER_READ_ONLY_PERMISSIONS)
        writeImmutable(executable, executableBytes, OWNER_READ_EXECUTE_PERMISSIONS)
        return FourWayFixture(
            archive,
            Files.readAllBytes(archive),
            lineageIndex,
            lineageBytes,
            hostedReceipt,
            receiptBytes,
            executable,
            executableBytes,
        )
    }

    private fun canonicalHostedReceipt(lineage: JsonObject, executable: ByteArray): ByteArray {
        val archive = lineage.getValue("archive").jsonObject
        val source = lineage.getValue("source").jsonObject
        val accepted = lineage.getValue("acceptedAcp").jsonObject
        val executableSha256 = sha256(executable)
        val inspectDigest = "sha256:${"a".repeat(64)}"
        val sourceRevision = source.getValue("revisionSha256").jsonPrimitive.content
        val sourceCount = source.getValue("inputCount").jsonPrimitive.content.toLong()
        val buildOne = buildDocument(1, sourceRevision, sourceCount, executable.size.toLong(), executableSha256)
        val buildTwo = buildDocument(2, sourceRevision, sourceCount, executable.size.toLong(), executableSha256)
        val document = obj(
            "schemaVersion" to JsonPrimitive(2),
            "kind" to JsonPrimitive(HOSTED_RECEIPT_SCHEMA),
            "authority" to JsonPrimitive("kotlin-jvm-unsigned-inner-clean-build-worker-v2"),
            "schema" to obj(
                "name" to JsonPrimitive(HOSTED_RECEIPT_SCHEMA),
                "sha256" to JsonPrimitive(OracleSchemas.identity(HOSTED_RECEIPT_SCHEMA).sha256),
            ),
            "archive" to obj(
                "bytes" to archive.getValue("bytes"),
                "sha256" to archive.getValue("sha256"),
                "archiveManifestBytes" to archive.getValue("archiveManifestBytes"),
                "archiveManifestSha256" to archive.getValue("archiveManifestSha256"),
                "sourceTreeManifestBytes" to archive.getValue("sourceTreeManifestBytes"),
                "sourceTreeManifestSha256" to archive.getValue("sourceTreeManifestSha256"),
                "verified" to JsonPrimitive(true),
            ),
            "candidateLineageIndex" to obj(
                "schemaVersion" to JsonPrimitive(2),
                "bytes" to JsonPrimitive(OracleJson.canonicalBytes(lineage, LINEAGE_LIMITS).size),
                "sha256" to JsonPrimitive(sha256(OracleJson.canonicalBytes(lineage, LINEAGE_LIMITS))),
                "candidateSourceLineageSha256" to lineage.getValue("candidateSourceLineageSha256"),
                "acceptedAcp" to accepted,
            ),
            "source" to obj(
                "profileId" to source.getValue("profileId"),
                "profileSha256" to source.getValue("profileSha256"),
                "revisionAlgorithm" to source.getValue("revisionAlgorithm"),
                "inputCount" to source.getValue("inputCount"),
                "revisionSha256" to source.getValue("revisionSha256"),
            ),
            "lockedToolchain" to lockedToolchain(inspectDigest),
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
                    listOf(JsonPrimitive(HOSTED_RECEIPT_FILE), JsonPrimitive(EXECUTABLE_FILE)),
                ),
                "hostedWorkflowAuthenticated" to JsonPrimitive(false),
                "sigstoreBundleVerified" to JsonPrimitive(false),
            ),
            "acpBoundary" to lineage.getValue("acpBoundary"),
            "claims" to hostedClaims(),
        )
        return OracleJson.canonicalBytes(document, HOSTED_RECEIPT_LIMITS)
    }

    private fun lockedToolchain(inspectDigest: String): JsonObject = obj(
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
    )

    private fun buildDocument(
        ordinal: Int,
        sourceRevision: String,
        sourceCount: Long,
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
        "sourceCount" to JsonPrimitive(sourceCount),
        "buildEnvironmentSha256" to JsonPrimitive("b".repeat(64)),
        "compileCommandSetSha256" to JsonPrimitive("c".repeat(64)),
        "dependencyCount" to JsonPrimitive(sourceCount + 1),
        "dependencySetSha256" to JsonPrimitive("d".repeat(64)),
        "objectSetSha256" to JsonPrimitive("e".repeat(64)),
        "linkCommandSha256" to JsonPrimitive("1".repeat(64)),
        "linkDependencyCount" to JsonPrimitive(sourceCount + 2),
        "linkDependencySetSha256" to JsonPrimitive("2".repeat(64)),
        "combinedOutputBytes" to JsonPrimitive(0),
        "combinedOutputSha256" to JsonPrimitive(sha256(byteArrayOf())),
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

    private fun hostedClaims(): JsonObject = obj(
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

    private fun verify(fixture: FourWayFixture): LlvmBehaviorCandidateFourWayBindingV2Verification =
        LlvmBehaviorCandidateFourWayBindingV2Verifier.verify(
            fixture.archive,
            fixture.lineageIndex,
            fixture.hostedReceipt,
            fixture.executable,
        )

    private fun parseObject(bytes: ByteArray): JsonObject =
        OracleJson.parseCanonical(bytes, LINEAGE_LIMITS) as JsonObject

    private fun writeImmutable(path: Path, bytes: ByteArray, permissions: Set<PosixFilePermission>) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, permissions)
    }

    private fun replaceImmutable(path: Path, bytes: ByteArray, permissions: Set<PosixFilePermission>) {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, permissions)
    }

    private fun obj(vararg values: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*values))

    private class FourWayEvidenceHarness(id: String) : AgentHarness {
        private val implementationId = "four-way-test-acp-$id"
        private var evidence: AcpExecutionEvidenceSnapshot? = null
        private lateinit var requestBinding: AgentExecutionRequestBinding
        val factoryProvenance = AcpHarnessProvenance(
            harness = "acp",
            implementationId = implementationId,
            agentExecutionContractVersion = 1,
            acpProtocolVersion = ACP_STABLE_PROTOCOL_VERSION,
            acpSdkVersion = ACP_KOTLIN_SDK_VERSION,
            configurationSha256 = sha256("configuration-$id".toByteArray()),
            deprecated = false,
        )

        override fun implementationIdentifier(): String = implementationId

        override fun execute(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionResult {
            requestBinding = AgentExecutionRequestBinding.capture(request)
            val target = request.accessPolicy.pathRules.single { rule ->
                decompengine.agent.AgentOperation.WRITE_FILE in rule.operations
            }.path
            val source = """
                #include "modules/parse.h"
                /* fn_0000000000401000 */
                int parse_input(void) { return 17; }
            """.trimIndent() + "\n"
            target.resolve(request.workspaceRoots).writeText(source)
            val bytes = source.toByteArray()
            val change = AgentFileChange(
                target,
                AgentFileChangeKind.CREATED,
                beforeSha256 = null,
                afterSha256 = sha256(bytes),
                sizeBytes = bytes.size.toLong(),
            )
            onEvent(AgentMessageEvent(0, "message", AgentMessageRole.ASSISTANT, "working", true))
            onEvent(AgentFileChangeEvent(1, change))
            evidence = snapshot()
            return AgentExecutionResult(
                AgentStopReason.COMPLETED,
                "complete",
                listOf(change),
                AgentSessionReference(implementationId, "session-$implementationId"),
                AgentUsage(10, 20, 3, 0, Duration.ofMillis(100)),
            )
        }

        override fun executeReceipt(
            request: AgentExecutionRequest,
            onEvent: (AgentExecutionEvent) -> Unit,
        ): AgentExecutionReceipt {
            val result = execute(request, onEvent)
            val complete = requireNotNull(evidence)
            return AgentExecutionReceipt(
                requestBinding,
                AgentExecutionOutcome.Returned(result),
                AcpInvocationEvidenceSnapshot(
                    factoryProvenance = complete.factoryProvenance,
                    phaseReached = AcpExecutionLifecyclePhase.FINAL_WORKSPACE_SNAPSHOT,
                    cleanupDisposition = AcpExecutionCleanupDisposition.VERIFIED,
                    negotiatedAgent = complete.negotiatedAgent,
                    wirePromptSha256 = complete.wirePromptSha256,
                    diagnostics = complete.diagnostics,
                    filesystemAudit = complete.filesystemAudit,
                    terminalAudit = complete.terminalAudit,
                    permissionAudit = complete.permissionAudit,
                    sandboxEvidence = complete.sandboxEvidence,
                    completeness = AcpExecutionEvidenceCompleteness(true, true, true),
                    completeExecutionEvidence = complete,
                ),
            )
        }

        private fun snapshot(): AcpExecutionEvidenceSnapshot = AcpExecutionEvidenceSnapshot(
            factoryProvenance = factoryProvenance,
            negotiatedAgent = AcpNegotiatedAgentEvidence(
                ACP_STABLE_PROTOCOL_VERSION,
                "four-way-test-agent",
                "1",
                null,
                AcpNegotiatedCapabilitiesEvidence(false, false, false, false, false, false, false),
            ),
            wirePromptSha256 = "c".repeat(64),
            diagnostics = AcpProcessDiagnostics(
                pid = 123,
                exitCode = 0,
                stderr = "",
                stderrTruncated = false,
                producedOutputBytes = 0,
                producedOutputLimitBytes = 1_024,
                outputLimitExceeded = false,
                forcedTermination = false,
                rootTerminationRequested = false,
                remainingProcessIds = emptyList(),
                containment = "linux-bubblewrap",
                networkIsolated = true,
                sandboxCleanupVerified = true,
            ),
            filesystemAudit = emptyList(),
            terminalAudit = emptyList(),
            permissionAudit = emptyList(),
            sandboxEvidence = AcpSandboxEvidence(
                provider = "sandbox-evidence-v1",
                providerVersion = "1",
                providerExecutableSha256 = "d".repeat(64),
                providerExecutableMode = 365,
                resourceLimiterSha256 = "e".repeat(64),
                scopeSupervisorSha256 = "f".repeat(64),
                scopeInspectorSha256 = "1".repeat(64),
                environmentFdOpenerSha256 = "2".repeat(64),
                securityExecutables = emptyList(),
                outerAgentLimits = AcpSandboxResourceLimits(),
                runtimeClosureLimits = AcpRuntimeClosureLimits(),
                cgroupV2PidsLimited = true,
                cgroupV2MemoryLimited = true,
                cgroupV2CpuLimited = true,
                networkIsolated = true,
                outerAgentContained = true,
                nestedUserNamespacesDisabled = true,
                newSession = true,
                dieWithParent = true,
                policySha256 = "3".repeat(64),
                terminalLimits = null,
                launches = emptyList(),
                authorities = emptyList(),
                terminalAudit = emptyList(),
                outerProcessOutput = AcpProducedOutputEvidence(1_024, 0, false),
            ),
        )
    }

    private data class FourWayFixture(
        val archive: Path,
        val archiveBytes: ByteArray,
        val lineageIndex: Path,
        val lineageBytes: ByteArray,
        val hostedReceipt: Path,
        val receiptBytes: ByteArray,
        val executable: Path,
        val executableBytes: ByteArray,
    )

    private companion object {
        const val LINEAGE_INDEX_FILE = "candidate-acp-lineage-index-v2.json"
        const val HOSTED_RECEIPT_FILE = "candidate-hosted-clean-build-v2.json"
        const val EXECUTABLE_FILE = "candidate-reconstructed"
        const val HOSTED_RECEIPT_SCHEMA = "llvm-behavior-hosted-clean-build-v2"
        val OWNER_DIRECTORY_PERMISSIONS = PosixFilePermissions.fromString("rwx------")
        val OWNER_READ_ONLY_PERMISSIONS = PosixFilePermissions.fromString("r--------")
        val OWNER_READ_EXECUTE_PERMISSIONS = PosixFilePermissions.fromString("r-x------")
        val LINEAGE_LIMITS = StrictJsonLimits(
            maximumInputBytes = 64 * 1024,
            maximumCanonicalBytes = 64 * 1024,
            maximumDepth = 16,
            maximumNodes = 512,
            maximumStringBytes = 4096,
            maximumTotalStringBytes = 32 * 1024,
        )
        val HOSTED_RECEIPT_LIMITS = StrictJsonLimits(
            maximumInputBytes = 128 * 1024,
            maximumCanonicalBytes = 128 * 1024,
            maximumDepth = 20,
            maximumNodes = 1024,
            maximumStringBytes = 4096,
            maximumTotalStringBytes = 64 * 1024,
        )

        fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256")
            .digest(bytes)
            .joinToString("") { byte -> "%02x".format(byte) }
    }
}
