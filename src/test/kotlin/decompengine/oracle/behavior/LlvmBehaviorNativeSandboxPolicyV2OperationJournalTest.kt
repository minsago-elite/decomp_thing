package decompengine.oracle.behavior

import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmBehaviorNativeSandboxPolicyV2OperationJournalTest {
    @Test
    fun `bound journal copies exact sealed validation and first class ACP requirements without authority`() =
        withFixture { fixture ->
            val validation = fixture.verify()
            open(fixture).use { owner ->
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND,
                    owner.phase,
                )
                assertEquals(
                    "non-authoritative-llvm-behavior-native-sandbox-policy-v2-operation-journal-v1",
                    owner.authority,
                )
                assertEquals(validation.authority, owner.policyAuthority)
                assertEquals(validation.schemaVersion, owner.policySchemaVersion)
                assertEquals(validation.helperPolicyDraftValidated, owner.helperPolicyDraftValidated)
                assertEquals(validation.policySha256, owner.policySha256)
                assertEquals(validation.schemaSha256, owner.schemaSha256)
                assertEquals(validation.helperBytes, owner.helperBytes)
                assertEquals(validation.helperSha256, owner.helperSha256)
                assertEquals(validation.checksumSha256, owner.checksumSha256)
                assertEquals(validation.sourceSha256, owner.sourceSha256)
                assertEquals(validation.buildRecordSha256, owner.buildRecordSha256)
                assertEquals(validation.protocol, owner.protocol)
                assertEquals(validation.helperContainerPath, owner.helperContainerPath)

                assertEquals("first-class-candidate-producer-operator", owner.acpRole)
                assertEquals(
                    "authenticated-session-change-build-artifact-provenance",
                    owner.acpCandidateContribution,
                )
                assertEquals("read-only-oracle-input", owner.acpCandidateProvenanceAccess)
                assertEquals("kotlin-jvm-host", owner.acpCandidateAdmissionOwner)
                assertEquals("separately-reviewed-kotlin-jvm-host", owner.acpCandidateLiveExecutionOwner)
                assertEquals("kotlin-jvm-host-only", owner.acpReferenceSubjectAdmission)
                assertEquals(
                    "candidate-only-required-from-authenticated-acp-session-receipt",
                    owner.candidateAcpSessionProvenance,
                )
                assertEquals(
                    "candidate-only-required-from-authenticated-acp-change-receipt",
                    owner.candidateAcpChangeProvenance,
                )
                assertEquals(
                    "candidate-only-required-from-hosted-clean-build-receipt",
                    owner.candidateAcpBuildProvenance,
                )
                assertEquals(
                    "candidate-only-required-from-kotlin-candidate-admission",
                    owner.candidateAcpArtifactProvenance,
                )
                assertAllAuthorityFalse(owner)

                assertEquals(pathSha256(fixture.journalRoot), owner.journalRootPathSha256)
                assertEquals(pathSha256(fixture.policy), owner.policyPathSha256)
                assertEquals(pathSha256(fixture.helper), owner.helperPathSha256)
                assertEquals(pathSha256(fixture.checksum), owner.checksumPathSha256)
                assertEquals(pathSha256(fixture.source), owner.helperSourcePathSha256)
                assertEquals(pathSha256(fixture.buildRecord), owner.helperBuildRecordPathSha256)

                val binding = OracleJson.parse(owner.canonicalBindingBytes) as JsonObject
                assertEquals(JsonPrimitive(owner.operationId), binding.getValue("operationId"))
                assertEquals(JsonPrimitive(owner.requestSha256), binding.getValue("requestSha256"))
                assertEquals(JsonPrimitive(owner.bindingSha256), binding.getValue("bindingSha256"))
                assertEquals(owner.bindingSha256, sha256(JsonObject(binding - "bindingSha256")))
                val callerCopy = owner.canonicalBindingBytes
                callerCopy.fill(0)
                assertFalse(callerCopy.contentEquals(owner.canonicalBindingBytes))
                assertEquals(falseClaims(), binding.getValue("claims"))
                val acp = binding.getValue("acpRequirements") as JsonObject
                assertEquals(
                    JsonObject(
                        mapOf(
                            "candidateAcpArtifactProvenance" to
                                JsonPrimitive(owner.candidateAcpArtifactProvenance),
                            "candidateAcpBuildProvenance" to JsonPrimitive(owner.candidateAcpBuildProvenance),
                            "candidateAcpChangeProvenance" to JsonPrimitive(owner.candidateAcpChangeProvenance),
                            "candidateAcpSessionProvenance" to JsonPrimitive(owner.candidateAcpSessionProvenance),
                            "candidateAdmissionOwner" to JsonPrimitive(owner.acpCandidateAdmissionOwner),
                            "candidateContribution" to JsonPrimitive(owner.acpCandidateContribution),
                            "candidateLiveExecutionOwner" to
                                JsonPrimitive(owner.acpCandidateLiveExecutionOwner),
                            "candidateProvenanceAccess" to
                                JsonPrimitive(owner.acpCandidateProvenanceAccess),
                            "certificationAuthority" to JsonPrimitive(false),
                            "containmentAuthority" to JsonPrimitive(false),
                            "observationAuthoringAuthority" to JsonPrimitive(false),
                            "oracleAuthority" to JsonPrimitive(false),
                            "policyAuthoringAuthority" to JsonPrimitive(false),
                            "referenceAuthoringAuthority" to JsonPrimitive(false),
                            "referenceSubjectAdmission" to JsonPrimitive(owner.acpReferenceSubjectAdmission),
                            "releaseAuthority" to JsonPrimitive(false),
                            "role" to JsonPrimitive(owner.acpRole),
                            "scoringAuthority" to JsonPrimitive(false),
                            "startAuthority" to JsonPrimitive(false),
                            "terminalAbsenceAuthority" to JsonPrimitive(false),
                            "validationAuthority" to JsonPrimitive(false),
                        ),
                    ),
                    acp,
                )
                assertEquals(JsonPrimitive("first-class-candidate-producer-operator"), acp.getValue("role"))
                listOf(
                    "oracleAuthority",
                    "referenceAuthoringAuthority",
                    "policyAuthoringAuthority",
                    "validationAuthority",
                    "observationAuthoringAuthority",
                    "startAuthority",
                    "containmentAuthority",
                    "terminalAbsenceAuthority",
                    "scoringAuthority",
                    "certificationAuthority",
                    "releaseAuthority",
                ).forEach { name -> assertEquals(JsonPrimitive(false), acp.getValue(name), name) }

                val directory = operationDirectory(fixture, owner.operationId)
                assertEquals(
                    setOf("binding.json", "transition-0000.json"),
                    entryNames(directory),
                )
                entryNames(directory).forEach { name -> requireImmutableFile(directory.resolve(name)) }
                val transition = OracleJson.parse(Files.readAllBytes(directory.resolve("transition-0000.json")))
                    as JsonObject
                assertEquals(JsonPrimitive("policy-draft-bound"), transition.getValue("phase"))
                assertEquals(falseClaims(), transition.getValue("claims"))
            }
        }

    @Test
    fun `ordinary close permits deterministic cold reopen and explicit terminal close is idempotent`() =
        withFixture { fixture ->
            val firstBinding: ByteArray
            val operationId: String
            open(fixture).use { owner ->
                operationId = owner.operationId
                firstBinding = owner.canonicalBindingBytes
            }

            open(fixture).use { owner ->
                assertEquals(operationId, owner.operationId)
                assertContentEquals(firstBinding, owner.canonicalBindingBytes)
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND,
                    owner.phase,
                )
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START,
                    owner.closeWithoutStart(),
                )
                val terminalHash = owner.latestTransitionSha256
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START,
                    owner.closeWithoutStart(),
                )
                assertEquals(terminalHash, owner.latestTransitionSha256)
                assertAllAuthorityFalse(owner)
            }

            open(fixture).use { owner ->
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START,
                    owner.phase,
                )
                val directory = operationDirectory(fixture, operationId)
                assertEquals(
                    setOf("binding.json", "transition-0000.json", "transition-0001.json"),
                    entryNames(directory),
                )
                val first = OracleJson.parse(Files.readAllBytes(directory.resolve("transition-0000.json")))
                    as JsonObject
                val second = OracleJson.parse(Files.readAllBytes(directory.resolve("transition-0001.json")))
                    as JsonObject
                assertEquals(JsonPrimitive(owner.operationId), first.getValue("operationId"))
                assertEquals(JsonPrimitive(owner.operationId), second.getValue("operationId"))
                assertEquals(JsonPrimitive(owner.bindingSha256), first.getValue("bindingSha256"))
                assertEquals(JsonPrimitive(owner.bindingSha256), second.getValue("bindingSha256"))
                assertEquals(
                    first.getValue("transitionSha256"),
                    JsonPrimitive(sha256(JsonObject(first - "transitionSha256"))),
                )
                assertEquals(
                    second.getValue("transitionSha256"),
                    JsonPrimitive(sha256(JsonObject(second - "transitionSha256"))),
                )
                assertEquals(first.getValue("transitionSha256"), second.getValue("previousTransitionSha256"))
                assertEquals(JsonPrimitive("closed-without-start"), second.getValue("phase"))
                assertEquals(falseClaims(), second.getValue("claims"))
            }
        }

    @Test
    fun `public JVM surface is six raw Paths and cannot represent positive execution phases`() {
        val open = LlvmBehaviorNativeSandboxPolicyV2OperationJournal::class.java.declaredMethods.single {
            it.name == "open" && !it.isSynthetic
        }
        assertTrue(Modifier.isPublic(open.modifiers))
        assertTrue(open.parameterTypes.contentEquals(Array(6) { Path::class.java }))
        assertEquals(
            setOf("open"),
            LlvmBehaviorNativeSandboxPolicyV2OperationJournal::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
                .map { it.name }
                .toSet(),
        )
        assertTrue(
            open.parameterTypes.none { type ->
                type.name.contains("Json") || type.name.contains("Digest") ||
                    type.name.contains("Runner") || type.name.contains("Admission") ||
                    type.name.contains("Preflight") || type.name.contains("Acp")
            },
        )

        val ownerType = LlvmBehaviorNativeSandboxPolicyV2OperationJournalOwner::class.java
        assertTrue(ownerType.isSealed)
        val implementations = LlvmBehaviorNativeSandboxPolicyV2OperationJournal::class.java.declaredClasses
            .filter(ownerType::isAssignableFrom)
        assertEquals(1, implementations.size)
        assertTrue(Modifier.isPrivate(implementations.single().modifiers))
        assertTrue(ownerType.permittedSubclasses.contentEquals(arrayOf(implementations.single())))
        assertTrue(implementations.single().declaredConstructors.single().parameterTypes
            .contentEquals(Array(6) { Path::class.java }))
        assertFailsWith<IllegalArgumentException> {
            Proxy.newProxyInstance(ownerType.classLoader, arrayOf(ownerType)) { _, _, _ -> null }
        }
        val expectedOwnerProperties = setOf(
            "authority",
            "operationId",
            "requestSha256",
            "bindingSha256",
            "latestTransitionSha256",
            "phase",
            "policyAuthority",
            "policySchemaVersion",
            "helperPolicyDraftValidated",
            "policySha256",
            "schemaSha256",
            "helperBytes",
            "helperSha256",
            "checksumSha256",
            "sourceSha256",
            "buildRecordSha256",
            "protocol",
            "helperContainerPath",
            "journalRootPathSha256",
            "policyPathSha256",
            "helperPathSha256",
            "checksumPathSha256",
            "helperSourcePathSha256",
            "helperBuildRecordPathSha256",
            "acpRole",
            "acpCandidateContribution",
            "acpCandidateProvenanceAccess",
            "acpCandidateAdmissionOwner",
            "acpCandidateLiveExecutionOwner",
            "acpReferenceSubjectAdmission",
            "candidateAcpSessionProvenance",
            "candidateAcpChangeProvenance",
            "candidateAcpBuildProvenance",
            "candidateAcpArtifactProvenance",
            "acpOracleAuthority",
            "acpReferenceAuthoringAuthority",
            "acpPolicyAuthoringAuthority",
            "acpValidationAuthority",
            "acpObservationAuthoringAuthority",
            "acpStartAuthority",
            "acpContainmentAuthority",
            "acpTerminalAbsenceAuthority",
            "acpScoringAuthority",
            "acpCertificationAuthority",
            "acpReleaseAuthority",
            "runtimeInputsBound",
            "candidateLineageBound",
            "prepared",
            "liveRuntimeIdentityVerified",
            "liveContainmentVerified",
            "executionClaimed",
            "referencePinned",
            "candidateStarted",
            "startAuthorized",
            "containmentAuthority",
            "terminalAbsenceAuthority",
            "observationAuthoringAuthority",
            "scoringAuthority",
            "certificationAuthority",
            "releaseEligible",
            "canonicalBindingBytes",
        )
        assertEquals(
            expectedOwnerProperties.mapTo(mutableSetOf()) { name ->
                "get${name.replaceFirstChar(Char::uppercaseChar)}"
            } + setOf("close", "closeWithoutStart"),
            ownerType.declaredMethods.filterNot { it.isSynthetic }.map { it.name }.toSet(),
        )

        assertEquals(
            listOf("policy-draft-bound", "closed-without-start"),
            LlvmBehaviorNativeSandboxPolicyV2OperationPhase.entries.map { it.wireName },
        )
        val actionNames = ownerType.methods
            .filterNot { it.name.startsWith("get") || it.name in setOf("close", "equals", "hashCode", "toString") }
            .map { it.name }
            .toSet()
        assertEquals(setOf("closeWithoutStart"), actionNames)
        val actionMethods = ownerType.methods.filterNot { it.name.startsWith("get") }
        assertFalse(actionMethods.any { it.name.contains("prepare", ignoreCase = true) })
        assertFalse(actionMethods.any { it.name == "start" || it.name.startsWith("recordStart") })
    }

    @Test
    fun `Python v1 and nonexact paths fail before journal mutation`() {
        withFixture { fixture ->
            Files.writeString(
                fixture.source,
                "\n/* behavior-preexec-v1 Python */\n",
                Charsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND,
            )
            val failure = assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                open(fixture)
            }
            assertTrue(failure.message.orEmpty().contains("forbidden runtime marker"))
            assertTrue(entryNames(fixture.journalRoot).isEmpty())
        }
        withFixture { fixture ->
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                LlvmBehaviorNativeSandboxPolicyV2OperationJournal.open(
                    fixture.journalRoot.resolve(".."),
                    fixture.policy,
                    fixture.helper,
                    fixture.checksum,
                    fixture.source,
                    fixture.buildRecord,
                )
            }
            assertTrue(entryNames(fixture.journalRoot).isEmpty())
        }
    }

    @Test
    fun `root and child locks exclude duplicate ownership and release on close`() = withFixture { fixture ->
        val first = open(fixture)
        try {
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> { open(fixture) }
        } finally {
            first.close()
        }
        open(fixture).close()
    }

    @Test
    fun `root lock is released after separate JVM owner death`() = withFixture { fixture ->
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            LlvmBehaviorNativeSandboxPolicyV2OperationJournalLockProbe::class.java.name,
            fixture.journalRoot.toString(),
            fixture.policy.toString(),
            fixture.helper.toString(),
            fixture.checksum.toString(),
            fixture.source.toString(),
            fixture.buildRecord.toString(),
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader()
        val reader = Executors.newSingleThreadExecutor()
        try {
            assertEquals("READY", reader.submit<String?> { output.readLine() }.get(10, TimeUnit.SECONDS))
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                open(fixture)
            }
            process.destroyForcibly()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "journal lock probe did not die")
            open(fixture).close()
        } finally {
            reader.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    @Test
    fun `exact binding and transition temporaries recover while collision and unknown residue are retained`() {
        withFixture { fixture ->
            val operationId = open(fixture).use { it.operationId }
            val directory = operationDirectory(fixture, operationId)
            val binding = directory.resolve("binding.json")
            val bindingTemporary = directory.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("binding.json"),
            )
            Files.delete(directory.resolve("transition-0000.json"))
            Files.move(binding, bindingTemporary)
            open(fixture).use { owner ->
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND,
                    owner.phase,
                )
            }
            assertTrue(Files.exists(binding, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(bindingTemporary, LinkOption.NOFOLLOW_LINKS))
        }

        withFixture { fixture ->
            val owner = open(fixture)
            val operationId = owner.operationId
            owner.closeWithoutStart()
            owner.close()
            val directory = operationDirectory(fixture, operationId)
            val terminal = directory.resolve("transition-0001.json")
            val terminalTemporary = directory.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("transition-0001.json"),
            )
            Files.move(terminal, terminalTemporary)
            open(fixture).use { reopened ->
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.CLOSED_WITHOUT_START,
                    reopened.phase,
                )
            }
            assertTrue(Files.exists(terminal, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(terminalTemporary, LinkOption.NOFOLLOW_LINKS))
        }

        withFixture { fixture ->
            val operationId = open(fixture).use { it.operationId }
            val directory = operationDirectory(fixture, operationId)
            val first = directory.resolve("transition-0000.json")
            val firstTemporary = directory.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("transition-0000.json"),
            )
            Files.move(first, firstTemporary)
            open(fixture).use { owner ->
                assertEquals(
                    LlvmBehaviorNativeSandboxPolicyV2OperationPhase.POLICY_DRAFT_BOUND,
                    owner.phase,
                )
            }
            assertTrue(Files.exists(first, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(firstTemporary, LinkOption.NOFOLLOW_LINKS))

            val collision = directory.resolve(DescriptorBoundAtomicStateFile.temporaryName("transition-0000.json"))
            Files.copy(first, collision, StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(collision, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> { open(fixture) }
            assertTrue(Files.exists(first, LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(collision, LinkOption.NOFOLLOW_LINKS))
            Files.delete(collision)

            val unknown = directory.resolve(".unknown.json.atomic")
            Files.writeString(unknown, "unknown\n")
            Files.setPosixFilePermissions(unknown, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> { open(fixture) }
            assertTrue(Files.exists(unknown, LinkOption.NOFOLLOW_LINKS))
        }
    }

    @Test
    fun `binding and transition corruption are retained and rejected on cold reopen`() {
        listOf("binding.json", "transition-0000.json").forEach { targetName ->
            withFixture { fixture ->
                val operationId = open(fixture).use { it.operationId }
                val target = operationDirectory(fixture, operationId).resolve(targetName)
                val original = Files.readAllBytes(target)
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                Files.write(target, original + '\n'.code.toByte())
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException>(targetName) {
                    open(fixture)
                }
                assertContentEquals(original + '\n'.code.toByte(), Files.readAllBytes(target))
            }
        }
    }

    @Test
    fun `operation handle is poisoned by child replacement and never mutates the replacement`() =
        withFixture { fixture ->
            val owner = open(fixture)
            val directory = operationDirectory(fixture, owner.operationId)
            val detached = fixture.journalRoot.resolve("detached-operation")
            try {
                Files.move(directory, detached)
                Files.createDirectory(directory)
                Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
                assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                    owner.closeWithoutStart()
                }
                val poisoned = assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                    owner.closeWithoutStart()
                }
                assertTrue(poisoned.cause is IllegalStateException)
                assertTrue(entryNames(directory).isEmpty())
            } finally {
                owner.close()
            }
        }

    @Test
    fun `policy drift and root replacement poison before terminal publication`() {
        withFixture { fixture ->
            val owner = open(fixture)
            val directory = operationDirectory(fixture, owner.operationId)
            try {
                Files.writeString(
                    fixture.source,
                    "\n/* changed after binding */\n",
                    Charsets.UTF_8,
                    java.nio.file.StandardOpenOption.APPEND,
                )
                assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                    owner.closeWithoutStart()
                }
                assertFalse(Files.exists(directory.resolve("transition-0001.json"), LinkOption.NOFOLLOW_LINKS))
            } finally {
                owner.close()
            }
        }

        withFixture { fixture ->
            val owner = open(fixture)
            val detached = fixture.container.resolve("detached-journal-root")
            try {
                Files.move(fixture.journalRoot, detached)
                Files.createDirectory(fixture.journalRoot)
                Files.setPosixFilePermissions(
                    fixture.journalRoot,
                    PosixFilePermissions.fromString("rwx------"),
                )
                assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2OperationJournalException> {
                    owner.closeWithoutStart()
                }
                assertTrue(entryNames(fixture.journalRoot).isEmpty())
            } finally {
                owner.close()
            }
        }
    }

    private fun open(
        fixture: LlvmBehaviorNativeSandboxPolicyV2Fixture,
    ): LlvmBehaviorNativeSandboxPolicyV2OperationJournalOwner =
        LlvmBehaviorNativeSandboxPolicyV2OperationJournal.open(
            fixture.journalRoot,
            fixture.policy,
            fixture.helper,
            fixture.checksum,
            fixture.source,
            fixture.buildRecord,
        )

    private fun assertAllAuthorityFalse(owner: LlvmBehaviorNativeSandboxPolicyV2OperationJournalOwner) {
        assertFalse(owner.acpOracleAuthority)
        assertFalse(owner.acpReferenceAuthoringAuthority)
        assertFalse(owner.acpPolicyAuthoringAuthority)
        assertFalse(owner.acpValidationAuthority)
        assertFalse(owner.acpObservationAuthoringAuthority)
        assertFalse(owner.acpStartAuthority)
        assertFalse(owner.acpContainmentAuthority)
        assertFalse(owner.acpTerminalAbsenceAuthority)
        assertFalse(owner.acpScoringAuthority)
        assertFalse(owner.acpCertificationAuthority)
        assertFalse(owner.acpReleaseAuthority)
        assertFalse(owner.runtimeInputsBound)
        assertFalse(owner.candidateLineageBound)
        assertFalse(owner.prepared)
        assertFalse(owner.liveRuntimeIdentityVerified)
        assertFalse(owner.liveContainmentVerified)
        assertFalse(owner.executionClaimed)
        assertFalse(owner.referencePinned)
        assertFalse(owner.candidateStarted)
        assertFalse(owner.startAuthorized)
        assertFalse(owner.containmentAuthority)
        assertFalse(owner.terminalAbsenceAuthority)
        assertFalse(owner.observationAuthoringAuthority)
        assertFalse(owner.scoringAuthority)
        assertFalse(owner.certificationAuthority)
        assertFalse(owner.releaseEligible)
    }

    private fun falseClaims(): JsonObject = JsonObject(
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

    private fun operationDirectory(
        fixture: LlvmBehaviorNativeSandboxPolicyV2Fixture,
        operationId: String,
    ): Path = fixture.journalRoot.resolve(
        ".llvm-behavior-native-sandbox-policy-v2-operation-$operationId",
    )

    private fun entryNames(directory: Path): Set<String> = Files.list(directory).use { entries ->
        entries.map { it.fileName.toString() }.toList().toSet()
    }

    private fun requireImmutableFile(path: Path) {
        assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
        )
        assertEquals(1L, (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong())
    }

    private fun pathSha256(path: Path): String = OracleArtifacts.sha256(path.toString().encodeToByteArray())

    private fun sha256(value: JsonObject): String = OracleArtifacts.sha256(OracleJson.canonicalBytes(value))

    private inline fun withFixture(action: (LlvmBehaviorNativeSandboxPolicyV2Fixture) -> Unit) {
        assumeTrue(
            LlvmBehaviorNativeSandboxPolicyV2Fixture.HOST_ARCHITECTURE in setOf("amd64", "x86_64"),
            "the fixed linux/amd64 policy requires a native x86-64 helper fixture",
        )
        LlvmBehaviorNativeSandboxPolicyV2Fixture.create().use(action)
    }
}
