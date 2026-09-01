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
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorHostedContainerV1OperationJournalTest {
    @Test
    fun `happy path is an exact self hashed chain but never gains authority`() = withJournalRoot { root ->
        val bindingBytes: ByteArray
        val operationId: String
        LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { owner ->
            assertEquals(LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED, owner.phase)
            assertEquals(
                "non-authoritative-code-only-llvm-behavior-hosted-container-v1-operation-journal",
                owner.authority,
            )
            assertEquals("first-class-candidate-producer-operator", owner.acpRole)
            assertEquals("read-only-oracle-input", owner.acpOracleAccess)
            assertAllAuthorityFalse(owner)

            bindingBytes = owner.canonicalBindingBytes
            operationId = owner.operationId
            assertEquals(owner.requestSha256, owner.operationId)
            assertEquals(pathSha256(root), owner.journalRootPathSha256)
            assertEquals("decomp-llvm-behavior-v1-${owner.operationId}", owner.containerName)
            assertTrue(owner.containerName.matches(Regex("[a-z0-9][a-z0-9_.-]{0,127}")))
            val binding = OracleJson.parse(bindingBytes) as JsonObject
            assertEquals(JsonPrimitive(owner.operationId), binding.getValue("operationId"))
            assertEquals(JsonPrimitive(owner.requestSha256), binding.getValue("requestSha256"))
            assertEquals(JsonPrimitive(owner.bindingSha256), binding.getValue("bindingSha256"))
            assertEquals(JsonPrimitive(owner.containerName), binding.getValue("containerName"))
            assertEquals(owner.bindingSha256, sha256(JsonObject(binding - "bindingSha256")))
            assertEquals(falseClaims(), binding.getValue("claims"))
            assertEquals(
                JsonObject(
                    mapOf(
                        "authority" to JsonPrimitive(false),
                        "oracleAccess" to JsonPrimitive("read-only-oracle-input"),
                        "role" to JsonPrimitive("first-class-candidate-producer-operator"),
                    ),
                ),
                binding.getValue("acpBoundary"),
            )
            val callerCopy = owner.canonicalBindingBytes
            callerCopy.fill(0)
            assertFalse(callerCopy.contentEquals(owner.canonicalBindingBytes))

            val reached = listOf(
                owner.recordInputAuthenticated(),
                owner.recordImageAuthenticated(),
                owner.armCreate(),
                owner.recordContainerVerified(),
                owner.recordWorkerCompleted(),
                owner.recordStagedPairVerified(),
                owner.recordContainerAbsenceProved(),
                owner.recordFinalPairPublished(),
                owner.recordCompleteAwaitingAttestation(),
            )
            assertEquals(
                LlvmBehaviorHostedContainerV1OperationPhase.entries
                    .filter { it != LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED }
                    .filter { it != LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED },
                reached,
            )
            val terminalHash = owner.latestTransitionSha256
            assertEquals(
                LlvmBehaviorHostedContainerV1OperationPhase.COMPLETE_AWAITING_ATTESTATION,
                owner.recordCompleteAwaitingAttestation(),
            )
            assertEquals(terminalHash, owner.latestTransitionSha256)
            assertAllAuthorityFalse(owner)
        }

        LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { reopened ->
            assertEquals(operationId, reopened.operationId)
            assertContentEquals(bindingBytes, reopened.canonicalBindingBytes)
            assertEquals(
                LlvmBehaviorHostedContainerV1OperationPhase.COMPLETE_AWAITING_ATTESTATION,
                reopened.phase,
            )
            assertAllAuthorityFalse(reopened)
        }

        val names = entryNames(root)
        assertEquals(
            setOf("binding.json") + (0..9).map { "transition-${it.toString().padStart(4, '0')}.json" },
            names,
        )
        names.forEach { name -> requireImmutableFile(root.resolve(name)) }
        var previous = "0".repeat(64)
        (0..9).forEach { sequence ->
            val transition = OracleJson.parse(
                Files.readAllBytes(root.resolve("transition-${sequence.toString().padStart(4, '0')}.json")),
            ) as JsonObject
            assertEquals(JsonPrimitive(sequence), transition.getValue("sequence"))
            assertEquals(JsonPrimitive(operationId), transition.getValue("operationId"))
            assertEquals(JsonPrimitive(previous), transition.getValue("previousTransitionSha256"))
            assertEquals(falseClaims(), transition.getValue("claims"))
            val transitionSha256 = (transition.getValue("transitionSha256") as JsonPrimitive).content
            assertEquals(transitionSha256, sha256(JsonObject(transition - "transitionSha256")))
            previous = transitionSha256
        }
    }

    @Test
    fun `CREATE armed failure becomes a durable terminal cleanup obligation`() = withJournalRoot { root ->
        val operationId: String
        LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { owner ->
            operationId = owner.operationId
            owner.recordInputAuthenticated()
            owner.recordImageAuthenticated()
            owner.armCreate()
            assertEquals(
                LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
                owner.requireCleanup(),
            )
            val terminalHash = owner.latestTransitionSha256
            assertEquals(
                LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED,
                owner.requireCleanup(),
            )
            assertEquals(terminalHash, owner.latestTransitionSha256)
            assertAllAuthorityFalse(owner)
        }

        LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { recovered ->
            assertEquals(operationId, recovered.operationId)
            assertEquals(LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED, recovered.phase)
            val before = entryNames(root)
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                recovered.recordContainerVerified()
            }
            assertEquals(before, entryNames(root))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                recovered.requireCleanup()
            }
        }
        assertEquals(
            setOf(
                "binding.json",
                "transition-0000.json",
                "transition-0001.json",
                "transition-0002.json",
                "transition-0003.json",
                "transition-0004.json",
            ),
            entryNames(root),
        )
    }

    @Test
    fun `public JVM surface accepts only one raw Path and no facts engine or runner`() {
        val open = LlvmBehaviorHostedContainerV1OperationJournal::class.java.declaredMethods.single {
            it.name == "open" && !it.isSynthetic
        }
        assertTrue(Modifier.isPublic(open.modifiers))
        assertTrue(open.parameterTypes.contentEquals(arrayOf(Path::class.java)))
        assertEquals(
            setOf("open"),
            LlvmBehaviorHostedContainerV1OperationJournal::class.java.declaredMethods
                .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
                .map { it.name }
                .toSet(),
        )

        val ownerType = LlvmBehaviorHostedContainerV1OperationJournalOwner::class.java
        assertTrue(ownerType.isSealed)
        val implementations = LlvmBehaviorHostedContainerV1OperationJournal::class.java.declaredClasses
            .filter(ownerType::isAssignableFrom)
        assertEquals(1, implementations.size)
        assertTrue(Modifier.isPrivate(implementations.single().modifiers))
        assertTrue(ownerType.permittedSubclasses.contentEquals(arrayOf(implementations.single())))
        assertTrue(
            implementations.single().declaredConstructors.single().parameterTypes
                .contentEquals(arrayOf(Path::class.java)),
        )
        assertFailsWith<IllegalArgumentException> {
            Proxy.newProxyInstance(ownerType.classLoader, arrayOf(ownerType)) { _, _, _ -> null }
        }

        val mutations = ownerType.declaredMethods.filter {
            it.name !in setOf(
                "close",
                "getAuthority",
                "getOperationId",
                "getRequestSha256",
                "getBindingSha256",
                "getLatestTransitionSha256",
                "getPhase",
                "getContainerName",
                "getJournalRootPathSha256",
                "getCanonicalBindingBytes",
                "getAcpRole",
                "getAcpOracleAccess",
                "getOracleAuthority",
                "getAcpAuthority",
                "getWorkflowAuthority",
                "getAdmissionAuthority",
                "getStartAuthority",
                "getContainmentAuthority",
                "getExecutionAuthority",
                "getObservationAuthority",
                "getScoringAuthority",
                "getPublicationAuthority",
                "getAttestationAuthority",
                "getReleaseAuthority",
                "getParsedFactsAccepted",
                "getEngineAccepted",
                "getRunnerAccepted",
                "getImageIdentityBound",
                "getContainerIdentityBound",
                "getStagingIdentitiesBound",
                "getExecutionClaimed",
                "getReleaseEligible",
            )
        }
        assertEquals(
            setOf(
                "recordInputAuthenticated",
                "recordImageAuthenticated",
                "armCreate",
                "recordContainerVerified",
                "recordWorkerCompleted",
                "recordStagedPairVerified",
                "recordContainerAbsenceProved",
                "recordFinalPairPublished",
                "recordCompleteAwaitingAttestation",
                "requireCleanup",
            ),
            mutations.map { it.name }.toSet(),
        )
        assertTrue(mutations.all { it.parameterCount == 0 })
        assertTrue(
            ownerType.methods.none { method ->
                method.parameterTypes.any { type ->
                    listOf("Fact", "Json", "Receipt", "Engine", "Runner", "Acp", "Admission").any {
                        marker -> type.name.contains(marker, ignoreCase = true)
                    }
                }
            },
        )
        assertEquals(
            listOf(
                "recovered",
                "input-authenticated",
                "image-authenticated",
                "create-armed",
                "container-verified",
                "worker-completed",
                "staged-pair-verified",
                "container-absence-proved",
                "final-pair-published",
                "complete-awaiting-attestation",
                "cleanup-required",
            ),
            LlvmBehaviorHostedContainerV1OperationPhase.entries.map { it.wireName },
        )
    }

    @Test
    fun `private exact root and exclusive lock fail closed before mutation`() {
        withJournalRoot { root ->
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root.resolve("."))
            }
            assertTrue(entryNames(root).isEmpty())

            val first = LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            try {
                assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                    LlvmBehaviorHostedContainerV1OperationJournal.open(root)
                }
            } finally {
                first.close()
            }
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
        }

        withJournalRoot { root ->
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-x---"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(entryNames(root).isEmpty())
        }

        withJournalRoot { root ->
            Files.setPosixFilePermissions(root.parent, PosixFilePermissions.fromString("rwxrwx---"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(entryNames(root).isEmpty())
        }
    }

    @Test
    fun `exact binding and transition temporaries recover but collisions remain`() {
        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
            val binding = root.resolve("binding.json")
            val temporary = root.resolve(DescriptorBoundAtomicStateFile.temporaryName("binding.json"))
            Files.delete(root.resolve("transition-0000.json"))
            Files.move(binding, temporary)
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { owner ->
                assertEquals(LlvmBehaviorHostedContainerV1OperationPhase.RECOVERED, owner.phase)
            }
            assertTrue(Files.exists(binding, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(temporary, LinkOption.NOFOLLOW_LINKS))
        }

        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { owner ->
                owner.recordInputAuthenticated()
                owner.recordImageAuthenticated()
                owner.armCreate()
                owner.requireCleanup()
            }
            val cleanup = root.resolve("transition-0004.json")
            val temporary = root.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("transition-0004.json"),
            )
            Files.move(cleanup, temporary)
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { owner ->
                assertEquals(LlvmBehaviorHostedContainerV1OperationPhase.CLEANUP_REQUIRED, owner.phase)
            }
            assertTrue(Files.exists(cleanup, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(temporary, LinkOption.NOFOLLOW_LINKS))
        }

        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
            val transition = root.resolve("transition-0000.json")
            val collision = root.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("transition-0000.json"),
            )
            Files.copy(transition, collision, StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(collision, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(Files.exists(transition, LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(collision, LinkOption.NOFOLLOW_LINKS))
        }

        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
            val unknown = root.resolve(".unknown.json.atomic")
            Files.writeString(unknown, "unknown\n")
            Files.setPosixFilePermissions(unknown, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(Files.exists(unknown, LinkOption.NOFOLLOW_LINKS))
        }
    }

    @Test
    fun `corruption gaps unknown residue and illegal transitions are retained`() {
        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
            val path = root.resolve("binding.json")
            val binding = OracleJson.parse(Files.readAllBytes(path)) as JsonObject
            val forgedWithoutHash = JsonObject(
                (binding - "bindingSha256") +
                    ("containerName" to JsonPrimitive("caller-selected-container")),
            )
            val forged = JsonObject(
                forgedWithoutHash +
                    ("bindingSha256" to JsonPrimitive(sha256(forgedWithoutHash))),
            )
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
            Files.write(path, OracleJson.canonicalBytes(forged))
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertContentEquals(OracleJson.canonicalBytes(forged), Files.readAllBytes(path))
        }

        listOf("binding.json", "transition-0000.json").forEach { targetName ->
            withJournalRoot { root ->
                LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
                val target = root.resolve(targetName)
                val original = Files.readAllBytes(target)
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                Files.write(target, original + '\n'.code.toByte())
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                    LlvmBehaviorHostedContainerV1OperationJournal.open(root)
                }
                assertContentEquals(original + '\n'.code.toByte(), Files.readAllBytes(target))
            }
        }

        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).use { owner ->
                owner.recordInputAuthenticated()
            }
            Files.move(root.resolve("transition-0001.json"), root.resolve("transition-0002.json"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(Files.exists(root.resolve("transition-0002.json"), LinkOption.NOFOLLOW_LINKS))
        }

        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
            val residue = root.resolve("caller-fact.json")
            Files.writeString(residue, "{}\n")
            Files.setPosixFilePermissions(residue, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(Files.exists(residue, LinkOption.NOFOLLOW_LINKS))
        }

        withJournalRoot { root ->
            LlvmBehaviorHostedContainerV1OperationJournal.open(root).close()
            repeat(12) { index ->
                val residue = root.resolve("bounded-residue-${index.toString().padStart(2, '0')}")
                Files.writeString(residue, "residue\n")
                Files.setPosixFilePermissions(residue, PosixFilePermissions.fromString("r--------"))
            }
            val failure = assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            }
            assertTrue(failure.message.orEmpty().contains("exceeds its entry bound"), failure.message)
            assertEquals(14, entryNames(root).size)
        }

        withJournalRoot { root ->
            val owner = LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            try {
                val before = entryNames(root)
                assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                    owner.recordImageAuthenticated()
                }
                assertEquals(before, entryNames(root))
                assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                    owner.recordInputAuthenticated()
                }
            } finally {
                owner.close()
            }
        }
    }

    @Test
    fun `root replacement poisons the owner and never mutates the replacement`() =
        withJournalRoot { root ->
            val owner = LlvmBehaviorHostedContainerV1OperationJournal.open(root)
            val detached = root.parent.resolve("detached-journal")
            try {
                Files.move(root, detached)
                Files.createDirectory(root)
                Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
                assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                    owner.recordInputAuthenticated()
                }
                assertTrue(entryNames(root).isEmpty())
                assertFailsWith<LlvmBehaviorHostedContainerV1OperationJournalException> {
                    owner.recordInputAuthenticated()
                }
                assertTrue(entryNames(root).isEmpty())
            } finally {
                owner.close()
            }
        }

    private fun assertAllAuthorityFalse(owner: LlvmBehaviorHostedContainerV1OperationJournalOwner) {
        assertFalse(owner.oracleAuthority)
        assertFalse(owner.acpAuthority)
        assertFalse(owner.workflowAuthority)
        assertFalse(owner.admissionAuthority)
        assertFalse(owner.startAuthority)
        assertFalse(owner.containmentAuthority)
        assertFalse(owner.executionAuthority)
        assertFalse(owner.observationAuthority)
        assertFalse(owner.scoringAuthority)
        assertFalse(owner.publicationAuthority)
        assertFalse(owner.attestationAuthority)
        assertFalse(owner.releaseAuthority)
        assertFalse(owner.parsedFactsAccepted)
        assertFalse(owner.engineAccepted)
        assertFalse(owner.runnerAccepted)
        assertFalse(owner.imageIdentityBound)
        assertFalse(owner.containerIdentityBound)
        assertFalse(owner.stagingIdentitiesBound)
        assertFalse(owner.executionClaimed)
        assertFalse(owner.releaseEligible)
    }

    private fun falseClaims(): JsonObject = JsonObject(
        mapOf(
            "acpAuthority" to JsonPrimitive(false),
            "admissionAuthority" to JsonPrimitive(false),
            "attestationAuthority" to JsonPrimitive(false),
            "containmentAuthority" to JsonPrimitive(false),
            "containerIdentityBound" to JsonPrimitive(false),
            "engineAccepted" to JsonPrimitive(false),
            "executionAuthority" to JsonPrimitive(false),
            "executionClaimed" to JsonPrimitive(false),
            "imageIdentityBound" to JsonPrimitive(false),
            "observationAuthority" to JsonPrimitive(false),
            "oracleAuthority" to JsonPrimitive(false),
            "parsedFactsAccepted" to JsonPrimitive(false),
            "publicationAuthority" to JsonPrimitive(false),
            "releaseAuthority" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            "runnerAccepted" to JsonPrimitive(false),
            "scoringAuthority" to JsonPrimitive(false),
            "startAuthority" to JsonPrimitive(false),
            "stagingIdentitiesBound" to JsonPrimitive(false),
            "workflowAuthority" to JsonPrimitive(false),
        ),
    )

    private fun requireImmutableFile(path: Path) {
        assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.isSymbolicLink(path))
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
        )
        assertEquals(1, (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt())
    }

    private fun entryNames(directory: Path): Set<String> = Files.list(directory).use { entries ->
        entries.map { it.fileName.toString() }.toList().toSet()
    }

    private fun pathSha256(path: Path): String =
        OracleArtifacts.sha256(path.toString().toByteArray(Charsets.UTF_8))

    private fun sha256(document: JsonObject): String =
        OracleArtifacts.sha256(OracleJson.canonicalBytes(document))

    private inline fun withJournalRoot(action: (Path) -> Unit) {
        val temporary = createTempDirectory("hosted-container-v1-journal-test-")
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rwx------"))
        val container = Files.createDirectory(temporary.resolve("container"))
        Files.setPosixFilePermissions(container, PosixFilePermissions.fromString("rwx------"))
        val root = Files.createDirectory(container.resolve("journal"))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            if (Files.exists(temporary, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(temporary).use { paths ->
                    paths.sorted(Comparator.reverseOrder()).forEach { path ->
                        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
                        } else if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
                        }
                        Files.deleteIfExists(path)
                    }
                }
            }
        }
    }
}
