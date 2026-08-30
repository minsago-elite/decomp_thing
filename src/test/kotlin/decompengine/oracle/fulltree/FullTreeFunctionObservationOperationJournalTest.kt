package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FullTreeFunctionObservationOperationJournalTest {
    @Test
    fun `operation binding is canonical self hashed and fixes every runtime name`() {
        val binding = binding()
        val isolationConfiguration = isolationConfiguration("6")

        assertEquals(".function-observation-operation-${"1".repeat(64)}", binding.journalDirectoryName)
        assertEquals(".decomp-oracle-lease-${"1".repeat(64)}", binding.leaseDirectoryName)
        assertEquals(
            ".decomp-oracle-lease-release-${"1".repeat(64)}",
            binding.leaseReleaseQuarantineDirectoryName,
        )
        assertEquals(
            ".decomp-oracle-lease-failed-${"1".repeat(64)}",
            binding.leaseFailureQuarantineDirectoryName,
        )
        assertEquals(".function-observation-run-${"1".repeat(64)}", binding.runDirectoryName)
        assertEquals(
            ".function-observation-run-abort-${"1".repeat(64)}",
            binding.runQuarantineDirectoryName,
        )
        assertEquals("decomp-oracle-function-${"1".repeat(64)}.scope", binding.unitName)
        assertEquals(".function-observation-output-${"1".repeat(64)}.atomic", binding.outputStageName)
        assertEquals(isolationConfiguration.canonicalSha256, binding.isolationConfigurationSha256)
        assertEquals(FULL_TREE_DISK_SCRATCH_PROVIDER, binding.diskAuthorityProvider)
        assertEquals(
            binding.requestSha256,
            OracleArtifacts.sha256(binding.canonicalRequestBytesForTest()),
        )
        assertEquals(
            binding.bindingSha256,
            OracleArtifacts.sha256(binding.canonicalBytesWithoutSelfHashForTest()),
        )
        assertEquals(FROZEN_BINDING_SHA256, binding.bindingSha256)
        assertEquals(FROZEN_BINDING_ARTIFACT_SHA256, OracleArtifacts.sha256(binding.canonicalBytes()))
        assertContentEquals(
            binding.canonicalBytes(),
            FullTreeFunctionObservationOperationBinding.parseCanonical(binding.canonicalBytes()).canonicalBytes(),
        )
        assertEquals(binding.operationId, binding.diskOperation().operationId)
        assertEquals(binding.requestSha256, binding.diskOperation().requestSha256)
        assertEquals(binding.requiredAvailableBytes, binding.diskPolicy().requiredAvailableBytes)
        assertEquals(binding.maximumFilesystemInodes, binding.diskPolicy().maximumFilesystemInodes)
    }

    @Test
    fun `binding parser rejects noncanonical unknown mistyped and self hash mutations`() {
        val bytes = binding().canonicalBytes()
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationBinding.parseCanonical(bytes + '\n'.code.toByte())
        }

        val root = OracleJson.parse(bytes) as JsonObject
        val unknown = OracleJson.canonicalBytes(JsonObject(root + ("unknown" to JsonPrimitive(true))))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationBinding.parseCanonical(unknown)
        }
        val mistyped = OracleJson.canonicalBytes(JsonObject(root + ("schemaVersion" to JsonPrimitive("1"))))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationBinding.parseCanonical(mistyped)
        }
        val mutatedHash = OracleJson.canonicalBytes(
            JsonObject(root + ("bindingSha256" to JsonPrimitive("0".repeat(64)))),
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationBinding.parseCanonical(mutatedHash)
        }

        val changedIsolation = root +
            ("isolationConfigurationSha256" to JsonPrimitive("a".repeat(64)))
        val changedIsolationHash = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(changedIsolation - "bindingSha256")),
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationBinding.parseCanonical(
                OracleJson.canonicalBytes(
                    JsonObject(changedIsolation + ("bindingSha256" to JsonPrimitive(changedIsolationHash))),
                ),
            )
        }

        val wrongDiskProvider = root + ("diskAuthorityProvider" to JsonPrimitive("ordinary-directory-v1"))
        val wrongDiskProviderHash = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(wrongDiskProvider - "bindingSha256")),
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationBinding.parseCanonical(
                OracleJson.canonicalBytes(
                    JsonObject(
                        wrongDiskProvider +
                            ("bindingSha256" to JsonPrimitive(wrongDiskProviderHash)),
                    ),
                ),
            )
        }
    }

    @Test
    fun `v2 journal rejects legacy v1 binding bytes without mutation`() = withJournalRoot { root ->
        val binding = binding()
        val current = OracleJson.parse(binding.canonicalBytes()) as JsonObject
        val legacyWithoutHash = current
            .minus("bindingSha256")
            .minus("diskAuthorityProvider")
            .minus("isolationConfigurationSha256") +
            mapOf(
                "isolationSha256" to JsonPrimitive(binding.isolationConfigurationSha256),
                "provider" to JsonPrimitive("kotlin-function-observation-operation-v1"),
                "schemaVersion" to JsonPrimitive(1),
            )
        val legacy = OracleJson.canonicalBytes(
            JsonObject(
                legacyWithoutHash +
                    ("bindingSha256" to JsonPrimitive(
                        OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(legacyWithoutHash))),
                    )),
            ),
        )

        FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
            authority.createNew(binding).use { journal ->
                val path = root.resolve(binding.journalDirectoryName).resolve("binding.json")
                writeImmutable(path, legacy)
                val namesBefore = Files.list(path.parent).use { entries ->
                    entries.map { it.fileName.toString() }.sorted().toList()
                }

                assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                    journal.loadOrNull()
                }

                assertContentEquals(legacy, Files.readAllBytes(path))
                assertEquals(
                    namesBefore,
                    Files.list(path.parent).use { entries ->
                        entries.map { it.fileName.toString() }.sorted().toList()
                    },
                )
            }
        }
    }

    @Test
    fun `append only transition history is canonical monotonic and hash chained`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val leased = FullTreeFunctionObservationOperationTransition.next(
            binding,
            preparing,
            FullTreeFunctionObservationOperationPhase.LEASED,
            diskEvidenceSha256 = "6".repeat(64),
        )
        val attached = FullTreeFunctionObservationOperationTransition.next(
            binding,
            leased,
            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
        )
        val absent = FullTreeFunctionObservationOperationTransition.next(
            binding,
            attached,
            FullTreeFunctionObservationOperationPhase.CGROUP_ABSENT,
            outputSha256 = "7".repeat(64),
            outputBytes = 4096,
        )
        val published = FullTreeFunctionObservationOperationTransition.next(
            binding,
            absent,
            FullTreeFunctionObservationOperationPhase.PUBLISHED,
        )
        val complete = FullTreeFunctionObservationOperationTransition.next(
            binding,
            published,
            FullTreeFunctionObservationOperationPhase.COMPLETE,
        )
        val transitions = listOf(preparing, leased, attached, absent, published, complete)
        val history = FullTreeFunctionObservationOperationHistory.validate(binding, transitions)

        assertEquals(FullTreeFunctionObservationOperationPhase.COMPLETE, history.latest?.phase)
        assertEquals(
            listOf(
                "transition-0000.json",
                "transition-0001.json",
                "transition-0002.json",
                "transition-0003.json",
                "transition-0004.json",
                "transition-0005.json",
            ),
            transitions.map { it.fileName },
        )
        transitions.forEach { transition ->
            assertEquals(
                transition.transitionSha256,
                OracleArtifacts.sha256(transition.canonicalBytesWithoutSelfHashForTest()),
            )
            assertContentEquals(
                transition.canonicalBytes(),
                FullTreeFunctionObservationOperationTransition.parseCanonical(transition.canonicalBytes())
                    .canonicalBytes(),
            )
        }
        assertEquals(FROZEN_INITIAL_TRANSITION_SHA256, preparing.transitionSha256)
        assertEquals(FROZEN_COMPLETE_TRANSITION_SHA256, complete.transitionSha256)

        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationTransition.next(
                binding,
                preparing,
                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
            )
        }
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationTransition.next(
                binding,
                complete,
                FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                outputSha256 = null,
                outputBytes = null,
            )
        }

        val alternateLeased = FullTreeFunctionObservationOperationTransition.next(
            binding,
            preparing,
            FullTreeFunctionObservationOperationPhase.LEASED,
            diskEvidenceSha256 = "8".repeat(64),
        )
        val alternateAttached = FullTreeFunctionObservationOperationTransition.next(
            binding,
            alternateLeased,
            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(
                binding,
                listOf(preparing, leased, alternateAttached),
            )
        }
    }

    @Test
    fun `history rejects hash-valid disk output and abort evidence substitution`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val leased = FullTreeFunctionObservationOperationTransition.next(
            binding,
            preparing,
            FullTreeFunctionObservationOperationPhase.LEASED,
            diskEvidenceSha256 = "6".repeat(64),
        )
        val attached = FullTreeFunctionObservationOperationTransition.next(
            binding,
            leased,
            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
        )
        val absent = FullTreeFunctionObservationOperationTransition.next(
            binding,
            attached,
            FullTreeFunctionObservationOperationPhase.CGROUP_ABSENT,
            outputSha256 = "7".repeat(64),
            outputBytes = 4096,
        )
        val published = FullTreeFunctionObservationOperationTransition.next(
            binding,
            absent,
            FullTreeFunctionObservationOperationPhase.PUBLISHED,
        )
        val aborted = FullTreeFunctionObservationOperationTransition.next(
            binding,
            leased,
            FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
            outputSha256 = null,
            outputBytes = null,
        )

        val changedDisk = mutateTransition(attached, "diskEvidenceSha256", JsonPrimitive("8".repeat(64)))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(binding, listOf(preparing, leased, changedDisk))
        }
        val changedOutput = mutateTransition(published, "outputSha256", JsonPrimitive("9".repeat(64)))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(
                binding,
                listOf(preparing, leased, attached, absent, changedOutput),
            )
        }
        val droppedLease = mutateTransition(aborted, "diskEvidenceSha256", JsonNull)
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(binding, listOf(preparing, leased, droppedLease))
        }
    }

    @Test
    fun `recovered abort is terminal and drops any unreleased output claim`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val leased = FullTreeFunctionObservationOperationTransition.next(
            binding,
            preparing,
            FullTreeFunctionObservationOperationPhase.LEASED,
            diskEvidenceSha256 = "6".repeat(64),
        )
        val aborted = FullTreeFunctionObservationOperationTransition.next(
            binding,
            leased,
            FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
            outputSha256 = null,
            outputBytes = null,
        )

        val history = FullTreeFunctionObservationOperationHistory.validate(
            binding,
            listOf(preparing, leased, aborted),
        )
        assertEquals(FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT, history.latest?.phase)
        assertEquals("6".repeat(64), history.latest?.diskEvidenceSha256)
        assertEquals(null, history.latest?.outputSha256)
        assertEquals(null, history.latest?.outputBytes)
    }

    @Test
    fun `locked append only journal persists and reloads exact history`() = withJournalRoot { root ->
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val leased = FullTreeFunctionObservationOperationTransition.next(
            binding,
            preparing,
            FullTreeFunctionObservationOperationPhase.LEASED,
            diskEvidenceSha256 = "6".repeat(64),
        )

        FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
            authority.createNew(binding).use { journal ->
                assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                    authority.openExisting(binding)
                }
                assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                    FullTreeFunctionObservationJournalAuthority.open(root)
                }
                assertEquals(listOf(preparing.transitionSha256), journal.initialize().transitions.map {
                    it.transitionSha256
                })
                assertEquals(
                    listOf(preparing.transitionSha256, leased.transitionSha256),
                    journal.append(leased).transitions.map { it.transitionSha256 },
                )
                assertEquals(
                    listOf(preparing.transitionSha256, leased.transitionSha256),
                    journal.append(leased).transitions.map { it.transitionSha256 },
                )
            }
        }

        FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
            requireNotNull(authority.openExisting(binding)).use { reopened ->
                val loaded = requireNotNull(reopened.loadOrNull())
                assertContentEquals(binding.canonicalBytes(), loaded.binding.canonicalBytes())
                assertEquals(
                    listOf(preparing.transitionSha256, leased.transitionSha256),
                    loaded.transitions.map { it.transitionSha256 },
                )
            }
        }
    }

    @Test
    fun `journal initialization converges after every atomic crash point`() {
        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            for (crashOccurrence in 1..2) {
                withJournalRoot { root ->
                    val binding = binding()
                    var occurrences = 0
                    assertFailsWith<SimulatedProcessDeath> {
                        FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                            authority.createNew(binding).use { journal ->
                                journal.initialize(
                                    DescriptorBoundStateFaultInjector { observed ->
                                        if (observed == point && ++occurrences == crashOccurrence) {
                                            throw SimulatedProcessDeath()
                                        }
                                    },
                                )
                            }
                        }
                    }
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        requireNotNull(authority.openExisting(binding)).use { recovered ->
                            val cold = recovered.completeExactPendingPublication()
                            val expectedCompletion = if (
                                point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC
                            ) {
                                if (crashOccurrence == 1) {
                                    FullTreeFunctionObservationColdCompletionKind.BINDING
                                } else {
                                    FullTreeFunctionObservationColdCompletionKind.TRANSITION
                                }
                            } else {
                                FullTreeFunctionObservationColdCompletionKind.NONE
                            }
                            assertEquals(expectedCompletion, cold.kind)
                            val history = recovered.initialize()
                            assertEquals(
                                listOf(FullTreeFunctionObservationOperationPhase.PREPARING),
                                history.transitions.map { it.phase },
                            )
                        }
                    }
                }
            }
        }
    }

    @Test
    fun `journal append converges after every atomic crash point`() {
        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            withJournalRoot { root ->
                val binding = binding()
                val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
                val leased = FullTreeFunctionObservationOperationTransition.next(
                    binding,
                    preparing,
                    FullTreeFunctionObservationOperationPhase.LEASED,
                    diskEvidenceSha256 = "6".repeat(64),
                )
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    authority.createNew(binding).use { it.initialize() }
                }
                assertFailsWith<SimulatedProcessDeath> {
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        requireNotNull(authority.openExisting(binding)).use { journal ->
                            journal.append(
                                leased,
                                DescriptorBoundStateFaultInjector { observed ->
                                    if (observed == point) throw SimulatedProcessDeath()
                                },
                            )
                        }
                    }
                }
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    requireNotNull(authority.openExisting(binding)).use { recovered ->
                        val cold = recovered.completeExactPendingPublication()
                        val expectedCompletion = if (
                            point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC
                        ) FullTreeFunctionObservationColdCompletionKind.TRANSITION
                        else FullTreeFunctionObservationColdCompletionKind.NONE
                        assertEquals(expectedCompletion, cold.kind)
                        val history = cold.history ?: recovered.loadOrNull()
                        val expectedPhases = if (
                            point == DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC
                        ) listOf(FullTreeFunctionObservationOperationPhase.PREPARING)
                        else listOf(
                            FullTreeFunctionObservationOperationPhase.PREPARING,
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        )
                        assertEquals(expectedPhases, history?.transitions?.map { it.phase })
                    }
                }
            }
        }
    }

    @Test
    fun `journal root authority creates exact directories and detects detach replacement permanently`() =
        withJournalRoot { root ->
            val binding = binding()
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    journal.initialize()
                    val directory = root.resolve(binding.journalDirectoryName)
                    assertTrue(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS))
                    assertEquals(
                        PosixFilePermissions.fromString("rwx------"),
                        Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS),
                    )
                    val detached = root.resolve("detached-operation")
                    Files.move(directory, detached)
                    Files.createDirectory(directory)
                    Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))

                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.loadOrNull()
                    }
                    assertTrue(Files.list(directory).use { it.findAny().isEmpty })
                    Files.delete(directory)
                    Files.move(detached, directory)
                    assertFailsWith<IllegalStateException> { journal.loadOrNull() }
                }
            }
        }

    @Test
    fun `journal handle is poisoned when its configured root is detached and replaced`() =
        withJournalRoot { root ->
            val binding = binding()
            val otherBinding = binding(operationSeed = "a")
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    authority.createNew(otherBinding).use { other ->
                        journal.initialize()
                        other.initialize()
                        val held = root.parent.resolve("held-root")
                        Files.move(root, held)
                        Files.createDirectory(root)
                        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            journal.loadOrNull()
                        }
                        assertTrue(Files.list(root).use { it.findAny().isEmpty })
                        Files.delete(root)
                        Files.move(held, root)
                        assertFailsWith<IllegalStateException> { journal.loadOrNull() }
                        assertFailsWith<IllegalStateException> { other.loadOrNull() }
                        assertFailsWith<IllegalStateException> {
                            authority.createNew(binding(operationSeed = "b"))
                        }
                    }
                }
            }
        }

    @Test
    fun `one root authority supports parallel distinct operations while excluding duplicate ownership`() =
        withJournalRoot { root ->
            val firstBinding = binding()
            val secondBinding = binding(operationSeed = "a")
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                assertEquals(null, authority.openExisting(firstBinding))
                authority.createNew(firstBinding).use { first ->
                    authority.createNew(secondBinding).use { second ->
                        assertEquals(firstBinding.bindingSha256, first.initialize().binding.bindingSha256)
                        assertEquals(secondBinding.bindingSha256, second.initialize().binding.bindingSha256)
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            authority.openExisting(firstBinding)
                        }
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            authority.createNew(firstBinding)
                        }
                    }
                }
            }
        }

    @Test
    fun `journal root lock is released after separate JVM process death`() = withJournalRoot { root ->
        val java = Path.of(System.getProperty("java.home"), "bin", "java")
        val process = ProcessBuilder(
            java.toString(),
            "-cp",
            System.getProperty("java.class.path"),
            FullTreeFunctionObservationJournalLockProbe::class.java.name,
            root.toString(),
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader()
        val reader = Executors.newSingleThreadExecutor()
        try {
            assertEquals("READY", reader.submit<String?> { output.readLine() }.get(10, TimeUnit.SECONDS))
            assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                FullTreeFunctionObservationJournalAuthority.open(root)
            }
            process.destroyForcibly()
            assertTrue(process.waitFor(10, TimeUnit.SECONDS), "journal lock probe did not die")
            FullTreeFunctionObservationJournalAuthority.open(root).use { }
        } finally {
            reader.shutdownNow()
            if (process.isAlive) process.destroyForcibly()
        }
    }

    @Test
    fun `cold completion rejects replacement missing collision multiple and unknown temporary residue`() {
        withJournalRoot { root ->
            val binding = binding()
            val directory = root.resolve(binding.journalDirectoryName)
            val bindingTemporary = DescriptorBoundAtomicStateFile.temporaryName("binding.json")

            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    writeImmutable(directory.resolve(bindingTemporary), binding.canonicalBytes())
                    assertFailsWith<java.io.IOException> {
                        journal.completeExactPendingPublication(afterInspection = {
                            Files.delete(directory.resolve(bindingTemporary))
                        })
                    }
                    assertFalse(Files.exists(directory.resolve("binding.json"), LinkOption.NOFOLLOW_LINKS))
                }
            }

            writeImmutable(directory.resolve(bindingTemporary), binding.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<java.io.IOException> {
                        journal.completeExactPendingPublication(afterInspection = {
                            val pending = directory.resolve(bindingTemporary)
                            Files.delete(pending)
                            writeImmutable(pending, binding.canonicalBytes())
                        })
                    }
                    assertFalse(Files.exists(directory.resolve("binding.json"), LinkOption.NOFOLLOW_LINKS))
                    assertTrue(Files.exists(directory.resolve(bindingTemporary), LinkOption.NOFOLLOW_LINKS))
                }
            }

            Files.delete(directory.resolve(bindingTemporary))
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal -> journal.initialize() }
            }
            val initial = FullTreeFunctionObservationOperationTransition.initial(binding)
            val initialTemporary = DescriptorBoundAtomicStateFile.temporaryName(initial.fileName)
            writeImmutable(directory.resolve(initialTemporary), initial.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertTrue(Files.exists(directory.resolve(initial.fileName), LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(directory.resolve(initialTemporary), LinkOption.NOFOLLOW_LINKS))
            Files.delete(directory.resolve(initialTemporary))

            val unknown = ".unknown.atomic"
            val another = ".another.atomic"
            writeImmutable(directory.resolve(unknown), "unknown\n".toByteArray())
            writeImmutable(directory.resolve(another), "another\n".toByteArray())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertTrue(Files.exists(directory.resolve(unknown), LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(directory.resolve(another), LinkOption.NOFOLLOW_LINKS))
            Files.delete(directory.resolve(another))
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertTrue(Files.exists(directory.resolve(unknown), LinkOption.NOFOLLOW_LINKS))
        }
    }

    @Test
    fun `cold completion rejects cross request gap and hash-valid evidence substitution`() {
        withJournalRoot { root ->
            val binding = binding()
            val directory = root.resolve(binding.journalDirectoryName)
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal -> journal.initialize() }
            }
            val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
            val leased = FullTreeFunctionObservationOperationTransition.next(
                binding,
                preparing,
                FullTreeFunctionObservationOperationPhase.LEASED,
                diskEvidenceSha256 = "6".repeat(64),
            )
            val attached = FullTreeFunctionObservationOperationTransition.next(
                binding,
                leased,
                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
            )

            writeImmutable(
                directory.resolve(DescriptorBoundAtomicStateFile.temporaryName(attached.fileName)),
                attached.canonicalBytes(),
            )
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            Files.delete(directory.resolve(DescriptorBoundAtomicStateFile.temporaryName(attached.fileName)))

            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal -> journal.append(leased) }
            }
            val changedDisk = mutateTransition(attached, "diskEvidenceSha256", JsonPrimitive("8".repeat(64)))
            val attachedTemporary = DescriptorBoundAtomicStateFile.temporaryName(attached.fileName)
            writeImmutable(directory.resolve(attachedTemporary), changedDisk.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertFalse(Files.exists(directory.resolve(attached.fileName), LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(directory.resolve(attachedTemporary), LinkOption.NOFOLLOW_LINKS))
            Files.delete(directory.resolve(attachedTemporary))

            val aborted = FullTreeFunctionObservationOperationTransition.next(
                binding,
                leased,
                FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                outputSha256 = null,
                outputBytes = null,
            )
            val droppedLease = mutateTransition(aborted, "diskEvidenceSha256", JsonNull)
            writeImmutable(directory.resolve(attachedTemporary), droppedLease.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertFalse(Files.exists(directory.resolve(aborted.fileName), LinkOption.NOFOLLOW_LINKS))
            assertTrue(Files.exists(directory.resolve(attachedTemporary), LinkOption.NOFOLLOW_LINKS))
            Files.delete(directory.resolve(attachedTemporary))

            val expectedRequest = binding(operationSeed = "c")
            val crossRequest = binding(operationSeed = "c", isolationSeed = "b")
            val crossDirectory = root.resolve(expectedRequest.journalDirectoryName)
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(expectedRequest).use { }
            }
            writeImmutable(crossDirectory.resolve(bindingTemporaryName()), crossRequest.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(expectedRequest)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertTrue(Files.exists(crossDirectory.resolve(bindingTemporaryName()), LinkOption.NOFOLLOW_LINKS))
        }
    }

    @Test
    fun `cold completion reconstructs a recovered-abort link without caller transition state`() =
        withJournalRoot { root ->
            val binding = binding()
            val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
            val leased = FullTreeFunctionObservationOperationTransition.next(
                binding,
                preparing,
                FullTreeFunctionObservationOperationPhase.LEASED,
                diskEvidenceSha256 = "6".repeat(64),
            )
            val aborted = FullTreeFunctionObservationOperationTransition.next(
                binding,
                leased,
                FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                outputSha256 = null,
                outputBytes = null,
            )
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    journal.initialize()
                    journal.append(leased)
                    assertFailsWith<SimulatedProcessDeath> {
                        journal.append(
                            aborted,
                            DescriptorBoundStateFaultInjector { point ->
                                if (point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC) {
                                    throw SimulatedProcessDeath()
                                }
                            },
                        )
                    }
                }
            }
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val completion = journal.completeExactPendingPublication()
                    assertEquals(FullTreeFunctionObservationColdCompletionKind.TRANSITION, completion.kind)
                    assertEquals(
                        FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                        completion.history?.latest?.phase,
                    )
                    assertEquals("6".repeat(64), completion.history?.latest?.diskEvidenceSha256)
                }
            }
        }

    private fun binding(
        operationSeed: String = "1",
        isolationSeed: String = "6",
    ) = FullTreeFunctionObservationOperationBinding.create(
        operationId = operationSeed.repeat(64),
        shardId = "clang-lib-driver",
        shardInputSha256 = "2".repeat(64),
        scopeSha256 = "3".repeat(64),
        inventoryArtifactSha256 = "4".repeat(64),
        richArtifactSha256 = "5".repeat(64),
        isolationConfiguration = isolationConfiguration(isolationSeed),
        output = Path.of("/var/lib/decomp-oracle/output/clang-lib-driver.json"),
        diskPolicy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1024,
            maximumFilesystemBytes = 8192,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = 64,
        ),
    )

    private fun isolationConfiguration(seed: String): FullTreeFunctionObservationIsolationConfiguration {
        val javaRuntime = Path.of("/provisioned/java")
        val tool = Path.of("/provisioned/tools")
        return FullTreeFunctionObservationIsolationConfiguration(
            javaExecutable = javaRuntime.resolve("bin/java"),
            javaRuntime = FullTreeFunctionObservationRuntimeMount(
                javaRuntime,
                Path.of("/runtime/java"),
                "7".repeat(64),
            ),
            systemLibraryMounts = listOf(
                FullTreeFunctionObservationRuntimeMount(
                    Path.of("/provisioned/libraries"),
                    Path.of("/runtime/libraries"),
                    "8".repeat(64),
                ),
            ),
            bubblewrapExecutable = tool.resolve("bwrap"),
            resourceLimiterExecutable = tool.resolve("prlimit"),
            scopeSupervisorExecutable = tool.resolve("systemd-run"),
            scopeInspectorExecutable = tool.resolve("systemctl"),
            systemdUserRuntimeDirectory = Path.of("/run/user/1000"),
            workerClassPath = listOf(
                FullTreeFunctionObservationClassPathEntry(
                    Path.of("/provisioned/application/worker.jar"),
                    "9".repeat(64),
                ),
            ),
            expectedJavaSha256 = seed.repeat(64),
            expectedBubblewrapSha256 = "a".repeat(64),
            expectedResourceLimiterSha256 = "b".repeat(64),
            expectedScopeSupervisorSha256 = "c".repeat(64),
            expectedScopeInspectorSha256 = "d".repeat(64),
        )
    }

    private fun mutateTransition(
        transition: FullTreeFunctionObservationOperationTransition,
        field: String,
        value: kotlinx.serialization.json.JsonElement,
    ): FullTreeFunctionObservationOperationTransition {
        val root = OracleJson.parse(transition.canonicalBytes()) as JsonObject
        val changed = root + (field to value)
        val transitionSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(changed - "transitionSha256")),
        )
        return FullTreeFunctionObservationOperationTransition.parseCanonical(
            OracleJson.canonicalBytes(
                JsonObject(changed + ("transitionSha256" to JsonPrimitive(transitionSha256))),
            ),
        )
    }

    private fun bindingTemporaryName(): String = DescriptorBoundAtomicStateFile.temporaryName("binding.json")

    private fun writeImmutable(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private inline fun withJournalRoot(action: (Path) -> Unit) {
        val container = createTempDirectory("function-operation-journal-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(container, PosixFilePermissions.fromString("rwx------"))
        val root = Files.createDirectory(container.resolve("root"))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            if (Files.exists(container, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(container).use { entries ->
                    entries.sorted(Comparator.reverseOrder()).toList()
                }.forEach(Files::deleteIfExists)
            }
        }
    }

    private class SimulatedProcessDeath : Error()

    private companion object {
        const val FROZEN_BINDING_SHA256 = "6300f8fab1437d65e5dbe8f4446c5b06ae4541c4239f67317de9fec3b5a3d004"
        const val FROZEN_BINDING_ARTIFACT_SHA256 =
            "b077857d0ed082d04e1b657b0320554be85a6299df5f2da86e56370b35ce7a75"
        const val FROZEN_INITIAL_TRANSITION_SHA256 =
            "cabba2a2d307e94ace6f7470d7708a5e047582346286463de8607f719ad15de0"
        const val FROZEN_COMPLETE_TRANSITION_SHA256 =
            "4c33ec3621fb4c178556ad8c0ec0eab7e062f448debd4dfbccb719e999d8da60"
    }
}
