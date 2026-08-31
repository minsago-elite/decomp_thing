package decompengine.oracle.fulltree

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxFilesystemCapacity
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
import kotlinx.serialization.json.JsonArray
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
    fun `unit attachment receipt is canonical strict and bound to one leased operation`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val evidence = diskEvidence(binding)
        val leased = FullTreeFunctionObservationOperationTransition.leased(binding, preparing, evidence)
        val receipt = attachmentReceipt(binding, leased)

        assertEquals(
            receipt.receiptSha256,
            OracleArtifacts.sha256(receipt.canonicalBytesWithoutSelfHashForTest()),
        )
        assertEquals(FROZEN_ATTACHMENT_RECEIPT_SHA256, receipt.receiptSha256)
        assertEquals(
            FROZEN_ATTACHMENT_RECEIPT_ARTIFACT_SHA256,
            OracleArtifacts.sha256(receipt.canonicalBytes()),
        )
        assertContentEquals(
            receipt.canonicalBytes(),
            FullTreeFunctionObservationUnitAttachmentReceipt.parseCanonical(receipt.canonicalBytes())
                .canonicalBytes(),
        )
        assertEquals(FullTreeFunctionObservationAttachmentProcessRole.entries, receipt.processes.map { it.role })

        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationUnitAttachmentReceipt.parseCanonical(
                receipt.canonicalBytes() + '\n'.code.toByte(),
            )
        }
        val root = OracleJson.parse(receipt.canonicalBytes()) as JsonObject
        val unknown = OracleJson.canonicalBytes(JsonObject(root + ("unknown" to JsonPrimitive(true))))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationUnitAttachmentReceipt.parseCanonical(unknown)
        }
        val mistyped = OracleJson.canonicalBytes(JsonObject(root + ("bootId" to JsonPrimitive(1))))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationUnitAttachmentReceipt.parseCanonical(mistyped)
        }
        val mutatedSelfHash = OracleJson.canonicalBytes(
            JsonObject(root + ("receiptSha256" to JsonPrimitive("f".repeat(64)))),
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationUnitAttachmentReceipt.parseCanonical(mutatedSelfHash)
        }
        val reversedProcesses = JsonArray((root.getValue("processes") as JsonArray).reversed())
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            mutateReceipt(receipt, "processes", reversedProcesses)
        }

        val otherBinding = binding(operationSeed = "a", isolationSeed = "b")
        val otherPreparing = FullTreeFunctionObservationOperationTransition.initial(otherBinding)
        val otherEvidence = diskEvidence(otherBinding)
        val otherLeased = FullTreeFunctionObservationOperationTransition.leased(
            otherBinding,
            otherPreparing,
            otherEvidence,
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationTransition.unitAttached(
                otherBinding,
                otherLeased,
                receipt,
            )
        }
        listOf(
            "operationId" to JsonPrimitive(otherBinding.operationId),
            "requestSha256" to JsonPrimitive(otherBinding.requestSha256),
            "bindingSha256" to JsonPrimitive(otherBinding.bindingSha256),
            "leasedTransitionSha256" to JsonPrimitive(otherLeased.transitionSha256),
            "diskEvidenceSha256" to JsonPrimitive(checkNotNull(otherLeased.diskEvidenceSha256)),
            "isolationConfigurationSha256" to JsonPrimitive(otherBinding.isolationConfigurationSha256),
        ).forEach { (field, value) ->
            val crossPaired = mutateReceipt(receipt, field, value)
            assertFailsWith<FullTreeFunctionObservationOperationJournalException>(field) {
                FullTreeFunctionObservationOperationTransition.unitAttached(
                    binding,
                    leased,
                    crossPaired,
                )
            }
        }
        val otherUnit = mutateReceipt(
            receipt,
            mapOf(
                "unitName" to JsonPrimitive(otherBinding.unitName),
                "controlGroup" to JsonPrimitive(
                    "/user.slice/user-1000.slice/user@1000.service/app.slice/${otherBinding.unitName}",
                ),
            ),
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationTransition.unitAttached(binding, leased, otherUnit)
        }
    }

    @Test
    fun `v4 journal rejects legacy v3 binding bytes without mutation`() = withJournalRoot { root ->
        val binding = binding()
        val current = OracleJson.parse(binding.canonicalBytes()) as JsonObject
        val currentRequest = OracleJson.parse(binding.canonicalRequestBytesForTest()) as JsonObject
        val legacyRequest = currentRequest + mapOf(
            "provider" to JsonPrimitive("kotlin-function-observation-request-v3"),
            "schemaVersion" to JsonPrimitive(3),
        )
        val legacyWithoutHash = current.minus("bindingSha256") + mapOf(
            "provider" to JsonPrimitive("kotlin-function-observation-operation-v3"),
            "requestSha256" to JsonPrimitive(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(legacyRequest))),
            ),
            "schemaVersion" to JsonPrimitive(3),
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
        val diskEvidence = diskEvidence(binding)
        val leased = FullTreeFunctionObservationOperationTransition.leased(
            binding,
            preparing,
            diskEvidence,
        )
        val attachmentReceipt = attachmentReceipt(binding, leased)
        val attached = FullTreeFunctionObservationOperationTransition.unitAttached(
            binding,
            leased,
            attachmentReceipt,
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
        val history = FullTreeFunctionObservationOperationHistory.validate(
            binding,
            transitions,
            diskEvidence,
            attachmentReceipt,
        )

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
                leased,
                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
            )
        }
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationTransition.recoveredAbort(
                binding,
                published,
            )
        }
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationTransition.recoveredAbort(
                binding,
                complete,
            )
        }

        val alternateEvidence = diskEvidence(binding, leaseRecordSeed = "8")
        val alternateLeased = FullTreeFunctionObservationOperationTransition.leased(
            binding,
            preparing,
            alternateEvidence,
        )
        val alternateReceipt = attachmentReceipt(binding, alternateLeased, identitySeed = 2)
        val alternateAttached = FullTreeFunctionObservationOperationTransition.unitAttached(
            binding,
            alternateLeased,
            alternateReceipt,
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(
                binding,
                listOf(preparing, leased, alternateAttached),
                diskEvidence,
                alternateReceipt,
            )
        }
    }

    @Test
    fun `history rejects hash-valid disk output and abort evidence substitution`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val diskEvidence = diskEvidence(binding)
        val leased = FullTreeFunctionObservationOperationTransition.leased(
            binding,
            preparing,
            diskEvidence,
        )
        val attachmentReceipt = attachmentReceipt(binding, leased)
        val attached = FullTreeFunctionObservationOperationTransition.unitAttached(
            binding,
            leased,
            attachmentReceipt,
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
        val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
            binding,
            leased,
        )

        val alternateEvidence = diskEvidence(binding, leaseRecordSeed = "8")
        val changedDisk = mutateTransition(
            attached,
            "diskEvidenceSha256",
            JsonPrimitive(alternateEvidence.evidenceSha256),
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(
                binding,
                listOf(preparing, leased, changedDisk),
                diskEvidence,
                attachmentReceipt,
            )
        }
        val changedOutput = mutateTransition(published, "outputSha256", JsonPrimitive("9".repeat(64)))
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(
                binding,
                listOf(preparing, leased, attached, absent, changedOutput),
                diskEvidence,
                attachmentReceipt,
            )
        }
        val droppedLease = mutateTransition(aborted, "diskEvidenceSha256", JsonNull)
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            FullTreeFunctionObservationOperationHistory.validate(
                binding,
                listOf(preparing, leased, droppedLease),
                diskEvidence,
            )
        }
    }

    @Test
    fun `recovered abort is terminal and drops any unreleased output claim`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val diskEvidence = diskEvidence(binding)
        val leased = FullTreeFunctionObservationOperationTransition.leased(
            binding,
            preparing,
            diskEvidence,
        )
        val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
            binding,
            leased,
        )

        val history = FullTreeFunctionObservationOperationHistory.validate(
            binding,
            listOf(preparing, leased, aborted),
            diskEvidence,
        )
        assertEquals(FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT, history.latest?.phase)
        assertEquals(diskEvidence.evidenceSha256, history.latest?.diskEvidenceSha256)
        assertEquals(null, history.latest?.outputSha256)
        assertEquals(null, history.latest?.outputBytes)
    }

    @Test
    fun `exact disk evidence requires its typed introduction link`() {
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val evidence = diskEvidence(binding)
        val staged = FullTreeFunctionObservationOperationHistory.validate(
            binding,
            listOf(preparing),
            evidence,
        )
        listOf(
            FullTreeFunctionObservationOperationPhase.LEASED,
            FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
        ).forEach { phase ->
            assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                staged.requireDiskEvidenceIntroducedAt(phase)
            }
        }

        val leased = FullTreeFunctionObservationOperationTransition.leased(binding, preparing, evidence)
        val leasedHistory = FullTreeFunctionObservationOperationHistory.validate(
            binding,
            listOf(preparing, leased),
            evidence,
        )
        assertTrue(
            leasedHistory.requireDiskEvidenceIntroducedAt(
                FullTreeFunctionObservationOperationPhase.LEASED,
            ) === evidence,
        )
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            leasedHistory.requireDiskEvidenceIntroducedAt(
                FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
            )
        }

        val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
            binding,
            preparing,
            evidence,
        )
        val abortedHistory = FullTreeFunctionObservationOperationHistory.validate(
            binding,
            listOf(preparing, aborted),
            evidence,
        )
        assertTrue(
            abortedHistory.requireDiskEvidenceIntroducedAt(
                FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
            ) === evidence,
        )
    }

    @Test
    fun `locked append only journal persists and reloads exact history`() = withJournalRoot { root ->
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val diskEvidence = diskEvidence(binding)
        val leased = FullTreeFunctionObservationOperationTransition.leased(
            binding,
            preparing,
            diskEvidence,
        )
        val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
            binding,
            leased,
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
                    journal.recordLeased(diskEvidence).transitions.map { it.transitionSha256 },
                )
                assertEquals(
                    listOf(preparing.transitionSha256, leased.transitionSha256),
                    journal.recordLeased(diskEvidence).transitions.map { it.transitionSha256 },
                )
                assertEquals(
                    listOf(
                        preparing.transitionSha256,
                        leased.transitionSha256,
                        aborted.transitionSha256,
                    ),
                    journal.append(aborted).transitions.map { it.transitionSha256 },
                )
                assertEquals(
                    listOf(
                        preparing.transitionSha256,
                        leased.transitionSha256,
                        aborted.transitionSha256,
                    ),
                    journal.recordLeased(diskEvidence).transitions.map { it.transitionSha256 },
                )
            }
        }

        FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
            requireNotNull(authority.openExisting(binding)).use { reopened ->
                val loaded = requireNotNull(reopened.loadOrNull())
                assertContentEquals(binding.canonicalBytes(), loaded.binding.canonicalBytes())
                assertEquals(
                    listOf(
                        preparing.transitionSha256,
                        leased.transitionSha256,
                        aborted.transitionSha256,
                    ),
                    loaded.transitions.map { it.transitionSha256 },
                )
                assertContentEquals(
                    diskEvidence.canonicalBytes(),
                    requireNotNull(loaded.diskEvidence).canonicalBytes(),
                )
                assertEquals(
                    loaded.transitions.map { it.transitionSha256 },
                    reopened.recordLeased(diskEvidence).transitions.map { it.transitionSha256 },
                )
            }
        }
    }

    @Test
    fun `leased recording persists exact evidence and rejects raw transition append`() =
        withJournalRoot { root ->
            val binding = binding()
            val evidence = diskEvidence(binding)
            val mismatchedEvidence = listOf(
                mutateDiskEvidence(evidence, "operationId", JsonPrimitive("a".repeat(64))),
                mutateDiskEvidence(evidence, "requestSha256", JsonPrimitive("a".repeat(64))),
                mutateDiskEvidence(evidence, "shardId", JsonPrimitive("different-shard")),
                mutateDiskEvidence(evidence, "scopeSha256", JsonPrimitive("b".repeat(64))),
                mutateDiskEvidence(evidence, "requiredAvailableBytes", JsonPrimitive(512)),
                mutateDiskEvidence(evidence, "maximumFilesystemBytes", JsonPrimitive(16384)),
                mutateDiskEvidence(evidence, "requiredAvailableInodes", JsonPrimitive(5)),
                mutateDiskEvidence(evidence, "maximumFilesystemInodes", JsonPrimitive(128)),
            )
            val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
            val leased = FullTreeFunctionObservationOperationTransition.leased(
                binding,
                preparing,
                evidence,
            )
            val directory = root.resolve(binding.journalDirectoryName)

            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    journal.initialize()
                    val before = Files.list(directory).use { entries ->
                        entries.map { it.fileName.toString() }.sorted().toList()
                    }
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.append(leased)
                    }
                    assertEquals(
                        before,
                        Files.list(directory).use { entries ->
                            entries.map { it.fileName.toString() }.sorted().toList()
                        },
                    )
                    assertFalse(Files.exists(directory.resolve("disk-evidence.json"), LinkOption.NOFOLLOW_LINKS))
                }

                mismatchedEvidence.forEach { wrongEvidence ->
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            journal.recordLeased(wrongEvidence)
                        }
                        assertFalse(
                            Files.exists(directory.resolve("disk-evidence.json"), LinkOption.NOFOLLOW_LINKS),
                        )
                    }
                }

                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val recorded = journal.recordLeased(evidence)
                    assertEquals(FullTreeFunctionObservationOperationPhase.LEASED, recorded.latest?.phase)
                    assertEquals(evidence.evidenceSha256, recorded.latest?.diskEvidenceSha256)
                    assertContentEquals(
                        evidence.canonicalBytes(),
                        requireNotNull(recorded.diskEvidence).canonicalBytes(),
                    )
                    assertContentEquals(
                        evidence.canonicalBytes(),
                        Files.readAllBytes(directory.resolve("disk-evidence.json")),
                    )
                    assertEquals(
                        PosixFilePermissions.fromString("r--------"),
                        Files.getPosixFilePermissions(
                            directory.resolve("disk-evidence.json"),
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                    )
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.recordLeased(diskEvidence(binding, leaseRecordSeed = "8"))
                    }
                    assertContentEquals(
                        evidence.canonicalBytes(),
                        Files.readAllBytes(directory.resolve("disk-evidence.json")),
                    )
                }
            }
        }

    @Test
    fun `unit attachment sidecar is canonical and generic append stays forbidden`() =
        withJournalRoot { root ->
            val binding = binding()
            val evidence = diskEvidence(binding)
            val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
            val leased = FullTreeFunctionObservationOperationTransition.leased(binding, preparing, evidence)
            val receipt = attachmentReceipt(binding, leased)
            val attached = FullTreeFunctionObservationOperationTransition.unitAttached(
                binding,
                leased,
                receipt,
            )
            val directory = root.resolve(binding.journalDirectoryName)

            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    journal.initialize()
                    journal.recordLeased(evidence)
                    val before = journalSnapshot(directory)
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.append(attached)
                    }
                    assertEquals(before, journalSnapshot(directory))
                }
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val recorded = journal.recordUnitAttached(receipt)
                    assertEquals(FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED, recorded.latest?.phase)
                    assertTrue(
                        recorded.requireUnitAttachmentReceiptIntroducedAt(
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                        ) === recorded.unitAttachmentReceipt,
                    )
                    assertContentEquals(
                        receipt.canonicalBytes(),
                        requireNotNull(recorded.unitAttachmentReceipt).canonicalBytes(),
                    )
                    assertEquals(receipt.receiptSha256, recorded.latest?.unitAttachmentReceiptSha256)
                    assertContentEquals(
                        receipt.canonicalBytes(),
                        Files.readAllBytes(directory.resolve("unit-attachment.json")),
                    )
                    assertEquals(
                        PosixFilePermissions.fromString("r--------"),
                        Files.getPosixFilePermissions(
                            directory.resolve("unit-attachment.json"),
                            LinkOption.NOFOLLOW_LINKS,
                        ),
                    )
                    val completeSnapshot = journalSnapshot(directory)
                    assertEquals(
                        recorded.transitions.map { it.transitionSha256 },
                        journal.recordUnitAttached(receipt).transitions.map { it.transitionSha256 },
                    )
                    assertEquals(completeSnapshot, journalSnapshot(directory))
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.recordUnitAttached(attachmentReceipt(binding, leased, identitySeed = 2))
                    }
                    assertEquals(completeSnapshot, journalSnapshot(directory))
                }
                assertTrue(Files.exists(directory.resolve(attached.fileName), LinkOption.NOFOLLOW_LINKS))
            }
        }

    @Test
    fun `attachment receipt and transition publication crash states stay staged until exact retry`() {
        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            withJournalRoot { root ->
                val binding = binding()
                val evidence = diskEvidence(binding)
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    authority.createNew(binding).use { journal ->
                        journal.initialize()
                        journal.recordLeased(evidence)
                    }
                }
                val leased = FullTreeFunctionObservationOperationTransition.leased(
                    binding,
                    FullTreeFunctionObservationOperationTransition.initial(binding),
                    evidence,
                )
                val receipt = attachmentReceipt(binding, leased)
                assertFailsWith<SimulatedProcessDeath> {
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        requireNotNull(authority.openExisting(binding)).use { journal ->
                            journal.recordUnitAttached(
                                receipt,
                                receiptFaultInjector = DescriptorBoundStateFaultInjector { observed ->
                                    if (observed == point) throw SimulatedProcessDeath()
                                },
                            )
                        }
                    }
                }

                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val completion = journal.completeExactPendingPublication()
                        val expectedKind = if (
                            point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC
                        ) {
                            FullTreeFunctionObservationColdCompletionKind.UNIT_ATTACHMENT_RECEIPT
                        } else {
                            FullTreeFunctionObservationColdCompletionKind.NONE
                        }
                        assertEquals(expectedKind, completion.kind)
                        val staged = completion.history ?: requireNotNull(journal.loadOrNull())
                        assertEquals(FullTreeFunctionObservationOperationPhase.LEASED, staged.latest?.phase)
                        val receiptWasDurable =
                            point != DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC
                        assertEquals(receiptWasDurable, staged.unitAttachmentReceipt != null)
                        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                            staged.requireUnitAttachmentReceiptIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            )
                        }
                        val attached = journal.recordUnitAttached(receipt)
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            attached.latest?.phase,
                        )
                        assertContentEquals(
                            receipt.canonicalBytes(),
                            attached.requireUnitAttachmentReceiptIntroducedAt(
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            ).canonicalBytes(),
                        )
                    }
                }
            }
        }

        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            withJournalRoot { root ->
                val binding = binding()
                val evidence = diskEvidence(binding)
                val leased = FullTreeFunctionObservationOperationTransition.leased(
                    binding,
                    FullTreeFunctionObservationOperationTransition.initial(binding),
                    evidence,
                )
                val receipt = attachmentReceipt(binding, leased)
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    authority.createNew(binding).use { journal ->
                        journal.initialize()
                        journal.recordLeased(evidence)
                    }
                }
                assertFailsWith<SimulatedProcessDeath> {
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        requireNotNull(authority.openExisting(binding)).use { journal ->
                            journal.recordUnitAttached(
                                receipt,
                                transitionFaultInjector = DescriptorBoundStateFaultInjector { observed ->
                                    if (observed == point) throw SimulatedProcessDeath()
                                },
                            )
                        }
                    }
                }

                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val completion = journal.completeExactPendingPublication()
                        val expectedKind = if (
                            point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC
                        ) {
                            FullTreeFunctionObservationColdCompletionKind.TRANSITION
                        } else {
                            FullTreeFunctionObservationColdCompletionKind.NONE
                        }
                        assertEquals(expectedKind, completion.kind)
                        val attached = completion.history ?: requireNotNull(journal.loadOrNull())
                        val transitionWasDurable =
                            point != DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC
                        assertEquals(
                            if (transitionWasDurable) {
                                FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED
                            } else {
                                FullTreeFunctionObservationOperationPhase.LEASED
                            },
                            attached.latest?.phase,
                        )
                        val retried = journal.recordUnitAttached(receipt)
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.UNIT_ATTACHED,
                            retried.latest?.phase,
                        )
                    }
                }
            }
        }
    }

    @Test
    fun `disk evidence publication crash states remain explicit and converge only on caller retry`() {
        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            withJournalRoot { root ->
                val binding = binding()
                val evidence = diskEvidence(binding)
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    authority.createNew(binding).use { it.initialize() }
                }
                assertFailsWith<SimulatedProcessDeath> {
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        requireNotNull(authority.openExisting(binding)).use { journal ->
                            journal.recordLeased(
                                evidence,
                                evidenceFaultInjector = DescriptorBoundStateFaultInjector { observed ->
                                    if (observed == point) throw SimulatedProcessDeath()
                                },
                            )
                        }
                    }
                }

                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        val cold = journal.completeExactPendingPublication()
                        val expectedKind = if (
                            point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC
                        ) {
                            FullTreeFunctionObservationColdCompletionKind.DISK_EVIDENCE
                        } else {
                            FullTreeFunctionObservationColdCompletionKind.NONE
                        }
                        assertEquals(expectedKind, cold.kind)
                        val staged = cold.history ?: requireNotNull(journal.loadOrNull())
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.PREPARING,
                            staged.latest?.phase,
                        )
                        val evidenceWasDurable =
                            point != DescriptorBoundStateFaultPoint.AFTER_UNNAMED_FILE_SYNC
                        assertEquals(evidenceWasDurable, staged.diskEvidence != null)
                        if (evidenceWasDurable) {
                            assertContentEquals(
                                evidence.canonicalBytes(),
                                requireNotNull(staged.diskEvidence).canonicalBytes(),
                            )
                        }

                        val resumed = journal.recordLeased(evidence)
                        assertEquals(FullTreeFunctionObservationOperationPhase.LEASED, resumed.latest?.phase)
                        assertContentEquals(
                            evidence.canonicalBytes(),
                            requireNotNull(resumed.diskEvidence).canonicalBytes(),
                        )
                    }
                }
            }
        }
    }

    @Test
    fun `prepared disk evidence can be linked to recovered abort without becoming leased`() =
        withJournalRoot { root ->
            val binding = binding()
            val evidence = diskEvidence(binding)
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { it.initialize() }
            }
            assertFailsWith<SimulatedProcessDeath> {
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    requireNotNull(authority.openExisting(binding)).use { journal ->
                        journal.recordLeased(
                            evidence,
                            evidenceFaultInjector = DescriptorBoundStateFaultInjector { point ->
                                if (point == DescriptorBoundStateFaultPoint.AFTER_PUBLICATION_DIRECTORY_SYNC) {
                                    throw SimulatedProcessDeath()
                                }
                            },
                        )
                    }
                }
            }

            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val staged = requireNotNull(journal.loadOrNull())
                    assertEquals(FullTreeFunctionObservationOperationPhase.PREPARING, staged.latest?.phase)
                    val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
                        binding,
                        checkNotNull(staged.latest),
                        evidence,
                    )
                    val terminal = journal.append(aborted)
                    assertEquals(
                        FullTreeFunctionObservationOperationPhase.RECOVERED_ABORT,
                        terminal.latest?.phase,
                    )
                    assertEquals(evidence.evidenceSha256, terminal.latest?.diskEvidenceSha256)
                    assertTrue(terminal.transitions.none {
                        it.phase == FullTreeFunctionObservationOperationPhase.LEASED
                    })
                    assertContentEquals(
                        evidence.canonicalBytes(),
                        requireNotNull(terminal.diskEvidence).canonicalBytes(),
                    )
                }
            }
        }

    @Test
    fun `leased history rejects missing substituted and colliding disk evidence without mutation`() =
        withJournalRoot { root ->
            val binding = binding()
            val evidence = diskEvidence(binding)
            val alternate = diskEvidence(binding, leaseRecordSeed = "8")
            val directory = root.resolve(binding.journalDirectoryName)
            val evidencePath = directory.resolve("disk-evidence.json")
            val evidenceTemporary = directory.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("disk-evidence.json"),
            )
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    journal.initialize()
                    journal.recordLeased(evidence)
                }
            }
            val transitionPath = directory.resolve("transition-0001.json")
            val transitionBytes = Files.readAllBytes(transitionPath)

            Files.delete(evidencePath)
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.loadOrNull()
                    }
                }
            }
            assertContentEquals(transitionBytes, Files.readAllBytes(transitionPath))

            writeImmutable(evidencePath, alternate.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.loadOrNull()
                    }
                }
            }
            assertContentEquals(alternate.canonicalBytes(), Files.readAllBytes(evidencePath))
            assertContentEquals(transitionBytes, Files.readAllBytes(transitionPath))

            Files.delete(evidencePath)
            writeImmutable(evidencePath, evidence.canonicalBytes())
            writeImmutable(evidenceTemporary, evidence.canonicalBytes())
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                        journal.completeExactPendingPublication()
                    }
                }
            }
            assertContentEquals(evidence.canonicalBytes(), Files.readAllBytes(evidencePath))
            assertContentEquals(evidence.canonicalBytes(), Files.readAllBytes(evidenceTemporary))
            Files.delete(evidenceTemporary)

            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    val loaded = requireNotNull(journal.loadOrNull())
                    assertContentEquals(
                        evidence.canonicalBytes(),
                        requireNotNull(loaded.diskEvidence).canonicalBytes(),
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
                val diskEvidence = diskEvidence(binding)
                val leased = FullTreeFunctionObservationOperationTransition.leased(
                    binding,
                    preparing,
                    diskEvidence,
                )
                FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                    authority.createNew(binding).use { it.initialize() }
                }
                assertFailsWith<SimulatedProcessDeath> {
                    FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                        requireNotNull(authority.openExisting(binding)).use { journal ->
                            journal.recordLeased(
                                diskEvidence,
                                transitionFaultInjector = DescriptorBoundStateFaultInjector { observed ->
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
                        assertContentEquals(
                            diskEvidence.canonicalBytes(),
                            requireNotNull(history?.diskEvidence).canonicalBytes(),
                        )
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
            val diskEvidence = diskEvidence(binding)
            val leased = FullTreeFunctionObservationOperationTransition.leased(
                binding,
                preparing,
                diskEvidence,
            )
            val receipt = attachmentReceipt(binding, leased)
            val attached = FullTreeFunctionObservationOperationTransition.unitAttached(
                binding,
                leased,
                receipt,
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
                requireNotNull(authority.openExisting(binding)).use { journal ->
                    journal.recordLeased(diskEvidence)
                }
            }
            val changedDisk = mutateTransition(
                attached,
                "diskEvidenceSha256",
                JsonPrimitive(diskEvidence(binding, leaseRecordSeed = "8").evidenceSha256),
            )
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

            val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
                binding,
                leased,
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
            val diskEvidence = diskEvidence(binding)
            val leased = FullTreeFunctionObservationOperationTransition.leased(
                binding,
                preparing,
                diskEvidence,
            )
            val aborted = FullTreeFunctionObservationOperationTransition.recoveredAbort(
                binding,
                leased,
            )
            FullTreeFunctionObservationJournalAuthority.open(root).use { authority ->
                authority.createNew(binding).use { journal ->
                    journal.initialize()
                    journal.recordLeased(diskEvidence)
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
                    assertEquals(diskEvidence.evidenceSha256, completion.history?.latest?.diskEvidenceSha256)
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

    private fun diskEvidence(
        binding: FullTreeFunctionObservationOperationBinding,
        leaseRecordSeed: String = "e",
    ): FullTreeDiskScratchEvidence = FullTreeDiskScratchEvidence.create(
        operation = binding.diskOperation(),
        policy = binding.diskPolicy(),
        mountPathSha256 = "f".repeat(64),
        mount = FullTreeDiskMount(
            mountId = 42,
            parentMountId = 36,
            device = "7:1",
            root = Path.of("/"),
            mountPoint = Path.of("/var/lib/decomp-scratch"),
            options = listOf("noatime", "nodev", "noexec", "nosuid", "rw"),
            fileSystemType = "ext4",
        ),
        mountIdentity = diskIdentity(device = 7, inode = 2, mountId = 42),
        capacity = LinuxFilesystemCapacity(
            fragmentBytes = 4096,
            totalBytes = 8192,
            availableBytes = 4096,
            totalInodes = 64,
            availableInodes = 60,
            maximumNameBytes = 255,
            readOnly = false,
        ),
        leaseIdentity = diskIdentity(device = 7, inode = 12, mountId = 42),
        leaseRecordSha256 = leaseRecordSeed.repeat(64),
    )

    private fun attachmentReceipt(
        binding: FullTreeFunctionObservationOperationBinding,
        leased: FullTreeFunctionObservationOperationTransition,
        identitySeed: Int = 1,
    ): FullTreeFunctionObservationUnitAttachmentReceipt {
        val firstPid = 1000L + identitySeed * 10L
        val bubblewrapDevice = 100L + identitySeed
        val javaDevice = 200L + identitySeed
        return FullTreeFunctionObservationUnitAttachmentReceipt.create(
            binding = binding,
            leasedTransition = leased,
            bootId = identitySeed.toString(16).padStart(32, '0'),
            invocationId = (identitySeed + 16).toString(16).padStart(32, '0'),
            controlGroup = "/user.slice/user-1000.slice/user@1000.service/app.slice/${binding.unitName}",
            cgroupDevice = 300L + identitySeed,
            cgroupInode = 400L + identitySeed,
            cgroupMountId = 500L + identitySeed,
            processes = listOf(
                attachmentProcess(
                    FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP,
                    firstPid,
                    null,
                    listOf(firstPid),
                    bubblewrapDevice,
                    101L + identitySeed,
                    102L + identitySeed,
                ),
                attachmentProcess(
                    FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
                    firstPid + 1,
                    FullTreeFunctionObservationAttachmentProcessRole.OUTER_BUBBLEWRAP,
                    listOf(firstPid + 1, 1L),
                    bubblewrapDevice,
                    101L + identitySeed,
                    102L + identitySeed,
                ),
                attachmentProcess(
                    FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM,
                    firstPid + 2,
                    FullTreeFunctionObservationAttachmentProcessRole.NAMESPACE_INIT_BUBBLEWRAP,
                    listOf(firstPid + 2, 2L),
                    javaDevice,
                    201L + identitySeed,
                    202L + identitySeed,
                ),
                attachmentProcess(
                    FullTreeFunctionObservationAttachmentProcessRole.WORKER_JVM,
                    firstPid + 3,
                    FullTreeFunctionObservationAttachmentProcessRole.SUPERVISOR_JVM,
                    listOf(firstPid + 3, 3L),
                    javaDevice,
                    201L + identitySeed,
                    202L + identitySeed,
                ),
            ),
        )
    }

    private fun attachmentProcess(
        role: FullTreeFunctionObservationAttachmentProcessRole,
        hostPid: Long,
        parentRole: FullTreeFunctionObservationAttachmentProcessRole?,
        namespacePids: List<Long>,
        executableDevice: Long,
        executableInode: Long,
        executableMountId: Long,
    ) = FullTreeFunctionObservationAttachmentProcessIdentity(
        role = role,
        hostPid = hostPid,
        startTimeTicks = hostPid * 100L,
        parentRole = parentRole,
        namespacePids = namespacePids,
        executableDevice = executableDevice,
        executableInode = executableInode,
        executableMountId = executableMountId,
    )

    private fun diskIdentity(device: Long, inode: Long, mountId: Long) = LinuxFileIdentity(
        key = LinuxFileKey(device, inode),
        mode = 0x41c0,
        uid = 1000,
        gid = 1000,
        linkCount = 2,
        mountId = mountId,
        isRegularFile = false,
        isDirectory = true,
        isSymbolicLink = false,
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

    private fun mutateReceipt(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
        field: String,
        value: kotlinx.serialization.json.JsonElement,
    ): FullTreeFunctionObservationUnitAttachmentReceipt = mutateReceipt(
        receipt,
        mapOf(field to value),
    )

    private fun mutateReceipt(
        receipt: FullTreeFunctionObservationUnitAttachmentReceipt,
        fields: Map<String, kotlinx.serialization.json.JsonElement>,
    ): FullTreeFunctionObservationUnitAttachmentReceipt {
        val root = OracleJson.parse(receipt.canonicalBytes()) as JsonObject
        val changed = root + fields
        val receiptSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(changed - "receiptSha256")),
        )
        return FullTreeFunctionObservationUnitAttachmentReceipt.parseCanonical(
            OracleJson.canonicalBytes(
                JsonObject(changed + ("receiptSha256" to JsonPrimitive(receiptSha256))),
            ),
        )
    }

    private fun mutateDiskEvidence(
        evidence: FullTreeDiskScratchEvidence,
        field: String,
        value: kotlinx.serialization.json.JsonElement,
    ): FullTreeDiskScratchEvidence {
        val root = OracleJson.parse(evidence.canonicalBytes()) as JsonObject
        val changed = root + (field to value)
        val evidenceSha256 = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(JsonObject(changed - "evidenceSha256")),
        )
        return FullTreeDiskScratchEvidence.parseCanonical(
            OracleJson.canonicalBytes(
                JsonObject(changed + ("evidenceSha256" to JsonPrimitive(evidenceSha256))),
            ),
        )
    }

    private fun bindingTemporaryName(): String = DescriptorBoundAtomicStateFile.temporaryName("binding.json")

    private fun writeImmutable(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private fun journalSnapshot(directory: Path): Map<String, List<Byte>> =
        Files.list(directory).use { entries ->
            entries.map { path -> path.fileName.toString() to Files.readAllBytes(path).toList() }
                .toList()
                .toMap()
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
        const val FROZEN_BINDING_SHA256 = "f31c14d42bc65baf60d3fd5545b968cf9009e7775ecbcfcf0fcbb79c984aa624"
        const val FROZEN_BINDING_ARTIFACT_SHA256 =
            "66326322c329b9dd5736214c638130533a74803f4763f0b5599b4e7bf7c6f0df"
        const val FROZEN_INITIAL_TRANSITION_SHA256 =
            "6601a75e6391b3c2d97b93f727a5e1d703deb85e5a95515d838d423271a697b0"
        const val FROZEN_ATTACHMENT_RECEIPT_SHA256 =
            "e35801e232c4fa16a86e0642035a1f6ca10ae79b94a1ee7892f63e692db487c4"
        const val FROZEN_ATTACHMENT_RECEIPT_ARTIFACT_SHA256 =
            "82ee6b22114061c8840b05d873fa6ece803eb19053620620482aafc5b8560097"
        const val FROZEN_COMPLETE_TRANSITION_SHA256 =
            "7e3cb5c019da3f71adb95885a463e7f74c90082ee4ffeb3621e0688a49ba2f57"
    }
}
