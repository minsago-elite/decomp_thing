package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonPrimitive
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

class FullTreeFunctionObservationOperationJournalTest {
    @Test
    fun `operation binding is canonical self hashed and fixes every runtime name`() {
        val binding = binding()

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

        val changedIsolation = root + ("isolationSha256" to JsonPrimitive("a".repeat(64)))
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
    fun `locked append only journal persists and reloads exact history`() = withJournalDirectory { directory ->
        val binding = binding()
        val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
        val leased = FullTreeFunctionObservationOperationTransition.next(
            binding,
            preparing,
            FullTreeFunctionObservationOperationPhase.LEASED,
            diskEvidenceSha256 = "6".repeat(64),
        )

        FullTreeFunctionObservationOperationJournal.open(directory).use { journal ->
            assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
                FullTreeFunctionObservationOperationJournal.open(directory)
            }
            assertEquals(listOf(preparing.transitionSha256), journal.initialize(binding).transitions.map {
                it.transitionSha256
            })
            assertEquals(
                listOf(preparing.transitionSha256, leased.transitionSha256),
                journal.append(binding, leased).transitions.map { it.transitionSha256 },
            )
            assertEquals(
                listOf(preparing.transitionSha256, leased.transitionSha256),
                journal.append(binding, leased).transitions.map { it.transitionSha256 },
            )
        }

        FullTreeFunctionObservationOperationJournal.open(directory).use { reopened ->
            val loaded = requireNotNull(reopened.loadOrNull())
            assertContentEquals(binding.canonicalBytes(), loaded.binding.canonicalBytes())
            assertEquals(
                listOf(preparing.transitionSha256, leased.transitionSha256),
                loaded.transitions.map { it.transitionSha256 },
            )
        }
    }

    @Test
    fun `journal initialization converges after every atomic crash point`() {
        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            for (crashOccurrence in 1..2) {
                withJournalDirectory { directory ->
                    val binding = binding()
                    var occurrences = 0
                    assertFailsWith<SimulatedProcessDeath> {
                        FullTreeFunctionObservationOperationJournal.open(directory).use { journal ->
                            journal.initialize(
                                binding,
                                DescriptorBoundStateFaultInjector { observed ->
                                    if (observed == point && ++occurrences == crashOccurrence) {
                                        throw SimulatedProcessDeath()
                                    }
                                },
                            )
                        }
                    }
                    FullTreeFunctionObservationOperationJournal.open(directory).use { recovered ->
                        val history = recovered.initialize(binding)
                        assertEquals(
                            listOf(FullTreeFunctionObservationOperationPhase.PREPARING),
                            history.transitions.map { it.phase },
                        )
                    }
                }
            }
        }
    }

    @Test
    fun `journal append converges after every atomic crash point`() {
        DescriptorBoundStateFaultPoint.entries.forEach { point ->
            withJournalDirectory { directory ->
                val binding = binding()
                val preparing = FullTreeFunctionObservationOperationTransition.initial(binding)
                val leased = FullTreeFunctionObservationOperationTransition.next(
                    binding,
                    preparing,
                    FullTreeFunctionObservationOperationPhase.LEASED,
                    diskEvidenceSha256 = "6".repeat(64),
                )
                FullTreeFunctionObservationOperationJournal.open(directory).use { it.initialize(binding) }
                assertFailsWith<SimulatedProcessDeath> {
                    FullTreeFunctionObservationOperationJournal.open(directory).use { journal ->
                        journal.append(
                            binding,
                            leased,
                            DescriptorBoundStateFaultInjector { observed ->
                                if (observed == point) throw SimulatedProcessDeath()
                            },
                        )
                    }
                }
                FullTreeFunctionObservationOperationJournal.open(directory).use { recovered ->
                    val history = recovered.append(binding, leased)
                    assertEquals(
                        listOf(
                            FullTreeFunctionObservationOperationPhase.PREPARING,
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        ),
                        history.transitions.map { it.phase },
                    )
                }
            }
        }
    }

    private fun binding() = FullTreeFunctionObservationOperationBinding.create(
        operationId = "1".repeat(64),
        shardId = "clang-lib-driver",
        shardInputSha256 = "2".repeat(64),
        scopeSha256 = "3".repeat(64),
        inventoryArtifactSha256 = "4".repeat(64),
        richArtifactSha256 = "5".repeat(64),
        isolationSha256 = "6".repeat(64),
        output = Path.of("/var/lib/decomp-oracle/output/clang-lib-driver.json"),
        diskPolicy = FullTreeDiskScratchPolicy(
            requiredAvailableBytes = 1024,
            maximumFilesystemBytes = 8192,
            requiredAvailableInodes = 4,
            maximumFilesystemInodes = 64,
        ),
    )

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

    private inline fun withJournalDirectory(action: (Path) -> Unit) {
        val parent = createTempDirectory("function-operation-journal-").toAbsolutePath().normalize()
        val directory = parent.resolve(journalDirectoryName("1".repeat(64)))
        Files.createDirectory(directory)
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        try {
            action(directory)
        } finally {
            if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                Files.list(directory).use { entries -> entries.toList() }.forEach(Files::deleteIfExists)
                Files.deleteIfExists(directory)
            }
            Files.deleteIfExists(parent)
        }
    }

    private class SimulatedProcessDeath : Error()

    private companion object {
        const val FROZEN_BINDING_SHA256 = "c133c50e9eb12900e2d8a886f36655eb894b84eb8e221e3d169c9f773fbf7ecf"
        const val FROZEN_BINDING_ARTIFACT_SHA256 =
            "e72942fa18b92c41c02aa9ea8147268325bbe602a871f7db5333dc34398e19f5"
        const val FROZEN_INITIAL_TRANSITION_SHA256 =
            "792a7684c901a6c2447953cbf5cd857ac47a88b107057abc169b75569896b290"
        const val FROZEN_COMPLETE_TRANSITION_SHA256 =
            "4c2c14d78ab2ecc2d39cddd80cd3f7d5329768b25b8775ad03b1bfb18412bffd"
    }
}
