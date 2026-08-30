package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.atomic.AtomicLong
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FullTreeFunctionObservationShardPublisherTest {
    @Test
    fun `file-backed producer publishes byte-identical read-only shard without residue`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("clang-lib-driver.json")
            val expected = FullTreeFunctionObservationProducer.generateShard(
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                shardId = "clang-lib-driver",
                scratchParent = scratch,
            )
            val expectedBytes = FullTreeFunctionObservations.canonicalEnvelopeBytes(expected.document)

            val result = FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                shardId = "clang-lib-driver",
                scratchParent = scratch,
                output = output,
                limits = FullTreeFunctionObservationShardPublisherLimits(),
                runtime = incrementingRuntime(),
            )

            assertContentEquals(expectedBytes, Files.readAllBytes(output))
            assertEquals(expected.outputSha256, result.outputSha256)
            assertEquals(expected.outputBytes, result.outputBytes)
            assertEquals(expected.entities, result.entities)
            assertEquals(expected.scannedDies, result.scannedDies)
            assertEquals(1L, result.units)
            assertEquals(1L, result.emittedRvas)
            assertEquals(0L, result.nonEmitted)
            assertEquals(0L, result.nonEmittedDies)
            assertEquals(1L, result.subprograms)
            assertTrue(result.databaseHighWaterBytes in 1L..4L * 1024L * 1024L)
            assertEquals(TEST_PEAK_RESIDENT_BYTES, result.peakResidentBytes)
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(output, LinkOption.NOFOLLOW_LINKS),
            )
            val validated = FullTreeFunctionObservationShardPublisher.loadAndValidateInternal(
                candidate = output,
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                shardId = "clang-lib-driver",
                scratchParent = scratch,
                limits = FullTreeFunctionObservationShardPublisherLimits(),
                runtime = incrementingRuntime(),
            )
            assertEquals(result, validated)
            assertEquals(listOf(output), Files.list(outputParent).use { it.toList() })
            assertDirectoryEmpty(scratch)
        }

    @Test
    fun `file-backed producer never replaces an existing publication`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("occupied.json")
            val sentinel = "keep-existing-publication\n".toByteArray()
            Files.write(output, sentinel)
            Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rw-------"))

            val failure = assertFailsWith<FullTreeFunctionObservationShardPublicationException> {
                FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = fixture.authenticatedScope(),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    limits = FullTreeFunctionObservationShardPublisherLimits(),
                    runtime = incrementingRuntime(),
                )
            }

            assertTrue(failure.message.orEmpty().contains("already exists"), failure.message)
            assertContentEquals(sentinel, Files.readAllBytes(output))
            assertEquals(listOf(output), Files.list(outputParent).use { it.toList() })
            assertDirectoryEmpty(scratch)
        }

    @Test
    fun `cooperative timeout revokes staged output and SQLite scratch`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("timed-out.json")
            val counter = AtomicLong()
            val runtime = FullTreeFunctionObservationRuntime { checkpoint ->
                val elapsed = if (checkpoint == "after closing function-observation SQLite state") {
                    1_201L * 1_000_000_000L
                } else {
                    counter.getAndIncrement() * 1_000_000L
                }
                FullTreeFunctionObservationRuntimeSample(
                    elapsed,
                    elapsed,
                    TEST_CURRENT_RESIDENT_BYTES,
                    TEST_PEAK_RESIDENT_BYTES,
                )
            }

            val failure = assertFailsWith<FullTreeFunctionObservationShardPublicationException> {
                FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = fixture.authenticatedScope(),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    limits = FullTreeFunctionObservationShardPublisherLimits(),
                    runtime = runtime,
                )
            }

            assertTrue(failure.message.orEmpty().contains("wall-clock bound"), failure.message)
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(outputParent)
            assertDirectoryEmpty(scratch)
        }

    @Test
    fun `cooperative CPU violation revokes staged output and SQLite scratch`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("over-cpu.json")
            val counter = AtomicLong()
            val runtime = FullTreeFunctionObservationRuntime { checkpoint ->
                val wall = counter.getAndIncrement() * 1_000_000L
                val cpu = if (checkpoint == "after closing function-observation SQLite state") {
                    2_401L * 1_000_000_000L
                } else {
                    wall
                }
                FullTreeFunctionObservationRuntimeSample(
                    wall,
                    cpu,
                    TEST_CURRENT_RESIDENT_BYTES,
                    TEST_PEAK_RESIDENT_BYTES,
                )
            }

            val failure = assertFailsWith<FullTreeFunctionObservationShardPublicationException> {
                FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = fixture.authenticatedScope(),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    limits = FullTreeFunctionObservationShardPublisherLimits(),
                    runtime = runtime,
                )
            }

            assertTrue(failure.message.orEmpty().contains("CPU bound"), failure.message)
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(outputParent)
            assertDirectoryEmpty(scratch)
        }

    @Test
    fun `independent re-derivation rejects corruption and revokes the private stage`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("corrupted-stage.json")
            val counter = AtomicLong()
            var corrupted = false
            val runtime = FullTreeFunctionObservationRuntime { checkpoint ->
                if (checkpoint == "before re-deriving staged function-observation output") {
                    val stage = Files.list(outputParent).use { it.toList().single() }
                    Files.write(stage, "corrupted staged observation\n".toByteArray())
                    corrupted = true
                }
                val elapsed = counter.getAndIncrement() * 1_000_000L
                FullTreeFunctionObservationRuntimeSample(
                    elapsed,
                    elapsed,
                    TEST_CURRENT_RESIDENT_BYTES,
                    TEST_PEAK_RESIDENT_BYTES,
                )
            }

            val failure = assertFailsWith<FullTreeFunctionObservationShardPublicationException> {
                FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = fixture.authenticatedScope(),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    limits = FullTreeFunctionObservationShardPublisherLimits(),
                    runtime = runtime,
                )
            }

            assertTrue(corrupted)
            assertTrue(
                failure.message.orEmpty().contains("candidate") ||
                    failure.cause?.message.orEmpty().contains("candidate"),
                failure.message,
            )
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(outputParent)
            assertDirectoryEmpty(scratch)
        }

    @Test
    fun `read-only validation rejects a corrupted candidate without mutating it`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("corrupted-existing.json")
            FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                richArtifact = fixture.richArtifact,
                inventoryPath = fixture.inventory,
                scope = scope,
                shardId = "clang-lib-driver",
                scratchParent = scratch,
                output = output,
                limits = FullTreeFunctionObservationShardPublisherLimits(),
                runtime = incrementingRuntime(),
            )
            val corrupted = Files.readAllBytes(output).also { it[0] = (it[0].toInt() xor 1).toByte() }
            Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rw-------"))
            Files.write(output, corrupted)
            Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("r--------"))

            val failure = assertFailsWith<FullTreeFunctionObservationShardPublicationException> {
                FullTreeFunctionObservationShardPublisher.loadAndValidateInternal(
                    candidate = output,
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = scope,
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    limits = FullTreeFunctionObservationShardPublisherLimits(),
                    runtime = incrementingRuntime(),
                )
            }

            assertTrue(failure.message.orEmpty().contains("candidate"), failure.message)
            assertContentEquals(corrupted, Files.readAllBytes(output))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(output, LinkOption.NOFOLLOW_LINKS),
            )
            assertEquals(listOf(output), Files.list(outputParent).use { it.toList() })
            assertDirectoryEmpty(scratch)
        }

    @Test
    fun `resident high-water violation revokes staged output`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scope = fixture.authenticatedScope()
            val maximumResidentBytes = scope.document.controlObject("bounds")
                .controlObject("perShard")
                .controlLong("maximumResidentBytes")
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("over-resident.json")
            val counter = AtomicLong()
            val runtime = FullTreeFunctionObservationRuntime { checkpoint ->
                val peak = if (checkpoint == "before re-deriving staged function-observation output") {
                    maximumResidentBytes + 1L
                } else {
                    TEST_PEAK_RESIDENT_BYTES
                }
                val elapsed = counter.getAndIncrement() * 1_000_000L
                FullTreeFunctionObservationRuntimeSample(
                    elapsed,
                    elapsed,
                    TEST_CURRENT_RESIDENT_BYTES,
                    peak,
                )
            }

            val failure = assertFailsWith<FullTreeFunctionObservationShardPublicationException> {
                FullTreeFunctionObservationShardPublisher.generateAndPublishInternal(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = scope,
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    limits = FullTreeFunctionObservationShardPublisherLimits(),
                    runtime = runtime,
                )
            }

            assertTrue(failure.message.orEmpty().contains("resident-memory bound"), failure.message)
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertDirectoryEmpty(outputParent)
            assertDirectoryEmpty(scratch)
        }

    private fun incrementingRuntime(): FullTreeFunctionObservationRuntime {
        val counter = AtomicLong()
        return FullTreeFunctionObservationRuntime {
            val elapsed = counter.getAndIncrement() * 1_000_000L
            FullTreeFunctionObservationRuntimeSample(
                elapsed,
                elapsed,
                TEST_CURRENT_RESIDENT_BYTES,
                TEST_PEAK_RESIDENT_BYTES,
            )
        }
    }

    private fun privateDirectory(path: Path): Path {
        Files.createDirectory(path)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        return path
    }

    private fun assertDirectoryEmpty(path: Path) {
        assertTrue(Files.list(path).use { it.findAny().isEmpty }, "unexpected residue below $path")
    }

    private companion object {
        const val TEST_CURRENT_RESIDENT_BYTES = 32L * 1024L * 1024L
        const val TEST_PEAK_RESIDENT_BYTES = 64L * 1024L * 1024L
    }
}
