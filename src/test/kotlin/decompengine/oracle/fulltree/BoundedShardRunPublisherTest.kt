package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BoundedShardRunPublisherTest {
    @Test
    fun `publisher reproduces the historical verifier-compatible v1 tree exactly`(): Unit =
        inTemporaryDirectory { directory ->
            val prepared = frozenPreparedOutputs(directory.resolve("prepared ?#%"), reverse = true)
            val target = directory.resolve("published ?#%")
            val validated = ArrayList<String>()

            val binding = BoundedShardRunPublisher.publish(
                target = target,
                runId = FROZEN_RUN_ID,
                preparedOutputs = prepared,
                bounds = frozenBounds(maximumWorkers = 1),
                semanticValidator = semanticValidator(validated),
            )

            assertEquals(listOf("alpha", "omega"), validated)
            assertEquals(FROZEN_RUN_SHA256, binding.runSha256)
            assertEquals(FROZEN_INDEX_SHA256, binding.indexArtifactSha256)
            assertEquals(listOf("alpha", "omega"), binding.outputs.map { it.shardId })
            assertEquals(listOf(210L, 210L), binding.outputs.map { it.outputBytes })
            assertEquals(listOf(1L, 1L), binding.outputs.map { it.entities })
            assertEquals(EXACT_TREE, treeMembers(target))
            EXACT_FILES.forEach { relative ->
                assertContentEquals(historicalBytes(1, relative), Files.readAllBytes(target.resolve(relative)))
            }
            assertEquals(
                PosixFilePermissions.fromString("r-x------"),
                Files.getPosixFilePermissions(target),
            )
            listOf("outputs", "checkpoints").forEach { directoryName ->
                assertEquals(
                    PosixFilePermissions.fromString("r-x------"),
                    Files.getPosixFilePermissions(target.resolve(directoryName)),
                )
            }
            EXACT_FILES.forEach { relative ->
                assertEquals(
                    PosixFilePermissions.fromString("r--------"),
                    Files.getPosixFilePermissions(target.resolve(relative)),
                )
            }

            val independentlyVerified = BoundedShardRunVerifier.verify(target, FROZEN_INDEX_SHA256)
            assertEquals(binding, independentlyVerified)
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `input order and worker declarations preserve deterministic content`(): Unit =
        inTemporaryDirectory { directory ->
            val prepared = frozenPreparedOutputs(directory.resolve("prepared"), reverse = true)
            val ordered = prepared.sortedBy { it.shardId }
            val reverseOne = directory.resolve("reverse-one")
            val orderedOne = directory.resolve("ordered-one")
            val workersTwo = directory.resolve("workers-two")

            val first = BoundedShardRunPublisher.publish(
                reverseOne,
                FROZEN_RUN_ID,
                prepared,
                frozenBounds(maximumWorkers = 1),
                semanticValidator(mutableListOf()),
            )
            val repeated = BoundedShardRunPublisher.publish(
                orderedOne,
                FROZEN_RUN_ID,
                ordered,
                frozenBounds(maximumWorkers = 1),
                semanticValidator(mutableListOf()),
            )
            val parallelDeclaration = BoundedShardRunPublisher.publish(
                workersTwo,
                FROZEN_RUN_ID,
                ordered,
                frozenBounds(maximumWorkers = 2),
                semanticValidator(mutableListOf()),
            )

            assertEquals(first.runSha256, repeated.runSha256)
            assertEquals(first.indexArtifactSha256, repeated.indexArtifactSha256)
            EXACT_FILES.forEach { relative ->
                assertContentEquals(
                    Files.readAllBytes(reverseOne.resolve(relative)),
                    Files.readAllBytes(orderedOne.resolve(relative)),
                )
            }
            assertNotEquals(first.runSha256, parallelDeclaration.runSha256)
            assertNotEquals(first.indexArtifactSha256, parallelDeclaration.indexArtifactSha256)
            assertEquals(
                first.outputs.map { Triple(it.shardId, it.outputSha256, it.outputBytes) },
                parallelDeclaration.outputs.map { Triple(it.shardId, it.outputSha256, it.outputBytes) },
            )
            listOf("alpha", "omega").forEach { shardId ->
                assertContentEquals(
                    Files.readAllBytes(reverseOne.resolve("outputs/$shardId.json")),
                    Files.readAllBytes(workersTwo.resolve("outputs/$shardId.json")),
                )
            }

            val report = FullTreeRunDeterminism.compareAndPublish(
                reverseOne,
                first.indexArtifactSha256,
                workersTwo,
                parallelDeclaration.indexArtifactSha256,
                directory.resolve("worker-determinism"),
            )
            assertEquals(emptyList(), report.differingShards)
            assertTrue(
                FullTreeRunDeterminism.validate(
                    directory.resolve("worker-determinism"),
                    report.artifactSha256,
                ).identical,
            )
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `bindings limits paths permissions conflicts and semantic rejection fail before publication`(): Unit =
        inTemporaryDirectory { directory ->
            fun reject(
                name: String,
                prepared: List<BoundedShardPreparedOutput>,
                bounds: BoundedShardRunPublicationBounds = frozenBounds(1),
                limits: BoundedShardRunLimits = BoundedShardRunLimits(),
                validator: BoundedShardOutputSemanticValidator = semanticValidator(mutableListOf()),
            ) {
                val target = directory.resolve(name)
                assertFailsWith<BoundedShardRunPublicationException> {
                    BoundedShardRunPublisher.publish(
                        target,
                        FROZEN_RUN_ID,
                        prepared,
                        bounds,
                        validator,
                        limits,
                    )
                }
                assertFalse(Files.exists(target))
                assertNoPublicationResidue(directory)
            }

            val badDigest = frozenPreparedOutputs(directory.resolve("bad-digest"))
            reject("digest-target", badDigest.mapIndexed { index, output ->
                if (index == 0) output.copy(outputSha256 = "f".repeat(64)) else output
            })

            val badCount = frozenPreparedOutputs(directory.resolve("bad-count"))
            reject("count-target", badCount.mapIndexed { index, output ->
                if (index == 0) output.copy(entities = 9L) else output
            })

            val badBytes = frozenPreparedOutputs(directory.resolve("bad-bytes"))
            reject("bytes-target", badBytes.mapIndexed { index, output ->
                if (index == 0) output.copy(outputBytes = 209L) else output
            })

            val bounded = frozenPreparedOutputs(directory.resolve("bounded"))
            reject(
                "limit-target",
                bounded,
                bounds = frozenBounds(2),
                limits = BoundedShardRunLimits(maximumWorkers = 1),
            )

            val duplicated = frozenPreparedOutputs(directory.resolve("duplicated"))
            reject("duplicate-target", listOf(duplicated[0], duplicated[1].copy(shardId = "alpha")))

            val writable = frozenPreparedOutputs(directory.resolve("writable"))
            Files.setPosixFilePermissions(writable[0].output, PosixFilePermissions.fromString("rw-------"))
            reject("writable-target", writable)

            val linked = frozenPreparedOutputs(directory.resolve("linked"))
            val symbolic = directory.resolve("linked/alpha-link.json")
            Files.createSymbolicLink(symbolic, linked[0].output.fileName)
            reject("symlink-target", linked.mapIndexed { index, output ->
                if (index == 0) output.copy(output = symbolic) else output
            })

            val rejectedSemantics = frozenPreparedOutputs(directory.resolve("semantic-rejection"))
            reject(
                "semantic-target",
                rejectedSemantics,
                validator = BoundedShardOutputSemanticValidator {
                    throw IllegalArgumentException("semantic authority rejected output")
                },
            )

            val existingInputs = frozenPreparedOutputs(directory.resolve("existing-inputs"))
            val existing = Files.createDirectory(directory.resolve("existing-target"))
            val sentinel = existing.resolve("sentinel")
            Files.writeString(sentinel, "preserve")
            assertFailsWith<BoundedShardRunPublicationException> {
                BoundedShardRunPublisher.publish(
                    existing,
                    FROZEN_RUN_ID,
                    existingInputs,
                    frozenBounds(1),
                    semanticValidator(mutableListOf()),
                )
            }
            assertEquals("preserve", Files.readString(sentinel))
            assertNoPublicationResidue(directory)

            val racedInputs = frozenPreparedOutputs(directory.resolve("raced-inputs"))
            val racedTarget = directory.resolve("raced-target")
            var reserved = false
            assertFailsWith<BoundedShardRunPublicationException> {
                BoundedShardRunPublisher.publishForTesting(
                    racedTarget,
                    FROZEN_RUN_ID,
                    racedInputs,
                    frozenBounds(1),
                    semanticValidator(mutableListOf()),
                    probe = BoundedShardRunPublicationProbe { stage ->
                        if (stage == BoundedShardRunPublicationStage.AFTER_TARGET_ABSENCE_CHECK) {
                            Files.createDirectory(racedTarget)
                            reserved = true
                        }
                    },
                )
            }
            assertTrue(reserved)
            assertTrue(Files.isDirectory(racedTarget))
            assertEquals(emptySet(), Files.list(racedTarget).use { it.toList().toSet() })
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `callback mutation source substitution and post-move failure leave no publication residue`(): Unit =
        inTemporaryDirectory { directory ->
            val callbackInputs = frozenPreparedOutputs(directory.resolve("callback-inputs"))
            val callbackTarget = directory.resolve("callback-target")
            assertFailsWith<BoundedShardRunPublicationException> {
                BoundedShardRunPublisher.publish(
                    callbackTarget,
                    FROZEN_RUN_ID,
                    callbackInputs,
                    frozenBounds(1),
                    BoundedShardOutputSemanticValidator { validation ->
                        Files.setPosixFilePermissions(
                            validation.output,
                            PosixFilePermissions.fromString("rw-------"),
                        )
                    },
                )
            }
            assertFalse(Files.exists(callbackTarget))
            assertNoPublicationResidue(directory)

            val substitutedInputs = frozenPreparedOutputs(directory.resolve("substituted-inputs"))
            val substitutedTarget = directory.resolve("substituted-target")
            var substituted = false
            assertFailsWith<BoundedShardRunPublicationException> {
                BoundedShardRunPublisher.publishForTesting(
                    substitutedTarget,
                    FROZEN_RUN_ID,
                    substitutedInputs,
                    frozenBounds(1),
                    semanticValidator(mutableListOf()),
                    probe = BoundedShardRunPublicationProbe { stage ->
                        if (stage == BoundedShardRunPublicationStage.BEFORE_ATOMIC_MOVE && !substituted) {
                            substituted = true
                            val source = substitutedInputs.first().output
                            val bytes = Files.readAllBytes(source)
                            Files.move(source, source.resolveSibling("alpha-original.json"))
                            Files.write(source, bytes)
                            Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("r--------"))
                        }
                    },
                )
            }
            assertTrue(substituted)
            assertFalse(Files.exists(substitutedTarget))
            assertNoPublicationResidue(directory)

            val revokedInputs = frozenPreparedOutputs(directory.resolve("revoked-inputs"))
            val revokedTarget = directory.resolve("revoked-target")
            var moved = false
            assertFailsWith<BoundedShardRunPublicationException> {
                BoundedShardRunPublisher.publishForTesting(
                    revokedTarget,
                    FROZEN_RUN_ID,
                    revokedInputs,
                    frozenBounds(1),
                    semanticValidator(mutableListOf()),
                    probe = BoundedShardRunPublicationProbe { stage ->
                        if (stage == BoundedShardRunPublicationStage.AFTER_ATOMIC_MOVE) {
                            moved = Files.exists(revokedTarget)
                            throw IllegalStateException("injected post-move failure")
                        }
                    },
                )
            }
            assertTrue(moved)
            assertFalse(Files.exists(revokedTarget))
            assertNoPublicationResidue(directory)
        }

    private fun frozenPreparedOutputs(root: Path, reverse: Boolean = false): List<BoundedShardPreparedOutput> {
        Files.createDirectory(root)
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        val outputs = listOf(
            preparedOutput(root, "alpha", "1".repeat(64), FROZEN_ALPHA_SHA256),
            preparedOutput(root, "omega", "2".repeat(64), FROZEN_OMEGA_SHA256),
        )
        return if (reverse) outputs.reversed() else outputs
    }

    private fun preparedOutput(
        root: Path,
        shardId: String,
        inputSha256: String,
        outputSha256: String,
    ): BoundedShardPreparedOutput {
        val path = root.resolve("$shardId.json")
        Files.write(path, historicalBytes(1, "outputs/$shardId.json"))
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        return BoundedShardPreparedOutput(
            shardId = shardId,
            inputSha256 = inputSha256,
            output = path,
            outputSha256 = outputSha256,
            outputBytes = 210L,
            entities = 1L,
        )
    }

    private fun semanticValidator(order: MutableList<String>) = BoundedShardOutputSemanticValidator { validation ->
        val bytes = Files.readAllBytes(validation.output)
        val document = OracleJson.parseCanonical(bytes) as JsonObject
        assertEquals(validation.outputBytes, bytes.size.toLong())
        assertEquals(validation.outputSha256, OracleArtifacts.sha256(bytes))
        assertEquals(validation.shardId, (document["shardId"] as JsonPrimitive).content)
        assertEquals(validation.inputSha256, (document["inputSha256"] as JsonPrimitive).content)
        assertEquals(validation.entities, (document["entities"] as JsonArray).size.toLong())
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(validation.output),
        )
        order.add(validation.shardId)
    }

    private fun frozenBounds(maximumWorkers: Int) = BoundedShardRunPublicationBounds(
        maximumShards = 2,
        perShardEntities = 8L,
        wholeRunEntities = 16L,
        perShardBytes = 4096L,
        wholeRunBytes = 8192L,
        perShardSeconds = 10.0,
        wholeRunSeconds = 30.0,
        perShardCpuSeconds = 10.0,
        wholeRunCpuSeconds = 30.0,
        maximumResidentBytes = 1024L * 1024L * 1024L,
        maximumWorkers = maximumWorkers,
    )

    private fun historicalBytes(workers: Int, relative: String): ByteArray = checkNotNull(
        javaClass.getResourceAsStream(
            "/oracle/bounded-shard-run-v1-frozen/workers-$workers/$relative",
        ),
    ) { "historical bounded-shard v1 member is unavailable: $relative" }.use { it.readAllBytes() }

    private fun treeMembers(root: Path): Set<String> = Files.walk(root).use { paths ->
        paths.map { root.relativize(it).toString() }.toList().toSet()
    }

    private fun assertNoPublicationResidue(parent: Path) {
        val residue = Files.walk(parent).use { paths ->
            paths.filter { path -> ".bounded-shard-stage-" in path.fileName.toString() }.toList()
        }
        assertEquals(emptyList(), residue)
    }

    private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
        val container = createTempDirectory("bounded-shard-publisher-test-")
        val directory = Files.createDirectory(container.resolve("workspace"))
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        return try {
            block(directory)
        } finally {
            val paths = Files.walk(container).use { it.toList() }
            paths.filter { Files.isDirectory(it) }.forEach { path ->
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val FROZEN_RUN_ID = "frozen-determinism"
        const val FROZEN_RUN_SHA256 =
            "01f7d381e08676528d873ecf6be1e2a0aa2659ea4b2befa33625d01444d71d24"
        const val FROZEN_INDEX_SHA256 =
            "9784e592199e923ba238ba7eddc8a8059164b97c3d3afac4000131007df58ec4"
        const val FROZEN_ALPHA_SHA256 =
            "c5c3b58fac58ac3fdb9701aabcec4316af91660cba012117b714811607ceb264"
        const val FROZEN_OMEGA_SHA256 =
            "11b828e10169186e82ef4b590bb15dd7b8362fd4c0a4f8974d5118f6273cd41b"

        val EXACT_FILES = setOf(
            "run.json",
            "index.json",
            "outputs/alpha.json",
            "outputs/omega.json",
            "checkpoints/alpha.json",
            "checkpoints/omega.json",
        )
        val EXACT_TREE = EXACT_FILES + setOf("", "outputs", "checkpoints")

        /*
         * Compatibility provenance: these literal hashes and the existing frozen resources were
         * emitted on 2026-08-30 by the checked-in historical Python bounded-shards v1 producer.
         * They are inert differential witnesses; Kotlin production and tests never invoke Python.
         */
    }
}
