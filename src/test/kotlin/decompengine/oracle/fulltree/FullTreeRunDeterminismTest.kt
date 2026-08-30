package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeRunDeterminismTest {
    @Test
    fun `frozen historical v2 bytes exclude only worker count and publish deterministically`(): Unit =
        inTemporaryDirectory { directory ->
            val first = FrozenBoundedShardFixture.copyRun(1, directory.resolve("first ?#%"))
            val second = FrozenBoundedShardFixture.copyRun(2, directory.resolve("second ?#%"))
            val outputOne = directory.resolve("report one ?#%")
            val outputTwo = directory.resolve("report two ?#%")

            val firstGeneration = FullTreeRunDeterminism.compareAndPublish(
                first,
                FROZEN_FIRST_INDEX_SHA256,
                second,
                FROZEN_SECOND_INDEX_SHA256,
                outputOne,
            )
            val secondGeneration = FullTreeRunDeterminism.compareAndPublish(
                first,
                FROZEN_FIRST_INDEX_SHA256,
                second,
                FROZEN_SECOND_INDEX_SHA256,
                outputTwo,
            )
            val actual = Files.readAllBytes(outputOne.resolve("report.json"))
            val repeated = Files.readAllBytes(outputTwo.resolve("report.json"))
            val frozen = checkNotNull(
                javaClass.getResourceAsStream("/oracle/full-tree-determinism-v2-frozen.json"),
            ) { "frozen v2 determinism fixture is unavailable" }.use { it.readAllBytes() }

            assertTrue(actual.contentEquals(frozen))
            assertTrue(actual.contentEquals(repeated))
            assertEquals(firstGeneration, secondGeneration)
            assertEquals(FROZEN_REPORT_SHA256, firstGeneration.reportSha256)
            assertEquals(FROZEN_REPORT_ARTIFACT_SHA256, firstGeneration.artifactSha256)
            assertEquals(FROZEN_CONTENT_CONTRACT_SHA256, firstGeneration.contentContractSha256)
            assertEquals(emptyList(), firstGeneration.differingShards)
            assertEquals(setOf("", "report.json"), Files.walk(outputOne).use { paths ->
                paths.map { outputOne.relativize(it).toString() }.toList().toSet()
            })

            val binding = FullTreeRunDeterminism.validate(outputOne, firstGeneration.artifactSha256)
            assertTrue(binding.identical)
            assertEquals(2L, binding.shards)
            assertEquals(FROZEN_REPORT_SHA256, binding.reportSha256)
            assertEquals(FROZEN_FIRST_INDEX_SHA256, binding.firstIndexSha256)
            assertEquals(FROZEN_SECOND_INDEX_SHA256, binding.secondIndexSha256)
        }

    @Test
    fun `authenticated output differences produce exact ordered shard identities`(): Unit =
        inTemporaryDirectory { directory ->
            val first = FrozenBoundedShardFixture.copyRun(1, directory.resolve("first"))
            val second = FrozenBoundedShardFixture.copyRun(2, directory.resolve("second"))
            val omega = FrozenBoundedShardFixture.parseObject(
                Files.readAllBytes(second.resolve("outputs/omega.json")),
            )
            FrozenBoundedShardFixture.writeCanonical(
                second.resolve("outputs/omega.json"),
                JsonObject(omega + ("shardId" to JsonPrimitive("omega-mutated"))),
            )
            val reboundSecondIndex = FrozenBoundedShardFixture.rebind(second)
            val output = directory.resolve("different-report")

            val generation = FullTreeRunDeterminism.compareAndPublish(
                first,
                FROZEN_FIRST_INDEX_SHA256,
                second,
                reboundSecondIndex,
                output,
            )
            assertEquals(listOf("omega"), generation.differingShards)
            val binding = FullTreeRunDeterminism.validate(output, generation.artifactSha256)
            assertFalse(binding.identical)
            assertEquals(listOf("omega"), binding.differingShards)
        }

    @Test
    fun `content contract rejects every run mutation except maximumWorkers`(): Unit =
        inTemporaryDirectory { directory ->
            val first = FrozenBoundedShardFixture.copyRun(1, directory.resolve("first"))
            val mutated = FrozenBoundedShardFixture.copyRun(2, directory.resolve("mutated"))
            val runPath = mutated.resolve("run.json")
            val run = FrozenBoundedShardFixture.parseObject(Files.readAllBytes(runPath))
            FrozenBoundedShardFixture.writeCanonical(
                runPath,
                JsonObject(run + ("id" to JsonPrimitive("different-contract"))),
            )
            val mutatedIndex = FrozenBoundedShardFixture.rebind(mutated)
            val output = directory.resolve("rejected-report")

            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.compareAndPublish(
                    first,
                    FROZEN_FIRST_INDEX_SHA256,
                    mutated,
                    mutatedIndex,
                    output,
                )
            }
            assertFalse(Files.exists(output))
            assertNoPublicationResidue(directory)
        }

    @Test
    fun `report validation rejects stale self hashes malformed bytes and extra membership`(): Unit =
        inTemporaryDirectory { directory ->
            val first = FrozenBoundedShardFixture.copyRun(1, directory.resolve("first"))
            val second = FrozenBoundedShardFixture.copyRun(2, directory.resolve("second"))
            val output = directory.resolve("valid-report")
            val generated = FullTreeRunDeterminism.compareAndPublish(
                first,
                FROZEN_FIRST_INDEX_SHA256,
                second,
                FROZEN_SECOND_INDEX_SHA256,
                output,
            )
            Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"))
            Files.writeString(output.resolve("extra.json"), "{}\n")
            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.validate(output, generated.artifactSha256)
            }

            val staleRoot = directory.resolve("stale-report")
            Files.createDirectory(staleRoot)
            val frozen = checkNotNull(
                javaClass.getResourceAsStream("/oracle/full-tree-determinism-v2-frozen.json"),
            ).use { it.readAllBytes() }
            val report = FrozenBoundedShardFixture.parseObject(frozen)
            FrozenBoundedShardFixture.writeCanonical(
                staleRoot.resolve("report.json"),
                JsonObject(report + ("reportSha256" to JsonPrimitive("f".repeat(64)))),
            )
            val staleArtifact = OracleArtifacts.sha256(Files.readAllBytes(staleRoot.resolve("report.json")))
            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.validate(staleRoot, staleArtifact)
            }

            val malformedRoot = directory.resolve("malformed-report")
            Files.createDirectory(malformedRoot)
            Files.writeString(malformedRoot.resolve("report.json"), "{\n")
            val malformedArtifact = OracleArtifacts.sha256(
                Files.readAllBytes(malformedRoot.resolve("report.json")),
            )
            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.validate(malformedRoot, malformedArtifact)
            }
        }

    @Test
    fun `publication limits conflicts and post-move deadlines leave no usable artifact`(): Unit =
        inTemporaryDirectory { directory ->
            val first = FrozenBoundedShardFixture.copyRun(1, directory.resolve("first"))
            val second = FrozenBoundedShardFixture.copyRun(2, directory.resolve("second"))
            val existing = directory.resolve("existing")
            Files.createDirectory(existing)
            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.compareAndPublish(
                    first,
                    FROZEN_FIRST_INDEX_SHA256,
                    second,
                    FROZEN_SECOND_INDEX_SHA256,
                    existing,
                )
            }

            val bounded = directory.resolve("bounded")
            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.compareAndPublish(
                    first,
                    FROZEN_FIRST_INDEX_SHA256,
                    second,
                    FROZEN_SECOND_INDEX_SHA256,
                    bounded,
                    FullTreeRunDeterminismLimits(maximumReportBytes = 512),
                )
            }
            assertFalse(Files.exists(bounded))

            val deadline = directory.resolve("deadline")
            var reached = false
            val runtime = FullTreeRunDeterminismRuntime { stage ->
                if (stage == "after atomic determinism report publication") reached = true
                FullTreeRunDeterminismRuntimeSample(
                    wallNanos = if (reached) 3601L * 1_000_000_000L else 0L,
                    processCpuNanos = 0L,
                )
            }
            assertFailsWith<FullTreeRunDeterminismException> {
                FullTreeRunDeterminism.compareAndPublishForTesting(
                    first,
                    FROZEN_FIRST_INDEX_SHA256,
                    second,
                    FROZEN_SECOND_INDEX_SHA256,
                    deadline,
                    runtime = runtime,
                )
            }
            assertTrue(reached)
            assertFalse(Files.exists(deadline))
            assertNoPublicationResidue(directory)
        }

    private fun assertNoPublicationResidue(parent: Path) {
        val residue = Files.walk(parent).use { paths ->
            paths.filter { path -> ".determinism-stage-" in path.fileName.toString() }.toList()
        }
        assertEquals(emptyList(), residue)
    }

    private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
        val container = createTempDirectory("full-tree-run-determinism-test-")
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
        const val FROZEN_FIRST_INDEX_SHA256 =
            "9784e592199e923ba238ba7eddc8a8059164b97c3d3afac4000131007df58ec4"
        const val FROZEN_SECOND_INDEX_SHA256 =
            "232cc1cd9b47b931174cf84ebe8b5301c254c4898b0dc4a7e8e6346355ae55bd"

        /*
         * One-time migration provenance: both bounded runs and this report were emitted on
         * 2026-08-30 by the checked-in historical Python v1/v2 implementations. They are inert,
         * independently frozen compatibility witnesses. Kotlin production and tests never invoke
         * or import Python, and expected hashes are literals rather than Kotlin-derived blessings.
         */
        const val FROZEN_CONTENT_CONTRACT_SHA256 =
            "77d23d1fe3176f7decf426f09537ead98d65c9b7283f0832281171843444b733"
        const val FROZEN_REPORT_SHA256 =
            "4fc4e09387b88b1035b066549645dd6792554769d5035923be2b52c573658251"
        const val FROZEN_REPORT_ARTIFACT_SHA256 =
            "cd917ab2ba0b5de98298e6d337dc15695fb1657e772204cbfeb492ba7384f365"
    }
}
