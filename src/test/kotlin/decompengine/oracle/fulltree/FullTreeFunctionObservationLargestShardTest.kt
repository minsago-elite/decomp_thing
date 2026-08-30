package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Opt-in disk/RSS proof for the largest authenticated historical-v3 shard. */
class FullTreeFunctionObservationLargestShardTest {
    @Test
    fun `largest frozen shard fits authenticated SQLite output and resident bounds`() {
        assumeTrue(
            System.getenv("DECOMP_A13_RUN_LARGEST_SHARD") == "1",
            "set DECOMP_A13_RUN_LARGEST_SHARD=1 for the long production proof",
        )
        val release = requireEnvironmentPath("DECOMP_A13_RELEASE_ROOT")
        val functions = requireEnvironmentPath("DECOMP_A13_FUNCTIONS_ROOT")
        val scope = FullTreeScopeControl.load(
            functions.resolve("control/scope.json"),
            release.resolve("source-lock.json"),
            release.resolve("oracle-manifest.json"),
        )

        inControlTemporaryDirectory { scratch ->
            val output = scratch.resolve("llvm-lib-transforms.json")
            val result = FullTreeFunctionObservationShardPublisher.generateAndPublish(
                richArtifact = release.resolve("artifacts/clang-driver.full"),
                inventoryPath = functions.resolve("control/inventory.json"),
                scope = scope,
                shardId = "llvm-lib-transforms",
                scratchParent = scratch,
                output = output,
            )

            assertEquals(481_793_648L, result.outputBytes)
            assertEquals(
                "76a19b35e69ee47d512c524c525dd38d76756369b16c19bf1df522416ae46102",
                result.outputSha256,
            )
            assertEquals(result.outputBytes, Files.size(output))
            assertEquals(304_752L, result.entities)
            assertEquals(13_354_065L, result.scannedDies)
            assertEquals(686_518_272L, result.databaseHighWaterBytes)
            assertTrue(result.databaseHighWaterBytes in 1L..2L * 1024L * 1024L * 1024L)
            assertTrue(result.peakResidentBytes in 1L..4L * 1024L * 1024L * 1024L)
            println(
                "largest-shard-proof outputBytes=${result.outputBytes} " +
                    "databaseHighWaterBytes=${result.databaseHighWaterBytes} " +
                    "peakResidentBytes=${result.peakResidentBytes}",
            )
        }
    }

    private fun requireEnvironmentPath(name: String): Path {
        val value = System.getenv(name)?.takeIf(String::isNotBlank)
        assumeTrue(value != null, "set $name for the long production proof")
        return Path.of(checkNotNull(value)).toAbsolutePath().normalize()
    }
}
