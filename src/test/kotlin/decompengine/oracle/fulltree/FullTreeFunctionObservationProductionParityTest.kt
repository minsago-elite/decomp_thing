package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Opt-in byte-parity probe against the authenticated local A13 migration corpus. */
class FullTreeFunctionObservationProductionParityTest {
    @Test
    fun `Kotlin scanner reproduces the frozen current v3 generated shard`() {
        val release = environmentPath("DECOMP_A13_RELEASE_ROOT")
        val functions = environmentPath("DECOMP_A13_FUNCTIONS_ROOT")
        assumeTrue(release != null && functions != null, "set both DECOMP_A13_*_ROOT paths for parity")
        checkNotNull(release)
        checkNotNull(functions)

        val scope = FullTreeScopeControl.load(
            functions.resolve("control/scope.json"),
            release.resolve("source-lock.json"),
            release.resolve("oracle-manifest.json"),
        )
        val expected = functions.resolve("outputs/generated-tools-clang.json")
        assumeTrue(Files.isRegularFile(expected), "frozen v3 generated shard is unavailable")
        inControlTemporaryDirectory { scratch ->
            val result = FullTreeFunctionObservationProducer.generateShard(
                richArtifact = release.resolve("artifacts/clang-driver.full"),
                inventoryPath = functions.resolve("control/inventory.json"),
                scope = scope,
                shardId = "generated-tools-clang",
                scratchParent = scratch,
            )
            assertEquals(3_090L, result.outputBytes)
            assertEquals(
                "f53c3c5f06bb17aa4d9a86bfe9ed56d7733d1cc121452ac49863cd06b05c28d2",
                result.outputSha256,
            )
            assertTrue(
                Files.readAllBytes(expected).contentEquals(
                    FullTreeFunctionObservations.canonicalEnvelopeBytes(result.document),
                ),
            )
        }
    }

    private fun environmentPath(name: String): Path? = System.getenv(name)
        ?.takeIf(String::isNotBlank)
        ?.let(Path::of)
        ?.toAbsolutePath()
        ?.normalize()
}
