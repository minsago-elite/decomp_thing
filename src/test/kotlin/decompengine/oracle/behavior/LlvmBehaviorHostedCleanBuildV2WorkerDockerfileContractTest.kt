package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals

class LlvmBehaviorHostedCleanBuildV2WorkerDockerfileContractTest {
    @Test
    fun `derived worker image has the reviewed fixed build and launch surface`() {
        val bytes = Files.readAllBytes(DOCKERFILE)

        assertContentEquals(EXPECTED_DOCKERFILE.toByteArray(StandardCharsets.UTF_8), bytes)
        assertEquals(EXPECTED_DOCKERFILE_SHA256, OracleArtifacts.sha256(bytes))
        assertEquals(
            listOf(
                "ARG TOOLCHAIN_IMAGE",
                "FROM \${TOOLCHAIN_IMAGE}",
                "COPY jdk/ /decomp-jdk/",
                "COPY app/lib/ /decomp-app/lib/",
                "COPY app/worker.args /decomp-app/worker.args",
                "ENTRYPOINT [\"/decomp-jdk/bin/java\",\"@/decomp-app/worker.args\"]",
                "CMD []",
            ),
            EXPECTED_DOCKERFILE.lineSequence().filter(String::isNotBlank).toList(),
        )
    }

    private companion object {
        val DOCKERFILE: Path =
            Path.of("oracle/llvm/22.1.6/hosted-clean-build-v2-worker.Dockerfile")
        const val EXPECTED_DOCKERFILE_SHA256 =
            "fee734ad2acdf083e1cc71a286255af76a14b3175016a888a1761060acb143cf"
        val EXPECTED_DOCKERFILE = """
            ARG TOOLCHAIN_IMAGE
            FROM ${'$'}{TOOLCHAIN_IMAGE}

            COPY jdk/ /decomp-jdk/
            COPY app/lib/ /decomp-app/lib/
            COPY app/worker.args /decomp-app/worker.args

            ENTRYPOINT ["/decomp-jdk/bin/java","@/decomp-app/worker.args"]
            CMD []
        """.trimIndent() + "\n"
    }
}
