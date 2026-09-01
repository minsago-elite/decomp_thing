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
                "ENTRYPOINT [\"/decomp-jdk/bin/java\",\"-Djna.nosys=true\",\"-Djna.tmpdir=/decomp-jna\",\"-cp\",\"/decomp-app/lib/*\",\"decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain\"]",
                "CMD []",
            ),
            EXPECTED_DOCKERFILE.lineSequence().filter(String::isNotBlank).toList(),
        )
    }

    private companion object {
        val DOCKERFILE: Path =
            Path.of("oracle/llvm/22.1.6/hosted-clean-build-v2-worker.Dockerfile")
        const val EXPECTED_DOCKERFILE_SHA256 =
            "6da99d34eed94961fe8657317e90f64bfd16a186fb8f598097589d1a650948da"
        val EXPECTED_DOCKERFILE = """
            ARG TOOLCHAIN_IMAGE
            FROM ${'$'}{TOOLCHAIN_IMAGE}

            COPY jdk/ /decomp-jdk/
            COPY app/lib/ /decomp-app/lib/

            ENTRYPOINT ["/decomp-jdk/bin/java","-Djna.nosys=true","-Djna.tmpdir=/decomp-jna","-cp","/decomp-app/lib/*","decompengine.oracle.behavior.LlvmBehaviorHostedCleanBuildV2InnerWorkerMain"]
            CMD []
        """.trimIndent() + "\n"
    }
}
