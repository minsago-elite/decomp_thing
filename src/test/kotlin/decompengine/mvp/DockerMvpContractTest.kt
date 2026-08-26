package decompengine.mvp

import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DockerMvpContractTest {
    @Test
    fun `runtime image and compose runner exclude fixture source and credentials`() {
        val dockerignore = Path.of(".dockerignore").readText()
        val dockerfile = Path.of("Dockerfile").readText()
        val compose = Path.of("compose.yaml").readText()
        val runner = compose.substringAfter("  binary-runner:").substringBefore("\nvolumes:")
        val builder = compose.substringAfter("  fixture-builder:").substringBefore("\nvolumes:")

        assertTrue(dockerignore.lineSequence().any { it.trim() == "benchmarks/fixtures/c-vul" })
        assertFalse(dockerfile.contains("COPY --from=build /workspace/benchmarks/fixtures/c-vul"))
        assertFalse(dockerfile.contains("CVUL_HOME"))
        assertFalse(runner.contains("BASE_URL"))
        assertFalse(runner.contains("API_KEY"))
        assertFalse(runner.contains("MODEL"))
        assertTrue(runner.contains("network_mode: none"))
        assertTrue(builder.contains("- clang"))
        assertTrue(builder.contains("network_mode: none"))
        assertTrue(builder.contains("/fixture:ro"))
        assertFalse(builder.contains("API_KEY"))
    }

    @Test
    fun `end to end validation script checks pinned input output layout and evidence`() {
        val script = Path.of("scripts/validate-mvp-docker.sh").readText()

        assertTrue(script.contains("git submodule update --init --recursive benchmarks/fixtures/c-vul"))
        assertTrue(script.contains("actual_fixture_commit"))
        assertTrue(script.contains("the MVP acceptance run requires a clean checkout"))
        assertTrue(script.contains("01_out_of_bounds_write.c"))
        assertTrue(script.contains("--profile acceptance run --rm --no-deps fixture-builder"))
        assertTrue(script.contains("INPUT_PROVENANCE.txt"))
        assertTrue(script.contains("--entrypoint /input/binary_01 binary-runner"))
        assertTrue(script.contains("patch /input/binary_01 --output /output/mvp --yes"))
        assertTrue(script.contains("[03] Alexandria Stone"))
        assertTrue(script.contains("cwe-787-sanitizer.txt"))
        assertTrue(script.contains("networkIsolated=true; credentialsIsolated=true"))
        assertTrue(script.contains("API key leaked into MVP artifacts"))
        assertTrue(script.contains("--entrypoint /output/mvp/patched_binary/patched_binary binary-runner"))
    }
}
