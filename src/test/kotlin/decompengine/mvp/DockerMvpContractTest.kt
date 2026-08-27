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
        assertTrue(dockerfile.lineSequence().any { it.trim() == "USER llm-bin-patch" })
        assertFalse(runner.contains("BASE_URL"))
        assertFalse(runner.contains("API_KEY"))
        assertFalse(runner.contains("MODEL"))
        assertTrue(runner.contains("network_mode: none"))
        assertTrue(builder.contains("- clang"))
        assertTrue(builder.contains("network_mode: none"))
        assertTrue(builder.contains("read_only: true"))
        assertTrue(builder.contains("/tmp:size=64m,noexec,nosuid,nodev,mode=1777"))
        assertTrue(builder.contains("/fixture:ro"))
        assertFalse(builder.contains("API_KEY"))

        val provider = compose.substringAfter("  mvp-fake-provider:").substringBefore("\nvolumes:")
        assertTrue(provider.contains("read_only: true"))
        assertTrue(provider.contains("no-new-privileges:true"))
        assertTrue(provider.contains("/tmp:size=8m,noexec,nosuid,nodev,mode=1777"))
        assertFalse(provider.contains("CVUL_SOURCE_DIR"))
        assertTrue(compose.contains("default:\n    internal: \${MVP_FAKE_PROVIDER:-false}"))
    }

    @Test
    fun `end to end validation script checks pinned input output layout and evidence`() {
        val script = Path.of("scripts/validate-mvp-docker.sh").readText()

        assertTrue(script.contains("git submodule update --init --recursive benchmarks/fixtures/c-vul"))
        assertTrue(script.contains("actual_fixture_commit"))
        assertTrue(script.contains("the MVP acceptance run requires a clean checkout"))
        assertTrue(script.contains("01_out_of_bounds_write.c"))
        assertTrue(script.contains("--profile acceptance run --rm --no-deps fixture-builder"))
        assertTrue(script.contains("chmod 0777 \"\$validation_root/input\" \"\$validation_root/output\""))
        assertTrue(script.contains("binds_ready=false"))
        assertTrue(script.contains("\"\${OUTPUT_DIR:-}\" == \"\$validation_root/output\""))
        assertTrue(script.indexOf("binds_ready=true") < script.indexOf("fixture-builder --version"))
        assertTrue(script.contains("INPUT_PROVENANCE.txt"))
        assertTrue(script.contains("--entrypoint /input/binary_01 binary-runner"))
        assertTrue(script.contains("up --detach --wait --wait-timeout 30 mvp-fake-provider"))
        assertTrue(script.contains("accepted mvp request 2: memory-safety"))
        assertTrue(script.contains("patch /input/binary_01 --output /output/mvp --yes"))
        assertTrue(script.contains("[03] Alexandria Stone"))
        assertTrue(script.contains("cwe-787-sanitizer.txt"))
        assertTrue(script.contains("networkIsolated=true; credentialsIsolated=true"))
        assertTrue(script.contains("API key leaked into MVP artifacts"))
        assertTrue(script.contains("API key artifact scan failed with exit code"))
        assertTrue(script.contains("source hash artifact scan failed with exit code"))
        assertTrue(script.contains("grep -r --devices=skip --fixed-strings --quiet -- \"\$API_KEY\" /output/mvp"))
        assertTrue(script.contains("--entrypoint /output/mvp/patched_binary/patched_binary binary-runner"))
    }

    @Test
    fun `credential free MVP provider is bounded and fixture scoped`() {
        val config = Path.of("benchmarks/fixtures/mvp-c-vul/fake-provider.env").readText()
        val provider = Path.of("benchmarks/fixtures/mvp-c-vul/fake_openai_provider.py").readText()

        assertTrue(config.contains("MVP_FAKE_PROVIDER=true"))
        assertTrue(config.contains("API_KEY=mvp-fixture-not-a-secret-v1"))
        assertTrue(provider.contains("MAXIMUM_REQUEST_BYTES = 4 * 1024 * 1024"))
        assertTrue(provider.contains("EXPECTED_SEQUENCE = (\"binary-reconstruction\", \"memory-safety\")"))
        assertTrue(provider.contains("self.connection.settimeout(5)"))
        assertTrue(provider.contains("HTTPServer((HOST, PORT), FixtureHandler)"))
        assertFalse(provider.contains("ThreadingHTTPServer"))
        assertTrue(provider.contains("request is outside the pinned MVP fixture contract"))
        assertFalse(provider.contains("benchmarks/fixtures/c-vul/src"))
    }
}
