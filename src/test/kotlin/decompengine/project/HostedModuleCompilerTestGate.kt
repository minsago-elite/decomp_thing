package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.TestInfo

/**
 * Opt-in test admission only; the real policy still authenticates configuration and execution.
 * Call from @BeforeEach and serialize users of the dedicated scratch slot with
 * @ResourceLock("contained-module-compilation-runtime") and same-thread execution.
 */
internal fun requireHostedModuleCompiler(test: TestInfo) {
    if ("ci-live" !in test.tags) return
    val file = System.getenv("GENERATED_C_MODULE_COMPILE_CONFIG_FILE")
    val directory = System.getenv("GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY")
    val configured = file != null || directory != null
    if (System.getenv("GENERATED_C_MODULE_COMPILE_REQUIRE") == "true") {
        assertTrue(configured, "required module acceptance tests need the provisioned contained compiler runtime")
    }
    assumeTrue(configured, "configure the contained compiler to run module acceptance tests")
    // Once selected, malformed or unavailable configuration must fail qualification, not skip it.
    assertTrue(System.getProperty("os.name").lowercase().contains("linux"))
    assertTrue(file == null || directory == null, "compiler file and directory configuration are mutually exclusive")
    file?.let { assertTrue(it.isNotBlank() && Files.isRegularFile(Path.of(it)), "configured compiler file is missing") }
    directory?.let { assertTrue(it.isNotBlank() && Files.isDirectory(Path.of(it)), "configured compiler directory is missing") }
}
