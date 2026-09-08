package decompengine

import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InstalledReconstructionCliTest {
    @Test
    fun `installed CLI validates profile selection before creating reconstruction output`() {
        val temp = Files.createTempDirectory("installed-reconstruction-profile-")
        val output = temp.resolve("result")
        val launcher = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch/bin/llm_bin_patch")
        val cases = listOf(
            listOf("--profile", "generated-c-ninja-v1") to "reconstruct requires an input binary and output directory",
            listOf("unused", "--output", output.toString(), "--profile", "unknown-profile") to "unsupported reconstruction profile: unknown-profile",
            listOf("--profile") to "--profile requires a registered profile ID",
        )
        for ((index, case) in cases.withIndex()) {
            val log = temp.resolve("case-$index.log")
            val builder = ProcessBuilder(listOf(launcher.toString(), "reconstruct") + case.first)
                .redirectErrorStream(true).redirectOutput(log.toFile())
            for (key in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "LLM_BIN_PATCH_OPTS")) {
                builder.environment().remove(key)
            }
            builder.environment()["JAVA_HOME"] = System.getProperty("java.home")
            builder.environment()["JAVA_OPTS"] = "-Xmx256m"
            val process = builder.start()
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS))
                assertEquals(2, process.exitValue())
                val bytes = Files.newInputStream(log).use { it.readNBytes(65_537) }
                assertTrue(bytes.size <= 65_536)
                val text = bytes.decodeToString()
                assertTrue(case.second in text, text)
                assertTrue("--profile generated-c-make-v1|generated-c-ninja-v1" in text)
                assertFalse(Files.exists(output))
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
            }
        }
    }
}
