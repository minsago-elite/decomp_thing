package decompengine

import java.nio.file.Files
import java.nio.file.Path
import java.io.ByteArrayOutputStream
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class InstalledReconstructionCliTest {
    @Test
    fun `installed web launcher caps only the web command heap`() {
        val launcher = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch/bin/llm_bin_patch")

        fun run(command: List<String>, javaOpts: String? = null): Pair<Int, String> {
            val builder = ProcessBuilder(command).redirectErrorStream(true)
            for (key in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "LLM_BIN_PATCH_OPTS")) {
                builder.environment().remove(key)
            }
            builder.environment()["JAVA_HOME"] = System.getProperty("java.home")
            if (javaOpts == null) builder.environment().remove("JAVA_OPTS") else builder.environment()["JAVA_OPTS"] = javaOpts
            val process = builder.start()
            val output = ByteArrayOutputStream()
            val drain = Thread.ofPlatform().start {
                process.inputStream.use { input -> input.copyTo(output) }
            }
            try {
                if (!process.waitFor(30, TimeUnit.SECONDS)) {
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                    throw AssertionError("timed out running ${command.first()}")
                }
                assertTrue(drain.join(5_000).let { !drain.isAlive }, "child output reader did not finish")
                return process.exitValue() to output.toString(Charsets.UTF_8)
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
                if (drain.isAlive) {
                    process.inputStream.close()
                    drain.join(5_000)
                }
            }
        }

        val diagnosticOptions = "-XshowSettings:vm -XX:+PrintFlagsFinal"
        val (webExit, web) = run(listOf(launcher.toString(), "web", "--unknown-option"), diagnosticOptions)
        assertTrue(webExit != 0, web)
        assertTrue("Max. Heap Size: 256.00M" in web, web)
        assertTrue(Regex("int ActiveProcessorCount\\s*=\\s*4\\b").containsMatchIn(web), web)

        val java = Path.of(System.getProperty("java.home"), "bin", "java").toString()
        val (_, baseline) = run(listOf(java, "-Xms64m", "-XX:+PrintFlagsFinal", "-version"))
        val (reconstructionExit, reconstruction) = run(
            listOf(launcher.toString(), "reconstruct", "--profile", "unknown-profile"),
            "-XX:+PrintFlagsFinal",
        )
        assertTrue(reconstructionExit != 0, reconstruction)
        val maximumHeap = Regex("MaxHeapSize\\s*=\\s*(\\d+)")
        val baselineMaxHeap = maximumHeap.find(baseline)?.groupValues?.get(1)
        assertTrue(baselineMaxHeap != null, baseline)
        assertEquals(baselineMaxHeap, maximumHeap.find(reconstruction)?.groupValues?.get(1), reconstruction)
        assertFalse(Regex("int ActiveProcessorCount\\s*=\\s*4\\b").containsMatchIn(reconstruction), reconstruction)
    }

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
