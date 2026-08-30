package decompengine.doctor

import java.net.URI
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class DoctorTest {
    @Test
    fun `reports all tools output and authenticated connectivity independently`() {
        val temp = createTempDirectory("doctor-ok-")
        val ghidra = temp.resolve("ghidra")
        ghidra.resolve("support").createDirectories()
        ghidra.resolve("support/analyzeHeadless").writeText("#!/bin/sh\n")
        ghidra.resolve("support/analyzeHeadless").toFile().setExecutable(true)
        val commands = mutableListOf<List<String>>()
        val doctor = Doctor(
            environment = mapOf(
                "GHIDRA_HOME" to ghidra.toString(),
                "ACP_HARNESS" to "legacy-openai",
                "BASE_URL" to "https://models.example.test/v1",
                "API_KEY" to "must-not-appear",
                "MODEL" to "test-model",
            ),
            commandProbe = CommandProbe { command, _ ->
                commands += command
                CommandProbeResult(0, "available")
            },
            connectivityProbe = ConnectivityProbe { baseUrl, apiKey ->
                assertTrue(baseUrl == URI.create("https://models.example.test/v1"))
                assertTrue(apiKey == "must-not-appear")
                "authenticated probe succeeded"
            },
        )

        val report = doctor.inspect(DoctorOptions(temp.resolve("output")))

        assertTrue(report.passed, report.checks.toString())
        assertTrue(report.checks.any { it.name == "GCC sanitizers" && it.passed })
        assertTrue(report.checks.any { it.name == "output directory" && it.passed })
        assertTrue(report.checks.any { it.name == "LLM connectivity" && it.passed })
        assertTrue(commands.any { "-fsanitize=address,undefined" in it })
        assertFalse(report.checks.joinToString().contains("must-not-appear"))
    }

    @Test
    fun `retains actionable failures and skips credentials in tools only mode`() {
        val temp = createTempDirectory("doctor-fail-")
        val doctor = Doctor(
            environment = emptyMap(),
            commandProbe = CommandProbe { command, _ ->
                if (command.first() == "gcc" && command.any { it.startsWith("-fsanitize") }) {
                    CommandProbeResult(1, "cannot find libasan")
                } else {
                    CommandProbeResult(127, "not found")
                }
            },
            connectivityProbe = ConnectivityProbe { _, _ -> error("must not connect") },
        )

        val report = doctor.inspect(DoctorOptions(temp.resolve("output"), toolsOnly = true))

        assertFalse(report.passed)
        assertTrue(report.checks.any { it.name == "Java" && !it.passed && it.detail.contains("Install") })
        assertTrue(report.checks.any { it.name == "GCC sanitizers" && !it.passed && it.detail.contains("libasan") })
        assertFalse(report.checks.any { it.name.startsWith("LLM") })
    }

    @Test
    fun `invalid configuration still records a connectivity result`() {
        val temp = createTempDirectory("doctor-config-")
        val ghidra = temp.resolve("ghidra/support").createDirectories().resolve("analyzeHeadless")
        ghidra.writeText("x")
        ghidra.toFile().setExecutable(true)
        val doctor = Doctor(
            environment = mapOf(
                "GHIDRA_HOME" to ghidra.parent.parent.toString(),
                "ACP_HARNESS" to "legacy-openai",
                "BASE_URL" to "not a URL",
            ),
            commandProbe = CommandProbe { command, _ ->
                if (command.first().contains("probe")) CommandProbeResult(0, "") else CommandProbeResult(0, "ok")
            },
        )

        val report = doctor.inspect(DoctorOptions(temp.resolve("output")))

        assertFalse(report.passed)
        assertTrue(report.checks.any { it.name == "LLM base URL" && !it.passed })
        assertTrue(report.checks.any { it.name == "LLM API key" && !it.passed })
        assertTrue(report.checks.any { it.name == "LLM model" && !it.passed })
        assertTrue(report.checks.any { it.name == "LLM connectivity" && !it.passed })
    }

    @Test
    fun `default harness fails closed without ACP provisioning and does not request legacy credentials`() {
        val temp = createTempDirectory("doctor-acp-default-")
        val doctor = Doctor(
            environment = emptyMap(),
            commandProbe = CommandProbe { _, _ -> CommandProbeResult(0, "ok") },
            connectivityProbe = ConnectivityProbe { _, _ -> error("ACP diagnostics must not probe a legacy API") },
        )

        val report = doctor.inspect(DoctorOptions(temp.resolve("output")))

        assertFalse(report.passed)
        assertTrue(
            report.checks.any {
                it.name == "ACP harness" &&
                    !it.passed &&
                    it.detail.contains("ACP_CONFIG_FILE is required")
            },
            report.checks.toString(),
        )
        assertFalse(report.checks.any { it.name.startsWith("LLM") })
    }

    @Test
    fun `legacy API checks require explicit deprecated harness selection`() {
        val temp = createTempDirectory("doctor-legacy-opt-in-")
        val doctor = Doctor(
            environment = mapOf("ACP_HARNESS" to "legacy-openai"),
            commandProbe = CommandProbe { _, _ -> CommandProbeResult(0, "ok") },
            connectivityProbe = ConnectivityProbe { _, _ -> error("invalid credentials must prevent connection") },
        )

        val report = doctor.inspect(DoctorOptions(temp.resolve("output")))

        assertTrue(report.checks.any { it.name == "ACP harness" && it.passed && it.detail.contains("deprecated") })
        assertTrue(report.checks.any { it.name == "LLM base URL" && !it.passed })
        assertTrue(report.checks.any { it.name == "LLM API key" && !it.passed })
        assertTrue(report.checks.any { it.name == "LLM model" && !it.passed })
    }
}
