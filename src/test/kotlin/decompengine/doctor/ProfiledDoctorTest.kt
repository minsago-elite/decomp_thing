package decompengine.doctor

import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.project.ReconstructionBudgets
import decompengine.project.ReconstructionHostSafetyLimits
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.io.path.isDirectory
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class ProfiledDoctorTest {
    @Test
    fun `selected profiles forward tool commands and retain authored sanitizer probe lifecycle`() = inControlTemporaryDirectory { root ->
        for (base in ReconstructionProfiles.builtIn) {
            val custom = profile(base, configuration = base.adapterConfiguration + mapOf(
                "compiler-driver" to listOf("fixture-cc"),
                "build-executable" to listOf("fixture-build-tool"),
                "compiler-flags" to listOf("-DPROFILE_BUILD_ONLY"),
            ))
            for ((index, selected) in listOf(base, custom).withIndex()) {
                val compiler = selected.adapterConfiguration.getValue("compiler-driver").single()
                val builder = selected.adapterConfiguration.getValue("build-executable").single()
                val buildName = when (selected.adapterConfiguration.getValue("build-system").single()) {
                    "gnu-make" -> "Make"
                    "ninja" -> "Ninja"
                    else -> error("fixture profile has an unexpected build system")
                }
                val output = root.resolve("${base.id}-$index")
                val commands = mutableListOf<List<String>>()
                val capabilitySteps = mutableListOf<String>()
                var probeDirectory: Path? = null
                val doctor = Doctor(
                    environment = toolsOnlyEnvironment,
                    commandProbe = CommandProbe { command, workingDirectory ->
                        commands += command.toList()
                        if ("-fsanitize=address,undefined" in command) {
                            val directory = assertNotNull(workingDirectory)
                            probeDirectory = directory
                            val source = directory.resolve("probe.c")
                            assertTrue(source.isRegularFile())
                            assertEquals("int main(void) { return 0; }\n", source.readText())
                            assertEquals(listOf(
                                compiler, "-std=c11", "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                                source.toString(), "-o", directory.resolve("probe").toString(),
                            ), command)
                            assertFalse("-DPROFILE_BUILD_ONLY" in command)
                            capabilitySteps += "compile"
                        } else if (workingDirectory != null) {
                            assertEquals(probeDirectory, workingDirectory)
                            assertEquals(listOf(workingDirectory.resolve("probe").toString()), command)
                            assertEquals(listOf("compile"), capabilitySteps)
                            capabilitySteps += "run"
                        }
                        CommandProbeResult(0, "fixture available")
                    },
                    connectivityProbe = ConnectivityProbe { _, _ -> error("tools-only must not connect") },
                )

                val report = doctor.inspect(DoctorOptions(output, toolsOnly = true), selected)

                assertEquals(listOf("java", "-version"), commands[0])
                assertEquals(listOf(compiler, "--version"), commands[1])
                assertEquals(listOf(builder, "--version"), commands[2])
                assertTrue(listOf("fixture-python", "-c", "import angr") in commands)
                assertEquals(listOf("compile", "run"), capabilitySteps)
                assertFalse(assertNotNull(probeDirectory).exists())
                assertTrue(output.isDirectory())
                assertEquals(listOf(
                    "Java", "C compiler", buildName, "binutils/readelf", "binutils/strings", "Python", "angr",
                    "Ghidra", "C sanitizers", "bubblewrap", "output directory", "reconstruction profile",
                ), report.checks.map { it.name })
                for (name in listOf("C compiler", buildName, "C sanitizers", "output directory")) {
                    assertTrue(report.checks.single { it.name == name }.passed, name)
                }
                val identity = report.checks.last()
                assertTrue(identity.passed)
                assertEquals("Selected ${selected.id}; sha256=${selected.sha256}", identity.detail)
            }
        }
    }

    @Test
    fun `profile host and adapter admission precede all probes and output creation`() = inControlTemporaryDirectory { root ->
        val base = ReconstructionProfiles.default
        val configuration = base.adapterConfiguration
        val cases = listOf(
            AdmissionCase("unknown-profile", profile(base, id = "unregistered-fixture"), "no reconstruction adapter registered"),
            AdmissionCase("above-default-host", profile(base, budgets = base.budgets.copy(
                buildWallClockMillis = ReconstructionHostSafetyLimits.DEFAULT.maximum.buildWallClockMillis + 1,
            )), "host safety limit"),
            AdmissionCase("explicit-host-ceiling", base, "host safety limit", ReconstructionHostSafetyLimits(
                base.budgets.copy(buildWallClockMillis = base.budgets.buildWallClockMillis - 1),
            )),
            AdmissionCase("missing-compiler", profile(base, configuration = configuration - "compiler-driver"), "compiler-driver"),
            AdmissionCase("multiple-compilers", profile(base, configuration = configuration +
                ("compiler-driver" to listOf("fixture-cc", "second-fixture-cc"))), "compiler-driver"),
            AdmissionCase("missing-builder", profile(base, configuration = configuration - "build-executable"), "build-executable"),
            AdmissionCase("multiple-builders", profile(base, configuration = configuration +
                ("build-executable" to listOf("fixture-builder", "second-fixture-builder"))), "build-executable"),
            AdmissionCase("mismatched-build-system", profile(base, configuration = configuration +
                ("build-system" to listOf("unsupported-fixture-system"))), "build-system"),
        )
        for (case in cases) {
            val output = root.resolve(case.name)
            var probeCalls = 0
            val doctor = Doctor(
                environment = emptyMap(),
                commandProbe = CommandProbe { _, _ ->
                    probeCalls++
                    error("admission must precede probes")
                },
                connectivityProbe = ConnectivityProbe { _, _ -> error("admission must precede connectivity") },
            )

            val failure = assertFailsWith<IllegalArgumentException>(case.name) {
                doctor.inspect(DoctorOptions(output, toolsOnly = true), case.profile, case.hostSafetyLimits)
            }

            assertTrue(failure.message.orEmpty().contains(case.message), case.name)
            assertEquals(0, probeCalls, case.name)
            assertFalse(output.exists(), case.name)
        }
    }

    @Test
    fun `sanitizer compile failure keeps the first useful diagnostic and cleans its directory`() = inControlTemporaryDirectory { root ->
        val output = root.resolve("output")
        var probeDirectory: Path? = null
        var runCalls = 0
        val doctor = Doctor(
            environment = toolsOnlyEnvironment,
            commandProbe = CommandProbe { command, workingDirectory ->
                when {
                    "-fsanitize=address,undefined" in command -> {
                        probeDirectory = assertNotNull(workingDirectory)
                        assertTrue(workingDirectory.resolve("probe.c").isRegularFile())
                        CommandProbeResult(1, "\n   sanitizer runtime library unavailable   \nsecondary diagnostic\n")
                    }
                    workingDirectory != null -> {
                        runCalls++
                        CommandProbeResult(0, "unexpected execution")
                    }
                    else -> CommandProbeResult(0, "fixture available")
                }
            },
            connectivityProbe = ConnectivityProbe { _, _ -> error("tools-only must not connect") },
        )

        val report = doctor.inspect(DoctorOptions(output, toolsOnly = true), ReconstructionProfiles.builtIn.last())

        val sanitizer = report.checks.single { it.name == "C sanitizers" }
        assertFalse(sanitizer.passed)
        assertTrue(sanitizer.detail.endsWith("sanitizer runtime library unavailable"))
        assertFalse(sanitizer.detail.contains("secondary diagnostic"))
        assertEquals(0, runCalls)
        assertFalse(assertNotNull(probeDirectory).exists())
        assertTrue(output.isDirectory())
    }

    @Test
    fun `sanitizer cancellation retains its identity and cleans before output creation`() = inControlTemporaryDirectory { root ->
        val output = root.resolve("output")
        val cancellation = InterruptedException("caller cancelled sanitizer compilation")
        var probeDirectory: Path? = null
        var runCalls = 0
        val doctor = Doctor(
            environment = toolsOnlyEnvironment,
            commandProbe = CommandProbe { command, workingDirectory ->
                if ("-fsanitize=address,undefined" in command) {
                    probeDirectory = assertNotNull(workingDirectory)
                    assertTrue(workingDirectory.resolve("probe.c").isRegularFile())
                    throw cancellation
                }
                if (workingDirectory != null) runCalls++
                CommandProbeResult(0, "fixture available")
            },
            connectivityProbe = ConnectivityProbe { _, _ -> error("tools-only must not connect") },
        )

        val failure = assertFailsWith<InterruptedException> {
            doctor.inspect(DoctorOptions(output, toolsOnly = true), ReconstructionProfiles.default)
        }

        assertSame(cancellation, failure)
        assertEquals(0, runCalls)
        assertFalse(assertNotNull(probeDirectory).exists())
        assertFalse(output.exists())
    }

    private val toolsOnlyEnvironment = object : AbstractMap<String, String>() {
        override val entries: Set<Map.Entry<String, String>>
            get() = error("tools-only must not enumerate agent configuration")

        override fun get(key: String): String? = when (key) {
            "ANGR_PYTHON" -> "fixture-python"
            else -> error("tools-only must not resolve agent configuration: $key")
        }
    }

    private data class AdmissionCase(
        val name: String,
        val profile: ReconstructionProfile,
        val message: String,
        val hostSafetyLimits: ReconstructionHostSafetyLimits = ReconstructionHostSafetyLimits.DEFAULT,
    )

    private fun profile(
        base: ReconstructionProfile,
        id: String = base.id,
        budgets: ReconstructionBudgets = base.budgets,
        configuration: Map<String, List<String>> = base.adapterConfiguration,
    ) = ReconstructionProfile(base.schemaVersion, id, base.layout, budgets, configuration)
}
