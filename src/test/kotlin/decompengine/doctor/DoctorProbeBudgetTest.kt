package decompengine.doctor

import decompengine.analysis.BundledGhidra
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import decompengine.project.ReconstructionBudgets
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import decompengine.project.sha256
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNotSame
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DoctorProbeBudgetTest {
    @Test
    fun `budget capable callbacks receive selected phase limits and retain profile evidence`() = inControlTemporaryDirectory { root ->
        withAuthoredBundle(root) {
            for (base in ReconstructionProfiles.builtIn) {
                val custom = profile(base, base.budgets.copy(
                    buildWallClockMillis = 12_345,
                    buildMaximumOutputBytes = 2_048,
                    exportWallClockMillis = 23_456,
                ))
                for ((index, selected) in listOf(base, custom).withIndex()) {
                    val identityBefore = selected.sha256
                    val canonicalBefore = selected.canonicalJson()
                    val calls = mutableListOf<ProbeCall>()
                    val probe = object : BudgetedCommandProbe {
                        override fun run(command: List<String>, workingDirectory: Path?): CommandProbeResult =
                            error("Doctor must pass a budget to a budget-capable probe")

                        override fun run(command: List<String>, workingDirectory: Path?, budget: CommandProbeBudget): CommandProbeResult {
                            calls += ProbeCall(command.toList(), workingDirectory, budget, budget.remainingOutputBytes())
                            budget.consumeOutputBytes(2)
                            return CommandProbeResult(0, "ok")
                        }
                    }
                    val doctor = doctor(probe)

                    val report = doctor.inspect(DoctorOptions(root.resolve("${base.id}-$index"), toolsOnly = true), selected)

                    val host = CommandProbeLimits()
                    val expectedToolchain = host.copy(
                        maximumWallClockMillis = minOf(host.maximumWallClockMillis, selected.budgets.buildWallClockMillis),
                        maximumOutputBytes = minOf(host.maximumOutputBytes.toLong(), selected.budgets.buildMaximumOutputBytes).toInt(),
                    )
                    val expectedExport = host.copy(
                        maximumWallClockMillis = minOf(host.maximumWallClockMillis, selected.budgets.exportWallClockMillis),
                    )
                    val compiler = selected.adapterConfiguration.getValue("compiler-driver").single()
                    val builder = selected.adapterConfiguration.getValue("build-executable").single()
                    val toolchain = calls.filter { it.command.first() in setOf(compiler, builder) || it.directory != null }
                    assertEquals(4, toolchain.size)
                    for ((callIndex, call) in toolchain.withIndex()) {
                        assertEquals(expectedToolchain, call.budget.limits)
                        assertSame(toolchain.first().budget, call.budget)
                        assertEquals(expectedToolchain.maximumOutputBytes - 2 * callIndex, call.outputBefore)
                    }
                    val ghidra = calls.single { isGhidraProbe(it.command) }
                    assertEquals(expectedExport, ghidra.budget.limits)
                    assertEquals(host.maximumOutputBytes, ghidra.outputBefore)
                    assertNotSame(toolchain.first().budget, ghidra.budget)
                    val java = calls.single { it.command == listOf("java", "-version") }
                    assertEquals(host, java.budget.limits)
                    val buildName = if (selected.adapterConfiguration.getValue("build-system").single() == "ninja") "Ninja" else "Make"
                    assertEquals(listOf(
                        "Java", "C compiler", buildName, "binutils/readelf", "binutils/strings", "Python", "angr",
                        "Ghidra", "C sanitizers", "bubblewrap", "output directory", "reconstruction profile", "diagnostic limits",
                    ), report.checks.map { it.name })
                    assertEquals("Selected ${selected.id}; sha256=$identityBefore",
                        report.checks.single { it.name == "reconstruction profile" }.detail)
                    assertEquals(identityBefore, selected.sha256)
                    assertEquals(canonicalBefore, selected.canonicalJson())
                    val limits = report.checks.last().detail
                    assertTrue(limits.contains("toolchain group: ${expectedToolchain.maximumWallClockMillis} ms and ${expectedToolchain.maximumOutputBytes} combined output bytes"))
                    assertTrue(limits.contains("bundled Ghidra preparation/probe: ${expectedExport.maximumWallClockMillis} ms"))
                    assertTrue(limits.contains("Owned command execution enforces these limits."))
                }
            }
        }
    }

    @Test
    fun `injected version and sanitizer callbacks consume one toolchain output allowance`() = inControlTemporaryDirectory { root ->
        withAuthoredBundle(root) {
            val base = ReconstructionProfiles.default
            val selected = profile(base, base.budgets.copy(buildMaximumOutputBytes = 5))
            val compiler = selected.adapterConfiguration.getValue("compiler-driver").single()
            val builder = selected.adapterConfiguration.getValue("build-executable").single()
            var compileCalls = 0
            var runtimeCalls = 0
            var probeDirectory: Path? = null
            val doctor = doctor(CommandProbe { command, directory ->
                val output = when {
                    "-fsanitize=address,undefined" in command -> {
                        compileCalls++
                        probeDirectory = assertNotNull(directory)
                        assertEquals("int main(void) { return 0; }\n", directory.resolve("probe.c").readText())
                        "ok"
                    }
                    directory != null -> {
                        runtimeCalls++
                        ""
                    }
                    command == listOf(compiler, "--version") -> "é"
                    command == listOf(builder, "--version") -> "mk"
                    else -> ""
                }
                CommandProbeResult(0, output)
            })

            val report = doctor.inspect(DoctorOptions(root.resolve("output"), toolsOnly = true), selected)

            assertTrue(report.checks.single { it.name == "C compiler" }.passed)
            val sanitizer = report.checks.single { it.name == "C sanitizers" }
            assertFalse(sanitizer.passed)
            assertTrue(sanitizer.detail.contains("output", ignoreCase = true), sanitizer.detail)
            assertEquals(1, compileCalls)
            assertEquals(0, runtimeCalls)
            assertFalse(assertNotNull(probeDirectory).exists())
            assertTrue(report.checks.last().detail.contains("Injected command callbacks receive cooperative before/after checks only."))
        }
    }

    @Test
    fun `first command cancellation preserves identity and prevents later calls or output`() = inControlTemporaryDirectory { root ->
        val output = root.resolve("output")
        val cancellation = InterruptedException("caller cancelled Java probe")
        val calls = mutableListOf<List<String>>()
        val doctor = doctor(CommandProbe { command, _ ->
            calls += command.toList()
            throw cancellation
        })

        val failure = assertFailsWith<InterruptedException> {
            doctor.inspect(DoctorOptions(output, toolsOnly = true), ReconstructionProfiles.default)
        }

        assertSame(cancellation, failure)
        assertEquals(listOf(listOf("java", "-version")), calls)
        assertFalse(output.exists())
    }

    @Test
    fun `bundled Ghidra callback cancellation preserves identity before capability and output work`() = inControlTemporaryDirectory { root ->
        withAuthoredBundle(root) {
            val output = root.resolve("output")
            val cancellation = InterruptedException("caller cancelled bundled probe")
            val calls = mutableListOf<List<String>>()
            var capabilityCalls = 0
            val doctor = doctor(CommandProbe { command, directory ->
                calls += command.toList()
                if (isGhidraProbe(command)) throw cancellation
                if (directory != null) capabilityCalls++
                CommandProbeResult(0, "")
            })

            val failure = assertFailsWith<InterruptedException> {
                doctor.inspect(DoctorOptions(output, toolsOnly = true), ReconstructionProfiles.default)
            }

            assertSame(cancellation, failure)
            assertTrue(isGhidraProbe(calls.last()))
            assertEquals(0, capabilityCalls)
            assertFalse(output.exists())
        }
    }

    @Test
    fun `elapsed injected callback prevents later toolchain and capability callbacks`() = inControlTemporaryDirectory { root ->
        withAuthoredBundle(root) {
            val base = ReconstructionProfiles.default
            val selected = profile(base, base.budgets.copy(buildWallClockMillis = 250))
            val compiler = selected.adapterConfiguration.getValue("compiler-driver").single()
            val builder = selected.adapterConfiguration.getValue("build-executable").single()
            var compilerReturned = false
            var builderCalls = 0
            var capabilityCalls = 0
            val doctor = doctor(CommandProbe { command, directory ->
                if (command == listOf(compiler, "--version")) {
                    Thread.sleep(300)
                    compilerReturned = true
                }
                if (command == listOf(builder, "--version")) builderCalls++
                if (directory != null) capabilityCalls++
                CommandProbeResult(0, "")
            })

            val report = doctor.inspect(DoctorOptions(root.resolve("output"), toolsOnly = true), selected)

            assertTrue(compilerReturned, "injected callback is checked after returning")
            assertEquals(0, builderCalls)
            assertEquals(0, capabilityCalls)
            assertFalse(report.checks.single { it.name == "C compiler" }.passed)
            assertFalse(report.checks.single { it.name == "C sanitizers" }.passed)
        }
    }

    private fun doctor(probe: CommandProbe) = Doctor(
        environment = emptyMap(),
        commandProbe = probe,
        connectivityProbe = ConnectivityProbe { _, _ -> error("tools-only must not connect") },
    )

    private data class ProbeCall(
        val command: List<String>,
        val directory: Path?,
        val budget: CommandProbeBudget,
        val outputBefore: Int,
    )

    private fun profile(base: ReconstructionProfile, budgets: ReconstructionBudgets) =
        ReconstructionProfile(base.schemaVersion, base.id, base.layout, budgets, base.adapterConfiguration)

    private fun isGhidraProbe(command: List<String>) = BundledGhidra.WORKER_CLASS in command && command.last() == "probe"

    private fun withAuthoredBundle(root: Path, block: () -> Unit) {
        val bundle = root.resolve("bundle").createDirectories()
        val release = "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra"
        val files = linkedMapOf(
            "decomp-ghidra-bridge.jar" to "authored bridge text, never executed\n",
            "$release/Features/Base/lib/Base.jar" to "authored library text, never executed\n",
            "$release/application.properties" to
                "application.version=${BundledGhidra.VERSION}\napplication.release.name=PUBLIC\n",
        )
        for ((relative, content) in files) {
            bundle.resolve(relative).also { path ->
                path.parent.createDirectories()
                path.writeText(content)
            }
        }
        bundle.resolve("bundle.sha256").writeText(files.entries.joinToString("") { (relative, content) ->
            "${sha256(content.toByteArray(Charsets.UTF_8))}  $relative\n"
        })
        val property = "decompengine.ghidra.bundle"
        val previous = System.getProperty(property)
        try {
            System.setProperty(property, bundle.toString())
            block()
        } finally {
            if (previous == null) System.clearProperty(property) else System.setProperty(property, previous)
        }
    }
}
