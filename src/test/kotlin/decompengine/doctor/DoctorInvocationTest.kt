package decompengine.doctor

import decompengine.acp.AcpPreflightWorkflow
import decompengine.renderDoctorUsageError
import decompengine.runDoctorCliAction
import decompengine.project.ReconstructionProfiles
import java.nio.file.Path
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class DoctorInvocationTest {
    private val defaultOutput = Path.of("caller-selected-output")

    @Test
    fun `doctor terminal reports redact formatted fields after cleanup with correct exit status`() {
        val output = ByteArrayOutputStream()
        val diagnostic = ByteArrayOutputStream()
        val values = listOf("private-credential", "[ok] project: visible")
        var closed = false
        fun afterCleanup(bytes: ByteArrayOutputStream) = object : PrintStream(bytes) {
            override fun println(value: String?) {
                assertTrue(closed, "diagnostics must follow action cleanup")
                super.println(value)
            }
        }
        val status = runDoctorCliAction(values, afterCleanup(output), afterCleanup(diagnostic)) {
            try {
                DoctorReport(listOf(DoctorCheck("project", true, "visible"),
                    DoctorCheck("private-credential", false, "Authorization: Basic synthetic-wire-value")))
            } finally {
                closed = true
            }
        }
        assertTrue(closed)
        assertEquals(1, status)
        val text = output.toString() + diagnostic.toString()
        assertFalse(text.contains("private-credential") || text.contains("synthetic-wire-value"))
        assertFalse(text.contains("[ok] project: visible"))
        output.reset(); diagnostic.reset()
        assertEquals(0, runDoctorCliAction(emptyList(), PrintStream(output), PrintStream(diagnostic)) {
            DoctorReport(listOf(DoctorCheck("public", true, "available")))
        })
        assertTrue(output.toString().contains("Environment check passed (1 checks)"))
        assertEquals("", diagnostic.toString())
        output.reset(); diagnostic.reset()
        val cause = IllegalStateException("private cause chain")
        assertEquals(1, runDoctorCliAction(values, PrintStream(output), PrintStream(diagnostic)) {
            throw IllegalStateException("private-credential", cause)
        })
        assertEquals("", output.toString())
        assertFalse(diagnostic.toString().contains("private-credential") || diagnostic.toString().contains("private cause chain"))
        output.reset(); diagnostic.reset()
        assertEquals(2, renderDoctorUsageError("unknown option private-credential", false, values, PrintStream(diagnostic)))
        assertTrue(diagnostic.toString().contains("usage: llm_bin_patch doctor"))
        assertFalse(diagnostic.toString().contains("private-credential"))
        val cancelled = java.util.concurrent.CancellationException("private cancellation")
        assertSame(cancelled, assertFailsWith<java.util.concurrent.CancellationException> {
            runDoctorCliAction(emptyList(), PrintStream(output), PrintStream(diagnostic)) { throw cancelled }
        })
        val fatal = AssertionError("private fatal error")
        assertSame(fatal, assertFailsWith<AssertionError> {
            runDoctorCliAction(emptyList(), PrintStream(output), PrintStream(diagnostic)) { throw fatal }
        })
    }

    @Test
    fun `doctor terminal admission withholds rejected inventories and tools only usage never enumerates them`() {
        val output = ByteArrayOutputStream()
        val diagnostic = ByteArrayOutputStream()
        var actions = 0
        val oversized = object : AbstractCollection<String>() {
            override val size: Int = 4097
            override fun iterator(): Iterator<String> = error("oversized inventory must not be iterated")
        }
        for (values in listOf(oversized, listOf("x".repeat(1024 * 1024 + 1)))) {
            assertEquals(2, runDoctorCliAction(values, PrintStream(output), PrintStream(diagnostic)) {
                actions++
                DoctorReport(emptyList())
            })
        }
        assertEquals(0, actions)
        assertEquals("", output.toString() + diagnostic.toString())
        assertEquals(2, runDoctorCliAction(emptyList(), PrintStream(output), PrintStream(diagnostic)) {
            throw DoctorDiagnosticAdmissionException()
        })
        assertEquals("", output.toString() + diagnostic.toString())
        val opaque = object : AbstractCollection<String>() {
            override val size: Int get() = error("tools-only must not enumerate ambient values")
            override fun iterator(): Iterator<String> = error("tools-only must not iterate ambient values")
        }
        assertEquals(2, renderDoctorUsageError("private unknown argument", true, opaque, PrintStream(diagnostic)))
        assertFalse(diagnostic.toString().contains("private unknown argument"))
        assertTrue(diagnostic.toString().contains("usage: llm_bin_patch doctor"))
        diagnostic.reset()
        val wasInterrupted = Thread.interrupted()
        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> {
                runDoctorCliAction(emptyList(), PrintStream(output), PrintStream(diagnostic)) {
                    actions++
                    DoctorReport(emptyList())
                }
            }
            assertTrue(Thread.currentThread().isInterrupted)
            assertEquals(0, actions)
            assertEquals("", output.toString() + diagnostic.toString())
        } finally {
            Thread.interrupted()
            if (wasInterrupted) Thread.currentThread().interrupt()
        }
    }

    @Test
    fun `empty arguments preserve caller output and default selections`() {
        val invocation = parseDoctorInvocation(emptyList(), defaultOutput)

        assertEquals(DoctorOptions(defaultOutput), invocation.options)
        assertSame(ReconstructionProfiles.default, invocation.profile)
    }

    @Test
    fun `tools only accepts each built in reconstruction profile`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val invocation = parseDoctorInvocation(listOf("--tools-only", "--profile", profile.id), defaultOutput)

            assertSame(profile, invocation.profile)
            assertTrue(invocation.options.toolsOnly)
            assertEquals(defaultOutput, invocation.options.outputDir)
            assertNull(invocation.options.harnessOverride)
            assertNull(invocation.options.workflowOverride)
        }
    }

    @Test
    fun `workflow harness output and reconstruction profile are independent selections`() {
        val selectedProfile = ReconstructionProfiles.builtIn.last()
        val selectedOutput = Path.of("reports with spaces", "doctor")
        for (workflow in AcpPreflightWorkflow.entries) {
            for (harness in listOf("acp", "legacy-openai")) {
                val invocation = parseDoctorInvocation(
                    listOf(
                        "--workflow", workflow.cliName,
                        "--output", selectedOutput.toString(),
                        "--profile", selectedProfile.id,
                        "--harness", harness,
                    ),
                    defaultOutput,
                )

                assertSame(selectedProfile, invocation.profile)
                assertEquals(selectedOutput, invocation.options.outputDir)
                assertEquals(harness, invocation.options.harnessOverride)
                assertEquals(workflow, invocation.options.workflowOverride)
                assertFalse(invocation.options.toolsOnly)
            }
        }
    }

    @Test
    fun `profile and workflow selections require exact supported values`() {
        val profileId = ReconstructionProfiles.builtIn.first().id
        for (selected in listOf("missing-profile", profileId.uppercase(), " $profileId", "$profileId ", "")) {
            val failure = assertFailsWith<IllegalArgumentException> {
                parseDoctorInvocation(listOf("--profile", selected), defaultOutput)
            }
            assertEquals("unsupported reconstruction profile: $selected", failure.message)
        }
        for (selected in listOf("ALL", " patch", "repair ", "reconstruction", "")) {
            val failure = assertFailsWith<IllegalArgumentException> {
                parseDoctorInvocation(listOf("--workflow", selected), defaultOutput)
            }
            assertEquals(
                "unknown doctor workflow (expected exactly all, patch, reconstruct, repair, or web)",
                failure.message,
            )
        }
    }

    @Test
    fun `missing values report the relevant option`() {
        val messages = mapOf(
            "--harness" to "--harness requires acp or legacy-openai",
            "--workflow" to "--workflow requires all, patch, reconstruct, repair, or web",
            "--output" to "--output requires a directory",
            "--profile" to "--profile requires a profile id",
        )
        for ((option, message) in messages) {
            val failure = assertFailsWith<IllegalArgumentException> {
                parseDoctorInvocation(listOf(option), defaultOutput)
            }
            assertEquals(message, failure.message)
        }
    }

    @Test
    fun `tools only rejects agent selectors in either argument order`() {
        for ((option, selected) in listOf("--harness" to "acp", "--workflow" to "repair")) {
            for (args in listOf(listOf("--tools-only", option, selected), listOf(option, selected, "--tools-only"))) {
                val failure = assertFailsWith<IllegalArgumentException> {
                    parseDoctorInvocation(args, defaultOutput)
                }
                assertEquals("--tools-only cannot be combined with $option", failure.message)
            }
        }
        for (args in listOf(listOf("--tools-only", "--auth-methods"), listOf("--auth-methods", "--tools-only"))) {
            val failure = assertFailsWith<IllegalArgumentException> {
                parseDoctorInvocation(args, defaultOutput)
            }
            assertEquals("--tools-only cannot be combined with --auth-methods", failure.message)
        }
    }

    @Test
    fun `auth methods flag is independent of profile and workflow selections`() {
        val selectedProfile = ReconstructionProfiles.builtIn.last()
        val invocation = parseDoctorInvocation(
            listOf("--auth-methods", "--profile", selectedProfile.id, "--workflow", "web"),
            defaultOutput,
        )
        assertTrue(invocation.options.showAuthMethods)
        assertSame(selectedProfile, invocation.profile)
        assertEquals(AcpPreflightWorkflow.WEB, invocation.options.workflowOverride)
    }

    @Test
    fun `unknown arguments fail while harness interpretation remains with doctor`() {
        for (argument in listOf("--unknown", "unexpected")) {
            val failure = assertFailsWith<IllegalArgumentException> {
                parseDoctorInvocation(listOf(argument), defaultOutput)
            }
            assertEquals("unexpected argument: $argument", failure.message)
        }
        val invocation = parseDoctorInvocation(listOf("--harness", "ACP"), defaultOutput)
        assertEquals("ACP", invocation.options.harnessOverride)
    }

    @Test
    fun `repeated valued options retain the last selection`() {
        val invocation = parseDoctorInvocation(
            listOf(
                "--output", "first-output", "--output", "last-output",
                "--harness", "acp", "--harness", "legacy-openai",
                "--workflow", "patch", "--workflow", "web",
                "--profile", ReconstructionProfiles.builtIn.first().id,
                "--profile", ReconstructionProfiles.builtIn.last().id,
            ),
            defaultOutput,
        )

        assertEquals(Path.of("last-output"), invocation.options.outputDir)
        assertEquals("legacy-openai", invocation.options.harnessOverride)
        assertEquals(AcpPreflightWorkflow.WEB, invocation.options.workflowOverride)
        assertSame(ReconstructionProfiles.builtIn.last(), invocation.profile)
    }
}
