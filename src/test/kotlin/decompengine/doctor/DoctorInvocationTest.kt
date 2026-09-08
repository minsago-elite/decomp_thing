package decompengine.doctor

import decompengine.acp.AcpPreflightWorkflow
import decompengine.project.ReconstructionProfiles
import java.nio.file.Path
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
