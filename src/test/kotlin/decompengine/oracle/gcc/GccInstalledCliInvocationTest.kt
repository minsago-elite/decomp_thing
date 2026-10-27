package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.inControlTemporaryDirectory
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccInstalledCliInvocationTest {
    @Test
    fun `diagnostic selection invokes launcher and retains unverified evidence`() = withFakeInstalledLauncher { installation, evidence ->
        val command = "gcc-engine-runtime-diagnostic"
        val args = listOf("cc1", "binary path with spaces")
        assertEquals(23, invokeInstalledGccCli(args, evidence, 5, installation, command))
        assertEquals((listOf(command) + args).joinToString("\n", postfix = "\n"),
            Files.readString(evidence.resolve("launcher-stdout.bin")))
        assertEquals("fake launcher stderr\n", Files.readString(evidence.resolve("launcher-stderr.bin")))
        val request = OracleJson.parseCanonical(Files.readAllBytes(evidence.resolve("launcher-invocation.json"))).jsonObject
        val result = OracleJson.parseCanonical(Files.readAllBytes(evidence.resolve("launcher-result.json"))).jsonObject
        assertEquals(JsonArray((listOf(installation.resolve("bin/llm_bin_patch").toString(), command) + args)
            .map(::JsonPrimitive)), request["argv"])
        assertEquals(JsonPrimitive(5), request["outerTimeoutSeconds"])
        assertEquals(JsonPrimitive(false), request["productionVerified"])
        assertEquals(JsonPrimitive(false), result["productionVerified"])
        val checked = verifyInstalledCliEvidence(evidence, args, installation, 23, command)
        assertEquals(JsonPrimitive(false), checked["productionVerified"])
    }

    @Test
    fun `unknown installed launcher command is rejected before invocation`() = withFakeInstalledLauncher { installation, evidence ->
        assertFailsWith<IllegalArgumentException> {
            invokeInstalledGccCli(listOf("cc1", "unused"), evidence, 5, installation, "gcc-engine-unknown")
        }
        Files.list(evidence).use { assertEquals(0L, it.count()) }
    }

    @Test
    fun `retained diagnostic evidence rejects other command selections`() = withFakeInstalledLauncher { installation, evidence ->
        val args = listOf("cc1", "unused")
        val command = "gcc-engine-runtime-diagnostic"
        assertEquals(23, invokeInstalledGccCli(args, evidence, 5, installation, command))
        val checked = verifyInstalledCliEvidence(evidence, args, installation, 23, command)
        for (substitutedCommand in listOf("gcc-engine-plan", "gcc-engine-full-export", "gcc-engine-unknown")) {
            assertFailsWith<IllegalArgumentException> {
                verifyInstalledCliEvidence(evidence, args, installation, 23, substitutedCommand)
            }
        }
        assertEquals(checked, verifyInstalledCliEvidence(evidence, args, installation, 23, command))
    }

    private fun withFakeInstalledLauncher(block: (Path, Path) -> Unit) = inControlTemporaryDirectory { root ->
        val installation = Files.createDirectory(root.resolve("installation")).toRealPath()
        val launcher = Files.createDirectories(installation.resolve("bin")).resolve("llm_bin_patch")
        Files.writeString(launcher, "#!/bin/sh\nprintf '%s\\n' \"\$@\"\nprintf 'fake launcher stderr\\n' >&2\nexit 23\n")
        Files.setPosixFilePermissions(launcher, PosixFilePermissions.fromString("rwx------"))
        block(installation, Files.createDirectory(root.resolve("evidence")))
    }

    @Test
    fun `installed launcher reports invalid engine selection without starting analysis`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val evidence = Files.createTempDirectory(scratch, "installed-gcc-cli-")
        assertEquals(2, invokeInstalledGccCli(listOf("invalid-engine", "unused"), evidence, 30))
        val stderrText = Files.readString(evidence.resolve("launcher-stderr.bin"))
        assertTrue(stderrText.contains("expected cc1, lto1 or driver and its stripped binary"),
            "launcher stderr: $stderrText")
        val result = OracleJson.parseCanonical(Files.readAllBytes(evidence.resolve("launcher-result.json"))).jsonObject
        assertEquals("false", result.getValue("productionVerified").jsonPrimitive.content)
        assertEquals("2", result.getValue("exitCode").jsonPrimitive.content)
        val installation = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch")
        val args = listOf("invalid-engine", "unused")
        val checked = verifyInstalledCliEvidence(evidence, args, installation, 2)
        assertEquals("false", checked.getValue("productionVerified").jsonPrimitive.content)
        assertFails { verifyInstalledCliEvidence(evidence, listOf("cc1", "unused"), installation, 2) }
        val stderr = evidence.resolve("launcher-stderr.bin")
        val prior = Files.readAllBytes(stderr)
        Files.write(stderr, prior + byteArrayOf(10))
        assertFails { verifyInstalledCliEvidence(evidence, args, installation, 2) }
        Files.write(stderr, prior)
        assertEquals(checked, verifyInstalledCliEvidence(evidence, args, installation, 2))
    }
}
