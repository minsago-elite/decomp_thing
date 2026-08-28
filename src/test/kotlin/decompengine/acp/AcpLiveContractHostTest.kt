package decompengine.acp

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createDirectories
import kotlin.io.path.createSymbolicLinkPointingTo
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import org.opentest4j.TestAbortedException

class AcpLiveContractHostTest {
    @Test
    fun `discovers the effective system Python runtime without distro paths`() {
        val runtime = requirePythonRuntime()

        assertTrue(Files.isExecutable(runtime.executable))
        assertTrue(Files.isDirectory(runtime.stdlib))
        assertTrue(Files.isRegularFile(runtime.jsonExtension))
        assertTrue(runtime.jsonExtension.startsWith(runtime.stdlib))
        assertTrue(runtime.nativeRuntimeMounts.isNotEmpty())
        assertTrue(runtime.nativeRuntimeMounts.any { it.source == runtime.jsonExtension })
        assertEquals(
            runtime.nativeRuntimeMounts.size,
            runtime.nativeRuntimeMounts.map { it.destination }.distinct().size,
        )
    }

    @Test
    fun `required live contract capabilities fail instead of skipping`() {
        val failure = assertFailsWith<AssertionError> {
            AcpLiveContractHost.requireCapability(false, { "fixture host is unavailable" }, required = true)
        }

        assertTrue(failure.message.orEmpty().contains("DECOMP_REQUIRE_LIVE_ACP_CONTRACT=1"))
        assertFailsWith<TestAbortedException> {
            AcpLiveContractHost.requireCapability(false, { "fixture host is unavailable" }, required = false)
        }
    }

    @Test
    fun `stdlib mounts are exact and traversal is rejected`() {
        val runtime = requirePythonRuntime()

        val mounts = runtime.stdlibMounts(listOf("json", "json"))

        assertEquals(1, mounts.size)
        assertEquals(runtime.stdlib.resolve("json"), mounts.single().source)
        assertEquals(mounts.single().source, mounts.single().destination)
        assertFailsWith<IllegalArgumentException> { runtime.stdlibMounts(listOf("../outside")) }
    }

    @Test
    fun `native runtime closure preserves verified loader alias destinations`() {
        val root = createTempDirectory("acp-runtime-alias-")
        val canonicalRoot = root.resolve("usr/lib64").createDirectories()
        val runtimeFile = canonicalRoot.resolve("libfixture.so").apply { writeText("fixture") }
        val soname = canonicalRoot.resolve("libfixture.so.1")
            .createSymbolicLinkPointingTo(runtimeFile.fileName)
        val aliasRoot = root.resolve("lib64").createSymbolicLinkPointingTo(Path.of("usr/lib64"))

        val destinations = AcpLiveContractHost.runtimeAliasDestinations(
            runtimeFile,
            aliasRoots = listOf(aliasRoot),
        )

        assertEquals(
            listOf(
                aliasRoot.resolve("libfixture.so"),
                aliasRoot.resolve("libfixture.so.1"),
                runtimeFile,
                soname,
            ).sortedBy(Path::toString),
            destinations,
        )
        assertTrue(destinations.all { Files.isSameFile(runtimeFile, it) })
    }

    private fun requirePythonRuntime(): AcpPythonRuntimeLayout {
        val result = runCatching { AcpLiveContractHost.discoverPythonRuntime() }
        AcpLiveContractHost.requireCapability(
            result.isSuccess,
            message = { "system Python runtime discovery failed: ${result.exceptionOrNull()?.message}" },
        )
        return result.getOrThrow()
    }
}
