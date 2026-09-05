package decompengine.acp

import java.io.IOException
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.ServerSocketChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermissions
import java.nio.file.attribute.UserDefinedFileAttributeView
import java.util.Comparator
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

class PinnedSystemdBusEndpointTest {
    @Test
    fun `runtime membership changes do not replace the pinned bus endpoint`() = withEndpoint { _, runtime, endpoint ->
        val originalTime = Files.getLastModifiedTime(runtime)
        val marker = runtime.resolve("transient-manager-state")
        Files.writeString(marker, "active")
        Files.setLastModifiedTime(runtime, FileTime.fromMillis(originalTime.toMillis() + 60_000L))
        assertNotEquals(originalTime, Files.getLastModifiedTime(runtime))
        endpoint.requireUnchanged()
        Files.delete(marker)
        endpoint.requireUnchanged()
        assertEquals(runtime.toString(), endpoint.controlEnvironment.getValue("XDG_RUNTIME_DIR"))
    }

    @Test
    fun `runtime permission changes still reject the endpoint`() = withEndpoint { _, runtime, endpoint ->
        Files.setPosixFilePermissions(runtime, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFailsWith<IOException> { endpoint.requireUnchanged() }
        Files.setPosixFilePermissions(runtime, OWNER_DIRECTORY)
        endpoint.requireUnchanged()
    }

    @Test
    fun `runtime replacement rejects even when the socket inode is retained`() = withEndpoint { root, runtime, endpoint ->
        val original = root.resolve("original-runtime")
        val socketIdentity = Files.getAttribute(runtime.resolve("bus"), "unix:ino", LinkOption.NOFOLLOW_LINKS)
        Files.move(runtime, original, StandardCopyOption.ATOMIC_MOVE)
        Files.createDirectory(runtime, PosixFilePermissions.asFileAttribute(OWNER_DIRECTORY))
        Files.move(original.resolve("bus"), runtime.resolve("bus"), StandardCopyOption.ATOMIC_MOVE)
        assertEquals(socketIdentity, Files.getAttribute(runtime.resolve("bus"), "unix:ino", LinkOption.NOFOLLOW_LINKS))
        assertFailsWith<IOException> { endpoint.requireUnchanged() }
    }

    @Test
    fun `socket name replacement rejects the new live socket`() = withEndpoint { _, runtime, endpoint ->
        val replacement = runtime.resolve("replacement")
        bindSocket(replacement).use {
            assertNotEquals(
                Files.getAttribute(runtime.resolve("bus"), "unix:ino", LinkOption.NOFOLLOW_LINKS),
                Files.getAttribute(replacement, "unix:ino", LinkOption.NOFOLLOW_LINKS),
            )
            Files.move(replacement, runtime.resolve("bus"), StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            assertFailsWith<IOException> { endpoint.requireUnchanged() }
        }
    }

    @Test
    fun `socket permission and type changes remain inadmissible`() = withEndpoint { _, runtime, endpoint ->
        val bus = runtime.resolve("bus")
        Files.setPosixFilePermissions(bus, PosixFilePermissions.fromString("r--------"))
        assertFailsWith<IOException> { endpoint.requireUnchanged() }
        Files.delete(bus)
        Files.writeString(bus, "")
        assertFailsWith<IOException> { endpoint.requireUnchanged() }
        assertFailsWith<IOException> { PinnedSystemdBusEndpoint.pin(runtime) }
    }

    @Test
    fun `runtime extended metadata changes remain inadmissible`() = withEndpoint { _, runtime, endpoint ->
        AcpLiveContractHost.requireCapability(
            Files.getFileStore(runtime).supportsFileAttributeView(UserDefinedFileAttributeView::class.java),
            { "systemd endpoint tests require user-defined filesystem attributes" },
        )
        val attributes = Files.getFileAttributeView(runtime, UserDefinedFileAttributeView::class.java)
        attributes.write("decomp-endpoint-test", ByteBuffer.wrap(byteArrayOf(1)))
        assertFailsWith<IOException> { endpoint.requireUnchanged() }
        attributes.delete("decomp-endpoint-test")
        endpoint.requireUnchanged()
    }

    private fun withEndpoint(action: (Path, Path, PinnedSystemdBusEndpoint) -> Unit) {
        AcpLiveContractHost.requireCapability(System.getProperty("os.name") == "Linux", { "systemd endpoint tests require Linux" })
        val root = createTempDirectory("bus-pin-")
        try {
            val runtime = Files.createDirectory(
                root.resolve("runtime"), PosixFilePermissions.asFileAttribute(OWNER_DIRECTORY),
            )
            bindSocket(runtime.resolve("bus")).use {
                val endpoint = PinnedSystemdBusEndpoint.pin(runtime)
                endpoint.requireUnchanged()
                action(root, runtime, endpoint)
            }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun bindSocket(path: Path): ServerSocketChannel = ServerSocketChannel.open(StandardProtocolFamily.UNIX).also {
        it.bind(UnixDomainSocketAddress.of(path))
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    }

    private companion object {
        val OWNER_DIRECTORY = PosixFilePermissions.fromString("rwx------")
    }
}
