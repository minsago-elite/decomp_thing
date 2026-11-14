package decompengine.web

import java.net.ServerSocket
import java.net.Socket
import java.net.SocketException
import java.net.SocketTimeoutException
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

/** Read to server EOF/reset without releasing the client; a read timeout must fail qualification. */
internal fun requireResourcePeerClosedByServer(socket: Socket) {
    assertFalse(socket.isClosed, "the client must remain open while server cleanup is qualified")
    try {
        socket.getInputStream().readBytes()
    } catch (failure: SocketException) {
        // SocketTimeoutException is not a SocketException. Other I/O errors are not closure proof.
        if (!failure.message.orEmpty().contains("reset", ignoreCase = true)) throw failure
    }
    assertFalse(socket.isClosed, "reading server EOF/reset must not close the client")
}

class WebResourcePeerClosureTest {
    private fun withPeers(test: (Socket, Socket) -> Unit) {
        ServerSocket(0, 1, java.net.InetAddress.getLoopbackAddress()).use { listener ->
            Socket(listener.inetAddress, listener.localPort).use { client ->
                listener.accept().use { server ->
                    client.soTimeout = 100
                    test(client, server)
                }
            }
        }
    }

    @Test fun `a silent server fails with a read timeout while the client remains open`() = withPeers { client, _ ->
        assertFailsWith<SocketTimeoutException> { requireResourcePeerClosedByServer(client) }
        assertFalse(client.isClosed)
    }

    @Test fun `server EOF is accepted without closing the client`() = withPeers { client, server ->
        server.shutdownOutput()
        requireResourcePeerClosedByServer(client)
        assertFalse(client.isClosed)
    }

    @Test fun `server reset is accepted without closing the client`() = withPeers { client, server ->
        server.setSoLinger(true, 0)
        server.close()
        requireResourcePeerClosedByServer(client)
        assertFalse(client.isClosed)
    }
}
