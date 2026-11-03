package decompengine.web

import java.io.BufferedReader
import java.io.IOException
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** Validate the raw HTTP/SSE preamble without leaking a socket on any failed handshake. */
internal fun awaitWebTestStreamAnnouncement(socket: Socket, reader: BufferedReader, timeoutMs: Long = 5000) {
    val deadline = Executors.newSingleThreadScheduledExecutor()
    // Closing the socket bounds even a readLine stalled on a partial line or a trickling peer.
    val timeout = deadline.schedule({ socket.close() }, timeoutMs, TimeUnit.MILLISECONDS)
    try {
        assertEquals("HTTP/1.1 200 OK", reader.readLine())
        while (true) {
            val line = reader.readLine() ?: error("Stream ended before : connected")
            if (line == ": connected") return
        }
    } catch (failure: Throwable) {
        socket.close()
        throw failure
    } finally {
        timeout.cancel(false)
        deadline.shutdownNow()
    }
}

class WebStreamHandshakeTest {
    private fun peer(response: String, closeOutput: Boolean = true, check: (Socket, BufferedReader) -> Unit) {
        ServerSocket(0, 1, InetAddress.getByName("127.0.0.1")).use { listener ->
            Socket("127.0.0.1", listener.localPort).use { client ->
                listener.accept().use { server ->
                    server.getOutputStream().write(response.toByteArray())
                    if (closeOutput) server.shutdownOutput()
                    check(client, client.getInputStream().bufferedReader())
                }
            }
        }
    }

    @Test fun `connected announcement leaves the stream open for its caller`() {
        peer("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\nd\r\n: connected\n\n\r\n",
            closeOutput = false) { socket, reader ->
            awaitWebTestStreamAnnouncement(socket, reader)
            assertFalse(socket.isClosed)
        }
    }

    @Test fun `EOF before announcement fails immediately and closes the socket`() {
        for (response in listOf("HTTP/1.1 200 OK\r\n", "HTTP/1.1 200 OK\r\n\r\n", "HTTP/1.1 200 OK\r\n\r\n: con")) {
            peer(response) { socket, reader ->
                val failure = assertFailsWith<IllegalStateException> { awaitWebTestStreamAnnouncement(socket, reader) }
                assertEquals("Stream ended before : connected", failure.message)
                assertTrue(socket.isClosed)
            }
        }
    }

    @Test fun `missing or refused status closes the socket`() {
        for (response in listOf("", "HTTP/1.1 403 Forbidden\r\n\r\n")) {
            peer(response) { socket, reader ->
                assertFailsWith<AssertionError> { awaitWebTestStreamAnnouncement(socket, reader) }
                assertTrue(socket.isClosed)
            }
        }
    }

    @Test fun `overall handshake deadline closes a stalled status or partial announcement`() {
        for (response in listOf("", "HTTP/1.1 200 OK\r\n\r\n: con")) {
            peer(response, closeOutput = false) { socket, reader ->
                assertFailsWith<IOException> { awaitWebTestStreamAnnouncement(socket, reader, timeoutMs = 100) }
                assertTrue(socket.isClosed)
            }
        }
    }
}
