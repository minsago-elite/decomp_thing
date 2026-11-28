package decompengine.builtin.provider

import org.junit.jupiter.api.Test
import java.io.*
import java.net.InetAddress
import java.nio.file.Path
import java.security.KeyStore
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.*
import kotlin.test.*

internal class ChatGptPlanSocketHttpV1Test {
    @Test fun exactFixedRequestTlsPolicyAndBodySlices() {
        val out = ByteArrayOutputStream(); val c = C4Connector(C4Input(""), out)
        val body = ByteArray(20001) { 120 }
        val op = ChatGptPlanSocketHttpV1.startForTest(c4context(), PlanHttpEndpointV1.RESPONSES, "synthetic", body, c)
        body.fill(99)
        try {
            c4headers(op)
            val bytes = out.toByteArray(); val request = String(bytes, Charsets.US_ASCII)
            assertTrue(request.startsWith("POST /v1/responses HTTP/1.1\r\nHost: api.openai.com\r\n"))
            assertTrue(request.contains("Content-Length: 20001\r\n")); assertTrue(request.endsWith("x".repeat(20001)))
            assertEquals(20001, op.transfer().bodyBytesOffered); assertEquals(20001, op.transfer().bodyBytesReturned)
            assertEquals(1, c.resolves.get()); assertEquals(1, c.connects.get())
            assertEquals("HTTPS", c.tls.sslParameters.endpointIdentificationAlgorithm)
            assertEquals(listOf("TLSv1.3", "TLSv1.2"), c.tls.selected.toList())
            assertEquals("api.openai.com", (c.tls.sslParameters.serverNames.single() as SNIHostName).asciiName)
            assertContentEquals(arrayOf("http/1.1"), c.tls.sslParameters.applicationProtocols)
        } finally { c4release(op) }
    }
    @Test fun headerAndPartialBodyWriteFailuresPreservePossiblySentAndUnknownPrefix() {
        for (failAt in 1..3) {
            var writes = 0
            val out = object : OutputStream() {
                override fun write(b: Int) = error("unexpected scalar write")
                override fun write(b: ByteArray, off: Int, len: Int) { writes++; if (writes == failAt) throw IOException("synthetic partial write") }
            }
            val op = ChatGptPlanSocketHttpV1.startForTest(c4context(), PlanHttpEndpointV1.RESPONSES, "synthetic", ByteArray(9000), C4Connector(C4Input(), out))
            try {
                c4await { op.transfer().failure }; c4release(op)
                val f = op.transfer(); assertTrue(f.headerPossiblySent)
                assertEquals(when (failAt) { 1 -> 0; 2 -> 8192; else -> 9000 }.toLong(), f.bodyBytesOffered)
                assertEquals(if (failAt == 3) 8192L else 0L, f.bodyBytesReturned)
                assertEquals(PlanHttpCloseV1.FAILED, op.closeStep(1))
            } finally { c4release(op) }
        }
    }
    @Test fun lateVoidWriteReturnRecordsWholeSliceButNeverAdmitsNextSlice() {
        var writes = 0; val barrier = C4Latch()
        val out = object : OutputStream() {
            override fun write(b: Int) = error("scalar")
            override fun write(b: ByteArray, off: Int, len: Int) { writes++; if (writes == 2) barrier.block() }
        }
        val op = ChatGptPlanSocketHttpV1.startForTest(c4context(), PlanHttpEndpointV1.RESPONSES, "synthetic", ByteArray(9000), C4Connector(C4Input(), out))
        try { barrier.await(); op.cancel(); assertTrue(op.transfer().retained); barrier.open(); c4await { !op.transfer().retained }
            assertEquals(8192, op.transfer().bodyBytesReturned); assertEquals(8192, op.transfer().bodyBytesOffered); assertEquals(2, writes) }
        finally { barrier.open(); c4release(op) }
    }
    @Test fun requestBoundsBadBearerAlpnAndNonLoopbackFailBeforeUnauthorizedEffects() {
        val c = C4Connector()
        assertFailsWith<PlanHttpBoundaryV1> { ChatGptPlanSocketHttpV1.startForTest(c4context(request = 1), PlanHttpEndpointV1.RESPONSES, "synthetic", ByteArray(2), c) }
        assertEquals(0, c.resolves.get())
        for (token in listOf("", "a\r\nb", "a".repeat(4097))) assertFailsWith<PlanHttpBoundaryV1> { ChatGptPlanSocketHttpV1.startForTest(c4context(), PlanHttpEndpointV1.RESPONSES, token, ByteArray(1), c) }
        for (alpn in listOf("", "http/1.1", "h2")) {
            val connector = C4Connector(); connector.tls.negotiated = alpn; val op = c4start(connector)
            try { if (alpn == "h2") { c4await { op.transfer().failure }; assertFalse(op.transfer().headerPossiblySent) } else c4headers(op) }
            finally { c4release(op) }
        }
        val notLocal = C4Connector(); notLocal.address = InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 1))
        val op = c4start(notLocal)
        try { c4await { op.transfer().failure }; assertEquals(0, notLocal.connects.get()) } finally { c4release(op) }
    }
    private fun ssl(name: String): SSLContext {
        val ks = KeyStore.getInstance("PKCS12")
        Path.of(System.getProperty("c4.fixtures"), name).toFile().inputStream().use { ks.load(it, "fixture-password".toCharArray()) }
        val km = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()); km.init(ks, "fixture-password".toCharArray())
        val tm = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm()); tm.init(ks)
        return SSLContext.getInstance("TLS").also { it.init(km.keyManagers, tm.trustManagers, null) }
    }
    @Test fun realLoopbackTlsCatalogKeepAliveExactEofAndHostnameTrustDenials() {
        for (mode in listOf("success", "hostname", "trust")) {
            val context = ssl(if (mode == "hostname") "wrong.p12" else "server.p12")
            val server = context.serverSocketFactory.createServerSocket(0, 1, InetAddress.getLoopbackAddress()) as SSLServerSocket
            server.soTimeout = 3000
            val done = C4Latch(); val failure = AtomicReference<Throwable?>(); val received = AtomicReference<String?>()
            val peer = AtomicReference<SSLSocket?>()
            val worker = Thread {
                try {
                    val socket = server.accept() as SSLSocket; peer.set(socket); socket.soTimeout = 3000
                    val p = socket.sslParameters; p.applicationProtocols = arrayOf("http/1.1"); socket.sslParameters = p
                    socket.startHandshake()
                    val b = ByteArrayOutputStream(); val input = socket.inputStream
                    while (b.size() < 20480) {
                        val v = input.read(); check(v >= 0); b.write(v)
                        if (b.size() >= 4 && b.toString(Charsets.US_ASCII).endsWith("\r\n\r\n")) break
                    }
                    received.set(b.toString(Charsets.US_ASCII))
                    socket.outputStream.write("HTTP/1.1 200 OK\r\nContent-Type:application/json\r\nContent-Length:2\r\n\r\n{}".toByteArray())
                    done.block() // peer stays open until client has proven framed EOF + physical ACK
                } catch (t: Throwable) { failure.set(t) }
                finally { try { peer.get()?.close() } catch (_: Exception) {} }
            }
            worker.start()
            val trust = if (mode == "trust") ssl("wrong.p12") else context
            val op = ChatGptPlanSocketHttpV1.startForTest(c4context(span = 10_000_000_000), PlanHttpEndpointV1.MODELS,
                "synthetic", null, PlanHttpLoopbackTlsV1(server.localPort, trust))
            try {
                if (mode == "success") {
                    c4headers(op); val b = ByteArray(2); assertEquals(2, c4read(op, b)); assertEquals("{}", String(b))
                    assertEquals(-1, c4read(op, b)); done.await(); assertTrue(worker.isAlive)
                    op.finish(); assertEquals(PlanHttpCloseV1.SUCCEEDED, op.closeStep(200_000_000))
                    assertTrue(received.get()!!.startsWith("GET /v1/models HTTP/1.1\r\nHost: api.openai.com\r\n"))
                    assertEquals(0, op.transfer().bodyBytesOffered)
                } else { c4await { op.transfer().failure }; assertFalse(op.transfer().headerPossiblySent) }
            } finally { done.open(); server.close(); c4release(op); worker.join(3500); assertFalse(worker.isAlive) }
            if (mode == "success") assertNull(failure.get())
        }
        assertEquals(0, ChatGptPlanTransportLifetimeV1.processFacts()[0])
        println("C4A_TLS sockets=0 fixtureThreads=0 externalConnections=0")
    }
}
