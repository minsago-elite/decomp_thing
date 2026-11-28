package decompengine.web

import com.sun.net.httpserver.HttpContext
import com.sun.net.httpserver.HttpExchange
import com.sun.net.httpserver.HttpPrincipal
import com.sun.net.httpserver.Headers
import java.io.InputStream
import java.io.OutputStream
import java.net.InetSocketAddress
import java.net.URI

/**
 * Delegating exchange that confirms a response completed. Only two shapes qualify: a bodyless response
 * (`-1`, HEAD, 204 or 304) whose headers were sent, and a fixed-length response whose body stream closed
 * without any write, flush or close failure (the JDK's fixed-length close fails when bytes are missing).
 * A chunked response (declared length 0) never qualifies: the JDK's chunked close can swallow a failure
 * writing its terminating chunk. A status code alone is not completion either: headers can be sent and a
 * later body write fail while a dispatcher swallows it and returns. Closing the exchange never confirms it.
 */
internal class WebResponseCompletion(private val delegate: HttpExchange) : HttpExchange() {
    @Volatile private var failed = false
    @Volatile private var fixedLengthBody = false
    @Volatile private var completed = false
    // Set before delegating an exchange close: the JDK then marks the body closed and swallows a short-body
    // failure, so a later body close would wrongly look clean. Completion established earlier is kept.
    @Volatile private var exchangeClosed = false
    private var declaredLength = 0L
    private val written = java.util.concurrent.atomic.AtomicLong()
    /** Test seam between a body close returning and its completion check, where an exchange close can race. */
    @Volatile internal var afterBodyClose: () -> Unit = {}
    private var body: TrackedBody? = null

    private inline fun <T> tracked(block: () -> T): T = try { block() } catch (failure: Throwable) { failed = true; throw failure }

    override fun sendResponseHeaders(rCode: Int, responseLength: Long) {
        tracked { delegate.sendResponseHeaders(rCode, responseLength) }
        // These responses carry no body: the JDK finishes them once their headers are written.
        if (responseLength == -1L || delegate.requestMethod == "HEAD" || rCode == 204 || rCode == 304) completed = true
        else if (responseLength > 0) { declaredLength = responseLength; fixedLengthBody = true }
    }

    override fun getResponseBody(): OutputStream {
        val current = delegate.responseBody
        synchronized(this) {
            val existing = body
            if (existing != null && existing.output === current) return existing
            return TrackedBody(current).also { body = it }
        }
    }

    private inner class TrackedBody(val output: OutputStream) : OutputStream() {
        override fun write(b: Int) { tracked { output.write(b) }; written.incrementAndGet() }
        override fun write(b: ByteArray, off: Int, len: Int) { tracked { output.write(b, off, len) }; written.addAndGet(len.toLong()) }
        override fun flush() = tracked { output.flush() }
        override fun close() {
            tracked { output.close() }
            afterBodyClose()
            // An exchange close (for example the request deadline) can overlap this one. A clean return then
            // confirms completion only if the exact declared length was accepted: after an exchange close the
            // JDK marks the body closed and swallows a short-body failure, so the return alone proves nothing.
            if (fixedLengthBody && !failed && (!exchangeClosed || written.get() == declaredLength)) completed = true
        }
    }

    override fun getRequestHeaders(): Headers = delegate.requestHeaders
    override fun getResponseHeaders(): Headers = delegate.responseHeaders
    override fun getRequestURI(): URI = delegate.requestURI
    override fun getRequestMethod(): String = delegate.requestMethod
    override fun getHttpContext(): HttpContext = delegate.httpContext
    override fun close() {
        exchangeClosed = true
        delegate.close()
    }
    override fun getRequestBody(): InputStream = delegate.requestBody
    override fun getResponseCode(): Int = delegate.responseCode
    override fun getRemoteAddress(): InetSocketAddress = delegate.remoteAddress
    override fun getLocalAddress(): InetSocketAddress = delegate.localAddress
    override fun getProtocol(): String = delegate.protocol
    override fun getAttribute(name: String): Any? = delegate.getAttribute(name)
    override fun setAttribute(name: String, value: Any?) = delegate.setAttribute(name, value)
    override fun setStreams(i: InputStream?, o: OutputStream?) = delegate.setStreams(i, o)
    override fun getPrincipal(): HttpPrincipal? = delegate.principal

    companion object {
        /** Only a tracked exchange can confirm completion; any other exchange is treated as incomplete. */
        fun completed(exchange: HttpExchange): Boolean = (exchange as? WebResponseCompletion)?.let { it.completed && !it.failed } == true
    }
}
