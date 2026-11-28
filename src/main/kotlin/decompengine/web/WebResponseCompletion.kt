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
 * Delegating exchange that confirms a response completed: its headers were sent and, when it has a body,
 * that body stream was closed without any write, flush or close failure. A status code alone is not
 * completion: headers can be sent and a later body write fail while a dispatcher swallows the failure,
 * closes the exchange and returns normally. Closing the exchange itself never confirms completion.
 */
internal class WebResponseCompletion(private val delegate: HttpExchange) : HttpExchange() {
    @Volatile private var failed = false
    @Volatile private var headersSent = false
    @Volatile private var completed = false
    private var body: TrackedBody? = null

    private inline fun <T> tracked(block: () -> T): T = try { block() } catch (failure: Throwable) { failed = true; throw failure }

    override fun sendResponseHeaders(rCode: Int, responseLength: Long) {
        tracked { delegate.sendResponseHeaders(rCode, responseLength) }
        headersSent = true
        // These responses carry no body: the JDK finishes them once their headers are written.
        if (responseLength == -1L || delegate.requestMethod == "HEAD" || rCode == 204 || rCode == 304) completed = true
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
        override fun write(b: Int) = tracked { output.write(b) }
        override fun write(b: ByteArray, off: Int, len: Int) = tracked { output.write(b, off, len) }
        override fun flush() = tracked { output.flush() }
        override fun close() {
            tracked { output.close() }
            if (headersSent && !failed) completed = true
        }
    }

    override fun getRequestHeaders(): Headers = delegate.requestHeaders
    override fun getResponseHeaders(): Headers = delegate.responseHeaders
    override fun getRequestURI(): URI = delegate.requestURI
    override fun getRequestMethod(): String = delegate.requestMethod
    override fun getHttpContext(): HttpContext = delegate.httpContext
    override fun close() = delegate.close()
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
