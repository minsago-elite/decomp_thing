package decompengine.chatgpt

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.ServerSocketChannel
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.concurrent.atomic.AtomicBoolean

/** Incremental bounded ASCII envelope admission. Query interpretation belongs exclusively to OAuth. */
internal class ChatGptCallbackEnvelope(private val authority: String) : ChatGptAuthSafeObject() {
    enum class State { READING, ADMITTED, REJECTED }
    var state = State.READING
        private set
    var rawTarget: String? = null
        private set
    private val line = ByteArray(18 * 1024)
    private var length = 0
    private var cr = false
    private var requestLine = true
    private var headerBytes = 0
    private var headers = 0
    private var host = false

    fun feed(bytes: ByteBuffer): State {
        while (bytes.hasRemaining()) {
            if (state != State.READING) return reject() // extra bytes/body/pipeline in this read
            val b = bytes.get().toInt() and 255
            if (!requestLine && ++headerBytes > 8 * 1024) return reject()
            if (cr) {
                if (b != 10) return reject()
                cr = false
                finishLine()
                length = 0
                continue
            }
            if (b == 13) { cr = true; continue }
            if (b == 10 || b > 126 || b < 32 && !(b == 9 && !requestLine)) return reject()
            val cap = if (requestLine) 18 * 1024 else 8 * 1024
            if (length >= cap) return reject()
            line[length++] = b.toByte()
        }
        return state
    }

    private fun finishLine() {
        if (requestLine) {
            requestLine = false
            val text = String(line, 0, length, StandardCharsets.US_ASCII)
            if (!text.startsWith("GET ") || !text.endsWith(" HTTP/1.1")) { reject(); return }
            val targetLength = length - 4 - 9
            if (targetLength < 15 || targetLength > 15 + 16 * 1024) { reject(); return }
            // Check raw bytes before copying the target. No decoding or URI normalization.
            for (i in 4 until length - 9) if (line[i].toInt() <= 32 || line[i] == '#'.code.toByte() || line[i] == '\\'.code.toByte()) {
                reject(); return
            }
            if (!text.startsWith("GET /auth/callback?")) { reject(); return }
            rawTarget = text.substring(4, length - 9)
            return
        }
        if (length == 0) {
            if (host) state = State.ADMITTED else reject()
            return
        }
        if (++headers > 32 || line[0] == 32.toByte() || line[0] == 9.toByte()) { reject(); return }
        val text = String(line, 0, length, StandardCharsets.US_ASCII)
        val colon = text.indexOf(':')
        if (colon <= 0 || text.substring(0, colon).any { !it.isLetterOrDigit() && it !in "!#$%&'*+-.^_`|~" }) {
            reject(); return
        }
        val name = text.substring(0, colon).lowercase(java.util.Locale.ROOT)
        val value = text.substring(colon + 1).trim(' ', '\t')
        when (name) {
            "host" -> if (host || value != authority) { reject(); return } else host = true
            "content-length", "transfer-encoding", "upgrade", "expect", "trailer", "te" -> { reject(); return }
            "connection" -> if (value.split(',').any { it.trim().equals("upgrade", true) }) { reject(); return }
        }
    }

    private fun reject(): State { state = State.REJECTED; rawTarget = null; return state }
}

internal abstract class ChatGptBoundCallback : ChatGptAuthSafeObject() {
    abstract val redirect: ChatGptPlanOAuthRedirect
    abstract fun await(attempt: ChatGptPlanOAuthAttempt, lifetime: ChatGptAuthLifetime): ChatGptPlanOAuthAttempt.CallbackResult
    abstract fun close(): ChatGptAuthSettlement
}

/** No configurable address/port/path and no browser, controller, HTTP client or issuer access. */
internal class ChatGptLoopbackListener : ChatGptAuthSafeObject() {
    fun bind(lifetime: ChatGptAuthLifetime): ChatGptBoundCallback {
        lifetime.admitListener()
        val bound = Bound(lifetime)
        try {
            lifetime.own(bound.cleanup)
            bound.acquire()
            lifetime.check()
            return bound
        } catch (e: Exception) {
            lifetime.cancel()
            throw if (e is ChatGptAuthException) e else ChatGptAuthException(ChatGptAuthFailure.LISTENER_FAILED)
        }
    }

    private class Bound(private val lifetime: ChatGptAuthLifetime) : ChatGptBoundCallback() {
        private enum class Start { NEW, STARTED, CLOSED }
        private val start = AtomicReference(Start.NEW)
        @Volatile private var server: ServerSocketChannel? = null
        @Volatile private var selector: Selector? = null
        @Volatile private var endpoint: ChatGptPlanOAuthRedirect? = null
        private val ready = CountDownLatch(1)
        private val assigned = CountDownLatch(1)
        private val protocol = AtomicReference<ChatGptPlanOAuthAttempt?>()
        private val worker = Thread({ runOwner() }, "chatgpt-auth-loopback").also { it.isDaemon = true }
        private val awaited = AtomicBoolean()
        private val done = CountDownLatch(1)
        @Volatile private var stopping = false
        @Volatile private var cleanupOk = true
        @Volatile private var result: ChatGptPlanOAuthAttempt.CallbackResult? = null
        @Volatile private var failure: ChatGptAuthFailure? = null
        override val redirect: ChatGptPlanOAuthRedirect
            get() = endpoint ?: throw ChatGptAuthException(ChatGptAuthFailure.LISTENER_FAILED)

        val cleanup = object : ChatGptAuthResource() {
            override fun stopAndAwait(): Boolean {
                stop()
                done.await() // isolated cleanup worker; lifetime bounds its acknowledgement wait
                if (start.get() == Start.STARTED) worker.join()
                return cleanupOk && done.count == 0L
            }
        }

        fun acquire() {
            lifetime.check()
            if (!start.compareAndSet(Start.NEW, Start.STARTED)) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            try { worker.start() } catch (_: Throwable) {
                failure = ChatGptAuthFailure.LISTENER_FAILED; ready.countDown(); done.countDown()
                throw ChatGptAuthException(ChatGptAuthFailure.LISTENER_FAILED)
            }
            try {
                while (!ready.await(minOf(lifetime.remainingNanos(), ChatGptAuthLifetime.POLL_NANOS), TimeUnit.NANOSECONDS)) lifetime.check()
                lifetime.check()
                failure?.let { throw ChatGptAuthException(it) }
                if (stopping || endpoint == null) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt(); lifetime.cancel()
                throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            }
        }

        private fun runOwner() {
            try {
                lifetime.check()
                if (stopping) return
                // The same owner acquires, selects and closes every handle, including partial failures.
                server = ServerSocketChannel.open()
                server!!.configureBlocking(false)
                server!!.bind(InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 0), 4)
                endpoint = ChatGptPlanOAuthRedirect.of((server!!.localAddress as InetSocketAddress).port)
                selector = Selector.open()
                server!!.register(selector, SelectionKey.OP_ACCEPT)
                lifetime.check()
                ready.countDown()
                while (!stopping && !assigned.await(minOf(lifetime.remainingNanos(), ChatGptAuthLifetime.POLL_NANOS), TimeUnit.NANOSECONDS)) lifetime.check()
                if (!stopping) runLoop(protocol.get() ?: throw ChatGptAuthException(ChatGptAuthFailure.INVALID_OWNER))
            } catch (e: ChatGptAuthException) { failure = e.failure }
            catch (_: Throwable) { failure = ChatGptAuthFailure.LISTENER_FAILED }
            finally {
                closeHandle(server); closeHandle(selector)
                if (!cleanupOk) failure = ChatGptAuthFailure.UNSETTLED
                ready.countDown(); done.countDown()
            }
        }

        override fun await(attempt: ChatGptPlanOAuthAttempt, lifetime: ChatGptAuthLifetime): ChatGptPlanOAuthAttempt.CallbackResult {
            if (lifetime !== this.lifetime || attempt.redirect.value != redirect.value) throw ChatGptAuthException(ChatGptAuthFailure.INVALID_OWNER)
            if (!awaited.compareAndSet(false, true)) throw ChatGptAuthException(ChatGptAuthFailure.ATTEMPT_USED)
            try {
                lifetime.check()
                if (stopping) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
                protocol.set(attempt)
                assigned.countDown()
                while (!done.await(minOf(lifetime.remainingNanos(), ChatGptAuthLifetime.POLL_NANOS), TimeUnit.NANOSECONDS)) {
                    lifetime.check()
                }
                lifetime.check() // late helper/cleanup completion has no result authority
                if (stopping) throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
                failure?.let { throw ChatGptAuthException(it) }
                return result ?: throw ChatGptAuthException(ChatGptAuthFailure.LISTENER_FAILED)
            } catch (_: InterruptedException) {
                Thread.currentThread().interrupt()
                lifetime.cancel()
                throw ChatGptAuthException(ChatGptAuthFailure.CANCELLED)
            } catch (e: ChatGptAuthException) {
                stop()
                throw e
            }
        }

        private class Connection(val channel: SocketChannel, val origin: Long, val budget: Long, authority: String) {
            val parser = ChatGptCallbackEnvelope(authority)
            val bytes: ByteBuffer = ByteBuffer.allocate(2048)
            var reply: ByteBuffer? = null
        }

        private fun runLoop(attempt: ChatGptPlanOAuthAttempt) {
            val connections = LinkedHashMap<SocketChannel, Connection>()
            var rejected = 0
            var consumed = false
            var inputLimit = false
            try {
                val poller = selector!!
                val listener = server!!
                while (!stopping) {
                    lifetime.check()
                    if ((consumed || inputLimit) && connections.isEmpty()) break
                    val remaining = minOf(lifetime.remainingNanos(), ChatGptAuthLifetime.POLL_NANOS)
                    poller.select(maxOf(1, remaining / 1_000_000))
                    lifetime.check()
                    val keys = poller.selectedKeys().iterator()
                    while (keys.hasNext()) {
                        val key = keys.next(); keys.remove()
                        if (!key.isValid) continue
                        if (key.isAcceptable) {
                            // One accept per selector turn keeps cancellation and live reads fair.
                            val channel = listener.accept() ?: continue
                            try {
                                channel.configureBlocking(false)
                                if (connections.size >= 4 || consumed || inputLimit) { channel.close(); continue }
                                val connection = Connection(channel, System.nanoTime(), minOf(2_000_000_000L, lifetime.remainingNanos()), redirect.hostHeader)
                                connections[channel] = connection
                                channel.register(poller, SelectionKey.OP_READ, connection)
                            } catch (e: Throwable) {
                                try { channel.close() } catch (_: Throwable) { cleanupOk = false }
                                throw e
                            }
                        } else {
                            val c = key.attachment() as Connection
                            if (System.nanoTime() - c.origin >= c.budget) {
                                closeHandle(c.channel); connections.remove(c.channel)
                                if (c.reply == null && !consumed && !inputLimit && ++rejected >= 16) {
                                    inputLimit = true; closeHandle(listener)
                                }
                                continue
                            }
                            lifetime.check()
                            try {
                                if (key.isReadable) {
                                    var eof = false
                                    // Drain available bytes before admission to reject coalesced pipelines.
                                    var readBudget = 28 * 1024
                                    while (readBudget > 0) {
                                        c.bytes.clear()
                                        val read = c.channel.read(c.bytes)
                                        if (read <= 0) { eof = read < 0; break }
                                        readBudget -= read
                                        c.bytes.flip(); c.parser.feed(c.bytes)
                                        if (c.parser.state == ChatGptCallbackEnvelope.State.REJECTED) break
                                    }
                                    if (c.parser.state != ChatGptCallbackEnvelope.State.READING || eof) {
                                        if (!consumed && !inputLimit && c.parser.state == ChatGptCallbackEnvelope.State.ADMITTED) {
                                            consumed = true // first structural callback owns the protocol forever
                                            lifetime.check()
                                            result = attempt.consumeCallback("GET", redirect.hostHeader, c.parser.rawTarget!!)
                                            lifetime.check()
                                            closeHandle(listener)
                                        } else {
                                            rejected++
                                            if (rejected >= 16) { inputLimit = true; closeHandle(listener) }
                                        }
                                        c.reply = ByteBuffer.wrap(REPLY)
                                        key.interestOps(SelectionKey.OP_WRITE)
                                    }
                                }
                                if (key.isValid && key.isWritable) {
                                    c.channel.write(c.reply!!)
                                    if (!c.reply!!.hasRemaining()) { closeHandle(c.channel); connections.remove(c.channel) }
                                }
                            } catch (_: IOException) {
                                // A peer reset is one failed connection, not a new protocol attempt.
                                closeHandle(c.channel); connections.remove(c.channel)
                                if (c.reply == null && !consumed && !inputLimit && ++rejected >= 16) {
                                    inputLimit = true; closeHandle(listener)
                                }
                            }
                        }
                    }
                    for (c in connections.values.toList()) {
                        if (System.nanoTime() - c.origin >= c.budget) {
                            closeHandle(c.channel); connections.remove(c.channel)
                            if (c.reply == null && !consumed && !inputLimit && ++rejected >= 16) {
                                inputLimit = true; closeHandle(listener)
                            }
                        }
                    }
                }
                if (inputLimit) failure = ChatGptAuthFailure.CALLBACK_INPUT_LIMIT
            } catch (e: ChatGptAuthException) { failure = e.failure }
            catch (_: Exception) { failure = ChatGptAuthFailure.LISTENER_FAILED }
            finally {
                for (c in connections.keys) closeHandle(c)
                closeHandle(server); closeHandle(selector)
                if (!cleanupOk) failure = ChatGptAuthFailure.UNSETTLED
            }
        }

        private fun closeHandle(handle: AutoCloseable?) {
            try { handle?.close() } catch (_: Throwable) { cleanupOk = false }
        }

        private fun stop() {
            stopping = true // revoke result authority before wakeup/close/join
            result = null
            assigned.countDown()
            selector?.wakeup()
            if (start.compareAndSet(Start.NEW, Start.CLOSED)) { ready.countDown(); done.countDown() }
        }

        override fun close(): ChatGptAuthSettlement {
            stop()
            val budget = try { minOf(250_000_000L, lifetime.remainingNanos()) } catch (_: Exception) { 0L }
            if (budget > 0 && start.get() == Start.STARTED) try {
                worker.join(budget / 1_000_000, (budget % 1_000_000).toInt())
            } catch (_: InterruptedException) { Thread.currentThread().interrupt() }
            return if (done.count == 0L && !worker.isAlive && cleanupOk) ChatGptAuthSettlement.SETTLED else ChatGptAuthSettlement.UNSETTLED
        }
    }

    companion object {
        private val REPLY = ("HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\n" +
            "Content-Length: 26\r\nCache-Control: no-store\r\nContent-Security-Policy: default-src 'none'; frame-ancestors 'none'\r\n" +
            "Referrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n" +
            "Return to the application.\n").toByteArray(StandardCharsets.US_ASCII)
    }
}
