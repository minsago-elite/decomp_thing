package decompengine.oracle.provenance

import java.io.IOException
import java.net.URI
import java.net.http.HttpClient
import java.net.http.HttpHeaders
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CancellationException
import java.util.concurrent.CompletableFuture
import java.util.concurrent.CompletionStage
import java.util.concurrent.ExecutionException
import java.util.concurrent.Flow
import java.util.concurrent.TimeUnit
import java.util.concurrent.TimeoutException

internal data class HttpsDownloadRequest(
    val uri: URI,
    val expectedBytes: Long,
    val expectedSha256: String,
    val userAgent: String,
    val timeout: Duration,
    val allowedHosts: Set<String>,
)

internal data class HttpsDownloadReceipt(
    val bytes: Long,
    val sha256: String,
    val finalUri: URI,
)

internal data class HttpsExchangeRequest(
    val uri: URI,
    val userAgent: String,
    val timeout: Duration,
    val maximumBodyBytes: Long,
)

internal data class HttpsBodyReceipt(val bytes: Long, val sha256: String)

internal data class HttpsExchangeResult(
    val statusCode: Int,
    val headers: HttpHeaders,
    val body: HttpsBodyReceipt?,
)

internal fun interface HttpsExchangeTransport {
    fun exchange(
        request: HttpsExchangeRequest,
        shouldStreamBody: (Int, HttpHeaders) -> Boolean,
        sink: WritableByteChannel,
    ): HttpsExchangeResult
}

/**
 * One explicitly bounded HTTPS download.
 *
 * Redirects are followed manually so every hop remains inside the caller's host policy and the
 * complete exchange shares one wall-clock deadline. Response bytes are never materialized in JVM
 * memory: a back-pressured body subscriber hashes and writes each buffer directly to the caller's
 * pinned staging inode.
 */
internal class BoundedHttpsDownloader(
    private val transport: HttpsExchangeTransport = JdkHttpsExchangeTransport(),
) {
    fun download(request: HttpsDownloadRequest, sink: WritableByteChannel): HttpsDownloadReceipt {
        require(request.expectedBytes > 0L) { "expected download bytes must be positive" }
        require(request.expectedSha256.matches(SHA256)) { "expected download SHA-256 is invalid" }
        require(request.userAgent.isNotBlank() && '\n' !in request.userAgent && '\r' !in request.userAgent) {
            "download user agent is invalid"
        }
        require(!request.timeout.isZero && !request.timeout.isNegative) { "download timeout must be positive" }
        val allowedHosts = request.allowedHosts.mapTo(linkedSetOf()) { it.lowercase() }
        require(allowedHosts.isNotEmpty() && allowedHosts.none { it.isBlank() }) {
            "download host policy must not be empty"
        }

        var current = validateUri(request.uri, allowedHosts)
        val visited = linkedSetOf<URI>()
        val deadline = deadlineAfter(request.timeout)
        var redirects = 0
        while (true) {
            if (!visited.add(current)) provenanceFail("HTTPS download entered a redirect cycle")
            val remaining = remaining(deadline)
            val exchange = transport.exchange(
                HttpsExchangeRequest(
                    uri = current,
                    userAgent = request.userAgent,
                    timeout = remaining,
                    maximumBodyBytes = request.expectedBytes,
                ),
                shouldStreamBody = { status, headers ->
                    requireBoundedHeaders(headers)
                    when {
                        status in REDIRECT_STATUS_CODES -> false
                        status != 200 -> provenanceFail("HTTPS download returned HTTP $status")
                        else -> {
                            requireIdentityEncoding(headers)
                            requireExpectedContentLength(headers, request.expectedBytes)
                            true
                        }
                    }
                },
                sink = sink,
            )
            requireBoundedHeaders(exchange.headers)
            when {
                exchange.statusCode in REDIRECT_STATUS_CODES -> {
                    if (exchange.body != null) provenanceFail("redirect response unexpectedly exposed a body")
                    if (redirects >= MAXIMUM_REDIRECTS) provenanceFail("HTTPS download exceeded its redirect bound")
                    val locations = exchange.headers.allValues("Location")
                    if (locations.size != 1 || locations.single().isBlank()) {
                        provenanceFail("HTTPS redirect must contain exactly one Location header")
                    }
                    val redirected = try {
                        current.resolve(locations.single())
                    } catch (failure: Exception) {
                        throw ReleaseArtifactProvenanceException("HTTPS redirect Location is invalid", failure)
                    }
                    current = validateUri(redirected, allowedHosts)
                    redirects++
                }
                exchange.statusCode == 200 -> {
                    val body = exchange.body ?: provenanceFail("successful HTTPS response has no body receipt")
                    if (body.bytes != request.expectedBytes) {
                        provenanceFail(
                            "HTTPS body byte length mismatch: expected ${request.expectedBytes}, observed ${body.bytes}",
                        )
                    }
                    if (body.sha256 != request.expectedSha256) {
                        provenanceFail("HTTPS body SHA-256 differs from its release lock")
                    }
                    return HttpsDownloadReceipt(body.bytes, body.sha256, current)
                }
                else -> provenanceFail("HTTPS download returned HTTP ${exchange.statusCode}")
            }
        }
    }

    private fun validateUri(uri: URI, allowedHosts: Set<String>): URI {
        val host = uri.host?.lowercase()
        if (
            !uri.isAbsolute || !uri.scheme.equals("https", ignoreCase = true) || host == null ||
            uri.rawUserInfo != null || uri.rawFragment != null || host !in allowedHosts ||
            (uri.port != -1 && uri.port != HTTPS_PORT)
        ) {
            provenanceFail("download URI is outside the trusted HTTPS host policy: ${redacted(uri)}")
        }
        return uri
    }

    private fun requireIdentityEncoding(headers: HttpHeaders) {
        val encodings = headers.allValues("Content-Encoding")
        if (encodings.isNotEmpty() && (encodings.size != 1 || !encodings.single().equals("identity", true))) {
            provenanceFail("HTTPS response used an unexpected content encoding")
        }
    }

    private fun requireBoundedHeaders(headers: HttpHeaders) {
        var fieldCount = 0
        var totalBytes = 0L
        headers.map().forEach { (name, values) ->
            val nameBytes = name.toByteArray(Charsets.UTF_8).size
            if (nameBytes > MAXIMUM_HEADER_NAME_BYTES) {
                provenanceFail("HTTPS response header name exceeds its byte bound")
            }
            values.forEach { value ->
                fieldCount = Math.addExact(fieldCount, 1)
                if (fieldCount > MAXIMUM_HEADER_FIELDS) {
                    provenanceFail("HTTPS response exceeds its header-count bound")
                }
                val valueBytes = value.toByteArray(Charsets.UTF_8).size
                if (valueBytes > MAXIMUM_HEADER_VALUE_BYTES) {
                    provenanceFail("HTTPS response header value exceeds its byte bound")
                }
                totalBytes = try {
                    Math.addExact(totalBytes, Math.addExact(nameBytes.toLong(), valueBytes.toLong()))
                } catch (failure: ArithmeticException) {
                    throw ReleaseArtifactProvenanceException("HTTPS response header byte count overflows", failure)
                }
                if (totalBytes > MAXIMUM_TOTAL_HEADER_BYTES) {
                    provenanceFail("HTTPS response headers exceed their total byte bound")
                }
            }
        }
    }

    private fun requireExpectedContentLength(headers: HttpHeaders, expectedBytes: Long) {
        val lengths = headers.allValues("Content-Length")
        if (lengths.isEmpty()) return
        if (lengths.size != 1 || !lengths.single().matches(DECIMAL)) {
            provenanceFail("HTTPS response Content-Length is malformed or repeated")
        }
        val observed = lengths.single().toLongOrNull()
            ?: provenanceFail("HTTPS response Content-Length exceeds the supported range")
        if (observed != expectedBytes) {
            provenanceFail("HTTPS response Content-Length mismatch: expected $expectedBytes, observed $observed")
        }
    }

    private fun deadlineAfter(timeout: Duration): Long {
        val now = System.nanoTime()
        return try {
            Math.addExact(now, timeout.toNanos())
        } catch (_: ArithmeticException) {
            Long.MAX_VALUE
        }
    }

    private fun remaining(deadline: Long): Duration {
        val nanos = deadline - System.nanoTime()
        if (nanos <= 0L) provenanceFail("HTTPS download exceeded its wall-clock deadline")
        return Duration.ofNanos(nanos)
    }

    private fun redacted(uri: URI): String {
        val host = uri.host ?: "invalid-host"
        val port = if (uri.port < 0) "" else ":${uri.port}"
        val path = uri.rawPath?.takeIf { it.isNotEmpty() } ?: "/"
        return "${uri.scheme ?: "invalid"}://$host$port$path"
    }

    private companion object {
        val SHA256 = Regex("[0-9a-f]{64}")
        val DECIMAL = Regex("0|[1-9][0-9]*")
        val REDIRECT_STATUS_CODES = setOf(301, 302, 303, 307, 308)
        const val MAXIMUM_REDIRECTS = 10
        const val HTTPS_PORT = 443
        const val MAXIMUM_HEADER_FIELDS = 128
        const val MAXIMUM_HEADER_NAME_BYTES = 256
        const val MAXIMUM_HEADER_VALUE_BYTES = 8 * 1024
        const val MAXIMUM_TOTAL_HEADER_BYTES = 64 * 1024L
    }
}

internal fun interface HttpsAsyncSender {
    fun send(
        request: HttpRequest,
        handler: HttpResponse.BodyHandler<HttpsBodyReceipt?>,
    ): CompletableFuture<HttpResponse<HttpsBodyReceipt?>>
}

internal class JdkHttpsExchangeTransport(
    private val client: HttpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(30))
        .followRedirects(HttpClient.Redirect.NEVER)
        .build(),
    private val sender: HttpsAsyncSender = HttpsAsyncSender { request, handler ->
        client.sendAsync(request, handler)
    },
) : HttpsExchangeTransport {
    init {
        require(client.followRedirects() == HttpClient.Redirect.NEVER) {
            "provenance HTTP client must not follow redirects implicitly"
        }
    }

    override fun exchange(
        request: HttpsExchangeRequest,
        shouldStreamBody: (Int, HttpHeaders) -> Boolean,
        sink: WritableByteChannel,
    ): HttpsExchangeResult {
        val httpRequest = HttpRequest.newBuilder(request.uri)
            .timeout(request.timeout)
            .header("User-Agent", request.userAgent)
            .header("Accept-Encoding", "identity")
            .GET()
            .build()
        val future = sender.send(
            httpRequest,
            HttpResponse.BodyHandler { information ->
                if (shouldStreamBody(information.statusCode(), information.headers())) {
                    StreamingBodySubscriber(sink, request.maximumBodyBytes)
                } else {
                    CancellingBodySubscriber()
                }
            },
        )
        try {
            val response = future.get(request.timeout.toNanos(), TimeUnit.NANOSECONDS)
            return HttpsExchangeResult(response.statusCode(), response.headers(), response.body())
        } catch (failure: TimeoutException) {
            future.cancel(true)
            throw ReleaseArtifactProvenanceException("HTTPS exchange exceeded its wall-clock deadline", failure)
        } catch (failure: InterruptedException) {
            future.cancel(true)
            Thread.currentThread().interrupt()
            throw ReleaseArtifactProvenanceException("HTTPS exchange was interrupted", failure)
        } catch (failure: CancellationException) {
            throw ReleaseArtifactProvenanceException("HTTPS exchange was cancelled", failure)
        } catch (failure: ExecutionException) {
            val cause = failure.cause ?: failure
            if (cause is ReleaseArtifactProvenanceException) throw cause
            throw ReleaseArtifactProvenanceException("HTTPS exchange failed", cause)
        } catch (failure: IOException) {
            future.cancel(true)
            throw ReleaseArtifactProvenanceException("HTTPS exchange failed", failure)
        }
    }
}

internal class CancellingBodySubscriber : HttpResponse.BodySubscriber<HttpsBodyReceipt?> {
    private val body = CompletableFuture.completedFuture<HttpsBodyReceipt?>(null)

    override fun getBody(): CompletionStage<HttpsBodyReceipt?> = body

    override fun onSubscribe(subscription: Flow.Subscription) = subscription.cancel()

    override fun onNext(item: List<ByteBuffer>) = Unit

    override fun onError(throwable: Throwable) = Unit

    override fun onComplete() = Unit
}

internal class StreamingBodySubscriber(
    private val sink: WritableByteChannel,
    private val maximumBytes: Long,
) : HttpResponse.BodySubscriber<HttpsBodyReceipt?> {
    private val body = CompletableFuture<HttpsBodyReceipt?>()
    private val digest = MessageDigest.getInstance("SHA-256")
    private var subscription: Flow.Subscription? = null
    private var observed = 0L

    override fun getBody(): CompletionStage<HttpsBodyReceipt?> = body

    override fun onSubscribe(subscription: Flow.Subscription) {
        if (this.subscription != null) {
            subscription.cancel()
            return
        }
        this.subscription = subscription
        subscription.request(1)
    }

    override fun onNext(item: List<ByteBuffer>) {
        if (body.isDone) return
        try {
            item.forEach { source ->
                val count = source.remaining().toLong()
                observed = Math.addExact(observed, count)
                if (observed > maximumBytes) provenanceFail("HTTPS body exceeded its locked byte length")
                digest.update(source.asReadOnlyBuffer())
                while (source.hasRemaining()) {
                    if (sink.write(source) <= 0) provenanceFail("HTTPS staging output made no write progress")
                }
            }
            subscription?.request(1)
        } catch (failure: Throwable) {
            subscription?.cancel()
            body.completeExceptionally(failure)
        }
    }

    override fun onError(throwable: Throwable) {
        body.completeExceptionally(throwable)
    }

    override fun onComplete() {
        body.complete(HttpsBodyReceipt(observed, digest.digest().hex()))
    }
}

internal class ReleaseArtifactProvenanceException(message: String, cause: Throwable? = null) :
    IOException(message, cause)

internal fun provenanceFail(message: String): Nothing = throw ReleaseArtifactProvenanceException(message)

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}
