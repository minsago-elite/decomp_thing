package decompengine.oracle.provenance

import java.net.URI
import java.net.http.HttpHeaders
import java.nio.ByteBuffer
import java.nio.channels.WritableByteChannel
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CompletableFuture
import java.util.concurrent.ExecutionException
import java.util.concurrent.Flow
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BoundedHttpsDownloaderTest {
    @Test
    fun `manual redirect remains on trusted HTTPS hosts and streams exact bytes`() {
        val payload = "locked release artifact\n".toByteArray()
        val transport = FakeHttpsTransport(
            FakeResponse(
                302,
                mapOf(
                    "Location" to listOf(
                        "https://release-assets.githubusercontent.com/object?id=secret-token",
                    ),
                ),
            ),
            FakeResponse(
                200,
                mapOf(
                    "Content-Length" to listOf(payload.size.toString()),
                    "Content-Encoding" to listOf("identity"),
                ),
                payload,
            ),
        )
        val output = CollectingChannel()

        val receipt = BoundedHttpsDownloader(transport).download(request(payload), output)

        assertEquals(payload.toList(), output.bytes().toList())
        assertEquals(payload.size.toLong(), receipt.bytes)
        assertEquals(payload.sha256(), receipt.sha256)
        assertEquals("release-assets.githubusercontent.com", receipt.finalUri.host)
        assertEquals(2, transport.requests.size)
        assertTrue(transport.requests.all { it.userAgent == "decomp-thing-oracle-assets/1" })
    }

    @Test
    fun `redirect downgrade foreign host encoding and length violations fail closed`() {
        val payload = "bounded".toByteArray()
        val failures = listOf(
            FakeHttpsTransport(
                FakeResponse(302, mapOf("Location" to listOf("http://release-assets.githubusercontent.com/x"))),
            ),
            FakeHttpsTransport(
                FakeResponse(302, mapOf("Location" to listOf("https://example.com/x"))),
            ),
            FakeHttpsTransport(
                FakeResponse(302, mapOf("Location" to listOf("https://release-assets.githubusercontent.com:8443/x"))),
            ),
            FakeHttpsTransport(
                FakeResponse(200, mapOf("Content-Encoding" to listOf("gzip")), payload),
            ),
            FakeHttpsTransport(
                FakeResponse(200, mapOf("Content-Length" to listOf((payload.size + 1).toString())), payload),
            ),
            FakeHttpsTransport(
                FakeResponse(200, mapOf("Content-Length" to listOf(payload.size.toString(), payload.size.toString())), payload),
            ),
            FakeHttpsTransport(FakeResponse(503, emptyMap(), payload)),
        )

        failures.forEach { transport ->
            assertFailsWith<ReleaseArtifactProvenanceException> {
                BoundedHttpsDownloader(transport).download(request(payload), CollectingChannel())
            }
        }
    }

    @Test
    fun `initial URI rejects arbitrary ports while explicit HTTPS port is accepted`() {
        val payload = "port policy".toByteArray()
        val rejected = FakeHttpsTransport(FakeResponse(200, emptyMap(), payload))
        assertFailsWith<ReleaseArtifactProvenanceException> {
            BoundedHttpsDownloader(rejected).download(
                request(payload).copy(uri = URI.create("https://github.com:8443/start")),
                CollectingChannel(),
            )
        }
        assertEquals(0, rejected.requests.size)

        val accepted = FakeHttpsTransport(FakeResponse(200, emptyMap(), payload))
        val receipt = BoundedHttpsDownloader(accepted).download(
            request(payload).copy(uri = URI.create("https://github.com:443/start")),
            CollectingChannel(),
        )
        assertEquals(443, receipt.finalUri.port)
    }

    @Test
    fun `truncated oversized and redirect-cycle bodies fail without acceptance`() {
        val payload = "expected bytes".toByteArray()
        val truncated = FakeHttpsTransport(FakeResponse(200, emptyMap(), payload.dropLast(1).toByteArray()))
        val oversized = FakeHttpsTransport(FakeResponse(200, emptyMap(), payload + 0))
        val cycle = FakeHttpsTransport(
            FakeResponse(302, mapOf("Location" to listOf("https://github.com/again"))),
            FakeResponse(302, mapOf("Location" to listOf("https://github.com/start"))),
        )

        listOf(truncated, oversized).forEach { transport ->
            assertFailsWith<ReleaseArtifactProvenanceException> {
                BoundedHttpsDownloader(transport).download(request(payload), CollectingChannel())
            }
        }
        assertFailsWith<ReleaseArtifactProvenanceException> {
            BoundedHttpsDownloader(cycle).download(request(payload), CollectingChannel())
        }
    }

    @Test
    fun `redirect count has a hard upper bound`() {
        val responses = Array(11) { index ->
            FakeResponse(
                302,
                mapOf("Location" to listOf("https://github.com/redirect-${index + 1}")),
            )
        }
        assertFailsWith<ReleaseArtifactProvenanceException> {
            BoundedHttpsDownloader(FakeHttpsTransport(*responses))
                .download(request("unused".toByteArray()), CollectingChannel())
        }
    }

    @Test
    fun `response header count value and total byte bounds fail before handling`() {
        val payload = "bounded headers".toByteArray()
        val tooMany = (0..128).associate { index -> "X-Field-$index" to listOf("v") }
        val tooLargeValue = mapOf("X-Large" to listOf("v".repeat(8 * 1024 + 1)))
        val tooLargeTotal = (0 until 65).associate { index ->
            "X-Total-$index" to listOf("v".repeat(1024))
        }

        listOf(tooMany, tooLargeValue, tooLargeTotal).forEach { headers ->
            val transport = FakeHttpsTransport(FakeResponse(200, headers, payload))
            assertFailsWith<ReleaseArtifactProvenanceException> {
                BoundedHttpsDownloader(transport).download(request(payload), CollectingChannel())
            }
        }
    }

    @Test
    fun `production subscriber streams with backpressure and cancels overflow`() {
        val payload = "production subscriber".toByteArray()
        val output = CollectingChannel()
        val subscription = RecordingSubscription()
        val subscriber = StreamingBodySubscriber(output, payload.size.toLong())

        subscriber.onSubscribe(subscription)
        subscriber.onNext(listOf(ByteBuffer.wrap(payload.copyOfRange(0, 4)), ByteBuffer.wrap(payload.copyOfRange(4, payload.size))))
        subscriber.onComplete()
        val receipt = subscriber.getBody().toCompletableFuture().get(1, TimeUnit.SECONDS)

        assertEquals(2L, subscription.requests)
        assertEquals(payload.size.toLong(), receipt?.bytes)
        assertEquals(payload.sha256(), receipt?.sha256)
        assertEquals(payload.toList(), output.bytes().toList())

        val overflowSubscription = RecordingSubscription()
        val overflow = StreamingBodySubscriber(CollectingChannel(), payload.size.toLong() - 1)
        overflow.onSubscribe(overflowSubscription)
        overflow.onNext(listOf(ByteBuffer.wrap(payload)))
        val failure = assertFailsWith<ExecutionException> {
            overflow.getBody().toCompletableFuture().get(1, TimeUnit.SECONDS)
        }
        assertTrue(failure.cause is ReleaseArtifactProvenanceException)
        assertTrue(overflowSubscription.cancelled)
    }

    @Test
    fun `production redirect subscriber and exchange deadline cancel upstream work`() {
        val redirectSubscription = RecordingSubscription()
        CancellingBodySubscriber().onSubscribe(redirectSubscription)
        assertTrue(redirectSubscription.cancelled)

        val pending = CompletableFuture<java.net.http.HttpResponse<HttpsBodyReceipt?>>()
        val transport = JdkHttpsExchangeTransport(
            sender = HttpsAsyncSender { _, _ -> pending },
        )
        assertFailsWith<ReleaseArtifactProvenanceException> {
            transport.exchange(
                HttpsExchangeRequest(
                    uri = URI.create("https://github.com/timeout"),
                    userAgent = "decomp-thing-oracle-assets/1",
                    timeout = Duration.ofMillis(10),
                    maximumBodyBytes = 1,
                ),
                shouldStreamBody = { _, _ -> true },
                sink = CollectingChannel(),
            )
        }
        assertTrue(pending.isCancelled)
    }

    private fun request(payload: ByteArray) = HttpsDownloadRequest(
        uri = URI.create("https://github.com/start"),
        expectedBytes = payload.size.toLong(),
        expectedSha256 = payload.sha256(),
        userAgent = "decomp-thing-oracle-assets/1",
        timeout = Duration.ofSeconds(30),
        allowedHosts = setOf("github.com", "release-assets.githubusercontent.com"),
    )
}

private class RecordingSubscription : Flow.Subscription {
    var requests = 0L
    var cancelled = false

    override fun request(count: Long) {
        requests += count
    }

    override fun cancel() {
        cancelled = true
    }
}

internal data class FakeResponse(
    val status: Int,
    val headers: Map<String, List<String>>,
    val body: ByteArray = ByteArray(0),
)

internal class FakeHttpsTransport(vararg responses: FakeResponse) : HttpsExchangeTransport {
    private val responses = ArrayDeque(responses.toList())
    val requests = mutableListOf<HttpsExchangeRequest>()

    override fun exchange(
        request: HttpsExchangeRequest,
        shouldStreamBody: (Int, HttpHeaders) -> Boolean,
        sink: WritableByteChannel,
    ): HttpsExchangeResult {
        requests += request
        val response = responses.removeFirstOrNull()
            ?: throw ReleaseArtifactProvenanceException("unexpected fake HTTPS exchange")
        val headers = HttpHeaders.of(response.headers) { _, _ -> true }
        if (!shouldStreamBody(response.status, headers)) {
            return HttpsExchangeResult(response.status, headers, null)
        }
        if (response.body.size.toLong() > request.maximumBodyBytes) {
            throw ReleaseArtifactProvenanceException("HTTPS body exceeded its locked byte length")
        }
        val buffer = ByteBuffer.wrap(response.body)
        while (buffer.hasRemaining()) {
            if (sink.write(buffer) <= 0) throw ReleaseArtifactProvenanceException("fake sink made no progress")
        }
        return HttpsExchangeResult(
            response.status,
            headers,
            HttpsBodyReceipt(response.body.size.toLong(), response.body.sha256()),
        )
    }
}

internal class CollectingChannel : WritableByteChannel {
    private val output = ArrayList<Byte>()
    private var open = true

    override fun write(source: ByteBuffer): Int {
        check(open)
        val count = source.remaining()
        while (source.hasRemaining()) output += source.get()
        return count
    }

    override fun isOpen(): Boolean = open

    override fun close() {
        open = false
    }

    fun bytes(): ByteArray = output.toByteArray()
}

internal fun ByteArray.sha256(): String = MessageDigest.getInstance("SHA-256").digest(this).joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}
