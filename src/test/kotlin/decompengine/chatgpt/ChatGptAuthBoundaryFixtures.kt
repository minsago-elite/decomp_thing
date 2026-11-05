package decompengine.chatgpt

import java.net.http.HttpResponse
import java.nio.ByteBuffer
import java.util.concurrent.Flow

/** Test-only helpers for exercising private boundaries on the actual compiled sources. */
internal object ChatGptAuthBoundaryFixtures {
    fun privateForm(fields: List<Pair<String, String>>, operation: ChatGptStoreOperation, deadline: ChatGptDeadline): java.net.http.HttpRequest.BodyPublisher {
        val owner = Class.forName("decompengine.chatgpt.ChatGptAuthTransportKt")
        val method = owner.getDeclaredMethod("encodedForm", List::class.java, ChatGptStoreOperation::class.java, ChatGptDeadline::class.java)
            .apply { isAccessible = true }
        return try { method.invoke(null, fields, operation, deadline) as java.net.http.HttpRequest.BodyPublisher }
        catch (e: java.lang.reflect.InvocationTargetException) { throw (e.cause ?: e) }
    }

    data class CopyObservation(val positionsBefore: List<Int>, val positionsAfter: List<Int>) {
        val advancedBytes: Int get() = positionsAfter.zip(positionsBefore).sumOf { (after, before) -> after - before }
    }

    fun observe(buffers: List<ByteBuffer>, body: () -> Unit): CopyObservation {
        val before = buffers.map(ByteBuffer::position)
        body()
        return CopyObservation(before, buffers.map(ByteBuffer::position))
    }

    fun responseInfo(status: Int, headers: Map<String, List<String>>) = object : HttpResponse.ResponseInfo {
        override fun statusCode() = status
        override fun headers() = java.net.http.HttpHeaders.of(headers) { _, _ -> true }
        override fun version() = java.net.http.HttpClient.Version.HTTP_1_1
    }

    fun collect(publisher: java.net.http.HttpRequest.BodyPublisher): ByteArray {
        val output = java.io.ByteArrayOutputStream()
        var error: Throwable? = null
        publisher.subscribe(object : Flow.Subscriber<ByteBuffer> {
            override fun onSubscribe(subscription: Flow.Subscription) = subscription.request(1)
            override fun onNext(item: ByteBuffer) { while (item.hasRemaining()) output.write(item.get().toInt()) }
            override fun onError(value: Throwable) { error = value }
            override fun onComplete() {}
        })
        check(error == null) { "body publisher failed" }
        return output.toByteArray()
    }

    fun safeString(value: Any?): String = when (value) {
        null -> "null"
        is Throwable -> buildString {
            append(value.toString())
            append(value.message ?: "")
            value.cause?.let { append(it.toString()); append(it.message ?: "") }
            value.suppressed.forEach { append(it.toString()); append(it.message ?: "") }
        }
        else -> value.toString()
    }
}
