package decompengine.builtin.provider

import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocket

/** Only an inert test connector can be constructed in C4a. No configuration/environment escape.
 * Its callbacks may block; the reserved operation and independent stopper retain ownership.
 */
internal interface PlanHttpTestConnectorV1 {
    fun resolveLoopback(): InetAddress
    fun rawSocket(): Socket
    fun wrapForTest(raw: Socket): SSLSocket
    val loopbackPort: Int
}
internal class PlanHttpLoopbackTlsV1(private val port: Int, private val trustForTest: SSLContext) : PlanHttpTestConnectorV1 {
    init { planHttpRequire(port in 1..65535) }
    override val loopbackPort get() = port
    override fun resolveLoopback(): InetAddress = InetAddress.getLoopbackAddress()
    override fun rawSocket(): Socket = Socket(Proxy.NO_PROXY)
    override fun wrapForTest(raw: Socket): SSLSocket =
        trustForTest.socketFactory.createSocket(raw, ChatGptPlanSocketHttpV1.HOST, port, false) as SSLSocket
}

/** Disabled lower transport: intentionally no production constructor or Plan authority. */
internal class ChatGptPlanSocketHttpV1 private constructor() {
    companion object {
        const val HOST = "api.openai.com"
        const val PORT = 443
        const val MODELS_PATH = "/v1/models"
        const val RESPONSES_PATH = "/v1/responses"

        /** All inputs explicitly TEST-only. Context carries no credential/A/admission provenance. */
        fun startForTest(context: PlanHttpTestContextV1, endpoint: PlanHttpEndpointV1,
            syntheticBearer: String, entity: ByteArray?, connector: PlanHttpTestConnectorV1,
            gate: PlanHttpTestGateV1 = PlanHttpTestGateV1 {}): ChatGptPlanTransportLifetimeV1 =
            ChatGptPlanTransportLifetimeV1.reserve(context, gate) { owner, arena ->
                planHttpRequire(syntheticBearer.length in 1..4096 && syntheticBearer.all { it in 'a'..'z' || it in 'A'..'Z' || it in '0'..'9' || it in "-._~+/=" })
                planHttpRequire(if (endpoint == PlanHttpEndpointV1.MODELS) entity == null else entity != null)
                planHttpRequire((entity?.size ?: 0) <= context.requestLimit)
                // Reserve/check BEFORE copying; no asynchronous retention of caller-owned request.
                val body = entity?.copyOf()
                var at = 0
                fun ascii(value: String) {
                    planHttpRequire(value.length <= arena.outbound.size - at)
                    for (c in value) { planHttpRequire(c.code in 9..126); arena.outbound[at++] = c.code.toByte() }
                }
                ascii(if (endpoint == PlanHttpEndpointV1.MODELS) "GET $MODELS_PATH HTTP/1.1\r\n" else "POST $RESPONSES_PATH HTTP/1.1\r\n")
                ascii("Host: $HOST\r\nAuthorization: Bearer "); ascii(syntheticBearer)
                ascii("\r\nConnection: close\r\nAccept-Encoding: identity\r\n")
                if (body == null) ascii("Accept: application/json\r\n")
                else { ascii("Accept: text/event-stream\r\nContent-Type: application/json\r\nContent-Length: "); ascii(body.size.toString()); ascii("\r\n") }
                ascii("\r\n")
                val headerBytes = at
                val acquire: () -> Unit = {
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    val address = connector.resolveLoopback()
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    planHttpRequire(address.isLoopbackAddress)
                    val port = connector.loopbackPort
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    planHttpRequire(port in 1..65535)
                    val raw = connector.rawSocket()
                    owner.own(0, raw) // publish even if callback returned after stop
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    raw.connect(InetSocketAddress(address, port), owner.timeoutMillis())
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    val tls = connector.wrapForTest(raw)
                    owner.own(1, tls) // raw retained until both close returns
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    tls.useClientMode = true
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    tls.enabledProtocols = arrayOf("TLSv1.3", "TLSv1.2")
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    val parameters = tls.sslParameters
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    parameters.endpointIdentificationAlgorithm = "HTTPS"
                    parameters.serverNames = listOf(SNIHostName(HOST))
                    parameters.applicationProtocols = arrayOf("http/1.1")
                    tls.sslParameters = parameters
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    tls.soTimeout = owner.timeoutMillis()
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    tls.startHandshake()
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    val negotiated = tls.applicationProtocol
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    planHttpRequire(negotiated.isNullOrEmpty() || negotiated == "http/1.1")
                    val input = tls.inputStream
                    owner.action(PlanHttpActionV1.ACQUIRE)
                    val output = tls.outputStream
                    owner.action(PlanHttpActionV1.HEADER_WRITE)
                    owner.headerOffered()
                    output.write(arena.outbound, 0, headerBytes)
                    // Void write throws => prefix unknown; only whole returned slices are counted.
                    if (body != null) {
                        var offset = 0
                        while (offset < body.size) {
                            val n = minOf(8192, body.size - offset)
                            owner.action(PlanHttpActionV1.BODY_WRITE)
                            owner.bodyOffered(n)
                            output.write(body, offset, n)
                            owner.bodyReturned(n)
                            offset += n
                        }
                    }
                    owner.action(PlanHttpActionV1.READ)
                    owner.install(ChatGptPlanHttp1FramingV1(input, arena, endpoint, context.entityLimit,
                        beforeRead = {
                            owner.action(PlanHttpActionV1.READ)
                            tls.soTimeout = owner.timeoutMillis()
                            // Socket setter is a foreign seam too; recheck after it returns.
                            owner.action(PlanHttpActionV1.READ)
                        }, observedEntity = owner::observed, observedFraming = owner::framed))
                }
                acquire
            }
    }
}
