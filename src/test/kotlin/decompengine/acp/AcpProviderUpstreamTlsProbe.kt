package decompengine.acp

import java.lang.reflect.InvocationTargetException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.time.Duration
import javax.net.ssl.SSLSocket

/**
 * Child-JVM entry point for [AcpProviderUpstreamTlsTest]. The parent selects the trust roots only
 * through the standard `javax.net.ssl.trustStore` system properties, so production trust code runs
 * unchanged. The loopback fixture is not an admissible destination for `connect`, so the probe
 * reaches the private TLS layer by reflection; production callers have no such entry point.
 */
object AcpProviderUpstreamTlsProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        val port = args.single().toInt()
        val policy = AcpProviderTransportPolicy.fromOperatorPolicy(providerPolicyConfiguration()) as AcpProviderTransportPolicy.Approved
        val tls = AcpProviderUpstreamTls.platform(policy)
        val handshake = AcpProviderUpstreamTls::class.java
            .getDeclaredMethod("handshake", Socket::class.java, Duration::class.java)
            .apply { isAccessible = true }
        val plain = Socket(Proxy.NO_PROXY).apply { connect(InetSocketAddress(InetAddress.getLoopbackAddress(), port), 5_000) }
        try {
            (handshake.invoke(tls, plain, Duration.ofSeconds(15)) as SSLSocket).use { socket ->
                println(
                    "HANDSHAKE_OK protocol=${socket.session.protocol} " +
                        "identification=${socket.sslParameters.endpointIdentificationAlgorithm} byte=${socket.inputStream.read()}",
                )
            }
        } catch (invocation: InvocationTargetException) {
            val failure = invocation.targetException
            val messages = generateSequence(failure) { it.cause }.joinToString(" | ") { it.message.orEmpty() }
            println("HANDSHAKE_FAILED type=${failure.javaClass.name} closed=${plain.isClosed} causes=$messages")
        }
    }
}
