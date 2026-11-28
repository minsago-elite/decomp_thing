package decompengine.acp

import java.io.IOException
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.Socket
import java.security.KeyStore
import java.time.Duration
import javax.net.ssl.SNIHostName
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLParameters
import javax.net.ssl.SSLSocket
import javax.net.ssl.TrustManagerFactory

/** A destination or TLS check refused the upstream connection before any provider bytes were sent. */
internal class AcpProviderUpstreamRefusedException(val reason: AcpProviderRouteRefusal) : IOException(reason.name)

/**
 * The only upstream TLS client for an approved provider policy. Its [SSLContext] uses a PKIX trust
 * manager initialized from the JVM platform trust store (the standard `javax.net.ssl.trustStore`
 * configuration), with no caller-supplied trust store, trust manager, key manager or hostname
 * verifier. Every socket verifies the policy hostname (HTTPS endpoint identification), sends it as
 * SNI, and negotiates only TLS 1.3 or 1.2.
 *
 * [connect] is the only entry point. The #959 broker passes one numeric address that the #1510
 * resolver returned; [connect] re-applies [AcpProviderRouting.destinationRefusal] and connects
 * directly. The policy hostname, never the address, remains the TLS identity.
 */
internal class AcpProviderUpstreamTls private constructor(private val policy: AcpProviderTransportPolicy.Approved) {
    private val context: SSLContext

    init {
        check(policy.tlsVerification == AcpProviderTlsVerification.PLATFORM_TRUST_HOSTNAME_VERIFIED) {
            "unsupported provider TLS verification mode"
        }
        val trust = TrustManagerFactory.getInstance("PKIX").apply { init(null as KeyStore?) }
        context = SSLContext.getInstance("TLS").apply { init(null, trust.trustManagers, null) }
    }

    /** Opens a direct connection to an admitted address and completes the verified TLS handshake. */
    fun connect(address: InetAddress, connectTimeout: Duration, handshakeTimeout: Duration): SSLSocket {
        AcpProviderRouting.destinationRefusal(policy, listOf(address))?.let { throw AcpProviderUpstreamRefusedException(it) }
        val socket = Socket(Proxy.NO_PROXY)
        try {
            socket.connect(InetSocketAddress(address, UPSTREAM_PORT), positiveMillis(connectTimeout))
            return handshake(socket, handshakeTimeout)
        } catch (failure: Throwable) {
            socket.close()
            throw failure
        }
    }

    /** Layers verified TLS over the socket [connect] opened. The socket is closed on failure. */
    private fun handshake(connected: Socket, timeout: Duration): SSLSocket {
        try {
            require(connected.isConnected && !connected.isClosed) { "provider upstream socket is not connected" }
            connected.soTimeout = positiveMillis(timeout)
            val socket = context.socketFactory.createSocket(connected, policy.endpoint.host, UPSTREAM_PORT, true) as SSLSocket
            try {
                socket.useClientMode = true
                socket.sslParameters = upstreamParameters()
                socket.startHandshake()
                check(socket.session.protocol in PROVIDER_TLS_PROTOCOLS) { "provider TLS negotiated an unsupported protocol" }
                return socket
            } catch (failure: Throwable) {
                socket.close()
                throw failure
            }
        } catch (failure: Throwable) {
            connected.close()
            throw failure
        }
    }

    private fun upstreamParameters(): SSLParameters {
        val defaults = context.defaultSSLParameters
        val protocols = defaults.protocols.filter { it in PROVIDER_TLS_PROTOCOLS }
        check(protocols.isNotEmpty()) { "provider TLS requires TLSv1.3 or TLSv1.2" }
        return SSLParameters(defaults.cipherSuites, protocols.toTypedArray()).apply {
            endpointIdentificationAlgorithm = "HTTPS"
            serverNames = listOf(SNIHostName(policy.endpoint.host))
        }
    }

    companion object {
        /** The JVM platform PKIX trust store, nothing else. */
        fun platform(policy: AcpProviderTransportPolicy.Approved): AcpProviderUpstreamTls = AcpProviderUpstreamTls(policy)
    }
}

private const val UPSTREAM_PORT = 443
private val PROVIDER_TLS_PROTOCOLS = setOf("TLSv1.3", "TLSv1.2")

private fun positiveMillis(duration: Duration): Int {
    require(duration >= Duration.ofMillis(1) && duration <= Duration.ofMinutes(30)) { "provider upstream timeout is outside the bound" }
    return duration.toMillis().toInt()
}
