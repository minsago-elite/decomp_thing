package decompengine.git

import com.sun.net.httpserver.HttpsConfigurator
import com.sun.net.httpserver.HttpsServer
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path
import java.security.KeyStore
import java.util.Base64
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import javax.net.ssl.KeyManagerFactory
import javax.net.ssl.SSLContext

/**
 * Loopback HTTPS Git remote for tests (#586, #593): `git http-backend` behind a JDK HTTPS server
 * with a throwaway self-signed certificate. It can require Basic credentials and can stall
 * responses, so certificate verification, authentication, timeouts and cancellation are tested
 * without any network. Nothing here is used by production code.
 */
internal class GitHttpsFixture(private val projectRoot: Path, private val work: Path,
    private val username: String? = null, private val password: String? = null,
    private val authenticateWritesOnly: Boolean = false) : AutoCloseable {
    @Volatile var stall: CountDownLatch? = null
    /** Pause only after sending actual pack bytes, not at discovery or before a transfer starts. */
    class PartialUpload {
        val started = CountDownLatch(1)
        val release = CountDownLatch(1)
    }
    @Volatile var partialUpload: PartialUpload? = null
    @Volatile var requests = 0
        private set
    /** PEM certificate that a client must trust to verify this server. */
    val certificate: Path = work.resolve("fixture-ca.pem")
    private val server: HttpsServer
    private val git = (GitRuntime.detect() as GitAvailability.Available).executable

    init {
        Files.createDirectories(work)
        val store = work.resolve("fixture.p12")
        val keytool = Path.of(System.getProperty("java.home"), "bin", "keytool").toString()
        fun run(vararg args: String) {
            val process = ProcessBuilder(keytool, *args).redirectErrorStream(true).start()
            val output = process.inputStream.readBytes().toString(Charsets.UTF_8)
            check(process.waitFor(60, TimeUnit.SECONDS) && process.exitValue() == 0) { "keytool failed: $output" }
        }
        run("-genkeypair", "-alias", "fixture", "-keyalg", "EC", "-groupname", "secp256r1", "-dname", "CN=localhost",
            "-ext", "SAN=dns:localhost,ip:127.0.0.1", "-ext", "BC=ca:true", "-validity", "2", "-keystore", store.toString(),
            "-storetype", "PKCS12", "-storepass", "fixture-pass", "-keypass", "fixture-pass")
        run("-exportcert", "-rfc", "-alias", "fixture", "-keystore", store.toString(), "-storepass", "fixture-pass", "-file", certificate.toString())
        val keys = KeyStore.getInstance("PKCS12").apply { Files.newInputStream(store).use { load(it, "fixture-pass".toCharArray()) } }
        val managers = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm()).apply { init(keys, "fixture-pass".toCharArray()) }
        val context = SSLContext.getInstance("TLS").apply { init(managers.keyManagers, null, null) }
        server = HttpsServer.create(InetSocketAddress("127.0.0.1", 0), 16)
        server.httpsConfigurator = HttpsConfigurator(context)
        server.executor = Executors.newCachedThreadPool()
        server.createContext("/") { exchange ->
            requests++
            try {
                stall?.await(60, TimeUnit.SECONDS)
                val receiving = exchange.requestURI.path.endsWith("/git-receive-pack") ||
                    exchange.requestURI.rawQuery == "service=git-receive-pack"
                if (username != null && (!authenticateWritesOnly || receiving)) {
                    val expected = "Basic " + Base64.getEncoder().encodeToString("$username:$password".toByteArray())
                    if (exchange.requestHeaders.getFirst("Authorization") != expected) {
                        exchange.responseHeaders.set("WWW-Authenticate", "Basic realm=\"fixture\"")
                        exchange.sendResponseHeaders(401, -1)
                        return@createContext
                    }
                }
                val body = exchange.requestBody.readBytes()
                val process = ProcessBuilder(git.toString(), "http-backend").also { builder ->
                    builder.environment().clear()
                    builder.environment().putAll(mapOf(
                        "PATH" to "/usr/bin:/bin", "GIT_PROJECT_ROOT" to projectRoot.toString(), "GIT_HTTP_EXPORT_ALL" to "1",
                        "GIT_CONFIG_NOSYSTEM" to "1", "GIT_CONFIG_GLOBAL" to "/dev/null", "HOME" to work.toString(),
                        "REQUEST_METHOD" to exchange.requestMethod, "PATH_INFO" to exchange.requestURI.rawPath,
                        "QUERY_STRING" to (exchange.requestURI.rawQuery ?: ""), "CONTENT_TYPE" to (exchange.requestHeaders.getFirst("Content-Type") ?: ""),
                        "CONTENT_LENGTH" to body.size.toString(), "REMOTE_USER" to (username ?: "anonymous"), "REMOTE_ADDR" to "127.0.0.1",
                        "GIT_PROTOCOL" to (exchange.requestHeaders.getFirst("Git-Protocol") ?: ""),
                        "HTTP_CONTENT_ENCODING" to (exchange.requestHeaders.getFirst("Content-Encoding") ?: ""),
                    ))
                }.start()
                process.outputStream.use { it.write(body) }
                val output = process.inputStream.readBytes()
                process.waitFor(60, TimeUnit.SECONDS)
                val split = indexOf(output, "\r\n\r\n".toByteArray()).takeIf { it >= 0 }?.let { it to 4 }
                    ?: indexOf(output, "\n\n".toByteArray()).let { it to 2 }
                val headers = output.copyOfRange(0, split.first).toString(Charsets.ISO_8859_1).lines().filter { it.isNotBlank() }
                val payload = output.copyOfRange(split.first + split.second, output.size)
                var status = 200
                for (header in headers) {
                    val name = header.substringBefore(':').trim(); val value = header.substringAfter(':').trim()
                    if (name.equals("Status", true)) status = value.substringBefore(' ').toInt() else exchange.responseHeaders.add(name, value)
                }
                exchange.sendResponseHeaders(status, if (payload.isEmpty()) -1 else payload.size.toLong())
                if (payload.isNotEmpty()) exchange.responseBody.use { response ->
                    // Protocol v2 also POSTs ls-refs to this endpoint; only pause a pack response.
                    val pack = indexOf(payload, "PACK".toByteArray())
                    val pause = partialUpload.takeIf {
                        exchange.requestMethod == "POST" && exchange.requestURI.path.endsWith("/git-upload-pack") && pack >= 0
                    }
                    if (pause == null) response.write(payload)
                    else {
                        val cut = payload.size / 2
                        check(pack + 12 < cut) { "Expected a populated pack before the transfer pause" }
                        response.write(payload, 0, cut)
                        response.flush()
                        pause.started.countDown()
                        check(pause.release.await(60, TimeUnit.SECONDS)) { "Partial upload was not released" }
                        response.write(payload, cut, payload.size - cut)
                    }
                }
            } catch (_: Exception) {
                try { exchange.sendResponseHeaders(500, -1) } catch (_: Exception) { }
            } finally { exchange.close() }
        }
        server.start()
    }

    val port: Int get() = server.address.port
    fun url(repository: String) = "https://localhost:$port/$repository"

    private fun indexOf(bytes: ByteArray, needle: ByteArray): Int {
        outer@ for (index in 0..bytes.size - needle.size) {
            for (offset in needle.indices) if (bytes[index + offset] != needle[offset]) continue@outer
            return index
        }
        return -1
    }

    override fun close() {
        stall?.countDown()
        partialUpload?.release?.countDown()
        server.stop(0)
        (server.executor as java.util.concurrent.ExecutorService).shutdownNow()
    }

}
