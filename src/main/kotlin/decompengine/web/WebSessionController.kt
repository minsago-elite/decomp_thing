package decompengine.web

import com.sun.net.httpserver.HttpExchange
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import java.util.UUID

/** Session exchange/logout shared by browser presentations without an asset or job dependency.
 * The owning router selects the exact route and renders typed access failures.
 */
internal class WebSessionController(private val access: LocalWebAccess) {
    fun handle(exchange: HttpExchange) {
        access.authorize(exchange, WebEndpointPolicy.transport(setOf("POST", "DELETE")))
        requireNoWebApiQuery(exchange)
        requireJsonAccept(exchange)
        when (exchange.requestMethod) {
            "POST" -> {
                val credentials = access.establishSession(exchange)
                exchange.responseHeaders.add("Set-Cookie", checkNotNull(credentials.setCookie))
                sendWebApiResponse(exchange, 200, "session", buildJsonObject {
                    put("csrfToken", credentials.csrfToken)
                    put("expiresAt", credentials.session.expiresAt.toString())
                })
            }
            "DELETE" -> {
                val cookie = access.logout(exchange)
                exchange.responseHeaders.add("Set-Cookie", cookie)
                webApiHeaders(exchange, UUID.randomUUID().toString())
                exchange.sendResponseHeaders(204, -1)
                exchange.close()
            }
        }
    }
}
