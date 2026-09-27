package decompengine.web

import com.sun.net.httpserver.HttpExchange
import java.security.MessageDigest
import java.util.Base64

/**
 * Browser response policy shared by the legacy adapter and the embedded SPA.
 *
 * Application documents may load only reviewed same-origin resources. Other
 * response bodies are inert when navigated directly, including JSON, source,
 * generated reports, downloads, redirects, and static subresources.
 */
internal const val WEB_APPLICATION_CONTENT_SECURITY_POLICY =
    "default-src 'none'; script-src 'self'; style-src 'self'; " +
        "img-src 'self' data:; font-src 'self'; connect-src 'self'; worker-src 'self'; " +
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"

internal const val WEB_INERT_CONTENT_SECURITY_POLICY =
    "sandbox; default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'"

/** HTML plus the renderer-owned inline script inventory used to build its CSP. */
internal data class WebApplicationDocument(
    val body: String,
    val trustedInlineScripts: List<String>,
)

/**
 * Legacy pages retain small trusted inline adapters during migration. Authorize
 * only the script bodies supplied by the renderer's explicit inventory. Never
 * derive this list from the final HTML: doing so could authorize an injected
 * script after an escaping regression.
 */
internal fun webApplicationContentSecurityPolicy(trustedInlineScripts: Iterable<String>): String {
    val hashes = trustedInlineScripts.map { script ->
        val digest = MessageDigest.getInstance("SHA-256")
            .digest(script.toByteArray(Charsets.UTF_8))
        "'sha256-${Base64.getEncoder().encodeToString(digest)}'"
    }.distinct().toList()
    if (hashes.isEmpty()) return WEB_APPLICATION_CONTENT_SECURITY_POLICY
    return WEB_APPLICATION_CONTENT_SECURITY_POLICY.replace(
        "script-src 'self'",
        "script-src 'self' ${hashes.joinToString(" ")}",
    )
}

internal fun HttpExchange.applyWebSecurityHeaders(
    contentSecurityPolicy: String = WEB_INERT_CONTENT_SECURITY_POLICY,
) {
    responseHeaders.set("X-Content-Type-Options", "nosniff")
    responseHeaders.set("Referrer-Policy", "no-referrer")
    responseHeaders.set("X-Frame-Options", "DENY")
    responseHeaders.set("Content-Security-Policy", contentSecurityPolicy)
}
