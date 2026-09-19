package decompengine.web

import java.net.http.HttpResponse
import kotlin.test.assertTrue

/** Production-local browser authority must not be widened by a CORS response. */
internal fun assertNoWebCors(response: HttpResponse<*>) {
    assertTrue(response.headers().map().keys.none { it.startsWith("access-control-", ignoreCase = true) },
        "Local web responses must not grant CORS authority")
}
