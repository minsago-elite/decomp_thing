package decompengine.web

import com.sun.net.httpserver.HttpServer
import decompengine.project.ModulePlan
import decompengine.project.RecoveredFunction
import java.net.InetSocketAddress
import java.net.URI
import java.net.URLEncoder
import java.net.http.HttpClient
import java.net.http.HttpRequest
import java.net.http.HttpResponse
import java.time.Duration
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*
import kotlin.test.*

/**
 * Recorded identities through a real listener with its redaction policy installed: every structure view, echo,
 * selector and link projects one identity per record, so the final JSON pass never makes related fields disagree.
 */
class WebStructureIdentityHttpTest {
    private val literal = "Zq8LiteralCredential7xx"
    private val fixture = WebStructureFixture()
    private val main = "fn_main"
    private val syntax = "sk-abcdefghijklmnopqrst" // credential syntax, but not a configured credential
    private val secret = "fn_$literal" // contains the listener's configured credential
    private val other = "fn_other"
    private val syntaxModule = "sk-moduleabcdefghijklmnop"
    private val secretModule = "mod_$literal"
    private val moduleIdGrammar = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")

    private fun function(id: String, name: String, address: ULong, calls: Set<String> = emptySet()) =
        RecoveredFunction(id, name, address, "void $name(void)", null, calls = calls)

    private fun <T> listener(block: (String) -> T): T {
        fixture.revision("run_1", "revision_1", fixture.model(listOf(
            function(main, "main", 0x401000u, setOf(syntax, secret, other)), function(syntax, "shaped", 0x401010u),
            function(secret, "withheld", 0x401020u), function(other, "other", 0x401030u, setOf(main)))),
            ModulePlan(modules = listOf(fixture.planned("core", listOf(main, syntax)), fixture.planned(syntaxModule, listOf(other)),
                fixture.planned(secretModule, listOf(secret)))))
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val worker = Executors.newFixedThreadPool(2)
        http.executor = worker
        val context = http.createContext("/") { exchange ->
            val query = exchange.requestURI.rawQuery
            val policy = WebRedactionPolicy.of(exchange)
            val pages = fixture.pages
            val job = fixture.jobId
            try {
                val path = exchange.requestURI.rawPath
                val (kind, data) = when {
                    path == "/graph" -> "structureNeighborhood" to pages.neighborhood(job, "run_1", "revision_1", query, policy)
                    path == "/scorecard" -> "structureScorecard" to pages.scorecard("owner", job, "run_1", "revision_1", query, policy)
                    path == "/functions" -> "functionInventory" to pages.functions("owner", job, "run_1", "revision_1", query, policy)
                    path == "/modules" -> "moduleInventory" to pages.modules("owner", job, "run_1", "revision_1", query, policy)
                    path.startsWith("/modules/") -> "moduleDetail" to pages.module("owner", job, "run_1", "revision_1",
                        java.net.URLDecoder.decode(path.removePrefix("/modules/"), Charsets.UTF_8), query, policy)
                    else -> "entityDetail" to pages.entity(WebStructureKind.FUNCTION, job, "run_1", "revision_1",
                        java.net.URLDecoder.decode(path.removePrefix("/functions/"), Charsets.UTF_8), query, policy)
                }
                sendWebApiResponse(exchange, 200, kind, data)
            } catch (failure: WebAccessDenied) {
                val body = buildJsonObject { put("code", failure.code) }.toString().toByteArray()
                exchange.sendResponseHeaders(failure.status, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
        }
        WebRedactionPolicy.install(context, WebRedactionPolicy.create(mapOf("API_TOKEN" to literal), emptyList(), emptyList()))
        http.start()
        try {
            return block("http://127.0.0.1:${http.address.port}")
        } finally {
            http.stop(0); worker.shutdownNow(); worker.awaitTermination(3, TimeUnit.SECONDS)
        }
    }

    private val client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()
    private fun get(origin: String, path: String): HttpResponse<String> =
        client.send(HttpRequest.newBuilder(URI(origin + path)).timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofString())
    private fun encode(value: String) = URLEncoder.encode(value, Charsets.UTF_8)

    /** The published document: no configured credential and no placeholder where an identity belongs. */
    private fun data(response: HttpResponse<String>, kind: String): JsonObject {
        assertEquals(200, response.statusCode(), response.body())
        assertFalse(response.body().contains(literal), response.body())
        val body = Json.parseToJsonElement(response.body()).jsonObject
        assertEquals(kind, body.getValue("kind").jsonPrimitive.content)
        return body.getValue("data").jsonObject.also { fixture.assertContract(kind, it) }
    }

    private fun JsonObject.text(name: String) = get(name)?.takeIf { it != JsonNull }?.jsonPrimitive?.content
    private fun nodes(data: JsonObject) = data.getValue("neighborhood").jsonObject.getValue("nodes").jsonArray.map { it.jsonObject }

    /** An identity is exact (its own selector), or an alias without one; module IDs keep their wire grammar. */
    private fun assertIdentities(rows: List<JsonObject>) {
        for (row in rows) {
            row.text("entityId")?.let { id -> assertTrue(row.text("selector") == null || row.text("selector") == id, row.toString()) }
            row.text("moduleId")?.let { id ->
                assertTrue(moduleIdGrammar.matches(id), row.toString())
                val selector = if (row["kind"]?.jsonPrimitive?.content == "module") row.text("selector") else row.text("moduleSelector")
                assertTrue(selector == null || selector == id, row.toString())
            }
        }
    }

    @Test fun `a credential-shaped focus is echoed exactly as its center node identity and selector`() = listener { origin ->
        val graph = data(get(origin, "/graph?view=calls&focus=${encode(syntax)}&direction=both"), "structureNeighborhood")
        val center = nodes(graph).first()
        // The browser rejects a graph whose focus, center selector and center identity disagree.
        assertEquals(syntax, graph.getValue("query").jsonObject.text("focus"))
        assertEquals(syntax, center.text("selector")); assertEquals(syntax, center.text("entityId"))
        assertIdentities(nodes(graph))
        val modules = data(get(origin, "/graph?view=modules&focus=${encode(syntaxModule)}&depth=2"), "structureNeighborhood")
        assertEquals(syntaxModule, modules.getValue("query").jsonObject.text("focus"))
        assertEquals(syntaxModule, nodes(modules).first().text("selector"))
        assertIdentities(nodes(modules))
    }

    @Test fun `identities with a configured credential become aliases without selectors in every view`() = listener { origin ->
        val graph = data(get(origin, "/graph?view=calls&focus=$main&direction=outgoing"), "structureNeighborhood")
        val byName = nodes(graph).associateBy { it.text("name") }
        val withheld = byName.getValue("withheld")
        val alias = withheld.text("entityId")!!
        assertTrue(alias.matches(Regex("function:[0-9a-f]{64}")), alias)
        assertNull(withheld.text("selector"))
        assertTrue(withheld.text("moduleId")!!.matches(Regex("_withheld\\.[0-9a-f]{64}")))
        assertNull(withheld.text("moduleSelector"))
        assertEquals(syntax, byName.getValue("shaped").text("selector"))
        assertIdentities(nodes(graph))
        // The inventory, the caller's references and the module graph show the same aliases.
        val inventory = data(get(origin, "/functions"), "functionInventory").getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(alias, inventory.single { it.text("name") == "withheld" }.text("entityId"))
        assertIdentities(inventory)
        val detail = data(get(origin, "/functions/$main"), "entityDetail").getValue("entity").jsonObject
        val calls = detail.getValue("calls").jsonObject.getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(alias, calls.single { it.text("name") == "withheld" }.text("entityId"))
        assertIdentities(calls)
        val moduleGraph = data(get(origin, "/graph?view=modules&focus=core&depth=2"), "structureNeighborhood")
        assertEquals(withheld.text("moduleId"), nodes(moduleGraph).single { it.text("moduleId")!!.startsWith("_withheld.") }.text("moduleId"))
        assertIdentities(nodes(moduleGraph))
        val modules = data(get(origin, "/modules"), "moduleInventory").getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(setOf("core", syntaxModule, withheld.text("moduleId")), modules.map { it.text("moduleId") }.toSet())
        assertIdentities(modules.map { JsonObject(it + ("kind" to JsonPrimitive("module"))) })
        val scorecard = data(get(origin, "/scorecard"), "structureScorecard").getValue("scorecard").jsonObject
        val rows = scorecard.getValue("modules").jsonObject.getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(withheld.text("moduleId"), rows.single { it.text("selector") == null }.text("moduleId"))
        assertEquals(syntaxModule, rows.single { it.text("moduleId") == syntaxModule }.text("selector"))
    }

    @Test fun `selectors that the listener would rewrite select nothing`() = listener { origin ->
        for (path in listOf("/graph?view=calls&focus=${encode(secret)}", "/graph?view=modules&focus=${encode(secretModule)}",
                "/functions/${encode(secret)}", "/modules/${encode(secretModule)}")) {
            val response = get(origin, path)
            assertEquals(404, response.statusCode(), path)
            assertFalse(response.body().contains(literal))
        }
    }
}
