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

    /** A listener over two revisions (`run_2` has no module plan) whose policy configures [credentials]. */
    private fun <T> listener(credentials: Map<String, String> = mapOf("API_TOKEN" to literal), block: (String) -> T): T {
        val model = fixture.model(listOf(
            function(main, "main", 0x401000u, setOf(syntax, secret, other)), function(syntax, "shaped", 0x401010u),
            function(secret, "withheld", 0x401020u), function(other, "other", 0x401030u, setOf(main))))
        fixture.revision("run_1", "revision_1", model,
            ModulePlan(modules = listOf(fixture.planned("core", listOf(main, syntax)), fixture.planned(syntaxModule, listOf(other)),
                fixture.planned(secretModule, listOf(secret)))))
        fixture.revision("run_2", "revision_2", model, null)
        val http = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        val worker = Executors.newFixedThreadPool(2)
        http.executor = worker
        val context = http.createContext("/") { exchange ->
            val query = exchange.requestURI.rawQuery
            val policy = WebRedactionPolicy.of(exchange)
            val pages = fixture.pages
            val job = fixture.jobId
            try {
                val raw = exchange.requestURI.rawPath
                val unplanned = raw.startsWith("/unplanned/")
                val (run, revision) = if (unplanned) "run_2" to "revision_2" else "run_1" to "revision_1"
                val path = raw.removePrefix("/unplanned")
                val (kind, data) = when {
                    path == "/graph" -> "structureNeighborhood" to pages.neighborhood(job, run, revision, query, policy)
                    path == "/scorecard" -> "structureScorecard" to pages.scorecard("owner", job, run, revision, query, policy)
                    path == "/functions" -> "functionInventory" to pages.functions("owner", job, run, revision, query, policy)
                    path == "/modules" -> "moduleInventory" to pages.modules("owner", job, run, revision, query, policy)
                    path.startsWith("/modules/") -> "moduleDetail" to pages.module("owner", job, run, revision,
                        java.net.URLDecoder.decode(path.removePrefix("/modules/"), Charsets.UTF_8), query, policy)
                    else -> "entityDetail" to pages.entity(WebStructureKind.FUNCTION, job, run, revision,
                        java.net.URLDecoder.decode(path.removePrefix("/functions/"), Charsets.UTF_8), query, policy)
                }
                sendWebApiResponse(exchange, 200, kind, data)
            } catch (failure: WebAccessDenied) {
                val body = buildJsonObject { put("code", failure.code) }.toString().toByteArray()
                exchange.sendResponseHeaders(failure.status, body.size.toLong())
                exchange.responseBody.use { it.write(body) }
            }
        }
        WebRedactionPolicy.install(context, WebRedactionPolicy.create(credentials, emptyList(), emptyList()))
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

    private val moduleAlias = Regex("_withheld\\.[0-9a-f]{64}")
    private val functionAlias = Regex("function:[0-9a-f]{64}")
    private fun aliases(origin: String): Pair<String, String> {
        val modules = data(get(origin, "/modules"), "moduleInventory").getValue("items").jsonArray.map { it.jsonObject }
        val functions = data(get(origin, "/functions"), "functionInventory").getValue("items").jsonArray.map { it.jsonObject }
        return modules.single { it.text("selector") == null }.text("moduleId")!! to
            functions.single { it.text("name") == "withheld" }.text("entityId")!!
    }

    @Test fun `aliases a configured value would overlap are re-derived, and refused when no safe alias exists`() {
        val (module, entity) = listener { origin -> aliases(origin) }
        // Configured values that overlap the first-round aliases: the final pass would mark both, and the module marker
        // would also break the module-ID grammar.
        val overlaps = mapOf("API_TOKEN" to literal, "AUTH_TOKEN" to module.take(20), "SECRET_VALUE" to entity.take(20))
        listener(overlaps) { origin ->
            val (rederivedModule, rederivedEntity) = aliases(origin)
            assertNotEquals(module, rederivedModule); assertTrue(moduleAlias.matches(rederivedModule), rederivedModule)
            assertNotEquals(entity, rederivedEntity); assertTrue(functionAlias.matches(rederivedEntity), rederivedEntity)
            for (path in listOf("/modules", "/functions", "/graph?view=calls&focus=$main", "/graph?view=modules&focus=core&depth=2", "/scorecard")) {
                val response = get(origin, path)
                assertEquals(200, response.statusCode(), path)
                // Prose such as source paths is redacted as text; identities are never replaced by the marker.
                val identities = identityValues(Json.parseToJsonElement(response.body()))
                assertTrue(identities.isNotEmpty() && identities.none { it.contains(WebRedactionPolicy.SECRET_MARK) }, "$path: $identities")
                assertTrue(identities.none { it.contains(module.take(20)) || it.contains(entity.take(20)) }, path)
            }
            // Every view states the same re-derived identity.
            val graph = data(get(origin, "/graph?view=calls&focus=$main&direction=outgoing"), "structureNeighborhood")
            assertEquals(rederivedEntity, nodes(graph).single { it.text("name") == "withheld" }.text("entityId"))
            assertEquals(rederivedModule, nodes(graph).single { it.text("name") == "withheld" }.text("moduleId"))
        }
        // A configured value inside the alias prefix itself leaves no safe module alias: the projection fails explicitly.
        listener(mapOf("API_TOKEN" to literal, "AUTH_TOKEN" to "_withheld.")) { origin ->
            val refused = get(origin, "/modules")
            assertEquals(409, refused.statusCode())
            assertEquals("STRUCTURE_IDENTITY_WITHHELD", Json.parseToJsonElement(refused.body()).jsonObject.text("code"))
        }
    }

    private fun identityValues(element: JsonElement): List<String> = when (element) {
        is JsonObject -> element.flatMap { (key, value) ->
            if (key in setOf("entityId", "moduleId", "selector", "moduleSelector", "focus") && value is JsonPrimitive && value.isString)
                listOf(value.content) else identityValues(value)
        }
        is JsonArray -> element.flatMap(::identityValues)
        else -> emptyList()
    }

    @Test fun `a module filter is a selector - concealed it is not found, credential-shaped it echoes exactly`() = listener { origin ->
        assertEquals(404, get(origin, "/functions?module=${encode(secretModule)}").statusCode())
        val filtered = data(get(origin, "/functions?module=${encode(syntaxModule)}"), "functionInventory")
        assertEquals(syntaxModule, filtered.getValue("query").jsonObject.text("module"))
        val rows = filtered.getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(listOf("other"), rows.map { it.text("name") })
        assertTrue(rows.all { it.text("moduleSelector") == syntaxModule })
    }

    @Test fun `an unavailable graph checks its focus before echoing it`() = listener { origin ->
        val concealed = get(origin, "/unplanned/graph?view=modules&focus=${encode(secretModule)}")
        assertEquals(404, concealed.statusCode()); assertFalse(concealed.body().contains(literal))
        val unavailable = data(get(origin, "/unplanned/graph?view=modules&focus=${encode(syntaxModule)}"), "structureNeighborhood")
        assertNotEquals("available", unavailable.text("graphState"))
        assertEquals(JsonNull, unavailable.getValue("neighborhood"))
        assertEquals(syntaxModule, unavailable.getValue("query").jsonObject.text("focus"))
    }
}
