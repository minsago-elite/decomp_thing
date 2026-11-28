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

    /** The policy installed on the most recent listener. */
    private lateinit var installed: WebRedactionPolicy

    /** Records stream from the fixture's committed bytes, through the production delivery. */
    private val records = WebStructureRecordDelivery { _, runId, path, declared, consume, cancellation ->
        val file = fixture.files.getValue("reports/runs/$runId/$path")
        declared(file.bytes.size.toLong())
        var offset = 0
        while (offset < file.bytes.size) {
            cancellation()
            val count = minOf(8 * 1024, file.bytes.size - offset)
            consume(file.bytes.copyOfRange(offset, offset + count), count)
            offset += count
        }
        decompengine.repair.StableFileDigest(file.sha256, file.bytes.size.toLong(), file.identity, true)
    }

    /**
     * A listener over three revisions whose policy configures [credentials]: `run_1` records the concealed identities,
     * `run_2` has no module plan and `run_3` no model. Denials go through the production writer.
     */
    private fun <T> listener(credentials: Map<String, String> = mapOf("API_TOKEN" to literal), block: (String) -> T): T {
        val model = fixture.model(listOf(
            function(main, "main", 0x401000u, setOf(syntax, secret, other)), function(syntax, "shaped", 0x401010u),
            function(secret, "withheld", 0x401020u), function(other, "other", 0x401030u, setOf(main))))
        fixture.revision("run_1", "revision_1", model,
            ModulePlan(modules = listOf(fixture.planned("core", listOf(main, syntax)), fixture.planned(syntaxModule, listOf(other)),
                fixture.planned(secretModule, listOf(secret)))))
        fixture.revision("run_2", "revision_2", model, null)
        fixture.revision("run_3", "revision_3", null, null)
        val access = LocalWebAccess(LocalWebAccessConfiguration("http://127.0.0.1:8080"))
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
                val prefixes = mapOf("/unplanned/" to 2, "/unmodeled/" to 3)
                val prefix = prefixes.keys.firstOrNull(raw::startsWith)
                val number = prefix?.let(prefixes::getValue) ?: 1
                val (run, revision) = "run_$number" to "revision_$number"
                val path = prefix?.let { raw.removePrefix(it.dropLast(1)) } ?: raw
                if (path.startsWith("/records/")) {
                    records.send(exchange, job, pages.record(job, run, revision, path.removePrefix("/records/"), query))
                    return@createContext
                }
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
                access.sendDenied(exchange, failure)
            }
        }
        installed = WebRedactionPolicy.create(credentials, emptyList(), emptyList())
        WebRedactionPolicy.install(context, installed)
        http.start()
        try {
            return block("http://127.0.0.1:${http.address.port}")
        } finally {
            http.stop(0); worker.shutdownNow(); worker.awaitTermination(3, TimeUnit.SECONDS); access.close()
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
            assertEquals("STRUCTURE_IDENTITY_WITHHELD", Json.parseToJsonElement(refused.body()).jsonObject.getValue("error").jsonObject.text("code"))
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

    @Test fun `a module filter is a selector and a credential-shaped one echoes exactly`() = listener { origin ->
        val filtered = data(get(origin, "/functions?module=${encode(syntaxModule)}"), "functionInventory")
        assertEquals(syntaxModule, filtered.getValue("query").jsonObject.text("module"))
        val rows = filtered.getValue("items").jsonArray.map { it.jsonObject }
        assertEquals(listOf("other"), rows.map { it.text("name") })
        assertTrue(rows.all { it.text("moduleSelector") == syntaxModule })
    }

    /**
     * Status, headers and body without the per-request ID and the transport date, the only parts allowed to differ
     * between two requests.
     */
    private fun reply(origin: String, path: String): Triple<Int, Map<String, List<String>>, String> {
        val response = get(origin, path)
        val body = Json.parseToJsonElement(response.body()).jsonObject
        val headers = response.headers().map().filterKeys { it.lowercase() !in setOf("x-request-id", "date") }
        return Triple(response.statusCode(), headers.toSortedMap(String.CASE_INSENSITIVE_ORDER), JsonObject(body - "requestId").toString())
    }

    @Test fun `a concealed selector is denied exactly as an unknown one on every path`() = listener { origin ->
        val unknownFunction = "fn_unrecorded"
        val unknownModule = "mod_unrecorded"
        val paths = listOf(
            "inventory module filter" to { selector: String -> "/functions?module=${encode(selector)}" } to (secretModule to unknownModule),
            "inventory module filter without a plan" to { selector: String -> "/unplanned/functions?module=${encode(selector)}" } to (secretModule to unknownModule),
            "module detail" to { selector: String -> "/modules/${encode(selector)}" } to (secretModule to unknownModule),
            "module detail without a plan" to { selector: String -> "/unplanned/modules/${encode(selector)}" } to (secretModule to unknownModule),
            "entity detail" to { selector: String -> "/functions/${encode(selector)}" } to (secret to unknownFunction),
            "entity detail without a model" to { selector: String -> "/unmodeled/functions/${encode(selector)}" } to (secret to unknownFunction),
            "call graph focus" to { selector: String -> "/graph?view=calls&focus=${encode(selector)}" } to (secret to unknownFunction),
            "module graph focus" to { selector: String -> "/graph?view=modules&focus=${encode(selector)}" } to (secretModule to unknownModule),
            "unavailable module graph focus" to { selector: String -> "/unplanned/graph?view=modules&focus=${encode(selector)}" } to (secretModule to unknownModule),
            "unavailable call graph focus" to { selector: String -> "/unmodeled/graph?view=calls&focus=${encode(selector)}" } to (secret to unknownFunction),
        )
        for ((route, values) in paths) {
            val (name, path) = route
            val (concealed, unknown) = values
            val denied = reply(origin, path(concealed))
            assertEquals(reply(origin, path(unknown)), denied, name)
            assertFalse(denied.third.contains(literal), name)
        }
    }

    @Test fun `concealed and unknown selectors resolve through the published lookup without scanning the supplied value`() = listener { origin ->
        val scope = installed.selectorScope
        // A module-filtered inventory builds and charges only the module lookup, not the entity maps.
        assertEquals(200, get(origin, "/functions?module=core").statusCode())
        val index = fixture.cache.retained().single { it.reference.runId == "run_1" }
        assertTrue(index.retainsDerived("published-modules:$scope"))
        assertTrue(WebStructureKind.entries.none { index.retainsDerived("published-${it.route}:$scope") })
        // One successful entity read builds the function lookup; both lookups stay charged with the projection.
        data(get(origin, "/functions/$main"), "entityDetail")
        assertTrue(index.retainsDerived("published-functions:$scope"))
        val modules = index.publishedModules(installed)
        val functions = index.publishedEntities(WebStructureKind.FUNCTION, installed)
        for ((name, path) in listOf(
            "inventory module filter" to { selector: String -> "/functions?module=${encode(selector)}" },
            "module detail" to { selector: String -> "/modules/${encode(selector)}" },
            "entity detail" to { selector: String -> "/functions/${encode(selector)}" },
            "call graph focus" to { selector: String -> "/graph?view=calls&focus=${encode(selector)}" },
            "module graph focus" to { selector: String -> "/graph?view=modules&focus=${encode(selector)}" },
        )) {
            val entity = name.startsWith("entity") || name.startsWith("call")
            val (concealed, unknown) = if (entity) secret to "fn_unrecorded" else secretModule to "mod_unrecorded"
            val lookup = if (entity) functions else modules
            for (selector in listOf(concealed, unknown)) {
                val (scans, lookups) = installed.opaqueChecks.get() to lookup.lookups.get()
                assertEquals(404, get(origin, path(selector)).statusCode(), "$name $selector")
                // One map miss, and no configured-value scan of the supplied selector.
                assertEquals(lookups + 1, lookup.lookups.get(), "$name $selector")
                assertEquals(scans, installed.opaqueChecks.get(), "$name $selector")
            }
        }
    }

    @Test fun `record downloads are the exact committed evidence and are not subject to view-level redaction`() = listener { origin ->
        // The JSON views alias the concealed identities; the cited records are delivered as committed (#2040).
        val version = data(get(origin, "/functions"), "functionInventory").text("structureVersion")!!
        for ((record, path) in listOf("program-model" to "reports/program_model.json", "module-plan" to "reports/module_plan.json",
                "confidence" to "reports/confidence.json")) {
            val response = client.send(HttpRequest.newBuilder(URI("$origin/records/$record?structureVersion=$version"))
                .timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofByteArray())
            assertEquals(200, response.statusCode(), record)
            val committed = fixture.files.getValue("reports/runs/run_1/source-tree/$path")
            assertContentEquals(committed.bytes, response.body(), record)
            assertEquals(committed.sha256, response.headers().firstValue("X-Decomp-Content-SHA256").orElseThrow(), record)
        }
    }
}
