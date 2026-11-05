package decompengine.chatgpt.operator

import decompengine.builtin.LocalBudgetV1
import kotlinx.serialization.json.*
import java.time.Instant
import java.util.UUID
import kotlin.test.*

class ChatGptPlanOperatorCliV1Test {
    private val names = listOf("inputUnits","outputUnits","maxRequests","maxToolActions","callsPerResponse","requestBytes","responseBytes","eventBytes","contextBytes","historyReserveBytes","continuationBytes","toolResultBytes","receivedBytesTotal","displayedBytesTotal","evidenceBytes","privateDiskBytes","maxIdenticalAction","traceRecords","wallClockMs","overallTimeoutMs","connectTimeoutMs","requestTimeoutMs","idleTimeoutMs","maxRetries")
    private fun limits(values: Map<String, String> = ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap()) = JsonObject(values.mapValues { JsonPrimitive(it.value) }).toString().toByteArray()
    private fun ChatGptLocalLimitsV1.asMap(): Map<String, String> = listOf(inputUnits,outputUnits,maxRequests,maxToolActions,callsPerResponse,requestBytes,responseBytes,eventBytes,contextBytes,historyReserveBytes,continuationBytes,toolResultBytes,receivedBytesTotal,displayedBytesTotal,evidenceBytes,privateDiskBytes,maxIdenticalAction,traceRecords,wallClockMs,overallTimeoutMs,connectTimeoutMs,requestTimeoutMs,idleTimeoutMs,maxRetries).map { it.toString() }.let { names.zip(it).toMap() }

    @Test fun `all chatgpt command family actions parse and preserve explicit choices`() {
        assertEquals(ChatGptPlanCliActionV1.SignIn(false, null), ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "sign-in")))
        assertEquals(ChatGptPlanCliActionV1.SignIn(true, null), ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "sign-in", "--open")))
        assertEquals(ChatGptPlanCliActionV1.SignIn(true, "00000000-0000-0000-0000-000000000001"), ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "sign-in", "--open", "--account", "00000000-0000-0000-0000-000000000001")))
        assertEquals(ChatGptPlanCliActionV1.Accounts, ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "accounts")))
        assertEquals(ChatGptPlanCliActionV1.Status, ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "status")))
        assertEquals(ChatGptPlanCliActionV1.Doctor, ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "doctor")))
        assertEquals(ChatGptPlanCliActionV1.Models(null), ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "models")))
        assertEquals(ChatGptPlanCliActionV1.Select("00000000-0000-0000-0000-000000000001"), ChatGptPlanOperatorCliV1.parse(listOf("chatgpt", "select", "--account", "00000000-0000-0000-0000-000000000001")))
    }

    @Test fun `plan reconstruct requires every explicit election flag and refuses extras`() {
        val id = "00000000-0000-0000-0000-000000000001"
        val base = listOf("reconstruct", "a.out", "--output", "out", "--harness", "chatgpt-plan", "--account", id,
            "--model", "returned/model", "--budget-policy", "local-acceptance-v1", "--local-limits", "limits.json", "--accept-local-limits")
        val parsed = ChatGptPlanOperatorCliV1.parse(base, limits()) as ChatGptPlanCliActionV1.Reconstruct
        assertEquals("returned/model", parsed.model)
        val stamp = AccountStampV1(id, 3, 4); val fetched = Instant.parse("2026-11-05T00:00:00Z")
        val catalog = CatalogViewV1(stamp, UUID.fromString("00000000-0000-0000-0000-000000000002"), fetched, fetched.plusSeconds(300),
            listOf(PlanModelViewV1("returned/model", "Returned")), OperatorVersionV1(5, id, 3, 4))
        val election = parsed.election(stamp, catalog, fetched.plusSeconds(1))
        assertEquals(stamp.authEpoch, election.expectedAuthEpoch); assertEquals(stamp.generation, election.expectedGeneration)
        assertEquals(catalog.catalogId.toString(), election.catalogId)
        val wrongCatalog = CatalogViewV1(stamp, catalog.catalogId, fetched, fetched.plusSeconds(300), listOf(PlanModelViewV1("other", "Other")), OperatorVersionV1(5, id, 3, 4))
        assertFailsWith<CliParseFailure> { parsed.election(stamp, wrongCatalog, fetched.plusSeconds(1)) }
        assertFailsWith<CliParseFailure> { parsed.election(stamp.copy(generation = 5), catalog, fetched.plusSeconds(1)) }
        assertFailsWith<CliParseFailure> { parsed.election(stamp, catalog, fetched.plusSeconds(301)) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parse(base.dropLast(1), limits()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parse(base + "--evidence-only", limits()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parse(base + listOf("--account", id), limits()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parse(base + listOf("--max-output-tokens", "8"), limits()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parse(base, null) }
    }

    @Test fun `strict limits parser enforces exact 24 keys canonical decimal values and byte bounds`() {
        val defaults = ChatGptLocalLimitsV1.from(LocalBudgetV1())
        assertEquals(defaults, ChatGptPlanOperatorCliV1.parseLimits(limits()))
        val padded = limits().let { raw -> raw + ByteArray(4096 - raw.size) { ' '.code.toByte() } }
        assertEquals(defaults, ChatGptPlanOperatorCliV1.parseLimits(padded))
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(padded + byteArrayOf(' '.code.toByte())) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(mapOf("inputUnits" to "1"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("unexpected" to "1"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("inputUnits" to "01"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("outputUnits" to "18446744073709551615"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("maxRetries" to "11"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("eventBytes" to "999999999999"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("historyReserveBytes" to "1"))) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseLimits(limits(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap() + ("wallClockMs" to "9223372036854775807"))) }
    }

    @Test fun `all 24 fields independently accept exact valid value and reject wire overflow`() {
        val base = ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap()
        names.forEach { name ->
            assertNotNull(ChatGptPlanOperatorCliV1.parseLimits(limits(base)), name)
            assertFailsWith<CliParseFailure>(name) {
                ChatGptPlanOperatorCliV1.parseLimits(limits(base + (name to "18446744073709551615")))
            }
        }
    }

    @Test fun `minimums plus ones and the accepted zero retry boundary are converted with all 24 constructor arguments`() {
        val min = mapOf("inputUnits" to "1", "outputUnits" to "1", "maxRequests" to "1", "maxToolActions" to "1",
            "callsPerResponse" to "1", "requestBytes" to "1", "responseBytes" to "1", "eventBytes" to "1",
            "contextBytes" to "8", "historyReserveBytes" to "2", "continuationBytes" to "1", "toolResultBytes" to "1",
            "receivedBytesTotal" to "1", "displayedBytesTotal" to "1", "evidenceBytes" to "1", "privateDiskBytes" to "1",
            "maxIdenticalAction" to "1", "traceRecords" to "1", "wallClockMs" to "1", "overallTimeoutMs" to "1",
            "connectTimeoutMs" to "1", "requestTimeoutMs" to "1", "idleTimeoutMs" to "1", "maxRetries" to "0")
        assertEquals(0, ChatGptPlanOperatorCliV1.parseLimits(limits(min)).maxRetries)
        val base = ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap()
        names.forEach { name ->
            val current = base.getValue(name).toLong()
            val next = if (name == "callsPerResponse") 33L else if (name == "maxRetries") 3L else current + 1L
            val candidate = base + (name to next.toString())
            val accepted = runCatching { ChatGptPlanOperatorCliV1.parseLimits(limits(candidate)) }.isSuccess
            if (name in setOf("callsPerResponse", "continuationBytes")) assertFalse(accepted, name) else assertTrue(accepted, name)
        }
    }

    @Test fun `election parser is explicit closed canonical and binds a complete nested limit object`() {
        val id = "00000000-0000-0000-0000-000000000001"
        val cat = "00000000-0000-0000-0000-000000000002"
        val body = buildJsonObject {
            put("accountId", id); put("modelSlug", "returned/model"); put("budgetPolicy", "local-acceptance-v1")
            put("policyVersion", "1"); put("acceptedLocalLimits", true); put("expectedAuthEpoch", "7")
            put("expectedGeneration", "4"); put("catalogId", cat)
            put("requestedLimits", JsonObject(ChatGptLocalLimitsV1.from(LocalBudgetV1()).asMap().mapValues { JsonPrimitive(it.value) }))
        }
        val parsed = ChatGptPlanOperatorCliV1.parseElection(body.toString().toByteArray())
        assertEquals(id, parsed.accountId); assertEquals("returned/model", parsed.modelSlug)
        assertEquals(7, parsed.expectedAuthEpoch); assertEquals(4, parsed.expectedGeneration)
        assertEquals(ChatGptLocalLimitsV1.from(LocalBudgetV1()), parsed.requestedLimits)
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseElection(JsonObject(body + ("unexpected" to JsonPrimitive("x"))).toString().toByteArray()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseElection(JsonObject(body - "acceptedLocalLimits").toString().toByteArray()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseElection(JsonObject(body + ("acceptedLocalLimits" to JsonPrimitive(false))).toString().toByteArray()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseElection(JsonObject(body + ("expectedGeneration" to JsonPrimitive("04"))).toString().toByteArray()) }
        assertFailsWith<CliParseFailure> { ChatGptPlanOperatorCliV1.parseElection(JsonObject(body + ("catalogId" to JsonPrimitive("not-a-uuid"))).toString().toByteArray()) }
    }
}
