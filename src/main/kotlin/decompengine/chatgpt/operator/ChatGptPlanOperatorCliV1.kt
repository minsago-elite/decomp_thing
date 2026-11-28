package decompengine.chatgpt.operator

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*
import java.util.UUID
import java.time.Duration
import java.time.Instant

internal sealed interface ChatGptPlanCliActionV1 {
    data class SignIn(val open: Boolean, val accountId: String?) : ChatGptPlanCliActionV1
    data object Accounts : ChatGptPlanCliActionV1
    data class Select(val accountId: String) : ChatGptPlanCliActionV1
    data class Models(val accountId: String?) : ChatGptPlanCliActionV1
    data object Status : ChatGptPlanCliActionV1
    data class Refresh(val accountId: String) : ChatGptPlanCliActionV1
    data class SignOut(val accountId: String) : ChatGptPlanCliActionV1
    data object Doctor : ChatGptPlanCliActionV1
    data class Reconstruct(val binary: String, val output: String, val account: String,
        val model: String, val limitsFile: String, val limits: ChatGptLocalLimitsV1) : ChatGptPlanCliActionV1 {
        fun election(stamp: AccountStampV1, catalog: CatalogViewV1, now: Instant): ChatGptPlanRunElectionV1 {
            if (stamp.accountId != account || catalog.account != stamp || catalog.models.none { it.slug == model } ||
                now.isBefore(catalog.fetchedAt) || !now.isBefore(catalog.expiresAt) ||
                Duration.between(catalog.fetchedAt, catalog.expiresAt) > Duration.ofMinutes(5)) throw CliParseFailure()
            return ChatGptPlanRunElectionV1(account, model, "local-acceptance-v1", 1, true,
                stamp.authEpoch, stamp.generation, catalog.catalogId.toString(), limits)
        }
    }
}

internal class CliParseFailure(val code: OperatorFailureV1 = OperatorFailureV1.INVALID_REQUEST) : IllegalArgumentException("Invalid ChatGPT plan command.") {
    override fun toString() = "CliParseFailure(${code.name})"
}

/** Parser only. Dispatch and registration intentionally remain outside this independent slice. */
internal object ChatGptPlanOperatorCliV1 {
    fun parse(args: List<String>, localLimitsFile: ByteArray? = null): ChatGptPlanCliActionV1 {
        if (args.firstOrNull() == "chatgpt") return parseChatgpt(args.drop(1))
        if (args.firstOrNull() != "reconstruct") throw CliParseFailure()
        if (args.any { it == "--evidence-only" }) throw CliParseFailure()
        val positional = ArrayList<String>()
        val values = linkedMapOf<String, String>()
        val flags = mutableSetOf<String>()
        val knownValue = setOf("--output", "--harness", "--account", "--model", "--budget-policy", "--local-limits")
        val knownFlag = setOf("--accept-local-limits")
        var i = 1
        while (i < args.size) {
            val arg = args[i]
            if (arg.startsWith("--")) {
                if (arg in knownFlag) { if (!flags.add(arg)) throw CliParseFailure(); i++; continue }
                if (arg !in knownValue || values.containsKey(arg) || i + 1 >= args.size || args[i + 1].startsWith("--")) throw CliParseFailure()
                values[arg] = args[i + 1]; i += 2
            } else { positional += arg; i++ }
        }
        if (positional.size != 1 || values.keys != knownValue || flags != knownFlag) throw CliParseFailure()
        if (values["--harness"] != "chatgpt-plan" || values["--budget-policy"] != "local-acceptance-v1") throw CliParseFailure()
        if (positional.single().isBlank() || values.getValue("--output").isBlank()) throw CliParseFailure()
        val account = canonicalUuid(values.getValue("--account"))
        val model = values.getValue("--model")
        if (!model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}"))) throw CliParseFailure()
        // Parser accepts bytes from a caller that has already performed bounded file IO. It never
        // reads paths itself and never fills election fields from ambient state.
        if (localLimitsFile == null || values.getValue("--local-limits").isBlank()) throw CliParseFailure()
        val limits = parseLimits(localLimitsFile)
        return ChatGptPlanCliActionV1.Reconstruct(positional.single(), values.getValue("--output"), account, model, values.getValue("--local-limits"), limits)
    }

    private fun parseChatgpt(args: List<String>): ChatGptPlanCliActionV1 {
        if (args.isEmpty()) throw CliParseFailure()
        val command = args.first(); val tail = args.drop(1)
        return when (command) {
            "sign-in" -> {
                when {
                    tail.isEmpty() -> ChatGptPlanCliActionV1.SignIn(false, null)
                    tail == listOf("--open") -> ChatGptPlanCliActionV1.SignIn(true, null)
                    tail.size == 2 && tail[0] == "--account" -> ChatGptPlanCliActionV1.SignIn(false, canonicalUuid(tail[1]))
                    tail.size == 3 && tail[0] == "--account" && tail[2] == "--open" -> ChatGptPlanCliActionV1.SignIn(true, canonicalUuid(tail[1]))
                    tail.size == 3 && tail[0] == "--open" && tail[1] == "--account" -> ChatGptPlanCliActionV1.SignIn(true, canonicalUuid(tail[2]))
                    else -> throw CliParseFailure()
                }
            }
            "accounts" -> if (tail.isEmpty()) ChatGptPlanCliActionV1.Accounts else throw CliParseFailure()
            "status" -> if (tail.isEmpty()) ChatGptPlanCliActionV1.Status else throw CliParseFailure()
            "doctor" -> if (tail.isEmpty()) ChatGptPlanCliActionV1.Doctor else throw CliParseFailure()
            "select", "refresh", "sign-out" -> {
                if (tail.size != 2 || tail[0] != "--account") throw CliParseFailure()
                val id = canonicalUuid(tail[1]); when (command) {
                    "select" -> ChatGptPlanCliActionV1.Select(id)
                    "refresh" -> ChatGptPlanCliActionV1.Refresh(id)
                    else -> ChatGptPlanCliActionV1.SignOut(id)
                }
            }
            "models" -> when (tail.size) {
                0 -> ChatGptPlanCliActionV1.Models(null)
                2 -> if (tail[0] == "--account") ChatGptPlanCliActionV1.Models(canonicalUuid(tail[1])) else throw CliParseFailure()
                else -> throw CliParseFailure()
            }
            else -> throw CliParseFailure()
        }
    }

    fun parseLimits(bytes: ByteArray): ChatGptLocalLimitsV1 = try {
        parseLimitsObject(strictObject(bytes))
    } catch (e: CliParseFailure) { throw e } catch (_: Exception) { throw CliParseFailure() }

    fun parseElection(bytes: ByteArray): ChatGptPlanRunElectionV1 = try {
        val obj = strictObject(bytes)
        val expected = setOf("accountId", "modelSlug", "budgetPolicy", "policyVersion", "acceptedLocalLimits", "expectedAuthEpoch", "expectedGeneration", "catalogId", "requestedLimits")
        if (obj.keys != expected) throw CliParseFailure()
        fun string(name: String): String = (obj[name] as? JsonPrimitive)?.takeIf { it.isString }?.content ?: throw CliParseFailure()
        fun unsigned(name: String): Long = decimal(string(name))
        val accepted = (obj["acceptedLocalLimits"] as? JsonPrimitive)?.takeIf { !it.isString }?.booleanOrNull ?: throw CliParseFailure()
        if (!accepted) throw CliParseFailure(OperatorFailureV1.POLICY_REQUIRED)
        val accountId = canonicalUuid(string("accountId")); val catalogId = canonicalUuid(string("catalogId"))
        val model = string("modelSlug")
        if (!model.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}"))) throw CliParseFailure()
        val version = Math.toIntExact(unsigned("policyVersion"))
        if (version != 1 || string("budgetPolicy") != "local-acceptance-v1") throw CliParseFailure(OperatorFailureV1.POLICY_REQUIRED)
        val nested = obj["requestedLimits"] as? JsonObject ?: throw CliParseFailure()
        ChatGptPlanRunElectionV1(accountId, model, "local-acceptance-v1", version, true,
            unsigned("expectedAuthEpoch"), unsigned("expectedGeneration"), catalogId, parseLimitsObject(nested))
    } catch (e: CliParseFailure) { throw e } catch (_: Exception) { throw CliParseFailure() }

    private fun strictObject(bytes: ByteArray): JsonObject =
        OracleJson.parse(bytes, StrictJsonLimits(4096, 4096, 8, 256, 128, 2048, 32)) as? JsonObject ?: throw CliParseFailure()

    private fun parseLimitsObject(obj: JsonObject): ChatGptLocalLimitsV1 {
        val names = listOf("inputUnits","outputUnits","maxRequests","maxToolActions","callsPerResponse","requestBytes","responseBytes","eventBytes","contextBytes","historyReserveBytes","continuationBytes","toolResultBytes","receivedBytesTotal","displayedBytesTotal","evidenceBytes","privateDiskBytes","maxIdenticalAction","traceRecords","wallClockMs","overallTimeoutMs","connectTimeoutMs","requestTimeoutMs","idleTimeoutMs","maxRetries")
        if (obj.keys != names.toSet()) throw CliParseFailure()
        fun unsigned(name: String): Long {
            val p = obj[name] as? JsonPrimitive ?: throw CliParseFailure()
            if (!p.isString) throw CliParseFailure()
            val s = p.content
            return decimal(s)
        }
        fun int(name: String): Int = Math.toIntExact(unsigned(name))
        return ChatGptLocalLimitsV1(unsigned("inputUnits"), unsigned("outputUnits"), int("maxRequests"), int("maxToolActions"), int("callsPerResponse"),
            unsigned("requestBytes"), unsigned("responseBytes"), unsigned("eventBytes"), unsigned("contextBytes"), unsigned("historyReserveBytes"),
            unsigned("continuationBytes"), unsigned("toolResultBytes"), unsigned("receivedBytesTotal"), unsigned("displayedBytesTotal"), unsigned("evidenceBytes"),
            unsigned("privateDiskBytes"), int("maxIdenticalAction"), unsigned("traceRecords"), unsigned("wallClockMs"), unsigned("overallTimeoutMs"),
            unsigned("connectTimeoutMs"), unsigned("requestTimeoutMs"), unsigned("idleTimeoutMs"), int("maxRetries")).also { it.toLocalBudget() }
    }

    private fun decimal(s: String): Long {
        if (!s.matches(Regex("0|[1-9][0-9]{0,18}"))) throw CliParseFailure()
        return s.toLongOrNull() ?: throw CliParseFailure()
    }

    private fun canonicalUuid(v: String): String = try { UUID.fromString(v).toString().also { if (it != v) throw CliParseFailure() } } catch (_: Exception) { throw CliParseFailure() }
}
