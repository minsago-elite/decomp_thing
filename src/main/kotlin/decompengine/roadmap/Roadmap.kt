package decompengine.roadmap

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put
import java.nio.file.Path
import java.time.Instant
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeText

class RoadmapException(message: String) : RuntimeException(message)

class RoadmapManager(private val repoRoot: Path = Path.of("").toAbsolutePath().normalize()) {
    private val roadmapPath = repoRoot.resolve("ROADMAP.md")
    private val progressPath = repoRoot.resolve("roadmap/progress.json")
    private val schemaPath = repoRoot.resolve("roadmap/progress.schema.json")
    private val reportPath = repoRoot.resolve("roadmap/reports/latest.json")
    private val json = Json { prettyPrint = true }

    fun update(): String {
        val progress = loadProgress().toMutableProgress()
        validate(progress)
        val updated = progress.with("last_updated", JsonPrimitive(Instant.now().toString()))
        writeJson(progressPath, updated)
        writeJson(reportPath, buildReport(updated))
        roadmapPath.writeText(renderRoadmap(roadmapPath.readText(), updated))
        return "Updated $progressPath, $reportPath, and $roadmapPath"
    }

    fun check(): String {
        val progress = loadProgress()
        val schema = Json.parseToJsonElement(schemaPath.readText()).jsonObject
        if (schema.string("\$id") != "https://decomp-engine.local/schemas/progress.schema.json") {
            throw RoadmapException("progress.schema.json has an unexpected \$id")
        }
        validate(progress)
        val expected = renderRoadmap(roadmapPath.readText(), progress)
        val actual = roadmapPath.readText()
        if (actual != expected) {
            throw RoadmapException("ROADMAP.md is stale; run `roadmap update`")
        }
        return "Roadmap check passed"
    }

    private fun loadProgress(): JsonObject = Json.parseToJsonElement(progressPath.readText()).jsonObject

    private fun validate(progress: JsonObject) {
        requireKeys(progress, setOf("current_level", "current_status", "last_updated", "levels"), "progress")
        val statuses = setOf("pending", "active", "complete", "blocked")
        val gateStatuses = setOf("pending", "passing", "failing", "blocked", "manual_review")
        val gateSources = setOf("test", "benchmark", "manual", "report")
        if (progress.string("current_status") !in statuses) {
            throw RoadmapException("progress.current_status has invalid status: ${progress.string("current_status")}")
        }
        val levels = progress.array("levels")
        if (levels.isEmpty()) throw RoadmapException("progress.levels must be a non-empty list")
        val levelIds = mutableSetOf<String>()
        var activeCount = 0
        levels.forEach { element ->
            val level = element.jsonObject
            requireKeys(level, setOf("id", "name", "status", "gates"), "level ${level["id"] ?: "<unknown>"}")
            val levelId = level.string("id")
            levelIds += levelId
            if (level.string("status") !in statuses) throw RoadmapException("level $levelId has invalid status: ${level.string("status")}")
            if (level.string("status") == "active") activeCount += 1
            val gates = level.array("gates")
            if (gates.isEmpty()) throw RoadmapException("level $levelId must define at least one gate")
            val gateIds = mutableSetOf<String>()
            gates.forEach { gateElement ->
                val gate = gateElement.jsonObject
                requireKeys(gate, setOf("id", "description", "status", "source", "evidence"), "gate ${gate["id"] ?: "<unknown>"}")
                val gateId = gate.string("id")
                if (!gateIds.add(gateId)) throw RoadmapException("level $levelId has duplicate gate id: $gateId")
                if (gate.string("status") !in gateStatuses) throw RoadmapException("gate $gateId has invalid status: ${gate.string("status")}")
                if (gate.string("source") !in gateSources) throw RoadmapException("gate $gateId has invalid source: ${gate.string("source")}")
                if (gate.string("evidence").isBlank()) throw RoadmapException("gate $gateId must include evidence")
                if (gate.string("status") == "passing") {
                    val evidence = gate.string("evidence")
                    if (!evidence.startsWith("http://") && !evidence.startsWith("https://") && !repoRoot.resolve(evidence).exists()) {
                        throw RoadmapException("passing gate $gateId references missing evidence: $evidence")
                    }
                }
            }
            if (level.string("status") == "complete" && gates.any { it.jsonObject.string("status") != "passing" }) {
                throw RoadmapException("level $levelId is complete but has non-passing gates")
            }
        }
        if (activeCount > 1) throw RoadmapException("only one level may be active at a time")
        if (progress.string("current_level") !in levelIds) {
            throw RoadmapException("current_level does not match any level: ${progress.string("current_level")}")
        }
        val current = findCurrentLevel(progress)
        if (progress.string("current_status") != current.string("status")) {
            throw RoadmapException("current_status (${progress.string("current_status")}) must match current level status (${current.string("status")})")
        }
    }

    private fun buildReport(progress: JsonObject): JsonObject {
        var totalGates = 0
        var passingGates = 0
        var failingGates = 0
        val levels = buildJsonArray {
            progress.array("levels").forEach { element ->
                val level = element.jsonObject
                val summary = summarize(level)
                totalGates += summary.total
                passingGates += summary.passing
                failingGates += level.array("gates").count { it.jsonObject.string("status") in setOf("failing", "blocked") }
                add(buildJsonObject {
                    put("id", level.string("id"))
                    put("name", level.string("name"))
                    put("status", level.string("status"))
                    put("passing_gates", summary.passing)
                    put("total_gates", summary.total)
                    put("blocking_gate", summary.blockingGate)
                })
            }
        }
        return buildJsonObject {
            put("generated_at", Instant.now().toString())
            put("current_level", progress.string("current_level"))
            put("current_status", progress.string("current_status"))
            put("next_failing_gate", findNextFailingGate(progress))
            put("totals", buildJsonObject {
                put("levels", progress.array("levels").size)
                put("gates", totalGates)
                put("passing_gates", passingGates)
                put("failing_or_blocked_gates", failingGates)
            })
            put("levels", levels)
        }
    }

    private fun renderRoadmap(text: String, progress: JsonObject): String =
        replaceMarkedSection(
            replaceMarkedSection(text, SUMMARY_START, SUMMARY_END, renderSummary(progress)),
            TABLE_START,
            TABLE_END,
            renderProgressTable(progress),
        )

    private fun renderSummary(progress: JsonObject): String {
        val current = findCurrentLevel(progress)
        return listOf(
            "- Current maturity level: `${progress.string("current_level")}`",
            "- Current milestone: ${current.string("name")}",
            "- Current status: `${progress.string("current_status")}`",
            "- Next failing gate: ${findNextFailingGate(progress)}",
            "- Latest generated report: `roadmap/reports/latest.json`",
        ).joinToString("\n")
    }

    private fun renderProgressTable(progress: JsonObject): String =
        buildList {
            add("| Level | Name | Status | Passing Gates | Blocking Gate |")
            add("|---|---|---:|---:|---|")
            progress.array("levels").forEach { element ->
                val level = element.jsonObject
                val summary = summarize(level)
                add("| ${level.string("id")} | ${level.string("name")} | ${level.string("status")} | ${summary.passing}/${summary.total} | ${summary.blockingGate} |")
            }
        }.joinToString("\n")

    private fun replaceMarkedSection(text: String, start: String, end: String, replacement: String): String {
        if (!text.contains(start) || !text.contains(end)) {
            throw RoadmapException("ROADMAP.md is missing generated markers $start / $end")
        }
        val before = text.substringBefore(start)
        val afterStart = text.substringAfter(start)
        val after = afterStart.substringAfter(end)
        return "$before$start\n$replacement\n$end$after"
    }

    private fun findCurrentLevel(progress: JsonObject): JsonObject =
        progress.array("levels").firstOrNull { it.jsonObject.string("id") == progress.string("current_level") }?.jsonObject
            ?: throw RoadmapException("current level not found: ${progress.string("current_level")}")

    private fun findNextFailingGate(progress: JsonObject): String =
        findCurrentLevel(progress).array("gates")
            .firstOrNull { it.jsonObject.string("status") in setOf("failing", "blocked", "manual_review", "pending") }
            ?.jsonObject
            ?.string("description")
            ?: "none"

    private fun summarize(level: JsonObject): GateSummary {
        val gates = level.array("gates")
        val passing = gates.count { it.jsonObject.string("status") == "passing" }
        val blocking = gates.firstOrNull { it.jsonObject.string("status") in setOf("failing", "blocked", "manual_review", "pending") }
            ?.jsonObject
            ?.string("description")
            ?: "none"
        return GateSummary(passing, gates.size, blocking)
    }

    private fun writeJson(path: Path, payload: JsonObject) {
        path.writeText(json.encodeToString(JsonElement.serializer(), payload) + "\n")
    }

    private fun requireKeys(obj: JsonObject, keys: Set<String>, context: String) {
        val missing = keys - obj.keys
        if (missing.isNotEmpty()) throw RoadmapException("$context is missing required key(s): ${missing.sorted().joinToString(", ")}")
    }

    private fun JsonObject.toMutableProgress(): JsonObject = JsonObject(toMutableMap())
    private fun JsonObject.with(name: String, value: JsonElement): JsonObject = JsonObject(toMutableMap().also { it[name] = value })

    private data class GateSummary(val passing: Int, val total: Int, val blockingGate: String)

    companion object {
        private const val TABLE_START = "<!-- roadmap:progress:start -->"
        private const val TABLE_END = "<!-- roadmap:progress:end -->"
        private const val SUMMARY_START = "<!-- roadmap:summary:start -->"
        private const val SUMMARY_END = "<!-- roadmap:summary:end -->"
    }
}

private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content
private fun JsonObject.array(name: String): JsonArray = getValue(name).jsonArray
