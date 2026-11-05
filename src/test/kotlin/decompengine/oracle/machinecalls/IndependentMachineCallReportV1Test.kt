package decompengine.oracle.machinecalls

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class IndependentMachineCallReportV1Test {
    @Test fun `generated positive and unresolved component report round trips canonical validation`() = withMachineCallComponentFixtureV1 { report ->
        IndependentMachineCallReportV1.validateComponent(report)
        assertEquals(report, IndependentMachineCallReportV1.parseComponent(OracleJson.canonicalBytes(report)))
        assertFails { IndependentMachineCallReportV1.parseComponent(OracleJson.canonicalBytes(report) + byteArrayOf(10)) }
        Thread.currentThread().interrupt()
        try { assertFails { IndependentMachineCallReportV1.validateComponent(report) } } finally { Thread.interrupted() }
    }

    @Test fun `ownership validation includes absolute extents starting below image base`() = withMachineCallCrossBaseFixtureV1 { report ->
        IndependentMachineCallReportV1.validateComponent(report)
        assertEquals(report, IndependentMachineCallReportV1.parseComponent(OracleJson.canonicalBytes(report)))
        val roots = report.getValue("roots") as JsonArray
        val index = roots.indexOfFirst { (it as JsonObject).getValue("rva") == JsonNull }
        val problems = report.at(listOf("roots", index, "ownershipProblems")) as JsonArray
        // All counts and local extent checks still agree; only the absolute overlap relation rejects this.
        reject(report.edit(listOf("roots", index, "ownershipProblems"),
            JsonArray(problems.filter { it != JsonPrimitive("overlapping-symbol-extents") })))
    }

    @Test fun `report fields are closed at every nesting level and authority is never admitted`() = withMachineCallComponentFixtureV1 { report ->
        val objects = listOf(emptyList<Any>(), listOf("limits"), listOf("counts"), listOf("roots", 0),
            listOf("roots", 0, "origins", 0), listOf("canonicalPopulation", 0), listOf("calls", 0))
        for (path in objects) {
            val item = report.at(path) as JsonObject
            reject(report.edit(path, JsonObject(item + ("unexpected" to JsonPrimitive(true)))))
            for (key in item.keys) reject(report.edit(path, JsonObject(item - key)))
        }
        for (flag in listOf("complete", "releaseEligible", "negativeCompleteness")) reject(report.edit(listOf(flag), JsonPrimitive(true)))
        for (flag in listOf("canonicalPopulationComplete", "rawSymbolPopulationComplete")) reject(report.edit(listOf(flag), JsonPrimitive(false)))
        reject(report.edit(listOf("calls", 0, "negativeCompleteness"), JsonPrimitive(true)))
        reject(report.edit(listOf("roots", 0, "negativeCompleteness"), JsonPrimitive(true)))
        reject(report.edit(listOf("inputSha256"), JsonPrimitive("A".repeat(64))))
        reject(report.edit(listOf("inputBytes"), JsonPrimitive("500")))
        reject(report.edit(listOf("imageBase"), JsonPrimitive("0x0400000")))
        reject(report.edit(listOf("decoderAuthentication"), JsonPrimitive("authenticated-bundled-worker-v1")))
        reject(report.edit(listOf("limits", "maximumOutputBytes"), JsonPrimitive(1)))
        reject(report.edit(listOf("limits", "maximumRoots"), JsonPrimitive(131073)))
    }

    @Test fun `population order aliases root references and all aggregate counts are exact`() = withMachineCallComponentFixtureV1 { report ->
        for (key in listOf("roots", "canonicalPopulation", "calls")) {
            val array = report.getValue(key) as JsonArray
            reject(report.edit(listOf(key), JsonArray(array.reversed())))
            reject(report.edit(listOf(key), JsonArray(array + array.first())))
        }
        val origin = report.at(listOf("roots", 0, "origins", 0))
        reject(report.edit(listOf("roots", 0, "origins"), JsonArray(listOf(origin, origin))))
        reject(report.edit(listOf("canonicalPopulation", 0, "rootIds"), JsonArray(emptyList())))
        reject(report.edit(listOf("canonicalPopulation", 0, "disposition"), JsonPrimitive("unresolved-missing-symbol-extent")))
        reject(report.edit(listOf("roots", 0, "endExclusiveRva"), JsonPrimitive("0x999")))
        reject(report.edit(listOf("roots", 0, "origins", 0, "type"), JsonPrimitive(10)))
        reject(report.edit(listOf("roots", 0, "origins", 0, "sectionKind"), JsonPrimitive("undefined")))
        reject(report.edit(listOf("roots", 0, "fileOffset"), report.getValue("inputBytes")))
        reject(report.edit(listOf("roots", 1, "instructionAttempts"), JsonPrimitive(0)))
        for ((key, value) in report.getValue("counts") as JsonObject) {
            reject(report.edit(listOf("counts", key), JsonPrimitive((value as JsonPrimitive).content.toLong() + 1)))
        }
    }

    @Test fun `positive call requires exact eligible caller target extent identity and typed raw agreement`() = withMachineCallComponentFixtureV1 { report ->
        val changes = mapOf<String, JsonElement>(
            "callerRoot" to JsonPrimitive("symbol-root:missing"), "callerRva" to JsonPrimitive("0x111"),
            "callerCanonicalId" to JsonPrimitive("canonical-150"), "instructionRva" to JsonPrimitive("0x14f"),
            "instructionBytes" to JsonPrimitive("c3"), "instructionLength" to JsonPrimitive(1),
            "classification" to JsonPrimitive("ordinary"), "directTargetRva" to JsonPrimitive("0x151"),
            "directTargetAddress" to JsonPrimitive("0x400151"), "rawPcodeCallTargetAddress" to JsonPrimitive("0x400151"),
            "targetCanonicalId" to JsonPrimitive("canonical-110"), "targetAgreement" to JsonPrimitive("computed-target-unresolved"),
            "directTargetAddresses" to JsonArray(emptyList()), "fallthroughAddress" to JsonPrimitive("0x400118"),
            "contextStatus" to JsonPrimitive("context-change"), "disposition" to JsonPrimitive("unresolved-indirect-target"),
        )
        for ((key, value) in changes) reject(report.edit(listOf("calls", 0, key), value))
        // An attacker cannot make an external or indirect call positive by only changing its disposition/counts.
        for (index in listOf(1, 2)) reject(report.edit(listOf("calls", index, "disposition"), JsonPrimitive("positive-internal-exact-start")))
        val exclusion = JsonObject(mapOf("kind" to JsonPrimitive("compiler-generated"), "reason" to JsonPrimitive("authored exclusion")))
        for (index in listOf(0, 1)) {
            val excluded = report.edit(listOf("canonicalPopulation", index, "exclusion"), exclusion)
                .edit(listOf("canonicalPopulation", index, "disposition"), JsonPrimitive("unresolved-canonical-exclusion-no-parent-inference"))
            reject(excluded)
        }
        // Coordinated address edits still cannot borrow the target's canonical identity at its interior.
        var interior = report
        for (key in listOf("directTargetAddress", "rawPcodeCallTargetAddress")) interior = interior.edit(listOf("calls", 0, key), JsonPrimitive("0x400151"))
        interior = interior.edit(listOf("calls", 0, "directTargetRva"), JsonPrimitive("0x151"))
            .edit(listOf("calls", 0, "directTargetAddresses"), JsonArray(listOf(JsonPrimitive("0x400151"))))
        reject(interior)
    }

    @Test fun `stop inventory preserves sorted unique coordinates reason summaries and bounded bytes`() = withMachineCallComponentFixtureV1 { report ->
        val event = JsonObject(mapOf("address" to JsonPrimitive("0x40011f"), "rva" to JsonPrimitive("0x11f"),
            "reason" to JsonPrimitive("unsupported-flow"), "targetAddress" to JsonNull,
            "bytesKind" to JsonPrimitive("decoded-instruction"), "bytes" to JsonPrimitive("c3")))
        val stopped = report.edit(listOf("roots", 0, "traversalStops"), JsonArray(listOf(JsonPrimitive("unsupported-flow"))))
            .edit(listOf("roots", 0, "traversalStopEvents"), JsonArray(listOf(event)))
            .edit(listOf("counts", "rootsWithTraversalStops"), JsonPrimitive(1))
        IndependentMachineCallReportV1.validateComponent(stopped)
        reject(stopped.edit(listOf("roots", 0, "traversalStopEvents"), JsonArray(listOf(event, event))))
        reject(stopped.edit(listOf("roots", 0, "traversalStops"), JsonArray(emptyList())))
        reject(stopped.edit(listOf("roots", 0, "traversalStopEvents", 0, "rva"), JsonPrimitive("0x11e")))
        reject(stopped.edit(listOf("roots", 0, "traversalStopEvents", 0, "bytes"), JsonPrimitive("c3".repeat(16))))
        reject(stopped.edit(listOf("roots", 0, "traversalStopEvents", 0, "bytesKind"), JsonPrimitive("available-window")))
        reject(stopped.edit(listOf("roots", 0, "traversalStopEvents", 0), JsonObject(event + ("extra" to JsonPrimitive(1)))))
    }

    @Test fun `worker report binds complete request inputs runtime limits and containment without release authority`() = withMachineCallComponentFixtureV1 { report ->
        val root = Path.of("build/report-validator-controls").toAbsolutePath().normalize()
        fun text(key: String) = (report.getValue(key) as JsonPrimitive).content
        val request = IndependentMachineCallRequestV1(
            MachineCallFileV1(root.resolve("rich.elf"), text("inputBytes").toLong(), text("inputSha256")),
            MachineCallFileV1(root.resolve("canonical.json"), 1, text("canonicalOracleSha256")), text("artifactManifestSha256"),
            MachineCallRuntimeV1(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256, 569445154,
                "a".repeat(64), "b".repeat(64), "x86:LE:64:default", "4.8"), root.resolve("report.json"))
        val requestHash = OracleArtifacts.sha256(request.canonicalBytes)
        val worker = JsonObject(report + mapOf("requestSha256" to JsonPrimitive(requestHash), "runtime" to request.runtime.json(),
            "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"), "containmentStatus" to JsonPrimitive("external-owner-required")))
        IndependentMachineCallReportV1.validateWorker(worker, requestHash, request)
        reject(worker)
        for (key in listOf("requestSha256", "inputSha256", "canonicalOracleSha256", "artifactManifestSha256")) assertFails(key) {
            IndependentMachineCallReportV1.validateWorker(worker.edit(listOf(key), JsonPrimitive("e".repeat(64))), requestHash, request)
        }
        for (key in request.runtime.json().keys) assertFails(key) {
            IndependentMachineCallReportV1.validateWorker(worker.edit(listOf("runtime", key), JsonPrimitive("changed")), requestHash, request)
        }
        for ((path, value) in listOf(listOf("inputBytes") to JsonPrimitive(text("inputBytes").toLong() + 1),
            listOf("limits", "maximumWallMillis") to JsonPrimitive(1000), listOf("containmentStatus") to JsonPrimitive("contained"),
            listOf("runtime", "extra") to JsonPrimitive(true))) assertFails(path.toString()) {
            IndependentMachineCallReportV1.validateWorker(worker.edit(path, value), requestHash, request)
        }
    }

    private fun reject(report: JsonObject) { assertFails { IndependentMachineCallReportV1.validateComponent(report) } }
    private fun JsonElement.at(path: List<Any>): JsonElement = path.fold(this) { current, key ->
        if (key is Int) (current as JsonArray)[key] else (current as JsonObject).getValue(key as String)
    }
    private fun JsonObject.edit(path: List<Any>, value: JsonElement): JsonObject {
        fun replace(current: JsonElement, index: Int): JsonElement {
            if (index == path.size) return value
            val key = path[index]
            return if (key is Int) JsonArray((current as JsonArray).mapIndexed { i, item -> if (i == key) replace(item, index + 1) else item })
            else JsonObject((current as JsonObject) + (key as String to replace(current[key] ?: JsonNull, index + 1)))
        }
        return replace(this, 0) as JsonObject
    }
}
