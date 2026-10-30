package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.machinecalls.MachineCallFileV1
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class IndependentExternalCallReportV1Test {
    @Test
    fun `generated report round trips canonically with positive and unresolved physical sites`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        IndependentExternalCallReportV1.validateComponent(report)
        assertEquals(report, IndependentExternalCallReportV1.parseComponent(OracleJson.canonicalBytes(report)))
        val sites = report.getValue("sites") as JsonArray
        assertTrue(sites.any { (it as JsonObject)["compositionDisposition"] == JsonPrimitive("static-import-request-reference") })
        assertTrue(sites.any { (it as JsonObject)["compositionDisposition"] == JsonPrimitive("unresolved-weak-runtime-target") })
        assertFails { IndependentExternalCallReportV1.parseComponent(OracleJson.canonicalBytes(report) + byteArrayOf(10)) }
        Thread.currentThread().interrupt()
        try { assertFails { IndependentExternalCallReportV1.validateComponent(report) } } finally { Thread.interrupted() }
    }

    @Test
    fun `every object is closed and authority and limits cannot be widened in retained evidence`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        objectPaths(report).forEach { path ->
            val record = report.at(path) as JsonObject
            reject(report.edit(path, JsonObject(record + ("recoveredFacts" to JsonPrimitive(true)))), path.toString())
            if (record.isNotEmpty()) reject(report.edit(path, JsonObject(record - record.keys.first())), "missing at $path")
        }
        for (name in listOf("complete", "releaseEligible", "negativeCompleteness", "sourceCallPopulationComplete"))
            reject(report.edit(listOf(name), JsonPrimitive(true)), name)
        reject(report.edit(listOf("sourceCallRecordsEnumerated"), JsonPrimitive(false)))
        reject(report.edit(listOf("sites", 0, "negativeCompleteness"), JsonPrimitive(true)))
        reject(report.edit(listOf("limits", "maximumOutputBytes"), JsonPrimitive(1)))
        reject(report.edit(listOf("limits", "maximumCalls"), JsonPrimitive(100001)))
        reject(report.edit(listOf("decoderAuthentication"), JsonPrimitive("authenticated-bundled-worker-v1")))
        reject(report.edit(listOf("inputSha256"), JsonPrimitive("A".repeat(64))))
        reject(report.edit(listOf("inputBytes"), JsonPrimitive("3840")))
        reject(report.edit(listOf("imageBase"), JsonPrimitive("0x0400000")))
    }

    @Test
    fun `namespace hashes full symbol versions relocation indexes and slot ownership are recomputed`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        val changes = listOf(
            listOf("externalNamespaceSha256") to JsonPrimitive("e".repeat(64)),
            listOf("externalNamespace", "entries", 0, "id") to JsonPrimitive("ext-${"e".repeat(64)}"),
            listOf("externalNamespace", "entries", 0, "identity", "version", "providerRequest") to JsonPrimitive("fake-provider.so"),
            listOf("dynamicInventory", "dynamicSymbols", 1, "version", "hidden") to JsonPrimitive(true),
            listOf("dynamicInventory", "dynamicSymbols", 1, "symbolIndex") to JsonPrimitive(999),
            listOf("dynamicInventory", "versionRequirements", 0, "index") to JsonPrimitive(5),
            listOf("dynamicInventory", "versionDefinitions", 0, "parentNames", 0) to JsonPrimitive(""),
            listOf("dynamicInventory", "versionDefinitions", 0, "auxiliaryOffsets", 1) to JsonPrimitive(0x778),
            listOf("dynamicInventory", "relocations", 0, "symbolIndex") to JsonPrimitive(999),
            listOf("dynamicInventory", "relocations", 6, "slotFileOffset") to JsonPrimitive(1),
            listOf("dynamicInventory", "relocations", 6, "dynamicTables") to JsonArray(emptyList()),
            listOf("dynamicInventory", "programHeaders", 0, "fileSize") to JsonPrimitive("0x1"),
        )
        changes.forEach { (path, value) -> reject(report.edit(path, value), path.toString()) }
        for (key in listOf("dynamicSymbols", "relocations", "versionDefinitions", "versionRequirements")) {
            val path = listOf("dynamicInventory", key); val array = report.at(path) as JsonArray
            reject(report.edit(path, JsonArray(array + array.first())), "duplicate $key")
            if (array.size > 1) reject(report.edit(path, JsonArray(array.reversed())), "unordered $key")
        }
        val namespacePath = listOf("externalNamespace", "entries")
        val namespace = report.at(namespacePath) as JsonArray
        reject(report.edit(namespacePath, JsonArray(namespace.dropLast(1))))
    }

    @Test
    fun `physical coordinates memory proof and write coverage cannot be edited into an import association`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        val changes = listOf(
            listOf("sites", 0, "sourceOrdinal") to JsonPrimitive(1),
            listOf("sites", 0, "callerCanonicalId") to JsonPrimitive("canonical-missing"),
            listOf("sites", 0, "callerRva") to JsonPrimitive("0x271"),
            listOf("sites", 0, "instructionRva") to JsonPrimitive("0x100000"),
            listOf("sites", 0, "instructionLength") to JsonPrimitive(4),
            listOf("sites", 0, "returnAddress") to JsonPrimitive("0x400999"),
            listOf("sites", 0, "physicalTargetAddress") to JsonPrimitive("0x400201"),
            listOf("sites", 0, "viaForwarder") to JsonPrimitive(false),
            listOf("sites", 0, "memoryTransfer", "pointerSlotAddress") to JsonPrimitive("0x400818"),
            listOf("sites", 0, "memoryTransfer", "pointerWidthBytes") to JsonPrimitive(4),
            listOf("sites", 0, "memoryTransfer", "rawReadOpcode") to JsonPrimitive("CALLIND"),
            listOf("sites", 0, "memoryTransfer", "rawCopyOpIndices") to JsonArray(listOf(JsonPrimitive(1), JsonPrimitive(0))),
            listOf("sites", 0, "memoryTransfer", "contextStatus") to JsonPrimitive("context-change"),
            listOf("sites", 0, "relocationBinding", "writeCoverage", "overlappingWrite") to JsonPrimitive(true),
            listOf("sites", 0, "relocationBinding", "writeCoverage", "unknownWriteWidth") to JsonPrimitive(true),
            listOf("sites", 0, "relocationBinding", "runtimeProviderAvailable") to JsonPrimitive(true),
            listOf("sites", 0, "compositionDisposition") to JsonPrimitive("unresolved-slot-without-relocation"),
            listOf("sites", 1, "targetBindingDisposition") to JsonPrimitive("static-import-request-reference"),
        )
        changes.forEach { (path, value) -> reject(report.edit(path, value), path.toString()) }
        val second = report.at(listOf("sites", 1, "memoryTransfer")) as JsonObject
        val shortened = JsonObject(second + mapOf("length" to JsonPrimitive(2), "bytes" to JsonPrimitive("ff15")))
        reject(report.edit(listOf("sites", 1, "memoryTransfer"), shortened), "truncated memory receipt")
    }

    @Test
    fun `site populations caller exclusions and every count agree with retained evidence`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        val sites = report.getValue("sites") as JsonArray
        reject(report.edit(listOf("sites"), JsonArray(sites.reversed())))
        reject(report.edit(listOf("sites"), JsonArray(sites + sites.first())))
        reject(report.edit(listOf("sourceCanonicalPopulation"), JsonArray(emptyList())))
        val excluded = JsonObject(mapOf("kind" to JsonPrimitive("compiler-generated"), "reason" to JsonPrimitive("authored exclusion")))
        reject(report.edit(listOf("sourceCanonicalPopulation", 0, "exclusion"), excluded))
        for (key in listOf("sourcePhysicalSites", "composedSiteRecords", "namespaceEntries"))
            reject(report.edit(listOf("counts", key), JsonPrimitive(999)))
        val dispositions = report.at(listOf("counts", "dispositions")) as JsonObject
        dispositions.keys.forEach { key -> reject(report.edit(listOf("counts", "dispositions", key), JsonPrimitive(999))) }
        reject(report.edit(listOf("sites", 0, "sourceDisposition"), JsonPrimitive("positive-internal-exact-start")))
    }

    @Test
    fun `worker schema binds complete request runtime limits and source identities without release authority`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        val request = IndependentExternalCallRequestV1(MachineCallFileV1(fixture.rich, Files.size(fixture.rich), fixture.inputSha),
            MachineCallFileV1(fixture.sourceReport, Files.size(fixture.sourceReport), fixture.reportSha),
            MachineCallFileV1(fixture.sourceRequest, Files.size(fixture.sourceRequest), fixture.requestSha), fixture.runtime,
            fixture.root.resolve("external-worker-report.json"))
        val requestSha = OracleArtifacts.sha256(request.canonicalBytes)
        val worker = JsonObject(report + mapOf("requestSha256" to JsonPrimitive(requestSha), "runtime" to request.runtime.reportJson(),
            "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"), "containmentStatus" to JsonPrimitive("external-owner-required")))
        IndependentExternalCallReportV1.validateWorker(worker, requestSha, request)
        reject(worker)
        for (key in listOf("requestSha256", "inputSha256", "sourceReportSha256", "sourceRequestSha256")) assertFails(key) {
            IndependentExternalCallReportV1.validateWorker(worker.edit(listOf(key), JsonPrimitive("f".repeat(64))), requestSha, request)
        }
        request.runtime.reportJson().keys.forEach { key -> assertFails(key) {
            IndependentExternalCallReportV1.validateWorker(worker.edit(listOf("runtime", key), JsonPrimitive("changed")), requestSha, request)
        } }
        for ((path, value) in listOf(listOf("limits", "maximumWallMillis") to JsonPrimitive(1000),
            listOf("metadataPolicy") to JsonPrimitive("custom"), listOf("containmentStatus") to JsonPrimitive("contained"),
            listOf("runtime", "extra") to JsonPrimitive(true), listOf("releaseEligible") to JsonPrimitive(true))) assertFails(path.toString()) {
            IndependentExternalCallReportV1.validateWorker(worker.edit(path, value), requestSha, request)
        }
    }
}

private fun reject(report: JsonObject, label: String = "mutation") { assertFails(label) { IndependentExternalCallReportV1.validateComponent(report) } }
private fun objectPaths(value: JsonElement, path: List<Any> = emptyList()): List<List<Any>> = when (value) {
    is JsonObject -> listOf(path) + value.flatMap { (key, child) -> objectPaths(child, path + key) }
    is JsonArray -> value.flatMapIndexed { index, child -> objectPaths(child, path + index) }
    else -> emptyList()
}
private fun JsonElement.at(path: List<Any>): JsonElement = path.fold(this) { current, key ->
    if (key is Int) (current as JsonArray)[key] else (current as JsonObject).getValue(key as String)
}
private fun JsonObject.edit(path: List<Any>, replacement: JsonElement): JsonObject {
    fun replace(current: JsonElement, offset: Int): JsonElement {
        if (offset == path.size) return replacement
        val key = path[offset]
        return if (key is Int) JsonArray((current as JsonArray).mapIndexed { index, child -> if (index == key) replace(child, offset + 1) else child })
        else JsonObject((current as JsonObject) + (key as String to replace(current[key] ?: JsonNull, offset + 1)))
    }
    return replace(this, 0) as JsonObject
}
