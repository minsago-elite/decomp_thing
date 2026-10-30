package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.externalcalls.FrozenNativeExternalClaimsSnapshotV1
import kotlinx.serialization.json.*

/** Deterministic source-preserving algebra only; no constructor or parser can issue CALLS authority. */
internal class StructuralNativeExternalCallProjectionResultV1(input: ByteArray, report: ByteArray, evidence: ByteArray) {
    private val input = input.copyOf()
    private val report = report.copyOf()
    private val evidence = evidence.copyOf()
    val inputBytes: ByteArray get() = input.copyOf()
    val reportBytes: ByteArray get() = report.copyOf()
    val evidenceBytes: ByteArray get() = evidence.copyOf()
    val productionVerified = false
    val negativeCompleteness = false
    val complete = false
    val releaseEligible = false
}

internal object StructuralNativeExternalCallProjectionV1 {
    private const val POLICY = "native-external-call-ledger-v1:original-two-source-census;own-target-selection-before-oracle;positive-only;physical-site-once;exact-owner-exclusions;indirect-stays-indirect;conflicts-unknown"
    private val LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024, maximumCanonicalBytes = 64 * 1024 * 1024,
        maximumNodes = 1_000_000, maximumDepth = 32, maximumStringBytes = 4 * 1024 * 1024, maximumTotalStringBytes = 64 * 1024 * 1024)

    fun project(core: FrozenNativeRecoveredCallPopulationV1, external: FrozenNativeExternalClaimsSnapshotV1,
        boundary: StructuralSelectedBoundaryProjectionV1, machineBytes: ByteArray, independentBytes: ByteArray,
        recoveredBytes: ByteArray, expectedNamespace: JsonObject, checkpoint: () -> Unit = {}): StructuralNativeExternalCallProjectionResultV1 {
        require(core.rawManifestBytes.contentEquals(external.rawManifestBytes) &&
            core.rawObservationBytes.contentEquals(external.rawObservationBytes) && core.rawRecordCount == external.rawRecordCount &&
            core.rawSiteCount.toLong() == external.rawSiteCount && core.programModelSha256 == external.bindings.programModelSha256 &&
            core.programModelBytes == external.bindings.programModelBytes && core.inputSha256 == external.inputSha256)
        return projectFrozen(core.project(boundary), core.canonicalEvidenceBytes, external, boundary,
            machineBytes, independentBytes, recoveredBytes, expectedNamespace, checkpoint)
    }

    /** Pure internal seam for authored controls; it carries no stronger authority than project. */
    internal fun projectFrozen(coreFragmentBytes: ByteArray, coreEvidenceBytes: ByteArray,
        external: FrozenNativeExternalClaimsSnapshotV1, boundary: StructuralSelectedBoundaryProjectionV1,
        machineBytes: ByteArray, independentBytes: ByteArray, recoveredBytes: ByteArray,
        expectedNamespace: JsonObject, checkpoint: () -> Unit = {}): StructuralNativeExternalCallProjectionResultV1 {
        fun step() { check(!Thread.currentThread().isInterrupted); checkpoint() }
        step()
        fun parse(bytes: ByteArray) = OracleJson.parseCanonical(bytes, LIMITS).jsonObject
        val fragment = parse(coreFragmentBytes)
        val machine = parse(machineBytes)
        val independent = parse(independentBytes)
        val recovered = parse(recoveredBytes)
        val namespaceSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(expectedNamespace, LIMITS))
        require(independent["externalNamespace"] == expectedNamespace && recovered["externalNamespace"] == expectedNamespace &&
            independent.text("externalNamespaceSha256") == namespaceSha && recovered.text("externalNamespaceSha256") == namespaceSha)
        val tokens = expectedNamespace.rows("entries").map { it.text("id") }.toSet()
        require(tokens.size == expectedNamespace.rows("entries").size)
        require(independent.text("sourceReportSha256") == OracleArtifacts.sha256(machineBytes) &&
            independent["sourceRequestSha256"] == machine["requestSha256"] && independent["inputSha256"] == machine["inputSha256"] &&
            expectedNamespace["inputSha256"] == machine["inputSha256"] &&
            machine.text("canonicalOracleSha256") == boundary.functionOracleSha256 &&
            recovered.text("frozenClaimsSha256") == external.evidenceSha256 &&
            external.bindings.programModelSha256 == boundary.programModelSha256 && external.bindings.programModelBytes == boundary.programModelBytes &&
            external.inputSha256 == boundary.inputSha256 &&
            external.bindings.imageBase.offsetBits?.toULong(16) == boundary.selectedModelImageBase)
        for (document in listOf(machine, independent, recovered)) for (flag in listOf("negativeCompleteness", "complete", "releaseEligible"))
            require(document[flag] == JsonPrimitive(false))
        require(independent["sourceCallPopulationComplete"] == JsonPrimitive(false))
        val fragmentBinding = fragment.getValue("binding").jsonObject
        require(fragmentBinding["inputSha256"] == JsonPrimitive(boundary.inputSha256) &&
            fragmentBinding["programModelSha256"] == JsonPrimitive(boundary.programModelSha256) &&
            fragmentBinding["boundaryObservationSha256"] == JsonPrimitive(boundary.boundaryObservationSha256) &&
            fragmentBinding["externalNamespaceSha256"] == JsonNull)
        val canonical = machine.rows("canonicalPopulation")
        require(independent["sourceCanonicalPopulation"] == JsonArray(canonical.map {
            JsonObject(it.filterKeys { key -> key in setOf("id", "rva", "exclusion") })
        })) { "external component substitutes the original canonical population" }
        require(canonical.map { it.text("id") }.toSet() == boundary.oracleFunctions.keys + boundary.excludedOracleIds &&
            canonical.map { it.text("id") }.distinct().size == canonical.size) { "independent canonical census differs from the selected universe" }
        for (row in canonical) {
            step()
            val id = row.text("id")
            val excluded = boundary.excludedFunctions[id]
            val expectedRva = excluded?.rva ?: boundary.oracleFunctions[id]?.rva
            require(row["rva"] == hex(expectedRva))
            if (excluded == null) require(row["exclusion"] == JsonNull)
            else require(row.getValue("exclusion").jsonObject == obj("kind" to str(excluded.kind), "reason" to str(excluded.reason)))
        }
        val calls = machine.rows("calls")
        val independentSites = independent.rows("sites")
        val recoveredRows = recovered.rows("sites")
        require(calls.size == independentSites.size && recoveredRows.size.toLong() == external.rawSiteCount &&
            calls.size + recoveredRows.size <= 100_000) { "combined raw call census exceeds its bound or was changed" }
        val rawExternal = external.sites.associateBy { it.recordOrdinal }
        require(rawExternal.size == external.sites.size)
        val externalRows = linkedMapOf<Long, JsonObject>()
        for ((index, row) in recoveredRows.withIndex()) {
            step()
            val raw = external.sites[index]
            require(row.number("sourceRecordOrdinal") == raw.recordOrdinal && row.number("sourceSiteOrdinal") == raw.siteOrdinal &&
                row.text("siteId") == "native-site-${raw.siteOrdinal}" && row.text("frozenDisposition") == raw.disposition &&
                row["negativeCompleteness"] == JsonPrimitive(false)) { "recovered external source ordinal changed" }
            require(externalRows.put(raw.recordOrdinal, row) == null)
        }
        val policySha = OracleArtifacts.sha256(POLICY.toByteArray())
        val originalSource = fragment.getValue("source").jsonObject
        require(originalSource.text("sha256") == external.observationsSha256 && originalSource.number("bytes") == external.observationBytes)
        val nativeSource = JsonObject(originalSource + ("policySha256" to str(policySha)))
        val nativeRecordIds = originalSource.getValue("recordIds").jsonArray.map { it.jsonPrimitive.content }
        require(nativeRecordIds.toSet() == rawExternal.keys.map { "records/$it" }.toSet() && nativeRecordIds.size == rawExternal.size)
        val nativeSites = fragment.rows("sites")
        val nativeExclusions = fragment.rows("exclusions")
        val consumedNative = hashSetOf<Long>()
        fun nativeOrdinal(row: JsonObject): Long {
            val refs = row.rows("observations")
            require(refs.size == 1 && refs.single().text("sourceId") == originalSource.text("id"))
            val id = refs.single().text("recordId")
            require(id.startsWith("records/"))
            val ordinal = id.removePrefix("records/").toLong()
            require(id == "records/$ordinal" && ordinal in rawExternal && consumedNative.add(ordinal))
            return ordinal
        }
        nativeExclusions.forEach { row -> nativeOrdinal(row); require(row.text("ownerId") in boundary.ignoredRecoveredIds) }
        val refined = nativeSites.map { site ->
            step()
            val ordinal = nativeOrdinal(site)
            require(site.text("id") == "native-site-$ordinal")
            val raw = rawExternal.getValue(ordinal)
            val extension = externalRows.getValue(ordinal)
            val token = extension.nullableText("externalTargetId")
            if (extension.text("disposition") != "verified-object-local-import-request") {
                require(token == null)
                site
            } else {
                require(token in tokens && raw.physicalCallEligible && raw.candidate != null &&
                    site.getValue("instruction").jsonObject["space"] == str("image"))
                // An independently supplied target never fills recovery's absent own selection.
                val conflict = site["targets"] != JsonNull || site["callerId"] == JsonNull
                JsonObject(site + mapOf("category" to str(if (raw.prototypeFlowCode in setOf(8, 13, 15)) "indirect" else "external"),
                    "state" to str(if (conflict) "recovered-unknown" else "recovered"),
                    "targets" to if (conflict) JsonNull else targets("external", requireNotNull(token))))
            }
        }
        require(consumedNative == rawExternal.keys) { "native sites or exact exclusions omitted an original ordinal" }
        val sourceId = "machine-${OracleArtifacts.sha256(machineBytes)}"
        fun refs(index: Int) = JsonArray(listOf(obj("sourceId" to str(sourceId), "recordId" to str("calls/$index"))))
        val oracleSites = arrayListOf<JsonObject>()
        val exclusions = nativeExclusions.toMutableList()
        val oracleExclusionEvidence = linkedMapOf<String, JsonElement>()
        val base = machine.text("imageBase").removePrefix("0x").toULong(16)
        for ((index, call) in calls.withIndex()) {
            step()
            val witness = independentSites[index]
            require(witness.number("sourceOrdinal") == index.toLong())
            for ((raw, composed) in mapOf("callerRoot" to "callerRoot", "callerCanonicalId" to "callerCanonicalId", "callerRva" to "callerRva",
                "instructionRva" to "instructionRva", "instructionBytes" to "instructionBytes", "instructionLength" to "instructionLength",
                "classification" to "physicalClassification", "directTargetAddress" to "physicalTargetAddress",
                "fallthroughAddress" to "returnAddress", "disposition" to "sourceDisposition")) require(call[raw] == witness[composed])
            val id = call.nullableText("callerCanonicalId")
            val rva = call.getValue("callerRva")
            val exclusion = id?.let(boundary.excludedFunctions::get)
            if (exclusion != null) {
                require(exclusion.rva != null && rva == hex(exclusion.rva))
                exclusions += obj("id" to str("machine-site-$index"), "side" to str("oracle"), "ownerId" to str(id), "observations" to refs(index))
                oracleExclusionEvidence[id] = exclusion.evidence
                continue
            }
            val caller = id?.takeIf { it in boundary.oracleFunctions && rva == hex(boundary.oracleFunctions.getValue(it).rva) }
            val direct = call.text("classification") == "direct-call"
            val externalId = witness.nullableText("externalTargetId")
            val externalPositive = witness.text("compositionDisposition") == "static-import-request-reference" &&
                witness.text("targetBindingDisposition") == "static-import-request-reference"
            if (externalPositive) require(externalId in tokens && caller != null)
            val target = call.nullableText("targetCanonicalId")?.takeIf { it in boundary.oracleFunctions &&
                call["directTargetRva"] == hex(boundary.oracleFunctions.getValue(it).rva) }
            val internalPositive = call.text("disposition") == "positive-internal-exact-start" && caller != null && target != null
            require(!internalPositive || !externalPositive)
            val selected = when { internalPositive -> targets("function", requireNotNull(target))
                externalPositive -> targets("external", requireNotNull(externalId)); else -> JsonNull }
            val returned = call.nullableText("fallthroughAddress")?.removePrefix("0x")?.toULong(16)?.let {
                if (it >= base) coordinate(hex(it - base)) else null } ?: JsonNull
            oracleSites += obj("id" to str("machine-site-$index"), "callerId" to (caller?.let(::str) ?: JsonNull),
                "rawOwner" to coordinate(rva), "instruction" to coordinate(call.getValue("instructionRva")), "return" to returned,
                "category" to str(if (!direct) "indirect" else if (externalPositive) "external" else if (internalPositive) "internal" else "unknown"),
                "state" to str(if (selected == JsonNull) "oracle-unobservable" else "observable"), "targets" to selected, "observations" to refs(index))
        }
        val consolidated = arrayListOf<JsonObject>()
        fun consolidate(sites: List<JsonObject>, side: String): List<JsonObject> {
            val groups = linkedMapOf<String, MutableList<JsonObject>>()
            for (site in sites) {
                step()
                val owner = site["callerId"]
                val instruction = site["instruction"]
                val image = (instruction as? JsonObject)?.get("space") == str("image")
                val key = if (owner != JsonNull && image) OracleJson.canonicalBytes(JsonArray(listOf(requireNotNull(owner), requireNotNull(instruction)))).decodeToString()
                    else "unjoined:${site.text("id")}"
                groups.getOrPut(key) { arrayListOf() } += site
            }
            return groups.values.map { group ->
                if (group.size == 1) group.single() else {
                    val first = group.first()
                    val agreement = group.all { row -> listOf("callerId", "rawOwner", "instruction", "return", "category", "state", "targets").all { row[it] == first[it] } }
                    consolidated += obj("side" to str(side), "retainedId" to first.getValue("id"),
                        "originalIds" to JsonArray(group.map { it.getValue("id") }), "agreement" to JsonPrimitive(agreement))
                    JsonObject(first + mapOf("observations" to JsonArray(group.flatMap { it.getValue("observations").jsonArray })) +
                        if (agreement) emptyMap() else mapOf("category" to str("unknown"), "targets" to JsonNull,
                            "return" to JsonNull, "state" to str(if (side == "oracle") "oracle-unobservable" else "recovered-unknown")))
                }
            }
        }
        val oracleFinal = consolidate(oracleSites, "oracle")
        val recoveryFinal = consolidate(refined, "recovered")
        val machineSource = obj("id" to str(sourceId), "role" to str("oracle"), "sha256" to str(OracleArtifacts.sha256(machineBytes)),
            "bytes" to JsonPrimitive(machineBytes.size), "policySha256" to str(policySha),
            "recordIds" to JsonArray(calls.indices.map { str("calls/$it") }))
        val gaps = arrayListOf(obj("id" to str("positive-only-source"), "sourceId" to str(sourceId), "callerId" to JsonNull,
            "reason" to str("Positive observations enumerate this input stream only; unobserved code and negative call coverage remain unavailable.")))
        canonical.filter { it.text("id") in boundary.oracleFunctions && it.text("disposition") != "owned-symbol-extent" }.forEachIndexed { index, row ->
            gaps += obj("id" to str("canonical-coverage-$index"), "sourceId" to str(sourceId), "callerId" to row.getValue("id"),
                "reason" to row.getValue("disposition")) }
        val input = obj("schemaVersion" to JsonPrimitive(1), "provider" to str("structural-call-population-input-v1"),
            "binding" to JsonObject(fragmentBinding + ("externalNamespaceSha256" to str(namespaceSha))),
            "sources" to JsonArray(listOf(nativeSource, machineSource)), "oracleSites" to JsonArray(oracleFinal),
            "recoveredSites" to JsonArray(recoveryFinal), "exclusions" to JsonArray(exclusions), "coverageGaps" to JsonArray(gaps))
        val inputBytes = OracleJson.canonicalBytes(input, StructuralCallPopulationLimitsV1().json())
        step()
        val report = StructuralCallPopulationV1.derive(inputBytes, boundary)
        step()
        val evidence = obj("schemaVersion" to JsonPrimitive(1), "provider" to str("structural-native-external-projection-v1"),
            "policySha256" to str(policySha), "upstreamNativePolicySha256" to originalSource.getValue("policySha256"),
            "upstreamExternalPolicySha256" to str(external.policySha256),
            "coreClaimsSha256" to str(OracleArtifacts.sha256(coreEvidenceBytes)), "coreFragmentSha256" to str(OracleArtifacts.sha256(coreFragmentBytes)),
            "externalClaimsSha256" to str(external.evidenceSha256), "machineReportSha256" to str(OracleArtifacts.sha256(machineBytes)),
            "independentExternalReportSha256" to str(OracleArtifacts.sha256(independentBytes)), "recoveredExternalReportSha256" to str(OracleArtifacts.sha256(recoveredBytes)),
            "externalNamespaceSha256" to str(namespaceSha), "ledgerInputSha256" to str(OracleArtifacts.sha256(inputBytes)),
            "ledgerReportSha256" to str(OracleArtifacts.sha256(report)), "nativeRawRecords" to JsonPrimitive(external.rawRecordCount),
            "nativeRawSites" to JsonPrimitive(external.rawSiteCount), "independentRawSites" to JsonPrimitive(calls.size),
            "nativeExclusionEvidence" to fragment.getValue("exclusionEvidence"), "independentExclusionEvidence" to JsonObject(oracleExclusionEvidence),
            "consolidations" to JsonArray(consolidated), "productionVerified" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(false))
        val evidenceBytes = OracleJson.canonicalBytes(evidence, LIMITS)
        step()
        return StructuralNativeExternalCallProjectionResultV1(inputBytes, report, evidenceBytes)
    }
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.nullableText(key: String) = getValue(key).takeUnless { it == JsonNull }?.jsonPrimitive?.content
    private fun JsonObject.number(key: String) = getValue(key).jsonPrimitive.long
    private fun JsonObject.rows(key: String) = getValue(key).jsonArray.map { it.jsonObject }
    private fun str(value: String) = JsonPrimitive(value)
    private fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
    private fun hex(value: ULong?): JsonElement = value?.let { str("0x" + it.toString(16)) } ?: JsonNull
    private fun coordinate(offset: JsonElement): JsonElement = if (offset == JsonNull) JsonNull else obj("space" to str("image"), "offset" to offset)
    private fun targets(kind: String, id: String) = JsonArray(listOf(obj("kind" to str(kind), "id" to str(id))))
}
