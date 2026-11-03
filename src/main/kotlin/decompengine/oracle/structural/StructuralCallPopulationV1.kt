package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.*

/** Limits apply before indexes, coordinate expansion or report allocation. Raw sources are not read here. */
data class StructuralCallPopulationLimitsV1(
    val maximumInputBytes: Int = 32 * 1024 * 1024,
    val maximumReportBytes: Int = 64 * 1024 * 1024,
    val maximumSources: Int = 256,
    val maximumRecords: Int = 100_000,
    val maximumSites: Int = 100_000,
) {
    init {
        require(maximumInputBytes in 1..32 * 1024 * 1024 && maximumReportBytes in 1..64 * 1024 * 1024)
        require(maximumSources in 1..256 && maximumRecords in 1..100_000 && maximumSites in 1..100_000)
    }
    internal fun json(output: Boolean = false) = StrictJsonLimits(
        maximumInputBytes = maximumInputBytes,
        maximumCanonicalBytes = if (output) maximumReportBytes else maximumInputBytes,
        maximumDepth = 16, maximumNodes = 1_000_000, maximumStringBytes = 4096,
        maximumTotalStringBytes = if (output) maximumReportBytes else maximumInputBytes,
    )
}

/**
 * Closed diagnostic population algebra. Parsing commitments does not authenticate their sources.
 * This API cannot establish negative coverage, CALLS admission, or a production threshold result.
 * The complete native and independent source streams must be replayed by their respective owners.
 */
object StructuralCallPopulationV1 {
    fun derive(
        bytes: ByteArray,
        boundary: StructuralSelectedBoundaryProjectionV1,
        limits: StructuralCallPopulationLimitsV1 = StructuralCallPopulationLimitsV1(),
    ): ByteArray = evaluate(bytes, boundary, limits, emptySet(), false)

    /** Recomputes every disposition and metric; an edited, rehashed report is not evidence. */
    fun validateReport(
        inputBytes: ByteArray,
        boundary: StructuralSelectedBoundaryProjectionV1,
        reportBytes: ByteArray,
        limits: StructuralCallPopulationLimitsV1 = StructuralCallPopulationLimitsV1(),
    ) {
        require(reportBytes.size <= limits.maximumReportBytes)
        require(derive(inputBytes, boundary, limits).contentEquals(reportBytes)) {
            "call population report differs from independent input recomputation"
        }
    }

    /** Authored controls exercise the negative-site rule; their output is never production authority. */
    internal fun deriveFixtureWithNegativeSites(
        bytes: ByteArray,
        boundary: StructuralSelectedBoundaryProjectionV1,
        negativeSites: Set<FixtureNegativeSite>,
        limits: StructuralCallPopulationLimitsV1 = StructuralCallPopulationLimitsV1(),
    ): ByteArray = evaluate(bytes, boundary, limits, negativeSites, true)

    internal data class FixtureNegativeSite(val oracleCallerId: String, val instructionRva: ULong)

    private fun evaluate(
        bytes: ByteArray,
        boundary: StructuralSelectedBoundaryProjectionV1,
        limits: StructuralCallPopulationLimitsV1,
        negativeSites: Set<FixtureNegativeSite>,
        fixture: Boolean,
    ): ByteArray {
        require(bytes.size <= limits.maximumInputBytes) { "call population input exceeds its byte limit" }
        val snapshot = bytes.copyOf()
        val root = OracleJson.parseCanonical(snapshot, limits.json()).obj("call population", ROOT_FIELDS)
        require(root.long("schemaVersion") == 1L && root.text("provider") == "structural-call-population-input-v1")
        val binding = root.getValue("binding").obj("binding", BINDING_FIELDS)
        require(binding.digest("inputSha256") == boundary.inputSha256 &&
            binding.digest("programModelSha256") == boundary.programModelSha256 &&
            binding.digest("boundaryObservationSha256") == boundary.boundaryObservationSha256) {
            "call population differs from the exact selected model or boundary observation"
        }
        val externalNamespace = binding.nullableDigest("externalNamespaceSha256")
        val sources = linkedMapOf<String, Source>()
        var rawCount = 0
        for (element in root.array("sources", limits.maximumSources)) {
            val value = element.obj("source", SOURCE_FIELDS)
            val id = value.identifier("id")
            val role = value.text("role").also { require(it in SIDES) }
            value.digest("sha256"); value.digest("policySha256")
            require(value.long("bytes") in 1..1024L * 1024 * 1024)
            val records = value.array("recordIds", limits.maximumRecords).map { it.identifier("source record ID") }
            require(records.toSet().size == records.size) { "source repeats a raw record" }
            rawCount = Math.addExact(rawCount, records.size)
            require(rawCount <= limits.maximumRecords) { "raw call census exceeds its record limit" }
            require(sources.put(id, Source(role, records.toSet(), value)) == null) { "duplicate source ID" }
        }
        val consumed = hashSetOf<RawRef>()
        fun observations(value: JsonObject, side: String): List<RawRef> {
            val refs = value.array("observations", limits.maximumRecords).map { raw ->
                val item = raw.obj("raw reference", setOf("sourceId", "recordId"))
                val ref = RawRef(item.identifier("sourceId"), item.identifier("recordId"))
                val source = requireNotNull(sources[ref.source]) { "raw reference has no bound source" }
                require(source.side == side && ref.record in source.records) { "raw reference differs from its side or census" }
                require(consumed.add(ref)) { "raw call record was consumed more than once" }
                ref
            }
            require(refs.isNotEmpty()) { "call obligation has no original observation" }
            return refs
        }
        fun sites(field: String, side: String): List<Site> {
            val identifiers = hashSetOf<String>()
            return root.array(field, limits.maximumSites).map { element ->
                val value = element.obj("call site", SITE_FIELDS)
                val id = value.identifier("id")
                require(identifiers.add(id)) { "duplicate call obligation ID" }
                val caller = value.nullableIdentifier("callerId")
                val universe = if (side == "oracle") boundary.oracleFunctions.keys else boundary.recoveredFunctions.keys
                require(caller == null || caller in universe) { "call caller is outside the complete selected universe" }
                val rawOwner = coordinate(value.getValue("rawOwner"))
                if (caller != null) {
                    val start = if (side == "oracle") boundary.oracleFunctions.getValue(caller).rva
                        else boundary.recoveredFunctions.getValue(caller).rva
                    require(rawOwner == Coordinate("image", start)) {
                        "resolved caller does not match the retained raw owner coordinate"
                    }
                }
                val instruction = coordinate(value.getValue("instruction"))
                val returned = coordinate(value.getValue("return"))
                val category = value.text("category").also { require(it in CATEGORIES) }
                val state = value.text("state")
                require(state in if (side == "oracle") setOf("observable", "oracle-unobservable")
                    else setOf("recovered", "recovered-unknown")) { "wrong evidence state for call population side" }
                val concrete = state == "observable" || state == "recovered"
                val targets = if (value.getValue("targets") == JsonNull) null else value.array("targets", 16).map { raw ->
                    val item = raw.obj("call target", setOf("kind", "id"))
                    val kind = item.text("kind").also { require(it in setOf("function", "external")) }
                    val target = item.identifier("id")
                    if (kind == "function") require(target in universe) { "call target is outside the selected identity universe" }
                    else require(externalNamespace != null && target.matches(Regex("ext-[a-f0-9]{64}"))) {
                        "external target requires an explicit namespace commitment and closed identity token"
                    }
                    Target(kind, target)
                }
                require(concrete == (targets != null)) { "unknown call evidence must have a null target value" }
                if (targets != null) {
                    require(targets.isNotEmpty() && targets.distinct().size == targets.size)
                    require(targets == targets.sortedWith(compareBy(Target::kind, Target::id))) { "target set is not canonical" }
                    when (category) {
                        "internal" -> require(targets.size == 1 && targets.single().kind == "function")
                        "external" -> require(targets.size == 1 && targets.single().kind == "external")
                        "indirect" -> Unit
                        else -> error("unknown category cannot carry a concrete target")
                    }
                }
                val refs = observations(value, side)
                Site(id, caller, rawOwner, instruction, returned, category, state, targets, refs, value)
            }
        }
        val oracle = sites("oracleSites", "oracle")
        val recovered = sites("recoveredSites", "recovered")
        require(oracle.size + recovered.size <= limits.maximumSites) { "combined call obligation limit exceeded" }
        val excluded = root.array("exclusions", limits.maximumRecords).map { element ->
            val value = element.obj("exclusion", setOf("id", "side", "ownerId", "observations"))
            value.identifier("id")
            val side = value.text("side").also { require(it in SIDES) }
            val owner = value.identifier("ownerId")
            require(owner in if (side == "oracle") boundary.excludedOracleIds else boundary.ignoredRecoveredIds) {
                "call exclusion lacks exact selected-boundary owner evidence"
            }
            observations(value, side)
            value
        }
        require(excluded.map { it.text("id") }.distinct().size == excluded.size) { "duplicate exclusion ID" }
        for ((id, source) in sources) require(source.records.all { RawRef(id, it) in consumed }) {
            "raw call source contains an undisposed observation"
        }
        require(consumed.size == rawCount)
        val gaps = root.array("coverageGaps", limits.maximumRecords).map { element ->
            val value = element.obj("coverage gap", setOf("id", "sourceId", "callerId", "reason"))
            value.identifier("id")
            require(sources[value.identifier("sourceId")]?.side == "oracle") { "coverage gap requires an independent oracle source" }
            val caller = value.nullableIdentifier("callerId")
            require(caller == null || caller in boundary.oracleFunctions || caller in boundary.excludedOracleIds)
            require(value.text("reason").length in 1..1024)
            value
        }
        require(gaps.map { it.text("id") }.distinct().size == gaps.size)

        // Only independent oracle observations can connect a call instruction to a return PC.
        val returnPairs = hashMapOf<Anchor, Anchor>()
        val instructionPairs = hashMapOf<Anchor, Anchor>()
        for (site in oracle) if (site.caller != null && site.instruction != null && site.returned != null &&
            executable(site.instruction, boundary) && executable(site.returned, boundary)) {
            val instruction = Anchor(site.caller, "instruction", site.instruction)
            val returned = Anchor(site.caller, "return", site.returned)
            require(returnPairs.putIfAbsent(returned, instruction).let { it == null || it == instruction } &&
                instructionPairs.putIfAbsent(instruction, returned).let { it == null || it == returned }) {
                "independent instruction/return coordinates are not one-to-one"
            }
        }
        fun anchor(site: Site, side: String): Anchor? {
            val caller = site.caller?.let { if (side == "oracle") it else boundary.recoveredToOracle[it] } ?: return null
            if (site.instruction != null && !executable(site.instruction, boundary)) return null
            if (site.returned != null && !executable(site.returned, boundary)) return null
            val direct = site.instruction?.takeIf { executable(it, boundary) }?.let { Anchor(caller, "instruction", it) }
            val returned = site.returned?.takeIf { executable(it, boundary) }?.let { Anchor(caller, "return", it) }
            if (direct != null && returned != null) {
                // Recovered pairs do not create authority; contradiction with an independent pair prevents alignment.
                if (instructionPairs[direct]?.let { it != returned } == true ||
                    returnPairs[returned]?.let { it != direct } == true) return null
            }
            return direct ?: returned?.let { returnPairs[it] ?: it }
        }
        val oracleAnchors = hashMapOf<Anchor, Site>()
        for (site in oracle) anchor(site, "oracle")?.let {
            require(oracleAnchors.put(it, site) == null) { "oracle site duplicates a normalized anchor; consolidate original observations explicitly" }
        }
        val recoveredAnchors = hashMapOf<Anchor, Site>()
        for (site in recovered) anchor(site, "recovered")?.let {
            require(recoveredAnchors.put(it, site) == null) { "recovery duplicates a normalized anchor; consolidate original observations explicitly" }
        }
        for (negative in negativeSites) {
            require(fixture && negative.oracleCallerId in boundary.oracleFunctions)
            val key = Anchor(negative.oracleCallerId, "instruction", Coordinate("image", negative.instructionRva))
            require(executable(key.coordinate, boundary) && key !in oracleAnchors) {
                "negative fixture witness conflicts with a positive obligation or executable extent"
            }
        }

        val rows = arrayListOf<JsonObject>()
        val unresolved = arrayListOf<JsonObject>()
        val usedRecovery = hashSetOf<String>()
        fun normalizedTargets(site: Site): List<Target>? = site.targets?.map { target ->
            if (target.kind == "external") target else Target("function", boundary.recoveredToOracle[target.id] ?: return null)
        }?.sortedWith(compareBy(Target::kind, Target::id))
        for (expected in oracle.sortedBy { it.id }) {
            val selected = anchor(expected, "oracle")?.let(recoveredAnchors::get)
            selected?.let { require(usedRecovery.add(it.id)) }
            val normalized = selected?.let(::normalizedTargets)
            val outcome = when {
                expected.state == "oracle-unobservable" -> "oracle-unobservable"
                selected == null || selected.state == "recovered-unknown" -> "recovered-unknown"
                normalized == null -> "contradicted"
                expected.category == selected.category && expected.targets == normalized -> "exact"
                else -> "contradicted"
            }
            rows += row(expected, selected, outcome)
        }
        for (site in recovered.sortedBy { it.id }) if (site.id !in usedRecovery) {
            val key = anchor(site, "recovered")
            val negative = key != null && key.kind == "instruction" &&
                FixtureNegativeSite(key.caller, key.coordinate.offset) in negativeSites
            if (negative) rows += row(null, site, "fabricated")
            else unresolved += JsonObject(mapOf(
                "recoveredId" to JsonPrimitive(site.id), "category" to JsonPrimitive(site.category),
                "reason" to JsonPrimitive(when {
                    site.caller == null -> "unowned-recovered-site"
                    site.caller !in boundary.recoveredToOracle -> "unmapped-recovered-caller"
                    site.instruction == null && site.returned == null -> "unlocated-recovered-site"
                    key == null -> "unresolved-coordinate-or-pair"
                    else -> "independent-negative-coverage-unavailable"
                }),
            ))
        }
        val outcomes = OUTCOMES.associateWith { outcome -> rows.count { it.text("outcome") == outcome } }
        require(rows.count { it["oracleId"] != JsonNull } == oracle.size)
        require(rows.count { it["recoveredId"] != JsonNull } + unresolved.size == recovered.size)
        fun metrics(category: String?): JsonObject {
            val expected = oracle.count { category == null || it.category == category }
            val claims = recovered.count { category == null || it.category == category }
            val credit = rows.count { it.text("outcome") == "exact" &&
                (category == null || it["oracleCategory"] == JsonPrimitive(category)) }
            return JsonObject(mapOf(
                "oracleDenominator" to JsonPrimitive(expected), "recoveredDenominator" to JsonPrimitive(claims),
                "exact" to JsonPrimitive(credit), "claimPrecision" to ratio(credit, claims),
                "oracleRecall" to ratio(credit, expected),
            ))
        }
        val report = JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-call-population-report-v1"), "schemaVersion" to JsonPrimitive(1),
            "authority" to JsonPrimitive(if (fixture) "fixture-negative-site-controls-only" else "untrusted-population-projection"),
            "productionVerified" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "negativeCoverageAuthenticated" to JsonPrimitive(false),
            "inputSha256" to JsonPrimitive(OracleArtifacts.sha256(snapshot)), "binding" to binding,
            "twin" to JsonPrimitive(boundary.twin), "otherTwinAvailable" to JsonPrimitive(false),
            "sources" to JsonArray(sources.toSortedMap().values.map { it.document }),
            "oracleSites" to JsonArray(oracle.sortedBy { it.id }.map { it.document }),
            "recoveredSites" to JsonArray(recovered.sortedBy { it.id }.map { it.document }),
            "exclusions" to JsonArray(excluded.sortedBy { it.text("id") }),
            "coverageGaps" to JsonArray(gaps.sortedBy { it.text("id") }),
            "rows" to JsonArray(rows), "unresolvedRecovered" to JsonArray(unresolved),
            "outcomes" to JsonObject(outcomes.mapValues { JsonPrimitive(it.value) }),
            "unresolvedRecoveredCount" to JsonPrimitive(unresolved.size),
            "rawObservationCount" to JsonPrimitive(rawCount),
            "rawObservationDispositionCount" to JsonPrimitive(consumed.size),
            "oracleFunctionCount" to JsonPrimitive(boundary.oracleFunctions.size),
            "recoveredFunctionCount" to JsonPrimitive(boundary.recoveredFunctions.size),
            "metrics" to metrics(null),
            "dimensions" to JsonObject(CATEGORIES.associateWith(::metrics)),
        ))
        return OracleJson.canonicalBytes(report, limits.json(output = true))
    }

    private data class Source(val side: String, val records: Set<String>, val document: JsonObject)
    private data class RawRef(val source: String, val record: String)
    private data class Coordinate(val space: String, val offset: ULong)
    private data class Target(val kind: String, val id: String)
    private data class Anchor(val caller: String, val kind: String, val coordinate: Coordinate)
    private data class Site(val id: String, val caller: String?, val rawOwner: Coordinate?,
        val instruction: Coordinate?, val returned: Coordinate?, val category: String, val state: String,
        val targets: List<Target>?, val observations: List<RawRef>, val document: JsonObject)

    private fun row(oracle: Site?, recovered: Site?, outcome: String) = JsonObject(mapOf(
        "oracleId" to (oracle?.id?.let(::JsonPrimitive) ?: JsonNull),
        "recoveredId" to (recovered?.id?.let(::JsonPrimitive) ?: JsonNull),
        "oracleCategory" to (oracle?.category?.let(::JsonPrimitive) ?: JsonNull),
        "recoveredCategory" to (recovered?.category?.let(::JsonPrimitive) ?: JsonNull),
        "outcome" to JsonPrimitive(outcome),
    ))
    private fun ratio(numerator: Int, denominator: Int): JsonElement = if (denominator == 0) JsonNull else
        JsonObject(mapOf("numerator" to JsonPrimitive(numerator), "denominator" to JsonPrimitive(denominator)))
    private fun coordinate(raw: JsonElement): Coordinate? {
        if (raw == JsonNull) return null
        val value = raw.obj("coordinate", setOf("space", "offset"))
        val space = value.identifier("space")
        val offset = value.text("offset")
        require(offset.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "coordinate is not a canonical unsigned offset" }
        return Coordinate(space, offset.drop(2).toULong(16))
    }
    private fun executable(value: Coordinate, boundary: StructuralSelectedBoundaryProjectionV1): Boolean =
        value.space == "image" && boundary.executableRvaRanges.any { value.offset >= it.first && value.offset < it.second }
    private fun JsonElement.obj(label: String, fields: Set<String>): JsonObject =
        (this as? JsonObject)?.also { require(it.keys == fields) { "$label has unknown or missing fields" } }
            ?: error("$label must be an object")
    private fun JsonObject.text(name: String): String = (getValue(name) as? JsonPrimitive)?.also { require(it.isString) }?.content
        ?: error("$name must be a string")
    private fun JsonObject.long(name: String): Long = (getValue(name) as? JsonPrimitive)?.also { require(!it.isString) }?.longOrNull
        ?: error("$name must be an integer")
    private fun JsonElement.identifier(label: String): String = (this as? JsonPrimitive)?.also { require(it.isString) }?.content
        ?.also { require(it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}"))) { "$label is not a bounded identity" } }
        ?: error("$label must be a string")
    private fun JsonObject.identifier(name: String) = getValue(name).identifier(name)
    private fun JsonObject.nullableIdentifier(name: String): String? = if (getValue(name) == JsonNull) null else identifier(name)
    private fun JsonObject.digest(name: String) = text(name).also { require(it.matches(Regex("[a-f0-9]{64}"))) }
    private fun JsonObject.nullableDigest(name: String): String? = if (getValue(name) == JsonNull) null else digest(name)
    private fun JsonObject.array(name: String, maximum: Int): JsonArray =
        (getValue(name) as? JsonArray)?.also { require(it.size <= maximum) { "$name exceeds its item limit" } }
            ?: error("$name must be an array")

    private val SIDES = setOf("oracle", "recovered")
    private val CATEGORIES = listOf("internal", "external", "indirect", "unknown")
    private val OUTCOMES = listOf("exact", "abi-equivalent", "recovered-unknown", "oracle-unobservable", "contradicted", "fabricated")
    private val ROOT_FIELDS = setOf("provider", "schemaVersion", "binding", "sources", "oracleSites", "recoveredSites", "exclusions", "coverageGaps")
    private val BINDING_FIELDS = setOf("inputSha256", "programModelSha256", "boundaryObservationSha256", "externalNamespaceSha256")
    private val SOURCE_FIELDS = setOf("id", "role", "sha256", "bytes", "policySha256", "recordIds")
    private val SITE_FIELDS = setOf("id", "callerId", "rawOwner", "instruction", "return", "category", "state", "targets", "observations")
}
