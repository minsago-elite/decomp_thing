package decompengine.oracle.machinecalls

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Closed, bounded consistency validation, not an instruction decoder or authenticity verifier.
 * Positive records still require the independently authenticated inputs and decoder that produced
 * them. Neither this validator nor a successful report grants negative or release authority.
 */
object IndependentMachineCallReportV1 {
    fun parseComponent(bytes: ByteArray): JsonObject {
        val document = OracleJson.parseCanonical(bytes, HARD_LIMITS, ::checkpoint).record()
        validateComponent(document)
        return document
    }

    fun validateComponent(document: JsonObject) = validate(document, worker = false)

    internal fun validateWorker(document: JsonObject, expectedRequestSha256: String, request: IndependentMachineCallRequestIdentity) {
        digest(expectedRequestSha256)
        require(OracleArtifacts.sha256(request.canonicalBytes) == expectedRequestSha256) { "expected request digest does not bind the request" }
        validate(document, worker = true)
        require(document.string("requestSha256") == expectedRequestSha256) { "worker request commitment differs" }
        require(document["runtime"] == request.reportRuntimeJson()) { "worker runtime commitment differs" }
        require(document.string("inputSha256") == request.richFile.sha256 && document.number("inputBytes") == request.richFile.bytes &&
            document.string("canonicalOracleSha256") == request.canonicalOracle.sha256 &&
            document.string("artifactManifestSha256") == request.manifestSha256 && document["limits"] == request.limits.toJson()) {
            "worker input or limit commitments differ"
        }
    }

    private fun validate(document: JsonObject, worker: Boolean) {
        // Applies equally to parsed input and caller-constructed JSON (including depth/node/string bounds).
        OracleJson.canonicalBytes(document, HARD_LIMITS, ::checkpoint)
        document.keysExactly(COMPONENT_KEYS + if (worker) setOf("requestSha256", "runtime", "containmentStatus") else emptySet())
        require(document.number("schemaVersion") == 1L && document.string("kind") == "independent-machine-call-positive-observations" &&
            document.string("scope") == "component") { "unsupported machine-call report" }
        listOf("complete", "releaseEligible", "negativeCompleteness").forEach { document.flag(it, false) }
        listOf("canonicalPopulationComplete", "rawSymbolPopulationComplete").forEach { document.flag(it, true) }
        listOf("inputSha256", "canonicalOracleSha256", "artifactManifestSha256").forEach { digest(document.string(it)) }
        val inputBytes = document.number("inputBytes", 1, 512L * 1024 * 1024)
        val base = document.address("imageBase")!!
        require(document.string("languageId") == "x86:LE:64:default" && document.string("languageVersion") == "4.8")
        require(document.string("decoderAuthentication") == if (worker) "authenticated-bundled-worker-v1" else "external-worker-required")
        if (worker) {
            digest(document.string("requestSha256"))
            require(document.string("containmentStatus") == "external-owner-required")
            val runtime = document.getValue("runtime").record()
            runtime.keysExactly(setOf("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256",
                "bundleManifestSha256", "languageId", "languageVersion"))
            listOf("archiveSha256", "bridgeSha256", "bundleManifestSha256").forEach { digest(runtime.string(it)) }
            require(runtime.string("languageId") == document.string("languageId") && runtime.string("languageVersion") == document.string("languageVersion"))
        }
        val limitRecord = document.getValue("limits").record()
        limitRecord.keysExactly(setOf("maximumRoots", "maximumInstructionsPerRoot", "maximumInstructions", "maximumCalls",
            "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis"))
        val limits = MachineCallLimitsV1(limitRecord.number("maximumRoots", 1, 131072).toInt(),
            limitRecord.number("maximumInstructionsPerRoot", 1, 1000000).toInt(), limitRecord.number("maximumInstructions", 1, 10000000),
            limitRecord.number("maximumCalls", 1, 1000000).toInt(), limitRecord.number("maximumWorkUnits", 1, 100000000),
            limitRecord.number("maximumOutputBytes", 1, 64L * 1024 * 1024).toInt(), limitRecord.number("maximumWallMillis", 1, 1800000))
        OracleJson.canonicalBytes(document, IndependentMachineCallsV1.outputLimits(limits), ::checkpoint)
        require(document.number("canonicalOracleRecordLimit") == 20000L)

        val locators = hashSetOf<String>()
        val roots = document.array("roots", limits.maximumRoots).map { raw ->
            checkpoint("root")
            val root = raw.record()
            root.keysExactly(setOf("id", "rva", "endExclusiveRva", "fileOffset", "ownershipProblems", "traversalStops",
                "traversalStopEvents", "instructionAttempts", "negativeCompleteness", "origins"))
            root.flag("negativeCompleteness", false)
            val id = root.string("id", 16400)
            val rva = root.address("rva", nullable = true)
            val endRva = root.address("endExclusiveRva", nullable = true)
            val offset = root.nullableNumber("fileOffset")
            val problems = root.strings("ownershipProblems", OWNERSHIP_PROBLEMS)
            val stops = root.strings("traversalStops", STOP_REASONS)
            val attempts = root.number("instructionAttempts", 0, limits.maximumInstructionsPerRoot.toLong())
            val origins = root.array("origins", limits.maximumRoots)
            require(origins.isNotEmpty()) { "root has no origin" }
            var previousLocator: String? = null
            var coordinates: List<JsonElement>? = null
            var value = 0UL
            var size = 0UL
            origins.forEach { originRaw ->
                checkpoint("origin")
                val origin = originRaw.record()
                origin.keysExactly(setOf("name", "locator", "type", "binding", "visibility", "other", "sectionKind", "sectionIndex", "sectionName", "value", "size"))
                val name = origin.string("name", 8192, empty = true)
                require(name.codePointCount(0, name.length) <= 4096 && name.toByteArray(Charsets.UTF_8).size <= 16384)
                val locator = origin.string("locator", 16384)
                require(locator.toByteArray(Charsets.UTF_8).size <= 16384)
                require(locators.add(locator) && (previousLocator == null || previousLocator!! < locator)) { "duplicate or unordered origin locator" }
                previousLocator = locator
                val type = origin.number("type")
                require(type == 2L || type == 10L)
                origin.number("binding", 0, 15)
                val other = origin.number("other", 0, 255)
                require(origin.number("visibility", 0, 3) == (other and 3L))
                val section = origin.string("sectionKind")
                require(section in setOf("defined", "undefined", "common", "absolute", "reserved"))
                val sectionIndex = origin.number("sectionIndex", 0, 0xffffffffL)
                val sectionName = origin.nullableString("sectionName", 4096, empty = true)
                require((section == "defined") == (sectionName != null))
                require(when (section) {
                    "defined" -> sectionIndex in 1..131071
                    "undefined" -> sectionIndex == 0L
                    "absolute" -> sectionIndex == 0xfff1L
                    "common" -> sectionIndex == 0xfff2L
                    else -> sectionIndex >= 0xff00L && sectionIndex != 0xfff1L && sectionIndex != 0xfff2L
                }) { "symbol section identity disagrees with kind" }
                value = origin.address("value")!!
                size = origin.address("size")!!
                val current = listOf(origin.getValue("value"), origin.getValue("size"), origin.getValue("sectionIndex"), origin.getValue("sectionKind"))
                require(coordinates == null || coordinates == current) { "root aliases disagree on extent coordinates" }
                coordinates = current
                require(type != 10L || "ifunc-resolver-identity-unresolved" in problems)
                require(section == "defined" || "non-defined-function-symbol" in problems)
            }
            require(id == "symbol-root:${origins.first().record().string("locator", 16384)}") { "root ID does not identify its first origin" }
            require(rva == value.takeIf { it >= base }?.minus(base)) { "root RVA differs from symbol value" }
            val end = if (size > 0UL && value <= ULong.MAX_VALUE - size) value + size else null
            require(endRva == end?.takeIf { it >= base }?.minus(base)) { "root end differs from symbol size" }
            require(rva != null || "below-image-base" in problems)
            require(size != 0UL || "zero-size-no-end-inference" in problems)
            require(size == 0UL || end != null || "extent-address-overflow" in problems)
            if (problems.isEmpty()) {
                require(rva != null && end != null && offset != null && offset <= inputBytes && size <= (inputBytes - offset).toULong()) {
                    "owned extent exceeds committed input"
                }
                require(attempts > 0) { "owned root was not attempted" }
            } else require(attempts == 0L && stops.isEmpty()) { "unowned root was traversed" }
            val events = root.array("traversalStopEvents", limits.maximumInstructions.toInt())
            var previousEvent: Stop? = null
            val eventReasons = sortedSetOf<String>()
            events.forEach { eventRaw ->
                checkpoint("traversal stop")
                val event = eventRaw.record()
                event.keysExactly(setOf("address", "rva", "reason", "targetAddress", "bytesKind", "bytes"))
                val address = event.address("address")!!
                require(event.address("rva", true) == address.takeIf { it >= base }?.minus(base))
                val reason = event.string("reason")
                require(reason in STOP_REASONS)
                val target = event.address("targetAddress", true)
                val bytesKind = event.nullableString("bytesKind")
                val bytes = event.nullableString("bytes", 64)
                require((bytesKind == null) == (bytes == null))
                if (bytes != null) {
                    require(bytesKind in setOf("available-window", "decoded-instruction"))
                    val length = byteLength(bytes)
                    require(length in 1..15 && end != null && address >= value && address < end && length.toULong() <= end - address)
                }
                require(reason != "decoder-refused-instruction" || bytesKind == "available-window")
                require(bytesKind != "available-window" || reason == "decoder-refused-instruction")
                require(end != null)
                when (reason) {
                    "control-flow-outside-owned-extent" -> if (target != null) {
                        require(bytesKind == "decoded-instruction" && (target < value || target >= end))
                    } else require(bytes == null && (address < value || address >= end))
                    "overlapping-instruction-paths" -> require(target == null && address >= value && address < end)
                    "decoder-refused-instruction" -> require(target == null && bytes != null &&
                        byteLength(bytes) == minOf(15UL, end - address).toInt())
                    "unresolved-indirect-jump" -> require(target == null && bytesKind == "decoded-instruction")
                    else -> require(bytesKind == "decoded-instruction")
                }
                val key = Stop(address, reason, target, bytesKind, bytes)
                previousEvent?.let { require(STOP_ORDER.compare(it, key) < 0) { "duplicate or unordered traversal stop" } }
                previousEvent = key
                eventReasons += reason
            }
            require(eventReasons.toList() == stops) { "traversal stop summaries differ from events" }
            require(events.isEmpty() || attempts > 0)
            Root(id, rva, endRva, value, end, problems, stops, attempts)
        }
        requireOrdered(roots, compareBy<Root> { it.rva == null }.thenBy { it.rva }.thenBy { it.id }, "roots")
        require(roots.map { it.id }.distinct().size == roots.size)
        require(locators.size <= limits.maximumRoots)
        val rootById = roots.associateBy { it.id }
        val rootsByRva = roots.filter { it.rva != null }.groupBy { it.rva!! }
        val population = document.array("canonicalPopulation", minOf(20000, limits.maximumRoots)).map { raw ->
            checkpoint("canonical population")
            val item = raw.record()
            item.keysExactly(setOf("id", "rva", "exclusion", "rootIds", "disposition"))
            val id = item.string("id", 4096)
            val rva = item.address("rva", true)
            if (rva != null) require(rva <= ULong.MAX_VALUE - base)
            val excluded = item.getValue("exclusion") != JsonNull
            if (excluded) {
                val exclusion = item.getValue("exclusion").record()
                exclusion.keysExactly(setOf("kind", "reason"))
                val kind = exclusion.string("kind")
                require(kind in setOf("compiler-generated", "inlined") && (kind == "inlined") == (rva == null))
                exclusion.string("reason", 16384)
            } else require(rva != null)
            val selected = rva?.let(rootsByRva::get).orEmpty()
            require(item.array("rootIds", limits.maximumRoots).map { it.string(16400) } == selected.map { it.id }) { "canonical root references differ" }
            val expected = when {
                rva == null -> "unresolved-no-emitted-address"
                selected.isEmpty() -> "unresolved-missing-symbol-extent"
                selected.size != 1 -> "unresolved-multiple-symbol-extents"
                selected.single().problems.isNotEmpty() -> "unresolved-symbol-extent"
                excluded -> "unresolved-canonical-exclusion-no-parent-inference"
                else -> "owned-symbol-extent"
            }
            require(item.string("disposition") == expected) { "canonical disposition disagrees with ownership" }
            Canonical(id, rva, excluded)
        }
        requireOrdered(population, compareBy<Canonical> { it.rva == null }.thenBy { it.rva }.thenBy { it.id }, "canonical population")
        require(population.map { it.id }.distinct().size == population.size)
        require(population.any { !it.excluded }) { "canonical population lacks a scoreable function" }
        val emitted = population.filter { it.rva != null }
        require(emitted.map { it.rva }.distinct().size == emitted.size)
        val canonicalByRva = emitted.associateBy { it.rva!! }
        validateOwnershipRelations(roots, canonicalByRva.keys.sorted())
        var previousCall: Pair<Int, ULong>? = null
        val rootOrder = roots.withIndex().associate { it.value.id to it.index }
        val callsPerRoot = hashMapOf<String, Int>()
        var positives = 0
        val calls = document.array("calls", limits.maximumCalls)
        calls.forEach { raw ->
            checkpoint("call")
            val call = raw.record()
            call.keysExactly(setOf("callerRoot", "callerRva", "callerCanonicalId", "instructionRva", "instructionBytes", "instructionLength",
                "classification", "directTargetRva", "directTargetAddress", "rawPcodeCallTargetAddress", "targetAgreement", "targetCanonicalId",
                "directTargetAddresses", "fallthroughAddress", "contextStatus", "disposition", "negativeCompleteness"))
            call.flag("negativeCompleteness", false)
            val root = requireNotNull(rootById[call.string("callerRoot", 16400)]) { "unknown caller root" }
            require(root.problems.isEmpty() && root.rva != null && root.end != null)
            require(call.address("callerRva") == root.rva)
            val siteRva = call.address("instructionRva")!!
            require(siteRva <= ULong.MAX_VALUE - base)
            val site = base + siteRva
            val length = call.number("instructionLength", 1, 15)
            require(byteLength(call.string("instructionBytes", 30)) == length.toInt() && site >= root.value && site < root.end &&
                length.toULong() <= root.end - site) { "call witness is outside its exact extent" }
            require(call.address("fallthroughAddress") == site + length.toULong())
            require(call.string("contextStatus") == "language-default-no-commits-v1")
            val key = rootOrder.getValue(root.id) to siteRva
            previousCall?.let { require(CALL_ORDER.compare(it, key) < 0) { "duplicate or unordered call site" } }
            previousCall = key
            callsPerRoot[root.id] = callsPerRoot.getOrDefault(root.id, 0) + 1
            val classification = call.string("classification")
            require(classification in setOf("direct-call", "indirect-call"))
            val targetAddress = call.address("directTargetAddress", true)
            require(call.address("rawPcodeCallTargetAddress", true) == targetAddress)
            val targets = call.array("directTargetAddresses", 1).map { it.address() }
            require(targets == targetAddress?.let { listOf(it) }.orEmpty())
            val targetRva = targetAddress?.takeIf { it >= base }?.minus(base)
            require(call.address("directTargetRva", true) == targetRva)
            require((classification == "direct-call") == (targetAddress != null))
            require(call.string("targetAgreement") == if (classification == "direct-call") "typed-flow-and-raw-call" else "computed-target-unresolved")
            val caller = canonicalByRva[root.rva]
            val target = targetRva?.let(canonicalByRva::get)
            require(call.nullableString("callerCanonicalId", 4096) == caller?.id && call.nullableString("targetCanonicalId", 4096) == target?.id)
            val targetRoots = targetRva?.let(rootsByRva::get).orEmpty()
            val expected = when {
                "overlapping-instruction-paths" in root.stops -> "unresolved-instruction-overlap"
                classification == "indirect-call" -> "unresolved-indirect-target"
                caller == null -> "unresolved-caller-outside-canonical-population"
                caller.excluded -> "unresolved-caller-canonical-exclusion"
                target == null -> "unresolved-target-outside-canonical-population"
                target.excluded -> "unresolved-target-canonical-exclusion"
                targetRoots.size != 1 || targetRoots.single().problems.isNotEmpty() -> "unresolved-target-extent"
                else -> "positive-internal-exact-start"
            }
            require(call.string("disposition") == expected) { "call disposition disagrees with canonical identity or extent evidence" }
            if (expected == "positive-internal-exact-start") positives++
        }
        roots.forEach { require(callsPerRoot.getOrDefault(it.id, 0) <= it.attempts) }
        val counts = document.getValue("counts").record()
        val expectedCounts = mapOf("rawFunctionSymbols" to locators.size.toLong(), "roots" to roots.size.toLong(),
            "canonicalFunctions" to population.size.toLong(), "instructionAttempts" to roots.sumOf { it.attempts },
            "physicalCallSites" to calls.size.toLong(), "positiveInternalCallSites" to positives.toLong(),
            "unresolvedCallSites" to (calls.size - positives).toLong(), "rootsWithUnresolvedOwnership" to roots.count { it.problems.isNotEmpty() }.toLong(),
            "rootsWithTraversalStops" to roots.count { it.stops.isNotEmpty() }.toLong())
        counts.keysExactly(expectedCounts.keys)
        expectedCounts.forEach { (key, value) -> require(counts.number(key) == value) { "report count differs: $key" } }
        require(counts.number("instructionAttempts") <= limits.maximumInstructions)
    }

    private fun validateOwnershipRelations(roots: List<Root>, canonicalStarts: List<ULong>) {
        roots.groupBy { it.value }.values.filter { it.size > 1 }.forEach { group ->
            group.forEach { require("conflicting-symbols-at-start" in it.problems) }
        }
        var previous: Root? = null
        roots.filter { it.rva != null && it.end != null }.sortedBy { it.value }.forEach { root ->
            checkpoint("ownership relation")
            val prior = previous
            if (prior != null && root.value < prior.end!!) {
                require("overlapping-symbol-extents" in root.problems && "overlapping-symbol-extents" in prior.problems)
            }
            if (prior == null || root.end!! > prior.end!!) previous = root
            val next = canonicalStarts.binarySearch(root.rva!!).let { if (it < 0) -it - 1 else it + 1 }
            if (next < canonicalStarts.size && canonicalStarts[next] < root.endRva!!) require("interior-canonical-start" in root.problems)
        }
    }

    private data class Root(val id: String, val rva: ULong?, val endRva: ULong?, val value: ULong, val end: ULong?,
        val problems: List<String>, val stops: List<String>, val attempts: Long)
    private data class Canonical(val id: String, val rva: ULong?, val excluded: Boolean)
    private data class Stop(val address: ULong, val reason: String, val target: ULong?, val bytesKind: String?, val bytes: String?)
    private val STOP_ORDER = compareBy<Stop> { it.address }.thenBy { it.reason }.thenBy { it.target }.thenBy { it.bytesKind }.thenBy { it.bytes }
    private val CALL_ORDER = compareBy<Pair<Int, ULong>> { it.first }.thenBy { it.second }
    private val COMPONENT_KEYS = setOf("schemaVersion", "kind", "scope", "complete", "releaseEligible", "negativeCompleteness",
        "canonicalPopulationComplete", "rawSymbolPopulationComplete", "inputSha256", "inputBytes", "canonicalOracleSha256", "artifactManifestSha256",
        "imageBase", "languageId", "languageVersion", "decoderAuthentication", "limits", "canonicalOracleRecordLimit", "canonicalPopulation", "roots", "calls", "counts")
    private val OWNERSHIP_PROBLEMS = setOf("ifunc-resolver-identity-unresolved", "non-defined-function-symbol", "below-image-base",
        "zero-size-no-end-inference", "extent-address-overflow", "extent-not-in-executable-section", "extent-not-in-one-file-backed-executable-load",
        "overlapping-load-ownership", "extent-file-range-invalid", "section-load-file-mapping-disagreement", "overlapping-symbol-extents",
        "conflicting-symbols-at-start", "interior-canonical-start")
    private val STOP_REASONS = setOf("control-flow-outside-owned-extent", "overlapping-instruction-paths", "decoder-refused-instruction",
        "unresolved-indirect-jump", "unsupported-pcode", "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow")
    private val HARD_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024, maximumCanonicalBytes = 64 * 1024 * 1024,
        maximumNodes = 1000000, maximumStringBytes = 64 * 1024 * 1024, maximumTotalStringBytes = 64 * 1024 * 1024)
    private fun checkpoint(stage: String) { check(!Thread.currentThread().isInterrupted) { "machine-call report validation interrupted: $stage" } }
    private fun digest(value: String) { require(value.matches(Regex("[0-9a-f]{64}"))) { "noncanonical SHA-256" } }
    private fun byteLength(value: String): Int { require(value.isNotEmpty() && value.length % 2 == 0 && value.matches(Regex("[0-9a-f]+"))); return value.length / 2 }
    private fun JsonElement.record(): JsonObject = this as? JsonObject ?: throw IllegalArgumentException("expected report object")
    private fun JsonObject.keysExactly(expected: Set<String>) { require(keys == expected) { "unknown or missing report fields: ${keys - expected}; ${expected - keys}" } }
    private fun JsonElement.string(maximum: Int = 16384, empty: Boolean = false): String {
        val primitive = this as? JsonPrimitive
        require(primitive != null && primitive.isString && primitive.content.length in (if (empty) 0 else 1)..maximum) { "expected bounded JSON string" }
        return primitive.content
    }
    private fun JsonObject.string(key: String, maximum: Int = 16384, empty: Boolean = false) = getValue(key).string(maximum, empty)
    private fun JsonObject.nullableString(key: String, maximum: Int = 16384, empty: Boolean = false): String? =
        getValue(key).takeUnless { it == JsonNull }?.string(maximum, empty)
    private fun JsonObject.flag(key: String, value: Boolean) { require(getValue(key) == JsonPrimitive(value)) { "invalid authority or population flag: $key" } }
    private fun JsonObject.number(key: String, minimum: Long = 0, maximum: Long = Long.MAX_VALUE): Long {
        val primitive = getValue(key) as? JsonPrimitive
        require(primitive != null && !primitive.isString && primitive.content.matches(Regex("0|[1-9][0-9]*"))) { "expected canonical nonnegative integer: $key" }
        val value = primitive.content.toLongOrNull()
        require(value != null && value in minimum..maximum) { "report number exceeds bound: $key" }
        return value
    }
    private fun JsonObject.nullableNumber(key: String): Long? = if (getValue(key) == JsonNull) null else number(key)
    private fun JsonElement.address(): ULong {
        val value = string(18)
        require(value.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "noncanonical address" }
        return value.removePrefix("0x").toULong(16)
    }
    private fun JsonObject.address(key: String, nullable: Boolean = false): ULong? =
        if (nullable && getValue(key) == JsonNull) null else getValue(key).address()
    private fun JsonObject.array(key: String, maximum: Int): JsonArray {
        val value = getValue(key) as? JsonArray
        require(value != null && value.size <= maximum) { "expected bounded array: $key" }
        return value
    }
    private fun JsonObject.strings(key: String, allowed: Set<String>): List<String> = array(key, allowed.size).map { it.string() }.also {
        require(it.all(allowed::contains) && it == it.distinct().sorted()) { "invalid reason inventory: $key" }
    }
    private fun <T> requireOrdered(items: List<T>, comparator: Comparator<T>, label: String) {
        require(items.zipWithNext().all { (left, right) -> comparator.compare(left, right) < 0 }) { "duplicate or unordered $label" }
    }
}
