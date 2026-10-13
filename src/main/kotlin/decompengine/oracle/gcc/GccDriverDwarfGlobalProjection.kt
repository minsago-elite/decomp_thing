package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFacts
import decompengine.oracle.fulltree.DwarfGlobalVariableFacts
import decompengine.oracle.fulltree.DwarfInterfaceFact
import decompengine.oracle.fulltree.DwarfInterfaceFactState
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeElfMemorySegment
import decompengine.oracle.fulltree.FullTreeElfObjectLayoutObservation
import decompengine.oracle.fulltree.FullTreeElfObjectStorage
import decompengine.oracle.fulltree.FullTreeElfObjectSymbol
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class GccDriverDwarfGlobalProjectionLimits(
    val maximumInputsPerKind: Int = 100_000,
    val maximumRecords: Int = 600_000,
    val maximumTypeDepth: Int = 64,
    val maximumWork: Long = 10_000_000,
    val maximumRecordBytes: Int = 1024 * 1024,
    val maximumRecordPayloadBytes: Long = 128L * 1024 * 1024,
) {
    init {
        require(maximumInputsPerKind in 1..100_000 && maximumRecords in 1..600_000)
        require(maximumTypeDepth in 1..128 && maximumWork in 1..10_000_000)
        require(maximumRecordBytes in 1..1024 * 1024 && maximumRecordPayloadBytes in 1..128L * 1024 * 1024)
    }
}

internal class GccDriverDwarfGlobalProjectionResult(
    records: List<JsonObject>,
    val summary: JsonObject,
    val configuration: JsonObject,
) {
    val records: List<JsonObject> = Collections.unmodifiableList(ArrayList(records))
}

/** Physical storage joins only. Every raw source row survives independently of any join. */
internal object GccDriverDwarfGlobalProjection {
    fun project(
        facts: BoundedDwarfInterfaceFacts,
        strippedObjects: List<FullTreeElfObjectSymbol>,
        strippedLayout: FullTreeElfObjectLayoutObservation,
        limits: GccDriverDwarfGlobalProjectionLimits = GccDriverDwarfGlobalProjectionLimits(),
    ): GccDriverDwarfGlobalProjectionResult = Projection(facts, strippedObjects, strippedLayout, limits).run()
}

private class Projection(
    private val facts: BoundedDwarfInterfaceFacts,
    private val strippedObjects: List<FullTreeElfObjectSymbol>,
    private val strippedLayout: FullTreeElfObjectLayoutObservation,
    private val limits: GccDriverDwarfGlobalProjectionLimits,
) {
    private var work = 0L
    private var outputBytes = 0L
    private val records = ArrayList<JsonObject>()
    private val bindings = sortedMapOf<String, Binding>()
    init {
        for ((kind, size) in listOf("variables" to facts.globals.size, "rich objects" to facts.objectSymbols.size,
            "stripped objects" to strippedObjects.size, "types" to facts.types.size)) {
            if (size > limits.maximumInputsPerKind) fail("$kind exceed the input count bound")
        }
    }
    private val richLayout = facts.objectLayout
    private val richRanges = richLayout?.let(::Ranges)
    private val strippedRanges = Ranges(strippedLayout)
    private val commonLayout = richLayout != null && equivalentLayout(richLayout, strippedLayout)
    private val commonTlsLayout = commonLayout && richLayout!!.tlsSegments.singleOrNull()?.alignment != null
    private val extentsByCoordinate = HashMap<String, MutableSet<ULong>>()
    private val counts = sortedMapOf<String, Int>()

    private data class Key(val domain: String, val coordinate: ULong, val size: ULong) {
        fun suffix(): String = "$domain:${hex(coordinate)}:${hex(size)}"
        fun json(): JsonObject = JsonObject(linkedMapOf(
            "domain" to JsonPrimitive(domain), "coordinate" to JsonPrimitive(hex(coordinate)),
            "byteSize" to JsonPrimitive(hex(size)),
        ))
    }
    private class Binding(val key: Key, val layoutDomain: String) {
        val dwarfs = ArrayList<String>()
        val rich = ArrayList<String>()
        val stripped = ArrayList<String>()
        val types = sortedSetOf<String>()
    }
    private data class SizeProof(val size: ULong?, val reason: String? = null)
    private data class Proof(val key: Key?, val reasons: List<String>)

    fun run(): GccDriverDwarfGlobalProjectionResult {
        val seen = HashSet<String>()
        for (global in facts.globals.sortedBy { it.locator }) {
            charge()
            val id = "dwarf:${global.locator}"
            if (!seen.add(id)) fail("duplicate DWARF variable locator")
            val proof = globalProof(global)
            val bindingId = bind(proof, false) {
                it.dwarfs += global.locator
                global.type.singleKnown()?.let(it.types::add)
            }
            count("rawDwarfVariables")
            if (global.storage.singleKnown() == "automatic") count("automaticLocals")
            if (global.declaration.singleKnown() == "1") count("declarations")
            count(if (bindingId == null) "unresolvedDwarfVariables" else "storageProvedDwarfVariables")
            add(sourceRow(id, "dwarf-variable", global.locator, bindingId, proof))
        }
        for ((stripped, symbols) in listOf(false to facts.objectSymbols, true to strippedObjects)) {
            val kind = if (stripped) "stripped-object" else "rich-object"
            for (symbol in symbols.sortedBy { it.locator }) {
                charge()
                val id = "$kind:${symbol.locator}"
                if (!seen.add(id)) fail("duplicate $kind locator")
                val proof = symbolProof(symbol, if (stripped) strippedRanges else richRanges)
                val bindingId = bind(proof, stripped) { if (stripped) it.stripped += symbol.locator else it.rich += symbol.locator }
                count(if (stripped) "rawStrippedObjects" else "rawRichObjects")
                if (bindingId == null) count(if (stripped) "unresolvedStrippedObjects" else "unresolvedRichObjects")
                add(sourceRow(id, kind, symbol.locator, bindingId, proof))
            }
        }
        for ((id, binding) in bindings) {
            charge()
            if (binding.dwarfs.isEmpty()) count("symbolOnlyBindings")
            val conflictingExtent = extentsByCoordinate.getValue(coordinateId(binding.layoutDomain, binding.key)).size > 1
            val ambiguous = binding.dwarfs.size > 1 || binding.types.size > 1 || conflictingExtent
            if (ambiguous) count("ambiguousStorageIdentityBindings")
            else count("unambiguousStorageKeyBindings")
            add(JsonObject(linkedMapOf(
                "id" to JsonPrimitive(id), "kind" to JsonPrimitive("storage-binding"),
                "layoutDomain" to JsonPrimitive(binding.layoutDomain), "storage" to binding.key.json(),
                "dwarfLocators" to strings(binding.dwarfs), "richSymbolLocators" to strings(binding.rich),
                "strippedSymbolLocators" to strings(binding.stripped),
                "sourceIdentity" to JsonPrimitive(if (!ambiguous && binding.dwarfs.size == 1) "one-raw-candidate" else "unresolved"),
                "dwarfTypeLocators" to strings(binding.types.toList()),
                "ambiguities" to strings(buildList {
                    if (binding.dwarfs.size > 1) add("multiple-raw-variable-candidates")
                    if (binding.types.size > 1) add("multiple-raw-type-identities")
                    if (conflictingExtent) add("same-coordinate-with-conflicting-byte-sizes")
                }),
                "strippedStorageProved" to JsonPrimitive(binding.layoutDomain != "rich"),
                "namesJoined" to JsonPrimitive(false), "typesJoined" to JsonPrimitive(false),
            )))
        }
        val summary = JsonObject(linkedMapOf(
            "rawDwarfVariables" to JsonPrimitive(facts.globals.size),
            "rawRichObjects" to JsonPrimitive(facts.objectSymbols.size),
            "rawStrippedObjects" to JsonPrimitive(strippedObjects.size),
            "storageBindings" to JsonPrimitive(bindings.size), "records" to JsonPrimitive(records.size),
            "canonicalRecordPayloadBytes" to JsonPrimitive(outputBytes),
            "counts" to JsonObject(counts.mapValues { JsonPrimitive(it.value) }),
            "excludedRecords" to JsonPrimitive(0), "scored" to JsonPrimitive(false),
        ))
        val configuration = JsonObject(linkedMapOf(
            "schema" to JsonPrimitive("gcc-driver-dwarf-global-storage-projection-v1"),
            "mapping" to JsonPrimitive("positive-address-or-tls-offset-and-explicit-size"),
            "equalRecordedRichStrippedLayout" to JsonPrimitive(commonLayout),
            "tlsTemplateGeometryProved" to JsonPrimitive(commonTlsLayout),
            "layoutReason" to if (commonLayout) JsonNull else JsonPrimitive("rich-stripped-layout-not-proved-equivalent"),
            "nameMatching" to JsonPrimitive(false), "exclusionsApplied" to JsonPrimitive(false),
            // The enclosing shard writer separately charges envelopes, delimiters, metadata and all other kinds.
            "byteBudgetScope" to JsonPrimitive("sum-of-canonical-record-bytes-before-shard-envelopes"),
            "maximumInputsPerKind" to JsonPrimitive(limits.maximumInputsPerKind),
            "maximumRecords" to JsonPrimitive(limits.maximumRecords), "maximumTypeDepth" to JsonPrimitive(limits.maximumTypeDepth),
            "maximumWork" to JsonPrimitive(limits.maximumWork), "maximumRecordBytes" to JsonPrimitive(limits.maximumRecordBytes),
            "maximumRecordPayloadBytes" to JsonPrimitive(limits.maximumRecordPayloadBytes),
        ))
        return GccDriverDwarfGlobalProjectionResult(records, summary, configuration)
    }

    private fun sourceRow(id: String, kind: String, locator: String, binding: String?, proof: Proof) = JsonObject(linkedMapOf(
        "id" to JsonPrimitive(id), "kind" to JsonPrimitive(kind), "sourceLocator" to JsonPrimitive(locator),
        "state" to JsonPrimitive(if (binding == null) "unresolved" else "storage-proved"),
        "storageBindingId" to (binding?.let(::JsonPrimitive) ?: JsonNull),
        "reasons" to strings(proof.reasons),
    ))

    private fun bind(proof: Proof, stripped: Boolean, append: (Binding) -> Unit): String? {
        val key = proof.key ?: return null
        val shared = commonLayout && (key.domain != "tls-offset" || commonTlsLayout)
        val domain = if (shared) "rich-and-stripped" else if (stripped) "stripped" else "rich"
        extentsByCoordinate.getOrPut(coordinateId(domain, key)) { HashSet() } += key.size
        val id = "storage:$domain:${key.suffix()}"
        append(bindings.getOrPut(id) { Binding(key, domain) })
        return id
    }

    private fun globalProof(global: DwarfGlobalVariableFacts): Proof {
        if (global.declaration.state !in setOf(DwarfInterfaceFactState.ABSENT, DwarfInterfaceFactState.KNOWN) ||
            (global.declaration.state == DwarfInterfaceFactState.KNOWN && global.declaration.singleKnown() != "0")) {
            return unknown("declaration-is-not-a-proved-storage-definition")
        }
        val domain = when (global.storage.singleKnown()) {
            "static-storage" -> "process-address"
            "thread-local" -> "tls-offset"
            "automatic" -> return unknown("automatic-local-retained-without-global-storage-binding")
            else -> return unknown("storage-domain-unresolved")
        }
        val coordinate = (if (domain == "tls-offset") global.tlsOffset else global.address).singleKnown()?.hexValue()
            ?: return unknown("storage-coordinate-unresolved")
        val size = explicitSize(global)
        val key = Key(domain, coordinate, size.size ?: return unknown(checkNotNull(size.reason)))
        if (richRanges?.contains(key) != true) return unknown("full-extent-not-proved-in-rich-storage")
        return Proof(key, emptyList())
    }

    /** Only typedef/const/volatile/restrict preserve size without their own byte-size evidence. */
    private fun explicitSize(global: DwarfGlobalVariableFacts): SizeProof {
        var size: ULong? = null
        fun merge(fact: DwarfInterfaceFact<String>): String? {
            if (fact.state == DwarfInterfaceFactState.ABSENT) return null
            val value = fact.singleKnown()?.decimalValue()?.takeIf { it > 0UL }
                ?: return "positive-byte-size-${fact.state.name.lowercase()}-or-invalid"
            if (size != null && size != value) return "conflicting-explicit-byte-sizes"
            size = value
            return null
        }
        fun result() = SizeProof(size, if (size == null) "explicit-positive-byte-size-absent" else null)
        merge(global.byteSize)?.let { return SizeProof(null, it) }
        if (global.type.state == DwarfInterfaceFactState.ABSENT) return result()
        var id = global.type.singleKnown() ?: return SizeProof(null, "type-reference-unresolved")
        val visited = HashSet<String>()
        var depth = 0
        while (true) {
            charge()
            if (++depth > limits.maximumTypeDepth) fail("type-size resolution exceeds depth bound")
            if (!visited.add(id)) return SizeProof(null, "cyclic-size-preserving-type-chain")
            val type = facts.types[id] ?: return SizeProof(null, "type-size-node-unavailable")
            merge(type.byteSize)?.let { return SizeProof(null, it) }
            if (type.tag !in setOf(0x16L, 0x26L, 0x35L, 0x37L)) return result()
            if (type.type.state == DwarfInterfaceFactState.ABSENT) return result()
            id = type.type.singleKnown() ?: return SizeProof(null, "size-preserving-type-reference-unresolved")
        }
    }

    private fun symbolProof(symbol: FullTreeElfObjectSymbol, ranges: Ranges?): Proof {
        if (ranges == null) return unknown("object-layout-unavailable")
        val domain = when {
            symbol.storage == FullTreeElfObjectStorage.MAPPED_LOAD && symbol.type == 1 -> "process-address"
            symbol.storage == FullTreeElfObjectStorage.TLS && symbol.type == 6 -> "tls-offset"
            else -> return unknown("symbol-storage-domain-unresolved")
        }
        if (symbol.sectionKind != FullTreeElfSymbolSectionKind.DEFINED || symbol.size == 0UL) {
            return unknown("defined-positive-symbol-extent-unresolved")
        }
        val key = Key(domain, symbol.value, symbol.size)
        if (!ranges.contains(key) || symbol.segmentIndices.isEmpty()) return unknown("symbol-full-extent-unresolved")
        if (domain == "process-address" && (symbol.value < ranges.layout.imageBase ||
            symbol.rva != symbol.value - ranges.layout.imageBase)) return unknown("symbol-rva-disagrees-with-address")
        if (symbol.segmentIndices.size > 1024) fail("symbol segment references exceed bound")
        val proved = symbol.segmentIndices.any { index ->
            charge()
            ranges.segment(key, index)?.let { segment -> ranges.contains(key, segment) } == true
        }
        return if (proved) Proof(key, emptyList()) else unknown("symbol-storage-segment-unresolved")
    }

    /** Prefix maxima answer full-extent membership in overlapping PT_LOAD ranges in logarithmic time. */
    private inner class Ranges(val layout: FullTreeElfObjectLayoutObservation) {
        init {
            if (layout.loadedMemory.size > 1024 || layout.tlsSegments.size > 1024) fail("storage segment count exceeds bound")
            (layout.loadedMemory + layout.tlsSegments).forEach { charge() }
        }
        private val loaded = layout.loadedMemory.sortedBy { it.virtualAddress }
        private val loadedByIndex = loaded.associateBy { it.index }
        private val tlsByIndex = layout.tlsSegments.associateBy { it.index }
        private val maximumEnds = ArrayList<ULong>()
        init {
            if (loadedByIndex.size != loaded.size || tlsByIndex.size != layout.tlsSegments.size) fail("duplicate storage segment index")
            var maximum = 0UL
            for (segment in loaded) { maximum = maxOf(maximum, segment.endExclusive); maximumEnds += maximum }
        }
        fun segment(key: Key, index: Int): FullTreeElfMemorySegment? =
            (if (key.domain == "tls-offset") tlsByIndex else loadedByIndex)[index]
        fun contains(key: Key): Boolean {
            if (!widthFits(key)) return false
            if (key.domain == "tls-offset") return layout.tlsSegments.singleOrNull()?.let { contains(key, it) } == true
            var low = 0
            var high = loaded.size
            while (low < high) {
                charge()
                val middle = low + (high - low) / 2
                if (loaded[middle].virtualAddress <= key.coordinate) low = middle + 1 else high = middle
            }
            return low > 0 && key.coordinate + key.size <= maximumEnds[low - 1]
        }
        fun contains(key: Key, segment: FullTreeElfMemorySegment): Boolean = widthFits(key) &&
            if (key.domain == "tls-offset") key.coordinate < segment.memorySize && key.size <= segment.memorySize - key.coordinate
            else key.coordinate >= segment.virtualAddress && key.coordinate < segment.endExclusive &&
                key.size <= segment.endExclusive - key.coordinate
        private fun widthFits(key: Key): Boolean {
            // ELF32 can represent an exclusive end at 2^32 in our ULong arithmetic.
            // ELF64 still requires a representable exclusive end, avoiding addition wraparound.
            val endLimit = when (layout.elfClass) { 1 -> 0x100000000UL; 2 -> ULong.MAX_VALUE; else -> return false }
            return key.size > 0UL && key.coordinate < endLimit && key.size <= endLimit - key.coordinate
        }
    }

    private fun add(record: JsonObject) {
        if (records.size >= limits.maximumRecords) fail("record count exceeds bound")
        val bytes = OracleJson.canonicalBytes(record, StrictJsonLimits(
            maximumInputBytes = limits.maximumRecordBytes, maximumCanonicalBytes = limits.maximumRecordBytes,
            maximumDepth = 16, maximumNodes = 100_000, maximumStringBytes = 4096,
            maximumTotalStringBytes = limits.maximumRecordBytes,
        )).size
        if (outputBytes > limits.maximumRecordPayloadBytes - bytes) fail("aggregate record payload exceeds byte bound")
        outputBytes += bytes
        records += record
    }
    private fun coordinateId(domain: String, key: Key) = "$domain:${key.domain}:${hex(key.coordinate)}"
    private fun unknown(reason: String) = Proof(null, listOf(reason))
    private fun charge() { if (++work > limits.maximumWork) fail("projection exceeds work bound") }
    private fun count(name: String) { counts[name] = (counts[name] ?: 0) + 1 }
}

private fun equivalentLayout(a: FullTreeElfObjectLayoutObservation, b: FullTreeElfObjectLayoutObservation): Boolean =
    a.elfClass == b.elfClass && a.byteOrder == b.byteOrder && a.elfType == b.elfType && a.machine == b.machine &&
        a.osAbi == b.osAbi && a.abiVersion == b.abiVersion && a.imageBase == b.imageBase &&
        a.loadedMemory.sortedBy { it.index } == b.loadedMemory.sortedBy { it.index } &&
        a.tlsSegments.sortedBy { it.index } == b.tlsSegments.sortedBy { it.index }
private fun DwarfInterfaceFact<String>.singleKnown(): String? =
    values.singleOrNull()?.takeIf { state == DwarfInterfaceFactState.KNOWN }
private fun String.hexValue(): ULong? = takeIf { matches(Regex("0x[0-9a-f]+")) }?.drop(2)?.toULongOrNull(16)
private fun String.decimalValue(): ULong? = takeIf { matches(Regex("[0-9]+")) }?.toULongOrNull()
private fun hex(value: ULong): String = "0x${value.toString(16)}"
private fun strings(values: List<String>) = JsonArray(values.map(::JsonPrimitive))
private fun fail(message: String): Nothing = throw FullTreeControlException("global storage projection: $message")
