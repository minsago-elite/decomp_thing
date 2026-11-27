package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeElfCoreLayout
import decompengine.oracle.fulltree.FullTreeElfDynamicStructure
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
import decompengine.oracle.fulltree.FullTreeElfMemorySegment
import decompengine.oracle.fulltree.FullTreeElfRawDynamicSymbol
import decompengine.oracle.fulltree.FullTreeElfRawProgramHeader
import decompengine.oracle.fulltree.FullTreeElfRawSection
import decompengine.oracle.fulltree.FullTreeElfSymbolSectionKind
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Closed consistency checks only. Input-byte/decoder authentication remains the producer's boundary. */
internal object IndependentExternalCallReportV1 {
    fun parseComponent(bytes: ByteArray): JsonObject {
        val document = OracleJson.parseCanonical(bytes, HARD_LIMITS, ::checkpoint).record()
        validateComponent(document)
        return document
    }
    fun validateComponent(document: JsonObject) { Validator(document, false).validate() }
    fun validateWorker(document: JsonObject, requestSha256: String, request: IndependentExternalCallRequestV1) {
        Validator(document, true).validate()
        validateExternalWorkerCommitmentsV1(document, requestSha256, request)
    }
}

private class Validator(val document: JsonObject, val worker: Boolean) {
    private var work = 0L
    private fun step(stage: String = "external report") {
        require(++work <= 100_000_000) { "external report validation work bound exceeded" }; checkpoint(stage)
    }
    fun validate() {
        OracleJson.canonicalBytes(document, HARD_LIMITS, ::step)
        document.keys(COMPONENT_KEYS + if (worker) setOf("requestSha256", "runtime", "containmentStatus") else emptySet())
        require(document.number("schemaVersion") == 1L && document.text("kind") == "independent-external-call-component-v1" &&
            document.text("scope") == "component")
        for (flag in listOf("complete", "releaseEligible", "negativeCompleteness", "sourceCallPopulationComplete")) document.flag(flag, false)
        document.flag("sourceCallRecordsEnumerated", true)
        require(document.text("decoderAuthentication") == if (worker) "authenticated-bundled-worker-v1" else "external-worker-required")
        require(document.text("metadataPolicy") == "elf-dynamic-binding-default-limits-v1")
        if (worker) {
            digest(document.text("requestSha256")); require(document.text("containmentStatus") == "external-owner-required")
            document.obj("runtime").keys(setOf("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256",
                "bundleManifestSha256", "languageId", "languageVersion"))
        }
        for (key in listOf("inputSha256", "sourceReportSha256", "sourceRequestSha256", "externalNamespaceSha256")) digest(document.text(key))
        val inputBytes = document.number("inputBytes", 1, 512L * 1024 * 1024)
        val base = document.address("imageBase")!!
        val limit = document.obj("limits")
        limit.keys(setOf("maximumCalls", "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis"))
        val limits = ExternalCallLimitsV1(limit.number("maximumCalls", 1, 100000).toInt(), limit.number("maximumWorkUnits", 1, 100000000),
            limit.number("maximumOutputBytes", 1, 64L * 1024 * 1024).toInt(), limit.number("maximumWallMillis", 1, 1800000))
        OracleJson.canonicalBytes(document, HARD_LIMITS.copy(maximumCanonicalBytes = limits.maximumOutputBytes), ::step)
        val inventory = inventory(document.obj("dynamicInventory"), inputBytes)
        require(inventory.inputSha256 == document.text("inputSha256") && inventory.imageBase == base)
        val symbols = inventory.dynamicSymbols.associateBy { it.tableSectionIndex to it.symbolIndex }
        val relocations = inventory.relocations.groupBy { it.offset }
        val relocationsByLocator = inventory.relocations.associateBy { it.locator }
        require(relocationsByLocator.size == inventory.relocations.size)
        val writeIndex = ElfRelocationWriteCoverageV1.build(inventory, charge = ::step)
        val mechanismUnresolved = inventory.unsupportedReasons.any { it in setOf("packed-relr-relocations-not-expanded",
            "android-packed-relocations-not-expanded", "unclassified-dynamic-tag") }
        val imports = linkedMapOf<Pair<Int, Long>, Pair<String, JsonObject>>()
        inventory.dynamicSymbols.forEach { symbol ->
            step()
            if (symbol.symbolIndex != 0L && symbol.raw.sectionKind == FullTreeElfSymbolSectionKind.UNDEFINED && symbol.name.isNotEmpty() &&
                symbol.binding in setOf(1, 2) && symbol.visibility == 0 && symbol.type in setOf(0, 2, 10)) {
                val identity = importIdentity(inventory.inputSha256, symbol)
                imports[symbol.tableSectionIndex to symbol.symbolIndex] = "ext-${OracleArtifacts.sha256(OracleJson.canonicalBytes(identity))}" to identity
            }
        }
        val expectedNamespace = obj("schemaVersion" to num(1), "kind" to str("elf-static-import-request-namespace-v1"),
            "inputSha256" to str(inventory.inputSha256), "populationBasis" to str("eligible-section-declared-undefined-dynamic-symbols"),
            "runtimeImplementationAvailable" to flag(false), "negativeCompleteness" to flag(false),
            "entries" to JsonArray(imports.values.map { obj("id" to str(it.first), "identity" to it.second) }))
        require(document.getValue("externalNamespace") == expectedNamespace) { "external namespace differs from complete eligible inventory" }
        require(document.text("externalNamespaceSha256") == OracleArtifacts.sha256(OracleJson.canonicalBytes(expectedNamespace, HARD_LIMITS, ::step)))
        val canonical = document.array("sourceCanonicalPopulation", 20000).map { raw ->
            step(); val item = raw.record(); item.keys(setOf("id", "rva", "exclusion"))
            val id = item.text("id", 4096); val rva = item.address("rva", true)
            if (rva != null) checkedAdd(base, rva)
            val exclusion = item.getValue("exclusion")
            if (exclusion != JsonNull) {
                val e = exclusion.record(); e.keys(setOf("kind", "reason")); e.text("reason", 16384)
                require(e.text("kind") in setOf("compiler-generated", "inlined") && (e.text("kind") == "inlined") == (rva == null))
            } else require(rva != null)
            Canonical(id, rva, exclusion != JsonNull)
        }
        require(canonical.any { !it.excluded } && canonical.map { it.id }.distinct().size == canonical.size)
        require(canonical == canonical.sortedWith(compareBy<Canonical> { it.rva == null }.thenBy { it.rva }.thenBy { it.id }))
        val emitted = canonical.filter { it.rva != null }
        require(emitted.map { it.rva }.distinct().size == emitted.size)
        val canonicalByRva = emitted.associateBy { it.rva!! }
        val sites = document.array("sites", limits.maximumCalls)
        var previous: Triple<ULong, String, ULong>? = null
        val statuses = sortedMapOf<String, Int>()
        sites.forEachIndexed { ordinal, raw ->
            step("external site")
            val site = raw.record(); site.keys(SITE_KEYS); site.flag("negativeCompleteness", false)
            require(site.number("sourceOrdinal") == ordinal.toLong())
            val callerRoot = site.text("callerRoot", 16400); require(callerRoot.startsWith("symbol-root:"))
            val callerRva = site.address("callerRva")!!; checkedAdd(base, callerRva)
            val caller = canonicalByRva[callerRva]
            require(site.nullableText("callerCanonicalId", 4096) == caller?.id)
            val rva = site.address("instructionRva")!!; val address = checkedAdd(base, rva)
            require(rva >= callerRva)
            val key = Triple(callerRva, callerRoot, rva)
            previous?.let { require(SITE_ORDER.compare(it, key) < 0) { "duplicate or unordered physical site" } }; previous = key
            val bytes = site.text("instructionBytes", 30); val length = byteLength(bytes)
            require(site.number("instructionLength", 1, 15) == length.toLong())
            require(codeWindowLength(inventory, address)?.let { length <= it } == true) { "source call has no complete owned byte window" }
            require(site.address("returnAddress") == checkedAdd(address, length.toULong()))
            val classification = site.text("physicalClassification"); require(classification in setOf("direct-call", "indirect-call"))
            val target = site.address("physicalTargetAddress", true)
            require((classification == "direct-call") == (target != null))
            val targetCanonical = target?.takeIf { it >= base }?.let { canonicalByRva[it - base] }
            val source = site.text("sourceDisposition")
            validateSourceDisposition(source, classification, caller, targetCanonical)
            var expectedId: String? = null
            val expectedBindingStatus: String
            val probe = site.getValue("memoryProbe").takeUnless { it == JsonNull }?.record()
            val transfer = site.getValue("memoryTransfer").takeUnless { it == JsonNull }?.record()
            val binding = site.getValue("relocationBinding").takeUnless { it == JsonNull }?.record()
            if (source == "unresolved-instruction-overlap" || classification == "direct-call" && targetCanonical != null) {
                require(probe == null && transfer == null && binding == null); site.flag("viaForwarder", false)
                expectedBindingStatus = if (source == "unresolved-instruction-overlap") "unresolved-source-instruction-boundary" else "retained-canonical-target"
            } else {
                val location = if (classification == "indirect-call") address else checkNotNull(target)
                val forwarder = location != address; site.flag("viaForwarder", forwarder)
                val window = codeWindowLength(inventory, location)
                if (probe == null) {
                    require(window == null && transfer == null && binding == null)
                    expectedBindingStatus = if (location == 0UL) "unresolved-null-physical-target" else "unresolved-forwarder-byte-ownership"
                } else {
                    probe.keys(setOf("address", "availableBytes", "refusal"))
                    require(probe.address("address") == location)
                    val available = probe.text("availableBytes", 30); require(byteLength(available) == window)
                    val refusal = probe.nullableText("refusal", 128)
                    if (refusal != null) {
                        require(refusal.matches(Regex("[a-z0-9-]{1,128}")) && transfer == null && binding == null)
                        expectedBindingStatus = "unresolved-memory-decoder-refusal"
                    } else {
                        require(transfer != null)
                        validateTransfer(transfer, location, available)
                        if (!forwarder) require(transfer.number("length") == length.toLong() && transfer.text("bytes") == bytes &&
                            transfer.text("classification") == classification)
                        val desired = if (forwarder) "indirect-jump" else "indirect-call"
                        val slot = transfer.address("pointerSlotAddress", true)
                        when {
                            transfer.text("classification") != desired -> { require(binding == null); expectedBindingStatus = "unresolved-forwarder-sequence" }
                            slot == null -> { require(binding == null); expectedBindingStatus = "unresolved-memory-transfer" }
                            mechanismUnresolved -> { require(binding == null); expectedBindingStatus = "unresolved-unexpanded-relocation-writes" }
                            else -> {
                                val candidates = relocations[slot].orEmpty()
                                if (candidates.size != 1) {
                                    require(binding == null)
                                    expectedBindingStatus = if (candidates.isEmpty()) "unresolved-slot-without-relocation" else "unresolved-competing-relocations"
                                } else {
                                    val relocation = candidates.single(); val symbol = symbols.getValue(relocation.symbolTableSectionIndex to relocation.symbolIndex)
                                    val reference = imports[relocation.symbolTableSectionIndex to relocation.symbolIndex]
                                    expectedId = reference?.first
                                    val writes = writeIndex.assess(slot, relocation)
                                    require(binding == expectedBinding(slot, relocation, symbol, writes)) { "relocation proof differs from inventory" }
                                    expectedBindingStatus = when {
                                        relocation.dynamicTables.size != 1 -> "unresolved-relocation-runtime-membership"
                                        relocation.slotLoadIndices.size != 1 -> "unresolved-slot-memory-ownership"
                                        relocation.slotFileOffset == null -> "unresolved-slot-file-storage"
                                        relocation.symbolTableSectionIndex != inventory.activeSymbolTableSectionIndex -> "unresolved-inactive-symbol-table"
                                        relocation.type == 37L -> "unresolved-irelative-resolver"
                                        relocation.type !in setOf(6L, 7L) -> "unresolved-relocation-type"
                                        relocation.symbolIndex == 0L -> "unresolved-null-symbol-index"
                                        !writes.safeForStaticSlotAssociation -> "unresolved-relocation-write-coverage"
                                        symbol.type == 10 -> "unresolved-ifunc-runtime-implementation"
                                        symbol.raw.sectionKind != FullTreeElfSymbolSectionKind.UNDEFINED -> "unresolved-defined-symbol-reference"
                                        reference == null -> "unresolved-symbol-import-identity"
                                        symbol.version != null && symbol.version.index >= 2 && (symbol.version.name == null || symbol.version.providerRequest == null) -> "unresolved-symbol-version"
                                        symbol.binding == 2 -> "unresolved-weak-runtime-target"
                                        symbol.type == 0 -> "unresolved-untyped-import-request"
                                        else -> "static-import-request-reference"
                                    }
                                }
                            }
                        }
                    }
                }
            }
            require(site.nullableText("externalTargetId", 68) == expectedId)
            require(site.text("targetBindingDisposition") == expectedBindingStatus)
            val expectedStatus = when {
                source == "unresolved-instruction-overlap" -> "unresolved-source-instruction-boundary"
                caller == null || caller.excluded -> "unresolved-source-caller"
                source == "unresolved-target-canonical-exclusion" -> "unresolved-source-target-exclusion"
                source == "unresolved-target-extent" -> "unresolved-source-target-extent"
                else -> expectedBindingStatus
            }
            require(site.text("compositionDisposition") == expectedStatus)
            statuses[expectedStatus] = (statuses[expectedStatus] ?: 0) + 1
        }
        require(document.getValue("counts") == obj("sourcePhysicalSites" to num(sites.size), "composedSiteRecords" to num(sites.size),
            "namespaceEntries" to num(imports.size), "dispositions" to JsonObject(statuses.mapValues { num(it.value) })))
    }

    private fun inventory(raw: JsonObject, inputBytes: Long): ElfDynamicBindingInventoryV1 {
        val base = raw.address("imageBase")!!; val input = raw.text("inputSha256"); digest(input)
        require(raw.number("elfClass") == 2L && raw.number("byteOrder") == 1L && raw.number("machine") == 62L)
        require(raw.text("elfType") in setOf("ET_DYN", "ET_EXEC"))
        val sections = raw.array("sections", 131072).mapIndexed { index, value ->
            step(); val item = value.record(); require(item.number("index") == index.toLong())
            FullTreeElfRawSection(index, item.text("name", 4096, true), item.number("type", 0, 0xffffffffL), item.address("flags")!!,
                item.address("address")!!, item.number("offset", 0, inputBytes), item.address("size")!!,
                item.number("link", 0, 131071).toInt(), item.number("info", 0, Int.MAX_VALUE.toLong()).toInt(),
                item.address("alignment")!!, item.address("entrySize")!!).also { section ->
                if (section.type != 8L && !(index == 0 && section.type == 0L)) require(section.size <= (inputBytes - section.offset).toULong())
            }
        }
        require(sections.isNotEmpty())
        val programs = raw.array("programHeaders", 65535).mapIndexed { index, value ->
            step(); val item = value.record(); require(item.number("index") == index.toLong())
            FullTreeElfRawProgramHeader(index, item.number("type", 0, 0xffffffffL), item.number("flags", 0, 0xffffffffL),
                item.address("offset")!!, item.address("virtualAddress")!!, item.address("physicalAddress")!!,
                item.address("fileSize")!!, item.address("memorySize")!!, item.address("alignment")!!).also { p ->
                if (p.type != 0L) { require(p.offset <= inputBytes.toULong() && p.fileSize <= inputBytes.toULong() - p.offset); checkedAdd(p.virtualAddress, p.memorySize) }
            }
        }
        val loads = programs.filter { it.type == 1L }.map { p ->
            step(); require(p.fileSize <= p.memorySize)
            if (p.alignment > 1UL) require(p.alignment and (p.alignment - 1UL) == 0UL && p.offset % p.alignment == p.virtualAddress % p.alignment)
            FullTreeElfMemorySegment(p.index, p.flags, p.offset, p.virtualAddress, p.fileSize, p.memorySize,
                checkedAdd(p.virtualAddress, p.memorySize), checkedAdd(p.virtualAddress, p.fileSize),
                p.virtualAddress.takeIf { it >= base }?.minus(base), p.alignment)
        }
        val nonempty = loads.filter { it.memorySize != 0UL }
        require(nonempty.isNotEmpty() && nonempty.minOf { it.virtualAddress } == base)
        val ranges = nonempty.filter { it.flags and 1L != 0L }.map { FullTreeElfExecutableRange(it.virtualAddress - base, it.endExclusive - base) }.sortedBy { it.start }
        require(ranges.isNotEmpty())
        fun section(index: Int, type: Long): FullTreeElfRawSection {
            step(); return sections.getOrNull(index)?.also { require(it.type == type) } ?: error("missing inventory section")
        }
        fun linkedStringFits(table: FullTreeElfRawSection, offset: Long, value: String) {
            val start = offset.toULong(); val bytes = value.toByteArray(Charsets.UTF_8).size.toULong()
            require(start < table.size && bytes < table.size - start)
        }
        fun metadata(section: FullTreeElfRawSection) {
            step(); require(section.flags and 2UL != 0UL && section.flags and 0x800UL == 0UL && section.type != 8L)
            if (section.size == 0UL) return
            val end = checkedAdd(section.address, section.size)
            val owners = loads.filter { step(); it.virtualAddress < end && it.endExclusive > section.address }
            require(owners.size == 1)
            val owner = owners.single()
            require(section.address >= owner.virtualAddress && end <= owner.fileEndExclusive &&
                checkedAdd(owner.fileOffset, section.address - owner.virtualAddress) == section.offset.toULong())
        }
        val dynamic = sections.filter { it.type == 6L }.single(); val dynamicProgram = programs.filter { it.type == 2L }.single()
        require(dynamic.address == dynamicProgram.virtualAddress && dynamic.offset.toULong() == dynamicProgram.offset &&
            dynamic.size == dynamicProgram.fileSize && dynamicProgram.fileSize <= dynamicProgram.memorySize && dynamic.entrySize == 16UL)
        metadata(dynamic)
        val entries = raw.array("dynamicEntries", 65536).mapIndexed { index, value ->
            step(); val item = value.record(); require(item.number("index") == index.toLong())
            require(item.number("fileOffset") == dynamic.offset + index * 16L)
            ElfDynamicEntryV1(index, item.number("fileOffset"), item.address("tag")!!, item.address("value")!!)
        }
        require(entries.isNotEmpty() && entries.size.toULong() * 16UL == dynamic.size)
        var terminated = false
        val tags = hashMapOf<ULong, ULong>()
        entries.forEach { entry ->
            step(); if (terminated) require(entry.tag == 0UL && entry.value == 0UL)
            if (entry.tag == 0UL) terminated = true
            else if (entry.tag in SINGLETON_TAGS) require(tags.put(entry.tag, entry.value) == null)
        }
        require(terminated)
        val activeIndex = raw.number("activeSymbolTableSectionIndex", 1, sections.lastIndex.toLong()).toInt()
        val active = section(activeIndex, 11L); val strings = section(active.link, 3L)
        require(dynamic.link == strings.index && tags[6UL] == active.address && tags[11UL] == 24UL && active.entrySize == 24UL &&
            tags[5UL] == strings.address && tags[10UL] == strings.size && strings.size != 0UL)
        metadata(active); metadata(strings)
        val requirements = raw.array("versionRequirements", 131072).map { value ->
            step(); val item = value.record()
            val result = ElfVersionRequirementV1(item.number("sectionIndex", 1, sections.lastIndex.toLong()).toInt(),
                item.number("stringSectionIndex", 1, sections.lastIndex.toLong()).toInt(), item.number("recordOffset"), item.number("auxiliaryOffset"),
                item.text("providerRequest", 16384, true), item.number("providerRequestOffset", 0, 0xffffffffL),
                item.text("name", 16384), item.number("nameOffset", 0, 0xffffffffL), item.number("rawIndex", 0, 65535).toInt(),
                item.number("index", 2, 32767).toInt(), item.number("flags", 0, 65535).toInt(), item.number("hash", 0, 0xffffffffL))
            require(result.index == (result.rawIndex and 0x7fff) && result.hash == elfHash(result.name))
            val owner = section(result.sectionIndex, 0x6ffffffeL); require(owner.link == result.stringSectionIndex)
            val stringTable = section(owner.link, 3L)
            linkedStringFits(stringTable, result.providerRequestOffset, result.providerRequest)
            linkedStringFits(stringTable, result.nameOffset, result.name)
            metadata(owner); require(within(owner, result.recordOffset, 16) && within(owner, result.auxiliaryOffset, 16) && result.auxiliaryOffset >= result.recordOffset + 16)
            result
        }
        val definitions = raw.array("versionDefinitions", 131072).map { value ->
            step(); val item = value.record()
            val result = ElfVersionDefinitionV1(item.number("sectionIndex", 1, sections.lastIndex.toLong()).toInt(),
                item.number("stringSectionIndex", 1, sections.lastIndex.toLong()).toInt(), item.number("recordOffset"),
                item.number("rawIndex", 0, 65535).toInt(), item.number("index", 1, 32767).toInt(), item.number("flags", 0, 65535).toInt(),
                item.number("hash", 0, 0xffffffffL), item.text("name", 16384), item.strings("parentNames", 65535),
                item.array("auxiliaryOffsets", 65535).map { it.integer() },
                item.array("auxiliaryNameOffsets", 65535).map { it.integer(0, 0xffffffffL) })
            require(result.index == (result.rawIndex and 0x7fff) && result.hash == elfHash(result.name))
            val owner = section(result.sectionIndex, 0x6ffffffdL); require(owner.link == result.stringSectionIndex)
            val stringTable = section(owner.link, 3L)
            require(result.auxiliaryNameOffsets.size == result.parentNames.size + 1)
            (listOf(result.name) + result.parentNames).zip(result.auxiliaryNameOffsets).forEach { (name, offset) ->
                linkedStringFits(stringTable, offset, name)
            }
            metadata(owner); require(within(owner, result.recordOffset, 20) && result.auxiliaryOffsets.size == result.parentNames.size + 1)
            require(result.auxiliaryOffsets.isNotEmpty() && result.auxiliaryOffsets == result.auxiliaryOffsets.distinct().sorted())
            require(result.parentNames.all { it.isNotEmpty() }) { "empty defined parent version name" }
            result.auxiliaryOffsets.zipWithNext().forEach { (first, second) -> require(second - first >= 8L) { "overlapping Verdaux records" } }
            result.auxiliaryOffsets.forEach { require(within(owner, it, 8) && it >= result.recordOffset + 20) }
            result
        }
        require(requirements.map { it.auxiliaryOffset }.distinct().size == requirements.size)
        require(requirements == requirements.sortedWith(compareBy<ElfVersionRequirementV1> { it.sectionIndex }.thenBy { it.recordOffset }.thenBy { it.auxiliaryOffset }))
        require(definitions == definitions.sortedWith(compareBy<ElfVersionDefinitionV1> { it.sectionIndex }.thenBy { it.recordOffset }))
        val versionKeys = hashSetOf<Pair<Int, Int>>()
        requirements.forEach { require(versionKeys.add(it.stringSectionIndex to it.index)) }
        definitions.forEach { require(versionKeys.add(it.stringSectionIndex to it.index)) }
        val needs = requirements.associateBy { it.stringSectionIndex to it.index }; val defs = definitions.associateBy { it.stringSectionIndex to it.index }
        val requirementRecords = requirements.groupBy { step(); it.sectionIndex }.mapValues { (_, values) -> values.map { it.recordOffset }.distinct().size }
        val definitionRecords = definitions.groupingBy { step(); it.sectionIndex }.eachCount()
        sections.filter { it.type == 0x6ffffffeL || it.type == 0x6ffffffdL }.forEach { owner ->
            step(); require(owner.entrySize == 0UL && owner.info > 0)
            val count = if (owner.type == 0x6ffffffeL) requirementRecords[owner.index] ?: 0 else definitionRecords[owner.index] ?: 0
            require(owner.info == count)
        }
        val symbols = raw.array("dynamicSymbols", 131072).map { value ->
            step(); val item = value.record(); val tableIndex = item.number("tableSectionIndex", 1, sections.lastIndex.toLong()).toInt()
            val table = section(tableIndex, 11L); val symbolStrings = section(table.link, 3L)
            val symbolIndex = item.number("symbolIndex", 0, 131071)
            val name = item.text("name", 16384, true); require(name.codePointCount(0, name.length) <= 4096)
            val nameOffset = item.number("nameOffset", 0, 0xffffffffL); require(nameOffset.toULong() < symbolStrings.size)
            if (nameOffset == 0L) require(name.isEmpty())
            val info = item.number("info", 0, 255).toInt(); val other = item.number("other", 0, 255).toInt()
            require(item.number("type") == (info and 15).toLong() && item.number("binding") == (info ushr 4).toLong() && item.number("visibility") == (other and 3).toLong())
            val rawSection = item.number("rawSectionIndex", 0, 65535).toInt(); val resolved = item.number("resolvedSectionIndex", 0, 0xffffffffL)
            val kind = FullTreeElfSymbolSectionKind.valueOf(item.text("sectionKind").uppercase())
            require(item.text("sectionKind") == kind.name.lowercase())
            require(if (rawSection == 65535) resolved in 0xff00L until sections.size.toLong() && kind == FullTreeElfSymbolSectionKind.DEFINED else resolved == rawSection.toLong())
            require(when (kind) {
                FullTreeElfSymbolSectionKind.UNDEFINED -> resolved == 0L
                FullTreeElfSymbolSectionKind.ABSOLUTE -> resolved == 0xfff1L
                FullTreeElfSymbolSectionKind.COMMON -> resolved == 0xfff2L
                FullTreeElfSymbolSectionKind.DEFINED -> resolved in 1 until sections.size.toLong() && (rawSection == 65535 || resolved < 0xff00L)
                FullTreeElfSymbolSectionKind.RESERVED -> resolved >= 0xff00L && resolved != 0xfff1L && resolved != 0xfff2L && rawSection != 65535
            })
            val symbol = FullTreeElfRawDynamicSymbol(tableIndex, symbolIndex, item.text("locator", 16384), nameOffset, name, info, other,
                rawSection, resolved, kind, item.address("value")!!, item.address("size")!!)
            require(symbol.locator == "dynamic-binding:section[$tableIndex]=${table.name}:symbol[$symbolIndex]")
            if (symbolIndex == 0L) require(nameOffset == 0L && info == 0 && other == 0 && rawSection == 0 && symbol.value == 0UL && symbol.size == 0UL)
            val version = item.getValue("version").takeUnless { it == JsonNull }?.record()?.let { version ->
                val owner = section(version.number("sectionIndex", 1, sections.lastIndex.toLong()).toInt(), 0x6fffffffL)
                metadata(owner); require(owner.link == tableIndex && owner.entrySize == 2UL && version.number("fileOffset") == owner.offset + symbolIndex * 2)
                val bits = version.number("raw", 0, 65535).toInt(); val index = bits and 0x7fff
                require(version.number("index") == index.toLong()); version.flag("hidden", bits and 0x8000 != 0)
                if (symbolIndex == 0L) require(bits == 0)
                val need = if (index > 1) needs[table.link to index] else null
                val def = if (index > 1) defs[table.link to index] else null
                require(index <= 1 || need != null || def != null)
                val expectedKind = when { index == 0 -> "local"; index == 1 -> "global-unversioned"; need != null -> "required-version"; else -> "defined-version" }
                require(version.text("kind") == expectedKind && version.nullableText("name") == (need?.name ?: def?.name) && version.nullableText("providerRequest", empty = true) == need?.providerRequest)
                ElfSymbolVersionV1(owner.index, version.number("fileOffset"), bits, index, bits and 0x8000 != 0,
                    expectedKind, need?.name ?: def?.name, need?.providerRequest)
            }
            ElfDynamicSymbolV1(symbol, version)
        }
        require(symbols == symbols.sortedWith(compareBy<ElfDynamicSymbolV1> { it.tableSectionIndex }.thenBy { it.symbolIndex }))
        val symbolsByTable = symbols.groupBy { it.tableSectionIndex }
        val versionsByTable = sections.filter { it.type == 0x6fffffffL }.groupBy { step(); it.link }
        sections.filter { it.type == 11L }.forEach { table ->
            step(); val items = symbolsByTable[table.index] ?: error("missing DYNSYM population")
            require(table.entrySize == 24UL && table.size == items.size.toULong() * 24UL && table.info in 1..items.size)
            val versions = versionsByTable[table.index].orEmpty()
            require(versions.size <= 1)
            if (versions.isNotEmpty()) require(versions.single().size == items.size.toULong() * 2UL)
            items.forEachIndexed { index, item ->
                step(); require(item.symbolIndex == index.toLong() && (item.binding == 0) == (index < table.info) &&
                    (item.version == null) == versions.isEmpty())
            }
        }
        val symbolMap = symbols.associateBy { it.tableSectionIndex to it.symbolIndex }
        require(symbolMap.size == symbols.size)
        val versionTags = listOf(Triple(0x6ffffffeUL, 0x6fffffffUL, 0x6ffffffeL), Triple(0x6ffffffcUL, 0x6ffffffdUL, 0x6ffffffdL))
        versionTags.forEach { (pointer, count, type) ->
            val selected = sections.filter { it.type == type && it.link == strings.index }
            require((tags[pointer] == null) == (tags[count] == null) && (tags[pointer] == null) == selected.isEmpty())
            if (selected.isNotEmpty()) require(selected.size == 1 && tags[pointer] == selected.single().address && tags[count] == selected.single().info.toULong())
        }
        val activeVersions = sections.filter { it.type == 0x6fffffffL && it.link == activeIndex }
        require((tags[0x6ffffff0UL] == null) == activeVersions.isEmpty())
        if (activeVersions.isNotEmpty()) require(activeVersions.size == 1 && tags[0x6ffffff0UL] == activeVersions.single().address)
        val taggedRanges = arrayListOf<TaggedRange>()
        fun range(name: String, address: ULong, size: ULong, type: Long, width: Int) {
            require(size % width.toULong() == 0UL); val end = checkedAdd(address, size)
            if (size > 0UL) {
                val selected = sections.filter { step(); it.type == type && it.size != 0UL && it.address < end && checkedAdd(it.address, it.size) > address }
                    .sortedWith { a, b -> step(); a.address.compareTo(b.address) }
                var covered = address
                selected.forEach { owner ->
                    metadata(owner); require(owner.link == activeIndex && owner.entrySize == width.toULong())
                    val begin = maxOf(address, owner.address); val pieceEnd = minOf(end, checkedAdd(owner.address, owner.size))
                    require(begin == covered && (begin - owner.address) % width.toULong() == 0UL && (pieceEnd - owner.address) % width.toULong() == 0UL)
                    covered = pieceEnd
                }
                require(covered == end)
            }
            taggedRanges += TaggedRange(name, address, end, type)
        }
        for ((name, values) in listOf("rela" to listOf(7UL, 8UL, 9UL, 4UL, 24UL), "rel" to listOf(17UL, 18UL, 19UL, 9UL, 16UL))) {
            if (values.take(3).any { tags[it] != null }) {
                require(tags[values[0]] != null && tags[values[1]] != null && tags[values[2]] == values[4])
                range(name, tags.getValue(values[0]), tags.getValue(values[1]), values[3].toLong(), values[4].toInt())
            }
        }
        if (listOf(23UL, 2UL, 20UL).any { tags[it] != null }) {
            require(tags[23UL] != null && tags[2UL] != null && tags[20UL] in setOf(7UL, 17UL))
            range("jmprel", tags.getValue(23UL), tags.getValue(2UL), if (tags[20UL] == 7UL) 4 else 9, if (tags[20UL] == 7UL) 24 else 16)
        }
        val relocations = raw.array("relocations", 1000000).map { value ->
            step(); val item = value.record(); val owner = sections[item.number("sectionIndex", 1, sections.lastIndex.toLong()).toInt()]
            require(owner.type in setOf(4L, 9L)); val width = if (owner.type == 4L) 24 else 16
            val index = item.number("relocationIndex", 0, 999999); require(item.number("fileOffset") == owner.offset + index * width)
            require(item.number("symbolTableSectionIndex") == owner.link.toLong() && owner.entrySize == width.toULong() && owner.size % width.toULong() == 0UL)
            require(owner.info == 0 || owner.info in sections.indices && sections[owner.info].type != 0L)
            if (owner.flags and 2UL != 0UL) metadata(owner)
            val locator = item.text("locator"); require(locator == "elf:section[${owner.index}]:relocation[$index]")
            val symbolIndex = item.number("symbolIndex", 0, 0xffffffffL); require(symbolMap.containsKey(owner.link to symbolIndex))
            val address = checkedAdd(owner.address, index.toULong() * width.toULong())
            val memberships = taggedRanges.filter { step(); it.type == owner.type && address >= it.start && address < it.end }.map { it.name }
            require(item.strings("dynamicTables", 3) == memberships)
            val addend = item.nullableNumber("addend", Long.MIN_VALUE, Long.MAX_VALUE); require((width == 24) == (addend != null))
            ElfDynamicRelocationV1(owner.index, index, item.number("fileOffset"), locator, owner.link, symbolIndex,
                item.address("offset")!!, item.number("type", 0, 0xffffffffL), addend, memberships,
                item.nullableNumber("slotFileOffset", 0, inputBytes), item.array("slotLoadIndices", 65535).map { it.integer(0, programs.lastIndex.toLong()).toInt() },
                item.strings("dispositions", 32))
        }
        require(relocations == relocations.sortedWith(compareBy<ElfDynamicRelocationV1> { it.sectionIndex }.thenBy { it.relocationIndex }))
        val relocationsBySection = relocations.groupBy { it.sectionIndex }
        sections.filter { it.type in setOf(4L, 9L) && sections.getOrNull(it.link)?.type == 11L }.forEach { owner ->
            val items = relocationsBySection[owner.index].orEmpty(); val width = if (owner.type == 4L) 24 else 16
            require(owner.entrySize == width.toULong() && owner.size == items.size.toULong() * width.toULong())
            items.forEachIndexed { index, item -> require(item.relocationIndex == index.toLong()) }
        }
        val slotCounts = relocations.groupingBy { it.offset }.eachCount()
        relocations.forEach { relocation ->
            step(); val symbol = symbolMap.getValue(relocation.symbolTableSectionIndex to relocation.symbolIndex)
            val reasons = arrayListOf<String>()
            if (relocation.dynamicTables.isEmpty()) reasons += "not-in-active-dynamic-relocation-tables"
            if (relocation.symbolTableSectionIndex != activeIndex) reasons += "inactive-dynsym-table"
            reasons += when {
                relocation.type == 37L -> "irelative-runtime-resolver-unresolved"
                relocation.type !in setOf(6L, 7L) -> "unsupported-relocation-type"
                relocation.symbolIndex == 0L -> "null-symbol-reference"
                symbol.type == 10 -> "ifunc-runtime-resolution-unresolved"
                symbol.raw.sectionKind != FullTreeElfSymbolSectionKind.UNDEFINED -> "defined-symbol-runtime-binding-unresolved"
                symbol.name.isEmpty() -> "unnamed-import-reference"
                else -> "declared-import-runtime-provider-unresolved"
            }
            if (symbol.binding == 2 && symbol.raw.sectionKind == FullTreeElfSymbolSectionKind.UNDEFINED) reasons += "weak-import-may-resolve-null"
            if (symbol.binding !in setOf(1, 2) && relocation.symbolIndex != 0L) reasons += "symbol-binding-not-global-or-weak"
            if (symbol.visibility != 0) reasons += "symbol-visibility-nondefault"
            if (symbol.type !in setOf(0, 2, 10)) reasons += "non-function-symbol-reference"
            var fileOffset: Long? = null; var owners = emptyList<Int>()
            if (relocation.type in setOf(6L, 7L, 37L)) {
                val address = relocation.offset
                if (ULong.MAX_VALUE - address < 8UL) reasons += "slot-address-overflow"
                else {
                    val end = address + 8UL
                    val selected = loads.filter { step(); it.virtualAddress < end && it.endExclusive > address }; owners = selected.map { it.index }
                    when {
                        selected.size != 1 -> reasons += if (selected.isEmpty()) "unmapped-slot" else "ambiguous-load-slot"
                        address < selected.single().virtualAddress || end > selected.single().endExclusive -> reasons += "partial-load-slot"
                        end > selected.single().fileEndExclusive -> reasons += "zero-filled-slot"
                        else -> fileOffset = checkedAdd(selected.single().fileOffset, address - selected.single().virtualAddress).toLong()
                    }
                }
            }
            if (slotCounts.getValue(relocation.offset) > 1) reasons += "competing-relocation-slot"
            require(relocation.slotFileOffset == fileOffset && relocation.slotLoadIndices == owners && relocation.dispositions == reasons)
        }
        for ((tag, name) in listOf(0x6ffffff9UL to "rela", 0x6ffffffaUL to "rel")) tags[tag]?.let { count ->
            val selected = relocations.filter { name in it.dynamicTables }.sortedWith { a, b ->
                step(); checkedAdd(sections[a.sectionIndex].address, a.relocationIndex.toULong() * (if (name == "rela") 24UL else 16UL))
                    .compareTo(checkedAdd(sections[b.sectionIndex].address, b.relocationIndex.toULong() * (if (name == "rela") 24UL else 16UL))) }
            require(count <= selected.size.toULong()); repeat(count.toInt()) { require(selected[it].type == 8L && selected[it].symbolIndex == 0L) }
        }
        val unsupported = sortedSetOf("runtime-provider-and-interposition-unresolved", "dynamic-hash-population-not-reconciled")
        if (sections.any { it.type == 11L && it.index != activeIndex }) unsupported += "inactive-dynsym-table-retained"
        entries.forEach { entry -> when (entry.tag) {
            35UL, 36UL, 37UL -> unsupported += "packed-relr-relocations-not-expanded"
            0x6000000fUL, 0x60000010UL, 0x60000011UL, 0x60000012UL, 0x6fffe000UL, 0x6fffe001UL, 0x6fffe003UL -> unsupported += "android-packed-relocations-not-expanded"
            0x7ffffffdUL, 0x7fffffffUL -> unsupported += "dynamic-filter-provider-selection-unresolved"
            else -> if (entry.tag !in KNOWN_DYNAMIC_TAGS) unsupported += "unclassified-dynamic-tag"
        } }
        val needed = raw.strings("neededLibraries", 65536); require(needed.size == entries.count { it.tag == 1UL })
        entries.filter { it.tag == 1UL }.forEach { require(it.value < strings.size) }
        val meta = (sections.filter { it.flags and 2UL != 0UL && it.type in setOf(6L, 11L, 4L, 9L, 0x6fffffffL, 0x6ffffffeL, 0x6ffffffdL) } + strings)
            .distinctBy { it.index }.filter { it.size != 0UL }.sortedWith { a, b -> step(); a.offset.compareTo(b.offset) }
        var end = 0UL
        meta.forEach { require(it.offset.toULong() >= end); end = checkedAdd(it.offset.toULong(), it.size) }
        val structure = FullTreeElfDynamicStructure(FullTreeElfCoreLayout(2, 1, raw.text("elfType"), 62, 0, 0, base, ranges),
            sections, programs, loads, symbols.size.toLong())
        val result = ElfDynamicBindingInventoryV1(input, base, activeIndex, structure, entries, symbols, relocations,
            requirements, definitions, needed, unsupported.toList())
        require(result.toJson() == raw) { "inventory has unknown fields or inconsistent raw metadata" }
        return result
    }

    private fun codeWindowLength(inventory: ElfDynamicBindingInventoryV1, address: ULong): Int? {
        val sections = inventory.sections.filter { step(); it.flags and 2UL != 0UL && it.address <= address && it.size > address - it.address }
        if (sections.size != 1) return null
        val section = sections.single()
        if (section.type != 1L || section.flags and 6UL != 6UL || section.address > ULong.MAX_VALUE - section.size) return null
        val loads = inventory.loadedMemory.filter { step(); address >= it.virtualAddress && address < it.endExclusive }
        if (loads.size != 1) return null
        val load = loads.single()
        if (load.flags and 1L == 0L || address >= load.fileEndExclusive) return null
        val length = minOf(15UL, section.address + section.size - address, load.fileEndExclusive - address)
        val end = checkedAdd(address, length)
        if (inventory.loadedMemory.any { step(); it.index != load.index && address < it.endExclusive && end > it.virtualAddress }) return null
        if (inventory.sections.any { step(); it.index != section.index && it.flags and 2UL != 0UL && it.address < end &&
                it.address <= ULong.MAX_VALUE - it.size && address < it.address + it.size }) return null
        return if (checkedAdd(load.fileOffset, address - load.virtualAddress) == checkedAdd(section.offset.toULong(), address - section.address)) length.toInt() else null
    }

    private fun validateTransfer(value: JsonObject, address: ULong, available: String) {
        value.keys(TRANSFER_KEYS)
        require(value.address("address") == address)
        val length = value.number("length", 1, 15).toInt(); val bytes = value.text("bytes", 30)
        require(byteLength(bytes) == length && available.startsWith(bytes))
        val classification = value.text("classification"); require(classification in CLASSIFICATIONS)
        val context = value.text("contextStatus"); require(context in CONTEXTS)
        val slot = value.address("pointerSlotAddress", true); val width = value.nullableNumber("pointerWidthBytes", 1, 16)
        val relation = value.text("relationship"); val reason = value.nullableText("unresolvedReason", 128)
        val readOpcode = value.nullableText("rawReadOpcode", 128); val read = value.nullableNumber("rawReadOpIndex", 0, 4095)
        val transferOpcode = value.nullableText("rawTransferOpcode", 128); val transfer = value.nullableNumber("rawTransferOpIndex", 0, 4095)
        val copies = value.array("rawCopyOpIndices", 4096).map { it.integer(0, 4095) }
        require(copies == copies.distinct().sorted())
        val expectedTransfer = when (classification) { "indirect-call" -> "CALLIND"; "indirect-jump" -> "BRANCHIND"; else -> null }
        require((transferOpcode == null) == (transfer == null) && (transferOpcode == null || transferOpcode == expectedTransfer))
        if (slot == null) {
            require(width == null && relation == "unresolved" && reason in UNRESOLVED_REASONS && readOpcode == null && read == null && copies.isEmpty())
        } else {
            require(slot <= ULong.MAX_VALUE - 7UL && width == 8L && reason == null && expectedTransfer != null && transferOpcode == expectedTransfer &&
                read != null && transfer != null && read <= transfer && context == "language-default-no-commits-v1")
            require(copies.all { it in read until transfer })
            when (relation) {
                "single-static-load-exact-transfer-v1" -> require(readOpcode == "LOAD" && read < transfer && copies.all { it > read })
                "static-ram-varnode-exact-transfer-v1" -> when (readOpcode) {
                    "COPY" -> require(read < transfer && copies.firstOrNull() == read)
                    expectedTransfer -> require(read == transfer && copies.isEmpty())
                    else -> error("invalid implicit RAM read opcode")
                }
                else -> error("unknown memory-transfer relationship")
            }
        }
    }

    private fun validateSourceDisposition(source: String, classification: String, caller: Canonical?, target: Canonical?) {
        require(when (source) {
            "unresolved-instruction-overlap" -> true
            "unresolved-indirect-target" -> classification == "indirect-call"
            "unresolved-caller-outside-canonical-population" -> classification == "direct-call" && caller == null
            "unresolved-caller-canonical-exclusion" -> classification == "direct-call" && caller?.excluded == true
            "unresolved-target-outside-canonical-population" -> classification == "direct-call" && caller != null && !caller.excluded && target == null
            "unresolved-target-canonical-exclusion" -> classification == "direct-call" && caller != null && !caller.excluded && target?.excluded == true
            "unresolved-target-extent", "positive-internal-exact-start" -> classification == "direct-call" && caller != null && !caller.excluded && target != null && !target.excluded
            else -> false
        }) { "source disposition contradicts caller/target evidence" }
    }

    private fun expectedBinding(slot: ULong, relocation: ElfDynamicRelocationV1, symbol: ElfDynamicSymbolV1,
        writes: ElfRelocationWriteAssessmentV1): JsonObject = obj(
        "slotAddress" to hex(slot), "relocationLocator" to str(relocation.locator), "relocationType" to num(relocation.type),
        "relocationAddend" to (relocation.addend?.let(::num) ?: JsonNull), "dynamicTables" to stringArray(relocation.dynamicTables),
        "slotLoadIndices" to JsonArray(relocation.slotLoadIndices.map(::num)), "slotFileOffset" to (relocation.slotFileOffset?.let(::num) ?: JsonNull),
        "relocationDispositions" to stringArray(relocation.dispositions), "writeCoverage" to writes.toJson(),
        "symbolTableSectionIndex" to num(relocation.symbolTableSectionIndex), "symbolIndex" to num(relocation.symbolIndex),
        "symbolLocator" to str(symbol.raw.locator), "runtimeImplementationAvailable" to flag(false), "runtimeProviderAvailable" to flag(false),
    )

    private fun elfHash(value: String): Long {
        var hash = 0L
        value.toByteArray(Charsets.UTF_8).forEach { byte ->
            step(); hash = ((hash shl 4) + (byte.toInt() and 255)) and 0xffffffffL; val high = hash and 0xf0000000L
            if (high != 0L) hash = hash xor (high ushr 24); hash = hash and high.inv()
        }
        return hash
    }
}

private fun importIdentity(input: String, symbol: ElfDynamicSymbolV1): JsonObject = obj(
    "schemaVersion" to num(1), "namespace" to str("elf-static-import-request-v1"), "inputSha256" to str(input),
    "symbolTableSectionIndex" to num(symbol.tableSectionIndex), "symbolIndex" to num(symbol.symbolIndex),
    "name" to str(symbol.name), "type" to num(symbol.type), "binding" to num(symbol.binding), "visibility" to num(symbol.visibility),
    "version" to (symbol.version?.let { obj("raw" to num(it.raw), "index" to num(it.index), "hidden" to flag(it.hidden),
        "kind" to str(it.kind), "name" to (it.name?.let(::str) ?: JsonNull), "providerRequest" to (it.providerRequest?.let(::str) ?: JsonNull)) } ?: JsonNull),
    "weakMayRemainNull" to flag(symbol.binding == 2), "ifuncImplementationUnresolved" to flag(symbol.type == 10),
    "runtimeProviderAvailable" to flag(false), "runtimeImplementationAvailable" to flag(false), "interpositionUnresolved" to flag(true),
)
private data class Canonical(val id: String, val rva: ULong?, val excluded: Boolean)
private data class TaggedRange(val name: String, val start: ULong, val end: ULong, val type: Long)
private val SITE_ORDER = compareBy<Triple<ULong, String, ULong>> { it.first }.thenBy { it.second }.thenBy { it.third }
private val COMPONENT_KEYS = setOf("schemaVersion", "kind", "scope", "decoderAuthentication", "complete", "releaseEligible", "negativeCompleteness",
    "sourceCallRecordsEnumerated", "sourceCallPopulationComplete", "limits", "metadataPolicy", "inputSha256", "inputBytes", "imageBase",
    "sourceReportSha256", "sourceRequestSha256", "externalNamespaceSha256", "externalNamespace", "sourceCanonicalPopulation", "dynamicInventory", "sites", "counts")
private val SITE_KEYS = setOf("sourceOrdinal", "callerRoot", "callerCanonicalId", "callerRva", "instructionRva", "instructionBytes", "instructionLength",
    "returnAddress", "physicalClassification", "physicalTargetAddress", "sourceDisposition", "compositionDisposition", "targetBindingDisposition",
    "externalTargetId", "viaForwarder", "memoryProbe", "memoryTransfer", "relocationBinding", "negativeCompleteness")
private val TRANSFER_KEYS = setOf("address", "length", "bytes", "classification", "pointerSlotAddress", "pointerWidthBytes", "relationship",
    "rawReadOpcode", "rawReadOpIndex", "rawTransferOpcode", "rawTransferOpIndex", "rawCopyOpIndices", "contextStatus", "unresolvedReason")
private val CLASSIFICATIONS = setOf("direct-call", "indirect-call", "direct-jump", "indirect-jump", "return", "ordinary", "unsupported-pcode",
    "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow")
private val CONTEXTS = setOf("language-default-no-commits-v1", "context-change", "unassessed-userop-context", "unassessed-pcode-context")
private val UNRESOLVED_REASONS = setOf("pcode-bound", "unsupported-transfer-profile", "pcode-varnode-bound", "unsupported-pcode-or-userop",
    "competing-or-invalid-transfers", "internal-pcode-control", "missing-indirect-transfer", "trailing-pcode-after-transfer", "multiple-memory-loads",
    "unsupported-pointer-width", "nondefault-memory-space", "register-transfer", "nonmemory-indirect-value", "overlapping-value-write",
    "missing-value-definition", "unsupported-value-transform", "nondefault-load-space", "nonstatic-load-address", "pointer-slot-wrap",
    "memory-write-before-read", "typed-flow-disagreement", "not-indirect-transfer", "unsupported-context", "unsupported-pcode", "unsupported-trap-or-userop", "unsupported-flow")
private val KNOWN_DYNAMIC_TAGS = (0UL..34UL).toSet() + setOf(0x6ffffef5UL, 0x6ffffff0UL,
    0x6ffffff9UL, 0x6ffffffaUL, 0x6ffffffbUL, 0x6ffffffcUL, 0x6ffffffdUL, 0x6ffffffeUL, 0x6fffffffUL)
private val SINGLETON_TAGS = setOf(2UL, 3UL, 4UL, 5UL, 6UL, 7UL, 8UL, 9UL, 10UL, 11UL, 17UL, 18UL, 19UL, 20UL, 23UL,
    35UL, 36UL, 37UL, 0x6ffffef5UL, 0x6ffffff0UL, 0x6ffffff9UL, 0x6ffffffaUL, 0x6ffffffcUL, 0x6ffffffdUL, 0x6ffffffeUL, 0x6fffffffUL)
private val HARD_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024, maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumNodes = 1000000, maximumStringBytes = 64 * 1024 * 1024, maximumTotalStringBytes = 64 * 1024 * 1024)
private fun checkpoint(stage: String) { check(!Thread.currentThread().isInterrupted) { "external report validation interrupted: $stage" } }
private fun checkedAdd(a: ULong, b: ULong): ULong { require(a <= ULong.MAX_VALUE - b) { "address overflow" }; return a + b }
private fun digest(value: String) { require(value.matches(Regex("[0-9a-f]{64}"))) }
private fun byteLength(value: String): Int { require(value.matches(Regex("(?:[0-9a-f]{2}){1,15}"))); return value.length / 2 }
private fun within(section: FullTreeElfRawSection, offset: Long, width: Int): Boolean = offset >= section.offset &&
    offset - section.offset <= section.size.toLong() - width && (offset - section.offset) % 4 == 0L
private fun JsonElement.record(): JsonObject = this as? JsonObject ?: error("expected external report object")
private fun JsonObject.obj(key: String): JsonObject = getValue(key).record()
private fun JsonObject.keys(expected: Set<String>) { require(keys == expected) { "unknown or missing external report fields: ${keys - expected}; ${expected - keys}" } }
private fun JsonElement.text(maximum: Int = 16384, empty: Boolean = false): String {
    val value = this as? JsonPrimitive
    require(value != null && value.isString && value.content.length in (if (empty) 0 else 1)..maximum && value.content.toByteArray(Charsets.UTF_8).size <= maximum)
    return value.content
}
private fun JsonObject.text(key: String, maximum: Int = 16384, empty: Boolean = false): String = getValue(key).text(maximum, empty)
private fun JsonObject.nullableText(key: String, maximum: Int = 16384, empty: Boolean = false): String? = getValue(key).takeUnless { it == JsonNull }?.text(maximum, empty)
private fun JsonObject.flag(key: String, expected: Boolean) { require(getValue(key) == JsonPrimitive(expected)) }
private fun JsonElement.integer(minimum: Long = 0, maximum: Long = Long.MAX_VALUE): Long {
    val value = this as? JsonPrimitive
    require(value != null && !value.isString && value.content.matches(Regex("(?:0|-?[1-9][0-9]*)")))
    return value.content.toLong().also { require(it in minimum..maximum) }
}
private fun JsonObject.number(key: String, minimum: Long = 0, maximum: Long = Long.MAX_VALUE): Long = getValue(key).integer(minimum, maximum)
private fun JsonObject.nullableNumber(key: String, minimum: Long = 0, maximum: Long = Long.MAX_VALUE): Long? =
    getValue(key).takeUnless { it == JsonNull }?.integer(minimum, maximum)
private fun JsonObject.address(key: String, nullable: Boolean = false): ULong? {
    val value = getValue(key)
    if (nullable && value == JsonNull) return null
    val text = value.text(18)
    require(text.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")))
    return text.substring(2).toULong(16)
}
private fun JsonObject.array(key: String, maximum: Int): JsonArray = (getValue(key) as? JsonArray ?: error("expected array $key")).also { require(it.size <= maximum) }
private fun JsonObject.strings(key: String, maximum: Int): List<String> = array(key, maximum).map { it.text(16384, true) }
private fun obj(vararg fields: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*fields))
private fun str(value: String): JsonPrimitive = JsonPrimitive(value)
private fun num(value: Int): JsonPrimitive = JsonPrimitive(value)
private fun num(value: Long): JsonPrimitive = JsonPrimitive(value)
private fun flag(value: Boolean): JsonPrimitive = JsonPrimitive(value)
private fun hex(value: ULong): JsonPrimitive = str("0x${value.toString(16)}")
private fun stringArray(values: List<String>): JsonArray = JsonArray(values.map(::str))
