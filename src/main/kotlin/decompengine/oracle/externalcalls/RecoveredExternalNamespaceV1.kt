package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.machinecalls.MachineInstructionDecoderV1
import decompengine.oracle.machinecalls.MachineInstructionRefusalV1
import decompengine.oracle.machinecalls.MachineInstructionV1
import decompengine.project.NativeCallAddressV1
import decompengine.project.NativeCallBindingsV1
import kotlinx.serialization.json.*

internal data class RecoveredExternalNamespaceLimitsV1(
    val maximumSites: Int = 100_000,
    val maximumWorkUnits: Long = 100_000_000,
    val maximumOutputBytes: Int = 64 * 1024 * 1024,
    val maximumWallMillis: Long = 1_800_000,
) {
    init {
        require(maximumSites in 1..100_000 && maximumWorkUnits in 1..100_000_000)
        require(maximumOutputBytes in 1..64 * 1024 * 1024 && maximumWallMillis in 1..1_800_000)
    }
    fun toJson() = JsonObject(mapOf("maximumSites" to JsonPrimitive(maximumSites),
        "maximumWorkUnits" to JsonPrimitive(maximumWorkUnits), "maximumOutputBytes" to JsonPrimitive(maximumOutputBytes),
        "maximumWallMillis" to JsonPrimitive(maximumWallMillis)))
}

/** Refines existing native sites only. Neither independent call rows nor selected mapping is an input. */
internal object RecoveredExternalNamespaceV1 {
    fun compose(
        frozen: FrozenNativeExternalClaimsSnapshotV1,
        pair: ElfExternalNamespacePairV1,
        instructionDecoder: MachineInstructionDecoderV1,
        memoryDecoder: StaticMemoryTransferDecoderV1,
        limits: RecoveredExternalNamespaceLimitsV1 = RecoveredExternalNamespaceLimitsV1(),
        checkpoint: (String) -> Unit = {},
    ): JsonObject {
        val budget = RecoveryNamespaceBudget(limits, checkpoint)
        require(frozen.inputSha256 == pair.strippedInventory.inputSha256) { "native input is not the authenticated stripped twin" }
        require(frozen.rawSiteCount <= limits.maximumSites && frozen.sites.size.toLong() == frozen.rawSiteCount)
        val base = pair.strippedInventory.imageBase
        val nativeBase = requireNotNull(frozen.bindings.imageBase.offsetBits).toULong(16)
        val ram = requireNotNull(frozen.bindings.imageBase.spaceIndex)
        fun rva(address: NativeCallAddressV1?): ULong? {
            if (address?.spaceIndex != ram || address.offsetBits == null) return null
            val offset = address.offsetBits.toULong(16)
            return if (offset < nativeBase) null else offset - nativeBase
        }
        fun linked(address: NativeCallAddressV1?): ULong? = rva(address)?.takeIf { it <= ULong.MAX_VALUE - base }?.let { base + it }
        val composed = frozen.sites.map { site ->
            budget.step("compose frozen external claim")
            var status = "unresolved-frozen-native-claim"
            var physical: JsonObject? = null
            var memory: JsonObject? = null
            var paired: JsonObject? = null
            var candidateId: String? = null
            var targetId: String? = null
            var refusal: String? = null
            val candidate = site.candidate
            if (candidate != null) {
                status = "unresolved-native-instruction-correspondence"
                val siteRva = rva(site.address)
                val claimedBytes = requireNotNull(site.instructionBytes).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                val code = siteRva?.let { pair.proveCodeBytes(it, claimedBytes) }
                if (code != null) {
                    val address = requireNotNull(linked(site.address))
                    try {
                        val decoded = instructionDecoder.decode(address, claimedBytes.copyOf())
                        requireReceipt(decoded, address, claimedBytes)
                        physical = instructionJson(decoded)
                        val direct = candidate is NativeExternalCandidateV1.Thunk
                        val expectedTarget = if (candidate is NativeExternalCandidateV1.Thunk) linked(candidate.target) else null
                        val expectedReturn = linked(site.prototypeFallThrough)
                        val supported = decoded.contextStatus == "language-default-no-commits-v1" &&
                            decoded.classification == if (direct) "direct-call" else "indirect-call"
                        status = "unresolved-native-flow-or-target"
                        if (supported && decoded.directCallTarget == expectedTarget && decoded.directTargets == listOfNotNull(expectedTarget) &&
                            expectedReturn != null && decoded.fallthrough == expectedReturn &&
                            address <= ULong.MAX_VALUE - decoded.length.toULong() && decoded.fallthrough == address + decoded.length.toULong()) {
                            val probeRva = if (candidate is NativeExternalCandidateV1.Thunk) rva(candidate.target) else siteRva
                            val probe = probeRva?.let { pair.codeWindowAtRva(it) }
                            status = "unresolved-memory-transfer"
                            if (probe != null) {
                                val probeAddress = base + requireNotNull(probeRva)
                                val bytes = probe.bytes
                                val basic = instructionDecoder.decode(probeAddress, bytes.copyOf())
                                requireReceipt(basic, probeAddress, bytes, exact = false)
                                val transfer = memoryDecoder.decode(probeAddress, bytes.copyOf())
                                requireMemoryReceipt(transfer, basic, bytes)
                                memory = transferJson(transfer)
                                val desired = if (direct) "indirect-jump" else "indirect-call"
                                val slot = transfer.pointerSlotAddress
                                if (transfer.classification == desired && slot != null && transfer.contextStatus == "language-default-no-commits-v1") {
                                    status = "unresolved-native-slot-disagreement"
                                    if (candidate !is NativeExternalCandidateV1.Slot || linked(candidate.slot) == slot) {
                                        status = "unresolved-paired-slot"
                                        val row = if (slot >= base) pair.slotAtRva(slot - base) else null
                                        if (row != null) {
                                            paired = row.toJson()
                                            candidateId = row.richImportId
                                            status = "unresolved-static-import-eligibility"
                                            if (row.eligible) {
                                                targetId = requireNotNull(candidateId)
                                                status = "verified-object-local-import-request"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch (failure: MachineInstructionRefusalV1) {
                        refusal = failure.message
                        status = "unresolved-byte-decoder-refusal"
                    }
                }
            }
            JsonObject(linkedMapOf(
                "siteId" to JsonPrimitive("native-site-${site.siteOrdinal}"), "sourceRecordOrdinal" to JsonPrimitive(site.recordOrdinal),
                "sourceSiteOrdinal" to JsonPrimitive(site.siteOrdinal), "frozenDisposition" to JsonPrimitive(site.disposition),
                "disposition" to JsonPrimitive(status), "physicalInstruction" to (physical ?: JsonNull),
                "memoryTransfer" to (memory ?: JsonNull), "slotPair" to (paired ?: JsonNull),
                "candidateImportRequestId" to nullable(candidateId), "externalTargetId" to nullable(targetId),
                "decoderRefusal" to nullable(refusal), "negativeCompleteness" to JsonPrimitive(false),
            ))
        }
        // A recovered node is one claim identity. Do not silently split a conflated EXTERNAL node.
        val identities = HashMap<NativeCallAddressV1, MutableSet<String>>()
        composed.forEachIndexed { index, row ->
            budget.step("index recovered external node claims")
            val candidate = frozen.sites[index].candidate
            val id = (row.getValue("candidateImportRequestId") as? JsonPrimitive)?.takeIf { it.isString }?.content
            if (candidate != null && id != null) identities.getOrPut(candidate.externalTarget.address) { HashSet() }.add(id)
        }
        val records = composed.mapIndexed { index, row ->
            budget.step("preserve recovered external node conflicts")
            val candidate = frozen.sites[index].candidate
            if (candidate != null && identities[candidate.externalTarget.address].orEmpty().size > 1)
                JsonObject(row + mapOf("disposition" to JsonPrimitive("unresolved-external-node-conflict"), "externalTargetId" to JsonNull))
            else row
        }
        val result = JsonObject(linkedMapOf(
            "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive("recovered-external-namespace-component-v1"),
            "scope" to JsonPrimitive("component"), "policy" to JsonPrimitive("native-claim-before-pair-v1"),
            "decoderAuthentication" to JsonPrimitive("external-worker-required"),
            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false), "runtimeProviderAvailable" to JsonPrimitive(false),
            "runtimeImplementationAvailable" to JsonPrimitive(false), "rawSitesEnumerated" to JsonPrimitive(true),
            "frozenClaimsSha256" to JsonPrimitive(frozen.evidenceSha256), "frozenClaimsBinding" to frozenBinding(frozen),
            "pairProofSha256" to JsonPrimitive(pair.receiptSha256), "pairProof" to pair.receipt,
            "externalNamespaceSha256" to JsonPrimitive(pair.richNamespaceSha256), "externalNamespace" to pair.richNamespace,
            "sites" to JsonArray(records), "counts" to JsonObject(mapOf("rawSites" to JsonPrimitive(frozen.rawSiteCount),
                "projectedSites" to JsonPrimitive(records.size), "dispositions" to JsonObject(records.groupingBy {
                    (it.getValue("disposition") as JsonPrimitive).content
                }.eachCount().toSortedMap().mapValues { JsonPrimitive(it.value) }))), "limits" to limits.toJson(),
        ))
        validate(result, frozen, pair, limits, budget::step)
        OracleJson.canonicalBytes(result, recoveryNamespaceJsonLimits(limits), budget::step)
        pair.requireCurrent()
        return result
    }

    /** Closed component consistency against held capabilities; parsing grants no execution authority. */
    fun validate(document: JsonObject, frozen: FrozenNativeExternalClaimsSnapshotV1, pair: ElfExternalNamespacePairV1,
                 limits: RecoveredExternalNamespaceLimitsV1 = RecoveredExternalNamespaceLimitsV1(), checkpoint: (String) -> Unit = {}) {
        OracleJson.canonicalBytes(document, recoveryNamespaceJsonLimits(limits), checkpoint)
        require(frozen.inputSha256 == pair.strippedInventory.inputSha256) { "native input is not the authenticated stripped twin" }
        require(document.keys == ROOT_KEYS)
        require(document["schemaVersion"] == JsonPrimitive(1) && document["kind"] == JsonPrimitive("recovered-external-namespace-component-v1") &&
            document["scope"] == JsonPrimitive("component") && document["policy"] == JsonPrimitive("native-claim-before-pair-v1") &&
            document["decoderAuthentication"] == JsonPrimitive("external-worker-required") && document["rawSitesEnumerated"] == JsonPrimitive(true))
        listOf("complete", "releaseEligible", "negativeCompleteness", "productionVerified", "runtimeProviderAvailable", "runtimeImplementationAvailable").forEach {
            require(document[it] == JsonPrimitive(false))
        }
        require(document["limits"] == limits.toJson() && document["pairProof"] == pair.receipt &&
            document["pairProofSha256"] == JsonPrimitive(pair.receiptSha256) && document["externalNamespace"] == pair.richNamespace &&
            document["externalNamespaceSha256"] == JsonPrimitive(pair.richNamespaceSha256) &&
            document["frozenClaimsSha256"] == JsonPrimitive(frozen.evidenceSha256))
        require(OracleArtifacts.sha256(OracleJson.canonicalBytes(document.getValue("pairProof"), recoveryNamespaceJsonLimits(limits), checkpoint)) == pair.receiptSha256 &&
            OracleArtifacts.sha256(OracleJson.canonicalBytes(document.getValue("externalNamespace"), recoveryNamespaceJsonLimits(limits), checkpoint)) == pair.richNamespaceSha256)
        require(document["frozenClaimsBinding"] == frozenBinding(frozen)) { "required raw sources or frozen census binding differs" }
        val sites = document["sites"] as? JsonArray ?: error("projected sites must be an array")
        require(sites.size == frozen.sites.size && sites.size <= limits.maximumSites)
        val statuses = sortedMapOf<String, Int>()
        val expectedStatuses = ArrayList<String>(sites.size)
        val nodeIdentities = HashMap<NativeCallAddressV1, MutableSet<String>>()
        val nativeBase = requireNotNull(frozen.bindings.imageBase.offsetBits).toULong(16)
        val base = pair.strippedInventory.imageBase
        fun linked(value: NativeCallAddressV1?): ULong? {
            if (value == null || value.spaceIndex != frozen.bindings.imageBase.spaceIndex || value.offsetBits == null) return null
            val address = value.offsetBits.toULong(16)
            return if (address < nativeBase || address - nativeBase > ULong.MAX_VALUE - base) null else base + address - nativeBase
        }
        var previousRecordOrdinal = -1L
        sites.forEachIndexed { index, raw ->
            checkpoint("validate complete projected site population")
            val site = raw as? JsonObject ?: error("projected site must be an object")
            require(site.keys == SITE_KEYS && site["negativeCompleteness"] == JsonPrimitive(false))
            val original = frozen.sites[index]
            require(original.siteOrdinal == index.toLong() && original.recordOrdinal > previousRecordOrdinal && original.recordOrdinal < frozen.rawRecordCount)
            previousRecordOrdinal = original.recordOrdinal
            require(site["siteId"] == JsonPrimitive("native-site-${original.siteOrdinal}") && site["sourceRecordOrdinal"] == JsonPrimitive(original.recordOrdinal) &&
                site["sourceSiteOrdinal"] == JsonPrimitive(original.siteOrdinal) && site["frozenDisposition"] == JsonPrimitive(original.disposition))
            val status = (site["disposition"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            require(status in STATUSES)
            statuses[requireNotNull(status)] = (statuses[status] ?: 0) + 1
            val target = site.getValue("externalTargetId")
            require((target != JsonNull) == (status == "verified-object-local-import-request"))
            val candidate = original.candidate
            val physical = site.getValue("physicalInstruction").takeUnless { it == JsonNull }?.let(::readInstruction)
            val memory = site.getValue("memoryTransfer").takeUnless { it == JsonNull }?.let(::readTransfer)
            val candidateId = site.nullableString("candidateImportRequestId")
            val refusal = site.nullableString("decoderRefusal")
            require(refusal == null || refusal.matches(Regex("[a-z0-9-]{1,128}")))
            if (physical != null) {
                require(candidate != null && original.instructionBytes != null && physical.address == linked(original.address))
                val originalBytes = original.instructionBytes.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                requireReceipt(physical, requireNotNull(linked(original.address)), originalBytes)
                require(pair.proveCodeBytes(physical.address - base, originalBytes) != null)
            }
            if (memory != null) {
                require(candidate != null && physical != null)
                val probe = if (candidate is NativeExternalCandidateV1.Thunk) linked(candidate.target) else linked(original.address)
                require(memory.address == probe)
                val owned = pair.codeWindowAtRva(memory.address - base)
                require(owned != null && memory.length <= owned.bytes.size && memory.bytes.contentEquals(owned.bytes.copyOf(memory.length)))
                // This validates the closed receipt, not SLEIGH execution or runtime provenance.
                requireMemoryReceipt(memory, MachineInstructionV1(memory.address, memory.length, memory.bytes,
                    memory.classification, null, emptyList(), null, memory.contextStatus), owned.bytes)
            }
            val slot = memory?.pointerSlotAddress
            val paired = if (slot != null && slot >= base) pair.slotAtRva(slot - base) else null
            val direct = candidate is NativeExternalCandidateV1.Thunk
            val expectedTarget = if (candidate is NativeExternalCandidateV1.Thunk) linked(candidate.target) else null
            val flowMatches = physical != null && physical.contextStatus == "language-default-no-commits-v1" &&
                physical.classification == (if (direct) "direct-call" else "indirect-call") &&
                physical.directCallTarget == expectedTarget && physical.directTargets == listOfNotNull(expectedTarget) &&
                physical.fallthrough != null && physical.fallthrough == linked(original.prototypeFallThrough) &&
                physical.address <= ULong.MAX_VALUE - physical.length.toULong() && physical.fallthrough == physical.address + physical.length.toULong()
            val desiredMemoryClass = if (direct) "indirect-jump" else "indirect-call"
            if (site["slotPair"] != JsonNull) {
                require(paired != null && site["slotPair"] == paired.toJson() && candidateId == paired.richImportId)
                require(candidate !is NativeExternalCandidateV1.Slot || linked(candidate.slot) == slot)
            } else require(candidateId == null)
            if (candidate != null && candidateId != null) nodeIdentities.getOrPut(candidate.externalTarget.address) { HashSet() }.add(candidateId)
            if (site["slotPair"] != JsonNull) {
                require(candidate != null && physical != null && memory != null && refusal == null)
                require(flowMatches && memory.classification == desiredMemoryClass)
            }
            if (target != JsonNull) require(candidate != null && target == site["candidateImportRequestId"] && paired?.eligible == true)
            if (original.candidate == null) require(status == "unresolved-frozen-native-claim" &&
                listOf("physicalInstruction", "memoryTransfer", "slotPair", "candidateImportRequestId", "externalTargetId", "decoderRefusal").all { site[it] == JsonNull })
            val expectedStatus = when {
                candidate == null -> "unresolved-frozen-native-claim"
                physical == null -> {
                    require(memory == null && site["slotPair"] == JsonNull)
                    val address = linked(original.address)
                    val bytes = requireNotNull(original.instructionBytes).chunked(2).map { it.toInt(16).toByte() }.toByteArray()
                    val owned = address?.let { pair.proveCodeBytes(it - base, bytes) }
                    if (refusal != null) {
                        require(owned != null)
                        "unresolved-byte-decoder-refusal"
                    } else {
                        require(owned == null) { "owned native bytes have neither a decoder receipt nor a refusal" }
                        "unresolved-native-instruction-correspondence"
                    }
                }
                !flowMatches -> {
                    require(memory == null && site["slotPair"] == JsonNull && refusal == null)
                    "unresolved-native-flow-or-target"
                }
                memory == null -> {
                    require(site["slotPair"] == JsonNull)
                    val probe = if (candidate is NativeExternalCandidateV1.Thunk) linked(candidate.target) else linked(original.address)
                    val owned = probe?.let { pair.codeWindowAtRva(it - base) }
                    if (refusal != null) {
                        require(owned != null)
                        "unresolved-byte-decoder-refusal"
                    } else {
                        require(owned == null) { "owned probe bytes have neither a memory receipt nor a refusal" }
                        "unresolved-memory-transfer"
                    }
                }
                else -> {
                    require(refusal == null)
                    when {
                        memory.classification != desiredMemoryClass || slot == null || memory.contextStatus != "language-default-no-commits-v1" -> {
                            require(site["slotPair"] == JsonNull); "unresolved-memory-transfer"
                        }
                        candidate is NativeExternalCandidateV1.Slot && linked(candidate.slot) != slot -> {
                            require(site["slotPair"] == JsonNull); "unresolved-native-slot-disagreement"
                        }
                        paired == null -> { require(site["slotPair"] == JsonNull); "unresolved-paired-slot" }
                        else -> {
                            require(site["slotPair"] == paired.toJson()) { "paired slot receipt is missing" }
                            if (paired.eligible) "verified-object-local-import-request" else "unresolved-static-import-eligibility"
                        }
                    }
                }
            }
            expectedStatuses += expectedStatus
        }
        sites.forEachIndexed { index, raw ->
            checkpoint("validate recovered external node conflicts")
            val candidate = frozen.sites[index].candidate
            val conflict = candidate != null && nodeIdentities[candidate.externalTarget.address].orEmpty().size > 1
            val expected = if (conflict) "unresolved-external-node-conflict" else expectedStatuses[index]
            require((raw as JsonObject)["disposition"] == JsonPrimitive(expected)) { "disposition differs from retained claim and proof progression" }
        }
        require(document["counts"] == JsonObject(mapOf("rawSites" to JsonPrimitive(frozen.rawSiteCount),
            "projectedSites" to JsonPrimitive(sites.size), "dispositions" to JsonObject(statuses.mapValues { JsonPrimitive(it.value) }))))
    }
}

/** These raw sources are required for independent re-freeze; this commitment cannot replace them. */
private fun frozenBinding(frozen: FrozenNativeExternalClaimsSnapshotV1): JsonObject = JsonObject(mapOf(
    "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive("required-frozen-native-external-source-binding-v1"),
    "rawSourcesRequired" to JsonPrimitive(true), "manifestSha256" to JsonPrimitive(frozen.manifestSha256),
    "manifestBytes" to JsonPrimitive(frozen.manifestBytes), "observationsSha256" to JsonPrimitive(frozen.observationsSha256),
    "observationsBytes" to JsonPrimitive(frozen.observationBytes), "frozenClaimsSha256" to JsonPrimitive(frozen.evidenceSha256),
    "frozenClaimsBytes" to JsonPrimitive(frozen.evidenceBytes), "policySha256" to JsonPrimitive(frozen.policySha256),
    "inputSha256" to JsonPrimitive(frozen.inputSha256), "programModelSha256" to JsonPrimitive(frozen.bindings.programModelSha256),
    "programModelBytes" to JsonPrimitive(frozen.bindings.programModelBytes), "rawRecordCount" to JsonPrimitive(frozen.rawRecordCount),
    "rawSiteCount" to JsonPrimitive(frozen.rawSiteCount), "bindings" to nativeExternalBindingsJsonV1(frozen.bindings),
    "negativeCompleteness" to JsonPrimitive(false),
))

internal fun nativeExternalBindingsJsonV1(bindings: NativeCallBindingsV1): JsonObject = JsonObject(mapOf(
    "collectorSha256" to JsonPrimitive(bindings.collectorSha256), "compilerSpecId" to JsonPrimitive(bindings.compilerSpecId),
    "ghidraArchiveSha256" to JsonPrimitive(bindings.ghidraArchiveSha256), "inputSha256" to JsonPrimitive(bindings.inputSha256),
    "languageId" to JsonPrimitive(bindings.languageId), "programModelBytes" to JsonPrimitive(bindings.programModelBytes),
    "programModelExporterSha256" to JsonPrimitive(bindings.programModelExporterSha256), "programModelSha256" to JsonPrimitive(bindings.programModelSha256),
    "imageBase" to JsonObject(mapOf("kind" to JsonPrimitive("address"), "spaceIndex" to JsonPrimitive(requireNotNull(bindings.imageBase.spaceIndex)),
        "offsetBits" to JsonPrimitive(requireNotNull(bindings.imageBase.offsetBits)))),
))

private fun requireReceipt(decoded: MachineInstructionV1, address: ULong, bytes: ByteArray, exact: Boolean = true) {
    require(decoded.address == address && decoded.length in 1..15 && decoded.length <= bytes.size &&
        (!exact || decoded.length == bytes.size) && decoded.bytes.contentEquals(bytes.copyOf(decoded.length))) { "byte decoder receipt differs" }
}
private fun requireMemoryReceipt(transfer: StaticMemoryTransferV1, basic: MachineInstructionV1, bytes: ByteArray) {
    require(transfer.address == basic.address && transfer.length == basic.length && transfer.bytes.contentEquals(basic.bytes) &&
        transfer.classification == basic.classification && transfer.contextStatus == basic.contextStatus && bytes.size >= transfer.length) { "memory decoder receipt differs" }
    require(transfer.classification in CLASSIFICATIONS && transfer.contextStatus in CONTEXTS &&
        transfer.rawCopyOpIndices.size <= 4096 && transfer.length in 1..15)
    if (transfer.pointerSlotAddress != null) {
        require(transfer.pointerWidthBytes == 8 && transfer.pointerSlotAddress <= ULong.MAX_VALUE - 7UL &&
            transfer.contextStatus == "language-default-no-commits-v1" && transfer.unresolvedReason == null &&
            transfer.classification in setOf("indirect-call", "indirect-jump") &&
            transfer.relationship in setOf("static-ram-varnode-exact-transfer-v1", "single-static-load-exact-transfer-v1"))
        val op = if (transfer.classification == "indirect-call") "CALLIND" else "BRANCHIND"
        val read = requireNotNull(transfer.rawReadOpIndex)
        val end = requireNotNull(transfer.rawTransferOpIndex)
        require(read in 0..4095 && end in read..4095 && transfer.rawTransferOpcode == op &&
            transfer.rawCopyOpIndices == transfer.rawCopyOpIndices.distinct().sorted() && transfer.rawCopyOpIndices.all { it in read until end })
        when (transfer.relationship) {
            "single-static-load-exact-transfer-v1" -> require(transfer.rawReadOpcode == "LOAD" && read < end && transfer.rawCopyOpIndices.all { it > read })
            else -> if (transfer.rawReadOpcode == "COPY") require(read < end && transfer.rawCopyOpIndices.firstOrNull() == read)
                else require(transfer.rawReadOpcode == op && read == end && transfer.rawCopyOpIndices.isEmpty())
        }
    } else require(transfer.pointerWidthBytes == null && transfer.relationship == "unresolved" && transfer.unresolvedReason != null &&
        transfer.unresolvedReason.matches(Regex("[a-z0-9-]{1,128}")) && transfer.rawReadOpcode == null && transfer.rawReadOpIndex == null &&
        transfer.rawCopyOpIndices.isEmpty() && (transfer.rawTransferOpcode == null) == (transfer.rawTransferOpIndex == null) &&
        (transfer.rawTransferOpIndex == null || transfer.rawTransferOpIndex in 0..4095 && transfer.rawTransferOpcode ==
            when (transfer.classification) { "indirect-call" -> "CALLIND"; "indirect-jump" -> "BRANCHIND"; else -> null }))
}
private fun readInstruction(raw: JsonElement): MachineInstructionV1 {
    val row = raw as? JsonObject ?: error("instruction proof must be an object")
    require(row.keys == setOf("address", "length", "bytes", "classification", "fallthrough", "directTargets", "directCallTarget", "contextStatus"))
    val targets = row["directTargets"] as? JsonArray ?: error("direct targets must be an array")
    require(targets.size <= 64)
    val result = MachineInstructionV1(requireNotNull(row.address("address")), row.integer("length"), row.bytes(), row.string("classification"),
        row.address("fallthrough"), targets.map { parseAddress(it) ?: error("target cannot be null") }, row.address("directCallTarget"), row.string("contextStatus"))
    require(result.classification in CLASSIFICATIONS && result.contextStatus in CONTEXTS && instructionJson(result) == row)
    return result
}
private fun readTransfer(raw: JsonElement): StaticMemoryTransferV1 {
    val row = raw as? JsonObject ?: error("memory proof must be an object")
    require(row.keys == setOf("address", "length", "bytes", "classification", "pointerSlotAddress", "pointerWidthBytes", "relationship",
        "rawReadOpcode", "rawReadOpIndex", "rawTransferOpcode", "rawTransferOpIndex", "rawCopyOpIndices", "contextStatus", "unresolvedReason"))
    val copies = row["rawCopyOpIndices"] as? JsonArray ?: error("copy indices must be an array")
    require(copies.size <= 4096)
    val result = StaticMemoryTransferV1(requireNotNull(row.address("address")), row.integer("length"), row.bytes(), row.string("classification"),
        row.address("pointerSlotAddress"), row.nullableInteger("pointerWidthBytes"), row.string("relationship"), row.nullableString("rawReadOpcode"),
        row.nullableInteger("rawReadOpIndex"), row.nullableString("rawTransferOpcode"), row.nullableInteger("rawTransferOpIndex"),
        copies.map { (it as? JsonPrimitive)?.takeUnless { v -> v.isString }?.intOrNull ?: error("copy index must be integer") },
        row.string("contextStatus"), row.nullableString("unresolvedReason"))
    require(transferJson(result) == row)
    return result
}
private fun JsonObject.string(key: String) = (getValue(key) as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("$key must be a string")
private fun JsonObject.nullableString(key: String) = if (getValue(key) == JsonNull) null else string(key)
private fun JsonObject.integer(key: String) = (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.intOrNull ?: error("$key must be an integer")
private fun JsonObject.nullableInteger(key: String) = if (getValue(key) == JsonNull) null else integer(key)
private fun JsonObject.address(key: String) = parseAddress(getValue(key))
private fun parseAddress(raw: JsonElement): ULong? {
    if (raw == JsonNull) return null
    val value = (raw as? JsonPrimitive)?.takeIf { it.isString }?.content ?: error("address must be a string")
    require(value.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")))
    return value.substring(2).toULong(16)
}
private fun JsonObject.bytes(): ByteArray {
    val value = string("bytes")
    require(value.matches(Regex("(?:[0-9a-f]{2}){1,15}")))
    return value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
}
private fun instructionJson(value: MachineInstructionV1) = JsonObject(mapOf(
    "address" to hex(value.address), "length" to JsonPrimitive(value.length), "bytes" to JsonPrimitive(value.bytes.hexBytes()),
    "classification" to JsonPrimitive(value.classification), "fallthrough" to hex(value.fallthrough),
    "directTargets" to JsonArray(value.directTargets.map(::hex)), "directCallTarget" to hex(value.directCallTarget),
    "contextStatus" to JsonPrimitive(value.contextStatus)))
private fun transferJson(value: StaticMemoryTransferV1) = JsonObject(mapOf(
    "address" to hex(value.address), "length" to JsonPrimitive(value.length), "bytes" to JsonPrimitive(value.bytes.hexBytes()),
    "classification" to JsonPrimitive(value.classification), "pointerSlotAddress" to hex(value.pointerSlotAddress),
    "pointerWidthBytes" to (value.pointerWidthBytes?.let(::JsonPrimitive) ?: JsonNull), "relationship" to JsonPrimitive(value.relationship),
    "rawReadOpcode" to nullable(value.rawReadOpcode), "rawReadOpIndex" to (value.rawReadOpIndex?.let(::JsonPrimitive) ?: JsonNull),
    "rawTransferOpcode" to nullable(value.rawTransferOpcode), "rawTransferOpIndex" to (value.rawTransferOpIndex?.let(::JsonPrimitive) ?: JsonNull),
    "rawCopyOpIndices" to JsonArray(value.rawCopyOpIndices.map(::JsonPrimitive)), "contextStatus" to JsonPrimitive(value.contextStatus),
    "unresolvedReason" to nullable(value.unresolvedReason)))
private fun nullable(value: String?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
private fun ByteArray.hexBytes() = joinToString("") { (it.toInt() and 255).toString(16).padStart(2, '0') }
private fun hex(value: ULong?): JsonElement = value?.let { JsonPrimitive("0x${it.toString(16)}") } ?: JsonNull
internal fun recoveryNamespaceJsonLimits(limits: RecoveredExternalNamespaceLimitsV1) = StrictJsonLimits(
    maximumInputBytes = limits.maximumOutputBytes, maximumCanonicalBytes = limits.maximumOutputBytes, maximumNodes = 1_000_000,
    maximumDepth = 32, maximumStringBytes = limits.maximumOutputBytes, maximumTotalStringBytes = limits.maximumOutputBytes)
private class RecoveryNamespaceBudget(val limits: RecoveredExternalNamespaceLimitsV1, val checkpoint: (String) -> Unit) {
    private val start = System.nanoTime()
    private var work = 0L
    fun step(stage: String) {
        require(++work <= limits.maximumWorkUnits) { "recovered external namespace work limit exceeded" }
        check(!Thread.currentThread().isInterrupted && (System.nanoTime() - start) / 1_000_000 <= limits.maximumWallMillis) { "recovered external namespace interrupted or expired" }
        checkpoint(stage)
    }
}
private val ROOT_KEYS = setOf("schemaVersion", "kind", "scope", "policy", "decoderAuthentication", "complete", "releaseEligible",
    "negativeCompleteness", "productionVerified", "runtimeProviderAvailable", "runtimeImplementationAvailable", "rawSitesEnumerated",
    "frozenClaimsSha256", "frozenClaimsBinding", "pairProofSha256", "pairProof", "externalNamespaceSha256", "externalNamespace", "sites", "counts", "limits")
private val SITE_KEYS = setOf("siteId", "sourceRecordOrdinal", "sourceSiteOrdinal", "frozenDisposition", "disposition", "physicalInstruction",
    "memoryTransfer", "slotPair", "candidateImportRequestId", "externalTargetId", "decoderRefusal", "negativeCompleteness")
private val STATUSES = setOf("unresolved-frozen-native-claim", "unresolved-native-instruction-correspondence", "unresolved-native-flow-or-target",
    "unresolved-memory-transfer", "unresolved-native-slot-disagreement", "unresolved-paired-slot", "unresolved-static-import-eligibility",
    "verified-object-local-import-request", "unresolved-byte-decoder-refusal", "unresolved-external-node-conflict")
private val CLASSIFICATIONS = setOf("direct-call", "indirect-call", "direct-jump", "indirect-jump", "return", "ordinary",
    "unsupported-pcode", "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow")
private val CONTEXTS = setOf("language-default-no-commits-v1", "context-change", "unassessed-userop-context", "unassessed-pcode-context")
