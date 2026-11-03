package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.NativeCallAddressSpaceV1
import decompengine.project.NativeCallAddressV1
import decompengine.project.NativeCallBindingsV1
import decompengine.project.NativeCallFunctionRecordV1
import decompengine.project.NativeCallFunctionSummaryRecordV1
import decompengine.project.NativeCallObservationLimitsV1
import decompengine.project.NativeCallObservationsV1
import decompengine.project.NativeCallRecordV1
import decompengine.project.NativeCallSiteRecordV1
import decompengine.project.NativeCallTargetV1
import java.io.ByteArrayInputStream
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class NativeExternalClaimLimitsV1(
    val maximumObservationBytes: Int = 64 * 1024 * 1024,
    val maximumManifestBytes: Int = 64 * 1024,
    val maximumSites: Int = 100_000,
    val maximumRecords: Int = 362_144,
    val maximumEvidenceBytes: Int = 64 * 1024 * 1024,
) {
    init {
        require(maximumObservationBytes in 1..64 * 1024 * 1024 && maximumManifestBytes in 1..64 * 1024)
        require(maximumSites in 1..100_000 && maximumRecords in 1..362_144 && maximumEvidenceBytes in 1..64 * 1024 * 1024)
    }
}

/** Native coordinates and indices only. Neither candidate represents a resolved import identity. */
internal sealed interface NativeExternalCandidateV1 {
    val kind: String
    val externalTarget: NativeCallTargetV1

    data class Slot(
        val slot: NativeCallAddressV1,
        override val externalTarget: NativeCallTargetV1,
        val viaReferenceIndex: Int,
        val neighborhoodIndex: Int,
        val targetReferenceIndex: Int,
    ) : NativeExternalCandidateV1 {
        override val kind: String get() = "native-slot-external-chain-v1"
    }

    data class Thunk(
        val target: NativeCallAddressV1,
        override val externalTarget: NativeCallTargetV1,
        val functionRecordOrdinal: Long,
    ) : NativeExternalCandidateV1 {
        override val kind: String get() = "native-immediate-thunk-external-chain-v1"
    }
}

/** All nested native value types used here contain immutable scalars, not collection references. */
internal data class NativeExternalClaimSiteV1(
    val recordOrdinal: Long,
    val siteOrdinal: Long,
    val address: NativeCallAddressV1,
    val owner: NativeCallAddressV1?,
    val observationKind: String,
    val listedLength: Int,
    val instructionBytes: String?,
    val prototypeFlowCode: Int,
    val effectiveFlowCode: Int,
    val prototypeFallThrough: NativeCallAddressV1?,
    val effectiveFallThrough: NativeCallAddressV1?,
    val physicalCallEligible: Boolean,
    val candidate: NativeExternalCandidateV1?,
    val disposition: String,
)

/** Immutable recovery-only snapshot. Expected bindings and this object confer no production capability. */
internal class FrozenNativeExternalClaimsSnapshotV1 internal constructor(
    val bindings: NativeCallBindingsV1,
    addressSpaces: List<NativeCallAddressSpaceV1>,
    sites: List<NativeExternalClaimSiteV1>,
    manifest: ByteArray,
    observations: ByteArray,
    evidence: ByteArray,
    val rawRecordCount: Long,
) {
    private val manifestSnapshot = manifest.copyOf()
    private val observationSnapshot = observations.copyOf()
    private val evidenceSnapshot = evidence.copyOf()
    val addressSpaces: List<NativeCallAddressSpaceV1> = immutableList(addressSpaces)
    val sites: List<NativeExternalClaimSiteV1> = immutableList(sites)
    val inputSha256: String get() = bindings.inputSha256
    val manifestSha256: String = OracleArtifacts.sha256(manifestSnapshot)
    val observationsSha256: String = OracleArtifacts.sha256(observationSnapshot)
    val evidenceSha256: String = OracleArtifacts.sha256(evidenceSnapshot)
    val policySha256: String = OracleArtifacts.sha256(POLICY.toByteArray(Charsets.UTF_8))
    val rawSiteCount: Long get() = sites.size.toLong()
    val manifestBytes: Long get() = manifestSnapshot.size.toLong()
    val observationBytes: Long get() = observationSnapshot.size.toLong()
    val evidenceBytes: Long get() = evidenceSnapshot.size.toLong()
    val rawManifestBytes: ByteArray get() = manifestSnapshot.copyOf()
    val rawObservationBytes: ByteArray get() = observationSnapshot.copyOf()
    val canonicalEvidenceBytes: ByteArray get() = evidenceSnapshot.copyOf()
    val productionVerified: Boolean get() = false
    val scored: Boolean get() = false
    val complete: Boolean get() = false
    val releaseEligible: Boolean get() = false
    val negativeCompleteness: Boolean get() = false
}

/** Validate the complete stream before selecting candidates; this API has no ELF or oracle input. */
internal object FrozenNativeExternalClaimsV1 {
    fun freeze(
        manifestBytes: ByteArray,
        observationBytes: ByteArray,
        expectedBindings: NativeCallBindingsV1,
        limits: NativeExternalClaimLimitsV1 = NativeExternalClaimLimitsV1(),
        checkpoint: () -> Unit = {},
    ): FrozenNativeExternalClaimsSnapshotV1 {
        checkpoint()
        require(manifestBytes.size in 1..limits.maximumManifestBytes && observationBytes.size in 1..limits.maximumObservationBytes)
        val manifest = manifestBytes.copyOf()
        val observations = observationBytes.copyOf()
        val records = arrayListOf<NativeCallRecordV1>()
        val summary = NativeCallObservationsV1.validate(manifest, expectedBindings,
            NativeCallObservationLimitsV1(maximumManifestBytes = limits.maximumManifestBytes,
                maximumCombinedBytes = limits.maximumObservationBytes.toLong() + limits.maximumManifestBytes,
                maximumSites = limits.maximumSites.toLong()), checkpoint, { ByteArrayInputStream(observations) }) { record ->
            checkpoint()
            require(records.size < limits.maximumRecords) { "native external claim record bound exceeded" }
            records += record
        }
        require(summary.records == records.size.toLong() && summary.observationsBytes == observations.size.toLong())
        val functions = hashMapOf<NativeCallAddressV1, IndexedFunction>()
        records.forEachIndexed { ordinal, record ->
            checkpoint()
            if (record is NativeCallFunctionRecordV1) functions[record.entry] = IndexedFunction(ordinal.toLong(), record)
        }
        val selector = Selector(summary.bindings.imageBase, summary.addressSpaces, functions, checkpoint)
        val sites = arrayListOf<NativeExternalClaimSiteV1>()
        val census = records.mapIndexed { ordinal, record ->
            checkpoint()
            val address: NativeCallAddressV1
            val owner: NativeCallAddressV1?
            val kind: String
            val observationKind: String?
            when (record) {
                is NativeCallFunctionRecordV1 -> { address = record.entry; owner = null; kind = "function"; observationKind = null }
                is NativeCallFunctionSummaryRecordV1 -> { address = record.entry; owner = null; kind = "function-summary"; observationKind = null }
                is NativeCallSiteRecordV1 -> {
                    address = record.address; owner = record.owner; kind = "site"; observationKind = record.observationKind
                    require(sites.size < limits.maximumSites) { "native external claim site bound exceeded" }
                    sites += selector.site(record, ordinal.toLong(), sites.size.toLong())
                }
            }
            obj("recordOrdinal" to num(ordinal), "recordKind" to str(kind), "address" to coordinate(address),
                "owner" to coordinate(owner), "observationKind" to nullable(observationKind))
        }
        require(sites.size.toLong() == summary.scanSummary.sites)
        val evidence = obj("schemaVersion" to num(1), "kind" to str("frozen-native-external-claims-v1"), "authority" to str("diagnostic-only"),
            "productionVerified" to flag(false), "scored" to flag(false), "complete" to flag(false), "releaseEligible" to flag(false),
            "negativeCompleteness" to flag(false), "externalNamespaceSha256" to JsonNull,
            "policy" to str(POLICY), "policySha256" to str(OracleArtifacts.sha256(POLICY.toByteArray(Charsets.UTF_8))),
            "manifestSha256" to str(OracleArtifacts.sha256(manifest)), "observationsSha256" to str(summary.observationsSha256),
            "inputSha256" to str(summary.bindings.inputSha256), "programModelSha256" to str(summary.bindings.programModelSha256),
            "rawRecordCount" to num(summary.records), "rawSiteCount" to num(sites.size),
            "records" to JsonArray(census), "sites" to JsonArray(sites.map { checkpoint(); siteJson(it) }))
        val bytes = OracleJson.canonicalBytes(evidence, StrictJsonLimits(maximumInputBytes = limits.maximumEvidenceBytes,
            maximumCanonicalBytes = limits.maximumEvidenceBytes, maximumDepth = 24, maximumNodes = 1_000_000,
            maximumStringBytes = limits.maximumEvidenceBytes, maximumTotalStringBytes = limits.maximumEvidenceBytes)) { checkpoint() }
        checkpoint()
        val snapshot = FrozenNativeExternalClaimsSnapshotV1(summary.bindings, summary.addressSpaces, sites, manifest, observations, bytes, summary.records)
        checkpoint()
        return snapshot
    }
}

private data class IndexedFunction(val ordinal: Long, val record: NativeCallFunctionRecordV1)
private data class Selection(val candidate: NativeExternalCandidateV1?, val disposition: String)

private class Selector(
    private val imageBase: NativeCallAddressV1,
    private val spaces: List<NativeCallAddressSpaceV1>,
    private val functions: Map<NativeCallAddressV1, IndexedFunction>,
    private val checkpoint: () -> Unit,
) {
    private fun physicalAddress(address: NativeCallAddressV1): Boolean {
        if (address.isNoAddress || imageBase.isNoAddress || address.spaceIndex != imageBase.spaceIndex) return false
        val space = spaces[checkNotNull(address.spaceIndex)]
        return space.type == 1 && !space.overlay && !space.signedOffsets && space.addressableUnitSize == 1 &&
            checkNotNull(address.offsetBits).toULong(16) >= checkNotNull(imageBase.offsetBits).toULong(16)
    }

    fun site(record: NativeCallSiteRecordV1, ordinal: Long, siteOrdinal: Long): NativeExternalClaimSiteV1 {
        val physical = record.observationKind == "prototype-call" && record.prototypeFlow.code in PHYSICAL_CALLS &&
            record.byteStatus == "available" && !record.lengthOverridden && record.delaySlotDepth == 0 &&
            record.flowOverride == "NONE" && physicalAddress(record.address)
        val selected = when {
            !physical -> Selection(null, "unresolved-nonphysical-prototype-call")
            record.effectiveFlow != record.prototypeFlow -> Selection(null, "unresolved-effective-flow-mismatch")
            record.prototypeFlow.code in INDIRECT_CALLS -> slot(record)
            else -> thunk(record)
        }
        return NativeExternalClaimSiteV1(ordinal, siteOrdinal, record.address, record.owner, record.observationKind,
            record.listedLength, record.instructionBytes, record.prototypeFlow.code, record.effectiveFlow.code,
            record.prototypeFallThrough, record.effectiveFallThrough, physical, selected.candidate, selected.disposition)
    }

    private fun slot(record: NativeCallSiteRecordV1): Selection {
        if (record.prototypeTargets.isNotEmpty()) return Selection(null, "unresolved-computed-prototype-targets")
        val references = record.references.withIndex().filter { checkpoint(); it.value.referenceType.code == 9 }
        if (references.size != 1) return Selection(null, if (references.isEmpty()) "unresolved-missing-indirection-reference" else "unresolved-competing-indirection-references")
        val reference = references.single()
        val slot = reference.value.target.address
        if (!physicalAddress(slot)) return Selection(null, "unresolved-nonphysical-slot")
        val neighborhoodIndex = record.referenceNeighborhoods.indexOfFirst { checkpoint(); it.viaReferenceIndex == reference.index }
        check(neighborhoodIndex >= 0) { "validated native indirection neighborhood is missing" }
        val neighborhood = record.referenceNeighborhoods[neighborhoodIndex]
        check(neighborhood.source == slot)
        if (neighborhood.references.size != 1) return Selection(null,
            if (neighborhood.references.isEmpty()) "unresolved-missing-slot-target" else "unresolved-competing-slot-targets")
        val external = neighborhood.references.single().target
        if (!isExternal(external)) return Selection(null, "unresolved-nonexternal-slot-target")
        if (conflict(record, external.address, setOf(slot, external.address))) return Selection(null, "unresolved-conflicting-native-targets")
        return Selection(NativeExternalCandidateV1.Slot(slot, external, reference.index, neighborhoodIndex, 0), "retained-slot-external-candidate")
    }

    private fun thunk(record: NativeCallSiteRecordV1): Selection {
        val target = record.prototypeTargets.singleOrNull()
            ?: return Selection(null, if (record.prototypeTargets.isEmpty()) "unresolved-missing-prototype-target" else "unresolved-competing-prototype-targets")
        if (!physicalAddress(target.address)) return Selection(null, "unresolved-nonphysical-prototype-target")
        val function = functions[target.address]
        if (target.functionEntry != target.address || function == null) return Selection(null, "unresolved-missing-exact-thunk-function")
        if (!function.record.isThunk) return Selection(null, "unresolved-nonthunk-prototype-target")
        val external = function.record.immediateThunkTarget
        if (external == null || !isExternal(external) || external.functionEntry != external.address)
            return Selection(null, "unresolved-nonexternal-immediate-thunk-target")
        if (conflict(record, external.address, setOf(target.address, external.address))) return Selection(null, "unresolved-conflicting-native-targets")
        return Selection(NativeExternalCandidateV1.Thunk(target.address, external, function.ordinal), "retained-immediate-thunk-external-candidate")
    }

    private fun isExternal(target: NativeCallTargetV1): Boolean = !target.address.isNoAddress &&
        spaces[checkNotNull(target.address.spaceIndex)].type == 10 && target.external?.externalSpaceAddress == target.address

    private fun conflict(record: NativeCallSiteRecordV1, external: NativeCallAddressV1, allowedCalls: Set<NativeCallAddressV1>): Boolean {
        fun other(target: NativeCallTargetV1): Boolean { checkpoint(); return target.external != null && target.address != external }
        if (record.prototypeTargets.any(::other)) return true
        if (record.references.any { checkpoint(); other(it.target) || it.referenceType.code in CALL_REFERENCES && it.target.address !in allowedCalls }) return true
        return record.referenceNeighborhoods.any { neighborhood ->
            checkpoint(); neighborhood.references.any { other(it.target) }
        }
    }
}

private fun siteJson(site: NativeExternalClaimSiteV1): JsonObject = obj(
    "recordOrdinal" to num(site.recordOrdinal), "siteOrdinal" to num(site.siteOrdinal), "address" to coordinate(site.address),
    "owner" to coordinate(site.owner), "observationKind" to str(site.observationKind), "listedLength" to num(site.listedLength),
    "instructionBytes" to nullable(site.instructionBytes), "prototypeFlowCode" to num(site.prototypeFlowCode), "effectiveFlowCode" to num(site.effectiveFlowCode),
    "prototypeFallThrough" to coordinate(site.prototypeFallThrough), "effectiveFallThrough" to coordinate(site.effectiveFallThrough),
    "physicalCallEligible" to flag(site.physicalCallEligible), "disposition" to str(site.disposition),
    "candidate" to (site.candidate?.let(::candidateJson) ?: JsonNull),
)
private fun candidateJson(candidate: NativeExternalCandidateV1): JsonObject {
    val common = mapOf("kind" to str(candidate.kind), "externalAddress" to coordinate(candidate.externalTarget.address))
    return JsonObject(common + when (candidate) {
        is NativeExternalCandidateV1.Slot -> mapOf("slot" to coordinate(candidate.slot), "viaReferenceIndex" to num(candidate.viaReferenceIndex),
            "neighborhoodIndex" to num(candidate.neighborhoodIndex), "targetReferenceIndex" to num(candidate.targetReferenceIndex))
        is NativeExternalCandidateV1.Thunk -> mapOf("target" to coordinate(candidate.target), "functionRecordOrdinal" to num(candidate.functionRecordOrdinal))
    })
}
private fun coordinate(address: NativeCallAddressV1?): JsonElement = when {
    address == null -> JsonNull
    address.isNoAddress -> obj("kind" to str("no-address"))
    else -> obj("kind" to str("address"), "spaceIndex" to num(checkNotNull(address.spaceIndex)), "offsetBits" to str(checkNotNull(address.offsetBits)))
}
private fun <T> immutableList(values: List<T>): List<T> = Collections.unmodifiableList(ArrayList(values))
private fun obj(vararg values: Pair<String, JsonElement>): JsonObject = JsonObject(linkedMapOf(*values))
private fun str(value: String): JsonPrimitive = JsonPrimitive(value)
private fun num(value: Int): JsonPrimitive = JsonPrimitive(value)
private fun num(value: Long): JsonPrimitive = JsonPrimitive(value)
private fun flag(value: Boolean): JsonPrimitive = JsonPrimitive(value)
private fun nullable(value: String?): JsonElement = value?.let(::str) ?: JsonNull
private val DIRECT_CALLS = setOf(3, 4, 10, 14)
private val INDIRECT_CALLS = setOf(8, 13, 15)
private val PHYSICAL_CALLS = DIRECT_CALLS + INDIRECT_CALLS
private val CALL_REFERENCES = PHYSICAL_CALLS + setOf(16, 18)
private const val POLICY = "frozen-native-external-claims-v1:all-records-and-sites;prototype-physical-ram-only;exact-indirection-neighborhood-or-immediate-thunk;no-effective-promotion;no-name-selection;no-ELF-or-oracle;no-external-tokens"
