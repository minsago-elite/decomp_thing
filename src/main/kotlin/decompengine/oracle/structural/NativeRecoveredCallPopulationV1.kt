package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.*
import java.io.ByteArrayInputStream
import java.util.Locale
import kotlinx.serialization.json.*

/** Bounds are checked before private snapshots or claim allocation. This is a selected-model adapter. */
data class NativeRecoveredCallPopulationLimitsV1(
    val maximumObservationBytes: Int = 64 * 1024 * 1024,
    val maximumModelBytes: Int = 512 * 1024 * 1024,
    val maximumSites: Int = 100_000,
    val maximumEvidenceBytes: Int = 64 * 1024 * 1024,
) {
    init {
        require(maximumObservationBytes in 1..64 * 1024 * 1024)
        require(maximumModelBytes in 1..512 * 1024 * 1024)
        require(maximumSites in 1..100_000 && maximumEvidenceBytes in 1..64 * 1024 * 1024)
    }
}

/** Pure, bounded byte assessment. Neither this parser nor its projection grants a production capability. */
object NativeRecoveredCallPopulationV1 {
    fun freeze(
        manifestBytes: ByteArray,
        observationsBytes: ByteArray,
        programModelBytes: ByteArray,
        expectedBindings: NativeCallBindingsV1,
        limits: NativeRecoveredCallPopulationLimitsV1 = NativeRecoveredCallPopulationLimitsV1(),
        checkpoint: () -> Unit = {},
    ): FrozenNativeRecoveredCallPopulationV1 = FrozenNativeRecoveredCallPopulationV1(
        manifestBytes, observationsBytes, programModelBytes, expectedBindings, limits, checkpoint)
}

/**
 * The raw bytes and recovery-only claim selection are frozen before any oracle projection is supplied.
 * Caller-supplied digest assertions authenticate nothing. A future production owner must supply the
 * same guarded, frozen native/model snapshots and independently replay this derivation.
 */
class FrozenNativeRecoveredCallPopulationV1 internal constructor(
    manifestBytes: ByteArray,
    observationsBytes: ByteArray,
    programModelBytes: ByteArray,
    expectedBindings: NativeCallBindingsV1,
    private val limits: NativeRecoveredCallPopulationLimitsV1,
    checkpoint: () -> Unit,
) {
    private val manifestSnapshot: ByteArray
    private val observationSnapshot: ByteArray
    private val model: CanonicalProgramModelSnapshot
    private val summary: NativeCallObservationSummaryV1
    private val claims: List<Claim>
    private val evidenceSnapshot: ByteArray
    val observationsSha256: String
    val programModelSha256: String
    val programModelBytes: Long
    val inputSha256: String
    val rawRecordCount: Long
    val rawSiteCount: Int
    val productionVerified: Boolean get() = false
    val rawObservationBytes: ByteArray get() = observationSnapshot.copyOf()
    val rawManifestBytes: ByteArray get() = manifestSnapshot.copyOf()
    val canonicalEvidenceBytes: ByteArray get() = evidenceSnapshot.copyOf()

    init {
        checkpoint()
        require(manifestBytes.size in 1..64 * 1024)
        require(observationsBytes.size in 1..limits.maximumObservationBytes)
        require(programModelBytes.size in 1..limits.maximumModelBytes)
        manifestSnapshot = manifestBytes.copyOf()
        observationSnapshot = observationsBytes.copyOf()
        model = CanonicalProgramModelStreaming.readCanonical(programModelBytes,
            CanonicalProgramModelStreamingLimits(
                maximumInputBytes = limits.maximumModelBytes, maximumFunctions = 131_072,
                maximumGlobals = 131_072, maximumTypes = 131_072, maximumReferencesPerFunction = 1_000_000,
                maximumIdentifierCodePoints = 64 * 1024 * 1024, maximumPrototypeCodePoints = 64 * 1024 * 1024,
                maximumTextCodePoints = 64 * 1024 * 1024, maximumTotalStringBytes = limits.maximumModelBytes.toLong(),
                maximumNodes = limits.maximumModelBytes.toLong(), maximumTokens = limits.maximumModelBytes.toLong()))
        require(model.sha256 == expectedBindings.programModelSha256 &&
            model.sizeBytes.toLong() == expectedBindings.programModelBytes &&
            model.model.inputSha256 == expectedBindings.inputSha256) {
            "native claims substitute the exact paired model or input"
        }
        val records = arrayListOf<NativeCallRecordV1>()
        summary = NativeCallObservationsV1.validate(manifestSnapshot, expectedBindings,
            NativeCallObservationLimitsV1(maximumCombinedBytes = limits.maximumObservationBytes.toLong() + 64 * 1024,
                maximumSites = limits.maximumSites.toLong()), checkpoint,
            { ByteArrayInputStream(observationSnapshot) }, records::add)
        require(summary.observationsBytes == observationSnapshot.size.toLong())
        observationsSha256 = summary.observationsSha256
        programModelSha256 = model.sha256
        this.programModelBytes = model.sizeBytes.toLong()
        inputSha256 = model.model.inputSha256
        rawRecordCount = summary.records
        val byAddress = model.model.functions.groupBy { it.address }
        val functions = records.filterIsInstance<NativeCallFunctionRecordV1>().associateBy { it.entry }
        fun modelId(address: NativeCallAddressV1?): String? = address?.let(::imageRva)?.let { rva ->
            byAddress[imageBase() + rva]?.singleOrNull()?.id
        }
        claims = records.mapIndexedNotNull { ordinal, record ->
            checkpoint()
            if (record !is NativeCallSiteRecordV1) return@mapIndexedNotNull null
            val physical = record.observationKind == "prototype-call" &&
                record.prototypeFlow.code in PHYSICAL_CALLS && record.byteStatus == "available" &&
                !record.lengthOverridden && record.delaySlotDepth == 0 && record.flowOverride == "NONE"
            val direct = physical && record.prototypeFlow.code in DIRECT_CALLS
            val target = record.prototypeTargets.singleOrNull()
            val targetId = if (direct && target?.external == null && target?.functionEntry != null &&
                functions[target.functionEntry]?.isThunk == false) modelId(target.functionEntry) else null
            val kind = when {
                record.observationKind != "prototype-call" -> record.observationKind
                !physical -> "unsupported-prototype-claim"
                record.prototypeFlow.code in INDIRECT_CALLS -> "indirect-prototype-claim"
                target?.external != null -> "external-prototype-claim"
                targetId != null -> "direct-internal-prototype-claim"
                else -> "unresolved-internal-prototype-target"
            }
            Claim(ordinal, record, modelId(record.owner), targetId, physical, kind)
        }
        rawSiteCount = claims.size
        require(rawSiteCount.toLong() == summary.scanSummary.sites && records.size.toLong() == rawRecordCount)
        // Retain a census of every record phase. Full original records, including references,
        // external addresses, thunk metadata and summaries remain in observationSnapshot.
        evidenceSnapshot = encode(envelope("native-recovered-call-claims-v1") + mapOf(
            "binding" to binding(null), "source" to source(),
            "manifestSha256" to JsonPrimitive(OracleArtifacts.sha256(manifestSnapshot)),
            "rawRecordCount" to JsonPrimitive(rawRecordCount), "rawSiteCount" to JsonPrimitive(rawSiteCount),
            "rawRecords" to JsonArray(records.mapIndexed { ordinal, record -> obj(
                "recordId" to JsonPrimitive(recordId(ordinal)), "recordOrdinal" to JsonPrimitive(ordinal),
                "recordKind" to JsonPrimitive(when (record) {
                    is NativeCallFunctionRecordV1 -> "function"
                    is NativeCallSiteRecordV1 -> "site"
                    is NativeCallFunctionSummaryRecordV1 -> "function-summary"
                })) }),
            "claims" to JsonArray(claims.map(::claimEvidence))))
    }

    /**
     * Adds only the already-admitted model correspondence and explicit ignored-owner exclusions.
     * Targets were selected above, without oracle access. No external token is inferred from names,
     * synthetic spaces, reference neighborhoods, rich-ELF section indices, or address coincidences.
     */
    fun project(boundary: StructuralSelectedBoundaryProjectionV1): ByteArray {
        require(boundary.inputSha256 == inputSha256 && boundary.programModelSha256 == programModelSha256 &&
            boundary.programModelBytes == model.sizeBytes.toLong() && boundary.selectedModelImageBase == imageBase()) {
            "selected projection substitutes the native model, input or image base"
        }
        val selected = boundary.recoveredFunctions.mapValues { (_, value) -> value.rva to value.status } +
            boundary.ignoredRecoveries.mapValues { (_, value) -> value.rva to value.status }
        require(selected.keys == model.model.functions.mapTo(hashSetOf()) { it.id }) {
            "selected projection omits or adds a paired model identity"
        }
        for (function in model.model.functions) require(function.address >= imageBase() &&
            selected[function.id] == (function.address - imageBase() to function.status.name.lowercase(Locale.ROOT))) {
            "selected projection substitutes a recovered start or status"
        }
        val sites = arrayListOf<JsonObject>()
        val exclusions = arrayListOf<JsonObject>()
        val dispositions = arrayListOf<JsonObject>()
        val ignoredEvidence = linkedMapOf<String, JsonObject>()
        val oracleEvidence = linkedMapOf<String, JsonObject>()
        var retainedEvidenceBytes = 0L
        fun retainEvidence(rows: MutableMap<String, JsonObject>, id: String, bytes: () -> ByteArray) {
            if (id in rows) return
            val snapshot = bytes()
            retainedEvidenceBytes = Math.addExact(retainedEvidenceBytes, snapshot.size.toLong())
            require(retainedEvidenceBytes <= limits.maximumEvidenceBytes) { "unique exclusion evidence exceeds its byte bound" }
            rows[id] = OracleJson.parseCanonical(snapshot, jsonLimits()).jsonObject
        }
        for (claim in claims) {
            val ignored = claim.ownerId?.let(boundary.ignoredRecoveries::get)
            val refs = observations(claim)
            if (ignored != null) {
                val original = requireNotNull(boundary.excludedFunctions[ignored.oracleId])
                exclusions += obj("id" to JsonPrimitive(siteId(claim)), "side" to JsonPrimitive("recovered"),
                    "ownerId" to JsonPrimitive(ignored.id), "observations" to refs)
                // Parse each original row once. Repeated sites reference that exact evidence,
                // avoiding unbounded expansion of a large alias/exclusion document per call.
                retainEvidence(ignoredEvidence, ignored.id) { ignored.canonicalEvidenceBytes }
                retainEvidence(oracleEvidence, original.id) { original.canonicalEvidenceBytes }
                dispositions += claimEvidence(claim).plusFields(
                    "disposition" to JsonPrimitive("explicit-ignored-owner"),
                    "ignoredRecoveryEvidenceId" to JsonPrimitive(ignored.id),
                    "oracleExclusionEvidenceId" to JsonPrimitive(original.id))
                continue
            }
            val owner = claim.ownerId?.takeIf { it in boundary.recoveredFunctions }
            val target = claim.targetId?.takeIf { it in boundary.recoveredFunctions }
            val category = when {
                target != null -> "internal"
                claim.kind == "indirect-prototype-claim" -> "indirect"
                claim.kind == "external-prototype-claim" -> "external"
                else -> "unknown"
            }
            sites += obj("id" to JsonPrimitive(siteId(claim)), "callerId" to nullable(owner),
                "rawOwner" to coordinate(claim.record.owner),
                // Nonphysical observations must not participate in a physical instruction join.
                "instruction" to coordinate(claim.record.address, claim.physical), "return" to JsonNull,
                "category" to JsonPrimitive(category),
                "state" to JsonPrimitive(if (target != null) "recovered" else "recovered-unknown"),
                "targets" to (target?.let { JsonArray(listOf(obj("kind" to JsonPrimitive("function"),
                    "id" to JsonPrimitive(it)))) } ?: JsonNull), "observations" to refs)
            dispositions += claimEvidence(claim).plusFields("disposition" to JsonPrimitive(when {
                owner == null -> "retained-unowned-or-unmapped-owner"
                target == null -> "retained-unresolved-target"
                else -> "retained-recovered-target-claim"
            }))
        }
        check(sites.size + exclusions.size == rawSiteCount)
        return encode(envelope("native-recovered-call-population-fragment-v1") + mapOf(
            "binding" to binding(boundary), "source" to source(), "sites" to JsonArray(sites),
            "exclusions" to JsonArray(exclusions), "dispositions" to JsonArray(dispositions),
            "exclusionEvidence" to obj("ignoredRecoveries" to JsonObject(ignoredEvidence),
                "oracleExclusions" to JsonObject(oracleEvidence))))
    }

    private data class Claim(val ordinal: Int, val record: NativeCallSiteRecordV1, val ownerId: String?,
        val targetId: String?, val physical: Boolean, val kind: String)

    private fun imageBase(): ULong = checkNotNull(summary.bindings.imageBase.offsetBits).toULong(16)
    private fun imageRva(address: NativeCallAddressV1): ULong? {
        if (address.isNoAddress || address.spaceIndex != summary.bindings.imageBase.spaceIndex) return null
        val space = summary.addressSpaces[checkNotNull(address.spaceIndex)]
        if (space.type != 1 || space.overlay || space.signedOffsets || space.addressableUnitSize != 1) return null
        val absolute = checkNotNull(address.offsetBits).toULong(16)
        return if (absolute >= imageBase()) absolute - imageBase() else null
    }
    private fun coordinate(address: NativeCallAddressV1?, eligible: Boolean = true): JsonElement {
        if (address == null || address.isNoAddress) return JsonNull
        val rva = if (eligible) imageRva(address) else null
        return obj("space" to JsonPrimitive(if (rva != null) "image" else "native-space-${address.spaceIndex}"),
            "offset" to JsonPrimitive("0x" + (rva ?: checkNotNull(address.offsetBits).toULong(16)).toString(16)))
    }
    private fun source(): JsonObject = obj("id" to JsonPrimitive("native-$observationsSha256"),
        "role" to JsonPrimitive("recovered"), "sha256" to JsonPrimitive(observationsSha256),
        "bytes" to JsonPrimitive(observationSnapshot.size),
        "policySha256" to JsonPrimitive(OracleArtifacts.sha256(POLICY.toByteArray(Charsets.UTF_8))),
        "recordIds" to JsonArray(claims.map { JsonPrimitive(recordId(it.ordinal)) }))
    private fun binding(boundary: StructuralSelectedBoundaryProjectionV1?): JsonObject = obj(
        "inputSha256" to JsonPrimitive(inputSha256), "programModelSha256" to JsonPrimitive(programModelSha256),
        "boundaryObservationSha256" to nullable(boundary?.boundaryObservationSha256),
        "externalNamespaceSha256" to JsonNull)
    private fun observations(claim: Claim) = JsonArray(listOf(obj("sourceId" to JsonPrimitive("native-$observationsSha256"),
        "recordId" to JsonPrimitive(recordId(claim.ordinal)))))
    private fun claimEvidence(claim: Claim): JsonObject = obj(
        "recordId" to JsonPrimitive(recordId(claim.ordinal)), "recordOrdinal" to JsonPrimitive(claim.ordinal),
        "observationKind" to JsonPrimitive(claim.record.observationKind), "claimKind" to JsonPrimitive(claim.kind),
        "physicalCallEligible" to JsonPrimitive(claim.physical), "ownerRecoveredId" to nullable(claim.ownerId),
        "targetRecoveredId" to nullable(claim.targetId), "rawOwner" to coordinate(claim.record.owner),
        "instruction" to coordinate(claim.record.address), "prototypeReturnCandidate" to coordinate(claim.record.prototypeFallThrough),
        "rawSource" to observations(claim))
    private fun recordId(ordinal: Int) = "records/$ordinal"
    private fun siteId(claim: Claim) = "native-site-${claim.ordinal}"
    private fun envelope(provider: String) = mapOf("schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive(provider),
        "productionVerified" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "complete" to JsonPrimitive(false),
        "releaseEligible" to JsonPrimitive(false), "negativeCoverageAvailable" to JsonPrimitive(false))
    private fun jsonLimits() = StrictJsonLimits(
        maximumInputBytes = limits.maximumEvidenceBytes, maximumCanonicalBytes = limits.maximumEvidenceBytes,
        maximumDepth = 24, maximumNodes = 1_000_000, maximumStringBytes = limits.maximumEvidenceBytes,
        maximumTotalStringBytes = limits.maximumEvidenceBytes)
    private fun encode(fields: Map<String, JsonElement>) = OracleJson.canonicalBytes(JsonObject(fields), jsonLimits())
    private fun nullable(value: String?): JsonElement = value?.let(::JsonPrimitive) ?: JsonNull
    private fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
    private fun JsonObject.plusFields(vararg fields: Pair<String, JsonElement>) = JsonObject(this + fields)

    private companion object {
        val DIRECT_CALLS = setOf(3, 4, 10, 14)
        val INDIRECT_CALLS = setOf(8, 13, 15)
        val PHYSICAL_CALLS = DIRECT_CALLS + INDIRECT_CALLS
        const val POLICY = "native-recovered-call-population-v1:prototype-bytes-only;no-analysis-tail-override-credit;exact-paired-model;no-name-or-thunk-forwarding;no-external-token;all-site-ordinals"
    }
}
