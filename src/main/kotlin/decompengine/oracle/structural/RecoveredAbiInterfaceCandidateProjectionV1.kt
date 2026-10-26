package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.gcc.GccBundledInferredInterfaceSnapshot
import decompengine.project.NativeInferredInterfaceFunctionV1
import decompengine.project.NativeInferredInterfaceRecordV1
import decompengine.project.NativeInferredInterfaceSummaryV1
import decompengine.project.NativeInferredInterfaceObservationsV1
import decompengine.project.NativeInferredInterfaceObservationLimitsV1
import decompengine.project.NativeInterfaceFunctionV1
import decompengine.project.NativeInterfaceModelFunctionV1
import decompengine.project.NativeInterfaceObservedFunctionV1
import decompengine.project.NativeInterfaceRecordV1
import decompengine.project.NativeInterfaceObservationSummaryV1
import decompengine.project.NativeInterfaceObservationsV1
import decompengine.project.NativeInterfaceTypeV1
import decompengine.project.NativeInterfaceStorageV1
import decompengine.project.NativeInterfaceTypeEdgeV1
import decompengine.project.NativeInterfaceTypeNodeV1
import decompengine.project.NativeInterfaceTypeRootV1
import java.nio.charset.StandardCharsets
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull

/**
 * Deterministic structural-fact candidates projected from the separately validated native listing
 * and HighFunction streams. This envelope is deliberately untrusted: it is not a score, production
 * replay receipt, oracle observation, or INTERFACES admission capability.
 *
 * Listing parameter ordinals and HighFunction slots remain separate channels. Only a unique
 * model-to-native mapping carried by the listing assessment can assign a recovered function ID.
 */
class RecoveredAbiInterfaceCandidateProjectionV1 private constructor(private val canonical: ByteArray) {
    val sha256: String = OracleArtifacts.sha256(canonical)
    val canonicalBytes: ByteArray get() = canonical.copyOf()
    val document: JsonObject get() = OracleJson.parse(canonical, jsonLimits(MAXIMUM_OUTPUT_BYTES)) as JsonObject

    companion object {
        private const val MAXIMUM_FUNCTIONS = 131_072
        private const val MAXIMUM_PARAMETERS_PER_FUNCTION = 1024
        private const val MAXIMUM_MAPPING_REFERENCES = 1_000_000L
        private const val MAXIMUM_OUTPUT_BYTES = 64 * 1024 * 1024
        private const val MAXIMUM_NODES = 1_000_000
        private const val MAXIMUM_CAPTURE_CANDIDATE_BYTES = 128L * 1024 * 1024
        private const val CALLING_CONVENTION = "function.calling-convention"
        private const val PROTOTYPE = "function.prototype"
        private const val VARIADIC = "function.variadic"
        private const val RETURN_CLASS = "function.return-abi-class"
        private const val PARAMETER_CLASS = "function.parameter-abi-class"
        private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 32,
            maximumNodes = MAXIMUM_NODES,
            maximumStringBytes = 4096,
            maximumTotalStringBytes = maximumBytes,
        )

        /**
         * Revalidates the exact immutable capture bytes before constructing typed candidate rows.
         * The returned projection remains untrusted and carries no oracle or scoring authority.
         */
        internal fun projectCapturedSnapshot(
            snapshot: GccBundledInferredInterfaceSnapshot,
            target: StructuralTargetAbiV1,
            limits: RecoveredAbiInterfaceCandidateProjectionLimitsV1 = RecoveredAbiInterfaceCandidateProjectionLimitsV1(),
            checkpoint: () -> Unit = {},
        ): RecoveredAbiInterfaceCandidateProjectionV1 {
            checkpoint()
            val modelBytes = snapshot.programModelBytes
            val listingManifest = snapshot.listingManifestBytes
            val listingBytes = snapshot.listingObservationsBytes
            val inferredManifest = snapshot.inferredManifestBytes
            val inferredBytes = snapshot.inferredObservationsBytes
            val totalBytes = listOf(modelBytes.size, listingManifest.size, listingBytes.size, inferredManifest.size, inferredBytes.size)
                .fold(0L) { total, size -> Math.addExact(total, size.toLong()) }
            require(totalBytes <= MAXIMUM_CAPTURE_CANDIDATE_BYTES) {
                "authenticated interface snapshot exceeds bounded candidate materialization bytes"
            }
            val rawLimits = NativeInferredInterfaceObservationLimitsV1(
                maximumCombinedBytes = MAXIMUM_CAPTURE_CANDIDATE_BYTES,
                maximumModelBytes = MAXIMUM_CAPTURE_CANDIDATE_BYTES.toInt(),
                maximumFunctions = limits.maximumNativeFunctions,
                maximumParameters = limits.maximumParameters.toInt(),
                maximumGraphNodes = RecoveredAbiTypeGraphClassifierV1.maximumNodes,
                maximumGraphEdges = RecoveredAbiTypeGraphClassifierV1.maximumEdges,
                maximumGraphWork = RecoveredAbiTypeGraphClassifierV1.maximumWork.toLong(),
            )
            val listingRecords = ArrayList<NativeInterfaceRecordV1>()
            val listingSummary = NativeInterfaceObservationsV1.validate(
                listingManifest, snapshot.summary.listing.bindings, modelBytes, rawLimits.listingLimits(), checkpoint,
                { ByteArrayInputStream(listingBytes) },
            ) { record ->
                checkpoint()
                require(listingRecords.size.toLong() < limits.maximumNativeFunctions.toLong() + 524_288L) {
                    "authenticated listing candidate record retention exceeds its bound"
                }
                listingRecords += record
            }
            require(listingSummary == snapshot.summary.listing) { "captured listing bytes differ from their authenticated summary" }
            val inferredRecords = ArrayList<NativeInferredInterfaceRecordV1>()
            val inferredSummary = NativeInferredInterfaceObservationsV1.validate(
                inferredManifest, snapshot.summary.bindings, modelBytes, listingManifest, rawLimits, checkpoint,
                { ByteArrayInputStream(listingBytes) }, { ByteArrayInputStream(inferredBytes) },
            ) { record ->
                checkpoint()
                require(inferredRecords.size.toLong() < limits.maximumNativeFunctions.toLong() +
                    RecoveredAbiTypeGraphClassifierV1.maximumNodes + RecoveredAbiTypeGraphClassifierV1.maximumEdges +
                    RecoveredAbiTypeGraphClassifierV1.maximumRoots) {
                    "authenticated inference candidate record retention exceeds its bound"
                }
                inferredRecords += record
            }
            require(inferredSummary == snapshot.summary) { "captured inferred bytes differ from their authenticated summary" }
            return project(listingSummary, listingRecords, inferredSummary, inferredRecords, target, limits, checkpoint)
        }

        fun project(
            listing: NativeInterfaceObservationSummaryV1,
            listingRecords: Collection<NativeInterfaceRecordV1>,
            inferred: NativeInferredInterfaceSummaryV1,
            inferredRecords: Collection<NativeInferredInterfaceRecordV1>,
            target: StructuralTargetAbiV1,
            limits: RecoveredAbiInterfaceCandidateProjectionLimitsV1 = RecoveredAbiInterfaceCandidateProjectionLimitsV1(),
            checkpoint: () -> Unit = {},
        ): RecoveredAbiInterfaceCandidateProjectionV1 {
            checkpoint()
            require(listing.manifest.sha256.matches(StructuralRecoveryV1Contract.SHA256))
            require(inferred.manifest.sha256.matches(StructuralRecoveryV1Contract.SHA256))
            require(target.snapshot.sha256.matches(StructuralRecoveryV1Contract.SHA256))
            require(listing.manifest.collectorSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.manifest.inputSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.manifest.programModelSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.bindings.collectorSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.bindings.ghidraArchiveSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.bindings.inputSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.bindings.programModelExporterSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                listing.bindings.programModelSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.manifest.collectorSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.manifest.configurationSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.manifest.inputSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.manifest.listingSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.manifest.programModelSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.manifest.typeGraphSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.collectorSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.wrapperSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.nativeDecompilerSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.listingSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.listingManifestSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.configurationSha256.matches(StructuralRecoveryV1Contract.SHA256) &&
                inferred.bindings.typeGraphSha256.matches(StructuralRecoveryV1Contract.SHA256)) {
                "candidate stream commitment fields must have canonical digest shape"
            }
            requireCompatibleInputs(listing, inferred)
            require(listing.manifest.inputSha256 == listing.bindings.inputSha256 &&
                listing.manifest.programModelSha256 == listing.bindings.programModelSha256 &&
                inferred.bindings.listingBindings == listing.bindings && inferred.bindings.listingBytes == listing.manifest.bytes &&
                inferred.bindings.listingSha256 == listing.manifest.sha256 &&
                inferred.manifest.collectorSha256 == inferred.bindings.collectorSha256 &&
                inferred.manifest.configurationSha256 == inferred.bindings.configurationSha256 &&
                inferred.manifest.typeGraphSha256 == inferred.bindings.typeGraphSha256 &&
                inferred.manifest.programModelSha256 == inferred.bindings.listingBindings.programModelSha256) {
                "claimed input and cross-channel commitment fields disagree"
            }
            require(listing.modelFunctions.size <= limits.maximumModelFunctions) {
                "model function population exceeds its fixed bound"
            }

            require(listingRecords.size.toLong() == Math.addExact(listing.scan.functions, listing.scan.types) &&
                listingRecords.size <= limits.maximumNativeFunctions + 524_288) {
                "listing record population differs from bounded scan counts"
            }
            require(listing.scan.functions in 0..limits.maximumNativeFunctions.toLong() && listing.scan.types in 0..524_288L &&
                inferred.scan.graphNodes in 0..200_000L && inferred.scan.graphEdges in 0..1_000_000L && inferred.scan.roots in 0..3_393_216L) {
                "interface record census exceeds fixed bounds"
            }
            require(inferredRecords.size.toLong() == Math.addExact(
                Math.addExact(inferred.scan.functions, inferred.scan.graphNodes),
                Math.addExact(inferred.scan.graphEdges, inferred.scan.roots),
            ) && inferredRecords.size <= limits.maximumNativeFunctions + 4_793_216) {
                "inferred record population differs from bounded scan counts"
            }
            val listingFunctions = listingRecords.filterIsInstance<NativeInterfaceFunctionV1>()
            require(listingRecords.all { it is NativeInterfaceFunctionV1 || it is NativeInterfaceTypeV1 }) {
                "listing contains an unsupported typed record"
            }
            val listingTypes = listingRecords.count { it is NativeInterfaceTypeV1 }
            val inferredFunctions = inferredRecords.filterIsInstance<NativeInferredInterfaceFunctionV1>()
            require(inferredRecords.all {
                it is NativeInferredInterfaceFunctionV1 || it is NativeInterfaceTypeNodeV1 ||
                    it is NativeInterfaceTypeEdgeV1 || it is NativeInterfaceTypeRootV1
            }) { "inference contains an unsupported typed record" }
            val graphNodes = inferredRecords.count { it is NativeInterfaceTypeNodeV1 }
            val graphEdges = inferredRecords.count { it is NativeInterfaceTypeEdgeV1 }
            val graphRoots = inferredRecords.count { it is NativeInterfaceTypeRootV1 }
            require(listingFunctions.size.toLong() == listing.scan.functions &&
                listingTypes.toLong() == listing.scan.types) { "listing records do not conserve the validated listing scan" }
            require(inferredFunctions.size.toLong() == inferred.scan.functions &&
                graphNodes.toLong() == inferred.scan.graphNodes && graphEdges.toLong() == inferred.scan.graphEdges &&
                graphRoots.toLong() == inferred.scan.roots) { "inferred records do not conserve the validated inference scan" }
            require(listing.observedFunctions.size.toLong() == listing.scan.functions &&
                listing.observedFunctions.size <= limits.maximumNativeFunctions) {
                "observed-function census exceeds its fixed bound or listing scan"
            }
            validateScanCounts(listing, listingFunctions, listingTypes, inferred, inferredFunctions)
            require(listing.modelFunctions.size <= limits.maximumModelFunctions &&
                listingFunctions.size <= limits.maximumNativeFunctions && inferredFunctions.size == listingFunctions.size) {
                "interface function population exceeds its fixed bound or paired census"
            }
            var listingParameterRows = 0L
            listingFunctions.forEach { row ->
                checkpoint()
                require(row.parameters.size <= MAXIMUM_PARAMETERS_PER_FUNCTION) { "listing parameter count exceeds its fixed bound" }
                listingParameterRows = Math.addExact(listingParameterRows, row.parameters.size.toLong())
                require(listingParameterRows <= limits.maximumParameters) { "listing parameter population exceeds its fixed bound" }
            }
            var inferredParameterRows = 0L
            inferredFunctions.forEach { row ->
                checkpoint()
                require(row.parameters.size <= MAXIMUM_PARAMETERS_PER_FUNCTION) { "HighFunction parameter count exceeds its fixed bound" }
                inferredParameterRows = Math.addExact(inferredParameterRows, row.parameters.size.toLong())
                require(inferredParameterRows <= limits.maximumParameters) { "HighFunction parameter population exceeds its fixed bound" }
            }
            require(listingParameterRows == listing.scan.parameters && inferredParameterRows == inferred.scan.parameters) {
                "parameter records do not conserve their respective channel scans"
            }

            var parameterCount = 0L
            var inputTextBytes = 0L
            var detailJsonNodes = 0
            var candidateReferences = 0L
            var observedModelReferences = 0L
            var storageVarnodes = 0L
            fun countText(value: String?) {
                if (value == null) return
                require(value.length <= 4096) { "interface projection field exceeds its per-string bound" }
                val bytes = value.toByteArray(StandardCharsets.UTF_8).size
                require(bytes <= 4096) { "interface projection field exceeds its UTF-8 byte bound" }
                inputTextBytes = Math.addExact(inputTextBytes, bytes.toLong())
                require(inputTextBytes <= limits.maximumInputTextBytes) { "interface projection text exceeds its cumulative UTF-8 bound" }
            }
            fun countJson(value: JsonElement) {
                val pending = java.util.ArrayDeque<JsonElement>()
                pending.add(value)
                fun enqueue(child: JsonElement) {
                    require(detailJsonNodes.toLong() + pending.size < MAXIMUM_NODES) {
                        "interface projection JSON details exceed their cumulative node bound"
                    }
                    pending.add(child)
                }
                while (pending.isNotEmpty()) {
                    checkpoint()
                    require(++detailJsonNodes <= MAXIMUM_NODES) { "interface projection JSON details exceed their cumulative node bound" }
                    when (val next = pending.removeLast()) {
                        is JsonObject -> next.forEach { (key, child) -> countText(key); enqueue(child) }
                        is JsonArray -> next.forEach(::enqueue)
                        JsonNull -> Unit
                        is JsonPrimitive -> countText(next.content)
                    }
                }
            }
            fun countStorage(storage: NativeInterfaceStorageV1) {
                require(storage.varnodes.size <= 64) { "interface storage exceeds its per-storage varnode bound" }
                storageVarnodes = Math.addExact(storageVarnodes, storage.varnodes.size.toLong())
                require(storageVarnodes <= 2_000_000) { "interface storage exceeds its aggregate varnode bound" }
                countText(storage.state); countText(storage.autoParameterType)
                storage.varnodes.forEach { countText(it.address.offsetBits) }
            }
            countText(target.id)
            listing.modelFunctions.forEach { row ->
                checkpoint(); countText(row.id); countText(row.modelAddressBits); countText(row.state)
                require(row.candidateEntries.size <= limits.maximumNativeFunctions) { "one model row exceeds its native candidate bound" }
                candidateReferences = Math.addExact(candidateReferences, row.candidateEntries.size.toLong())
                require(candidateReferences <= MAXIMUM_MAPPING_REFERENCES) {
                    "model-to-native candidate references exceed their aggregate bound"
                }
                row.candidateEntries.forEach { countText(it.offsetBits) }
            }
            listing.observedFunctions.forEach { row ->
                checkpoint(); countText(row.state); countText(row.entry.offsetBits)
                require(row.modelIds.size <= limits.maximumModelFunctions) { "one observed row exceeds its model-ID bound" }
                observedModelReferences = Math.addExact(observedModelReferences, row.modelIds.size.toLong())
                require(observedModelReferences <= MAXIMUM_MAPPING_REFERENCES) { "observed model-ID references exceed their aggregate bound" }
                row.modelIds.forEach(::countText)
            }
            listingRecords.forEach { record -> if (record is NativeInterfaceTypeV1) {
                checkpoint(); countText(record.kind); countText(record.nativeClass); countText(record.name); countText(record.path); countText(record.signedness)
            } }
            listingFunctions.forEach { row ->
                checkpoint()
                parameterCount = Math.addExact(parameterCount, row.parameters.size.toLong())
                countText(row.signatureSource); countText(row.convention.name); countText(row.convention.resolvedModel)
                countText(row.name)
                countText(row.entry.offsetBits); countText(row.immediateThunkTarget?.offsetBits)
                row.parameters.forEach { parameter ->
                    checkpoint(); countText(parameter.name); countText(parameter.source); countText(parameter.autoParameterType)
                    countStorage(parameter.storage)
                }
                row.returned?.let { parameter ->
                    countText(parameter.name); countText(parameter.source); countText(parameter.autoParameterType)
                    countStorage(parameter.storage)
                }
            }
            inferredFunctions.forEach { row ->
                checkpoint()
                parameterCount = Math.addExact(parameterCount, row.parameters.size.toLong())
                countText(row.disposition); countText(row.result?.diagnostic); countText(row.prototype?.modelName)
                countText(row.entry.offsetBits)
                row.parameters.forEach { parameter ->
                    checkpoint(); countText(parameter.highVariableState); countText(parameter.nativeIdBits); countText(parameter.name)
                    countStorage(parameter.storage)
                    countText(parameter.firstUse?.offsetBits)
                }
                row.prototype?.let { countStorage(it.returnStorage) }
            }
            inferredRecords.forEach { record -> when (record) {
                is NativeInterfaceTypeNodeV1 -> {
                    checkpoint(); countText(record.nativeClass); countText(record.kind); countText(record.expansion)
                    countJson(record.details)
                }
                is NativeInterfaceTypeEdgeV1 -> { checkpoint(); countText(record.relation); countText(record.fieldName) }
                is NativeInterfaceTypeRootV1 -> { checkpoint(); countText(record.role) }
                is NativeInferredInterfaceFunctionV1 -> Unit
            } }
            require(parameterCount <= limits.maximumParameters) { "interface parameter population exceeds its fixed bound" }
            require(listing.scan.parameters <= limits.maximumParameters && inferred.scan.parameters <= limits.maximumParameters) {
                "per-channel parameter population exceeds its fixed bound"
            }
            // Canonical JSON may expand a control byte to a six-byte `\\u00xx` escape.
            require(inputTextBytes * 6L + (listing.modelFunctions.size + listingFunctions.size + inferredFunctions.size) * 2048L +
                parameterCount * 1024L <= limits.maximumOutputBytes) {
                "candidate projection cannot fit its conservative serialized output bound"
            }

            val listingTypesByOrdinal = uniqueBy(
                listingRecords.filterIsInstance<NativeInterfaceTypeV1>(), NativeInterfaceTypeV1::ordinal, "listing type ordinal",
            )
            val listingByEntry = uniqueBy(listingFunctions, NativeInterfaceFunctionV1::entry, "listing function entry")
            val inferredByEntry = uniqueBy(inferredFunctions, NativeInferredInterfaceFunctionV1::entry, "inferred function entry")
            val classifiedRoots = RecoveredAbiTypeGraphClassifierV1.classify(
                inferredRecords, target, inferred.dataOrganization,
                minOf(limits.maximumParameters.toLong() * 4L + limits.maximumNativeFunctions.toLong() * 2L,
                    3_393_216L).coerceAtLeast(1L).toInt(), checkpoint,
            )
            val listingFunctionOrdinals = listingFunctions.withIndex().associate { it.value.entry to it.index }
            val observedByEntry = uniqueBy(listing.observedFunctions, NativeInterfaceObservedFunctionV1::entry, "observed function entry")
            val modelById = uniqueBy(listing.modelFunctions, NativeInterfaceModelFunctionV1::id, "model function ID")
            require(listingByEntry.keys == observedByEntry.keys && inferredByEntry.keys == observedByEntry.keys) {
                "listing, inferred and native census entries differ"
            }
            for ((entry, listingFunction) in listingByEntry) {
                checkpoint()
                val inferredFunction = inferredByEntry.getValue(entry)
                require(listingFunction.isExternal == inferredFunction.isExternal && listingFunction.isThunk == inferredFunction.isThunk) {
                    "inference function flags differ from the paired listing entry"
                }
            }
            require(modelById.values.all { it.state in MODEL_STATES } && observedByEntry.values.all { it.state in OBSERVED_STATES }) {
                "interface mapping uses an unsupported disposition"
            }
            validateMappingAssessment(listing, listingByEntry, observedByEntry)

            val matchedListingEntry = HashMap<String, decompengine.project.NativeInterfaceAddressV1>()
            val consumedNativeEntries = HashSet<decompengine.project.NativeInterfaceAddressV1>()
            for (model in listing.modelFunctions) {
                checkpoint()
                if (model.state != "matched") continue
                require(model.candidateEntries.size == 1) { "matched model row must have one native candidate" }
                val entry = model.candidateEntries.single()
                val observed = observedByEntry[entry] ?: error("matched model candidate is absent from native census")
                require(observed.state == "matched" && observed.modelIds == listOf(model.id)) {
                    "model and native mapping assessments disagree"
                }
                val listingFunction = listingByEntry[entry] ?: error("matched listing record is missing")
                val inferredFunction = inferredByEntry[entry] ?: error("paired inference record is missing")
                require(!listingFunction.isExternal && listingFunction.isThunk == inferredFunction.isThunk &&
                    !inferredFunction.isExternal) { "matched function metadata differs across raw channels" }
                require(matchedListingEntry.put(model.id, entry) == null && consumedNativeEntries.add(entry)) {
                    "native listing entry is assigned to more than one model function"
                }
            }
            for ((entry, observed) in observedByEntry) {
                if (observed.state == "matched") {
                    require(observed.modelIds.size == 1 && matchedListingEntry[observed.modelIds.single()] == entry) {
                        "native matched row does not have its exact model-side reciprocal"
                    }
                }
            }

            val entities = listing.modelFunctions.sortedBy { it.id }.map { model ->
                checkpoint()
                val entry = matchedListingEntry[model.id]
                val listingFunction = entry?.let(listingByEntry::get)
                val inferredFunction = entry?.let(inferredByEntry::get)
                val facts = ArrayList<JsonObject>()
                val reasons = ArrayList<JsonObject>()
                fun addFact(dimension: String, slot: String, state: String, value: JsonElement?, reason: String, channel: String) {
                    val id = factId(model.id, dimension, slot)
                    facts += obj(
                        "id" to str(id), "dimension" to str(dimension), "slot" to str(slot),
                        "evidence" to evidence(listing.manifest.sha256, inferred.manifest.sha256),
                        "state" to str(state), "value" to (value ?: JsonNull),
                    )
                    reasons += obj("factId" to str(id), "channel" to str(channel), "reason" to str(reason))
                }

                addFact(PROTOTYPE, "prototype", "recovered-unknown", null,
                    if (entry == null) "native-function-not-uniquely-mapped" else "formal-source-prototype-is-not-derived-from-display-or-slot-counts",
                    "listing+inferred")

                val convention = listingFunction?.let { normalizedConvention(it, target) }
                if (convention?.value != null) {
                    addFact(CALLING_CONVENTION, "calling-convention", "recovered", convention.value,
                        "exact-raw-convention-name-and-resolved-model-alias-target-descriptor", "listing")
                } else {
                    val reason = when {
                        entry == null -> "native-function-not-uniquely-mapped"
                        listingFunction?.isThunk == true -> "thunk-signature-is-not-an-independent-interface"
                        listingFunction == null -> "listing-signature-not-observed"
                        else -> convention?.reason ?: "raw-convention-is-unknown-default-unresolved-or-absent-from-target-descriptor"
                    }
                    addFact(CALLING_CONVENTION, "calling-convention", "recovered-unknown", null, reason, "listing")
                }

                val variadic = inferredFunction?.let { normalizedVariadic(listingFunction, it, target) }
                if (variadic?.value != null) {
                    addFact(VARIADIC, "variadic", "recovered", variadic.value, "completed-highfunction-and-listing-varargs-agree", "inferred+listing")
                } else {
                    val reason = when {
                        entry == null -> "native-function-not-uniquely-mapped"
                        listingFunction?.isThunk == true -> "thunk-signature-is-not-an-independent-interface"
                        inferredFunction == null -> "inference-observation-is-missing"
                        else -> variadic?.reason ?: "inference-did-not-prove-a-consistent-varargs-observation"
                    }
                    addFact(VARIADIC, "variadic", "recovered-unknown", null, reason, "inferred+listing")
                }

                val functionOrdinal = listingFunction?.let { listingFunctionOrdinals[it.entry] }
                val returnCandidate = listingFunction?.returned?.let { returned ->
                    if (functionOrdinal == null || listingFunction.customStorage || returned.forcedIndirect || returned.autoParameterType != null) null
                    else classifiedFormalRoot(classifiedRoots, functionOrdinal, "return-formal", -1, returned.formalType, listingTypesByOrdinal, target)
                }
                if (returnCandidate?.value != null) {
                    addFact(RETURN_CLASS, "return", "recovered", returnCandidate.value,
                        returnCandidate.reason, "listing-formal-type-graph")
                } else {
                    val reason = when {
                        entry == null -> "native-function-not-uniquely-mapped"
                        listingFunction?.customStorage == true -> "custom-function-storage-can-override-target-abi-passing"
                        listingFunction?.returned?.forcedIndirect == true -> "return-forced-indirect-role-is-not-normalized"
                        listingFunction?.returned?.autoParameterType != null -> "return-auto-role-is-not-a-source-return-value"
                        listingFunction?.returned == null -> "listing-return-formal-type-is-absent"
                        else -> returnCandidate?.reason ?: "listing-return-formal-type-graph-is-unavailable-or-unsupported"
                    }
                    addFact(RETURN_CLASS, "return", "recovered-unknown", null, reason, "listing-formal-type-graph")
                }
                listingFunction?.parameters.orEmpty().sortedBy { it.ordinal }.forEach { parameter ->
                    checkpoint()
                    val parameterCandidate = if (functionOrdinal == null || listingFunction.customStorage || parameter.autoParameter ||
                        parameter.forcedIndirect || parameter.autoParameterType != null) null else classifiedFormalRoot(
                        classifiedRoots, functionOrdinal, "parameter-formal", parameter.ordinal, parameter.formalType, listingTypesByOrdinal, target,
                    )
                    if (parameterCandidate?.value != null) {
                        addFact(PARAMETER_CLASS, "parameter:${parameter.ordinal}", "recovered", parameterCandidate.value,
                            parameterCandidate.reason, "listing-formal-type-graph")
                    } else {
                        val reason = when {
                            entry == null -> "native-function-not-uniquely-mapped"
                            listingFunction?.customStorage == true -> "custom-function-storage-can-override-target-abi-passing"
                            parameter.autoParameter || parameter.autoParameterType != null -> "automatic-this-or-hidden-role-is-not-a-source-formal-parameter"
                            parameter.forcedIndirect -> "parameter-forced-indirect-role-is-not-normalized"
                            else -> parameterCandidate?.reason ?: "listing-formal-type-graph-is-unavailable-or-unsupported"
                        }
                        addFact(PARAMETER_CLASS, "parameter:${parameter.ordinal}", "recovered-unknown", null, reason, "listing-formal-type-graph")
                    }
                }

                val rawListing = listingFunction?.let { function -> obj(
                    "entry" to address(function.entry.spaceIndex, function.entry.offsetBits),
                    "external" to JsonPrimitive(function.isExternal), "thunk" to JsonPrimitive(function.isThunk),
                    "signatureSource" to str(function.signatureSource), "convention" to obj(
                        "name" to nullable(function.convention.name), "resolvedModel" to nullable(function.convention.resolvedModel),
                        "state" to str(function.convention.state)),
                    "variadic" to JsonPrimitive(function.varArgs), "customStorage" to JsonPrimitive(function.customStorage),
                    "parameterCount" to JsonPrimitive(function.parameterCount), "autoParameterCount" to JsonPrimitive(function.autoParameterCount),
                    "parameterOrdinals" to JsonArray(function.parameters.sortedBy { it.ordinal }.map { JsonPrimitive(it.ordinal) }),
                ) } ?: JsonNull
                val rawInferred = inferredFunction?.let { function -> obj(
                    "entry" to address(function.entry.spaceIndex, function.entry.offsetBits),
                    "disposition" to str(function.disposition), "attempt" to JsonPrimitive(function.attempt),
                    "thunk" to JsonPrimitive(function.isThunk),
                    "prototype" to (function.prototype?.let { proto -> obj(
                        "parameterCount" to JsonPrimitive(proto.parameterCount),
                        "localSymbolParameterCount" to JsonPrimitive(proto.localSymbolParameterCount),
                        "parameterCountsMatch" to JsonPrimitive(proto.parameterCountsMatch),
                        "variadic" to JsonPrimitive(proto.varArgs), "hasThis" to JsonPrimitive(proto.hasThis),
                        "returnTypeOrdinal" to nullable(proto.returnType),
                        "formalEffectiveRelation" to str(proto.formalEffectiveRelation),
                        "allMappings" to str(proto.allMappings),
                    ) } ?: JsonNull),
                    "parameters" to JsonArray(function.parameters.sortedBy { it.index }.map { parameter -> obj(
                        "index" to JsonPrimitive(parameter.index), "categoryIndex" to JsonPrimitive(parameter.categoryIndex),
                        "highParamSlot" to nullable(parameter.highParamSlot), "highVariableState" to str(parameter.highVariableState),
                        "typeOrdinal" to nullable(parameter.type), "isThisPointer" to JsonPrimitive(parameter.isThisPointer),
                        "isHiddenReturn" to JsonPrimitive(parameter.isHiddenReturn),
                    ) }),
                ) } ?: JsonNull

                obj(
                    "kind" to str("function"), "id" to str(model.id), "mappingState" to str(model.state),
                    "nativeEntry" to (entry?.let { address(it.spaceIndex, it.offsetBits) } ?: JsonNull),
                    "listingObservation" to rawListing, "inferredObservation" to rawInferred,
                    "facts" to JsonArray(facts), "decisions" to JsonArray(reasons),
                )
            }

            val nativeOnly = listing.observedFunctions.filter { it.entry !in consumedNativeEntries }
                .sortedWith(compareBy({ it.entry.spaceIndex }, { it.entry.offsetBits }))
                .map { observed ->
                    checkpoint()
                    val function = listingByEntry.getValue(observed.entry)
                    val inferredFunction = inferredByEntry.getValue(observed.entry)
                    obj(
                        "entry" to address(observed.entry.spaceIndex, observed.entry.offsetBits),
                        "mappingState" to str(observed.state), "modelIds" to JsonArray(observed.modelIds.sorted().map(::str)),
                        "external" to JsonPrimitive(function.isExternal), "thunk" to JsonPrimitive(function.isThunk),
                        "inferenceDisposition" to str(inferredFunction.disposition),
                        "listingParameterCount" to JsonPrimitive(function.parameterCount),
                        "inferredParameterCount" to JsonPrimitive(inferredFunction.parameters.size),
                    )
                }

            require(matchedListingEntry.size + nativeOnly.size == listing.scan.functions.toInt()) {
                "candidate and native-only partitions do not conserve the complete native census"
            }

            val bindings = obj(
                "targetAbiId" to str(target.id), "targetAbiSha256" to str(target.snapshot.sha256),
                "inputSha256" to str(listing.bindings.inputSha256),
                "programModelSha256" to str(listing.bindings.programModelSha256),
                "claimedListingObservationsSha256" to str(listing.manifest.sha256),
                "claimedListingManifestSha256" to str(inferred.bindings.listingManifestSha256),
                "claimedInferredObservationsSha256" to str(inferred.manifest.sha256),
                "typeGraphSha256" to str(inferred.manifest.typeGraphSha256),
                "configurationSha256" to str(inferred.manifest.configurationSha256),
            )
            val counts = obj(
                "modelFunctions" to JsonPrimitive(listing.modelFunctions.size),
                "listingFunctions" to JsonPrimitive(listing.scan.functions),
                "inferredFunctions" to JsonPrimitive(inferred.scan.functions),
                "matchedModelFunctions" to JsonPrimitive(matchedListingEntry.size),
                "nativeOnlyFunctions" to JsonPrimitive(nativeOnly.size),
                "listingParameters" to JsonPrimitive(listing.scan.parameters),
                "inferredParameters" to JsonPrimitive(inferred.scan.parameters),
                "typeGraphRoots" to JsonPrimitive(inferred.scan.roots),
                "typeGraphNodes" to JsonPrimitive(inferred.scan.graphNodes),
                "typeGraphEdges" to JsonPrimitive(inferred.scan.graphEdges),
            )
            val document = obj(
                "schemaVersion" to JsonPrimitive(1),
                "kind" to str("recovered-abi-interface-candidate-projection-v1"),
                "scope" to str("untrusted-component-candidate"),
                "scoreStatus" to str("not-scored"),
                "bindings" to bindings,
                "counts" to counts,
                "candidateEntities" to JsonArray(entities),
                "nativeOnlyFunctions" to JsonArray(nativeOnly),
            )
            val bytes = OracleJson.canonicalBytes(document, jsonLimits(limits.maximumOutputBytes)) { _ -> checkpoint() }
            require(bytes.size <= limits.maximumOutputBytes) { "candidate projection exceeds its serialized byte bound" }
            return RecoveredAbiInterfaceCandidateProjectionV1(bytes)
        }

        private data class NormalizationResult(val value: JsonObject?, val reason: String)

        private data class TypeCandidateResult(val value: JsonObject?, val reason: String)

        /** Promote only exact listing formal roots; inferred graph roots have no cross-channel join. */
        private fun classifiedFormalRoot(
            classified: Map<RecoveredAbiTypeGraphClassifierV1.RootKey, RecoveredAbiTypeGraphClassifierV1.Result>,
            functionOrdinal: Int,
            role: String,
            slot: Int,
            typeOrdinal: Int?,
            listingTypesByOrdinal: Map<Int, NativeInterfaceTypeV1>,
            target: StructuralTargetAbiV1,
        ): TypeCandidateResult {
            if (typeOrdinal == null) return TypeCandidateResult(null, "listing-formal-type-reference-is-absent")
            val exactType = listingTypesByOrdinal[typeOrdinal]
                ?: return TypeCandidateResult(null, "listing-formal-type-ordinal-is-not-unique")
            val key = RecoveredAbiTypeGraphClassifierV1.RootKey(
                RecoveredAbiTypeGraphClassifierV1.ScopeKey("listing", functionOrdinal), role, slot,
            )
            val result = classified[key] ?: return TypeCandidateResult(null, "exact-listing-formal-graph-root-is-absent-or-ambiguous")
            if (result.root.listingTypeOrdinal != typeOrdinal || result.root.node == null) {
                return TypeCandidateResult(null, "formal-root-does-not-bind-the-exact-listing-type-occurrence")
            }
            val nativeNode = result.nativeNode ?: return TypeCandidateResult(null, "formal-root-native-node-is-absent")
            val expectedKinds = if (exactType.kind == "other") setOf("bitfield", "unsupported") else setOf(exactType.kind)
            if (nativeNode.kind !in expectedKinds || nativeNode.nativeClass != exactType.nativeClass ||
                nativeNode.length != exactType.length || nativeNode.alignedLength != exactType.alignedLength ||
                nativeNode.alignment != exactType.alignment || nativeNode.notYetDefined != exactType.notYetDefined ||
                nativeNode.undefined != exactType.undefined) {
                return TypeCandidateResult(null, "formal-root-typed-layout-disagrees-with-exact-listing-occurrence")
            }
            if (exactType.kind == "integer") {
                val graphSigned = (nativeNode.details["signed"] as? JsonPrimitive)?.booleanOrNull
                val listingSigned = when (exactType.signedness) { "signed" -> true; "unsigned" -> false; else -> null }
                if (listingSigned == null || graphSigned != listingSigned) {
                    return TypeCandidateResult(null, "integer-formal-signedness-is-not-proved-by-both-listing-channels")
                }
            }
            if (result.shape == null || result.classification?.known != true) {
                return TypeCandidateResult(null, result.reason)
            }
            // Graph metadata was already checked by the authenticated raw validator. Keep a local
            // consistency guard for caller-constructed candidate DTOs, without treating it as auth.
            if (result.shape.byteSize != exactType.length.toLong() || result.shape.alignmentBytes != exactType.alignment.toLong()) {
                return TypeCandidateResult(null, "formal-root-layout-disagrees-with-its-listing-occurrence")
            }
            val bits = result.classification.classes.map { it.name }
            if (bits.isEmpty()) return TypeCandidateResult(null, "target-classifier-produced-no-ABI-classes")
            val value = obj(
                "source" to str("type-token:${result.typeTokenSha256}"),
                "abi" to obj(
                    "callingConvention" to JsonNull,
                    "classes" to JsonArray(bits.map(::str)),
                    "sizeBits" to JsonPrimitive(Math.multiplyExact(result.shape.byteSize, 8L)),
                    "alignmentBits" to JsonPrimitive(Math.multiplyExact(result.shape.alignmentBytes, 8L)),
                    "variadic" to JsonNull,
                ),
            )
            validateStructuralValue(value, "candidate $role ABI class", if (role == "return-formal") RETURN_CLASS else PARAMETER_CLASS,
                target, StructuralRecoveryV1Limits())
            return TypeCandidateResult(value,
                "exact-listing-formal-type-root-classified-from-complete-capture-local-layout-under-explicit-sysv-amd64-target")
        }

        private fun normalizedConvention(function: NativeInterfaceFunctionV1, target: StructuralTargetAbiV1): NormalizationResult {
            val convention = function.convention
            if (convention.state != "named-resolved" || function.isExternal || function.isThunk) {
                return NormalizationResult(null, "convention-is-not-an-independent-resolved-function-interface")
            }
            val rawName = convention.name ?: return NormalizationResult(null, "convention-name-is-absent")
            val resolvedName = convention.resolvedModel ?: return NormalizationResult(null, "resolved-convention-model-is-absent")
            val rawCanonical = target.conventionAliases[rawName]
                ?: return NormalizationResult(null, "raw-convention-is-absent-from-target-descriptor")
            val resolvedCanonical = target.conventionAliases[resolvedName]
                ?: return NormalizationResult(null, "resolved-convention-is-absent-from-target-descriptor")
            if (rawCanonical != resolvedCanonical) return NormalizationResult(null, "raw-and-resolved-convention-map-to-different-target-entries")
            val value = obj(
                "source" to str("convention:$rawName"),
                "abi" to abiValue(callingConvention = rawCanonical),
            )
            validateStructuralValue(value, "candidate calling convention", CALLING_CONVENTION, target, StructuralRecoveryV1Limits())
            return NormalizationResult(value, "exact-raw-convention-name-and-resolved-model-alias-target-descriptor")
        }

        private fun normalizedVariadic(
            listing: NativeInterfaceFunctionV1?, inferred: NativeInferredInterfaceFunctionV1, target: StructuralTargetAbiV1,
        ): NormalizationResult {
            if (listing == null) return NormalizationResult(null, "listing-function-is-absent")
            if (listing.isThunk || inferred.isThunk) {
                return NormalizationResult(null, "thunk-signature-is-not-an-independent-interface")
            }
            if (inferred.disposition != "high-function-observed" || inferred.prototype == null) {
                return NormalizationResult(null, "highfunction-prototype-was-not-observed")
            }
            val prototype = inferred.prototype
            val result = inferred.result
            if (result == null || !result.completed || !result.valid || result.timedOut || result.cancelled || result.failedToStart) {
                return NormalizationResult(null, "highfunction-result-is-not-a-completed-valid-observation")
            }
            if (!prototype.parameterCountsMatch || prototype.parameterCount != inferred.parameters.size) {
                return NormalizationResult(null, "highfunction-parameter-counts-do-not-match")
            }
            if (listing.varArgs != prototype.varArgs) return NormalizationResult(null, "listing-and-highfunction-varargs-disagree")
            val value = obj("source" to JsonPrimitive(prototype.varArgs), "abi" to abiValue(variadic = prototype.varArgs))
            validateStructuralValue(value, "candidate variadic", VARIADIC, target, StructuralRecoveryV1Limits())
            return NormalizationResult(value, "completed-highfunction-and-listing-varargs-agree")
        }

        private fun requireCompatibleInputs(listing: NativeInterfaceObservationSummaryV1, inferred: NativeInferredInterfaceSummaryV1) {
            val nested = inferred.listing
            require(nested.manifest == listing.manifest && nested.bindings == listing.bindings && nested.scan == listing.scan &&
                nested.modelFunctions == listing.modelFunctions && nested.observedFunctions == listing.observedFunctions &&
                nested.addressSpaces == listing.addressSpaces) { "inference summary does not embed the supplied listing assessment" }
            require(inferred.manifest.listingSha256 == listing.manifest.sha256 &&
                inferred.bindings.listingSha256 == listing.manifest.sha256 &&
                inferred.manifest.programModelSha256 == listing.manifest.programModelSha256 &&
                inferred.manifest.inputSha256 == listing.manifest.inputSha256) {
                "inference manifest does not bind the exact listing, model and input commitments"
            }
        }

        /** Recheck the public DTO mapping rows against the supplied census; this is consistency, not byte authentication. */
        private fun validateMappingAssessment(
            listing: NativeInterfaceObservationSummaryV1,
            listingByEntry: Map<decompengine.project.NativeInterfaceAddressV1, NativeInterfaceFunctionV1>,
            observedByEntry: Map<decompengine.project.NativeInterfaceAddressV1, NativeInterfaceObservedFunctionV1>,
        ) {
            val modelByAddress = listing.modelFunctions.groupBy { row ->
                require(row.modelAddressBits.matches(Regex("[0-9a-f]{16}"))) { "model address is not canonical" }
                row.modelAddressBits
            }
            val nativeByOffset = listingByEntry.values.filterNot { it.isExternal }.groupBy { function ->
                checkNotNull(function.entry.offsetBits) { "function entry must have an address" }
            }
            for (model in listing.modelFunctions) {
                val candidates = nativeByOffset[model.modelAddressBits].orEmpty().map { it.entry }
                val expectedState = when {
                    modelByAddress.getValue(model.modelAddressBits).size != 1 -> "ambiguous-model-address"
                    candidates.size > 1 -> "ambiguous-native-address"
                    candidates.isEmpty() -> "missing-listing-function"
                    candidates.single().spaceIndex != listing.bindings.imageBase.spaceIndex -> "different-address-space"
                    else -> "matched"
                }
                require(model.state == expectedState && model.candidateEntries.size == candidates.size &&
                    model.candidateEntries.toSet() == candidates.toSet()) {
                    "model mapping row disagrees with the complete listing census"
                }
            }
            val modelIdsByAddress = modelByAddress.mapValues { (_, rows) -> rows.map { it.id }.sorted() }
            for ((entry, observed) in observedByEntry) {
                val function = listingByEntry.getValue(entry)
                val modelIds = if (function.isExternal) emptyList() else modelIdsByAddress[checkNotNull(entry.offsetBits)].orEmpty()
                val sameOffsetNative = nativeByOffset[entry.offsetBits].orEmpty()
                val expectedState = when {
                    function.isExternal -> "external-unmapped"
                    modelIds.size > 1 -> "ambiguous-model-address"
                    modelIds.isNotEmpty() && sameOffsetNative.size > 1 -> "ambiguous-native-address"
                    entry.spaceIndex != listing.bindings.imageBase.spaceIndex -> "different-address-space"
                    modelIds.isEmpty() -> "unmatched-observed-function"
                    else -> "matched"
                }
                require(observed.state == expectedState && observed.modelIds == modelIds) {
                    "native mapping row disagrees with the complete model/listing census"
                }
            }
        }

        private fun validateScanCounts(
            listing: NativeInterfaceObservationSummaryV1,
            listingFunctions: List<NativeInterfaceFunctionV1>,
            listingTypes: Int,
            inferred: NativeInferredInterfaceSummaryV1,
            inferredFunctions: List<NativeInferredInterfaceFunctionV1>,
        ) {
            val listingInternal = listingFunctions.count { !it.isExternal }.toLong()
            val listingExternal = listingFunctions.count { it.isExternal }.toLong()
            val listingThunks = listingFunctions.count { it.isThunk }.toLong()
            val listingParameters = listingFunctions.sumOf { it.parameters.size.toLong() }
            val listingAutoParameters = listingFunctions.sumOf { function -> function.parameters.count { it.autoParameter }.toLong() }
            val listingStorage = listingFunctions.sumOf { function ->
                function.parameters.sumOf { it.storage.varnodes.size.toLong() } + (function.returned?.storage?.varnodes?.size ?: 0)
            }
            require(listing.scan == listing.scan.copy(functions = listingFunctions.size.toLong(), internalFunctions = listingInternal,
                externalFunctions = listingExternal, thunks = listingThunks, parameters = listingParameters,
                autoParameters = listingAutoParameters, types = listingTypes.toLong(), storageVarnodes = listingStorage)) {
                "listing summary does not conserve all supplied channel populations"
            }
            val attempts = inferredFunctions.sumOf { it.attempt.toLong() }
            val highFunctions = inferredFunctions.count { it.disposition == "high-function-observed" }.toLong()
            val inferredParameters = inferredFunctions.sumOf { it.parameters.size.toLong() }
            val inferredStorage = inferredFunctions.sumOf { function ->
                if (function.disposition != "high-function-observed") 0L else
                    function.parameters.sumOf { it.storage.varnodes.size.toLong() } +
                        checkNotNull(function.prototype).returnStorage.varnodes.size.toLong()
            }
            val dispositionCounts = NativeInferredInterfaceObservationsV1.dispositions.associateWith { state ->
                inferredFunctions.count { it.disposition == state }.toLong()
            }
            require(inferred.scan.dispositions.keys.all { it in NativeInferredInterfaceObservationsV1.dispositions } &&
                NativeInferredInterfaceObservationsV1.dispositions.all { inferred.scan.dispositions.getOrDefault(it, 0L) == dispositionCounts.getValue(it) }) {
                "inference summary does not conserve every supported or unsupported disposition"
            }
            val alignmentRows = (inferred.dataOrganization["sizeAlignments"] as? JsonArray)?.size
                ?: error("inference data organization does not contain typed alignment rows")
            val graphWork = Math.addExact(inferred.scan.roots,
                Math.addExact(Math.multiplyExact(3L, inferred.scan.graphNodes),
                    Math.addExact(Math.multiplyExact(3L, inferred.scan.graphEdges), 1L + alignmentRows)))
            require(inferred.scan.functions == listing.scan.functions && inferred.scan.internalFunctions == listing.scan.internalFunctions &&
                inferred.scan.externalFunctions == listing.scan.externalFunctions && inferred.scan.thunks == listing.scan.thunks &&
                inferred.scan.attempted == attempts && inferred.scan.observed == highFunctions && inferred.scan.parameters == inferredParameters &&
                inferred.scan.storageVarnodes == inferredStorage && inferred.scan.graphWork == graphWork) {
                "inference summary does not conserve all supplied channel populations"
            }
        }

        private fun <K, V> uniqueBy(values: Collection<V>, key: (V) -> K, label: String): Map<K, V> {
            val result = LinkedHashMap<K, V>()
            values.forEach { value -> require(result.put(key(value), value) == null) { "$label is duplicated" } }
            return result
        }

        private fun factId(functionId: String, dimension: String, slot: String): String {
            val digest = MessageDigest.getInstance("SHA-256").digest("$functionId\u0000$dimension\u0000$slot".toByteArray(StandardCharsets.UTF_8))
                .joinToString("") { "%02x".format(it) }
            return "abi-candidate-$digest"
        }

        private fun evidence(listingSha: String, inferredSha: String) = JsonArray(listOf(
            obj("kind" to str("native-interface-v1"), "locator" to str(listingSha)),
            obj("kind" to str("native-inferred-interface-v1"), "locator" to str(inferredSha)),
        ))

        private fun abiValue(callingConvention: String? = null, variadic: Boolean? = null) = obj(
            "callingConvention" to nullable(callingConvention), "classes" to JsonArray(emptyList()),
            "sizeBits" to JsonNull, "alignmentBits" to JsonNull, "variadic" to nullable(variadic),
        )

        private fun address(space: Int?, offset: String?): JsonElement = if (space == null) JsonNull else obj(
            "spaceIndex" to JsonPrimitive(space), "offsetBits" to str(checkNotNull(offset)),
        )

        private fun obj(vararg values: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*values))
        private fun str(value: String) = JsonPrimitive(value)
        private fun nullable(value: String?) = value?.let(::str) ?: JsonNull
        private fun nullable(value: Int?) = value?.let(::JsonPrimitive) ?: JsonNull
        private fun nullable(value: Boolean?) = value?.let(::JsonPrimitive) ?: JsonNull

        private val MODEL_STATES = setOf("matched", "ambiguous-model-address", "ambiguous-native-address", "missing-listing-function", "different-address-space")
        private val OBSERVED_STATES = setOf("matched", "external-unmapped", "ambiguous-model-address", "ambiguous-native-address", "different-address-space", "unmatched-observed-function")
    }
}

data class RecoveredAbiInterfaceCandidateProjectionLimitsV1(
    val maximumModelFunctions: Int = 50_000,
    val maximumNativeFunctions: Int = 131_072,
    val maximumParameters: Long = 1_000_000,
    val maximumInputTextBytes: Long = 32L * 1024 * 1024,
    val maximumOutputBytes: Int = 64 * 1024 * 1024,
) {
    init {
        require(maximumModelFunctions in 1..50_000)
        require(maximumNativeFunctions in 1..131_072)
        require(maximumParameters in 0..1_000_000)
        require(maximumInputTextBytes in 1..32L * 1024 * 1024)
        require(maximumOutputBytes in 1..64 * 1024 * 1024)
    }
}
