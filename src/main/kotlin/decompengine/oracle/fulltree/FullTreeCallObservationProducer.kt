package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.OutputStream
import java.nio.file.Path
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Independent implementation ceilings for one artifact-backed call-observation shard. */
internal data class FullTreeCallObservationProducerLimits(
    val dieLimits: FullTreeDwarfDieLimits = FullTreeDwarfDieLimits(
        maximumPhysicalRecords = 10_000_000L,
        maximumNonNullRecords = 5_000_000,
        maximumAttributes = 50_000_000L,
        maximumTreeDepth = 65_536,
        maximumRetainedBytes = 64L * 1024L * 1024L,
    ),
    val elfLayoutLimits: FullTreeElfLayoutLimits = FullTreeElfLayoutLimits(),
    val maximumReferenceChainEntries: Int = 32,
    val maximumCachedCompilationUnits: Int = 2,
    val maximumScannedDies: Long = 50_000_000L,
    val maximumCalls: Int = 50_000,
    val maximumRetainedBytes: Long = 64L * 1024L * 1024L,
) {
    init {
        require(maximumReferenceChainEntries in 1..32)
        require(maximumCachedCompilationUnits in 1..32)
        require(maximumScannedDies in 1L..1_000_000_000L)
        require(maximumCalls in 1..1_000_000)
        require(maximumRetainedBytes in 1L..1024L * 1024L * 1024L)
    }
}

internal data class FullTreeCallObservationShardGeneration(
    val shardId: String,
    val inputSha256: String,
    val inventoryArtifactSha256: String,
    val richArtifactSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
    val scannedDies: Long,
    val document: JsonObject,
)

internal class FullTreeCallObservationAuthenticatedInputs internal constructor(
    val inventory: JsonObject,
    val inventoryArtifactSha256: String,
    val shard: FullTreeCallObservationShardInput,
)

internal data class FullTreeObservedCallTarget(
    val kind: String,
    val dispatchKind: String,
    val functionId: String?,
    val aliases: List<String>,
    val originDieOffset: ULong?,
    val provenFunctionIds: List<String>,
    val targetEvidence: String,
)

internal data class FullTreeObservedCallSite(
    val callerId: String?,
    val callerLocalReturnOffset: ULong?,
    val dieOffset: ULong,
    val population: String,
    val reasonCode: String?,
    val returnPcRva: ULong?,
    val target: FullTreeObservedCallTarget,
    val tailCall: Boolean,
    val unitId: String,
)

/**
 * Raw Kotlin/JVM call observer over authenticated ELF/DWARF bytes.
 *
 * The bounded diagnostic collector and streaming SQLite sink share the same traversal and
 * policy-v3 record projection. Python and ACP have no entry point into the scan.
 */
internal object FullTreeCallObservationProducer {
    fun generateShardTo(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        output: OutputStream,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        producerLimits: FullTreeCallObservationProducerLimits = FullTreeCallObservationProducerLimits(),
        sqliteLimits: FullTreeCallObservationSqliteLimits = FullTreeCallObservationSqliteLimits(),
    ): FullTreeCallObservationStreamResult = generateShardToWithinDeadline(
        richArtifact, inventoryPath, scope, shardId, scratchParent, output,
        controlLimits, producerLimits, sqliteLimits, FullTreeCallObservationDeadline.start(scope, controlLimits),
    )

    internal fun generateShardToWithinDeadline(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        output: OutputStream,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        producerLimits: FullTreeCallObservationProducerLimits = FullTreeCallObservationProducerLimits(),
        sqliteLimits: FullTreeCallObservationSqliteLimits = FullTreeCallObservationSqliteLimits(),
        deadline: FullTreeCallObservationDeadline,
    ): FullTreeCallObservationStreamResult {
        deadline.requireScope(scope)
        val checkpoint = deadline::checkpoint
        checkpoint("before authenticating call-observation scope")
        FullTreeScopeControl.validate(scope, controlLimits)
        val bounds = scope.document.controlObject("bounds").controlObject("perShard")
        checkpoint("after authenticating call-observation scope")
        val boundedSqlite = sqliteLimits.copy(
            maximumCalls = minOf(
                sqliteLimits.maximumCalls.toLong(), producerLimits.maximumCalls.toLong(), bounds.controlLong("entities"),
            ).toInt(),
            maximumDatabaseBytes = minOf(
                sqliteLimits.maximumDatabaseBytes,
                maxOf(4096L, minOf(bounds.controlLong("serializedBytes"), sqliteLimits.maximumDatabaseBytes) * 4L),
            ),
            maximumOutputBytes = minOf(sqliteLimits.maximumOutputBytes, bounds.controlLong("serializedBytes")),
            maximumScannedDies = minOf(sqliteLimits.maximumScannedDies, producerLimits.maximumScannedDies),
        )
        val modeledSinkBytes = boundedSqlite.maximumCacheBytes.toLong() +
            boundedSqlite.maximumRecordBytes.toLong() * 8L + 16L * 1024L * 1024L
        val boundedProducer = producerLimits.copy(
            maximumRetainedBytes = maxOf(producerLimits.maximumRetainedBytes, modeledSinkBytes),
        )
        requireResidentBudget(scope.document, boundedProducer)
        checkpoint("before opening call-observation inputs")
        StableControlFile.open(inventoryPath, controlLimits.maximumInventoryBytes.toLong(), "call inventory").use { inventory ->
            checkpoint("after opening call-observation inventory")
            StableControlFile.open(richArtifact, controlLimits.maximumRichArtifactBytes, "call artifact").use { artifact ->
                checkpoint("after opening call-observation artifact")
                val inputs = authenticateShardInputs(inventoryPath, scope, shardId, controlLimits, checkpoint)
                require(inputs.inventoryArtifactSha256 == inventory.authenticatedSha256) {
                    "call-observation inventory changed during authentication"
                }
                val expectedArtifact = scope.document.controlObject("oracle").controlString("richArtifactSha256")
                require(artifact.authenticatedSha256 == expectedArtifact) { "call-observation artifact differs from scope" }
                FullTreeCallObservationSqlite.open(scratchParent, inputs, scope, boundedSqlite, checkpoint).use { sink ->
                    scanAuthenticatedShard(
                        richArtifact, scope, inputs, scratchParent, controlLimits, boundedProducer,
                        checkpoint = checkpoint,
                        recordScannedDies = sink::recordScannedDies, accept = sink::accept,
                    )
                    checkpoint("before authenticating call-observation projection inputs")
                    inventory.verifyUnchanged("inventory before call projection")
                    checkpoint("after authenticating inventory before call projection")
                    artifact.verifyUnchanged("artifact before call projection")
                    checkpoint("after authenticating artifact before call projection")
                    val result = sink.finishTo(output)
                    FullTreeScopeControl.validate(scope, controlLimits)
                    checkpoint("after authenticating scope after call projection")
                    inventory.verifyUnchanged("inventory after call projection")
                    checkpoint("after authenticating inventory after call projection")
                    artifact.verifyUnchanged("artifact after call projection")
                    checkpoint("after authenticating artifact after call projection")
                    return result
                }
            }
        }
    }

    fun generateShard(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
    ): FullTreeCallObservationShardGeneration = generateShardWithLimits(
        richArtifact,
        inventoryPath,
        scope,
        shardId,
        scratchParent,
        controlLimits,
        FullTreeCallObservationProducerLimits(),
    )

    internal fun generateShardWithLimits(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits,
        producerLimits: FullTreeCallObservationProducerLimits,
    ): FullTreeCallObservationShardGeneration {
        FullTreeScopeControl.validate(scope, controlLimits)
        requireStableDirectory(scratchParent, "call-observation scratch parent")
        requireResidentBudget(scope.document, producerLimits)
        val inputs = authenticateShardInputs(
            inventoryPath,
            scope,
            shardId,
            controlLimits,
        )
        val accumulator = CallObservationAccumulator(inputs.shard, producerLimits)
        val richArtifactSha256 = scanAuthenticatedShard(
            richArtifact = richArtifact,
            scope = scope,
            inputs = inputs,
            scratchParent = scratchParent,
            controlLimits = controlLimits,
            producerLimits = producerLimits,
            recordScannedDies = accumulator::recordScannedDies,
            accept = accumulator::accept,
        )
        val document = accumulator.finish(
            inventoryIndexSha256 = inputs.inventory.controlString("indexSha256"),
            richArtifactSha256 = richArtifactSha256,
            scopeSha256 = scope.sha256,
        )
        FullTreeCallObservations.validateEnvelope(
            document,
            scope.document,
            scope.sha256,
            inputs.inventory,
            inputs.inventoryArtifactSha256,
            inputs.shard,
        )
        val output = FullTreeCallObservations.canonicalEnvelopeBytes(document)
        return FullTreeCallObservationShardGeneration(
            shardId = inputs.shard.identifier,
            inputSha256 = inputs.shard.inputSha256,
            inventoryArtifactSha256 = inputs.inventoryArtifactSha256,
            richArtifactSha256 = richArtifactSha256,
            outputSha256 = OracleArtifacts.sha256(output),
            outputBytes = output.size.toLong(),
            entities = document.controlObject("counts").controlLong("observedCallSites"),
            scannedDies = document.controlObject("counts").controlLong("scannedDies"),
            document = document,
        )
    }

    internal fun authenticateShardInputs(
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        checkpoint: (String) -> Unit = {},
    ): FullTreeCallObservationAuthenticatedInputs {
        FullTreeScopeControl.validate(scope, controlLimits)
        checkpoint("after authenticating call-observation scope")
        val (inventory, inventoryBytes) = readCanonicalControlObject(
            inventoryPath,
            controlLimits.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        )
        FullTreeInventoryControl.validate(inventory, scope, controlLimits)
        checkpoint("after authenticating call-observation inventory")
        val inventoryArtifactSha256 = OracleArtifacts.sha256(inventoryBytes)
        val shard = FullTreeCallObservations.shardInputs(
            inventory,
            inventoryArtifactSha256,
            scope.document,
            scope.sha256,
        ).singleOrNull { it.identifier == shardId }
            ?: throw FullTreeControlException(
                "call-observation shard is absent from the authenticated inventory: $shardId",
            )
        return FullTreeCallObservationAuthenticatedInputs(inventory, inventoryArtifactSha256, shard)
    }

    internal fun scanAuthenticatedShard(
        richArtifact: Path,
        scope: AuthenticatedFullTreeScope,
        inputs: FullTreeCallObservationAuthenticatedInputs,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits,
        producerLimits: FullTreeCallObservationProducerLimits,
        checkpoint: (String) -> Unit = {},
        recordScannedDies: (Long) -> Unit,
        accept: (FullTreeObservedCallSite) -> Unit,
    ): String {
        FullTreeScopeControl.validate(scope, controlLimits)
        requireStableDirectory(scratchParent, "call-observation scratch parent")
        requireResidentBudget(scope.document, producerLimits)
        val authenticated = FullTreeCallObservations.shardInputs(
            inputs.inventory,
            inputs.inventoryArtifactSha256,
            scope.document,
            scope.sha256,
        ).singleOrNull { it.identifier == inputs.shard.identifier }
            ?: throw FullTreeControlException("call-observation scan input is outside the inventory")
        if (authenticated.inputSha256 != inputs.shard.inputSha256 || authenticated.units != inputs.shard.units) {
            throw FullTreeControlException("call-observation scan input is not authenticated")
        }

        StableControlFile.open(
            richArtifact,
            controlLimits.maximumRichArtifactBytes,
            "rich artifact",
        ).use { artifact ->
            val richArtifactSha256 = artifact.sha256(checkpoint, "rich artifact")
            if (richArtifactSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")) {
                throw FullTreeControlException("rich artifact does not match the full-tree scope")
            }
            val observedUnits = FullTreeDwarfCompilationUnits.read(
                artifact,
                scratchParent,
                scope.document,
                controlLimits,
                checkpoint,
            )
            checkpoint("after authenticating rich-artifact compilation units")
            FullTreeFunctionObservationProducer.authenticateInventoryAgainstArtifact(
                inputs.inventory,
                observedUnits,
                scope.document,
            )
            val layout = FullTreeElfLayout.scanLayout(
                artifact,
                "rich artifact",
                producerLimits.elfLayoutLimits,
                checkpoint,
            )
            val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)
            FullTreeDwarfSections.open(
                artifact,
                scratchParent,
                controlLimits,
                FullTreeDwarfSections.FUNCTION_OBSERVATION_SECTION_NAMES,
            ).use { sections ->
                scanSections(
                    sections,
                    layout,
                    executable,
                    inputs.inventory,
                    inputs.shard,
                    controlLimits,
                    producerLimits,
                    checkpoint,
                    recordScannedDies,
                    accept,
                )
            }
            artifact.verifyUnchanged("rich artifact after call observation")
            return richArtifactSha256
        }
    }

    private fun scanSections(
        sections: FullTreeDwarfSections,
        layout: FullTreeElfCoreLayout,
        executable: FullTreeElfExecutableMembership,
        inventory: JsonObject,
        shard: FullTreeCallObservationShardInput,
        controlLimits: FullTreeControlLimits,
        producerLimits: FullTreeCallObservationProducerLimits,
        checkpoint: (String) -> Unit,
        recordScannedDies: (Long) -> Unit,
        accept: (FullTreeObservedCallSite) -> Unit,
    ) {
        val info = sections.required(".debug_info")
        val parseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
        val headers = FullTreeFunctionObservationProducer.readAllHeaders(
            info,
            inventory.controlArray("units").size,
            parseBudget,
        )
        val headersByOffset = headers.associateBy { it.offset }
        val repository = FunctionDwarfUnitRepository(
            sections,
            headers,
            controlLimits,
            repositoryLimits(producerLimits),
            parseBudget,
            retainedTags = setOf(
                DW_TAG_FORMAL_PARAMETER,
                DW_TAG_MEMBER,
                DW_TAG_SUBPROGRAM,
                DW_TAG_VARIABLE,
                DW_TAG_CALL_SITE,
            ),
            contextForAttribute = ::callAttributeContext,
        )
        shard.units.forEach { unit ->
            val offset = parseDwarfOffset(unit.controlString("dwarfOffset"), "inventory DWARF offset")
            val header = headersByOffset[offset]
                ?: throw FullTreeControlException(
                    "inventory compilation-unit offset is absent from the rich artifact: ${unit.controlString("id")}",
                )
            val owner = repository.load(header)
            recordScannedDies(owner.index.physicalRecordCount)
            owner.index.recordsInPhysicalOrder.forEach { record ->
                when (record.tag) {
                    DW_TAG_CALL_SITE -> accept(
                        observeCall(
                            owner,
                            record,
                            nearestParentSubprogram(owner.index, record),
                            unit.controlString("id"),
                            repository,
                            layout,
                            executable,
                            producerLimits,
                            parseBudget,
                        ),
                    )
                }
            }
        }
    }

    private fun nearestParentSubprogram(
        index: FullTreeDwarfDieIndex,
        call: FullTreeDwarfDieRecord,
    ): FullTreeDwarfDieRecord? {
        var offset = call.nearestRetainedParentOffset
        while (offset != null) {
            val parent = index.required(offset, "call-site retained ancestor")
            if (parent.tag == DW_TAG_SUBPROGRAM) return parent
            offset = parent.nearestRetainedParentOffset
        }
        return null
    }

    private fun observeCall(
        owner: FunctionDwarfUnit,
        call: FullTreeDwarfDieRecord,
        caller: FullTreeDwarfDieRecord?,
        unitId: String,
        repository: FunctionDwarfUnitRepository,
        layout: FullTreeElfCoreLayout,
        executable: FullTreeElfExecutableMembership,
        producerLimits: FullTreeCallObservationProducerLimits,
        parseBudget: FullTreeDwarfParseBudget,
    ): FullTreeObservedCallSite {
        val returnAttribute = call.optionalUniqueAttribute(DW_AT_CALL_RETURN_PC, "DW_AT_call_return_pc")
            ?: call.optionalUniqueAttribute(DW_AT_CALL_PC, "DW_AT_call_pc")
        val returnAddress = returnAttribute?.let { callAddress(owner, it, "call-site return address") }
        val returnRva = returnAddress?.toExecutableRva(layout.imageBase, executable)
        val callerRva = caller?.functionStart(owner)?.toExecutableRva(layout.imageBase, executable)
            ?.takeIf { returnRva != null && it <= returnRva }
        val reason = when {
            returnRva == null -> "call-site-no-address"
            callerRva == null -> "caller-no-emitted-range"
            else -> null
        }
        return FullTreeObservedCallSite(
            callerId = callerRva?.let { "function-rva-${callHex(it)}" },
            callerLocalReturnOffset = if (callerRva != null && returnRva != null) returnRva - callerRva else null,
            dieOffset = call.offset.toULong(),
            population = if (reason == null) "scored" else "unobservable",
            reasonCode = reason,
            returnPcRva = returnRva,
            target = observeTarget(
                owner,
                call,
                repository,
                layout,
                executable,
                producerLimits,
                parseBudget,
            ),
            tailCall = call.truthy(DW_AT_CALL_TAIL_CALL, "DW_AT_call_tail_call"),
            unitId = unitId,
        )
    }

    private fun observeTarget(
        owner: FunctionDwarfUnit,
        call: FullTreeDwarfDieRecord,
        repository: FunctionDwarfUnitRepository,
        layout: FullTreeElfCoreLayout,
        executable: FullTreeElfExecutableMembership,
        producerLimits: FullTreeCallObservationProducerLimits,
        parseBudget: FullTreeDwarfParseBudget,
    ): FullTreeObservedCallTarget {
        val targetAttribute = call.optionalUniqueAttribute(DW_AT_CALL_TARGET, "DW_AT_call_target")
        val clobberedAttribute = call.optionalUniqueAttribute(
            DW_AT_CALL_TARGET_CLOBBERED,
            "DW_AT_call_target_clobbered",
        )
        clobberedAttribute?.let {
            validateExpression(owner, it, "DW_AT_call_target_clobbered", parseBudget)
        }
        val targetEvidence = when {
            targetAttribute != null && clobberedAttribute != null -> "call-target-and-clobbered-expressions"
            targetAttribute != null -> "call-target-expression"
            clobberedAttribute != null -> "call-target-clobbered-expression"
            else -> "none"
        }
        val proven = targetAttribute?.let { attribute ->
            singleAddressExpression(owner, attribute, parseBudget)
                ?.toExecutableRva(layout.imageBase, executable)
        }?.let { listOf("function-rva-${callHex(it)}") } ?: emptyList()
        val originAttribute = call.optionalUniqueAttribute(DW_AT_CALL_ORIGIN, "DW_AT_call_origin")
        if (originAttribute == null) {
            val kind = if (proven.isEmpty()) "indirect-unresolved" else "indirect-proven"
            return FullTreeObservedCallTarget(
                kind,
                kind,
                null,
                emptyList(),
                null,
                proven,
                targetEvidence,
            )
        }
        val origin = repository.resolveReference(owner, originAttribute, "DW_AT_call_origin")
        if (origin.record.tag !in CALL_ORIGIN_TAGS) {
            throw FullTreeControlException("DW_AT_call_origin identifies an unsupported DIE tag")
        }
        val chain = repository.referenceChain(
            origin.unit,
            origin.record,
            producerLimits.maximumReferenceChainEntries,
        )
        val compatibleOriginTags = when (origin.record.tag) {
            DW_TAG_MEMBER,
            DW_TAG_VARIABLE,
            -> CALL_OBJECT_ORIGIN_TAGS
            else -> setOf(origin.record.tag)
        }
        if (chain.any { it.record.tag !in compatibleOriginTags }) {
            throw FullTreeControlException(
                "DW_AT_call_origin reference chain changes DIE kind",
            )
        }
        if (origin.record.tag != DW_TAG_SUBPROGRAM) {
            val kind = if (proven.isEmpty()) "indirect-unresolved" else "indirect-proven"
            return FullTreeObservedCallTarget(
                kind,
                kind,
                null,
                emptyList(),
                null,
                proven,
                targetEvidence,
            )
        }
        val aliases = observeOriginNames(chain)
        val virtual = chain.firstNotNullOfOrNull { source ->
            source.record.optionalIntegral(DW_AT_VIRTUALITY, "DW_AT_virtuality")
        } ?: 0UL
        if (virtual != 0UL) {
            return FullTreeObservedCallTarget(
                "virtual-unresolved",
                "virtual-unresolved",
                null,
                aliases,
                origin.record.offset.toULong(),
                emptyList(),
                targetEvidence,
            )
        }
        val internal = origin.unit.functionStart(origin.record)
            ?.toExecutableRva(layout.imageBase, executable)
        return FullTreeObservedCallTarget(
            kind = if (internal == null) "external-unresolved" else "direct-internal",
            dispatchKind = "direct",
            functionId = internal?.let { "function-rva-${callHex(it)}" },
            aliases = aliases,
            originDieOffset = origin.record.offset.toULong(),
            provenFunctionIds = emptyList(),
            targetEvidence = targetEvidence,
        )
    }

    private fun observeOriginNames(chain: List<ResolvedFunctionDie>): List<String> {
        val names = sortedSetOf(FULL_TREE_CODE_POINT_ORDER)
        for (source in chain) {
            for ((attributeName, attributeLabel) in FUNCTION_NAME_ATTRIBUTES) {
                val attribute = source.record.optionalUniqueAttribute(attributeName, attributeLabel) ?: continue
                names += FullTreeDwarfForms.decodeString(
                    attribute.value,
                    source.unit.sections,
                    source.unit.stringOffsetsBase,
                    source.unit.header.offsetSize,
                    source.unit.controlLimits,
                    "call origin $attributeLabel",
                    maximumCharacters = 16_384,
                )
            }
        }
        if (names.isEmpty()) {
            throw FullTreeControlException(
                "call-origin subprogram ${canonicalHex(chain.first().record.offset)} has no resolvable name",
            )
        }
        return Collections.unmodifiableList(names.toList())
    }

    private fun callAddress(
        owner: FunctionDwarfUnit,
        attribute: FullTreeDwarfDieAttribute,
        label: String,
    ): ULong = when (val value = attribute.value) {
        is FullTreeDwarfAddressValue -> value.rawValue
        is FullTreeDwarfAddressIndexValue -> owner.resolveAddress(value)
        else -> throw FullTreeControlException("$label must have DWARF address class")
    }

    private fun singleAddressExpression(
        owner: FunctionDwarfUnit,
        attribute: FullTreeDwarfDieAttribute,
        parseBudget: FullTreeDwarfParseBudget,
    ): ULong? {
        val expression = expressionValue(attribute, "DW_AT_call_target")
        return expression.inspect { bytes ->
            FullTreeDwarfExpressions.singleAddressOrNull(
                bytes,
                owner.header.addressSize,
                owner.header.offsetSize,
                owner.sections.required(".debug_info").byteOrder,
                chargeOperation = {
                    parseBudget.consume("DWARF call-target expression operations")
                },
            )
        }
    }

    private fun validateExpression(
        owner: FunctionDwarfUnit,
        attribute: FullTreeDwarfDieAttribute,
        label: String,
        parseBudget: FullTreeDwarfParseBudget,
    ) {
        expressionValue(attribute, label).inspect { bytes ->
            FullTreeDwarfExpressions.singleAddressOrNull(
                bytes,
                owner.header.addressSize,
                owner.header.offsetSize,
                owner.sections.required(".debug_info").byteOrder,
                chargeOperation = {
                    parseBudget.consume("DWARF call-target expression operations")
                },
            )
        }
    }

    private fun expressionValue(
        attribute: FullTreeDwarfDieAttribute,
        label: String,
    ): FullTreeDwarfExpressionValue =
        attribute.value as? FullTreeDwarfExpressionValue
            ?: throw FullTreeControlException("$label is not a DWARF expression")

    private fun ULong.toExecutableRva(
        imageBase: ULong,
        executable: FullTreeElfExecutableMembership,
    ): ULong? {
        if (this < imageBase) return null
        val rva = this - imageBase
        return rva.takeIf(executable::contains)
    }

    private fun FullTreeDwarfDieRecord.functionStart(owner: FunctionDwarfUnit): ULong? =
        owner.functionStart(this)

    private fun repositoryLimits(limits: FullTreeCallObservationProducerLimits) =
        FullTreeFunctionObservationProducerLimits(
            dieLimits = limits.dieLimits,
            elfLayoutLimits = limits.elfLayoutLimits,
            maximumReferenceChainEntries = limits.maximumReferenceChainEntries,
            maximumCachedCompilationUnits = limits.maximumCachedCompilationUnits,
        )

    private fun requireResidentBudget(
        scope: JsonObject,
        limits: FullTreeCallObservationProducerLimits,
    ) {
        val repositoryBytes = Math.multiplyExact(
            limits.dieLimits.maximumRetainedBytes,
            Math.addExact(limits.maximumReferenceChainEntries, limits.maximumCachedCompilationUnits).toLong(),
        )
        val modeled = Math.addExact(
            Math.addExact(repositoryBytes, limits.maximumRetainedBytes),
            limits.elfLayoutLimits.modeledResidentBytes(),
        )
        if (
            modeled > scope.controlObject("bounds").controlObject("perShard")
                .controlLong("maximumResidentBytes")
        ) {
            throw FullTreeControlException(
                "call-observation scanner model exceeds the authenticated resident-byte bound",
            )
        }
    }
}

private class CallObservationAccumulator(
    private val shard: FullTreeCallObservationShardInput,
    private val limits: FullTreeCallObservationProducerLimits,
) {
    private val unitIds = shard.units.mapTo(hashSetOf()) { it.controlString("id") }
    private val calls = TreeMap<String, JsonObject>(FULL_TREE_CODE_POINT_ORDER)
    private val dieOffsets = HashSet<ULong>()
    private var scannedDies = 0L
    private var retainedBytes = 0L
    private var finished = false

    fun recordScannedDies(count: Long) {
        requireMutable()
        if (count <= 0L) throw FullTreeControlException("call-observation DIE increment is invalid")
        scannedDies = Math.addExact(scannedDies, count)
        if (scannedDies > limits.maximumScannedDies) {
            throw FullTreeControlException("call-observation scan exceeds its DIE bound")
        }
    }

    fun accept(observation: FullTreeObservedCallSite) {
        requireMutable()
        if (observation.unitId !in unitIds) {
            throw FullTreeControlException("observed call owner is outside its authenticated shard")
        }
        if (!dieOffsets.add(observation.dieOffset)) {
            throw FullTreeControlException("artifact scan emitted a call-site DIE more than once")
        }
        if (calls.size >= limits.maximumCalls) {
            throw FullTreeControlException("call-observation population exceeds its bound")
        }
        val document = callObservationDocument(observation)
        val id = document.controlString("id")
        val encoded = OracleJson.canonicalBytes(document)
        val encodedModel = Math.multiplyExact(encoded.size.toLong(), 2L)
        retainedBytes = Math.addExact(retainedBytes, Math.addExact(encodedModel, MODELED_CALL_BYTES))
        if (retainedBytes > limits.maximumRetainedBytes) {
            throw FullTreeControlException("call-observation accumulator exceeds its retained-byte bound")
        }
        if (calls.put(id, document) != null) {
            throw FullTreeControlException("artifact scan emitted a duplicate call identity")
        }
    }

    fun finish(
        inventoryIndexSha256: String,
        richArtifactSha256: String,
        scopeSha256: String,
    ): JsonObject {
        requireMutable()
        if (scannedDies < shard.units.size.toLong() + calls.size.toLong()) {
            throw FullTreeControlException("call-observation scan cannot cover its evidence")
        }
        finished = true
        val documents = calls.values.toList()
        val scored = documents.count { it.controlString("population") == "scored" }.toLong()
        return callObservationEnvelope(
            shard, inventoryIndexSha256, richArtifactSha256, scopeSha256,
            documents, documents.size.toLong(), scored, scannedDies,
        )
    }

    private fun requireMutable() {
        if (finished) throw FullTreeControlException("call-observation accumulator is already finished")
    }
}

internal fun callObservationDocument(observation: FullTreeObservedCallSite): JsonObject {
    val callerRva = observation.callerId?.removePrefix("function-rva-")
    val identity = JsonObject(
        mapOf(
            "caller" to (callerRva?.let(::JsonPrimitive) ?: JsonNull),
            "die" to JsonPrimitive(callHex(observation.dieOffset)),
            "return" to (observation.returnPcRva?.let { JsonPrimitive(callHex(it)) } ?: JsonNull),
            "unit" to JsonPrimitive(observation.unitId),
        ),
    )
    val id = "call-" + OracleArtifacts.sha256(OracleJson.canonicalBytes(identity)).take(32)
    return JsonObject(
        mapOf(
            "callerId" to (observation.callerId?.let(::JsonPrimitive) ?: JsonNull),
            "callerLocalReturnOffset" to (
                observation.callerLocalReturnOffset?.let { JsonPrimitive(callHex(it)) } ?: JsonNull
            ),
            "dieOffset" to JsonPrimitive(callHex(observation.dieOffset)),
            "id" to JsonPrimitive(id),
            "population" to JsonPrimitive(observation.population),
            "reasonCode" to (observation.reasonCode?.let(::JsonPrimitive) ?: JsonNull),
            "returnPcRva" to (observation.returnPcRva?.let { JsonPrimitive(callHex(it)) } ?: JsonNull),
            "target" to callTargetDocument(observation.target),
            "tailCall" to JsonPrimitive(observation.tailCall),
            "unitId" to JsonPrimitive(observation.unitId),
        ),
    )
}

internal fun callObservationEnvelope(
    shard: FullTreeCallObservationShardInput,
    inventoryIndexSha256: String,
    richArtifactSha256: String,
    scopeSha256: String,
    documents: List<JsonObject>,
    observedCallSites: Long,
    scored: Long,
    scannedDies: Long,
): JsonObject {
    return JsonObject(
        mapOf(
            "calls" to JsonArray(documents),
            "counts" to JsonObject(
                mapOf(
                    "observedCallSites" to JsonPrimitive(observedCallSites),
                    "scannedDies" to JsonPrimitive(scannedDies),
                    "scored" to JsonPrimitive(scored),
                    "units" to JsonPrimitive(shard.units.size.toLong()),
                    "unobservable" to JsonPrimitive(observedCallSites - scored),
                ),
            ),
            "oracle" to JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(FullTreeCallObservations.configurationSha256),
                    "inventoryIndexSha256" to JsonPrimitive(inventoryIndexSha256),
                    "richArtifactSha256" to JsonPrimitive(richArtifactSha256),
                    "scopeSha256" to JsonPrimitive(scopeSha256),
                ),
            ),
            "schemaVersion" to JsonPrimitive(1),
            "shard" to JsonObject(
                mapOf(
                    "id" to JsonPrimitive(shard.identifier),
                    "inputSha256" to JsonPrimitive(shard.inputSha256),
                ),
            ),
        ),
    )
}

private fun callTargetDocument(target: FullTreeObservedCallTarget): JsonObject = JsonObject(
    mapOf(
        "aliases" to JsonArray(target.aliases.map(::JsonPrimitive)),
        "dispatchKind" to JsonPrimitive(target.dispatchKind),
        "functionId" to (target.functionId?.let(::JsonPrimitive) ?: JsonNull),
        "kind" to JsonPrimitive(target.kind),
        "originDieOffset" to (target.originDieOffset?.let { JsonPrimitive(callHex(it)) } ?: JsonNull),
        "provenFunctionIds" to JsonArray(target.provenFunctionIds.map(::JsonPrimitive)),
        "targetEvidence" to JsonPrimitive(target.targetEvidence),
    ),
)

private fun callAttributeContext(attribute: FullTreeDwarfAbbreviationAttribute): FullTreeDwarfFormContext =
    when (attribute.name) {
        DW_AT_CALL_TARGET,
        DW_AT_CALL_TARGET_CLOBBERED,
        -> FullTreeDwarfFormContext.EXPRESSION
        DW_AT_RANGES -> FullTreeDwarfFormContext.RANGE_LIST
        DW_AT_ENTRY_PC,
        DW_AT_DECLARATION,
        DW_AT_INLINE,
        DW_AT_VIRTUALITY,
        DW_AT_CALL_TAIL_CALL,
        -> FullTreeDwarfFormContext.CONSTANT
        else -> FullTreeDwarfFormContext.GENERAL
    }

private fun callHex(value: ULong): String = "0x${value.toString(16)}"

private const val MODELED_CALL_BYTES = 1024L
private const val DW_TAG_FORMAL_PARAMETER = 0x05L
private const val DW_TAG_MEMBER = 0x0dL
private const val DW_TAG_CALL_SITE = 0x48L
private const val DW_TAG_VARIABLE = 0x34L
private const val DW_AT_VIRTUALITY = 0x4cL
private const val DW_AT_CALL_RETURN_PC = 0x7dL
private const val DW_AT_CALL_ORIGIN = 0x7fL
private const val DW_AT_CALL_PC = 0x81L
private const val DW_AT_CALL_TAIL_CALL = 0x82L
private const val DW_AT_CALL_TARGET = 0x83L
private const val DW_AT_CALL_TARGET_CLOBBERED = 0x84L
private val CALL_ORIGIN_TAGS = setOf(
    DW_TAG_FORMAL_PARAMETER,
    DW_TAG_MEMBER,
    DW_TAG_SUBPROGRAM,
    DW_TAG_VARIABLE,
)
private val CALL_OBJECT_ORIGIN_TAGS = setOf(DW_TAG_MEMBER, DW_TAG_VARIABLE)
