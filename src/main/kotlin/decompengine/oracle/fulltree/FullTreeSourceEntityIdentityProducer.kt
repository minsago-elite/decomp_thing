package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.Collections
import java.util.LinkedHashSet
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.JsonObject

/** Result of one complete, authenticated source-entity pass. No partial fact list escapes a failed pass. */
internal data class FullTreeSourceEntityIdentityScan(
    val richArtifactSha256: String,
    val inventoryArtifactSha256: String,
    val shardId: String,
    val scannedDies: Long,
    val facts: List<FullTreeSourceEntityFact>,
    val canonicalSha256: String,
    val canonicalBytes: Long,
    val peakRetainedLineTableBytes: Long,
    val peakRetainedLineTableUnits: Int,
)

/** Additive extractor for source identities; it does not write or alter either frozen observation schema. */
internal object FullTreeSourceEntityIdentityProducer {
    fun scanShard(
        richArtifact: Path,
        inventoryPath: Path,
        scope: AuthenticatedFullTreeScope,
        shardId: String,
        scratchParent: Path,
        controlLimits: FullTreeControlLimits = FullTreeControlLimits(),
        producerLimits: FullTreeFunctionObservationProducerLimits = FullTreeFunctionObservationProducerLimits(),
        checkpoint: (String) -> Unit = {},
    ): FullTreeSourceEntityIdentityScan {
        FullTreeScopeControl.validate(scope, controlLimits)
        requireStableDirectory(scratchParent, "source-identity scratch parent")
        val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
            inventoryPath,
            scope,
            shardId,
            controlLimits,
            checkpoint,
        )
        val perShard = scope.document.controlObject("bounds").controlObject("perShard")
        // The authenticated per-shard entity ceiling applies to this census. The separate
        // 20,000-function limit belongs to function projection and is not a census cap.
        val maximumFacts = perShard.controlLong("entities")
        val maximumSerializedBytes = minOf(
            perShard.controlLong("serializedBytes"),
            MAXIMUM_SOURCE_IDENTITY_BYTES,
        )
        val maximumFactBytes = minOf(
            perShard.controlLong("maximumResidentBytes") / 4L,
            maximumSerializedBytes,
            MAXIMUM_SOURCE_IDENTITY_BYTES,
            MAXIMUM_SOURCE_IDENTITY_ROW_BYTES,
        )
        val maximumReferencedUnits = scope.document.controlObject("bounds").controlObject("wholeRun")
            .controlLong("compilationUnits")
        val lineWorkingSetBudget = perShard.controlLong("maximumResidentBytes") / 4L
        val lineBytesPerUnit = lineWorkingSetBudget / maximumReferencedUnits
        val boundedLineLimits = boundedSourceIdentityLineTableLimits(
            producerLimits.lineTableLimits,
            lineBytesPerUnit,
        )
        val lineLimits = boundedLineLimits
        val modeledLineBytesPerUnit = try {
            Math.addExact(
                Math.addExact(
                    Math.multiplyExact(lineLimits.maximumAggregatePathBytes, 2L),
                    Math.multiplyExact(
                        Math.addExact(lineLimits.maximumDirectories.toLong(), lineLimits.maximumFiles.toLong()),
                        128L,
                    ),
                ),
                1_024L,
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("source-identity line-table working-set model overflows", failure)
        }
        val modeledLineBytes = Math.multiplyExact(
            modeledLineBytesPerUnit,
            maximumReferencedUnits,
        )
        if (modeledLineBytes > lineWorkingSetBudget) {
            throw FullTreeControlException("source-identity line-table model exceeds its authenticated working-set share")
        }
        val maximumRepositoryBytes = try {
            Math.subtractExact(
                Math.subtractExact(
                    Math.subtractExact(perShard.controlLong("maximumResidentBytes"), modeledLineBytes),
                    maximumFactBytes,
                ),
                maximumSerializedBytes,
            )
        } catch (failure: ArithmeticException) {
            throw FullTreeControlException("source-identity working-set model overflows", failure)
        }
        if (maximumFacts <= 0L || maximumFactBytes <= 0L) {
            throw FullTreeControlException("authenticated source-identity bounds are empty")
        }
        if (maximumRepositoryBytes <= 0L) {
            throw FullTreeControlException("source-identity scanner has no authenticated retained-unit working-set budget")
        }

        StableControlFile.open(
            richArtifact,
            controlLimits.maximumRichArtifactBytes,
            "source-identity rich artifact",
        ).use { artifact ->
            val artifactSha256 = artifact.sha256(checkpoint, "source-identity rich artifact")
            if (artifactSha256 != scope.document.controlObject("oracle").controlString("richArtifactSha256")) {
                throw FullTreeControlException("source-identity rich artifact does not match the authenticated scope")
            }
            val observedUnits = FullTreeDwarfCompilationUnits.read(
                artifact,
                scratchParent,
                scope.document,
                controlLimits,
                checkpoint,
            )
            FullTreeFunctionObservationProducer.authenticateInventoryAgainstArtifact(
                inputs.inventory,
                observedUnits,
                scope.document,
            )
            val unitDocuments = inputs.inventory.controlArray("units").controlObjects("inventory units")
            val unitByOffset = unitDocuments.associateBy {
                parseDwarfOffset(it.controlString("dwarfOffset"), "inventory DWARF offset")
            }
            if (unitByOffset.size != unitDocuments.size) {
                throw FullTreeControlException("authenticated inventory repeats a DWARF compilation-unit offset")
            }
            val headerParseBudget = FullTreeDwarfParseBudget(controlLimits.maximumDwarfParseSteps, checkpoint)
            var scannedDies = 0L
            var peakRetainedLineTableBytes = 0L
            var peakRetainedLineTableUnits = 0
            val budget = SourceIdentityRetentionBudget(maximumFacts, maximumFactBytes)
            val anchorClaims = SourceIdentityAnchorClaims(budget)
            val facts = ArrayList<FullTreeSourceEntityFact>()
            val layout = FullTreeElfLayout.scanLayout(artifact, "rich artifact", producerLimits.elfLayoutLimits, checkpoint)
            val executable = FullTreeElfExecutableMembership.fromSorted(layout.executableRanges)

            FullTreeDwarfSections.open(
                artifact,
                scratchParent,
                controlLimits,
           