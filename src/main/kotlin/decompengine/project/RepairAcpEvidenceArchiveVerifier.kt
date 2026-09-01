package decompengine.project

import decompengine.agent.AgentFileChange
import decompengine.agent.AgentFileChangeKind
import decompengine.agent.AgentWorkspacePath
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.MAXIMUM_REPAIR_ACP_RECEIPT_BYTES
import decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
import decompengine.repair.RepairIndexProfile
import decompengine.repair.RepairResourceBudget
import decompengine.repair.TRACE_REPAIR_ACP_RECEIPT_KIND
import decompengine.repair.TRACE_REPAIR_ACP_TASK_FIELD
import decompengine.repair.readStableRepairFile
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.TreeMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/**
 * Historical and current source identities authenticated by one completed repair graph.
 * [lastAcceptedRevisionId] is non-null exactly when an accepted repair changed this path.
 */
internal data class ArchivedRepairSourceLineage(
    val path: String,
    val rootSha256: String,
    val rootBytes: Long,
    val headSha256: String,
    val headBytes: Long,
    val lastAcceptedRevisionId: String?,
)

internal class ArchivedRepairReleaseLineage private constructor(
    sources: Map<String, ArchivedRepairSourceLineage>,
) {
    private val sources = sources.toMap()

    fun repairedSource(path: String): ArchivedRepairSourceLineage? =
        sources[path]?.takeIf { it.lastAcceptedRevisionId != null }

    companion object {
        val NONE = ArchivedRepairReleaseLineage(emptyMap())

        fun of(sources: Collection<ArchivedRepairSourceLineage>): ArchivedRepairReleaseLineage =
            ArchivedRepairReleaseLineage(sources.associateBy(ArchivedRepairSourceLineage::path))
    }
}

/**
 * Pure release verifier for trace-repair state. It does not open [decompengine.repair.ModuleRevisionGraph],
 * take its mutation lock, recover a pending attempt, or trust the workflow parser. Instead it walks the
 * archive payload, rebuilds the accepted source lineage, verifies the compatibility history projection,
 * and sends every immutable invocation through the independent schema-v2 ACP receipt verifier.
 */
internal object RepairAcpEvidenceArchiveVerifier {
    fun verifyIfPresent(
        projectDir: Path,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
        manifest: SourceTreeManifest,
        reconstructionProfile: ReconstructionProfile,
        repairProfile: RepairIndexProfile = GeneratedCRepairIndexProfile,
    ): ArchivedRepairReleaseLineage {
        val repairPaths = payloadSha256.keys.filterTo(linkedSetOf()) { path ->
            path == REPAIR_HISTORY_PATH || path.startsWith(REPAIR_STATE_PREFIX)
        }
        if (repairPaths.isEmpty()) return ArchivedRepairReleaseLineage.NONE

        require(reconstructionProfile.id == repairProfile.profileId()) {
            "repair release evidence profile differs from the archived reconstruction profile"
        }
        require(REPAIR_GRAPH_PATH in repairPaths && REPAIR_HISTORY_PATH in repairPaths) {
            "repair release evidence is missing repair_history.json or repair-revisions/graph.json"
        }

        val graphBytes = readPayloadFile(
            projectDir,
            REPAIR_GRAPH_PATH,
            MAXIMUM_REPAIR_GRAPH_RELEASE_BYTES,
            payloadSha256,
            payloadSizes,
        )
        val graph = parseGraph(graphBytes)
        require(graphBytes.size.toLong() <= graph.budget.maximumGraphBytes) {
            "repair release graph exceeds its persisted byte bound"
        }
        require(graph.schemaVersion == 2) {
            "legacy schema-v1 repair evidence is non-release"
        }
        require(graph.pending == null) {
            "repair release evidence contains a pending workflow assessment"
        }
        require(graph.profileId == repairProfile.profileId() &&
            graph.profileSha256 == repairProfile.configurationSha256(graph.budget)
        ) { "repair release evidence uses an unsupported repair profile" }
        val unknownRepairPaths = repairPaths.filterNot { path ->
            path in setOf(REPAIR_HISTORY_PATH, REPAIR_GRAPH_PATH, REPAIR_RECOVERY_BINDING_PATH) ||
                REPAIR_RECEIPT_PATH.matches(path) ||
                path.startsWith(REPAIR_BLOB_PREFIX)
        }
        require(unknownRepairPaths.isEmpty()) {
            "repair release evidence contains extra or stale state artifacts: ${unknownRepairPaths.sorted()}"
        }

        val bindingBytes = readPayloadFile(
            projectDir,
            REPAIR_RECOVERY_BINDING_PATH,
            minOf(graph.budget.maximumGraphBytes, MAXIMUM_REPAIR_RECOVERY_BINDING_BYTES),
            payloadSha256,
            payloadSizes,
        )
        verifyRecoveryBinding(parseRecoveryBinding(bindingBytes), graph, repairProfile)

        val manifestByPath = manifest.files.associateBy(GeneratedFileEvidence::path)
        val reconstructed = verifyGraphLineage(
            graph,
            projectDir,
            payloadSha256,
            payloadSizes,
            manifestByPath,
            repairProfile,
        )
        verifyReceipts(graph, projectDir, payloadSha256, payloadSizes)
        verifyHistory(graph, projectDir, payloadSha256, payloadSizes)

        return ArchivedRepairReleaseLineage.of(reconstructed)
    }

    private fun verifyGraphLineage(
        graph: ReleaseRepairGraph,
        projectDir: Path,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
        manifestByPath: Map<String, GeneratedFileEvidence>,
        repairProfile: RepairIndexProfile,
    ): List<ArchivedRepairSourceLineage> {
        require(graph.nodes.isNotEmpty() && graph.nodes.size <= graph.budget.maximumRevisionNodes) {
            "repair release graph has no bounded revision lineage"
        }
        require(graph.nodes.map(ReleaseRepairNode::id).distinct().size == graph.nodes.size) {
            "repair release graph contains duplicate revision identities"
        }
        require(graph.editablePaths == graph.editablePaths.distinct().sorted()) {
            "repair release graph editable paths are not unique and sorted"
        }
        require(graph.retainedRegressionInputs.size <= graph.budget.maximumRegressionInputs) {
            "repair release graph exceeds its retained regression input bound"
        }
        validateRegressionCorpus(graph.retainedRegressionInputs, graph.budget)
        require(graph.regressionCorpusSha256 == regressionCorpusSha256(graph.retainedRegressionInputs)) {
            "repair release graph retained regression digest is stale"
        }

        val root = graph.nodes.first()
        require(root.status == "root" && root.parentId == null && root.ordinal == 0 &&
            root.repairMetadata == null && !root.recoveredAfterCrash
        ) { "repair release graph root is invalid" }
        val rootPaths = root.changes.map(ReleaseRepairDelta::path)
        require(rootPaths.isNotEmpty() && rootPaths == rootPaths.distinct().sorted() &&
            rootPaths.size <= graph.budget.maximumSourceFiles
        ) { "repair release graph root paths are invalid" }
        require(graph.editablePaths.all(rootPaths::contains) &&
            repairProfile.authorizesRecoveryLayout(rootPaths, graph.editablePaths, graph.budget)
        ) { "repair release graph source layout is not authorized by its profile" }
        require(root.changedModules.isEmpty() && root.invalidatedModules.isEmpty()) {
            "repair release graph root claims module changes"
        }

        val referencedBlobs = TreeMap<String, Long>()
        fun recordBlob(digest: String?, size: Long?) {
            if (digest == null) return
            require(size != null && digest.matches(SHA256)) { "repair release graph blob binding is invalid" }
            val prior = referencedBlobs.putIfAbsent(digest, size)
            require(prior == null || prior == size) { "repair release graph gives one blob inconsistent sizes" }
        }
        fun validateDelta(delta: ReleaseRepairDelta, rootDelta: Boolean) {
            requireNormalizedPath(delta.path, "repair release graph source path")
            require(delta.path in rootPaths) { "repair release graph references an unknown source path: ${delta.path}" }
            require(delta.afterSha256.matches(SHA256) && delta.afterBlobSha256 == delta.afterSha256 &&
                delta.afterBytes in 0..graph.budget.maximumSourceFileBytes
            ) { "repair release graph candidate binding is invalid: ${delta.path}" }
            if (rootDelta) {
                require(delta.beforeSha256 == null && delta.beforeBytes == null && delta.beforeBlobSha256 == null) {
                    "repair release graph root contains a preimage: ${delta.path}"
                }
            } else {
                require(delta.beforeSha256?.matches(SHA256) == true &&
                    delta.beforeBytes != null && delta.beforeBytes in 0..graph.budget.maximumSourceFileBytes &&
                    delta.beforeBlobSha256 == delta.beforeSha256
                ) { "repair release graph preimage binding is invalid: ${delta.path}" }
            }
            recordBlob(delta.beforeBlobSha256, delta.beforeBytes)
            recordBlob(delta.afterBlobSha256, delta.afterBytes)
        }
        root.changes.forEach { validateDelta(it, rootDelta = true) }
        var accepted = root.changes.associateTo(sortedMapOf()) { delta ->
            delta.path to ReleaseSourceIdentity(delta.path, delta.afterBytes, delta.afterSha256)
        }
        val roots = accepted.toMap()
        require(root.sourceRevisionSha256 == revisionSha256(accepted.values)) {
            "repair release graph root source digest is invalid"
        }
        require(root.id == "root_${sha256((graph.indexSha256 + "\n" + root.sourceRevisionSha256).toByteArray()).take(24)}") {
            "repair release graph root identity is not content-bound"
        }

        var derivedHead = root.id
        var previousOrdinal = 0
        var previousIteration = 0
        val lastAcceptedByPath = mutableMapOf<String, String>()
        graph.nodes.drop(1).forEach { node ->
            require(node.id.matches(REPAIR_NODE_ID) && node.ordinal == previousOrdinal + 1) {
                "repair release graph revision identity or ordinal is invalid: ${node.id}"
            }
            previousOrdinal = node.ordinal
            require(node.parentId == derivedHead && node.status in setOf("accepted", "rejected")) {
                "repair release graph revision is detached from its accepted parent: ${node.id}"
            }
            require(node.changedModules == node.changedModules.distinct().sorted() &&
                node.invalidatedModules == node.invalidatedModules.distinct().sorted() &&
                node.changedModules.intersect(node.invalidatedModules.toSet()).isEmpty()
            ) { "repair release graph module projections are invalid: ${node.id}" }
            require(node.changes.map(ReleaseRepairDelta::path) ==
                node.changes.map(ReleaseRepairDelta::path).distinct().sorted() &&
                node.changes.size <= graph.budget.maximumPatchFiles
            ) { "repair release graph changes are missing, duplicated, or unordered: ${node.id}" }
            val patchBytes = node.changes.fold(0L) { total, delta -> Math.addExact(total, delta.afterBytes) }
            require(patchBytes <= graph.budget.maximumPatchBytes) {
                "repair release graph patch exceeds its byte bound: ${node.id}"
            }
            node.changes.forEach { validateDelta(it, rootDelta = false) }
            val candidate = accepted.toMutableMap()
            node.changes.forEach { delta ->
                val before = requireNotNull(accepted[delta.path]) {
                    "repair release graph change has no accepted preimage: ${node.id}:${delta.path}"
                }
                require(delta.beforeSha256 == before.sha256 && delta.beforeBytes == before.bytes) {
                    "repair release graph change is stale against its accepted parent: ${node.id}:${delta.path}"
                }
                candidate[delta.path] = ReleaseSourceIdentity(delta.path, delta.afterBytes, delta.afterSha256)
            }
            require(node.sourceRevisionSha256 == revisionSha256(candidate.values)) {
                "repair release graph revision digest is invalid: ${node.id}"
            }
            val metadata = node.repairMetadata ?: throw IllegalArgumentException(
                "non-ACP repair evidence lacks an invocation-bound workflow assessment: ${node.id}",
            )
            require(metadata.iterationIndex == previousIteration + 1) {
                "repair release graph iteration indexes are not contiguous"
            }
            previousIteration = metadata.iterationIndex
            validateMetadata(metadata, graph)
            require(metadata.publicationMode == "acp_release" && metadata.agentInvocation != null) {
                "non-ACP repair evidence cannot satisfy the release gate: ${node.id}"
            }
            val expectedAssessment = if (node.status == "accepted") "accepted" else "rejected"
            require(metadata.agentInvocation.assessmentStatus == expectedAssessment) {
                "repair release assessment status disagrees with its graph node: ${node.id}"
            }
            if (node.status == "accepted") {
                require(node.changes.isNotEmpty()) { "accepted repair has no exact source change: ${node.id}" }
                require(metadata.agentInvocation.releaseComplete &&
                    metadata.agentInvocation.terminalOutcome == "returned-completed"
                ) { "accepted repair lacks release-complete ACP evidence: ${node.id}" }
                require(metadata.agentInvocation.resultChangesSha256 == agentChangeSetSha256(node.changes)) {
                    "accepted repair exact changes differ from its ACP receipt: ${node.id}"
                }
                accepted = candidate.toSortedMap()
                derivedHead = node.id
                node.changes.forEach { lastAcceptedByPath[it.path] = node.id }
            }
        }
        require(graph.headId == derivedHead && graph.nextOrdinal == previousOrdinal + 1) {
            "repair release graph head or next ordinal is stale"
        }

        val expectedReceiptPaths = graph.nodes.drop(1).mapTo(sortedSetOf()) { node ->
            requireNotNull(node.repairMetadata?.agentInvocation).receiptPath
        }
        val observedReceiptPaths = payloadSha256.keys.filter(REPAIR_RECEIPT_PATH::matches).toSortedSet()
        require(observedReceiptPaths == expectedReceiptPaths) {
            "repair release evidence contains missing, extra, or stale ACP receipts"
        }
        val expectedBlobPaths = referencedBlobs.keys.mapTo(sortedSetOf()) { "$REPAIR_BLOB_PREFIX$it" }
        val observedBlobPaths = payloadSha256.keys.filter { it.startsWith(REPAIR_BLOB_PREFIX) }.toSortedSet()
        require(observedBlobPaths == expectedBlobPaths) {
            "repair release evidence contains missing, extra, or stale revision blobs"
        }
        val referencedBytes = referencedBlobs.values.fold(0L, Math::addExact)
        require(referencedBytes == graph.storedBlobBytes && referencedBytes <= graph.budget.maximumStoredBlobBytes) {
            "repair release graph stored-blob accounting is invalid"
        }
        referencedBlobs.forEach { (digest, size) ->
            val path = "$REPAIR_BLOB_PREFIX$digest"
            val bytes = readPayloadFile(
                projectDir,
                path,
                graph.budget.maximumSourceFileBytes,
                payloadSha256,
                payloadSizes,
            )
            require(bytes.size.toLong() == size && sha256(bytes) == digest) {
                "repair release blob differs from its graph binding: $digest"
            }
        }

        return accepted.values.map { head ->
            val rootSource = requireNotNull(roots[head.path])
            val manifestFile = requireNotNull(manifestByPath[head.path]) {
                "repair release graph source is absent from source_tree_manifest.json: ${head.path}"
            }
            val current = readPayloadFile(
                projectDir,
                head.path,
                graph.budget.maximumSourceFileBytes,
                payloadSha256,
                payloadSizes,
            )
            require(current.size.toLong() == head.bytes && sha256(current) == head.sha256 &&
                manifestFile.sha256 == head.sha256
            ) { "repair release graph head differs from the archived source: ${head.path}" }
            val acceptedRevision = lastAcceptedByPath[head.path]
            if (acceptedRevision != null) {
                require(manifestFile.generator == REPAIR_REVISION_GENERATOR &&
                    manifestFile.promptSha256 == sha256("revision:$acceptedRevision".toByteArray()) &&
                    manifestFile.acceptedImplementation != false
                ) { "repair release source manifest assessment is stale: ${head.path}" }
            }
            ArchivedRepairSourceLineage(
                head.path,
                rootSource.sha256,
                rootSource.bytes,
                head.sha256,
                head.bytes,
                acceptedRevision,
            )
        }
    }

    private fun verifyReceipts(
        graph: ReleaseRepairGraph,
        projectDir: Path,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
    ) {
        graph.nodes.drop(1).forEach { node ->
            val metadata = requireNotNull(node.repairMetadata)
            val invocation = requireNotNull(metadata.agentInvocation)
            val expectedPath = "reports/repair-revisions/${node.id}.acp-receipt.json"
            require(invocation.receiptPath == expectedPath && invocation.receiptSchemaVersion == 2) {
                "repair ACP receipt path or schema is cross-paired: ${node.id}"
            }
            val bytes = readPayloadFile(
                projectDir,
                expectedPath,
                MAXIMUM_REPAIR_ACP_RECEIPT_BYTES,
                payloadSha256,
                payloadSizes,
            )
            require(sha256(bytes) == invocation.receiptSha256) {
                "repair ACP receipt digest differs from its workflow assessment: ${node.id}"
            }
            val verified = verifyAcpExecutionReceiptDocument(
                bytes,
                TRACE_REPAIR_ACP_RECEIPT_KIND,
                TRACE_REPAIR_ACP_TASK_FIELD,
                node.id,
            )
            require(verified.requestSha256 == invocation.requestSha256 &&
                verified.promptSha256 == metadata.promptSha256 &&
                verified.resultChangesSha256 == invocation.resultChangesSha256 &&
                verified.terminalOutcome == invocation.terminalOutcome &&
                verified.releaseComplete == invocation.releaseComplete
            ) { "repair ACP receipt content is cross-paired with its workflow assessment: ${node.id}" }
            verified.releaseFacts?.let { releaseFacts ->
                val expectedChanges = node.changes.map { change ->
                    VerifiedAcpReceiptChange(
                        rootId = expectedAcpTextCommitment("project"),
                        relativePath = expectedAcpTextCommitment(change.path),
                        kind = "modified",
                        beforeSha256 = change.beforeSha256,
                        afterSha256 = change.afterSha256,
                        sizeBytes = change.afterBytes,
                    )
                }
                require(releaseFacts.changes == expectedChanges &&
                    verified.resultChangesSha256 == agentChangeSetSha256(node.changes)
                ) {
                    "repair ACP receipt records differ from the exact workflow change set: ${node.id}"
                }
            }
        }
    }

    private fun verifyHistory(
        graph: ReleaseRepairGraph,
        projectDir: Path,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
    ) {
        val bytes = readPayloadFile(
            projectDir,
            REPAIR_HISTORY_PATH,
            minOf(graph.budget.maximumProjectionBytes, MAXIMUM_REPAIR_PROJECTION_BYTES),
            payloadSha256,
            payloadSizes,
        )
        val root = strictObject(bytes, HISTORY_JSON_LIMITS, "repair release history")
        val schemaVersion = root["schemaVersion"]?.jsonPrimitive?.intOrNull ?: 1
        require(schemaVersion == 2) { "legacy schema-v1 repair history is non-release" }
        root.requireExactKeys(HISTORY_FIELDS, "repair release history")
        val historyInputs = root.requiredArray("regressionInputs", "repair release history")
            .map(::parseRegressionInput)
        require(historyInputs == graph.retainedRegressionInputs) {
            "repair release history retained regression corpus is stale"
        }
        val expectedNodes = graph.nodes.mapNotNull { node -> node.repairMetadata?.let { node } }
        val iterations = root.requiredArray("iterations", "repair release history")
        require(iterations.size == expectedNodes.size) {
            "repair release history is missing or contains stale iterations"
        }
        iterations.zip(expectedNodes).forEach { (element, node) ->
            verifyHistoryIteration(element.requiredObject("repair release history iteration"), node, projectDir)
        }
    }

    private fun verifyHistoryIteration(root: JsonObject, node: ReleaseRepairNode, projectDir: Path) {
        root.requireExactKeys(HISTORY_ITERATION_FIELDS, "repair release history iteration")
        val metadata = requireNotNull(node.repairMetadata)
        require(root.requiredInt("index", "repair release history iteration") == metadata.iterationIndex &&
            root.requiredString("failureKind", "repair release history iteration") == metadata.failureKind &&
            root.requiredString("prompt", "repair release history iteration") == metadata.promptSha256 &&
            root.requiredString("summary", "repair release history iteration") == metadata.projectedSummary(node) &&
            root.requiredBoolean("succeeded", "repair release history iteration") ==
                (node.status == "accepted" && node.evidenceKind == "valid") &&
            root.requiredStringArray("retainedRegressionIds", "repair release history iteration") ==
                metadata.retainedRegressionIds &&
            root.optionalEvidence("before", "repair release history iteration") == metadata.before &&
            root.optionalEvidence("after", "repair release history iteration") == node.evidence &&
            root.requiredString("publicationMode", "repair release history iteration") == metadata.publicationMode &&
            root.optionalInvocation("agentInvocation", "repair release history iteration") == metadata.agentInvocation
        ) { "repair release history is cross-paired with graph revision ${node.id}" }

        val patches = root.requiredArray("patches", "repair release history iteration")
        require(patches.size == node.changes.size) {
            "repair release history patch count differs from graph revision ${node.id}"
        }
        patches.zip(node.changes).forEach { (element, delta) ->
            val patch = element.requiredObject("repair release history patch")
            patch.requireExactKeys(HISTORY_PATCH_FIELDS, "repair release history patch")
            require(patch.requiredString("relativePath", "repair release history patch") == delta.path) {
                "repair release history patch path is cross-paired: ${node.id}"
            }
            val replacement = patch.requiredString("replacementHex", "repair release history patch")
                .decodeLowerHex("repair release history patch")
            val blob = readStableRepairFile(
                projectDir,
                "$REPAIR_BLOB_PREFIX${delta.afterBlobSha256}",
                maxOf(1L, delta.afterBytes),
            )
            require(replacement.contentEquals(blob) && sha256(replacement) == delta.afterSha256) {
                "repair release history patch bytes differ from graph revision ${node.id}"
            }
        }
    }

    private fun validateMetadata(metadata: ReleaseRepairMetadata, graph: ReleaseRepairGraph) {
        require(metadata.iterationIndex in 1..graph.budget.maximumRevisionNodes &&
            metadata.failureKind in setOf("compile", "behavior") &&
            metadata.promptSha256.matches(SHA256) &&
            metadata.retainedRegressionIds == metadata.retainedRegressionIds.distinct().sorted()
        ) { "repair release workflow metadata is invalid" }
        val retained = metadata.retainedRegressionIds.map { id ->
            graph.retainedRegressionInputs.singleOrNull { it.id == id }
                ?: error("repair release metadata references an unknown regression input: $id")
        }
        require(metadata.regressionCorpusSha256 == regressionCorpusSha256(retained)) {
            "repair release workflow regression binding is stale"
        }
    }

    private fun readPayloadFile(
        projectDir: Path,
        relativePath: String,
        maximumBytes: Long,
        payloadSha256: Map<String, String>,
        payloadSizes: Map<String, Long>,
    ): ByteArray {
        requireNormalizedPath(relativePath, "repair release evidence path")
        val expectedDigest = requireNotNull(payloadSha256[relativePath]) {
            "repair release evidence is missing from archive payload: $relativePath"
        }
        val expectedSize = requireNotNull(payloadSizes[relativePath]) {
            "repair release evidence size is missing from archive payload: $relativePath"
        }
        require(expectedSize in 0..maximumBytes) {
            "repair release evidence exceeds its $maximumBytes-byte bound: $relativePath"
        }
        val bytes = readStableRepairFile(projectDir, relativePath, maximumBytes)
        require(bytes.size.toLong() == expectedSize && sha256(bytes) == expectedDigest) {
            "repair release evidence changed after archive payload inspection: $relativePath"
        }
        return bytes
    }

    private fun parseGraph(bytes: ByteArray): ReleaseRepairGraph {
        val root = strictObject(bytes, GRAPH_JSON_LIMITS, "repair release graph")
        root.requireExactKeys(GRAPH_FIELDS, "repair release graph")
        val schema = root.requiredInt("schemaVersion", "repair release graph")
        require(schema in 1..2) { "unsupported repair release graph schema" }
        require(schema == 2) { "legacy schema-v1 repair evidence is non-release" }
        val budget = parseBudget(root.requiredObject("budget", "repair release graph"))
        return ReleaseRepairGraph(
            schemaVersion = schema,
            budget = budget,
            profileId = root.requiredString("profileId", "repair release graph"),
            profileSha256 = root.requiredSha256("profileSha256", "repair release graph"),
            editablePaths = root.requiredStringArray("editablePaths", "repair release graph"),
            indexSha256 = root.requiredSha256("indexSha256", "repair release graph"),
            retainedRegressionInputs = root.requiredArray("retainedRegressionInputs", "repair release graph")
                .map(::parseRegressionInput),
            regressionCorpusSha256 = root.requiredSha256("regressionCorpusSha256", "repair release graph"),
            headId = root.requiredString("headId", "repair release graph"),
            nextOrdinal = root.requiredInt("nextOrdinal", "repair release graph"),
            storedBlobBytes = root.requiredNonNegativeLong("storedBlobBytes", "repair release graph"),
            nodes = root.requiredArray("nodes", "repair release graph").map { parseNode(it, schema) },
            pending = root.getValue("pending").takeUnless { it is JsonNull },
        )
    }

    private fun parseNode(element: JsonElement, schemaVersion: Int): ReleaseRepairNode {
        val root = element.requiredObject("repair release graph node")
        root.requireExactKeys(NODE_FIELDS, "repair release graph node")
        return ReleaseRepairNode(
            id = root.requiredString("id", "repair release graph node"),
            parentId = root.optionalString("parentId", "repair release graph node"),
            ordinal = root.requiredInt("ordinal", "repair release graph node"),
            status = root.requiredString("status", "repair release graph node"),
            sourceRevisionSha256 = root.requiredSha256("sourceRevisionSha256", "repair release graph node"),
            changedModules = root.requiredStringArray("changedModules", "repair release graph node"),
            invalidatedModules = root.requiredStringArray("invalidatedModules", "repair release graph node"),
            evidenceKind = root.optionalString("evidenceKind", "repair release graph node"),
            evidenceArtifact = root.optionalString("evidenceArtifact", "repair release graph node"),
            evidenceSummary = root.optionalString("evidenceSummary", "repair release graph node"),
            repairMetadata = root.getValue("repairMetadata").takeUnless { it is JsonNull }
                ?.let { parseMetadata(it, schemaVersion) },
            recoveredAfterCrash = root.requiredBoolean("recoveredAfterCrash", "repair release graph node"),
            changes = root.requiredArray("changes", "repair release graph node").map(::parseDelta),
        ).also { node ->
            require((node.evidenceKind == null) == (node.evidenceSummary == null)) {
                "repair release graph evidence kind and summary are incomplete: ${node.id}"
            }
        }
    }

    private fun parseMetadata(element: JsonElement, schemaVersion: Int): ReleaseRepairMetadata {
        val root = element.requiredObject("repair release workflow metadata")
        val expectedFields = if (schemaVersion >= 2) METADATA_V2_FIELDS else METADATA_V1_FIELDS
        root.requireExactKeys(expectedFields, "repair release workflow metadata")
        return ReleaseRepairMetadata(
            iterationIndex = root.requiredInt("iterationIndex", "repair release workflow metadata"),
            failureKind = root.requiredString("failureKind", "repair release workflow metadata"),
            promptSha256 = root.requiredString("prompt", "repair release workflow metadata"),
            summary = root.optionalString("summary", "repair release workflow metadata"),
            retainedRegressionIds = root.requiredStringArray("retainedRegressionIds", "repair release workflow metadata"),
            before = root.optionalEvidence("before", "repair release workflow metadata"),
            regressionCorpusSha256 = root.optionalString("regressionCorpusSha256", "repair release workflow metadata"),
            agentInvocation = if (schemaVersion >= 2) {
                root.optionalInvocation("agentInvocation", "repair release workflow metadata")
            } else null,
            publicationMode = if (schemaVersion >= 2) {
                root.requiredString("publicationMode", "repair release workflow metadata")
            } else "test_only_non_release",
        )
    }

    private fun parseDelta(element: JsonElement): ReleaseRepairDelta {
        val root = element.requiredObject("repair release graph delta")
        root.requireExactKeys(DELTA_FIELDS, "repair release graph delta")
        return ReleaseRepairDelta(
            path = root.requiredString("path", "repair release graph delta"),
            beforeSha256 = root.optionalString("beforeSha256", "repair release graph delta"),
            beforeBytes = root.optionalLong("beforeBytes", "repair release graph delta"),
            afterSha256 = root.requiredString("afterSha256", "repair release graph delta"),
            beforeBlobSha256 = root.optionalString("beforeBlobSha256", "repair release graph delta"),
            afterBlobSha256 = root.requiredString("afterBlobSha256", "repair release graph delta"),
            afterBytes = root.requiredNonNegativeLong("afterBytes", "repair release graph delta"),
        )
    }

    private fun parseRegressionInput(element: JsonElement): ReleaseRegressionInput {
        val root = element.requiredObject("repair release regression input")
        root.requireExactKeys(REGRESSION_INPUT_FIELDS, "repair release regression input")
        return ReleaseRegressionInput(
            root.requiredString("id", "repair release regression input"),
            root.requiredStringArray("args", "repair release regression input"),
            root.requiredString("stdinHex", "repair release regression input")
                .decodeLowerHex("repair release regression input"),
        )
    }

    private fun parseRecoveryBinding(bytes: ByteArray): ReleaseRecoveryBinding {
        val root = strictObject(bytes, RECOVERY_BINDING_JSON_LIMITS, "repair release recovery binding")
        root.requireExactKeys(RECOVERY_BINDING_FIELDS, "repair release recovery binding")
        require(root.requiredInt("schemaVersion", "repair release recovery binding") == 1) {
            "unsupported repair release recovery binding schema"
        }
        return ReleaseRecoveryBinding(
            root.requiredString("profileId", "repair release recovery binding"),
            root.requiredSha256("profileSha256", "repair release recovery binding"),
            root.requiredSha256("budgetSha256", "repair release recovery binding"),
            root.requiredStringArray("sourcePaths", "repair release recovery binding"),
            root.requiredStringArray("editablePaths", "repair release recovery binding"),
            root.requiredSha256("indexSha256", "repair release recovery binding"),
        )
    }

    private fun verifyRecoveryBinding(
        binding: ReleaseRecoveryBinding,
        graph: ReleaseRepairGraph,
        repairProfile: RepairIndexProfile,
    ) {
        val rootPaths = graph.nodes.firstOrNull()?.changes?.map(ReleaseRepairDelta::path).orEmpty()
        require(binding.profileId == graph.profileId && binding.profileSha256 == graph.profileSha256 &&
            binding.budgetSha256 == sha256(renderBudget(graph.budget).toByteArray(StandardCharsets.UTF_8)) &&
            binding.sourcePaths == rootPaths && binding.editablePaths == graph.editablePaths &&
            binding.indexSha256 == graph.indexSha256 &&
            repairProfile.authorizesRecoveryLayout(binding.sourcePaths, binding.editablePaths, graph.budget)
        ) { "repair release graph differs from its recovery authorization" }
    }

    private fun parseBudget(root: JsonObject): RepairResourceBudget {
        root.requireExactKeys(BUDGET_FIELDS, "repair release graph budget")
        return RepairResourceBudget(
            maximumIndexedModules = root.requiredInt("maximumIndexedModules", "repair release graph budget"),
            maximumIndexedEntities = root.requiredInt("maximumIndexedEntities", "repair release graph budget"),
            maximumDependencyEdges = root.requiredNonNegativeLong("maximumDependencyEdges", "repair release graph budget"),
            maximumSourceFiles = root.requiredInt("maximumSourceFiles", "repair release graph budget"),
            maximumSourceFileBytes = root.requiredNonNegativeLong("maximumSourceFileBytes", "repair release graph budget"),
            maximumSourceBytes = root.requiredNonNegativeLong("maximumSourceBytes", "repair release graph budget"),
            maximumIndexEvidenceBytes = root.requiredNonNegativeLong("maximumIndexEvidenceBytes", "repair release graph budget"),
            maximumDiagnosticCharacters = root.requiredInt("maximumDiagnosticCharacters", "repair release graph budget"),
            maximumRegressionInputBytes = root.requiredNonNegativeLong("maximumRegressionInputBytes", "repair release graph budget"),
            maximumRegressionInputs = root.requiredInt("maximumRegressionInputs", "repair release graph budget"),
            maximumRegressionArguments = root.requiredInt("maximumRegressionArguments", "repair release graph budget"),
            maximumRequestBytes = root.requiredNonNegativeLong("maximumRequestBytes", "repair release graph budget"),
            maximumResponseBytes = root.requiredNonNegativeLong("maximumResponseBytes", "repair release graph budget"),
            maximumProjectionBytes = root.requiredNonNegativeLong("maximumProjectionBytes", "repair release graph budget"),
            maximumContextModules = root.requiredInt("maximumContextModules", "repair release graph budget"),
            maximumContextFiles = root.requiredInt("maximumContextFiles", "repair release graph budget"),
            maximumContextBytes = root.requiredNonNegativeLong("maximumContextBytes", "repair release graph budget"),
            maximumStagingDirectories = root.requiredInt("maximumStagingDirectories", "repair release graph budget"),
            maximumStagingBytes = root.requiredNonNegativeLong("maximumStagingBytes", "repair release graph budget"),
            maximumPatchFiles = root.requiredInt("maximumPatchFiles", "repair release graph budget"),
            maximumPatchBytes = root.requiredNonNegativeLong("maximumPatchBytes", "repair release graph budget"),
            maximumBehaviorStdoutBytes = root.requiredNonNegativeLong("maximumBehaviorStdoutBytes", "repair release graph budget"),
            maximumBehaviorStderrBytes = root.requiredNonNegativeLong("maximumBehaviorStderrBytes", "repair release graph budget"),
            maximumBehaviorOutputBytes = root.requiredNonNegativeLong("maximumBehaviorOutputBytes", "repair release graph budget"),
            maximumBehaviorExecutionMillis = root.requiredNonNegativeLong("maximumBehaviorExecutionMillis", "repair release graph budget"),
            maximumDiscoveryEntries = root.requiredInt("maximumDiscoveryEntries", "repair release graph budget"),
            maximumDiscoveryDirectories = root.requiredInt("maximumDiscoveryDirectories", "repair release graph budget"),
            maximumDiscoveryDepth = root.requiredInt("maximumDiscoveryDepth", "repair release graph budget"),
            maximumStateDirectoryEntries = root.requiredInt("maximumStateDirectoryEntries", "repair release graph budget"),
            maximumGraphLockWaitMillis = root.requiredNonNegativeLong("maximumGraphLockWaitMillis", "repair release graph budget"),
            maximumRevisionNodes = root.requiredInt("maximumRevisionNodes", "repair release graph budget"),
            maximumGraphBytes = root.requiredNonNegativeLong("maximumGraphBytes", "repair release graph budget"),
            maximumStoredBlobBytes = root.requiredNonNegativeLong("maximumStoredBlobBytes", "repair release graph budget"),
        )
    }
}

private data class ReleaseRepairGraph(
    val schemaVersion: Int,
    val budget: RepairResourceBudget,
    val profileId: String,
    val profileSha256: String,
    val editablePaths: List<String>,
    val indexSha256: String,
    val retainedRegressionInputs: List<ReleaseRegressionInput>,
    val regressionCorpusSha256: String,
    val headId: String,
    val nextOrdinal: Int,
    val storedBlobBytes: Long,
    val nodes: List<ReleaseRepairNode>,
    val pending: JsonElement?,
)

private data class ReleaseRepairNode(
    val id: String,
    val parentId: String?,
    val ordinal: Int,
    val status: String,
    val sourceRevisionSha256: String,
    val changedModules: List<String>,
    val invalidatedModules: List<String>,
    val evidenceKind: String?,
    val evidenceArtifact: String?,
    val evidenceSummary: String?,
    val repairMetadata: ReleaseRepairMetadata?,
    val recoveredAfterCrash: Boolean,
    val changes: List<ReleaseRepairDelta>,
) {
    val evidence: ReleaseRepairEvidence?
        get() = evidenceKind?.let { ReleaseRepairEvidence(it, evidenceSummary.orEmpty(), evidenceArtifact) }
}

private data class ReleaseRepairDelta(
    val path: String,
    val beforeSha256: String?,
    val beforeBytes: Long?,
    val afterSha256: String,
    val beforeBlobSha256: String?,
    val afterBlobSha256: String,
    val afterBytes: Long,
)

private data class ReleaseRepairMetadata(
    val iterationIndex: Int,
    val failureKind: String,
    val promptSha256: String,
    val summary: String?,
    val retainedRegressionIds: List<String>,
    val before: ReleaseRepairEvidence?,
    val regressionCorpusSha256: String?,
    val agentInvocation: ReleaseRepairInvocation?,
    val publicationMode: String,
) {
    fun projectedSummary(node: ReleaseRepairNode): String = summary ?: if (node.recoveredAfterCrash) {
        "repair attempt interrupted before the agent summary was durably recorded"
    } else {
        "repair attempt ${node.id}"
    }
}

private data class ReleaseRepairInvocation(
    val receiptPath: String,
    val receiptSha256: String,
    val receiptSchemaVersion: Int,
    val requestSha256: String,
    val resultChangesSha256: String,
    val terminalOutcome: String,
    val releaseComplete: Boolean,
    val assessmentStatus: String,
)

private data class ReleaseRepairEvidence(val kind: String, val summary: String, val artifactPath: String?)

private data class ReleaseRegressionInput(val id: String, val args: List<String>, val stdin: ByteArray) {
    override fun equals(other: Any?): Boolean =
        other is ReleaseRegressionInput && id == other.id && args == other.args && stdin.contentEquals(other.stdin)

    override fun hashCode(): Int = 31 * (31 * id.hashCode() + args.hashCode()) + stdin.contentHashCode()
}

private data class ReleaseSourceIdentity(val path: String, val bytes: Long, val sha256: String)

private data class ReleaseRecoveryBinding(
    val profileId: String,
    val profileSha256: String,
    val budgetSha256: String,
    val sourcePaths: List<String>,
    val editablePaths: List<String>,
    val indexSha256: String,
)

private fun JsonObject.optionalEvidence(field: String, label: String): ReleaseRepairEvidence? =
    getValue(field).takeUnless { it is JsonNull }?.requiredObject("$label $field")?.let { root ->
        root.requireExactKeys(EVIDENCE_FIELDS, "$label $field")
        ReleaseRepairEvidence(
            root.requiredString("kind", "$label $field"),
            root.requiredString("summary", "$label $field"),
            root.optionalString("artifactPath", "$label $field"),
        )
    }

private fun JsonObject.optionalInvocation(field: String, label: String): ReleaseRepairInvocation? =
    getValue(field).takeUnless { it is JsonNull }?.requiredObject("$label $field")?.let { root ->
        root.requireExactKeys(INVOCATION_FIELDS, "$label $field")
        ReleaseRepairInvocation(
            receiptPath = root.requiredString("receiptPath", "$label $field"),
            receiptSha256 = root.requiredSha256("receiptSha256", "$label $field"),
            receiptSchemaVersion = root.requiredInt("receiptSchemaVersion", "$label $field"),
            requestSha256 = root.requiredSha256("requestSha256", "$label $field"),
            resultChangesSha256 = root.requiredSha256("resultChangesSha256", "$label $field"),
            terminalOutcome = root.requiredString("terminalOutcome", "$label $field"),
            releaseComplete = root.requiredBoolean("receiptReleaseComplete", "$label $field"),
            assessmentStatus = root.requiredString("assessmentStatus", "$label $field"),
        )
    }

private fun agentChangeSetSha256(changes: List<ReleaseRepairDelta>): String =
    agentFileChangeSetSha256(changes.map { change ->
        AgentFileChange(
            AgentWorkspacePath("project", change.path),
            AgentFileChangeKind.MODIFIED,
            change.beforeSha256,
            change.afterSha256,
            change.afterBytes,
        )
    })

private fun revisionSha256(sources: Collection<ReleaseSourceIdentity>): String = sha256(
    sources.sortedBy(ReleaseSourceIdentity::path).joinToString("") { source ->
        "${source.path.length}:${source.path}:${source.bytes}:${source.sha256}\n"
    }.toByteArray(StandardCharsets.UTF_8),
)

private fun validateRegressionCorpus(inputs: List<ReleaseRegressionInput>, budget: RepairResourceBudget) {
    require(inputs.map(ReleaseRegressionInput::id) == inputs.map(ReleaseRegressionInput::id).distinct().sorted()) {
        "repair release retained regression input IDs are not unique and sorted"
    }
    var arguments = 0L
    var bytes = 0L
    inputs.forEach { input ->
        require(input.id.isNotBlank() && '\u0000' !in input.id && input.args.none { '\u0000' in it }) {
            "repair release retained regression input is invalid"
        }
        arguments = Math.addExact(arguments, input.args.size.toLong())
        bytes = Math.addExact(bytes, input.id.toByteArray().size.toLong())
        bytes = Math.addExact(bytes, input.stdin.size.toLong())
        input.args.forEach { bytes = Math.addExact(bytes, it.toByteArray().size.toLong()) }
    }
    require(arguments <= budget.maximumRegressionArguments && bytes <= budget.maximumRegressionInputBytes) {
        "repair release retained regression corpus exceeds its bounds"
    }
}

private fun regressionCorpusSha256(inputs: List<ReleaseRegressionInput>): String = sha256(
    buildString {
        inputs.forEach { input ->
            val idBytes = input.id.toByteArray(StandardCharsets.UTF_8)
            append(idBytes.size).append(':').append(input.id).append('|').append(input.args.size).append('|')
            input.args.forEach { argument ->
                append(argument.toByteArray(StandardCharsets.UTF_8).size).append(':').append(argument).append('|')
            }
            append(input.stdin.size).append(':').append(input.stdin.toHex()).append('\n')
        }
    }.toByteArray(StandardCharsets.UTF_8),
)

private fun renderBudget(value: RepairResourceBudget): String =
    "{\"maximumIndexedModules\":${value.maximumIndexedModules},\"maximumIndexedEntities\":${value.maximumIndexedEntities}," +
        "\"maximumDependencyEdges\":${value.maximumDependencyEdges},\"maximumSourceFiles\":${value.maximumSourceFiles}," +
        "\"maximumSourceFileBytes\":${value.maximumSourceFileBytes},\"maximumSourceBytes\":${value.maximumSourceBytes}," +
        "\"maximumIndexEvidenceBytes\":${value.maximumIndexEvidenceBytes},\"maximumDiagnosticCharacters\":${value.maximumDiagnosticCharacters}," +
        "\"maximumRegressionInputBytes\":${value.maximumRegressionInputBytes}," +
        "\"maximumRegressionInputs\":${value.maximumRegressionInputs}," +
        "\"maximumRegressionArguments\":${value.maximumRegressionArguments},\"maximumRequestBytes\":${value.maximumRequestBytes}," +
        "\"maximumResponseBytes\":${value.maximumResponseBytes}," +
        "\"maximumProjectionBytes\":${value.maximumProjectionBytes}," +
        "\"maximumContextModules\":${value.maximumContextModules},\"maximumContextFiles\":${value.maximumContextFiles}," +
        "\"maximumContextBytes\":${value.maximumContextBytes},\"maximumStagingDirectories\":${value.maximumStagingDirectories}," +
        "\"maximumStagingBytes\":${value.maximumStagingBytes},\"maximumPatchFiles\":${value.maximumPatchFiles}," +
        "\"maximumPatchBytes\":${value.maximumPatchBytes}," +
        "\"maximumBehaviorStdoutBytes\":${value.maximumBehaviorStdoutBytes}," +
        "\"maximumBehaviorStderrBytes\":${value.maximumBehaviorStderrBytes}," +
        "\"maximumBehaviorOutputBytes\":${value.maximumBehaviorOutputBytes}," +
        "\"maximumBehaviorExecutionMillis\":${value.maximumBehaviorExecutionMillis}," +
        "\"maximumDiscoveryEntries\":${value.maximumDiscoveryEntries}," +
        "\"maximumDiscoveryDirectories\":${value.maximumDiscoveryDirectories}," +
        "\"maximumDiscoveryDepth\":${value.maximumDiscoveryDepth}," +
        "\"maximumStateDirectoryEntries\":${value.maximumStateDirectoryEntries}," +
        "\"maximumGraphLockWaitMillis\":${value.maximumGraphLockWaitMillis}," +
        "\"maximumRevisionNodes\":${value.maximumRevisionNodes}," +
        "\"maximumGraphBytes\":${value.maximumGraphBytes}," +
        "\"maximumStoredBlobBytes\":${value.maximumStoredBlobBytes}}"

private fun strictObject(bytes: ByteArray, limits: StrictJsonLimits, label: String): JsonObject =
    OracleJson.parse(bytes, limits).requiredObject(label)

private fun JsonElement.requiredObject(label: String): JsonObject = this as? JsonObject
    ?: throw IllegalArgumentException("$label must be a JSON object")

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    require(keys == expected) { "$label has missing, extra, or duplicate fields" }
}

private fun JsonObject.requiredObject(field: String, label: String): JsonObject =
    get(field)?.requiredObject("$label $field") ?: error("$label is missing $field")

private fun JsonObject.requiredArray(field: String, label: String): JsonArray =
    get(field) as? JsonArray ?: error("$label is missing array $field")

private fun JsonObject.requiredString(field: String, label: String): String =
    (get(field) as? JsonPrimitive)?.also {
        require(it.isString) { "$label $field must be a JSON string" }
    }?.content ?: error("$label is missing string $field")

private fun JsonObject.optionalString(field: String, label: String): String? = when (val value = getValue(field)) {
    JsonNull -> null
    is JsonPrimitive -> value.also {
        require(it.isString) { "$label $field must be a JSON string or null" }
    }.content
    else -> error("$label has invalid string $field")
}

private fun JsonObject.requiredInt(field: String, label: String): Int {
    val value = get(field) as? JsonPrimitive ?: error("$label is missing integer $field")
    require(!value.isString) { "$label $field must be a JSON integer" }
    return value.intOrNull ?: error("$label is missing integer $field")
}

private fun JsonObject.requiredNonNegativeLong(field: String, label: String): Long {
    val value = get(field) as? JsonPrimitive ?: error("$label is missing integer $field")
    require(!value.isString) { "$label $field must be a JSON integer" }
    return (value.longOrNull ?: error("$label is missing integer $field")).also {
        require(it >= 0L) { "$label $field must be non-negative" }
    }
}

private fun JsonObject.optionalLong(field: String, label: String): Long? = when (val value = getValue(field)) {
    JsonNull -> null
    is JsonPrimitive -> {
        require(!value.isString) { "$label $field must be a JSON integer or null" }
        value.longOrNull ?: error("$label has invalid integer $field")
    }
    else -> error("$label has invalid integer $field")
}

private fun JsonObject.requiredBoolean(field: String, label: String): Boolean {
    val value = get(field) as? JsonPrimitive ?: error("$label is missing boolean $field")
    require(!value.isString) { "$label $field must be a JSON boolean" }
    return value.booleanOrNull ?: error("$label is missing boolean $field")
}

private fun JsonObject.requiredSha256(field: String, label: String): String =
    requiredString(field, label).also { require(it.matches(SHA256)) { "$label $field is not lowercase SHA-256" } }

private fun JsonObject.requiredStringArray(field: String, label: String): List<String> =
    requiredArray(field, label).map { element ->
        val value = element as? JsonPrimitive ?: error("$label $field contains a non-string")
        require(value.isString) { "$label $field contains a non-string" }
        value.content
    }

private fun String.decodeLowerHex(label: String): ByteArray {
    require(length % 2 == 0 && all { it in '0'..'9' || it in 'a'..'f' }) {
        "$label must use lowercase hexadecimal"
    }
    return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
}

private fun ByteArray.toHex(): String = joinToString("") { byte -> "%02x".format(byte.toInt() and 0xff) }

private fun requireNormalizedPath(value: String, label: String) {
    require(value.isNotBlank() && '\\' !in value && !value.startsWith('/') &&
        value.none { it.code < 0x20 || it.code == 0x7f } &&
        value.split('/').none { it.isEmpty() || it == "." || it == ".." }
    ) { "$label is not a normalized project-relative path: $value" }
}

private const val REPAIR_HISTORY_PATH = "reports/repair_history.json"
private const val REPAIR_STATE_PREFIX = "reports/repair-revisions/"
private const val REPAIR_GRAPH_PATH = "reports/repair-revisions/graph.json"
private const val REPAIR_RECOVERY_BINDING_PATH = "reports/repair-revisions/recovery-binding.json"
private const val REPAIR_BLOB_PREFIX = "reports/repair-revisions/blobs/"
private const val REPAIR_REVISION_GENERATOR = "repair-revision"
private const val MAXIMUM_REPAIR_GRAPH_RELEASE_BYTES = 64L * 1024 * 1024
private const val MAXIMUM_REPAIR_RECOVERY_BINDING_BYTES = 4L * 1024 * 1024
private val SHA256 = Regex("[0-9a-f]{64}")
private val REPAIR_NODE_ID = Regex("revision_[A-Za-z0-9_]+")
private val REPAIR_RECEIPT_PATH = Regex("reports/repair-revisions/revision_[A-Za-z0-9_]+\\.acp-receipt\\.json")

private val GRAPH_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_REPAIR_GRAPH_RELEASE_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_REPAIR_GRAPH_RELEASE_BYTES.toInt(),
    maximumDepth = 64,
    maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024,
    maximumTotalStringBytes = MAXIMUM_REPAIR_GRAPH_RELEASE_BYTES.toInt(),
)
private val HISTORY_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_REPAIR_PROJECTION_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_REPAIR_PROJECTION_BYTES.toInt(),
    maximumDepth = 64,
    maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024,
    maximumTotalStringBytes = MAXIMUM_REPAIR_PROJECTION_BYTES.toInt(),
)
private val RECOVERY_BINDING_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 4 * 1024 * 1024,
    maximumCanonicalBytes = 4 * 1024 * 1024,
    maximumDepth = 16,
    maximumNodes = 1_000_000,
    maximumStringBytes = 1024 * 1024,
    maximumTotalStringBytes = 4 * 1024 * 1024,
)

private val GRAPH_FIELDS = setOf(
    "schemaVersion", "budget", "profileId", "profileSha256", "editablePaths", "indexSha256",
    "retainedRegressionInputs", "regressionCorpusSha256", "headId", "nextOrdinal", "storedBlobBytes",
    "nodes", "pending",
)
private val BUDGET_FIELDS = setOf(
    "maximumIndexedModules", "maximumIndexedEntities", "maximumDependencyEdges", "maximumSourceFiles",
    "maximumSourceFileBytes", "maximumSourceBytes", "maximumIndexEvidenceBytes", "maximumDiagnosticCharacters",
    "maximumRegressionInputBytes", "maximumRegressionInputs", "maximumRegressionArguments", "maximumRequestBytes",
    "maximumResponseBytes", "maximumProjectionBytes", "maximumContextModules", "maximumContextFiles",
    "maximumContextBytes", "maximumStagingDirectories", "maximumStagingBytes", "maximumPatchFiles",
    "maximumPatchBytes", "maximumBehaviorStdoutBytes", "maximumBehaviorStderrBytes", "maximumBehaviorOutputBytes",
    "maximumBehaviorExecutionMillis", "maximumDiscoveryEntries", "maximumDiscoveryDirectories",
    "maximumDiscoveryDepth", "maximumStateDirectoryEntries", "maximumGraphLockWaitMillis", "maximumRevisionNodes",
    "maximumGraphBytes", "maximumStoredBlobBytes",
)
private val NODE_FIELDS = setOf(
    "id", "parentId", "ordinal", "status", "sourceRevisionSha256", "changedModules", "invalidatedModules",
    "evidenceKind", "evidenceArtifact", "evidenceSummary", "repairMetadata", "recoveredAfterCrash", "changes",
)
private val DELTA_FIELDS = setOf(
    "path", "beforeSha256", "beforeBytes", "afterSha256", "beforeBlobSha256", "afterBlobSha256", "afterBytes",
)
private val METADATA_V1_FIELDS = setOf(
    "iterationIndex", "failureKind", "prompt", "summary", "retainedRegressionIds", "before", "regressionCorpusSha256",
)
private val METADATA_V2_FIELDS = METADATA_V1_FIELDS + setOf("agentInvocation", "publicationMode")
private val INVOCATION_FIELDS = setOf(
    "receiptPath", "receiptSha256", "receiptSchemaVersion", "requestSha256", "resultChangesSha256",
    "terminalOutcome", "receiptReleaseComplete", "assessmentStatus",
)
private val EVIDENCE_FIELDS = setOf("kind", "summary", "artifactPath")
private val REGRESSION_INPUT_FIELDS = setOf("id", "args", "stdinHex")
private val RECOVERY_BINDING_FIELDS = setOf(
    "schemaVersion", "profileId", "profileSha256", "budgetSha256", "sourcePaths", "editablePaths", "indexSha256",
)
private val HISTORY_FIELDS = setOf("schemaVersion", "regressionInputs", "iterations")
private val HISTORY_ITERATION_FIELDS = setOf(
    "index", "failureKind", "prompt", "summary", "succeeded", "retainedRegressionIds", "before", "after",
    "agentInvocation", "publicationMode", "patches",
)
private val HISTORY_PATCH_FIELDS = setOf("relativePath", "replacementHex")
