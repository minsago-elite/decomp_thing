package decompengine.oracle.fulltree

import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.util.Collections
import java.util.PriorityQueue
import java.util.TreeMap
import java.util.TreeSet

internal class FullTreeCompilerHeaderPlanProjectionException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

/** One planning module and its raw, explicitly unauthenticated Clang header trace. */
internal class FullTreeCompilerHeaderTraceModule(
    val moduleId: String,
    val shardId: String,
    val sourcePath: String,
    rawTraceBytes: ByteArray,
) {
    private val storedTraceBytes = rawTraceBytes.copyOf()

    val traceByteCount: Int
        get() = storedTraceBytes.size

    val rawTraceBytes: ByteArray
        get() = storedTraceBytes.copyOf()
}

/** Caller-lowerable aggregate limits around the independently bounded parser and plan builder. */
internal data class FullTreeCompilerHeaderPlanProjectionLimits(
    val trace: FullTreeClangHeaderTraceLimits = FullTreeClangHeaderTraceLimits(),
    val plan: FullTreeHeaderModulePlanLimits = FullTreeHeaderModulePlanLimits(),
    val maximumTraces: Int = COMPILER_HEADER_PROJECTION_MAXIMUM_TRACES,
    val maximumTotalTraceBytes: Long = COMPILER_HEADER_PROJECTION_MAXIMUM_TOTAL_TRACE_BYTES,
    val maximumEvidenceFacts: Int = COMPILER_HEADER_PROJECTION_MAXIMUM_EVIDENCE_FACTS,
    val maximumEvidenceBytes: Long = COMPILER_HEADER_PROJECTION_MAXIMUM_EVIDENCE_BYTES,
    val maximumWorkUnits: Long = COMPILER_HEADER_PROJECTION_MAXIMUM_WORK_UNITS,
) {
    init {
        require(maximumTraces in 1..COMPILER_HEADER_PROJECTION_MAXIMUM_TRACES)
        require(maximumTotalTraceBytes in 1L..COMPILER_HEADER_PROJECTION_MAXIMUM_TOTAL_TRACE_BYTES)
        require(maximumEvidenceFacts in 1..COMPILER_HEADER_PROJECTION_MAXIMUM_EVIDENCE_FACTS)
        require(maximumEvidenceBytes in 1L..COMPILER_HEADER_PROJECTION_MAXIMUM_EVIDENCE_BYTES)
        require(maximumWorkUnits in 1L..COMPILER_HEADER_PROJECTION_MAXIMUM_WORK_UNITS)
    }
}

/**
 * Non-authoritative multi-TU projection from raw Clang traces into the first-class header plan.
 *
 * Only compiler-resolved project file identities whose dependency is present in the complete
 * canonical header manifest become contextual direct edges. Everything else remains digest-bound
 * blocker evidence, including an unavoidable unauthenticated-trace blocker for every module.
 */
internal object FullTreeCompilerHeaderPlanProjection {
    fun project(
        modules: List<FullTreeCompilerHeaderTraceModule>,
        canonicalHeaderPaths: List<String>,
        sourceOnlyUnits: List<FullTreeHeaderSourceOnlyUnit>,
        traceRoots: List<FullTreeClangTraceRoot>,
        limits: FullTreeCompilerHeaderPlanProjectionLimits =
            FullTreeCompilerHeaderPlanProjectionLimits(),
    ): FullTreeHeaderModulePlanResult = try {
        preflightProjectionInputs(modules, canonicalHeaderPaths, sourceOnlyUnits, traceRoots, limits)
        projectCompilerHeaderPlan(
            snapshotModules(modules),
            ArrayList(canonicalHeaderPaths),
            sourceOnlyUnits.map { it.copy() },
            ArrayList(traceRoots),
            limits,
        )
    } catch (failure: FullTreeCompilerHeaderPlanProjectionException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeCompilerHeaderPlanProjectionException(
            "compiler header-plan projection failed: ${failure.message}",
            failure,
        )
    }
}

private data class ProjectionModule(
    val moduleId: String,
    val shardId: String,
    val sourcePath: String,
    val traceSource: FullTreeCompilerHeaderTraceModule,
)

private data class ContextualEdge(
    val observingModuleId: String,
    val consumerPath: String,
    val dependencyHeaderPath: String,
)

private data class EvidenceKey(
    val consumerPath: String,
    val kind: FullTreeHeaderResolutionBlockerKind,
)

private data class EvidenceFact(val tag: String, val fields: List<String>)

private data class Attachment(val distance: Int, val ownerPath: String)

private data class AttachmentCandidate(
    val distance: Int,
    val ownerPath: String,
    val path: String,
)

private fun snapshotModules(raw: List<FullTreeCompilerHeaderTraceModule>): List<ProjectionModule> =
    ArrayList(raw).map { module ->
        ProjectionModule(
            module.moduleId,
            module.shardId,
            module.sourcePath,
            module,
        )
    }

private fun preflightProjectionInputs(
    modules: List<FullTreeCompilerHeaderTraceModule>,
    headerPaths: List<String>,
    sourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
    roots: List<FullTreeClangTraceRoot>,
    limits: FullTreeCompilerHeaderPlanProjectionLimits,
) {
    if (modules.isEmpty()) projectionFail("projection requires at least one traced module")
    if (modules.size > limits.maximumTraces || modules.size > limits.plan.maximumModules) {
        projectionFail("projection exceeds its trace/module bound")
    }
    if (headerPaths.size > limits.plan.maximumHeaders) {
        projectionFail("projection exceeds its canonical-header bound")
    }
    if (sourceOnly.size > limits.plan.maximumSourceOnlyUnits) {
        projectionFail("projection exceeds its source-only bound")
    }
    if (roots.size != 2) projectionFail("projection requires exactly two trace roots")
    roots.forEach { root ->
        if (root.observedRoot.length > limits.trace.maximumPathBytes ||
            root.observedRoot.toByteArray(StandardCharsets.UTF_8).size > limits.trace.maximumPathBytes
        ) {
            projectionFail("projection trace root exceeds its path bound")
        }
    }
    if (modules.size.toLong() + headerPaths.size.toLong() > limits.plan.maximumGraphNodes.toLong()) {
        projectionFail("projection exceeds its graph-node bound")
    }
    var totalTraceBytes = 0L
    modules.forEach { module ->
        if (module.traceByteCount > limits.trace.maximumInputBytes) {
            projectionFail("projection trace exceeds its per-trace input bound")
        }
        totalTraceBytes = addProjectionCount(totalTraceBytes, module.traceByteCount.toLong(), "trace byte")
        if (totalTraceBytes > limits.maximumTotalTraceBytes) {
            projectionFail("projection exceeds its aggregate trace-byte bound")
        }
    }
}

private fun projectCompilerHeaderPlan(
    modules: List<ProjectionModule>,
    headerPaths: List<String>,
    sourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
    roots: List<FullTreeClangTraceRoot>,
    limits: FullTreeCompilerHeaderPlanProjectionLimits,
): FullTreeHeaderModulePlanResult {
    if (modules.isEmpty()) projectionFail("projection requires at least one traced module")
    if (modules.size > limits.maximumTraces || modules.size > limits.plan.maximumModules) {
        projectionFail("projection exceeds its trace/module bound")
    }
    val work = ProjectionWorkBudget(
        limits.maximumWorkUnits,
        limits.maximumEvidenceFacts,
        limits.maximumEvidenceBytes,
        limits.plan.maximumBlockers,
    )
    val orderedModules = validateProjectionInputs(modules, headerPaths, sourceOnly, work)
    val headerSet = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER).apply { addAll(headerPaths) }
    val modulePaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER).apply {
        addAll(orderedModules.map(ProjectionModule::sourcePath))
    }
    val observations = TreeSet(HEADER_OBSERVATION_ORDER)
    val edges = TreeSet(CONTEXTUAL_EDGE_ORDER)
    val evidence = TreeMap<EvidenceKey, MutableList<EvidenceFact>>(EVIDENCE_KEY_ORDER)
    var totalTraceBytes = 0L

    orderedModules.forEach { module ->
        totalTraceBytes = addProjectionCount(
            totalTraceBytes,
            module.traceSource.traceByteCount.toLong(),
            "trace byte",
        )
        if (totalTraceBytes > limits.maximumTotalTraceBytes) {
            projectionFail("projection exceeds its aggregate trace-byte bound")
        }
        work.charge("trace")
        val remainingParserWork = work.remainingWorkUnits()
        if (remainingParserWork < 1L) {
            projectionFail("projection has no remaining work budget for trace parsing")
        }
        val effectiveTraceLimits = limits.trace.copy(
            maximumWorkUnits = minOf(limits.trace.maximumWorkUnits, remainingParserWork),
        )
        val traceBytes = module.traceSource.rawTraceBytes
        val trace = FullTreeClangHeaderTraceParser.parse(
            traceBytes,
            roots,
            module.sourcePath,
            effectiveTraceLimits,
        )
        work.charge(trace.workUnits, "parsed trace work")
        trace.projectFiles.forEach { path ->
            work.charge("observed project file")
            if (isProjectionHeader(path) && path !in headerSet) {
                projectionFail("observed project header is absent from the canonical manifest: $path")
            }
            if (isProjectionHeader(path)) {
                val added = observations.add(FullTreeObservedHeaderUse(module.moduleId, path))
                if (added && observations.size > limits.plan.maximumHeaderObservations) {
                    projectionFail("projection exceeds its contextual header-observation bound")
                }
            }
        }

        fun isEligibleConsumer(path: String): Boolean = path == module.sourcePath || path in headerSet
        val attachments = buildNearestKnownAttachments(trace, module.sourcePath, headerSet, work)
        fun attachmentFor(consumerPath: String): String =
            if (isEligibleConsumer(consumerPath)) consumerPath
            else attachments[consumerPath]?.ownerPath ?: module.sourcePath

        addEvidence(
            evidence,
            module.sourcePath,
            FullTreeHeaderResolutionBlockerKind.COMPILER_TRACE_UNAUTHENTICATED,
            unauthenticatedTraceFact(module, trace, roots, traceBytes.size),
            work,
        )

        trace.includeOccurrences.forEach { occurrence ->
            work.charge("project include occurrence")
            val consumer = attachmentFor(occurrence.consumerPath)
            val consumerEligible = isEligibleConsumer(occurrence.consumerPath)
            val foreignModuleConsumer = occurrence.consumerPath in modulePaths &&
                occurrence.consumerPath != module.sourcePath
            if (!consumerEligible && !foreignModuleConsumer) {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.OUT_OF_SCOPE_CONSUMER,
                    projectIncludeFact(module, trace, occurrence),
                    work,
                )
            }
            if (foreignModuleConsumer) {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.NON_HEADER_PROJECT_TARGET,
                    projectIncludeFact(module, trace, occurrence),
                    work,
                )
            }
            if (isProjectionHeader(occurrence.dependencyPath)) {
                if (occurrence.dependencyPath !in headerSet) {
                    projectionFail(
                        "observed project header is absent from the canonical manifest: " +
                            occurrence.dependencyPath,
                    )
                }
                if (consumerEligible) {
                    val added = edges.add(ContextualEdge(
                        module.moduleId,
                        occurrence.consumerPath,
                        occurrence.dependencyPath,
                    ))
                    if (added && edges.size > limits.plan.maximumDirectEdges) {
                        projectionFail("projection exceeds its contextual direct-edge bound")
                    }
                }
            } else {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.NON_HEADER_PROJECT_TARGET,
                    projectIncludeFact(module, trace, occurrence),
                    work,
                )
            }
        }

        trace.externalIncludeOccurrences.forEach { occurrence ->
            work.charge("external include occurrence")
            val consumer = attachmentFor(occurrence.consumerPath)
            val foreignModuleConsumer = occurrence.consumerPath in modulePaths &&
                occurrence.consumerPath != module.sourcePath
            if (!isEligibleConsumer(occurrence.consumerPath) && !foreignModuleConsumer) {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.OUT_OF_SCOPE_CONSUMER,
                    externalIncludeFact(module, trace, occurrence),
                    work,
                )
            }
            if (foreignModuleConsumer) {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.NON_HEADER_PROJECT_TARGET,
                    externalIncludeFact(module, trace, occurrence),
                    work,
                )
            }
            addEvidence(
                evidence,
                consumer,
                FullTreeHeaderResolutionBlockerKind.EXTERNAL_INCLUDE,
                externalIncludeFact(module, trace, occurrence),
                work,
            )
        }

        trace.externalConsumerIncludeOccurrences.forEach { occurrence ->
            work.charge("external consumer include occurrence")
            val fact = externalConsumerIncludeFact(module, trace, occurrence)
            addEvidence(
                evidence,
                module.sourcePath,
                FullTreeHeaderResolutionBlockerKind.OUT_OF_SCOPE_CONSUMER,
                fact,
                work,
            )
            val projectDependency = occurrence.dependencyProjectPath
            if (projectDependency == null) {
                addEvidence(
                    evidence,
                    module.sourcePath,
                    FullTreeHeaderResolutionBlockerKind.EXTERNAL_INCLUDE,
                    fact,
                    work,
                )
            } else if (isProjectionHeader(projectDependency)) {
                if (projectDependency !in headerSet) {
                    projectionFail(
                        "observed project header is absent from the canonical manifest: $projectDependency",
                    )
                }
            } else {
                addEvidence(
                    evidence,
                    module.sourcePath,
                    FullTreeHeaderResolutionBlockerKind.NON_HEADER_PROJECT_TARGET,
                    fact,
                    work,
                )
            }
        }

        trace.moduleImports.forEach { imported ->
            work.charge("module import")
            val consumer = attachmentFor(imported.consumerPath)
            val fact = moduleImportFact(module, trace, imported)
            val foreignModuleConsumer = imported.consumerPath in modulePaths &&
                imported.consumerPath != module.sourcePath
            if (!isEligibleConsumer(imported.consumerPath) && !foreignModuleConsumer) {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.OUT_OF_SCOPE_CONSUMER,
                    fact,
                    work,
                )
            }
            if (foreignModuleConsumer) {
                addEvidence(
                    evidence,
                    consumer,
                    FullTreeHeaderResolutionBlockerKind.NON_HEADER_PROJECT_TARGET,
                    fact,
                    work,
                )
            }
            addEvidence(
                evidence,
                consumer,
                FullTreeHeaderResolutionBlockerKind.MODULE_IMPORT,
                fact,
                work,
            )
        }

        trace.externalConsumerModuleImports.forEach { imported ->
            work.charge("external consumer module import")
            val fact = externalConsumerModuleImportFact(module, trace, imported)
            addEvidence(
                evidence,
                module.sourcePath,
                FullTreeHeaderResolutionBlockerKind.OUT_OF_SCOPE_CONSUMER,
                fact,
                work,
            )
            addEvidence(
                evidence,
                module.sourcePath,
                FullTreeHeaderResolutionBlockerKind.MODULE_IMPORT,
                fact,
                work,
            )
        }
    }

    val blockers = evidence.map { (key, facts) ->
        work.charge(facts.size.toLong() + 1L, "aggregated blocker evidence")
        FullTreeHeaderResolutionBlocker(
            key.consumerPath,
            key.kind,
            evidenceSha256(key, facts),
        )
    }
    val blockerCounts = blockers.groupingBy(FullTreeHeaderResolutionBlocker::consumerPath).eachCount()
    val planModules = orderedModules.map { module ->
        FullTreeHeaderPlanningModule(
            module.moduleId,
            module.shardId,
            module.sourcePath,
            blockerCounts.getOrDefault(module.sourcePath, 0),
        )
    }
    val headers = headerSet.map { path ->
        FullTreeCanonicalHeader(path, blockerCounts.getOrDefault(path, 0))
    }
    val directEdges = edges.map { edge ->
        FullTreeResolvedDirectFileEdge(
            observingModuleId = edge.observingModuleId,
            consumerPath = edge.consumerPath,
            dependencyHeaderPath = edge.dependencyHeaderPath,
        )
    }
    return FullTreeHeaderModulePlan.build(
        planModules,
        headers,
        sourceOnly,
        observations.toList(),
        directEdges,
        blockers,
        limits.plan,
    )
}

private fun validateProjectionInputs(
    modules: List<ProjectionModule>,
    headerPaths: List<String>,
    sourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
    work: ProjectionWorkBudget,
): List<ProjectionModule> {
    val moduleIds = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    val modulePaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    modules.forEach { module ->
        work.charge("module input")
        if (!COMPILER_HEADER_PROJECTION_MODULE_ID.matches(module.moduleId)) {
            projectionFail("projection module ID is not a canonical compilation-unit ID")
        }
        requireProjectionShard(module.shardId, "projection module")
        requireProjectionPath(
            module.sourcePath,
            COMPILER_HEADER_PROJECTION_MODULE_SUFFIXES,
            "projection module source",
        )
        if (!moduleIds.add(module.moduleId) || !modulePaths.add(module.sourcePath)) {
            projectionFail("each planning module must have exactly one trace and unique identity/path")
        }
    }
    val headers = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    headerPaths.forEach { path ->
        work.charge("header manifest input")
        requireProjectionPath(path, COMPILER_HEADER_PROJECTION_HEADER_SUFFIXES, "projection header")
        if (!headers.add(path)) projectionFail("canonical header manifest contains a duplicate path")
    }
    val sourceOnlyPaths = TreeSet<String>(FULL_TREE_CODE_POINT_ORDER)
    sourceOnly.forEach { unit ->
        work.charge("source-only input")
        requireProjectionShard(unit.shardId, "projection source-only unit")
        requireProjectionPath(
            unit.sourcePath,
            COMPILER_HEADER_PROJECTION_MODULE_SUFFIXES,
            "projection source-only unit",
        )
        if (!sourceOnlyPaths.add(unit.sourcePath)) {
            projectionFail("source-only inputs contain a duplicate path")
        }
    }
    if (modulePaths.any { it in headers || it in sourceOnlyPaths } ||
        headers.any { it in sourceOnlyPaths }
    ) {
        projectionFail("module, header, and source-only paths must be fully disjoint")
    }
    return modules.sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.moduleId })
}

private fun buildNearestKnownAttachments(
    trace: FullTreeClangHeaderTrace,
    moduleSourcePath: String,
    headerPaths: Set<String>,
    work: ProjectionWorkBudget,
): Map<String, Attachment> {
    fun isKnownPath(path: String): Boolean = path == moduleSourcePath || path in headerPaths
    val outgoing = TreeMap<String, TreeSet<String>>(FULL_TREE_CODE_POINT_ORDER)
    trace.includeOccurrences.forEach { occurrence ->
        work.charge("attachment graph edge")
        outgoing.computeIfAbsent(occurrence.consumerPath) { TreeSet(FULL_TREE_CODE_POINT_ORDER) }
            .add(occurrence.dependencyPath)
        outgoing.computeIfAbsent(occurrence.dependencyPath) { TreeSet(FULL_TREE_CODE_POINT_ORDER) }
    }
    val best = TreeMap<String, Attachment>(FULL_TREE_CODE_POINT_ORDER)
    val ready = PriorityQueue(ATTACHMENT_CANDIDATE_ORDER)
    outgoing.keys.filter(::isKnownPath).forEach { path ->
        val attachment = Attachment(0, path)
        best[path] = attachment
        ready += AttachmentCandidate(0, path, path)
    }
    while (ready.isNotEmpty()) {
        val candidate = ready.remove()
        work.charge("attachment graph node")
        if (best[candidate.path] != Attachment(candidate.distance, candidate.ownerPath)) continue
        outgoing.getValue(candidate.path).forEach { dependency ->
            work.charge("attachment graph traversal")
            if (isKnownPath(dependency)) return@forEach
            val next = Attachment(Math.addExact(candidate.distance, 1), candidate.ownerPath)
            val previous = best[dependency]
            if (previous == null || ATTACHMENT_ORDER.compare(next, previous) < 0) {
                best[dependency] = next
                ready += AttachmentCandidate(next.distance, next.ownerPath, dependency)
            }
        }
    }
    return Collections.unmodifiableMap(best)
}

private fun projectIncludeFact(
    module: ProjectionModule,
    trace: FullTreeClangHeaderTrace,
    occurrence: FullTreeClangIncludeOccurrence,
): EvidenceFact = EvidenceFact(
    "project-include",
    listOf(
        module.moduleId,
        trace.canonicalFactsSha256,
        occurrence.consumerPath,
        occurrence.presumedLocationFile,
        occurrence.line.toString(),
        occurrence.column.toString(),
        occurrence.dependencyPath,
    ),
)

private fun unauthenticatedTraceFact(
    module: ProjectionModule,
    trace: FullTreeClangHeaderTrace,
    roots: List<FullTreeClangTraceRoot>,
    traceByteCount: Int,
): EvidenceFact {
    val rootFields = roots.sortedWith { left, right ->
        FULL_TREE_CODE_POINT_ORDER.compare(left.canonicalRoot, right.canonicalRoot).takeIf { it != 0 }
            ?: FULL_TREE_CODE_POINT_ORDER.compare(left.observedRoot, right.observedRoot)
    }.flatMap { root -> listOf(root.canonicalRoot, root.observedRoot) }
    return EvidenceFact(
        "unauthenticated-compiler-trace",
        listOf(
            module.moduleId,
            module.sourcePath,
            trace.expectedMainSourcePath,
            traceByteCount.toString(),
            trace.inputSha256,
            trace.canonicalFactsSha256,
            roots.size.toString(),
        ) + rootFields,
    )
}

private fun externalIncludeFact(
    module: ProjectionModule,
    trace: FullTreeClangHeaderTrace,
    occurrence: FullTreeClangExternalIncludeOccurrence,
): EvidenceFact = EvidenceFact(
    "external-include",
    listOf(
        module.moduleId,
        trace.canonicalFactsSha256,
        occurrence.consumerPath,
        occurrence.presumedLocationFile,
        occurrence.line.toString(),
        occurrence.column.toString(),
        occurrence.observedDependencyPath,
    ),
)

private fun externalConsumerIncludeFact(
    module: ProjectionModule,
    trace: FullTreeClangHeaderTrace,
    occurrence: FullTreeClangExternalConsumerIncludeOccurrence,
): EvidenceFact = EvidenceFact(
    "external-consumer-include",
    listOf(
        module.moduleId,
        trace.canonicalFactsSha256,
        occurrence.observedConsumerPath,
        occurrence.presumedLocationFile,
        occurrence.line.toString(),
        occurrence.column.toString(),
        occurrence.observedDependencyPath,
        occurrence.dependencyProjectPath ?: "",
    ),
)

private fun moduleImportFact(
    module: ProjectionModule,
    trace: FullTreeClangHeaderTrace,
    imported: FullTreeClangModuleImport,
): EvidenceFact = EvidenceFact(
    "module-import",
    listOf(
        module.moduleId,
        trace.canonicalFactsSha256,
        imported.consumerPath,
        imported.presumedLocationFile,
        imported.line.toString(),
        imported.column.toString(),
        imported.moduleName,
        imported.observedModuleMapPath,
        imported.moduleMapPath ?: "",
    ),
)

private fun externalConsumerModuleImportFact(
    module: ProjectionModule,
    trace: FullTreeClangHeaderTrace,
    imported: FullTreeClangExternalConsumerModuleImport,
): EvidenceFact = EvidenceFact(
    "external-consumer-module-import",
    listOf(
        module.moduleId,
        trace.canonicalFactsSha256,
        imported.observedConsumerPath,
        imported.presumedLocationFile,
        imported.line.toString(),
        imported.column.toString(),
        imported.moduleName,
        imported.observedModuleMapPath,
        imported.moduleMapProjectPath ?: "",
    ),
)

private fun addEvidence(
    evidence: MutableMap<EvidenceKey, MutableList<EvidenceFact>>,
    consumerPath: String,
    kind: FullTreeHeaderResolutionBlockerKind,
    fact: EvidenceFact,
    work: ProjectionWorkBudget,
) {
    work.charge("blocker evidence occurrence")
    val key = EvidenceKey(consumerPath, kind)
    val facts = evidence[key] ?: run {
        work.addEvidenceKey(evidence.size)
        arrayListOf<EvidenceFact>().also { evidence[key] = it }
    }
    work.addEvidenceFact(fact)
    facts.add(fact)
}

private fun evidenceSha256(key: EvidenceKey, rawFacts: List<EvidenceFact>): String {
    val digest = MessageDigest.getInstance("SHA-256")
    digest.updateProjectionFrame(COMPILER_HEADER_PROJECTION_EVIDENCE_DOMAIN)
    digest.updateProjectionFrame(key.consumerPath)
    digest.updateProjectionFrame(key.kind.wireName)
    val facts = rawFacts.sortedWith(EVIDENCE_FACT_ORDER)
    digest.updateProjectionInt(facts.size)
    facts.forEach { fact ->
        digest.updateProjectionFrame(fact.tag)
        digest.updateProjectionInt(fact.fields.size)
        fact.fields.forEach(digest::updateProjectionFrame)
    }
    return digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}

private fun MessageDigest.updateProjectionFrame(value: String) {
    val bytes = value.toByteArray(StandardCharsets.UTF_8)
    updateProjectionInt(bytes.size)
    update(bytes)
}

private fun MessageDigest.updateProjectionInt(value: Int) {
    if (value < 0) projectionFail("negative value cannot enter an evidence frame")
    update(
        byteArrayOf(
            (value ushr 24).toByte(),
            (value ushr 16).toByte(),
            (value ushr 8).toByte(),
            value.toByte(),
        ),
    )
}

private fun isProjectionHeader(path: String): Boolean =
    COMPILER_HEADER_PROJECTION_HEADER_SUFFIXES.any(path::endsWith)

private fun requireProjectionShard(value: String, label: String) {
    if (!COMPILER_HEADER_PROJECTION_SHARD_ID.matches(value) ||
        value in COMPILER_HEADER_PROJECTION_CATCH_ALL_IDS
    ) {
        projectionFail("$label shard ID is malformed or a forbidden catch-all")
    }
}

private fun requireProjectionPath(path: String, suffixes: Set<String>, label: String) {
    if (path.length > COMPILER_HEADER_PROJECTION_MAXIMUM_PATH_BYTES || path.isEmpty() ||
        path.startsWith('/') || '\\' in path || path.any { it.code !in 0x20..0x7e } ||
        !(path.startsWith("source/") || path.startsWith("generated/")) ||
        path.split('/').any { it.isEmpty() || it == "." || it == ".." } ||
        suffixes.none(path::endsWith)
    ) {
        projectionFail("$label is not a canonical bounded source/generated file path")
    }
}

private fun addProjectionCount(current: Long, amount: Long, label: String): Long = try {
    Math.addExact(current, amount)
} catch (failure: ArithmeticException) {
    throw FullTreeCompilerHeaderPlanProjectionException("projection $label count overflowed", failure)
}

private class ProjectionWorkBudget(
    private val maximum: Long,
    private val maximumEvidenceFacts: Int,
    private val maximumEvidenceBytes: Long,
    private val maximumEvidenceKeys: Int,
) {
    var used: Long = 0L
        private set
    private var evidenceFacts: Int = 0
    private var evidenceBytes: Long = 0L

    fun charge(label: String) = charge(1L, label)

    fun charge(amount: Long, label: String) {
        used = addProjectionCount(used, amount, "work-unit")
        if (used > maximum) projectionFail("projection exceeds its work-unit bound during $label")
    }

    fun remainingWorkUnits(): Long = maximum - used

    fun addEvidenceKey(currentKeyCount: Int) {
        if (currentKeyCount >= maximumEvidenceKeys) {
            projectionFail("projection exceeds its aggregated blocker bound")
        }
    }

    fun addEvidenceFact(fact: EvidenceFact) {
        evidenceFacts = try {
            Math.addExact(evidenceFacts, 1)
        } catch (failure: ArithmeticException) {
            throw FullTreeCompilerHeaderPlanProjectionException(
                "projection evidence-fact count overflowed",
                failure,
            )
        }
        if (evidenceFacts > maximumEvidenceFacts) {
            projectionFail("projection exceeds its aggregate evidence-fact bound")
        }
        var factBytes = 8L
        factBytes = addProjectionCount(
            factBytes,
            fact.tag.toByteArray(StandardCharsets.UTF_8).size.toLong(),
            "evidence byte",
        )
        fact.fields.forEach { field ->
            factBytes = addProjectionCount(factBytes, 4L, "evidence byte")
            factBytes = addProjectionCount(
                factBytes,
                field.toByteArray(StandardCharsets.UTF_8).size.toLong(),
                "evidence byte",
            )
        }
        evidenceBytes = addProjectionCount(evidenceBytes, factBytes, "evidence byte")
        if (evidenceBytes > maximumEvidenceBytes) {
            projectionFail("projection exceeds its aggregate evidence-byte bound")
        }
    }
}

private fun projectionFail(message: String): Nothing =
    throw FullTreeCompilerHeaderPlanProjectionException(message)

private val CONTEXTUAL_EDGE_ORDER = Comparator<ContextualEdge> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.observingModuleId, right.observingModuleId).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.consumerPath, right.consumerPath).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.dependencyHeaderPath, right.dependencyHeaderPath)
}

private val HEADER_OBSERVATION_ORDER = Comparator<FullTreeObservedHeaderUse> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.observingModuleId, right.observingModuleId).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.headerPath, right.headerPath)
}

private val EVIDENCE_KEY_ORDER = Comparator<EvidenceKey> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.consumerPath, right.consumerPath).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.kind.wireName, right.kind.wireName)
}

private val EVIDENCE_FACT_ORDER = Comparator<EvidenceFact> { left, right ->
    FULL_TREE_CODE_POINT_ORDER.compare(left.tag, right.tag).takeIf { it != 0 }
        ?: compareProjectionFields(left.fields, right.fields)
}

private fun compareProjectionFields(left: List<String>, right: List<String>): Int {
    val shared = minOf(left.size, right.size)
    repeat(shared) { index ->
        val compared = FULL_TREE_CODE_POINT_ORDER.compare(left[index], right[index])
        if (compared != 0) return compared
    }
    return left.size.compareTo(right.size)
}

private val ATTACHMENT_ORDER = Comparator<Attachment> { left, right ->
    left.distance.compareTo(right.distance).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.ownerPath, right.ownerPath)
}

private val ATTACHMENT_CANDIDATE_ORDER = Comparator<AttachmentCandidate> { left, right ->
    left.distance.compareTo(right.distance).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.ownerPath, right.ownerPath).takeIf { it != 0 }
        ?: FULL_TREE_CODE_POINT_ORDER.compare(left.path, right.path)
}

private val COMPILER_HEADER_PROJECTION_HEADER_SUFFIXES =
    setOf(".def", ".h", ".hh", ".hpp", ".hxx", ".inc")
private val COMPILER_HEADER_PROJECTION_MODULE_SUFFIXES = setOf(".c", ".cc", ".cpp", ".cxx", ".m", ".mm")
private val COMPILER_HEADER_PROJECTION_MODULE_ID = Regex("cu-[0-9a-f]{32}")
private val COMPILER_HEADER_PROJECTION_SHARD_ID = Regex("[a-z0-9][a-z0-9-]{0,127}")
private val COMPILER_HEADER_PROJECTION_CATCH_ALL_IDS =
    setOf("catch-all", "catchall", "core", "default", "misc", "unowned")

private const val COMPILER_HEADER_PROJECTION_EVIDENCE_DOMAIN =
    "decomp-full-tree-compiler-header-plan-projection-evidence-v1-length-framed-utf8"
private const val COMPILER_HEADER_PROJECTION_MAXIMUM_PATH_BYTES = 4096
internal const val COMPILER_HEADER_PROJECTION_MAXIMUM_TRACES = HEADER_PLAN_MAXIMUM_MODULES
internal const val COMPILER_HEADER_PROJECTION_MAXIMUM_TOTAL_TRACE_BYTES = 16L * 1024L * 1024L * 1024L
internal const val COMPILER_HEADER_PROJECTION_MAXIMUM_EVIDENCE_FACTS = 100_000
internal const val COMPILER_HEADER_PROJECTION_MAXIMUM_EVIDENCE_BYTES = 64L * 1024L * 1024L
internal const val COMPILER_HEADER_PROJECTION_MAXIMUM_WORK_UNITS = 100_000_000L
