package decompengine.oracle.fulltree

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.*
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.util.Collections

internal class ExternalProviderAssessmentV1 internal constructor(
    canonical: ByteArray,
    blockers: List<ExternalBoundaryFindingV1>,
    val recordedInputsConsistent: Boolean,
    val sha256: String, budget: ExternalBoundaryBudgetV1? = null,
) {
    init {
        // Admit the entire caller-owned population before allocating any defensive copy.
        budget?.checkpoint("assessment constructor admission")
        require(canonical.size <= (budget?.limits?.maximumDocumentBytes ?: 4 * 1024 * 1024))
        require(blockers.size <= (budget?.limits?.maximumFindings ?: 16384))
        val referenceLimit = budget?.limits?.maximumReferencesAndEvents ?: 65536
        var references = 0L
        for (finding in blockers) {
            budget?.checkpoint("assessment nested reference admission")
            references += finding.evidenceRefs.size.toLong()
            require(references <= referenceLimit) { "assessment aggregate evidence reference ceiling exceeded" }
        }
        budget?.checkpoint("assessment constructor copy", canonical.size.toLong() + references)
    }
    private val canonical = canonical.copyOf()
    val blockers = Collections.unmodifiableList(blockers.map { budget?.checkpoint("assessment finding ownership"); it.copy(evidenceRefs=Collections.unmodifiableList(it.evidenceRefs.toList())) })
    fun canonicalBytes(): ByteArray = canonical.copyOf()
}

/** Pure, bounded ledger assessment over explicitly recorded input. All outputs are non-bearer. */
internal object FullTreeExternalProviderLedgerV1 {
    private val policyKeys = setOf("schemaVersion", "kind", "bindings", "providers", "tools", "requirements", "expectedStages", "runtimePolicy")
    private val inputKeys = setOf("schemaVersion", "kind", "bindings", "universe", "stages", "elfEvidence", "rawMeasurements", "recordedClosures", "runtimeInterfaces")

    fun assess(
        policyBytes: ByteArray,
        inputBytes: ByteArray,
        parent: AnalysisDeadline,
        limits: ExternalProviderLimitsV1 = ExternalProviderLimitsV1(),
    ): ExternalProviderAssessmentV1 {
        require(policyBytes.size <= limits.maximumDocumentBytes && inputBytes.size <= limits.maximumDocumentBytes)
        require(policyBytes.size.toLong() + inputBytes.size <= limits.maximumAggregateInputBytes) { "aggregate input ceiling exceeded" }
        val budget = ExternalBoundaryBudgetV1(limits, parent)
        budget.checkpoint("ledger input-byte admission", policyBytes.size.toLong()+inputBytes.size)
        val decodedPolicy = (OracleJson.parseCanonical(policyBytes, budget.jsonLimits(), { budget.checkpoint(it) }) as? JsonObject)
            ?: error("policy must be object")
        val decodedInput = (OracleJson.parseCanonical(inputBytes, budget.jsonLimits(), { budget.checkpoint(it) }) as? JsonObject)
            ?: error("inputs must be object")
        require(decodedPolicy.keys == policyKeys && decodedPolicy["schemaVersion"] == JsonPrimitive(1) && decodedPolicy["kind"] == JsonPrimitive("external-provider-policy-v1"))
        require(decodedInput.keys == inputKeys && decodedInput["schemaVersion"] == JsonPrimitive(1) && decodedInput["kind"] == JsonPrimitive("external-provider-inputs-v1"))
        val findings = mutableListOf<ExternalBoundaryFindingV1>()
        fun finding(code: String, category: String = "consistency", stage: String? = null, occurrence: String? = null) {
            require(findings.size < limits.maximumFindings) { "finding limit exceeded" }
            findings += ExternalBoundaryFindingV1(code, category, stage, occurrence)
        }
        val policyBindings = validateBindings(decodedPolicy["bindings"] as? JsonObject ?: error("policy bindings missing"), budget, ::finding)
        val inputBindings = validateBindings(decodedInput["bindings"] as? JsonObject ?: error("input bindings missing"), budget, ::finding)
        // Normalize once; comparison, document digests and retained rows share these values.
        val policy = JsonObject(decodedPolicy + ("bindings" to policyBindings))
        val input = JsonObject(decodedInput + ("bindings" to inputBindings))
        budget.checkpoint("ledger population check")
        val providers = arr(policy, "providers", limits.maximumProviders)
        val tools = arr(policy, "tools", limits.maximumTools)
        val requirements = arr(policy, "requirements", limits.maximumRequirements)
        val expectedStages = strings(policy, "expectedStages", limits.maximumStages).onEach { require(hex.matches(it)) { "expected stage ID must be lowercase SHA-256" } }
        unique(expectedStages, "expected stage ID")
        val stages = arr(input, "stages", limits.maximumStages)
        if (policyBindings != inputBindings) finding("policy-input-binding-mismatch")
        val policyDigest = configurationSha256(limits, budget)
        val detectorBinding = policyBindings["detectorPolicy"]!!.jsonObject
        if (detectorBinding["disposition"] == JsonPrimitive("available") && detectorBinding["sha256"] != JsonPrimitive(policyDigest))
            finding("detector-policy-configuration-digest-mismatch")
        val derivedApplicability = mutableListOf<JsonObject>()
        val providerIds = validateRecords(providers, "provider", ::validateProvider, derivedApplicability, budget)
        val toolIds = validateRecords(tools, "tool", ::validateTool, derivedApplicability, budget)
        val providerRecords = providers.associate { it.jsonObject["id"]!!.jsonPrimitive.content to it.jsonObject }
        val toolRecords = tools.associate { it.jsonObject["id"]!!.jsonPrimitive.content to it.jsonObject }
        fun bindingDigest(name: String): String? {
            val row = inputBindings[name]!!.jsonObject
            return if (row["disposition"] == JsonPrimitive("available")) str(row, "sha256") else null
        }
        providerRecords.forEach { (id, provider) ->
            if (bindingDigest("sourceLock")?.let { it != str(provider, "sourceLockSha256") } == true)
                finding("provider-source-lock-binding-mismatch", occurrence = id)
            if (bindingDigest("runtimeProfile")?.let { it != str(provider, "runtimeProfileSha256") } == true)
                finding("provider-runtime-profile-binding-mismatch", occurrence = id)
        }
        toolRecords.forEach { (id, tool) ->
            if (bindingDigest("runtimeProfile")?.let { it != str(tool, "runtimeProfileSha256") } == true)
                finding("tool-runtime-profile-binding-mismatch", occurrence = id)
        }
        val requirementRecords = requirements.map { validateRequirement(it, budget) }
        requirementRecords.forEach { r ->
            budget.checkpoint("ELF requirement supported semantics")
            if (r.binding in setOf("gnu-unique","10") || r.raw["type"] == JsonPrimitive(10)) finding("symbol-selection-semantics-unqualified",occurrence=r.id)
        }
        unique(requirementRecords.map { it.id }, "requirement ID")
        unique(requirementRecords.map { it.symbolKeyDigest }, "required physical symbol key")
        val requirementBySymbol = requirementRecords.associateBy { it.symbolKeyDigest }
        val stageRecords = stages.map { validateStage(it, budget) }
        val hasGeneratedTableObligations = (((input["universe"] as? JsonObject)?.get("requiredGeneratedTables") as? JsonArray)?.isNotEmpty() == true)
        val stageIds = stageRecords.map { it.id }
        unique(stageIds, "stage ID")
        if (stageIds.toSet() == expectedStages.toSet() && stageIds != expectedStages) finding("semantic-link-stage-order-changed")
        stageRecords.forEachIndexed { index, stage -> if (stage.ordinal != index) finding("link-stage-ordinal-gap-or-reorder", stage = stage.id) }
        stageRecords.forEach { stage -> if (stage.policySha256 != policyDigest) finding("stage-policy-binding-mismatch", stage = stage.id) }
        if (bindingDigest("sourceRevision") != null) stageRecords.forEach { stage ->
            if (stage.sourceRevisionSha256 != bindingDigest("sourceRevision")) finding("stage-source-revision-binding-mismatch", stage = stage.id)
        }
        if (bindingDigest("planning") != null) stageRecords.forEach { stage ->
            if (stage.planSha256 != bindingDigest("planning")) finding("stage-plan-binding-mismatch", stage = stage.id)
        }
        if (stageRecords.map { it.buildRunId }.toSet().size > 1) finding("multiple-build-runs-in-one-ledger")
        if (stageRecords.map { it.sourceRevisionSha256 }.toSet().size > 1) finding("stage-source-revision-drift")
        if (stageRecords.map { it.planSha256 }.toSet().size > 1) finding("stage-plan-drift")
        val stageById = stageRecords.associateBy { it.id }
        val occurrenceById = stageRecords.flatMap { stage -> stage.before + stage.after }.associateBy { it.id }
        val parentIds = stageRecords.flatMap { it.parentStageIds }.toSet()
        stageRecords.forEach { stage ->
            if (stage.toolIds.any { it !in toolIds }) finding("undeclared-stage-tool", stage = stage.id)
            stage.violations.forEach { finding(it, stage = stage.id) }
            for (parent in stage.parentStageIds) {
                val prior = stageById[parent]
                if (prior == null) finding("missing-parent-stage", stage = stage.id)
                else if (prior.ordinal >= stage.ordinal) finding("invalid-stage-parent-order", stage = stage.id)
            }
            val beforeById = stage.before.associateBy { it.id }
            val afterById = stage.after.associateBy { it.id }
            val selectionById = stage.selections.associateBy { it.occurrenceId }
            stage.selections.forEach { selection ->
                budget.checkpoint("stage selection reconciliation")
                if (selection.occurrenceId !in beforeById) finding("selection-does-not-bind-before-occurrence", stage = stage.id, occurrence = selection.occurrenceId)
                if (selection.providerId != null && selection.providerId !in providerIds) finding("undeclared-selected-provider", stage = stage.id, occurrence = selection.occurrenceId)
                if (selection.aliasTargetId != null && selection.aliasTargetId !in occurrenceById) finding("dangling-alias-target", stage = stage.id, occurrence = selection.occurrenceId)
                if (selection.aliasTargetId != null) {
                    val targetOccurrence = occurrenceById[selection.aliasTargetId]
                    val sourceRequirement = beforeById[selection.occurrenceId]?.let { requirementBySymbol[it.symbolKeyDigest] }
                    val targetRequirement = targetOccurrence?.let { requirementBySymbol[it.symbolKeyDigest] }
                    if (sourceRequirement?.ownerModuleId != targetRequirement?.ownerModuleId) finding("cross-owner-alias-substitution", stage = stage.id, occurrence = selection.occurrenceId)
                    if (targetRequirement == null || selection.exportSymbolKey != targetRequirement.raw["symbolKey"] ||
                        selection.exportName != targetRequirement.name || selection.exportVersion != targetRequirement.version ||
                        selection.providerId != targetOccurrence.providerId)
                        finding("alias-selected-export-does-not-match-explicit-target", stage = stage.id, occurrence = selection.occurrenceId)
                }
                val occurrence = beforeById[selection.occurrenceId]
                if (occurrence?.aliasTargetId != selection.aliasTargetId)
                    finding("alias-occurrence-selection-target-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                val requirement = occurrence?.let { requirementBySymbol[it.symbolKeyDigest] }
                if (selection.absenceProof != null && (occurrence?.disposition != "declared-weak-null" ||
                        !validWeakAbsence(selection, occurrence, stage, requirement, budget)))
                    finding("absence-proof-inapplicable-or-unbound", stage = stage.id, occurrence = selection.occurrenceId)
                if (selection.exportPopulation != null && occurrence?.disposition != "declared-external")
                    finding("export-population-inapplicable", stage = stage.id, occurrence = selection.occurrenceId)
                if (selection.discardProof != null && (occurrence?.disposition != "discarded-with-link-proof" ||
                        selection.discardProof != stage.raw["linkMapSha256"]))
                    finding("discard-proof-inapplicable-or-unbound", stage = stage.id, occurrence = selection.occurrenceId)
                if (occurrence?.disposition == "declared-alias" && selection.aliasTargetId == null) finding("alias-selection-lacks-explicit-target", stage = stage.id, occurrence = selection.occurrenceId)
                if (occurrence?.disposition == "in-scope-owner" && requirement != null &&
                    (selection.providerId != null || selection.exportSymbolKey != requirement.raw["symbolKey"] || selection.exportName != requirement.name || selection.exportVersion != requirement.version || selection.evidenceRefs.isEmpty()))
                    finding("internal-owner-selection-does-not-match-exact-owned-symbol", stage = stage.id, occurrence = selection.occurrenceId)
                if (occurrence?.disposition == "declared-external") {
                    if (selection.providerId != occurrence.providerId) finding("selection-provider-conflicts-with-occurrence", stage = stage.id, occurrence = selection.occurrenceId)
                    if (selection.exportSymbolKey == null || selection.exportName != requirement?.name) finding("selected-export-identity-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                    val provider=selection.providerId?.let(providerRecords::get)
                    if (provider != null && selection.exportSymbolKey?.get("artifactSha256") != provider["sha256"])
                        finding("selected-export-provider-artifact-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                    if (selection.evidenceRefs.isEmpty()) finding("selected-export-link-proof-absent", stage = stage.id, occurrence = selection.occurrenceId)
                    if (selection.exportPopulation == null) finding("selected-export-population-provenance-unavailable", "qualification", stage.id, selection.occurrenceId)
                    else if (provider != null) validateExportPopulation(selection, provider, requirement, stage, budget, ::finding)
                    if (provider != null && (provider["role"] == JsonPrimitive("static-archive") || provider["role"] == JsonPrimitive("system-archive") || provider["soname"] == JsonNull))
                        finding("dynamic-import-selected-nonshared-provider", stage = stage.id, occurrence = selection.occurrenceId)
                    if (provider != null && requirement != null) {
                        val providerAbi=provider["abi"]!!.jsonObject
                        for (field in listOf("family", "version", "cxxLibraryAbi", "unwinderAbi"))
                            if (providerAbi[field] != requirement.abi[field]) finding("provider-ABI-mismatch:$field", stage = stage.id, occurrence = selection.occurrenceId)
                        val requestedSoname=(requirement.version["providerRequest"] as? JsonPrimitive)?.contentOrNull
                        if (requestedSoname != null && provider["soname"] != JsonPrimitive(requestedSoname)) finding("GNU-provider-request-SONAME-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                        val linkerTargets = stage.toolIds.mapNotNull(toolRecords::get)
                            .filter { it["role"] == JsonPrimitive("compiler") || it["role"] == JsonPrimitive("linker") }
                            .map { it["target"] }
                        if (linkerTargets.any { it != provider["target"] }) finding("provider-tool-target-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                    }
                    val requiredName = (requirement?.version?.get("name") as? JsonPrimitive)?.contentOrNull
                    val selectedName = (selection.exportVersion?.get("name") as? JsonPrimitive)?.contentOrNull
                    if (requiredName != null && selectedName != requiredName) finding("selected-GNU-version-name-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                    // GNU version indices identify entries only within their own ELF object.
                    // A definition's providerRequest is not a second caller-side VERNEED request.
                    val requiredDefault = requirement?.version?.get("defaultDefinition")
                    val selectedDefault = selection.exportVersion?.get("defaultDefinition")
                    // A named request may select a nondefault definition with its local high bit set
                    // (glibc dl-lookup.c, check_match). An explicit default requirement still binds.
                    if (requiredDefault == JsonPrimitive(true) && selectedDefault != JsonPrimitive(true))
                        finding("selected-GNU-default-version-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                    if (requiredName == null && (selection.exportVersion?.get("hidden") == JsonPrimitive(true) ||
                            selectedName != null && selectedDefault != JsonPrimitive(true)))
                        finding("selected-GNU-unversioned-lookup-mismatch", stage = stage.id, occurrence = selection.occurrenceId)
                }
            }
            (stage.before + stage.after).forEach { occurrence ->
                val requirement = requirementBySymbol[occurrence.symbolKeyDigest]
                if (requirement == null) {
                    finding("unmatched-symbol-occurrence", stage = stage.id, occurrence = occurrence.id)
                } else {
                    if (occurrence.requirementId != requirement.id) finding("wrong-symbol-requirement", stage = stage.id, occurrence = occurrence.id)
                    if (occurrence.providerId != null && occurrence.providerId !in providerIds) finding("undeclared-selected-provider", stage = stage.id, occurrence = occurrence.id)
                    if (occurrence.disposition != requirement.disposition) finding("unauthorized-disposition-change", stage = stage.id, occurrence = occurrence.id)
                    if (occurrence.ownerModuleId != requirement.ownerModuleId) finding("wrong-symbol-owner", stage = stage.id, occurrence = occurrence.id)
                    if (occurrence.referenceDigest !in requirement.references) finding("physical-reference-not-owned-by-symbol-requirement", stage = stage.id, occurrence = occurrence.id)
                    if (nullableString(occurrence.reference, "ownerModuleId") != requirement.ownerModuleId || nullableString(occurrence.reference, "ownerEntityId") != requirement.ownerEntityId)
                        finding("physical-reference-owner-lineage-mismatch", stage = stage.id, occurrence = occurrence.id)
                    if (occurrence.disposition == "declared-weak-null" &&
                        (requirement.binding !in setOf("weak", "2") || occurrence.providerId != null)) {
                        finding("invalid-weak-null-disposition", stage = stage.id, occurrence = occurrence.id)
                    }
                    if (occurrence.disposition == "declared-external" && occurrence.providerId == null) finding("external-occurrence-without-provider", stage = stage.id, occurrence = occurrence.id)
                    if (occurrence.disposition == "declared-external" && occurrence.side == "after") finding("runtime-provider-binding-unqualified", "qualification", stage.id, occurrence.id)
                    if (occurrence.disposition in setOf("unexplained", "unsupported")) finding("blocking-occurrence-disposition:${occurrence.disposition}", stage = stage.id, occurrence = occurrence.id)
                }
            }
            // A census row can only carry unchanged or discharge with an exact selection.
            stage.after.forEach { after ->
                budget.checkpoint("after census join")
                val before = beforeById[after.id]
                if (before == null || before.copy(side = "after") != after)
                    finding("after-census-without-exact-before-obligation", stage = stage.id, occurrence = after.id)
            }
            stage.before.forEach { before ->
                budget.checkpoint("before obligation discharge join")
                val carried = afterById[before.id] == before.copy(side = "after") && stage.id in parentIds
                if (!carried) {
                    val selected = selectionById[before.id]
                    if (before.disposition == "declared-weak-null") {
                        if (!validWeakAbsence(selected, before, stage, requirementBySymbol[before.symbolKeyDigest], budget))
                            finding("weak-null-supported-absence-proof-unavailable", stage = stage.id, occurrence = before.id)
                        if (hasGeneratedTableObligations) finding("weak-null-may-hide-required-generated-table", stage = stage.id, occurrence = before.id)
                    } else if (selected == null || selected.evidenceRefs.isEmpty())
                        finding("before-obligation-not-carried-or-discharged", stage = stage.id, occurrence = before.id)
                    if (before.disposition == "discarded-with-link-proof" && selected?.discardProof != JsonPrimitive(stage.raw["linkMapSha256"]!!.jsonPrimitive.content))
                        finding("discarded-occurrence-lacks-exact-link-proof", stage = stage.id, occurrence = before.id)
                }
            }
            for (parent in stage.parentStageIds) stageById[parent]?.let { prior ->
                val priorKeys = prior.after.map { it.referenceDigest to it.requirementId }.toSet()
                val childKeys = stage.before.map { it.referenceDigest to it.requirementId }.toSet()
                if (!childKeys.containsAll(priorKeys)) finding("intermediate-obligation-carry-gap", stage = stage.id)
                val childByReference=stage.before.associateBy { it.referenceDigest }
                prior.after.forEach { p ->
                    budget.checkpoint("parent-child exact obligation join")
                    val c=childByReference[p.referenceDigest]
                    if(c==null || c.symbolKey != p.symbolKey || c.requirementId != p.requirementId || c.ownerModuleId != p.ownerModuleId || c.providerId != p.providerId || c.disposition != p.disposition)
                        finding("intermediate-obligation-identity-drift",stage=stage.id,occurrence=p.id)
                }
            }
        }
        stageRecords.filter { it.id !in parentIds }.forEach { finalStage ->
            finalStage.after.forEach { occurrence ->
                val req = requirementBySymbol[occurrence.symbolKeyDigest]
                when (occurrence.disposition) {
                    "declared-external" -> if (finalStage.selections.none { it.occurrenceId == occurrence.id && it.providerId == occurrence.providerId })
                        finding("final-external-obligation-not-discharged", stage = finalStage.id, occurrence = occurrence.id)
                    "declared-weak-null" -> {
                        if (req?.binding !in setOf("weak", "2")) finding("strong-import-cannot-resolve-null", stage = finalStage.id, occurrence = occurrence.id)
                        if (hasGeneratedTableObligations) finding("weak-null-may-hide-required-generated-table", stage = finalStage.id, occurrence = occurrence.id)
                    }
                    "in-scope-owner" -> {
                        val selection = finalStage.selections.firstOrNull { it.occurrenceId == occurrence.id }
                        val exactOwner = req != null && selection != null && selection.providerId == null && selection.exportSymbolKey == req.raw["symbolKey"] &&
                            selection.exportName == req.name && selection.exportVersion == req.version && selection.evidenceRefs.isNotEmpty()
                        if (!exactOwner) finding("final-in-scope-obligation-not-discharged", stage = finalStage.id, occurrence = occurrence.id)
                    }
                    "declared-alias" -> if (finalStage.selections.none { it.occurrenceId == occurrence.id && it.aliasTargetId != null })
                        finding("final-alias-obligation-not-discharged", stage = finalStage.id, occurrence = occurrence.id)
                    "discarded-with-link-proof" -> if (finalStage.selections.none { it.occurrenceId == occurrence.id })
                        finding("discarded-occurrence-lacks-link-proof", stage = finalStage.id, occurrence = occurrence.id)
                    else -> Unit
                }
            }
        }
        detectAliasCycles(stageRecords, budget, ::finding)
        val observedBySymbol = stageRecords.flatMap { it.before + it.after }.groupBy { budget.checkpoint("occurrence index"); it.symbolKeyDigest }
        requirementRecords.forEach { requirement ->
            val observed = observedBySymbol[requirement.symbolKeyDigest].orEmpty()
            budget.checkpoint("requirement occurrence join", observed.size.toLong())
            if (observed.isEmpty()) finding("expected-symbol-requirement-unobserved", occurrence = requirement.id)
            val expectedReferences = requirement.references.toSet()
            val observedReferences = observed.map { it.referenceDigest }.toSet()
            (expectedReferences - observedReferences).forEach { finding("expected-reference-unobserved", occurrence = requirement.id) }
            (observedReferences - expectedReferences).forEach { finding("unexpected-reference-observation", occurrence = requirement.id) }
        }
        if (stageIds.size != stageIds.toSet().size) finding("duplicate-stage-id")
        expectedStages.filter { it !in stageIds }.forEach { finding("missing-expected-stage", stage = it) }
        stageIds.filter { it !in expectedStages }.forEach { finding("unexpected-stage", stage = it) }
        val universe = input["universe"] as? JsonObject ?: error("universe must be object")
        val universeKeys = setOf("expectedEntities", "expectedReferences", "ownerModuleIds", "stageIds", "provenanceLimitations", "requiredGeneratedTables")
        require(universe.keys == universeKeys) { "universe keys differ from v1 schema" }
        val expectedEntities = arr(universe, "expectedEntities", limits.maximumRequirements).map { item ->
            val key = item as? JsonObject ?: error("expected entity must be symbol key"); validateSymbolKey(key)
            sha(OracleJson.canonicalBytes(key, budget.jsonLimits(), { budget.checkpoint(it) }))
        }
        unique(expectedEntities, "expected entity symbol key")
        val actualEntities = requirementRecords.map { it.symbolKeyDigest }
        compareSet(expectedEntities, actualEntities, "expected-entity", ::finding)
        val expectedReferenceRows = arr(universe, "expectedReferences", limits.maximumReferencesAndEvents)
        budget.retain(0, expectedReferenceRows.size.toLong(), "expected physical references")
        val expectedReferences = expectedReferenceRows.map { item ->
            val ref=item as? JsonObject ?: error("expected reference must be object"); validateReference(ref); referenceDigest(ref, budget)
        }
        unique(expectedReferences, "expected physical reference")
        val policyReferences = requirementRecords.flatMap { it.references }
        compareSet(expectedReferences, policyReferences, "expected-reference-policy", ::finding)
        val ownerModules = strings(universe, "ownerModuleIds", limits.maximumRequirements)
        unique(ownerModules, "expected owner module")
        requirementRecords.forEach { requirement -> if (requirement.ownerModuleId != null && requirement.ownerModuleId !in ownerModules) finding("requirement-owner-outside-universe", occurrence = requirement.id) }
        val universeStages = strings(universe, "stageIds", limits.maximumStages).onEach { require(hex.matches(it)) }
        unique(universeStages, "universe expected stage ID")
        if (universeStages != expectedStages) finding("universe-policy-stage-population-mismatch")
        val provenance = arr(universe, "provenanceLimitations", limits.maximumFindings)
        unique(provenance.map { it.jsonPrimitive.content }, "provenance limitation")
        provenance.forEach { item ->
            require(item is JsonPrimitive && item.isString)
            finding("universe-provenance-limitation", "qualification", occurrence = item.jsonPrimitive.content)
        }
        finding("authenticated-live-owner-universe-unavailable", "qualification")
        val generatedTables = arr(universe, "requiredGeneratedTables", limits.maximumRequirements)
        val generatedTableIds = mutableListOf<String>()
        generatedTables.forEach { table ->
            val row=table as? JsonObject ?: error("generated table obligation must be object")
            require(row.keys == setOf("id", "disposition", "sourceSha256", "generatorActionId", "inputSha256", "outputSha256"))
            val tableId = str(row,"id"); generatedTableIds += tableId
            val disposition=str(row,"disposition"); require(disposition in setOf("reproduced", "checked-data"))
            listOf("sourceSha256", "inputSha256", "outputSha256").forEach { digest(row,it) }
            val actionId = nullableString(row,"generatorActionId")
            if (disposition == "reproduced") require(actionId != null) { "reproduced generated table requires an exact generator action ID" }
            if (disposition == "checked-data") require(actionId == null) { "checked-data table cannot claim a reproduced generator action" }
            if (stageRecords.none { stage -> stage.outputs.any { it.first == "generated-table" && it.second == str(row,"outputSha256") } })
                finding("required-generated-table-output-absent", occurrence = tableId)
            finding("generated-table-provenance-not-authenticated", "qualification", occurrence = tableId)
        }
        unique(generatedTableIds, "generated table ID")
        derivedApplicability.forEach { row ->
            require(findings.size < limits.maximumFindings) { "finding limit exceeded" }
            val recordId = str(row,"recordId")
            findings += ExternalBoundaryFindingV1("not-applicable:${str(row,"field")}", "qualification", occurrenceId = recordId,
                evidenceRefs = listOf(str(row,"fixedReason")))
        }
        val elfEvidence = arr(input, "elfEvidence", limits.maximumStages)
        val rawMeasurements = arr(input, "rawMeasurements", limits.maximumStages)
        val closures = arr(input, "recordedClosures", limits.maximumStages)
        val diagnosticEvidenceEntries = mutableListOf<JsonObject>()
        elfEvidence.forEach { item ->
            val elfStage = validateElfProjection(item, budget, ::finding)
            diagnosticEvidenceEntries += buildJsonObject { put("recordKind", "recorded-elf-evidence"); put("id", str(elfStage, "outputSha256")); put("record", item) }
            val outputIdentity = str(elfStage,"outputRole") to str(elfStage,"outputSha256")
            val match = stageRecords.firstOrNull { stage ->
                stage.buildRunId == str(elfStage,"buildRunId") && stage.graphActionId == str(elfStage,"graphActionId") && stage.ordinal.toLong() == nonNegative(elfStage,"ordinal") &&
                    stage.sourceRevisionSha256 == str(elfStage,"sourceRevisionSha256") && stage.planSha256 == str(elfStage,"planSha256") &&
                    stage.policySha256 == str(elfStage,"policySha256") && Triple(outputIdentity.first, outputIdentity.second, nonNegative(elfStage,"outputBytes")) in stage.outputs
            }
            if (match == null) finding("recorded-ELF-evidence-not-bound-to-link-stage", occurrence = str(elfStage,"outputSha256"))
        }
        rawMeasurements.forEach { item ->
            val bytes = OracleJson.canonicalBytes(item, budget.jsonLimits(), { budget.checkpoint(it) })
            val projection = FullTreeExternalProviderEvidenceV1.fromRawMeasurement(bytes, budget)
            diagnosticEvidenceEntries += buildJsonObject { put("recordKind", "recorded-runtime-candidates"); put("id", projection.sourceSha256); put("record", projection.toJson(budget)) }
            finding("runtime-measurement-does-not-prove-provider-binding", "qualification", occurrence = projection.sourceSha256)
            if (projection.ambiguousCandidateCount > 0) finding("ambiguous-runtime-provider-candidates", "qualification", occurrence = projection.sourceSha256)
            val namespaceDigest = projection.mergedNamespaceSha256
            val subjectPath = projection.staticGraph["subjectRequestedPath"]!!.jsonPrimitive.content
            val inspect = projection.readOnlyRuntime["inspect"]!!.jsonObject
            val observedArchitecture = inspect["Architecture"]?.jsonPrimitive?.content
            for (node in projection.nodes) {
                budget.checkpoint("raw runtime node to provider candidate join")
                val nodePath = str(node, "resolvedPath")
                if (nodePath == subjectPath) continue
                val exact = providers.filter { providerValue ->
                    budget.checkpoint("runtime candidate-provider comparison")
                    val provider = providerValue.jsonObject
                    provider["namespaceSha256"] == JsonPrimitive(namespaceDigest) &&
                        provider["resolvedPath"] == node["resolvedPath"] && provider["bytes"] == node["bytes"] &&
                        provider["sha256"] == node["sha256"] && provider["soname"] == node["soname"]
                }
                if (exact.size != 1) finding("runtime-node-provider-candidate-not-exactly-unique", "consistency", occurrence = nodePath)
                else {
                    val target = exact.single().jsonObject["target"]!!.jsonObject
                    val targetArch = when (target["machine"]!!.jsonPrimitive.long) { 62L -> "amd64"; 183L -> "arm64"; else -> "unsupported" }
                    if (observedArchitecture != targetArch) finding("runtime-node-provider-target-architecture-mismatch", "consistency", occurrence = nodePath)
                    // The raw node has no ELF class/OS ABI/ABI-flags fields, so the full target key cannot be established.
                    finding("runtime-node-full-provider-target-binding-unavailable", "qualification", occurrence = nodePath)
                }
            }
            for (edge in projection.edges) for (candidate in edge["candidates"]!!.jsonArray) {
                budget.checkpoint("raw runtime search candidate path join")
                val candidateRow = candidate.jsonObject
                val matches = projection.nodes.filter { node ->
                    budget.checkpoint("runtime search-node comparison")
                    node["resolvedPath"] == candidateRow["resolvedPath"] && node["inode"] == candidateRow["inode"] && node["sha256"] == candidateRow["sha256"]
                }
                if (matches.size != 1) finding("runtime-search-candidate-not-bound-to-unique-static-node", "consistency", occurrence = str(candidateRow, "resolvedPath"))
            }
        }
        closures.forEach { item ->
            val bytes = OracleJson.canonicalBytes(item, budget.jsonLimits(), { budget.checkpoint(it) })
            val projection = FullTreeExternalProviderEvidenceV1.fromRecordedClosure(bytes, budget)
            diagnosticEvidenceEntries += buildJsonObject { put("recordKind", "recorded-runtime-closure"); put("id", projection.sourceSha256); put("record", projection.toJson(budget)) }
            finding("runtime-closure-executable-binding-absent", "qualification", occurrence = projection.sourceSha256)
        }

        // A recorded policy is executable for runtime interface declarations; observations remain non-authoritative.
        val runtimePolicyJson = policy["runtimePolicy"] as? JsonObject ?: error("runtimePolicy must be object")
        val runtimePolicyBytes = OracleJson.canonicalBytes(runtimePolicyJson, budget.jsonLimits(), { budget.checkpoint(it) })
        val runtime = FullTreeRuntimeInterfacePolicyV1.decode(runtimePolicyBytes, budget)
        val runtimeObserved = input["runtimeInterfaces"] as? JsonObject ?: error("runtimeInterfaces must be object")
        val runtimeObservedBytes = OracleJson.canonicalBytes(runtimeObserved, budget.jsonLimits(), { budget.checkpoint(it) })
        val observed = FullTreeRuntimeInterfacePolicyV1.decodeObserved(runtimeObservedBytes, budget)
        observed.trace?.let { trace ->
            if(stageRecords.none { it.buildRunId == str(trace,"buildRunId") && it.graphActionId == str(trace,"graphActionId") }) finding("runtime-trace-run-action-binding-mismatch")
        }
        FullTreeRuntimeInterfacePolicyV1.detect(runtime, observed, budget).forEach { eventFinding ->
            require(findings.size < limits.maximumFindings) { "finding limit exceeded" }
            findings += eventFinding
        }

        // This first pure slice has no authenticated expected universe or contained link producer.
        // Keep these qualification gaps explicit; never turn fixture consistency into acceptance.
        finding("provider-and-tool-provenance-not-authenticated", "qualification")
        finding("per-link-stage-undefined-census-not-authenticated", "qualification")
        if (providers.isEmpty()) finding("empty-provider-policy", "consistency")
        if (tools.isEmpty()) finding("empty-tool-policy", "consistency")
        if (requirements.isEmpty()) finding("empty-requirement-population", "qualification")
        if (findings.size > limits.maximumFindings) error("finding ceiling exceeded")
        val consistent = findings.none { it.category == "consistency" }
        val inputDigest = sha(OracleJson.canonicalBytes(normalizeInputForDigest(input, budget), budget.jsonLimits(), { budget.checkpoint(it) }))
        val policyArtifactDigest = sha(OracleJson.canonicalBytes(normalizePolicyForDigest(policy, budget), budget.jsonLimits(), { budget.checkpoint(it) }))
        val stableFindings = findings.sortedWith(compareByJsonKey(budget) { f -> listOf(f.category, f.code, f.stageId.orEmpty(), f.occurrenceId.orEmpty(), f.evidenceRefs.joinToString("\u0000")).joinToString("\u0001") })
        val rowsMutable=mutableListOf<JsonObject>()
        stableFindings.forEach { f ->
            val row=buildJsonObject {
                put("code", f.code); put("category", f.category)
                put("stageId", f.stageId?.let(::JsonPrimitive) ?: JsonNull)
                put("occurrenceId", f.occurrenceId?.let(::JsonPrimitive) ?: JsonNull)
                put("evidenceRefs", JsonArray(f.evidenceRefs.map(::JsonPrimitive)))
            }
            val measure=BoundaryTreeV1(budget,false); measure.json(null,row)
            budget.retain(measure.bytes,stage="assessment finding row precharge")
            rowsMutable += row
        }
        val rows=Collections.unmodifiableList(rowsMutable)
        val entriesMutable=mutableListOf<JsonObject>()
        fun retainEntry(row: JsonObject) {
            val measure=BoundaryTreeV1(budget,false); measure.json(null,row)
            budget.retain(measure.bytes,stage="assessment ledger row precharge")
            entriesMutable += row
        }
        providers.forEach { item -> val r=item.jsonObject; retainEntry(buildJsonObject { put("recordKind","provider"); put("id",r["id"]!!); put("record",r) }) }
        tools.forEach { item -> val r=item.jsonObject; retainEntry(buildJsonObject { put("recordKind","tool"); put("id",r["id"]!!); put("record",r) }) }
        requirementRecords.forEach { r -> retainEntry(buildJsonObject { put("recordKind","expected-requirement"); put("id",r.id); put("record",r.raw) }) }
        stageRecords.forEach { s -> retainEntry(buildJsonObject { put("recordKind","link-stage"); put("id",s.id); put("recordSha256",s.recordDigest); put("record",s.raw) }) }
        stageRecords.forEach { stage -> (stage.before + stage.after).forEach { occurrence ->
            val row=buildJsonObject {
                put("recordKind","symbol-reference-occurrence")
                put("id",occurrence.id)
                put("stageId", stage.id); put("stageRecordSha256", stage.recordDigest); put("occurrenceId", occurrence.id)
                put("side", occurrence.side)
                put("symbolKey", occurrence.symbolKey); put("reference", occurrence.reference)
                put("requirementId", occurrence.requirementId?.let(::JsonPrimitive) ?: JsonNull)
                put("ownerModuleId", occurrence.ownerModuleId?.let(::JsonPrimitive) ?: JsonNull)
                put("providerId", occurrence.providerId?.let(::JsonPrimitive) ?: JsonNull)
                put("disposition", occurrence.disposition)
                put("evidenceRefs", JsonArray(occurrence.evidenceRefs.map(::JsonPrimitive)))
            }
            retainEntry(row)
        } }
        diagnosticEvidenceEntries.forEach(::retainEntry)
        val entries=Collections.unmodifiableList(entriesMutable.sortedWith(MeteredComparator(budget) { a,b ->
            val logical=compareByJsonKey(budget) { row: JsonObject -> row["recordKind"]!!.jsonPrimitive.content+":"+row["id"]!!.jsonPrimitive.content }.compare(a,b)
            if(logical != 0) logical else compareCanonicalJson(a,b,budget)
        }))
        budget.reserveOutputHeadroom(4096,"assessment envelope precharge")
        val result = buildJsonObject {
            put("schemaVersion", 1); put("kind", "external-provider-assessment-v1")
            put("authority", "diagnostic-recorded-inputs-only")
            put("bindings", inputBindings)
            put("inputDigests", buildJsonObject { put("policy", policyArtifactDigest); put("inputs", inputDigest) })
            put("policyDigest", policyDigest)
            put("populations", buildJsonObject {
                put("providers", providers.size); put("tools", tools.size); put("requirements", requirements.size)
                put("expectedStages", expectedStages.size); put("observedStages", stages.size)
            })
            put("entries", JsonArray(entries))
            put("findings", JsonArray(rows)); put("recordedInputsConsistent", consistent)
            put("complete", false); put("oracleAuthority", false); put("runtimeProfileApproved", false)
            put("startAuthorized", false); put("containmentProved", false); put("scoringAuthority", false)
            put("releaseEligible", false); put("reportSha256", "")
        }
        val withoutHash = OracleJson.canonicalBytes(JsonObject(result - "reportSha256"), budget.jsonLimits(), { budget.checkpoint(it) })
        val resultDigest = sha(withoutHash, budget)
        val final = JsonObject(result + ("reportSha256" to JsonPrimitive(resultDigest)))
        val bytes = OracleJson.canonicalBytes(final, budget.jsonLimits(), { budget.checkpoint(it) })
        require(bytes.size <= limits.maximumDocumentBytes) { "assessment output ceiling exceeded" }
        val assessmentDigest = sha(bytes, budget)
        budget.checkpoint("before assessment result snapshot", bytes.size.toLong())
        val retainedCanonical = bytes.copyOf()
        val retainedFindings = Collections.unmodifiableList(stableFindings.toList())
        val assessment = ExternalProviderAssessmentV1(retainedCanonical, retainedFindings, consistent, assessmentDigest, budget)
        budget.checkpoint("terminal external boundary assessment publication")
        return assessment
    }

    private fun arr(o: JsonObject, key: String, ceiling: Int): JsonArray = (o[key] as? JsonArray ?: error("$key must be array")).also {
        require(it.size <= ceiling) { "$key population exceeds ceiling" }
    }
    private fun strings(o: JsonObject, key: String, ceiling: Int): List<String> = stringArray(o, key, ceiling)

    private data class RequirementRecord(val id: String, val raw: JsonObject, val symbolKeyDigest: String, val ownerModuleId: String?, val ownerEntityId: String?, val disposition: String, val references: List<String>, val binding: String, val name: String, val version: JsonObject, val abi: JsonObject)
    private data class StageRecord(val id: String, val raw: JsonObject, val buildRunId: String, val graphActionId: String, val ordinal: Int, val sourceRevisionSha256: String, val planSha256: String, val policySha256: String, val toolIds: List<String>, val parentStageIds: List<String>, val outputs: Set<Triple<String,String,Long>>, val before: List<OccurrenceRecord>, val after: List<OccurrenceRecord>, val selections: List<SelectionRecord>, val violations: List<String>, val recordDigest: String)
    private data class OccurrenceRecord(
        val id: String, val symbolKeyDigest: String, val symbolKey: JsonObject, val reference: JsonObject,
        val requirementId: String?, val ownerModuleId: String?, val providerId: String?, val disposition: String,
        val evidenceRefs: List<String>, val aliasTargetId: String?, val side: String, val referenceDigest: String,
    )
    private data class SelectionRecord(val occurrenceId: String, val providerId: String?, val aliasTargetId: String?, val exportSymbolKey: JsonObject?, val exportName: String?, val exportVersion: JsonObject?, val evidenceRefs: List<String>, val absenceProof: JsonObject?, val exportPopulation: JsonObject?, val discardProof: JsonElement?)

    private val hex = Regex("[0-9a-f]{64}")
    private val dispositions = setOf("in-scope-owner", "declared-external", "declared-weak-null", "declared-alias", "discarded-with-link-proof", "unexplained", "unsupported")
    private val providerKeys = setOf("id", "role", "sourceLockSha256", "sourceReleaseSha256", "runtimeProfileId", "runtimeProfileSha256", "namespaceSha256", "path", "resolvedPath", "soname", "bytes", "sha256", "target", "abi", "exportsSha256")
    private val toolKeys = setOf("id", "role", "path", "resolvedPath", "bytes", "sha256", "versionOutputSha256", "versionText", "target", "resourceDirSha256", "sysrootSha256", "runtimeProfileSha256")
    private val targetKeys = setOf("triple", "elfClass", "byteOrder", "machine", "osAbi", "abiFlags")
    private val abiKeys = setOf("family", "version", "cxxLibraryAbi", "unwinderAbi")
    private val symbolKeyKeys = setOf("artifactRole", "artifactSha256", "tableSectionIndex", "symbolIndex", "rawLocator")
    private val versionKeys = setOf("rawIndex", "index", "hidden", "name", "providerRequest", "defaultDefinition")
    private val referenceKeys = setOf("artifactRole", "artifactSha256", "member", "tableSectionIndex", "symbolIndex", "rawLocator", "relocationSectionIndex", "relocationIndex", "offset", "type", "addend", "ownerModuleId", "ownerEntityId", "abiSourceId")
    private val requirementKeys = setOf("id", "symbolKey", "name", "type", "binding", "visibility", "version", "abi", "ownerModuleId", "ownerEntityId", "references", "disposition")
    private val referenceOccurrenceKeys = setOf("id", "symbolKey", "reference", "requirementId", "ownerModuleId", "providerId", "disposition", "evidenceRefs", "aliasTargetId")
    private val stageKeys = setOf("id", "buildRunId", "ordinal", "kind", "graphActionId", "parentStageIds", "sourceRevisionSha256", "planSha256", "policySha256", "toolIds", "argv", "environment", "cwd", "inputOccurrences", "outputIdentities", "undefinedBefore", "undefinedAfter", "selections", "linkMapSha256", "traceSha256", "exitCode", "blockers")
    private val stageIdentityExcluded = setOf("id", "outputIdentities", "undefinedBefore", "undefinedAfter", "selections", "linkMapSha256", "traceSha256", "exitCode", "blockers")
    private val providerRoles = setOf("loader", "c-runtime", "cxx-runtime", "cxx-abi-support", "unwinder", "compiler-builtins", "crt", "system-library", "system-archive", "static-archive", "external-plugin")
    private val occurrenceArtifactRoles = setOf("source", "generated-source", "object", "archive", "bitcode", "response-file", "linker-script", "shared-library", "relocatable", "executable", "generated-table", "tool", "runtime")

    private fun validateRecords(values: JsonArray, kind: String, validator: (JsonObject, MutableList<JsonObject>, ExternalBoundaryBudgetV1) -> String, derived: MutableList<JsonObject>, budget: ExternalBoundaryBudgetV1): Set<String> {
        val ids = values.map { item ->
            budget.checkpoint("$kind identity validation")
            val record = item as? JsonObject ?: error("$kind record must be object")
            validator(record, derived, budget)
        }
        unique(ids, "$kind ID")
        return ids.toSet()
    }

    private val bindingNames = setOf("sourceLock", "artifactManifest", "scope", "planning", "ownerUniverse", "sourceRevision", "graph", "runtimeProfile", "detectorPolicy")
    private fun validateBindings(bindings: JsonObject, budget: ExternalBoundaryBudgetV1, finding: (String, String, String?, String?) -> Unit): JsonObject {
        require(bindings.keys == bindingNames) { "binding population differs from v1 schema" }
        return JsonObject(bindings.mapValues { (name, value) ->
            budget.checkpoint("binding evidence reference normalization")
            val row=value as? JsonObject ?: error("binding $name must be an object")
            require(row.keys == setOf("sha256", "disposition", "evidenceRefs"))
            val disposition=str(row,"disposition"); require(disposition in setOf("available", "unavailable"))
            val hash=row["sha256"]
            val refs=stringArray(row,"evidenceRefs",128)
            if (disposition == "available") {
                require(hash != JsonNull); require(hex.matches(str(row,"sha256"))); require(refs.isNotEmpty())
            } else {
                require(hash == JsonNull && refs.isNotEmpty())
                finding("unavailable-binding:$name", "qualification", null, null)
            }
            JsonObject(row + ("evidenceRefs" to JsonArray(refs.sortedWith(compareByJsonKey(budget) { it }).map(::JsonPrimitive))))
        })
    }

    private fun compareSet(expected: List<String>, actual: List<String>, code: String, finding: (String, String, String?, String?) -> Unit) {
        if (expected.toSet().size != expected.size) finding("duplicate-$code", "consistency", null, null)
        if (actual.toSet().size != actual.size) finding("duplicate-observed-$code", "consistency", null, null)
        (expected.toSet() - actual.toSet()).forEach { finding("missing-$code", "consistency", null, it) }
        (actual.toSet() - expected.toSet()).forEach { finding("unexpected-$code", "consistency", null, it) }
    }

    private fun validateElfProjection(value: JsonElement, budget: ExternalBoundaryBudgetV1, finding: (String, String, String?, String?) -> Unit): JsonObject {
        budget.checkpoint("recorded ELF evidence projection validation")
        val r=value as? JsonObject ?: error("ELF evidence projection must be object")
        require(r.keys == setOf("schemaKind", "sourceSha256", "stage", "inventorySha256", "symbolCount", "relocationCount", "symbols", "references", "neededLibraries", "unsupportedReasons", "inventory", "limitations"))
        require(str(r,"schemaKind") == "independent-elf-dynamic-bindings-v1")
        digest(r,"sourceSha256"); require(digest(r,"inventorySha256") == str(r,"sourceSha256"))
        val stage=r["stage"]!!.jsonObject
        require(stage.keys == setOf("buildRunId", "graphActionId", "ordinal", "sourceRevisionSha256", "planSha256", "policySha256", "outputRole", "outputBytes", "outputSha256"))
        for (k in listOf("buildRunId","graphActionId","outputRole")) str(stage,k)
        for (k in listOf("sourceRevisionSha256","planSha256","policySha256","outputSha256")) digest(stage,k)
        nonNegative(stage,"ordinal"); nonNegative(stage,"outputBytes")
        val inv=r["inventory"]!!.jsonObject
        val inventoryKeys = setOf("schemaVersion", "kind", "authority", "inputSha256", "elfClass", "byteOrder", "elfType", "machine", "imageBase", "activeSymbolTableSectionIndex", "symbolPopulationBasis", "complete", "releaseEligible", "negativeCompleteness", "sections", "programHeaders", "dynamicEntries", "dynamicSymbols", "relocations", "versionRequirements", "versionDefinitions", "neededLibraries", "unsupportedReasons")
        require(inv.keys == inventoryKeys && inv["schemaVersion"] == JsonPrimitive(1))
        require(inv["kind"] == JsonPrimitive("independent-elf-dynamic-bindings-v1") && inv["authority"] == JsonPrimitive("diagnostic-authenticated-elf-metadata") && inv["inputSha256"] == stage["outputSha256"])
        val inventoryCanonical = OracleJson.canonicalBytes(inv, budget.jsonLimits(), { budget.checkpoint(it) })
        require(sha(inventoryCanonical, budget) == str(r, "sourceSha256") && str(r, "inventorySha256") == str(r, "sourceSha256"))
        require(inv["complete"] == JsonPrimitive(false) && inv["releaseEligible"] == JsonPrimitive(false) && inv["negativeCompleteness"] == JsonPrimitive(false))
        if (!validInventorySchema(inv, budget)) {
            finding("ELF-inventory-nested-schema-mismatch", "consistency", null, str(stage,"outputSha256"))
            return stage
        }
        val inventorySymbols=inv["dynamicSymbols"]!!.jsonArray; val inventoryReferences=inv["relocations"]!!.jsonArray
        val symbols=arr(r,"symbols",budget.limits.maximumReferencesAndEvents)
        val references=arr(r,"references",budget.limits.maximumReferencesAndEvents)
        require(r["symbolCount"] == JsonPrimitive(inventorySymbols.size) && symbols.size == inventorySymbols.size)
        require(r["relocationCount"] == JsonPrimitive(inventoryReferences.size) && references.size == inventoryReferences.size)
        budget.retain(0, symbols.size.toLong() + references.size, "ELF projection row population")
        val symbolDigests=mutableSetOf<String>()
        symbols.forEachIndexed { i, item ->
            val projected=item.jsonObject; val raw=inventorySymbols[i].jsonObject
            require(projected.keys == setOf("artifactRole", "artifactSha256", "tableSectionIndex", "symbolIndex", "rawLocator", "name", "type", "binding", "visibility", "version", "sectionKind"))
            require(str(projected,"artifactRole") == str(stage,"outputRole") && str(projected,"artifactSha256") == str(stage,"outputSha256"))
            for ((dest,src) in listOf("tableSectionIndex" to "tableSectionIndex", "symbolIndex" to "symbolIndex", "rawLocator" to "locator", "name" to "name", "type" to "type", "binding" to "binding", "visibility" to "visibility", "version" to "version", "sectionKind" to "sectionKind")) require(projected[dest] == raw[src])
            val id=sha(OracleJson.canonicalBytes(buildJsonObject { put("artifactRole",projected["artifactRole"]!!); put("artifactSha256",projected["artifactSha256"]!!); put("tableSectionIndex",projected["tableSectionIndex"]!!); put("symbolIndex",projected["symbolIndex"]!!); put("rawLocator",projected["rawLocator"]!!) }))
            require(symbolDigests.add(id)) { "duplicate projected ELF symbol key" }
        }
        val rawBySymbol = inventorySymbols.associate { raw -> budget.checkpoint("ELF raw physical symbol index"); raw.jsonObject.let { (it["tableSectionIndex"] to it["symbolIndex"]) to it } }
        require(rawBySymbol.size == inventorySymbols.size)
        val relocationKeys = mutableSetOf<Pair<JsonElement?,JsonElement?>>()
        references.forEachIndexed { i,item ->
            val ref=item.jsonObject; val raw=inventoryReferences[i].jsonObject
            validateReference(ref)
            budget.checkpoint("ELF relocation-symbol locator join")
            require(relocationKeys.add(raw["sectionIndex"] to raw["relocationIndex"]))
            val symbol = rawBySymbol[raw["symbolTableSectionIndex"] to raw["symbolIndex"]]
            if (symbol == null || ref["tableSectionIndex"] != symbol["tableSectionIndex"] || ref["symbolIndex"] != symbol["symbolIndex"] || ref["rawLocator"] != symbol["locator"])
                finding("ELF-reference-raw-symbol-locator-mismatch", "consistency", null, str(ref,"rawLocator"))
            require(str(ref,"artifactRole") == str(stage,"outputRole") && str(ref,"artifactSha256") == str(stage,"outputSha256"))
            require(ref["relocationSectionIndex"] == raw["sectionIndex"] && ref["relocationIndex"] == raw["relocationIndex"] && ref["offset"] == raw["offset"] && ref["type"] == raw["type"] && ref["addend"] == raw["addend"])
            finding("ELF-owner-lineage-unavailable", "qualification", null, str(ref,"rawLocator"))
        }
        require(stringArray(r,"neededLibraries",4096) == stringArray(inv,"neededLibraries",4096))
        require(stringArray(r,"unsupportedReasons",4096) == stringArray(inv,"unsupportedReasons",4096))
        require(r["limitations"] == JsonArray(listOf(
            JsonPrimitive("section-declared DYNSYM is not a complete full-tree symbol universe"),
            JsonPrimitive("ELF inventory does not authenticate a link stage or runtime provider"),
        )))
        if (inv["unsupportedReasons"]!!.jsonArray.isNotEmpty()) finding("ELF-observation-has-unsupported-reasons", "qualification", null, str(stage,"outputSha256"))
        return stage
    }


    private fun validInventorySchema(inv: JsonObject, budget: ExternalBoundaryBudgetV1): Boolean {
        require(str(inv,"imageBase").matches(Regex("0x[0-9a-f]{1,16}")))
        require(nonNegative(inv,"activeSymbolTableSectionIndex") <= Int.MAX_VALUE)
        val schemas = mapOf(
            "sections" to "index name type flags address offset size link info alignment entrySize",
            "programHeaders" to "index type flags offset virtualAddress physicalAddress fileSize memorySize alignment",
            "dynamicEntries" to "index fileOffset tag value",
            "dynamicSymbols" to "tableSectionIndex symbolIndex locator nameOffset name info other type binding visibility rawSectionIndex resolvedSectionIndex sectionKind value size version",
            "relocations" to "sectionIndex relocationIndex fileOffset locator symbolTableSectionIndex symbolIndex offset type addend dynamicTables slotFileOffset slotLoadIndices dispositions",
            "versionRequirements" to "sectionIndex stringSectionIndex recordOffset auxiliaryOffset providerRequest providerRequestOffset name nameOffset rawIndex index flags hash",
            "versionDefinitions" to "sectionIndex stringSectionIndex recordOffset rawIndex index flags hash name parentNames auxiliaryOffsets auxiliaryNameOffsets",
        )
        val hexFields = setOf("flags", "address", "size", "alignment", "entrySize", "offset", "virtualAddress", "physicalAddress", "fileSize", "memorySize", "tag", "value")
        val stringFields = setOf("name", "locator", "providerRequest", "sectionKind")
        for ((kind, fields) in schemas) {
            val rows = inv[kind] as? JsonArray ?: return false
            budget.retain(0,rows.size.toLong(),"raw ELF nested schema populations")
            val identities=mutableSetOf<List<JsonElement?>>()
            for (element in rows) {
                budget.checkpoint("raw ELF nested schema validation")
                val row=element as? JsonObject ?: return false
                if(row.keys != fields.split(' ').toSet()) return false
                val identityFields=when(kind) {
                    "sections","programHeaders","dynamicEntries" -> listOf("index")
                    "dynamicSymbols" -> listOf("tableSectionIndex","symbolIndex")
                    "relocations" -> listOf("sectionIndex","relocationIndex")
                    "versionRequirements" -> listOf("sectionIndex","recordOffset","auxiliaryOffset")
                    else -> listOf("sectionIndex","recordOffset")
                }
                if(!identities.add(identityFields.map { row[it] })) return false
                for ((key,value) in row) {
                    if(key == "version") {
                        if(value != JsonNull) {
                            val v=value as? JsonObject ?: return false
                            if(v.keys != setOf("sectionIndex","fileOffset","raw","index","hidden","kind","name","providerRequest")) return false
                            nonNegative(v,"sectionIndex"); nonNegative(v,"fileOffset")
                            val raw=nonNegative(v,"raw"); val index=nonNegative(v,"index")
                            if(raw > 65535 || index != raw and 32767 || bool(v,"hidden") != (raw and 32768 != 0L)) return false
                            if(str(v,"kind") !in setOf("local", "global-unversioned", "required-version", "defined-version")) return false
                            nullableString(v,"name"); nullableString(v,"providerRequest")
                        }
                    } else if(key in setOf("dynamicTables","dispositions","parentNames")) stringArray(row,key,65536)
                    else if(key in setOf("slotLoadIndices","auxiliaryOffsets","auxiliaryNameOffsets")) {
                        val a=value as? JsonArray ?: return false
                        budget.retain(0,a.size.toLong(),"raw ELF nested numeric population")
                        if(a.any { it !is JsonPrimitive || it.isString || it.longOrNull == null || it.long < 0 }) return false
                    } else if(key in stringFields) boundedString(row,key,allowEmpty=key=="name")
                    else if(key in hexFields && !(kind=="sections" && key=="offset") && !(kind=="programHeaders" && key=="flags") && !(kind.startsWith("version") && key=="flags")) {
                        if(!str(row,key).matches(Regex("0x[0-9a-f]{1,16}"))) return false
                    } else if(value == JsonNull && key in setOf("addend","slotFileOffset")) Unit
                    else if(key=="addend") intLong(row,key)
                    else nonNegative(row,key)
                }
                if(kind=="dynamicSymbols") {
                    val info=nonNegative(row,"info"); val other=nonNegative(row,"other")
                    if(info>255 || other>255 || nonNegative(row,"type") != info and 15 || nonNegative(row,"binding") != info shr 4 || nonNegative(row,"visibility") != other and 3) return false
                    if(str(row,"sectionKind") !in setOf("undefined","defined","absolute","common","reserved")) return false
                }
            }
        }
        return inv["elfClass"] == JsonPrimitive(2) && inv["byteOrder"] == JsonPrimitive(1) && inv["machine"] == JsonPrimitive(62) &&
            inv["elfType"] in setOf(JsonPrimitive("ET_DYN"),JsonPrimitive("ET_EXEC")) && inv["symbolPopulationBasis"] == JsonPrimitive("section-declared-dynsym")
    }

    private fun validateProvider(record: JsonObject, derived: MutableList<JsonObject>, budget: ExternalBoundaryBudgetV1): String {
        require(record.keys == providerKeys) { "provider identity keys differ from v1 schema" }
        val role = str(record, "role")
        require(role in providerRoles) { "unsupported provider role" }
        digest(record, "sourceLockSha256"); digest(record, "sourceReleaseSha256"); str(record, "runtimeProfileId")
        digest(record, "runtimeProfileSha256"); digest(record, "namespaceSha256"); path(record, "path"); path(record, "resolvedPath")
        positive(record, "bytes"); digest(record, "sha256"); digest(record, "exportsSha256")
        val target = record["target"] as? JsonObject ?: error("provider target missing")
        validateTarget(target)
        validateAbi(record["abi"] as? JsonObject ?: error("provider ABI missing"), role, target, derived, "provider", record)
        val soname = record["soname"]
        if (soname == JsonNull) {
            require(role in setOf("static-archive", "system-archive")) { "null SONAME is applicable only to an archive provider role" }
            require(supportedNullAbiTarget(target)) { "archive target does not support the fixed SONAME-null applicability rule" }
            derived += applicability("provider", record, "soname", "role=$role denotes an archive without ELF DT_SONAME")
        } else { require(role !in setOf("static-archive", "system-archive")) { "archive provider cannot claim an ELF SONAME" }; str(record, "soname") }
        val expected = id("provider", JsonObject(record - "id"), budget)
        require(str(record, "id") == expected) { "provider ID does not match canonical identity" }
        return expected
    }

    private fun validateTool(record: JsonObject, derived: MutableList<JsonObject>, budget: ExternalBoundaryBudgetV1): String {
        require(record.keys == toolKeys) { "tool identity keys differ from v1 schema" }
        val role = str(record, "role")
        require(role in setOf("compiler", "assembler", "linker", "build-generator", "generation-tool")) { "unsupported tool role" }
        path(record, "path"); path(record, "resolvedPath"); positive(record, "bytes")
        digest(record, "sha256"); digest(record, "versionOutputSha256"); str(record, "versionText")
        validateTarget(record["target"] as? JsonObject ?: error("tool target missing"))
        val resource = record["resourceDirSha256"]
        if (resource == JsonNull) {
            require(role in setOf("assembler", "linker", "build-generator", "generation-tool")) { "compiler requires a resource directory digest" }
            derived += applicability("tool", record, "resourceDirSha256", "role=$role has no compiler resource directory")
        } else digest(record, "resourceDirSha256")
        val sysroot = record["sysrootSha256"]
        if (sysroot == JsonNull) {
            require(role in setOf("build-generator", "generation-tool")) { "$role requires a sysroot digest" }
            derived += applicability("tool", record, "sysrootSha256", "role=$role performs no target compilation or link")
        } else digest(record, "sysrootSha256")
        digest(record, "runtimeProfileSha256")
        val expected = id("tool", JsonObject(record - "id"), budget)
        require(str(record, "id") == expected) { "tool ID does not match canonical identity" }
        return expected
    }

    private fun validateTarget(target: JsonObject) {
        require(target.keys == targetKeys) { "target keys differ from v1 schema" }
        val triple = str(target, "triple"); val elfClass = int(target, "elfClass", setOf(32, 64))
        val byteOrder = str(target, "byteOrder"); require(byteOrder in setOf("little", "big"))
        val machine = positive(target, "machine"); val osAbi = nonNegative(target, "osAbi"); nonNegative(target, "abiFlags")
        when (triple) {
            "x86_64-unknown-linux-gnu" -> require(elfClass == 64 && byteOrder == "little" && machine == 62L)
            "aarch64-unknown-linux-gnu" -> require(elfClass == 64 && byteOrder == "little" && machine == 183L)
            else -> error("target is outside the supported pure-slice ELF target table")
        }
        require(osAbi in setOf(0L, 3L)) { "target OS ABI is unsupported" }
    }

    private fun supportedNullAbiTarget(target: JsonObject): Boolean =
        target["triple"] in setOf(JsonPrimitive("x86_64-unknown-linux-gnu"), JsonPrimitive("aarch64-unknown-linux-gnu")) &&
            target["elfClass"] == JsonPrimitive(64) && target["byteOrder"] == JsonPrimitive("little")

    private fun validateAbi(abi: JsonObject, role: String, target: JsonObject?, derived: MutableList<JsonObject>, recordKind: String, ownerRecord: JsonObject? = null) {
        require(abi.keys == abiKeys) { "ABI keys differ from v1 schema" }
        val family = str(abi, "family"); require(family in setOf("c", "cxx", "none"))
        str(abi, "version")
        for (field in listOf("cxxLibraryAbi", "unwinderAbi")) {
            val value = abi[field]
            if (value == JsonNull) {
                require(family == "c" || family == "none") { "$field is required by $family ABI" }
                require(role in setOf("loader", "c-runtime", "system-library", "static-archive", "system-archive", "compiler-builtins")) { "$role does not prove $field inapplicable" }
                require(target != null && supportedNullAbiTarget(target)) { "$field applicability cannot be proved for unsupported or unspecified target" }
                derived += applicability(recordKind, ownerRecord ?: JsonObject(mapOf("role" to JsonPrimitive(role), "abi" to abi)), field,
                    "abi.family=$family, role=$role, target=${target.get("triple")?.jsonPrimitive?.content} carry no C++ ABI obligation")
            } else (value as? JsonPrimitive)?.takeIf { it.isString && it.content.isNotBlank() } ?: error("$field must be a string or justified null")
        }
    }

    private fun validateRequirement(value: JsonElement, budget: ExternalBoundaryBudgetV1): RequirementRecord {
        budget.checkpoint("external symbol requirement validation")
        val r = value as? JsonObject ?: error("requirement must be object")
        require(r.keys == requirementKeys) { "requirement keys differ from v1 schema" }
        val symbol = r["symbolKey"] as? JsonObject ?: error("symbolKey missing")
        validateSymbolKey(symbol)
        val name = boundedString(r,"name", allowEmpty = true); require(nonNegative(r, "type") in setOf(0L, 1L, 2L, 3L, 4L, 5L, 6L, 10L)); val binding=scalar(r,"binding"); require(binding in if(r["binding"]!!.jsonPrimitive.isString) setOf("local", "global", "weak", "gnu-unique") else setOf("0", "1", "2", "10")); require(scalar(r, "visibility") in if(r["visibility"]!!.jsonPrimitive.isString) setOf("default", "internal", "hidden", "protected") else setOf("0", "1", "2", "3"))
        val version = r["version"] as? JsonObject ?: error("version missing")
        validateVersion(version)
        bool(version, "hidden"); bool(version, "defaultDefinition")
        nullableString(version, "name"); nullableString(version, "providerRequest")
        val abi = r["abi"] as? JsonObject ?: error("requirement ABI missing")
        validateAbi(abi, "requirement", null, mutableListOf(), "requirement", r)
        val ownerModule = nullableString(r, "ownerModuleId"); nullableString(r, "ownerEntityId")
        val references = r["references"] as? JsonArray ?: error("requirement references missing")
        require(references.size <= budget.limits.maximumReferencesAndEvents)
        budget.retain(0, references.size.toLong(), "requirement physical references")
        references.forEach { ref -> validateReference(ref as? JsonObject ?: error("reference must be object")) }
        references.forEach { reference ->
            val row = reference.jsonObject
            require(symbolKeyKeys.all { symbol[it] == row[it] }) { "reference must name the exact required physical symbol" }
            require(nullableString(row, "ownerModuleId") == ownerModule && nullableString(row, "ownerEntityId") == nullableString(r, "ownerEntityId")) {
                "physical symbol reference owner differs from its requirement"
            }
        }
        unique(references.map { referenceDigest(it.jsonObject, budget) }, "requirement physical reference key")
        val disposition = str(r, "disposition"); require(disposition in dispositions)
        if (name.isEmpty()) {
            require(symbol["symbolIndex"] == JsonPrimitive(0) || disposition in setOf("unsupported", "discarded-with-link-proof"))
            require(disposition in setOf("unsupported", "discarded-with-link-proof")) { "unnamed metadata must retain a non-callable diagnostic disposition" }
        }
        if (disposition == "in-scope-owner") require(ownerModule != null) { "in-scope definition requires an exact owner module" }
        if (disposition == "declared-weak-null") require(binding in setOf("weak", "2")) { "weak-null requires a weak binding" }
        val base = JsonObject(JsonObject(r - setOf("id", "disposition")) + ("references" to JsonArray(references.map { it.jsonObject }.sortedWith(compareCanonicalJsonElements(budget)))))
        val computed = id("requirement", base, budget)
        require(str(r, "id") == computed) { "requirement ID does not match canonical identity" }
        return RequirementRecord(computed, JsonObject(r + ("references" to base["references"]!!)), sha(OracleJson.canonicalBytes(symbol, budget.jsonLimits(), { budget.checkpoint(it) })), ownerModule, nullableString(r,"ownerEntityId"), disposition,
            references.map { referenceDigest(it.jsonObject, budget) }, binding, name, JsonObject(version), JsonObject(abi))
    }


    private fun validateVersion(v: JsonObject) {
        require(v.keys == versionKeys)
        val raw = nonNegative(v, "rawIndex"); val index = nonNegative(v, "index")
        require(raw <= 65535 && index <= 32767 && (raw and 32767) == index) { "invalid object-local GNU version index" }
        require(bool(v, "hidden") == (raw and 32768 != 0L)) { "GNU hidden bit differs from local raw index" }
        val default=bool(v, "defaultDefinition"); val name=nullableString(v, "name"); val request=nullableString(v, "providerRequest")
        require(index > 1 || name == null && request == null) { "GNU local/global indices cannot claim a named version" }
        require(!default || !bool(v,"hidden")) { "hidden definition cannot be the default version" }
    }

    private fun validWeakAbsence(s: SelectionRecord?, o: OccurrenceRecord, stage: StageRecord, r: RequirementRecord?, budget: ExternalBoundaryBudgetV1): Boolean {
        budget.checkpoint("weak absence proof join")
        val p = s?.absenceProof ?: return false
        return p["kind"] == JsonPrimitive("recorded-weak-zero-v1") && p["semantics"] == JsonPrimitive("null-checked-optional-reference") &&
            p["stageId"] == JsonPrimitive(stage.id) && p["requirementId"] == JsonPrimitive(r?.id) &&
            p["referenceSha256"] == JsonPrimitive(o.referenceDigest) && p["traceSha256"] == stage.raw["traceSha256"] &&
            p["linkMapSha256"] == stage.raw["linkMapSha256"] && p["abiSourceId"] != JsonNull && p["abiSourceId"] == o.reference["abiSourceId"] &&
            p["resolvedValue"] == JsonPrimitive("0x0") && r?.binding in setOf("weak", "2") && r?.ownerModuleId == null &&
            s.providerId == null && s.exportSymbolKey == null && s.exportName == null && s.exportVersion == null && s.aliasTargetId == null &&
            s.evidenceRefs.isNotEmpty() && o.evidenceRefs.isNotEmpty()
    }

    private fun validateExportPopulation(s: SelectionRecord, provider: JsonObject, r: RequirementRecord?, stage: StageRecord, budget: ExternalBoundaryBudgetV1, finding: (String,String,String?,String?)->Unit) {
        val p = s.exportPopulation!!
        val rows = p["exports"]!!.jsonArray
        val keys = mutableSetOf<String>()
        var matches = 0
        for (v in rows) {
            budget.checkpoint("provider export membership join")
            val e = v.jsonObject
            val key = e["symbolKey"]!!.jsonObject
            require(keys.add(sha(OracleJson.canonicalBytes(key, budget.jsonLimits(), budget::checkpoint), budget)))
            if (key["artifactSha256"] != provider["sha256"] || p["artifactSha256"] != provider["sha256"])
                finding("export-population-artifact-mismatch", "consistency", stage.id, s.occurrenceId)
            if (key == s.exportSymbolKey && e["name"] == JsonPrimitive(s.exportName) && e["version"] == s.exportVersion) {
                matches++
                if (e["type"] != r?.raw?.get("type") || nonNegative(e,"binding") != 1L || nonNegative(e,"visibility") !in setOf(0L,3L) || e["selectionSemantics"] != JsonPrimitive("strong-direct"))
                    finding("export-selection-semantics-unqualified", "consistency", stage.id, s.occurrenceId)
            }
        }
        val canonical = JsonObject(p + ("exports" to JsonArray(rows.sortedWith(compareCanonicalJsonElements(budget)))))
        if (matches != 1 || sha(OracleJson.canonicalBytes(canonical, budget.jsonLimits(), budget::checkpoint),budget) != provider["exportsSha256"]!!.jsonPrimitive.content)
            finding("selected-export-population-mismatch", "consistency", stage.id, s.occurrenceId)
    }

    private fun validateOptionalSelectionProofs(selection: JsonObject, budget: ExternalBoundaryBudgetV1) {
        selection["absenceProof"]?.let { value ->
            budget.checkpoint("optional absence proof decode")
            val proof = value as? JsonObject ?: error("absenceProof must be object")
            require(proof.keys == setOf("kind", "stageId", "requirementId", "referenceSha256", "traceSha256", "linkMapSha256", "abiSourceId", "resolvedValue", "semantics"))
            proof.keys.forEach { str(proof, it) }
        }
        selection["discardProof"]?.let {
            budget.checkpoint("optional discard proof decode")
            digest(selection, "discardProof")
        }
        selection["exportPopulation"]?.let { value ->
            budget.checkpoint("optional export population decode")
            val population = value as? JsonObject ?: error("exportPopulation must be object")
            require(population.keys == setOf("kind", "artifactSha256", "exports"))
            require(str(population, "kind") == "recorded-provider-exports-v1")
            digest(population, "artifactSha256")
            val rows = arr(population, "exports", budget.limits.maximumReferencesAndEvents)
            budget.retain(0, rows.size.toLong(), "provider export population")
            rows.forEach { row ->
                budget.checkpoint("optional export row decode")
                val export = row as? JsonObject ?: error("export must be object")
                require(export.keys == setOf("symbolKey", "name", "type", "binding", "visibility", "version", "selectionSemantics"))
                validateSymbolKey(export["symbolKey"] as? JsonObject ?: error("export symbol key missing"))
                validateVersion(export["version"] as? JsonObject ?: error("export version missing"))
                boundedString(export, "name", allowEmpty = true); str(export, "selectionSemantics")
                require(nonNegative(export, "type") in 0L..15L)
                require(nonNegative(export, "binding") in setOf(0L, 1L, 2L, 10L))
                require(nonNegative(export, "visibility") in 0L..3L)
            }
        }
    }

    private fun normalizeStage(s: JsonObject, budget: ExternalBoundaryBudgetV1): JsonObject {
        fun sorted(v: JsonElement) = JsonArray(v.jsonArray.sortedWith(compareCanonicalJsonElements(budget)))
        return JsonObject(s + listOf("parentStageIds", "toolIds", "outputIdentities", "undefinedBefore", "undefinedAfter", "selections", "blockers").associateWith { key ->
            val rows = s[key]!!.jsonArray.map { row ->
                if (row !is JsonObject) row else {
                    var normalized=row
                    if(row["evidenceRefs"] is JsonArray) normalized=JsonObject(normalized+("evidenceRefs" to sorted(row["evidenceRefs"]!!)))
                    val population=row["exportPopulation"] as? JsonObject
                    if(population != null) normalized=JsonObject(normalized+("exportPopulation" to JsonObject(population+("exports" to sorted(population["exports"]!!)))))
                    normalized
                }
            }
            sorted(JsonArray(rows))
        })
    }

    private fun validateSymbolKey(key: JsonObject) {
        require(key.keys == symbolKeyKeys) { "symbol key fields differ from v1 schema" }
        require(str(key, "artifactRole") in occurrenceArtifactRoles); digest(key, "artifactSha256"); require(nonNegative(key, "tableSectionIndex") <= Int.MAX_VALUE)
        nonNegative(key, "symbolIndex"); str(key, "rawLocator")
    }

    private fun validateReference(ref: JsonObject) {
        require(ref.keys == referenceKeys) { "reference key fields differ from v1 schema" }
        str(ref, "artifactRole"); digest(ref, "artifactSha256"); nullableString(ref, "member")
        nonNegative(ref, "tableSectionIndex"); nonNegative(ref, "symbolIndex"); str(ref, "rawLocator")
        nonNegative(ref, "relocationSectionIndex"); nonNegative(ref, "relocationIndex");
        require(str(ref, "offset").matches(Regex("0x[0-9a-f]+"))) { "reference offset must use the scanner's lowercase hexadecimal encoding" }
        nonNegative(ref, "type"); if (ref["addend"] != JsonNull) intLong(ref, "addend")
        nullableString(ref, "ownerModuleId"); nullableString(ref, "ownerEntityId"); nullableString(ref, "abiSourceId")
    }

    private fun validateStage(value: JsonElement, budget: ExternalBoundaryBudgetV1): StageRecord {
        budget.checkpoint("link stage validation")
        val s = value as? JsonObject ?: error("stage must be object")
        require(s.keys == stageKeys) { "link-stage keys differ from v1 schema" }
        for (field in listOf("buildRunId", "graphActionId")) str(s, field)
        val kind = str(s,"kind")
        require(kind in setOf("archive-create", "archive-index", "partial-relocatable", "lto-link", "shared-library", "executable"))
        val ordinalLong = nonNegative(s, "ordinal"); require(ordinalLong <= Int.MAX_VALUE); val ordinal = ordinalLong.toInt()
        for (field in listOf("sourceRevisionSha256", "planSha256", "policySha256", "linkMapSha256", "traceSha256")) digest(s, field)
        val stageTools = stringArray(s, "toolIds", 256); unique(stageTools, "stage tool id"); require(stageTools.isNotEmpty())
        val parentStageIds = stringArray(s, "parentStageIds", 4096).onEach { require(hex.matches(it)) }
        unique(parentStageIds, "parent link stage ID")
        val argv = stringArray(s, "argv", 16384)
        val environment = s["environment"] as? JsonObject ?: error("stage environment missing")
        val stageViolations = mutableListOf<String>()
        environment.forEach { (k, v) ->
            require(k.matches(Regex("[A-Za-z_][A-Za-z0-9_]*")) && (v == JsonNull || v is JsonPrimitive && v.isString))
            if (k in setOf("LD_PRELOAD", "LD_AUDIT", "LD_LIBRARY_PATH", "CPATH", "LIBRARY_PATH", "SDKROOT", "GCC_EXEC_PREFIX", "COMPILER_PATH", "PKG_CONFIG_PATH") && v != JsonNull && v.jsonPrimitive.content.isNotEmpty())
                stageViolations += "ambient-host-search-environment-present:$k"
            if (k in setOf("HOME", "TMPDIR") && v != JsonNull && (v.jsonPrimitive.content.startsWith("/home/") || v.jsonPrimitive.content.startsWith("/root/")))
                stageViolations += "developer-host-directory-in-stage-environment:$k"
        }
        if (argv.any { arg -> arg == "-l" || arg == "-L" || arg.startsWith("-l") || arg.startsWith("-L") || arg.startsWith("@") ||
                arg.contains('*') || arg.contains('?') || arg.startsWith("-Wl,-rpath") || arg.startsWith("-Wl,-rpath-link") ||
                arg.startsWith("-Wl,--dynamic-linker") || arg == "--sysroot" || arg.startsWith("--sysroot=") || arg == "-B" ||
                arg.startsWith("-B/") || arg.startsWith("-fuse-ld=") || arg.startsWith("-specs=") })
            stageViolations += "wildcard-or-implicit-linker-search-in-argv"
        path(s, "cwd")
        val inputOccurrences = s["inputOccurrences"] as? JsonArray ?: error("input occurrences missing")
        val outputIdentities = s["outputIdentities"] as? JsonArray ?: error("output identities missing")
        require(inputOccurrences.size <= budget.limits.maximumReferencesAndEvents && outputIdentities.size in 1..budget.limits.maximumReferencesAndEvents)
        budget.retain(0, inputOccurrences.size.toLong() + outputIdentities.size, "stage input and output populations")
        inputOccurrences.forEach { item ->
            val x=item.jsonObject; require(x.keys == setOf("role", "bytes", "sha256", "member", "sequence"))
            require(str(x,"role") in occurrenceArtifactRoles) { "unknown input occurrence artifact role" }
            positive(x,"bytes"); digest(x,"sha256"); nullableString(x,"member"); nonNegative(x,"sequence")
        }
        outputIdentities.forEach { item ->
            val x=item.jsonObject; require(x.keys == setOf("role", "bytes", "sha256")); require(str(x,"role") in occurrenceArtifactRoles) { "unknown output identity artifact role" }; positive(x,"bytes"); digest(x,"sha256")
        }
        val outputRoles = outputIdentities.map { str(it.jsonObject, "role") }.toSet()
        val allowedOutputRoles = when (kind) {
            "archive-create", "archive-index" -> setOf("archive")
            "partial-relocatable" -> setOf("relocatable")
            "shared-library" -> setOf("shared-library")
            "executable" -> setOf("executable")
            "lto-link" -> setOf("relocatable", "shared-library", "executable")
            else -> emptySet()
        }
        require(outputRoles.isNotEmpty() && outputRoles.all { it in allowedOutputRoles }) { "stage kind and output artifact role disagree" }
        if (kind == "lto-link") stageViolations += "lto-output-kind-not-qualified-by-producer"
        val inputOrder = inputOccurrences.map { it.jsonObject["sequence"]!!.jsonPrimitive.long }
        require(inputOrder == inputOrder.sorted() && inputOrder.toSet().size == inputOrder.size) { "link input occurrence sequence changed or duplicated" }
        val beforeArray = s["undefinedBefore"] as? JsonArray ?: error("undefinedBefore missing")
        val afterArray = s["undefinedAfter"] as? JsonArray ?: error("undefinedAfter missing")
        require(beforeArray.size <= budget.limits.maximumReferencesAndEvents && afterArray.size <= budget.limits.maximumReferencesAndEvents)
        budget.retain(0, beforeArray.size.toLong() + afterArray.size, "stage symbol census populations")
        val before = beforeArray.map { validateOccurrence(it, str(s, "id"), "before", budget) }
        val after = afterArray.map { validateOccurrence(it, str(s, "id"), "after", budget) }
        unique(before.map { it.id }, "before occurrence identity"); unique(after.map { it.id }, "after occurrence identity")
        val selections = s["selections"] as? JsonArray ?: error("selections missing")
        budget.retain(0, selections.size.toLong(), "stage provider selection population")
        selections.forEach { selection ->
            val o = selection as? JsonObject ?: error("selection must be object")
            val allowed = setOf("occurrenceId", "providerId", "exportSymbolKey", "exportName", "exportVersion", "aliasTargetId", "evidenceRefs")
            require(o.keys.containsAll(allowed) && o.keys.all { it in allowed || it in setOf("absenceProof", "exportPopulation", "discardProof") }) { "selection keys differ from v1 diagnostic amendment" }
            validateOptionalSelectionProofs(o, budget)
            str(o, "occurrenceId"); nullableString(o, "providerId")
            o["exportSymbolKey"]?.let { if (it != JsonNull) (it as? JsonObject)?.let(::validateSymbolKey) ?: error("exportSymbolKey invalid") }
            nullableString(o,"exportName")
            nullableString(o, "aliasTargetId"); stringArray(o, "evidenceRefs", 128)
            o["exportVersion"]?.let { versionValue -> if (versionValue != JsonNull) {
                val version = versionValue.jsonObject; require(version.keys == versionKeys)
                validateVersion(version)
                nullableString(version,"name"); nullableString(version,"providerRequest")
            } }
        }
        val selectionRecords = selections.map { item -> val o=item.jsonObject; SelectionRecord(str(o,"occurrenceId"), nullableString(o,"providerId"), nullableString(o,"aliasTargetId"), o["exportSymbolKey"] as? JsonObject, nullableString(o,"exportName"), o["exportVersion"] as? JsonObject, stringArray(o,"evidenceRefs",128), o["absenceProof"]?.let { it as? JsonObject ?: error("absenceProof must be object") }, o["exportPopulation"]?.let { it as? JsonObject ?: error("exportPopulation must be object") }, o["discardProof"]) }
        unique(selectionRecords.map { it.occurrenceId }, "selected occurrence")
        intLong(s, "exitCode")
        val blockers = stringArray(s, "blockers", 16384)
        if (long(s,"exitCode") != 0L) stageViolations += "link-stage-exit-nonzero"
        if (blockers.isNotEmpty()) stageViolations += "link-stage-recorded-blockers-present"
        val computed = id("stage", canonicalStageIdentity(s, budget), budget)
        require(str(s, "id") == computed) { "stage ID does not match canonical identity" }
        val normalizedStage = normalizeStage(s, budget)
        val recordDigest = sha(OracleJson.canonicalBytes(normalizedStage, budget.jsonLimits(), { budget.checkpoint(it) }))
        // Charge semantic arrays and output rows before retaining the projected values.
        budget.checkpoint("link-stage nested projection work", (inputOccurrences.size + outputIdentities.size + blockers.size).toLong())
        val outputKeys=outputIdentities.map { item -> val x=item.jsonObject; Triple(str(x,"role"), digest(x,"sha256"), positive(x,"bytes")) }.toSet()
        require(outputKeys.size == outputIdentities.size) { "duplicate stage output identity" }
        return StageRecord(computed, normalizedStage, str(s,"buildRunId"), str(s,"graphActionId"), ordinal, str(s,"sourceRevisionSha256"), str(s,"planSha256"), str(s,"policySha256"), stageTools, parentStageIds, outputKeys,
            Collections.unmodifiableList(before), Collections.unmodifiableList(after), Collections.unmodifiableList(selectionRecords),
            Collections.unmodifiableList(stageViolations), recordDigest)
    }

    private fun validateOccurrence(value: JsonElement, stageId: String, side: String, budget: ExternalBoundaryBudgetV1): OccurrenceRecord {
        budget.checkpoint("link occurrence validation")
        val o = value as? JsonObject ?: error("occurrence must be object")
        require(o.keys == referenceOccurrenceKeys) { "occurrence keys differ from v1 schema" }
        val symbol = o["symbolKey"] as? JsonObject ?: error("occurrence symbol key missing"); validateSymbolKey(symbol)
        val reference = o["reference"] as? JsonObject ?: error("occurrence reference missing"); validateReference(reference)
        require(symbolKeyKeys.all { symbol[it] == reference[it] }) { "occurrence reference differs from physical symbol" }
        val expectedId = id("occurrence", buildJsonObject { put("stageId", stageId); put("reference", reference) }, budget)
        require(str(o, "id") == expectedId) { "occurrence ID does not bind stage and physical reference" }
        val disposition = str(o, "disposition"); require(disposition in dispositions)
        val refs = stringArray(o, "evidenceRefs", 128).sortedWith(compareByJsonKey(budget) { it })
        return OccurrenceRecord(expectedId, sha(OracleJson.canonicalBytes(symbol, budget.jsonLimits(), { budget.checkpoint(it) })), symbol,
            reference, nullableString(o, "requirementId"), nullableString(o, "ownerModuleId"), nullableString(o, "providerId"), disposition,
            refs, nullableString(o, "aliasTargetId"), side, referenceDigest(reference, budget))
    }

    private fun referenceDigest(reference: JsonObject, budget: ExternalBoundaryBudgetV1): String = sha(OracleJson.canonicalBytes(reference, budget.jsonLimits(), { budget.checkpoint(it) }), budget)

    private fun detectAliasCycles(stages: List<StageRecord>, budget: ExternalBoundaryBudgetV1, finding: (String, String, String?, String?) -> Unit) {
        val edges = stages.flatMap { stage -> stage.selections.mapNotNull { selection -> selection.aliasTargetId?.let { selection.occurrenceId to it } } }.toMap()
        val state = HashMap<String, Int>()
        for (start in edges.keys) {
            if (state[start] == 2) continue
            val path = mutableListOf<String>()
            val local = HashSet<String>()
            var cursor: String? = start
            while (cursor != null && state[cursor] != 2) {
                budget.checkpoint("alias graph cycle reconciliation")
                if (!local.add(cursor)) {
                    finding("alias-cycle", "consistency", null, cursor)
                    break
                }
                state[cursor] = 1
                path += cursor
                cursor = edges[cursor]
            }
            path.forEach { state[it] = 2 }
        }
    }

    private fun id(kind: String, identity: JsonElement, budget: ExternalBoundaryBudgetV1): String {
        val domain = "a14-external-provider-v1:$kind".toByteArray(StandardCharsets.US_ASCII)
        val bytes = OracleJson.canonicalBytes(identity, budget.jsonLimits(), { budget.checkpoint(it) })
        val allocation = Math.addExact(16, Math.addExact(domain.size, bytes.size))
        budget.checkpoint("framed identity allocation",allocation.toLong())
        val buffer = ByteBuffer.allocate(allocation)
        buffer.putLong(domain.size.toLong()).put(domain).putLong(bytes.size.toLong()).put(bytes)
        return sha(buffer.array(), budget)
    }

    /** Stable non-circular digest for the fixed decoder rules and this invocation's effective ceilings. */
    internal fun configurationSha256(limits: ExternalProviderLimitsV1, budget: ExternalBoundaryBudgetV1? = null): String {
        val rules = "a14-external-provider-v1:diagnostic-amendment-1:exact-obligation-proof:local-GNU-indices:strict-nested-snapshots:non-bearer"
        val configuration = buildJsonObject {
            put("schemaVersion", 1); put("kind", "external-provider-detector-configuration-v1")
            put("rulesSha256", sha(rules.toByteArray(StandardCharsets.US_ASCII)))
            put("limits", buildJsonObject {
                put("maximumDocumentBytes",limits.maximumDocumentBytes); put("maximumAggregateInputBytes",limits.maximumAggregateInputBytes)
                put("maximumDepth",limits.maximumDepth); put("maximumNodes",limits.maximumNodes); put("maximumStringBytes",limits.maximumStringBytes)
                put("maximumTotalStringBytes",limits.maximumTotalStringBytes); put("maximumProviders",limits.maximumProviders); put("maximumTools",limits.maximumTools)
                put("maximumStages",limits.maximumStages); put("maximumRequirements",limits.maximumRequirements); put("maximumReferencesAndEvents",limits.maximumReferencesAndEvents)
                put("maximumClauses",limits.maximumClauses); put("maximumFindings",limits.maximumFindings); put("maximumWorkUnits",limits.maximumWorkUnits)
            })
        }
        val bytes = if (budget == null) OracleJson.canonicalBytes(configuration) else OracleJson.canonicalBytes(configuration, budget.jsonLimits(), { budget.checkpoint(it) })
        return sha(bytes, budget)
    }

    private fun normalizeInputForDigest(input: JsonObject, budget: ExternalBoundaryBudgetV1): JsonObject {
        fun sortedArray(value: JsonElement, key: (JsonElement) -> String): JsonArray = JsonArray((value as JsonArray).sortedWith(compareByJsonKey(budget, key)))
        fun sortedCanonical(value: JsonElement): JsonArray = JsonArray((value as JsonArray).sortedWith(compareCanonicalJsonElements(budget)))
        val universe = input["universe"]!!.jsonObject
        val normalizedUniverse = JsonObject(universe + mapOf(
            "expectedEntities" to sortedCanonical(universe["expectedEntities"]!!),
            "expectedReferences" to sortedCanonical(universe["expectedReferences"]!!),
            "ownerModuleIds" to sortedArray(universe["ownerModuleIds"]!!) { it.jsonPrimitive.content },
            "stageIds" to sortedArray(universe["stageIds"]!!) { it.jsonPrimitive.content },
            "provenanceLimitations" to sortedArray(universe["provenanceLimitations"]!!) { it.jsonPrimitive.content },
            "requiredGeneratedTables" to sortedArray(universe["requiredGeneratedTables"]!!) { it.jsonObject["id"]!!.jsonPrimitive.content },
        ))
        return JsonObject(input + mapOf(
            "universe" to normalizedUniverse,
            "stages" to JsonArray(input["stages"]!!.jsonArray.map { normalizeStage(it.jsonObject, budget) }),
            "elfEvidence" to sortedArray(input["elfEvidence"]!!) { sha(OracleJson.canonicalBytes(it, budget.jsonLimits(), { budget.checkpoint(it) }), budget) },
            "rawMeasurements" to sortedArray(input["rawMeasurements"]!!) { sha(OracleJson.canonicalBytes(it, budget.jsonLimits(), { budget.checkpoint(it) }), budget) },
            "recordedClosures" to sortedArray(input["recordedClosures"]!!) { sha(OracleJson.canonicalBytes(it, budget.jsonLimits(), { budget.checkpoint(it) }), budget) },
        ))
    }

    private fun normalizePolicyForDigest(policy: JsonObject, budget: ExternalBoundaryBudgetV1): JsonObject {
        fun sortedRecords(key: String) = JsonArray((policy[key] as JsonArray).sortedWith(MeteredComparator(budget) { a, b ->
            compareCanonicalJson(JsonObject(a.jsonObject - "id"), JsonObject(b.jsonObject - "id"), budget)
        }))
        val runtime = policy["runtimePolicy"]!!.jsonObject
        val clauses=(runtime["clauses"] as JsonArray).map { clauseValue ->
            val clause=clauseValue.jsonObject
            JsonObject(clause + mapOf("operations" to sortedRuntimeStrings(clause["operations"]!!,budget), "targets" to sortedRuntimeStrings(clause["targets"]!!,budget),
                "inputs" to sortedRuntimeStrings(clause["inputs"]!!,budget), "evidenceRefs" to sortedRuntimeStrings(clause["evidenceRefs"]!!,budget)))
        }.sortedWith(compareByJsonKey(budget) { it.jsonObject["id"]!!.jsonPrimitive.content })
        val normalizedRuntime = JsonObject(runtime + ("clauses" to JsonArray(clauses)))
        val requirements=(policy["requirements"] as JsonArray).map { value ->
            val r=value.jsonObject
            val refs=(r["references"] as JsonArray).sortedWith(compareCanonicalJsonElements(budget))
            JsonObject(r + ("references" to JsonArray(refs)))
        }.sortedWith(MeteredComparator(budget) { a, b ->
            val logical = compareCanonicalJson(a.jsonObject["symbolKey"]!!, b.jsonObject["symbolKey"]!!, budget)
            if (logical != 0) logical else compareByJsonKey(budget) { value: JsonElement -> value.jsonObject["id"]!!.jsonPrimitive.content }.compare(a, b)
        })
        return JsonObject(policy + mapOf(
            "providers" to sortedRecords("providers"),
            "tools" to sortedRecords("tools"),
            "requirements" to JsonArray(requirements),
            "runtimePolicy" to normalizedRuntime,
        ))
    }

    private fun sortedRuntimeStrings(value: JsonElement, budget: ExternalBoundaryBudgetV1): JsonArray =
        JsonArray((value as JsonArray).sortedWith(compareByJsonKey(budget) { it.jsonPrimitive.content }))

    private fun canonicalStageIdentity(stage: JsonObject, budget: ExternalBoundaryBudgetV1): JsonObject {
        val identity=JsonObject(stage - stageIdentityExcluded)
        return JsonObject(identity + mapOf(
            "parentStageIds" to JsonArray((identity["parentStageIds"] as JsonArray).sortedWith(compareByJsonKey(budget) { it.jsonPrimitive.content })),
            "toolIds" to JsonArray((identity["toolIds"] as JsonArray).sortedWith(compareByJsonKey(budget) { it.jsonPrimitive.content })),
            // The clarification keeps output classification in the ID while output bytes remain non-circular evidence.
            "outputIdentities" to JsonArray((stage["outputIdentities"] as JsonArray).map { item -> buildJsonObject { put("role", item.jsonObject["role"]!!) } }
                .sortedWith(compareByJsonKey(budget) { it.jsonObject["role"]!!.jsonPrimitive.content })),
        ))
    }

    private fun applicability(kind: String, record: JsonObject, field: String, reason: String) = buildJsonObject {
        put("recordKind", kind); put("recordId", record["id"]?.jsonPrimitive?.content ?: "unidentified")
        put("field", field); put("fixedReason", reason)
    }
    private fun sha(bytes: ByteArray, budget: ExternalBoundaryBudgetV1? = null): String {
        budget?.checkpoint("before external boundary SHA-256", bytes.size.toLong())
        val digest = boundarySha256(bytes, budget)
        budget?.checkpoint("after external boundary SHA-256")
        return digest
    }
    private fun str(o: JsonObject, field: String): String = (o[field] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?.also { require(it.isNotBlank() && it.length <= 16 * 1024 && it.none(Char::isISOControl)) } ?: error("$field must be a non-empty string")
    private fun boundedString(o: JsonObject, field: String, allowEmpty: Boolean = false): String = (o[field] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?.also { require((allowEmpty || it.isNotBlank()) && it.length <= 16 * 1024 && it.none(Char::isISOControl)) } ?: error("$field must be a bounded string")
    private fun scalar(o: JsonObject, field: String): String = (o[field] as? JsonPrimitive)?.let { primitive ->
        if (primitive.isString) primitive.content.also { require(it.isNotBlank()) } else primitive.longOrNull?.toString() ?: error("$field must be string or integer")
    } ?: error("$field must be string or integer")
    private fun nullableString(o: JsonObject, field: String): String? = if (o[field] == JsonNull) null else str(o, field)
    private fun digest(o: JsonObject, field: String): String = str(o, field).also { require(hex.matches(it)) { "$field must be lowercase SHA-256" } }
    private fun positive(o: JsonObject, field: String): Long = long(o, field).also { require(it > 0) }
    private fun nonNegative(o: JsonObject, field: String): Long = long(o, field).also { require(it >= 0) }
    private fun intLong(o: JsonObject, field: String): Long = long(o, field)
    private fun long(o: JsonObject, field: String): Long = (o[field] as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull ?: error("$field must be an integer")
    private fun int(o: JsonObject, field: String, allowed: Set<Int>): Int = long(o, field).also { require(it in allowed.map(Int::toLong)) }.toInt()
    private fun bool(o: JsonObject, field: String): Boolean = (o[field] as? JsonPrimitive)?.takeUnless { it.isString }?.booleanOrNull ?: throw IllegalArgumentException("$field must be boolean")
    private fun path(o: JsonObject, field: String): String = str(o, field).also {
        val p = Path.of(it); require(p.isAbsolute && p.normalize().toString() == it && !it.contains("\\") && it.none(Char::isISOControl)) { "$field must be normalized absolute path" }
    }
    private fun stringArray(o: JsonObject, field: String, ceiling: Int): List<String> {
        val a = o[field] as? JsonArray ?: error("$field must be array"); require(a.size <= ceiling)
        val values = a.map { (it as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content ?: error("$field entry must be string") }
        require(values.all { it.isNotBlank() && it.length <= 16 * 1024 && it.none(Char::isISOControl) })
        return values
    }
    private fun unique(values: List<String>, label: String) { require(values.toSet().size == values.size) { "duplicate $label" } }
    private fun <T> compareByJsonKey(budget: ExternalBoundaryBudgetV1, selector: (T) -> String): MeteredComparator<T> = MeteredComparator(budget) { a, b ->
        val astr = selector(a); val bstr = selector(b)
        budget.checkpoint("external boundary stable sort comparison", astr.length.toLong() + bstr.length)
        val aa = astr.toByteArray(StandardCharsets.UTF_8); val bb = bstr.toByteArray(StandardCharsets.UTF_8)
        var i = 0; while (i < minOf(aa.size, bb.size)) { val d = (aa[i].toInt() and 255) - (bb[i].toInt() and 255); if (d != 0) return@MeteredComparator d; i++ }
        aa.size - bb.size
    }
    private fun compareCanonicalJsonElements(budget: ExternalBoundaryBudgetV1): MeteredComparator<JsonElement> = MeteredComparator(budget) { a, b -> compareCanonicalJson(a, b, budget) }
    private fun compareCanonicalJson(a: JsonElement, b: JsonElement, budget: ExternalBoundaryBudgetV1): Int {
        val aa = OracleJson.canonicalBytes(a, budget.jsonLimits(), { budget.checkpoint(it) })
        val bb = OracleJson.canonicalBytes(b, budget.jsonLimits(), { budget.checkpoint(it) })
        budget.checkpoint("external boundary canonical identity ordering", aa.size.toLong() + bb.size)
        var index = 0
        while (index < minOf(aa.size, bb.size)) {
            val difference = (aa[index].toInt() and 0xff) - (bb[index].toInt() and 0xff)
            if (difference != 0) return difference
            index++
        }
        return aa.size - bb.size
    }
}

private class MeteredComparator<T>(val budget: ExternalBoundaryBudgetV1, val compareValues: (T,T)->Int): Comparator<T> {
    override fun compare(a: T,b: T): Int = compareValues(a,b)
}

/** Stable bottom-up merge with both comparisons and every copied element charged. */
private fun <T> Iterable<T>.sortedWith(comparator: MeteredComparator<T>): List<T> {
    val source=this as? Collection<T> ?: error("sort population must be bounded")
    require(source.size <= comparator.budget.limits.maximumNodes)
    comparator.budget.checkpoint("sort storage admission",source.size.toLong()*2)
    var from=source.toMutableList();var into=from.toMutableList();var width=1
    while(width < from.size) {
        var start=0
        while(start < from.size) {
            val mid=minOf(start+width,from.size);val end=minOf(mid+width,from.size)
            var a=start;var b=mid;var dest=start
            while(dest<end) {
                comparator.budget.checkpoint("external boundary stable merge")
                into[dest++]=if(a<mid && (b>=end || comparator.compare(from[a],from[b]) <= 0)) from[a++] else from[b++]
            }
            start=end
        }
        val temp=from;from=into;into=temp;width=Math.multiplyExact(width,2)
    }
    comparator.budget.checkpoint("terminal stable sort")
    return from
}
