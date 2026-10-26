package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.NativeCallAddressV1
import decompengine.project.NativeCallBindingsV1
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Authored complete native streams exercise recovery-only selection, not production admission. */
class FrozenNativeExternalClaimsV1Test {
    @Test
    fun `complete raw census retains zero-site functions unowned sites and two explicit claim shapes`() {
        val document = fixture()
        val raw = canonical(document)
        val manifest = manifest(raw)
        val frozen = FrozenNativeExternalClaimsV1.freeze(manifest, raw, BINDINGS)
        assertEquals(9L, frozen.rawRecordCount)
        assertEquals(3L, frozen.rawSiteCount)
        assertEquals(listOf(3L, 4L, 5L), frozen.sites.map { it.recordOrdinal })
        assertEquals(listOf(0L, 1L, 2L), frozen.sites.map { it.siteOrdinal })
        assertEquals(listOf(address(1, 0x1010), address(1, 0x1020), address(1, 0x1300)), frozen.sites.map { it.address })
        assertNull(frozen.sites.last().owner)
        assertTrue(frozen.sites.all { it.physicalCallEligible })
        assertNull(frozen.sites.last().candidate)
        val direct = assertIs<NativeExternalCandidateV1.Thunk>(frozen.sites[0].candidate)
        assertEquals("native-immediate-thunk-external-chain-v1", direct.kind)
        assertEquals(address(1, 0x1200), direct.target)
        assertEquals(address(0, 0x80), direct.externalTarget.address)
        assertEquals(2L, direct.functionRecordOrdinal)
        val indirect = assertIs<NativeExternalCandidateV1.Slot>(frozen.sites[1].candidate)
        assertEquals("native-slot-external-chain-v1", indirect.kind)
        assertEquals(address(1, 0x2000), indirect.slot)
        assertEquals(address(0, 0x80), indirect.externalTarget.address)
        assertEquals(0, indirect.viaReferenceIndex)
        assertEquals(0, indirect.neighborhoodIndex)
        assertEquals(0, indirect.targetReferenceIndex)
        assertEquals(address(1, 0x1015), frozen.sites[0].prototypeFallThrough)
        assertEquals(address(1, 0x1026), frozen.sites[1].prototypeFallThrough)
        assertEquals(BINDINGS, frozen.bindings)
        assertEquals(BINDINGS.inputSha256, frozen.inputSha256)
        assertEquals(OracleArtifacts.sha256(manifest), frozen.manifestSha256)
        assertEquals(OracleArtifacts.sha256(raw), frozen.observationsSha256)
        assertEquals(OracleArtifacts.sha256(frozen.canonicalEvidenceBytes), frozen.evidenceSha256)
        assertContentEquals(raw, frozen.rawObservationBytes)
        assertContentEquals(manifest, frozen.rawManifestBytes)
        assertContentEquals(frozen.canonicalEvidenceBytes, freeze(document).canonicalEvidenceBytes)
        assertFalse(frozen.productionVerified)
        assertFalse(frozen.scored)
        assertFalse(frozen.complete)
        assertFalse(frozen.releaseEligible)
        assertFalse(frozen.negativeCompleteness)
        val evidence = OracleJson.parseCanonical(frozen.canonicalEvidenceBytes) as JsonObject
        assertEquals(JsonNull, evidence["externalNamespaceSha256"])
        for (key in listOf("productionVerified", "scored", "complete", "releaseEligible", "negativeCompleteness"))
            assertEquals(JsonPrimitive(false), evidence[key])
        val census = (evidence.getValue("records") as JsonArray).map { it as JsonObject }
        assertEquals((0L..8L).toList(), census.map { (it.getValue("recordOrdinal") as JsonPrimitive).content.toLong() })
        assertEquals(listOf("function", "function", "function", "site", "site", "site", "function-summary", "function-summary", "function-summary"),
            census.map { (it.getValue("recordKind") as JsonPrimitive).content })
    }

    @Test
    fun `instruction bytes alone never supply missing slot or external target evidence`() {
        val original = fixture()
        val variations = listOf(
            mutateSite(original, 1) { it + ("references" to JsonArray(emptyList())) + ("referenceNeighborhoods" to JsonArray(emptyList())) },
            mutateSite(original, 1) { it + ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 1, 0x2000, emptyList())))) },
            mutateSite(original, 1) { site -> site + ("references" to JsonArray(listOf(reference(1, 0x1020, target(1, 0x2000), 101, "READ")))) },
            mutateSite(original, 1) { site -> site + ("references" to JsonArray(listOf(reference(1, 0x1020, externalTarget(), 8, "COMPUTED_CALL")))) +
                ("referenceNeighborhoods" to JsonArray(emptyList())) },
        )
        for (document in variations) {
            val frozen = freeze(document)
            assertEquals(3L, frozen.rawSiteCount)
            assertEquals("ff15da0f0000", frozen.sites[1].instructionBytes)
            assertTrue(frozen.sites[1].physicalCallEligible)
            assertNull(frozen.sites[1].candidate)
        }
    }

    @Test
    fun `conflicting slots external endpoints and prototype targets remain unresolved`() {
        val original = fixture()
        val multipleSlots = mutateSite(original, 1) { it +
            ("references" to JsonArray(listOf(reference(1, 0x1020, target(1, 0x2000), 9, "INDIRECTION"),
                reference(1, 0x1020, target(1, 0x2010), 9, "INDIRECTION")))) +
            ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 1, 0x2000, listOf(reference(1, 0x2000, externalTarget(), 101, "READ"))),
                neighborhood(1, 1, 0x2010, listOf(reference(1, 0x2010, externalTarget(), 101, "READ")))))) }
        val multipleExternals = mutateSite(original, 1) { it + ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 1, 0x2000,
            listOf(reference(1, 0x2000, externalTarget(), 101, "READ"), reference(1, 0x2000, externalTarget(0x90), 101, "READ")))))) }
        val multipleDirectTargets = mutateSite(original, 0) { it + ("prototypeTargets" to JsonArray(listOf(
            target(1, 0x1100, entry = true), target(1, 0x1200, entry = true)))) }
        val multipleComputedTargets = mutateSite(original, 1) { it + ("prototypeTargets" to JsonArray(listOf(
            target(1, 0x1100, entry = true), target(1, 0x1200, entry = true)))) }
        val singleComputedTarget = mutateSite(original, 1) { it + ("prototypeTargets" to JsonArray(listOf(target(1, 0x1200, entry = true)))) }
        for ((document, siteIndex) in listOf(multipleSlots to 1, multipleExternals to 1, multipleDirectTargets to 0, multipleComputedTargets to 1, singleComputedTarget to 1)) {
            val frozen = freeze(document)
            assertEquals(3L, frozen.rawSiteCount)
            assertNull(frozen.sites[siteIndex].candidate)
            assertTrue(frozen.sites[siteIndex].physicalCallEligible)
        }
    }

    @Test
    fun `same external coordinate across sites remains separate while within-site conflict is unresolved`() {
        val repeated = mutateSite(fixture(), 2) { it +
            ("references" to JsonArray(listOf(reference(1, 0x1300, target(1, 0x2010), 9, "INDIRECTION")))) +
            ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 1, 0x2010, listOf(reference(1, 0x2010, externalTarget(), 101, "READ")))))) }
        val sites = freeze(repeated).sites
        assertEquals(3, sites.size)
        assertEquals(3, sites.count { it.candidate != null })
        assertEquals(address(0, 0x80), assertIs<NativeExternalCandidateV1.Slot>(sites[2].candidate).externalTarget.address)
        assertEquals(listOf(3L, 4L, 5L), sites.map { it.recordOrdinal })
        for (endpoint in listOf(0x80L, 0x90L)) {
            val direct = mutateSite(fixture(), 0) { it + ("references" to JsonArray(listOf(
                reference(1, 0x1010, externalTarget(endpoint), 3, "UNCONDITIONAL_CALL"),
                reference(1, 0x1010, target(1, 0x1200, entry = true), 3, "UNCONDITIONAL_CALL")))) }
            val indirect = mutateSite(fixture(), 1) { it + ("references" to JsonArray(listOf(
                reference(1, 0x1020, externalTarget(endpoint), 8, "COMPUTED_CALL"),
                reference(1, 0x1020, target(1, 0x2000), 9, "INDIRECTION")))) +
                ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(1, 1, 0x2000,
                    listOf(reference(1, 0x2000, externalTarget(), 101, "READ")))))) }
            val directClaim = freeze(direct).sites[0].candidate
            val indirectClaim = freeze(indirect).sites[1].candidate
            if (endpoint == 0x80L) {
                assertIs<NativeExternalCandidateV1.Thunk>(directClaim)
                assertIs<NativeExternalCandidateV1.Slot>(indirectClaim)
            } else {
                assertNull(directClaim)
                assertNull(indirectClaim)
            }
        }
    }

    @Test
    fun `direct target requires its own exact immediate external thunk relation`() {
        val nonThunk = mutateFunction(fixture(), 2) { it + ("isThunk" to JsonPrimitive(false)) + ("immediateThunkTarget" to JsonNull) }
        val recursive = mutateFunction(fixture(), 2) { it + ("immediateThunkTarget" to target(1, 0x1200, entry = true)) }
        val local = mutateFunction(fixture(), 2) { it + ("immediateThunkTarget" to target(1, 0x1100, entry = true)) }
        val nameOnly = mutateSite(fixture(), 0) { it + ("prototypeTargets" to JsonArray(listOf(externalTarget()))) }
        for (document in listOf(nonThunk, recursive, local, nameOnly)) {
            val frozen = freeze(document)
            assertNull(frozen.sites.first().candidate)
            assertEquals(3L, frozen.rawSiteCount)
        }
    }

    @Test
    fun `only exact bound image RAM coordinates can form physical claim anchors`() {
        val wrongSlot = mutateSite(fixture(), 1) { it +
            ("references" to JsonArray(listOf(reference(1, 0x1020, target(2, 0x2000), 9, "INDIRECTION")))) +
            ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 2, 0x2000, listOf(reference(2, 0x2000, externalTarget(), 101, "READ")))))) }
        val overlaySlot = mutateSite(fixture(), 1) { it +
            ("references" to JsonArray(listOf(reference(1, 0x1020, target(3, 0x2000), 9, "INDIRECTION")))) +
            ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 3, 0x2000, listOf(reference(3, 0x2000, externalTarget(), 101, "READ")))))) }
        val belowBaseSlot = mutateSite(fixture(), 1) { it +
            ("references" to JsonArray(listOf(reference(1, 0x1020, target(1, 0x800), 9, "INDIRECTION")))) +
            ("referenceNeighborhoods" to JsonArray(listOf(neighborhood(0, 1, 0x800, listOf(reference(1, 0x800, externalTarget(), 101, "READ")))))) }
        for (document in listOf(wrongSlot, overlaySlot, belowBaseSlot)) assertNull(freeze(document).sites[1].candidate)
        val codeFunction = mutateFunction(fixture(), 2) { it + ("entry" to addr(2, 0x1200)) }
        val wrongDirect = mutateSite(codeFunction, 0) { it + ("prototypeTargets" to JsonArray(listOf(target(2, 0x1200, entry = true)))) +
            ("references" to JsonArray(listOf(reference(1, 0x1010, target(2, 0x1200, entry = true), 3, "UNCONDITIONAL_CALL")))) }
        assertNull(freeze(wrongDirect).sites[0].candidate)
        val belowBaseSite = mutateSite(fixture(), 0) { site -> site + ("address" to addr(1, 0x900)) +
            ("references" to JsonArray(listOf(reference(1, 0x900, target(1, 0x1200, entry = true), 3, "UNCONDITIONAL_CALL")))) }
        val below = freeze(belowBaseSite).sites.first()
        assertFalse(below.physicalCallEligible)
        assertNull(below.candidate)
        val signed = replace(fixture(), listOf("addressSpaces", 1, "signedOffsets"), JsonPrimitive(true))
        assertTrue(freeze(signed).sites.all { !it.physicalCallEligible && it.candidate == null })
        val nonByteRam = replace(replace(fixture(), listOf("addressSpaces", 1, "sizeBits"), JsonPrimitive(63)),
            listOf("addressSpaces", 1, "addressableUnitSize"), JsonPrimitive(2))
        assertTrue(freeze(nonByteRam).sites.all { !it.physicalCallEligible && it.candidate == null })
    }

    @Test
    fun `analysis tail overrides unsupported boundaries and effective mismatch retain unresolved census`() {
        val variations = listOf(
            mutateSite(fixture(), 0) { it + ("observationKind" to JsonPrimitive("analysis-call-candidate")) +
                ("prototypeFlow" to flow(0, "FALL_THROUGH")) },
            mutateSite(fixture(), 0) { it + ("observationKind" to JsonPrimitive("direct-tail-candidate")) +
                ("prototypeFlow" to flow(1, "UNCONDITIONAL_JUMP")) + ("effectiveFlow" to flow(1, "UNCONDITIONAL_JUMP")) +
                ("references" to JsonArray(listOf(reference(1, 0x1010, target(1, 0x1200, entry = true), 1, "UNCONDITIONAL_JUMP")))) },
            mutateSite(fixture(), 0) { it + ("flowOverride" to JsonPrimitive("CALL_RETURN")) },
            mutateSite(fixture(), 0) { it + ("prototypeFlow" to flow(16, "CALL_OVERRIDE_UNCONDITIONAL")) + ("effectiveFlow" to flow(16, "CALL_OVERRIDE_UNCONDITIONAL")) },
            mutateSite(fixture(), 0) { it + ("prototypeFlow" to flow(18, "CALLOTHER_OVERRIDE_CALL")) + ("effectiveFlow" to flow(18, "CALLOTHER_OVERRIDE_CALL")) },
            mutateSite(fixture(), 0) { it + ("lengthOverridden" to JsonPrimitive(true)) + ("byteStatus" to JsonPrimitive("unsupported-boundary")) + ("instructionBytes" to JsonNull) },
            mutateSite(fixture(), 0) { it + ("delaySlotDepth" to JsonPrimitive(1)) + ("byteStatus" to JsonPrimitive("unsupported-boundary")) + ("instructionBytes" to JsonNull) },
        )
        for (document in variations) {
            val frozen = freeze(document)
            assertEquals(3L, frozen.rawSiteCount)
            assertEquals(9L, frozen.rawRecordCount)
            assertFalse(frozen.sites.first().physicalCallEligible)
            assertNull(frozen.sites.first().candidate)
        }
        val mismatch = mutateSite(fixture(), 0) { it + ("effectiveFlow" to flow(8, "COMPUTED_CALL")) }
        val site = freeze(mismatch).sites.first()
        assertTrue(site.physicalCallEligible)
        assertNull(site.candidate)
        assertEquals(3, site.prototypeFlowCode)
        assertEquals(8, site.effectiveFlowCode)
    }

    @Test
    fun `labels libraries and imported spelling never select the physical target`() {
        val original = fixture()
        fun renamed(element: JsonElement): JsonElement = when (element) {
            is JsonArray -> JsonArray(element.map(::renamed))
            is JsonObject -> JsonObject(element.mapValues { (key, value) -> when (key) {
                "label" -> JsonPrimitive("different@@VERSION_9")
                "libraryName" -> JsonPrimitive("unrelated-provider.so")
                "originalImportedName" -> JsonPrimitive("invented-versioned-name@V7")
                else -> renamed(value)
            } })
            else -> element
        }
        val first = freeze(original)
        val second = freeze(renamed(original) as JsonObject)
        assertEquals(first.sites.map { it.address }, second.sites.map { it.address })
        assertEquals(first.sites.map { it.candidate?.kind }, second.sites.map { it.candidate?.kind })
        assertEquals(assertIs<NativeExternalCandidateV1.Thunk>(first.sites[0].candidate).target,
            assertIs<NativeExternalCandidateV1.Thunk>(second.sites[0].candidate).target)
        assertEquals(assertIs<NativeExternalCandidateV1.Slot>(first.sites[1].candidate).slot,
            assertIs<NativeExternalCandidateV1.Slot>(second.sites[1].candidate).slot)
        assertNotEquals(first.observationsSha256, second.observationsSha256)
        assertNotEquals(first.evidenceSha256, second.evidenceSha256)
        assertTrue(second.rawObservationBytes.toString(Charsets.UTF_8).contains("different@@VERSION_9"))
    }

    @Test
    fun `complete validation rejects late malformed census and substituted byte bindings`() {
        val document = fixture()
        val bytes = canonical(document)
        val manifest = manifest(bytes)
        assertFails { FrozenNativeExternalClaimsV1.freeze(manifest, bytes, BINDINGS.copy(inputSha256 = "0".repeat(64))) }
        assertFails { FrozenNativeExternalClaimsV1.freeze(manifest, bytes, BINDINGS.copy(programModelSha256 = "0".repeat(64))) }
        assertFails { FrozenNativeExternalClaimsV1.freeze(manifest, bytes.copyOf().also { it[it.lastIndex] = ' '.code.toByte() }, BINDINGS) }
        assertFails { freeze(replace(document, listOf("summary", "sites"), JsonPrimitive(4))) }
        val brokenSummary = replace(document, listOf("records", 8, "prototypeCalls"), JsonPrimitive(1))
        assertFails { freeze(brokenSummary) }
        assertFails { freeze(replace(document, listOf("records", 4, "referenceNeighborhoods", 0, "source"), addr(1, 0x2010))) }
    }

    @Test
    fun `bounds reject instead of truncating and cancellation returns no snapshot`() {
        val document = fixture()
        val bytes = canonical(document)
        val manifest = manifest(bytes)
        val limits = listOf(
            NativeExternalClaimLimitsV1(maximumObservationBytes = bytes.size - 1),
            NativeExternalClaimLimitsV1(maximumManifestBytes = manifest.size - 1),
            NativeExternalClaimLimitsV1(maximumSites = 2),
            NativeExternalClaimLimitsV1(maximumRecords = 8),
            NativeExternalClaimLimitsV1(maximumEvidenceBytes = 128),
        )
        for (limit in limits) assertFails { FrozenNativeExternalClaimsV1.freeze(manifest, bytes, BINDINGS, limit) }
        var checkpoints = 0
        assertFails {
            FrozenNativeExternalClaimsV1.freeze(manifest, bytes, BINDINGS, checkpoint = {
                if (++checkpoints == 8) error("authored cancellation")
            })
        }
        assertTrue(checkpoints >= 8)
    }

    @Test
    fun `input snapshots output byte copies and exposed lists cannot mutate frozen claims`() {
        val raw = canonical(fixture())
        val manifest = manifest(raw)
        val expectedRaw = raw.copyOf()
        val expectedManifest = manifest.copyOf()
        val snapshot = FrozenNativeExternalClaimsV1.freeze(manifest, raw, BINDINGS)
        val evidence = snapshot.canonicalEvidenceBytes
        val expectedEvidence = evidence.copyOf()
        raw.fill(0); manifest.fill(0); evidence.fill(0)
        snapshot.rawManifestBytes.fill(0)
        snapshot.rawObservationBytes.fill(0)
        assertContentEquals(expectedRaw, snapshot.rawObservationBytes)
        assertContentEquals(expectedManifest, snapshot.rawManifestBytes)
        assertContentEquals(expectedEvidence, snapshot.canonicalEvidenceBytes)
        assertEquals(OracleArtifacts.sha256(expectedEvidence), snapshot.evidenceSha256)
        assertFails { (snapshot.sites as MutableList<NativeExternalClaimSiteV1>).clear() }
        assertFails { (snapshot.addressSpaces as MutableList<*>).clear() }
        assertEquals(3, snapshot.sites.size)
        assertIs<NativeExternalCandidateV1.Thunk>(snapshot.sites.first().candidate)
    }

    internal fun fixture(): JsonObject {
        val functions = listOf(function(0x1000), function(0x1100), function(0x1200, externalTarget()))
        val direct = site(0x1010, addr(1, 0x1000), 3, "UNCONDITIONAL_CALL", "e8eb010000", listOf(target(1, 0x1200, entry = true)),
            listOf(reference(1, 0x1010, target(1, 0x1200, entry = true), 3, "UNCONDITIONAL_CALL")), emptyList())
        val computed = site(0x1020, addr(1, 0x1000), 8, "COMPUTED_CALL", "ff15da0f0000", emptyList(),
            listOf(reference(1, 0x1020, target(1, 0x2000), 9, "INDIRECTION")),
            listOf(neighborhood(0, 1, 0x2000, listOf(reference(1, 0x2000, externalTarget(), 101, "READ")))))
        val unowned = site(0x1300, JsonNull, 8, "COMPUTED_CALL", "ffd0", emptyList(), emptyList(), emptyList())
        return recount(obj("schemaVersion" to num(1), "policy" to str("ghidra-native-call-observations-v1"),
            "addressSpaces" to JsonArray(listOf(space(0, "EXTERNAL", 10), space(1, "ram", 1), space(2, "code", 2), space(3, "overlay", 1, true))),
            "bindings" to obj("collectorSha256" to str(BINDINGS.collectorSha256), "compilerSpecId" to str(BINDINGS.compilerSpecId),
                "ghidraArchiveSha256" to str(BINDINGS.ghidraArchiveSha256), "imageBase" to addr(1, 0x1000),
                "inputSha256" to str(BINDINGS.inputSha256), "languageId" to str(BINDINGS.languageId), "programModelBytes" to num(BINDINGS.programModelBytes),
                "programModelExporterSha256" to str(BINDINGS.programModelExporterSha256), "programModelSha256" to str(BINDINGS.programModelSha256)),
            "records" to JsonArray(functions + listOf(direct, computed, unowned)), "summary" to JsonNull))
    }

    internal fun recount(document: JsonObject): JsonObject {
        val raw = (document.getValue("records") as JsonArray).map { it as JsonObject }
        fun text(item: JsonObject, key: String) = (item.getValue(key) as JsonPrimitive).content
        fun coordinate(item: JsonObject, key: String): String {
            val value = item.getValue(key) as JsonObject
            return (value.getValue("spaceIndex") as JsonPrimitive).content.padStart(3, '0') + ":" + (value.getValue("offsetBits") as JsonPrimitive).content
        }
        val functions = raw.filter { text(it, "recordKind") == "function" }.sortedBy { coordinate(it, "entry") }
        val sites = raw.filter { text(it, "recordKind") == "site" }.sortedBy { coordinate(it, "address") }
        fun count(items: List<JsonObject>, kind: String) = items.count { text(it, "observationKind") == kind }.toLong()
        val summaries = functions.map { function ->
            val owned = sites.filter { it["owner"] == function["entry"] }
            obj("recordKind" to str("function-summary"), "entry" to function.getValue("entry"), "instructionsVisited" to num(maxOf(1, owned.size)),
                "prototypeCalls" to num(count(owned, "prototype-call")), "analysisCallCandidates" to num(count(owned, "analysis-call-candidate")),
                "directTailCandidates" to num(count(owned, "direct-tail-candidate")), "ordinaryJumpInstructions" to num(0), "unresolvedComputedJumps" to num(0))
        }
        val unowned = sites.filter { it["owner"] == JsonNull }
        val ownedInstructions = summaries.sumOf { (it.getValue("instructionsVisited") as JsonPrimitive).content.toLong() }
        val summary = obj("coverage" to str("all-currently-listed-instructions-and-recovered-functions"), "functions" to num(functions.size),
            "thunks" to num(functions.count { it["isThunk"] == JsonPrimitive(true) }), "instructionsVisited" to num(ownedInstructions + unowned.size),
            "ownedInstructions" to num(ownedInstructions), "unownedInstructions" to num(unowned.size), "sites" to num(sites.size),
            "prototypeCalls" to num(count(sites, "prototype-call")), "analysisCallCandidates" to num(count(sites, "analysis-call-candidate")),
            "directTailCandidates" to num(count(sites, "direct-tail-candidate")), "ordinaryJumpInstructions" to num(0), "unresolvedComputedJumps" to num(0),
            "directReferences" to num(sites.sumOf { (it.getValue("references") as JsonArray).size }),
            "neighborhoodReferences" to num(sites.sumOf { (it.getValue("referenceNeighborhoods") as JsonArray).sumOf { n -> ((n as JsonObject).getValue("references") as JsonArray).size } }),
            "unownedPrototypeCalls" to num(count(unowned, "prototype-call")), "unownedAnalysisCallCandidates" to num(count(unowned, "analysis-call-candidate")),
            "unownedDirectTailCandidates" to num(count(unowned, "direct-tail-candidate")))
        return JsonObject(document + ("records" to JsonArray(functions + sites + summaries)) + ("summary" to summary))
    }

    internal fun mutateSite(document: JsonObject, index: Int, transform: (JsonObject) -> Map<String, JsonElement>): JsonObject = mutateRecord(document, "site", index, transform)
    internal fun mutateFunction(document: JsonObject, index: Int, transform: (JsonObject) -> Map<String, JsonElement>): JsonObject = mutateRecord(document, "function", index, transform)
    private fun mutateRecord(document: JsonObject, kind: String, index: Int, transform: (JsonObject) -> Map<String, JsonElement>): JsonObject {
        var ordinal = -1
        val rows = (document.getValue("records") as JsonArray).map { raw ->
            val record = raw as JsonObject
            if (record["recordKind"] == str(kind) && ++ordinal == index) JsonObject(transform(record)) else record
        }
        return recount(JsonObject(document + ("records" to JsonArray(rows))))
    }
    internal fun replace(document: JsonObject, path: List<Any>, value: JsonElement): JsonObject {
        fun visit(element: JsonElement, depth: Int): JsonElement {
            if (depth == path.size) return value
            return when (val key = path[depth]) {
                is String -> JsonObject((element as JsonObject) + (key to visit(element.getValue(key), depth + 1)))
                is Int -> JsonArray((element as JsonArray).mapIndexed { index, child -> if (index == key) visit(child, depth + 1) else child })
                else -> error("invalid fixture path")
            }
        }
        return visit(document, 0) as JsonObject
    }
    private fun function(offset: Long, target: JsonElement = JsonNull) = obj("recordKind" to str("function"), "entry" to addr(1, offset),
        "bodyAddressCount" to num(64), "bodyRangeCount" to num(1), "isThunk" to JsonPrimitive(target != JsonNull), "immediateThunkTarget" to target)
    private fun site(offset: Long, owner: JsonElement, code: Int, name: String, bytes: String, targets: List<JsonObject>, references: List<JsonObject>, neighborhoods: List<JsonObject>) = obj(
        "recordKind" to str("site"), "address" to addr(1, offset), "owner" to owner, "observationKind" to str("prototype-call"),
        "listedLength" to num(bytes.length / 2), "delaySlotDepth" to num(0), "lengthOverridden" to JsonPrimitive(false),
        "byteStatus" to str("available"), "instructionBytes" to str(bytes), "prototypeFlow" to flow(code, name), "effectiveFlow" to flow(code, name),
        "flowOverride" to str("NONE"), "prototypeFallThrough" to addr(1, offset + bytes.length / 2), "effectiveFallThrough" to addr(1, offset + bytes.length / 2),
        "prototypeTargets" to JsonArray(targets), "references" to JsonArray(references), "referenceNeighborhoods" to JsonArray(neighborhoods))
    private fun target(space: Int, offset: Long, entry: Boolean = false) = obj("address" to addr(space, offset),
        "functionEntry" to if (entry) addr(space, offset) else JsonNull, "external" to JsonNull, "memoryBlock" to JsonNull)
    private fun externalTarget(offset: Long = 0x80) = obj("address" to addr(0, offset), "functionEntry" to addr(0, offset),
        "external" to obj("externalSpaceAddress" to addr(0, offset), "externalProgramAddress" to JsonNull,
            "libraryName" to str("libfixture.so"), "label" to str("fixture_external"), "originalImportedName" to JsonNull, "source" to str("IMPORTED")),
        "memoryBlock" to JsonNull)
    private fun reference(fromSpace: Int, from: Long, target: JsonObject, code: Int, name: String) = obj("from" to addr(fromSpace, from), "target" to target,
        "operandIndex" to num(0), "primary" to JsonPrimitive(true), "source" to str("ANALYSIS"), "referenceType" to flow(code, name))
    private fun neighborhood(index: Int, space: Int, offset: Long, references: List<JsonObject>) = obj("viaReferenceIndex" to num(index), "source" to addr(space, offset), "references" to JsonArray(references))
    private fun space(index: Int, name: String, type: Int, overlay: Boolean = false) = obj("index" to num(index), "name" to str(name), "type" to num(type),
        "sizeBits" to num(64), "addressableUnitSize" to num(1), "overlay" to JsonPrimitive(overlay), "signedOffsets" to JsonPrimitive(false))
    private fun flow(code: Int, name: String) = obj("code" to num(code), "name" to str(name))
    private fun addr(space: Int, offset: Long) = obj("kind" to str("address"), "spaceIndex" to num(space), "offsetBits" to str(offset.toULong().toString(16).padStart(16, '0')))
    private fun address(space: Int, offset: Long) = NativeCallAddressV1(space, offset.toULong().toString(16).padStart(16, '0'))
    private fun manifest(bytes: ByteArray) = canonical(obj("schemaVersion" to num(1), "kind" to str("ghidra-native-call-observation-manifest-v1"),
        "file" to str("native-calls.json"), "bytes" to num(bytes.size), "sha256" to str(OracleArtifacts.sha256(bytes)), "inputSha256" to str(BINDINGS.inputSha256),
        "programModelSha256" to str(BINDINGS.programModelSha256), "collectorSha256" to str(BINDINGS.collectorSha256)))
    private fun freeze(document: JsonObject): FrozenNativeExternalClaimsSnapshotV1 {
        val bytes = canonical(document)
        return FrozenNativeExternalClaimsV1.freeze(manifest(bytes), bytes, BINDINGS)
    }
    private fun canonical(value: JsonElement) = OracleJson.canonicalBytes(value)
    private fun obj(vararg pairs: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*pairs))
    private fun str(value: String) = JsonPrimitive(value)
    private fun num(value: Int) = JsonPrimitive(value)
    private fun num(value: Long) = JsonPrimitive(value)
    internal companion object {
        val BINDINGS = NativeCallBindingsV1("a".repeat(64), "gcc", "b".repeat(64), NativeCallAddressV1(1, "0000000000001000"),
            "c".repeat(64), "x86:LE:64:default", 100, "d".repeat(64), "e".repeat(64))
    }
}

/** Shared authored native envelope; callers can rebind documents explicitly without oracle inputs. */
internal data class NativeExternalFixtureV1(val document: JsonObject, val bindings: NativeCallBindingsV1) {
    fun observationBytes(): ByteArray = OracleJson.canonicalBytes(document)
    fun manifestBytes(observationBytes: ByteArray = this.observationBytes()): ByteArray = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive("ghidra-native-call-observation-manifest-v1"),
        "file" to JsonPrimitive("native-calls.json"), "bytes" to JsonPrimitive(observationBytes.size),
        "sha256" to JsonPrimitive(OracleArtifacts.sha256(observationBytes)), "inputSha256" to JsonPrimitive(bindings.inputSha256),
        "programModelSha256" to JsonPrimitive(bindings.programModelSha256), "collectorSha256" to JsonPrimitive(bindings.collectorSha256),
    )))
    fun withSite(index: Int, transform: (JsonObject) -> Map<String, JsonElement>): NativeExternalFixtureV1 =
        copy(document = FrozenNativeExternalClaimsV1Test().mutateSite(document, index, transform))
    fun withFunction(index: Int, transform: (JsonObject) -> Map<String, JsonElement>): NativeExternalFixtureV1 =
        copy(document = FrozenNativeExternalClaimsV1Test().mutateFunction(document, index, transform))
    fun replace(path: List<Any>, value: JsonElement): NativeExternalFixtureV1 =
        copy(document = FrozenNativeExternalClaimsV1Test().replace(document, path, value))
    fun recount(): NativeExternalFixtureV1 = copy(document = FrozenNativeExternalClaimsV1Test().recount(document))
}

internal fun nativeExternalFixtureV1(): NativeExternalFixtureV1 =
    NativeExternalFixtureV1(FrozenNativeExternalClaimsV1Test().fixture(), FrozenNativeExternalClaimsV1Test.BINDINGS)
