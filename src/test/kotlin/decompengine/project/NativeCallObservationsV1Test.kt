package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDataTruthException
import java.io.ByteArrayInputStream
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

/** Authored documents exercise byte assessment; they are not native or production qualification. */
class NativeCallObservationsV1Test {
    @Test
    fun `descriptor stream preserves repeated sites unowned provenance zero-site functions and immediate thunks`() {
        val document = fixture()
        val bytes = canonical(document)
        val seen = mutableListOf<NativeCallRecordV1>()
        val stream = TrackedStream(bytes)
        var opens = 0
        val result = NativeCallObservationsV1.validate(
            manifest(bytes), BINDINGS, checkpoint = {},
            openObservations = { opens++; stream }, consume = seen::add,
        )

        assertEquals(1, opens)
        assertTrue(stream.closed)
        assertEquals(9, seen.size)
        assertEquals(9L, result.records)
        assertEquals(bytes.size.toLong(), result.observationsBytes)
        assertEquals(sha256(bytes), result.observationsSha256)
        assertEquals(BINDINGS, result.bindings)
        assertEquals(listOf(10, 1, 2, 7), result.addressSpaces.map { it.type })
        assertFalse(result.authoritativeOracleEvidence)
        assertFalse(result.recoveredModelScored)
        assertFalse(result.releaseEligible)

        val functions = seen.filterIsInstance<NativeCallFunctionRecordV1>()
        assertEquals(address(1, 0x10), functions.first().entry)
        assertEquals(address(1, 0x10), functions.last().immediateThunkTarget?.address)
        assertTrue(functions.last().isThunk)
        val sites = seen.filterIsInstance<NativeCallSiteRecordV1>()
        assertEquals(listOf(address(1, 0x11), address(1, 0x12), address(1, 0x40)), sites.map { it.address })
        assertEquals(listOf(address(1, 0x20), address(1, 0x20)), sites.take(2).map { it.prototypeTargets.single().functionEntry })
        assertEquals(null, sites.last().owner)
        val indirect = sites.last()
        assertEquals(emptyList(), indirect.prototypeTargets)
        assertEquals(listOf(0, 1, 2), indirect.referenceNeighborhoods.map { it.viaReferenceIndex })
        assertTrue(indirect.referenceNeighborhoods.drop(1).all { it.references.isEmpty() })
        val external = indirect.referenceNeighborhoods.first().references.single().target.external!!
        assertEquals("libfixture", external.libraryName)
        assertEquals("imported_symbol", external.label)
        assertEquals(null, external.originalImportedName)
        assertEquals(address(0, 0x80), external.externalSpaceAddress)
        assertEquals(0L, seen.filterIsInstance<NativeCallFunctionSummaryRecordV1>()[1].prototypeCalls)
        assertEquals(5L, result.scanSummary.directReferences)
        assertEquals(1L, result.scanSummary.neighborhoodReferences)
        assertEquals(1L, result.scanSummary.unownedPrototypeCalls)
    }

    @Test
    fun `native table order and signed offsets govern all record phases`() {
        val document = signedFixture()
        val seen = mutableListOf<NativeCallRecordV1>()
        assess(document, consume = seen::add)
        assertEquals(
            listOf(address(1, 0x10), address(2, 0x10), address(3, -3), address(3, 0)),
            seen.filterIsInstance<NativeCallFunctionRecordV1>().map { it.entry },
        )
        assertEquals(
            listOf(address(1, 0x11), address(2, 0x11), address(3, -2), address(3, 1)),
            seen.filterIsInstance<NativeCallSiteRecordV1>().map { it.address },
        )
        listOf(0 to 1, 2 to 3, 4 to 5, 6 to 7, 8 to 9, 10 to 11).forEach { (a, b) ->
            reject("reordered records $a/$b", reorder(document, a, b))
        }
        reject("unsigned interpretation of signed offsets", set(document, JsonPrimitive(false), "addressSpaces", 3, "signedOffsets"))
    }

    @Test
    fun `closed objects and native enums reject metadata substitutions`() {
        val document = fixture()
        val objectPaths = listOf(
            emptyList(), listOf("addressSpaces", 0), listOf("bindings"), listOf("records", 0),
            listOf("records", 3), listOf("records", 3, "address"), listOf("records", 3, "prototypeFlow"),
            listOf("records", 5, "references", 0), listOf("records", 5, "references", 0, "target"),
            listOf("records", 5, "referenceNeighborhoods", 0),
            listOf("records", 5, "referenceNeighborhoods", 0, "references", 0, "target", "external"),
            listOf("records", 5, "references", 0, "target", "memoryBlock"), listOf("records", 6), listOf("summary"),
        )
        objectPaths.forEach { path ->
            reject("extra field at $path", edit(document, path) { obj -> JsonObject((obj as JsonObject) + ("authority" to JsonPrimitive(true))) })
        }
        listOf(
            set(document, referenceType(3, "COMPUTED_CALL"), "records", 3, "prototypeFlow"),
            set(document, referenceType(108, "READ"), "records", 5, "references", 1, "referenceType"),
            set(document, JsonPrimitive("TRUSTED"), "records", 5, "references", 0, "source"),
            set(document, JsonPrimitive("CALL_AND_RETURN"), "records", 3, "flowOverride"),
            set(document, JsonPrimitive("direct-call"), "records", 3, "observationKind"),
            set(document, JsonPrimitive("3"), "records", 3, "prototypeFlow", "code"),
            set(document, JsonPrimitive("false"), "records", 0, "isThunk"),
            set(document, JsonPrimitive(1), "addressSpaces", 0, "index"),
            set(document, JsonPrimitive("ram"), "addressSpaces", 2, "name"),
            set(document, JsonPrimitive(65), "addressSpaces", 1, "sizeBits"),
            set(document, JsonPrimitive(0), "addressSpaces", 1, "addressableUnitSize"),
        ).forEachIndexed { index, mutation -> reject("enum or scalar substitution $index", mutation) }
        listOf(listOf("bindings") to "inputSha256", listOf("records", 3) to "prototypeFallThrough", listOf("records", 5, "referenceNeighborhoods", 1) to "references").forEach { (path, field) ->
            reject("missing closed field $field", edit(document, path) { JsonObject((it as JsonObject) - field) })
        }
        val bytes = canonical(document)
        val badManifest = JsonObject(manifestObject(bytes) + ("authority" to JsonPrimitive(true)))
        assertFails { assessBytes(bytes, canonical(badManifest)) }
    }

    @Test
    fun `record uniqueness phases inventory ownership and exact targets are enforced`() {
        val document = fixture()
        val records = records(document)
        val mutations = listOf(
            replaceRecords(document, records.toMutableList().apply { this[1] = this[0] }),
            replaceRecords(document, records.toMutableList().apply { this[4] = this[3] }),
            replaceRecords(document, records.toMutableList().apply { this[7] = this[6] }),
            reorder(document, 2, 3), reorder(document, 5, 6),
            replaceRecords(document, records.dropLast(1)),
            set(document, addr(1, 0x99), "records", 3, "owner"),
            set(document, noAddress(), "records", 3, "owner"),
            set(document, addr(1, 0x21), "records", 3, "prototypeTargets", 0, "functionEntry"),
            set(document, target(1, 0x20, functionEntry = addr(1, 0x20)), "records", 0, "immediateThunkTarget"),
            set(document, JsonPrimitive(2), "records", 1, "bodyRangeCount"),
        )
        mutations.forEachIndexed { index, mutation -> reject("record or ownership mutation $index", mutation) }
        // Coverage stays valid and reject() recomputes the digest; these lose required thunk metadata.
        reject("thunk without immediate target", set(document, JsonNull, "records", 2, "immediateThunkTarget"))
        reject("thunk target without exact function entry", set(document, JsonNull, "records", 2, "immediateThunkTarget", "functionEntry"))

        // All counters and ordering still match; EXTERNAL functions alone violate the inventory contract.
        var externalFunction = set(document, addr(0, 0x80), "records", 0, "entry")
        externalFunction = set(externalFunction, addr(0, 0x80), "records", 3, "owner")
        externalFunction = set(externalFunction, addr(0, 0x80), "records", 4, "owner")
        externalFunction = set(externalFunction, addr(0, 0x80), "records", 6, "entry")
        reject("EXTERNAL function inventory", externalFunction)
    }

    @Test
    fun `local target identity agrees with exhaustive inventory including forward thunks`() {
        val document = fixture()
        val targetPaths = listOf(
            listOf("records", 3, "prototypeTargets", 0),
            listOf("records", 3, "references", 0, "target"),
            listOf("records", 2, "immediateThunkTarget"),
        )
        for (path in targetPaths) {
            // Both fields agree with each other, but the claimed function is absent from inventory.
            reject("unknown local function at $path", edit(document, path) { target(1, 0x99, functionEntry = addr(1, 0x99)) })
            reject("known local function identity omitted at $path", edit(document, path + "functionEntry") { JsonNull })
        }
        val neighborPath = listOf("records", 5, "referenceNeighborhoods", 0, "references", 0, "target")
        val knownNeighbor = edit(document, neighborPath) { target(1, 0x20, functionEntry = addr(1, 0x20)) }
        assess(knownNeighbor)
        reject("unknown neighborhood function", edit(document, neighborPath) { target(1, 0x99, functionEntry = addr(1, 0x99)) })
        reject("known neighborhood function identity omitted", edit(knownNeighbor, neighborPath + "functionEntry") { JsonNull })

        var forwardThunk = set(document, JsonPrimitive(true), "records", 0, "isThunk")
        forwardThunk = set(forwardThunk, target(1, 0x30, functionEntry = addr(1, 0x30)), "records", 0, "immediateThunkTarget")
        forwardThunk = set(forwardThunk, JsonPrimitive(false), "records", 2, "isThunk")
        forwardThunk = set(forwardThunk, JsonNull, "records", 2, "immediateThunkTarget")
        assertEquals(1L, assess(forwardThunk).scanSummary.thunks)
        reject("unknown forward thunk function", set(forwardThunk, target(1, 0x99, functionEntry = addr(1, 0x99)), "records", 0, "immediateThunkTarget"))
    }

    @Test
    fun `external program address is nullable loaded memory rather than a synthetic coordinate`() {
        val document = fixture()
        val path = listOf("records", 5, "referenceNeighborhoods", 0, "references", 0, "target", "external", "externalProgramAddress")
        assess(edit(document, path) { JsonNull })
        assess(edit(document, path) { addr(2, 0x500) })
        listOf(addr(0, 0x80), noAddress(), addr(3, -1)).forEach { address ->
            reject("synthetic external program address $address", edit(document, path) { address })
        }
        val registerSpaces = edit(document, listOf("addressSpaces")) { JsonArray((it as JsonArray) + space(4, "register", 4)) }
        assess(registerSpaces)
        reject("register external program address", edit(registerSpaces, path) { addr(4, 0) })
    }

    @Test
    fun `typed one-hop observations require every eligible empty neighborhood`() {
        val document = fixture()
        for (index in 0..2) {
            reject("missing memory neighborhood $index", edit(document, listOf("records", 5, "referenceNeighborhoods")) {
                JsonArray((it as JsonArray).filterIndexed { i, _ -> i != index })
            })
        }
        val mutations = listOf(
            set(document, JsonPrimitive(3), "records", 5, "referenceNeighborhoods", 2, "viaReferenceIndex"),
            set(document, addr(2, 0x201), "records", 5, "referenceNeighborhoods", 1, "source"),
            set(document, addr(1, 0x101), "records", 5, "referenceNeighborhoods", 0, "references", 0, "from"),
            set(document, referenceType(3, "UNCONDITIONAL_CALL"), "records", 5, "references", 1, "referenceType"),
            set(document, JsonPrimitive(10), "addressSpaces", 2, "type"),
            set(document, JsonPrimitive(1), "addressSpaces", 0, "type"),
            set(document, addr(0, 0x81), "records", 5, "referenceNeighborhoods", 0, "references", 0, "target", "external", "externalSpaceAddress"),
            set(document, block(0, 0x80, 0x80), "records", 5, "referenceNeighborhoods", 0, "references", 0, "target", "memoryBlock"),
            set(document, addr(1, 0x101), "records", 5, "references", 0, "target", "memoryBlock", "start"),
        )
        mutations.forEachIndexed { index, mutation -> reject("one-hop provenance mutation $index", mutation) }
        reject("duplicate references", edit(document, listOf("records", 5, "references")) {
            val refs = it as JsonArray
            JsonArray(listOf(refs[0], refs[0], refs[2]))
        })
        reject("reordered references", edit(document, listOf("records", 5, "references")) { JsonArray((it as JsonArray).reversed()) })
        reject("reordered neighborhoods", edit(document, listOf("records", 5, "referenceNeighborhoods")) { JsonArray((it as JsonArray).reversed()) })
    }

    @Test
    fun `counts reject invented coverage and overflowing arithmetic`() {
        val document = fixture()
        listOf(
            "functions" to 4L, "thunks" to 2L, "sites" to 4L, "prototypeCalls" to 4L,
            "analysisCallCandidates" to 1L, "directTailCandidates" to 1L,
            "ownedInstructions" to 7L, "instructionsVisited" to 9L, "unownedInstructions" to 0L,
            "directReferences" to 6L, "neighborhoodReferences" to 2L,
            "unownedPrototypeCalls" to 0L, "ordinaryJumpInstructions" to 0L, "unresolvedComputedJumps" to 1L,
        ).forEach { (field, value) -> reject("invented $field", set(document, JsonPrimitive(value), "summary", field)) }
        reject("wrong function coverage", set(document, JsonPrimitive(1), "records", 6, "prototypeCalls"))
        reject("impossible visited instruction count", set(document, JsonPrimitive(1), "records", 6, "instructionsVisited"))
        reject("other coverage label", set(document, JsonPrimitive("complete-binary-decoding"), "summary", "coverage"))
        // Without checked arithmetic, 1 + Long.MAX_VALUE wraps negative in both coverage predicates.
        reject("coverage addition overflow", singleFixture(ordinaryJumps = Long.MAX_VALUE))
    }

    @Test
    fun `site categories require their own native evidence and preserve selection precedence`() {
        var analysis = set(fixture(), JsonPrimitive("analysis-call-candidate"), "records", 3, "observationKind")
        analysis = set(analysis, referenceType(6, "COMPUTED_JUMP"), "records", 3, "prototypeFlow")
        analysis = set(analysis, referenceType(8, "COMPUTED_CALL"), "records", 3, "effectiveFlow")
        analysis = categoryCounts(analysis, "analysisCallCandidates")
        assertEquals(1L, assess(analysis).scanSummary.analysisCallCandidates)
        reject("prototype call mislabeled as analysis", set(analysis, referenceType(3, "UNCONDITIONAL_CALL"), "records", 3, "prototypeFlow"))
        var noAnalysisEvidence = set(analysis, referenceType(6, "COMPUTED_JUMP"), "records", 3, "effectiveFlow")
        noAnalysisEvidence = set(noAnalysisEvidence, referenceType(1, "UNCONDITIONAL_JUMP"), "records", 3, "references", 0, "referenceType")
        reject("invented analysis call", noAnalysisEvidence)

        var tail = set(fixture(), JsonPrimitive("direct-tail-candidate"), "records", 3, "observationKind")
        tail = set(tail, referenceType(1, "UNCONDITIONAL_JUMP"), "records", 3, "prototypeFlow")
        tail = set(tail, referenceType(1, "UNCONDITIONAL_JUMP"), "records", 3, "effectiveFlow")
        tail = set(tail, referenceType(1, "UNCONDITIONAL_JUMP"), "records", 3, "references", 0, "referenceType")
        tail = categoryCounts(tail, "directTailCandidates")
        assertEquals(1L, assess(tail).scanSummary.directTailCandidates)
        reject("conditional branch mislabeled as tail", set(tail, referenceType(2, "CONDITIONAL_JUMP"), "records", 3, "prototypeFlow"))
        reject("computed switch mislabeled as tail", set(tail, referenceType(6, "COMPUTED_JUMP"), "records", 3, "prototypeFlow"))
        reject("tail without exact recovered entry", set(tail, JsonNull, "records", 3, "prototypeTargets", 0, "functionEntry"))
        reject("call reference mislabeled as tail", set(tail, referenceType(3, "UNCONDITIONAL_CALL"), "records", 3, "references", 0, "referenceType"))
        val sameOwner = set(tail, JsonArray(listOf(target(1, 0x10, functionEntry = addr(1, 0x10)))), "records", 3, "prototypeTargets")
        reject("internal branch mislabeled as tail", sameOwner)
    }

    @Test
    fun `all target and paired-model bindings must match despite a fresh payload digest`() {
        val document = fixture()
        val staleBindings = listOf(
            BINDINGS.copy(collectorSha256 = "f".repeat(64)), BINDINGS.copy(inputSha256 = "f".repeat(64)),
            BINDINGS.copy(programModelSha256 = "f".repeat(64)), BINDINGS.copy(programModelExporterSha256 = "f".repeat(64)),
            BINDINGS.copy(ghidraArchiveSha256 = "f".repeat(64)), BINDINGS.copy(programModelBytes = 101),
            BINDINGS.copy(imageBase = address(1, 1)), BINDINGS.copy(languageId = "other:LE:64:default"),
            BINDINGS.copy(compilerSpecId = "other"),
        )
        staleBindings.forEach { expected -> assertFails { assess(document, expected = expected) } }
        val bytes = canonical(document)
        listOf("collectorSha256", "inputSha256", "programModelSha256", "sha256").forEach { field ->
            val staleManifest = JsonObject(manifestObject(bytes) + (field to JsonPrimitive("f".repeat(64))))
            assertFails("stale manifest $field") { assessBytes(bytes, canonical(staleManifest)) }
        }
        for (count in listOf(bytes.size - 1L, bytes.size + 1L)) {
            assertFails("wrong exact length $count") { assessBytes(bytes, canonical(JsonObject(manifestObject(bytes) + ("bytes" to JsonPrimitive(count))))) }
        }
        assertFails { assessBytes(bytes.copyOf(bytes.size - 1), manifest(bytes)) }
        assertFails { assessBytes(bytes + byteArrayOf(' '.code.toByte()), manifest(bytes)) }
        reject("malformed digest", set(document, JsonPrimitive("A".repeat(64)), "bindings", "inputSha256"))
    }

    @Test
    fun `instruction boundaries remain target neutral and unsupported bytes stay absent`() {
        val document = fixture()
        val longInstruction = set(set(document, JsonPrimitive(32), "records", 3, "listedLength"), JsonPrimitive("ab".repeat(32)), "records", 3, "instructionBytes")
        val sites = mutableListOf<NativeCallRecordV1>()
        assess(longInstruction, consume = sites::add)
        assertEquals(32, sites.filterIsInstance<NativeCallSiteRecordV1>().first().listedLength)
        for ((field, value) in listOf("delaySlotDepth" to JsonPrimitive(1), "lengthOverridden" to JsonPrimitive(true), "listedLength" to JsonPrimitive(4097))) {
            var unsupported = set(document, value, "records", 3, field)
            unsupported = set(unsupported, JsonPrimitive("unsupported-boundary"), "records", 3, "byteStatus")
            unsupported = set(unsupported, JsonNull, "records", 3, "instructionBytes")
            assess(unsupported)
            reject("unsupported boundary leaks bytes $field", set(unsupported, JsonPrimitive("90"), "records", 3, "instructionBytes"))
        }
        reject("wrong byte length", set(document, JsonPrimitive("90"), "records", 3, "instructionBytes"))
        reject("uppercase instruction hex", set(document, JsonPrimitive("ABCD"), "records", 3, "instructionBytes"))
        reject("supported boundary lacks bytes", set(document, JsonNull, "records", 3, "instructionBytes"))
        reject("uppercase coordinate", set(document, JsonPrimitive("00000000000000AF"), "records", 3, "address", "offsetBits"))
        reject("unrepresented space", set(document, JsonPrimitive(4), "records", 3, "address", "spaceIndex"))
    }

    @Test
    fun `bounded parser fails rather than truncating any inventory`() {
        val document = fixture()
        val bytes = canonical(document)
        val manifest = manifest(bytes)
        val limits = listOf(
            NativeCallObservationLimitsV1(maximumCombinedBytes = bytes.size.toLong() + manifest.size - 1),
            NativeCallObservationLimitsV1(maximumManifestBytes = manifest.size - 1),
            NativeCallObservationLimitsV1(maximumFunctions = 2), NativeCallObservationLimitsV1(maximumSites = 2),
            NativeCallObservationLimitsV1(maximumInstructions = 7), NativeCallObservationLimitsV1(maximumAddressSpaces = 3),
            NativeCallObservationLimitsV1(maximumReferencesPerSource = 2), NativeCallObservationLimitsV1(maximumReferencesPerSite = 3),
            NativeCallObservationLimitsV1(maximumRecordBytes = 256, maximumStringBytes = 128),
            NativeCallObservationLimitsV1(maximumStringBytes = 63), NativeCallObservationLimitsV1(maximumDepth = 2),
        )
        limits.forEach { bound -> assertFails("overflow of $bound") { assess(document, limits = bound) } }
        val twoTargets = set(document, JsonArray(listOf(target(1, 0x20, functionEntry = addr(1, 0x20)), target(1, 0x30, functionEntry = addr(1, 0x30)))), "records", 3, "prototypeTargets")
        assertFails { assess(twoTargets, limits = NativeCallObservationLimitsV1(maximumPrototypeTargets = 1)) }
    }

    @Test
    fun `record ceiling below instruction string maximum accepts exact size and rejects one byte less`() {
        var document = singleFixture(ordinaryJumps = 0)
        document = edit(document, listOf("addressSpaces")) { JsonArray((it as JsonArray).take(2)) }
        document = set(document, JsonPrimitive(256), "records", 1, "listedLength")
        document = set(document, JsonPrimitive("ab".repeat(256)), "records", 1, "instructionBytes")
        val siteBytes = canonical(records(document)[1]).size
        val otherMaximum = (document.filterKeys { it != "records" }.values + records(document).filterIndexed { index, _ -> index != 1 }).maxOf { canonical(it).size }
        assertTrue(siteBytes < 8192, "positive control must exercise a record cap below the instruction-string ceiling")
        assertTrue(siteBytes - 1 > otherMaximum, "negative bound must admit every other record and envelope")
        assertTrue(siteBytes - 1 > 256, "negative bound must admit the metadata-string setting")
        val exact = NativeCallObservationLimitsV1(maximumRecordBytes = siteBytes, maximumStringBytes = 256)
        assertEquals(3L, assess(document, limits = exact).records)
        val failure = assertFailsWith<FullTreeDataTruthException> { assess(document, limits = exact.copy(maximumRecordBytes = siteBytes - 1)) }
        assertTrue(failure.message.orEmpty().contains("entity exceeds strict JSON limits"), failure.message)
    }

    @Test
    fun `cancellation closes the retained stream and cannot return a successful assessment`() {
        val bytes = canonical(fixture())
        val stream = TrackedStream(bytes)
        var checkpoints = 0
        val speculative = mutableListOf<NativeCallRecordV1>()
        val cancellation = TestCancellation()
        val failure = assertFailsWith<FullTreeDataTruthException> {
            NativeCallObservationsV1.validate(
                manifest(bytes), BINDINGS,
                checkpoint = { if (++checkpoints == 6) throw cancellation },
                openObservations = { stream }, consume = speculative::add,
            )
        }
        assertSame(cancellation, failure.cause)
        assertEquals("cannot stream native-call observations: test cancellation", failure.message)
        assertTrue(stream.closed)
        assertEquals(1, speculative.size)
    }

    @Test
    fun `noncanonical duplicate scalar and malformed UTF8 documents are rejected even with matching digests`() {
        val bytes = canonical(fixture())
        val text = bytes.toString(Charsets.UTF_8)
        val malformed = listOf(
            " $text".toByteArray(),
            replaceFixtureText(text, "\"schemaVersion\": 1", "\"schemaVersion\": 1,\"schemaVersion\": 1"),
            replaceFixtureText(text, "\"bodyRangeCount\": 1", "\"bodyRangeCount\": 1,\"bodyRangeCount\": 1"),
            replaceFixtureText(text, "\"schemaVersion\": 1", "\"schemaVersion\": 1.0"),
            replaceFixtureText(text, "\"schemaVersion\": 1", "\"schemaVersion\": 01"),
            bytes.copyOf().also { it[text.indexOf("libfixture")] = 0xc3.toByte() },
        )
        malformed.forEachIndexed { index, mutation ->
            assertFalse(bytes.contentEquals(mutation), "malformed observations $index must change the bytes")
            assertFails("malformed observations $index") { assessBytes(mutation, manifest(mutation)) }
        }
        val originalManifest = manifest(bytes)
        val whitespaceManifest = " ${originalManifest.toString(Charsets.UTF_8)}".toByteArray()
        assertFalse(originalManifest.contentEquals(whitespaceManifest))
        assertFails { assessBytes(bytes, whitespaceManifest) }
        val duplicateManifest = replaceFixtureText(originalManifest.toString(Charsets.UTF_8), "\"schemaVersion\": 1", "\"schemaVersion\": 1,\"schemaVersion\": 1")
        assertFalse(originalManifest.contentEquals(duplicateManifest))
        assertFails { assessBytes(bytes, duplicateManifest) }
    }

    private fun fixture(): JsonObject {
        val caller = addr(1, 0x10)
        val indirect = site(1, 0x40, JsonNull, referenceType(8, "COMPUTED_CALL"), emptyList(), listOf(
            reference(addr(1, 0x40), target(1, 0x100, memoryBlock = block(1, 0x100, 0x107)), 0, referenceType(9, "INDIRECTION")),
            reference(addr(1, 0x40), target(2, 0x200), 1, referenceType(101, "READ")),
            reference(addr(1, 0x40), target(3, -1), 2, referenceType(100, "DATA")),
        ), listOf(
            neighborhood(0, addr(1, 0x100), listOf(reference(addr(1, 0x100), externalTarget(), 0, referenceType(101, "READ")))),
            neighborhood(1, addr(2, 0x200), emptyList()), neighborhood(2, addr(3, -1), emptyList()),
        ))
        return root(listOf(
            function(caller, 10), function(addr(1, 0x20), 1), function(addr(1, 0x30), 1, target(1, 0x10, functionEntry = caller)),
            directSite(1, 0x11, caller, 1, 0x20), directSite(1, 0x12, caller, 1, 0x20), indirect,
            functionSummary(caller, 4, 2, ordinaryJumps = 1), functionSummary(addr(1, 0x20), 1, 0), functionSummary(addr(1, 0x30), 1, 0),
        ), scan(functions = 3, thunks = 1, instructions = 8, owned = 6, unowned = 2, sites = 3, prototypeCalls = 3, ordinaryJumps = 1, directReferences = 5, neighborhoodReferences = 1, unownedPrototypeCalls = 1))
    }

    private fun signedFixture(): JsonObject {
        val entries = listOf(addr(1, 0x10), addr(2, 0x10), addr(3, -3), addr(3, 0))
        return root(entries.map { function(it, 2) } + listOf(
            directSite(1, 0x11, entries[0], 1, 0x10), directSite(2, 0x11, entries[1], 1, 0x10),
            directSite(3, -2, entries[2], 1, 0x10), directSite(3, 1, entries[3], 1, 0x10),
        ) + entries.map { functionSummary(it, 1, 1) }, scan(functions = 4, instructions = 4, owned = 4, sites = 4, prototypeCalls = 4, directReferences = 4))
    }

    private fun singleFixture(ordinaryJumps: Long): JsonObject {
        val entry = addr(1, 0x10)
        return root(listOf(function(entry, 2), directSite(1, 0x11, entry, 1, 0x10), functionSummary(entry, 1, 1, ordinaryJumps)), scan(functions = 1, instructions = 1, owned = 1, sites = 1, prototypeCalls = 1, ordinaryJumps = ordinaryJumps, directReferences = 1))
    }

    private fun root(records: List<JsonElement>, scan: JsonObject) = objectOf(
        "addressSpaces" to JsonArray(listOf(space(0, "EXTERNAL", 10), space(1, "ram", 1), space(2, "code", 2), space(3, "other", 7, signed = true))),
        "bindings" to objectOf(
            "collectorSha256" to JsonPrimitive(BINDINGS.collectorSha256), "compilerSpecId" to JsonPrimitive(BINDINGS.compilerSpecId),
            "ghidraArchiveSha256" to JsonPrimitive(BINDINGS.ghidraArchiveSha256), "imageBase" to addr(1, 0),
            "inputSha256" to JsonPrimitive(BINDINGS.inputSha256), "languageId" to JsonPrimitive(BINDINGS.languageId),
            "programModelBytes" to JsonPrimitive(BINDINGS.programModelBytes), "programModelExporterSha256" to JsonPrimitive(BINDINGS.programModelExporterSha256), "programModelSha256" to JsonPrimitive(BINDINGS.programModelSha256),
        ),
        "policy" to JsonPrimitive("ghidra-native-call-observations-v1"), "records" to JsonArray(records), "schemaVersion" to JsonPrimitive(1), "summary" to scan,
    )

    private fun space(index: Int, name: String, type: Int, signed: Boolean = false) = objectOf(
        "index" to JsonPrimitive(index), "name" to JsonPrimitive(name), "type" to JsonPrimitive(type), "sizeBits" to JsonPrimitive(64),
        "addressableUnitSize" to JsonPrimitive(1), "overlay" to JsonPrimitive(false), "signedOffsets" to JsonPrimitive(signed),
    )

    private fun function(entry: JsonObject, body: Long, thunkTarget: JsonElement = JsonNull) = objectOf(
        "recordKind" to JsonPrimitive("function"), "entry" to entry, "bodyAddressCount" to JsonPrimitive(body), "bodyRangeCount" to JsonPrimitive(1),
        "isThunk" to JsonPrimitive(thunkTarget != JsonNull), "immediateThunkTarget" to thunkTarget,
    )

    private fun directSite(space: Int, offset: Long, owner: JsonElement, targetSpace: Int, targetOffset: Long): JsonObject {
        val target = target(targetSpace, targetOffset, functionEntry = addr(targetSpace, targetOffset))
        return site(space, offset, owner, referenceType(3, "UNCONDITIONAL_CALL"), listOf(target), listOf(reference(addr(space, offset), target, 0, referenceType(3, "UNCONDITIONAL_CALL"))), emptyList())
    }

    private fun site(space: Int, offset: Long, owner: JsonElement, flow: JsonObject, targets: List<JsonObject>, references: List<JsonObject>, neighborhoods: List<JsonObject>) = objectOf(
        "recordKind" to JsonPrimitive("site"), "address" to addr(space, offset), "owner" to owner, "observationKind" to JsonPrimitive("prototype-call"),
        "listedLength" to JsonPrimitive(2), "delaySlotDepth" to JsonPrimitive(0), "lengthOverridden" to JsonPrimitive(false), "byteStatus" to JsonPrimitive("available"), "instructionBytes" to JsonPrimitive("9090"),
        "prototypeFlow" to flow, "effectiveFlow" to flow, "flowOverride" to JsonPrimitive("NONE"), "prototypeFallThrough" to JsonNull, "effectiveFallThrough" to JsonNull,
        "prototypeTargets" to JsonArray(targets), "references" to JsonArray(references), "referenceNeighborhoods" to JsonArray(neighborhoods),
    )

    private fun functionSummary(entry: JsonObject, instructions: Long, prototypeCalls: Long, ordinaryJumps: Long = 0) = objectOf(
        "recordKind" to JsonPrimitive("function-summary"), "entry" to entry, "instructionsVisited" to JsonPrimitive(instructions), "prototypeCalls" to JsonPrimitive(prototypeCalls),
        "analysisCallCandidates" to JsonPrimitive(0), "directTailCandidates" to JsonPrimitive(0), "ordinaryJumpInstructions" to JsonPrimitive(ordinaryJumps), "unresolvedComputedJumps" to JsonPrimitive(0),
    )

    private fun scan(functions: Long, thunks: Long = 0, instructions: Long, owned: Long, unowned: Long = 0, sites: Long, prototypeCalls: Long, ordinaryJumps: Long = 0, directReferences: Long, neighborhoodReferences: Long = 0, unownedPrototypeCalls: Long = 0) = objectOf(
        "coverage" to JsonPrimitive("all-currently-listed-instructions-and-recovered-functions"), "functions" to JsonPrimitive(functions), "thunks" to JsonPrimitive(thunks),
        "instructionsVisited" to JsonPrimitive(instructions), "ownedInstructions" to JsonPrimitive(owned), "unownedInstructions" to JsonPrimitive(unowned), "sites" to JsonPrimitive(sites), "prototypeCalls" to JsonPrimitive(prototypeCalls),
        "analysisCallCandidates" to JsonPrimitive(0), "directTailCandidates" to JsonPrimitive(0), "ordinaryJumpInstructions" to JsonPrimitive(ordinaryJumps), "unresolvedComputedJumps" to JsonPrimitive(0),
        "directReferences" to JsonPrimitive(directReferences), "neighborhoodReferences" to JsonPrimitive(neighborhoodReferences), "unownedPrototypeCalls" to JsonPrimitive(unownedPrototypeCalls), "unownedAnalysisCallCandidates" to JsonPrimitive(0), "unownedDirectTailCandidates" to JsonPrimitive(0),
    )

    private fun target(space: Int, offset: Long, functionEntry: JsonElement = JsonNull, memoryBlock: JsonElement = JsonNull) = objectOf("address" to addr(space, offset), "functionEntry" to functionEntry, "external" to JsonNull, "memoryBlock" to memoryBlock)

    private fun externalTarget() = objectOf("address" to addr(0, 0x80), "functionEntry" to JsonNull, "external" to objectOf(
        "externalSpaceAddress" to addr(0, 0x80), "externalProgramAddress" to addr(1, 0x500), "libraryName" to JsonPrimitive("libfixture"), "label" to JsonPrimitive("imported_symbol"), "originalImportedName" to JsonNull, "source" to JsonPrimitive("IMPORTED"),
    ), "memoryBlock" to JsonNull)

    private fun block(space: Int, start: Long, end: Long) = objectOf("name" to JsonPrimitive("pointer_slot"), "start" to addr(space, start), "end" to addr(space, end), "initialized" to JsonPrimitive(true), "executable" to JsonPrimitive(false))
    private fun reference(from: JsonObject, target: JsonObject, operand: Int, type: JsonObject) = objectOf("from" to from, "target" to target, "operandIndex" to JsonPrimitive(operand), "primary" to JsonPrimitive(true), "source" to JsonPrimitive("ANALYSIS"), "referenceType" to type)
    private fun neighborhood(index: Int, source: JsonObject, references: List<JsonObject>) = objectOf("viaReferenceIndex" to JsonPrimitive(index), "source" to source, "references" to JsonArray(references))
    private fun referenceType(code: Int, name: String) = objectOf("code" to JsonPrimitive(code), "name" to JsonPrimitive(name))
    private fun addr(space: Int, offset: Long) = objectOf("kind" to JsonPrimitive("address"), "spaceIndex" to JsonPrimitive(space), "offsetBits" to JsonPrimitive(offset.toULong().toString(16).padStart(16, '0')))
    private fun noAddress() = objectOf("kind" to JsonPrimitive("no-address"))
    private fun address(space: Int, offset: Long) = NativeCallAddressV1(space, offset.toULong().toString(16).padStart(16, '0'))
    private fun objectOf(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
    private fun records(document: JsonObject) = (document.getValue("records") as JsonArray).toList()
    private fun replaceRecords(document: JsonObject, records: List<JsonElement>) = JsonObject(document + ("records" to JsonArray(records)))
    private fun categoryCounts(document: JsonObject, category: String): JsonObject {
        var result = set(document, JsonPrimitive(1), "records", 6, "prototypeCalls")
        result = set(result, JsonPrimitive(1), "records", 6, category)
        result = set(result, JsonPrimitive(2), "summary", "prototypeCalls")
        return set(result, JsonPrimitive(1), "summary", category)
    }
    private fun reorder(document: JsonObject, a: Int, b: Int) = replaceRecords(document, records(document).toMutableList().apply { val first = this[a]; this[a] = this[b]; this[b] = first })
    private fun set(document: JsonObject, value: JsonElement, vararg path: Any) = edit(document, path.toList()) { value }
    private fun edit(document: JsonObject, path: List<Any>, transform: (JsonElement) -> JsonElement): JsonObject {
        fun replace(element: JsonElement, depth: Int): JsonElement {
            if (depth == path.size) return transform(element)
            return when (val key = path[depth]) {
                is String -> JsonObject((element as JsonObject) + (key to replace(element.getValue(key), depth + 1)))
                is Int -> JsonArray((element as JsonArray).mapIndexed { index, child -> if (index == key) replace(child, depth + 1) else child })
                else -> error("unsupported fixture path")
            }
        }
        return replace(document, 0) as JsonObject
    }

    private fun reject(label: String, document: JsonObject) { assertFails(label) { assess(document) } }
    private fun assess(document: JsonObject, expected: NativeCallBindingsV1 = BINDINGS, limits: NativeCallObservationLimitsV1 = NativeCallObservationLimitsV1(), consume: (NativeCallRecordV1) -> Unit = {}): NativeCallObservationSummaryV1 {
        val bytes = canonical(document)
        return NativeCallObservationsV1.validate(manifest(bytes), expected, limits, {}, { ByteArrayInputStream(bytes) }, consume)
    }
    private fun assessBytes(bytes: ByteArray, manifest: ByteArray) = NativeCallObservationsV1.validate(manifest, BINDINGS, checkpoint = {}, openObservations = { ByteArrayInputStream(bytes) })
    private fun manifest(bytes: ByteArray) = canonical(manifestObject(bytes))
    private fun manifestObject(bytes: ByteArray) = objectOf(
        "bytes" to JsonPrimitive(bytes.size), "collectorSha256" to JsonPrimitive(BINDINGS.collectorSha256), "file" to JsonPrimitive("native-calls.json"), "inputSha256" to JsonPrimitive(BINDINGS.inputSha256),
        "kind" to JsonPrimitive("ghidra-native-call-observation-manifest-v1"), "programModelSha256" to JsonPrimitive(BINDINGS.programModelSha256), "schemaVersion" to JsonPrimitive(1), "sha256" to JsonPrimitive(sha256(bytes)),
    )
    private fun canonical(value: JsonElement) = OracleJson.canonicalBytes(value)
    private fun replaceFixtureText(original: String, before: String, after: String): ByteArray {
        assertTrue(original.contains(before), "fixture must contain mutation target $before")
        val changed = original.replaceFirst(before, after)
        assertTrue(changed != original, "fixture text mutation must change the document")
        return changed.toByteArray(Charsets.UTF_8)
    }
    private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it.toInt() and 255) }
    private class TrackedStream(bytes: ByteArray) : ByteArrayInputStream(bytes) { var closed = false; override fun close() { closed = true; super.close() } }
    private class TestCancellation : RuntimeException("test cancellation")
    private companion object {
        val BINDINGS = NativeCallBindingsV1("a".repeat(64), "default", "b".repeat(64), NativeCallAddressV1(1, "0000000000000000"), "c".repeat(64), "fixture:LE:64:default", 100, "d".repeat(64), "e".repeat(64))
    }
}
