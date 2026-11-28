package decompengine.oracle.structural

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.*
import kotlinx.serialization.json.*

class StructuralCallPopulationV1Test {
    @Test
    fun `positive-only census never invents a negative or an oracle fact`() = fixture { boundary ->
        val report = derive(boundary, emptyList(), listOf(site(false, "r1", 0x18)))
        assertEquals(0, report.count("outcomes", "fabricated"))
        assertEquals(1, report.count("unresolvedRecoveredCount"))
        assertEquals(0, report.count("metrics", "oracleDenominator"))
        assertEquals(1, report.count("metrics", "recoveredDenominator"))
        assertEquals(JsonNull, report.obj("metrics")["oracleRecall"])
        assertEquals(0, report.obj("metrics").obj("claimPrecision").count("numerator"))
        assertEquals(emptyList(), report.rows("oracleSites"))
        for (flag in listOf("productionVerified", "scored", "complete", "releaseEligible", "negativeCoverageAuthenticated")) {
            assertEquals(JsonPrimitive(false), report[flag])
        }
    }

    @Test
    fun `missing unobservable and unresolved records conserve both denominators`() = fixture { boundary ->
        val oracle = listOf(site(true, "o1", 0x18), site(true, "o2", 0x28, targets = null),
            site(true, "o3", null), site(true, "o4", null, caller = null, targets = null))
        val recovered = listOf(site(false, "r1", 0x18, targets = null), site(false, "r2", 0x28),
            site(false, "r3", null, caller = null), site(false, "r4", null))
        val report = derive(boundary, oracle, recovered)
        assertEquals(4, report.count("metrics", "oracleDenominator"))
        assertEquals(4, report.count("metrics", "recoveredDenominator"))
        assertEquals(0, report.count("metrics", "exact"))
        assertEquals(2, report.count("outcomes", "oracle-unobservable"))
        assertEquals(2, report.count("outcomes", "recovered-unknown"))
        assertEquals(2, report.count("unresolvedRecoveredCount"))
        assertEquals(8, report.count("rawObservationCount"))
        assertEquals(8, report.count("rawObservationDispositionCount"))
    }

    @Test
    fun `caller mapping and category comparison use one physical site independently of claimed target`() = fixture { boundary ->
        val expected = site(true, "o1", 0x28, caller = O_BETA)
        val actual = site(false, "r1", 0x28, caller = R_BETA,
            category = "external", targets = listOf(target("external", EXTERNAL)))
        val report = derive(boundary, listOf(expected), listOf(actual))
        assertEquals(1, report.rows("rows").size)
        assertEquals(1, report.count("outcomes", "contradicted"))
        assertEquals(0, report.count("unresolvedRecoveredCount"))
        assertEquals(1, report.obj("dimensions").obj("internal").count("oracleDenominator"))
        assertEquals(1, report.obj("dimensions").obj("external").count("recoveredDenominator"))
    }

    @Test
    fun `pre-entry coordinates survive without unsigned local offset wrapping`() = fixture { boundary ->
        val report = derive(boundary, listOf(site(true, "o1", 0x8)), listOf(site(false, "r1", 0x8)))
        assertEquals(1, report.count("metrics", "exact"))
        assertEquals(coordinate(0x8), report.rows("recoveredSites").single()["instruction"])
        assertEquals(coordinate(0x10), report.rows("recoveredSites").single()["rawOwner"])
    }

    @Test
    fun `typed return coordinates reconcile only through independent pairs and preserve adjacent calls`() = fixture { boundary ->
        val oracle = listOf(site(true, "o1", 0x18, returned = 0x1d), site(true, "o2", 0x1d, returned = 0x22))
        val recovered = listOf(site(false, "r1", null, returned = 0x1d), site(false, "r2", 0x1d))
        val report = derive(boundary, oracle, recovered)
        assertEquals(2, report.count("metrics", "exact"))
        assertEquals(listOf("r1", "r2"), report.rows("rows").map { it.text("recoveredId") })
        val noPair = derive(boundary, listOf(site(true, "o1", 0x18)), listOf(site(false, "r1", null, returned = 0x18)))
        assertEquals(0, noPair.count("metrics", "exact"))
        assertEquals(1, noPair.count("outcomes", "recovered-unknown"))
        assertEquals(1, noPair.count("unresolvedRecoveredCount"))
    }

    @Test
    fun `recovered pair cannot override an independent pair or normalize synthetic instruction space`() = fixture { boundary ->
        val oracle = listOf(site(true, "o1", 0x18, returned = 0x1d))
        for (candidate in listOf(site(false, "r1", 0x18, returned = 0x1e),
            site(false, "r1", 0x18, returned = 0x1d).with("instruction", coordinate(0x18, "external-space")))) {
            val report = derive(boundary, oracle, listOf(candidate))
            assertEquals(0, report.count("metrics", "exact"))
            assertEquals(1, report.count("unresolvedRecoveredCount"))
        }
        assertFails { derive(boundary, oracle + site(true, "o2", 0x19, returned = 0x1d), emptyList()) }
    }

    @Test
    fun `repeated calls stay separate and duplicate observations require explicit consolidation`() = fixture { boundary ->
        val report = derive(boundary, listOf(site(true, "o1", 0x18), site(true, "o2", 0x28)),
            listOf(site(false, "r1", 0x18), site(false, "r2", 0x28)))
        assertEquals(2, report.count("metrics", "exact"))
        assertFails { derive(boundary, listOf(site(true, "o1", 0x18), site(true, "o2", 0x18)), emptyList()) }
        val deduplicated = site(true, "o1", 0x18).with("observations", JsonArray(listOf(ref(true, "raw1"), ref(true, "raw2"))))
        val combined = derive(boundary, listOf(deduplicated), emptyList())
        assertEquals(2, combined.count("rawObservationCount"))
        assertEquals(1, combined.count("metrics", "oracleDenominator"))
    }

    @Test
    fun `complete selected universes include zero-call false-negative and false-positive functions`() = fixture { boundary ->
        val report = derive(boundary, emptyList(), emptyList())
        assertEquals(5, report.count("oracleFunctionCount"))
        assertEquals(5, report.count("recoveredFunctionCount"))
        assertEquals(JsonNull, report.obj("metrics")["claimPrecision"])
        assertEquals(JsonPrimitive(false), report["otherTwinAvailable"])
        val unknownCaller = site(false, "r1", 0x88, caller = R_FALSE_POSITIVE)
        val unmapped = derive(boundary, emptyList(), listOf(unknownCaller))
        assertEquals("unmapped-recovered-caller", unmapped.rows("unresolvedRecovered").single().text("reason"))
        val expectedMissing = site(true, "o1", 0x38, caller = O_FALSE_NEGATIVE)
        assertEquals(1, derive(boundary, listOf(expectedMissing), emptyList()).count("outcomes", "recovered-unknown"))
    }

    @Test
    fun `only exact selected owner exclusions remove raw records from scoring`() = fixture { boundary ->
        val exclusion = JsonObject(mapOf("id" to JsonPrimitive("excluded-r1"), "side" to JsonPrimitive("recovered"),
            "ownerId" to JsonPrimitive(R_EXCLUDED), "observations" to JsonArray(listOf(ref(false, "raw-excluded")))))
        val bytes = input(boundary, emptyList(), emptyList(), exclusions = listOf(exclusion))
        val report = parse(StructuralCallPopulationV1.derive(bytes, boundary))
        assertEquals(1, report.count("rawObservationCount"))
        assertEquals(0, report.count("metrics", "recoveredDenominator"))
        for (owner in listOf(R_ALPHA, "missing-caller", "external-import")) {
            assertFails { StructuralCallPopulationV1.derive(input(boundary, emptyList(), emptyList(),
                exclusions = listOf(exclusion.with("ownerId", JsonPrimitive(owner)))), boundary) }
        }
    }

    @Test
    fun `oracle and recovery raw records cannot be omitted duplicated or cross-assigned`() = fixture { boundary ->
        val valid = parse(input(boundary, listOf(site(true, "o1", 0x18)), emptyList()))
        assertFails { StructuralCallPopulationV1.derive(encode(valid.with("oracleSites", JsonArray(emptyList()))), boundary) }
        val sites = valid.rows("oracleSites")
        assertFails { StructuralCallPopulationV1.derive(encode(valid.with("oracleSites", JsonArray(sites + sites))), boundary) }
        val crossed = sites.single().with("observations", JsonArray(listOf(ref(false, "o1"))))
        assertFails { StructuralCallPopulationV1.derive(encode(valid.with("oracleSites", JsonArray(listOf(crossed)))), boundary) }
    }

    @Test
    fun `closed contract rejects source substitution unknown fields and completeness booleans`() = fixture { boundary ->
        val original = parse(input(boundary, listOf(site(true, "o1", 0x18)), emptyList()))
        for (field in listOf("inputSha256", "programModelSha256", "boundaryObservationSha256")) {
            val changed = original.with("binding", original.obj("binding").with(field, JsonPrimitive("f".repeat(64))))
            assertFails { StructuralCallPopulationV1.derive(encode(changed), boundary) }
        }
        for (field in listOf("complete", "negativeCompleteness", "negativeCoverageAuthenticated", "productionVerified")) {
            assertFails { StructuralCallPopulationV1.derive(encode(original.with(field, JsonPrimitive(true))), boundary) }
        }
        val source = original.rows("sources").first().with("complete", JsonPrimitive(true))
        assertFails { StructuralCallPopulationV1.derive(encode(original.with("sources", JsonArray(listOf(source)))), boundary) }
    }

    @Test
    fun `fixture-only negative evidence is scoped and cannot enter public report validation`() = fixture { boundary ->
        val bytes = input(boundary, emptyList(), listOf(site(false, "r1", 0x18), site(false, "r2", 0x28)))
        val fixtureBytes = StructuralCallPopulationV1.deriveFixtureWithNegativeSites(bytes, boundary,
            setOf(StructuralCallPopulationV1.FixtureNegativeSite(O_ALPHA, 0x18UL)))
        val report = parse(fixtureBytes)
        assertEquals(1, report.count("outcomes", "fabricated"))
        assertEquals(1, report.count("unresolvedRecoveredCount"))
        assertEquals(2, report.count("metrics", "recoveredDenominator"))
        assertEquals(JsonPrimitive(false), report["negativeCoverageAuthenticated"])
        assertFails { StructuralCallPopulationV1.validateReport(bytes, boundary, fixtureBytes) }
        val wrongOwner = parse(StructuralCallPopulationV1.deriveFixtureWithNegativeSites(bytes, boundary,
            setOf(StructuralCallPopulationV1.FixtureNegativeSite(O_BETA, 0x18UL))))
        assertEquals(0, wrongOwner.count("outcomes", "fabricated"))
        assertFails { StructuralCallPopulationV1.deriveFixtureWithNegativeSites(
            input(boundary, listOf(site(true, "o1", 0x18)), emptyList()), boundary,
            setOf(StructuralCallPopulationV1.FixtureNegativeSite(O_ALPHA, 0x18UL))) }
    }

    @Test
    fun `indirect proven sets external namespaces and unresolved targets remain distinct`() = fixture { boundary ->
        val expected = listOf(target("function", O_ALPHA), target("function", O_BETA))
        val actual = listOf(target("function", R_ALPHA), target("function", R_BETA))
        val report = derive(boundary, listOf(site(true, "o1", 0x18, category = "indirect", targets = expected)),
            listOf(site(false, "r1", 0x18, category = "indirect", targets = actual)))
        assertEquals(1, report.count("metrics", "exact"))
        assertEquals(0, report.count("outcomes", "abi-equivalent"))
        val unknown = derive(boundary, listOf(site(true, "o1", 0x18, category = "indirect", targets = null)),
            listOf(site(false, "r1", 0x18, category = "indirect", targets = actual)))
        assertEquals(1, unknown.count("outcomes", "oracle-unobservable"))
        val external = site(true, "o1", 0x18, category = "external", targets = listOf(target("external", EXTERNAL)))
        val badNamespace = parse(input(boundary, listOf(external), emptyList()))
        assertFails { StructuralCallPopulationV1.derive(encode(badNamespace.with("binding",
            badNamespace.obj("binding").with("externalNamespaceSha256", JsonNull))), boundary) }
        assertFails { derive(boundary, listOf(site(true, "o1", 0x18, category = "external",
            targets = listOf(target("external", "puts")))), emptyList()) }
    }

    @Test
    fun `coverage gaps remain visible and never promote observed subset recall to completeness`() = fixture { boundary ->
        val gap = JsonObject(mapOf("id" to JsonPrimitive("gap1"), "sourceId" to JsonPrimitive("oracle"),
            "callerId" to JsonPrimitive(O_ALPHA), "reason" to JsonPrimitive("unresolved-computed-jump")))
        val bytes = input(boundary, listOf(site(true, "o1", 0x18)), listOf(site(false, "r1", 0x18)), gaps = listOf(gap))
        val report = parse(StructuralCallPopulationV1.derive(bytes, boundary))
        assertEquals(listOf(gap), report.rows("coverageGaps"))
        assertEquals(1, report.count("metrics", "exact"))
        assertEquals(JsonPrimitive(false), report["complete"])
        assertEquals(JsonPrimitive(false), report["releaseEligible"])
    }

    @Test
    fun `off-canonical owners and unknown categories retain raw coordinates without inventing identities`() = fixture { boundary ->
        val expected = site(true, "o1", null, caller = null, category = "unknown", targets = null)
            .with("rawOwner", coordinate(0x4500))
        val recovered = site(false, "r1", 0x4508, caller = null, category = "unknown", targets = null)
            .with("rawOwner", coordinate(0x4500))
        val report = derive(boundary, listOf(expected), listOf(recovered))
        assertEquals(1, report.count("outcomes", "oracle-unobservable"))
        assertEquals(1, report.count("unresolvedRecoveredCount"))
        assertEquals(1, report.obj("dimensions").obj("unknown").count("oracleDenominator"))
        assertEquals(1, report.obj("dimensions").obj("unknown").count("recoveredDenominator"))
        assertEquals(expected, report.rows("oracleSites").single())
        assertEquals(recovered, report.rows("recoveredSites").single())
        assertFails { derive(boundary, listOf(site(true, "o1", 0x18,
            targets = listOf(target("function", "missing-function")))), emptyList()) }
        val external = listOf(target("external", EXTERNAL))
        val exactExternal = derive(boundary, listOf(site(true, "o1", 0x18, category = "external", targets = external)),
            listOf(site(false, "r1", 0x18, category = "external", targets = external)))
        assertEquals(1, exactExternal.obj("dimensions").obj("external").count("exact"))
    }

    @Test
    fun `replay rejects edited outcomes metrics and omitted unresolved records even with recomputed JSON`() = fixture { boundary ->
        val bytes = input(boundary, listOf(site(true, "o1", 0x18)), listOf(site(false, "r1", 0x28)))
        val reportBytes = StructuralCallPopulationV1.derive(bytes, boundary)
        StructuralCallPopulationV1.validateReport(bytes, boundary, reportBytes)
        assertContentEquals(reportBytes, StructuralCallPopulationV1.derive(bytes, boundary))
        val report = parse(reportBytes)
        for (changed in listOf(report.with("unresolvedRecovered", JsonArray(emptyList())),
            report.with("metrics", report.obj("metrics").with("exact", JsonPrimitive(1))),
            report.with("productionVerified", JsonPrimitive(true)))) {
            assertFails { StructuralCallPopulationV1.validateReport(bytes, boundary, encode(changed)) }
        }
    }

    @Test
    fun `bounds and inconsistent owner coordinates fail without partial output`() = fixture { boundary ->
        val bytes = input(boundary, listOf(site(true, "o1", 0x18)), emptyList())
        assertFails { StructuralCallPopulationV1.derive(bytes, boundary, StructuralCallPopulationLimitsV1(maximumInputBytes = bytes.size - 1)) }
        assertFails { StructuralCallPopulationV1.derive(bytes, boundary, StructuralCallPopulationLimitsV1(maximumReportBytes = 32)) }
        assertFails { derive(boundary, listOf(site(true, "o1", 0x18).with("rawOwner", coordinate(0x20))), emptyList()) }
        val oversized = listOf(site(true, "o1", 0x18), site(true, "o2", 0x28))
        assertFails { StructuralCallPopulationV1.derive(input(boundary, oversized, emptyList()), boundary,
            StructuralCallPopulationLimitsV1(maximumRecords = 1)) }
    }

    private fun derive(boundary: StructuralSelectedBoundaryProjectionV1, oracle: List<JsonObject>, recovered: List<JsonObject>) =
        parse(StructuralCallPopulationV1.derive(input(boundary, oracle, recovered), boundary))

    private fun input(boundary: StructuralSelectedBoundaryProjectionV1, oracle: List<JsonObject>, recovered: List<JsonObject>,
        exclusions: List<JsonObject> = emptyList(), gaps: List<JsonObject> = emptyList()): ByteArray {
        val records = (oracle + recovered + exclusions).flatMap { it.rows("observations") }
        val sources = listOf("oracle", "recovered").map { side -> JsonObject(mapOf(
            "id" to JsonPrimitive(side), "role" to JsonPrimitive(side), "sha256" to JsonPrimitive("a".repeat(64)),
            "bytes" to JsonPrimitive(100), "policySha256" to JsonPrimitive("b".repeat(64)),
            "recordIds" to JsonArray(records.filter { it.text("sourceId") == side }.map { it.text("recordId") }
                .distinct().sorted().map(::JsonPrimitive)),
        )) }
        return encode(JsonObject(mapOf(
            "provider" to JsonPrimitive("structural-call-population-input-v1"), "schemaVersion" to JsonPrimitive(1),
            "binding" to JsonObject(mapOf("inputSha256" to JsonPrimitive(boundary.inputSha256),
                "programModelSha256" to JsonPrimitive(boundary.programModelSha256),
                "boundaryObservationSha256" to JsonPrimitive(boundary.boundaryObservationSha256),
                "externalNamespaceSha256" to JsonPrimitive("c".repeat(64)))),
            "sources" to JsonArray(sources), "oracleSites" to JsonArray(oracle), "recoveredSites" to JsonArray(recovered),
            "exclusions" to JsonArray(exclusions), "coverageGaps" to JsonArray(gaps),
        )))
    }

    private fun site(oracle: Boolean, id: String, pc: Long?, returned: Long? = null,
        caller: String? = if (oracle) O_ALPHA else R_ALPHA, category: String = "internal",
        targets: List<JsonObject>? = listOf(target("function", if (oracle) O_BETA else R_BETA))): JsonObject {
        val owner = caller?.let { mapOf(O_ALPHA to 0x10L, O_BETA to 0x20L, O_FALSE_NEGATIVE to 0x30L,
            R_ALPHA to 0x10L, R_BETA to 0x22L, R_FALSE_POSITIVE to 0x80L).getValue(it) }
        return JsonObject(mapOf("id" to JsonPrimitive(id), "callerId" to (caller?.let(::JsonPrimitive) ?: JsonNull),
            "rawOwner" to (owner?.let(::coordinate) ?: JsonNull), "instruction" to (pc?.let(::coordinate) ?: JsonNull),
            "return" to (returned?.let(::coordinate) ?: JsonNull), "category" to JsonPrimitive(category),
            "state" to JsonPrimitive(if (oracle) { if (targets == null) "oracle-unobservable" else "observable" }
                else { if (targets == null) "recovered-unknown" else "recovered" }),
            "targets" to (targets?.let(::JsonArray) ?: JsonNull), "observations" to JsonArray(listOf(ref(oracle, id)))))
    }

    private fun fixture(block: (StructuralSelectedBoundaryProjectionV1) -> Unit) {
        fun resource(name: String) = checkNotNull(javaClass.getResourceAsStream(name)).use { it.readAllBytes() }
        val directory = Files.createTempDirectory(Files.createDirectories(Path.of("build/tmp/call-population-tests")), "fixture-")
        try {
            val oracle = directory.resolve("oracle.json")
            Files.write(oracle, resource("/oracle/structural-v1/function-oracle.json"))
            setPermissions(oracle, "rw-------")
            val observation = StructuralBoundaryReplayV1.observeSelected(StructuralRecoveryV1Inputs.loadFunctionOracle(oracle),
                "rich", resource("/oracle/structural-boundary-replay-v1/rich-model.json"), 0x400000UL)
            block(StructuralSelectedBoundaryProjectionV1.fromObservation(observation.canonicalBytes))
        } finally { Files.walk(directory).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists) } }
    }

    private fun JsonObject.obj(key: String) = getValue(key).jsonObject
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.count(key: String) = getValue(key).jsonPrimitive.int
    private fun JsonObject.count(parent: String, key: String) = obj(parent).count(key)
    private fun JsonObject.rows(key: String) = getValue(key).jsonArray.map { it.jsonObject }
    private fun JsonObject.with(key: String, value: JsonElement) = JsonObject(this + (key to value))
    private fun encode(value: JsonObject) = OracleJson.canonicalBytes(value)
    private fun parse(bytes: ByteArray) = OracleJson.parseCanonical(bytes).jsonObject
    private fun ref(oracle: Boolean, id: String) = JsonObject(mapOf("sourceId" to JsonPrimitive(if (oracle) "oracle" else "recovered"), "recordId" to JsonPrimitive(id)))
    private fun target(kind: String, id: String) = JsonObject(mapOf("kind" to JsonPrimitive(kind), "id" to JsonPrimitive(id)))
    private fun coordinate(value: Long, space: String = "image") = JsonObject(mapOf("space" to JsonPrimitive(space), "offset" to JsonPrimitive("0x${value.toString(16)}")))

    private companion object {
        const val O_ALPHA = "die-cu0-10-alpha"
        const val O_BETA = "die-cu0-20-beta"
        const val O_FALSE_NEGATIVE = "die-cu0-30-gamma"
        const val R_ALPHA = "fn_0000000000400010"
        const val R_BETA = "fn_0000000000400022"
        const val R_FALSE_POSITIVE = "fn_0000000000400080"
        const val R_EXCLUDED = "fn_0000000000400060"
        val EXTERNAL = "ext-" + "d".repeat(64)
    }
}
