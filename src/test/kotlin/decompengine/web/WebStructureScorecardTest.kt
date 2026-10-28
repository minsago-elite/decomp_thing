package decompengine.web

import decompengine.project.*
import kotlinx.serialization.json.*
import kotlin.test.*

/** Recorded scorecards and cross-attempt comparison over synthetic confidence records. */
class WebStructureScorecardTest {
    private val fixture = WebStructureFixture()

    private fun id(index: Int) = stableFunctionId(0x401000uL + index.toULong() * 16uL)
    private fun function(index: Int, status: RecoveryStatus = RecoveryStatus.RECOVERED) =
        RecoveredFunction(id(index), "f$index", 0x401000uL + index.toULong() * 16uL, "void f$index(void)", null, status = status)

    private val statuses = listOf(RecoveryStatus.RECOVERED, RecoveryStatus.RECOVERED, RecoveryStatus.PARTIAL, RecoveryStatus.SYNTHETIC,
        RecoveryStatus.FAILED, RecoveryStatus.RECOVERED)
    private fun model(labels: List<RecoveryStatus> = statuses, schema: Int = 2) =
        fixture.model(labels.mapIndexed { index, status -> function(index, status) },
            listOf(RecoveredGlobal("global_0000000000500000", "g", 0x500000u, "int", status = RecoveryStatus.PARTIAL)), schema = schema)
    /** Module `core` owns 0–2 and the global, `edge` owns 2–4 (so 2 is shared), `empty` owns nothing and 5 is excluded. */
    private fun plan() = ModulePlan(modules = listOf(fixture.planned("core", listOf(id(0), id(1), id(2)), listOf("global_0000000000500000")),
        fixture.planned("edge", listOf(id(2), id(3), id(4))), fixture.planned("empty", emptyList())))

    private fun card(run: String = "run_1", revision: String = "revision_1", query: String? = null) =
        fixture.pages.scorecard("owner", fixture.jobId, run, revision, query).also { fixture.assertContract("structureScorecard", it) }
    private fun JsonObject.scorecard() = getValue("scorecard").jsonObject
    private fun JsonObject.metric(id: String) = scorecard().getValue("metrics").jsonArray.map { it.jsonObject }.single { it.text("id") == id }
    private fun JsonObject.text(name: String) = getValue(name).jsonPrimitive.contentOrNull
    private fun JsonObject.modules() = scorecard().getValue("modules").jsonObject.getValue("items").jsonArray.map { it.jsonObject }

    @Test fun `metrics state exact numerators denominators recorded values and parity`() {
        fixture.revision("run_1", "revision_1", model(), plan(), accepted = setOf("core"))
        val page = card()
        assertEquals("available", page.getValue("confidence").jsonObject.text("state"))
        val score = page.metric("structural-recovery-score")
        // 1 + 1 + 0.6 + 0.25 + 0 + 1 (functions) + 0.6 (global) over seven entities.
        assertEquals("measured", score.text("state")); assertEquals("4.45", score.text("numerator")); assertEquals("7", score.text("denominator"))
        assertEquals(StructuralRecoveryScore.render(statuses + RecoveryStatus.PARTIAL), score.text("value"))
        assertEquals(score.text("value"), score.text("recomputed"))
        assertEquals("projectScore", score.getValue("source").jsonObject.text("field"))
        // Unmeasured families are never a measured zero.
        assertEquals("unmeasured", page.metric("calibrated-confidence").text("state"))
        assertEquals("UNCALIBRATED", page.metric("calibrated-confidence").text("reason"))
        assertEquals(JsonNull, page.metric("calibrated-confidence").getValue("value"))
        val assessed = page.metric("assessed-recovery")
        assertEquals("unmeasured", assessed.text("state")); assertEquals("0", assessed.text("numerator")); assertEquals("7", assessed.text("denominator"))
        assertEquals("1", page.metric("implementation-acceptance").text("numerator")); assertEquals("3", page.metric("implementation-acceptance").text("denominator"))
        assertEquals("measured", page.metric("generation-completion").text("state"))
        assertEquals("1", page.metric("excluded-entities").text("numerator"))
        assertEquals("not-recorded", page.scorecard().getValue("thresholds").jsonObject.text("state"))
        val scope = page.scorecard().getValue("scope").jsonObject
        assertEquals(fixture.inputSha, scope.text("inputSha256")); assertEquals("7", scope.text("entities"))
        val labels = page.scorecard().getValue("labels").jsonArray.map { it.jsonObject }.associateBy { it.text("label") }
        assertEquals("1.2", labels.getValue("partial").text("contribution")); assertEquals("0", labels.getValue("failed").text("weight"))
        val modules = page.modules().associateBy { it.text("moduleId") }
        assertEquals("unmeasured", modules.getValue("empty").getValue("metric").jsonObject.text("state"))
        assertEquals("EMPTY_POPULATION", modules.getValue("empty").getValue("metric").jsonObject.text("reason"))
        assertEquals("0.0000", modules.getValue("empty").getValue("metric").jsonObject.text("value"))
        assertEquals("measured", modules.getValue("core").getValue("metric").jsonObject.text("state"))
    }

    @Test fun `module breakdowns reconcile with the project population and explain non-additive measures`() {
        fixture.revision("run_1", "revision_1", model(), plan())
        val reconciliation = card().scorecard().getValue("reconciliation").jsonObject
        assertEquals(true, reconciliation.getValue("reconciles").jsonPrimitive.boolean)
        assertEquals("7", reconciliation.text("projectDenominator"))
        // core: 4 entities, edge: 3 (entity 2 is in both), excluded: entity 5.
        assertEquals("7", reconciliation.text("moduleDenominatorSum")); assertEquals("1", reconciliation.text("duplicateMemberships"))
        assertEquals("1", reconciliation.text("excludedEntities")); assertEquals("0.6", reconciliation.text("duplicateNumerator"))
        assertEquals("4.05", reconciliation.text("moduleNumeratorSum")); assertEquals("1", reconciliation.text("excludedNumerator"))
        assertEquals(listOf("EXCLUDED_ENTITIES", "SHARED_OWNERSHIP"), reconciliation.getValue("adjustments").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("non-additive-mean", reconciliation.text("scoreAdditivity"))
    }

    @Test fun `recorded values are kept verbatim and a parity mismatch is a failed measurement`() {
        val model = model()
        fixture.revision("run_1", "revision_1", model, plan(), confidence = fixture.confidence(model, plan(), emptySet(), projectScore = "0.9999",
            completedModules = 2))
        val page = card()
        val score = page.metric("structural-recovery-score")
        assertEquals("failed", score.text("state")); assertEquals("SCORE_PARITY_MISMATCH", score.text("reason"))
        assertEquals("0.9999", score.text("value")); assertNotEquals("0.9999", score.text("recomputed"))
        assertEquals("partial", page.metric("generation-completion").text("state"))
        fixture.revision("run_2", "revision_2", model, plan(), confidence = fixture.confidence(model, plan(), emptySet(), generation = false))
        assertEquals("unknown", card("run_2", "revision_2").metric("generation-completion").text("state"))
    }

    @Test fun `empty populations are unmeasured rather than a measured zero`() {
        val empty = fixture.model(emptyList())
        fixture.revision("run_1", "revision_1", empty, ModulePlan(modules = emptyList()))
        val score = card().metric("structural-recovery-score")
        assertEquals("unmeasured", score.text("state")); assertEquals("EMPTY_POPULATION", score.text("reason")); assertEquals("0.0000", score.text("value"))
    }

    @Test fun `missing foreign or unsupported confidence records produce no scorecard`() {
        fixture.revision("run_1", "revision_1", model(), plan(), confidence = null)
        val missing = card()
        assertEquals(JsonNull, missing.getValue("scorecard"))
        assertEquals("CONFIDENCE_NOT_RECORDED", missing.getValue("confidence").jsonObject.text("stateReason"))
        // A confidence record bound to another model digest is refused.
        val other = model(statuses.reversed())
        fixture.revision("run_2", "revision_2", model(), plan(), confidence = fixture.confidence(other, plan(), emptySet()))
        assertEquals("CONFIDENCE_MODEL_MISMATCH", card("run_2", "revision_2").getValue("confidence").jsonObject.text("stateReason"))
        val unsupported = fixture.confidence(model(), plan(), emptySet()).decodeToString().replaceFirst("\"schemaVersion\":2", "\"schemaVersion\":3")
        fixture.revision("run_3", "revision_3", model(), plan(), confidence = unsupported.toByteArray())
        assertEquals("unsupported", card("run_3", "revision_3").getValue("confidence").jsonObject.text("state"))
        fixture.revision("run_4", "revision_4", model(), plan(), confidence = "{\"schemaVersion\":2,\"basis\":1}".toByteArray())
        assertEquals("CONFIDENCE_MALFORMED", card("run_4", "revision_4").getValue("confidence").jsonObject.text("stateReason"))
    }

    @Test fun `an accepted repair changes current acceptance without contradicting the historical generation outcome`() {
        val model = model()
        // The generation accepted nothing; a later repair accepted core in the manifest but kept the generation outcome.
        fixture.revision("run_1", "revision_1", model, plan(), accepted = setOf("core"), confidence = fixture.confidence(model, plan(), emptySet()))
        fixture.revision("run_2", "revision_2", model, plan(), confidence = fixture.confidence(model, plan(), emptySet()))
        val acceptance = card().metric("implementation-acceptance")
        assertEquals("measured", acceptance.text("state")); assertEquals("1", acceptance.text("numerator")); assertEquals("3", acceptance.text("denominator"))
        assertEquals("measured", card().metric("generation-completion").text("state"))
        val delta = compare("run_2", "revision_2", run = "run_1", revision = "revision_1").getValue("metrics").jsonArray.map { it.jsonObject }
            .single { it.text("id") == "implementation-acceptance" }.getValue("delta").jsonObject
        assertEquals("computed", delta.text("state")); assertEquals("1", delta.text("numerator"))
    }

    @Test fun `cited records download as their exact committed bytes for the displayed version`() {
        val model = model()
        val confidence = fixture.confidence(model, plan(), emptySet())
        fixture.revision("run_1", "revision_1", model, plan(), confidence = confidence)
        val version = card().text("structureVersion")
        val record = fixture.pages.record(fixture.jobId, "run_1", "revision_1", "confidence", "structureVersion=$version")
        assertContentEquals(confidence, record.bytes); assertEquals("confidence.json", record.name); assertEquals(fixture.sha(confidence), record.sha256)
        assertContentEquals(model.toJson().toByteArray(),
            fixture.pages.record(fixture.jobId, "run_1", "revision_1", "program-model", "structureVersion=$version").bytes)
        assertEquals("STRUCTURE_CHANGED", assertFailsWith<WebAccessDenied> {
            fixture.pages.record(fixture.jobId, "run_1", "revision_1", "confidence", "structureVersion=${"0".repeat(64)}")
        }.code)
        assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> { fixture.pages.record(fixture.jobId, "run_1", "revision_1", "confidence", null) }.code)
        assertEquals("RECORD_NOT_FOUND", assertFailsWith<WebAccessDenied> {
            fixture.pages.record(fixture.jobId, "run_1", "revision_1", "manifest", "structureVersion=$version")
        }.code)
        fixture.revision("run_2", "revision_2", model, plan(), confidence = null)
        val other = card("run_2", "revision_2").text("structureVersion")
        assertEquals("RECORD_NOT_RECORDED", assertFailsWith<WebAccessDenied> {
            fixture.pages.record(fixture.jobId, "run_2", "revision_2", "confidence", "structureVersion=$other")
        }.code)
    }

    @Test fun `module rows sort by recorded score with unmeasured rows last and page by cursor`() {
        fixture.revision("run_1", "revision_1", model(), plan())
        val descending = card(query = "sort=score&order=desc&limit=2")
        val first = descending.modules().map { it.text("moduleId") }
        assertEquals(listOf("core", "edge"), first)
        val cursor = descending.scorecard().getValue("modules").jsonObject.getValue("page").jsonObject.text("nextCursor")
        assertEquals(listOf("empty"), card(query = "sort=score&order=desc&limit=2&cursor=$cursor").modules().map { it.text("moduleId") })
        assertEquals("INVALID_CURSOR", assertFailsWith<WebAccessDenied> { card(query = "sort=module&limit=2&cursor=$cursor") }.code)
    }

    private fun compare(baselineRun: String, baselineRevision: String, run: String = "run_2", revision: String = "revision_2", extra: String = "") =
        fixture.pages.comparison("owner", fixture.jobId, run, revision, "baselineRunId=$baselineRun&baselineRevisionId=$baselineRevision$extra")
            .also { fixture.assertContract("scorecardComparison", it) }

    @Test fun `compatible attempts compare with exact deltas and module presence`() {
        fixture.revision("run_1", "revision_1", model(), plan())
        val improved = model(statuses.map { RecoveryStatus.RECOVERED })
        val grown = ModulePlan(modules = plan().modules.filter { it.id != "empty" } + fixture.planned("late", listOf(id(5))))
        fixture.revision("run_2", "revision_2", improved, grown, accepted = setOf("core", "edge"))
        val comparison = compare("run_1", "revision_1")
        assertEquals("compatible", comparison.getValue("compatibility").jsonObject.text("state"))
        val metrics = comparison.getValue("metrics").jsonArray.map { it.jsonObject }.associateBy { it.text("id") }
        val score = metrics.getValue("structural-recovery-score").getValue("delta").jsonObject
        assertEquals("computed", score.text("state"))
        val expected = java.math.BigDecimal(StructuralRecoveryScore.render(List(6) { RecoveryStatus.RECOVERED } + RecoveryStatus.PARTIAL)) -
            java.math.BigDecimal(StructuralRecoveryScore.render(statuses + RecoveryStatus.PARTIAL))
        assertEquals(expected.toPlainString(), score.text("value")); assertEquals("2.15", score.text("numerator")); assertEquals("0", score.text("denominator"))
        assertEquals("not-comparable", metrics.getValue("calibrated-confidence").getValue("delta").jsonObject.text("state"))
        assertEquals("2", metrics.getValue("implementation-acceptance").getValue("delta").jsonObject.text("numerator"))
        val modules = comparison.getValue("modules").jsonObject.getValue("items").jsonArray.map { it.jsonObject }.associateBy { it.text("moduleId") }
        assertEquals("baseline-only", modules.getValue("empty").text("presence")); assertEquals("current-only", modules.getValue("late").text("presence"))
        assertEquals("not-comparable", modules.getValue("late").getValue("delta").jsonObject.text("state"))
        assertEquals("computed", modules.getValue("core").getValue("delta").jsonObject.text("state"))
        // The plan change is flagged without blocking the comparison.
        val checks = comparison.getValue("compatibility").jsonObject.getValue("checks").jsonArray.map { it.jsonObject }.associateBy { it.text("id") }
        assertEquals("differs", checks.getValue("module-plan").text("state")); assertEquals(false, checks.getValue("module-plan").getValue("blocking").jsonPrimitive.boolean)
        for (side in listOf("current", "baseline")) {
            assertEquals(true, comparison.getValue(side).jsonObject.getValue("reconciliation").jsonObject.getValue("reconciles").jsonPrimitive.boolean)
        }
    }

    @Test fun `incompatible or unavailable baselines withhold every delta`() {
        fixture.revision("run_1", "revision_1", model(schema = 1), plan())
        fixture.revision("run_2", "revision_2", model(), plan())
        val incompatible = compare("run_1", "revision_1")
        assertEquals("incompatible", incompatible.getValue("compatibility").jsonObject.text("state"))
        val checks = incompatible.getValue("compatibility").jsonObject.getValue("checks").jsonArray.map { it.jsonObject }.associateBy { it.text("id") }
        assertEquals("differs", checks.getValue("model-schema").text("state"))
        assertTrue(incompatible.getValue("metrics").jsonArray.all { it.jsonObject.getValue("delta").jsonObject.text("state") == "withheld" })
        assertTrue(incompatible.getValue("modules").jsonObject.getValue("items").jsonArray.all {
            it.jsonObject.getValue("delta").jsonObject.let { delta -> delta.text("state") != "computed" && delta.getValue("value") == JsonNull }
        })
        fixture.revision("run_3", "revision_3", model(), plan(), confidence = null)
        val unavailable = compare("run_3", "revision_3")
        assertEquals("unavailable", unavailable.getValue("compatibility").jsonObject.text("state"))
        assertTrue(unavailable.getValue("metrics").jsonArray.isEmpty())
        assertEquals("REVISION_NOT_FOUND", assertFailsWith<WebAccessDenied> { compare("run_9", "revision_9") }.code)
        assertEquals("VALIDATION_FAILED", assertFailsWith<WebAccessDenied> {
            fixture.pages.comparison("owner", fixture.jobId, "run_2", "revision_2", "baselineRunId=run_1")
        }.code)
    }
}
