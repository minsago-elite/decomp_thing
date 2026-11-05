package decompengine.oracle.fulltree

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.ByteBuffer
import java.nio.charset.StandardCharsets
import java.util.concurrent.TimeUnit
import kotlin.test.*
import kotlinx.serialization.json.*

class FullTreeExternalProviderLedgerV1Test {
    @Test fun `R1 named hidden nondefault definitions match by name with local tuples validated`() {
        val base = changeRequirement(fixture()) { r ->
            JsonObject(r + ("version" to JsonObject(r["version"]!!.jsonObject + ("defaultDefinition" to JsonPrimitive(false)))))
        }
        fun definition(raw: Int, index: Int, hidden: Boolean, default: Boolean = false, name: JsonElement = JsonPrimitive("GLIBC_2.2.5")) =
            changeSelection(base) { selected -> JsonObject(selected + ("exportVersion" to JsonObject(selected["exportVersion"]!!.jsonObject + mapOf(
                "rawIndex" to JsonPrimitive(raw), "index" to JsonPrimitive(index), "hidden" to JsonPrimitive(hidden),
                "defaultDefinition" to JsonPrimitive(default), "name" to name, "providerRequest" to JsonNull)))) }
        val name = base.policy.jsonObject["requirements"]!!.jsonArray.single().jsonObject["version"]!!.jsonObject["name"]!!
        for (hidden in listOf(false, true)) {
            val positive = definition(if (hidden) 32775 else 7, 7, hidden, name = name)
            assertTrue(assess(positive).recordedInputsConsistent)
            assertFalse(assess(positive).blockers.any { it.code == "selected-GNU-hidden-bit-mismatch" })
        }
        assertTrue(assess(definition(7, 7, false, default = true, name = name)).recordedInputsConsistent)
        assertFalse(assess(definition(32775, 7, true, name = JsonPrimitive("WRONG"))).recordedInputsConsistent)
        for (bad in listOf(definition(7, 7, true), definition(32775, 2, true), definition(32775, 7, true, true), definition(1, 1, false)))
            assertFails { assess(bad) }
        val malformedCaller = changeRequirement(base) { r -> JsonObject(r + ("version" to JsonObject(r["version"]!!.jsonObject + ("hidden" to JsonPrimitive(true))))) }
        assertFails { assess(malformedCaller) }
    }

    @Test fun `R1 unversioned lookup requires a public default and explicit default remains binding`() {
        val unversioned = changeRequirement(fixture()) { r -> JsonObject(r + ("version" to buildJsonObject {
            put("rawIndex", 1); put("index", 1); put("hidden", false); put("name", JsonNull); put("providerRequest", JsonNull); put("defaultDefinition", false)
        })) }
        assertTrue(assess(unversioned).recordedInputsConsistent) // Public named default definition.
        val plain = changeSelection(unversioned) { s -> JsonObject(s + ("exportVersion" to unversioned.policy.jsonObject["requirements"]!!.jsonArray.single().jsonObject["version"]!!)) }
        assertTrue(assess(plain).recordedInputsConsistent)
        for (hidden in listOf(false, true)) {
            val nondefault = changeSelection(unversioned) { s -> JsonObject(s + ("exportVersion" to JsonObject(s["exportVersion"]!!.jsonObject + mapOf(
                "rawIndex" to JsonPrimitive(if (hidden) 32775 else 7), "index" to JsonPrimitive(7), "hidden" to JsonPrimitive(hidden), "defaultDefinition" to JsonPrimitive(false))))) }
            assertTrue(assess(nondefault).blockers.any { it.code == "selected-GNU-unversioned-lookup-mismatch" })
        }
        val explicitDefault = changeSelection(fixture()) { s -> JsonObject(s + ("exportVersion" to JsonObject(s["exportVersion"]!!.jsonObject + ("defaultDefinition" to JsonPrimitive(false))))) }
        assertTrue(assess(explicitDefault).blockers.any { it.code == "selected-GNU-default-version-mismatch" })
    }

    @Test fun `R3 binding refs normalize on either side once for comparisons digests and retained bytes`() {
        val base = fixture()
        fun bindings(refs: List<String>) = JsonObject(base.policy.jsonObject["bindings"]!!.jsonObject.mapValues { (_, v) ->
            JsonObject(v.jsonObject + ("evidenceRefs" to JsonArray(refs.map(::JsonPrimitive))))
        })
        fun variant(policyRefs: List<String>, inputRefs: List<String>) = base.copy(
            policy = JsonObject(base.policy.jsonObject + ("bindings" to bindings(policyRefs))),
            input = JsonObject(base.input.jsonObject + ("bindings" to bindings(inputRefs))))
        val refs = listOf("a", "b", "c")
        val reference = assess(variant(refs, refs))
        assertTrue(reference.recordedInputsConsistent)
        for ((left, right) in listOf(refs.reversed() to refs, refs to refs.reversed(), refs.reversed() to refs.reversed(), listOf("b", "c", "a") to listOf("c", "a", "b"))) {
            val result = assess(variant(left, right))
            assertTrue(result.recordedInputsConsistent)
            assertEquals(reference.sha256, result.sha256)
            assertContentEquals(reference.canonicalBytes(), result.canonicalBytes())
        }
        assertTrue(assess(variant(refs, listOf("a", "b", "different"))).blockers.any { it.code == "policy-input-binding-mismatch" })
        val stages = positiveMultiStageFixture()
        val reversed = stages.copy(input = JsonObject(stages.input.jsonObject + ("stages" to JsonArray(stages.input.jsonObject["stages"]!!.jsonArray.reversed()))))
        assertTrue(assess(reversed).blockers.any { it.code == "semantic-link-stage-order-changed" })
        val inputs = fixture(inputRoles = listOf("source", "object"))
        assertFails { assess(changeStage(inputs) { s -> JsonObject(s + ("inputOccurrences" to JsonArray(s["inputOccurrences"]!!.jsonArray.reversed()))) }) }
    }

    @Test fun `R4 every optional proof has strict keys and token types even when unused`() {
        val external = fixture()
        val weak = fixture(weakNull = true)
        val exported = withExportPopulation(external)
        assertTrue(assess(external).recordedInputsConsistent)
        assertTrue(assess(weak).recordedInputsConsistent)
        assertTrue(assess(exported).recordedInputsConsistent)
        fun proof(f: Fixture, field: String) = f.input.jsonObject["stages"]!!.jsonArray.single().jsonObject["selections"]!!.jsonArray.single().jsonObject[field]!!
        val absence = proof(weak, "absenceProof").jsonObject
        val population = proof(exported, "exportPopulation").jsonObject
        fun attach(field: String, value: JsonElement) = changeSelection(external) { JsonObject(it + (field to value)) }
        for (field in listOf("absenceProof", "exportPopulation", "discardProof")) {
            for (value in listOf(JsonNull, JsonPrimitive(true), JsonPrimitive(1), JsonArray(emptyList()), buildJsonObject { put("unexpectedAuthority", true) }))
                assertFails("$field=$value") { assess(attach(field, value)) }
        }
        for ((field, valid) in listOf("absenceProof" to absence, "exportPopulation" to population)) {
            assertFails { assess(attach(field, JsonObject(valid + ("unexpectedAuthority" to JsonPrimitive(true))))) }
            for (key in valid.keys) {
                assertFails("$field missing $key") { assess(attach(field, JsonObject(valid - key))) }
                assertFails("$field mistyped $key") { assess(attach(field, JsonObject(valid + (key to JsonPrimitive(true))))) }
            }
        }
        val row = population["exports"]!!.jsonArray.single().jsonObject
        for (key in row.keys) {
            val invalid = JsonObject(row + (key to JsonPrimitive(true)))
            assertFails("export row mistyped $key") { assess(attach("exportPopulation", JsonObject(population + ("exports" to JsonArray(listOf(invalid)))))) }
        }
        val extraRow = JsonObject(row + ("extra" to JsonPrimitive(true)))
        assertFails { assess(attach("exportPopulation", JsonObject(population + ("exports" to JsonArray(listOf(extraRow)))))) }
    }

    @Test fun `R4 valid optional proofs must apply to their disposition and bind the stage`() {
        val external = fixture()
        val weak = fixture(weakNull = true)
        val absence = weak.input.jsonObject["stages"]!!.jsonArray.single().jsonObject["selections"]!!.jsonArray.single().jsonObject["absenceProof"]!!
        assertFalse(assess(changeSelection(external) { JsonObject(it + ("absenceProof" to absence)) }).recordedInputsConsistent)
        val export = withExportPopulation(external).input.jsonObject["stages"]!!.jsonArray.single().jsonObject["selections"]!!.jsonArray.single().jsonObject["exportPopulation"]!!
        assertFalse(assess(changeSelection(weak) { JsonObject(it + ("exportPopulation" to export)) }).recordedInputsConsistent)
        val discarded = changeRequirement(external) { JsonObject(it + ("disposition" to JsonPrimitive("discarded-with-link-proof"))) }
        val hash = discarded.input.jsonObject["stages"]!!.jsonArray.single().jsonObject["linkMapSha256"]!!
        val valid = changeSelection(discarded) { JsonObject(it + ("discardProof" to hash)) }
        assertTrue(assess(valid).recordedInputsConsistent)
        assertFalse(assess(changeSelection(valid) { JsonObject(it + ("discardProof" to JsonPrimitive("f".repeat(64)))) }).recordedInputsConsistent)
        assertFalse(assess(changeSelection(external) { JsonObject(it + ("discardProof" to hash)) }).recordedInputsConsistent)
        val report = OracleJson.parseCanonical(assess(valid).canonicalBytes()).jsonObject
        for (flag in listOf("complete", "releaseEligible")) assertEquals(JsonPrimitive(false), report[flag])
    }

    @Test fun `R5 direct assessment lower byte finding and aggregate ref caps precede copies`() {
        val first = ExternalBoundaryFindingV1("first", "qualification", evidenceRefs = listOf("a", "b"))
        val second = ExternalBoundaryFindingV1("second", "qualification", evidenceRefs = listOf("c"))
        val limits = ExternalProviderLimitsV1(maximumDocumentBytes = 2, maximumFindings = 2, maximumReferencesAndEvents = 3)
        fun construct(l: ExternalProviderLimitsV1, rows: List<ExternalBoundaryFindingV1> = listOf(first, second)) =
            ExternalProviderAssessmentV1(byteArrayOf(1, 2), rows, true, "a".repeat(64), ExternalBoundaryBudgetV1(l, deadline()))
        assertEquals(2, construct(limits).blockers.size)
        assertFailsWith<IllegalArgumentException> { construct(limits.copy(maximumDocumentBytes = 1)) }
        assertFailsWith<IllegalArgumentException> { construct(limits.copy(maximumFindings = 1)) }
        assertFailsWith<IllegalArgumentException> { construct(limits.copy(maximumReferencesAndEvents = 2)) }
        val unreadable = object : AbstractList<ExternalBoundaryFindingV1>() {
            override val size = 2
            override fun get(index: Int): ExternalBoundaryFindingV1 = error("copied before admission")
        }
        assertFailsWith<IllegalArgumentException> { construct(limits.copy(maximumDocumentBytes = 1), unreadable) }
        assertFailsWith<IllegalArgumentException> { construct(limits.copy(maximumFindings = 1), unreadable) }
        val many = ExternalBoundaryFindingV1("many", "qualification", evidenceRefs = List(32768) { "r" })
        assertNotNull(ExternalProviderAssessmentV1(byteArrayOf(1), listOf(many, many), true, "a".repeat(64)))
        assertFailsWith<IllegalArgumentException> { ExternalProviderAssessmentV1(byteArrayOf(1), listOf(many, many, second), true, "a".repeat(64)) }
        val bytes = byteArrayOf(1, 2); val rows = mutableListOf(first, second)
        val owned = ExternalProviderAssessmentV1(bytes, rows, true, "a".repeat(64), ExternalBoundaryBudgetV1(limits, deadline()))
        bytes.fill(9); rows.clear()
        assertContentEquals(byteArrayOf(1, 2), owned.canonicalBytes())
        assertEquals(listOf("a", "b"), owned.blockers.first().evidenceRefs)
    }

    @Test fun `R5 direct assessment uses original shared work and cancellation budget`() {
        val rows = listOf(ExternalBoundaryFindingV1("f", "qualification", evidenceRefs = listOf("a", "b")))
        fun construct(b: ExternalBoundaryBudgetV1) = ExternalProviderAssessmentV1(byteArrayOf(1), rows, true, "a".repeat(64), b)
        fun budget(work: Long) = ExternalBoundaryBudgetV1(ExternalProviderLimitsV1(maximumWorkUnits = work), deadline())
        var exact = 1L
        while (runCatching { construct(budget(exact)) }.isFailure) { exact++; check(exact < 100) }
        assertEquals(6L, exact, "admission, row, byte and reference copy work, then ownership")
        assertNotNull(construct(budget(exact)))
        assertFails { construct(budget(exact - 1)) }
        val shared = budget(exact); shared.checkpoint("prior caller work")
        assertFails { construct(shared) }
        val expired = ExternalBoundaryBudgetV1(ExternalProviderLimitsV1(), AnalysisDeadline.start(1, "expired constructor parent"))
        assertFails { construct(expired) }
        val interrupted = budget(100)
        try {
            Thread.currentThread().interrupt()
            assertFailsWith<InterruptedException> { construct(interrupted) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally { Thread.interrupted() }
    }

    private fun changeSelection(f: Fixture, change: (JsonObject) -> JsonObject) = changeStage(f) { stage ->
        JsonObject(stage + ("selections" to JsonArray(stage["selections"]!!.jsonArray.map { change(it.jsonObject) })))
    }

    private fun changeRequirement(f: Fixture, change: (JsonObject) -> JsonObject): Fixture {
        val changed = change(f.policy.jsonObject["requirements"]!!.jsonArray.single().jsonObject)
        val requirement = JsonObject(changed + ("id" to JsonPrimitive(identity("requirement", JsonObject(changed - setOf("id", "disposition"))))))
        return f.copy(policy = JsonObject(f.policy.jsonObject + ("requirements" to JsonArray(listOf(requirement)))), input = changeStage(f) { stage ->
            JsonObject(stage + listOf("undefinedBefore", "undefinedAfter").associateWith { key -> JsonArray(stage[key]!!.jsonArray.map { row ->
                JsonObject(row.jsonObject + mapOf("requirementId" to requirement["id"]!!, "disposition" to requirement["disposition"]!!))
            }) })
        }.input)
    }

    @Test fun `complete recorded population reconciles and remains non bearer`() {
        val f = fixture()
        val result = assess(f)
        assertTrue(result.blockers.none { it.category == "consistency" }, result.blockers.joinToString { it.code })
        assertFalse(result.recordedInputsConsistent.not())
        val json = OracleJson.parseCanonical(result.canonicalBytes()) as JsonObject
        assertEquals(1, json["entries"]!!.jsonArray.count { it.jsonObject["recordKind"] == JsonPrimitive("link-stage") })
        assertEquals(JsonPrimitive(false), json["complete"])
        assertEquals(JsonPrimitive(false), json["releaseEligible"])
        assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(json - "reportSha256"))), json["reportSha256"]!!.jsonPrimitive.content)
        assertContentEquals(result.canonicalBytes(), result.canonicalBytes())
        val bytes = result.canonicalBytes(); bytes.fill(0)
        assertNotEquals(0, result.canonicalBytes()[0])
    }

    @Test fun `recorded identity and relationship mutations produce blockers`() {
        val original = fixture()
        val input = original.input.jsonObject
        val stage = input["stages"]!!.jsonArray.single().jsonObject
        val before = stage["undefinedBefore"]!!.jsonArray.single().jsonObject
        val changedBefore = JsonObject(before + ("disposition" to JsonPrimitive("in-scope-owner")))
        val changedStage = JsonObject(stage + ("undefinedBefore" to JsonArray(listOf(changedBefore))))
        val mutated = Fixture(original.policy, JsonObject(input + ("stages" to JsonArray(listOf(changedStage)))))
        val result = assess(mutated)
        assertTrue(result.blockers.any { it.code == "unauthorized-disposition-change" })

        val unknown = JsonObject(original.policy.jsonObject + ("providers" to JsonArray(original.policy.jsonObject["providers"]!!.jsonArray.map { provider ->
            JsonObject(provider.jsonObject + ("sha256" to JsonPrimitive("f".repeat(64))))
        })))
        assertFails { assess(Fixture(unknown, original.input)) }

        val missingStage = JsonObject(original.input.jsonObject + ("stages" to JsonArray(emptyList())))
        assertTrue(assess(Fixture(original.policy, missingStage)).blockers.any { it.code == "missing-expected-stage" })

        val versionStage = original.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        val selection = versionStage["selections"]!!.jsonArray.single().jsonObject
        val version = JsonObject(selection["exportVersion"]!!.jsonObject + ("hidden" to JsonPrimitive(true)))
        val changedSelection = JsonObject(selection + ("exportVersion" to version))
        val changedVersionStage = JsonObject(versionStage + ("selections" to JsonArray(listOf(changedSelection))))
        val changedVersionInput = JsonObject(original.input.jsonObject + ("stages" to JsonArray(listOf(changedVersionStage))))
        assertFails("hidden flag must agree with object-local raw index") { assess(Fixture(original.policy, changedVersionInput)) }
    }

    @Test fun `null identity fields follow explicit applicability table and role changes invalidate them`() {
        val f = fixture(includeStaticArchive = true)
        val result = assess(f)
        val assessment = OracleJson.parseCanonical(result.canonicalBytes()) as JsonObject
        val applicableRows = assessment["findings"]!!.jsonArray.map { it.jsonObject }
            .filter { it["code"]!!.jsonPrimitive.content.startsWith("not-applicable:") }
        assertTrue(applicableRows.any { it["code"] == JsonPrimitive("not-applicable:soname") })
        assertTrue(applicableRows.any { it["code"] == JsonPrimitive("not-applicable:cxxLibraryAbi") })
        assertTrue(applicableRows.all { it["evidenceRefs"]!!.jsonArray.isNotEmpty() })
        assertTrue(applicableRows.any { it["evidenceRefs"]!!.jsonArray.single() == JsonPrimitive("role=static-archive denotes an archive without ELF DT_SONAME") })
        assertTrue(applicableRows.any { it["evidenceRefs"]!!.jsonArray.single().jsonPrimitive.content.contains("abi.family=c, role=static-archive, target=x86_64-unknown-linux-gnu") })

        val policy = f.policy.jsonObject
        val archive = policy["providers"]!!.jsonArray.last().jsonObject
        val changedArchive = JsonObject(archive + ("role" to JsonPrimitive("system-library")))
        val changedPolicy = JsonObject(policy + ("providers" to JsonArray(policy["providers"]!!.jsonArray.dropLast(1) + changedArchive)))
        assertFails("a shared library cannot inherit static archive SONAME nullability") { assess(Fixture(changedPolicy, f.input)) }

        val unsupportedTarget = JsonObject(archive["target"]!!.jsonObject + ("triple" to JsonPrimitive("x86_64-unknown-linux-musl")))
        val changedTargetWithoutApplicability = JsonObject(archive + ("target" to unsupportedTarget))
        val recomputedTarget = withId("provider", JsonObject(changedTargetWithoutApplicability - "id"))
        val targetPolicy = JsonObject(policy + ("providers" to JsonArray(policy["providers"]!!.jsonArray.dropLast(1) + recomputedTarget)))
        assertFails("an unsupported target cannot inherit the fixed archive-null applicability rule") { assess(Fixture(targetPolicy, f.input)) }

        val missingRequired = JsonObject(archive + ("role" to JsonPrimitive("system-library")) + ("soname" to JsonPrimitive("libx.so")))
        val missingAbi = JsonObject(missingRequired + ("abi" to JsonObject(missingRequired["abi"]!!.jsonObject + mapOf("family" to JsonPrimitive("cxx"), "cxxLibraryAbi" to JsonNull))))
        val idless = JsonObject(missingAbi - "id")
        val recomputed = JsonObject(idless + ("id" to JsonPrimitive(identity("provider", idless))))
        val badPolicy = JsonObject(policy + ("providers" to JsonArray(policy["providers"]!!.jsonArray.dropLast(1) + recomputed)))
        assertFails { assess(Fixture(badPolicy, f.input)) }
    }

    @Test fun `strict null required fields and configured work ceiling fail closed`() {
        val f = fixture()
        val policy = f.policy.jsonObject
        val compiler = policy["tools"]!!.jsonArray.single().jsonObject
        val nullResource = JsonObject(compiler + ("resourceDirSha256" to JsonNull))
        val bad = JsonObject(policy + ("tools" to JsonArray(listOf(nullResource))))
        assertFails { assess(Fixture(bad, f.input)) }
        assertFails { FullTreeExternalProviderLedgerV1.assess(OracleJson.canonicalBytes(f.policy), OracleJson.canonicalBytes(f.input), deadline(), ExternalProviderLimitsV1(maximumWorkUnits = 1)) }
    }

    @Test fun `an exhausted original analysis deadline cannot be extended by recorded child work`() {
        val f = fixture()
        val parent = AnalysisDeadline.start(1, "already exhausted parent")
        Thread.sleep(1)
        assertFails { FullTreeExternalProviderLedgerV1.assess(OracleJson.canonicalBytes(f.policy), OracleJson.canonicalBytes(f.input), parent) }
    }

    @Test fun `all recorded occurrence roles are finite and included in stage identity`() {
        val roles = listOf("source", "generated-source", "object", "archive", "bitcode", "response-file", "linker-script", "shared-library", "relocatable", "executable", "generated-table", "tool", "runtime")
        val f = fixture(inputRoles = roles)
        assertTrue(assess(f).blockers.none { it.category == "consistency" })
        val stage = f.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        val occurrence = stage["inputOccurrences"]!!.jsonArray.first().jsonObject
        val changed = JsonObject(occurrence + ("role" to JsonPrimitive("object")))
        val changedStage = JsonObject(stage + ("inputOccurrences" to JsonArray(listOf(changed) + stage["inputOccurrences"]!!.jsonArray.drop(1))))
        val changedInput = JsonObject(f.input.jsonObject + ("stages" to JsonArray(listOf(changedStage))))
        assertFails { assess(Fixture(f.policy, changedInput)) }
        val output = stage["outputIdentities"]!!.jsonArray.single().jsonObject
        val changedOutput = JsonObject(output + ("role" to JsonPrimitive("relocatable")))
        val changedKindStage = JsonObject(stage + mapOf("kind" to JsonPrimitive("partial-relocatable"), "outputIdentities" to JsonArray(listOf(changedOutput))))
        val changedKindInput = JsonObject(f.input.jsonObject + ("stages" to JsonArray(listOf(changedKindStage))))
        assertFails { assess(Fixture(f.policy, changedKindInput)) }
        for (invalid in listOf<JsonElement>(JsonPrimitive("host-discovery"), JsonNull)) {
            val invalidRow = JsonObject(occurrence + ("role" to invalid))
            val invalidStage = JsonObject(stage + ("inputOccurrences" to JsonArray(listOf(invalidRow) + stage["inputOccurrences"]!!.jsonArray.drop(1))))
            val invalidInput = JsonObject(f.input.jsonObject + ("stages" to JsonArray(listOf(invalidStage))))
            assertFails { assess(Fixture(f.policy, invalidInput)) }
            val invalidOutput = JsonObject(output + ("role" to invalid))
            val invalidOutputStage = JsonObject(stage + ("outputIdentities" to JsonArray(listOf(invalidOutput))))
            val invalidOutputInput = JsonObject(f.input.jsonObject + ("stages" to JsonArray(listOf(invalidOutputStage))))
            assertFails { assess(Fixture(f.policy, invalidOutputInput)) }
        }
    }

    @Test fun `weak null alias cycles and provider SONAME swaps retain explicit findings`() {
        val weak = fixture(weakNull = true)
        assertTrue(assess(weak).blockers.none { it.category == "consistency" })
        val weakWithGeneratedTable = fixture(weakNull = true, generatedTable = true)
        assertTrue(assess(weakWithGeneratedTable).blockers.any { it.code == "weak-null-may-hide-required-generated-table" })
        assertTrue(assess(weakWithGeneratedTable).blockers.any { it.code == "generated-table-provenance-not-authenticated" })

        val base = fixture()
        val input = base.input.jsonObject
        val stage = input["stages"]!!.jsonArray.single().jsonObject
        val before = stage["undefinedBefore"]!!.jsonArray.single().jsonObject
        val alias = JsonObject(before + mapOf("disposition" to JsonPrimitive("declared-alias"), "aliasTargetId" to before["id"]!!))
        val aliasSelection = JsonObject(stage["selections"]!!.jsonArray.single().jsonObject + mapOf(
            "providerId" to JsonNull, "exportSymbolKey" to JsonNull, "exportName" to JsonNull, "exportVersion" to JsonNull, "aliasTargetId" to before["id"]!!,
        ))
        val aliasStage = JsonObject(stage + mapOf("undefinedBefore" to JsonArray(listOf(alias)), "undefinedAfter" to JsonArray(listOf(alias)), "selections" to JsonArray(listOf(aliasSelection))))
        val aliasReq = JsonObject(base.policy.jsonObject["requirements"]!!.jsonArray.single().jsonObject + ("disposition" to JsonPrimitive("declared-alias")))
        val aliasPolicy = JsonObject(base.policy.jsonObject + ("requirements" to JsonArray(listOf(aliasReq))))
        val aliasInput = JsonObject(input + ("stages" to JsonArray(listOf(aliasStage))))
        assertTrue(assess(Fixture(aliasPolicy, aliasInput)).blockers.any { it.code == "alias-cycle" })

        val provider = base.policy.jsonObject["providers"]!!.jsonArray.single().jsonObject
        val swapped = JsonObject(provider + mapOf("soname" to JsonPrimitive("libwrong.so"), "sha256" to JsonPrimitive("c".repeat(64)), "bytes" to JsonPrimitive(11)))
        val replacement = withId("provider", JsonObject(swapped - "id"))
        val oldId = provider["id"]!!
        val newId = replacement["id"]!!
        val changedPolicy = JsonObject(base.policy.jsonObject + ("providers" to JsonArray(listOf(replacement))))
        val changedStage = JsonObject(stage + mapOf(
            "undefinedBefore" to JsonArray(listOf(JsonObject(before + ("providerId" to newId)))),
            "undefinedAfter" to JsonArray(listOf(JsonObject(before + ("providerId" to newId)))),
            "selections" to JsonArray(listOf(JsonObject(stage["selections"]!!.jsonArray.single().jsonObject + ("providerId" to newId)))),
        ))
        assertNotEquals(oldId, newId)
        assertTrue(assess(Fixture(changedPolicy, JsonObject(input + ("stages" to JsonArray(listOf(changedStage)))))).blockers.any { it.code == "GNU-provider-request-SONAME-mismatch" })
    }

    @Test fun `positive two stage ledger carries internal external weak null and alias obligations`() {
        val f = positiveMultiStageFixture()
        val result = assess(f)
        assertTrue(result.blockers.none { it.category == "consistency" }, result.blockers.joinToString { it.code })
        assertFalse(result.recordedInputsConsistent.not())
    }

    @Test fun `target ABI GNU default owner weak omission and alias target mutations block`() {
        val base = fixture()
        val policy = base.policy.jsonObject
        val stage = base.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        val selection = stage["selections"]!!.jsonArray.single().jsonObject
        val version = JsonObject(selection["exportVersion"]!!.jsonObject + ("defaultDefinition" to JsonPrimitive(false)))
        val defaultSelection = JsonObject(selection + ("exportVersion" to version))
        val defaultStage = JsonObject(stage + ("selections" to JsonArray(listOf(defaultSelection))))
        assertTrue(assess(Fixture(base.policy, JsonObject(base.input.jsonObject + ("stages" to JsonArray(listOf(defaultStage)))))).blockers.any { it.code == "selected-GNU-default-version-mismatch" })

        val before = stage["undefinedBefore"]!!.jsonArray.single().jsonObject
        val wrongOwner = JsonObject(before + ("ownerModuleId" to JsonPrimitive("other-module")))
        val ownerStage = JsonObject(stage + mapOf("undefinedBefore" to JsonArray(listOf(wrongOwner)), "undefinedAfter" to JsonArray(listOf(wrongOwner))))
        assertTrue(assess(Fixture(base.policy, JsonObject(base.input.jsonObject + ("stages" to JsonArray(listOf(ownerStage)))))).blockers.any { it.code == "wrong-symbol-owner" })

        val weak = fixture(weakNull = true)
        val weakStage = weak.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        val dropped = JsonObject(weakStage + mapOf("undefinedBefore" to JsonArray(emptyList()), "undefinedAfter" to JsonArray(emptyList())))
        val droppedInput = JsonObject(weak.input.jsonObject + ("stages" to JsonArray(listOf(dropped))))
        assertTrue(assess(Fixture(weak.policy, droppedInput)).blockers.any { it.code == "expected-reference-unobserved" })

        val unnamed = fixture()
        val unnamedPolicy = unnamed.policy.jsonObject
        val requirement = unnamedPolicy["requirements"]!!.jsonArray.single().jsonObject
        val unnamedBase = JsonObject(requirement + mapOf("name" to JsonPrimitive(""), "disposition" to JsonPrimitive("unsupported")))
        val identityBase = JsonObject(JsonObject(unnamedBase - setOf("id", "disposition")) + ("references" to unnamedBase["references"]!!))
        val unnamedRequirement = JsonObject(unnamedBase + ("id" to JsonPrimitive(identity("requirement", identityBase))))
        val unnamedStage = unnamed.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        fun unsupported(row: JsonObject) = JsonObject(row + mapOf("requirementId" to unnamedRequirement["id"]!!, "disposition" to JsonPrimitive("unsupported")))
        val unsupportedStage = JsonObject(unnamedStage + mapOf(
            "undefinedBefore" to JsonArray(listOf(unsupported(unnamedStage["undefinedBefore"]!!.jsonArray.single().jsonObject))),
            "undefinedAfter" to JsonArray(listOf(unsupported(unnamedStage["undefinedAfter"]!!.jsonArray.single().jsonObject))),
        ))
        val unnamedInput = JsonObject(unnamed.input.jsonObject + ("stages" to JsonArray(listOf(unsupportedStage))))
        val unnamedPolicyUpdated = JsonObject(unnamedPolicy + ("requirements" to JsonArray(listOf(unnamedRequirement))))
        assertTrue(assess(Fixture(unnamedPolicyUpdated, unnamedInput)).blockers.any { it.code == "blocking-occurrence-disposition:unsupported" })

        val multi = positiveMultiStageFixture()
        val finalStage = multi.input.jsonObject["stages"]!!.jsonArray.last().jsonObject
        val finalAlias = finalStage["selections"]!!.jsonArray.last().jsonObject
        val dangling = JsonObject(finalAlias + ("aliasTargetId" to JsonPrimitive("f".repeat(64))))
        val danglingStage = JsonObject(finalStage + ("selections" to JsonArray(finalStage["selections"]!!.jsonArray.dropLast(1) + dangling)))
        val danglingInput = JsonObject(multi.input.jsonObject + ("stages" to JsonArray(multi.input.jsonObject["stages"]!!.jsonArray.dropLast(1) + danglingStage)))
        assertTrue(assess(Fixture(multi.policy, danglingInput)).blockers.any { it.code == "dangling-alias-target" })

        val provider = policy["providers"]!!.jsonArray.single().jsonObject
        val changedAbi = JsonObject(provider["abi"]!!.jsonObject + ("unwinderAbi" to JsonPrimitive("different-unwinder")))
        val changedProvider = withId("provider", JsonObject(JsonObject(provider + ("abi" to changedAbi)) - "id"))
        val newId = changedProvider["id"]!!
        val changedPolicy = JsonObject(policy + ("providers" to JsonArray(listOf(changedProvider))))
        val changedOccurrencesBefore = JsonArray(stage["undefinedBefore"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to newId)) })
        val changedOccurrencesAfter = JsonArray(stage["undefinedAfter"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to newId)) })
        val changedSelections = JsonArray(stage["selections"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to newId)) })
        val abiStage = JsonObject(stage + mapOf("undefinedBefore" to changedOccurrencesBefore, "undefinedAfter" to changedOccurrencesAfter, "selections" to changedSelections))
        assertTrue(assess(Fixture(changedPolicy, JsonObject(base.input.jsonObject + ("stages" to JsonArray(listOf(abiStage)))))).blockers.any { it.code == "provider-ABI-mismatch:unwinderAbi" })

        val cxxAbi = JsonObject(provider["abi"]!!.jsonObject + ("cxxLibraryAbi" to JsonPrimitive("different-cxx-abi")))
        val cxxProvider = withId("provider", JsonObject(JsonObject(provider + ("abi" to cxxAbi)) - "id"))
        val cxxId = cxxProvider["id"]!!
        val cxxPolicy = JsonObject(policy + ("providers" to JsonArray(listOf(cxxProvider))))
        val cxxStage = JsonObject(stage + mapOf(
            "undefinedBefore" to JsonArray(stage["undefinedBefore"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to cxxId)) }),
            "undefinedAfter" to JsonArray(stage["undefinedAfter"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to cxxId)) }),
            "selections" to JsonArray(stage["selections"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to cxxId)) }),
        ))
        assertTrue(assess(Fixture(cxxPolicy, JsonObject(base.input.jsonObject + ("stages" to JsonArray(listOf(cxxStage)))))).blockers.any { it.code == "provider-ABI-mismatch:cxxLibraryAbi" })

        val aarch64 = JsonObject(provider["target"]!!.jsonObject + mapOf("triple" to JsonPrimitive("aarch64-unknown-linux-gnu"), "machine" to JsonPrimitive(183)))
        val targetProvider = withId("provider", JsonObject(JsonObject(provider + ("target" to aarch64)) - "id"))
        val targetId = targetProvider["id"]!!
        val targetPolicy = JsonObject(policy + ("providers" to JsonArray(listOf(targetProvider))))
        val targetBefore = JsonArray(stage["undefinedBefore"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to targetId)) })
        val targetAfter = JsonArray(stage["undefinedAfter"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to targetId)) })
        val targetSelections = JsonArray(stage["selections"]!!.jsonArray.map { JsonObject(it.jsonObject + ("providerId" to targetId)) })
        val targetStage = JsonObject(stage + mapOf("undefinedBefore" to targetBefore, "undefinedAfter" to targetAfter, "selections" to targetSelections))
        assertTrue(assess(Fixture(targetPolicy, JsonObject(base.input.jsonObject + ("stages" to JsonArray(listOf(targetStage)))))).blockers.any { it.code == "provider-tool-target-mismatch" })
    }

    @Test fun `archive input sequence and implicit linker search are identity bound or blocked`() {
        val ordered = fixture(inputRoles = listOf("archive", "object"))
        assertTrue(assess(ordered).recordedInputsConsistent)
        val stage = ordered.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        val rows = stage["inputOccurrences"]!!.jsonArray
        val swapped = JsonObject(stage + ("inputOccurrences" to JsonArray(rows.reversed())))
        assertFails { assess(Fixture(ordered.policy, JsonObject(ordered.input.jsonObject + ("stages" to JsonArray(listOf(swapped)))))) }

        val hostFallback = fixture(stageArgv = listOf("cc", "-L/usr/lib", "-lhostfallback"))
        assertTrue(assess(hostFallback).blockers.any { it.code == "wildcard-or-implicit-linker-search-in-argv" })
        val reorderedPolicy = fixture(includeStaticArchive = true)
        val policy = reorderedPolicy.policy.jsonObject
        val reversed = JsonObject(policy + ("providers" to JsonArray(policy["providers"]!!.jsonArray.reversed())))
        assertContentEquals(assess(reorderedPolicy).canonicalBytes(), assess(Fixture(reversed, reorderedPolicy.input)).canonicalBytes())
    }

    @Test fun `provider tool stage requirement reference event finding and work caps admit N reject N plus one`() {
        val providerLimit = ExternalProviderLimitsV1(maximumProviders = 2)
        assertTrue(assess(fixture(includeStaticArchive = true, limits = providerLimit), providerLimit).recordedInputsConsistent)
        val providerOver = ExternalProviderLimitsV1(maximumProviders = 1)
        assertFails { assess(fixture(includeStaticArchive = true, limits = providerOver), providerOver) }

        val oneEach = ExternalProviderLimitsV1(maximumTools = 1, maximumStages = 1, maximumRequirements = 1)
        val exactOne = fixture(limits = oneEach)
        assertTrue(assess(exactOne, oneEach).recordedInputsConsistent)
        val extraTool = JsonObject(exactOne.policy.jsonObject + ("tools" to JsonArray(exactOne.policy.jsonObject["tools"]!!.jsonArray + exactOne.policy.jsonObject["tools"]!!.jsonArray.single())))
        assertFails { assess(Fixture(extraTool, exactOne.input), oneEach) }
        val extraRequirement = JsonObject(exactOne.policy.jsonObject + ("requirements" to JsonArray(exactOne.policy.jsonObject["requirements"]!!.jsonArray + exactOne.policy.jsonObject["requirements"]!!.jsonArray.single())))
        assertFails { assess(Fixture(extraRequirement, exactOne.input), oneEach) }
        val tooManyStages = JsonObject(exactOne.input.jsonObject + ("stages" to JsonArray(listOf(
            exactOne.input.jsonObject["stages"]!!.jsonArray.single(), exactOne.input.jsonObject["stages"]!!.jsonArray.single(),
        ))))
        assertFails { assess(Fixture(exactOne.policy, tooManyStages), oneEach) }

        val exactOccurrences = ExternalProviderLimitsV1(maximumReferencesAndEvents = 37)
        assertTrue(assess(fixture(limits = exactOccurrences), exactOccurrences).recordedInputsConsistent)
        val occurrenceOver = ExternalProviderLimitsV1(maximumReferencesAndEvents = 36)
        assertFails { assess(fixture(limits = occurrenceOver), occurrenceOver) }

        val baselineFindings = assess(fixture()).blockers.size
        val findingExact = ExternalProviderLimitsV1(maximumFindings = baselineFindings)
        assertEquals(baselineFindings, assess(fixture(limits = findingExact), findingExact).blockers.size)
        val findingBelow = findingExact.copy(maximumFindings = baselineFindings - 1)
        assertFails { assess(fixture(limits = findingBelow), findingBelow) }
        val findingAbove = findingExact.copy(maximumFindings = baselineFindings + 1)
        assertEquals(baselineFindings, assess(fixture(limits = findingAbove), findingAbove).blockers.size)
    }

    @Test fun `aggregate input and assessment output byte ceilings admit exact N reject N minus one`() {
        val default = fixture()
        val seedPolicy = OracleJson.canonicalBytes(default.policy)
        val seedInput = OracleJson.canonicalBytes(default.input)
        val aggregate = seedPolicy.size + seedInput.size
        val atAggregate = ExternalProviderLimitsV1(maximumAggregateInputBytes = aggregate)
        val exactAggregateFixture = fixture(limits = atAggregate)
        val policyBytes = OracleJson.canonicalBytes(exactAggregateFixture.policy)
        val inputBytes = OracleJson.canonicalBytes(exactAggregateFixture.input)
        assertNotNull(FullTreeExternalProviderLedgerV1.assess(policyBytes, inputBytes, deadline(), atAggregate))
        val belowAggregate = atAggregate.copy(maximumAggregateInputBytes = aggregate - 1)
        val belowFixture = fixture(limits = belowAggregate)
        assertFails { FullTreeExternalProviderLedgerV1.assess(OracleJson.canonicalBytes(belowFixture.policy), OracleJson.canonicalBytes(belowFixture.input), deadline(), belowAggregate) }

        val reportSize = assess(default).canonicalBytes().size
        val exactOutput = ExternalProviderLimitsV1(maximumDocumentBytes = reportSize)
        val exactFixture = fixture(limits = exactOutput)
        val exactResult = assess(exactFixture, exactOutput)
        assertEquals(reportSize, exactResult.canonicalBytes().size)
        val belowOutput = exactOutput.copy(maximumDocumentBytes = reportSize - 1)
        assertFails { assess(fixture(limits = belowOutput), belowOutput) }
    }

    @Test fun `F1 every stage obligation requires exact carry discharge or absence proof`() {
        val multi=positiveMultiStageFixture()
        for(index in 0..1) {
            val changed=changeStage(multi,index) { s -> JsonObject(s+mapOf("undefinedAfter" to JsonArray(emptyList()),"selections" to JsonArray(emptyList()))) }
            assertTrue(assess(changed).blockers.any { it.code=="before-obligation-not-carried-or-discharged" })
        }
        val weak=fixture(weakNull=true)
        assertTrue(assess(weak).recordedInputsConsistent)
        for(field in listOf("stageId","requirementId","referenceSha256","traceSha256","linkMapSha256","abiSourceId","resolvedValue","semantics")) {
            val changed=changeStage(weak) { s ->
                val selected=s["selections"]!!.jsonArray.single().jsonObject
                val proof=JsonObject(selected["absenceProof"]!!.jsonObject+(field to JsonPrimitive("wrong")))
                JsonObject(s+("selections" to JsonArray(listOf(JsonObject(selected+("absenceProof" to proof))))))
            }
            assertTrue(assess(changed).blockers.any { it.code=="weak-null-supported-absence-proof-unavailable" },field)
        }
        val missing=changeStage(weak) { s -> JsonObject(s+("selections" to JsonArray(emptyList()))) }
        assertFalse(assess(missing).recordedInputsConsistent)
    }

    @Test fun `F2 export population binds exact provider bytes locator name type and version`() {
        val base=withExportPopulation(fixture())
        assertTrue(assess(base).recordedInputsConsistent)
        assertFalse(assess(base).blockers.any { it.code=="selected-export-population-provenance-unavailable" })
        for(field in listOf("artifactSha256","tableSectionIndex","symbolIndex","rawLocator")) {
            val changed=changeStage(base) { s ->
                val selected=s["selections"]!!.jsonArray.single().jsonObject
                val key=selected["exportSymbolKey"]!!.jsonObject
                val value=if(field.endsWith("Index")) JsonPrimitive(999) else JsonPrimitive(if(field=="artifactSha256") "f".repeat(64) else "wrong")
                JsonObject(s+("selections" to JsonArray(listOf(JsonObject(selected+("exportSymbolKey" to JsonObject(key+(field to value))))))))
            }
            assertFalse(assess(changed).recordedInputsConsistent,field)
        }
        for((field,value) in listOf("type" to JsonPrimitive(1),"binding" to JsonPrimitive(2),"binding" to JsonPrimitive(10),"visibility" to JsonPrimitive(2),"selectionSemantics" to JsonPrimitive("COMDAT"),"selectionSemantics" to JsonPrimitive("interposition"))) {
            val changed=withExportPopulation(fixture(),field,value)
            assertTrue(assess(changed).blockers.any { it.code=="export-selection-semantics-unqualified" },"$field=$value")
        }
    }

    @Test fun `F11 GNU object local indices differ while names and provider request match`() {
        val base=fixture()
        val changed=changeStage(base) { s ->
            val selected=s["selections"]!!.jsonArray.single().jsonObject
            val v=JsonObject(selected["exportVersion"]!!.jsonObject+mapOf("rawIndex" to JsonPrimitive(7),"index" to JsonPrimitive(7),"providerRequest" to JsonNull))
            JsonObject(s+("selections" to JsonArray(listOf(JsonObject(selected+("exportVersion" to v))))))
        }
        assertTrue(assess(changed).recordedInputsConsistent)
        for((field,value) in listOf("name" to JsonPrimitive("WRONG_1"),"defaultDefinition" to JsonPrimitive(false))) {
            val bad=changeStage(changed) { s ->
                val selected=s["selections"]!!.jsonArray.single().jsonObject
                val changedVersion = JsonObject(selected["exportVersion"]!!.jsonObject + mapOf(field to value))
                val changedSelection = JsonObject(selected + mapOf("exportVersion" to changedVersion))
                JsonObject(s + mapOf("selections" to JsonArray(listOf(changedSelection))))
            }
            assertFalse(assess(bad).recordedInputsConsistent)
        }
    }

    @Test fun `F6 unordered census selections and records preserve reports while argv order changes identity`() {
        val base=positiveMultiStageFixture()
        val reversed=base.copy(input=JsonObject(base.input.jsonObject+("stages" to JsonArray(base.input.jsonObject["stages"]!!.jsonArray.map { row ->
            val stage=row.jsonObject
            JsonObject(stage+listOf("undefinedBefore","undefinedAfter","selections","toolIds","parentStageIds","outputIdentities").associateWith { JsonArray(stage[it]!!.jsonArray.reversed()) })
        }))))
        assertContentEquals(assess(base).canonicalBytes(),assess(reversed).canonicalBytes())
        assertFails { assess(changeStage(base,1) { s -> JsonObject(s+("argv" to JsonArray(s["argv"]!!.jsonArray.reversed()))) }) }
        assertFails { assess(changeStage(base,1) { s -> JsonObject(s+("environment" to buildJsonObject { put("HOME","/staged") })) }) }
    }

    @Test fun `distinct tool stage and requirement populations hit exact ceilings`() {
        val base=fixture()
        val tool=base.policy.jsonObject["tools"]!!.jsonArray.single().jsonObject
        val other=withId("tool",JsonObject(tool-"id"+("versionText" to JsonPrimitive("cc distinct"))))
        val f=base.copy(policy=JsonObject(base.policy.jsonObject+("tools" to JsonArray(listOf(tool,other)))))
        assertTrue(assess(f).recordedInputsConsistent)
        assertFails { assess(f,ExternalProviderLimitsV1(maximumTools=1)) }
        val multi=positiveMultiStageFixture()
        assertTrue(assess(multi).recordedInputsConsistent)
        assertFails { assess(multi,ExternalProviderLimitsV1(maximumStages=1)) }
        assertFails { assess(multi,ExternalProviderLimitsV1(maximumRequirements=3)) }
        val generated=fixture(generatedTable=true)
        assertTrue(assess(generated).blockers.any { it.code=="required-generated-table-output-absent" })
    }

    @Test fun `positive actual inert ELF adapter integrates both link stages and denies changed run bytes and locator`() {
        val base=positiveMultiStageFixture()
        val bytes=decompengine.oracle.externalcalls.DynamicBindingElfFixtureV1().bytes
        val root=java.nio.file.Path.of("build/remediation-inert"); java.nio.file.Files.createDirectories(root)
        val file=root.resolve("two-stage.elf"); java.nio.file.Files.write(file,bytes)
        try {
            StableControlFile.open(file,bytes.size.toLong(),"two-stage adapter").use { stable ->
                val hash=OracleArtifacts.sha256(bytes)
                val inventory=decompengine.oracle.externalcalls.BoundedElfDynamicBindingsV1.scan(stable,hash)
                val stages=base.input.jsonObject["stages"]!!.jsonArray.map { row -> val s=row.jsonObject
                    JsonObject(s+("outputIdentities" to JsonArray(s["outputIdentities"]!!.jsonArray.map { JsonObject(it.jsonObject+mapOf("sha256" to JsonPrimitive(hash),"bytes" to JsonPrimitive(bytes.size))) })))
                }
                val evidence=stages.map { s -> FullTreeExternalProviderEvidenceV1.fromElf(ExternalLinkStageIdentityV1(
                    s["buildRunId"]!!.jsonPrimitive.content,s["graphActionId"]!!.jsonPrimitive.content,s["ordinal"]!!.jsonPrimitive.int,
                    s["sourceRevisionSha256"]!!.jsonPrimitive.content,s["planSha256"]!!.jsonPrimitive.content,s["policySha256"]!!.jsonPrimitive.content,
                    s["outputIdentities"]!!.jsonArray.single().jsonObject["role"]!!.jsonPrimitive.content,bytes.size.toLong(),hash),inventory,ExternalBoundaryBudgetV1(ExternalProviderLimitsV1(),deadline())).toJson() }
                assertNotEquals(hash,evidence.first()["inventorySha256"]!!.jsonPrimitive.content)
                val f=base.copy(input=JsonObject(base.input.jsonObject+mapOf("stages" to JsonArray(stages),"elfEvidence" to JsonArray(evidence))))
                assertTrue(assess(f).recordedInputsConsistent,assess(f).blockers.joinToString { it.code })
                val permuted=f.copy(input=JsonObject(f.input.jsonObject+("elfEvidence" to JsonArray(evidence.reversed()))))
                assertContentEquals(assess(f).canonicalBytes(),assess(permuted).canonicalBytes(),"same executable digest at distinct stages must have stable full-row ordering")
                for(field in listOf("buildRunId","graphActionId","outputBytes")) {
                    val e=evidence.first(); val changed=JsonObject(e+("stage" to JsonObject(e["stage"]!!.jsonObject+(field to if(field=="outputBytes") JsonPrimitive(1) else JsonPrimitive("wrong")))))
                    val bad=f.copy(input=JsonObject(f.input.jsonObject+("elfEvidence" to JsonArray(listOf(changed)+evidence.drop(1)))))
                    assertTrue(assess(bad).blockers.any { it.code=="recorded-ELF-evidence-not-bound-to-link-stage" })
                }
                val e=evidence.first();val refs=e["references"]!!.jsonArray
                val forged=JsonObject(e+("references" to JsonArray(refs.map { JsonObject(it.jsonObject+("rawLocator" to JsonPrimitive("forged"))) })))
                val bad=f.copy(input=JsonObject(f.input.jsonObject+("elfEvidence" to JsonArray(listOf(forged)+evidence.drop(1)))))
                assertTrue(assess(bad).blockers.any { it.code=="ELF-reference-raw-symbol-locator-mismatch" })
            }
        } finally { java.nio.file.Files.delete(file); java.nio.file.Files.delete(root) }
    }

    private fun changeStage(f: Fixture,index: Int=0, change: (JsonObject)->JsonObject): Fixture = f.copy(input=JsonObject(f.input.jsonObject+("stages" to JsonArray(f.input.jsonObject["stages"]!!.jsonArray.mapIndexed { i,s -> if(i==index) change(s.jsonObject) else s }))))
    private fun withExportPopulation(f: Fixture, field: String?=null, value: JsonElement=JsonNull): Fixture {
        val stage=f.input.jsonObject["stages"]!!.jsonArray.single().jsonObject
        val selected=stage["selections"]!!.jsonArray.single().jsonObject
        var export=buildJsonObject { put("symbolKey",selected["exportSymbolKey"]!!); put("name",selected["exportName"]!!); put("version",selected["exportVersion"]!!); put("type",2); put("binding",1); put("visibility",0); put("selectionSemantics","strong-direct") }
        if(field!=null) export=JsonObject(export+(field to value))
        val provider=f.policy.jsonObject["providers"]!!.jsonArray.single().jsonObject
        val population=buildJsonObject { put("kind","recorded-provider-exports-v1"); put("artifactSha256",provider["sha256"]!!); put("exports",JsonArray(listOf(export))) }
        val replacement=withId("provider",JsonObject(provider-"id"+("exportsSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(population))))))
        val input=changeStage(f) { s -> JsonObject(s+mapOf(
            "undefinedBefore" to JsonArray(s["undefinedBefore"]!!.jsonArray.map { JsonObject(it.jsonObject+("providerId" to replacement["id"]!!)) }),
            "undefinedAfter" to JsonArray(s["undefinedAfter"]!!.jsonArray.map { JsonObject(it.jsonObject+("providerId" to replacement["id"]!!)) }),
            "selections" to JsonArray(listOf(JsonObject(selected+mapOf("providerId" to replacement["id"]!!,"exportPopulation" to population)))))) }.input
        return f.copy(policy=JsonObject(f.policy.jsonObject+("providers" to JsonArray(listOf(replacement)))),input=input)
    }

    private data class Fixture(val policy: JsonElement, val input: JsonElement)

    private fun fixture(includeStaticArchive: Boolean = false, inputRoles: List<String> = listOf("source"), weakNull: Boolean = false, generatedTable: Boolean = false, limits: ExternalProviderLimitsV1 = ExternalProviderLimitsV1(), stageArgv: List<String> = listOf("cc", "-o", "out")): Fixture {
        val h = "1".repeat(64)
        val target = buildJsonObject { put("triple", "x86_64-unknown-linux-gnu"); put("elfClass", 64); put("byteOrder", "little"); put("machine", 62); put("osAbi", 0); put("abiFlags", 0) }
        val abi = buildJsonObject { put("family", "c"); put("version", "gnu-1"); put("cxxLibraryAbi", "libstdc++-13"); put("unwinderAbi", "libgcc-1") }
        val providerBase = buildJsonObject {
            put("role", "system-library"); put("sourceLockSha256", h); put("sourceReleaseSha256", h); put("runtimeProfileId", "runtime"); put("runtimeProfileSha256", h)
            put("namespaceSha256", h); put("path", "/sys/lib/libx.so"); put("resolvedPath", "/sys/lib/libx.so"); put("soname", "libx.so")
            put("bytes", 10); put("sha256", h); put("target", target); put("abi", abi); put("exportsSha256", h)
        }
        val provider = withId("provider", providerBase)
        val providers = mutableListOf<JsonElement>(provider)
        if (includeStaticArchive) {
            val archiveAbi = buildJsonObject { put("family", "c"); put("version", "gnu-1"); put("cxxLibraryAbi", JsonNull); put("unwinderAbi", JsonNull) }
            val archiveBase = buildJsonObject {
                put("role", "static-archive"); put("sourceLockSha256", h); put("sourceReleaseSha256", h); put("runtimeProfileId", "runtime"); put("runtimeProfileSha256", h)
                put("namespaceSha256", h); put("path", "/sys/lib/libx.a"); put("resolvedPath", "/sys/lib/libx.a"); put("soname", JsonNull)
                put("bytes", 10); put("sha256", h); put("target", target); put("abi", archiveAbi); put("exportsSha256", h)
            }
            providers += withId("provider", archiveBase)
        }
        val toolBase = buildJsonObject {
            put("role", "compiler"); put("path", "/tools/bin/cc"); put("resolvedPath", "/tools/bin/cc"); put("bytes", 10); put("sha256", h)
            put("versionOutputSha256", h); put("versionText", "cc 1"); put("target", target); put("resourceDirSha256", h); put("sysrootSha256", h); put("runtimeProfileSha256", h)
        }
        val tool = withId("tool", toolBase)
        val symbol = buildJsonObject { put("artifactRole", "executable"); put("artifactSha256", h); put("tableSectionIndex", 3); put("symbolIndex", 8); put("rawLocator", "dynsym:3:8") }
        val reference = buildJsonObject {
            put("artifactRole", "executable"); put("artifactSha256", h); put("member", JsonNull); put("tableSectionIndex", 3); put("symbolIndex", 8); put("rawLocator", "dynsym:3:8")
            put("relocationSectionIndex", 4); put("relocationIndex", 0); put("offset", "0x10"); put("type", 7); put("addend", 0)
            put("ownerModuleId", JsonNull); put("ownerEntityId", JsonNull); put("abiSourceId", "abi-1")
        }
        val requirementBase = buildJsonObject {
            put("symbolKey", symbol); put("name", "external_fn"); put("type", 2); put("binding", if (weakNull) "weak" else "global"); put("visibility", "default")
            put("version", buildJsonObject { put("rawIndex", 2); put("index", 2); put("hidden", false); put("name", "LIB_1"); put("providerRequest", "libx.so"); put("defaultDefinition", true) })
            put("abi", abi); put("ownerModuleId", JsonNull); put("ownerEntityId", JsonNull); put("references", buildJsonArray { add(reference) }); put("disposition", if (weakNull) "declared-weak-null" else "declared-external")
        }
        val requirementIdentity = JsonObject(JsonObject(requirementBase - "disposition") + ("references" to JsonArray(listOf(reference))))
        val requirement = JsonObject(requirementBase + ("id" to JsonPrimitive(identity("requirement", requirementIdentity))))
        val deadline = deadline()
        val config = FullTreeExternalProviderLedgerV1.configurationSha256(limits)
        val stageBase = buildJsonObject {
            put("buildRunId", "build-1"); put("ordinal", 0); put("kind", "executable"); put("graphActionId", "link-action-1"); put("parentStageIds", JsonArray(emptyList()))
            put("sourceRevisionSha256", h); put("planSha256", h); put("policySha256", config); put("toolIds", buildJsonArray { add(tool["id"]!!) })
            put("argv", JsonArray(stageArgv.map(::JsonPrimitive))); put("environment", buildJsonObject { put("HOME", JsonNull) })
            put("cwd", "/workspace/build"); put("inputOccurrences", JsonArray(inputRoles.mapIndexed { index, role -> buildJsonObject {
                put("role", role); put("bytes", 10); put("sha256", h); put("member", JsonNull); put("sequence", index)
            } })); put("outputIdentities", buildJsonArray { add(buildJsonObject { put("role", "executable"); put("bytes", 10); put("sha256", h) }) })
        }
        val stageId = identity("stage", stageIdentity(stageBase))
        val occurrenceId = identity("occurrence", buildJsonObject { put("stageId", stageId); put("reference", reference) })
        val occurrence = buildJsonObject {
            put("id", occurrenceId); put("symbolKey", symbol); put("reference", reference); put("requirementId", requirement["id"]!!)
            put("ownerModuleId", JsonNull); put("providerId", if (weakNull) JsonNull else provider["id"]!!); put("disposition", if (weakNull) "declared-weak-null" else "declared-external"); put("evidenceRefs", buildJsonArray { add("recorded-fixture") }); put("aliasTargetId", JsonNull)
        }
        val selection = buildJsonObject {
            put("occurrenceId", occurrenceId); put("providerId", if (weakNull) JsonNull else provider["id"]!!); put("exportSymbolKey", if (weakNull) JsonNull else symbol); put("exportName", if (weakNull) JsonNull else JsonPrimitive("external_fn"))
            put("exportVersion", if (weakNull) JsonNull else requirement["version"]!!); put("aliasTargetId", JsonNull); put("evidenceRefs", buildJsonArray { add("recorded-fixture") })
        }
        val stage = JsonObject(stageBase + mapOf(
            "id" to JsonPrimitive(stageId),
            "undefinedBefore" to JsonArray(listOf(occurrence)), "undefinedAfter" to JsonArray(listOf(occurrence)),
            "selections" to buildJsonArray { add(if (weakNull) JsonObject(selection + ("absenceProof" to absenceProof(stageId, occurrence, h, h))) else selection) }, "linkMapSha256" to JsonPrimitive(h), "traceSha256" to JsonPrimitive(h),
            "exitCode" to JsonPrimitive(0), "blockers" to JsonArray(emptyList())))
        val bindings = buildJsonObject {
            for (key in listOf("sourceLock", "artifactManifest", "scope", "planning", "ownerUniverse", "sourceRevision", "graph", "runtimeProfile", "detectorPolicy")) {
                val digest = if (key == "detectorPolicy") config else h
                put(key, buildJsonObject { put("sha256", digest); put("disposition", "available"); put("evidenceRefs", buildJsonArray { add("fixture") }) })
            }
        }
        val runtimeClauses = listOf("filesystem", "process", "environment", "locale", "terminal", "time").mapIndexed { i, category ->
            buildJsonObject { put("id", "runtime-$i"); put("category", category); put("subjectOwner", "owner"); put("operations", buildJsonArray { add("observe") }); put("targets", buildJsonArray { add("staged") }); put("inputs", buildJsonArray { add("case-$i") }); put("observableResultPolicy", "any"); put("evidenceRefs", buildJsonArray { add("fixture") }) }
        }
        val runtimePolicy = buildJsonObject { put("schemaVersion", 1); put("kind", "runtime-interface-policy-v1"); put("clauses", JsonArray(runtimeClauses)) }
        val runtimeEvents = runtimeClauses.mapIndexed { i, c -> buildJsonObject { put("id", "event-$i"); put("category", c["category"]!!); put("subjectOwner", "owner"); put("operation", "observe"); put("target", "staged"); put("input", "case-$i"); put("result", "ok") } }
        val requirements = buildJsonArray { add(requirement) }
        val policy = buildJsonObject { put("schemaVersion", 1); put("kind", "external-provider-policy-v1"); put("bindings", bindings); put("providers", JsonArray(providers)); put("tools", buildJsonArray { add(tool) }); put("requirements", requirements); put("expectedStages", buildJsonArray { add(stageId) }); put("runtimePolicy", runtimePolicy) }
        val universe = buildJsonObject {
            put("expectedEntities", buildJsonArray { add(symbol) }); put("expectedReferences", buildJsonArray { add(reference) }); put("ownerModuleIds", JsonArray(emptyList()))
            put("stageIds", buildJsonArray { add(stageId) }); put("provenanceLimitations", JsonArray(emptyList())); put("requiredGeneratedTables", if (generatedTable) buildJsonArray {
                add(buildJsonObject { put("id", "generated-gperf-table"); put("disposition", "reproduced"); put("sourceSha256", h); put("generatorActionId", "action-gen"); put("inputSha256", h); put("outputSha256", h) })
            } else JsonArray(emptyList()))
        }
        val observed = buildJsonObject { put("schemaVersion", 1); put("kind", "runtime-interface-observations-v1"); put("uses", JsonArray(runtimeEvents)) }
        val input = buildJsonObject {
            put("schemaVersion", 1); put("kind", "external-provider-inputs-v1"); put("bindings", bindings); put("universe", universe)
            put("stages", buildJsonArray { add(stage) }); put("elfEvidence", JsonArray(emptyList())); put("rawMeasurements", JsonArray(emptyList()))
            put("recordedClosures", JsonArray(emptyList())); put("runtimeInterfaces", observed)
        }
        return Fixture(policy, input)
    }

    private fun positiveMultiStageFixture(): Fixture {
        val base = fixture()
        val policyBase = base.policy.jsonObject
        val inputBase = base.input.jsonObject
        val h = "1".repeat(64)
        val provider = policyBase["providers"]!!.jsonArray.single().jsonObject
        val tool = policyBase["tools"]!!.jsonArray.single().jsonObject
        val config = policyBase["bindings"]!!.jsonObject["detectorPolicy"]!!.jsonObject["sha256"]!!.jsonPrimitive.content
        val abi = policyBase["requirements"]!!.jsonArray.single().jsonObject["abi"]!!.jsonObject
        val specs = listOf(
            Triple("internal_fn", "in-scope-owner", "module-internal"),
            Triple("external_fn", "declared-external", null),
            Triple("optional_fn", "declared-weak-null", null),
            Triple("alias_fn", "declared-alias", "module-internal"),
        )
        val records = specs.mapIndexed { index, (name, disposition, owner) ->
            val symbol = buildJsonObject { put("artifactRole", "object"); put("artifactSha256", h); put("tableSectionIndex", 3); put("symbolIndex", index + 1); put("rawLocator", "symtab:3:${index + 1}") }
            val ref = buildJsonObject {
                put("artifactRole", "object"); put("artifactSha256", h); put("member", "unit$index.o"); put("tableSectionIndex", 3); put("symbolIndex", index + 1); put("rawLocator", "symtab:3:${index + 1}")
                put("relocationSectionIndex", 4); put("relocationIndex", index); put("offset", "0x${(16 + index).toString(16)}"); put("type", 7); put("addend", 0)
                put("ownerModuleId", owner?.let(::JsonPrimitive) ?: JsonNull); put("ownerEntityId", if (owner != null) JsonPrimitive("entity-internal") else JsonNull); put("abiSourceId", "abi-$index")
            }
            val isWeak = disposition == "declared-weak-null"
            val version = buildJsonObject {
                put("rawIndex", if (name == "external_fn") 2 else 0); put("index", if (name == "external_fn") 2 else 0); put("hidden", false)
                put("name", if (name == "external_fn") JsonPrimitive("LIB_1") else JsonNull)
                put("providerRequest", if (name == "external_fn") JsonPrimitive("libx.so") else JsonNull)
                put("defaultDefinition", name == "external_fn")
            }
            val reqBase = buildJsonObject {
                put("symbolKey", symbol); put("name", name); put("type", 2); put("binding", if (isWeak) "weak" else "global"); put("visibility", "default")
                put("version", version); put("abi", abi); put("ownerModuleId", owner?.let(::JsonPrimitive) ?: JsonNull)
                put("ownerEntityId", if (owner != null) JsonPrimitive("entity-internal") else JsonNull); put("references", buildJsonArray { add(ref) }); put("disposition", disposition)
            }
            val identity = JsonObject(JsonObject(reqBase - "disposition") + ("references" to JsonArray(listOf(ref))))
            Triple(JsonObject(reqBase + ("id" to JsonPrimitive(identity("requirement", identity)))), symbol, ref)
        }
        val requirements = records.map { it.first }
        val stage0Base = stageBase("action-partial", 0, "partial-relocatable", emptyList(), listOf("object"), "relocatable", tool, config, h)
        val stage0Id = identity("stage", stageIdentity(stage0Base))
        val stage0Before = records.mapIndexed { index, row -> occurrence(stage0Id, row, provider, index) }
        val stage0 = makeStage(stage0Base, stage0Id, stage0Before, stage0Before, emptyList())
        val stage1Base = stageBase("action-final", 1, "executable", listOf(stage0Id), listOf("relocatable", "archive"), "executable", tool, config, h)
        val stage1Id = identity("stage", stageIdentity(stage1Base))
        val stage1Before = records.mapIndexed { index, row -> occurrence(stage1Id, row, provider, index) }.toMutableList()
        stage1Before[3] = JsonObject(stage1Before[3] + ("aliasTargetId" to stage1Before[0]["id"]!!))
        val internal = records[0]
        val external = records[1]
        val alias = records[3]
        val selections = listOf(
            select(stage1Before[0], null, internal.second, "internal_fn", internal.first["version"]!!.jsonObject, null),
            select(stage1Before[1], provider["id"]!!.jsonPrimitive.content, external.second, "external_fn", external.first["version"]!!.jsonObject, null),
            buildJsonObject {
                put("occurrenceId",stage1Before[2]["id"]!!); put("providerId",JsonNull); put("exportSymbolKey",JsonNull); put("exportName",JsonNull); put("exportVersion",JsonNull); put("aliasTargetId",JsonNull)
                put("evidenceRefs",JsonArray(listOf(JsonPrimitive("recorded-weak-zero")))); put("absenceProof",absenceProof(stage1Id,stage1Before[2],"2".repeat(64),h))
            },
            select(stage1Before[3], null, internal.second, "internal_fn", internal.first["version"]!!.jsonObject, stage1Before[0]["id"]!!.jsonPrimitive.content),
        )
        val stage1 = makeStage(stage1Base, stage1Id, stage1Before, stage1Before, selections)
        val universe = buildJsonObject {
            put("expectedEntities", JsonArray(records.map { it.second })); put("expectedReferences", JsonArray(records.map { it.third }))
            put("ownerModuleIds", buildJsonArray { add("module-internal") }); put("stageIds", buildJsonArray { add(stage0Id); add(stage1Id) })
            put("provenanceLimitations", JsonArray(emptyList())); put("requiredGeneratedTables", JsonArray(emptyList()))
        }
        val policy = JsonObject(policyBase + mapOf("requirements" to JsonArray(requirements), "expectedStages" to buildJsonArray { add(stage0Id); add(stage1Id) }))
        val input = JsonObject(inputBase + mapOf("universe" to universe, "stages" to JsonArray(listOf(stage0, stage1))))
        return Fixture(policy, input)
    }

    private fun stageBase(action: String, ordinal: Int, kind: String, parents: List<String>, inputs: List<String>, outputRole: String, tool: JsonObject, config: String, h: String) = buildJsonObject {
        put("buildRunId", "build-multistage"); put("ordinal", ordinal); put("kind", kind); put("graphActionId", action)
        put("parentStageIds", JsonArray(parents.map(::JsonPrimitive))); put("sourceRevisionSha256", h); put("planSha256", h); put("policySha256", config)
        put("toolIds", buildJsonArray { add(tool["id"]!!) }); put("argv", buildJsonArray { add("cc"); add(if (kind == "executable") "-o" else "-r"); add("output") })
        put("environment", buildJsonObject { put("HOME", JsonNull) }); put("cwd", "/workspace/build")
        put("inputOccurrences", JsonArray(inputs.mapIndexed { index, role -> buildJsonObject {
            put("role", role); put("bytes", 10); put("sha256", h); put("member", JsonNull); put("sequence", index)
        } }))
        put("outputIdentities", buildJsonArray { add(buildJsonObject { put("role", outputRole); put("bytes", 10); put("sha256", h) }) })
    }

    private fun occurrence(stageId: String, row: Triple<JsonObject, JsonObject, JsonObject>, provider: JsonObject, index: Int): JsonObject {
        val requirement = row.first
        val disposition = requirement["disposition"]!!.jsonPrimitive.content
        val externalProviderId = if (disposition == "declared-external") provider["id"]!! else JsonNull
        return buildJsonObject {
            put("id", identity("occurrence", buildJsonObject { put("stageId", stageId); put("reference", row.third) }))
            put("symbolKey", row.second); put("reference", row.third); put("requirementId", requirement["id"]!!)
            put("ownerModuleId", requirement["ownerModuleId"]!!); put("providerId", externalProviderId)
            put("disposition", disposition); put("evidenceRefs", buildJsonArray { add("stage-census-$index") }); put("aliasTargetId", JsonNull)
        }
    }

    private fun makeStage(base: JsonObject, stageId: String, before: List<JsonObject>, after: List<JsonObject>, selections: List<JsonObject>) = JsonObject(base + mapOf(
        "id" to JsonPrimitive(stageId), "undefinedBefore" to JsonArray(before), "undefinedAfter" to JsonArray(after), "selections" to JsonArray(selections),
        "linkMapSha256" to JsonPrimitive("1".repeat(64)), "traceSha256" to JsonPrimitive("2".repeat(64)), "exitCode" to JsonPrimitive(0), "blockers" to JsonArray(emptyList()),
    ))

    private fun select(occurrence: JsonObject, providerId: String?, exportSymbolKey: JsonObject, exportName: String, exportVersion: JsonObject, aliasTargetId: String?) = buildJsonObject {
        put("occurrenceId", occurrence["id"]!!); put("providerId", providerId?.let(::JsonPrimitive) ?: JsonNull)
        put("exportSymbolKey", exportSymbolKey); put("exportName", exportName); put("exportVersion", exportVersion)
        put("aliasTargetId", aliasTargetId?.let(::JsonPrimitive) ?: JsonNull); put("evidenceRefs", buildJsonArray { add("selection-fixture") })
    }

    private fun absenceProof(stageId: String, occurrence: JsonObject, trace: String, map: String) = buildJsonObject {
        put("kind","recorded-weak-zero-v1"); put("stageId",stageId); put("requirementId",occurrence["requirementId"]!!)
        put("referenceSha256",OracleArtifacts.sha256(OracleJson.canonicalBytes(occurrence["reference"]!!)))
        put("traceSha256",trace); put("linkMapSha256",map); put("abiSourceId",occurrence["reference"]!!.jsonObject["abiSourceId"]!!)
        put("resolvedValue","0x0"); put("semantics","null-checked-optional-reference")
    }

    private fun withId(kind: String, base: JsonObject) = JsonObject(base + ("id" to JsonPrimitive(identity(kind, base))))
    private fun stageIdentity(stage: JsonObject): JsonObject {
        val excluded = setOf("id", "outputIdentities", "undefinedBefore", "undefinedAfter", "selections", "linkMapSha256", "traceSha256", "exitCode", "blockers")
        return JsonObject(JsonObject(stage - excluded) + mapOf(
            "parentStageIds" to JsonArray(stage["parentStageIds"]!!.jsonArray.sortedBy { it.jsonPrimitive.content }),
            "toolIds" to JsonArray(stage["toolIds"]!!.jsonArray.sortedBy { it.jsonPrimitive.content }),
            "outputIdentities" to JsonArray(stage["outputIdentities"]!!.jsonArray.map { buildJsonObject { put("role", it.jsonObject["role"]!!) } }.sortedBy { it["role"]!!.jsonPrimitive.content }),
        ))
    }
    private fun identity(kind: String, value: JsonObject): String {
        val domain = "a14-external-provider-v1:$kind".toByteArray(StandardCharsets.US_ASCII)
        val bytes = OracleJson.canonicalBytes(value)
        val payload = ByteBuffer.allocate(16 + domain.size + bytes.size).putLong(domain.size.toLong()).put(domain).putLong(bytes.size.toLong()).put(bytes).array()
        return OracleArtifacts.sha256(payload)
    }
    private fun assess(f: Fixture, limits: ExternalProviderLimitsV1 = ExternalProviderLimitsV1()) = FullTreeExternalProviderLedgerV1.assess(OracleJson.canonicalBytes(f.policy), OracleJson.canonicalBytes(f.input), deadline(), limits)
    private fun deadline() = AnalysisDeadline.start(TimeUnit.SECONDS.toNanos(30), "external provider ledger fixture")
}
