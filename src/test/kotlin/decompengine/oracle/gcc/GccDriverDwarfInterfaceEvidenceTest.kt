package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.BoundedDwarfCanonicalShardWriter
import decompengine.oracle.fulltree.BoundedDwarfShardLimits
import decompengine.oracle.fulltree.parseCanonicalDwarfShard
import decompengine.oracle.structural.DwarfSysvAmd64InterfaceProjection
import decompengine.oracle.structural.DwarfSysvAmd64Classification
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFactScanner
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFacts
import decompengine.oracle.fulltree.BoundedDwarfInterfaceTypeResolver
import decompengine.oracle.fulltree.BoundedDwarfObservationInventoryV1
import decompengine.oracle.fulltree.BoundedDwarfObservationInput
import decompengine.oracle.fulltree.BoundedDwarfInterfaceFactLimits
import decompengine.oracle.fulltree.DwarfInterfaceFact
import decompengine.oracle.fulltree.DwarfInterfaceFactState
import decompengine.oracle.fulltree.DwarfInterfaceFunctionFacts
import decompengine.oracle.fulltree.FullTreeControlException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class GccDriverDwarfInterfaceEvidenceTest {
    @Test
    fun `RVA mapping retains missing ambiguous and excluded facts without name inference`() {
        val records = JsonArray(listOf(
            oracle("unique", "0x3000"), oracle("ambiguous", "0x3010"), oracle("missing", "0x3020"),
            oracle("excluded", "0x3040", true), oracle("inline", null, true),
        ))
        val facts = listOf(
            function(0x3000UL, "die-1", "unrelated-name"),
            function(0x3010UL, "die-2"), function(0x3010UL, "die-3"),
            function(0x3020UL, "die-4", executable = false),
            function(0x3040UL, "die-5"), function(0x3999UL, "die-6", "missing"),
        )
        val projection = GccDriverDwarfInterfaceEvidence.mapFunctions(records, facts)
        val coverage = projection.getValue("coverage").jsonObject
        fun count(field: String, value: Int) = assertEquals(JsonPrimitive(value), coverage.getValue(field), field)
        count("oracleRecords", 5)
        count("scoredPhysicalFunctions", 3)
        count("excludedRecords", 2)
        count("uniqueRawDwarfFunctions", 1)
        count("ambiguousDwarfFunctions", 1)
        count("missingDwarfFunctions", 1)
        count("addressMatchedDwarfFunctions", 2)
        count("uniqueWithKnownRawReturnType", 1)
        count("uniqueWithKnownRawCallingConvention", 0)
        count("observableNeutralAbiFunctions", 0)
        count("unresolvedAbiFunctions", 3)
        val mapped = projection.getValue("functions").jsonArray.map { it.jsonObject }
        assertEquals(JsonArray(listOf(JsonPrimitive("die-1"))), mapped[0].getValue("candidateDieLocators"))
        assertEquals(JsonArray(listOf(JsonPrimitive("die-2"), JsonPrimitive("die-3"))), mapped[1].getValue("candidateDieLocators"))
        assertEquals(JsonArray(emptyList()), mapped[2].getValue("candidateDieLocators"))
        assertEquals(JsonPrimitive("no-physical-rva"), mapped[4].getValue("dwarfMatch"))
        assertTrue(mapped.all { it.getValue("projectedAbiLocator") == JsonNull })
        assertEquals(records[3].jsonObject.getValue("exclusion"), mapped[3].getValue("exclusion"))
        assertEquals(JsonArray(listOf(JsonPrimitive("die-4"), JsonPrimitive("die-6"))),
            projection.getValue("unmatchedRawCandidateDieLocators"))
        assertContentEquals(OracleJson.canonicalBytes(projection), OracleJson.canonicalBytes(
            GccDriverDwarfInterfaceEvidence.mapFunctions(records, facts.reversed())))
    }

    @Test
    fun `inventory selections preserve every reviewed record independently of ABI classification`() {
        val oracle = JsonArray(listOf(oracle("known", "0x3000"), oracle("missing", "0x3010"), oracle("inline", null, true)))
        val mapping = GccDriverDwarfInterfaceEvidence.mapFunctions(oracle, listOf(function(0x3000UL, "die-1")))
        val changed = JsonObject(mapping + ("functions" to JsonArray(mapping.getValue("functions").jsonArray.map {
            JsonObject(it.jsonObject + mapOf("abiStatus" to JsonPrimitive("changed-ABI-assessment"),
                "projectedAbiLocator" to JsonPrimitive("unrelated-projection")))
        })))
        fun selectionFields(value: JsonObject) = GccDriverDwarfInterfaceEvidence.inventorySelections(value).map {
            listOf(it.id, it.rva?.toString(16), it.candidateLocators.joinToString(","), it.excluded.toString())
        }
        assertEquals(listOf(listOf("known", "3000", "die-1", "false"),
            listOf("missing", "3010", "", "false"), listOf("inline", null, "", "true")), selectionFields(mapping))
        assertEquals(selectionFields(mapping), selectionFields(changed))
    }

    @Test
    fun `driver capture rejects a same-size changed checked control before scanning`() = temporary { temp ->
        val path = temp.resolve("oracle/targets/sysv-amd64-v1.json")
        Files.createDirectories(path.parent)
        val checked = Files.readAllBytes(repositoryRoot().resolve("oracle/targets/sysv-amd64-v1.json"))
        val changed = checked.decodeToString().replace("\"addressBits\": 64", "\"addressBits\": 32").toByteArray()
        assertEquals(checked.size, changed.size)
        assertNotEquals(OracleArtifacts.sha256(checked), OracleArtifacts.sha256(changed))
        Files.write(path, changed)
        val failure = assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.capture(temp, Files.createDirectory(temp.resolve("scratch")))
        }
        assertTrue(failure.message.orEmpty().contains("targetAbi differs from its checked identity"))
    }

    @Test
    fun `driver capture rejects aliased checked control paths`() = temporary { temp ->
        val path = temp.resolve("oracle/targets/sysv-amd64-v1.json")
        Files.createDirectories(path.parent)
        val bytes = Files.readAllBytes(repositoryRoot().resolve("oracle/targets/sysv-amd64-v1.json"))
        val actual = Files.write(temp.resolve("target.json"), bytes)
        Files.createSymbolicLink(path, actual)
        assertFailsWith<Exception> {
            GccDriverDwarfInterfaceEvidence.capture(temp, Files.createDirectory(temp.resolve("scratch")))
        }
    }

    @Test
    fun `checked rich GCC driver produces repeatable raw DWARF interface evidence`() {
        assumeTrue(System.getenv("DECOMP_REQUIRE_GCC_DWARF_INTERFACES") == "true", "actual GCC DWARF qualification is opt-in")
        val root = repositoryRoot()
        val destination = (System.getenv("DECOMP_GCC_DWARF_EVIDENCE_ROOT")?.let(Path::of)
            ?: root.resolve("build/gcc-driver-dwarf-interfaces")).toAbsolutePath().normalize()
        require(destination.startsWith(root) && destination != root) { "qualification output must remain inside the repository" }
        Files.createDirectories(destination, PRIVATE_DIRECTORY)
        val scratch = Files.createDirectories(destination.resolve("scratch"), PRIVATE_DIRECTORY)
        val started = System.nanoTime()
        val first = GccDriverDwarfInterfaceEvidence.capture(root, scratch)
        val firstBytes = first.canonicalBytes()
        val originalFirstByte = firstBytes[0]
        firstBytes[0] = 0
        assertEquals(originalFirstByte, first.canonicalBytes()[0], "publication must return defensive byte copies")
        val second = GccDriverDwarfInterfaceEvidence.capture(root, scratch)
        assertContentEquals(first.canonicalBytes(), second.canonicalBytes())
        assertEquals(first.partNames, second.partNames)
        first.partNames.forEach { name -> assertContentEquals(first.partBytes(name), second.partBytes(name), name) }
        val parts = first.partNames.map { it to first.partBytes(it) }
        val policy = checkedAutomaticLocalPolicy(root)
        GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts, automaticLocalPolicy = policy)
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.dropLast(1), automaticLocalPolicy = policy) }
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.reversed(), automaticLocalPolicy = policy) }
        val changedPart = parts.first().second.copyOf().also { it[it.lastIndex] = 0 }
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), listOf(parts.first().first to changedPart) + parts.drop(1),
                automaticLocalPolicy = policy)
        }
        val document = OracleJson.parseCanonical(first.canonicalBytes(), GccDriverDwarfInterfaceEvidence.EVIDENCE_JSON_LIMITS).jsonObject
        exerciseRehashedDecisionTamper(document, parts, policy)
        val rehashedDecisionTamperResult = "rehashed-decision-membership-change-rejected"
        assertEquals(JsonPrimitive(7), document.getValue("schemaVersion"))
        assertEquals(JsonPrimitive("gcc-driver-dwarf-interface-evidence-v7"), document.getValue("provider"))
        listOf("complete", "scored", "productionVerified", "releaseEligible").forEach {
            assertEquals(JsonPrimitive(false), document.getValue(it), it)
        }
        val coverage = document.getValue("coverage").jsonObject
        assertEquals(JsonPrimitive(12_844), coverage.getValue("oracleRecords"))
        assertEquals(JsonPrimitive(3_284), coverage.getValue("scoredPhysicalFunctions"))
        assertEquals(JsonPrimitive(9_560), coverage.getValue("excludedRecords"))
        val observable = coverage.getValue("observableNeutralAbiFunctions").jsonPrimitive.content.toInt()
        assertTrue(observable > 0 && observable <= 3_284, "actual neutral projection must produce measured observability")
        assertEquals(3_284 - observable, coverage.getValue("unresolvedAbiFunctions").jsonPrimitive.content.toInt())
        assertTrue(coverage.getValue("uniqueRawDwarfFunctions").jsonPrimitive.content.toInt() > 0)
        fun records(kind: String) = parts.filter { it.first.contains("-$kind-") }.flatMap {
            parseCanonicalDwarfShard(it.second).records
        }
        val metadata = records("metadata").single()
        assertEquals(JsonPrimitive(BoundedDwarfInterfaceFactScanner.PRODUCER), metadata.getValue("schema"))
        assertTrue(records("functions").isNotEmpty())
        assertTrue(records("types").isNotEmpty())
        assertTrue(records("globals").isNotEmpty())
        assertTrue(records("globalProjection").isNotEmpty())
        val inventory = document.getValue("prePolicyInventory").jsonObject
        val secondInventory = OracleJson.parseCanonical(second.canonicalBytes(),
            GccDriverDwarfInterfaceEvidence.EVIDENCE_JSON_LIMITS).jsonObject.getValue("prePolicyInventory")
        assertEquals(inventory, secondInventory, "both authenticated captures must reproduce the pre-policy commitment")
        val inventoryCounts = inventory.getValue("counts").jsonObject
        assertEquals(JsonPrimitive(records("functions").size), inventoryCounts.getValue("functionReturnRoots"))
        assertEquals(JsonPrimitive(records("globals").size), inventoryCounts.getValue("variableRoots"))
        assertEquals(JsonPrimitive(12_844), inventoryCounts.getValue("selections"))
        assertEquals(12_844, records("inventorySelections").size)
        assertTrue(records("inventoryRoots").isNotEmpty())
        assertTrue(records("inventoryTypeCompleteness").isNotEmpty())
        val rawGlobals = records("globals")
        val decisions = records(GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND)
        assertEquals(rawGlobals.size, decisions.size, "every raw variable record must have one decision")
        val application = document.getValue("automaticLocalPopulation").jsonObject
        val independentlyExcluded = decisions.count { it.getValue("classification") == JsonPrimitive("excluded") }
        val independentlyRetained = decisions.size - independentlyExcluded
        val counts = application.getValue("counts").jsonObject
        assertEquals(JsonPrimitive(rawGlobals.size), counts.getValue("rawVariableRecords"))
        assertEquals(JsonPrimitive(independentlyExcluded), counts.getValue("excludedAutomaticLocalRecords"))
        assertEquals(JsonPrimitive(independentlyRetained), counts.getValue("retainedRawCandidateRecords"))
        val globalsByLocator = rawGlobals.associateBy { it.getValue("locator").jsonPrimitive.content }
        decisions.filter { it.getValue("classification") == JsonPrimitive("excluded") }.forEach { decision ->
            val declaration = globalsByLocator.getValue(decision.getValue("sourceLocator").jsonPrimitive.content)
                .getValue("declaration").jsonObject
            val accepted = declaration.getValue("state") == JsonPrimitive("absent") && declaration.getValue("values") == JsonArray(emptyList()) ||
                declaration.getValue("state") == JsonPrimitive("known") && declaration.getValue("values") == JsonArray(listOf(JsonPrimitive("0")))
            assertTrue(accepted, "excluded record lacks the closed negative declaration guard")
        }
        val declarationVetoed = decisions.count {
            it.getValue("reason") == JsonPrimitive("declaration-is-not-a-proved-definition")
        }
        val candidateIds = records("functions").map { it.getValue("locator").jsonPrimitive.content }.toSet()
        records("oracleFunctions").forEach { record ->
            record.getValue("candidateDieLocators").jsonArray.forEach { assertTrue(it.jsonPrimitive.content in candidateIds) }
        }
        val tamperResults = exerciseCheckedInputTampering(root, destination, document) +
            listOf(rehashedDecisionTamperResult, "missing-shard-rejected", "altered-shard-rejected", "reordered-shards-rejected")
        first.visitParts { relative, bytes ->
            val path = destination.resolve(relative)
            Files.createDirectories(path.parent, PRIVATE_DIRECTORY)
            OracleArtifacts.publishAtomically(path, bytes, OracleArtifactLimits(GccDriverDwarfInterfaceEvidence.SHARD_LIMITS.maximumShardBytes))
        }
        OracleArtifacts.publishAtomically(destination.resolve(GccDriverDwarfInterfaceEvidence.EVIDENCE_NAME), first.canonicalBytes(),
            OracleArtifactLimits(GccDriverDwarfInterfaceEvidence.MAXIMUM_EVIDENCE_BYTES))
        val qualification = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-driver-dwarf-interface-qualification-v7"),
            "prePolicyInventorySha256" to inventory.getValue("inventorySha256"),
            "policyInput" to document.getValue("inputs").jsonObject.getValue("automaticLocalPopulationPolicy"),
            "canonicalPolicySha256" to application.getValue("canonicalPolicySha256"),
            "automaticLocalPopulationApplicationSha256" to application.getValue("applicationSha256"),
            "decisionCommitment" to application.getValue("decisionCommitment"),
            "decisionCounts" to counts,
            "declarationVetoedOtherwisePositiveRecords" to JsonPrimitive(declarationVetoed),
            "evidenceSha256" to JsonPrimitive(first.sha256), "evidenceBytes" to JsonPrimitive(first.canonicalBytes().size),
            "deterministicRepeat" to JsonPrimitive(true), "deterministicBundleParts" to JsonPrimitive(first.partNames.size), "tamperChecks" to JsonArray(tamperResults.map(::JsonPrimitive)),
            "elapsedMillis" to JsonPrimitive((System.nanoTime() - started) / 1_000_000),
            "producerSourceRevision" to (System.getenv("GITHUB_SHA")?.let(::JsonPrimitive) ?: JsonNull),
            "javaRuntimeVersion" to JsonPrimitive(System.getProperty("java.runtime.version")),
            "javaVendor" to JsonPrimitive(System.getProperty("java.vendor")),
            "osName" to JsonPrimitive(System.getProperty("os.name")), "osArch" to JsonPrimitive(System.getProperty("os.arch")),
            "compiledClassResources" to JsonArray(listOf(
                BoundedDwarfInterfaceFactScanner::class.java, BoundedDwarfInterfaceTypeResolver::class.java,
                BoundedDwarfInterfaceFacts::class.java, GccDriverDwarfInterfaceEvidence::class.java,
                DwarfSysvAmd64InterfaceProjection::class.java, DwarfSysvAmd64Classification::class.java,
                GccDriverDwarfGlobalProjection::class.java, BoundedDwarfCanonicalShardWriter::class.java,
                BoundedDwarfObservationInventoryV1::class.java, GccDriverAutomaticLocalPopulationPolicyV1::class.java,
            ).map(::compiledClassIdentity)),
            "identityScope" to JsonPrimitive("bounded classpath resource bytes read during qualification; not a signed or complete runtime closure"),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ))
        OracleArtifacts.publishAtomically(destination.resolve(GccDriverDwarfInterfaceEvidence.QUALIFICATION_NAME),
            OracleJson.canonicalBytes(qualification))
        println("GCC raw DWARF interface evidence retained at $destination; ${first.sha256}")
    }

    @Test
    fun `small v3 bundle rejects missing altered reordered and rehashed reordered parts`() {
        val facts = BoundedDwarfInterfaceFacts("0".repeat(64), 1L, "ET_EXEC", 0x400000UL,
            emptyList(), emptyList(), emptyMap(), 0L, 0, true, BoundedDwarfInterfaceFactLimits())
        val inventory = BoundedDwarfObservationInventoryV1.collect(facts, emptyList(), null,
            listOf(BoundedDwarfObservationInput("rich", facts.inputSha256, facts.inputBytes)))
        val base = fixtureManifest(6, inventory.manifest)
        val kinds = listOf("metadata", "functions", "types", "typeChildren", "globals", "objectSymbols", "physicalUnits", "physicalDies", "strippedObjects",
            "projectedTypes", "projectedFunctions", "projectedGlobalTypes", "oracleFunctions", "unmatchedFunctions", "globalProjection") +
            BoundedDwarfObservationInventoryV1.RECORD_KINDS
        val groups = kinds.associateWith { mutableListOf<JsonObject>() }
        val retain: (String, Int, ByteArray, Int) -> Unit = { kind, ordinal, bytes, count ->
            groups.getValue(kind) += parseCanonicalDwarfShard(bytes, expectedKind = kind,
                expectedOrdinal = ordinal, expectedRecordCount = count).records
        }
        facts.visitCanonicalShards(retain)
        inventory.visitCanonicalShards(retain)
        fun bundle(order: List<String> = kinds) = GccDriverDwarfInterfaceEvidence.pack(base) { consume ->
            val writer = BoundedDwarfCanonicalShardWriter(GccDriverDwarfInterfaceEvidence.SHARD_LIMITS, consume)
            order.forEach { writer.write(it, groups[it]?.asSequence() ?: emptySequence()) }
            writer.finish()
        }
        val first = bundle(); val second = bundle()
        assertContentEquals(first.canonicalBytes(), second.canonicalBytes())
        val parts = first.partNames.map { it to first.partBytes(it) }
        parts.forEach { (name, bytes) -> assertContentEquals(bytes, second.partBytes(name)) }
        GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts)
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), parts.reversed()) }
        val altered = parts.first().second.copyOf().also { it[it.lastIndex] = 0 }
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(first.canonicalBytes(), listOf(parts.first().first to altered) + parts.drop(1))
        }
        val manifest = OracleJson.parseCanonical(first.canonicalBytes()).jsonObject
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(
                OracleJson.canonicalBytes(JsonObject(manifest + ("unknownAuthority" to JsonPrimitive(true)))), parts,
            )
        }
        val descriptors = manifest.getValue("parts").jsonArray
        assertEquals(JsonPrimitive(0), descriptors.single {
            it.jsonObject["kind"] == JsonPrimitive("typeChildren")
        }.jsonObject["recordCount"])
        assertFailsWith<IllegalArgumentException> { bundle(kinds - "typeChildren") }
        assertFailsWith<IllegalArgumentException> { bundle((kinds - "typeChildren") + "typeChildren") }
        assertFailsWith<IllegalArgumentException> { bundle(kinds.map { if (it == "typeChildren") "unknownChildren" else it }) }
        val changedManifest = OracleJson.canonicalBytes(JsonObject(manifest + ("parts" to JsonArray(descriptors.reversed()))))
        assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(changedManifest, parts.reversed()) }
        for (numeric in listOf("ordinal", "recordCount")) {
            val changed = JsonObject(descriptors.first().jsonObject +
                (numeric to JsonPrimitive(descriptors.first().jsonObject.getValue(numeric).jsonPrimitive.content)))
            val typedManifest = OracleJson.canonicalBytes(JsonObject(manifest +
                ("parts" to JsonArray(listOf(changed) + descriptors.drop(1)))))
            assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.verifyBundle(typedManifest, parts) }
        }
        val copy = first.partBytes(first.partNames.first()); copy[0] = 0
        assertNotEquals(0, first.partBytes(first.partNames.first())[0].toInt())
    }

    @Test
    fun `v7 bundle preserves v6 observations and verifies automatic-local decisions`() {
        val fixture = emptyPolicyBundleFixture()
        val artifact = fixture.v7
        val parts = artifact.partNames.map { it to artifact.partBytes(it) }
        GccDriverDwarfInterfaceEvidence.verifyBundle(artifact.canonicalBytes(), parts,
            automaticLocalPolicy = fixture.policy)
        assertEquals(fixture.v6.partNames, artifact.partNames.dropLast(1))
        fixture.v6.partNames.forEach { name -> assertContentEquals(fixture.v6.partBytes(name), artifact.partBytes(name), name) }
        val document = OracleJson.parseCanonical(artifact.canonicalBytes()).jsonObject
        assertEquals(JsonPrimitive(7), document.getValue("schemaVersion"))
        assertEquals(fixture.inventory.manifest, document.getValue("prePolicyInventory"))
        assertTrue(document.getValue("prePolicyInventory").jsonObject.getValue("inputs").jsonArray.none {
            it.jsonObject.getValue("role") == JsonPrimitive("automaticLocalPopulationPolicy")
        })
        assertEquals(JsonPrimitive(0), document.getValue("automaticLocalPopulation").jsonObject
            .getValue("counts").jsonObject.getValue("rawVariableRecords"))
    }

    @Test
    fun `v7 rejects rehashed membership and policy substitutions`() {
        val fixture = emptyPolicyBundleFixture()
        val artifact = fixture.v7
        val parts = artifact.partNames.map { it to artifact.partBytes(it) }
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(artifact.canonicalBytes(), parts.dropLast(1),
                automaticLocalPolicy = fixture.policy)
        }
        val manifest = OracleJson.parseCanonical(artifact.canonicalBytes()).jsonObject
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(OracleJson.canonicalBytes(JsonObject(
                manifest + ("unknownAuthority" to JsonPrimitive(true)),
            )), parts, automaticLocalPolicy = fixture.policy)
        }
        val inputs = manifest.getValue("inputs").jsonObject
        val policyInput = inputs.getValue("automaticLocalPopulationPolicy").jsonObject
        val substituted = JsonObject(policyInput + ("sha256" to JsonPrimitive("f".repeat(64))))
        val changed = JsonObject(manifest + ("inputs" to JsonObject(inputs +
            ("automaticLocalPopulationPolicy" to substituted))))
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(OracleJson.canonicalBytes(changed), parts,
                automaticLocalPolicy = fixture.policy)
        }
        val shardLimits = BoundedDwarfShardLimits()
        val largeEnvelope = OracleJson.canonicalBytes(JsonObject(linkedMapOf(
            "schema" to JsonPrimitive("bounded-dwarf-record-shard-v1"),
            "kind" to JsonPrimitive(GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND),
            "ordinal" to JsonPrimitive(0), "recordCount" to JsonPrimitive(300),
            "records" to JsonArray(List(300) { JsonObject(mapOf(
                "payload" to JsonPrimitive("x".repeat(14_000)),
            )) }),
        )), shardLimits.jsonLimits())
        assertTrue(largeEnvelope.size > 4 * 1024 * 1024, "fixture must exceed the generic JSON input limit")
        val parsedLargeEnvelope = parseDecisionEnvelopeForTamper(largeEnvelope)
        assertEquals(300, parsedLargeEnvelope.getValue("records").jsonArray.size)
        assertContentEquals(largeEnvelope, canonicalDecisionEnvelopeForTamper(parsedLargeEnvelope))
    }

    private data class EmptyPolicyBundleFixture(
        val policy: GccDriverAutomaticLocalPopulationPolicy,
        val inventory: decompengine.oracle.fulltree.BoundedDwarfObservationInventory,
        val v6: GccDriverDwarfInterfaceArtifact,
        val v7: GccDriverDwarfInterfaceArtifact,
    )

    private fun fixtureManifest(
        version: Int,
        inventory: JsonObject,
        population: JsonObject? = null,
        inputs: JsonObject = JsonObject(emptyMap()),
    ): JsonObject {
        require(version == 6 && population == null || version == 7 && population != null)
        val fields = linkedMapOf<String, JsonElement>(
            "schemaVersion" to JsonPrimitive(version),
            "provider" to JsonPrimitive("gcc-driver-dwarf-interface-evidence-v$version"),
            "oracleId" to JsonPrimitive("fixture"), "sourceRevision" to JsonPrimitive("0".repeat(40)),
            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false),
            "productionVerified" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
            "configuration" to JsonObject(emptyMap()), "inputs" to inputs,
            "targetAbi" to JsonObject(emptyMap()), "ruleProfile" to JsonObject(emptyMap()),
            "ruleProfileSha256" to JsonPrimitive("0".repeat(64)),
            "coverage" to JsonObject(emptyMap()), "globalCoverage" to JsonObject(emptyMap()),
            "prePolicyInventory" to inventory,
            "globalDeclaredTypeCoverage" to JsonObject(emptyMap()),
            "strippedObjectLayout" to JsonNull, "reviewedExclusions" to JsonObject(emptyMap()),
            "unresolved" to JsonArray(emptyList()),
        )
        if (population != null) fields["automaticLocalPopulation"] = population
        return JsonObject(fields)
    }

    private fun emptyPolicyBundleFixture(): EmptyPolicyBundleFixture {
        val facts = BoundedDwarfInterfaceFacts("0".repeat(64), 1L, "ET_EXEC", 0x400000UL,
            emptyList(), emptyList(), emptyMap(), 0L, 0, true, BoundedDwarfInterfaceFactLimits())
        val inventory = BoundedDwarfObservationInventoryV1.collect(facts, emptyList(), null,
            listOf(BoundedDwarfObservationInput("rich", facts.inputSha256, facts.inputBytes)))
        val policyPath = repositoryRoot().resolve("oracle/gcc/16.2.0/automatic-local-population-policy-v1.json")
        val policyBytes = Files.readAllBytes(policyPath)
        val policy = GccDriverAutomaticLocalPopulationPolicyV1.load(policyBytes)
        val rawCommitment = inventory.manifest.getValue("rawCommitments").jsonArray.map { it.jsonObject }
            .single { it.getValue("kind") == JsonPrimitive("globals") }
        val population = GccDriverAutomaticLocalPopulationPolicyV1.apply(policy, emptySequence(),
            OracleArtifacts.sha256(policyBytes), policyBytes.size.toLong(),
            inventory.manifest.getValue("inventorySha256").jsonPrimitive.content, rawCommitment)
        val v6Document = fixtureManifest(6, inventory.manifest)
        val v7Document = fixtureManifest(7, inventory.manifest, population.summary, JsonObject(mapOf(
            "automaticLocalPopulationPolicy" to JsonObject(mapOf(
                "path" to JsonPrimitive("oracle/gcc/16.2.0/automatic-local-population-policy-v1.json"),
                "bytes" to JsonPrimitive(policyBytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(policyBytes)),
            )),
        )))
        val v6Kinds = listOf("metadata", "functions", "types", "typeChildren", "globals", "objectSymbols", "physicalUnits", "physicalDies", "strippedObjects",
            "projectedTypes", "projectedFunctions", "projectedGlobalTypes", "oracleFunctions", "unmatchedFunctions", "globalProjection") +
            BoundedDwarfObservationInventoryV1.RECORD_KINDS
        val groups = v6Kinds.associateWith { mutableListOf<JsonObject>() }
        val retain: (String, Int, ByteArray, Int) -> Unit = { kind, ordinal, bytes, count ->
            groups.getValue(kind) += parseCanonicalDwarfShard(bytes, expectedKind = kind,
                expectedOrdinal = ordinal, expectedRecordCount = count).records
        }
        facts.visitCanonicalShards(retain)
        inventory.visitCanonicalShards(retain)
        fun bundle(document: JsonObject, v7: Boolean) = GccDriverDwarfInterfaceEvidence.pack(document,
            automaticLocalPolicy = if (v7) policy else null) { consume ->
            val writer = BoundedDwarfCanonicalShardWriter(GccDriverDwarfInterfaceEvidence.SHARD_LIMITS, consume)
            v6Kinds.forEach { writer.write(it, groups.getValue(it).asSequence()) }
            if (v7) writer.write(GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND, population.decisions.asSequence())
            writer.finish()
        }
        return EmptyPolicyBundleFixture(policy, inventory, bundle(v6Document, false), bundle(v7Document, true))
    }

    private fun exerciseCheckedInputTampering(root: Path, destination: Path, document: JsonObject): List<String> {
        val fixture = Files.createTempDirectory(destination, "tamper-", PRIVATE_DIRECTORY)
        try {
            document.getValue("inputs").jsonObject.values.forEach { value ->
                val relative = value.jsonObject.getValue("path").jsonPrimitive.content
                val path = fixture.resolve(relative)
                Files.createDirectories(path.parent)
                Files.copy(root.resolve(relative), path)
            }
            val scratch = Files.createDirectory(fixture.resolve("scratch"), PRIVATE_DIRECTORY)
            val full = fixture.resolve("oracle/gcc/16.2.0/artifacts/gcc-driver.full")
            flipLastByte(full)
            val wrongBytes = assertFailsWith<IllegalArgumentException> { GccDriverDwarfInterfaceEvidence.capture(fixture, scratch) }
            assertTrue(wrongBytes.message.orEmpty().contains("rich differs from its checked identity"))
            flipLastByte(full)
            val policy = fixture.resolve("oracle/gcc/16.2.0/automatic-local-population-policy-v1.json")
            flipLastByte(policy)
            val wrongPolicy = assertFailsWith<IllegalArgumentException> {
                GccDriverDwarfInterfaceEvidence.capture(fixture, scratch)
            }
            assertTrue(wrongPolicy.message.orEmpty().contains("automaticLocalPopulationPolicy differs from its checked identity"))
            flipLastByte(policy)
            var replaced = false
            val replacedControl = assertFailsWith<FullTreeControlException> {
                GccDriverDwarfInterfaceEvidence.capture(fixture, scratch) { stage ->
                    if (stage == "before scanning checked GCC driver interfaces") {
                        val saved = policy.resolveSibling("old-automatic-local-policy.json")
                        Files.move(policy, saved)
                        Files.copy(saved, policy)
                        replaced = true
                    }
                }
            }
            assertTrue(replaced, "retained identity attack did not execute")
            assertTrue(replacedControl.message.orEmpty().startsWith("before GCC driver interface scan: automaticLocalPopulationPolicy "),
                "wrong rejection: ${replacedControl.message}")
            return listOf("same-size-rich-byte-tamper-rejected", "same-size-policy-byte-tamper-rejected",
                "same-content-policy-path-replacement-rejected")
        } finally { deleteTree(fixture) }
    }

    private fun exerciseRehashedDecisionTamper(
        manifest: JsonObject,
        parts: List<Pair<String, ByteArray>>,
        policy: GccDriverAutomaticLocalPopulationPolicy,
    ) {
        val index = parts.indexOfFirst { it.first.contains("-${GccDriverAutomaticLocalPopulationPolicyV1.DECISION_KIND}-") }
        assertTrue(index >= 0, "decision shard is absent")
        val envelope = parseDecisionEnvelopeForTamper(parts[index].second)
        val records = envelope.getValue("records").jsonArray
        assertTrue(records.isNotEmpty(), "actual qualification must emit policy decisions")
        val first = records.first().jsonObject
        val forged = JsonObject(first + mapOf(
            "classification" to JsonPrimitive(if (first.getValue("classification") == JsonPrimitive("excluded"))
                "retained-raw-candidate" else "excluded"),
            "reason" to JsonPrimitive(if (first.getValue("classification") == JsonPrimitive("excluded"))
                "automatic-local-not-positively-proved" else "positively-proved-automatic-local"),
        ))
        val forgedEnvelope = JsonObject(envelope + ("records" to JsonArray(listOf(forged) + records.drop(1))))
        val forgedBytes = canonicalDecisionEnvelopeForTamper(forgedEnvelope)
        val parsed = parseCanonicalDwarfShard(forgedBytes)
        val descriptor = manifest.getValue("parts").jsonArray[index].jsonObject
        val forgedDescriptor = JsonObject(descriptor + mapOf(
            "bytes" to JsonPrimitive(forgedBytes.size),
            "nodes" to JsonPrimitive(parsed.nodeCount),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(forgedBytes)),
        ))
        val forgedManifest = JsonObject(manifest + ("parts" to JsonArray(
            manifest.getValue("parts").jsonArray.mapIndexed { selected, value ->
                if (selected == index) forgedDescriptor else value
            },
        )))
        val forgedParts = parts.mapIndexed { selected, value -> if (selected == index) value.first to forgedBytes else value }
        assertFailsWith<IllegalArgumentException> {
            GccDriverDwarfInterfaceEvidence.verifyBundle(OracleJson.canonicalBytes(forgedManifest), forgedParts,
                automaticLocalPolicy = policy)
        }
    }

    private fun parseDecisionEnvelopeForTamper(bytes: ByteArray): JsonObject =
        OracleJson.parseCanonical(bytes, BoundedDwarfShardLimits().jsonLimits()).jsonObject

    private fun canonicalDecisionEnvelopeForTamper(envelope: JsonObject): ByteArray =
        OracleJson.canonicalBytes(envelope, BoundedDwarfShardLimits().jsonLimits())

    private fun compiledClassIdentity(type: Class<*>): JsonObject {
        val resource = "/${type.name.replace('.', '/')}.class"
        val bytes = requireNotNull(type.getResourceAsStream(resource)).use { it.readNBytes(4 * 1024 * 1024 + 1) }
        require(bytes.isNotEmpty() && bytes.size <= 4 * 1024 * 1024)
        return JsonObject(mapOf("class" to JsonPrimitive(type.name), "resource" to JsonPrimitive(resource),
            "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))
    }

    private fun checkedAutomaticLocalPolicy(root: Path = repositoryRoot()): GccDriverAutomaticLocalPopulationPolicy =
        GccDriverAutomaticLocalPopulationPolicyV1.load(
            Files.readAllBytes(root.resolve("oracle/gcc/16.2.0/automatic-local-population-policy-v1.json")),
        )

    private fun flipLastByte(path: Path) = FileChannel.open(path, StandardOpenOption.READ, StandardOpenOption.WRITE).use { channel ->
        val value = ByteBuffer.allocate(1)
        assertEquals(1, channel.read(value, channel.size() - 1))
        value.array()[0] = (value.array()[0].toInt() xor 1).toByte()
        value.rewind()
        assertEquals(1, channel.write(value, channel.size() - 1))
        channel.force(true)
    }

    private fun oracle(id: String, rva: String?, excluded: Boolean = false) = JsonObject(mapOf(
        "id" to JsonPrimitive(id), "rva" to (rva?.let(::JsonPrimitive) ?: JsonNull),
        "aliases" to JsonArray(listOf(JsonObject(mapOf("name" to JsonPrimitive(id))))),
        "exclusion" to if (excluded) JsonObject(mapOf("kind" to JsonPrimitive("reviewed"), "reason" to JsonPrimitive("retained reason"))) else JsonNull,
    ))

    private fun function(rva: ULong, locator: String, name: String = "raw-name", executable: Boolean = true): DwarfInterfaceFunctionFacts {
        val absent = DwarfInterfaceFact<String>(DwarfInterfaceFactState.ABSENT)
        return DwarfInterfaceFunctionFacts(rva, 0x400000UL + rva, executable, locator,
            DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(name)), absent, absent, absent, absent, absent, absent,
            DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf("raw-type-id")), emptyList(),
            DwarfInterfaceFact(DwarfInterfaceFactState.KNOWN, listOf(locator)), emptyList(),
            DwarfInterfaceFact(DwarfInterfaceFactState.ABSENT), emptyList(), emptyList())
    }

    private fun repositoryRoot(): Path = Path.of("").toAbsolutePath().normalize()
    private fun temporary(block: (Path) -> Unit) {
        val parent = Files.createDirectories(repositoryRoot().resolve("build/test-tmp"), PRIVATE_DIRECTORY)
        val directory = Files.createTempDirectory(parent, "gcc-interface-", PRIVATE_DIRECTORY)
        try { block(directory) } finally { deleteTree(directory) }
    }
    private fun deleteTree(directory: Path) = Files.walk(directory).use { paths ->
        paths.sorted(java.util.Comparator.reverseOrder()).forEach { Files.deleteIfExists(it) }
    }
    private companion object {
        val PRIVATE_DIRECTORY = PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------"))
    }
}
