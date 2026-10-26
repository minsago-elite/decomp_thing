package decompengine.oracle.machinecalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeElfTestBytes
import decompengine.oracle.fulltree.TestElfSymbol
import decompengine.oracle.fulltree.TestElfVariant
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class IndependentMachineCallsV1Test {
    internal fun withComponentFixture(action: (JsonObject) -> Unit) = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 0x20), Symbol("target", 0x150, 1)), listOf(0x110, 0x150))
        action(input.produce(cfgDecoder()))
    }

    internal fun withWorkerFixture(action: (Path, Path, String, String, String) -> Unit) = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 16), Symbol("target", 0x150, 1), Symbol("truncated", 0x170, 1)),
            listOf(0x110, 0x150, 0x170), code = mapOf(0x110 to byteArrayOf(-24, 59, 0, 0, 0, -1, -48, -112, -61),
                0x170 to byteArrayOf(-24)))
        action(input.rich, input.oracle, input.inputSha, input.oracleSha, input.manifestSha)
    }

    @Test fun `every raw function and canonical record remains visible including unresolved ownership`() = fixture { root ->
        val symbols = listOf(
            Symbol("caller", 0x110, 2), Symbol("alias", 0x110, 2), Symbol("target", 0x120, 1),
            Symbol("zero", 0x140, 0), Symbol("import", null, 7), Symbol("resolver", 0x150, 1, type = 10),
            Symbol("overlap-one", 0x160, 8), Symbol("overlap-two", 0x164, 8),
            Symbol("", 0x180, 1), Symbol("outside-text", 0x300, 1),
        )
        val input = input(root, symbols, listOf(0x110, 0x120, 0x140, 0x150, 0x160, 0x164, 0x180, 0x190), inline = true)
        val visited = mutableListOf<ULong>()
        val report = input.produce(MachineInstructionDecoderV1 { address, bytes ->
            visited += address
            instruction(address, bytes, "return")
        })
        assertEquals(10L, report.count("rawFunctionSymbols"))
        assertEquals(9L, report.count("roots"))
        assertEquals(9L, report.count("canonicalFunctions"))
        val roots = report.records("roots")
        assertEquals(10, roots.sumOf { (it.getValue("origins") as JsonArray).size })
        assertEquals(listOf("caller", "alias"), roots.single { it.text("rva") == "0x110" }.records("origins").map { it.text("name") })
        assertEquals(1, roots.flatMap { it.records("origins") }.count { it.text("name").isEmpty() })
        fun problems(rva: String) = roots.single { it.text("rva") == rva }.texts("ownershipProblems")
        assertTrue("zero-size-no-end-inference" in problems("0x140"))
        assertTrue("ifunc-resolver-identity-unresolved" in problems("0x150"))
        assertTrue("overlapping-symbol-extents" in problems("0x160"))
        assertTrue("overlapping-symbol-extents" in problems("0x164"))
        assertTrue("extent-not-in-executable-section" in problems("0x300"))
        assertTrue(roots.single { it["rva"] == JsonNull }.texts("ownershipProblems").contains("non-defined-function-symbol"))
        val canonical = report.records("canonicalPopulation")
        assertEquals("unresolved-missing-symbol-extent", canonical.single { it.text("id") == "canonical-190" }.text("disposition"))
        assertEquals("unresolved-no-emitted-address", canonical.single { it.text("id") == "inlined-only" }.text("disposition"))
        assertEquals(listOf(0x400110UL, 0x400120UL, 0x400180UL), visited)
        assertNoNegativeAuthority(report)
    }

    @Test fun `below base raw extent revokes overlapping caller ownership and positive calls`() =
        withBelowBaseCallFixture(0x130) { report, visits ->
            val roots = report.records("roots")
            val below = roots.single { it["rva"] == JsonNull }
            val caller = roots.single { it.text("rva") == "0x110" }
            assertTrue("below-image-base" in below.texts("ownershipProblems"))
            for (record in listOf(below, caller)) assertTrue("overlapping-symbol-extents" in record.texts("ownershipProblems"))
            assertEquals(listOf(0x400150UL), visits)
            assertEquals(0L, report.count("physicalCallSites"))
            assertEquals(0L, report.count("positiveInternalCallSites"))
            assertEquals("unresolved-symbol-extent", report.records("canonicalPopulation")
                .single { it.text("rva") == "0x110" }.text("disposition"))
            IndependentMachineCallReportV1.validateComponent(report)
            assertNoNegativeAuthority(report)
        }

    @Test fun `validator rejects below base overlap hidden behind a positive caller`() =
        withBelowBaseCallFixture(0x120) { report, visits ->
            // Touching ranges do not overlap. The caller legitimately emits a positive here.
            assertEquals(listOf(0x400110UL, 0x400115UL, 0x400150UL), visits)
            assertEquals(1L, report.count("positiveInternalCallSites"))
            IndependentMachineCallReportV1.validateComponent(report)
            // Extend only the invalid below-base origin across the caller. Keep the forged
            // owned caller, positive call, canonical dispositions, and aggregate counts intact.
            val roots = report.records("roots").map { record ->
                if (record["rva"] != JsonNull) record else JsonObject(record + mapOf(
                    "endExclusiveRva" to str("0x120"),
                    "origins" to JsonArray(record.records("origins").map { origin ->
                        JsonObject(origin + ("size" to str("0x130")))
                    }),
                ))
            }
            assertFails { IndependentMachineCallReportV1.validateComponent(JsonObject(report + ("roots" to JsonArray(roots)))) }
        }

    @Test fun `CFG follows both branch successors and call fallthrough while preserving external and indirect calls`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 0x20), Symbol("target", 0x150, 1)), listOf(0x110, 0x150))
        val visits = mutableListOf<ULong>()
        val report = input.produce(cfgDecoder(visits))
        assertEquals(listOf(0x400110UL, 0x400112UL, 0x400117UL, 0x400118UL, 0x40011dUL, 0x40011fUL, 0x400150UL), visits)
        val calls = report.records("calls")
        assertEquals(listOf("0x112", "0x118", "0x11d"), calls.map { it.text("instructionRva") })
        assertEquals(listOf("positive-internal-exact-start", "unresolved-target-outside-canonical-population", "unresolved-indirect-target"),
            calls.map { it.text("disposition") })
        assertEquals("canonical-150", calls.first().text("targetCanonicalId"))
        assertEquals(JsonPrimitive("0x999000"), calls[1]["directTargetAddress"])
        assertEquals(JsonNull, calls[2]["directTargetAddress"])
        assertEquals(listOf("direct-call", "direct-call", "indirect-call"), calls.map { it.text("classification") })
        assertEquals(listOf("0x400117", "0x40011d", "0x40011f"), calls.map { it.text("fallthroughAddress") })
        assertEquals(1L, report.count("positiveInternalCallSites"))
        assertEquals(2L, report.count("unresolvedCallSites"))
        assertEquals(7L, report.count("instructionAttempts"))
        assertNoNegativeAuthority(report)
    }

    @Test fun `interior canonical starts and conflicting aliases are unresolved without inferred extents`() = fixture { root ->
        val input = input(root, listOf(Symbol("interior-owner", 0x110, 16), Symbol("alias-a", 0x140, 1),
            Symbol("alias-b", 0x140, 2)), listOf(0x110, 0x118, 0x140))
        val report = input.produce(MachineInstructionDecoderV1 { _, _ -> error("ambiguous roots must never be decoded") })
        val roots = report.records("roots")
        assertTrue("interior-canonical-start" in roots.single { it.text("rva") == "0x110" }.texts("ownershipProblems"))
        assertEquals(2, roots.count { "conflicting-symbols-at-start" in it.texts("ownershipProblems") })
        assertEquals("unresolved-multiple-symbol-extents",
            report.records("canonicalPopulation").single { it.text("id") == "canonical-140" }.text("disposition"))
        assertEquals(0L, report.count("instructionAttempts"))
        assertNoNegativeAuthority(report)
    }

    @Test fun `mid function direct targets remain unresolved and cannot borrow canonical identity`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 6), Symbol("target", 0x150, 4)), listOf(0x110, 0x150))
        val report = input.produce(MachineInstructionDecoderV1 { address, bytes ->
            if (address == 0x400110UL) instruction(address, bytes, "direct-call", 5, target = 0x400151UL)
            else instruction(address, bytes, "return")
        })
        val call = report.records("calls").single()
        assertEquals("unresolved-target-outside-canonical-population", call.text("disposition"))
        assertEquals(JsonNull, call["targetCanonicalId"])
        assertEquals(0L, report.count("positiveInternalCallSites"))
    }

    @Test fun `overlapping instruction paths revoke earlier positive calls from the same root`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 8), Symbol("target", 0x150, 1)), listOf(0x110, 0x150))
        val report = input.produce(MachineInstructionDecoderV1 { address, bytes ->
            when (address) {
                0x400110UL -> instruction(address, bytes, "direct-jump", 2, target = 0x400114UL, conditional = true)
                0x400112UL -> instruction(address, bytes, "direct-call", 5, target = 0x400150UL)
                else -> instruction(address, bytes, "return")
            }
        })
        assertEquals("unresolved-instruction-overlap", report.records("calls").single().text("disposition"))
        assertEquals(0L, report.count("positiveInternalCallSites"))
        val rootRecord = report.records("roots").single { it.text("rva") == "0x110" }
        assertTrue("overlapping-instruction-paths" in rootRecord.texts("traversalStops"))
        assertEquals("0x400114", rootRecord.records("traversalStopEvents").single().text("address"))
        assertNoNegativeAuthority(report)
    }

    @Test fun `a direct self loop terminates without inferring call absence`() = fixture { root ->
        val input = input(root, listOf(Symbol("loop", 0x110, 2)), listOf(0x110))
        var attempts = 0
        val report = input.produce(MachineInstructionDecoderV1 { address, bytes ->
            attempts++
            instruction(address, bytes, "direct-jump", 2, target = address)
        }, MachineCallLimitsV1(maximumInstructions = 1, maximumInstructionsPerRoot = 1))
        assertEquals(1, attempts)
        assertEquals(1L, report.count("instructionAttempts"))
        assertEquals(0L, report.count("physicalCallSites"))
        assertNoNegativeAuthority(report)
    }

    @Test fun `decoder receipts cannot change owned bytes addresses fallthrough targets or context`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 6), Symbol("target", 0x150, 1)), listOf(0x110, 0x150))
        val mutations: List<(MachineInstructionV1) -> MachineInstructionV1> = listOf(
            { it.copy(address = it.address + 1UL) }, { it.copy(bytes = byteArrayOf(0)) },
            { it.copy(length = 16) }, { it.copy(fallthrough = it.address + 2UL) },
            { it.copy(directTargets = listOf(0x400151UL)) }, { it.copy(directCallTarget = null) },
            { it.copy(directTargets = listOf(0x400150UL, 0x400150UL)) },
            { it.copy(contextStatus = "unchecked") }, { it.copy(classification = "made-up") },
        )
        for ((index, mutate) in mutations.withIndex()) assertFails("mutation $index") {
            input.produce(MachineInstructionDecoderV1 { address, bytes ->
                mutate(instruction(address, bytes, "direct-call", 5, target = 0x400150UL))
            })
        }
        assertFails { input.produce(MachineInstructionDecoderV1 { _, _ -> throw IllegalStateException("adapter-runtime-failure") }) }
    }

    @Test fun `canonical exclusions retain cold endpoints without parent identity inference`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller.cold", 0x110, 6), Symbol("target.cold", 0x150, 1)), listOf(0x110, 0x150))
        val original = OracleJson.parseCanonical(Files.readAllBytes(input.oracle)) as JsonObject
        val decoder = MachineInstructionDecoderV1 { address, bytes ->
            if (address == 0x400110UL) instruction(address, bytes, "direct-call", 5, target = 0x400150UL)
            else instruction(address, bytes, "return")
        }
        for ((excluded, expected) in listOf("canonical-110" to "unresolved-caller-canonical-exclusion",
            "canonical-150" to "unresolved-target-canonical-exclusion")) {
            val records = original.records("functions").map { record ->
                if (record.text("id") != excluded) record else JsonObject(record + ("exclusion" to
                    obj("kind" to str("compiler-generated"), "reason" to str("authored cold partition exclusion"))))
            }
            val bytes = OracleJson.canonicalBytes(JsonObject(original + ("functions" to JsonArray(records))))
            Files.write(input.oracle, bytes)
            val report = input.copy(oracleSha = OracleArtifacts.sha256(bytes)).produce(decoder)
            assertEquals(expected, report.records("calls").single().text("disposition"))
            assertEquals(0L, report.count("positiveInternalCallSites"))
            assertNoNegativeAuthority(report)
        }
    }

    @Test fun `hard population instruction call output and work limits never return a truncated report`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 0x20), Symbol("target", 0x150, 1)), listOf(0x110, 0x150))
        for (limits in listOf(MachineCallLimitsV1(maximumRoots = 1), MachineCallLimitsV1(maximumInstructionsPerRoot = 1),
            MachineCallLimitsV1(maximumInstructions = 1), MachineCallLimitsV1(maximumCalls = 1),
            MachineCallLimitsV1(maximumOutputBytes = 1), MachineCallLimitsV1(maximumWorkUnits = 1))) {
            assertFails(limits.toString()) { input.produce(cfgDecoder(), limits) }
        }
    }

    @Test fun `input oracle and manifest identities are all required before decoding`() = fixture { root ->
        val input = input(root, listOf(Symbol("caller", 0x110, 1)), listOf(0x110))
        val noDecode = MachineInstructionDecoderV1 { _, _ -> error("identity failures must precede decoding") }
        for (mutated in listOf(input.copy(inputSha = "0".repeat(64)), input.copy(oracleSha = "0".repeat(64)),
            input.copy(manifestSha = "0".repeat(64)))) assertFails { mutated.produce(noDecode) }
        val oracle = OracleJson.parseCanonical(Files.readAllBytes(input.oracle)) as JsonObject
        val header = oracle.getValue("oracle") as JsonObject
        val fixtureOracle = JsonObject(oracle + mapOf("scope" to JsonPrimitive("fixture"),
            "oracle" to JsonObject(header + ("artifactManifestSha256" to JsonNull))))
        val fixtureBytes = OracleJson.canonicalBytes(fixtureOracle)
        Files.write(input.oracle, fixtureBytes)
        assertFails { input.copy(oracleSha = OracleArtifacts.sha256(fixtureBytes)).produce(noDecode) }
    }

    @Test fun `traversal stops retain exact addresses and bytes without authorizing negative facts`() = fixture { root ->
        val input = input(root, listOf(Symbol("indirect", 0x110, 2), Symbol("outside", 0x120, 2),
            Symbol("refused", 0x130, 1)), listOf(0x110, 0x120, 0x130))
        val report = input.produce(MachineInstructionDecoderV1 { address, bytes ->
            when (address) {
                0x400110UL -> instruction(address, bytes, "indirect-jump", 2)
                0x400120UL -> instruction(address, bytes, "direct-jump", 2, target = 0x400190UL)
                else -> throw MachineInstructionRefusalV1("authored-decoder-refusal")
            }
        })
        val roots = report.records("roots")
        assertTrue("unresolved-indirect-jump" in roots.single { it.text("rva") == "0x110" }.texts("traversalStops"))
        assertTrue("control-flow-outside-owned-extent" in roots.single { it.text("rva") == "0x120" }.texts("traversalStops"))
        assertTrue("decoder-refused-instruction" in roots.single { it.text("rva") == "0x130" }.texts("traversalStops"))
        val events = roots.flatMap { it.records("traversalStopEvents") }
        assertEquals(3, events.size)
        val wire = OracleJson.canonicalBytes(JsonArray(events)).decodeToString()
        for (address in listOf("0x400110", "0x400120", "0x400130", "0x400190")) assertTrue(address in wire, wire)
        assertTrue("c3c3" in wire && "c3" in wire, wire)
        assertNoNegativeAuthority(report)
    }

    private fun withBelowBaseCallFixture(size: Int, action: (JsonObject, List<ULong>) -> Unit) = fixture { root ->
        val input = input(root, listOf(Symbol("below", 0x100, size, value = 0x3ffff0UL),
            Symbol("caller", 0x110, 6), Symbol("target", 0x150, 1)), listOf(0x110, 0x150))
        val visits = mutableListOf<ULong>()
        val report = input.produce(MachineInstructionDecoderV1 { address, bytes ->
            visits += address
            if (address == 0x400110UL) instruction(address, bytes, "direct-call", 5, target = 0x400150UL)
            else instruction(address, bytes, "return")
        })
        action(report, visits)
    }

    private fun cfgDecoder(visits: MutableList<ULong> = mutableListOf()) = MachineInstructionDecoderV1 { address, bytes ->
        visits += address
        when (address) {
            0x400110UL -> instruction(address, bytes, "direct-jump", 2, target = 0x400118UL, conditional = true)
            0x400112UL -> instruction(address, bytes, "direct-call", 5, target = 0x400150UL)
            0x400118UL -> instruction(address, bytes, "direct-call", 5, target = 0x999000UL)
            0x40011dUL -> instruction(address, bytes, "indirect-call", 2)
            else -> instruction(address, bytes, "return")
        }
    }

    private fun instruction(address: ULong, bytes: ByteArray, kind: String, length: Int = 1,
        target: ULong? = null, conditional: Boolean = false): MachineInstructionV1 = MachineInstructionV1(
        address, length, bytes.copyOf(length), kind,
        if (kind in setOf("ordinary", "direct-call", "indirect-call") || conditional) address + length.toULong() else null,
        target?.let { listOf(it) }.orEmpty(), if (kind == "direct-call") target else null, "language-default-no-commits-v1",
    )

    private fun assertNoNegativeAuthority(report: JsonObject) {
        for (key in listOf("complete", "releaseEligible", "negativeCompleteness")) assertEquals(JsonPrimitive(false), report[key])
        for (record in report.records("roots") + report.records("calls")) assertEquals(JsonPrimitive(false), record["negativeCompleteness"])
        assertEquals(JsonPrimitive(true), report["canonicalPopulationComplete"])
        assertEquals(JsonPrimitive(true), report["rawSymbolPopulationComplete"])
        assertFalse(report.records("calls").any { it.text("disposition").startsWith("negative") })
    }

    private data class Symbol(val name: String, val rva: Int?, val size: Int, val type: Int = 2, val value: ULong? = null)
    private data class Input(val rich: Path, val oracle: Path, val inputSha: String, val oracleSha: String, val manifestSha: String) {
        fun produce(decoder: MachineInstructionDecoderV1, limits: MachineCallLimitsV1 = MachineCallLimitsV1()) =
            IndependentMachineCallsV1.produce(rich, oracle, inputSha, oracleSha, manifestSha, decoder, limits)
    }

    /** Authored canonical input exercises the authenticated boundary; it is not a release oracle. */
    private fun input(root: Path, symbols: List<Symbol>, canonical: List<Int>, inline: Boolean = false,
        code: Map<Int, ByteArray> = emptyMap()): Input {
        val bytes = FullTreeElfTestBytes.build(TestElfVariant(true, true, false, false),
            symbols.map { TestElfSymbol(it.name, it.rva?.toULong(), type = it.type) })
        bytes.fill(0xc3.toByte(), 0x100, 0x200)
        code.forEach { (offset, instructions) -> instructions.copyInto(bytes, offset) }
        val symbolOffset = FullTreeElfTestBytes.symbolTableOffset(bytes)
        symbols.forEachIndexed { index, symbol ->
            val entry = symbolOffset + (index + 1) * 24
            symbol.value?.let { FullTreeElfTestBytes.put64(bytes, entry + 8, it, true) }
            FullTreeElfTestBytes.put64(bytes, entry + 16, symbol.size.toULong(), true)
        }
        val inputSha = OracleArtifacts.sha256(bytes)
        val manifestSha = "6".repeat(64)
        val rich = Files.write(root.resolve("rich.elf"), bytes)
        fun artifact(sha: String) = obj("inputSha256" to str(sha), "elfType" to str("ET_DYN"), "elfImageBase" to str("0x400000"),
            "executableRvaRanges" to JsonArray(listOf(obj("start" to str("0x0"), "endExclusive" to str("0x${bytes.size.toString(16)}")))))
        fun function(rva: Int?) = obj("id" to str(rva?.let { "canonical-${it.toString(16)}" } ?: "inlined-only"),
            "rva" to (rva?.let { str("0x${it.toString(16)}") } ?: JsonNull),
            "aliases" to JsonArray(listOf(obj("name" to str("fixture-name-${rva ?: "inline"}"),
                "availability" to obj("rich" to str("surviving"), "stripped" to str("removed")),
                "evidence" to JsonArray(listOf(obj("kind" to str("dwarf-subprogram"), "locator" to str("fixture-cu:die:${rva ?: 0}")),
                    obj("kind" to str("elf-symbol"), "locator" to str("fixture-sym:${rva ?: 0}"))))))),
            "exclusion" to (if (rva != null) JsonNull else obj("kind" to str("inlined"), "reason" to str("authored addressless inline fixture"))))
        val oracleDocument = obj("schemaVersion" to JsonPrimitive(1), "scope" to str("production"),
            "oracle" to obj("id" to str("authored-machine-call-oracle"), "source" to str("dwarf-and-symbols"),
                "artifactManifestSha256" to str(manifestSha)),
            "artifacts" to obj("rich" to artifact(inputSha), "stripped" to artifact("7".repeat(64))),
            "scoringPolicy" to obj("nearMissBytes" to JsonPrimitive(8)),
            "functions" to JsonArray(canonical.map { function(it) } + if (inline) listOf(function(null)) else emptyList()))
        val oracleBytes = OracleJson.canonicalBytes(oracleDocument)
        val oracle = Files.write(root.resolve("oracle.json"), oracleBytes)
        return Input(rich, oracle, inputSha, OracleArtifacts.sha256(oracleBytes), manifestSha)
    }

    private fun fixture(action: (Path) -> Unit) {
        val base = Files.createDirectories(Path.of("build", "machine-call-producer-tests").toAbsolutePath().normalize())
        val directory = Files.createTempDirectory(base, "fixture-")
        try { action(directory) } finally { Files.walk(directory).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }

    private fun obj(vararg fields: Pair<String, JsonElement>) = JsonObject(mapOf(*fields))
    private fun str(value: String) = JsonPrimitive(value)
    private fun JsonObject.records(key: String) = (getValue(key) as JsonArray).map { it as JsonObject }
    private fun JsonObject.text(key: String) = getValue(key).jsonPrimitive.content
    private fun JsonObject.texts(key: String) = (getValue(key) as JsonArray).map { it.jsonPrimitive.content }
    private fun JsonObject.count(key: String) = (getValue("counts") as JsonObject).getValue(key).jsonPrimitive.long
}

internal fun withMachineCallComponentFixtureV1(action: (JsonObject) -> Unit) =
    IndependentMachineCallsV1Test().withComponentFixture(action)

internal fun withMachineCallWorkerFixtureV1(action: (Path, Path, String, String, String) -> Unit) =
    IndependentMachineCallsV1Test().withWorkerFixture(action)
