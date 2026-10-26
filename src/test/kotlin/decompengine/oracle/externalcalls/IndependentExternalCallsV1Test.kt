package decompengine.oracle.externalcalls

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.machinecalls.MachineInstructionDecoderV1
import decompengine.oracle.machinecalls.MachineInstructionRefusalV1
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class IndependentExternalCallsV1Test {
    @Test fun `PLT and direct memory calls retain physical sites while namespace commits exact import requests`(): Unit = withExternalCallFixtureV1 { fixture ->
        val report = fixture.produce()
        val sites = report.records("sites")
        assertEquals(listOf("0x270", "0x275"), sites.map { it.text("instructionRva") })
        assertEquals(listOf("0x400275", "0x40027b"), sites.map { it.text("returnAddress") })
        assertEquals(listOf("static-import-request-reference", "unresolved-weak-runtime-target"), sites.map { it.text("compositionDisposition") })
        assertEquals(listOf(JsonPrimitive(true), JsonPrimitive(false)), sites.map { it["viaForwarder"] })
        assertEquals(JsonPrimitive(2), (report.getValue("counts") as JsonObject)["sourcePhysicalSites"])
        val namespace = report.getValue("externalNamespace") as JsonObject
        assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(namespace))), report["externalNamespaceSha256"])
        val identities = namespace.records("entries")
        assertEquals(listOf("puts", "weak_name"), identities.map { (it.getValue("identity") as JsonObject).text("name") })
        identities.forEach { assertEquals("ext-${OracleArtifacts.sha256(OracleJson.canonicalBytes(it.getValue("identity")))}", it.text("id")) }
        assertEquals(identities[0]["id"], sites[0]["externalTargetId"])
        assertEquals(JsonPrimitive("libc.so.6"), ((identities[0].getValue("identity") as JsonObject).getValue("version") as JsonObject)["providerRequest"])
        for (record in listOf(report, namespace) + sites) assertEquals(JsonPrimitive(false), record["negativeCompleteness"])
        assertEquals(JsonPrimitive(false), report["complete"])
        assertEquals(JsonPrimitive(false), report["releaseEligible"])
        assertEquals(JsonPrimitive(false), report["sourceCallPopulationComplete"])
        assertEquals(report, fixture.produce())
    }

    @Test fun `all uncertain relocation and symbol targets remain explicit without invented semantic callees`(): Unit = withDynamicFixture { root ->
        val cases = listOf(0x808 to "unresolved-defined-symbol-reference", 0x810 to "unresolved-irelative-resolver",
            0x830 to "unresolved-ifunc-runtime-implementation", 0x838 to "unresolved-defined-symbol-reference",
            0x840 to "unresolved-symbol-import-identity", 0x848 to "unresolved-null-symbol-index",
            0x850 to "unresolved-slot-without-relocation")
        cases.forEachIndexed { index, (slot, status) ->
            val directory = Files.createDirectory(root.resolve("case-$index"))
            val fixture = ExternalCallFixtureV1(directory, mutate = { it.word32(0x202, (slot - 0x206).toLong()) })
            val site = fixture.produce().records("sites").first()
            assertEquals(status, site.text("compositionDisposition"), "slot ${slot.toString(16)}")
            assertEquals(JsonNull, site["externalTargetId"])
        }
    }

    @Test fun `overlapping and unsupported writes cannot prove a unique slot association`(): Unit = withDynamicFixture { root ->
        val mutations: List<Pair<String, (DynamicBindingElfFixtureV1) -> Unit>> = listOf(
            "unresolved-competing-relocations" to { it.word64(0x618, 0x400800UL) },
            "unresolved-relocation-write-coverage" to { it.word64(0x618, 0x400804UL) },
            "unresolved-relocation-write-coverage" to { it.word64(0x508, 0x777UL) },
            "unresolved-unexpanded-relocation-writes" to { it.tagType(1UL, 36UL) },
            "unresolved-unexpanded-relocation-writes" to { it.tagType(1UL, 0x60001234UL) },
            "unresolved-slot-file-storage" to { it.word64(0x600, 0x400f04UL); it.word64(0x68, 0x1000UL); it.word32(0x202, 0xcfe) },
        )
        mutations.forEachIndexed { index, (expected, mutate) ->
            val fixture = ExternalCallFixtureV1(Files.createDirectory(root.resolve("case-$index")), mutate)
            assertEquals(expected, fixture.produce().records("sites").first().text("compositionDisposition"), "mutation $index")
        }
    }

    @Test fun `excluded caller keeps target evidence but gains no composed positive authority`(): Unit = withDynamicFixture { root ->
        val fixture = ExternalCallFixtureV1(root, excludedCaller = true)
        val sites = fixture.produce().records("sites")
        assertTrue(sites.all { it.text("compositionDisposition") == "unresolved-source-caller" })
        assertEquals("static-import-request-reference", sites.first().text("targetBindingDisposition"))
        assertTrue(sites.first().text("externalTargetId").startsWith("ext-"))
    }

    @Test fun `unsupported forwarders and typed byte refusals retain original sites`(): Unit = withExternalCallFixtureV1 { fixture ->
        val refused = fixture.produce(memoryDecoder = StaticMemoryTransferDecoderV1 { _, _ -> throw MachineInstructionRefusalV1("authored-byte-refusal") })
        assertEquals(2, refused.records("sites").size)
        assertTrue(refused.records("sites").all { it.text("compositionDisposition") == "unresolved-memory-decoder-refusal" })
        assertFails { fixture.produce(memoryDecoder = StaticMemoryTransferDecoderV1 { _, _ -> error("runtime-failure") }) }
        val unknown = fixture.produce(memoryDecoder = StaticMemoryTransferDecoderV1 { address, bytes ->
            val real = ExternalCallFixtureV1.memory.decode(address, bytes)
            real.copy(pointerSlotAddress = null, pointerWidthBytes = null, relationship = "unresolved", rawReadOpcode = null,
                rawReadOpIndex = null, rawTransferOpcode = null, rawTransferOpIndex = null, rawCopyOpIndices = emptyList(), unresolvedReason = "register-transfer")
        })
        assertTrue(unknown.records("sites").all { it.text("compositionDisposition") == "unresolved-memory-transfer" })
    }

    @Test fun `canonical null and unsupported forwarder targets keep their original physical identity`(): Unit = withDynamicFixture { root ->
        val canonical = ExternalCallFixtureV1(Files.createDirectory(root.resolve("canonical")), mutate = { it.word32(0x271, -5) })
        val canonicalSite = canonical.produce().records("sites").first()
        assertEquals("retained-canonical-target", canonicalSite.text("compositionDisposition"))
        assertEquals(JsonPrimitive("0x400270"), canonicalSite["physicalTargetAddress"])
        assertEquals(JsonNull, canonicalSite["memoryTransfer"])
        val nullTarget = ExternalCallFixtureV1(Files.createDirectory(root.resolve("null")), mutate = { it.word32(0x271, -0x400275) })
        assertEquals("unresolved-null-physical-target", nullTarget.produce().records("sites").first().text("compositionDisposition"))
        val prefixed = ExternalCallFixtureV1(Files.createDirectory(root.resolve("prefixed")), mutate = { it.bytes[0x200] = 0x90.toByte() })
        val unresolved = prefixed.produce().records("sites").first()
        assertEquals("unresolved-forwarder-sequence", unresolved.text("compositionDisposition"))
        assertEquals(JsonPrimitive("0x400200"), unresolved["physicalTargetAddress"])
        assertEquals(JsonNull, unresolved["externalTargetId"])
    }

    @Test fun `byte and typed transfer receipts cannot change instruction identity context or proof`(): Unit = withExternalCallFixtureV1 { fixture ->
        val changes: List<(StaticMemoryTransferV1) -> StaticMemoryTransferV1> = listOf(
            { it.copy(address = it.address + 1UL) }, { it.copy(length = 2, bytes = it.bytes.copyOf(2)) },
            { it.copy(bytes = byteArrayOf(0)) }, { it.copy(pointerWidthBytes = 4) },
            { it.copy(contextStatus = "unverified") }, { it.copy(rawTransferOpcode = "CALL") },
            { it.copy(rawCopyOpIndices = listOf(1, 1)) }, { it.copy(relationship = "linear-sweep-name-inference") },
        )
        changes.forEachIndexed { index, change -> assertFails("memory mutation $index") {
            fixture.produce(memoryDecoder = StaticMemoryTransferDecoderV1 { address, bytes -> change(ExternalCallFixtureV1.memory.decode(address, bytes)) })
        } }
        assertFails { fixture.produce(instructionDecoder = MachineInstructionDecoderV1 { address, bytes ->
            ExternalCallFixtureV1.decoder.decode(address, bytes).copy(fallthrough = address + 1UL)
        }) }
    }

    @Test fun `input commitments source population and bounded execution fail closed`(): Unit = withExternalCallFixtureV1 { fixture ->
        assertFails { fixture.produce(limits = ExternalCallLimitsV1(maximumCalls = 1)) }
        assertFails { fixture.produce(limits = ExternalCallLimitsV1(maximumWorkUnits = 1)) }
        assertFails { fixture.produce(limits = ExternalCallLimitsV1(maximumOutputBytes = 100)) }
        assertFails { fixture.produce(limits = ExternalCallLimitsV1(metadata = ElfDynamicBindingLimitsV1(maximumDynamicSymbols = 1))) }
        Thread.currentThread().interrupt()
        try { assertFails { fixture.produce() } } finally { Thread.interrupted() }
        val bytes = Files.readAllBytes(fixture.sourceReport)
        Files.write(fixture.sourceReport, bytes + byteArrayOf(32))
        assertFails { fixture.produce() }
    }

    @Test fun `namespace identities are object local and include version visibility and binding`(): Unit = withDynamicFixture { root ->
        val first = ExternalCallFixtureV1(Files.createDirectory(root.resolve("one")))
        val second = ExternalCallFixtureV1(Files.createDirectory(root.resolve("two")), mutate = { it.bytes[0x280] = 1 })
        val a = first.produce(); val b = second.produce()
        assertNotEquals(a["externalNamespaceSha256"], b["externalNamespaceSha256"])
        assertNotEquals(a.records("sites").first()["externalTargetId"], b.records("sites").first()["externalTargetId"])
        val hidden = ExternalCallFixtureV1(Files.createDirectory(root.resolve("hidden")), mutate = { it.bytes[0x400 + 24 + 5] = 2 })
        assertEquals("unresolved-symbol-import-identity", hidden.produce().records("sites").first().text("compositionDisposition"))
    }

    private fun JsonObject.records(key: String) = (getValue(key) as JsonArray).map { it as JsonObject }
    private fun JsonObject.text(key: String) = (getValue(key) as JsonPrimitive).content
}
