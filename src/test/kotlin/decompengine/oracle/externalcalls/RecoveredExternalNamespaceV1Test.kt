package decompengine.oracle.externalcalls

import decompengine.oracle.machinecalls.MachineInstructionDecoderV1
import decompengine.oracle.machinecalls.MachineInstructionRefusalV1
import decompengine.oracle.machinecalls.MachineInstructionV1
import kotlin.test.*
import org.junit.jupiter.api.Test
import kotlinx.serialization.json.*

class RecoveredExternalNamespaceV1Test {
    @Test fun `existing direct thunk and indirect slot claims project once while raw unknown remains`() {
        withRecoveredExternalFixtureV1 { files, native -> files.withPair { pair ->
            val frozen = freeze(native)
            val result = compose(frozen, pair)
            val sites = result.sites()
            assertEquals(3, sites.size)
            assertEquals(listOf("verified-object-local-import-request", "verified-object-local-import-request", "unresolved-frozen-native-claim"), sites.map { it.text("disposition") })
            assertEquals(sites[0]["externalTargetId"], sites[1]["externalTargetId"])
            assertEquals(JsonPrimitive(false), result["productionVerified"])
            assertEquals(JsonPrimitive(false), result["negativeCompleteness"])
            assertEquals(JsonPrimitive(3L), (result.getValue("counts") as JsonObject)["rawSites"])
            assertEquals(frozen.evidenceSha256, result.text("frozenClaimsSha256"))
            val binding = result.getValue("frozenClaimsBinding") as JsonObject
            assertEquals(JsonPrimitive(true), binding["rawSourcesRequired"])
            assertEquals(JsonPrimitive(frozen.observationBytes), binding["observationsBytes"])
            assertEquals(JsonPrimitive(frozen.rawRecordCount), binding["rawRecordCount"])
            // Deliberately mismatched recovered label/version is raw data, never a namespace selector.
            assertTrue(String(frozen.rawObservationBytes).contains("fixture_external"))
            assertTrue(result.getValue("externalNamespace").toString().contains("puts"))
            RecoveredExternalNamespaceV1.validate(result, frozen, pair)
        } }
    }

    @Test fun `known PLT bytes never supply a missing recovered external claim`() {
        withRecoveredExternalFixtureV1 { files, original ->
            val native = original.withFunction(2) { it + mapOf("isThunk" to JsonPrimitive(false), "immediateThunkTarget" to JsonNull) }
                .withSite(1) { it + ("referenceNeighborhoods" to JsonArray((it.getValue("referenceNeighborhoods") as JsonArray).map { raw ->
                    JsonObject((raw as JsonObject) + ("references" to JsonArray(emptyList())))
                })) }
            files.withPair { pair ->
                val frozen = freeze(native)
                var calls = 0
                val result = RecoveredExternalNamespaceV1.compose(frozen, pair, MachineInstructionDecoderV1 { _, _ -> calls++; error("no candidate may decode") }, MEMORY)
                assertEquals(0, calls)
                assertTrue(result.sites().all { it["externalTargetId"] == JsonNull && it["candidateImportRequestId"] == JsonNull })
            }
        }
    }

    @Test fun `native slot must agree with byte transfer and no substitute is selected`() {
        withRecoveredExternalFixtureV1 { files, original ->
            val native = original.copy(document = replaceAddresses(original.document, mapOf(0x1800L to 0x1818L)) as JsonObject).recount()
            files.withPair { pair ->
                val result = compose(freeze(native), pair)
                assertEquals("verified-object-local-import-request", result.sites()[0].text("disposition"))
                assertEquals("unresolved-native-slot-disagreement", result.sites()[1].text("disposition"))
                assertEquals(JsonNull, result.sites()[1]["externalTargetId"])
            }
        }
    }

    @Test fun `conflated external node keeps distinct physical candidates unresolved`() {
        withRecoveredExternalFixtureV1 { files, original ->
            // A second independently encoded request, with the same recovered synthetic E.
            for (elf in listOf(files.richElf, files.strippedElf)) {
                elf.bytes[0x400 + 2 * 24 + 4] = 0x12
                elf.word64(0x618 + 8, (2UL shl 32) or 7UL)
                hexBytes("ff1502060000").copyInto(elf.bytes, 0x210)
            }
            files.write()
            var native = rebound(original, files.strippedSha)
            native = native.copy(document = replaceAddresses(native.document, mapOf(0x1800L to 0x1818L)) as JsonObject)
                .withSite(1) { it + ("instructionBytes" to JsonPrimitive("ff1502060000")) }
            files.withPair { pair ->
                val result = compose(freeze(native), pair, indirectSlot = 0x400818UL)
                val sites = result.sites()
                assertEquals(listOf("unresolved-external-node-conflict", "unresolved-external-node-conflict"), sites.take(2).map { it.text("disposition") })
                assertNotEquals(sites[0]["candidateImportRequestId"], sites[1]["candidateImportRequestId"])
                assertTrue(sites.take(2).all { it["externalTargetId"] == JsonNull && it["physicalInstruction"] != JsonNull && it["slotPair"] != JsonNull })
            }
        }
    }

    @Test fun `weak request stays unresolved without manufacturing runtime implementation`() {
        withRecoveredExternalFixtureV1 { files, original ->
            for (elf in listOf(files.richElf, files.strippedElf)) elf.bytes[0x400 + 24 + 4] = 0x22
            files.write()
            files.withPair { pair ->
                val result = compose(freeze(rebound(original, files.strippedSha)), pair)
                assertTrue(result.sites().take(2).all { it.text("disposition") == "unresolved-static-import-eligibility" && it["externalTargetId"] == JsonNull && it["candidateImportRequestId"] != JsonNull })
                assertEquals(JsonPrimitive(false), result["runtimeImplementationAvailable"])
            }
        }
    }

    @Test fun `native byte or input identity mismatch cannot use paired truth`() {
        withRecoveredExternalFixtureV1 { files, original -> files.withPair { pair ->
            val changed = original.withSite(0) { it + ("instructionBytes" to JsonPrimitive("e800000000")) }
            assertEquals("unresolved-native-instruction-correspondence", compose(freeze(changed), pair).sites()[0].text("disposition"))
            assertFails { compose(freeze(rebound(original, "f".repeat(64))), pair) }
        } }
    }

    @Test fun `closed validator rejects forged path fields nested authority and census edits`() {
        withRecoveredExternalFixtureV1 { files, native -> files.withPair { pair ->
            val frozen = freeze(native)
            val result = compose(frozen, pair)
            fun changedSite(change: (JsonObject) -> Map<String, JsonElement>): JsonObject = JsonObject(result + ("sites" to JsonArray(result.sites().mapIndexed { index, row ->
                if (index == 0) JsonObject(change(row)) else row
            })))
            val mutations = listOf(
                JsonObject(result + ("productionVerified" to JsonPrimitive(true))),
                JsonObject(result + ("sites" to JsonArray(result.sites().dropLast(1)))),
                JsonObject(result + ("sites" to JsonArray(listOf(result.sites()[0], result.sites()[0], result.sites()[2])))),
                JsonObject(result + ("frozenClaimsBinding" to JsonObject((result.getValue("frozenClaimsBinding") as JsonObject) - "observationsSha256"))),
                JsonObject(result + ("frozenClaimsBinding" to JsonObject((result.getValue("frozenClaimsBinding") as JsonObject) + ("rawSourcesRequired" to JsonPrimitive(false))))),
                changedSite { it + ("sourceRecordOrdinal" to JsonPrimitive(99)) },
                changedSite { it + ("physicalInstruction" to JsonObject((it.getValue("physicalInstruction") as JsonObject) + ("authority" to JsonPrimitive(true)))) },
                changedSite { it + ("physicalInstruction" to JsonObject((it.getValue("physicalInstruction") as JsonObject) + ("directCallTarget" to JsonPrimitive("0x400280")))) },
                changedSite { it + ("slotPair" to JsonObject((it.getValue("slotPair") as JsonObject) + ("eligible" to JsonPrimitive(false)))) },
                changedSite { it + ("memoryTransfer" to JsonObject((it.getValue("memoryTransfer") as JsonObject) + ("rawTransferOpIndex" to JsonPrimitive(4096)))) },
            )
            mutations.forEach { assertFails { RecoveredExternalNamespaceV1.validate(it, frozen, pair) } }
            assertFails { RecoveredExternalNamespaceV1.validate(result, frozen, pair, RecoveredExternalNamespaceLimitsV1(maximumOutputBytes = 100)) }
            assertFails { RecoveredExternalNamespaceV1.validate(result, freeze(rebound(native, "f".repeat(64))), pair) }
        } }
    }

    @Test fun `bounds cancellation and malformed decoder receipt fail closed`() {
        withRecoveredExternalFixtureV1 { files, native -> files.withPair { pair ->
            val frozen = freeze(native)
            assertFails { RecoveredExternalNamespaceV1.compose(frozen, pair, BASIC, MEMORY, RecoveredExternalNamespaceLimitsV1(maximumSites = 2)) }
            assertFails { RecoveredExternalNamespaceV1.compose(frozen, pair, BASIC, MEMORY, checkpoint = { error("cancel") }) }
            assertFails { RecoveredExternalNamespaceV1.compose(frozen, pair, MachineInstructionDecoderV1 { address, bytes -> BASIC.decode(address, bytes).copy(address = address + 1UL) }, MEMORY) }
            assertFails { RecoveredExternalNamespaceV1.compose(frozen, pair, BASIC, StaticMemoryTransferDecoderV1 { address, bytes -> MEMORY.decode(address, bytes).copy(rawTransferOpcode = "CALL") }) }
        } }
    }

    @Test fun `coordinated disposition target and count edits cannot hide eligible proof or invent refusal`() {
        withRecoveredExternalFixtureV1 { files, native -> files.withPair { pair ->
            val frozen = freeze(native)
            val report = compose(frozen, pair)
            fun mutate(change: (JsonObject) -> Map<String, JsonElement>): JsonObject {
                val sites = report.sites().mapIndexed { index, row -> if (index == 0) JsonObject(change(row)) else row }
                val counts = JsonObject(mapOf("rawSites" to JsonPrimitive(frozen.rawSiteCount), "projectedSites" to JsonPrimitive(sites.size),
                    "dispositions" to JsonObject(sites.groupingBy { it.text("disposition") }.eachCount().mapValues { JsonPrimitive(it.value) })))
                return JsonObject(report + mapOf("sites" to JsonArray(sites), "counts" to counts))
            }
            for (status in listOf("unresolved-native-instruction-correspondence", "unresolved-frozen-native-claim",
                "unresolved-memory-transfer", "unresolved-static-import-eligibility", "unresolved-byte-decoder-refusal")) {
                val changed = mutate { it + mapOf("disposition" to JsonPrimitive(status), "externalTargetId" to JsonNull) }
                assertFails(status) { RecoveredExternalNamespaceV1.validate(changed, frozen, pair) }
            }
            val extraRefusal = mutate { it + ("decoderRefusal" to JsonPrimitive("unsupported-flow")) }
            assertFails { RecoveredExternalNamespaceV1.validate(extraRefusal, frozen, pair) }
            val removedProofs = mutate { it + mapOf("disposition" to JsonPrimitive("unresolved-native-instruction-correspondence"),
                "externalTargetId" to JsonNull, "candidateImportRequestId" to JsonNull, "physicalInstruction" to JsonNull,
                "memoryTransfer" to JsonNull, "slotPair" to JsonNull) }
            assertFails { RecoveredExternalNamespaceV1.validate(removedProofs, frozen, pair) }
        } }
    }

    @Test fun `typed decode refusals flow disagreement and unresolved memory remain valid explicit outcomes`() {
        withRecoveredExternalFixtureV1 { files, native -> files.withPair { pair ->
            val frozen = freeze(native)
            val firstRefusal = RecoveredExternalNamespaceV1.compose(frozen, pair,
                MachineInstructionDecoderV1 { _, _ -> throw MachineInstructionRefusalV1("unsupported-flow") }, MEMORY)
            assertTrue(firstRefusal.sites().take(2).all { it.text("disposition") == "unresolved-byte-decoder-refusal" && it["physicalInstruction"] == JsonNull })
            val memoryRefusal = RecoveredExternalNamespaceV1.compose(frozen, pair, BASIC,
                StaticMemoryTransferDecoderV1 { _, _ -> throw MachineInstructionRefusalV1("unsupported-flow") })
            assertTrue(memoryRefusal.sites().take(2).all { it.text("disposition") == "unresolved-byte-decoder-refusal" && it["physicalInstruction"] != JsonNull })
            val flow = RecoveredExternalNamespaceV1.compose(frozen, pair, MachineInstructionDecoderV1 { address, bytes ->
                val receipt = BASIC.decode(address, bytes)
                if (address == 0x400200UL) receipt.copy(directCallTarget = 0x400250UL, directTargets = listOf(0x400250UL)) else receipt
            }, MEMORY)
            assertEquals("unresolved-native-flow-or-target", flow.sites()[0].text("disposition"))
            val unresolved = RecoveredExternalNamespaceV1.compose(frozen, pair, BASIC, StaticMemoryTransferDecoderV1 { address, bytes ->
                MEMORY.decode(address, bytes).copy(pointerSlotAddress = null, pointerWidthBytes = null, relationship = "unresolved",
                    rawReadOpcode = null, rawReadOpIndex = null, unresolvedReason = "register-transfer")
            })
            assertTrue(unresolved.sites().take(2).all { it.text("disposition") == "unresolved-memory-transfer" && it["externalTargetId"] == JsonNull })
        } }
    }
}

internal fun withRecoveredExternalFixtureV1(action: (ElfExternalNamespacePairFixtureV1, NativeExternalFixtureV1) -> Unit) {
    withElfExternalNamespacePairFixtureV1 { files ->
        for (elf in listOf(files.richElf, files.strippedElf)) {
            hexBytes("e83b000000").copyInto(elf.bytes, 0x200)
            hexBytes("ff15ea050000").copyInto(elf.bytes, 0x210)
            hexBytes("ff25ba050000").copyInto(elf.bytes, 0x240)
        }
        files.write()
        val initial = nativeExternalFixtureV1()
        val moved = initial.copy(document = replaceAddresses(initial.document, mapOf(0x1010L to 0x1200L, 0x1015L to 0x1205L,
            0x1020L to 0x1210L, 0x1026L to 0x1216L, 0x1200L to 0x1240L, 0x2000L to 0x1800L)) as JsonObject).recount()
            .withSite(0) { it + ("instructionBytes" to JsonPrimitive("e83b000000")) }
            .withSite(1) { it + ("instructionBytes" to JsonPrimitive("ff15ea050000")) }
        action(files, rebound(moved, files.strippedSha))
    }
}
private fun rebound(native: NativeExternalFixtureV1, input: String): NativeExternalFixtureV1 = native.copy(
    bindings = native.bindings.copy(inputSha256 = input),
    document = JsonObject(native.document + ("bindings" to JsonObject((native.document.getValue("bindings") as JsonObject) + ("inputSha256" to JsonPrimitive(input))))))
private fun replaceAddresses(raw: JsonElement, offsets: Map<Long, Long>): JsonElement = when (raw) {
    is JsonObject -> if (raw["kind"] == JsonPrimitive("address") && raw["spaceIndex"] == JsonPrimitive(1)) {
        val old = (raw.getValue("offsetBits") as JsonPrimitive).content.toULong(16).toLong()
        JsonObject(raw + ("offsetBits" to JsonPrimitive((offsets[old] ?: old).toULong().toString(16).padStart(16, '0'))))
    } else JsonObject(raw.mapValues { replaceAddresses(it.value, offsets) })
    is JsonArray -> JsonArray(raw.map { replaceAddresses(it, offsets) })
    else -> raw
}
private fun freeze(native: NativeExternalFixtureV1) = FrozenNativeExternalClaimsV1.freeze(native.manifestBytes(), native.observationBytes(), native.bindings)
private fun compose(frozen: FrozenNativeExternalClaimsSnapshotV1, pair: ElfExternalNamespacePairV1, indirectSlot: ULong = 0x400800UL) =
    RecoveredExternalNamespaceV1.compose(frozen, pair, BASIC, StaticMemoryTransferDecoderV1 { address, bytes ->
        val value = MEMORY.decode(address, bytes)
        if (address == 0x400210UL) value.copy(pointerSlotAddress = indirectSlot) else value
    })
private val BASIC = MachineInstructionDecoderV1 { address, bytes ->
    val length = if (address == 0x400200UL) 5 else 6
    val classification = when (address) { 0x400200UL -> "direct-call"; 0x400210UL -> "indirect-call"; 0x400240UL -> "indirect-jump"; else -> error("unexpected decode address") }
    MachineInstructionV1(address, length, bytes.copyOf(length), classification,
        if (classification == "indirect-jump") null else address + length.toULong(),
        if (classification == "direct-call") listOf(0x400240UL) else emptyList(),
        if (classification == "direct-call") 0x400240UL else null, "language-default-no-commits-v1")
}
private val MEMORY = StaticMemoryTransferDecoderV1 { address, bytes ->
    val call = address == 0x400210UL
    val op = if (call) "CALLIND" else "BRANCHIND"
    StaticMemoryTransferV1(address, 6, bytes.copyOf(6), if (call) "indirect-call" else "indirect-jump", 0x400800UL, 8,
        "static-ram-varnode-exact-transfer-v1", op, 0, op, 0, emptyList(), "language-default-no-commits-v1", null)
}
private fun hexBytes(value: String) = value.chunked(2).map { it.toInt(16).toByte() }.toByteArray()
private fun JsonObject.sites() = (getValue("sites") as JsonArray).map { it as JsonObject }
private fun JsonObject.text(key: String) = (getValue(key) as JsonPrimitive).content
