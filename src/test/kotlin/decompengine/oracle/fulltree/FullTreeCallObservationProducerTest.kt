package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.ByteArrayOutputStream
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallObservationProducerTest {
    @Test
    fun `handcrafted ELF observes call sites and target classifications deterministically`() =
        inControlTemporaryDirectory { root ->
            val controls = createFullTreeControlFixture(root.resolve("controls"))
            val fixture = CallObservationElfFixture.build()
            val artifact = writeElf(root.resolve("calls.elf"), fixture.bytes)
            val scope = callScopeForArtifact(
                controls.authenticatedScope(),
                OracleArtifacts.sha256(fixture.bytes),
                fixture.bytes.size.toLong(),
            )
            val inventoryPath = root.resolve("calls-inventory.json")
            val inventory = FullTreeInventoryControl.generateAndPublish(
                artifact,
                scope,
                inventoryPath,
                maximumWorkers = 1,
            )
            val shardId = inventory.inventory.controlArray("shards").single().let {
                (it as JsonObject).controlString("id")
            }
            assertEquals("clang-lib-call", shardId)

            val first = FullTreeCallObservationProducer.generateShardWithLimits(
                richArtifact = artifact,
                inventoryPath = inventoryPath,
                scope = scope,
                shardId = shardId,
                scratchParent = root,
                controlLimits = FullTreeControlLimits(),
                producerLimits = callProducerLimits(),
            )
            val second = FullTreeCallObservationProducer.generateShardWithLimits(
                richArtifact = artifact,
                inventoryPath = inventoryPath,
                scope = scope,
                shardId = shardId,
                scratchParent = root,
                controlLimits = FullTreeControlLimits(),
                producerLimits = callProducerLimits(),
            )

            assertEquals(19L, first.scannedDies)
            assertEquals(7L, first.entities)
            assertEquals(first.outputSha256, second.outputSha256)
            assertTrue(
                FullTreeCallObservations.canonicalEnvelopeBytes(first.document).contentEquals(
                    FullTreeCallObservations.canonicalEnvelopeBytes(second.document),
                ),
            )

            assertEquals(
                JsonObject(
                    mapOf(
                        "observedCallSites" to JsonPrimitive(7),
                        "scannedDies" to JsonPrimitive(19),
                        "scored" to JsonPrimitive(5),
                        "units" to JsonPrimitive(1),
                        "unobservable" to JsonPrimitive(2),
                    ),
                ),
                first.document.controlObject("counts"),
            )
            assertEquals(
                JsonObject(
                    mapOf(
                        "configurationSha256" to JsonPrimitive(FullTreeCallObservations.configurationSha256),
                        "inventoryIndexSha256" to JsonPrimitive(inventory.indexSha256),
                        "richArtifactSha256" to JsonPrimitive(inventory.artifactSha256),
                        "scopeSha256" to JsonPrimitive(scope.sha256),
                    ),
                ),
                first.document.controlObject("oracle"),
            )
            assertEquals(JsonPrimitive(1), first.document["schemaVersion"])
            val authenticatedInput = FullTreeCallObservations.shardInputs(
                inventory.inventory,
                inventory.outputSha256,
                scope.document,
                scope.sha256,
            ).single()
            assertEquals(shardId, first.shardId)
            assertEquals(authenticatedInput.inputSha256, first.inputSha256)
            assertEquals(inventory.outputSha256, first.inventoryArtifactSha256)
            assertEquals(inventory.artifactSha256, first.richArtifactSha256)
            assertEquals(first.inputSha256, first.document.controlObject("shard").controlString("inputSha256"))
            assertEquals(shardId, first.document.controlObject("shard").controlString("id"))
            assertEquals(
                first.outputSha256,
                OracleArtifacts.sha256(FullTreeCallObservations.canonicalEnvelopeBytes(first.document)),
            )
            assertEquals(
                FullTreeCallObservations.canonicalEnvelopeBytes(first.document).size.toLong(),
                first.outputBytes,
            )

            val unit = inventory.inventory.controlArray("units").single() as JsonObject
            assertEquals("source/clang/lib/Call/calls.c", unit.controlString("sourcePath"))
            val unitId = unit.controlString("id")
            val calls = first.document.controlArray("calls").map { it as JsonObject }
            assertEquals(
                calls.map { it.controlString("id") }.sorted(),
                calls.map { it.controlString("id") },
            )
            assertTrue(calls.all { it.controlString("unitId") == unitId })
            val byDie = calls.associateBy { it.controlString("dieOffset") }

            // This call is nested below an unretained lexical-block DIE. The physical depth must
            // still preserve the nearest emitted subprogram as its caller.
            val direct = byDie.getValue(callHex(fixture.directCallDieOffset))
            assertScoredCall(direct, localOffset = "0x8", returnRva = "0x148", tailCall = true)
            assertTarget(
                direct,
                kind = "direct-internal",
                dispatchKind = "direct",
                functionId = "function-rva-0x180",
                aliases = listOf("internal_linkage", "internal_name"),
                originDieOffset = callHex(fixture.internalTargetDieOffset),
                targetEvidence = "none",
            )

            val proven = byDie.getValue(callHex(fixture.provenCallDieOffset))
            assertScoredCall(proven, localOffset = "0x10", returnRva = "0x150")
            assertTarget(
                proven,
                kind = "indirect-proven",
                dispatchKind = "indirect-proven",
                provenFunctionIds = listOf("function-rva-0x1c0"),
                targetEvidence = "call-target-and-clobbered-expressions",
            )

            val external = byDie.getValue(callHex(fixture.externalCallDieOffset))
            assertScoredCall(external, localOffset = "0x18", returnRva = "0x158")
            assertTarget(
                external,
                kind = "external-unresolved",
                dispatchKind = "direct",
                aliases = listOf("external_target"),
                originDieOffset = callHex(fixture.externalTargetDieOffset),
                targetEvidence = "none",
            )

            val virtual = byDie.getValue(callHex(fixture.virtualCallDieOffset))
            assertScoredCall(virtual, localOffset = "0x20", returnRva = "0x160")
            assertTarget(
                virtual,
                kind = "virtual-unresolved",
                dispatchKind = "virtual-unresolved",
                aliases = listOf("virtual_target"),
                originDieOffset = callHex(fixture.virtualTargetDieOffset),
                targetEvidence = "none",
            )

            val unresolved = byDie.getValue(callHex(fixture.unresolvedCallDieOffset))
            assertScoredCall(unresolved, localOffset = "0x28", returnRva = "0x168")
            assertTarget(
                unresolved,
                kind = "indirect-unresolved",
                dispatchKind = "indirect-unresolved",
                targetEvidence = "call-target-expression",
            )

            val addressless = byDie.getValue(callHex(fixture.addresslessCallDieOffset))
            assertEquals("unobservable", addressless.controlString("population"))
            assertEquals("call-site-no-address", addressless.controlString("reasonCode"))
            assertEquals(JsonNull, addressless["callerId"])
            assertEquals(JsonNull, addressless["callerLocalReturnOffset"])
            assertEquals(JsonNull, addressless["returnPcRva"])
            assertEquals(JsonPrimitive(true), addressless["tailCall"])
            assertTarget(
                addressless,
                kind = "indirect-unresolved",
                dispatchKind = "indirect-unresolved",
                targetEvidence = "none",
            )

            val callerless = byDie.getValue(callHex(fixture.callerlessCallDieOffset))
            assertEquals("unobservable", callerless.controlString("population"))
            assertEquals("caller-no-emitted-range", callerless.controlString("reasonCode"))
            assertEquals(JsonNull, callerless["callerId"])
            assertEquals(JsonNull, callerless["callerLocalReturnOffset"])
            assertEquals("0x178", callerless.controlString("returnPcRva"))
            assertEquals(JsonPrimitive(false), callerless["tailCall"])
            assertTarget(
                callerless,
                kind = "indirect-unresolved",
                dispatchKind = "indirect-unresolved",
                targetEvidence = "none",
            )
        }

    @Test
    fun `variable and member definition chains remain indirect`() =
        inControlTemporaryDirectory { root ->
            val fixture = CallObservationElfFixture.build(CallOriginChainFixture.COMPATIBLE_OBJECTS)
            val observed = generateFixture(
                root,
                fixture,
                callProducerLimits(
                    maximumPhysicalRecords = 25,
                    maximumNonNullRecords = 21,
                    maximumAttributes = 38,
                    maximumScannedDies = 25,
                    maximumCalls = 9,
                ),
            )
            assertEquals(25L, observed.scannedDies)
            assertEquals(9L, observed.entities)
            val byDie = observed.document.controlArray("calls")
                .map { it as JsonObject }
                .associateBy { it.controlString("dieOffset") }

            val variableDefinition = byDie.getValue(
                callHex(requireNotNull(fixture.variableDefinitionCallDieOffset)),
            )
            assertScoredCall(variableDefinition, localOffset = "0x30", returnRva = "0x170")
            assertTarget(
                variableDefinition,
                kind = "indirect-proven",
                dispatchKind = "indirect-proven",
                provenFunctionIds = listOf("function-rva-0x1d0"),
                targetEvidence = "call-target-expression",
            )

            val memberDefinition = byDie.getValue(
                callHex(requireNotNull(fixture.memberDefinitionCallDieOffset)),
            )
            assertScoredCall(memberDefinition, localOffset = "0x34", returnRva = "0x174")
            assertTarget(
                memberDefinition,
                kind = "indirect-unresolved",
                dispatchKind = "indirect-unresolved",
                targetEvidence = "none",
            )
        }

    @Test
    fun `origin chain crossing to an unrelated tag fails before target classification`() =
        inControlTemporaryDirectory { root ->
            val fixture = CallObservationElfFixture.build(CallOriginChainFixture.SUBPROGRAM_TO_COMPILE_UNIT)
            val failure = assertFailsWith<FullTreeControlException> {
                generateFixture(
                    root,
                    fixture,
                    callProducerLimits(
                        maximumPhysicalRecords = 21,
                        maximumNonNullRecords = 17,
                        maximumAttributes = 35,
                        maximumScannedDies = 21,
                        maximumCalls = 8,
                    ),
                )
            }

            // The origin deliberately also has malformed alias bytes plus virtual and direct
            // cues. Kind compatibility must fail closed before any of those are interpreted.
            assertEquals("DW_AT_call_origin reference chain changes DIE kind", failure.message)
        }

    private fun generateFixture(
        root: Path,
        fixture: CallObservationArtifact,
        producerLimits: FullTreeCallObservationProducerLimits,
    ): FullTreeCallObservationShardGeneration {
        val controls = createFullTreeControlFixture(root.resolve("controls"))
        val artifact = writeElf(root.resolve("calls.elf"), fixture.bytes)
        val scope = callScopeForArtifact(
            controls.authenticatedScope(),
            OracleArtifacts.sha256(fixture.bytes),
            fixture.bytes.size.toLong(),
        )
        val inventoryPath = root.resolve("calls-inventory.json")
        val inventory = FullTreeInventoryControl.generateAndPublish(
            artifact,
            scope,
            inventoryPath,
            maximumWorkers = 1,
        )
        val shardId = inventory.inventory.controlArray("shards").single().let {
            (it as JsonObject).controlString("id")
        }
        assertEquals("clang-lib-call", shardId)
        return FullTreeCallObservationProducer.generateShardWithLimits(
            richArtifact = artifact,
            inventoryPath = inventoryPath,
            scope = scope,
            shardId = shardId,
            scratchParent = root,
            controlLimits = FullTreeControlLimits(),
            producerLimits = producerLimits,
        )
    }

    private fun assertScoredCall(
        call: JsonObject,
        localOffset: String,
        returnRva: String,
        tailCall: Boolean = false,
    ) {
        assertEquals("scored", call.controlString("population"))
        assertEquals(JsonNull, call["reasonCode"])
        assertEquals("function-rva-0x140", call.controlString("callerId"))
        assertEquals(localOffset, call.controlString("callerLocalReturnOffset"))
        assertEquals(returnRva, call.controlString("returnPcRva"))
        assertEquals(JsonPrimitive(tailCall), call["tailCall"])
    }

    private fun assertTarget(
        call: JsonObject,
        kind: String,
        dispatchKind: String,
        functionId: String? = null,
        aliases: List<String> = emptyList(),
        originDieOffset: String? = null,
        provenFunctionIds: List<String> = emptyList(),
        targetEvidence: String,
    ) {
        val target = call.controlObject("target")
        assertEquals(kind, target.controlString("kind"))
        assertEquals(dispatchKind, target.controlString("dispatchKind"))
        if (functionId == null) assertEquals(JsonNull, target["functionId"])
        else assertEquals(functionId, target.controlString("functionId"))
        assertEquals(aliases, target.controlArray("aliases").map { (it as JsonPrimitive).content })
        if (originDieOffset == null) assertEquals(JsonNull, target["originDieOffset"])
        else assertEquals(originDieOffset, target.controlString("originDieOffset"))
        assertEquals(
            provenFunctionIds,
            target.controlArray("provenFunctionIds").map { (it as JsonPrimitive).content },
        )
        assertEquals(targetEvidence, target.controlString("targetEvidence"))
    }

    private fun callProducerLimits(
        maximumPhysicalRecords: Long = 19,
        maximumNonNullRecords: Int = 15,
        maximumAttributes: Long = 29,
        maximumScannedDies: Long = 19,
        maximumCalls: Int = 7,
    ) = FullTreeCallObservationProducerLimits(
        dieLimits = FullTreeDwarfDieLimits(
            maximumPhysicalRecords = maximumPhysicalRecords,
            maximumNonNullRecords = maximumNonNullRecords,
            maximumAttributes = maximumAttributes,
            maximumTreeDepth = 3,
            maximumRetainedBytes = 128 * 1024,
        ),
        elfLayoutLimits = FullTreeElfLayoutLimits(
            maximumProgramHeaders = 1,
            maximumSectionHeaders = 5,
            maximumSymbolTables = 1,
            maximumSymbols = 1,
            maximumSectionNameBytes = 32,
            maximumTotalSectionNameBytes = 128,
            maximumFunctionNameBytes = 64,
            maximumFunctionNameCodePoints = 64,
            maximumLocatorBytes = 256,
            maximumParseSteps = 64,
        ),
        maximumReferenceChainEntries = 2,
        maximumCachedCompilationUnits = 1,
        maximumScannedDies = maximumScannedDies,
        maximumCalls = maximumCalls,
        maximumRetainedBytes = 128 * 1024,
    )
}

private fun callScopeForArtifact(
    original: AuthenticatedFullTreeScope,
    artifactSha256: String,
    artifactBytes: Long,
): AuthenticatedFullTreeScope {
    val originalArtifacts = original.artifactManifest.controlObject("artifacts")
    val full = JsonObject(originalArtifacts.controlObject("full").toMutableMap().apply {
        this["bytes"] = JsonPrimitive(artifactBytes)
        this["sha256"] = JsonPrimitive(artifactSha256)
    })
    val manifest = JsonObject(original.artifactManifest.toMutableMap().apply {
        this["artifacts"] = JsonObject(originalArtifacts.toMutableMap().apply {
            this["full"] = full
        })
    })
    val manifestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
    val oracle = original.document.controlObject("oracle")
    val document = JsonObject(original.document.toMutableMap().apply {
        this["oracle"] = JsonObject(oracle.toMutableMap().apply {
            this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
            this["richArtifactSha256"] = JsonPrimitive(artifactSha256)
        })
    })
    return AuthenticatedFullTreeScope(
        document = document,
        sha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(document)),
        sourceLock = original.sourceLock,
        sourceLockSha256 = original.sourceLockSha256,
        artifactManifest = manifest,
        artifactManifestSha256 = manifestSha256,
    )
}

private enum class CallOriginChainFixture {
    NONE,
    COMPATIBLE_OBJECTS,
    SUBPROGRAM_TO_COMPILE_UNIT,
}

private data class CallObservationArtifact(
    val bytes: ByteArray,
    val internalTargetDieOffset: Int,
    val externalTargetDieOffset: Int,
    val virtualTargetDieOffset: Int,
    val directCallDieOffset: Int,
    val provenCallDieOffset: Int,
    val externalCallDieOffset: Int,
    val virtualCallDieOffset: Int,
    val unresolvedCallDieOffset: Int,
    val addresslessCallDieOffset: Int,
    val callerlessCallDieOffset: Int,
    val variableDefinitionCallDieOffset: Int?,
    val memberDefinitionCallDieOffset: Int?,
)

private object CallObservationElfFixture {
    private const val IMAGE_BASE = 0x400000L
    private const val ELF_HEADER_BYTES = 64
    private const val PROGRAM_HEADER_BYTES = 56
    private const val SECTION_HEADER_BYTES = 64
    private const val TEXT_OFFSET = 0x100
    private const val TEXT_BYTES = 0x100

    fun build(originChainFixture: CallOriginChainFixture = CallOriginChainFixture.NONE): CallObservationArtifact {
        val dwarf = dwarfSections(originChainFixture)
        val sectionNames = listOf(".text", ".debug_info", ".debug_abbrev", ".shstrtab")
        val nameTable = ByteArrayOutputStream().apply { write(0) }
        val nameOffsets = sectionNames.associateWith { name ->
            nameTable.size().also {
                nameTable.write(name.toByteArray(Charsets.US_ASCII))
                nameTable.write(0)
            }
        }
        val shstrtab = nameTable.toByteArray()
        val infoOffset = callAlign(TEXT_OFFSET + TEXT_BYTES, 8)
        val abbreviationOffset = callAlign(infoOffset + dwarf.info.size, 1)
        val shstrtabOffset = callAlign(abbreviationOffset + dwarf.abbreviations.size, 1)
        val sectionTableOffset = callAlign(shstrtabOffset + shstrtab.size, 8)
        val sectionCount = 5
        val totalBytes = sectionTableOffset + sectionCount * SECTION_HEADER_BYTES
        val result = ByteArray(totalBytes)
        ByteArray(TEXT_BYTES) { 0x90.toByte() }.copyInto(result, TEXT_OFFSET)
        dwarf.info.copyInto(result, infoOffset)
        dwarf.abbreviations.copyInto(result, abbreviationOffset)
        shstrtab.copyInto(result, shstrtabOffset)

        result[0] = 0x7f
        result[1] = 'E'.code.toByte()
        result[2] = 'L'.code.toByte()
        result[3] = 'F'.code.toByte()
        result[4] = 2 // ELF64
        result[5] = 1 // little-endian
        result[6] = 1 // current ELF version
        callPut16(result, 16, 2) // ET_EXEC
        callPut16(result, 18, 62) // EM_X86_64
        callPut32(result, 20, 1)
        callPut64(result, 24, IMAGE_BASE + 0x140L)
        callPut64(result, 32, ELF_HEADER_BYTES.toLong())
        callPut64(result, 40, sectionTableOffset.toLong())
        callPut16(result, 52, ELF_HEADER_BYTES)
        callPut16(result, 54, PROGRAM_HEADER_BYTES)
        callPut16(result, 56, 1)
        callPut16(result, 58, SECTION_HEADER_BYTES)
        callPut16(result, 60, sectionCount)
        callPut16(result, 62, 4)

        val program = ELF_HEADER_BYTES
        callPut32(result, program, 1) // PT_LOAD
        callPut32(result, program + 4, 5) // PF_R | PF_X
        callPut64(result, program + 8, 0L)
        callPut64(result, program + 16, IMAGE_BASE)
        callPut64(result, program + 24, IMAGE_BASE)
        callPut64(result, program + 32, totalBytes.toLong())
        callPut64(result, program + 40, totalBytes.toLong())
        callPut64(result, program + 48, 0x1000L)

        callWriteSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES,
            nameOffsets.getValue(".text"),
            type = 1,
            flags = 6L,
            address = IMAGE_BASE + TEXT_OFFSET,
            fileOffset = TEXT_OFFSET,
            size = TEXT_BYTES,
            alignment = 16,
        )
        callWriteSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 2,
            nameOffsets.getValue(".debug_info"),
            type = 1,
            fileOffset = infoOffset,
            size = dwarf.info.size,
        )
        callWriteSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 3,
            nameOffsets.getValue(".debug_abbrev"),
            type = 1,
            fileOffset = abbreviationOffset,
            size = dwarf.abbreviations.size,
        )
        callWriteSection(
            result,
            sectionTableOffset + SECTION_HEADER_BYTES * 4,
            nameOffsets.getValue(".shstrtab"),
            type = 3,
            fileOffset = shstrtabOffset,
            size = shstrtab.size,
        )
        return CallObservationArtifact(
            bytes = result,
            internalTargetDieOffset = dwarf.internalTargetDieOffset,
            externalTargetDieOffset = dwarf.externalTargetDieOffset,
            virtualTargetDieOffset = dwarf.virtualTargetDieOffset,
            directCallDieOffset = dwarf.directCallDieOffset,
            provenCallDieOffset = dwarf.provenCallDieOffset,
            externalCallDieOffset = dwarf.externalCallDieOffset,
            virtualCallDieOffset = dwarf.virtualCallDieOffset,
            unresolvedCallDieOffset = dwarf.unresolvedCallDieOffset,
            addresslessCallDieOffset = dwarf.addresslessCallDieOffset,
            callerlessCallDieOffset = dwarf.callerlessCallDieOffset,
            variableDefinitionCallDieOffset = dwarf.variableDefinitionCallDieOffset,
            memberDefinitionCallDieOffset = dwarf.memberDefinitionCallDieOffset,
        )
    }

    private fun dwarfSections(originChainFixture: CallOriginChainFixture): CallObservationDwarfSections {
        val abbreviations = ByteArrayOutputStream().apply {
            callAbbreviation(
                code = 1,
                tag = 0x11,
                hasChildren = true,
                attributes = listOf(
                    0x03L to FULL_TREE_DW_FORM_STRING,
                    0x1bL to FULL_TREE_DW_FORM_STRING,
                    0x25L to FULL_TREE_DW_FORM_STRING,
                    0x13L to FULL_TREE_DW_FORM_DATA2,
                ),
            )
            callAbbreviation(
                code = 2,
                tag = 0x2e,
                attributes = listOf(
                    0x03L to FULL_TREE_DW_FORM_STRING,
                    0x6eL to FULL_TREE_DW_FORM_STRING,
                    0x11L to FULL_TREE_DW_FORM_ADDR,
                ),
            )
            callAbbreviation(
                code = 3,
                tag = 0x2e,
                attributes = listOf(0x03L to FULL_TREE_DW_FORM_STRING),
            )
            callAbbreviation(
                code = 4,
                tag = 0x2e,
                attributes = listOf(
                    0x03L to FULL_TREE_DW_FORM_STRING,
                    0x4cL to FULL_TREE_DW_FORM_DATA1,
                ),
            )
            callAbbreviation(
                code = 5,
                tag = 0x2e,
                hasChildren = true,
                attributes = listOf(
                    0x03L to FULL_TREE_DW_FORM_STRING,
                    0x11L to FULL_TREE_DW_FORM_ADDR,
                ),
            )
            callAbbreviation(code = 6, tag = 0x0b, hasChildren = true, attributes = emptyList())
            callAbbreviation(
                code = 7,
                tag = 0x48,
                attributes = listOf(
                    0x7dL to FULL_TREE_DW_FORM_ADDR,
                    0x7fL to FULL_TREE_DW_FORM_REF4,
                    0x82L to FULL_TREE_DW_FORM_FLAG_PRESENT,
                ),
            )
            callAbbreviation(
                code = 8,
                tag = 0x48,
                attributes = listOf(
                    0x81L to FULL_TREE_DW_FORM_ADDR,
                    0x83L to FULL_TREE_DW_FORM_EXPRLOC,
                    0x84L to FULL_TREE_DW_FORM_EXPRLOC,
                ),
            )
            callAbbreviation(
                code = 9,
                tag = 0x48,
                attributes = listOf(
                    0x7dL to FULL_TREE_DW_FORM_ADDR,
                    0x7fL to FULL_TREE_DW_FORM_REF4,
                ),
            )
            callAbbreviation(
                code = 10,
                tag = 0x48,
                attributes = listOf(
                    0x7dL to FULL_TREE_DW_FORM_ADDR,
                    0x83L to FULL_TREE_DW_FORM_EXPRLOC,
                    0x7fL to FULL_TREE_DW_FORM_REF4,
                ),
            )
            callAbbreviation(
                code = 11,
                tag = 0x48,
                attributes = listOf(0x82L to FULL_TREE_DW_FORM_FLAG_PRESENT),
            )
            callAbbreviation(
                code = 12,
                tag = 0x2e,
                hasChildren = true,
                attributes = listOf(0x03L to FULL_TREE_DW_FORM_STRING),
            )
            callAbbreviation(
                code = 13,
                tag = 0x48,
                attributes = listOf(0x7dL to FULL_TREE_DW_FORM_ADDR),
            )
            callAbbreviation(
                code = 14,
                tag = 0x34, // DW_TAG_variable is an indirect call-origin object
                attributes = listOf(0x03L to FULL_TREE_DW_FORM_STRING),
            )
            when (originChainFixture) {
                CallOriginChainFixture.NONE -> Unit
                CallOriginChainFixture.COMPATIBLE_OBJECTS -> {
                    callAbbreviation(
                        code = 15,
                        tag = 0x0d, // DW_TAG_member specification
                        attributes = listOf(0x03L to FULL_TREE_DW_FORM_STRING),
                    )
                    callAbbreviation(
                        code = 16,
                        tag = 0x34, // DW_TAG_variable definition
                        attributes = listOf(DW_AT_SPECIFICATION to FULL_TREE_DW_FORM_REF4),
                    )
                    callAbbreviation(
                        code = 17,
                        tag = 0x34, // DW_TAG_variable abstract origin
                        attributes = listOf(0x03L to FULL_TREE_DW_FORM_STRING),
                    )
                    callAbbreviation(
                        code = 18,
                        tag = 0x0d, // DW_TAG_member definition
                        attributes = listOf(DW_AT_ABSTRACT_ORIGIN to FULL_TREE_DW_FORM_REF4),
                    )
                }
                CallOriginChainFixture.SUBPROGRAM_TO_COMPILE_UNIT -> callAbbreviation(
                    code = 19,
                    tag = DW_TAG_SUBPROGRAM,
                    attributes = listOf(
                        0x03L to FULL_TREE_DW_FORM_STRING,
                        0x4cL to FULL_TREE_DW_FORM_DATA1,
                        0x11L to FULL_TREE_DW_FORM_ADDR,
                        DW_AT_SPECIFICATION to FULL_TREE_DW_FORM_REF4,
                    ),
                )
            }
            write(0)
        }.toByteArray()

        val dies = ByteArrayOutputStream()
        dies.write(callUleb(1))
        dies.write(callUtf8z("calls.c"))
        dies.write(callUtf8z("/fixture/source-tree/clang/lib/Call"))
        dies.write(callUtf8z("Kotlin call-observation fixture"))
        dies.write(callUnsigned(0x000cL, 2)) // DW_LANG_C99

        val internalTargetDieOffset = 11 + dies.size()
        dies.write(callUleb(2))
        dies.write(callUtf8z("internal_name"))
        dies.write(callUtf8z("internal_linkage"))
        dies.write(callUnsigned(IMAGE_BASE + 0x180L, 8))

        val externalTargetDieOffset = 11 + dies.size()
        dies.write(callUleb(3))
        dies.write(callUtf8z("external_target"))

        val virtualTargetDieOffset = 11 + dies.size()
        dies.write(callUleb(4))
        dies.write(callUtf8z("virtual_target"))
        dies.write(1)

        val indirectObjectDieOffset = 11 + dies.size()
        dies.write(callUleb(14))
        dies.write(callUtf8z("function_pointer"))

        var variableDefinitionOriginDieOffset: Int? = null
        var memberDefinitionOriginDieOffset: Int? = null
        var incompatibleOriginDieOffset: Int? = null
        when (originChainFixture) {
            CallOriginChainFixture.NONE -> Unit
            CallOriginChainFixture.COMPATIBLE_OBJECTS -> {
                val memberSpecificationDieOffset = 11 + dies.size()
                dies.write(callUleb(15))
                dies.write(callUtf8z("member_specification"))

                variableDefinitionOriginDieOffset = 11 + dies.size()
                dies.write(callUleb(16))
                dies.write(callUnsigned(memberSpecificationDieOffset.toLong(), 4))

                val variableAbstractOriginDieOffset = 11 + dies.size()
                dies.write(callUleb(17))
                dies.write(callUtf8z("variable_abstract_origin"))

                memberDefinitionOriginDieOffset = 11 + dies.size()
                dies.write(callUleb(18))
                dies.write(callUnsigned(variableAbstractOriginDieOffset.toLong(), 4))
            }
            CallOriginChainFixture.SUBPROGRAM_TO_COMPILE_UNIT -> {
                incompatibleOriginDieOffset = 11 + dies.size()
                dies.write(callUleb(19))
                dies.write(byteArrayOf(0xc3.toByte(), 0x28, 0)) // deliberately malformed UTF-8 alias
                dies.write(1) // virtual dispatch cue
                dies.write(callUnsigned(IMAGE_BASE + 0x1e0L, 8)) // direct-internal cue
                dies.write(callUnsigned(11L, 4)) // specification crosses to DW_TAG_compile_unit
            }
        }

        dies.write(callUleb(5))
        dies.write(callUtf8z("caller"))
        dies.write(callUnsigned(IMAGE_BASE + 0x140L, 8))
        dies.write(callUleb(6)) // unretained DW_TAG_lexical_block

        val directCallDieOffset = 11 + dies.size()
        dies.write(callUleb(7))
        dies.write(callUnsigned(IMAGE_BASE + 0x148L, 8))
        dies.write(callUnsigned(internalTargetDieOffset.toLong(), 4))

        val provenCallDieOffset = 11 + dies.size()
        dies.write(callUleb(8))
        dies.write(callUnsigned(IMAGE_BASE + 0x150L, 8))
        dies.write(callExpression(byteArrayOf(0x03) + callUnsigned(IMAGE_BASE + 0x1c0L, 8)))
        dies.write(callExpression(byteArrayOf(0x50))) // DW_OP_reg0, retained only as clobber evidence
        dies.write(0) // close lexical block

        val externalCallDieOffset = 11 + dies.size()
        dies.write(callUleb(9))
        dies.write(callUnsigned(IMAGE_BASE + 0x158L, 8))
        dies.write(callUnsigned(externalTargetDieOffset.toLong(), 4))

        val virtualCallDieOffset = 11 + dies.size()
        dies.write(callUleb(9))
        dies.write(callUnsigned(IMAGE_BASE + 0x160L, 8))
        dies.write(callUnsigned(virtualTargetDieOffset.toLong(), 4))

        val unresolvedCallDieOffset = 11 + dies.size()
        dies.write(callUleb(10))
        dies.write(callUnsigned(IMAGE_BASE + 0x168L, 8))
        dies.write(callExpression(byteArrayOf(0x50))) // non-address expression remains unresolved
        dies.write(callUnsigned(indirectObjectDieOffset.toLong(), 4))

        var variableDefinitionCallDieOffset: Int? = null
        var memberDefinitionCallDieOffset: Int? = null
        when (originChainFixture) {
            CallOriginChainFixture.NONE -> Unit
            CallOriginChainFixture.COMPATIBLE_OBJECTS -> {
                variableDefinitionCallDieOffset = 11 + dies.size()
                dies.write(callUleb(10))
                dies.write(callUnsigned(IMAGE_BASE + 0x170L, 8))
                dies.write(callExpression(byteArrayOf(0x03) + callUnsigned(IMAGE_BASE + 0x1d0L, 8)))
                dies.write(callUnsigned(requireNotNull(variableDefinitionOriginDieOffset).toLong(), 4))

                memberDefinitionCallDieOffset = 11 + dies.size()
                dies.write(callUleb(9))
                dies.write(callUnsigned(IMAGE_BASE + 0x174L, 8))
                dies.write(callUnsigned(requireNotNull(memberDefinitionOriginDieOffset).toLong(), 4))
            }
            CallOriginChainFixture.SUBPROGRAM_TO_COMPILE_UNIT -> {
                dies.write(callUleb(9))
                dies.write(callUnsigned(IMAGE_BASE + 0x170L, 8))
                dies.write(callUnsigned(requireNotNull(incompatibleOriginDieOffset).toLong(), 4))
            }
        }

        val addresslessCallDieOffset = 11 + dies.size()
        dies.write(callUleb(11))
        dies.write(0) // close emitted caller

        dies.write(callUleb(12))
        dies.write(callUtf8z("caller_without_range"))

        val callerlessCallDieOffset = 11 + dies.size()
        dies.write(callUleb(13))
        dies.write(callUnsigned(IMAGE_BASE + 0x178L, 8))
        dies.write(0) // close caller without a range
        dies.write(0) // close compilation unit

        val dieBytes = dies.toByteArray()
        val unitBody = callUnsigned(4L, 2) + callUnsigned(0L, 4) + byteArrayOf(8) + dieBytes
        return CallObservationDwarfSections(
            info = callUnsigned(unitBody.size.toLong(), 4) + unitBody,
            abbreviations = abbreviations,
            internalTargetDieOffset = internalTargetDieOffset,
            externalTargetDieOffset = externalTargetDieOffset,
            virtualTargetDieOffset = virtualTargetDieOffset,
            directCallDieOffset = directCallDieOffset,
            provenCallDieOffset = provenCallDieOffset,
            externalCallDieOffset = externalCallDieOffset,
            virtualCallDieOffset = virtualCallDieOffset,
            unresolvedCallDieOffset = unresolvedCallDieOffset,
            addresslessCallDieOffset = addresslessCallDieOffset,
            callerlessCallDieOffset = callerlessCallDieOffset,
            variableDefinitionCallDieOffset = variableDefinitionCallDieOffset,
            memberDefinitionCallDieOffset = memberDefinitionCallDieOffset,
        )
    }
}

private data class CallObservationDwarfSections(
    val info: ByteArray,
    val abbreviations: ByteArray,
    val internalTargetDieOffset: Int,
    val externalTargetDieOffset: Int,
    val virtualTargetDieOffset: Int,
    val directCallDieOffset: Int,
    val provenCallDieOffset: Int,
    val externalCallDieOffset: Int,
    val virtualCallDieOffset: Int,
    val unresolvedCallDieOffset: Int,
    val addresslessCallDieOffset: Int,
    val callerlessCallDieOffset: Int,
    val variableDefinitionCallDieOffset: Int?,
    val memberDefinitionCallDieOffset: Int?,
)

private fun ByteArrayOutputStream.callAbbreviation(
    code: Long,
    tag: Long,
    hasChildren: Boolean = false,
    attributes: List<Pair<Long, Long>>,
) {
    write(callUleb(code))
    write(callUleb(tag))
    write(if (hasChildren) 1 else 0)
    attributes.forEach { (name, form) ->
        write(callUleb(name))
        write(callUleb(form))
    }
    write(0)
    write(0)
}

private fun callWriteSection(
    result: ByteArray,
    offset: Int,
    nameOffset: Int,
    type: Int,
    flags: Long = 0L,
    address: Long = 0L,
    fileOffset: Int,
    size: Int,
    alignment: Int = 1,
) {
    callPut32(result, offset, nameOffset.toLong())
    callPut32(result, offset + 4, type.toLong())
    callPut64(result, offset + 8, flags)
    callPut64(result, offset + 16, address)
    callPut64(result, offset + 24, fileOffset.toLong())
    callPut64(result, offset + 32, size.toLong())
    callPut64(result, offset + 48, alignment.toLong())
}

private fun callExpression(bytes: ByteArray): ByteArray = callUleb(bytes.size.toLong()) + bytes

private fun callUnsigned(value: Long, width: Int): ByteArray =
    ByteArray(width) { index -> (value ushr (index * 8)).toByte() }

private fun callUleb(value: Long): ByteArray {
    require(value >= 0L)
    var remaining = value
    val result = ByteArrayOutputStream()
    do {
        var current = (remaining and 0x7fL).toInt()
        remaining = remaining ushr 7
        if (remaining != 0L) current = current or 0x80
        result.write(current)
    } while (remaining != 0L)
    return result.toByteArray()
}

private fun callUtf8z(value: String): ByteArray = value.toByteArray(Charsets.UTF_8) + byteArrayOf(0)

private fun callAlign(value: Int, alignment: Int): Int =
    Math.addExact(value, alignment - 1) / alignment * alignment

private fun callPut16(bytes: ByteArray, offset: Int, value: Int) {
    repeat(2) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}

private fun callPut32(bytes: ByteArray, offset: Int, value: Long) {
    repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}

private fun callPut64(bytes: ByteArray, offset: Int, value: Long) {
    repeat(8) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}

private fun callHex(value: Int): String = "0x${value.toString(16)}"
