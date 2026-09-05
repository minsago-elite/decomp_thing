package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCrossShardCallFixtureTest {
    @Test
    fun `three authenticated raw shards contain cross-shard cycles and bounded target evidence`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCrossShardCallFixture(root.resolve("fixture"))
            assertEquals(listOf("clang-lib-alpha", "clang-lib-beta", "llvm-lib-gamma"), fixture.shardIds)
            assertEquals(3, fixture.inventory.controlArray("units").size)
            val first = fixture.generateRawCallShards()
            val repeated = fixture.generateRawCallShards()
            assertEquals(fixture.shardIds.toSet(), first.keys)
            assertEquals(12L, first.values.sumOf { it.entities })
            assertTrue(first.values.all { it.entities == 4L })
            assertEquals(11L, first.values.sumOf { it.document.controlObject("counts").controlLong("scored") })
            assertEquals(1L, first.values.sumOf { it.document.controlObject("counts").controlLong("unobservable") })
            for ((shardId, generation) in first) {
                assertEquals(generation.outputSha256, repeated.getValue(shardId).outputSha256)
                assertContentEquals(
                    FullTreeCallObservations.canonicalEnvelopeBytes(generation.document),
                    FullTreeCallObservations.canonicalEnvelopeBytes(repeated.getValue(shardId).document),
                )
                assertEquals(fixtureSha256(fixture.artifact), generation.richArtifactSha256)
                assertEquals(fixtureSha256(fixture.inventoryPath), generation.inventoryArtifactSha256)
                assertEquals(
                    FullTreeCallObservations.configurationSha256,
                    generation.document.controlObject("oracle").controlString("configurationSha256"),
                )
            }
            val observed = first.values.flatMap {
                it.document.controlArray("calls").controlObjects("raw calls")
            }.associateBy { it.controlString("dieOffset") }
            assertEquals(12, observed.size)
            for (expected in fixture.calls) {
                val call = observed.getValue(hex(fixture.dieOffsets.getValue(expected.name)))
                val caller = fixture.functions.getValue(expected.caller)
                val shard = first.getValue(fixture.shardForFunction(expected.caller))
                assertTrue(call in shard.document.controlArray("calls"))
                val owner = fixture.inventory.controlArray("units").controlObjects("inventory units")
                    .single { it.controlString("sourcePath") == caller.sourcePath }
                assertEquals(owner["id"], call["unitId"])
                assertEquals(JsonPrimitive(expected.tailCall), call["tailCall"])
                if (expected.addressRva == null) {
                    assertEquals("unobservable", call.controlString("population"))
                    assertEquals("call-site-no-address", call.controlString("reasonCode"))
                    assertEquals(JsonNull, call["callerId"])
                    assertEquals(JsonNull, call["callerLocalReturnOffset"])
                    assertEquals(JsonNull, call["returnPcRva"])
                } else {
                    assertEquals("scored", call.controlString("population"))
                    assertEquals(JsonNull, call["reasonCode"])
                    assertEquals(caller.functionId, call.controlString("callerId"))
                    assertEquals(hex(expected.addressRva), call.controlString("returnPcRva"))
                    assertEquals(hex(expected.addressRva - caller.rva), call.controlString("callerLocalReturnOffset"))
                }
                val target = call.controlObject("target")
                assertEquals(expected.targetKind, target.controlString("kind"))
                assertEquals(JsonArray(expected.aliases.map(::JsonPrimitive)), target["aliases"])
                assertEquals(
                    if (expected.targetKind == "direct-internal") {
                        JsonPrimitive(fixture.functionIds.getValue(checkNotNull(expected.target)))
                    } else {
                        JsonNull
                    },
                    target["functionId"],
                )
                assertEquals(
                    JsonArray(if (expected.targetKind == "indirect-proven") {
                        listOf(JsonPrimitive(fixture.functionIds.getValue(checkNotNull(expected.target))))
                    } else {
                        emptyList()
                    }),
                    target["provenFunctionIds"],
                )
            }
            for ((caller, target) in listOf("alpha" to "beta", "beta" to "gamma", "gamma" to "alpha")) {
                val call = observed.getValue(hex(fixture.dieOffsets.getValue("$caller-to-$target")))
                assertNotEquals(fixture.shardForFunction(caller), fixture.shardForFunction(target))
                assertEquals(fixture.functionIds.getValue(target), call.controlObject("target").controlString("functionId"))
                assertEquals(hex(fixture.dieOffsets.getValue(target)), call.controlObject("target").controlString("originDieOffset"))
            }
            val duplicatePair = fixture.duplicateCallGroups.single().map { name ->
                observed.getValue(hex(fixture.dieOffsets.getValue(name)))
            }
            assertNotEquals(duplicatePair.first()["id"], duplicatePair.last()["id"])
            assertEquals(
                duplicatePair.first().filterKeys { it !in setOf("id", "dieOffset") },
                duplicatePair.last().filterKeys { it !in setOf("id", "dieOffset") },
            )
            assertEquals(
                setOf("direct-internal", "external-unresolved", "indirect-proven", "indirect-unresolved", "virtual-unresolved"),
                observed.values.map { it.controlObject("target").controlString("kind") }.toSet(),
            )
            assertTrue("normalized-semantic-thunk-targets" in fixture.unsupportedSemantics)
            assertTrue("relocation-backed-external-or-PLT-target-identities" in fixture.unsupportedSemantics)
            assertTrue("virtual-slot-identities-and-proven-virtual-targets" in fixture.unsupportedSemantics)
        }

    @Test
    fun `raw function observations and authenticated ELF twins resolve every fixture function`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeCrossShardCallFixture(root.resolve("fixture"))
            val generations = fixture.generateRawFunctionShards()
            assertEquals(fixture.shardIds.toSet(), generations.keys)
            assertEquals(5L, generations.values.sumOf { it.entities })
            val emittedByRva = generations.values.flatMap { generation ->
                assertTrue(generation.document.controlArray("nonEmitted").isEmpty())
                assertEquals(fixtureSha256(fixture.artifact), generation.richArtifactSha256)
                assertEquals(fixtureSha256(fixture.inventoryPath), generation.inventoryArtifactSha256)
                generation.document.controlArray("emitted").controlObjects("emitted functions")
            }.associateBy { it.controlString("rva") }
            assertEquals(fixture.functions.values.map { hex(it.rva) }.toSet(), emittedByRva.keys)
            for ((name, function) in fixture.functions) {
                val emitted = emittedByRva.getValue(hex(function.rva))
                assertEquals(
                    listOf(function.name, function.linkageName).sorted(),
                    emitted.controlArray("aliases").controlObjects("function aliases").map { it.controlString("name") },
                )
                assertTrue(emitted in generations.getValue(fixture.shardForFunction(name)).document.controlArray("emitted"))
                val declaration = emitted.controlArray("declarations").controlObjects("function declarations").single()
                assertEquals(function.sourcePath, declaration.controlString("unitSourcePath"))
            }
            val firstOutput = root.resolve("elf-functions-first.json")
            val secondOutput = root.resolve("elf-functions-second.json")
            val bindings = listOf(firstOutput, secondOutput).mapIndexed { index, output ->
                FullTreeElfFunctionsSqlite.generateAndPublish(
                    fixture.artifact,
                    fixture.strippedArtifact,
                    fixture.scope,
                    fixture.inventory,
                    output,
                    maximumWorkers = index + 1,
                )
            }
            assertEquals(FullTreeElfFunctionCounts(10, 1, 5, 1), bindings.first().counts)
            assertEquals("0x400000", bindings.first().imageBase)
            assertEquals("ET_EXEC", bindings.first().elfType)
            assertEquals(bindings.first().sha256, bindings.last().sha256)
            assertContentEquals(Files.readAllBytes(firstOutput), Files.readAllBytes(secondOutput))
            val validated = FullTreeElfFunctionsSqlite.loadAndValidate(
                firstOutput,
                fixture.artifact,
                fixture.strippedArtifact,
                fixture.scope,
                fixture.inventory,
                maximumWorkers = 1,
            )
            assertEquals(bindings.first().sha256, validated.sha256)
            assertEquals(fixtureSha256(fixture.artifact), validated.richInputSha256)
            assertEquals(fixtureSha256(fixture.strippedArtifact), validated.strippedInputSha256)
            val index = parseControlObject(firstOutput)
            val functions = index.controlArray("functions").controlObjects("ELF functions")
            assertEquals(fixture.functionIds.values.toSet(), functions.map { it.controlString("id") }.toSet())
            val external = index.controlArray("externalFunctions").controlObjects("external functions").single()
            assertEquals("fixture_external", external.controlString("name"))
            assertTrue(external.controlArray("evidence").controlObjects("external evidence").any {
                it.controlString("locator").contains(".dynsym")
            })
            val calls = fixture.generateRawCallShards().values.flatMap {
                it.document.controlArray("calls").controlObjects("raw calls")
            }
            val indexedIds = functions.map { it.controlString("id") }.toSet()
            for (call in calls) {
                val target = call.controlObject("target")
                if (call["callerId"] != JsonNull) assertTrue(call.controlString("callerId") in indexedIds)
                if (target["functionId"] != JsonNull) assertTrue(target.controlString("functionId") in indexedIds)
                for (proven in target.controlArray("provenFunctionIds")) {
                    assertTrue((proven as JsonPrimitive).content in indexedIds)
                }
            }
            val independent = createFullTreeCrossShardCallFixture(root.resolve("independent"))
            assertEquals(fixture.scope.sha256, independent.scope.sha256)
            assertEquals(fixtureSha256(fixture.artifact), fixtureSha256(independent.artifact))
            assertEquals(fixtureSha256(fixture.strippedArtifact), fixtureSha256(independent.strippedArtifact))
            assertEquals(fixtureSha256(fixture.inventoryPath), fixtureSha256(independent.inventoryPath))
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(firstOutput)), validated.sha256)
        }

    private fun hex(value: Long): String = "0x${value.toString(16)}"
}
