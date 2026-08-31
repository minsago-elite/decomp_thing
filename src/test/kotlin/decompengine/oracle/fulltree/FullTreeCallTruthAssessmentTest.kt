package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.io.path.createDirectories
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallTruthAssessmentTest {
    @Test
    fun `raw three-shard assessment preserves call identities and is permanently non-authoritative`() =
        inControlTemporaryDirectory { directory ->
            val fixture = CallAssessmentFixture.create(directory)
            val pathsBefore = Files.walk(directory).use { stream -> stream.map(Path::toString).sorted().toList() }

            val first = fixture.assess()
            val second = fixture.assess()

            assertEquals("non-authoritative-bounded-kotlin-call-semantics-fixture-assessment", first.authority)
            assertFalse(first.complete)
            assertFalse(first.releaseEligible)
            assertEquals(
                listOf(
                    "kotlin-full-tree-function-truth-producer",
                    "kotlin-dwarf-call-observation-producer",
                    "kotlin-contained-whole-process-tree-call-observation-runtime-receipt",
                    "kotlin-scalable-sqlite-sharded-call-truth-producer",
                ),
                first.missingAuthorities,
            )
            assertEquals(3, first.shards.size)
            first.shards.zip(second.shards).forEach { (left, right) ->
                assertContentEquals(left.canonicalBytes, right.canonicalBytes)
            }
            assertEquals(first.assessmentSha256, second.assessmentSha256)
            assertEquals(
                "307bcda7156bf7ab0dedbde982557c750d7f80999e7b37563987d544db6bb101",
                first.assessmentSha256,
            )
            assertEquals(
                "a0d96c2a9c772793b9dc858b7150c5bcb32760606375e5fab763238e54c37183",
                first.historicalCallTruthConfigurationSha256,
            )
            val all = first.shards.flatMap { it.calls }
            assertEquals(
                setOf(
                    "direct-internal",
                    "external",
                    "indirect-proven",
                    "indirect-unresolved",
                    "virtual-unresolved",
                ),
                all.map { it.targetKind }.toSet(),
            )
            val direct = all.single { it.returnPcRva == "0x14" }
            assertEquals("function-rva-0x10", direct.callerId)
            assertEquals("function-rva-0x20", direct.physicalTargetId)
            assertEquals("function-rva-0x20", direct.semanticTargetId)
            assertEquals(2, direct.observationIds.size)
            assertEquals("clang-lib-driver", first.shards.single { direct in it.calls }.id)

            val external = all.single { it.returnPcRva == "0x15" }
            assertEquals("external", external.targetKind)
            assertEquals(listOf(externalId("puts@plt")), external.externalTargetIds)
            assertEquals("scored", external.population)
            val unsupportedExternal = all.single { it.returnPcRva == "0x16" }
            assertEquals("external", unsupportedExternal.targetKind)
            assertTrue(unsupportedExternal.externalTargetIds.isEmpty())
            assertEquals("external-without-elf-evidence", unsupportedExternal.reasonCode)
            assertEquals("unobservable", unsupportedExternal.population)
            val ambiguousAlias = all.single { it.returnPcRva == "0x17" }
            assertEquals("indirect-unresolved", ambiguousAlias.targetKind)
            assertEquals("direct", ambiguousAlias.dispatchKind)
            assertEquals("ambiguous-authenticated-internal-aliases", ambiguousAlias.reasonCode)

            val proven = all.single { it.targetKind == "indirect-proven" }
            assertEquals(listOf("function-rva-0x10", "function-rva-0x30"), proven.provenTargetIds)
            val virtual = all.single { it.targetKind == "virtual-unresolved" }
            assertEquals("virtual-target-set-unproven", virtual.reasonCode)
            val thunk = all.single { it.returnPcRva == "0x35" }
            assertEquals("function-rva-0x30", thunk.physicalTargetId)
            assertEquals(null, thunk.semanticTargetId)
            assertEquals("thunk-semantic-target-unresolved", thunk.reasonCode)
            assertEquals(
                "function-rva-0x10",
                all.single { it.returnPcRva == "0x26" }.physicalTargetId,
                "the fixture contains an authenticated cross-shard direct-call cycle",
            )

            val defensive = first.shards.first().canonicalBytes
            defensive[0] = (defensive[0].toInt() xor 1).toByte()
            assertContentEquals(second.shards.first().canonicalBytes, first.shards.first().canonicalBytes)
            assertEquals(pathsBefore, Files.walk(directory).use { stream -> stream.map(Path::toString).sorted().toList() })
            assertFailsWithMessage("assessment bound") {
                fixture.assess(FullTreeCallTruthAssessmentLimits(maximumFunctions = 2))
            }
            assertFailsWithMessage("assessment bound") {
                fixture.assess(FullTreeCallTruthAssessmentLimits(maximumAliases = 2))
            }
        }

    @Test
    fun `dangling duplicate and overflow inputs fail closed across shards`() =
        inControlTemporaryDirectory { directory ->
            val danglingCaller = CallAssessmentFixture.create(directory.resolve("caller"))
            danglingCaller.mutateCall("clang-lib-driver", "0x14") { call ->
                callWithCaller(call, "0xffffffffffffffff", "0x1", "0x0")
            }
            assertFailsWithMessage("without overflow") { danglingCaller.assess() }

            val danglingDirect = CallAssessmentFixture.create(directory.resolve("direct"))
            danglingDirect.mutateCall("generated-tools-clang", "0x26") { call ->
                replaceTarget(call) { target ->
                    JsonObject(target.toMutableMap().apply {
                        this["functionId"] = JsonPrimitive("function-rva-0x999")
                    })
                }
            }
            assertFailsWithMessage("dangling direct target") { danglingDirect.assess() }

            val danglingProven = CallAssessmentFixture.create(directory.resolve("proven"))
            danglingProven.mutateCall("generated-tools-clang", "0x24") { call ->
                replaceTarget(call) { target ->
                    JsonObject(target.toMutableMap().apply {
                        this["provenFunctionIds"] = JsonArray(listOf(JsonPrimitive("function-rva-0x999")))
                    })
                }
            }
            assertFailsWithMessage("dangling proven target") { danglingProven.assess() }

            val duplicate = CallAssessmentFixture.create(directory.resolve("duplicate"))
            duplicate.duplicateCall("llvm-lib-ir")
            assertFailsWithMessage("not unique") { duplicate.assess() }

            val missing = CallAssessmentFixture.create(directory.resolve("missing"))
            missing.writeCallRun(listOf("clang-lib-driver", "generated-tools-clang"))
            assertFailsWithMessage("authenticated scope") { missing.assess() }
        }

    @Test
    fun `artifact substitution malformed classifications and symlinks fail closed`() =
        inControlTemporaryDirectory { directory ->
            val forgedControl = CallAssessmentFixture.create(directory.resolve("control"))
            val copied = parseControlObject(forgedControl.callRoot.resolve("control/scope.json"))
            writeControlObject(
                forgedControl.callRoot.resolve("control/scope.json"),
                JsonObject(copied.toMutableMap().apply { this["schemaVersion"] = JsonPrimitive(1) }),
            )
            Files.write(
                forgedControl.callRoot.resolve("control/scope.json"),
                Files.readAllBytes(forgedControl.callRoot.resolve("control/scope.json")) + byteArrayOf(' '.code.toByte()),
            )
            assertFailsWith<FullTreeCallTruthAssessmentException> { forgedControl.assess() }

            val extraControl = CallAssessmentFixture.create(directory.resolve("extra-control"))
            writeJson(extraControl.callRoot.resolve("control/ignored.json"), JsonObject(emptyMap()))
            assertFailsWithMessage("membership") { extraControl.assess() }

            val extraUsage = CallAssessmentFixture.create(directory.resolve("extra-usage"))
            writeJson(extraUsage.callRoot.resolve("usage/ignored.json"), JsonObject(emptyMap()))
            assertFailsWithMessage("membership") { extraUsage.assess() }

            val staleEvidence = CallAssessmentFixture.create(directory.resolve("stale-evidence"))
            val evidencePath = staleEvidence.callRoot.resolve("execution-evidence.json")
            val evidence = parseControlObject(evidencePath)
            writeJson(
                evidencePath,
                JsonObject(evidence.toMutableMap().apply { this["evidenceSha256"] = JsonPrimitive("f".repeat(64)) }),
            )
            assertFailsWithMessage("self-hash") { staleEvidence.assess() }

            val contradictory = CallAssessmentFixture.create(directory.resolve("matrix"))
            contradictory.mutateCall("generated-tools-clang", "0x25") { call ->
                replaceTarget(call) { target ->
                    JsonObject(target.toMutableMap().apply { this["dispatchKind"] = JsonPrimitive("direct") })
                }
            }
            assertFailsWithMessage("classification") { contradictory.assess() }

            val linked = CallAssessmentFixture.create(directory.resolve("linked"))
            val output = linked.callRoot.resolve("outputs/llvm-lib-ir.json")
            val real = linked.callRoot.resolve("outputs/llvm-lib-ir-real.json")
            Files.move(output, real)
            Files.createSymbolicLink(output, real.fileName)
            assertFailsWithMessage("authenticated") { linked.assess() }
        }

    @Test
    fun `embedded verifier extension stays internal and rejects hostile member sets`() {
        assertTrue(
            BoundedShardRunVerifier::class.java.methods.none { it.name == "verifyEmbedded" },
            "the embedded verifier must not widen the public Java authority surface",
        )
        val digest = "0".repeat(64)
        assertFailsWithMessage("member name") {
            BoundedShardRunVerifier.verifyEmbedded(
                Path.of("does-not-exist"),
                digest,
                (0..8).associate { "member-$it" to Unit }.keys,
            )
        }
        assertFailsWithMessage("member name") {
            BoundedShardRunVerifier.verifyEmbedded(
                Path.of("does-not-exist"),
                digest,
                setOf("a".repeat(129)),
            )
        }
        assertFailsWithMessage("member name") {
            BoundedShardRunVerifier.verifyEmbedded(Path.of("does-not-exist"), digest, setOf("../escape"))
        }
    }

    @Test
    fun `assessment API accepts only raw paths and fixed limits`() {
        val assess = FullTreeCallTruthAssessmentVerifier::class.java.declaredMethods.single { it.name == "assess" }
        assertEquals(
            listOf(
                Path::class.java,
                Path::class.java,
                Path::class.java,
                Path::class.java,
                Path::class.java,
                Path::class.java,
                Path::class.java,
                FullTreeCallTruthAssessmentLimits::class.java,
            ),
            assess.parameterTypes.toList(),
        )
        assertTrue(FullTreeCallTruthAssessment::class.java.isInterface)
        assertTrue(FullTreeCallTruthEdgeAssessment::class.java.isInterface)
        assertTrue(FullTreeCallTruthShardAssessment::class.java.isInterface)
        assertTrue(
            FullTreeCallTruthAssessmentVerifier::class.java.declaredClasses
                .single { it.simpleName == "DerivedAssessment" }
                .declaredConstructors
                .none { java.lang.reflect.Modifier.isPublic(it.modifiers) && !it.isSynthetic },
        )
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumIndexBytes = 16 * 1024 * 1024 + 1)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumShardBytes = 64 * 1024 * 1024 + 1)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumShards = 16_385)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumFunctions = 2_500_001)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumObservations = 2_500_001)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumAliases = 10_000_001)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeCallTruthAssessmentLimits(maximumDiagnosticBytes = 64 * 1024 * 1024 + 1)
        }
    }

    private fun assertFailsWithMessage(fragment: String, block: () -> Unit) {
        val failure = assertFailsWith<Exception> { block() }
        assertTrue(fragment in failure.message.orEmpty(), failure.message)
    }
}

private class CallAssessmentFixture private constructor(
    private val control: FullTreeControlFixture,
    private val inventory: JsonObject,
    private val functionTruthRoot: Path,
    private val elfIndex: Path,
    val callRoot: Path,
) {
    fun assess(
        limits: FullTreeCallTruthAssessmentLimits = FullTreeCallTruthAssessmentLimits(),
    ): FullTreeCallTruthAssessment = FullTreeCallTruthAssessmentVerifier.assess(
        control.scope,
        control.sourceLock,
        control.manifest,
        control.inventory,
        functionTruthRoot,
        elfIndex,
        callRoot,
        limits,
    )

    fun mutateCall(shardId: String, returnPc: String, change: (JsonObject) -> JsonObject) {
        val path = callRoot.resolve("outputs/$shardId.json")
        val document = parseControlObject(path)
        val calls = document.testArray("calls").map { it as JsonObject }.toMutableList()
        val position = calls.indexOfFirst { it.testNullableString("returnPcRva") == returnPc }
        check(position >= 0)
        calls[position] = change(calls[position])
        writeCallDocument(shardId, calls)
        writeCallRun(SHARDS)
    }

    fun duplicateCall(shardId: String) {
        val path = callRoot.resolve("outputs/$shardId.json")
        val document = parseControlObject(path)
        val calls = document.testArray("calls").map { it as JsonObject }.toMutableList()
        calls += calls.first()
        writeCallDocument(shardId, calls)
        writeCallRun(SHARDS)
    }

    fun writeCallRun(activeShards: List<String>) {
        SHARDS.filter { it !in activeShards }.forEach { shard ->
            Files.deleteIfExists(callRoot.resolve("outputs/$shard.json"))
            Files.deleteIfExists(callRoot.resolve("checkpoints/$shard.json"))
            Files.deleteIfExists(callRoot.resolve("usage/$shard.json"))
        }
        val configuration = CALL_OBSERVATION_CONFIGURATION
        val inventoryIndex = inventory.testString("indexSha256")
        val scope = parseControlObject(control.scope)
        val scopeSha = sha(Files.readAllBytes(control.scope))
        val richSha = scope.testObject("oracle").testString("richArtifactSha256")
        val scopeBounds = scope.testObject("bounds")
        val perShardBounds = scopeBounds.testObject("perShard")
        val wholeRunBounds = scopeBounds.testObject("wholeRun")
        val unitsById = inventory.testArray("units").map { it as JsonObject }.associateBy { it.testString("id") }
        val inputs = activeShards.map { shard ->
            val shardRecord = inventory.testArray("shards").map { it as JsonObject }
                .single { it.testString("id") == shard }
            val units = shardRecord.testArray("unitIds").map { unitsById.getValue((it as JsonPrimitive).content) }
            val inputSha = sha(
                canonical(
                    JsonObject(
                        mapOf(
                            "inventoryIndexSha256" to JsonPrimitive(inventoryIndex),
                            "producerConfigurationSha256" to JsonPrimitive(configuration),
                            "richArtifactSha256" to JsonPrimitive(richSha),
                            "scopeSha256" to JsonPrimitive(scopeSha),
                            "shardId" to JsonPrimitive(shard),
                            "units" to JsonArray(units),
                        ),
                    ),
                ),
            )
            shard to inputSha
        }
        val run = JsonObject(
            mapOf(
                "bounds" to JsonObject(
                    mapOf(
                        "maximumResidentBytes" to wholeRunBounds["maximumResidentBytes"]!!,
                        "maximumShards" to JsonPrimitive(activeShards.size),
                        "maximumWorkers" to JsonPrimitive(1),
                        "perShardBytes" to perShardBounds["serializedBytes"]!!,
                        "perShardCpuSeconds" to perShardBounds["cpuSeconds"]!!,
                        "perShardEntities" to perShardBounds["entities"]!!,
                        "perShardSeconds" to perShardBounds["wallClockSeconds"]!!,
                        "wholeRunBytes" to wholeRunBounds["serializedBytes"]!!,
                        "wholeRunCpuSeconds" to wholeRunBounds["cpuSeconds"]!!,
                        "wholeRunEntities" to wholeRunBounds["entities"]!!,
                        "wholeRunSeconds" to wholeRunBounds["wallClockSeconds"]!!,
                    ),
                ),
                "id" to JsonPrimitive("full-tree-calls-${scopeSha.take(16)}"),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(inputs.map { (id, inputSha) ->
                    JsonObject(mapOf("id" to JsonPrimitive(id), "inputSha256" to JsonPrimitive(inputSha)))
                }),
            ),
        )
        val runBytes = canonical(run)
        writeBytes(callRoot.resolve("run.json"), runBytes)
        val runSha = sha(runBytes)
        val records = inputs.map { (id, inputSha) ->
            val outputPath = callRoot.resolve("outputs/$id.json")
            val outputBytes = Files.readAllBytes(outputPath)
            val calls = parseControlObject(outputPath).testArray("calls").size
            JsonObject(
                mapOf(
                    "entities" to JsonPrimitive(calls),
                    "inputSha256" to JsonPrimitive(inputSha),
                    "outputBytes" to JsonPrimitive(outputBytes.size),
                    "outputSha256" to JsonPrimitive(sha(outputBytes)),
                    "runSha256" to JsonPrimitive(runSha),
                    "schemaVersion" to JsonPrimitive(1),
                    "shardId" to JsonPrimitive(id),
                    "status" to JsonPrimitive("complete"),
                ),
            ).also { writeJson(callRoot.resolve("checkpoints/$id.json"), it) }
        }
        val leafDigest = MessageDigest.getInstance("SHA-256").apply {
            update("bounded-shards-v1\u0000".toByteArray(StandardCharsets.UTF_8))
            records.forEach { update(MessageDigest.getInstance("SHA-256").digest(canonical(it))) }
        }.digest().hex()
        val index = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to JsonObject(
                    mapOf(
                        "entities" to JsonPrimitive(records.sumOf { it.testLong("entities") }),
                        "serializedBytes" to JsonPrimitive(records.sumOf { it.testLong("outputBytes") }),
                        "shards" to JsonPrimitive(records.size),
                    ),
                ),
                "indexSha256" to JsonPrimitive(leafDigest),
                "runSha256" to JsonPrimitive(runSha),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(records),
            ),
        )
        writeJson(callRoot.resolve("index.json"), index)
        writeExecutionEvidence(index, records, inputs)
    }

    private fun writeExecutionEvidence(
        index: JsonObject,
        records: List<JsonObject>,
        inputs: List<Pair<String, String>>,
    ) {
        val usages = records.zip(inputs).map { (record, input) ->
            JsonObject(
                mapOf(
                    "entities" to record["entities"]!!,
                    "id" to JsonPrimitive(input.first),
                    "inputSha256" to JsonPrimitive(input.second),
                    "maximumResidentBytes" to JsonPrimitive(1024),
                    "outputSha256" to record["outputSha256"]!!,
                    "serializedBytes" to record["outputBytes"]!!,
                    "systemCpuSeconds" to JsonPrimitive(0.0),
                    "userCpuSeconds" to JsonPrimitive(0.0),
                    "wallClockSeconds" to JsonPrimitive(0.0),
                ),
            ).also { writeJson(callRoot.resolve("usage/${input.first}.json"), it) }
        }
        val scopeBounds = parseControlObject(control.scope).testObject("bounds")
        val withoutHash = JsonObject(
            mapOf(
                "bounds" to scopeBounds,
                "environment" to JsonObject(
                    mapOf("platform" to JsonPrimitive("test"), "python" to JsonPrimitive("compatibility-only")),
                ),
                "indexSha256" to index["indexSha256"]!!,
                "observed" to JsonObject(
                    mapOf(
                        "entities" to JsonPrimitive(usages.sumOf { it.testLong("entities") }),
                        "maximumResidentBytes" to JsonPrimitive(1024),
                        "serializedBytes" to JsonPrimitive(usages.sumOf { it.testLong("serializedBytes") }),
                        "systemCpuSeconds" to JsonPrimitive(0.0),
                        "userCpuSeconds" to JsonPrimitive(0.0),
                        "wallClockSeconds" to JsonPrimitive(0.0),
                    ),
                ),
                "runSha256" to index["runSha256"]!!,
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(usages),
            ),
        )
        writeJson(
            callRoot.resolve("execution-evidence.json"),
            JsonObject(withoutHash.toMutableMap().apply {
                this["evidenceSha256"] = JsonPrimitive(sha(canonical(withoutHash)))
            }),
        )
    }

    private fun writeCallDocument(shardId: String, calls: List<JsonObject>) {
        val sorted = calls.sortedBy { it.testString("id") }
        val shard = inventory.testArray("shards").map { it as JsonObject }
            .single { it.testString("id") == shardId }
        val unitIds = shard.testArray("unitIds").map { (it as JsonPrimitive).content }
        val scope = parseControlObject(control.scope)
        val scopeSha = sha(Files.readAllBytes(control.scope))
        val richSha = scope.testObject("oracle").testString("richArtifactSha256")
        val unitsById = inventory.testArray("units").map { it as JsonObject }.associateBy { it.testString("id") }
        val units = unitIds.map(unitsById::getValue)
        val input = sha(
            canonical(
                JsonObject(
                    mapOf(
                        "inventoryIndexSha256" to JsonPrimitive(inventory.testString("indexSha256")),
                        "producerConfigurationSha256" to JsonPrimitive(CALL_OBSERVATION_CONFIGURATION),
                        "richArtifactSha256" to JsonPrimitive(richSha),
                        "scopeSha256" to JsonPrimitive(scopeSha),
                        "shardId" to JsonPrimitive(shardId),
                        "units" to JsonArray(units),
                    ),
                ),
            ),
        )
        writeJson(
            callRoot.resolve("outputs/$shardId.json"),
            JsonObject(
                mapOf(
                    "calls" to JsonArray(sorted),
                    "counts" to JsonObject(
                        mapOf(
                            "observedCallSites" to JsonPrimitive(sorted.size),
                            "scannedDies" to JsonPrimitive(sorted.size + 1),
                            "scored" to JsonPrimitive(sorted.count { it.testString("population") == "scored" }),
                            "units" to JsonPrimitive(unitIds.size),
                            "unobservable" to JsonPrimitive(sorted.count { it.testString("population") == "unobservable" }),
                        ),
                    ),
                    "oracle" to JsonObject(
                        mapOf(
                            "configurationSha256" to JsonPrimitive(CALL_OBSERVATION_CONFIGURATION),
                            "inventoryIndexSha256" to JsonPrimitive(inventory.testString("indexSha256")),
                            "richArtifactSha256" to JsonPrimitive(richSha),
                            "scopeSha256" to JsonPrimitive(scopeSha),
                        ),
                    ),
                    "schemaVersion" to JsonPrimitive(1),
                    "shard" to JsonObject(
                        mapOf("id" to JsonPrimitive(shardId), "inputSha256" to JsonPrimitive(input)),
                    ),
                ),
            ),
        )
    }

    companion object {
        fun create(root: Path): CallAssessmentFixture {
            root.createDirectories()
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
            val control = createFullTreeControlFixture(root.resolve("controls"))
            val inventory = threeShardInventory(control)
            writeControlObject(control.inventory, inventory)
            val elf = root.resolve("elf-functions.json")
            writeJson(elf, elfIndex(parseControlObject(control.scope), inventory))
            val functionRoot = root.resolve("function-truth")
            writeFunctionTruth(functionRoot, parseControlObject(control.scope), inventory, sha(Files.readAllBytes(elf)))
            val callRoot = root.resolve("call-observations")
            listOf(callRoot, callRoot.resolve("outputs"), callRoot.resolve("checkpoints"), callRoot.resolve("control"), callRoot.resolve("usage")).forEach {
                it.createDirectories()
                Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
            }
            Files.copy(control.scope, callRoot.resolve("control/scope.json"))
            Files.copy(control.inventory, callRoot.resolve("control/inventory.json"))
            Files.setPosixFilePermissions(callRoot.resolve("control/scope.json"), PosixFilePermissions.fromString("rw-r--r--"))
            Files.setPosixFilePermissions(callRoot.resolve("control/inventory.json"), PosixFilePermissions.fromString("rw-r--r--"))
            val fixture = CallAssessmentFixture(control, inventory, functionRoot, elf, callRoot)
            fixture.writeInitialCalls()
            fixture.writeCallRun(SHARDS)
            return fixture
        }
    }

    private fun writeInitialCalls() {
        val shardUnits = inventory.testArray("shards").map { it as JsonObject }.associate { shard ->
            shard.testString("id") to (shard.testArray("unitIds").single() as JsonPrimitive).content
        }
        val direct = target("direct-internal", "direct", "function-rva-0x20", listOf("target"))
        val clang = listOf(
            call(shardUnits.getValue("clang-lib-driver"), "0x201", "0x10", "0x14", direct),
            call(shardUnits.getValue("clang-lib-driver"), "0x202", "0x10", "0x15", target("external-unresolved", "direct", aliases = listOf("puts@plt"))),
            call(shardUnits.getValue("clang-lib-driver"), "0x203", "0x10", "0x16", target("external-unresolved", "direct", aliases = listOf("mystery"))),
            call(shardUnits.getValue("clang-lib-driver"), "0x204", "0x10", "0x17", target("external-unresolved", "direct", aliases = listOf("ambiguous"))),
        )
        val generated = listOf(
            call(shardUnits.getValue("generated-tools-clang"), "0x301", "0x10", "0x14", direct),
            call(shardUnits.getValue("generated-tools-clang"), "0x302", "0x20", "0x24", target("indirect-proven", "indirect-proven", proven = listOf("function-rva-0x10", "function-rva-0x30"))),
            call(shardUnits.getValue("generated-tools-clang"), "0x303", "0x20", "0x25", target("indirect-unresolved", "indirect-unresolved")),
            call(shardUnits.getValue("generated-tools-clang"), "0x304", "0x20", "0x26", target("direct-internal", "direct", "function-rva-0x10", listOf("caller"))),
        )
        val llvm = listOf(
            call(shardUnits.getValue("llvm-lib-ir"), "0x401", "0x30", "0x34", target("virtual-unresolved", "virtual-unresolved", aliases = listOf("virtual"))),
            call(shardUnits.getValue("llvm-lib-ir"), "0x402", "0x30", "0x35", target("direct-internal", "direct", "function-rva-0x30", listOf("_ZThn8_thunk")), tail = true),
            call(shardUnits.getValue("llvm-lib-ir"), "0x403", null, null, target("indirect-unresolved", "indirect-unresolved"), reason = "call-site-no-address"),
        )
        writeCallDocument("clang-lib-driver", clang)
        writeCallDocument("generated-tools-clang", generated)
        writeCallDocument("llvm-lib-ir", llvm)
    }
}

private fun threeShardInventory(control: FullTreeControlFixture): JsonObject {
    val original = parseControlObject(control.inventory)
    val existing = original.testArray("units").map { it as JsonObject }
    val sourcePath = "source/llvm/lib/IR/third.cpp"
    val third = JsonObject(existing.last().toMutableMap().apply {
        this["dwarfOffset"] = JsonPrimitive("0x100")
        this["id"] = JsonPrimitive(FullTreeInventoryControl.compilationUnitId(sourcePath))
        this["rawPathSha256"] = JsonPrimitive(sha("/fixture/source-tree/llvm/lib/IR/third.cpp".toByteArray()))
        this["shardId"] = JsonPrimitive("llvm-lib-ir")
        this["sourcePath"] = JsonPrimitive(sourcePath)
    })
    val units = (existing + third).sortedWith(compareBy(FULL_TREE_CODE_POINT_ORDER) { it.testString("sourcePath") })
    val shards = units.groupBy { it.testString("shardId") }.toSortedMap(FULL_TREE_CODE_POINT_ORDER).map { (id, records) ->
        JsonObject(
            mapOf(
                "id" to JsonPrimitive(id),
                "unitIds" to JsonArray(records.map { JsonPrimitive(it.testString("id")) }.sortedBy { it.content }),
            ),
        )
    }
    val indexDigest = MessageDigest.getInstance("SHA-256").apply {
        update("full-tree-index-v1\u0000".toByteArray(StandardCharsets.UTF_8))
        units.forEach { update(MessageDigest.getInstance("SHA-256").digest(canonical(it))) }
    }.digest().hex()
    return JsonObject(
        original.toMutableMap().apply {
            this["counts"] = JsonObject(
                mapOf(
                    "compilationUnits" to JsonPrimitive(3),
                    "generatedUnits" to JsonPrimitive(1),
                    "handwrittenUnits" to JsonPrimitive(2),
                    "shards" to JsonPrimitive(3),
                ),
            )
            this["indexSha256"] = JsonPrimitive(indexDigest)
            this["shards"] = JsonArray(shards)
            this["units"] = JsonArray(units)
        },
    )
}

private fun elfIndex(scope: JsonObject, inventory: JsonObject): JsonObject {
    fun alias(name: String, rva: String) = JsonObject(
        mapOf(
            "availability" to JsonObject(mapOf("rich" to JsonPrimitive("surviving"), "stripped" to JsonPrimitive("surviving"))),
            "evidence" to JsonArray(listOf(JsonObject(mapOf("kind" to JsonPrimitive("elf-symbol"), "locator" to JsonPrimitive("sym:$rva:$name"))))),
            "name" to JsonPrimitive(name),
        ),
    )
    val functions = listOf("0x10" to "caller", "0x20" to "target", "0x30" to "_ZThn8_thunk").map { (rva, name) ->
        JsonObject(mapOf("aliases" to JsonArray(listOf(alias(name, rva))), "id" to JsonPrimitive("function-rva-$rva"), "rva" to JsonPrimitive(rva)))
    }
    val external = JsonObject(
        mapOf(
            "availability" to JsonObject(mapOf("rich" to JsonPrimitive("surviving"), "stripped" to JsonPrimitive("surviving"))),
            "evidence" to JsonArray(listOf(JsonObject(mapOf("kind" to JsonPrimitive("elf-symbol"), "locator" to JsonPrimitive("dyn:puts@plt"))))),
            "name" to JsonPrimitive("puts@plt"),
        ),
    )
    val scopeOracle = scope.testObject("oracle")
    return JsonObject(
        mapOf(
            "artifacts" to JsonObject(
                mapOf(
                    "rich" to JsonObject(mapOf("inputSha256" to scopeOracle["richArtifactSha256"]!!, "scannedSymbols" to JsonPrimitive(4), "sizeBytes" to JsonPrimitive(100))),
                    "stripped" to JsonObject(mapOf("inputSha256" to scopeOracle["strippedArtifactSha256"]!!, "scannedSymbols" to JsonPrimitive(4), "sizeBytes" to JsonPrimitive(80))),
                ),
            ),
            "counts" to JsonObject(mapOf("aliases" to JsonPrimitive(3), "externalFunctions" to JsonPrimitive(1), "functionRvas" to JsonPrimitive(3), "strippedFunctionRvas" to JsonPrimitive(3))),
            "externalFunctions" to JsonArray(listOf(external)),
            "functions" to JsonArray(functions),
            "image" to JsonObject(
                mapOf(
                    "elfType" to JsonPrimitive("ET_DYN"),
                    "executableRanges" to JsonArray(listOf(JsonObject(mapOf("endExclusive" to JsonPrimitive("0x100"), "start" to JsonPrimitive("0x0"))))),
                    "imageBase" to JsonPrimitive("0x0"),
                ),
            ),
            "oracle" to JsonObject(
                mapOf(
                    "configurationSha256" to JsonPrimitive(FullTreeElfFunctionsSqlite.configurationSha256),
                    "inventoryIndexSha256" to inventory["indexSha256"]!!,
                    "scopeSha256" to JsonPrimitive(sha(canonical(scope))),
                ),
            ),
            "schemaVersion" to JsonPrimitive(1),
        ),
    )
}

private fun writeFunctionTruth(root: Path, scope: JsonObject, inventory: JsonObject, elfSha: String) {
    root.createDirectories()
    root.resolve("shards").createDirectories()
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    Files.setPosixFilePermissions(root.resolve("shards"), PosixFilePermissions.fromString("rwx------"))
    val oracle = JsonObject(
        mapOf(
            "configurationSha256" to JsonPrimitive(FUNCTION_TRUTH_CONFIGURATION),
            "elfIndexSha256" to JsonPrimitive(elfSha),
            "inventoryIndexSha256" to inventory["indexSha256"]!!,
            "observationIndexSha256" to JsonPrimitive("a".repeat(64)),
            "scopeSha256" to JsonPrimitive(sha(canonical(scope))),
        ),
    )
    val shardRecords = inventory.testArray("shards").map { it as JsonObject }.mapIndexed { index, shard ->
        val id = shard.testString("id")
        val unitId = (shard.testArray("unitIds").single() as JsonPrimitive).content
        val (rva, names) = when (id) {
            "clang-lib-driver" -> "0x10" to listOf("caller")
            "generated-tools-clang" -> "0x20" to listOf("ambiguous", "target")
            else -> "0x30" to listOf("_ZThn8_thunk", "ambiguous")
        }
        val function = functionRecord(rva, unitId, names, index)
        val document = JsonObject(
            mapOf(
                "counts" to JsonObject(mapOf("functions" to JsonPrimitive(1), "nonEmitted" to JsonPrimitive(0))),
                "functions" to JsonArray(listOf(function)),
                "nonEmitted" to JsonArray(emptyList()),
                "oracle" to oracle,
                "schemaVersion" to JsonPrimitive(1),
                "shard" to shard,
            ),
        )
        val bytes = canonical(document)
        writeBytes(root.resolve("shards/$id.json"), bytes)
        JsonObject(
            mapOf(
                "bytes" to JsonPrimitive(bytes.size),
                "functions" to JsonPrimitive(1),
                "id" to JsonPrimitive(id),
                "nonEmitted" to JsonPrimitive(0),
                "path" to JsonPrimitive("shards/$id.json"),
                "sha256" to JsonPrimitive(sha(bytes)),
            ),
        )
    }
    val exclusionDocument = JsonObject(
        mapOf(
            "functions" to JsonArray(emptyList()),
            "oracle" to oracle,
            "reasonCode" to JsonPrimitive("elf-no-source-aligned-dwarf"),
            "schemaVersion" to JsonPrimitive(1),
        ),
    )
    val exclusionBytes = canonical(exclusionDocument)
    writeBytes(root.resolve("exclusions.json"), exclusionBytes)
    val withoutHash = JsonObject(
        mapOf(
            "complete" to JsonPrimitive(true),
            "counts" to JsonObject(
                mapOf(
                    "coalescedEmittedRvas" to JsonPrimitive(0),
                    "definitionNoRangeUnique" to JsonPrimitive(0),
                    "dwarfOnlyRvas" to JsonPrimitive(0),
                    "dwarfRvas" to JsonPrimitive(3),
                    "elfOnlyRvas" to JsonPrimitive(0),
                    "elfRvas" to JsonPrimitive(3),
                    "inlineOnlyUnique" to JsonPrimitive(0),
                    "nonEmittedObservations" to JsonPrimitive(0),
                    "nonEmittedUnique" to JsonPrimitive(0),
                    "scoredRvas" to JsonPrimitive(3),
                    "selectedElsewhereUnique" to JsonPrimitive(0),
                ),
            ),
            "exclusions" to JsonObject(
                mapOf(
                    "bytes" to JsonPrimitive(exclusionBytes.size),
                    "functions" to JsonPrimitive(0),
                    "id" to JsonPrimitive("elf-only-exclusions"),
                    "nonEmitted" to JsonPrimitive(0),
                    "path" to JsonPrimitive("exclusions.json"),
                    "sha256" to JsonPrimitive(sha(exclusionBytes)),
                ),
            ),
            "oracle" to oracle,
            "schemaVersion" to JsonPrimitive(1),
            "shards" to JsonArray(shardRecords),
        ),
    )
    writeJson(
        root.resolve("index.json"),
        JsonObject(withoutHash.toMutableMap().apply { this["indexSha256"] = JsonPrimitive(sha(canonical(withoutHash))) }),
    )
}

private fun functionRecord(rva: String, unitId: String, names: List<String>, index: Int): JsonObject {
    val aliases = names.sorted().map { name ->
        JsonObject(
            mapOf(
                "evidence" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "kind" to JsonPrimitive("dwarf-subprogram"),
                                "locator" to JsonPrimitive("$unitId:0x${index + 1}"),
                                "unitId" to JsonPrimitive(unitId),
                            ),
                        ),
                    ),
                ),
                "name" to JsonPrimitive(name),
            ),
        )
    }
    return JsonObject(
        mapOf(
            "aliases" to JsonArray(aliases),
            "declarations" to JsonArray(
                listOf(
                    JsonObject(
                        mapOf(
                            "column" to JsonPrimitive(1),
                            "externalPathSha256" to JsonNull,
                            "fileIndex" to JsonPrimitive(1),
                            "line" to JsonPrimitive(index + 1),
                            "sourcePath" to JsonPrimitive("source/test-$index.cpp"),
                            "unitSourcePath" to JsonPrimitive("source/test-$index.cpp"),
                        ),
                    ),
                ),
            ),
            "emissionKind" to JsonPrimitive("single-definition"),
            "entityKind" to JsonPrimitive(if (names.any { it.startsWith("_ZT") }) "thunk" else "function"),
            "id" to JsonPrimitive("function-rva-$rva"),
            "ownerUnitId" to JsonPrimitive(unitId),
            "ownershipCandidates" to JsonArray(listOf(JsonPrimitive(unitId))),
            "population" to JsonPrimitive("scored"),
            "reasonCode" to JsonNull,
            "rva" to JsonPrimitive(rva),
        ),
    )
}

private fun target(
    kind: String,
    dispatch: String,
    functionId: String? = null,
    aliases: List<String> = emptyList(),
    proven: List<String> = emptyList(),
): JsonObject = JsonObject(
    mapOf(
        "aliases" to JsonArray(aliases.sorted().map(::JsonPrimitive)),
        "dispatchKind" to JsonPrimitive(dispatch),
        "functionId" to (functionId?.let(::JsonPrimitive) ?: JsonNull),
        "kind" to JsonPrimitive(kind),
        "originDieOffset" to if (kind in setOf("direct-internal", "external-unresolved", "virtual-unresolved")) JsonPrimitive("0x1") else JsonNull,
        "provenFunctionIds" to JsonArray(proven.sorted().map(::JsonPrimitive)),
        "targetEvidence" to JsonPrimitive(if (kind == "indirect-proven") "call-target-expression" else "none"),
    ),
)

private fun call(
    unitId: String,
    die: String,
    callerRva: String?,
    returnPc: String?,
    target: JsonObject,
    tail: Boolean = false,
    reason: String? = null,
): JsonObject {
    val callerId = callerRva?.let { "function-rva-$it" }
    val local = if (callerRva != null && returnPc != null) {
        "0x${(returnPc.substring(2).toULong(16) - callerRva.substring(2).toULong(16)).toString(16)}"
    } else {
        null
    }
    val identity = JsonObject(
        mapOf(
            "caller" to (callerRva?.let(::JsonPrimitive) ?: JsonNull),
            "die" to JsonPrimitive(die),
            "return" to (returnPc?.let(::JsonPrimitive) ?: JsonNull),
            "unit" to JsonPrimitive(unitId),
        ),
    )
    return JsonObject(
        mapOf(
            "callerId" to (callerId?.let(::JsonPrimitive) ?: JsonNull),
            "callerLocalReturnOffset" to (local?.let(::JsonPrimitive) ?: JsonNull),
            "dieOffset" to JsonPrimitive(die),
            "id" to JsonPrimitive("call-${sha(canonical(identity)).take(32)}"),
            "population" to JsonPrimitive(if (reason == null) "scored" else "unobservable"),
            "reasonCode" to (reason?.let(::JsonPrimitive) ?: JsonNull),
            "returnPcRva" to (returnPc?.let(::JsonPrimitive) ?: JsonNull),
            "tailCall" to JsonPrimitive(tail),
            "target" to target,
            "unitId" to JsonPrimitive(unitId),
        ),
    )
}

private fun callWithCaller(call: JsonObject, callerRva: String, local: String, returnPc: String): JsonObject {
    val unit = call.testString("unitId")
    val die = call.testString("dieOffset")
    val identity = JsonObject(
        mapOf(
            "caller" to JsonPrimitive(callerRva),
            "die" to JsonPrimitive(die),
            "return" to JsonPrimitive(returnPc),
            "unit" to JsonPrimitive(unit),
        ),
    )
    return JsonObject(call.toMutableMap().apply {
        this["callerId"] = JsonPrimitive("function-rva-$callerRva")
        this["callerLocalReturnOffset"] = JsonPrimitive(local)
        this["id"] = JsonPrimitive("call-${sha(canonical(identity)).take(32)}")
        this["returnPcRva"] = JsonPrimitive(returnPc)
    })
}

private fun replaceTarget(call: JsonObject, change: (JsonObject) -> JsonObject): JsonObject =
    JsonObject(call.toMutableMap().apply { this["target"] = change(call.testObject("target")) })

private fun writeJson(path: Path, document: JsonObject) = writeBytes(path, canonical(document))

private fun writeBytes(path: Path, bytes: ByteArray) {
    path.parent.createDirectories()
    Files.setPosixFilePermissions(path.parent, PosixFilePermissions.fromString("rwx------"))
    Files.write(path, bytes)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-r--r--"))
}

private fun canonical(value: JsonObject): ByteArray = OracleJson.canonicalBytes(value, controlJsonLimits(64 * 1024 * 1024))
private fun sha(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)
private fun externalId(name: String): String = "external-function-${sha(name.toByteArray()).take(32)}"
private fun ByteArray.hex(): String = joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
private fun JsonObject.testObject(name: String): JsonObject = this[name] as JsonObject
private fun JsonObject.testArray(name: String): JsonArray = this[name] as JsonArray
private fun JsonObject.testString(name: String): String = (this[name] as JsonPrimitive).content
private fun JsonObject.testNullableString(name: String): String? = if (this[name] == JsonNull) null else testString(name)
private fun JsonObject.testLong(name: String): Long = (this[name] as JsonPrimitive).content.toLong()

private const val CALL_OBSERVATION_CONFIGURATION = "7723b7ff5908661f0c64a80a90a8a8e88d5147bdca524b21e5d1092f77b0826f"
private const val FUNCTION_TRUTH_CONFIGURATION = "17c61e43524b98a215075b82fa50732d6d8f50d883dce235e511731612da04e5"
private val SHARDS = listOf("clang-lib-driver", "generated-tools-clang", "llvm-lib-ir")
