package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.nio.file.Path
import java.security.MessageDigest
import java.util.TreeMap
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GccCompilerEngineResumeEvidenceValidationTest {
    @Test
    fun `state-bound progress retains raw digest and rejects impossible prefix positions`() {
        val fixture = oneBatchFixture()
        val state = GccCompilerEngineResumeByteValidator.assessExporterState(fixture.state)
        val progress = GccCompilerEngineResumeByteValidator.assessExportProgress(fixture.state, fixture.progress)
        assertEquals("non-authoritative-byte-assessment", state.authority)
        assertEquals("non-authoritative-byte-assessment", progress.authority)
        assertEquals(fixture.progress.size, progress.artifactBytes)
        assertEquals(sha(fixture.progress), progress.artifactSha256)
        assertEquals(sha(fixture.state), progress.stateSha256)

        val impossible = listOf(
            progress(total = 3, completed = 2, partial = 1, failed = 1),
            progress(total = 2, completed = 2, recovered = 1, partial = 0, failed = 1),
            progress(total = 2, completed = 1, partial = 1, failed = 0),
            progress(total = 2, completed = 2, partial = 1, failed = 1, reused = 1),
        )
        impossible.forEach { bytes ->
            assertFailsWith<GccCompilerEngineResumeEvidenceException> {
                GccCompilerEngineResumeByteValidator.assessExportProgress(fixture.state, bytes)
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExportProgress(
                fixture.state,
                progress(phase = "publishing", total = 2, completed = 2, partial = 1, failed = 1),
            )
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExporterState(
                fixture.state.decodeToString().replace("\"recoveryMode\":\"planning\"", "\"recoveryMode\":\"full\"")
                    .toByteArray(),
            )
        }
        val twoBatches = twoBatchFixture()
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExportProgress(twoBatches.state, fixture.progress)
        }
        val alignedButIncompleteComplete = progress(
            total = 513,
            completed = 512,
            partial = 512,
            failed = 0,
        )
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessExportProgress(
                twoBatches.state,
                alignedButIncompleteComplete,
            )
        }
        val planningZero = progress(
            phase = "planning",
            total = 2,
            completed = 0,
            partial = 0,
            failed = 0,
        )
        GccCompilerEngineResumeByteValidator.assessExportProgress(fixture.state, planningZero)
    }

    @Test
    fun `one-shot raw run reproduces inventory commitments semantics and framed model`() {
        val fixture = oneBatchFixture()
        val result = assess(fixture)
        assertEquals("non-authoritative-byte-assessment", result.authority)
        assertEquals(2L, result.functionCount)
        assertEquals(1L, result.planningBatchCount)
        assertEquals(fixture.inventorySha256, result.inventorySha256)
        assertEquals(fixture.semantic.canonicalBytes, result.semanticCanonicalBytes)
        assertEquals(fixture.semantic.sha256, result.semanticSha256)
        assertEquals(fixture.batchCommitmentSha256, result.batchCommitmentSha256)
        assertEquals(1L, result.partial)
        assertEquals(1L, result.failed)
        assertEquals(fixture.model.size, result.programModelBytes)
        assertEquals(sha(fixture.model), result.programModelSha256)
    }

    @Test
    fun `assessment objects are never accepted as authority or copy tokens`() {
        val assessmentClasses = listOf(
            GccExporterStateAssessment::class.java,
            GccExportProgressAssessment::class.java,
            GccCompletedRunAssessment::class.java,
        )
        assessmentClasses.forEach { type ->
            assertFalse(type.declaredMethods.any { it.name == "copy" || it.name.startsWith("component") })
        }
        GccCompilerEngineResumeByteValidator::class.java.declaredMethods.forEach { method ->
            assertFalse(method.parameterTypes.any { parameter -> parameter in assessmentClasses })
        }
        assertFailsWith<ClassNotFoundException> {
            Class.forName("decompengine.oracle.gcc.GccExporterStateSummary")
        }
        assertFailsWith<ClassNotFoundException> {
            Class.forName("decompengine.oracle.gcc.GccPlanningBatchSummary")
        }
        assertFalse(
            GccCompilerEngineResumeByteValidator::class.java.declaredMethods.any {
                Modifier.isPublic(it.modifiers) && it.name.contains("validateAssembledModel")
            },
        )
        val bytecode = (assessmentClasses + GccCompilerEngineResumeByteValidator::class.java)
            .joinToString("\n", transform = ::javap)
        assertFalse(bytecode.contains("GccExporterStateSummary"))
        assertFalse(bytecode.contains("GccPlanningBatchSummary"))
        assertFalse(bytecode.contains("validateAssembledModel"))
        assertFalse(bytecode.lineSequence().any { line -> line.contains(" copy(") })
    }

    @Test
    fun `raw function fragments reject arbitrary bytes reordering and swapped embedded IDs`() {
        val fixture = oneBatchFixture()
        assertRejected(fixture.copy(batches = listOf(fixture.batches.single().withFunctions("not-json".toByteArray()))))

        val records = fixture.specs.single().functions.map { it.bytes }
        val reordered = fragment(records.reversed())
        assertRejected(fixture.copy(batches = listOf(fixture.batches.single().withFunctions(reordered))))

        val firstId = fixture.specs.single().functions[0].id
        val secondId = fixture.specs.single().functions[1].id
        val swappedId = fixture.batches.single().functions.decodeToString()
            .replaceFirst("\"id\": \"$firstId\"", "\"id\": \"$secondId\"")
            .toByteArray()
        assertRejected(fixture.copy(batches = listOf(fixture.batches.single().withFunctions(swappedId))))
    }

    @Test
    fun `evidence fragments reject arbitrary bytes and checkpoint embedded ID drift`() {
        val fixture = oneBatchFixture()
        val batch = fixture.batches.single()
        assertRejected(fixture.copy(batches = listOf(batch.withGlobals("not-json".toByteArray()))))
        assertRejected(fixture.copy(batches = listOf(batch.withTypes("not-json".toByteArray()))))

        val globalId = fixture.specs.single().globals.single().id
        val wrongGlobal = globalId(2)
        val globalDrift = batch.globals.decodeToString().replace(globalId, wrongGlobal).toByteArray()
        assertRejected(fixture.copy(batches = listOf(batch.withGlobals(globalDrift))))

        val typeId = fixture.specs.single().types.single().id
        val wrongType = typeId(2)
        val typeDrift = batch.types.decodeToString().replace(typeId, wrongType).toByteArray()
        assertRejected(fixture.copy(batches = listOf(batch.withTypes(typeDrift))))

        val failureId = fixture.specs.single().failures.single().id
        val wrongFailure = fixture.specs.single().functions.first().id
        val failureDrift = batch.failures.decodeToString().replace(failureId, wrongFailure).toByteArray()
        assertRejected(fixture.copy(batches = listOf(batch.withFailures(failureDrift))))
    }

    @Test
    fun `full run rejects reordered batches and duplicate cross-batch first owners`() {
        val fixture = twoBatchFixture()
        val valid = assess(fixture)
        assertEquals(2L, valid.planningBatchCount)
        assertEquals(513L, valid.functionCount)
        assertRejected(fixture.copy(batches = fixture.batches.reversed()))

        assertRejected(twoBatchFixture(duplicateGlobalOwner = true))
        assertRejected(twoBatchFixture(duplicateTypeOwner = true))
    }

    @Test
    fun `state inventory commitment and semantic drift all fail independently`() {
        val base = oneBatchFixture()
        val stateMismatch = base.state.decodeToString().replace(SHA_B, SHA_F).toByteArray()
        assertRejected(base.copy(state = stateMismatch))

        assertRejected(oneBatchFixture(inventoryOverride = SHA_F))
        assertRejected(oneBatchFixture(batchCommitmentOverride = SHA_F))
        assertRejected(oneBatchFixture(semanticShaOverride = SHA_F))
        assertRejected(oneBatchFixture(semanticBytesOverride = base.semantic.canonicalBytes + 1L))
    }

    @Test
    fun `raw capture is detached from caller mutation and run-wide bytes are charged`() {
        val fixture = oneBatchFixture()
        val result = assess(fixture)
        val expectedState = result.stateSha256
        val expectedProgress = result.progressSha256
        val expectedModel = result.programModelSha256

        fixture.state.fill(0)
        fixture.progress.fill(0)
        fixture.model.fill(0)
        fixture.batches.forEach { batch ->
            batch.checkpoint.fill(0)
            batch.functions.fill(0)
            batch.globals.fill(0)
            batch.types.fill(0)
            batch.failures.fill(0)
        }
        assertEquals(expectedState, result.stateSha256)
        assertEquals(expectedProgress, result.progressSha256)
        assertEquals(expectedModel, result.programModelSha256)

        val fresh = oneBatchFixture()
        val retained = fresh.batches.sumOf { batch ->
            batch.checkpoint.size.toLong() + batch.functions.size + batch.globals.size +
                batch.types.size + batch.failures.size
        }
        assess(fresh, GccResumeByteValidationLimits(aggregateFragmentBytes = retained))
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assess(fresh, GccResumeByteValidationLimits(aggregateFragmentBytes = retained - 1L))
        }

        val batch = fresh.batches.single()
        var hasNextCalls = 0
        var nextCalls = 0
        val unboundedIterator = object : AbstractList<GccPlanningBatchBytes>() {
            override val size: Int = 1
            override fun get(index: Int): GccPlanningBatchBytes = batch
            override fun iterator(): Iterator<GccPlanningBatchBytes> = object : Iterator<GccPlanningBatchBytes> {
                override fun hasNext(): Boolean {
                    hasNextCalls++
                    return true
                }

                override fun next(): GccPlanningBatchBytes {
                    nextCalls++
                    return batch
                }
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fresh.state,
                fresh.progress,
                unboundedIterator,
                fresh.model,
            )
        }
        assertEquals(257, hasNextCalls)
        assertEquals(256, nextCalls)

        val declaredCountDrift = object : AbstractList<GccPlanningBatchBytes>() {
            override val size: Int = 1
            override fun get(index: Int): GccPlanningBatchBytes = batch
            override fun iterator(): Iterator<GccPlanningBatchBytes> = listOf(batch, batch).iterator()
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fresh.state,
                fresh.progress,
                declaredCountDrift,
                fresh.model,
            )
        }
    }

    @Test
    fun `pre-decode and final framing limits remain fail closed`() {
        val invalidUtf8 = byteArrayOf(0x80.toByte(), 0x80.toByte())
        assertByteBoundFailure("exporter state") {
            GccCompilerEngineResumeByteValidator.assessExporterState(
                invalidUtf8,
                GccResumeByteValidationLimits(exporterStateBytes = 1),
            )
        }
        val fixture = oneBatchFixture()
        assertByteBoundFailure("export progress") {
            GccCompilerEngineResumeByteValidator.assessExportProgress(
                fixture.state,
                invalidUtf8,
                GccResumeByteValidationLimits(progressBytes = 1),
            )
        }
        val valid = fixture.batches.single()
        assertByteBoundFailure("planning checkpoint") {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fixture.state,
                fixture.progress,
                listOf(GccPlanningBatchBytes(invalidUtf8, valid.functions, valid.globals, valid.types, valid.failures)),
                fixture.model,
                GccResumeByteValidationLimits(checkpointBytes = 1),
            )
        }
        val fragmentCases = listOf(
            "function fragment" to GccPlanningBatchBytes(valid.checkpoint, invalidUtf8, byteArrayOf(), byteArrayOf(), byteArrayOf()),
            "global fragment" to GccPlanningBatchBytes(valid.checkpoint, byteArrayOf('x'.code.toByte()), invalidUtf8, byteArrayOf(), byteArrayOf()),
            "type fragment" to GccPlanningBatchBytes(valid.checkpoint, byteArrayOf('x'.code.toByte()), byteArrayOf(), invalidUtf8, byteArrayOf()),
            "failure fragment" to GccPlanningBatchBytes(valid.checkpoint, byteArrayOf('x'.code.toByte()), byteArrayOf(), byteArrayOf(), invalidUtf8),
        )
        fragmentCases.forEach { (label, batch) ->
            assertByteBoundFailure(label) {
                GccCompilerEngineResumeByteValidator.assessCompletedRun(
                    fixture.state,
                    fixture.progress,
                    listOf(batch),
                    fixture.model,
                    GccResumeByteValidationLimits(planningFragmentBytes = 1),
                )
            }
        }
        assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            assess(fixture, GccResumeByteValidationLimits(assembledModelBytes = fixture.model.size - 1))
        }
        val truncatedModel = fixture.model.copyOf(fixture.model.size - 1)
        val framingFailure = assertFailsWith<GccCompilerEngineResumeEvidenceException> {
            GccCompilerEngineResumeByteValidator.assessCompletedRun(
                fixture.state,
                fixture.progress,
                fixture.batches,
                truncatedModel,
                GccResumeByteValidationLimits(assembledModelBytes = truncatedModel.size),
            )
        }
        assertTrue(framingFailure.message?.contains("framing exceeds") == true)
    }

    private fun assess(
        fixture: RunFixture,
        limits: GccResumeByteValidationLimits = GccResumeByteValidationLimits(),
    ): GccCompletedRunAssessment = GccCompilerEngineResumeByteValidator.assessCompletedRun(
        fixture.state,
        fixture.progress,
        fixture.batches,
        fixture.model,
        limits,
    )

    private fun assertRejected(fixture: RunFixture) {
        assertFailsWith<GccCompilerEngineResumeEvidenceException> { assess(fixture) }
    }

    private fun assertByteBoundFailure(label: String, operation: () -> Unit) {
        val failure = assertFailsWith<GccCompilerEngineResumeEvidenceException>(block = operation)
        assertTrue(failure.message?.contains(label) == true)
        assertTrue(failure.message?.contains("byte bound") == true)
    }

    private fun oneBatchFixture(
        inventoryOverride: String? = null,
        batchCommitmentOverride: String? = null,
        semanticShaOverride: String? = null,
        semanticBytesOverride: Long? = null,
    ): RunFixture {
        val globalId = globalId(1)
        val typeId = typeId(1)
        val first = function(functionId(0), "first", "partial", referencedGlobals = listOf(globalId))
        val second = function(functionId(1), "second", "failed")
        val spec = BatchSpec(
            functions = listOf(first, second),
            globals = listOf(record(globalId, globalRecord(globalId, "counter"))),
            types = listOf(record(typeId, typeRecord(typeId, "typedef int value_t;"))),
            failures = listOf(record(second.id, failureRecord(second.id, "decompilation failed"))),
        )
        return buildFixture(
            listOf(spec),
            inventoryOverride,
            batchCommitmentOverride,
            semanticShaOverride,
            semanticBytesOverride,
        )
    }

    private fun twoBatchFixture(
        duplicateGlobalOwner: Boolean = false,
        duplicateTypeOwner: Boolean = false,
    ): RunFixture {
        val global = record(globalId(1), globalRecord(globalId(1), "shared"))
        val type = record(typeId(1), typeRecord(typeId(1), "typedef int shared_t;"))
        val firstFunctions = (0 until 512).map { index -> function(functionId(index), "function_$index", "partial") }
        val secondFunction = function(functionId(512), "last", "partial")
        return buildFixture(
            listOf(
                BatchSpec(firstFunctions, globals = listOf(global), types = listOf(type)),
                BatchSpec(
                    listOf(secondFunction),
                    globals = if (duplicateGlobalOwner) listOf(global) else emptyList(),
                    types = if (duplicateTypeOwner) listOf(type) else emptyList(),
                ),
            ),
        )
    }

    private fun buildFixture(
        specs: List<BatchSpec>,
        inventoryOverride: String? = null,
        batchCommitmentOverride: String? = null,
        semanticShaOverride: String? = null,
        semanticBytesOverride: Long? = null,
    ): RunFixture {
        val rawFragments = specs.map { spec ->
            RawFragments(
                functions = fragment(spec.functions.map { it.bytes }),
                globals = fragment(spec.globals.map { it.bytes }),
                types = fragment(spec.types.map { it.bytes }),
                failures = fragment(spec.failures.map { it.bytes }),
            )
        }
        val allFunctions = specs.flatMap { it.functions }
        val inventory = inventoryOverride ?: sha(
            (allFunctions.joinToString("\n") { it.id } + "\n").toByteArray(),
        )
        val commitment = batchCommitmentOverride ?: batchCommitment(specs, rawFragments)
        val semantic = semanticBinding(specs)
        val state = state(
            functionCount = allFunctions.size,
            planningBatchCount = specs.size,
            canonicalBytes = semanticBytesOverride ?: semantic.canonicalBytes,
            semanticSha256 = semanticShaOverride ?: semantic.sha256,
            batchCommitmentSha256 = commitment,
        )
        val stateSha = sha(state)
        var start = 0
        val batches = specs.zip(rawFragments).map { (spec, raw) ->
            val end = start + spec.functions.size
            val checkpoint = checkpoint(stateSha, inventory, start, end, spec, raw)
            start = end
            GccPlanningBatchBytes(checkpoint, raw.functions, raw.globals, raw.types, raw.failures)
        }
        val partial = allFunctions.count { it.status == "partial" }.toLong()
        val failed = allFunctions.count { it.status == "failed" }.toLong()
        val progress = progress(
            total = allFunctions.size.toLong(),
            completed = allFunctions.size.toLong(),
            partial = partial,
            failed = failed,
        )
        val globals = TreeMap<String, Record>()
        val types = TreeMap<String, Record>()
        specs.forEach { spec ->
            spec.globals.forEach { globals.putIfAbsent(it.id, it) }
            spec.types.forEach { types.putIfAbsent(it.id, it) }
        }
        val model = model(allFunctions.map { it.bytes }, globals.values.map { it.bytes }, types.values.map { it.bytes })
        return RunFixture(state, progress, batches, model, specs, inventory, semantic, commitment)
    }

    private fun checkpoint(
        stateSha: String,
        inventorySha: String,
        start: Int,
        end: Int,
        spec: BatchSpec,
        raw: RawFragments,
    ): ByteArray = buildString {
        val partial = spec.functions.count { it.status == "partial" }
        val failed = spec.functions.count { it.status == "failed" }
        append("schemaVersion=1\n")
        append("exporterVersion=9\n")
        append("recoveryMode=planning\n")
        append("stateSha256=$stateSha\n")
        append("inventorySha256=$inventorySha\n")
        append("startIndex=$start\n")
        append("endExclusive=$end\n")
        appendFragment("function", raw.functions)
        append("recovered=0\npartial=$partial\nfailed=$failed\n")
        append("functionIds=${spec.functions.joinToString(",") { it.id }}\n")
        appendFragment("global", raw.globals)
        append("globalIds=${spec.globals.joinToString(",") { it.id }}\n")
        appendFragment("type", raw.types)
        append("typeIds=${spec.types.joinToString(",") { it.id }}\n")
        appendFragment("failure", raw.failures)
        append("failureIds=${spec.failures.joinToString(",") { it.id }}\n")
    }.toByteArray()

    private fun StringBuilder.appendFragment(prefix: String, bytes: ByteArray) {
        append("${prefix}FragmentBytes=${bytes.size}\n")
        append("${prefix}FragmentSha256=${sha(bytes)}\n")
    }

    private fun state(
        functionCount: Int,
        planningBatchCount: Int,
        canonicalBytes: Long,
        semanticSha256: String,
        batchCommitmentSha256: String,
    ): ByteArray = (
        "{\"schemaVersion\":2,\"exporterVersion\":9,\"exporterSha256\":\"$SHA_B\"," +
            "\"analysisToolSha256\":\"$SHA_C\",\"recoveryMode\":\"planning\"," +
            "\"inputSha256\":\"$SHA_A\",\"language\":\"x86:LE:64:default\",\"compilerSpec\":\"gcc\"," +
            "\"semanticStateBinding\":{\"schemaVersion\":1,\"scope\":\"planning-exporter-visible-program\"," +
            "\"functionCount\":$functionCount,\"planningBatchCount\":$planningBatchCount," +
            "\"canonicalBytes\":$canonicalBytes,\"sha256\":\"$semanticSha256\"," +
            "\"batchCommitmentSha256\":\"$batchCommitmentSha256\"}}\n"
        ).toByteArray()

    private fun progress(
        phase: String = "complete",
        total: Long,
        completed: Long,
        recovered: Long = 0,
        partial: Long,
        failed: Long,
        reused: Long = 0,
    ): ByteArray = (
        "{\"schemaVersion\":1,\"phase\":\"$phase\",\"completed\":$completed,\"total\":$total," +
            "\"recovered\":$recovered,\"partial\":$partial,\"failed\":$failed,\"reused\":$reused," +
            "\"currentFunction\":null}\n"
        ).toByteArray()

    private fun batchCommitment(specs: List<BatchSpec>, raw: List<RawFragments>): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update("decomp-thing/planning-batch-commitments/v1\n".toByteArray(StandardCharsets.US_ASCII))
        var start = 0L
        specs.zip(raw).forEach { (spec, fragments) ->
            val end = start + spec.functions.size
            updateLong(digest, start)
            updateLong(digest, end)
            listOf(fragments.functions, fragments.globals, fragments.types, fragments.failures).forEach { bytes ->
                updateLong(digest, bytes.size.toLong())
                digest.update(sha(bytes).toByteArray(StandardCharsets.US_ASCII))
            }
            start = end
        }
        return digest.digest().hex()
    }

    private fun semanticBinding(specs: List<BatchSpec>): Semantic {
        val digest = MessageDigest.getInstance("SHA-256")
        val domain = "decomp-thing/program-semantic-fingerprint/v1\n".toByteArray(StandardCharsets.US_ASCII)
        digest.update(domain)
        var bytes = domain.size.toLong()
        fun frame(tag: Byte, record: Record) {
            val id = record.id.toByteArray(StandardCharsets.UTF_8)
            digest.update(tag)
            updateLong(digest, id.size.toLong())
            digest.update(id)
            updateLong(digest, record.bytes.size.toLong())
            digest.update(record.bytes)
            bytes += 17L + id.size + record.bytes.size
        }
        specs.flatMap { it.functions }.forEach { frame(1, record(it.id, it.bytes)) }
        val failures = TreeMap<String, Record>()
        val globals = TreeMap<String, Record>()
        val types = TreeMap<String, Record>()
        specs.forEach { spec ->
            spec.failures.forEach { failures.putIfAbsent(it.id, it) }
            spec.globals.forEach { globals.putIfAbsent(it.id, it) }
            spec.types.forEach { types.putIfAbsent(it.id, it) }
        }
        failures.values.forEach { frame(4, it) }
        globals.values.forEach { frame(2, it) }
        types.values.forEach { frame(3, it) }
        frame(5, record("functions", specs.sumOf { it.functions.size }.toString().toByteArray()))
        return Semantic(bytes, digest.digest().hex())
    }

    private fun updateLong(digest: MessageDigest, value: Long) {
        for (shift in 56 downTo 0 step 8) digest.update((value ushr shift).toByte())
    }

    private fun function(
        id: String,
        name: String,
        status: String,
        referencedGlobals: List<String> = emptyList(),
    ): FunctionRecord = FunctionRecord(
        id,
        status,
        buildString {
            append("    {\n")
            append("      \"id\": \"$id\",\n")
            append("      \"name\": \"$name\",\n")
            append("      \"address\": \"${addressForId(id)}\",\n")
            append("      \"prototype\": \"void $name(void)\",\n")
            append("      \"status\": \"$status\",\n")
            append("      \"calls\": [],\n")
            append("      \"referencedGlobals\": [${quoted(referencedGlobals)}],\n")
            append("      \"strings\": [],\n")
            append("      \"decompiledC\": null\n")
            append("    }")
        }.toByteArray(),
    )

    private fun globalRecord(id: String, name: String): ByteArray = buildString {
        append("    {\n")
        append("      \"id\": \"$id\",\n")
        append("      \"name\": \"$name\",\n")
        append("      \"address\": \"${addressForId(id)}\",\n")
        append("      \"type\": \"int\",\n")
        append("      \"initializer\": null,\n")
        append("      \"status\": \"recovered\"\n")
        append("    }")
    }.toByteArray()

    private fun typeRecord(id: String, declaration: String): ByteArray = buildString {
        append("    {\n")
        append("      \"id\": \"$id\",\n")
        append("      \"declaration\": \"$declaration\",\n")
        append("      \"sourceAddress\": \"0x1\",\n")
        append("      \"status\": \"partial\"\n")
        append("    }")
    }.toByteArray()

    private fun failureRecord(id: String, message: String): ByteArray = buildString {
        append("    {\n")
        append("      \"id\": \"$id\",\n")
        append("      \"status\": \"failed\",\n")
        append("      \"message\": \"$message\"\n")
        append("    }")
    }.toByteArray()

    private fun model(functions: List<ByteArray>, globals: List<ByteArray>, types: List<ByteArray>): ByteArray =
        buildString {
            append("{\n  \"schemaVersion\": 1,\n  \"inputSha256\": \"$SHA_A\",\n  \"functions\": [\n")
            append(modelRecords(functions))
            append("  ],\n  \"globals\": [\n")
            append(modelRecords(globals))
            append("  ],\n  \"types\": [\n")
            append(modelRecords(types))
            append("  ]\n}\n")
        }.toByteArray()

    private fun fragment(records: List<ByteArray>): ByteArray =
        records.joinToString(",\n") { it.decodeToString() }.toByteArray()

    private fun modelRecords(records: List<ByteArray>): String =
        if (records.isEmpty()) "" else records.joinToString(",\n", postfix = "\n") { it.decodeToString() }

    private fun record(id: String, bytes: ByteArray) = Record(id, bytes)
    private fun sha(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)
    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it.toInt() and 0xff) }
    private fun quoted(values: List<String>) = values.joinToString(", ") { "\"$it\"" }
    private fun functionId(index: Int) = "fn_${index.toString(16).padStart(16, '0')}"
    private fun globalId(index: Int) = "global_${index.toString(16).padStart(16, '0')}"
    private fun typeId(index: Int) = "type_${index.toString(16).padStart(64, '0')}"
    private fun addressForId(id: String) = "0x${id.substringAfter('_').trimStart('0').ifEmpty { "0" }}"

    private data class Record(val id: String, val bytes: ByteArray)
    private data class FunctionRecord(val id: String, val status: String, val bytes: ByteArray)
    private data class BatchSpec(
        val functions: List<FunctionRecord>,
        val globals: List<Record> = emptyList(),
        val types: List<Record> = emptyList(),
        val failures: List<Record> = emptyList(),
    )
    private data class RawFragments(
        val functions: ByteArray,
        val globals: ByteArray,
        val types: ByteArray,
        val failures: ByteArray,
    )
    private data class Semantic(val canonicalBytes: Long, val sha256: String)
    private data class RunFixture(
        val state: ByteArray,
        val progress: ByteArray,
        val batches: List<GccPlanningBatchBytes>,
        val model: ByteArray,
        val specs: List<BatchSpec>,
        val inventorySha256: String,
        val semantic: Semantic,
        val batchCommitmentSha256: String,
    )

    private fun GccPlanningBatchBytes.withFunctions(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, replacement, globals, types, failures)

    private fun GccPlanningBatchBytes.withGlobals(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, functions, replacement, types, failures)

    private fun GccPlanningBatchBytes.withTypes(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, functions, globals, replacement, failures)

    private fun GccPlanningBatchBytes.withFailures(replacement: ByteArray) =
        GccPlanningBatchBytes(checkpoint, functions, globals, types, replacement)

    private fun javap(type: Class<*>): String {
        val executable = Path.of(System.getProperty("java.home"), "bin", "javap")
        val process = ProcessBuilder(
            executable.toString(),
            "-classpath",
            System.getProperty("java.class.path"),
            "-p",
            type.name,
        ).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader(StandardCharsets.UTF_8).use { it.readText() }
        assertTrue(process.waitFor(10, TimeUnit.SECONDS), "javap timed out")
        assertEquals(0, process.exitValue(), output)
        return output
    }

    private companion object {
        val SHA_A = "a".repeat(64)
        val SHA_B = "b".repeat(64)
        val SHA_C = "c".repeat(64)
        val SHA_F = "f".repeat(64)
    }
}
