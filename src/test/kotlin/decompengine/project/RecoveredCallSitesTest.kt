package decompengine.project

import decompengine.oracle.core.OracleJson
import io.github.optimumcode.json.schema.JsonSchema
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class RecoveredCallSitesTest {
    private val bindings = RecoveredCallSiteBindings("1".repeat(64), "2".repeat(64), "3".repeat(64), "4".repeat(64))

    @Test
    fun `versioned sidecar retains repeated sites physical targets and unresolved computed flow`() = withTemporaryRoot { root ->
        val document = document(listOf(
            site("0x100", "0x100", physical = "0x200", targets = listOf("0x200")),
            site("0x100", "0x105", physical = "0x200", targets = listOf("0x200")),
            site("0x100", "0x10a", kind = "indirect-call", bytes = "ffd0", returnPc = "0x10c"),
            site("0x100", "0x10c", kind = "direct-tail-call", physical = "0x300", returnPc = null),
            site("0x200", "0x200", kind = "indirect-jump", bytes = "ffe0", returnPc = null),
        ))
        val calls = mutableListOf<RecoveredCallSite>()
        val receipt = read(root, document, consume = calls::add)
        val schemaText = checkNotNull(javaClass.getResourceAsStream("/project/recovered-call-sites-v1.schema.json"))
            .use { it.readBytes().decodeToString() }
        val schema = JsonSchema.fromDefinition(schemaText)
        assertTrue(schema.validate(document) {})
        assertFalse(schema.validate(JsonObject(document + ("extra" to JsonNull))) {})
        assertEquals(5L, receipt.sites)
        assertEquals(2, calls.count { it.physicalTargetRva == 0x200UL })
        assertEquals(listOf(0UL, 5UL, 10UL, 12UL, 0UL), calls.map { it.callerLocalInstructionOffset })
        assertEquals("function-rva-0x100", calls.first().callerId)
        assertEquals(emptyList(), calls[2].recoveredTargetRvas)
        assertEquals(null, calls[3].returnPcRva)
        assertEquals(bindings, receipt.bindings)
        assertFalse(receipt.authoritativeOracleEvidence)
        assertFalse(receipt.recoveredModelScored)
    }

    @Test
    fun `candidate ordering is unsigned and image address arithmetic cannot wrap`() = withTemporaryRoot { root ->
        val ordered = document(listOf(
            site("0x7ffffffffffffffe", "0x7ffffffffffffffe", bytes = "ffd0", returnPc = "0x8000000000000000"),
            site("0x8000000000000000", "0x8000000000000000", bytes = "ffd0", returnPc = "0x8000000000000002"),
        ))
        assertEquals(2L, read(root, ordered).sites)
        assertFailsWith<IllegalArgumentException> {
            read(root, JsonObject(ordered + ("imageBaseAddress" to JsonPrimitive("0x8000000000000000"))))
        }
        assertFailsWith<IllegalArgumentException> {
            read(root, document(listOf(site("0xffffffffffffffff", "0xffffffffffffffff", returnPc = "0x4"))))
        }
    }

    @Test
    fun `closed candidate grammar rejects contradictory fields duplicate sites and target overflow`() = withTemporaryRoot { root ->
        val valid = site("0x100", "0x100")
        val mutations = listOf(
            JsonObject(valid + ("extra" to JsonNull)),
            JsonObject(valid + ("callerRva" to JsonPrimitive(256))),
            JsonObject(valid + ("instructionRva" to JsonPrimitive("0x0100"))),
            JsonObject(valid + ("instructionBytes" to JsonPrimitive("e8".repeat(16)))),
            JsonObject(valid + ("flowKind" to JsonPrimitive("direct-name-only"))),
            JsonObject(valid + ("returnPcRva" to JsonPrimitive("0x106"))),
            site("0x100", "0x100", kind = "indirect-call", physical = "0x200"),
            site("0x100", "0x100", kind = "direct-tail-call", returnPc = null),
            site("0x100", "0x100", kind = "indirect-jump"),
            site("0x100", "0x100", targets = listOf("0x200", "0x200")),
            site("0x100", "0x100", targets = listOf("0x300", "0x200")),
            site("0x100", "0x100", targets = (1..17).map { "0x${(0x200 + it).toString(16)}" }),
        )
        mutations.forEach { mutation ->
            assertFailsWith<IllegalArgumentException> { read(root, document(listOf(mutation))) }
        }
        assertFailsWith<IllegalArgumentException> { read(root, document(listOf(valid, valid))) }
        assertFailsWith<IllegalArgumentException> {
            read(root, document(listOf(site("0x200", "0x200"), valid)))
        }
    }

    @Test
    fun `bindings canonical bytes and resource limits are checked even for rehashed candidates`() = withTemporaryRoot { root ->
        val value = document(listOf(site("0x100", "0x100"), site("0x100", "0x105")))
        for (field in listOf("inputSha256", "programModelSha256", "exporterSha256", "analysisToolSha256")) {
            assertFailsWith<IllegalArgumentException> {
                read(root, JsonObject(value + (field to JsonPrimitive("a".repeat(64)))))
            }
        }
        assertFailsWith<IllegalArgumentException> { read(root, JsonObject(value + ("schemaVersion" to JsonPrimitive(2)))) }
        assertFailsWith<IllegalArgumentException> { read(root, value, RecoveredCallSiteLimits(maximumSites = 1)) }
        assertFailsWith<IllegalArgumentException> { read(root, value, RecoveredCallSiteLimits(maximumInputBytes = 32)) }
        assertFailsWith<IllegalStateException> {
            read(root, value, RecoveredCallSiteLimits(maximumWallClock = Duration.ofNanos(1)))
        }
        val bytes = OracleJson.canonicalBytes(value)
        for (nonCanonical in listOf(
            " " + bytes.toString(Charsets.UTF_8),
            bytes.toString(Charsets.UTF_8).replace("\"schemaVersion\": 1", "\"schemaVersion\": 1,\"schemaVersion\": 1"),
        )) {
            val path = root.resolve("candidate.json")
            Files.writeString(path, nonCanonical)
            assertFailsWith<IllegalArgumentException> {
                RecoveredCallSites.read(path, sha256(nonCanonical.toByteArray()), bindings) {}
            }
        }
    }

    @Test
    fun `artifact digest unsafe paths and caller lowered target limits fail closed`() = withTemporaryRoot { root ->
        val value = document(listOf(site("0x100", "0x100", targets = listOf("0x200", "0x300"))))
        val bytes = OracleJson.canonicalBytes(value)
        val path = root.resolve("candidate.json")
        Files.write(path, bytes)
        assertFailsWith<IllegalArgumentException> {
            RecoveredCallSites.read(path, "f".repeat(64), bindings) {}
        }
        assertFailsWith<IllegalArgumentException> {
            RecoveredCallSites.read(path, sha256(bytes), bindings, RecoveredCallSiteLimits(maximumTargetsPerSite = 1)) {}
        }
        val link = Files.createSymbolicLink(root.resolve("linked.json"), path)
        assertFailsWith<IllegalArgumentException> { RecoveredCallSites.read(link, sha256(bytes), bindings) {} }
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-rw----"))
        assertFailsWith<IllegalArgumentException> { RecoveredCallSites.read(path, sha256(bytes), bindings) {} }
    }

    @Test
    fun `callbacks remain speculative until final authentication and interruption is preserved`() = withTemporaryRoot { root ->
        val value = document(listOf(site("0x100", "0x100")))
        var observed = 0
        assertFailsWith<IllegalArgumentException> {
            read(root, JsonObject(value + ("schemaVersion" to JsonPrimitive(2)))) { observed++ }
        }
        assertEquals(1, observed)
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<IllegalStateException> { read(root, value) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
    }

    @Test
    fun `real static Ghidra export preserves repeated direct indirect and tail sites beside schema one model`() =
        withTemporaryRoot { root ->
            assumeTrue(System.getenv("RUN_REAL_GHIDRA_CALL_SITES") == "true", "real Ghidra call-site fixture is opt-in")
            val home = Path.of(checkNotNull(System.getenv("GHIDRA_HOME")))
            val source = root.resolve("calls.s")
            Files.writeString(source, """
                .text
                .globl _start
                .type _start,@function
                _start:
                    call worker
                    call worker
                    lea worker(%rip), %rax
                    call *%rax
                    jmp tail
                .size _start, .-_start
                .type worker,@function
                worker:
                    ret
                .size worker, .-worker
                .type tail,@function
                tail:
                    jmp worker
                .size tail, .-tail
                .section .note.GNU-stack,"",@progbits
            """.trimIndent() + "\n")
            val binary = root.resolve("calls")
            runTool(root, listOf("cc", "-nostdlib", "-no-pie", "-Wl,--build-id=none", "-o", binary.toString(), source.toString()))
            val analyzer = GhidraHeadlessProgramModelAnalyzer(home, recoveryMode = GhidraProgramModelRecoveryMode.PLANNING)
            val first = analyzer.analyzeWithCallSites(binary, root.resolve("first"))
            val second = analyzer.analyzeWithCallSites(binary, root.resolve("second"))
            assertEquals(1, first.programModel.schemaVersion)
            assertEquals(first.programModel.toJson(), second.programModel.toJson())
            assertEquals(first.callSites.artifactSha256, second.callSites.artifactSha256)
            assertEquals(sha256(Files.readAllBytes(binary)), first.callSites.bindings.inputSha256)
            val calls = mutableListOf<RecoveredCallSite>()
            RecoveredCallSites.read(first.callSites.path, first.callSites.artifactSha256, first.callSites.bindings, consume = calls::add)
            val entry = first.programModel.functions.single { it.name == "_start" }
            val worker = first.programModel.functions.single { it.name == "worker" }
            val entryRva = entry.address - first.callSites.imageBaseAddress
            val workerRva = worker.address - first.callSites.imageBaseAddress
            val repeated = calls.filter { it.callerRva == entryRva && it.flowKind == "direct-call" }
            assertEquals(2, repeated.size, calls.toString())
            assertEquals(listOf(workerRva, workerRva), repeated.map { it.physicalTargetRva })
            assertNotEquals(repeated[0].instructionRva, repeated[1].instructionRva)
            assertTrue(calls.any { it.callerRva == entryRva && it.flowKind == "indirect-call" && it.physicalTargetRva == null })
            assertEquals(2, calls.count { it.flowKind == "direct-tail-call" && it.returnPcRva == null })
            assertTrue(calls.all { it.instructionBytes.length in 2..30 })
            val unchanged = Files.readAllBytes(first.callSites.path)
            assertFailsWith<IllegalArgumentException> { analyzer.analyzeWithCallSites(binary, root.resolve("first")) }
            assertTrue(unchanged.contentEquals(Files.readAllBytes(first.callSites.path)))
        }

    private fun site(
        caller: String,
        instruction: String,
        kind: String = "direct-call",
        bytes: String = "e800000000",
        physical: String? = null,
        targets: List<String> = emptyList(),
        returnPc: String? = "0x${(instruction.substring(2).toULong(16) + (bytes.length / 2).toULong()).toString(16)}",
    ): JsonObject = JsonObject(mapOf(
        "callerRva" to JsonPrimitive(caller), "flowKind" to JsonPrimitive(kind),
        "instructionBytes" to JsonPrimitive(bytes), "instructionRva" to JsonPrimitive(instruction),
        "physicalTargetRva" to (physical?.let(::JsonPrimitive) ?: JsonNull),
        "recoveredTargetRvas" to JsonArray(targets.map(::JsonPrimitive)),
        "returnPcRva" to (returnPc?.let(::JsonPrimitive) ?: JsonNull),
    ))

    private fun document(sites: List<JsonObject>): JsonObject = JsonObject(mapOf(
        "analysisToolSha256" to JsonPrimitive(bindings.analysisToolSha256), "calls" to JsonArray(sites),
        "exporterSha256" to JsonPrimitive(bindings.exporterSha256), "imageBaseAddress" to JsonPrimitive("0x0"),
        "inputSha256" to JsonPrimitive(bindings.inputSha256), "programModelSha256" to JsonPrimitive(bindings.programModelSha256),
        "schemaVersion" to JsonPrimitive(1),
    ))

    private fun read(
        root: Path,
        value: JsonObject,
        limits: RecoveredCallSiteLimits = RecoveredCallSiteLimits(),
        consume: (RecoveredCallSite) -> Unit = {},
    ): RecoveredCallSiteReceipt {
        val bytes = OracleJson.canonicalBytes(value)
        val path = root.resolve("candidate.json")
        Files.write(path, bytes)
        return RecoveredCallSites.read(path, sha256(bytes), bindings, limits, consume)
    }

    private fun runTool(root: Path, arguments: List<String>) {
        val log = root.resolve("compiler.log")
        val process = ProcessBuilder(arguments).redirectErrorStream(true).redirectOutput(log.toFile()).start()
        try {
            assertTrue(process.waitFor(30L, TimeUnit.SECONDS), "fixture compilation timed out")
            assertEquals(0, process.exitValue(), Files.readString(log))
        } finally {
            if (process.isAlive) process.destroyForcibly()
        }
    }

    private fun <Result> withTemporaryRoot(action: (Path) -> Result): Result {
        val root = Files.createTempDirectory("recovered-call-sites-")
        try {
            return action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
