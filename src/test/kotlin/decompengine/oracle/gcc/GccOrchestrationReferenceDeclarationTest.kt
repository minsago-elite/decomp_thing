package decompengine.oracle.gcc

import decompengine.oracle.behavior.LlvmBehaviorNativeOciImageV2
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.reference.ReferenceNativeRuntime
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Assumptions.assumeTrue

class GccOrchestrationReferenceDeclarationTest {
    @Test
    fun `compiled inputs bind all fourteen declarations without treating four recorded outputs as mounted executables`() {
        GccMetadataReferenceProfile.open(profileRoot).use { profile ->
            val contract = profile.registeredInput("orchestration-contract", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES)
            val reference = profile.registeredInput("orchestration-reference", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES)
            val parsed = GccOrchestrationReferenceDeclaration.validateDocuments(contract, reference)
            assertEquals(14, parsed.contract.getValue("cases").jsonArray.size)
            assertEquals(4, parsed.contract.getValue("cases").jsonArray.count { "producedProgram" in it.jsonObject })
            assertEquals(7, parsed.contract.getValue("phaseStartupDependencies").jsonObject.size)
            assertEquals(parsed.runtimeFiles.map { it.path }.sorted().distinct(), parsed.runtimeFiles.map { it.path })
            assertTrue(parsed.runtimeFiles.any { it.path == "/oracle/install/bin/gcc" })
            assertTrue(parsed.runtimeFiles.any { it.path == "/usr/bin/as" && it.resolvedPath == "/usr/bin/x86_64-linux-gnu-as" })
            assertTrue(parsed.runtimeFiles.any { it.path == "/lib64/ld-linux-x86-64.so.2" })
            assertFalse(parsed.runtimeFiles.any { it.path.startsWith("/w/") })
            // Pure description validation has no admitted owner and publishes no authority receipt.
            assertFalse("declarationAuthenticated" in parsed.contract)
        }
    }

    @Test
    fun `registered input access rejects unknown oversized and closed reads and returns independent bytes`() {
        val profile = GccMetadataReferenceProfile.open(profileRoot)
        try {
            val first = profile.registeredInput("orchestration-contract", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES)
            val original = first.copyOf()
            first[0] = 0
            assertContentEquals(original, profile.registeredInput("orchestration-contract", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES))
            assertFails { profile.registeredInput("caller-authorized", 1024) }
            assertFails { profile.registeredInput("orchestration-reference", 512 * 1024) }
            assertFails { profile.registeredInput("orchestration-contract", 0) }
        } finally { profile.close() }
        assertFails { profile.registeredInput("orchestration-contract", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES) }
    }

    @Test
    fun `case population invocation environment and independently fixed reference cannot drift`() {
        val contract = contract()
        val cases = contract.getValue("cases").jsonArray
        val first = cases[0].jsonObject
        val invocation = first.getValue("driverInvocation").jsonObject
        val attacks = listOf(
            JsonObject(contract + ("cases" to JsonArray(cases.dropLast(1)))),
            JsonObject(contract + ("cases" to JsonArray(cases.reversed()))),
            JsonObject(contract + ("cases" to JsonArray(cases.dropLast(1) + cases[0]))),
            replaceCase(contract, JsonObject(first + ("driverInvocation" to JsonObject(invocation +
                ("argv" to JsonArray(listOf(JsonPrimitive("/host/compiler"), JsonPrimitive("-S"), JsonPrimitive("source.c")))))))),
            replaceCase(contract, JsonObject(first + ("driverInvocation" to JsonObject(invocation +
                ("environment" to JsonObject(invocation.getValue("environment").jsonObject + ("LD_PRELOAD" to JsonPrimitive("/host.so")))))))),
            JsonObject(contract + ("unexpected" to JsonPrimitive(true))),
        )
        attacks.forEach { assertFails { check(it, referenceBytes()) } }
        assertFails { check(contract, referenceBytes() + byteArrayOf(10)) }
        assertFails { GccOrchestrationReferenceDeclaration.validateDocuments(OracleJson.canonicalBytes(contract) + byteArrayOf(10), referenceBytes()) }
    }

    @Test
    fun `rehashed reference metadata still cannot substitute raw command transcripts or argument policy`() {
        val original = contract()
        val reference = reference()
        val cases = reference.getValue("cases").jsonArray.toMutableList()
        val first = cases[0].jsonObject
        val observed = first.getValue("observed").jsonObject
        val plan = observed.getValue("plan").jsonObject
        val phases = plan.getValue("phases").jsonArray.toMutableList()
        val phase = phases[0].jsonObject
        phases[0] = JsonObject(phase + ("argv" to JsonArray(phase.getValue("argv").jsonArray + JsonPrimitive("-changed"))))
        val changedObservation = JsonObject(observed + ("plan" to JsonObject(plan + ("phases" to JsonArray(phases)))))
        cases[0] = JsonObject(first + ("observed" to changedObservation))
        val changedReference = OracleJson.canonicalBytes(JsonObject(reference + ("cases" to JsonArray(cases))))
        val changedContract = rebindReference(original, changedReference, changedObservation)
        assertFails { check(changedContract, changedReference) }
        val policy = original.getValue("invocationPolicy").jsonObject
        assertFails { check(JsonObject(original + ("invocationPolicy" to JsonObject(policy +
            ("argumentEquivalence" to JsonObject(mapOf("all" to JsonPrimitive("ignore every argument"))))))), referenceBytes()) }
    }

    @Test
    fun `phase verbosity is positional and failures only permit a nonempty planned prefix`() {
        val reference = reference()
        val tools = reference.getValue("toolchain").jsonObject.getValue("phaseTools").jsonObject
        val observed = reference.getValue("cases").jsonArray[1].jsonObject.getValue("observed").jsonObject
        val planned = observed.getValue("plan").jsonObject.getValue("phases").jsonArray.map { it.jsonObject }
        val traced = observed.getValue("executedPhases").jsonObject.getValue("phases").jsonArray.map { it.jsonObject }
        GccOrchestrationReferenceDeclaration.validatePhases(planned, traced, tools, false)
        GccOrchestrationReferenceDeclaration.validatePhases(planned, traced.take(1), tools, true)
        assertFails { GccOrchestrationReferenceDeclaration.validatePhases(planned, traced.take(1), tools, false) }
        assertFails { GccOrchestrationReferenceDeclaration.validatePhases(planned, emptyList(), tools, true) }
        val argv = traced[0].getValue("argv").jsonArray.toMutableList()
        val verbose = argv.removeAt(argv.indexOf(JsonPrimitive("-v")))
        argv.add(verbose)
        val changed = listOf(JsonObject(traced[0] + ("argv" to JsonArray(argv)))) + traced.drop(1)
        assertFails { GccOrchestrationReferenceDeclaration.validatePhases(planned, changed, tools, false) }
    }

    @Test
    fun `startup closure changes and produced output substitutions cannot be reclassified as image files`() {
        val contract = contract()
        val closures = contract.getValue("phaseStartupDependencies").jsonObject
        val path = "/usr/bin/as"
        val closure = closures.getValue(path).jsonObject
        val elf = closure.getValue("elf").jsonObject
        val changed = JsonObject(closure + ("elf" to JsonObject(elf + ("resolvedPath" to JsonPrimitive("/host/as")))))
        assertFails { check(JsonObject(contract + ("phaseStartupDependencies" to JsonObject(closures + (path to changed)))), referenceBytes()) }
        val cases = contract.getValue("cases").jsonArray.toMutableList()
        val linked = cases[6].jsonObject
        val produced = linked.getValue("producedProgram").jsonObject
        val runtime = produced.getValue("startupDependencies").jsonObject
        cases[6] = JsonObject(linked + ("producedProgram" to JsonObject(produced + ("startupDependencies" to
            JsonObject(runtime + ("elf" to elf))))))
        assertFails { check(JsonObject(contract + ("cases" to JsonArray(cases))), referenceBytes()) }
    }

    @Test
    fun `retained shell words are parsed as data with quotes escapes and no execution`() {
        assertEquals(listOf("tool", "a b", "c d", "", "literal;$(no-execution)", "a\\q"),
            GccOrchestrationReferenceDeclaration.shellWords("tool 'a b' \"c d\" '' 'literal;$(no-execution)' \"a\\q\""))
        assertEquals(listOf("a b", "c"), GccOrchestrationReferenceDeclaration.shellWords("a\\ b c"))
        assertFails { GccOrchestrationReferenceDeclaration.shellWords("tool 'unfinished") }
        assertFails { GccOrchestrationReferenceDeclaration.shellWords("tool trailing\\") }
    }

    @Test
    fun `real pinned image contains every declared selected phase and startup file`() {
        val configured = System.getenv("DECOMP_REFERENCE_NATIVE_REAL_OCI").orEmpty()
        assumeTrue(configured.isNotEmpty(), "set DECOMP_REFERENCE_NATIVE_REAL_OCI to check actual image declaration bindings")
        GccMetadataReferenceProfile.open(profileRoot).use { profile ->
            val description = GccOrchestrationReferenceDeclaration.validateDocuments(
                profile.registeredInput("orchestration-contract", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES),
                profile.registeredInput("orchestration-reference", GccOrchestrationReferenceDeclaration.MAXIMUM_BYTES))
            LlvmBehaviorNativeOciImageV2.openLayout(Path.of(configured)).use { image ->
                val plan = ReferenceNativeRuntime.plan(image, profile.nativeRuntimeSelection, profile.originalArtifacts)
                ReferenceNativeRuntime.verifyDeclaredFiles(plan, profile.originalArtifacts, description.runtimeFiles)
                assertTrue(description.runtimeFiles.size > 10)
                image.requireCurrent()
                profile.requireCurrent("actual image declaration checks")
            }
        }
        // This is transport validation only; there is no admitted runtime and no declaration receipt.
    }

    private fun contract() = OracleJson.parse(Files.readAllBytes(profileRoot.resolve("orchestration-identity-contract.json"))).jsonObject
    private fun referenceBytes() = Files.readAllBytes(profileRoot.resolve("orchestration-phase-reference.json"))
    private fun reference() = OracleJson.parse(referenceBytes()).jsonObject
    private fun check(contract: JsonObject, reference: ByteArray) = GccOrchestrationReferenceDeclaration.validateDocuments(OracleJson.canonicalBytes(contract), reference)
    private fun replaceCase(contract: JsonObject, first: JsonObject) = JsonObject(contract +
        ("cases" to JsonArray(listOf(first) + contract.getValue("cases").jsonArray.drop(1))))
    private fun rebindReference(contract: JsonObject, bytes: ByteArray, firstObservation: JsonObject): JsonObject {
        val provenance = contract.getValue("provenance").jsonObject
        val reference = provenance.getValue("reference").jsonObject
        val rebound = JsonObject(contract + ("provenance" to JsonObject(provenance + ("reference" to JsonObject(reference + mapOf(
            "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes))))))))
        val first = rebound.getValue("cases").jsonArray[0].jsonObject
        return replaceCase(rebound, JsonObject(first + ("referenceObservationSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(firstObservation))))))
    }

    companion object { private val profileRoot = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize() }
}
