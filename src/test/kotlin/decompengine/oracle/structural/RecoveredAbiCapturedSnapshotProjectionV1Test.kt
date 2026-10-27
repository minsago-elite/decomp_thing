package decompengine.oracle.structural

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.oracle.gcc.GccBundledFullExportSnapshot
import decompengine.oracle.gcc.GccBundledInferredInterfaceSnapshot
import decompengine.oracle.gcc.GccBundledInterfaceAddressSpaceIdentityV1
import decompengine.oracle.gcc.GccBundledInterfaceCaptureBindingsV1
import decompengine.oracle.gcc.GccBundledInterfaceTargetEvidenceV1
import decompengine.project.InferredInterfaceFixture
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlinx.serialization.json.*

/** Authored immutable snapshot bytes exercise revalidation, not factory ownership or admission. */
class RecoveredAbiCapturedSnapshotProjectionV1Test {
    private val target = StructuralRecoveryV1Inputs.loadTargetAbi(Path.of("src/test/resources/oracle/structural-v1/target-abi.json"))
    private val zero = RecoveredAbiInterfaceCandidateProjectionLimitsV1(maximumNativeFunctions = 2, maximumParameters = 0)

    @Test
    fun `snapshot entry point accepts zero parameters and retains formal return candidates at zero limit`() {
        val fixture = InferredInterfaceFixture
        var document = fixture.fixture()
        var function = fixture.function(1)
        function = fixture.set(function, JsonArray(emptyList()), "parameters")
        for (name in listOf("parameterCount", "localSymbolParameterCount")) {
            function = fixture.set(function, JsonPrimitive(0), "prototype", name)
        }
        document = fixture.set(document, JsonArray(document.getValue("records").jsonArray.take(6) + function), "records")
        for ((name, value) in mapOf("parameters" to 0, "storageVarnodes" to 1, "roots" to 3,
            "graphNodes" to 2, "graphEdges" to 0, "graphWork" to 12)) {
            document = fixture.set(document, JsonPrimitive(value), "summary", name)
        }
        for ((name, value) in mapOf("pointerSize" to 8, "pointerShift" to 0, "charSize" to 1, "shortSize" to 2,
            "integerSize" to 4, "longSize" to 8, "longLongSize" to 8, "floatSize" to 4, "doubleSize" to 8)) {
            document = fixture.set(document, JsonPrimitive(value), "dataOrganization", name)
        }
        val snapshot = snapshot(document)
        assertEquals(0L, snapshot.summary.listing.scan.parameters)
        assertEquals(0L, snapshot.summary.scan.parameters)
        val projected = RecoveredAbiInterfaceCandidateProjectionV1.projectCapturedSnapshot(snapshot, target, zero).document
        val matched = projected.getValue("candidateEntities").jsonArray.map { it.jsonObject }
            .single { it.getValue("facts").jsonArray.any { fact ->
                fact.jsonObject["dimension"] == JsonPrimitive("function.return-abi-class") &&
                    fact.jsonObject["state"] == JsonPrimitive("recovered")
            } }
        val returned = matched.getValue("facts").jsonArray.map { it.jsonObject }
            .single { it["dimension"] == JsonPrimitive("function.return-abi-class") }
        assertEquals(listOf("INTEGER"), returned.getValue("value").jsonObject.getValue("abi").jsonObject
            .getValue("classes").jsonArray.map { it.jsonPrimitive.content })
        assertEquals("untrusted-component-candidate", projected.getValue("scope").jsonPrimitive.content)
    }

    @Test
    fun `minimum raw validator capacity does not relax the zero projection parameter limit`() {
        val snapshot = snapshot(InferredInterfaceFixture.fixture())
        assertEquals(1L, snapshot.summary.scan.parameters)
        // One parameter is admitted by raw revalidation, then rejected by exact projection limits.
        val failure = assertFailsWith<IllegalArgumentException> {
            RecoveredAbiInterfaceCandidateProjectionV1.projectCapturedSnapshot(snapshot, target, zero)
        }
        assertEquals("HighFunction parameter population exceeds its fixed bound", failure.message)
    }

    private fun snapshot(document: JsonObject): GccBundledInferredInterfaceSnapshot {
        val fixture = InferredInterfaceFixture
        val bytes = fixture.bytes(document)
        val summary = fixture.assess(document)
        val binding = summary.listing.bindings
        val digest = "a".repeat(64)
        val model = GccBundledFullExportSnapshot(binding.inputSha256, 1, binding.programModelExporterSha256, 1,
            binding.ghidraArchiveSha256, 1, binding.languageId, binding.compilerSpecId, digest, digest,
            binding.programModelSha256, fixture.model.size.toLong(), 2, 2, 0, 0, 0, digest, 1,
            fixture.model.size.toLong(), fixture.model, byteArrayOf())
        return GccBundledInferredInterfaceSnapshot(model, summary,
            GccBundledInterfaceTargetEvidenceV1(digest, "x86_64-linux-gnu", binding.inputSha256, 1, 0uL,
                binding.languageId, binding.compilerSpecId,
                GccBundledInterfaceAddressSpaceIdentityV1("ram", 1, 64, 1, false, false), emptyList()),
            GccBundledInterfaceCaptureBindingsV1(binding.collectorSha256, summary.bindings.collectorSha256,
                summary.bindings.typeGraphSha256, summary.bindings.wrapperSha256, summary.bindings.nativeDecompilerSha256,
                digest, digest, digest),
            LinuxFileIdentity(LinuxFileKey(1, 1), 0, 0, 0, 1, 1, false, true, false),
            "authored-fixture", emptyMap(), emptyMap(),
            (fixture.model.size + fixture.listingManifest().size + fixture.listingBytes.size + fixture.manifest(bytes).size + bytes.size).toLong(),
            fixture.listingManifest(), fixture.listingBytes, fixture.manifest(bytes), bytes,
            byteArrayOf(), byteArrayOf(), byteArrayOf())
    }
}
