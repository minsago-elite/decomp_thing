package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleArtifacts
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccDriverStructuralProfileTest {
    @Test
    fun `fixed profile authenticates GCC cc1 source build artifact identities target and image base`() {
        val profile = profile()

        assertEquals("gcc-cc1-16.2.0", profile.profileId)
        assertEquals("16.2.0", profile.version)
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", profile.sourceRevision)
        assertEquals("1bfd82a556302bdfbd78948cbbb0e6fe549c755a48c1ad3e56247ca7b9bbc301", profile.compilerEngineProfileSha256)
        assertEquals("dbef520c025d268f5126229ace8ad5b08a15722573d45b5e1ab934611905abb4", profile.artifactManifestSha256)
        assertEquals("ba9b2f314bfb3d92a172e67f8ce993a2e98b9bc14aabf00ff6d58e4631037621", profile.fullBinary.sha256)
        assertEquals("e51bf6e3f3300d31ce9713e2160c6fe5895d1e4914fb25562c3542b161427905", profile.strippedBinary.sha256)
        assertEquals("x86_64-sysv-amd64-v1", profile.targetAbi.id)
        assertEquals("sysv-amd64", profile.targetAbi.abi)
        assertEquals(62, profile.targetAbi.machine)
        assertEquals(3, profile.targetAbi.osAbi)
        assertEquals(64, profile.targetAbi.pointerBits)
        assertEquals("ELF64", profile.targetAbi.elfClass)
        assertEquals("little-endian", profile.targetAbi.dataEncoding)
        assertEquals("ET_EXEC", profile.strippedBinary.elfType)
        assertEquals("ET_EXEC", profile.targetAbi.elfType)
        assertEquals(0x400000UL, profile.imageBase)
        assertEquals(1, profile.executableRanges.size)
        assertEquals(0x366000UL, profile.executableRanges.single().startRva)
        assertEquals(0x1d4c4f5UL, profile.executableRanges.single().endExclusiveRva)
        assertEquals("0x400000", profile.inputBinary.imageBase)
        assertEquals(profile.strippedBinary.sha256, profile.inputBinary.sha256)
        assertEquals("15049e6609677a741412712e26f48fd4177e83cad7a872e8afb14d49e4758918",
            profile.inputBinary.executableRangesSha256)
    }

    @Test
    fun `manifest substitution that repeats expected binary hashes is rejected`() {
        val parent = Files.createTempDirectory("gcc-driver-structural-profile-")
        val root = Files.createDirectory(parent.resolve("16.2.0"))
        try {
            val original = OracleJson.parse(Files.readAllBytes(Path.of("oracle/gcc/16.2.0/compiler-engines.json")))
                .jsonObject
            val changedBenchmark = JsonObject(original.getValue("benchmark").jsonObject +
                ("id" to JsonPrimitive("attacker-profile")))
            Files.write(root.resolve("compiler-engines.json"), OracleJson.canonicalBytes(
                JsonObject(original + ("benchmark" to changedBenchmark)),
            ))

            val failure = assertFailsWith<GccDriverStructuralProfileException> {
                GccDriverStructuralInputsV1.load(root)
            }

            assertTrue(failure.message.orEmpty().contains("cannot authenticate"))
        } finally {
            Files.walk(parent).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    @Test
    fun `captured cc1 full export binds binary exporter loader target image base and executable addresses`() {
        val profile = profile()
        val modelBytes = modelBytes(profile, executableAddress(profile))
        val snapshot = fullSnapshot(profile, modelBytes)

        val operation = fullOperation(profile, snapshot)
        val binding = profile.bindFullExport(operation)
        val document = OracleJson.parseCanonical(binding.canonicalBytes).jsonObject

        assertEquals("gcc-compiler-engine-structural-full-export-binding-v2", document.getValue("provider").jsonPrimitive.content)
        assertEquals(2, document.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(profile.compilerEngineProfileSha256,
            document.getValue("compilerEngineProfileSha256").jsonPrimitive.content)
        assertEquals(profile.artifactManifestSha256, document.getValue("artifactManifestSha256").jsonPrimitive.content)
        val target = document.getValue("targetDescriptor").jsonObject
        assertEquals("x86_64-sysv-amd64-v1", target.getValue("id").jsonPrimitive.content)
        assertEquals("x86:LE:64:default", target.getValue("ghidraLanguage").jsonPrimitive.content)
        assertEquals("gcc", target.getValue("ghidraCompilerSpec").jsonPrimitive.content)
        assertEquals("0x400000", target.getValue("imageBase").jsonPrimitive.content)
        assertEquals(snapshot.outputTreeSha256, document.getValue("outputTreeSha256").jsonPrimitive.content)
        val lineage = document.getValue("receiptLineage").jsonObject
        assertEquals("gcc-bundled-full-export-receipt-lineage-v1", lineage.getValue("provider").jsonPrimitive.content)
        assertEquals("a".repeat(64), lineage.getValue("operationId").jsonPrimitive.content)
        assertEquals(
            OracleArtifacts.sha256(OracleJson.canonicalBytes(lineage)),
            document.getValue("receiptLineageSha256").jsonPrimitive.content,
        )
        assertEquals(64, binding.sha256.length)
    }

    @Test
    fun `authenticated full export keeps the exact captured model paired with its provenance`() {
        val profile = profile()
        val modelBytes = modelBytes(profile, executableAddress(profile))
        val snapshot = fullSnapshot(profile, modelBytes)
        val authenticated = profile.captureFullExport(fullOperation(profile, snapshot))

        assertContentEquals(modelBytes, authenticated.canonicalProgramModelBytes)
        assertEquals(OracleArtifacts.sha256(modelBytes), authenticated.programModelSha256)
        assertEquals(snapshot.programModelBytes, authenticated.programModelBytes)
        assertEquals(snapshot.outputTreeSha256, authenticated.outputTreeSha256)
        assertFalse(authenticated.scored)
        assertFalse(authenticated.releaseEligible)
        authenticated.requireSameSnapshot(snapshot)

        val mutatedCopy = authenticated.canonicalProgramModelBytes
        mutatedCopy[0] = (mutatedCopy[0].toInt() xor 1).toByte()
        assertContentEquals(modelBytes, authenticated.canonicalProgramModelBytes)
        assertFailsWith<GccDriverStructuralProfileException> {
            authenticated.requireSameSnapshot(fullSnapshot(profile, modelBytes))
        }
    }

    @Test
    fun `full export binding rejects binary-only JSON target and loader substitutions`() {
        val profile = profile()
        val canonical = modelBytes(profile, executableAddress(profile))

        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile,
                fullSnapshot(profile, "{\"inputSha256\":\"${profile.strippedBinary.sha256}\"}".toByteArray())))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.captureFullExport(fullOperation(profile,
                fullSnapshot(profile, "{\"inputSha256\":\"${profile.strippedBinary.sha256}\"}".toByteArray())))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile, fullSnapshot(profile, modelBytes(profile, profile.imageBase))))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile,
                fullSnapshot(profile, canonical, language = "x86:LE:64:default:attacker")))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile, fullSnapshot(profile, canonical, compilerSpec = "attacker")))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile, fullSnapshot(profile, canonical, inputSha256 = "f".repeat(64))))
        }
    }

    @Test
    fun `full export binding rejects a broken receipt chain and intent artifact substitutions`() {
        val profile = profile()
        val snapshot = fullSnapshot(profile, modelBytes(profile, executableAddress(profile)))

        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile, snapshot, exportPreviousSha256 = "f".repeat(64)))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullOperation(profile, snapshot, intentExporterSha256 = "e".repeat(64)))
        }
    }

    private fun modelBytes(profile: GccDriverStructuralInputsV1, address: ULong): ByteArray =
        RecoveredProgramModel(
            inputSha256 = profile.strippedBinary.sha256,
            functions = listOf(
                RecoveredFunction(
                    id = "fn_${address.toString(16).padStart(16, '0')}",
                    name = "driver_function",
                    address = address,
                    prototype = "void driver_function(void)",
                ),
            ),
        ).toJson().toByteArray()

    private fun fullSnapshot(
        profile: GccDriverStructuralInputsV1,
        modelBytes: ByteArray,
        inputSha256: String = profile.strippedBinary.sha256,
        language: String = profile.targetAbi.ghidraLanguage,
        compilerSpec: String = profile.targetAbi.ghidraCompilerSpec,
    ): GccBundledFullExportSnapshot {
        val runtime = GccRetainedCompilerEngineProfile.open(profile.root.resolve("compiler-engines.json")).use {
            it.suite.analysis
        }
        val exporterBytes = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
            .use { it.readBytes() }
        val modelSha = OracleArtifacts.sha256(modelBytes)
        return GccBundledFullExportSnapshot(
            inputSha256 = inputSha256,
            inputBytes = profile.strippedBinary.bytes,
            exporterSha256 = runtime.exporterSha256,
            exporterBytes = exporterBytes.size.toLong(),
            analysisToolSha256 = runtime.ghidraArchive.sha256,
            analysisToolBytes = runtime.ghidraArchive.bytes,
            language = language,
            compilerSpec = compilerSpec,
            stateSha256 = OracleArtifacts.sha256("state".toByteArray()),
            progressSha256 = OracleArtifacts.sha256("progress".toByteArray()),
            programModelSha256 = modelSha,
            programModelBytes = modelBytes.size.toLong(),
            functionCount = 1,
            recovered = 1,
            partial = 0,
            failed = 0,
            reused = 0,
            outputTreeSha256 = OracleArtifacts.sha256("tree".toByteArray()),
            outputFileCount = 4,
            capturedBytes = modelBytes.size.toLong() + 2,
            programModel = modelBytes,
            sidecarManifest = OracleJson.canonicalBytes(JsonObject(emptyMap())),
        )
    }

    private fun fullOperation(
        profile: GccDriverStructuralInputsV1,
        snapshot: GccBundledFullExportSnapshot,
        exportPreviousSha256: String? = null,
        intentExporterSha256: String = snapshot.exporterSha256,
    ): GccBundledFullExportOperation {
        val operationId = "a".repeat(64)
        val plannerProfile = GccRetainedCompilerEngineProfile.open(profile.root.resolve("compiler-engines.json")).use {
            OracleJson.parseCanonical(it.policyBytes()) as JsonObject
        }
        val intent = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-operation-intent-v2"),
            "schemaVersion" to JsonPrimitive(2),
            "operationId" to JsonPrimitive(operationId),
            "engineId" to JsonPrimitive("cc1"),
            "runKind" to JsonPrimitive("fresh-control"),
            "plannerProfile" to plannerProfile,
            "bundledRuntime" to JsonObject(mapOf("provider" to JsonPrimitive("bundled-ghidra-java-api-runtime-v5"))),
            "artifacts" to JsonArray(listOf(
                artifact("engine-binary", profile.strippedBinary.bytes, profile.strippedBinary.sha256),
                artifact("exporter-source", snapshot.exporterBytes, intentExporterSha256),
                artifact("ghidra-archive", snapshot.analysisToolBytes, snapshot.analysisToolSha256),
            )),
        ))
        val intentBytes = OracleJson.canonicalBytes(intent)
        val intentSha256 = OracleArtifacts.sha256(intentBytes)
        val executionUnsigned = JsonObject(mapOf(
            "provider" to JsonPrimitive("kotlin-lease-contained-command-execution-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "childExitCode" to JsonPrimitive(0),
            "unitAbsent" to JsonPrimitive(true),
            "cgroupAbsent" to JsonPrimitive(true),
            "processesAbsent" to JsonPrimitive(true),
            "releaseEligible" to JsonPrimitive(false),
        ))
        val execution = JsonObject(executionUnsigned + (
            "executionSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(executionUnsigned)))
        ))
        val executionReceipt = linkedRecord(
            provider = "gcc-bundled-command-executed-v1",
            operationId = operationId,
            intentSha256 = intentSha256,
            previousSha256 = "b".repeat(64),
            payloadName = "execution",
            payload = execution,
        )
        val assessment = OracleJson.parseCanonical(snapshot.assessmentBytes).jsonObject
        val assessmentUnsigned = JsonObject(assessment - "assessmentSha256" + (
            "operationWallTime" to JsonObject(mapOf("elapsedMillis" to JsonPrimitive(50)))
        ))
        val assessmentWithDigest = JsonObject(assessmentUnsigned + (
            "assessmentSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(assessmentUnsigned)))
        ))
        val exportReceipt = linkedRecord(
            provider = "gcc-bundled-command-export-assessed-v1",
            operationId = operationId,
            intentSha256 = intentSha256,
            previousSha256 = exportPreviousSha256 ?: OracleArtifacts.sha256(executionReceipt),
            payloadName = "assessment",
            payload = assessmentWithDigest,
        )
        return GccBundledFullExportOperation(intentBytes, executionReceipt, exportReceipt, snapshot)
    }

    private fun artifact(role: String, bytes: Long, sha256: String): JsonObject = JsonObject(mapOf(
        "role" to JsonPrimitive(role),
        "bytes" to JsonPrimitive(bytes),
        "sha256" to JsonPrimitive(sha256),
    ))

    private fun linkedRecord(
        provider: String,
        operationId: String,
        intentSha256: String,
        previousSha256: String,
        payloadName: String,
        payload: JsonObject,
    ): ByteArray {
        val fields = JsonObject(mapOf(
            "provider" to JsonPrimitive(provider),
            "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive(operationId),
            "intentSha256" to JsonPrimitive(intentSha256),
            "previousSha256" to JsonPrimitive(previousSha256),
            "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false),
            payloadName to payload,
            "${payloadName}Sha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(payload))),
        ))
        return OracleJson.canonicalBytes(JsonObject(fields + (
            "recordSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(fields)))
        )))
    }

    private fun profile(): GccDriverStructuralInputsV1 = PROFILE

    private fun executableAddress(profile: GccDriverStructuralInputsV1): ULong =
        profile.imageBase + profile.executableRanges.first().startRva + 1UL

    private companion object {
        val PROFILE: GccDriverStructuralInputsV1 by lazy {
            GccDriverStructuralInputsV1.load(Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize())
        }
    }
}
