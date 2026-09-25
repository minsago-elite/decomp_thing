package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleArtifacts
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccDriverStructuralProfileTest {
    @Test
    fun `fixed profile authenticates GCC source build ELF twins target and image base`() {
        val root = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize()

        val profile = GccDriverStructuralInputsV1.load(root)

        assertEquals("gcc-driver-16.2.0", profile.profileId)
        assertEquals("16.2.0", profile.version)
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", profile.sourceRevision)
        assertEquals("c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9", profile.artifactManifestSha256)
        assertEquals("8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b", profile.fullBinary.sha256)
        assertEquals("3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4", profile.strippedBinary.sha256)
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
        assertEquals(0x3000UL, profile.executableRanges.single().startRva)
        assertEquals(0x10eac9UL, profile.executableRanges.single().endExclusiveRva)
        assertEquals("0x400000", profile.inputBinary.imageBase)
        assertEquals(profile.strippedBinary.sha256, profile.inputBinary.sha256)
        assertTrue(profile.inputBinary.executableRangesSha256.matches(Regex("[a-f0-9]{64}")))
    }

    @Test
    fun `manifest substitution that repeats expected binary hashes is rejected`() {
        val parent = Files.createTempDirectory("gcc-driver-structural-profile-")
        val root = Files.createDirectory(parent.resolve("16.2.0"))
        try {
            val original = OracleJson.parse(Files.readAllBytes(Path.of("oracle/gcc/16.2.0/oracle-manifest.json")))
                .jsonObject
            val changedOracle = JsonObject(original.getValue("oracle").jsonObject +
                ("id" to JsonPrimitive("attacker-profile")))
            Files.write(root.resolve("oracle-manifest.json"), OracleJson.canonicalBytes(
                JsonObject(original + ("oracle" to changedOracle)),
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
    fun `captured full export binds binary exporter loader target image base and executable addresses`() {
        val root = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize()
        val profile = GccDriverStructuralInputsV1.load(root)
        val modelBytes = modelBytes(profile, 0x403000UL)
        val snapshot = fullSnapshot(profile, modelBytes)

        val binding = profile.bindFullExport(snapshot)
        val document = OracleJson.parseCanonical(binding.canonicalBytes).jsonObject

        assertEquals("gcc-driver-structural-full-export-binding-v1", document.getValue("provider").jsonPrimitive.content)
        assertEquals(1, document.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals(profile.artifactManifestSha256, document.getValue("artifactManifestSha256").jsonPrimitive.content)
        val target = document.getValue("targetDescriptor").jsonObject
        assertEquals("x86_64-sysv-amd64-v1", target.getValue("id").jsonPrimitive.content)
        assertEquals("x86:LE:64:default", target.getValue("ghidraLanguage").jsonPrimitive.content)
        assertEquals("gcc", target.getValue("ghidraCompilerSpec").jsonPrimitive.content)
        assertEquals("0x400000", target.getValue("imageBase").jsonPrimitive.content)
        assertEquals(snapshot.outputTreeSha256, document.getValue("outputTreeSha256").jsonPrimitive.content)
        assertEquals(64, binding.sha256.length)
    }

    @Test
    fun `full export binding rejects binary-only JSON target and loader substitutions`() {
        val root = Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize()
        val profile = GccDriverStructuralInputsV1.load(root)
        val canonical = modelBytes(profile, 0x403000UL)

        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullSnapshot(profile, "{\"inputSha256\":\"${profile.strippedBinary.sha256}\"}".toByteArray()))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullSnapshot(profile, modelBytes(profile, 0x400000UL)))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullSnapshot(profile, canonical, language = "x86:LE:64:default:attacker"))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullSnapshot(profile, canonical, compilerSpec = "attacker"))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            profile.bindFullExport(fullSnapshot(profile, canonical, inputSha256 = "f".repeat(64)))
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
}
