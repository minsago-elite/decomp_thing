package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.structural.CanonicalProgramModelStreaming
import decompengine.oracle.structural.CanonicalProgramModelStreamingLimits
import decompengine.oracle.structural.StructuralRecoveryV1Exception
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
import kotlinx.serialization.json.long

class GccDriverStructuralProfileTest {
    @Test
    fun `fixed profile authenticates GCC cc1 source build artifact identities target and image base`() {
        val profile = profile()

        assertEquals("cc1", profile.engineId)
        assertEquals("gcc-cc1-16.2.0", profile.profileId)
        assertEquals("16.2.0", profile.version)
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", profile.sourceRevision)
        assertEquals("9c3187dedb789d547a9c455d7403ca42168c1789ff439412f6e9bea48390f925",
            profile.compilerEngineProfileSha256)
        assertEquals("bbab2fbd88ddea358401b609c20524034ee1720ede5b04b00b84a01551b00bc1",
            profile.fullExportProfileSha256)
        assertEquals("dbef520c025d268f5126229ace8ad5b08a15722573d45b5e1ab934611905abb4", profile.artifactManifestSha256)
        assertEquals("ba9b2f314bfb3d92a172e67f8ce993a2e98b9bc14aabf00ff6d58e4631037621", profile.fullBinary.sha256)
        assertEquals("e51bf6e3f3300d31ce9713e2160c6fe5895d1e4914fb25562c3542b161427905", profile.strippedBinary.sha256)
        assertEquals("sysv-amd64-elf-v1", profile.targetAbi.id)
        assertEquals("d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343",
            profile.targetAbi.descriptorSha256)
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
    fun `driver selection authenticates its distinct manifest twins and executable layout`() {
        val driver = profile("driver")
        val cc1 = profile()
        assertEquals("driver", driver.engineId)
        assertEquals("gcc-driver-16.2.0", driver.profileId)
        assertEquals(cc1.sourceRevision, driver.sourceRevision)
        assertEquals(cc1.sourceLockSha256, driver.sourceLockSha256)
        assertEquals(cc1.buildRecordSha256, driver.buildRecordSha256)
        assertEquals(cc1.toolchainReproductionSha256, driver.toolchainReproductionSha256)
        assertEquals(cc1.compilerEngineProfileSha256, driver.compilerEngineProfileSha256)
        assertEquals(cc1.fullExportProfileSha256, driver.fullExportProfileSha256)
        assertEquals(cc1.targetAbi, driver.targetAbi)
        assertEquals("c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9", driver.artifactManifestSha256)
        assertEquals("8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b", driver.fullBinary.sha256)
        assertEquals(20_713_760L, driver.fullBinary.bytes)
        assertEquals("3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4", driver.strippedBinary.sha256)
        assertEquals(2_349_296L, driver.strippedBinary.bytes)
        assertEquals(0x400000UL, driver.imageBase)
        assertEquals(listOf(GccDriverStructuralExecutableRangeV1(0x3000UL, 0x10eac9UL)), driver.executableRanges)
        assertEquals("b7244d96c63edd15050a2bd8eb19309965977b47ca39ddb10a0b4909d9ad4da3",
            driver.inputBinary.executableRangesSha256)
        assertEquals(driver.strippedBinary.sha256, driver.inputBinary.sha256)
        for (unsupported in listOf("lto1", "other", "CC1")) {
            assertFailsWith<GccDriverStructuralProfileException>(unsupported) {
                GccDriverStructuralInputsV1.load(driver.root, unsupported)
            }
        }
    }

    @Test
    fun `driver manifest cannot substitute cc1 or alter layout while retaining binary hashes`() {
        val scratch = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(scratch)
        val parent = Files.createTempDirectory(scratch, "gcc-driver-profile-binding-")
        val root = Files.createDirectories(parent.resolve("gcc/16.2.0"))
        val originalRoot = profile().root
        try {
            for (name in listOf("compiler-engines.json", "source-lock.json", "build-record.json",
                "toolchain-reproduction.json", "build-toolchain.Dockerfile", "cc1-build-record.json",
                "cc1-oracle-manifest.json", "lto1-build-record.json", "lto1-oracle-manifest.json",
                "oracle-manifest.json", "structural-full-export-profile.json")) {
                Files.copy(originalRoot.resolve(name), root.resolve(name))
            }
            val targets = Files.createDirectories(parent.resolve("targets"))
            Files.copy(originalRoot.parent.parent.resolve("targets/sysv-amd64-v1.json"), targets.resolve("sysv-amd64-v1.json"))
            assertEquals(profile("driver").inputBinary, GccDriverStructuralInputsV1.load(root, "driver").inputBinary)

            val manifestPath = root.resolve("oracle-manifest.json")
            val original = OracleJson.parse(Files.readAllBytes(manifestPath)).jsonObject
            val artifacts = original.getValue("artifacts").jsonObject
            val stripped = artifacts.getValue("stripped").jsonObject
            val elf = stripped.getValue("elf").jsonObject
            val header = elf.getValue("header").jsonObject
            val changedHeader = JsonObject(header + ("machine" to JsonPrimitive(183)))
            val changedElf = JsonObject(elf + ("header" to changedHeader))
            val changedStripped = JsonObject(stripped + ("elf" to changedElf))
            val changed = JsonObject(original + ("artifacts" to JsonObject(artifacts + ("stripped" to changedStripped))))
            Files.write(manifestPath, OracleJson.canonicalBytes(changed))
            assertEquals(profile("driver").strippedBinary.sha256,
                changed.getValue("artifacts").jsonObject.getValue("stripped").jsonObject.getValue("sha256").jsonPrimitive.content)
            assertFailsWith<GccDriverStructuralProfileException> { GccDriverStructuralInputsV1.load(root, "driver") }

            Files.write(manifestPath, Files.readAllBytes(root.resolve("cc1-oracle-manifest.json")))
            assertFailsWith<GccDriverStructuralProfileException> { GccDriverStructuralInputsV1.load(root, "driver") }
        } finally {
            Files.walk(parent).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
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
        assertEquals(profile.fullExportProfileSha256,
            document.getValue("fullExportProfileSha256").jsonPrimitive.content)
        assertEquals(profile.artifactManifestSha256, document.getValue("artifactManifestSha256").jsonPrimitive.content)
        val target = document.getValue("targetDescriptor").jsonObject
        assertEquals("sysv-amd64-elf-v1", target.getValue("id").jsonPrimitive.content)
        assertEquals(profile.targetAbi.descriptorSha256,
            target.getValue("checkedTargetAbiSha256").jsonPrimitive.content)
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
    fun `full export binding accepts source beyond historical text limit without truncation`() {
        val profile = profile()
        val address = executableAddress(profile)
        val historical = CanonicalProgramModelStreamingLimits()
        val model = RecoveredProgramModel(
            schemaVersion = 2,
            inputSha256 = profile.strippedBinary.sha256,
            functions = listOf(RecoveredFunction(
                id = "fn_${address.toString(16).padStart(16, '0')}",
                name = "driver_function",
                address = address,
                prototype = "void driver_function(void)",
                decompiledC = "/*${"x".repeat(historical.maximumTextCodePoints + 1)}*/",
            )),
        )
        val bytes = model.toJson().toByteArray()
        // Even the entire model fits one admitted function record; no 64 MiB fixture is needed.
        assertTrue(bytes.size < GccBundledFullExportCapture.MAXIMUM_FULL_FUNCTION_RECORD_BYTES)
        val historicalFailure = assertFailsWith<StructuralRecoveryV1Exception> {
            CanonicalProgramModelStreaming.readCanonical(bytes)
        }
        assertTrue(historicalFailure.message.orEmpty().contains("decompiledC"))

        val binding = profile.bindFullExport(fullOperation(profile, fullSnapshot(profile, bytes)))
        val committedModel = OracleJson.parseCanonical(binding.canonicalBytes).jsonObject
            .getValue("programModel").jsonObject
        assertEquals(OracleArtifacts.sha256(bytes), committedModel.getValue("sha256").jsonPrimitive.content)
        assertEquals(bytes.size.toLong(), committedModel.getValue("bytes").jsonPrimitive.long)

        val failure = assertFailsWith<StructuralRecoveryV1Exception> {
            CanonicalProgramModelStreaming.readCanonical(bytes,
                GccDriverStructuralInputsV1.FULL_EXPORT_MODEL_LIMITS.copy(
                    maximumTextCodePoints = model.functions.single().decompiledC!!.length - 1,
                ))
        }
        assertTrue(failure.message.orEmpty().contains("decompiledC"))
    }

    @Test
    fun `full export name prototype and reference limits follow the captured record envelope`() {
        val profile = profile()
        val address = executableAddress(profile)
        val historical = CanonicalProgramModelStreamingLimits()
        val function = RecoveredFunction(
            id = "fn_${address.toString(16).padStart(16, '0')}",
            name = "n".repeat(historical.maximumIdentifierCodePoints + 1),
            address = address,
            prototype = "p".repeat(historical.maximumPrototypeCodePoints + 1),
            decompiledC = "void driver_function(void) {}",
            calls = (0..historical.maximumReferencesPerFunction).mapTo(linkedSetOf()) {
                "fn_${it.toString(16).padStart(16, '0')}"
            },
        )
        val model = RecoveredProgramModel(2, profile.strippedBinary.sha256, listOf(function))
        val bytes = model.toJson().toByteArray()
        assertTrue(bytes.size < GccBundledFullExportCapture.MAXIMUM_FULL_FUNCTION_RECORD_BYTES)
        val limits = GccDriverStructuralInputsV1.FULL_EXPORT_MODEL_LIMITS
        assertEquals(model, CanonicalProgramModelStreaming.readCanonical(bytes, limits).model)
        profile.bindFullExport(fullOperation(profile, fullSnapshot(profile, bytes)))

        listOf(
            limits.copy(maximumIdentifierCodePoints = function.name.length - 1) to "function name",
            limits.copy(maximumPrototypeCodePoints = function.prototype.length - 1) to "function prototype",
            limits.copy(maximumReferencesPerFunction = function.calls.size - 1) to "collection-entry limit",
        ).forEach { (bounded, message) ->
            val failure = assertFailsWith<StructuralRecoveryV1Exception> {
                CanonicalProgramModelStreaming.readCanonical(bytes, bounded)
            }
            assertTrue(failure.message.orEmpty().contains(message))
        }
    }

    @Test
    fun `driver capture derives selected target and rejects cross paired engines inputs and policies`() {
        val driver = profile("driver")
        val cc1 = profile()
        val driverSnapshot = fullSnapshot(driver, modelBytes(driver, executableAddress(driver)))
        val cc1Snapshot = fullSnapshot(cc1, modelBytes(cc1, executableAddress(cc1)))
        val driverOperation = fullOperation(driver, driverSnapshot)
        val captured = driver.captureFullExport(driverOperation)
        val document = OracleJson.parseCanonical(captured.binding.canonicalBytes).jsonObject
        assertEquals("driver", captured.engineId)
        assertEquals("gcc-driver-16.2.0", document.getValue("profileId").jsonPrimitive.content)
        assertEquals("driver", document.getValue("receiptLineage").jsonObject.getValue("engineId").jsonPrimitive.content)
        assertContentEquals(driverSnapshot.programModel, captured.canonicalProgramModelBytes)
        assertFalse(captured.scored)
        assertFalse(captured.releaseEligible)
        assertFailsWith<GccDriverStructuralProfileException> { cc1.bindFullExport(driverOperation) }
        assertFailsWith<GccDriverStructuralProfileException> {
            driver.bindFullExport(fullOperation(cc1, cc1Snapshot))
        }
        // Rehash the complete receipt chain around each changed intent so rejection proves
        // selected-target consistency, rather than merely noticing a stale receipt digest.
        for (engine in listOf("cc1", "lto1")) {
            assertFailsWith<GccDriverStructuralProfileException> {
                driver.bindFullExport(fullOperation(driver, driverSnapshot, intentEngineId = engine))
            }
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            driver.bindFullExport(fullOperation(driver, driverSnapshot, plannerEngineId = "cc1"))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            driver.bindFullExport(fullOperation(cc1, cc1Snapshot, intentEngineId = "driver", plannerEngineId = "driver"))
        }
        assertFailsWith<GccDriverStructuralProfileException> {
            driver.bindFullExport(fullOperation(driver, fullSnapshot(driver, modelBytes(driver, driver.imageBase))))
        }
    }

    @Test
    fun `driver boundary evidence retains exact captured inputs and remains unqualified`() {
        val driver = profile("driver")
        val model = modelBytes(driver, executableAddress(driver))
        val captured = driver.captureFullExport(fullOperation(driver, fullSnapshot(driver, model)))
        val evidence = GccDriverStructuralBoundaryEvidenceV1.capture(driver, captured)
        val repeated = GccDriverStructuralBoundaryEvidenceV1.capture(driver, captured)
        assertContentEquals(evidence.observationBytes, repeated.observationBytes)
        assertContentEquals(evidence.bindingBytes, repeated.bindingBytes)
        val binding = OracleJson.parseCanonical(evidence.bindingBytes).jsonObject
        for (flag in listOf("complete", "scored", "productionVerified", "releaseEligible")) {
            assertEquals(JsonPrimitive(false), binding.getValue(flag), flag)
        }
        GccDriverStructuralBoundaryEvidenceV1.verifyRetained(driver, captured.binding.canonicalBytes,
            model, evidence.observationBytes, evidence.bindingBytes)

        val observationLimits = StrictJsonLimits(
            maximumInputBytes = GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_OBSERVATION_BYTES,
            maximumCanonicalBytes = GccDriverStructuralBoundaryEvidenceV1.MAXIMUM_OBSERVATION_BYTES,
            maximumNodes = 1_000_000,
            maximumStringBytes = 4 * 1024 * 1024,
            maximumTotalStringBytes = 48 * 1024 * 1024,
        )
        val observation = OracleJson.parseCanonical(evidence.observationBytes, observationLimits).jsonObject
        val forgedObservation = OracleJson.canonicalBytes(
            JsonObject(observation + ("scored" to JsonPrimitive(true))), observationLimits,
        )
        val reboundForgery = OracleJson.canonicalBytes(JsonObject(binding + mapOf(
            "observationSha256" to JsonPrimitive(OracleArtifacts.sha256(forgedObservation)),
            "observationBytes" to JsonPrimitive(forgedObservation.size),
        )))
        assertFailsWith<IllegalArgumentException> {
            GccDriverStructuralBoundaryEvidenceV1.verifyRetained(driver, captured.binding.canonicalBytes,
                model, forgedObservation, reboundForgery)
        }
        val releaseForgery = OracleJson.canonicalBytes(JsonObject(binding + ("releaseEligible" to JsonPrimitive(true))))
        assertFailsWith<IllegalArgumentException> {
            GccDriverStructuralBoundaryEvidenceV1.verifyRetained(driver, captured.binding.canonicalBytes,
                model, evidence.observationBytes, releaseForgery)
        }
        assertFailsWith<IllegalArgumentException> {
            GccDriverStructuralBoundaryEvidenceV1.verifyRetained(driver, captured.binding.canonicalBytes,
                modelBytes(driver, executableAddress(driver) + 1UL), evidence.observationBytes, evidence.bindingBytes)
        }
        assertFailsWith<IllegalArgumentException> {
            GccDriverStructuralBoundaryEvidenceV1.capture(profile(), captured)
        }
        val changedCopy = evidence.observationBytes
        changedCopy[0] = (changedCopy[0].toInt() xor 1).toByte()
        assertContentEquals(repeated.observationBytes, evidence.observationBytes)
    }

    @Test
    fun `authenticated full export keeps the exact captured model paired with its provenance`() {
        val profile = profile()
        val modelBytes = modelBytes(profile, executableAddress(profile))
        val snapshot = fullSnapshot(profile, modelBytes)
        val authenticated = profile.captureFullExport(fullOperation(profile, snapshot))

        assertContentEquals(modelBytes, authenticated.canonicalProgramModelBytes)
        assertEquals("cc1", authenticated.engineId)
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

    @Test
    fun `publication rejects a binding from another retained export`() {
        val profile = profile()
        val first = fullOperation(profile, fullSnapshot(profile,
            modelBytes(profile, executableAddress(profile))))
        val second = fullOperation(profile, fullSnapshot(profile,
            modelBytes(profile, executableAddress(profile) + 1UL)))
        val firstBinding = profile.bindFullExport(first)
        val secondBinding = profile.bindFullExport(second)

        requireGccFullExportBindingMatchesOperation(firstBinding, first, "a".repeat(64))
        assertFailsWith<IllegalArgumentException> {
            requireGccFullExportBindingMatchesOperation(secondBinding, first, "a".repeat(64))
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
        val runtime = GccRetainedCompilerEngineProfile.open(profile.root.resolve("compiler-engines.json"), profile.engineId).use {
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
        intentEngineId: String = profile.engineId,
        plannerEngineId: String = profile.engineId,
    ): GccBundledFullExportOperation {
        val operationId = "a".repeat(64)
        val plannerProfile = GccRetainedCompilerEngineProfile.open(profile.root.resolve("compiler-engines.json"), plannerEngineId).use {
            OracleJson.parseCanonical(it.policyBytes()) as JsonObject
        }
        val intent = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-operation-intent-v2"),
            "schemaVersion" to JsonPrimitive(2),
            "operationId" to JsonPrimitive(operationId),
            "engineId" to JsonPrimitive(intentEngineId),
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
        // Test-only fixture: production callers cannot obtain the coordinator's private permit.
        val permitField = Class.forName("decompengine.oracle.gcc.GCC_BUNDLED_PREPARED_OPERATION_PERMIT")
            .getDeclaredField("INSTANCE")
        permitField.isAccessible = true
        return GccBundledFullExportOperation(
            intentBytes, executionReceipt, exportReceipt, snapshot, permitField.get(null),
        )
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

    private fun profile(engineId: String): GccDriverStructuralInputsV1 =
        if (engineId == "cc1") PROFILE else DRIVER_PROFILE

    private fun executableAddress(profile: GccDriverStructuralInputsV1): ULong =
        profile.imageBase + profile.executableRanges.first().startRva + 1UL

    private companion object {
        val PROFILE: GccDriverStructuralInputsV1 by lazy {
            GccDriverStructuralInputsV1.load(Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize())
        }
        val DRIVER_PROFILE: GccDriverStructuralInputsV1 by lazy {
            GccDriverStructuralInputsV1.load(Path.of("oracle/gcc/16.2.0").toAbsolutePath().normalize(), "driver")
        }
    }
}
