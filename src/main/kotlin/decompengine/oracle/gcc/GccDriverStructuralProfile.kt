package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.structural.CanonicalProgramModelStreaming
import decompengine.oracle.structural.CanonicalProgramModelStreamingLimits
import decompengine.oracle.structural.StructuralReplayInputBinaryV1
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull
import kotlinx.serialization.json.jsonPrimitive

internal class GccDriverStructuralProfileException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

internal data class GccDriverStructuralExecutableRangeV1(val startRva: ULong, val endExclusiveRva: ULong) {
    init {
        require(startRva < endExclusiveRva) { "GCC structural executable range is empty or reversed" }
    }
}

internal data class GccDriverStructuralTargetAbiV1(
    val id: String,
    val descriptorSha256: String,
    val architecture: String,
    val abi: String,
    val machine: Int,
    val osAbi: Int,
    val elfClass: String,
    val dataEncoding: String,
    val pointerBits: Int,
    val elfType: String,
    val ghidraLanguage: String,
    val ghidraCompilerSpec: String,
)

internal data class GccDriverStructuralBinaryV1(
    val bytes: Long,
    val sha256: String,
    val elfType: String,
)

/**
 * The fixed GCC cc1 input set, authenticated from its checked compiler-engine profile and artifact
 * manifest. ELF layout values come from that SHA-pinned manifest, so normal tests do not need to
 * materialize the 380 MB DWARF-rich twin. It does not claim that a model has been exported.
 */
internal class GccDriverStructuralInputsV1 private constructor(
    val root: Path,
    val profileId: String,
    val version: String,
    val sourceRevision: String,
    val compilerEngineProfileSha256: String,
    val fullExportProfileSha256: String,
    val artifactManifestSha256: String,
    val sourceLockSha256: String,
    val buildRecordSha256: String,
    val toolchainReproductionSha256: String,
    val fullBinary: GccDriverStructuralBinaryV1,
    val strippedBinary: GccDriverStructuralBinaryV1,
    val targetAbi: GccDriverStructuralTargetAbiV1,
    val imageBase: ULong,
    executableRanges: List<GccDriverStructuralExecutableRangeV1>,
    val inputBinary: StructuralReplayInputBinaryV1,
) {
    val executableRanges: List<GccDriverStructuralExecutableRangeV1> =
        Collections.unmodifiableList(ArrayList(executableRanges))

    /**
     * Binds one descriptor-captured full export and its linked contained-operation receipts to the
     * authenticated cc1 input, target and runtime profile. This is provenance evidence only; it does
     * not authorize structural scoring or independent replay admission.
     */
    fun bindFullExport(
        operation: GccBundledFullExportOperation,
    ): GccDriverStructuralFullExportBindingV2 = translateProfileFailure {
        val receiptLineage = GccDriverStructuralFullExportReceiptLineageV1.validate(
            operation, compilerEngineProfileSha256,
        )
        val snapshot = operation.snapshot
        require(snapshot.inputSha256 == strippedBinary.sha256 && snapshot.inputBytes == strippedBinary.bytes) {
            "GCC full export input differs from the authenticated stripped cc1"
        }
        require(snapshot.language == targetAbi.ghidraLanguage && snapshot.compilerSpec == targetAbi.ghidraCompilerSpec) {
            "GCC full export loader identity differs from the authenticated target profile"
        }
        val model = CanonicalProgramModelStreaming.readCanonical(
            snapshot.programModel,
            CanonicalProgramModelStreamingLimits(
                maximumFunctions = GccBundledFullExportCapture.MAXIMUM_FULL_FUNCTIONS.toInt(),
            ),
        )
        require(model.model.inputSha256 == strippedBinary.sha256 &&
            model.model.functions.size.toLong() == snapshot.functionCount
        ) { "GCC full program model differs from the authenticated cc1 input or export inventory" }
        for (function in model.model.functions) {
            require(function.address >= imageBase) { "GCC exported function precedes the authenticated image base" }
            val rva = function.address - imageBase
            require(executableRanges.any { rva >= it.startRva && rva < it.endExclusiveRva }) {
                "GCC exported function lies outside authenticated executable ranges"
            }
            require(function.id == "fn_${function.address.toString(16).padStart(16, '0')}") {
                "GCC exported function identity does not encode its loaded address"
            }
        }
        GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json")).use { runtimeProfile ->
            runtimeProfile.requireCurrent()
            require(loadFullExportAuthority(root, runtimeProfile.suite.analysis.exporterSha256,
                runtimeProfile.suite.analysis.ghidraArchive.sha256) == fullExportProfileSha256
            ) { "GCC full-export authority changed after structural profile admission" }
            val intent = OracleJson.parseCanonical(operation.intentBytes) as JsonObject
            require(intent["plannerProfile"] == OracleJson.parseCanonical(runtimeProfile.policyBytes())) {
                "GCC full-export intent planner profile differs from the retained compiler-engine profile"
            }
            require(runtimeProfile.suite.profileSha256 == compilerEngineProfileSha256 &&
                runtimeProfile.suite.engine("cc1").strippedArtifact.sha256 == strippedBinary.sha256 &&
                runtimeProfile.suite.engine("cc1").strippedArtifact.bytes == strippedBinary.bytes
            ) { "GCC full export operation profile differs from the authenticated cc1 structural input" }
            val analysis = runtimeProfile.suite.analysis
            val exporterBytes = GccCompilerEngineProfiles::class.java
                .getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")?.use {
                    it.readNBytes(4 * 1024 * 1024 + 1)
                } ?: profileFail("bundled Ghidra exporter is unavailable")
            require(snapshot.exporterSha256 == analysis.exporterSha256 &&
                snapshot.exporterBytes == exporterBytes.size.toLong()
            ) { "GCC full export implementation differs from the authenticated bundled exporter" }
            require(snapshot.analysisToolSha256 == analysis.ghidraArchive.sha256 &&
                snapshot.analysisToolBytes == analysis.ghidraArchive.bytes
            ) { "GCC full export analysis runtime differs from the authenticated bundled Ghidra archive" }
            val descriptor = OracleJson.canonicalBytes(JsonObject(linkedMapOf(
                "id" to JsonPrimitive(targetAbi.id),
                "checkedTargetAbiSha256" to JsonPrimitive(targetAbi.descriptorSha256),
                "architecture" to JsonPrimitive(targetAbi.architecture),
                "abi" to JsonPrimitive(targetAbi.abi),
                "machine" to JsonPrimitive(targetAbi.machine),
                "osAbi" to JsonPrimitive(targetAbi.osAbi),
                "elfClass" to JsonPrimitive(targetAbi.elfClass),
                "dataEncoding" to JsonPrimitive(targetAbi.dataEncoding),
                "pointerBits" to JsonPrimitive(targetAbi.pointerBits),
                "elfType" to JsonPrimitive(targetAbi.elfType),
                "ghidraLanguage" to JsonPrimitive(targetAbi.ghidraLanguage),
                "ghidraCompilerSpec" to JsonPrimitive(targetAbi.ghidraCompilerSpec),
                "imageBase" to JsonPrimitive("0x${imageBase.toString(16)}"),
                "executableRangesSha256" to JsonPrimitive(inputBinary.executableRangesSha256),
            )))
            GccDriverStructuralFullExportBindingV2.create(
                admissionPermit = GCC_STRUCTURAL_BINDING_ADMISSION_PERMIT,
                profileId = profileId,
                version = version,
                sourceRevision = sourceRevision,
                artifactManifestSha256 = artifactManifestSha256,
                compilerEngineProfileSha256 = compilerEngineProfileSha256,
                fullExportProfileSha256 = fullExportProfileSha256,
                targetDescriptorBytes = descriptor,
                inputSha256 = snapshot.inputSha256,
                inputBytes = snapshot.inputBytes,
                exporterSha256 = snapshot.exporterSha256,
                exporterBytes = snapshot.exporterBytes,
                ghidraArchiveSha256 = snapshot.analysisToolSha256,
                ghidraArchiveBytes = snapshot.analysisToolBytes,
                programModelSha256 = snapshot.programModelSha256,
                programModelBytes = snapshot.programModelBytes,
                outputTreeSha256 = snapshot.outputTreeSha256,
                functionCount = snapshot.functionCount,
                receiptLineageBytes = receiptLineage.canonicalBytes,
            )
        }
    }

    /**
     * Retains the exact immutable model snapshot alongside the profile binding that authenticated it.
     * Scorers must consume this value rather than pair caller-provided model bytes with a binding.
     * This remains input provenance only; it does not create the production scoring capability.
     */
    fun captureFullExport(
        operation: GccBundledFullExportOperation,
    ): GccDriverStructuralAuthenticatedFullExportV1 =
        GccDriverStructuralAuthenticatedFullExportV1.capture(this, operation)

    companion object {
        private const val PROFILE_ID = "gcc-cc1-16.2.0"
        private const val SOURCE_PROFILE_ID = "gcc-driver-16.2.0"
        private const val PROFILE_VERSION = "16.2.0"
        private const val SOURCE_REVISION = "78d4ac73dd391005b895a6148cd9831e28e1208b"
        private const val COMPILER_ENGINE_PROFILE_SHA256 = "e03bbf701e36e04e86fda27a6fa546ef7fa5cd2153ecf2ff2636795b974e6eb5"
        private const val CC1_MANIFEST_SHA256 = "dbef520c025d268f5126229ace8ad5b08a15722573d45b5e1ab934611905abb4"
        private const val CC1_BUILD_RECORD_SHA256 = "f6b2711d4f82562195acebe7250d7dc62eb9425af4f736736e0ea69b65103e8e"
        private const val SOURCE_LOCK_SHA256 = "e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc"
        private const val BUILD_RECORD_SHA256 = "f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637"
        private const val TOOLCHAIN_REPRODUCTION_SHA256 = "5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de"
        private const val TARGET_ABI_SHA256 = "d251d5e6a0edc17655c355fb8fd757d557f064a6e67095ad53c8ca1e7569a343"
        private const val FULL_EXPORT_PROFILE_SHA256 = "be6517f6423b37e70168c738ba2b7084fd15d816a36dacb10e5639b6851f2dfe"
        private const val MAXIMUM_CONTROL_BYTES = 4 * 1024 * 1024
        private const val MAXIMUM_MANIFEST_BYTES = 64 * 1024 * 1024
        private val JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAXIMUM_MANIFEST_BYTES,
            maximumCanonicalBytes = MAXIMUM_MANIFEST_BYTES,
            maximumNodes = 1_000_000,
            maximumStringBytes = 4 * 1024 * 1024,
            maximumTotalStringBytes = 32 * 1024 * 1024,
        )

        fun load(root: Path): GccDriverStructuralInputsV1 = translateProfileFailure {
            require(root.isAbsolute && root.normalize() == root && root.toRealPath() == root) {
                "GCC structural profile root must be canonical and contain no links"
            }
            require(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) && root.fileName.toString() == PROFILE_VERSION) {
                "GCC structural profile root is not the pinned version directory"
            }
            val compilerEngineProfilePath = root.resolve("compiler-engines.json")
            val compilerEngineProfileSha256 = readRaw(
                compilerEngineProfilePath, MAXIMUM_CONTROL_BYTES, "GCC compiler-engine profile",
            )
            requireDigest(compilerEngineProfileSha256, COMPILER_ENGINE_PROFILE_SHA256, "GCC compiler-engine profile")

            val sourceLock = readJson(root.resolve("source-lock.json"), MAXIMUM_CONTROL_BYTES, "gcc/source-lock")
            requireDigest(sourceLock.sha256, SOURCE_LOCK_SHA256, "GCC cc1 source lock")
            val sourceOracle = sourceLock.document.objectField("oracle", "GCC source lock")
            val sourceRevision = sourceLock.document.objectField("revision", "GCC source lock")
                .stringField("commit", "GCC source revision")
            require(sourceOracle.stringField("id", "GCC source lock oracle") == SOURCE_PROFILE_ID &&
                sourceOracle.stringField("version", "GCC source lock oracle") == PROFILE_VERSION &&
                sourceRevision == SOURCE_REVISION
            ) { "GCC source lock differs from the pinned cc1 profile" }

            val buildRecord = readJson(root.resolve("build-record.json"), MAXIMUM_CONTROL_BYTES, "gcc/build-record")
            requireDigest(buildRecord.sha256, BUILD_RECORD_SHA256, "GCC base build record")
            val buildOracle = buildRecord.document.objectField("oracle", "GCC build record")
            require(buildOracle.stringField("id", "GCC build record oracle") == SOURCE_PROFILE_ID &&
                buildOracle.stringField("version", "GCC build record oracle") == PROFILE_VERSION &&
                buildOracle.stringField("sourceRevision", "GCC build record oracle") == SOURCE_REVISION &&
                buildOracle.stringField("sourceLockSha256", "GCC build record oracle") == sourceLock.sha256
            ) { "GCC build record is not derived from the pinned source lock" }

            val toolchain = readJson(
                root.resolve("toolchain-reproduction.json"), MAXIMUM_CONTROL_BYTES, "gcc/toolchain-reproduction",
            )
            requireDigest(toolchain.sha256, TOOLCHAIN_REPRODUCTION_SHA256, "GCC toolchain reproduction record")
            val recordedBuild = toolchain.document.objectField("recordedOrigin", "GCC toolchain reproduction")
                .stringField("buildRecordSha256", "GCC recorded toolchain origin")
            require(recordedBuild == buildRecord.sha256) {
                "GCC toolchain reproduction record does not bind the pinned build record"
            }
            val recipe = toolchain.document.objectField("recipe", "GCC toolchain reproduction")
            val dockerfilePath = root.resolve(recipe.stringField("dockerfile", "GCC toolchain recipe"))
                .normalize()
            require(dockerfilePath.parent == root && dockerfilePath.fileName.toString() == "build-toolchain.Dockerfile") {
                "GCC toolchain recipe path is not fixed"
            }
            val dockerfileSha256 = readRaw(dockerfilePath, MAXIMUM_CONTROL_BYTES, "GCC toolchain Dockerfile")
            requireDigest(dockerfileSha256, recipe.stringField("dockerfileSha256", "GCC toolchain recipe"),
                "GCC toolchain Dockerfile")

            val (cc1, analysis) = GccRetainedCompilerEngineProfile.open(compilerEngineProfilePath).use { retained ->
                retained.requireCurrent()
                val suite = retained.suite
                require(suite.id == "gcc-compiler-engines-$PROFILE_VERSION" && suite.version == PROFILE_VERSION &&
                    suite.sourceRevision == SOURCE_REVISION && suite.sourceLockSha256 == sourceLock.sha256 &&
                    suite.baseBuildRecordSha256 == buildRecord.sha256 &&
                    suite.toolchainReproductionSha256 == toolchain.sha256 &&
                    suite.profileSha256 == compilerEngineProfileSha256
                ) { "GCC cc1 compiler-engine profile differs from its authenticated source/build records" }
                val engine = suite.engine("cc1").also { engine ->
                    require(engine.buildRecordSha256 == CC1_BUILD_RECORD_SHA256 &&
                        engine.oracleManifestSha256 == CC1_MANIFEST_SHA256 &&
                        engine.fullArtifact.relativePath == "artifacts/gcc-cc1.full" &&
                        engine.strippedArtifact.relativePath == "artifacts/gcc-cc1.stripped"
                    ) { "GCC cc1 artifact records differ from the fixed structural profile" }
                }
                engine to suite.analysis
            }
            val fullExportProfileSha256 = loadFullExportAuthority(
                root, analysis.exporterSha256, analysis.ghidraArchive.sha256,
            )
            val manifest = readJson(
                root.resolve("cc1-oracle-manifest.json"), MAXIMUM_MANIFEST_BYTES, "gcc/oracle-manifest",
            )
            requireDigest(manifest.sha256, cc1.oracleManifestSha256, "GCC cc1 oracle manifest")
            fun requireArtifact(name: String, expected: GccCompilerEngineArtifactBinding): JsonObject {
                val artifact = manifest.document.objectField("artifacts", "GCC cc1 oracle manifest")
                    .objectField(name, "GCC cc1 artifacts")
                require(artifact.stringField("path", "GCC cc1 $name artifact") == expected.relativePath &&
                    artifact.longField("bytes", "GCC cc1 $name artifact") == expected.bytes &&
                    artifact.stringField("sha256", "GCC cc1 $name artifact") == expected.sha256
                ) { "GCC cc1 $name artifact differs from its authenticated compiler-engine profile" }
                return artifact
            }
            val fullRecord = requireArtifact("full", cc1.fullArtifact)
            val strippedRecord = requireArtifact("stripped", cc1.strippedArtifact)
            val full = binary(fullRecord, cc1.fullArtifact)
            val stripped = binary(strippedRecord, cc1.strippedArtifact)
            val fullElf = fullRecord.objectField("elf", "GCC cc1 full artifact")
            val strippedElf = strippedRecord.objectField("elf", "GCC cc1 stripped artifact")
            require(fullElf.getValue("identity") == strippedElf.getValue("identity")) {
                "GCC cc1 full and stripped ELF identities differ in the authenticated manifest"
            }
            val fullProgramHeaders = programHeaders(fullElf)
            val strippedProgramHeaders = programHeaders(strippedElf)
            require(fullProgramHeaders == strippedProgramHeaders) {
                "GCC cc1 full and stripped program headers differ in the authenticated manifest"
            }
            val fullHeader = fullElf.objectField("header", "GCC cc1 full ELF")
            val header = strippedElf.objectField("header", "GCC cc1 stripped ELF")
            val targetDescriptor = readJson(
                root.parent.parent.resolve("targets/sysv-amd64-v1.json"), MAXIMUM_CONTROL_BYTES, "target-abi",
            )
            requireDigest(targetDescriptor.sha256, TARGET_ABI_SHA256, "GCC target ABI descriptor")
            val checkedTarget = targetDescriptor.document.objectField("target", "GCC target ABI descriptor")
            require(targetDescriptor.document.stringField("id", "GCC target ABI descriptor") == "sysv-amd64-elf-v1" &&
                checkedTarget.stringField("architecture", "GCC target ABI descriptor") == "x86_64" &&
                checkedTarget.stringField("endianness", "GCC target ABI descriptor") == "little" &&
                checkedTarget.longField("addressBits", "GCC target ABI descriptor") == 64L &&
                checkedTarget.stringField("objectFormat", "GCC target ABI descriptor") == "ELF"
            ) { "GCC target ABI descriptor differs from the checked x86-64 SysV identity" }
            val target = target(header, targetDescriptor.document.stringField("id", "GCC target ABI descriptor"),
                targetDescriptor.sha256)
            require(target(fullHeader, target.id, target.descriptorSha256) == target &&
                full.elfType == stripped.elfType
            ) {
                "GCC cc1 full and stripped ELF target records differ in the authenticated manifest"
            }
            val imageBase = strippedProgramHeaders.filter { it.typeName == "PT_LOAD" && it.memorySize > 0UL }
                .minOfOrNull(StructuralProgramHeaderV1::virtualAddress)
                ?: profileFail("GCC cc1 has no nonempty loadable ELF segment")
            val ranges = executableRanges(strippedProgramHeaders, imageBase)
            val rangesSha256 = executableRangesSha256(imageBase, ranges)
            val input = StructuralReplayInputBinaryV1(
                sha256 = stripped.sha256,
                bytes = stripped.bytes,
                elfType = stripped.elfType,
                imageBase = address(imageBase),
                executableRangesSha256 = rangesSha256,
            )
            GccDriverStructuralInputsV1(
                root = root,
                profileId = PROFILE_ID,
                version = PROFILE_VERSION,
                compilerEngineProfileSha256 = compilerEngineProfileSha256,
                fullExportProfileSha256 = fullExportProfileSha256,
                sourceRevision = sourceRevision,
                artifactManifestSha256 = cc1.oracleManifestSha256,
                sourceLockSha256 = sourceLock.sha256,
                buildRecordSha256 = buildRecord.sha256,
                toolchainReproductionSha256 = toolchain.sha256,
                fullBinary = full,
                strippedBinary = stripped,
                targetAbi = target,
                imageBase = imageBase,
                executableRanges = ranges,
                inputBinary = input,
            )
        }

        private fun loadFullExportAuthority(root: Path, exporterSha256: String,
            ghidraArchiveSha256: String): String {
            val bytes = OracleArtifacts.read(root.resolve("structural-full-export-profile.json"),
                OracleArtifactLimits(MAXIMUM_CONTROL_BYTES)).bytes
            val digest = OracleArtifacts.sha256(bytes)
            requireDigest(digest, FULL_EXPORT_PROFILE_SHA256, "GCC structural full-export profile")
            val authority = OracleJson.parseCanonical(bytes) as? JsonObject
                ?: profileFail("GCC structural full-export profile is not an object")
            require(authority.keys == setOf("provider", "schemaVersion", "compilerEngineProfileSha256",
                "exporterSha256", "exporterVersion", "recoveryMode", "ghidraArchiveSha256") &&
                authority.stringField("provider", "GCC structural full-export profile") ==
                    "gcc-driver-structural-full-export-profile-v1" &&
                authority.longField("schemaVersion", "GCC structural full-export profile") == 1L &&
                authority.stringField("compilerEngineProfileSha256", "GCC structural full-export profile") ==
                    COMPILER_ENGINE_PROFILE_SHA256 &&
                authority.stringField("exporterSha256", "GCC structural full-export profile") == exporterSha256 &&
                authority.longField("exporterVersion", "GCC structural full-export profile") == 10L &&
                authority.stringField("recoveryMode", "GCC structural full-export profile") == "full" &&
                authority.stringField("ghidraArchiveSha256", "GCC structural full-export profile") ==
                    ghidraArchiveSha256
            ) { "GCC structural profile does not authorize the authenticated full-recovery exporter" }
            return digest
        }

        private fun requireTarget(
            elfClass: String,
            dataEncoding: String,
            machine: Int,
            osAbi: Int,
            elfType: String,
            descriptorId: String,
            descriptorSha256: String,
        ): GccDriverStructuralTargetAbiV1 {
            require(elfClass == "ELF64" && dataEncoding == "little-endian" && machine == 62 && osAbi == 3 &&
                elfType == "ET_EXEC"
            ) {
                "GCC cc1 ELF differs from its fixed x86-64 SysV target profile"
            }
            return GccDriverStructuralTargetAbiV1(
                id = descriptorId,
                descriptorSha256 = descriptorSha256,
                architecture = "x86_64",
                abi = "sysv-amd64",
                machine = machine,
                osAbi = osAbi,
                elfClass = elfClass,
                dataEncoding = dataEncoding,
                pointerBits = 64,
                elfType = elfType,
                ghidraLanguage = "x86:LE:64:default",
                ghidraCompilerSpec = "gcc",
            )
        }

        private fun target(
            header: JsonObject,
            descriptorId: String,
            descriptorSha256: String,
        ): GccDriverStructuralTargetAbiV1 = requireTarget(
            header.stringField("class", "GCC cc1 ELF header"),
            header.stringField("dataEncoding", "GCC cc1 ELF header"),
            Math.toIntExact(header.longField("machine", "GCC cc1 ELF header")),
            Math.toIntExact(header.longField("osAbi", "GCC cc1 ELF header")),
            header.stringField("typeName", "GCC cc1 ELF header"),
            descriptorId,
            descriptorSha256,
        )

        private fun binary(record: JsonObject, expected: GccCompilerEngineArtifactBinding): GccDriverStructuralBinaryV1 {
            val header = record.objectField("elf", "GCC cc1 artifact")
                .objectField("header", "GCC cc1 ELF")
            return GccDriverStructuralBinaryV1(
                bytes = expected.bytes,
                sha256 = expected.sha256,
                elfType = header.stringField("typeName", "GCC cc1 ELF header"),
            )
        }

        private fun programHeaders(elf: JsonObject): List<StructuralProgramHeaderV1> =
            elf.arrayField("programHeaders", "GCC cc1 ELF").mapIndexed { index, value ->
                val header = value as? JsonObject ?: profileFail("GCC cc1 program header $index must be an object")
                fun unsigned(name: String): ULong {
                    val value = header.longField(name, "GCC cc1 program header $index")
                    require(value >= 0L) { "GCC cc1 program header $index $name is negative" }
                    return value.toULong()
                }
                StructuralProgramHeaderV1(
                    typeName = header.stringField("typeName", "GCC cc1 program header $index"),
                    flags = unsigned("flags"),
                    fileSize = unsigned("fileSize"),
                    memorySize = unsigned("memorySize"),
                    virtualAddress = unsigned("virtualAddress"),
                )
            }

        private fun executableRanges(
            headers: List<StructuralProgramHeaderV1>,
            imageBase: ULong,
        ): List<GccDriverStructuralExecutableRangeV1> {
            val ranges = headers.filter { it.typeName == "PT_LOAD" && it.flags and 1UL != 0UL && it.fileSize > 0UL }
                .map { header ->
                    require(header.virtualAddress >= imageBase) { "GCC executable segment precedes its image base" }
                    val start = header.virtualAddress - imageBase
                    val end = start + header.fileSize
                    require(end > start) { "GCC executable segment range overflows" }
                    GccDriverStructuralExecutableRangeV1(start, end)
                }
                .sortedWith(compareBy(GccDriverStructuralExecutableRangeV1::startRva, GccDriverStructuralExecutableRangeV1::endExclusiveRva))
            require(ranges.isNotEmpty()) { "GCC cc1 has no file-backed executable load range" }
            require(ranges.zipWithNext().all { (left, right) -> left.endExclusiveRva <= right.startRva }) {
                "GCC cc1 executable PT_LOAD ranges overlap"
            }
            return ranges
        }

        private fun executableRangesSha256(
            imageBase: ULong,
            ranges: List<GccDriverStructuralExecutableRangeV1>,
        ): String {
            val document = JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "imageBase" to JsonPrimitive(address(imageBase)),
                "ranges" to JsonArray(ranges.map { range -> JsonObject(mapOf(
                    "startRva" to JsonPrimitive(address(range.startRva)),
                    "endExclusiveRva" to JsonPrimitive(address(range.endExclusiveRva)),
                )) }),
            ))
            return OracleArtifacts.sha256(OracleJson.canonicalBytes(document))
        }

        private fun address(value: ULong): String = "0x${value.toString(16)}"

        private fun readJson(path: Path, maximumBytes: Int, schema: String): JsonArtifact {
            val snapshot = OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes))
            val document = try {
                OracleJson.parse(snapshot.bytes, JSON_LIMITS) as? JsonObject
                    ?: profileFail("$schema root must be an object")
            } catch (failure: GccDriverStructuralProfileException) {
                throw failure
            } catch (failure: Exception) {
                throw GccDriverStructuralProfileException("$schema is not strict bounded JSON", failure)
            }
            try {
                OracleSchemas.validate(schema, document)
            } catch (failure: Exception) {
                throw GccDriverStructuralProfileException("$schema fails its bundled schema", failure)
            }
            return JsonArtifact(snapshot.size.toLong(), snapshot.sha256, document)
        }

        private fun readRaw(path: Path, maximumBytes: Int, label: String): String = try {
            OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes)).sha256
        } catch (failure: Exception) {
            throw GccDriverStructuralProfileException("cannot read authenticated $label", failure)
        }

        private fun requireDigest(actual: String, expected: String, label: String) {
            require(actual == expected) { "$label SHA-256 differs from the fixed GCC cc1 profile" }
        }

        private fun <T> translateProfileFailure(action: () -> T): T = try {
            action()
        } catch (failure: GccDriverStructuralProfileException) {
            throw failure
        } catch (failure: Exception) {
            throw GccDriverStructuralProfileException("cannot authenticate the GCC cc1 structural input profile", failure)
        }

        private fun profileFail(message: String): Nothing = throw GccDriverStructuralProfileException(message)
    }
}

private data class JsonArtifact(val bytes: Long, val sha256: String, val document: JsonObject)

private data class StructuralProgramHeaderV1(
    val typeName: String,
    val flags: ULong,
    val fileSize: ULong,
    val memorySize: ULong,
    val virtualAddress: ULong,
)

private fun JsonObject.objectField(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: throw GccDriverStructuralProfileException("$label.$name must be an object")

private fun JsonObject.arrayField(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: throw GccDriverStructuralProfileException("$label.$name must be an array")

private fun JsonObject.stringField(name: String, label: String): String =
    (this[name] as? JsonPrimitive)?.takeIf(JsonPrimitive::isString)?.content
        ?: throw GccDriverStructuralProfileException("$label.$name must be a string")

private fun JsonObject.longField(name: String, label: String): Long =
    (this[name] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
        ?: throw GccDriverStructuralProfileException("$label.$name must be an integer")

private fun JsonElement.stringValue(label: String): String = jsonPrimitive.takeIf(JsonPrimitive::isString)?.content
    ?: throw GccDriverStructuralProfileException("$label must be a string")

private object GCC_STRUCTURAL_BINDING_ADMISSION_PERMIT

/** Profile-bound provenance for a full export; it is not a verified-input capability or score authority. */
internal class GccDriverStructuralFullExportBindingV2 private constructor(bytes: ByteArray) {
    private val storedBytes = bytes.copyOf()
    val canonicalBytes: ByteArray get() = storedBytes.copyOf()
    val sha256: String = OracleArtifacts.sha256(storedBytes)

    companion object {
        fun create(
            admissionPermit: Any,
            profileId: String,
            version: String,
            sourceRevision: String,
            compilerEngineProfileSha256: String,
            fullExportProfileSha256: String,
            artifactManifestSha256: String,
            targetDescriptorBytes: ByteArray,
            inputSha256: String,
            inputBytes: Long,
            exporterSha256: String,
            exporterBytes: Long,
            ghidraArchiveSha256: String,
            ghidraArchiveBytes: Long,
            programModelSha256: String,
            programModelBytes: Long,
            outputTreeSha256: String,
            functionCount: Long,
            receiptLineageBytes: ByteArray,
        ): GccDriverStructuralFullExportBindingV2 {
            check(admissionPermit === GCC_STRUCTURAL_BINDING_ADMISSION_PERMIT) {
                "GCC structural binding requires authenticated profile admission"
            }
            val target = OracleJson.parseCanonical(targetDescriptorBytes) as? JsonObject
                ?: throw GccDriverStructuralProfileException("GCC target descriptor is not a canonical object")
            val receiptLineage = OracleJson.parseCanonical(receiptLineageBytes) as? JsonObject
                ?: throw GccDriverStructuralProfileException("GCC full-export receipt lineage is not a canonical object")
            val fields = JsonObject(linkedMapOf(
                "provider" to JsonPrimitive("gcc-compiler-engine-structural-full-export-binding-v2"),
                "schemaVersion" to JsonPrimitive(2),
                "profileId" to JsonPrimitive(profileId),
                "profileVersion" to JsonPrimitive(version),
                "sourceRevision" to JsonPrimitive(sourceRevision),
                "compilerEngineProfileSha256" to JsonPrimitive(compilerEngineProfileSha256),
                "fullExportProfileSha256" to JsonPrimitive(fullExportProfileSha256),
                "artifactManifestSha256" to JsonPrimitive(artifactManifestSha256),
                "targetDescriptor" to target,
                "targetDescriptorSha256" to JsonPrimitive(OracleArtifacts.sha256(targetDescriptorBytes)),
                "inputBinary" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(inputSha256),
                    "bytes" to JsonPrimitive(inputBytes),
                )),
                "exporter" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(exporterSha256),
                    "bytes" to JsonPrimitive(exporterBytes),
                    "recoveryMode" to JsonPrimitive("full"),
                )),
                "ghidraArchive" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(ghidraArchiveSha256),
                    "bytes" to JsonPrimitive(ghidraArchiveBytes),
                )),
                "programModel" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(programModelSha256),
                    "bytes" to JsonPrimitive(programModelBytes),
                    "functionCount" to JsonPrimitive(functionCount),
                )),
                "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
                "receiptLineage" to receiptLineage,
                "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(receiptLineageBytes)),
            ))
            require(profileId.matches(Regex("[a-z0-9][a-z0-9._-]{0,127}"))) {
                "GCC structural full-export profile ID is invalid"
            }
            require(version.matches(Regex("[A-Za-z0-9._+-]{1,64}"))) {
                "GCC structural full-export profile version is invalid"
            }
            require(sourceRevision.matches(Regex("[a-f0-9]{40}"))) {
                "GCC structural full-export source revision is invalid"
            }
            listOf(
                artifactManifestSha256, fullExportProfileSha256, inputSha256, exporterSha256, ghidraArchiveSha256,
                programModelSha256, outputTreeSha256,
            ).forEach { require(it.matches(Regex("[a-f0-9]{64}"))) { "GCC structural full-export digest is invalid" } }
            require(inputBytes > 0L && exporterBytes > 0L && ghidraArchiveBytes > 0L &&
                programModelBytes > 0L && functionCount > 0L
            ) { "GCC structural full-export inventory is empty or invalid" }
            val bytes = OracleJson.canonicalBytes(fields)
            return GccDriverStructuralFullExportBindingV2(bytes)
        }
    }
}
