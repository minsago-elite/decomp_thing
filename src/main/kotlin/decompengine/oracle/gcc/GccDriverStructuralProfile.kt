package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.provenance.BoundedElfTwinV1
import decompengine.oracle.provenance.BoundedElfTwinV1Limits
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
    val architecture: String,
    val abi: String,
    val elfClass: String,
    val dataEncoding: String,
    val pointerBits: Int,
)

internal data class GccDriverStructuralBinaryV1(
    val path: Path,
    val bytes: Long,
    val sha256: String,
    val elfType: String,
)

/**
 * The fixed GCC driver input set, authenticated from the checked source/build manifest and both
 * ELF twins. It only admits benchmark inputs; it does not claim that a model has been exported.
 */
internal class GccDriverStructuralInputsV1 private constructor(
    val root: Path,
    val profileId: String,
    val version: String,
    val sourceRevision: String,
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

    companion object {
        private const val PROFILE_ID = "gcc-driver-16.2.0"
        private const val PROFILE_VERSION = "16.2.0"
        private const val SOURCE_REVISION = "78d4ac73dd391005b895a6148cd9831e28e1208b"
        private const val MANIFEST_SHA256 = "c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9"
        private const val SOURCE_LOCK_SHA256 = "e2930ecc9748b40e56d6fe09dbe88f21f735953d4e6da50403f2cc0aa5b650cc"
        private const val BUILD_RECORD_SHA256 = "f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637"
        private const val TOOLCHAIN_REPRODUCTION_SHA256 = "5c2c159d7287305159a220a1260f6ff6bffe9ec78bb1cbe2fb24f85b68a7d4de"
        private const val MAXIMUM_CONTROL_BYTES = 4 * 1024 * 1024
        private const val MAXIMUM_MANIFEST_BYTES = 64 * 1024 * 1024
        private const val MAXIMUM_BINARY_BYTES = 64L * 1024 * 1024
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
                "GCC structural profile root is not the pinned driver version directory"
            }

            val manifest = readJson(root.resolve("oracle-manifest.json"), MAXIMUM_MANIFEST_BYTES, "gcc/oracle-manifest")
            requireDigest(manifest.sha256, MANIFEST_SHA256, "GCC driver artifact manifest")
            val manifestOracle = manifest.document.objectField("oracle", "GCC artifact manifest")
            require(manifestOracle.stringField("id", "GCC artifact manifest oracle") == PROFILE_ID &&
                manifestOracle.stringField("version", "GCC artifact manifest oracle") == PROFILE_VERSION &&
                manifestOracle.stringField("sourceRevision", "GCC artifact manifest oracle") == SOURCE_REVISION
            ) { "GCC artifact manifest differs from the pinned driver profile" }

            val sourceLock = readJson(root.resolve("source-lock.json"), MAXIMUM_CONTROL_BYTES, "gcc/source-lock")
            requireDigest(sourceLock.sha256, SOURCE_LOCK_SHA256, "GCC source lock")
            val sourceOracle = sourceLock.document.objectField("oracle", "GCC source lock")
            val sourceRevision = sourceLock.document.objectField("revision", "GCC source lock")
                .stringField("commit", "GCC source revision")
            require(sourceOracle.stringField("id", "GCC source lock oracle") == PROFILE_ID &&
                sourceOracle.stringField("version", "GCC source lock oracle") == PROFILE_VERSION &&
                sourceRevision == SOURCE_REVISION
            ) { "GCC source lock differs from the pinned driver profile" }

            val buildRecord = readJson(root.resolve("build-record.json"), MAXIMUM_CONTROL_BYTES, "gcc/build-record")
            requireDigest(buildRecord.sha256, BUILD_RECORD_SHA256, "GCC driver build record")
            val buildOracle = buildRecord.document.objectField("oracle", "GCC build record")
            require(buildOracle.stringField("id", "GCC build record oracle") == PROFILE_ID &&
                buildOracle.stringField("version", "GCC build record oracle") == PROFILE_VERSION &&
                buildOracle.stringField("sourceRevision", "GCC build record oracle") == SOURCE_REVISION &&
                buildOracle.stringField("sourceLockSha256", "GCC build record oracle") == sourceLock.sha256
            ) { "GCC build record is not derived from the pinned source lock" }

            val manifestInputs = manifest.document.objectField("inputs", "GCC artifact manifest")
            requireFileRecord(manifestInputs.objectField("sourceLock", "GCC artifact manifest inputs"),
                "source-lock.json", sourceLock)
            requireFileRecord(manifestInputs.objectField("buildRecord", "GCC artifact manifest inputs"),
                "build-record.json", buildRecord)

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

            val fullPath = root.resolve("artifacts/gcc-driver.full")
            val strippedPath = root.resolve("artifacts/gcc-driver.stripped")
            require(fullPath.toRealPath() == fullPath && strippedPath.toRealPath() == strippedPath) {
                "GCC driver artifact paths must not contain links"
            }
            val pair = BoundedElfTwinV1.inspectTwin(
                fullPath,
                strippedPath,
                BoundedElfTwinV1Limits(
                    maximumFileBytes = MAXIMUM_BINARY_BYTES,
                    maximumRangeBytes = MAXIMUM_BINARY_BYTES,
                    maximumExecutableBytes = MAXIMUM_BINARY_BYTES,
                    maximumAggregateHashedBytes = 2 * MAXIMUM_BINARY_BYTES,
                ),
            )
            val manifestArtifacts = manifest.document.objectField("artifacts", "GCC artifact manifest")
            val full = requireBinaryRecord(
                manifestArtifacts.objectField("full", "GCC artifact manifest artifacts"),
                "artifacts/gcc-driver.full", pair.full,
            )
            val stripped = requireBinaryRecord(
                manifestArtifacts.objectField("stripped", "GCC artifact manifest artifacts"),
                "artifacts/gcc-driver.stripped", pair.stripped,
            )
            requireTwinEquivalence(manifest.document.objectField("equivalence", "GCC artifact manifest"), pair)

            val target = requireTarget(pair.stripped.elf.header.elfClass, pair.stripped.elf.header.dataEncoding,
                pair.stripped.elf.header.machine.toInt(), pair.stripped.elf.header.typeName)
            val imageBase = pair.stripped.elf.programHeaders
                .filter { it.typeName == "PT_LOAD" && it.memorySize > 0UL }
                .minOfOrNull { it.virtualAddress }
                ?: profileFail("GCC driver has no nonempty loadable ELF segment")
            val ranges = executableRanges(pair.stripped.elf.programHeaders, imageBase)
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
                sourceRevision = sourceRevision,
                artifactManifestSha256 = manifest.sha256,
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

        private fun requireBinaryRecord(
            document: JsonObject,
            expectedPath: String,
            actual: decompengine.oracle.provenance.BoundedElfArtifactV1,
        ): GccDriverStructuralBinaryV1 {
            require(document.stringField("path", "GCC artifact record") == expectedPath &&
                document.longField("bytes", "GCC artifact record") == actual.bytes &&
                document.stringField("sha256", "GCC artifact record") == actual.sha256
            ) { "GCC ELF artifact differs from its authenticated manifest record" }
            val elf = document.objectField("elf", "GCC artifact record")
            val header = elf.objectField("header", "GCC ELF record")
            require(header.stringField("class", "GCC ELF header") == actual.elf.header.elfClass &&
                header.stringField("dataEncoding", "GCC ELF header") == actual.elf.header.dataEncoding &&
                header.stringField("typeName", "GCC ELF header") == actual.elf.header.typeName &&
                header.longField("machine", "GCC ELF header") == actual.elf.header.machine.toLong()
            ) { "GCC ELF target facts differ from the authenticated manifest" }
            val load = elf.objectField("executableLoad", "GCC ELF record")
            require(load.stringField("sha256", "GCC executable-load record") == actual.elf.executableLoad.sha256 &&
                load.longField("bytes", "GCC executable-load record") == actual.elf.executableLoad.bytes
            ) { "GCC executable load differs from the authenticated manifest" }
            val manifestBuildIds = elf.arrayField("buildIds", "GCC ELF record").map { value ->
                value.stringValue("GCC ELF build ID")
            }
            require(manifestBuildIds == actual.elf.buildIds) { "GCC ELF build ID differs from the authenticated manifest" }
            return GccDriverStructuralBinaryV1(
                actual.path, actual.bytes, actual.sha256, actual.elf.header.typeName,
            )
        }

        private fun requireTwinEquivalence(
            document: JsonObject,
            actual: decompengine.oracle.provenance.BoundedElfTwinResultV1,
        ) {
            val identity = document.objectField("elfIdentity", "GCC ELF twin equivalence")
            require(identity.stringField("class", "GCC ELF twin identity") == actual.equivalence.elfIdentity.elfClass &&
                identity.stringField("dataEncoding", "GCC ELF twin identity") == actual.equivalence.elfIdentity.dataEncoding &&
                identity.longField("type", "GCC ELF twin identity") == actual.equivalence.elfIdentity.type.toLong() &&
                identity.longField("machine", "GCC ELF twin identity") == actual.equivalence.elfIdentity.machine.toLong() &&
                document.stringField("buildId", "GCC ELF twin equivalence") == actual.equivalence.buildId &&
                document.stringField("programHeadersSha256", "GCC ELF twin equivalence") ==
                    actual.equivalence.programHeadersSha256 &&
                document.stringField("allocatedSectionsSha256", "GCC ELF twin equivalence") ==
                    actual.equivalence.allocatedSectionsSha256
            ) { "GCC ELF twin identity differs from the authenticated manifest" }
            val load = document.objectField("executableLoad", "GCC ELF twin equivalence")
            require(load.stringField("sha256", "GCC twin executable load") == actual.equivalence.executableLoad.sha256 &&
                load.longField("bytes", "GCC twin executable load") == actual.equivalence.executableLoad.bytes
            ) { "GCC ELF twin executable load differs from the authenticated manifest" }
        }

        private fun requireTarget(
            elfClass: String,
            dataEncoding: String,
            machine: Int,
            elfType: String,
        ): GccDriverStructuralTargetAbiV1 {
            require(elfClass == "ELF64" && dataEncoding == "little-endian" && machine == 62 && elfType == "ET_EXEC") {
                "GCC driver ELF differs from its fixed x86-64 SysV target profile"
            }
            return GccDriverStructuralTargetAbiV1(
                id = "x86_64-sysv-amd64-v1",
                architecture = "x86_64",
                abi = "sysv-amd64",
                elfClass = elfClass,
                dataEncoding = dataEncoding,
                pointerBits = 64,
            )
        }

        private fun executableRanges(
            headers: List<decompengine.oracle.provenance.BoundedElfProgramHeaderV1>,
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
            require(ranges.isNotEmpty()) { "GCC driver has no file-backed executable load range" }
            require(ranges.zipWithNext().all { (left, right) -> left.endExclusiveRva <= right.startRva }) {
                "GCC driver executable PT_LOAD ranges overlap"
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

        private fun requireFileRecord(document: JsonObject, expectedPath: String, actual: JsonArtifact) {
            require(document.stringField("path", "GCC manifest file record") == expectedPath &&
                document.longField("bytes", "GCC manifest file record") == actual.bytes &&
                document.stringField("sha256", "GCC manifest file record") == actual.sha256
            ) { "GCC artifact manifest input record does not match its authenticated file" }
        }

        private fun requireDigest(actual: String, expected: String, label: String) {
            require(actual == expected) { "$label SHA-256 differs from the fixed GCC driver profile" }
        }

        private fun translateProfileFailure(action: () -> GccDriverStructuralInputsV1): GccDriverStructuralInputsV1 = try {
            action()
        } catch (failure: GccDriverStructuralProfileException) {
            throw failure
        } catch (failure: Exception) {
            throw GccDriverStructuralProfileException("cannot authenticate the GCC driver structural input profile", failure)
        }

        private fun profileFail(message: String): Nothing = throw GccDriverStructuralProfileException(message)
    }
}

private data class JsonArtifact(val bytes: Long, val sha256: String, val document: JsonObject)

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
