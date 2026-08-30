package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifactLimits
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.GeneratedCMakeReconstructionProfile
import decompengine.project.ReconstructionBudgets
import decompengine.project.ReconstructionProfile
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.util.Collections
import java.util.EnumSet
import kotlin.io.path.isExecutable
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccCompilerEngineProfileException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

data class GccCompilerEngineBudgets(
    val exportWallClockMillis: Long,
    val exportMaximumResidentBytes: Long,
    val plannerMaximumEntities: Int,
    val plannerMaximumDependencyEdges: Long,
    val plannerMaximumWorkUnits: Long,
) {
    init {
        require(exportWallClockMillis in 1..MAXIMUM_EXPORT_MILLIS)
        require(exportMaximumResidentBytes in 1..MAXIMUM_RESIDENT_BYTES)
        require(plannerMaximumEntities in 1..MAXIMUM_PLANNER_ENTITIES)
        require(plannerMaximumDependencyEdges in 1..MAXIMUM_PLANNER_EDGES)
        require(plannerMaximumWorkUnits in 1..MAXIMUM_PLANNER_WORK_UNITS)
    }

    private companion object {
        const val MAXIMUM_EXPORT_MILLIS = 24L * 60 * 60 * 1_000
        const val MAXIMUM_RESIDENT_BYTES = 64L * 1024 * 1024 * 1024
        const val MAXIMUM_PLANNER_ENTITIES = 10_000_000
        const val MAXIMUM_PLANNER_EDGES = 1_000_000_000L
        const val MAXIMUM_PLANNER_WORK_UNITS = 10_000_000_000L
    }
}

data class GccCompilerEngineArtifactBinding(
    val relativePath: String,
    val bytes: Long,
    val sha256: String,
)

data class AuthenticatedGccCompilerEngineArtifact(
    val path: Path,
    val bytes: Long,
    val sha256: String,
)

data class GccCompilerEngineAnalysisToolchain(
    val exporterId: String,
    val exporterVersion: Int,
    val exporterSha256: String,
    val exporterMode: String,
    val ghidraVersion: String,
    val ghidraRelease: String,
    val ghidraArchive: GccCompilerEngineArtifactBinding,
    val plannerId: String,
    val plannerVersion: Int,
) {
    fun authenticateGhidraArchive(path: Path): AuthenticatedGccCompilerEngineArtifact =
        authenticateLargeArtifact(path, ghidraArchive, "Ghidra release archive")

    fun requireGhidraHome(path: Path): Path {
        val home = path.toAbsolutePath().normalize()
        stableDirectory(home, "Ghidra home")
        val launcher = home.resolve("support/analyzeHeadless")
        stableFile(launcher, "Ghidra headless launcher")
        trustedPermissions(launcher, "Ghidra headless launcher")
        if (!launcher.isExecutable()) fail("Ghidra headless launcher is not executable")
        val properties = try {
            OracleArtifacts.read(home.resolve("Ghidra/application.properties"), OracleArtifactLimits(1024 * 1024)).bytes
        } catch (failure: Exception) {
            throw GccCompilerEngineProfileException("cannot authenticate Ghidra application properties", failure)
        }
        val values = properties.decodeToString().lineSequence()
            .filter { it.isNotBlank() && !it.startsWith('#') && '=' in it }
            .associate { line -> line.substringBefore('=') to line.substringAfter('=') }
        if (
            values["application.name"] != "Ghidra" || values["application.version"] != ghidraVersion ||
            values["application.release.name"] != ghidraRelease
        ) {
            fail("Ghidra installation identity differs from the compiler-engine profile")
        }
        return home
    }
}

data class GccCompilerEngine(
    val id: String,
    val buildOutput: String,
    val buildRecordPath: Path,
    val buildRecordSha256: String,
    val oracleManifestPath: Path,
    val oracleManifestSha256: String,
    val functionOracleRelativePath: String,
    val reconstructionArchiveRelativePath: String,
    val fullArtifact: GccCompilerEngineArtifactBinding,
    val strippedArtifact: GccCompilerEngineArtifactBinding,
) {
    fun authenticateStrippedArtifact(path: Path): AuthenticatedGccCompilerEngineArtifact =
        authenticateLargeArtifact(path, strippedArtifact, "GCC $id stripped artifact")

    fun authenticateFullArtifact(path: Path): AuthenticatedGccCompilerEngineArtifact =
        authenticateLargeArtifact(path, fullArtifact, "GCC $id DWARF-rich artifact")
}

data class GccCompilerEngineSuite(
    val id: String,
    val version: String,
    val target: String,
    val profilePath: Path,
    val profileSha256: String,
    val sourceLockPath: Path,
    val sourceLockSha256: String,
    val baseBuildRecordPath: Path,
    val baseBuildRecordSha256: String,
    val toolchainReproductionPath: Path,
    val toolchainReproductionSha256: String,
    val sourceRevision: String,
    val analysis: GccCompilerEngineAnalysisToolchain,
    val budgets: GccCompilerEngineBudgets,
    val engines: List<GccCompilerEngine>,
) {
    init {
        require(engines.map(GccCompilerEngine::id) == listOf("cc1", "lto1"))
    }

    fun engine(id: String): GccCompilerEngine = engines.singleOrNull { it.id == id }
        ?: throw GccCompilerEngineProfileException("unknown GCC compiler engine: $id")

    /** Program-neutral reconstruction policy with only authenticated benchmark ceilings replaced. */
    fun reconstructionProfile(): ReconstructionProfile {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val baseBudgets = base.budgets
        return ReconstructionProfile(
            schemaVersion = ReconstructionProfile.CURRENT_SCHEMA_VERSION,
            id = "${base.id}-$id",
            layout = base.layout,
            budgets = ReconstructionBudgets(
                exportWallClockMillis = budgets.exportWallClockMillis,
                exportMaximumResidentBytes = budgets.exportMaximumResidentBytes,
                plannerMaximumEntities = budgets.plannerMaximumEntities,
                plannerMaximumDependencyEdges = budgets.plannerMaximumDependencyEdges,
                plannerMaximumWorkUnits = budgets.plannerMaximumWorkUnits,
                maximumFunctionsPerModule = baseBudgets.maximumFunctionsPerModule,
                reconstructionMaximumContextCharacters = baseBudgets.reconstructionMaximumContextCharacters,
                buildWallClockMillis = baseBudgets.buildWallClockMillis,
                buildMaximumOutputBytes = baseBudgets.buildMaximumOutputBytes,
                archiveMaximumEntries = baseBudgets.archiveMaximumEntries,
                archiveMaximumFileBytes = baseBudgets.archiveMaximumFileBytes,
                archiveMaximumTotalBytes = baseBudgets.archiveMaximumTotalBytes,
            ),
            adapterConfiguration = base.adapterConfiguration + mapOf(
                "benchmark-profile-id" to listOf(id),
                "benchmark-profile-sha256" to listOf(profileSha256),
                "benchmark-target" to listOf(target),
                "benchmark-version" to listOf(version),
            ),
        )
    }
}

/** Kotlin/JVM authority for the checked GCC cc1/lto1 benchmark control plane. */
object GccCompilerEngineProfiles {
    fun load(path: Path): GccCompilerEngineSuite {
        val profileArtifact = readJsonArtifact(path, MAXIMUM_PROFILE_BYTES, "compiler-engine profile", "gcc/compiler-engines")
        val profile = profileArtifact.document
        val root = profileArtifact.path.parent
        val analysisDocument = profile.objectField("analysis")
        val exporter = analysisDocument.objectField("exporter")
        val ghidra = analysisDocument.objectField("ghidra")
        val planner = analysisDocument.objectField("planner")
        val benchmark = profile.objectField("benchmark")
        val provenance = profile.objectField("provenance")
        val budgetDocument = profile.objectField("budgets")
        val suiteId = benchmark.stringField("id")
        val version = benchmark.stringField("version")
        val target = benchmark.stringField("target")
        val budgets = GccCompilerEngineBudgets(
            exportWallClockMillis = Math.multiplyExact(budgetDocument.longField("exportWallClockSeconds"), 1_000L),
            exportMaximumResidentBytes = budgetDocument.longField("exportMaximumResidentBytes"),
            plannerMaximumEntities = budgetDocument.intField("plannerMaximumEntities"),
            plannerMaximumDependencyEdges = budgetDocument.longField("plannerMaximumDependencyEdges"),
            plannerMaximumWorkUnits = budgetDocument.longField("plannerMaximumWorkUnits"),
        )
        val analysis = GccCompilerEngineAnalysisToolchain(
            exporterId = exporter.stringField("id"),
            exporterVersion = exporter.intField("version"),
            exporterSha256 = exporter.stringField("sha256"),
            exporterMode = exporter.stringField("recoveryMode"),
            ghidraVersion = ghidra.stringField("version"),
            ghidraRelease = ghidra.stringField("release"),
            ghidraArchive = GccCompilerEngineArtifactBinding(
                relativePath = ghidra.stringField("archiveFileName"),
                bytes = ghidra.longField("archiveBytes"),
                sha256 = ghidra.stringField("archiveSha256"),
            ),
            plannerId = planner.stringField("id"),
            plannerVersion = planner.intField("version"),
        )
        authenticateAnalysisToolchain(analysis)

        val sourceLock = readBoundDependency(
            root,
            provenance.stringField("sourceLockPath"),
            provenance.stringField("sourceLockSha256"),
            MAXIMUM_CONTROL_BYTES,
            "source lock",
            "gcc/source-lock",
        )
        val baseBuild = readBoundDependency(
            root,
            provenance.stringField("baseBuildRecordPath"),
            provenance.stringField("baseBuildRecordSha256"),
            MAXIMUM_CONTROL_BYTES,
            "base build record",
            "gcc/build-record",
        )
        val toolchain = readBoundDependency(
            root,
            provenance.stringField("toolchainReproductionPath"),
            provenance.stringField("toolchainReproductionSha256"),
            MAXIMUM_CONTROL_BYTES,
            "toolchain reproduction record",
            "gcc/toolchain-reproduction",
        )
        authenticateControlRelationships(suiteId, version, sourceLock, baseBuild, toolchain)

        val engineDocuments = profile.arrayField("engines").objects("compiler engines")
        if (engineDocuments.map { it.stringField("id") } != listOf("cc1", "lto1")) {
            fail("compiler engines must be ordered cc1 then lto1")
        }
        val sourceRevision = baseBuild.document.objectField("oracle").stringField("sourceRevision")
        val engines = engineDocuments.map { engine ->
            loadEngine(root, version, sourceRevision, sourceLock, baseBuild, engine)
        }
        return GccCompilerEngineSuite(
            id = suiteId,
            version = version,
            target = target,
            profilePath = profileArtifact.path,
            profileSha256 = profileArtifact.sha256,
            sourceLockPath = sourceLock.path,
            sourceLockSha256 = sourceLock.sha256,
            baseBuildRecordPath = baseBuild.path,
            baseBuildRecordSha256 = baseBuild.sha256,
            toolchainReproductionPath = toolchain.path,
            toolchainReproductionSha256 = toolchain.sha256,
            sourceRevision = sourceRevision,
            analysis = analysis,
            budgets = budgets,
            engines = Collections.unmodifiableList(engines),
        )
    }

    private fun authenticateAnalysisToolchain(analysis: GccCompilerEngineAnalysisToolchain) {
        if (
            analysis.exporterId != "decompengine-ghidra-program-model" || analysis.exporterVersion != 9 ||
            analysis.exporterMode != "planning" ||
            analysis.plannerId != "deterministic-module-planner" || analysis.plannerVersion != 1
        ) {
            fail("compiler-engine analysis implementation identity is unsupported")
        }
        requireDigest(analysis.exporterSha256, "compiler-engine exporter")
        requireDigest(analysis.ghidraArchive.sha256, "Ghidra archive")
        val exporterBytes = GccCompilerEngineProfiles::class.java
            .getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")?.use { input ->
                input.readNBytes(MAXIMUM_EXPORTER_BYTES + 1)
            } ?: fail("bundled Ghidra program-model exporter is unavailable")
        if (exporterBytes.size > MAXIMUM_EXPORTER_BYTES) fail("bundled Ghidra exporter exceeds its byte limit")
        if (OracleArtifacts.sha256(exporterBytes) != analysis.exporterSha256) {
            fail("bundled Ghidra exporter differs from the authenticated compiler-engine profile")
        }
    }

    private fun loadEngine(
        root: Path,
        version: String,
        sourceRevision: String,
        sourceLock: JsonArtifact,
        baseBuild: JsonArtifact,
        engine: JsonObject,
    ): GccCompilerEngine {
        val id = engine.stringField("id")
        val expected = mapOf(
            "buildOutput" to "/oracle/build/gcc/$id",
            "buildRecord" to "$id-build-record.json",
            "fullArtifact" to "artifacts/gcc-$id.full",
            "functionOracle" to "$id-function-recovery-oracle.json",
            "oracleManifest" to "$id-oracle-manifest.json",
            "reconstructionArchive" to "$id-reconstruction.zip",
            "strippedArtifact" to "artifacts/gcc-$id.stripped",
        )
        expected.forEach { (field, value) ->
            if (engine.stringField(field) != value) fail("compiler engine $id has inconsistent $field")
        }

        val checkedBuild = readJsonArtifact(
            resolveBaseName(root, engine.stringField("buildRecord"), "compiler engine $id build record"),
            MAXIMUM_CONTROL_BYTES,
            "compiler engine $id build record",
            "gcc/build-record",
        )
        if (checkedBuild.sha256 != engine.stringField("buildRecordSha256")) {
            fail("compiler engine $id build record SHA-256 differs from its profile")
        }
        val derived = deriveEngineBuildRecord(baseBuild.document, engine)
        if (checkedBuild.document != derived) fail("compiler engine $id build record differs from its Kotlin derivation")

        val manifest = readJsonArtifact(
            resolveBaseName(root, engine.stringField("oracleManifest"), "compiler engine $id oracle manifest"),
            MAXIMUM_MANIFEST_BYTES,
            "compiler engine $id oracle manifest",
            "gcc/oracle-manifest",
        )
        if (manifest.sha256 != engine.stringField("oracleManifestSha256")) {
            fail("compiler engine $id oracle manifest SHA-256 differs from its profile")
        }
        authenticateManifest(
            id = id,
            version = version,
            sourceRevision = sourceRevision,
            sourceLock = sourceLock,
            buildRecord = checkedBuild,
            manifest = manifest.document,
            expectedFullPath = engine.stringField("fullArtifact"),
            expectedStrippedPath = engine.stringField("strippedArtifact"),
        )
        val artifacts = manifest.document.objectField("artifacts")
        return GccCompilerEngine(
            id = id,
            buildOutput = engine.stringField("buildOutput"),
            buildRecordPath = checkedBuild.path,
            buildRecordSha256 = checkedBuild.sha256,
            oracleManifestPath = manifest.path,
            oracleManifestSha256 = manifest.sha256,
            functionOracleRelativePath = engine.stringField("functionOracle"),
            reconstructionArchiveRelativePath = engine.stringField("reconstructionArchive"),
            fullArtifact = artifacts.objectField("full").artifactBinding("compiler engine $id full artifact"),
            strippedArtifact = artifacts.objectField("stripped").artifactBinding("compiler engine $id stripped artifact"),
        )
    }

    private fun authenticateControlRelationships(
        suiteId: String,
        version: String,
        sourceLock: JsonArtifact,
        baseBuild: JsonArtifact,
        toolchain: JsonArtifact,
    ) {
        if (suiteId != "gcc-compiler-engines-$version") fail("compiler-engine benchmark ID and version differ")
        val sourceOracle = sourceLock.document.objectField("oracle")
        val baseOracle = baseBuild.document.objectField("oracle")
        if (sourceOracle.stringField("version") != version || baseOracle.stringField("version") != version) {
            fail("compiler-engine benchmark version differs from its source or build record")
        }
        if (baseOracle.stringField("sourceLockSha256") != sourceLock.sha256) {
            fail("base build record does not bind the authenticated source lock")
        }
        val compile = baseBuild.document.objectField("commands").arrayField("compile").strings("base compile command")
        if (compile != listOf("/usr/bin/make", "-j4", "all-gcc")) {
            fail("compiler-engine base build must use the authenticated all-gcc command")
        }
        val recordedOrigin = toolchain.document.objectField("recordedOrigin")
        if (recordedOrigin.stringField("buildRecordSha256") != baseBuild.sha256) {
            fail("toolchain reproduction record does not bind the authenticated base build")
        }
        val recipe = toolchain.document.objectField("recipe")
        val dockerfile = readRawBoundDependency(
            toolchain.path.parent,
            recipe.stringField("dockerfile"),
            recipe.stringField("dockerfileSha256"),
            MAXIMUM_DOCKERFILE_BYTES,
            "toolchain Dockerfile",
        )
        if (dockerfile.bytes.isEmpty()) fail("toolchain Dockerfile must not be empty")
    }

    private fun deriveEngineBuildRecord(base: JsonObject, engine: JsonObject): JsonObject {
        val id = engine.stringField("id")
        val oracle = base.objectField("oracle")
        val commands = base.objectField("commands")
        val derivedOracle = JsonObject(
            oracle.toMutableMap().also { fields ->
                fields["sourceProfileId"] = fields.getValue("id")
                fields["id"] = JsonPrimitive("gcc-$id-${oracle.stringField("version")}")
            },
        )
        val derivedCommands = JsonObject(
            commands.toMutableMap().also { fields ->
                fields["stageFull"] = JsonArray(
                    listOf("/usr/bin/install", "-m", "0755", engine.stringField("buildOutput"), "{full}")
                        .map(::JsonPrimitive),
                )
            },
        )
        return JsonObject(
            base.toMutableMap().also { fields ->
                fields["schemaVersion"] = JsonPrimitive(3)
                fields["buildSystem"] = JsonPrimitive("autoconf")
                fields["oracle"] = derivedOracle
                fields["commands"] = derivedCommands
                fields["outputs"] = JsonObject(
                    mapOf(
                        "full" to JsonPrimitive(engine.stringField("fullArtifact")),
                        "stripped" to JsonPrimitive(engine.stringField("strippedArtifact")),
                    ),
                )
            },
        )
    }

    private fun authenticateManifest(
        id: String,
        version: String,
        sourceRevision: String,
        sourceLock: JsonArtifact,
        buildRecord: JsonArtifact,
        manifest: JsonObject,
        expectedFullPath: String,
        expectedStrippedPath: String,
    ) {
        val oracle = manifest.objectField("oracle")
        if (oracle.stringField("version") != version || oracle.stringField("sourceRevision") != sourceRevision) {
            fail("compiler engine $id oracle manifest differs from its authenticated source")
        }
        val inputs = manifest.objectField("inputs")
        inputs.objectField("sourceLock").requireFileRecord(sourceLock, sourceLock.path.fileName.toString(), "$id source lock")
        inputs.objectField("buildRecord").requireFileRecord(buildRecord, buildRecord.path.fileName.toString(), "$id build record")
        val artifacts = manifest.objectField("artifacts")
        val full = artifacts.objectField("full").artifactBinding("compiler engine $id full artifact")
        val stripped = artifacts.objectField("stripped").artifactBinding("compiler engine $id stripped artifact")
        if (full.relativePath != expectedFullPath || stripped.relativePath != expectedStrippedPath) {
            fail("compiler engine $id manifest artifact paths differ from its profile")
        }
        val equivalence = manifest.objectField("equivalence")
        val fullElf = artifacts.objectField("full").objectField("elf")
        val strippedElf = artifacts.objectField("stripped").objectField("elf")
        if (
            equivalence["elfIdentity"] != fullElf["identity"] ||
            equivalence["elfIdentity"] != strippedElf["identity"] ||
            equivalence["executableLoad"] != fullElf["executableLoad"] ||
            equivalence["executableLoad"] != strippedElf["executableLoad"]
        ) {
            fail("compiler engine $id manifest does not prove executable ELF equivalence")
        }
    }

    private fun readBoundDependency(
        root: Path,
        relative: String,
        expectedSha256: String,
        maximumBytes: Int,
        label: String,
        schemaName: String,
    ): JsonArtifact {
        requireDigest(expectedSha256, "$label binding")
        val artifact = readJsonArtifact(resolveBaseName(root, relative, label), maximumBytes, label, schemaName)
        if (artifact.sha256 != expectedSha256) fail("$label SHA-256 does not match compiler-engine profile")
        return artifact
    }

    private fun readRawBoundDependency(
        root: Path,
        relative: String,
        expectedSha256: String,
        maximumBytes: Int,
        label: String,
    ): RawArtifact {
        requireDigest(expectedSha256, "$label binding")
        val path = resolveBaseName(root, relative, label)
        val snapshot = try {
            OracleArtifacts.read(path, OracleArtifactLimits(maximumBytes))
        } catch (failure: Exception) {
            throw GccCompilerEngineProfileException("cannot read authenticated $label", failure)
        }
        if (snapshot.sha256 != expectedSha256) fail("$label SHA-256 does not match its authenticated binding")
        return RawArtifact(path.toAbsolutePath().normalize(), snapshot.bytes, snapshot.sha256)
    }

    private fun readJsonArtifact(path: Path, maximumBytes: Int, label: String, schemaName: String): JsonArtifact {
        val normalized = path.toAbsolutePath().normalize()
        val snapshot = try {
            OracleArtifacts.read(normalized, OracleArtifactLimits(maximumBytes))
        } catch (failure: Exception) {
            throw GccCompilerEngineProfileException("cannot read authenticated $label", failure)
        }
        if (snapshot.size == 0) fail("$label must not be empty")
        val document = try {
            OracleJson.parse(snapshot.bytes, jsonLimits(maximumBytes)) as? JsonObject
                ?: fail("$label root must be an object")
        } catch (failure: GccCompilerEngineProfileException) {
            throw failure
        } catch (failure: Exception) {
            throw GccCompilerEngineProfileException("$label is not strict bounded JSON", failure)
        }
        try {
            OracleSchemas.validate(schemaName, document)
        } catch (failure: Exception) {
            throw GccCompilerEngineProfileException("$label fails its bundled schema", failure)
        }
        return JsonArtifact(normalized, document, snapshot.size.toLong(), snapshot.sha256)
    }

    private fun JsonObject.requireFileRecord(actual: JsonArtifact, expectedPath: String, label: String) {
        if (
            stringField("path") != expectedPath || longField("bytes") != actual.bytes ||
            stringField("sha256") != actual.sha256
        ) {
            fail("compiler engine $label file record differs from its authenticated bytes")
        }
    }

    private fun JsonObject.artifactBinding(label: String): GccCompilerEngineArtifactBinding {
        val path = stringField("path")
        requireNormalizedRelativePath(path, label)
        val bytes = longField("bytes")
        if (bytes <= 0L || bytes > MAXIMUM_ENGINE_ARTIFACT_BYTES) fail("$label size is outside the supported bound")
        val sha256 = stringField("sha256")
        requireDigest(sha256, label)
        return GccCompilerEngineArtifactBinding(path, bytes, sha256)
    }

    private fun resolveBaseName(root: Path, relative: String, label: String): Path {
        if (relative.isBlank() || relative != Path.of(relative).fileName.toString() || '/' in relative || '\\' in relative) {
            fail("$label path must be one normalized base name")
        }
        val normalizedRoot = root.toAbsolutePath().normalize()
        val resolved = normalizedRoot.resolve(relative).normalize()
        if (resolved.parent != normalizedRoot) fail("$label path escapes its profile directory")
        return resolved
    }

    private fun requireNormalizedRelativePath(value: String, label: String) {
        if (
            value.isBlank() || value.length > 4_096 || value.startsWith('/') || '\\' in value || ':' in value ||
            value.any { it.code < 0x20 || it.code == 0x7f } ||
            value.split('/').any { it.isBlank() || it == "." || it == ".." || it.length > 255 }
        ) {
            fail("$label path is not a normalized relative path")
        }
    }

    private fun requireDigest(value: String, label: String) {
        if (!value.matches(SHA256)) fail("$label SHA-256 is invalid")
    }

    private fun jsonLimits(maximumBytes: Int) = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 128,
        maximumNodes = 1_000_000,
        maximumStringBytes = minOf(maximumBytes, 1024 * 1024),
        maximumTotalStringBytes = maximumBytes,
    )

    private data class JsonArtifact(
        val path: Path,
        val document: JsonObject,
        val bytes: Long,
        val sha256: String,
    )

    private data class RawArtifact(val path: Path, val bytes: ByteArray, val sha256: String)

    private const val MAXIMUM_PROFILE_BYTES = 1024 * 1024
    private const val MAXIMUM_CONTROL_BYTES = 32 * 1024 * 1024
    private const val MAXIMUM_MANIFEST_BYTES = 32 * 1024 * 1024
    private const val MAXIMUM_DOCKERFILE_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_EXPORTER_BYTES = 1024 * 1024
    private const val MAXIMUM_ENGINE_ARTIFACT_BYTES = 1024L * 1024 * 1024
    private val SHA256 = Regex("[0-9a-f]{64}")
}

internal fun authenticateLargeArtifact(
    path: Path,
    binding: GccCompilerEngineArtifactBinding,
    label: String,
): AuthenticatedGccCompilerEngineArtifact {
    val normalized = path.toAbsolutePath().normalize()
    val parent = normalized.parent ?: fail("$label path has no parent")
    val parentBefore = stableDirectory(parent, "$label parent")
    val before = stableFile(normalized, label)
    val permissions = trustedPermissions(normalized, label)
    if (before.size() != binding.bytes) fail("$label byte length differs from its oracle manifest")
    val digest = MessageDigest.getInstance("SHA-256")
    try {
        FileChannel.open(normalized, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            var observed = 0L
            while (observed < binding.bytes) {
                buffer.clear()
                buffer.limit(minOf(buffer.capacity().toLong(), binding.bytes - observed).toInt())
                val count = channel.read(buffer)
                if (count <= 0) fail("$label ended while hashing")
                digest.update(buffer.array(), 0, count)
                observed = Math.addExact(observed, count.toLong())
            }
            buffer.clear()
            buffer.limit(1)
            if (channel.read(buffer) >= 0 || channel.size() != binding.bytes) fail("$label changed size while hashing")
        }
    } catch (failure: GccCompilerEngineProfileException) {
        throw failure
    } catch (failure: Exception) {
        throw GccCompilerEngineProfileException("cannot hash authenticated $label", failure)
    }
    val after = stableFile(normalized, label)
    val parentAfter = stableDirectory(parent, "$label parent")
    if (!sameVersion(before, after) || parentBefore.fileKey() != parentAfter.fileKey() || permissions != trustedPermissions(normalized, label)) {
        fail("$label identity, metadata, parent, or permissions changed while hashing")
    }
    val actualSha256 = digest.digest().hex()
    if (actualSha256 != binding.sha256) fail("$label SHA-256 differs from its oracle manifest")
    return AuthenticatedGccCompilerEngineArtifact(normalized, binding.bytes, actualSha256)
}

internal fun stableDirectory(path: Path, label: String): BasicFileAttributes {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = try {
        Files.readAttributes(normalized, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw GccCompilerEngineProfileException("$label is unavailable", failure)
    }
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        fail("$label must be an identified real directory")
    }
    if (normalized.toRealPath() != normalized) fail("$label path contains a symbolic link")
    trustedPermissions(normalized, label)
    return attributes
}

internal fun stableFile(path: Path, label: String): BasicFileAttributes {
    val attributes = try {
        Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw GccCompilerEngineProfileException("$label is unavailable", failure)
    }
    if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
        fail("$label must be an identified regular file")
    }
    if (path.toRealPath() != path) fail("$label path contains a symbolic link")
    return attributes
}

internal fun trustedPermissions(path: Path, label: String): Set<PosixFilePermission> {
    val permissions = try {
        Files.getFileAttributeView(path, PosixFileAttributeView::class.java, LinkOption.NOFOLLOW_LINKS)
            ?.readAttributes()?.permissions()
    } catch (failure: Exception) {
        throw GccCompilerEngineProfileException("$label permissions are unavailable", failure)
    } ?: fail("$label requires POSIX permissions")
    if (permissions.any { it in UNTRUSTED_WRITE_PERMISSIONS }) fail("$label is writable by an untrusted principal")
    return HashSet(permissions)
}

internal fun sameVersion(left: BasicFileAttributes, right: BasicFileAttributes): Boolean =
    left.fileKey() == right.fileKey() && left.size() == right.size() &&
        left.lastModifiedTime() == right.lastModifiedTime()

private fun JsonObject.objectField(name: String): JsonObject = this[name] as? JsonObject
    ?: fail("compiler-engine field $name is not an object")

private fun JsonObject.arrayField(name: String): JsonArray = this[name] as? JsonArray
    ?: fail("compiler-engine field $name is not an array")

private fun JsonObject.stringField(name: String): String {
    val primitive = this[name] as? JsonPrimitive ?: fail("compiler-engine field $name is not a string")
    if (!primitive.isString) fail("compiler-engine field $name is not a string")
    return primitive.content
}

private fun JsonObject.longField(name: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: fail("compiler-engine field $name is not an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) fail("compiler-engine field $name is not an integer")
    return primitive.content.toLongOrNull() ?: fail("compiler-engine field $name exceeds the Kotlin integer range")
}

private fun JsonObject.intField(name: String): Int {
    val value = longField(name)
    if (value !in 1..Int.MAX_VALUE.toLong()) fail("compiler-engine field $name exceeds the Kotlin integer range")
    return value.toInt()
}

private fun JsonArray.objects(label: String): List<JsonObject> = map { value ->
    value as? JsonObject ?: fail("$label contains a non-object")
}

private fun JsonArray.strings(label: String): List<String> = map { value ->
    val primitive = value as? JsonPrimitive ?: fail("$label contains a non-string")
    if (!primitive.isString) fail("$label contains a non-string")
    primitive.content
}

private fun ByteArray.hex(): String = joinToString("") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun fail(message: String): Nothing = throw GccCompilerEngineProfileException(message)

private val UNTRUSTED_WRITE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
    PosixFilePermission.GROUP_WRITE,
    PosixFilePermission.OTHERS_WRITE,
)
