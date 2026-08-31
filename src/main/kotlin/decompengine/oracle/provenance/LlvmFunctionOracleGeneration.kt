package decompengine.oracle.provenance

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.BoundedDwarfFunctionFactLimits
import decompengine.oracle.fulltree.BoundedDwarfFunctionFactScanner
import decompengine.oracle.fulltree.BoundedDwarfFunctionFacts
import decompengine.oracle.fulltree.BoundedFunctionEvidence
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.FullTreeControlLimits
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.structural.StructuralRecoveryV1Inputs
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class LlvmFunctionOracleGenerationException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

internal enum class LlvmFunctionOracleGenerationPoint {
    AFTER_STAGE_VALIDATION,
}

internal fun interface LlvmFunctionOracleGenerationFaultInjector {
    fun hit(point: LlvmFunctionOracleGenerationPoint)
}

/** Immutable diagnostics exposed after raw inputs have produced a fully validated publication. */
internal sealed interface LlvmFunctionOracleGeneration {
    val outputPath: Path
    val outputSha256: String
    val outputBytes: Int
    val manifestSha256: String
    val richArtifactSha256: String
    val strippedArtifactSha256: String
    val functions: Int
    val exclusions: Int
}

private data class ExplicitFunctionExclusions(
    val richArtifactSha256: String,
    val entries: Map<ULong, String>,
    val bytes: ByteArray,
    val sha256: String,
)

/**
 * Kotlin/JVM production authority for the historical LLVM function-oracle v1 document.
 *
 * Its only authority inputs are the raw artifact manifest, raw reviewed exclusion profile,
 * artifact-root directory, and absent output path. The Clang selectors, 16-byte near-miss policy,
 * traversal limits, schema, and semantic validator are closed implementation policy. No parsed
 * facts, selector, token, or caller-supplied limit can enter this boundary.
 */
internal object LlvmFunctionOracleGenerator {
    fun generate(
        manifestPath: Path,
        exclusionsPath: Path,
        artifactRoot: Path,
        outputPath: Path,
    ): LlvmFunctionOracleGeneration = ProductionGeneration(
        manifestPath,
        exclusionsPath,
        artifactRoot,
        outputPath,
    )

    private class ProductionGeneration(
        manifestPath: Path,
        exclusionsPath: Path,
        artifactRootPath: Path,
        outputPathValue: Path,
    ) : LlvmFunctionOracleGeneration {
        private val result = generateProduction(
            manifestPath,
            exclusionsPath,
            artifactRootPath,
            outputPathValue,
        )

        override val outputPath: Path = result.outputPath
        override val outputSha256: String = result.outputSha256
        override val outputBytes: Int = result.outputBytes
        override val manifestSha256: String = result.manifestSha256
        override val richArtifactSha256: String = result.richArtifactSha256
        override val strippedArtifactSha256: String = result.strippedArtifactSha256
        override val functions: Int = result.functions
        override val exclusions: Int = result.exclusions
    }
}

private data class GenerationResult(
    override val outputPath: Path,
    override val outputSha256: String,
    override val outputBytes: Int,
    override val manifestSha256: String,
    override val richArtifactSha256: String,
    override val strippedArtifactSha256: String,
    override val functions: Int,
    override val exclusions: Int,
) : LlvmFunctionOracleGeneration

private fun generateProduction(
    manifestPathValue: Path,
    exclusionsPathValue: Path,
    artifactRootValue: Path,
    outputPathValue: Path,
    faultInjector: LlvmFunctionOracleGenerationFaultInjector? = null,
): GenerationResult = translateFunctionGenerationFailure {
    val manifestPath = normalizedFilePath(manifestPathValue, "LLVM artifact manifest")
    val exclusionsPath = normalizedFilePath(exclusionsPathValue, "LLVM function exclusions")
    val artifactRoot = normalizedDirectoryPath(artifactRootValue, "LLVM artifact root")
    val outputPath = normalizedFilePath(outputPathValue, "LLVM function-oracle output")
    val initial = LlvmArtifactManifestVerifier.verify(manifestPath, artifactRoot)
    val richPath = resolveArtifactPath(artifactRoot, initial.full.path, "rich LLVM artifact")
    val strippedPath = resolveArtifactPath(artifactRoot, initial.stripped.path, "stripped LLVM artifact")
    requireDistinctPaths(
        outputPath,
        manifestPath,
        exclusionsPath,
        richPath,
        strippedPath,
    )

    val outputParent = checkNotNull(outputPath.parent)
    requirePrivateOutputParent(outputParent)
    val stageDirectory = Files.createTempDirectory(outputParent, ".llvm-function-oracle-stage-")
        .toAbsolutePath().normalize()
    Files.setPosixFilePermissions(stageDirectory, PosixFilePermissions.fromString("rwx------"))
    var stageDocument: Path? = null
    try {
        StableControlFile.open(
            exclusionsPath,
            MAXIMUM_EXCLUSION_BYTES.toLong(),
            "LLVM function exclusions",
        ).use { exclusionFile ->
            val exclusions = readExclusions(exclusionFile)
            if (exclusions.richArtifactSha256 != initial.full.sha256) {
                functionGenerationFail(
                    "reviewed exclusion profile is not bound to the verified rich LLVM artifact",
                )
            }
            StableControlFile.open(
                richPath,
                MAXIMUM_ARTIFACT_BYTES,
                "rich LLVM artifact",
            ).use { richFile ->
                StableControlFile.open(
                    strippedPath,
                    MAXIMUM_ARTIFACT_BYTES,
                    "stripped LLVM artifact",
                ).use { strippedFile ->
                    val rich = BoundedDwarfFunctionFactScanner.scan(
                        artifact = richFile,
                        twin = "rich",
                        scratchParent = stageDirectory,
                        symbolNameSelected = ::llvmDriverSymbol,
                        compilationUnitSelected = ::llvmDriverCompilationUnit,
                        includeInlineOnly = false,
                        controlLimits = functionControlLimits(),
                        limits = functionFactLimits(),
                    )
                    val stripped = BoundedDwarfFunctionFactScanner.scan(
                        artifact = strippedFile,
                        twin = "stripped",
                        scratchParent = stageDirectory,
                        symbolNameSelected = ::llvmDriverSymbol,
                        compilationUnitSelected = ::llvmDriverCompilationUnit,
                        includeInlineOnly = false,
                        controlLimits = functionControlLimits(),
                        limits = functionFactLimits(),
                    )
                    requireScanIdentity(rich, initial.full, "rich")
                    requireScanIdentity(stripped, initial.stripped, "stripped")
                    val document = FunctionOracleV1Composer.compose(
                        oracleId = initial.oracleId,
                        artifactManifestSha256 = initial.manifestSha256,
                        rich = rich,
                        stripped = stripped,
                        exclusions = exclusions.entries,
                        includeInlineOnly = false,
                    )
                    try {
                        OracleSchemas.validate("function-recovery-oracle", document)
                    } catch (failure: Exception) {
                        throw LlvmFunctionOracleGenerationException(
                            "generated LLVM function oracle fails its bundled schema",
                            failure,
                        )
                    }
                    val bytes = OracleJson.canonicalBytes(document, FUNCTION_JSON_LIMITS)
                    if (bytes.size !in 1..MAXIMUM_OUTPUT_BYTES) {
                        functionGenerationFail("generated LLVM function oracle exceeds its byte bound")
                    }
                    val staged = stageDirectory.resolve("function-recovery-oracle.json")
                    writePrivateStage(staged, bytes)
                    stageDocument = staged
                    val semantic = StructuralRecoveryV1Inputs.loadFunctionOracle(staged)
                    if (
                        semantic.scope != "production" || semantic.id != initial.oracleId ||
                        semantic.artifactManifestSha256 != initial.manifestSha256 ||
                        semantic.nearMissBytes != LLVM_NEAR_MISS_BYTES ||
                        !MessageDigest.isEqual(OracleJson.canonicalBytes(semantic.document, FUNCTION_JSON_LIMITS), bytes)
                    ) {
                        functionGenerationFail(
                            "generated LLVM function oracle fails structural v1 semantic validation",
                        )
                    }
                    faultInjector?.hit(LlvmFunctionOracleGenerationPoint.AFTER_STAGE_VALIDATION)

                    richFile.verifyUnchanged("rich LLVM artifact before function-oracle publication")
                    strippedFile.verifyUnchanged("stripped LLVM artifact before function-oracle publication")
                    exclusionFile.verifyUnchanged("LLVM function exclusions before publication")
                    val terminalExclusionBytes = exclusionFile.readExactly(
                        0L,
                        exclusionFile.size.toInt(),
                        "LLVM function exclusions",
                    )
                    if (
                        !MessageDigest.isEqual(exclusions.bytes, terminalExclusionBytes) ||
                        OracleArtifacts.sha256(terminalExclusionBytes) != exclusions.sha256
                    ) {
                        functionGenerationFail("LLVM function exclusions changed during generation")
                    }
                    val terminal = LlvmArtifactManifestVerifier.verify(manifestPath, artifactRoot)
                    requireSameManifestVerification(initial, terminal)
                    if (
                        richFile.sha256(label = "terminal rich LLVM artifact") != initial.full.sha256 ||
                        strippedFile.sha256(label = "terminal stripped LLVM artifact") != initial.stripped.sha256
                    ) {
                        functionGenerationFail("LLVM artifacts changed during function-oracle generation")
                    }

                    val published = FunctionOracleNoReplacePublisher.publish(outputPath, bytes)
                    return@translateFunctionGenerationFailure GenerationResult(
                        outputPath = outputPath,
                        outputSha256 = published.sha256,
                        outputBytes = bytes.size,
                        manifestSha256 = initial.manifestSha256,
                        richArtifactSha256 = initial.full.sha256,
                        strippedArtifactSha256 = initial.stripped.sha256,
                        functions = document.requiredArray("functions").size,
                        exclusions = document.requiredArray("functions").count { function ->
                            (function as JsonObject)["exclusion"] != JsonNull
                        },
                    )
                }
            }
        }
    } finally {
        val staged = stageDocument
        if (staged != null) Files.deleteIfExists(staged)
        val residues = Files.list(stageDirectory).use { entries -> entries.toList() }
        if (residues.isNotEmpty()) {
            throw LlvmFunctionOracleGenerationException(
                "LLVM function-oracle scratch retained unexpected files: ${residues.size}",
            )
        }
        Files.deleteIfExists(stageDirectory)
    }
}

/** Pure composition surface used only by parity and hostile tests; it is not an authority. */
internal object LlvmFunctionOracleTestSupport {
    fun compose(
        oracleId: String,
        artifactManifestSha256: String,
        rich: BoundedDwarfFunctionFacts,
        stripped: BoundedDwarfFunctionFacts,
        exclusions: Map<ULong, String> = emptyMap(),
    ): JsonObject = FunctionOracleV1Composer.compose(
        oracleId,
        artifactManifestSha256,
        rich,
        stripped,
        exclusions,
        includeInlineOnly = false,
    )

    fun publishNoReplace(output: Path, bytes: ByteArray): String =
        FunctionOracleNoReplacePublisher.publish(output, bytes).sha256

    fun generateWithFault(
        manifestPath: Path,
        exclusionsPath: Path,
        artifactRoot: Path,
        outputPath: Path,
        faultInjector: LlvmFunctionOracleGenerationFaultInjector,
    ): LlvmFunctionOracleGeneration = generateProduction(
        manifestPath,
        exclusionsPath,
        artifactRoot,
        outputPath,
        faultInjector,
    )
}

private object FunctionOracleV1Composer {
    fun compose(
        oracleId: String,
        artifactManifestSha256: String,
        rich: BoundedDwarfFunctionFacts,
        stripped: BoundedDwarfFunctionFacts,
        exclusions: Map<ULong, String>,
        includeInlineOnly: Boolean,
    ): JsonObject {
        requireProfileText(oracleId, 4096, "oracle id")
        requireSha256(artifactManifestSha256, "artifact manifest SHA-256")
        if (
            rich.elfType != stripped.elfType || rich.imageBase != stripped.imageBase ||
            rich.executableRanges != stripped.executableRanges
        ) {
            functionGenerationFail("ELF twins disagree on type, image base, or executable ranges")
        }
        val strippedOnlyRvas = stripped.aliasesByRva.keys - rich.aliasesByRva.keys
        if (strippedOnlyRvas.isNotEmpty()) {
            functionGenerationFail(
                "stripped twin introduces an emitted RVA absent from the rich twin: " +
                    canonicalHex(strippedOnlyRvas.min()),
            )
        }
        val absentExclusions = exclusions.keys - rich.aliasesByRva.keys
        if (absentExclusions.isNotEmpty()) {
            functionGenerationFail(
                "explicit exclusion does not identify an emitted rich RVA: " +
                    canonicalHex(absentExclusions.min()),
            )
        }
        exclusions.values.forEach { reason ->
            requireProfileText(reason, 16_384, "explicit exclusion reason")
        }

        val functions = ArrayList<JsonElement>()
        rich.aliasesByRva.toSortedMap().forEach { (rva, richAliases) ->
            val strippedAliases = stripped.aliasesByRva[rva].orEmpty()
            val strippedOnlyNames = strippedAliases.keys - richAliases.keys
            if (strippedOnlyNames.isNotEmpty()) {
                functionGenerationFail(
                    "stripped twin introduces alias ${strippedOnlyNames.minWith(CODE_POINT_ORDER)} at ${canonicalHex(rva)}",
                )
            }
            val aliases = richAliases.entries.sortedWith { left, right ->
                CODE_POINT_ORDER.compare(left.key, right.key)
            }.map { (name, richEvidence) ->
                val evidence = (richEvidence + strippedAliases[name].orEmpty())
                    .distinct()
                    .sortedWith(EVIDENCE_ORDER)
                if (evidence.isEmpty() || evidence.size > MAXIMUM_EVIDENCE) {
                    functionGenerationFail("generated alias evidence count is outside limits")
                }
                JsonObject(
                    mapOf(
                        "name" to JsonPrimitive(name),
                        "evidence" to JsonArray(evidence.map(::evidenceDocument)),
                        "availability" to JsonObject(
                            mapOf(
                                "rich" to JsonPrimitive("surviving"),
                                "stripped" to JsonPrimitive(
                                    if (name in strippedAliases) "surviving" else "removed",
                                ),
                            ),
                        ),
                    ),
                )
            }
            if (aliases.isEmpty() || aliases.size > MAXIMUM_ALIASES) {
                functionGenerationFail("emitted RVA ${canonicalHex(rva)} has an unsupported alias count")
            }
            functions += JsonObject(
                mapOf(
                    "id" to JsonPrimitive("function-rva-${canonicalHex(rva)}"),
                    "rva" to JsonPrimitive(canonicalHex(rva)),
                    "aliases" to JsonArray(aliases),
                    "exclusion" to (exclusions[rva]?.let { reason ->
                        JsonObject(
                            mapOf(
                                "kind" to JsonPrimitive("compiler-generated"),
                                "reason" to JsonPrimitive(reason),
                            ),
                        )
                    } ?: JsonNull),
                ),
            )
        }
        if (includeInlineOnly) {
            rich.inlineOnly.sortedBy { it.first }.forEach { (dieOffset, aliasesByName) ->
                val aliases = aliasesByName.entries.sortedWith { left, right ->
                    CODE_POINT_ORDER.compare(left.key, right.key)
                }.map { (name, evidence) ->
                    JsonObject(
                        mapOf(
                            "name" to JsonPrimitive(name),
                            "evidence" to JsonArray(evidence.sortedWith(EVIDENCE_ORDER).map(::evidenceDocument)),
                            "availability" to JsonObject(
                                mapOf(
                                    "rich" to JsonPrimitive("not-observable"),
                                    "stripped" to JsonPrimitive("not-observable"),
                                ),
                            ),
                        ),
                    )
                }
                functions += JsonObject(
                    mapOf(
                        "id" to JsonPrimitive("inline-die-${canonicalHex(dieOffset)}"),
                        "rva" to JsonNull,
                        "aliases" to JsonArray(aliases),
                        "exclusion" to JsonObject(
                            mapOf(
                                "kind" to JsonPrimitive("inlined"),
                                "reason" to JsonPrimitive(INLINE_EXCLUSION_REASON),
                            ),
                        ),
                    ),
                )
            }
        }
        if (functions.size !in 1..MAXIMUM_FUNCTIONS) {
            functionGenerationFail("generated function count is outside schema limits")
        }
        return JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "scope" to JsonPrimitive("production"),
                "oracle" to JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(oracleId),
                        "source" to JsonPrimitive("dwarf-and-symbols"),
                        "artifactManifestSha256" to JsonPrimitive(artifactManifestSha256),
                    ),
                ),
                "artifacts" to JsonObject(
                    mapOf(
                        "rich" to artifactDocument(rich),
                        "stripped" to artifactDocument(stripped),
                    ),
                ),
                "scoringPolicy" to JsonObject(
                    mapOf("nearMissBytes" to JsonPrimitive(LLVM_NEAR_MISS_BYTES)),
                ),
                "functions" to JsonArray(functions),
            ),
        )
    }

    private fun artifactDocument(facts: BoundedDwarfFunctionFacts): JsonObject {
        if (facts.executableRanges.size !in 1..256) {
            functionGenerationFail("ELF executable-range count is outside schema limits")
        }
        return JsonObject(
            mapOf(
                "inputSha256" to JsonPrimitive(facts.inputSha256),
                "elfType" to JsonPrimitive(facts.elfType),
                "elfImageBase" to JsonPrimitive(canonicalHex(facts.imageBase)),
                "executableRvaRanges" to JsonArray(facts.executableRanges.map(::rangeDocument)),
            ),
        )
    }

    private fun rangeDocument(range: FullTreeElfExecutableRange): JsonObject = JsonObject(
        mapOf(
            "start" to JsonPrimitive(canonicalHex(range.start)),
            "endExclusive" to JsonPrimitive(canonicalHex(range.endExclusive)),
        ),
    )

    private fun evidenceDocument(evidence: BoundedFunctionEvidence): JsonObject = JsonObject(
        mapOf(
            "kind" to JsonPrimitive(evidence.kind),
            "locator" to JsonPrimitive(evidence.locator),
        ),
    )
}

private fun readExclusions(file: StableControlFile): ExplicitFunctionExclusions {
    if (file.size > MAXIMUM_EXCLUSION_BYTES.toLong()) {
        functionGenerationFail("LLVM function exclusions exceed their byte bound")
    }
    val bytes = file.readExactly(0L, file.size.toInt(), "LLVM function exclusions")
    file.verifyUnchanged("LLVM function exclusions")
    val document = try {
        OracleJson.parseCanonical(bytes, EXCLUSION_JSON_LIMITS) as? JsonObject
            ?: functionGenerationFail("LLVM function exclusions root must be an object")
    } catch (failure: LlvmFunctionOracleGenerationException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmFunctionOracleGenerationException(
            "LLVM function exclusions are not strict canonical JSON",
            failure,
        )
    }
    document.requireExactKeys(setOf("schemaVersion", "richArtifactSha256", "exclusions"), "exclusions")
    if (document["schemaVersion"] != JsonPrimitive(1)) {
        functionGenerationFail("LLVM function exclusions schemaVersion must be 1")
    }
    val artifactSha256 = document.requiredString("richArtifactSha256")
    requireSha256(artifactSha256, "LLVM exclusion artifact SHA-256")
    val entries = LinkedHashMap<ULong, String>()
    var previous: ULong? = null
    document.requiredArray("exclusions").forEachIndexed { index, element ->
        val item = element as? JsonObject
            ?: functionGenerationFail("LLVM function exclusion $index must be an object")
        item.requireExactKeys(setOf("rva", "reason"), "exclusion $index")
        val rvaText = item.requiredString("rva")
        val rva = parseCanonicalAddress(rvaText, "exclusion $index RVA")
        if (previous != null && rva <= checkNotNull(previous)) {
            functionGenerationFail("LLVM function exclusion RVAs must be unique and increasing")
        }
        val reason = item.requiredString("reason")
        requireProfileText(reason, 16_384, "exclusion $index reason")
        entries[rva] = reason
        previous = rva
    }
    if (entries.size > MAXIMUM_FUNCTIONS) {
        functionGenerationFail("LLVM function exclusions exceed the function-record limit")
    }
    return ExplicitFunctionExclusions(
        artifactSha256,
        Collections.unmodifiableMap(entries),
        bytes.copyOf(),
        OracleArtifacts.sha256(bytes),
    )
}

private data class FunctionOraclePublication(
    val sha256: String,
)

/** Dedicated 64 MiB ceiling; the general descriptor-bound state primitive remains capped at 1 MiB. */
private object FunctionOracleNoReplacePublisher {
    fun publish(path: Path, bytesValue: ByteArray): FunctionOraclePublication {
        val bytes = bytesValue.copyOf()
        if (bytes.size !in 1..MAXIMUM_OUTPUT_BYTES) {
            functionGenerationFail("function-oracle publication exceeds its dedicated byte bound")
        }
        val target = normalizedFilePath(path, "function-oracle publication target")
        val parentPath = normalizedDirectoryPath(checkNotNull(target.parent), "function-oracle publication parent")
        requirePrivateOutputParent(parentPath)
        val name = target.fileName.toString()
        if (!PUBLICATION_NAME.matches(name) || name.toByteArray(Charsets.UTF_8).size > 220) {
            functionGenerationFail("function-oracle publication name is invalid")
        }
        LinuxFilesystemSyscalls.openRoot(parentPath).use { parent ->
            requirePublicationParent(parent)
            LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)?.use {
                functionGenerationFail("function-oracle publication target already exists")
            }
            val temporaryName = ".$name.function-oracle.atomic"
            LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName)?.use {
                functionGenerationFail("function-oracle publication temporary already exists")
            }
            var prepared: LinuxDescriptor? = null
            var materialized = false
            try {
                prepared = LinuxFilesystemSyscalls.createTemporaryAt(parent.fd)
                LinuxFilesystemSyscalls.write(prepared, bytes) {}
                LinuxFilesystemSyscalls.chmod(prepared, OWNER_READ_ONLY_MODE)
                LinuxFilesystemSyscalls.synchronize(prepared)
                val preparedIdentity = LinuxFilesystemSyscalls.identity(prepared.fd)
                requirePreparedIdentity(preparedIdentity, parent.identity, linked = false)
                LinuxFilesystemSyscalls.linkTemporaryAt(prepared, parent.fd, temporaryName)
                materialized = true
                val staged = readPublished(parent, temporaryName, bytes.size)
                if (!sameFile(preparedIdentity, staged.first) || !MessageDigest.isEqual(bytes, staged.second)) {
                    functionGenerationFail("function-oracle publication temporary differs from prepared bytes")
                }
                LinuxFilesystemSyscalls.synchronize(parent)
                LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)?.use {
                    functionGenerationFail("function-oracle publication target appeared before commit")
                }
                LinuxFilesystemSyscalls.renameNoReplace(parent.fd, temporaryName, name)
                materialized = false
                LinuxFilesystemSyscalls.synchronize(parent)
                val published = readPublished(parent, name, bytes.size)
                if (!sameFile(preparedIdentity, published.first) || !MessageDigest.isEqual(bytes, published.second)) {
                    functionGenerationFail("published function oracle differs from prepared bytes")
                }
                return FunctionOraclePublication(OracleArtifacts.sha256(bytes))
            } finally {
                prepared?.close()
                if (materialized) {
                    val current = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, temporaryName)
                    if (current != null) {
                        current.use {
                            val preparedIdentity = prepared?.identity
                            if (preparedIdentity != null && sameFile(preparedIdentity, current.identity)) {
                                LinuxFilesystemSyscalls.unlink(parent.fd, temporaryName)
                                LinuxFilesystemSyscalls.synchronize(parent)
                            }
                        }
                    }
                }
            }
        }
    }

    private fun readPublished(
        parent: LinuxDescriptor,
        name: String,
        expectedBytes: Int,
    ): Pair<LinuxFileIdentity, ByteArray> {
        val selected = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
            ?: functionGenerationFail("function-oracle publication file is missing")
        selected.use {
            requirePreparedIdentity(selected.identity, parent.identity, linked = true)
            val bytes = LinuxFilesystemSyscalls.openReadableFrom(selected).use { readable ->
                LinuxFilesystemSyscalls.read(readable, expectedBytes) {}
            }
            if (bytes.size != expectedBytes) {
                functionGenerationFail("function-oracle publication file has the wrong size")
            }
            val after = LinuxFilesystemSyscalls.identity(selected.fd)
            if (after != selected.identity) {
                functionGenerationFail("function-oracle publication file changed while read")
            }
            return after to bytes
        }
    }

    private fun requirePublicationParent(parent: LinuxDescriptor) {
        val current = LinuxFilesystemSyscalls.identity(parent.fd)
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        if (
            current != parent.identity || !current.isDirectory || current.isSymbolicLink ||
            current.uid != uid || current.mode.permissions != OWNER_DIRECTORY_MODE
        ) {
            functionGenerationFail("function-oracle publication parent is not a pinned owner-only directory")
        }
    }

    private fun requirePreparedIdentity(
        identity: LinuxFileIdentity,
        parent: LinuxFileIdentity,
        linked: Boolean,
    ) {
        if (
            !identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
            identity.mountId != parent.mountId || identity.uid != parent.uid ||
            identity.mode.permissions != OWNER_READ_ONLY_MODE || identity.linkCount != if (linked) 1 else 0
        ) {
            functionGenerationFail("function-oracle publication inode violates private immutable policy")
        }
    }

    private fun sameFile(first: LinuxFileIdentity, second: LinuxFileIdentity): Boolean =
        first.key == second.key && first.mountId == second.mountId && first.uid == second.uid &&
            first.gid == second.gid && first.isRegularFile && second.isRegularFile &&
            !first.isSymbolicLink && !second.isSymbolicLink
}

private fun writePrivateStage(path: Path, bytes: ByteArray) {
    FileChannel.open(
        path,
        setOf(StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS),
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
    ).use { channel ->
        val source = ByteBuffer.wrap(bytes)
        while (source.hasRemaining()) channel.write(source)
        channel.force(true)
    }
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    FileChannel.open(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
}

private fun requireScanIdentity(
    facts: BoundedDwarfFunctionFacts,
    expected: LlvmArtifactManifestArtifactIdentity,
    twin: String,
) {
    if (facts.inputSha256 != expected.sha256) {
        functionGenerationFail("$twin function scan differs from the verified LLVM artifact")
    }
}

private fun requireSameManifestVerification(
    first: LlvmArtifactManifestVerification,
    second: LlvmArtifactManifestVerification,
) {
    if (
        first.manifestPath != second.manifestPath || first.artifactRoot != second.artifactRoot ||
        first.manifestSha256 != second.manifestSha256 || first.sourceLockPath != second.sourceLockPath ||
        first.sourceLockSha256 != second.sourceLockSha256 || first.buildRecordPath != second.buildRecordPath ||
        first.buildRecordSha256 != second.buildRecordSha256 || first.oracleId != second.oracleId ||
        first.version != second.version || first.sourceRevision != second.sourceRevision ||
        first.full != second.full || first.stripped != second.stripped || first.buildId != second.buildId
    ) {
        functionGenerationFail("LLVM artifact manifest verification changed during function generation")
    }
}

private fun resolveArtifactPath(root: Path, relative: String, label: String): Path {
    val relativePath = try {
        Path.of(relative)
    } catch (failure: Exception) {
        throw LlvmFunctionOracleGenerationException("$label path is invalid", failure)
    }
    if (relativePath.isAbsolute) functionGenerationFail("$label path must be relative")
    val resolved = root.resolve(relativePath).normalize()
    if (!resolved.startsWith(root) || resolved == root) {
        functionGenerationFail("$label path escapes the artifact root")
    }
    return resolved
}

private fun requireDistinctPaths(output: Path, vararg inputs: Path) {
    if (inputs.any { it == output }) {
        functionGenerationFail("function-oracle output must not replace a generation input")
    }
    if (inputs.toSet().size != inputs.size) {
        functionGenerationFail("function-oracle generation inputs must have distinct paths")
    }
}

private fun requirePrivateOutputParent(path: Path) {
    val permissions = try {
        Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw LlvmFunctionOracleGenerationException("function-oracle output parent is unavailable", failure)
    }
    if (permissions != PosixFilePermissions.fromString("rwx------")) {
        functionGenerationFail("function-oracle output parent must have POSIX mode 0700")
    }
}

private fun normalizedFilePath(path: Path, label: String): Path {
    val normalized = path.toAbsolutePath().normalize()
    if (normalized.fileName == null || normalized.parent == null) {
        functionGenerationFail("$label must name a file")
    }
    return normalized
}

private fun normalizedDirectoryPath(path: Path, label: String): Path {
    val normalized = path.toAbsolutePath().normalize()
    val attributes = try {
        Files.readAttributes(normalized, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
    } catch (failure: Exception) {
        throw LlvmFunctionOracleGenerationException("$label is unavailable", failure)
    }
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
        functionGenerationFail("$label must be an identified real directory")
    }
    val real = try {
        normalized.toRealPath()
    } catch (failure: Exception) {
        throw LlvmFunctionOracleGenerationException("$label cannot be resolved", failure)
    }
    if (real != normalized) functionGenerationFail("$label path contains a symbolic link")
    return normalized
}

private fun llvmDriverSymbol(name: String): Boolean =
    name == "main" || name == "clang_main" || name.startsWith("_ZN5clang6driver")

private fun llvmDriverCompilationUnit(path: String): Boolean =
    "/clang/lib/Driver/" in path || path.endsWith("/clang/tools/driver/driver.cpp")

private fun functionControlLimits(): FullTreeControlLimits = FullTreeControlLimits(
    maximumRichArtifactBytes = MAXIMUM_ARTIFACT_BYTES,
    maximumDwarfSectionBytes = MAXIMUM_ARTIFACT_BYTES,
    maximumDwarfScratchBytes = 1024L * 1024L * 1024L,
    maximumDwarfMetadataBytes = 256L * 1024L * 1024L,
    maximumDwarfAttributeBytes = 16 * 1024 * 1024,
    maximumDwarfParseSteps = 100_000_000L,
    maximumCompilationUnits = 1_000_000,
)

private fun functionFactLimits(): BoundedDwarfFunctionFactLimits = BoundedDwarfFunctionFactLimits(
    maximumArtifactBytes = MAXIMUM_ARTIFACT_BYTES,
)

private fun JsonObject.requireExactKeys(expected: Set<String>, label: String) {
    if (keys != expected) functionGenerationFail("$label has invalid fields")
}

private fun JsonObject.requiredString(name: String): String {
    val value = this[name] as? JsonPrimitive
        ?: functionGenerationFail("$name must be a string")
    if (!value.isString) functionGenerationFail("$name must be a string")
    return value.content
}

private fun JsonObject.requiredArray(name: String): JsonArray = this[name] as? JsonArray
    ?: functionGenerationFail("$name must be an array")

private fun parseCanonicalAddress(value: String, label: String): ULong {
    if (!CANONICAL_ADDRESS.matches(value)) functionGenerationFail("$label is not canonical")
    return value.removePrefix("0x").toULongOrNull(16)
        ?: functionGenerationFail("$label exceeds unsigned 64-bit range")
}

private fun requireProfileText(value: String, maximumCharacters: Int, label: String) {
    if (
        value.isEmpty() || '\u0000' in value ||
        value.codePointCount(0, value.length) > maximumCharacters
    ) functionGenerationFail("$label is invalid")
}

private fun requireSha256(value: String, label: String) {
    if (!SHA256.matches(value)) functionGenerationFail("$label is invalid")
}

private fun canonicalHex(value: ULong): String = "0x${value.toString(16)}"

private inline fun <T> translateFunctionGenerationFailure(action: () -> T): T = try {
    action()
} catch (failure: LlvmFunctionOracleGenerationException) {
    throw failure
} catch (failure: LlvmArtifactManifestException) {
    throw LlvmFunctionOracleGenerationException("LLVM artifact manifest verification failed", failure)
} catch (failure: FullTreeControlException) {
    throw LlvmFunctionOracleGenerationException("bounded ELF/DWARF function scan failed", failure)
} catch (failure: IOException) {
    throw LlvmFunctionOracleGenerationException("LLVM function-oracle filesystem operation failed", failure)
} catch (failure: Exception) {
    throw LlvmFunctionOracleGenerationException("LLVM function-oracle generation failed closed", failure)
}

private fun functionGenerationFail(message: String): Nothing =
    throw LlvmFunctionOracleGenerationException(message)

private val CODE_POINT_ORDER = Comparator<String> { left, right ->
    var leftOffset = 0
    var rightOffset = 0
    while (leftOffset < left.length && rightOffset < right.length) {
        val leftPoint = Character.codePointAt(left, leftOffset)
        val rightPoint = Character.codePointAt(right, rightOffset)
        if (leftPoint != rightPoint) return@Comparator leftPoint.compareTo(rightPoint)
        leftOffset += Character.charCount(leftPoint)
        rightOffset += Character.charCount(rightPoint)
    }
    (left.length - leftOffset).compareTo(right.length - rightOffset)
}
private val EVIDENCE_ORDER = Comparator<BoundedFunctionEvidence> { left, right ->
    CODE_POINT_ORDER.compare(left.kind, right.kind).takeIf { it != 0 }
        ?: CODE_POINT_ORDER.compare(left.locator, right.locator)
}
private val FUNCTION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024,
    maximumDepth = 128,
    maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024,
    maximumTotalStringBytes = 64 * 1024 * 1024,
    maximumNumberCharacters = 128,
)
private val EXCLUSION_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 4 * 1024 * 1024,
    maximumCanonicalBytes = 4 * 1024 * 1024,
    maximumDepth = 16,
    maximumNodes = 100_000,
    maximumStringBytes = 16 * 1024,
    maximumTotalStringBytes = 4 * 1024 * 1024,
    maximumNumberCharacters = 64,
)
private const val MAXIMUM_ARTIFACT_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_EXCLUSION_BYTES = 4 * 1024 * 1024
private const val MAXIMUM_OUTPUT_BYTES = 64 * 1024 * 1024
private const val MAXIMUM_FUNCTIONS = 20_000
private const val MAXIMUM_ALIASES = 256
private const val MAXIMUM_EVIDENCE = 256
private const val LLVM_NEAR_MISS_BYTES = 16
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
private const val OWNER_READ_ONLY_MODE = 0x100 // 0400
private const val INLINE_EXCLUSION_REASON =
    "DWARF subprogram is marked inline-only and has no emitted address range."
private val SHA256 = Regex("[0-9a-f]{64}")
private val CANONICAL_ADDRESS = Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})")
private val PUBLICATION_NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,218}[A-Za-z0-9]")
