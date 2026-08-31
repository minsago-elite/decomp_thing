package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.provenance.BoundedTarEntryKind
import decompengine.oracle.provenance.BoundedTarXzArchive
import decompengine.oracle.provenance.BoundedTarXzException
import decompengine.oracle.provenance.BoundedTarXzLimits
import decompengine.oracle.provenance.BoundedTarXzSource
import java.nio.file.Path
import java.util.TreeSet
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

data class FullTreeSourceInventoryGeneration(
    val report: JsonObject,
    val reportSha256: String,
    val sourceArchiveSha256: String,
    val outputSha256: String,
    val outputBytes: Long,
)

/** Authoritative Kotlin/JVM generation and validation of full-tree-source-inventory v1. */
object FullTreeSourceInventoryControl {
    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256("full-tree-source-inventory", SOURCE_INVENTORY_POLICY)
    }

    fun generateAndPublish(
        archive: Path,
        scope: AuthenticatedFullTreeScope,
        buildRecordPath: Path,
        inventoryPath: Path,
        output: Path,
        maximumWorkers: Int,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): FullTreeSourceInventoryGeneration {
        if (maximumWorkers !in 1..limits.maximumWorkers) {
            throw FullTreeControlException("source-inventory worker count exceeds its configured bound")
        }
        requireDistinctControlOutput(
            output,
            "source archive" to archive,
            "build record" to buildRecordPath,
            "DWARF inventory" to inventoryPath,
        )
        FullTreeScopeControl.validate(scope, limits)
        val (buildRecord, buildBytes) = readCanonicalControlObject(
            buildRecordPath,
            limits.maximumBuildRecordBytes,
            "build record",
            "build-record",
        )
        val inventory = FullTreeInventoryControl.loadAndValidate(inventoryPath, scope, limits)
        authenticateBuildRecord(buildRecord, scope)
        val archiveRecord = scope.sourceLock.controlObject("source").controlObject("archive")
        val expectedArchiveBytes = archiveRecord.controlLong("bytes")
        val expectedArchiveSha256 = archiveRecord.controlString("sha256")
        requireControlDigest(expectedArchiveSha256, "source archive")
        val sourceArchive = StableControlFile.open(
            archive,
            minOf(expectedArchiveBytes, limits.maximumSourceArchiveBytes),
            "source archive",
        )
        try {
            if (sourceArchive.size != expectedArchiveBytes) {
                throw FullTreeControlException("source archive byte count differs from its lock")
            }
            val observedArchiveSha256 = sourceArchive.sha256()
            if (observedArchiveSha256 != expectedArchiveSha256) {
                throw FullTreeControlException("source archive differs from its lock")
            }
            val archiveIndex = SourceTarIndex.read(sourceArchive, scope, limits)
            sourceArchive.verifyUnchanged("source archive")
            val report = buildReport(
                archiveIndex,
                scope,
                buildRecord,
                buildBytes,
                inventory,
                sourceArchive.size,
                observedArchiveSha256,
                limits,
            )
            validate(report, scope, buildRecord, inventory, limits, archiveIndex)
            val outputBytes = publishCanonicalControl(output, report, limits.maximumSourceInventoryBytes)
            return FullTreeSourceInventoryGeneration(
                report = report,
                reportSha256 = report.controlString("reportSha256"),
                sourceArchiveSha256 = observedArchiveSha256,
                outputSha256 = OracleArtifacts.sha256(outputBytes),
                outputBytes = outputBytes.size.toLong(),
            )
        } finally {
            sourceArchive.close()
        }
    }

    fun loadAndValidate(
        path: Path,
        scope: AuthenticatedFullTreeScope,
        buildRecordPath: Path,
        inventoryPath: Path,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ): JsonObject {
        val (buildRecord, _) = readCanonicalControlObject(
            buildRecordPath,
            limits.maximumBuildRecordBytes,
            "build record",
            "build-record",
        )
        val inventory = FullTreeInventoryControl.loadAndValidate(inventoryPath, scope, limits)
        val (report, _) = readCanonicalControlObject(
            path,
            limits.maximumSourceInventoryBytes,
            "full-tree source inventory",
            "full-tree-source-inventory",
        )
        validate(report, scope, buildRecord, inventory, limits)
        return report
    }

    fun validate(
        value: JsonObject,
        scope: AuthenticatedFullTreeScope,
        buildRecord: JsonObject,
        inventory: JsonObject,
        limits: FullTreeControlLimits = FullTreeControlLimits(),
    ) = validate(value, scope, buildRecord, inventory, limits, archiveIndex = null)

    private fun validate(
        value: JsonObject,
        scope: AuthenticatedFullTreeScope,
        buildRecordValue: JsonObject,
        inventoryValue: JsonObject,
        limits: FullTreeControlLimits,
        archiveIndex: SourceArchiveIndex?,
    ) {
        FullTreeScopeControl.validate(scope, limits)
        val (buildRecord, buildBytes) = snapshotControlObject(
            buildRecordValue,
            limits.maximumBuildRecordBytes,
            "build record",
            "build-record",
        )
        val (inventory, _) = snapshotControlObject(
            inventoryValue,
            limits.maximumInventoryBytes,
            "full-tree inventory",
            "full-tree-inventory",
        )
        FullTreeInventoryControl.validate(inventory, scope, limits)
        authenticateBuildRecord(buildRecord, scope)
        val (report, _) = snapshotControlObject(
            value,
            limits.maximumSourceInventoryBytes,
            "full-tree source inventory",
            "full-tree-source-inventory",
        )
        val withoutHash = JsonObject(report.filterKeys { it != "reportSha256" })
        val expectedReportSha = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(withoutHash, controlJsonLimits(limits.maximumSourceInventoryBytes)),
        )
        if (report.controlString("reportSha256") != expectedReportSha) {
            throw FullTreeControlException("source inventory hash does not reconcile")
        }
        val archiveRecord = scope.sourceLock.controlObject("source").controlObject("archive")
        val expectedOracle = JsonObject(
            mapOf(
                "buildRecordSha256" to JsonPrimitive(OracleArtifacts.sha256(buildBytes)),
                "configurationSha256" to JsonPrimitive(configurationSha256),
                "inventoryIndexSha256" to inventory["indexSha256"]!!,
                "scopeSha256" to JsonPrimitive(scope.sha256),
                "sourceArchiveBytes" to archiveRecord["bytes"]!!,
                "sourceArchiveSha256" to archiveRecord["sha256"]!!,
                "sourceLockSha256" to JsonPrimitive(scope.sourceLockSha256),
            ),
        )
        if (report.controlObject("oracle") != expectedOracle) {
            throw FullTreeControlException("source inventory bindings differ")
        }
        val configure = buildRecord.controlObject("commands").controlArray("configure")
        val disabled = report.controlObject("build").controlArray("disabledProjects")
            .map { it.controlString("disabled project") }
        if (disabled != disabled.sortedWith(FULL_TREE_CODE_POINT_ORDER) || disabled.toSet().size != disabled.size ||
            disabled.any { it !in PROJECT_DIRECTORIES || it in ENABLED_PROJECTS }
        ) {
            throw FullTreeControlException("source inventory disabled projects are not canonical")
        }
        val expectedBuild = JsonObject(
            mapOf(
                "configureSha256" to JsonPrimitive(
                    OracleArtifacts.sha256(
                        OracleJson.canonicalBytes(configure, controlJsonLimits(limits.maximumBuildRecordBytes)),
                    ),
                ),
                "disabledProjects" to JsonArray(disabled.map(::JsonPrimitive)),
                "enabledProjects" to JsonArray(ENABLED_PROJECTS.map(::JsonPrimitive)),
                "targets" to JsonArray(ENABLED_TARGETS.map(::JsonPrimitive)),
            ),
        )
        if (report.controlObject("build") != expectedBuild) {
            throw FullTreeControlException("source inventory build bindings differ")
        }
        val inventoryUnits = inventory.controlArray("units").controlObjects("inventory units")
        val handwrittenById = inventoryUnits.filter { it.controlString("sourceKind") == "handwritten" }
            .associateBy { it.controlString("id") }
        val handwrittenByPath = handwrittenById.values.associateBy { it.controlString("sourcePath") }
        if (handwrittenByPath.size != handwrittenById.size) {
            throw FullTreeControlException("inventory handwritten source ownership is duplicated")
        }
        val sourceUnits = report.controlArray("sourceUnits").controlObjects("source inventory units")
        if (sourceUnits != sourceUnits.sortedWith(compareByCodePoint("path")) ||
            sourceUnits.map { it.controlString("path") }.toSet().size != sourceUnits.size
        ) {
            throw FullTreeControlException("source units are not ordered and unique")
        }
        val linkedIds = HashSet<String>()
        sourceUnits.forEach { unit ->
            val path = unit.controlString("path")
            val classification = unit.controlString("classification")
            val reason = nullableControlString(unit["reasonCode"], "source unit reason")
            val unitId = nullableControlString(unit["unitId"], "source unit ID")
            val expectedLinked = handwrittenByPath[path]
            if (classification == "linked") {
                if (expectedLinked == null || reason != null || unitId == null ||
                    unitId != expectedLinked.controlString("id") ||
                    unit.controlString("shardId") != expectedLinked.controlString("shardId") || !linkedIds.add(unitId)
                ) {
                    throw FullTreeControlException("linked source unit ownership differs from inventory")
                }
            } else {
                if (expectedLinked != null || unitId != null || reason != sourceOnlyReason(path) ||
                    unit.controlString("shardId") != FullTreeScopeControl.shardForSourcePath(scope.document, path)
                ) {
                    throw FullTreeControlException("source-only unit classification differs from policy")
                }
            }
        }
        if (linkedIds != handwrittenById.keys) {
            throw FullTreeControlException("source inventory does not cover every handwritten DWARF unit")
        }
        val generated = report.controlArray("generatedCompilationUnits")
            .controlObjects("generated compilation units")
        val expectedGenerated = inventoryUnits.filter { it.controlString("sourceKind") == "generated" }
            .map { unit ->
                JsonObject(
                    mapOf(
                        "path" to unit["sourcePath"]!!,
                        "shardId" to unit["shardId"]!!,
                        "unitId" to unit["id"]!!,
                    ),
                )
            }.sortedWith(compareByCodePoint("unitId"))
        if (generated != expectedGenerated) {
            throw FullTreeControlException("source inventory does not cover every generated DWARF unit")
        }
        val tablegen = report.controlArray("tablegenInputs").controlObjects("TableGen inputs")
        if (tablegen != tablegen.sortedWith(compareByCodePoint("path")) ||
            tablegen.map { it.controlString("path") }.toSet().size != tablegen.size
        ) {
            throw FullTreeControlException("TableGen inputs are not ordered and unique")
        }
        tablegen.forEach { input ->
            val expected = if (
                input.controlString("path").removePrefix("source/").startsWithAny(ENABLED_PROJECT_PREFIXES)
            ) {
                "enabled-project-input"
            } else {
                "disabled-project-input"
            }
            if (input.controlString("classification") != expected) {
                throw FullTreeControlException("TableGen input classification differs from policy")
            }
        }
        archiveIndex?.let { index ->
            val expectedSourcePaths = candidateTranslationUnits(index.names)
            if (sourceUnits.map { it.controlString("path") } != expectedSourcePaths) {
                throw FullTreeControlException("source inventory candidate population differs from archive")
            }
            val expectedTablegenPaths = index.names.filter { it.endsWith(".td") }
                .sortedWith(FULL_TREE_CODE_POINT_ORDER).map { "source/$it" }
            if (tablegen.map { it.controlString("path") } != expectedTablegenPaths) {
                throw FullTreeControlException("source inventory TableGen population differs from archive")
            }
            val expectedDisabled = TreeSet(FULL_TREE_CODE_POINT_ORDER).apply {
                addAll(index.topLevel.filter { it in PROJECT_DIRECTORIES && it !in ENABLED_PROJECTS })
            }.toList()
            if (disabled != expectedDisabled) {
                throw FullTreeControlException("source inventory disabled-project population differs from archive")
            }
        }
        val linked = sourceUnits.count { it.controlString("classification") == "linked" }.toLong()
        val expectedCounts = JsonObject(
            mapOf(
                "candidateTranslationUnits" to JsonPrimitive(sourceUnits.size.toLong()),
                "disabledProjects" to JsonPrimitive(disabled.size.toLong()),
                "generatedCompilationUnits" to JsonPrimitive(generated.size.toLong()),
                "linkedSourceUnits" to JsonPrimitive(linked),
                "sourceOnlyUnits" to JsonPrimitive(sourceUnits.size.toLong() - linked),
                "tablegenInputs" to JsonPrimitive(tablegen.size.toLong()),
            ),
        )
        if (report.controlObject("counts") != expectedCounts) {
            throw FullTreeControlException("source inventory counts do not reconcile")
        }
    }

    private fun buildReport(
        archive: SourceArchiveIndex,
        scope: AuthenticatedFullTreeScope,
        buildRecord: JsonObject,
        buildBytes: ByteArray,
        inventory: JsonObject,
        archiveBytes: Long,
        archiveSha256: String,
        limits: FullTreeControlLimits,
    ): JsonObject {
        val inventoryUnits = inventory.controlArray("units").controlObjects("inventory units")
        val linkedByPath = inventoryUnits.filter { it.controlString("sourceKind") == "handwritten" }
            .associateBy { it.controlString("sourcePath") }
        val candidates = candidateTranslationUnits(archive.names)
        val candidateSet = candidates.toHashSet()
        if (linkedByPath.keys.any { it !in candidateSet }) {
            throw FullTreeControlException("DWARF inventory contains a handwritten unit absent from source candidates")
        }
        val sourceUnits = candidates.map { path ->
            val linked = linkedByPath[path]
            JsonObject(
                mapOf(
                    "classification" to JsonPrimitive(if (linked == null) "source-only" else "linked"),
                    "path" to JsonPrimitive(path),
                    "reasonCode" to (linked?.let { JsonNull } ?: JsonPrimitive(sourceOnlyReason(path))),
                    "shardId" to (
                        linked?.get("shardId")
                            ?: JsonPrimitive(FullTreeScopeControl.shardForSourcePath(scope.document, path))
                    ),
                    "unitId" to (linked?.get("id") ?: JsonNull),
                ),
            )
        }
        val tablegenInputs = archive.names.filter { it.endsWith(".td") }
            .sortedWith(FULL_TREE_CODE_POINT_ORDER)
            .map { name ->
                JsonObject(
                    mapOf(
                        "classification" to JsonPrimitive(
                            if (name.startsWithAny(ENABLED_PROJECT_PREFIXES)) {
                                "enabled-project-input"
                            } else {
                                "disabled-project-input"
                            },
                        ),
                        "path" to JsonPrimitive("source/$name"),
                    ),
                )
            }
        val disabledProjects = TreeSet(FULL_TREE_CODE_POINT_ORDER).apply {
            addAll(archive.topLevel.filter { it in PROJECT_DIRECTORIES && it !in ENABLED_PROJECTS })
        }.toList()
        val generatedUnits = inventoryUnits.filter { it.controlString("sourceKind") == "generated" }
            .map { unit ->
                JsonObject(
                    mapOf(
                        "path" to unit["sourcePath"]!!,
                        "shardId" to unit["shardId"]!!,
                        "unitId" to unit["id"]!!,
                    ),
                )
            }.sortedWith(compareByCodePoint("unitId"))
        val linkedCount = sourceUnits.count { it.controlString("classification") == "linked" }
        val counts = JsonObject(
            mapOf(
                "candidateTranslationUnits" to JsonPrimitive(sourceUnits.size),
                "disabledProjects" to JsonPrimitive(disabledProjects.size),
                "generatedCompilationUnits" to JsonPrimitive(generatedUnits.size),
                "linkedSourceUnits" to JsonPrimitive(linkedCount),
                "sourceOnlyUnits" to JsonPrimitive(sourceUnits.size - linkedCount),
                "tablegenInputs" to JsonPrimitive(tablegenInputs.size),
            ),
        )
        val configure = buildRecord.controlObject("commands").controlArray("configure")
        val withoutHash = JsonObject(
            mapOf(
                "build" to JsonObject(
                    mapOf(
                        "configureSha256" to JsonPrimitive(
                            OracleArtifacts.sha256(
                                OracleJson.canonicalBytes(
                                    configure,
                                    controlJsonLimits(limits.maximumBuildRecordBytes),
                                ),
                            ),
                        ),
                        "disabledProjects" to JsonArray(disabledProjects.map(::JsonPrimitive)),
                        "enabledProjects" to JsonArray(ENABLED_PROJECTS.map(::JsonPrimitive)),
                        "targets" to JsonArray(ENABLED_TARGETS.map(::JsonPrimitive)),
                    ),
                ),
                "counts" to counts,
                "generatedCompilationUnits" to JsonArray(generatedUnits),
                "oracle" to JsonObject(
                    mapOf(
                        "buildRecordSha256" to JsonPrimitive(OracleArtifacts.sha256(buildBytes)),
                        "configurationSha256" to JsonPrimitive(configurationSha256),
                        "inventoryIndexSha256" to inventory["indexSha256"]!!,
                        "scopeSha256" to JsonPrimitive(scope.sha256),
                        "sourceArchiveBytes" to JsonPrimitive(archiveBytes),
                        "sourceArchiveSha256" to JsonPrimitive(archiveSha256),
                        "sourceLockSha256" to JsonPrimitive(scope.sourceLockSha256),
                    ),
                ),
                "schemaVersion" to JsonPrimitive(1),
                "sourceUnits" to JsonArray(sourceUnits),
                "tablegenInputs" to JsonArray(tablegenInputs),
            ),
        )
        val reportHash = OracleArtifacts.sha256(
            OracleJson.canonicalBytes(withoutHash, controlJsonLimits(limits.maximumSourceInventoryBytes)),
        )
        return JsonObject(withoutHash + ("reportSha256" to JsonPrimitive(reportHash)))
    }

    private fun authenticateBuildRecord(buildRecord: JsonObject, scope: AuthenticatedFullTreeScope) {
        val configure = buildRecord.controlObject("commands").controlArray("configure")
            .map { it.controlString("build configure argument") }
        if ("-DLLVM_ENABLE_PROJECTS=clang" !in configure || "-DLLVM_TARGETS_TO_BUILD=X86" !in configure) {
            throw FullTreeControlException("build record does not select the locked Clang/X86 scope")
        }
        val buildOracle = buildRecord.controlObject("oracle")
        if (buildOracle.controlString("sourceLockSha256") != scope.sourceLockSha256) {
            throw FullTreeControlException("build record source-lock binding differs from scope")
        }
    }

    private fun candidateTranslationUnits(names: Set<String>): List<String> = names.asSequence()
        .filter { name -> name.startsWithAny(SOURCE_PREFIXES) && translationUnitSuffix(name) in TU_SUFFIXES }
        .map { "source/$it" }
        .sortedWith(FULL_TREE_CODE_POINT_ORDER)
        .toList()

    private fun translationUnitSuffix(path: String): String {
        val name = path.substringAfterLast('/')
        val dot = name.lastIndexOf('.')
        return if (dot <= 0 || dot == name.lastIndex) "" else name.substring(dot)
    }

    private fun sourceOnlyReason(path: String): String {
        val relative = path.removePrefix("source/")
        return when {
            relative.startsWith("clang/tools/") || relative.startsWith("llvm/tools/") ->
                "tool-not-linked-into-clang-driver"
            relative.startsWith("llvm/lib/Target/") && !relative.startsWith("llvm/lib/Target/X86/") ->
                "target-not-enabled-or-not-linked"
            else -> "not-selected-by-authenticated-build-graph"
        }
    }

    private fun compareByCodePoint(field: String): Comparator<JsonObject> = Comparator { left, right ->
        FULL_TREE_CODE_POINT_ORDER.compare(left.controlString(field), right.controlString(field))
    }

    private fun String.startsWithAny(prefixes: List<String>): Boolean = prefixes.any(::startsWith)

    private fun nullableControlString(value: JsonElement?, label: String): String? = when (value) {
        null -> throw FullTreeControlException("$label is absent")
        JsonNull -> null
        else -> value.controlString(label)
    }

    private val TU_SUFFIXES = listOf(".C", ".S", ".c", ".cc", ".cpp", ".cxx", ".s")
    private val SOURCE_PREFIXES = listOf("clang/lib/", "clang/tools/", "llvm/lib/", "llvm/tools/")
    private val ENABLED_PROJECT_PREFIXES = listOf("clang/", "llvm/")
    private val ENABLED_PROJECTS = listOf("clang", "llvm")
    private val ENABLED_TARGETS = listOf("X86")
    private val PROJECT_DIRECTORIES = setOf(
        "bolt",
        "clang",
        "clang-tools-extra",
        "compiler-rt",
        "cross-project-tests",
        "flang",
        "flang-rt",
        "libc",
        "libclc",
        "libcxx",
        "libcxxabi",
        "libsycl",
        "libunwind",
        "lld",
        "lldb",
        "llvm",
        "llvm-libgcc",
        "mlir",
        "offload",
        "openmp",
        "orc-rt",
        "polly",
        "runtimes",
    )
    private val SOURCE_INVENTORY_POLICY = JsonObject(
        mapOf(
            "id" to JsonPrimitive("full-tree-source-inventory"),
            "sourcePrefixes" to JsonArray(SOURCE_PREFIXES.map(::JsonPrimitive)),
            "translationUnitSuffixes" to JsonArray(TU_SUFFIXES.map(::JsonPrimitive)),
            "version" to JsonPrimitive(1),
        ),
    )
}

internal data class SourceArchiveIndex(val names: Set<String>, val topLevel: Set<String>)

internal object SourceTarIndex {
    fun read(
        archive: StableControlFile,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeControlLimits,
    ): SourceArchiveIndex {
        val archiveRoot = scope.sourceLock.controlObject("source").controlString("archiveRoot")
        if (archiveRoot != HISTORICAL_ARCHIVE_ROOT) {
            throw FullTreeControlException("source lock archive root differs from source-inventory v1 policy")
        }
        try {
            val names = HashSet<String>()
            val topLevel = HashSet<String>()
            val source = object : BoundedTarXzSource {
                override val size: Long = archive.size

                override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int =
                    archive.readAt(position, destination, offset, length)
            }
            BoundedTarXzArchive.scan(
                source = source,
                expectedRoot = archiveRoot,
                expectedCommit = scope.sourceLock.controlObject("revision").controlString("commit"),
                limits = BoundedTarXzLimits(
                    maximumCompressedBytes = limits.maximumSourceArchiveBytes,
                    maximumExpandedBytes = limits.maximumExpandedArchiveBytes,
                    maximumDecoderMemoryKiB = limits.maximumXzDecoderMemoryKiB,
                    maximumMembers = limits.maximumArchiveMembers,
                    maximumMetadataBytes = limits.maximumArchiveMetadataBytes,
                    maximumEntryBytes = limits.maximumArchiveEntryBytes,
                    maximumPathBytes = limits.maximumArchivePathBytes,
                    maximumComponentBytes = limits.maximumArchiveComponentBytes,
                    maximumLinkBytes = limits.maximumArchiveLinkBytes,
                    maximumIndexBytes = limits.maximumArchiveIndexBytes,
                    maximumSelectedBytes = limits.maximumArchiveSelectedBytes,
                ),
            ) { entry ->
                if (entry.kind == BoundedTarEntryKind.REGULAR && entry.relativePath.isNotEmpty()) {
                    names += entry.relativePath
                    topLevel += entry.relativePath.substringBefore('/')
                }
            }
            return SourceArchiveIndex(names, topLevel)
        } catch (failure: BoundedTarXzException) {
            throw FullTreeControlException(failure.message ?: "source archive violates its strict profile", failure)
        } catch (failure: FullTreeControlException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeControlException("cannot decode the bounded source tar.xz archive", failure)
        }
    }

    private const val HISTORICAL_ARCHIVE_ROOT = "llvm-project-22.1.6.src"
}
