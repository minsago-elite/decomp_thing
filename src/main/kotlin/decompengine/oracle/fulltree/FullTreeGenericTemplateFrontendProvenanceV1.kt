package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.provenance.BoundedTarEntry
import decompengine.oracle.provenance.BoundedTarEntryKind
import decompengine.oracle.provenance.BoundedTarXzArchive
import decompengine.oracle.provenance.BoundedTarXzLimits
import decompengine.oracle.provenance.BoundedTarXzRegularFileVisitor
import decompengine.oracle.provenance.BoundedTarXzSource
import java.nio.file.Path
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Authenticated input matching and immutable loaders for frontend provenance v1. */
object FullTreeGenericTemplateFrontendProvenanceV1 {
    const val SCHEMA_NAME = "full-tree-generic-template-frontend-v1"

    val configurationSha256: String by lazy {
        OracleSchemas.configurationSha256(
            SCHEMA_NAME,
            FullTreeGenericTemplateFrontendProfileV1.POLICY,
        )
    }

    data class RawInputs(
        val scope: AuthenticatedFullTreeScope,
        val buildRecordBytes: ByteArray,
        val sourceArchivePath: Path,
        val sourceInventory: JsonObject,
        val inventory: JsonObject,
        val capture: FullTreeClangCaptureInputRegistry,
        val reconciliation: FullTreeClangCompdbReconciliationRegistry,
        val generated: FullTreeGeneratedFileRegistry,
        val authenticatedToolchainRoot: Path,
        val cxxDriverIdentity: FullTreeGenericTemplateFrontendProfileV1.CxxDriverIdentityInputV1,
        val adapterExecutablePath: Path,
        val limits: FullTreeControlLimits = FullTreeControlLimits(),
    )

    data class RawActionInput(
        val unitId: String,
        val action: FullTreeClangCaptureAction,
        val compdbMatch: FullTreeClangCompdbMatch,
        val executionArgv: List<String>,
        val argvSha256: String,
        val executionArgvSha256: String,
        val sourceFileSha256: String,
        val cwd: String,
        val environment: FullTreeGenericTemplateFrontendProfileV1.EffectiveEnvironmentV1,
        val actionId: String,
    )

    /** Small immutable views used to test the raw capture/compdb join without constructing Clang. */
    data class CapturedActionSelectionV1(
        val actionSha256: String,
        val unitId: String,
        val sourcePath: String,
        val workingDirectory: String,
        val mainInput: String,
        val arguments: List<String>,
        val objectOutput: String,
    )

    data class CompdbSelectionV1(
        val captureActionSha256: String,
        val directory: String,
        val file: String,
        val output: String,
        val resolvedOutput: String,
    )

    data class ReplayedActionVectorV1(
        val executionArgv: List<String>,
        val argvSha256: String,
        val executionArgvSha256: String,
    )

    data class ValidatedRawInput(
        val bindings: JsonObject,
        val profile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1,
        val pathTransform: FullTreeGenericTemplateFrontendProfileV1.PathTransformV1,
        val resourceManifest: FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1,
        val receipt: FullTreeGenericTemplateFrontendReceiptV1.ValidatedReceipt,
        val actions: List<RawActionInput>,
    )

    /** Strict bounded schema-loader entry point for canonical on-disk receipts. */
    fun loadAndValidate(
        path: Path,
        limits: FullTreeGenericTemplateFrontendReceiptV1.Limits,
        expectedBindings: JsonObject? = null,
        expectedPathTransform: FullTreeGenericTemplateFrontendProfileV1.PathTransformV1? = null,
        expectedProfile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1? = null,
        expectedRawEnvironment: Map<String, String>? = null,
        expectedSourceFileDigests: Map<String, String> = emptyMap(),
        expectedResourceManifest: FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1? = null,
        expectedDriverPath: String? = null,
    ): FullTreeGenericTemplateFrontendReceiptV1.ValidatedReceipt {
        val receipt = FullTreeGenericTemplateFrontendReceiptV1.loadCanonical(
            path,
            limits,
            expectedBindings = expectedBindings,
            expectedPathTransform = expectedPathTransform,
            expectedProfile = expectedProfile,
            expectedRawEnvironment = expectedRawEnvironment,
            expectedSourceFileDigests = expectedSourceFileDigests,
            expectedResourceManifest = expectedResourceManifest,
            expectedDriverPath = expectedDriverPath,
        )
        validateSchemaAndConfiguration(receipt.document)
        return receipt
    }

    /** Raw source/build replay follows the same executable schema and fixed configuration gate. */
    private fun validateSchemaAndConfiguration(document: JsonObject) {
        try {
            OracleSchemas.validate(SCHEMA_NAME, document)
        } catch (failure: Exception) {
            throw FullTreeControlException("frontend provenance fails its bundled schema", failure)
        }
        if (document["configurationSha256"] != JsonPrimitive(configurationSha256)) {
            throw FullTreeControlException("frontend provenance configuration digest differs from its bundled contract")
        }
    }

    /**
     * Independently join receipt units to existing validated capture and compdb controls. This is
     * a data loader only: it authenticates vectors but does not admit options or invoke Clang.
     */
    fun validateRawInputs(
        document: JsonObject,
        raw: RawInputs,
        profile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1,
        receiptLimits: FullTreeGenericTemplateFrontendReceiptV1.Limits,
    ): ValidatedRawInput {
        validateSchemaAndConfiguration(document)
        val limits = raw.limits
        FullTreeScopeControl.validate(raw.scope, limits)
        val buildRecord = parseCanonicalObject(raw.buildRecordBytes, limits.maximumBuildRecordBytes, "build record")
        val buildRecordSha256 = OracleArtifacts.sha256(raw.buildRecordBytes)
        if (FullTreeScopeControl.requireBuildRecordBinding(raw.scope, raw.buildRecordBytes, limits) != buildRecordSha256) {
            fail("build record differs from the authenticated manifest")
        }
        FullTreeInventoryControl.validate(raw.inventory, raw.scope, limits)
        FullTreeSourceInventoryControl.validate(raw.sourceInventory, raw.scope, buildRecord, raw.inventory, limits)

        val captureDocument = parseCanonicalObject(
            raw.capture.canonicalBytes,
            raw.capture.canonicalBytes.size,
            "Clang capture input",
        )
        val captureAuthority = captureDocument.controlObject("authority")
        if (captureAuthority.controlString("status") != "unexecuted-unreceipted-capture-input" ||
            captureAuthority["captureInputAuthenticated"] != JsonPrimitive(false) ||
            captureAuthority["compilerActionsAuthenticated"] != JsonPrimitive(false)
        ) {
            fail("capture input is being promoted to execution evidence")
        }
        if (captureDocument.controlObject("compiler")["cxxDriverIdentityAuthenticated"] != JsonPrimitive(false)) {
            fail("upstream capture claims an authenticated C++ driver identity")
        }
        if (raw.generated.generationReceiptBound) {
            // The existing generated-byte snapshot and a future generator execution receipt are
            // different authority levels; preserve the registry's exact status without upgrading it.
            fail("generated-input registry status differs from its validated snapshot contract")
        }
        val captureOracle = captureDocument.controlObject("oracle")
        if (captureOracle.controlString("scopeSha256") != raw.scope.sha256 ||
            captureOracle.controlString("sourceLockSha256") != raw.scope.sourceLockSha256 ||
            captureOracle.controlString("artifactManifestSha256") != raw.scope.artifactManifestSha256 ||
            captureOracle.controlString("buildRecordSha256") != buildRecordSha256 ||
            captureOracle.controlString("generatedFileInventoryArtifactSha256") != raw.generated.artifactSha256 ||
            captureOracle.controlString("sourceInventoryArtifactSha256") !=
            OracleArtifacts.sha256(
                FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
                    raw.sourceInventory,
                    limits.maximumSourceInventoryBytes.toLong(),
                    "authenticated source inventory",
                ),
            ) ||
            captureOracle.controlString("inventoryArtifactSha256") !=
            OracleArtifacts.sha256(
                FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
                    raw.inventory,
                    limits.maximumInventoryBytes.toLong(),
                    "authenticated rich inventory",
                ),
            )
        ) {
            fail("capture input no longer matches its validated source, build, or inventory bindings")
        }
        if (raw.reconciliation.captureInputArtifactSha256 != raw.capture.artifactSha256) {
            fail("compilation-database reconciliation selects a different capture input")
        }

        val buildEnvironment = buildRecord.controlObject("environment")
        val containerImageDigest = buildEnvironment.controlObject("container").controlString("digest")
        val rawEnvironment = environmentFromBuildRecord(buildRecord)
        if (rawEnvironment != raw.capture.baseEnvironment) {
            fail("capture environment differs from the authenticated build-record environment")
        }
        val pathTransform = FullTreeGenericTemplateFrontendProfileV1.transformPath(
            rawEnvironment["PATH"] ?: fail("build record is missing PATH"),
            containerImageDigest,
        )
        profile.requirePathTransform(pathTransform)
        val expectedDriver = configuredCxxDriver(buildRecord)
        if (raw.cxxDriverIdentity.buildRecordSha256 != buildRecordSha256 ||
            raw.cxxDriverIdentity.containerImageDigest != containerImageDigest ||
            raw.cxxDriverIdentity.configuredPathSha256 !=
            OracleArtifacts.sha256(FullTreeGenericTemplateFrontendProfileV1.strictUtf8(expectedDriver)) ||
            raw.cxxDriverIdentity.compilerSha256 != profile.compilerSha256 ||
            raw.cxxDriverIdentity.toolchainProfileSha256 != profile.toolchainProfileSha256 ||
            FullTreeGenericTemplateFrontendProfileV1.cxxDriverIdentity(raw.cxxDriverIdentity) !=
            profile.cxxDriverIdentitySha256
        ) {
            fail("C++ driver identity does not match the exact captured path and pinned profile")
        }
        val adapter = StableControlFile.open(
            raw.adapterExecutablePath,
            limits.maximumRichArtifactBytes,
            "authenticated frontend adapter",
        )
        adapter.use {
            it.requireSingleLink("authenticated frontend adapter")
            if (it.sha256() != profile.adapterSha256) fail("frontend adapter bytes differ from the pinned profile")
            it.verifyUnchanged("authenticated frontend adapter")
        }
        val resourceManifest = FullTreeGenericTemplateFrontendProfileV1.loadResourceManifest(
            raw.authenticatedToolchainRoot,
            profile.resolvedResourceDirectory,
        )
        if (resourceManifest.sha256 != profile.resourceHeaderManifestSha256) {
            fail("frontend resource directory bytes differ from the pinned profile")
        }

        val archiveSha = raw.scope.sourceLock.controlObject("source").controlObject("archive").controlString("sha256")
        val archiveBytes = raw.scope.sourceLock.controlObject("source").controlObject("archive").controlLong("bytes")
        val receiptUnits = (document["units"] as? JsonArray)
            ?: fail("frontend provenance units are invalid")
        val dependencyRows = receiptUnits.flatMap { element ->
            val unit = element as? JsonObject ?: fail("frontend provenance unit is invalid")
            val dependencies = unit["dependencies"] as? JsonArray
                ?: fail("frontend unit dependencies are invalid")
            dependencies.map { dependency ->
                dependency as? JsonObject ?: fail("frontend dependency row is invalid")
            }
        }
        val sourceDependencyPaths = dependencyRows.mapNotNull { dependency ->
            val path = dependency.controlString("path")
            path.takeIf { it.startsWith("source/") }?.removePrefix("source/")
        }.toSet()
        val generatedDependencies = dependencyRows.mapNotNull { dependency ->
            val path = dependency.controlString("path")
            path.takeIf { it.startsWith("generated/") }
        }.distinct().associateWith { generatedPath ->
            raw.generated.requireGeneratedFile(generatedPath).sha256
        }
        val sourceDigests = sourceArchiveDigests(
            raw.sourceArchivePath,
            raw.scope,
            limits,
            sourceDependencyPaths,
            archiveSha,
            archiveBytes,
        )
        val buildRootValue = Path.of(buildRecord.controlObject("directories").controlString("build"))
        if (!buildRootValue.isAbsolute) fail("authenticated build root is not absolute")
        val buildRoot = buildRootValue.toAbsolutePath().normalize()
        val buildDependencyPaths = dependencyRows.mapNotNull { dependency ->
            dependency.controlString("path").takeIf { it.startsWith("build/") }
        }.toSet()
        val buildDigests = closureFileDigests(
            buildRoot,
            "build/",
            buildDependencyPaths,
            limits.maximumArchiveEntryBytes,
            "authenticated build dependency",
        )
        val toolchainDependencyPaths = dependencyRows.mapNotNull { dependency ->
            dependency.controlString("path").takeIf { it.startsWith("toolchain/") }
        }.toSet()
        val toolchainDigests = closureFileDigests(
            raw.authenticatedToolchainRoot,
            "toolchain/",
            toolchainDependencyPaths,
            limits.maximumRichArtifactBytes,
            "authenticated toolchain dependency",
        )
        val profileSha256 = profile.sha256()
        val bindings = JsonObject(
            mapOf(
                "artifactManifestSha256" to JsonPrimitive(raw.scope.artifactManifestSha256),
                "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
                "compilationDatabaseSha256" to JsonPrimitive(raw.reconciliation.compdbSha256),
                "frontendProfileSha256" to JsonPrimitive(profileSha256),
                "generatedInventorySha256" to JsonPrimitive(raw.generated.artifactSha256),
                "richArtifactSha256" to raw.scope.document.controlObject("oracle").getValue("richArtifactSha256"),
                "richInventorySha256" to JsonPrimitive(raw.inventory.controlString("indexSha256")),
                "scopeSha256" to JsonPrimitive(raw.scope.sha256),
                "sourceArchiveSha256" to JsonPrimitive(archiveSha),
                "sourceInventorySha256" to captureOracle.getValue("sourceInventoryArtifactSha256"),
                "sourceLockSha256" to JsonPrimitive(raw.scope.sourceLockSha256),
            ),
        )
        val allSourceDigests = buildMap {
            sourceDigests.forEach { (relative, sha) -> put("source/$relative", sha) }
            putAll(generatedDependencies)
            putAll(buildDigests)
            putAll(toolchainDigests)
            resourceManifest.files.forEach { put(it.path, it.sha256) }
        }
        val receipt = FullTreeGenericTemplateFrontendReceiptV1.validate(
            document,
            receiptLimits,
            expectedBindings = bindings,
            expectedPathTransform = pathTransform,
            expectedProfile = profile,
            expectedRawEnvironment = rawEnvironment,
            expectedSourceFileDigests = allSourceDigests,
            expectedResourceManifest = resourceManifest,
            expectedDriverPath = raw.cxxDriverIdentity.resolvedDriverPath,
        )
        val canonicalReceiptUnits = receiptUnits.map { it as JsonObject }
        if (canonicalReceiptUnits.size != raw.capture.actions.size || canonicalReceiptUnits.size > limits.maximumCompilationUnits) {
            fail("frontend unit population differs from the authenticated action scope")
        }
        val validatedActions = ArrayList<RawActionInput>(canonicalReceiptUnits.size)
        val usedActionHashes = HashSet<String>()
        for (unit in canonicalReceiptUnits) {
            val unitId = unit.controlString("unitId")
            val action = raw.capture.actions.singleOrNull { it.unitId == unitId }
                ?: fail("frontend unit is not selectable from the authenticated capture plan")
            if (unit.controlString("captureActionSha256") != action.actionSha256 ||
                !usedActionHashes.add(action.actionSha256)
            ) fail("frontend unit does not select one unique authenticated capture action")
            val match = raw.reconciliation.requireMatchForCaptureAction(action.actionSha256)
            val replay = authenticateReplayVector(
                CapturedActionSelectionV1(
                    action.actionSha256, action.unitId, action.sourcePath, action.workingDirectory,
                    action.mainInput, action.arguments, action.objectOutput,
                ),
                CompdbSelectionV1(
                    match.captureActionSha256, match.directory, match.file, match.output, match.resolvedOutput,
                ),
                expectedDriver,
            )
            val executionArgv = replay.executionArgv
            val argvSha = replay.argvSha256
            val executionSha = replay.executionArgvSha256
            val sourcePath = action.sourcePath
            val sourceSha = allSourceDigests[sourcePath] ?: fail("captured source blob is absent from its authenticated inventory")
            val cwd = normalizeActionDirectory(action.workingDirectory, buildRecord)
            val effectiveEnvironment = authenticateReplayEnvironment(unit, rawEnvironment, pathTransform)
            if (unit.controlString("argvSha256") != argvSha ||
                unit.controlString("executionArgvSha256") != executionSha ||
                unit.controlString("sourcePath") != sourcePath ||
                unit.controlString("sourceFileSha256") != sourceSha ||
                unit.controlString("cwd") != cwd ||
                unit.controlString("environmentSha256") != effectiveEnvironment.sha256 ||
                unit.controlString("actionId") != FullTreeGenericTemplateFrontendReceiptV1.actionId(bindings, unit)
            ) fail("frontend receipt action binding differs from raw capture and source inputs")
            validatedActions += RawActionInput(
                unitId, action, match, executionArgv, argvSha, executionSha, sourceSha, cwd,
                effectiveEnvironment, unit.controlString("actionId"),
            )
        }
        if (usedActionHashes.size != raw.capture.actions.size) {
            fail("authenticated capture actions and frontend units do not form a complete one-to-one join")
        }
        return ValidatedRawInput(
            bindings,
            profile,
            pathTransform,
            resourceManifest,
            receipt,
            Collections.unmodifiableList(validatedActions),
        )
    }

    /** Join one raw capture action to its exact unique external-compdb reconciliation projection. */
    fun authenticateReplayVector(
        action: CapturedActionSelectionV1,
        match: CompdbSelectionV1,
        expectedConfiguredCxxDriver: String,
    ): ReplayedActionVectorV1 {
        if (match.captureActionSha256 != action.actionSha256 || match.directory != action.workingDirectory ||
            match.file != action.mainInput || match.output != action.arguments.getOrNull(8) ||
            match.resolvedOutput != action.objectOutput
        ) fail("frontend unit lacks its unique external-compdb reconciliation row")
        if (action.arguments.firstOrNull() != expectedConfiguredCxxDriver) {
            fail("captured C++ driver path differs from the authenticated build-record path")
        }
        val executionArgv = FullTreeGenericTemplateFrontendReceiptV1.deriveExecutionArgv(
            action.arguments,
            action.mainInput,
        )
        return ReplayedActionVectorV1(
            executionArgv,
            FullTreeGenericTemplateFrontendReceiptV1.argvSha256(action.arguments),
            FullTreeGenericTemplateFrontendReceiptV1.executionArgvSha256(action.arguments, action.mainInput),
        )
    }

    /** Read the build-record variables object without dropping required or optional values. */
    fun environmentFromBuildRecord(buildRecord: JsonObject): Map<String, String> {
        val variables = buildRecord.controlObject("environment").controlObject("variables")
        val values = LinkedHashMap<String, String>()
        variables.forEach { (name, value) ->
            values[name] = (value as? JsonPrimitive)?.takeIf { it.isString }?.content
                ?: fail("build-record environment variable $name is not a string")
        }
        return Collections.unmodifiableMap(values)
    }

    /** Recompute and compare the exact child environment retained in a replayed receipt unit. */
    fun authenticateReplayEnvironment(
        unit: JsonObject,
        rawEnvironment: Map<String, String>,
        pathTransform: FullTreeGenericTemplateFrontendProfileV1.PathTransformV1,
    ): FullTreeGenericTemplateFrontendProfileV1.EffectiveEnvironmentV1 {
        val effective = FullTreeGenericTemplateFrontendProfileV1.effectiveEnvironment(rawEnvironment, pathTransform)
        val recorded = unit["environment"] as? JsonObject ?: fail("frontend unit environment is invalid")
        if (recorded != effective.json() ||
            unit.controlString("environmentSha256") != effective.sha256
        ) fail("frontend unit environment differs from build-record replay")
        return effective
    }

    private fun configuredCxxDriver(buildRecord: JsonObject): String {
        val values = buildRecord.controlObject("commands").controlArray("configure").map {
            val value = (it as? JsonPrimitive)?.takeIf { primitive -> primitive.isString }?.content
                ?: fail("build-record configure command is invalid")
            value
        }
        val matches = values.filter { it.startsWith("-DCMAKE_CXX_COMPILER=") }
        if (matches.size != 1) fail("build record does not contain one configured C++ driver path")
        val path = matches.single().removePrefix("-DCMAKE_CXX_COMPILER=")
        if (!path.startsWith('/') || path.startsWith("//") || path.contains("//") || path.endsWith('/') ||
            path.split('/').drop(1).any { it.isEmpty() || it == "." || it == ".." }
        ) fail("configured C++ driver path is invalid")
        FullTreeGenericTemplateFrontendProfileV1.strictUtf8(path)
        return path
    }

    private fun normalizeActionDirectory(path: String, buildRecord: JsonObject): String {
        if (!path.startsWith('/') || path.startsWith("//") || path.contains("//")) {
            fail("captured frontend cwd is invalid")
        }
        val directories = buildRecord.controlObject("directories")
        val roots = listOf(
            "source" to directories.controlString("source"),
            "build" to directories.controlString("build"),
        ).sortedByDescending { it.second.length }
        for ((kind, root) in roots) {
            val normalizedRoot = root.removeSuffix("/")
            if (path == normalizedRoot) {
                return FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(kind, "cwd")
            }
            if (path.startsWith("$normalizedRoot/")) {
                val relative = path.removePrefix("$normalizedRoot/")
                if (relative.isNotEmpty()) {
                    return FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(
                        "$kind/$relative",
                        "cwd",
                    )
                }
            }
        }
        fail("captured frontend cwd is outside authenticated source and build roots")
    }

    private fun sourceArchiveDigests(
        archivePath: Path,
        scope: AuthenticatedFullTreeScope,
        limits: FullTreeControlLimits,
        wantedRelativePaths: Set<String>,
        expectedSha256: String,
        expectedBytes: Long,
    ): Map<String, String> {
        val archive = StableControlFile.open(
            archivePath,
            minOf(expectedBytes, limits.maximumSourceArchiveBytes),
            "authenticated source archive",
        )
        archive.use {
            if (it.size != expectedBytes || it.sha256() != expectedSha256) {
                fail("source archive bytes differ from the authenticated source lock")
            }
            val digests = LinkedHashMap<String, MessageDigest>()
            val result = LinkedHashMap<String, String>()
            val targetCount = HashMap<String, Int>()
            val visitor = object : BoundedTarXzRegularFileVisitor {
                override fun wants(entry: BoundedTarEntry): Boolean = entry.relativePath in wantedRelativePaths

                override fun onChunk(entry: BoundedTarEntry, bytes: ByteArray, length: Int, endOfEntry: Boolean) {
                    val digest = digests.getOrPut(entry.relativePath) { MessageDigest.getInstance("SHA-256") }
                    if (length > 0) digest.update(bytes, 0, length)
                    if (endOfEntry) {
                        result[entry.relativePath] = digest.digest().joinToString("") {
                            (it.toInt() and 0xff).toString(16).padStart(2, '0')
                        }
                        digests.remove(entry.relativePath)
                    }
                }
            }
            val source = object : BoundedTarXzSource {
                override val size: Long = it.size
                override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int =
                    it.readAt(position, destination, offset, length)
            }
            val archiveRecord = scope.sourceLock.controlObject("source").controlObject("archive")
            BoundedTarXzArchive.scan(
                source,
                scope.sourceLock.controlObject("source").controlString("archiveRoot"),
                scope.sourceLock.controlObject("revision").controlString("commit"),
                BoundedTarXzLimits(
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
                regularFileVisitor = visitor,
                onEntry = { entry ->
                    if (entry.kind == BoundedTarEntryKind.REGULAR && entry.relativePath in wantedRelativePaths) {
                        targetCount[entry.relativePath] = (targetCount[entry.relativePath] ?: 0) + 1
                    }
                },
            )
            if (targetCount.keys != wantedRelativePaths || targetCount.values.any { count -> count != 1 } ||
                result.keys != wantedRelativePaths
            ) fail("source archive is missing a selected source blob")
            if (archiveRecord.controlString("sha256") != expectedSha256) fail("source archive identity changed")
            it.verifyUnchanged("authenticated source archive")
            return Collections.unmodifiableMap(result)
        }
    }

    private fun closureFileDigests(
        rootPath: Path,
        closurePrefix: String,
        closurePaths: Set<String>,
        maximumFileBytes: Long,
        label: String,
    ): Map<String, String> {
        if (closurePaths.isEmpty()) return emptyMap()
        val root = rootPath.toAbsolutePath().normalize()
        if (!java.nio.file.Files.isDirectory(root, java.nio.file.LinkOption.NOFOLLOW_LINKS) ||
            java.nio.file.Files.isSymbolicLink(root)
        ) fail("$label root is unavailable")
        val result = LinkedHashMap<String, String>()
        closurePaths.sortedWith(Comparator(FullTreeGenericTemplateFrontendProfileV1::compareUtf8)).forEach { path ->
            FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(path, "$label path")
            if (!path.startsWith(closurePrefix)) fail("$label path is outside its authenticated root")
            val relative = path.removePrefix(closurePrefix)
            if (relative.isEmpty()) fail("$label path is invalid")
            val target = root.resolve(relative).normalize()
            if (!target.startsWith(root) || target == root) fail("$label path escapes its authenticated root")
            var ancestor = root
            root.relativize(target).forEachIndexed { index, component ->
                ancestor = ancestor.resolve(component)
                if (java.nio.file.Files.isSymbolicLink(ancestor)) fail("$label path contains a symlink")
                if (index < root.relativize(target).nameCount - 1 &&
                    !java.nio.file.Files.isDirectory(ancestor, java.nio.file.LinkOption.NOFOLLOW_LINKS)
                ) fail("$label path contains a non-directory parent")
            }
            val file = try {
                StableControlFile.open(target, maximumFileBytes, label)
            } catch (failure: Exception) {
                throw FullTreeControlException("cannot open $label", failure)
            }
            file.use {
                it.requireSingleLink(label)
                result[path] = it.sha256()
                it.verifyUnchanged(label)
            }
        }
        return Collections.unmodifiableMap(result)
    }

    private fun parseCanonicalObject(bytes: ByteArray, maximumBytes: Int, label: String): JsonObject = try {
        OracleJson.parseCanonical(
            bytes,
            StrictJsonLimits(
                maximumInputBytes = maximumBytes,
                maximumCanonicalBytes = maximumBytes,
                maximumDepth = 128,
                maximumNodes = 1_000_000,
                maximumStringBytes = 1_048_576,
                maximumTotalStringBytes = maximumBytes,
            ),
        ) as? JsonObject ?: fail("$label is not a JSON object")
    } catch (failure: FullTreeControlException) {
        throw failure
    } catch (failure: Exception) {
        throw FullTreeControlException("$label is not strict canonical JSON", failure)
    }

    private fun fail(message: String): Nothing = throw FullTreeControlException(message)
}
