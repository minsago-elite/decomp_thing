package decompengine.project

import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.util.WeakHashMap
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Explicit diagnostic compilation policy. It supplies no recovered declarations or implementation authority. */
internal object GeneratedCEvidenceCarrier {
    const val PURPOSE_KEY = "declaration-purpose"
    const val PURPOSE = "evidence-carrier-v1"
    const val IDENTITY = "evidence-carrier:v1"
    private const val MARKER = "/* decomp-evidence-carrier-v1\n"
    private val sharedHeaderDigests = WeakHashMap<String, String>()
    private val markerBytes = MARKER.toByteArray(Charsets.US_ASCII)
    private val markerPrefixes = IntArray(markerBytes.size).also { prefixes ->
        var matched = 0
        for (index in 1 until markerBytes.size) {
            while (matched > 0 && markerBytes[index] != markerBytes[matched]) matched = prefixes[matched - 1]
            if (markerBytes[index] == markerBytes[matched]) matched++
            prefixes[index] = matched
        }
    }

    fun isSelected(profile: ReconstructionProfile): Boolean {
        val value = profile.adapterConfiguration[PURPOSE_KEY] ?: return false
        require(value == listOf(PURPOSE)) { "unsupported generated-C declaration purpose" }
        return true
    }

    fun profile(base: ReconstructionProfile): ReconstructionProfile {
        ReconstructionAdapters.resolve(base)
        if (isSelected(base)) return base
        return ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration + (PURPOSE_KEY to listOf(PURPOSE)))
    }

    val reconstructor: ModuleReconstructor = CarrierReconstructor

    fun requireReconstructor(profile: ReconstructionProfile, selected: ModuleReconstructor) {
        require(isSelected(profile) == (selected === CarrierReconstructor)) {
            "evidence-carrier purpose requires its fixed reconstructor and cannot be mixed with implementation reconstruction"
        }
        require(isSelected(profile) || selected.cacheIdentity(profile) != IDENTITY) {
            "evidence-carrier reconstructor identity cannot authorize implementation reconstruction"
        }
    }

    fun requireImplementationPurpose(profile: ReconstructionProfile, operation: String) {
        require(!isSelected(profile)) { "evidence-carrier output cannot authorize $operation" }
    }

    fun rejectCarrierContent(bytes: ByteArray, label: String) {
        require(!isCarrierContent(bytes)) { "evidence-carrier content cannot be used as an implementation: $label" }
    }

    fun isCarrierContent(bytes: ByteArray): Boolean {
        var matched = 0
        for (index in bytes.indices) {
            if (index % 65_536 == 0) checkpoint()
            while (matched > 0 && bytes[index] != markerBytes[matched]) matched = markerPrefixes[matched - 1]
            if (bytes[index] == markerBytes[matched]) matched++
            if (matched == markerBytes.size) return true
        }
        return false
    }

    /** Existing strict profile/budget changes remain supported; only crossing the declaration purpose is forbidden. */
    fun requireWorkspacePurpose(projectDir: Path, profile: ReconstructionProfile) {
        checkpoint()
        val selected = isSelected(profile)
        val path = projectDir.resolve("source_tree_manifest.json")
        val maximum = maximumFileBytes(profile)
        if (!Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            if (!Files.exists(projectDir, LinkOption.NOFOLLOW_LINKS)) return
            inspectDeclaredBuildInputs(projectDir, profile) { relative, bytes ->
                require(!selected) { "evidence-carrier workspace has compiler inputs without a retained manifest: $relative" }
                rejectCarrierContent(bytes, relative)
            }
            return
        }
        val manifestBytes = readStableRegularFile(projectDir, "source_tree_manifest.json", maximum, cancellationCheck = ::checkpoint).bytes
        val text = manifestBytes.decodeToString(throwOnInvalidSequence = true)
        UniqueJsonObjectKeyValidator(text).validate()
        val document = Json.parseToJsonElement(text).jsonObject
        val files = document.getValue("files").jsonArray
        require(files.size <= profile.budgets.archiveMaximumEntries) { "existing source manifest exceeds its entry bound" }
        var total = manifestBytes.size.toLong()
        var observedCarrier = false
        val inspectedPaths = mutableSetOf<String>()
        for (element in files) {
            checkpoint()
            val record = element.jsonObject
            val relative = record.getValue("path").jsonPrimitive.let {
                require(it.isString); requireNormalizedProjectPath(it.content, "existing generated source")
            }
            val generator = record.getValue("generator").jsonPrimitive.content
            // Retained role/generator fields are editable claims. Inspect all bounded
            // declared bytes so removing a role cannot hide the reserved carrier marker.
            if (!selected) require(generator != IDENTITY) { "evidence-carrier metadata cannot authorize implementation reconstruction" }
            if (!Files.exists(projectDir.resolve(relative), LinkOption.NOFOLLOW_LINKS)) {
                require(!selected && generator != IDENTITY) { "evidence-carrier workspace is missing retained source: $relative" }
                continue
            }
            val snapshot = readStableRegularFile(projectDir, relative, maximum, cancellationCheck = ::checkpoint)
            inspectedPaths += relative
            total = Math.addExact(total, snapshot.bytes.size.toLong())
            require(total <= profile.budgets.archiveMaximumTotalBytes) { "existing source inventory exceeds its byte bound" }
            val carrier = isCarrierContent(snapshot.bytes)
            if (carrier) {
                require(selected) { "cannot reuse an evidence-carrier workspace for implementation reconstruction" }
                require(snapshot.sha256 == record.getValue("sha256").jsonPrimitive.content) {
                    "evidence-carrier source differs from its retained manifest: $relative"
                }
                observedCarrier = true
            }
        }
        if (!selected) {
            inspectDeclaredBuildInputs(projectDir, profile, inspectedPaths, total) { relative, bytes ->
                rejectCarrierContent(bytes, relative)
            }
        }
        if (selected) {
            require(observedCarrier && document.getValue("profileId").jsonPrimitive.content == profile.id &&
                document.getValue("profileSha256").jsonPrimitive.content == profile.sha256) {
                "cannot reuse an implementation or different-purpose workspace for evidence-carrier generation"
            }
            val retained = SourceTreeManifestReader.parse(text, profile)
            var retainedBytes = manifestBytes.size.toLong()
            val sizes = retained.files.associate { file ->
                checkpoint()
                val attributes = Files.readAttributes(projectDir.resolve(file.path), BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS)
                require(attributes.isRegularFile && attributes.size() in 0..maximum) {
                    "evidence-carrier retained input is not a bounded regular file: ${file.path}"
                }
                retainedBytes = Math.addExact(retainedBytes, attributes.size())
                require(retainedBytes <= profile.budgets.archiveMaximumTotalBytes)
                file.path to attributes.size()
            }
            ReconstructionAcpEvidenceArchiveVerifier.verify(projectDir,
                retained.files.associate { it.path to it.sha256 }, sizes, retained, profile)
        }
    }

    /** Missing manifest records (or the manifest itself) cannot hide retained compiler input. */
    private fun inspectDeclaredBuildInputs(
        projectDir: Path,
        profile: ReconstructionProfile,
        inspectedPaths: Set<String> = emptySet(),
        initialBytes: Long = 0,
        consume: (String, ByteArray) -> Unit,
    ) {
        val root = Files.readAttributes(projectDir, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        require(root.isDirectory && !root.isSymbolicLink) { "existing source workspace must be a regular directory" }
        // Only declaration prefixes are traversed; unrelated entries still charge work.
        val declarations = profile.layout.declarations.filter { ProjectFileRole.BUILD_INPUT in it.roles }
        val maximumDepth = declarations.maxOfOrNull { it.pathTemplate.split('/').size } ?: 0
        val maximumVisits = Math.addExact(Math.multiplyExact(profile.budgets.archiveMaximumEntries.toLong(),
            maximumDepth.toLong() + 1L), declarations.size.toLong())
        val directories = ArrayDeque<Path>()
        directories.add(projectDir)
        var visits = 0L
        var total = initialBytes
        while (directories.isNotEmpty()) {
            checkpoint()
            Files.newDirectoryStream(directories.removeFirst()).use { entries ->
                for (entry in entries) {
                    checkpoint()
                    visits = Math.addExact(visits, 1L)
                    require(visits <= maximumVisits) { "existing declared-source inspection exceeds its entry bound" }
                    val relative = projectDir.relativize(entry).toString().replace('\\', '/')
                    val matches = declarations.any { it.matches(relative) }
                    val descendant = declarations.any { it.canMaterializeUnder(relative) }
                    if (!matches && !descendant) continue
                    val attributes = Files.readAttributes(entry, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                    require(!attributes.isSymbolicLink) { "existing declared source path is a symbolic link: $relative" }
                    if (attributes.isDirectory) {
                        require(!matches) { "existing declared source is a directory: $relative" }
                        directories.add(entry)
                    } else if (matches && relative !in inspectedPaths) {
                        val snapshot = readStableRegularFile(projectDir, relative, maximumFileBytes(profile), cancellationCheck = ::checkpoint)
                        total = Math.addExact(total, snapshot.bytes.size.toLong())
                        require(total <= profile.budgets.archiveMaximumTotalBytes) { "existing source inventory exceeds its byte bound" }
                        consume(relative, snapshot.bytes)
                    }
                }
            }
        }
    }

    fun rendering(model: RecoveredProgramModel, plan: ModulePlan, profile: ReconstructionProfile): ProjectRendering {
        require(isSelected(profile))
        return CarrierRendering(model, plan, profile)
    }

    fun verifyArchivePurpose(projectDir: Path, profile: ReconstructionProfile, manifest: SourceTreeManifest,
        payloadPaths: Set<String>) {
        if (!isSelected(profile)) return
        verifyProject(projectDir, profile, manifest)
        require(manifest.files.none { it.generator == "repair-revision" } &&
            payloadPaths.none { it.startsWith("reports/repair-revisions/") }) {
            "evidence-carrier output cannot retain accepted repair lineage"
        }
    }

    fun validateArchivedCheckpoint(profile: ReconstructionProfile, source: GeneratedFileEvidence,
        checkpoint: ArchivedModuleCheckpointProvenance) {
        if (isSelected(profile)) {
            require(!checkpoint.repairLineagePresent && checkpoint.schemaVersion == 6L &&
                source.acceptedImplementation == false && !checkpoint.accepted &&
                source.generator == IDENTITY && checkpoint.generator == IDENTITY &&
                checkpoint.reconstructorIdentity == IDENTITY &&
                !checkpoint.compilationPresent && !checkpoint.executionEvidencePresent) {
                "evidence-carrier checkpoint cannot claim implementation, compiler, ACP or repair authority: ${source.path}"
            }
        } else {
            require(source.generator != IDENTITY && checkpoint.generator != IDENTITY &&
                checkpoint.reconstructorIdentity != IDENTITY) {
                "evidence-carrier identity cannot authorize an implementation checkpoint: ${source.path}"
            }
        }
    }

    /** Called by both direct audit and archive verification, independently of mutable generator labels. */
    fun verifyProject(projectDir: Path, profile: ReconstructionProfile, manifest: SourceTreeManifest) {
        require(isSelected(profile))
        require(manifest.profileId == profile.id && manifest.profileSha256 == profile.sha256)
        require(manifest.files.all { file ->
            file.acceptedImplementation == if (ProjectFileRole.MODULE_IMPLEMENTATION in file.roles) false else null
        }) { "evidence-carrier manifest cannot claim accepted implementations or interfaces" }
        val byPath = manifest.files.associateBy { it.path }
        require(byPath.size == manifest.files.size && byPath.size <= profile.budgets.archiveMaximumEntries)
        var total = 0L
        fun read(relative: String): ByteArray {
            checkpoint()
            val bound = requireNotNull(byPath[relative]) { "evidence-carrier input is absent from its manifest: $relative" }
            val snapshot = readStableRegularFile(projectDir, relative, maximumFileBytes(profile), cancellationCheck = ::checkpoint)
            total = Math.addExact(total, snapshot.bytes.size.toLong())
            require(total <= profile.budgets.archiveMaximumTotalBytes) { "evidence-carrier verification exceeds its byte bound" }
            require(snapshot.sha256 == bound.sha256) { "evidence-carrier input differs from its manifest: $relative" }
            return snapshot.bytes
        }
        val modelBytes = read(profile.layout.declaration("program-model-evidence").materialize())
        val model = ProgramModelJson.readCanonical(modelBytes) { checkpoint() }
        require(model.inputSha256 == manifest.inputSha256)
        val plan = ModulePlanJson.readCanonical(read(profile.layout.declaration("module-plan-evidence").materialize()),
            minOf(maximumFileBytes(profile), 512L * 1024 * 1024).toInt())
        ModulePlanJson.requireExactOwnership(plan, model, profile.layout, profile.budgets.maximumFunctionsPerModule)
        // Admit the complete artifact inventory before allocating any rendered source.
        val expectedCount = Math.addExact(Math.multiplyExact(plan.modules.size.toLong(), 3L), 3L)
        require(expectedCount <= manifest.files.size && expectedCount <= profile.budgets.archiveMaximumEntries) {
            "evidence-carrier complete build inventory exceeds its declared entry bound"
        }
        val expectedPaths = linkedSetOf<String>()
        fun path(value: String) { require(expectedPaths.add(value)) { "evidence-carrier paths overlap" } }
        path(profile.layout.declaration("shared-interface").materialize())
        path(profile.layout.declaration("entrypoint-implementation").materialize())
        path(profile.layout.declaration("build-definition").materialize())
        for (module in plan.modules) {
            checkpoint()
            path(module.sourcePath)
            path(module.headerPath)
            path(profile.layout.declaration("module-private-interface").materialize(mapOf("module" to module.id)))
        }
        require(manifest.files.filter { ProjectFileRole.BUILD_INPUT in it.roles }.map { it.path }.toSet() == expectedPaths) {
            "evidence-carrier build inventory differs from its complete plan"
        }
        val renderer = CarrierRendering(model, plan, profile, sha256(modelBytes))
        var renderedBytes = 0L
        fun expect(path: String, text: String, owners: List<String>, moduleSource: Boolean = false) {
            checkpoint()
            val bytes = text.toByteArray(Charsets.UTF_8)
            renderedBytes = Math.addExact(renderedBytes, bytes.size.toLong())
            require(bytes.size.toLong() <= maximumFileBytes(profile) && renderedBytes <= profile.budgets.archiveMaximumTotalBytes) {
                "evidence-carrier rendering exceeds its byte bound"
            }
            val record = byPath.getValue(path)
            require(record.entityIds == owners.sorted()) { "evidence-carrier ownership differs from its complete plan: $path" }
            require(record.generator == if (moduleSource) IDENTITY else "planner") {
                "evidence-carrier artifact has inconsistent generator provenance: $path"
            }
            require(moduleSource || record.promptSha256 == null) {
                "evidence-carrier planned artifact cannot claim a reconstruction prompt: $path"
            }
            require(read(path).contentEquals(bytes)) { "evidence-carrier source differs from its deterministic rendering: $path" }
        }
        val shared = renderer.sharedInterface()
        expect(profile.layout.declaration("shared-interface").materialize(), shared, model.types.map { it.id })
        for (module in plan.modules) {
            expect(module.headerPath, renderer.moduleInterface(module), module.functionIds + module.globalIds + module.typeIds)
            expect(profile.layout.declaration("module-private-interface").materialize(mapOf("module" to module.id)),
                renderer.privateInterface(module), module.functionIds)
            val source = source(module, shared, profile)
            expect(module.sourcePath, source, module.functionIds + module.globalIds, moduleSource = true)
            val record = requireNotNull(byPath[module.sourcePath])
            require(record.generator == IDENTITY && record.acceptedImplementation == false &&
                record.promptSha256 == sha256(source.toByteArray(Charsets.UTF_8))) {
                "evidence-carrier source cannot claim implementation acceptance: ${module.id}"
            }
        }
        val entry = renderer.entrypoint()
        expect(profile.layout.declaration("entrypoint-implementation").materialize(), entry.source, emptyList())
        val sources = (plan.modules.map { it.sourcePath } + profile.layout.declaration("entrypoint-implementation").materialize()).sorted()
        expect(profile.layout.declaration("build-definition").materialize(), renderer.buildDefinition(sources, profile), emptyList())
        require(manifest.unresolvedImplementationIds == (model.functions.map { it.id } + model.globals.map { it.id }).sorted()) {
            "evidence-carrier implementations must all remain unresolved"
        }
        require(manifest.unresolvedEntityIds == (model.functions.map { it.id } + model.globals.map { it.id } + model.types.map { it.id }).sorted()) {
            "evidence-carrier recovery must all remain unresolved"
        }
    }

    private object CarrierReconstructor : ModuleReconstructor {
        override fun cacheIdentity(): String = IDENTITY
        override fun reconstruct(request: ModuleReconstructionRequest): ReconstructedModule {
            require(isSelected(request.profile))
            val text = source(request.module, request.sharedHeader, request.profile)
            return ReconstructedModule(text, IDENTITY, sha256(text.toByteArray(Charsets.UTF_8)),
                issues = listOf(ModuleReconstructionIssue("evidence-only-carrier",
                    "diagnostic inventory only; recovered declarations, implementations and behavior remain unresolved",
                    request.module.functionIds + request.module.globalIds)), retryable = false)
        }
    }

    private class CarrierRendering(
        private val model: RecoveredProgramModel,
        private val plan: ModulePlan,
        private val profile: ReconstructionProfile,
        private val modelHash: String = sha256(model.toJson { checkpoint() }.toByteArray(Charsets.UTF_8)),
    ) : ProjectRendering {
        override fun sharedInterface(): String = buildString {
            append(prefix(profile)).append("model-sha256: ").append(modelHash).append("\n*/\n")
            append("#ifndef DECOMP_EVIDENCE_TYPES_H\n#define DECOMP_EVIDENCE_TYPES_H\n")
            model.types.forEach { checkpoint(); append("/* type-id-sha256: ").append(token(it.id)).append(" */\n") }
            append("#endif\n")
        }
        override fun moduleInterface(module: PlannedModule): String = buildString {
            append(prefix(profile)).append("module-id-sha256: ").append(token(module.id)).append("\n*/\n")
            val guard = "DECOMP_EVIDENCE_${token(module.id).uppercase()}_H"
            append("#ifndef ").append(guard).append("\n#define ").append(guard).append("\n")
            append(include(module.headerPath, profile.layout.declaration("shared-interface").materialize()))
            append("void ").append(symbol(module)).append("(void);\n#endif\n")
        }
        override fun privateInterface(module: PlannedModule): String =
            prefix(profile) + "private-module-id-sha256: ${token(module.id)}\n*/\n"

        override fun entrypoint(): RenderedEntrypoint = RenderedEntrypoint(buildString {
            append(prefix(profile)).append("diagnostic entry; no recovered entry is invoked\n*/\n#include <stdio.h>\n")
            plan.modules.forEach { checkpoint(); append("void ").append(symbol(it)).append("(void);\n") }
            append("int main(void) {\n")
            plan.modules.forEach { checkpoint(); append("    ").append(symbol(it)).append("();\n") }
            append("    fputs(\"evidence-only diagnostic inventory; recovered implementation and behavior unresolved\\n\", stderr);\n")
            append("    return 1;\n}\n")
        }, emptyList())

        override fun buildDefinition(sources: List<String>, profile: ReconstructionProfile): String =
            when (profile.id) {
                GeneratedCMakeReconstructionProfile.PROFILE_ID -> generatedCMakeBuildDefinition(sources, profile)
                GeneratedCNinjaReconstructionProfile.PROFILE_ID -> generatedCNinjaBuildDefinition(sources, profile)
                else -> error("unsupported evidence-carrier build adapter")
            }
    }

    private fun source(module: PlannedModule, sharedHeader: String, profile: ReconstructionProfile): String = buildString {
        checkpoint()
        append(prefix(profile)).append("module-id-sha256: ").append(token(module.id)).append('\n')
        append("shared-evidence-sha256: ").append(sharedHeaderDigest(sharedHeader)).append('\n')
        for (id in module.functionIds) { checkpoint(); append("function-id-sha256: ").append(token(id)).append('\n') }
        for (id in module.globalIds) { checkpoint(); append("global-id-sha256: ").append(token(id)).append('\n') }
        for (id in module.typeIds) { checkpoint(); append("type-id-sha256: ").append(token(id)).append('\n') }
        append("*/\n")
        append(include(module.sourcePath, module.headerPath))
        append(include(module.sourcePath, profile.layout.declaration("module-private-interface").materialize(mapOf("module" to module.id))))
        append("void ").append(symbol(module)).append("(void) {\n    /* No recovered function or global is implemented. */\n}\n")
    }

    private fun sharedHeaderDigest(header: String): String = synchronized(sharedHeaderDigests) {
        sharedHeaderDigests.getOrPut(header) { checkpoint(); sha256(header.toByteArray(Charsets.UTF_8)) }
    }
    private fun prefix(profile: ReconstructionProfile): String = MARKER + "profile-sha256: ${profile.sha256}\n"
    private fun token(value: String): String = sha256(value.toByteArray(Charsets.UTF_8))
    private fun symbol(module: PlannedModule): String = "decomp_evidence_module_${token(module.id)}"
    private fun include(from: String, target: String): String {
        val relative = (Path.of(from).parent ?: Path.of("")).relativize(Path.of(target)).toString().replace('\\', '/')
        require(relative.matches(Regex("[A-Za-z0-9_./+-]+"))) { "evidence-carrier include path is not representable in C" }
        return "#include \"$relative\"\n"
    }
    private fun maximumFileBytes(profile: ReconstructionProfile): Long =
        minOf(profile.budgets.archiveMaximumFileBytes, Int.MAX_VALUE.toLong() - 1)
    private fun checkpoint() { if (Thread.currentThread().isInterrupted) throw InterruptedException("evidence-carrier generation cancelled") }
}
