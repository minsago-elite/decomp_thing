package decompengine.project

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairIndexLayout
import decompengine.repair.RepairIndexProfile
import decompengine.repair.RepairEntityEvidence
import decompengine.repair.RepairFailureOwnership
import decompengine.repair.RepairModuleEvidence
import decompengine.repair.RepairResourceBudget
import decompengine.repair.CompileFailure
import decompengine.repair.RepairValidationStrategy
import decompengine.repair.RepairValidationAssurance
import decompengine.repair.RepairCandidateValidationOutcome
import decompengine.repair.RepairCandidateValidationRequest
import decompengine.repair.readStableRegularFile
import decompengine.repair.openRepairRootDirectory
import decompengine.repair.repairDescriptorPath
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import decompengine.validation.SandboxUnavailableException
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.util.TreeMap
import java.util.TreeSet
import kotlin.io.path.pathString

/**
 * Adapter for generated C/Make projects. All C syntax, suffix, directory, build-evidence, and entry
 * symbol conventions live here rather than in the reusable repair/revision implementation.
 */
object GeneratedCRepairIndexProfile : RepairIndexProfile {
    override fun profileId(): String = "generated-c-make-v1"

    override fun authorizesRecoveryLayout(
        sourcePaths: List<String>,
        editablePaths: List<String>,
        budget: RepairResourceBudget,
    ): Boolean {
        if (sourcePaths.isEmpty() || sourcePaths.size > budget.maximumSourceFiles) return false
        if (sourcePaths != sourcePaths.distinct().sorted() || editablePaths != editablePaths.distinct().sorted()) return false
        if (sourcePaths.any { path ->
                path != MAKEFILE && !path.startsWith("src/") && !path.startsWith("include/") ||
                    path.split('/').any { it.endsWith(".repair") }
            }) return false
        return editablePaths == sourcePaths.filter { it == MAKEFILE || it.endsWith(".c") || it.endsWith(".h") }
    }

    override fun resolve(projectRoot: Path, budget: RepairResourceBudget): RepairIndexLayout {
        val sourcePaths = discoverSourcePaths(projectRoot, budget)
        val editable = sourcePaths.filterTo(TreeSet()) {
            it == MAKEFILE || it.endsWith(".c") || it.endsWith(".h")
        }
        require(editable.isNotEmpty()) { "generated C project has no editable source inputs" }
        val evidence = readIndexEvidence(projectRoot, sourcePaths.toSet(), editable, budget)
        val modules = evidence.modules.map { module ->
            val sourceParent = Path.of(module.sourcePath).parent?.pathString?.replace('\\', '/').orEmpty()
            val internal = listOf(
                listOf(sourceParent, "${module.id}_internal.h").filter { it.isNotEmpty() }.joinToString("/"),
            ).filter { it in sourcePaths }.sorted()
            RepairModuleEvidence(
                id = module.id,
                ownedPaths = (listOf(module.sourcePath, module.headerPath) + internal)
                    .filter { it in sourcePaths }.distinct().sorted(),
                dependencyContextPaths = listOf(module.headerPath).filter { it in sourcePaths },
                entityIds = (module.functionIds + module.globalIds + module.typeIds).distinct().sorted(),
            )
        }.sortedBy { it.id }
        val entities = buildList {
            evidence.functions.forEach { function ->
                add(
                    RepairEntityEvidence(
                        id = function.id,
                        relevanceTokens = listOf(function.id, function.name).distinct().sorted(),
                        dependencyEntityIds = (function.calls + function.referencedGlobals).distinct().sorted(),
                    ),
                )
            }
            evidence.globals.forEach { global ->
                add(
                    RepairEntityEvidence(
                        id = global.id,
                        relevanceTokens = listOf(global.id, global.name).distinct().sorted(),
                    ),
                )
            }
            evidence.types.forEach { type ->
                add(RepairEntityEvidence(id = type.id, relevanceTokens = listOf(type.id)))
            }
        }.sortedBy { it.id }
        val ownershipRecords = modules.flatMap { module -> module.entityIds.map { it to module.id } }
        val ownerByEntity = ownershipRecords.toMap()
        require(
            ownershipRecords.size == entities.size &&
                ownerByEntity.keys == entities.mapTo(hashSetOf()) { it.id },
        ) {
            "generated C module ownership does not exactly match program-model entities"
        }
        val explicitlyOwnedPaths = modules.flatMapTo(hashSetOf()) { it.ownedPaths }
        val shared = listOf(MAKEFILE, TYPES_HEADER).filter { it in sourcePaths }.sorted()
        val sharedSet = shared.toHashSet()
        val fallbackModules = TreeMap<String, String>()
        sourcePaths.filter { it !in explicitlyOwnedPaths && it !in sharedSet }.forEach { path ->
            fallbackModules[path] = generatedCUnplannedModuleId(path)
        }
        return RepairIndexLayout(
            sourcePaths = sourcePaths,
            editablePaths = editable.toList(),
            modules = modules,
            entities = entities,
            sharedContextPaths = shared,
            sharedInvalidationPaths = shared.filter { it in editable },
            pathDependencies = deriveIncludes(projectRoot, sourcePaths.toSet(), budget),
            fallbackModuleIdsByPath = fallbackModules,
            behaviorRootModuleIds = fallbackModules
                .filterKeys { it.endsWith(".c") }
                .values
                .distinct()
                .sorted(),
            behaviorRootEntityIds = evidence.functions.filter {
                it.name in setOf("_start", "decomp_engine_main", "entry", "main")
            }.map { it.id }.sorted(),
        )
    }

    override fun failureOwnership(
        projectRoot: Path,
        sourceRevisionSha256: String,
        budget: RepairResourceBudget,
    ): RepairFailureOwnership {
        val relative = "reports/build_contract.json"
        if (!Files.exists(projectRoot.resolve(relative), LinkOption.NOFOLLOW_LINKS)) return RepairFailureOwnership()
        val payload = readStableRegularFile(projectRoot, relative, budget.maximumIndexEvidenceBytes).bytes
        val root = Json.parseToJsonElement(decodeGeneratedCText(payload, relative)).jsonObject
        require(root.requiredInt("schemaVersion", relative) == BUILD_CONTRACT_SCHEMA_VERSION) {
            "unsupported generated C build-contract schemaVersion"
        }
        require(root.requiredBoolean("sourceStableDuringBuild", relative)) {
            "generated C build-contract source was not stable during validation"
        }
        val contractRevision = root.requiredBoundedString("sourceRevisionSha256", relative, 64)
        require(contractRevision.matches(Regex("[0-9a-f]{64}"))) {
            "generated C build-contract source revision digest is malformed"
        }
        require(contractRevision == sourceRevisionSha256) {
            "generated C build-contract source revision does not match the indexed source revision"
        }
        val moduleElements = root.requiredArray("modules", relative)
        val failedOwnerElements = root.requiredArray("failedOwners", relative)
        if (moduleElements.size > budget.maximumIndexedModules) {
            throw RepairBudgetExceededException(
                "generated C build-contract has ${moduleElements.size} modules; " +
                    "limit=${budget.maximumIndexedModules}",
            )
        }
        if (failedOwnerElements.size > budget.maximumContextModules) {
            throw RepairBudgetExceededException(
                "generated C build-contract has ${failedOwnerElements.size} failed owners; " +
                    "limit=${budget.maximumContextModules}",
            )
        }
        val declaredModuleIds = moduleElements.map { element ->
            val module = element.jsonObject
            module.requiredBoundedString("id", relative, MAXIMUM_EVIDENCE_IDENTIFIER_CHARACTERS)
        }
        require(declaredModuleIds == declaredModuleIds.distinct().sorted()) {
            "generated C build-contract module IDs must be unique and sorted"
        }
        val owners = failedOwnerElements.map { element ->
            element.requiredBoundedString(relative, MAXIMUM_EVIDENCE_IDENTIFIER_CHARACTERS)
        }
        require(owners == owners.distinct().sorted()) {
            "generated C build-contract failed owners must be unique and sorted"
        }
        require(owners.all { it in declaredModuleIds || it in SHARED_BUILD_OWNERS }) {
            "generated C build-contract references an undeclared failed owner"
        }
        return RepairFailureOwnership(
            moduleIds = owners.filterNot { it in SHARED_BUILD_OWNERS },
            includesSharedContext = owners.any { it in SHARED_BUILD_OWNERS },
        )
    }

    override fun diagnosticEvidence(hint: String): String {
        val relevant = hint.lineSequence().filter(DIAGNOSTIC_FAILURE::containsMatchIn).toList()
        return if (relevant.isEmpty()) hint else relevant.joinToString("\n")
    }

    private data class PlannedModule(
        val id: String,
        val sourcePath: String,
        val headerPath: String,
        val functionIds: List<String>,
        val globalIds: List<String>,
        val typeIds: List<String>,
    )
    private data class ProgramFunction(
        val id: String,
        val name: String,
        val calls: List<String>,
        val referencedGlobals: List<String>,
    )
    private data class ProgramGlobal(val id: String, val name: String)
    private data class ProgramType(val id: String)
    private data class GeneratedCIndexEvidence(
        val modules: List<PlannedModule>,
        val functions: List<ProgramFunction>,
        val globals: List<ProgramGlobal>,
        val types: List<ProgramType>,
    )

    private fun readIndexEvidence(
        root: Path,
        sourcePaths: Set<String>,
        editablePaths: Set<String>,
        budget: RepairResourceBudget,
    ): GeneratedCIndexEvidence {
        val planRelative = "reports/module_plan.json"
        val modelRelative = "reports/program_model.json"
        val planBytes = readOptionalEvidence(root, planRelative, budget.maximumIndexEvidenceBytes)
        val remaining = budget.maximumIndexEvidenceBytes - (planBytes?.size?.toLong() ?: 0L)
        val modelBytes = readOptionalEvidence(root, modelRelative, remaining)
        require((planBytes == null) == (modelBytes == null)) {
            "generated C repair indexing requires module-plan and program-model evidence together"
        }
        if (planBytes == null) return GeneratedCIndexEvidence(emptyList(), emptyList(), emptyList(), emptyList())
        val planRoot = Json.parseToJsonElement(decodeGeneratedCText(planBytes, planRelative)).jsonObject
        planRoot.requireExactKeys(PLAN_ROOT_KEYS, planRelative)
        val planSchemaVersion = planRoot.requiredInt("schemaVersion", planRelative)
        require(planSchemaVersion in setOf(LEGACY_PLAN_SCHEMA_VERSION, PLAN_SCHEMA_VERSION)) {
            "unsupported generated C module-plan schemaVersion"
        }
        val moduleElements = planRoot.requiredArray("modules", planRelative)
        if (moduleElements.size > budget.maximumIndexedModules) {
            throw RepairBudgetExceededException(
                "generated C module plan has ${moduleElements.size} modules; limit=${budget.maximumIndexedModules}",
            )
        }
        val cycleElements = planRoot.requiredArray("dependencyCycles", planRelative)
        if (cycleElements.size > budget.maximumIndexedModules) {
            throw RepairBudgetExceededException(
                "generated C module plan has ${cycleElements.size} dependency cycles; " +
                    "limit=${budget.maximumIndexedModules}",
            )
        }

        val modelRoot = Json.parseToJsonElement(decodeGeneratedCText(requireNotNull(modelBytes), modelRelative)).jsonObject
        modelRoot.requireExactKeys(MODEL_ROOT_KEYS, modelRelative)
        require(modelRoot.requiredInt("schemaVersion", modelRelative) == INDEX_EVIDENCE_SCHEMA_VERSION) {
            "unsupported generated C program-model schemaVersion"
        }
        modelRoot.requiredBoundedString(
            "inputSha256",
            modelRelative,
            evidenceIdentifierLimit(budget),
        )
        val functionElements = modelRoot.requiredArray("functions", modelRelative)
        val globalElements = modelRoot.requiredArray("globals", modelRelative)
        val typeElements = modelRoot.requiredArray("types", modelRelative)
        val entityCount = Math.addExact(Math.addExact(functionElements.size, globalElements.size), typeElements.size)
        if (entityCount > budget.maximumIndexedEntities) {
            throw RepairBudgetExceededException(
                "generated C model has $entityCount indexed entities; limit=${budget.maximumIndexedEntities}",
            )
        }
        val identifierLimit = evidenceIdentifierLimit(budget)
        val textLimit = evidenceTextLimit(budget)
        var structuralEntries = 0L
        var dependencyReferences = 0L
        fun chargeStructural(count: Int, subject: String) {
            structuralEntries = chargeBoundedCount(
                structuralEntries,
                count,
                budget.maximumDependencyEdges,
                "$subject structural entries",
            )
        }
        fun chargeDependencies(count: Int) {
            dependencyReferences = chargeBoundedCount(
                dependencyReferences,
                count,
                budget.maximumDependencyEdges,
                "generated C dependency references",
            )
        }

        moduleElements.forEach { element ->
            val module = element.jsonObject
            module.requireExactKeys(
                if (planSchemaVersion == PLAN_SCHEMA_VERSION) PLAN_MODULE_KEYS else LEGACY_PLAN_MODULE_KEYS,
                "$planRelative module",
            )
            module.requiredBoundedString("id", planRelative, identifierLimit)
            module.requiredBoundedString("sourcePath", planRelative, identifierLimit)
            module.requiredBoundedString("headerPath", planRelative, identifierLimit)
            val functionIds = module.requiredArray("functionIds", planRelative)
            val globalIds = module.requiredArray("globalIds", planRelative)
            val typeIds = if (planSchemaVersion == PLAN_SCHEMA_VERSION) {
                module.requiredArray("typeIds", planRelative)
            } else {
                JsonArray(emptyList())
            }
            val boundaryEvidence = module.requiredArray("boundaryEvidence", planRelative)
            chargeStructural(functionIds.size, "generated C module function ownership")
            chargeStructural(globalIds.size, "generated C module global ownership")
            chargeStructural(typeIds.size, "generated C module type ownership")
            chargeStructural(boundaryEvidence.size, "generated C module boundary evidence")
            functionIds.preflightStringElements(planRelative, identifierLimit)
            globalIds.preflightStringElements(planRelative, identifierLimit)
            typeIds.preflightStringElements(planRelative, identifierLimit)
            boundaryEvidence.preflightStringElements(planRelative, textLimit, allowBlank = true)
        }
        cycleElements.forEach { element ->
            val cycle = element.jsonArray
            chargeStructural(cycle.size, "generated C dependency cycles")
            cycle.preflightStringElements(planRelative, identifierLimit)
        }
        functionElements.forEach { element ->
            val function = element.jsonObject
            function.requireExactKeys(MODEL_FUNCTION_KEYS, "$modelRelative function")
            function.requiredBoundedString("id", modelRelative, identifierLimit)
            function.requiredBoundedString("name", modelRelative, identifierLimit)
            function.requiredBoundedString("address", modelRelative, identifierLimit)
            function.requiredBoundedString("prototype", modelRelative, textLimit)
            function.requiredBoundedString("status", modelRelative, identifierLimit)
            val calls = function.requiredArray("calls", modelRelative)
            val referencedGlobals = function.requiredArray("referencedGlobals", modelRelative)
            val strings = function.requiredArray("strings", modelRelative)
            chargeStructural(calls.size, "generated C function calls")
            chargeStructural(referencedGlobals.size, "generated C global references")
            chargeStructural(strings.size, "generated C string references")
            chargeDependencies(calls.size)
            chargeDependencies(referencedGlobals.size)
            calls.preflightStringElements(modelRelative, identifierLimit)
            referencedGlobals.preflightStringElements(modelRelative, identifierLimit)
            strings.preflightStringElements(modelRelative, textLimit, allowBlank = true)
            function.requireNullableBoundedString("decompiledC", modelRelative, textLimit, allowBlank = true)
        }
        globalElements.forEach { element ->
            val global = element.jsonObject
            global.requireExactKeys(MODEL_GLOBAL_KEYS, "$modelRelative global")
            global.requiredBoundedString("id", modelRelative, identifierLimit)
            global.requiredBoundedString("name", modelRelative, identifierLimit)
            global.requiredBoundedString("address", modelRelative, identifierLimit)
            global.requiredBoundedString("type", modelRelative, textLimit)
            global.requireNullableBoundedString("initializer", modelRelative, textLimit, allowBlank = true)
            global.requiredBoundedString("status", modelRelative, identifierLimit)
        }
        typeElements.forEach { element ->
            val type = element.jsonObject
            type.requireExactKeys(MODEL_TYPE_KEYS, "$modelRelative type")
            type.requiredBoundedString("id", modelRelative, identifierLimit)
            type.requiredBoundedString("declaration", modelRelative, textLimit)
            type.requireNullableBoundedString("sourceAddress", modelRelative, identifierLimit)
            type.requiredBoundedString("status", modelRelative, identifierLimit)
        }

        val modules = moduleElements.map { element ->
            val module = element.jsonObject
            val functionIds = module.requiredArray("functionIds", planRelative)
                .boundedUniqueStrings(planRelative, identifierLimit, "generated C module function IDs")
            val globalIds = module.requiredArray("globalIds", planRelative)
                .boundedUniqueStrings(planRelative, identifierLimit, "generated C module global IDs")
            val typeIds = if (planSchemaVersion == PLAN_SCHEMA_VERSION) {
                module.requiredArray("typeIds", planRelative)
                    .boundedUniqueStrings(planRelative, identifierLimit, "generated C module type IDs")
            } else {
                emptyList()
            }
            PlannedModule(
                id = module.requiredBoundedString("id", planRelative, identifierLimit),
                sourcePath = normalizedProfilePath(
                    module.requiredBoundedString("sourcePath", planRelative, identifierLimit),
                ),
                headerPath = normalizedProfilePath(
                    module.requiredBoundedString("headerPath", planRelative, identifierLimit),
                ),
                functionIds = functionIds,
                globalIds = globalIds,
                typeIds = typeIds,
            )
        }.also { parsed ->
            requireUniqueValues(parsed.map { it.id }, "generated C module IDs")
            parsed.forEach { module ->
                require(module.sourcePath in sourcePaths && module.sourcePath in editablePaths) {
                    "generated C module source is not an editable discovered input: ${module.sourcePath}"
                }
                require(module.headerPath in sourcePaths) {
                    "generated C module header is not a discovered input: ${module.headerPath}"
                }
            }
        }
        val plannedModuleIds = modules.mapTo(hashSetOf()) { it.id }
        cycleElements.forEach { element ->
            val cycle = element.jsonArray.boundedUniqueStrings(
                planRelative,
                identifierLimit,
                "generated C dependency-cycle module IDs",
            )
            require(cycle.all { it in plannedModuleIds }) {
                "generated C dependency cycle references an unknown module"
            }
        }
        val functions = functionElements.map { element ->
            val function = element.jsonObject
            ProgramFunction(
                id = function.requiredBoundedString("id", modelRelative, identifierLimit),
                name = function.requiredBoundedString("name", modelRelative, identifierLimit),
                calls = function.requiredArray("calls", modelRelative)
                    .boundedUniqueStrings(modelRelative, identifierLimit, "generated C function calls"),
                referencedGlobals = function.requiredArray("referencedGlobals", modelRelative)
                    .boundedUniqueStrings(modelRelative, identifierLimit, "generated C global references"),
            )
        }.also { parsed ->
            requireUniqueValues(parsed.map { it.id }, "generated C function IDs")
        }
        val globals = globalElements.map { element ->
            val global = element.jsonObject
            ProgramGlobal(
                global.requiredBoundedString("id", modelRelative, identifierLimit),
                global.requiredBoundedString("name", modelRelative, identifierLimit),
            )
        }.also { parsed ->
            requireUniqueValues(parsed.map { it.id }, "generated C global IDs")
        }
        val types = typeElements.map { element ->
            ProgramType(element.jsonObject.requiredBoundedString("id", modelRelative, identifierLimit))
        }.also { parsed ->
            requireUniqueValues(parsed.map { it.id }, "generated C type IDs")
        }
        val functionIds = functions.mapTo(hashSetOf()) { it.id }
        val globalIds = globals.mapTo(hashSetOf()) { it.id }
        functions.forEach { function ->
            require(function.calls.all { it in functionIds }) { "generated C function calls an unknown function" }
            require(function.referencedGlobals.all { it in globalIds }) {
                "generated C function references an unknown global"
            }
        }
        return GeneratedCIndexEvidence(
            modules.sortedBy { it.id },
            functions.sortedBy { it.id },
            globals.sortedBy { it.id },
            if (planSchemaVersion == PLAN_SCHEMA_VERSION) types.sortedBy { it.id } else emptyList(),
        )
    }

    private fun chargeBoundedCount(current: Long, addition: Int, limit: Long, subject: String): Long {
        if (addition.toLong() > limit - current) {
            throw RepairBudgetExceededException("$subject exceed $limit entries")
        }
        return current + addition
    }

    private fun evidenceIdentifierLimit(budget: RepairResourceBudget): Int =
        minOf(MAXIMUM_EVIDENCE_IDENTIFIER_CHARACTERS, budget.maximumIndexEvidenceBytes.toInt())

    private fun evidenceTextLimit(budget: RepairResourceBudget): Int =
        minOf(MAXIMUM_EVIDENCE_TEXT_CHARACTERS, budget.maximumIndexEvidenceBytes.toInt())

    private fun JsonObject.requireExactKeys(expected: Set<String>, subject: String) {
        require(keys == expected) {
            "$subject has an incompatible generated C evidence shape; " +
                "missing=${expected - keys} unexpected=${keys - expected}"
        }
    }

    private fun JsonObject.requiredArray(name: String, subject: String): JsonArray =
        requireNotNull(this[name]) { "$subject is missing $name" }.jsonArray

    private fun JsonObject.requiredInt(name: String, subject: String): Int {
        val primitive = this[name]?.jsonPrimitive
            ?: throw IllegalArgumentException("$subject is missing integer $name")
        if (primitive.isString) throw IllegalArgumentException("$subject has non-integer $name")
        return primitive.intOrNull ?: throw IllegalArgumentException("$subject is missing integer $name")
    }

    private fun JsonObject.requiredBoolean(name: String, subject: String): Boolean {
        val primitive = this[name]?.jsonPrimitive
            ?: throw IllegalArgumentException("$subject is missing boolean $name")
        if (primitive.isString) throw IllegalArgumentException("$subject has non-boolean $name")
        return primitive.booleanOrNull ?: throw IllegalArgumentException("$subject is missing boolean $name")
    }

    private fun JsonObject.requiredBoundedString(name: String, subject: String, maximumCharacters: Int): String =
        requireNotNull(this[name]) { "$subject is missing $name" }
            .requiredBoundedString(subject, maximumCharacters)

    private fun JsonElement.requiredBoundedString(
        subject: String,
        maximumCharacters: Int,
        allowBlank: Boolean = false,
    ): String {
        val primitive = jsonPrimitive
        require(primitive.isString) { "$subject contains a non-string evidence value" }
        val value = primitive.content
        require(allowBlank || value.isNotBlank()) { "$subject contains a blank evidence string" }
        if (value.length > maximumCharacters) {
            throw RepairBudgetExceededException(
                "$subject contains a ${value.length}-character string; limit=$maximumCharacters",
            )
        }
        return value
    }

    private fun JsonObject.requireNullableBoundedString(
        name: String,
        subject: String,
        maximumCharacters: Int,
        allowBlank: Boolean = false,
    ) {
        val element = requireNotNull(this[name]) { "$subject is missing $name" }
        if (element !is JsonNull) element.requiredBoundedString(subject, maximumCharacters, allowBlank)
    }

    private fun JsonArray.preflightStringElements(
        subject: String,
        maximumCharacters: Int,
        allowBlank: Boolean = false,
    ) {
        forEach { it.requiredBoundedString(subject, maximumCharacters, allowBlank) }
    }

    private fun JsonArray.boundedUniqueStrings(
        subject: String,
        maximumCharacters: Int,
        label: String,
    ): List<String> {
        val values = map { it.requiredBoundedString(subject, maximumCharacters) }
        requireUniqueValues(values, label)
        return values.sorted()
    }

    private fun requireUniqueValues(values: List<String>, label: String) {
        val observed = HashSet<String>(values.size)
        require(values.all(observed::add)) { "$label must be unique" }
    }

    private fun readOptionalEvidence(root: Path, relative: String, maximumBytes: Long): ByteArray? {
        if (!Files.exists(root.resolve(relative), LinkOption.NOFOLLOW_LINKS)) return null
        if (maximumBytes <= 0) {
            throw RepairBudgetExceededException("generated C index evidence exceeds its byte budget")
        }
        return readStableRegularFile(root, relative, maximumBytes).bytes
    }

    private fun discoverSourcePaths(root: Path, budget: RepairResourceBudget): List<String> {
        val paths = TreeSet<String>()
        var entries = 0
        var directories = 0
        fun countEntry(relative: String) {
            entries = Math.addExact(entries, 1)
            if (entries > budget.maximumDiscoveryEntries) {
                throw RepairBudgetExceededException(
                    "generated C discovery exceeds ${budget.maximumDiscoveryEntries} entries at $relative",
                )
            }
        }
        fun countDirectory(relative: String, depth: Int) {
            require(depth <= budget.maximumDiscoveryDepth) {
                "generated C discovery exceeds depth ${budget.maximumDiscoveryDepth} at $relative"
            }
            directories = Math.addExact(directories, 1)
            if (directories > budget.maximumDiscoveryDirectories) {
                throw RepairBudgetExceededException(
                    "generated C discovery exceeds ${budget.maximumDiscoveryDirectories} directories at $relative",
                )
            }
        }
        fun names(directory: LinuxDescriptor, relativeDirectory: String): List<String> {
            val discovered = ArrayList<String>()
            Files.newDirectoryStream(repairDescriptorPath(directory)).use { stream ->
                stream.forEach { path ->
                    val name = path.fileName.toString()
                    require(name.isNotBlank() && '/' !in name && name !in setOf(".", "..")) {
                        "generated C discovery returned an invalid directory entry"
                    }
                    countEntry(normalizedProfilePath("$relativeDirectory/$name"))
                    discovered += name
                }
            }
            discovered.sort()
            return discovered
        }
        fun traverse(
            directory: LinuxDescriptor,
            relativeDirectory: String,
            depth: Int,
            excludedAncestor: Boolean,
            rootMount: Long,
        ) {
            names(directory, relativeDirectory).forEach { name ->
                val relative = normalizedProfilePath("$relativeDirectory/$name")
                val entry = requireNotNull(LinuxFilesystemSyscalls.openPathAtOrNull(directory.fd, name)) {
                    "generated C discovery entry disappeared: $relative"
                }
                entry.use {
                    require(!entry.identity.isSymbolicLink && entry.identity.mountId == rootMount) {
                        "generated C discovery rejects links or mounted entries: $relative"
                    }
                    when {
                        entry.identity.isDirectory -> {
                            countDirectory(relative, depth + 1)
                            LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, name).use { child ->
                                require(child.identity.key == entry.identity.key && child.identity.mountId == rootMount) {
                                    "generated C discovery directory changed identity: $relative"
                                }
                                traverse(
                                    child,
                                    relative,
                                    depth + 1,
                                    excludedAncestor || relative.endsWith(".repair"),
                                    rootMount,
                                )
                            }
                        }
                        entry.identity.isRegularFile -> {
                            if (!excludedAncestor && !relative.endsWith(".repair")) {
                                if (paths.size >= budget.maximumSourceFiles) {
                                    throw RepairBudgetExceededException(
                                        "generated C project has more than ${budget.maximumSourceFiles} source files",
                                    )
                                }
                                paths += relative
                            }
                        }
                        else -> error("generated C project contains a non-regular source input: $relative")
                    }
                }
            }
        }

        openRepairRootDirectory(root).use { rootDescriptor ->
            val rootMount = rootDescriptor.identity.mountId
            LinuxFilesystemSyscalls.openPathAtOrNull(rootDescriptor.fd, MAKEFILE)?.use { makefile ->
                countEntry(MAKEFILE)
                require(makefile.identity.isRegularFile && !makefile.identity.isSymbolicLink &&
                    makefile.identity.mountId == rootMount) {
                    "generated C Makefile is not a regular contained file"
                }
                paths += MAKEFILE
            }
            listOf("include", "src").forEach { directoryName ->
                val authorized = LinuxFilesystemSyscalls.openPathAtOrNull(rootDescriptor.fd, directoryName)
                    ?: return@forEach
                authorized.use {
                    countEntry(directoryName)
                    require(authorized.identity.isDirectory && !authorized.identity.isSymbolicLink &&
                        authorized.identity.mountId == rootMount) {
                        "generated C source root is not a regular contained directory: $directoryName"
                    }
                    countDirectory(directoryName, 1)
                    LinuxFilesystemSyscalls.openDirectoryAt(rootDescriptor.fd, directoryName).use { directory ->
                        require(directory.identity.key == authorized.identity.key && directory.identity.mountId == rootMount) {
                            "generated C source root changed identity: $directoryName"
                        }
                        traverse(directory, directoryName, 1, false, rootMount)
                    }
                }
            }
        }
        if (paths.size > budget.maximumSourceFiles) {
            throw RepairBudgetExceededException(
                "generated C project has more than ${budget.maximumSourceFiles} source files",
            )
        }
        return paths.toList()
    }

    private fun deriveIncludes(
        root: Path,
        sourcePaths: Set<String>,
        budget: RepairResourceBudget,
    ): Map<String, List<String>> {
        val result = TreeMap<String, List<String>>()
        var count = 0L
        sourcePaths.filter { it.endsWith(".c") || it.endsWith(".h") }.sorted().forEach { relative ->
            val text = decodeGeneratedCText(
                readStableRegularFile(root, relative, budget.maximumSourceFileBytes).bytes,
                relative,
            )
            val dependencies = INCLUDE_DIRECTIVE.findAll(text).mapNotNull { match ->
                resolveInclude(relative, match.groupValues[2], match.groupValues[1] == "\"", sourcePaths)
            }.distinct().sorted().toList()
            count = Math.addExact(count, dependencies.size.toLong())
            if (count > budget.maximumDependencyEdges) {
                throw RepairBudgetExceededException(
                    "generated C include evidence exceeds ${budget.maximumDependencyEdges} edges",
                )
            }
            result[relative] = dependencies
        }
        return result
    }

    private fun resolveInclude(
        includingPath: String,
        includeName: String,
        quoted: Boolean,
        sourcePaths: Set<String>,
    ): String? {
        if (includeName.isBlank() || '\\' in includeName || includeName.startsWith('/')) return null
        val candidates = buildList {
            if (quoted) {
                val parent = Path.of(includingPath).parent ?: Path.of("")
                add(parent.resolve(includeName).normalize().pathString.replace('\\', '/'))
            }
            add("include/$includeName")
            add(includeName)
        }
        return candidates.firstOrNull { candidate ->
            candidate.isNotBlank() && !candidate.startsWith('/') &&
                candidate.split('/').none { it in setOf("", ".", "..") } && candidate in sourcePaths
        }
    }

    private fun normalizedProfilePath(value: String): String {
        require(value.isNotBlank() && '\\' !in value && !value.startsWith('/')) { "invalid generated C profile path" }
        require(value.split('/').none { it in setOf("", ".", "..") }) { "invalid generated C profile path" }
        return value
    }

    private const val INDEX_EVIDENCE_SCHEMA_VERSION = 1
    private const val LEGACY_PLAN_SCHEMA_VERSION = 1
    private const val PLAN_SCHEMA_VERSION = 2
    private const val BUILD_CONTRACT_SCHEMA_VERSION = 2
    private const val MAXIMUM_EVIDENCE_IDENTIFIER_CHARACTERS = 4_096
    private const val MAXIMUM_EVIDENCE_TEXT_CHARACTERS = 16 * 1024 * 1024
    private const val MAKEFILE = "Makefile"
    private const val TYPES_HEADER = "include/decomp_types.h"
    private val SHARED_BUILD_OWNERS = setOf("link", "project")
    private val PLAN_ROOT_KEYS = setOf("schemaVersion", "modules", "dependencyCycles")
    private val LEGACY_PLAN_MODULE_KEYS = setOf(
        "id",
        "sourcePath",
        "headerPath",
        "functionIds",
        "globalIds",
        "boundaryEvidence",
    )
    private val PLAN_MODULE_KEYS = LEGACY_PLAN_MODULE_KEYS + "typeIds"
    private val MODEL_ROOT_KEYS = setOf("schemaVersion", "inputSha256", "functions", "globals", "types")
    private val MODEL_FUNCTION_KEYS = setOf(
        "id",
        "name",
        "address",
        "prototype",
        "status",
        "calls",
        "referencedGlobals",
        "strings",
        "decompiledC",
    )
    private val MODEL_GLOBAL_KEYS = setOf(
        "id",
        "name",
        "address",
        "type",
        "initializer",
        "status",
    )
    private val MODEL_TYPE_KEYS = setOf("id", "declaration", "sourceAddress", "status")
    private val DIAGNOSTIC_FAILURE = Regex(
        "error:|fatal error:|undefined reference|no rule to make target|\\*\\*\\*|failed",
        RegexOption.IGNORE_CASE,
    )
    private val INCLUDE_DIRECTIVE = Regex("(?m)^[ \\t]*#[ \\t]*include[ \\t]*([<\\\"])([^>\\\"\\r\\n]+)[>\\\"]")
}

private fun decodeGeneratedCText(bytes: ByteArray, relative: String): String = try {
    Charsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: java.nio.charset.CharacterCodingException) {
    throw IllegalArgumentException("generated C profile input is not valid UTF-8 text: $relative", failure)
}

/**
 * Capability required by the generated-C adapter to validate hostile candidate source.
 *
 * A production implementation must snapshot the exact bounded project inputs into a private,
 * quota-backed workspace; clear the host environment; mount only pinned tool/runtime inputs; deny
 * network access; enforce tree-wide pids, memory, CPU/wall, writable-file, and output limits; and
 * return only bounded authenticated build evidence and artifacts. It must never execute a
 * candidate-controlled build file in the canonical project tree. Behavior runs use a fresh
 * contained scope and mount the authenticated executable itself, never its sibling directory.
 */
interface GeneratedCRepairValidationBoundary {
    val assurance: RepairValidationAssurance
    fun requireAvailable()
    fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome =
        throw SandboxUnavailableException("generated-C boundary does not implement immutable candidate validation")
    fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure?
    fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path
    fun evaluateBehavior(
        id: String,
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
        budget: RepairResourceBudget,
    ): BehaviorComparisonReport
}

/** Fail-closed placeholder until a verified generic process boundary is wired by the application. */
object UnavailableGeneratedCRepairValidationBoundary : GeneratedCRepairValidationBoundary {
    override val assurance: RepairValidationAssurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS
    private fun unavailable(): Nothing = throw SandboxUnavailableException(
        "generated-C repair requires a production snapshot/build/behavior validation boundary",
    )

    override fun requireAvailable() = unavailable()
    override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? = unavailable()
    override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path = unavailable()
    override fun evaluateBehavior(
        id: String,
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
        budget: RepairResourceBudget,
    ): BehaviorComparisonReport = unavailable()
}

/** Generated C/Make profile adapter; all execution is delegated to its mandatory boundary. */
class GeneratedCRepairValidationStrategy(
    private val boundary: GeneratedCRepairValidationBoundary,
) : RepairValidationStrategy {
    override val assurance: RepairValidationAssurance = boundary.assurance
    override fun requireAvailable() = boundary.requireAvailable()

    override fun validateCandidate(request: RepairCandidateValidationRequest): RepairCandidateValidationOutcome =
        if (assurance == RepairValidationAssurance.STRICT_CONTAINED) boundary.validateCandidate(request)
        else super.validateCandidate(request)

    override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? =
        boundary.compile(projectDir, logPath, budget)

    override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
        boundary.rebuiltProgram(projectDir, budget)

    override fun evaluateBehavior(
        id: String,
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
        budget: RepairResourceBudget,
    ): BehaviorComparisonReport = boundary.evaluateBehavior(
        id,
        projectDir,
        originalBinary,
        rebuiltBinary,
        inputs,
        reportsDir,
        budget,
    )
}
