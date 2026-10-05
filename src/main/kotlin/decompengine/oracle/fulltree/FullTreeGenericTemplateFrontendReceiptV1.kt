package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.util.Collections
import java.util.LinkedHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Canonical action and full-run receipts for the authenticated generic-template frontend v1. */
object FullTreeGenericTemplateFrontendReceiptV1 {
    const val SCHEMA_NAME = "full-tree-generic-template-frontend-v1"
    const val UNIT_RECEIPT_DOMAIN = "decomp-thing/generic-template/unit-receipt/v1"
    const val RECEIPT_SET_DOMAIN = "decomp-thing/generic-template/receipt-set/v1"

    val BINDING_FIELDS: Set<String> = linkedSetOf(
        "scopeSha256", "sourceLockSha256", "artifactManifestSha256", "buildRecordSha256", "sourceArchiveSha256",
        "sourceInventorySha256", "generatedInventorySha256", "richArtifactSha256", "richInventorySha256",
        "compilationDatabaseSha256", "frontendProfileSha256",
    )
    val DOCUMENT_FIELDS: Set<String> = linkedSetOf(
        "schemaVersion", "policyId", "policyVersion", "configurationSha256", "bindings", "units", "counts",
    )
    val UNIT_FIELDS: Set<String> = linkedSetOf(
        "unitId", "actionId", "sourcePath", "sourceFileSha256", "captureActionSha256", "argvSha256",
        "executionArgvSha256", "cwd", "environment", "environmentSha256", "dependencySetSha256", "dependencies",
        "semanticContextSha256", "resolvedResourceDirectory", "resourceHeaderManifestSha256", "frontendProfileSha256",
        "adapterSha256", "receiptSha256", "exitCode", "outputBytes",
    )
    val COUNT_FIELDS: Set<String> = linkedSetOf("unitCount", "dependencyCount", "outputBytes")
    val DEPENDENCY_ROLES: Set<String> = linkedSetOf(
        "compiler-executable", "toolchain-runtime", "main-source", "resource-header", "header", "source",
        "generated", "build-input",
    )

    data class Limits(
        /** Caller-provided remaining scope limits; the adapter never raises these. */
        val maximumUnits: Long,
        val maximumDependencyRows: Long,
        val maximumDependencyBytes: Long,
        val maximumReceiptBytes: Long,
        val maximumOutputBytes: Long,
    ) {
        init {
            require(maximumUnits > 0L)
            require(maximumDependencyRows > 0L)
            require(maximumDependencyBytes > 0L)
            require(maximumReceiptBytes > 0L)
            require(maximumOutputBytes >= 0L)
        }
    }

    data class ValidatedReceipt(
        val document: JsonObject,
        val frontendReceiptSha256: String,
        val unitCount: Long,
        val dependencyCount: Long,
        val dependencyBytes: Long,
        val receiptBytes: Long,
        val outputBytes: Long,
        val profileSha256: String,
    )

    /** Validate one complete receipt. Nothing is returned until all bindings and limits pass. */
    fun validate(
        value: JsonObject,
        limits: Limits,
        expectedBindings: JsonObject? = null,
        expectedPathTransform: FullTreeGenericTemplateFrontendProfileV1.PathTransformV1? = null,
        expectedProfile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1? = null,
        expectedRawEnvironment: Map<String, String>? = null,
        expectedSourceFileDigests: Map<String, String> = emptyMap(),
        expectedResourceManifest: FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1? = null,
        expectedDriverPath: String? = null,
    ): ValidatedReceipt {
        requireExactFields(value, DOCUMENT_FIELDS, "frontend provenance document")
        requireInteger(value, "schemaVersion", 1L)
        requireString(value, "policyId", FullTreeGenericTemplateFrontendProfileV1.POLICY_ID)
        requireInteger(value, "policyVersion", FullTreeGenericTemplateFrontendProfileV1.POLICY_VERSION.toLong())
        sha256(string(value, "configurationSha256"), "frontend configuration digest")
        val bindings = value["bindings"] as? JsonObject ?: reject("frontend provenance bindings are invalid")
        requireExactFields(bindings, BINDING_FIELDS, "frontend provenance bindings")
        bindings.values.forEach { sha256(primitiveString(it, "frontend binding"), "frontend binding") }
        if (expectedBindings != null && bindings != expectedBindings) {
            reject("frontend provenance bindings differ from validated raw inputs")
        }
        val profileSha = string(bindings, "frontendProfileSha256")
        if (expectedProfile != null && profileSha != expectedProfile.sha256()) {
            reject("frontend provenance profile differs from the authenticated profile")
        }
        if (expectedPathTransform != null && expectedProfile != null) {
            try {
                expectedProfile.requirePathTransform(expectedPathTransform)
            } catch (failure: Exception) {
                throw FullTreeControlException("frontend profile differs from the authenticated PATH transform", failure)
            }
        }
        if (expectedResourceManifest != null && expectedProfile != null &&
            (expectedResourceManifest.resolvedResourceDirectory != expectedProfile.resolvedResourceDirectory ||
                expectedResourceManifest.sha256 != expectedProfile.resourceHeaderManifestSha256)
        ) reject("frontend profile differs from the independently loaded resource manifest")

        val units = value["units"] as? JsonArray ?: reject("frontend provenance units are invalid")
        if (units.isEmpty() || units.size.toLong() > limits.maximumUnits) {
            reject("frontend provenance action count exceeds the authenticated scope limit")
        }
        var dependencyRows = 0L
        var dependencyBytes = 0L
        var outputBytes = 0L
        val unitObjects = ArrayList<JsonObject>(units.size)
        val unitIds = HashSet<String>()
        val actionIds = HashSet<String>()
        var previousUnit: Pair<String, String>? = null
        for (element in units) {
            val unit = element as? JsonObject ?: reject("frontend provenance unit is invalid")
            requireExactFields(unit, UNIT_FIELDS, "frontend provenance unit")
            val unitId = string(unit, "unitId")
            val actionId = string(unit, "actionId")
            identifier(unitId, "frontend unit id")
            sha256(actionId, "frontend action id")
            if (!unitIds.add(unitId) || !actionIds.add(actionId)) reject("frontend provenance repeats an action or unit")
            val order = unitId to actionId
            if (previousUnit != null && compareTuple(previousUnit!!, order) >= 0) {
                reject("frontend provenance units are not sorted by (unitId, actionId)")
            }
            previousUnit = order
            validateUnit(
                unit, bindings, expectedPathTransform, expectedProfile, expectedRawEnvironment,
                expectedSourceFileDigests, expectedResourceManifest, expectedDriverPath,
            )
            val dependencies = unit["dependencies"] as? JsonArray
                ?: reject("frontend unit dependencies are invalid")
            dependencyRows = addExact(dependencyRows, dependencies.size.toLong(), "frontend dependency count")
            val remainingDependencyBytes = limits.maximumDependencyBytes - dependencyBytes
            dependencyBytes = addExact(
                dependencyBytes,
                FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
                    dependencies,
                    remainingDependencyBytes,
                    "frontend dependency rows",
                ).size.toLong(),
                "frontend dependency bytes",
            )
            outputBytes = addExact(outputBytes, longValue(unit, "outputBytes"), "frontend output bytes")
            unitObjects += unit
        }
        if (dependencyRows > limits.maximumDependencyRows) {
            reject("frontend dependency count exceeds the authenticated scope limit")
        }
        if (dependencyBytes > limits.maximumDependencyBytes) {
            reject("frontend dependency bytes exceed the authenticated scope limit")
        }
        if (outputBytes > limits.maximumOutputBytes) {
            reject("frontend output bytes exceed the authenticated scope limit")
        }

        val counts = value["counts"] as? JsonObject ?: reject("frontend provenance counts are invalid")
        requireExactFields(counts, COUNT_FIELDS, "frontend provenance counts")
        if (longValue(counts, "unitCount") != unitObjects.size.toLong() ||
            longValue(counts, "dependencyCount") != dependencyRows ||
            longValue(counts, "outputBytes") != outputBytes || outputBytes != 0L
        ) {
            reject("frontend provenance counts do not match its complete unit population")
        }

        val bytes = FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
            value,
            limits.maximumReceiptBytes,
            "frontend receipt",
        )
        if (bytes.size.toLong() > limits.maximumReceiptBytes) reject("frontend receipt bytes exceed the authenticated scope limit")
        val receiptSet = receiptSetPreimage(value)
        val aggregate = FullTreeGenericTemplateFrontendProfileV1.domainHash(RECEIPT_SET_DOMAIN, receiptSet)
        return ValidatedReceipt(
            snapshot(value), aggregate, unitObjects.size.toLong(), dependencyRows, dependencyBytes,
            bytes.size.toLong(), outputBytes, profileSha,
        )
    }

    fun loadCanonical(
        path: java.nio.file.Path,
        limits: Limits,
        expectedBindings: JsonObject? = null,
        expectedPathTransform: FullTreeGenericTemplateFrontendProfileV1.PathTransformV1? = null,
        expectedProfile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1? = null,
        expectedRawEnvironment: Map<String, String>? = null,
        expectedSourceFileDigests: Map<String, String> = emptyMap(),
        expectedResourceManifest: FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1? = null,
        expectedDriverPath: String? = null,
    ): ValidatedReceipt {
        val maximum = minOf(
            limits.maximumReceiptBytes,
            FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
        ).toInt()
        val artifact = try {
            OracleArtifacts.read(path, decompengine.oracle.core.OracleArtifactLimits(maximum))
        } catch (failure: Exception) {
            throw FullTreeControlException("cannot read frontend provenance receipt", failure)
        }
        val parsed = try {
            OracleJson.parseCanonical(
                artifact.bytes,
                decompengine.oracle.core.StrictJsonLimits(
                    maximumInputBytes = maximum,
                    maximumCanonicalBytes = maximum,
                    maximumDepth = 128,
                    maximumNodes = 1_000_000,
                    maximumStringBytes = maximum,
                    maximumTotalStringBytes = maximum,
                ),
            ) as? JsonObject ?: reject("frontend provenance root is invalid")
        } catch (failure: FullTreeControlException) {
            throw failure
        } catch (failure: Exception) {
            throw FullTreeControlException("frontend provenance is not strict canonical JSON", failure)
        }
        val validated = validate(
            parsed, limits, expectedBindings, expectedPathTransform, expectedProfile,
            expectedRawEnvironment, expectedSourceFileDigests, expectedResourceManifest, expectedDriverPath,
        )
        if (validated.receiptBytes != artifact.bytes.size.toLong()) {
            reject("frontend provenance canonical byte count changed during validation")
        }
        // Provenance.loadAndValidate applies the bundled schema and configuration gate after this data validation.
        return validated
    }

    /** Unit receipt preimage is the exact unit object minus dependencies and receiptSha256. */
    fun unitReceiptPreimage(unit: JsonObject): JsonObject {
        requireExactFields(unit, UNIT_FIELDS, "frontend provenance unit")
        return JsonObject(unit.filterKeys { it != "dependencies" && it != "receiptSha256" })
    }

    fun unitReceiptSha256(unit: JsonObject): String = FullTreeGenericTemplateFrontendProfileV1.domainHash(
        UNIT_RECEIPT_DOMAIN,
        unitReceiptPreimage(unit),
    )

    fun dependencySetSha256(dependencies: JsonArray): String =
        OracleArtifacts.sha256(FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
            dependencies,
            FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
            "frontend dependency rows",
        ))

    fun environmentSha256(environment: JsonObject): String =
        OracleArtifacts.sha256(FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
            environment,
            FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
            "frontend environment",
        ))

    /** Exact 23-key action preimage defined by the accepted design. */
    fun actionIdPreimage(bindings: JsonObject, unit: JsonObject): JsonObject {
        requireExactFields(bindings, BINDING_FIELDS, "frontend provenance bindings")
        requireExactFields(unit, UNIT_FIELDS, "frontend provenance unit")
        return JsonObject(
            mapOf(
                "adapterSha256" to unit.getValue("adapterSha256"),
                "artifactManifestSha256" to bindings.getValue("artifactManifestSha256"),
                "argvSha256" to unit.getValue("argvSha256"),
                "buildRecordSha256" to bindings.getValue("buildRecordSha256"),
                "captureActionSha256" to unit.getValue("captureActionSha256"),
                "compilationDatabaseSha256" to bindings.getValue("compilationDatabaseSha256"),
                "cwd" to unit.getValue("cwd"),
                "dependencySetSha256" to unit.getValue("dependencySetSha256"),
                "executionArgvSha256" to unit.getValue("executionArgvSha256"),
                "environmentSha256" to unit.getValue("environmentSha256"),
                "frontendProfileSha256" to unit.getValue("frontendProfileSha256"),
                "generatedInventorySha256" to bindings.getValue("generatedInventorySha256"),
                "richArtifactSha256" to bindings.getValue("richArtifactSha256"),
                "richInventorySha256" to bindings.getValue("richInventorySha256"),
                "resolvedResourceDirectory" to unit.getValue("resolvedResourceDirectory"),
                "resourceHeaderManifestSha256" to unit.getValue("resourceHeaderManifestSha256"),
                "scopeSha256" to bindings.getValue("scopeSha256"),
                "semanticContextSha256" to unit.getValue("semanticContextSha256"),
                "sourceArchiveSha256" to bindings.getValue("sourceArchiveSha256"),
                "sourceFileSha256" to unit.getValue("sourceFileSha256"),
                "sourceInventorySha256" to bindings.getValue("sourceInventorySha256"),
                "sourceLockSha256" to bindings.getValue("sourceLockSha256"),
                "unitId" to unit.getValue("unitId"),
            ),
        )
    }

    fun actionId(bindings: JsonObject, unit: JsonObject): String =
        FullTreeGenericTemplateFrontendProfileV1.domainHash(
            "decomp-thing/generic-template/action/v1",
            actionIdPreimage(bindings, unit),
        )

    /** Exact seven-field aggregate receipt preimage for an already structurally validated envelope. */
    fun receiptSetPreimage(document: JsonObject): JsonObject {
        requireExactFields(document, DOCUMENT_FIELDS, "frontend provenance document")
        val units = document["units"] as? JsonArray ?: reject("frontend provenance units are invalid")
        val unitReceipts = JsonArray(units.map { element ->
            val unit = element as? JsonObject ?: reject("frontend provenance unit is invalid")
            JsonObject(
                mapOf(
                    "unitId" to (unit["unitId"] ?: reject("frontend unit id is missing")),
                    "actionId" to (unit["actionId"] ?: reject("frontend action id is missing")),
                    "receiptSha256" to (unit["receiptSha256"] ?: reject("frontend unit receipt digest is missing")),
                ),
            )
        })
        return JsonObject(
            mapOf(
                "bindings" to (document["bindings"] ?: reject("frontend provenance bindings are missing")),
                "configurationSha256" to (document["configurationSha256"] ?: reject("frontend configuration digest is missing")),
                "counts" to (document["counts"] ?: reject("frontend provenance counts are missing")),
                "policyId" to (document["policyId"] ?: reject("frontend policy id is missing")),
                "policyVersion" to (document["policyVersion"] ?: reject("frontend policy version is missing")),
                "schemaVersion" to (document["schemaVersion"] ?: reject("frontend schema version is missing")),
                "unitReceipts" to unitReceipts,
            ),
        )
    }

    /** Authenticate captured argument bytes and strip only original indices 2 through 6. */
    fun deriveExecutionArgv(arguments: List<String>, mainSource: String): List<String> {
        if (arguments.size < 11 || arguments[1] != "--no-default-config" || arguments[2] != "-MD" ||
            arguments[3] != "-MT" || arguments[5] != "-MF" || arguments[7] != "-o" ||
            arguments[9] != "-c" || arguments[10] != mainSource || arguments[4] != arguments[8] ||
            arguments[6] != "${arguments[8]}.d"
        ) {
            reject("captured action does not match the validated fixed dependency frame")
        }
        return Collections.unmodifiableList(
            buildList(arguments.size - 5) {
                add(arguments[0])
                add(arguments[1])
                addAll(arguments.subList(7, arguments.size))
            },
        )
    }

    fun argvSha256(arguments: List<String>): String =
        OracleArtifacts.sha256(FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
            JsonArray(arguments.map(::JsonPrimitive)),
            FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
            "frontend argument vector",
        ))

    fun executionArgvSha256(arguments: List<String>, mainSource: String): String =
        OracleArtifacts.sha256(
            FullTreeGenericTemplateFrontendProfileV1.canonicalBytes(
                JsonArray(deriveExecutionArgv(arguments, mainSource).map(::JsonPrimitive)),
                FullTreeGenericTemplateFrontendProfileV1.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
                "frontend argument vector",
            ),
        )

    private fun validateUnit(
        unit: JsonObject,
        bindings: JsonObject,
        pathTransform: FullTreeGenericTemplateFrontendProfileV1.PathTransformV1?,
        profile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1?,
        expectedRawEnvironment: Map<String, String>?,
        expectedSourceFileDigests: Map<String, String>,
        expectedResourceManifest: FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1?,
        expectedDriverPath: String?,
    ) {
        setOf(
            "unitId", "actionId", "sourcePath", "sourceFileSha256", "captureActionSha256", "argvSha256",
            "executionArgvSha256", "cwd", "environmentSha256", "dependencySetSha256", "semanticContextSha256",
            "resolvedResourceDirectory", "resourceHeaderManifestSha256", "frontendProfileSha256", "adapterSha256",
            "receiptSha256",
        ).forEach { string(unit, it) }
        listOf(
            "sourceFileSha256", "captureActionSha256", "argvSha256", "executionArgvSha256", "environmentSha256",
            "dependencySetSha256", "semanticContextSha256", "resourceHeaderManifestSha256", "frontendProfileSha256",
            "adapterSha256", "receiptSha256",
        ).forEach { sha256(string(unit, it), "frontend unit $it") }
        if (longValue(unit, "exitCode") != 0L || longValue(unit, "outputBytes") != 0L) {
            reject("frontend receipt records a failed action or compiler output")
        }
        val unitProfile = string(unit, "frontendProfileSha256")
        if (unitProfile != string(bindings, "frontendProfileSha256") ||
            profile != null && unitProfile != profile.sha256()
        ) reject("frontend unit profile differs from the homogeneous run profile")
        val sourcePath = FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(
            string(unit, "sourcePath"), "source path",
        )
        if (!sourcePath.startsWith("source/") && !sourcePath.startsWith("generated/")) {
            reject("frontend unit source path is outside authenticated source inputs")
        }
        val cwd = FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(string(unit, "cwd"), "cwd")
        if (cwd.startsWith("toolchain/")) reject("frontend cwd is outside the authenticated action roots")
        val resourceDirectory = FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(
            string(unit, "resolvedResourceDirectory"), "resolved resource directory",
        )
        if (!resourceDirectory.startsWith("toolchain/")) reject("frontend resource directory is outside toolchain")
        if (profile != null && (resourceDirectory != profile.resolvedResourceDirectory ||
                string(unit, "resourceHeaderManifestSha256") != profile.resourceHeaderManifestSha256 ||
                string(unit, "adapterSha256") != profile.adapterSha256)
        ) reject("frontend unit resource or adapter binding differs from its profile")
        expectedSourceFileDigests[sourcePath]?.let { expected ->
            if (string(unit, "sourceFileSha256") != expected) reject("frontend unit source blob binding changed")
        }
        val environment = unit["environment"] as? JsonObject ?: reject("frontend unit environment is invalid")
        if (environment.keys.any { it !in FullTreeGenericTemplateFrontendProfileV1.ENVIRONMENT_ALLOWLIST } ||
            environment.values.any { it !is JsonPrimitive || !it.isString }
        ) reject("frontend unit environment is outside its exact allowlist")
        val requiredEnvironment = setOf("PATH", "HOME", "TMPDIR", "LC_ALL", "SOURCE_DATE_EPOCH", "TZ")
        val sourceDateEpoch = (environment["SOURCE_DATE_EPOCH"] as? JsonPrimitive)
            ?.takeIf { it.isString }?.content
        if (!environment.keys.containsAll(requiredEnvironment) ||
            environment["HOME"] != JsonPrimitive("/__decomp/home") ||
            environment["TMPDIR"] != JsonPrimitive("/__decomp/tmp") ||
            environment["LC_ALL"] != JsonPrimitive("C") ||
            environment["TZ"] != JsonPrimitive("UTC") ||
            sourceDateEpoch == null || !sourceDateEpoch.matches(Regex("^[1-9][0-9]*$")) ||
            sourceDateEpoch.toBigIntegerOrNull() == null ||
            (pathTransform == null && (environment["PATH"] as? JsonPrimitive)?.content?.matches(
                Regex("^/__decomp/toolchain/path/[0-9]{4}(:/__decomp/toolchain/path/[0-9]{4})*$"),
            ) != true) ||
            FullTreeGenericTemplateFrontendProfileV1.PATH_LIST_ENVIRONMENT.any { name ->
                environment[name]?.let { it != JsonPrimitive("") } == true
            }
        ) reject("frontend unit environment violates the required replay values")
        if (environmentSha256(environment) != string(unit, "environmentSha256")) {
            reject("frontend unit environment digest does not match its canonical environment")
        }
        if (pathTransform != null) {
            if (environment["PATH"] != JsonPrimitive(pathTransform.effectivePath) ||
                environment["HOME"] != JsonPrimitive("/__decomp/home") ||
                environment["TMPDIR"] != JsonPrimitive("/__decomp/tmp")
            ) {
                reject("frontend unit environment differs from the authenticated PATH transform")
            }
            val raw = expectedRawEnvironment?.let {
                FullTreeGenericTemplateFrontendProfileV1.effectiveEnvironment(it, pathTransform)
            }
            if (raw != null && (raw.sha256 != string(unit, "environmentSha256") || raw.json() != environment)) {
                reject("frontend unit environment differs from the authenticated PATH transform")
            }
        }
        val dependencies = unit["dependencies"] as? JsonArray ?: reject("frontend unit dependencies are invalid")
        validateDependencies(
            dependencies, sourcePath, string(unit, "sourceFileSha256"), profile,
            expectedSourceFileDigests, expectedResourceManifest, expectedDriverPath,
        )
        if (dependencySetSha256(dependencies) != string(unit, "dependencySetSha256")) {
            reject("frontend unit dependency-set digest does not match canonical rows")
        }
        if (actionId(bindings, unit) != string(unit, "actionId")) {
            reject("frontend unit action id does not match its exact 23-field preimage")
        }
        if (unitReceiptSha256(unit) != string(unit, "receiptSha256")) {
            reject("frontend unit receipt digest does not match its canonical preimage")
        }
    }

    private fun validateDependencies(
        dependencies: JsonArray,
        sourcePath: String,
        sourceSha256: String,
        profile: FullTreeGenericTemplateFrontendProfileV1.ProfileV1?,
        expectedFileDigests: Map<String, String>,
        expectedResourceManifest: FullTreeGenericTemplateFrontendProfileV1.ResourceManifestV1?,
        expectedDriverPath: String?,
    ) {
        var previous: String? = null
        val paths = HashSet<String>()
        var mainSourceCount = 0
        var driverCount = 0
        val runtimeRows = ArrayList<Pair<String, String>>()
        for (dependency in dependencies) {
            val row = dependency as? JsonObject ?: reject("frontend dependency row is invalid")
            requireExactFields(row, setOf("path", "sha256", "role"), "frontend dependency row")
            val path = FullTreeGenericTemplateFrontendProfileV1.requireCanonicalClosurePath(
                string(row, "path"), "dependency path",
            )
            val digest = string(row, "sha256")
            sha256(digest, "frontend dependency digest")
            val role = string(row, "role")
            if (role !in DEPENDENCY_ROLES) reject("frontend dependency has an unsupported role")
            if (!paths.add(path)) reject("frontend unit repeats a dependency path")
            if (previous != null && FullTreeGenericTemplateFrontendProfileV1.compareUtf8(previous!!, path) >= 0) {
                reject("frontend dependencies are not sorted by unsigned UTF-8 path bytes")
            }
            previous = path
            expectedFileDigests[path]?.let { expected ->
                if (digest != expected) reject("frontend dependency bytes differ from the authenticated closure")
            }
            if (profile != null && path !in expectedFileDigests) {
                reject("frontend dependency is absent from the independently revalidated closure")
            }
            when (role) {
                "compiler-executable" -> {
                    if (!path.startsWith("toolchain/") ||
                        profile != null && digest != profile.compilerSha256
                    ) {
                        reject("frontend compiler dependency differs from the pinned profile")
                    }
                    if (expectedDriverPath != null && path != expectedDriverPath) {
                        reject("frontend compiler dependency path differs from rederived C++ driver identity")
                    }
                    driverCount++
                }
                "toolchain-runtime" -> {
                    if (!path.startsWith("toolchain/")) reject("frontend runtime dependency is not in toolchain")
                    runtimeRows += path to digest
                }
                "main-source" -> {
                    if (path != sourcePath || digest != sourceSha256) {
                        reject("frontend main-source dependency differs from the selected source blob")
                    }
                    mainSourceCount++
                }
                "resource-header" -> if (!path.startsWith("toolchain/")) {
                    reject("frontend resource dependency is not in the authenticated toolchain")
                } else {
                    val resourceFile = expectedResourceManifest?.files?.singleOrNull { it.path == path }
                    if (profile != null && resourceFile == null ||
                        resourceFile != null && resourceFile.sha256 != digest
                    ) reject("frontend resource dependency differs from the exact resource manifest")
                }
                "header" -> if (expectedResourceManifest?.files?.any { it.path == path } == true) {
                    reject("frontend resource file is assigned a non-resource dependency role")
                }
                "source" -> if (!path.startsWith("source/")) reject("frontend source dependency is outside the source archive")
                "generated" -> if (!path.startsWith("generated/")) {
                    reject("frontend generated dependency is outside the generated inventory")
                }
                "build-input" -> if (!path.startsWith("build/")) {
                    reject("frontend build dependency is outside the authenticated build tree")
                }
            }
        }
        if (mainSourceCount != 1) reject("frontend unit must contain exactly its selected main-source dependency")
        if (profile != null) {
            val expectedRuntime = profile.runtimeLibraryDigests.map { it.path to it.sha256 }
            if (runtimeRows != expectedRuntime) reject("frontend runtime dependencies differ from the fixed loaded closure")
            if (driverCount != 1) reject("frontend unit must contain exactly one pinned compiler executable")
        }
    }

    private fun snapshot(value: JsonObject): JsonObject = JsonObject(LinkedHashMap(value))

    private fun requireExactFields(value: JsonObject, expected: Set<String>, label: String) {
        if (value.keys != expected) reject("$label has unknown or missing fields")
    }

    private fun string(value: JsonObject, key: String): String = primitiveString(
        value[key] ?: reject("frontend field is missing"), "frontend field",
    )

    private fun primitiveString(value: JsonElement, label: String): String =
        (value as? JsonPrimitive)?.takeIf { it.isString }?.content ?: reject("$label is invalid")

    private fun requireString(value: JsonObject, key: String, expected: String) {
        if (string(value, key) != expected) reject("frontend field has an unsupported value")
    }

    private fun requireInteger(value: JsonObject, key: String, expected: Long) {
        if (longValue(value, key) != expected) reject("frontend field has an unsupported value")
    }

    private fun longValue(value: JsonObject, key: String): Long {
        val primitive = value[key] as? JsonPrimitive ?: reject("frontend integer field is invalid")
        if (primitive.isString) reject("frontend integer field is invalid")
        return primitive.content.toLongOrNull()?.takeIf { it >= 0L } ?: reject("frontend integer field is invalid")
    }

    private fun identifier(value: String, label: String) {
        if (value.isEmpty() || value.length > 16_384 || value.any { it.code < 0x21 || it.code > 0x7e }) {
            reject("$label is invalid")
        }
    }

    private fun sha256(value: String, label: String) =
        FullTreeGenericTemplateFrontendProfileV1.requireSha256(value, label)

    private fun addExact(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeControlException("$label exceeds signed 64-bit bounds", failure)
    }

    private fun compareTuple(left: Pair<String, String>, right: Pair<String, String>): Int {
        val first = FullTreeGenericTemplateFrontendProfileV1.compareUtf8(left.first, right.first)
        return if (first != 0) first else FullTreeGenericTemplateFrontendProfileV1.compareUtf8(left.second, right.second)
    }

    private fun reject(message: String): Nothing = throw FullTreeControlException(message)
}
