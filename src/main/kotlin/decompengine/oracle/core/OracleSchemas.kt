package decompengine.oracle.core

import io.github.optimumcode.json.schema.JsonSchema
import io.github.optimumcode.json.schema.ValidationError
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class OracleSchemaException(message: String, cause: Throwable? = null) : IllegalArgumentException(message, cause)

data class OracleSchemaIdentity(
    val name: String,
    val sha256: String,
)

/**
 * Application-owned access to the versioned JSON Schema contracts bundled in this JVM artifact.
 *
 * Schema names are logical resource names such as `full-tree-data-truth` or `gcc/build-record`;
 * callers cannot supply filesystem paths or remote schema locations. Documents must already have
 * passed [OracleJson]'s strict bounded parser before validation.
 */
object OracleSchemas {
    val supportedNames: Set<String>
        get() = SUPPORTED_NAMES

    fun identity(name: String): OracleSchemaIdentity = loaded(name).identity

    /** Hashes canonical policy bytes followed by the exact bundled schema bytes. */
    fun configurationSha256(name: String, policy: JsonElement): String =
        configurationSha256(listOf(name), policy)

    /**
     * Hashes canonical policy bytes followed by exact bundled schema bytes in caller order.
     *
     * Logical catalog names are resolved through the same bounded classpath-only loader as
     * [identity] and [validate]; callers cannot substitute filesystem or remote schema content.
     */
    fun configurationSha256(names: List<String>, policy: JsonElement): String {
        if (names.isEmpty()) throw OracleSchemaException("oracle configuration must bind at least one schema")
        if (names.toSet().size != names.size) {
            throw OracleSchemaException("oracle configuration schema names must be unique")
        }
        val schemas = names.map(::loaded)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(OracleJson.canonicalBytes(policy))
        schemas.forEach { digest.update(it.bytes) }
        return digest.digest().joinToString("") { byte ->
            (byte.toInt() and 0xff).toString(16).padStart(2, '0')
        }
    }

    fun validate(name: String, document: JsonElement) {
        val loaded = loaded(name)
        val errors = ArrayList<String>()
        val valid = try {
            loaded.schema.validate(document) { error ->
                if (errors.size >= MAXIMUM_REPORTED_ERRORS) throw TooManySchemaErrors()
                errors += boundedError(error)
            }
        } catch (_: TooManySchemaErrors) {
            throw OracleSchemaException(
                "oracle document fails ${loaded.identity.name} schema validation: " +
                    "at least ${MAXIMUM_REPORTED_ERRORS + 1} violations",
            )
        } catch (failure: OracleSchemaException) {
            throw failure
        } catch (failure: Exception) {
            throw OracleSchemaException(
                "oracle document could not be validated against ${loaded.identity.name}",
                failure,
            )
        }
        if (!valid || errors.isNotEmpty()) {
            val detail = errors.joinToString(separator = "; ").take(MAXIMUM_ERROR_DETAIL_CHARACTERS)
            throw OracleSchemaException(
                "oracle document fails ${loaded.identity.name} schema validation" +
                    if (detail.isEmpty()) "" else ": $detail",
            )
        }
    }

    private fun loaded(name: String): LoadedSchema = CACHE.computeIfAbsent(requireSchemaName(name), ::load)

    private fun load(name: String): LoadedSchema {
        val resourceName = "oracle/$name.schema.json"
        val bytes = OracleSchemas::class.java.classLoader.getResourceAsStream(resourceName)?.use { input ->
            val bounded = input.readNBytes(MAXIMUM_SCHEMA_BYTES + 1)
            if (bounded.size > MAXIMUM_SCHEMA_BYTES) {
                throw OracleSchemaException("bundled oracle schema exceeds its byte limit: $name")
            }
            bounded
        } ?: throw OracleSchemaException("bundled oracle schema is unavailable: $name")
        if (bytes.isEmpty()) throw OracleSchemaException("bundled oracle schema is empty: $name")
        val inventoryEntry = SCHEMA_INVENTORY[name]
            ?: throw OracleSchemaException("bundled oracle schema is absent from the versioned inventory: $name")
        if (inventoryEntry.path != resourceName || inventoryEntry.registration != SHARED_KOTLIN_REGISTRATION) {
            throw OracleSchemaException("bundled oracle schema has an invalid shared-catalog inventory entry: $name")
        }
        if (OracleArtifacts.sha256(bytes) != inventoryEntry.sha256) {
            throw OracleSchemaException("bundled oracle schema bytes do not match the versioned inventory: $name")
        }

        val canonical = try {
            OracleJson.parseAndCanonicalize(
                bytes,
                StrictJsonLimits(
                    maximumInputBytes = MAXIMUM_SCHEMA_BYTES,
                    maximumCanonicalBytes = MAXIMUM_SCHEMA_BYTES,
                    maximumDepth = MAXIMUM_SCHEMA_DEPTH,
                    maximumNodes = MAXIMUM_SCHEMA_NODES,
                    maximumStringBytes = MAXIMUM_SCHEMA_STRING_BYTES,
                    maximumTotalStringBytes = MAXIMUM_SCHEMA_TOTAL_STRING_BYTES,
                ),
            )
        } catch (failure: Exception) {
            throw OracleSchemaException("bundled oracle schema is not strict bounded JSON: $name", failure)
        }
        val schema = try {
            JsonSchema.fromDefinition(canonical.decodeToString())
        } catch (failure: Exception) {
            throw OracleSchemaException("bundled oracle schema cannot be compiled: $name", failure)
        }
        return LoadedSchema(
            OracleSchemaIdentity(name, OracleArtifacts.sha256(bytes)),
            schema,
            bytes.copyOf(),
        )
    }

    private fun requireSchemaName(name: String): String {
        if (!name.matches(SCHEMA_NAME)) {
            throw OracleSchemaException("oracle schema name is invalid")
        }
        if (name !in SUPPORTED_NAMES) {
            throw OracleSchemaException("oracle schema is not in the bundled contract catalog: $name")
        }
        return name
    }

    private fun loadSchemaInventory(): Map<String, SchemaInventoryEntry> {
        val bytes = OracleSchemas::class.java.classLoader
            .getResourceAsStream(SCHEMA_INVENTORY_RESOURCE)
            ?.use { input ->
                val bounded = input.readNBytes(MAXIMUM_SCHEMA_BYTES + 1)
                if (bounded.size > MAXIMUM_SCHEMA_BYTES) {
                    throw OracleSchemaException("versioned oracle schema inventory exceeds its byte limit")
                }
                bounded
            }
            ?: throw OracleSchemaException("versioned oracle schema inventory is unavailable")
        val root = try {
            OracleJson.parseCanonical(
                bytes,
                StrictJsonLimits(
                    maximumInputBytes = MAXIMUM_SCHEMA_BYTES,
                    maximumCanonicalBytes = MAXIMUM_SCHEMA_BYTES,
                    maximumDepth = MAXIMUM_SCHEMA_DEPTH,
                    maximumNodes = MAXIMUM_SCHEMA_NODES,
                    maximumStringBytes = MAXIMUM_SCHEMA_STRING_BYTES,
                    maximumTotalStringBytes = MAXIMUM_SCHEMA_TOTAL_STRING_BYTES,
                ),
            ) as? JsonObject ?: throw OracleSchemaException("versioned oracle schema inventory must be an object")
        } catch (failure: Exception) {
            if (failure is OracleSchemaException) throw failure
            throw OracleSchemaException("versioned oracle schema inventory is not canonical bounded JSON", failure)
        }

        val expectedFields = setOf(
            "historicalStartingCount",
            "kind",
            "schemaCount",
            "schemaInventoryVersion",
            "sharedCatalogCount",
            "schemas",
        )
        if (root.keys != expectedFields || root.stringValue("kind") != SCHEMA_INVENTORY_KIND ||
            root.integerValue("schemaInventoryVersion") != SCHEMA_INVENTORY_VERSION ||
            root.integerValue("historicalStartingCount") != HISTORICAL_SCHEMA_STARTING_COUNT
        ) {
            throw OracleSchemaException("versioned oracle schema inventory has an unsupported header")
        }

        val array = root["schemas"] as? JsonArray
            ?: throw OracleSchemaException("versioned oracle schema inventory has no schema list")
        if (array.isEmpty() || array.size > MAXIMUM_INVENTORY_ENTRIES ||
            root.integerValue("schemaCount") != array.size
        ) {
            throw OracleSchemaException("versioned oracle schema inventory has an invalid schema count")
        }

        val entries = LinkedHashMap<String, SchemaInventoryEntry>()
        var previousName: String? = null
        var registeredCount = 0
        for (element in array) {
            val value = element as? JsonObject
                ?: throw OracleSchemaException("versioned oracle schema inventory entry must be an object")
            val name = value.stringValue("name")
            val path = value.stringValue("path")
            val registration = value.stringValue("registration")
            val sha256 = value.stringValue("schemaSha256")
            val versions = value["formatVersions"] as? JsonArray
                ?: throw OracleSchemaException("versioned oracle schema entry has no format versions: $name")
            val scopeNote = (value["scopeNote"] as? JsonPrimitive)?.takeIf { it.isString }?.content
            val expectedEntryFields = if (registration == SHARED_KOTLIN_REGISTRATION) {
                setOf("formatVersions", "name", "path", "registration", "schemaSha256")
            } else {
                setOf("formatVersions", "name", "path", "registration", "schemaSha256", "scopeNote")
            }
            val formatVersions = versions.map { version ->
                val primitive = version as? JsonPrimitive
                    ?: throw OracleSchemaException("schema format version must be an integer: $name")
                if (primitive.isString) {
                    throw OracleSchemaException("schema format version must be an integer: $name")
                }
                primitive.content.toIntOrNull()
                    ?: throw OracleSchemaException("schema format version must be an integer: $name")
            }
            if (value.keys != expectedEntryFields || !name.matches(SCHEMA_NAME) ||
                path != "oracle/$name.schema.json" || registration !in INVENTORY_REGISTRATIONS ||
                !sha256.matches(SHA256) || formatVersions.isEmpty() ||
                formatVersions.any { it <= 0 } || formatVersions != formatVersions.distinct().sorted() ||
                (registration == SHARED_KOTLIN_REGISTRATION && scopeNote != null) ||
                (registration != SHARED_KOTLIN_REGISTRATION && scopeNote.isNullOrBlank()) ||
                previousName?.let { it >= name } == true
            ) {
                throw OracleSchemaException("versioned oracle schema inventory entry is invalid: $name")
            }
            if (registration == SHARED_KOTLIN_REGISTRATION) registeredCount++
            if (entries.put(name, SchemaInventoryEntry(path, registration, sha256)) != null) {
                throw OracleSchemaException("versioned oracle schema inventory repeats a schema: $name")
            }
            previousName = name
        }
        if (registeredCount != root.integerValue("sharedCatalogCount") ||
            entries.filterValues { it.registration == SHARED_KOTLIN_REGISTRATION }.keys != SUPPORTED_NAMES
        ) {
            throw OracleSchemaException("versioned oracle schema inventory does not match the shared Kotlin catalog")
        }
        return Collections.unmodifiableMap(entries)
    }

    private fun JsonObject.stringValue(name: String): String =
        (get(name) as? JsonPrimitive)?.takeIf { it.isString }?.content
            ?: throw OracleSchemaException("versioned oracle schema inventory field is not a string: $name")

    private fun JsonObject.integerValue(name: String): Int {
        val value = get(name) as? JsonPrimitive
            ?: throw OracleSchemaException("versioned oracle schema inventory field is not an integer: $name")
        if (value.isString) throw OracleSchemaException("versioned oracle schema inventory field is not an integer: $name")
        return value.content.toIntOrNull()
            ?: throw OracleSchemaException("versioned oracle schema inventory field is not an integer: $name")
    }

    private fun boundedError(error: ValidationError): String =
        error.toString().replace('\n', ' ').replace('\r', ' ').take(MAXIMUM_SINGLE_ERROR_CHARACTERS)

    private data class LoadedSchema(
        val identity: OracleSchemaIdentity,
        val schema: JsonSchema,
        private val storedBytes: ByteArray,
    ) {
        val bytes: ByteArray
            get() = storedBytes.copyOf()
    }

    private data class SchemaInventoryEntry(
        val path: String,
        val registration: String,
        val sha256: String,
    )

    private class TooManySchemaErrors : RuntimeException()

    private const val MAXIMUM_SCHEMA_BYTES = 1024 * 1024
    private const val MAXIMUM_SCHEMA_DEPTH = 96
    private const val MAXIMUM_SCHEMA_NODES = 200_000
    private const val MAXIMUM_SCHEMA_STRING_BYTES = 256 * 1024
    private const val MAXIMUM_SCHEMA_TOTAL_STRING_BYTES = 768 * 1024
    private const val MAXIMUM_REPORTED_ERRORS = 64
    private const val MAXIMUM_SINGLE_ERROR_CHARACTERS = 512
    private const val MAXIMUM_ERROR_DETAIL_CHARACTERS = 8 * 1024
    private const val MAXIMUM_INVENTORY_ENTRIES = 1_024
    private const val SCHEMA_INVENTORY_RESOURCE = "oracle/kotlin-schema-inventory-v1.json"
    private const val SCHEMA_INVENTORY_KIND = "kotlin-oracle-schema-inventory"
    private const val SCHEMA_INVENTORY_VERSION = 1
    private const val HISTORICAL_SCHEMA_STARTING_COUNT = 43
    private const val SHARED_KOTLIN_REGISTRATION = "shared-kotlin"
    private val INVENTORY_REGISTRATIONS = setOf(
        SHARED_KOTLIN_REGISTRATION,
        "retained-outside-shared-catalog",
        "separate-non-authoritative-validator",
    )
    private val SHA256 = Regex("[0-9a-f]{64}")
    private val SCHEMA_NAME = Regex("[a-z0-9]+(?:[/-][a-z0-9]+)*")
    private val SUPPORTED_NAMES: Set<String> = Collections.unmodifiableSet(sortedSetOf(
        "behavior-corpus",
        "behavior-corpus-report",
        "bounded-shard-index",
        "build-record",
        "clang-diagnostic-matrix",
        "confidence-calibration-artifact",
        "full-tree-call-baseline",
        "full-tree-call-observations",
        "full-tree-call-observations-v2",
        "full-tree-call-truth",
        "full-tree-call-truth-v2",
        "full-tree-call-truth-index",
        "full-tree-clang-compdb-reconciliation",
        "full-tree-clang-capture-input",
        "full-tree-data-baseline",
        "full-tree-data-observations",
        "full-tree-data-reconciliation",
        "full-tree-data-truth",
        "full-tree-data-truth-index",
        "full-tree-determinism-report",
        "full-tree-elf-data",
        "full-tree-elf-functions",
        "full-tree-execution-evidence",
        "full-tree-function-baseline",
        "full-tree-function-exclusions",
        "full-tree-function-observations",
        "full-tree-function-observations-v2",
        "full-tree-function-truth",
        "full-tree-function-truth-v3",
        "full-tree-function-truth-index",
        "full-tree-function-truth-index-v3",
        "full-tree-generated-file-inventory",
        "full-tree-generated-file-provenance",
        "full-tree-generic-template-frontend-v1",
        "full-tree-header-plan-readiness",
        "full-tree-inventory",
        "full-tree-implementation-ownership",
        "full-tree-materialization-determinism",
        "full-tree-ninja-compdb-prestart",
        "full-tree-ninja-compdb-execution-receipt",
        "full-tree-planning-inventory",
        "full-tree-release-assets",
        "full-tree-release-evidence",
        "full-tree-scope",
        "full-tree-source-header-dependencies",
        "full-tree-source-inventory",
        "function-recovery-oracle",
        "function-recovery-score",
        "gcc/build-record",
        "gcc/compiler-engines",
        "gcc/compiler-engine-plan-evidence",
        "gcc/oracle-manifest",
        "gcc/source-lock",
        "gcc/toolchain-reproduction",
        "llvm/source-lock",
        "llvm-behavior-candidate-acp-lineage-index-v2",
        "llvm-behavior-candidate-execution-admission",
        "llvm-behavior-candidate-observations",
        "llvm-behavior-case-ownership",
        "llvm-behavior-comparison-assessment",
        "llvm-behavior-hosted-clean-build-v2",
        "llvm-behavior-reference-input-plan-v2",
        "llvm-behavior-runtime-preflight",
        "oracle-manifest",
        "recovered-structure",
        "release-artifacts",
        "structural-identity-map",
        "structural-identity-replay-receipt",
        "structural-model-replay-receipt",
        "structural-oracle",
        "structural-score",
        "target-abi",
        "toolchain-reproduction",
    ))
    private val SCHEMA_INVENTORY: Map<String, SchemaInventoryEntry> by lazy(::loadSchemaInventory)
    private val CACHE = ConcurrentHashMap<String, LoadedSchema>()
}
