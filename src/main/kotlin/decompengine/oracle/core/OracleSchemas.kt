package decompengine.oracle.core

import io.github.optimumcode.json.schema.JsonSchema
import io.github.optimumcode.json.schema.ValidationError
import java.security.MessageDigest
import java.util.Collections
import java.util.concurrent.ConcurrentHashMap
import kotlinx.serialization.json.JsonElement

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
    fun configurationSha256(name: String, policy: JsonElement): String {
        val loaded = loaded(name)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(OracleJson.canonicalBytes(policy))
        digest.update(loaded.bytes)
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

    private class TooManySchemaErrors : RuntimeException()

    private const val MAXIMUM_SCHEMA_BYTES = 1024 * 1024
    private const val MAXIMUM_SCHEMA_DEPTH = 96
    private const val MAXIMUM_SCHEMA_NODES = 200_000
    private const val MAXIMUM_SCHEMA_STRING_BYTES = 256 * 1024
    private const val MAXIMUM_SCHEMA_TOTAL_STRING_BYTES = 768 * 1024
    private const val MAXIMUM_REPORTED_ERRORS = 64
    private const val MAXIMUM_SINGLE_ERROR_CHARACTERS = 512
    private const val MAXIMUM_ERROR_DETAIL_CHARACTERS = 8 * 1024
    private val SCHEMA_NAME = Regex("[a-z0-9]+(?:[/-][a-z0-9]+)*")
    private val SUPPORTED_NAMES: Set<String> = Collections.unmodifiableSet(sortedSetOf(
        "behavior-corpus",
        "behavior-corpus-report",
        "bounded-shard-index",
        "build-record",
        "clang-diagnostic-matrix",
        "full-tree-call-baseline",
        "full-tree-call-observations",
        "full-tree-call-truth",
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
        "full-tree-function-truth",
        "full-tree-function-truth-index",
        "full-tree-generated-file-inventory",
        "full-tree-generated-file-provenance",
        "full-tree-header-plan-readiness",
        "full-tree-inventory",
        "full-tree-implementation-ownership",
        "full-tree-materialization-determinism",
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
    private val CACHE = ConcurrentHashMap<String, LoadedSchema>()
}
