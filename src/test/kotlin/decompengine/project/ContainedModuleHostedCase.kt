package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Passive test artifacts only. A recorded case never supplies execution or acceptance authority. */
internal object ContainedModuleHostedCase {
    const val DIRECTORY_PROPERTY = "decompengine.moduleQualification.caseDirectory"

    fun run(caseId: String, testClass: String, testMethod: String, profileId: String?, block: (Case) -> Unit) {
        val case = Case(caseId, testClass, testMethod, profileId)
        try {
            block(case)
            if (Thread.currentThread().isInterrupted) throw InterruptedException("hosted qualification case interrupted")
            case.complete()
        } catch (failure: Throwable) {
            val interrupted = Thread.interrupted()
            try {
                case.failed(failure)
            } catch (reportFailure: Throwable) {
                if (reportFailure !== failure) failure.addSuppressed(reportFailure)
            } finally {
                if (interrupted || failure is InterruptedException) Thread.currentThread().interrupt()
            }
            throw failure
        }
    }

    class Case internal constructor(
        private val caseId: String,
        private val testClass: String,
        private val testMethod: String,
        private val profileId: String?,
    ) {
        private val directory: Path
        private val artifacts = linkedMapOf<String, JsonObject>()
        private val stages = linkedSetOf("initializing")
        private var currentStage = "initializing"
        private var totalBytes = 0L
        private var status = "running"
        private var failureRecord: JsonObject? = null

        init {
            require(EXPECTED_PROFILES.containsKey(caseId) && EXPECTED_PROFILES[caseId] == profileId) {
                "hosted qualification case and profile are not registered"
            }
            require(testClass.matches(Regex("decompengine(?:\\.[A-Za-z_][A-Za-z0-9_]*)+")) &&
                testMethod.length in 1..2048 && testMethod.none { it.code < 32 || it.code == 127 }) {
                "hosted qualification test identity is invalid"
            }
            val checkout = Path.of("").toAbsolutePath().toRealPath()
            val configured = System.getProperty(DIRECTORY_PROPERTY)
            val required = System.getenv("GENERATED_C_MODULE_COMPILE_REQUIRE") == "true"
            require(!required || configured != null) { "required hosted qualification lacks its case directory" }
            val base = if (configured != null) Path.of(configured).toAbsolutePath().normalize() else {
                // Other optional live suites may use this recorder without the dedicated hosted gate.
                // A fresh standalone directory preserves their assumption behavior and earns no index credit.
                val standalone = checkout.resolve("build/reports/contained-module-compilation-live/standalone")
                requireUnaliasedAncestors(standalone)
                Files.createDirectories(standalone)
                Files.createTempDirectory(standalone, "case-")
            }
            require(base != checkout.resolve("build") && base.startsWith(checkout.resolve("build"))) {
                "hosted qualification case directory must belong to checkout build"
            }
            requireUnaliasedAncestors(base)
            if (required) {
                val index = base.resolve("expected-case-index.json")
                require(Files.isRegularFile(index, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(index) && index.toRealPath() == index) {
                    "required hosted qualification lacks its immutable expected case index"
                }
                val encoded = Files.newInputStream(index).use { it.readNBytes(2 * 1024 * 1024 + 1) }
                require(encoded.size <= 2 * 1024 * 1024)
                val record = OracleJson.parse(encoded, INDEX_LIMITS) as? JsonObject
                    ?: error("hosted qualification expected index must be an object")
                require(record.keys == setOf("schemaVersion", "provider", "run", "source", "cases") &&
                    record["schemaVersion"] == JsonPrimitive(1) && record["provider"] == JsonPrimitive("contained-module-hosted-case-index-v1"))
                val cases = record["cases"] as? JsonArray ?: error("hosted qualification expected cases are missing")
                require(cases.size == 13 && cases.count { it == JsonObject(mapOf("caseId" to JsonPrimitive(caseId),
                    "testClass" to JsonPrimitive(testClass), "testMethod" to JsonPrimitive(testMethod),
                    "profileId" to (profileId?.let(::JsonPrimitive) ?: JsonNull))) } == 1) {
                    "hosted qualification case differs from its expected test identity"
                }
            }
            Files.createDirectories(base)
            requireUnaliasedAncestors(base)
            directory = Files.createDirectory(base.resolve(caseId))
            publish()
        }

        @Synchronized
        fun stage(name: String) {
            require(status == "running") { "hosted qualification case is already terminal" }
            require(name.matches(Regex("[a-z][a-z0-9-]{0,63}")) && name !in stages && stages.size < MAXIMUM_STAGES) {
                "hosted qualification stage is invalid, duplicate, or exceeds its bound"
            }
            stages += name
            currentStage = name
            publish()
        }

        /** Checks budgets before filesystem writes and retains a defensive payload copy. */
        @Synchronized
        fun retain(relativeName: String, bytes: ByteArray): JsonObject {
            require(status == "running") { "hosted qualification case is already terminal" }
            require(bytes.size <= MAXIMUM_MEMBER_BYTES) { "hosted qualification artifact exceeds its member bound" }
            require(relativeName.toByteArray(Charsets.UTF_8).size in 1..MAXIMUM_PATH_BYTES)
            val segments = relativeName.split('/')
            require(segments.size in 1..MAXIMUM_PATH_SEGMENTS && segments.all {
                it !in setOf(".", "..") && it.matches(Regex("[A-Za-z0-9_.-]+"))
            } && relativeName != "case.json") { "hosted qualification artifact path is invalid" }
            require(relativeName !in artifacts && artifacts.size < MAXIMUM_MEMBERS) {
                "hosted qualification artifact is duplicate or exceeds the member count"
            }
            val nextTotal = Math.addExact(totalBytes, bytes.size.toLong())
            require(nextTotal <= MAXIMUM_CASE_BYTES) { "hosted qualification artifacts exceed their aggregate bound" }
            val copy = bytes.copyOf()
            val target = directory.resolve(relativeName).normalize()
            require(target != directory && target.startsWith(directory))
            requireUnaliasedAncestors(target.parent)
            Files.createDirectories(target.parent)
            requireUnaliasedAncestors(target.parent)
            Files.write(target, copy, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            val record = JsonObject(mapOf("path" to JsonPrimitive(relativeName), "bytes" to JsonPrimitive(copy.size),
                "sha256" to JsonPrimitive(sha256(copy))))
            artifacts[relativeName] = record
            totalBytes = nextTotal
            publish()
            return record
        }

        @Synchronized
        internal fun complete() {
            require(status == "running" && artifacts.isNotEmpty() && totalBytes > 0L && stages.size > 1) {
                "hosted qualification case did not retain a completed observation"
            }
            status = "passed"
            publish()
        }

        @Synchronized
        internal fun failed(failure: Throwable) {
            status = "failed"
            failureRecord = JsonObject(mapOf("type" to JsonPrimitive(failure.javaClass.name.take(512)),
                "message" to JsonPrimitive("hosted qualification failed; inspect retained bounded test evidence")))
            publish()
        }

        private fun publish() {
            requireUnaliasedAncestors(directory)
            val record = JsonObject(mapOf("schemaVersion" to JsonPrimitive(1),
                "provider" to JsonPrimitive("contained-module-hosted-case-v1"), "caseId" to JsonPrimitive(caseId),
                "testClass" to JsonPrimitive(testClass), "testMethod" to JsonPrimitive(testMethod),
                "profileId" to (profileId?.let(::JsonPrimitive) ?: JsonNull), "status" to JsonPrimitive(status),
                "stage" to JsonPrimitive(currentStage), "artifacts" to JsonArray(artifacts.values.toList()),
                "failure" to (failureRecord ?: JsonNull)))
            val bytes = OracleJson.canonicalBytes(record, JSON_LIMITS)
            val target = directory.resolve("case.json")
            require(!Files.exists(target, LinkOption.NOFOLLOW_LINKS) ||
                Files.isRegularFile(target, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(target)) {
                "hosted qualification case metadata changed type"
            }
            val temporary = Files.createTempFile(directory, "case-metadata-", ".tmp")
            try {
                Files.write(temporary, bytes, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.WRITE)
                Files.move(temporary, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            } finally {
                Files.deleteIfExists(temporary)
            }
        }
    }

    private fun requireUnaliasedAncestors(path: Path) {
        var cursor: Path? = path
        while (cursor != null) {
            val current = cursor
            if (Files.exists(current, LinkOption.NOFOLLOW_LINKS)) require(
                Files.isDirectory(current, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(current) && current.toRealPath() == current,
            ) { "hosted qualification artifact ancestor is not a canonical directory" }
            cursor = current.parent
        }
    }

    private val EXPECTED_PROFILES: Map<String, String?> = buildMap {
        for ((short, profile) in listOf("make" to "generated-c-make-v1", "ninja" to "generated-c-ninja-v1")) {
            for (case in listOf("exact-snapshot", "source-tree-rejection", "source-tree-cancellation", "output-refusal", "inherited-hard-refusal")) {
                put("module-$short-$case", profile)
            }
        }
        for (case in listOf("generic-default-512", "generic-visibility-v4", "generated-visibility-canaries")) put(case, null)
    }
    private const val MAXIMUM_MEMBER_BYTES = 4 * 1024 * 1024
    private const val MAXIMUM_CASE_BYTES = 64L * 1024 * 1024
    private const val MAXIMUM_MEMBERS = 2048
    private const val MAXIMUM_PATH_SEGMENTS = 16
    private const val MAXIMUM_PATH_BYTES = 512
    private const val MAXIMUM_STAGES = 32
    private val JSON_LIMITS = StrictJsonLimits(maximumCanonicalBytes = 4 * 1024 * 1024, maximumDepth = 8,
        maximumNodes = 32_768, maximumStringBytes = 4096, maximumTotalStringBytes = 4 * 1024 * 1024,
        maximumNumberCharacters = 32)
    private val INDEX_LIMITS = StrictJsonLimits(maximumInputBytes = 2 * 1024 * 1024, maximumCanonicalBytes = 4 * 1024 * 1024,
        maximumDepth = 10, maximumNodes = 32_768, maximumStringBytes = 4096, maximumTotalStringBytes = 2 * 1024 * 1024,
        maximumNumberCharacters = 32)
}
