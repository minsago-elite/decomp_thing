package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class LlvmBehaviorNativeSandboxPolicyV2Fixture private constructor(
    val container: Path,
) : AutoCloseable {
    val inputDirectory: Path = Files.createDirectory(container.resolve("inputs")).also(::makePrivateDirectory)
    val journalRoot: Path = Files.createDirectory(container.resolve("journal-root")).also(::makePrivateDirectory)
    val policy: Path = inputDirectory.resolve(POLICY_NAME)
    val helper: Path = inputDirectory.resolve(HELPER_NAME)
    val checksum: Path = inputDirectory.resolve(CHECKSUM_NAME)
    val source: Path = inputDirectory.resolve(SOURCE_NAME)
    val buildRecord: Path = inputDirectory.resolve(BUILD_RECORD_NAME)

    init {
        Files.copy(requiredArtifact(HELPER_PROPERTY, "production LLVM behavior helper"), helper,
            StandardCopyOption.COPY_ATTRIBUTES)
        Files.copy(requiredArtifact(CHECKSUM_PROPERTY, "production LLVM behavior helper checksum"), checksum,
            StandardCopyOption.COPY_ATTRIBUTES)
        Files.copy(repositorySource(), source, StandardCopyOption.COPY_ATTRIBUTES)
        Files.setPosixFilePermissions(helper, PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-------"))
        Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rw-------"))
        writeBuildRecord()
        writePolicy(validPolicy())
    }

    fun verify(): LlvmBehaviorNativeSandboxPolicyV2Validation =
        LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(policy, helper, checksum, source, buildRecord)

    fun writePolicy(document: JsonObject) {
        Files.write(policy, OracleJson.canonicalBytes(document, JSON_LIMITS))
        Files.setPosixFilePermissions(policy, PosixFilePermissions.fromString("rw-------"))
    }

    fun validPolicy(): JsonObject {
        val static = STATIC_SCHEMA_PROPERTIES
        return JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(2),
                "kind" to JsonPrimitive("llvm-behavior-native-sandbox-helper-policy-draft"),
                "authority" to JsonPrimitive(
                    "non-authoritative-native-sandbox-helper-policy-v2-draft-validation",
                ),
                "acpBoundary" to static.getValue("acpBoundary"),
                "backend" to JsonPrimitive("oci-container-v2"),
                "helper" to JsonObject(
                    mapOf(
                        "fileName" to JsonPrimitive(HELPER_NAME),
                        "checksumFileName" to JsonPrimitive(CHECKSUM_NAME),
                        "bytes" to JsonPrimitive(Files.size(helper)),
                        "sha256" to JsonPrimitive(sha256(helper)),
                        "checksumSha256" to JsonPrimitive(sha256(checksum)),
                        "protocol" to JsonPrimitive("decomp-llvm-behavior-helper-v2"),
                        "containerPath" to JsonPrimitive("/decomp-llvm-behavior-helper"),
                        "preExecFrame" to JsonPrimitive("behavior-preexec-v2:"),
                        "source" to fileRecord(SOURCE_NAME, source),
                        "buildRecord" to fileRecord(BUILD_RECORD_NAME, buildRecord),
                    ),
                ),
                "environment" to static.getValue("environment"),
                "container" to static.getValue("container"),
                "roles" to static.getValue("roles"),
                "mountProfiles" to static.getValue("mountProfiles"),
                "cgroup" to static.getValue("cgroup"),
                "rlimits" to static.getValue("rlimits"),
                "workspace" to static.getValue("workspace"),
                "captures" to static.getValue("captures"),
                "unboundRuntimeInputs" to static.getValue("unboundRuntimeInputs"),
                "claims" to static.getValue("claims"),
            ),
        )
    }

    private fun writeBuildRecord() {
        val record = JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(2),
                "kind" to JsonPrimitive("llvm-behavior-native-helper-build-record"),
                "compiler" to JsonObject(
                    mapOf(
                        "executable" to JsonPrimitive("/usr/bin/cc"),
                        "version" to JsonPrimitive("cc journal fixture 1.0"),
                    ),
                ),
                "argumentTemplate" to JsonArray(
                    listOf(
                        "-std=c11",
                        "-O2",
                        "-static",
                        "-Wall",
                        "-Wextra",
                        "-Werror",
                        "-Wformat=2",
                        "-Wl,--build-id=none",
                        "\${SOURCE}",
                        "-o",
                        "\${OUTPUT}",
                    ).map(::JsonPrimitive),
                ),
                "source" to fileRecord(SOURCE_NAME, source),
                "output" to fileRecord(HELPER_NAME, helper),
            ),
        )
        Files.write(buildRecord, OracleJson.canonicalBytes(record, JSON_LIMITS))
        Files.setPosixFilePermissions(buildRecord, PosixFilePermissions.fromString("rw-------"))
    }

    override fun close() {
        if (!Files.exists(container, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(container).use { entries ->
            entries.sorted(Comparator.reverseOrder()).toList()
        }.forEach(Files::deleteIfExists)
    }

    internal companion object {
        const val POLICY_NAME = "llvm-behavior-native-sandbox-policy-v2.json"
        const val HELPER_NAME = "decomp-llvm-behavior-helper"
        const val CHECKSUM_NAME = "decomp-llvm-behavior-helper.sha256"
        const val SOURCE_NAME = "decomp_llvm_behavior_helper.c"
        const val BUILD_RECORD_NAME = "decomp-llvm-behavior-helper-build-v2.json"
        const val HELPER_PROPERTY = "decompengine.oracle.behavior.nativeHelperExecutable"
        const val CHECKSUM_PROPERTY = "decompengine.oracle.behavior.nativeHelperChecksum"
        val HOST_ARCHITECTURE: String = System.getProperty("os.arch", "")

        fun create(): LlvmBehaviorNativeSandboxPolicyV2Fixture {
            val container = createTempDirectory("native-policy-v2-journal-").toAbsolutePath().normalize()
            makePrivateDirectory(container)
            return LlvmBehaviorNativeSandboxPolicyV2Fixture(container)
        }

        fun sha256(path: Path): String = OracleArtifacts.sha256(Files.readAllBytes(path))

        private val JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = 256 * 1024,
            maximumCanonicalBytes = 256 * 1024,
            maximumDepth = 96,
            maximumNodes = 50_000,
            maximumStringBytes = 64 * 1024,
            maximumTotalStringBytes = 192 * 1024,
        )

        private val STATIC_SCHEMA_PROPERTIES: Map<String, JsonElement> by lazy {
            val bytes = requireNotNull(
                LlvmBehaviorNativeSandboxPolicyV2Fixture::class.java.classLoader.getResourceAsStream(
                    "oracle/llvm-behavior-native-sandbox-policy-v2.schema.json",
                ),
            ).use { it.readNBytes(256 * 1024 + 1) }
            val schema = OracleJson.parse(bytes, JSON_LIMITS) as JsonObject
            val properties = schema.getValue("properties") as JsonObject
            listOf(
                "acpBoundary",
                "environment",
                "container",
                "roles",
                "mountProfiles",
                "cgroup",
                "rlimits",
                "workspace",
                "captures",
                "unboundRuntimeInputs",
                "claims",
            ).associateWith { name ->
                (properties.getValue(name) as JsonObject).getValue("const")
            }
        }

        private fun fileRecord(fileName: String, path: Path): JsonObject = JsonObject(
            mapOf(
                "fileName" to JsonPrimitive(fileName),
                "bytes" to JsonPrimitive(Files.size(path)),
                "sha256" to JsonPrimitive(sha256(path)),
            ),
        )

        private fun requiredArtifact(property: String, label: String): Path {
            val configured = requireNotNull(System.getProperty(property)) { "$label was not supplied by Gradle" }
            val path = Path.of(configured).toAbsolutePath().normalize()
            require(path == Path.of(configured)) { "$label path must be absolute and normalized" }
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "$label is unavailable: $path" }
            return path
        }

        private fun repositorySource(): Path {
            val path = Path.of("src/main/c/decomp_llvm_behavior_helper.c").toAbsolutePath().normalize()
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "native helper source is unavailable" }
            return path
        }

        private fun makePrivateDirectory(path: Path) {
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        }
    }
}
