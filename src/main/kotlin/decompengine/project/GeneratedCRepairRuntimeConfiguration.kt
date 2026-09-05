package decompengine.project

import decompengine.acp.AcpHarnessProvisioning
import decompengine.acp.AcpLinuxSandboxConfiguration
import decompengine.acp.AcpSandboxReadOnlyMount
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.readStableRegularFile
import decompengine.validation.SandboxUnavailableException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.intOrNull

/**
 * Operator-provisioned data for the single registered generated-C validation implementation.
 * It is deliberately independent of CI fixture discovery and contains no implementation class,
 * launch command, environment override, network permission, or assurance switch.
 */
internal class GeneratedCRepairRuntimeConfiguration private constructor(
    val configurationSha256: String,
    val configurationRecord: JsonObject,
    val sandbox: AcpLinuxSandboxConfiguration,
    tools: Map<String, AcpSandboxReadOnlyMount>,
    buildRuntime: List<AcpSandboxReadOnlyMount>,
    programRuntime: List<AcpSandboxReadOnlyMount>,
    val sourceTmpfs: Path,
    val outputTmpfs: Path,
) {
    val tools: Map<String, AcpSandboxReadOnlyMount> = Collections.unmodifiableMap(LinkedHashMap(tools))
    val buildRuntime: List<AcpSandboxReadOnlyMount> = Collections.unmodifiableList(ArrayList(buildRuntime))
    val programRuntime: List<AcpSandboxReadOnlyMount> = Collections.unmodifiableList(ArrayList(programRuntime))

    companion object {
        const val ENVIRONMENT = "GENERATED_C_REPAIR_CONFIG_FILE"
        val TOOL_NAMES = mapOf("make" to "make", "compiler" to "cc", "linker" to "ld", "assembler" to "as",
            "shell" to "sh", "find" to "find", "mkdir" to "mkdir")
        val TOOL_ROLES: Set<String> = TOOL_NAMES.keys
        val TOOL_DIRECTORY: Path = Path.of("/decomp-generated-c-tools")

        fun loadFromEnvironment(): GeneratedCRepairRuntimeConfiguration {
            val configured = System.getenv(ENVIRONMENT)
                ?: throw SandboxUnavailableException("$ENVIRONMENT must name the provisioned generated-C validation runtime")
            return load(Path.of(configured))
        }

        internal fun load(path: Path): GeneratedCRepairRuntimeConfiguration {
            requireCanonical(path, "generated-C runtime configuration")
            requireRootOwned(path, directory = false)
            val bytes = readStableRegularFile(requireNotNull(path.parent), path.fileName.toString(), MAXIMUM_CONFIG_BYTES.toLong()).bytes
            val document = OracleJson.parse(bytes, CONFIG_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("generated-C runtime configuration must be an object")
            require(document.keys == ROOT_FIELDS) { "generated-C runtime configuration fields differ from schema v1" }
            require((document["schemaVersion"] as? JsonPrimitive)?.intOrNull == 1) {
                "unsupported generated-C runtime configuration schema"
            }
            require(document.text("profileId") == GeneratedCRepairIndexProfile.profileId()) {
                "generated-C runtime configuration identifies a different profile"
            }
            val sandboxPath = document.path("sandboxConfigurationFile")
            requireRootOwned(sandboxPath, directory = false)
            val provisionedSandbox = AcpHarnessProvisioning.parseSandboxConfiguration(readStableRegularFile(
                requireNotNull(sandboxPath.parent), sandboxPath.fileName.toString(), MAXIMUM_CONFIG_BYTES.toLong(),
            ).bytes)
            val base = provisionedSandbox.configuration
            val toolRecords = document["tools"] as? JsonObject
                ?: throw IllegalArgumentException("generated-C tools must be an object")
            require(toolRecords.keys == TOOL_ROLES) { "generated-C runtime must declare the exact registered tool roles" }
            val tools = TOOL_ROLES.sorted().associateWith { role ->
                val record = toolRecords[role] as? JsonObject
                    ?: throw IllegalArgumentException("generated-C tool record is not an object")
                mount(record).also { declared ->
                    requireRootOwned(declared.source, directory = false)
                    require(declared.destination == TOOL_DIRECTORY.resolve(TOOL_NAMES.getValue(role))) {
                        "generated-C tool destination differs from the registered role"
                    }
                }
            }
            require(tools.values.map { it.destination }.distinct().size == TOOL_ROLES.size) {
                "generated-C tool roles require distinct executable destinations"
            }
            fun runtimeMounts(field: String): List<AcpSandboxReadOnlyMount> {
                val runtimeRecords = document[field] as? JsonArray
                    ?: throw IllegalArgumentException("generated-C $field must be an array")
                require(runtimeRecords.size <= MAXIMUM_RUNTIME_MOUNTS) { "generated-C runtime mount count exceeds its bound" }
                return runtimeRecords.map { value ->
                    mount(value as? JsonObject ?: throw IllegalArgumentException("generated-C runtime mount is not an object"))
                        .also { declared ->
                            requireRootOwned(declared.source, directory = Files.isDirectory(declared.source, LinkOption.NOFOLLOW_LINKS))
                            require(declared.source !in BROAD_RUNTIME_DIRECTORIES && declared.destination !in BROAD_RUNTIME_DIRECTORIES) {
                                "generated-C validation cannot expose a broad host runtime or executable directory"
                            }
                        }
                }
            }
            val buildRuntime = runtimeMounts("buildRuntimeMounts")
            val programRuntime = runtimeMounts("programRuntimeMounts")
            val runtime = (buildRuntime + programRuntime).distinctBy { it.destination }
            (buildRuntime + programRuntime).groupBy { it.destination }.values.forEach { records ->
                require(records.all { it.source == records.first().source &&
                    it.expectedManifestSha256 == records.first().expectedManifestSha256 }) {
                    "generated-C build and program runtime authorities conflict"
                }
            }
            val all = tools.values + runtime
            require(all.map { it.destination }.distinct().size == all.size) { "generated-C runtime mount destinations collide" }
            val source = document.path("sourceTmpfs")
            val output = document.path("outputTmpfs")
            require(source != output && !source.startsWith(output) && !output.startsWith(source)) {
                "generated-C source and output quota mounts must be independent"
            }
            require(all.none { it.source.startsWith(source) || it.source.startsWith(output) }) {
                "generated-C runtime inputs overlap candidate staging"
            }
            // The shared boundary's final launch checks own loader admission. Agent-specific and
            // Ninja closures are deliberately not inherited as compiler/program authority.
            val sandbox = AcpLinuxSandboxConfiguration(
                bubblewrapExecutable = base.bubblewrapExecutable,
                resourceLimiterExecutable = base.resourceLimiterExecutable,
                scopeSupervisorExecutable = base.scopeSupervisorExecutable,
                scopeInspectorExecutable = base.scopeInspectorExecutable,
                environmentFdOpenerExecutable = base.environmentFdOpenerExecutable,
                sandboxGateHelperExecutable = base.sandboxGateHelperExecutable,
                launcherRuntimeMounts = base.launcherRuntimeMounts,
                agentRuntimeMounts = emptyList(),
                systemdUserRuntimeDirectory = base.systemdUserRuntimeDirectory,
                agentResourceLimits = base.agentResourceLimits,
                runtimeClosureLimits = base.runtimeClosureLimits,
                expectedBubblewrapSha256 = base.expectedBubblewrapSha256,
                expectedResourceLimiterSha256 = base.expectedResourceLimiterSha256,
                expectedScopeSupervisorSha256 = base.expectedScopeSupervisorSha256,
                expectedScopeInspectorSha256 = base.expectedScopeInspectorSha256,
                expectedEnvironmentFdOpenerSha256 = base.expectedEnvironmentFdOpenerSha256,
                expectedSandboxGateHelperSha256 = base.expectedSandboxGateHelperSha256,
                expectedSandboxGateHelperManifestSha256 = base.expectedSandboxGateHelperManifestSha256,
                validationRuntimeMounts = all,
            )
            val binding = JsonObject(mapOf(
                "runtime" to document,
                "sandboxConfigurationSha256" to JsonPrimitive(provisionedSandbox.canonicalSha256),
            ))
            return GeneratedCRepairRuntimeConfiguration(
                sha256(OracleJson.canonicalBytes(binding, CONFIG_LIMITS)), binding, sandbox, tools, buildRuntime, programRuntime, source, output,
            )
        }

        private fun mount(record: JsonObject): AcpSandboxReadOnlyMount {
            require(record.keys == setOf("source", "destination", "sha256")) { "generated-C mount record fields differ" }
            val digest = record.text("sha256")
            require(digest.matches(Regex("[0-9a-f]{64}"))) { "generated-C runtime mount digest is malformed" }
            return AcpSandboxReadOnlyMount(record.path("source"), record.path("destination"), digest)
        }

        private fun JsonObject.text(key: String): String = (this[key] as? JsonPrimitive)?.let { value ->
            require(value.isString) { "generated-C configuration $key must be a string" }
            value.content
        } ?: throw IllegalArgumentException("generated-C configuration is missing $key")

        private fun JsonObject.path(key: String): Path = Path.of(text(key)).also { requireCanonical(it, key) }

        private fun requireCanonical(path: Path, label: String) {
            require(path.isAbsolute && path == path.normalize() && path.toString().isNotBlank()) {
                "$label must be an absolute normalized path"
            }
        }

        private fun requireRootOwned(path: Path, directory: Boolean) {
            requireCanonical(path, "generated-C runtime input")
            require(path.toRealPath() == path) { "generated-C runtime inputs must be canonical without symbolic links" }
            var current: Path? = path
            while (current != null) {
                val checked = requireNotNull(current)
                requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(checked)).use { descriptor ->
                    val identity = descriptor.identity
                    require(identity.uid == 0 && !identity.isSymbolicLink && identity.mode.permissions and 0x12 == 0) {
                        "generated-C runtime input and ancestors must be root-owned and not group/world writable"
                    }
                    require(if (checked == path && !directory) identity.isRegularFile else identity.isDirectory) {
                        "generated-C runtime input has an unexpected file type"
                    }
                }
                current = checked.parent
            }
        }

        private const val MAXIMUM_CONFIG_BYTES = 256 * 1024
        private const val MAXIMUM_RUNTIME_MOUNTS = 48
        private val CONFIG_LIMITS = StrictJsonLimits(
            maximumInputBytes = MAXIMUM_CONFIG_BYTES,
            maximumCanonicalBytes = MAXIMUM_CONFIG_BYTES * 2,
            maximumDepth = 12,
            maximumNodes = 4096,
            maximumStringBytes = 4096,
            maximumTotalStringBytes = MAXIMUM_CONFIG_BYTES,
        )
        private val ROOT_FIELDS = setOf(
            "schemaVersion", "profileId", "sandboxConfigurationFile", "tools", "buildRuntimeMounts", "programRuntimeMounts",
            "sourceTmpfs", "outputTmpfs",
        )
        private val BROAD_RUNTIME_DIRECTORIES = setOf(
            "/", "/usr", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64", "/usr/lib",
        ).mapTo(hashSetOf(), Path::of)
    }
}
