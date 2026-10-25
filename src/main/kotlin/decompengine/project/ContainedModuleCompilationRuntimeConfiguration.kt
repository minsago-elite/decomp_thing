package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import decompengine.oracle.fulltree.FullTreeFunctionObservationClassPathEntry
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeMount
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import decompengine.repair.readStableRegularFile
import decompengine.validation.SandboxUnavailableException
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.DigestOutputStream
import java.security.MessageDigest
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Deployment data for the registered contained module compiler. Loading this declaration does
 * not acquire a scratch lease or prove a compilation. The command launcher authenticates the
 * keeper and runtime again, and the disk authority alone admits the dedicated ext4 filesystem.
 * There are no configurable commands, environment entries, provider classes, or bypass switches.
 */
internal class ContainedModuleCompilationRuntimeConfiguration private constructor(
    private val declaration: Declaration,
) {
    val configurationSha256: String get() = declaration.configurationSha256
    val configurationRecord: JsonObject get() = declaration.configurationRecord
    val profileId: String get() = declaration.profileId
    val isolation: FullTreeFunctionObservationIsolationConfiguration get() = declaration.isolation
    val compilerExecutable: Path get() = declaration.compilerExecutable
    val compilerSha256: String get() = declaration.compilerSha256
    val compilerRuntimeMounts: List<FullTreeFunctionObservationRuntimeMount> get() = declaration.compilerRuntimeMounts
    val scratchMount: Path get() = declaration.scratchMount
    val scratchPolicy: FullTreeDiskScratchPolicy get() = declaration.scratchPolicy
    val managerControlGroup: String get() = declaration.managerControlGroup

    /** Required immediately before every launch; the directory manifest is not a content hash. */
    fun verifyCompilerInput(): KotlinSystemdCgroupCommandInput = verifyPinnedFile(
        compilerExecutable, compilerSha256, executable = true,
    )

    /** Parsed data is deliberately not an executable runtime configuration. */
    internal class Declaration internal constructor(
        val configurationRecord: JsonObject,
        val profileId: String,
        val isolation: FullTreeFunctionObservationIsolationConfiguration,
        val compilerExecutable: Path,
        val compilerSha256: String,
        compilerRuntimeMounts: List<FullTreeFunctionObservationRuntimeMount>,
        val scratchMount: Path,
        val scratchPolicy: FullTreeDiskScratchPolicy,
        val managerControlGroup: String,
    ) {
        val compilerRuntimeMounts: List<FullTreeFunctionObservationRuntimeMount> = java.util.List.copyOf(compilerRuntimeMounts)
        val configurationSha256: String = sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("contained-generated-c-module-runtime-v1"),
            "configuration" to configurationRecord,
            "isolationConfigurationSha256" to JsonPrimitive(isolation.canonicalSha256),
        )), CONFIG_LIMITS))
    }

    companion object {
        const val ENVIRONMENT = "GENERATED_C_MODULE_COMPILE_CONFIG_FILE"
        const val DIRECTORY_ENVIRONMENT = "GENERATED_C_MODULE_COMPILE_CONFIG_DIRECTORY"
        const val PROFILE_ENVIRONMENT = "GENERATED_C_MODULE_COMPILE_PROFILE"

        fun loadFromEnvironment(): ContainedModuleCompilationRuntimeConfiguration {
            val environment = System.getenv()
            val profile = if (environment[DIRECTORY_ENVIRONMENT] != null)
                environment[PROFILE_ENVIRONMENT] ?: GeneratedCMakeReconstructionProfile.PROFILE_ID else null
            return load(configuredPath(environment, profile)).also {
                require(profile == null || it.profileId == profile) { "contained compiler runtime belongs to a different profile" }
            }
        }

        fun loadFromEnvironment(profileId: String): ContainedModuleCompilationRuntimeConfiguration =
            load(configuredPath(System.getenv(), profileId)).also {
                require(it.profileId == profileId) { "contained compiler runtime belongs to a different profile" }
            }

        /** Pure path selection only; loading still requires root-owned configuration and pins. */
        internal fun configuredPath(environment: Map<String, String>, profileId: String? = null): Path {
            profileId?.let(::requireRegisteredProfile)
            val file = environment[ENVIRONMENT]
            val directory = environment[DIRECTORY_ENVIRONMENT]
            require(file == null || directory == null) { "module compiler file and directory configuration are mutually exclusive" }
            if (file != null) return canonicalPath(file, ENVIRONMENT)
            if (directory != null) {
                val selected = profileId ?: environment[PROFILE_ENVIRONMENT] ?: GeneratedCMakeReconstructionProfile.PROFILE_ID
                requireRegisteredProfile(selected)
                return canonicalPath(directory, DIRECTORY_ENVIRONMENT).resolve("$selected.json")
            }
            throw SandboxUnavailableException("$ENVIRONMENT or $DIRECTORY_ENVIRONMENT must select the provisioned contained module compiler runtime")
        }

        private fun requireRegisteredProfile(profileId: String) {
            require(profileId in setOf(GeneratedCMakeReconstructionProfile.PROFILE_ID, GeneratedCNinjaReconstructionProfile.PROFILE_ID)) {
                "contained module compiler requires a registered generated-C profile"
            }
        }

        internal fun load(path: Path): ContainedModuleCompilationRuntimeConfiguration {
            requireRootOwned(path, directory = false)
            val bytes = readStableRegularFile(requireNotNull(path.parent), path.fileName.toString(), MAXIMUM_CONFIG_BYTES.toLong()).bytes
            val declaration = parse(bytes)
            val isolation = declaration.isolation
            (listOf(isolation.javaRuntime) + isolation.systemLibraryMounts + declaration.compilerRuntimeMounts).forEach { mount ->
                require(calculateFullTreeObservationRuntimeManifestSha256(mount.source) == mount.expectedManifestSha256) {
                    "contained module compiler runtime tree differs from its declared manifest"
                }
            }
            listOf(
                isolation.javaExecutable to isolation.expectedJavaSha256,
                isolation.bubblewrapExecutable to isolation.expectedBubblewrapSha256,
                isolation.resourceLimiterExecutable to isolation.expectedResourceLimiterSha256,
                isolation.scopeSupervisorExecutable to isolation.expectedScopeSupervisorSha256,
                isolation.scopeInspectorExecutable to isolation.expectedScopeInspectorSha256,
                isolation.systemdBusControllerExecutable to isolation.expectedSystemdBusControllerSha256,
            ).forEach { (executable, digest) -> verifyPinnedFile(executable, digest, executable = true) }
            isolation.workerClassPath.forEach { verifyPinnedFile(it.path, it.expectedSha256, executable = false) }
            // The scratch root belongs to the service UID, unlike its root-owned ancestors.
            // Its live owner, mount flags, ext4 capacity and exclusive use are checked at acquire.
            return ContainedModuleCompilationRuntimeConfiguration(declaration).also { it.verifyCompilerInput() }
        }

        internal fun parse(bytes: ByteArray): Declaration {
            val document = OracleJson.parse(bytes, CONFIG_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("contained module compiler configuration must be an object")
            document.exact(ROOT_FIELDS, "runtime")
            require(document.integer("schemaVersion") == 1L) { "unsupported contained module compiler runtime schema" }
            val profileId = document.text("profileId")
            requireRegisteredProfile(profileId)
            val isolation = parseIsolation(document.objectField("isolation"))
            val compiler = document.objectField("compiler").also { it.exact(setOf("path", "sha256"), "compiler") }
            val compilerPath = compiler.path("path")
            val compilerSha256 = compiler.digest("sha256")
            val mounts = document.mounts("compilerRuntimeMounts")
            val scratch = document.path("scratchMount")
            val managerControlGroup = document.path("managerControlGroup").toString()
            val scratchRecord = document.objectField("scratchPolicy").also { it.exact(SCRATCH_FIELDS, "scratch policy") }
            val scratchPolicy = FullTreeDiskScratchPolicy(
                scratchRecord.integer("requiredAvailableBytes"), scratchRecord.integer("maximumFilesystemBytes"),
                scratchRecord.integer("requiredAvailableInodes"), scratchRecord.integer("maximumFilesystemInodes"),
            )
            require(scratchPolicy.maximumFilesystemBytes <= MAXIMUM_SCRATCH_BYTES &&
                scratchPolicy.maximumFilesystemInodes <= MAXIMUM_SCRATCH_INODES) {
                "contained module compiler scratch policy exceeds its finite bound"
            }
            val baseMounts = listOf(isolation.javaRuntime) + isolation.systemLibraryMounts
            val reserved = listOf(Path.of("/proc"), Path.of("/dev"), isolation.systemdUserRuntimeDirectory)
            require(reserved.none { overlaps(scratch, it) }) { "module scratch overlaps a reserved namespace" }
            val basePaths = baseMounts.flatMap { listOf(it.source, it.destination) }
            require(basePaths.none { overlaps(scratch, it) }) { "module scratch overlaps the keeper runtime" }
            val hostFiles = listOf(isolation.javaExecutable, isolation.bubblewrapExecutable,
                isolation.resourceLimiterExecutable, isolation.scopeSupervisorExecutable,
                isolation.scopeInspectorExecutable, isolation.systemdBusControllerExecutable) + isolation.workerClassPath.map { it.path }
            require(hostFiles.none { overlaps(scratch, it) }) { "module scratch overlaps keeper deployment files" }
            baseMounts.forEach { mount ->
                val loaderAlias = mount in isolation.systemLibraryMounts && mount.source in LOADER_DIRECTORIES &&
                    mount.destination in LOADER_DIRECTORIES
                require((mount.source !in BROAD_DIRECTORIES || loaderAlias) &&
                    reserved.none { overlaps(mount.source, it) || overlaps(mount.destination, it) }) {
                    "keeper runtime exposes a broad host tree or reserved namespace"
                }
            }
            mounts.forEachIndexed { index, mount ->
                require(mount.source !in BROAD_DIRECTORIES && mount.destination !in BROAD_DIRECTORIES) {
                    "compiler runtime cannot expose a broad host tree"
                }
                require((basePaths + reserved + listOf(scratch) + hostFiles).none {
                    overlaps(mount.source, it) || overlaps(mount.destination, it)
                }) {
                    "compiler runtime overlaps keeper, scratch, or reserved authority"
                }
                require(mounts.drop(index + 1).none {
                    overlaps(mount.source, it.source) || overlaps(mount.destination, it.destination)
                }) {
                    "compiler runtime trees must be disjoint"
                }
            }
            val compilerMount = mounts.singleOrNull { compilerPath != it.source && compilerPath.startsWith(it.source) }
            require(compilerMount != null && compilerMount.source == compilerMount.destination) {
                "compiler executable must belong to exactly one same-path compiler runtime tree"
            }
            // Curated headers and compiler internals may retain their toolchain's compiled-in
            // lookup paths through explicit aliases. The executable's own path stays canonical.
            return Declaration(document, profileId, isolation, compilerPath, compilerSha256, mounts, scratch,
                scratchPolicy, managerControlGroup)
        }

        private fun parseIsolation(record: JsonObject): FullTreeFunctionObservationIsolationConfiguration {
            record.exact(ISOLATION_FIELDS, "isolation")
            val classPath = record["workerClassPath"] as? JsonArray
                ?: throw IllegalArgumentException("workerClassPath must be an array")
            require(classPath.size in 1..MAXIMUM_CLASSPATH_ENTRIES) { "worker classpath count exceeds its bound" }
            val entries = classPath.map { value ->
                val entry = value as? JsonObject ?: throw IllegalArgumentException("worker classpath entry must be an object")
                entry.exact(setOf("path", "sha256"), "worker classpath entry")
                FullTreeFunctionObservationClassPathEntry(entry.path("path"), entry.digest("sha256"))
            }
            require(entries.map { it.path }.distinct().size == entries.size) { "worker classpath contains duplicate paths" }
            return FullTreeFunctionObservationIsolationConfiguration(
                javaExecutable = record.path("javaExecutable"),
                javaRuntime = mount(record.objectField("javaRuntime")),
                systemLibraryMounts = record.mounts("systemLibraryMounts"),
                bubblewrapExecutable = record.path("bubblewrapExecutable"),
                resourceLimiterExecutable = record.path("resourceLimiterExecutable"),
                scopeSupervisorExecutable = record.path("scopeSupervisorExecutable"),
                scopeInspectorExecutable = record.path("scopeInspectorExecutable"),
                systemdBusControllerExecutable = record.path("systemdBusControllerExecutable"),
                systemdUserRuntimeDirectory = record.path("systemdUserRuntimeDirectory"),
                workerClassPath = entries,
                expectedJavaSha256 = record.digest("expectedJavaSha256"),
                expectedBubblewrapSha256 = record.digest("expectedBubblewrapSha256"),
                expectedResourceLimiterSha256 = record.digest("expectedResourceLimiterSha256"),
                expectedScopeSupervisorSha256 = record.digest("expectedScopeSupervisorSha256"),
                expectedScopeInspectorSha256 = record.digest("expectedScopeInspectorSha256"),
                expectedSystemdBusControllerSha256 = record.digest("expectedSystemdBusControllerSha256"),
            )
        }

        private fun JsonObject.mounts(field: String): List<FullTreeFunctionObservationRuntimeMount> {
            val records = this[field] as? JsonArray ?: throw IllegalArgumentException("$field must be an array")
            require(records.size in 1..MAXIMUM_RUNTIME_MOUNTS) { "$field count exceeds its bound" }
            return records.map { mount(it as? JsonObject ?: throw IllegalArgumentException("$field entry must be an object")) }
        }

        private fun mount(record: JsonObject): FullTreeFunctionObservationRuntimeMount {
            record.exact(setOf("source", "destination", "sha256"), "runtime mount")
            return FullTreeFunctionObservationRuntimeMount(record.path("source"), record.path("destination"), record.digest("sha256"))
        }

        private fun JsonObject.exact(fields: Set<String>, label: String) {
            require(keys == fields) { "contained module compiler $label fields differ from schema v1" }
        }

        private fun JsonObject.objectField(field: String): JsonObject = this[field] as? JsonObject
            ?: throw IllegalArgumentException("$field must be an object")

        private fun JsonObject.text(field: String): String {
            val value = this[field] as? JsonPrimitive ?: throw IllegalArgumentException("$field must be a string")
            require(value.isString) { "$field must be a string" }
            return value.content
        }

        private fun JsonObject.integer(field: String): Long {
            val value = this[field] as? JsonPrimitive ?: throw IllegalArgumentException("$field must be an integer")
            require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]*"))) { "$field must be a nonnegative integer" }
            return value.content.toLongOrNull() ?: throw IllegalArgumentException("$field exceeds the integer range")
        }

        private fun JsonObject.digest(field: String): String = text(field).also {
            require(it.matches(SHA256)) { "$field must be a lowercase SHA-256 digest" }
        }

        private fun JsonObject.path(field: String): Path = canonicalPath(text(field), field)

        private fun canonicalPath(text: String, label: String): Path {
            require(text.isNotEmpty() && text.none { it.code < 32 || it.code == 127 }) { "$label contains invalid path characters" }
            return Path.of(text).also { path ->
                require(path.isAbsolute && path.parent != null && path.normalize() == path && path.toString() == text) {
                    "$label must be an absolute normalized non-root path"
                }
            }
        }

        private fun requireRootOwned(path: Path, directory: Boolean) {
            canonicalPath(path.toString(), "runtime input")
            require(path.toRealPath() == path) { "runtime inputs must be canonical without symbolic links" }
            var current: Path? = path
            while (current != null) {
                val checked = requireNotNull(current)
                requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(checked)).use { descriptor ->
                    val identity = descriptor.identity
                    require(identity.uid == 0 && !identity.isSymbolicLink && identity.mode.permissions and 0x12 == 0) {
                        "runtime input and ancestors must be root-owned and not group/world writable"
                    }
                    require(if (checked == path && !directory) identity.isRegularFile else identity.isDirectory) {
                        "runtime input has an unexpected file type"
                    }
                }
                current = checked.parent
            }
        }

        private fun verifyPinnedFile(path: Path, expectedSha256: String, executable: Boolean): KotlinSystemdCgroupCommandInput {
            requireRootOwned(path, directory = false)
            requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)).use { descriptor ->
                require(!executable || descriptor.identity.mode.permissions and 0x49 != 0) { "runtime executable has no execute permission" }
                val descriptorPath = LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd)
                val before = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                require(before.isRegularFile && before.size() in 1..MAXIMUM_PINNED_FILE_BYTES) { "runtime file size exceeds its bound" }
                val digest = MessageDigest.getInstance("SHA-256")
                val count = DigestOutputStream(OutputStream.nullOutputStream(), digest).use { output ->
                    LinuxFilesystemSyscalls.copyReadableTo(descriptor, output, MAXIMUM_PINNED_FILE_BYTES)
                }
                val after = Files.readAttributes(descriptorPath, BasicFileAttributes::class.java)
                require(count == before.size() && after.size() == count && before.fileKey() == after.fileKey() &&
                    before.lastModifiedTime() == after.lastModifiedTime() &&
                    LinuxFilesystemSyscalls.identity(descriptor.fd) == descriptor.identity) { "runtime file changed while hashing" }
                requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)).use { named ->
                    require(named.identity == descriptor.identity) { "runtime file name changed while hashing" }
                }
                requireRootOwned(path, directory = false)
                val actual = digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
                require(actual == expectedSha256) { "runtime file differs from its pinned content digest" }
                return KotlinSystemdCgroupCommandInput(path, count, actual)
            }
        }

        private fun overlaps(first: Path, second: Path): Boolean = first.startsWith(second) || second.startsWith(first)
        private const val MAXIMUM_CONFIG_BYTES = 256 * 1024
        private const val MAXIMUM_RUNTIME_MOUNTS = 16
        private const val MAXIMUM_CLASSPATH_ENTRIES = 512
        private const val MAXIMUM_PINNED_FILE_BYTES = 512L * 1024 * 1024
        private const val MAXIMUM_SCRATCH_BYTES = 8L * 1024 * 1024 * 1024
        private const val MAXIMUM_SCRATCH_INODES = 1_048_576L
        private val SHA256 = Regex("[0-9a-f]{64}")
        private val BROAD_DIRECTORIES = setOf("/", "/usr", "/bin", "/sbin", "/usr/bin", "/usr/sbin", "/lib", "/lib64",
            "/usr/lib", "/usr/lib64", "/usr/libexec", "/etc", "/var", "/run", "/home", "/root", "/opt", "/tmp").mapTo(hashSetOf(), Path::of)
        private val LOADER_DIRECTORIES = setOf(Path.of("/lib64"), Path.of("/usr/lib64"))
        private val ROOT_FIELDS = setOf("schemaVersion", "profileId", "isolation", "compiler", "compilerRuntimeMounts",
            "scratchMount", "scratchPolicy", "managerControlGroup")
        private val SCRATCH_FIELDS = setOf("requiredAvailableBytes", "maximumFilesystemBytes", "requiredAvailableInodes", "maximumFilesystemInodes")
        private val ISOLATION_FIELDS = setOf("javaExecutable", "javaRuntime", "systemLibraryMounts", "bubblewrapExecutable",
            "resourceLimiterExecutable", "scopeSupervisorExecutable", "scopeInspectorExecutable", "systemdBusControllerExecutable",
            "systemdUserRuntimeDirectory", "workerClassPath", "expectedJavaSha256", "expectedBubblewrapSha256",
            "expectedResourceLimiterSha256", "expectedScopeSupervisorSha256", "expectedScopeInspectorSha256", "expectedSystemdBusControllerSha256")
        private val CONFIG_LIMITS = StrictJsonLimits(maximumInputBytes = MAXIMUM_CONFIG_BYTES,
            maximumCanonicalBytes = MAXIMUM_CONFIG_BYTES * 2, maximumDepth = 8, maximumNodes = 4096,
            maximumStringBytes = 4096, maximumTotalStringBytes = MAXIMUM_CONFIG_BYTES, maximumNumberCharacters = 32)
    }
}
