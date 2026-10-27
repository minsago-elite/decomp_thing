package decompengine.project

import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionProcess
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/**
 * Hosted operator-data writer using the existing runtime and scratch provisioners. It runs no
 * compiler or reconstructed program, grants no live authority, and supplies no qualification by
 * itself. The operator installs its output root-owned before the production factory can load it.
 */
object ContainedModuleCompilationQualificationCli {
    private val runtimeRoot = Path.of("/var/lib/decomp-generated-c-runtime-ci")
    private val provisionedJavaRoot = Path.of("/var/lib/decomp-oracle-ci-java")
    private const val SCRATCH_ENVIRONMENT = "DECOMP_TEST_MODULE_COMPILE_EXT4_SCRATCH"
    private const val MAXIMUM_WORKER_BYTES = 256L * 1024 * 1024
    private val limits = StrictJsonLimits(maximumInputBytes = 256 * 1024, maximumCanonicalBytes = 512 * 1024,
        maximumDepth = 12, maximumNodes = 4096, maximumStringBytes = 4096,
        maximumTotalStringBytes = 256 * 1024, maximumNumberCharacters = 32)

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2 && arguments[0] == "write-config") {
            "usage: ContainedModuleCompilationQualificationCli write-config <fresh absolute output directory under checkout/build>"
        }
        val output = Path.of(arguments[1])
        requireCompilerAbsolutePath(output)
        val checkout = Path.of("").toAbsolutePath().toRealPath()
        val build = checkout.resolve("build")
        require(Files.isDirectory(build, LinkOption.NOFOLLOW_LINKS) && build.toRealPath() == build &&
            output != build && output.startsWith(build) && !Files.exists(output, LinkOption.NOFOLLOW_LINKS)) {
            "module qualification output must be fresh and belong to checkout/build"
        }
        var existing: Path? = output.parent
        while (existing != null) {
            val selected = requireNotNull(existing)
            if (Files.exists(selected, LinkOption.NOFOLLOW_LINKS)) require(selected.toRealPath() == selected) {
                "module qualification output ancestors must not be symbolic links"
            }
            existing = selected.parent
        }
        val configurations = configurations()
        Files.createDirectories(output)
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"))
        configurations.forEach { (profile, record) ->
            Files.write(output.resolve("$profile.json"), OracleJson.canonicalBytes(record, limits),
                StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            Files.setPosixFilePermissions(output.resolve("$profile.json"), PosixFilePermissions.fromString("rw-------"))
        }
        println("Wrote Make/Ninja operator configuration data under $output; root-owned installation and live qualification remain required")
    }

    private fun configurations(): Map<String, JsonObject> {
        val plan = readTrustedJson(runtimeRoot.resolve("runtime-plan.json"))
        require(plan.keys == setOf("schemaVersion", "profileId", "sandboxConfigurationFile", "tools", "buildRuntimeMounts",
            "programRuntimeMounts", "sourceTmpfs", "outputTmpfs") && plan["schemaVersion"] == JsonPrimitive(1) &&
            plan.text("profileId") == GeneratedCMakeReconstructionProfile.PROFILE_ID) {
            "installed generated-C runtime plan differs from its existing provisioner contract"
        }
        val tools = plan.objectField("tools")
        require(tools.keys == GeneratedCRepairRuntimeConfiguration.TOOL_ROLES) { "installed runtime tool roles differ" }
        val compilerRecord = tools.objectField("compiler")
        compilerRecord.exact(setOf("source", "destination"))
        val compiler = compilerRecord.path("source")
        require(compiler == runtimeRoot.resolve("tools/cc") &&
            compilerRecord.path("destination") == GeneratedCRepairRuntimeConfiguration.TOOL_DIRECTORY.resolve("cc")) {
            "installed compiler is not the existing provisioner's pinned compiler"
        }
        val buildMounts = plan["buildRuntimeMounts"] as? JsonArray ?: error("installed build runtime must be an array")
        require(buildMounts.size in 1..48)
        val selected = buildMounts.map { value ->
            (value as? JsonObject ?: error("installed build mount must be an object")).also {
                it.exact(setOf("source", "destination"))
            }
        }
        fun selectedMount(name: String): JsonObject = selected.singleOrNull { it.path("source") == runtimeRoot.resolve(name) }
            ?: error("existing provisioner lacks the exact $name runtime directory")
        val gcc = selectedMount("gcc")
        val headers = selectedMount("headers")
        require(gcc.path("destination").startsWith(Path.of("/usr/lib/gcc")) && gcc.path("destination").nameCount >= 5 &&
            headers.path("destination") == Path.of("/usr/include")) {
            "installed compiler internals or header aliases differ from the reviewed closure"
        }
        val manifestCache = mutableMapOf<Path, String>()
        fun mount(source: Path, destination: Path = source): JsonObject = JsonObject(mapOf(
            "source" to JsonPrimitive(source.toString()), "destination" to JsonPrimitive(destination.toString()),
            "sha256" to JsonPrimitive(manifestCache.getOrPut(source) { calculateFullTreeObservationRuntimeManifestSha256(source) }),
        ))
        val compilerMounts = JsonArray(listOf(mount(runtimeRoot.resolve("tools")),
            mount(gcc.path("source"), gcc.path("destination")), mount(headers.path("source"), headers.path("destination"))))
        val workerManifest = readTrustedJson(runtimeRoot.resolve("module-worker-classpath.json"))
        workerManifest.exact(setOf("schemaVersion", "entries"))
        require(workerManifest["schemaVersion"] == JsonPrimitive(1))
        val entries = workerManifest["entries"] as? JsonArray ?: error("installed worker classpath must be an array")
        require(entries.size in 1..512)
        var workerBytes = 0L
        val workerClassPath = JsonArray(entries.mapIndexed { index, value ->
            val entry = value as? JsonObject ?: error("installed worker entry must be an object")
            entry.exact(setOf("path", "bytes", "sha256"))
            val path = entry.path("path")
            require(path == runtimeRoot.resolve("worker/classpath-$index.jar")) { "installed worker classpath order or path differs" }
            val size = entry.number("bytes")
            require(size in 1..MAXIMUM_WORKER_BYTES)
            workerBytes = Math.addExact(workerBytes, size)
            require(workerBytes <= MAXIMUM_WORKER_BYTES) { "installed worker classpath exceeds its aggregate bound" }
            require(Files.size(path) == size && (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt() == 1 &&
                digest(path, MAXIMUM_WORKER_BYTES) == entry.text("sha256")) { "installed worker file differs from its explicit pin" }
            JsonObject(mapOf("path" to JsonPrimitive(path.toString()), "sha256" to JsonPrimitive(entry.text("sha256"))))
        })
        val javaRoot = Path.of(System.getProperty("java.home")).toRealPath()
        require(javaRoot == provisionedJavaRoot) { "qualification must run with the existing provisioned oracle JDK" }
        val java = javaRoot.resolve("bin/java").toRealPath()
        fun executable(name: String): Path = Path.of("/usr/bin", name).toRealPath().also {
            requireTrusted(it, directory = false)
            require(Files.isExecutable(it)) { "qualification launcher helper is not executable: $name" }
        }
        val executables = mapOf("bubblewrapExecutable" to executable("bwrap"), "resourceLimiterExecutable" to executable("prlimit"),
            "scopeSupervisorExecutable" to executable("systemd-run"), "scopeInspectorExecutable" to executable("systemctl"),
            "systemdBusControllerExecutable" to executable("busctl"))
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        require(uid > 0) { "qualification application must run as a non-root user" }
        val session = Path.of("/run/user/$uid")
        require(Files.isDirectory(session, LinkOption.NOFOLLOW_LINKS) && session.toRealPath() == session)
        val manager = LinuxBoundedSessionProcess.execute(LinuxBoundedSessionCommand(
            listOf(executables.getValue("scopeInspectorExecutable").toString(), "--user", "show", "--property=ControlGroup", "--value"),
            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC", "XDG_RUNTIME_DIR" to session.toString(),
                "DBUS_SESSION_BUS_ADDRESS" to "unix:path=${session.resolve("bus")}"),
            workingDirectory = Path.of("/"), timeout = Duration.ofSeconds(10), maximumStdoutBytes = 4096, maximumStderrBytes = 4096,
        ))
        require(manager.exitCode == 0 && manager.signal == null && manager.stderr.isEmpty()) { "cannot observe the active user systemd manager" }
        val managerGroup = manager.stdout.toString(Charsets.UTF_8).trim()
        requireCompilerAbsolutePath(Path.of(managerGroup))
        val abi = when (System.getProperty("os.arch")) {
            "amd64", "x86_64" -> "x86_64-linux-gnu"
            "aarch64", "arm64" -> "aarch64-linux-gnu"
            else -> error("module qualification has no reviewed system ABI mapping")
        }
        // Match the existing real-keeper test seam, retaining ABI trees rather than whole /usr/lib.
        val libraries = listOf("/lib/$abi", "/lib64", "/usr/lib/$abi", "/usr/lib64").map(Path::of)
            .filter { Files.isDirectory(it) }.map { directory ->
                val destination = if (abi == "aarch64-linux-gnu" && directory == Path.of("/lib/$abi")) Path.of("/lib") else directory
                mount(directory.toRealPath(), destination)
            }
        require(libraries.isNotEmpty())
        val isolation = JsonObject(mapOf(
            "javaExecutable" to JsonPrimitive(java.toString()), "javaRuntime" to mount(javaRoot, Path.of("/decomp-runtime/java")),
            "systemLibraryMounts" to JsonArray(libraries), "systemdUserRuntimeDirectory" to JsonPrimitive(session.toString()),
            "workerClassPath" to workerClassPath, "expectedJavaSha256" to JsonPrimitive(digest(java)),
        ) + executables.mapValues { JsonPrimitive(it.value.toString()) } + executables.mapKeys { (key, _) ->
            "expected${key.removeSuffix("Executable").replaceFirstChar(Char::uppercase)}Sha256"
        }.mapValues { JsonPrimitive(digest(it.value)) })
        val scratch = Path.of(requireNotNull(System.getenv(SCRATCH_ENVIRONMENT)) { "$SCRATCH_ENVIRONMENT must select the existing dedicated module scratch mount" })
        requireCompilerAbsolutePath(scratch)
        require(scratch.toRealPath() == scratch)
        val capacity = LinuxFilesystemSyscalls.openRoot(scratch).use { root ->
            require(root.identity.uid == uid && root.identity.mode.permissions == 448) { "module scratch is not private to the qualification user" }
            require(LinuxFilesystemSyscalls.directoryEntryNames(root, 1).isEmpty()) { "module scratch must initially be empty" }
            LinuxFilesystemSyscalls.filesystemCapacity(root)
        }
        val policy = JsonObject(mapOf("requiredAvailableBytes" to JsonPrimitive(workerBytes + 128L * 1024 * 1024),
            "maximumFilesystemBytes" to JsonPrimitive(capacity.totalBytes), "requiredAvailableInodes" to JsonPrimitive(8192),
            "maximumFilesystemInodes" to JsonPrimitive(capacity.totalInodes)))
        require(capacity.availableBytes >= workerBytes + 128L * 1024 * 1024 && capacity.availableInodes >= 8192)
        return listOf(GeneratedCMakeReconstructionProfile.PROFILE_ID, GeneratedCNinjaReconstructionProfile.PROFILE_ID).associateWith { profile ->
            JsonObject(mapOf("schemaVersion" to JsonPrimitive(1), "profileId" to JsonPrimitive(profile), "isolation" to isolation,
                "compiler" to JsonObject(mapOf("path" to JsonPrimitive(compiler.toString()), "sha256" to JsonPrimitive(digest(compiler)))),
                "compilerRuntimeMounts" to compilerMounts, "scratchMount" to JsonPrimitive(scratch.toString()), "scratchPolicy" to policy,
                "managerControlGroup" to JsonPrimitive(managerGroup))).also {
                ContainedModuleCompilationRuntimeConfiguration.parse(OracleJson.canonicalBytes(it, limits))
            }
        }
    }

    private fun readTrustedJson(path: Path): JsonObject {
        requireTrusted(path, directory = false)
        return OracleJson.parse(readStableRegularFile(requireNotNull(path.parent), path.fileName.toString(),
            limits.maximumInputBytes.toLong()).bytes, limits) as? JsonObject ?: error("operator record must be an object")
    }

    private fun digest(path: Path, maximum: Long = 512L * 1024 * 1024): String {
        requireTrusted(path, directory = false)
        val digest = MessageDigest.getInstance("SHA-256")
        require(Files.size(path) in 1..maximum) { "operator input size exceeds its hash bound" }
        val before = Files.readAttributes(path, "unix:dev,ino,size,lastModifiedTime,ctime,mode,uid,nlink", LinkOption.NOFOLLOW_LINKS)
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(128 * 1024)
            var total = 0L
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total = Math.addExact(total, count.toLong())
                require(total <= maximum) { "operator input exceeds its hash bound" }
                digest.update(buffer, 0, count)
            }
        }
        require(before == Files.readAttributes(path, "unix:dev,ino,size,lastModifiedTime,ctime,mode,uid,nlink", LinkOption.NOFOLLOW_LINKS)) {
            "operator input changed while hashing"
        }
        return digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }

    private fun requireTrusted(path: Path, directory: Boolean) {
        requireCompilerAbsolutePath(path)
        require(path.toRealPath() == path) { "operator input must be canonical" }
        var current: Path? = path
        while (current != null) {
            val selected = requireNotNull(current)
            requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(selected)).use { opened ->
                val identity = opened.identity
                require(identity.uid == 0 && !identity.isSymbolicLink && identity.mode.permissions and 0x12 == 0 &&
                    if (selected == path && !directory) identity.isRegularFile else identity.isDirectory) {
                    "operator input and ancestors must be root-owned and not writable by other users"
                }
            }
            current = selected.parent
        }
    }

    private fun JsonObject.exact(fields: Set<String>) { require(keys == fields) { "operator record fields differ" } }
    private fun JsonObject.objectField(field: String): JsonObject = this[field] as? JsonObject ?: error("operator $field must be an object")
    private fun JsonObject.text(field: String): String = (this[field] as? JsonPrimitive)?.takeIf { it.isString }?.content
        ?: error("operator $field must be a string")
    private fun JsonObject.path(field: String): Path = Path.of(text(field)).also {
        requireCompilerAbsolutePath(it)
        require(it.toString() == text(field))
    }
    private fun JsonObject.number(field: String): Long {
        val value = this[field] as? JsonPrimitive ?: error("operator $field must be an integer")
        require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]*")))
        return requireNotNull(value.content.toLongOrNull())
    }
}
