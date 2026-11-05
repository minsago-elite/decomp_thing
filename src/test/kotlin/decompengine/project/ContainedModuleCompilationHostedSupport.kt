package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandExecutionException
import decompengine.oracle.fulltree.OracleNativeLibraries
import decompengine.oracle.fulltree.parseContainedCommandFileDescriptorLimits
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.IdentityHashMap
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Authored hosted fixtures only. These declarations do not create compiler acceptance authority. */
internal object ContainedModuleCompilationHostedSupport {
    const val FUNCTION_ID = "fn_0000000000401000"
    const val DEFAULT_BODY = "volatile unsigned value = 7u; return (int)(value + headers_sum);"
    const val CHILD_CLASSPATH_PROPERTY = "decompengine.moduleQualification.childClasspathManifest"
    private const val EXTRA_MODULES = 255
    private const val MAXIMUM_MANIFEST_BYTES = 1024 * 1024
    private const val MAXIMUM_JAR_BYTES = 128L * 1024 * 1024
    private const val MAXIMUM_CLASSPATH_BYTES = 512L * 1024 * 1024
    private val digestPattern = Regex("[0-9a-f]{64}")
    private val manifestLimits = StrictJsonLimits(maximumInputBytes = MAXIMUM_MANIFEST_BYTES,
        maximumCanonicalBytes = 2 * MAXIMUM_MANIFEST_BYTES, maximumDepth = 12, maximumNodes = 8192,
        maximumStringBytes = 4096, maximumTotalStringBytes = MAXIMUM_MANIFEST_BYTES, maximumNumberCharacters = 32)

    fun model() = RecoveredProgramModel(inputSha256 = sha256("authored live module fixture".toByteArray()),
        functions = listOf(RecoveredFunction(FUNCTION_ID, "parse_input", 0x401000UL, "int parse_input(void)",
            decompiledC = "int parse_input(void) { volatile unsigned value = 7u; return (int)value; }")))

    fun stageExtraHeaders(project: Path, profile: ReconstructionProfile): List<String> {
        requireContainedModuleCompilerProfile(profile)
        require(project.isAbsolute && project.toRealPath() == project && Files.isDirectory(project, LinkOption.NOFOLLOW_LINKS))
        val paths = ArrayList<String>(EXTRA_MODULES * 2)
        for (index in 0 until EXTRA_MODULES) {
            val module = extraModule(index)
            for ((role, prefix, value) in listOf(Triple("module-interface", "FD_PUBLIC", index + 1),
                Triple("module-private-interface", "FD_PRIVATE", EXTRA_MODULES + index + 1))) {
                val relative = profile.layout.declaration(role).materialize(mapOf("module" to module))
                val target = project.resolve(relative)
                Files.createDirectories(target.parent)
                require(target.parent.toRealPath() == target.parent)
                Files.writeString(target, "enum { ${prefix}_$module = $value };\n",
                    StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
                paths += relative
            }
        }
        return paths.sorted().also { require(it.size == 510 && it.distinct().size == it.size) }
    }

    fun source(profile: ReconstructionProfile, moduleId: String, body: String = DEFAULT_BODY,
        extraPrelude: String = ""): String {
        requireContainedModuleCompilerProfile(profile)
        require(moduleId !in (0 until EXTRA_MODULES).map(::extraModule))
        val parent = Path.of(profile.layout.declaration("module-implementation").materialize(mapOf("module" to moduleId))).parent
        val interfaces = listOf(profile.layout.declaration("shared-interface").materialize(),
            profile.layout.declaration("module-interface").materialize(mapOf("module" to moduleId)),
            profile.layout.declaration("module-private-interface").materialize(mapOf("module" to moduleId))) +
            (0 until EXTRA_MODULES).flatMap { index -> listOf("module-interface", "module-private-interface").map { role ->
                profile.layout.declaration(role).materialize(mapOf("module" to extraModule(index)))
            } }
        return buildString {
            interfaces.forEach { path -> append("#include \"").append(parent.relativize(Path.of(path))).append("\"\n") }
            if (extraPrelude.isNotEmpty()) append(extraPrelude).append('\n')
            append("/* $FUNCTION_ID */\nint parse_input(void) {\nconst unsigned headers_sum = 0u\n")
            for (index in 0 until EXTRA_MODULES) {
                val module = extraModule(index)
                append(" + (unsigned)FD_PUBLIC_$module + (unsigned)FD_PRIVATE_$module\n")
            }
            append(";\n(void)headers_sum;\n").append(body).append("\n}\n")
        }.also { require(it.toByteArray().size.toLong() <= ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES) }
    }

    fun reconstructor(profile: ReconstructionProfile, body: String = DEFAULT_BODY,
        extraPrelude: String = ""): ModuleReconstructor = ModuleReconstructor { request ->
        require(request.profile.sha256 == profile.sha256 && request.module.functionIds == listOf(FUNCTION_ID))
        val source = source(profile, request.module.id, body, extraPrelude)
        ReconstructedModule(source, "authored-contained-compiler-live-fixture", sha256(source.toByteArray()))
    }

    /** Explicit build-produced test closure; hashing it does not authenticate a production deployment. */
    fun validateChildClasspathManifest(path: Path, expectedSha256: String): List<Path> {
        require(expectedSha256.matches(digestPattern))
        requireBuildPath(path)
        val encoded = readRegular(path, MAXIMUM_MANIFEST_BYTES)
        require(sha256(encoded) == expectedSha256) { "hosted child classpath manifest bytes changed" }
        val record = parseObject(encoded)
        require(record.keys == setOf("schemaVersion", "provider", "workerClasspathManifestSha256", "entries") &&
            record["schemaVersion"] == JsonPrimitive(1) &&
            record["provider"] == JsonPrimitive("contained-module-hosted-child-classpath-v1"))
        val entries = parseClasspathEntries(record)
        val workerPath = checkout().resolve("build/module-compilation-qualification/worker-classpath.json")
        requireBuildPath(workerPath)
        val workerBytes = readRegular(workerPath, MAXIMUM_MANIFEST_BYTES)
        require(sha256(workerBytes) == digest(record, "workerClasspathManifestSha256")) {
            "hosted child worker manifest bytes changed"
        }
        val worker = parseObject(workerBytes)
        require(worker.keys == setOf("schemaVersion", "entries") && worker["schemaVersion"] == JsonPrimitive(1))
        val workerEntries = parseClasspathEntries(worker)
        workerEntries.forEach { required ->
            require(entries.count { it.bytes == required.bytes && it.sha256 == required.sha256 } == 1) {
                "hosted child classpath omits or duplicates a pinned worker JAR"
            }
        }
        return entries.map { it.path }
    }

    internal fun checkout(): Path = Path.of("").toAbsolutePath().toRealPath().also {
        require(Files.isRegularFile(it.resolve("build.gradle.kts"), LinkOption.NOFOLLOW_LINKS)) {
            "hosted child must use the checkout as its working directory"
        }
    }

    internal fun requireBuildPath(path: Path, exists: Boolean = true) {
        val build = checkout().resolve("build")
        require(path.isAbsolute && path.normalize() == path && path != build && path.startsWith(build)) {
            "hosted fixture path must belong to checkout/build"
        }
        val selected = if (exists) path else requireNotNull(path.parent)
        require(selected.toRealPath() == selected) { "hosted fixture path has a symbolic ancestor" }
    }

    internal fun readRegular(path: Path, maximum: Int): ByteArray {
        require(path.toRealPath() == path) { "hosted fixture file has a symbolic path alias: $path" }
        val before = fileIdentity(path)
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
            (before.getValue("nlink") as Number).toLong() == 1L &&
            (before.getValue("size") as Number).toLong() in 0..maximum.toLong()) { "hosted fixture file exceeds its type or size bound: $path" }
        val bytes = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(maximum + 1) }
        require(bytes.size <= maximum && bytes.size.toLong() == (before.getValue("size") as Number).toLong() && before == fileIdentity(path)) {
            "hosted fixture file changed while reading: $path"
        }
        return bytes
    }

    internal fun parseObject(bytes: ByteArray): JsonObject = OracleJson.parse(bytes, manifestLimits) as? JsonObject
        ?: error("hosted fixture manifest must be an object")

    internal fun text(record: JsonObject, key: String): String = (record[key] as? JsonPrimitive)?.let {
        require(it.isString); it.content
    } ?: error("missing hosted fixture string: $key")

    internal fun number(record: JsonObject, key: String): Long = (record[key] as? JsonPrimitive)?.let {
        require(!it.isString && it.content.matches(Regex("0|[1-9][0-9]{0,18}")))
        requireNotNull(it.content.toLongOrNull())
    } ?: error("missing hosted fixture number: $key")

    internal fun digest(record: JsonObject, key: String): String = text(record, key).also { require(it.matches(digestPattern)) }

    internal fun fileDigest(path: Path, maximum: Long): Pair<Long, String> {
        val before = fileIdentity(path)
        val size = (before.getValue("size") as Number).toLong()
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(path) &&
            (before.getValue("nlink") as Number).toLong() == 1L && size in 1..maximum)
        val digest = MessageDigest.getInstance("SHA-256")
        var total = 0L
        Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total = Math.addExact(total, count.toLong())
                require(total <= maximum)
                digest.update(buffer, 0, count)
            }
        }
        require(total == size && before == fileIdentity(path)) { "hosted fixture JAR changed while hashing: $path" }
        return size to digest.digest().joinToString("") { "%02x".format(it) }
    }

    private data class ClasspathEntry(val path: Path, val bytes: Long, val sha256: String)
    private fun parseClasspathEntries(record: JsonObject): List<ClasspathEntry> {
        val raw = record["entries"] as? JsonArray ?: error("hosted classpath entries must be an array")
        require(raw.size in 1..128)
        var total = 0L
        val entries = raw.map { value ->
            val entry = value as? JsonObject ?: error("hosted classpath entry must be an object")
            require(entry.keys == setOf("path", "bytes", "sha256"))
            val path = Path.of(text(entry, "path"))
            requireBuildPath(path)
            require(path.fileName.toString().endsWith(".jar")) { "hosted child classpath must contain only explicit JAR files" }
            val size = number(entry, "bytes")
            require(size in 1..MAXIMUM_JAR_BYTES)
            total = Math.addExact(total, size)
            require(total <= MAXIMUM_CLASSPATH_BYTES)
            val digest = digest(entry, "sha256")
            require(fileDigest(path, MAXIMUM_JAR_BYTES) == (size to digest)) { "hosted child classpath JAR differs from its manifest: $path" }
            ClasspathEntry(path, size, digest)
        }
        require(entries.map { it.path }.distinct().size == entries.size) { "hosted child classpath paths repeat" }
        require(entries.map { it.sha256 }.distinct().size == entries.size) { "hosted child classpath JAR bytes repeat" }
        return entries
    }

    private fun fileIdentity(path: Path): Map<String, Any> = Files.readAttributes(path,
        "unix:dev,ino,size,lastModifiedTime,ctime,mode,uid,nlink", LinkOption.NOFOLLOW_LINKS)

    private fun extraModule(index: Int): String = "fd" + index.toString().padStart(4, '0')
}

/** Test coordinator under a lowered hard limit; it never substitutes a worker or issues a permit. */
internal object ContainedModuleCompilationLowHardChild {
    private const val MAXIMUM_REPORT_BYTES = 1024 * 1024
    private const val MAXIMUM_BASELINE_FILE_BYTES = 16 * 1024 * 1024
    private const val EXPECTED_REFUSAL = "launcher inherited hard limit cannot admit the closed file-descriptor policy"
    private val support = ContainedModuleCompilationHostedSupport

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 6) {
            "usage: ContainedModuleCompilationLowHardChild <project> <profileId> <fresh-report-directory> <baseline-manifest> <classpath-manifest> <classpath-manifest-sha256>"
        }
        val project = Path.of(arguments[0])
        val profile = ReconstructionProfiles.named(arguments[1])
        requireContainedModuleCompilerProfile(profile)
        val reports = Path.of(arguments[2])
        support.requireBuildPath(project)
        support.requireBuildPath(reports, exists = false)
        require(Files.isDirectory(project, LinkOption.NOFOLLOW_LINKS) && !reports.startsWith(project) && !project.startsWith(reports))
        Files.createDirectory(reports)
        try {
            execute(project, profile, reports, Path.of(arguments[3]), Path.of(arguments[4]), arguments[5])
        } catch (failure: Throwable) {
            try { write(reports, "child-failure.json", failureRecord(failure)) }
            catch (retention: Throwable) { if (retention !== failure) failure.addSuppressed(retention) }
            throw failure
        }
    }

    private fun execute(project: Path, profile: ReconstructionProfile, reports: Path,
        baselinePath: Path, classpathPath: Path, expectedClasspathSha256: String) {
        val classpath = support.validateChildClasspathManifest(classpathPath, expectedClasspathSha256)
        val actualClasspath = System.getProperty("java.class.path").split(File.pathSeparator).map(Path::of)
        require(actualClasspath == classpath) { "actual child classpath differs from its explicit ordered manifest" }
        val native = Path.of(requireNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory")))
        require(native.isAbsolute && native.toRealPath() == native)
        OracleNativeLibraries.jvmArguments(native).forEach { argument ->
            val property = argument.removePrefix("-D").substringBefore('=')
            require(System.getProperty(property) == argument.substringAfter('=')) { "child native JVM property differs: $property" }
        }
        OracleNativeLibraries.requireCurrent(native, classpath.map { support.fileDigest(it, 128L * 1024 * 1024).second })
        require(System.getenv(ContainedModuleCompilationRuntimeConfiguration.ENVIRONMENT) == null &&
            !System.getenv(ContainedModuleCompilationRuntimeConfiguration.DIRECTORY_ENVIRONMENT).isNullOrBlank() &&
            System.getenv("GENERATED_C_MODULE_COMPILE_REQUIRE") == "true") { "low-hard child requires the configured hosted directory" }
        for (property in listOf("java.io.tmpdir", "user.home", "jna.tmpdir")) {
            val path = Path.of(requireNotNull(System.getProperty(property)))
            support.requireBuildPath(path)
            require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS))
        }
        val runtime = ContainedModuleCompilationRuntimeConfiguration.loadFromEnvironment(profile.id)
        require(Path.of(System.getProperty("java.home"), "bin/java").toRealPath() == runtime.isolation.javaExecutable) {
            "low-hard child did not use the configured pinned JDK"
        }
        val classpathBytes = support.readRegular(classpathPath, MAXIMUM_REPORT_BYTES)
        require(sha256(classpathBytes) == expectedClasspathSha256)
        writeBytes(reports, "child-classpath-manifest.json", classpathBytes)
        val workerBytes = support.readRegular(support.checkout()
            .resolve("build/module-compilation-qualification/worker-classpath.json"), MAXIMUM_REPORT_BYTES)
        require(sha256(workerBytes) == support.digest(support.parseObject(classpathBytes), "workerClasspathManifestSha256"))
        writeBytes(reports, "worker-classpath-manifest.json", workerBytes)
        support.requireBuildPath(baselinePath)
        val baselineBytes = support.readRegular(baselinePath, MAXIMUM_REPORT_BYTES)
        writeBytes(reports, "baseline-manifest.json", baselineBytes)
        val accepted = baseline(project, profile, baselineBytes)
        retainBaseline(reports, "before", accepted)
        requireClean(project, runtime)

        val pid = ProcessHandle.current().pid()
        val beforeStat = readProc(Path.of("/proc/self/stat"))
        val limitsBytes = readProc(Path.of("/proc/self/limits"))
        val afterStat = readProc(Path.of("/proc/self/stat"))
        val start = startTime(beforeStat, pid)
        require(startTime(afterStat, pid) == start)
        val limits = parseContainedCommandFileDescriptorLimits(limitsBytes.toString(Charsets.UTF_8))
        writeBytes(reports, "self-stat-before.txt", beforeStat)
        writeBytes(reports, "self-limits.txt", limitsBytes)
        writeBytes(reports, "self-stat-after.txt", afterStat)
        write(reports, "self-observation.json", JsonObject(mapOf("schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("hosted-low-hard-child-observation-v1"), "hostPid" to JsonPrimitive(pid),
            "startTimeTicks" to JsonPrimitive(start), "softLimit" to JsonPrimitive(limits.softLimit),
            "hardLimit" to JsonPrimitive(limits.hardLimit), "limitsSha256" to JsonPrimitive(sha256(limitsBytes)),
            "statBeforeSha256" to JsonPrimitive(sha256(beforeStat)), "statAfterSha256" to JsonPrimitive(sha256(afterStat)))))
        require(limits.softLimit == 7677L && limits.hardLimit == 7677L) { "child did not actually inherit 7677:7677" }

        var dispatched = false
        val failure = try {
            SourceTreeGenerator.generate(support.model(), project, profile = profile, reconstructor = ModuleReconstructor {
                dispatched = true
                error("the accepted low-hard revision must be revalidated without reconstruction dispatch")
            })
            error("low-hard SourceTree generation unexpectedly succeeded")
        } catch (caught: Exception) {
            if (caught is InterruptedException || caught is java.util.concurrent.CancellationException ||
                caught is java.io.InterruptedIOException || caught is java.nio.channels.ClosedByInterruptException ||
                Thread.currentThread().isInterrupted) throw caught
            caught
        }
        write(reports, "admission-failure.json", failureRecord(failure))
        require(!dispatched) { "low-hard child dispatched reconstruction" }
        val chain = failureChain(failure)
        require(chain.any { it is IllegalArgumentException && it.message == EXPECTED_REFUSAL }) {
            "SourceTree failed for a cause other than the actual inherited hard limit"
        }
        val executionFailure = chain.filterIsInstance<KotlinSystemdCgroupCommandExecutionException>().single()
        require(executionFailure.cleanup.absenceProved && chain.all { it.suppressed.isEmpty() }) {
            "low-hard launcher cleanup did not complete without suppressed failures"
        }
        val evidencePath = profile.layout.declaration("module-evidence").materialize(mapOf("module" to "parse"))
        val attemptPath = project.resolve(evidencePath.removeSuffix(".json") + ".attempt.json")
        val attemptBytes = support.readRegular(attemptPath, MAXIMUM_REPORT_BYTES)
        writeBytes(reports, "validation-failure-attempt.json", attemptBytes)
        val attempt = support.parseObject(attemptBytes)
        val sourcePath = profile.layout.declaration("module-implementation").materialize(mapOf("module" to "parse"))
        val sourceHash = sha256(accepted.getValue(sourcePath))
        require(attempt["schemaVersion"] == JsonPrimitive(1) && attempt["kind"] == JsonPrimitive("module-compilation-failure") &&
            attempt["status"] == JsonPrimitive("validation-failed") && attempt["attemptKind"] == JsonPrimitive("compiler-revalidation") &&
            attempt["moduleId"] == JsonPrimitive("parse") && attempt["candidateSourceSha256"] == JsonPrimitive(sourceHash) &&
            attempt["previousAcceptedSourceSha256"] == JsonPrimitive(sourceHash) &&
            attempt["failureType"] == JsonPrimitive(failure.javaClass.name)) { "SourceTree did not retain the expected revalidation failure" }
        val restored = baseline(project, profile, baselineBytes)
        accepted.forEach { (path, bytes) -> require(bytes.contentEquals(restored.getValue(path))) { "accepted baseline bytes changed: $path" } }
        retainBaseline(reports, "after", restored)
        requireClean(project, runtime)
        write(reports, "child-result.json", JsonObject(mapOf("schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("hosted-low-hard-source-tree-refusal-v1"), "profileId" to JsonPrimitive(profile.id),
            "profileSha256" to JsonPrimitive(profile.sha256), "runtimeConfigurationSha256" to JsonPrimitive(runtime.configurationSha256),
            "classpathManifestSha256" to JsonPrimitive(expectedClasspathSha256), "baselineManifestSha256" to JsonPrimitive(sha256(baselineBytes)),
            "hostPid" to JsonPrimitive(pid), "startTimeTicks" to JsonPrimitive(start), "softLimit" to JsonPrimitive(limits.softLimit),
            "hardLimit" to JsonPrimitive(limits.hardLimit), "expectedAdmissionRefusal" to JsonPrimitive(true),
            "launcherCleanupAbsenceProved" to JsonPrimitive(true), "baselineBytesPreserved" to JsonPrimitive(true),
            "reconstructionDispatched" to JsonPrimitive(false), "scratchEmpty" to JsonPrimitive(true),
            "privateRequestDirectoriesAbsent" to JsonPrimitive(true), "newAcceptedProof" to JsonPrimitive(false),
            "validationFailureAttemptSha256" to JsonPrimitive(sha256(attemptBytes)))))
    }

    private fun baseline(project: Path, profile: ReconstructionProfile, bytes: ByteArray): Map<String, ByteArray> {
        val record = support.parseObject(bytes)
        require(record.keys == setOf("entries"))
        val entries = record["entries"] as? JsonArray ?: error("baseline entries must be an array")
        require(entries.size == 3)
        val expected = setOf(profile.layout.declaration("module-implementation").materialize(mapOf("module" to "parse")),
            profile.layout.declaration("module-evidence").materialize(mapOf("module" to "parse")), "source_tree_manifest.json")
        val result = linkedMapOf<String, ByteArray>()
        entries.forEach { value ->
            val entry = value as? JsonObject ?: error("baseline entry must be an object")
            require(entry.keys == setOf("path", "bytes", "sha256"))
            val relative = support.text(entry, "path")
            require(relative in expected && relative !in result)
            val current = support.readRegular(project.resolve(relative), MAXIMUM_BASELINE_FILE_BYTES)
            require(current.size.toLong() == support.number(entry, "bytes") && sha256(current) == support.digest(entry, "sha256")) {
                "accepted baseline differs from its retained bytes: $relative"
            }
            result[relative] = current
        }
        require(result.keys == expected)
        return result
    }

    private fun retainBaseline(reports: Path, phase: String, baseline: Map<String, ByteArray>) {
        val destination = Files.createDirectory(reports.resolve("baseline-$phase"))
        baseline.toSortedMap().forEach { (relative, bytes) ->
            val target = destination.resolve(relative)
            Files.createDirectories(target.parent)
            Files.write(target, bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        }
    }

    private fun requireClean(project: Path, runtime: ContainedModuleCompilationRuntimeConfiguration) {
        require(Files.newDirectoryStream(runtime.scratchMount).use { !it.iterator().hasNext() }) { "module scratch is not empty" }
        require(Files.newDirectoryStream(project).use { entries ->
            entries.none { it.fileName.toString().startsWith(".module-compilation-") }
        }) { "private module request directories remain" }
    }

    private fun readProc(path: Path): ByteArray = Files.newInputStream(path).use { it.readNBytes(64 * 1024 + 1) }.also {
        require(it.size in 1..64 * 1024) { "kernel observation exceeds its bound" }
    }

    private fun startTime(bytes: ByteArray, pid: Long): Long {
        val text = bytes.toString(Charsets.UTF_8).trimEnd('\n')
        require(text.startsWith("$pid (") && text.lastIndexOf(") ") > 0)
        val fields = text.substring(text.lastIndexOf(") ") + 2).split(' ')
        require(fields.size >= 20)
        return fields[19].toLong().also { require(it > 0) }
    }

    private fun failureChain(failure: Throwable): List<Throwable> {
        val chain = ArrayList<Throwable>()
        val seen = IdentityHashMap<Throwable, Boolean>()
        var current: Throwable? = failure
        while (current != null) {
            val next = current
            require(chain.size < 16 && seen.put(next, true) == null) { "failure chain exceeds its finite bound" }
            chain += next
            current = next.cause
        }
        return chain
    }

    private fun failureRecord(failure: Throwable): JsonObject = JsonObject(mapOf("schemaVersion" to JsonPrimitive(1),
        "provider" to JsonPrimitive("hosted-child-actual-failure-chain-v1"), "chain" to JsonArray(failureChain(failure).map { item ->
            val message = item.message.orEmpty().also { require(it.toByteArray().size <= 16 * 1024) }
            require(item.suppressed.size <= 16 && item.stackTrace.size <= 256)
            JsonObject(mapOf("type" to JsonPrimitive(item.javaClass.name), "message" to JsonPrimitive(message),
                "suppressedTypes" to JsonArray(item.suppressed.map { JsonPrimitive(it.javaClass.name) }),
                "stack" to JsonArray(item.stackTrace.map { JsonPrimitive(it.toString()) })))
        })))

    private fun write(reports: Path, name: String, value: JsonObject) = writeBytes(reports, name, OracleJson.canonicalBytes(value))
    private fun writeBytes(reports: Path, name: String, bytes: ByteArray) {
        require(bytes.size <= MAXIMUM_REPORT_BYTES)
        Files.write(reports.resolve(name), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
    }
}
