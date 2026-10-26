package decompengine.project

import decompengine.binary.ElfMetadataReader
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.OracleNativeLibraries
import java.io.File
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Properties
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import java.util.zip.ZipFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

/** Local descriptor diagnosis only. No keeper receipt, authenticated runtime or acceptance permit. */
class ContainedModuleCompilerDescriptorBudgetTest {
    @Test
    fun `four nonempty inputs compile with child nofile 512`(): Unit {
        runCase("four-inputs-512", modules = 1, limit = 512, expectDescriptorRefusal = false)
    }

    @Test
    fun `complete 514 input closure refuses descriptor exhaustion with child nofile 512`(): Unit {
        runCase("514-inputs-512", modules = 256, limit = 512, expectDescriptorRefusal = true)
    }

    @Test
    fun `identical complete 514 input closure compiles with child nofile 4096`(): Unit {
        runCase("514-inputs-4096", modules = 256, limit = 4096, expectDescriptorRefusal = false)
    }

    @Test
    fun `complete 4096 input closure compiles with child nofile 7678 and rejects 4097 inputs`(): Unit {
        val retained = RetainedRuntime(
            manifestSha256 = requireNotNull(System.getProperty("decompengine.moduleCompiler.fdDiagnosticManifestSha256")),
            compilerRecord = Path.of(requireNotNull(System.getProperty("decompengine.moduleCompiler.fdDiagnosticCompilerRecord"))),
            compilerRecordSha256 = requireNotNull(System.getProperty("decompengine.moduleCompiler.fdDiagnosticCompilerRecordSha256")),
            currentApplicationJar = Path.of(requireNotNull(System.getProperty("decompengine.moduleCompiler.fdDiagnosticCurrentApplicationJar"))),
        )
        require(retained.manifestSha256 == RETAINED_MANIFEST_SHA256 && retained.compilerRecordSha256 == RETAINED_COMPILER_RECORD_SHA256)
        runCase("4096-inputs-7678", modules = 2047, limit = 7678, expectDescriptorRefusal = false, retained = retained)
    }

    private fun runCase(name: String, modules: Int, limit: Int, expectDescriptorRefusal: Boolean, retained: RetainedRuntime? = null) {
        val repository = Path.of("").toRealPath()
        val sourceSha = requireNotNull(System.getProperty("decompengine.moduleCompiler.fdDiagnosticSourceSha"))
        require(sourceSha == "a46d25423c72ead7dc68db8ad473fddb90c8e576") { "diagnostic requires the reviewed production source" }
        val parent = repository.resolve("build/module-compiler-fd-diagnostic")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "$name-").toRealPath()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        val content = contents(modules)
        val snapshot = Files.createDirectory(root.resolve("snapshot"))
        val output = Files.createDirectory(root.resolve("output"))
        val inputs = content.toSortedMap().map { (relative, bytes) ->
            val path = snapshot.resolve(relative)
            Files.createDirectories(path.parent)
            Files.write(path, bytes, StandardOpenOption.CREATE_NEW)
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
            ContainedModuleCompilerInput(relative, sha256(bytes), bytes.size.toLong())
        }
        assertEquals(2 * modules + 2, inputs.size)
        assertTrue(inputs.all { it.bytes > 0 })
        if (modules == 256) assertTrue(inputs.indexOfFirst { it.path == "src/modules/m0255_internal.h" } >= 512)
        if (retained != null) {
            require(modules == 2047 && limit == 7678 && !expectDescriptorRefusal)
            assertEquals(4096, inputs.size)
            assertEquals("src/modules/m2046_internal.h", inputs.last().path)
            val maximumParentComponents = inputs.maxOf { snapshot.resolve(it.path).parent.nameCount }
            require(maximumParentComponents <= 12) { "4096-input diagnostic must retain the reviewed flat parent depth" }
            writeJson(root.resolve("input-depth.json"), JsonObject(mapOf("maximumParentComponents" to JsonPrimitive(maximumParentComponents),
                "maximumAllowedParentComponents" to JsonPrimitive(12))))
        }
        val compiler = if (retained == null) stageCompiler(root) else reuseCompiler(root, repository, retained)
        val profile = GeneratedCMakeReconstructionProfile.descriptor
        val request = ContainedModuleCompilerRequest("a".repeat(64), profile.id, profile.sha256, snapshot,
            "src/modules/m0000.c", inputs, compiler, digest(compiler, MAXIMUM_RUNTIME_BYTES), output,
            maximumWallMillis = 30_000, maximumOutputBytes = 65_536,
            profileRecord = OracleJson.parse(profile.canonicalJson().toByteArray()) as JsonObject)
        val requestFile = root.resolve("request.json")
        Files.write(requestFile, request.canonicalBytes, StandardOpenOption.CREATE_NEW)
        Files.setPosixFilePermissions(requestFile, PosixFilePermissions.fromString("r--------"))
        val inventory = JsonObject(mapOf("provider" to JsonPrimitive("module-compiler-snapshot-v1"),
            "files" to JsonArray(inputs.map { it.json() })))
        writeJson(root.resolve("input-manifest.json"), inventory)
        assertEquals(request.snapshotSha256, sha256(OracleJson.canonicalBytes(inventory)))
        if (modules == 256) assertEquals("f8cac9de042d25033827c1435f91c7d550ccf78f76d836bc0e03e3cf1f29ee6e", request.snapshotSha256,
            "both 514-input cases must use the same frozen complete bytes")
        if (retained != null) reject4097Inputs(root, request)
        val runtime = runtime(root, repository, retained)
        val temporary = Files.createDirectory(root.resolve("tmp"))
        val diagnostic = root.resolve("worker-startup.json")
        val inherited = readBounded(Path.of("/proc/self/limits"), 8192)
        Files.write(root.resolve("parent-limits.txt"), inherited, StandardOpenOption.CREATE_NEW)
        val inheritedLimits = nofile(inherited.decodeToString())
        if (retained == null) {
            require(limit.toLong() <= inheritedLimits.first && limit.toLong() <= inheritedLimits.second) {
                "diagnostic may only lower its inherited open-file limits"
            }
        } else {
            require(inheritedLimits.second >= 7678) { "4096-input diagnostic requires an existing hard limit of at least 7678" }
        }
        val java = Path.of(System.getProperty("java.home"), "bin/java").toRealPath()
        val javaHash = digest(java, MAXIMUM_RUNTIME_BYTES)
        val limiter = Path.of("/usr/bin/prlimit").toRealPath()
        val limiterHash = digest(limiter, MAXIMUM_RUNTIME_BYTES)
        val arguments = listOf(limiter.toString(), "--nofile=$limit:$limit", "--") +
            listOf(java.toString(), "-Xms16m", "-Xmx128m", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1",
                "-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-XX:MaxMetaspaceSize=96m", "-XX:ReservedCodeCacheSize=32m") +
            OracleNativeLibraries.jvmArguments(runtime.native) + listOf("-Djna.tmpdir=$temporary", "-Djava.io.tmpdir=$temporary",
                "-Duser.home=$temporary", "-classpath", runtime.classpath.joinToString(File.pathSeparator),
                WRAPPER_CLASS, requestFile.toString(), request.sha256, diagnostic.toString())
        writeJson(root.resolve("command.json"), JsonObject(mapOf("sourceSha" to JsonPrimitive(sourceSha),
            "scope" to JsonPrimitive("test-only-passive-worker-descriptor-diagnosis"),
            "arguments" to JsonArray(arguments.map(::JsonPrimitive)), "requestSha256" to JsonPrimitive(request.sha256),
            "snapshotSha256" to JsonPrimitive(request.snapshotSha256), "javaSha256" to JsonPrimitive(javaHash),
            "resourceLimiterSha256" to JsonPrimitive(limiterHash),
            "parentLimitsSha256" to JsonPrimitive(sha256(inherited)),
            "environment" to JsonObject(mapOf("TMPDIR" to JsonPrimitive(temporary.toString()))))))
        val execution = execute(arguments, root, temporary, 40, MAXIMUM_CAPTURE_BYTES, "worker")
        val startupBytes = readBounded(diagnostic, 32 * 1024)
        val startup = OracleJson.parse(startupBytes) as JsonObject
        assertEquals(execution.pid, startup.getValue("pid").jsonPrimitive.long)
        assertTrue(startup.getValue("startTimeTicks").jsonPrimitive.long > 0)
        val observed = startup.getValue("softNofile").jsonPrimitive.long to startup.getValue("hardNofile").jsonPrimitive.long
        assertEquals(limit.toLong() to limit.toLong(), observed)
        assertEquals(sha256(startup.getValue("limits").jsonPrimitive.content.toByteArray()), startup.getValue("limitsSha256").jsonPrimitive.content)
        assertEquals(sha256(startup.getValue("stat").jsonPrimitive.content.toByteArray()), startup.getValue("statSha256").jsonPrimitive.content)
        verifyInventory(snapshot, inputs)
        assertEquals(request.sha256, sha256(readBounded(requestFile, ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES)))
        runtime.recheck()
        assertEquals(javaHash, digest(java, MAXIMUM_RUNTIME_BYTES))
        assertEquals(limiterHash, digest(limiter, MAXIMUM_RUNTIME_BYTES))
        val compilerFiles = OracleJson.parse(readBounded(root.resolve("compiler-files.json"), 16 * 1024)) as JsonObject
        (compilerFiles.getValue("files") as JsonArray).forEach { value ->
            val file = value as JsonObject
            val path = Path.of(file.getValue("path").jsonPrimitive.content)
            assertEquals(file.getValue("bytes").jsonPrimitive.long, Files.size(path))
            assertEquals(file.getValue("sha256").jsonPrimitive.content, digest(path, MAXIMUM_RUNTIME_BYTES))
        }
        assertEquals(request.compilerSha256, digest(compiler, MAXIMUM_RUNTIME_BYTES))
        if (expectDescriptorRefusal) {
            assertTrue(execution.exitCode != 0, "descriptor-exhausted worker unexpectedly succeeded: $root")
            assertTrue(execution.stdout.isEmpty(), "descriptor refusal emitted a passive result: $root")
            val error = execution.stderr.decodeToString()
            assertTrue(error.contains("PinnedCompilerInput") && error.contains("StableControlFile") &&
                (error.contains("errno 24") || error.contains("Too many open files")),
                "failure was not input-pinning descriptor exhaustion: $root\n$error")
            assertFalse(Files.exists(output.resolve("module.o")))
        } else {
            assertEquals(0, execution.exitCode, "$root\n${execution.stderr.decodeToString()}")
            assertTrue(execution.stderr.isEmpty(), "$root\n${execution.stderr.decodeToString()}")
            val result = ContainedModuleCompilerResult.parse(execution.stdout)
            result.requireBinding(request)
            assertEquals("compiled-object", result.outcome)
            assertEquals(0, result.exitCode)
            assertEquals(null, result.signal)
            val objectBytes = readBounded(output.resolve("module.o"), ContainedModuleCompilerRequest.MAXIMUM_OBJECT_BYTES.toInt())
            assertEquals(result.objectBytes, objectBytes.size.toLong())
            assertEquals(result.objectSha256, sha256(objectBytes))
            assertEquals("relocatable", ElfMetadataReader.read(objectBytes).objectType)
            for ((path, size, hash) in listOf(Triple("compiler.stdout", result.stdoutBytes, result.stdoutSha256),
                Triple("compiler.stderr", result.stderrBytes, result.stderrSha256))) {
                val bytes = readBounded(output.resolve(path), 65_536)
                assertEquals(size, bytes.size.toLong()); assertEquals(hash, sha256(bytes))
            }
        }
        writeJson(root.resolve("verification.json"), JsonObject(mapOf("sourceSha" to JsonPrimitive(sourceSha),
            "status" to JsonPrimitive("passed"), "case" to JsonPrimitive(name), "inputCount" to JsonPrimitive(inputs.size),
            "snapshotSha256" to JsonPrimitive(request.snapshotSha256), "requestSha256" to JsonPrimitive(request.sha256),
            "startupSha256" to JsonPrimitive(sha256(startupBytes)), "workerExitCode" to JsonPrimitive(execution.exitCode),
            "workerReaped" to JsonPrimitive(true), "productionQualified" to JsonPrimitive(false))))
    }

    private fun contents(modules: Int): Map<String, ByteArray> {
        require(modules == 1 || modules == 256 || modules == 2047)
        val result = linkedMapOf("include/decomp_types.h" to "/* shared diagnostic interface */\n")
        val source = StringBuilder("#include \"decomp_types.h\"\n")
        for (index in 0 until modules) {
            val module = "m" + index.toString().padStart(4, '0')
            result["include/modules/$module.h"] = "int $module(void);\n"
            result["src/modules/${module}_internal.h"] = "#define VALUE_$module ${index + 1}\n"
            source.append("#include \"modules/$module.h\"\n#include \"${module}_internal.h\"\n")
        }
        source.append("int m0000(void) { return VALUE_m${(modules - 1).toString().padStart(4, '0')}; }\n")
        result["src/modules/m0000.c"] = source.toString()
        return result.mapValues { it.value.toByteArray() }
    }

    private fun reject4097Inputs(root: Path, request: ContainedModuleCompilerRequest) {
        assertEquals(4096, request.inputs.size)
        val extraPath = "include/modules/m2047.h"
        val extraBytes = "int m2047(void);\n".toByteArray()
        assertEquals("module-interface", request.profile.layout.declarationForPath(extraPath).id)
        assertFalse(request.inputs.any { it.path == extraPath })
        // Preserve the legal extra header separately; it must never enter the launched 4096-file snapshot.
        val rejectedRoot = Files.createDirectory(root.resolve("rejected-4097"))
        val extraFile = rejectedRoot.resolve(extraPath)
        Files.createDirectories(extraFile.parent)
        Files.write(extraFile, extraBytes, StandardOpenOption.CREATE_NEW)
        val oversized = (request.inputs + ContainedModuleCompilerInput(extraPath, sha256(extraBytes), extraBytes.size.toLong())).sortedBy { it.path }
        assertEquals(4097, oversized.size)
        val inventory = JsonObject(mapOf("provider" to JsonPrimitive("module-compiler-snapshot-v1"),
            "files" to JsonArray(oversized.map { it.json() })))
        val inventoryBytes = OracleJson.canonicalBytes(inventory)
        val snapshotHash = sha256(inventoryBytes)
        Files.write(rejectedRoot.resolve("input-manifest.json"), inventoryBytes, StandardOpenOption.CREATE_NEW)
        val original = OracleJson.parseCanonical(request.canonicalBytes) as JsonObject
        val record = JsonObject(original + mapOf("inputs" to JsonArray(oversized.map { it.json() }),
            "snapshotSha256" to JsonPrimitive(snapshotHash)))
        val recordBytes = OracleJson.canonicalBytes(record)
        require(recordBytes.size <= ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES)
        require(oversized.sumOf { it.bytes } <= ContainedModuleCompilerRequest.MAXIMUM_TOTAL_INPUT_BYTES)
        Files.write(rejectedRoot.resolve("request.json"), recordBytes, StandardOpenOption.CREATE_NEW)
        val constructorFailure = assertFailsWith<IllegalArgumentException> {
            ContainedModuleCompilerRequest(request.nonce, request.profileId, request.profileSha256, request.snapshotRoot,
                request.sourcePath, oversized, request.compilerPath, request.compilerSha256, request.outputDirectory,
                request.maximumWallMillis, request.maximumOutputBytes,
                profileRecord = OracleJson.parse(request.profile.canonicalJson().toByteArray()) as JsonObject)
        }
        val parserFailure = assertFailsWith<IllegalArgumentException> { ContainedModuleCompilerRequest.parse(recordBytes) }
        val expected = "module compiler snapshot count exceeds its bound"
        assertEquals(expected, constructorFailure.message)
        assertEquals(expected, parserFailure.message)
        assertFalse(Files.exists(root.resolve("worker-startup.json")))
        assertFalse(Files.exists(request.snapshotRoot.resolve(extraPath)))
        verifyInventory(request.snapshotRoot, request.inputs)
        writeJson(rejectedRoot.resolve("admission-rejection.json"), JsonObject(mapOf("inputCount" to JsonPrimitive(oversized.size),
            "snapshotSha256" to JsonPrimitive(snapshotHash), "requestSha256" to JsonPrimitive(sha256(recordBytes)),
            "extraHeaderPath" to JsonPrimitive(extraPath), "extraHeaderSha256" to JsonPrimitive(sha256(extraBytes)),
            "constructorFailure" to JsonPrimitive(checkNotNull(constructorFailure.message)),
            "parserFailure" to JsonPrimitive(checkNotNull(parserFailure.message)), "beforeWorkerLaunch" to JsonPrimitive(true))))
    }

    private data class Runtime(val native: Path, val classpath: List<Path>, val files: Map<Path, String>) {
        fun recheck() { files.forEach { (path, hash) -> assertEquals(hash, digest(path, MAXIMUM_RUNTIME_BYTES), "$path changed") } }
    }

    private data class RetainedRuntime(val manifestSha256: String, val compilerRecord: Path,
        val compilerRecordSha256: String, val currentApplicationJar: Path)

    private fun runtime(root: Path, repository: Path, retained: RetainedRuntime? = null): Runtime {
        val manifest = Path.of(requireNotNull(System.getProperty("decompengine.moduleCompiler.fdDiagnosticManifest"))).toRealPath()
        require(manifest == repository.resolve("build/module-compilation-qualification/worker-classpath.json"))
        val manifestBytes = readBounded(manifest, 64 * 1024)
        if (retained != null) assertEquals(retained.manifestSha256, sha256(manifestBytes))
        val record = OracleJson.parse(manifestBytes) as JsonObject
        require(record.keys == setOf("schemaVersion", "entries") && record["schemaVersion"] == JsonPrimitive(1))
        val entries = record.getValue("entries") as JsonArray
        require(entries.size in 6..9)
        if (retained != null) assertEquals(7, entries.size)
        var total = 0L
        val files = linkedMapOf<Path, String>()
        val classpath = entries.mapIndexed { index, element ->
            val entry = element as JsonObject
            require(entry.keys == setOf("path", "bytes", "sha256"))
            val path = Path.of(entry.getValue("path").jsonPrimitive.content)
            require(path.toRealPath() == path && path.parent == manifest.parent.resolve("deployment") &&
                path.fileName.toString().startsWith(index.toString().padStart(3, '0') + "-") && path.toString().endsWith(".jar"))
            val bytes = entry.getValue("bytes").jsonPrimitive.long
            require(bytes in 1..MAXIMUM_RUNTIME_BYTES && Files.size(path) == bytes)
            total = Math.addExact(total, bytes); require(total <= MAXIMUM_RUNTIME_BYTES)
            val hash = entry.getValue("sha256").jsonPrimitive.content
            require(hash.matches(Regex("[0-9a-f]{64}")) && digest(path, MAXIMUM_RUNTIME_BYTES) == hash)
            require(files.put(path, hash) == null)
            path
        }
        // The staged application JAR must contain the actual freshly compiled worker, not a substitute.
        val workerResource = "decompengine/project/ContainedModuleCompilerWorker.class"
        val compiledWorker = readBounded(repository.resolve("build/classes/kotlin/main/$workerResource"), 1024 * 1024)
        ZipFile(classpath.first().toFile()).use { jar ->
            val entry = requireNotNull(jar.getEntry(workerResource))
            val bytes = jar.getInputStream(entry).use { readBounded(it, 1024 * 1024) }
            require(bytes.contentEquals(compiledWorker)) { "deployment worker differs from compiled source" }
        }
        if (retained != null) {
            val current = retained.currentApplicationJar
            require(current.toRealPath() == current && current.parent == repository.resolve("build/libs") &&
                current.fileName.toString().endsWith(".jar")) { "current application must be the normal build JAR" }
            val oldClasses = applicationClasses(classpath.first())
            val currentClasses = applicationClasses(current)
            assertTrue(oldClasses == currentClasses, "retained application class payloads differ from the current normal build")
            val currentHash = digest(current, MAXIMUM_RUNTIME_BYTES)
            files[current] = currentHash
            writeJson(root.resolve("application-class-equivalence.json"), JsonObject(mapOf(
                "retainedApplicationSha256" to JsonPrimitive(files.getValue(classpath.first())),
                "currentApplicationSha256" to JsonPrimitive(currentHash), "classCount" to JsonPrimitive(oldClasses.size),
                "classes" to JsonArray(oldClasses.map { (path, hash) -> JsonObject(mapOf("path" to JsonPrimitive(path),
                    "sha256" to JsonPrimitive(hash))) }))))
        }
        val wrapperPath = WRAPPER_CLASS.replace('.', '/') + ".class"
        val wrapper = readBounded(repository.resolve("build/classes/java/test/$wrapperPath"), 64 * 1024)
        if (retained != null) assertEquals(RETAINED_WRAPPER_SHA256, sha256(wrapper))
        val wrapperRoot = Files.createDirectory(root.resolve("wrapper"))
        val copied = wrapperRoot.resolve(wrapperPath)
        Files.createDirectories(copied.parent)
        Files.write(copied, wrapper, StandardOpenOption.CREATE_NEW)
        files[copied] = sha256(wrapper)
        val native = Path.of(requireNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory"))).toRealPath()
        require(native == repository.resolve("build/native/oracle"))
        val policy = Properties().apply { Files.newInputStream(repository.resolve("src/main/resources/oracle-native-libraries-v1.properties")).use(::load) }
        for (name in listOf("jna", "sqlite")) {
            val path = native.resolve(policy.getProperty("$name.name"))
            require(Files.size(path) == policy.getProperty("$name.bytes").toLong())
            val hash = policy.getProperty("$name.sha256")
            require(digest(path, MAXIMUM_RUNTIME_BYTES) == hash)
            files[path] = hash
        }
        files[manifest] = sha256(manifestBytes)
        Files.write(root.resolve("worker-classpath.json"), manifestBytes, StandardOpenOption.CREATE_NEW)
        writeJson(root.resolve("runtime-files.json"), JsonObject(mapOf("workerClassSha256" to JsonPrimitive(sha256(compiledWorker)),
            "files" to JsonArray(files.map { (path, hash) -> JsonObject(mapOf("path" to JsonPrimitive(path.toString()),
                "sha256" to JsonPrimitive(hash), "bytes" to JsonPrimitive(Files.size(path)))) }))))
        return Runtime(native, classpath + listOf(wrapperRoot), files)
    }

    private fun stageCompiler(root: Path): Path {
        val driver = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
        val tools = Files.createDirectory(root.resolve("toolchain"))
        val temporary = Files.createDirectory(root.resolve("probe-tmp"))
        val selected = linkedMapOf("compiler" to driver)
        for (name in listOf("cc1", "as")) {
            val result = execute(listOf(driver.toString(), "-print-prog-name=$name"), root, temporary, 5, 4096, "probe-$name")
            assertEquals(0, result.exitCode, result.stderr.decodeToString())
            assertTrue(result.stderr.isEmpty())
            val text = result.stdout.decodeToString().trim()
            require(text.length in 1..4096 && '\n' !in text)
            selected[name] = Path.of(text).let { if (it.isAbsolute) it else Path.of("/usr/bin", text) }.toRealPath()
        }
        val records = selected.map { (name, source) ->
            val hash = digest(source, MAXIMUM_RUNTIME_BYTES)
            val destination = Files.copy(source, tools.resolve(name), StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r-x------"))
            assertEquals(hash, digest(destination, MAXIMUM_RUNTIME_BYTES))
            JsonObject(mapOf("source" to JsonPrimitive(source.toString()), "path" to JsonPrimitive(destination.toString()),
                "sha256" to JsonPrimitive(hash), "bytes" to JsonPrimitive(Files.size(destination))))
        }
        writeJson(root.resolve("compiler-files.json"), JsonObject(mapOf("files" to JsonArray(records))))
        return tools.resolve("compiler")
    }

    private fun reuseCompiler(root: Path, repository: Path, retained: RetainedRuntime): Path {
        val recordPath = retained.compilerRecord
        require(recordPath.toRealPath() == recordPath && recordPath.startsWith(repository.resolve("build/module-compiler-fd-diagnostic")) &&
            recordPath.fileName.toString() == "compiler-files.json")
        val bytes = readBounded(recordPath, 16 * 1024)
        assertEquals(retained.compilerRecordSha256, sha256(bytes))
        val record = OracleJson.parseCanonical(bytes) as JsonObject
        require(record.keys == setOf("files"))
        val entries = record.getValue("files") as JsonArray
        require(entries.size == 3)
        val paths = entries.map { value ->
            val entry = value as JsonObject
            require(entry.keys == setOf("source", "path", "sha256", "bytes"))
            val path = Path.of(entry.getValue("path").jsonPrimitive.content)
            require(path.toRealPath() == path && path.parent == recordPath.parent.resolve("toolchain") && Files.isExecutable(path))
            assertEquals(entry.getValue("bytes").jsonPrimitive.long, Files.size(path))
            assertEquals(entry.getValue("sha256").jsonPrimitive.content, digest(path, MAXIMUM_RUNTIME_BYTES))
            path
        }
        assertEquals(setOf("compiler", "cc1", "as"), paths.map { it.fileName.toString() }.toSet())
        Files.write(root.resolve("compiler-files.json"), bytes, StandardOpenOption.CREATE_NEW)
        writeJson(root.resolve("compiler-reuse.json"), JsonObject(mapOf("priorRecordPath" to JsonPrimitive(recordPath.toString()),
            "priorRecordSha256" to JsonPrimitive(sha256(bytes)), "hostRestaging" to JsonPrimitive(false), "discoveryProbes" to JsonPrimitive(false))))
        return paths.single { it.fileName.toString() == "compiler" }
    }

    private fun applicationClasses(path: Path): Map<String, String> {
        require(Files.size(path) in 1..MAXIMUM_RUNTIME_BYTES)
        val classes = sortedMapOf<String, String>()
        var total = 0L
        var entriesSeen = 0
        ZipFile(path.toFile()).use { jar ->
            val entries = jar.entries()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                require(++entriesSeen <= 100_000)
                if (entry.isDirectory || !entry.name.endsWith(".class")) continue
                require(entry.size in 1..16L * 1024 * 1024 && entry.name.length <= 4096)
                total = Math.addExact(total, entry.size); require(total <= MAXIMUM_RUNTIME_BYTES)
                val bytes = jar.getInputStream(entry).use { readBounded(it, 16 * 1024 * 1024) }
                assertEquals(entry.size, bytes.size.toLong())
                require(classes.put(entry.name, sha256(bytes)) == null) { "duplicate application class payload" }
            }
        }
        require(classes.isNotEmpty())
        return classes
    }

    private data class Execution(val pid: Long, val exitCode: Int, val stdout: ByteArray, val stderr: ByteArray)

    private fun execute(arguments: List<String>, root: Path, temporary: Path, seconds: Long, maximum: Int, prefix: String): Execution {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(seconds)
        fun remaining(until: Long): Long = (until - System.nanoTime()).coerceAtLeast(0)
        val process = ProcessBuilder(arguments).directory(root.toFile()).apply {
            environment().clear(); environment()["TMPDIR"] = temporary.toString()
        }.start()
        val failure = AtomicReference<Throwable?>()
        fun drain(stream: InputStream, path: Path): Thread = Thread.ofVirtual().start {
            try {
                stream.use { input -> Files.newOutputStream(path, StandardOpenOption.CREATE_NEW).use { output ->
                    val buffer = ByteArray(4096)
                    var retained = 0
                    while (true) {
                        val count = input.read(buffer)
                        if (count < 0) break
                        val accepted = minOf(count, maximum - retained)
                        if (accepted > 0) output.write(buffer, 0, accepted)
                        retained += accepted
                        if (accepted != count) failure.compareAndSet(null, IllegalStateException("$prefix output exceeds $maximum bytes"))
                    }
                } }
            } catch (problem: Throwable) {
                failure.compareAndSet(null, problem)
            }
        }
        val stdout = root.resolve("$prefix.stdout")
        val stderr = root.resolve("$prefix.stderr")
        val readers = mutableListOf<Thread>()
        var completed = false
        var primaryFailure: Throwable? = null
        try {
            process.outputStream.close()
            readers += drain(process.inputStream, stdout)
            readers += drain(process.errorStream, stderr)
            completed = process.waitFor(remaining(deadline), TimeUnit.NANOSECONDS)
            check(completed) { "$prefix exceeded $seconds seconds: $root" }
            readers.forEach { reader ->
                val nanos = remaining(deadline)
                if (nanos > 0) TimeUnit.NANOSECONDS.timedJoin(reader, nanos)
                check(!reader.isAlive) { "$prefix capture did not terminate within $seconds seconds" }
            }
            failure.get()?.let { throw it }
            check(!process.isAlive)
            return Execution(process.pid(), process.exitValue(), readBounded(stdout, maximum), readBounded(stderr, maximum))
        } catch (problem: Throwable) {
            primaryFailure = problem
            throw problem
        } finally {
            val cleanupDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            var interrupted = Thread.interrupted() || primaryFailure is InterruptedException
            var cleanupFailure: Throwable? = null
            fun clean(action: () -> Unit) {
                try { action() } catch (problem: Throwable) {
                    interrupted = Thread.interrupted() || interrupted || problem is InterruptedException
                    val prior = cleanupFailure
                    if (prior == null) cleanupFailure = problem else if (prior !== problem) prior.addSuppressed(problem)
                }
            }
            if (process.isAlive) {
                clean { process.descendants().use { children -> children.forEach { it.destroyForcibly() } } }
                clean { process.destroyForcibly() }
                clean { process.waitFor(remaining(cleanupDeadline), TimeUnit.NANOSECONDS) }
            }
            clean { process.outputStream.close() }
            clean { process.inputStream.close() }; clean { process.errorStream.close() }
            readers.forEach { reader -> clean {
                val nanos = remaining(cleanupDeadline)
                if (nanos > 0) TimeUnit.NANOSECONDS.timedJoin(reader, nanos)
            } }
            clean { check(!process.isAlive && readers.none { it.isAlive }) { "$prefix test process cleanup incomplete" } }
            clean { writeJson(root.resolve("$prefix-process.json"), JsonObject(mapOf("pid" to JsonPrimitive(process.pid()),
                "completedWithinBound" to JsonPrimitive(completed), "reaped" to JsonPrimitive(!process.isAlive),
                "captureThreadsTerminated" to JsonPrimitive(readers.none { it.isAlive })) )) }
            if (interrupted) Thread.currentThread().interrupt()
            cleanupFailure?.let { problem ->
                val prior = primaryFailure
                if (prior == null) throw problem else if (prior !== problem) prior.addSuppressed(problem)
            }
        }
    }

    private fun verifyInventory(root: Path, inputs: List<ContainedModuleCompilerInput>) {
        val actual = Files.walk(root).use { paths -> paths.filter { !Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
            .map { root.relativize(it).toString() }.toList().sorted() }
        assertEquals(inputs.map { it.path }, actual)
        inputs.forEach { input ->
            val path = root.resolve(input.path)
            assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
            assertEquals(input.bytes, Files.size(path)); assertEquals(input.sha256, digest(path, 16L * 1024 * 1024))
        }
    }

    private fun nofile(text: String): Pair<Long, Long> {
        val values = text.lineSequence().single { it.startsWith("Max open files ") }.removePrefix("Max open files").trim().split(Regex("\\s+"))
        require(values.size == 3 && values[2] == "files")
        return values[0].toLong() to values[1].toLong()
    }

    private companion object {
        const val WRAPPER_CLASS = "decompengine.project.ModuleCompilerFdDiagnosticMain"
        const val MAXIMUM_RUNTIME_BYTES = 256L * 1024 * 1024
        const val MAXIMUM_CAPTURE_BYTES = 64 * 1024
        const val RETAINED_MANIFEST_SHA256 = "0c8a736222d0684bb7d7a129142b068a2f665e8dfe7c54d08aafb280fea1bf05"
        const val RETAINED_COMPILER_RECORD_SHA256 = "b09977238f909c23cf0c1b866970316b1ce2fee60e68345817c137ee55dd34b0"
        const val RETAINED_WRAPPER_SHA256 = "f4c79763aa93b88fd3875939816f36d1e30e186b9340b98af148170e1355bc95"

        fun readBounded(path: Path, maximum: Int): ByteArray = Files.newInputStream(path).use { readBounded(it, maximum) }
        fun readBounded(input: InputStream, maximum: Int): ByteArray = input.readNBytes(maximum + 1).also {
            require(it.size <= maximum) { "diagnostic input exceeds $maximum bytes" }
        }
        fun digest(path: Path, maximum: Long): String {
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) && Files.size(path) in 0..maximum)
            val hash = MessageDigest.getInstance("SHA-256")
            Files.newInputStream(path).use { input ->
                val buffer = ByteArray(65_536)
                var size = 0L
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    size += count; require(size <= maximum)
                    hash.update(buffer, 0, count)
                }
            }
            return hash.digest().joinToString("") { "%02x".format(it) }
        }
        fun writeJson(path: Path, record: JsonObject) {
            Files.write(path, OracleJson.canonicalBytes(record), StandardOpenOption.CREATE_NEW)
        }
    }
}
