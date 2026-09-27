package decompengine.validation

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal data class BehaviorSandboxRuntimeMount(val source: Path, val destination: Path)

internal data class CapturedBehaviorRuntimeClosure(
    val record: JsonObject,
    val mounts: List<BehaviorSandboxRuntimeMount>,
)

/** Resolves and stages the exact ELF interpreter/shared-object set visible to a behavior binary. */
internal object BehaviorRuntimeClosureCapture {
    private data class RuntimeFile(
        val path: Path,
        val identity: JsonObject,
        val metadata: BehaviorElfRuntimeMetadata,
    )

    private data class LibraryCandidate(val path: Path)

    private data class ResolverListing(
        val resolver: Path,
        val resolverIdentity: JsonObject,
        val cache: Path,
        val cacheIdentity: JsonObject,
        val bytes: ByteArray,
        val libraries: Map<String, List<LibraryCandidate>>,
    )

    fun capture(
        evidence: BehaviorEvidenceCapture,
        binaries: List<Pair<Path, JsonObject>>,
        stagingDirectory: Path,
    ): CapturedBehaviorRuntimeClosure {
        require(binaries.size == 2) { "behavior runtime closure requires one original and one rebuilt executable" }
        val executableMetadata = binaries.map { (path, identity) ->
            BehaviorElfRuntimeMetadataReader.read(evidence.bytes(path, identity))
        }
        val primary = executableMetadata.first()
        require(executableMetadata.all { it.interpreter != null || it.neededLibraries.isEmpty() }) {
            "behavior executable needs shared libraries but has no retained ELF interpreter"
        }
        require(executableMetadata.all {
            it.machine == primary.machine && it.elfClass == primary.elfClass && it.byteOrder == primary.byteOrder &&
                it.osAbi == primary.osAbi && it.abiFlags == primary.abiFlags
        }) { "original and rebuilt ELF executables do not share one target ABI" }

        val sourceFiles = linkedMapOf<Path, RuntimeFile>()
        fun sourceFile(candidate: Path, expected: RuntimeFile? = null): RuntimeFile {
            val realPath = candidate.toRealPath().toAbsolutePath().normalize()
            sourceFiles[realPath]?.let { existing ->
                if (expected != null) require(existing.identity == expected.identity && existing.metadata == expected.metadata) {
                    "behavior runtime file changed during dependency resolution: $realPath"
                }
                return existing
            }
            val identity = evidence.file(realPath)
            if (expected != null) require(identity == expected.identity) {
                "behavior runtime file changed during dependency resolution: $realPath"
            }
            val bytes = evidence.bytes(realPath, identity)
            val metadata = BehaviorElfRuntimeMetadataReader.read(bytes)
            if (expected != null) require(metadata == expected.metadata) {
                "behavior runtime ELF changed during dependency resolution: $realPath"
            }
            require(metadata.machine == primary.machine && metadata.elfClass == primary.elfClass &&
                metadata.byteOrder == primary.byteOrder && metadata.abiFlags == primary.abiFlags) {
                "behavior runtime file targets a different ELF ABI: $realPath"
            }
            return RuntimeFile(realPath, identity, metadata).also { sourceFiles[realPath] = it }
        }

        val interpreters = linkedMapOf<Path, RuntimeFile>()
        executableMetadata.mapNotNull { it.interpreter }.distinct().sortedBy(Path::toString).forEach { guestPath ->
            val interpreter = sourceFile(guestPath)
            require(interpreter.metadata.interpreter == null) {
                "behavior ELF interpreter unexpectedly names another ELF interpreter"
            }
            interpreters[guestPath] = interpreter
        }

        val pending = ArrayDeque<String>()
        executableMetadata.forEach { pending.addAll(it.neededLibraries) }
        interpreters.values.forEach { pending.addAll(it.metadata.neededLibraries) }
        val listing = if (pending.isEmpty()) null else resolverListing(evidence)
        val libraries = linkedMapOf<String, RuntimeFile>()
        while (pending.isNotEmpty()) {
            val name = pending.removeFirst()
            if (name in libraries) continue
            require(libraries.size < MAXIMUM_RUNTIME_LIBRARIES) {
                "behavior runtime closure exceeds its library-count bound"
            }
            val candidate = resolveLibrary(name, requireNotNull(listing), primary)
            val file = sourceFile(candidate.path, candidate)
            libraries[name] = file
            pending.addAll(file.metadata.neededLibraries)
        }

        val totalRuntimeBytes = sourceFiles.values.fold(0L) { sum, file ->
            Math.addExact(sum, file.identity.count("bytes"))
        }
        require(totalRuntimeBytes <= MAXIMUM_RUNTIME_BYTES) {
            "behavior runtime closure exceeds its aggregate byte bound"
        }
        evidence.requireCurrent()

        val interpreterStageDirectory = stagingDirectory.resolve("interpreters")
        val libraryStageDirectory = stagingDirectory.resolve("lib")
        Files.createDirectories(interpreterStageDirectory)
        Files.createDirectories(libraryStageDirectory)
        val mounts = mutableListOf<BehaviorSandboxRuntimeMount>()
        val interpreterRecords = interpreters.entries.sortedBy { it.key.toString() }.mapIndexed { index, (guestPath, file) ->
            val staged = interpreterStageDirectory.resolve("interpreter-$index")
            evidence.retainRuntimeFile(file.path, staged, file.identity)
            mounts += BehaviorSandboxRuntimeMount(staged, guestPath)
            JsonObject(mapOf(
                "guestPath" to JsonPrimitive(guestPath.toString()),
                "sourcePath" to JsonPrimitive(file.path.toString()),
                "snapshotPath" to JsonPrimitive(staged.toAbsolutePath().normalize().toString()),
                "bytes" to JsonPrimitive(file.identity.count("bytes")),
                "sha256" to JsonPrimitive(file.identity.string("sha256")),
            ))
        }
        val libraryRecords = libraries.toSortedMap().entries.toList().mapIndexed { index, (name, file) ->
            val staged = libraryStageDirectory.resolve("library-$index")
            evidence.retainRuntimeFile(file.path, staged, file.identity)
            mounts += BehaviorSandboxRuntimeMount(staged, Path.of("/runtime/lib").resolve(name))
            JsonObject(mapOf(
                "name" to JsonPrimitive(name),
                "sourcePath" to JsonPrimitive(file.path.toString()),
                "snapshotPath" to JsonPrimitive(staged.toAbsolutePath().normalize().toString()),
                "bytes" to JsonPrimitive(file.identity.count("bytes")),
                "sha256" to JsonPrimitive(file.identity.string("sha256")),
            ))
        }
        val payload = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("bounded-elf-needed-runtime-v1"),
            "elfMachine" to JsonPrimitive(primary.machine),
            "elfClass" to JsonPrimitive(primary.elfClass),
            "elfOsAbi" to JsonPrimitive(primary.osAbi),
            "elfAbiFlags" to JsonPrimitive(primary.abiFlags),
            "byteOrder" to JsonPrimitive(if (primary.byteOrder == java.nio.ByteOrder.LITTLE_ENDIAN) "little" else "big"),
            "resolver" to (listing?.let { JsonObject(it.resolverIdentity +
                ("path" to JsonPrimitive(it.resolver.toString()))) } ?: kotlinx.serialization.json.JsonNull),
            "loaderCache" to (listing?.let { JsonObject(it.cacheIdentity +
                ("path" to JsonPrimitive(it.cache.toString()))) } ?: kotlinx.serialization.json.JsonNull),
            "resolverListingBytes" to (listing?.let { JsonPrimitive(it.bytes.size) } ?: kotlinx.serialization.json.JsonNull),
            "resolverListingSha256" to (listing?.let { JsonPrimitive(OracleArtifacts.sha256(it.bytes)) } ?: kotlinx.serialization.json.JsonNull),
            "interpreters" to JsonArray(interpreterRecords),
            "libraries" to JsonArray(libraryRecords),
            "visibleSearchPath" to JsonPrimitive("/runtime/lib"),
            "hostRuntimeRootsVisible" to JsonPrimitive(false),
        ))
        val record = JsonObject(payload + ("closureSha256" to JsonPrimitive(hash(payload))))
        return CapturedBehaviorRuntimeClosure(record, mounts.sortedBy { it.destination.toString() })
    }

    private fun resolverListing(evidence: BehaviorEvidenceCapture): ResolverListing {
        val resolver = listOf("/sbin/ldconfig", "/usr/sbin/ldconfig", "/usr/bin/ldconfig")
            .asSequence().map(Path::of).firstOrNull(Files::isExecutable)
            ?.toRealPath()?.toAbsolutePath()?.normalize()
            ?: throw SandboxUnavailableException("ldconfig is required to resolve a closed behavior ELF runtime")
        val resolverIdentity = evidence.executable(resolver)
        val cache = Path.of("/etc/ld.so.cache")
        val cacheIdentity = evidence.file(cache)
        val bytes = runResolver(resolver)
        evidence.requireCurrent()
        val text = bytes.toString(Charsets.UTF_8)
        val result = linkedMapOf<String, MutableList<LibraryCandidate>>()
        val entryPattern = Regex("^([^\\s]+)\\s+\\(([^)]*)\\)\\s+=>\\s+(\\S+)$")
        var entries = 0
        text.lineSequence().forEach { rawLine ->
            val line = rawLine.trim()
            if (line.isEmpty() || line.contains("libs found in cache") || line.startsWith("Cache generated by:")) return@forEach
            val match = entryPattern.matchEntire(line)
                ?: throw IllegalArgumentException("ldconfig runtime inventory has an unsupported record")
            val name = match.groupValues[1]
            require(name.matches(SONAME_PATTERN)) { "ldconfig returned an invalid shared-object name" }
            val path = Path.of(match.groupValues[3])
            require(path.isAbsolute && path.normalize() == path) { "ldconfig returned a non-normalized library path" }
            entries = Math.addExact(entries, 1)
            require(entries <= MAXIMUM_RESOLVER_ENTRIES) { "ldconfig runtime inventory exceeds its entry bound" }
            result.getOrPut(name, ::mutableListOf).add(LibraryCandidate(path))
        }
        require(entries > 0) { "ldconfig returned an empty shared-object inventory" }
        return ResolverListing(resolver, resolverIdentity, cache, cacheIdentity, bytes,
            result.mapValues { (_, candidates) -> candidates.toList() })
    }

    private fun resolveLibrary(
        name: String,
        listing: ResolverListing,
        required: BehaviorElfRuntimeMetadata,
    ): RuntimeFile {
        val candidates = listing.libraries[name]
            ?: throw IllegalArgumentException("behavior ELF shared object is missing from ldconfig: $name")
        for (candidate in candidates) {
            val realPath = runCatching { candidate.path.toRealPath().toAbsolutePath().normalize() }.getOrNull() ?: continue
            val snapshot = runCatching {
                readStableRegularFile(realPath.parent, realPath.fileName.toString(), BehaviorEvidenceCapture.MAXIMUM_FILE_BYTES)
            }.getOrNull() ?: continue
            val metadata = runCatching { BehaviorElfRuntimeMetadataReader.read(snapshot.bytes) }.getOrNull() ?: continue
            if (metadata.machine == required.machine && metadata.elfClass == required.elfClass &&
                metadata.byteOrder == required.byteOrder && metadata.abiFlags == required.abiFlags) {
                return RuntimeFile(realPath, JsonObject(mapOf(
                    "bytes" to JsonPrimitive(snapshot.bytes.size),
                    "sha256" to JsonPrimitive(snapshot.sha256),
                )), metadata)
            }
        }
        throw IllegalArgumentException("behavior ELF shared object has no compatible cached candidate: $name")
    }

    private fun runResolver(resolver: Path): ByteArray {
        val builder = ProcessBuilder(resolver.toString(), "-p").redirectErrorStream(true)
        builder.environment().clear()
        builder.environment()["PATH"] = "/usr/bin:/bin"
        builder.environment()["LC_ALL"] = "C"
        val process = builder.start()
        val output = AtomicReference<ByteArray?>()
        val failure = AtomicReference<Throwable?>()
        val reader = Thread({
            try {
                process.inputStream.use { output.set(it.readNBytes(MAXIMUM_RESOLVER_BYTES + 1)) }
            } catch (problem: Throwable) {
                failure.set(problem)
            }
        }, "behavior-runtime-inventory").apply { isDaemon = true; start() }
        val deadline = System.nanoTime() + java.util.concurrent.TimeUnit.SECONDS.toNanos(5)
        try {
            while (process.isAlive) {
                val captured = output.get()
                if (captured != null && captured.size > MAXIMUM_RESOLVER_BYTES) {
                    process.destroyForcibly()
                    throw IllegalArgumentException("ldconfig runtime inventory exceeds its byte bound")
                }
                if (System.nanoTime() >= deadline) {
                    process.destroyForcibly()
                    throw SandboxUnavailableException("ldconfig runtime inventory exceeded its time bound")
                }
                process.waitFor(20, java.util.concurrent.TimeUnit.MILLISECONDS)
            }
            reader.join(1000)
            require(!reader.isAlive) { "ldconfig output reader did not terminate" }
            failure.get()?.let { throw IllegalArgumentException("ldconfig runtime inventory could not be read", it) }
            val bytes = requireNotNull(output.get()) { "ldconfig did not produce a runtime inventory" }
            require(bytes.size <= MAXIMUM_RESOLVER_BYTES) { "ldconfig runtime inventory exceeds its byte bound" }
            require(process.exitValue() == 0) { "ldconfig runtime inventory exited unsuccessfully" }
            return bytes
        } finally {
            if (process.isAlive) process.destroyForcibly()
            process.inputStream.close()
            reader.interrupt()
            reader.join(1000)
        }
    }

    private fun hash(value: JsonObject): String = OracleArtifacts.sha256(OracleJson.canonicalBytes(value))

    private const val MAXIMUM_RUNTIME_LIBRARIES = 512
    private const val MAXIMUM_RUNTIME_BYTES = 512L * 1024 * 1024
    private const val MAXIMUM_RESOLVER_BYTES = 8 * 1024 * 1024
    private const val MAXIMUM_RESOLVER_ENTRIES = 100_000
    private val SONAME_PATTERN = Regex("[A-Za-z0-9_.+~-]{1,255}")
}
