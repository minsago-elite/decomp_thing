package decompengine.oracle.machinecalls

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole
import decompengine.oracle.fulltree.requireStableDirectory
import decompengine.oracle.gcc.GccCompilerEngineAnalysisToolchain
import decompengine.oracle.gcc.GccCompilerEngineArtifactBinding
import decompengine.oracle.gcc.authenticateGhidraInstallation
import java.io.ByteArrayInputStream
import java.net.URI
import java.net.URL
import java.lang.reflect.InvocationTargetException
import java.nio.file.Path
import java.security.CodeSource
import java.security.SecureClassLoader
import java.security.cert.Certificate
import java.util.Collections
import java.util.Enumeration
import java.util.jar.Attributes
import java.util.jar.JarFile
import java.util.jar.Manifest
import java.util.zip.ZipFile
import java.util.zip.ZipEntry
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Input commitments only: there is deliberately no recovered-program/model field. */
internal data class MachineCallFileV1(val path: Path, val bytes: Long, val sha256: String) {
    init {
        requireMachineCallPath(path)
        require(bytes in 1..MAXIMUM_INPUT_BYTES)
        requireMachineCallDigest(sha256)
    }

    fun json(): JsonObject = JsonObject(mapOf(
        "path" to JsonPrimitive(path.toString()), "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256),
    ))
}

internal data class MachineCallRuntimeV1(
    val bundleRoot: Path,
    val ghidraArchivePath: Path,
    val archiveSha256: String,
    val archiveBytes: Long,
    val bridgeSha256: String,
    val bundleManifestSha256: String,
    val languageId: String,
    val languageVersion: String,
) {
    init {
        requireMachineCallPath(bundleRoot)
        requireMachineCallPath(ghidraArchivePath)
        require(archiveSha256 == BundledGhidra.ARCHIVE_SHA256 && archiveBytes == GHIDRA_ARCHIVE_BYTES) {
            "machine-call runtime must use the pinned bundled Ghidra archive"
        }
        requireMachineCallDigest(bridgeSha256)
        requireMachineCallDigest(bundleManifestSha256)
        require(languageId == "x86:LE:64:default" && languageVersion == "4.8") {
            "machine-call runtime language identity differs"
        }
    }

    fun json(): JsonObject = JsonObject(mapOf(
        "bundleRoot" to JsonPrimitive(bundleRoot.toString()),
        "ghidraArchivePath" to JsonPrimitive(ghidraArchivePath.toString()),
        "archiveSha256" to JsonPrimitive(archiveSha256), "archiveBytes" to JsonPrimitive(archiveBytes),
        "bridgeSha256" to JsonPrimitive(bridgeSha256), "bundleManifestSha256" to JsonPrimitive(bundleManifestSha256),
        "languageId" to JsonPrimitive(languageId), "languageVersion" to JsonPrimitive(languageVersion),
    ))
}

internal data class MachineCallRuntimeV2(
    val bundleRoot: Path,
    val ghidraArchivePath: Path,
    val archiveSha256: String,
    val archiveBytes: Long,
    val bridgeSha256: String,
    val bundleManifestSha256: String,
    val languageId: String,
    val languageVersion: String,
    val bridgeSnapshot: MachineCallFileV1,
    val bundleManifestSnapshot: MachineCallFileV1,
) {
    init {
        requireMachineCallPath(bundleRoot)
        requireMachineCallPath(ghidraArchivePath)
        require(archiveSha256 == BundledGhidra.ARCHIVE_SHA256 && archiveBytes == GHIDRA_ARCHIVE_BYTES)
        requireMachineCallDigest(bridgeSha256)
        requireMachineCallDigest(bundleManifestSha256)
        require(languageId == "x86:LE:64:default" && languageVersion == "4.8")
        require(bridgeSnapshot.sha256 == bridgeSha256 &&
            bridgeSnapshot.bytes in 1..FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE.maximumBytes)
        require(bundleManifestSnapshot.sha256 == bundleManifestSha256 &&
            bundleManifestSnapshot.bytes in 1..FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST.maximumBytes)
    }

    fun reportJson(): JsonObject = MachineCallRuntimeV1(bundleRoot, ghidraArchivePath, archiveSha256, archiveBytes,
        bridgeSha256, bundleManifestSha256, languageId, languageVersion).json()

    fun json(): JsonObject = JsonObject(mapOf(
        "bundleRoot" to JsonPrimitive(bundleRoot.toString()),
        "ghidraArchivePath" to JsonPrimitive(ghidraArchivePath.toString()),
        "archiveSha256" to JsonPrimitive(archiveSha256),
        "archiveBytes" to JsonPrimitive(archiveBytes),
        "bridgeSha256" to JsonPrimitive(bridgeSha256),
        "bundleManifestSha256" to JsonPrimitive(bundleManifestSha256),
        "languageId" to JsonPrimitive(languageId),
        "languageVersion" to JsonPrimitive(languageVersion),
        "bridgeSnapshot" to bridgeSnapshot.json(),
        "bundleManifestSnapshot" to bundleManifestSnapshot.json(),
    ))
}

internal interface IndependentMachineCallRequestIdentity {
    val richFile: MachineCallFileV1
    val canonicalOracle: MachineCallFileV1
    val manifestSha256: String
    val outputPath: Path
    val limits: MachineCallLimitsV1
    val canonicalBytes: ByteArray
    fun reportRuntimeJson(): JsonObject
}

internal data class IndependentMachineCallRequestV1(
    override val richFile: MachineCallFileV1,
    override val canonicalOracle: MachineCallFileV1,
    override val manifestSha256: String,
    val runtime: MachineCallRuntimeV1,
    override val outputPath: Path,
    override val limits: MachineCallLimitsV1 = MachineCallLimitsV1(),
) : IndependentMachineCallRequestIdentity {
    init {
        requireMachineCallDigest(manifestSha256)
        requireMachineCallPath(outputPath)
        require(richFile.bytes <= 512L * 1024 * 1024 && canonicalOracle.bytes <= 64L * 1024 * 1024) {
            "machine-call inputs exceed the producer's file bounds"
        }
        require(richFile.path != canonicalOracle.path && outputPath !in listOf(richFile.path, canonicalOracle.path,
            runtime.ghidraArchivePath) && !outputPath.startsWith(runtime.bundleRoot)) {
            "machine-call request input/output paths overlap"
        }
        require(limits.maximumRoots in 1..131072 && limits.maximumInstructionsPerRoot in 1..1000000 &&
            limits.maximumInstructions in 1..10000000L && limits.maximumCalls in 1..1000000 &&
            limits.maximumWorkUnits in 1..100000000L && limits.maximumOutputBytes in 1..64 * 1024 * 1024 &&
            limits.maximumWallMillis in 1..1800000L) { "machine-call worker limits exceed the supported bounds" }
    }

    override val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive(REQUEST_KIND),
        "richFile" to richFile.json(), "canonicalOracle" to canonicalOracle.json(),
        "manifestSha256" to JsonPrimitive(manifestSha256), "runtime" to runtime.json(),
        "outputPath" to JsonPrimitive(outputPath.toString()), "limits" to JsonObject(mapOf(
            "maximumRoots" to JsonPrimitive(limits.maximumRoots),
            "maximumInstructionsPerRoot" to JsonPrimitive(limits.maximumInstructionsPerRoot),
            "maximumInstructions" to JsonPrimitive(limits.maximumInstructions),
            "maximumCalls" to JsonPrimitive(limits.maximumCalls),
            "maximumWorkUnits" to JsonPrimitive(limits.maximumWorkUnits),
            "maximumOutputBytes" to JsonPrimitive(limits.maximumOutputBytes),
            "maximumWallMillis" to JsonPrimitive(limits.maximumWallMillis),
        )),
    )), REQUEST_LIMITS)
    override fun reportRuntimeJson(): JsonObject = runtime.json()

    companion object {
        fun parse(bytes: ByteArray): IndependentMachineCallRequestV1 {
            val root = OracleJson.parseCanonical(bytes, REQUEST_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("machine-call request must be an object")
            root.fields("schemaVersion", "kind", "richFile", "canonicalOracle", "manifestSha256", "runtime", "outputPath", "limits")
            require(root.number("schemaVersion") == 1L && root.string("kind") == REQUEST_KIND)
            fun input(key: String): MachineCallFileV1 {
                val record = root.obj(key)
                record.fields("path", "bytes", "sha256")
                return MachineCallFileV1(Path.of(record.string("path")), record.number("bytes"), record.string("sha256"))
            }
            val runtime = root.obj("runtime")
            runtime.fields("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256",
                "bundleManifestSha256", "languageId", "languageVersion")
            val limits = root.obj("limits")
            limits.fields("maximumRoots", "maximumInstructionsPerRoot", "maximumInstructions", "maximumCalls",
                "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis")
            fun boundedInt(key: String): Int = Math.toIntExact(limits.number(key))
            return IndependentMachineCallRequestV1(input("richFile"), input("canonicalOracle"), root.string("manifestSha256"),
                MachineCallRuntimeV1(Path.of(runtime.string("bundleRoot")), Path.of(runtime.string("ghidraArchivePath")),
                    runtime.string("archiveSha256"), runtime.number("archiveBytes"), runtime.string("bridgeSha256"),
                    runtime.string("bundleManifestSha256"), runtime.string("languageId"), runtime.string("languageVersion")),
                Path.of(root.string("outputPath")), MachineCallLimitsV1(
                    maximumRoots = boundedInt("maximumRoots"), maximumInstructionsPerRoot = boundedInt("maximumInstructionsPerRoot"),
                    maximumInstructions = limits.number("maximumInstructions"), maximumCalls = boundedInt("maximumCalls"),
                    maximumWorkUnits = limits.number("maximumWorkUnits"), maximumOutputBytes = boundedInt("maximumOutputBytes"),
                    maximumWallMillis = limits.number("maximumWallMillis"),
                ))
        }
    }
}

/** Live worker request. Snapshot files are fixed children of the exact owned control root. */
internal data class IndependentMachineCallRequestV2(
    override val richFile: MachineCallFileV1,
    override val canonicalOracle: MachineCallFileV1,
    override val manifestSha256: String,
    val runtime: MachineCallRuntimeV2,
    val controlRoot: Path,
    override val outputPath: Path,
    override val limits: MachineCallLimitsV1 = MachineCallLimitsV1(),
) : IndependentMachineCallRequestIdentity {
    init {
        requireMachineCallDigest(manifestSha256)
        requireMachineCallPath(controlRoot)
        requireMachineCallPath(outputPath)
        require(richFile.bytes <= 512L * 1024 * 1024 && canonicalOracle.bytes <= 64L * 1024 * 1024)
        require(richFile.path != canonicalOracle.path && outputPath !in listOf(
            richFile.path, canonicalOracle.path, runtime.ghidraArchivePath,
        ) && !outputPath.startsWith(runtime.bundleRoot))
        require(controlRoot == outputPath.parent?.parent) { "machine-call control root differs from its output root" }
        require(outputPath == controlRoot.resolve("reports").resolve(MACHINE_CALL_REPORT_NAME)) {
            "machine-call output path differs from its fixed owned control-root location"
        }
        require(runtime.bridgeSnapshot.path == controlRoot.resolve("runtime").resolve(
            FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE.snapshotName,
        )) { "machine-call bridge snapshot path differs from its fixed owned control-root location" }
        require(runtime.bundleManifestSnapshot.path == controlRoot.resolve("runtime").resolve(
            FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST.snapshotName,
        )) { "machine-call manifest snapshot path differs from its fixed owned control-root location" }
        require(limits.maximumRoots in 1..131072 && limits.maximumInstructionsPerRoot in 1..1000000 &&
            limits.maximumInstructions in 1..10000000L && limits.maximumCalls in 1..1000000 &&
            limits.maximumWorkUnits in 1..100000000L && limits.maximumOutputBytes in 1..64 * 1024 * 1024 &&
            limits.maximumWallMillis in 1..1800000L)
    }

    override val canonicalBytes: ByteArray get() = OracleJson.canonicalBytes(JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(2),
        "kind" to JsonPrimitive(REQUEST_KIND_V2),
        "richFile" to richFile.json(),
        "canonicalOracle" to canonicalOracle.json(),
        "manifestSha256" to JsonPrimitive(manifestSha256),
        "runtime" to runtime.json(),
        "controlRoot" to JsonPrimitive(controlRoot.toString()),
        "outputPath" to JsonPrimitive(outputPath.toString()),
        "limits" to limits.toJson(),
    )), REQUEST_LIMITS)

    override fun reportRuntimeJson(): JsonObject = runtime.reportJson()

    fun requireMaterializerBindings(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        expectedControlRoot: Path,
    ) {
        require(controlRoot == expectedControlRoot) { "machine-call request control root differs from the owned run root" }
        val artifacts = configuration.runtimeArtifacts.associateBy { it.role }
        require(artifacts.keys == setOf(
            FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE,
            FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST,
        )) { "machine-call runtime artifact roles differ from the authenticated materializer" }
        fun requireArtifact(
            role: FullTreeFunctionObservationRuntimeArtifactRole,
            file: MachineCallFileV1,
        ) {
            val declared = artifacts.getValue(role)
            require(declared.path == runtime.bundleRoot.resolve(role.sourceName) &&
                declared.bytes == file.bytes && declared.expectedSha256 == file.sha256 &&
                file.path == controlRoot.resolve("runtime").resolve(role.snapshotName)) {
                "machine-call runtime snapshot identity differs from the authenticated materializer: $role"
            }
        }
        requireArtifact(FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE, runtime.bridgeSnapshot)
        requireArtifact(FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST,
            runtime.bundleManifestSnapshot)
    }

    companion object {
        fun parse(bytes: ByteArray): IndependentMachineCallRequestV2 {
            val root = OracleJson.parseCanonical(bytes, REQUEST_LIMITS) as? JsonObject
                ?: throw IllegalArgumentException("machine-call request must be an object")
            root.fields("schemaVersion", "kind", "richFile", "canonicalOracle", "manifestSha256", "runtime",
                "controlRoot", "outputPath", "limits")
            require(root.number("schemaVersion") == 2L && root.string("kind") == REQUEST_KIND_V2)
            fun input(key: String): MachineCallFileV1 {
                val record = root.obj(key)
                record.fields("path", "bytes", "sha256")
                return MachineCallFileV1(Path.of(record.string("path")), record.number("bytes"), record.string("sha256"))
            }
            val runtime = root.obj("runtime")
            runtime.fields("bundleRoot", "ghidraArchivePath", "archiveSha256", "archiveBytes", "bridgeSha256",
                "bundleManifestSha256", "languageId", "languageVersion", "bridgeSnapshot", "bundleManifestSnapshot")
            fun nestedInput(key: String): MachineCallFileV1 {
                val record = runtime.obj(key)
                record.fields("path", "bytes", "sha256")
                return MachineCallFileV1(Path.of(record.string("path")), record.number("bytes"), record.string("sha256"))
            }
            val limits = root.obj("limits")
            limits.fields("maximumRoots", "maximumInstructionsPerRoot", "maximumInstructions", "maximumCalls",
                "maximumWorkUnits", "maximumOutputBytes", "maximumWallMillis")
            fun boundedInt(key: String): Int = Math.toIntExact(limits.number(key))
            return IndependentMachineCallRequestV2(input("richFile"), input("canonicalOracle"),
                root.string("manifestSha256"), MachineCallRuntimeV2(
                    Path.of(runtime.string("bundleRoot")), Path.of(runtime.string("ghidraArchivePath")),
                    runtime.string("archiveSha256"), runtime.number("archiveBytes"), runtime.string("bridgeSha256"),
                    runtime.string("bundleManifestSha256"), runtime.string("languageId"), runtime.string("languageVersion"),
                    nestedInput("bridgeSnapshot"), nestedInput("bundleManifestSnapshot")),
                Path.of(root.string("controlRoot")), Path.of(root.string("outputPath")), MachineCallLimitsV1(
                    maximumRoots = boundedInt("maximumRoots"),
                    maximumInstructionsPerRoot = boundedInt("maximumInstructionsPerRoot"),
                    maximumInstructions = limits.number("maximumInstructions"),
                    maximumCalls = boundedInt("maximumCalls"),
                    maximumWorkUnits = limits.number("maximumWorkUnits"),
                    maximumOutputBytes = boundedInt("maximumOutputBytes"),
                    maximumWallMillis = limits.number("maximumWallMillis"),
                ))
        }
    }
}

/**
 * Diagnostic child computation, not a launcher or containment receipt. The external owner must
 * provide process/resource/filesystem isolation; even a successful result grants no release or
 * negative-completeness authority. No production coordinator or consumer is registered here.
 */
object IndependentMachineCallWorkerV1 {
    @JvmStatic fun main(arguments: Array<String>) {
        require(arguments.size == 2) { "machine-call worker requires request path and SHA-256" }
        run(Path.of(arguments[0]), arguments[1])
    }

    internal fun run(requestPath: Path, requestSha256: String) {
        requireMachineCallPath(requestPath)
        requireMachineCallDigest(requestSha256)
        StableControlFile.open(requestPath, REQUEST_LIMITS.maximumInputBytes.toLong(), "machine-call request").use { requestFile ->
            require(requestFile.authenticatedSha256 == requestSha256) { "machine-call request SHA-256 differs" }
            val request = IndependentMachineCallRequestV2.parse(requestFile.readExactly(0L, requestFile.size.toInt(), "machine-call request"))
            require(request.outputPath != requestPath) { "machine-call output overlaps request" }
            val started = System.nanoTime()
            val checkpoint: (String) -> Unit = { label ->
                check(!Thread.currentThread().isInterrupted) { "machine-call worker cancelled $label" }
                check((System.nanoTime() - started) / 1000000L <= request.limits.maximumWallMillis) {
                    "machine-call worker wall limit exceeded $label"
                }
            }
            openCommitted(request.richFile, "machine-call rich ELF", checkpoint).use { rich ->
                openCommitted(request.canonicalOracle, "machine-call canonical oracle", checkpoint).use { oracle ->
                    AuthenticatedMachineCallRuntimeV2.open(request.runtime, checkpoint).use { runtime ->
                        val result = runtime.withDecoder { decoder ->
                            IndependentMachineCallsV1.produce(request.richFile.path, request.canonicalOracle.path,
                                request.richFile.sha256, request.canonicalOracle.sha256, request.manifestSha256, decoder, request.limits)
                        }
                        runtime.verify(checkpoint)
                        rich.verifyUnchanged("machine-call rich ELF after production")
                        oracle.verifyUnchanged("machine-call canonical oracle after production")
                        requestFile.verifyUnchanged("machine-call request after production")
                        checkpoint("before publication")
                        val final = JsonObject(result + mapOf(
                            "requestSha256" to JsonPrimitive(requestSha256), "runtime" to request.reportRuntimeJson(),
                            "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                            "negativeCompleteness" to JsonPrimitive(false),
                            "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
                            "containmentStatus" to JsonPrimitive("external-owner-required"),
                        ))
                        val outputLimits = IndependentMachineCallsV1.outputLimits(request.limits)
                        IndependentMachineCallReportV1.validateWorker(final, requestSha256, request)
                        val bytes = OracleJson.canonicalBytes(final, outputLimits, checkpoint)
                        publishMachineCallResultV1(request.outputPath, bytes)
                    }
                }
            }
        }
    }
}

/** Reuses the existing archive/tree verifier; its container's GCC metadata grants no authority. */
internal class AuthenticatedMachineCallRuntimeV2 private constructor(
    private val request: MachineCallRuntimeV2,
    private val archive: StableControlFile,
    private val bridge: StableControlFile,
    private val manifest: StableControlFile,
    private val loader: MachineCallJarClassLoaderV1,
    private val decoderClass: Class<*>,
) : AutoCloseable {
    fun <T> withDecoder(consume: (MachineInstructionDecoderV1) -> T): T {
        val thread = Thread.currentThread()
        val previous = thread.contextClassLoader
        thread.contextClassLoader = loader
        try {
            decoderClass.getMethod("initialize", String::class.java).invoke(null,
                request.bundleRoot.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC").toString())
            val decoder = decoderClass.getConstructor(String::class.java).newInstance(request.languageId)
            val decode = decoderClass.getMethod("decode", java.lang.Long.TYPE, ByteArray::class.java)
            return consume(MachineInstructionDecoderV1 { address, bytes ->
                val record = try {
                    decode.invoke(decoder, address.toLong(), bytes.copyOf())
                } catch (failure: InvocationTargetException) {
                    val cause = failure.cause
                    if (cause?.javaClass?.name == "decompengine.ghidra.ByteInstructionDecoderV1\$DecodeException" &&
                        cause.javaClass.classLoader === loader) throw MachineInstructionRefusalV1(requireNotNull(cause.message))
                    throw failure
                } ?: throw IllegalArgumentException("machine-call decoder returned null")
                require(record.javaClass.classLoader === loader && record.javaClass.isRecord)
                machineInstructionFromBridgeV1(record)
            })
        } finally {
            thread.contextClassLoader = previous
        }
    }

    fun verify(checkpoint: (String) -> Unit) {
        checkpoint("before runtime reauthentication")
        authenticateRelease(request)
        val manifestBytes = manifest.readExactly(0L, manifest.size.toInt(), "machine-call bundle manifest snapshot")
        BundledGhidra.at(request.bundleRoot).verifiedLibraryPathsFromManifestSnapshot(manifestBytes, checkpoint)
        archive.verifyUnchanged("machine-call Ghidra archive after production")
        bridge.verifyUnchanged("machine-call bridge after production")
        manifest.verifyUnchanged("machine-call bundle manifest after production")
        checkpoint("after runtime reauthentication")
    }

    override fun close() {
        try { loader.close() } finally { try { manifest.close() } finally { try { bridge.close() } finally { archive.close() } } }
    }

    companion object {
        fun open(request: MachineCallRuntimeV2, checkpoint: (String) -> Unit = {}): AuthenticatedMachineCallRuntimeV2 {
            requireStableDirectory(request.bundleRoot, "machine-call bundle root")
            val opened = mutableListOf<AutoCloseable>()
            try {
                val archive = openCommitted(MachineCallFileV1(request.ghidraArchivePath, request.archiveBytes, request.archiveSha256),
                    "machine-call Ghidra archive", checkpoint).also(opened::add)
                val bridgePath = request.bridgeSnapshot.path
                val bridge = openCommitted(request.bridgeSnapshot, "machine-call bridge snapshot", checkpoint).also(opened::add)
                val manifest = openCommitted(request.bundleManifestSnapshot, "machine-call bundle manifest snapshot", checkpoint).also(opened::add)
                require(bridge.authenticatedSha256 == request.bridgeSha256) { "machine-call bridge snapshot SHA-256 differs" }
                require(manifest.authenticatedSha256 == request.bundleManifestSha256) { "machine-call bundle manifest snapshot SHA-256 differs" }
                checkpoint("before release authentication")
                authenticateRelease(request)
                val manifestBytes = manifest.readExactly(0L, manifest.size.toInt(), "machine-call bundle manifest snapshot")
                manifest.verifyUnchanged("machine-call bundle manifest before library verification")
                val libraries = BundledGhidra.at(request.bundleRoot)
                    .verifiedLibraryPathsFromManifestSnapshot(manifestBytes, checkpoint)
                manifest.verifyUnchanged("machine-call bundle manifest after library verification")
                require(libraries.size in 1..511) { "machine-call runtime library count exceeds its bound" }
                val classPath = listOf(bridgePath) + libraries
                val loader = MachineCallJarClassLoaderV1(classPath, checkpoint).also(opened::add)
                // Do not execute any class initializer before the source commitment is checked.
                val type = Class.forName("decompengine.ghidra.ByteInstructionDecoderV1", false, loader)
                requireLoadedMachineCallBridgeV1(type, bridgePath, request.bridgeSha256)
                require(type.classLoader === loader) { "machine-call decoder escaped its isolated loader" }
                archive.verifyUnchanged("machine-call archive before decoder initialization")
                bridge.verifyUnchanged("machine-call bridge before decoder initialization")
                manifest.verifyUnchanged("machine-call bundle manifest before decoder initialization")
                return AuthenticatedMachineCallRuntimeV2(request, archive, bridge, manifest, loader, type)
            } catch (failure: Throwable) {
                opened.asReversed().forEach { resource -> try { resource.close() } catch (close: Throwable) { failure.addSuppressed(close) } }
                throw failure
            }
        }
    }
}

internal fun requireLoadedMachineCallBridgeV1(type: Class<*>, expectedPath: Path, expectedSha256: String) {
    requireMachineCallDigest(expectedSha256)
    val source = type.protectionDomain?.codeSource?.location ?: error("machine-call decoder source is unavailable")
    require(source.protocol == "file" && Path.of(source.toURI()) == expectedPath) { "machine-call decoder source differs from requested bridge" }
    StableControlFile.open(expectedPath, 128L * 1024 * 1024, "loaded machine-call bridge").use { file ->
        require(file.authenticatedSha256 == expectedSha256) { "loaded machine-call bridge SHA-256 differs" }
        file.verifyUnchanged("loaded machine-call bridge")
    }
}

/**
 * Loads only explicit authenticated JARs. URLClassLoader would follow manifest Class-Path and
 * INDEX.LIST expansion; bundled third-party JARs retain stale references, so ignoring expansion
 * is necessary. Multi-release selection and package metadata retain normal JVM semantics.
 */
internal class MachineCallJarClassLoaderV1(classPath: List<Path>, private val checkpoint: (String) -> Unit = {}) :
    SecureClassLoader(ClassLoader.getPlatformClassLoader()), AutoCloseable {
    private data class Library(val source: URL, val jar: JarFile, val manifest: Manifest?)
    private val libraries: List<Library>

    init {
        require(classPath.size in 2..512 && classPath.distinct().size == classPath.size)
        val opened = arrayListOf<Library>()
        var manifestBytes = 0L
        var archiveEntries = 0L
        try {
            for (path in classPath) {
                checkpoint("before explicit runtime JAR inspection")
                requireMachineCallPath(path)
                // Bound manifest decompression before enabling versioned lookup.
                val manifest = ZipFile(path.toFile()).use { jar ->
                    require(jar.size() <= 200000) { "machine-call JAR entry count exceeds its bound" }
                    archiveEntries += jar.size()
                    require(archiveEntries <= 2000000) { "machine-call JAR entry aggregate exceeds its bound" }
                    var selected: ZipEntry? = null
                    val entries = jar.entries()
                    while (entries.hasMoreElements()) {
                        checkpoint("while inspecting explicit runtime JAR")
                        val entry = entries.nextElement()
                        if (entry.name.equals(JarFile.MANIFEST_NAME, ignoreCase = true)) {
                            require(entry.name == JarFile.MANIFEST_NAME && selected == null) { "ambiguous machine-call JAR manifest" }
                            selected = entry
                        }
                    }
                    selected?.let { entry ->
                        require(entry.size in 0..2L * 1024 * 1024) { "machine-call JAR manifest exceeds its byte bound" }
                        manifestBytes += entry.size
                        require(manifestBytes <= 16L * 1024 * 1024) { "machine-call JAR manifest aggregate exceeds its bound" }
                        val bytes = jar.getInputStream(entry).use { it.readNBytes(entry.size.toInt() + 1) }
                        require(bytes.size.toLong() == entry.size) { "machine-call JAR manifest size differs" }
                        Manifest(ByteArrayInputStream(bytes))
                    }
                }
                opened += Library(path.toUri().toURL(), JarFile(path.toFile(), false, JarFile.OPEN_READ, Runtime.version()), manifest)
            }
            libraries = opened.toList()
        } catch (failure: Throwable) {
            opened.asReversed().forEach { try { it.jar.close() } catch (close: Throwable) { failure.addSuppressed(close) } }
            throw failure
        }
    }

    override fun findClass(name: String): Class<*> {
        checkpoint("before loading explicit runtime class")
        val resource = name.replace('.', '/') + ".class"
        for (library in libraries) {
            val entry = library.jar.getJarEntry(resource) ?: continue
            require(entry.size in 1..16L * 1024 * 1024) { "machine-call runtime class exceeds its byte bound" }
            val bytes = library.jar.getInputStream(entry).use { it.readNBytes(entry.size.toInt() + 1) }
            checkpoint("after reading explicit runtime class")
            require(bytes.size.toLong() == entry.size) { "machine-call runtime class size differs" }
            val packageName = name.substringBeforeLast('.', "")
            if (packageName.isNotEmpty()) {
                val attributes = library.manifest?.getAttributes(packageName.replace('.', '/') + "/")
                fun attribute(key: Attributes.Name): String? = attributes?.getValue(key) ?: library.manifest?.mainAttributes?.getValue(key)
                val sealed = attribute(Attributes.Name.SEALED).equals("true", ignoreCase = true)
                val defined = getDefinedPackage(packageName)
                if (defined == null) definePackage(packageName,
                    attribute(Attributes.Name.SPECIFICATION_TITLE), attribute(Attributes.Name.SPECIFICATION_VERSION),
                    attribute(Attributes.Name.SPECIFICATION_VENDOR), attribute(Attributes.Name.IMPLEMENTATION_TITLE),
                    attribute(Attributes.Name.IMPLEMENTATION_VERSION), attribute(Attributes.Name.IMPLEMENTATION_VENDOR),
                    library.source.takeIf { sealed })
                else require(if (defined.isSealed) defined.isSealed(library.source) else !sealed) { "machine-call package sealing differs" }
            }
            return defineClass(name, bytes, 0, bytes.size, CodeSource(library.source, null as Array<Certificate>?))
        }
        throw ClassNotFoundException(name)
    }

    override fun findResource(name: String): URL? = explicitResources(name).firstOrNull()
    override fun findResources(name: String): Enumeration<URL> = Collections.enumeration(explicitResources(name))
    private fun explicitResources(name: String): List<URL> = libraries.mapNotNull { library ->
        library.jar.getJarEntry(name)?.let { entry ->
            val encoded = URI(null, null, "/${entry.realName}", null).rawPath.removePrefix("/")
            URI.create("jar:${library.source}!/$encoded").toURL()
        }
    }

    override fun close() {
        var failure: Throwable? = null
        libraries.asReversed().forEach { library ->
            try { library.jar.close() } catch (close: Throwable) { if (failure == null) failure = close else failure!!.addSuppressed(close) }
        }
        failure?.let { throw it }
    }
}

internal fun machineInstructionFromBridgeV1(record: Any): MachineInstructionV1 {
    val type = record.javaClass
    require(type.isRecord && type.recordComponents.map { it.name }.toSet() == setOf("address", "length", "bytes", "classification",
        "call", "computed", "jump", "conditional", "terminal", "fallthrough", "directTargets", "directCallTarget", "contextStatus")) {
        "machine-call decoder record schema differs"
    }
    fun value(key: String): Any? = type.getMethod(key).invoke(record)
    fun string(key: String): String = value(key) as? String ?: error("machine-call decoder $key must be a string")
    fun address(value: Any?): ULong? {
        if (value == null) return null
        require(value is String && value.matches(Regex("0x(?:0|[1-9a-f][0-9a-f]{0,15})"))) { "machine-call decoder address is invalid" }
        return value.substring(2).toULong(16)
    }
    fun flag(key: String): Boolean = value(key) as? Boolean ?: error("machine-call decoder $key must be boolean")
    val call = flag("call"); val computed = flag("computed"); val jump = flag("jump")
    val conditional = flag("conditional"); val terminal = flag("terminal")
    val classification = string("classification")
    val consistent = when (classification) {
        "direct-call" -> call && !computed && !jump
        "indirect-call" -> call && computed && !jump
        "direct-jump" -> !call && !computed && jump
        "indirect-jump" -> !call && computed && jump
        "return" -> !call && !computed && !jump && terminal
        "ordinary" -> !call && !computed && !jump && !conditional && !terminal
        else -> classification in setOf("unsupported-pcode", "unsupported-context", "unsupported-trap-or-userop", "unsupported-flow")
    }
    require(consistent) { "machine-call decoder classification and flow flags disagree" }
    val targets = value("directTargets") as? List<*> ?: error("machine-call decoder targets must be a list")
    require(targets.size <= 16) { "machine-call decoder target bound exceeded" }
    return MachineInstructionV1(requireNotNull(address(value("address"))), value("length") as? Int ?: error("invalid decoder length"),
        (value("bytes") as? ByteArray ?: error("invalid decoder bytes")).copyOf(), classification,
        address(value("fallthrough")), targets.map { requireNotNull(address(it)) }, address(value("directCallTarget")), string("contextStatus"))
}

/**
 * Pin every directory lookup without following symlinks, then publish an unnamed inode through
 * that retained parent. Neither link source/destination nor failure cleanup re-resolves a mutable
 * absolute pathname. A renamed parent receives the authentic bytes, never its replacement.
 * Linux/O_TMPFILE support is required: there is deliberately no pathname-based fallback.
 */
internal fun publishMachineCallResultV1(output: Path, bytes: ByteArray, checkpoint: (String) -> Unit = {}) {
    requireMachineCallPath(output)
    LinuxFilesystemSyscalls.requireSupported(output)
    val directories = mutableListOf<LinuxDescriptor>()
    try {
        var parent = LinuxFilesystemSyscalls.openRoot(output.root).also(directories::add)
        for (component in requireNotNull(output.parent)) {
            parent = LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, component.toString()).also(directories::add)
        }
        val identity = LinuxFilesystemSyscalls.identity(parent.fd)
        require(identity.isDirectory && !identity.isSymbolicLink && identity.mode and 0x12 == 0) {
            "machine-call output parent must not be group/world writable"
        }
        val name = output.fileName.toString()
        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)?.use {
            throw IllegalArgumentException("machine-call output already exists")
        }
        LinuxFilesystemSyscalls.createTemporaryAt(parent.fd).use { staged ->
            try {
                LinuxFilesystemSyscalls.write(staged, bytes) {}
                checkpoint("before publication link")
                val current = LinuxFilesystemSyscalls.identity(staged.fd)
                require(current.key == staged.identity.key && current.isRegularFile && current.linkCount == 0) {
                    "machine-call staged inode changed"
                }
                // linkat(AT_EMPTY_PATH) names the retained inode, and fails if the target exists.
                LinuxFilesystemSyscalls.linkTemporaryAt(staged, parent.fd, name)
            } finally {
                // Closing an unpublished O_TMPFILE releases the inode; no unlink pathname exists.
                checkpoint("before staging close")
            }
        }
    } finally {
        directories.asReversed().forEach { it.close() }
    }
}

private fun authenticateRelease(request: MachineCallRuntimeV2) {
    GccCompilerEngineAnalysisToolchain("independent-machine-call-byte-decoder-v1", 1, request.bridgeSha256,
        "decode-bytes", BundledGhidra.VERSION, "PUBLIC",
        GccCompilerEngineArtifactBinding("ghidra-release.zip", GHIDRA_ARCHIVE_BYTES, BundledGhidra.ARCHIVE_SHA256),
        "none", 1).authenticateGhidraInstallation(request.ghidraArchivePath,
        request.bundleRoot.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC"))
}

private fun openCommitted(input: MachineCallFileV1, label: String, checkpoint: (String) -> Unit = {}): StableControlFile {
    val file = StableControlFile.openWithCheckpoint(input.path, input.bytes, label, checkpoint)
    try {
        require(file.size == input.bytes && file.authenticatedSha256 == input.sha256) { "$label bytes or SHA-256 differ" }
        return file
    } catch (failure: Throwable) {
        file.close()
        throw failure
    }
}

private fun requireMachineCallPath(path: Path) {
    val value = path.toString()
    require(path.isAbsolute && path.normalize() == path && path.parent != null && value.length in 1..4096 &&
        value.none { it.code < 32 || it.code == 127 }) { "machine-call path must be absolute and normalized" }
}
private fun requireMachineCallDigest(value: String) = require(value.matches(Regex("[0-9a-f]{64}"))) { "invalid machine-call digest" }
private fun JsonObject.fields(vararg expected: String) = require(keys == expected.toSet()) { "unknown or missing machine-call request fields" }
private fun JsonObject.obj(key: String): JsonObject = getValue(key) as? JsonObject ?: error("$key must be an object")
private fun JsonObject.string(key: String): String = (getValue(key) as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("$key must be a string")
private fun JsonObject.number(key: String): Long = (getValue(key) as? JsonPrimitive)?.takeUnless { it.isString }?.longOrNull
    ?: throw IllegalArgumentException("$key must be an integer")
private const val REQUEST_KIND = "independent-machine-call-request-v1"
private const val REQUEST_KIND_V2 = "independent-machine-call-request-v2"
private const val MACHINE_CALL_REPORT_NAME = "independent-machine-call-observations.json"
private const val BRIDGE_FILE = "decomp-ghidra-bridge.jar"
private const val GHIDRA_ARCHIVE_BYTES = 569445154L
private const val MAXIMUM_INPUT_BYTES = 2L * 1024 * 1024 * 1024
private val REQUEST_LIMITS = StrictJsonLimits(maximumInputBytes = 65536, maximumCanonicalBytes = 65536,
    maximumDepth = 8, maximumNodes = 128, maximumStringBytes = 4096, maximumTotalStringBytes = 16384)
