package decompengine.oracle.behavior

import decompengine.acp.LinuxBoundedSessionCommand
import decompengine.acp.LinuxBoundedSessionProcess
import decompengine.acp.LinuxBoundedSessionResult
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

class LlvmBehaviorRuntimePreflightException(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/** Caller values can only lower fixed input, command-time, and capture ceilings. */
class LlvmBehaviorRuntimePreflightLimits(
    val maximumCorpusBytes: Int = MAXIMUM_CORPUS_BYTES,
    val maximumReferenceReportBytes: Int = MAXIMUM_REFERENCE_REPORT_BYTES,
    val maximumDiagnosticMatrixBytes: Int = MAXIMUM_DIAGNOSTIC_MATRIX_BYTES,
    val maximumArtifactManifestBytes: Int = MAXIMUM_ARTIFACT_MANIFEST_BYTES,
    val maximumControlClientBytes: Long = MAXIMUM_CONTROL_CLIENT_BYTES,
    val commandTimeoutMilliseconds: Long = MAXIMUM_COMMAND_TIMEOUT_MILLISECONDS,
    val maximumCommandStdoutBytes: Int = MAXIMUM_COMMAND_CAPTURE_BYTES,
    val maximumCommandStderrBytes: Int = MAXIMUM_COMMAND_CAPTURE_BYTES,
) {
    init {
        require(maximumCorpusBytes in 1..MAXIMUM_CORPUS_BYTES) { "maximumCorpusBytes may only lower its ceiling" }
        require(maximumReferenceReportBytes in 1..MAXIMUM_REFERENCE_REPORT_BYTES) {
            "maximumReferenceReportBytes may only lower its ceiling"
        }
        require(maximumDiagnosticMatrixBytes in 1..MAXIMUM_DIAGNOSTIC_MATRIX_BYTES) {
            "maximumDiagnosticMatrixBytes may only lower its ceiling"
        }
        require(maximumArtifactManifestBytes in 1..MAXIMUM_ARTIFACT_MANIFEST_BYTES) {
            "maximumArtifactManifestBytes may only lower its ceiling"
        }
        require(maximumControlClientBytes in 1L..MAXIMUM_CONTROL_CLIENT_BYTES) {
            "maximumControlClientBytes may only lower its ceiling"
        }
        require(commandTimeoutMilliseconds in 1L..MAXIMUM_COMMAND_TIMEOUT_MILLISECONDS) {
            "commandTimeoutMilliseconds may only lower its ceiling"
        }
        require(maximumCommandStdoutBytes in 1..MAXIMUM_COMMAND_CAPTURE_BYTES) {
            "maximumCommandStdoutBytes may only lower its ceiling"
        }
        require(maximumCommandStderrBytes in 1..MAXIMUM_COMMAND_CAPTURE_BYTES) {
            "maximumCommandStderrBytes may only lower its ceiling"
        }
    }

    private companion object {
        const val MAXIMUM_CORPUS_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_REFERENCE_REPORT_BYTES = 64 * 1024 * 1024
        const val MAXIMUM_DIAGNOSTIC_MATRIX_BYTES = 1024 * 1024
        const val MAXIMUM_ARTIFACT_MANIFEST_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_CONTROL_CLIENT_BYTES = 128L * 1024L * 1024L
        const val MAXIMUM_COMMAND_TIMEOUT_MILLISECONDS = 30_000L
        const val MAXIMUM_COMMAND_CAPTURE_BYTES = 1024 * 1024
    }
}

/**
 * A live read-only runtime identity/capability receipt. It is not candidate execution,
 * per-container containment evidence, behavior comparison, a score, or release admission.
 */
sealed interface LlvmBehaviorRuntimePreflight {
    val authority: String
    val corpusSha256: String
    val controlClientSha256: String
    val runtimeIdentityVerified: Boolean
    val containmentCapabilitiesVerified: Boolean
    val imageVerified: Boolean
    val candidateStarted: Boolean
    val liveContainmentVerified: Boolean
    val scoringAuthority: Boolean
    val releaseEligible: Boolean
    val preflightSha256: String
    val canonicalBytes: ByteArray
}

/**
 * Production authority accepts only eight raw paths and caller-lowered limits. No parser, runner,
 * endpoint facts, response bytes, digest claim, callback, score, or release token is accepted.
 */
object LlvmBehaviorRuntimePreflightPublisher {
    fun publish(
        corpusPath: Path,
        referenceReportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        controlClientPath: Path,
        dockerConfigDirectory: Path,
        runtimeSocketPath: Path,
        outputPath: Path,
        limits: LlvmBehaviorRuntimePreflightLimits = LlvmBehaviorRuntimePreflightLimits(),
    ): LlvmBehaviorRuntimePreflight = PublishedPreflight(
        corpusPath,
        referenceReportPath,
        diagnosticMatrixPath,
        artifactManifestPath,
        controlClientPath,
        dockerConfigDirectory,
        runtimeSocketPath,
        outputPath,
        limits,
    )

    /* Reflective construction still supplies only the same raw paths and lowering limits. */
    private class PublishedPreflight(
        corpusPath: Path,
        referenceReportPath: Path,
        diagnosticMatrixPath: Path,
        artifactManifestPath: Path,
        controlClientPath: Path,
        dockerConfigDirectory: Path,
        runtimeSocketPath: Path,
        outputPath: Path,
        limits: LlvmBehaviorRuntimePreflightLimits,
    ) : LlvmBehaviorRuntimePreflight {
        private val storedBytes: ByteArray
        override val authority = PREFLIGHT_AUTHORITY
        override val corpusSha256: String
        override val controlClientSha256: String
        override val runtimeIdentityVerified = true
        override val containmentCapabilitiesVerified = true
        override val imageVerified = true
        override val candidateStarted = false
        override val liveContainmentVerified = false
        override val scoringAuthority = false
        override val releaseEligible = false
        override val preflightSha256: String

        override val canonicalBytes: ByteArray
            get() = storedBytes.copyOf()

        init {
            val derived = deriveAndPublishPreflight(
                corpusPath,
                referenceReportPath,
                diagnosticMatrixPath,
                artifactManifestPath,
                controlClientPath,
                dockerConfigDirectory,
                runtimeSocketPath,
                outputPath,
                limits,
            )
            corpusSha256 = derived.corpusSha256
            controlClientSha256 = derived.controlClientSha256
            storedBytes = derived.bytes.copyOf()
            preflightSha256 = OracleArtifacts.sha256(storedBytes)
        }
    }
}

private fun deriveAndPublishPreflight(
    corpusPath: Path,
    referenceReportPath: Path,
    diagnosticMatrixPath: Path,
    artifactManifestPath: Path,
    controlClientPath: Path,
    dockerConfigDirectory: Path,
    runtimeSocketPath: Path,
    outputPath: Path,
    limits: LlvmBehaviorRuntimePreflightLimits,
): DerivedPreflight {
    try {
        val paths = normalizePreflightPaths(
            corpusPath,
            referenceReportPath,
            diagnosticMatrixPath,
            artifactManifestPath,
            controlClientPath,
            dockerConfigDirectory,
            runtimeSocketPath,
            outputPath,
        )
        requireDistinctPreflightPaths(paths)
        requireDedicatedPreflightOutputParent(paths.output)
        StableControlFile.open(paths.corpus, limits.maximumCorpusBytes.toLong(), "LLVM behavior corpus").use {
                corpusGuard ->
            StableControlFile.open(
                paths.referenceReport,
                limits.maximumReferenceReportBytes.toLong(),
                "LLVM behavior reference report",
            ).use { reportGuard ->
                StableControlFile.open(
                    paths.diagnosticMatrix,
                    limits.maximumDiagnosticMatrixBytes.toLong(),
                    "LLVM diagnostic matrix",
                ).use { matrixGuard ->
                    StableControlFile.open(
                        paths.artifactManifest,
                        limits.maximumArtifactManifestBytes.toLong(),
                        "LLVM artifact manifest",
                    ).use { manifestGuard ->
                        val corpusBytes = corpusGuard.readExactly(
                            0L,
                            corpusGuard.size.toPreflightInt("LLVM behavior corpus"),
                            "LLVM behavior corpus",
                        )
                        val corpus = parsePreflightCorpus(corpusBytes)
                        val declaration = parseRuntimeDeclaration(corpus)
                        val corpusSha256 = OracleArtifacts.sha256(corpusBytes)
                        val reference = LlvmBehaviorReferenceEvidenceVerifier.verify(
                            paths.corpus,
                            paths.referenceReport,
                            paths.diagnosticMatrix,
                            paths.artifactManifest,
                        )
                        requireReferenceMatches(reference, declaration.corpusId, corpusSha256)

                        capturePinnedDockerRuntimeBindings(
                            controlClientPath = paths.controlClient,
                            expectedControlClientBytes = declaration.controlClientBytes,
                            expectedControlClientSha256 = declaration.controlClientSha256,
                            maximumControlClientBytes = limits.maximumControlClientBytes,
                            dockerConfigPath = paths.dockerConfig,
                            runtimeSocketPath = paths.runtimeSocket,
                        ).use { runtimeBindings ->
                            val executor = LiveRuntimeCommandExecutor(runtimeBindings, limits)
                            val verification = verifyLiveRuntime(declaration, executor)
                            requireStableReferenceInputs(
                                corpusGuard,
                                reportGuard,
                                matrixGuard,
                                manifestGuard,
                            )
                            runtimeBindings.requireCurrent()
                            val terminalReference = LlvmBehaviorReferenceEvidenceVerifier.verify(
                                paths.corpus,
                                paths.referenceReport,
                                paths.diagnosticMatrix,
                                paths.artifactManifest,
                            )
                            if (!samePreflightReference(reference, terminalReference)) {
                                preflightFail("LLVM reference evidence changed during runtime preflight")
                            }
                            requireStableReferenceInputs(
                                corpusGuard,
                                reportGuard,
                                matrixGuard,
                                manifestGuard,
                            )
                            runtimeBindings.requireCurrent()

                            val bytes = renderPreflightReceipt(
                                declaration,
                                reference,
                                verification,
                                runtimeBindings,
                                limits,
                            )
                            val parent = paths.output.parent
                                ?: preflightFail("runtime preflight output must have a parent")
                            LinuxFilesystemSyscalls.openRoot(parent).use { parentDescriptor ->
                                val published = DescriptorBoundAtomicStateFile.publishNoReplace(
                                    parentDescriptor,
                                    paths.output.fileName.toString(),
                                    bytes,
                                    MAXIMUM_PREFLIGHT_BYTES,
                                )
                                if (!published.bytes.contentEquals(bytes)) {
                                    preflightFail("published runtime preflight bytes changed")
                                }
                            }
                            // Directory-inode separation above means receipt publication cannot
                            // populate the directory still described as the empty Docker config.
                            runtimeBindings.requireCurrent()
                            return DerivedPreflight(
                                corpusSha256,
                                runtimeBindings.controlClientSha256,
                                bytes,
                            )
                        }
                    }
                }
            }
        }
    } catch (failure: LlvmBehaviorRuntimePreflightException) {
        throw failure
    } catch (failure: Exception) {
        preflightFail("cannot complete live LLVM runtime preflight", failure)
    }
}

private fun capturePinnedDockerRuntimeBindings(
    controlClientPath: Path,
    expectedControlClientBytes: Long,
    expectedControlClientSha256: String,
    maximumControlClientBytes: Long,
    dockerConfigPath: Path,
    runtimeSocketPath: Path,
): PinnedDockerRuntimeBindings = try {
    PinnedDockerRuntimeBindings.capture(
        controlClientPath = controlClientPath,
        expectedControlClientBytes = expectedControlClientBytes,
        expectedControlClientSha256 = expectedControlClientSha256,
        maximumControlClientBytes = maximumControlClientBytes,
        dockerConfigPath = dockerConfigPath,
        runtimeSocketPath = runtimeSocketPath,
    )
} catch (failure: PinnedDockerRuntimeBindingsException) {
    preflightFail(failure.message ?: "cannot capture pinned Docker runtime bindings", failure)
}

private class LiveRuntimeCommandExecutor(
    private val runtimeBindings: PinnedDockerRuntimeBindings,
    private val limits: LlvmBehaviorRuntimePreflightLimits,
) : RuntimeCommandExecutor {
    override fun run(id: RuntimeQueryId, arguments: List<String>): RuntimeCommandObservation {
        runtimeBindings.requireCurrent()
        val fullArguments = listOf(runtimeBindings.executableDescriptorPath.toString()) + arguments
        val result = try {
            LinuxBoundedSessionProcess.execute(
                LinuxBoundedSessionCommand(
                    arguments = fullArguments,
                    environment = runtimeBindings.environment,
                    timeout = Duration.ofMillis(limits.commandTimeoutMilliseconds),
                    maximumStdoutBytes = limits.maximumCommandStdoutBytes,
                    maximumStderrBytes = limits.maximumCommandStderrBytes,
                ),
            )
        } catch (failure: Exception) {
            try {
                runtimeBindings.requireCurrent()
            } catch (bindingFailure: Exception) {
                failure.addSuppressed(bindingFailure)
            }
            preflightFail("runtime ${id.label} query did not complete within its hard bounds", failure)
        }
        runtimeBindings.requireCurrent()
        return requireSuccessfulRuntimeCommand(id, arguments, result)
    }
}

private interface RuntimeCommandExecutor {
    fun run(id: RuntimeQueryId, arguments: List<String>): RuntimeCommandObservation
}

private enum class RuntimeQueryId(val jsonName: String, val label: String) {
    CLIENT_VERSION("client-version", "control-client version"),
    ENGINE_IDENTITY("engine-identity", "engine identity"),
    SECURITY_CAPABILITIES("security-capabilities", "security capability"),
    IMAGE_IDENTITY("image-identity", "image identity"),
}

private data class RuntimeCommandObservation(
    val id: RuntimeQueryId,
    val argumentsSha256: String,
    val stdout: ByteArray,
    val stdoutSha256: String,
    val stderrBytes: Int,
    val stderrSha256: String,
)

private data class RuntimeVerification(
    val observations: List<RuntimeCommandObservation>,
    val engine: ObservedEngineProfile,
    val imageEnvironmentSha256: String,
)

private fun verifyLiveRuntime(
    declaration: RuntimeDeclaration,
    executor: RuntimeCommandExecutor,
): RuntimeVerification {
    val observations = ArrayList<RuntimeCommandObservation>(4)
    val version = executor.run(RuntimeQueryId.CLIENT_VERSION, listOf("--version")).also(observations::add)
    verifyClientVersion(declaration, version.stdout)
    val identity = executor.run(
        RuntimeQueryId.ENGINE_IDENTITY,
        listOf("version", "--format", "{{json .Server}}"),
    ).also(observations::add)
    val observedIdentity = verifyEngineIdentity(declaration, identity.stdout)
    val security = executor.run(
        RuntimeQueryId.SECURITY_CAPABILITIES,
        listOf(
            "info",
            "--format",
            "{{json .SecurityOptions}}\n{{.CgroupVersion}}\n{{.CgroupDriver}}\n" +
                "{{.Driver}}\n{{json .Plugins.Volume}}\n{{json .Runtimes}}",
        ),
    ).also(observations::add)
    val observedEngine = verifySecurityCapabilities(declaration, observedIdentity, security.stdout)
    val image = executor.run(
        RuntimeQueryId.IMAGE_IDENTITY,
        listOf("image", "inspect", declaration.imageDigest),
    ).also(observations::add)
    val imageEnvironmentSha256 = verifyImageIdentity(declaration, image.stdout)
    if (observations.map { it.id } != RuntimeQueryId.entries) {
        preflightFail("runtime preflight command order is not the fixed four-query profile")
    }
    return RuntimeVerification(
        observations = Collections.unmodifiableList(observations),
        engine = observedEngine,
        imageEnvironmentSha256 = imageEnvironmentSha256,
    )
}

private fun requireSuccessfulRuntimeCommand(
    id: RuntimeQueryId,
    arguments: List<String>,
    result: LinuxBoundedSessionResult,
): RuntimeCommandObservation {
    if (result.signal != null || result.exitCode != 0) {
        val detail = strictUtf8(result.stderr, "runtime ${id.label} stderr").trim().take(512)
        preflightFail(
            "runtime ${id.label} query failed with exit=${result.exitCode}, signal=${result.signal}: $detail",
        )
    }
    return RuntimeCommandObservation(
        id = id,
        argumentsSha256 = compactAsciiSha256(arguments, includeFinalNewline = false),
        stdout = result.stdout.copyOf(),
        stdoutSha256 = OracleArtifacts.sha256(result.stdout),
        stderrBytes = result.stderr.size,
        stderrSha256 = OracleArtifacts.sha256(result.stderr),
    )
}

private fun verifyClientVersion(declaration: RuntimeDeclaration, stdout: ByteArray) {
    val actual = strictUtf8(stdout, "runtime control-client version")
    if (actual != declaration.controlClientVersion) {
        preflightFail("runtime control-client version does not match the authenticated corpus")
    }
}

private data class ObservedEngineIdentity(
    val product: String,
    val serverVersion: String,
    val serverCommit: String,
    val apiVersion: String,
    val operatingSystem: String,
    val architecture: String,
    val kernelVersion: String,
    val componentsSha256: String,
    val containerRuntimeVersion: String,
    val containerRuntimeCommit: String,
)

private data class ObservedEngineProfile(
    val identity: ObservedEngineIdentity,
    val cgroupVersion: Long,
    val cgroupDriver: String,
    val storageDriver: String,
    val securityOptions: List<String>,
    val containerRuntimePath: String,
    val containerRuntimeFeaturesSha256: String,
)

private fun verifyEngineIdentity(declaration: RuntimeDeclaration, stdout: ByteArray): ObservedEngineIdentity {
    val root = parseRuntimeJson(stdout, "container engine identity") as? JsonObject
        ?: preflightFail("container engine identity root must be an object")
    val components = root.runtimeArray("Components", "container engine identity")
    if (components.isEmpty() || components.size > 64) {
        preflightFail("container engine components must contain 1..64 records")
    }
    val normalized = ArrayList<Map<String, Any?>>(components.size)
    val named = linkedMapOf<String, JsonObject>()
    components.forEachIndexed { index, element ->
        val component = element as? JsonObject
            ?: preflightFail("container engine component $index must be an object")
        val label = "container engine component $index"
        val name = component.runtimeString("Name", label, 256)
        val version = component.runtimeString("Version", label, 256)
        val details = component.runtimeObject("Details", label)
        if (details.size > 64) preflightFail("$label details exceed 64 fields")
        if (named.put(name, component) != null) preflightFail("container engine components contain duplicate names")
        val stableDetails = linkedMapOf<String, String>()
        details.entries.sortedWith { left, right -> compareCodePoints(left.key, right.key) }
            .forEach { (detailName, rawValue) ->
                requireRuntimeString(detailName, "$label detail name", 256, allowEmpty = false)
                val detailValue = rawValue.runtimeString("$label.$detailName", 4096, allowEmpty = true)
                if ((name to detailName) !in COMPONENT_DETAIL_EXCLUSIONS) {
                    stableDetails[detailName] = detailValue
                }
            }
        normalized += linkedMapOf(
            "details" to stableDetails,
            "name" to name,
            "version" to version,
        )
    }
    normalized.sortWith { left, right -> compareCodePoints(left.getValue("name") as String, right.getValue("name") as String) }
    val componentsSha256 = compactAsciiSha256(normalized, includeFinalNewline = true)
    val engineComponent = named["Engine"] ?: preflightFail("container engine identity lacks Engine component")
    if (components.count { (it as? JsonObject)?.get("Name")?.runtimeStringOrNull() == "Engine" } != 1) {
        preflightFail("container engine identity must contain exactly one Engine component")
    }
    val kernel = root.runtimeString("KernelVersion", "container engine identity", 4096)
    val componentKernel = engineComponent.runtimeObject("Details", "container engine Engine")
        .runtimeString("KernelVersion", "container engine Engine details", 4096)
    if (componentKernel != kernel) preflightFail("container engine kernel versions disagree")
    val runtimeComponent = named[declaration.engine.containerRuntime]
        ?: preflightFail("container engine lacks configured runtime component")
    val observed = ObservedEngineIdentity(
        product = root.runtimeObject("Platform", "container engine identity")
            .runtimeString("Name", "container engine platform", 256),
        serverVersion = root.runtimeString("Version", "container engine identity", 256),
        serverCommit = root.runtimeString("GitCommit", "container engine identity", 256),
        apiVersion = root.runtimeString("ApiVersion", "container engine identity", 16),
        operatingSystem = root.runtimeString("Os", "container engine identity", 256),
        architecture = root.runtimeString("Arch", "container engine identity", 64),
        kernelVersion = kernel,
        componentsSha256 = componentsSha256,
        containerRuntimeVersion = runtimeComponent.runtimeString("Version", "container runtime component", 256),
        containerRuntimeCommit = runtimeComponent.runtimeObject("Details", "container runtime component")
            .runtimeString("GitCommit", "container runtime component details", 256),
    )
    if (observed.operatingSystem != "linux") {
        preflightFail("container engine does not provide the required Linux capabilities")
    }
    declaration.engine.requireIdentity(observed)
    return observed
}

private fun verifySecurityCapabilities(
    declaration: RuntimeDeclaration,
    identity: ObservedEngineIdentity,
    stdout: ByteArray,
): ObservedEngineProfile {
    val lines = strictUtf8(stdout, "container engine security information").trim().lines()
    if (lines.size != 6) preflightFail("container engine security information must contain exactly six lines")
    val securityOptions = parseRuntimeStringArray(lines[0].encodeToByteArray(), "container security options")
    val cgroupVersion = lines[1].trim().toLongOrNull()
        ?: preflightFail("container engine cgroup version is malformed")
    val cgroupDriver = requireRuntimeString(lines[2], "container engine cgroup driver", 256)
    val storageDriver = requireRuntimeString(lines[3], "container engine storage driver", 256)
    val volumePlugins = parseRuntimeStringArray(lines[4].encodeToByteArray(), "container volume plugins")
    val runtimes = parseRuntimeJson(lines[5].encodeToByteArray(), "container runtimes") as? JsonObject
        ?: preflightFail("container runtimes must be an object")
    val runtime = runtimes[declaration.engine.containerRuntime] as? JsonObject
        ?: preflightFail("container runtimes omit the configured runtime")
    val runtimePath = runtime.runtimeString("path", "configured container runtime", 256)
    val runtimeFeatures = runtime.runtimeObject("status", "configured container runtime")
        .runtimeString(
            "org.opencontainers.runtime-spec.features",
            "configured container runtime status",
            MAXIMUM_RUNTIME_FEATURE_BYTES,
            allowEmpty = true,
        )
    if (cgroupVersion != 2L) preflightFail("container engine does not expose cgroup v2 capability")
    if (!MANDATORY_SECURITY_OPTIONS.all(securityOptions::contains)) {
        preflightFail("container engine omits a mandatory sandbox security capability")
    }
    if (declaration.engine.volumePlugin !in volumePlugins) {
        preflightFail("container engine lacks the declared workspace volume plugin")
    }
    if (securityOptions.toSet().size != securityOptions.size) {
        preflightFail("container engine security options contain duplicates")
    }
    val observed = ObservedEngineProfile(
        identity = identity,
        cgroupVersion = cgroupVersion,
        cgroupDriver = cgroupDriver,
        storageDriver = storageDriver,
        securityOptions = securityOptions.sortedWith(::compareCodePoints),
        containerRuntimePath = runtimePath,
        containerRuntimeFeaturesSha256 = OracleArtifacts.sha256(runtimeFeatures.encodeToByteArray()),
    )
    declaration.engine.requireSecurity(observed)
    return observed
}

private fun verifyImageIdentity(declaration: RuntimeDeclaration, stdout: ByteArray): String {
    val records = parseRuntimeJson(stdout, "container image identity") as? JsonArray
        ?: preflightFail("container image identity root must be an array")
    if (records.size != 1) preflightFail("container image identity must contain exactly one record")
    val image = records.single() as? JsonObject ?: preflightFail("container image identity record must be an object")
    val imageId = image.runtimeString("Id", "container image identity", 71)
    val platform = image.runtimeString("Os", "container image identity", 32) + "/" +
        image.runtimeString("Architecture", "container image identity", 64)
    val config = image.runtimeObject("Config", "container image identity")
    val volumes = config["Volumes"]
    if (volumes != null && volumes != JsonNull && (volumes !is JsonObject || volumes.isNotEmpty())) {
        preflightFail("container image declares implicit volumes outside the closed mount set")
    }
    val environment = when (val raw = config["Env"]) {
        null, JsonNull -> emptyList()
        is JsonArray -> raw.mapIndexed { index, element ->
            element.runtimeString("container image environment $index", 16 * 1024, allowEmpty = true)
        }
        else -> preflightFail("container image environment must be an array or null")
    }
    if (imageId != declaration.imageDigest) preflightFail("container image ID differs from the corpus")
    if (platform != declaration.platform) preflightFail("container image platform differs from the corpus")
    if (environment != declaration.imageEnvironment) {
        preflightFail("container image prelaunch environment differs from the corpus")
    }
    return compactAsciiSha256(environment, includeFinalNewline = false)
}

private data class DeclaredEngineProfile(
    val product: String,
    val serverVersion: String,
    val serverCommit: String,
    val apiVersion: String,
    val operatingSystem: String,
    val architecture: String,
    val kernelVersion: String,
    val componentsSha256: String,
    val cgroupVersion: Long,
    val cgroupDriver: String,
    val storageDriver: String,
    val securityOptions: List<String>,
    val containerRuntime: String,
    val containerRuntimePath: String,
    val containerRuntimeVersion: String,
    val containerRuntimeCommit: String,
    val containerRuntimeFeaturesSha256: String,
    val volumePlugin: String,
) {
    fun requireIdentity(actual: ObservedEngineIdentity) {
        val mismatches = buildList {
            if (actual.product != product) add("product")
            if (actual.serverVersion != serverVersion) add("serverVersion")
            if (actual.serverCommit != serverCommit) add("serverCommit")
            if (actual.apiVersion != apiVersion) add("apiVersion")
            if (actual.operatingSystem != operatingSystem) add("operatingSystem")
            if (actual.architecture != architecture) add("architecture")
            if (actual.kernelVersion != kernelVersion) add("kernelVersion")
            if (actual.componentsSha256 != componentsSha256) add("componentsSha256")
            if (actual.containerRuntimeVersion != containerRuntimeVersion) add("containerRuntimeVersion")
            if (actual.containerRuntimeCommit != containerRuntimeCommit) add("containerRuntimeCommit")
        }
        if (mismatches.isNotEmpty()) {
            preflightFail("container engine identity differs from the exact corpus fields: ${mismatches.joinToString()}")
        }
    }

    fun requireSecurity(actual: ObservedEngineProfile) {
        val mismatches = buildList {
            if (actual.cgroupVersion != cgroupVersion) add("cgroupVersion")
            if (actual.cgroupDriver != cgroupDriver) add("cgroupDriver")
            if (actual.storageDriver != storageDriver) add("storageDriver")
            if (actual.securityOptions != securityOptions) add("securityOptions")
            if (actual.containerRuntimePath != containerRuntimePath) add("containerRuntimePath")
            if (actual.containerRuntimeFeaturesSha256 != containerRuntimeFeaturesSha256) {
                add("containerRuntimeFeaturesSha256")
            }
        }
        if (mismatches.isNotEmpty()) {
            preflightFail("container security capabilities differ from the exact corpus fields: ${mismatches.joinToString()}")
        }
    }
}

private data class RuntimeDeclaration(
    val corpusId: String,
    val sandbox: JsonObject,
    val sandboxSha256: String,
    val backend: String,
    val resourcePolicyVersion: Long,
    val isolation: String,
    val controlClientBytes: Long,
    val controlClientSha256: String,
    val controlClientVersion: String,
    val imageDigest: String,
    val platform: String,
    val imageEnvironment: List<String>,
    val engineObject: JsonObject,
    val engineSha256: String,
    val engine: DeclaredEngineProfile,
)

private fun parseRuntimeDeclaration(corpus: JsonObject): RuntimeDeclaration {
    val sandbox = corpus.preflightObject("sandbox", "behavior corpus")
    val client = sandbox.preflightObject("controlClient", "behavior corpus sandbox")
    val engineObject = sandbox.preflightObject("engineProfile", "behavior corpus sandbox")
    val securityOptions = engineObject.preflightArray("securityOptions", "behavior corpus engine profile")
        .mapIndexed { index, element -> element.preflightString("engine security option $index") }
    val imageEnvironment = sandbox.preflightArray("imageEnvironment", "behavior corpus sandbox")
        .mapIndexed { index, element -> element.preflightString("image environment $index") }
    return RuntimeDeclaration(
        corpusId = corpus.preflightString("id", "behavior corpus"),
        sandbox = sandbox,
        sandboxSha256 = canonicalPreflightSha256(sandbox),
        backend = sandbox.preflightString("backend", "behavior corpus sandbox"),
        resourcePolicyVersion = sandbox.preflightLong("resourcePolicyVersion", "behavior corpus sandbox"),
        isolation = sandbox.preflightString("isolation", "behavior corpus sandbox"),
        controlClientBytes = client.preflightLong("bytes", "behavior corpus control client"),
        controlClientSha256 = client.preflightString("sha256", "behavior corpus control client"),
        controlClientVersion = client.preflightString("version", "behavior corpus control client"),
        imageDigest = sandbox.preflightString("imageDigest", "behavior corpus sandbox"),
        platform = sandbox.preflightString("platform", "behavior corpus sandbox"),
        imageEnvironment = Collections.unmodifiableList(imageEnvironment),
        engineObject = engineObject,
        engineSha256 = canonicalPreflightSha256(engineObject),
        engine = DeclaredEngineProfile(
            product = engineObject.preflightString("product", "behavior corpus engine profile"),
            serverVersion = engineObject.preflightString("serverVersion", "behavior corpus engine profile"),
            serverCommit = engineObject.preflightString("serverCommit", "behavior corpus engine profile"),
            apiVersion = engineObject.preflightString("apiVersion", "behavior corpus engine profile"),
            operatingSystem = engineObject.preflightString("operatingSystem", "behavior corpus engine profile"),
            architecture = engineObject.preflightString("architecture", "behavior corpus engine profile"),
            kernelVersion = engineObject.preflightString("kernelVersion", "behavior corpus engine profile"),
            componentsSha256 = engineObject.preflightString("componentsSha256", "behavior corpus engine profile"),
            cgroupVersion = engineObject.preflightLong("cgroupVersion", "behavior corpus engine profile"),
            cgroupDriver = engineObject.preflightString("cgroupDriver", "behavior corpus engine profile"),
            storageDriver = engineObject.preflightString("storageDriver", "behavior corpus engine profile"),
            securityOptions = Collections.unmodifiableList(securityOptions),
            containerRuntime = engineObject.preflightString("containerRuntime", "behavior corpus engine profile"),
            containerRuntimePath = engineObject.preflightString(
                "containerRuntimePath",
                "behavior corpus engine profile",
            ),
            containerRuntimeVersion = engineObject.preflightString(
                "containerRuntimeVersion",
                "behavior corpus engine profile",
            ),
            containerRuntimeCommit = engineObject.preflightString(
                "containerRuntimeCommit",
                "behavior corpus engine profile",
            ),
            containerRuntimeFeaturesSha256 = engineObject.preflightString(
                "containerRuntimeFeaturesSha256",
                "behavior corpus engine profile",
            ),
            volumePlugin = engineObject.preflightString("volumePlugin", "behavior corpus engine profile"),
        ),
    )
}

private fun renderPreflightReceipt(
    declaration: RuntimeDeclaration,
    reference: LlvmBehaviorReferenceEvidence,
    verification: RuntimeVerification,
    runtimeBindings: PinnedDockerRuntimeBindings,
    limits: LlvmBehaviorRuntimePreflightLimits,
): ByteArray {
    val engine = verification.engine
    val identity = engine.identity
    val document = JsonObject(
        linkedMapOf(
            "authority" to JsonPrimitive(PREFLIGHT_AUTHORITY),
            "candidate" to JsonObject(
                linkedMapOf(
                    "executed" to JsonPrimitive(false),
                    "started" to JsonPrimitive(false),
                ),
            ),
            "controlClient" to JsonObject(
                linkedMapOf(
                    "bytes" to JsonPrimitive(runtimeBindings.controlClientBytes),
                    "executedFromPinnedDescriptor" to JsonPrimitive(true),
                    "identitySha256" to JsonPrimitive(runtimeBindings.controlClientIdentitySha256),
                    "sha256" to JsonPrimitive(runtimeBindings.controlClientSha256),
                    "versionSha256" to JsonPrimitive(
                        OracleArtifacts.sha256(declaration.controlClientVersion.encodeToByteArray()),
                    ),
                ),
            ),
            "corpus" to JsonObject(
                linkedMapOf(
                    "id" to JsonPrimitive(declaration.corpusId),
                    "sandboxSha256" to JsonPrimitive(declaration.sandboxSha256),
                    "sha256" to JsonPrimitive(reference.corpusSha256),
                ),
            ),
            "dockerConfig" to JsonObject(
                linkedMapOf(
                    "empty" to JsonPrimitive(true),
                    "identitySha256" to JsonPrimitive(runtimeBindings.dockerConfigIdentitySha256),
                    "mode" to JsonPrimitive("0o700"),
                    "pathSha256" to JsonPrimitive(runtimeBindings.dockerConfigPathSha256),
                ),
            ),
            "executionClaimed" to JsonPrimitive(false),
            "kind" to JsonPrimitive(PREFLIGHT_KIND),
            "oracleExpectationsExposed" to JsonPrimitive(false),
            "publication" to JsonObject(
                linkedMapOf(
                    "mechanism" to JsonPrimitive(PUBLICATION_MECHANISM),
                    "mode" to JsonPrimitive("0o400"),
                ),
            ),
            "queries" to JsonObject(
                linkedMapOf(
                    "commandCount" to JsonPrimitive(verification.observations.size),
                    "maximumStderrBytes" to JsonPrimitive(limits.maximumCommandStderrBytes),
                    "maximumStdoutBytes" to JsonPrimitive(limits.maximumCommandStdoutBytes),
                    "timeoutMilliseconds" to JsonPrimitive(limits.commandTimeoutMilliseconds),
                    "transcript" to JsonArray(verification.observations.map(::renderCommandObservation)),
                ),
            ),
            "referenceAuthentication" to JsonObject(
                linkedMapOf(
                    "artifactManifestSha256" to JsonPrimitive(reference.artifactManifestSha256),
                    "diagnosticMatrixSelfSha256" to JsonPrimitive(reference.diagnosticMatrixSelfSha256),
                    "diagnosticMatrixSha256" to JsonPrimitive(reference.diagnosticMatrixSha256),
                    "referenceReportSha256" to JsonPrimitive(reference.reportSha256),
                ),
            ),
            "releaseEligible" to JsonPrimitive(false),
            "runtime" to JsonObject(
                linkedMapOf(
                    "apiVersion" to JsonPrimitive(identity.apiVersion),
                    "architecture" to JsonPrimitive(identity.architecture),
                    "backend" to JsonPrimitive(declaration.backend),
                    "cgroupDriver" to JsonPrimitive(engine.cgroupDriver),
                    "cgroupVersion" to JsonPrimitive(engine.cgroupVersion),
                    "componentsSha256" to JsonPrimitive(identity.componentsSha256),
                    "containmentCapabilitiesVerified" to JsonPrimitive(true),
                    "containerRuntime" to JsonPrimitive(declaration.engine.containerRuntime),
                    "containerRuntimeCommit" to JsonPrimitive(identity.containerRuntimeCommit),
                    "containerRuntimeFeaturesSha256" to JsonPrimitive(engine.containerRuntimeFeaturesSha256),
                    "containerRuntimePath" to JsonPrimitive(engine.containerRuntimePath),
                    "containerRuntimeVersion" to JsonPrimitive(identity.containerRuntimeVersion),
                    "engineProfileSha256" to JsonPrimitive(declaration.engineSha256),
                    "imageDigest" to JsonPrimitive(declaration.imageDigest),
                    "imageEnvironmentSha256" to JsonPrimitive(verification.imageEnvironmentSha256),
                    "imageVerified" to JsonPrimitive(true),
                    "kernelVersion" to JsonPrimitive(identity.kernelVersion),
                    "liveContainmentVerified" to JsonPrimitive(false),
                    "liveRuntimeIdentityVerified" to JsonPrimitive(true),
                    "operatingSystem" to JsonPrimitive(identity.operatingSystem),
                    "platform" to JsonPrimitive(declaration.platform),
                    "product" to JsonPrimitive(identity.product),
                    "resourcePolicyVersion" to JsonPrimitive(declaration.resourcePolicyVersion),
                    "securityOptions" to JsonArray(engine.securityOptions.map(::JsonPrimitive)),
                    "serverCommit" to JsonPrimitive(identity.serverCommit),
                    "serverVersion" to JsonPrimitive(identity.serverVersion),
                    "storageDriver" to JsonPrimitive(engine.storageDriver),
                    "volumePlugin" to JsonPrimitive(declaration.engine.volumePlugin),
                ),
            ),
            "runtimeEndpoint" to JsonObject(
                linkedMapOf(
                    "identitySha256" to JsonPrimitive(runtimeBindings.runtimeSocketIdentitySha256),
                    "mode" to JsonPrimitive(runtimeBindings.runtimeSocketMode),
                    "parentIdentitySha256" to JsonPrimitive(runtimeBindings.runtimeSocketParentIdentitySha256),
                    "pathSha256" to JsonPrimitive(runtimeBindings.runtimeSocketPathSha256),
                    "scheme" to JsonPrimitive("unix"),
                ),
            ),
            "schemaVersion" to JsonPrimitive(1),
            "scoringAuthority" to JsonPrimitive(false),
        ),
    )
    try {
        OracleSchemas.validate(PREFLIGHT_SCHEMA, document)
    } catch (failure: Exception) {
        preflightFail("derived runtime preflight fails its bundled schema", failure)
    }
    return try {
        OracleJson.canonicalBytes(document, PREFLIGHT_JSON_LIMITS).also {
            if (it.size !in 1..MAXIMUM_PREFLIGHT_BYTES) preflightFail("runtime preflight exceeds its byte limit")
        }
    } catch (failure: LlvmBehaviorRuntimePreflightException) {
        throw failure
    } catch (failure: Exception) {
        preflightFail("runtime preflight cannot be canonically encoded", failure)
    }
}

private fun renderCommandObservation(value: RuntimeCommandObservation): JsonObject = JsonObject(
    linkedMapOf(
        "argumentsSha256" to JsonPrimitive(value.argumentsSha256),
        "exitCode" to JsonPrimitive(0),
        "id" to JsonPrimitive(value.id.jsonName),
        "signal" to JsonNull,
        "stderrBytes" to JsonPrimitive(value.stderrBytes),
        "stderrSha256" to JsonPrimitive(value.stderrSha256),
        "stdoutBytes" to JsonPrimitive(value.stdout.size),
        "stdoutSha256" to JsonPrimitive(value.stdoutSha256),
    ),
)

/**
 * Visibly non-authoritative response-parser seam. It cannot authenticate paths, execute a process,
 * publish a receipt, or return a production [LlvmBehaviorRuntimePreflight].
 */
internal data class NonAuthoritativeRuntimeResponse(
    val exitCode: Int? = 0,
    val signal: Int? = null,
    val stdout: ByteArray,
    val stderr: ByteArray = ByteArray(0),
)

internal data class NonAuthoritativeRuntimeVerification(
    val authority: Boolean,
    val queryIds: List<String>,
    val componentsSha256: String,
    val runtimeFeaturesSha256: String,
)

@JvmSynthetic
internal fun verifyRuntimeResponsesForNonAuthoritativeTest(
    corpus: JsonObject,
    responses: List<NonAuthoritativeRuntimeResponse>,
): NonAuthoritativeRuntimeVerification {
    if (responses.size != 4) preflightFail("non-authoritative runtime fixture must provide four responses")
    val declaration = parseRuntimeDeclaration(corpus)
    var offset = 0
    val executor = object : RuntimeCommandExecutor {
        override fun run(id: RuntimeQueryId, arguments: List<String>): RuntimeCommandObservation {
            val response = responses[offset++]
            return requireSuccessfulRuntimeCommand(
                id,
                arguments,
                LinuxBoundedSessionResult(
                    response.exitCode,
                    response.signal,
                    response.stdout.copyOf(),
                    response.stderr.copyOf(),
                ),
            )
        }
    }
    val verified = verifyLiveRuntime(declaration, executor)
    return NonAuthoritativeRuntimeVerification(
        authority = false,
        queryIds = Collections.unmodifiableList(verified.observations.map { it.id.jsonName }),
        componentsSha256 = verified.engine.identity.componentsSha256,
        runtimeFeaturesSha256 = verified.engine.containerRuntimeFeaturesSha256,
    )
}

@JvmSynthetic
internal fun runtimeCommandArgumentsForNonAuthoritativeTest(
    corpus: JsonObject,
    pinnedExecutablePath: Path,
): List<List<String>> {
    val declaration = parseRuntimeDeclaration(corpus)
    val executable = pinnedExecutablePath.toString()
    return listOf(
        listOf(executable, "--version"),
        listOf(executable, "version", "--format", "{{json .Server}}"),
        listOf(
            executable,
            "info",
            "--format",
            "{{json .SecurityOptions}}\n{{.CgroupVersion}}\n{{.CgroupDriver}}\n" +
                "{{.Driver}}\n{{json .Plugins.Volume}}\n{{json .Runtimes}}",
        ),
        listOf(executable, "image", "inspect", declaration.imageDigest),
    )
}

private fun normalizePreflightPaths(
    corpus: Path,
    report: Path,
    matrix: Path,
    manifest: Path,
    client: Path,
    config: Path,
    socket: Path,
    output: Path,
): PreflightPaths = PreflightPaths(
    corpus = requireAbsoluteNormalizedFilePath(corpus, "behavior corpus"),
    referenceReport = requireAbsoluteNormalizedFilePath(report, "reference report"),
    diagnosticMatrix = requireAbsoluteNormalizedFilePath(matrix, "diagnostic matrix"),
    artifactManifest = requireAbsoluteNormalizedFilePath(manifest, "artifact manifest"),
    controlClient = requireAbsoluteNormalizedFilePath(client, "runtime control client"),
    dockerConfig = requireAbsoluteNormalizedDirectoryPath(config, "Docker config directory"),
    runtimeSocket = requireAbsoluteNormalizedFilePath(socket, "runtime socket"),
    output = requireAbsoluteNormalizedFilePath(output, "runtime preflight output"),
)

private fun requireAbsoluteNormalizedFilePath(path: Path, label: String): Path {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        preflightFail("$label path must be absolute, normalized, and name a file")
    }
    return path
}

private fun requireAbsoluteNormalizedDirectoryPath(path: Path, label: String): Path {
    if (!path.isAbsolute || path.normalize() != path || path.fileName == null || path.parent == null) {
        preflightFail("$label path must be absolute, normalized, and name a non-root directory")
    }
    return path
}

private fun requireCanonicalDirectoryPath(path: Path, label: String) {
    val attributes = preflightFileAttributes(path, label)
    if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null || path.toRealPath() != path) {
        preflightFail("$label must be a canonical identified directory")
    }
}

private fun requireDistinctPreflightPaths(paths: PreflightPaths) {
    val files = listOf(
        "behavior corpus" to paths.corpus,
        "reference report" to paths.referenceReport,
        "diagnostic matrix" to paths.diagnosticMatrix,
        "artifact manifest" to paths.artifactManifest,
        "runtime control client" to paths.controlClient,
    )
    files.forEachIndexed { index, (leftLabel, left) ->
        files.drop(index + 1).forEach { (rightLabel, right) ->
            if (left == right || sameExistingPreflightFile(left, right)) {
                preflightFail("$leftLabel and $rightLabel must not alias")
            }
        }
        if (left == paths.output || sameExistingPreflightFile(left, paths.output)) {
            preflightFail("runtime preflight output must not alias $leftLabel")
        }
    }
    val runtimeDirectories = listOf(
        "runtime preflight output parent" to paths.output.parent,
        "Docker config directory" to paths.dockerConfig,
        "runtime socket parent" to paths.runtimeSocket.parent,
    )
    runtimeDirectories.forEachIndexed { index, (leftLabel, left) ->
        runtimeDirectories.drop(index + 1).forEach { (rightLabel, right) ->
            requireDistinctExistingPreflightDirectories(leftLabel, left, rightLabel, right)
        }
    }
    files.map { it.second.parent }.distinct().forEach { inputParent ->
        runtimeDirectories.forEach { (directoryLabel, directory) ->
            requireDistinctExistingPreflightDirectories(
                "authenticated input parent",
                inputParent,
                directoryLabel,
                directory,
            )
        }
    }
    if (paths.runtimeSocket == paths.output || sameExistingPreflightFile(paths.runtimeSocket, paths.output)) {
        preflightFail("runtime socket must not alias the output")
    }
    val temporary = paths.output.parent.resolve(
        DescriptorBoundAtomicStateFile.temporaryName(paths.output.fileName.toString()),
    )
    files.forEach { (label, input) ->
        if (sameExistingPreflightFile(input, temporary)) {
            preflightFail("runtime preflight temporary must not alias $label")
        }
    }
}

private fun requireDistinctExistingPreflightDirectories(
    leftLabel: String,
    left: Path,
    rightLabel: String,
    right: Path,
) {
    if (left == right || sameExistingPreflightFile(left, right)) {
        preflightFail("$leftLabel and $rightLabel must not alias")
    }
}

private fun requireDedicatedPreflightOutputParent(output: Path) {
    val parent = output.parent ?: preflightFail("runtime preflight output must have a parent")
    requireCanonicalDirectoryPath(parent, "runtime preflight output parent")
    val mode = (Files.getAttribute(parent, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    val uid = (Files.getAttribute(parent, "unix:uid", LinkOption.NOFOLLOW_LINKS) as Number).toInt()
    if (mode.permissions != OWNER_DIRECTORY_MODE || uid != currentUid()) {
        preflightFail("runtime preflight output parent must be current-user mode 0700")
    }
    val allowed = setOf(
        output.fileName.toString(),
        DescriptorBoundAtomicStateFile.temporaryName(output.fileName.toString()),
    )
    val entries = Files.newDirectoryStream(parent).use { stream -> stream.map { it.fileName.toString() }.toList() }
    if (entries.size > 1 || entries.any { it !in allowed }) {
        preflightFail("runtime preflight output parent is not dedicated to one receipt")
    }
}

private fun sameExistingPreflightFile(left: Path, right: Path): Boolean =
    Files.exists(left, LinkOption.NOFOLLOW_LINKS) && Files.exists(right, LinkOption.NOFOLLOW_LINKS) &&
        try {
            Files.isSameFile(left, right)
        } catch (failure: Exception) {
            preflightFail("cannot establish runtime preflight path alias identity", failure)
        }

private fun parsePreflightCorpus(bytes: ByteArray): JsonObject {
    val parsed = try {
        OracleJson.parseCanonical(bytes, CORPUS_JSON_LIMITS) as? JsonObject
            ?: preflightFail("LLVM behavior corpus root must be an object")
    } catch (failure: LlvmBehaviorRuntimePreflightException) {
        throw failure
    } catch (failure: Exception) {
        preflightFail("LLVM behavior corpus is not strict canonical bounded JSON", failure)
    }
    try {
        OracleSchemas.validate("behavior-corpus", parsed)
    } catch (failure: Exception) {
        preflightFail("LLVM behavior corpus fails its bundled schema", failure)
    }
    return parsed
}

private fun requireReferenceMatches(
    reference: LlvmBehaviorReferenceEvidence,
    corpusId: String,
    corpusSha256: String,
) {
    if (reference.corpusId != corpusId || reference.corpusSha256 != corpusSha256) {
        preflightFail("authenticated reference evidence differs from the pinned behavior corpus")
    }
}

private fun requireStableReferenceInputs(
    corpus: StableControlFile,
    report: StableControlFile,
    matrix: StableControlFile,
    manifest: StableControlFile,
) {
    corpus.verifyUnchanged("LLVM behavior corpus")
    report.verifyUnchanged("LLVM behavior reference report")
    matrix.verifyUnchanged("LLVM diagnostic matrix")
    manifest.verifyUnchanged("LLVM artifact manifest")
}

private fun samePreflightReference(
    left: LlvmBehaviorReferenceEvidence,
    right: LlvmBehaviorReferenceEvidence,
): Boolean =
    left.corpusId == right.corpusId && left.corpusSha256 == right.corpusSha256 &&
        left.reportSha256 == right.reportSha256 &&
        left.diagnosticMatrixSha256 == right.diagnosticMatrixSha256 &&
        left.diagnosticMatrixSelfSha256 == right.diagnosticMatrixSelfSha256 &&
        left.artifactManifestSha256 == right.artifactManifestSha256 &&
        left.executableBytes == right.executableBytes && left.executableSha256 == right.executableSha256 &&
        left.sandboxSha256 == right.sandboxSha256 && left.caseIds == right.caseIds &&
        left.diagnosticOwners == right.diagnosticOwners

private fun parseRuntimeJson(bytes: ByteArray, label: String): JsonElement {
    if (bytes.isEmpty()) preflightFail("$label is empty")
    return try {
        OracleJson.parse(bytes, RUNTIME_RESPONSE_JSON_LIMITS)
    } catch (failure: Exception) {
        preflightFail("$label is not strict bounded JSON", failure)
    }
}

private fun parseRuntimeStringArray(bytes: ByteArray, label: String): List<String> {
    val array = parseRuntimeJson(bytes, label) as? JsonArray ?: preflightFail("$label must be an array")
    if (array.size > MAXIMUM_RUNTIME_STRING_ARRAY_ITEMS) preflightFail("$label exceeds its item limit")
    return array.mapIndexed { index, value ->
        value.runtimeString("$label item $index", MAXIMUM_RUNTIME_STRING_BYTES, allowEmpty = true)
    }
}

private fun strictUtf8(bytes: ByteArray, label: String): String = try {
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: Exception) {
    preflightFail("$label is not UTF-8", failure)
}

private fun compactAsciiSha256(value: Any?, includeFinalNewline: Boolean): String {
    val encoder = CompactAsciiDigest(MAXIMUM_COMPACT_DIGEST_BYTES)
    encoder.write(value)
    if (includeFinalNewline) encoder.ascii("\n")
    return encoder.finish()
}

private class CompactAsciiDigest(private val maximumBytes: Long) {
    private val digest = MessageDigest.getInstance("SHA-256")
    private var bytes = 0L

    fun write(value: Any?) {
        when (value) {
            null -> ascii("null")
            is Boolean -> ascii(if (value) "true" else "false")
            is String -> string(value)
            is Byte, is Short, is Int, is Long -> ascii(value.toString())
            is Map<*, *> -> objectValue(value)
            is Iterable<*> -> arrayValue(value)
            else -> preflightFail("compact runtime commitment contains unsupported value")
        }
    }

    fun ascii(value: String) {
        val encoded = value.toByteArray(StandardCharsets.US_ASCII)
        if (bytes > maximumBytes - encoded.size.toLong()) {
            preflightFail("compact runtime commitment exceeds its byte limit")
        }
        bytes += encoded.size.toLong()
        digest.update(encoded)
    }

    fun finish(): String = digest.digest().joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private fun objectValue(value: Map<*, *>) {
        val entries = value.entries.map { entry ->
            val key = entry.key as? String ?: preflightFail("compact runtime commitment key is not a string")
            key to entry.value
        }.sortedWith { left, right -> compareCodePoints(left.first, right.first) }
        ascii("{")
        entries.forEachIndexed { index, (key, field) ->
            if (index > 0) ascii(",")
            string(key)
            ascii(":")
            write(field)
        }
        ascii("}")
    }

    private fun arrayValue(value: Iterable<*>) {
        ascii("[")
        value.forEachIndexed { index, element ->
            if (index > 0) ascii(",")
            write(element)
        }
        ascii("]")
    }

    /** Python json.dumps(ensure_ascii=True) escaping, including UTF-16 surrogate-pair output. */
    private fun string(value: String) {
        ascii("\"")
        value.forEach { current ->
            when (current) {
                '"' -> ascii("\\\"")
                '\\' -> ascii("\\\\")
                '\b' -> ascii("\\b")
                '\u000c' -> ascii("\\f")
                '\n' -> ascii("\\n")
                '\r' -> ascii("\\r")
                '\t' -> ascii("\\t")
                else -> if (current.code < 0x20 || current.code >= 0x80) {
                    ascii("\\u${current.code.toString(16).padStart(4, '0')}")
                } else {
                    ascii(current.toString())
                }
            }
        }
        ascii("\"")
    }
}

private fun compareCodePoints(left: String, right: String): Int {
    var leftOffset = 0
    var rightOffset = 0
    while (leftOffset < left.length && rightOffset < right.length) {
        val leftPoint = Character.codePointAt(left, leftOffset)
        val rightPoint = Character.codePointAt(right, rightOffset)
        if (leftPoint != rightPoint) return leftPoint.compareTo(rightPoint)
        leftOffset += Character.charCount(leftPoint)
        rightOffset += Character.charCount(rightPoint)
    }
    return (left.length - leftOffset).compareTo(right.length - rightOffset)
}

private fun canonicalPreflightSha256(value: JsonElement): String = try {
    OracleArtifacts.sha256(OracleJson.canonicalBytes(value, PREFLIGHT_JSON_LIMITS))
} catch (failure: Exception) {
    preflightFail("runtime declaration exceeds its canonical commitment bounds", failure)
}

private fun JsonObject.runtimeObject(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: preflightFail("$label $name must be an object")

private fun JsonObject.runtimeArray(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: preflightFail("$label $name must be an array")

private fun JsonObject.runtimeString(
    name: String,
    label: String,
    maximumBytes: Int,
    allowEmpty: Boolean = false,
): String = (this[name] ?: preflightFail("$label is missing $name"))
    .runtimeString("$label $name", maximumBytes, allowEmpty)

private fun JsonElement.runtimeString(label: String, maximumBytes: Int, allowEmpty: Boolean = false): String {
    val primitive = this as? JsonPrimitive ?: preflightFail("$label must be a string")
    if (!primitive.isString) preflightFail("$label must be a string")
    return requireRuntimeString(primitive.content, label, maximumBytes, allowEmpty)
}

private fun JsonElement.runtimeStringOrNull(): String? {
    val primitive = this as? JsonPrimitive ?: return null
    return if (primitive.isString) primitive.content else null
}

private fun requireRuntimeString(
    value: String,
    label: String,
    maximumBytes: Int,
    allowEmpty: Boolean = false,
): String {
    val size = value.toByteArray(StandardCharsets.UTF_8).size
    if ((!allowEmpty && value.isEmpty()) || size > maximumBytes || value.any { it == '\u0000' }) {
        preflightFail("$label is outside its string bounds")
    }
    return value
}

private fun JsonObject.preflightObject(name: String, label: String): JsonObject =
    this[name] as? JsonObject ?: preflightFail("$label $name must be an object")

private fun JsonObject.preflightArray(name: String, label: String): JsonArray =
    this[name] as? JsonArray ?: preflightFail("$label $name must be an array")

private fun JsonObject.preflightString(name: String, label: String): String =
    (this[name] ?: preflightFail("$label is missing $name")).preflightString("$label $name")

private fun JsonElement.preflightString(label: String): String {
    val primitive = this as? JsonPrimitive ?: preflightFail("$label must be a string")
    if (!primitive.isString) preflightFail("$label must be a string")
    return primitive.content
}

private fun JsonObject.preflightLong(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: preflightFail("$label $name must be an integer")
    if (primitive.isString || primitive.content.any { it in ".eE" }) {
        preflightFail("$label $name must be an integer")
    }
    return primitive.longOrNull ?: preflightFail("$label $name exceeds the integer range")
}

private fun preflightFileAttributes(path: Path, label: String): BasicFileAttributes = try {
    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
} catch (failure: Exception) {
    preflightFail("$label metadata is unavailable", failure)
}

private fun currentUid(): Int =
    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()

private fun Long.toPreflightInt(label: String): Int {
    if (this !in 1L..Int.MAX_VALUE.toLong()) preflightFail("$label exceeds its in-memory bound")
    return toInt()
}

private fun preflightFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorRuntimePreflightException(message, cause)

private data class PreflightPaths(
    val corpus: Path,
    val referenceReport: Path,
    val diagnosticMatrix: Path,
    val artifactManifest: Path,
    val controlClient: Path,
    val dockerConfig: Path,
    val runtimeSocket: Path,
    val output: Path,
)

private data class DerivedPreflight(
    val corpusSha256: String,
    val controlClientSha256: String,
    val bytes: ByteArray,
)

private val COMPONENT_DETAIL_EXCLUSIONS = setOf(
    "Engine" to "KernelVersion",
    "rootlesskit" to "StateDir",
)
private val MANDATORY_SECURITY_OPTIONS = setOf(
    "name=cgroupns",
    "name=rootless",
    "name=seccomp,profile=builtin",
)
private val CORPUS_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 16 * 1024 * 1024,
    maximumCanonicalBytes = 16 * 1024 * 1024,
    maximumDepth = 64,
    maximumNodes = 250_000,
    maximumStringBytes = 1024 * 1024,
    maximumTotalStringBytes = 16 * 1024 * 1024,
)
private val RUNTIME_RESPONSE_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 1024 * 1024,
    maximumCanonicalBytes = 1024 * 1024,
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 1024 * 1024,
)
private val PREFLIGHT_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 1024 * 1024,
    maximumCanonicalBytes = 1024 * 1024,
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 1024 * 1024,
)
private const val PREFLIGHT_SCHEMA = "llvm-behavior-runtime-preflight"
private const val PREFLIGHT_KIND = "llvm-behavior-runtime-preflight"
private const val PREFLIGHT_AUTHORITY = "kotlin-host-live-runtime-preflight-v1"
private const val PUBLICATION_MECHANISM = "descriptor-bound-no-replace"
private const val MAXIMUM_PREFLIGHT_BYTES = 1024 * 1024
private const val MAXIMUM_RUNTIME_FEATURE_BYTES = 256 * 1024
private const val MAXIMUM_RUNTIME_STRING_BYTES = 16 * 1024
private const val MAXIMUM_RUNTIME_STRING_ARRAY_ITEMS = 256
private const val MAXIMUM_COMPACT_DIGEST_BYTES = 1024L * 1024L
private const val OWNER_DIRECTORY_MODE = 0x1c0 // 0700
