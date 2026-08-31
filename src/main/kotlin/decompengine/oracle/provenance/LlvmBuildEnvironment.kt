package decompengine.oracle.provenance

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.time.Duration
import java.util.Collections
import java.util.LinkedHashMap
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.system.exitProcess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class LlvmBuildEnvironmentException(
    message: String,
    cause: Throwable? = null,
) : IllegalArgumentException(message, cause)

internal data class LlvmBuildOracleV1(
    val id: String,
    val sourceProfileId: String,
    val version: String,
    val sourceRevision: String,
    val sourceLockSha256: String,
)

internal data class LlvmBuildContainerV1(
    val image: String,
    val digest: String,
    val platform: String,
)

internal data class LlvmBuildEnvironmentV1(
    val container: LlvmBuildContainerV1,
    val variables: Map<String, String>,
)

internal data class LlvmBuildDirectoriesV1(
    val source: String,
    val build: String,
    val install: String,
)

internal data class LlvmBuildCommandsV1(
    val configure: List<String>,
    val compile: List<String>,
    val install: List<String>,
    val stageFull: List<String>,
    val strip: List<String>,
)

internal data class LlvmBuildToolV1(
    val role: String,
    val path: String,
    val versionCommand: List<String>,
    val versionOutput: String,
    val executableBytes: Long,
    val executableSha256: String,
)

internal data class LlvmBuildOutputsV1(
    val full: String,
    val stripped: String,
)

internal data class LlvmBuildRecordV1(
    val schemaVersion: Int,
    val buildSystem: String,
    val oracle: LlvmBuildOracleV1,
    val environment: LlvmBuildEnvironmentV1,
    val directories: LlvmBuildDirectoriesV1,
    val commands: LlvmBuildCommandsV1,
    val tools: List<LlvmBuildToolV1>,
    val outputs: LlvmBuildOutputsV1,
)

internal sealed interface LlvmBuildEnvironmentVerification {
    val sourceLockPath: Path
    val sourceLockSha256: String
    val buildRecordPath: Path
    val buildRecordSha256: String
    val recordedOriginDigest: String
    val record: LlvmBuildRecordV1
}

/** Deliberately non-authoritative result exposed only to exercise injected validation seams. */
internal data class LlvmBuildEnvironmentAssessment(
    val sourceLockPath: Path,
    val sourceLockSha256: String,
    val buildRecordPath: Path,
    val buildRecordSha256: String,
    val recordedOriginDigest: String,
    val record: LlvmBuildRecordV1,
)

internal data class LlvmBuildPlatform(
    val operatingSystem: String,
    val architecture: String,
)

internal fun interface LlvmBuildPlatformAuthority {
    fun current(): LlvmBuildPlatform
}

internal data class LlvmToolVersionProcessRequest(
    val command: List<String>,
    val environment: Map<String, String>,
    val workingDirectory: Path,
    val timeout: Duration,
    val maximumOutputBytes: Int,
    val cleanupTimeout: Duration,
)

internal class LlvmToolVersionProcessResult(
    val exitCode: Int,
    combinedOutput: ByteArray,
) {
    private val storedOutput = combinedOutput.copyOf()
    val output: ByteArray
        get() = storedOutput.copyOf()
}

internal fun interface LlvmToolVersionProcessRunner {
    fun run(request: LlvmToolVersionProcessRequest): LlvmToolVersionProcessResult
}

internal enum class LlvmBuildVerificationPoint {
    AFTER_INPUTS_AUTHENTICATED,
    AFTER_TOOLS_AUTHENTICATED,
    AFTER_TOOL_EXECUTION,
    BEFORE_TERMINAL_REAUTHENTICATION,
}

internal fun interface LlvmBuildVerificationFaultInjector {
    fun hit(point: LlvmBuildVerificationPoint, role: String?)
}

internal fun interface LlvmBuildSourceLockAuthority {
    fun verify(path: Path): LlvmSourceLockVerification
}

/**
 * Live LLVM build-record verifier with descriptor-pinned inputs and tools.
 *
 * The production boundary assumes a read-only build container. It detects every pathname,
 * descriptor, size, permission, and content change observable at its checkpoints, but it does not
 * claim exclusion from a cooperating same-UID/root writer that can mutate and perfectly restore
 * bytes between checks. Commands are executed directly, never through a shell selected by this
 * verifier, and the returned value is in-memory evidence only. Its digest argument is the
 * historical recorded-origin digest from the reproduction lock; authenticating the distinct fresh
 * image ID is a required preceding operation of [LlvmToolchainReproductionVerifier].
 */
private class LlvmBuildEnvironmentEngine(
    private val sourceLockAuthority: LlvmBuildSourceLockAuthority,
    private val platformAuthority: LlvmBuildPlatformAuthority,
    private val processRunner: LlvmToolVersionProcessRunner,
    private val faultInjector: LlvmBuildVerificationFaultInjector? = null,
) {
    fun assess(
        sourceLockPath: Path,
        buildRecordPath: Path,
        recordedOriginDigest: String,
    ): LlvmBuildEnvironmentAssessment = translateBuildFailure {
        requireImageDigest(recordedOriginDigest, "recorded-origin container")
        PinnedBuildFile.open(
            sourceLockPath,
            MAXIMUM_SOURCE_LOCK_BYTES,
            "LLVM source lock",
            executable = false,
        ).use { sourceInput ->
            PinnedBuildFile.open(
                buildRecordPath,
                MAXIMUM_BUILD_RECORD_BYTES,
                "LLVM build record",
                executable = false,
            ).use { buildInput ->
                val sourceBytes = sourceInput.readComplete()
                val sourceSha256 = sourceBytes.sha256()
                val buildBytes = buildInput.readComplete()
                val buildSha256 = buildBytes.sha256()
                sourceInput.requireCurrent(sourceSha256, sourceBytes.size.toLong())
                buildInput.requireCurrent(buildSha256, buildBytes.size.toLong())

                val sourceLock = verifySourceLock(sourceInput.path, sourceSha256)
                sourceInput.requireCurrent(sourceSha256, sourceBytes.size.toLong())
                buildInput.requireCurrent(buildSha256, buildBytes.size.toLong())
                val record = LlvmBuildRecordParser.parse(buildBytes, sourceLock, sourceSha256)
                if (record.environment.container.digest != recordedOriginDigest) {
                    buildFail(
                        "build container recorded-origin digest mismatch: build record " +
                            "${record.environment.container.digest}, expected $recordedOriginDigest",
                    )
                }
                requirePlatform(platformAuthority.current())
                faultInjector?.hit(LlvmBuildVerificationPoint.AFTER_INPUTS_AUTHENTICATED, null)
                sourceInput.requireCurrent(sourceSha256, sourceBytes.size.toLong())
                buildInput.requireCurrent(buildSha256, buildBytes.size.toLong())

                val pinnedTools = ArrayList<Pair<LlvmBuildToolV1, PinnedBuildFile>>(record.tools.size)
                try {
                    record.tools.forEach { tool ->
                        if (tool.executableBytes > MAXIMUM_TOOL_BYTES) {
                            buildFail("${tool.role} executable exceeds its byte bound")
                        }
                        val pinned = PinnedBuildFile.open(
                            Path.of(tool.path),
                            MAXIMUM_TOOL_BYTES,
                            "${tool.role} executable",
                            executable = true,
                        )
                        try {
                            pinned.requireCurrent(tool.executableSha256, tool.executableBytes)
                            pinnedTools += tool to pinned
                        } catch (failure: Throwable) {
                            pinned.close()
                            throw failure
                        }
                    }
                    faultInjector?.hit(LlvmBuildVerificationPoint.AFTER_TOOLS_AUTHENTICATED, null)
                    requireAllCurrent(
                        sourceInput,
                        sourceSha256,
                        sourceBytes.size.toLong(),
                        buildInput,
                        buildSha256,
                        buildBytes.size.toLong(),
                        pinnedTools,
                    )

                    val processEnvironment = buildMap {
                        putAll(record.environment.variables)
                        put("PATH", DETERMINISTIC_PATH)
                    }.toSortedMap()
                    pinnedTools.forEach { (tool, pinned) ->
                        requireAllCurrent(
                            sourceInput,
                            sourceSha256,
                            sourceBytes.size.toLong(),
                            buildInput,
                            buildSha256,
                            buildBytes.size.toLong(),
                            pinnedTools,
                        )
                        val request = LlvmToolVersionProcessRequest(
                            command = tool.versionCommand,
                            environment = processEnvironment,
                            workingDirectory = ROOT_DIRECTORY,
                            timeout = VERSION_TIMEOUT,
                            maximumOutputBytes = MAXIMUM_VERSION_OUTPUT_BYTES,
                            cleanupTimeout = PROCESS_CLEANUP_TIMEOUT,
                        )
                        val result = runWithPostAuthentication(
                            tool,
                            pinned,
                            sourceInput,
                            sourceSha256,
                            sourceBytes.size.toLong(),
                            buildInput,
                            buildSha256,
                            buildBytes.size.toLong(),
                        ) { processRunner.run(request) }
                        if (result.exitCode != 0) {
                            buildFail("${tool.role} version command failed with exit code ${result.exitCode}")
                        }
                        if (result.output.size > MAXIMUM_VERSION_OUTPUT_BYTES) {
                            buildFail("${tool.role} version command exceeded its output-byte bound")
                        }
                        val output = decodeUtf8(result.output, "${tool.role} version output")
                        if (output != tool.versionOutput) {
                            buildFail("${tool.role} version output differs from its build record")
                        }
                    }

                    faultInjector?.hit(LlvmBuildVerificationPoint.BEFORE_TERMINAL_REAUTHENTICATION, null)
                    requireAllCurrent(
                        sourceInput,
                        sourceSha256,
                        sourceBytes.size.toLong(),
                        buildInput,
                        buildSha256,
                        buildBytes.size.toLong(),
                        pinnedTools,
                    )
                    val terminalSource = verifySourceLock(sourceInput.path, sourceSha256)
                    requireSameSourceLock(sourceLock, terminalSource)
                    requireAllCurrent(
                        sourceInput,
                        sourceSha256,
                        sourceBytes.size.toLong(),
                        buildInput,
                        buildSha256,
                        buildBytes.size.toLong(),
                        pinnedTools,
                    )
                    LlvmBuildEnvironmentAssessment(
                        sourceLockPath = sourceInput.path,
                        sourceLockSha256 = sourceSha256,
                        buildRecordPath = buildInput.path,
                        buildRecordSha256 = buildSha256,
                        recordedOriginDigest = recordedOriginDigest,
                        record = record,
                    )
                } finally {
                    pinnedTools.asReversed().forEach { (_, pinned) -> pinned.close() }
                }
            }
        }
    }

    private fun verifySourceLock(path: Path, expectedSha256: String): LlvmSourceLockVerification {
        val verified = try {
            sourceLockAuthority.verify(path)
        } catch (failure: LlvmBuildEnvironmentException) {
            throw failure
        } catch (failure: Exception) {
            throw LlvmBuildEnvironmentException("LLVM source lock verification failed", failure)
        }
        if (verified.path.toAbsolutePath().normalize() != path || verified.lockSha256 != expectedSha256) {
            buildFail("LLVM source-lock authority returned a different pinned identity")
        }
        return verified
    }

    private fun runWithPostAuthentication(
        tool: LlvmBuildToolV1,
        pinned: PinnedBuildFile,
        sourceInput: PinnedBuildFile,
        sourceSha256: String,
        sourceBytes: Long,
        buildInput: PinnedBuildFile,
        buildSha256: String,
        buildBytes: Long,
        execute: () -> LlvmToolVersionProcessResult,
    ): LlvmToolVersionProcessResult {
        var executionFailure: Throwable? = null
        var result: LlvmToolVersionProcessResult? = null
        try {
            result = execute()
        } catch (failure: Throwable) {
            executionFailure = failure
        }
        var authenticationFailure: Throwable? = null
        try {
            faultInjector?.hit(LlvmBuildVerificationPoint.AFTER_TOOL_EXECUTION, tool.role)
            pinned.requireCurrent(tool.executableSha256, tool.executableBytes)
            sourceInput.requireCurrent(sourceSha256, sourceBytes)
            buildInput.requireCurrent(buildSha256, buildBytes)
        } catch (failure: Throwable) {
            authenticationFailure = failure
        }
        if (executionFailure != null) {
            if (authenticationFailure != null) executionFailure.addSuppressed(authenticationFailure)
            throw executionFailure
        }
        if (authenticationFailure != null) throw authenticationFailure
        return result ?: buildFail("${tool.role} version command returned no result")
    }

    private fun requireAllCurrent(
        sourceInput: PinnedBuildFile,
        sourceSha256: String,
        sourceBytes: Long,
        buildInput: PinnedBuildFile,
        buildSha256: String,
        buildBytes: Long,
        tools: List<Pair<LlvmBuildToolV1, PinnedBuildFile>>,
    ) {
        sourceInput.requireCurrent(sourceSha256, sourceBytes)
        buildInput.requireCurrent(buildSha256, buildBytes)
        tools.forEach { (tool, pinned) ->
            pinned.requireCurrent(tool.executableSha256, tool.executableBytes)
        }
    }

    private fun requireSameSourceLock(
        initial: LlvmSourceLockVerification,
        terminal: LlvmSourceLockVerification,
    ) {
        if (
            initial.path != terminal.path || initial.lockSha256 != terminal.lockSha256 ||
            initial.oracleId != terminal.oracleId || initial.version != terminal.version ||
            initial.archiveRoot != terminal.archiveRoot || initial.tag != terminal.tag ||
            initial.tagObject != terminal.tagObject || initial.commit != terminal.commit ||
            initial.archive != terminal.archive || initial.detachedSignature != terminal.detachedSignature ||
            initial.archiveContents != terminal.archiveContents ||
            initial.signingKeySha256 != terminal.signingKeySha256 ||
            initial.signingFingerprint != terminal.signingFingerprint
        ) {
            buildFail("LLVM source-lock semantics changed during build-environment verification")
        }
    }
}

/** Constructorless production authority: no source-lock, platform, process, or fault seam is accepted. */
internal object LlvmBuildEnvironmentVerifier {
    private class AuthenticatedVerification private constructor(
        sourceLockPath: Path,
        buildRecordPath: Path,
        recordedOriginDigest: String,
    ) : LlvmBuildEnvironmentVerification {
        /**
         * Keep the fixed production assessment inside the constructor. Kotlin emits a public
         * synthetic bridge for a private constructor called from the enclosing object; accepting
         * only these three untrusted production inputs makes that bridge no more privileged than
         * [LlvmBuildEnvironmentVerifier.verify]. In particular, it cannot accept injected evidence,
         * a parsed record, or any validation seam.
         */
        private val assessment = LlvmBuildEnvironmentEngine(
            sourceLockAuthority = LlvmBuildSourceLockAuthority { LlvmSourceLockVerifier().verify(it) },
            platformAuthority = LlvmBuildPlatformAuthority {
                LlvmBuildPlatform(
                    System.getProperty("os.name", ""),
                    System.getProperty("os.arch", ""),
                )
            },
            processRunner = JvmLlvmToolVersionProcessRunner,
            faultInjector = null,
        ).assess(sourceLockPath, buildRecordPath, recordedOriginDigest)

        override val sourceLockPath: Path = assessment.sourceLockPath
        override val sourceLockSha256: String = assessment.sourceLockSha256
        override val buildRecordPath: Path = assessment.buildRecordPath
        override val buildRecordSha256: String = assessment.buildRecordSha256
        override val recordedOriginDigest: String = assessment.recordedOriginDigest
        override val record: LlvmBuildRecordV1 = assessment.record

        companion object {
            fun verify(
                sourceLockPath: Path,
                buildRecordPath: Path,
                recordedOriginDigest: String,
            ): LlvmBuildEnvironmentVerification = AuthenticatedVerification(
                sourceLockPath,
                buildRecordPath,
                recordedOriginDigest,
            )
        }
    }

    fun verify(
        sourceLockPath: Path,
        buildRecordPath: Path,
        recordedOriginDigest: String,
    ): LlvmBuildEnvironmentVerification = AuthenticatedVerification.verify(
        sourceLockPath,
        buildRecordPath,
        recordedOriginDigest,
    )
}

/** Test-only behavioral seam. Its result cannot be converted into authority-bearing verification. */
internal object LlvmBuildEnvironmentTestSupport {
    fun assess(
        sourceLockPath: Path,
        buildRecordPath: Path,
        recordedOriginDigest: String,
        sourceLockAuthority: LlvmBuildSourceLockAuthority = LlvmBuildSourceLockAuthority {
            LlvmSourceLockVerifier().verify(it)
        },
        platformAuthority: LlvmBuildPlatformAuthority,
        processRunner: LlvmToolVersionProcessRunner,
        faultInjector: LlvmBuildVerificationFaultInjector? = null,
    ): LlvmBuildEnvironmentAssessment = LlvmBuildEnvironmentEngine(
        sourceLockAuthority,
        platformAuthority,
        processRunner,
        faultInjector,
    ).assess(sourceLockPath, buildRecordPath, recordedOriginDigest)
}

internal object JvmLlvmToolVersionProcessRunner : LlvmToolVersionProcessRunner {
    override fun run(request: LlvmToolVersionProcessRequest): LlvmToolVersionProcessResult {
        if (request.command.isEmpty() || request.command.first().isEmpty()) {
            buildFail("tool version command is empty")
        }
        if (!request.workingDirectory.isAbsolute || request.workingDirectory.normalize() != request.workingDirectory) {
            buildFail("tool version working directory is not absolute and normalized")
        }
        if (request.timeout.isZero || request.timeout.isNegative ||
            request.cleanupTimeout.isZero || request.cleanupTimeout.isNegative
        ) {
            buildFail("tool version process deadlines are invalid")
        }
        if (request.maximumOutputBytes <= 0) buildFail("tool version output-byte bound is empty")

        val process = try {
            ProcessBuilder(request.command)
                .redirectErrorStream(true)
                .directory(request.workingDirectory.toFile())
                .also { builder ->
                    builder.environment().clear()
                    builder.environment().putAll(request.environment)
                }
                .start()
        } catch (failure: IOException) {
            throw LlvmBuildEnvironmentException("could not start tool version command", failure)
        }
        runCatching { process.outputStream.close() }

        val output = ByteArrayOutputStream(minOf(request.maximumOutputBytes, PROCESS_BUFFER_BYTES))
        val overflow = AtomicBoolean(false)
        val readerFailure = AtomicReference<Throwable?>(null)
        val reader = Thread.ofPlatform().daemon(true).name("llvm-tool-version-output").start {
            try {
                val buffer = ByteArray(PROCESS_BUFFER_BYTES)
                while (true) {
                    val count = process.inputStream.read(buffer)
                    if (count < 0) break
                    if (count == 0) continue
                    if (output.size() > request.maximumOutputBytes - count) {
                        overflow.set(true)
                        process.destroyForcibly()
                        break
                    }
                    output.write(buffer, 0, count)
                }
            } catch (failure: Throwable) {
                readerFailure.set(failure)
            }
        }

        var primaryFailure: LlvmBuildEnvironmentException? = null
        var exited = false
        val deadline = deadlineAfter(request.timeout)
        try {
            while (!exited && primaryFailure == null) {
                if (overflow.get()) {
                    primaryFailure = LlvmBuildEnvironmentException("tool version command exceeded its output-byte bound")
                    break
                }
                readerFailure.get()?.let { failure ->
                    primaryFailure = LlvmBuildEnvironmentException("could not read tool version output", failure)
                    break
                }
                val remaining = deadline - System.nanoTime()
                if (remaining <= 0L) {
                    primaryFailure = LlvmBuildEnvironmentException("tool version command exceeded its deadline")
                    break
                }
                exited = process.waitFor(
                    minOf(remaining, PROCESS_POLL_NANOS),
                    TimeUnit.NANOSECONDS,
                )
            }
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            primaryFailure = LlvmBuildEnvironmentException("tool version command wait was interrupted", failure)
        }

        if (primaryFailure != null) {
            cleanupProcess(process, reader, request.cleanupTimeout)?.let(primaryFailure::addSuppressed)
            throw primaryFailure
        }
        val cleanupNanos = request.cleanupTimeout.toNanosSaturated()
        try {
            reader.join(TimeUnit.NANOSECONDS.toMillis(cleanupNanos).coerceAtLeast(1L))
        } catch (failure: InterruptedException) {
            Thread.currentThread().interrupt()
            val interrupted = LlvmBuildEnvironmentException("tool version output cleanup was interrupted", failure)
            cleanupProcess(process, reader, request.cleanupTimeout)?.let(interrupted::addSuppressed)
            throw interrupted
        }
        if (reader.isAlive) {
            val failure = LlvmBuildEnvironmentException("tool version output did not close within its cleanup bound")
            cleanupProcess(process, reader, request.cleanupTimeout)?.let(failure::addSuppressed)
            throw failure
        }
        readerFailure.get()?.let { failure ->
            throw LlvmBuildEnvironmentException("could not read tool version output", failure)
        }
        if (overflow.get()) buildFail("tool version command exceeded its output-byte bound")
        return LlvmToolVersionProcessResult(process.exitValue(), output.toByteArray())
    }

    private fun cleanupProcess(process: Process, reader: Thread, timeout: Duration): Throwable? = try {
        val descendants = process.descendants().use { stream ->
            stream.limit((MAXIMUM_CLEANUP_DESCENDANTS + 1).toLong()).toList()
        }
        descendants.asReversed().forEach { handle -> runCatching { handle.destroyForcibly() } }
        runCatching { process.destroyForcibly() }
        val timeoutMillis = TimeUnit.NANOSECONDS.toMillis(timeout.toNanosSaturated()).coerceAtLeast(1L)
        runCatching { process.waitFor(timeoutMillis, TimeUnit.MILLISECONDS) }
        runCatching { process.inputStream.close() }
        runCatching { process.errorStream.close() }
        reader.join(timeoutMillis)
        when {
            descendants.size > MAXIMUM_CLEANUP_DESCENDANTS ->
                LlvmBuildEnvironmentException("tool version process exceeded its descendant cleanup bound")
            process.isAlive -> LlvmBuildEnvironmentException("tool version process survived bounded cleanup")
            reader.isAlive -> LlvmBuildEnvironmentException("tool version output reader survived bounded cleanup")
            else -> null
        }
    } catch (failure: Throwable) {
        if (failure is InterruptedException) Thread.currentThread().interrupt()
        failure
    }

    private fun deadlineAfter(timeout: Duration): Long {
        val now = System.nanoTime()
        val nanos = timeout.toNanosSaturated()
        return if (nanos >= Long.MAX_VALUE - now) Long.MAX_VALUE else now + nanos
    }
}

internal object LlvmBuildRecordParser {
    fun parse(
        bytes: ByteArray,
        sourceLock: LlvmSourceLockVerification,
        sourceLockSha256: String,
    ): LlvmBuildRecordV1 {
        val root = try {
            OracleJson.parseCanonical(bytes, BUILD_JSON_LIMITS) as? JsonObject
                ?: buildFail("LLVM build-record root must be an object")
        } catch (failure: LlvmBuildEnvironmentException) {
            throw failure
        } catch (failure: Exception) {
            throw LlvmBuildEnvironmentException("LLVM build record is not strict bounded canonical JSON", failure)
        }
        try {
            OracleSchemas.validate("build-record", root)
        } catch (failure: Exception) {
            throw LlvmBuildEnvironmentException("LLVM build record fails its bundled schema", failure)
        }

        val schemaVersion = root.requiredInteger("schemaVersion", "LLVM build record").toInt()
        if (schemaVersion !in 1..3) buildFail("build record schemaVersion must be the integer 1, 2, or 3")
        val rootFields = linkedSetOf(
            "schemaVersion",
            "oracle",
            "environment",
            "directories",
            "commands",
            "tools",
            "outputs",
        ).also { if (schemaVersion >= 2) it += "buildSystem" }
        root.requireExactFields(rootFields, "LLVM build record")
        val buildSystem = if (schemaVersion == 1) {
            "autoconf"
        } else {
            root.requiredString("buildSystem", "LLVM build record")
        }
        if (buildSystem !in setOf("autoconf", "cmake-ninja")) {
            buildFail("build record buildSystem must be autoconf or cmake-ninja")
        }

        val oracleObject = root.requiredObject("oracle", "LLVM build record")
        oracleObject.requireExactFields(
            linkedSetOf("id", "version", "sourceRevision", "sourceLockSha256").also {
                if (schemaVersion == 3) it += "sourceProfileId"
            },
            "LLVM build-record oracle",
        )
        val artifactId = oracleObject.requiredString("id", "LLVM build-record oracle")
        val sourceProfileId = if (schemaVersion == 3) {
            oracleObject.requiredString("sourceProfileId", "LLVM build-record oracle")
        } else {
            artifactId
        }
        if (sourceProfileId != sourceLock.oracleId) {
            buildFail("build record source profile does not match the source lock")
        }
        val version = oracleObject.requiredString("version", "LLVM build-record oracle")
        requireMatch(version, VERSION, "build-record oracle version")
        if (version != sourceLock.version) buildFail("build record oracle version does not match the source lock")
        val revision = oracleObject.requiredString("sourceRevision", "LLVM build-record oracle")
        requireMatch(revision, GIT_OBJECT, "build-record source revision")
        if (revision != sourceLock.commit) buildFail("build record source revision does not match the source lock")
        val lockedSha = oracleObject.requiredString("sourceLockSha256", "LLVM build-record oracle")
        requireSha256(lockedSha, "build-record source lock")
        if (lockedSha != sourceLockSha256) {
            buildFail("build record sourceLockSha256 does not match source-lock bytes")
        }
        val oracle = LlvmBuildOracleV1(artifactId, sourceProfileId, version, revision, lockedSha)

        val environmentObject = root.requiredObject("environment", "LLVM build record")
        environmentObject.requireExactFields(setOf("container", "variables"), "LLVM build-record environment")
        val containerObject = environmentObject.requiredObject("container", "LLVM build-record environment")
        containerObject.requireExactFields(setOf("image", "digest", "platform"), "LLVM build container")
        val image = containerObject.requiredString("image", "LLVM build container")
        if ('@' in image || image.any(Char::isWhitespace)) {
            buildFail("container image must omit the separately locked digest and whitespace")
        }
        val digest = containerObject.requiredString("digest", "LLVM build container")
        requireImageDigest(digest, "recorded build container")
        val platform = containerObject.requiredString("platform", "LLVM build container")
        if (platform != REQUIRED_PLATFORM) buildFail("the ELF oracle build platform must be linux/amd64")
        val variablesObject = environmentObject.requiredObject("variables", "LLVM build-record environment")
        if (variablesObject.isEmpty() || variablesObject.size > MAXIMUM_ENVIRONMENT_VARIABLES) {
            buildFail("build-record environment variable count is outside its bound")
        }
        val variables = variablesObject.entries.associate { (name, value) ->
            if (!name.matches(ENVIRONMENT_NAME)) buildFail("invalid build environment variable name: $name")
            if (name.matchesSecretName()) buildFail("build record must not retain secret variable $name")
            name to value.requiredStringValue("build environment variable $name", allowEmpty = true)
        }.toSortedMap()
        if (variables["LC_ALL"] != "C") buildFail("build record must set LC_ALL=C")
        if (variables["TZ"] != "UTC") buildFail("build record must set TZ=UTC")
        if (!variables["SOURCE_DATE_EPOCH"].orEmpty().matches(POSITIVE_DECIMAL)) {
            buildFail("build record must set a positive decimal SOURCE_DATE_EPOCH")
        }
        variables["PATH"]?.let { path ->
            if (path != DETERMINISTIC_PATH) buildFail("recorded PATH differs from the deterministic build PATH")
        }
        val environment = LlvmBuildEnvironmentV1(
            LlvmBuildContainerV1(image, digest, platform),
            Collections.unmodifiableMap(LinkedHashMap(variables)),
        )

        val directoriesObject = root.requiredObject("directories", "LLVM build record")
        directoriesObject.requireExactFields(setOf("source", "build", "install"), "LLVM build directories")
        val directories = LlvmBuildDirectoriesV1(
            source = requireAbsolutePath(directoriesObject.requiredString("source", "LLVM build directories"), "source directory"),
            build = requireAbsolutePath(directoriesObject.requiredString("build", "LLVM build directories"), "build directory"),
            install = requireAbsolutePath(directoriesObject.requiredString("install", "LLVM build directories"), "install directory"),
        )
        val directoryValues = listOf(directories.source, directories.build, directories.install)
        if (directoryValues.toSet().size != directoryValues.size) {
            buildFail("source, build, and install directories must be distinct")
        }
        if (directories.source.substringAfterLast('/') != sourceLock.archiveRoot) {
            buildFail("build source directory must end with the locked source archive root")
        }
        if (isAncestor(directories.source, directories.build) || isAncestor(directories.build, directories.source)) {
            buildFail("the oracle build must be out of tree, not nested in its source")
        }

        val commandsObject = root.requiredObject("commands", "LLVM build record")
        commandsObject.requireExactFields(
            setOf("configure", "compile", "install", "stageFull", "strip"),
            "LLVM build commands",
        )
        val commands = LlvmBuildCommandsV1(
            configure = immutableList(commandsObject.requiredCommand("configure")),
            compile = immutableList(commandsObject.requiredCommand("compile")),
            install = immutableList(commandsObject.requiredCommand("install")),
            stageFull = immutableList(commandsObject.requiredCommand("stageFull")),
            strip = immutableList(commandsObject.requiredCommand("strip")),
        )
        if (buildSystem == "autoconf") {
            val expected = "${directories.source}/configure"
            if (commands.configure.first() != expected) buildFail("configure command must start with $expected")
        } else {
            if (posixBaseName(commands.configure.first()) != "cmake") {
                buildFail("cmake-ninja configure command must invoke cmake")
            }
            listOf(
                "-G" to "Ninja",
                "-S" to "${directories.source}/llvm",
                "-B" to directories.build,
            ).forEach { (option, expected) ->
                val positions = commands.configure.indices.filter { commands.configure[it] == option }
                if (positions.size != 1 || positions.single() + 1 >= commands.configure.size ||
                    commands.configure[positions.single() + 1] != expected
                ) {
                    buildFail("cmake-ninja configure command must contain $option $expected exactly once")
                }
            }
        }
        if (commands.stageFull.count { it == "{full}" } != 1) {
            buildFail("stageFull command must contain {full} exactly once")
        }
        if (commands.strip.count { it == "{full}" } != 1 ||
            commands.strip.count { it == "{stripped}" } != 1
        ) {
            buildFail("strip command must contain {full} and {stripped} exactly once")
        }
        if (commands.strip.none { it == "--strip-all" || it == "-s" }) {
            buildFail("strip command must request complete symbol stripping")
        }

        val toolsArray = root.requiredArray("tools", "LLVM build record")
        if (toolsArray.isEmpty() || toolsArray.size > MAXIMUM_TOOLS) {
            buildFail("build-record tool count is outside its bound")
        }
        val tools = toolsArray.mapIndexed { index, element ->
            val tool = element as? JsonObject ?: buildFail("build-record tool $index must be an object")
            tool.requireExactFields(
                setOf(
                    "role",
                    "path",
                    "versionCommand",
                    "versionOutput",
                    "executableBytes",
                    "executableSha256",
                ),
                "build-record tool $index",
            )
            val role = tool.requiredString("role", "build-record tool $index")
            requireMatch(role, TOOL_ROLE, "build-record tool role")
            val executable = requireAbsolutePath(
                tool.requiredString("path", "build-record tool $index"),
                "build-record tool path",
            )
            val versionCommand = tool.requiredCommand("versionCommand")
            if (versionCommand.first() != executable) {
                buildFail("build-record tool $index versionCommand must invoke the locked tool path")
            }
            val versionOutput = tool.requiredString("versionOutput", "build-record tool $index")
            if (versionOutput.toByteArray(StandardCharsets.UTF_8).size > MAXIMUM_RECORDED_VERSION_BYTES) {
                buildFail("build-record tool $index version output exceeds its byte bound")
            }
            val executableBytes = tool.requiredInteger("executableBytes", "build-record tool $index")
            if (executableBytes !in 1L..MAXIMUM_TOOL_BYTES) {
                buildFail("build-record tool $index executable byte length is outside its bound")
            }
            val executableSha256 = tool.requiredString("executableSha256", "build-record tool $index")
            requireSha256(executableSha256, "build-record tool $index executable")
            LlvmBuildToolV1(
                role,
                executable,
                immutableList(versionCommand),
                versionOutput,
                executableBytes,
                executableSha256,
            )
        }
        val roles = tools.map { it.role }
        if (roles != roles.sorted() || roles.toSet().size != roles.size) {
            buildFail("build-record tool roles must be unique and sorted")
        }
        val missingRoles = REQUIRED_TOOL_ROLES - roles.toSet()
        if (missingRoles.isNotEmpty()) {
            buildFail("build record is missing required tool roles: ${missingRoles.sorted()}")
        }
        val stripperPath = tools.single { it.role == "stripper" }.path
        if (commands.strip.first() != stripperPath) {
            buildFail("strip command must invoke the locked stripper tool path")
        }

        val outputsObject = root.requiredObject("outputs", "LLVM build record")
        outputsObject.requireExactFields(setOf("full", "stripped"), "LLVM build outputs")
        val outputs = LlvmBuildOutputsV1(
            full = requireRelativePath(outputsObject.requiredString("full", "LLVM build outputs"), "full output"),
            stripped = requireRelativePath(
                outputsObject.requiredString("stripped", "LLVM build outputs"),
                "stripped output",
            ),
        )
        if (outputs.full == outputs.stripped) buildFail("full and stripped artifact paths must differ")
        return LlvmBuildRecordV1(
            schemaVersion,
            buildSystem,
            oracle,
            environment,
            directories,
            commands,
            immutableList(tools),
            outputs,
        )
    }
}

private class PinnedBuildFile private constructor(
    val path: Path,
    private val parentPath: Path,
    private val name: String,
    private val label: String,
    private val parent: LinuxDescriptor,
    private val descriptor: LinuxDescriptor,
    private val identity: LinuxFileIdentity,
    private val channel: FileChannel,
    private val maximumBytes: Long,
    private val executable: Boolean,
) : AutoCloseable {
    val bytes: Long = channel.size()

    fun readComplete(): ByteArray {
        if (bytes > Int.MAX_VALUE.toLong()) buildFail("$label is too large to snapshot")
        val result = ByteArray(bytes.toInt())
        var offset = 0
        while (offset < result.size) {
            val read = channel.read(ByteBuffer.wrap(result, offset, result.size - offset), offset.toLong())
            if (read <= 0) buildFail("$label ended during descriptor-bound reading")
            offset += read
        }
        if (channel.size() != bytes) buildFail("$label size changed during descriptor-bound reading")
        return result
    }

    fun requireCurrent(expectedSha256: String, expectedBytes: Long) {
        if (expectedBytes != bytes) buildFail("$label byte length mismatch: expected $expectedBytes, observed $bytes")
        val parentNow = LinuxFilesystemSyscalls.identity(parent.fd)
        if (!sameBuildDirectory(parent.identity, parentNow)) buildFail("$label parent descriptor identity changed")
        val realParent = try {
            parentPath.toRealPath()
        } catch (failure: IOException) {
            throw LlvmBuildEnvironmentException("$label parent path is unavailable", failure)
        }
        if (realParent != parentPath ||
            !Files.isSameFile(parentPath, LinuxFilesystemSyscalls.stableDescriptorPath(parent.fd))
        ) {
            buildFail("$label parent pathname changed")
        }
        val descriptorNow = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameBuildFile(identity, descriptorNow) ||
            descriptorNow.mode.permissions and UNTRUSTED_WRITE_MODE != 0 ||
            executable && descriptorNow.mode.permissions and EXECUTE_MODE == 0
        ) {
            buildFail("$label descriptor identity, permissions, or type changed")
        }
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use { named ->
            if (!sameBuildFile(identity, LinuxFilesystemSyscalls.identity(named.fd))) {
                buildFail("$label pathname changed")
            }
        } ?: buildFail("$label pathname disappeared")
        if (channel.size() != expectedBytes) buildFail("$label byte length changed")
        val observed = hashChannel(channel, expectedBytes, maximumBytes, label)
        if (observed != expectedSha256) buildFail("$label SHA-256 mismatch: expected $expectedSha256, observed $observed")
    }

    override fun close() {
        try {
            channel.close()
        } finally {
            try {
                descriptor.close()
            } finally {
                parent.close()
            }
        }
    }

    companion object {
        fun open(path: Path, maximumBytes: Long, label: String, executable: Boolean): PinnedBuildFile {
            val absolute = path.toAbsolutePath().normalize()
            val parentPath = absolute.parent ?: buildFail("$label path has no parent")
            val name = absolute.fileName?.toString() ?: buildFail("$label path has no file name")
            if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name) {
                buildFail("$label file name is invalid")
            }
            val realParent = try {
                parentPath.toRealPath()
            } catch (failure: IOException) {
                throw LlvmBuildEnvironmentException("$label parent path is unavailable", failure)
            }
            if (realParent != parentPath) buildFail("$label parent path contains a symbolic link")
            LinuxFilesystemSyscalls.requireSupported(realParent)
            val parent = LinuxFilesystemSyscalls.openRoot(realParent)
            try {
                val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                    ?: buildFail("$label is unavailable")
                try {
                    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                    if (!identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
                        identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0 ||
                        executable && identity.mode.permissions and EXECUTE_MODE == 0
                    ) {
                        buildFail("$label is not a trusted non-symlink regular executable/file")
                    }
                    val channel = FileChannel.open(
                        LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
                        StandardOpenOption.READ,
                    )
                    try {
                        val size = channel.size()
                        if (size !in 1L..maximumBytes) buildFail("$label exceeds its byte bound")
                        return PinnedBuildFile(
                            absolute,
                            realParent,
                            name,
                            label,
                            parent,
                            descriptor,
                            identity,
                            channel,
                            maximumBytes,
                            executable,
                        )
                    } catch (failure: Throwable) {
                        channel.close()
                        throw failure
                    }
                } catch (failure: Throwable) {
                    descriptor.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                parent.close()
                throw failure
            }
        }
    }
}

/**
 * Verifies live tool facts against the historical build-record origin.
 *
 * This command does not authenticate a freshly rebuilt image ID. Deployment must first run the
 * separate Kotlin toolchain-reproduction verifier, then execute this command inside that verified
 * read-only image while supplying the reproduction lock's recorded-origin digest.
 */
internal object LlvmBuildEnvironmentVerifierCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        exitProcess(run(arguments))
    }

    internal fun run(
        arguments: Array<String>,
        stdout: (String) -> Unit = ::println,
        stderr: (String) -> Unit = System.err::println,
    ): Int = try {
        val parsed = parseArguments(arguments)
        val verification = LlvmBuildEnvironmentVerifier.verify(
            parsed.sourceLock,
            parsed.buildRecord,
            parsed.recordedOriginDigest,
        )
        successMessages(verification).forEach(stdout)
        0
    } catch (failure: Exception) {
        stderr("LLVM build-record verification failed: ${failure.message ?: failure::class.simpleName}")
        1
    }

    internal fun successMessages(verification: LlvmBuildEnvironmentVerification): List<String> = buildList {
        val container = verification.record.environment.container
        add(
            "verified LLVM oracle build environment for recorded origin: " +
                "${container.image}@${verification.recordedOriginDigest}",
        )
        verification.record.tools.forEach { tool ->
            add("  ${tool.role}: ${tool.versionOutput.lineSequence().first()}")
        }
    }

    private fun parseArguments(arguments: Array<String>): CliArguments {
        var sourceLock: Path? = null
        var buildRecord: Path? = null
        var recordedOriginDigest: String? = null
        var index = 0
        while (index < arguments.size) {
            val option = arguments[index]
            if (index + 1 >= arguments.size) buildFail("missing value for $option")
            val value = arguments[index + 1]
            if (value.isEmpty()) buildFail("empty value for $option")
            when (option) {
                "--source-lock" -> {
                    if (sourceLock != null) buildFail("duplicate --source-lock option")
                    sourceLock = Path.of(value)
                }
                "--build-record" -> {
                    if (buildRecord != null) buildFail("duplicate --build-record option")
                    buildRecord = Path.of(value)
                }
                "--recorded-origin-digest" -> {
                    if (recordedOriginDigest != null) buildFail("duplicate --recorded-origin-digest option")
                    recordedOriginDigest = value
                }
                else -> buildFail("unknown option $option")
            }
            index += 2
        }
        return CliArguments(
            sourceLock ?: buildFail("missing --source-lock option"),
            buildRecord ?: buildFail("missing --build-record option"),
            recordedOriginDigest ?: buildFail("missing --recorded-origin-digest option"),
        )
    }

    private data class CliArguments(
        val sourceLock: Path,
        val buildRecord: Path,
        val recordedOriginDigest: String,
    )
}

private fun requirePlatform(platform: LlvmBuildPlatform) {
    if (platform.operatingSystem != "Linux" || platform.architecture.lowercase() !in setOf("amd64", "x86_64")) {
        buildFail("build environment is not Linux x86-64")
    }
}

private fun hashChannel(channel: FileChannel, bytes: Long, maximumBytes: Long, label: String): String {
    if (bytes !in 1L..maximumBytes) buildFail("$label byte length is outside its bound")
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(HASH_BUFFER_BYTES)
    var offset = 0L
    while (offset < bytes) {
        val count = minOf(buffer.size.toLong(), bytes - offset).toInt()
        val read = channel.read(ByteBuffer.wrap(buffer, 0, count), offset)
        if (read <= 0) buildFail("$label ended during descriptor-bound hashing")
        digest.update(buffer, 0, read)
        offset += read
    }
    if (channel.size() != bytes) buildFail("$label size changed during descriptor-bound hashing")
    return digest.digest().hex()
}

private fun JsonObject.requireExactFields(expected: Set<String>, label: String) {
    if (keys != expected) {
        val missing = (expected - keys).sorted()
        val unexpected = (keys - expected).sorted()
        buildFail("$label has invalid fields: missing=$missing unexpected=$unexpected")
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: buildFail("$label field $name must be an object")

private fun JsonObject.requiredArray(name: String, label: String): JsonArray = this[name] as? JsonArray
    ?: buildFail("$label field $name must be an array")

private fun JsonObject.requiredString(name: String, label: String, allowEmpty: Boolean = false): String =
    (this[name] ?: buildFail("$label field $name is missing")).requiredStringValue(
        "$label field $name",
        allowEmpty,
    )

private fun JsonElement.requiredStringValue(label: String, allowEmpty: Boolean): String {
    val primitive = this as? JsonPrimitive ?: buildFail("$label must be a string")
    if (!primitive.isString || (!allowEmpty && primitive.content.isEmpty()) || '\u0000' in primitive.content) {
        buildFail("$label must be ${if (allowEmpty) "a" else "a non-empty"} string without NUL")
    }
    return primitive.content
}

private fun JsonObject.requiredInteger(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: buildFail("$label field $name must be an integer")
    if (primitive.isString || !primitive.content.matches(NONNEGATIVE_INTEGER)) {
        buildFail("$label field $name must be a non-negative integer")
    }
    return primitive.content.toLongOrNull() ?: buildFail("$label field $name exceeds the supported integer range")
}

private fun JsonObject.requiredCommand(name: String): List<String> {
    val array = requiredArray(name, "LLVM build commands")
    if (array.isEmpty() || array.size > MAXIMUM_COMMAND_ARGUMENTS) {
        buildFail("build-record command $name argument count is outside its bound")
    }
    return array.mapIndexed { index, value ->
        value.requiredStringValue("build-record command $name argument $index", allowEmpty = false)
    }
}

private fun requireAbsolutePath(value: String, label: String): String {
    if (!value.startsWith('/') || value == "/" || '\\' in value || '\u0000' in value ||
        value.split('/').drop(1).any { it.isEmpty() || it == "." || it == ".." }
    ) {
        buildFail("$label must be a normalized non-root absolute POSIX path")
    }
    return value
}

private fun requireRelativePath(value: String, label: String): String {
    if (value.isEmpty() || value.startsWith('/') || value.endsWith('/') || '\\' in value || '\u0000' in value ||
        value.split('/').any { it.isEmpty() || it == "." || it == ".." }
    ) {
        buildFail("$label must be a normalized relative POSIX path")
    }
    return value
}

private fun posixBaseName(value: String): String = value.trimEnd('/').substringAfterLast('/')

private fun isAncestor(parent: String, child: String): Boolean = child.startsWith("$parent/")

private fun String.matchesSecretName(): Boolean = SECRET_ENVIRONMENT_NAME.containsMatchIn(this)

private fun requireSha256(value: String, label: String) = requireMatch(value, SHA256, "$label SHA-256")

private fun requireImageDigest(value: String, label: String) = requireMatch(value, IMAGE_DIGEST, "$label digest")

private fun requireMatch(value: String, pattern: Regex, label: String) {
    if (!value.matches(pattern)) buildFail("$label has an invalid format")
}

private fun decodeUtf8(bytes: ByteArray, label: String): String = try {
    StandardCharsets.UTF_8.newDecoder()
        .onMalformedInput(CodingErrorAction.REPORT)
        .onUnmappableCharacter(CodingErrorAction.REPORT)
        .decode(ByteBuffer.wrap(bytes))
        .toString()
} catch (failure: Exception) {
    throw LlvmBuildEnvironmentException("$label is not strict UTF-8", failure)
}

private fun ByteArray.sha256(): String = MessageDigest.getInstance("SHA-256").digest(this).hex()

private fun ByteArray.hex(): String = joinToString(separator = "") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun Duration.toNanosSaturated(): Long = try {
    toNanos()
} catch (_: ArithmeticException) {
    Long.MAX_VALUE
}

private fun sameBuildObject(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId

private fun sameBuildFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    sameBuildObject(left, right) && left.mode == right.mode && left.uid == right.uid &&
        left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isRegularFile && right.isRegularFile && !left.isDirectory && !right.isDirectory &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun sameBuildDirectory(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    sameBuildObject(left, right) && left.mode == right.mode && left.uid == right.uid &&
        left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isDirectory && right.isDirectory && !left.isRegularFile && !right.isRegularFile &&
        !left.isSymbolicLink && !right.isSymbolicLink

private inline fun <T> translateBuildFailure(action: () -> T): T = try {
    action()
} catch (failure: LlvmBuildEnvironmentException) {
    throw failure
} catch (failure: Exception) {
    throw LlvmBuildEnvironmentException(
        "LLVM build-environment verification failed: ${failure.message ?: failure::class.simpleName}",
        failure,
    )
}

private fun buildFail(message: String): Nothing = throw LlvmBuildEnvironmentException(message)

private fun <T> immutableList(values: Collection<T>): List<T> =
    Collections.unmodifiableList(ArrayList(values))

private const val MAXIMUM_SOURCE_LOCK_BYTES = 64L * 1024L
private const val MAXIMUM_BUILD_RECORD_BYTES = 1024L * 1024L
private const val MAXIMUM_TOOL_BYTES = 512L * 1024L * 1024L
private const val MAXIMUM_TOOLS = 64
private const val MAXIMUM_ENVIRONMENT_VARIABLES = 256
private const val MAXIMUM_COMMAND_ARGUMENTS = 4_096
private const val MAXIMUM_RECORDED_VERSION_BYTES = 64 * 1024
private const val MAXIMUM_VERSION_OUTPUT_BYTES = 1024 * 1024
private const val HASH_BUFFER_BYTES = 64 * 1024
private const val PROCESS_BUFFER_BYTES = 8 * 1024
private const val MAXIMUM_CLEANUP_DESCENDANTS = 128
private const val UNTRUSTED_WRITE_MODE = 0x12
private const val EXECUTE_MODE = 0x49
private const val REQUIRED_PLATFORM = "linux/amd64"
private const val DETERMINISTIC_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
private val ROOT_DIRECTORY = Path.of("/")
private val VERSION_TIMEOUT = Duration.ofSeconds(30)
private val PROCESS_CLEANUP_TIMEOUT = Duration.ofSeconds(5)
private const val PROCESS_POLL_NANOS = 25L * 1000L * 1000L
private val REQUIRED_TOOL_ROLES = setOf("compiler", "linker", "stripper")
private val VERSION = Regex("[0-9]+\\.[0-9]+\\.[0-9]+")
private val GIT_OBJECT = Regex("[0-9a-f]{40}")
private val SHA256 = Regex("[0-9a-f]{64}")
private val IMAGE_DIGEST = Regex("sha256:[0-9a-f]{64}")
private val ENVIRONMENT_NAME = Regex("[A-Z_][A-Z0-9_]*")
private val TOOL_ROLE = Regex("[a-z][A-Za-z0-9]*")
private val POSITIVE_DECIMAL = Regex("[1-9][0-9]*")
private val NONNEGATIVE_INTEGER = Regex("0|[1-9][0-9]*")
private val SECRET_ENVIRONMENT_NAME = Regex(
    "(?:^|_)(?:AUTH(?:ORIZATION)?|CREDENTIALS?|KEY|PASSWORD|PASSWD|SECRET|TOKEN)(?:_|$)",
)
private val BUILD_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = MAXIMUM_BUILD_RECORD_BYTES.toInt(),
    maximumCanonicalBytes = MAXIMUM_BUILD_RECORD_BYTES.toInt(),
    maximumDepth = 32,
    maximumNodes = 20_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = 512 * 1024,
    maximumNumberCharacters = 64,
)
