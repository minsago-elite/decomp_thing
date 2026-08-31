package decompengine.oracle.provenance

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import kotlin.system.exitProcess
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonArray
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

internal class LlvmArtifactManifestException(
    message: String,
    cause: Throwable? = null,
) : IllegalStateException(message, cause)

internal data class LlvmArtifactManifestArtifactIdentity(
    val path: String,
    val bytes: Long,
    val sha256: String,
)

/**
 * Immutable diagnostic identity returned only after the raw production inputs have been verified.
 * It deliberately exposes no parsed JSON, ELF model, validation seam, or authority token.
 */
internal sealed interface LlvmArtifactManifestVerification {
    val manifestPath: Path
    val artifactRoot: Path
    val manifestSha256: String
    val sourceLockPath: Path
    val sourceLockSha256: String
    val buildRecordPath: Path
    val buildRecordSha256: String
    val oracleId: String
    val version: String
    val sourceRevision: String
    val full: LlvmArtifactManifestArtifactIdentity
    val stripped: LlvmArtifactManifestArtifactIdentity
    val buildId: String
}

/** Non-authoritative result used only by hostile tests with lowered limits or mutation seams. */
internal data class LlvmArtifactManifestAssessment(
    val manifestPath: Path,
    val artifactRoot: Path,
    val manifestSha256: String,
    val sourceLockPath: Path,
    val sourceLockSha256: String,
    val buildRecordPath: Path,
    val buildRecordSha256: String,
    val oracleId: String,
    val version: String,
    val sourceRevision: String,
    val full: LlvmArtifactManifestArtifactIdentity,
    val stripped: LlvmArtifactManifestArtifactIdentity,
    val buildId: String,
)

internal data class LlvmArtifactManifestLimits(
    val maximumManifestBytes: Int = MAXIMUM_MANIFEST_BYTES,
    val maximumInputBytes: Int = MAXIMUM_INPUT_BYTES,
    val elf: BoundedElfTwinV1Limits = BoundedElfTwinV1Limits(),
) {
    init {
        require(maximumManifestBytes in 1..MAXIMUM_MANIFEST_BYTES)
        require(maximumInputBytes in 1..MAXIMUM_INPUT_BYTES)
    }
}

internal enum class LlvmArtifactManifestVerificationPoint {
    AFTER_MANIFEST_PARSED,
    AFTER_INPUTS_AUTHENTICATED,
    AFTER_ELF_TWIN_INSPECTED,
    BEFORE_TERMINAL_REAUTHENTICATION,
}

internal fun interface LlvmArtifactManifestFaultInjector {
    fun hit(point: LlvmArtifactManifestVerificationPoint)
}

internal fun interface LlvmArtifactManifestSourceLockAuthority {
    fun verify(path: Path): LlvmSourceLockVerification
}

/**
 * Descriptor-pinned verifier for the legacy LLVM ELF-manifest v1 document.
 *
 * The source lock, its local OpenPGP evidence, the build record, both complete ELF files, and all
 * derived twin-equivalence facts are recomputed. The manifest and input files remain open and are
 * authenticated again at the terminal boundary; the ELF twin is independently inspected a second
 * time. A cooperating same-UID/root writer can still make and perfectly restore an indistinguishable
 * transient mutation between checks. This verifier makes no claim to exclude that threat and does
 * not generate a manifest, authenticate a fresh container image, execute build tools, or authorize
 * a release by itself.
 */
private class LlvmArtifactManifestEngine(
    private val limits: LlvmArtifactManifestLimits,
    private val sourceLockAuthority: LlvmArtifactManifestSourceLockAuthority,
    private val faultInjector: LlvmArtifactManifestFaultInjector?,
) {
    fun assess(manifestPath: Path, artifactRootPath: Path): LlvmArtifactManifestAssessment =
        translateManifestFailure {
            PinnedManifestDirectory.open(artifactRootPath, "LLVM artifact root").use { artifactRoot ->
                PinnedManifestFile.open(
                    manifestPath,
                    limits.maximumManifestBytes.toLong(),
                    "LLVM artifact manifest",
                ).use { manifest ->
                    val manifestBytes = manifest.readComplete()
                    val manifestSha256 = manifestBytes.sha256()
                    manifest.requireCurrent(manifestSha256, manifestBytes.size.toLong())
                    artifactRoot.requireCurrent()
                    val document = parseManifest(manifestBytes)
                    faultInjector?.hit(LlvmArtifactManifestVerificationPoint.AFTER_MANIFEST_PARSED)
                    manifest.requireCurrent(manifestSha256, manifestBytes.size.toLong())
                    artifactRoot.requireCurrent()

                    val inputs = document.requiredObject("inputs", "LLVM artifact manifest")
                    val sourceRecord = parseInputRecord(
                        inputs.requiredObject("sourceLock", "LLVM artifact-manifest inputs"),
                        "LLVM source-lock input",
                    )
                    val buildRecord = parseInputRecord(
                        inputs.requiredObject("buildRecord", "LLVM artifact-manifest inputs"),
                        "LLVM build-record input",
                    )
                    requireManifestInputBaseName(sourceRecord.path, "LLVM source-lock input")
                    requireManifestInputBaseName(buildRecord.path, "LLVM build-record input")
                    if (sourceRecord.path == buildRecord.path) {
                        manifestFail("LLVM source-lock and build-record paths must differ")
                    }
                    val manifestDirectory = manifest.path.parent
                        ?: manifestFail("LLVM artifact manifest has no parent directory")
                    val sourcePath = resolveRelative(manifestDirectory, sourceRecord.path, "LLVM source lock")
                    val buildPath = resolveRelative(manifestDirectory, buildRecord.path, "LLVM build record")

                    PinnedManifestFile.open(
                        sourcePath,
                        limits.maximumInputBytes.toLong(),
                        "LLVM source lock",
                    ).use { sourceInput ->
                        PinnedManifestFile.open(
                            buildPath,
                            limits.maximumInputBytes.toLong(),
                            "LLVM build record",
                        ).use { buildInput ->
                            if (
                                sourceInput.sameObject(buildInput) || sourceInput.sameObject(manifest) ||
                                buildInput.sameObject(manifest)
                            ) {
                                manifestFail("LLVM manifest, source lock, and build record must be distinct files")
                            }
                            val sourceBytes = sourceInput.readComplete()
                            val sourceSha256 = sourceBytes.sha256()
                            val buildBytes = buildInput.readComplete()
                            val buildSha256 = buildBytes.sha256()
                            requireRecordIdentity(sourceRecord, sourceBytes.size.toLong(), sourceSha256)
                            requireRecordIdentity(buildRecord, buildBytes.size.toLong(), buildSha256)
                            requireAllCurrent(
                                manifest,
                                manifestSha256,
                                manifestBytes.size.toLong(),
                                sourceInput,
                                sourceSha256,
                                sourceBytes.size.toLong(),
                                buildInput,
                                buildSha256,
                                buildBytes.size.toLong(),
                                artifactRoot,
                            )

                            val source = verifySourceLock(sourceInput.path, sourceSha256)
                            val build = parseBuildRecord(buildBytes, source, sourceSha256)
                            faultInjector?.hit(LlvmArtifactManifestVerificationPoint.AFTER_INPUTS_AUTHENTICATED)
                            requireAllCurrent(
                                manifest,
                                manifestSha256,
                                manifestBytes.size.toLong(),
                                sourceInput,
                                sourceSha256,
                                sourceBytes.size.toLong(),
                                buildInput,
                                buildSha256,
                                buildBytes.size.toLong(),
                                artifactRoot,
                            )

                            val fullPath = artifactRoot.resolve(build.outputs.full, "full LLVM artifact")
                            val strippedPath = artifactRoot.resolve(build.outputs.stripped, "stripped LLVM artifact")
                            val artifactInputs = PinnedManifestArtifactPair.open(
                                fullPath,
                                strippedPath,
                                limits.elf.maximumFileBytes,
                            )
                            artifactInputs.use {
                            val twin = inspectTwin(fullPath, strippedPath)
                            artifactInputs.requireCurrent(twin)
                            artifactRoot.requireCurrent()
                            faultInjector?.hit(LlvmArtifactManifestVerificationPoint.AFTER_ELF_TWIN_INSPECTED)

                            val expected = manifestDocument(
                                source,
                                sourceRecord.path,
                                sourceBytes.size.toLong(),
                                sourceSha256,
                                buildRecord.path,
                                buildBytes.size.toLong(),
                                buildSha256,
                                build,
                                twin,
                            )
                            if (document != expected) {
                                manifestFail("LLVM artifact manifest differs from independently recomputed facts")
                            }

                            faultInjector?.hit(
                                LlvmArtifactManifestVerificationPoint.BEFORE_TERMINAL_REAUTHENTICATION,
                            )
                            artifactInputs.requireCurrent(twin)
                            requireAllCurrent(
                                manifest,
                                manifestSha256,
                                manifestBytes.size.toLong(),
                                sourceInput,
                                sourceSha256,
                                sourceBytes.size.toLong(),
                                buildInput,
                                buildSha256,
                                buildBytes.size.toLong(),
                                artifactRoot,
                            )
                            val terminalManifest = manifest.readComplete()
                            val terminalSourceBytes = sourceInput.readComplete()
                            val terminalBuildBytes = buildInput.readComplete()
                            if (!MessageDigest.isEqual(manifestBytes, terminalManifest)) {
                                manifestFail("LLVM artifact manifest changed during verification")
                            }
                            if (!MessageDigest.isEqual(sourceBytes, terminalSourceBytes)) {
                                manifestFail("LLVM source lock changed during manifest verification")
                            }
                            if (!MessageDigest.isEqual(buildBytes, terminalBuildBytes)) {
                                manifestFail("LLVM build record changed during manifest verification")
                            }

                            val terminalSource = verifySourceLock(sourceInput.path, sourceSha256)
                            requireSameSourceLock(source, terminalSource)
                            val terminalBuild = parseBuildRecord(terminalBuildBytes, terminalSource, sourceSha256)
                            if (terminalBuild != build) {
                                manifestFail("LLVM build-record semantics changed during manifest verification")
                            }
                            val terminalTwin = inspectTwin(fullPath, strippedPath)
                            if (terminalTwin != twin) {
                                manifestFail("LLVM ELF-twin facts changed during manifest verification")
                            }
                            artifactInputs.requireCurrent(terminalTwin)
                            requireAllCurrent(
                                manifest,
                                manifestSha256,
                                manifestBytes.size.toLong(),
                                sourceInput,
                                sourceSha256,
                                sourceBytes.size.toLong(),
                                buildInput,
                                buildSha256,
                                buildBytes.size.toLong(),
                                artifactRoot,
                            )

                            LlvmArtifactManifestAssessment(
                                manifestPath = manifest.path,
                                artifactRoot = artifactRoot.path,
                                manifestSha256 = manifestSha256,
                                sourceLockPath = sourceInput.path,
                                sourceLockSha256 = sourceSha256,
                                buildRecordPath = buildInput.path,
                                buildRecordSha256 = buildSha256,
                                oracleId = source.oracleId,
                                version = source.version,
                                sourceRevision = source.commit,
                                full = LlvmArtifactManifestArtifactIdentity(
                                    build.outputs.full,
                                    twin.full.bytes,
                                    twin.full.sha256,
                                ),
                                stripped = LlvmArtifactManifestArtifactIdentity(
                                    build.outputs.stripped,
                                    twin.stripped.bytes,
                                    twin.stripped.sha256,
                                ),
                                buildId = twin.equivalence.buildId,
                            )
                            }
                        }
                    }
                }
            }
        }

    private fun parseManifest(bytes: ByteArray): JsonObject {
        val root = try {
            OracleJson.parseCanonical(bytes, manifestJsonLimits(limits.maximumManifestBytes)) as? JsonObject
                ?: manifestFail("LLVM artifact-manifest root must be an object")
        } catch (failure: LlvmArtifactManifestException) {
            throw failure
        } catch (failure: Exception) {
            throw LlvmArtifactManifestException(
                "LLVM artifact manifest is not strict bounded canonical JSON",
                failure,
            )
        }
        try {
            OracleSchemas.validate("oracle-manifest", root)
        } catch (failure: Exception) {
            throw LlvmArtifactManifestException("LLVM artifact manifest fails its bundled schema", failure)
        }
        return root
    }

    private fun parseInputRecord(value: JsonObject, label: String): ManifestInputRecord {
        value.requireExactFields(setOf("path", "bytes", "sha256"), label)
        val path = requireRelativePath(value.requiredString("path", label), "$label path")
        val bytes = value.requiredLong("bytes", label)
        if (bytes !in 1L..limits.maximumInputBytes.toLong()) {
            manifestFail("$label byte length is outside its bound")
        }
        val sha256 = value.requiredString("sha256", label)
        requireSha256(sha256, label)
        return ManifestInputRecord(path, bytes, sha256)
    }

    private fun requireRecordIdentity(record: ManifestInputRecord, bytes: Long, sha256: String) {
        if (record.bytes != bytes) manifestFail("${record.path} byte length differs from the manifest")
        if (record.sha256 != sha256) manifestFail("${record.path} SHA-256 differs from the manifest")
    }

    private fun verifySourceLock(path: Path, expectedSha256: String): LlvmSourceLockVerification {
        val verification = try {
            sourceLockAuthority.verify(path)
        } catch (failure: LlvmArtifactManifestException) {
            throw failure
        } catch (failure: Exception) {
            throw LlvmArtifactManifestException("LLVM source-lock verification failed", failure)
        }
        if (
            verification.path.toAbsolutePath().normalize() != path ||
            verification.lockSha256 != expectedSha256
        ) {
            manifestFail("LLVM source-lock authority returned a different pinned identity")
        }
        return verification
    }

    private fun parseBuildRecord(
        bytes: ByteArray,
        source: LlvmSourceLockVerification,
        sourceSha256: String,
    ): LlvmBuildRecordV1 = try {
        LlvmBuildRecordParser.parse(bytes, source, sourceSha256)
    } catch (failure: LlvmArtifactManifestException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmArtifactManifestException("LLVM build-record verification failed", failure)
    }

    private fun inspectTwin(full: Path, stripped: Path): BoundedElfTwinResultV1 = try {
        BoundedElfTwinV1.inspectTwin(full, stripped, limits.elf)
    } catch (failure: LlvmArtifactManifestException) {
        throw failure
    } catch (failure: Exception) {
        throw LlvmArtifactManifestException("LLVM ELF-twin verification failed", failure)
    }

    private fun requireSameSourceLock(
        initial: LlvmSourceLockVerification,
        terminal: LlvmSourceLockVerification,
    ) {
        if (
            initial.path != terminal.path || initial.lockSha256 != terminal.lockSha256 ||
            initial.oracleId != terminal.oracleId || initial.version != terminal.version ||
            initial.archiveRoot != terminal.archiveRoot || initial.archive != terminal.archive ||
            initial.detachedSignature != terminal.detachedSignature || initial.tag != terminal.tag ||
            initial.tagObject != terminal.tagObject || initial.commit != terminal.commit ||
            initial.tagPayloadSha256 != terminal.tagPayloadSha256 ||
            initial.tagSignatureSha256 != terminal.tagSignatureSha256 ||
            initial.signingKeySha256 != terminal.signingKeySha256 ||
            initial.signingFingerprint != terminal.signingFingerprint ||
            initial.archiveContents != terminal.archiveContents
        ) {
            manifestFail("LLVM source-lock semantics changed during manifest verification")
        }
    }

    private fun requireAllCurrent(
        manifest: PinnedManifestFile,
        manifestSha256: String,
        manifestBytes: Long,
        source: PinnedManifestFile,
        sourceSha256: String,
        sourceBytes: Long,
        build: PinnedManifestFile,
        buildSha256: String,
        buildBytes: Long,
        artifactRoot: PinnedManifestDirectory,
    ) {
        manifest.requireCurrent(manifestSha256, manifestBytes)
        source.requireCurrent(sourceSha256, sourceBytes)
        build.requireCurrent(buildSha256, buildBytes)
        artifactRoot.requireCurrent()
    }
}

/** Constructorless production authority; its JVM bridges accept only the two raw path inputs. */
internal object LlvmArtifactManifestVerifier {
    private class AuthenticatedVerification private constructor(
        manifestPath: Path,
        artifactRoot: Path,
    ) : LlvmArtifactManifestVerification {
        /*
         * Kotlin emits a synthetic bridge for this private constructor. Keeping fixed production
         * validation here means that bridge accepts only untrusted paths, never parsed JSON, ELF
         * facts, claimed digests, injected authorities, or a prevalidated token.
         */
        private val assessment = LlvmArtifactManifestEngine(
            limits = LlvmArtifactManifestLimits(),
            sourceLockAuthority = LlvmArtifactManifestSourceLockAuthority {
                LlvmSourceLockVerifier().verify(it)
            },
            faultInjector = null,
        ).assess(manifestPath, artifactRoot)

        override val manifestPath: Path = assessment.manifestPath
        override val artifactRoot: Path = assessment.artifactRoot
        override val manifestSha256: String = assessment.manifestSha256
        override val sourceLockPath: Path = assessment.sourceLockPath
        override val sourceLockSha256: String = assessment.sourceLockSha256
        override val buildRecordPath: Path = assessment.buildRecordPath
        override val buildRecordSha256: String = assessment.buildRecordSha256
        override val oracleId: String = assessment.oracleId
        override val version: String = assessment.version
        override val sourceRevision: String = assessment.sourceRevision
        override val full: LlvmArtifactManifestArtifactIdentity = assessment.full
        override val stripped: LlvmArtifactManifestArtifactIdentity = assessment.stripped
        override val buildId: String = assessment.buildId

        companion object {
            fun verify(manifestPath: Path, artifactRoot: Path): LlvmArtifactManifestVerification =
                AuthenticatedVerification(manifestPath, artifactRoot)
        }
    }

    fun verify(manifestPath: Path, artifactRoot: Path): LlvmArtifactManifestVerification =
        AuthenticatedVerification.verify(manifestPath, artifactRoot)
}

/** Test-only seams return a non-authoritative assessment that no production consumer accepts. */
internal object LlvmArtifactManifestTestSupport {
    fun assess(
        manifestPath: Path,
        artifactRoot: Path,
        limits: LlvmArtifactManifestLimits = LlvmArtifactManifestLimits(),
        sourceLockAuthority: LlvmArtifactManifestSourceLockAuthority =
            LlvmArtifactManifestSourceLockAuthority { LlvmSourceLockVerifier().verify(it) },
        faultInjector: LlvmArtifactManifestFaultInjector? = null,
    ): LlvmArtifactManifestAssessment = LlvmArtifactManifestEngine(
        limits,
        sourceLockAuthority,
        faultInjector,
    ).assess(manifestPath, artifactRoot)

    fun recomputeCanonicalBytes(
        sourceLockPath: Path,
        buildRecordPath: Path,
        artifactRoot: Path,
        sourceRelativePath: String,
        buildRelativePath: String,
        elfLimits: BoundedElfTwinV1Limits = BoundedElfTwinV1Limits(),
    ): ByteArray {
        val sourcePath = sourceLockPath.toAbsolutePath().normalize()
        val buildPath = buildRecordPath.toAbsolutePath().normalize()
        val sourceBytes = Files.readAllBytes(sourcePath)
        val buildBytes = Files.readAllBytes(buildPath)
        val source = LlvmSourceLockVerifier().verify(sourcePath)
        val sourceSha256 = sourceBytes.sha256()
        if (source.lockSha256 != sourceSha256) manifestFail("test source-lock snapshot changed")
        val build = LlvmBuildRecordParser.parse(buildBytes, source, sourceSha256)
        val root = PinnedManifestDirectory.open(artifactRoot, "test LLVM artifact root")
        root.use {
            val twin = BoundedElfTwinV1.inspectTwin(
                it.resolve(build.outputs.full, "test full LLVM artifact"),
                it.resolve(build.outputs.stripped, "test stripped LLVM artifact"),
                elfLimits,
            )
            return OracleJson.canonicalBytes(
                manifestDocument(
                    source,
                    requireRelativePath(sourceRelativePath, "test source-lock path"),
                    sourceBytes.size.toLong(),
                    sourceSha256,
                    requireRelativePath(buildRelativePath, "test build-record path"),
                    buildBytes.size.toLong(),
                    buildBytes.sha256(),
                    build,
                    twin,
                ),
                manifestJsonLimits(MAXIMUM_MANIFEST_BYTES),
            )
        }
    }
}

/** Fixed checked-profile CLI: no arguments, paths only from the profile and one environment root. */
internal object LlvmArtifactManifestVerifierCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        exitProcess(run(arguments))
    }

    internal fun run(
        arguments: Array<String>,
        environment: (String) -> String? = System::getenv,
        stdout: (String) -> Unit = ::println,
        stderr: (String) -> Unit = System.err::println,
    ): Int = try {
        if (arguments.isNotEmpty()) manifestFail("this fixed verifier accepts no arguments")
        val rootText = environment(ARTIFACT_ROOT_ENVIRONMENT)
            ?: manifestFail("missing $ARTIFACT_ROOT_ENVIRONMENT")
        if (rootText.isEmpty()) manifestFail("$ARTIFACT_ROOT_ENVIRONMENT is empty")
        val root = Path.of(rootText)
        if (!root.isAbsolute || root.normalize() != root) {
            manifestFail("$ARTIFACT_ROOT_ENVIRONMENT must be an absolute normalized path")
        }
        val verification = LlvmArtifactManifestVerifier.verify(CHECKED_MANIFEST_PATH, root)
        successMessages(verification).forEach(stdout)
        0
    } catch (failure: Exception) {
        stderr("LLVM artifact-manifest verification failed: ${failure.message ?: failure::class.simpleName}")
        1
    }

    internal fun successMessages(verification: LlvmArtifactManifestVerification): List<String> = listOf(
        "verified LLVM oracle pair: ${verification.oracleId} (${verification.buildId})",
        "  manifest: ${verification.manifestSha256}",
        "  full: ${verification.full.bytes} bytes ${verification.full.sha256}",
        "  stripped: ${verification.stripped.bytes} bytes ${verification.stripped.sha256}",
    )

    private val CHECKED_MANIFEST_PATH = Path.of("oracle/llvm/22.1.6/oracle-manifest.json")
    private const val ARTIFACT_ROOT_ENVIRONMENT = "LLVM_ORACLE_ARTIFACT_ROOT"
}

private data class ManifestInputRecord(
    val path: String,
    val bytes: Long,
    val sha256: String,
)

private class PinnedManifestDirectory private constructor(
    val path: Path,
    private val descriptor: LinuxDescriptor,
    private val identity: LinuxFileIdentity,
    private val label: String,
) : AutoCloseable {
    fun resolve(relative: String, childLabel: String): Path {
        val normalized = requireRelativePath(relative, "$childLabel path")
        val components = normalized.split('/')
        if (components.size > MAXIMUM_ARTIFACT_PATH_COMPONENTS) {
            manifestFail("$childLabel path may contain at most one directory component")
        }
        var current = path
        components.forEach { component ->
            current = current.resolve(component)
            if (Files.isSymbolicLink(current)) manifestFail("$childLabel path contains a symbolic link")
        }
        val candidate = current.toAbsolutePath().normalize()
        if (candidate == path || !candidate.startsWith(path)) manifestFail("$childLabel escapes $label")
        return candidate
    }

    fun requireCurrent() {
        val now = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameManifestDirectory(identity, now) || now.mode.permissions and UNTRUSTED_WRITE_MODE != 0) {
            manifestFail("$label descriptor identity or permissions changed")
        }
        val real = try {
            path.toRealPath()
        } catch (failure: IOException) {
            throw LlvmArtifactManifestException("$label path is unavailable", failure)
        }
        if (real != path || !Files.isSameFile(path, LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd))) {
            manifestFail("$label pathname changed")
        }
    }

    override fun close() = descriptor.close()

    companion object {
        fun open(path: Path, label: String): PinnedManifestDirectory {
            val absolute = path.toAbsolutePath().normalize()
            val real = try {
                absolute.toRealPath()
            } catch (failure: IOException) {
                throw LlvmArtifactManifestException("$label is unavailable", failure)
            }
            if (real != absolute) manifestFail("$label path contains a symbolic link or alias")
            LinuxFilesystemSyscalls.requireSupported(real)
            val descriptor = LinuxFilesystemSyscalls.openRoot(real)
            try {
                val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                if (!identity.isDirectory || identity.isRegularFile || identity.isSymbolicLink) {
                    manifestFail("$label is not a real directory")
                }
                if (identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0) {
                    manifestFail("$label may not be writable by group or other principals")
                }
                return PinnedManifestDirectory(real, descriptor, identity, label).also { it.requireCurrent() }
            } catch (failure: Throwable) {
                descriptor.close()
                throw failure
            }
        }
    }
}

private class PinnedManifestFile private constructor(
    val path: Path,
    private val parentPath: Path,
    private val name: String,
    private val label: String,
    private val parent: LinuxDescriptor,
    private val descriptor: LinuxDescriptor,
    private val identity: LinuxFileIdentity,
    private val channel: FileChannel,
    private val maximumBytes: Long,
) : AutoCloseable {
    private val bytes = channel.size()

    fun sameObject(other: PinnedManifestFile): Boolean = sameManifestObject(identity, other.identity)

    fun readComplete(): ByteArray {
        if (bytes > Int.MAX_VALUE.toLong()) manifestFail("$label is too large to snapshot")
        val result = ByteArray(bytes.toInt())
        var offset = 0
        while (offset < result.size) {
            val read = channel.read(ByteBuffer.wrap(result, offset, result.size - offset), offset.toLong())
            if (read <= 0) manifestFail("$label ended during descriptor-bound reading")
            offset += read
        }
        if (channel.size() != bytes) manifestFail("$label size changed during descriptor-bound reading")
        return result
    }

    fun requireCurrent(expectedSha256: String, expectedBytes: Long) {
        if (expectedBytes != bytes) manifestFail("$label byte length changed")
        val parentNow = LinuxFilesystemSyscalls.identity(parent.fd)
        if (
            !sameManifestDirectory(parent.identity, parentNow) ||
            parentNow.mode.permissions and UNTRUSTED_WRITE_MODE != 0
        ) {
            manifestFail("$label parent descriptor identity or permissions changed")
        }
        val realParent = try {
            parentPath.toRealPath()
        } catch (failure: IOException) {
            throw LlvmArtifactManifestException("$label parent path is unavailable", failure)
        }
        if (
            realParent != parentPath ||
            !Files.isSameFile(parentPath, LinuxFilesystemSyscalls.stableDescriptorPath(parent.fd))
        ) {
            manifestFail("$label parent pathname changed")
        }
        val descriptorNow = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameManifestFile(identity, descriptorNow) || descriptorNow.mode.permissions and UNTRUSTED_WRITE_MODE != 0) {
            manifestFail("$label descriptor identity, permissions, or type changed")
        }
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use { named ->
            if (!sameManifestFile(identity, LinuxFilesystemSyscalls.identity(named.fd))) {
                manifestFail("$label pathname changed")
            }
        } ?: manifestFail("$label pathname disappeared")
        if (channel.size() != expectedBytes) manifestFail("$label byte length changed")
        val observed = hashChannel(channel, expectedBytes, maximumBytes, label)
        if (observed != expectedSha256) manifestFail("$label SHA-256 changed")
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
        fun open(path: Path, maximumBytes: Long, label: String): PinnedManifestFile {
            val absolute = path.toAbsolutePath().normalize()
            val parentPath = absolute.parent ?: manifestFail("$label path has no parent")
            val name = absolute.fileName?.toString() ?: manifestFail("$label path has no file name")
            if (name.isEmpty() || name == "." || name == ".." || '/' in name || '\u0000' in name) {
                manifestFail("$label file name is invalid")
            }
            val realParent = try {
                parentPath.toRealPath()
            } catch (failure: IOException) {
                throw LlvmArtifactManifestException("$label parent path is unavailable", failure)
            }
            if (realParent != parentPath) manifestFail("$label parent path contains a symbolic link or alias")
            LinuxFilesystemSyscalls.requireSupported(realParent)
            val parent = LinuxFilesystemSyscalls.openRoot(realParent)
            try {
                val parentIdentity = LinuxFilesystemSyscalls.identity(parent.fd)
                if (
                    !parentIdentity.isDirectory || parentIdentity.isRegularFile || parentIdentity.isSymbolicLink ||
                    parentIdentity.mode.permissions and UNTRUSTED_WRITE_MODE != 0
                ) {
                    manifestFail("$label parent type or permissions are not trusted")
                }
                val descriptor = LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)
                    ?: manifestFail("$label is unavailable")
                try {
                    val identity = LinuxFilesystemSyscalls.identity(descriptor.fd)
                    if (
                        !identity.isRegularFile || identity.isDirectory || identity.isSymbolicLink ||
                        identity.mode.permissions and UNTRUSTED_WRITE_MODE != 0
                    ) {
                        manifestFail("$label is not a trusted non-symlink regular file")
                    }
                    val channel = FileChannel.open(
                        LinuxFilesystemSyscalls.stableDescriptorPath(descriptor.fd),
                        StandardOpenOption.READ,
                    )
                    try {
                        val bytes = channel.size()
                        if (bytes !in 1L..maximumBytes) manifestFail("$label exceeds its byte bound")
                        return PinnedManifestFile(
                            absolute,
                            realParent,
                            name,
                            label,
                            parent,
                            descriptor,
                            identity,
                            channel,
                            maximumBytes,
                        ).also { it.requirePathCurrent() }
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

    private fun requirePathCurrent() {
        val parentNow = LinuxFilesystemSyscalls.identity(parent.fd)
        if (
            !sameManifestDirectory(parent.identity, parentNow) ||
            parentNow.mode.permissions and UNTRUSTED_WRITE_MODE != 0
        ) {
            manifestFail("$label parent descriptor identity or permissions changed")
        }
        val realParent = try {
            parentPath.toRealPath()
        } catch (failure: IOException) {
            throw LlvmArtifactManifestException("$label parent path is unavailable", failure)
        }
        if (
            realParent != parentPath ||
            !Files.isSameFile(parentPath, LinuxFilesystemSyscalls.stableDescriptorPath(parent.fd))
        ) {
            manifestFail("$label parent pathname changed")
        }
        val descriptorNow = LinuxFilesystemSyscalls.identity(descriptor.fd)
        if (!sameManifestFile(identity, descriptorNow) || descriptorNow.mode.permissions and UNTRUSTED_WRITE_MODE != 0) {
            manifestFail("$label descriptor identity, permissions, or type changed")
        }
        LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)?.use { named ->
            if (!sameManifestFile(identity, LinuxFilesystemSyscalls.identity(named.fd))) {
                manifestFail("$label pathname changed")
            }
        } ?: manifestFail("$label pathname disappeared")
        if (channel.size() != bytes) manifestFail("$label byte length changed")
    }
}

private class PinnedManifestArtifactPair private constructor(
    private val full: PinnedManifestFile,
    private val stripped: PinnedManifestFile,
) : AutoCloseable {
    fun requireCurrent(twin: BoundedElfTwinResultV1) {
        full.requireCurrent(twin.full.sha256, twin.full.bytes)
        stripped.requireCurrent(twin.stripped.sha256, twin.stripped.bytes)
    }

    override fun close() {
        var failure: Throwable? = null
        try {
            stripped.close()
        } catch (caught: Throwable) {
            failure = caught
        }
        try {
            full.close()
        } catch (caught: Throwable) {
            if (failure == null) failure = caught else failure.addSuppressed(caught)
        }
        if (failure != null) throw failure
    }

    companion object {
        fun open(fullPath: Path, strippedPath: Path, maximumBytes: Long): PinnedManifestArtifactPair {
            val full = PinnedManifestFile.open(fullPath, maximumBytes, "full LLVM artifact")
            try {
                val stripped = PinnedManifestFile.open(
                    strippedPath,
                    maximumBytes,
                    "stripped LLVM artifact",
                )
                try {
                    if (full.sameObject(stripped)) {
                        manifestFail("full and stripped LLVM artifacts resolve to the same file")
                    }
                    return PinnedManifestArtifactPair(full, stripped)
                } catch (failure: Throwable) {
                    stripped.close()
                    throw failure
                }
            } catch (failure: Throwable) {
                full.close()
                throw failure
            }
        }
    }
}

private fun manifestDocument(
    source: LlvmSourceLockVerification,
    sourceRelative: String,
    sourceBytes: Long,
    sourceSha256: String,
    buildRelative: String,
    buildBytes: Long,
    buildSha256: String,
    build: LlvmBuildRecordV1,
    twin: BoundedElfTwinResultV1,
): JsonObject = buildJsonObject {
    put("schemaVersion", 1)
    put("oracle", buildJsonObject {
        put("id", source.oracleId)
        put("version", source.version)
        put("sourceRevision", source.commit)
    })
    put("inputs", buildJsonObject {
        put("sourceLock", fileRecord(sourceRelative, sourceBytes, sourceSha256))
        put("buildRecord", fileRecord(buildRelative, buildBytes, buildSha256))
    })
    put("artifacts", buildJsonObject {
        put("full", artifactRecord(build.outputs.full, twin.full))
        put("stripped", artifactRecord(build.outputs.stripped, twin.stripped))
    })
    put("equivalence", equivalenceRecord(twin.equivalence))
}

private fun fileRecord(path: String, bytes: Long, sha256: String): JsonObject = buildJsonObject {
    put("path", path)
    put("bytes", bytes)
    put("sha256", sha256)
}

private fun artifactRecord(path: String, artifact: BoundedElfArtifactV1): JsonObject = buildJsonObject {
    put("path", path)
    put("bytes", artifact.bytes)
    put("sha256", artifact.sha256)
    put("elf", elfRecord(artifact.elf))
}

private fun elfRecord(elf: BoundedElfInspectionV1): JsonObject = buildJsonObject {
    put("header", headerRecord(elf.header))
    put("identity", identityRecord(elf.identity))
    put("buildIds", stringArray(elf.buildIds))
    put("programHeaders", JsonArray(elf.programHeaders.map(::programHeaderRecord)))
    put("sections", JsonArray(elf.sections.map(::sectionRecord)))
    put("metadata", metadataRecord(elf.metadata))
    put("executableLoad", executableLoadRecord(elf.executableLoad))
}

private fun headerRecord(header: BoundedElfHeaderV1): JsonObject = buildJsonObject {
    put("class", header.elfClass)
    put("dataEncoding", header.dataEncoding)
    put("identVersion", header.identVersion)
    put("osAbi", header.osAbi)
    put("osAbiName", header.osAbiName)
    put("abiVersion", header.abiVersion)
    put("type", unsignedJson(header.type, "ELF type"))
    put("typeName", header.typeName)
    put("machine", unsignedJson(header.machine, "ELF machine"))
    put("machineName", header.machineName)
    put("version", unsignedJson(header.version, "ELF version"))
    put("entryPoint", unsignedJson(header.entryPoint, "ELF entry point"))
    put("programHeaderOffset", unsignedJson(header.programHeaderOffset, "ELF program-header offset"))
    put("sectionHeaderOffset", unsignedJson(header.sectionHeaderOffset, "ELF section-header offset"))
    put("flags", unsignedJson(header.flags, "ELF flags"))
    put("headerSize", header.headerSize)
    put("programHeaderEntrySize", header.programHeaderEntrySize)
    put("programHeaderCount", header.programHeaderCount)
    put("sectionHeaderEntrySize", header.sectionHeaderEntrySize)
    put("sectionHeaderCount", header.sectionHeaderCount)
    put("sectionNameTableIndex", header.sectionNameTableIndex)
}

private fun identityRecord(identity: BoundedElfIdentityV1): JsonObject = buildJsonObject {
    put("class", identity.elfClass)
    put("dataEncoding", identity.dataEncoding)
    put("identVersion", identity.identVersion)
    put("osAbi", identity.osAbi)
    put("abiVersion", identity.abiVersion)
    put("type", unsignedJson(identity.type, "ELF identity type"))
    put("machine", unsignedJson(identity.machine, "ELF identity machine"))
    put("version", unsignedJson(identity.version, "ELF identity version"))
    put("entryPoint", unsignedJson(identity.entryPoint, "ELF identity entry point"))
    put("flags", unsignedJson(identity.flags, "ELF identity flags"))
}

private fun programHeaderRecord(header: BoundedElfProgramHeaderV1): JsonObject = buildJsonObject {
    put("index", header.index)
    put("type", unsignedJson(header.type, "program-header type"))
    put("typeName", header.typeName)
    put("flags", unsignedJson(header.flags, "program-header flags"))
    put("flagNames", header.flagNames)
    put("offset", unsignedJson(header.offset, "program-header offset"))
    put("virtualAddress", unsignedJson(header.virtualAddress, "program-header virtual address"))
    put("physicalAddress", unsignedJson(header.physicalAddress, "program-header physical address"))
    put("fileSize", unsignedJson(header.fileSize, "program-header file size"))
    put("memorySize", unsignedJson(header.memorySize, "program-header memory size"))
    put("alignment", unsignedJson(header.alignment, "program-header alignment"))
    put("contentSha256", header.contentSha256)
}

private fun sectionRecord(section: BoundedElfSectionV1): JsonObject = buildJsonObject {
    put("index", section.index)
    put("name", section.name)
    put("type", unsignedJson(section.type, "section type"))
    put("typeName", section.typeName)
    put("flags", unsignedJson(section.flags, "section flags"))
    put("address", unsignedJson(section.address, "section address"))
    put("offset", unsignedJson(section.offset, "section offset"))
    put("size", unsignedJson(section.size, "section size"))
    put("link", unsignedJson(section.link, "section link"))
    put("info", unsignedJson(section.info, "section info"))
    put("alignment", unsignedJson(section.alignment, "section alignment"))
    put("entrySize", unsignedJson(section.entrySize, "section entry size"))
    put("allocated", section.allocated)
    put("executable", section.executable)
    put("fileBacked", section.fileBacked)
    put("contentSha256", section.contentSha256?.let(::JsonPrimitive) ?: JsonNull)
}

private fun metadataRecord(metadata: BoundedElfMetadataV1): JsonObject = buildJsonObject {
    put("hasDwarf", metadata.hasDwarf)
    put("dwarfSections", stringArray(metadata.dwarfSections))
    put("hasStaticSymbols", metadata.hasStaticSymbols)
    put("staticSymbolTables", JsonArray(metadata.staticSymbolTables.map(::symbolTableRecord)))
    put("hasDynamicSymbols", metadata.hasDynamicSymbols)
    put("dynamicSymbolTables", JsonArray(metadata.dynamicSymbolTables.map(::symbolTableRecord)))
}

private fun symbolTableRecord(table: BoundedElfSymbolTableV1): JsonObject = buildJsonObject {
    put("section", table.section)
    put("entries", unsignedJson(table.entries, "symbol-table entry count"))
}

private fun executableLoadRecord(load: BoundedElfExecutableLoadV1): JsonObject = buildJsonObject {
    put("selector", load.selector)
    put("segmentIndexes", buildJsonArray { load.segmentIndexes.forEach { add(JsonPrimitive(it)) } })
    put("bytes", load.bytes)
    put("sha256", load.sha256)
}

private fun equivalenceRecord(equivalence: BoundedElfEquivalenceV1): JsonObject = buildJsonObject {
    put("buildId", equivalence.buildId)
    put("elfIdentity", identityRecord(equivalence.elfIdentity))
    put("programHeadersSha256", equivalence.programHeadersSha256)
    put("allocatedSectionsSha256", equivalence.allocatedSectionsSha256)
    put("executableLoad", executableLoadRecord(equivalence.executableLoad))
    put("metadataDelta", buildJsonObject {
        put("fullOnlySections", stringArray(equivalence.metadataDelta.fullOnlySections))
        put("strippedOnlySections", stringArray(equivalence.metadataDelta.strippedOnlySections))
        put("changedCommonSections", stringArray(equivalence.metadataDelta.changedCommonSections))
        put("removedDwarfSections", stringArray(equivalence.metadataDelta.removedDwarfSections))
        put(
            "removedStaticSymbolTables",
            JsonArray(equivalence.metadataDelta.removedStaticSymbolTables.map(::symbolTableRecord)),
        )
    })
}

private fun stringArray(values: List<String>): JsonArray = JsonArray(values.map(::JsonPrimitive))

private fun unsignedJson(value: ULong, label: String): JsonPrimitive {
    if (value > Long.MAX_VALUE.toULong()) manifestFail("$label exceeds the v1 JSON integer boundary")
    return JsonPrimitive(value.toLong())
}

private fun resolveRelative(base: Path, relative: String, label: String): Path {
    val normalizedRelative = requireRelativePath(relative, "$label path")
    var current = base
    normalizedRelative.split('/').forEach { component ->
        current = current.resolve(component)
        if (Files.isSymbolicLink(current)) manifestFail("$label path contains a symbolic link")
    }
    val result = current.toAbsolutePath().normalize()
    if (result == base || !result.startsWith(base)) manifestFail("$label escapes the manifest directory")
    return result
}

private fun requireRelativePath(value: String, label: String): String {
    if (
        value.isEmpty() || value.startsWith('/') || value.endsWith('/') || '\\' in value || '\u0000' in value ||
        value.split('/').any { it.isEmpty() || it == "." || it == ".." }
    ) {
        manifestFail("$label must be a normalized relative POSIX path")
    }
    return value
}

private fun requireManifestInputBaseName(value: String, label: String) {
    if ('/' in value) manifestFail("$label path must be a base name in the authenticated manifest directory")
}

private fun JsonObject.requireExactFields(expected: Set<String>, label: String) {
    if (keys != expected) {
        manifestFail("$label has invalid fields: missing=${(expected - keys).sorted()} unexpected=${(keys - expected).sorted()}")
    }
}

private fun JsonObject.requiredObject(name: String, label: String): JsonObject = this[name] as? JsonObject
    ?: manifestFail("$label field $name must be an object")

private fun JsonObject.requiredString(name: String, label: String): String {
    val primitive = this[name] as? JsonPrimitive ?: manifestFail("$label field $name must be a string")
    if (!primitive.isString || primitive.content.isEmpty() || '\u0000' in primitive.content) {
        manifestFail("$label field $name must be a non-empty string without NUL")
    }
    return primitive.content
}

private fun JsonObject.requiredLong(name: String, label: String): Long {
    val primitive = this[name] as? JsonPrimitive ?: manifestFail("$label field $name must be an integer")
    if (primitive.isString || !primitive.content.matches(NONNEGATIVE_INTEGER)) {
        manifestFail("$label field $name must be a non-negative integer")
    }
    return primitive.content.toLongOrNull()
        ?: manifestFail("$label field $name exceeds the supported integer range")
}

private fun requireSha256(value: String, label: String) {
    if (!value.matches(SHA256)) manifestFail("$label SHA-256 is invalid")
}

private fun hashChannel(channel: FileChannel, bytes: Long, maximumBytes: Long, label: String): String {
    if (bytes !in 1L..maximumBytes) manifestFail("$label byte length is outside its bound")
    val digest = MessageDigest.getInstance("SHA-256")
    val buffer = ByteArray(HASH_BUFFER_BYTES)
    var offset = 0L
    while (offset < bytes) {
        val count = minOf(buffer.size.toLong(), bytes - offset).toInt()
        val read = channel.read(ByteBuffer.wrap(buffer, 0, count), offset)
        if (read <= 0) manifestFail("$label ended during descriptor-bound hashing")
        digest.update(buffer, 0, read)
        offset += read
    }
    if (channel.size() != bytes) manifestFail("$label size changed during descriptor-bound hashing")
    return digest.digest().hex()
}

private fun ByteArray.sha256(): String = OracleArtifacts.sha256(this)

private fun ByteArray.hex(): String = joinToString(separator = "") { byte ->
    (byte.toInt() and 0xff).toString(16).padStart(2, '0')
}

private fun sameManifestObject(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    left.key == right.key && left.mountId == right.mountId

private fun sameManifestFile(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    sameManifestObject(left, right) && left.mode == right.mode && left.uid == right.uid &&
        left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isRegularFile && right.isRegularFile && !left.isDirectory && !right.isDirectory &&
        !left.isSymbolicLink && !right.isSymbolicLink

private fun sameManifestDirectory(left: LinuxFileIdentity, right: LinuxFileIdentity): Boolean =
    sameManifestObject(left, right) && left.mode == right.mode && left.uid == right.uid &&
        left.gid == right.gid && left.linkCount == right.linkCount &&
        left.isDirectory && right.isDirectory && !left.isRegularFile && !right.isRegularFile &&
        !left.isSymbolicLink && !right.isSymbolicLink

private inline fun <T> translateManifestFailure(action: () -> T): T = try {
    action()
} catch (failure: LlvmArtifactManifestException) {
    throw failure
} catch (failure: Exception) {
    throw LlvmArtifactManifestException(
        "LLVM artifact-manifest verification failed: ${failure.message ?: failure::class.simpleName}",
        failure,
    )
}

private fun manifestJsonLimits(maximumBytes: Int) = StrictJsonLimits(
    maximumInputBytes = maximumBytes,
    maximumCanonicalBytes = maximumBytes,
    maximumDepth = 64,
    maximumNodes = 100_000,
    maximumStringBytes = 64 * 1024,
    maximumTotalStringBytes = maximumBytes,
    maximumNumberCharacters = 64,
)

private fun manifestFail(message: String): Nothing = throw LlvmArtifactManifestException(message)

private const val MAXIMUM_MANIFEST_BYTES = 1024 * 1024
private const val MAXIMUM_INPUT_BYTES = 1024 * 1024
private const val HASH_BUFFER_BYTES = 64 * 1024
private const val MAXIMUM_ARTIFACT_PATH_COMPONENTS = 2
private const val UNTRUSTED_WRITE_MODE = 0x12
private val SHA256 = Regex("[0-9a-f]{64}")
private val NONNEGATIVE_INTEGER = Regex("0|[1-9][0-9]*")
