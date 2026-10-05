package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.charset.CodingErrorAction
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import java.security.MessageDigest
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Immutable Clang frontend profile identities and pure input projections for contract v1. */
object FullTreeGenericTemplateFrontendProfileV1 {
    const val PROVIDER = "clang-libtooling-cxx-v1"
    const val POLICY_ID = "full-tree-generic-template-frontend"
    const val POLICY_VERSION = 1
    const val ADAPTER_API_VERSION = "clang-libtooling-18.1.3-v1"
    const val ARGV_POLICY =
        "clang-toolinvocation-capture-dependency-frame-strip-clang18.1.3-joined-tail-allowlist-v1"
    const val ENVIRONMENT_PATH_POLICY = "captured-posix-path-to-inert-virtual-directories-v1"

    const val MAX_ENTITY_ROW_BYTES = 67_108_864L
    const val MAX_GENERIC_EVIDENCE_BYTES = 67_108_864L
    const val MAX_RESOURCE_FILES = 65_536
    const val MAX_RESOURCE_TREE_BYTES = 1_073_741_824L
    const val MAX_RESOURCE_MANIFEST_BYTES = 67_108_864
    const val MAX_PATH_BYTES = 4_096
    const val MAX_PATH_ENTRIES = 64
    const val MAX_PATH_ENTRY_BYTES = 1_024
    const val MAX_PATH_COMPONENT_BYTES = 255
    const val MAX_DRIVER_SYMLINK_HOPS = 16

    val ENVIRONMENT_ALLOWLIST: List<String> = listOf(
        "CPATH",
        "CPLUS_INCLUDE_PATH",
        "C_INCLUDE_PATH",
        "HOME",
        "LANG",
        "LC_ALL",
        "OBJCPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "PATH",
        "SDKROOT",
        "SOURCE_DATE_EPOCH",
        "TMPDIR",
        "TZ",
    )

    val PATH_LIST_ENVIRONMENT: Set<String> = setOf(
        "CPATH",
        "CPLUS_INCLUDE_PATH",
        "C_INCLUDE_PATH",
        "OBJCPLUS_INCLUDE_PATH",
        "OBJC_INCLUDE_PATH",
        "SDKROOT",
    )

    val POLICY: JsonObject by lazy {
        JsonObject(
            mapOf(
                "argvPolicy" to JsonPrimitive(ARGV_POLICY),
                "environmentAllowlist" to JsonArray(ENVIRONMENT_ALLOWLIST.map(::JsonPrimitive)),
                "environmentPathPolicy" to JsonPrimitive(ENVIRONMENT_PATH_POLICY),
                "id" to JsonPrimitive(POLICY_ID),
                "limits" to JsonObject(
                    mapOf(
                        "genericResidentCanonicalByteMultiplier" to JsonPrimitive(3),
                        "genericResidentFixedBytes" to JsonPrimitive(64),
                        "genericResidentShareDivisor" to JsonPrimitive(4),
                        "maxCxxDriverSymlinkHops" to JsonPrimitive(MAX_DRIVER_SYMLINK_HOPS),
                        "maxEntityRowBytes" to JsonPrimitive(MAX_ENTITY_ROW_BYTES),
                        "maxFormalActualDescriptorNodesPerEntity" to JsonPrimitive(1024),
                        "maxGenericEvidenceBytes" to JsonPrimitive(MAX_GENERIC_EVIDENCE_BYTES),
                        "maxMacroExpansionDepth" to JsonPrimitive(256),
                        "maxPathBytes" to JsonPrimitive(MAX_PATH_BYTES),
                        "maxPathComponentBytes" to JsonPrimitive(MAX_PATH_COMPONENT_BYTES),
                        "maxPathEntries" to JsonPrimitive(MAX_PATH_ENTRIES),
                        "maxPathEntryBytes" to JsonPrimitive(MAX_PATH_ENTRY_BYTES),
                        "maxRelationWalkDepth" to JsonPrimitive(32),
                        "maxResourceHeaderFiles" to JsonPrimitive(MAX_RESOURCE_FILES),
                        "maxResourceHeaderManifestBytes" to JsonPrimitive(MAX_RESOURCE_MANIFEST_BYTES),
                        "maxResourceHeaderTreeBytes" to JsonPrimitive(MAX_RESOURCE_TREE_BYTES),
                        "maxEdgesPerEntity" to JsonPrimitive(32),
                        "maxTypeDepth" to JsonPrimitive(64),
                        "maxTypeNodesPerDescriptor" to JsonPrimitive(4096),
                    ),
                ),
                "reasonCodes" to JsonArray(REASON_CODES.map(::JsonPrimitive)),
                "supportedArgumentKinds" to JsonArray(ARGUMENT_KINDS.map(::JsonPrimitive)),
                "supportedCallingConventionKinds" to JsonArray(CALLING_CONVENTIONS.map(::JsonPrimitive)),
                "supportedDeclarationKinds" to JsonArray(DECLARATION_KINDS.map(::JsonPrimitive)),
                "supportedEdgeKinds" to JsonArray(EDGE_KINDS.map(::JsonPrimitive)),
                "supportedEntityKinds" to JsonArray(ENTITY_KINDS.map(::JsonPrimitive)),
                "supportedQualifierKinds" to JsonArray(QUALIFIERS.map(::JsonPrimitive)),
                "supportedSpecializationKinds" to JsonArray(SPECIALIZATION_KINDS.map(::JsonPrimitive)),
                "supportedStatusKinds" to JsonArray(STATUS_KINDS.map(::JsonPrimitive)),
                "supportedTypeKinds" to JsonArray(TYPE_KINDS.map(::JsonPrimitive)),
                "unsupportedKinds" to JsonArray(UNSUPPORTED_KINDS.map(::JsonPrimitive)),
                "version" to JsonPrimitive(POLICY_VERSION),
            ),
        )
    }

    val ENTITY_KINDS = listOf(
        "concrete-instantiation", "explicit-specialization", "partial-specialization",
        "primary-template", "supporting-declaration",
    )
    val DECLARATION_KINDS = listOf("class", "class-template", "enum", "function", "function-template", "other-named", "record")
    val EDGE_KINDS = listOf(
        "declares-specialization-of", "explicit-specializes", "instantiates-function-template",
        "instantiates-partial", "instantiates-primary", "member-specialization", "redeclares",
        "specializes-primary", "templated-declaration",
    )
    val STATUS_KINDS = listOf("ambiguous", "supported", "unknown", "unsupported")
    val SPECIALIZATION_KINDS = listOf(
        "explicit-instantiation-declaration", "explicit-instantiation-definition", "explicit-specialization",
        "implicit-instantiation", "undeclared",
    )
    val QUALIFIERS = listOf("const", "restrict", "volatile")
    val TYPE_KINDS = listOf(
        "array", "builtin", "enum", "function", "lvalueReference", "pointer", "record",
        "rvalueReference", "templateParameter", "templateSpecialization",
    )
    val ARGUMENT_KINDS = listOf("integral", "pack", "template", "templateParameter", "type")
    val CALLING_CONVENTIONS = listOf(
        "aapcs", "aapcs-vfp", "aarch64-sve-pcs", "aarch64-vector-pcs", "amdgpu-kernel", "cdecl",
        "fastcall", "intel-ocl-bicc", "m68k-rtd", "opencl-kernel", "pascal", "preserve-all",
        "preserve-most", "regcall", "spir-function", "stdcall", "swift", "swift-async", "sysv64",
        "thiscall", "vectorcall", "win64",
    )
    val UNSUPPORTED_KINDS = listOf(
        "class-valued-nttp", "concepts-requires", "dependent-non-type-expression",
        "dynamic-exception-specification-dependent", "floating-nttp", "module", "other-calling-convention",
        "other-clang-argument", "other-clang-type", "pch", "pointer-nttp", "unexpanded-pack",
        "unresolved-dependent-actual", "unresolved-template-name", "variable-template",
    )
    val REASON_CODES = listOf(
        "ambiguous-template-selection", "argument-vector-incomplete", "conflicting-redeclaration-default",
        "cross-unit-target", "invalid-source-location", "limit-exceeded", "missing-source-anchor",
        "missing-template-relation", "semantic-anchor-conflict", "specialization-not-instantiated",
        "unauthenticated-input", "unresolved-dependent-actual", "unsupported-argument-kind",
        "unsupported-compiler-profile", "unsupported-concept", "unsupported-language-mode",
        "unsupported-module", "unsupported-non-type-formal-type", "unsupported-pch",
        "unsupported-template-kind", "unsupported-type-kind",
    )

    data class RuntimeLibraryDigestV1(val path: String, val sha256: String) {
        init {
            requireSha256(sha256, "runtime library digest")
            requireToolchainPath(path, "runtime library path")
        }

        internal fun json(): JsonObject = JsonObject(
            mapOf("path" to JsonPrimitive(path), "sha256" to JsonPrimitive(sha256)),
        )
    }

    data class ResourceFileV1(val path: String, val sha256: String, val bytes: Long, val regular: Boolean = true) {
        init {
            requireSha256(sha256, "resource file digest")
            require(bytes >= 0L) { "frontend profile resource manifest is invalid" }
            requireToolchainPath(path, "resource file path")
            require(regular) { "frontend profile resource tree contains a non-regular file" }
        }
    }

    data class ResourceManifestV1(
        val resolvedResourceDirectory: String,
        val files: List<ResourceFileV1>,
        val totalBytes: Long,
        val preimageBytes: Int,
        val sha256: String,
    )

    data class PathTransformV1(
        val rawPathSha256: String,
        val containerImageDigest: String,
        val virtualPathEntries: List<String>,
        val inertDirectorySha256: String,
        val pathTransformSha256: String,
    ) {
        val effectivePath: String get() = virtualPathEntries.joinToString(":")

        fun jsonForChildEnvironment(): JsonPrimitive = JsonPrimitive(effectivePath)
    }

    data class EffectiveEnvironmentV1(
        val values: Map<String, String>,
        val sha256: String,
    ) {
        fun json(): JsonObject = JsonObject(values.toSortedMap(UTF8_ORDER).mapValues { JsonPrimitive(it.value) })
    }

    /**
     * The profile member set is immutable and all digest formulas below use precisely the eleven
     * fields frozen in the accepted design's frontend-profile preimage.
     */
    data class ProfileV1(
        val compilerSha256: String,
        val cxxDriverIdentitySha256: String,
        val pathTransformSha256: String,
        val runtimeLibraryDigests: List<RuntimeLibraryDigestV1>,
        val resolvedResourceDirectory: String,
        val resourceHeaderManifestSha256: String,
        val adapterSourceRevision: String,
        val adapterSha256: String,
        val adapterApiVersion: String,
        val targetTriple: String,
        val toolchainProfileSha256: String,
        val containerImageDigest: String,
    ) {
        init {
            requireSha256(compilerSha256, "frontend compiler digest")
            requireSha256(cxxDriverIdentitySha256, "C++ driver identity digest")
            requireSha256(pathTransformSha256, "PATH transform digest")
            requireSha256(resourceHeaderManifestSha256, "resource manifest digest")
            requireSha256(adapterSha256, "frontend adapter digest")
            requireSha256(toolchainProfileSha256, "toolchain profile digest")
            requireContainerDigest(containerImageDigest)
            require(adapterSourceRevision.matches(Regex("^[0-9a-f]{40}$"))) {
                "frontend profile adapter source revision is invalid"
            }
            require(adapterApiVersion == ADAPTER_API_VERSION) {
                "frontend profile adapter API version is unsupported"
            }
            strictUtf8(targetTriple)
            require(targetTriple.matches(Regex("^[A-Za-z0-9_.+-]+$"))) {
                "frontend profile target triple is invalid"
            }
            requireToolchainPath(resolvedResourceDirectory, "resolved resource directory")
            require(runtimeLibraryDigests == runtimeLibraryDigests.sortedWith(compareByUtf8 { it.path })) {
                "frontend profile runtime digest rows are not in canonical path order"
            }
            require(runtimeLibraryDigests.map { it.path }.distinct().size == runtimeLibraryDigests.size) {
                "frontend profile repeats a runtime digest path"
            }
            require(runtimeLibraryDigests.none { it.sha256 == compilerSha256 }) {
                "frontend profile runtime closure repeats the compiler executable"
            }
        }

        fun preimage(): JsonObject = JsonObject(
            mapOf(
                "adapterApiVersion" to JsonPrimitive(adapterApiVersion),
                "adapterSha256" to JsonPrimitive(adapterSha256),
                "adapterSourceRevision" to JsonPrimitive(adapterSourceRevision),
                "compilerSha256" to JsonPrimitive(compilerSha256),
                "cxxDriverIdentitySha256" to JsonPrimitive(cxxDriverIdentitySha256),
                "pathTransformSha256" to JsonPrimitive(pathTransformSha256),
                "resourceHeaderManifestSha256" to JsonPrimitive(resourceHeaderManifestSha256),
                "resolvedResourceDirectory" to JsonPrimitive(resolvedResourceDirectory),
                "runtimeLibraryDigests" to JsonArray(runtimeLibraryDigests.map { it.json() }),
                "targetTriple" to JsonPrimitive(targetTriple),
                "toolchainProfileSha256" to JsonPrimitive(toolchainProfileSha256),
            ),
        )

        fun sha256(): String = domainHash("decomp-thing/generic-template/frontend-profile/v1", preimage())

        fun requirePathTransform(transform: PathTransformV1) {
            if (pathTransformSha256 != transform.pathTransformSha256 ||
                containerImageDigest != transform.containerImageDigest
            ) {
                fail("frontend profile does not bind the authenticated image PATH transform")
            }
        }
    }

    data class CxxDriverIdentityInputV1(
        val buildRecordSha256: String,
        val containerImageDigest: String,
        val configuredPathSha256: String,
        val symlinkChain: List<Pair<String, String>>,
        val resolvedDriverPath: String,
        val executableSha256: String,
        val executableBytes: Long,
        val executableMode: String,
        val compilerSha256: String,
        val toolchainProfileSha256: String,
    )

    /** Recompute the PATH projection without opening, resolving, or serializing raw PATH entries. */
    fun transformPath(rawPath: String, containerImageDigest: String): PathTransformV1 {
        requireContainerDigest(containerImageDigest)
        val rawBytes = strictUtf8(rawPath)
        if (rawBytes.isEmpty() || rawBytes.size > MAX_PATH_BYTES) fail("captured PATH is outside its v1 bound")
        val entries = splitPreservingEmpty(rawPath, ':')
        if (entries.size !in 1..MAX_PATH_ENTRIES) fail("captured PATH entry count is outside its v1 bound")
        entries.forEach(::requireCanonicalPosixPath)
        val virtual = entries.indices.map { index ->
            "/__decomp/toolchain/path/${index.toString().padStart(4, '0')}"
        }
        val rawSha256 = OracleArtifacts.sha256(rawBytes)
        val inertSha256 = domainHash(
            "decomp-thing/generic-template/path-directory/v1",
            JsonObject(
                mapOf(
                    "entries" to JsonArray(emptyList()),
                    "mode" to JsonPrimitive("0555"),
                ),
            ),
        )
        val transformPreimage = JsonObject(
            mapOf(
                "containerImageDigest" to JsonPrimitive(containerImageDigest),
                "environmentPathPolicy" to JsonPrimitive(ENVIRONMENT_PATH_POLICY),
                "inertDirectorySha256" to JsonPrimitive(inertSha256),
                "rawPathSha256" to JsonPrimitive(rawSha256),
                "virtualPathEntries" to JsonArray(virtual.map(::JsonPrimitive)),
            ),
        )
        return PathTransformV1(
            rawSha256,
            containerImageDigest,
            Collections.unmodifiableList(virtual),
            inertSha256,
            domainHash("decomp-thing/generic-template/path-transform/v1", transformPreimage),
        )
    }

    /**
     * Replace the captured PATH by the ordered inert VFS directories. HOME and TMPDIR are also
     * fixed isolated mounts. Empty-versus-absent is preserved for the include-path variables.
     */
    fun effectiveEnvironment(
        declaredEnvironment: Map<String, String>,
        pathTransform: PathTransformV1,
    ): EffectiveEnvironmentV1 {
        if (declaredEnvironment.size > ENVIRONMENT_ALLOWLIST.size) {
            fail("declared frontend environment exceeds its fixed allowlist")
        }
        if (declaredEnvironment.keys.any { it !in ENVIRONMENT_ALLOWLIST }) {
            fail("declared frontend environment contains a non-allowlisted variable")
        }
        declaredEnvironment.values.forEach { value ->
            strictUtf8(value)
            if ('\u0000' in value) fail("declared frontend environment contains an unreadable value")
        }
        val rawPath = declaredEnvironment["PATH"]
            ?: fail("frontend environment is missing the captured PATH")
        if (OracleArtifacts.sha256(strictUtf8(rawPath)) != pathTransform.rawPathSha256) {
            fail("frontend environment PATH differs from the authenticated raw PATH")
        }
        if (declaredEnvironment["LC_ALL"] != "C") fail("frontend environment must retain LC_ALL=C")
        if (declaredEnvironment["TZ"] != "UTC") fail("frontend environment must retain TZ=UTC")
        val epoch = declaredEnvironment["SOURCE_DATE_EPOCH"]
            ?: fail("frontend environment is missing SOURCE_DATE_EPOCH")
        if (!epoch.matches(Regex("^[1-9][0-9]*$"))) fail("frontend SOURCE_DATE_EPOCH is not canonical")
        epoch.toBigIntegerOrNull() ?: fail("frontend SOURCE_DATE_EPOCH is invalid")
        for (name in PATH_LIST_ENVIRONMENT) {
            if (declaredEnvironment[name]?.isNotEmpty() == true) {
                fail("frontend environment has a nonempty include-path variable")
            }
        }
        val values = LinkedHashMap<String, String>()
        declaredEnvironment.forEach { (name, value) ->
            when (name) {
                "PATH" -> values[name] = pathTransform.effectivePath
                "HOME" -> Unit
                "TMPDIR" -> Unit
                else -> values[name] = value
            }
        }
        values["PATH"] = pathTransform.effectivePath
        values["HOME"] = "/__decomp/home"
        values["TMPDIR"] = "/__decomp/tmp"
        val ordered = values.toSortedMap(UTF8_ORDER)
        val json = JsonObject(ordered.mapValues { JsonPrimitive(it.value) })
        return EffectiveEnvironmentV1(
            Collections.unmodifiableMap(LinkedHashMap(ordered)),
            OracleArtifacts.sha256(canonicalBytes(json, MAX_RESOURCE_MANIFEST_BYTES.toLong(), "frontend environment")),
        )
    }

    /** Hash every regular file in a complete resolved resource-directory listing. */
    fun resourceManifest(
        resolvedResourceDirectory: String,
        files: List<ResourceFileV1>,
        maximumFiles: Int = MAX_RESOURCE_FILES,
        maximumTreeBytes: Long = MAX_RESOURCE_TREE_BYTES,
        maximumPreimageBytes: Int = MAX_RESOURCE_MANIFEST_BYTES,
    ): ResourceManifestV1 {
        requireToolchainPath(resolvedResourceDirectory, "resolved resource directory")
        require(maximumFiles in 1..MAX_RESOURCE_FILES)
        require(maximumTreeBytes in 1L..MAX_RESOURCE_TREE_BYTES)
        require(maximumPreimageBytes in 1..MAX_RESOURCE_MANIFEST_BYTES)
        if (files.size > maximumFiles) fail("frontend resource tree exceeds its file limit")
        val sorted = files.map { it to strictUtf8(it.path) }
            .sortedWith { left, right -> compareUtf8Bytes(left.second, right.second) }
            .map { it.first }
        for (index in 1 until sorted.size) {
            if (sorted[index - 1].path == sorted[index].path) {
                fail("frontend resource tree repeats a normalized file path")
            }
        }
        val prefix = "$resolvedResourceDirectory/"
        if (sorted.any { !it.path.startsWith(prefix) || it.path == prefix }) {
            fail("frontend resource file is outside the resolved resource directory")
        }
        var totalBytes = 0L
        sorted.forEach { item ->
            if (item.bytes > maximumTreeBytes - totalBytes) {
                fail("frontend resource tree exceeds its byte limit")
            }
            totalBytes += item.bytes
        }
        val rows = JsonArray(sorted.map { item ->
            JsonObject(
                mapOf(
                    "path" to JsonPrimitive(item.path),
                    "sha256" to JsonPrimitive(item.sha256),
                ),
            )
        })
        val preimage = JsonObject(
            mapOf(
                "files" to rows,
                "resolvedResourceDirectory" to JsonPrimitive(resolvedResourceDirectory),
            ),
        )
        val bytes = canonicalBytes(preimage, maximumPreimageBytes.toLong(), "frontend resource manifest")
        if (bytes.size > maximumPreimageBytes) fail("frontend resource manifest exceeds its byte limit")
        return ResourceManifestV1(
            resolvedResourceDirectory,
            Collections.unmodifiableList(ArrayList(sorted)),
            totalBytes,
            bytes.size,
            domainHash("decomp-thing/generic-template/resource-directory/v1", bytes),
        )
    }

    /**
     * Re-read a resolved profile directory without following symlinks and hash every regular file.
     * The caller supplies the already authenticated, read-only toolchain rootfs; no PATH lookup or
     * host-system directory discovery is performed here.
     */
    fun loadResourceManifest(
        authenticatedToolchainRoot: Path,
        resolvedResourceDirectory: String,
        maximumFiles: Int = MAX_RESOURCE_FILES,
        maximumTreeBytes: Long = MAX_RESOURCE_TREE_BYTES,
        maximumPreimageBytes: Int = MAX_RESOURCE_MANIFEST_BYTES,
    ): ResourceManifestV1 {
        require(maximumFiles in 1..MAX_RESOURCE_FILES)
        require(maximumTreeBytes in 1L..MAX_RESOURCE_TREE_BYTES)
        require(maximumPreimageBytes in 1..MAX_RESOURCE_MANIFEST_BYTES)
        requireToolchainPath(resolvedResourceDirectory, "resolved resource directory")
        val root = authenticatedToolchainRoot.toAbsolutePath().normalize()
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(root)) {
            fail("authenticated toolchain root is unavailable")
        }
        val relative = resolvedResourceDirectory.removePrefix("toolchain/")
        val directory = root.resolve(relative).normalize()
        if (!directory.startsWith(root) || directory == root || Files.isSymbolicLink(directory) ||
            !Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)
        ) {
            fail("authenticated frontend resource directory is unavailable")
        }
        var ancestor = root
        root.relativize(directory).forEach { component ->
            ancestor = ancestor.resolve(component)
            if (Files.isSymbolicLink(ancestor) || !Files.isDirectory(ancestor, LinkOption.NOFOLLOW_LINKS)) {
                fail("authenticated frontend resource path contains a link or non-directory")
            }
        }
        val entries = ArrayList<ResourceFileV1>()
        var treeBytes = 0L
        val paths = Files.walk(directory)
        paths.use { stream ->
            val iterator = stream.iterator()
            while (iterator.hasNext()) {
                val path = iterator.next()
                if (path == directory) continue
                val attributes = try {
                    Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                } catch (failure: Exception) {
                    throw FullTreeControlException("cannot inspect authenticated frontend resource file", failure)
                }
                if (attributes.isSymbolicLink || Files.isSymbolicLink(path)) {
                    fail("authenticated frontend resource tree contains a symlink")
                }
                if (attributes.isDirectory) continue
                if (!attributes.isRegularFile) fail("authenticated frontend resource tree contains a non-regular file")
                if (entries.size >= maximumFiles) fail("frontend resource tree exceeds its file limit")
                val relativeFile = root.relativize(path.toAbsolutePath().normalize()).toString()
                    .replace(path.fileSystem.separator, "/")
                val normalized = "toolchain/$relativeFile"
                requireToolchainPath(normalized, "resource file path")
                val pinned = try {
                    StableControlFile.open(path, maximumTreeBytes, "authenticated frontend resource file")
                } catch (failure: Exception) {
                    throw FullTreeControlException("cannot open authenticated frontend resource file", failure)
                }
                pinned.use { file ->
                    file.requireSingleLink("authenticated frontend resource file")
                    treeBytes = Math.addExact(treeBytes, file.size)
                    if (treeBytes > maximumTreeBytes) fail("frontend resource tree exceeds its byte limit")
                    entries += ResourceFileV1(normalized, file.sha256(), file.size)
                    file.verifyUnchanged("authenticated frontend resource file")
                }
            }
        }
        return resourceManifest(
            resolvedResourceDirectory,
            entries,
            maximumFiles,
            maximumTreeBytes,
            maximumPreimageBytes,
        )
    }

    /** Recompute the exact ten-field C++ driver identity required by amendment 6. */
    fun cxxDriverIdentity(input: CxxDriverIdentityInputV1): String {
        requireSha256(input.buildRecordSha256, "build record digest")
        requireContainerDigest(input.containerImageDigest)
        requireSha256(input.configuredPathSha256, "configured C++ path digest")
        requireToolchainPath(input.resolvedDriverPath, "resolved C++ driver path")
        requireSha256(input.executableSha256, "resolved C++ executable digest")
        requireSha256(input.compilerSha256, "registered compiler digest")
        requireSha256(input.toolchainProfileSha256, "toolchain profile digest")
        if (input.executableBytes <= 0L || input.executableSha256 != input.compilerSha256) {
            fail("resolved C++ executable differs from the registered compiler bytes")
        }
        val executableMode = input.executableMode.takeIf { it.matches(Regex("^[0-7]{4}$")) }
            ?.toIntOrNull(8) ?: fail("resolved C++ driver mode is invalid")
        if ((executableMode and 0b001_001_001) == 0) {
            fail("resolved C++ driver is not executable")
        }
        if (input.symlinkChain.size > MAX_DRIVER_SYMLINK_HOPS) {
            fail("resolved C++ driver exceeds its symlink-hop limit")
        }
        val seen = HashSet<String>()
        val hops = input.symlinkChain.map { (path, targetDigest) ->
            requireToolchainPath(path, "C++ driver symlink path")
            requireSha256(targetDigest, "C++ driver symlink target digest")
            if (!seen.add(path)) fail("resolved C++ driver has a symlink cycle")
            JsonObject(
                mapOf(
                    "path" to JsonPrimitive(path),
                    "targetBytesSha256" to JsonPrimitive(targetDigest),
                ),
            )
        }
        val symlinkChainSha256 = domainHash(
            "decomp-thing/generic-template/cxx-driver-symlink-chain/v1",
            JsonArray(hops),
        )
        val preimage = JsonObject(
            mapOf(
                "buildRecordSha256" to JsonPrimitive(input.buildRecordSha256),
                "compilerSha256" to JsonPrimitive(input.compilerSha256),
                "containerImageDigest" to JsonPrimitive(input.containerImageDigest),
                "configuredPathSha256" to JsonPrimitive(input.configuredPathSha256),
                "executableBytes" to JsonPrimitive(input.executableBytes),
                "executableMode" to JsonPrimitive(input.executableMode),
                "executableSha256" to JsonPrimitive(input.executableSha256),
                "resolvedDriverPath" to JsonPrimitive(input.resolvedDriverPath),
                "symlinkChainSha256" to JsonPrimitive(symlinkChainSha256),
                "toolchainProfileSha256" to JsonPrimitive(input.toolchainProfileSha256),
            ),
        )
        return domainHash("decomp-thing/generic-template/cxx-driver-identity/v1", preimage)
    }

    /** Compare full profile preimages before accepting multiple units in a run. */
    fun requireHomogeneousProfiles(profiles: Collection<ProfileV1>): ProfileV1 {
        val values = profiles.toList()
        if (values.isEmpty()) fail("frontend run has no authenticated profile")
        val firstBytes = canonicalBytes(
            values.first().preimage(), MAX_RESOURCE_MANIFEST_BYTES.toLong(), "frontend profile preimage",
        )
        val firstDigest = values.first().sha256()
        if (values.drop(1).any { it.sha256() != firstDigest ||
                !canonicalBytes(it.preimage(), MAX_RESOURCE_MANIFEST_BYTES.toLong(), "frontend profile preimage")
                    .contentEquals(firstBytes) }) {
            fail("frontend run mixes distinct profile preimages")
        }
        return values.first()
    }

    fun domainHash(domain: String, value: JsonElement): String {
        val domainBytes = domain.toByteArray(StandardCharsets.US_ASCII)
        val payload = canonicalBytes(value, MAX_RESOURCE_MANIFEST_BYTES.toLong(), "frontend digest preimage")
        return domainHash(domainBytes, payload)
    }

    fun domainHash(domain: String, canonicalPayload: ByteArray): String =
        domainHash(domain.toByteArray(StandardCharsets.US_ASCII), canonicalPayload)

    fun canonicalBytes(value: JsonElement, maximumBytes: Long, label: String): ByteArray {
        val bounded = minOf(maximumBytes, MAX_RESOURCE_MANIFEST_BYTES.toLong()).toInt()
        if (maximumBytes <= 0L) fail("$label byte limit is invalid")
        return try {
            OracleJson.canonicalBytes(
                value,
                StrictJsonLimits(
                    maximumInputBytes = bounded,
                    maximumCanonicalBytes = bounded,
                    maximumDepth = 128,
                    maximumNodes = 1_000_000,
                    maximumStringBytes = bounded,
                    maximumTotalStringBytes = bounded,
                ),
            )
        } catch (failure: Exception) {
            throw FullTreeControlException("$label exceeds its canonical JSON byte or structure limit", failure)
        }
    }

    private fun domainHash(domain: ByteArray, payload: ByteArray): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(domain)
        digest.update(0.toByte())
        digest.update(payload)
        return digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }

    fun strictUtf8(value: String): ByteArray = try {
        val buffer = StandardCharsets.UTF_8.newEncoder()
            .onMalformedInput(CodingErrorAction.REPORT)
            .onUnmappableCharacter(CodingErrorAction.REPORT)
            .encode(java.nio.CharBuffer.wrap(value))
        ByteArray(buffer.remaining()).also(buffer::get)
    } catch (failure: Exception) {
        throw FullTreeControlException("frontend contract contains a non-UTF-8 string", failure)
    }

    fun requireCanonicalClosurePath(value: String, label: String = "closure path"): String {
        val bytes = strictUtf8(value)
        if (bytes.isEmpty() || bytes.size > 4096 || value.startsWith('/') || value.contains('\\') || '\u0000' in value) {
            fail("frontend $label is invalid")
        }
        val parts = value.split('/')
        if (parts.any { it.isEmpty() || it == "." || it == ".." }) fail("frontend $label is invalid")
        if (parts.first() !in setOf("source", "generated", "build", "toolchain")) {
            fail("frontend $label is outside the authenticated closure")
        }
        parts.drop(1).forEach { part ->
            if (strictUtf8(part).size > MAX_PATH_COMPONENT_BYTES) fail("frontend $label is invalid")
        }
        return value
    }

    fun requireSha256(value: String, label: String = "digest") {
        if (!value.matches(Regex("^[0-9a-f]{64}$"))) fail("frontend $label is invalid")
    }

    fun compareUtf8(left: String, right: String): Int {
        val a = strictUtf8(left)
        val b = strictUtf8(right)
        return compareUtf8Bytes(a, b)
    }

    private fun compareUtf8Bytes(a: ByteArray, b: ByteArray): Int {
        val length = minOf(a.size, b.size)
        for (index in 0 until length) {
            val difference = (a[index].toInt() and 0xff) - (b[index].toInt() and 0xff)
            if (difference != 0) return difference
        }
        return a.size - b.size
    }

    private fun requireCanonicalPosixPath(value: String) {
        val bytes = strictUtf8(value)
        if (bytes.isEmpty() || bytes.size > MAX_PATH_ENTRY_BYTES || !value.startsWith('/') ||
            value.startsWith("//") || value.contains("//") || '\u0000' in value
        ) {
            fail("captured PATH contains an invalid absolute entry")
        }
        if (value != "/" && value.endsWith('/')) fail("captured PATH contains a non-canonical entry")
        val components = if (value == "/") emptyList() else value.substring(1).split('/')
        if (components.any { it.isEmpty() || it == "." || it == ".." || strictUtf8(it).size > MAX_PATH_COMPONENT_BYTES }) {
            fail("captured PATH contains an invalid path component")
        }
    }

    private fun requireToolchainPath(value: String, label: String) {
        val normalized = requireCanonicalClosurePath(value, label)
        if (!normalized.startsWith("toolchain/") || normalized.length == "toolchain/".length) {
            fail("frontend $label is outside the authenticated toolchain")
        }
    }

    private fun requireContainerDigest(value: String) {
        if (!value.matches(Regex("^sha256:[0-9a-f]{64}$"))) {
            fail("frontend container image digest is invalid")
        }
    }

    private fun splitPreservingEmpty(value: String, delimiter: Char): List<String> {
        val result = ArrayList<String>()
        var start = 0
        value.forEachIndexed { index, char ->
            if (char == delimiter) {
                result += value.substring(start, index)
                start = index + 1
            }
        }
        result += value.substring(start)
        return result
    }

    private fun fail(message: String): Nothing = throw FullTreeControlException(message)

    private val UTF8_ORDER = Comparator<String>(::compareUtf8)
    private fun <T> compareByUtf8(selector: (T) -> String): Comparator<T> =
        Comparator { left, right -> compareUtf8(selector(left), selector(right)) }
}
