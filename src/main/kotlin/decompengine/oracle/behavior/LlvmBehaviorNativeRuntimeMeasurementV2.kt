package decompengine.oracle.behavior

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.fulltree.StableControlFile
import java.lang.reflect.InvocationTargetException
import java.io.ByteArrayInputStream
import java.io.DataInputStream
import java.nio.file.Path
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

internal class LlvmBehaviorNativeRuntimeMeasurementV2Exception(message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause)

/**
 * A measurement candidate is deliberately not a runtime profile, reference definition, policy,
 * receipt of containment, or permission to START. It records independently retained raw inputs
 * and the actual read-only export; a separately reviewed production profile is still required.
 */
internal class LlvmBehaviorNativeRuntimeMeasurementV2Candidate private constructor(
    private val canonical: ByteArray,
) {
    val sha256: String = OracleArtifacts.sha256(canonical)
    fun canonicalBytes(): ByteArray = canonical.copyOf()

    companion object {
        internal fun measured(value: JsonObject, checkpoint: (String) -> Unit):
            LlvmBehaviorNativeRuntimeMeasurementV2Candidate {
            if (value["artifactKind"] != JsonPrimitive("native-runtime-measurement-candidate") ||
                value["authority"] != JsonPrimitive("unapproved-raw-measurement-only") ||
                listOf("oracleAuthority", "runtimeProfileApproved", "startAuthorized", "containmentProved",
                    "scoringAuthority", "releaseEligible").any { value[it] != JsonPrimitive(false) }
            ) measurementFail("raw measurement candidate cannot claim production or execution authority")
            return LlvmBehaviorNativeRuntimeMeasurementV2Candidate(
                OracleJson.canonicalBytes(value, NATIVE_MEASUREMENT_JSON_LIMITS, checkpoint),
            )
        }
    }
}

/** Fixed Docker 29.7.2 measurement factory. No caller supplied runtime JSON or tool pin is accepted. */
internal object LlvmBehaviorNativeRuntimeMeasurementV2 {
    fun measure(
        ociLayout: Path,
        controlClient: Path,
        emptyPrivateDockerConfig: Path,
        privateRuntimeSocket: Path,
    ): LlvmBehaviorNativeRuntimeMeasurementV2Candidate {
        val deadline = AnalysisDeadline.start(
            TimeUnit.MINUTES.toNanos(10), "native runtime V2 raw measurement",
        )
        val checkpoint: (String) -> Unit = deadline::checkpoint
        val deploymentPath = try {
            val location = LlvmBehaviorNativeRuntimeMeasurementV2::class.java.protectionDomain
                ?.codeSource?.location ?: measurementFail("measurement has no own deployment origin")
            Path.of(location.toURI()).toAbsolutePath().normalize()
        } catch (failure: Exception) {
            measurementFail("cannot select the measurement's own deployment JAR", failure)
        }
        if (!deploymentPath.fileName.toString().endsWith(".jar")) {
            measurementFail("production runtime measurement requires its own installed application JAR")
        }
        StableControlFile.openWithCheckpoint(
            deploymentPath, 512L * 1024 * 1024, "native measurement deployment", checkpoint,
        ).use { deployment ->
            requireOwnMeasurementClasses(deploymentPath, checkpoint)
            deployment.verifyUnchanged("native measurement deployment class-origin check")
            PinnedMeasurementCodecs.open(deploymentPath.parent, checkpoint).use { codecs ->
            LlvmBehaviorNativeOciImageV2.openLayout(ociLayout, checkpoint).use { image ->
                val recipe = ownRecipeBinding(deploymentPath, image, checkpoint)
                val bindings = captureFixed(controlClient, emptyPrivateDockerConfig, privateRuntimeSocket, deadline)
                bindings.use {
                    val measured = consumeFixed(bindings, image, deadline)
                    val subject = image.resolve("/subject/executable")
                    if (subject.kind != "regular" || subject.size != 84_561_368L ||
                        subject.contentSha256 != "65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006" ||
                        !subject.modeKnown || subject.mode and 0x49L == 0L
                    ) measurementFail("raw image lacks the independently locked LLVM22.1.6 subject executable")
                    val elfClosure = measureElfClosure(image, "/subject/executable", checkpoint)
                    image.requireCurrent(checkpoint)
                    codecs.requireCurrent(checkpoint)
                    deployment.verifyUnchanged("native measurement deployment terminal check")
                    if (deployment.sha256(checkpoint, "native measurement deployment terminal bytes") !=
                        deployment.authenticatedSha256
                    ) measurementFail("measurement deployment bytes changed")
                    checkpoint("before native measurement candidate rendering")
                    val candidate = LlvmBehaviorNativeRuntimeMeasurementV2Candidate.measured(
                        JsonObject(linkedMapOf(
                            "schemaVersion" to JsonPrimitive(2),
                            "artifactKind" to JsonPrimitive("native-runtime-measurement-candidate"),
                            "authority" to JsonPrimitive("unapproved-raw-measurement-only"),
                            "oracleAuthority" to JsonPrimitive(false),
                            "runtimeProfileApproved" to JsonPrimitive(false),
                            "startAuthorized" to JsonPrimitive(false),
                            "containmentProved" to JsonPrimitive(false),
                            "scoringAuthority" to JsonPrimitive(false),
                            "releaseEligible" to JsonPrimitive(false),
                            "deploymentJarSha256" to JsonPrimitive(deployment.authenticatedSha256),
                            "deploymentJarBytes" to JsonPrimitive(deployment.size),
                            "codecDeploymentInputs" to codecs.facts,
                            "measurementRecipeBinding" to recipe,
                            "rawOciIndexSha256" to JsonPrimitive(image.indexSha256),
                            "rawOciIndexBytes" to JsonPrimitive(image.indexBytes),
                            "rawOciManifestSha256" to JsonPrimitive(image.manifestSha256),
                            "rawOciManifestBytes" to JsonPrimitive(image.manifestBytes),
                            "rawConfigSha256" to JsonPrimitive(image.configSha256),
                            "rawConfigBytes" to JsonPrimitive(image.configBytes),
                            "mergedNamespaceSha256" to JsonPrimitive(image.namespaceSha256),
                            "mergedNamespaceEntries" to JsonPrimitive(image.namespace.size),
                            "orderedRawLayers" to JsonArray(image.layers.map { layer ->
                                JsonObject(linkedMapOf(
                                    "blobSha256" to JsonPrimitive(layer.blobSha256),
                                    "blobBytes" to JsonPrimitive(layer.blobBytes),
                                    "mediaType" to JsonPrimitive(layer.mediaType),
                                    "uncompressedDiffId" to JsonPrimitive(layer.diffId),
                                    "uncompressedBytes" to JsonPrimitive(layer.uncompressedBytes),
                                ))
                            }),
                            "readOnlyRuntime" to measured,
                            "subjectStaticElfClosure" to elfClosure,
                        )), checkpoint,
                    )
                    image.requireCurrent(checkpoint)
                    codecs.requireCurrent(checkpoint)
                    deployment.verifyUnchanged("native measurement deployment final candidate check")
                    if (deployment.sha256(checkpoint, "native measurement deployment final candidate bytes") !=
                        deployment.authenticatedSha256
                    ) measurementFail("measurement deployment bytes changed before candidate return")
                    verifyFixedTerminal(bindings, deadline)
                    return candidate
                }
            }
            }
        }
    }

    private fun consumeFixed(
        bindings: PinnedDockerRuntimeBindings,
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        deadline: AnalysisDeadline,
    ): JsonObject {
        val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
            it.name == "measureNativeRuntimeV2"
        }
        check(bridge.trySetAccessible())
        return try {
            bridge.invoke(PinnedDockerRuntimeBindings.Companion, bindings, image, deadline) as JsonObject
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private fun captureFixed(client: Path, config: Path, socket: Path, deadline: AnalysisDeadline): PinnedDockerRuntimeBindings {
        val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
            it.name == "captureForNativeRuntimeV2"
        }
        check(bridge.trySetAccessible())
        return try {
            bridge.invoke(PinnedDockerRuntimeBindings.Companion, client, config, socket, deadline) as PinnedDockerRuntimeBindings
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private fun verifyFixedTerminal(bindings: PinnedDockerRuntimeBindings, deadline: AnalysisDeadline) {
        val bridge = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
            it.name == "verifyNativeRuntimeV2Terminal"
        }
        check(bridge.trySetAccessible())
        try {
            bridge.invoke(PinnedDockerRuntimeBindings.Companion, bindings, deadline)
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }


    private data class ElfLoad(val offset: Long, val address: Long, val fileBytes: Long)
    private data class ElfMetadata(
        val entry: LlvmBehaviorNativeOciImageV2.Entry,
        val type: Int,
        val interpreter: String?,
        val needed: List<String>,
        val soname: String?,
        val rpath: String?,
        val runpath: String?,
        val flags1: Long,
        val unsupportedDynamic: List<String>,
    )
    private data class LoaderCacheEntry(val name: String, val path: String, val flags: Long, val hwcap: Long, val hwcapName: String? = null)
    private data class LoaderCache(
        val facts: JsonObject,
        val entries: List<LoaderCacheEntry>,
    )
    private data class ElfContext(val path: String, val ancestors: List<String>)

    /**
     * Static, read-only candidate graph under an explicitly stated glibc search model. Actual
     * loader bytes are retained, but neither their built-in search directories nor CPU/auxv,
     * secure-execution state, LD_* variables, preload/audit, symbol versions, relocations or
     * dlopen are qualified here. A complete measured graph must never become START authority.
     * Format/search references: glibc-2.39 sysdeps/generic/dl-cache.h, sysdeps/x86_64/dl-cache.h,
     * sysdeps/generic/ldconfig.h and elf/dl-load.c, in the upstream bminor/glibc repository.
     */
    private fun measureElfClosure(
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        subjectPath: String,
        checkpoint: (String) -> Unit,
    ): JsonObject {
        image.requireCurrent(checkpoint)
        val cache = readLoaderCache(image, checkpoint)
        val metadata = LinkedHashMap<Long, ElfMetadata>()
        val paths = LinkedHashMap<String, ElfMetadata>()
        val issues = LinkedHashSet<String>()
        val edges = ArrayList<JsonObject>()
        val contexts = HashSet<ElfContext>()
        val queue = ArrayDeque<ElfContext>()
        val loadedAliases = LinkedHashMap<String, String>()
        var metadataStringBytes = 0L
        var searchCount = 0
        var searchStringBytes = 0L
        fun chargeSearch(path: String, provenance: String) {
            searchCount++
            searchStringBytes += path.length.toLong() + provenance.length
            if (searchCount > 8192 || searchStringBytes > 1024 * 1024) measurementFail("static ELF graph search facts exceed their aggregate ceiling")
        }
        fun load(path: String): ElfMetadata {
            val entry = image.resolve(path)
            return metadata[entry.inode]?.also { paths[path] = it } ?: readElf(image, path, checkpoint).also {
                if (metadata.size >= 256) measurementFail("static ELF graph exceeds 256 nodes")
                metadataStringBytes += (listOfNotNull(it.entry.path, it.interpreter, it.soname, it.rpath, it.runpath) + it.needed).sumOf { value -> value.length.toLong() }
                if (metadataStringBytes > 1024 * 1024) measurementFail("static ELF graph metadata strings exceed their aggregate ceiling")
                metadata[entry.inode] = it
                paths[path] = it
                if (it.unsupportedDynamic.isNotEmpty()) issues += "unsupported dynamic loading tags at $path"
                if (entry.modeKnown && entry.mode and 0xc00L != 0L) issues += "set-id execution semantics are unqualified at $path"
            }
        }
        val subject = load(subjectPath)
        subject.soname?.let { loadedAliases[it] = subjectPath }
        queue += ElfContext(subjectPath, emptyList())
        val interpreterFacts = subject.interpreter?.let { path ->
            val entry = optionalEntry(image, path)
            if (entry == null) {
                issues += "PT_INTERP is absent from the measured namespace: $path"
                JsonObject(mapOf("requestedPath" to JsonPrimitive(path), "present" to JsonPrimitive(false)))
            } else {
                val loader = load(path)
                loader.soname?.let { loadedAliases.putIfAbsent(it, path) }
                queue += ElfContext(path, emptyList())
                JsonObject(linkedMapOf("requestedPath" to JsonPrimitive(path), "present" to JsonPrimitive(true),
                    "resolvedPath" to JsonPrimitive(loader.entry.path), "inode" to JsonPrimitive(loader.entry.inode),
                    "bytes" to JsonPrimitive(loader.entry.size), "sha256" to JsonPrimitive(loader.entry.contentSha256)))
            }
        } ?: JsonObject(mapOf("present" to JsonPrimitive(false)))
        while (queue.isNotEmpty()) {
            checkpoint("while measuring static ELF dependency graph")
            val context = queue.removeFirst()
            if (!contexts.add(context)) continue
            if (contexts.size > 2048) measurementFail("static ELF graph exceeds 2048 load contexts")
            val requester = load(context.path)
            for (name in requester.needed) {
                if (edges.size >= 2048) measurementFail("static ELF graph exceeds 2048 dependency edges")
                val searches = ArrayList<JsonObject>()
                val candidates = LinkedHashSet<String>()
                var uncertain = false
                fun candidate(path: String, provenance: String, conditional: Boolean = false): Boolean {
                    val entry = optionalEntry(image, path)
                    chargeSearch(path, provenance)
                    searches += JsonObject(linkedMapOf("path" to JsonPrimitive(path),
                        "provenance" to JsonPrimitive(provenance), "present" to JsonPrimitive(entry != null),
                        "conditional" to JsonPrimitive(conditional)))
                    if (searches.size > 512) measurementFail("ELF dependency search exceeds 512 candidates")
                    if (entry == null) return false
                    if (entry.kind != "regular") measurementFail("ELF dependency search found a non-regular file: $path")
                    candidates += path
                    uncertain = uncertain || conditional
                    return true
                }
                fun directory(directory: String, provenance: String): Boolean {
                    // open_path may select a glibc-hwcaps subdirectory before the base directory.
                    // Record every present x86-64 variant rather than invent the unmeasured auxv.
                    var hwcaps = false
                    for (level in listOf("x86-64-v4", "x86-64-v3", "x86-64-v2")) {
                        hwcaps = candidate("$directory/glibc-hwcaps/$level/$name", "$provenance/glibc-hwcaps", true) || hwcaps
                    }
                    val base = candidate("$directory/$name", provenance)
                    return hwcaps || base
                }
                val originPath = if (context.path == subjectPath) requester.entry.path else context.path
                val expandedName = expandOrigin(name, originPath)
                if (expandedName != null && expandedName in loadedAliases) {
                    candidate(loadedAliases.getValue(expandedName), "previously-loaded-DT_NEEDED-or-SONAME")
                } else if (expandedName == null) {
                    issues += "unqualified dynamic string token in DT_NEEDED at ${context.path}"
                    uncertain = true
                } else if (expandedName.contains('/')) {
                    if (!expandedName.startsWith('/')) {
                        issues += "relative DT_NEEDED needs an unmeasured working directory at ${context.path}"
                        uncertain = true
                    } else candidate(expandedName, "DT_NEEDED-explicit-path")
                } else {
                    // glibc skips the complete inherited RPATH chain when the requester has RUNPATH;
                    // each ancestor's own RUNPATH also suppresses its RPATH (cache_rpath semantics).
                    var found = false
                    if (requester.runpath == null) {
                        val owners = (listOf(context.path) + context.ancestors + subjectPath).distinct()
                        for (ownerPath in owners) {
                            val owner = load(ownerPath)
                            if (owner.runpath != null || owner.rpath == null) continue
                            val directories = searchDirectories(owner.rpath, if (ownerPath == subjectPath) owner.entry.path else ownerPath, issues)
                            if (directories == null) uncertain = true
                            for (dir in directories.orEmpty()) {
                                if (directory(dir, "DT_RPATH:$ownerPath")) { found = true; break }
                            }
                            if (found) break
                        }
                    }
                    // LD_LIBRARY_PATH is explicitly unknown, not silently derived from the host.
                    if (!found && requester.runpath != null) {
                        val directories = searchDirectories(requester.runpath, originPath, issues)
                        if (directories == null) uncertain = true
                        for (dir in directories.orEmpty()) {
                            if (directory(dir, "DT_RUNPATH:${context.path}")) { found = true; break }
                        }
                    }
                    if (!found) {
                        val cached = cache.entries.filter { it.name == name && it.flags == 0x303L }
                        if (requester.flags1 and 0x800L != 0L && cached.isNotEmpty()) {
                            issues += "DF_1_NODEFLIB cache filtering needs unqualified built-in directories at ${context.path}"
                            uncertain = true
                        }
                        for (entry in cached) {
                            chargeSearch(entry.path, "ld.so.cache")
                            searches += JsonObject(linkedMapOf("path" to JsonPrimitive(entry.path),
                                "provenance" to JsonPrimitive("ld.so.cache"), "flags" to JsonPrimitive(entry.flags),
                                "hwcapUnsigned" to JsonPrimitive(entry.hwcap.toULong().toString()),
                                "hwcapName" to (entry.hwcapName?.let(::JsonPrimitive) ?: kotlinx.serialization.json.JsonNull),
                                "present" to JsonPrimitive(optionalEntry(image, entry.path) != null),
                                "conditional" to JsonPrimitive(entry.hwcap != 0L)))
                            if (searches.size > 512) measurementFail("ELF dependency cache search exceeds 512 candidates")
                            if (optionalEntry(image, entry.path)?.kind == "regular") candidates += entry.path
                            else issues += "cached library path is absent or non-regular: ${entry.path}"
                        }
                        if (cached.any { it.hwcap != 0L } || candidates.size > 1) uncertain = true
                        found = candidates.isNotEmpty()
                    }
                    if (!found && requester.flags1 and 0x800L == 0L) {
                        // These are measured candidates, never asserted loader-built search paths.
                        issues += "default-directory fallback is not bound to actual loader build at ${context.path}: $name"
                        uncertain = true
                        for (dir in listOf("/lib/x86_64-linux-gnu", "/usr/lib/x86_64-linux-gnu", "/lib64", "/usr/lib64", "/lib", "/usr/lib")) {
                            directory(dir, "unqualified-default-directory-candidate")
                        }
                    }
                }
                if (candidates.isEmpty()) issues += "DT_NEEDED has no measured candidate at ${context.path}: $name"
                if (uncertain || candidates.size > 1) issues += "DT_NEEDED selection is unqualified or ambiguous at ${context.path}: $name"
                val selected = candidates.map { path ->
                    val target = load(path)
                    if (candidates.size == 1 && !uncertain) {
                        for (alias in listOfNotNull(expandedName, target.soname)) {
                            val prior = loadedAliases.putIfAbsent(alias, path)
                            if (prior != null && image.resolve(prior).inode != target.entry.inode) {
                                issues += "previously loaded SONAME conflicts with a new inode: $alias"
                                uncertain = true
                            }
                        }
                    }
                    // The first BFS discovery models l_loader; repeated/shared references reuse the
                    // retained inode instead of changing its inherited RPATH with each later edge.
                    if (contexts.none { paths[it.path]?.entry?.inode == target.entry.inode } &&
                        queue.none { paths[it.path]?.entry?.inode == target.entry.inode }
                    ) queue += ElfContext(path, listOf(context.path) + context.ancestors)
                    JsonObject(linkedMapOf("requestedPath" to JsonPrimitive(path),
                        "resolvedPath" to JsonPrimitive(target.entry.path), "inode" to JsonPrimitive(target.entry.inode),
                        "sha256" to JsonPrimitive(target.entry.contentSha256)))
                }
                edges += JsonObject(linkedMapOf("requester" to JsonPrimitive(context.path),
                    "needed" to JsonPrimitive(name), "searches" to JsonArray(searches),
                    "candidates" to JsonArray(selected),
                    "selectionUniqueUnderStatedModel" to JsonPrimitive(candidates.size == 1 && !uncertain)))
            }
        }
        image.requireCurrent(checkpoint)
        return JsonObject(linkedMapOf(
            "scope" to JsonPrimitive("read-only-ELF64-x86-64-static-dependency-candidates"),
            "subjectRequestedPath" to JsonPrimitive(subjectPath),
            "interpreter" to interpreterFacts,
            "glibcSearchModelVersion" to JsonPrimitive("2.39-static-source-model"),
            "loaderSearchImplementationQualified" to JsonPrimitive(false),
            "loaderBuiltInDirectoriesQualified" to JsonPrimitive(false),
            "processEnvironmentAndAuxvQualified" to JsonPrimitive(false),
            "dynamicDlopenAndSymbolResolutionQualified" to JsonPrimitive(false),
            "libraryClosureQualified" to JsonPrimitive(false),
            "staticGraphCompleteUnderStatedModel" to JsonPrimitive(issues.isEmpty()),
            "loaderCache" to cache.facts,
            "nodes" to JsonArray(metadata.values.map { elf -> JsonObject(linkedMapOf(
                "resolvedPath" to JsonPrimitive(elf.entry.path), "inode" to JsonPrimitive(elf.entry.inode),
                "bytes" to JsonPrimitive(elf.entry.size), "sha256" to JsonPrimitive(elf.entry.contentSha256),
                "elfType" to JsonPrimitive(elf.type), "needed" to JsonArray(elf.needed.map(::JsonPrimitive)),
                "soname" to (elf.soname?.let(::JsonPrimitive) ?: kotlinx.serialization.json.JsonNull),
                "interpreter" to (elf.interpreter?.let(::JsonPrimitive) ?: kotlinx.serialization.json.JsonNull),
                "rpath" to (elf.rpath?.let(::JsonPrimitive) ?: kotlinx.serialization.json.JsonNull),
                "runpath" to (elf.runpath?.let(::JsonPrimitive) ?: kotlinx.serialization.json.JsonNull),
                "flags1" to JsonPrimitive(elf.flags1),
                "unsupportedDynamicTags" to JsonArray(elf.unsupportedDynamic.map(::JsonPrimitive)),
            )) }),
            "edges" to JsonArray(edges), "incompleteReasons" to JsonArray(issues.map(::JsonPrimitive)),
        ))
    }

    private fun optionalEntry(image: LlvmBehaviorNativeOciImageV2.MeasuredImage, path: String): LlvmBehaviorNativeOciImageV2.Entry? =
        try { image.resolve(path) } catch (failure: LlvmBehaviorNativeOciImageV2Exception) {
            if (failure.message?.startsWith("container path is absent:") == true) null else throw failure
        }

    private fun searchDirectories(raw: String, originPath: String, issues: MutableSet<String>): List<String>? {
        val result = ArrayList<String>()
        var valid = true
        for (part in raw.split(':', ';')) {
            val expanded = expandOrigin(part, originPath)
            if (expanded == null || !expanded.startsWith('/')) {
                issues += "relative, empty or unsupported dynamic search directory at $originPath"
                valid = false
            } else result += expanded.trimEnd('/').ifEmpty { "/" }
            if (result.size > 128) measurementFail("ELF search directory count exceeds 128")
        }
        // Do not continue with a partial ordered search list: an unknown earlier directory could
        // select a different inode before a later measured candidate.
        return if (valid) result else null
    }

    private fun expandOrigin(raw: String, originPath: String): String? {
        val origin = originPath.substringBeforeLast('/').ifEmpty { "/" }
        val result = StringBuilder()
        var cursor = 0
        while (cursor < raw.length) {
            if (raw[cursor] != '$') { result.append(raw[cursor++]); continue }
            val token = if (raw.startsWith("\${ORIGIN}", cursor)) "\${ORIGIN}" else if (raw.startsWith("\$ORIGIN", cursor)) "\$ORIGIN" else return null
            val end = cursor + token.length
            if (token == "\$ORIGIN" && end < raw.length && (raw[end].isLetterOrDigit() || raw[end] == '_')) return null
            result.append(origin)
            cursor = end
            if (result.length > 4096) measurementFail("expanded ELF dynamic string exceeds its bound")
        }
        return result.toString().takeIf { it.length <= 4096 }
    }

    private fun readElf(
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        path: String,
        checkpoint: (String) -> Unit,
    ): ElfMetadata {
        val entry = image.resolve(path)
        if (entry.kind != "regular" || entry.size < 64) measurementFail("ELF candidate is not a regular header-sized file: $path")
        val header = image.readFileRange(path, 0, 64, checkpoint)
        val h = little(header)
        if (!header.copyOfRange(0, 7).contentEquals(byteArrayOf(0x7f, 69, 76, 70, 2, 1, 1)) ||
            (header[7].toInt() and 255) !in listOf(0, 3) || h.getShort(18).toInt() and 65535 != 62 ||
            h.getInt(20) != 1 || h.getShort(52).toInt() and 65535 != 64 || h.getShort(54).toInt() and 65535 != 56
        ) measurementFail("ELF candidate is not supported ELF64 little-endian x86-64: $path")
        val type = h.getShort(16).toInt() and 65535
        if (type !in listOf(2, 3)) measurementFail("ELF candidate is neither executable nor shared object: $path")
        val phCount = h.getShort(56).toInt() and 65535
        if (phCount !in 1..1024) measurementFail("ELF program-header count is unsupported or unbounded")
        val phOffset = unsignedLong(h.getLong(32), "program-header offset")
        requireFileRange(entry.size, phOffset, phCount * 56L, "ELF program headers")
        val ph = little(image.readFileRange(path, phOffset, phCount * 56, checkpoint))
        val loads = ArrayList<ElfLoad>()
        var dynamic: ElfLoad? = null
        var interpreterRange: Pair<Long, Int>? = null
        for (index in 0 until phCount) {
            checkpoint("while decoding bounded ELF program headers")
            val offset = index * 56
            val kind = ph.getInt(offset)
            val fileOffset = unsignedLong(ph.getLong(offset + 8), "segment offset")
            val address = unsignedLong(ph.getLong(offset + 16), "segment virtual address")
            val fileSize = unsignedLong(ph.getLong(offset + 32), "segment file bytes")
            val memorySize = unsignedLong(ph.getLong(offset + 40), "segment memory bytes")
            requireFileRange(entry.size, fileOffset, fileSize, "ELF segment")
            if (kind == 1) {
                if (memorySize < fileSize) measurementFail("ELF PT_LOAD file bytes exceed memory bytes")
                checkedAdd(address, memorySize, "ELF virtual segment")
                val align = unsignedLong(ph.getLong(offset + 48), "segment alignment")
                if (align > 1 && (align and (align - 1) != 0L || fileOffset % align != address % align)) {
                    measurementFail("ELF PT_LOAD has inconsistent alignment")
                }
                loads += ElfLoad(fileOffset, address, fileSize)
                if (loads.size > 256) measurementFail("ELF PT_LOAD count exceeds its ceiling")
            } else if (kind == 2) {
                if (dynamic != null || fileSize !in 16L..65536L || fileSize % 16 != 0L) measurementFail("ELF PT_DYNAMIC is duplicate or unbounded")
                dynamic = ElfLoad(fileOffset, address, fileSize)
            } else if (kind == 3) {
                if (interpreterRange != null || fileSize !in 2L..4096L) measurementFail("ELF PT_INTERP is duplicate or unbounded")
                interpreterRange = fileOffset to fileSize.toInt()
            }
        }
        if (loads.isEmpty()) measurementFail("ELF has no file-backed PT_LOAD")
        val interpreter = interpreterRange?.let { (offset, size) ->
            val bytes = image.readFileRange(path, offset, size, checkpoint)
            val value = elfString(bytes, 0, bytes.size, "PT_INTERP")
            if (value.length + 1 != bytes.size || !value.startsWith('/')) measurementFail("ELF PT_INTERP is not a unique absolute terminated path")
            value
        }
        if (dynamic == null) return ElfMetadata(entry, type, interpreter, emptyList(), null, null, null, 0, emptyList())
        val segment = dynamic
        if (virtualFileOffset(loads, segment.address, segment.fileBytes) != segment.offset) measurementFail("ELF PT_DYNAMIC disagrees with PT_LOAD mapping")
        val table = little(image.readFileRange(path, segment.offset, segment.fileBytes.toInt(), checkpoint))
        val tags = LinkedHashMap<Long, Long>()
        val neededOffsets = ArrayList<Long>()
        val unsupported = ArrayList<String>()
        var terminated = false
        for (offset in 0 until table.capacity() step 16) {
            checkpoint("while decoding bounded ELF dynamic table")
            val tag = table.getLong(offset)
            val value = table.getLong(offset + 8)
            if (tag == 0L) { terminated = true; break }
            if (tag == 1L) {
                neededOffsets += unsignedLong(value, "DT_NEEDED string index")
                if (neededOffsets.size > 256) measurementFail("ELF DT_NEEDED count exceeds 256")
            } else if (tag in listOf(5L, 10L, 14L, 15L, 29L, 0x6ffffffbL)) {
                if (tags.put(tag, unsignedLong(value, "ELF dynamic value")) != null) measurementFail("ELF dynamic singleton tag is duplicated")
            } else if (tag in listOf(0x7fffffffL, 0x7ffffffdL, 0x6ffffefcL, 0x6ffffefbL)) unsupported += "0x${tag.toString(16)}"
        }
        if (!terminated) measurementFail("ELF PT_DYNAMIC lacks a bounded DT_NULL terminator")
        val offsets = (neededOffsets + listOfNotNull(tags[14L], tags[15L], tags[29L])).distinct()
        val strings = HashMap<Long, String>()
        if (offsets.isNotEmpty()) {
            val stringAddress = tags[5L] ?: measurementFail("ELF dynamic strings lack DT_STRTAB")
            val stringBytes = tags[10L] ?: measurementFail("ELF dynamic strings lack DT_STRSZ")
            if (stringBytes == 0L) measurementFail("ELF dynamic string table is empty")
            // Validate the complete declared table mapping, but read only referenced bounded names.
            val base = virtualFileOffset(loads, stringAddress, stringBytes)
            val ranges = offsets.map { offset ->
                if (offset >= stringBytes) measurementFail("ELF dynamic string index lies outside DT_STRSZ")
                LlvmBehaviorNativeOciImageV2.FileRange(checkedAdd(base, offset, "ELF string offset"), minOf(4096L, stringBytes - offset).toInt())
            }
            ranges.chunked(128).forEach { batch ->
                val values = image.readFileRanges(path, batch, checkpoint)
                batch.zip(values).forEach { (range, bytes) -> strings[range.offset - base] = elfString(bytes, 0, bytes.size, "ELF dynamic string") }
            }
        }
        return ElfMetadata(entry, type, interpreter, neededOffsets.map { strings.getValue(it) },
            tags[14L]?.let(strings::getValue), tags[15L]?.let(strings::getValue), tags[29L]?.let(strings::getValue),
            tags[0x6ffffffbL] ?: 0L, unsupported.distinct())
    }

    private fun readLoaderCache(image: LlvmBehaviorNativeOciImageV2.MeasuredImage, checkpoint: (String) -> Unit): LoaderCache {
        val entry = optionalEntry(image, "/etc/ld.so.cache") ?: return LoaderCache(JsonObject(mapOf("present" to JsonPrimitive(false))), emptyList())
        if (entry.kind != "regular" || entry.size !in 48L..4L * 1024 * 1024) measurementFail("ld.so.cache is not a bounded regular cache")
        val bytes = image.readFileRange("/etc/ld.so.cache", 0, entry.size.toInt(), checkpoint)
        val data = little(bytes)
        var base = 0
        var legacy = false
        if (bytes.copyOfRange(0, 11).contentEquals("ld.so-1.7.0".encodeToByteArray())) {
            legacy = true
            val count = uint(data.getInt(12))
            if (count > 16384) measurementFail("legacy ld.so.cache count exceeds its bound")
            val end = checkedAdd(16, count * 12, "legacy ld.so.cache table")
            base = (checkedAdd(end, 7, "ld.so.cache alignment") and -8L).toInt()
        }
        requireFileRange(bytes.size.toLong(), base.toLong(), 48, "glibc ld.so.cache header")
        if (!bytes.copyOfRange(base, base + 20).contentEquals("glibc-ld.so.cache1.1".encodeToByteArray())) measurementFail("ld.so.cache is not supported glibc 1.1")
        val count = uint(data.getInt(base + 20))
        val stringBytes = uint(data.getInt(base + 24))
        if (count > 16384 || stringBytes > 2 * 1024 * 1024) measurementFail("glibc ld.so.cache table exceeds its bound")
        val endian = bytes[base + 28].toInt() and 3
        if (endian !in listOf(0, 2)) measurementFail("ld.so.cache does not have compatible little-endian bytes")
        val stringStart = checkedAdd(base.toLong() + 48, count * 24, "ld.so.cache entries")
        val stringEnd = checkedAdd(stringStart, stringBytes, "ld.so.cache strings")
        requireFileRange(bytes.size.toLong(), stringStart, stringBytes, "ld.so.cache string table")
        var decodedBytes = 0L
        fun cacheString(relative: Long): String {
            val offset = checkedAdd(base.toLong(), relative, "ld.so.cache string index")
            if (offset !in stringStart until stringEnd) measurementFail("ld.so.cache string index is outside its actual table")
            val text = elfString(bytes, offset.toInt(), minOf(stringEnd - offset, 4096).toInt(), "ld.so.cache string")
            decodedBytes += text.length + 1
            if (decodedBytes > 2 * 1024 * 1024) measurementFail("decoded ld.so.cache strings exceed their aggregate ceiling")
            return text
        }
        val entries = ArrayList<LoaderCacheEntry>()
        repeat(count.toInt()) { index ->
            checkpoint("while parsing actual glibc ld.so.cache entries")
            val offset = base + 48 + index * 24
            val name = cacheString(uint(data.getInt(offset + 4)))
            val path = cacheString(uint(data.getInt(offset + 8)))
            if (!path.startsWith('/') || name.contains('/')) measurementFail("ld.so.cache has an invalid library name or path")
            entries += LoaderCacheEntry(name, path, uint(data.getInt(offset)), data.getLong(offset + 16))
        }
        val extensions = ArrayList<JsonObject>()
        var hardwareNames: List<String>? = null
        val extensionOffset = uint(data.getInt(base + 32))
        if (extensionOffset != 0L) {
            if (extensionOffset % 4 != 0L) measurementFail("ld.so.cache extension is misaligned")
            requireFileRange(bytes.size.toLong(), extensionOffset, 8, "ld.so.cache extension header")
            val offset = extensionOffset.toInt()
            if (data.getInt(offset) != -358342284) measurementFail("ld.so.cache extension has invalid magic")
            val extensionCount = uint(data.getInt(offset + 4))
            if (extensionCount > 64) measurementFail("ld.so.cache extension count is unbounded")
            requireFileRange(bytes.size.toLong(), extensionOffset + 8, extensionCount * 16, "ld.so.cache extension descriptors")
            repeat(extensionCount.toInt()) { index ->
                val descriptor = offset + 8 + index * 16
                val tag = uint(data.getInt(descriptor))
                val flags = uint(data.getInt(descriptor + 4))
                val start = uint(data.getInt(descriptor + 8))
                val size = uint(data.getInt(descriptor + 12))
                requireFileRange(bytes.size.toLong(), start, size, "ld.so.cache extension payload")
                val names = if (tag == 1L) {
                    if (start % 4 != 0L || size % 4 != 0L || size > 4096) measurementFail("ld.so.cache hwcaps extension has invalid bounds")
                    (0 until size.toInt() step 4).map { cursor -> cacheString(uint(data.getInt(start.toInt() + cursor))) }
                } else emptyList()
                if (tag == 1L) {
                    if (hardwareNames != null) measurementFail("ld.so.cache duplicates its hwcaps extension")
                    hardwareNames = names
                }
                extensions += JsonObject(linkedMapOf("tag" to JsonPrimitive(tag), "flags" to JsonPrimitive(flags),
                    "bytes" to JsonPrimitive(size), "hwcapNames" to JsonArray(names.map(::JsonPrimitive))))
            }
        }
        return LoaderCache(JsonObject(linkedMapOf("present" to JsonPrimitive(true), "path" to JsonPrimitive(entry.path),
            "inode" to JsonPrimitive(entry.inode), "bytes" to JsonPrimitive(entry.size), "sha256" to JsonPrimitive(entry.contentSha256),
            "format" to JsonPrimitive("glibc-ld.so.cache-1.1"), "legacyCompatibilityPrefix" to JsonPrimitive(legacy),
            "entries" to JsonPrimitive(count), "extensions" to JsonArray(extensions))), entries.map { cached ->
                if ((cached.hwcap ushr 32) and 0x3ffL.inv() == (1L shl 30)) {
                    val names = hardwareNames ?: measurementFail("ld.so.cache hwcap entry lacks its actual extension")
                    val index = cached.hwcap and 0xffffffffL
                    if (index >= names.size) measurementFail("ld.so.cache hwcap name index is outside its extension")
                    cached.copy(hwcapName = names[index.toInt()])
                } else cached
            })
    }

    private fun little(bytes: ByteArray): ByteBuffer = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN)
    private fun uint(value: Int): Long = value.toLong() and 0xffffffffL
    private fun unsignedLong(value: Long, label: String): Long = value.takeIf { it >= 0 } ?: measurementFail("$label exceeds the supported signed file-offset range")
    private fun checkedAdd(left: Long, right: Long, label: String): Long =
        if (left < 0 || right < 0 || left > Long.MAX_VALUE - right) measurementFail("$label arithmetic overflows") else left + right
    private fun requireFileRange(fileBytes: Long, offset: Long, length: Long, label: String) {
        if (checkedAdd(offset, length, label) > fileBytes) measurementFail("$label extends outside the retained file")
    }
    private fun virtualFileOffset(loads: List<ElfLoad>, address: Long, length: Long): Long {
        val end = checkedAdd(address, length, "ELF virtual-file mapping")
        val mapped = loads.filter { address >= it.address && end <= checkedAdd(it.address, it.fileBytes, "ELF PT_LOAD file mapping") }
            .map { checkedAdd(it.offset, address - it.address, "ELF mapped file offset") }.distinct()
        if (mapped.size != 1) measurementFail("ELF virtual range has no unique file-backed PT_LOAD mapping")
        return mapped.single()
    }
    private fun elfString(bytes: ByteArray, offset: Int, limit: Int, label: String): String {
        if (offset < 0 || limit !in 1..4096 || offset > bytes.size - limit) measurementFail("$label has invalid string bounds")
        val end = (offset until offset + limit).firstOrNull { bytes[it] == 0.toByte() } ?: measurementFail("$label is not terminated within its 4096-byte ceiling")
        if (end == offset || (offset until end).any { (bytes[it].toInt() and 255) !in 0x20..0x7e }) measurementFail("$label has an empty or unsupported byte string")
        return String(bytes, offset, end - offset, Charsets.US_ASCII)
    }

    private fun requireOwnMeasurementClasses(deploymentPath: Path, checkpoint: (String) -> Unit) {
        val classes = listOf(LlvmBehaviorNativeRuntimeMeasurementV2::class.java,
            LlvmBehaviorNativeOciImageV2::class.java, PinnedDockerRuntimeBindings::class.java)
        classes.forEach { type ->
            val location = type.protectionDomain?.codeSource?.location
                ?: measurementFail("measurement dependency lacks its own deployment origin")
            if (Path.of(location.toURI()).toAbsolutePath().normalize() != deploymentPath) {
                measurementFail("measurement dependency is shadowed outside the own application JAR")
            }
        }
        val required = classes.map { it.name.replace('.', '/') + ".class" }.toSet()
        val seen = HashSet<String>()
        val ownedClasses = ArrayList<String>()
        val referencedClasses = HashSet<String>()
        var namesBytes = 0L
        var classBytes = 0L
        JarFile(deploymentPath.toFile(), false).use { jar ->
            val entries = jar.entries()
            while (entries.hasMoreElements()) {
                checkpoint("while checking native measurement deployment entries")
                val entry = entries.nextElement()
                val size = entry.name.encodeToByteArray().size
                namesBytes = Math.addExact(namesBytes, size.toLong())
                if (seen.size >= 100_000 || size > 4096 || namesBytes > 32L * 1024 * 1024 || !seen.add(entry.name)) {
                    measurementFail("measurement application JAR contains duplicate or unbounded entries")
                }
                if (entry.name in required && (entry.isDirectory || entry.size !in 1L..1024 * 1024)) {
                    measurementFail("measurement application class entry has invalid bounds")
                }
                if (entry.name.startsWith("decompengine/") && entry.name.endsWith(".class")) {
                    if (entry.isDirectory || entry.size !in 1L..4 * 1024 * 1024 || ownedClasses.size >= 25_000) {
                        measurementFail("measurement application's complete class closure exceeds its bounds")
                    }
                    ownedClasses += entry.name.removeSuffix(".class").replace('/', '.')
                    classBytes = Math.addExact(classBytes, entry.size)
                    if (classBytes > 256L * 1024 * 1024) measurementFail("measurement application class bytes exceed their ceiling")
                    val bytes = jar.getInputStream(entry).use { it.readNBytes(entry.size.toInt() + 1) }
                    if (bytes.size.toLong() != entry.size) measurementFail("measurement class ZIP length is inconsistent")
                    referencedClasses += applicationClassReferences(bytes)
                }
            }
        }
        if (!seen.containsAll(required)) measurementFail("measurement classes are absent from their own application JAR")
        if (referencedClasses.any { it.replace('.', '/') + ".class" !in seen }) {
            measurementFail("measurement application's class closure falls back outside its own JAR")
        }
        // Include generated companions, private HTTP/endpoint/ELF owners, lambdas and the shared
        // descriptor/JSON/deadline implementation. Selecting only outer classes permits a separately
        // shadowed operational helper to manufacture accepted facts while its outer origin matches.
        ownedClasses.forEach { name ->
            checkpoint("while authenticating native measurement complete class origins")
            val selected = Class.forName(name, false, LlvmBehaviorNativeRuntimeMeasurementV2::class.java.classLoader)
            val origin = selected.protectionDomain?.codeSource?.location
                ?: measurementFail("measurement class $name lacks its deployment origin")
            if (Path.of(origin.toURI()).toAbsolutePath().normalize() != deploymentPath) {
                measurementFail("measurement operational class $name is shadowed outside the own application JAR")
            }
        }
    }

    /** Only JVM CONSTANT_Class references are authority here; arbitrary UTF-8 strings are not names. */
    private fun applicationClassReferences(
        bytes: ByteArray,
        prefixes: List<String> = listOf("decompengine/"),
    ): Set<String> {
        val names = ArrayList<Int>()
        val descriptors = ArrayList<Int>()
        val selected = HashSet<String>()
        DataInputStream(ByteArrayInputStream(bytes)).use { input ->
            if (input.readInt() != 0xcafebabe.toInt()) measurementFail("measurement application class magic is malformed")
            input.readUnsignedShort()
            val major = input.readUnsignedShort()
            if (major !in 45..65) measurementFail("measurement application class version exceeds Java21")
            val count = input.readUnsignedShort()
            if (count < 1) measurementFail("measurement application class has an empty constant pool")
            val strings = arrayOfNulls<String>(count)
            var index = 1
            while (index < count) {
                when (input.readUnsignedByte()) {
                    1 -> strings[index] = input.readUTF()
                    3, 4 -> input.readInt()
                    5, 6 -> { input.readLong(); index++ }
                    7 -> names += input.readUnsignedShort()
                    8, 19, 20 -> input.readUnsignedShort()
                    16 -> descriptors += input.readUnsignedShort()
                    12 -> { input.readUnsignedShort(); descriptors += input.readUnsignedShort() }
                    9, 10, 11, 17, 18 -> input.readInt()
                    15 -> { input.readUnsignedByte(); input.readUnsignedShort() }
                    else -> measurementFail("measurement application constant-pool tag is unsupported")
                }
                index++
            }
            input.readUnsignedShort() // access flags
            input.readUnsignedShort() // this class
            input.readUnsignedShort() // superclass
            repeat(input.readUnsignedShort()) { input.readUnsignedShort() }
            repeat(2) { // fields, then methods: descriptor indices have explicit JVM provenance.
                repeat(input.readUnsignedShort()) {
                    input.readUnsignedShort()
                    input.readUnsignedShort()
                    descriptors += input.readUnsignedShort()
                    repeat(input.readUnsignedShort()) {
                        input.readUnsignedShort()
                        val length = input.readInt()
                        if (length < 0 || length > input.available()) measurementFail("measurement class attribute is unbounded")
                        input.skipNBytes(length.toLong())
                    }
                }
            }
            names.forEach { reference ->
                val raw = strings.getOrNull(reference) ?: measurementFail("measurement class name reference is invalid")
                val name = if (raw.startsWith('[')) {
                    val element = raw.dropWhile { it == '[' }
                    if (element.startsWith('L') && element.endsWith(';')) element.substring(1, element.length - 1) else ""
                } else raw
                if (prefixes.any(name::startsWith)) selected += name.replace('/', '.')
            }
            descriptors.forEach { reference ->
                val descriptor = strings.getOrNull(reference) ?: measurementFail("measurement descriptor reference is invalid")
                var cursor = 0
                while (cursor < descriptor.length) {
                    if (descriptor[cursor] == 'L') {
                        val end = descriptor.indexOf(';', cursor + 1)
                        if (end < 0) measurementFail("measurement class descriptor is unterminated")
                        val name = descriptor.substring(cursor + 1, end)
                        if (prefixes.any(name::startsWith)) selected += name.replace('/', '.')
                        cursor = end + 1
                    } else cursor++
                }
            }
        }
        return selected
    }

    private fun ownRecipeBinding(
        deployment: Path,
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        checkpoint: (String) -> Unit,
    ): JsonObject {
        val resource = "oracle/llvm/22.1.6/native-runtime-measurement-v2.Dockerfile"
        val bytes = JarFile(deployment.toFile(), false).use { jar ->
            val entries = jar.entries().asSequence().filter { it.name == resource }.toList()
            if (entries.size != 1 || entries.single().isDirectory || entries.single().size !in 1L..64 * 1024) {
                measurementFail("own measurement recipe is absent, duplicated or unbounded")
            }
            jar.getInputStream(entries.single()).use { it.readNBytes(entries.single().size.toInt() + 1) }.also {
                if (it.size.toLong() != entries.single().size) measurementFail("own measurement recipe ZIP length differs")
            }
        }
        checkpoint("after reading own deployment recipe")
        val sha = OracleArtifacts.sha256(bytes)
        val actual = image.resolve("/decomp-native-build/native-runtime-measurement-v2.Dockerfile")
        if (actual.kind != "regular" || actual.size != bytes.size.toLong() || actual.contentSha256 != sha) {
            measurementFail("actual raw image recipe bytes differ from the own deployment recipe")
        }
        return JsonObject(linkedMapOf(
            "ownJarResource" to JsonPrimitive(resource), "containerPath" to JsonPrimitive(actual.path),
            "bytes" to JsonPrimitive(actual.size), "sha256" to JsonPrimitive(sha),
            "rawImageBytesMatchDeployment" to JsonPrimitive(true),
            "buildExecutionAuthenticated" to JsonPrimitive(false),
            "runtimeProfileApproved" to JsonPrimitive(false),
        ))
    }

    /** Fixed pure Java codec deployment, including helper classes selected by bytecode references. */
    private class PinnedMeasurementCodecs private constructor(
        private val guards: List<StableControlFile>,
        val facts: JsonArray,
    ) : AutoCloseable {
        fun requireCurrent(checkpoint: (String) -> Unit) {
            guards.forEach { guard ->
                guard.verifyUnchanged("native measurement codec terminal binding")
                if (guard.sha256(checkpoint, "native measurement codec terminal bytes") != guard.authenticatedSha256) {
                    measurementFail("native measurement codec bytes changed")
                }
            }
        }
        override fun close() {
            var failure: Throwable? = null
            guards.asReversed().forEach { guard ->
                try { guard.close() } catch (caught: Throwable) {
                    if (failure == null) failure = caught else failure!!.addSuppressed(caught)
                }
            }
            failure?.let { throw it }
        }

        companion object {
            private data class Pin(val filename: String, val bytes: Long, val sha256: String)
            private val pins = listOf(
                Pin("aircompressor-2.0.3.jar", 255_256L, "b86bb66f610079e0bf790d62e2ff68853eb0dc4748a6d68ae28bce92b68094aa"),
                Pin("commons-compress-1.28.0.jar", 1_117_221L, "e1522945218456f3649a39bc4afd70ce4bd466221519dba7d378f2141a4642ca"),
                Pin("commons-io-2.20.0.jar", 563_971L, "df90bba0fe3cb586b7f164e78fe8f8f4da3f2dd5c27fa645f888100ccc25dd72"),
                Pin("commons-lang3-3.18.0.jar", 702_952L, "4eeeae8d20c078abb64b015ec158add383ac581571cddc45c68f0c9ae0230720"),
            )

            fun open(directory: Path, checkpoint: (String) -> Unit): PinnedMeasurementCodecs {
                val guards = ArrayList<StableControlFile>()
                try {
                    val classes = HashMap<String, Pair<Path, ByteArray>>()
                    val variantReferences = HashMap<String, MutableSet<String>>()
                    val prefixes = listOf("io/airlift/", "org/apache/commons/")
                    var aggregateClassBytes = 0L
                    pins.forEach { pin ->
                        val path = directory.resolve(pin.filename)
                        val guard = StableControlFile.openWithCheckpoint(path, pin.bytes, "native codec ${pin.filename}", checkpoint)
                        guards += guard
                        if (guard.size != pin.bytes || guard.authenticatedSha256 != pin.sha256) {
                            measurementFail("native codec differs from its fixed official artifact bytes")
                        }
                        JarFile(path.toFile(), false).use { jar ->
                            val seen = HashSet<String>()
                            var nameBytes = 0L
                            jar.entries().asSequence().forEach entries@{ entry ->
                                checkpoint("while checking native codec deployment entries")
                                nameBytes += entry.name.encodeToByteArray().size
                                if (seen.size >= 10_000 || entry.name.length > 4096 || nameBytes > 8L * 1024 * 1024 || !seen.add(entry.name)) {
                                    measurementFail("native codec JAR has duplicate or unbounded entries")
                                }
                                var logical = entry.name
                                if (logical.startsWith("META-INF/versions/")) {
                                    val parts = logical.split('/', limit = 4)
                                    val version = parts.getOrNull(2)?.toIntOrNull() ?: measurementFail("malformed multi-release codec entry")
                                    if (version > Runtime.version().feature()) return@entries
                                    logical = parts.getOrNull(3) ?: measurementFail("malformed multi-release codec class")
                                }
                                if (!logical.endsWith(".class") || prefixes.none(logical::startsWith)) return@entries
                                if (entry.isDirectory || entry.size !in 1L..4 * 1024 * 1024 || classes.size >= 10_000) {
                                    measurementFail("native codec class entry is unbounded")
                                }
                                aggregateClassBytes = Math.addExact(aggregateClassBytes, entry.size)
                                if (aggregateClassBytes > 32L * 1024 * 1024) measurementFail("native codec class closure bytes exceed their bound")
                                val bytes = jar.getInputStream(entry).use { it.readNBytes(entry.size.toInt() + 1) }
                                if (bytes.size.toLong() != entry.size) measurementFail("native codec class ZIP length differs")
                                val name = logical.removeSuffix(".class").replace('/', '.')
                                val previous = classes[name]
                                if (previous != null && previous.first != path) measurementFail("native codec classes are duplicated across fixed dependencies")
                                // Retain all active variant references, not merely an outer class origin.
                                if (previous == null) classes[name] = path to bytes
                                else {
                                    val extra = applicationClassReferences(bytes, prefixes)
                                    extra.forEach { reference ->
                                        // Variant-only dependencies are enqueued below through a synthetic
                                        // reference set; their actual selected class remains origin checked.
                                        variantReferences.getOrPut(name) { HashSet() }.add(reference)
                                    }
                                }
                            }
                        }
                        guard.verifyUnchanged("native codec class-inventory binding")
                    }
                    val queue = ArrayDeque(listOf("io.airlift.compress.zstd.ZstdInputStream",
                        "org.apache.commons.compress.compressors.gzip.GzipCompressorInputStream"))
                    val selected = HashSet<String>()
                    while (queue.isNotEmpty()) {
                        checkpoint("while authenticating native codec invoked class closure")
                        val name = queue.removeFirst()
                        if (!selected.add(name)) continue
                        if (selected.size > 10_000) measurementFail("native codec invoked closure has too many classes")
                        val (expectedPath, bytes) = classes[name] ?: measurementFail("native codec helper is absent from the fixed deployment")
                        val type = Class.forName(name, false, LlvmBehaviorNativeRuntimeMeasurementV2::class.java.classLoader)
                        val origin = type.protectionDomain?.codeSource?.location ?: measurementFail("native codec helper lacks origin")
                        if (Path.of(origin.toURI()).toAbsolutePath().normalize() != expectedPath) {
                            measurementFail("native codec helper is shadowed outside its fixed deployment")
                        }
                        queue.addAll(applicationClassReferences(bytes, prefixes))
                        queue.addAll(variantReferences[name].orEmpty())
                    }
                    return PinnedMeasurementCodecs(guards, JsonArray(pins.map { pin -> JsonObject(linkedMapOf(
                        "filename" to JsonPrimitive(pin.filename), "bytes" to JsonPrimitive(pin.bytes),
                        "sha256" to JsonPrimitive(pin.sha256), "nativeFallbackAllowed" to JsonPrimitive(false),
                        "selectedCodecClassesOriginVerified" to JsonPrimitive(true),
                    )) })).also { it.requireCurrent(checkpoint) }
                } catch (failure: Throwable) {
                    guards.asReversed().forEach { runCatching { it.close() } }
                    throw failure
                }
            }
        }
    }
}

/** Strict JSON facts only, never an operational transport or caller accepted authority. */
internal fun nativeMeasurementObject(bytes: ByteArray, label: String, checkpoint: (String) -> Unit): JsonObject =
    OracleJson.parse(bytes, NATIVE_MEASUREMENT_JSON_LIMITS, checkpoint) as? JsonObject
        ?: measurementFail("$label must be a JSON object")

internal fun JsonObject.nativeMeasurementString(key: String, maximumBytes: Int = 4096): String {
    val primitive = get(key) as? JsonPrimitive ?: measurementFail("measurement $key is absent or not a string")
    if (!primitive.isString) measurementFail("measurement $key is not a string")
    val value = primitive.content
    if (value.isEmpty() || value.encodeToByteArray().size > maximumBytes || value.any { it.code < 0x20 }) {
        measurementFail("measurement $key is outside its string bound")
    }
    return value
}

internal fun nativeMeasurementJsonHash(value: JsonElement, checkpoint: (String) -> Unit): String =
    OracleArtifacts.sha256(OracleJson.canonicalBytes(value, NATIVE_MEASUREMENT_JSON_LIMITS, checkpoint))

internal fun measurementFail(message: String, cause: Throwable? = null): Nothing =
    throw LlvmBehaviorNativeRuntimeMeasurementV2Exception(message, cause)

internal val NATIVE_MEASUREMENT_JSON_LIMITS = StrictJsonLimits(
    maximumInputBytes = 4 * 1024 * 1024,
    maximumCanonicalBytes = 4 * 1024 * 1024,
    maximumDepth = 64,
    maximumNodes = 100_000,
    maximumStringBytes = 256 * 1024,
    maximumTotalStringBytes = 2 * 1024 * 1024,
)
