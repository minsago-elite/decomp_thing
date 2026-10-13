package decompengine.oracle.behavior

import decompengine.analysis.AnalysisDeadline
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import java.io.ByteArrayOutputStream
import java.io.FilterInputStream
import java.io.InputStream
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.apache.commons.compress.archivers.tar.TarArchiveInputStream
import org.tukaani.xz.XZInputStream

/**
 * Explicit manual Actions probe. This test-only main is not shipped or automatically executed in
 * ordinary CI. Its classpath selects the installed application JAR before test-only probe classes.
 */
object LlvmBehaviorNativeRuntimeMeasurementV2LiveMain {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 7) {
            "expected raw OCI directory, fixed client, empty config, private socket, authenticated source archive, detached signature, fresh output"
        }
        val selected = arguments.map { Path.of(it).toAbsolutePath().normalize() }
        val deadline = AnalysisDeadline.start(TimeUnit.MINUTES.toNanos(20), "manual native resource byte proof")
        val checkpoint: (String) -> Unit = deadline::checkpoint
        val deploymentPath = Path.of(LlvmBehaviorNativeRuntimeMeasurementV2::class.java.protectionDomain
            .codeSource.location.toURI()).toAbsolutePath().normalize()
        check(deploymentPath.fileName.toString().endsWith(".jar")) {
            "manual measurement must use the production factory from its installed application JAR"
        }
        StableControlFile.openWithCheckpoint(deploymentPath, 512L * 1024 * 1024,
            "manual measurement installed application", checkpoint).use { deployment ->
            StableControlFile.openWithCheckpoint(selected[4], SOURCE_ARCHIVE_BYTES,
                "locked LLVM source archive", checkpoint).use { source ->
                StableControlFile.openWithCheckpoint(selected[5], SOURCE_SIGNATURE_BYTES,
                    "locked LLVM detached signature", checkpoint).use { signature ->
                    check(source.size == SOURCE_ARCHIVE_BYTES && source.authenticatedSha256 == SOURCE_ARCHIVE_SHA256) {
                        "selected source archive differs from the independently authenticated repository source lock"
                    }
                    check(signature.size == SOURCE_SIGNATURE_BYTES && signature.authenticatedSha256 == SOURCE_SIGNATURE_SHA256) {
                        "selected detached signature differs from the independently authenticated repository source lock"
                    }
                    source.requireSingleLink("before signed source archive use")
                    signature.requireSingleLink("before detached signature use")
                    val recipe = installedRecipe(deploymentPath, checkpoint)
                    deployment.verifyUnchanged("installed recipe selection")
                    val measuredFiles = LlvmBehaviorNativeOciImageV2.openLayout(selected[0], checkpoint).use { image ->
                        measureReferenceBytes(image, source, signature, recipe, checkpoint)
                    }
                    source.verifyUnchanged("signed source archive resource proof")
                    signature.verifyUnchanged("detached signature resource proof")
                    val candidate = LlvmBehaviorNativeRuntimeMeasurementV2.measure(selected[0], selected[1], selected[2], selected[3])
                    val bytes = candidate.canonicalBytes()
                    val value = OracleJson.parseCanonical(bytes, NATIVE_MEASUREMENT_JSON_LIMITS, checkpoint) as JsonObject
                    check(value["runtimeProfileApproved"] == JsonPrimitive(false) && value["startAuthorized"] == JsonPrimitive(false))
                    check(value["mergedNamespaceSha256"] == measuredFiles["mergedNamespaceSha256"]) {
                        "raw image changed between independent signed-source byte proof and production runtime measurement"
                    }
                    source.verifyUnchanged("signed source archive final boundary")
                    signature.verifyUnchanged("detached signature final boundary")
                    deployment.verifyUnchanged("manual installed factory final boundary")
                    val referenceFacts = OracleJson.canonicalBytes(measuredFiles, NATIVE_MEASUREMENT_JSON_LIMITS, checkpoint)
                    checkpoint("before publishing manual measurement candidates")
                    Files.createDirectories(selected[6].parent)
                    Files.write(selected[6].resolveSibling("locked-reference-byte-measurement.json"), referenceFacts,
                        StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
                    Files.write(selected[6], bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
                    println("Actual installed raw OCI/Docker export measurement candidate SHA-256=${candidate.sha256}; signed-source resource proof SHA-256=${OracleArtifacts.sha256(referenceFacts)}")
                    println("runtimeProfileApproved=false startAuthorized=false containmentProved=false scoringAuthority=false releaseEligible=false")
                }
            }
        }
    }

    private fun measureReferenceBytes(
        image: LlvmBehaviorNativeOciImageV2.MeasuredImage,
        source: StableControlFile,
        signature: StableControlFile,
        recipe: ByteArray,
        checkpoint: (String) -> Unit,
    ): JsonObject {
        val clang = image.resolve("/subject/executable")
        check(clang.kind == "regular" && clang.size == 84_561_368L &&
            clang.contentSha256 == "65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006" &&
            clang.modeKnown && clang.mode and 0x49L != 0L) {
            "raw image does not contain the independently locked Clang22.1.6 executable"
        }
        val rawRecipe = image.readFile(IMAGE_RECIPE_PATH, MAXIMUM_RECIPE_BYTES, checkpoint)
        check(rawRecipe.contentEquals(recipe)) { "raw image recipe differs from the production factory's own installed recipe" }
        val licenseFacts = SOURCE_LICENSES.map { license ->
            val entry = image.resolve(license.imagePath)
            check(entry.kind == "regular" && entry.size == license.bytes && entry.contentSha256 == license.sha256) {
                "raw image lacks the exact source-locked LLVM/Clang license bytes"
            }
            JsonObject(linkedMapOf("imagePath" to JsonPrimitive(entry.path), "sourceArchivePath" to JsonPrimitive(license.sourcePath),
                "bytes" to JsonPrimitive(entry.size), "sha256" to JsonPrimitive(entry.contentSha256)))
        }
        val includeRoot = image.resolve("/lib/clang/22/include")
        check(includeRoot.kind == "directory") { "fixed subject's default resource include directory is absent" }
        val resourcePrefix = includeRoot.path + "/"
        val members = image.namespace.values.filter { it.path.startsWith(resourcePrefix) }.sortedBy { it.path }
        check(members.isNotEmpty() && members.size <= MAXIMUM_RESOURCE_MEMBERS) { "resource directory member bound is exceeded" }
        check(members.all { it.kind == "directory" || it.kind == "regular" }) {
            "resource directory contains a link or special node whose source bytes have not been proved"
        }
        val resources = members.filter { it.kind == "regular" }.associate { entry ->
            val relative = entry.path.removePrefix(resourcePrefix)
            check(relative !in GENERATED_RESOURCE_NAMES) { "X86-only resource installation contains an unproved generated header" }
            check(entry.size in 0L..MAXIMUM_RESOURCE_BYTES && entry.contentSha256 != null) {
                "resource header lacks bounded regular-file bytes"
            }
            relative to ResourceBytes(entry.size, requireNotNull(entry.contentSha256))
        }.toSortedMap()
        check(resources.keys.containsAll(listOf("stddef.h", "stdarg.h", "limits.h", "module.modulemap"))) {
            "resource installation lacks required core headers"
        }
        val resourceBytes = resources.values.fold(0L) { total, member -> Math.addExact(total, member.bytes) }
        check(resourceBytes <= MAXIMUM_RESOURCE_BYTES) { "resource directory aggregate bytes exceed their bound" }
        val sourceProof = proveStaticResourceBytes(source.slice(), resources, checkpoint)
        image.requireCurrent(checkpoint)
        return JsonObject(linkedMapOf(
            "artifactKind" to JsonPrimitive("locked-reference-byte-measurement"),
            "authority" to JsonPrimitive("unapproved-signed-source-byte-comparison-only"),
            "clangPath" to JsonPrimitive(clang.path), "clangBytes" to JsonPrimitive(clang.size),
            "clangSha256" to JsonPrimitive(clang.contentSha256),
            "sourceArchiveBytes" to JsonPrimitive(source.size), "sourceArchiveSha256" to JsonPrimitive(source.authenticatedSha256),
            "sourceSignatureBytes" to JsonPrimitive(signature.size), "sourceSignatureSha256" to JsonPrimitive(signature.authenticatedSha256),
            "sourceRevision" to JsonPrimitive("fc4aad7b5db3fff421df9a9637605b9ca5667881"),
            "signatureAuthentication" to JsonPrimitive("fetchLlvmSourceArchive prerequisite; exact independently locked archive and signature bytes reauthenticated here"),
            "resourceIncludeRequestedPath" to JsonPrimitive("/lib/clang/22/include"),
            "resourceIncludeResolvedPath" to JsonPrimitive(includeRoot.path),
            "resourceRole" to JsonPrimitive("CMake-installed static copies from signed clang/lib/Headers source members"),
            "sourceLicenses" to JsonArray(licenseFacts),
            "resourceTarget" to JsonPrimitive("clang-resource-headers"), "llvmTargetsToBuild" to JsonArray(listOf(JsonPrimitive("X86"))),
            "generatedHeadersPresent" to JsonPrimitive(false),
            "resourceRegularFileCount" to JsonPrimitive(resources.size), "resourceBytes" to JsonPrimitive(resourceBytes),
            "resourceMembers" to JsonArray(resources.map { (relative, member) -> JsonObject(linkedMapOf(
                "relativePath" to JsonPrimitive(relative), "imagePath" to JsonPrimitive(resourcePrefix + relative),
                "sourceArchivePath" to JsonPrimitive(SOURCE_HEADER_PREFIX + relative),
                "role" to JsonPrimitive("static-copy"), "bytes" to JsonPrimitive(member.bytes), "sha256" to JsonPrimitive(member.sha256),
            )) }),
            "resourceCmakeArchivePath" to JsonPrimitive(SOURCE_CMAKE_PATH),
            "resourceCmakeBytes" to JsonPrimitive(sourceProof.cmake.bytes), "resourceCmakeSha256" to JsonPrimitive(sourceProof.cmake.sha256),
            "sourceArchiveMemberCount" to JsonPrimitive(sourceProof.members), "sourceArchiveExpandedBytes" to JsonPrimitive(sourceProof.expandedBytes),
            "imageRecipePath" to JsonPrimitive(IMAGE_RECIPE_PATH), "installedRecipeEntry" to JsonPrimitive(INSTALLED_RECIPE_ENTRY),
            "recipeBytes" to JsonPrimitive(recipe.size), "recipeSha256" to JsonPrimitive(OracleArtifacts.sha256(recipe)),
            "mergedNamespaceSha256" to JsonPrimitive(image.namespaceSha256),
            "oracleAuthority" to JsonPrimitive(false), "runtimeProfileApproved" to JsonPrimitive(false),
            "startAuthorized" to JsonPrimitive(false), "containmentProved" to JsonPrimitive(false),
            "scoringAuthority" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ))
    }

    /** Only called after the complete compressed file has been authenticated to the repository lock. */
    private fun proveStaticResourceBytes(
        compressed: InputStream,
        resources: Map<String, ResourceBytes>,
        checkpoint: (String) -> Unit,
    ): SourceProof {
        val seen = HashSet<String>()
        val nodeKinds = HashMap<String, String>()
        val matched = HashSet<String>()
        val expectedSourcePaths = resources.mapKeys { SOURCE_HEADER_PREFIX + it.key } +
            SOURCE_LICENSES.associate { it.sourcePath to ResourceBytes(it.bytes, it.sha256) }
        var memberCount = 0
        var metadataBytes = 0L
        var cmake: ResourceBytes? = null
        var cmakeSource: ByteArray? = null
        val expanded = ExpandedSourceInput(XZInputStream(compressed, 256 * 1024), checkpoint)
        TarArchiveInputStream(expanded, "UTF-8").use { tar ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                checkpoint("before signed source archive member")
                val entry = tar.nextEntry ?: break
                memberCount++
                check(memberCount <= 200_000) { "signed source archive member bound is exceeded" }
                check(entry.isCheckSumOK && tar.canReadEntryData(entry) && !entry.isSparse) {
                    "signed source archive member cannot be safely streamed"
                }
                val path = canonicalArchivePath(entry.name, entry.isDirectory)
                check(seen.add(path)) { "signed source archive contains duplicate member paths" }
                metadataBytes = Math.addExact(metadataBytes, path.toByteArray(Charsets.UTF_8).size.toLong())
                metadataBytes = Math.addExact(metadataBytes, entry.linkName.toByteArray(Charsets.UTF_8).size.toLong())
                check(metadataBytes <= 64L * 1024 * 1024 && entry.linkName.toByteArray(Charsets.UTF_8).size <= 4096) {
                    "signed source archive path or link metadata exceeds its bound"
                }
                check(entry.size in 0L..512L * 1024 * 1024) { "signed source archive member exceeds its payload bound" }
                nodeKinds[path] = when {
                    entry.isDirectory -> "directory"
                    entry.isFile && !entry.isLink && !entry.isSymbolicLink -> "regular"
                    else -> "unused-nonregular"
                }
                val relative = path.removePrefix(SOURCE_HEADER_PREFIX)
                val expected = expectedSourcePaths[path]
                val selectedCmake = path == SOURCE_CMAKE_PATH
                check(expected == null && !selectedCmake || nodeKinds[path] == "regular") {
                    "selected signed-source resource or CMake member is not a regular file"
                }
                if (selectedCmake) check(entry.size in 1L..MAXIMUM_RECIPE_BYTES.toLong()) {
                    "signed resource CMake file exceeds its bound"
                }
                if (expected != null) check(entry.size == expected.bytes) { "resource size differs from its signed-source member: $relative" }
                val digest = if (expected != null || selectedCmake) MessageDigest.getInstance("SHA-256") else null
                val cmakeOutput = if (selectedCmake) ByteArrayOutputStream() else null
                var bytes = 0L
                while (true) {
                    val count = tar.read(buffer)
                    if (count < 0) break
                    check(count > 0) { "signed source archive stream made no progress" }
                    bytes = Math.addExact(bytes, count.toLong())
                    check(bytes <= entry.size) { "signed source archive payload exceeds its declared size" }
                    digest?.update(buffer, 0, count)
                    cmakeOutput?.write(buffer, 0, count)
                    checkpoint("while comparing signed source resource bytes")
                }
                check(bytes == entry.size) { "signed source archive member is truncated" }
                if (digest != null) {
                    val sha256 = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
                    if (expected != null) {
                        check(sha256 == expected.sha256) { "resource bytes differ from their signed-source member: $relative" }
                        matched.add(path)
                    }
                    if (selectedCmake) {
                        cmake = ResourceBytes(bytes, sha256)
                        cmakeSource = requireNotNull(cmakeOutput).toByteArray()
                    }
                }
            }
            // Consume the XZ trailer/checksum and all remaining tar padding without retaining it.
            while (true) {
                val count = expanded.read(buffer)
                if (count < 0) break
                check(count > 0 && (0 until count).all { buffer[it] == 0.toByte() }) {
                    "signed source archive contains bytes after its tar terminator"
                }
                checkpoint("after signed archive tar terminator")
            }
        }
        check(matched == expectedSourcePaths.keys) { "resource installation or licenses contain members absent from the signed source archive" }
        check(staticCmakeResourcePaths(requireNotNull(cmakeSource)) == resources.keys) {
            "resource installation is incomplete or differs from the signed clang-resource-headers component"
        }
        (expectedSourcePaths.keys + SOURCE_CMAKE_PATH).forEach { selected ->
            var parent = selected.substringBeforeLast('/')
            while (true) {
                check(nodeKinds[parent] == "directory") { "selected source member has a missing or non-directory archive parent" }
                if (parent == SOURCE_ARCHIVE_ROOT) break
                parent = parent.substringBeforeLast('/')
            }
        }
        return SourceProof(memberCount, expanded.bytes, requireNotNull(cmake) { "signed source archive lacks resource CMake metadata" })
    }

    /** Parse only the fixed release's simple static lists, never evaluate or execute CMake. */
    private fun staticCmakeResourcePaths(bytes: ByteArray): Set<String> {
        check(bytes.all { it.toInt() and 0xff < 128 }) { "resource CMake static-list profile is not ASCII" }
        val text = bytes.toString(Charsets.US_ASCII)
        val prefix = text.substringBefore("include(GetClangResourceDir)")
        check(prefix.length < text.length) { "resource CMake static-list profile is absent" }
        val uncommented = prefix.lines().joinToString("\n") { it.substringBefore('#') }
        val lists = LinkedHashMap<String, List<String>>()
        Regex("(?ms)^set\\(([a-z0-9_]+)\\s+(.*?)\\)").findAll(uncommented).forEach { match ->
            val name = match.groupValues[1]
            check(name !in lists) { "resource CMake static list is duplicated" }
            val values = match.groupValues[2].trim().split(Regex("\\s+")).filter { it.isNotEmpty() }.flatMap { token ->
                val variable = Regex("\\$\\{([a-z0-9_]+)\\}").matchEntire(token)
                if (variable != null) requireNotNull(lists[variable.groupValues[1]]) { "resource CMake list has an unknown dependency" }
                else {
                    check(token.matches(Regex("[A-Za-z0-9_+./-]+")) && token.split('/').all { it.isNotEmpty() && it != "." && it != ".." }) {
                        "resource CMake list has an unsupported static path"
                    }
                    listOf(token)
                }
            }
            lists[name] = values
        }
        val installedLists = listOf("files", "cuda_wrapper_files", "cuda_wrapper_bits_files", "cuda_wrapper_utility_files",
            "ppc_wrapper_files", "llvm_libc_wrapper_files", "openmp_wrapper_files", "llvm_offload_wrapper_files", "zos_wrapper_files")
        val installed = installedLists.flatMap { requireNotNull(lists[it]) { "resource CMake installation list is absent" } }
        check(installed.isNotEmpty() && installed.size <= MAXIMUM_RESOURCE_MEMBERS && installed.toSet().size == installed.size) {
            "resource CMake installation list is duplicated or unbounded"
        }
        return installed.toSet()
    }

    private fun canonicalArchivePath(raw: String, directory: Boolean): String {
        val path = if (directory) raw.removeSuffix("/") else raw
        check(path == SOURCE_ARCHIVE_ROOT || path.startsWith("$SOURCE_ARCHIVE_ROOT/")) { "source member is outside the locked archive root" }
        check(path.toByteArray(Charsets.UTF_8).size <= 4096 && path.none { it.code < 32 || it.code == 127 }) {
            "source archive member path exceeds its text bound"
        }
        check(path.split('/').all { it.isNotEmpty() && it != "." && it != ".." && it.toByteArray(Charsets.UTF_8).size <= 255 }) {
            "source archive member path is not canonical"
        }
        return path
    }

    private fun installedRecipe(deployment: Path, checkpoint: (String) -> Unit): ByteArray = JarFile(deployment.toFile()).use { jar ->
        val entries = jar.entries()
        var count = 0
        var selected: java.util.jar.JarEntry? = null
        while (entries.hasMoreElements()) {
            val entry = entries.nextElement()
            check(++count <= 200_000) { "installed application JAR entry bound is exceeded" }
            if (entry.name == INSTALLED_RECIPE_ENTRY) {
                check(selected == null && !entry.isDirectory && entry.size in 1L..MAXIMUM_RECIPE_BYTES.toLong()) {
                    "installed application recipe is duplicated or unbounded"
                }
                selected = entry
            }
            checkpoint("while selecting own installed recipe")
        }
        val entry = requireNotNull(selected) { "installed application lacks the production runtime measurement recipe" }
        jar.getInputStream(entry).use { input ->
            val bytes = input.readNBytes(MAXIMUM_RECIPE_BYTES + 1)
            check(bytes.size.toLong() == entry.size && bytes.size <= MAXIMUM_RECIPE_BYTES && input.read() == -1) {
                "installed application recipe bytes exceed their authenticated entry size"
            }
            bytes
        }
    }

    private class ExpandedSourceInput(input: InputStream, private val checkpoint: (String) -> Unit) : FilterInputStream(input) {
        var bytes: Long = 0L
            private set
        override fun read(): Int {
            val result = `in`.read()
            if (result >= 0) account(1)
            return result
        }
        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            val count = `in`.read(buffer, offset, length)
            if (count > 0) account(count)
            return count
        }
        override fun skip(count: Long): Long {
            val buffer = ByteArray(64 * 1024)
            var remaining = count.coerceAtLeast(0L)
            while (remaining > 0) {
                val read = read(buffer, 0, minOf(remaining, buffer.size.toLong()).toInt())
                if (read < 0) break
                remaining -= read
            }
            return count.coerceAtLeast(0L) - remaining
        }
        private fun account(count: Int) {
            bytes = Math.addExact(bytes, count.toLong())
            check(bytes <= 8L * 1024 * 1024 * 1024) { "signed source archive expanded-byte bound is exceeded" }
            checkpoint("while streaming authenticated LLVM source archive")
        }
    }

    private data class ResourceBytes(val bytes: Long, val sha256: String)
    private data class SourceProof(val members: Int, val expandedBytes: Long, val cmake: ResourceBytes)
    private data class SourceLicense(val sourcePath: String, val imagePath: String, val bytes: Long, val sha256: String)
    private val SOURCE_LICENSES = listOf(
        SourceLicense("llvm-project-22.1.6.src/LICENSE.TXT", "/decomp-native-build/licenses/llvm-LICENSE.TXT", 15_141L,
            "8d85c1057d742e597985c7d4e6320b015a9139385cff4cbae06ffc0ebe89afee"),
        SourceLicense("llvm-project-22.1.6.src/clang/LICENSE.TXT", "/decomp-native-build/licenses/clang-LICENSE.TXT", 15_140L,
            "ebcd9bbf783a73d05c53ba4d586b8d5813dcdf3bbec50265860ccc885e606f47"),
    )
    private const val SOURCE_ARCHIVE_ROOT = "llvm-project-22.1.6.src"
    private const val SOURCE_HEADER_PREFIX = "$SOURCE_ARCHIVE_ROOT/clang/lib/Headers/"
    private const val SOURCE_CMAKE_PATH = "${SOURCE_HEADER_PREFIX}CMakeLists.txt"
    private const val SOURCE_ARCHIVE_BYTES = 167_043_464L
    private const val SOURCE_ARCHIVE_SHA256 = "6e0b376a1f6d9873e7dfb09ae6e04b9c7024400f01733fa4c29be69d5c138bc2"
    private const val SOURCE_SIGNATURE_BYTES = 119L
    private const val SOURCE_SIGNATURE_SHA256 = "cb605632f17606799b8a3b76781e80ceeae5e2c7e7823823eff688557ce53a68"
    private const val IMAGE_RECIPE_PATH = "/decomp-native-build/native-runtime-measurement-v2.Dockerfile"
    private const val INSTALLED_RECIPE_ENTRY = "oracle/llvm/22.1.6/native-runtime-measurement-v2.Dockerfile"
    private const val MAXIMUM_RECIPE_BYTES = 64 * 1024
    private const val MAXIMUM_RESOURCE_MEMBERS = 5000
    private const val MAXIMUM_RESOURCE_BYTES = 64L * 1024 * 1024
    private val GENERATED_RESOURCE_NAMES = setOf("arm_neon.h", "arm_fp16.h", "arm_sve.h", "arm_sme.h", "arm_bf16.h", "arm_mve.h",
        "arm_cde.h", "arm_vector_types.h", "riscv_vector.h")
}
