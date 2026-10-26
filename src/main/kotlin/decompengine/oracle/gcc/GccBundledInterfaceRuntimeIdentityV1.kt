package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.StableControlFile
import decompengine.project.NativeInferredInterfaceObservationsV1
import java.nio.file.Path
import java.nio.file.Files
import java.nio.file.LinkOption
import java.io.ByteArrayInputStream
import java.util.jar.Manifest
import java.util.Collections
import java.util.jar.JarFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

internal data class GccBundledInterfaceSourceV1(val role: String, val resourcePath: String, val bytes: Long, val sha256: String) {
    fun toJson() = JsonObject(mapOf("role" to JsonPrimitive(role), "resourcePath" to JsonPrimitive(resourcePath),
        "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256)))
}

internal data class GccBundledInterfaceFileV1(val path: String, val bytes: Long, val sha256: String, val mode: Int) {
    fun toJson() = JsonObject(mapOf("path" to JsonPrimitive(path), "bytes" to JsonPrimitive(bytes),
        "sha256" to JsonPrimitive(sha256), "mode" to JsonPrimitive(mode)))
}

internal data class GccBundledInterfaceClassV1(val path: String, val bytes: Long, val sha256: String) {
    fun toJson() = JsonObject(mapOf("path" to JsonPrimitive(path), "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256)))
}

/** Candidate commitments, never an execution permit. The installed reference and retained owner authenticate them. */
internal class GccBundledInterfaceRuntimeIdentityV1 private constructor(
    sources: List<GccBundledInterfaceSourceV1>,
    val bridge: GccBundledInterfaceFileV1,
    val wrapper: GccBundledInterfaceFileV1,
    val nativeDecompiler: GccBundledInterfaceFileV1,
    classes: List<GccBundledInterfaceClassV1>,
    val sourceClosureSha256: String,
    val closureSha256: String,
) {
    val sources = Collections.unmodifiableList(ArrayList(sources))
    val classes = Collections.unmodifiableList(ArrayList(classes))
    val configurationSha256: String = NativeInferredInterfaceObservationsV1.configurationSha256
    val exporterSha256: String get() = source("model").sha256
    val listingCollectorSha256: String get() = source("listing").sha256
    val inferredCollectorSha256: String get() = source("inferred").sha256
    val typeGraphSha256: String get() = source("typeGraph").sha256
    val wrapperSha256: String get() = source("wrapper").sha256
    val nativeDecompilerSha256: String get() = nativeDecompiler.sha256
    fun source(role: String): GccBundledInterfaceSourceV1 = sources.single { it.role == role }

    private fun unsigned() = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive(PROVIDER),
        "sources" to JsonArray(sources.map { it.toJson() }), "sourceClosureSha256" to JsonPrimitive(sourceClosureSha256),
        "bridge" to bridge.toJson(), "wrapper" to wrapper.toJson(), "nativeDecompiler" to nativeDecompiler.toJson(),
        "classes" to JsonArray(classes.map { it.toJson() }), "configurationSha256" to JsonPrimitive(configurationSha256),
    ))
    fun toJson() = JsonObject(unsigned() + ("closureSha256" to JsonPrimitive(closureSha256)))
    override fun equals(other: Any?) = other is GccBundledInterfaceRuntimeIdentityV1 && toJson() == other.toJson()
    override fun hashCode() = closureSha256.hashCode()

    fun requireReference(entries: Map<String, GccBundledGhidraReferenceEntry>, exporterBytes: Long, exporterSha256: String) {
        require(source("model").bytes == exporterBytes && this.exporterSha256 == exporterSha256) {
            "interface source closure differs from the independently retained exporter"
        }
        for (file in listOf(bridge, wrapper, nativeDecompiler)) {
            val entry = entries[file.path]
            require(entry != null && entry.kind == "file" && entry.bytes == file.bytes &&
                entry.sha256 == file.sha256 && entry.mode == file.mode) { "interface runtime file differs from deployment inventory" }
        }
        require(entries.keys.none { path -> path.endsWith(".class") &&
            (CLASS_FAMILIES.any { family -> val name = path.substringAfterLast('/'); val base = family.substringAfterLast('/');
                name == "$base.class" || name.startsWith("$base$") && name.endsWith(".class") } || path.substringAfterLast('/') == "RunBundledExports.class") && path != wrapper.path
        }) { "interface helper family has a shadow outside its bridge JAR" }
    }

    /** Caller owns and revalidates the application JAR descriptor; no class-loader resource lookup. */
    fun requireApplicationSources(jar: JarFile) {
        val entries = jar.entries().asSequence().take(200_001).toList()
        require(entries.size <= 200_000) { "interface application JAR exceeds its entry bound" }
        for (source in sources) {
            val entry = entries.singleOrNull { it.name == source.resourcePath.removePrefix("/") }
            require(entry != null && !entry.isDirectory && entry.size == source.bytes) {
                "application JAR has no exact unique interface source resource"
            }
            val bytes = jar.getInputStream(entry).use { it.readNBytes(4 * 1024 * 1024 + 1) }
            require(bytes.size.toLong() == source.bytes && OracleArtifacts.sha256(bytes) == source.sha256) {
                "interface source differs from its independent application resource"
            }
        }
    }

    /** All ordered JARs are bounded, pinned and inspected; only the bridge may own helper/worker families. */
    fun requireExecutedClasses(root: Path, classPath: List<String>, entries: Map<String, GccBundledGhidraReferenceEntry>) {
        require(classPath.size in 2..512 && classPath.first() == bridge.path && classPath.distinct().size == classPath.size) {
            "interface runtime classpath count or ownership is invalid"
        }
        var entryCount = 0
        var classBytes = 0L
        val observed = ArrayList<GccBundledInterfaceClassV1>()
        for ((index, relative) in classPath.withIndex()) {
            val expected = entries.getValue(relative)
            StableControlFile.open(root.resolve(relative), 128L * 1024 * 1024, "interface runtime JAR").use { guard ->
                require(guard.size == expected.bytes && guard.sha256(label = "interface runtime JAR") == expected.sha256) {
                    "interface runtime JAR differs from deployment reference"
                }
                JarFile(root.resolve(relative).toFile(), false).use { jar ->
                    jar.getJarEntry("META-INF/MANIFEST.MF")?.let { manifest ->
                        // Signed release JARs have large per-entry sections. Only the bounded
                        // main section can extend the loader classpath; the whole JAR stays hashed.
                        val prefix = jar.getInputStream(manifest).use { it.readNBytes(65537) }
                        val text = prefix.toString(Charsets.ISO_8859_1)
                        val crlf = text.indexOf("\r\n\r\n").takeIf { it >= 0 }?.plus(4)
                        val lf = text.indexOf("\n\n").takeIf { it >= 0 }?.plus(2)
                        val end = listOfNotNull(crlf, lf).minOrNull()
                        ?: prefix.size.takeIf { it <= 65536 && it.toLong() == manifest.size }
                        require(end != null && end <= 65536) { "interface JAR manifest main section exceeds its byte bound" }
                        val linked = Manifest(ByteArrayInputStream(prefix, 0, end)).mainAttributes.getValue("Class-Path")
                        if (!linked.isNullOrBlank()) {
                            val names = linked.trim().split(Regex(" +"))
                            require(names.size <= 128 && names.all { it.matches(Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,250}\\.jar")) }) {
                                "interface JAR manifest escapes its bounded sibling classpath"
                            }
                            for (name in names) {
                                val target = (Path.of(relative).parent ?: Path.of("")).resolve(name).toString()
                                require(target in classPath || target !in entries &&
                                    !Files.exists(root.resolve(target), LinkOption.NOFOLLOW_LINKS)) {
                                    "interface JAR manifest adds an unscanned classpath target"
                                }
                            }
                        }
                    }
                    val seen = HashSet<String>()
                    val enumeration = jar.entries()
                    while (enumeration.hasMoreElements()) {
                        require(++entryCount <= MAXIMUM_JAR_ENTRIES) { "interface classpath exceeds its aggregate JAR entry bound" }
                        val entry = enumeration.nextElement()
                        require(entry.name.length <= 4096 && seen.add(entry.name)) { "interface classpath has a duplicate or excessive entry" }
                        val logical = entry.name.removePrefix("META-INF/versions/").let {
                            if (entry.name.startsWith("META-INF/versions/")) it.substringAfter('/') else it
                        }
                        require(logical != "RunBundledExports.class") { "interface wrapper is shadowed by a classpath JAR" }
                        if (!isFamily(logical)) continue
                        require(index == 0 && relative == bridge.path && logical == entry.name && !entry.isDirectory &&
                            observed.size < MAXIMUM_CLASSES && entry.size in 1..MAXIMUM_CLASS_BYTES.toLong()) {
                            "interface helper class is shadowed, versioned or outside its byte bound"
                        }
                        classBytes = Math.addExact(classBytes, entry.size)
                        require(classBytes <= 128L * 1024 * 1024) { "interface class families exceed their aggregate byte bound" }
                        val bytes = jar.getInputStream(entry).use { it.readNBytes(MAXIMUM_CLASS_BYTES + 1) }
                        require(bytes.size.toLong() == entry.size) { "interface helper class size is invalid" }
                        observed.add(GccBundledInterfaceClassV1(entry.name, entry.size, OracleArtifacts.sha256(bytes)))
                    }
                }
                guard.verifyUnchanged("after interface class family authentication")
            }
        }
        require(observed.sortedBy { it.path } == classes) { "interface compiled class families differ from their complete reference" }
    }

    companion object {
        const val PROVIDER = "gcc-bundled-interface-runtime-identity-v1"
        const val MAXIMUM_CLASSES = 512
        const val MAXIMUM_CLASS_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_JAR_ENTRIES = 1_000_000
        val SOURCE_RESOURCES: Map<String, String> = Collections.unmodifiableMap(mapOf(
            "inferred" to "/ghidra_scripts/ExportInferredInterfacesV1.java",
            "listing" to "/ghidra_scripts/ExportNativeInterfacesV1.java",
            "model" to "/ghidra_scripts/ExportProgramModel.java",
            "typeGraph" to "/ghidra_scripts/NativeInterfaceTypeGraphV1.java",
            "wrapper" to "/ghidra_scripts/RunBundledExports.java",
        ))
        val CLASS_FAMILIES: List<String> = Collections.unmodifiableList(listOf("ExportInferredInterfacesV1", "ExportNativeInterfacesV1", "NativeInterfaceTypeGraphV1",
            "decompengine/ghidra/BundledGhidraWorker", "decompengine/ghidra/JvmMxBeanDiagnostics"))
        fun isFamily(path: String) = CLASS_FAMILIES.any { path == "$it.class" || path.startsWith("$it$") && path.endsWith(".class") }

        fun parse(value: JsonObject): GccBundledInterfaceRuntimeIdentityV1 {
            value.fields("schemaVersion", "provider", "sources", "sourceClosureSha256", "bridge", "wrapper", "nativeDecompiler", "classes", "configurationSha256", "closureSha256")
            require(value.number("schemaVersion") == 1L && value.string("provider") == PROVIDER) { "interface runtime identity version is invalid" }
            require(value.string("configurationSha256") == NativeInferredInterfaceObservationsV1.configurationSha256) {
                "interface collector configuration differs from the fixed policy"
            }
            val rawSources = value.array("sources")
            require(rawSources.size == SOURCE_RESOURCES.size) { "interface source count is invalid" }
            val sources = rawSources.map { raw ->
                val node = raw as? JsonObject ?: throw IllegalArgumentException("interface source entry must be an object")
                node.fields("role", "resourcePath", "bytes", "sha256")
                val role = node.string("role")
                require(SOURCE_RESOURCES[role] == node.string("resourcePath")) { "interface source role or resource path is invalid" }
                GccBundledInterfaceSourceV1(role, node.string("resourcePath"), node.boundedBytes(4 * 1024 * 1024), node.digest("sha256"))
            }
            require(sources.map { it.role } == SOURCE_RESOURCES.keys.sorted()) { "interface source inventory is incomplete or noncanonical" }
            val sourceClosure = value.digest("sourceClosureSha256")
            require(sourceClosure == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
                "sources" to JsonArray(sources.map { it.toJson() })))))) { "interface source commitment is invalid" }
            fun file(name: String, path: String, executable: Boolean): GccBundledInterfaceFileV1 {
                val node = value[name] as? JsonObject ?: throw IllegalArgumentException("interface runtime file must be an object")
                node.fields("path", "bytes", "sha256", "mode")
                require(node.string("path") == path && node.number("mode") == (if (executable) 493L else 420L)) { "interface runtime file layout or mode is invalid" }
                return GccBundledInterfaceFileV1(path, node.boundedBytes(128 * 1024 * 1024), node.digest("sha256"), node.number("mode").toInt())
            }
            val bridge = file("bridge", "decomp-ghidra-bridge.jar", false)
            val wrapper = file("wrapper", "scripts/RunBundledExports.class", false)
            val native = file("nativeDecompiler", "ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Decompiler/os/linux_x86_64/decompile", true)
            val rawClasses = value.array("classes")
            require(rawClasses.size in CLASS_FAMILIES.size..MAXIMUM_CLASSES) { "interface class family count is invalid" }
            val classes = rawClasses.map { raw ->
                val node = raw as? JsonObject ?: throw IllegalArgumentException("interface class entry must be an object")
                node.fields("path", "bytes", "sha256")
                val path = node.string("path")
                require(path.length <= 4096 && isFamily(path)) { "interface class family path is invalid" }
                GccBundledInterfaceClassV1(path, node.boundedBytes(MAXIMUM_CLASS_BYTES), node.digest("sha256"))
            }
            require(classes.map { it.path } == classes.map { it.path }.distinct().sorted() &&
                CLASS_FAMILIES.all { family -> classes.any { it.path == "$family.class" } } &&
                classes.sumOf { it.bytes } <= 128L * 1024 * 1024) {
                "interface class families are incomplete, repeated, unordered or excessive"
            }
            val closure = value.digest("closureSha256")
            require(closure == OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(value - "closureSha256")))) {
                "interface runtime closure commitment is invalid"
            }
            return GccBundledInterfaceRuntimeIdentityV1(sources, bridge, wrapper, native, classes, sourceClosure, closure)
        }
    }
}

private fun JsonObject.fields(vararg names: String) = require(keys == names.toSet()) { "interface runtime identity fields are invalid" }
private fun JsonObject.string(name: String): String = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("interface runtime $name must be a string")
private fun JsonObject.number(name: String): Long = (this[name] as? JsonPrimitive)?.takeIf { !it.isString }?.longOrNull
    ?: throw IllegalArgumentException("interface runtime $name must be an integer")
private fun JsonObject.array(name: String): JsonArray = this[name] as? JsonArray
    ?: throw IllegalArgumentException("interface runtime $name must be an array")
private fun JsonObject.digest(name: String): String = string(name).also { require(it.matches(Regex("[a-f0-9]{64}"))) { "interface runtime digest is invalid" } }
private fun JsonObject.boundedBytes(maximum: Int): Long = number("bytes").also { require(it in 1..maximum.toLong()) { "interface runtime byte bound is invalid" } }
