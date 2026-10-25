package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.NativeInferredInterfaceObservationsV1
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarFile
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject

class GccBundledInterfaceRuntimeIdentityV1Test {
    @Test
    fun `interface identity is closed complete immutable and configuration bound`() {
        val document = fixture()
        val identity = GccBundledInterfaceRuntimeIdentityV1.parse(document)
        assertEquals(document, identity.toJson())
        assertEquals(identity, GccBundledInterfaceRuntimeIdentityV1.parse(identity.toJson()))
        assertEquals(SHA_A, identity.listingCollectorSha256)
        assertEquals(SHA_A, identity.inferredCollectorSha256)
        assertEquals(SHA_A, identity.typeGraphSha256)
        assertEquals(SHA_A, identity.wrapperSha256)
        assertFailsWith<UnsupportedOperationException> { (identity.sources as MutableList<GccBundledInterfaceSourceV1>).clear() }
        assertFailsWith<UnsupportedOperationException> { (identity.classes as MutableList<GccBundledInterfaceClassV1>).clear() }
        for (bad in listOf(JsonObject(document + ("authority" to JsonPrimitive(true))),
            JsonObject(document - "sources"), JsonObject(document + ("configurationSha256" to JsonPrimitive(SHA_B))),
            JsonObject(document + ("sourceClosureSha256" to JsonPrimitive(SHA_B))),
            JsonObject(document + ("closureSha256" to JsonPrimitive(SHA_B))))) {
            assertFailsWith<IllegalArgumentException> { GccBundledInterfaceRuntimeIdentityV1.parse(bad) }
        }
        val sources = document.getValue("sources").jsonArray
        for (bad in listOf(JsonArray(sources.dropLast(1)), JsonArray(sources + sources.first()), JsonArray(sources.reversed()),
            JsonArray(sources.mapIndexed { index, item -> if (index == 0) JsonObject(item.jsonObject +
                ("resourcePath" to JsonPrimitive("/other.java"))) else item }),
            JsonArray(sources.mapIndexed { index, item -> if (index == 0) JsonObject(item.jsonObject +
                ("bytes" to JsonPrimitive(4L * 1024 * 1024 + 1))) else item }))) {
            assertFailsWith<IllegalArgumentException> { GccBundledInterfaceRuntimeIdentityV1.parse(rehash(JsonObject(document + ("sources" to bad)))) }
        }
    }

    @Test
    fun `nested class inventory and native executable mode cannot be removed or relabelled`() {
        val document = fixture()
        val classes = document.getValue("classes").jsonArray
        for (bad in listOf(JsonArray(classes.dropLast(1)), JsonArray(classes + classes.first()), JsonArray(classes.reversed()),
            JsonArray(classes.mapIndexed { index, item -> if (index == 0) JsonObject(item.jsonObject +
                ("path" to JsonPrimitive("Other.class"))) else item }))) {
            assertFailsWith<IllegalArgumentException> { GccBundledInterfaceRuntimeIdentityV1.parse(rehash(JsonObject(document + ("classes" to bad)))) }
        }
        val native = document.getValue("nativeDecompiler").jsonObject
        for (bad in listOf(JsonObject(native + ("mode" to JsonPrimitive(420))),
            JsonObject(native + ("path" to JsonPrimitive("other/decompile"))),
            JsonObject(native + ("bytes" to JsonPrimitive(0))), JsonObject(native + ("bytes" to JsonPrimitive("32"))))) {
            assertFailsWith<IllegalArgumentException> { GccBundledInterfaceRuntimeIdentityV1.parse(rehash(JsonObject(document + ("nativeDecompiler" to bad)))) }
        }
    }

    @Test
    fun `reference correspondence rejects rehashed file source and loose class substitutions`() {
        val identity = GccBundledInterfaceRuntimeIdentityV1.parse(fixture())
        val inventory = inventory(identity)
        identity.requireReference(inventory, 32, SHA_A)
        assertFailsWith<IllegalArgumentException> { identity.requireReference(inventory, 33, SHA_A) }
        assertFailsWith<IllegalArgumentException> { identity.requireReference(inventory, 32, SHA_B) }
        for (file in listOf(identity.bridge, identity.wrapper, identity.nativeDecompiler)) {
            for (changed in listOf(inventory.getValue(file.path).copy(bytes = file.bytes + 1),
                inventory.getValue(file.path).copy(sha256 = SHA_B), inventory.getValue(file.path).copy(mode = 448))) {
                assertFailsWith<IllegalArgumentException> { identity.requireReference(inventory + (file.path to changed), 32, SHA_A) }
            }
        }
        for (name in listOf("ExportNativeInterfacesV1.class", "NativeInterfaceTypeGraphV1\$Node.class", "BundledGhidraWorker.class")) {
            val path = "scripts/$name"
            assertFailsWith<IllegalArgumentException> { identity.requireReference(inventory +
                (path to GccBundledGhidraReferenceEntry(path, "file", 420, 32, SHA_A)), 32, SHA_A) }
        }
    }

    @Test
    fun `runtime nine preserves serial ceilings binds exact arguments and refuses mixed legacy identities`() {
        val identity = GccBundledInterfaceRuntimeIdentityV1.parse(fixture())
        val runtime = runtime(identity)
        val command = command(runtime)
        val arguments = command.drop(command.indexOf("decompengine.ghidra.BundledGhidraWorker") + 1)
        assertEquals(33, arguments.size)
        assertEquals(listOf("ExportProgramModel.java", "4", SHA_A, BundledGhidra.ARCHIVE_SHA256, "full",
            "/scratch/run/reports/program_model.json"), arguments.subList(6, 12))
        assertEquals(listOf("ExportNativeInterfacesV1.class", "6", SHA_B, SHA_A, BundledGhidra.ARCHIVE_SHA256,
            identity.listingCollectorSha256, arguments[11], "/scratch/run/reports/native-interfaces-v1"), arguments.subList(12, 20))
        assertEquals(listOf("ExportInferredInterfacesV1.class", "11", SHA_B, SHA_A, BundledGhidra.ARCHIVE_SHA256,
            identity.listingCollectorSha256, identity.inferredCollectorSha256, identity.typeGraphSha256,
            identity.wrapperSha256, identity.nativeDecompilerSha256, arguments[11], arguments[19],
            "/scratch/run/reports/native-inferred-interfaces-v1"), arguments.subList(20, 33))
        assertEquals(2L * 1024 * 1024 * 1024, runtime.maximumJavaHeapBytes)
        assertEquals(1, runtime.processorCount)
        assertEquals(1, runtime.analysisThreadCount)
        assertEquals(1, runtime.decompilerWorkerCount)
        assertFalse(runtime.runtimeDiagnostics)
        assertFalse(command.any { it.substringAfterLast('/').substringAfterLast('\\').equals("analyzeHeadless", ignoreCase = true) ||
            it.substringAfterLast('/').substringAfterLast('\\').equals("analyzeHeadless.bat", ignoreCase = true) ||
            it.startsWith("full-recovery-workers") })
        assertEquals(runtime.toJson(), GccBundledGhidraRuntime.parse(runtime.toJson()).toJson())
        for (version in 1..8) assertFailsWith<IllegalArgumentException> {
            GccBundledGhidraRuntime(runtime.root, runtime.classPath, version, interfaceCollector = identity)
        }
        assertFailsWith<IllegalArgumentException> { GccBundledGhidraRuntime(runtime.root, runtime.classPath, 9) }
        assertFailsWith<IllegalArgumentException> { GccBundledGhidraRuntime(runtime.root, runtime.classPath, 9,
            GccBundledNativeCallCollectorIdentityV1(32, SHA_A, 32, SHA_A), identity) }
        for (kind in listOf(GccCompilerEngineContainmentRunKind.INTERRUPTED, GccCompilerEngineContainmentRunKind.RESUMED)) {
            assertFailsWith<IllegalArgumentException> { command(runtime, kind) }
        }
        for (bad in listOf(JsonObject(runtime.toJson() - "interfaceCollector"),
            JsonObject(runtime.toJson() + ("processorCount" to JsonPrimitive(4))),
            JsonObject(runtime.toJson() + ("provider" to JsonPrimitive("bundled-ghidra-java-api-runtime-v5"))))) {
            assertFailsWith<IllegalArgumentException> { GccBundledGhidraRuntime.parse(bad) }
        }
    }

    @Test
    fun `new installed reference links each source class and native identity while legacy absent field remains readable`() {
        GccBundledGhidraDeploymentReference.open().use { deployment ->
            val identity = assertNotNull(deployment.reference.interfaceCollector)
            identity.requireReference(deployment.reference.entries, deployment.reference.exporterBytes, deployment.reference.exporterSha256)
            assertEquals(deployment.reference.exporterSha256, identity.exporterSha256)
            assertTrue(identity.classes.any { it.path.startsWith("NativeInterfaceTypeGraphV1\$") })
            val referencePath = Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bundledGhidraReference")))
            val bytes = Files.newInputStream(referencePath).use { it.readNBytes(8 * 1024 * 1024 + 1) }
            val limits = decompengine.oracle.core.StrictJsonLimits(maximumInputBytes = 8 * 1024 * 1024,
                maximumCanonicalBytes = 8 * 1024 * 1024, maximumNodes = 250000, maximumTotalStringBytes = 8 * 1024 * 1024)
            val document = OracleJson.parseCanonical(bytes, limits).jsonObject
            val legacyUnsigned = JsonObject(document - "interfaceCollector" - "closureSha256")
            val legacy = JsonObject(legacyUnsigned + ("closureSha256" to JsonPrimitive(OracleArtifacts.sha256(
                OracleJson.canonicalBytes(legacyUnsigned, limits)))))
            assertEquals(null, GccBundledGhidraReference.parse(OracleJson.canonicalBytes(legacy, limits)).interfaceCollector)
            val invalid = JsonObject(document + ("interfaceCollector" to JsonObject(identity.toJson() + ("authority" to JsonPrimitive(true)))))
            assertFailsWith<IllegalArgumentException> { GccBundledGhidraReference.parse(OracleJson.canonicalBytes(invalid, limits)) }
        }
    }

    @Test
    fun `compiled validator rejects every unpaired interface route before initialization`() {
        GccBundledGhidraDeploymentReference.open().use { deployment ->
            assertNotNull(deployment.reference.interfaceCollector)
            val urls = deployment.reference.classPath.map { deployment.bundleRoot.resolve(it).toUri().toURL() }.toTypedArray()
            java.net.URLClassLoader(urls, ClassLoader.getPlatformClassLoader()).use { loader ->
                val worker = Class.forName("decompengine.ghidra.BundledGhidraWorker", false, loader)
                val validate = worker.getDeclaredMethod("validateInterfaceInvocation", Array<String>::class.java).also { it.isAccessible = true }
                val full = command(runtime(GccBundledInterfaceRuntimeIdentityV1.parse(fixture())))
                val arguments = full.drop(full.indexOf("decompengine.ghidra.BundledGhidraWorker") + 1).toTypedArray()
                validate.invoke(null, arguments as Any)
                val mutations = listOf(1 to "analyze-diagnostics-v1", 6 to "ExportDecompiledC.java", 7 to "5", 10 to "planning",
                    12 to "ExportNativeInterfacesV1.java", 13 to "5", 15 to SHA_B, 16 to SHA_B, 18 to "/other/model.json",
                    20 to "ExportNativeCallsV1.class", 21 to "10", 22 to SHA_A, 23 to SHA_B, 24 to SHA_B, 25 to SHA_B,
                    26 to "bad", 27 to "bad", 28 to "bad", 29 to "bad", 30 to "/other/model.json",
                    31 to "/other/listing", 32 to "/other/inferred", 11 to "/scratch/reports/../program_model.json")
                for ((index, value) in mutations) {
                    val failure = assertFailsWith<java.lang.reflect.InvocationTargetException>("argument $index") {
                        validate.invoke(null, arguments.copyOf().also { it[index] = value } as Any)
                    }
                    assertTrue(failure.cause is IllegalArgumentException)
                }
                for (bad in listOf(arguments + arrayOf("Other.class", "0"), arguments.dropLast(1).toTypedArray())) {
                    assertTrue(assertFailsWith<java.lang.reflect.InvocationTargetException> {
                        validate.invoke(null, bad as Any)
                    }.cause is IllegalArgumentException)
                }
                validate.invoke(null, arrayOf("/bundle", "probe") as Any)
            }
        }
    }

    @Test
    fun `complete class family authentication rejects nested substitution removal and library shadow`() {
        withJarFixture { root, identity, paths, entries ->
            identity.requireExecutedClasses(root, paths, entries)
            val original = Files.readAllBytes(root.resolve(paths.first()))
            for (changed in listOf(classRecords().filterNot { it.first.endsWith("\$Nested.class") }, classRecords().map { (name, bytes) ->
                name to if (name.endsWith("\$Nested.class")) byteArrayOf(99) else bytes })) {
                writeJar(root.resolve(paths.first()), changed)
                val rebound = entries + (paths.first() to reference(root, paths.first()))
                assertFailsWith<IllegalArgumentException> { identity.requireExecutedClasses(root, paths, rebound) }
            }
            Files.write(root.resolve(paths.first()), original)
            for (shadow in listOf("ExportNativeInterfacesV1.class", "NativeInterfaceTypeGraphV1\$Nested.class",
                "RunBundledExports.class", "META-INF/versions/21/ExportInferredInterfacesV1.class")) {
                writeJar(root.resolve(paths.last()), listOf(shadow to byteArrayOf(1)))
                val rebound = entries + (paths.last() to reference(root, paths.last()))
                assertFailsWith<IllegalArgumentException> { identity.requireExecutedClasses(root, paths, rebound) }
            }
        }
    }

    @Test
    fun `manifest classpath cannot add urls traversal or present unscanned jars`() {
        withJarFixture { root, identity, paths, entries ->
            for (target in listOf("https://invalid.example/a.jar", "../a.jar", "extra.jar")) {
                Files.write(root.resolve(paths.last()).parent.resolve("extra.jar"), byteArrayOf(1))
                writeJar(root.resolve(paths.last()), listOf("META-INF/MANIFEST.MF" to
                    "Manifest-Version: 1.0\r\nClass-Path: $target\r\n\r\n".toByteArray()))
                assertFailsWith<IllegalArgumentException> { identity.requireExecutedClasses(root, paths,
                    entries + (paths.last() to reference(root, paths.last()))) }
            }
            writeJar(root.resolve(paths.last()), listOf("META-INF/MANIFEST.MF" to
                "Manifest-Version: 1.0\r\nClass-Path: absent-legacy.jar\r\n\r\n".toByteArray()))
            identity.requireExecutedClasses(root, paths, entries + (paths.last() to reference(root, paths.last())))
        }
    }

    @Test
    fun `duplicate jar entries fail even after the enclosing file hash is rebound`() {
        withJarFixture { root, identity, paths, entries ->
            val path = root.resolve(paths.last())
            writeJar(path, listOf("OtherA.class" to byteArrayOf(1), "OtherB.class" to byteArrayOf(2)))
            replaceZipName(path, "OtherB.class", "OtherA.class")
            assertFailsWith<IllegalArgumentException> { identity.requireExecutedClasses(root, paths,
                entries + (paths.last() to reference(root, paths.last()))) }
        }
    }

    @Test
    fun `application jar sources reject replacement missing and duplicate resources independently of hashes supplied by callers`() {
        withJarFixture { root, _, _, _ ->
            val content = ByteArray(32) { 5 }
            val original = fixture()
            val sources = JsonArray(original.getValue("sources").jsonArray.map { raw ->
                JsonObject(raw.jsonObject + ("sha256" to JsonPrimitive(OracleArtifacts.sha256(content))))
            })
            val identity = GccBundledInterfaceRuntimeIdentityV1.parse(rehash(JsonObject(original + mapOf(
                "sources" to sources, "sourceClosureSha256" to JsonPrimitive(OracleArtifacts.sha256(
                    OracleJson.canonicalBytes(JsonObject(mapOf("sources" to sources)))))))))
            val path = root.resolve("application.jar")
            val records = identity.sources.map { it.resourcePath.removePrefix("/") to content }
            writeJar(path, records)
            JarFile(path.toFile(), false).use(identity::requireApplicationSources)
            for (index in records.indices) {
                for (changed in listOf(records.filterIndexed { selected, _ -> selected != index },
                    records.mapIndexed { selected, item -> if (selected == index) item.first to ByteArray(32) { 6 } else item })) {
                    writeJar(path, changed)
                    assertFailsWith<IllegalArgumentException> { JarFile(path.toFile(), false).use(identity::requireApplicationSources) }
                }
            }
            val selected = records.first().first
            val duplicateName = selected.dropLast(5) + ".javb"
            writeJar(path, records + (duplicateName to content))
            replaceZipName(path, duplicateName, selected)
            assertFailsWith<IllegalArgumentException> { JarFile(path.toFile(), false).use(identity::requireApplicationSources) }
        }
    }

    private fun replaceZipName(path: Path, old: String, replacement: String) {
        val before = old.toByteArray()
        val after = replacement.toByteArray()
        require(before.size == after.size)
        val bytes = Files.readAllBytes(path)
        var replacements = 0
        for (offset in 0..bytes.size - before.size) {
            if (before.indices.all { bytes[offset + it] == before[it] }) {
                after.copyInto(bytes, offset)
                replacements++
            }
        }
        assertEquals(2, replacements, "both local and central ZIP names must change")
        Files.write(path, bytes)
    }

    private fun runtime(identity: GccBundledInterfaceRuntimeIdentityV1): GccBundledGhidraRuntime {
        val root = Path.of("/trusted/bundle")
        return GccBundledGhidraRuntime(root, listOf(GccBundledGhidraClassPathEntry(root.resolve(identity.bridge.path),
            identity.bridge.bytes, identity.bridge.sha256), GccBundledGhidraClassPathEntry(root.resolve(LIBRARY), 32, SHA_A)),
            9, interfaceCollector = identity)
    }

    private fun command(runtime: GccBundledGhidraRuntime, kind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.FRESH_CONTROL): List<String> {
        val identity = checkNotNull(runtime.interfaceCollector)
        val artifacts = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.map { role ->
            val relative = when (role) {
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> identity.bridge.path
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> identity.wrapper.path
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> "bundle.sha256"
                else -> null
            }
            GccCompilerEngineContainmentArtifactIdentity(role,
                relative?.let(runtime.root::resolve) ?: Path.of("/trusted/${if (role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE) "ExportProgramModel.java" else role.wireName}"),
                if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR) identity.bridge.bytes else 32,
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> BundledGhidra.ARCHIVE_SHA256
                    GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY -> SHA_B
                    else -> SHA_A
                })
        }
        return runtime.command(artifacts, GccCompilerEngineAnalysisStateIdentity(GccCompilerEngineAnalysisStateMode.FRESH_EMPTY,
            Path.of("/scratch/run/state"), null, 0, 0), GccCompilerEngineOutputLeaseIdentity(Path.of("/scratch/run"),
            1, 2, 3, 1000, 1000, 448, 1024, 2048, 128, 256), kind)
    }

    private fun fixture(classes: List<Pair<String, ByteArray>> = classRecords(), bridge: GccBundledGhidraReferenceEntry? = null): JsonObject {
        fun file(path: String, mode: Int = 420, bytes: Long = 32, sha: String = SHA_A) = JsonObject(mapOf(
            "path" to JsonPrimitive(path), "mode" to JsonPrimitive(mode), "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha)))
        val sources = JsonArray(GccBundledInterfaceRuntimeIdentityV1.SOURCE_RESOURCES.toSortedMap().map { (role, path) ->
            JsonObject(mapOf("role" to JsonPrimitive(role), "resourcePath" to JsonPrimitive(path), "bytes" to JsonPrimitive(32), "sha256" to JsonPrimitive(SHA_A)))
        })
        return rehash(JsonObject(mapOf("schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive(GccBundledInterfaceRuntimeIdentityV1.PROVIDER),
            "sources" to sources, "sourceClosureSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf("sources" to sources))))),
            "configurationSha256" to JsonPrimitive(NativeInferredInterfaceObservationsV1.configurationSha256),
            "bridge" to file("decomp-ghidra-bridge.jar", bytes = bridge?.bytes ?: 32, sha = bridge?.sha256 ?: SHA_A),
            "wrapper" to file("scripts/RunBundledExports.class"),
            "nativeDecompiler" to file("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Features/Decompiler/os/linux_x86_64/decompile", 493),
            "classes" to JsonArray(classes.sortedBy { it.first }.map { (path, bytes) -> JsonObject(mapOf(
                "path" to JsonPrimitive(path), "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)))) }))))
    }
    private fun inventory(identity: GccBundledInterfaceRuntimeIdentityV1) = listOf(identity.bridge, identity.wrapper, identity.nativeDecompiler)
        .associate { it.path to GccBundledGhidraReferenceEntry(it.path, "file", it.mode, it.bytes, it.sha256) }
    private fun rehash(value: JsonObject): JsonObject {
        val unsigned = JsonObject(value - "closureSha256")
        return JsonObject(unsigned + ("closureSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)))))
    }
    private fun classRecords() = (GccBundledInterfaceRuntimeIdentityV1.CLASS_FAMILIES.map { "$it.class" } +
        "NativeInterfaceTypeGraphV1\$Nested.class").sorted().map { it to byteArrayOf(1, 2, 3) }
    private fun writeJar(path: Path, records: List<Pair<String, ByteArray>>) {
        Files.createDirectories(path.parent)
        JarOutputStream(Files.newOutputStream(path)).use { jar -> for ((name, bytes) in records) {
            jar.putNextEntry(JarEntry(name)); jar.write(bytes); jar.closeEntry()
        } }
    }
    private fun reference(root: Path, name: String): GccBundledGhidraReferenceEntry {
        val bytes = Files.readAllBytes(root.resolve(name))
        return GccBundledGhidraReferenceEntry(name, "file", 420, bytes.size.toLong(), OracleArtifacts.sha256(bytes))
    }
    private fun withJarFixture(block: (Path, GccBundledInterfaceRuntimeIdentityV1, List<String>, Map<String, GccBundledGhidraReferenceEntry>) -> Unit) {
        val parent = Path.of("build/interface-runtime-controls").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "jars-")
        try {
            val paths = listOf("decomp-ghidra-bridge.jar", LIBRARY)
            writeJar(root.resolve(paths.first()), classRecords())
            writeJar(root.resolve(paths.last()), listOf("Other.class" to byteArrayOf(4)))
            val entries = paths.associateWith { reference(root, it) }
            block(root, GccBundledInterfaceRuntimeIdentityV1.parse(fixture(bridge = entries.getValue(paths.first()))), paths, entries)
        } finally {
            Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    private companion object {
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const val LIBRARY = "ghidra_12.1.3_PUBLIC/Ghidra/Framework/Module/lib/library.jar"
    }
}
