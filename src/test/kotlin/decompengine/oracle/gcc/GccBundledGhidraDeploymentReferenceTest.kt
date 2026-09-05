package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class GccBundledGhidraDeploymentReferenceTest {
    @Test
    fun `installed opener selects its own application exporter despite an earlier shadow resource`() {
        assertTrue(runInstalledProbe("open").startsWith("installed-reference-opened:"))
    }

    @Test
    fun `installed opener rejects reference root and paired overrides before source selection`() {
        for (mode in listOf("reference-override", "root-override", "paired-overrides")) {
            assertEquals("installed-overrides-rejected:$mode", runInstalledProbe(mode))
        }
    }

    @Test
    fun `deployment opener retains generated reference and validates packaged exporter`() {
        val deployment = GccBundledGhidraDeploymentReference.open()
        try {
            val reference = deployment.reference
            assertTrue(deployment.bundleRoot.isAbsolute)
            assertTrue(reference.entries.values.any { it.kind == "file" && it.bytes == 0L })
            assertEquals(BRIDGE, reference.classPath.first())
            assertTrue(reference.classPath.size in 2..512)
            assertEquals("file", reference.entries.getValue(GUARD).kind)
            val exporter = assertNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
                .use { it.readNBytes(4 * 1024 * 1024 + 1) }
            assertEquals(reference.exporterBytes, exporter.size.toLong())
            assertEquals(reference.exporterSha256, OracleArtifacts.sha256(exporter))
            deployment.verify("after test inspection")
            deployment.verify("second read-only inspection")
        } finally {
            deployment.close()
        }
        deployment.close()
        assertFailsWith<IllegalStateException> { deployment.verify("after close") }
    }

    @Test
    fun `closed deployment reference preserves directories empty files modes and exact classpath`() {
        val document = fixture()
        val bytes = canonical(document)
        val reference = GccBundledGhidraReference.parse(bytes)
        bytes[0] = '!'.code.toByte()
        assertEquals(document.getValue("closureSha256").jsonPrimitive.content, reference.closureSha256)
        assertEquals(document.getValue("entries").jsonArray.size, reference.entries.size)
        assertEquals(listOf(BRIDGE, LIBRARY_FIRST, LIBRARY_LAST), reference.classPath)
        assertEquals(EXPORTER_BYTES, reference.exporterBytes)
        assertEquals(SHA_C, reference.exporterSha256)
        val emptyDirectory = reference.entries.getValue("$RELEASE/empty-directory")
        assertEquals("directory", emptyDirectory.kind)
        assertEquals(493, emptyDirectory.mode)
        assertNull(emptyDirectory.bytes)
        assertNull(emptyDirectory.sha256)
        val emptyFile = reference.entries.getValue("$RELEASE/empty-file")
        assertEquals("file", emptyFile.kind)
        assertEquals(0L, emptyFile.bytes)
        assertEquals(EMPTY_SHA256, emptyFile.sha256)
        assertEquals(493, reference.entries.getValue("$RELEASE/support/launch").mode)
        assertEquals(420, reference.entries.getValue(BRIDGE).mode)
        assertTrue(reference.entries.containsKey("bundle.sha256"))
        assertFalse(reference.classPath.contains("$RELEASE/other.jar"))
        assertFailsWith<UnsupportedOperationException> {
            (reference.entries as MutableMap<String, GccBundledGhidraReferenceEntry>).clear()
        }
        assertFailsWith<UnsupportedOperationException> { (reference.classPath as MutableList<String>).clear() }
    }

    @Test
    fun `reference selfhash is required and strict canonical bytes cannot be silently normalized`() {
        val valid = fixture()
        val stale = JsonObject(valid + ("exporter" to JsonObject(
            valid.getValue("exporter").jsonObject + ("sha256" to JsonPrimitive(SHA_B)),
        )))
        val malformed = listOf(
            canonical(JsonObject(valid - "closureSha256")),
            canonical(JsonObject(valid + ("closureSha256" to JsonPrimitive(SHA_A)))),
            canonical(stale),
            canonical(valid) + "\n".encodeToByteArray(),
            "{\"schemaVersion\":1,\"schemaVersion\":1}".encodeToByteArray(),
            byteArrayOf(0xc3.toByte(), 0x28),
            "[]".encodeToByteArray(),
        )
        for (bytes in malformed) {
            assertFailsWith<IllegalArgumentException> { GccBundledGhidraReference.parse(bytes) }
        }
        val changed = GccBundledGhidraReference.parse(rehash(stale))
        assertEquals(SHA_B, changed.exporterSha256)
        assertNotEquals(valid.getValue("closureSha256").jsonPrimitive.content, changed.closureSha256)
    }

    @Test
    fun `rehashed reference still requires exact provider version release archive and root mode`() {
        val valid = fixture()
        val archive = valid.getValue("archive").jsonObject
        val mutations = listOf(
            JsonObject(valid + ("extra" to JsonPrimitive(true))),
            JsonObject(valid + ("schemaVersion" to JsonPrimitive(2))),
            JsonObject(valid + ("schemaVersion" to JsonPrimitive("1"))),
            JsonObject(valid + ("provider" to JsonPrimitive("unreviewed-deployment"))),
            JsonObject(valid + ("ghidraVersion" to JsonPrimitive("12.1.2"))),
            JsonObject(valid + ("ghidraRelease" to JsonPrimitive("DEV"))),
            JsonObject(valid + ("rootMode" to JsonPrimitive(511))),
            JsonObject(valid + ("rootMode" to JsonPrimitive(420))),
            JsonObject(valid + ("rootMode" to JsonPrimitive("493"))),
            JsonObject(valid + ("archive" to JsonObject(archive + ("extra" to JsonPrimitive(true))))),
            JsonObject(valid + ("archive" to JsonObject(archive + ("bytes" to JsonPrimitive(ARCHIVE_BYTES + 1))))),
            JsonObject(valid + ("archive" to JsonObject(archive + ("sha256" to JsonPrimitive(SHA_A))))),
        )
        for (document in mutations) assertRejected(document)
    }

    @Test
    fun `exporter reference has exact packaged resource identity and bounded nonempty bytes`() {
        val valid = fixture()
        val exporter = valid.getValue("exporter").jsonObject
        val changed = listOf(
            JsonObject(exporter - "sha256"),
            JsonObject(exporter + ("extra" to JsonPrimitive(true))),
            JsonObject(exporter + ("resourcePath" to JsonPrimitive("/elsewhere/ExportProgramModel.java"))),
            JsonObject(exporter + ("resourcePath" to JsonPrimitive("ghidra_scripts/ExportProgramModel.java"))),
            JsonObject(exporter + ("bytes" to JsonPrimitive(0))),
            JsonObject(exporter + ("bytes" to JsonPrimitive(4L * 1024 * 1024 + 1))),
            JsonObject(exporter + ("bytes" to JsonPrimitive("32"))),
            JsonObject(exporter + ("sha256" to JsonPrimitive("A".repeat(64)))),
        )
        for (candidate in changed) assertRejected(JsonObject(valid + ("exporter" to candidate)))
        val maximum = JsonObject(valid + ("exporter" to JsonObject(exporter + ("bytes" to JsonPrimitive(4L * 1024 * 1024)))))
        assertEquals(4L * 1024 * 1024, GccBundledGhidraReference.parse(rehash(maximum)).exporterBytes)
    }

    @Test
    fun `entry kind determines closed fields normalized modes and empty file digest`() {
        val valid = fixture()
        val regular = entries(valid).single { it.getValue("path").jsonPrimitive.content == BRIDGE }
        val directory = entries(valid).single { it.getValue("path").jsonPrimitive.content == "scripts" }
        val empty = entries(valid).single { it.getValue("path").jsonPrimitive.content == "$RELEASE/empty-file" }
        val invalidFiles = listOf(
            JsonObject(regular + ("extra" to JsonPrimitive(true))),
            JsonObject(regular - "bytes"),
            JsonObject(regular + ("kind" to JsonPrimitive("symlink"))),
            JsonObject(regular + ("mode" to JsonPrimitive(511))),
            JsonObject(regular + ("mode" to JsonPrimitive(292))),
            JsonObject(regular + ("mode" to JsonPrimitive(2541))),
            JsonObject(regular + ("bytes" to JsonPrimitive(-1))),
            JsonObject(regular + ("bytes" to JsonPrimitive(128L * 1024 * 1024 + 1))),
            JsonObject(regular + ("bytes" to JsonPrimitive("32"))),
            JsonObject(regular + ("bytes" to JsonPrimitive(1.5))),
            JsonObject(regular + ("sha256" to JsonPrimitive(SHA_A.drop(1)))),
            JsonObject(regular + ("sha256" to JsonPrimitive("g".repeat(64)))),
            JsonObject(regular + ("sha256" to JsonNull)),
        )
        for (entry in invalidFiles) assertRejected(replaceEntry(valid, BRIDGE, entry))
        for (entry in listOf(
            JsonObject(directory + ("bytes" to JsonPrimitive(0))),
            JsonObject(directory + ("sha256" to JsonPrimitive(EMPTY_SHA256))),
            JsonObject(directory + ("mode" to JsonPrimitive(420))),
            JsonObject(directory + ("mode" to JsonPrimitive(511))),
        )) assertRejected(replaceEntry(valid, "scripts", entry))
        assertRejected(replaceEntry(valid, "$RELEASE/empty-file", JsonObject(empty + ("sha256" to JsonPrimitive(SHA_A)))))
    }

    @Test
    fun `reference inventory requires unique ordered canonical paths and explicit directory parents`() {
        val valid = fixture()
        val original = entries(valid)
        assertRejected(withEntries(valid, original.reversed()))
        assertRejected(withEntries(valid, original + original.last()))
        assertRejected(withEntries(valid, original.filterNot { it.getValue("path").jsonPrimitive.content == "scripts" }))
        assertRejected(replaceEntry(valid, "scripts", file("scripts", 1, SHA_A)))
        val invalidPaths = listOf(
            "", " ", ".", "..", "/absolute", "relative/../escape", "relative/./file", "relative//file", "relative/   /file",
            "trailing/", "back\\slash", "colon:path", "new\nline", "delete\u007f", "a".repeat(256),
            List(33) { "part" }.joinToString("/"), List(18) { "가".repeat(80) }.joinToString("/"),
        )
        for (path in invalidPaths) {
            assertRejected(withEntries(valid, (original + file(path, 1, SHA_A)).sortedBy { it.getValue("path").jsonPrimitive.content }))
        }
    }

    @Test
    fun `reference classpath is exactly bridge then every sorted release lib jar`() {
        val valid = fixture()
        val paths = listOf(BRIDGE, LIBRARY_FIRST, LIBRARY_LAST)
        val invalid = listOf(
            emptyList(), paths.take(1), paths.drop(1), paths.reversed(), paths + paths.last(),
            listOf(BRIDGE, LIBRARY_LAST, LIBRARY_FIRST), listOf(BRIDGE, LIBRARY_FIRST),
            paths + "$RELEASE/other.jar", paths + "$RELEASE/Framework/missing/lib/library.jar",
            paths + "scripts/RunBundledExports.class", paths + "$RELEASE/empty-directory",
        )
        for (classPath in invalid) {
            assertRejected(JsonObject(valid + ("classPath" to JsonArray(classPath.map(::JsonPrimitive)))))
        }
        assertRejected(JsonObject(valid + ("classPath" to JsonArray(listOf(JsonPrimitive(BRIDGE), JsonPrimitive(1))))))
        assertRejected(JsonObject(valid + ("classPath" to JsonObject(emptyMap()))))
        val hiddenLibrary = "$RELEASE/Ghidra/Framework/Module/lib/hidden.jar"
        assertRejected(withEntries(valid, (entries(valid) + file(hiddenLibrary, 1, SHA_A)).sortedBy { it.getValue("path").jsonPrimitive.content }))
        assertRejected(JsonObject(valid + ("bridgePath" to JsonPrimitive("other.jar"))))
        assertRejected(JsonObject(valid + ("exportGuardPath" to JsonPrimitive("scripts/Other.class"))))
    }

    @Test
    fun `required bridge guard inventory and release directory must exist with correct kinds`() {
        val valid = fixture()
        for (path in listOf(BRIDGE, GUARD, "bundle.sha256", RELEASE)) {
            assertRejected(withEntries(valid, entries(valid).filterNot { it.getValue("path").jsonPrimitive.content == path }))
        }
        for (path in listOf(BRIDGE, GUARD, "bundle.sha256", LIBRARY_FIRST)) {
            assertRejected(replaceEntry(valid, path, directory(path)))
        }
        assertRejected(replaceEntry(valid, RELEASE, file(RELEASE, 1, SHA_A)))
        for (path in listOf(BRIDGE, GUARD, "bundle.sha256", LIBRARY_FIRST)) {
            assertRejected(replaceEntry(valid, path, file(path, 0, EMPTY_SHA256)))
        }
    }

    @Test
    fun `reference inventory count per-file aggregate and document bounds are enforced`() {
        val valid = fixture()
        val maximumEntry = replaceEntry(valid, "$RELEASE/other.jar", file("$RELEASE/other.jar", 128L * 1024 * 1024, SHA_A))
        assertEquals(128L * 1024 * 1024, GccBundledGhidraReference.parse(rehash(maximumEntry)).entries.getValue("$RELEASE/other.jar").bytes)
        val oversized = entries(valid) + List(16) { index -> file("aggregate-${index.toString().padStart(2, '0')}", 128L * 1024 * 1024, SHA_A) }
        assertRejected(withEntries(valid, oversized.sortedBy { it.getValue("path").jsonPrimitive.content }))
        val excessiveCount = entries(valid) + List(20_001 - entries(valid).size) { index ->
            file("count-${index.toString().padStart(5, '0')}", 0, EMPTY_SHA256)
        }
        assertEquals(20_000, GccBundledGhidraReference.parse(rehash(withEntries(
            valid, excessiveCount.dropLast(1).sortedBy { it.getValue("path").jsonPrimitive.content },
        ))).entries.size)
        assertRejected(withEntries(valid, excessiveCount.sortedBy { it.getValue("path").jsonPrimitive.content }))
        assertFailsWith<IllegalArgumentException> { GccBundledGhidraReference.parse(ByteArray(8 * 1024 * 1024 + 1)) }
    }

    @Test
    fun `candidate correspondence is relocatable but pins every referenced runtime identity`() {
        val reference = GccBundledGhidraReference.parse(canonical(fixture()))
        for (root in listOf(Path.of("/trusted/bundle"), Path.of("/relocated/application/libexec/ghidra"))) {
            val runtime = candidateRuntime(reference, root)
            reference.requireCandidate(runtime, candidateArtifacts(reference, runtime))
            val changed = GccBundledGhidraRuntime(root, runtime.classPath.mapIndexed { index, entry ->
                if (index == 1) entry.copy(sha256 = SHA_C) else entry
            })
            assertFailsWith<IllegalArgumentException> { reference.requireCandidate(changed, candidateArtifacts(reference, runtime)) }
            val changedBytes = GccBundledGhidraRuntime(root, runtime.classPath.mapIndexed { index, entry ->
                if (index == 1) entry.copy(bytes = entry.bytes + 1) else entry
            })
            assertFailsWith<IllegalArgumentException> { reference.requireCandidate(changedBytes, candidateArtifacts(reference, runtime)) }
            val missing = GccBundledGhidraRuntime(root, runtime.classPath.dropLast(1))
            assertFailsWith<IllegalArgumentException> { reference.requireCandidate(missing, candidateArtifacts(reference, runtime)) }
        }
    }

    @Test
    fun `candidate bound bridge guard manifest source and archive cannot be substituted`() {
        val reference = GccBundledGhidraReference.parse(canonical(fixture()))
        val runtime = candidateRuntime(reference)
        val artifacts = candidateArtifacts(reference, runtime)
        val roles = setOf(
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST,
            GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,
            GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE,
        )
        for (role in roles) {
            for (replace in listOf<(GccCompilerEngineContainmentArtifactIdentity) -> GccCompilerEngineContainmentArtifactIdentity>(
                { it.copy(bytes = it.bytes + 1) }, { it.copy(sha256 = "0".repeat(64)) },
            )) {
                val changed = artifacts.map { if (it.role == role) replace(it) else it }
                assertFailsWith<IllegalArgumentException>(role.wireName) { reference.requireCandidate(runtime, changed) }
            }
        }
        for (role in roles - setOf(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)) {
            val changed = artifacts.map {
                if (it.role == role) {
                    it.copy(path = if (role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE) {
                        Path.of("/trusted/scripts/Other.java")
                    } else Path.of("/unbound/${it.path.fileName}"))
                } else it
            }
            assertFailsWith<IllegalArgumentException>(role.wireName) { reference.requireCandidate(runtime, changed) }
        }
        reference.requireCandidate(runtime, artifacts.map {
            if (it.role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE) {
                it.copy(path = Path.of("/relocated-source/ExportProgramModel.java"))
            } else it
        })
        assertFailsWith<IllegalArgumentException> { reference.requireCandidate(runtime, artifacts.dropLast(1)) }
        assertFailsWith<IllegalArgumentException> { reference.requireCandidate(runtime, artifacts + artifacts.first()) }
        val legacy = artifacts + artifacts.first().copy(
            role = GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS, path = Path.of("/trusted/analyzeHeadless"),
        )
        assertFailsWith<IllegalArgumentException> { reference.requireCandidate(runtime, legacy) }
    }

    private fun runInstalledProbe(mode: String): String {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed deployment reference probe is opt-in")
        val installed = Path.of("build/install/llm_bin_patch").toAbsolutePath().normalize()
        val jars = Files.list(installed.resolve("lib")).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.fileName.toString().endsWith(".jar") }.sorted().toList()
        }
        val application = jars.single { path ->
            JarFile(path.toFile(), false).use { it.getJarEntry("decompengine/oracle/gcc/GccBundledGhidraDeploymentReference.class") != null }
        }
        val tests = Path.of(GccBundledGhidraInstalledReferenceProbe::class.java.protectionDomain.codeSource.location.toURI())
        assertTrue(Files.isDirectory(tests))
        val temporary = Files.createTempDirectory("gcc-installed-reference-probe-")
        try {
            val shadow = temporary.resolve("shadow")
            val exporter = shadow.resolve("ghidra_scripts/ExportProgramModel.java")
            Files.createDirectories(exporter.parent)
            Files.writeString(exporter, GccBundledGhidraInstalledReferenceProbe.SHADOW_EXPORTER)
            val command = listOf(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Djava.io.tmpdir=$temporary",
                "-Ddecompengine.oracle.nativeLibraryDirectory=${installed.resolve("libexec/oracle-native")}",
                "-cp", (listOf(tests, shadow) + jars).joinToString(File.pathSeparator),
                GccBundledGhidraInstalledReferenceProbe::class.java.name,
                application.toString(), installed.resolve("libexec/ghidra").toString(), mode,
            )
            val process = ProcessBuilder(command).directory(temporary.toFile()).redirectErrorStream(true).apply {
                for (name in listOf("JAVA_TOOL_OPTIONS", "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "GHIDRA_HOME")) {
                    environment().remove(name)
                }
            }.start()
            val reader = Executors.newSingleThreadExecutor()
            val output = reader.submit<ByteArray> {
                process.inputStream.use { it.readNBytes(16 * 1024 + 1) }.also {
                    if (it.size > 16 * 1024) process.destroyForcibly()
                }
            }
            try {
                assertTrue(process.waitFor(30, TimeUnit.SECONDS), "installed deployment reference probe timed out")
                val captured = output.get(5, TimeUnit.SECONDS)
                assertTrue(captured.size <= 16 * 1024, "installed deployment reference probe output exceeded its bound")
                val text = captured.toString(Charsets.UTF_8).trim()
                assertEquals(0, process.exitValue(), text)
                return text
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS), "installed deployment reference probe did not terminate")
                }
                output.cancel(true)
                reader.shutdownNow()
                assertTrue(reader.awaitTermination(5, TimeUnit.SECONDS), "installed deployment reference output reader did not terminate")
            }
        } finally {
            Files.walk(temporary).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun fixture(): JsonObject {
        val files = listOf(
            file(BRIDGE, 32, SHA_A), file(GUARD, 64, SHA_B), file("bundle.sha256", 96, SHA_C),
            file(LIBRARY_FIRST, 128, SHA_A), file(LIBRARY_LAST, 256, SHA_B),
            file("$RELEASE/Ghidra/Framework/Module/lib/README", 12, SHA_C),
            file("$RELEASE/other.jar", 24, SHA_B), file("$RELEASE/empty-file", 0, EMPTY_SHA256),
            file("$RELEASE/support/launch", 16, SHA_A, mode = 493),
        )
        val directories = linkedSetOf("$RELEASE/empty-directory")
        for (entry in files) {
            val components = entry.getValue("path").jsonPrimitive.content.split('/')
            for (size in 1 until components.size) directories += components.take(size).joinToString("/")
        }
        val entries = (directories.map(::directory) + files).sortedBy { it.getValue("path").jsonPrimitive.content }
        val unsigned = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("gcc-bundled-ghidra-deployment-reference-v1"),
            "ghidraVersion" to JsonPrimitive("12.1.3"),
            "ghidraRelease" to JsonPrimitive("PUBLIC"),
            "archive" to JsonObject(mapOf("bytes" to JsonPrimitive(ARCHIVE_BYTES), "sha256" to JsonPrimitive(BundledGhidra.ARCHIVE_SHA256))),
            "rootMode" to JsonPrimitive(493),
            "entries" to JsonArray(entries),
            "classPath" to JsonArray(listOf(BRIDGE, LIBRARY_FIRST, LIBRARY_LAST).map(::JsonPrimitive)),
            "bridgePath" to JsonPrimitive(BRIDGE),
            "exportGuardPath" to JsonPrimitive(GUARD),
            "exporter" to JsonObject(mapOf(
                "resourcePath" to JsonPrimitive("/ghidra_scripts/ExportProgramModel.java"),
                "bytes" to JsonPrimitive(EXPORTER_BYTES), "sha256" to JsonPrimitive(SHA_C),
            )),
        ))
        return OracleJson.parseCanonical(rehash(unsigned), TEST_JSON_LIMITS).jsonObject
    }

    private fun file(path: String, bytes: Long, sha256: String, mode: Int = 420): JsonObject = JsonObject(mapOf(
        "path" to JsonPrimitive(path), "kind" to JsonPrimitive("file"), "mode" to JsonPrimitive(mode),
        "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256),
    ))

    private fun directory(path: String): JsonObject = JsonObject(mapOf(
        "path" to JsonPrimitive(path), "kind" to JsonPrimitive("directory"), "mode" to JsonPrimitive(493),
    ))

    private fun entries(document: JsonObject): List<JsonObject> = document.getValue("entries").jsonArray.map { it.jsonObject }

    private fun withEntries(document: JsonObject, entries: List<JsonObject>): JsonObject = JsonObject(document + ("entries" to JsonArray(entries)))

    private fun replaceEntry(document: JsonObject, path: String, replacement: JsonObject): JsonObject = withEntries(
        document, entries(document).map { if (it.getValue("path").jsonPrimitive.content == path) replacement else it },
    )

    private fun assertRejected(document: JsonObject) {
        assertFailsWith<IllegalArgumentException> { GccBundledGhidraReference.parse(rehash(document)) }
    }

    private fun rehash(document: JsonObject): ByteArray {
        val unsigned = JsonObject(document - "closureSha256")
        return canonical(JsonObject(unsigned + ("closureSha256" to JsonPrimitive(OracleArtifacts.sha256(canonical(unsigned))))))
    }

    private fun canonical(document: JsonElement): ByteArray = OracleJson.canonicalBytes(document, TEST_JSON_LIMITS)

    private fun candidateRuntime(
        reference: GccBundledGhidraReference,
        root: Path = Path.of("/trusted/bundle"),
    ): GccBundledGhidraRuntime = GccBundledGhidraRuntime(root, reference.classPath.map { path ->
        val entry = reference.entries.getValue(path)
        GccBundledGhidraClassPathEntry(root.resolve(path), assertNotNull(entry.bytes), assertNotNull(entry.sha256))
    })

    private fun candidateArtifacts(
        reference: GccBundledGhidraReference,
        runtime: GccBundledGhidraRuntime,
    ): List<GccCompilerEngineContainmentArtifactIdentity> = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.mapIndexed { index, role ->
        val relative = when (role) {
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> BRIDGE
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> GUARD
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> "bundle.sha256"
            else -> null
        }
        val entry = relative?.let(reference.entries::getValue)
        GccCompilerEngineContainmentArtifactIdentity(
            role,
            when {
                relative != null -> runtime.root.resolve(relative)
                role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/trusted/scripts/ExportProgramModel.java")
                else -> Path.of("/trusted/${role.wireName}")
            },
            when {
                entry != null -> assertNotNull(entry.bytes)
                role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> reference.exporterBytes
                role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> ARCHIVE_BYTES
                else -> index + 1L
            },
            when {
                entry != null -> assertNotNull(entry.sha256)
                role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> reference.exporterSha256
                role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> BundledGhidra.ARCHIVE_SHA256
                else -> (index + 1).toString(16).padStart(2, '0').repeat(32)
            },
        )
    }

    private companion object {
        const val RELEASE = "ghidra_12.1.3_PUBLIC"
        const val BRIDGE = "decomp-ghidra-bridge.jar"
        const val GUARD = "scripts/RunBundledExports.class"
        const val LIBRARY_FIRST = "$RELEASE/Ghidra/Framework/Module/lib/first.jar"
        const val LIBRARY_LAST = "$RELEASE/Ghidra/Framework/Module/lib/last.jar"
        const val ARCHIVE_BYTES = 569_445_154L
        const val EXPORTER_BYTES = 32L
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        const val SHA_C = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
        const val EMPTY_SHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        val TEST_JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = 16 * 1024 * 1024,
            maximumCanonicalBytes = 16 * 1024 * 1024,
            maximumNodes = 250_000,
            maximumTotalStringBytes = 12 * 1024 * 1024,
        )
    }
}

object GccBundledGhidraInstalledReferenceProbe {
    const val SHADOW_EXPORTER = "test-only shadow exporter must not authenticate"

    @JvmStatic
    fun main(arguments: Array<String>) {
        check(arguments.size == 3)
        val expectedApplication = Path.of(arguments[0]).toRealPath()
        val expectedRoot = Path.of(arguments[1]).toRealPath()
        val mode = arguments[2]
        val actualApplication = Path.of(
            GccBundledGhidraDeploymentReference::class.java.protectionDomain.codeSource.location.toURI(),
        ).toRealPath()
        check(actualApplication == expectedApplication && Files.isRegularFile(actualApplication)) {
            "probe did not load its controller from the exact installed application JAR"
        }
        val shadow = checkNotNull(GccBundledGhidraDeploymentReference::class.java.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
            .use { it.readNBytes(1024).toString(Charsets.UTF_8) }
        check(shadow == SHADOW_EXPORTER) { "probe exporter resource was not actually shadowed" }
        if (mode == "open") {
            GccBundledGhidraDeploymentReference.open().use { deployment ->
                check(deployment.bundleRoot == expectedRoot)
                deployment.verify("from the installed child JVM")
                println("installed-reference-opened:${deployment.reference.closureSha256}")
            }
            return
        }
        check(mode in setOf("reference-override", "root-override", "paired-overrides"))
        if (mode != "root-override") {
            System.setProperty("decompengine.oracle.gcc.bundledGhidraReference", "/nonexistent/forbidden-reference.json")
        }
        if (mode != "reference-override") {
            System.setProperty("decompengine.oracle.gcc.bundledGhidraRoot", "/nonexistent/forbidden-root")
        }
        try {
            GccBundledGhidraDeploymentReference.open().use { error("installed reference accepted a development override") }
        } catch (failure: IllegalArgumentException) {
            check(failure.message.orEmpty().contains("overrides require paired Gradle class-directory configuration"))
        }
        println("installed-overrides-rejected:$mode")
    }
}
