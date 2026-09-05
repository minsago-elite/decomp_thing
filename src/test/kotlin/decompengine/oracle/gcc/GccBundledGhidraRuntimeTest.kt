package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraWorkerCommand
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledGhidraRuntimeTest {
    @Test
    fun `bundled worker command uses exact shared JVM prefix and planning exporter arguments`() {
        val runtime = runtime()
        val artifacts = artifacts(runtime)
        val byRole = artifacts.associateBy { it.role }
        val command = runtime.command(artifacts, state(), lease())
        val expectedPrefix = GhidraWorkerCommand.prefix(
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE).path,
            runtime.release,
            runtime.classPath.map { it.path },
        )
        assertEquals(
            expectedPrefix + listOf(
                "analyze", "/scratch/run/state", "archival_reconstruction", "/trusted/engine-binary",
                "/trusted/scripts", "ExportProgramModel.java", "4",
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE).sha256,
                BundledGhidra.ARCHIVE_SHA256, "planning", "/scratch/run/reports/program_model.json",
            ),
            command,
        )
        assertEquals("-Xshare:off", command[2])
        assertTrue(command.contains("-Djava.system.class.loader=ghidra.GhidraClassLoader"))
        assertFalse(command.any { it.contains("analyzeHeadless") || it.contains("GHIDRA_HOME") })
        assertEquals(command, request(runtime, artifacts).command)
    }

    @Test
    fun `bundled runtime snapshots ordered classpath and exposes no mutable list`() {
        val entries = classPath().toMutableList()
        val runtime = GccBundledGhidraRuntime(ROOT, entries)
        val expected = runtime.toJson()
        entries.clear()
        assertEquals(3, runtime.classPath.size)
        assertEquals(expected, GccBundledGhidraRuntime.parse(expected).toJson())
        assertFailsWith<UnsupportedOperationException> {
            (runtime.classPath as MutableList<GccBundledGhidraClassPathEntry>).clear()
        }
    }

    @Test
    fun `bundled classpath requires bridge first and unique sorted release library jars`() {
        val valid = classPath()
        val invalid = listOf(
            emptyList(), valid.take(1), valid.reversed(), valid + valid.last(),
            listOf(valid.first(), valid.last(), valid[1]),
            valid.toMutableList().also { it[0] = it[0].copy(path = ROOT.resolve("other-bridge.jar")) },
            valid.toMutableList().also { it[1] = it[1].copy(path = Path.of("/outside/lib/library.jar")) },
            valid.toMutableList().also { it[1] = it[1].copy(path = RELEASE.resolve("Ghidra/Framework/Module/not-lib/library.jar")) },
            valid.toMutableList().also { it[1] = it[1].copy(path = RELEASE.resolve("Ghidra/Framework/Module/lib/library.class")) },
            valid.toMutableList().also { it[1] = it[1].copy(path = ROOT.resolve("ghidra_old_PUBLIC/Ghidra/Module/lib/library.jar")) },
        )
        for (entries in invalid) {
            assertFailsWith<IllegalArgumentException>(entries.toString()) { GccBundledGhidraRuntime(ROOT, entries) }
        }
    }

    @Test
    fun `bundled identities enforce path byte digest count and aggregate limits`() {
        val paths = listOf(
            Path.of("relative.jar"), Path.of("/"), Path.of("/trusted/../library.jar"),
            Path.of("/trusted/colon:library.jar"), Path.of("/trusted/back\\slash.jar"),
            Path.of("/trusted/new\nline.jar"), Path.of("/trusted/delete\u007f.jar"),
            Path.of("/" + List(33) { "part" }.joinToString("/")), Path.of("/" + "a".repeat(4096)),
        )
        for (path in paths) {
            assertFailsWith<IllegalArgumentException> { GccBundledGhidraClassPathEntry(path, 1, SHA_A) }
            assertFailsWith<IllegalArgumentException> { GccBundledGhidraRuntime(path, classPath()) }
        }
        for (size in listOf(-1L, 0L, 128L * 1024 * 1024 + 1, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { classPath().first().copy(bytes = size) }
        }
        for (digest in listOf("", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { classPath().first().copy(sha256 = digest) }
        }
        val maximumEntries = classPath(libraryCount = 511)
        assertEquals(512, GccBundledGhidraRuntime(ROOT, maximumEntries).classPath.size)
        assertFailsWith<IllegalArgumentException> { GccBundledGhidraRuntime(ROOT, classPath(libraryCount = 512)) }
        val maximumAggregate = classPath(libraryCount = 15).map { it.copy(bytes = 128L * 1024 * 1024) }
        assertEquals(2L * 1024 * 1024 * 1024, GccBundledGhidraRuntime(ROOT, maximumAggregate).classPath.sumOf { it.bytes })
        assertFailsWith<IllegalArgumentException> {
            GccBundledGhidraRuntime(ROOT, maximumAggregate + classPath(libraryCount = 16).last())
        }
    }

    @Test
    fun `bundled runtime JSON rejects open fields incorrect provider and coercible entry values`() {
        val valid = runtime().toJson()
        val entries = valid.getValue("classPath").jsonArray
        val invalid = listOf(
            JsonObject(valid + ("extra" to JsonPrimitive(true))),
            JsonObject(valid - "provider"),
            JsonObject(valid + ("provider" to JsonPrimitive("other-runtime"))),
            JsonObject(valid + ("root" to JsonPrimitive(1))),
            JsonObject(valid + ("classPath" to JsonObject(emptyMap()))),
            JsonObject(valid + ("classPath" to JsonArray(listOf(JsonNull, entries[1])))),
        ) + listOf(
            JsonObject(entries[0].jsonObject + ("extra" to JsonPrimitive(true))),
            JsonObject(entries[0].jsonObject - "sha256"),
            JsonObject(entries[0].jsonObject + ("bytes" to JsonPrimitive("1"))),
            JsonObject(entries[0].jsonObject + ("bytes" to JsonPrimitive(1.5))),
            JsonObject(entries[0].jsonObject + ("bytes" to JsonPrimitive(true))),
            JsonObject(entries[0].jsonObject + ("sha256" to JsonPrimitive(123))),
            JsonObject(entries[0].jsonObject + ("path" to JsonNull)),
        ).map { entry -> JsonObject(valid + ("classPath" to JsonArray(listOf(entry) + entries.drop(1)))) }
        for (document in invalid) {
            assertFailsWith<IllegalArgumentException>(document.toString()) { GccBundledGhidraRuntime.parse(document) }
        }
    }

    @Test
    fun `bundled definition rejects legacy missing duplicate and overlapping artifact roles`() {
        val runtime = runtime()
        val valid = artifacts(runtime)
        val bridge = valid.single { it.role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR }
        val variants = listOf(
            valid.dropLast(1), valid + bridge,
            valid + bridge.copy(role = GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS, path = Path.of("/trusted/legacy")),
            valid.map { if (it.role == bridge.role) it.copy(role = GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE) else it },
            valid.map { if (it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) it.copy(path = bridge.path) else it },
            valid.map { if (it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) it.copy(path = ROOT.resolve("engine")) else it },
            valid.map { if (it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) it.copy(path = Path.of("/scratch/run/engine")) else it },
        )
        val command = runtime.command(valid, state(), lease())
        for (candidate in variants) {
            assertFailsWith<IllegalArgumentException> { request(runtime, candidate, command) }
        }
        assertFailsWith<IllegalArgumentException> { request(null, valid, command) }
    }

    @Test
    fun `bundled command rejects mismatched bridge inventory guard archive and exporter source`() {
        val runtime = runtime()
        val valid = artifacts(runtime)
        val mutations = listOf<Pair<GccCompilerEngineContainmentArtifactRole, (GccCompilerEngineContainmentArtifactIdentity) -> GccCompilerEngineContainmentArtifactIdentity>>(
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR to { it.copy(sha256 = SHA_B) },
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR to { it.copy(bytes = it.bytes + 1) },
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR to { it.copy(path = ROOT.resolve("another.jar")) },
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST to { it.copy(path = Path.of("/trusted/foreign/bundle.sha256")) },
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD to { it.copy(path = ROOT.resolve("scripts/Other.class")) },
            GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE to { it.copy(sha256 = SHA_B) },
            GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE to { it.copy(path = Path.of("/trusted/scripts/Other.java")) },
        )
        for ((role, mutate) in mutations) {
            val changed = valid.map { if (it.role == role) mutate(it) else it }
            assertFailsWith<IllegalArgumentException>(role.wireName) { runtime.command(changed, state(), lease()) }
        }
    }

    @Test
    fun `bundled runtime and classpath cannot cross writable output root`() {
        for (root in listOf(Path.of("/scratch"), Path.of("/scratch/run"), Path.of("/scratch/run/bundle"))) {
            val runtime = runtime(root)
            assertFailsWith<IllegalArgumentException> { request(runtime) }
        }
        val entries = classPath().toMutableList()
        entries[1] = entries[1].copy(path = Path.of("/scratch/run/lib/library.jar"))
        assertFailsWith<IllegalArgumentException> { GccBundledGhidraRuntime(ROOT, entries) }
    }

    @Test
    fun `bundled import worker cannot claim authenticated resume semantics`() {
        val runtime = runtime()
        val resumed = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST, Path.of("/scratch/run/state"), SHA_A, 1, 1,
        )
        assertFailsWith<IllegalArgumentException> { runtime.command(artifacts(runtime), resumed, lease()) }
        val valid = request(runtime)
        assertFailsWith<IllegalArgumentException> {
            GccCompilerEngineContainmentRequest(
                engineId = valid.engineId,
                runKind = GccCompilerEngineContainmentRunKind.RESUMED,
                artifacts = valid.artifacts,
                analysisState = resumed,
                command = valid.command,
                environment = valid.environment,
                outputLease = valid.outputLease,
                budgets = valid.budgets,
                bundledRuntime = runtime,
            )
        }
    }

    @Test
    fun `exact invocation refuses JVM agent classpath script output and locale injection`() {
        val runtime = runtime()
        val artifacts = artifacts(runtime)
        val valid = runtime.command(artifacts, state(), lease())
        val mutations = listOf(
            listOf("/unbound/java") + valid.drop(1),
            valid.take(1) + "-javaagent:/unbound/agent.jar" + valid.drop(1),
            valid + listOf("-postScript", "Other.java"),
            valid.map { if (it == "-Xmx2G") "-Xmx32G" else it },
            valid.map { if (it == "planning") "observation" else it },
            valid.map { if (it == "ExportProgramModel.java") "Other.java" else it },
            valid.map { if (it == "4") "5" else it },
            valid.map { if (it == "/scratch/run/reports/program_model.json") "/scratch/run/other.json" else it },
            valid.toMutableList().also { it[it.indexOf("-cp") + 1] += ":/unbound/extra.jar" },
        )
        for (command in mutations) {
            assertFailsWith<IllegalArgumentException>(command.toString()) { request(runtime, artifacts, command) }
        }
        assertFailsWith<IllegalArgumentException> {
            request(runtime, environment = ENVIRONMENT + ("JAVA_TOOL_OPTIONS" to "-javaagent:/unbound/agent.jar"))
        }
        assertFailsWith<IllegalArgumentException> { request(runtime, environment = ENVIRONMENT + ("LANG" to "en_US.UTF-8")) }
    }

    @Test
    fun `bundled definition admits actual scale classpath beyond legacy argument bound`() {
        val root = Path.of("/application/distributions/installed-decompengine/runtime/bundled-ghidra")
        val runtime = GccBundledGhidraRuntime(root, classPath(root, libraryCount = 153))
        val request = request(runtime)
        val classPathArgument = request.command[request.command.indexOf("-cp") + 1]
        assertTrue(classPathArgument.length > 16_384)
        assertTrue(classPathArgument.length < 65_536)
        val definition = GccCompilerEngineContainmentContract.assessDefinition(request)
        val parsed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition.canonicalBytes)
        assertEquals(154, assertNotNull(parsed.bundledRuntime).classPath.size)
        assertEquals(request.command, parsed.command)
        val excessiveRoot = Path.of("/application/" + "directory".repeat(40))
        val excessive = GccBundledGhidraRuntime(excessiveRoot, classPath(excessiveRoot, libraryCount = 153))
        assertFailsWith<IllegalArgumentException> { request(excessive) }
    }

    @Test
    fun `v2 canonical definition binds runtime inventory without granting execution or release`() {
        val runtime = runtime()
        val request = request(runtime)
        val assessment = GccCompilerEngineContainmentContract.assessDefinition(request)
        val canonical = assessment.canonicalBytes
        val document = OracleJson.parseCanonical(canonical).jsonObject
        assertEquals("2", document.getValue("schemaVersion").jsonPrimitive.content)
        assertEquals("gcc-compiler-engine-containment-definition-v2", document.getValue("provider").jsonPrimitive.content)
        assertEquals(runtime.toJson(), document.getValue("request").jsonObject.getValue("bundledRuntime"))
        assertFalse(assessment.startAuthorized)
        assertFalse(assessment.releaseEligible)
        val parsed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(canonical)
        canonical[0] = '!'.code.toByte()
        assertContentEquals(assessment.canonicalBytes, parsed.canonicalBytes)
        assertEquals(request.command, parsed.command)
        assertEquals(runtime.toJson(), assertNotNull(parsed.bundledRuntime).toJson())
        val changedRuntime = GccBundledGhidraRuntime(ROOT, classPath().mapIndexed { index, entry ->
            if (index == 1) entry.copy(sha256 = SHA_B) else entry
        })
        val changed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
            GccCompilerEngineContainmentContract.assessDefinition(request(changedRuntime)).canonicalBytes,
        )
        assertEquals(parsed.command, changed.command)
        assertNotEquals(parsed.runtimeSha256, changed.runtimeSha256)
        assertNotEquals(parsed.requestSha256, changed.requestSha256)
        assertNotEquals(parsed.bindingSha256, changed.bindingSha256)
        assertEquals(parsed.inputSetSha256, changed.inputSetSha256)
    }

    @Test
    fun `raw v2 reparse refuses version confusion open records and stale runtime digests`() {
        val document = definition()
        val request = document.getValue("request").jsonObject
        val bundled = request.getValue("bundledRuntime").jsonObject
        val entries = bundled.getValue("classPath").jsonArray
        val changedEntries = entries.toMutableList().also {
            it[1] = JsonObject(it[1].jsonObject + ("sha256" to JsonPrimitive(SHA_B)))
        }
        val invalid = listOf(
            JsonObject(document + ("schemaVersion" to JsonPrimitive(1))),
            JsonObject(document + ("schemaVersion" to JsonPrimitive(3))),
            JsonObject(document + ("provider" to JsonPrimitive("gcc-compiler-engine-containment-definition-v1"))),
            JsonObject(document + ("request" to JsonObject(request - "bundledRuntime"))),
            JsonObject(document + ("request" to JsonObject(request + ("extra" to JsonPrimitive(true))))),
            withRuntime(document, JsonObject(bundled + ("extra" to JsonPrimitive(true)))),
            withRuntime(document, JsonObject(bundled + ("classPath" to JsonArray(changedEntries)))),
        )
        for (candidate in invalid) {
            assertFailsWith<IllegalArgumentException> {
                GccCompilerEngineContainmentContract.parseDefinitionForLiveController(OracleJson.canonicalBytes(candidate))
            }
        }
        val noncanonical = OracleJson.canonicalBytes(document) + " ".encodeToByteArray()
        assertFailsWith<IllegalArgumentException> {
            GccCompilerEngineContainmentContract.parseDefinitionForLiveController(noncanonical)
        }
    }

    @Test
    fun `rehashing every digest cannot legalize contradictory bridge command or authority claims`() {
        val document = definition()
        val request = document.getValue("request").jsonObject
        val artifacts = request.getValue("artifacts").jsonArray
        val changedArtifacts = artifacts.map { artifact ->
            val value = artifact.jsonObject
            if (value.getValue("role").jsonPrimitive.content == "ghidra-bridge-jar") {
                JsonObject(value + ("sha256" to JsonPrimitive(SHA_B)))
            } else value
        }
        val command = request.getValue("command").jsonObject
        val argv = command.getValue("argv").jsonArray
        val invalid = listOf(
            JsonObject(document + ("request" to JsonObject(request + ("artifacts" to JsonArray(changedArtifacts))))),
            JsonObject(document + ("request" to JsonObject(request + ("command" to JsonObject(
                command + ("argv" to JsonArray(argv + JsonPrimitive("-javaagent:/unbound/agent.jar"))),
            ))))),
            JsonObject(document + ("startAuthorized" to JsonPrimitive(true))),
            JsonObject(document + ("releaseEligible" to JsonPrimitive(true))),
            withRuntime(document, JsonObject(request.getValue("bundledRuntime").jsonObject + ("root" to JsonPrimitive("/trusted//bundle")))),
        )
        for (candidate in invalid) {
            assertFailsWith<IllegalArgumentException> {
                GccCompilerEngineContainmentContract.parseDefinitionForLiveController(rehashDefinition(candidate))
            }
        }
        assertContentEquals(OracleJson.canonicalBytes(document), rehashDefinition(document))
    }

    @Test
    fun `raw controller rejects an unreferenced v2 runtime before opening artifacts or publishing BOOT state`() {
        val directory = Files.createTempDirectory("gcc-bundled-definition-")
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        val definitionPath = directory.resolve("definition.json")
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val bytes = GccCompilerEngineContainmentContract.assessDefinition(
            request(outputLease = lease().copy(uid = uid, gid = uid)),
        ).canonicalBytes
        try {
            Files.write(definitionPath, bytes)
            Files.setPosixFilePermissions(definitionPath, PosixFilePermissions.fromString("r--------"))
            val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(definitionPath).use {
                    error("bundled runtime reached BOOT before retained authentication")
                }
            }
            assertTrue(failure.message.orEmpty().contains("independent deployment reference"), failure.message)
            assertContentEquals(bytes, Files.readAllBytes(definitionPath))
            assertEquals(listOf("definition.json"), Files.list(directory).use { paths -> paths.map { it.fileName.toString() }.toList() })
        } finally {
            Files.deleteIfExists(definitionPath)
            Files.delete(directory)
        }
    }

    private fun runtime(root: Path = ROOT): GccBundledGhidraRuntime = GccBundledGhidraRuntime(root, classPath(root))

    private fun classPath(root: Path = ROOT, libraryCount: Int = 2): List<GccBundledGhidraClassPathEntry> =
        listOf(GccBundledGhidraClassPathEntry(root.resolve("decomp-ghidra-bridge.jar"), 32, SHA_A)) +
            List(libraryCount) { index ->
                GccBundledGhidraClassPathEntry(
                    root.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Framework/Module/lib/library-${index.toString().padStart(3, '0')}.jar"),
                    64, SHA_A,
                )
            }

    private fun artifacts(runtime: GccBundledGhidraRuntime): List<GccCompilerEngineContainmentArtifactIdentity> =
        GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.mapIndexed { index, role ->
            val bridge = runtime.classPath.first()
            GccCompilerEngineContainmentArtifactIdentity(
                role,
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> bridge.path
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> runtime.root.resolve("bundle.sha256")
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> runtime.root.resolve("scripts/RunBundledExports.class")
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/trusted/scripts/ExportProgramModel.java")
                    else -> Path.of("/trusted/${role.wireName}")
                },
                if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR) bridge.bytes else index + 1L,
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> bridge.sha256
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> BundledGhidra.ARCHIVE_SHA256
                    else -> (index + 1).toString(16).padStart(2, '0').repeat(32)
                },
            )
        }

    private fun state() = GccCompilerEngineAnalysisStateIdentity(
        GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, Path.of("/scratch/run/state"), null, 0, 0,
    )

    private fun lease() = GccCompilerEngineOutputLeaseIdentity(
        Path.of("/scratch/run"), 1, 2, 3, 1000, 1000, 0x1c0, 1024, 2048, 128, 256,
    )

    private fun request(
        runtime: GccBundledGhidraRuntime? = runtime(),
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity> = artifacts(requireNotNull(runtime)),
        command: List<String> = requireNotNull(runtime).command(artifacts, state(), lease()),
        environment: Map<String, String> = ENVIRONMENT,
        outputLease: GccCompilerEngineOutputLeaseIdentity = lease(),
    ) = GccCompilerEngineContainmentRequest(
        engineId = "cc1",
        runKind = GccCompilerEngineContainmentRunKind.INTERRUPTED,
        artifacts = artifacts,
        analysisState = state(),
        command = command,
        environment = environment,
        outputLease = outputLease,
        budgets = GccCompilerEngineContainmentBudgets(1_800_000, 16L * 1024 * 1024 * 1024, 256),
        bundledRuntime = runtime,
    )

    private fun definition(): JsonObject = OracleJson.parseCanonical(
        GccCompilerEngineContainmentContract.assessDefinition(request()).canonicalBytes,
    ).jsonObject

    private fun withRuntime(document: JsonObject, runtime: JsonObject): JsonObject = JsonObject(
        document + ("request" to JsonObject(document.getValue("request").jsonObject + ("bundledRuntime" to runtime))),
    )

    private fun rehashDefinition(document: JsonObject): ByteArray {
        val original = document.getValue("request").jsonObject
        val command = original.getValue("command").jsonObject - "commandSha256"
        val lease = original.getValue("outputLease").jsonObject - "leaseSha256"
        val artifacts = original.getValue("artifacts").jsonArray
        val inputs = setOf("engine-binary", "benchmark-profile", "source-lock", "build-record", "oracle-manifest", "toolchain-reproduction")
        val request = JsonObject(original + mapOf(
            "command" to JsonObject(command + ("commandSha256" to JsonPrimitive(digest(JsonObject(command))))),
            "outputLease" to JsonObject(lease + ("leaseSha256" to JsonPrimitive(digest(JsonObject(lease))))),
            "runtimeSha256" to JsonPrimitive(digest(JsonObject(mapOf(
                "artifacts" to JsonArray(artifacts.filter { it.jsonObject.getValue("role").jsonPrimitive.content !in inputs }),
                "bundledRuntime" to original.getValue("bundledRuntime"),
            )))),
            "inputSetSha256" to JsonPrimitive(digest(JsonObject(mapOf(
                "analysisState" to original.getValue("analysisState"),
                "artifacts" to JsonArray(artifacts.filter { it.jsonObject.getValue("role").jsonPrimitive.content in inputs }),
            )))),
        ))
        val requestSha256 = digest(request)
        val unsigned = JsonObject(document - "bindingSha256" + mapOf(
            "request" to request,
            "requestSha256" to JsonPrimitive(requestSha256),
            "unitName" to JsonPrimitive("decomp-gcc-cc1-${requestSha256.take(32)}.scope"),
        ))
        return OracleJson.canonicalBytes(JsonObject(unsigned + ("bindingSha256" to JsonPrimitive(digest(unsigned)))))
    }

    private fun digest(value: JsonElement): String = OracleArtifacts.sha256(OracleJson.canonicalBytes(value))

    private companion object {
        val ROOT: Path = Path.of("/trusted/bundle")
        val RELEASE: Path = ROOT.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC")
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val SHA_B = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        val ENVIRONMENT = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC")
    }
}
