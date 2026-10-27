package decompengine.project

import io.github.optimumcode.json.schema.JsonSchema
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assumptions.assumeTrue

/** The authored inputs exercise real bundled APIs; they do not qualify retained cc1 or create oracle authority. */
class NativeCallCollectorRealTest {
    @Test
    fun `real ELF collector retains physical native controls beside unchanged model`() = withRealControl("static") { root ->
        val assembly = copyResource("control-calls.s", root)
        root.resolve("calls").also { binary ->
            run(root, listOf("cc", "-nostdlib", "-no-pie", "-Wl,--build-id=none", "-o", binary.toString(), assembly.toString()), "compile-elf", Duration.ofSeconds(30))
        }
    }

    @Test
    fun `real linked PLT and no PLT calls retain external and one hop pointer provenance`() {
        for (mode in listOf("plt", "no-plt")) withRealControl(mode) { root ->
            val source = copyResource("control-external.c", root)
            root.resolve("external").also { binary ->
                run(root, listOf("cc", "-O0", "-g", "-no-pie", if (mode == "no-plt") "-fno-plt" else "-fplt", "-Wl,--build-id=none", "-o", binary.toString(), source.toString()), "compile-elf", Duration.ofSeconds(30))
            }
        }
    }

    @Test
    fun `genuine delayed MIPS calls remain explicit unsupported boundaries`() = withRealControl("delayed") { root ->
        root.resolve("mips-input").also { Files.write(it, byteArrayOf(0x0c, 0, 4, 4, 0, 0, 0, 0)) }
    }

    @Test
    fun `real bundled iterator scans ordinary high reference sources and rejects late call overflow`() = withRealControl("reference-scan") { root ->
        val assembly = copyResource("control-calls.s", root)
        root.resolve("calls").also { binary ->
            run(root, listOf("cc", "-nostdlib", "-no-pie", "-Wl,--build-id=none", "-o", binary.toString(), assembly.toString()), "compile-elf", Duration.ofSeconds(30))
        }
    }

    private fun withRealControl(mode: String, prepareInput: (Path) -> Path) {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA_NATIVE_CALLS") == "true", "bundled native collector controls are opt-in")
        val repository = Path.of("").toAbsolutePath().normalize()
        val parent = repository.resolve("build/native-call-real-controls")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "$mode-")
        val temporary = Files.createDirectory(root.resolve("tmp"))
        val home = Files.createDirectory(root.resolve("home"))
        val bundleRoot = Path.of(checkNotNull(System.getProperty("decompengine.ghidra.bundle")) { "bundled Ghidra test path missing" })
        val release = bundleRoot.resolve("ghidra_12.1.3_PUBLIC")
        assertTrue(Files.isDirectory(release), "bundled Ghidra release missing: $release")
        val jars = Files.walk(release.resolve("Ghidra")).use { paths ->
            paths.filter { Files.isRegularFile(it) && it.parent.fileName.toString() == "lib" && it.fileName.toString().endsWith(".jar") }
                .sorted().toList()
        }
        assertTrue(jars.isNotEmpty(), "bundled Ghidra jars missing")
        val source = copyResource("NativeCallCollectorControls.java", root)
        val collector = repository.resolve("ghidra-bridge/src/main/java/ExportNativeCallsV1.java")
        val globalCollector = repository.resolve("ghidra-bridge/src/main/java/ExportGlobalTypeObservationsV1.java")
        val interfaceCollector = repository.resolve("ghidra-bridge/src/main/java/ExportNativeInterfacesV1.java")
        val inferredCollector = repository.resolve("ghidra-bridge/src/main/java/ExportInferredInterfacesV1.java")
        val typeGraph = repository.resolve("ghidra-bridge/src/main/java/NativeInterfaceTypeGraphV1.java")
        val exporter = repository.resolve("src/main/resources/ghidra_scripts/ExportProgramModel.java")
        val phaseRoute = repository.resolve("ghidra-bridge/src/main/java/BundledExportPhaseRoute.java")
        val dispatch = repository.resolve("ghidra-bridge/src/main/java/RunBundledExports.java")
        val worker = repository.resolve("ghidra-bridge/src/main/java/decompengine/ghidra/BundledGhidraWorker.java")
        assertTrue(Files.isRegularFile(collector), "current compiled collector source missing")
        val classes = Files.createDirectory(root.resolve("classes"))
        val classpath = jars.joinToString(System.getProperty("path.separator"))
        val javaBin = Path.of(System.getProperty("java.home"), "bin")
        val javaProperties = listOf("-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary", "-Duser.home=$home", "-Djava.awt.headless=true", "-XX:-UsePerfData")
        run(root, listOf(javaBin.resolve("javac").toString()) + javaProperties.map { "-J$it" } + listOf("-proc:none", "-cp", classpath, "-d", classes.toString(), source.toString(), collector.toString(), interfaceCollector.toString(), inferredCollector.toString(), globalCollector.toString(), typeGraph.toString(), exporter.toString(), phaseRoute.toString(), dispatch.toString(), worker.toString()), "compile-controls", Duration.ofSeconds(45))
        val input = prepareInput(root)
        run(root, listOf(javaBin.resolve("java").toString(), "-Xmx1g") + javaProperties + listOf("-cp", "$classes${System.getProperty("path.separator")}$classpath", "NativeCallCollectorControls", release.toString(), root.toString(), collector.toString(), exporter.toString(), mode, input.toString()), "native-control", Duration.ofSeconds(120))
        assertTrue(Files.readString(root.resolve("verified-controls.txt")).contains("model-unchanged"))
        assertTrue(Files.isRegularFile(root.resolve("first-native/manifest.json")))
        for ((file, schemaResource) in listOf(
            "native-calls.json" to "/project/native-call-observations-v1.schema.json",
            "manifest.json" to "/project/native-call-observation-manifest-v1.schema.json",
        )) {
            val definition = checkNotNull(javaClass.getResourceAsStream(schemaResource)) { "missing native observation schema $schemaResource" }
                .use { it.readBytes().decodeToString() }
            val actual = Json.parseToJsonElement(Files.readString(root.resolve("first-native/$file")))
            assertTrue(JsonSchema.fromDefinition(definition).validate(actual) {}, "actual collector output violates $schemaResource")
        }
        val native = Json.parseToJsonElement(Files.readString(root.resolve("native-properties.json"))) as JsonObject
        val model = root.resolve("reports/program_model.json")
        val observed = mutableListOf<NativeCallRecordV1>()
        val receipt = NativeCallObservationsV1.validateBoundToSpaces(
            Files.readAllBytes(root.resolve("first-native/manifest.json")),
            expectedBindings = { spaces ->
                val imageSpace = spaces.single { it.name == native.getValue("imageBaseSpace").jsonPrimitive.content }
                NativeCallBindingsV1(
                    collectorSha256 = sha256(collector),
                    compilerSpecId = native.getValue("compilerSpecId").jsonPrimitive.content,
                    ghidraArchiveSha256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",
                    imageBase = NativeCallAddressV1(imageSpace.index, native.getValue("imageBaseOffsetBits").jsonPrimitive.content),
                    inputSha256 = sha256(input),
                    languageId = native.getValue("languageId").jsonPrimitive.content,
                    programModelBytes = Files.size(model),
                    programModelExporterSha256 = sha256(exporter),
                    programModelSha256 = sha256(model),
                )
            },
            checkpoint = {},
            openObservations = { Files.newInputStream(root.resolve("first-native/native-calls.json")) },
            consume = observed::add,
        )
        assertEquals(native.getValue("functions").jsonPrimitive.long, receipt.scanSummary.functions)
        assertEquals(native.getValue("instructionsVisited").jsonPrimitive.long, receipt.scanSummary.instructionsVisited)
        assertTrue(observed.filterIsInstance<NativeCallSiteRecordV1>().isNotEmpty())
        assertFalse(receipt.authoritativeOracleEvidence)
        assertFalse(receipt.recoveredModelScored)
        assertFalse(receipt.releaseEligible)
        if (mode == "reference-scan") {
            val controls = Json.parseToJsonElement(Files.readString(root.resolve("reference-scan-controls.json"))) as JsonObject
            assertEquals(1720L, controls.getValue("ordinaryReferenceCount").jsonPrimitive.long)
            assertEquals(65L, controls.getValue("jumpReferenceCount").jsonPrimitive.long)
            for (field in listOf("completeScan", "sameCountMutationRejected", "midScanCancellationRejected"))
                assertTrue(controls.getValue(field).jsonPrimitive.boolean)
            val failure = controls.getValue("lateCallOverflowDiagnostic").jsonPrimitive.content
            assertTrue(failure.contains("count=66") && failure.contains("limit=64") && failure.contains("offsetBits="))
            val sites = observed.filterIsInstance<NativeCallSiteRecordV1>()
            assertEquals(sites.sumOf { it.references.size.toLong() }, receipt.scanSummary.directReferences)
            assertEquals(sites.sumOf { site -> site.referenceNeighborhoods.sumOf { it.references.size.toLong() } }, receipt.scanSummary.neighborhoodReferences)
        }
    }

    private fun copyResource(name: String, root: Path): Path = root.resolve(name).also { path ->
        checkNotNull(javaClass.getResourceAsStream("/nativecalls/$name")) { "missing native control resource $name" }
            .use { Files.copy(it, path) }
    }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { stream ->
            val buffer = ByteArray(65536)
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                digest.update(buffer, 0, read)
            }
        }
        return java.util.HexFormat.of().formatHex(digest.digest())
    }

    private fun run(root: Path, arguments: List<String>, name: String, deadline: Duration) {
        val log = root.resolve("$name.log")
        val temporary = root.resolve("tmp")
        val home = root.resolve("home")
        val process = ProcessBuilder(arguments).directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).also {
            it.environment().remove("JAVA_TOOL_OPTIONS")
            it.environment().remove("JDK_JAVA_OPTIONS")
            it.environment().remove("_JAVA_OPTIONS")
            it.environment()["TMPDIR"] = temporary.toString()
            it.environment()["XDG_CACHE_HOME"] = home.resolve("cache").toString()
            it.environment()["XDG_CONFIG_HOME"] = home.resolve("config").toString()
        }.start()
        try {
            assertTrue(process.waitFor(deadline.toMillis(), TimeUnit.MILLISECONDS), "$name timed out; log at $log")
            assertEquals(0, process.exitValue(), Files.readString(log))
        } finally {
            if (process.isAlive) {
                process.descendants().forEach { it.destroyForcibly() }
                process.destroyForcibly()
                process.waitFor(10, TimeUnit.SECONDS)
            }
        }
    }
}
