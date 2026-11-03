package decompengine.project

import io.github.optimumcode.json.schema.JsonSchema
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.test.*
import kotlinx.serialization.json.*

/** Fresh bundled API controls use authored ProgramDB facts, never independent oracle truth. */
class NativeInterfaceCollectorRealTest {
    @Test
    fun `fresh bundled listing collector retains complete typed signature observations`() {
        val repository = Path.of("").toAbsolutePath().normalize()
        val parent = repository.resolve("build/native-interface-real-controls")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "listing-")
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
        val source = copyResource("NativeInterfaceCollectorControls.java", root)
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

        run(root, listOf(javaBin.resolve("java").toString(), "-Xmx1g") + javaProperties + listOf("-cp", "$classes${System.getProperty("path.separator")}$classpath", "NativeInterfaceCollectorControls", release.toString(), root.toString(), interfaceCollector.toString(), exporter.toString()), "native-control", Duration.ofSeconds(120))
        assertTrue(Files.readString(root.resolve("verified-controls.txt")).contains("model-unchanged"))
        for ((file, resource) in listOf(
            "native-interfaces.json" to "/project/native-interface-observations-v1.schema.json",
            "manifest.json" to "/project/native-interface-observation-manifest-v1.schema.json",
        )) {
            val definition = checkNotNull(javaClass.getResourceAsStream(resource)).use { it.readBytes().decodeToString() }
            val actual = Json.parseToJsonElement(Files.readString(root.resolve("first-native/$file")))
            assertTrue(JsonSchema.fromDefinition(definition).validate(actual) {}, "actual collector output violates $resource")
        }
        val native = Json.parseToJsonElement(Files.readString(root.resolve("native-properties.json"))).jsonObject
        val model = root.resolve("reports/program_model.json")
        val seen = mutableListOf<NativeInterfaceRecordV1>()
        val result = NativeInterfaceObservationsV1.validateBoundToSpaces(
            Files.readAllBytes(root.resolve("first-native/manifest.json")),
            expectedBindings = { spaces ->
                val imageSpace = spaces.single { it.name == native.getValue("imageBaseSpace").jsonPrimitive.content }
                NativeInterfaceBindingsV1(
                    collectorSha256 = sha256(interfaceCollector),
                    compilerSpecId = native.getValue("compilerSpecId").jsonPrimitive.content,
                    ghidraArchiveSha256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",
                    imageBase = NativeInterfaceAddressV1(imageSpace.index, native.getValue("imageBaseOffsetBits").jsonPrimitive.content),
                    inputSha256 = sha256(root.resolve("synthetic-input.bin")),
                    languageId = native.getValue("languageId").jsonPrimitive.content,
                    programModelBytes = Files.size(model), programModelExporterSha256 = sha256(exporter), programModelSha256 = sha256(model),
                )
            }, programModelBytes = Files.readAllBytes(model), checkpoint = {},
            openObservations = { Files.newInputStream(root.resolve("first-native/native-interfaces.json")) }, consume = seen::add,
        )
        assertEquals(native.getValue("functions").jsonPrimitive.long, result.scan.functions)
        assertEquals(native.getValue("externalFunctions").jsonPrimitive.long, result.scan.externalFunctions)
        assertEquals(native.getValue("thunks").jsonPrimitive.long, result.scan.thunks)
        assertEquals(result.scan.functions, result.observedFunctions.size.toLong())
        assertTrue(result.observedFunctions.any { it.state == "external-unmapped" })
        assertTrue(result.modelFunctions.isNotEmpty())
        val functions = seen.filterIsInstance<NativeInterfaceFunctionV1>()
        assertTrue(functions.any { it.parameters.any { p -> p.forcedIndirect && p.formalType != p.effectiveType } })
        assertTrue(functions.any { it.parameters.any { p -> p.autoParameter } })
        assertTrue(functions.any { it.parameters.any { p -> p.storage.varnodes.size > 1 } })
        // The actual global collector must join the complete independently read listing census,
        // including external owners, and preserve undefined targets as unresolved observations.
        val sidecar = root.resolve("global-types.ndjson")
        val globalHeader = Json.parseToJsonElement(Files.readAllLines(sidecar).first()).jsonObject
        val imageSpace = globalHeader.getValue("addressSpaces").jsonArray.single {
            it.jsonObject.getValue("name").jsonPrimitive.content == native.getValue("imageBaseSpace").jsonPrimitive.content
        }.jsonObject.getValue("index").jsonPrimitive.int
        val global = GlobalTypeObservationsV1.validate(
            GlobalTypeObservationBindingsV1(
                inputSha256 = sha256(root.resolve("synthetic-input.bin")), exporterSha256 = sha256(exporter),
                archiveSha256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",
                programModelBytes = Files.size(model), programModelSha256 = sha256(model),
                languageId = native.getValue("languageId").jsonPrimitive.content,
                compilerSpecId = native.getValue("compilerSpecId").jsonPrimitive.content,
                imageBase = "as$imageSpace@${native.getValue("imageBaseOffsetBits").jsonPrimitive.content}",
            ), Files.size(sidecar), sha256(sidecar),
            expectedFunctionIds = functions.map { "fn_${it.entry.offsetBits}" }.toSet(),
            checkpoint = {}, openObservations = { Files.newInputStream(sidecar) },
        )
        assertEquals(result.scan.functions, global.functionsInCapture)
        assertEquals(1, global.definedDataEntities)
        assertEquals(1, global.functionGlobalReferences)
        assertEquals(1, global.unresolvedFunctionGlobalReferences)
        assertEquals("recovered-observations-only", global.authorityBoundary)
        assertFalse(result.authoritativeOracleEvidence)
        assertFalse(result.productionInterfacesAdmitted)
        assertFalse(result.releaseEligible)
    }

    private fun copyResource(name: String, root: Path): Path = root.resolve(name).also { path ->
        checkNotNull(javaClass.getResourceAsStream("/nativeinterfaces/$name")) { "missing native control resource $name" }
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
