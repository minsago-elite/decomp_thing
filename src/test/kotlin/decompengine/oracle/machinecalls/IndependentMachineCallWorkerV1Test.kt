package decompengine.oracle.machinecalls

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.gcc.GccKotlinBootClasspathReference
import decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole
import decompengine.oracle.gcc.gccIndependentMachineCallJvmArguments
import decompengine.oracle.fulltree.OracleNativeLibraries
import java.io.File
import java.util.concurrent.TimeUnit
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import java.util.jar.Attributes
import java.util.jar.Manifest
import javax.tools.ToolProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive

class IndependentMachineCallWorkerV1Test {
    @Test fun `closed request round trips every committed field and limit`() = fixture { root ->
        val request = request(root)
        val parsed = IndependentMachineCallRequestV1.parse(request.canonicalBytes)
        assertContentEquals(request.canonicalBytes, parsed.canonicalBytes)
        assertEquals(request.richFile, parsed.richFile)
        assertEquals(request.runtime, parsed.runtime)
        assertEquals(request.limits.maximumInstructions, parsed.limits.maximumInstructions)
    }

    @Test fun `unknown recovered and missing fields are rejected at every nesting level`() = fixture { root ->
        val base = json(request(root))
        for (key in listOf("recovered", "programModel", "instructions", "functions", "callSites", "unknown")) {
            assertFailsWith<IllegalArgumentException>(key) { parse(JsonObject(base + (key to JsonPrimitive("forbidden")))) }
            for (container in listOf("richFile", "canonicalOracle", "runtime", "limits")) {
                val inner = base.getValue(container) as JsonObject
                assertFailsWith<IllegalArgumentException>("$container/$key") {
                    parse(JsonObject(base + (container to JsonObject(inner + (key to JsonPrimitive("forbidden"))))))
                }
            }
        }
        for (key in base.keys) assertFailsWith<IllegalArgumentException>(key) { parse(JsonObject(base - key)) }
        assertFailsWith<IllegalArgumentException> { parse(JsonObject(base + ("schemaVersion" to JsonPrimitive("1")))) }
        assertFailsWith<IllegalArgumentException> {
            IndependentMachineCallRequestV1.parse(request(root).canonicalBytes + byteArrayOf(10))
        }
    }

    @Test fun `live v2 request binds snapshot files and exact control root`() = fixture { root ->
        val request = liveRequest(root)
        assertContentEquals(request.canonicalBytes,
            IndependentMachineCallRequestV2.parse(request.canonicalBytes).canonicalBytes)
        assertFailsWith<IllegalArgumentException> { request.copy(controlRoot = root.resolve("other")) }
        assertFailsWith<IllegalArgumentException> {
            request.copy(runtime = request.runtime.copy(bridgeSnapshot =
                request.runtime.bridgeSnapshot.copy(path = root.resolve("elsewhere/bridge.jar"))))
        }
        assertFailsWith<IllegalArgumentException> {
            request.copy(runtime = request.runtime.copy(bridgeSnapshot =
                request.runtime.bridgeSnapshot.copy(bytes = FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE.maximumBytes + 1)))
        }
        // A legacy v1 live envelope is still parseable for frozen evidence, but the live worker
        // admission path must reject it instead of treating its source-path hashes as snapshots.
        val legacy = request(root)
        val path = Files.write(root.resolve("legacy-request.json"), legacy.canonicalBytes)
        assertFailsWith<IllegalArgumentException> { IndependentMachineCallWorkerV1.run(path, OracleArtifacts.sha256(legacy.canonicalBytes)) }
    }

    @Test fun `runtime pins paths hashes and finite budgets cannot be loosened by a request`() = fixture { root ->
        val base = json(request(root))
        val runtime = base.getValue("runtime") as JsonObject
        for ((field, value) in mapOf(
            "archiveBytes" to JsonPrimitive(569445153), "archiveSha256" to JsonPrimitive("0".repeat(64)),
            "languageId" to JsonPrimitive("x86:LE:32:default"), "languageVersion" to JsonPrimitive("4.7"),
            "bridgeSha256" to JsonPrimitive("ABC"), "bundleManifestSha256" to JsonPrimitive("0".repeat(63)),
            "bundleRoot" to JsonPrimitive("relative/bundle"),
        )) assertFailsWith<IllegalArgumentException>(field) {
            parse(JsonObject(base + ("runtime" to JsonObject(runtime + (field to value)))))
        }
        val limits = base.getValue("limits") as JsonObject
        for (key in limits.keys) {
            for (value in listOf(JsonPrimitive(0), JsonPrimitive(Long.MAX_VALUE), JsonPrimitive("1"))) {
                assertFails("$key=$value") { parse(JsonObject(base + ("limits" to JsonObject(limits + (key to value))))) }
            }
        }
        assertFailsWith<IllegalArgumentException> { request(root).copy(outputPath = request(root).richFile.path) }
        assertFailsWith<IllegalArgumentException> { request(root).copy(outputPath = root.resolve("bundle/result.json")) }
        assertFailsWith<IllegalArgumentException> { request(root).copy(outputPath = root.resolve("unused/../result.json")) }
        assertFailsWith<IllegalArgumentException> { request(root).let { it.copy(richFile = it.richFile.copy(bytes = 512L * 1024 * 1024 + 1)) } }
        assertFailsWith<IllegalArgumentException> { request(root).let { it.copy(canonicalOracle = it.canonicalOracle.copy(bytes = 64L * 1024 * 1024 + 1)) } }
    }

    @Test fun `request and input commitment mutations fail before runtime loading or output`() = fixture { root ->
        val rich = Files.write(root.resolve("rich.elf"), byteArrayOf(1, 2, 3))
        val oracle = Files.write(root.resolve("oracle.json"), byteArrayOf(123, 125))
        val base = request(root).copy(
            richFile = MachineCallFileV1(rich, 3, OracleArtifacts.sha256(Files.readAllBytes(rich))),
            canonicalOracle = MachineCallFileV1(oracle, 2, OracleArtifacts.sha256(Files.readAllBytes(oracle))),
        )
        val requestPath = Files.write(root.resolve("request.json"), base.canonicalBytes)
        assertFailsWith<IllegalArgumentException> { IndependentMachineCallWorkerV1.run(requestPath, "0".repeat(64)) }
        Files.write(rich, byteArrayOf(1, 2, 4))
        assertFailsWith<IllegalArgumentException> {
            IndependentMachineCallWorkerV1.run(requestPath, OracleArtifacts.sha256(base.canonicalBytes))
        }
        assertFalse(Files.exists(base.outputPath))
    }

    @Test fun `self consistent bundle metadata cannot replace the pinned archive`() = fixture { root ->
        val bundle = Files.createDirectory(root.resolve("bundle"))
        val bridge = Files.write(bundle.resolve("decomp-ghidra-bridge.jar"), byteArrayOf(1, 2))
        val manifest = Files.writeString(bundle.resolve("bundle.sha256"),
            OracleArtifacts.sha256(Files.readAllBytes(bridge)) + "  decomp-ghidra-bridge.jar\n")
        Files.write(root.resolve("ghidra.zip"), byteArrayOf(80, 75, 3, 4))
        val runtime = MachineCallRuntimeV2(bundle, root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
            569445154L, OracleArtifacts.sha256(Files.readAllBytes(bridge)),
            OracleArtifacts.sha256(Files.readAllBytes(manifest)), "x86:LE:64:default", "4.8",
            MachineCallFileV1(root.resolve("control/runtime/ghidra-bridge.runtime"), Files.size(bridge),
                OracleArtifacts.sha256(Files.readAllBytes(bridge))),
            MachineCallFileV1(root.resolve("control/runtime/ghidra-bundle-manifest.runtime"), Files.size(manifest),
                OracleArtifacts.sha256(Files.readAllBytes(manifest))))
        assertFailsWith<IllegalArgumentException> { AuthenticatedMachineCallRuntimeV2.open(runtime).close() }
        assertFalse(Files.exists(root.resolve("output.json")))
    }

    @Test fun `runtime library verification consumes the authenticated manifest snapshot`() = fixture { root ->
        val bundle = Files.createDirectory(root.resolve("bundle"))
        val bridge = Files.write(bundle.resolve("decomp-ghidra-bridge.jar"), byteArrayOf(1, 2, 3))
        val application = Files.createDirectories(bundle.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra"))
            .resolve("application.properties")
        Files.writeString(application,
            "application.version=${BundledGhidra.VERSION}\napplication.release.name=PUBLIC\n")
        val library = Files.createDirectories(application.parent.resolve("Framework/Test/lib"))
            .resolve("runtime.jar").also { Files.write(it, byteArrayOf(4, 5, 6)) }
        fun record(path: Path): String = "${OracleArtifacts.sha256(Files.readAllBytes(path))}  ${bundle.relativize(path).joinToString("/")}\n"
        val manifestBytes = (record(bridge) + record(application) + record(library)).toByteArray()
        Files.write(bundle.resolve("bundle.sha256"), manifestBytes)
        val expected = listOf(library)
        assertEquals(expected, BundledGhidra.at(bundle)
            .verifiedLibraryPathsFromManifestSnapshot(manifestBytes) {})

        // The worker's selected inventory remains bound to the snapshot even if the source-side
        // manifest path changes; a source manifest is not allowed to silently replace it.
        Files.writeString(bundle.resolve("bundle.sha256"), "malformed source manifest\n")
        assertEquals(expected, BundledGhidra.at(bundle)
            .verifiedLibraryPathsFromManifestSnapshot(manifestBytes) {})
        assertFailsWith<IllegalArgumentException> { BundledGhidra.at(bundle).verifiedLibraryPaths {} }
    }

    @Test fun `loaded bridge must have the committed jar source and bytes`() = fixture { root ->
        fakeBridge(root) { type, jar ->
            val digest = OracleArtifacts.sha256(Files.readAllBytes(jar))
            requireLoadedMachineCallBridgeV1(type, jar, digest)
            assertFailsWith<IllegalArgumentException> { requireLoadedMachineCallBridgeV1(type, jar, "0".repeat(64)) }
            val copy = Files.copy(jar, root.resolve("other.jar"))
            assertFailsWith<IllegalArgumentException> { requireLoadedMachineCallBridgeV1(type, copy, digest) }
            assertFailsWith<IllegalArgumentException> {
                requireLoadedMachineCallBridgeV1(IndependentMachineCallWorkerV1Test::class.java, jar, digest)
            }
        }
    }

    @Test fun `manifest and index loading cannot expand authenticated classpath`() = fixture { root ->
        fun jar(name: String, dependency: String? = null, index: Boolean = false): Path {
            val manifest = Manifest().apply {
                mainAttributes[Attributes.Name.MANIFEST_VERSION] = "1.0"
                if (dependency != null) mainAttributes[Attributes.Name.CLASS_PATH] = dependency
            }
            return root.resolve(name).also { path ->
                JarOutputStream(Files.newOutputStream(path), manifest).use { output ->
                    if (index) {
                        output.putNextEntry(JarEntry("META-INF/INDEX.LIST"))
                        output.write("JarIndex-Version: 1.0\n\nexternal.jar\nexternal\n".toByteArray())
                        output.closeEntry()
                    }
                }
            }
        }
        val library = jar("library.jar")
        fakeBridge(root) { _, compiled ->
            val external = jar("external-bridge.jar", "fake.jar https://example.invalid/code.jar", index = true)
            MachineCallJarClassLoaderV1(listOf(external, library)).use { loader ->
                assertFailsWith<ClassNotFoundException> { Class.forName("FakeBridge", false, loader) }
                assertNull(loader.getResource("FakeBridge.class"))
            }
            MachineCallJarClassLoaderV1(listOf(external, compiled, library)).use { loader ->
                val type = Class.forName("FakeBridge", false, loader)
                requireLoadedMachineCallBridgeV1(type, compiled, OracleArtifacts.sha256(Files.readAllBytes(compiled)))
                assertNotNull(loader.getResource("FakeBridge.class"))
                assertEquals(1, loader.getResources("FakeBridge.class").toList().size)
            }
        }
    }

    @Test fun `contained worker authenticates requests in a fresh JVM without native extraction`() = fixture { root ->
        val native = Path.of(checkNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory")))
        val bootRoot = Path.of(checkNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot")))
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            reference.entries.joinToString(File.pathSeparator) { bootRoot.resolve(it.logicalName).toString() }
        }
        Files.createDirectory(root.resolve("state"))
        // A regular file is a deterministic extraction trap, even on an executable test filesystem.
        // Production scratch stays noexec; this regression must not depend on host mount privileges.
        val temporary = Files.write(root.resolve("tmp"), byteArrayOf(42))
        val requestPath = Files.write(root.resolve("request.json"), request(root).canonicalBytes)
        val arguments = gccIndependentMachineCallJvmArguments(root, native)
        assertTrue("-Djna.nounpack=true" in arguments)
        assertTrue("-Djna.nosys=true" in arguments)
        assertTrue("-Djna.boot.library.path=$native" in arguments)
        assertTrue("-Dorg.sqlite.lib.path=$native" in arguments)
        assertFailsWith<IllegalArgumentException> { gccIndependentMachineCallJvmArguments(root, root.resolve("native")) }
        fun launch(name: String, jvmArguments: List<String>): Pair<Int, String> {
            val log = root.resolve("$name.log")
            val process = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(),
                "-Xmx256m", "-XX:-UsePerfData") + jvmArguments + listOf("-cp", classpath,
                IndependentMachineCallWorkerV1::class.java.name, requestPath.toString(), "0".repeat(64)))
                .directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
                    environment().clear()
                    environment()["HOME"] = root.resolve("state").toString()
                    environment()["TMPDIR"] = temporary.toString()
                    environment()["LANG"] = "C.UTF-8"
                }.start()
            try {
                process.outputStream.close()
                assertTrue(process.waitFor(30, TimeUnit.SECONDS), "worker bootstrap timed out")
                return process.exitValue() to Files.readString(log).takeLast(12000)
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
                process.inputStream.close(); process.errorStream.close()
            }
        }
        val unpinned = launch("unpinned", arguments.filterNot { it in OracleNativeLibraries.jvmArguments(native) } +
            "-Djna.nosys=true")
        assertTrue(unpinned.first != 0 && unpinned.second.contains("UnsatisfiedLinkError"), unpinned.second)
        val pinned = launch("pinned", arguments)
        assertTrue(pinned.first != 0 && pinned.second.contains("machine-call request SHA-256 differs"), pinned.second)
        assertFalse(pinned.second.contains("UnsatisfiedLinkError"), pinned.second)
        assertContentEquals(byteArrayOf(42), Files.readAllBytes(temporary))
        assertFalse(Files.exists(root.resolve("output.json")))
        assertTrue(Files.list(root.resolve("state")).use { !it.findAny().isPresent })
    }

    @Test fun `pinned bundled runtime initializes and decodes bytes in a fresh worker JVM`() = fixture { root ->
        val bundle = Path.of(requireNotNull(System.getProperty("decompengine.ghidra.bundle"))).toAbsolutePath().normalize()
        val archive = Path.of(requireNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))).toAbsolutePath().normalize()
        val runtime = runtimeV2(root, bundle, archive)
        val bootRoot = Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot")))
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            reference.entries.joinToString(File.pathSeparator) { bootRoot.resolve(it.logicalName).toString() }
        }
        val home = Files.createDirectory(root.resolve("state"))
        val temporary = Files.createDirectory(root.resolve("tmp"))
        val log = Files.createTempDirectory(root.parent, "runtime-evidence-").resolve("worker.log")
        withMachineCallWorkerFixtureV1 { rich, oracle, inputSha, oracleSha, manifestSha ->
            val control = Files.createDirectories(root.resolve("control/runtime"))
            val reports = Files.createDirectory(root.resolve("control/reports"))
            val request = IndependentMachineCallRequestV2(MachineCallFileV1(rich, Files.size(rich), inputSha),
                MachineCallFileV1(oracle, Files.size(oracle), oracleSha), manifestSha, runtime, root.resolve("control"),
                reports.resolve("independent-machine-call-observations.json"))
            val requestPath = Files.write(root.resolve("request.json"), request.canonicalBytes)
            val requestSha = OracleArtifacts.sha256(request.canonicalBytes)
            val process = ProcessBuilder(listOf(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx512m",
                "-XX:-UsePerfData") + gccIndependentMachineCallJvmArguments(root,
                    Path.of(checkNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory")))) +
                listOf("-cp", classpath, IndependentMachineCallWorkerV1::class.java.name,
                    requestPath.toString(), requestSha)).directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
                    environment().clear()
                    environment()["HOME"] = home.toString()
                    environment()["TMPDIR"] = temporary.toString()
                    environment()["XDG_CACHE_HOME"] = temporary.toString()
                    environment()["XDG_CONFIG_HOME"] = home.toString()
                    environment()["LANG"] = "C.UTF-8"
                }.start()
            try {
                assertTrue(process.waitFor(60, TimeUnit.SECONDS), "worker timed out: ${Files.readString(log).takeLast(12000)}")
                assertEquals(0, process.exitValue(), Files.readString(log).takeLast(12000))
            } finally {
                if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
                process.outputStream.close(); process.inputStream.close(); process.errorStream.close()
            }
            val report = OracleJson.parseCanonical(Files.readAllBytes(request.outputPath)) as JsonObject
            IndependentMachineCallReportV1.validateWorker(report, requestSha, request)
            assertEquals(JsonPrimitive("authenticated-bundled-worker-v1"), report["decoderAuthentication"])
            val calls = (report.getValue("calls") as JsonArray).map { it as JsonObject }
            assertEquals(listOf(JsonPrimitive("direct-call"), JsonPrimitive("indirect-call")), calls.map { it["classification"] })
            assertEquals(JsonPrimitive("0x400150"), calls[0]["directTargetAddress"])
            assertEquals(JsonPrimitive("0x400115"), calls[0]["fallthroughAddress"])
            assertEquals(JsonPrimitive("e83b000000"), calls[0]["instructionBytes"])
            assertEquals(JsonPrimitive("positive-internal-exact-start"), calls[0]["disposition"])
            assertEquals(JsonPrimitive("unresolved-indirect-target"), calls[1]["disposition"])
            val roots = (report.getValue("roots") as JsonArray).map { it as JsonObject }
            assertEquals(JsonPrimitive(4), roots.single { it["rva"] == JsonPrimitive("0x110") }["instructionAttempts"])
            val refused = roots.single { it["rva"] == JsonPrimitive("0x170") }
            assertEquals(JsonArray(listOf(JsonPrimitive("decoder-refused-instruction"))), refused["traversalStops"])
            assertEquals(JsonPrimitive(false), report["negativeCompleteness"])
            assertEquals(JsonPrimitive(false), report["releaseEligible"])
        }
    }

    @Test fun `manifest size and ambiguous spelling fail before version aware jar parsing`() = fixture { root ->
        fun jar(name: String, entryName: String, bytes: ByteArray) = root.resolve(name).also { path ->
            JarOutputStream(Files.newOutputStream(path)).use { output ->
                output.putNextEntry(JarEntry(entryName))
                output.write(bytes)
                output.closeEntry()
            }
        }
        val ordinary = jar("ordinary.jar", "resource.txt", byteArrayOf(1))
        val oversized = jar("oversized.jar", "META-INF/MANIFEST.MF", ByteArray(2 * 1024 * 1024 + 1) { 65 })
        assertFailsWith<IllegalArgumentException> { MachineCallJarClassLoaderV1(listOf(oversized, ordinary)).close() }
        val ambiguous = jar("ambiguous.jar", "meta-inf/manifest.mf", "Manifest-Version: 1.0\r\n\r\n".toByteArray())
        assertFailsWith<IllegalArgumentException> { MachineCallJarClassLoaderV1(listOf(ambiguous, ordinary)).close() }
    }

    @Test fun `reflective decoder preserves fields and refuses hidden flow flag and address mismatches`() = fixture { root ->
        fakeBridge(root) { type, _ ->
            val sample = type.getMethod("sample", String::class.java, String::class.java, java.lang.Boolean.TYPE)
            val decoded = machineInstructionFromBridgeV1(sample.invoke(null, "0x401000", "direct-call", true))
            assertEquals(0x401000UL, decoded.address)
            assertEquals(5, decoded.length)
            assertContentEquals(byteArrayOf(-24, 11, 0, 0, 0), decoded.bytes)
            assertEquals(0x401005UL, decoded.fallthrough)
            assertEquals(listOf(0x401010UL), decoded.directTargets)
            assertEquals(0x401010UL, decoded.directCallTarget)
            assertEquals("language-default-no-commits-v1", decoded.contextStatus)
            for ((classification, call) in listOf("direct-call" to false, "ordinary" to true, "direct-jump" to true,
                "unknown" to true)) {
                assertFailsWith<IllegalArgumentException> {
                    machineInstructionFromBridgeV1(sample.invoke(null, "0x401000", classification, call))
                }
            }
            for (address in listOf("0X401000", "0x0401000", "-1", "0x10000000000000000")) {
                assertFailsWith<IllegalArgumentException> {
                    machineInstructionFromBridgeV1(sample.invoke(null, address, "direct-call", true))
                }
            }
        }
    }

    @Test fun `publication is create new atomic and cleans staging files on collision`() = fixture { root ->
        val output = root.resolve("output.json")
        publishMachineCallResultV1(output, "first".toByteArray())
        assertContentEquals("first".toByteArray(), Files.readAllBytes(output))
        assertFailsWith<IllegalArgumentException> { publishMachineCallResultV1(output, "replacement".toByteArray()) }
        assertContentEquals("first".toByteArray(), Files.readAllBytes(output))
        val dangling = Files.createSymbolicLink(root.resolve("linked.json"), root.resolve("missing"))
        assertFailsWith<IllegalArgumentException> { publishMachineCallResultV1(dangling, byteArrayOf(1)) }
        assertFalse(Files.exists(root.resolve("missing")))
        Files.list(root).use { paths -> assertFalse(paths.anyMatch { it.fileName.toString().endsWith(".pending") }) }
    }

    private fun request(root: Path) = IndependentMachineCallRequestV1(
        MachineCallFileV1(root.resolve("rich.elf"), 3, "1".repeat(64)),
        MachineCallFileV1(root.resolve("oracle.json"), 2, "2".repeat(64)), "3".repeat(64),
        MachineCallRuntimeV1(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
            569445154L, "4".repeat(64), "5".repeat(64), "x86:LE:64:default", "4.8"), root.resolve("output.json"),
    )

    private fun liveRequest(root: Path): IndependentMachineCallRequestV2 {
        val control = root.resolve("control")
        val bridge = MachineCallFileV1(control.resolve("runtime/ghidra-bridge.runtime"), 4, "4".repeat(64))
        val manifest = MachineCallFileV1(control.resolve("runtime/ghidra-bundle-manifest.runtime"), 5, "5".repeat(64))
        return IndependentMachineCallRequestV2(
            MachineCallFileV1(root.resolve("rich.elf"), 3, "1".repeat(64)),
            MachineCallFileV1(root.resolve("oracle.json"), 2, "2".repeat(64)), "3".repeat(64),
            MachineCallRuntimeV2(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
                569445154L, "4".repeat(64), "5".repeat(64), "x86:LE:64:default", "4.8", bridge, manifest),
            control, control.resolve("reports/independent-machine-call-observations.json"),
        )
    }

    private fun runtimeV2(root: Path, bundle: Path, archive: Path): MachineCallRuntimeV2 {
        val directory = Files.createDirectories(root.resolve("control/runtime"))
        val bridgeSource = bundle.resolve("decomp-ghidra-bridge.jar")
        val manifestSource = bundle.resolve("bundle.sha256")
        val bridge = Files.copy(bridgeSource, directory.resolve("ghidra-bridge.runtime"))
        val manifest = Files.copy(manifestSource, directory.resolve("ghidra-bundle-manifest.runtime"))
        val bridgeSha = OracleArtifacts.sha256(Files.readAllBytes(bridgeSource))
        val manifestSha = OracleArtifacts.sha256(Files.readAllBytes(manifestSource))
        return MachineCallRuntimeV2(bundle, archive, BundledGhidra.ARCHIVE_SHA256, 569445154L,
            bridgeSha, manifestSha, "x86:LE:64:default", "4.8",
            MachineCallFileV1(bridge, Files.size(bridge), bridgeSha),
            MachineCallFileV1(manifest, Files.size(manifest), manifestSha))
    }

    private fun json(request: IndependentMachineCallRequestV1) = OracleJson.parseCanonical(request.canonicalBytes) as JsonObject
    private fun parse(value: JsonObject) = IndependentMachineCallRequestV1.parse(OracleJson.canonicalBytes(value))

    private fun fakeBridge(root: Path, action: (Class<*>, Path) -> Unit) {
        val source = Files.writeString(root.resolve("FakeBridge.java"), """
            import java.util.List;
            public class FakeBridge {
                public record DecodedInstruction(String address, int length, byte[] bytes, String classification,
                    boolean call, boolean computed, boolean jump, boolean conditional, boolean terminal,
                    String fallthrough, List<String> directTargets, String directCallTarget, String contextStatus) {}
                public static DecodedInstruction sample(String address, String classification, boolean call) {
                    return new DecodedInstruction(address, 5, new byte[]{(byte)0xe8,11,0,0,0}, classification,
                        call, false, false, false, false, "0x401005", List.of("0x401010"), "0x401010",
                        "language-default-no-commits-v1");
                }
            }
        """.trimIndent())
        val classes = Files.createDirectory(root.resolve("classes"))
        val compiler = requireNotNull(ToolProvider.getSystemJavaCompiler())
        assertEquals(0, compiler.run(null, null, null, "-d", classes.toString(), source.toString()))
        val jar = root.resolve("fake.jar")
        JarOutputStream(Files.newOutputStream(jar)).use { output ->
            for (name in listOf("FakeBridge.class", "FakeBridge\$DecodedInstruction.class")) {
                output.putNextEntry(JarEntry(name))
                output.write(Files.readAllBytes(classes.resolve(name)))
                output.closeEntry()
            }
        }
        URLClassLoader(arrayOf(jar.toUri().toURL()), ClassLoader.getPlatformClassLoader()).use { loader ->
            action(Class.forName("FakeBridge", false, loader), jar)
        }
    }

    private fun fixture(action: (Path) -> Unit) {
        val base = Files.createDirectories(Path.of("build", "machine-call-worker-tests").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(base, "fixture-")
        try { action(root) } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
