package decompengine.oracle.externalcalls

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.gcc.GccKotlinBootClasspathReference
import decompengine.oracle.machinecalls.IndependentMachineCallWorkerV1
import decompengine.oracle.machinecalls.IndependentMachineCallReportV1
import decompengine.oracle.machinecalls.IndependentMachineCallRequestV2
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV2
import java.net.URLClassLoader
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import javax.tools.ToolProvider
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class IndependentExternalCallWorkerV1Test {
    @Test fun `closed request round trips all file runtime limit and metadata commitments`() = fixture { root ->
        val original = request(root)
        val parsed = IndependentExternalCallRequestV1.parse(original.canonicalBytes)
        assertEquals(original, parsed)
        assertContentEquals(original.canonicalBytes, parsed.canonicalBytes)
        assertFails { IndependentExternalCallRequestV1.parse(original.canonicalBytes + byteArrayOf(10)) }
    }

    @Test fun `unknown recovered inputs missing fields and metadata overrides are refused`() = fixture { root ->
        val document = document(request(root))
        for (unknown in listOf("recovered", "programModel", "references", "instructionListing", "unknown")) {
            assertFails { parse(JsonObject(document + (unknown to JsonPrimitive("forbidden")))) }
            for (container in listOf("richFile", "sourceReport", "sourceRequest", "runtime", "limits")) {
                val inner = document.getValue(container) as JsonObject
                assertFails { parse(JsonObject(document + (container to JsonObject(inner + (unknown to JsonPrimitive(1)))))) }
            }
        }
        for (key in document.keys) assertFails(key) { parse(JsonObject(document - key)) }
        for (container in listOf("richFile", "sourceReport", "sourceRequest", "runtime", "limits")) {
            val inner = document.getValue(container) as JsonObject
            for (key in inner.keys) assertFails("$container.$key") { parse(JsonObject(document + (container to JsonObject(inner - key)))) }
        }
        assertFails { parse(JsonObject(document + ("metadataPolicy" to JsonPrimitive("unbounded")))) }
        assertFails { request(root).copy(limits = ExternalCallLimitsV1(metadata = ElfDynamicBindingLimitsV1(maximumRelocations = 1))) }
        assertFails { parse(JsonObject(document + ("schemaVersion" to JsonPrimitive("1")))) }
    }

    @Test fun `input path byte and runtime pins cannot be widened by the new request`() = fixture { root ->
        val request = request(root)
        assertFails { request.copy(richFile = request.richFile.copy(bytes = 512L * 1024 * 1024 + 1)) }
        assertFails { request.copy(sourceReport = request.sourceReport.copy(bytes = 64L * 1024 * 1024 + 1)) }
        assertFails { request.copy(sourceRequest = request.sourceRequest.copy(bytes = 65537)) }
        assertFails { request.copy(sourceRequest = request.sourceReport) }
        assertFails { request.copy(outputPath = request.richFile.path) }
        assertFails { request.copy(outputPath = request.runtime.ghidraArchivePath) }
        assertFails { request.copy(outputPath = root.resolve("bundle/output.json")) }
        assertFails { request.copy(outputPath = root.resolve("unused/../output.json")) }
        assertFails { request.copy(outputPath = Path.of("relative.json")) }
        val document = document(request)
        val limits = document.getValue("limits") as JsonObject
        for (key in limits.keys) for (value in listOf(JsonPrimitive(0), JsonPrimitive(Long.MAX_VALUE), JsonPrimitive("1"))) {
            assertFails("$key=$value") { parse(JsonObject(document + ("limits" to JsonObject(limits + (key to value))))) }
        }
        val runtime = document.getValue("runtime") as JsonObject
        for ((key, value) in mapOf("archiveSha256" to JsonPrimitive("0".repeat(64)), "archiveBytes" to JsonPrimitive(1),
            "languageId" to JsonPrimitive("x86:LE:32:default"), "languageVersion" to JsonPrimitive("4.7"),
            "bridgeSha256" to JsonPrimitive("not-a-digest"))) assertFails(key) {
            parse(JsonObject(document + ("runtime" to JsonObject(runtime + (key to value)))))
        }
    }

    @Test fun `changed request or any committed input fails before runtime loading or publication`() = fixture { root ->
        fun file(name: String, data: ByteArray): MachineCallFileV1 {
            val path = Files.write(root.resolve(name), data)
            return MachineCallFileV1(path, data.size.toLong(), OracleArtifacts.sha256(data))
        }
        val bytes = byteArrayOf(1, 2, 3)
        val base = request(root).copy(richFile = file("rich.elf", bytes), sourceReport = file("source-report.json", bytes),
            sourceRequest = file("source-request.json", bytes))
        val requestPath = Files.write(root.resolve("request.json"), base.canonicalBytes)
        val digest = OracleArtifacts.sha256(base.canonicalBytes)
        assertFails { IndependentExternalCallWorkerV1.run(requestPath, "0".repeat(64)) }
        for (input in listOf(base.richFile, base.sourceReport, base.sourceRequest)) {
            Files.write(input.path, byteArrayOf(1, 2, 4))
            assertFails { IndependentExternalCallWorkerV1.run(requestPath, digest) }
            assertFalse(Files.exists(base.outputPath))
            Files.write(input.path, bytes)
        }
    }

    @Test fun `worker output commitments and authority flags cannot drift from its authenticated request`() = fixture { root ->
        val request = request(root)
        val digest = OracleArtifacts.sha256(request.canonicalBytes)
        val output = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "kind" to JsonPrimitive("independent-external-call-component-v1"), "scope" to JsonPrimitive("component"),
            "requestSha256" to JsonPrimitive(digest), "runtime" to request.runtime.reportJson(), "limits" to externalCallLimitsJsonV1(request.limits),
            "metadataPolicy" to JsonPrimitive("elf-dynamic-binding-default-limits-v1"), "inputSha256" to JsonPrimitive(request.richFile.sha256),
            "inputBytes" to JsonPrimitive(request.richFile.bytes), "sourceReportSha256" to JsonPrimitive(request.sourceReport.sha256),
            "sourceRequestSha256" to JsonPrimitive(request.sourceRequest.sha256), "decoderAuthentication" to JsonPrimitive("authenticated-bundled-worker-v1"),
            "containmentStatus" to JsonPrimitive("external-owner-required"), "complete" to JsonPrimitive(false),
            "releaseEligible" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(false),
        ))
        validateExternalWorkerCommitmentsV1(output, digest, request)
        for (key in output.keys) assertFails(key) { validateExternalWorkerCommitmentsV1(JsonObject(output + (key to JsonPrimitive("changed"))), digest, request) }
        assertFails { validateExternalWorkerCommitmentsV1(output, "0".repeat(64), request) }
    }

    @Test fun `JDK record conversion checks exact schema coordinates opcode chains and owns its mutable values`() = fixture { root ->
        fakeRecord(root) { type ->
            val sample = type.getMethod("sample").invoke(null)
            val components = sample.javaClass.recordComponents
            val values = components.map { it.accessor.invoke(sample) }
            fun changed(key: String, value: Any?): Any {
                val arguments = values.toMutableList()
                arguments[components.indexOfFirst { it.name == key }] = value
                return sample.javaClass.declaredConstructors.single().newInstance(*arguments.toTypedArray())
            }
            val converted = staticMemoryTransferFromBridgeV1(sample)
            assertEquals(0x401000UL, converted.address)
            assertEquals(0x5000UL, converted.pointerSlotAddress)
            assertEquals(listOf(0), converted.rawCopyOpIndices)
            val mutations = mapOf<String, Any?>("address" to "0x0401000", "length" to 0, "bytes" to byteArrayOf(0),
                "classification" to "made-up", "pointerSlotAddress" to "0xffffffffffffffff", "pointerWidthBytes" to 4,
                "relationship" to "resolved-runtime-target", "rawReadOpcode" to "LOAD", "rawReadOpIndex" to 2,
                "rawTransferOpcode" to "BRANCHIND", "rawTransferOpIndex" to 0, "rawCopyOpIndices" to listOf(0, 0),
                "contextStatus" to "context-change", "unresolvedReason" to "register-transfer")
            for ((key, value) in mutations) assertFails(key) { staticMemoryTransferFromBridgeV1(changed(key, value)) }
            assertFails { staticMemoryTransferFromBridgeV1(changed("rawCopyOpIndices", listOf("0"))) }
            assertFails { staticMemoryTransferFromBridgeV1(type.getMethod("extra").invoke(null)) }
            assertFails { staticMemoryTransferFromBridgeV1(type.getMethod("wrongType").invoke(null)) }
            val unresolved = type.getMethod("unresolved").invoke(null)
            assertNull(staticMemoryTransferFromBridgeV1(unresolved).pointerSlotAddress)
            (values[components.indexOfFirst { it.name == "bytes" }] as ByteArray)[0] = 0
            @Suppress("UNCHECKED_CAST")
            (values[components.indexOfFirst { it.name == "rawCopyOpIndices" }] as MutableList<Int>).clear()
            assertEquals(0xff.toByte(), converted.bytes[0])
            assertEquals(listOf(0), converted.rawCopyOpIndices)
        }
    }

    @Test fun `fresh authenticated worker composes actual PLT and GOT byte witnesses without resolving runtime targets`() = fixture { root ->
        val authored = ExternalCallFixtureV1(root)
        val bundle = Path.of(requireNotNull(System.getProperty("decompengine.ghidra.bundle"))).toAbsolutePath().normalize()
        val archive = Path.of(requireNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))).toAbsolutePath().normalize()
        val controlRoot = Files.createDirectories(root.resolve("source-control"))
        Files.createDirectories(controlRoot.resolve("reports"))
        val runtimeFiles = Files.createDirectories(controlRoot.resolve("runtime"))
        val bridgeSource = bundle.resolve("decomp-ghidra-bridge.jar")
        val manifestSource = bundle.resolve("bundle.sha256")
        val bridgeSnapshot = Files.copy(bridgeSource, runtimeFiles.resolve("ghidra-bridge.runtime"))
        val manifestSnapshot = Files.copy(manifestSource, runtimeFiles.resolve("ghidra-bundle-manifest.runtime"))
        val bridgeSha = OracleArtifacts.sha256(Files.readAllBytes(bridgeSource))
        val manifestSha = OracleArtifacts.sha256(Files.readAllBytes(manifestSource))
        val runtime = MachineCallRuntimeV2(bundle, archive, BundledGhidra.ARCHIVE_SHA256, 569445154L,
            bridgeSha, manifestSha, "x86:LE:64:default", "4.8",
            MachineCallFileV1(bridgeSnapshot, Files.size(bridgeSnapshot), bridgeSha),
            MachineCallFileV1(manifestSnapshot, Files.size(manifestSnapshot), manifestSha))
        val bootRoot = Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot")))
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            reference.entries.joinToString(File.pathSeparator) { bootRoot.resolve(it.logicalName).toString() }
        }
        val sourceRequest = IndependentMachineCallRequestV2(authored.request.richFile, authored.request.canonicalOracle,
            authored.request.manifestSha256, runtime, controlRoot,
            controlRoot.resolve("reports/independent-machine-call-observations.json"))
        val sourceRequestPath = Files.write(root.resolve("authenticated-source-request.json"), sourceRequest.canonicalBytes)
        val sourceRequestSha = OracleArtifacts.sha256(sourceRequest.canonicalBytes)
        freshWorker(root, "source", classpath, IndependentMachineCallWorkerV1::class.java.name, sourceRequestPath, sourceRequestSha)
        val sourceReportBytes = Files.readAllBytes(sourceRequest.outputPath)
        IndependentMachineCallReportV1.validateWorker(OracleJson.parseCanonical(sourceReportBytes) as JsonObject, sourceRequestSha, sourceRequest)
        val request = IndependentExternalCallRequestV1(sourceRequest.richFile,
            MachineCallFileV1(sourceRequest.outputPath, sourceReportBytes.size.toLong(), OracleArtifacts.sha256(sourceReportBytes)),
            MachineCallFileV1(sourceRequestPath, Files.size(sourceRequestPath), sourceRequestSha), runtime, root.resolve("external-report.json"))
        val requestPath = Files.write(root.resolve("external-request.json"), request.canonicalBytes)
        val requestSha = OracleArtifacts.sha256(request.canonicalBytes)
        freshWorker(root, "external", classpath, IndependentExternalCallWorkerV1::class.java.name, requestPath, requestSha)
        val output = OracleJson.parseCanonical(Files.readAllBytes(request.outputPath)) as JsonObject
        IndependentExternalCallReportV1.validateWorker(output, requestSha, request)
        val sites = (output.getValue("sites") as JsonArray).map { it as JsonObject }
        assertEquals(2, sites.size, "forwarding evidence must not invent a second physical call")
        assertEquals(listOf(JsonPrimitive("static-import-request-reference"), JsonPrimitive("unresolved-weak-runtime-target")),
            sites.map { it["compositionDisposition"] })
        assertEquals(listOf(JsonPrimitive(true), JsonPrimitive(false)), sites.map { it["viaForwarder"] })
        assertEquals(listOf(JsonPrimitive("0x400275"), JsonPrimitive("0x40027b")), sites.map { it["returnAddress"] })
        val transfers = sites.map { it.getValue("memoryTransfer") as JsonObject }
        assertEquals(listOf(JsonPrimitive("0x400800"), JsonPrimitive("0x400828")), transfers.map { it["pointerSlotAddress"] })
        assertEquals(listOf(JsonPrimitive("BRANCHIND"), JsonPrimitive("COPY")), transfers.map { it["rawReadOpcode"] })
        assertEquals(JsonArray(listOf(JsonPrimitive(0))), transfers[1]["rawCopyOpIndices"])
        for (site in sites) {
            assertEquals(JsonPrimitive(false), site["negativeCompleteness"])
            val binding = site.getValue("relocationBinding") as JsonObject
            assertEquals(JsonPrimitive(false), binding["runtimeImplementationAvailable"])
            assertEquals(JsonPrimitive(false), binding["runtimeProviderAvailable"])
        }
    }

    private fun request(root: Path): IndependentExternalCallRequestV1 {
        val snapshotRoot = Files.createDirectories(root.resolve("request-runtime"))
        val bridgeBytes = byteArrayOf(1, 2, 3)
        val manifestBytes = byteArrayOf(4, 5, 6)
        val bridgePath = Files.write(snapshotRoot.resolve("bridge.runtime"), bridgeBytes)
        val manifestPath = Files.write(snapshotRoot.resolve("manifest.runtime"), manifestBytes)
        val bridgeSha = OracleArtifacts.sha256(bridgeBytes)
        val manifestSha = OracleArtifacts.sha256(manifestBytes)
        val runtime = MachineCallRuntimeV2(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
            569445154L, bridgeSha, manifestSha, "x86:LE:64:default", "4.8",
            MachineCallFileV1(bridgePath, bridgeBytes.size.toLong(), bridgeSha),
            MachineCallFileV1(manifestPath, manifestBytes.size.toLong(), manifestSha))
        return IndependentExternalCallRequestV1(
            MachineCallFileV1(root.resolve("rich.elf"), 3, "1".repeat(64)),
            MachineCallFileV1(root.resolve("source-report.json"), 3, "2".repeat(64)),
            MachineCallFileV1(root.resolve("source-request.json"), 3, "3".repeat(64)),
            runtime, root.resolve("output.json"))
    }
    private fun document(request: IndependentExternalCallRequestV1) = OracleJson.parseCanonical(request.canonicalBytes) as JsonObject
    private fun parse(document: JsonObject) = IndependentExternalCallRequestV1.parse(OracleJson.canonicalBytes(document))

    private fun fakeRecord(root: Path, action: (Class<*>) -> Unit) {
        val source = Files.writeString(root.resolve("FakeStaticBridge.java"), """
            import java.util.List;
            import java.util.ArrayList;
            public class FakeStaticBridge {
                public record StaticMemoryTransfer(String address, int length, byte[] bytes, String classification,
                    String pointerSlotAddress, Integer pointerWidthBytes, String relationship, String rawReadOpcode, Integer rawReadOpIndex,
                    String rawTransferOpcode, Integer rawTransferOpIndex, List<Integer> rawCopyOpIndices, String contextStatus, String unresolvedReason) {}
                public record Extra(String address, boolean hidden) {}
                public record WrongType(String address, Integer length, byte[] bytes, String classification,
                    String pointerSlotAddress, Integer pointerWidthBytes, String relationship, String rawReadOpcode, Integer rawReadOpIndex,
                    String rawTransferOpcode, Integer rawTransferOpIndex, List<Integer> rawCopyOpIndices, String contextStatus, String unresolvedReason) {}
                public static Object extra() { return new Extra("0x401000", true); }
                public static Object wrongType() { return new WrongType("0x401000",6,new byte[]{(byte)255,21,0,0,0,0},"indirect-call",
                    "0x5000",8,"static-ram-varnode-exact-transfer-v1","COPY",0,"CALLIND",3,List.of(0),"language-default-no-commits-v1",null); }
                public static StaticMemoryTransfer sample() {
                    return new StaticMemoryTransfer("0x401000",6,new byte[]{(byte)255,21,0,0,0,0},"indirect-call",
                        "0x5000",8,"static-ram-varnode-exact-transfer-v1","COPY",0,"CALLIND",3,
                        new ArrayList<Integer>(List.of(0)),"language-default-no-commits-v1",null);
                }
                public static StaticMemoryTransfer unresolved() {
                    return new StaticMemoryTransfer("0x401000",2,new byte[]{(byte)255,(byte)208},"indirect-call",
                        null,null,"unresolved",null,null,"CALLIND",3,List.of(),"language-default-no-commits-v1","register-transfer");
                }
            }
        """.trimIndent())
        val classes = Files.createDirectory(root.resolve("classes"))
        assertEquals(0, requireNotNull(ToolProvider.getSystemJavaCompiler()).run(null, null, null, "-proc:none", "-d", classes.toString(), source.toString()))
        URLClassLoader(arrayOf(classes.toUri().toURL()), ClassLoader.getPlatformClassLoader()).use { loader -> action(Class.forName("FakeStaticBridge", false, loader)) }
    }

    private fun freshWorker(root: Path, label: String, classpath: String, main: String, request: Path, digest: String) {
        val home = Files.createDirectory(root.resolve("$label-home"))
        val temporary = Files.createDirectory(root.resolve("$label-tmp"))
        val log = Files.createTempDirectory(root.parent, "runtime-evidence-").resolve("$label-worker.log")
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx512m",
            "-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary",
            "-cp", classpath, main, request.toString(), digest).directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
                environment().clear()
                environment()["HOME"] = home.toString(); environment()["TMPDIR"] = temporary.toString()
                environment()["XDG_CACHE_HOME"] = temporary.toString(); environment()["XDG_CONFIG_HOME"] = home.toString()
                environment()["LANG"] = "C.UTF-8"
            }.start()
        try {
            assertTrue(process.waitFor(90, TimeUnit.SECONDS), "$label worker timed out: ${Files.readString(log).takeLast(16000)}")
            assertEquals(0, process.exitValue(), Files.readString(log).takeLast(16000))
        } finally {
            if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            process.outputStream.close(); process.inputStream.close(); process.errorStream.close()
        }
    }

    private fun fixture(action: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build", "external-call-worker-tests").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(parent, "fixture-")
        try { action(root) } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
