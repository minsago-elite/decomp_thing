package decompengine.oracle.externalcalls

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.gcc.GccKotlinBootClasspathReference
import decompengine.oracle.machinecalls.MachineCallFileV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV1
import decompengine.oracle.machinecalls.MachineCallRuntimeV2
import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class RecoveredExternalNamespaceWorkerV1Test {
    private fun live(request: RecoveredExternalNamespaceRequestV1, root: Path, name: String,
        materializeRuntime: Boolean = false): RecoveredExternalNamespaceRequestV2 {
        val control = Files.createDirectories(root.resolve("$name-control"))
        Files.createDirectories(control.resolve("reports"))
        Files.createDirectories(control.resolve("runtime"))
        val legacy = request.copy(outputPath = control.resolve("reports/recovered-external-call-observations.json"))
        fun snapshot(role: decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole): MachineCallFileV1 {
            val source = legacy.runtime.bundleRoot.resolve(role.sourceName)
            val destination = control.resolve("runtime/${role.snapshotName}")
            val sha = if (role == decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE)
                legacy.runtime.bridgeSha256 else legacy.runtime.bundleManifestSha256
            if (!materializeRuntime) return MachineCallFileV1(destination, 1, sha)
            val bytes = Files.readAllBytes(source)
            assertEquals(sha, sha(bytes))
            Files.write(destination, bytes)
            Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r--------"))
            return MachineCallFileV1(destination, bytes.size.toLong(), sha)
        }
        val runtime = MachineCallRuntimeV2(legacy.runtime.bundleRoot, legacy.runtime.ghidraArchivePath,
            legacy.runtime.archiveSha256, legacy.runtime.archiveBytes, legacy.runtime.bridgeSha256,
            legacy.runtime.bundleManifestSha256, legacy.runtime.languageId, legacy.runtime.languageVersion,
            snapshot(decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BRIDGE),
            snapshot(decompengine.oracle.fulltree.FullTreeFunctionObservationRuntimeArtifactRole.GHIDRA_BUNDLE_MANIFEST))
        return RecoveredExternalNamespaceRequestV2(legacy, runtime, control)
    }

    @Test fun `live v2 recovered request binds each snapshot and report to its owned control root`() = fixture { root ->
        val source = request(root)
        val control = root.resolve("owned-recovered-control")
        val legacy = source.copy(outputPath = control.resolve("reports/recovered-external-call-observations.json"))
        val runtime = MachineCallRuntimeV2(legacy.runtime.bundleRoot, legacy.runtime.ghidraArchivePath,
            legacy.runtime.archiveSha256, legacy.runtime.archiveBytes, legacy.runtime.bridgeSha256, legacy.runtime.bundleManifestSha256,
            legacy.runtime.languageId, legacy.runtime.languageVersion,
            MachineCallFileV1(control.resolve("runtime/ghidra-bridge.runtime"), 1, legacy.runtime.bridgeSha256),
            MachineCallFileV1(control.resolve("runtime/ghidra-bundle-manifest.runtime"), 1, legacy.runtime.bundleManifestSha256))
        val live = RecoveredExternalNamespaceRequestV2(legacy, runtime, control)
        val parsed = RecoveredExternalNamespaceRequestV2.parse(live.canonicalBytes)
        assertEquals(live, parsed)
        assertContentEquals(live.canonicalBytes, parsed.canonicalBytes)
        assertFails { RecoveredExternalNamespaceRequestV2.parse(OracleJson.canonicalBytes(
            JsonObject((OracleJson.parseCanonical(live.canonicalBytes) as JsonObject) +
                ("controlRoot" to JsonPrimitive(root.resolve("confused-root").toString()))))) }
        assertFails { RecoveredExternalNamespaceRequestV1.parse(live.canonicalBytes) }
    }
    @Test fun `closed request preserves native artifact runtime and bounded composition commitments`() = fixture { root ->
        val original = request(root)
        val parsed = RecoveredExternalNamespaceRequestV1.parse(original.canonicalBytes)
        assertEquals(original, parsed)
        assertContentEquals(original.canonicalBytes, parsed.canonicalBytes)
        assertFails { RecoveredExternalNamespaceRequestV1.parse(original.canonicalBytes + byteArrayOf(10)) }
        assertFails { RecoveredExternalNamespaceRequestV1.parse(ByteArray(65537) { 32 }) }
        val document = document(original)
        assertEquals(JsonPrimitive("recovered-external-namespace-request-v1"), document["kind"])
        assertEquals(JsonPrimitive(1), document["schemaVersion"])
    }

    @Test fun `request closes every nested object and refuses extra truth or selected namespace inputs`() = fixture { root ->
        val document = document(request(root))
        val nested = listOf("nativeManifest", "nativeObservations", "artifactManifest", "richFile", "strippedFile",
            "expectedNativeBindings", "runtime", "limits")
        for (unknown in listOf("sourceReport", "oracleCalls", "programModel", "externalNamespace", "selectedMapping", "unknown")) {
            assertFails(unknown) { parse(JsonObject(document + (unknown to JsonPrimitive("forbidden")))) }
            for (key in nested) {
                val inner = document.getValue(key) as JsonObject
                assertFails("$key.$unknown") { parse(JsonObject(document + (key to JsonObject(inner + (unknown to JsonPrimitive(1)))))) }
            }
        }
        for (key in document.keys) assertFails(key) { parse(JsonObject(document - key)) }
        for (key in nested) {
            val inner = document.getValue(key) as JsonObject
            for (field in inner.keys) assertFails("$key.$field") { parse(JsonObject(document + (key to JsonObject(inner - field)))) }
        }
        val bindings = document.getValue("expectedNativeBindings") as JsonObject
        val base = bindings.getValue("imageBase") as JsonObject
        assertFails { parse(JsonObject(document + ("expectedNativeBindings" to JsonObject(bindings +
            ("imageBase" to JsonObject(base + ("unknown" to JsonPrimitive(true)))))))) }
        assertFails { parse(JsonObject(document + ("schemaVersion" to JsonPrimitive("1")))) }
    }

    @Test fun `request caps files and limits binds stripped input and rejects path overlap`() = fixture { root ->
        val request = request(root)
        assertFails { request.copy(nativeManifest = request.nativeManifest.copy(bytes = 65537)) }
        assertFails { request.copy(nativeObservations = request.nativeObservations.copy(bytes = 64L * 1024 * 1024 + 1)) }
        assertFails { request.copy(artifactManifest = request.artifactManifest.copy(bytes = 2L * 1024 * 1024 + 1)) }
        assertFails { request.copy(richFile = request.richFile.copy(bytes = 512L * 1024 * 1024 + 1)) }
        assertFails { request.copy(strippedFile = request.strippedFile.copy(bytes = 512L * 1024 * 1024 + 1)) }
        assertFails { request.copy(nativeManifest = request.nativeObservations) }
        for (input in listOf(request.nativeManifest, request.nativeObservations, request.artifactManifest, request.richFile, request.strippedFile))
            assertFails { request.copy(outputPath = input.path) }
        assertFails { request.copy(outputPath = request.runtime.ghidraArchivePath) }
        assertFails { request.copy(outputPath = request.runtime.bundleRoot.resolve("output.json")) }
        assertFails { request.copy(outputPath = root.resolve("unused/../output.json")) }
        assertFails { request.copy(outputPath = Path.of("relative.json")) }
        assertFails { request.copy(expectedNativeBindings = request.expectedNativeBindings.copy(inputSha256 = "f".repeat(64))) }
        assertFails { request.copy(expectedNativeBindings = request.expectedNativeBindings.copy(ghidraArchiveSha256 = "f".repeat(64))) }
        assertFails { request.copy(expectedNativeBindings = request.expectedNativeBindings.copy(languageId = "x86:LE:32:default")) }
        val document = document(request)
        val limits = document.getValue("limits") as JsonObject
        for (key in limits.keys) for (value in listOf(JsonPrimitive(0), JsonPrimitive(Long.MAX_VALUE), JsonPrimitive("1"))) {
            assertFails("$key=$value") { parse(JsonObject(document + ("limits" to JsonObject(limits + (key to value))))) }
        }
        val bindings = document.getValue("expectedNativeBindings") as JsonObject
        for (key in listOf("collectorSha256", "programModelExporterSha256", "programModelSha256"))
            assertFails(key) { parse(JsonObject(document + ("expectedNativeBindings" to JsonObject(bindings + (key to JsonPrimitive("not-a-digest")))))) }
        val runtime = document.getValue("runtime") as JsonObject
        for ((key, value) in mapOf("archiveSha256" to JsonPrimitive("0".repeat(64)), "archiveBytes" to JsonPrimitive(1),
            "languageId" to JsonPrimitive("x86:LE:32:default"), "languageVersion" to JsonPrimitive("4.7"),
            "bridgeSha256" to JsonPrimitive("not-a-digest"))) assertFails(key) {
            parse(JsonObject(document + ("runtime" to JsonObject(runtime + (key to value)))))
        }
    }

    @Test fun `malformed native census fails before absent ELF files are opened`() = fixture { root ->
        val original = runtimeBound(nativeExternalFixtureV1(), runtime(root))
        val malformed = original.replace(listOf("summary", "sites"), JsonPrimitive(99))
        val request = live(nativeRequest(root, malformed), root, "malformed")
        val path = Files.write(root.resolve("request.json"), request.canonicalBytes)
        val stages = mutableListOf<String>()
        val failure = assertFails {
            RecoveredExternalNamespaceWorkerV1.run(path, sha(request.canonicalBytes), stages::add)
        }
        assertTrue(failure is IllegalArgumentException, "native validation must fail before opening missing ELF inputs: $failure")
        assertFalse("after-native-freeze" in stages)
        assertFalse(Files.exists(request.artifactManifest.path))
        assertFalse(Files.exists(request.richFile.path))
        assertFalse(Files.exists(request.strippedFile.path))
        assertFalse(Files.exists(request.outputPath))
    }

    @Test fun `changed request and native input pins fail before freeze or publication`() = fixture { root ->
        val native = runtimeBound(nativeExternalFixtureV1(), runtime(root))
        val request = live(nativeRequest(root, native), root, "changed")
        val requestPath = Files.write(root.resolve("request.json"), request.canonicalBytes)
        assertFails { RecoveredExternalNamespaceWorkerV1.run(requestPath, "0".repeat(64)) }
        for (input in listOf(request.nativeManifest, request.nativeObservations)) {
            val original = Files.readAllBytes(input.path)
            val replacement = original.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
            Files.write(input.path, replacement)
            val stages = mutableListOf<String>()
            assertFails { RecoveredExternalNamespaceWorkerV1.run(requestPath, sha(request.canonicalBytes), stages::add) }
            assertFalse("after-native-freeze" in stages)
            assertFalse(Files.exists(request.outputPath))
            Files.write(input.path, original)
        }
    }

    @Test fun `native path replacement after freeze is rejected before absent ELF input access`() = fixture { root ->
        val native = runtimeBound(nativeExternalFixtureV1(), runtime(root))
        val request = live(nativeRequest(root, native), root, "replacement")
        val requestPath = Files.write(root.resolve("request.json"), request.canonicalBytes)
        val replacement = Files.write(root.resolve("replacement-native.json"), native.observationBytes())
        var replaced = false
        val failure = assertFails {
            RecoveredExternalNamespaceWorkerV1.run(requestPath, sha(request.canonicalBytes)) { stage ->
                if (stage == "after-native-freeze") {
                    assertFalse(replaced)
                    Files.move(replacement, request.nativeObservations.path, StandardCopyOption.REPLACE_EXISTING)
                    replaced = true
                }
            }
        }
        assertTrue(replaced, "the fully validated native census must be frozen first")
        assertFalse(failure.toString().contains(request.artifactManifest.path.toString()), "held native continuity must fail before ELF access: $failure")
        assertFalse(Files.exists(request.outputPath))
    }

    @Test fun `every independent ELF input remains bound after native selection`(): Unit =
        withRecoveredExternalFixtureV1 { files, original ->
            val native = runtimeBound(original, runtime(files.root))
            val request = live(nativeRequest(files.root, native).copy(
                artifactManifest = pin(files.manifest), richFile = pin(files.rich), strippedFile = pin(files.stripped))
                , files.root, "elf-pins")
            val requestPath = Files.write(files.root.resolve("request.json"), request.canonicalBytes)
            for (input in listOf(request.artifactManifest, request.richFile, request.strippedFile)) {
                val bytes = Files.readAllBytes(input.path)
                Files.write(input.path, bytes.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() })
                val stages = mutableListOf<String>()
                val failure = assertFails { RecoveredExternalNamespaceWorkerV1.run(requestPath, sha(request.canonicalBytes), stages::add) }
                assertTrue("after-native-freeze" in stages)
                assertTrue(failure.toString().contains("bytes or SHA-256 differ"), "input pin must fail before parser or runtime: $failure")
                assertFalse(Files.exists(request.outputPath))
                Files.write(input.path, bytes)
            }
        }

    @Test fun `existing output remains untouched on worker refusal`() = fixture { root ->
        val native = runtimeBound(nativeExternalFixtureV1(), runtime(root))
        val request = live(nativeRequest(root, native), root, "existing-output")
        val sentinel = "existing result must survive".toByteArray()
        Files.write(request.outputPath, sentinel)
        val path = Files.write(root.resolve("request.json"), request.canonicalBytes)
        val failure = assertFails { RecoveredExternalNamespaceWorkerV1.run(path, sha(request.canonicalBytes)) }
        assertTrue(failure.toString().contains("output", ignoreCase = true), "existing output must fail at preflight: $failure")
        assertContentEquals(sentinel, Files.readAllBytes(request.outputPath))
    }

    @Test fun `fresh authenticated worker refines existing claims with actual byte witnesses and preserves unknown census`(): Unit =
        withRecoveredExternalFixtureV1 { files, original ->
            val runtime = actualRuntime()
            val native = runtimeBound(original, runtime)
            val request = live(nativeRequest(files.root, native, runtime).copy(
                artifactManifest = pin(files.manifest), richFile = pin(files.rich), strippedFile = pin(files.stripped)),
                files.root, "authenticated", materializeRuntime = true)
            val requestPath = Files.write(files.root.resolve("request.json"), request.canonicalBytes)
            val requestSha = sha(request.canonicalBytes)
            freshWorker(files.root, requestPath, requestSha)
            val outputBytes = Files.readAllBytes(request.outputPath)
            val output = OracleJson.parseCanonical(outputBytes) as JsonObject
            validateRecoveredExternalWorkerCommitmentsV1(output, requestSha, request)
            val sites = (output.getValue("sites") as JsonArray).map { it as JsonObject }
            assertEquals(3, sites.size)
            assertEquals(listOf("verified-object-local-import-request", "verified-object-local-import-request", "unresolved-frozen-native-claim"),
                sites.map { (it.getValue("disposition") as JsonPrimitive).content })
            assertEquals(sites[0]["externalTargetId"], sites[1]["externalTargetId"])
            assertNotEquals(JsonNull, sites[0]["externalTargetId"])
            assertEquals(JsonNull, sites[2]["externalTargetId"])
            assertEquals(JsonNull, sites[2]["candidateImportRequestId"])
            assertEquals(listOf(JsonPrimitive("native-site-0"), JsonPrimitive("native-site-1"), JsonPrimitive("native-site-2")), sites.map { it["siteId"] })
            val physical = sites.take(2).map { it.getValue("physicalInstruction") as JsonObject }
            assertEquals(listOf(JsonPrimitive("direct-call"), JsonPrimitive("indirect-call")), physical.map { it["classification"] })
            assertEquals(listOf(JsonPrimitive("0x400205"), JsonPrimitive("0x400216")), physical.map { it["fallthrough"] })
            val transfers = sites.take(2).map { it.getValue("memoryTransfer") as JsonObject }
            assertEquals(listOf(JsonPrimitive("0x400800"), JsonPrimitive("0x400800")), transfers.map { it["pointerSlotAddress"] })
            assertEquals(listOf(JsonPrimitive("BRANCHIND"), JsonPrimitive("CALLIND")), transfers.map { it["rawTransferOpcode"] })
            assertEquals(JsonPrimitive("authenticated-bundled-worker-v1"), output["decoderAuthentication"])
            assertEquals(JsonPrimitive("external-owner-required"), output["containmentStatus"])
            assertEquals(JsonPrimitive(3L), (output.getValue("counts") as JsonObject)["rawSites"])
            for (flag in listOf("complete", "releaseEligible", "negativeCompleteness", "productionVerified", "runtimeProviderAvailable", "runtimeImplementationAvailable"))
                assertEquals(JsonPrimitive(false), output[flag])

            val frozen = FrozenNativeExternalClaimsV1.freeze(native.manifestBytes(), native.observationBytes(), native.bindings)
            assertEquals(JsonPrimitive(frozen.evidenceSha256), output["frozenClaimsSha256"])
            files.withPair { pair ->
                val component = JsonObject((output - setOf("requestSha256", "runtime", "containmentStatus")) +
                    ("decoderAuthentication" to JsonPrimitive("external-worker-required")))
                RecoveredExternalNamespaceV1.validate(component, frozen, pair, request.limits)
            }
            for (key in listOf("requestSha256", "runtime", "containmentStatus", "decoderAuthentication", "frozenClaimsSha256", "frozenClaimsBinding", "pairProofSha256", "externalNamespaceSha256", "limits"))
                assertFails(key) { validateRecoveredExternalWorkerCommitmentsV1(JsonObject(output + (key to JsonPrimitive("changed"))), requestSha, request) }
            val binding = output.getValue("frozenClaimsBinding") as JsonObject
            for (key in listOf("manifestSha256", "observationsSha256", "inputSha256", "programModelSha256"))
                assertFails(key) { validateRecoveredExternalWorkerCommitmentsV1(JsonObject(output + ("frozenClaimsBinding" to
                    JsonObject(binding + (key to JsonPrimitive("f".repeat(64)))))), requestSha, request) }
            val bindingChanges = mapOf(
                "manifestBytes" to JsonPrimitive(request.nativeManifest.bytes + 1),
                "observationsBytes" to JsonPrimitive(request.nativeObservations.bytes + 1),
                "programModelBytes" to JsonPrimitive(request.expectedNativeBindings.programModelBytes + 1),
                "frozenClaimsBytes" to JsonPrimitive(64L * 1024 * 1024 + 1),
                "rawRecordCount" to JsonPrimitive(362145), "rawSiteCount" to JsonPrimitive(request.limits.maximumSites + 1),
                "rawSourcesRequired" to JsonPrimitive(false), "negativeCompleteness" to JsonPrimitive(true),
                "policySha256" to JsonPrimitive("not-a-digest"), "unknown" to JsonPrimitive(1),
            )
            for ((key, value) in bindingChanges) assertFails(key) {
                validateRecoveredExternalWorkerCommitmentsV1(JsonObject(output + ("frozenClaimsBinding" to JsonObject(binding + (key to value)))), requestSha, request)
            }
            val sourceBindings = binding.getValue("bindings") as JsonObject
            for (key in sourceBindings.keys) assertFails("bindings.$key") {
                validateRecoveredExternalWorkerCommitmentsV1(JsonObject(output + ("frozenClaimsBinding" to
                    JsonObject(binding + ("bindings" to JsonObject(sourceBindings + (key to JsonPrimitive("changed"))))))), requestSha, request)
            }
            assertFails { validateRecoveredExternalWorkerCommitmentsV1(output, "0".repeat(64), request) }
            for (flag in listOf("complete", "releaseEligible", "negativeCompleteness", "productionVerified", "runtimeProviderAvailable", "runtimeImplementationAvailable"))
                assertFails(flag) { validateRecoveredExternalWorkerCommitmentsV1(JsonObject(output + (flag to JsonPrimitive(true))), requestSha, request) }
            assertFails { validateRecoveredExternalWorkerCommitmentsV1(JsonObject(output + ("selectedMapping" to JsonObject(emptyMap()))), requestSha, request) }
        }

    private fun request(root: Path): RecoveredExternalNamespaceRequestV1 {
        val runtime = runtime(root)
        val native = runtimeBound(nativeExternalFixtureV1(), runtime)
        return RecoveredExternalNamespaceRequestV1(
            MachineCallFileV1(root.resolve("native-manifest.json"), 3, "1".repeat(64)),
            MachineCallFileV1(root.resolve("native-calls.json"), 3, "2".repeat(64)),
            MachineCallFileV1(root.resolve("artifact-manifest.json"), 3, "3".repeat(64)),
            MachineCallFileV1(root.resolve("rich.elf"), 3, "4".repeat(64)),
            MachineCallFileV1(root.resolve("stripped.elf"), 3, native.bindings.inputSha256),
            native.bindings, runtime, root.resolve("output.json"))
    }

    private fun nativeRequest(root: Path, native: NativeExternalFixtureV1, runtime: MachineCallRuntimeV1 = runtime(root)): RecoveredExternalNamespaceRequestV1 {
        val observations = Files.write(root.resolve("native-calls.json"), native.observationBytes())
        val manifest = Files.write(root.resolve("native-manifest.json"), native.manifestBytes())
        return request(root).copy(nativeManifest = pin(manifest), nativeObservations = pin(observations),
            strippedFile = MachineCallFileV1(root.resolve("stripped.elf"), 3, native.bindings.inputSha256),
            expectedNativeBindings = native.bindings, runtime = runtime)
    }

    private fun runtimeBound(native: NativeExternalFixtureV1, runtime: MachineCallRuntimeV1): NativeExternalFixtureV1 {
        val bindings = native.bindings.copy(ghidraArchiveSha256 = runtime.archiveSha256, languageId = runtime.languageId)
        val raw = native.document.getValue("bindings") as JsonObject
        return native.copy(bindings = bindings, document = JsonObject(native.document + ("bindings" to JsonObject(raw + mapOf(
            "ghidraArchiveSha256" to JsonPrimitive(bindings.ghidraArchiveSha256), "languageId" to JsonPrimitive(bindings.languageId))))))
    }

    private fun runtime(root: Path) = MachineCallRuntimeV1(root.resolve("bundle"), root.resolve("ghidra.zip"), BundledGhidra.ARCHIVE_SHA256,
        569445154L, "6".repeat(64), "7".repeat(64), "x86:LE:64:default", "4.8")
    private fun actualRuntime(): MachineCallRuntimeV1 {
        val bundle = Path.of(requireNotNull(System.getProperty("decompengine.ghidra.bundle"))).toAbsolutePath().normalize()
        val archive = Path.of(requireNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))).toAbsolutePath().normalize()
        return MachineCallRuntimeV1(bundle, archive, BundledGhidra.ARCHIVE_SHA256, 569445154L,
            sha(Files.readAllBytes(bundle.resolve("decomp-ghidra-bridge.jar"))), sha(Files.readAllBytes(bundle.resolve("bundle.sha256"))),
            "x86:LE:64:default", "4.8")
    }
    private fun pin(path: Path) = MachineCallFileV1(path, Files.size(path), sha(Files.readAllBytes(path)))
    private fun sha(bytes: ByteArray) = OracleArtifacts.sha256(bytes)
    private fun document(request: RecoveredExternalNamespaceRequestV1) = OracleJson.parseCanonical(request.canonicalBytes) as JsonObject
    private fun parse(document: JsonObject) = RecoveredExternalNamespaceRequestV1.parse(OracleJson.canonicalBytes(document))

    private fun freshWorker(root: Path, request: Path, digest: String) {
        val bootRoot = Path.of(requireNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot")))
        val classpath = GccKotlinBootClasspathReference.open().use { reference ->
            reference.entries.joinToString(File.pathSeparator) { bootRoot.resolve(it.logicalName).toString() }
        }
        val home = Files.createDirectory(root.resolve("worker-home"))
        val temporary = Files.createDirectory(root.resolve("worker-tmp"))
        val log = Files.createTempDirectory(root.parent, "recovered-worker-evidence-").resolve("worker.log")
        val process = ProcessBuilder(Path.of(System.getProperty("java.home"), "bin/java").toString(), "-Xmx512m",
            "-XX:-UsePerfData", "-XX:+DisableAttachMechanism", "-Duser.home=$home", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary",
            "-cp", classpath, RecoveredExternalNamespaceWorkerV1::class.java.name, request.toString(), digest)
            .directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).apply {
                environment().clear()
                environment()["HOME"] = home.toString(); environment()["TMPDIR"] = temporary.toString()
                environment()["XDG_CACHE_HOME"] = temporary.toString(); environment()["XDG_CONFIG_HOME"] = home.toString()
                environment()["LANG"] = "C.UTF-8"
            }.start()
        try {
            assertTrue(process.waitFor(90, TimeUnit.SECONDS), "worker timed out: ${Files.readString(log).takeLast(16000)}")
            assertEquals(0, process.exitValue(), Files.readString(log).takeLast(16000))
        } finally {
            if (process.isAlive) { process.destroyForcibly(); assertTrue(process.waitFor(5, TimeUnit.SECONDS)) }
            process.outputStream.close(); process.inputStream.close(); process.errorStream.close()
        }
    }

    private fun fixture(action: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build", "recovered-external-worker-tests").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(parent, "fixture-")
        try { action(root) } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
