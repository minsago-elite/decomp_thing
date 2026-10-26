package decompengine.project

import io.github.optimumcode.json.schema.JsonSchema
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.test.*
import kotlinx.serialization.json.*

/** Real bounded native decompilation of authored instructions; no constructor-only HighFunction proof. */
class NativeInferredInterfaceCollectorRealTest {
    @Test
    fun `fresh bundled inference preserves listing census type graphs and unknown semantics`(): Unit {
        val repository = Path.of("").toAbsolutePath().normalize()
        val parent = repository.resolve("build/native-inferred-interface-real-controls")
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "inferred-")
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
        val source = root.resolve("NativeInferredInterfaceControls.java")
        checkNotNull(javaClass.getResourceAsStream("/nativeinterfaces/NativeInferredInterfaceControls.java"))
            .use { Files.copy(it, source) }
        val graphControls = root.resolve("NativeInterfaceTypeGraphControls.java")
        checkNotNull(javaClass.getResourceAsStream("/nativeinterfaces/NativeInterfaceTypeGraphControls.java"))
            .use { Files.copy(it, graphControls) }
        val failureControls = root.resolve("NativeInferredFailureDiagnosticsControls.java")
        checkNotNull(javaClass.getResourceAsStream("/nativeinterfaces/NativeInferredFailureDiagnosticsControls.java"))
            .use { Files.copy(it, failureControls) }
        val collector = repository.resolve("ghidra-bridge/src/main/java/ExportInferredInterfacesV1.java")
        val listingCollector = repository.resolve("ghidra-bridge/src/main/java/ExportNativeInterfacesV1.java")
        val typeGraph = repository.resolve("ghidra-bridge/src/main/java/NativeInterfaceTypeGraphV1.java")
        val callCollector = repository.resolve("ghidra-bridge/src/main/java/ExportNativeCallsV1.java")
        val exporter = repository.resolve("src/main/resources/ghidra_scripts/ExportProgramModel.java")
        val dispatch = repository.resolve("ghidra-bridge/src/main/java/RunBundledExports.java")
        val worker = repository.resolve("ghidra-bridge/src/main/java/decompengine/ghidra/BundledGhidraWorker.java")
        val nativeDecompiler = release.resolve("Ghidra/Features/Decompiler/os/linux_x86_64/decompile")
        assertTrue(Files.isExecutable(nativeDecompiler), "actual bundled native decompiler missing")
        val classes = Files.createDirectory(root.resolve("classes"))
        val classpath = jars.joinToString(System.getProperty("path.separator"))
        val javaBin = Path.of(System.getProperty("java.home"), "bin")
        val javaProperties = listOf("-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary", "-Duser.home=$home", "-Djava.awt.headless=true", "-XX:-UsePerfData")
        run(root, listOf(javaBin.resolve("javac").toString()) + javaProperties.map { "-J$it" } +
            listOf("-proc:none", "-cp", classpath, "-d", classes.toString()) +
            listOf(source, graphControls, failureControls, collector, listingCollector, typeGraph, callCollector, exporter, dispatch, worker).map(Path::toString),
            "compile-controls", Duration.ofSeconds(45))
        run(root, listOf(javaBin.resolve("java").toString(), "-Xmx1g") + javaProperties +
            listOf("-cp", "$classes${System.getProperty("path.separator")}$classpath", "NativeInferredInterfaceControls",
                release.toString(), root.toString(), collector.toString(), listingCollector.toString(), exporter.toString(), dispatch.toString(), typeGraph.toString()),
            "native-control", Duration.ofSeconds(120))
        val controls = Files.readString(root.resolve("verified-controls.txt"))
        for (required in listOf("actual-bundled-native-decompilation", "model-unchanged", "listing-unchanged", "program-unchanged", "same-census-mutation-rejected"))
            assertTrue(controls.contains(required), "actual control missing: $required")
        for (captureRoot in listOf(root, root.resolve("windows-inferred"))) {
            for ((file, schema) in listOf(
                "native-inferred-interfaces.json" to "/project/native-inferred-interface-observations-v1.schema.json",
                "manifest.json" to "/project/native-inferred-interface-observation-manifest-v1.schema.json",
            )) {
                val definition = checkNotNull(javaClass.getResourceAsStream(schema)).use { it.readBytes().decodeToString() }
                val actual = Json.parseToJsonElement(Files.readString(captureRoot.resolve("first-inferred/$file")))
                assertTrue(JsonSchema.fromDefinition(definition).validate(actual) {}, "actual output violates $schema at $captureRoot")
            }
        }
        assertStagingControls(root)
        assertFailureDiagnostics(root)
        val controlReceipt = Json.parseToJsonElement(Files.readString(root.resolve("verified-control-receipt.json"))).jsonObject
        assertTrue(controlReceipt.getValue("fixtureOnly").jsonPrimitive.boolean)
        val nativeRows = controlReceipt.getValue("functions").jsonArray.map { it.jsonObject }
        assertEquals(14, nativeRows.size)
        val integer = nativeRows.single { it.getValue("authoredLabel").jsonPrimitive.content == "integer_add" }
        assertEquals(0, integer.getValue("listingParameterCount").jsonPrimitive.int)
        assertEquals(2, integer.getValue("inferredParameterCount").jsonPrimitive.int)
        val ninth = nativeRows.single { it.getValue("authoredLabel").jsonPrimitive.content == "ninth_sse" }
        assertEquals(8, ninth.getValue("inferredParameterCount").jsonPrimitive.int)
        assertFalse(controlReceipt.getValue("productionInterfacesAdmitted").jsonPrimitive.boolean)
        validateActual(root, collector, listingCollector, typeGraph, exporter, dispatch, nativeDecompiler)
        val windows = root.resolve("windows-inferred")
        assertTrue(Files.readString(windows.resolve("verified-controls.txt")).contains("independent-real-native-prototype-symbol-comparison"))
        val windowsReceipt = Json.parseToJsonElement(Files.readString(windows.resolve("verified-control-receipt.json"))).jsonObject
        assertEquals("windows", windowsReceipt.getValue("compilerSpecId").jsonPrimitive.content)
        assertEquals(2, windowsReceipt.getValue("functions").jsonArray.size)
        val method = windowsReceipt.getValue("functions").jsonArray.map { it.jsonObject }
            .single { it.getValue("authoredLabel").jsonPrimitive.content == "windows_aggregate_method" }
        assertTrue(method.getValue("nativeHasThis").jsonPrimitive.boolean)
        val methodParameters = method.getValue("parameters").jsonArray.map { it.jsonObject }
        assertTrue(methodParameters[0].getValue("isThisPointer").jsonPrimitive.boolean)
        assertTrue(methodParameters[1].getValue("isHiddenReturn").jsonPrimitive.boolean)
        assertFalse(methodParameters[2].getValue("rawStorageForcedIndirect").jsonPrimitive.boolean)
        assertEquals("unavailable-native-api", windowsReceipt.getValue("formalEffectiveMeaning").jsonPrimitive.content)
        assertEquals("unavailable-for-plain-decoded-storage", windowsReceipt.getValue("forcedIndirectMeaning").jsonPrimitive.content)
        assertFalse(windowsReceipt.getValue("productionInterfacesAdmitted").jsonPrimitive.boolean)
        assertTrue(windowsReceipt.getValue("successfulInferenceDiagnosticSilence").jsonPrimitive.boolean)
        validateActual(windows, collector, listingCollector, typeGraph, exporter, dispatch, nativeDecompiler)
    }

    private fun assertFailureDiagnostics(root: Path) {
        val evidence = root.resolve("failure-diagnostics-controls")
        val pure = Json.parseToJsonElement(Files.readString(evidence.resolve("pure-controls.json"))).jsonObject
        assertEquals("authored-inferred-failure-diagnostics-controls-v1", pure.getValue("kind").jsonPrimitive.content)
        assertTrue(pure.getValue("fixtureOnly").jsonPrimitive.boolean)
        assertFalse(pure.getValue("nativeExecutionClaimed").jsonPrimitive.boolean)
        assertFalse(pure.getValue("productionInterfacesAdmitted").jsonPrimitive.boolean)
        assertFalse(pure.getValue("releaseEligible").jsonPrimitive.boolean)
        val cases = pure.getValue("cases").jsonArray.map { it.jsonPrimitive.content }
        val expected = setOf(
            "failure-before-census-retains-unknowns",
            "pre-call-zero-seconds-is-not-a-started-call",
            "in-flight-exception-retains-unreturned-state",
            "returned-before-checkpoint-failure-keeps-timeout-unknown-and-duration-frozen",
            "observed-timeout-is-distinct-from-unread-timeout",
            "nonoverlapping-stage-totals-and-first-freeze-survive-cleanup",
            "fixed-four-returned-calls-use-deterministic-duration-ordinal-order",
            "maximum-count-address-and-time-render-within-framed-4096-bytes",
            "success-is-silent-and-failure-emission-occurs-at-most-once",
            "diagnostic-output-failure-never-replaces-or-retries-original-failure",
            "listing-check-cancellation-preserves-first-exception-before-expired-deadline",
            "listing-query-true-short-circuits-expired-deadline",
            "listing-query-false-deadline-freezes-one-guard-sample",
            "listing-check-deadline-preserves-cancelled-exception-type",
            "invalid-passive-state-omits-diagnostic-without-product-exception",
        )
        assertEquals(expected.size, cases.size)
        assertEquals(expected, cases.toSet())
        val cancellation = Json.parseToJsonElement(Files.readString(evidence.resolve("listing-cancellation.json"))).jsonObject
        assertEquals("authored-inferred-listing-cancellation-control-v1", cancellation.getValue("kind").jsonPrimitive.content)
        for (field in listOf("fixtureOnly", "actualListingBridgeObserved", "emittedBeforeListingCleanup", "originalExceptionPreserved", "completeFrozenCensusRetained",
            "outputAndComparisonAbsent", "frozenInputsAndProgramUnchanged")) {
            assertTrue(cancellation.getValue(field).jsonPrimitive.boolean, "actual cancellation control missing: $field")
        }
        assertFalse(cancellation.getValue("productionInterfacesAdmitted").jsonPrimitive.boolean)
        for (file in listOf("direct-cancellation.stderr", "listing-cancellation.stderr", "staging-refusal.stderr")) {
            val bytes = Files.readAllBytes(evidence.resolve(file))
            assertTrue(bytes.size <= 1024 * 1024)
            val prefix = "DECOMP_INFERRED_FAILURE_V1 "
            // This is the complete authored fixture stream, not the production raw-tail reader.
            val frames = bytes.decodeToString().lineSequence().filter { it.startsWith(prefix) }.toList()
            assertEquals(1, frames.size, file)
            assertTrue((frames.single() + "\n").toByteArray(Charsets.UTF_8).size <= 4096)
            val frame = Json.parseToJsonElement(frames.single().removePrefix(prefix)).jsonObject
            assertEquals("diagnostic-only", frame.getValue("authority").jsonPrimitive.content)
            for (flag in listOf("complete", "productionInterfacesAdmitted", "releaseEligible"))
                assertFalse(frame.getValue(flag).jsonPrimitive.boolean)
        }
        assertFalse(Files.exists(root.resolve("listing-cancelled-inferred")))
    }

    private fun assertStagingControls(root: Path) {
        val evidence = root.resolve("staging-budget-controls")
        val receipt = Json.parseToJsonElement(Files.readString(evidence.resolve("verified-staging-controls.json"))).jsonObject
        fun number(name: String) = receipt.getValue(name).jsonPrimitive.long
        assertEquals("authored-native-interface-staging-budget-control-v1", receipt.getValue("kind").jsonPrimitive.content)
        assertTrue(receipt.getValue("fixtureOnly").jsonPrimitive.boolean)
        assertEquals(number("measuredChargedPeakBytes"), number("exactLimitBytes"))
        assertEquals(number("exactLimitBytes"), number("exactObservedPeakBytes"))
        assertEquals(number("exactLimitBytes") - 1, number("belowLimitBytes"))
        assertTrue(number("belowLimitBytes") >= number("finalListingBytes") + number("manifestReservationBytes"))
        assertTrue(number("largerActualFinalListingBytes") > number("finalListingBytes"))
        assertEquals(number("largerActualFinalListingBytes") + number("manifestReservationBytes"), number("staleComparisonAvailableBytes"))
        assertTrue(number("staleComparisonAvailableBytes") < number("largerActualChargedPeakBytes"))
        assertEquals(number("staleFrozenInputBytes") + number("staleComparisonAvailableBytes"), number("staleCombinedLimitBytes"))
        assertTrue(number("staleCombinedLimitBytes") < 4L * 1024 * 1024)
        for (field in listOf("belowRejectedWithOutputAndSpoolLive", "belowOutputRemoved", "boundedOutputMatchesOrdinaryBytes",
            "staleRejectedDuringBoundedWrites", "staleInferredAndComparisonRemoved", "frozenInputsUnchanged", "boundedFailureDiagnosticRetained",
            "ownedComparisonExactPeakReachedContentCheck", "ownedComparisonOneOverRejectedBeforeWrite", "ownedComparisonFinalBytesFitBothLimits")) {
            assertTrue(receipt.getValue(field).jsonPrimitive.boolean, "staging control missing: $field")
        }
        assertEquals(2L * 64 * 1024 * 1024, number("ownedStreamReservationBytes"))
        assertTrue(receipt.getValue("belowFailure").jsonPrimitive.content.contains("while output and type spool are live"))
        assertTrue(receipt.getValue("staleFailure").jsonPrimitive.content.contains("while output and type spool are live"))
        assertFalse(Files.exists(evidence.resolve("one-below-peak-listing")))
        assertFalse(Files.exists(evidence.resolve("stale-smaller-inferred")))
        assertFalse(receipt.getValue("authoritativeOracleEvidence").jsonPrimitive.boolean)
        assertFalse(receipt.getValue("productionInterfacesAdmitted").jsonPrimitive.boolean)
        assertFalse(receipt.getValue("releaseEligible").jsonPrimitive.boolean)
    }

    private fun validateActual(root: Path, collector: Path, listingCollector: Path, typeGraph: Path, exporter: Path, dispatch: Path, nativeDecompiler: Path) {
        val native = Json.parseToJsonElement(Files.readString(root.resolve("native-properties.json"))).jsonObject
        val document = Json.parseToJsonElement(Files.readString(root.resolve("first-inferred/native-inferred-interfaces.json"))).jsonObject
        val imageSpace = document.getValue("addressSpaces").jsonArray.map { it.jsonObject }
            .single { it.getValue("name").jsonPrimitive.content == native.getValue("imageBaseSpace").jsonPrimitive.content }
        val model = root.resolve("reports/program_model.json")
        val listing = root.resolve("frozen-listing/native-interfaces.json")
        val listingManifest = root.resolve("frozen-listing/manifest.json")
        val listingBindings = NativeInterfaceBindingsV1(
            collectorSha256 = sha256(listingCollector), compilerSpecId = native.getValue("compilerSpecId").jsonPrimitive.content,
            ghidraArchiveSha256 = "93a5d11a9ad510622acaaf908c556a7b9b764d338e78a7567f3689bf5081fd54",
            imageBase = NativeInterfaceAddressV1(imageSpace.getValue("index").jsonPrimitive.int, native.getValue("imageBaseOffsetBits").jsonPrimitive.content),
            inputSha256 = sha256(root.resolve("synthetic-input.bin")), languageId = native.getValue("languageId").jsonPrimitive.content,
            programModelBytes = Files.size(model), programModelExporterSha256 = sha256(exporter), programModelSha256 = sha256(model),
        )
        val configurationSha = NativeInferredInterfaceObservationsV1.configurationSha256
        val bindings = NativeInferredInterfaceBindingsV1(
            listingBindings = listingBindings, collectorSha256 = sha256(collector), wrapperSha256 = sha256(dispatch),
            nativeDecompilerSha256 = sha256(nativeDecompiler), listingBytes = Files.size(listing), listingSha256 = sha256(listing),
            listingManifestSha256 = sha256(listingManifest), configurationSha256 = configurationSha, typeGraphSha256 = sha256(typeGraph),
        )
        val seen = mutableListOf<NativeInferredInterfaceRecordV1>()
        val receipt = NativeInferredInterfaceObservationsV1.validate(
            manifestBytes = Files.readAllBytes(root.resolve("first-inferred/manifest.json")), expectedBindings = bindings,
            programModelBytes = Files.readAllBytes(model), listingManifestBytes = Files.readAllBytes(listingManifest),
            checkpoint = {}, openListing = { Files.newInputStream(listing) },
            openObservations = { Files.newInputStream(root.resolve("first-inferred/native-inferred-interfaces.json")) }, consume = seen::add,
        )
        assertFalse(receipt.authoritativeOracleEvidence)
        assertFalse(receipt.productionInterfacesAdmitted)
        assertFalse(receipt.releaseEligible)
        assertTrue(seen.isNotEmpty(), "closed reader consumed no actual records")
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
        val process = ProcessBuilder(arguments).directory(root.toFile()).redirectErrorStream(true).redirectOutput(log.toFile()).also {
            it.environment().remove("JAVA_TOOL_OPTIONS")
            it.environment().remove("JDK_JAVA_OPTIONS")
            it.environment().remove("_JAVA_OPTIONS")
            it.environment()["TMPDIR"] = root.resolve("tmp").toString()
            it.environment()["XDG_CACHE_HOME"] = root.resolve("home/cache").toString()
            it.environment()["XDG_CONFIG_HOME"] = root.resolve("home/config").toString()
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
