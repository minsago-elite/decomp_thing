package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.*
import decompengine.project.*
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.SecureRandom
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag

/** One installed, pinned-driver feasibility run. Retained replay never reconstitutes live authority. */
@Tag("ci-live")
class GccInferredInterfaceQualificationTest {
    @Test
    fun `live pinned driver retains complete owned raw interface observations`() {
        assumeTrue(System.getenv("DECOMP_REQUIRE_GCC_INTERFACE_OBSERVATIONS") == "true",
            "installed pinned-driver interface qualification is opt-in")
        require(listOf("DECOMP_REQUIRE_GCC_CLI_FULL_EXPORT", "DECOMP_REQUIRE_GCC_RUNTIME_DIAGNOSTICS",
            "DECOMP_REQUIRE_GCC_NATIVE_CALLS", "DECOMP_REQUIRE_GCC_ENGINE_CLI").none { System.getenv(it) == "true" })
        require(System.getenv("DECOMP_GCC_CLI_FULL_EXPORT_ENGINE") == "driver")
        val installation = configured("DECOMP_GCC_CLI_INSTALLATION")
        val profilePath = configured("DECOMP_GCC_CLI_PROFILE")
        val archive = configured("DECOMP_GCC_CLI_ARCHIVE")
        val binary = configured("DECOMP_GCC_CLI_EXPORT_BINARY")
        val scratch = configured("DECOMP_GCC_CLI_EXPORT_SCRATCH", "DECOMP_GCC_CLI_CC1_FRESH_SCRATCH")
        val evidence = configured("DECOMP_GCC_CLI_EVIDENCE_ROOT")
        require(profilePath.fileName.toString() == "compiler-engines-exporter17.json")
        require(binary.fileName.toString() == "gcc-driver.stripped")
        require(names(scratch).isEmpty() && names(evidence).isEmpty())
        require(Files.getPosixFilePermissions(evidence) == PosixFilePermissions.fromString("rwx------"))
        for (input in listOf(installation, profilePath, archive, binary, evidence))
            require(!input.startsWith(scratch) && !scratch.startsWith(input))
        val selected = GccRetainedCompilerEngineProfile.open(profilePath, "driver").use {
            it.requireInterfaceObservationProfile()
        }
        val output = directory(evidence.resolve("cli-output"))
        val launcher = directory(evidence.resolve("launcher"))
        val captured = directory(evidence.resolve("captured"))
        val arguments = listOf("driver", binary.toString(), "--profile", profilePath.toString(),
            "--ghidra-archive", archive.toString(), "--output", output.toString(), "--scratch", scratch.toString())
        val options = GccBundledCliOptions.parse(arguments, nativeInterfaceObservations = true)
        assertEquals(FullTreeDiskScratchPolicy(8L * GIB, 64L * GIB, 32768, 1_000_000), options.diskPolicy)
        // Fail before the expensive single run if installDist and this test's deployment generation differ.
        assertContentEquals(read(propertyPath("decompengine.oracle.gcc.bundledGhidraReference"), 8 * MIB),
            read(installation.resolve("lib/gcc-bundled-ghidra-reference-v1.json"), 8 * MIB))
        assertContentEquals(read(propertyPath("decompengine.oracle.gcc.bootKeeperClasspathReference"), 256 * 1024),
            read(installation.resolve("lib/kotlin-boot-classpath-reference-v1.json"), 256 * 1024))

        // These are host-only sentinels, never extra inputs or scripts supplied to recovery.
        val canaryDirectory = directory(binary.parent.resolve(CANARY_DIRECTORY))
        val guards = arrayListOf<StableControlFile>()
        var failure: Throwable? = null
        try {
            val canaries = CANARY_ROLES.associateWith { role ->
                val path = canaryDirectory.resolve("$role.canary")
                publish(path, ByteArray(32).also(SecureRandom()::nextBytes))
                StableControlFile.open(path, 32, "host-only $role canary").also(guards::add)
            }
            val binaryGuard = StableControlFile.open(binary, selected.strippedBinary.bytes, "selected stripped driver").also(guards::add)
            require(binaryGuard.size == selected.strippedBinary.bytes && binaryGuard.authenticatedSha256 == selected.strippedBinary.sha256)
            val richGuard = StableControlFile.open(binary.parent.resolve("gcc-driver.full"), selected.fullBinary.bytes,
                "hidden rich driver").also(guards::add)
            require(richGuard.size == selected.fullBinary.bytes && richGuard.authenticatedSha256 == selected.fullBinary.sha256)
            publish(captured.resolve("host-canary-commitments.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-interface-host-canary-commitments-v1"),
                "inputSha256" to JsonPrimitive(binaryGuard.authenticatedSha256),
                "fullBinarySha256" to JsonPrimitive(richGuard.authenticatedSha256),
                "markers" to JsonObject(canaries.mapValues { (_, guard) -> JsonPrimitive(guard.authenticatedSha256) }),
                "authority" to JsonPrimitive("qualification-control-only"),
            ))))
            assertEquals(0, invokeInstalledGccCli(arguments, launcher, 2100, installation, COMMAND),
                "installed interface CLI failed; bounded failure streams are retained without inventing a successful capture")
            val launcherSummary = verifyInstalledCliEvidence(launcher, arguments, installation, 0, COMMAND)
            guards.forEach { it.verifyUnchanged("after installed interface execution") }
            qualify(options, arguments, installation, captured, launcherSummary)
            guards.forEach { it.verifyUnchanged("after complete durable interface replay") }
            guards.asReversed().forEach { it.close() }
            guards.clear()
            // This is the final success marker. Every earlier artifact is also useful on failure.
            publish(evidence.resolve("qualification.json"), read(captured.resolve("qualification-summary.json"), MIB))
        } catch (problem: Throwable) {
            failure = problem
            try { retainFailureStreams(scratch, evidence, problem) } catch (captureFailure: Throwable) {
                if (captureFailure !== problem) problem.addSuppressed(captureFailure)
            }
            throw problem
        } finally {
            for (guard in guards.asReversed()) try { guard.close() } catch (problem: Throwable) {
                if (failure == null) throw problem else if (problem !== failure) failure.addSuppressed(problem)
            }
            // Retain canaries with their host pins until the qualification ends; do not mutate inputs.
        }
    }

    /** Retained consistency checks deliberately do not claim to recreate the destroyed HMAC secret. */
    private fun validateExecution(definition: GccCompilerEngineValidatedContainmentDefinition,
        execution: JsonObject, attachment: JsonObject, request: KotlinContainedCommandRequest,
        control: Path, deployment: String, result: JsonObject, captured: Path) {
        require(attachment.keys == setOf("schemaVersion", "provider", "unitName", "nonce", "bootId", "invocationId",
            "controlGroup", "cgroupDevice", "cgroupInode", "cgroupMountId", "requestSha256", "deploymentClosureSha256",
            "runtimeClosureSha256", "resources", "releaseEligible", "processes", "attachmentSha256"))
        require(attachment.number("schemaVersion") == 1L && attachment.text("provider") == "kotlin-lease-contained-command-attachment-v1")
        checksum(attachment, "attachmentSha256")
        require(attachment.text("unitName") == definition.unitName && attachment.digest("nonce") == definition.bindingSha256 &&
            attachment.text("controlGroup") == definition.expectedControlGroup && attachment.digest("deploymentClosureSha256") == deployment &&
            attachment.digest("requestSha256") == request.sha256 && attachment["releaseEligible"] == JsonPrimitive(false))
        attachment.digest("runtimeClosureSha256")
        require(attachment.text("bootId").matches(Regex("[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}")) &&
            attachment.text("invocationId").matches(Regex("[a-f0-9]{32}")))
        require(attachment.number("cgroupDevice") >= 0 && attachment.number("cgroupInode") > 0 && attachment.number("cgroupMountId") > 0)
        val resources = attachment.getValue("resources").jsonObject
        require(resources.keys == setOf("wallClockMillis", "maximumResidentBytes", "pidsMax", "maximumFileBytes",
            "maximumAddressSpaceBytes", "cpuSeconds", "serviceRuntimeSeconds"))
        val wall = resources.number("wallClockMillis")
        require(wall in 1000..1_800_000 && wall % 1000L == 0L)
        val expected = KotlinSystemdCgroupCommandResources(wall, 16L * GIB, 128, GIB)
        assertEquals(JsonObject(expected.json() + mapOf("maximumAddressSpaceBytes" to JsonPrimitive(64L * GIB),
            "cpuSeconds" to JsonPrimitive(expected.aggregateCpuSeconds), "serviceRuntimeSeconds" to JsonPrimitive(expected.aggregateCpuSeconds))), resources)
        require(request.runDirectory == control && request.nonce == definition.bindingSha256 &&
            request.command == definition.command && request.environment == definition.environment &&
            request.maximumWallSeconds == wall / 1000 && request.maximumStartWaitSeconds == minOf(expected.aggregateCpuSeconds, 300) &&
            request.maximumStdoutBytes == 64L * MIB && request.maximumStderrBytes == 64L * MIB &&
            !request.allowInterruption && request.retainedInputVisibilitySha256 == null)
        require(definition.command.count { it == "-Xmx2G" } == 1 &&
            definition.command.count { it == "-XX:ActiveProcessorCount=1" } == 1)
        val roles = listOf("outer-bubblewrap", "namespace-init-bubblewrap", "supervisor-jvm")
        val processes = attachment.getValue("processes").jsonArray
        require(processes.size == roles.size)
        val pids = hashSetOf<Long>()
        for ((index, raw) in processes.withIndex()) {
            val process = raw.jsonObject
            require(process.keys == setOf("role", "hostPid", "startTimeTicks", "parentRole", "namespacePids",
                "executableDevice", "executableInode", "executableMountId"))
            require(process.text("role") == roles[index] && process["parentRole"] ==
                if (index == 0) JsonNull else JsonPrimitive(roles[index - 1]))
            require(process.number("hostPid") in 1..Int.MAX_VALUE.toLong() && pids.add(process.number("hostPid")) &&
                process.number("startTimeTicks") > 0 && process.number("executableDevice") >= 0 &&
                process.number("executableInode") > 0 && process.number("executableMountId") > 0)
            val namespaces = process.getValue("namespacePids").jsonArray
            require(namespaces.size in 1..32 && namespaces.all { it.jsonPrimitive.long in 1..Int.MAX_VALUE.toLong() })
        }
        require(execution.keys == setOf("schemaVersion", "provider", "attachmentSha256", "requestSha256", "deploymentClosureSha256",
            "outcomeSha256", "outcome", "childExitCode", "derivationWallNanos", "unitAbsent", "cgroupAbsent", "processesAbsent",
            "releaseEligible", "cgroup", "controlDirectory", "controlDirectoryIdentity", "operationWallTime", "executionSha256"))
        require(execution.number("schemaVersion") == 1L && execution.text("provider") == "kotlin-lease-contained-command-execution-v1")
        checksum(execution, "executionSha256")
        require(execution.digest("attachmentSha256") == sha(OracleJson.canonicalBytes(attachment)) &&
            execution.digest("requestSha256") == request.sha256 && execution.digest("deploymentClosureSha256") == deployment &&
            execution.number("childExitCode") == 0L && execution["releaseEligible"] == JsonPrimitive(false) &&
            execution.text("controlDirectory") == control.toString() && execution.number("derivationWallNanos") in 0..wall * 1_000_000L)
        for (name in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) require(execution[name] == JsonPrimitive(true))
        LinuxFilesystemSyscalls.openRoot(control).use {
            require(execution["controlDirectoryIdentity"] == containedControlIdentityJson(control.fileName.toString(), it.identity))
        }
        val protocol = listOf("boot" to "BOOT", "start" to "START", "outcome" to "OUTCOME").associate { (name, event) ->
            val file = "contained-command.$name.json"
            val bytes = read(control.resolve(file), 4096)
            val record = document(bytes)
            require(record.keys == setOf("schemaVersion", "provider", "event", "nonce", "requestSha256", "keeperPid", "childPid",
                "exitCode", "elapsedMillis", "stdoutBytes", "stderrBytes", "status", "hmacSha256"))
            require(record.number("schemaVersion") == 1L && record.text("provider") == "kotlin-contained-command-protocol-v1" &&
                record.text("event") == event && record.text("status") == (if (event == "OUTCOME") "EXITED" else event))
            require(record.digest("nonce") == request.nonce && record.digest("requestSha256") == request.sha256)
            record.digest("hmacSha256")
            publish(captured.resolve(file), bytes)
            event to record
        }
        val outcome = protocol.getValue("OUTCOME")
        require(execution["outcome"] == outcome && execution.digest("outcomeSha256") == sha(OracleJson.canonicalBytes(outcome)))
        require(outcome.number("keeperPid") in 1..Int.MAX_VALUE.toLong() && outcome.number("childPid") in 1..Int.MAX_VALUE.toLong() &&
            outcome.number("keeperPid") != outcome.number("childPid") && outcome.number("exitCode") == 0L &&
            outcome.number("elapsedMillis") in 0..wall + 15_000 && outcome.number("stdoutBytes") in 0..64L * MIB &&
            outcome.number("stderrBytes") in 0..64L * MIB)
        for (event in listOf("BOOT", "START")) {
            val record = protocol.getValue(event)
            require(record["keeperPid"] == outcome["keeperPid"])
            for (field in listOf("childPid", "exitCode", "elapsedMillis", "stdoutBytes", "stderrBytes")) require(record.number(field) == 0L)
        }
        require(processes.last().jsonObject.getValue("namespacePids").jsonArray.last() == outcome["keeperPid"])
        val cgroup = execution.getValue("cgroup").jsonObject
        require(cgroup.keys == setOf("peakResidentBytes", "cpuNanos", "memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents"))
        require(cgroup.number("peakResidentBytes") in 1..16L * GIB && cgroup.number("cpuNanos") in 0..expected.aggregateCpuSeconds * 1_000_000_000L)
        for (field in listOf("memoryMaxEvents", "memoryOomEvents", "memoryOomKillEvents")) require(cgroup.number(field) == 0L)
        val executionWall = execution.getValue("operationWallTime").jsonObject
        val resultWall = result.getValue("operationWallTime").jsonObject
        validateWall(executionWall); validateWall(resultWall)
        require(executionWall["startedMonotonicNanos"] == resultWall["startedMonotonicNanos"] &&
            resultWall.number("elapsedNanos") >= executionWall.number("elapsedNanos"))
    }

    private fun validateRawPointers(result: JsonObject, run: Path, raw: GccBundledInferredInterfaceSnapshot) {
        checkPointer(result, "programModel", run.resolve("reports/program_model.json"), raw.programModelBytes)
        require(result.number("programModelBytes") == raw.model.programModelBytes && result.number("capturedBytes") == raw.capturedBytes)
        checkPointer(result, "listingObservations", run.resolve("reports/native-interfaces-v1/native-interfaces.json"), raw.listingObservationsBytes)
        checkPointer(result, "listingManifest", run.resolve("reports/native-interfaces-v1/manifest.json"), raw.listingManifestBytes)
        checkPointer(result, "inferredObservations", run.resolve("reports/native-inferred-interfaces-v1/native-inferred-interfaces.json"), raw.inferredObservationsBytes)
        checkPointer(result, "inferredManifest", run.resolve("reports/native-inferred-interfaces-v1/manifest.json"), raw.inferredManifestBytes)
        assertTrue(raw.completeObservedNativeCensus)
        assertFalse(raw.complete); assertFalse(raw.authoritativeOracleEvidence); assertFalse(raw.productionInterfacesAdmitted)
        assertFalse(raw.scored); assertFalse(raw.releaseEligible)
    }

    /** Reconstruct the runner's serial/fresh runtime preimage; this is derived evidence, not a worker file. */
    private fun verifyRuntimeSelection(definition: GccCompilerEngineValidatedContainmentDefinition,
        intent: GccBundledOperationIntent, inputs: GccBundledOperationInputs, execution: JsonObject,
        attachment: JsonObject, control: Path, captured: Path): JsonObject {
        inputs.verify("before deriving complete contained runtime selection")
        val configuration = deriveRuntimeConfiguration(definition, inputs.classPathEntries)
        val configurationBytes = configuration.canonicalBytesForTest()
        require(sha(configurationBytes) == configuration.canonicalSha256)
        val runtime = requireNotNull(definition.bundledRuntime)
        require(runtime.invocationVersion == 9 && runtime.processorCount == 1 &&
            definition.runKind == GccCompilerEngineContainmentRunKind.FRESH_CONTROL)
        val mount = FullTreeFunctionObservationRuntimeMount(runtime.root, runtime.root,
            calculateFullTreeObservationRuntimeManifestSha256(runtime.root))
        val mountedInputs = intent.artifacts.filter { it.role in setOf(
            GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
            GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE,
        ) }
        require(mountedInputs.size == 2 && mountedInputs.map { it.role }.toSet().size == 2)
        val wall = execution.getValue("operationWallTime").jsonObject
        validateWall(wall)
        // Exactly the fresh serial branch of KotlinSystemdCgroupCommandLauncher.execute:
        // no interruption, prior control/state/reports view, selected-input view or parallel resources.
        val preimage = JsonObject(mapOf(
            "provider" to JsonPrimitive("kotlin-lease-contained-command-runtime-v1"),
            "configurationSha256" to JsonPrimitive(configuration.canonicalSha256),
            "deploymentClosureSha256" to JsonPrimitive(inputs.deploymentClosureSha256),
            "runtimeMounts" to JsonArray(listOf(JsonObject(mapOf(
                "source" to JsonPrimitive(mount.source.toString()),
                "destination" to JsonPrimitive(mount.destination.toString()),
                "expectedManifestSha256" to JsonPrimitive(mount.expectedManifestSha256),
            )))),
            "readOnlyInputs" to JsonArray(mountedInputs.map { input -> JsonObject(mapOf(
                "path" to JsonPrimitive(input.path.toString()), "bytes" to JsonPrimitive(input.bytes),
                "sha256" to JsonPrimitive(input.sha256),
            )) }),
            "keeperEntryPoint" to JsonPrimitive(KotlinContainedCommandKeeper::class.java.name),
            "requestVersion" to JsonPrimitive(KotlinContainedCommandProtocol.VERSION),
            "controlDirectory" to JsonPrimitive(control.toString()),
            "writableRoot" to JsonPrimitive(definition.outputLease.path.toString()),
            "operationWallDeadline" to JsonObject(wall.filterKeys {
                it in setOf("provider", "maximumWallMillis", "startedMonotonicNanos")
            }),
        ))
        val preimageBytes = OracleJson.canonicalBytes(preimage)
        require(sha(preimageBytes) == attachment.digest("runtimeClosureSha256")) {
            "contained attachment differs from the complete derived runtime and ordered input selection"
        }
        inputs.verify("after deriving complete contained runtime selection")
        publish(captured.resolve("derived-runtime-configuration.json"), configurationBytes)
        publish(captured.resolve("derived-runtime-selection.json"), preimageBytes)
        val verification = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-interface-derived-runtime-selection-verification-v1"),
            "origin" to JsonPrimitive("derived-from-retained-definition-inputs-and-verified-execution-policy"),
            "validation" to JsonPrimitive("verified-against-attachment-runtimeClosureSha256"),
            "runtimeSelectionSha256" to JsonPrimitive(sha(preimageBytes)),
            "configurationSha256" to JsonPrimitive(configuration.canonicalSha256),
            "attachmentSha256" to JsonPrimitive(sha(OracleJson.canonicalBytes(attachment))),
            "complete" to JsonPrimitive(false), "productionInterfacesAdmitted" to JsonPrimitive(false),
            "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
        ))
        publish(captured.resolve("derived-runtime-selection-verification.json"), OracleJson.canonicalBytes(verification))
        return verification
    }

    private fun copyCompleteTree(source: Path, destination: Path, raw: GccBundledInferredInterfaceSnapshot): Map<String, JsonObject> {
        // Preserve empty directories too. The copied tree has its own inode identities, never the old owner's authority.
        for (relative in raw.directories.keys.sortedBy { it.length })
            directory(destination.resolve(relative))
        val commitments = linkedMapOf<String, JsonObject>()
        var bytes = 0L
        for ((relative, pin) in raw.files.toSortedMap()) {
            val stdoutPath = "${raw.controlName}/reports/contained-command.stdout"
            val stderrPath = "${raw.controlName}/reports/contained-command.stderr"
            require((relative.startsWith("reports/") || relative == stdoutPath || relative == stderrPath) &&
                Path.of(relative).normalize().toString() == relative)
            val size = pin.metadata.getValue("size") as Long
            require(size in 0..GIB && bytes <= GIB - size)
            bytes += size
            val hash = if (relative == stdoutPath || relative == stderrPath) {
                val stream = if (relative == stdoutPath) raw.stdoutBytes else raw.stderrBytes
                val expected = if (relative == stdoutPath) raw.stdoutSha256 else raw.stderrSha256
                require(stream.size.toLong() == size && sha(stream) == expected)
                publish(destination.resolve(relative), stream)
                expected
            } else copyStable(source.resolve(relative), destination.resolve(relative), size)
            commitments[relative] = JsonObject(mapOf("bytes" to JsonPrimitive(size), "sha256" to JsonPrimitive(hash)))
        }
        require(bytes == raw.capturedBytes && commitments.size == raw.files.size)
        val tree = document(raw.model.sidecarManifest, GccBundledFullExportCliResultV2.TREE_MANIFEST_JSON_LIMITS).getValue("tree").jsonObject
        for ((relative, expected) in tree.getValue("sidecars").jsonObject)
            require(commitments["reports/program_model.json.export/$relative"] == expected)
        require(commitments.getValue("reports/program_model.json").text("sha256") == raw.model.programModelSha256)
        require(commitments.getValue("reports/program_model.json.export/state.json").text("sha256") == raw.model.stateSha256)
        require(commitments.getValue("reports/program_model.json.progress.json").text("sha256") == raw.model.progressSha256)
        return commitments
    }

    private fun verifyDurableFiles(root: Path, files: Map<String, JsonObject>, directories: Set<String>, expectedBytes: Long) {
        var bytes = 0L
        val actual = arrayListOf<String>()
        val actualDirectories = hashSetOf<String>()
        val pins = linkedMapOf<Path, Map<String, Any>>()
        var entries = 0
        Files.walk(root, 8).use { paths -> paths.forEach { path ->
            require(++entries <= 300_032 && !Files.isSymbolicLink(path))
            val before = Files.readAttributes(path, "unix:dev,ino,nlink,size,lastModifiedTime,ctime,mode,uid,gid", NOFOLLOW_LINKS)
            if (Files.isRegularFile(path, NOFOLLOW_LINKS)) {
                require((before.getValue("nlink") as Number).toLong() == 1L)
                require(actual.size < 300_009)
                val relative = root.relativize(path).toString()
                val expected = files.getValue(relative)
                if (expected.number("bytes") == 0L) {
                    require(read(path, 1, allowEmpty = true).isEmpty() && expected.digest("sha256") == sha(byteArrayOf()))
                } else StableControlFile.open(path, expected.number("bytes"), "durable full interface tree").use { guard ->
                    require(guard.size == expected.number("bytes") && guard.authenticatedSha256 == expected.digest("sha256"))
                    require(bytes <= GIB - guard.size); bytes += guard.size
                    guard.verifyUnchanged("after durable full tree verification")
                }
                actual += relative
            } else {
                require(Files.isDirectory(path, NOFOLLOW_LINKS))
                require(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == PosixFilePermissions.fromString("rwx------"))
                if (path != root) actualDirectories += root.relativize(path).toString()
            }
            require(Files.readAttributes(path, "unix:dev,ino,nlink,size,lastModifiedTime,ctime,mode,uid,gid", NOFOLLOW_LINKS) == before)
            pins[path] = before
        } }
        require(actual.toSet() == files.keys && actual.size == files.size && bytes == expectedBytes && actualDirectories == directories)
        for ((path, pin) in pins) require(Files.readAttributes(path,
            "unix:dev,ino,nlink,size,lastModifiedTime,ctime,mode,uid,gid", NOFOLLOW_LINKS) == pin)
    }

    private fun replay(root: Path, raw: GccBundledInferredInterfaceSnapshot): NativeInferredInterfaceSummaryV1 {
        val limits = NativeInferredInterfaceObservationLimitsV1()
        val model = read(root.resolve("reports/program_model.json"), limits.maximumModelBytes)
        val listingManifest = read(root.resolve("reports/native-interfaces-v1/manifest.json"), limits.maximumManifestBytes)
        val inferredManifest = read(root.resolve("reports/native-inferred-interfaces-v1/manifest.json"), limits.maximumManifestBytes)
        val listing = root.resolve("reports/native-interfaces-v1/native-interfaces.json")
        val inferred = root.resolve("reports/native-inferred-interfaces-v1/native-inferred-interfaces.json")
        // Binding was derived through retained inputs + typed address matching by the complete raw capture.
        return NativeInferredInterfaceObservationsV1.validate(inferredManifest, raw.summary.bindings, model,
            listingManifest, limits, {}, { Files.newInputStream(listing, READ, NOFOLLOW_LINKS) },
            { Files.newInputStream(inferred, READ, NOFOLLOW_LINKS) }).also {
            require(!it.authoritativeOracleEvidence && !it.recoveredModelScored && !it.productionInterfacesAdmitted && !it.releaseEligible)
            require(it.scan.functions > 0 && it.scan.observed > 0 && it.scan.graphNodes > 0 &&
                it.listing.modelFunctions.isNotEmpty() &&
                it.scan.dispositions.keys == NativeInferredInterfaceObservationsV1.dispositions &&
                it.scan.dispositions.values.sum() == it.scan.functions &&
                it.scan.internalFunctions + it.scan.externalFunctions == it.scan.functions)
        }
    }

    private fun population(summary: NativeInferredInterfaceSummaryV1): JsonObject = JsonObject(mapOf(
        "modelFunctions" to JsonPrimitive(summary.listing.modelFunctions.size), "nativeFunctions" to JsonPrimitive(summary.scan.functions),
        "internalFunctions" to JsonPrimitive(summary.scan.internalFunctions), "externalFunctions" to JsonPrimitive(summary.scan.externalFunctions),
        "thunks" to JsonPrimitive(summary.scan.thunks), "attempted" to JsonPrimitive(summary.scan.attempted), "observed" to JsonPrimitive(summary.scan.observed),
        "parameters" to JsonPrimitive(summary.scan.parameters), "roots" to JsonPrimitive(summary.scan.roots),
        "storageVarnodes" to JsonPrimitive(summary.scan.storageVarnodes), "graphNodes" to JsonPrimitive(summary.scan.graphNodes),
        "graphEdges" to JsonPrimitive(summary.scan.graphEdges), "graphWork" to JsonPrimitive(summary.scan.graphWork),
        "dispositions" to JsonObject(summary.scan.dispositions.mapValues { JsonPrimitive(it.value) }),
        "modelMappingStates" to JsonObject(summary.listing.modelFunctions.groupingBy { it.state }.eachCount().mapValues { JsonPrimitive(it.value) }),
        "nativeMappingStates" to JsonObject(summary.listing.observedFunctions.groupingBy { it.state }.eachCount().mapValues { JsonPrimitive(it.value) }),
        "sourceTypeIdentity" to JsonPrimitive(summary.sourceTypeIdentity), "abiClassification" to JsonPrimitive(summary.abiClassification),
        "inferredSha256" to JsonPrimitive(summary.manifest.sha256), "listingSha256" to JsonPrimitive(summary.bindings.listingSha256),
        "complete" to JsonPrimitive(false), "authoritativeOracleEvidence" to JsonPrimitive(false),
        "productionInterfacesAdmitted" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
    ))

    private fun requireProbe(stderr: ByteArray, inputSha256: String): JsonObject {
        val lines = selectedLines(stderr, PROBE_PREFIX, 2048)
        require(lines.size == 1) { "contained interface canary probe is absent or repeated" }
        val expected = JsonObject(sortedMapOf("schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("gcc-interface-containment-probe-v1"),
            "inputSha256" to JsonPrimitive(inputSha256),
            "hidden" to JsonObject((CANARY_ROLES + "fullBinary").associateWith { JsonPrimitive(true) }.toSortedMap()),
            "readOnly" to JsonObject(listOf("binary", "exporter").associateWith { JsonPrimitive(true) }.toSortedMap())))
        // The worker's bounded frame is compact sorted JSON, unlike OracleJson's pretty document format.
        assertEquals(PROBE_PREFIX + expected.toString(), lines.single())
        return expected
    }

    private fun requirePhases(stderr: ByteArray): JsonArray {
        val lines = selectedLines(stderr, "DECOMP_INTERFACE_PHASE_V1 ", 512)
        require(lines.size == 6) { "complete interface phase population is absent or repeated" }
        val phases = listOf("full-model", "listing", "inferred")
        return JsonArray(lines.mapIndexed { index, line ->
            val phase = phases[index / 2]
            val state = if (index % 2 == 0) "started" else "completed"
            val expected = Regex("DECOMP_INTERFACE_PHASE_V1 phase=$phase state=$state elapsedMillis=([0-9]+)" +
                if (phase == "inferred") " collectorLifetimeMillis=120000" else "")
            val elapsed = requireNotNull(expected.matchEntire(line)).groupValues[1].toLong()
            require(elapsed in 0..1_800_000 && (state != "started" || elapsed == 0L))
            JsonObject(mapOf("phase" to JsonPrimitive(phase), "state" to JsonPrimitive(state), "elapsedMillis" to JsonPrimitive(elapsed)))
        })
    }

    private fun selectedLines(bytes: ByteArray, prefix: String, maximum: Int): List<String> {
        val marker = prefix.toByteArray(Charsets.US_ASCII)
        val selected = arrayListOf<String>()
        var start = 0
        for (end in bytes.indices) if (bytes[end] == 10.toByte()) {
            if (end - start >= marker.size && marker.indices.all { bytes[start + it] == marker[it] }) {
                require(end - start <= maximum && selected.size < 7)
                selected += bytes.copyOfRange(start, end).toString(Charsets.UTF_8)
            }
            start = end + 1
        }
        // A truncated final control frame cannot be accepted as a completed probe/phase record.
        require(bytes.size - start < marker.size || !marker.indices.all { bytes[start + it] == marker[it] })
        return selected
    }

    private fun retainFailureStreams(scratch: Path, evidence: Path, primary: Throwable) {
        var reportsSelected = false
        try { LinuxFilesystemSyscalls.openRoot(scratch).use { root ->
            val leaseName = LinuxFilesystemSyscalls.directoryEntryNames(root, 1).singleOrNull() ?: return
            require(leaseName.matches(Regex("\\.decomp-oracle-lease-[a-f0-9]{64}")))
            val operation = leaseName.removePrefix(".decomp-oracle-lease-")
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, leaseName).use { lease ->
                LinuxFilesystemSyscalls.openDirectoryAt(lease.fd, ".function-observation-run-$operation").use { run ->
                    val controlName = LinuxFilesystemSyscalls.directoryEntryNames(run, 16)
                        .filter { it.matches(Regex("control-[a-f0-9]{64}")) }.singleOrNull() ?: return
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { control ->
                        LinuxFilesystemSyscalls.openDirectoryAt(control.fd, "reports").use { reports ->
                            reportsSelected = true
                            GccInterfaceFailureStderrTail.retainBestEffort(primary, prefixes = {
                                for (stream in listOf("stdout", "stderr")) {
                                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, "contained-command.$stream")?.use { source ->
                                        val bytes = LinuxFilesystemSyscalls.readPrefix(source, 16 * MIB)
                                        publish(evidence.resolve("failed-command-$stream.bin"), bytes)
                                        publish(evidence.resolve("failed-command-$stream.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                                            "provider" to JsonPrimitive("gcc-interface-failed-stream-prefix-v1"),
                                            "authority" to JsonPrimitive("diagnostic-only"), "stream" to JsonPrimitive(stream),
                                            "capturedBytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(sha(bytes)),
                                            "captureLimitReached" to JsonPrimitive(bytes.size == 16 * MIB),
                                            "complete" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                                        ))))
                                    }
                                }
                            }, tail = {
                                val tail = GccInterfaceFailureStderrTail.capture(reports)
                                if (tail == null) {
                                    publish(evidence.resolve("failed-command-stderr-tail-unavailable.json"),
                                        OracleJson.canonicalBytes(GccInterfaceFailureStderrTail.unavailable("absent")))
                                } else {
                                    // Publish checked range metadata only after exact capture and raw-byte publication.
                                    // Neither file is a structured diagnostic frame or an execution result.
                                    publish(evidence.resolve("failed-command-stderr-tail.bin"), tail.bytes)
                                    publish(evidence.resolve("failed-command-stderr-tail.json"), OracleJson.canonicalBytes(tail.metadata()))
                                }
                            }, tailUnavailable = {
                                publish(evidence.resolve("failed-command-stderr-tail-unavailable.json"),
                                    OracleJson.canonicalBytes(GccInterfaceFailureStderrTail.unavailable("capture-or-publication-failed")))
                            })
                        }
                    }
                }
            }
        } } finally {
            if (!reportsSelected) try {
                publish(evidence.resolve("failed-command-stderr-tail-unavailable.json"),
                    OracleJson.canonicalBytes(GccInterfaceFailureStderrTail.unavailable("not-attempted-reports-unavailable")))
            } catch (captureFailure: Throwable) {
                if (captureFailure !== primary) primary.addSuppressed(captureFailure)
            }
        }
    }

    private fun copyStable(source: Path, destination: Path, size: Long): String =
        StableControlFile.open(source, size, "complete raw interface file").use { guard ->
            require(guard.size == size)
            val digest = MessageDigest.getInstance("SHA-256")
            val buffer = ByteArray(64 * 1024)
            FileChannel.open(destination, CREATE_NEW, WRITE).use { output ->
                var offset = 0L
                while (offset < size) {
                    val count = guard.readAt(offset, buffer, 0, minOf(buffer.size.toLong(), size - offset).toInt())
                    require(count > 0); digest.update(buffer, 0, count)
                    val chunk = ByteBuffer.wrap(buffer, 0, count)
                    while (chunk.hasRemaining()) output.write(chunk)
                    offset += count
                }
                output.force(true)
            }
            val hash = digest.digest().joinToString("") { "%02x".format(it) }
            require(hash == guard.authenticatedSha256)
            guard.verifyUnchanged("after durable raw file copy")
            Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("r--------"))
            FileChannel.open(destination.parent, READ).use { it.force(true) }
            hash
        }

    private fun read(path: Path, maximum: Int, allowEmpty: Boolean = false): ByteArray {
        if (allowEmpty && Files.size(path) == 0L) {
            // StableControlFile intentionally requires positive size. Empty streams still need
            // a real regular-file descriptor and unchanged identity/metadata, never absence.
            return LinuxFilesystemSyscalls.openRoot(path.parent).use { parent ->
                val name = path.fileName.toString()
                requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)).use { file ->
                    val before = Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(file.fd),
                        "unix:dev,ino,nlink,size,lastModifiedTime,ctime,mode,uid,gid")
                    require(file.identity.isRegularFile && file.identity.linkCount == 1 && before["size"] == 0L)
                    val bytes = LinuxFilesystemSyscalls.readPrefix(file, 1)
                    require(bytes.isEmpty() && Files.readAttributes(LinuxFilesystemSyscalls.stableDescriptorPath(file.fd),
                        "unix:dev,ino,nlink,size,lastModifiedTime,ctime,mode,uid,gid") == before)
                    requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, name)).use { named ->
                        require(named.identity == file.identity)
                    }
                    bytes
                }
            }
        }
        return StableControlFile.open(path, maximum.toLong(), "interface qualification evidence").use { guard ->
            require(guard.size in (if (allowEmpty) 0L else 1L)..maximum.toLong())
            guard.readExactly(0, guard.size.toInt(), "interface qualification evidence").also {
                guard.verifyUnchanged("after interface qualification read")
            }
        }
    }
    private fun publish(path: Path, bytes: ByteArray) {
        FileChannel.open(path, CREATE_NEW, WRITE).use { channel ->
            val content = ByteBuffer.wrap(bytes)
            while (content.hasRemaining()) channel.write(content)
            channel.force(true)
        }
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        FileChannel.open(path.parent, READ).use { it.force(true) }
    }
    private fun directory(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun configured(name: String, vararg alternatives: String): Path {
        val value = (listOf(name) + alternatives).firstNotNullOfOrNull { System.getenv(it)?.takeIf(String::isNotBlank) }
            ?: error("required interface qualification input is missing: $name")
        return canonicalPath(Path.of(value))
    }
    private fun propertyPath(name: String): Path = canonicalPath(Path.of(requireNotNull(System.getProperty(name))))
    private fun canonicalPath(path: Path): Path = path.also {
        require(it.isAbsolute && it.normalize() == it && it.toRealPath() == it)
    }
    private fun names(path: Path): Set<String> = LinuxFilesystemSyscalls.openRoot(path).use {
        LinuxFilesystemSyscalls.directoryEntryNames(it, 32).toSet()
    }
    private fun document(bytes: ByteArray, limits: decompengine.oracle.core.StrictJsonLimits = decompengine.oracle.core.StrictJsonLimits()): JsonObject =
        OracleJson.parseCanonical(bytes, limits).jsonObject
    private fun JsonObject.text(name: String): String = getValue(name).jsonPrimitive.let { require(it.isString); it.content }
    private fun JsonObject.number(name: String): Long = getValue(name).jsonPrimitive.let { require(!it.isString); requireNotNull(it.longOrNull) }
    private fun JsonObject.digest(name: String): String = text(name).also { require(it.matches(Regex("[a-f0-9]{64}"))) }
    private fun sha(bytes: ByteArray): String = OracleArtifacts.sha256(bytes)
    private fun checksum(document: JsonObject, field: String) = require(document.digest(field) ==
        sha(OracleJson.canonicalBytes(JsonObject(document - field))))
    private fun checkPointer(document: JsonObject, name: String, path: Path, bytes: ByteArray) {
        require(document.text(name) == path.toString() && document.digest("${name}Sha256") == sha(bytes))
    }
    private fun rawFlags(document: JsonObject) {
        for (name in listOf("complete", "authoritativeOracleEvidence", "productionInterfacesAdmitted", "scored", "releaseEligible"))
            require(document[name] == JsonPrimitive(false))
        require(document["completeObservedNativeCensus"] == JsonPrimitive(true) &&
            document.text("interfaceAuthority") == "unavailable-raw-recovery-only")
    }
    private fun validateWall(wall: JsonObject) {
        require(wall.keys == setOf("provider", "maximumWallMillis", "startedMonotonicNanos", "elapsedNanos", "remainingNanos"))
        require(wall.text("provider") == "kotlin-contained-operation-wall-deadline-v1" && wall.number("maximumWallMillis") == 1_800_000L)
        wall.number("startedMonotonicNanos")
        require(wall.number("elapsedNanos") in 0 until 1_800_000_000_000L &&
            wall.number("remainingNanos") == 1_800_000_000_000L - wall.number("elapsedNanos"))
    }
    private companion object {
        const val COMMAND = "gcc-engine-interface-observations"
        const val MIB = 1024 * 1024
        const val GIB = 1024L * MIB
        const val CANARY_DIRECTORY = ".decomp-interface-hidden-canaries-v1"
        val CANARY_ROLES = listOf("rich", "debug", "source", "build", "oracle", "nominal")
        const val PROBE_PREFIX = "DECOMP_INTERFACE_CONTAINMENT_V1 "
        val JOURNAL_FILES = listOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json", "attachment.json",
            "start-authorized.json", "execution.json", "export-assessment.json")
        val RESULT_KEYS = setOf("provider", "schemaVersion", "complete", "authoritativeOracleEvidence", "productionInterfacesAdmitted",
            "scored", "releaseEligible", "completeObservedNativeCensus", "interfaceAuthority", "operationId", "requestSha256", "journal",
            "programModel", "programModelSha256", "programModelBytes", "outputTreeManifest", "outputTreeManifestSha256",
            "listingObservations", "listingObservationsSha256", "listingManifest", "listingManifestSha256",
            "inferredObservations", "inferredObservationsSha256", "inferredManifest", "inferredManifestSha256",
            "interfaceBinding", "interfaceBindingSha256", "executionReceiptSha256", "assessmentReceiptSha256", "capturedBytes",
            "operationWallTime", "scratchDisposition")
    }

    private fun qualify(options: GccBundledCliOptions, arguments: List<String>, installation: Path,
        captured: Path, launcherSummary: JsonObject) {
        val resultBytes = read(options.output.resolve("result.json"), 256 * 1024)
        val result = document(resultBytes)
        require(result.keys == RESULT_KEYS)
        require(result.text("provider") == "gcc-bundled-cli-interface-observation-result-v1" && result.number("schemaVersion") == 1L)
        rawFlags(result)
        val operationId = result.digest("operationId")
        val journal = options.output.resolve("journal/.gcc-bundled-operation-$operationId")
        require(result.text("journal") == journal.toString() && names(journal) == JOURNAL_FILES.toSet())
        val records = JOURNAL_FILES.associateWith { read(journal.resolve(it), MIB) }
        for ((name, bytes) in records) publish(captured.resolve(name), bytes)
        val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(records.getValue("definition.json"))
        val runtime = requireNotNull(definition.bundledRuntime)
        require(definition.engineId == "driver" && definition.runKind == GccCompilerEngineContainmentRunKind.FRESH_CONTROL)
        assertEquals(GccCompilerEngineContainmentBudgets(1_800_000, 16L * GIB, 128), definition.budgets)
        require(runtime.invocationVersion == 9 && runtime.processorCount == 1 && runtime.decompilerWorkerCount == 1)
        assertEquals(runtime.command(definition.artifacts, definition.analysisState, definition.outputLease, definition.runKind),
            definition.command)
        require(runtime.root == installation.resolve("libexec/ghidra") && runtime.root.toRealPath() == runtime.root)
        val component = requireNotNull(runtime.interfaceCollector)
        assertEquals(NativeInferredInterfaceObservationsV1.configurationSha256, component.configurationSha256)
        val installedReference = read(installation.resolve("lib/gcc-bundled-ghidra-reference-v1.json"), 8 * MIB)
        val installedBoot = read(installation.resolve("lib/kotlin-boot-classpath-reference-v1.json"), 256 * 1024)
        assertContentEquals(read(propertyPath("decompengine.oracle.gcc.bundledGhidraReference"), 8 * MIB), installedReference)
        assertContentEquals(read(propertyPath("decompengine.oracle.gcc.bootKeeperClasspathReference"), 256 * 1024), installedBoot)
        GccBundledGhidraReference.parse(installedReference).requireCandidate(runtime, definition.artifacts)
        publish(captured.resolve("gcc-bundled-ghidra-reference-v1.json"), installedReference)
        publish(captured.resolve("kotlin-boot-classpath-reference-v1.json"), installedBoot)
        publish(captured.resolve("compiler-engines.json"), read(options.profile, MIB))
        val identities = listOf(options.output, options.output.resolve("inputs"), options.output.resolve("journal"))
            .associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val invocation = GccBundledCliInvocation(options, arguments, identities)
        assertContentEquals(invocation.canonicalBytes, read(options.output.resolve("invocation.json"), 256 * 1024))
        publish(captured.resolve("invocation.json"), invocation.canonicalBytes)
        GccRetainedCompilerEngineProfile.open(options.profile, "driver").use { profile ->
            profile.requireInterfaceObservationProfile()
            val intent = GccBundledOperationIntent(operationId, "driver", GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                definition.artifacts, runtime, definition.budgets, options.diskPolicy, profile, invocation)
            assertContentEquals(intent.canonicalBytes, records.getValue("intent.json"))
            val bootArtifact = intent.artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH }
            val bootManifest = read(bootArtifact.path, MIB)
            require(bootManifest.size.toLong() == bootArtifact.bytes && sha(bootManifest) == bootArtifact.sha256)
            publish(captured.resolve("boot-classpath.json"), bootManifest)
            require(result.digest("requestSha256") == intent.requestSha256 && definition.environment == intent.environment)
            val expectedRun = options.scratch.resolve(".decomp-oracle-lease-$operationId/.function-observation-run-$operationId")
            require(definition.outputLease.path == expectedRun)
            val lease = FullTreeDiskScratchEvidence.parseCanonical(records.getValue("lease-evidence.json"))
            require(lease.operationId == operationId && lease.requestSha256 == intent.requestSha256 &&
                lease.shardId == "driver" && lease.scopeSha256 == intent.workScopeSha256 &&
                lease.requiredAvailableBytes == options.diskPolicy.requiredAvailableBytes &&
                lease.maximumFilesystemBytes == options.diskPolicy.maximumFilesystemBytes &&
                lease.requiredAvailableInodes == options.diskPolicy.requiredAvailableInodes &&
                lease.maximumFilesystemInodes == options.diskPolicy.maximumFilesystemInodes)
            val prepared = document(records.getValue("prepared.json"))
            require(prepared.keys == setOf("provider", "schemaVersion", "operationId", "intentSha256", "diskEvidenceSha256",
                "definitionSha256", "definitionBindingSha256", "deploymentClosureSha256", "preparedSha256"))
            require(prepared.text("provider") == "gcc-bundled-prepared-operation-v1" && prepared.number("schemaVersion") == 1L &&
                prepared.digest("operationId") == operationId && prepared.digest("intentSha256") == intent.requestSha256 &&
                prepared.digest("diskEvidenceSha256") == lease.evidenceSha256 &&
                prepared.digest("definitionSha256") == sha(records.getValue("definition.json")) &&
                prepared.digest("definitionBindingSha256") == definition.bindingSha256)
            checksum(prepared, "preparedSha256")
            var previous = records.getValue("prepared.json")
            for (name in listOf("attachment.json", "start-authorized.json", "execution.json", "export-assessment.json")) {
                requireGccCliLinkedRecord(records.getValue(name), name, operationId, intent.requestSha256, sha(previous))
                previous = records.getValue(name)
            }
            require(result.digest("executionReceiptSha256") == sha(records.getValue("execution.json")) &&
                result.digest("assessmentReceiptSha256") == sha(records.getValue("export-assessment.json")))
            GccBundledOperationInputs.open(intent, listOf(options.output.resolve("journal"), options.scratch)).use { inputs ->
                require(prepared.digest("deploymentClosureSha256") == inputs.deploymentClosureSha256)
                val target = inputs.interfaceTargetEvidence {}
                val captureRuntime = GccBundledInterfaceCaptureBindingsV1(component.listingCollectorSha256,
                    component.inferredCollectorSha256, component.typeGraphSha256, component.wrapperSha256,
                    component.nativeDecompilerSha256, inputs.deploymentClosureSha256,
                    inputs.ghidraRuntimeIdentitySha256, component.closureSha256)
                val controlName = requireNotNull(runtime.freshControlDirectoryName(expectedRun))
                val control = expectedRun.resolve(controlName)
                val execution = document(records.getValue("execution.json")).getValue("execution").jsonObject
                val attachment = document(records.getValue("attachment.json")).getValue("attachment").jsonObject
                val requestBytes = read(control.resolve("runtime/contained-command-request.json"), 256 * 1024)
                val request = KotlinContainedCommandRequest.parse(requestBytes)
                publish(captured.resolve("contained-command-request.json"), requestBytes)
                validateExecution(definition, execution, attachment, request, control, inputs.deploymentClosureSha256, result, captured)
                val runtimeSelection = verifyRuntimeSelection(definition, intent, inputs, execution, attachment, control, captured)
                val bindingBytes = read(options.output.resolve(GccBundledInterfaceCliResultV1.BINDING_NAME), 256 * 1024)
                val binding = document(bindingBytes)
                require(binding.keys == setOf("provider", "schemaVersion", "complete", "authoritativeOracleEvidence",
                    "productionInterfacesAdmitted", "scored", "releaseEligible", "completeObservedNativeCensus", "interfaceAuthority",
                    "component", "captureAssessment", "fullExportTreeManifestSha256", "receiptLineage", "receiptLineageSha256"))
                require(binding.text("provider") == "gcc-bundled-interface-observation-binding-v1" && binding.number("schemaVersion") == 1L)
                rawFlags(binding)
                require(binding["component"] == component.toJson())
                checkPointer(result, "interfaceBinding", options.output.resolve(GccBundledInterfaceCliResultV1.BINDING_NAME), bindingBytes)
                val treeManifest = read(options.output.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME),
                    GccBundledFullExportCliResultV2.MAXIMUM_TREE_MANIFEST_BYTES)
                checkPointer(result, "outputTreeManifest", options.output.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME), treeManifest)
                require(binding.digest("fullExportTreeManifestSha256") == sha(treeManifest))
                val assessment = document(records.getValue("export-assessment.json")).getValue("assessment").jsonObject
                checksum(assessment, "assessmentSha256")
                val assessmentWall = assessment.getValue("operationWallTime").jsonObject
                validateWall(assessmentWall)
                require(assessmentWall["startedMonotonicNanos"] == execution.getValue("operationWallTime").jsonObject["startedMonotonicNanos"] &&
                    assessmentWall.number("elapsedNanos") >= execution.getValue("operationWallTime").jsonObject.number("elapsedNanos") &&
                    assessmentWall.number("elapsedNanos") <= result.getValue("operationWallTime").jsonObject.number("elapsedNanos"))
                val originalAssessment = binding.getValue("captureAssessment").jsonObject
                require(JsonObject(assessment - setOf("assessmentSha256", "operationWallTime")) == JsonObject(originalAssessment - "assessmentSha256"))
                val lineage = binding.getValue("receiptLineage").jsonObject
                assertEquals(JsonObject(mapOf("operationId" to JsonPrimitive(operationId), "intentSha256" to JsonPrimitive(intent.requestSha256),
                    "executionReceiptSha256" to JsonPrimitive(sha(records.getValue("execution.json"))),
                    "executionPayloadSha256" to JsonPrimitive(sha(OracleJson.canonicalBytes(execution))),
                    "assessmentReceiptSha256" to JsonPrimitive(sha(records.getValue("export-assessment.json"))),
                    "assessmentSha256" to assessment.getValue("assessmentSha256"))), lineage)
                require(binding.digest("receiptLineageSha256") == sha(OracleJson.canonicalBytes(lineage)))
                val summary = LinuxFilesystemSyscalls.openRoot(expectedRun).use { run ->
                    LinuxFilesystemSyscalls.openDirectoryAt(run.fd, "reports").use { reports ->
                        LinuxFilesystemSyscalls.openDirectoryAt(run.fd, controlName).use { controlDirectory ->
                            val raw = GccBundledInferredInterfaceCapture.capture(run, reports.identity, controlName,
                                controlDirectory.identity, definition.artifacts, target, captureRuntime, checkpoint = {})
                            assertContentEquals(OracleJson.canonicalBytes(originalAssessment), raw.assessmentBytes)
                            assertContentEquals(treeManifest, raw.model.sidecarManifest)
                            validateRawPointers(result, expectedRun, raw)
                            require(raw.capturedBytes <= GIB - treeManifest.size - bindingBytes.size - resultBytes.size)
                            val durable = directory(captured.resolve("run"))
                            val durableFiles = copyCompleteTree(expectedRun, durable, raw)
                            GccBundledInferredInterfaceCapture.requireUnchanged(run, raw, definition.artifacts) {}
                            val first = replay(durable, raw)
                            val second = replay(durable, raw)
                            assertEquals(first, second, "two independent complete durable replays differ")
                            assertEquals(raw.summary, first)
                            verifyDurableFiles(durable, durableFiles, raw.directories.keys, raw.capturedBytes)
                            publish(captured.resolve("durable-files.json"), OracleJson.canonicalBytes(JsonObject(durableFiles),
                                GccBundledFullExportCliResultV2.TREE_MANIFEST_JSON_LIMITS))
                            publish(captured.resolve("population-replay.json"), OracleJson.canonicalBytes(population(first)))
                            population(first)
                        }
                    }
                }
                val durableControl = captured.resolve("run/$controlName")
                val stderr = read(durableControl.resolve("reports/contained-command.stderr"), 64 * MIB, allowEmpty = true)
                val stdout = read(durableControl.resolve("reports/contained-command.stdout"), 64 * MIB, allowEmpty = true)
                val outcome = execution.getValue("outcome").jsonObject
                require(stderr.size.toLong() == outcome.number("stderrBytes") && stdout.size.toLong() == outcome.number("stdoutBytes"))
                require(stderr.size.toLong() == originalAssessment.number("stderrBytes") &&
                    stdout.size.toLong() == originalAssessment.number("stdoutBytes") &&
                    sha(stderr) == originalAssessment.digest("stderrSha256") && sha(stdout) == originalAssessment.digest("stdoutSha256"))
                // Stream lengths come from the outcome; exact contents are separately committed
                // by the descriptor capture assessment. Their one durable copy is in run/control/reports.
                val probe = requireProbe(stderr, target.inputSha256)
                val phases = requirePhases(stderr)
                inputs.verify("after durable snapshot and all interface receipts")
                profile.requireCurrent()
                publish(captured.resolve("result.json"), resultBytes)
                publish(captured.resolve(GccBundledInterfaceCliResultV1.BINDING_NAME), bindingBytes)
                publish(captured.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME), treeManifest)
                publish(captured.resolve("launcher-summary.json"), OracleJson.canonicalBytes(launcherSummary))
                publish(captured.resolve("qualification-summary.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive("gcc-driver-inferred-interface-qualification-v1"), "schemaVersion" to JsonPrimitive(1),
                    "engine" to JsonPrimitive("driver"), "requestSha256" to JsonPrimitive(intent.requestSha256),
                    "deploymentClosureSha256" to JsonPrimitive(inputs.deploymentClosureSha256),
                    "componentClosureSha256" to JsonPrimitive(component.closureSha256),
                    "runtimeSelection" to runtimeSelection,
                    "interfaceBindingSha256" to JsonPrimitive(sha(bindingBytes)), "captureAssessment" to originalAssessment,
                    "population" to summary, "containmentProbe" to probe, "phases" to phases,
                    "stdoutSha256" to JsonPrimitive(sha(stdout)), "stderrSha256" to JsonPrimitive(sha(stderr)),
                    "operationWallTime" to result.getValue("operationWallTime"),
                    "rawPopulationRetained" to JsonPrimitive(true), "completeObservedNativeCensus" to JsonPrimitive(true),
                    "complete" to JsonPrimitive(false), "authoritativeOracleEvidence" to JsonPrimitive(false),
                    "productionInterfacesAdmitted" to JsonPrimitive(false), "scored" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                    "limitation" to JsonPrimitive("installed recovery capture and complete durable byte replay only; archived HMACs are retained but cannot be reauthenticated without the destroyed live secret; canaries corroborate the fixed synthetic input mount policy; semantic ABI and oracle admission remain unavailable"),
                ))))
            }
        }
    }

}
