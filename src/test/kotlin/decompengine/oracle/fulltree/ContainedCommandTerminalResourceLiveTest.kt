package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxProcessDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.ContainedModuleHostedCase
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.Base64
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import javax.tools.ToolProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.assertContentEquals
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag

@Tag("ci-live")
class ContainedCommandTerminalResourceLiveTest {
    @Test
    fun `strict generic command accepts clean exit and rejects handled task limit with zero exit`() {
        ContainedModuleHostedCase.run("generic-default-512", javaClass.name, DEFAULT_METHOD, null) { record ->
            withConfiguredBoundary(record) { mount, configuration, fixture, managerCgroup ->
                for (mode in listOf("benign", "refusal")) {
                    exerciseCommand(mount, configuration, fixture, managerCgroup, mode, record)
                }
            }
        }
    }

    @Test
    fun `configured visibility only command retains selected files and proves owned cleanup`() {
        ContainedModuleHostedCase.run("generic-visibility-v4", javaClass.name, VISIBILITY_METHOD, null) { record ->
            withConfiguredBoundary(record) { mount, configuration, fixture, managerCgroup ->
                exerciseCommand(mount, configuration, fixture, managerCgroup, "visibility", record)
            }
        }
    }

    private fun withConfiguredBoundary(record: ContainedModuleHostedCase.Case,
        action: (Path, FullTreeFunctionObservationIsolationConfiguration, Path, String) -> Unit) {
        record.stage("configuration")
        requireOrAssume(System.getProperty("os.name").lowercase().contains("linux"), "live contained-command test requires Linux")
        val mount = provisionedScratchMount()
        inControlTemporaryDirectory { root ->
            val configuration = availableConfiguration(privateDirectory(root.resolve("runtime")))
            requireOrAssume(configuration != null, "live contained-command boundary is unavailable")
            checkNotNull(configuration)
            val fixture = compileFixture(root)
            record.retain("configuration.json", configuration.canonicalBytesForTest())
            record.retain("fixture-source.java", FIXTURE_SOURCE.toByteArray())
            record.retain("fixture.jar", readBoundedBytes(fixture, 1024 * 1024))
            val managerCgroup = systemctl(configuration, listOf("show", "--property=ControlGroup", "--value")).trim()
            require(managerCgroup.startsWith('/') && !managerCgroup.contains(".."))
            action(mount, configuration, fixture, managerCgroup)
        }
    }

    private fun exerciseCommand(
        mount: Path,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        fixture: Path,
        managerCgroup: String,
        mode: String,
        record: ContainedModuleHostedCase.Case,
    ) {
        record.stage("$mode-prepare")
        val visibilityOnly = mode == "visibility"
        assertTrue(Files.list(mount).use { it.findAny().isEmpty }, "provisioned ext4 slot must be empty")
        val capacity = LinuxFilesystemSyscalls.openRoot(mount).use(LinuxFilesystemSyscalls::filesystemCapacity)
        val operationId = randomDigest()
        val operation = FullTreeDiskScratchOperation(operationId, randomDigest(), "terminal-resource-$mode", randomDigest())
        val policy = FullTreeDiskScratchPolicy(1, capacity.totalBytes, 4, capacity.totalInodes)
        val fixtureInput = KotlinSystemdCgroupCommandInput(fixture, Files.size(fixture), sha256(fixture))
        val deploymentBytes = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("contained-command-terminal-resource-test-deployment-v1"),
            "configurationSha256" to JsonPrimitive(configuration.canonicalSha256),
            "fixtureSha256" to JsonPrimitive(fixtureInput.sha256),
        )))
        record.retain("$mode/deployment.json", deploymentBytes)
        val deploymentClosureSha256 = OracleArtifacts.sha256(deploymentBytes)
        val unitName = "decomp-terminal-resource-${operationId.take(32)}.scope"
        val controlGroup = "${managerCgroup.trimEnd('/')}/app.slice/$unitName"
        val processHandles = mutableListOf<LinuxProcessDescriptor>()
        FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(mount, operation, policy).use { lease ->
            val token = lease.createEmptyOperationRunRoot()
            var stateIdentity: LinuxFileIdentity? = null
            var reportsIdentity: LinuxFileIdentity? = null
            val runPath = lease.withCurrentOperationRunRootBeforeLaunch(token) { borrowed ->
                borrowed.withPinnedDescriptor { directory ->
                    for (name in listOf("state", "reports", "tmp")) {
                        LinuxFilesystemSyscalls.createDirectory(directory.fd, name, 448)
                    }
                    if (visibilityOnly) {
                        stateIdentity = LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, "state").use { it.identity }
                        reportsIdentity = LinuxFilesystemSyscalls.openDirectoryAt(directory.fd, "reports").use { it.identity }
                    }
                }
                borrowed.path
            }
            val activeName = "control-$operationId".takeIf { visibilityOnly }
            val controlPath = activeName?.let(runPath::resolve) ?: runPath
            val canaries = if (visibilityOnly) VISIBILITY_CANARIES else emptyMap()
            val selected = if (visibilityOnly) listOf(KotlinContainedCommandRetainedInput(
                "reports/selected.txt", VISIBILITY_CANARIES.getValue("reports/selected.txt").toByteArray().size.toLong(),
                OracleArtifacts.sha256(VISIBILITY_CANARIES.getValue("reports/selected.txt").toByteArray()))) else null
            var absenceProved = true
            var cleanup: KotlinSystemdCgroupCommandCleanup? = null
            try {
                for ((relative, content) in canaries) {
                    val file = runPath.resolve(relative)
                    if (!Files.exists(file.parent)) privateDirectory(file.parent)
                    Files.write(file, content.toByteArray())
                    Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-------"))
                    record.retain("$mode/host-before/$relative", readBoundedBytes(file, 4096))
                }
                lease.withCurrentOperationRunRootForContainedExecution(token) { borrowed ->
                    var attachmentBytes: ByteArray? = null
                    var execution: KotlinSystemdCgroupCommandExecution? = null
                    var failure: KotlinSystemdCgroupCommandExecutionException? = null
                    var keeperNamespacePid: Long? = null
                    absenceProved = false
                    record.stage("$mode-launch")
                    try {
                        execution = KotlinSystemdCgroupCommandLauncher.execute(
                            borrowed = borrowed,
                            configuration = configuration,
                            unitName = unitName,
                            expectedControlGroup = controlGroup,
                            nonce = operationId,
                            command = listOf(
                                configuration.javaExecutable.toString(), "-Xms16m", "-Xmx32m", "-Xss256k",
                                "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1", "-XX:-UsePerfData", "-Xlog:os+thread=off",
                                "-XX:+DisableAttachMechanism", "-Djava.io.tmpdir=${controlPath.resolve("tmp")}",
                                "-classpath", fixture.toString(), FIXTURE_CLASS, mode,
                            ) + if (visibilityOnly) listOf(runPath.toString(), checkNotNull(activeName)) else emptyList(),
                            environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
                            readOnlyInputs = listOf(fixtureInput),
                            // The launcher deduplicates this already authenticated root-owned runtime mount.
                            runtimeMounts = listOf(configuration.javaRuntime),
                            resources = KotlinSystemdCgroupCommandResources(30_000, 512L * 1024 * 1024, 64, CLEANUP_MAXIMUM_BYTES),
                            deploymentClosureSha256 = deploymentClosureSha256,
                            beforeStart = { attachment ->
                                attachmentBytes = attachment.canonicalBytes
                                record.stage("$mode-before-start")
                                record.retain("$mode/attachment.json", attachment.canonicalBytes)
                                val document = OracleJson.parseCanonical(attachment.canonicalBytes) as JsonObject
                                for (process in document.getValue("processes") as JsonArray) {
                                    val pid = (process as JsonObject).getValue("hostPid").jsonPrimitive.long
                                    processHandles += LinuxFilesystemSyscalls.openProcessHandle(pid)
                                }
                                keeperNamespacePid = captureDefaultKeeperLimits(document, controlGroup, record, mode)
                            },
                            requireTerminalResourceEventProof = !visibilityOnly,
                            controlDirectoryName = activeName,
                            readOnlyStateDirectory = stateIdentity,
                            readOnlyReportsDirectory = reportsIdentity,
                            retainedInputVisibility = selected,
                        )
                        absenceProved = true
                    } catch (caught: KotlinSystemdCgroupCommandExecutionException) {
                        failure = caught
                        cleanup = caught.cleanup
                        absenceProved = caught.cleanup.absenceProved
                    } finally {
                        record.stage("$mode-retain-lifecycle")
                        execution?.let { record.retain("$mode/execution.json", it.canonicalBytes) }
                        failure?.let { record.retain("$mode/refusal.txt", it.stackTraceToString().toByteArray()) }
                        retainAvailableLifecycle(controlPath, record, mode)
                    }
                    failure?.let { caught ->
                        if (mode != "refusal" || generateSequence<Throwable>(caught) { it.cause }.none {
                            it.message.orEmpty().contains("contained command terminal resource limit event: pids.max")
                        }) throw caught
                    }

                    val requestBytes = readBoundedBytes(controlPath.resolve("runtime/contained-command-request.json"),
                        KotlinContainedCommandRequest.MAXIMUM_REQUEST_BYTES)
                    val request = KotlinContainedCommandRequest.parse(requestBytes)
                    assertNull(request.fileDescriptorPolicy)
                    if (!visibilityOnly) {
                        assertEquals(ContainedCommandTerminalResourceEvidence.policySha256, request.terminalResourcePolicySha256)
                        assertNull(request.retainedInputVisibilitySha256)
                        assertEquals(JsonPrimitive(3), (OracleJson.parseCanonical(requestBytes) as JsonObject)["schemaVersion"])
                    }
                    val attachment = OracleJson.parseCanonical(assertNotNull(attachmentBytes)) as JsonObject
                    assertEquals(JsonPrimitive(request.sha256), attachment["requestSha256"])
                    assertEquals(JsonPrimitive(deploymentClosureSha256), attachment["deploymentClosureSha256"])
                    assertTrue("fileDescriptorLimits" !in attachment)
                    val outcomeBytes = readBoundedBytes(controlPath.resolve(KotlinContainedCommandProtocol.OUTCOME_FILE),
                        KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES)
                    val outcome = OracleJson.parseCanonical(outcomeBytes) as JsonObject
                    assertEquals(JsonPrimitive(request.sha256), outcome["requestSha256"])
                    val boot = OracleJson.parseCanonical(readBoundedBytes(controlPath.resolve(KotlinContainedCommandProtocol.BOOT_FILE),
                        KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES)) as JsonObject
                    val start = OracleJson.parseCanonical(readBoundedBytes(controlPath.resolve(KotlinContainedCommandProtocol.START_FILE),
                        KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES)) as JsonObject
                    for (event in listOf(boot, start)) {
                        assertEquals(JsonPrimitive(request.sha256), event["requestSha256"])
                        assertEquals(keeperNamespacePid, event.getValue("keeperPid").jsonPrimitive.long)
                    }
                    assertEquals(keeperNamespacePid, boot.getValue("keeperPid").jsonPrimitive.long)
                    assertEquals(keeperNamespacePid, outcome.getValue("keeperPid").jsonPrimitive.long)
                    execution?.let { retained ->
                        val document = OracleJson.parseCanonical(retained.canonicalBytes) as JsonObject
                        assertEquals(JsonPrimitive(request.sha256), document["requestSha256"])
                        assertEquals(JsonPrimitive(OracleArtifacts.sha256(assertNotNull(attachmentBytes))), document["attachmentSha256"])
                        assertEquals(JsonPrimitive(OracleArtifacts.sha256(outcomeBytes)), document["outcomeSha256"])
                        assertEquals(outcome, document["outcome"])
                    }
                    val stdout = readBoundedBytes(controlPath.resolve("reports/${KotlinContainedCommandProtocol.STDOUT_FILE}"), MAXIMUM_CHILD_OUTPUT_BYTES)
                    val stderr = readBoundedBytes(controlPath.resolve("reports/${KotlinContainedCommandProtocol.STDERR_FILE}"), MAXIMUM_CHILD_OUTPUT_BYTES)
                    assertEquals(stdout.size.toLong(), outcome.getValue("stdoutBytes").jsonPrimitive.long)
                    assertEquals(stderr.size.toLong(), outcome.getValue("stderrBytes").jsonPrimitive.long)
                    if (!visibilityOnly) {
                        assertEquals(JsonPrimitive(OracleArtifacts.sha256(stdout)), outcome["stdoutSha256"])
                        assertEquals(JsonPrimitive(OracleArtifacts.sha256(stderr)), outcome["stderrSha256"])
                    }
                    val childMarker = verifyChildDefaultLimits(stdout, outcome, record, mode)
                    record.stage("$mode-validate")

                    if (mode == "benign") {
                        assertNull(failure, failure?.stackTraceToString())
                        val bytes = assertNotNull(execution).canonicalBytes
                        val document = OracleJson.parseCanonical(bytes) as JsonObject
                        assertEquals(JsonPrimitive(3), document["schemaVersion"])
                        assertEquals(JsonPrimitive("kotlin-lease-contained-command-execution-v3"), document["provider"])
                        ContainedCommandTerminalResourceEvidence.verifyExecution(bytes, assertNotNull(attachmentBytes))
                        val proof = document.getValue("terminalResourceEvidence") as JsonObject
                        for (phase in listOf("baseline", "final")) {
                            val counters = proof.getValue(phase) as JsonObject
                            assertEquals(JsonPrimitive(0), (counters.getValue("pids") as JsonObject)["max"])
                            val memory = counters.getValue("memory") as JsonObject
                            for (event in listOf("high", "max", "oom", "oom_kill")) {
                                assertEquals(JsonPrimitive(0), memory[event], "$phase memory.$event")
                            }
                        }
                        assertEquals(JsonPrimitive(true), proof["frozen"])
                        assertEquals(JsonPrimitive(true), proof["keeperOnly"])
                        val cleanupEvidence = proof.getValue("cleanup") as JsonObject
                        for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) {
                            assertEquals(JsonPrimitive(true), cleanupEvidence[field])
                            assertEquals(JsonPrimitive(true), document[field])
                        }
                        assertEquals("BENIGN_EXIT_ZERO", childMarker)
                    } else if (mode == "refusal") {
                        val refused = assertNotNull(failure, "a handled pids.max refusal must invalidate the zero exit")
                        assertTrue(generateSequence<Throwable>(refused) { it.cause }.any {
                            it.message.orEmpty().contains("contained command terminal resource limit event: pids.max")
                        }, refused.stackTraceToString())
                        assertNull(execution, "resource refusal must not produce an accepted execution")
                        assertTrue(refused.cleanup.absenceProved, "strict refusal must complete its cleanup proof")
                        refused.cleanup.closeAndProveAbsent()
                        assertEquals("HANDLED_PIDS_REFUSAL_EXIT_ZERO", childMarker)
                    } else {
                        assertNull(failure, failure?.stackTraceToString())
                        val executionDocument = OracleJson.parseCanonical(assertNotNull(execution).canonicalBytes) as JsonObject
                        assertEquals(JsonPrimitive(1), executionDocument["schemaVersion"])
                        assertEquals(JsonPrimitive("kotlin-lease-contained-command-execution-v1"), executionDocument["provider"])
                        assertEquals(JsonPrimitive(1), attachment["schemaVersion"])
                        assertNull(request.terminalResourcePolicySha256)
                        assertEquals(JsonPrimitive(4), (OracleJson.parseCanonical(requestBytes) as JsonObject)["schemaVersion"])
                        assertTrue("terminalResourceEvidence" !in executionDocument)
                        assertTrue("terminalResourcePolicySha256" !in attachment)
                        val visibility = ContainedCommandRetainedInputVisibility(checkNotNull(activeName), setOf("reports", "state"),
                            checkNotNull(selected)).canonicalIdentity()
                        record.retain("$mode/visibility-policy.json", OracleJson.canonicalBytes(visibility))
                        assertEquals(OracleArtifacts.sha256(OracleJson.canonicalBytes(visibility)), request.retainedInputVisibilitySha256)
                        assertEquals("VISIBILITY_ONLY_OK", childMarker)
                        for ((relative, content) in canaries) {
                            val current = readBoundedBytes(runPath.resolve(relative), 4096)
                            record.retain("$mode/host-after/$relative", current)
                            assertContentEquals(content.toByteArray(), current)
                        }
                        val owned = readBoundedBytes(controlPath.resolve("owned-result"), 4096)
                        record.retain("$mode/owned-result", owned)
                        assertContentEquals("owned-write".toByteArray(), owned)
                        assertTrue(Files.notExists(runPath.resolve("overlay-residue"), LinkOption.NOFOLLOW_LINKS))
                        for (field in listOf("unitAbsent", "cgroupAbsent", "processesAbsent")) {
                            assertEquals(JsonPrimitive(true), executionDocument[field])
                        }
                    }

                    // The launcher authenticated this outcome before accepting or rejecting resource evidence.
                    assertEquals(JsonPrimitive("EXITED"), outcome["status"])
                    assertEquals(JsonPrimitive(0), outcome["exitCode"])
                    assertTrue(absenceProved)
                    assertEquals(3, processHandles.size, "retain all three attached keeper processes")
                    processHandles.forEach { assertTrue(!LinuxFilesystemSyscalls.processExists(it), "retained keeper survived cleanup") }
                    assertTrue(Files.notExists(Path.of("/sys/fs/cgroup").resolve(controlGroup.removePrefix("/")), LinkOption.NOFOLLOW_LINKS))
                    val unitsAfter = systemctl(configuration,
                        listOf("--no-legend", "--plain", "--full", "list-units", "--all", "--", unitName))
                    record.retain("$mode/systemd-units-after.txt", unitsAfter.toByteArray())
                    assertTrue(unitsAfter.isBlank(),
                        "completed contained unit remains in the manager inventory")
                }
            } finally {
                try {
                    cleanup?.let { retained ->
                        retained.closeAndProveAbsent()
                        absenceProved = retained.absenceProved
                    }
                    if (absenceProved) {
                        record.stage("$mode-remove-scratch")
                        lease.removeOperationRunRootAfterCgroupAbsence(token, 256, CLEANUP_MAXIMUM_BYTES)
                        lease.requireCleanAndRelease()
                        assertTrue(Files.notExists(runPath, LinkOption.NOFOLLOW_LINKS), "completed run root remains")
                        assertTrue(Files.list(mount).use { it.findAny().isEmpty }, "completed test must release its scratch lease")
                        record.retain("$mode/cleanup-observed.json", OracleJson.canonicalBytes(JsonObject(mapOf(
                            "unitName" to JsonPrimitive(unitName), "controlGroup" to JsonPrimitive(controlGroup),
                            "runPath" to JsonPrimitive(runPath.toString()), "scratchMount" to JsonPrimitive(mount.toString()),
                            "runAbsent" to JsonPrimitive(Files.notExists(runPath, LinkOption.NOFOLLOW_LINKS)),
                            "scratchEmpty" to JsonPrimitive(true), "retainedKeeperHandleCount" to JsonPrimitive(processHandles.size),
                            "retainedKeeperHandlesAbsent" to JsonPrimitive(
                                processHandles.all { !LinuxFilesystemSyscalls.processExists(it) }),
                        ))))
                    }
                } finally {
                    processHandles.forEach(LinuxProcessDescriptor::close)
                }
            }
        }
    }

    /** Passive reads of the actual attached keeper; none of these test records supplies launcher authority. */
    private fun captureDefaultKeeperLimits(attachment: JsonObject, controlGroup: String,
        record: ContainedModuleHostedCase.Case, mode: String): Long {
        val processes = (attachment.getValue("processes") as JsonArray).map { it as JsonObject }
        val keeper = processes.single { it.getValue("role").jsonPrimitive.content == "supervisor-jvm" }
        val pid = keeper.getValue("hostPid").jsonPrimitive.long
        val start = keeper.getValue("startTimeTicks").jsonPrimitive.long
        val namespaces = (keeper.getValue("namespacePids") as JsonArray).map { it.jsonPrimitive.long }
        val parentRole = keeper.getValue("parentRole").jsonPrimitive.content
        val parentPid = processes.single { it.getValue("role").jsonPrimitive.content == parentRole }
            .getValue("hostPid").jsonPrimitive.long
        fun read(name: String, destination: String): ByteArray = readBoundedBytes(Path.of("/proc/$pid/$name"),
            MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES).also { record.retain("$mode/keeper/$destination", it) }
        fun statusIdentity(bytes: ByteArray): Pair<List<Long>, Long> {
            val lines = bytes.toString(Charsets.UTF_8).lineSequence().toList()
            val ns = lines.single { it.startsWith("NSpid:") }.substringAfter(':').trim().split(Regex("[ \\t]+"))
                .map { requireNotNull(it.toLongOrNull()) }
            val parent = lines.single { it.startsWith("PPid:") }.substringAfter(':').trim().toLong()
            require(ns.size in 1..2 && ns.first() == pid && ns.all { it in 1L..Int.MAX_VALUE.toLong() })
            return ns to parent
        }
        LinuxFilesystemSyscalls.openProcessHandle(pid).use { handle ->
            assertTrue(LinuxFilesystemSyscalls.processExists(handle), "attached keeper is not alive before observation")
            val beforeStat = read("stat", "before-stat.txt")
            val beforeStatus = read("status", "before-status.txt")
            val beforeCgroup = read("cgroup", "before-cgroup.txt")
            val limits = read("limits", "limits.txt")
            val afterStat = read("stat", "after-stat.txt")
            val afterStatus = read("status", "after-status.txt")
            val afterCgroup = read("cgroup", "after-cgroup.txt")
            assertTrue(LinuxFilesystemSyscalls.processExists(handle), "attached keeper exited during observation")
            assertEquals(start, parseFullTreeFunctionObservationProcessStartTimeTicks(pid, beforeStat.toString(Charsets.UTF_8)))
            assertEquals(start, parseFullTreeFunctionObservationProcessStartTimeTicks(pid, afterStat.toString(Charsets.UTF_8)))
            assertEquals(namespaces to parentPid, statusIdentity(beforeStatus))
            assertEquals(namespaces to parentPid, statusIdentity(afterStatus))
            assertEquals("0::$controlGroup", beforeCgroup.toString(Charsets.UTF_8).trimEnd('\n'))
            assertContentEquals(beforeCgroup, afterCgroup)
            val pair = parseContainedCommandFileDescriptorLimits(limits.toString(Charsets.UTF_8))
            assertEquals(ContainedCommandFileDescriptorLimits(512, 512), pair)
            val observed = ContainedCommandFileDescriptorObservation(pid, start, pair)
            observed.requireIdentity(pid, start)
            record.retain("$mode/keeper/observation.json", OracleJson.canonicalBytes(observed.json()))
        }
        return namespaces.last()
    }

    private fun verifyChildDefaultLimits(stdout: ByteArray, outcome: JsonObject,
        record: ContainedModuleHostedCase.Case, mode: String): String {
        val lines = stdout.toString(Charsets.UTF_8).split('\n')
        assertEquals(6, lines.size, "fixture output has four raw observation records, one result marker and final LF")
        assertEquals("", lines.last())
        assertTrue(lines[0].startsWith("CHILD_PID="))
        val pid = requireNotNull(lines[0].removePrefix("CHILD_PID=").toLongOrNull())
        assertEquals(outcome.getValue("childPid").jsonPrimitive.long, pid)
        record.retain("$mode/child/namespace-pid.txt", "$pid\n".toByteArray())
        fun raw(index: Int, key: String, destination: String): ByteArray {
            assertTrue(lines[index].startsWith("$key="))
            val encoded = lines[index].removePrefix("$key=")
            require(encoded.length <= 4 * ((MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES + 2) / 3))
            val bytes = Base64.getDecoder().decode(encoded)
            require(bytes.size in 1..MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES)
            assertEquals(encoded, Base64.getEncoder().encodeToString(bytes))
            record.retain("$mode/child/$destination", bytes)
            return bytes
        }
        val before = raw(1, "CHILD_STAT_BEFORE", "before-stat.txt")
        val limits = raw(2, "CHILD_LIMITS", "limits.txt")
        val after = raw(3, "CHILD_STAT_AFTER", "after-stat.txt")
        val beforeStart = parseFullTreeFunctionObservationProcessStartTimeTicks(pid, before.toString(Charsets.UTF_8))
        assertEquals(beforeStart, parseFullTreeFunctionObservationProcessStartTimeTicks(pid, after.toString(Charsets.UTF_8)))
        assertEquals(ContainedCommandFileDescriptorLimits(512, 512),
            parseContainedCommandFileDescriptorLimits(limits.toString(Charsets.UTF_8)))
        return lines[4]
    }

    private fun retainAvailableLifecycle(controlPath: Path, record: ContainedModuleHostedCase.Case, mode: String) {
        val paths = linkedMapOf(
            "request.json" to "runtime/contained-command-request.json",
            "boot.json" to KotlinContainedCommandProtocol.BOOT_FILE,
            "start.json" to KotlinContainedCommandProtocol.START_FILE,
            "outcome.json" to KotlinContainedCommandProtocol.OUTCOME_FILE,
            "stdout.bin" to "reports/${KotlinContainedCommandProtocol.STDOUT_FILE}",
            "stderr.bin" to "reports/${KotlinContainedCommandProtocol.STDERR_FILE}",
        )
        for ((name, relative) in paths) {
            val path = controlPath.resolve(relative)
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                record.retain("$mode/$name", readBoundedBytes(path, MAXIMUM_RETAINED_MEMBER_BYTES))
            }
        }
    }

    private fun availableConfiguration(runtimeParent: Path): FullTreeFunctionObservationIsolationConfiguration? {
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val runtime = Path.of("/run/user/$uid")
        if (!Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS) || !Files.exists(runtime.resolve("bus"))) return null
        val java = realExecutable(Path.of(System.getProperty("java.home"), "bin", "java")) ?: return null
        val javaRuntime = Path.of(System.getProperty("java.home")).toRealPath()
        val bwrap = realExecutable(Path.of("/usr/bin/bwrap")) ?: return null
        val prlimit = realExecutable(Path.of("/usr/bin/prlimit")) ?: return null
        val systemdRun = realExecutable(Path.of("/usr/bin/systemd-run")) ?: return null
        val systemctl = realExecutable(Path.of("/usr/bin/systemctl")) ?: return null
        val busctl = realExecutable(Path.of("/usr/bin/busctl")) ?: return null
        val abi = when (System.getProperty("os.arch")) {
            "amd64", "x86_64" -> "x86_64-linux-gnu"
            "aarch64", "arm64" -> "aarch64-linux-gnu"
            else -> return null
        }
        val manifests = mutableMapOf<Path, String>()
        val libraries = listOf("/lib/$abi", "/lib64", "/usr/lib/$abi", "/usr/lib64")
            .map(Path::of).filter { Files.isDirectory(it) }.map { directory ->
                val source = directory.toRealPath()
                val destination = if (abi == "aarch64-linux-gnu" && directory == Path.of("/lib/$abi")) Path.of("/lib") else directory
                FullTreeFunctionObservationRuntimeMount(source, destination,
                    manifests.getOrPut(source) { calculateFullTreeObservationRuntimeManifestSha256(source) })
            }
        return FullTreeFunctionObservationIsolationConfiguration(
            javaExecutable = java,
            javaRuntime = FullTreeFunctionObservationRuntimeMount(javaRuntime, Path.of("/decomp-runtime/java"),
                calculateFullTreeObservationRuntimeManifestSha256(javaRuntime)),
            systemLibraryMounts = libraries,
            bubblewrapExecutable = bwrap,
            resourceLimiterExecutable = prlimit,
            scopeSupervisorExecutable = systemdRun,
            scopeInspectorExecutable = systemctl,
            systemdBusControllerExecutable = busctl,
            systemdUserRuntimeDirectory = runtime,
            workerClassPath = keeperClassPath(runtimeParent),
            expectedJavaSha256 = sha256(java), expectedBubblewrapSha256 = sha256(bwrap),
            expectedResourceLimiterSha256 = sha256(prlimit), expectedScopeSupervisorSha256 = sha256(systemdRun),
            expectedScopeInspectorSha256 = sha256(systemctl), expectedSystemdBusControllerSha256 = sha256(busctl),
        )
    }

    private fun keeperClassPath(runtimeParent: Path): List<FullTreeFunctionObservationClassPathEntry> {
        // Match the existing bounded BOOT fixture's selected deployment containers, excluding the
        // complete test runtime. Preserve the original JNA/SQLite JARs for native-policy authentication.
        val sources = listOf(KotlinContainedCommandKeeper::class.java, Unit::class.java, com.sun.jna.Native::class.java,
            org.sqlite.JDBC::class.java, kotlinx.serialization.json.Json::class.java,
            kotlinx.serialization.KSerializer::class.java, com.fasterxml.jackson.core.JsonFactory::class.java)
            .map { Path.of(checkNotNull(it.protectionDomain.codeSource).location.toURI()).toAbsolutePath().normalize() }
            .toMutableList()
        val policy = checkNotNull(OracleNativeLibraries::class.java.getResource("/oracle-native-libraries-v1.properties"))
        sources.add(when (policy.protocol) {
            "file" -> Path.of(policy.toURI()).parent
            "jar" -> Path.of((policy.openConnection() as java.net.JarURLConnection).jarFileURL.toURI())
            else -> error("native policy has no local deployment container")
        })
        var totalBytes = 0L
        return sources.distinct().mapIndexed { index, source ->
            val remaining = KEEPER_CLASSPATH_MAXIMUM_BYTES - totalBytes
            require(remaining > 0) { "keeper closure exceeds its scratch allowance" }
            val regular = if (Files.isDirectory(source, LinkOption.NOFOLLOW_LINKS)) {
                runtimeParent.resolve("keeper-$index.jar").also { packJar(source, it, remaining) }
            } else source
            require(Files.isRegularFile(regular, LinkOption.NOFOLLOW_LINKS))
            val bytes = Files.size(regular)
            require(bytes in 1..remaining) { "keeper closure exceeds its scratch allowance" }
            totalBytes = Math.addExact(totalBytes, bytes)
            FullTreeFunctionObservationClassPathEntry(regular, sha256(regular))
        }.also { entries ->
            println("contained terminal-resource keeper classpath: ${entries.size} entries, $totalBytes bytes; maximum $KEEPER_CLASSPATH_MAXIMUM_BYTES bytes")
        }
    }

    private fun compileFixture(root: Path): Path {
        val source = root.resolve("$FIXTURE_CLASS.java")
        Files.writeString(source, FIXTURE_SOURCE)
        val classes = privateDirectory(root.resolve("fixture-classes"))
        val compiler = assertNotNull(ToolProvider.getSystemJavaCompiler(), "live fixture requires the test JDK compiler")
        assertEquals(0, compiler.run(null, null, null, "-d", classes.toString(), source.toString()))
        return privateDirectory(root.resolve("fixture-runtime")).resolve("fixture.jar").also { packJar(classes, it, 1024L * 1024) }
    }

    private fun packJar(source: Path, target: Path, maximumBytes: Long) {
        val output = object : java.io.FilterOutputStream(Files.newOutputStream(target)) {
            private var count = 0L
            override fun write(value: Int) {
                require(count < maximumBytes) { "packed fixture JAR exceeds its byte allowance" }
                out.write(value)
                count++
            }
            override fun write(bytes: ByteArray, offset: Int, length: Int) {
                require(length.toLong() <= maximumBytes - count) { "packed fixture JAR exceeds its byte allowance" }
                out.write(bytes, offset, length)
                count += length
            }
        }
        try {
            JarOutputStream(output).use { jar ->
                Files.walk(source).use { files ->
                    files.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.sorted().forEach { file ->
                        jar.putNextEntry(JarEntry(source.relativize(file).joinToString("/")))
                        Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS).use { it.copyTo(jar) }
                        jar.closeEntry()
                    }
                }
            }
        } catch (failure: Throwable) {
            runCatching { Files.deleteIfExists(target) }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
    }

    private fun systemctl(configuration: FullTreeFunctionObservationIsolationConfiguration, arguments: List<String>): String {
        val process = ProcessBuilder(listOf(configuration.scopeInspectorExecutable.toString(), "--user", "--no-pager") + arguments)
            .redirectErrorStream(true).also { builder ->
                builder.environment().clear()
                builder.environment()["XDG_RUNTIME_DIR"] = configuration.systemdUserRuntimeDirectory.toString()
                builder.environment()["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=${configuration.systemdUserRuntimeDirectory.resolve("bus")}"
            }.start()
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            process.waitFor(1, TimeUnit.SECONDS)
            error("live fixture systemd query timed out")
        }
        val bytes = process.inputStream.use { it.readNBytes(4097) }
        assertTrue(bytes.size <= 4096)
        assertEquals(0, process.exitValue(), bytes.toString(Charsets.UTF_8))
        return bytes.toString(Charsets.UTF_8)
    }

    private fun provisionedScratchMount(): Path {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")
        requireOrAssume(!configured.isNullOrBlank(), "set DECOMP_TEST_ORACLE_EXT4_SCRATCH to the provisioned empty private ext4 slot")
        return Path.of(checkNotNull(configured)).toAbsolutePath().normalize()
    }

    private fun requireOrAssume(condition: Boolean, message: String) {
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true" ||
            System.getenv("GENERATED_C_MODULE_COMPILE_REQUIRE") == "true") assertTrue(condition, message)
        else assumeTrue(condition, message)
    }

    private fun realExecutable(path: Path): Path? = runCatching { path.toRealPath() }.getOrNull()
        ?.takeIf { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(it) }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun readBoundedBytes(path: Path, maximumBytes: Int): ByteArray {
        require(maximumBytes in 1..MAXIMUM_RETAINED_MEMBER_BYTES)
        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "bounded fixture record must be a regular file: $path" }
        return Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            input.readNBytes(maximumBytes + 1).also { require(it.size <= maximumBytes) { "fixture record exceeds its bound: $path" } }
        }
    }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input ->
            val buffer = ByteArray(1024 * 1024)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                digest.update(buffer, 0, count)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private fun randomDigest(): String = OracleArtifacts.sha256(UUID.randomUUID().toString().toByteArray())

    private companion object {
        const val FIXTURE_CLASS = "TerminalResourceFixture"
        const val DEFAULT_METHOD = "strict generic command accepts clean exit and rejects handled task limit with zero exit"
        const val VISIBILITY_METHOD = "configured visibility only command retains selected files and proves owned cleanup"
        const val MAXIMUM_RETAINED_MEMBER_BYTES = 4 * 1024 * 1024
        const val MAXIMUM_CHILD_OUTPUT_BYTES = 512 * 1024
        val VISIBILITY_CANARIES = linkedMapOf(
            "reports/selected.txt" to "selected-retained-input",
            "reports/hidden.txt" to "forbidden-report",
            "state/hidden.txt" to "forbidden-state",
            "untracked-sibling/hidden.txt" to "forbidden-untracked",
        )
        // Match the bounded BOOT fixture: reserve 16 MiB of the unchanged 64 MiB slot for metadata,
        // protocol and temporary files. The contained resource contract also bounds total cleanup.
        const val KEEPER_CLASSPATH_MAXIMUM_BYTES = 48L * 1024 * 1024
        const val CLEANUP_MAXIMUM_BYTES = 64L * 1024 * 1024
        val FIXTURE_SOURCE = """
            import java.io.IOException;
            import java.io.InputStream;
            import java.nio.file.Files;
            import java.nio.file.Path;
            import java.nio.file.StandardOpenOption;
            import java.util.Base64;
            import java.util.concurrent.CountDownLatch;

            public final class TerminalResourceFixture {
                private static byte[] bounded(Path path) throws IOException {
                    try (InputStream input = Files.newInputStream(path)) {
                        byte[] bytes = input.readNBytes(65537);
                        if (bytes.length == 0 || bytes.length > 65536) throw new IOException("proc record exceeds fixture bound");
                        return bytes;
                    }
                }
                private static void observeSelf() throws IOException {
                    long pid = ProcessHandle.current().pid();
                    byte[] before = bounded(Path.of("/proc/self/stat"));
                    byte[] limits = bounded(Path.of("/proc/self/limits"));
                    byte[] after = bounded(Path.of("/proc/self/stat"));
                    System.out.println("CHILD_PID=" + pid);
                    System.out.println("CHILD_STAT_BEFORE=" + Base64.getEncoder().encodeToString(before));
                    System.out.println("CHILD_LIMITS=" + Base64.getEncoder().encodeToString(limits));
                    System.out.println("CHILD_STAT_AFTER=" + Base64.getEncoder().encodeToString(after));
                }
                private static void requireReadonly(Path path) throws IOException {
                    try { Files.writeString(path, "unauthorized-write"); }
                    catch (IOException expected) { return; }
                    throw new IllegalStateException("forbidden writable path: " + path);
                }
                private static void visibility(Path root, String active) throws IOException {
                    Path selected = root.resolve("reports/selected.txt");
                    if (!Files.readString(selected).equals("selected-retained-input")) throw new IllegalStateException("selected input differs");
                    requireReadonly(selected);
                    for (String relative : new String[] {"reports/hidden.txt", "state/hidden.txt", "untracked-sibling/hidden.txt"}) {
                        try { Files.readAllBytes(root.resolve(relative)); }
                        catch (IOException expected) { continue; }
                        throw new IllegalStateException("forbidden readable path: " + relative);
                    }
                    requireReadonly(root.resolve("overlay-residue"));
                    requireReadonly(root.resolve("reports/unauthorized-file"));
                    Files.writeString(root.resolve(active).resolve("owned-result"), "owned-write", StandardOpenOption.CREATE_NEW);
                    System.out.println("VISIBILITY_ONLY_OK");
                }
                public static void main(String[] args) throws Exception {
                    if (args.length < 1) throw new IllegalArgumentException("one mode is required");
                    boolean visibility = args[0].equals("visibility");
                    if (args.length != (visibility ? 3 : 1)) throw new IllegalArgumentException("mode arguments differ");
                    observeSelf();
                    if (visibility) {
                        visibility(Path.of(args[1]), args[2]);
                        return;
                    }
                    if (args[0].equals("benign")) {
                        System.out.println("BENIGN_EXIT_ZERO");
                        return;
                    }
                    if (!args[0].equals("refusal")) throw new IllegalArgumentException("unknown mode");
                    CountDownLatch release = new CountDownLatch(1);
                    Thread[] threads = new Thread[256];
                    int started = 0;
                    boolean refused = false;
                    try {
                        for (int i = 0; i < threads.length; i++) {
                            Thread thread = new Thread(() -> {
                                try { release.await(); }
                                catch (InterruptedException interrupted) { Thread.currentThread().interrupt(); }
                            }, "terminal-resource-" + i);
                            thread.setDaemon(true);
                            try {
                                thread.start();
                                threads[started++] = thread;
                            } catch (OutOfMemoryError failure) {
                                if (failure.getMessage() == null || !failure.getMessage().contains("unable to create native thread")) throw failure;
                                refused = true;
                                break;
                            }
                        }
                    } finally {
                        release.countDown();
                        for (int i = 0; i < started; i++) threads[i].join();
                    }
                    if (!refused) throw new IllegalStateException("task limit was not reached");
                    System.out.println("HANDLED_PIDS_REFUSAL_EXIT_ZERO");
                }
            }
        """.trimIndent()
    }
}
