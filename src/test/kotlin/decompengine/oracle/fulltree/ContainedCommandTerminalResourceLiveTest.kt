package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxProcessDescriptor
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import javax.tools.ToolProvider
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
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
        assumeTrue(System.getProperty("os.name").lowercase().contains("linux"))
        val mount = provisionedScratchMount()
        inControlTemporaryDirectory { root ->
            val configuration = availableConfiguration(privateDirectory(root.resolve("runtime")))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertNotNull(configuration, "required live contained-command boundary is unavailable")
            }
            assumeTrue(configuration != null, "live contained-command boundary is unavailable")
            checkNotNull(configuration)
            val fixture = compileFixture(root)
            val managerCgroup = systemctl(configuration, listOf("show", "--property=ControlGroup", "--value")).trim()
            require(managerCgroup.startsWith('/') && !managerCgroup.contains(".."))

            for (mode in listOf("benign", "refusal")) {
                exerciseCommand(mount, configuration, fixture, managerCgroup, mode)
            }
        }
    }

    private fun exerciseCommand(
        mount: Path,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        fixture: Path,
        managerCgroup: String,
        mode: String,
    ) {
        assertTrue(Files.list(mount).use { it.findAny().isEmpty }, "provisioned ext4 slot must be empty")
        val capacity = LinuxFilesystemSyscalls.openRoot(mount).use(LinuxFilesystemSyscalls::filesystemCapacity)
        val operationId = randomDigest()
        val operation = FullTreeDiskScratchOperation(operationId, randomDigest(), "terminal-resource-$mode", randomDigest())
        val policy = FullTreeDiskScratchPolicy(1, capacity.totalBytes, 4, capacity.totalInodes)
        val fixtureInput = KotlinSystemdCgroupCommandInput(fixture, Files.size(fixture), sha256(fixture))
        val deploymentClosureSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("contained-command-terminal-resource-test-deployment-v1"),
            "configurationSha256" to JsonPrimitive(configuration.canonicalSha256),
            "fixtureSha256" to JsonPrimitive(fixtureInput.sha256),
        ))))
        val unitName = "decomp-terminal-resource-${operationId.take(32)}.scope"
        val controlGroup = "${managerCgroup.trimEnd('/')}/app.slice/$unitName"
        val processHandles = mutableListOf<LinuxProcessDescriptor>()
        FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(mount, operation, policy).use { lease ->
            val token = lease.createEmptyOperationRunRoot()
            val runPath = lease.withCurrentOperationRunRootBeforeLaunch(token) { borrowed ->
                borrowed.withPinnedDescriptor { directory ->
                    for (name in listOf("state", "reports", "tmp")) {
                        LinuxFilesystemSyscalls.createDirectory(directory.fd, name, 448)
                    }
                }
                borrowed.path
            }
            var absenceProved = true
            var cleanup: KotlinSystemdCgroupCommandCleanup? = null
            try {
                lease.withCurrentOperationRunRootForContainedExecution(token) { borrowed ->
                    var attachmentBytes: ByteArray? = null
                    var execution: KotlinSystemdCgroupCommandExecution? = null
                    var failure: KotlinSystemdCgroupCommandExecutionException? = null
                    absenceProved = false
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
                                "-XX:+DisableAttachMechanism", "-Djava.io.tmpdir=${runPath.resolve("tmp")}",
                                "-classpath", fixture.toString(), FIXTURE_CLASS, mode,
                            ),
                            environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
                            readOnlyInputs = listOf(fixtureInput),
                            // The launcher deduplicates this already authenticated root-owned runtime mount.
                            runtimeMounts = listOf(configuration.javaRuntime),
                            resources = KotlinSystemdCgroupCommandResources(30_000, 512L * 1024 * 1024, 64, CLEANUP_MAXIMUM_BYTES),
                            deploymentClosureSha256 = deploymentClosureSha256,
                            beforeStart = { attachment ->
                                attachmentBytes = attachment.canonicalBytes
                                val document = OracleJson.parseCanonical(attachment.canonicalBytes) as JsonObject
                                for (process in document.getValue("processes") as JsonArray) {
                                    val pid = (process as JsonObject).getValue("hostPid").jsonPrimitive.long
                                    processHandles += LinuxFilesystemSyscalls.openProcessHandle(pid)
                                }
                            },
                            requireTerminalResourceEventProof = true,
                        )
                        absenceProved = true
                    } catch (caught: KotlinSystemdCgroupCommandExecutionException) {
                        failure = caught
                        cleanup = caught.cleanup
                        absenceProved = caught.cleanup.absenceProved
                    }

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
                        assertEquals("BENIGN_EXIT_ZERO\n", readBounded(runPath.resolve("reports").resolve(KotlinContainedCommandProtocol.STDOUT_FILE)))
                    } else {
                        val refused = assertNotNull(failure, "a handled pids.max refusal must invalidate the zero exit")
                        assertTrue(generateSequence<Throwable>(refused) { it.cause }.any {
                            it.message.orEmpty().contains("contained command terminal resource limit event: pids.max")
                        }, refused.stackTraceToString())
                        assertNull(execution, "resource refusal must not produce an accepted execution")
                        assertTrue(refused.cleanup.absenceProved, "strict refusal must complete its cleanup proof")
                        refused.cleanup.closeAndProveAbsent()
                        assertEquals("HANDLED_PIDS_REFUSAL_EXIT_ZERO\n",
                            readBounded(runPath.resolve("reports").resolve(KotlinContainedCommandProtocol.STDOUT_FILE)))
                    }

                    // The launcher authenticated this outcome before accepting or rejecting resource evidence.
                    val outcome = OracleJson.parseCanonical(Files.readAllBytes(runPath.resolve(KotlinContainedCommandProtocol.OUTCOME_FILE))) as JsonObject
                    assertEquals(JsonPrimitive("EXITED"), outcome["status"])
                    assertEquals(JsonPrimitive(0), outcome["exitCode"])
                    assertTrue(absenceProved)
                    assertEquals(3, processHandles.size, "retain all three attached keeper processes")
                    processHandles.forEach { assertTrue(!LinuxFilesystemSyscalls.processExists(it), "retained keeper survived cleanup") }
                    assertTrue(Files.notExists(Path.of("/sys/fs/cgroup").resolve(controlGroup.removePrefix("/")), LinkOption.NOFOLLOW_LINKS))
                    assertTrue(systemctl(configuration,
                        listOf("--no-legend", "--plain", "--full", "list-units", "--all", "--", unitName)).isBlank(),
                        "completed contained unit remains in the manager inventory")
                }
            } finally {
                try {
                    cleanup?.let { retained ->
                        retained.closeAndProveAbsent()
                        absenceProved = retained.absenceProved
                    }
                    if (absenceProved) {
                        lease.removeOperationRunRootAfterCgroupAbsence(token, 256, CLEANUP_MAXIMUM_BYTES)
                        lease.requireCleanAndRelease()
                        assertTrue(Files.list(mount).use { it.findAny().isEmpty }, "completed test must release its scratch lease")
                    }
                } finally {
                    processHandles.forEach(LinuxProcessDescriptor::close)
                }
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
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
            assertTrue(!configured.isNullOrBlank(), "required CI ext4 scratch slot was not provisioned")
        }
        assumeTrue(!configured.isNullOrBlank(), "set DECOMP_TEST_ORACLE_EXT4_SCRATCH to the provisioned empty private ext4 slot")
        return Path.of(checkNotNull(configured)).toAbsolutePath().normalize()
    }

    private fun realExecutable(path: Path): Path? = runCatching { path.toRealPath() }.getOrNull()
        ?.takeIf { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(it) }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun readBounded(path: Path): String = Files.newInputStream(path).use { input ->
        input.readNBytes(4097).also { require(it.size <= 4096) }.toString(Charsets.UTF_8)
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
        // Match the bounded BOOT fixture: reserve 16 MiB of the unchanged 64 MiB slot for metadata,
        // protocol and temporary files. The contained resource contract also bounds total cleanup.
        const val KEEPER_CLASSPATH_MAXIMUM_BYTES = 48L * 1024 * 1024
        const val CLEANUP_MAXIMUM_BYTES = 64L * 1024 * 1024
        val FIXTURE_SOURCE = """
            import java.util.concurrent.CountDownLatch;

            public final class TerminalResourceFixture {
                public static void main(String[] args) throws Exception {
                    if (args.length != 1) throw new IllegalArgumentException("one mode is required");
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
