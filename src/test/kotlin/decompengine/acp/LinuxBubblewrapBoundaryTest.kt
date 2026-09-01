package decompengine.acp

import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.UserDefinedFileAttributeView
import java.security.MessageDigest
import java.time.Duration
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class LinuxBubblewrapBoundaryTest {
    @Test
    fun `mandatory command fragment isolates namespaces and never weakens bubblewrap`() {
        val arguments = acpBubblewrapIsolationArguments()
        listOf(
            "--unshare-all", "--unshare-user", "--new-session", "--die-with-parent",
            "--clearenv", "--disable-userns", "--assert-userns-disabled", "--cap-drop",
            "--proc", "--dev", "--tmpfs",
        ).forEach { assertTrue(it in arguments) }
        assertFalse("--share-net" in arguments)
        assertFalse("--not-a-security-boundary" in arguments)
        assertFalse("--block-fd" in arguments)
        listOf(
            "261.1",
            "261.1\n",
            "255.4-1ubuntu8.16\n",
            "252.30-1~deb12u2\r\n",
        ).forEach { assertTrue(isValidSystemdManagerVersionOutput(it), it) }
        listOf(
            "",
            "systemd 261.1\n",
            " 261.1\n",
            "261.1 packaged\n",
            "261.1\nignored",
            "261.1\n\n",
            "1".repeat(129),
        ).forEach { assertFalse(isValidSystemdManagerVersionOutput(it), it) }
        var committed = false
        commitSandboxAuthorization(object : OutputStream() {
            override fun write(value: Int) {
                committed = value == 'G'.code
                throw IOException("ambiguous peer close after delivery")
            }
        })
        assertTrue(committed)
    }

    @Test
    fun `missing digest mismatched and mutable ancestor security tools fail closed`() {
        assertFailsWith<IOException> {
            LinuxBubblewrapBoundary.prepare(
                syntheticConfiguration(Path.of("/definitely-absent/decomp-bwrap"), "0".repeat(64)),
            )
        }
        assumeTrue(Files.isExecutable(BWRAP), "digest mismatch probe requires /usr/bin/bwrap")
        assertFailsWith<IOException> {
            LinuxBubblewrapBoundary.prepare(syntheticConfiguration(BWRAP, "0".repeat(64)))
        }
        assumeTrue(Files.isExecutable(BASH), "ancestor-chain probe requires /usr/bin/bash")
        val mutableParent = createTempDirectory("acp-mutable-tool-parent-").toAbsolutePath().normalize()
        val copiedTool = mutableParent.resolve("bash")
        Files.copy(BASH, copiedTool)
        Files.setPosixFilePermissions(copiedTool, OWNER_EXECUTABLE)
        assertFailsWith<IOException> {
            PinnedSecurityExecutable.pin(copiedTool, "mutable-parent tool", sha256(copiedTool))
        }
        val linkedParent = mutableParent.resolve("bin-link")
        Files.createSymbolicLink(linkedParent, Path.of("/usr/bin"))
        assertFailsWith<IOException> {
            PinnedSecurityExecutable.pin(linkedParent.resolve("bash"), "symlinked tool", sha256(BASH))
        }
        val attributed = mutableParent.resolve("attributed-tool")
        Files.copy(BASH, attributed)
        val attributeView = Files.getFileAttributeView(attributed, UserDefinedFileAttributeView::class.java)
        val attributeCreated = runCatching {
            attributeView?.write("decomp-acp-test", ByteBuffer.wrap(byteArrayOf(1))) ?: return@runCatching false
            true
        }.getOrDefault(false)
        if (attributeCreated) {
            Files.setPosixFilePermissions(attributed, OWNER_READ_EXECUTE)
            // An ordinary user attribute is stable metadata, not write authority, and is accepted.
            requireSafeSandboxTrustExtendedAttributes(attributed)
        }
        if (Files.isExecutable(SETFACL)) {
            val aclPath = mutableParent.resolve("acl-tool")
            Files.copy(BASH, aclPath)
            Files.setPosixFilePermissions(aclPath, OWNER_READ_EXECUTE)
            val setAcl = ProcessBuilder(
                SETFACL.toString(), "-m", "u:65534:rw", aclPath.toString(),
            ).redirectErrorStream(true).start()
            setAcl.inputStream.readNBytes(4096)
            if (setAcl.waitFor(3, TimeUnit.SECONDS) && setAcl.exitValue() == 0) {
                assertFailsWith<IOException> { requireSafeSandboxTrustExtendedAttributes(aclPath) }
            }
        }
        repeat(5) { Files.writeString(mutableParent.resolve("entry-$it"), "x") }
        LinuxFilesystemSyscalls.openRoot(mutableParent).use { directory ->
            assertFailsWith<LinuxResourceLimitException> {
                LinuxFilesystemSyscalls.directoryEntryNames(directory, maximumEntries = 4)
            }
        }
        val pinnedFilePath = mutableParent.resolve("pinned-mode-file")
        val heldFilePath = mutableParent.resolve("pinned-mode-file-held")
        Files.writeString(pinnedFilePath, "authorized")
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(pinnedFilePath)!!.use { pinned ->
            val expectedKey = pinned.identity.key
            val expectedMountId = pinned.identity.mountId
            Files.move(pinnedFilePath, heldFilePath)
            Files.writeString(pinnedFilePath, "replacement")
            Files.setPosixFilePermissions(pinnedFilePath, OWNER_READ_WRITE)
            LinuxFilesystemSyscalls.chmodPinned(pinned, 0x140)
            val after = LinuxFilesystemSyscalls.identity(pinned.fd)
            assertEquals(expectedKey, after.key)
            assertEquals(expectedMountId, after.mountId)
            assertEquals(OWNER_READ_EXECUTE, Files.getPosixFilePermissions(heldFilePath))
            assertEquals(OWNER_READ_WRITE, Files.getPosixFilePermissions(pinnedFilePath))
        }
        val pinnedDirectoryPath = mutableParent.resolve("pinned-mode-directory")
        val heldDirectoryPath = mutableParent.resolve("pinned-mode-directory-held")
        Files.createDirectory(pinnedDirectoryPath)
        LinuxFilesystemSyscalls.openAbsolutePathOrNull(pinnedDirectoryPath)!!.use { pinned ->
            val expectedKey = pinned.identity.key
            val expectedMountId = pinned.identity.mountId
            Files.move(pinnedDirectoryPath, heldDirectoryPath)
            Files.createDirectory(pinnedDirectoryPath)
            Files.setPosixFilePermissions(pinnedDirectoryPath, OWNER_ONLY)
            LinuxFilesystemSyscalls.chmodPinned(pinned, 0x140)
            val after = LinuxFilesystemSyscalls.identity(pinned.fd)
            assertEquals(expectedKey, after.key)
            assertEquals(expectedMountId, after.mountId)
            assertEquals(OWNER_READ_EXECUTE, Files.getPosixFilePermissions(heldDirectoryPath))
            assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(pinnedDirectoryPath))
        }
        val wide = createTempDirectory("acp-cleanup-wide-").toAbsolutePath().normalize()
        repeat(5) { Files.writeString(wide.resolve("entry-$it"), "x") }
        LinuxFilesystemSyscalls.openRoot(wide).use { directory ->
            assertFailsWith<LinuxResourceLimitException> {
                deletePrivateTreeContents(directory, AcpRuntimeClosureLimits(4, 1024, 4))
            }
        }
        clearStaging(wide)
        Files.delete(wide)

        val deep = createTempDirectory("acp-cleanup-deep-").toAbsolutePath().normalize()
        var nested = deep
        repeat(4) { depth ->
            nested = Files.createDirectory(nested.resolve("depth-$depth"))
        }
        LinuxFilesystemSyscalls.openRoot(deep).use { directory ->
            assertFailsWith<LinuxResourceLimitException> {
                deletePrivateTreeContents(directory, AcpRuntimeClosureLimits(32, 1024, 2))
            }
        }
        clearStaging(deep)
        Files.delete(deep)

        val oversized = createTempDirectory("acp-cleanup-bytes-").toAbsolutePath().normalize()
        Files.write(oversized.resolve("large"), ByteArray(2048))
        LinuxFilesystemSyscalls.openRoot(oversized).use { directory ->
            assertFailsWith<LinuxResourceLimitException> {
                deletePrivateTreeContents(directory, AcpRuntimeClosureLimits(4, 1024, 2))
            }
        }
        clearStaging(oversized)
        Files.delete(oversized)
    }

    @Test
    fun `static helper attests inherited or closed stdin and denies malformed protocols`() {
        requireCompiledFixtures()
        val success = runDirectGate("PUBLIC_VALUE=visible\u0000".toByteArray(), "GZ".toByteArray())
        assertEquals(0, success.first, success.second)
        assertEquals("visible:Z\n", success.second)
        val closed = runDirectGate(
            "PUBLIC_VALUE=visible\u0000".toByteArray(),
            "GZ".toByteArray(),
            stdinDispositionArgument = AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC.protocolArgument,
        )
        assertEquals(80, closed.first, closed.second)
        assertEquals("", closed.second)
        val unknownDisposition = runDirectGate(
            "PUBLIC_VALUE=visible\u0000".toByteArray(),
            "GZ".toByteArray(),
            stdinDispositionArgument = "closed-after-exec",
        )
        assertNotEquals(0, unknownDisposition.first)
        assertEquals("", unknownDisposition.second)
        listOf(ByteArray(0), "XZ".toByteArray()).forEach { input ->
            val denied = runDirectGate("PUBLIC_VALUE=visible\u0000".toByteArray(), input)
            assertNotEquals(0, denied.first)
            assertEquals("", denied.second)
        }
        val malformed = runDirectGate("B=2\u0000A=1\u0000".toByteArray(), "GZ".toByteArray())
        assertNotEquals(0, malformed.first)
        assertEquals("", malformed.second)
        val exactPwd = runDirectGate(
            "PUBLIC_VALUE=visible\u0000".toByteArray(),
            "GZ".toByteArray(),
            bootstrapEnvironment = mapOf("PWD" to Path.of("/proc/self/cwd").toRealPath().toString()),
        )
        assertEquals(0, exactPwd.first, exactPwd.second)
        assertEquals("visible:Z\n", exactPwd.second)
        val polluted = runDirectGate(
            "PUBLIC_VALUE=visible\u0000".toByteArray(),
            "GZ".toByteArray(),
            bootstrapEnvironment = mapOf("UNEXPECTED" to "untrusted"),
        )
        assertNotEquals(0, polluted.first)
        assertEquals("", polluted.second)
        val script = createTempDirectory("acp-gate-script-").resolve("script")
        script.writeText("#!/bin/sh\nprintf EXECUTED\n")
        Files.setPosixFilePermissions(script, OWNER_EXECUTABLE)
        val scriptDenied = runDirectGate(ByteArray(0), "G".toByteArray(), script, emptyList())
        assertNotEquals(0, scriptDenied.first)
        assertEquals("", scriptDenied.second)
    }

    @Test
    fun `Ninja query purpose alone requires closed stdin separate pipes and no ambient roots`() {
        fun launch(
            purpose: AcpSandboxLaunchPurpose,
            stdin: AcpSandboxStdinDisposition,
            stagingRoots: List<AcpSandboxRootGrant> = emptyList(),
            emptyDirectories: List<Path> = emptyList(),
        ) = AcpSandboxLaunch(
            command = listOf("/usr/bin/ninja", "-t", "compdb"),
            environment = emptyMap(),
            workingDirectory = Path.of("/build"),
            resourceLimits = TEST_LIMITS,
            maximumWallDuration = Duration.ofSeconds(5),
            readOnlyMounts = emptyList(),
            stagingRoots = stagingRoots,
            purpose = purpose,
            emptyDirectories = emptyDirectories,
            stdinDisposition = stdin,
        )

        assertFailsWith<IllegalArgumentException> {
            launch(
                AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
                AcpSandboxStdinDisposition.INHERITED_PIPE,
            )
        }
        listOf(AcpSandboxLaunchPurpose.OUTER_AGENT, AcpSandboxLaunchPurpose.TERMINAL).forEach { purpose ->
            assertFailsWith<IllegalArgumentException> {
                launch(purpose, AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            launch(
                AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
                AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC,
                emptyDirectories = listOf(Path.of("/build")),
            )
        }

        val stagingParent = createTempDirectory("acp-ninja-purpose-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("ninja-stage", stagingParent)
        try {
            assertFailsWith<IllegalArgumentException> {
                launch(
                    AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
                    AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC,
                    stagingRoots = listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
                )
            }
        } finally {
            Files.deleteIfExists(staging.path)
            Files.deleteIfExists(stagingParent)
        }

        val query = launch(
            AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
            AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC,
        )
        val configuration = syntheticConfiguration(
            Path.of("/definitely-absent/decomp-bwrap"),
            "0".repeat(64),
        )
        requireAcpSandboxLaunchPolicy(configuration, query, mergeError = false)
        assertFailsWith<IOException> {
            requireAcpSandboxLaunchPolicy(configuration, query, mergeError = true)
        }
    }

    @Test
    fun `Ninja runtime closure is immutable bounded manifested and exact at protected destinations`() {
        val manifest = "a".repeat(64)
        fun mount(source: String, destination: String, expected: String? = manifest) =
            AcpSandboxReadOnlyMount(Path.of(source), Path.of(destination), expected)

        val trusted = mount(
            "/usr/lib64/decomp-ninja-lib.so",
            "/usr/lib64/decomp-ninja-lib.so",
        )
        val supplied = mutableListOf(trusted)
        val configuration = syntheticConfiguration(
            Path.of("/definitely-absent/decomp-bwrap"),
            "0".repeat(64),
            ninjaCompdbRuntimeMounts = supplied,
        )
        supplied.clear()
        assertEquals(listOf(trusted), configuration.ninjaCompdbRuntimeMounts)
        assertFailsWith<IllegalArgumentException> {
            syntheticConfiguration(
                Path.of("/definitely-absent/decomp-bwrap"),
                "0".repeat(64),
                ninjaCompdbRuntimeMounts = listOf(
                    mount("/usr/lib64/unmanifested.so", "/usr/lib64/unmanifested.so", null),
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            syntheticConfiguration(
                Path.of("/definitely-absent/decomp-bwrap"),
                "0".repeat(64),
                agentRuntimeMounts = listOf(
                    mount("/usr/lib64/agent.so", "/usr/lib64/agent.so"),
                ),
                ninjaCompdbRuntimeMounts = (0 until MAXIMUM_SANDBOX_MOUNTS).map { index ->
                    mount("/opt/ninja-lib-$index", "/usr/lib64/decomp-ninja-lib-$index.so")
                },
            )
        }

        val executable = mount("/usr/bin/ninja", "/usr/bin/ninja")
        val buildTree = mount("/opt/decomp-ninja-build", "/build")
        fun query(runtime: List<AcpSandboxReadOnlyMount>) = AcpSandboxLaunch(
            command = listOf("/usr/bin/ninja", "-f", "build.ninja", "-t", "compdb", "cc"),
            environment = emptyMap(),
            workingDirectory = Path.of("/build"),
            resourceLimits = TEST_LIMITS,
            maximumWallDuration = Duration.ofSeconds(5),
            readOnlyMounts = listOf(executable, buildTree) + runtime,
            stagingRoots = emptyList(),
            purpose = AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
            stdinDisposition = AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC,
        )

        requireAcpSandboxLaunchPolicy(configuration, query(listOf(trusted)), mergeError = false)
        listOf(
            emptyList(),
            listOf(mount("/usr/lib64/replacement.so", trusted.destination.toString())),
            listOf(mount(trusted.source.toString(), trusted.destination.toString(), "b".repeat(64))),
            listOf(trusted, mount("/lib64/unconfigured.so", "/lib64/unconfigured.so")),
        ).forEach { runtime ->
            assertFailsWith<IOException> {
                requireAcpSandboxLaunchPolicy(configuration, query(runtime), mergeError = false)
            }
        }

        val outerConfiguration = syntheticConfiguration(
            Path.of("/definitely-absent/decomp-bwrap"),
            "0".repeat(64),
            agentRuntimeMounts = listOf(trusted),
        )
        val outer = query(listOf(trusted)).copy(
            purpose = AcpSandboxLaunchPurpose.OUTER_AGENT,
            stdinDisposition = AcpSandboxStdinDisposition.INHERITED_PIPE,
        )
        requireAcpSandboxLaunchPolicy(outerConfiguration, outer, mergeError = false)
        assertFailsWith<IOException> {
            requireAcpSandboxLaunchPolicy(
                outerConfiguration,
                outer.copy(readOnlyMounts = listOf(
                    executable,
                    buildTree,
                    mount("/usr/lib64/replacement.so", trusted.destination.toString()),
                )),
                mergeError = false,
            )
        }
    }

    @Test
    fun `live boundary hides host data isolates network and launches concurrently through static helpers`() {
        requireLiveHost()
        val observed = mutableListOf<List<String>>()
        val boundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            observer = AcpSandboxCommandObserver { command ->
                observed.add(command)
                assertPrivateSnapshotLayering(command)
            },
        )
        try {
            val workspace = createTempDirectory("acp-private-anchor-").toAbsolutePath().normalize()
            val secret = workspace.resolve("host-only.txt").also { it.writeText("must stay hidden") }
            launchAndAwait(
                boundary,
                listOf("visibility", workspace.toString(), secret.toString()),
                emptyDirectories = listOf(workspace),
            )
            val net = launchAndAwait(boundary, listOf("netns"), captureOutput = true)
            assertNotEquals(Files.readSymbolicLink(Path.of("/proc/self/ns/net")).toString(), net.trim())
            val longLived = boundary.launch(probeLaunch(listOf("terminal-sleep")), true) {}
            try {
                val deadline = System.nanoTime() + Duration.ofSeconds(5).toNanos()
                val concurrent = boundary.launch(probeLaunch(listOf("netns")), true) {
                    if (System.nanoTime() >= deadline) throw IOException("concurrent launch serialized")
                }
                assertTrue(concurrent.process.waitFor(5, TimeUnit.SECONDS))
                assertEquals(0, concurrent.process.exitValue())
                concurrent.awaitCleanup(Duration.ofSeconds(5))
                assertTrue(longLived.process.isAlive)
                val launches = boundary.evidence(null).launches.takeLast(2)
                assertNotEquals(
                    launches[0].environment.device to launches[0].environment.inode,
                    launches[1].environment.device to launches[1].environment.inode,
                )
            } finally {
                longLived.destroyForcibly()
                longLived.awaitCleanup(Duration.ofSeconds(5))
            }
            observed.forEach { command ->
                assertEquals(PRLIMIT.toString(), command.first())
                listOf(SYSTEMD_RUN.toString(), BASH.toString(), "--unshare-all", "--new-session", "--clearenv")
                    .forEach { assertTrue(it in command) }
                assertTrue(command.any { it.contains("exec 4<") })
                assertTrue("--property=OOMPolicy=kill" in command)
                assertFalse(command.any { it.startsWith("--property=MemoryOOMGroup=") })
                assertTrue("--ro-bind-fd" in command)
                assertTrue("/decomp-acp-internal/gate-helper" in command)
                assertFalse("--block-fd" in command)
                assertFalse(command.any { it.contains("flock") })
            }
            val evidence = boundary.evidence(null)
            assertEquals(6, evidence.securityExecutables.size)
            assertTrue(evidence.securityExecutables.all { it.mode and 0x12 == 0 })
            assertTrue(evidence.launches.all { launch ->
                launch.controllers.pidsMax == launch.resourceLimits.maximumProcesses.toLong() &&
                    launch.controllers.memoryMaxBytes == launch.resourceLimits.maximumAddressSpaceBytes &&
                    launch.controllers.memorySwapMaxBytes == 0L && launch.controllers.memoryOomGroup &&
                    launch.startGate.descriptor == 0 && launch.startGate.positiveByteRequired &&
                    launch.environment.linkCount == 0 &&
                    launch.effectiveRlimits.openFilesSoft == launch.resourceLimits.maximumOpenFiles.toLong()
            })
            assertTrue(evidence.evidenceSha256.matches(Regex("[0-9a-f]{64}")))
        } finally {
            boundary.close()
        }
    }

    @Test
    fun `launch hooks and cancellation at every pre-G stage leave no scope snapshot or evidence`() {
        requireLiveHost()
        AcpSandboxLaunchStage.entries.forEach { stage ->
            val before = controlDirectories()
            val units = mutableListOf<String>()
            val scopes = mutableListOf<AcpSandboxScopeIdentity>()
            val boundary = LinuxBubblewrapBoundary.prepare(
                liveConfiguration(),
                observer = unitObserver(units),
                launchHook = AcpSandboxLaunchHook { if (it == stage) throw IOException("injected $stage") },
                scopeObserver = AcpSandboxScopeObserver { identity -> scopes.add(identity) },
            )
            try {
                assertFailsWith<IOException> { boundary.launch(probeLaunch(listOf("netns")), true) {} }
                assertTrue(boundary.evidence(null).launches.isEmpty())
            } finally {
                boundary.close()
            }
            assertBoundaryResidueAbsent(before, units, scopes)
        }
        AcpSandboxLaunchStage.entries.forEach { stage ->
            val cancelled = AtomicBoolean(false)
            val units = mutableListOf<String>()
            val scopes = mutableListOf<AcpSandboxScopeIdentity>()
            val boundary = LinuxBubblewrapBoundary.prepare(
                liveConfiguration(),
                observer = unitObserver(units),
                launchHook = AcpSandboxLaunchHook { if (it == stage) cancelled.set(true) },
                scopeObserver = AcpSandboxScopeObserver { identity -> scopes.add(identity) },
            )
            try {
                assertFailsWith<IOException> {
                    boundary.launch(probeLaunch(listOf("netns")), true) {
                        if (cancelled.get()) throw IOException("injected cancellation")
                    }
                }
                assertTrue(boundary.evidence(null).launches.isEmpty())
            } finally {
                boundary.close()
            }
            units.forEach(::assertUnitAbsent)
            scopes.forEach { assertFalse(Files.exists(it.cgroupPath, LinkOption.NOFOLLOW_LINKS)) }
        }
    }

    @Test
    fun `preparation and policy validation abort inside authenticated runtime work without residue`() {
        requireLiveHost()
        val before = controlDirectories()
        val preparationCheckpoint = AtomicBoolean(false)
        assertFailsWith<IOException> {
            LinuxBubblewrapBoundary.prepare(
                liveConfiguration(),
                cancellationCheck = {
                    if (Thread.currentThread().stackTrace.any { it.methodName == "copyRuntimeNode" } &&
                        preparationCheckpoint.compareAndSet(false, true)
                    ) throw IOException("injected preparation cancellation")
                },
            )
        }
        assertTrue(preparationCheckpoint.get(), "preparation must checkpoint inside snapshot copying")
        assertEquals(before, controlDirectories())

        val validationSource = createTempDirectory("acp-validation-cancel-").toAbsolutePath().normalize()
        Files.write(validationSource.resolve("payload"), ByteArray(1024 * 1024) { 0x41 })
        val mount = AcpSandboxReadOnlyMount(
            validationSource,
            Path.of("/decomp-acp-test-validation"),
            calculateAcpRuntimeManifestSha256(validationSource),
        )
        val boundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        val validationCheckpoint = AtomicBoolean(false)
        try {
            assertFailsWith<IOException> {
                boundary.validateReadOnlyMounts(mounts = listOf(mount)) {
                    if (Thread.currentThread().stackTrace.any { it.methodName == "copyRuntimeNode" } &&
                        validationCheckpoint.compareAndSet(false, true)
                    ) throw IOException("injected validation deadline")
                }
            }
            assertTrue(validationCheckpoint.get(), "policy validation must checkpoint inside snapshot copying")
        } finally {
            boundary.close()
            Files.deleteIfExists(validationSource.resolve("payload"))
            Files.deleteIfExists(validationSource)
        }
        assertEquals(before, controlDirectories())

        val launchBoundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        val nprocCheckpoint = AtomicBoolean(false)
        try {
            assertFailsWith<IOException> {
                launchBoundary.launch(probeLaunch(listOf("netns")), true) {
                    if (Thread.currentThread().stackTrace.any { it.methodName == "nprocBackstop" } &&
                        nprocCheckpoint.compareAndSet(false, true)
                    ) throw IOException("injected pre-start deadline")
                }
            }
            assertTrue(nprocCheckpoint.get(), "the /proc task scan must checkpoint before scope start")
            assertTrue(launchBoundary.evidence(null).launches.isEmpty())
        } finally {
            launchBoundary.close()
        }
        assertEquals(before, controlDirectories())

        val environmentBoundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        val environmentCheckpoint = AtomicBoolean(false)
        val largeEnvironment = (0 until 256).associate { index ->
            "VALUE_$index" to "v".repeat(2048)
        }
        try {
            assertFailsWith<IOException> {
                environmentBoundary.launch(
                    probeLaunch(listOf("netns")).copy(environment = largeEnvironment),
                    true,
                ) {
                    if (Thread.currentThread().stackTrace.any {
                            it.methodName == "canonicalSandboxEnvironment"
                        } && environmentCheckpoint.compareAndSet(false, true)
                    ) throw IOException("injected environment canonicalization deadline")
                }
            }
            assertTrue(environmentCheckpoint.get(), "environment encoding must checkpoint before scope start")
            assertTrue(environmentBoundary.evidence(null).launches.isEmpty())
        } finally {
            environmentBoundary.close()
        }
        assertEquals(before, controlDirectories())

        val commandBoundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        val commandCheckpoints = AtomicInteger()
        try {
            assertFailsWith<IOException> {
                commandBoundary.launch(
                    probeLaunch(listOf("netns")).copy(
                        emptyDirectories = (0 until 200).map { Path.of("/workspace/anchor-$it/child") },
                    ),
                    true,
                ) {
                    if (Thread.currentThread().stackTrace.any { it.methodName == "buildBubblewrapCommand" } &&
                        commandCheckpoints.incrementAndGet() >= 32
                    ) throw IOException("injected command-construction deadline")
                }
            }
            assertTrue(commandCheckpoints.get() >= 32, "multi-entry command construction must checkpoint")
            assertTrue(commandBoundary.evidence(null).launches.isEmpty())
        } finally {
            commandBoundary.close()
        }
        assertEquals(before, controlDirectories())
    }

    @Test
    fun `stale pidfd cannot signal a later process`() {
        if (System.getProperty("os.name") != "Linux") {
            assertFailsWith<IOException> { LinuxFilesystemSyscalls.requirePidfdSupported() }
            return
        }
        LinuxFilesystemSyscalls.requirePidfdSupported()
        val exited = ProcessBuilder("/usr/bin/sleep", "30").start()
        val handle = LinuxFilesystemSyscalls.openProcessHandle(exited.pid())
        val survivor = ProcessBuilder("/usr/bin/sleep", "30").start()
        try {
            assertTrue(LinuxFilesystemSyscalls.processExists(handle))
            exited.destroyForcibly()
            assertTrue(exited.waitFor(3, TimeUnit.SECONDS))
            assertFalse(LinuxFilesystemSyscalls.processExists(handle))
            assertFalse(LinuxFilesystemSyscalls.killProcess(handle))
            assertTrue(survivor.isAlive, "a stale process handle must not signal another process")
        } finally {
            handle.close()
            survivor.destroyForcibly()
            survivor.waitFor(3, TimeUnit.SECONDS)
        }
    }

    @Test
    fun `restored path ABA and post-attestation target mutation never execute the target`() {
        requireLiveHost()
        runTargetPathAba()
        runEnvironmentPathAba()
        runStagingPathAba()
        runTargetContentMutation()
    }

    @Test
    fun `cgroup and pinned cleanup kill process trees surface proof faults and never delete ABA replacements`() {
        requireLiveHost()
        val scopeSignalFailure = AtomicBoolean(false)
        val rootSignalAttempted = AtomicBoolean(false)
        val fallbackBoundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            cleanupHook = AcpSandboxCleanupHook { stage ->
                when (stage) {
                    AcpSandboxCleanupStage.SCOPE_SIGNAL -> if (scopeSignalFailure.compareAndSet(false, true)) {
                        throw IOException("injected scope control failure")
                    }
                    AcpSandboxCleanupStage.ROOT_PROCESS_SIGNAL -> rootSignalAttempted.set(true)
                    else -> Unit
                }
            },
        )
        try {
            val gated = fallbackBoundary.launch(probeLaunch(listOf("terminal-sleep")), true) {}
            assertFailsWith<IOException> { gated.destroyForcibly() }
            assertTrue(rootSignalAttempted.get(), "scope failure must not skip the exact pidfd signal")
            assertTrue(gated.process.waitFor(5, TimeUnit.SECONDS))
            gated.awaitCleanup(Duration.ofSeconds(5))
        } finally {
            fallbackBoundary.close()
        }

        val boundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        lateinit var scope: AcpSandboxScopeIdentity
        try {
            val escaped = boundary.launch(probeLaunch(listOf("escape")), true) {}
            scope = escaped.scopeIdentity
            assertTrue(escaped.process.inputStream.bufferedReader().readLine().isNotBlank())
            escaped.destroyForcibly()
            escaped.awaitCleanup(Duration.ofSeconds(5))
            assertFalse(Files.exists(scope.cgroupPath, LinkOption.NOFOLLOW_LINKS))
            assertUnitAbsent(scope.unitName)
        } finally {
            boundary.close()
        }
        val injected = AtomicBoolean(false)
        val cleanupBoundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            cleanupHook = AcpSandboxCleanupHook { stage ->
                if (stage == AcpSandboxCleanupStage.RUNTIME_SNAPSHOTS && injected.compareAndSet(false, true)) {
                    throw IOException("injected cleanup proof failure")
                }
            },
        )
        val cleaned = cleanupBoundary.launch(probeLaunch(listOf("netns")), true) {}
        assertTrue(cleaned.process.waitFor(5, TimeUnit.SECONDS))
        assertFailsWith<AcpCleanupProofFailure> { cleaned.awaitCleanup(Duration.ofSeconds(5)) }
        assertFailsWith<AcpCleanupProofFailure> { cleanupBoundary.close() }
        assertFailsWith<AcpCleanupProofFailure> { cleanupBoundary.close() }

        val runtimeSource = AtomicReference<Path?>()
        val abaBoundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            observer = runtimeSourceObserver(runtimeSource),
        )
        launchAndAwait(abaBoundary, listOf("netns"))
        val control = requireNotNull(runtimeSource.get()).parent.parent
        val originalHolding = Path.of("/tmp", ".decomp-acp-original-${UUID.randomUUID()}")
        val replacementHolding = Path.of("/tmp", ".decomp-acp-replacement-${UUID.randomUUID()}")
        Files.move(control, originalHolding)
        Files.createDirectory(control)
        val marker = control.resolve("replacement-marker").also { it.writeText("preserve") }
        assertFailsWith<AcpCleanupProofFailure> { abaBoundary.close() }
        assertTrue(Files.isRegularFile(marker))
        Files.move(control, replacementHolding)
        Files.move(originalHolding, control)
        assertFailsWith<AcpCleanupProofFailure> { abaBoundary.close() }
        assertFalse(Files.exists(control))
        assertEquals("preserve", Files.readString(replacementHolding.resolve("replacement-marker")))
        Files.delete(replacementHolding.resolve("replacement-marker"))
        Files.delete(replacementHolding)
    }

    @Test
    fun `quota backed staging contains many entries sparse files and a background writer`() {
        requireLiveHost()
        val mountText = System.getenv("DECOMP_TEST_ACP_QUOTA_TMPFS")
        assumeTrue(
            !mountText.isNullOrBlank(),
            "set DECOMP_TEST_ACP_QUOTA_TMPFS to an empty user-owned 0700 dedicated tmpfs with finite size,nr_inodes",
        )
        val staging = AcpWorkflowStagingRoot.createQuotaBacked(
            "quota",
            Path.of(mountText).toAbsolutePath().normalize(),
            AcpStagingQuotaLimits(64L * 1024 * 1024, 4096),
        )
        val boundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        try {
            listOf("many-files", "many-dirs").forEach { mode ->
                launchAndAwait(listOf(mode, staging.path.toString(), "100000"), boundary, staging)
                clearStaging(staging.path)
            }
            launchAndAwait(
                listOf("sparse", staging.path.toString(), (128L * 1024 * 1024).toString()),
                boundary,
                staging,
            )
            clearStaging(staging.path)
            val background = boundary.launch(
                probeLaunch(listOf("background-writer", staging.path.toString()), staging = staging),
                true,
            ) {}
            val backgroundScope = background.scopeIdentity
            assertTrue(background.process.inputStream.bufferedReader().readLine().isNotBlank())
            background.destroyForcibly()
            background.awaitCleanup(Duration.ofSeconds(5))
            assertFalse(Files.exists(backgroundScope.cgroupPath, LinkOption.NOFOLLOW_LINKS))
            assertUnitAbsent(backgroundScope.unitName)
            staging.requireCurrentIdentity()
        } finally {
            boundary.close()
            clearStaging(staging.path)
            Files.deleteIfExists(staging.path)
        }
    }

    @Test
    fun `helper controls loader roots and request code stay unavailable before authorization`() {
        val staging = AcpWorkflowStagingRoot.createReadOnly(
            "stage",
            createTempDirectory("acp-helper-policy-").toAbsolutePath().normalize(),
        )
        listOf("LD_PRELOAD", "BASH_ENV", "ENV", "GCONV_PATH", "LOCPATH", "SHLVL").forEach { name ->
            assertFailsWith<IllegalArgumentException> {
                AcpTerminalCommandRule(
                    AcpSandboxReadOnlyMount(Path.of("/usr/bin/true")),
                    emptyList(),
                    staging.path,
                    mapOf(name to "untrusted"),
                )
            }
        }
        assertFailsWith<IllegalArgumentException> {
            AcpSandboxReadOnlyMount(
                Path.of("/usr/bin/true"),
                ACP_INTERNAL_SANDBOX_ROOT.resolve("gate-helper"),
            )
        }
        requireLiveHost()
        val injected = createTempDirectory("acp-loader-control-").resolve("ld.so.preload")
            .also { it.writeText("untrusted") }
        val boundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        try {
            val base = probeLaunch(listOf("netns"))
            listOf(
                Path.of("/etc/ld.so.preload"),
                Path.of("/etc/ld.so.cache"),
                Path.of("/lib/x86_64-linux-gnu/glibc-hwcaps/decomp-rogue.so"),
                Path.of("/etc"),
            ).forEach { destination ->
                val launch = base.copy(
                    readOnlyMounts = base.readOnlyMounts + AcpSandboxReadOnlyMount(
                        injected,
                        destination,
                        calculateAcpRuntimeManifestSha256(injected),
                    ),
                )
                assertFailsWith<IOException>(destination.toString()) { boundary.launch(launch, true) {} }
            }
            assertTrue(boundary.evidence(null).launches.isEmpty())
        } finally {
            boundary.close()
        }
    }

    private fun runTargetPathAba() {
        val source = AtomicReference<Path?>()
        val scope = AtomicReference<AcpSandboxScopeIdentity?>()
        val restored = AtomicBoolean(false)
        val boundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            observer = runtimeSourceObserver(source),
            scopeObserver = AcpSandboxScopeObserver(scope::set),
            launchHook = AcpSandboxLaunchHook { stage ->
                when (stage) {
                    AcpSandboxLaunchStage.BEFORE_SCOPE_START -> {
                        val runtime = requireNotNull(source.get())
                        val parent = runtime.parent
                        val authorized = parent.resolve("authorized")
                        Files.setPosixFilePermissions(parent, OWNER_ONLY)
                        val mode = Files.getPosixFilePermissions(runtime)
                        Files.move(runtime, authorized)
                        Files.copy(PROBE, runtime)
                        Files.setPosixFilePermissions(runtime, mode)
                    }
                    AcpSandboxLaunchStage.AFTER_SCOPE_ATTACHED_BEFORE_SETUP_ATTESTATION -> {
                        val runtime = requireNotNull(source.get())
                        val parent = runtime.parent
                        val authorized = parent.resolve("authorized")
                        val rogue = parent.resolve("rogue")
                        waitForGateHelper(requireNotNull(scope.get()))
                        Files.move(runtime, rogue)
                        Files.move(authorized, runtime)
                        Files.setPosixFilePermissions(parent, OWNER_READ_EXECUTE)
                        restored.set(true)
                    }
                    else -> Unit
                }
            },
        )
        try {
            assertFailsWith<IOException> { boundary.launch(probeLaunch(listOf("netns")), true) {} }
            assertTrue(restored.get())
            assertTrue(boundary.evidence(null).launches.isEmpty())
        } finally {
            boundary.close()
        }
    }

    private fun runEnvironmentPathAba() {
        val source = AtomicReference<Path?>()
        val scope = AtomicReference<AcpSandboxScopeIdentity?>()
        val restored = AtomicBoolean(false)
        val boundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            observer = AcpSandboxCommandObserver { command ->
                command.firstOrNull { it.contains(".decomp-acp-environment-") }?.let { source.set(Path.of(it)) }
            },
            scopeObserver = AcpSandboxScopeObserver(scope::set),
            launchHook = AcpSandboxLaunchHook { stage ->
                when (stage) {
                    AcpSandboxLaunchStage.BEFORE_SCOPE_START -> {
                        val environment = requireNotNull(source.get())
                        val authorized = environment.parent.resolve("authorized-environment")
                        Files.move(environment, authorized)
                        Files.write(environment, "PUBLIC_VALUE=rogue\u0000".toByteArray())
                        Files.setPosixFilePermissions(environment, OWNER_READ_WRITE)
                    }
                    AcpSandboxLaunchStage.AFTER_SCOPE_ATTACHED_BEFORE_SETUP_ATTESTATION -> {
                        val environment = requireNotNull(source.get())
                        val authorized = environment.parent.resolve("authorized-environment")
                        val rogue = environment.parent.resolve("rogue-environment")
                        waitForGateHelper(requireNotNull(scope.get()))
                        Files.move(environment, rogue)
                        Files.move(authorized, environment)
                        restored.set(true)
                    }
                    else -> Unit
                }
            },
        )
        try {
            val launch = probeLaunch(listOf("netns")).copy(environment = mapOf("PUBLIC_VALUE" to "safe"))
            assertFailsWith<IOException> { boundary.launch(launch, true) {} }
            assertTrue(restored.get())
            assertTrue(boundary.evidence(null).launches.isEmpty())
        } finally {
            boundary.close()
        }
    }

    private fun runStagingPathAba() {
        val parent = createTempDirectory("acp-staging-aba-").toAbsolutePath().normalize()
        val staging = AcpWorkflowStagingRoot.createReadOnly("stage", parent)
        val authorized = parent.resolve("authorized")
        val rogue = parent.resolve("rogue")
        val scope = AtomicReference<AcpSandboxScopeIdentity?>()
        val restored = AtomicBoolean(false)
        val boundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            scopeObserver = AcpSandboxScopeObserver(scope::set),
            launchHook = AcpSandboxLaunchHook { stage ->
                when (stage) {
                    AcpSandboxLaunchStage.BEFORE_SCOPE_START -> {
                        Files.move(staging.path, authorized)
                        Files.createDirectory(staging.path)
                        Files.setPosixFilePermissions(staging.path, OWNER_ONLY)
                    }
                    AcpSandboxLaunchStage.AFTER_SCOPE_ATTACHED_BEFORE_SETUP_ATTESTATION -> {
                        waitForGateHelper(requireNotNull(scope.get()))
                        Files.move(staging.path, rogue)
                        Files.move(authorized, staging.path)
                        restored.set(true)
                    }
                    else -> Unit
                }
            },
        )
        try {
            val launch = probeLaunch(listOf("netns")).copy(
                stagingRoots = listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)),
            )
            assertFailsWith<IOException> { boundary.launch(launch, true) {} }
            assertTrue(restored.get())
            staging.requireCurrentIdentity()
        } finally {
            boundary.close()
            Files.deleteIfExists(rogue)
        }
    }

    private fun runTargetContentMutation() {
        val source = AtomicReference<Path?>()
        val mutated = AtomicBoolean(false)
        val boundary = LinuxBubblewrapBoundary.prepare(
            liveConfiguration(),
            observer = runtimeSourceObserver(source),
            launchHook = AcpSandboxLaunchHook { stage ->
                if (stage == AcpSandboxLaunchStage.AFTER_SETUP_BIND_ATTESTATION_BEFORE_RELEASE) {
                    val runtime = requireNotNull(source.get())
                    val mode = Files.getPosixFilePermissions(runtime)
                    Files.setPosixFilePermissions(runtime, OWNER_EXECUTABLE)
                    Files.write(
                        runtime,
                        ByteArray(4096) { 0x5a.toByte() },
                        StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.WRITE,
                    )
                    Files.setPosixFilePermissions(runtime, mode)
                    mutated.set(true)
                }
            },
        )
        try {
            assertFailsWith<IOException> { boundary.launch(probeLaunch(listOf("netns")), true) {} }
            assertTrue(mutated.get())
            assertTrue(boundary.evidence(null).launches.isEmpty())
        } finally {
            boundary.close()
        }
    }

    private fun runDirectGate(
        environment: ByteArray,
        input: ByteArray,
        target: Path = PROBE,
        targetArguments: List<String> = listOf("gate-protocol"),
        bootstrapEnvironment: Map<String, String> = emptyMap(),
        stdinDispositionArgument: String = AcpSandboxStdinDisposition.INHERITED_PIPE.protocolArgument,
    ): Pair<Int, String> {
        val directory = createTempDirectory("acp-direct-gate-").toAbsolutePath().normalize()
        val environmentPath = directory.resolve("environment")
        Files.write(environmentPath, environment)
        Files.setPosixFilePermissions(environmentPath, OWNER_READ_WRITE)
        val process = ProcessBuilder(
            listOf(
                GATE_HELPER.toString(),
                stdinDispositionArgument,
                environmentPath.toString(),
                target.toString(),
            ) + targetArguments,
        ).redirectErrorStream(true).also {
            it.environment().clear()
            it.environment().putAll(bootstrapEnvironment)
        }.start()
        val deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos()
        while (System.nanoTime() < deadline && !Files.exists(Path.of("/proc/${process.pid()}/fd/4"))) {
            if (!process.isAlive) break
            Thread.sleep(10)
        }
        Files.deleteIfExists(environmentPath)
        try {
            if (input.isNotEmpty()) process.outputStream.write(input)
        } catch (_: IOException) {
            // A rejected bootstrap environment can close stdin before the test supplies a token.
        }
        try {
            process.outputStream.close()
        } catch (_: IOException) {
            // The rejected helper may already have closed the pipe.
        }
        assertTrue(process.waitFor(5, TimeUnit.SECONDS), "static helper direct probe timed out")
        val output = process.inputStream.readAllBytes().toString(Charsets.UTF_8)
        Files.deleteIfExists(environmentPath)
        Files.deleteIfExists(directory)
        return process.exitValue() to output
    }

    private fun launchAndAwait(
        boundary: LinuxBubblewrapBoundary,
        arguments: List<String>,
        emptyDirectories: List<Path> = emptyList(),
        staging: AcpWorkflowStagingRoot? = null,
        captureOutput: Boolean = false,
    ): String {
        val process = boundary.launch(probeLaunch(arguments, emptyDirectories, staging), true) {}
        assertTrue(process.process.waitFor(8, TimeUnit.SECONDS), "sandbox probe timed out")
        val output = if (captureOutput) process.process.inputStream.readAllBytes().toString(Charsets.UTF_8) else ""
        assertEquals(0, process.process.exitValue(), output)
        process.awaitCleanup(Duration.ofSeconds(5))
        return output
    }

    private fun launchAndAwait(
        arguments: List<String>,
        boundary: LinuxBubblewrapBoundary,
        staging: AcpWorkflowStagingRoot,
    ): String = launchAndAwait(boundary, arguments, staging = staging)

    private fun probeLaunch(
        arguments: List<String>,
        emptyDirectories: List<Path> = emptyList(),
        staging: AcpWorkflowStagingRoot? = null,
    ): AcpSandboxLaunch = AcpSandboxLaunch(
        command = listOf(PROBE_DESTINATION.toString()) + arguments,
        environment = emptyMap(),
        workingDirectory = Path.of("/tmp"),
        resourceLimits = TEST_LIMITS,
        maximumWallDuration = Duration.ofSeconds(5),
        readOnlyMounts = listOf(
            AcpSandboxReadOnlyMount(PROBE, PROBE_DESTINATION, calculateAcpRuntimeManifestSha256(PROBE)),
        ),
        stagingRoots = staging?.let {
            listOf(AcpSandboxRootGrant(it, AcpSandboxRootMode.READ_WRITE))
        }.orEmpty(),
        emptyDirectories = emptyDirectories,
    )

    private fun runtimeSourceObserver(result: AtomicReference<Path?>): AcpSandboxCommandObserver =
        AcpSandboxCommandObserver { command ->
            command.windowed(3).singleOrNull { window ->
                window[0] == "--ro-bind" && window[2] == PROBE_DESTINATION.toString()
            }?.get(1)?.let { result.set(Path.of(it)) }
        }

    private fun assertPrivateSnapshotLayering(command: List<String>) {
        val mountedRoots = command.windowed(3).mapNotNull { window ->
            if (window[0] != "--ro-bind") return@mapNotNull null
            val source = Path.of(window[1])
            source.takeIf {
                it.fileName?.toString() == "root" &&
                    it.parent?.fileName?.toString()?.startsWith("runtime-") == true &&
                    it.parent?.parent?.fileName?.toString()?.startsWith(".decomp-acp-control-") == true
            }
        }
        assertTrue(mountedRoots.isNotEmpty(), "live fixture should exercise private runtime snapshots")
        mountedRoots.forEach { root ->
            val containerMode = (Files.getAttribute(root.parent, "unix:mode") as Number).toInt().permissions
            val mountedMode = (Files.getAttribute(root, "unix:mode") as Number).toInt().permissions
            assertEquals(0x1c0, containerMode, "snapshot container must remain exact mode 0700")
            assertEquals(0, mountedMode and 0x92, "mounted snapshot root must be non-writable")
        }
    }

    private fun unitObserver(units: MutableList<String>): AcpSandboxCommandObserver =
        AcpSandboxCommandObserver { command ->
            command.firstOrNull { it.startsWith("--unit=") }
                ?.removePrefix("--unit=")
                ?.let(units::add)
        }

    private fun waitForGateHelper(scope: AcpSandboxScopeIdentity) {
        val deadline = System.nanoTime() + Duration.ofSeconds(3).toNanos()
        while (System.nanoTime() < deadline) {
            val found = runCatching {
                Files.readAllLines(scope.cgroupPath.resolve("cgroup.procs"))
                    .mapNotNull { it.trim().toLongOrNull() }
                    .any { pid ->
                        runCatching {
                            Files.readAllBytes(Path.of("/proc/$pid/cmdline"))
                                .toString(Charsets.UTF_8)
                                .startsWith("/decomp-acp-internal/gate-helper\u0000")
                        }.getOrDefault(false)
                    }
            }.getOrDefault(false)
            if (found) return
            Thread.sleep(10)
        }
        throw IOException("test did not observe the static helper blocked before authorization")
    }

    private fun assertBoundaryResidueAbsent(
        before: Set<Path>,
        units: Collection<String>,
        scopes: Collection<AcpSandboxScopeIdentity>,
    ) {
        assertEquals(before, controlDirectories())
        units.forEach(::assertUnitAbsent)
        scopes.forEach { assertFalse(Files.exists(it.cgroupPath, LinkOption.NOFOLLOW_LINKS)) }
    }

    private fun requireCompiledFixtures() {
        assumeTrue(Files.isExecutable(CC), "static ACP fixtures require /usr/bin/cc")
        assumeTrue(GATE_HELPER_RESULT.isSuccess, "static gate helper unavailable: ${GATE_HELPER_RESULT.exceptionOrNull()}")
        assumeTrue(PROBE_RESULT.isSuccess, "static probe unavailable: ${PROBE_RESULT.exceptionOrNull()}")
    }

    private fun requireLiveHost() {
        requireCompiledFixtures()
        val missing = SECURITY_TOOLS.filterNot(Files::isExecutable)
        assumeTrue(missing.isEmpty(), "live ACP sandbox tools unavailable: $missing")
        assumeTrue(Files.exists(USER_RUNTIME.resolve("bus")), "systemd user bus is unavailable")
        assumeTrue(Files.isRegularFile(Path.of("/sys/fs/cgroup/cgroup.controllers")), "cgroup v2 is unavailable")
    }

    private fun liveConfiguration(): AcpLinuxSandboxConfiguration = AcpLinuxSandboxConfiguration(
        bubblewrapExecutable = BWRAP,
        resourceLimiterExecutable = PRLIMIT,
        scopeSupervisorExecutable = SYSTEMD_RUN,
        scopeInspectorExecutable = SYSTEMCTL,
        environmentFdOpenerExecutable = BASH,
        sandboxGateHelperExecutable = GATE_HELPER,
        launcherRuntimeMounts = emptyList(),
        agentRuntimeMounts = emptyList(),
        systemdUserRuntimeDirectory = USER_RUNTIME,
        agentResourceLimits = TEST_LIMITS,
        expectedBubblewrapSha256 = sha256(BWRAP),
        expectedResourceLimiterSha256 = sha256(PRLIMIT),
        expectedScopeSupervisorSha256 = sha256(SYSTEMD_RUN),
        expectedScopeInspectorSha256 = sha256(SYSTEMCTL),
        expectedEnvironmentFdOpenerSha256 = sha256(BASH),
        expectedSandboxGateHelperSha256 = sha256(GATE_HELPER),
        expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(GATE_HELPER),
    )

    private fun syntheticConfiguration(
        executable: Path,
        digest: String,
        agentRuntimeMounts: Collection<AcpSandboxReadOnlyMount> = emptyList(),
        ninjaCompdbRuntimeMounts: Collection<AcpSandboxReadOnlyMount> = emptyList(),
    ): AcpLinuxSandboxConfiguration =
        AcpLinuxSandboxConfiguration(
            bubblewrapExecutable = executable,
            resourceLimiterExecutable = Path.of("/definitely-absent/decomp-prlimit"),
            scopeSupervisorExecutable = Path.of("/definitely-absent/decomp-systemd-run"),
            scopeInspectorExecutable = Path.of("/definitely-absent/decomp-systemctl"),
            environmentFdOpenerExecutable = Path.of("/definitely-absent/decomp-bash"),
            sandboxGateHelperExecutable = Path.of("/definitely-absent/decomp-gate-helper"),
            launcherRuntimeMounts = emptyList(),
            agentRuntimeMounts = agentRuntimeMounts,
            systemdUserRuntimeDirectory = Path.of("/definitely-absent/decomp-runtime"),
            expectedBubblewrapSha256 = digest,
            expectedResourceLimiterSha256 = "0".repeat(64),
            expectedScopeSupervisorSha256 = "0".repeat(64),
            expectedScopeInspectorSha256 = "0".repeat(64),
            expectedEnvironmentFdOpenerSha256 = "0".repeat(64),
            expectedSandboxGateHelperSha256 = "0".repeat(64),
            expectedSandboxGateHelperManifestSha256 = "0".repeat(64),
            ninjaCompdbRuntimeMounts = ninjaCompdbRuntimeMounts,
        )

    private fun controlDirectories(): Set<Path> = Files.list(Path.of("/tmp")).use { entries ->
        entries.filter { it.fileName.toString().startsWith(".decomp-acp-control-") }.toList().toSet()
    }

    private fun assertUnitAbsent(unitName: String) {
        val process = ProcessBuilder(
            SYSTEMCTL.toString(), "--user", "show", "--property=LoadState", "--value", unitName,
        ).redirectErrorStream(true).also { builder ->
            builder.environment().clear()
            builder.environment()["XDG_RUNTIME_DIR"] = USER_RUNTIME.toString()
            builder.environment()["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=${USER_RUNTIME.resolve("bus")}"
        }.start()
        val output = process.inputStream.readNBytes(4096).toString(Charsets.UTF_8).trim()
        assertTrue(process.waitFor(3, TimeUnit.SECONDS))
        assertEquals("not-found", output)
    }

    private fun clearStaging(root: Path) {
        if (!Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS)) return
        Files.walk(root).use { entries ->
            entries.sorted(Comparator.reverseOrder()).filter { it != root }.forEach(Files::deleteIfExists)
        }
    }

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { "%02x".format(it) }

    private companion object {
        val BWRAP: Path = Path.of("/usr/bin/bwrap")
        val PRLIMIT: Path = Path.of("/usr/bin/prlimit")
        val SYSTEMD_RUN: Path = Path.of("/usr/bin/systemd-run")
        val SYSTEMCTL: Path = Path.of("/usr/bin/systemctl")
        val BASH: Path = Path.of("/usr/bin/bash")
        val CC: Path = Path.of("/usr/bin/cc")
        val SETFACL: Path = Path.of("/usr/bin/setfacl")
        val USER_RUNTIME: Path by lazy {
            Path.of("/run/user/${(Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()}")
        }
        val SECURITY_TOOLS = listOf(BWRAP, PRLIMIT, SYSTEMD_RUN, SYSTEMCTL, BASH)
        val GATE_HELPER_RESULT: Result<Path> by lazy { runCatching(::productionAcpGateHelper) }
        val PROBE_RESULT: Result<Path> by lazy {
            runCatching {
                val source = Path.of(
                    requireNotNull(LinuxBubblewrapBoundaryTest::class.java.getResource("/acp/sandbox_probe.c")).toURI(),
                )
                compileStatic(source, "acp-static-probe-")
            }
        }
        val GATE_HELPER: Path get() = GATE_HELPER_RESULT.getOrThrow()
        val PROBE: Path get() = PROBE_RESULT.getOrThrow()
        val PROBE_DESTINATION: Path = Path.of("/decomp-acp-test-probe")
        val OWNER_ONLY = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
        val OWNER_READ_EXECUTE = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_EXECUTE,
        )
        val OWNER_READ_WRITE = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
        )
        val OWNER_EXECUTABLE = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
        val TEST_LIMITS = AcpSandboxResourceLimits(
            maximumProcesses = 12,
            maximumOpenFiles = 64,
            maximumFileBytes = 64L * 1024 * 1024,
            maximumAddressSpaceBytes = 256L * 1024 * 1024,
            maximumCpuSeconds = 8,
        )

        private fun compileStatic(source: Path, prefix: String): Path {
            val output = createTempDirectory(prefix).resolve("program").toAbsolutePath().normalize()
            val process = ProcessBuilder(
                CC.toString(), "-std=c11", "-O2", "-static", source.toString(), "-o", output.toString(),
            ).redirectErrorStream(true).start()
            val diagnostics = process.inputStream.readNBytes(32 * 1024).toString(Charsets.UTF_8)
            if (!process.waitFor(20, TimeUnit.SECONDS) || process.exitValue() != 0) {
                throw IOException("static fixture compile failed: $diagnostics")
            }
            return output
        }
    }
}
