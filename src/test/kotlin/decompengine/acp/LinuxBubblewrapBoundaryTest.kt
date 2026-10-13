package decompengine.acp

import decompengine.agent.AgentAccessPolicy
import decompengine.agent.AgentCancellation
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionRequest
import decompengine.agent.AgentOperation
import decompengine.agent.AgentPathRule
import decompengine.agent.AgentWorkspacePath
import decompengine.agent.AgentWorkspaceRoot
import org.junit.jupiter.api.AfterAll
import java.io.IOException
import java.io.OutputStream
import java.nio.ByteBuffer
import java.nio.file.Files
import java.nio.file.FileAlreadyExistsException
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.UserDefinedFileAttributeView
import java.security.MessageDigest
import java.time.Duration
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlinx.coroutines.runBlocking
import com.agentclientprotocol.protocol.AcpExpectedError
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class LinuxBubblewrapBoundaryTest {
    @Test
    fun `configured temporary parent pins private controls and exact fd probe beside a disjoint workspace`() {
        PROBE_RESULT.getOrNull()?.let { fixture ->
            assertTrue(fixture.startsWith(repositoryRoot()))
        }
        withRepositoryTemporaryDirectory("acp-private-control-parent-") { base ->
            val parentAncestor = Files.createDirectory(base.resolve("control-root"))
            val parent = Files.createDirectory(parentAncestor.resolve("control-parent"))
            Files.setPosixFilePermissions(parent, OWNER_ONLY)
            val workspace = Files.createDirectory(base.resolve("workspace"))
            val replacementParent = Files.createDirectory(workspace.resolve("control-parent"))
            withTemporaryParent(parent.toString()) {
                val pinnedTemporaryParent = requireNotNull(
                    invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()),
                )
                try {
                    val temporaryParentType = Class.forName("decompengine.acp.PinnedSandboxControlTemporaryParent")
                    val validated = invokePrivate(
                        pinnedTemporaryParent,
                        temporaryParentType.getDeclaredMethod("getPath"),
                    ) as Path
                    assertEquals(parent, validated)
                    val probeMethod = Class.forName("decompengine.acp.LinuxBubblewrapBoundaryKt")
                        .getDeclaredMethod(
                            "probeEnvironmentFdOpener",
                            Path::class.java,
                            temporaryParentType,
                            Function0::class.java,
                        )
                    val type = Class.forName("decompengine.acp.PinnedControlDirectory")
                    val companion = type.getDeclaredField("Companion").apply { isAccessible = true }.get(null)
                    val createMethod = companion.javaClass.getDeclaredMethod(
                        "create",
                        AcpRuntimeClosureLimits::class.java,
                        temporaryParentType,
                    )
                    val runtimeClosureLimits = AcpRuntimeClosureLimits(32, 1024, 4)
                    val movedAncestor = base.resolve("control-root-pinned")
                    try {
                        Files.move(parentAncestor, movedAncestor)
                        Files.createSymbolicLink(parentAncestor, workspace)
                        assertFailsWith<IOException> {
                            invokePrivate(null, probeMethod, BASH, pinnedTemporaryParent, {})
                        }
                        assertFailsWith<IOException> {
                            invokePrivate(companion, createMethod, runtimeClosureLimits, pinnedTemporaryParent)
                        }
                        assertTrue(Files.list(replacementParent).use { it.findAny().isEmpty })
                        assertTrue(Files.list(movedAncestor.resolve("control-parent")).use { it.findAny().isEmpty })
                    } finally {
                        Files.deleteIfExists(parentAncestor)
                        if (Files.exists(movedAncestor, LinkOption.NOFOLLOW_LINKS)) {
                            Files.move(movedAncestor, parentAncestor)
                        }
                    }
                    invokePrivate(null, probeMethod, BASH, pinnedTemporaryParent, {})
                    assertTrue(Files.list(parent).use { it.findAny().isEmpty })
                    val control = invokePrivate(
                        companion,
                        createMethod,
                        runtimeClosureLimits,
                        pinnedTemporaryParent,
                    )!!
                    val controlPath = invokePrivate(control, type.getDeclaredMethod("getPath")) as Path
                    try {
                        assertEquals(parent, controlPath.parent)
                        assertEquals(OWNER_ONLY, Files.getPosixFilePermissions(controlPath))
                        LinuxFilesystemSyscalls.openRoot(parent).use { pinnedParent ->
                            LinuxFilesystemSyscalls.openRoot(controlPath).use { pinnedChild ->
                                assertEquals(pinnedParent.identity.mountId, pinnedChild.identity.mountId)
                                assertEquals(
                                    (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt(),
                                    pinnedChild.identity.uid,
                                )
                            }
                        }
                        invokePrivate(control, type.getDeclaredMethod("requireCurrent"))
                        val mountSourceGuard = type.getDeclaredMethod("requireMountSourceUnexposed", Path::class.java, Function0::class.java)
                        listOf(base, parent, controlPath, controlPath.resolve("child")).forEach { exposed ->
                            assertFailsWith<IOException> { invokePrivate(control, mountSourceGuard, exposed, {}) }
                        }
                        Files.writeString(controlPath.resolve("cleanup-marker"), "private-control-canary")
                        assertEquals(setOf(replacementParent), Files.list(workspace).use { it.toList().toSet() })
                        assertEquals(setOf(controlPath), Files.list(parent).use { it.toList().toSet() })
                    } finally {
                        invokePrivate(control, type.getDeclaredMethod("deleteAndProve"))
                    }
                    assertTrue(Files.list(parent).use { it.findAny().isEmpty })
                } finally {
                    invokePrivate(pinnedTemporaryParent, AutoCloseable::class.java.getMethod("close"))
                }
            }
            // Default Linux compatibility can be checked without creating any additional host-/tmp files.
            withTemporaryParent("/tmp") {
                val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                try {
                    assertEquals(
                        Path.of("/tmp"),
                        invokePrivate(
                            pinned,
                            Class.forName("decompengine.acp.PinnedSandboxControlTemporaryParent")
                                .getDeclaredMethod("getPath"),
                        ),
                    )
                } finally {
                    invokePrivate(pinned, AutoCloseable::class.java.getMethod("close"))
                }
            }
        }
    }

    @Test
    fun `temporary parent rejects missing relative noncanonical file and symlink paths before host probes`() {
        var failedSetupBase: Path? = null
        assertFailsWith<IOException> {
            withRepositoryTemporaryDirectory("acp-setup-failure-") { partial ->
                failedSetupBase = partial
                assertTrue(partial.startsWith(repositoryRoot()))
                Files.createDirectory(partial.resolve("partial-setup"))
                throw IOException("injected setup failure")
            }
        }
        assertFalse(Files.exists(requireNotNull(failedSetupBase)))

        withRepositoryTemporaryDirectory("acp-invalid-control-parent-") { base ->
            val parent = Files.createDirectory(base.resolve("real"))
            val file = Files.writeString(base.resolve("file"), "not a directory")
            val link = Files.createSymbolicLink(base.resolve("link"), parent)
            val nested = Files.createDirectory(parent.resolve("nested"))
            listOf(null, "", "relative", "\u0000", base.resolve("missing").toString(), file.toString(),
                link.toString(), link.resolve("nested").toString(), nested.resolve("..").toString()).forEach { value ->
                withTemporaryParent(value) {
                    val failure = assertFailsWith<IOException> {
                        LinuxBubblewrapBoundary.prepare(
                            syntheticConfiguration(Path.of("/definitely-absent/decomp-bwrap"), "0".repeat(64)),
                        )
                    }
                    assertTrue(failure.message.orEmpty().contains("temporary parent"), value.orEmpty())
                    assertTrue(Files.list(nested).use { it.findAny().isEmpty })
                }
            }
        }
    }

    @Test
    fun `repository-local workspace anchor hides controls while host mount sources remain rejected`() {
        requireLiveHost()
        withRepositoryTemporaryDirectory("acp-repository-local-anchor-") { workspace ->
            val controlParent = Files.createDirectory(workspace.resolve("private-tmp"))
            withTemporaryParent(controlParent.toString()) {
                val controlsBefore = controlDirectories()
                val boundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
                try {
                    val controlPath = (controlDirectories() - controlsBefore).single()
                    assertTrue(controlPath.startsWith(workspace))

                    val request = AgentExecutionRequest(
                        objective = "verify sandbox-only workspace anchors",
                        workspaceRoots = listOf(AgentWorkspaceRoot("repository", workspace)),
                        accessPolicy = AgentAccessPolicy(emptyList()),
                    )
                    val filesystemWithoutGrants = AcpFilesystemBroker.open(
                        request,
                        AcpFilesystemLimits(),
                        AcpFilesystemAuditRecorder(),
                    )
                    try {
                        assertEquals(null, filesystemWithoutGrants.capability)
                        val broker = boundary.openTerminalBroker(
                            request,
                            AgentCancellation.NONE,
                            configuredPolicy = null,
                            agentEnvironment = emptyMap(),
                            audit = AcpTerminalAuditRecorder(),
                        )
                        try {
                            assertFalse(broker.capability)
                        } finally {
                            broker.close()
                        }
                    } finally {
                        filesystemWithoutGrants.close()
                    }

                    val controlCanary = controlPath.resolve("callback-canary.txt").also {
                        Files.writeString(it, "private")
                    }
                    val callbackPath = AgentWorkspacePath(
                        "repository",
                        "private-tmp/${controlPath.fileName}/callback-canary.txt",
                    )
                    val callbackRule = AgentPathRule(
                        AgentWorkspacePath("repository", "private-tmp"),
                        setOf(AgentOperation.READ_FILE),
                        recursive = true,
                    )
                    val callbackRequest = AgentExecutionRequest(
                        objective = "reject callback access to private controls",
                        workspaceRoots = request.workspaceRoots,
                        accessPolicy = AgentAccessPolicy(listOf(callbackRule)),
                    )
                    assertTrue(callbackRequest.accessPolicy.allows(callbackPath, AgentOperation.READ_FILE))
                    assertFailsWith<IOException> {
                        AcpFilesystemBroker.open(callbackRequest, AcpFilesystemLimits(), AcpFilesystemAuditRecorder())
                    }
                    val failure = assertFailsWith<IOException> {
                        boundary.openTerminalBroker(
                            callbackRequest,
                            AgentCancellation.NONE,
                            configuredPolicy = null,
                            agentEnvironment = emptyMap(),
                            audit = AcpTerminalAuditRecorder(),
                        )
                    }
                    assertTrue(failure.message.orEmpty().contains("filesystem callback authority"))

                    val hostFile = workspace.resolve("host-only.txt").also {
                        Files.writeString(it, "must stay hidden")
                    }
                    launchAndAwait(
                        boundary,
                        listOf("visibility", workspace.toString(), hostFile.toString()),
                        emptyDirectories = listOf(workspace),
                    )
                    launchAndAwait(
                        boundary,
                        listOf("visibility", workspace.toString(), controlPath.toString()),
                        emptyDirectories = listOf(workspace),
                    )
                    assertTrue(Files.exists(controlCanary))
                    val successfulLaunches = boundary.evidence(null).launches.size

                    val controlMount = AcpSandboxReadOnlyMount(
                        controlPath,
                        Path.of("/acp-private-control"),
                        "0".repeat(64),
                    )
                    val mountFailure = assertFailsWith<IOException> {
                        val launch = probeLaunch(listOf("netns"))
                        boundary.launch(launch.copy(readOnlyMounts = launch.readOnlyMounts + controlMount), true) {}
                    }
                    assertTrue(mountFailure.message.orEmpty().contains("private control directory"))

                    val controlStaging = AcpWorkflowStagingRoot.createReadOnly("privateControl", controlPath)
                    try {
                        val stagingFailure = assertFailsWith<IOException> {
                            boundary.launch(
                                probeLaunch(listOf("netns")).copy(
                                    stagingRoots = listOf(
                                        AcpSandboxRootGrant(controlStaging, AcpSandboxRootMode.READ_ONLY),
                                    ),
                                ),
                                true,
                            ) {}
                        }
                        assertTrue(stagingFailure.message.orEmpty().contains("private control directory"))
                    } finally {
                        Files.deleteIfExists(controlStaging.path)
                    }
                    assertEquals(successfulLaunches, boundary.evidence(null).launches.size)
                } finally {
                    boundary.close()
                }
            }
        }
    }

    @Test
    fun `private controls reject native bind aliases and late callback exposure without denying disjoint grants`() {
        withRepositoryTemporaryDirectory("acp-private-bind-") { base ->
            val temporary = Files.createDirectory(base.resolve("tmp"))
            val java = Path.of(System.getProperty("java.home"), "bin", "java")
            val process = ProcessBuilder(
                "unshare", "--user", "--map-root-user", "--mount", "--fork", "--",
                java.toString(), "-XX:-UsePerfData", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary",
                "-cp", System.getProperty("java.class.path"),
                LinuxBubblewrapBoundaryTest::class.java.name, "private-control-bind-probe", base.toString(),
            ).redirectErrorStream(true).redirectOutput(base.resolve("native-probe.log").toFile()).start()
            try {
                assertTrue(process.waitFor(45, TimeUnit.SECONDS), "private-control bind probe timed out")
                val output = Files.readString(base.resolve("native-probe.log"))
                assertEquals(0, process.exitValue(), output)
                assertTrue(output.contains("private-control-bind-probe: all native controls passed"), output)
                output.lineSequence().filter { it.startsWith("private-control-bind-probe:") }.forEach(::println)
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    assertTrue(process.waitFor(5, TimeUnit.SECONDS))
                }
            }
            val policy = ProcessBuilder(
                java.toString(), "-XX:-UsePerfData", "-Djava.io.tmpdir=$temporary", "-Djna.tmpdir=$temporary",
                "-cp", System.getProperty("java.class.path"),
                LinuxBubblewrapBoundaryTest::class.java.name, "statx-policy-probe", base.toString(),
            ).redirectErrorStream(true).redirectOutput(base.resolve("statx-policy-probe.log").toFile()).start()
            try {
                assertTrue(policy.waitFor(15, TimeUnit.SECONDS), "statx policy probe timed out")
                val output = Files.readString(base.resolve("statx-policy-probe.log"))
                assertEquals(0, policy.exitValue(), output)
                assertTrue(output.contains("statx-policy-probe: nativeEperm=1 fallbackIdentityCases=4 invalidFdRefused=true"), output)
                output.lineSequence().filter { it.startsWith("statx-policy-probe:") }.forEach(::println)
            } finally {
                if (policy.isAlive) {
                    policy.destroyForcibly()
                    assertTrue(policy.waitFor(5, TimeUnit.SECONDS))
                }
            }
        }
    }

    private fun runStatxPolicyProbe(base: Path) {
        val (auditArchitecture, statxNumber) = when (System.getProperty("os.arch")) {
            "amd64", "x86_64" -> 0xc000003e.toInt() to 332
            "aarch64" -> 0xc00000b7.toInt() to 291
            else -> error("statx seccomp probe requires a supported 64-bit Linux architecture")
        }
        val directory = Files.createDirectory(base.resolve("statx-policy"))
        val file = Files.writeString(directory.resolve("regular"), "descriptor-policy-canary")
        val unlinked = Files.writeString(directory.resolve("unlinked"), "unlinked-policy-canary")
        val link = Files.createSymbolicLink(directory.resolve("link"), file.fileName)
        val descriptors = listOf(directory, file, unlinked, link).map {
            requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(it))
        }
        try {
            Files.delete(unlinked)
            val legacyMethod = LinuxFilesystemSyscalls::class.java.getDeclaredMethod(
                "descriptorProcIdentity", Int::class.javaPrimitiveType,
            )
            val before = descriptors.map { invokePrivate(LinuxFilesystemSyscalls, legacyMethod, it.fd) }
            val libc = com.sun.jna.NativeLibrary.getInstance(com.sun.jna.Platform.C_LIBRARY_NAME)
            // An irreversible filter belongs only to this separate JVM's current thread. Authenticate
            // the architecture, return EPERM only for statx, and allow every other syscall.
            com.sun.jna.Memory(7 * 8L).use { filters ->
                fun instruction(index: Int, code: Int, yes: Int = 0, no: Int = 0, value: Int) {
                    val offset = index * 8L
                    filters.setShort(offset, code.toShort())
                    filters.setByte(offset + 2, yes.toByte())
                    filters.setByte(offset + 3, no.toByte())
                    filters.setInt(offset + 4, value)
                }
                instruction(0, 0x20, value = 4) // LD seccomp_data.arch
                instruction(1, 0x15, yes = 1, value = auditArchitecture)
                instruction(2, 0x06, value = 0x80000000.toInt()) // KILL_PROCESS on a foreign ABI
                instruction(3, 0x20, value = 0) // LD seccomp_data.nr
                instruction(4, 0x15, no = 1, value = statxNumber)
                instruction(5, 0x06, value = 0x00050001) // ERRNO | EPERM
                instruction(6, 0x06, value = 0x7fff0000) // ALLOW
                com.sun.jna.Memory(16).use { program ->
                    program.clear()
                    program.setShort(0, 7)
                    program.setPointer(8, filters)
                    val prctl = libc.getFunction("prctl")
                    assertEquals(0, prctl.invokeInt(arrayOf(38, com.sun.jna.NativeLong(1),
                        com.sun.jna.NativeLong(0), com.sun.jna.NativeLong(0), com.sun.jna.NativeLong(0))),
                        "PR_SET_NO_NEW_PRIVS failed: errno=${com.sun.jna.Native.getLastError()}")
                    assertEquals(0, prctl.invokeInt(arrayOf(22, com.sun.jna.NativeLong(2), program,
                        com.sun.jna.NativeLong(0), com.sun.jna.NativeLong(0))),
                        "PR_SET_SECCOMP failed: errno=${com.sun.jna.Native.getLastError()}")
                }
            }
            com.sun.jna.Memory(256).use { statistics ->
                val result = libc.getFunction("statx").invokeInt(arrayOf(descriptors[0].fd, "", 0x1100, 0x17ff, statistics))
                val errno = com.sun.jna.Native.getLastError()
                assertEquals(-1, result, "the real seccomp policy must deny statx")
                assertEquals(1, errno)
            }
            descriptors.forEachIndexed { index, descriptor ->
                assertEquals(before[index], invokePrivate(LinuxFilesystemSyscalls, legacyMethod, descriptor.fd))
                assertEquals(before[index], LinuxFilesystemSyscalls.identity(descriptor.fd))
            }
            assertFailsWith<IOException> { LinuxFilesystemSyscalls.identity(-1) }
            assertEquals("descriptor-policy-canary", Files.readString(file))
            println("statx-policy-probe: nativeEperm=1 fallbackIdentityCases=4 invalidFdRefused=true")
        } finally {
            descriptors.asReversed().forEach { it.close() }
        }
    }

    private fun runPrivateControlBindProbe(base: Path) {
        fun command(vararg argv: String) {
            val process = ProcessBuilder(*argv).redirectErrorStream(true).start()
            assertTrue(process.waitFor(5, TimeUnit.SECONDS))
            assertEquals(0, process.exitValue(), process.inputStream.readNBytes(4096).toString(Charsets.UTF_8))
        }
        command("mount", "--make-rprivate", "/")
        val parent = Files.createDirectory(base.resolve("controls"))
        val workspace = Files.createDirectory(base.resolve("workspace"))
        fun openDescriptorCount() = Files.list(Path.of("/proc/self/fd")).use { it.count() }
        val identityType = LinuxFilesystemSyscalls::class.java
        val legacyIdentity = identityType.getDeclaredMethod("descriptorProcIdentity", Int::class.javaPrimitiveType)
        val statxIdentity = identityType.getDeclaredMethod("descriptorStatxIdentity", Int::class.javaPrimitiveType)
        var identityParityCases = 0
        var nativeStatxCases = 0
        fun identityParity(fd: Int) {
            val legacy = invokePrivate(LinuxFilesystemSyscalls, legacyIdentity, fd)
            val native = invokePrivate(LinuxFilesystemSyscalls, statxIdentity, fd)
            assertEquals(legacy, LinuxFilesystemSyscalls.identity(fd))
            if (native != null) {
                assertEquals(legacy, native)
                nativeStatxCases++
            }
            identityParityCases++
        }
        val identityFile = Files.writeString(workspace.resolve("identity-file"), "identity-parity")
        val identityLink = Files.createSymbolicLink(workspace.resolve("identity-link"), identityFile.fileName)
        val identityFifo = workspace.resolve("identity-fifo")
        command("mkfifo", identityFifo.toString())
        for (path in listOf(identityFile, workspace, identityLink, identityFifo, Path.of("/proc/self/mountinfo"))) {
            requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)).use { descriptor ->
                descriptor.whileOpen(::identityParity)
            }
        }
        val unlinked = Files.writeString(workspace.resolve("identity-unlinked"), "unlinked-parity")
        requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(unlinked)).use { descriptor ->
            Files.delete(unlinked)
            descriptor.whileOpen(::identityParity)
        }
        LinuxFilesystemSyscalls.openRoot(workspace).use { directory ->
            try {
                LinuxFilesystemSyscalls.createTemporaryAt(directory.fd).use { temporary -> temporary.whileOpen(::identityParity) }
            } catch (failure: LinuxSyscallException) {
                if (failure.errno !in setOf(21, 22, 95)) throw failure
                println("private-control-bind-probe: O_TMPFILE identity parity unsupported errno=${failure.errno}")
            }
        }
        val nativeLibrary = com.sun.jna.NativeLibrary.getInstance(com.sun.jna.Platform.C_LIBRARY_NAME)
        com.sun.jna.Memory(8).use { pipes ->
            assertEquals(0, nativeLibrary.getFunction("pipe2").invokeInt(arrayOf(pipes, 0x80000)))
            try {
                identityParity(pipes.getInt(0))
                identityParity(pipes.getInt(4))
            } finally {
                assertEquals(0, nativeLibrary.getFunction("close").invokeInt(arrayOf(pipes.getInt(0))))
                assertEquals(0, nativeLibrary.getFunction("close").invokeInt(arrayOf(pipes.getInt(4))))
            }
        }
        val decodeIdentity = identityType.getDeclaredMethod("decodeDescriptorStatxIdentity", com.sun.jna.Memory::class.java)
        com.sun.jna.Memory(256).use { incomplete ->
            incomplete.clear()
            incomplete.setInt(0, 0x11f) // Complete basic identity with MNT_ID explicitly missing.
            assertEquals(null, invokePrivate(LinuxFilesystemSyscalls, decodeIdentity, incomplete))
            incomplete.setInt(0, 0x111f)
            assertFailsWith<IOException> { invokePrivate(LinuxFilesystemSyscalls, decodeIdentity, incomplete) }
        }
        val invalidIdentity = assertFailsWith<IOException> { LinuxFilesystemSyscalls.identity(-1) }
        if (nativeStatxCases > 0) assertEquals(9, (invalidIdentity as LinuxSyscallException).errno)
        val statxQuery = identityType.getDeclaredMethod("descriptorStatxQueryOrNull", Function0::class.java)
        val retryQuery = identityType.getDeclaredMethod("retryOnInterrupted", String::class.java, Function0::class.java)
        fun failedStatxQuery(errno: Int) = invokePrivate(LinuxFilesystemSyscalls, statxQuery, {
            invokePrivate(LinuxFilesystemSyscalls, retryQuery, "statx errno dispatch regression", {
                com.sun.jna.Native.setLastError(errno)
                -1L
            })
        })
        for (errno in listOf(1, 38, 95)) assertEquals(null, failedStatxQuery(errno))
        for (errno in listOf(5, 9, 13)) {
            val genuine = assertFailsWith<LinuxSyscallException> { failedStatxQuery(errno) }
            assertEquals(errno, genuine.errno)
        }
        println("private-control-bind-probe: identityParityCases=$identityParityCases nativeStatxCases=$nativeStatxCases missingMaskFallback=true invalidFdRefused=true")
        println("private-control-bind-probe: syntheticErrnoFallbackCases=3 syntheticRealErrorsPropagated=3 actualRetryHelperExercised=true")
        val type = Class.forName("decompengine.acp.PinnedControlDirectory")
        val parentType = Class.forName("decompengine.acp.PinnedSandboxControlTemporaryParent")
        val companion = type.getDeclaredField("Companion").apply { isAccessible = true }.get(null)
        val create = companion.javaClass.getDeclaredMethod("create", AcpRuntimeClosureLimits::class.java, parentType)
        val guard = type.getDeclaredMethod("requireMountSourceUnexposed", Path::class.java, Function0::class.java)
        val controls = mutableListOf<Any>()
        val mounts = mutableListOf<Path>()
        var verifiedScaleDigest: String? = null
        fun newControl(cleanupLimits: AcpRuntimeClosureLimits = AcpRuntimeClosureLimits(64, 4096, 8)): Any = withTemporaryParent(parent.toString()) {
            val pinnedParent = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
            try {
                requireNotNull(invokePrivate(companion, create, cleanupLimits, pinnedParent))
                    .also(controls::add)
            } finally {
                invokePrivate(pinnedParent, AutoCloseable::class.java.getMethod("close"))
            }
        }
        fun controlPath(control: Any): Path = invokePrivate(control, type.getDeclaredMethod("getPath")) as Path
        fun alias(source: Path, name: String): Path {
            val destination = base.resolve(name)
            if (Files.isDirectory(source)) Files.createDirectory(destination) else Files.writeString(destination, "placeholder")
            command("mount", "--bind", source.toString(), destination.toString())
            mounts.add(destination)
            return destination
        }
        fun request(root: Path, relative: String) = AgentExecutionRequest(
            objective = "native private-control canary",
            workspaceRoots = listOf(AgentWorkspaceRoot("workspace", root)),
            accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(AgentWorkspacePath("workspace", relative),
                setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE)))),
        )
        fun denied(action: () -> Unit) {
            try { action(); error("private-control authority unexpectedly succeeded") }
            catch (_: AgentExecutionException) { }
            catch (_: IOException) { }
            catch (_: AcpExpectedError) { }
        }
        var probeFailure: Throwable? = null
        try {
            val first = newControl()
            val firstPath = controlPath(first)
            val privateChild = Files.createDirectory(firstPath.resolve("private-child"))
            val canary = Files.writeString(privateChild.resolve("canary.txt"), "controller-secret-canary")
            val rootAlias = alias(firstPath, "alias-root")
            val ancestorAlias = alias(parent, "alias-ancestor")
            val childAlias = alias(privateChild, "alias-child")
            val fileAlias = alias(canary, "alias-file")
            val beforeNestedAdmission = openDescriptorCount()
            for (temporaryParent in listOf(firstPath, privateChild, rootAlias, childAlias)) {
                val beforeEntries = Files.list(firstPath).use { it.map { entry -> entry.fileName.toString() }.toList().toSet() }
                withTemporaryParent(temporaryParent.toString()) {
                    val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                    try {
                        val rejected = assertFailsWith<IOException> {
                            invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned)
                        }
                        assertTrue(rejected.message.orEmpty().contains("private control directory"), rejected.toString())
                    } finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
                }
                assertEquals(beforeEntries, Files.list(firstPath).use { it.map { entry -> entry.fileName.toString() }.toList().toSet() })
                assertEquals("controller-secret-canary", Files.readString(canary))
            }
            val mountedPrivateParent = Files.createDirectory(firstPath.resolve("mounted-control-parent"))
            command("mount", "-t", "tmpfs", "-o", "size=1048576,nr_inodes=32", "tmpfs", mountedPrivateParent.toString())
            try {
                withTemporaryParent(mountedPrivateParent.toString()) {
                    val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                    try {
                        val rejected = assertFailsWith<IOException> {
                            invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned)
                        }
                        assertTrue(rejected.message.orEmpty().contains("private control directory"), rejected.toString())
                    } finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
                }
                assertTrue(Files.list(mountedPrivateParent).use { it.findAny().isEmpty })
            } finally {
                command("umount", mountedPrivateParent.toString())
                Files.delete(mountedPrivateParent)
            }
            assertEquals(beforeNestedAdmission, openDescriptorCount(), "rejected nested controls must release parent descriptors")
            val cleanupOuter = newControl()
            val cleanupInner = newControl()
            val cleanupOuterPath = controlPath(cleanupOuter)
            val cleanupInnerPath = controlPath(cleanupInner)
            val movedInner = cleanupOuterPath.resolve("relocated-active-control")
            Files.writeString(cleanupInnerPath.resolve("canary.txt"), "still-active-inner-control")
            Files.move(cleanupInnerPath, movedInner)
            try {
                // Exercise the bounded walker directly as well as outer admission: it must refuse an
                // actual selected active-control inode before quarantine, chmod or destructive descent.
                LinuxFilesystemSyscalls.openRoot(cleanupOuterPath).use { outer ->
                    val selectedFailure = assertFailsWith<IOException> {
                        deletePrivateTreeContents(outer, AcpRuntimeClosureLimits(64, 4096, 8))
                    }
                    assertTrue(selectedFailure.message.orEmpty().contains("another active private control"), selectedFailure.toString())
                }
                assertFailsWith<AcpCleanupProofFailure> { invokePrivate(cleanupOuter, type.getDeclaredMethod("deleteAndProve")) }
                assertEquals("still-active-inner-control", Files.readString(movedInner.resolve("canary.txt")))
                assertEquals(setOf("relocated-active-control"), Files.list(cleanupOuterPath).use {
                    it.map { entry -> entry.fileName.toString() }.toList().toSet()
                })
            } finally { Files.move(movedInner, cleanupInnerPath) }
            // A proved remediation does not erase the earlier unverified cleanup disposition.
            assertFailsWith<AcpCleanupProofFailure> { invokePrivate(cleanupOuter, type.getDeclaredMethod("deleteAndProve")) }
            assertFalse(Files.exists(cleanupOuterPath))
            controls.remove(cleanupOuter)
            invokePrivate(cleanupInner, type.getDeclaredMethod("deleteAndProve"))
            controls.remove(cleanupInner)
            assertFalse(Files.exists(cleanupInnerPath))
            assertEquals(beforeNestedAdmission, openDescriptorCount())
            println("private-control-bind-probe: nestedControlParentsRefused=5 relocatedLiveInnerPreserved=true exactRemediationProved=true")
            for (source in listOf(rootAlias, ancestorAlias, childAlias, fileAlias)) {
                denied { invokePrivate(first, guard, source, {}) }
                denied { calculateAcpRuntimeManifestSha256(source, AcpRuntimeClosureLimits(64, 4096, 8)) }
            }
            for ((root, relative) in listOf(rootAlias to "private-child/canary.txt",
                    ancestorAlias to "${firstPath.fileName}/private-child/canary.txt", childAlias to "canary.txt")) {
                denied { AcpFilesystemBroker.open(request(root, relative), AcpFilesystemLimits(), AcpFilesystemAuditRecorder()).close() }
            }
            denied { AcpFilesystemBroker.open(request(base, "alias-file"), AcpFilesystemLimits(), AcpFilesystemAuditRecorder()).close() }
            denied { requireAcpPrivateControlsUnexposed(ancestorAlias.resolve("${firstPath.fileName}/missing/new.txt"), false) }
            val ordinary = Files.writeString(parent.resolve("ordinary.txt"), "ordinary")
            AcpFilesystemBroker.open(request(ancestorAlias, "ordinary.txt"), AcpFilesystemLimits(), AcpFilesystemAuditRecorder()).use { broker ->
                assertEquals("ordinary", runBlocking { broker.readTextFile("disjoint", ancestorAlias.resolve("ordinary.txt").toString(), null, null) }.content)
                runBlocking { broker.writeTextFile("disjoint", ancestorAlias.resolve("ordinary.txt").toString(), "ordinary-updated") }
            }
            assertEquals("ordinary-updated", Files.readString(ordinary))
            val beforeAuthorityCancellation = openDescriptorCount()
            for (rootCheckpoint in listOf(true, false)) {
                var observed = false
                val cancelled = request(ancestorAlias, "ordinary.txt").let { original -> AgentExecutionRequest(
                    objective = original.objective,
                    workspaceRoots = original.workspaceRoots,
                    accessPolicy = original.accessPolicy,
                    cancellation = AgentCancellation {
                        val frames = Thread.currentThread().stackTrace.filter {
                            it.className == "decompengine.acp.AcpFilesystemBroker\$Companion"
                        }
                        val atRoot = frames.any { it.methodName.startsWith("openRoot") }
                        val selected = if (rootCheckpoint) atRoot else !atRoot && frames.any { it.methodName.startsWith("open") }
                        if (selected) observed = true
                        selected
                    },
                ) }
                val cancellation = assertFailsWith<RequestedAcpCancellation> {
                    AcpFilesystemBroker.open(cancelled, AcpFilesystemLimits(), AcpFilesystemAuditRecorder()).close()
                }
                assertTrue(observed)
                assertEquals("filesystem authority opening", cancellation.phase)
                assertEquals(beforeAuthorityCancellation, openDescriptorCount(), "cancelled admission must close every root descriptor")
            }
            println("private-control-bind-probe: cancelledRootAndRuleAdmissionPreserved=true admissionDescriptorsReleased=true")
            val late = Files.createDirectory(workspace.resolve("late"))
            Files.writeString(late.resolve("canary.txt"), "ordinary-before-bind")
            val audit = AcpFilesystemAuditRecorder()
            AcpFilesystemBroker.open(request(workspace, "late/canary.txt"), AcpFilesystemLimits(), audit).use { broker ->
                val second = newControl()
                val secondPath = controlPath(second)
                val secondCanary = Files.writeString(secondPath.resolve("canary.txt"), "second-controller-secret")
                command("mount", "--bind", secondPath.toString(), late.toString())
                mounts.add(late)
                denied { runBlocking { broker.readTextFile("late", late.resolve("canary.txt").toString(), null, null) } }
                denied { runBlocking { broker.writeTextFile("late", late.resolve("canary.txt").toString(), "must-not-land") } }
                assertEquals("second-controller-secret", Files.readString(secondCanary))
                assertEquals(setOf("canary.txt"), Files.list(secondPath).use { it.map { it.fileName.toString() }.toList().toSet() })
                assertEquals(2, audit.snapshot().size)
                assertTrue(audit.snapshot().none { it.outcome == AcpFilesystemAuditOutcome.ALLOWED })
            }
            // An already-open broker must also protect controls created later on its own mount.
            val future = Files.createDirectory(workspace.resolve("future-controls"))
            val futureRequest = AgentExecutionRequest(
                objective = "deny a later control without a mount transition",
                workspaceRoots = listOf(AgentWorkspaceRoot("workspace", workspace)),
                accessPolicy = AgentAccessPolicy(listOf(AgentPathRule(AgentWorkspacePath("workspace", "future-controls"),
                    setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE, AgentOperation.CREATE_FILE), recursive = true))),
            )
            val futureAudit = AcpFilesystemAuditRecorder()
            AcpFilesystemBroker.open(futureRequest, AcpFilesystemLimits(), futureAudit).use { broker ->
                val newControl = java.util.concurrent.CompletableFuture.supplyAsync {
                    withTemporaryParent(future.toString()) {
                        val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                        try { requireNotNull(invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned)) }
                        finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
                    }
                }.get(5, TimeUnit.SECONDS).also(controls::add)
                val newPath = controlPath(newControl)
                val secret = Files.writeString(newPath.resolve("future-canary.txt"), "future-controller-secret")
                denied { runBlocking { broker.readTextFile("future", secret.toString(), null, null) } }
                denied { runBlocking { broker.writeTextFile("future", secret.toString(), "must-not-land") } }
                assertEquals("future-controller-secret", Files.readString(secret))
                assertEquals(2, futureAudit.snapshot().size)
                assertTrue(futureAudit.snapshot().none { it.outcome == AcpFilesystemAuditOutcome.ALLOWED })
            }
            // A retained live staging bind must reject a later control before creating any entry.
            val staging = AcpWorkflowStagingRoot.createReadOnly("activeStaging", base)
            val retained = invokeBoundaryPrivate("retainHostStagingRoots", arrayOf(List::class.java, Function0::class.java),
                listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)), {}) as List<*>
            try {
                withTemporaryParent(staging.path.toString()) {
                    val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                    try { denied { invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned) } }
                    finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
                }
                assertTrue(Files.list(staging.path).use { it.findAny().isEmpty })
                val stagingAlias = alias(staging.path, "active-staging-alias")
                withTemporaryParent(stagingAlias.toString()) {
                    val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                    try { denied { invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned) } }
                    finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
                }
                assertTrue(Files.list(staging.path).use { it.findAny().isEmpty })
                val nested = Files.createDirectory(staging.path.resolve("nested-mount"))
                command("mount", "-t", "tmpfs", "-o", "size=1048576,nr_inodes=32", "tmpfs", nested.toString())
                try {
                    val nestedFailure = assertFailsWith<IOException> {
                        invokeBoundaryPrivate("retainHostStagingRoots", arrayOf(List::class.java, Function0::class.java),
                            listOf(AcpSandboxRootGrant(staging, AcpSandboxRootMode.READ_ONLY)), {})
                    }
                    assertTrue(nestedFailure.message.orEmpty().contains("nested mount"))
                    withTemporaryParent(nested.toString()) {
                        val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                        try { denied { invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned) } }
                        finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
                    }
                    assertTrue(Files.list(nested).use { it.findAny().isEmpty })
                } finally {
                    command("umount", nested.toString())
                    Files.delete(nested)
                }
            } finally {
                invokeBoundaryPrivate("cleanupLaunchResources", arrayOf(List::class.java,
                    Class.forName("decompengine.acp.SandboxEnvironmentFile"), List::class.java), emptyList<Any>(), null, retained)
            }
            withTemporaryParent(staging.path.toString()) {
                val pinned = requireNotNull(invokeBoundaryPrivate("sandboxControlTemporaryParent", emptyArray()))
                try { invokePrivate(companion, create, AcpRuntimeClosureLimits(64, 4096, 8), pinned).also { control ->
                    assertTrue(control != null)
                    invokePrivate(control, type.getDeclaredMethod("deleteAndProve"))
                } } finally { invokePrivate(pinned, AutoCloseable::class.java.getMethod("close")) }
            }
            assertTrue(Files.list(staging.path).use { it.findAny().isEmpty })
            // A replaced control name stays quarantined at both admitted and retained-fd locations.
            val original = firstPath
            val held = parent.resolve("retained-private-control")
            Files.move(original, held)
            Files.createDirectory(original)
            try {
                denied { invokePrivate(first, type.getDeclaredMethod("deleteAndProve")) }
                denied { requireAcpPrivateControlsUnexposed(held.resolve("private-child/canary.txt"), false) }
                denied { requireAcpPrivateControlsUnexposed(original, true) }
                AcpFilesystemBroker.open(request(ancestorAlias, "ordinary.txt"), AcpFilesystemLimits(), AcpFilesystemAuditRecorder()).use { broker ->
                    assertEquals("ordinary-updated", runBlocking { broker.readTextFile("quarantined-disjoint",
                        ancestorAlias.resolve("ordinary.txt").toString(), null, null) }.content)
                }
            } finally {
                Files.delete(original)
                Files.move(held, original)
            }
            assertEquals("controller-secret-canary", Files.readString(canary))
            val interrupted = assertFailsWith<IOException> {
                invokePrivate(first, guard, workspace, { throw IOException("bounded-checkpoint") })
            }
            assertEquals("bounded-checkpoint", interrupted.message)
            val closure = Files.createDirectory(workspace.resolve("ordinary-runtime-closure"))
            repeat(128) { index -> Files.writeString(closure.resolve("file-$index"), "ordinary-$index") }
            val closureStarted = System.nanoTime()
            val digest = calculateAcpRuntimeManifestSha256(closure, AcpRuntimeClosureLimits(256, 8192, 8))
            assertTrue(digest.matches(Regex("[0-9a-f]{64}")))
            println("private-control-bind-probe: ordinary128fileClosureMilliseconds=" +
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - closureStarted))
            repeat(4096 - 128) { index -> Files.writeString(closure.resolve("scale-$index"), "ordinary-$index") }
            val scaleLimits = AcpRuntimeClosureLimits(8192, 131072, 8)
            val retainedDescriptorCount = openDescriptorCount()
            val scaleStarted = System.nanoTime()
            val scaleDigest = calculateAcpRuntimeManifestSha256(closure, scaleLimits)
            verifiedScaleDigest = scaleDigest
            assertTrue(scaleDigest.matches(Regex("[0-9a-f]{64}")))
            assertEquals(4096L, Files.list(closure).use { it.count() })
            assertEquals(retainedDescriptorCount, openDescriptorCount(), "successful scope must release retained descriptors")
            println("private-control-bind-probe: ordinary4096fileClosureMilliseconds=" +
                TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - scaleStarted))
            println("private-control-bind-probe: scaleEntries=4097 activeControls=${controls.size} actualBindMounts=${mounts.size}")

            // A second invocation can register and remove a real control while the manifest is
            // running. The lease owns independent descriptors and refuses even restored membership.
            var checks = 0
            var registryChanged = false
            val registryFailure = assertFailsWith<IOException> {
                calculateAcpRuntimeManifestSha256(closure, scaleLimits) {
                    if (++checks == 400) {
                        java.util.concurrent.CompletableFuture.runAsync {
                            val concurrent = newControl()
                            invokePrivate(concurrent, type.getDeclaredMethod("deleteAndProve"))
                            controls.remove(concurrent)
                        }.get(5, TimeUnit.SECONDS)
                        registryChanged = true
                    }
                }
            }
            assertTrue(registryChanged)
            assertTrue(registryFailure.message.orEmpty().contains("private controls changed"), registryFailure.toString())
            assertEquals(retainedDescriptorCount, openDescriptorCount(), "registry drift must release retained descriptors")

            checks = 0
            var controlModeChanged = false
            try {
                val modeFailure = assertFailsWith<IOException> {
                    calculateAcpRuntimeManifestSha256(closure, scaleLimits) {
                        if (++checks == 400) {
                            Files.setPosixFilePermissions(firstPath, OWNER_ONLY + PosixFilePermission.GROUP_READ)
                            controlModeChanged = true
                        }
                    }
                }
                assertTrue(controlModeChanged)
                assertTrue(modeFailure.message.orEmpty().contains("private directory descriptor identity changed"), modeFailure.toString())
            } finally {
                if (controlModeChanged) Files.setPosixFilePermissions(firstPath, OWNER_ONLY)
            }
            assertEquals(retainedDescriptorCount, openDescriptorCount(), "control metadata drift must release retained descriptors")

            val largeSource = workspace.resolve("guarded-large-runtime")
            val largeBlock = ByteArray(1024 * 1024) { index -> (index and 0xff).toByte() }
            Files.newOutputStream(largeSource, StandardOpenOption.CREATE_NEW).use { output ->
                repeat(64) { output.write(largeBlock) }
            }
            val largeLimits = AcpRuntimeClosureLimits(10000, 536870912, 32)
            assertEquals(64L * 1024 * 1024, Files.size(largeSource))
            val largeDigest = calculateAcpRuntimeManifestSha256(largeSource, largeLimits)
            assertTrue(largeDigest.matches(Regex("[0-9a-f]{64}")))
            var byteCheckpoints = 0
            controlModeChanged = false
            try {
                val chunkFailure = assertFailsWith<IOException> {
                    calculateAcpRuntimeManifestSha256(largeSource, largeLimits) {
                        if (Thread.currentThread().stackTrace.any { it.methodName == "copyReadableTo" } && ++byteCheckpoints == 16) {
                            Files.setPosixFilePermissions(firstPath, OWNER_ONLY + PosixFilePermission.GROUP_READ)
                            controlModeChanged = true
                        }
                    }
                }
                assertTrue(controlModeChanged)
                assertTrue(chunkFailure.message.orEmpty().contains("private directory descriptor identity changed"), chunkFailure.toString())
            } finally {
                if (controlModeChanged) Files.setPosixFilePermissions(firstPath, OWNER_ONLY)
            }
            val copyControl = newControl(largeLimits)
            byteCheckpoints = 0
            var controlDuringCopy = false
            val copyFailure = assertFailsWith<IOException> {
                invokeBoundaryPrivate("stagePrivateRuntimeSnapshot", arrayOf(Path::class.java,
                    AcpRuntimeClosureLimits::class.java, type, Function0::class.java), largeSource, largeLimits, copyControl, {
                        if (Thread.currentThread().stackTrace.any { it.methodName == "copyReadableTo" } && ++byteCheckpoints == 16) {
                            val concurrent = newControl()
                            invokePrivate(concurrent, type.getDeclaredMethod("deleteAndProve"))
                            controls.remove(concurrent)
                            controlDuringCopy = true
                        }
                    })
            }
            assertTrue(controlDuringCopy)
            assertTrue(copyFailure.message.orEmpty().contains("private controls changed"), copyFailure.toString())
            assertTrue(Files.list(controlPath(copyControl)).use { it.findAny().isEmpty }, "rejected copy must prove cleanup of its partial snapshot")
            assertEquals(largeDigest, calculateAcpRuntimeManifestSha256(largeSource, largeLimits))
            invokePrivate(copyControl, type.getDeclaredMethod("deleteAndProve"))
            controls.remove(copyControl)
            assertEquals(retainedDescriptorCount, openDescriptorCount(), "large hash/copy refusal must release retained descriptors")
            println("private-control-bind-probe: actual64MiBHashPassed=true liveChunkModeDriftRefused=true partialCopyRegistryDriftRefused=true")

            // Keep the original mountinfo handle: moving an existing bind and restoring it before
            // the final table comparison must still leave a detectable kernel event.
            val mountSource = Files.createDirectory(workspace.resolve("mount-event-source"))
            val mountInitial = alias(mountSource, "mount-event-initial")
            val mountMoved = Files.createDirectory(base.resolve("mount-event-moved"))
            fun mountIdentity(path: Path) = requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path))
                .use { LinuxFilesystemSyscalls.identity(it.fd) }
            val movedIdentity = mountIdentity(mountInitial)
            val mountSlot = mounts.indexOf(mountInitial)
            fun moveMount(source: Path, destination: Path) {
                assertEquals(source, mounts[mountSlot])
                assertEquals(movedIdentity.mountId, mountIdentity(source).mountId)
                val result = nativeLibrary.getFunction("mount").invokeInt(arrayOf(
                    source.toString(), destination.toString(), null, com.sun.jna.NativeLong(0x2000), null,
                ))
                val errno = com.sun.jna.Native.getLastError()
                assertEquals(0, result, "native MS_MOVE $source to $destination failed: errno=$errno")
                // Transfer cleanup ownership immediately after the successful kernel operation.
                mounts[mountSlot] = destination
                val relocated = mountIdentity(destination)
                assertEquals(movedIdentity.mountId, relocated.mountId, "MS_MOVE must retain the exact mount")
                assertEquals(movedIdentity.key, relocated.key, "MS_MOVE must retain the exact bind root")
                assertNotEquals(movedIdentity.mountId, mountIdentity(source).mountId, "source must no longer own the moved mount")
            }
            var mountChanged = false
            val mountFailure = assertFailsWith<IOException> {
                calculateAcpRuntimeManifestSha256(closure, scaleLimits) {
                    // Mutate after the immutable snapshot is retained, before this checkpoint's
                    // poll. Counting callbacks also counts mount-table records and is host-dependent.
                    val scopeFrames = Thread.currentThread().stackTrace.filter {
                        it.className == "decompengine.acp.RuntimePrivateControlScope"
                    }
                    if (!mountChanged && scopeFrames.any { it.methodName == "checkpoint" } &&
                        scopeFrames.any { it.methodName == "requireDescriptor" }) {
                        moveMount(mountInitial, mountMoved)
                        moveMount(mountMoved, mountInitial)
                        mountChanged = true
                    }
                }
            }
            assertTrue(mountChanged)
            assertTrue(mountFailure.message.orEmpty().contains("host mounts changed"), mountFailure.toString())
            assertEquals(retainedDescriptorCount, openDescriptorCount(), "mount drift must release retained descriptors")

            val replacedFile = Files.writeString(workspace.resolve("manifest-file-replacement"), "ordinary-old-content")
            var replaced = false
            val replacementFailure = assertFailsWith<IOException> {
                calculateAcpRuntimeManifestSha256(replacedFile, AcpRuntimeClosureLimits(16, 4096, 8)) {
                    if (!replaced && Thread.currentThread().stackTrace.any { it.methodName == "sha256" }) {
                        Files.delete(replacedFile)
                        Files.writeString(replacedFile, "replacement-content")
                        replaced = true
                    }
                }
            }
            assertTrue(replaced)
            assertTrue(replacementFailure.message.orEmpty().contains("authenticated source pathname"), replacementFailure.toString())
            assertEquals("replacement-content", Files.readString(replacedFile))
            assertEquals(retainedDescriptorCount, openDescriptorCount(), "unknown descriptor names must release the scope")

            // A bind root can change physical root coordinates without changing its mount id.
            // Cross-mount scopes retain the full guard and reject before hashing private bytes.
            val renameSource = Files.createDirectory(workspace.resolve("rename-source"))
            Files.writeString(renameSource.resolve("ordinary.txt"), "ordinary-before-rename")
            val renameAlias = alias(renameSource, "rename-alias")
            val hiddenSource = firstPath.resolve("renamed-runtime")
            checks = 0
            var renamed = false
            try {
                denied {
                    calculateAcpRuntimeManifestSha256(renameAlias, AcpRuntimeClosureLimits(64, 4096, 8)) {
                        if (!renamed && Thread.currentThread().stackTrace.any { it.methodName == "readIdentity" }) {
                            Files.move(renameSource, hiddenSource)
                            Files.writeString(hiddenSource.resolve("ordinary.txt"), "controller-secret-after-rename")
                            renamed = true
                        }
                    }
                }
                assertTrue(renamed)
                assertEquals("controller-secret-after-rename", Files.readString(hiddenSource.resolve("ordinary.txt")))
            } finally {
                if (renamed) Files.move(hiddenSource, renameSource)
            }
            assertEquals(scaleDigest, calculateAcpRuntimeManifestSha256(closure, scaleLimits))
            println("private-control-bind-probe: scoped manifest scale, concurrent registry, mount restore, bind rename passed")
            println("private-control-bind-probe: all native controls passed")
        } catch (failure: Throwable) {
            probeFailure = failure
            throw failure
        } finally {
            var cleanupFailure: Throwable? = null
            fun clean(action: () -> Unit) {
                try { action() } catch (failure: Throwable) {
                    cleanupFailure?.addSuppressed(failure) ?: run { cleanupFailure = failure }
                }
            }
            mounts.asReversed().forEach { mount -> clean { command("umount", mount.toString()) } }
            controls.asReversed().forEach { control ->
                clean {
                    val path = controlPath(control)
                    try { invokePrivate(control, type.getDeclaredMethod("deleteAndProve")) }
                    catch (failure: AcpCleanupProofFailure) {
                        assertFalse(Files.exists(path), "failed cleanup must retain controls until a later proved removal")
                    }
                }
            }
            cleanupFailure?.let { failure -> probeFailure?.addSuppressed(failure) ?: throw failure }
        }
        // A deleted control cannot retain a stale-inode restriction on later ordinary directories.
        requireAcpPrivateControlsUnexposed(workspace, true)
        val closure = workspace.resolve("ordinary-runtime-closure")
        val scaleLimits = AcpRuntimeClosureLimits(8192, 131072, 8)
        assertEquals(verifiedScaleDigest, calculateAcpRuntimeManifestSha256(closure, scaleLimits))
        var emptyChecks = 0
        var admittedFromEmpty = false
        val emptyFailure = assertFailsWith<IOException> {
            calculateAcpRuntimeManifestSha256(closure, scaleLimits) {
                if (++emptyChecks == 400) {
                    val concurrent = newControl()
                    try { invokePrivate(concurrent, type.getDeclaredMethod("deleteAndProve")) }
                    finally { controls.remove(concurrent) }
                    admittedFromEmpty = true
                }
            }
        }
        assertTrue(admittedFromEmpty)
        assertTrue(emptyFailure.message.orEmpty().contains("private controls changed"), emptyFailure.toString())
    }

    @Test
    fun `systemd runtime ceiling uses one authenticated millisecond value`() {
        val cleanup = acpSandboxCleanupTimeoutMicros()
        assertEquals(cleanup + 1_000L, acpSandboxRuntimeMaximumMicros(Duration.ofNanos(1)))
        assertEquals(cleanup + 1_000L, acpSandboxRuntimeMaximumMicros(Duration.ofMillis(1)))
        assertEquals(
            cleanup + 2_000L,
            acpSandboxRuntimeMaximumMicros(Duration.ofMillis(1).plusNanos(1)),
        )
    }

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
        AcpLiveContractHost.requireCapability(Files.isExecutable(BWRAP), { "digest mismatch probe requires /usr/bin/bwrap" })
        assertFailsWith<IOException> {
            LinuxBubblewrapBoundary.prepare(syntheticConfiguration(BWRAP, "0".repeat(64)))
        }
        AcpLiveContractHost.requireCapability(Files.isExecutable(BASH), { "ancestor-chain probe requires /usr/bin/bash" })
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
            val configuredProbeManifest = calculateAcpRuntimeManifestSha256(PROBE)
            assertTrue(evidence.launches.all { launch ->
                launch.controllers.pidsMax == launch.resourceLimits.maximumProcesses.toLong() &&
                    launch.controllers.memoryMaxBytes == launch.resourceLimits.maximumAddressSpaceBytes &&
                    launch.controllers.memorySwapMaxBytes == 0L && launch.controllers.memoryOomGroup &&
                    launch.startGate.descriptor == 0 && launch.startGate.positiveByteRequired &&
                    launch.environment.linkCount == 0 &&
                    launch.executableMount.configuredManifestSha256 == configuredProbeManifest &&
                    launch.executableMount.manifestSha256 != configuredProbeManifest &&
                    launch.effectiveRlimits.openFilesSoft == launch.resourceLimits.maximumOpenFiles.toLong()
            })
            assertTrue(evidence.evidenceSha256.matches(Regex("[0-9a-f]{64}")))
        } finally {
            boundary.close()
        }
    }

    @Test
    fun `live Ninja query purpose closes stdin and retains separate authenticated evidence`() {
        requireLiveHost()
        val boundary = LinuxBubblewrapBoundary.prepare(liveConfiguration())
        try {
            val launch = probeLaunch(listOf("netns")).copy(
                purpose = AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY,
                stdinDisposition = AcpSandboxStdinDisposition.CLOSED_BEFORE_EXEC,
            )
            val contained = boundary.launch(launch, mergeError = false) {}
            assertTrue(contained.process.waitFor(8, TimeUnit.SECONDS), "Ninja-purpose probe timed out")
            val stdout = contained.process.inputStream.readAllBytes().toString(Charsets.UTF_8)
            val stderr = contained.process.errorStream.readAllBytes().toString(Charsets.UTF_8)
            assertEquals(0, contained.process.exitValue(), stderr)
            assertTrue(stdout.isNotBlank())
            assertEquals("", stderr)
            contained.awaitCleanup(Duration.ofSeconds(5))

            val evidence = boundary.evidence(null).launches.single()
            assertEquals(AcpSandboxLaunchPurpose.NINJA_COMPDB_QUERY, evidence.purpose)
            assertEquals("closed-before-exec", evidence.stdinDisposition)
            assertFalse(evidence.mergeError)
            assertEquals(acpSandboxCanonicalStringDigest(launch.command), evidence.commandSha256)
            assertEquals(acpSandboxEmptyStagingRootsDigest(), evidence.stagingRootsSha256)
            assertEquals(acpSandboxCanonicalStringDigest(emptyList()), evidence.emptyDirectoriesSha256)
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
        val originalHolding = control.parent.resolve(".decomp-acp-original-${UUID.randomUUID()}")
        val replacementHolding = control.parent.resolve(".decomp-acp-replacement-${UUID.randomUUID()}")
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
        AcpLiveContractHost.requireCapability(
            !mountText.isNullOrBlank(),
            { "set DECOMP_TEST_ACP_QUOTA_TMPFS to an empty user-owned 0700 dedicated tmpfs with finite size,nr_inodes" },
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
        AcpLiveContractHost.requireCapability(Files.isExecutable(CC), { "static ACP fixtures require /usr/bin/cc" })
        AcpLiveContractHost.requireCapability(GATE_HELPER_RESULT.isSuccess, { "static gate helper unavailable: ${GATE_HELPER_RESULT.exceptionOrNull()}" })
        AcpLiveContractHost.requireCapability(PROBE_RESULT.isSuccess, { "static probe unavailable: ${PROBE_RESULT.exceptionOrNull()}" })
    }

    private fun requireLiveHost() {
        requireCompiledFixtures()
        val missing = SECURITY_TOOLS.filterNot(Files::isExecutable)
        AcpLiveContractHost.requireCapability(missing.isEmpty(), { "live ACP sandbox tools unavailable: $missing" })
        AcpLiveContractHost.requireCapability(Files.exists(USER_RUNTIME.resolve("bus")), { "systemd user bus is unavailable" })
        AcpLiveContractHost.requireCapability(Files.isRegularFile(Path.of("/sys/fs/cgroup/cgroup.controllers")), { "cgroup v2 is unavailable" })
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

    private fun controlDirectories(): Set<Path> = Files.list(Path.of(System.getProperty("java.io.tmpdir"))).use { entries ->
        entries.filter { it.fileName.toString().startsWith(".decomp-acp-control-") }.toList().toSet()
    }

    private fun <T> withTemporaryParent(value: String?, action: () -> T): T {
        val previous = System.getProperty("java.io.tmpdir")
        try {
            if (value == null) System.clearProperty("java.io.tmpdir") else System.setProperty("java.io.tmpdir", value)
            return action()
        } finally {
            if (previous == null) System.clearProperty("java.io.tmpdir") else System.setProperty("java.io.tmpdir", previous)
        }
    }

    private fun invokeBoundaryPrivate(name: String, types: Array<Class<*>>, vararg arguments: Any?): Any? =
        invokePrivate(null, Class.forName("decompengine.acp.LinuxBubblewrapBoundaryKt").getDeclaredMethod(name, *types), *arguments)

    private fun invokePrivate(receiver: Any?, method: java.lang.reflect.Method, vararg arguments: Any?): Any? =
        try {
            method.isAccessible = true
            method.invoke(receiver, *arguments)
        } catch (failure: java.lang.reflect.InvocationTargetException) {
            throw failure.targetException
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

    private fun <T> withRepositoryTemporaryDirectory(prefix: String, action: (Path) -> T): T {
        val base = createRepositoryTemporaryDirectory(prefix)
        var actionFailure: Throwable? = null
        try {
            return action(base)
        } catch (failure: Throwable) {
            actionFailure = failure
            throw failure
        } finally {
            try {
                deleteRepositoryTemporaryDirectory(base)
            } catch (cleanup: Throwable) {
                actionFailure?.addSuppressed(cleanup) ?: throw cleanup
            }
        }
    }

    private fun sha256(path: Path): String = MessageDigest.getInstance("SHA-256")
        .digest(Files.readAllBytes(path))
        .joinToString("") { "%02x".format(it) }

    private companion object {
        @JvmStatic
        fun main(args: Array<String>) {
            require(args.size == 2)
            when (args[0]) {
                "private-control-bind-probe" -> LinuxBubblewrapBoundaryTest().runPrivateControlBindProbe(Path.of(args[1]))
                "statx-policy-probe" -> LinuxBubblewrapBoundaryTest().runStatxPolicyProbe(Path.of(args[1]))
                else -> error("unknown native boundary probe")
            }
        }

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

        private val staticFixtureDirectories = ConcurrentLinkedQueue<Path>()

        @AfterAll
        @JvmStatic
        fun removeStaticFixtures() {
            val failures = mutableListOf<Throwable>()
            while (true) {
                val directory = staticFixtureDirectories.poll() ?: break
                runCatching { deleteRepositoryTemporaryDirectory(directory) }
                    .exceptionOrNull()?.let(failures::add)
            }
            if (failures.isNotEmpty()) {
                val failure = IOException("static ACP test fixture cleanup was not proven", failures.first())
                failures.drop(1).forEach(failure::addSuppressed)
                throw failure
            }
        }

        private fun repositoryRoot(): Path {
            var repository = Path.of("").toAbsolutePath().normalize()
            while (!Files.exists(repository.resolve(".git"), LinkOption.NOFOLLOW_LINKS) ||
                !Files.isRegularFile(repository.resolve("gradlew"), LinkOption.NOFOLLOW_LINKS)
            ) {
                repository = repository.parent ?: throw IllegalStateException("test is not running inside the repository")
            }
            return repository.toRealPath()
        }

        private fun repositoryTemporaryParent(): Path {
            val repository = repositoryRoot()
            var current = repository
            val created = mutableListOf<Path>()
            try {
                for (component in listOf("build", "tmp", "acp-boundary-tests")) {
                    val child = current.resolve(component).normalize()
                    if (!child.startsWith(repository) || child.parent != current || current.toRealPath() != current) {
                        throw IOException("ACP test temporary parent would escape the repository")
                    }
                    if (!Files.exists(child, LinkOption.NOFOLLOW_LINKS)) {
                        try {
                            Files.createDirectory(child)
                            created.add(child)
                        } catch (_: FileAlreadyExistsException) {
                            // Another test worker created the same repository-local parent.
                        }
                    }
                    val attributes = Files.readAttributes(
                        child,
                        BasicFileAttributes::class.java,
                        LinkOption.NOFOLLOW_LINKS,
                    )
                    if (!attributes.isDirectory || attributes.isSymbolicLink || child.toRealPath() != child) {
                        throw IOException("ACP test temporary parent contains a noncanonical directory")
                    }
                    current = child
                }
                return current
            } catch (failure: Throwable) {
                created.asReversed().forEach { path ->
                    runCatching { Files.deleteIfExists(path) }.exceptionOrNull()?.let(failure::addSuppressed)
                }
                throw failure
            }
        }

        private fun createRepositoryTemporaryDirectory(prefix: String): Path {
            val parent = repositoryTemporaryParent()
            val repository = repositoryRoot()
            var base: Path? = null
            try {
                base = Files.createTempDirectory(parent, prefix).toAbsolutePath().normalize()
                if (!base.startsWith(repository) || base.parent != parent || base.toRealPath() != base) {
                    throw IOException("ACP test temporary directory escaped the repository")
                }
                return base
            } catch (failure: Throwable) {
                base?.let { path ->
                    runCatching { deleteRepositoryTemporaryDirectory(path) }
                        .exceptionOrNull()?.let(failure::addSuppressed)
                }
                throw failure
            }
        }

        private fun deleteRepositoryTemporaryDirectory(directory: Path) {
            val repository = repositoryRoot()
            if (!directory.isAbsolute || directory != directory.normalize() || !directory.startsWith(repository)) {
                throw IOException("refusing to clean an ACP test directory outside the repository")
            }
            if (Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(directory).use { entries ->
                    entries.sorted(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
                }
            } else {
                Files.deleteIfExists(directory)
            }
        }

        private fun compileStatic(source: Path, prefix: String): Path {
            val directory = createRepositoryTemporaryDirectory(prefix)
            try {
                val output = directory.resolve("program")
                val process = ProcessBuilder(
                    CC.toString(), "-std=c11", "-O2", "-static", source.toString(), "-o", output.toString(),
                ).redirectErrorStream(true).start()
                val diagnostics = process.inputStream.readNBytes(32 * 1024).toString(Charsets.UTF_8)
                if (!process.waitFor(20, TimeUnit.SECONDS) || process.exitValue() != 0) {
                    throw IOException("static fixture compile failed: $diagnostics")
                }
                staticFixtureDirectories.add(directory)
                return output
            } catch (failure: Throwable) {
                runCatching { deleteRepositoryTemporaryDirectory(directory) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
                throw failure
            }
        }
    }
}
