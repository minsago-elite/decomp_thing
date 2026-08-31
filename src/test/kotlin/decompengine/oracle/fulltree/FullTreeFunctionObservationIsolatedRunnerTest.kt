package decompengine.oracle.fulltree

import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.File
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.jar.JarEntry
import java.util.jar.JarOutputStream
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeFunctionObservationIsolatedFixtureRunnerTest {
    @Test
    fun `isolation configuration has immutable canonical Kotlin owned identity`() {
        val mounts = mutableListOf(
            FullTreeFunctionObservationRuntimeMount(
                Path.of("/provisioned/libraries-a"),
                Path.of("/runtime/libraries-a"),
                "2".repeat(64),
            ),
            FullTreeFunctionObservationRuntimeMount(
                Path.of("/provisioned/libraries-b"),
                Path.of("/runtime/libraries-b"),
                "3".repeat(64),
            ),
        )
        val classPath = mutableListOf(
            FullTreeFunctionObservationClassPathEntry(
                Path.of("/provisioned/application/worker-a.jar"),
                "4".repeat(64),
            ),
            FullTreeFunctionObservationClassPathEntry(
                Path.of("/provisioned/application/worker-b.jar"),
                "5".repeat(64),
            ),
        )
        val configuration = syntheticConfiguration(mounts, classPath)
        val canonical = configuration.canonicalBytesForTest()

        assertEquals(configuration.canonicalSha256, OracleArtifacts.sha256(canonical))
        assertContentEquals(canonical, OracleJson.canonicalBytes(OracleJson.parseCanonical(canonical)))
        assertEquals(FROZEN_ISOLATION_CONFIGURATION_SHA256, configuration.canonicalSha256)

        mounts.clear()
        classPath.clear()
        assertContentEquals(canonical, configuration.canonicalBytesForTest())
        assertEquals(2, configuration.systemLibraryMounts.size)
        assertEquals(2, configuration.workerClassPath.size)

        assertNotEquals(
            configuration.canonicalSha256,
            syntheticConfiguration(
                configuration.systemLibraryMounts.reversed(),
                configuration.workerClassPath,
            ).canonicalSha256,
        )
        assertNotEquals(
            configuration.canonicalSha256,
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath.reversed(),
            ).canonicalSha256,
        )
        assertNotEquals(
            configuration.canonicalSha256,
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                expectedJavaSha256 = "e".repeat(64),
            ).canonicalSha256,
        )

        val changedConfigurations = listOf(
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                javaExecutable = Path.of("/provisioned/java/bin/java-alt"),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                javaRuntime = configuration.javaRuntime.copy(destination = Path.of("/runtime/java-alt")),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                javaRuntime = configuration.javaRuntime.copy(expectedManifestSha256 = "a".repeat(64)),
            ),
            syntheticConfiguration(
                listOf(configuration.systemLibraryMounts.first().copy(source = Path.of("/alt/libraries-a"))) +
                    configuration.systemLibraryMounts.drop(1),
                configuration.workerClassPath,
            ),
            syntheticConfiguration(
                listOf(
                    configuration.systemLibraryMounts.first()
                        .copy(destination = Path.of("/runtime/libraries-alt")),
                ) + configuration.systemLibraryMounts.drop(1),
                configuration.workerClassPath,
            ),
            syntheticConfiguration(
                listOf(
                    configuration.systemLibraryMounts.first()
                        .copy(expectedManifestSha256 = "b".repeat(64)),
                ) + configuration.systemLibraryMounts.drop(1),
                configuration.workerClassPath,
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                listOf(
                    configuration.workerClassPath.first()
                        .copy(path = Path.of("/provisioned/application/worker-alt.jar")),
                ) + configuration.workerClassPath.drop(1),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                listOf(
                    configuration.workerClassPath.first().copy(expectedSha256 = "c".repeat(64)),
                ) + configuration.workerClassPath.drop(1),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                bubblewrapExecutable = Path.of("/provisioned/tools/bwrap-alt"),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                resourceLimiterExecutable = Path.of("/provisioned/tools/prlimit-alt"),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                scopeSupervisorExecutable = Path.of("/provisioned/tools/systemd-run-alt"),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                scopeInspectorExecutable = Path.of("/provisioned/tools/systemctl-alt"),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                systemdUserRuntimeDirectory = Path.of("/run/user/1001"),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                expectedBubblewrapSha256 = "d".repeat(64),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                expectedResourceLimiterSha256 = "e".repeat(64),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                expectedScopeSupervisorSha256 = "f".repeat(64),
            ),
            syntheticConfiguration(
                configuration.systemLibraryMounts,
                configuration.workerClassPath,
                expectedScopeInspectorSha256 = "a".repeat(64),
            ),
        )
        changedConfigurations.forEach { changed ->
            assertNotEquals(configuration.canonicalSha256, changed.canonicalSha256)
        }
    }

    @Test
    fun `cleanup fallback always thaws and retries kill before stop and reset`() {
        val calls = mutableListOf<Pair<List<String>, Set<Int>>>()

        runObservationSystemdCleanupFallback("keeper.service") { arguments, allowedExitCodes ->
            calls += arguments to allowedExitCodes
            if (calls.size < 5) error("injected cleanup failure")
        }

        assertEquals(
            listOf(
                listOf("kill", "--kill-whom=all", "--signal=SIGKILL", "keeper.service"),
                listOf("thaw", "keeper.service"),
                listOf("kill", "--kill-whom=all", "--signal=SIGKILL", "keeper.service"),
                listOf("stop", "keeper.service"),
                listOf("reset-failed", "keeper.service"),
            ),
            calls.map { it.first },
        )
        assertTrue(calls.all { it.second == setOf(0, 1, 4, 5) })
    }

    @Test
    fun `private cleanup budget independently includes DWARF scratch and rejects overflow`() {
        assertEquals(
            17_783_848_960L,
            isolatedObservationCleanupBytes(
                maximumOutputBytes = 512L * 1024L * 1024L,
                maximumDatabaseBytes = 8L * 1024L * 1024L * 1024L,
                maximumDwarfScratchBytes = 8L * 1024L * 1024L * 1024L,
                protocolAllowanceBytes = 64L * 1024L * 1024L,
            ),
        )
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            isolatedObservationCleanupBytes(
                maximumOutputBytes = Long.MAX_VALUE,
                maximumDatabaseBytes = 1L,
                maximumDwarfScratchBytes = 1L,
                protocolAllowanceBytes = 1L,
            )
        }
    }

    @Test
    fun `prepared disk policy upper caps must fit the physical isolation closure`() {
        val configuration = syntheticConfiguration(
            mounts = listOf(
                FullTreeFunctionObservationRuntimeMount(
                    Path.of("/provisioned/libraries"),
                    Path.of("/runtime/libraries"),
                    "2".repeat(64),
                ),
            ),
            classPath = listOf(
                FullTreeFunctionObservationClassPathEntry(
                    Path.of("/provisioned/application/worker.jar"),
                    "3".repeat(64),
                ),
            ),
        )
        val limits = AcpRuntimeClosureLimits(
            maximumEntries = 4,
            maximumUserOwnedFileBytes = 1024,
            maximumDepth = 1,
        )
        fun binding(maximumBytes: Long, maximumInodes: Long) =
            FullTreeFunctionObservationOperationBinding.create(
                operationId = "a".repeat(64),
                shardId = "clang-lib-driver",
                shardInputSha256 = "b".repeat(64),
                scopeSha256 = "c".repeat(64),
                inventoryArtifactSha256 = "d".repeat(64),
                richArtifactSha256 = "e".repeat(64),
                isolationConfiguration = configuration,
                output = Path.of("/var/lib/decomp-oracle/output/clang-lib-driver.json"),
                diskPolicy = FullTreeDiskScratchPolicy(
                    requiredAvailableBytes = 1,
                    maximumFilesystemBytes = maximumBytes,
                    requiredAvailableInodes = 4,
                    maximumFilesystemInodes = maximumInodes,
                ),
            )

        requireFullTreeObservationDiskClosureCompatibility(binding(1024, 4), limits)
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            requireFullTreeObservationDiskClosureCompatibility(binding(1025, 4), limits)
        }
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            requireFullTreeObservationDiskClosureCompatibility(binding(1024, 5), limits)
        }
    }

    @Test
    fun `production preparation transfers one leased run and authenticates its exact ext4 layout`() =
        inControlTemporaryDirectory { root ->
            val mount = provisionedOracleExt4Mount()
            assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")
            val configuration = availableConfiguration(
                root.resolve("authenticated-runtime"),
                launchBoundaryRequired = false,
            )
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI authenticated JVM runtime is unavailable")
            }
            assumeTrue(configuration != null, "authenticated JVM runtime is unavailable")
            checkNotNull(configuration)

            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val authenticatedScope = fixture.authenticatedScope()
            val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
                fixture.inventory,
                authenticatedScope,
                "clang-lib-driver",
            )
            val output = privateDirectory(root.resolve("output")).resolve("clang-lib-driver.json")
            val journalRoot = privateDirectory(root.resolve("journal"))
            val capacity = LinuxFilesystemSyscalls.openRoot(mount).use { descriptor ->
                LinuxFilesystemSyscalls.filesystemCapacity(descriptor)
            }
            val binding = FullTreeFunctionObservationOperationBinding.create(
                operationId = "f".repeat(64),
                shardId = inputs.shard.identifier,
                shardInputSha256 = inputs.shard.inputSha256,
                scopeSha256 = authenticatedScope.sha256,
                inventoryArtifactSha256 = inputs.inventoryArtifactSha256,
                richArtifactSha256 = fixtureSha256(fixture.richArtifact),
                isolationConfiguration = configuration,
                output = output,
                diskPolicy = FullTreeDiskScratchPolicy(
                    requiredAvailableBytes = 1,
                    maximumFilesystemBytes = capacity.totalBytes,
                    requiredAvailableInodes = 4,
                    maximumFilesystemInodes = capacity.totalInodes,
                ),
            )
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val runRoot = leaseRoot.resolve(binding.runDirectoryName)
            var leased: FullTreeFunctionObservationLeasedOperation? = null
            var prepared: FullTreeFunctionObservationPreparedRun? = null
            var isolation: FullTreeFunctionObservationPreparedIsolation? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(journalRoot).use { authority ->
                    val acquired = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    leased = acquired
                    val run = acquired.prepareRunRoot()
                    prepared = run
                    assertFailsWith<IllegalStateException> { acquired.requireCurrentAuthorized() }
                    acquired.close()
                    leased = null

                    val ready = FullTreeFunctionObservationIsolatedOperationRunner.prepareBeforeLaunch(
                        preparedRun = run,
                        richArtifact = fixture.richArtifact,
                        inventoryPath = fixture.inventory,
                        scopeFiles = FullTreeFunctionObservationScopeFiles(
                            fixture.scope,
                            fixture.sourceLock,
                            fixture.manifest,
                        ),
                        output = output,
                        configuration = configuration,
                    )
                    isolation = ready
                    assertFailsWith<IllegalStateException> { run.requireCurrentBeforeLaunch() }
                    run.close()
                    prepared = null

                    assertEquals(binding.operationId, ready.operationId)
                    assertEquals(binding.shardId, ready.shardId)
                    ready.requireCurrentBeforeLaunch()
                    assertEquals(listOf("runtime", "scratch", "tmp"), entryNames(runRoot))
                    listOf(runRoot, runRoot.resolve("runtime"), runRoot.resolve("scratch"), runRoot.resolve("tmp"))
                        .forEach { directory ->
                            assertEquals(
                                PosixFilePermissions.fromString("rwx------"),
                                Files.getPosixFilePermissions(directory, LinkOption.NOFOLLOW_LINKS),
                            )
                        }
                    assertTrue(entryNames(runRoot.resolve("scratch")).isEmpty())
                    assertTrue(entryNames(runRoot.resolve("tmp")).isEmpty())
                    val classPathNames = configuration.workerClassPath.indices
                        .map { index -> "classpath-$index.jar" }
                        .sorted()
                    assertEquals(classPathNames, entryNames(runRoot.resolve("runtime")))
                    configuration.workerClassPath.forEachIndexed { index, source ->
                        val snapshot = runRoot.resolve("runtime/classpath-$index.jar")
                        assertEquals(source.expectedSha256, sha256(snapshot))
                        assertEquals(
                            PosixFilePermissions.fromString("r--------"),
                            Files.getPosixFilePermissions(snapshot, LinkOption.NOFOLLOW_LINKS),
                        )
                    }

                    val recordBytes = Files.readAllBytes(leaseRoot.resolve(TEST_LEASE_RECORD_FILE))
                    val changed = runRoot.resolve("runtime/${classPathNames.first()}")
                    Files.setPosixFilePermissions(changed, PosixFilePermissions.fromString("rw-------"))
                    assertFailsWith<FullTreeFunctionObservationIsolationException> {
                        ready.requireCurrentBeforeLaunch()
                    }
                    ready.close()
                    isolation = null
                    ready.close()

                    assertContentEquals(recordBytes, Files.readAllBytes(leaseRoot.resolve(TEST_LEASE_RECORD_FILE)))
                    FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        authority,
                        binding,
                        mount,
                    ).use { cold ->
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            cold.observedPopulation,
                        )
                        cold.requireCurrentReadOnly()
                    }
                }
            } finally {
                runCatching { isolation?.close() }
                runCatching { prepared?.close() }
                runCatching { leased?.close() }
                removePreparedIsolationLease(
                    leaseRoot,
                    binding.runDirectoryName,
                    configuration.workerClassPath.size,
                )
            }
            assertTrue(entryNames(mount).isEmpty())
        }

    @Test
    fun `production attachment reaches deterministic BOOT while history remains leased`() =
        inControlTemporaryDirectory { root ->
            val mount = provisionedOracleExt4Mount()
            assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI authenticated launch boundary is unavailable")
            }
            assumeTrue(configuration != null, "authenticated JVM launch boundary is unavailable")
            checkNotNull(configuration)

            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val authenticatedScope = fixture.authenticatedScope()
            val inputs = FullTreeFunctionObservationProducer.authenticateShardInputs(
                fixture.inventory,
                authenticatedScope,
                "clang-lib-driver",
            )
            val output = privateDirectory(root.resolve("output")).resolve("clang-lib-driver.json")
            val journalRoot = privateDirectory(root.resolve("journal"))
            val capacity = LinuxFilesystemSyscalls.openRoot(mount).use { descriptor ->
                LinuxFilesystemSyscalls.filesystemCapacity(descriptor)
            }
            val binding = FullTreeFunctionObservationOperationBinding.create(
                operationId = "e".repeat(64),
                shardId = inputs.shard.identifier,
                shardInputSha256 = inputs.shard.inputSha256,
                scopeSha256 = authenticatedScope.sha256,
                inventoryArtifactSha256 = inputs.inventoryArtifactSha256,
                richArtifactSha256 = fixtureSha256(fixture.richArtifact),
                isolationConfiguration = configuration,
                output = output,
                diskPolicy = FullTreeDiskScratchPolicy(
                    requiredAvailableBytes = 1,
                    maximumFilesystemBytes = capacity.totalBytes,
                    requiredAvailableInodes = 4,
                    maximumFilesystemInodes = capacity.totalInodes,
                ),
            )
            val leaseRoot = mount.resolve(binding.leaseDirectoryName)
            val runRoot = leaseRoot.resolve(binding.runDirectoryName)
            var leased: FullTreeFunctionObservationLeasedOperation? = null
            var prepared: FullTreeFunctionObservationPreparedRun? = null
            var isolation: FullTreeFunctionObservationPreparedIsolation? = null
            var booted: FullTreeFunctionObservationBootedIsolation? = null
            try {
                FullTreeFunctionObservationJournalAuthority.open(journalRoot).use { authority ->
                    val acquired = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        authority,
                        binding,
                        mount,
                    )
                    leased = acquired
                    val run = acquired.prepareRunRoot()
                    prepared = run
                    acquired.close()
                    leased = null

                    val ready = FullTreeFunctionObservationIsolatedOperationRunner.prepareBeforeLaunch(
                        preparedRun = run,
                        richArtifact = fixture.richArtifact,
                        inventoryPath = fixture.inventory,
                        scopeFiles = FullTreeFunctionObservationScopeFiles(
                            fixture.scope,
                            fixture.sourceLock,
                            fixture.manifest,
                        ),
                        output = output,
                        configuration = configuration,
                    )
                    isolation = ready
                    run.close()
                    prepared = null

                    val atBoot = FullTreeFunctionObservationIsolatedOperationRunner.launchToBoot(ready)
                    booted = atBoot
                    assertFailsWith<IllegalStateException> { ready.requireCurrentBeforeLaunch() }
                    ready.close()
                    isolation = null

                    assertEquals(binding.operationId, atBoot.operationId)
                    assertEquals(binding.shardId, atBoot.shardId)
                    assertEquals(binding.unitName, atBoot.unitName)
                    atBoot.requireCurrentAtBoot()
                    assertEquals(
                        listOf("runtime", "scratch", "tmp", "worker.boot"),
                        entryNames(runRoot),
                    )
                    listOf(
                        "parent.start",
                        "worker.ready",
                        "worker.failure",
                        "supervisor.failure",
                        "candidate.json",
                    ).forEach { name ->
                        assertTrue(
                            Files.notExists(runRoot.resolve(name), LinkOption.NOFOLLOW_LINKS),
                            "$name must be absent while the worker is blocked at BOOT",
                        )
                    }
                    assertTrue(Files.notExists(output, LinkOption.NOFOLLOW_LINKS))

                    atBoot.close()
                    booted = null
                    FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        authority,
                        binding,
                        mount,
                    ).use { cold ->
                        assertEquals(
                            FullTreeFunctionObservationOperationPhase.LEASED,
                            cold.leasedHistory.latest?.phase,
                        )
                        assertEquals(
                            FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN,
                            cold.observedPopulation,
                        )
                        cold.requireCurrentReadOnly()
                    }
                }
            } finally {
                var cleanupFailure: Throwable? = null
                listOf<() -> Unit>(
                    { booted?.close() },
                    { isolation?.close() },
                    { prepared?.close() },
                    { leased?.close() },
                ).forEach { cleanup ->
                    runCatching(cleanup).exceptionOrNull()?.let { failure ->
                        val prior = cleanupFailure
                        if (prior == null) cleanupFailure = failure else if (failure !== prior) {
                            prior.addSuppressed(failure)
                        }
                    }
                }
                cleanupFailure?.let { throw it }
                removePreparedIsolationLease(
                    leaseRoot,
                    binding.runDirectoryName,
                    configuration.workerClassPath.size,
                    rootFiles = listOf("worker.boot"),
                )
            }
            assertTrue(entryNames(mount).isEmpty())
        }

    @Test
    fun `fixture boundary rejects inherited socket and session-runtime descriptors`() {
        val runtime = Path.of("/run/user/1000")

        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            requireNoHostSessionDescriptorAuthority(listOf("socket:[12345]"), runtime)
        }
        assertFailsWith<FullTreeFunctionObservationIsolationException> {
            requireNoHostSessionDescriptorAuthority(listOf("/run/user/1000/bus"), runtime)
        }
        requireNoHostSessionDescriptorAuthority(
            listOf("/dev/null", "pipe:[12345]", "anon_inode:[eventpoll]"),
            runtime,
        )
    }

    @Test
    fun `fixture configuration rejects shadowing runtime destinations`() {
        val javaRoot = Path.of("/provisioned/java")
        val absent = Path.of("/provisioned/tool")

        assertFailsWith<IllegalArgumentException> {
            FullTreeFunctionObservationIsolationConfiguration(
                javaExecutable = javaRoot.resolve("bin/java"),
                javaRuntime = FullTreeFunctionObservationRuntimeMount(
                    javaRoot,
                    Path.of("/runtime/java"),
                    ZERO_SHA256,
                ),
                systemLibraryMounts = listOf(
                    FullTreeFunctionObservationRuntimeMount(
                        Path.of("/provisioned/libraries"),
                        Path.of("/runtime"),
                        ZERO_SHA256,
                    ),
                ),
                bubblewrapExecutable = absent,
                resourceLimiterExecutable = absent,
                scopeSupervisorExecutable = absent,
                scopeInspectorExecutable = absent,
                systemdUserRuntimeDirectory = Path.of("/run/user/1000"),
                workerClassPath = listOf(
                    FullTreeFunctionObservationClassPathEntry(absent, ZERO_SHA256),
                ),
                expectedJavaSha256 = ZERO_SHA256,
                expectedBubblewrapSha256 = ZERO_SHA256,
                expectedResourceLimiterSha256 = ZERO_SHA256,
                expectedScopeSupervisorSha256 = ZERO_SHA256,
                expectedScopeInspectorSha256 = ZERO_SHA256,
            )
        }
    }

    @Test
    fun `isolated Kotlin fixture publishes only after cgroup exit and leaves no private residue`() =
        inControlTemporaryDirectory { root ->
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            assumeTrue(configuration != null, "verified user-systemd and bubblewrap boundary is unavailable")
            checkNotNull(configuration)
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("clang-lib-driver.json")
            withDiskScratch { scratch ->
                val expected = FullTreeFunctionObservationProducer.generateShard(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scope = fixture.authenticatedScope(),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                )
                val expectedBytes = FullTreeFunctionObservations.canonicalEnvelopeBytes(expected.document)

                val result = FullTreeFunctionObservationIsolatedFixtureRunner.generateFixtureNoReplace(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scopeFiles = FullTreeFunctionObservationScopeFiles(
                        fixture.scope,
                        fixture.sourceLock,
                        fixture.manifest,
                    ),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    configuration = configuration,
                )

                assertContentEquals(expectedBytes, Files.readAllBytes(output))
                assertEquals(expected.outputSha256, result.fixtureShard.outputSha256)
                assertEquals(expected.outputBytes, result.fixtureShard.outputBytes)
                assertEquals(result.cgroup.peakResidentBytes, result.fixtureShard.peakResidentBytes)
                assertTrue(result.cgroup.peakResidentBytes > 0L)
                assertTrue(result.cgroup.cpuNanos > 0L)
                assertTrue(result.cgroup.derivationWallNanos > 0L)
                assertEquals(0L, result.cgroup.memoryMaxEvents)
                assertEquals(0L, result.cgroup.memoryOomEvents)
                assertEquals(0L, result.cgroup.memoryOomKillEvents)
                assertEquals(
                    PosixFilePermissions.fromString("r--------"),
                    Files.getPosixFilePermissions(output, LinkOption.NOFOLLOW_LINKS),
                )
                assertTrue(Files.list(scratch).use { it.findAny().isEmpty }, "isolated run tree was not removed")
                assertEquals(listOf(output), Files.list(outputParent).use { it.toList() })
            }
        }

    @Test
    fun `parent rejects an occupied final name before launching an isolated worker`() =
        inControlTemporaryDirectory { root ->
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))
            val scratch = privateDirectory(root.resolve("scratch"))
            val outputParent = privateDirectory(root.resolve("output"))
            val output = outputParent.resolve("occupied.json")
            val sentinel = "keep parent-owned publication\n".toByteArray()
            Files.write(output, sentinel)
            val unavailable = Path.of("/definitely-absent/isolation-executable")
            val configuration = FullTreeFunctionObservationIsolationConfiguration(
                javaExecutable = unavailable,
                javaRuntime = FullTreeFunctionObservationRuntimeMount(
                    unavailable,
                    Path.of("/fixture-java"),
                    ZERO_SHA256,
                ),
                systemLibraryMounts = listOf(
                    FullTreeFunctionObservationRuntimeMount(
                        Path.of("/definitely-absent/system-library"),
                        Path.of("/fixture-system-library"),
                        ZERO_SHA256,
                    ),
                ),
                bubblewrapExecutable = unavailable,
                resourceLimiterExecutable = unavailable,
                scopeSupervisorExecutable = unavailable,
                scopeInspectorExecutable = unavailable,
                systemdUserRuntimeDirectory = Path.of("/definitely-absent/runtime"),
                workerClassPath = listOf(
                    FullTreeFunctionObservationClassPathEntry(unavailable, ZERO_SHA256),
                ),
                expectedJavaSha256 = ZERO_SHA256,
                expectedBubblewrapSha256 = ZERO_SHA256,
                expectedResourceLimiterSha256 = ZERO_SHA256,
                expectedScopeSupervisorSha256 = ZERO_SHA256,
                expectedScopeInspectorSha256 = ZERO_SHA256,
            )

            val failure = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                FullTreeFunctionObservationIsolatedFixtureRunner.generateFixtureNoReplace(
                    richArtifact = fixture.richArtifact,
                    inventoryPath = fixture.inventory,
                    scopeFiles = FullTreeFunctionObservationScopeFiles(
                        fixture.scope,
                        fixture.sourceLock,
                        fixture.manifest,
                    ),
                    shardId = "clang-lib-driver",
                    scratchParent = scratch,
                    output = output,
                    configuration = configuration,
                )
            }

            assertTrue(failure.message.orEmpty().contains("already exists"), failure.message)
            assertContentEquals(sentinel, Files.readAllBytes(output))
            assertTrue(Files.list(scratch).use { it.findAny().isEmpty })
        }

    private fun availableConfiguration(
        runtimeParent: Path,
        launchBoundaryRequired: Boolean = true,
    ): FullTreeFunctionObservationIsolationConfiguration? {
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val java = Path.of(System.getProperty("java.home"), "bin", "java").realExecutableOrNull() ?: return null
        val javaRuntime = Path.of(System.getProperty("java.home")).toRealPath()
        val unusedLaunchBoundary = runtimeParent.parent.resolve("unused-launch-boundary")
        val runtime: Path
        val bubblewrap: Path
        val prlimit: Path
        val systemdRun: Path
        val systemctl: Path
        if (launchBoundaryRequired) {
            runtime = Path.of("/run/user/$uid")
            bubblewrap = Path.of("/usr/bin/bwrap").realExecutableOrNull() ?: return null
            prlimit = Path.of("/usr/bin/prlimit").realExecutableOrNull() ?: return null
            systemdRun = Path.of("/usr/bin/systemd-run").realExecutableOrNull() ?: return null
            systemctl = Path.of("/usr/bin/systemctl").realExecutableOrNull() ?: return null
            if (!Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS) || !Files.exists(runtime.resolve("bus"))) {
                return null
            }
            val probe = ProcessBuilder(systemctl.toString(), "--user", "show", "--property=Version", "--value")
                .redirectErrorStream(true)
                .also { builder ->
                    builder.environment().clear()
                    builder.environment()["XDG_RUNTIME_DIR"] = runtime.toString()
                    builder.environment()["DBUS_SESSION_BUS_ADDRESS"] =
                        "unix:path=${runtime.resolve("bus")}"
                }
                .start()
            val exited = probe.waitFor(3, TimeUnit.SECONDS)
            if (!exited) {
                probe.destroyForcibly()
                probe.waitFor(1, TimeUnit.SECONDS)
                return null
            }
            if (probe.exitValue() != 0 || probe.inputStream.readNBytes(1025).size > 1024) return null
        } else {
            runtime = unusedLaunchBoundary.resolve("session-runtime")
            bubblewrap = unusedLaunchBoundary.resolve("bwrap")
            prlimit = unusedLaunchBoundary.resolve("prlimit")
            systemdRun = unusedLaunchBoundary.resolve("systemd-run")
            systemctl = unusedLaunchBoundary.resolve("systemctl")
        }
        Files.createDirectories(runtimeParent)
        val classPath = System.getProperty("java.class.path")
            .split(File.pathSeparator)
            .filter(String::isNotEmpty)
            .map { Path.of(it).toAbsolutePath().normalize() }
            .mapIndexed { index, entry ->
                val regular = if (Files.isDirectory(entry, LinkOption.NOFOLLOW_LINKS)) {
                    runtimeParent.resolve("classes-$index.jar").also { jar -> createRuntimeJar(entry, jar) }
                } else entry
                FullTreeFunctionObservationClassPathEntry(regular, sha256(regular))
            }
        val manifestCache = mutableMapOf<Path, String>()
        val libraryMounts = listOf("/lib", "/lib64", "/usr/lib", "/usr/lib64")
            .map(Path::of)
            .filter { Files.isDirectory(it) }
            .map { destination ->
                val source = destination.toRealPath()
                FullTreeFunctionObservationRuntimeMount(
                    source = source,
                    destination = destination,
                    expectedManifestSha256 = manifestCache.getOrPut(source) {
                        calculateFullTreeObservationRuntimeManifestSha256(source)
                    },
                )
            }
        return FullTreeFunctionObservationIsolationConfiguration(
            javaExecutable = java,
            javaRuntime = FullTreeFunctionObservationRuntimeMount(
                javaRuntime,
                Path.of("/decomp-runtime/java"),
                calculateFullTreeObservationRuntimeManifestSha256(javaRuntime),
            ),
            systemLibraryMounts = libraryMounts,
            bubblewrapExecutable = bubblewrap,
            resourceLimiterExecutable = prlimit,
            scopeSupervisorExecutable = systemdRun,
            scopeInspectorExecutable = systemctl,
            systemdUserRuntimeDirectory = runtime,
            workerClassPath = classPath,
            expectedJavaSha256 = sha256(java),
            expectedBubblewrapSha256 = if (launchBoundaryRequired) sha256(bubblewrap) else ZERO_SHA256,
            expectedResourceLimiterSha256 = if (launchBoundaryRequired) sha256(prlimit) else ZERO_SHA256,
            expectedScopeSupervisorSha256 = if (launchBoundaryRequired) sha256(systemdRun) else ZERO_SHA256,
            expectedScopeInspectorSha256 = if (launchBoundaryRequired) sha256(systemctl) else ZERO_SHA256,
        )
    }

    private fun syntheticConfiguration(
        mounts: List<FullTreeFunctionObservationRuntimeMount>,
        classPath: List<FullTreeFunctionObservationClassPathEntry>,
        expectedJavaSha256: String = "1".repeat(64),
        javaRuntime: FullTreeFunctionObservationRuntimeMount = FullTreeFunctionObservationRuntimeMount(
            Path.of("/provisioned/java"),
            Path.of("/runtime/java"),
            "0".repeat(64),
        ),
        javaExecutable: Path = javaRuntime.source.resolve("bin/java"),
        bubblewrapExecutable: Path = Path.of("/provisioned/tools/bwrap"),
        resourceLimiterExecutable: Path = Path.of("/provisioned/tools/prlimit"),
        scopeSupervisorExecutable: Path = Path.of("/provisioned/tools/systemd-run"),
        scopeInspectorExecutable: Path = Path.of("/provisioned/tools/systemctl"),
        systemdUserRuntimeDirectory: Path = Path.of("/run/user/1000"),
        expectedBubblewrapSha256: String = "6".repeat(64),
        expectedResourceLimiterSha256: String = "7".repeat(64),
        expectedScopeSupervisorSha256: String = "8".repeat(64),
        expectedScopeInspectorSha256: String = "9".repeat(64),
    ): FullTreeFunctionObservationIsolationConfiguration {
        return FullTreeFunctionObservationIsolationConfiguration(
            javaExecutable = javaExecutable,
            javaRuntime = javaRuntime,
            systemLibraryMounts = mounts,
            bubblewrapExecutable = bubblewrapExecutable,
            resourceLimiterExecutable = resourceLimiterExecutable,
            scopeSupervisorExecutable = scopeSupervisorExecutable,
            scopeInspectorExecutable = scopeInspectorExecutable,
            systemdUserRuntimeDirectory = systemdUserRuntimeDirectory,
            workerClassPath = classPath,
            expectedJavaSha256 = expectedJavaSha256,
            expectedBubblewrapSha256 = expectedBubblewrapSha256,
            expectedResourceLimiterSha256 = expectedResourceLimiterSha256,
            expectedScopeSupervisorSha256 = expectedScopeSupervisorSha256,
            expectedScopeInspectorSha256 = expectedScopeInspectorSha256,
        )
    }

    private fun createRuntimeJar(source: Path, target: Path) {
        JarOutputStream(Files.newOutputStream(target)).use { jar ->
            Files.walk(source).use { paths ->
                paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
                    .sorted()
                    .forEach { file ->
                        val name = source.relativize(file).joinToString("/") { it.toString() }
                        jar.putNextEntry(JarEntry(name))
                        Files.newInputStream(file, LinkOption.NOFOLLOW_LINKS).use { it.copyTo(jar) }
                        jar.closeEntry()
                    }
            }
        }
    }

    private fun Path.realExecutableOrNull(): Path? = runCatching { toRealPath() }.getOrNull()
        ?.takeIf { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(it) }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileChannel.open(path, StandardOpenOption.READ).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            while (true) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                digest.update(buffer.array(), 0, read)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun privateDirectory(path: Path): Path {
        Files.createDirectory(path)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        return path
    }

    private fun provisionedOracleExt4Mount(): Path {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
            assertTrue(!configured.isNullOrBlank(), "required CI ext4 scratch slot was not provisioned")
        }
        assumeTrue(
            !configured.isNullOrBlank(),
            "set DECOMP_TEST_ORACLE_EXT4_SCRATCH to an empty user-owned 0700 ext4 mount with " +
                "rw,nodev,nosuid,noexec,noatime",
        )
        return Path.of(requireNotNull(configured)).toAbsolutePath().normalize()
    }

    private fun removePreparedIsolationLease(
        leaseRoot: Path,
        runDirectoryName: String,
        classPathEntries: Int,
        rootFiles: List<String> = emptyList(),
    ) {
        val runRoot = leaseRoot.resolve(runDirectoryName)
        val runtime = runRoot.resolve("runtime")
        repeat(classPathEntries) { index ->
            Files.deleteIfExists(runtime.resolve("classpath-$index.jar"))
        }
        rootFiles.forEach { name -> Files.deleteIfExists(runRoot.resolve(name)) }
        Files.deleteIfExists(runtime)
        Files.deleteIfExists(runRoot.resolve("scratch"))
        Files.deleteIfExists(runRoot.resolve("tmp"))
        Files.deleteIfExists(runRoot)
        Files.deleteIfExists(leaseRoot.resolve(TEST_LEASE_RECORD_FILE))
        Files.deleteIfExists(leaseRoot)
    }

    private fun entryNames(directory: Path): List<String> =
        Files.list(directory).use { entries ->
            entries.map { it.fileName.toString() }.sorted().toList()
        }

    private inline fun <T> withDiskScratch(action: (Path) -> T): T {
        val parent = Path.of(System.getProperty("user.dir"), "build", "tmp").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        assumeTrue(
            Files.getFileStore(parent).type().lowercase() !in setOf("tmpfs", "ramfs", "hugetlbfs"),
            "a disk-backed test scratch filesystem is unavailable",
        )
        val scratch = kotlin.io.path.createTempDirectory(parent, "isolated-function-test-")
        Files.setPosixFilePermissions(scratch, PosixFilePermissions.fromString("rwx------"))
        return try {
            action(scratch)
        } finally {
            if (Files.exists(scratch, LinkOption.NOFOLLOW_LINKS)) {
                val entries = Files.walk(scratch).use { it.toList() }
                entries.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.forEach { directory ->
                    Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
                }
                entries.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }

    private companion object {
        const val ZERO_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000"
        const val FROZEN_ISOLATION_CONFIGURATION_SHA256 =
            "996c3815ddd9f6330fbf9f404353a2f28fa81ba47d58a3eff4ff57e83cd71e95"
        const val TEST_LEASE_RECORD_FILE = "lease.json"
    }
}
