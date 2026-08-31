package decompengine.oracle.fulltree

import decompengine.acp.AcpRuntimeClosureLimits
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxProcessDescriptor
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
    fun `cold systemd absence observation enumerates without loading or mutating the exact name`() =
        inControlTemporaryDirectory { root ->
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI systemd observation boundary is unavailable")
            }
            assumeTrue(configuration != null, "systemd observation boundary is unavailable")
            checkNotNull(configuration)
            val sleep = Path.of("/usr/bin/sleep").realExecutableOrNull()
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(sleep != null, "required CI collision helper /usr/bin/sleep is unavailable")
            }
            assumeTrue(sleep != null, "an executable /usr/bin/sleep is required for collision coverage")
            checkNotNull(sleep)
            val binding = coldObservationBinding(
                configuration,
                root.resolve("cold-output.json"),
                "7",
                FullTreeDiskScratchPolicy(1, 1, 4, 4),
            )
            val commands = mutableListOf<List<String>>()
            val observer = FullTreeFunctionObservationColdUnitAbsenceObserver.openWithTestObserver(
                binding,
                configuration,
                FullTreeFunctionObservationSystemctlCommandObserver { unitName, arguments ->
                    if (unitName == binding.unitName) commands += arguments
                },
            )
            val expectedSweep = coldTestSystemdSweep(binding.unitName)

            requireColdSystemdManagerFeaturesUnfiltered("+PAM -SELINUX +SECCOMP\n")
            listOf(
                "",
                "+PAM +SELINUX +SECCOMP\n",
                "+PAM -SELINUX\n+SECCOMP\n",
                "+PAM -SELINUX -SELINUX\n",
                "+PAM -SELINUX malformed\n",
            ).forEach { output ->
                assertFailsWith<FullTreeFunctionObservationIsolationException> {
                    requireColdSystemdManagerFeaturesUnfiltered(output)
                }
            }
            requireColdSystemdEnumerationEmpty("", "job inventory")
            listOf("\n", "1 ${binding.unitName} start waiting\n").forEach { output ->
                assertFailsWith<FullTreeFunctionObservationIsolationException> {
                    requireColdSystemdEnumerationEmpty(output, "job inventory")
                }
            }

            observer.requireAbsent()
            assertEquals(expectedSweep, commands)
            assertObservationUnitAndCgroupAbsent(configuration, binding.unitName)

            val cgroupParent = testObservationCgroupParentOrNull(configuration)
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(cgroupParent != null, "required CI cgroup-only collision boundary is unavailable")
            }
            if (cgroupParent != null) {
                val exactCgroup = cgroupParent.resolve(binding.unitName)
                val commandsBeforeCgroupCollision = commands.size
                try {
                    Files.createDirectory(exactCgroup)
                    val collision = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                        observer.requireAbsent()
                    }
                    assertTrue(collision.message.orEmpty().contains("exact-name cgroup"), collision.message)
                    assertEquals(expectedSweep.take(3), commands.drop(commandsBeforeCgroupCollision))
                } finally {
                    Files.deleteIfExists(exactCgroup)
                }
                observer.requireAbsent()
                assertEquals(expectedSweep, commands.takeLast(expectedSweep.size))
                assertObservationUnitAndCgroupAbsent(configuration, binding.unitName)
            }

            var occupant: OccupiedObservationUnit? = null
            try {
                val occupied = startOccupiedObservationUnit(configuration, binding.unitName, sleep)
                occupant = occupied
                val commandsBeforeCollision = commands.size
                val collision = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                    observer.requireAbsent()
                }
                assertTrue(collision.message.orEmpty().contains("unit inventory"), collision.message)
                assertEquals(
                    listOf(
                        COLD_TEST_MANAGER_FEATURES_COMMAND,
                        COLD_TEST_LIST_UNITS_COMMAND + listOf("--", binding.unitName),
                    ),
                    commands.drop(commandsBeforeCollision),
                )
                assertOccupiedObservationUnitUnchanged(configuration, occupied)
                stopOccupiedObservationUnit(configuration, occupied)
                occupant = null
                observer.requireAbsent()
                assertEquals(expectedSweep, commands.takeLast(expectedSweep.size))
                assertObservationUnitAndCgroupAbsent(configuration, binding.unitName)
            } finally {
                occupant?.let { stopOccupiedObservationUnit(configuration, it) }
            }
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
    fun `cold leased transfer observes only deterministic unit absence and never owns later units`() =
        inControlTemporaryDirectory { root ->
            val mount = provisionedOracleExt4Mount()
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI cold systemd boundary is unavailable")
            }
            assumeTrue(configuration != null, "cold systemd boundary is unavailable")
            checkNotNull(configuration)
            val sleep = Path.of("/usr/bin/sleep").realExecutableOrNull()
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(sleep != null, "required CI collision helper /usr/bin/sleep is unavailable")
            }
            assumeTrue(sleep != null, "an executable /usr/bin/sleep is required for collision coverage")
            checkNotNull(sleep)
            val capacity = LinuxFilesystemSyscalls.openRoot(mount).use { descriptor ->
                LinuxFilesystemSyscalls.filesystemCapacity(descriptor)
            }
            val policy = FullTreeDiskScratchPolicy(
                requiredAvailableBytes = 1,
                maximumFilesystemBytes = capacity.totalBytes,
                requiredAvailableInodes = 4,
                maximumFilesystemInodes = capacity.totalInodes,
            )

            listOf(false, true).forEach { activeRun ->
                assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")
                val label = if (activeRun) "active" else "record"
                val operationRoot = privateDirectory(root.resolve("cold-$label"))
                val journalRoot = privateDirectory(operationRoot.resolve("journal"))
                val binding = coldObservationBinding(
                    configuration,
                    operationRoot.resolve("output.json"),
                    if (activeRun) "6" else "5",
                    policy,
                )
                val leaseRoot = mount.resolve(binding.leaseDirectoryName)
                val runRoot = leaseRoot.resolve(binding.runDirectoryName)
                var live: AutoCloseable? = null
                var occupant: OccupiedObservationUnit? = null
                var authority: FullTreeFunctionObservationJournalAuthority? = null
                var retainedFailure: Throwable? = null
                fun retain(failure: Throwable) {
                    val prior = retainedFailure
                    if (prior == null) retainedFailure = failure else if (failure !== prior) {
                        prior.addSuppressed(failure)
                    }
                }
                try {
                    val openedAuthority = FullTreeFunctionObservationJournalAuthority.open(journalRoot)
                    authority = openedAuthority
                    val leased = FullTreeFunctionObservationOperationCoordinator.prepareNew(
                        openedAuthority,
                        binding,
                        mount,
                    )
                    live = leased
                    if (activeRun) {
                        val prepared = leased.prepareRunRoot()
                        live = prepared
                        prepared.close()
                    } else {
                        leased.close()
                    }
                    live = null

                    val journalBefore = immutableTestTreeSnapshot(journalRoot)
                    val mountBefore = immutableTestTreeSnapshot(mount)
                    val expectedPopulation = if (activeRun) {
                        FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN
                    } else {
                        FullTreeDiskScratchColdPopulation.RECORD_ONLY
                    }
                    val cold = FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        openedAuthority,
                        binding,
                        mount,
                    )
                    live = cold
                    if (!activeRun) {
                        assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                            cold.transferToDeterministicUnitAbsent(
                                configurationWithDifferentIdentity(
                                    configuration,
                                    operationRoot.resolve("unavailable-systemctl"),
                                ),
                            )
                        }
                        cold.requireCurrentReadOnly()
                        assertColdOperationLocksRetained(openedAuthority, binding, mount)

                        FullTreeFunctionObservationColdTransferFaultPoint.entries.forEach { faultPoint ->
                            val injected = assertFailsWith<FullTreeFunctionObservationOperationCoordinationException> {
                                cold.transferToDeterministicUnitAbsentForTesting(configuration, faultPoint)
                            }
                            assertTrue(injected.message.orEmpty().contains("final cold systemd sweep"))
                            cold.requireCurrentReadOnly()
                            assertColdOperationLocksRetained(openedAuthority, binding, mount)
                        }
                    } else {
                        val occupied = startOccupiedObservationUnit(configuration, binding.unitName, sleep)
                        occupant = occupied
                        val collision = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                            cold.transferToDeterministicUnitAbsent(configuration)
                        }
                        assertTrue(collision.message.orEmpty().contains("unit inventory"), collision.message)
                        assertOccupiedObservationUnitUnchanged(configuration, occupied)
                        cold.requireCurrentReadOnly()
                        assertColdOperationLocksRetained(openedAuthority, binding, mount)
                        stopOccupiedObservationUnit(configuration, occupied)
                        occupant = null
                    }

                    val absent = cold.transferToDeterministicUnitAbsent(configuration)
                    live = absent
                    assertFailsWith<IllegalStateException> { cold.requireCurrentReadOnly() }
                    assertEquals(binding.unitName, absent.unitName)
                    assertEquals(expectedPopulation, absent.observedPopulation)
                    assertEquals(
                        listOf(
                            FullTreeFunctionObservationOperationPhase.PREPARING,
                            FullTreeFunctionObservationOperationPhase.LEASED,
                        ),
                        absent.leasedHistory.transitions.map { it.phase },
                    )
                    absent.requireCurrentUnitAbsentReadOnly()
                    assertColdOperationLocksRetained(openedAuthority, binding, mount)

                    if (activeRun) {
                        val later = startOccupiedObservationUnit(configuration, binding.unitName, sleep)
                        occupant = later
                        assertFailsWith<FullTreeFunctionObservationIsolationException> {
                            absent.requireCurrentUnitAbsentReadOnly()
                        }
                        assertOccupiedObservationUnitUnchanged(configuration, later)
                        absent.close()
                        live = null
                        assertOccupiedObservationUnitUnchanged(configuration, later)
                        requireNotNull(openedAuthority.openExisting(binding)).close()
                        FullTreeDiskScratchAuthority.openExistingReadOnly(
                            mount,
                            binding.diskOperation(),
                            binding.diskPolicy(),
                        ).close()
                        stopOccupiedObservationUnit(configuration, later)
                        occupant = null
                    } else {
                        absent.close()
                        live = null
                    }
                    assertFailsWith<IllegalStateException> {
                        absent.requireCurrentUnitAbsentReadOnly()
                    }
                    FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
                        openedAuthority,
                        binding,
                        mount,
                    ).use { reopened ->
                        reopened.requireCurrentReadOnly()
                        assertEquals(expectedPopulation, reopened.observedPopulation)
                    }
                    assertEquals(journalBefore, immutableTestTreeSnapshot(journalRoot))
                    assertEquals(mountBefore, immutableTestTreeSnapshot(mount))
                    assertTrue(Files.notExists(operationRoot.resolve("output.json")))
                } catch (failure: Throwable) {
                    retain(failure)
                } finally {
                    listOf<() -> Unit>(
                        {
                            occupant?.let { stopOccupiedObservationUnit(configuration, it) }
                            occupant = null
                        },
                        {
                            live?.close()
                            live = null
                        },
                        {
                            authority?.close()
                            authority = null
                        },
                        { assertObservationUnitAndCgroupAbsent(configuration, binding.unitName) },
                    ).forEach { cleanup ->
                        runCatching(cleanup).exceptionOrNull()?.let(::retain)
                    }
                    if (live == null && authority == null) {
                        runCatching { removeColdObservationLease(leaseRoot, runRoot, activeRun) }
                            .exceptionOrNull()?.let(::retain)
                    } else {
                        retain(IllegalStateException("cold observation authorities survived teardown"))
                    }
                    runCatching { assertTrue(entryNames(mount).isEmpty()) }
                        .exceptionOrNull()?.let(::retain)
                    retainedFailure?.let { throw it }
                }
            }
        }

    @Test
    fun `unit collisions around deterministic absence sweeps stay untouched`() =
        inControlTemporaryDirectory { root ->
            val mount = provisionedOracleExt4Mount()
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI authenticated launch boundary is unavailable")
            }
            assumeTrue(configuration != null, "authenticated JVM launch boundary is unavailable")
            checkNotNull(configuration)
            val sleep = Path.of("/usr/bin/sleep").realExecutableOrNull()
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(sleep != null, "required CI collision helper /usr/bin/sleep is unavailable")
            }
            assumeTrue(sleep != null, "an executable /usr/bin/sleep is required for collision coverage")
            checkNotNull(sleep)
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))

            listOf(
                Triple("d", FullTreeFunctionObservationLaunchFaultPoint.BEFORE_INITIAL_UNIT_ABSENCE, true),
                Triple("c", FullTreeFunctionObservationLaunchFaultPoint.BEFORE_FINAL_UNIT_ABSENCE, true),
                Triple("a", FullTreeFunctionObservationLaunchFaultPoint.AFTER_FINAL_UNIT_ABSENCE, false),
            ).forEach { (seed, collisionPoint, rejectedByAbsenceSweep) ->
                withPreparedProductionIsolation(
                    root.resolve("collision-$seed"),
                    mount,
                    configuration,
                    fixture,
                    seed,
                ) { context ->
                    val commands = mutableListOf<List<String>>()
                    var occupant: OccupiedObservationUnit? = null
                    val hooks = FullTreeFunctionObservationLaunchTestHooks(
                        faultInjector = FullTreeFunctionObservationLaunchFaultInjector { point, unitName ->
                            if (point == collisionPoint) {
                                check(occupant == null)
                                occupant = startOccupiedObservationUnit(configuration, unitName, sleep)
                            }
                        },
                        systemctlCommandObserver = FullTreeFunctionObservationSystemctlCommandObserver { unitName, arguments ->
                            if (unitName == context.binding.unitName) commands += arguments
                        },
                    )
                    try {
                        val collision = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                            FullTreeFunctionObservationIsolatedOperationRunner.launchToBootWithTestHooks(
                                context.ready,
                                hooks,
                            )
                        }
                        if (rejectedByAbsenceSweep) {
                            assertTrue(collision.message.orEmpty().contains("already in use"), collision.message)
                        }
                        val occupied = checkNotNull(occupant)
                        assertOccupiedObservationUnitUnchanged(configuration, occupied)
                        assertOnlyExactUnitObservationSystemctlCommands(commands, context.binding.unitName)
                        assertOperationLocksRetained(context)

                        val retainedCollision = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                            context.ready.close()
                        }
                        if (rejectedByAbsenceSweep) {
                            assertTrue(
                                retainedCollision.message.orEmpty().contains("already in use"),
                                retainedCollision.message,
                            )
                        }
                        assertOccupiedObservationUnitUnchanged(configuration, occupied)
                        assertOnlyExactUnitObservationSystemctlCommands(commands, context.binding.unitName)
                        assertOperationLocksRetained(context)

                        try {
                            stopOccupiedObservationUnit(configuration, occupied)
                        } finally {
                            occupant = null
                        }
                        closeAfterExternalUnitCleanup(context.ready)
                        assertColdLeasedResidue(context)
                    } finally {
                        occupant?.let { occupied ->
                            stopOccupiedObservationUnit(configuration, occupied)
                        }
                    }
                }
            }
        }

    @Test
    fun `process start return grants only exact local pidfd cleanup before attachment`() =
        inControlTemporaryDirectory { root ->
            val mount = provisionedOracleExt4Mount()
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI authenticated launch boundary is unavailable")
            }
            assumeTrue(configuration != null, "authenticated JVM launch boundary is unavailable")
            checkNotNull(configuration)
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))

            withPreparedProductionIsolation(
                root.resolve("start-throws"),
                mount,
                configuration,
                fixture,
                "e",
            ) { context ->
                val commands = mutableListOf<List<String>>()
                var destructiveCleanupEntries = 0
                val hooks = FullTreeFunctionObservationLaunchTestHooks(
                    faultInjector = FullTreeFunctionObservationLaunchFaultInjector { point, _ ->
                        if (point == FullTreeFunctionObservationLaunchFaultPoint.BEFORE_DESTRUCTIVE_CLEANUP) {
                            destructiveCleanupEntries += 1
                        }
                    },
                    systemctlCommandObserver = FullTreeFunctionObservationSystemctlCommandObserver { unitName, arguments ->
                        if (unitName == context.binding.unitName) commands += arguments
                    },
                    forceProcessStartFailure = true,
                )

                val startFailure = assertFailsWith<java.io.IOException> {
                    FullTreeFunctionObservationIsolatedOperationRunner.launchToBootWithTestHooks(
                        context.ready,
                        hooks,
                    )
                }
                assertTrue(startFailure.message.orEmpty().isNotBlank())
                assertEquals(0, destructiveCleanupEntries)
                assertOnlyExactUnitObservationSystemctlCommands(commands, context.binding.unitName)
                assertObservationUnitAndCgroupAbsent(configuration, context.binding.unitName)
                assertColdLeasedResidue(context)
            }

            withPreparedProductionIsolation(
                root.resolve("start-returned"),
                mount,
                configuration,
                fixture,
                "f",
                allowedRootProtocolFiles = LIVE_FAULT_PROTOCOL_FILES,
            ) { context ->
                val launchFailure = SimulatedObservationAfterProcessStartFailure()
                var afterStartEntries = 0
                var destructiveCleanupEntries = 0
                val commands = mutableListOf<List<String>>()
                val hooks = FullTreeFunctionObservationLaunchTestHooks(
                    faultInjector = FullTreeFunctionObservationLaunchFaultInjector { point, _ ->
                        when (point) {
                            FullTreeFunctionObservationLaunchFaultPoint.AFTER_PROCESS_START_RETURNED -> {
                                afterStartEntries += 1
                                throw launchFailure
                            }

                            FullTreeFunctionObservationLaunchFaultPoint.BEFORE_DESTRUCTIVE_CLEANUP ->
                                destructiveCleanupEntries += 1

                            else -> Unit
                        }
                    },
                    systemctlCommandObserver = FullTreeFunctionObservationSystemctlCommandObserver { unitName, arguments ->
                        if (unitName == context.binding.unitName) commands += arguments
                    },
                )

                val retained = assertFailsWith<SimulatedObservationAfterProcessStartFailure> {
                    FullTreeFunctionObservationIsolatedOperationRunner.launchToBootWithTestHooks(
                        context.ready,
                        hooks,
                    )
                }
                assertTrue(retained === launchFailure)
                assertEquals(1, afterStartEntries)
                assertEquals(1, destructiveCleanupEntries)
                assertOnlyExactUnitObservationSystemctlCommands(commands, context.binding.unitName)
                assertObservationUnitAndCgroupAbsent(configuration, context.binding.unitName)
                assertColdLeasedResidue(context)
            }
        }

    @Test
    fun `post-attachment cleanup and final absence faults retain retry authority`() =
        inControlTemporaryDirectory { root ->
            val mount = provisionedOracleExt4Mount()
            val configuration = availableConfiguration(root.resolve("authenticated-runtime"))
            if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                assertTrue(configuration != null, "required CI authenticated launch boundary is unavailable")
            }
            assumeTrue(configuration != null, "authenticated JVM launch boundary is unavailable")
            checkNotNull(configuration)
            val fixture = createFullTreeControlFixture(root.resolve("fixture"))

            withPreparedProductionIsolation(
                root.resolve("cleanup-retry"),
                mount,
                configuration,
                fixture,
                "b",
                allowedRootProtocolFiles = LIVE_FAULT_PROTOCOL_FILES,
            ) { context ->
                val commands = mutableListOf<List<String>>()
                val launchFailure = SimulatedObservationLaunchFailure()
                var destructiveCleanupEntries = 0
                var finalAbsenceFaults = 0
                val hooks = FullTreeFunctionObservationLaunchTestHooks(
                    faultInjector = FullTreeFunctionObservationLaunchFaultInjector { point, _ ->
                        when (point) {
                            FullTreeFunctionObservationLaunchFaultPoint.AFTER_SCOPE_ATTACHED ->
                                throw launchFailure

                            FullTreeFunctionObservationLaunchFaultPoint.BEFORE_DESTRUCTIVE_CLEANUP -> {
                                destructiveCleanupEntries += 1
                                if (destructiveCleanupEntries <= 2) {
                                    throw SimulatedObservationCleanupFailure()
                                }
                            }

                            FullTreeFunctionObservationLaunchFaultPoint.BEFORE_FINAL_CLEANUP_ABSENCE -> {
                                finalAbsenceFaults += 1
                                if (finalAbsenceFaults == 1) {
                                    throw SimulatedObservationFinalAbsenceFailure()
                                }
                            }

                            else -> Unit
                        }
                    },
                    systemctlCommandObserver = FullTreeFunctionObservationSystemctlCommandObserver { unitName, arguments ->
                        if (unitName == context.binding.unitName) commands += arguments
                    },
                )

                val retained = assertFailsWith<SimulatedObservationLaunchFailure> {
                    FullTreeFunctionObservationIsolatedOperationRunner.launchToBootWithTestHooks(
                        context.ready,
                        hooks,
                    )
                }
                assertTrue(retained === launchFailure)
                assertEquals(2, destructiveCleanupEntries)
                assertEquals(0, finalAbsenceFaults)
                assertOperationLocksRetained(context)

                val commandsBeforeCleanupRetry = commands.size
                assertFailsWith<SimulatedObservationFinalAbsenceFailure> {
                    context.ready.close()
                }
                assertEquals(3, destructiveCleanupEntries)
                assertEquals(1, finalAbsenceFaults)
                assertTrue(
                    commands.drop(commandsBeforeCleanupRetry).any { arguments ->
                        arguments.firstOrNull() == "show"
                    },
                    "post-attachment cleanup never reached a fresh exact-unit observation",
                )
                assertObservationUnitAndCgroupAbsent(configuration, context.binding.unitName)
                assertOperationLocksRetained(context)
                assertTrue(Files.notExists(context.output, LinkOption.NOFOLLOW_LINKS))
                assertTrue(Files.notExists(context.runRoot.resolve("parent.start"), LinkOption.NOFOLLOW_LINKS))

                val commandsBeforeFinalAbsenceRetry = commands.size
                context.ready.close()
                assertEquals(2, finalAbsenceFaults)
                assertOnlyExactUnitObservationSystemctlCommands(
                    commands.drop(commandsBeforeFinalAbsenceRetry),
                    context.binding.unitName,
                )
                assertObservationUnitAndCgroupAbsent(configuration, context.binding.unitName)
                assertColdLeasedResidue(context)
            }
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

    private data class PreparedProductionIsolationTestContext(
        val binding: FullTreeFunctionObservationOperationBinding,
        val mount: Path,
        val runRoot: Path,
        val output: Path,
        val authority: FullTreeFunctionObservationJournalAuthority,
        val ready: FullTreeFunctionObservationPreparedIsolation,
    )

    private data class ImmutableTestTreeEntry(
        val kind: String,
        val device: Long,
        val inode: Long,
        val mountId: Long,
        val mode: Int,
        val uid: Int,
        val gid: Int,
        val linkCount: Long,
        val size: Long,
        val modified: String,
        val changed: String,
        val symbolicLinkTarget: String?,
        val bytes: List<Byte>,
    )

    private fun coldObservationBinding(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        output: Path,
        operationSeed: String,
        diskPolicy: FullTreeDiskScratchPolicy,
    ): FullTreeFunctionObservationOperationBinding {
        require(operationSeed.matches(Regex("[0-9a-f]")))
        return FullTreeFunctionObservationOperationBinding.create(
            operationId = operationSeed.repeat(64),
            shardId = "clang-lib-driver",
            shardInputSha256 = "a".repeat(64),
            scopeSha256 = "b".repeat(64),
            inventoryArtifactSha256 = "c".repeat(64),
            richArtifactSha256 = "d".repeat(64),
            isolationConfiguration = configuration,
            output = output.toAbsolutePath().normalize(),
            diskPolicy = diskPolicy,
        )
    }

    private fun configurationWithDifferentIdentity(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unavailableScopeInspector: Path? = null,
    ): FullTreeFunctionObservationIsolationConfiguration =
        FullTreeFunctionObservationIsolationConfiguration(
            javaExecutable = configuration.javaExecutable,
            javaRuntime = configuration.javaRuntime,
            systemLibraryMounts = configuration.systemLibraryMounts,
            bubblewrapExecutable = configuration.bubblewrapExecutable,
            resourceLimiterExecutable = configuration.resourceLimiterExecutable,
            scopeSupervisorExecutable = configuration.scopeSupervisorExecutable,
            scopeInspectorExecutable = unavailableScopeInspector ?: configuration.scopeInspectorExecutable,
            systemdUserRuntimeDirectory = configuration.systemdUserRuntimeDirectory,
            workerClassPath = configuration.workerClassPath,
            expectedJavaSha256 = if (configuration.expectedJavaSha256 == ZERO_SHA256) {
                "1".repeat(64)
            } else {
                ZERO_SHA256
            },
            expectedBubblewrapSha256 = configuration.expectedBubblewrapSha256,
            expectedResourceLimiterSha256 = configuration.expectedResourceLimiterSha256,
            expectedScopeSupervisorSha256 = configuration.expectedScopeSupervisorSha256,
            expectedScopeInspectorSha256 = if (unavailableScopeInspector == null) {
                configuration.expectedScopeInspectorSha256
            } else {
                ZERO_SHA256
            },
        )

    private fun assertColdOperationLocksRetained(
        authority: FullTreeFunctionObservationJournalAuthority,
        binding: FullTreeFunctionObservationOperationBinding,
        mount: Path,
    ) {
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            authority.openExisting(binding)
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchAuthority.openExistingReadOnly(
                mount,
                binding.diskOperation(),
                binding.diskPolicy(),
            )
        }
    }

    private fun immutableTestTreeSnapshot(root: Path): Map<String, ImmutableTestTreeEntry> =
        Files.walk(root).use { paths ->
            paths.sorted().iterator().asSequence().associate { path ->
                val pinnedBefore = requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)).use {
                    LinuxFilesystemSyscalls.identity(it.fd)
                }
                val attributes = Files.readAttributes(
                    path,
                    java.nio.file.attribute.BasicFileAttributes::class.java,
                    LinkOption.NOFOLLOW_LINKS,
                )
                val unix = Files.readAttributes(
                    path,
                    "unix:dev,ino,mode,uid,gid,nlink,ctime",
                    LinkOption.NOFOLLOW_LINKS,
                )
                fun unixLong(name: String): Long =
                    (unix[name] as? Number)?.toLong()
                        ?: error("immutable test snapshot lacks unix:$name for $path")
                require(
                    pinnedBefore.key.device == unixLong("dev") &&
                        pinnedBefore.key.inode == unixLong("ino") &&
                        pinnedBefore.mode.toLong() == unixLong("mode") &&
                        pinnedBefore.uid.toLong() == unixLong("uid") &&
                        pinnedBefore.gid.toLong() == unixLong("gid") &&
                        pinnedBefore.linkCount.toLong() == unixLong("nlink")
                ) { "immutable test snapshot selected inconsistent identity: $path" }
                val kind = when {
                    attributes.isDirectory -> "directory"
                    attributes.isRegularFile -> "regular"
                    attributes.isSymbolicLink -> "symlink"
                    else -> "other"
                }
                val bytes = if (attributes.isRegularFile) {
                    require(attributes.size() <= TEST_IMMUTABLE_TREE_FILE_BYTES) {
                        "immutable test snapshot file exceeds the byte limit: $path"
                    }
                    Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
                        input.readNBytes(TEST_IMMUTABLE_TREE_FILE_BYTES + 1).also { contents ->
                            require(contents.size <= TEST_IMMUTABLE_TREE_FILE_BYTES) {
                                "immutable test snapshot file grew beyond the byte limit: $path"
                            }
                            require(contents.size.toLong() == attributes.size()) {
                                "immutable test snapshot file changed while read: $path"
                            }
                        }.toList()
                    }
                } else {
                    emptyList()
                }
                val linkTarget = if (attributes.isSymbolicLink) {
                    Files.readSymbolicLink(path).toString().also { target ->
                        require(target.length <= TEST_SYMBOLIC_LINK_CHARS) {
                            "immutable test snapshot symbolic link exceeds the character limit: $path"
                        }
                    }
                } else {
                    null
                }
                val pinnedAfter = requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path)).use {
                    LinuxFilesystemSyscalls.identity(it.fd)
                }
                require(pinnedAfter == pinnedBefore) {
                    "immutable test snapshot identity changed while read: $path"
                }
                val relative = root.relativize(path).toString().ifEmpty { "." }
                relative to ImmutableTestTreeEntry(
                    kind = kind,
                    device = unixLong("dev"),
                    inode = unixLong("ino"),
                    mountId = pinnedBefore.mountId,
                    mode = unixLong("mode").toInt(),
                    uid = unixLong("uid").toInt(),
                    gid = unixLong("gid").toInt(),
                    linkCount = unixLong("nlink"),
                    size = attributes.size(),
                    modified = attributes.lastModifiedTime().toString(),
                    changed = unix["ctime"].toString(),
                    symbolicLinkTarget = linkTarget,
                    bytes = bytes,
                )
            }
        }

    private fun removeColdObservationLease(
        leaseRoot: Path,
        runRoot: Path,
        activeRun: Boolean,
    ) {
        if (Files.notExists(leaseRoot, LinkOption.NOFOLLOW_LINKS)) return
        val expectedLeaseNames = buildSet {
            add(TEST_LEASE_RECORD_FILE)
            if (activeRun) add(runRoot.fileName.toString())
        }
        check(entryNames(leaseRoot).toSet() == expectedLeaseNames) {
            "cold observation lease retained unexpected members"
        }
        if (activeRun) {
            check(entryNames(runRoot).isEmpty()) { "cold observation run root is not empty" }
            Files.delete(runRoot)
        }
        Files.delete(leaseRoot.resolve(TEST_LEASE_RECORD_FILE))
        Files.delete(leaseRoot)
    }

    private fun withPreparedProductionIsolation(
        root: Path,
        mount: Path,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        fixture: FullTreeControlFixture,
        operationSeed: String,
        allowedRootProtocolFiles: Set<String> = emptySet(),
        action: (PreparedProductionIsolationTestContext) -> Unit,
    ) {
        require(operationSeed.matches(Regex("[0-9a-f]")))
        require(allowedRootProtocolFiles.all { it in LIVE_FAULT_PROTOCOL_FILES })
        assertTrue(entryNames(mount).isEmpty(), "provisioned ext4 slot is not empty")
        privateDirectory(root)
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
            operationId = operationSeed.repeat(64),
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
                action(
                    PreparedProductionIsolationTestContext(
                        binding,
                        mount,
                        runRoot,
                        output,
                        authority,
                        ready,
                    ),
                )
            }
        } finally {
            var cleanupFailure: Throwable? = null
            listOf<() -> Unit>(
                { closePreparedIsolationAfterTest(isolation) },
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
            assertObservationUnitAndCgroupAbsent(configuration, binding.unitName)
            val rootFiles = if (Files.isDirectory(runRoot, LinkOption.NOFOLLOW_LINKS)) {
                entryNames(runRoot).filterNot { it in PREPARED_RUN_DIRECTORIES }
            } else {
                emptyList()
            }
            assertTrue(
                rootFiles.all { it in allowedRootProtocolFiles },
                "faulted BOOT run retained unexpected members: $rootFiles",
            )
            rootFiles.forEach { name ->
                assertFaultProtocolFile(runRoot.resolve(name), name, binding.bindingSha256)
            }
            removePreparedIsolationLease(
                leaseRoot,
                binding.runDirectoryName,
                configuration.workerClassPath.size,
                rootFiles,
            )
        }
        assertTrue(entryNames(mount).isEmpty())
    }

    private fun closePreparedIsolationAfterTest(
        isolation: FullTreeFunctionObservationPreparedIsolation?,
    ) {
        if (isolation == null) return
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        var last: Throwable? = null
        while (System.nanoTime() < deadline) {
            try {
                isolation.close()
                return
            } catch (failure: Throwable) {
                last = failure
                Thread.sleep(25)
            }
        }
        throw checkNotNull(last)
    }

    private fun assertOperationLocksRetained(context: PreparedProductionIsolationTestContext) {
        assertFailsWith<FullTreeFunctionObservationOperationJournalException> {
            context.authority.openExisting(context.binding)
        }
        assertFailsWith<FullTreeDiskScratchException> {
            FullTreeDiskScratchAuthority.openExistingReadOnly(
                context.mount,
                context.binding.diskOperation(),
                context.binding.diskPolicy(),
            )
        }
    }

    private fun assertColdLeasedResidue(context: PreparedProductionIsolationTestContext) {
        FullTreeFunctionObservationOperationCoordinator.openExistingLeasedReadOnly(
            context.authority,
            context.binding,
            context.mount,
        ).use { cold ->
            assertEquals(
                listOf(
                    FullTreeFunctionObservationOperationPhase.PREPARING,
                    FullTreeFunctionObservationOperationPhase.LEASED,
                ),
                cold.leasedHistory.transitions.map { it.phase },
            )
            assertEquals(FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN, cold.observedPopulation)
            cold.requireCurrentReadOnly()
        }
        assertTrue(Files.notExists(context.output, LinkOption.NOFOLLOW_LINKS))
        listOf("parent.start", "worker.ready", "candidate.json").forEach { name ->
            assertTrue(Files.notExists(context.runRoot.resolve(name), LinkOption.NOFOLLOW_LINKS))
        }
    }

    private fun assertOnlyExactUnitObservationSystemctlCommands(
        commands: List<List<String>>,
        unitName: String,
    ) {
        assertTrue(commands.isNotEmpty(), "exact-unit systemctl observer was not exercised")
        assertTrue(
            commands.all { arguments ->
                    arguments.size == 3 &&
                    arguments[0] == "show" &&
                    arguments[1] == unitName &&
                    arguments[2] == EXACT_UNIT_SHOW_PROPERTIES
            },
            "pre-launch absence-only path issued a non-observation systemctl command: $commands",
        )
    }

    private fun assertFaultProtocolFile(path: Path, name: String, nonce: String) {
        assertTrue(
            Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS),
            "faulted BOOT protocol residue is not a regular file: $name",
        )
        val bytes = Files.newInputStream(path, LinkOption.NOFOLLOW_LINKS).use { input ->
            input.readNBytes(TEST_FAULT_PROTOCOL_BYTES + 1)
        }
        assertTrue(
            bytes.size <= TEST_FAULT_PROTOCOL_BYTES,
            "fault protocol residue exceeds its byte bound: $name",
        )
        val content = bytes.toString(Charsets.UTF_8)
        when (name) {
            "worker.boot" -> assertEquals("BOOT\t1\t$nonce\n", content)
            "worker.failure", "supervisor.failure" -> {
                assertTrue(
                    content.endsWith('\n') && content.count { it == '\n' } == 1,
                    "fault protocol residue is not one canonical line: $name",
                )
                val fields = content.removeSuffix("\n").split('\t')
                assertEquals(5, fields.size, "fault protocol residue has an invalid field count: $name")
                assertEquals("FAIL", fields[0])
                assertEquals("1", fields[1])
                assertEquals(nonce, fields[2])
                assertTrue(fields[3].isNotBlank(), "fault protocol class is empty: $name")
                assertTrue(fields[3].length <= TEST_FAILURE_CLASS_CHARS, "fault protocol class is too long: $name")
                assertTrue(fields[4].length <= TEST_FAILURE_MESSAGE_CHARS, "fault protocol message is too long: $name")
                assertTrue(
                    fields.drop(3).all { field -> field.none(Char::isISOControl) },
                    "fault protocol residue contains a control character: $name",
                )
            }

            else -> error("unexpected fault protocol residue: $name")
        }
    }

    private fun assertObservationUnitAndCgroupAbsent(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
    ) {
        assertTrue(
            testObservationUnitAndJobInventoriesEmpty(configuration, unitName),
            "test observation unit or job remains present",
        )
        assertTrue(
            findObservationCgroupsForUnit(unitName).isEmpty(),
            "test observation cgroup remains present",
        )
    }

    private fun testObservationUnitAndJobInventoriesEmpty(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
    ): Boolean {
        val units = runTestSystemctl(
            configuration,
            COLD_TEST_LIST_UNITS_COMMAND + listOf("--", unitName),
            setOf(0),
        )
        val jobs = runTestSystemctl(
            configuration,
            COLD_TEST_LIST_JOBS_COMMAND + listOf("--", unitName),
            setOf(0),
        )
        return units.isEmpty() && jobs.isEmpty()
    }

    private fun coldTestSystemdSweep(unitName: String): List<List<String>> = listOf(
        COLD_TEST_MANAGER_FEATURES_COMMAND,
        COLD_TEST_LIST_UNITS_COMMAND + listOf("--", unitName),
        COLD_TEST_LIST_JOBS_COMMAND + listOf("--", unitName),
        COLD_TEST_LIST_JOBS_COMMAND + listOf("--", unitName),
        COLD_TEST_LIST_UNITS_COMMAND + listOf("--", unitName),
        COLD_TEST_MANAGER_FEATURES_COMMAND,
    )

    private fun testObservationCgroupParentOrNull(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
    ): Path? {
        val managerControlGroup = runTestSystemctl(
            configuration,
            listOf("--no-pager", "--property=ControlGroup", "--value", "show"),
            setOf(0),
        ).trim()
        if (!managerControlGroup.startsWith('/') || managerControlGroup.contains("..")) return null
        val parent = TEST_CGROUP_ROOT.resolve(managerControlGroup.removePrefix("/"))
            .resolve("app.slice")
            .normalize()
        return parent.takeIf {
            it.startsWith(TEST_CGROUP_ROOT) &&
                Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) &&
                Files.isWritable(it)
        }
    }

    private data class TestObservationUnitSnapshot(
        val unitName: String,
        val controlGroup: String,
        val invocationId: String,
        val cgroupPath: Path,
    )

    private data class StartingTestObservationUnit(
        val invocationId: String?,
        val activeSnapshot: TestObservationUnitSnapshot?,
    )

    private class OccupiedObservationUnit(
        val process: Process,
        val processHandle: LinuxProcessDescriptor,
        val snapshot: TestObservationUnitSnapshot,
        val cgroup: LinuxDescriptor,
    ) : AutoCloseable {
        override fun close() {
            processHandle.close()
            cgroup.close()
        }
    }

    private fun startOccupiedObservationUnit(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
        sleep: Path,
    ): OccupiedObservationUnit {
        val started = ProcessBuilder(
            configuration.scopeSupervisorExecutable.toString(),
            "--user",
            "--scope",
            "--quiet",
            "--collect",
            "--unit=$unitName",
            "--property=KillMode=control-group",
            "--property=SendSIGKILL=yes",
            "--",
            sleep.toString(),
            "60",
        ).redirectInput(ProcessBuilder.Redirect.PIPE)
            .redirectOutput(ProcessBuilder.Redirect.DISCARD)
            .redirectError(ProcessBuilder.Redirect.DISCARD)
            .also { builder -> configureTestSystemdEnvironment(builder, configuration) }
            .start()
        val processHandle = try {
            LinuxFilesystemSyscalls.openProcessHandle(started.pid())
        } catch (failure: Throwable) {
            runCatching { started.destroyForcibly() }.exceptionOrNull()?.let(failure::addSuppressed)
            runCatching { started.waitFor(5, TimeUnit.SECONDS) }.exceptionOrNull()?.let(failure::addSuppressed)
            throw failure
        }
        var processHandleTransferred = false
        var observedInvocationId: String? = null
        try {
            started.outputStream.close()
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (System.nanoTime() < deadline) {
                check(started.isAlive) { "collision scope exited before systemd observed it" }
                val starting = readStartingTestObservationUnit(configuration, unitName)
                starting.invocationId?.let { invocationId ->
                    val retained = observedInvocationId
                    check(retained == null || retained == invocationId) {
                        "collision scope invocation changed during setup"
                    }
                    observedInvocationId = invocationId
                }
                val snapshot = starting.activeSnapshot
                if (snapshot != null) {
                    val cgroup = LinuxFilesystemSyscalls.openRoot(snapshot.cgroupPath)
                    try {
                        try {
                            val occupied = OccupiedObservationUnit(started, processHandle, snapshot, cgroup)
                            assertOccupiedObservationUnitUnchanged(configuration, occupied)
                            processHandleTransferred = true
                            return occupied
                        } catch (failure: Throwable) {
                            throw failure
                        }
                    } catch (failure: Throwable) {
                        cgroup.close()
                        throw failure
                    }
                }
                Thread.sleep(25)
            }
            error("collision scope did not become visible to systemd")
        } catch (failure: Throwable) {
            if (LinuxFilesystemSyscalls.processExists(processHandle)) {
                runCatching { LinuxFilesystemSyscalls.killProcess(processHandle) }
                    .exceptionOrNull()?.let(failure::addSuppressed)
            }
            if (started.isAlive) {
                runCatching { started.destroyForcibly() }.exceptionOrNull()?.let(failure::addSuppressed)
            }
            if (!started.waitFor(5, TimeUnit.SECONDS)) {
                failure.addSuppressed(IllegalStateException("collision scope process survived failed setup"))
            }
            fun awaitAbsence(): Boolean {
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
                while (System.nanoTime() < deadline) {
                    val absent = runCatching {
                        !started.isAlive &&
                            testObservationUnitAndJobInventoriesEmpty(configuration, unitName) &&
                            findObservationCgroupsForUnit(unitName).isEmpty()
                    }.getOrDefault(false)
                    if (absent) return true
                    Thread.sleep(25)
                }
                return false
            }
            var absent = awaitAbsence()
            if (!absent && observedInvocationId != null) {
                runCatching {
                    stopStartingObservationUnitIfOwned(
                        configuration,
                        unitName,
                        requireNotNull(observedInvocationId),
                    )
                }.exceptionOrNull()?.let(failure::addSuppressed)
                absent = awaitAbsence()
            }
            if (absent) throw failure
            failure.addSuppressed(IllegalStateException("failed collision setup retained unit residue"))
            throw failure
        } finally {
            if (!processHandleTransferred) processHandle.close()
        }
    }

    private fun stopOccupiedObservationUnit(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        occupied: OccupiedObservationUnit,
    ) {
        var retainedFailure: Throwable? = null
        fun retain(failure: Throwable) {
            val prior = retainedFailure
            if (prior == null) retainedFailure = failure else if (failure !== prior) prior.addSuppressed(failure)
        }
        try {
            if (occupied.process.isAlive) {
                runCatching { assertOccupiedObservationUnitUnchanged(configuration, occupied) }
                    .exceptionOrNull()?.let(::retain)
                runCatching { LinuxFilesystemSyscalls.killProcess(occupied.processHandle) }
                    .exceptionOrNull()?.let(::retain)
                if (occupied.process.isAlive) {
                    runCatching { occupied.process.destroyForcibly() }.exceptionOrNull()?.let(::retain)
                }
            }
            if (!occupied.process.waitFor(5, TimeUnit.SECONDS)) {
                retain(IllegalStateException("collision scope process survived exact pidfd cleanup"))
            }
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
            var absent = false
            while (System.nanoTime() < deadline) {
                val loaded = try {
                    requireOwnedObservationUnitLoadedOrAbsent(configuration, occupied.snapshot)
                } catch (failure: Throwable) {
                    retain(failure)
                    break
                }
                val cgroups = try {
                    findObservationCgroupsForUnit(occupied.snapshot.unitName)
                } catch (failure: Throwable) {
                    retain(failure)
                    break
                }
                absent = !loaded &&
                    cgroups.isEmpty() &&
                    Files.notExists(occupied.snapshot.cgroupPath, LinkOption.NOFOLLOW_LINKS) &&
                    !LinuxFilesystemSyscalls.processExists(occupied.processHandle)
                if (absent) break
                Thread.sleep(25)
            }
            if (!absent) retain(IllegalStateException("collision scope did not become absent after exact pidfd cleanup"))
        } finally {
            occupied.close()
        }
        retainedFailure?.let { throw it }
    }

    private fun assertOccupiedObservationUnitUnchanged(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        occupied: OccupiedObservationUnit,
    ) {
        assertTrue(occupied.process.isAlive, "collision scope process is no longer live")
        assertTrue(
            LinuxFilesystemSyscalls.processExists(occupied.processHandle),
            "collision scope pidfd no longer names a live process",
        )
        assertEquals(
            occupied.snapshot,
            readTestObservationUnitSnapshot(configuration, occupied.snapshot.unitName),
            "collision scope systemd identity or state changed",
        )
        LinuxFilesystemSyscalls.openRoot(occupied.snapshot.cgroupPath).use { current ->
            assertEquals(occupied.cgroup.identity, current.identity, "collision cgroup identity changed")
        }
        assertEquals(
            setOf(occupied.process.pid()),
            readTestCgroupProcesses(occupied.snapshot.cgroupPath),
            "collision scope process population changed",
        )
        assertEquals(
            "0",
            Files.readString(occupied.snapshot.cgroupPath.resolve("cgroup.freeze")).trim(),
            "collision scope was frozen",
        )
    }

    private fun readTestObservationUnitSnapshot(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
    ): TestObservationUnitSnapshot? = requireActiveTestObservationUnitSnapshot(
        readTestObservationUnitProperties(configuration, unitName),
        unitName,
    )

    private fun readStartingTestObservationUnit(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
    ): StartingTestObservationUnit {
        val properties = readTestObservationUnitProperties(configuration, unitName)
        if (properties["LoadState"] == "not-found") return StartingTestObservationUnit(null, null)
        check(properties["Id"] == unitName) { "test systemd observed a different unit identity" }
        check(properties["LoadState"] == "loaded") { "test collision scope is not loaded" }
        val invocationId = properties["InvocationID"].orEmpty().takeIf {
            it.matches(Regex("[0-9a-f]{32}"))
        }
        if (properties["ActiveState"] in setOf("inactive", "activating")) {
            return StartingTestObservationUnit(invocationId, null)
        }
        return StartingTestObservationUnit(
            invocationId,
            requireActiveTestObservationUnitSnapshot(properties, unitName),
        )
    }

    private fun stopStartingObservationUnitIfOwned(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
        invocationId: String,
    ) {
        val properties = readTestObservationUnitProperties(configuration, unitName)
        if (properties["LoadState"] == "not-found") return
        check(properties["Id"] == unitName && properties["InvocationID"] == invocationId) {
            "refusing to stop a replacement collision unit after failed setup"
        }
        runTestSystemctl(configuration, listOf("stop", unitName), setOf(0, 1, 4))
    }

    private fun requireActiveTestObservationUnitSnapshot(
        properties: Map<String, String>,
        unitName: String,
    ): TestObservationUnitSnapshot? {
        if (properties["LoadState"] == "not-found") return null
        check(properties["Id"] == unitName) { "test systemd observed a different unit identity" }
        check(properties["LoadState"] == "loaded") { "test collision scope is not loaded" }
        check(properties["ActiveState"] == "active") { "test collision scope is not active" }
        check(properties["SubState"] == "running") { "test collision scope is not running" }
        check(properties["FreezerState"] == "running") { "test collision scope is not thawed" }
        val controlGroup = properties["ControlGroup"].orEmpty()
        val cgroupPath = testCgroupPath(unitName, controlGroup)
        val invocationId = properties["InvocationID"].orEmpty()
        check(invocationId.matches(Regex("[0-9a-f]{32}"))) {
            "test collision scope has an invalid invocation identity"
        }
        return TestObservationUnitSnapshot(unitName, controlGroup, invocationId, cgroupPath)
    }

    private fun requireOwnedObservationUnitLoadedOrAbsent(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        expected: TestObservationUnitSnapshot,
    ): Boolean {
        if (testObservationUnitAndJobInventoriesEmpty(configuration, expected.unitName)) return false
        val properties = readTestObservationUnitProperties(configuration, expected.unitName)
        if (properties["LoadState"] == "not-found") return true
        check(properties["Id"] == expected.unitName) {
            "refusing to observe a replacement collision unit identity"
        }
        check(properties["InvocationID"] == expected.invocationId) {
            "refusing to observe a replacement collision invocation"
        }
        val controlGroup = properties["ControlGroup"].orEmpty()
        check(controlGroup.isEmpty() || controlGroup == expected.controlGroup) {
            "refusing to observe a replacement collision cgroup"
        }
        return true
    }

    private fun readTestObservationUnitProperties(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        unitName: String,
    ): Map<String, String> {
        val output = runTestSystemctl(
            configuration,
            listOf(
                "show",
                unitName,
                "--property=Id,LoadState,ActiveState,SubState,ControlGroup,InvocationID,FreezerState",
            ),
            setOf(0, 1, 4),
        )
        val properties = linkedMapOf<String, String>()
        output.lineSequence().filter(String::isNotBlank).forEach { line ->
            check('=' in line) { "test systemd returned a malformed unit property" }
            val name = line.substringBefore('=')
            check(properties.put(name, line.substringAfter('=')) == null) {
                "test systemd returned a duplicate unit property"
            }
        }
        return properties
    }

    private fun testCgroupPath(unitName: String, controlGroup: String): Path {
        check(controlGroup.startsWith('/') && '\u0000' !in controlGroup) {
            "test collision scope has an invalid control group"
        }
        val cgroupPath = TEST_CGROUP_ROOT.resolve(controlGroup.removePrefix("/")).normalize()
        check(
            cgroupPath.startsWith(TEST_CGROUP_ROOT) &&
                cgroupPath != TEST_CGROUP_ROOT &&
                cgroupPath.fileName?.toString() == unitName
        ) { "test collision scope escaped the cgroup root" }
        return cgroupPath
    }

    private fun readTestCgroupProcesses(cgroup: Path): Set<Long> {
        val processFile = cgroup.resolve("cgroup.procs")
        val bytes = Files.newInputStream(processFile).use { input ->
            input.readNBytes(TEST_CGROUP_PROCS_BYTES + 1)
        }
        check(bytes.size <= TEST_CGROUP_PROCS_BYTES) {
            "test collision cgroup process list exceeded its bound"
        }
        val values = bytes.toString(Charsets.UTF_8).lineSequence().filter(String::isNotBlank).map { line ->
            line.trim().toLongOrNull()?.takeIf { it in 1..Int.MAX_VALUE.toLong() }
                ?: error("test collision cgroup contained an invalid process id")
        }.toList()
        check(values.size == values.toSet().size) {
            "test collision cgroup contained a duplicate process id"
        }
        return values.toSet()
    }

    private fun closeAfterExternalUnitCleanup(ready: FullTreeFunctionObservationPreparedIsolation) {
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        var last: FullTreeFunctionObservationIsolationException? = null
        while (System.nanoTime() < deadline) {
            try {
                ready.close()
                return
            } catch (failure: FullTreeFunctionObservationIsolationException) {
                last = failure
                Thread.sleep(25)
            }
        }
        throw FullTreeFunctionObservationIsolationException(
            "prepared isolation did not accept externally proved collision cleanup",
            last,
        )
    }

    private fun runTestSystemctl(
        configuration: FullTreeFunctionObservationIsolationConfiguration,
        arguments: List<String>,
        allowedExitCodes: Set<Int>,
    ): String {
        val process = ProcessBuilder(
            listOf(configuration.scopeInspectorExecutable.toString(), "--user") + arguments,
        ).redirectErrorStream(true)
            .also { builder -> configureTestSystemdEnvironment(builder, configuration) }
            .start()
        if (!process.waitFor(5, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            process.waitFor(1, TimeUnit.SECONDS)
            error("test systemd command timed out")
        }
        val bytes = process.inputStream.readNBytes(TEST_SYSTEMD_OUTPUT_BYTES + 1)
        check(bytes.size <= TEST_SYSTEMD_OUTPUT_BYTES) { "test systemd output exceeded its bound" }
        check(process.exitValue() in allowedExitCodes) {
            "test systemd command failed with exit ${process.exitValue()}: ${bytes.toString(Charsets.UTF_8)}"
        }
        return bytes.toString(Charsets.UTF_8)
    }

    private fun configureTestSystemdEnvironment(
        builder: ProcessBuilder,
        configuration: FullTreeFunctionObservationIsolationConfiguration,
    ) {
        builder.environment().clear()
        builder.environment()["XDG_RUNTIME_DIR"] = configuration.systemdUserRuntimeDirectory.toString()
        builder.environment()["DBUS_SESSION_BUS_ADDRESS"] =
            "unix:path=${configuration.systemdUserRuntimeDirectory.resolve("bus")}"
    }

    private class SimulatedObservationLaunchFailure : RuntimeException()

    private class SimulatedObservationAfterProcessStartFailure : RuntimeException()

    private class SimulatedObservationCleanupFailure : RuntimeException()

    private class SimulatedObservationFinalAbsenceFailure : RuntimeException()

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
        val PREPARED_RUN_DIRECTORIES = setOf("runtime", "scratch", "tmp")
        val LIVE_FAULT_PROTOCOL_FILES = setOf("worker.boot", "worker.failure", "supervisor.failure")
        val COLD_TEST_MANAGER_FEATURES_COMMAND = listOf(
            "--no-pager",
            "--property=Features",
            "--value",
            "show",
        )
        val COLD_TEST_LIST_UNITS_COMMAND = listOf(
            "--no-pager",
            "--no-legend",
            "--plain",
            "--full",
            "--all",
            "list-units",
        )
        val COLD_TEST_LIST_JOBS_COMMAND = listOf(
            "--no-pager",
            "--no-legend",
            "--plain",
            "--full",
            "--all",
            "list-jobs",
        )
        const val EXACT_UNIT_SHOW_PROPERTIES =
            "--property=Id,LoadState,ActiveState,SubState,CollectMode,ControlGroup,TasksMax," +
                "MemoryMax,MemorySwapMax,OOMPolicy,CPUQuotaPerSecUSec,KillMode,SendSIGKILL," +
                "RuntimeMaxUSec,TimeoutStopUSec,Delegate"
        const val TEST_SYSTEMD_OUTPUT_BYTES = 64 * 1024
        const val TEST_CGROUP_PROCS_BYTES = 64 * 1024
        const val TEST_IMMUTABLE_TREE_FILE_BYTES = 1024 * 1024
        const val TEST_SYMBOLIC_LINK_CHARS = 8192
        const val TEST_FAULT_PROTOCOL_BYTES = 8 * 1024
        const val TEST_FAILURE_CLASS_CHARS = 256
        const val TEST_FAILURE_MESSAGE_CHARS = 1024
        val TEST_CGROUP_ROOT = Path.of("/sys/fs/cgroup")
        const val ZERO_SHA256 =
            "0000000000000000000000000000000000000000000000000000000000000000"
        const val FROZEN_ISOLATION_CONFIGURATION_SHA256 =
            "996c3815ddd9f6330fbf9f404353a2f28fa81ba47d58a3eff4ff57e83cd71e95"
        const val TEST_LEASE_RECORD_FILE = "lease.json"
    }
}
