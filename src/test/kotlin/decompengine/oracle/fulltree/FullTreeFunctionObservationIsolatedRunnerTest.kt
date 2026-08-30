package decompengine.oracle.fulltree

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
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class FullTreeFunctionObservationIsolatedFixtureRunnerTest {
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

    private fun availableConfiguration(runtimeParent: Path): FullTreeFunctionObservationIsolationConfiguration? {
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val runtime = Path.of("/run/user/$uid")
        val java = Path.of(System.getProperty("java.home"), "bin", "java").realExecutableOrNull() ?: return null
        val javaRuntime = Path.of(System.getProperty("java.home")).toRealPath()
        val bubblewrap = Path.of("/usr/bin/bwrap").realExecutableOrNull() ?: return null
        val prlimit = Path.of("/usr/bin/prlimit").realExecutableOrNull() ?: return null
        val systemdRun = Path.of("/usr/bin/systemd-run").realExecutableOrNull() ?: return null
        val systemctl = Path.of("/usr/bin/systemctl").realExecutableOrNull() ?: return null
        if (!Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS) || !Files.exists(runtime.resolve("bus"))) return null
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
            expectedBubblewrapSha256 = sha256(bubblewrap),
            expectedResourceLimiterSha256 = sha256(prlimit),
            expectedScopeSupervisorSha256 = sha256(systemdRun),
            expectedScopeInspectorSha256 = sha256(systemctl),
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
    }
}
