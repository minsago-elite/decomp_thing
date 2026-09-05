package decompengine.acp

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class CandidateValidationMountPolicyTest {
    private val output = Path.of("/work/output")
    private fun ordinaryLayout(): List<AcpCandidateMountAccess> = listOf(
        AcpCandidateMountAccess(Path.of("/"), "tmpfs", setOf("ro")),
        AcpCandidateMountAccess(Path.of("/tmp"), "tmpfs", setOf("ro")),
        AcpCandidateMountAccess(Path.of("/dev"), "tmpfs", setOf("ro")),
        AcpCandidateMountAccess(Path.of("/dev/pts"), "devpts", setOf("ro")),
        AcpCandidateMountAccess(Path.of("/proc"), "proc", setOf("ro")),
        AcpCandidateMountAccess(output, "tmpfs", setOf("rw")),
    )

    @Test
    fun `ordinary immutable namespace accepts its one declared writable tmpfs`() {
        requireCandidateFilesystemLayout(ordinaryLayout(), setOf(output)) { error("no device lookup expected") }
    }

    @Test
    fun `private temporary filesystem must be read only`() {
        val records = ordinaryLayout().map { if (it.path == Path.of("/tmp")) it.copy(options = setOf("rw")) else it }
        assertFailsWith<IOException> { requireCandidateFilesystemLayout(records, setOf(output)) { null } }
    }

    @Test
    fun `ordinary extra writable directory does not inherit quota authority`() {
        val records = ordinaryLayout() + AcpCandidateMountAccess(Path.of("/cache"), "tmpfs", setOf("rw"))
        assertFailsWith<IOException> { requireCandidateFilesystemLayout(records, setOf(output)) { null } }
    }

    @Test
    fun `declared output must exist once with writable tmpfs semantics`() {
        assertFailsWith<IOException> { requireCandidateFilesystemLayout(ordinaryLayout().filter { it.path != output }, setOf(output)) { null } }
        assertFailsWith<IllegalArgumentException> {
            requireCandidateFilesystemLayout(ordinaryLayout() + ordinaryLayout().last(), setOf(output)) { null }
        }
        assertFailsWith<IOException> {
            requireCandidateFilesystemLayout(ordinaryLayout().map {
                if (it.path == output) it.copy(fileSystemType = "ext4") else it
            }, setOf(output)) { null }
        }
    }

    @Test
    fun `standard character device exception checks its real identity`() {
        val records = ordinaryLayout() + AcpCandidateMountAccess(Path.of("/dev/null"), "tmpfs", setOf("rw"))
        requireCandidateFilesystemLayout(records, setOf(output)) { 1L to 3L }
        assertFailsWith<IOException> { requireCandidateFilesystemLayout(records, setOf(output)) { null } }
        assertFailsWith<IOException> { requireCandidateFilesystemLayout(records, setOf(output)) { 1L to 5L } }
    }

    @Test
    fun `real candidate boundary writes ordinary quota output and records final sealed mount proof`() {
        // This is boundary qualification only. It does not provision or promote a production
        // generated-C provider, and never adopts the test mount through the public repair factory.
        val mount = System.getenv("DECOMP_TEST_ACP_QUOTA_TMPFS")
        AcpLiveContractHost.requireCapability(!mount.isNullOrBlank(), { "candidate boundary test needs the explicit finite test tmpfs" })
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val runtime = Path.of("/run/user/$uid")
        val paths = listOf("/usr/bin/bwrap", "/usr/bin/prlimit", "/usr/bin/systemd-run", "/usr/bin/systemctl", "/usr/bin/bash", "/usr/bin/cc").map(Path::of)
        AcpLiveContractHost.requireCapability(paths.all(Files::isExecutable) && Files.exists(runtime.resolve("bus")),
            { "candidate boundary requires the provisioned Linux sandbox host" })
        val helper = productionAcpGateHelper()
        val fixture = Files.createTempDirectory("candidate-boundary-fixture-")
        Files.setPosixFilePermissions(fixture, PosixFilePermissions.fromString("rwx------"))
        var stage: AcpWorkflowStagingRoot? = null
        try {
            val source = fixture.resolve("ordinary.c")
            Files.writeString(source, """
                #include <stdio.h>
                int main(int argc, char **argv) {
                    if (argc != 2) return 2;
                    FILE *out = fopen(argv[1], "wb");
                    if (!out) return 3;
                    if (fputs("ordinary contained output\n", out) < 0 || fclose(out)) return 4;
                    puts("candidate boundary ready");
                    return 0;
                }
            """.trimIndent())
            val probe = fixture.resolve("ordinary")
            val compileLog = fixture.resolve("compile.log")
            val compiler = ProcessBuilder("/usr/bin/cc", "-static", "-O0", "-o", probe.toString(), source.toString())
                .redirectErrorStream(true).redirectOutput(compileLog.toFile()).start()
            try { assertTrue(compiler.waitFor(20, TimeUnit.SECONDS)); assertEquals(0, compiler.exitValue()) }
            finally { if (compiler.isAlive) compiler.destroyForcibly().waitFor(5, TimeUnit.SECONDS) }
            Files.setPosixFilePermissions(probe, PosixFilePermissions.fromString("r-x------"))
            stage = AcpWorkflowStagingRoot.createQuotaBacked("candidate-test", Path.of(requireNotNull(mount)),
                AcpStagingQuotaLimits(64L * 1024 * 1024, 4096))
            val mounted = requireNotNull(stage)
            val config = AcpLinuxSandboxConfiguration(paths[0], paths[1], paths[2], paths[3], paths[4], helper,
                emptyList(), emptyList(), runtime, expectedBubblewrapSha256 = hash(paths[0]),
                expectedResourceLimiterSha256 = hash(paths[1]), expectedScopeSupervisorSha256 = hash(paths[2]),
                expectedScopeInspectorSha256 = hash(paths[3]), expectedEnvironmentFdOpenerSha256 = hash(paths[4]),
                expectedSandboxGateHelperSha256 = hash(helper), expectedSandboxGateHelperManifestSha256 = calculateAcpRuntimeManifestSha256(helper))
            LinuxBubblewrapBoundary.prepare(config).use { boundary ->
                val destination = Path.of("/candidate-boundary-probe")
                val outputFile = mounted.path.resolve("ordinary.txt")
                val launch = AcpSandboxLaunch(listOf(destination.toString(), outputFile.toString()), emptyMap(), mounted.path,
                    AcpSandboxResourceLimits(), Duration.ofSeconds(10),
                    listOf(AcpSandboxReadOnlyMount(probe, destination, calculateAcpRuntimeManifestSha256(probe))),
                    listOf(AcpSandboxRootGrant(mounted, AcpSandboxRootMode.READ_WRITE)), AcpSandboxLaunchPurpose.CANDIDATE_VALIDATION)
                val process = boundary.launch(launch, mergeError = false) {}
                process.process.outputStream.close()
                assertTrue(process.process.waitFor(10, TimeUnit.SECONDS))
                assertEquals(0, process.process.exitValue(), process.process.errorStream.readNBytes(4096).toString(Charsets.UTF_8))
                process.awaitCleanup(Duration.ofSeconds(5))
                assertTrue(process.cleanupSucceeded())
                assertEquals("ordinary contained output\n", Files.readString(outputFile))
                val evidence = boundary.evidence(null)
                val closure = assertNotNull(evidence.launches.single().writableMountClosureSha256)
                assertTrue(closure.matches(Regex("[0-9a-f]{64}")))
                assertTrue(canonicalAcpSandboxEvidenceFields(evidence).contains("launch[0].writableMountClosure" to closure))
            }
        } finally {
            stage?.path?.let { root -> Files.walk(root).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
            Files.walk(fixture).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun hash(path: Path): String = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(path))
        .joinToString("") { "%02x".format(it) }
}
