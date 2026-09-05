package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.analysis.BundledGhidra
import decompengine.oracle.fulltree.FullTreeDiskMount
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue

class GccBundledGhidraRetainedRuntimeTest {
    @Test
    fun `live deployment closure separates BOOT bundle reference and retained runtime identities`() {
        val boot = "a".repeat(64)
        val reference = "b".repeat(64)
        val runtime = "c".repeat(64)
        val expected = "2e724bc55ff0a816d212df91206f15a7f1932b977eb595b2fe7fb88e8bb84c4c"
        assertEquals(expected, gccBundledLiveDeploymentClosureSha256(boot, reference, runtime))
        assertNotEquals(expected, gccBundledLiveDeploymentClosureSha256(reference, boot, runtime))
        assertNotEquals(expected, gccBundledLiveDeploymentClosureSha256(boot, runtime, reference))
        assertNotEquals(expected, gccBundledLiveDeploymentClosureSha256("d".repeat(64), reference, runtime))
        assertNotEquals(expected, gccBundledLiveDeploymentClosureSha256(boot, "d".repeat(64), runtime))
        assertNotEquals(expected, gccBundledLiveDeploymentClosureSha256(boot, reference, "d".repeat(64)))
        for (invalid in listOf("", "a".repeat(63), "A".repeat(64), "g".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { gccBundledLiveDeploymentClosureSha256(invalid, reference, runtime) }
            assertFailsWith<IllegalArgumentException> { gccBundledLiveDeploymentClosureSha256(boot, invalid, runtime) }
            assertFailsWith<IllegalArgumentException> { gccBundledLiveDeploymentClosureSha256(boot, reference, invalid) }
        }
    }

    @Test
    fun `entry policy admits exact root-owned file and directory identities on the retained mount`() {
        val file = GccBundledGhidraReferenceEntry("library.jar", "file", 420, 1, SHA_A)
        val directory = GccBundledGhidraReferenceEntry("library", "directory", 493, null, null)
        requireGccBundledRuntimeEntry(fileIdentity(), file, MOUNT_ID)
        requireGccBundledRuntimeEntry(fileIdentity(mode = 493), file.copy(mode = 493), MOUNT_ID)
        requireGccBundledRuntimeEntry(directoryIdentity(), directory, MOUNT_ID)
    }

    @Test
    fun `entry policy rejects owner permission hardlink mount and inode type substitutions`() {
        val file = GccBundledGhidraReferenceEntry("library.jar", "file", 420, 1, SHA_A)
        val valid = fileIdentity()
        val invalid = listOf(
            valid.copy(uid = 1000), valid.copy(mode = 0x8000 + 438), valid.copy(mode = 0x8000 + 493),
            valid.copy(mode = valid.mode or 0x800), valid.copy(linkCount = 2), valid.copy(linkCount = 0),
            valid.copy(mountId = MOUNT_ID + 1), valid.copy(isSymbolicLink = true),
            valid.copy(isRegularFile = false), directoryIdentity(),
        )
        for (identity in invalid) {
            assertFailsWith<IllegalArgumentException>(identity.toString()) { requireGccBundledRuntimeEntry(identity, file, MOUNT_ID) }
        }
        val directory = GccBundledGhidraReferenceEntry("library", "directory", 493, null, null)
        val invalidDirectories = listOf(
            directoryIdentity().copy(uid = 1000), directoryIdentity().copy(mode = 0x4000 + 511),
            directoryIdentity().copy(mode = 0x4000 + 448), directoryIdentity().copy(isSymbolicLink = true),
            directoryIdentity().copy(mountId = MOUNT_ID + 1), directoryIdentity().copy(isDirectory = false),
            fileIdentity(),
        )
        for (identity in invalidDirectories) {
            assertFailsWith<IllegalArgumentException>(identity.toString()) { requireGccBundledRuntimeEntry(identity, directory, MOUNT_ID) }
        }
    }

    @Test
    fun `mount policy binds the unique descriptor mount without accepting noexec or nested mounts`() {
        val root = Path.of("/opt/decomp-bundle")
        val selected = mount()
        assertEquals(selected, requireGccBundledRuntimeMount(root, directoryIdentity(), listOf(selected)))
        val unrelated = selected.copy(mountId = MOUNT_ID + 1, mountPoint = Path.of("/opt/decomp-bundle-other"))
        assertEquals(selected, requireGccBundledRuntimeMount(root, directoryIdentity(), listOf(selected, unrelated)))
        val invalid = listOf(
            emptyList(), listOf(selected, selected), listOf(selected.copy(mountId = MOUNT_ID + 1)),
            listOf(selected.copy(mountPoint = Path.of("/unrelated"))),
            listOf(selected.copy(options = selected.options + "noexec")),
            listOf(selected, selected.copy(mountId = MOUNT_ID + 1, mountPoint = root.resolve("nested"))),
            listOf(selected, selected.copy(mountId = MOUNT_ID + 1, mountPoint = root)),
        )
        for (mounts in invalid) {
            assertFailsWith<IllegalArgumentException>(mounts.toString()) { requireGccBundledRuntimeMount(root, directoryIdentity(), mounts) }
        }
    }

    @Test
    fun `structurally valid v2 definitions with substituted deployment descriptions cannot retain a runtime`() {
        val reference = deploymentReference()
        val root = Path.of("/unavailable-runtime-must-not-be-opened")
        val runtime = runtime(reference, root)
        val wrongClassPath = GccBundledGhidraRuntime(root, runtime.classPath.mapIndexed { index, entry ->
            if (index == 1) entry.copy(sha256 = differentDigest(entry.sha256)) else entry
        })
        val variants = listOf(
            definition(reference, wrongClassPath),
            definition(reference, runtime, artifacts(reference, runtime).map {
                if (it.role == GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD) it.copy(bytes = it.bytes + 1) else it
            }),
        )
        for (candidate in variants) {
            val failure = assertFailsWith<IllegalArgumentException> { GccBundledGhidraRetainedRuntime.open(candidate).close() }
            assertTrue(failure.message.orEmpty().contains("independent deployment reference"))
        }
    }

    @Test
    fun `writable temporary or linked roots never acquire retained runtime authority or alter caller files`() {
        val reference = deploymentReference()
        val temporary = Files.createTempDirectory("gcc-untrusted-bundled-runtime-")
        val marker = temporary.resolve("caller-owned-marker")
        val link = temporary.resolve("bundle-link")
        try {
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("rwx------"))
            Files.writeString(marker, "must remain unchanged")
            val target = GccBundledGhidraDeploymentReference.open().use { it.bundleRoot }
            Files.createSymbolicLink(link, target)
            for (root in listOf(temporary, link)) {
                assertFailsWith<IllegalArgumentException> {
                    GccBundledGhidraRetainedRuntime.open(definition(reference, runtime(reference, root))).close()
                }
            }
            assertEquals("must remain unchanged", Files.readString(marker))
            assertEquals(target, Files.readSymbolicLink(link))
            assertEquals(listOf("bundle-link", "caller-owned-marker"), Files.list(temporary).use { paths ->
                paths.map { it.fileName.toString() }.sorted().toList()
            })
        } finally {
            Files.deleteIfExists(link)
            Files.deleteIfExists(marker)
            Files.delete(temporary)
        }
    }

    @Test
    fun `provisioned root-owned bundled tree remains exact through retained revalidation and close`() {
        val root = provisionedRoot()
        val reference = deploymentReference()
        val runtime = runtime(reference, root)
        val expectedClassPath = runtime.classPath.toList()
        val expectedRootKey = Files.readAttributes(root, "unix:dev,ino,uid,mode", LinkOption.NOFOLLOW_LINKS)
        val candidate = definition(reference, runtime)
        val retained = GccBundledGhidraRetainedRuntime.open(candidate)
        try {
            assertEquals(reference.closureSha256, retained.deploymentClosureSha256)
            assertTrue(retained.runtimeIdentitySha256.matches(Regex("[a-f0-9]{64}")))
            val identity = retained.runtimeIdentitySha256
            assertEquals(root, retained.root)
            retained.verify("first read-only test revalidation")
            retained.verify("second read-only test revalidation")
            assertEquals(identity, retained.runtimeIdentitySha256)
            assertEquals(expectedClassPath, assertNotNull(candidate.bundledRuntime).classPath)
            assertEquals(expectedRootKey, Files.readAttributes(root, "unix:dev,ino,uid,mode", LinkOption.NOFOLLOW_LINKS))
        } finally {
            retained.close()
        }
        retained.close()
        assertFailsWith<IllegalStateException> { retained.verify("after close") }
    }

    private fun provisionedRoot(): Path {
        val configured = System.getenv("DECOMP_TEST_BUNDLED_GHIDRA_ROOT")?.takeIf(String::isNotBlank)
        if (System.getenv("DECOMP_REQUIRE_BUNDLED_GHIDRA_RUNTIME") == "true") {
            assertNotNull(configured, "required CI root-owned bundled runtime was not provisioned")
        }
        assumeTrue(configured != null, "a root-owned bundled runtime is not provisioned")
        val root = Path.of(checkNotNull(configured))
        assertTrue(root.isAbsolute && root.normalize() == root && root.toRealPath() == root)
        assertTrue(Files.isDirectory(root, LinkOption.NOFOLLOW_LINKS))
        return root
    }

    private fun deploymentReference(): GccBundledGhidraReference = GccBundledGhidraDeploymentReference.open().use { it.reference }

    private fun runtime(reference: GccBundledGhidraReference, root: Path): GccBundledGhidraRuntime = GccBundledGhidraRuntime(
        root, reference.classPath.map { path ->
            val entry = reference.entries.getValue(path)
            GccBundledGhidraClassPathEntry(root.resolve(path), assertNotNull(entry.bytes), assertNotNull(entry.sha256))
        },
    )

    private fun definition(
        reference: GccBundledGhidraReference,
        runtime: GccBundledGhidraRuntime,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity> = artifacts(reference, runtime),
    ): GccCompilerEngineValidatedContainmentDefinition {
        val state = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, Path.of("/scratch/retained-runtime/state"), null, 0, 0,
        )
        val lease = GccCompilerEngineOutputLeaseIdentity(
            Path.of("/scratch/retained-runtime"), 1, 2, 3, 1000, 1000, 448, 1024, 2048, 128, 256,
        )
        val request = GccCompilerEngineContainmentRequest(
            engineId = "cc1",
            runKind = GccCompilerEngineContainmentRunKind.INTERRUPTED,
            artifacts = artifacts,
            analysisState = state,
            command = runtime.command(artifacts, state, lease),
            environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
            outputLease = lease,
            budgets = GccCompilerEngineContainmentBudgets(1_800_000, 16L * 1024 * 1024 * 1024, 256),
            bundledRuntime = runtime,
        )
        return GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
            GccCompilerEngineContainmentContract.assessDefinition(request).canonicalBytes,
        )
    }

    private fun artifacts(
        reference: GccBundledGhidraReference,
        runtime: GccBundledGhidraRuntime,
    ): List<GccCompilerEngineContainmentArtifactIdentity> = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.mapIndexed { index, role ->
        val relative = when (role) {
            GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> "decomp-ghidra-bridge.jar"
            GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> "scripts/RunBundledExports.class"
            GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> "bundle.sha256"
            else -> null
        }
        val entry = relative?.let(reference.entries::getValue)
        GccCompilerEngineContainmentArtifactIdentity(
            role,
            when {
                relative != null -> runtime.root.resolve(relative)
                role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/trusted/scripts/ExportProgramModel.java")
                else -> Path.of("/trusted/${role.wireName}")
            },
            when {
                entry != null -> assertNotNull(entry.bytes)
                role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> reference.exporterBytes
                role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> 569_445_154L
                else -> index + 1L
            },
            when {
                entry != null -> assertNotNull(entry.sha256)
                role == GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> reference.exporterSha256
                role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> BundledGhidra.ARCHIVE_SHA256
                else -> (index + 1).toString(16).padStart(2, '0').repeat(32)
            },
        )
    }

    private fun fileIdentity(mode: Int = 420) = LinuxFileIdentity(
        LinuxFileKey(1, 2), 0x8000 + mode, 0, 0, 1, MOUNT_ID, isRegularFile = true, isDirectory = false, isSymbolicLink = false,
    )

    private fun directoryIdentity() = LinuxFileIdentity(
        LinuxFileKey(1, 2), 0x4000 + 493, 0, 0, 2, MOUNT_ID, isRegularFile = false, isDirectory = true, isSymbolicLink = false,
    )

    private fun mount() = FullTreeDiskMount(
        MOUNT_ID, 1, "8:1", Path.of("/"), Path.of("/opt"), listOf("rw", "relatime"), "ext4",
    )

    private fun differentDigest(digest: String): String = if (digest == SHA_A) "b".repeat(64) else SHA_A

    private companion object {
        const val MOUNT_ID = 42L
        const val SHA_A = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    }
}
