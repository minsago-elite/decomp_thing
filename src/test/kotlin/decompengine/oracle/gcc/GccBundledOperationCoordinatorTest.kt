package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskScratchAuthority
import decompengine.oracle.fulltree.FullTreeDiskScratchColdPopulation
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.FullTreeDiskScratchException
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.opentest4j.TestAbortedException

class GccBundledOperationCoordinatorTest {
    @Test
    fun `overlapping journal and scratch roots are rejected without filesystem mutation`() = withFixture { fixture ->
        val journal = privateDirectory(fixture.resolve("journal"))
        val scratch = privateDirectory(journal.resolve("scratch"))
        assertFailsWith<IllegalArgumentException> { GccBundledOperationCoordinator.prepareNew(intent(), journal, scratch).close() }
        assertEquals(listOf("scratch"), names(journal))
        assertTrue(names(scratch).isEmpty())
    }

    @Test
    fun `linked runtime input is rejected before journal or ordinary scratch mutation`() = withFixture { fixture ->
        val sourceRoot = GccBundledGhidraDeploymentReference.open().use { it.bundleRoot }
        val linkedRoot = fixture.resolve("linked-bundle")
        Files.createSymbolicLink(linkedRoot, sourceRoot)
        val source = preparedIntentInputs(fixture, sourceRoot, requireLiveExecutables = false)
        val linkedRuntime = GccBundledGhidraRuntime(linkedRoot, source.bundledRuntime.classPath.map {
            it.copy(path = linkedRoot.resolve(sourceRoot.relativize(it.path)))
        })
        val linkedArtifacts = source.artifacts.map {
            if (it.path.startsWith(sourceRoot)) it.copy(path = linkedRoot.resolve(sourceRoot.relativize(it.path))) else it
        }
        val linked = intent(artifacts = linkedArtifacts, runtime = linkedRuntime)
        val journal = privateDirectory(fixture.resolve("journal"))
        val scratch = privateDirectory(fixture.resolve("scratch"))
        assertFailsWith<IllegalArgumentException> { GccBundledOperationCoordinator.prepareNew(linked, journal, scratch).close() }
        assertTrue(names(journal).isEmpty())
        assertTrue(names(scratch).isEmpty())
        assertEquals(sourceRoot, Files.readSymbolicLink(linkedRoot))
    }

    @Test
    fun `ordinary scratch denial retains only durable intent evidence and never claims a lease`() {
        withRequiredProvisioning {
            val bundledRoot = provisionedBundle()
            withFixture { fixture ->
                val intent = preparedIntentInputs(fixture, bundledRoot)
                val journal = privateDirectory(fixture.resolve("journal"))
                val scratch = privateDirectory(fixture.resolve("ordinary-scratch"))
                assertFailsWith<FullTreeDiskScratchException> { GccBundledOperationCoordinator.prepareNew(intent, journal, scratch).close() }
                assertTrue(names(scratch).isEmpty())
                val operationJournal = journal.resolve(".gcc-bundled-operation-${intent.operationId}")
                assertEquals(listOf(operationJournal.fileName.toString()), names(journal))
                assertEquals(listOf("intent.json"), names(operationJournal))
                assertContentEquals(intent.canonicalBytes, Files.readAllBytes(operationJournal.resolve("intent.json")))
            }
        }
    }

    @Test
    fun `provisioned preparation binds a genuine dedicated lease and close preserves recoverable residue`() {
        withRequiredProvisioning {
            val bundledRoot = provisionedBundle()
            val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_SCRATCH")?.takeIf(String::isNotBlank)
            assumeTrue(configured != null, "a dedicated ext4 scratch slot is not provisioned")
            val mount = Path.of(checkNotNull(configured)).toAbsolutePath().normalize()
            assertEquals(mount, mount.toRealPath())
            assertTrue(names(mount).isEmpty(), "dedicated scratch requires recovery before the test")
            withFixture { fixture ->
                val intent = preparedIntentInputs(fixture, bundledRoot)
                val journal = privateDirectory(fixture.resolve("journal"))
                var prepared: GccBundledPreparedOperation? = null
                var reset: AbandonedReset? = null
                try {
                    val owner = GccBundledOperationCoordinator.prepareNew(intent, journal, mount)
                    prepared = owner
                    assertEquals("gcc-bundled-live-prepared-operation-v1", owner.authority)
                    assertFalse(owner.complete)
                    assertFalse(owner.startAuthorized)
                    assertFalse(owner.releaseEligible)
                    val definitionBytes = owner.definitionBytes
                    val preparedBytes = owner.preparedReceiptBytes
                    val diskBytes = owner.diskEvidenceBytes
                    val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definitionBytes)
                    val disk = FullTreeDiskScratchEvidence.parseCanonical(diskBytes)
                    val output = definition.outputLease.path
                    val controlName = requireNotNull(intent.bundledRuntime.freshControlDirectoryName(output))
                    assertEquals("-Duser.home=${output.resolve(controlName).resolve("tmp")}", definition.command[1])
                    assertEquals("-Djava.io.tmpdir=${output.resolve(controlName).resolve("tmp")}", definition.command[2])
                    assertFalse(Files.exists(output.resolve(controlName)))
                    val leaseRoot = output.parent
                    assertEquals(mount, leaseRoot.parent)
                    assertEquals(".decomp-oracle-lease-${intent.operationId}", leaseRoot.fileName.toString())
                    assertEquals(".function-observation-run-${intent.operationId}", output.fileName.toString())
                    assertEquals(intent.operationId, disk.operationId)
                    assertEquals(intent.requestSha256, disk.requestSha256)
                    assertEquals(intent.engineId, disk.shardId)
                    assertEquals(intent.workScopeSha256, disk.scopeSha256)
                    assertEquals("ext4", disk.filesystemType)
                    assertTrue(disk.mountFlags.containsAll(listOf("rw", "nodev", "nosuid", "noexec", "noatime")))
                    assertEquals(disk.mountId, definition.outputLease.mountId)
                    assertEquals(intent.diskPolicy.maximumFilesystemBytes, definition.outputLease.maximumFilesystemBytes)
                    assertEquals(intent.diskPolicy.maximumFilesystemInodes, definition.outputLease.maximumFilesystemInodes)
                    assertEquals(output.resolve("state"), definition.analysisState.path)
                    assertEquals(listOf("reports", "state", "tmp"), names(output))
                    val childIdentities = names(output).associateWith { name ->
                        LinuxFilesystemSyscalls.openRoot(output.resolve(name)).use { child ->
                            assertTrue(names(output.resolve(name)).isEmpty())
                            assertEquals(448, child.identity.mode and 0xfff)
                            assertEquals(disk.mountId, child.identity.mountId)
                            child.identity
                        }
                    }
                    val leaseRecord = Files.readAllBytes(leaseRoot.resolve("lease.json"))
                    assertEquals(disk.leaseRecordSha256, OracleArtifacts.sha256(leaseRecord))
                    reset = AbandonedReset(intent, disk, definition, leaseRecord, childIdentities)
                    val operationJournal = journal.resolve(".gcc-bundled-operation-${intent.operationId}")
                    val expectedJournal = mapOf(
                        "intent.json" to intent.canonicalBytes, "lease-evidence.json" to diskBytes,
                        "definition.json" to definitionBytes, "prepared.json" to preparedBytes,
                    )
                    assertEquals(expectedJournal.keys.sorted(), names(operationJournal))
                    for ((name, bytes) in expectedJournal) assertContentEquals(bytes, Files.readAllBytes(operationJournal.resolve(name)))
                    val receipt = OracleJson.parseCanonical(preparedBytes).jsonObject
                    assertEquals("gcc-bundled-prepared-operation-v1", receipt.getValue("provider").jsonPrimitive.content)
                    assertEquals(intent.requestSha256, receipt.getValue("intentSha256").jsonPrimitive.content)
                    assertEquals(disk.evidenceSha256, receipt.getValue("diskEvidenceSha256").jsonPrimitive.content)
                    assertEquals(OracleArtifacts.sha256(definitionBytes), receipt.getValue("definitionSha256").jsonPrimitive.content)
                    assertEquals(definition.bindingSha256, receipt.getValue("definitionBindingSha256").jsonPrimitive.content)
                    assertEquals(
                        OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(receipt - "preparedSha256"))),
                        receipt.getValue("preparedSha256").jsonPrimitive.content,
                    )
                    assertTrue(receipt.getValue("deploymentClosureSha256").jsonPrimitive.content.matches(Regex("[a-f0-9]{64}")))
                    owner.definitionBytes[0] = '!'.code.toByte()
                    owner.preparedReceiptBytes[0] = '!'.code.toByte()
                    owner.diskEvidenceBytes[0] = '!'.code.toByte()
                    assertContentEquals(definitionBytes, owner.definitionBytes)
                    assertContentEquals(preparedBytes, owner.preparedReceiptBytes)
                    assertContentEquals(diskBytes, owner.diskEvidenceBytes)
                    owner.requireCurrent()
                    assertFailsWith<IllegalStateException> { owner.requireInterruptedStateCurrent() }
                    assertFailsWith<IllegalStateException> { owner.resume() }
                    owner.requireCurrent()
                    assertFailsWith<FullTreeDiskScratchException> {
                        FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(
                            mount, intent.diskOperation().copy(operationId = "2".repeat(64)), intent.diskPolicy,
                        ).close()
                    }
                    owner.close()
                    owner.close()
                    prepared = null
                    assertFailsWith<IllegalStateException> { owner.requireCurrent() }
                    assertContentEquals(leaseRecord, Files.readAllBytes(leaseRoot.resolve("lease.json")))
                    assertEquals(listOf("reports", "state", "tmp"), names(output))
                    for ((name, bytes) in expectedJournal) assertContentEquals(bytes, Files.readAllBytes(operationJournal.resolve(name)))
                    FullTreeDiskScratchAuthority.openExistingReadOnly(mount, intent.diskOperation(), intent.diskPolicy).use { cold ->
                        assertEquals(FullTreeDiskScratchColdPopulation.ACTIVE_OPERATION_RUN, cold.requireCurrent(disk).population)
                    }
                    assertTrue(GccBundledPreparedOperation::class.java.methods.none {
                        it.name.lowercase() in setOf("start", "launch", "release", "requirecleanandrelease", "publish")
                    })
                } finally {
                    prepared?.close()
                    reset?.let { resetAbandonedFixture(mount, it) }
                }
            }
            assertTrue(names(mount).isEmpty())
        }
    }

    @Test
    fun `intent snapshots exact input identities without depending on output allocation or inode state`() {
        val artifacts = artifacts().toMutableList()
        val intent = intent(artifacts = artifacts)
        val captured = intent.canonicalBytes
        artifacts.clear()
        val modified = intent.canonicalBytes
        modified[0] = '!'.code.toByte()
        assertContentEquals(captured, intent.canonicalBytes)
        assertEquals(OracleArtifacts.sha256(captured), intent.requestSha256)
        val document = OracleJson.parseCanonical(captured).jsonObject
        assertEquals(
            setOf("schemaVersion", "provider", "operationId", "engineId", "runKind", "artifacts", "bundledRuntime", "budgets", "diskPolicy", "environment", "workScopeSha256"),
            document.keys,
        )
        assertEquals("gcc-bundled-operation-intent-v1", document.getValue("provider").jsonPrimitive.content)
        assertEquals("1", document.getValue("schemaVersion").jsonPrimitive.content)
        val roles = document.getValue("artifacts").jsonArray.map { it.jsonObject.getValue("role").jsonPrimitive.content }
        assertEquals(GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.map { it.wireName }.sorted(), roles)
        assertFalse(captured.decodeToString().contains("\"outputLease\""))
        assertFalse(captured.decodeToString().contains("\"inode\""))
        assertFalse(captured.decodeToString().contains("\"analysisState\""))
        assertFalse(captured.decodeToString().contains("\"command\""))
        assertContentEquals(captured, intent(artifacts = artifacts().reversed()).canonicalBytes)
    }

    @Test
    fun `disk operation names real GCC work and binds the explicit engine profile source scope`() {
        val artifacts = artifacts()
        val byRole = artifacts.associateBy { it.role }
        for (engine in listOf("cc1", "lto1")) {
            val intent = intent(engineId = engine)
            val expectedScope = OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-bundled-work-scope-v1"),
                "engineId" to JsonPrimitive(engine),
                "engineSha256" to JsonPrimitive(byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256),
                "profileSha256" to JsonPrimitive(byRole.getValue(GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE).sha256),
                "sourceLockSha256" to JsonPrimitive(byRole.getValue(GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK).sha256),
            ))))
            assertEquals(expectedScope, intent.workScopeSha256)
            val operation = intent.diskOperation()
            assertEquals(OPERATION_ID, operation.operationId)
            assertEquals(intent.requestSha256, operation.requestSha256)
            assertEquals(engine, operation.shardId)
            assertEquals(expectedScope, operation.scopeSha256)
            assertFalse(intent.canonicalBytes.decodeToString().contains("llvm", ignoreCase = true))
        }
    }

    @Test
    fun `work scope and request commitments change in their respective semantic domains`() {
        val original = intent()
        for (role in listOf(
            GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
            GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE,
            GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK,
        )) {
            val changed = intent(artifacts = artifacts().map { if (it.role == role) it.copy(sha256 = SHA_CHANGED) else it })
            assertNotEquals(original.workScopeSha256, changed.workScopeSha256)
            assertNotEquals(original.requestSha256, changed.requestSha256)
        }
        val nonScopeChanges = listOf(
            intent(operationId = "2".repeat(64)),
            intent(runKind = GccCompilerEngineContainmentRunKind.FRESH_CONTROL),
            intent(artifacts = artifacts().map {
                if (it.role == GccCompilerEngineContainmentArtifactRole.BUILD_RECORD) it.copy(sha256 = SHA_CHANGED) else it
            }),
            intent(budgets = budgets().copy(wallClockMillis = 61_000)),
            intent(diskPolicy = policy().copy(requiredAvailableBytes = 2 * 1024 * 1024)),
        )
        for (changed in nonScopeChanges) {
            assertEquals(original.workScopeSha256, changed.workScopeSha256)
            assertNotEquals(original.requestSha256, changed.requestSha256)
        }
        assertNotEquals(original.workScopeSha256, intent(engineId = "lto1").workScopeSha256)
    }

    @Test
    fun `intent admits only fresh named engines bounded whole-second budgets and finite disk policy`() {
        for (operationId in listOf("", "1".repeat(63), "1".repeat(65), "G".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { intent(operationId = operationId) }
        }
        for (engine in listOf("", "gcc", "clang", "CC1", "../cc1")) {
            assertFailsWith<IllegalArgumentException> { intent(engineId = engine) }
        }
        assertFailsWith<IllegalArgumentException> { intent(runKind = GccCompilerEngineContainmentRunKind.RESUMED) }
        val fresh = intent()
        assertFailsWith<IllegalArgumentException> {
            GccBundledOperationIntent(
                fresh.operationId, fresh.engineId, fresh.runKind, fresh.artifacts,
                GccBundledGhidraRuntime(fresh.bundledRuntime.root, fresh.bundledRuntime.classPath, invocationVersion = 4),
                fresh.budgets, fresh.diskPolicy,
            )
        }
        assertFailsWith<IllegalArgumentException> { intent(budgets = budgets().copy(wallClockMillis = 60_001)) }
        val maximum = policy().copy(maximumFilesystemBytes = 1024L * 1024 * 1024 * 1024, maximumFilesystemInodes = 2_000_000)
        assertTrue(intent(diskPolicy = maximum).canonicalBytes.isNotEmpty())
        for (diskPolicy in listOf(
            maximum.copy(maximumFilesystemBytes = maximum.maximumFilesystemBytes + 1),
            maximum.copy(maximumFilesystemInodes = 2_000_001),
            maximum.copy(maximumFilesystemInodes = Long.MAX_VALUE),
            policy().copy(requiredAvailableInodes = 127),
        )) {
            assertFailsWith<IllegalArgumentException> { intent(diskPolicy = diskPolicy) }
        }
    }

    @Test
    fun `intent refuses incomplete duplicate legacy and contradictory bundled roles`() {
        val valid = artifacts()
        for (changed in listOf(
            valid.dropLast(1), valid + valid.first(),
            valid.map {
                if (it.role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR) {
                    it.copy(role = GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS)
                } else it
            },
            valid.map {
                if (it.role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR) it.copy(sha256 = SHA_CHANGED) else it
            },
            valid.map {
                if (it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) {
                    it.copy(path = valid.single { candidate -> candidate.role == GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE }.path)
                } else it
            },
        )) {
            assertFailsWith<IllegalArgumentException> { intent(artifacts = changed) }
        }
    }

    private data class AbandonedReset(
        val intent: GccBundledOperationIntent,
        val evidence: FullTreeDiskScratchEvidence,
        val definition: GccCompilerEngineValidatedContainmentDefinition,
        val leaseRecord: ByteArray,
        val children: Map<String, LinuxFileIdentity>,
    )

    private fun resetAbandonedFixture(mount: Path, expected: AbandonedReset) {
        val run = expected.definition.outputLease.path
        val lease = run.parent
        LinuxFilesystemSyscalls.openRoot(mount).use { root ->
            assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(root), "test reset cannot take the dedicated mount lock")
            try {
                assertEquals(expected.evidence.mountId, root.identity.mountId)
                assertEquals(expected.evidence.device, root.identity.key.device)
                assertEquals(expected.evidence.rootInode, root.identity.key.inode)
                assertEquals(listOf(lease.fileName.toString()), LinuxFilesystemSyscalls.directoryEntryNames(root, 2))
                LinuxFilesystemSyscalls.openDirectoryAt(root.fd, lease.fileName.toString()).use { leased ->
                    assertEquals(expected.evidence.leaseRootDevice, leased.identity.key.device)
                    assertEquals(expected.evidence.leaseRootInode, leased.identity.key.inode)
                    assertEquals(root.identity.uid, leased.identity.uid)
                    assertEquals(root.identity.mountId, leased.identity.mountId)
                    assertEquals(448, leased.identity.mode and 0xfff)
                    assertEquals(listOf(run.fileName.toString(), "lease.json").sorted(), LinuxFilesystemSyscalls.directoryEntryNames(leased, 3).sorted())
                    LinuxFilesystemSyscalls.openRegularFileAtOrNull(leased.fd, "lease.json").use { record ->
                        val selected = assertNotNull(record)
                        assertEquals(256, selected.identity.mode and 0xfff)
                        assertEquals(1, selected.identity.linkCount)
                        assertEquals(root.identity.uid, selected.identity.uid)
                        assertEquals(root.identity.mountId, selected.identity.mountId)
                        LinuxFilesystemSyscalls.openReadableFrom(selected).use { readable ->
                            assertContentEquals(expected.leaseRecord, LinuxFilesystemSyscalls.read(readable, 64 * 1024) {})
                        }
                        LinuxFilesystemSyscalls.openDirectoryAt(leased.fd, run.fileName.toString()).use { output ->
                            val identity = expected.definition.outputLease
                            assertEquals(identity.device, output.identity.key.device)
                            assertEquals(identity.inode, output.identity.key.inode)
                            assertEquals(identity.mountId, output.identity.mountId)
                            assertEquals(identity.uid, output.identity.uid)
                            assertEquals(identity.permissions, output.identity.mode and 0xfff)
                            assertEquals(expected.children.keys.sorted(), LinuxFilesystemSyscalls.directoryEntryNames(output, 4).sorted())
                            for ((name, original) in expected.children) {
                                LinuxFilesystemSyscalls.openDirectoryAt(output.fd, name).use { child ->
                                    assertEquals(original, child.identity)
                                    assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(child, 1).isEmpty())
                                    requireCurrentName(output, name, child.identity)
                                    LinuxFilesystemSyscalls.removeDirectory(output.fd, name)
                                }
                            }
                            assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(output, 1).isEmpty())
                            LinuxFilesystemSyscalls.synchronize(output)
                            requireCurrentName(leased, run.fileName.toString(), output.identity, compareLinkCount = false)
                            LinuxFilesystemSyscalls.removeDirectory(leased.fd, run.fileName.toString())
                        }
                        requireCurrentName(leased, "lease.json", selected.identity)
                        LinuxFilesystemSyscalls.unlink(leased.fd, "lease.json")
                    }
                    assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(leased, 1).isEmpty())
                    LinuxFilesystemSyscalls.synchronize(leased)
                    requireCurrentName(root, lease.fileName.toString(), leased.identity, compareLinkCount = false)
                    LinuxFilesystemSyscalls.removeDirectory(root.fd, lease.fileName.toString())
                }
                LinuxFilesystemSyscalls.synchronize(root)
                assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(root, 1).isEmpty())
            } finally {
                LinuxFilesystemSyscalls.unlock(root)
            }
        }
    }

    private fun requireCurrentName(parent: LinuxDescriptor, name: String, expected: LinuxFileIdentity, compareLinkCount: Boolean = true) {
        LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name).use { selected ->
            val identity = assertNotNull(selected).identity
            assertEquals(if (compareLinkCount) expected else expected.copy(linkCount = identity.linkCount), identity)
        }
    }

    private fun preparedIntentInputs(fixture: Path, bundledRoot: Path, requireLiveExecutables: Boolean = true): GccBundledOperationIntent {
        val inputs = privateDirectory(fixture.resolve("inputs"))
        val reference = GccBundledGhidraDeploymentReference.open().use { it.reference }
        val runtime = GccBundledGhidraRuntime(bundledRoot, reference.classPath.map { relative ->
            val entry = reference.entries.getValue(relative)
            GccBundledGhidraClassPathEntry(bundledRoot.resolve(relative), checkNotNull(entry.bytes), checkNotNull(entry.sha256))
        })
        val bootRoot = Path.of(checkNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot"))).toRealPath()
        val bootEntries = GccKotlinBootClasspathReference.open().use { it.entries }
        val bootManifest = writeReadOnly(inputs.resolve("boot-classpath.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("gcc-kotlin-boot-classpath-manifest-v1"),
            "entries" to JsonArray(bootEntries.map { entry -> JsonObject(mapOf(
                "path" to JsonPrimitive(bootRoot.resolve(entry.logicalName).toString()),
                "bytes" to JsonPrimitive(entry.bytes), "sha256" to JsonPrimitive(entry.sha256),
            )) }),
        ))))
        val exporter = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java")).use { it.readNBytes(4 * 1024 * 1024 + 1) }
        check(exporter.size in 1..4 * 1024 * 1024)
        val runtimePaths = mapOf(
            GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE to Path.of(System.getProperty("java.home"), "bin", "java"),
            GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE to Path.of("/usr/bin/bwrap"),
            GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE to Path.of("/usr/bin/prlimit"),
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE to Path.of("/usr/bin/systemd-run"),
            GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE to Path.of("/usr/bin/systemctl"),
            GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE to Path.of("/usr/bin/busctl"),
        )
        val artifacts = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.map { role ->
            val path = when (role) {
                GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH -> bootManifest
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> bundledRoot.resolve("decomp-ghidra-bridge.jar")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> bundledRoot.resolve("scripts/RunBundledExports.class")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> bundledRoot.resolve("bundle.sha256")
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> writeReadOnly(inputs.resolve("ExportProgramModel.java"), exporter)
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> Path.of(checkNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))).toRealPath()
                else -> runtimePaths[role]?.takeIf { requireLiveExecutables || Files.isExecutable(it) }?.toRealPath()
                    ?: writeReadOnly(inputs.resolve("${role.wireName}.bin"), "unexecuted-prepared-input-${role.wireName}".encodeToByteArray())
            }
            GccCompilerEngineContainmentArtifactIdentity(role, path, Files.size(path), sha256(path))
        }
        return intent(artifacts = artifacts, runtime = runtime)
    }

    private fun provisionedBundle(): Path {
        val configured = System.getenv("DECOMP_TEST_BUNDLED_GHIDRA_ROOT")?.takeIf(String::isNotBlank)
        assumeTrue(configured != null, "a root-owned bundled runtime is not provisioned")
        val root = Path.of(checkNotNull(configured))
        assertTrue(root.isAbsolute && root.normalize() == root && root.toRealPath() == root)
        return root
    }

    private fun withRequiredProvisioning(action: () -> Unit) {
        try {
            action()
        } catch (unavailable: TestAbortedException) {
            if (System.getenv("DECOMP_REQUIRE_BUNDLED_GHIDRA_RUNTIME") == "true" || System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                throw AssertionError("required GCC prepared-operation provisioner fixtures are unavailable", unavailable)
            }
            throw unavailable
        }
    }

    private fun withFixture(action: (Path) -> Unit) {
        val root = Files.createTempDirectory("gcc-bundled-operation-test-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun privateDirectory(path: Path): Path {
        Files.createDirectory(path)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        return path
    }

    private fun writeReadOnly(path: Path, bytes: ByteArray): Path {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        return path
    }

    private fun names(path: Path): List<String> = Files.list(path).use { entries -> entries.map { it.fileName.toString() }.sorted().toList() }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileChannel.open(path, StandardOpenOption.READ).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            while (true) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read < 0) break
                if (read > 0) digest.update(buffer.array(), 0, read)
            }
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    @Test
    fun `version two intent binds complete planner policy and independently retains it`() {
        val checked = Path.of(System.getProperty("user.dir")).resolve("oracle/gcc/16.2.0/compiler-engines.json")
        val root = Files.createTempDirectory("gcc-planner-intent-")
        GccRetainedCompilerEngineProfile.open(checked).use { original ->
            val inputs = OracleJson.parseCanonical(original.policyBytes()).jsonObject.getValue("inputs").jsonArray
            inputs.forEach { item ->
                val path = Path.of(item.jsonObject.getValue("path").jsonPrimitive.content)
                val target = root.resolve(path.fileName)
                Files.copy(path, target)
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
            }
        }
        lateinit var bound: GccBundledOperationIntent
        GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json")).use { profile ->
            val suite = profile.suite
            val engine = suite.engine("cc1")
            val controls = mapOf(
                GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to suite.profilePath,
                GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
                GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to engine.buildRecordPath,
                GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to engine.oracleManifestPath,
                GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath,
            )
            val selected = artifacts().map { artifact ->
                controls[artifact.role]?.let { path -> artifact.copy(path = path, bytes = Files.size(path),
                    sha256 = OracleArtifacts.sha256(Files.readAllBytes(path))) } ?: when (artifact.role) {
                    GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY -> artifact.copy(bytes = engine.strippedArtifact.bytes, sha256 = engine.strippedArtifact.sha256)
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> artifact.copy(bytes = suite.analysis.ghidraArchive.bytes, sha256 = suite.analysis.ghidraArchive.sha256)
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> artifact.copy(sha256 = suite.analysis.exporterSha256)
                    else -> artifact
                }
            }
            fun build(entries: List<GccCompilerEngineContainmentArtifactIdentity> = selected,
                limits: GccCompilerEngineContainmentBudgets = budgets()) = GccBundledOperationIntent(
                OPERATION_ID, "cc1", GccCompilerEngineContainmentRunKind.INTERRUPTED, entries, runtime(), limits, policy(), profile)
            bound = build()
            val document = OracleJson.parseCanonical(bound.canonicalBytes).jsonObject
            assertEquals("gcc-bundled-operation-intent-v2", document.getValue("provider").jsonPrimitive.content)
            assertEquals(OracleJson.parseCanonical(profile.policyBytes()), document.getValue("plannerProfile"))
            assertNotEquals(intent(artifacts = selected).requestSha256, bound.requestSha256)
            assertEquals(OracleArtifacts.sha256(bound.canonicalBytes), bound.diskOperation().requestSha256)
            for (role in controls.keys + setOf(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE, GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE)) {
                assertFails { build(selected.map { if (it.role == role) it.copy(sha256 = SHA_CHANGED) else it }) }
            }
            assertFails { build(limits = GccCompilerEngineContainmentBudgets(suite.budgets.exportWallClockMillis + 1000, budgets().maximumResidentBytes, 32)) }
            assertFails { build(limits = GccCompilerEngineContainmentBudgets(60_000, suite.budgets.exportMaximumResidentBytes + 1, 32)) }
            assertFails { bound.openPlannerProfile(listOf(root)) }
            assertFails { GccBundledOperationIntent(OPERATION_ID, "lto1", bound.runKind, selected, runtime(), budgets(), policy(), profile) }
            val lto = suite.engine("lto1")
            val ltoArtifacts = selected.map { artifact ->
                val path = when (artifact.role) {
                    GccCompilerEngineContainmentArtifactRole.BUILD_RECORD -> lto.buildRecordPath
                    GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST -> lto.oracleManifestPath
                    else -> null
                }
                if (path != null) artifact.copy(path = path, bytes = Files.size(path), sha256 = OracleArtifacts.sha256(Files.readAllBytes(path)))
                else if (artifact.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY)
                    artifact.copy(bytes = lto.strippedArtifact.bytes, sha256 = lto.strippedArtifact.sha256)
                else artifact
            }
            val ltoIntent = GccBundledOperationIntent(OPERATION_ID, "lto1", bound.runKind, ltoArtifacts, runtime(), budgets(), policy(), profile)
            checkNotNull(ltoIntent.openPlannerProfile(emptyList())).use { it.requireCurrent() }
            assertNotEquals(bound.requestSha256, ltoIntent.requestSha256)
        }
        // The intent owns bytes, not the caller's closed descriptor handle.
        checkNotNull(bound.openPlannerProfile(emptyList())).use { retained ->
            retained.requireCurrent()
            val journalRoot = Files.createDirectory(root.resolve("journal"))
            Files.setPosixFilePermissions(journalRoot, PosixFilePermissions.fromString("rwx------"))
            GccBundledOperationJournal.create(journalRoot, OPERATION_ID, bound.canonicalBytes).use { journal -> journal.verify("v2 planner intent test") }
            val dependency = root.resolve("build-toolchain.Dockerfile")
            val original = Files.readAllBytes(dependency)
            Files.move(dependency, root.resolve("original-Dockerfile"))
            Files.write(dependency, original)
            assertFails { retained.requireCurrent() }
        }
        val path = root.resolve("compiler-engines.json")
        Files.write(path, Files.readAllBytes(path) + byteArrayOf(32))
        assertFails { bound.openPlannerProfile(emptyList()) }
    }

    private fun intent(
        operationId: String = OPERATION_ID,
        engineId: String = "cc1",
        runKind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.INTERRUPTED,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity> = artifacts(),
        runtime: GccBundledGhidraRuntime = runtime(),
        budgets: GccCompilerEngineContainmentBudgets = budgets(),
        diskPolicy: FullTreeDiskScratchPolicy = policy(),
    ) = GccBundledOperationIntent(operationId, engineId, runKind, artifacts, runtime, budgets, diskPolicy)

    private fun budgets() = GccCompilerEngineContainmentBudgets(60_000, 512L * 1024 * 1024, 32)

    private fun policy() = FullTreeDiskScratchPolicy(1024 * 1024, 64L * 1024 * 1024, 128, 4096)

    private fun runtime() = GccBundledGhidraRuntime(ROOT, listOf(
        GccBundledGhidraClassPathEntry(ROOT.resolve("decomp-ghidra-bridge.jar"), 32, SHA_BRIDGE),
        GccBundledGhidraClassPathEntry(ROOT.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Framework/Module/lib/module.jar"), 64, SHA_CHANGED),
    ))

    private fun artifacts(): List<GccCompilerEngineContainmentArtifactIdentity> = GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.mapIndexed { index, role ->
        GccCompilerEngineContainmentArtifactIdentity(
            role,
            when (role) {
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> ROOT.resolve("decomp-ghidra-bridge.jar")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> ROOT.resolve("scripts/RunBundledExports.class")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> ROOT.resolve("bundle.sha256")
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/trusted/scripts/ExportProgramModel.java")
                else -> Path.of("/trusted/${role.wireName}")
            },
            if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR) 32 else index + 1L,
            when (role) {
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> SHA_BRIDGE
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> BundledGhidra.ARCHIVE_SHA256
                else -> (index + 1).toString(16).padStart(2, '0').repeat(32)
            },
        )
    }

    private companion object {
        val ROOT: Path = Path.of("/trusted/bundle")
        const val OPERATION_ID = "1111111111111111111111111111111111111111111111111111111111111111"
        const val SHA_BRIDGE = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val SHA_CHANGED = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    }
}
