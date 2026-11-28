package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.FullTreeDiskScratchException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.opentest4j.TestAbortedException
import org.tukaani.xz.XZInputStream

/**
 * Normal-CLI admission with the genuine checked cc1/driver bytes, checked profile, pinned Ghidra archive and host
 * containment tools. Admission stops at the coordinator's prepared owner: no worker START, export or plan occurs.
 */
class GccBundledCliAdmissionTest {
    @Test
    fun `genuine plan resume and full-export selections reach a prepared owner on provisioned scratch before START`() =
        withRequiredProvisioning {
            val bundle = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_ROOT", "a root-owned bundled runtime is not provisioned")
            val mount = configuredDirectory("DECOMP_TEST_ORACLE_EXT4_SCRATCH", "a dedicated ext4 scratch slot is not provisioned")
            assertTrue(names(mount).isEmpty(), "dedicated scratch requires recovery before the test")
            fixture { root ->
                val cc1 = genuineCc1(root)
                for (selection in listOf(
                    Selection("plan-fresh", "cc1", cc1, fullRecoveryExport = false, resumeAfterCheckpoint = null),
                    Selection("plan-resume", "cc1", cc1, fullRecoveryExport = false, resumeAfterCheckpoint = 512),
                    Selection("full-export", "driver", DRIVER, fullRecoveryExport = true, resumeAfterCheckpoint = null),
                )) admitOnProvisionedScratch(root, bundle, mount, selection)
            }
            assertTrue(names(mount).isEmpty())
        }

    @Test
    fun `genuine later-invocation recovery re-derives the intent but is refused while the admitted owner is live or unstarted`() =
        withRequiredProvisioning {
            val bundle = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_ROOT", "a root-owned bundled runtime is not provisioned")
            val mount = configuredDirectory("DECOMP_TEST_ORACLE_EXT4_SCRATCH", "a dedicated ext4 scratch slot is not provisioned")
            assertTrue(names(mount).isEmpty(), "dedicated scratch requires recovery before the test")
            fixture { root ->
                val output = privateDirectory(root.resolve("output-recovery"))
                val args = arguments("cc1", genuineCc1(root), output, mount) + listOf("--resume-after-checkpoint", "512")
                val options = GccBundledCliOptions.parse(args)
                var owner: GccBundledPreparedOperation? = null
                var reset: GccBundledAbandonedPreparation? = null
                try {
                    val earlier = withBundledGhidraRoot(bundle) { GccBundledCliCommand.admit(options, args) }
                    owner = earlier
                    reset = earlier.abandonedPreparation()
                    val recoveryArgs = args + listOf("--recover-operation", earlier.intent.operationId)
                    val recovery = GccBundledCliOptions.parse(recoveryArgs)
                    val operation = output.resolve("journal/.gcc-bundled-operation-${earlier.intent.operationId}")
                    val retained = (listOf("invocation.json") + names(output.resolve("inputs")).map { "inputs/$it" } +
                        names(operation).map { "journal/${operation.fileName}/$it" }).associateWith {
                        Files.readAllBytes(output.resolve(it)).toList()
                    }
                    fun requireUnchanged() {
                        assertEquals(listOf("inputs", "invocation.json", "journal"), names(output))
                        assertEquals(listOf("ExportProgramModel.java", "boot-classpath.json"), names(output.resolve("inputs")))
                        assertEquals(listOf("definition.json", "intent.json", "lease-evidence.json", "prepared.json"), names(operation))
                        retained.forEach { (name, bytes) -> assertEquals(bytes, Files.readAllBytes(output.resolve(name)).toList(), name) }
                    }
                    // A later invocation re-derives the byte-identical production intent from genuine inputs.
                    val rebuilt = withBundledGhidraRoot(bundle) { GccBundledCliCommand.recoveryIntent(recovery, recoveryArgs) }
                    assertContentEquals(earlier.intent.canonicalBytes, rebuilt.canonicalBytes)
                    requireUnchanged()
                    // The admitted owner is live, so the later invocation is refused at the journal locks.
                    val live = assertFailsWith<IllegalArgumentException> {
                        withBundledGhidraRoot(bundle) { GccBundledCliCommand.run(recovery, recoveryArgs) }
                    }
                    assertTrue(live.message.orEmpty().contains("held by a live owner"), live.toString())
                    requireUnchanged()
                    earlier.requireCurrent()
                    earlier.close()
                    owner = null
                    // With that owner gone, an unstarted history is still no stopped checkpoint and is refused unchanged.
                    val unstarted = assertFailsWith<IllegalArgumentException> {
                        withBundledGhidraRoot(bundle) { GccBundledCliCommand.run(recovery, recoveryArgs) }
                    }
                    assertTrue(unstarted.message.orEmpty().contains("unexpected residue"), unstarted.toString())
                    requireUnchanged()
                    println("gcc-cli-later-invocation-refusal ${OracleJson.canonicalBytes(JsonObject(mapOf(
                        "argv" to JsonArray((listOf(recovery.commandName) + recoveryArgs).map(::JsonPrimitive)),
                        "intentSha256" to JsonPrimitive(rebuilt.requestSha256),
                        "liveOwner" to JsonPrimitive(live.message.orEmpty()),
                        "unstartedHistory" to JsonPrimitive(unstarted.message.orEmpty()),
                        "startAuthorized" to JsonPrimitive(false),
                    ))).decodeToString()}")
                } finally {
                    owner?.close()
                    reset?.let { resetGccBundledAbandonedPreparation(mount, it) }
                }
            }
            assertTrue(names(mount).isEmpty())
        }

    @Test
    fun `ordinary scratch is refused after durable intent and before any lease or START`() = withRequiredProvisioning {
        val bundle = configuredDirectory("DECOMP_TEST_BUNDLED_GHIDRA_ROOT", "a root-owned bundled runtime is not provisioned")
        fixture { root ->
            val scratch = privateDirectory(root.resolve("ordinary-scratch"))
            val output = privateDirectory(root.resolve("output"))
            val args = arguments("cc1", genuineCc1(root), output, scratch)
            val options = GccBundledCliOptions.parse(args)
            assertFailsWith<FullTreeDiskScratchException> {
                withBundledGhidraRoot(bundle) { GccBundledCliCommand.run(options, args) }
            }
            assertTrue(names(scratch).isEmpty())
            assertEquals(listOf("inputs", "invocation.json", "journal"), names(output))
            assertEquals(listOf("ExportProgramModel.java", "boot-classpath.json"), names(output.resolve("inputs")))
            val operation = output.resolve("journal").resolve(names(output.resolve("journal")).single())
            assertTrue(operation.fileName.toString().startsWith(".gcc-bundled-operation-"))
            assertEquals(listOf("intent.json"), names(operation))
            val intent = OracleJson.parseCanonical(Files.readAllBytes(operation.resolve("intent.json"))).jsonObject
            assertEquals(OracleJson.parseCanonical(Files.readAllBytes(output.resolve("invocation.json"))), intent["cliInvocation"])
            assertEquals(bundle.toString(), intent.getValue("bundledRuntime").jsonObject.getValue("root").jsonPrimitive.content)
        }
    }

    @Test
    fun `genuine inputs authenticate but an untrusted bundled runtime is refused before journal lease or START`() = fixture { root ->
        val development = Path.of(checkNotNull(System.getProperty("decompengine.oracle.gcc.bundledGhidraRoot")))
        assumeTrue(Files.getAttribute(development, "unix:uid") != 0, "the development bundled runtime is root-owned")
        val cc1 = genuineCc1(root)
        for ((engine, binary, fullRecoveryExport) in listOf(Triple("cc1", cc1, false), Triple("driver", DRIVER, true))) {
            val output = privateDirectory(root.resolve("output-$engine"))
            val scratch = privateDirectory(root.resolve("scratch-$engine"))
            val args = arguments(engine, binary, output, scratch)
            val options = GccBundledCliOptions.parse(args, fullRecoveryExport = fullRecoveryExport)
            val failure = assertFailsWith<IllegalArgumentException> { GccBundledCliCommand.run(options, args) }
            assertTrue(failure.message.orEmpty().contains("bundled Ghidra runtime has an untrusted ancestor"), failure.toString())
            // Every engine, profile, archive, exporter, tool and BOOT identity was authenticated and both controls staged.
            assertEquals(listOf("inputs", "invocation.json", "journal"), names(output))
            assertEquals(listOf("ExportProgramModel.java", "boot-classpath.json"), names(output.resolve("inputs")))
            assertTrue(names(output.resolve("journal")).isEmpty())
            assertTrue(names(scratch).isEmpty())
        }
    }

    @Test
    fun `genuine bytes substituted for another engine or the Ghidra archive are refused before staging`() = fixture { root ->
        val cc1 = genuineCc1(root)
        fun bound(engine: String) = GccRetainedCompilerEngineProfile.open(PROFILE, engine).use { it.target(engine).strippedArtifact.bytes }
        val substitutions = listOf(
            Triple(arguments("cc1", DRIVER, root.resolve("cc1-output"), root.resolve("cc1-scratch")), false,
                "CLI binary differs from selected profile engine"),
            Triple(arguments("lto1", cc1, root.resolve("lto1-output"), root.resolve("lto1-scratch")), false,
                "CLI engine-binary must contain 1..${bound("lto1")} bytes"),
            Triple(arguments("driver", cc1, root.resolve("driver-output"), root.resolve("driver-scratch")), true,
                "CLI engine-binary must contain 1..${bound("driver")} bytes"),
            Triple(arguments("cc1", cc1, root.resolve("archive-output"), root.resolve("archive-scratch"), archive = cc1), false,
                "CLI Ghidra archive differs from profile provenance"),
        )
        for ((args, fullRecoveryExport, expected) in substitutions) {
            val output = privateDirectory(Path.of(args[args.indexOf("--output") + 1]))
            val scratch = privateDirectory(Path.of(args[args.indexOf("--scratch") + 1]))
            val options = GccBundledCliOptions.parse(args, fullRecoveryExport = fullRecoveryExport)
            val failure = assertFailsWith<IllegalArgumentException> { GccBundledCliCommand.run(options, args) }
            assertTrue(failure.message.orEmpty().contains(expected), failure.toString())
            assertEquals(listOf("inputs", "invocation.json", "journal"), names(output))
            for (path in listOf(output.resolve("inputs"), output.resolve("journal"), scratch)) assertTrue(names(path).isEmpty())
        }
    }

    private data class Selection(
        val label: String, val engine: String, val binary: Path,
        val fullRecoveryExport: Boolean, val resumeAfterCheckpoint: Long?,
    )

    private fun admitOnProvisionedScratch(root: Path, bundle: Path, mount: Path, selection: Selection) {
        val output = privateDirectory(root.resolve("output-${selection.label}"))
        val args = arguments(selection.engine, selection.binary, output, mount) +
            (selection.resumeAfterCheckpoint?.let { listOf("--resume-after-checkpoint", it.toString()) } ?: emptyList())
        val options = GccBundledCliOptions.parse(args, fullRecoveryExport = selection.fullRecoveryExport)
        var owner: GccBundledPreparedOperation? = null
        var reset: GccBundledAbandonedPreparation? = null
        try {
            val prepared = withBundledGhidraRoot(bundle) { GccBundledCliCommand.admit(options, args) }
            owner = prepared
            reset = prepared.abandonedPreparation()
            assertFalse(prepared.startAuthorized)
            assertFalse(prepared.complete)
            assertFalse(prepared.releaseEligible)
            val intent = prepared.intent
            val invocationBytes = Files.readAllBytes(output.resolve("invocation.json"))
            assertContentEquals(invocationBytes, checkNotNull(intent.cliInvocation).canonicalBytes)
            val invocation = OracleJson.parseCanonical(invocationBytes).jsonObject
            assertEquals(JsonArray((listOf(options.commandName) + args).map(::JsonPrimitive)), invocation["argv"])
            assertEquals(if (selection.resumeAfterCheckpoint == null) "fresh" else "same-owner-checkpoint",
                invocation.getValue("resumeMode").jsonPrimitive.content)
            assertEquals(selection.engine, intent.engineId)
            assertEquals(if (selection.resumeAfterCheckpoint == null) GccCompilerEngineContainmentRunKind.FRESH_CONTROL
                else GccCompilerEngineContainmentRunKind.INTERRUPTED, intent.runKind)
            assertEquals(bundle, intent.bundledRuntime.root)
            assertEquals(if (selection.fullRecoveryExport) "full" else "planning", intent.bundledRuntime.recoveryMode)
            assertEquals(options.diskPolicy, intent.diskPolicy)
            GccRetainedCompilerEngineProfile.open(PROFILE, selection.engine).use { profile ->
                val document = OracleJson.parseCanonical(intent.canonicalBytes).jsonObject
                assertEquals("gcc-bundled-operation-intent-v2", document.getValue("provider").jsonPrimitive.content)
                assertEquals(OracleJson.parseCanonical(profile.policyBytes()), document["plannerProfile"])
                assertEquals(OracleJson.parseCanonical(invocationBytes), document["cliInvocation"])
                val suite = profile.suite
                val target = profile.target(selection.engine)
                assertEquals(GccCompilerEngineContainmentBudgets(suite.budgets.exportWallClockMillis,
                    suite.budgets.exportMaximumResidentBytes, 128), intent.budgets)
                val byRole = intent.artifacts.associateBy { it.role }
                val expectedPaths = mapOf(
                    GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY to selection.binary,
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE to ARCHIVE,
                    GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to PROFILE,
                    GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
                    GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to target.buildRecordPath,
                    GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to target.oracleManifestPath,
                    GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath,
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST to bundle.resolve("bundle.sha256"),
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR to bundle.resolve("decomp-ghidra-bridge.jar"),
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD to bundle.resolve("scripts/RunBundledExports.class"),
                    GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH to output.resolve("inputs/boot-classpath.json"),
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE to output.resolve("inputs/ExportProgramModel.java"),
                    GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE to Path.of(System.getProperty("java.home"), "bin/java").toRealPath(),
                    GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE to Path.of("/usr/bin/bwrap").toRealPath(),
                    GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE to Path.of("/usr/bin/prlimit").toRealPath(),
                    GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE to Path.of("/usr/bin/systemd-run").toRealPath(),
                    GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE to Path.of("/usr/bin/systemctl").toRealPath(),
                    GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE to Path.of("/usr/bin/busctl").toRealPath(),
                )
                assertEquals(GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES, expectedPaths.keys)
                for ((role, path) in expectedPaths) {
                    val artifact = byRole.getValue(role)
                    // Production identities are the exact current bytes, never authored placeholder records.
                    assertEquals(path, artifact.path, role.wireName)
                    assertEquals(Files.size(path), artifact.bytes, role.wireName)
                    assertEquals(sha256(path), artifact.sha256, role.wireName)
                }
                assertEquals(target.strippedArtifact.sha256, byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).sha256)
                assertEquals(BundledGhidra.ARCHIVE_SHA256, byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE).sha256)
                assertEquals(suite.analysis.exporterSha256, byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE).sha256)
            }
            val disk = FullTreeDiskScratchEvidence.parseCanonical(prepared.diskEvidenceBytes)
            val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(prepared.definitionBytes)
            assertEquals(intent.operationId, disk.operationId)
            assertEquals(intent.requestSha256, disk.requestSha256)
            assertEquals(selection.engine, disk.shardId)
            assertEquals(intent.workScopeSha256, disk.scopeSha256)
            assertEquals("ext4", disk.filesystemType)
            assertEquals(LinuxFilesystemSyscalls.openRoot(mount).use { it.identity.mountId }, disk.mountId)
            assertEquals(mount, definition.outputLease.path.parent.parent)
            val receipt = OracleJson.parseCanonical(prepared.preparedReceiptBytes).jsonObject
            assertEquals(intent.requestSha256, receipt.getValue("intentSha256").jsonPrimitive.content)
            assertEquals(disk.evidenceSha256, receipt.getValue("diskEvidenceSha256").jsonPrimitive.content)
            val operation = output.resolve("journal/.gcc-bundled-operation-${intent.operationId}")
            val expectedJournal = mapOf("definition.json" to prepared.definitionBytes, "intent.json" to intent.canonicalBytes,
                "lease-evidence.json" to prepared.diskEvidenceBytes, "prepared.json" to prepared.preparedReceiptBytes)
            fun requireUnstarted() {
                assertEquals(listOf("inputs", "invocation.json", "journal"), names(output))
                assertEquals(listOf(operation.fileName.toString()), names(output.resolve("journal")))
                assertEquals(expectedJournal.keys.sorted(), names(operation))
                for ((name, bytes) in expectedJournal) assertContentEquals(bytes, Files.readAllBytes(operation.resolve(name)), name)
            }
            requireUnstarted()
            // A selection other than the admitted one is refused by the owner itself before any START.
            if (selection.fullRecoveryExport) {
                assertFailsWith<IllegalStateException> { prepared.execute() }
                assertFailsWith<IllegalArgumentException> { prepared.executeUntilCheckpoint(512) }
            } else if (selection.resumeAfterCheckpoint == null) {
                assertFailsWith<IllegalStateException> { prepared.executeFullExport() }
                assertFailsWith<IllegalArgumentException> { prepared.executeUntilCheckpoint(512) }
            } else {
                assertFailsWith<IllegalArgumentException> { prepared.execute() }
                assertFailsWith<IllegalArgumentException> { prepared.executeUntilCheckpoint(selection.resumeAfterCheckpoint + 512) }
            }
            assertFailsWith<IllegalStateException> { prepared.resume() }
            assertFailsWith<IllegalStateException> { prepared.plan() }
            prepared.requireCurrent()
            requireUnstarted()
            println("gcc-cli-admission ${OracleJson.canonicalBytes(JsonObject(mapOf(
                "selection" to JsonPrimitive(selection.label), "argv" to invocation.getValue("argv"),
                "invocationSha256" to JsonPrimitive(OracleArtifacts.sha256(invocationBytes)),
                "intentSha256" to JsonPrimitive(intent.requestSha256),
                "diskEvidenceSha256" to JsonPrimitive(disk.evidenceSha256),
                "definitionSha256" to JsonPrimitive(OracleArtifacts.sha256(prepared.definitionBytes)),
                "preparedSha256" to JsonPrimitive(OracleArtifacts.sha256(prepared.preparedReceiptBytes)),
                "journal" to JsonArray(names(operation).map(::JsonPrimitive)),
                "startAuthorized" to JsonPrimitive(false),
            ))).decodeToString()}")
            prepared.close()
            owner = null
            assertFailsWith<IllegalStateException> { prepared.requireCurrent() }
            requireUnstarted()
        } finally {
            owner?.close()
            reset?.let { resetGccBundledAbandonedPreparation(mount, it) }
        }
    }

    private fun arguments(engine: String, binary: Path, output: Path, scratch: Path, archive: Path = ARCHIVE) = listOf(
        engine, binary.toString(), "--profile", PROFILE.toString(), "--ghidra-archive", archive.toString(),
        "--output", output.toString(), "--scratch", scratch.toString(),
        // The bounded hosted ext4 slot is 64 MiB with 4,096 inodes; admission never writes analysis output.
        "--scratch-min-bytes", "1048576", "--scratch-max-bytes", "67108864",
        "--scratch-min-inodes", "128", "--scratch-max-inodes", "4096",
    )

    private fun genuineCc1(root: Path): Path {
        val target = root.resolve("gcc-cc1.stripped")
        XZInputStream(Files.newInputStream(CC1_ARCHIVE), 64 * 1024).use { input ->
            Files.newOutputStream(target, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { input.transferTo(it) }
        }
        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
        val expected = GccRetainedCompilerEngineProfile.open(PROFILE, "cc1").use { it.target("cc1").strippedArtifact }
        assertEquals(expected.bytes, Files.size(target))
        assertEquals(expected.sha256, sha256(target), "checked cc1 XZ archive differs from the profile's stripped engine")
        return target.toRealPath()
    }

    private fun <T> withBundledGhidraRoot(root: Path, action: () -> T): T {
        // Development class directories select the bundle by this paired property; the reference itself is unchanged.
        val previous = checkNotNull(System.getProperty(BUNDLED_ROOT_PROPERTY)) { "development bundled Ghidra root is unset" }
        System.setProperty(BUNDLED_ROOT_PROPERTY, root.toString())
        try {
            return action()
        } finally {
            System.setProperty(BUNDLED_ROOT_PROPERTY, previous)
        }
    }

    private fun configuredDirectory(name: String, unavailable: String): Path {
        val configured = System.getenv(name)?.takeIf(String::isNotBlank)
        assumeTrue(configured != null, unavailable)
        val path = Path.of(checkNotNull(configured))
        assertTrue(path.isAbsolute && path.normalize() == path && path.toRealPath() == path, "$name must be canonical")
        return path
    }

    private fun withRequiredProvisioning(action: () -> Unit) {
        try {
            action()
        } catch (unavailable: TestAbortedException) {
            if (System.getenv("DECOMP_REQUIRE_BUNDLED_GHIDRA_RUNTIME") == "true" || System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_SCRATCH") == "true") {
                throw AssertionError("required GCC CLI admission provisioner fixtures are unavailable", unavailable)
            }
            throw unavailable
        }
    }

    private fun fixture(action: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(parent, "gcc-cli-admission-").toRealPath()
        try {
            action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))

    private fun names(path: Path): List<String> = Files.list(path).use { entries -> entries.map { it.fileName.toString() }.sorted().toList() }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileChannel.open(path, StandardOpenOption.READ).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            while (channel.read(buffer.clear()) >= 0) digest.update(buffer.flip())
        }
        return digest.digest().joinToString("") { "%02x".format(it) }
    }

    private companion object {
        const val BUNDLED_ROOT_PROPERTY = "decompengine.oracle.gcc.bundledGhidraRoot"
        val REPOSITORY: Path = Path.of(System.getProperty("user.dir")).toRealPath()
        val PROFILE: Path = REPOSITORY.resolve("oracle/gcc/16.2.0/compiler-engines-exporter17.json").toRealPath()
        val CC1_ARCHIVE: Path = REPOSITORY.resolve("oracle/gcc/16.2.0/artifacts/gcc-cc1.stripped.xz").toRealPath()
        val DRIVER: Path = REPOSITORY.resolve("oracle/gcc/16.2.0/artifacts/gcc-driver.stripped").toRealPath()
        val ARCHIVE: Path = Path.of(checkNotNull(System.getProperty("decompengine.ghidra.provenanceArchive"))).toRealPath()
    }
}
