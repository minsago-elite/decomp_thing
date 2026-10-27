package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Admission controls only: candidate runtime metadata never executes a collector or grants scoring. */
class GccRetainedNativeCallProfileTest {
    @Test
    fun `native intent definition and retained runtime preserve the selected engine and independently reject a fake deployment`() {
        for (engine in listOf("cc1", "driver")) withNativeControls { root ->
            GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), engine).use { retained ->
                val runtime = runtime(root)
                val inputs = artifacts(retained, engine, runtime)
                val invocation = invocation(root, engine, inputs)
                val intent = GccBundledOperationIntent("e".repeat(64), engine,
                    GccCompilerEngineContainmentRunKind.FRESH_CONTROL, inputs, runtime, budgets(),
                    invocation.options.diskPolicy, retained, invocation)
                val wire = OracleJson.parseCanonical(intent.canonicalBytes).jsonObject
                assertEquals("gcc-bundled-operation-intent-v5", wire.getValue("provider").jsonPrimitive.content)
                assertEquals(engine, wire.getValue("engineId").jsonPrimitive.content)
                assertEquals(engine, wire.getValue("cliInvocation").jsonObject.getValue("engineId").jsonPrimitive.content)
                intent.openPlannerProfile(listOf(invocation.options.output, invocation.options.scratch)).use { reopened ->
                    assertEquals(engine, assertNotNull(reopened).requireNativeCallProfile().engineId)
                    assertContentEquals(retained.policyBytes(), reopened.policyBytes())
                }
                val lease = GccCompilerEngineOutputLeaseIdentity(invocation.options.scratch,
                    1, 2, 3, 1000, 1000, 448, 1024, 2048, 128, 256)
                val state = GccCompilerEngineAnalysisStateIdentity(GccCompilerEngineAnalysisStateMode.FRESH_EMPTY,
                    lease.path.resolve("state"), null, 0, 0)
                val request = GccCompilerEngineContainmentRequest(intent.engineId, intent.runKind, intent.artifacts,
                    state, runtime.command(intent.artifacts, state, lease, intent.runKind), intent.environment,
                    lease, intent.budgets, runtime)
                val assessment = GccCompilerEngineContainmentContract.assessDefinition(request)
                assertFalse(assessment.startAuthorized)
                val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(assessment.canonicalBytes)
                assertEquals(engine, definition.engineId)
                assertEquals(8, assertNotNull(definition.bundledRuntime).invocationVersion)
                // Reaching this independent check proves both runtime entry points rebound the selected
                // profile, while deliberately fake deployment metadata still grants no runtime authority.
                for (open in listOf<() -> GccBundledGhidraRetainedRuntime>(
                    { GccBundledGhidraRetainedRuntime.open(definition) },
                    { GccBundledGhidraRetainedRuntime.open(runtime, inputs, listOf(lease.path), budgets(), engine) },
                )) {
                    val failure = assertFails { open().close() }
                    assertTrue(failure.message.orEmpty().contains("independent deployment reference"), failure.toString())
                }
                for (wrong in listOf(null, "lto1", if (engine == "driver") "cc1" else "driver")) {
                    val failure = assertFails {
                        GccBundledGhidraRetainedRuntime.open(runtime, inputs, listOf(lease.path), budgets(), wrong).close()
                    }
                    assertFalse(failure.message.orEmpty().contains("independent deployment reference"), failure.toString())
                }
                assertFails { GccBundledOperationIntent("e".repeat(64), engine, intent.runKind, inputs, runtime,
                    budgets(), invocation.options.diskPolicy, retained) }
                val other = if (engine == "driver") "cc1" else "driver"
                assertFails { GccBundledOperationIntent("e".repeat(64), other, intent.runKind, inputs, runtime,
                    budgets(), invocation.options.diskPolicy, retained, invocation) }
            }
        }
    }

    @Test
    fun `constructed driver intent admits ordinary full export and excludes legacy parallel diagnostic and interrupted modes`() = withNativeControls { root ->
        GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), "driver").use { retained ->
            for (version in listOf(1, 2, 3, 4, 5, 6, 7)) {
                val runtime = runtime(root, version)
                val inputs = artifacts(retained, "driver", runtime)
                val invocation = invocation(root, "driver", inputs, fullRecoveryExport = true, suffix = "-$version")
                fun intent(kind: GccCompilerEngineContainmentRunKind) = GccBundledOperationIntent("e".repeat(64), "driver",
                    kind, inputs, runtime, budgets(), invocation.options.diskPolicy, retained, invocation)
                if (version == 5) {
                    val selected = intent(GccCompilerEngineContainmentRunKind.FRESH_CONTROL)
                    assertEquals("gcc-bundled-operation-intent-v2", OracleJson.parseCanonical(selected.canonicalBytes)
                        .jsonObject.getValue("provider").jsonPrimitive.content)
                    selected.requireFullExportExecution()
                } else assertFails { intent(GccCompilerEngineContainmentRunKind.FRESH_CONTROL) }
                assertFails { intent(GccCompilerEngineContainmentRunKind.INTERRUPTED) }
                assertFails { intent(GccCompilerEngineContainmentRunKind.RESUMED) }
            }
        }
    }

    @Test
    fun `selected driver and cc1 independently admit their pinned native call input profiles`() {
        for (engine in listOf("cc1", "driver")) withNativeControls { root ->
            GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), engine).use { retained ->
                val policy = retained.policyBytes()
                val pinned = retained.requireNativeCallProfile()
                val target = retained.target(engine)
                assertEquals(engine, pinned.engineId)
                assertEquals(target.profileId, pinned.profileId)
                assertEquals(target.strippedArtifact.sha256, pinned.strippedBinary.sha256)
                assertEquals(target.oracleManifestSha256, pinned.artifactManifestSha256)
                val wall = if (engine == "cc1") 14_400_000L else 1_800_000L
                assertEquals(wall, retained.exportWallClockMillis(engine, false, nativeCallObservations = true))
                assertContentEquals(policy, retained.bindInvocation(engine, artifacts(retained, engine), budgets(wall),
                    bundledRuntime = runtime(root), nativeCallObservations = true))
                assertContentEquals(policy, retained.policyBytes())
                assertFalse(Files.exists(root.resolve("artifacts")), "admission controls must not materialize native binaries")
            }
        }
    }

    @Test
    fun `legacy implicit cc1 preserves its policy while explicit lto1 cannot inherit native admission`() = withNativeControls { root ->
        val path = root.resolve(PROFILE)
        GccRetainedCompilerEngineProfile.open(path).use { legacy ->
            GccRetainedCompilerEngineProfile.open(path, "cc1").use { explicit ->
                assertContentEquals(legacy.policyBytes(), explicit.policyBytes())
                assertEquals("cc1", legacy.requireNativeCallProfile().engineId)
                assertEquals(legacy.requireNativeCallProfile().strippedBinary, explicit.requireNativeCallProfile().strippedBinary)
            }
        }
        GccRetainedCompilerEngineProfile.open(path, "lto1").use { retained ->
            assertFails { retained.requireNativeCallProfile() }
            assertFails { retained.exportWallClockMillis("lto1", false, nativeCallObservations = true) }
            assertFails { retained.bindInvocation("lto1", artifacts(retained, "lto1"), budgets(),
                bundledRuntime = runtime(root), nativeCallObservations = true) }
            assertFails { retained.bindInvocation("cc1", artifacts(retained, "cc1"), budgets(),
                bundledRuntime = runtime(root), nativeCallObservations = true) }
        }
    }

    @Test
    fun `native invocation rejects cross-target engine binary manifest and build bindings`() = withNativeControls { root ->
        GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), "driver").use { driver ->
            GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), "cc1").use { cc1 ->
                val driverArtifacts = artifacts(driver, "driver")
                val cc1Artifacts = artifacts(cc1, "cc1")
                for ((selected, engine, own, other) in listOf(
                    NativeSelection(driver, "driver", driverArtifacts, cc1Artifacts),
                    NativeSelection(cc1, "cc1", cc1Artifacts, driverArtifacts),
                )) {
                    for (role in listOf(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
                        GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST,
                        GccCompilerEngineContainmentArtifactRole.BUILD_RECORD)) {
                        val substituted = own.map { entry -> if (entry.role == role) other.single { it.role == role } else entry }
                        assertFails { selected.bindInvocation(engine, substituted, budgets(),
                            bundledRuntime = runtime(root), nativeCallObservations = true) }
                    }
                    val otherEngine = if (engine == "driver") "cc1" else "driver"
                    assertFails { selected.bindInvocation(otherEngine, own, budgets(),
                        bundledRuntime = runtime(root), nativeCallObservations = true) }
                }
            }
        }
    }

    @Test
    fun `native target cannot select legacy diagnostic or mixed full-export contracts or exceed its budget`() {
        for (engine in listOf("cc1", "driver")) withNativeControls { root ->
            GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), engine).use { retained ->
                val artifacts = artifacts(retained, engine)
                for (runtime in listOf(null, runtime(root, 3), runtime(root, 5), runtime(root, 7))) {
                    assertFails { retained.bindInvocation(engine, artifacts, budgets(),
                        bundledRuntime = runtime, nativeCallObservations = true) }
                }
                assertFails { retained.bindInvocation(engine, artifacts, budgets(), fullRecoveryExport = true,
                    bundledRuntime = runtime(root), nativeCallObservations = true) }
                assertFails { retained.exportWallClockMillis(engine, false, runtimeDiagnostics = true, nativeCallObservations = true) }
                val wall = retained.exportWallClockMillis(engine, false, nativeCallObservations = true)
                assertFails { retained.bindInvocation(engine, artifacts, budgets(wall + 1),
                    bundledRuntime = runtime(root), nativeCallObservations = true) }
            }
        }
    }

    @Test
    fun `canonical-looking edited profiles and crossed driver truth cannot create native admission`() {
        for (engine in listOf("cc1", "driver")) withNativeControls { root ->
            val profile = root.resolve(PROFILE)
            Files.write(profile, Files.readAllBytes(profile) + '\n'.code.toByte())
            assertFails {
                GccRetainedCompilerEngineProfile.open(profile, engine).use { it.requireNativeCallProfile() }
            }
        }
        withNativeControls { root ->
            Files.copy(root.resolve("cc1-oracle-manifest.json"), root.resolve("oracle-manifest.json"), StandardCopyOption.REPLACE_EXISTING)
            assertFails {
                GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), "driver").use { it.requireNativeCallProfile() }
            }
        }
    }

    @Test
    fun `target ABI and retained control mutation fail before returning a native profile`() = withNativeControls { root ->
        val target = root.parent.parent.resolve("targets/sysv-amd64-v1.json")
        GccRetainedCompilerEngineProfile.open(root.resolve(PROFILE), "driver").use { retained ->
            val original = Files.readAllBytes(target)
            Files.write(target, original + '\n'.code.toByte())
            assertFails { retained.requireNativeCallProfile() }
            Files.write(target, original)
            val profile = root.resolve(PROFILE)
            Files.move(profile, root.resolve("original-profile.json"))
            Files.write(profile, Files.readAllBytes(root.resolve("original-profile.json")))
            assertFails { retained.requireNativeCallProfile() }
        }
    }

    private fun artifacts(retained: GccRetainedCompilerEngineProfile, engine: String,
        runtime: GccBundledGhidraRuntime? = null): List<GccCompilerEngineContainmentArtifactIdentity> {
        val suite = retained.suite
        val target = retained.target(engine)
        val root = suite.profilePath.parent
        val controls = mapOf(GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to suite.profilePath,
            GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
            GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to target.buildRecordPath,
            GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to target.oracleManifestPath,
            GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath)
        return GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.map { role ->
            controls[role]?.let { path -> GccCompilerEngineContainmentArtifactIdentity(role, path, Files.size(path),
                OracleArtifacts.sha256(Files.readAllBytes(path))) } ?: when (role) {
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY -> GccCompilerEngineContainmentArtifactIdentity(role,
                    root.resolve(target.strippedArtifact.relativePath), target.strippedArtifact.bytes, target.strippedArtifact.sha256)
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> GccCompilerEngineContainmentArtifactIdentity(role,
                    root.resolve(suite.analysis.ghidraArchive.relativePath), suite.analysis.ghidraArchive.bytes, suite.analysis.ghidraArchive.sha256)
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> GccCompilerEngineContainmentArtifactIdentity(role,
                    root.resolve("ExportProgramModel.java"), 1, suite.analysis.exporterSha256)
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> runtime?.classPath?.first()?.let {
                    GccCompilerEngineContainmentArtifactIdentity(role, it.path, it.bytes, it.sha256)
                } ?: GccCompilerEngineContainmentArtifactIdentity(role, root.resolve("unmaterialized-${role.wireName}"), 1, "a".repeat(64))
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> GccCompilerEngineContainmentArtifactIdentity(role,
                    runtime?.root?.resolve("scripts/RunBundledExports.class") ?: root.resolve("unmaterialized-${role.wireName}"), 1, "a".repeat(64))
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> GccCompilerEngineContainmentArtifactIdentity(role,
                    runtime?.root?.resolve("bundle.sha256") ?: root.resolve("unmaterialized-${role.wireName}"), 1, "a".repeat(64))
                else -> GccCompilerEngineContainmentArtifactIdentity(role, root.resolve("unmaterialized-${role.wireName}"), 1, "a".repeat(64))
            }
        }
    }

    private fun invocation(root: Path, engine: String, inputs: List<GccCompilerEngineContainmentArtifactIdentity>,
        fullRecoveryExport: Boolean = false, suffix: String = ""): GccBundledCliInvocation {
        val byRole = inputs.associateBy { it.role }
        val output = Files.createDirectory(root.parent.resolve("output-$engine$suffix"))
        val scratch = root.parent.resolve("scratch-$engine$suffix")
        val directories = listOf(output, Files.createDirectory(output.resolve("inputs")), Files.createDirectory(output.resolve("journal")))
        val arguments = listOf(engine, byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
            "--profile", byRole.getValue(GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE).path.toString(),
            "--ghidra-archive", byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE).path.toString(),
            "--output", output.toString(), "--scratch", scratch.toString())
        val options = GccBundledCliOptions.parse(arguments, fullRecoveryExport = fullRecoveryExport,
            nativeCallObservations = !fullRecoveryExport)
        val identities = directories.associateWith { LinuxFilesystemSyscalls.openRoot(it).use { directory -> directory.identity } }
        return GccBundledCliInvocation(options, arguments, identities)
    }

    private fun runtime(root: Path, version: Int = 8): GccBundledGhidraRuntime {
        val bundle = root.resolve("unmaterialized-runtime")
        return GccBundledGhidraRuntime(bundle, listOf(
            GccBundledGhidraClassPathEntry(bundle.resolve("decomp-ghidra-bridge.jar"), 1, "a".repeat(64)),
            GccBundledGhidraClassPathEntry(bundle.resolve("ghidra_12.1.3_PUBLIC/Ghidra/Framework/lib/runtime.jar"), 1, "b".repeat(64)),
        ), version, if (version == 8) GccBundledNativeCallCollectorIdentityV1(1, "c".repeat(64), 1, "d".repeat(64)) else null)
    }

    private fun budgets(wall: Long = 1_800_000L) = GccCompilerEngineContainmentBudgets(wall, 16L * 1024 * 1024 * 1024, 32)

    private fun withNativeControls(action: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp").toAbsolutePath().normalize())
        val scratch = Files.createTempDirectory(parent, "native-profile-")
        val root = Files.createDirectories(scratch.resolve("oracle/gcc/16.2.0"))
        try {
            for (name in CONTROLS) {
                Files.copy(Path.of("oracle/gcc/16.2.0").resolve(name), root.resolve(name))
                Files.setPosixFilePermissions(root.resolve(name), PosixFilePermissions.fromString("rw-------"))
            }
            val targets = Files.createDirectories(scratch.resolve("oracle/targets"))
            Files.copy(Path.of("oracle/targets/sysv-amd64-v1.json"), targets.resolve("sysv-amd64-v1.json"))
            action(root)
        } finally {
            Files.walk(scratch).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private data class NativeSelection(val retained: GccRetainedCompilerEngineProfile, val engine: String,
        val own: List<GccCompilerEngineContainmentArtifactIdentity>, val other: List<GccCompilerEngineContainmentArtifactIdentity>)

    private companion object {
        const val PROFILE = "compiler-engines-exporter17.json"
        val CONTROLS = listOf(PROFILE, "source-lock.json", "build-record.json", "toolchain-reproduction.json",
            "build-toolchain.Dockerfile", "cc1-build-record.json", "cc1-oracle-manifest.json", "lto1-build-record.json",
            "lto1-oracle-manifest.json", "oracle-manifest.json", "structural-full-export-profile-exporter17.json")
    }
}
