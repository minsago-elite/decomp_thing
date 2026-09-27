package decompengine.oracle.gcc

import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledDriverOperationTest {
    @Test
    fun `driver intent retains and independently reopens its selected export policy`() = profileFixture { path ->
        lateinit var prepared: GccBundledOperationIntent
        lateinit var expectedPolicy: ByteArray
        GccRetainedCompilerEngineProfile.open(path, "driver").use { profile ->
            expectedPolicy = profile.policyBytes()
            prepared = intent(profile, artifacts = profileArtifacts(profile, "driver"))
            val document = OracleJson.parseCanonical(prepared.canonicalBytes).jsonObject
            assertEquals("driver", document.getValue("engineId").jsonPrimitive.content)
            assertEquals("fresh-control", document.getValue("runKind").jsonPrimitive.content)
            assertEquals(OracleJson.parseCanonical(expectedPolicy), document.getValue("plannerProfile"))
            assertEquals("driver", document.getValue("plannerProfile").jsonObject.getValue("target")
                .jsonObject.getValue("id").jsonPrimitive.content)
            assertEquals("driver", prepared.diskOperation().shardId)
        }
        // Preparation retains policy bytes, so reopening must select driver after the original handle closes.
        assertNotNull(prepared.openPlannerProfile(emptyList())).use { reopened ->
            assertContentEquals(expectedPolicy, reopened.policyBytes())
            assertEquals("driver", reopened.target("driver").id)
            assertFailsWith<IllegalArgumentException> { reopened.target("cc1") }
            assertEquals(listOf("cc1", "lto1"), reopened.suite.engines.map { it.id })
        }
    }

    @Test
    fun `driver intent refuses planning resume missing profiles and cross paired targets`() = profileFixture { path ->
        GccRetainedCompilerEngineProfile.open(path, "driver").use { driver ->
            val selected = profileArtifacts(driver, "driver")
            for ((version, kind) in forbiddenDriverModes()) {
                if (version == null) continue // Operation intents always require a bundled runtime.
                val failure = assertFailsWith<IllegalArgumentException>("v$version $kind") {
                    intent(driver, version = version, kind = kind, artifacts = selected)
                }
                assertTrue(failure.message.orEmpty().contains("driver"), failure.message)
            }
            assertFailsWith<IllegalArgumentException> { intent(null, artifacts = selected) }
            assertFailsWith<IllegalArgumentException> { intent(driver, engine = "cc1", artifacts = selected) }
            GccRetainedCompilerEngineProfile.open(path, "cc1").use { engines ->
                assertFailsWith<IllegalArgumentException> { intent(engines, artifacts = selected) }
                val cc1 = engines.target("cc1")
                val crossPaired = selected.map { artifact ->
                    if (artifact.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY) {
                        artifact.copy(bytes = cc1.strippedArtifact.bytes, sha256 = cc1.strippedArtifact.sha256)
                    } else artifact
                }
                val mismatch = assertFailsWith<IllegalArgumentException> { intent(driver, artifacts = crossPaired) }
                assertTrue(mismatch.message.orEmpty().contains("engine differs"), mismatch.message)
                // Existing engine planning and cc1 full export remain separate admitted selections.
                for (engine in listOf("cc1", "lto1")) {
                    intent(engines, engine = engine, version = 3, artifacts = profileArtifacts(engines, engine))
                }
                intent(engines, engine = "cc1", artifacts = profileArtifacts(engines, "cc1"))
                assertFailsWith<IllegalArgumentException> {
                    intent(engines, engine = "lto1", artifacts = profileArtifacts(engines, "lto1"))
                }
            }
        }
    }

    @Test
    fun `driver containment is a nonauthoritative v5 fresh definition with an exact roundtrip`() {
        val assessment = GccCompilerEngineContainmentContract.assessDefinition(request("driver", 5, FRESH))
        assertEquals("non-authoritative-caller-supplied-containment-bytes-v1", assessment.authority)
        assertFalse(assessment.releaseEligible)
        assertFalse(assessment.startAuthorized)
        assertEquals("decomp-gcc-driver-${assessment.requestSha256.take(32)}.scope", assessment.unitName)
        val parsed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(assessment.canonicalBytes)
        assertEquals("driver", parsed.engineId)
        assertEquals(FRESH, parsed.runKind)
        assertEquals(5, assertNotNull(parsed.bundledRuntime).invocationVersion)
        assertEquals(GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, parsed.analysisState.mode)
        assertContentEquals(assessment.canonicalBytes, parsed.canonicalBytes)
    }

    @Test
    fun `driver containment rejects legacy planning resumed and interrupted definitions`() {
        for ((version, kind) in forbiddenDriverModes()) {
            val failure = assertFailsWith<IllegalArgumentException>("v$version $kind") {
                request("driver", version, kind)
            }
            assertTrue(failure.message.orEmpty().contains("driver containment"), failure.message)
            if (version != 5) {
                // These same legacy/planning/resume combinations are still valid for both engines.
                for (engine in listOf("cc1", "lto1")) {
                    GccCompilerEngineContainmentContract.assessDefinition(request(engine, version, kind))
                }
            }
        }
    }

    @Test
    fun `rehashing an engine definition cannot admit a driver in a forbidden runtime mode`() {
        val full = GccCompilerEngineContainmentContract.assessDefinition(request("cc1", 5, FRESH)).canonicalBytes
        val validDriver = replaceEngineAndRehash(full, "driver")
        assertEquals("driver", GccCompilerEngineContainmentContract.parseDefinitionForLiveController(validDriver).engineId)
        for ((version, kind) in forbiddenDriverModes().filter { it.first != 5 }) {
            val original = GccCompilerEngineContainmentContract.assessDefinition(request("cc1", version, kind)).canonicalBytes
            val mutated = replaceEngineAndRehash(original, "driver")
            val failure = assertFailsWith<IllegalArgumentException>("v$version $kind") {
                GccCompilerEngineContainmentContract.parseDefinitionForLiveController(mutated)
            }
            assertTrue(failure.message.orEmpty().contains("driver containment"), failure.message)
        }
        val interrupted = replaceEngineAndRehash(full, "driver", GccCompilerEngineContainmentRunKind.INTERRUPTED)
        val failure = assertFailsWith<IllegalArgumentException> {
            GccCompilerEngineContainmentContract.parseDefinitionForLiveController(interrupted)
        }
        assertTrue(failure.message.orEmpty().contains("driver containment"), failure.message)
    }

    private fun intent(
        profile: GccRetainedCompilerEngineProfile?,
        engine: String = "driver",
        version: Int = 5,
        kind: GccCompilerEngineContainmentRunKind = FRESH,
        artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
    ) = GccBundledOperationIntent(SHA, engine, kind, artifacts, runtime(version), budgets(),
        FullTreeDiskScratchPolicy(1024 * 1024, 64L * 1024 * 1024, 128, 4096), profile)

    private fun profileArtifacts(profile: GccRetainedCompilerEngineProfile, engine: String): List<GccCompilerEngineContainmentArtifactIdentity> {
        val target = profile.target(engine)
        val suite = profile.suite
        val controls = mapOf(
            GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to suite.profilePath,
            GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
            GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to target.buildRecordPath,
            GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to target.oracleManifestPath,
            GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath,
        )
        return artifacts(runtime(5)).map { artifact ->
            controls[artifact.role]?.let { path ->
                artifact.copy(path = path, bytes = Files.size(path), sha256 = OracleArtifacts.sha256(Files.readAllBytes(path)))
            } ?: when (artifact.role) {
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY ->
                    artifact.copy(bytes = target.strippedArtifact.bytes, sha256 = target.strippedArtifact.sha256)
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE ->
                    artifact.copy(bytes = suite.analysis.ghidraArchive.bytes, sha256 = suite.analysis.ghidraArchive.sha256)
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> artifact.copy(sha256 = suite.analysis.exporterSha256)
                else -> artifact
            }
        }
    }

    private fun request(engine: String, version: Int?, kind: GccCompilerEngineContainmentRunKind): GccCompilerEngineContainmentRequest {
        val runtime = version?.let(::runtime)
        val artifacts = artifacts(runtime)
        val state = if (kind == GccCompilerEngineContainmentRunKind.RESUMED) {
            GccCompilerEngineAnalysisStateIdentity(GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
                LEASE_ROOT.resolve("state"), SHA, 1, 1)
        } else GccCompilerEngineAnalysisStateIdentity(GccCompilerEngineAnalysisStateMode.FRESH_EMPTY,
            LEASE_ROOT.resolve("state"), null, 0, 0)
        val lease = GccCompilerEngineOutputLeaseIdentity(LEASE_ROOT, 1, 2, 3, 1000, 1000, 448, 1024, 2048, 128, 256)
        val byRole = artifacts.associateBy { it.role }
        val command = runtime?.command(artifacts, state, lease,
            // Construct a valid v5 command first so the request's driver/run-kind gate is tested.
            if (version == 5 && kind == GccCompilerEngineContainmentRunKind.INTERRUPTED) FRESH else kind)
            ?: listOf(
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS).path.toString(),
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE).path.toString(),
                state.path.toString(), lease.path.toString(),
            )
        return GccCompilerEngineContainmentRequest(engine, kind, artifacts, state, command,
            mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), lease, budgets(), runtime)
    }

    private fun forbiddenDriverModes(): List<Pair<Int?, GccCompilerEngineContainmentRunKind>> = listOf(
        null to FRESH, 1 to FRESH, 2 to FRESH, 3 to FRESH,
        3 to GccCompilerEngineContainmentRunKind.INTERRUPTED,
        4 to GccCompilerEngineContainmentRunKind.RESUMED,
        5 to GccCompilerEngineContainmentRunKind.INTERRUPTED,
    )

    private fun runtime(version: Int) = GccBundledGhidraRuntime(BUNDLE_ROOT, listOf(
        GccBundledGhidraClassPathEntry(BUNDLE_ROOT.resolve("decomp-ghidra-bridge.jar"), 32, SHA),
        GccBundledGhidraClassPathEntry(BUNDLE_ROOT.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Framework/Module/lib/module.jar"), 64, SHA),
    ), invocationVersion = version)

    private fun artifacts(runtime: GccBundledGhidraRuntime?): List<GccCompilerEngineContainmentArtifactIdentity> =
        (if (runtime == null) GCC_LEGACY_CONTAINMENT_ARTIFACT_ROLES else GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES).mapIndexed { index, role ->
            GccCompilerEngineContainmentArtifactIdentity(role, when (role) {
                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> BUNDLE_ROOT.resolve("decomp-ghidra-bridge.jar")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> BUNDLE_ROOT.resolve("scripts/RunBundledExports.class")
                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> BUNDLE_ROOT.resolve("bundle.sha256")
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/trusted/scripts/ExportProgramModel.java")
                else -> Path.of("/trusted/${role.wireName}")
            }, if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR) 32 else index + 1L,
                if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE) BundledGhidra.ARCHIVE_SHA256 else SHA)
        }

    private fun budgets() = GccCompilerEngineContainmentBudgets(60_000, 512L * 1024 * 1024, 32)

    private fun replaceEngineAndRehash(bytes: ByteArray, engine: String, kind: GccCompilerEngineContainmentRunKind? = null): ByteArray {
        val document = OracleJson.parseCanonical(bytes).jsonObject
        val request = JsonObject(document.getValue("request").jsonObject + mapOf("engineId" to JsonPrimitive(engine)) +
            (kind?.let { mapOf("runKind" to JsonPrimitive(it.wireName)) } ?: emptyMap()))
        // Engine/run-kind are request fields; command/runtime/input/lease sub-preimages are unchanged.
        val requestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(request))
        val unsigned = JsonObject(document - "bindingSha256" + mapOf(
            "request" to request,
            "requestSha256" to JsonPrimitive(requestSha256),
            "unitName" to JsonPrimitive("decomp-gcc-$engine-${requestSha256.take(32)}.scope"),
        ))
        return OracleJson.canonicalBytes(JsonObject(unsigned + ("bindingSha256" to
            JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned))))))
    }

    private fun profileFixture(action: (Path) -> Unit) {
        val temporaryRoot = Files.createDirectories(Path.of("build", "test-tmp"))
        val root = Files.createTempDirectory(temporaryRoot, "gcc-driver-operation-").toRealPath()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            val checked = Path.of("oracle/gcc/16.2.0/compiler-engines.json").toRealPath()
            GccRetainedCompilerEngineProfile.open(checked, "driver").use { source ->
                OracleJson.parseCanonical(source.policyBytes()).jsonObject.getValue("inputs").jsonArray.forEach { entry ->
                    val input = Path.of(entry.jsonObject.getValue("path").jsonPrimitive.content)
                    val copied = Files.copy(input, root.resolve(input.fileName))
                    Files.setPosixFilePermissions(copied, PosixFilePermissions.fromString("rw-------"))
                }
            }
            action(root.resolve("compiler-engines.json"))
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private companion object {
        const val SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val BUNDLE_ROOT: Path = Path.of("/trusted/driver-test-bundle")
        val LEASE_ROOT: Path = Path.of("/scratch/driver-test-run")
        val FRESH = GccCompilerEngineContainmentRunKind.FRESH_CONTROL
    }
}
