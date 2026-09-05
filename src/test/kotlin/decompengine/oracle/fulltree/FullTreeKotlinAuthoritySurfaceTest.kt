package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class FullTreeKotlinAuthoritySurfaceTest {
    @Test
    fun `LLVM workflow uses stable Kotlin scope and inventory entrypoints`() {
        val build = Path.of("build.gradle.kts").readText()
        val workflow = Path.of(".github/workflows/llvm-oracle-model.yml").readText()

        mapOf(
            "verifyFullTreeScope" to "decompengine.oracle.fulltree.FullTreeScopeVerifierCli",
            "generateFullTreeInventory" to "decompengine.oracle.fulltree.FullTreeInventoryGeneratorCli",
            "generateFullTreeSourceInventory" to
                "decompengine.oracle.fulltree.FullTreeSourceInventoryGeneratorCli",
            "generateFullTreePlanningInventory" to
                "decompengine.oracle.fulltree.FullTreePlanningInventoryGeneratorCli",
            "verifyLlvmOracleArtifacts" to
                "decompengine.oracle.provenance.LlvmArtifactManifestVerifierCli",
            "generateLlvmFunctionRecoveryOracle" to
                "decompengine.oracle.provenance.LlvmFunctionOracleGeneratorCli",
        ).forEach { (task, entryPoint) ->
            assertTrue(build.contains("taskName = \"$task\""))
            assertTrue(build.contains("entryPoint = \"$entryPoint\""))
            assertTrue(workflow.contains("./gradlew --no-daemon $task"))
        }

        assertTrue(workflow.contains("full-tree-source-inventory.json"))
        assertTrue(workflow.contains("oracle/llvm/22.1.6/full-tree-source-inventory.json"))
        assertTrue(workflow.contains("full-tree-planning-inventory.json"))
        assertTrue(workflow.contains("oracle/llvm/22.1.6/full-tree-planning-inventory.json"))
        assertTrue(build.contains("taskName = \"generateFullTreeGeneratedFileInventory\""))
        assertTrue(
            build.contains(
                "entryPoint = \"decompengine.oracle.fulltree.FullTreeGeneratedFileInventoryGeneratorCli\"",
            ),
        )
        assertFalse(workflow.contains("python3 scripts/verify-llvm-full-tree-scope.py"))
        assertFalse(workflow.contains("python3 scripts/generate-llvm-full-tree-inventory.py"))
        assertFalse(workflow.contains("python3 scripts/generate-llvm-full-tree-source-inventory.py"))
        assertFalse(workflow.contains("python3 scripts/generate-llvm-full-tree-planning-inventory.py"))
        assertTrue(workflow.contains("./gradlew --no-daemon fetchLlvmSourceArchive"))
        assertFalse(workflow.contains("python3 scripts/verify-llvm-oracle-source.py"))
        assertFalse(workflow.contains("python3 scripts/fetch-llvm-oracle-source.py"))
        assertFalse(workflow.contains("python3 scripts/verify-llvm-oracle-artifacts.py"))
        assertFalse(workflow.contains("python3 scripts/generate-llvm-function-recovery-oracle.py"))
        assertFalse(workflow.contains("tests.oracle.test_llvm_source_lock"))

        assertTrue(workflow.contains("decompengine.oracle.provenance.LlvmBuildEnvironmentVerifierCli"))
        assertTrue(workflow.contains("--entrypoint /decomp-jdk/bin/java"))
        assertTrue(workflow.contains("-Djna.nosys=true"))
        assertTrue(workflow.contains("-Djna.tmpdir=/decomp-jna"))
        assertTrue(workflow.contains("/decomp-app/lib/*"))
        assertFalse(workflow.contains("scripts/verify-llvm-oracle-build-record.py"))

        // Unmigrated compatibility regressions stay active until equivalent Kotlin authorities exist.
        listOf(
            "python3 scripts/check-behavior-corpus-evidence.py",
            "python3 -m unittest",
        ).forEach { retainedGate -> assertTrue(workflow.contains(retainedGate)) }
    }

    @Test
    fun `LLVM clean rebuild verifies build tools through Kotlin inside the authenticated image`() {
        val workflow = Path.of(".github/workflows/llvm-oracle-rebuild.yml").readText()

        assertTrue(workflow.contains("./gradlew --no-daemon installDist"))
        assertTrue(workflow.contains("decompengine.oracle.provenance.LlvmBuildEnvironmentVerifierCli"))
        assertTrue(workflow.contains("/decomp-jdk/bin/java"))
        assertTrue(workflow.contains("-Djna.nosys=true"))
        assertTrue(workflow.contains("-Djna.tmpdir=/decomp-jna"))
        assertTrue(workflow.contains("-cp \"/decomp-app/lib/*\""))
        assertTrue(workflow.contains("build-record-verification.txt"))
        assertTrue(workflow.contains("--read-only"))
        assertTrue(workflow.contains("--tmpfs /tmp:rw,nosuid,nodev,noexec"))
        assertTrue(workflow.contains("--tmpfs /decomp-jna:rw,nosuid,nodev,exec,size=16777216,nr_inodes=128,mode=0700"))
        assertFalse(workflow.contains("scripts/capture-oracle-tools.py"))
        assertFalse(workflow.contains("tool-records.json"))
    }

    @Test
    fun `retained Python control wrappers disclaim Kotlin release authority`() {
        listOf(
            "scripts/verify-llvm-full-tree-scope.py",
            "scripts/generate-llvm-full-tree-inventory.py",
            "scripts/generate-llvm-full-tree-source-inventory.py",
        ).forEach { path ->
            val wrapper = Path.of(path).readText()
            assertTrue(wrapper.contains("Legacy Python compatibility"))
            assertTrue(wrapper.contains("not Kotlin/JVM oracle or release authority"))
        }

        val guide = Path.of("docs/oracle-acp-trust-boundary.md").readText()
        assertTrue(guide.contains("stable Kotlin/JVM Gradle entrypoints"))
        assertTrue(guide.contains("cannot authorize or enter a Kotlin-only release"))

        val manifestWrapper = Path.of("scripts/verify-llvm-oracle-artifacts.py").readText()
        assertTrue(manifestWrapper.contains("Legacy non-authoritative Python compatibility"))
        assertTrue(manifestWrapper.contains("cannot validate or certify a new Kotlin-only release"))

        val manifestGenerator = Path.of("scripts/create-llvm-oracle-manifest.py").readText()
        assertTrue(manifestGenerator.contains("Legacy non-authoritative Python compatibility"))
        assertTrue(manifestGenerator.contains("cannot validate, certify"))
        assertTrue(manifestGenerator.contains("non-authoritative LLVM oracle manifest candidate"))

        listOf(
            "scripts/verify-llvm-oracle-build-record.py",
            "scripts/capture-oracle-tools.py",
        ).forEach { path ->
            val wrapper = Path.of(path).readText()
            assertTrue(wrapper.contains("Legacy non-authoritative Python compatibility"), path)
            assertTrue(wrapper.contains("Kotlin/JVM"), path)
            assertTrue(wrapper.contains("cannot"), path)
        }
    }

    @Test
    fun `function truth keeps ACP and Python outside oracle authority`() {
        val source = Path.of(
            "src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionTruthSqlite.kt",
        ).readText()
        val guide = Path.of("docs/oracle-acp-trust-boundary.md").readText()

        assertTrue(source.contains("internal object FullTreeFunctionTruthSqlite"))
        assertTrue(source.contains("val authoritativeReleaseEvidence: Boolean = false"))
        assertTrue(source.contains("fun loadAndValidate("))
        assertTrue(source.contains("val rawInputsRederived: Boolean = true"))
        assertTrue(source.contains("val candidateLeaseRetained: Boolean = false"))
        assertTrue(source.contains("val downstreamScoringAuthorized: Boolean = false"))
        assertTrue(source.contains("The candidate is read-only input"))
        assertTrue(source.contains("exactly the generic four-member bounded-shard tree"))
        assertFalse(source.contains("generatePinnedDifferentialFixtureForTesting"))
        assertFalse(source.contains("ProcessBuilder"))
        assertFalse(source.contains("oracle.full_tree_function_truth"))
        assertFalse(source.contains("AcpAgentHarness"))

        val baselineSource = Path.of(
            "src/main/kotlin/decompengine/oracle/fulltree/FullTreeFunctionBaselineSqlite.kt",
        ).readText()
        assertTrue(baselineSource.contains("internal object FullTreeFunctionBaselineSqlite"))
        assertTrue(baselineSource.contains("internal fun generateAndPublishFromRawInputs("))
        assertTrue(baselineSource.contains("private fun publishNonAuthoritativeProjection("))
        assertTrue(baselineSource.contains("val candidateLeaseRetained: Boolean = false"))
        assertTrue(baselineSource.contains("val downstreamScoringAuthorized: Boolean = false"))
        assertTrue(baselineSource.contains("val authoritativeReleaseEvidence: Boolean = false"))
        assertTrue(baselineSource.contains("never accepts candidate truth as a"))
        assertFalse(baselineSource.contains("ProcessBuilder"))
        assertFalse(baselineSource.contains("oracle.full_tree_function_baseline"))
        assertFalse(baselineSource.contains("AcpAgentHarness"))
        assertFalse(source.contains("AcpClient"))

        val baselineParityRoot = Path.of(
            "src/test/resources/oracle/full-tree-function-baseline-raw-v1",
        )
        val baselineParityMembers = Files.walk(baselineParityRoot).use { paths ->
            paths.filter { Files.isRegularFile(it) }
                .map { baselineParityRoot.relativize(it).toString() }
                .toList()
                .toSet()
        }
        assertEquals(
            setOf(
                "PROVENANCE.txt",
                "expected/report.json.b64",
                "expected/historical-python-v1-report.json.b64",
            ),
            baselineParityMembers,
        )
        assertFalse(baselineParityMembers.any { it.endsWith(".json") })
        val baselineParityProvenance = baselineParityRoot.resolve("PROVENANCE.txt").readText()
        assertTrue(baselineParityProvenance.contains("NON-AUTHORITATIVE"))
        assertTrue(baselineParityProvenance.contains("grants no"))
        assertTrue(baselineParityProvenance.contains("Python did not generate or validate"))
        assertTrue(baselineParityProvenance.contains("inert differential fixture"))
        assertTrue(baselineParityProvenance.contains("without invoking Python"))

        val parityRoot = Path.of(
            "src/test/resources/oracle/full-tree-function-truth-raw-v2",
        )
        val parityMembers = Files.walk(parityRoot).use { paths ->
            paths.filter { Files.isRegularFile(it) }
                .map { parityRoot.relativize(it).toString() }
                .toList()
                .toSet()
        }
        assertEquals(
            setOf(
                "PROVENANCE.txt",
                "expected/clang-lib-driver.json.b64",
                "expected/exclusions.json.b64",
                "expected/generated-tools-clang.json.b64",
                "expected/index.json.b64",
            ),
            parityMembers,
        )
        assertFalse(parityMembers.any { it.endsWith(".json") })
        val parityProvenance = parityRoot.resolve("PROVENANCE.txt").readText()
        assertTrue(parityProvenance.contains("not an oracle"))
        assertTrue(parityProvenance.contains("not an ingestible full-tree truth publication"))

        assertTrue(guide.contains("Full-tree function-truth v2 now also has an internal Kotlin/SQLite"))
        assertTrue(guide.contains("authoritativeReleaseEvidence=false"))
        assertTrue(guide.contains("canonical-path"))
        assertTrue(guide.contains("presence is therefore never a bearer capability"))
        assertTrue(guide.contains("the candidate index contributes no expected fact"))
        assertTrue(guide.contains("Validation failure never repairs"))
        assertTrue(guide.contains("does not reuse that detached receipt"))
        assertTrue(guide.contains("fixed SQLite baseline composition"))
        assertTrue(guide.contains("neither downstream scoring nor release authority"))
        assertTrue(guide.contains("an ACP consumer must not infer authority"))
    }
}
