package decompengine.oracle.fulltree

import java.nio.file.Path
import kotlin.io.path.readText
import kotlin.test.Test
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

        // Unmigrated regression gates stay active until equivalent Kotlin authorities exist.
        listOf(
            "scripts/verify-llvm-oracle-build-record.py",
            "python3 scripts/check-behavior-corpus-evidence.py",
            "python3 -m unittest",
        ).forEach { retainedGate -> assertTrue(workflow.contains(retainedGate)) }
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
    }
}
