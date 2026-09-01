package decompengine.oracle.behavior

import java.nio.file.Files
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LlvmBehaviorLegacyEvidenceMarkerTest {
    @Test
    fun `candidate lineage production verifier rejects actual v1 identities`() {
        (FORBIDDEN_V1_IDENTITIES + RETAINED_LINEAGE_MARKERS).forEachIndexed { index, identity ->
            val root = createTempDirectory("candidate-lineage-legacy-$index-").toAbsolutePath().normalize()
            val archive = root.resolve("candidate.zip")
            val indexParent = root.resolve("lineage")
            Files.writeString(archive, "archive validation must not precede legacy syntax rejection")
            Files.createDirectory(indexParent)
            Files.setPosixFilePermissions(indexParent, PosixFilePermissions.fromString("rwx------"))
            val lineageIndex = indexParent.resolve("candidate-acp-lineage-index-v2.json")
            Files.writeString(lineageIndex, identity)
            Files.setPosixFilePermissions(lineageIndex, PosixFilePermissions.fromString("r--------"))

            val failure = assertFailsWith<LlvmBehaviorCandidateAcpLineageIndexV2Exception> {
                LlvmBehaviorCandidateAcpLineageIndexV2Verifier.verify(archive, lineageIndex)
            }
            assertTrue(failure.message.orEmpty().contains("forbidden Python or legacy behavior material"))
        }
    }

    @Test
    fun `hosted syntax boundary rejects actual v1 identities and retained unsafe markers`() {
        (FORBIDDEN_V1_IDENTITIES + RETAINED_HOSTED_MARKERS).forEach { marker ->
            val failure = assertFailsWith<LlvmBehaviorHostedCleanBuildV2Exception> {
                LlvmBehaviorHostedCleanBuildV2TestSupport.requireNoLegacyEvidenceText(marker)
            }
            assertTrue(failure.message.orEmpty().contains("forbidden Python, remote, or legacy behavior material"))
        }
        LlvmBehaviorHostedCleanBuildV2TestSupport.requireNoLegacyEvidenceText("reports/build_contract.json")
    }

    private companion object {
        val FORBIDDEN_V1_IDENTITIES = listOf(
            "llvm-behavior-candidate-execution-admission",
            "kotlin-host-pre-start-binding-v1",
            "llvm-behavior-runtime-preflight",
            "kotlin-host-live-runtime-preflight-v1",
        )
        val RETAINED_LINEAGE_MARKERS = listOf(
            "PYTHON",
            "behavior-preexec-v1",
            "oci-container-v1",
        )
        val RETAINED_HOSTED_MARKERS = listOf(
            *RETAINED_LINEAGE_MARKERS.toTypedArray(),
            "http://legacy.invalid",
            "https://legacy.invalid",
        )
    }
}
