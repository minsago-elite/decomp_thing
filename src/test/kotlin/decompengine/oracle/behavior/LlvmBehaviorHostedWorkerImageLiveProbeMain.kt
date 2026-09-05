package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Test-source-only entry point for the required live worker-image retained-tool regression. */
internal object LlvmBehaviorHostedWorkerImageLiveProbeMain {
    @JvmStatic
    fun main(arguments: Array<String>) {
        if (arguments.isNotEmpty()) error("live worker-image retained-tool probe accepts no arguments")
        if (Files.exists(CANDIDATE_SCRIPT_MARKER, LinkOption.NOFOLLOW_LINKS)) {
            error("candidate-controlled build script marker existed before the retained-tool probe")
        }

        val toolchain = LlvmBehaviorHostedRetainedToolChecks.requireToolchain()
        LlvmBehaviorHostedRetainedToolChecks.executableReplacement(toolchain)
        LlvmBehaviorHostedRetainedToolChecks.sourceAndHeaderReplacement(toolchain)
        LlvmBehaviorHostedRetainedToolChecks.objectReplacement(toolchain)
        LlvmBehaviorHostedRetainedToolChecks.outsideHeaderRejected()

        val assessment = LlvmBehaviorHostedCleanBuildV2TestSupport.assess(
            FIRST_SOURCE_ROOT,
            SECOND_SOURCE_ROOT,
        )

        if (assessment.sourceCount != 2) error("retained-tool probe compiled an unexpected source count")
        if (assessment.firstBuildEnvironmentSha256 != assessment.secondBuildEnvironmentSha256) {
            error("retained-tool probe build environments differ")
        }
        if (assessment.firstCompileCommandSetSha256 != assessment.secondCompileCommandSetSha256) {
            error("retained-tool probe compile command sets differ")
        }
        if (assessment.dependencyCount < assessment.sourceCount ||
            assessment.firstDependencySetSha256 != assessment.secondDependencySetSha256
        ) {
            error("retained-tool probe dependency sets differ")
        }
        if (assessment.firstObjectSetSha256 != assessment.secondObjectSetSha256) {
            error("retained-tool probe object sets differ")
        }
        if (assessment.firstLinkCommandSha256 != assessment.secondLinkCommandSha256) {
            error("retained-tool probe direct-LLD commands differ")
        }
        if (assessment.linkPlanInputCount != assessment.sourceCount + 12 ||
            assessment.firstLinkPlanSha256 != assessment.secondLinkPlanSha256
        ) {
            error("retained-tool probe direct-LLD input plans differ")
        }
        if (assessment.firstCombinedOutputBytes != assessment.secondCombinedOutputBytes ||
            assessment.firstCombinedOutputSha256 != assessment.secondCombinedOutputSha256
        ) {
            error("retained-tool probe combined outputs differ")
        }
        if (assessment.executableBytes != assessment.executable.size.toLong() ||
            assessment.executableSha256 != OracleArtifacts.sha256(assessment.executable)
        ) {
            error("retained-tool probe executable commitment differs")
        }
        val executable = assessment.executable
        if (executable.size < 4 || executable[0] != 0x7f.toByte() ||
            executable[1] != 'E'.code.toByte() || executable[2] != 'L'.code.toByte() ||
            executable[3] != 'F'.code.toByte()
        ) {
            error("retained-tool probe did not link an ELF executable")
        }
        if (Files.exists(CANDIDATE_SCRIPT_MARKER, LinkOption.NOFOLLOW_LINKS)) {
            error("candidate-controlled build script ran during the retained-tool probe")
        }

        System.out.print(
            "$RESULT_MAGIC ${assessment.executableSha256} ${assessment.executableBytes} swaps=5 outside-header=blocked\n",
        )
    }

    private val FIRST_SOURCE_ROOT = Path.of("/inputs/retained-tool-source-one")
    private val SECOND_SOURCE_ROOT = Path.of("/inputs/retained-tool-source-two")
    private val CANDIDATE_SCRIPT_MARKER = Path.of("/stage-output/candidate-build-script-ran")
    private const val RESULT_MAGIC = "DECOMP_LLVM_HOSTED_WORKER_RETAINED_TOOL_TEST_V2"
}
