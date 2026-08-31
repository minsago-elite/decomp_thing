package decompengine.oracle.behavior

import java.nio.file.Path

/**
 * Fixed checked-profile admission gate for LLVM behavior reference evidence.
 *
 * This command authenticates retained evidence only. It does not execute Clang, replay the
 * historical sandbox, compare a reconstruction, score behavior, or authorize a release.
 */
object LlvmBehaviorReferenceEvidenceCli {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.isEmpty()) { "LLVM behavior reference verification accepts no arguments" }
        val profile = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
        val evidence = LlvmBehaviorReferenceEvidenceVerifier.verify(
            corpusPath = profile.resolve("behavior-corpus.json"),
            reportPath = profile.resolve("behavior-corpus-evidence.json"),
            diagnosticMatrixPath = profile.resolve("diagnostic-matrix.json"),
            artifactManifestPath = profile.resolve("oracle-manifest.json"),
        )
        println(
            "verified ${evidence.caseIds.size} checked LLVM behavior cases and " +
                "${evidence.diagnosticOwners.size} diagnostic ownership records: " +
                evidence.corpusSha256,
        )
    }
}
