package decompengine.project

import java.nio.file.Path

/** Adapts deterministic test analyzers to the archival service's budget-binding contract. */
fun budgetedAnalyzer(
    analyze: (binaryPath: Path, workDir: Path) -> RecoveredProgramModel,
): ExportBudgetedProgramModelAnalyzer = object : ExportBudgetedProgramModelAnalyzer {
    override fun analyze(binaryPath: Path, workDir: Path): RecoveredProgramModel = analyze.invoke(binaryPath, workDir)

    override fun withExportBudgets(budgets: ReconstructionBudgets): ProgramModelAnalyzer = this
}
