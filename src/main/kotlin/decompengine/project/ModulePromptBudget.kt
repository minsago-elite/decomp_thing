package decompengine.project

internal fun moduleClaimsAgentExecution(generator: String, reconstructorIdentity: String): Boolean =
    generator.startsWith("agent:") || generator.startsWith("unresolved:agent:") ||
        reconstructorIdentity.startsWith("agent:")

/** Accepted agent evidence must attribute a prompt bounded by the selected profile. */
internal fun modulePromptBudgetIsValid(
    promptCharacters: Long?,
    promptBudgetCharacters: Long?,
    profile: ReconstructionProfile,
): Boolean = promptCharacters != null && promptBudgetCharacters != null &&
    promptBudgetCharacters in 1..profile.budgets.reconstructionMaximumContextCharacters.toLong() &&
    promptCharacters in 0..promptBudgetCharacters

/**
 * Prompt attribution follows the fresh-result rules whenever it is recorded: results that
 * claim agent execution must attribute a prompt, and any recorded prompt metadata must
 * attribute both size and budget within the selected profile. Reusing accepted checkpoints
 * applies the same rule so legacy over-budget metadata is revalidated, not silently accepted.
 */
internal fun modulePromptAttributionIsValid(
    claimsAgentExecution: Boolean,
    promptCharacters: Long?,
    promptBudgetCharacters: Long?,
    profile: ReconstructionProfile,
): Boolean = !(claimsAgentExecution || promptCharacters != null || promptBudgetCharacters != null) ||
    modulePromptBudgetIsValid(promptCharacters, promptBudgetCharacters, profile)
