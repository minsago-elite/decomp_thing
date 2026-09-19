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
