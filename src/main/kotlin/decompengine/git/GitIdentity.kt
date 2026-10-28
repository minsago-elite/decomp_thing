package decompengine.git

/**
 * Repository object format. Object IDs are opaque lowercase hexadecimal strings whose length is
 * a property of the format; no code may assume 40 characters, abbreviate an ID for a write or
 * accept an ID whose repository format is unknown.
 */
enum class GitObjectFormat(val wireName: String, val hexLength: Int?) {
    SHA1("sha1", 40), SHA256("sha256", 64), UNKNOWN("unknown", null);

    /** Full object ID for this format, or null. Unknown formats never yield a usable identity. */
    fun objectIdOrNull(value: String): String? {
        val length = hexLength ?: return null
        return value.takeIf { it.length == length && it.all { char -> char in '0'..'9' || char in 'a'..'f' } }
    }

    fun requireObjectId(value: String): String =
        objectIdOrNull(value) ?: throw IllegalArgumentException("Git object ID does not match the repository object format")

    companion object {
        fun fromGit(value: String): GitObjectFormat = entries.firstOrNull { it != UNKNOWN && it.wireName == value.trim() } ?: UNKNOWN
    }
}

/** Ref names are display/input text; this validation is the only way one reaches an argv. */
object GitRefNames {
    private const val MAX_BRANCH_CHARACTERS = 200

    /**
     * Local pre-check followed by Git's own `check-ref-format` of the fully qualified name. The
     * `refs/heads/` prefix means a caller value can never be parsed as an option.
     */
    fun requireBranchName(runner: GitCommandRunner, name: String): String {
        require(isPlausibleBranchName(name)) { "Git branch name is invalid" }
        val result = runner.run(GitInvocation("check-ref-format", listOf("refs/heads/$name"), allowedExitCodes = setOf(0, 1),
            limits = GitExecutionLimits(java.time.Duration.ofSeconds(10), 4096, 4096)))
        require(result.exitCode == 0) { "Git branch name is invalid" }
        return name
    }

    /** Bounded syntax that excludes control/whitespace characters and option or revision syntax. */
    fun isPlausibleBranchName(name: String): Boolean =
        name.length in 1..MAX_BRANCH_CHARACTERS && !name.startsWith("-") && name != "HEAD" && name != "@" &&
            name.none { it.isWhitespace() || it.isISOControl() || it in "~^:?*[\\" } &&
            !name.contains("..") && !name.contains("@{") && !name.contains("//") &&
            !name.startsWith("/") && !name.endsWith("/") && !name.endsWith(".") && !name.endsWith(".lock") &&
            name.split('/').none { it.startsWith(".") || it.endsWith(".lock") }

    /** Ref names read back from a repository must be fully qualified, printable and bounded. */
    fun isObservedRefName(name: String): Boolean =
        name.startsWith("refs/") && name.length <= 1024 && name.none { it.isISOControl() || it == ' ' } && !name.contains("..")
}
