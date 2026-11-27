package decompengine.project

import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Optional prompt context; reading it does not authenticate its behavioral claims. */
internal object ReconstructionExplorationInput {
    private const val MAXIMUM_HOST_BYTES = 16L * 1024 * 1024

    fun read(outputDir: Path, maximumCharacters: Int): String? {
        require(maximumCharacters > 0)
        fun checkCancellation() {
            if (Thread.interrupted()) throw InterruptedException("reconstruction exploration read cancelled")
        }
        checkCancellation()
        val moduleScoped = Files.exists(outputDir.resolve(ModuleObservedBehavior.FILE_NAME), LinkOption.NOFOLLOW_LINKS)
        val relative = if (moduleScoped) ModuleObservedBehavior.FILE_NAME else "exploration.json"
        if (!Files.exists(outputDir.resolve(relative), LinkOption.NOFOLLOW_LINKS)) return null
        // The envelope is a bounded corpus; only selected cases enter the module's prompt budget.
        val maximumBytes = if (moduleScoped) ModuleObservedBehavior.MAXIMUM_BYTES.toLong()
            else minOf(MAXIMUM_HOST_BYTES, maximumCharacters.toLong() * 4)
        val bytes = readStableRegularFile(outputDir, relative, maximumBytes,
            cancellationCheck = ::checkCancellation).bytes
        val text = bytes.decodeToString(throwOnInvalidSequence = true)
        if (moduleScoped) ModuleObservedBehavior.parse(text)
        else require(text.length <= maximumCharacters) {
            "exploration evidence exceeds $maximumCharacters reconstruction context characters"
        }
        checkCancellation()
        return text
    }
}
