package decompengine.git

import decompengine.git.GitStorage.hex
import java.io.IOException
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.SimpleFileVisitor
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.StandardOpenOption.WRITE
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration

/** Public failure of one materialization step. Codes and messages are fixed and path-free. */
class GitOperationFailure(val code: String, message: String) : Exception(message)

/**
 * Copies one recorded source snapshot into a new work tree, byte for byte. The snapshot is only
 * read: links, special files and nested `.git` entries are refused instead of being followed or
 * silently dropped, and every copied file is re-read afterwards so a concurrent change fails the
 * copy rather than producing a mixed tree.
 */
internal object GitSourceCopy {
    const val MAX_FILES = 20_000
    const val MAX_BYTES = 512L * 1024 * 1024
    private const val MAX_DEPTH = 64

    /** Directories created in a work tree; charged before each is created, like files. */
    const val MAX_DIRECTORIES = 20_000

    /** Returns `relative path -> SHA-256` of every copied file. [maxDirectories] is lowered only by tests. */
    fun copy(source: Path, target: Path, uncopiedRoots: Set<String> = GitTrackingPolicy.UNCOPIED_ROOTS,
        maxDirectories: Int = MAX_DIRECTORIES): Map<String, String> {
        if (!Files.isDirectory(source, NOFOLLOW_LINKS)) unavailable()
        val digests = sortedMapOf<String, String>()
        var bytes = 0L
        var directories = 0
        Files.walkFileTree(source, emptySet(), MAX_DEPTH + 1, object : SimpleFileVisitor<Path>() {
            override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
                GitStorage.checkInterrupted()
                val relative = source.relativize(directory)
                if (relative.nameCount > MAX_DEPTH || attributes.isSymbolicLink) unsupported()
                if (directory != source) {
                    if (relative.nameCount == 1 && relative.toString() in uncopiedRoots) return FileVisitResult.SKIP_SUBTREE
                    if (directory.fileName.toString() == ".git") unsupported()
                    // Empty directories cost inodes too; their breadth is bounded before any is created.
                    if (++directories > maxDirectories) unsupported()
                    Files.createDirectory(target.resolve(relative.toString()))
                }
                return FileVisitResult.CONTINUE
            }

            override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                val relative = source.relativize(file).toString()
                if (!attributes.isRegularFile || attributes.isSymbolicLink || file.fileName.toString() == ".git") unsupported()
                if (source.relativize(file).nameCount == 1 && relative in uncopiedRoots) return FileVisitResult.CONTINUE
                if (digests.size >= MAX_FILES || attributes.size() > MAX_BYTES - bytes) unsupported()
                bytes += attributes.size()
                val destination = target.resolve(relative)
                val digest = MessageDigest.getInstance("SHA-256")
                Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
                    Files.newOutputStream(destination, CREATE_NEW, WRITE).use { output ->
                        val buffer = ByteArray(64 * 1024)
                        var total = 0L
                        while (true) {
                            GitStorage.checkInterrupted()
                            val count = input.read(buffer)
                            if (count < 0) break
                            total += count
                            if (total > attributes.size()) unavailable()
                            digest.update(buffer, 0, count); output.write(buffer, 0, count)
                        }
                        if (total != attributes.size()) unavailable()
                    }
                }
                Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString(
                    if (Files.isExecutable(file)) "rwxr-xr-x" else "rw-r--r--"))
                digests[relative] = digest.digest().hex()
                return FileVisitResult.CONTINUE
            }

            override fun visitFileFailed(file: Path, failure: IOException): FileVisitResult = unavailable()
        })
        // The snapshot must be unchanged after the copy; the work tree must hold exactly those bytes.
        for ((relative, expected) in digests) {
            GitStorage.checkInterrupted()
            if (digestOf(source.resolve(relative)) != expected || digestOf(target.resolve(relative)) != expected) unavailable()
        }
        return digests
    }

    fun manifestDigest(digests: Map<String, String>): String =
        GitStorage.sha256(digests.entries.joinToString("") { (path, digest) -> "$path\u0000$digest\n" })

    fun digestOf(file: Path): String {
        if (!Files.isRegularFile(file, NOFOLLOW_LINKS)) unavailable()
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(file, NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) { GitStorage.checkInterrupted(); val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) }
        }
        return digest.digest().hex()
    }

    private fun unsupported(): Nothing = throw GitOperationFailure("SOURCE_UNSUPPORTED",
        "The source snapshot contains links, special files or nested repositories, or exceeds the copy limits.")
    private fun unavailable(): Nothing = throw GitOperationFailure("SOURCE_REVISION_UNAVAILABLE",
        "The selected source snapshot is unavailable or changed while it was copied.")
}

/** Bounds on the work tree an imported HEAD would expand to. */
data class GitCheckoutLimits(
    val maxFiles: Int = 20_000,
    val maxBytes: Long = 512L * 1024 * 1024,
    val maxDirectories: Int = 20_000,
) {
    init {
        require(maxFiles in 1..100_000 && maxBytes in 1..4L * 1024 * 1024 * 1024)
        require(maxDirectories in 1..100_000)
    }
}

/** Layout of a repository found under the operator-admitted import root. */
internal data class ImportedRepositoryLayout(val gitDir: Path, val bare: Boolean, val objectFormat: GitObjectFormat)

/**
 * Admission of an existing repository (#572). Only the operator-configured import root is
 * searched, by a single validated name. Imported configuration is parsed as data, hooks,
 * info files, index, reflogs, worktrees and submodule repositories are never copied, and the
 * managed copy is created and checked out with the server's own configuration.
 */
internal object GitRepositoryImport {
    private val NAME = Regex("[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
    private const val MAX_REFS = 10_000
    private const val MAX_PACKED_REFS_BYTES = 4 * 1024 * 1024
    private val ALLOWED_EXTENSIONS = setOf("objectformat", "worktreeconfig", "noop", "preciousobjects")

    fun isValidName(name: String): Boolean = NAME.matches(name) && !name.endsWith(".lock") && !name.contains("..")

    /** Resolve the admitted source without following links. */
    fun locate(importRoot: Path, name: String): Path? {
        if (!isValidName(name)) return null
        val source = importRoot.resolve(name)
        return source.takeIf { it.parent == importRoot && Files.isDirectory(it, NOFOLLOW_LINKS) }
    }

    fun layout(runner: GitCommandRunner, source: Path): ImportedRepositoryLayout {
        val dotGit = source.resolve(".git")
        val (gitDir, bare) = when {
            Files.isDirectory(dotGit, NOFOLLOW_LINKS) -> dotGit to false
            Files.exists(dotGit, NOFOLLOW_LINKS) -> unsupported("The repository's .git entry is a link or file; linked work trees and gitfiles are not imported.")
            else -> source to true
        }
        if (!Files.isRegularFile(gitDir.resolve("HEAD"), NOFOLLOW_LINKS) ||
            !Files.isDirectory(gitDir.resolve("objects"), NOFOLLOW_LINKS) || !Files.isDirectory(gitDir.resolve("refs"), NOFOLLOW_LINKS)
        ) unsupported("The admitted directory is not a Git repository.")
        for (forbidden in listOf("commondir", "shallow", "objects/info/alternates", "objects/info/http-alternates")) {
            if (Files.exists(gitDir.resolve(forbidden), NOFOLLOW_LINKS)) {
                unsupported("Shallow, linked or alternate-object repositories are not imported.")
            }
        }
        val config = gitDir.resolve("config")
        val entries = if (Files.exists(config, NOFOLLOW_LINKS)) GitConfigurationAudit.read(runner, config) else emptyList()
        val values = entries.groupBy({ it.first }, { it.second })
        val formatVersion = values["core.repositoryformatversion"]?.last() ?: "0"
        if (formatVersion !in setOf("0", "1")) unsupported("The repository format version is not supported.")
        val extensions = values.keys.filter { it.startsWith("extensions.") }.map { it.removePrefix("extensions.") }
        if (formatVersion == "1" && extensions.any { it !in ALLOWED_EXTENSIONS }) {
            unsupported("The repository uses an unsupported extension such as reftable or partial clone.")
        }
        val format = when (val declared = if (formatVersion == "1") values["extensions.objectformat"]?.last()?.lowercase() else null) {
            null, "sha1" -> GitObjectFormat.SHA1
            "sha256" -> GitObjectFormat.SHA256
            else -> { unsupported("The repository object format is not supported."); }
        }
        return ImportedRepositoryLayout(gitDir, bare, format)
    }

    /**
     * Copy objects, branch/tag refs and HEAD into an already initialized managed Git directory.
     * [maxRefEntries] bounds reference files and directories together and is lowered only by tests.
     * [beforeMetadataOpen] is an internal deterministic metadata replacement-race test seam.
     */
    fun copyHistory(layout: ImportedRepositoryLayout, managedGitDir: Path, maxRefEntries: Int = MAX_REFS,
        beforeMetadataOpen: (Path) -> Unit = {}) {
        GitImportObjectCopy.copy(layout.gitDir.resolve("objects"), managedGitDir.resolve("objects"))
        val packed = layout.gitDir.resolve("packed-refs")
        val packedBytes = if (Files.exists(packed, NOFOLLOW_LINKS)) GitImportMetadata.read(packed, MAX_PACKED_REFS_BYTES, beforeMetadataOpen) else byteArrayOf()
        val retainedPacked = filterPackedRefs(packedBytes, layout.objectFormat)
        // Resolve using all source namespaces, but publish only branches/tags. In particular a
        // symbolic branch may point at a packed remote-tracking ref which is not itself imported.
        val packedIds = packedBytes.toString(Charsets.UTF_8).lineSequence()
            .filter { it.isNotEmpty() && !it.startsWith("#") && !it.startsWith("^") }
            .associate { it.substringAfter(' ') to it.substringBefore(' ') }
        var refs = 0
        for (namespace in listOf("heads", "tags")) {
            val root = layout.gitDir.resolve("refs").resolve(namespace)
            if (!Files.exists(root, NOFOLLOW_LINKS)) continue
            if (!Files.isDirectory(root, NOFOLLOW_LINKS)) unsupported("The repository references are not ordinary files.")
            Files.walkFileTree(root, emptySet(), 32, object : SimpleFileVisitor<Path>() {
                override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
                    if (attributes.isSymbolicLink || !attributes.isDirectory) unsupported("The repository references are not ordinary files.")
                    GitStorage.checkInterrupted()
                    // Directories, empty ones included, are charged against the reference quota before creation.
                    if (++refs > maxRefEntries) unsupported("The repository has too many references.")
                    GitStorage.directories(managedGitDir.resolve("refs").resolve(namespace),
                        *root.relativize(directory).map { it.toString() }.filter { it.isNotEmpty() }.toTypedArray())
                    return FileVisitResult.CONTINUE
                }
                override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                    GitStorage.checkInterrupted()
                    if (!attributes.isRegularFile || attributes.isSymbolicLink) unsupported("The repository references are not ordinary files.")
                    if (++refs > maxRefEntries) unsupported("The repository has too many references.")
                    val name = "refs/$namespace/" + root.relativize(file).joinToString("/")
                    if (name.endsWith(".lock")) return FileVisitResult.CONTINUE
                    if (!validRefName(name)) unsupported("A repository reference has an unsupported name.")
                    val content = GitImportMetadata.read(file, 4096, beforeMetadataOpen).toString(Charsets.UTF_8)
                    val objectId = resolveRef(layout, name, content, packedIds, beforeMetadataOpen)
                    Files.writeString(managedGitDir.resolve(name), "$objectId\n", CREATE_NEW, WRITE)
                    return FileVisitResult.CONTINUE
                }
                override fun visitFileFailed(file: Path, failure: IOException): FileVisitResult = unsupported("The repository references could not be read.")
            })
        }
        if (packedBytes.isNotEmpty()) Files.write(managedGitDir.resolve("packed-refs"), retainedPacked)
        val head = GitImportMetadata.read(layout.gitDir.resolve("HEAD"), 4096, beforeMetadataOpen).toString(Charsets.UTF_8)
        val symbolic = head.removePrefix("ref: ").removeSuffix("\n").takeIf { head.startsWith("ref: ") }
        if (symbolic != null) {
            if (!symbolic.startsWith("refs/heads/") || !validRefName(symbolic)) unsupported("HEAD names an unsupported reference.")
        } else if (layout.objectFormat.objectIdOrNull(head.removeSuffix("\n")) == null) corrupt("HEAD is neither a branch nor a full object ID.")
        GitStorage.replaceAtomically(managedGitDir.resolve("HEAD"), head.toByteArray(Charsets.UTF_8))
    }

    /** Keep the header, branch and tag records and their peeled lines; drop every other namespace. */
    internal fun filterPackedRefs(bytes: ByteArray, format: GitObjectFormat): ByteArray {
        val output = StringBuilder()
        var keepPeel = false
        for (line in bytes.toString(Charsets.UTF_8).split('\n')) {
            when {
                line.isEmpty() -> Unit
                line.startsWith("# pack-refs with:") && output.isEmpty() -> output.append(line).append('\n')
                line.startsWith("^") -> {
                    if (format.objectIdOrNull(line.removePrefix("^")) == null) corrupt("The packed references are malformed.")
                    if (keepPeel) output.append(line).append('\n')
                }
                else -> {
                    val objectId = format.objectIdOrNull(line.substringBefore(' '))
                    val name = line.substringAfter(' ', "")
                    if (objectId == null || !GitRefNames.isObservedRefName(name)) corrupt("The packed references are malformed.")
                    // Other namespaces (remotes, notes, replace, stash) are intentionally not imported;
                    // a branch or tag that cannot be imported fails instead of silently disappearing.
                    keepPeel = name.startsWith("refs/heads/") || name.startsWith("refs/tags/")
                    if (keepPeel && !validRefName(name)) unsupported("A repository reference has an unsupported name.")
                    if (keepPeel) output.append(line).append('\n')
                }
            }
        }
        return output.toString().toByteArray(Charsets.UTF_8)
    }

    /**
     * Local equivalent of `git check-ref-format <refname>` for a complete stored name, so a valid
     * ref such as `refs/tags/HEAD` is kept. Branch-name rules apply to request input, not here.
     */
    internal fun validRefName(name: String): Boolean = GitRefNames.isObservedRefName(name) && name.count { it == '/' } >= 2 &&
        name.none { it in "~^:?*[\\" } && !name.contains("@{") && !name.contains("//") &&
        !name.endsWith("/") && !name.endsWith(".") &&
        name.split('/').all { it.isNotEmpty() && !it.startsWith(".") && !it.endsWith(".lock") }

    /** Bounded data-only symref resolution, including targets in intentionally omitted namespaces. */
    private fun resolveRef(layout: ImportedRepositoryLayout, name: String, content: String, packedIds: Map<String, String>,
        beforeMetadataOpen: (Path) -> Unit): String {
        val seen = mutableSetOf(name)
        var value = content.removeSuffix("\n")
        repeat(16) {
            GitStorage.checkInterrupted()
            layout.objectFormat.objectIdOrNull(value)?.let { return it }
            val target = value.removePrefix("ref: ")
            if (!value.startsWith("ref: ") || !validRefName(target)) corrupt("A repository reference does not contain a full object ID.")
            if (!seen.add(target)) unsupported("The repository contains cyclic symbolic references.")
            val file = layout.gitDir.resolve(target)
            value = if (Files.exists(file, NOFOLLOW_LINKS)) GitImportMetadata.read(file, 4096, beforeMetadataOpen).toString(Charsets.UTF_8).removeSuffix("\n")
                else packedIds[target] ?: corrupt("A symbolic repository reference has no target.")
        }
        unsupported("The repository's symbolic references exceed the import depth limit.")
    }

    /**
     * Full object verification: every object is re-hashed against its ID and everything reachable
     * from the copied refs must be present. `--connectivity-only` would not detect altered blobs.
     * Compressed file size and HEAD checkout quotas do not bound inflation of dangling, historical
     * or packed objects. The child therefore has a hard address-space budget before it reads any.
     */
    fun verify(runner: GitCommandRunner, managedGitDir: Path, maxAddressSpaceBytes: Long = 512L * 1024 * 1024) {
        try {
            runner.run(GitInvocation("fsck", listOf("--full", "--no-dangling", "--no-progress"), gitDir = managedGitDir,
                limits = GitExecutionLimits(Duration.ofMinutes(2), 1024 * 1024, 64 * 1024, maxAddressSpaceBytes)))
        } catch (failure: GitCommandException) {
            // Git's fatal allocation failure is 128; a resource-related signal can also end it.
            // These exits cannot establish corruption, and must never trigger an unbounded retry.
            if (failure.kind == GitCommandException.Kind.FAILED && failure.exitCode in setOf(128, 137, 139)) {
                unsupported("The repository could not be verified within the import memory budget.")
            }
            if (failure.kind == GitCommandException.Kind.FAILED) corrupt("The repository is missing objects or contains invalid objects.")
            throw GitOperationFailure("REPOSITORY_UNAVAILABLE", "The repository could not be verified within its bounds.")
        }
    }

    /** Bound files, directory prefixes and declared blob bytes before checkout creates anything. */
    fun requireCheckoutBounds(runner: GitCommandRunner, gitDir: Path, objectId: String, limits: GitCheckoutLimits,
        repositoryBudget: Long = Long.MAX_VALUE) = requireTreeBounds(runner, gitDir, listOf(objectId), limits, repositoryBudget)

    /** Conservative merge budget: the union cannot contain more entries/blob bytes than both
     * input trees combined. Shared paths are charged twice rather than risking an oversized merge.
     * This runs at admission and again under the publication lease, before touching the work tree. */
    fun requireIntegrationBounds(runner: GitCommandRunner, gitDir: Path, before: String, target: String, limits: GitCheckoutLimits) =
        requireTreeBounds(runner, gitDir, listOf(before, target), limits, Long.MAX_VALUE)

    private fun requireTreeBounds(runner: GitCommandRunner, gitDir: Path, objects: List<String>, limits: GitCheckoutLimits,
        repositoryBudget: Long) {
        var files = 0
        var directories = 0
        var bytes = 0L
        for (objectId in objects) {
            val listing = try {
                runner.run(GitInvocation("ls-tree", listOf("-r", "-t", "-l", "-z", "--full-tree", objectId), gitDir = gitDir,
                    limits = GitExecutionLimits(Duration.ofMinutes(2), 32 * 1024 * 1024, 64 * 1024)))
            } catch (failure: GitCommandException) {
                when (failure.kind) {
                    GitCommandException.Kind.OUTPUT_LIMIT -> tooLarge()
                    GitCommandException.Kind.FAILED -> corrupt("The repository's HEAD tree could not be read.")
                    else -> throw GitOperationFailure("REPOSITORY_UNAVAILABLE", "The repository could not be checked within its bounds.")
                }
            }
            for (entry in listing.text.split('\u0000')) {
                if (entry.isEmpty()) continue
                val fields = entry.substringBefore('\t').split(' ').filter { it.isNotEmpty() }
                if (fields.size != 4 || '\t' !in entry) corrupt("The repository's HEAD tree could not be read.")
                // -t includes each tree path once, even when multiple leaves share that prefix.
                // Inert gitlinks also create empty directories, so charge them to both entry quotas.
                if (fields[1] == "tree" || fields[1] == "commit") {
                    if (++directories > limits.maxDirectories) tooLarge()
                }
                if (fields[1] != "tree" && ++files > limits.maxFiles) tooLarge()
                if (fields[1] == "blob") {
                    val size = fields[3].toLongOrNull()?.takeIf { it >= 0 } ?: corrupt("The repository's HEAD tree could not be read.")
                    if (size > repositoryBudget - bytes) throw GitOperationFailure("TRANSFER_LIMIT",
                        "The clone's checkout exceeds the remaining repository size bound. Nothing was published.")
                    if (size > limits.maxBytes - bytes) tooLarge()
                    bytes += size
                }
            }
        }
    }

    private fun tooLarge(): Nothing = unsupported("The repository's checked-out tree exceeds the import size limits.")
    private fun unsupported(message: String): Nothing = throw GitOperationFailure("REPOSITORY_UNSUPPORTED", message)
    private fun corrupt(message: String): Nothing = throw GitOperationFailure("REPOSITORY_CORRUPT", message)
}
