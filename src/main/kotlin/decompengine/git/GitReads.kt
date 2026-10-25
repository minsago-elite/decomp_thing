package decompengine.git

import java.nio.ByteBuffer
import java.nio.charset.CharacterCodingException
import java.nio.charset.CodingErrorAction
import java.nio.file.Path
import java.time.Duration
import java.time.Instant

/**
 * A path as Git reported it: exact bytes for identity, plus an unambiguous display form. Control
 * characters, backslashes and invalid UTF-8 are escaped, so two different names never display
 * alike and nothing in a name can be read as markup, an option or a second entry.
 */
class GitPath private constructor(val bytes: ByteArray, val display: String, val exact: String?) {
    /** Opaque per-work-tree identity; the server maps it back to these bytes. */
    fun fileId(worktreeId: String): String = "file_" + GitStorage.sha256(
        "git-file-v1\n$worktreeId\n".toByteArray() + bytes).take(32)

    override fun equals(other: Any?) = other is GitPath && other.bytes.contentEquals(bytes)
    override fun hashCode() = bytes.contentHashCode()

    companion object {
        fun of(bytes: ByteArray): GitPath {
            val decoded = try {
                Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            } catch (_: CharacterCodingException) { null }
            val display = if (decoded == null) bytes.joinToString("") { byte ->
                val value = byte.toInt() and 0xff
                if (value in 0x20..0x7e && value != '\\'.code) value.toChar().toString() else "\\x%02x".format(value)
            } else buildString {
                for (char in decoded) when {
                    char == '\\' -> append("\\\\")
                    char == '\n' -> append("\\n")
                    char == '\t' -> append("\\t")
                    char == '\r' -> append("\\r")
                    char.isISOControl() || char == ' ' || char == ' ' -> append("\\u%04x".format(char.code))
                    else -> append(char)
                }
            }
            return GitPath(bytes, display, decoded)
        }
    }
}

enum class GitIndexChange(val wireName: String) {
    NONE("none"), ADDED("added"), MODIFIED("modified"), DELETED("deleted"), RENAMED("renamed"),
    COPIED("copied"), TYPE_CHANGED("type-changed");

    companion object {
        fun of(code: Char): GitIndexChange = when (code) {
            '.' -> NONE; 'A' -> ADDED; 'M' -> MODIFIED; 'D' -> DELETED; 'R' -> RENAMED; 'C' -> COPIED; 'T' -> TYPE_CHANGED
            else -> throw GitRepositoryException("REPOSITORY_CORRUPT", "Git status reported an unknown change code.")
        }
    }
}

enum class GitConflict(val wireName: String) {
    BOTH_DELETED("both-deleted"), ADDED_BY_US("added-by-us"), DELETED_BY_THEM("deleted-by-them"),
    ADDED_BY_THEM("added-by-them"), DELETED_BY_US("deleted-by-us"), BOTH_ADDED("both-added"), BOTH_MODIFIED("both-modified");

    companion object {
        fun of(code: String): GitConflict = when (code) {
            "DD" -> BOTH_DELETED; "AU" -> ADDED_BY_US; "UD" -> DELETED_BY_THEM; "UA" -> ADDED_BY_THEM
            "DU" -> DELETED_BY_US; "AA" -> BOTH_ADDED; "UU" -> BOTH_MODIFIED
            else -> throw GitRepositoryException("REPOSITORY_CORRUPT", "Git status reported an unknown conflict code.")
        }
    }
}

/** One status record. Staged and unstaged changes of the same path are reported together. */
data class GitStatusEntry(
    val path: GitPath,
    val originalPath: GitPath?,
    val staged: GitIndexChange,
    val unstaged: GitIndexChange,
    val untracked: Boolean,
    val ignored: Boolean,
    val conflict: GitConflict?,
    val submodule: Boolean,
    /** Index blob for tracked entries, so re-staging different content is observable. */
    val indexObjectId: String? = null,
    /** Index and work-tree file modes, so a mode-only change is observable too. */
    val indexMode: String? = null,
    val worktreeMode: String? = null,
)

data class GitStatusSnapshot(val entries: List<GitStatusEntry>, val complete: Boolean)

data class GitHistoryEntry(
    val objectId: String,
    val parentObjectIds: List<String>,
    val authorName: String,
    val authorEmail: String,
    val authoredAt: Instant,
    val committedAt: Instant,
    val subject: String,
    val subjectTruncated: Boolean,
)

data class GitHistoryPage(val entries: List<GitHistoryEntry>, val more: Boolean)

enum class GitDiffScope(val wireName: String) { STAGED("staged"), UNSTAGED("unstaged"), COMMIT("commit") }

data class GitDiffFile(
    val path: GitPath,
    val originalPath: GitPath?,
    val change: GitIndexChange,
    val oldObjectId: String?,
    val newObjectId: String?,
    val oldMode: String,
    val newMode: String,
    val binary: Boolean,
    val additions: Long?,
    val deletions: Long?,
    val newSizeBytes: Long?,
)

data class GitDiffListing(val files: List<GitDiffFile>, val complete: Boolean)

data class GitPatch(val text: String, val truncated: Boolean, val binary: Boolean)

data class GitRefEntry(val name: String, val objectId: String, val peeledObjectId: String?)

/**
 * One page of refs with the listing anchors around it: [anchorBefore] digests every ref that
 * precedes the page and [anchorThrough] every ref through its end. A continuation names the
 * anchor it read through, so a ref created, deleted or moved before it cannot shift a page.
 */
data class GitRefsPage(val entries: List<GitRefEntry>, val more: Boolean, val anchorBefore: String, val anchorThrough: String) {
    companion object {
        fun anchor(entries: List<GitRefEntry>): String = GitStorage.sha256(buildString {
            append("git-refs-listing-v1\n")
            entries.forEach { append(it.name).append('\u0000').append(it.objectId).append('\u0000').append(it.peeledObjectId ?: "").append('\n') }
        }).take(32)
    }
}

/**
 * Bounded, NUL-delimited reads of a managed repository (#574, #575). Every command disables
 * external diff tools and textconv, never resolves submodules, and passes paths after `--` as
 * literal pathspecs. Output limits produce explicit incompleteness rather than silent truncation.
 */
object GitReads {
    const val MAX_STATUS_BYTES = 4 * 1024 * 1024
    const val MAX_PATCH_BYTES = 128 * 1024
    const val MAX_DIFF_FILES = 2000
    const val MAX_SUBJECT = 200
    private val LIMITS = GitExecutionLimits(Duration.ofSeconds(30), MAX_STATUS_BYTES, 16 * 1024)
    private val DIFF_OPTIONS = listOf("--no-ext-diff", "--no-textconv", "--no-color", "--ignore-submodules=all", "-M")

    /** Split NUL-terminated records at the byte level so arbitrary path bytes survive. */
    internal fun records(bytes: ByteArray): MutableList<ByteArray> {
        val records = mutableListOf<ByteArray>()
        var start = 0
        for (index in bytes.indices) if (bytes[index] == 0.toByte()) {
            records += bytes.copyOfRange(start, index); start = index + 1
        }
        if (start < bytes.size) records += bytes.copyOfRange(start, bytes.size)
        return records
    }

    /** Split a header record into exactly [count] space-separated fields, the last keeping its spaces. */
    private fun fields(record: ByteArray, count: Int): Pair<List<String>, ByteArray> {
        val values = mutableListOf<String>()
        var start = 0
        for (index in record.indices) {
            if (values.size == count - 1) break
            if (record[index] == ' '.code.toByte()) { values += String(record, start, index - start, Charsets.US_ASCII); start = index + 1 }
        }
        if (values.size != count - 1) throw GitRepositoryException("REPOSITORY_CORRUPT", "Git status output is malformed.")
        return values to record.copyOfRange(start, record.size)
    }

    fun status(runner: GitCommandRunner, gitDir: Path, workTree: Path): GitStatusSnapshot {
        val result = runner.run(GitInvocation("status", listOf("--porcelain=v2", "-z", "--untracked-files=all",
            "--ignored=matching", "--find-renames", "--ignore-submodules=all", "--no-ahead-behind"),
            gitDir = gitDir, workTree = workTree, truncateStdout = true, limits = LIMITS))
        val records = records(result.stdout)
        // A truncated final record may be partial; drop it and report incompleteness instead.
        if (result.stdoutTruncated && records.isNotEmpty()) records.removeAt(records.lastIndex)
        val entries = mutableListOf<GitStatusEntry>()
        var index = 0
        while (index < records.size) {
            val record = records[index++]
            if (record.isEmpty()) continue
            when (record[0].toInt().toChar()) {
                '1' -> {
                    val (values, path) = fields(record, 9)
                    entries += ordinary(values[1], values[2], GitPath.of(path), null, values[7], values[4], values[5])
                }
                '2' -> {
                    val (values, path) = fields(record, 10)
                    if (index >= records.size) break
                    entries += ordinary(values[1], values[2], GitPath.of(path), GitPath.of(records[index++]), values[7], values[4], values[5])
                }
                'u' -> {
                    val (values, path) = fields(record, 11)
                    entries += GitStatusEntry(GitPath.of(path), null, GitIndexChange.NONE, GitIndexChange.NONE, false, false,
                        GitConflict.of(values[1]), values[2] != "N...")
                }
                '?' -> entries += GitStatusEntry(GitPath.of(record.copyOfRange(2, record.size)), null, GitIndexChange.NONE,
                    GitIndexChange.NONE, untracked = true, ignored = false, conflict = null, submodule = false)
                '!' -> entries += GitStatusEntry(GitPath.of(record.copyOfRange(2, record.size)), null, GitIndexChange.NONE,
                    GitIndexChange.NONE, untracked = false, ignored = true, conflict = null, submodule = false)
                '#' -> Unit
                else -> throw GitRepositoryException("REPOSITORY_CORRUPT", "Git status output is malformed.")
            }
        }
        return GitStatusSnapshot(coalesce(entries), !result.stdoutTruncated)
    }

    /**
     * `git rm --cached` leaves the file in place, so Git reports a staged deletion and an
     * untracked record for one path. A path has one file identity, so the records are merged:
     * the tracked record is kept and also marked untracked.
     */
    private fun coalesce(entries: List<GitStatusEntry>): List<GitStatusEntry> {
        val byPath = LinkedHashMap<GitPath, GitStatusEntry>()
        for (entry in entries) {
            val existing = byPath[entry.path]
            byPath[entry.path] = when {
                existing == null -> entry
                entry.untracked && !existing.untracked && !existing.ignored -> existing.copy(untracked = true)
                existing.untracked && !entry.untracked && !entry.ignored -> entry.copy(untracked = true)
                else -> existing
            }
        }
        return byPath.values.toList()
    }

    private fun ordinary(code: String, submodule: String, path: GitPath, original: GitPath?, index: String,
        indexMode: String, worktreeMode: String): GitStatusEntry {
        if (code.length != 2) throw GitRepositoryException("REPOSITORY_CORRUPT", "Git status output is malformed.")
        return GitStatusEntry(path, original, GitIndexChange.of(code[0]), GitIndexChange.of(code[1]), false, false, null,
            submodule != "N...", index.takeIf { it.isNotEmpty() && it.any { char -> char != '0' } }, indexMode, worktreeMode)
    }

    /** First-page start is fixed by the caller, so moving refs cannot shift later pages. */
    fun history(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, start: String, skip: Int, limit: Int): GitHistoryPage {
        val objectId = format.requireObjectId(start)
        require(skip in 0..1_000_000 && limit in 1..200)
        // Every field is NUL-terminated and commits are newline-separated. Commit headers cannot hold NUL
        // or newline and %s is a single line, so arbitrary subject or name text cannot shift a field.
        val result = runner.run(GitInvocation("log", listOf("--no-decorate", "--no-color", "--no-show-signature",
            "--no-notes", "--no-use-mailmap", "--topo-order", "--skip=$skip", "--max-count=${limit + 1}",
            "--format=%H%x00%P%x00%an%x00%ae%x00%at%x00%ct%x00%s%x00", objectId, "--"), gitDir = gitDir, limits = LIMITS))
        val tokens = records(result.stdout)
        if (tokens.isNotEmpty() && tokens.last().all { it == '\n'.code.toByte() }) tokens.removeAt(tokens.lastIndex)
        if (tokens.size % 7 != 0) throw GitRepositoryException("REPOSITORY_CORRUPT", "Git history output is malformed.")
        val entries = tokens.chunked(7).map { record ->
            val values = record.mapIndexed { index, bytes ->
                val text = bytes.toString(Charsets.UTF_8)
                if (index == 0) text.trimStart('\n') else text
            }
            val parents = values[1].split(' ').filter { it.isNotEmpty() }.map(format::requireObjectId)
            GitHistoryEntry(format.requireObjectId(values[0]), parents, values[2].take(256), values[3].take(256),
                Instant.ofEpochSecond(values[4].toLong()), Instant.ofEpochSecond(values[5].toLong()),
                values[6].take(MAX_SUBJECT), values[6].length > MAX_SUBJECT)
        }
        return GitHistoryPage(entries.take(limit), entries.size > limit)
    }

    /** Arguments selecting one comparison; commit scope compares against the first parent (or nothing). */
    private fun comparison(scope: GitDiffScope, commit: String?, parent: String?): Pair<String, List<String>> = when (scope) {
        GitDiffScope.UNSTAGED -> "diff" to emptyList()
        GitDiffScope.STAGED -> "diff" to listOf("--cached")
        GitDiffScope.COMMIT -> "diff-tree" to listOf("-r", "--no-commit-id") +
            (if (parent == null) listOf("--root", checkNotNull(commit)) else listOf(parent, checkNotNull(commit)))
    }

    fun diff(runner: GitCommandRunner, gitDir: Path, workTree: Path?, format: GitObjectFormat, scope: GitDiffScope,
        commit: String?, parent: String?, maxOutputBytes: Int = MAX_STATUS_BYTES, maxFiles: Int = MAX_DIFF_FILES): GitDiffListing {
        val (command, selection) = comparison(scope, commit, parent)
        val tree = if (scope == GitDiffScope.COMMIT) null else workTree
        val bounded = LIMITS.copy(maxStdoutBytes = maxOutputBytes)
        val raw = runner.run(GitInvocation(command, selection + DIFF_OPTIONS + listOf("--raw", "-z", "--no-abbrev"),
            gitDir = gitDir, workTree = tree, truncateStdout = true, limits = bounded))
        val numstat = runner.run(GitInvocation(command, selection + DIFF_OPTIONS + listOf("--numstat", "-z"),
            gitDir = gitDir, workTree = tree, truncateStdout = true, limits = bounded))
        val counts = HashMap<GitPath, Pair<Long?, Long?>>()
        run {
            val records = records(numstat.stdout)
            // A truncated final record may hold only part of its counts or path; drop it.
            if (numstat.stdoutTruncated && records.isNotEmpty()) records.removeAt(records.lastIndex)
            var index = 0
            while (index < records.size) {
                val record = records[index++]
                if (record.isEmpty()) continue
                val text = String(record, Charsets.ISO_8859_1)
                val added = text.substringBefore('\t'); val deleted = text.substringAfter('\t').substringBefore('\t')
                if (text.count { it == '\t' } < 2) break
                val pathBytes = record.copyOfRange(added.length + deleted.length + 2, record.size)
                // A rename or copy has an empty path field followed by its original and new paths.
                val path = if (pathBytes.isEmpty()) {
                    if (index + 1 >= records.size) break
                    index++
                    GitPath.of(records[index++])
                } else GitPath.of(pathBytes)
                counts[path] = added.toLongOrNull() to deleted.toLongOrNull()
            }
        }
        val zero = "0".repeat(format.hexLength ?: 40)
        val files = LinkedHashMap<GitPath, GitDiffFile>()
        val unmerged = HashSet<GitPath>()
        val records = records(raw.stdout)
        if (raw.stdoutTruncated && records.isNotEmpty()) records.removeAt(records.lastIndex)
        var index = 0
        while (index < records.size && files.size < maxFiles) {
            val header = records[index++].toString(Charsets.US_ASCII)
            if (header.isEmpty()) continue
            val parts = header.removePrefix(":").split(' ')
            // The output bound can cut between a header and its path: discard that incomplete entry.
            if (index >= records.size && raw.stdoutTruncated) break
            if (!header.startsWith(":") || parts.size != 5 || index >= records.size) {
                throw GitRepositoryException("REPOSITORY_CORRUPT", "Git diff output is malformed.")
            }
            val code = parts[4][0]
            val change = GitIndexChange.of(if (code == 'U') 'M' else code)
            val first = GitPath.of(records[index++])
            val (original, path) = if (change == GitIndexChange.RENAMED || change == GitIndexChange.COPIED) {
                if (index >= records.size) break
                first to GitPath.of(records[index++])
            } else null to first
            val (added, deleted) = counts[path] ?: (null to null)
            val oldId = parts[2].takeIf { it != zero }?.let(format::requireObjectId)
            val newId = parts[3].takeIf { it != zero }?.let(format::requireObjectId)
            val file = GitDiffFile(path, original, change, oldId, newId, parts[0], parts[1],
                binary = counts.containsKey(path) && added == null && deleted == null, additions = added, deletions = deleted, newSizeBytes = null)
            // An unmerged path is reported as a bare `U` record plus its real comparison record;
            // keep one entry per file, preferring the record that names actual blobs.
            when {
                code == 'U' -> { unmerged += path; files.putIfAbsent(path, file) }
                path in unmerged || path !in files -> files[path] = file
            }
        }
        val sizes = objectSizes(runner, gitDir, files.values.mapNotNull { it.newObjectId }.distinct())
        return GitDiffListing(files.values.map { it.copy(newSizeBytes = it.newObjectId?.let(sizes::get)) },
            !raw.stdoutTruncated && !numstat.stdoutTruncated && index >= records.size)
    }

    /** Sizes from object headers only; contents are never read for metadata. */
    fun objectSizes(runner: GitCommandRunner, gitDir: Path, objectIds: List<String>): Map<String, Long> {
        if (objectIds.isEmpty()) return emptyMap()
        val result = runner.run(GitInvocation("cat-file", listOf("--batch-check=%(objectname) %(objectsize)"), gitDir = gitDir,
            input = objectIds.take(MAX_DIFF_FILES).joinToString("") { "$it\n" }.toByteArray(), limits = LIMITS))
        return result.text.lineSequence().mapNotNull { line ->
            val parts = line.split(' ')
            if (parts.size == 2) parts[1].toLongOrNull()?.let { parts[0] to it } else null
        }.toMap()
    }

    /** A bounded unified patch for one file. Binary content is never rendered. */
    fun patch(runner: GitCommandRunner, gitDir: Path, workTree: Path?, scope: GitDiffScope, commit: String?, parent: String?,
        file: GitDiffFile): GitPatch {
        if (file.binary) return GitPatch("", truncated = false, binary = true)
        val path = file.path.exact
        if (path == null || (file.originalPath != null && file.originalPath.exact == null)) throw ManagedGitException("PATCH_UNAVAILABLE",
            "This file name is not valid UTF-8, so its patch cannot be read through the workbench. Its listing entry stays exact.")
        val paths = listOfNotNull(file.originalPath?.exact, path)
        val (command, selection) = comparison(scope, commit, parent)
        // Path filters are not record selectors (a path can now be a directory with other changes),
        // so the patch is read with full blob IDs and only the section for this exact record is kept.
        val result = runner.run(GitInvocation(command, selection + DIFF_OPTIONS + listOf("-p", "-U3", "--full-index", "--") + paths,
            gitDir = gitDir, workTree = if (scope == GitDiffScope.COMMIT) null else workTree, truncateStdout = true,
            limits = LIMITS.copy(maxStdoutBytes = MAX_PATCH_BYTES * 4)))
        val text = result.stdout.toString(Charsets.UTF_8)
        // An unresolved conflict prints a combined `diff --cc <path>` section instead of `diff --git`.
        val sections = Regex("(?m)^diff --(?:git|cc|combined) ").findAll(text).map { it.range.first }.toList().let { starts ->
            starts.mapIndexed { index, start -> text.substring(start, starts.getOrElse(index + 1) { text.length }) }
        }
        val zero = "0".repeat(file.oldObjectId?.length ?: file.newObjectId?.length ?: 40)
        fun index(section: String) = Regex("(?m)^index ([0-9a-f]+)\\.\\.([0-9a-f]+)").find(section)?.let { it.groupValues[1] to it.groupValues[2] }
        val matching = sections.filter { section ->
            val (old, new) = index(section) ?: return@filter false
            old == (file.oldObjectId ?: zero) && (file.newObjectId == null || new == file.newObjectId)
        }
        // Git prints a type change (file to symlink and back) as a deletion section followed by an
        // addition section; one listing record owns both, so both are kept in order.
        // An unstaged comparison has no stored blob for the work-tree side, so each section is
        // matched by this record's own header and whichever blob IDs the listing does name.
        val own = "diff --git ${quoted("a/$path")} ${quoted("b/$path")}\n"
        val typeChange = if (file.change == GitIndexChange.TYPE_CHANGED) {
            val deletion = sections.firstOrNull { section -> section.startsWith(own) &&
                index(section)?.let { (old, new) -> new == zero && (file.oldObjectId == null || old == file.oldObjectId) } == true }
            val addition = sections.firstOrNull { section -> section.startsWith(own) &&
                index(section)?.let { (old, new) -> old == zero && (file.newObjectId == null || new == file.newObjectId) } == true }
            if (deletion != null && addition != null) deletion + addition else null
        } else null
        // Pure renames and mode-only changes have no index line; identify them by their exact
        // header, quoted the way Git quotes unusual names.
        val header = "diff --git ${quoted("a/" + (file.originalPath?.exact ?: path))} ${quoted("b/$path")}\n"
        val combined = listOf("diff --cc ${quoted(path)}\n", "diff --combined ${quoted(path)}\n")
        val selected = typeChange ?: matching.firstOrNull()
            ?: sections.firstOrNull { it.startsWith(header) && !Regex("(?m)^index ").containsMatchIn(it) }
            ?: sections.firstOrNull { section -> combined.any(section::startsWith) } ?: ""
        val bytes = selected.toByteArray(Charsets.UTF_8)
        val cut = bytes.size > MAX_PATCH_BYTES || (result.stdoutTruncated && selected === sections.lastOrNull())
        return GitPatch(if (bytes.size > MAX_PATCH_BYTES) bytes.copyOf(MAX_PATCH_BYTES).toString(Charsets.UTF_8).trimEnd('\uFFFD') else selected,
            cut, binary = false)
    }

    /**
     * A diff header path as Git prints it with the default `core.quotePath`: a name holding a
     * quote, backslash, control character or any byte above 0x7f is wrapped in quotes with C
     * escapes and octal bytes.
     */
    internal fun quoted(name: String): String {
        val bytes = name.toByteArray(Charsets.UTF_8)
        fun special(value: Int) = value < 0x20 || value == 0x7f || value >= 0x80 || value == '"'.code || value == '\\'.code
        if (bytes.none { special(it.toInt() and 0xff) }) return name
        return buildString {
            append('"')
            for (byte in bytes) {
                val value = byte.toInt() and 0xff
                when (value) {
                    7 -> append("\\a"); 8 -> append("\\b"); 9 -> append("\\t"); 10 -> append("\\n")
                    11 -> append("\\v"); 12 -> append("\\f"); 13 -> append("\\r")
                    '"'.code -> append("\\\""); '\\'.code -> append("\\\\")
                    else -> if (special(value)) append('\\').append(value.toString(8).padStart(3, '0')) else append(value.toChar())
                }
            }
            append('"')
        }
    }

    /** Branches and tags with peeled tag targets, at most [limit] after [skip]. */
    fun refs(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, skip: Int, limit: Int): Pair<List<GitRefEntry>, Boolean> =
        refsPage(runner, gitDir, format, skip, limit).let { it.entries to it.more }

    /** [refs] with the anchors of the listing before and through the page. */
    fun refsPage(runner: GitCommandRunner, gitDir: Path, format: GitObjectFormat, skip: Int, limit: Int): GitRefsPage {
        require(skip in 0..100_000 && limit in 1..200)
        val result = runner.run(GitInvocation("for-each-ref", listOf("--format=%(objectname)%00%(refname)%00%(*objectname)",
            "--count=${skip + limit + 1}", "refs/heads", "refs/tags"), gitDir = gitDir, limits = LIMITS))
        val entries = result.text.lineSequence().filter { it.isNotEmpty() }.map { line ->
            val parts = line.split('\u0000')
            if (parts.size != 3 || !GitRefNames.isObservedRefName(parts[1])) {
                throw GitRepositoryException("REPOSITORY_CORRUPT", "A reference has an invalid name or object ID.")
            }
            GitRefEntry(parts[1], format.requireObjectId(parts[0]), parts[2].takeIf { it.isNotEmpty() }?.let(format::requireObjectId))
        }.toList()
        val page = entries.drop(skip).take(limit)
        return GitRefsPage(page, entries.size > skip + limit, GitRefsPage.anchor(entries.take(skip)),
            GitRefsPage.anchor(entries.take(skip + page.size)))
    }
}
