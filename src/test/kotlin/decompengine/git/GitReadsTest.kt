package decompengine.git

import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class GitReadsTest {
    private fun GitTestRepositories.write(workTree: Path, name: String, text: String) {
        val file = workTree.resolve(name)
        Files.createDirectories(file.parent)
        Files.writeString(file, text)
    }

    private fun GitTestRepositories.raw(gitDir: Path, workTree: Path, vararg args: String, expect: Int = 0) =
        git("--git-dir=$gitDir", "--work-tree=$workTree", *args, cwd = workTree, expect = expect)

    @Test fun `status distinguishes every category and keeps unusual names unambiguous`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("status")
        val unusual = listOf("-rf now.c", "new\nline.c", "tab\there.c", "quote\"s.c", "space name.c", "ünïcode.c", "back\\slash.c")
        for (name in listOf("modified.c", "deleted.c", "renamed.c", "both.c", "unstaged-delete.c")) f.write(workTree, name, "int ${name.replace('.', '_').replace('-', '_')} = 1;\n")
        f.commitAll(gitDir, workTree, "base")
        f.write(workTree, "added.c", "int added;\n"); f.raw(gitDir, workTree, "add", "--", "added.c")
        f.write(workTree, "modified.c", "int changed;\n"); f.raw(gitDir, workTree, "add", "--", "modified.c")
        f.raw(gitDir, workTree, "rm", "-q", "--", "deleted.c")
        f.raw(gitDir, workTree, "mv", "renamed.c", "moved.c")
        f.write(workTree, "both.c", "int staged;\n"); f.raw(gitDir, workTree, "add", "--", "both.c")
        f.write(workTree, "both.c", "int unstaged;\n")
        Files.delete(workTree.resolve("unstaged-delete.c"))
        unusual.forEach { f.write(workTree, it, "/* unusual */\n") }
        f.write(workTree, "input.elf", "binary")
        val observation = GitRepositoryInspector.inspect(f.runner, gitDir, workTree)
        val entries = observation.status.entries.associateBy { it.path.exact }
        assertEquals(GitIndexChange.ADDED, entries.getValue("added.c").staged)
        assertEquals(GitIndexChange.MODIFIED, entries.getValue("modified.c").staged)
        assertEquals(GitIndexChange.DELETED, entries.getValue("deleted.c").staged)
        assertEquals(GitIndexChange.RENAMED, entries.getValue("moved.c").staged)
        assertEquals("renamed.c", entries.getValue("moved.c").originalPath?.exact)
        assertEquals(GitIndexChange.MODIFIED to GitIndexChange.MODIFIED, entries.getValue("both.c").let { it.staged to it.unstaged })
        assertEquals(GitIndexChange.DELETED, entries.getValue("unstaged-delete.c").unstaged)
        assertTrue(entries.getValue("input.elf").ignored)
        for (name in unusual) assertTrue(entries.getValue(name).untracked, name)
        assertEquals("new\\nline.c", entries.getValue("new\nline.c").path.display)
        assertEquals("tab\\there.c", entries.getValue("tab\there.c").path.display)
        assertEquals("back\\\\slash.c", entries.getValue("back\\slash.c").path.display)
        assertEquals("-rf now.c", entries.getValue("-rf now.c").path.display)
        val ids = observation.status.entries.map { it.path.fileId("worktree_x") }
        assertEquals(ids.size, ids.toSet().size)
        assertTrue(observation.dirty)
        // Re-editing an already modified file changes no status code, but changes the version.
        val before = observation.statusDigest
        f.write(workTree, "both.c", "int unstaged_again_longer;\n")
        assertNotEquals(before, GitRepositoryInspector.inspect(f.runner, gitDir, workTree).statusDigest)
        // Ignored files never change the version.
        val stable = GitRepositoryInspector.inspect(f.runner, gitDir, workTree).statusDigest
        f.write(workTree, "build.log", "noise")
        assertEquals(stable, GitRepositoryInspector.inspect(f.runner, gitDir, workTree).statusDigest)
    }

    @Test fun `conflicts are reported per path from a real merge`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("conflict")
        f.write(workTree, "shared.c", "int base;\n"); f.commitAll(gitDir, workTree, "base")
        f.raw(gitDir, workTree, "checkout", "-q", "-b", "other")
        f.write(workTree, "shared.c", "int other;\n"); f.commitAll(gitDir, workTree, "other")
        f.raw(gitDir, workTree, "checkout", "-q", "trunk")
        f.write(workTree, "shared.c", "int ours;\n"); f.commitAll(gitDir, workTree, "ours")
        f.raw(gitDir, workTree, "merge", "-q", "other", expect = 1)
        val entry = GitRepositoryInspector.inspect(f.runner, gitDir, workTree).status.entries.single { it.path.exact == "shared.c" }
        assertEquals(GitConflict.BOTH_MODIFIED, entry.conflict)
        // The unmerged path appears once in an unstaged diff, with the record that names real blobs.
        val unstaged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.UNSTAGED, null, null)
        val shared = unstaged.files.filter { it.path.exact == "shared.c" }
        assertEquals(1, shared.size)
        assertEquals(unstaged.files.size, unstaged.files.map { it.path.fileId("w") }.toSet().size)
    }

    @Test fun `invalid UTF-8 names are escaped and keep a distinct identity`() {
        val raw = GitPath.of(byteArrayOf('a'.code.toByte(), 0xff.toByte(), 'b'.code.toByte()))
        assertNull(raw.exact); assertEquals("a\\xffb", raw.display)
        val lookalike = GitPath.of("a\\xffb".toByteArray())
        assertNotEquals(raw.display, lookalike.display)
        assertNotEquals(raw.fileId("w"), lookalike.fileId("w"))
        assertEquals("\\u001b[31m", GitPath.of("\u001b[31m".toByteArray()).display)
    }

    @Test fun `history pages are anchored to an exact object and report merges`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("history")
        val commits = (1..5).map { index -> f.write(workTree, "file$index.c", "int v$index;\n"); f.commitAll(gitDir, workTree, "commit $index") }
        f.raw(gitDir, workTree, "checkout", "-q", "-b", "side", commits[2])
        f.write(workTree, "side.c", "int side;\n"); val side = f.commitAll(gitDir, workTree, "side")
        f.raw(gitDir, workTree, "checkout", "-q", "trunk")
        f.raw(gitDir, workTree, "merge", "-q", "--no-ff", "-m", "merge side", "side")
        val head = f.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim()
        val first = GitReads.history(f.runner, gitDir, GitObjectFormat.SHA1, head, 0, 3)
        assertEquals(3, first.entries.size); assertTrue(first.more)
        assertEquals(head, first.entries[0].objectId); assertEquals(2, first.entries[0].parentObjectIds.size)
        assertEquals("merge side", first.entries[0].subject)
        // A ref moving after the first page cannot change what the anchored second page contains.
        f.write(workTree, "later.c", "int later;\n"); f.commitAll(gitDir, workTree, "later")
        val second = GitReads.history(f.runner, gitDir, GitObjectFormat.SHA1, head, 3, 3)
        val all = GitReads.history(f.runner, gitDir, GitObjectFormat.SHA1, head, 0, 200).entries
        assertEquals(all.drop(3).take(3), second.entries)
        assertEquals(7, all.size); assertTrue(all.any { it.objectId == side })
        assertTrue(all.all { it.objectId.length == 40 })
        // Separator-like and control characters in names and subjects cannot shift a field.
        f.write(workTree, "odd.c", "int odd;\n"); f.raw(gitDir, workTree, "add", "--", "odd.c")
        f.raw(gitDir, workTree, "commit", "-q", "--author=Na\u001fme <odd@example.invalid>", "-m", "sub\u001fject\u001fwith separators")
        val odd = GitReads.history(f.runner, gitDir, GitObjectFormat.SHA1, f.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim(), 0, 2)
        assertEquals("sub\u001fject\u001fwith separators", odd.entries.first().subject)
        assertEquals("Na\u001fme", odd.entries.first().authorName)
        assertEquals(2, odd.entries.size)
        val long = "x".repeat(300); f.write(workTree, "long.c", "int long;\n"); f.commitAll(gitDir, workTree, long)
        val latest = GitReads.history(f.runner, gitDir, GitObjectFormat.SHA1, f.git("--git-dir=$gitDir", "rev-parse", "HEAD").trim(), 0, 1)
        assertEquals(200, latest.entries.single().subject.length); assertTrue(latest.entries.single().subjectTruncated)
    }

    @Test fun `diffs list renames binaries and sizes and bound large patches without helpers`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("diff")
        val marker = f.root.resolve("diff-helper-ran")
        f.write(workTree, ".gitattributes", "*.c diff=evil\n")
        f.write(workTree, "keep.c", (1..200).joinToString("") { "int line$it;\n" })
        f.write(workTree, "old name.c", "int renamed_content_is_long_enough_for_detection;\nint more;\nint lines;\n")
        Files.write(workTree.resolve("table.dat"), byteArrayOf(0, 1, 2, 3, 0, 5))
        val base = f.commitAll(gitDir, workTree, "base")
        f.raw(gitDir, workTree, "mv", "old name.c", "new name.c")
        Files.write(workTree.resolve("table.dat"), byteArrayOf(0, 9, 9, 9, 0, 5, 7))
        f.raw(gitDir, workTree, "add", "--", "table.dat")
        f.write(workTree, "keep.c", (1..20_000).joinToString("") { "int changed$it;\n" })
        val staged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null)
        val renamed = staged.files.single { it.path.exact == "new name.c" }
        assertEquals(GitIndexChange.RENAMED, renamed.change); assertEquals("old name.c", renamed.originalPath?.exact)
        val binary = staged.files.single { it.path.exact == "table.dat" }
        assertTrue(binary.binary); assertNull(binary.additions); assertEquals(7L, binary.newSizeBytes)
        assertEquals(40, binary.newObjectId!!.length)
        assertTrue(GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.STAGED, null, null, binary).binary)
        val unstaged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.UNSTAGED, null, null)
        val large = unstaged.files.single { it.path.exact == "keep.c" }
        assertEquals(20_000L, large.additions); assertEquals(200L, large.deletions); assertNull(large.newObjectId)
        val patch = GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.UNSTAGED, null, null, large)
        assertTrue(patch.truncated); assertTrue(patch.text.toByteArray().size <= GitReads.MAX_PATCH_BYTES)
        assertTrue(patch.text.startsWith("diff --git"))
        f.raw(gitDir, workTree, "add", "-A")
        val commit = f.commitAll(gitDir, workTree, "second")
        val committed = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.COMMIT, commit, base)
        assertEquals(setOf("new name.c", "table.dat", "keep.c"), committed.files.mapNotNull { it.path.exact }.toSet())
        assertTrue(committed.complete)
        val root = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.COMMIT, base, null)
        assertTrue(root.files.all { it.change == GitIndexChange.ADDED && it.oldObjectId == null })
        assertFalse(marker.exists())
    }

    @Test fun `an output bound that cuts an entry yields an incomplete listing, and unreadable names refuse patches`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("bounded")
        (1..60).forEach { f.write(workTree, "directory-with-a-long-name-$it/file-with-a-long-name-$it.c", "int v$it;\n") }
        f.raw(gitDir, workTree, "add", "-A")
        val complete = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null)
        assertTrue(complete.complete); assertEquals(60, complete.files.size)
        // Every cut point, through raw headers, paths and numstat counts alike, yields a clean prefix.
        for (bound in (300..6000 step 23)) {
            val cut = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null, maxOutputBytes = bound)
            assertFalse(cut.complete, "bound $bound"); assertTrue(cut.files.size in 0..59, "bound $bound")
            assertEquals(complete.files.take(cut.files.size).map { it.path }, cut.files.map { it.path })
        }
        val unreadable = complete.files.first().copy(path = GitPath.of(byteArrayOf('a'.code.toByte(), 0xff.toByte())))
        assertEquals("PATCH_UNAVAILABLE", kotlin.test.assertFailsWith<ManagedGitException> {
            GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.STAGED, null, null, unreadable)
        }.code)
    }

    @Test fun `a selected patch holds only its exact record and modes are part of the version`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("exact")
        f.write(workTree, "old.c", (1..20).joinToString("") { "int line_$it = $it;\n" })
        f.write(workTree, "tool.sh", "echo hi\n")
        f.commitAll(gitDir, workTree, "base")
        f.raw(gitDir, workTree, "mv", "old.c", "new.c")
        f.write(workTree, "old.c/other.c", "int unrelated_secret_change;\n")
        f.raw(gitDir, workTree, "add", "--", "old.c/other.c")
        val staged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null)
        val renamed = staged.files.single { it.change == GitIndexChange.RENAMED }
        val patch = GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.STAGED, null, null, renamed)
        assertTrue(patch.text.contains("rename to new.c"), patch.text)
        assertFalse(patch.text.contains("unrelated_secret_change"), patch.text)
        // A mode-only index change on a file with other staged and unstaged edits changes the version.
        f.write(workTree, "tool.sh", "echo staged\n"); f.raw(gitDir, workTree, "add", "--", "tool.sh")
        f.write(workTree, "tool.sh", "echo unstaged\n")
        val before = GitRepositoryInspector.inspect(f.runner, gitDir, workTree).statusDigest
        f.raw(gitDir, workTree, "update-index", "--chmod=+x", "--", "tool.sh")
        assertNotEquals(before, GitRepositoryInspector.inspect(f.runner, gitDir, workTree).statusDigest)
    }

    @Test fun `metadata-only patches with quoted names and type changes keep their sections`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("quoted")
        val names = listOf("\u00fcnicode.c", "tab\tname.c", "quote\"name.c", "back\\slash.c")
        names.forEach { f.write(workTree, it, "int value;\n") }
        f.write(workTree, "link.c", "int target;\n")
        f.commitAll(gitDir, workTree, "base")
        names.forEach { f.raw(gitDir, workTree, "update-index", "--chmod=+x", "--", it) }
        val staged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null)
        for (name in names) {
            val file = staged.files.single { it.path.exact == name }
            val patch = GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.STAGED, null, null, file)
            assertTrue(patch.text.contains("new mode 100755"), "$name: ${patch.text}")
            assertFalse(patch.truncated)
        }
        assertEquals("\"a/\\303\\274nicode.c\"", GitReads.quoted("a/\u00fcnicode.c"))
        assertEquals("a/plain.c", GitReads.quoted("a/plain.c"))
        // A file replaced by a symlink is one type-change record whose patch has both sections.
        f.raw(gitDir, workTree, "commit", "-q", "-m", "modes")
        Files.delete(workTree.resolve("link.c"))
        Files.createSymbolicLink(workTree.resolve("link.c"), Path.of("target.c"))
        f.raw(gitDir, workTree, "add", "--", "link.c")
        val typed = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null)
            .files.single { it.path.exact == "link.c" }
        assertEquals(GitIndexChange.TYPE_CHANGED, typed.change)
        val patch = GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.STAGED, null, null, typed)
        assertTrue(patch.text.contains("deleted file mode 100644") && patch.text.contains("-int target;"), patch.text)
        assertTrue(patch.text.contains("new file mode 120000") && patch.text.contains("+target.c"), patch.text)
        // The same change left unstaged has no stored work-tree blob; both sections are still kept.
        f.raw(gitDir, workTree, "commit", "-q", "-m", "symlink")
        Files.delete(workTree.resolve("link.c"))
        f.write(workTree, "link.c", "int restored;\n")
        f.raw(gitDir, workTree, "commit", "-q", "-am", "regular again")
        Files.delete(workTree.resolve("link.c"))
        Files.createSymbolicLink(workTree.resolve("link.c"), Path.of("other.c"))
        val unstaged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.UNSTAGED, null, null)
            .files.single { it.path.exact == "link.c" }
        assertEquals(GitIndexChange.TYPE_CHANGED, unstaged.change)
        assertNull(unstaged.newObjectId)
        val pending = GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.UNSTAGED, null, null, unstaged)
        assertTrue(pending.text.contains("-int restored;") && pending.text.contains("+other.c"), pending.text)
        assertFalse(pending.truncated)
    }

    @Test fun `a cached removal is one entry and a conflicted file shows its combined patch`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("combined")
        f.write(workTree, "a.c", "int a;\n"); f.write(workTree, "shared.c", "int shared = 0;\n")
        f.commitAll(gitDir, workTree, "base")
        f.raw(gitDir, workTree, "rm", "-q", "--cached", "--", "a.c")
        val removed = GitReads.status(f.runner, gitDir, workTree).entries.filter { it.path.exact == "a.c" }
        assertEquals(1, removed.size, "one identity per path")
        assertEquals(GitIndexChange.DELETED, removed.single().staged)
        assertTrue(removed.single().untracked)
        f.raw(gitDir, workTree, "add", "--", "a.c")
        f.raw(gitDir, workTree, "switch", "-q", "-c", "other")
        f.write(workTree, "shared.c", "int shared = 2;\n"); f.raw(gitDir, workTree, "commit", "-q", "-am", "other")
        f.raw(gitDir, workTree, "switch", "-q", "trunk")
        f.write(workTree, "shared.c", "int shared = 1;\n"); f.raw(gitDir, workTree, "commit", "-q", "-am", "ours")
        f.raw(gitDir, workTree, "merge", "-q", "other", expect = 1)
        val unstaged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.UNSTAGED, null, null)
        val conflicted = unstaged.files.single { it.path.exact == "shared.c" }
        val patch = GitReads.patch(f.runner, gitDir, workTree, GitDiffScope.UNSTAGED, null, null, conflicted)
        assertTrue(patch.text.startsWith("diff --cc shared.c"), patch.text)
        assertTrue(patch.text.contains("int shared = 1;") && patch.text.contains("int shared = 2;"), patch.text)
    }

    @Test fun `staged diff works on an unborn branch`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("unborn")
        f.write(workTree, "first.c", "int first;\n")
        f.raw(gitDir, workTree, "add", "--", "first.c")
        val staged = GitReads.diff(f.runner, gitDir, workTree, GitObjectFormat.SHA1, GitDiffScope.STAGED, null, null)
        assertEquals(GitIndexChange.ADDED, staged.files.single().change)
    }

    @Test fun `refs page through branches and peeled annotated tags`(): Unit = GitTestRepositories().use { f ->
        val (gitDir, workTree) = f.managed("refs")
        f.write(workTree, "a.c", "int a;\n"); val commit = f.commitAll(gitDir, workTree, "a")
        (1..5).forEach { f.git("--git-dir=$gitDir", "branch", "b$it", commit) }
        f.git("--git-dir=$gitDir", "tag", "-a", "-m", "annotated", "v1", commit)
        val (first, more) = GitReads.refs(f.runner, gitDir, GitObjectFormat.SHA1, 0, 4)
        assertEquals(4, first.size); assertTrue(more)
        val (rest, end) = GitReads.refs(f.runner, gitDir, GitObjectFormat.SHA1, 4, 10)
        assertFalse(end)
        val tag = (first + rest).single { it.name == "refs/tags/v1" }
        assertNotEquals(commit, tag.objectId); assertEquals(commit, tag.peeledObjectId)
        assertEquals(7, (first + rest).size)
        assertContentEquals((first + rest).map { it.name }.toTypedArray(), (first + rest).map { it.name }.sorted().toTypedArray())
    }
}
