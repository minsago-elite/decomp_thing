package decompengine.acp

import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.sha256
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import kotlin.io.path.readBytes
import kotlin.io.path.exists

data class AcpFileSnapshot(val path: String, val sha256: String, val size: Long, val isSymlink: Boolean)

data class AcpChangeSet(
    val additions: List<String>,
    val modifications: List<String>,
    val deletions: List<String>,
    val moves: List<Pair<String, String>>,
    val beforeHashes: Map<String, String>,
    val afterHashes: Map<String, String>,
)

class AcpChangeSetException(message: String) : IllegalArgumentException(message)

class AcpChangeSetValidator(
    private val profile: ReconstructionProfile,
    private val allowlist: Set<String>,
    private val maximumFileBytes: Long = 1_048_576,
    private val maximumTotalBytes: Long = 8_388_608,
) {
    fun snapshot(projectDir: Path): Map<String, AcpFileSnapshot> {
        val snapshots = mutableMapOf<String, AcpFileSnapshot>()
        Files.walk(projectDir).use { stream ->
            stream.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(it) }.forEach { file ->
                val relative = projectDir.relativize(file).toString().replace('\\', '/')
                if (relative.isEmpty()) return@forEach
                val isSymlink = Files.isSymbolicLink(file)
                val size = if (isSymlink) 0 else Files.size(file)
                val hash = if (isSymlink) "symlink" else sha256(file.readBytes())
                snapshots[relative] = AcpFileSnapshot(relative, hash, size, isSymlink)
            }
        }
        return snapshots
    }

    fun compute(before: Map<String, AcpFileSnapshot>, after: Map<String, AcpFileSnapshot>): AcpChangeSet {
        val additions = mutableListOf<String>()
        val modifications = mutableListOf<String>()
        val deletions = mutableListOf<String>()
        val beforeHashes = before.mapValues { it.value.sha256 }
        val afterHashes = after.mapValues { it.value.sha256 }

        for ((path, snap) in after) {
            val prev = before[path]
            if (prev == null) additions += path else if (prev.sha256 != snap.sha256) modifications += path
        }
        for (path in before.keys) if (path !in after) deletions += path

        val moves = detectMoves(before, after, additions, deletions)
        return AcpChangeSet(additions, modifications, deletions, moves, beforeHashes, afterHashes)
    }

    private fun detectMoves(
        before: Map<String, AcpFileSnapshot>,
        after: Map<String, AcpFileSnapshot>,
        additions: MutableList<String>,
        deletions: MutableList<String>,
    ): List<Pair<String, String>> {
        val moves = mutableListOf<Pair<String, String>>()
        val addedByHash = additions.groupBy { after[it]!!.sha256 }
        val deletedByHash = deletions.groupBy { before[it]!!.sha256 }
        for ((hash, deletedPaths) in deletedByHash) {
            val addedPaths = addedByHash[hash] ?: continue
            if (deletedPaths.size == 1 && addedPaths.size == 1) {
                val from = deletedPaths.single()
                val to = addedPaths.single()
                moves += from to to
                additions.remove(to)
                deletions.remove(from)
            }
        }
        return moves
    }

    fun validate(changeSet: AcpChangeSet, projectDir: Path) {
        val allChanged = (changeSet.additions + changeSet.modifications + changeSet.moves.map { it.second })
        for (path in allChanged) {
            require(path !in setOf("reports/repair-revisions/graph.json", "reports/repair-revisions/graph.json.lock")) {
                "change-set cannot modify immutable revision graph: $path"
            }
            require(!path.contains("..")) { "change-set path escapes project: $path" }
            require(path !in setOf("UNRESOLVED.md") || ProjectFileRole.EVIDENCE in profile.layout.declarationForPath(path).roles) {
                "evidence file not declared: $path"
            }
            val file = projectDir.resolve(path)
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS)) {
                require(!Files.isSymbolicLink(file)) { "change-set cannot create escaping symlink: $path" }
                val attrs = Files.readAttributes(file, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
                require(attrs.isRegularFile) { "change-set special file not allowed: $path" }
                require(attrs.size() <= maximumFileBytes) { "change-set file exceeds size limit: $path" }
                val bytes = file.readBytes()
                require(isValidUtf8(bytes) || isAllowedBinary(path)) { "change-set undeclared binary content: $path" }
                try {
                    profile.layout.declarationForPath(path)
                } catch (e: IllegalArgumentException) {
                    throw AcpChangeSetException("path not declared by profile: $path")
                }
            }
            require(path in allowlist || isEvidencePath(path)) { "change outside allowlist: $path" }
        }
        val totalBytes = allChanged.sumOf { path ->
            val file = projectDir.resolve(path)
            if (Files.exists(file, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(file)) Files.size(file) else 0
        }
        require(totalBytes <= maximumTotalBytes) { "change-set total bytes exceed limit: $totalBytes" }
    }

    private fun isEvidencePath(path: String): Boolean = try {
        val decl = profile.layout.declarationForPath(path)
        ProjectFileRole.EVIDENCE in decl.roles || ProjectFileRole.BEHAVIOR_EVIDENCE in decl.roles
    } catch (_: IllegalArgumentException) { false }

    private fun isAllowedBinary(path: String): Boolean = try {
        val decl = profile.layout.declarationForPath(path)
        decl.contentKind.name == "BINARY"
    } catch (_: IllegalArgumentException) { false }

    private fun isValidUtf8(bytes: ByteArray): Boolean = try {
        String(bytes, Charsets.UTF_8)
        java.nio.charset.Charset.forName("UTF-8").newDecoder()
            .onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT)
            .decode(java.nio.ByteBuffer.wrap(bytes))
        true
    } catch (_: Exception) { false }
}
