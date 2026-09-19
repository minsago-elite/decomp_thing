package decompengine.project

import java.text.Normalizer
import java.util.Collections
import java.util.Locale

/** Immutable application-owned output omissions and build-control locations for archive transport. */
internal class ArchiveTransportLayout(
    excludedOutputRoots: Set<String>,
    strictBuildControlPaths: Set<String>,
) {
    val excludedOutputRoots: Set<String> = Collections.unmodifiableSet(excludedOutputRoots.map(::canonicalPath).toSortedSet())
    val strictBuildControlPaths: Set<String> = Collections.unmodifiableSet(strictBuildControlPaths.map(::canonicalPath).toSortedSet())

    init {
        this.excludedOutputRoots.forEach { root ->
            var ancestor = root.substringBeforeLast('/', "")
            while (ancestor.isNotEmpty()) {
                require(ancestor !in this.excludedOutputRoots) {
                    "archive output roots overlap: $ancestor and $root"
                }
                ancestor = ancestor.substringBeforeLast('/', "")
            }
        }
        requireRetains(this.strictBuildControlPaths)
    }

    private fun canonicalPath(path: String): String =
        Normalizer.normalize(requireNormalizedProjectPath(path, "archive path"), Normalizer.Form.NFC)
            .lowercase(Locale.ROOT)

    fun excludes(relativePath: String): Boolean {
        var candidate = canonicalPath(relativePath)
        while (candidate.isNotEmpty()) {
            if (candidate in excludedOutputRoots) return true
            candidate = candidate.substringBeforeLast('/', "")
        }
        return false
    }

    fun requireRetains(paths: Collection<String>) {
        paths.forEach { path ->
            require(!excludes(path)) { "archive output omission covers protected path: $path" }
        }
    }

    fun requireRetainsDeclarations(declarations: Collection<ProjectFileDeclaration>) {
        declarations.forEach { declaration ->
            require(excludedOutputRoots.none(declaration::canMaterializeUnderCanonical)) {
                "archive output omission covers protected path: ${declaration.pathTemplate}"
            }
        }
    }
}
