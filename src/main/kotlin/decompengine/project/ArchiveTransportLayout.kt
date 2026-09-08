package decompengine.project

import java.util.Collections

/** Immutable application-owned output omissions and build-control locations for archive transport. */
internal class ArchiveTransportLayout(
    excludedOutputRoots: Set<String>,
    strictBuildControlPaths: Set<String>,
) {
    val excludedOutputRoots: Set<String> = Collections.unmodifiableSet(excludedOutputRoots.toSortedSet())
    val strictBuildControlPaths: Set<String> = Collections.unmodifiableSet(strictBuildControlPaths.toSortedSet())

    init {
        this.excludedOutputRoots.forEach { root ->
            requireNormalizedProjectPath(root, "archive output root")
            var ancestor = root.substringBeforeLast('/', "")
            while (ancestor.isNotEmpty()) {
                require(ancestor !in this.excludedOutputRoots) {
                    "archive output roots overlap: $ancestor and $root"
                }
                ancestor = ancestor.substringBeforeLast('/', "")
            }
        }
        this.strictBuildControlPaths.forEach { requireNormalizedProjectPath(it, "archive build-control path") }
        requireRetains(this.strictBuildControlPaths)
    }

    fun excludes(relativePath: String): Boolean {
        var candidate = requireNormalizedProjectPath(relativePath, "archive path")
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
            require(excludedOutputRoots.none(declaration::canMaterializeUnder)) {
                "archive output omission covers protected path: ${declaration.pathTemplate}"
            }
        }
    }
}
