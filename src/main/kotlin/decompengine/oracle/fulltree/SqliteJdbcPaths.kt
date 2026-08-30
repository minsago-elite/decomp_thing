package decompengine.oracle.fulltree

import java.nio.file.Path

/** SQLite JDBC URLs with pathname delimiters encoded before URI query parameters are added. */
internal object SqliteJdbcPaths {
    fun create(path: Path): String = url(path, "rwc")

    fun readOnly(path: Path): String = url(path, "ro&immutable=1")

    private fun url(path: Path, mode: String): String {
        val absolute = path.toAbsolutePath().normalize()
        if (absolute.fileName == null) throw FullTreeDataTruthException("SQLite path must name a file")
        val uri = absolute.toUri()
        if (uri.scheme != "file" || uri.rawQuery != null || uri.rawFragment != null) {
            throw FullTreeDataTruthException("SQLite path cannot be represented as a local file URI")
        }
        return "jdbc:sqlite:${uri.toASCIIString()}?mode=$mode"
    }
}
