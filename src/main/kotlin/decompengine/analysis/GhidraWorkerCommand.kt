package decompengine.analysis

import java.io.File
import java.nio.file.Path

internal object GhidraWorkerCommand {
    fun prefix(java: Path, release: Path, classPath: List<Path>): List<String> {
        require(classPath.isNotEmpty() && classPath.distinct().size == classPath.size) { "Ghidra worker classpath is empty or duplicated" }
        val entries = classPath.map { path ->
            val absolute = path.toAbsolutePath().normalize().toString()
            require(File.pathSeparatorChar !in absolute && absolute.none { it.code < 32 || it.code == 127 }) {
                "Ghidra worker classpath contains an ambiguous path"
            }
            absolute
        }
        return listOf(
            java.toAbsolutePath().normalize().toString(), "-Xmx2G", "-Xshare:off", "-Djava.awt.headless=true",
            "-Djava.system.class.loader=ghidra.GhidraClassLoader", "-Dfile.encoding=UTF-8",
            "-Duser.language=en", "-Duser.country=US", "-Duser.variant=",
            "-Djavax.xml.accessExternalDTD=", "-Djavax.xml.accessExternalSchema=",
            "-Djavax.xml.accessExternalStylesheet=", "--enable-native-access=ALL-UNNAMED",
            "-cp", entries.joinToString(File.pathSeparator),
            BundledGhidra.WORKER_CLASS, release.toAbsolutePath().normalize().toString(),
        )
    }
}
