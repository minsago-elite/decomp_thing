package decompengine.testing

import java.nio.file.Path

/**
 * Launch settings for HotSpot JVMs that tests start from the host JDK (#2001).
 *
 * HotSpot writes `/tmp/hsperfdata_<user>/<pid>` for every JVM unless `-XX:-UsePerfData` is given, whatever
 * `java.io.tmpdir` or `TMPDIR` say, and children launched with a cleared environment inherit nothing from the
 * Gradle test worker. Every test-launched child therefore names the flag and the worker's repository-local
 * temporary root explicitly. Site-specific `-Djava.io.tmpdir` options placed after [options] still win.
 */
object ChildJvm {
    const val NO_PERF_DATA = "-XX:-UsePerfData"

    /** The worker's repository-local temporary root, chosen by Gradle under `build/t`. */
    val temporaryDirectory: String get() = System.getProperty("java.io.tmpdir")

    /** A launcher from the JDK running the tests, for example `java` or `javap`. */
    fun executable(tool: String = "java"): String = Path.of(System.getProperty("java.home"), "bin", tool).toString()

    /** HotSpot options for a `java` child. */
    fun options(): List<String> =
        listOf(NO_PERF_DATA, "-Djava.io.tmpdir=$temporaryDirectory", "-Djna.tmpdir=$temporaryDirectory")

    /** The same options for a JDK tool launcher such as `javap`, which forwards `-J` options to its JVM. */
    fun toolOptions(): List<String> = options().map { "-J$it" }

    /** `java` with [options], followed by [arguments]. */
    fun command(vararg arguments: String): List<String> = listOf(executable()) + options() + arguments

    /** A JDK tool launcher with [toolOptions], followed by [arguments]. */
    fun toolCommand(tool: String, vararg arguments: String): List<String> =
        listOf(executable(tool)) + toolOptions() + arguments

    /** Points the child's `TMPDIR` at [temporaryDirectory]; call it after any `environment().clear()`. */
    fun ProcessBuilder.withRepositoryTemporary(): ProcessBuilder = apply {
        environment()["TMPDIR"] = temporaryDirectory
    }
}
