package decompengine.ci

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Fixed CI flags for the five byte-exact child protocols; never parses shell option strings. */
fun ProcessBuilder.ownedJvmChild(): ProcessBuilder {
    val receipt = System.getProperty("decompengine.ci.fixture.receipt") ?: return this
    val state = Path.of(receipt).parent
    val java = Path.of(System.getProperty("java.home"), "bin/java")
    require(java.toRealPath() == java && Path.of(command().first()).toRealPath() == java)
    val uid = Files.getAttribute(java, "unix:uid", LinkOption.NOFOLLOW_LINKS)
    val scratch = Path.of(System.getProperty("java.io.tmpdir"))
    require(scratch.toString() == System.getenv("TMPDIR") && scratch.toString() == System.getProperty("jna.tmpdir"))
    val properties = linkedMapOf(
        "java.io.tmpdir" to scratch,
        "jna.tmpdir" to scratch,
        "user.home" to state.resolve("home"),
        "java.util.prefs.userRoot" to state.resolve("preferences"),
        "java.util.prefs.systemRoot" to state.resolve("preferences"),
    )
    for ((key, path) in properties) {
        require(path.isAbsolute && path.toRealPath() == path && System.getProperty(key) == path.toString())
        val attrs = Files.readAttributes(path, "unix:uid,mode", LinkOption.NOFOLLOW_LINKS)
        require(Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) && attrs.getValue("uid") == uid &&
            (attrs.getValue("mode") as Number).toInt() and 0x12 == 0)
    }
    command(listOf(command().first(), "-XX:-UsePerfData", "-XX:+DisableAttachMechanism") +
        properties.map { (key, value) -> "-D$key=$value" } + command().drop(1))
    // These variables are banner-producing. The admitted fixed properties above replace them.
    listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS").forEach { environment().remove(it) }
    return this
}
