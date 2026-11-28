package decompengine.testing

import org.junit.jupiter.api.io.TempDir
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.channels.ServerSocketChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Ordinary test JVMs must keep temporary files under the repository build directory (#2001). */
class RepositoryTemporaryRootTest {
    @TempDir lateinit var junitDirectory: Path

    private val repositoryRoot: Path = Path.of(assertNotNull(System.getProperty("decompengine.test.repositoryRoot"),
        "Gradle must name the repository root for test JVMs")).toRealPath()
    private val buildRoot: Path = repositoryRoot.resolve("build").toRealPath()

    private fun assertUnderBuild(path: Path, what: String) {
        val real = path.toRealPath()
        assertTrue(real.startsWith(buildRoot), "$what resolved outside $buildRoot: $real")
    }

    @Test
    fun `temporary directory settings name one existing root under build`() {
        val javaTemporary = Path.of(System.getProperty("java.io.tmpdir"))
        assertTrue(Files.isDirectory(javaTemporary), "java.io.tmpdir must exist before tests run: $javaTemporary")
        assertUnderBuild(javaTemporary, "java.io.tmpdir")
        assertEquals(javaTemporary.toRealPath(), Path.of(System.getProperty("jna.tmpdir")).toRealPath())
        assertEquals(javaTemporary.toRealPath(), Path.of(assertNotNull(System.getenv("TMPDIR"))).toRealPath())
    }

    @Test
    fun `each test execution gets its own owner-only root named by a short base36 counter under build t`() {
        val javaTemporary = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize()
        assertEquals(buildRoot.resolve("t"), javaTemporary.parent.toRealPath(),
            "java.io.tmpdir must be a per-execution child of build/t")
        assertTrue(javaTemporary.fileName.toString().matches(Regex("[0-9a-z]{1,2}")),
            "per-execution root must be a one- or two-character base36 counter: $javaTemporary")
        assertTrue(Files.isDirectory(javaTemporary, LinkOption.NOFOLLOW_LINKS), "per-execution root must not be a link")
        assertEquals("rwx------", PosixFilePermissions.toString(
            Files.getPosixFilePermissions(javaTemporary, LinkOption.NOFOLLOW_LINKS)))
    }

    @Test
    fun `junit TempDir resolves under the repository build directory`() {
        assertUnderBuild(junitDirectory, "@TempDir")
    }

    @Test
    fun `Files createTempDirectory and createTempFile resolve under the repository build directory`() {
        val directory = Files.createTempDirectory("repository-temporary-root")
        try {
            assertUnderBuild(directory, "Files.createTempDirectory()")
            val file = Files.createTempFile("repository-temporary-root", ".tmp")
            try {
                assertUnderBuild(file, "Files.createTempFile()")
            } finally {
                Files.deleteIfExists(file)
            }
        } finally {
            Files.deleteIfExists(directory)
        }
    }

    @Test
    fun `test worker JVM disables HotSpot perf data so it writes no hsperfdata file`() {
        assertTrue("-XX:-UsePerfData" in java.lang.management.ManagementFactory.getRuntimeMXBean().inputArguments)
        val perfData = Path.of("/tmp", "hsperfdata_${System.getProperty("user.name")}", ProcessHandle.current().pid().toString())
        assertTrue(!Files.exists(perfData, java.nio.file.LinkOption.NOFOLLOW_LINKS), "worker wrote $perfData")
    }

    @Test
    fun `short socket directories stay repository-local and fit sun_path at fixture depth`() {
        val root = ShortSocketDirectory.create()
        try {
            assertUnderBuild(root, "ShortSocketDirectory")
            // Every socket path the ShortSocketDirectory fixtures bind, relative to their root. The longest is
            // runtime/docker.sock; keep this list in step with the fixtures when they add or rename sockets.
            val fixtureSockets = listOf("runtime/bus", "runtime/new", "runtime/docker.sock", "src/socket")
            val sockets = fixtureSockets.map(root::resolve)
            // The per-execution root counter grows to two characters before ./gradlew clean resets it;
            // the longest fixture socket must still fit at that depth.
            val worstCase = Path.of(System.getProperty("java.io.tmpdir")).toAbsolutePath().normalize()
                .resolveSibling("zz").resolve(root.fileName).resolve(fixtureSockets.maxBy { it.length })
            assertTrue(worstCase.toString().toByteArray().size < 108, "worst-case socket path exceeds sun_path: $worstCase")
            sockets.forEach { socket ->
                Files.createDirectories(socket.parent)
                assertTrue(socket.toString().toByteArray().size < 108, "socket path exceeds sun_path: $socket")
                ServerSocketChannel.open(StandardProtocolFamily.UNIX).use { it.bind(UnixDomainSocketAddress.of(socket)) }
                assertUnderBuild(socket, "fixture socket")
            }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
