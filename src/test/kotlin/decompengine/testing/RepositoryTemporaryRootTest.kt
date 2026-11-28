package decompengine.testing

import org.junit.jupiter.api.io.TempDir
import java.nio.file.Files
import java.nio.file.Path
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
}
