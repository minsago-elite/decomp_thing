package decompengine.analysis

import java.lang.reflect.InvocationTargetException
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class GhidraProjectLocationTest {
    @Test
    fun `accepted project paths are passed to Ghidra unchanged`() {
        val project = Path.of("/srv/decomp-jobs/job-1/reports/analysis/ghidra_project")
        assertEquals(project, GhidraProjectLocation.forWorker(project, project.parent, processDirectoryAvailable = false))
        assertEquals(project, GhidraProjectLocation.forWorker(project.resolve("x/.."), project.parent))
    }

    @Test
    fun `dot prefixed data directories reach Ghidra through the worker directory`() {
        for (root in listOf(
            "/home/user/work/.decomp_engine/jobs", "/home/user/.local/share/decomp",
            "/home/user/repo/.claude/worktrees/agent-1/build", "/srv/jobs+archive",
        )) {
            val work = Path.of(root, "job-1", "reports", "analysis")
            val project = work.resolve("ghidra_project")
            assertFalse(GhidraProjectLocation.accepts(project), root)
            val located = GhidraProjectLocation.forWorker(project, work, processDirectoryAvailable = true)
            assertEquals(Path.of("/proc/self/cwd/ghidra_project"), located, root)
            assertTrue(GhidraProjectLocation.accepts(located))
            assertEquals(Path.of("/proc/self/cwd/state/ghidra_project"),
                GhidraProjectLocation.forWorker(work.resolve("state/ghidra_project"), work, processDirectoryAvailable = true))
        }
    }

    @Test
    fun `projects that cannot be aliased fail with an actionable message before launch`() {
        val work = Path.of("/home/user/.decomp_engine/jobs/job-1/reports/analysis")
        val cases = listOf(
            work.resolve("ghidra_project") to Path.of("/elsewhere"),
            work to work,
            work.resolve(".hidden/ghidra_project") to work,
            work.resolve("ghidra+project") to work,
        )
        for ((project, directory) in cases) {
            val failure = assertFailsWith<IllegalArgumentException>(project.toString()) {
                GhidraProjectLocation.forWorker(project, directory, processDirectoryAvailable = true)
            }
            assertTrue(failure.message!!.contains("Choose a data or output directory"), failure.message)
        }
        assertFailsWith<IllegalArgumentException> {
            GhidraProjectLocation.forWorker(work.resolve("ghidra_project"), work, processDirectoryAvailable = false)
        }
    }

    @Test
    fun `element rule matches the bundled Ghidra naming utility`() {
        val bundle = Path.of(checkNotNull(System.getProperty("decompengine.ghidra.bundle")) {
            "test task must stage the bundled Ghidra release"
        }).resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Framework")
        val jars = listOf(
            bundle.resolve("FileSystem/lib/FileSystem.jar"),
            Files.list(bundle.resolve("Generic/lib")).use { paths ->
                paths.filter { it.fileName.toString().startsWith("commons-lang3-") }.toList().single()
            },
        )
        URLClassLoader(jars.map { it.toUri().toURL() }.toTypedArray(), null).use { loader ->
            val checkName = loader.loadClass("ghidra.util.NamingUtilities")
                .getMethod("checkName", String::class.java, String::class.java)
            val samples = listOf(
                "", " ", ".", "..", ".decomp_engine", ".claude", "jobs", "ghidra_project", "a.b", "a b", "a-b=c@d",
                "(x)[y]~z", "a+b", "a,b", "a#b", "a%b", "a:b", "a\\b", "a'b", "naïve", "日本", "x\u0000y", "tab\t", "a!b",
            )
            for (sample in samples) {
                val ghidraAccepts = try {
                    checkName.invoke(null, sample, null)
                    true
                } catch (failure: InvocationTargetException) {
                    assertTrue(failure.cause is IllegalArgumentException, sample)
                    false
                }
                assertEquals(ghidraAccepts, GhidraProjectLocation.acceptsElement(sample), "element <$sample>")
            }
        }
    }
}
