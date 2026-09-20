package decompengine.jobs

import decompengine.project.ArchiveTransportLayout
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class JobArchiveInventoryLayoutTest {
    @Test
    fun `archive inventory uses declared output roots and preserves neighboring source files`() {
        val root = createTempDirectory("job-archive-layout-")
        try {
            val store = JobStore(root)
            val job = store.createFromUpload("authored.elf", elfFixture())
            val tree = store.reportsDirectory(job.id).resolve("source-tree").createDirectories()
            val files = setOf(
                "notes.txt",
                "src/module.txt",
                "build/source.txt",
                "artifacts/sibling.txt",
                "artifacts/obj/module.txt",
                ".ninja_log",
                ".ninja_deps",
            )
            files.forEach { relative ->
                val path = tree.resolve(relative)
                path.parent.createDirectories()
                path.writeText("Authored local inventory text: $relative\n")
            }
            val cases = listOf(
                "artifacts" to setOf("notes.txt", "src/module.txt", "build/source.txt", ".ninja_log", ".ninja_deps"),
                "artifacts/obj" to setOf("notes.txt", "src/module.txt", "build/source.txt", "artifacts/sibling.txt", ".ninja_log", ".ninja_deps"),
                "build" to setOf("notes.txt", "src/module.txt", "artifacts/sibling.txt", "artifacts/obj/module.txt", ".ninja_log", ".ninja_deps"),
            )
            for ((outputRoot, expectedFiles) in cases) {
                val layout = ArchiveTransportLayout(
                    excludedOutputRoots = setOf(outputRoot),
                    strictBuildControlPaths = emptySet(),
                )
                val inventory = store.sourceArchiveInventory(job.id, layout)
                assertEquals(expectedFiles, inventory.filterValues { it.isRegularFile }.keys, outputRoot)
                assertTrue(inventory.keys.none { it == outputRoot || it.startsWith("$outputRoot/") }, outputRoot)
            }

            val ninjaLayout = ArchiveTransportLayout(
                excludedOutputRoots = setOf("build", ".ninja_log", ".ninja_deps"),
                strictBuildControlPaths = emptySet(),
            )
            val ninjaInventory = store.sourceArchiveInventory(job.id, ninjaLayout)
            assertEquals(
                setOf("notes.txt", "src/module.txt", "artifacts/sibling.txt", "artifacts/obj/module.txt"),
                ninjaInventory.filterValues { it.isRegularFile }.keys,
            )

            val caseVariantLayout = ArchiveTransportLayout(
                excludedOutputRoots = setOf("BUILD"),
                strictBuildControlPaths = emptySet(),
            )
            val caseVariantInventory = store.sourceArchiveInventory(job.id, caseVariantLayout)
            assertTrue(caseVariantInventory.keys.none { it == "build" || it.startsWith("build/") })
            assertTrue(caseVariantInventory["build"] == null)
            assertTrue(caseVariantInventory["build/source.txt"] == null)
            assertTrue(ninjaInventory.keys.none { it == ".ninja_log" || it == ".ninja_deps" || it == "build" })
            assertTrue(ninjaInventory[".ninja_log"] == null)
            assertTrue(ninjaInventory[".ninja_deps"] == null)
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
