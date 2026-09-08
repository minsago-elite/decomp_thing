package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists

class ArchiveTransportLayoutTest {
    @Test
    fun `archive rejects omitted declared inputs before creating output paths`() {
        val root = createTempDirectory("archive-layout-admission-")
        try {
            for (base in ReconstructionProfiles.builtIn) {
                for ((id, path) in listOf("build-definition" to "build/rebuild.mk",
                    "module-implementation" to "build/modules/{module}.c",
                    "module-implementation" to "{module}/source.c",
                    "module-implementation" to "bui{module}/source.c")) {
                    val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map {
                        if (it.id == id) ProjectFileDeclaration(it.id, path, it.roles, it.contentKind) else it
                    })
                    val profile = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
                    val project = root.resolve("project")
                    val output = root.resolve("output/archive.zip")

                    val failure = assertFailsWith<IllegalArgumentException> {
                        ArchivalPackager.create(project, output, profile = profile)
                    }

                    assertTrue(failure.message.orEmpty().contains("protected path: $path"))
                    assertFalse(project.exists())
                    assertFalse(output.parent.exists())
                }
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `template payload guards distinguish possible output roots from neighboring components`() {
        val layout = ArchiveTransportLayout(setOf("build", "scratch/obj"), emptySet())
        fun declaration(template: String) = ProjectFileDeclaration("source", template,
            setOf(ProjectFileRole.ARCHIVE_PAYLOAD), ProjectContentKind.UTF8_TEXT)
        for (template in listOf("{module}/unit.txt", "bui{module}/unit.txt", "scratch/{module}/unit.txt")) {
            assertFailsWith<IllegalArgumentException>(template) {
                layout.requireRetainsDeclarations(listOf(declaration(template)))
            }
        }
        layout.requireRetainsDeclarations(listOf("build-{module}/unit.txt", "src/{module}/unit.txt",
            "scratch/objects/{module}.txt", "{module}.txt").map(::declaration))
    }

    @Test
    fun `transport layout copies inputs and exposes unmodifiable sets`() {
        val outputs = linkedSetOf("second-output", "first-output")
        val controls = linkedSetOf("evidence/build.json")
        val layout = ArchiveTransportLayout(outputs, controls)

        outputs.clear()
        outputs += "replacement-output"
        controls.clear()
        controls += "replacement-control.json"

        assertEquals(setOf("first-output", "second-output"), layout.excludedOutputRoots)
        assertEquals(setOf("evidence/build.json"), layout.strictBuildControlPaths)
        assertFailsWith<UnsupportedOperationException> {
            (layout.excludedOutputRoots as MutableSet<String>).add("third-output")
        }
        assertFailsWith<UnsupportedOperationException> {
            (layout.strictBuildControlPaths as MutableSet<String>).clear()
        }
        assertEquals(setOf("first-output", "second-output"), layout.excludedOutputRoots)
        assertEquals(setOf("evidence/build.json"), layout.strictBuildControlPaths)
    }

    @Test
    fun `output omissions match complete path components at every depth`() {
        val layout = ArchiveTransportLayout(setOf("build", "scratch/objects"), emptySet())

        for (path in listOf("build", "build/result.txt", "build/nested/result.txt",
            "scratch/objects", "scratch/objects/nested/result.txt")) {
            assertTrue(layout.excludes(path), path)
        }
        for (path in listOf("build-cache", "build-cache/result.txt", "rebuild/result.txt",
            "scratch", "scratch/objects-cache/result.txt", "other/build/result.txt")) {
            assertFalse(layout.excludes(path), path)
        }
    }

    @Test
    fun `overlapping output roots are rejected despite intervening sibling names`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            ArchiveTransportLayout(setOf("build", "build-cache", "build/nested"), emptySet())
        }
        assertTrue(failure.message.orEmpty().contains("archive output roots overlap"))

        val siblings = ArchiveTransportLayout(setOf("scratch/first", "scratch/second"), emptySet())
        assertFalse(siblings.excludes("scratch/third/result.txt"))
    }

    @Test
    fun `strict build controls cannot be omitted by output policy`() {
        for (control in listOf("build", "build/control.json")) {
            val failure = assertFailsWith<IllegalArgumentException>(control) {
                ArchiveTransportLayout(setOf("build"), setOf(control))
            }
            assertTrue(failure.message.orEmpty().contains("protected path: $control"))
        }
    }

    @Test
    fun `protected evidence must remain outside every omitted output root`() {
        val layout = ArchiveTransportLayout(setOf("build", "scratch/objects"), setOf("evidence/build.json"))
        layout.requireRetains(listOf("evidence/build.json", "build-cache/notes.txt", "source/unit.txt"))

        for (path in listOf("build", "scratch/objects/required-evidence.json")) {
            val failure = assertFailsWith<IllegalArgumentException>(path) {
                layout.requireRetains(listOf("evidence/model.json", path))
            }
            assertTrue(failure.message.orEmpty().contains("protected path: $path"))
        }
    }

    @Test
    fun `empty transport policy retains all normalized paths`() {
        val layout = ArchiveTransportLayout(emptySet(), emptySet())

        assertTrue(layout.excludedOutputRoots.isEmpty())
        assertTrue(layout.strictBuildControlPaths.isEmpty())
        assertFalse(layout.excludes("build/result.txt"))
        layout.requireRetains(emptyList())
        layout.requireRetains(listOf("source/unit.txt", "evidence/model.json"))
    }

    @Test
    fun `transport layout and lookup require normalized project paths`() {
        for (path in listOf("", "output//nested", "output/")) {
            assertFailsWith<IllegalArgumentException>(path) { ArchiveTransportLayout(setOf(path), emptySet()) }
            assertFailsWith<IllegalArgumentException>(path) { ArchiveTransportLayout(emptySet(), setOf(path)) }
        }
        val layout = ArchiveTransportLayout(emptySet(), emptySet())
        assertFailsWith<IllegalArgumentException> { layout.excludes("output//result.txt") }
        assertFailsWith<IllegalArgumentException> { layout.requireRetains(listOf("")) }
    }
}
