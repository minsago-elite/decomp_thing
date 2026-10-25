package decompengine.project

import java.nio.file.Files
import java.nio.file.Path
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.io.TempDir
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals

class ContainedModuleCompilationSnapshotTest {
    @TempDir lateinit var root: Path
    private val profile = GeneratedCMakeReconstructionProfile.descriptor
    private val sourcePath = "src/modules/parser.c"

    @Test fun `snapshot binds candidate and all declared headers but no other implementation or reports`() {
        prepare()
        val first = ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile)
        assertEquals(setOf(sourcePath, "include/decomp_types.h", "include/modules/parser.h",
            "src/modules/parser_internal.h", "include/modules/dependency.h"), first.inputs.map { it.path }.toSet())
        assertFalse(first.inputs.any { "secret" in it.path || it.path.endsWith("other.c") })
        val before = first.inputs.single { it.path == "include/modules/dependency.h" }.sha256
        write("include/modules/dependency.h", "int dependency(long x);\n")
        assertFailsWith<IllegalArgumentException> { first.requireCurrent() }
        val second = ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile)
        assertNotEquals(before, second.inputs.single { it.path == "include/modules/dependency.h" }.sha256)
        write(sourcePath, "int parser(void) { return 2; }\n")
        assertFailsWith<IllegalArgumentException> { second.requireCurrent() }
    }

    @Test fun `missing required interface and symlink cannot enter compiler snapshot`() {
        prepare()
        Files.delete(root.resolve("src/modules/parser_internal.h"))
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile) }
        write("src/modules/parser_internal.h", "/* private */\n")
        Files.delete(root.resolve("include/modules/parser.h"))
        Files.createSymbolicLink(root.resolve("include/modules/parser.h"), root.resolve("include/decomp_types.h"))
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile) }
    }

    @Test fun `undeclared shadow headers precompiled sidecars and changed inventory fail closed`() {
        prepare()
        val captured = ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile)
        write("include/stddef.h", "#error shadowed system header\n")
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile) }
        assertFailsWith<IllegalArgumentException> { captured.requireCurrent() }
        Files.delete(root.resolve("include/stddef.h"))
        write("include/modules/parser.h.gch", "precompiled sidecar")
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile) }
        Files.delete(root.resolve("include/modules/parser.h.gch"))
        Files.createLink(root.resolve("source-alias.c"), root.resolve(sourcePath))
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile) }
    }

    @Test fun `unregistered source path cannot become module compiler authority`() {
        prepare()
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, "src/main.c", profile) }
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationSnapshot.capture(root, "../parser.c", profile) }
    }

    @Test fun `preparation and revalidation charge enclosing deadline during inventory and byte reads`() {
        prepare()
        var calls = 0
        val expired = IllegalStateException("operation deadline exhausted")
        val failure = assertFailsWith<IllegalStateException> {
            ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile) {
                if (++calls == 4) throw expired
            }
        }
        kotlin.test.assertSame(expired, failure)
        assertEquals(4, calls)
        val captured = ContainedModuleCompilationSnapshot.capture(root, sourcePath, profile)
        assertFailsWith<IllegalStateException> { captured.requireCurrent { throw expired } }
        captured.requireCurrent()
    }

    private fun prepare() {
        write(sourcePath, "int parser(void) { return 1; }\n")
        write("src/modules/other.c", "int secret_implementation(void) { return 9; }\n")
        write("include/decomp_types.h", "#include <stdint.h>\n")
        write("include/modules/parser.h", "int parser(void);\n")
        write("include/modules/dependency.h", "int dependency(int x);\n")
        write("src/modules/parser_internal.h", "/* private */\n")
        write("reports/secret.txt", "not compiler input\n")
    }
    private fun write(relative: String, text: String) {
        val path = root.resolve(relative)
        Files.createDirectories(path.parent)
        Files.writeString(path, text)
    }
}
