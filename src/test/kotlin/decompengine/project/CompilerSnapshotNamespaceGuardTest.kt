package decompengine.project

import com.sun.jna.Memory
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.FileTime
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Bounded filesystem-only controls: no compiler, keeper, native oracle or live acceptance. */
class CompilerSnapshotNamespaceGuardTest {
    @Test
    fun `unchanged snapshot reads and unrelated output writes preserve namespace admission`() = withRoot { parent, root ->
        CompilerSnapshotNamespaceGuard.open(root).use { guard ->
            assertEquals("int alpha(void);\n", Files.readString(root.resolve("include/modules/alpha.h")))
            Files.writeString(parent.resolve("compiler.stdout"), "unrelated sibling output")
            guard.requireUnchanged()
            guard.requireUnchanged()
        }
    }

    @Test
    fun `transient undeclared nested header shadow header and sidecars invalidate matching endpoint inventories`() = withRoot { _, root ->
        for (name in listOf("include/modules/transient.h", "src/modules/alpha.h", "include/modules/alpha.h.gch",
            "include/modules/alpha.h.pch", "include/new-directory")) {
            val before = inventory(root)
            CompilerSnapshotNamespaceGuard.open(root).use { guard ->
                val path = root.resolve(name)
                if (name.endsWith("new-directory")) Files.createDirectory(path)
                else {
                    Files.writeString(path, "#define TRANSIENT 99\n")
                    assertTrue(Files.readString(path).contains("TRANSIENT"))
                }
                Files.delete(path)
                assertEquals(before, inventory(root), name)
                assertFailsWith<IllegalArgumentException>(name) { guard.requireUnchanged() }
                // Refusal is sticky, not a queue drain that permits the next attempt on this guard.
                assertFailsWith<IllegalStateException>(name) { guard.requireUnchanged() }
            }
        }
    }

    @Test
    fun `replacing and restoring a snapshot ancestor invalidates the original inode watches`() = withRoot { parent, root ->
        CompilerSnapshotNamespaceGuard.open(root).use { guard ->
            val parked = parent.resolve("parked")
            Files.move(root, parked)
            Files.createDirectory(root)
            Files.writeString(root.resolve("transient.h"), "#define SHADOW 1\n")
            Files.delete(root.resolve("transient.h"))
            Files.delete(root)
            Files.move(parked, root)
            assertFailsWith<IllegalArgumentException> { guard.requireUnchanged() }
        }
    }

    @Test
    fun `empty header write restore and mutation after an earlier successful check are not forgotten`() = withRoot { _, root ->
        val empty = Files.createFile(root.resolve("include/empty.h"))
        val modified = Files.getLastModifiedTime(empty)
        CompilerSnapshotNamespaceGuard.open(root).use { guard ->
            guard.requireUnchanged()
            Files.writeString(empty, "transient bytes")
            Files.write(empty, ByteArray(0))
            Files.setLastModifiedTime(empty, FileTime.fromMillis(modified.toMillis()))
            assertEquals(0L, Files.size(empty))
            assertFailsWith<IllegalArgumentException> { guard.requireUnchanged() }
        }
    }

    @Test
    fun `overflow lost watch unknown watch and malformed events fail closed`() = withRoot { _, root ->
        CompilerSnapshotNamespaceGuard.open(root).use { guard ->
            val inspect = CompilerSnapshotNamespaceGuard::class.java.getDeclaredMethod("inspect", Memory::class.java, Int::class.javaPrimitiveType)
            inspect.isAccessible = true
            for ((watch, mask, length) in listOf(Triple(-1, 0x4000, 0), Triple(1, 0x8000, 0),
                Triple(1, 0x2000, 0), Triple(Int.MAX_VALUE, 0x100, 0), Triple(1, 0x100, -1), Triple(1, 0x100, 1024))) {
                Memory(16).use { buffer ->
                    buffer.clear()
                    buffer.setInt(0, watch)
                    buffer.setInt(4, mask)
                    buffer.setInt(12, length)
                    val failure = assertFailsWith<InvocationTargetException> { inspect.invoke(guard, buffer, 16) }
                    assertTrue(failure.cause is IllegalArgumentException)
                }
            }
            Memory(16).use { buffer ->
                val failure = assertFailsWith<InvocationTargetException> { inspect.invoke(guard, buffer, 15) }
                assertTrue(failure.cause is IllegalArgumentException)
            }
        }
    }

    @Test
    fun `depth truncated namespaces refuse instead of hiding deeper search inputs`() = withRoot { _, root ->
        var directory = root
        repeat(32) { directory = Files.createDirectory(directory.resolve("nested")) }
        Files.writeString(directory.resolve("hidden.h"), "undeclared header below the walk cutoff")
        assertFailsWith<IllegalArgumentException> { CompilerSnapshotNamespaceGuard.open(root) }
    }

    @Test
    fun `closed guards and symbolic snapshot roots refuse without leaking the monitor descriptor`() = withRoot { parent, root ->
        // Initialize JNA before measuring only the per-attempt monitor ownership.
        CompilerSnapshotNamespaceGuard.open(root).use { it.requireUnchanged() }
        val before = descriptors()
        repeat(8) {
            val guard = CompilerSnapshotNamespaceGuard.open(root)
            val field = CompilerSnapshotNamespaceGuard::class.java.getDeclaredField("descriptor").apply { isAccessible = true }
            val info = Files.readString(Path.of("/proc/self/fdinfo/${field.getInt(guard)}"))
            val flags = info.lineSequence().single { it.startsWith("flags:") }.substringAfter(':').trim().toInt(8)
            assertEquals(0x80800, flags and 0x80800, "namespace FD must be nonblocking and close-on-exec")
            guard.close()
            guard.close()
            assertFailsWith<IllegalStateException> { guard.requireUnchanged() }
            val alias = parent.resolve("alias")
            Files.createSymbolicLink(alias, root)
            try {
                assertFailsWith<IllegalArgumentException> { CompilerSnapshotNamespaceGuard.open(alias) }
            } finally { Files.delete(alias) }
        }
        assertEquals(before, descriptors())
    }

    private fun descriptors(): Long = Files.list(Path.of("/proc/self/fd")).use { it.count() }
    private fun inventory(root: Path): List<String> = Files.walk(root).use { paths ->
        paths.map { root.relativize(it).toString() }.sorted().toList()
    }

    private fun withRoot(action: (Path, Path) -> Unit) {
        val work = Path.of("build/test-work/compiler-namespace").toAbsolutePath().normalize()
        Files.createDirectories(work)
        val parent = Files.createTempDirectory(work, "fixture-")
        try {
            val root = Files.createDirectory(parent.resolve("snapshot"))
            Files.createDirectories(root.resolve("include/modules"))
            Files.createDirectories(root.resolve("src/modules"))
            Files.writeString(root.resolve("include/modules/alpha.h"), "int alpha(void);\n")
            action(parent, root)
        } finally {
            Files.walk(parent).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
}
