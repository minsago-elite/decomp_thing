package decompengine.project

import decompengine.oracle.fulltree.ContainedCommandExecutableAlias
import decompengine.oracle.fulltree.KotlinSystemdCgroupCommandInput
import decompengine.oracle.fulltree.requireContainedCommandExecutableAliases
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse

class OwnedModuleCompilerSnapshotTest {
    @Test
    fun `host snapshot is digest identical owned single linked and executable without writable bits`() = fixture { root ->
        val input = compiler()
        val destination = root.resolve("compiler")
        val copy = materializeOwnedModuleCompilerSnapshot(input, destination)
        assertEquals(input.copy(path = destination), copy)
        assertEquals(input.sha256, sha256(Files.readAllBytes(destination)))
        assertEquals(Files.getAttribute(root, "unix:uid"), Files.getAttribute(destination, "unix:uid"))
        assertEquals(1, Files.getAttribute(destination, "unix:nlink"))
        assertEquals(PosixFilePermissions.fromString("r-x------"), Files.getPosixFilePermissions(destination))
        requireContainedCommandExecutableAliases(listOf(input, copy), listOf(ContainedCommandExecutableAlias(copy.path, input.path)))
    }

    @Test
    fun `wrong compiler pin is refused before snapshot creation`() = fixture { root ->
        assertFails { materializeOwnedModuleCompilerSnapshot(compiler().copy(sha256 = "0".repeat(64)), root.resolve("compiler")) }
        assertFalse(Files.exists(root.resolve("compiler")))
        assertFails { materializeOwnedModuleCompilerSnapshot(compiler().copy(bytes = 64L * 1024 * 1024 + 1), root.resolve("oversized")) }
        assertFalse(Files.exists(root.resolve("oversized")))
        val publicParent = Files.createDirectory(root.resolve("public"))
        Files.setPosixFilePermissions(publicParent, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFails { materializeOwnedModuleCompilerSnapshot(compiler(), publicParent.resolve("compiler")) }
        assertFalse(Files.exists(publicParent.resolve("compiler")))
    }

    @Test
    fun `existing snapshot is not replaced and untrusted source cannot grant executable authority`() = fixture { root ->
        val destination = Files.writeString(root.resolve("compiler"), "retained")
        assertFails { materializeOwnedModuleCompilerSnapshot(compiler(), destination) }
        assertEquals("retained", Files.readString(destination))
        val input = KotlinSystemdCgroupCommandInput(destination, 8, sha256("retained".toByteArray()))
        assertFails { materializeOwnedModuleCompilerSnapshot(input, root.resolve("untrusted")) }
        assertFalse(Files.exists(root.resolve("untrusted")))
    }

    @Test
    fun `alias refuses mismatched bytes digests missing records duplicate aliases and self aliases`() = fixture { root ->
        val original = compiler()
        val copy = materializeOwnedModuleCompilerSnapshot(original, root.resolve("compiler"))
        val alias = ContainedCommandExecutableAlias(copy.path, original.path)
        assertFails { requireContainedCommandExecutableAliases(listOf(original), listOf(alias)) }
        assertFails { requireContainedCommandExecutableAliases(listOf(copy), listOf(alias)) }
        assertFails { requireContainedCommandExecutableAliases(listOf(original, copy.copy(bytes = copy.bytes + 1)), listOf(alias)) }
        assertFails { requireContainedCommandExecutableAliases(listOf(original, copy.copy(sha256 = "0".repeat(64))), listOf(alias)) }
        assertFails { requireContainedCommandExecutableAliases(listOf(original, copy), listOf(alias, alias)) }
        assertFails { requireContainedCommandExecutableAliases(listOf(original, copy), listOf(ContainedCommandExecutableAlias(copy.path, copy.path))) }
        assertFails { requireContainedCommandExecutableAliases(listOf(original, copy), listOf(ContainedCommandExecutableAlias(original.path, copy.path))) }
        requireContainedCommandExecutableAliases(listOf(original, copy), emptyList())
    }

    private fun compiler(): KotlinSystemdCgroupCommandInput {
        val path = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
        assertEquals(0, Files.getAttribute(path, "unix:uid"))
        return KotlinSystemdCgroupCommandInput(path, Files.size(path), sha256(Files.readAllBytes(path)))
    }

    private fun fixture(action: (Path) -> Unit) {
        val parent = Path.of("build/test-work/owned-module-compiler").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "fixture-")
        try { action(root) } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
}
