package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertTrue

class GccBundledCliIntentBuilderTest {
    @Test
    fun `CLI command and requested recovery mode must agree before controls are staged`() = fixture { root ->
        val controls = privateDirectory(root.resolve("controls"))
        val operationJournal = privateDirectory(root.resolve("operation-journal"))
        val scratch = privateDirectory(root.resolve("scratch"))
        val output = privateDirectory(root.resolve("output"))
        val children = listOf(output, privateDirectory(output.resolve("inputs")), privateDirectory(output.resolve("journal")))
        val identities = children.associateWith { path -> LinuxFilesystemSyscalls.openRoot(path).use { it.identity } }
        val binary = Files.writeString(root.resolve("binary"), "fixture")
        val archive = Files.writeString(root.resolve("archive"), "fixture")
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines.json").toRealPath()
        val arguments = listOf("cc1", binary.toString(), "--profile", profile.toString(),
            "--ghidra-archive", archive.toString(), "--output", output.toString(), "--scratch", scratch.toString())
        for (invocationFullMode in listOf(false, true)) {
            val options = GccBundledCliOptions.parse(arguments, fullRecoveryExport = invocationFullMode)
            val invocation = GccBundledCliInvocation(options, arguments, identities)
            assertFails {
                GccBundledCliIntentBuilder.build(SHA, "cc1", GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                    binary, profile, archive, controls, operationJournal, scratch, options.diskPolicy,
                    invocation, fullRecoveryExport = !invocationFullMode)
            }
        }
        assertFails {
            GccBundledCliIntentBuilder.build(SHA, "lto1", GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                binary, profile, archive, controls, operationJournal, scratch, POLICY, fullRecoveryExport = true)
        }
        assertEmpty(controls)
        assertEmpty(operationJournal)
    }

    @Test
    fun `BOOT invocation manifest derives exact ordered paths and identities from retained deployment`() = fixture { root ->
        val deploymentRoot = Path.of(checkNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot"))).toRealPath()
        val reference = GccKotlinBootClasspathReference.open()
        reference.use {
            val manifest = reference.invocationManifestBytes()
            val entries = parseBootClassPathManifest(manifest, root, emptySet())
            assertEquals(reference.entries.map { deploymentRoot.resolve(it.logicalName) }, entries.map { it.path })
            assertEquals(reference.entries.map { it.bytes to it.sha256 }, entries.map { it.bytes to it.sha256 })
            reference.requireCandidateIdentities(entries.map { it.bytes to it.sha256 })
            assertContentEquals(manifest, reference.invocationManifestBytes())
            manifest.fill(0)
            assertTrue(reference.invocationManifestBytes().any { it != 0.toByte() })
        }
        assertFails { reference.invocationManifestBytes() }
    }

    @Test
    fun `wrong engine bytes fail before controls are published`() = fixture { root ->
        val controls = privateDirectory(root.resolve("controls"))
        val journal = privateDirectory(root.resolve("journal"))
        val scratch = privateDirectory(root.resolve("scratch"))
        val binary = Files.writeString(root.resolve("wrong-engine"), "not the selected profile binary")
        val archive = Files.writeString(root.resolve("archive"), "not the archive")
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines.json").toRealPath()
        assertFails {
            GccBundledCliIntentBuilder.build(SHA, "cc1", GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
                binary, profile, archive, controls, journal, scratch, POLICY)
        }
        assertEmpty(controls)
        assertEmpty(journal)
        assertEmpty(scratch)
        assertEquals("not the selected profile binary", Files.readString(binary))
    }

    @Test
    fun `ambiguous roots linked inputs and repeated staging fail before publication`() = fixture { root ->
        val controls = privateDirectory(root.resolve("controls"))
        val journal = privateDirectory(root.resolve("journal"))
        val scratch = privateDirectory(root.resolve("scratch"))
        val binary = Files.writeString(root.resolve("binary"), "binary")
        val archive = Files.writeString(root.resolve("archive"), "archive")
        val profile = Path.of(System.getProperty("user.dir"), "oracle/gcc/16.2.0/compiler-engines.json").toRealPath()
        fun build(selectedBinary: Path = binary, selectedJournal: Path = journal,
            operation: String = SHA, engine: String = "cc1", kind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.FRESH_CONTROL) =
            GccBundledCliIntentBuilder.build(operation, engine, kind, selectedBinary, profile, archive, controls, selectedJournal, scratch, POLICY)
        assertFails { build(selectedJournal = controls) }
        assertFails { build(operation = "invalid") }
        assertFails { build(engine = "driver") }
        assertFails { build(kind = GccCompilerEngineContainmentRunKind.RESUMED) }
        val linked = Files.createSymbolicLink(root.resolve("binary-link"), binary)
        assertFails { build(selectedBinary = linked) }
        assertEmpty(controls)
        val prior = Files.writeString(controls.resolve("boot-classpath.json"), "prior bytes")
        assertFails { build() }
        assertEquals("prior bytes", Files.readString(prior))
        assertEmpty(journal)
        assertEmpty(scratch)
    }

    private fun assertEmpty(path: Path) = Files.list(path).use { assertEquals(0L, it.count()) }
    private fun privateDirectory(path: Path): Path = Files.createDirectory(path,
        PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    private fun fixture(action: (Path) -> Unit) {
        val root = Files.createTempDirectory("gcc-cli-intent-").toRealPath()
        try { action(root) } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }
    private companion object {
        const val SHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        val POLICY = FullTreeDiskScratchPolicy(256L * 1024 * 1024, 1024L * 1024 * 1024, 1024, 16384)
    }
}
