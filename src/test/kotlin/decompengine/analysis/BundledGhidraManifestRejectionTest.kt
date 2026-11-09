package decompengine.analysis

import java.nio.charset.MalformedInputException
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/** Bounded hash-only fixtures: no worker, agent, native code, or jar loading. */
class BundledGhidraManifestRejectionTest {
    private val bridge = "decomp-ghidra-bridge.jar"
    private val ghidra = "ghidra_12.1.3_PUBLIC/Ghidra"
    private val library = "$ghidra/Framework/Toy/lib/toy.jar"

    private fun fixture(test: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build/test-tmp/manifest-rejection"))
        val root = Files.createTempDirectory(parent, "bundle-")
        try {
            val files = linkedMapOf(
                bridge to "dummy bridge bytes",
                "$ghidra/application.properties" to
                    "application.version=12.1.3\napplication.release.name=PUBLIC\n",
                library to "dummy library bytes",
            )
            val manifest = files.entries.joinToString("\n", postfix = "\n") { (name, content) ->
                val path = root.resolve(name)
                Files.createDirectories(path.parent)
                val bytes = content.toByteArray(Charsets.UTF_8)
                Files.write(path, bytes)
                val hash = MessageDigest.getInstance("SHA-256").digest(bytes)
                    .joinToString("") { "%02x".format(it) }
                "$hash  $name"
            }
            Files.writeString(root.resolve("bundle.sha256"), manifest)
            // Every negative starts from a bundle accepted by the actual verifier.
            BundledGhidra.at(root).verify()
            test(root)
        } finally {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { Files.delete(it) }
            }
        }
    }

    private fun refusal(root: Path, message: String) {
        val failure = assertFailsWith<IllegalArgumentException> { BundledGhidra.at(root).verify() }
        assertEquals(message, failure.message)
    }

    @Test
    fun `valid bounded bundle verifies without loading jars`() = fixture { root ->
        BundledGhidra.at(root).verify()
        assertEquals(listOf(root.toAbsolutePath().resolve(library)),
            BundledGhidra.at(root).verifiedLibraryPaths {})
    }

    @Test
    fun `changed bytes with old manifest are corrupt`() = fixture { root ->
        Files.writeString(root.resolve(bridge), "replacement bytes")
        refusal(root, "Corrupt bundled Ghidra file: $bridge")
    }

    @Test
    fun `extra regular file changes inventory`() = fixture { root ->
        Files.writeString(root.resolve("extra.jar"), "extra")
        refusal(root, "Bundled Ghidra file inventory changed")
    }

    @Test
    fun `unlisted publication temporary file changes inventory`() = fixture { root ->
        Files.writeString(root.resolve("publication.tmp"), "partial publication")
        refusal(root, "Bundled Ghidra file inventory changed")
    }

    @Test
    fun `missing listed file is refused`() = fixture { root ->
        Files.delete(root.resolve(bridge))
        refusal(root, "Missing bundled Ghidra file: $bridge")
    }

    @Test
    fun `symlinked listed file is refused`() = fixture { root ->
        val path = root.resolve(bridge)
        Files.move(path, root.resolve("bridge-target"))
        Files.createSymbolicLink(path, Path.of("bridge-target"))
        refusal(root, "Linked bundled Ghidra file: $bridge")
    }

    @Test
    fun `symlinked directory component is refused`() = fixture { root ->
        val directory = root.resolve("$ghidra/Framework/Toy/lib")
        Files.move(directory, directory.resolveSibling("real-lib"))
        Files.createSymbolicLink(directory, Path.of("real-lib"))
        refusal(root, "Linked bundled Ghidra file: $library")
    }

    @Test
    fun `malformed UTF8 manifest is refused`() = fixture { root ->
        Files.write(root.resolve("bundle.sha256"), byteArrayOf(0xc3.toByte(), 0x28))
        val failure = assertFailsWith<MalformedInputException> { BundledGhidra.at(root).verify() }
        assertEquals("Input length = 1", failure.message)
    }

    @Test
    fun `blank manifest record is refused`() = fixture { root ->
        Files.writeString(root.resolve("bundle.sha256"), "\n")
        refusal(root, "Invalid bundled Ghidra checksum record")
    }

    @Test
    fun `invalid checksum record is refused`() = fixture { root ->
        Files.writeString(root.resolve("bundle.sha256"), "${"g".repeat(64)}  $bridge\n")
        refusal(root, "Invalid bundled Ghidra checksum record")
    }

    @Test
    fun `empty manifest is refused by inventory guard`() = fixture { root ->
        Files.write(root.resolve("bundle.sha256"), byteArrayOf())
        refusal(root, "Bundled Ghidra file inventory changed")
    }
}
