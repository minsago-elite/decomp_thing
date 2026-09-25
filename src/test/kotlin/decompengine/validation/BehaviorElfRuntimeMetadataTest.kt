package decompengine.validation

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class BehaviorElfRuntimeMetadataTest {
    @Test
    fun `reader captures the dynamic loader and recursive-library roots from a real ELF`() {
        val root = Files.createTempDirectory("behavior-elf-runtime-")
        val source = root.resolve("probe.c")
        val executable = root.resolve("probe")
        Files.writeString(source, "#include <stdio.h>\nint main(void) { puts(\"probe\"); return 0; }\n")
        val compiler = ProcessBuilder("gcc", source.toString(), "-o", executable.toString())
            .redirectErrorStream(true).start()
        val diagnostics = compiler.inputStream.readAllBytes().decodeToString()
        assertEquals(0, compiler.waitFor(), diagnostics)

        val metadata = BehaviorElfRuntimeMetadataReader.read(Files.readAllBytes(executable))
        assertEquals(62, metadata.machine)
        assertEquals(2, metadata.elfClass)
        assertTrue(metadata.interpreter?.isAbsolute == true)
        assertTrue("libc.so.6" in metadata.neededLibraries)

        val librarySource = root.resolve("library.c")
        val library = root.resolve("libprobe.so")
        Files.writeString(librarySource, "#include <stdio.h>\nvoid probe(void) { puts(\"library\"); }\n")
        val linker = ProcessBuilder("gcc", "-shared", "-fPIC", librarySource.toString(), "-o", library.toString())
            .redirectErrorStream(true).start()
        val linkerDiagnostics = linker.inputStream.readAllBytes().decodeToString()
        assertEquals(0, linker.waitFor(), linkerDiagnostics)
        val libraryMetadata = BehaviorElfRuntimeMetadataReader.read(Files.readAllBytes(library))
        assertEquals(null, libraryMetadata.interpreter)
        assertTrue("libc.so.6" in libraryMetadata.neededLibraries)
    }

    @Test
    fun `reader rejects host-dependent RPATH and oversized program tables`() {
        val root = Files.createTempDirectory("behavior-elf-rpath-")
        val source = root.resolve("probe.c")
        val executable = root.resolve("probe")
        Files.writeString(source, "int main(void) { return 0; }\n")
        val compiler = ProcessBuilder("gcc", source.toString(), "-Wl,-rpath,/tmp", "-o", executable.toString())
            .redirectErrorStream(true).start()
        val diagnostics = compiler.inputStream.readAllBytes().decodeToString()
        assertEquals(0, compiler.waitFor(), diagnostics)
        assertFailsWith<IllegalArgumentException> {
            BehaviorElfRuntimeMetadataReader.read(Files.readAllBytes(executable))
        }

        val ordinary = Files.readAllBytes(Path.of("/bin/true"))
        val byteOrder = if (ordinary[5].toInt() == 1) ByteOrder.LITTLE_ENDIAN else ByteOrder.BIG_ENDIAN
        ByteBuffer.wrap(ordinary).order(byteOrder).putShort(56, 0xffff.toShort())
        assertFailsWith<IllegalArgumentException> { BehaviorElfRuntimeMetadataReader.read(ordinary) }
    }
}
