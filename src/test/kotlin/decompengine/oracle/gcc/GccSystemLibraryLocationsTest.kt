package decompengine.oracle.gcc

import java.nio.file.Path
import kotlin.test.*

/** Pure path metadata only; no filesystem capture, provisioning or native worker invocation. */
class GccSystemLibraryLocationsTest {
    @Test fun `x86 libraries retain ABI search locations and loader directories without whole library roots`() {
        val paths = listOf("/lib/x86_64-linux-gnu", "/lib64", "/usr/lib/x86_64-linux-gnu", "/usr/lib64").map(Path::of)
        for (architecture in listOf("amd64", "x86_64")) {
            val locations = gccSystemLibraryLocations(architecture)
            assertEquals(paths.map { it to it }, locations)
            assertTrue(locations.none { (source, _) -> source == Path.of("/lib") || source == Path.of("/usr/lib") })
        }
    }

    @Test fun `aarch64 interpreter and multiarch search destinations remain separate and complete`() {
        for (architecture in listOf("aarch64", "arm64")) {
            val locations = gccSystemLibraryLocations(architecture)
            assertEquals(listOf(
                Path.of("/lib/aarch64-linux-gnu") to Path.of("/lib"),
                Path.of("/lib64") to Path.of("/lib64"),
                Path.of("/usr/lib/aarch64-linux-gnu") to Path.of("/usr/lib/aarch64-linux-gnu"),
                Path.of("/usr/lib64") to Path.of("/usr/lib64"),
            ), locations)
            val destinations = locations.map { it.second }
            destinations.forEachIndexed { index, destination ->
                destinations.drop(index + 1).forEach { other ->
                    assertFalse(destination.startsWith(other) || other.startsWith(destination), "Runtime destinations must not overlap")
                }
            }
            assertTrue(locations.none { (source, _) -> source == Path.of("/lib") || source == Path.of("/usr/lib") })
        }
    }

    @Test fun `unsupported architectures fail explicitly before runtime capture instead of selecting broad roots`() {
        for (architecture in listOf("", "riscv64", "ppc64le", "AMD64", "../x86_64-linux-gnu")) {
            val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                gccSystemLibraryLocations(architecture)
            }
            assertEquals("GCC host has no fixed system-library ABI mapping", failure.message)
        }
    }
}
