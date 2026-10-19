package decompengine.oracle.gcc

import java.io.IOException
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

    @Test fun `missing aarch64 ABI source refuses other nonempty mounts before interpreter or manifest capture`() {
        for (architecture in listOf("aarch64", "arm64")) {
            var interpreterChecks = 0
            var captures = 0
            val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                withGccSystemLibrarySources(architecture,
                    resolveDirectory = { if (it == Path.of("/lib/aarch64-linux-gnu")) null else it },
                    isRegularFile = { interpreterChecks++; true },
                ) { captures++; error("Unsupported loader mapping must not capture manifests") }
            }
            assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
            assertEquals(0, interpreterChecks); assertEquals(0, captures)
        }
    }

    @Test fun `resolved aliases to whole library roots or their ancestors are refused before capture`() {
        for (alias in listOf("/lib64", "/usr/lib64")) {
            for (resolved in listOf("/", "/usr", "/lib", "/usr/lib")) {
                var interpreterChecks = 0
                var captures = 0
                val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                    withGccSystemLibrarySources("amd64",
                        resolveDirectory = { if (it == Path.of(alias)) Path.of(resolved) else it },
                        isRegularFile = { interpreterChecks++; true },
                    ) { captures++; error("Broad canonical roots must not capture manifests") }
                }
                assertEquals("GCC system-library source resolves to an unsupported whole-library root", failure.message)
                assertEquals(0, interpreterChecks); assertEquals(0, captures)
            }
        }
    }

    @Test fun `both supported ABI mappings require an actual interpreter before manifest capture`() {
        for (architecture in listOf("amd64", "x86_64", "aarch64", "arm64")) {
            var interpreterChecks = 0
            var captures = 0
            val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                withGccSystemLibrarySources(architecture, resolveDirectory = { it },
                    isRegularFile = { interpreterChecks++; false },
                ) { captures++; error("Missing interpreters must not capture manifests") }
            }
            assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
            assertEquals(1, interpreterChecks); assertEquals(0, captures)
        }
    }

    @Test fun `valid canonical sources preserve every destination and validate the interpreter before capture once`() {
        for (architecture in listOf("amd64", "x86_64", "aarch64", "arm64")) {
            val events = mutableListOf<String>()
            val expected = Any()
            val selected = gccSystemLibraryLocations(architecture)
            val interpreter = if (architecture in listOf("amd64", "x86_64")) Path.of("/lib64/ld-linux-x86-64.so.2")
                else Path.of("/lib/aarch64-linux-gnu/ld-linux-aarch64.so.1")
            val result = withGccSystemLibrarySources(architecture,
                resolveDirectory = { events += "resolve"; it },
                isRegularFile = { assertEquals(interpreter, it); events += "interpreter"; true },
            ) { sources -> assertEquals(selected, sources); events += "capture"; expected }
            assertSame(expected, result)
            assertEquals(listOf("resolve", "resolve", "resolve", "resolve", "interpreter", "capture"), events)
        }
    }

    @Test fun `source interpreter and capture failures propagate unchanged without retries`() {
        for (stage in listOf("resolve", "interpreter", "capture")) {
            val original = IOException("synthetic runtime input failure")
            val events = mutableListOf<String>()
            val failure = assertFailsWith<IOException> {
                withGccSystemLibrarySources("amd64",
                    resolveDirectory = { events += "resolve"; if (stage == "resolve") throw original; it },
                    isRegularFile = { events += "interpreter"; if (stage == "interpreter") throw original; true },
                ) { events += "capture"; throw original }
            }
            assertSame(original, failure)
            val expected = if (stage == "resolve") listOf("resolve")
                else listOf("resolve", "resolve", "resolve", "resolve", "interpreter") + if (stage == "capture") listOf("capture") else emptyList()
            assertEquals(expected, events)
        }
    }
}
