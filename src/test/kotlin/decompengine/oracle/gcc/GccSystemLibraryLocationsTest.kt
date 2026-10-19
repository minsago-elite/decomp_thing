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
                    symbolicLinkTarget = { null },
                    isDirectory = { true },
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
                        symbolicLinkTarget = { null },
                        isDirectory = { true },
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
                    symbolicLinkTarget = { null },
                    isDirectory = { true },
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
                symbolicLinkTarget = { null },
                isDirectory = { true },
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
                    symbolicLinkTarget = { null },
                    isDirectory = { true },
                    isRegularFile = { events += "interpreter"; if (stage == "interpreter") throw original; true },
                ) { events += "capture"; throw original }
            }
            assertSame(original, failure)
            val expected = if (stage == "resolve") listOf("resolve")
                else listOf("resolve", "resolve", "resolve", "resolve", "interpreter") + if (stage == "capture") listOf("capture") else emptyList()
            assertEquals(expected, events)
        }
    }

    @Test fun `canonical host interpreter cannot substitute for a missing mounted target`() {
        var regularChecks = 0
        var captures = 0
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            withGccSystemLibrarySources("amd64",
                resolveDirectory = { mergedX86Source(it, includeLibAbi = false) },
                symbolicLinkTarget = { if (it == Path.of("/usr/lib64/ld-linux-x86-64.so.2"))
                    Path.of("../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2") else null },
                isDirectory = { true },
                isRegularFile = { regularChecks++; true },
            ) { captures++; error("A host-only interpreter must not capture manifests") }
        }
        assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
        assertEquals(0, regularChecks); assertEquals(0, captures)
    }

    @Test fun `relative and absolute interpreter links use their actual selected destination mounts`() {
        for ((includeLibAbi, target) in listOf(
            true to "../lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
            false to "/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
        )) {
            var captures = 0
            var regularChecks = 0
            val expected = Any()
            val result = withGccSystemLibrarySources("amd64",
                resolveDirectory = { mergedX86Source(it, includeLibAbi) },
                symbolicLinkTarget = { if (it == Path.of("/usr/lib64/ld-linux-x86-64.so.2")) Path.of(target) else null },
                isDirectory = { true },
                isRegularFile = { regularChecks++; assertEquals(Path.of("/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"), it); true },
            ) { sources -> captures++; assertEquals(if (includeLibAbi) 4 else 3, sources.size); expected }
            assertSame(expected, result); assertEquals(1, captures); assertEquals(1, regularChecks)
        }
    }

    @Test fun `absolute interpreter links outside selected mounts refuse before capture`() {
        var regularChecks = 0
        var captures = 0
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            withGccSystemLibrarySources("amd64",
                resolveDirectory = { mergedX86Source(it) },
                symbolicLinkTarget = { if (it == Path.of("/usr/lib64/ld-linux-x86-64.so.2")) Path.of("/unmounted/loader") else null },
                isDirectory = { true },
                isRegularFile = { regularChecks++; true },
            ) { captures++; error("Unselected interpreter targets must not capture manifests") }
        }
        assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
        assertEquals(0, regularChecks); assertEquals(0, captures)
    }

    @Test fun `interpreter link cycles consume a fixed walk bound without capture or retry`() {
        var lookups = 0
        var captures = 0
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            withGccSystemLibrarySources("amd64",
                resolveDirectory = { mergedX86Source(it) },
                symbolicLinkTarget = {
                    check(++lookups <= 128) { "Interpreter traversal must remain bounded" }
                    if (it == Path.of("/usr/lib64/ld-linux-x86-64.so.2")) Path.of("ld-linux-x86-64.so.2") else null
                },
                isDirectory = { true },
                isRegularFile = { error("A cyclic interpreter has no resolved regular file") },
            ) { captures++; error("Cyclic interpreter targets must not capture manifests") }
        }
        assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
        assertTrue(lookups <= 128); assertEquals(0, captures)
    }

    @Test fun `parent components are applied after preceding mounted directory links`() {
        val result = withGccSystemLibrarySources("amd64",
            resolveDirectory = { mergedX86Source(it) },
            symbolicLinkTarget = {
                when (it) {
                    Path.of("/usr/lib64/ld-linux-x86-64.so.2") -> Path.of("../lib/x86_64-linux-gnu/alias/../loader")
                    Path.of("/usr/lib/x86_64-linux-gnu/alias") -> Path.of("deeper/directory")
                    else -> null
                }
            },
            isDirectory = { true },
            isRegularFile = { assertEquals(Path.of("/usr/lib/x86_64-linux-gnu/deeper/loader"), it); true },
        ) { "captured" }
        assertEquals("captured", result)
    }

    @Test fun `oversized interpreter link expansion refuses before walking its target or capturing manifests`() {
        var lookups = 0
        var captures = 0
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            withGccSystemLibrarySources("amd64",
                resolveDirectory = { mergedX86Source(it) },
                symbolicLinkTarget = {
                    lookups++
                    if (it == Path.of("/usr/lib64/ld-linux-x86-64.so.2")) Path.of("part/".repeat(300) + "loader") else null
                },
                isDirectory = { true },
                isRegularFile = { error("Oversized interpreter expansion must not read target metadata") },
            ) { captures++; error("Oversized interpreter expansion must not capture manifests") }
        }
        assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
        assertEquals(2, lookups); assertEquals(0, captures)
    }

    @Test fun `non-directory interpreter components cannot be normalized past before capture`() {
        var regularChecks = 0
        var captures = 0
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            withGccSystemLibrarySources("amd64",
                resolveDirectory = { mergedX86Source(it) },
                symbolicLinkTarget = { if (it == Path.of("/usr/lib64/ld-linux-x86-64.so.2"))
                    Path.of("../lib/x86_64-linux-gnu/not-a-directory/../loader") else null },
                isDirectory = { it != Path.of("/usr/lib/x86_64-linux-gnu/not-a-directory") },
                isRegularFile = { regularChecks++; true },
            ) { captures++; error("Non-directory interpreter components must not capture manifests") }
        }
        assertEquals("GCC system-library interpreter layout is unsupported", failure.message)
        assertEquals(0, regularChecks); assertEquals(0, captures)
    }

    @Test fun `interpreter path metadata failures propagate unchanged without capture or retry`() {
        for (stage in listOf("symbolic-link", "directory")) {
            val original = IOException("synthetic interpreter metadata failure")
            var lookups = 0
            var directoryChecks = 0
            var captures = 0
            val failure = assertFailsWith<IOException> {
                withGccSystemLibrarySources("amd64", resolveDirectory = { mergedX86Source(it) },
                    symbolicLinkTarget = { lookups++; if (stage == "symbolic-link") throw original; null },
                    isDirectory = { directoryChecks++; throw original },
                    isRegularFile = { error("Failed path metadata must not check regular-file state") },
                ) { captures++; error("Failed path metadata must not capture manifests") }
            }
            assertSame(original, failure); assertEquals(1, lookups); assertEquals(0, captures)
            assertEquals(if (stage == "directory") 1 else 0, directoryChecks)
        }
    }

    private fun mergedX86Source(candidate: Path, includeLibAbi: Boolean = true): Path? = when (candidate) {
        Path.of("/lib/x86_64-linux-gnu") -> if (includeLibAbi) Path.of("/usr/lib/x86_64-linux-gnu") else null
        Path.of("/lib64") -> Path.of("/usr/lib64")
        else -> candidate
    }
}
