package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Base64
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeElfFunctionsSqliteTest {
    @Test
    fun `producer matches frozen v1 differential bytes and is worker deterministic`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createElfFunctionFixture(directory.resolve("authenticated ?#% inputs"))
            val expected = frozenIndexBytes()
            val outputs = listOf(1, 2, 4).map { workers ->
                val path = directory.resolve("functions-$workers.json")
                val binding = generate(fixture, path, workers)
                val bytes = Files.readAllBytes(path)
                assertTrue(expected.contentEquals(bytes))
                assertEquals(FROZEN_INDEX_SHA256, binding.sha256)
                assertEquals(expected.size.toLong(), binding.bytes)
                assertEquals(FROZEN_CONFIGURATION_SHA256, binding.configurationSha256)
                assertEquals(FROZEN_SCOPE_SHA256, binding.scopeSha256)
                assertEquals(FROZEN_INPUT_SHA256, binding.richInputSha256)
                assertEquals(FROZEN_INPUT_SHA256, binding.strippedInputSha256)
                assertEquals(FullTreeElfFunctionCounts(5, 4, 5, 5), binding.counts)
                assertEquals("0x0", binding.imageBase)
                assertEquals("ET_DYN", binding.elfType)
                val document = OracleJson.parseCanonical(bytes, controlJsonLimits(1024 * 1024))
                OracleSchemas.validate("full-tree-elf-functions", document)
                val validated = FullTreeElfFunctionsSqlite.loadAndValidate(
                    path,
                    fixture.rich,
                    fixture.stripped,
                    fixture.scope,
                    fixture.inventory,
                    maximumWorkers = workers,
                )
                assertEquals(binding.sha256, validated.sha256)
                binding
            }
            assertTrue(outputs.all { it.sha256 == outputs.first().sha256 && it.counts == outputs.first().counts })
            assertNoElfFunctionScratch(directory)
        }

    @Test
    fun `validator rejects malformed duplicate noncanonical and substituted index bytes without residue`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createElfFunctionFixture(directory.resolve("validator inputs"))
            val canonicalPath = directory.resolve("canonical.json")
            generate(fixture, canonicalPath, workers = 1)
            val canonical = Files.readAllBytes(canonicalPath)
            val duplicate = canonical.decodeToString()
                .replaceFirst("{\n", "{\n  \"schemaVersion\": 1,\n")
                .toByteArray(StandardCharsets.UTF_8)
            val noncanonical = canonical + '\n'.code.toByte()
            val fixtureScopeSha256 = fixture.scope.sha256
            val staleBinding = canonical.decodeToString()
                .replaceFirst(fixtureScopeSha256, "f".repeat(64))
                .toByteArray(StandardCharsets.UTF_8)
            assertFalse(canonical.contentEquals(staleBinding))
            val malformedUtf8 = canonical.copyOf().also { bytes ->
                val name = "_init".toByteArray(StandardCharsets.US_ASCII)
                val offset = bytes.indexOfSubsequence(name)
                check(offset >= 0)
                bytes[offset] = 0xff.toByte()
            }
            listOf(duplicate, noncanonical, staleBinding, malformedUtf8).forEachIndexed { index, mutation ->
                val path = writeElf(directory.resolve("mutation-$index.json"), mutation)
                assertFailsWith<FullTreeElfFunctionException> {
                    FullTreeElfFunctionsSqlite.loadAndValidate(
                        path,
                        fixture.rich,
                        fixture.stripped,
                        fixture.scope,
                        fixture.inventory,
                        maximumWorkers = 1,
                    )
                }
                assertNoElfFunctionScratch(directory)
            }
        }

    @Test
    fun `artifact digest mode and path substitutions fail closed`() =
        inControlTemporaryDirectory { directory ->
            val changed = createElfFunctionFixture(directory.resolve("changed"))
            Files.write(changed.rich, Files.readAllBytes(changed.rich) + 0.toByte())
            assertGenerationRejected(changed, directory.resolve("changed-output.json"))

            val writable = createElfFunctionFixture(directory.resolve("writable"))
            Files.setPosixFilePermissions(writable.rich, PosixFilePermissions.fromString("rw-rw-r--"))
            assertGenerationRejected(writable, directory.resolve("writable-output.json"))

            val linked = createElfFunctionFixture(directory.resolve("linked"))
            Files.delete(linked.stripped)
            Files.createSymbolicLink(linked.stripped, linked.rich.fileName)
            assertGenerationRejected(linked, directory.resolve("linked-output.json"))

            val twinRich = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("defined", 0x100UL)),
            )
            val twinStripped = twinRich.copyOf().also { bytes ->
                FullTreeElfTestBytes.put16(bytes, 18, 183, littleEndian = true)
            }
            val headerMismatch = createElfFunctionFixture(
                directory.resolve("header-mismatch"),
                twinRich,
                twinStripped,
            )
            assertGenerationRejected(headerMismatch, directory.resolve("header-mismatch-output.json"))
            assertNoElfFunctionScratch(directory)
        }

    @Test
    fun `resident model is coupled to configured parser cardinalities`() {
        assertFailsWith<IllegalArgumentException> {
            FullTreeElfFunctionLimits(modeledResidentBytes = 96L * 1024L * 1024L)
        }
        assertFailsWith<IllegalArgumentException> {
            FullTreeElfFunctionLimits(
                layout = FullTreeElfLayoutLimits(
                    maximumProgramHeaders = 1_000_000,
                    maximumSectionHeaders = 1_000_000,
                    maximumSymbolTables = 1_000_000,
                    maximumTotalSectionNameBytes = 256L * 1024L * 1024L,
                ),
                modeledResidentBytes = 1024L * 1024L * 1024L,
            )
        }
        val defaults = FullTreeElfFunctionLimits()
        assertEquals(128L * 1024L * 1024L, defaults.modeledResidentBytes)
        assertTrue(
            defaults.modeledResidentBytes >=
                defaults.layout.modeledResidentBytes() + 32L * 1024L * 1024L,
        )
    }

    @Test
    fun `SQLite ordering is scalar-code-point canonical and alias ownership is bounded`() =
        inControlTemporaryDirectory { directory ->
            val bmp = "\ue000"
            val supplementary = "\ud800\udc00"
            val bytes = FullTreeElfTestBytes.build(
                TestElfVariant(true, true, extendedNumbering = true, shndx = true),
                listOf(
                    TestElfSymbol(supplementary, 0x100UL),
                    TestElfSymbol(bmp, 0x100UL),
                    TestElfSymbol("external", null),
                ),
            )
            val fixture = createElfFunctionFixture(directory.resolve("unicode"), bytes, bytes)
            val output = directory.resolve("unicode-index.json")
            generate(fixture, output, workers = 3)
            val text = Files.readString(output)
            assertTrue(text.indexOf("\"name\": \"$bmp\"") < text.indexOf("\"name\": \"$supplementary\""))

            assertFailsWith<FullTreeElfFunctionException> {
                FullTreeElfFunctionsSqlite.generateAndPublish(
                    fixture.rich,
                    fixture.stripped,
                    fixture.scope,
                    fixture.inventory,
                    directory.resolve("alias-bound.json"),
                    maximumWorkers = 1,
                    limits = FullTreeElfFunctionLimits(maximumAliasesPerRva = 1),
                )
            }

            val rich = FullTreeElfTestBytes.build(
                TestElfVariant(false, false, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("alpha", 0x100UL)),
            )
            val stripped = FullTreeElfTestBytes.build(
                TestElfVariant(false, false, extendedNumbering = false, shndx = false),
                listOf(TestElfSymbol("betaa", 0x100UL)),
            )
            val rebound = createElfFunctionFixture(directory.resolve("rebound"), rich, stripped)
            assertGenerationRejected(rebound, directory.resolve("rebound-output.json"))
            assertNoElfFunctionScratch(directory)
        }

    @Test
    fun `resource limits workers and existing targets reject without replacement`() =
        inControlTemporaryDirectory { directory ->
            val outputBound = createElfFunctionFixture(directory.resolve("output-bound"))
            assertFailsWith<FullTreeElfFunctionException> {
                FullTreeElfFunctionsSqlite.generateAndPublish(
                    outputBound.rich,
                    outputBound.stripped,
                    outputBound.scope,
                    outputBound.inventory,
                    directory.resolve("output-bound.json"),
                    maximumWorkers = 1,
                    limits = FullTreeElfFunctionLimits(maximumOutputBytes = 256),
                )
            }

            val databaseBound = createElfFunctionFixture(directory.resolve("database-bound"))
            assertFailsWith<FullTreeElfFunctionException> {
                FullTreeElfFunctionsSqlite.generateAndPublish(
                    databaseBound.rich,
                    databaseBound.stripped,
                    databaseBound.scope,
                    databaseBound.inventory,
                    directory.resolve("database-bound.json"),
                    maximumWorkers = 1,
                    limits = FullTreeElfFunctionLimits(maximumDatabaseBytes = 1),
                )
            }

            val workers = createElfFunctionFixture(directory.resolve("workers"))
            listOf(0, 33).forEach { workerCount ->
                assertFailsWith<FullTreeElfFunctionException> {
                    generate(workers, directory.resolve("workers-$workerCount.json"), workerCount)
                }
            }

            val target = directory.resolve("existing.json")
            val sentinel = "existing artifact".toByteArray(StandardCharsets.US_ASCII)
            writeElf(target, sentinel)
            assertGenerationRejected(workers, target)
            assertTrue(sentinel.contentEquals(Files.readAllBytes(target)))
            assertNoElfFunctionScratch(directory)
        }

    @Test
    fun `post-write input mutation and post-move interruption revoke publication`() =
        inControlTemporaryDirectory { directory ->
            val mutated = createElfFunctionFixture(directory.resolve("mutated"))
            val mutationTarget = directory.resolve("mutation-output.json")
            var changed = false
            val mutationRuntime = FullTreeElfRuntime { label ->
                if (!changed && label == "after writing ELF function index") {
                    changed = true
                    Files.write(mutated.rich, Files.readAllBytes(mutated.rich) + 0.toByte())
                }
                FullTreeElfRuntimeSample(0, 0)
            }
            assertFailsWith<FullTreeElfFunctionException> {
                FullTreeElfFunctionsSqlite.generateAndPublishInternal(
                    mutated.rich,
                    mutated.stripped,
                    mutated.scope,
                    mutated.inventory,
                    mutationTarget,
                    maximumWorkers = 1,
                    limits = FullTreeElfFunctionLimits(),
                    runtime = mutationRuntime,
                )
            }
            assertTrue(changed)
            assertFalse(Files.exists(mutationTarget, LinkOption.NOFOLLOW_LINKS))
            assertNoElfFunctionScratch(directory)

            val interrupted = createElfFunctionFixture(directory.resolve("interrupted"))
            val interruptionTarget = directory.resolve("interruption-output.json")
            val interruptingRuntime = FullTreeElfRuntime { label ->
                if (label == "after verifying atomic ELF function publication") {
                    throw IllegalStateException("deterministic post-move interruption")
                }
                FullTreeElfRuntimeSample(0, 0)
            }
            assertFailsWith<FullTreeElfFunctionException> {
                FullTreeElfFunctionsSqlite.generateAndPublishInternal(
                    interrupted.rich,
                    interrupted.stripped,
                    interrupted.scope,
                    interrupted.inventory,
                    interruptionTarget,
                    maximumWorkers = 1,
                    limits = FullTreeElfFunctionLimits(),
                    runtime = interruptingRuntime,
                )
            }
            assertFalse(Files.exists(interruptionTarget, LinkOption.NOFOLLOW_LINKS))
            assertNoElfFunctionScratch(directory)
        }

    private fun generate(fixture: ElfFunctionFixture, output: Path, workers: Int) =
        FullTreeElfFunctionsSqlite.generateAndPublish(
            fixture.rich,
            fixture.stripped,
            fixture.scope,
            fixture.inventory,
            output,
            maximumWorkers = workers,
        )

    private fun assertGenerationRejected(fixture: ElfFunctionFixture, output: Path) {
        assertFailsWith<FullTreeElfFunctionException> { generate(fixture, output, workers = 1) }
    }
}

private data class ElfFunctionFixture(
    val rich: Path,
    val stripped: Path,
    val scope: AuthenticatedFullTreeScope,
    val inventory: JsonObject,
)

private fun createElfFunctionFixture(
    root: Path,
    richBytes: ByteArray = Base64.getMimeDecoder().decode(fullTreeControlResource("rich.elf.b64")),
    strippedBytes: ByteArray = richBytes,
): ElfFunctionFixture {
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    val control = createFullTreeControlFixture(root.resolve("control"))
    val original = control.authenticatedScope()
    val rich = writeElf(root.resolve("rich-input.elf"), richBytes)
    val stripped = writeElf(root.resolve("stripped-input.elf"), strippedBytes)
    val originalArtifacts = original.artifactManifest.controlObject("artifacts")
    val originalFull = originalArtifacts.controlObject("full")
    fun reboundArtifact(path: String, bytes: ByteArray): JsonObject = JsonObject(
        originalFull.toMutableMap().apply {
            this["bytes"] = JsonPrimitive(bytes.size)
            this["path"] = JsonPrimitive(path)
            this["sha256"] = JsonPrimitive(OracleArtifacts.sha256(bytes))
        },
    )
    val manifest = JsonObject(
        original.artifactManifest.toMutableMap().apply {
            this["artifacts"] = JsonObject(
                mapOf(
                    "full" to reboundArtifact(originalFull.controlString("path"), richBytes),
                    "stripped" to reboundArtifact(
                        originalArtifacts.controlObject("stripped").controlString("path"),
                        strippedBytes,
                    ),
                ),
            )
        },
    )
    val manifestSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
    val scopeDocument = JsonObject(
        original.document.toMutableMap().apply {
            this["oracle"] = JsonObject(
                original.document.controlObject("oracle").toMutableMap().apply {
                    this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
                    this["richArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(richBytes))
                    this["strippedArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(strippedBytes))
                },
            )
        },
    )
    val scopeSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(scopeDocument))
    val scope = AuthenticatedFullTreeScope(
        document = scopeDocument,
        sha256 = scopeSha256,
        sourceLock = original.sourceLock,
        sourceLockSha256 = original.sourceLockSha256,
        artifactManifest = manifest,
        artifactManifestSha256 = manifestSha256,
    )
    val originalInventory = parseControlObject(control.inventory)
    val inventory = JsonObject(
        originalInventory.toMutableMap().apply {
            this["oracle"] = JsonObject(
                originalInventory.controlObject("oracle").toMutableMap().apply {
                    this["artifactManifestSha256"] = JsonPrimitive(manifestSha256)
                    this["richArtifactSha256"] = JsonPrimitive(OracleArtifacts.sha256(richBytes))
                    this["scopeSha256"] = JsonPrimitive(scopeSha256)
                },
            )
        },
    )
    FullTreeScopeControl.validate(scope)
    FullTreeInventoryControl.validate(inventory, scope)
    return ElfFunctionFixture(rich, stripped, scope, inventory)
}

private fun frozenIndexBytes(): ByteArray = Base64.getMimeDecoder().decode(
    checkNotNull(
        FullTreeElfFunctionsSqliteTest::class.java.getResourceAsStream(
            "/oracle/full-tree-elf-functions-v1/expected-index.json.b64",
        ),
    ) { "frozen full-tree ELF function fixture is unavailable" }.use { it.readAllBytes() },
)

private fun ByteArray.indexOfSubsequence(needle: ByteArray): Int {
    if (needle.isEmpty()) return 0
    for (offset in 0..size - needle.size) {
        var matches = true
        for (index in needle.indices) {
            if (this[offset + index] != needle[index]) {
                matches = false
                break
            }
        }
        if (matches) return offset
    }
    return -1
}

private fun assertNoElfFunctionScratch(root: Path) {
    val remnants = Files.walk(root).use { paths ->
        paths.filter { path -> path.fileName.toString().contains(".elf-functions-scratch-") }.toList()
    }
    assertEquals(emptyList(), remnants)
}

private const val FROZEN_CONFIGURATION_SHA256 =
    "5305350fd10d902979a5a1bc109dd424d8f7c274e22bd5e4bd47bc18ae639f2f"
private const val FROZEN_SCOPE_SHA256 = "725fbbc9d4f4dbef39f094bfcd751259d4313d22597c4863047e356e91d80578"
private const val FROZEN_INPUT_SHA256 = "28105cb58b619f88d8718e8cf30c0c3471b7f0c8825e95e171eebc940954b859"
private const val FROZEN_INDEX_SHA256 = "491e49951e780408962330764944b60b60616d78ad516c9e65d4b0d44b19b492"
