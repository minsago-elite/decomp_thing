package decompengine.oracle.fulltree

import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeFunctionObservationSqliteTest {
    @Test
    fun `SQLite projection is byte identical for merged emitted observations and unsigned RVAs`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val observations = listOf(
                observation(
                    fixture.first,
                    dieOffset = 0x20UL,
                    rva = 0x40UL,
                    aliases = listOf(
                        alias("\ud800\udc00", "astral", fixture.first.id),
                        alias("alpha", "first-alpha", fixture.first.id),
                    ),
                ),
                observation(
                    fixture.second,
                    dieOffset = 0x30UL,
                    rva = 0x40UL,
                    aliases = listOf(
                        alias("\ue000", "bmp", fixture.second.id),
                        alias("alpha", "second-alpha", fixture.second.id),
                    ),
                ),
                observation(
                    fixture.first,
                    dieOffset = ULong.MAX_VALUE,
                    rva = ULong.MAX_VALUE,
                    aliases = listOf(alias("omega", "maximum-rva", fixture.first.id)),
                ),
            )

            val projected = compareProjection(root, fixture, observations, scannedDies = 5)

            assertEquals(2L, projected.emitted)
            assertEquals(0L, projected.nonEmitted)
            assertEquals(0L, projected.nonEmittedDies)
            assertEquals(2L, projected.entities)
            assertEquals(5L, projected.scannedDies)
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite projection is byte identical for coalesced non-emitted observations`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val observations = listOf(
                observation(
                    fixture.second,
                    dieOffset = ULong.MAX_VALUE,
                    aliases = listOf(alias("inline-alpha", "second-inline", fixture.second.id)),
                    inline = true,
                ),
                observation(
                    fixture.first,
                    dieOffset = 0UL,
                    aliases = listOf(alias("inline-alpha", "first-inline", fixture.first.id)),
                ),
                observation(
                    fixture.first,
                    dieOffset = 0x70UL,
                    aliases = listOf(alias("separate", "separate-definition", fixture.first.id)),
                ),
            )

            val projected = compareProjection(root, fixture, observations, scannedDies = 5)

            assertEquals(0L, projected.emitted)
            assertEquals(2L, projected.nonEmitted)
            assertEquals(3L, projected.nonEmittedDies)
            assertEquals(2L, projected.entities)
            assertEquals(5L, projected.scannedDies)
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite sink enforces scanned DIE bounds incrementally and revokes scratch`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val limits = sqliteLimits(
                FullTreeFunctionObservationAccumulatorLimits(
                    maximumScannedDies = 2,
                    maximumSubprograms = 2,
                ),
            )
            FullTreeFunctionObservationSqlite.open(root, fixture.shard, limits).use { sink ->
                sink.recordScannedDies(2)
                val failure = assertFailsWith<FullTreeFunctionObservationSqliteException> {
                    sink.recordScannedDies(1)
                }
                assertTrue(failure.message.orEmpty().contains("DIE bound"), failure.message)
            }
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite projection preserves producer-valid identities larger than default JSON limits`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val astral = "\ud800\udc00".repeat(16_000)
            val aliases = (0 until 40).map { index ->
                alias("alias-$index-$astral", "large-identity-$index", fixture.first.id)
            }
            val observation = observation(
                fixture.first,
                dieOffset = 0x90UL,
                aliases = aliases,
            )
            val accumulator = FullTreeFunctionObservationAccumulator(fixture.shard)
            accumulator.recordScannedDies(3)
            accumulator.accept(observation)
            val expected = FullTreeFunctionObservations.canonicalEnvelopeBytes(
                accumulator.finish(
                    inventoryIndexSha256 = BINDINGS.inventoryIndexSha256,
                    richArtifactSha256 = BINDINGS.richArtifactSha256,
                    scopeSha256 = BINDINGS.scopeSha256,
                ),
            )
            assertTrue(expected.size > 2 * 1024 * 1024)

            val output = ByteArrayOutputStream()
            val result = FullTreeFunctionObservationSqlite.open(
                root,
                fixture.shard,
                sqliteLimits(
                    maximumDatabaseBytes = 64L * 1024L * 1024L,
                    maximumOutputBytes = 8L * 1024L * 1024L,
                ),
            ).use { sink ->
                sink.recordScannedDies(3)
                sink.accept(observation)
                sink.finishTo(output, BINDINGS)
            }
            assertContentEquals(expected, output.toByteArray())
            assertEquals(expected.size.toLong(), result.outputBytes)
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite entity counters accept the exact bound and reject the next distinct child`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val limits = sqliteLimits(
                FullTreeFunctionObservationAccumulatorLimits(maximumAliasesPerEntity = 1),
            )
            FullTreeFunctionObservationSqlite.open(root, fixture.shard, limits).use { sink ->
                sink.recordScannedDies(4)
                sink.accept(
                    observation(
                        fixture.first,
                        dieOffset = 0x10UL,
                        rva = 0x40UL,
                        aliases = listOf(alias("first", "first", fixture.first.id)),
                    ),
                )
                val failure = assertFailsWith<FullTreeFunctionObservationSqliteException> {
                    sink.accept(
                        observation(
                            fixture.second,
                            dieOffset = 0x20UL,
                            rva = 0x40UL,
                            aliases = listOf(alias("second", "second", fixture.second.id)),
                        ),
                    )
                }
                assertTrue(failure.message.orEmpty().contains("alias population"), failure.message)
            }
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite sink checkpoints bounded canonicalization within an observation`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val checkpoints = mutableListOf<String>()
            val output = ByteArrayOutputStream()
            FullTreeFunctionObservationSqlite.open(
                root,
                fixture.shard,
                sqliteLimits(
                    checkpoint = FullTreeFunctionObservationSqliteCheckpoint { checkpoints += it },
                ),
            ).use { sink ->
                sink.recordScannedDies(3)
                sink.accept(
                    observation(
                        fixture.first,
                        dieOffset = 0x50UL,
                        aliases = listOf(alias("checkpointed", "checkpointed", fixture.first.id)),
                    ),
                )
                sink.finishTo(output, BINDINGS)
            }
            assertTrue("before accepting a function observation" in checkpoints)
            assertTrue("while authenticating function alias evidence" in checkpoints)
            assertTrue("before canonicalizing a non-emitted observation identity" in checkpoints)
            assertTrue("after canonicalizing a non-emitted observation identity" in checkpoints)
            assertTrue("after accepting a function observation" in checkpoints)
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite sink rejects aggregate evidence beyond the per-subprogram bound`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val limits = sqliteLimits(
                FullTreeFunctionObservationAccumulatorLimits(maximumEvidencePerSubprogram = 1),
            )
            FullTreeFunctionObservationSqlite.open(root, fixture.shard, limits).use { sink ->
                sink.recordScannedDies(3)
                val failure = assertFailsWith<FullTreeFunctionObservationSqliteException> {
                    sink.accept(
                        observation(
                            fixture.first,
                            dieOffset = 0x60UL,
                            aliases = listOf(alias("bounded", "duplicate-evidence", fixture.first.id)),
                        ),
                    )
                }
                assertTrue(failure.message.orEmpty().contains("aggregate evidence"), failure.message)
            }
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite scratch directory and database are private from creation through revocation`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            FullTreeFunctionObservationSqlite.open(root, fixture.shard, sqliteLimits()).use {
                val scratch = Files.list(root).use { paths -> paths.toList().single() }
                val database = Files.list(scratch).use { paths -> paths.toList().single() }
                assertEquals(
                    PosixFilePermissions.fromString("rwx------"),
                    Files.getPosixFilePermissions(scratch, LinkOption.NOFOLLOW_LINKS),
                )
                assertEquals(
                    PosixFilePermissions.fromString("rw-------"),
                    Files.getPosixFilePermissions(database, LinkOption.NOFOLLOW_LINKS),
                )
            }
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite checkpoint callbacks cannot reenter a mutating sink`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            lateinit var sink: FullTreeFunctionObservationSink
            var armed = false
            var reentryFailure: Throwable? = null
            val checkpoint = FullTreeFunctionObservationSqliteCheckpoint { label ->
                if (armed && reentryFailure == null && label == "while authenticating function aliases") {
                    reentryFailure = runCatching { sink.recordScannedDies(1) }.exceptionOrNull()
                }
            }
            sink = FullTreeFunctionObservationSqlite.open(
                root,
                fixture.shard,
                sqliteLimits(checkpoint = checkpoint),
            )
            sink.use {
                it.recordScannedDies(3)
                armed = true
                it.accept(
                    observation(
                        fixture.first,
                        dieOffset = 0x80UL,
                        aliases = listOf(alias("reentrant", "reentrant", fixture.first.id)),
                    ),
                )
                it.finishTo(ByteArrayOutputStream(), BINDINGS)
            }
            assertTrue(reentryFailure is FullTreeFunctionObservationSqliteException)
            assertTrue(reentryFailure?.message.orEmpty().contains("not open"), reentryFailure?.message)
            assertNoSqliteScratch(root)
        }

    @Test
    fun `SQLite projection checkpoints every MiB inside one large canonical line`() =
        inControlTemporaryDirectory { root ->
            val fixture = fixture()
            val checkpoints = mutableListOf<String>()
            val largeDeclaration = JsonObject(
                declaration(fixture.first.sourcePath).toMutableMap().apply {
                    this["sourcePath"] = JsonPrimitive("x".repeat(3 * 1024 * 1024))
                },
            )
            val largeObservation = observation(
                fixture.first,
                dieOffset = 0xa0UL,
                aliases = listOf(alias("large-line", "large-line", fixture.first.id)),
            ).copy(declaration = largeDeclaration)
            FullTreeFunctionObservationSqlite.open(
                root,
                fixture.shard,
                sqliteLimits(
                    maximumDatabaseBytes = 64L * 1024L * 1024L,
                    maximumOutputBytes = 8L * 1024L * 1024L,
                    checkpoint = FullTreeFunctionObservationSqliteCheckpoint { checkpoints += it },
                ),
            ).use { sink ->
                sink.recordScannedDies(3)
                sink.accept(largeObservation)
                sink.finishTo(ByteArrayOutputStream(), BINDINGS)
            }
            assertTrue(
                checkpoints.count { it == "while projecting function-observation output" } >= 3,
                checkpoints.toString(),
            )
            assertNoSqliteScratch(root)
        }

    private fun compareProjection(
        root: java.nio.file.Path,
        fixture: Fixture,
        observations: List<FullTreeObservedSubprogram>,
        scannedDies: Long,
    ): FullTreeFunctionObservationStreamResult {
        val expectedAccumulator = FullTreeFunctionObservationAccumulator(fixture.shard)
        expectedAccumulator.recordScannedDies(scannedDies)
        observations.forEach(expectedAccumulator::accept)
        val expected = FullTreeFunctionObservations.canonicalEnvelopeBytes(
            expectedAccumulator.finish(
                inventoryIndexSha256 = BINDINGS.inventoryIndexSha256,
                richArtifactSha256 = BINDINGS.richArtifactSha256,
                scopeSha256 = BINDINGS.scopeSha256,
            ),
        )

        val output = ByteArrayOutputStream()
        val result = FullTreeFunctionObservationSqlite.open(root, fixture.shard, sqliteLimits()).use { sink ->
            sink.recordScannedDies(scannedDies)
            observations.forEach(sink::accept)
            sink.finishTo(output, BINDINGS)
        }
        assertContentEquals(expected, output.toByteArray())
        assertEquals(expected.size.toLong(), result.outputBytes)
        assertEquals(decompengine.oracle.core.OracleArtifacts.sha256(expected), result.outputSha256)
        return result
    }

    private fun fixture(): Fixture {
        val first = UnitFixture("cu-first", "source/!.cpp")
        val second = UnitFixture("cu-second", "source/z.cpp")
        val shard = FullTreeFunctionObservationShardInput(
            identifier = "sqlite-shard",
            inputSha256 = "a".repeat(64),
            units = listOf(first, second).map { unit ->
                JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(unit.id),
                        "sourcePath" to JsonPrimitive(unit.sourcePath),
                    ),
                )
            },
        )
        return Fixture(shard, first, second)
    }

    private fun observation(
        unit: UnitFixture,
        dieOffset: ULong,
        rva: ULong? = null,
        aliases: List<FullTreeObservedFunctionAlias>,
        inline: Boolean = false,
    ): FullTreeObservedSubprogram = FullTreeObservedSubprogram(
        unitId = unit.id,
        dieOffset = dieOffset,
        rvas = rva?.let(::listOf) ?: emptyList(),
        aliases = aliases,
        declaration = declaration(unit.sourcePath),
        inlineWithoutEmittedRange = inline,
    )

    private fun alias(name: String, locator: String, unitId: String) = FullTreeObservedFunctionAlias(
        name = name,
        evidence = listOf(
            FullTreeObservedFunctionEvidence(locator, unitId),
            FullTreeObservedFunctionEvidence(locator, unitId),
        ),
    )

    private fun declaration(unitSourcePath: String): JsonObject = JsonObject(
        mapOf(
            "column" to JsonPrimitive(3),
            "externalPathSha256" to JsonNull,
            "fileIndex" to JsonPrimitive(1),
            "line" to JsonPrimitive(2),
            "sourcePath" to JsonPrimitive("source/include/header.h"),
            "unitSourcePath" to JsonPrimitive(unitSourcePath),
        ),
    )

    private fun sqliteLimits(
        observations: FullTreeFunctionObservationAccumulatorLimits =
            FullTreeFunctionObservationAccumulatorLimits(),
        maximumDatabaseBytes: Long = 4L * 1024L * 1024L,
        maximumOutputBytes: Long = 1024L * 1024L,
        checkpoint: FullTreeFunctionObservationSqliteCheckpoint =
            FullTreeFunctionObservationSqliteCheckpoint {},
    ) = FullTreeFunctionObservationSqliteLimits(
        observations = observations,
        maximumDatabaseBytes = maximumDatabaseBytes,
        maximumOutputBytes = maximumOutputBytes,
        maximumCacheBytes = 64 * 1024,
        databaseCheckpointRows = 2,
        checkpoint = checkpoint,
    )

    private fun assertNoSqliteScratch(root: java.nio.file.Path) {
        val residue = Files.list(root).use { paths ->
            paths.anyMatch { it.fileName.toString().startsWith(".function-observation-sqlite-") }
        }
        assertTrue(!residue, "function-observation SQLite scratch was not revoked")
    }

    private data class Fixture(
        val shard: FullTreeFunctionObservationShardInput,
        val first: UnitFixture,
        val second: UnitFixture,
    )

    private data class UnitFixture(val id: String, val sourcePath: String)

    private companion object {
        val BINDINGS = FullTreeFunctionObservationBindings(
            inventoryIndexSha256 = "b".repeat(64),
            richArtifactSha256 = "c".repeat(64),
            scopeSha256 = "d".repeat(64),
        )
    }
}
