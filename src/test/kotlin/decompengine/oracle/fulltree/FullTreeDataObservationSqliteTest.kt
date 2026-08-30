package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.sql.DriverManager
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeDataObservationSqliteTest {
    @Test
    fun `frozen shard has tree parity and deterministic SQLite state`() = inTemporaryDirectory { directory ->
        val bytes = fixtureBytes()
        val document = OracleJson.parseCanonical(bytes) as JsonObject
        val input = authenticatedInput()
        FullTreeDataObservations.validateShard(document, scope(), SCOPE_SHA256, inventory(), input)

        val source = directory.resolve("observations.json")
        Files.write(source, bytes)
        val firstDatabase = directory.resolve("first.sqlite")
        val secondDatabase = directory.resolve("second.sqlite")
        val first = ingest(source, firstDatabase)
        val second = ingest(source, secondDatabase)

        assertEquals("b2974c3b5945c9e244cb83b67cf98e06fc4a5c1a8fd84372279ffe10031bb043", first.sourceSha256)
        assertEquals(bytes.size.toLong(), first.sourceBytes)
        assertEquals(1L, first.globals)
        assertEquals(1L, first.types)
        assertEquals(1L, first.fields)
        assertEquals(1L, first.bases)
        assertEquals(1L, first.enumerators)
        assertEquals(7L, first.scannedDies)
        assertEquals("1819bc97783d10fad85c498eefa730d4e7214b8c51de7767d828772d142f7d91", first.stateSha256)
        assertEquals("acb7c00f5351f53be6faee64133a2d123110c64399b62c5e7301f8e48128808d", first.databaseSha256)
        assertEquals(first.stateSha256, second.stateSha256)
        assertEquals(first.databaseSha256, second.databaseSha256)
        assertTrue(Files.mismatch(firstDatabase, secondDatabase) == -1L)
        assertEquals(
            setOf(PosixFilePermission.OWNER_READ),
            Files.getPosixFilePermissions(firstDatabase),
        )

        val stored = readStoredEntities(firstDatabase)
        assertEquals(document.requiredArray("globals").toList(), stored.getValue("global"))
        assertEquals(document.requiredArray("types").toList(), stored.getValue("type"))
    }

    @Test
    fun `authenticated output digest bytes and entity count are required`() = inTemporaryDirectory { directory ->
        val source = directory.resolve("observations.json")
        val bytes = fixtureBytes()
        Files.write(source, bytes)
        val bindings = listOf(
            artifactBinding(source).copy(outputSha256 = "0".repeat(64)),
            artifactBinding(source).copy(outputBytes = bytes.size.toLong() + 1L),
            artifactBinding(source).copy(entities = 3),
        )

        bindings.forEachIndexed { index, binding ->
            val database = directory.resolve("unauthenticated-$index.sqlite")
            assertFailsWith<FullTreeDataTruthException> { ingest(source, database, artifact = binding) }
            assertFalse(Files.exists(database), "unauthenticated output variant $index was published")
        }
    }

    @Test
    fun `malformed duplicate and non UTF-8 JSON fail without publication`() = inTemporaryDirectory { directory ->
        val fixture = fixtureBytes()
        val text = fixture.decodeToString()
        val variants = listOf(
            text.dropLast(2).toByteArray(),
            text.replace(
                "  \"schemaVersion\": 1,",
                "  \"schemaVersion\": 1,\n  \"schemaVersion\": 1,",
            ).toByteArray(),
            text.replaceFirst("{\n", "{ \n").toByteArray(),
            fixture.copyOf().apply { this[indexOfFirst { it == 's'.code.toByte() }] = 0xff.toByte() },
            byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte()) + fixture,
        )

        variants.forEachIndexed { index, bytes ->
            val source = directory.resolve("malformed-$index.json")
            val database = directory.resolve("malformed-$index.sqlite")
            Files.write(source, bytes)
            assertFailsWith<FullTreeDataTruthException> { ingest(source, database) }
            assertFalse(Files.exists(database), "invalid variant $index was published")
        }
    }

    @Test
    fun `input entity token and population bounds fail closed`() = inTemporaryDirectory { directory ->
        val source = directory.resolve("observations.json")
        val fixture = fixtureBytes()
        Files.write(source, fixture)
        val limits = listOf(
            ingestionLimits(maximumInputBytes = fixture.size.toLong() - 1L),
            ingestionLimits(maximumEntityBytes = 256, maximumStringBytes = 128),
            ingestionLimits(maximumTokens = 32),
            ingestionLimits(maximumEntities = 1),
            ingestionLimits(maximumDepth = 2),
        )

        limits.forEachIndexed { index, bound ->
            val database = directory.resolve("bounded-$index.sqlite")
            assertFailsWith<FullTreeDataTruthException> {
                ingest(source, database, bound)
            }
            assertFalse(Files.exists(database), "bounded variant $index was published")
        }

        assertTrue(FullTreeDataObservationIngestionLimits().maximumInputBytes > 64L * 1024L * 1024L)
    }

    @Test
    fun `ordering uniqueness ownership schema and authenticated bindings are enforced`() =
        inTemporaryDirectory { directory ->
            val original = OracleJson.parseCanonical(fixtureBytes()) as JsonObject
            val global = original.requiredArray("globals").single() as JsonObject
            val secondGlobal = JsonObject(global.toMutableMap().apply {
                this["id"] = JsonPrimitive("global-observation-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
            })
            val variants = listOf(
                JsonObject(original.toMutableMap().apply {
                    this["globals"] = JsonArray(listOf(global, global))
                    this["counts"] = countsWith(original, "globals", 2)
                }),
                JsonObject(original.toMutableMap().apply {
                    this["globals"] = JsonArray(listOf(secondGlobal, global))
                    this["counts"] = countsWith(original, "globals", 2)
                }),
                JsonObject(original.toMutableMap().apply {
                    this["globals"] = JsonArray(
                        listOf(JsonObject(global.toMutableMap().apply { this["unitId"] = JsonPrimitive("unit-b") })),
                    )
                }),
                JsonObject(original.toMutableMap().apply {
                    this["shard"] = JsonObject(
                        mapOf("id" to JsonPrimitive("shard-a"), "inputSha256" to JsonPrimitive("9".repeat(64))),
                    )
                }),
                JsonObject(original.toMutableMap().apply {
                    val invalid = JsonObject(global.toMutableMap().apply { this["unexpected"] = JsonPrimitive(true) })
                    this["globals"] = JsonArray(listOf(invalid))
                }),
            )

            variants.forEachIndexed { index, document ->
                val source = directory.resolve("invalid-$index.json")
                val database = directory.resolve("invalid-$index.sqlite")
                Files.write(source, OracleJson.canonicalBytes(document))
                assertFailsWith<FullTreeDataTruthException> { ingest(source, database) }
                assertFalse(Files.exists(database), "invalid semantic variant $index was published")
            }
        }

    private fun ingest(
        source: Path,
        database: Path,
        limits: FullTreeDataObservationIngestionLimits = FullTreeDataObservationIngestionLimits(),
        artifact: FullTreeDataObservationArtifactBinding = artifactBinding(source),
    ): FullTreeDataObservationIngestion = FullTreeDataObservationSqlite.ingest(
        source = source,
        database = database,
        scope = scope(),
        scopeSha256 = SCOPE_SHA256,
        inventory = inventory(),
        shard = authenticatedInput(),
        artifact = artifact,
        limits = limits,
    )

    private fun artifactBinding(source: Path): FullTreeDataObservationArtifactBinding {
        val bytes = Files.readAllBytes(source)
        return FullTreeDataObservationArtifactBinding(
            outputSha256 = OracleArtifacts.sha256(bytes),
            outputBytes = bytes.size.toLong(),
            entities = 2,
        )
    }

    private fun readStoredEntities(database: Path): Map<String, List<JsonObject>> {
        val result = linkedMapOf<String, MutableList<JsonObject>>(
            "global" to mutableListOf(),
            "type" to mutableListOf(),
        )
        DriverManager.getConnection("jdbc:sqlite:file:${database.toAbsolutePath()}?mode=ro").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery(
                    "SELECT kind, canonical_json FROM observations ORDER BY kind, id",
                ).use { rows ->
                    while (rows.next()) {
                        result.getValue(rows.getString(1)) += OracleJson.parseCanonical(rows.getBytes(2)) as JsonObject
                    }
                }
            }
        }
        return result
    }

    private fun countsWith(document: JsonObject, field: String, value: Long): JsonObject =
        JsonObject(document.requiredObject("counts").toMutableMap().apply { this[field] = JsonPrimitive(value) })

    private fun ingestionLimits(
        maximumInputBytes: Long = 8 * 1024L,
        maximumEntityBytes: Int = 4 * 1024,
        maximumStringBytes: Int = 1024,
        maximumTokens: Long = 10_000,
        maximumEntities: Long = 100,
        maximumDepth: Int = 32,
    ): FullTreeDataObservationIngestionLimits = FullTreeDataObservationIngestionLimits(
        maximumInputBytes = maximumInputBytes,
        maximumDatabaseBytes = 1024 * 1024,
        maximumEntities = maximumEntities,
        maximumTokens = maximumTokens,
        maximumEntityBytes = maximumEntityBytes,
        maximumEntityNodes = 10_000,
        maximumDepth = maximumDepth,
        maximumStringBytes = maximumStringBytes,
        maximumTotalStringBytes = minOf(maximumInputBytes, 4 * 1024L),
        maximumNumberCharacters = 64,
    )

    private fun authenticatedInput(): FullTreeDataObservationShardInput =
        FullTreeDataObservations.shardInputs(inventory(), SCOPE_SHA256, RICH_SHA256).single()

    private fun fixtureBytes(): ByteArray = requireNotNull(
        javaClass.getResourceAsStream("/oracle/full-tree-data-observations-shard.json"),
    ).use { it.readAllBytes() }

    private fun inventory(): JsonObject = JsonObject(
        mapOf(
            "indexSha256" to JsonPrimitive("1".repeat(64)),
            "units" to JsonArray(
                listOf(
                    JsonObject(
                        mapOf(
                            "id" to JsonPrimitive("unit-a"),
                            "dwarfOffset" to JsonPrimitive("0x10"),
                        ),
                    ),
                ),
            ),
            "shards" to JsonArray(
                listOf(
                    JsonObject(
                        mapOf(
                            "id" to JsonPrimitive("shard-a"),
                            "unitIds" to JsonArray(listOf(JsonPrimitive("unit-a"))),
                        ),
                    ),
                ),
            ),
        ),
    )

    private fun scope(): JsonObject = JsonObject(
        mapOf("oracle" to JsonObject(mapOf("richArtifactSha256" to JsonPrimitive(RICH_SHA256)))),
    )

    private fun <T> inTemporaryDirectory(action: (Path) -> T): T {
        val directory = createTempDirectory("data-observation-sqlite-").toAbsolutePath().normalize()
        return try {
            action(directory)
        } finally {
            directory.toFile().deleteRecursively()
        }
    }

    private companion object {
        const val SCOPE_SHA256 = "2222222222222222222222222222222222222222222222222222222222222222"
        const val RICH_SHA256 = "3333333333333333333333333333333333333333333333333333333333333333"
    }
}
