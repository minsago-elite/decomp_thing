package decompengine.oracle.fulltree

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.io.FilterInputStream
import java.io.InputStream
import java.io.PushbackInputStream
import java.math.BigInteger
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.FileChannel
import java.nio.charset.StandardCharsets
import java.nio.file.AtomicMoveNotSupportedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFileAttributeView
import java.nio.file.attribute.PosixFilePermission
import java.security.DigestInputStream
import java.security.MessageDigest
import java.sql.Connection
import java.sql.DriverManager
import java.sql.PreparedStatement
import java.util.EnumSet
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Independent limits for production shards that are intentionally larger than an in-memory tree. */
data class FullTreeDataObservationIngestionLimits(
    val maximumInputBytes: Long = 1024L * 1024L * 1024L,
    val maximumDatabaseBytes: Long = 2L * 1024L * 1024L * 1024L,
    val maximumEntities: Long = 5_000_000L,
    val maximumTokens: Long = 100_000_000L,
    val maximumEntityBytes: Int = 16 * 1024 * 1024,
    val maximumEntityNodes: Int = 1_000_000,
    val maximumDepth: Int = 128,
    val maximumStringBytes: Int = 1024 * 1024,
    val maximumTotalStringBytes: Long = 768L * 1024L * 1024L,
    val maximumNumberCharacters: Int = 256,
) {
    init {
        require(maximumInputBytes in 1L..HARD_MAXIMUM_INPUT_BYTES) {
            "maximumInputBytes is outside the supported range"
        }
        require(maximumDatabaseBytes in 1L..HARD_MAXIMUM_DATABASE_BYTES) {
            "maximumDatabaseBytes is outside the supported range"
        }
        require(maximumEntities in 1L..HARD_MAXIMUM_ENTITIES) {
            "maximumEntities is outside the supported range"
        }
        require(maximumTokens in 1L..HARD_MAXIMUM_TOKENS) {
            "maximumTokens is outside the supported range"
        }
        require(maximumEntityBytes in 1..HARD_MAXIMUM_ENTITY_BYTES) {
            "maximumEntityBytes is outside the supported range"
        }
        require(maximumEntityNodes in 1..HARD_MAXIMUM_ENTITY_NODES) {
            "maximumEntityNodes is outside the supported range"
        }
        require(maximumDepth in 1..HARD_MAXIMUM_DEPTH) {
            "maximumDepth is outside the supported range"
        }
        require(maximumStringBytes in 1..maximumEntityBytes) {
            "maximumStringBytes is outside the supported range"
        }
        require(maximumTotalStringBytes in 1L..maximumInputBytes) {
            "maximumTotalStringBytes is outside the supported range"
        }
        require(maximumNumberCharacters in 1..HARD_MAXIMUM_NUMBER_CHARACTERS) {
            "maximumNumberCharacters is outside the supported range"
        }
    }

    private companion object {
        const val HARD_MAXIMUM_INPUT_BYTES = 16L * 1024L * 1024L * 1024L
        const val HARD_MAXIMUM_DATABASE_BYTES = 32L * 1024L * 1024L * 1024L
        const val HARD_MAXIMUM_ENTITIES = 50_000_000L
        const val HARD_MAXIMUM_TOKENS = 1_000_000_000L
        const val HARD_MAXIMUM_ENTITY_BYTES = 64 * 1024 * 1024
        const val HARD_MAXIMUM_ENTITY_NODES = 1_000_000
        const val HARD_MAXIMUM_DEPTH = 256
        const val HARD_MAXIMUM_NUMBER_CHARACTERS = 4096
    }
}

data class FullTreeDataObservationIngestion(
    val databaseSha256: String,
    val stateSha256: String,
    val sourceSha256: String,
    val sourceBytes: Long,
    val globals: Long,
    val types: Long,
    val fields: Long,
    val bases: Long,
    val enumerators: Long,
    val scannedDies: Long,
)

/** Exact output identity copied from the authenticated bounded-shard checkpoint/index. */
data class FullTreeDataObservationArtifactBinding(
    val outputSha256: String,
    val outputBytes: Long,
    val entities: Long,
) {
    init {
        require(outputSha256.matches(Regex("[0-9a-f]{64}"))) {
            "data observation output digest is invalid"
        }
        require(outputBytes > 0L) { "data observation output byte count is invalid" }
        require(entities >= 0L) { "data observation output entity count is invalid" }
    }
}

/**
 * Streams one authenticated data-observation shard into an immutable, deterministic SQLite image.
 *
 * Only one bounded entity is materialized at a time. The destination must not exist, and it is
 * published by an atomic same-directory rename only after the complete source and SQLite state have
 * passed validation. The schema is deliberately small so later Kotlin truth generation can scan
 * canonical entities without recreating the original multi-hundred-megabyte JSON tree.
 *
 * As with [decompengine.oracle.core.OracleArtifacts], Java NIO cannot compare an open channel's
 * descriptor identity with a pathname. The non-group-writable directory owner is therefore a
 * cooperating member of this trusted oracle boundary and must not swap names during ingestion.
 */
object FullTreeDataObservationSqlite {
    fun ingest(
        source: Path,
        database: Path,
        scope: JsonObject,
        scopeSha256: String,
        inventory: JsonObject,
        shard: FullTreeDataObservationShardInput,
        artifact: FullTreeDataObservationArtifactBinding,
        limits: FullTreeDataObservationIngestionLimits = FullTreeDataObservationIngestionLimits(),
    ): FullTreeDataObservationIngestion {
        val bindings = FullTreeDataObservations.authenticatedBindings(scope, scopeSha256, inventory, shard)
        if (artifact.outputBytes > limits.maximumInputBytes || artifact.entities > limits.maximumEntities) {
            throw FullTreeDataTruthException("authenticated data observation output exceeds ingestion limits")
        }
        val sourceFile = validateSource(source, limits, artifact)
        val destination = validateDestination(database)
        val parentIdentity = directoryIdentity(destination.parent)
        var temporary: Path? = null
        var published = false
        try {
            temporary = Files.createTempFile(
                destination.parent,
                ".${destination.fileName}.observation-ingest-",
                ".sqlite",
            )
            Files.setPosixFilePermissions(temporary, PRIVATE_FILE_PERMISSIONS)
            val parsed = buildDatabase(
                sourceFile,
                temporary,
                bindings,
                shard,
                artifact,
                limits,
            )
            forceFile(temporary)
            val databaseSize = Files.size(temporary)
            if (databaseSize > limits.maximumDatabaseBytes) {
                throw FullTreeDataTruthException("data observation SQLite image exceeds its byte limit")
            }
            val stateSha256 = logicalStateSha256(temporary)
            val databaseSha256 = sha256File(temporary, limits.maximumDatabaseBytes)
            Files.setPosixFilePermissions(temporary, READ_ONLY_FILE_PERMISSIONS)
            val committedIdentity = readRegularFileAttributes(temporary, "temporary SQLite image").fileKey()
            ensureDirectoryIdentity(destination.parent, parentIdentity)
            if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
                throw FullTreeDataTruthException("data observation SQLite destination already exists")
            }
            forceDirectory(destination.parent)
            try {
                Files.move(temporary, destination, StandardCopyOption.ATOMIC_MOVE)
            } catch (failure: AtomicMoveNotSupportedException) {
                throw FullTreeDataTruthException("atomic SQLite publication is unavailable", failure)
            }
            temporary = null
            try {
                ensureCommittedIdentity(destination, committedIdentity)
                forceDirectory(destination.parent)
                ensureDirectoryIdentity(destination.parent, parentIdentity)
                ensureCommittedIdentity(destination, committedIdentity)
            } catch (failure: Throwable) {
                try {
                    revokeCommittedDatabase(destination, committedIdentity)
                } catch (revocationFailure: Throwable) {
                    failure.addSuppressed(revocationFailure)
                }
                throw FullTreeDataTruthException(
                    "data observation SQLite publication could not be verified and was revoked",
                    failure,
                )
            }
            published = true
            return FullTreeDataObservationIngestion(
                databaseSha256 = databaseSha256,
                stateSha256 = stateSha256,
                sourceSha256 = parsed.sourceSha256,
                sourceBytes = parsed.sourceBytes,
                globals = parsed.counts.requiredLong("globals"),
                types = parsed.counts.requiredLong("types"),
                fields = parsed.counts.requiredLong("fields"),
                bases = parsed.counts.requiredLong("bases"),
                enumerators = parsed.counts.requiredLong("enumerators"),
                scannedDies = parsed.counts.requiredLong("scannedDies"),
            )
        } catch (failure: FullTreeDataTruthException) {
            throw failure
        } catch (failure: Exception) {
            val state = if (published) "after publication" else "before publication"
            throw FullTreeDataTruthException("streaming data observation ingestion failed $state", failure)
        } finally {
            temporary?.let(::deleteTemporaryDatabase)
        }
    }

    private fun buildDatabase(
        source: SourceFile,
        database: Path,
        bindings: FullTreeDataObservationBindings,
        shard: FullTreeDataObservationShardInput,
        artifact: FullTreeDataObservationArtifactBinding,
        limits: FullTreeDataObservationIngestionLimits,
    ): ParsedShard {
        val jdbcUrl = "jdbc:sqlite:${database.toAbsolutePath().normalize()}"
        DriverManager.getConnection(jdbcUrl).use { connection ->
            configureDatabase(connection, limits)
            connection.autoCommit = false
            try {
                createSchema(connection)
                val parsed = connection.prepareStatement(INSERT_ENTITY_SQL).use { insert ->
                    parseAndInsert(source, bindings, shard, artifact, limits, insert)
                }
                insertMetadata(connection, bindings, shard, parsed)
                connection.commit()
                connection.autoCommit = true
                requireIntegrity(connection)
                return parsed
            } catch (failure: Throwable) {
                try {
                    connection.rollback()
                } catch (rollbackFailure: Throwable) {
                    failure.addSuppressed(rollbackFailure)
                }
                throw failure
            }
        }
    }

    private fun configureDatabase(connection: Connection, limits: FullTreeDataObservationIngestionLimits) {
        connection.createStatement().use { statement ->
            statement.execute("PRAGMA journal_mode=OFF")
            statement.execute("PRAGMA synchronous=OFF")
            statement.execute("PRAGMA locking_mode=EXCLUSIVE")
            statement.execute("PRAGMA temp_store=MEMORY")
            statement.execute("PRAGMA trusted_schema=OFF")
            statement.execute("PRAGMA page_size=$SQLITE_PAGE_BYTES")
            val maximumPages = Math.addExact(limits.maximumDatabaseBytes, SQLITE_PAGE_BYTES - 1L) /
                SQLITE_PAGE_BYTES
            statement.execute("PRAGMA max_page_count=$maximumPages")
            statement.execute("PRAGMA application_id=$SQLITE_APPLICATION_ID")
            statement.execute("PRAGMA user_version=$SQLITE_SCHEMA_VERSION")
        }
    }

    private fun createSchema(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.execute(
                """
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY NOT NULL,
                    value TEXT NOT NULL
                ) WITHOUT ROWID
                """.trimIndent(),
            )
            statement.execute(
                """
                CREATE TABLE observations (
                    kind TEXT NOT NULL CHECK (kind IN ('global', 'type')),
                    id TEXT NOT NULL,
                    unit_id TEXT NOT NULL,
                    canonical_json BLOB NOT NULL,
                    PRIMARY KEY (kind, id)
                ) WITHOUT ROWID
                """.trimIndent(),
            )
        }
    }

    private fun parseAndInsert(
        source: SourceFile,
        bindings: FullTreeDataObservationBindings,
        shard: FullTreeDataObservationShardInput,
        artifact: FullTreeDataObservationArtifactBinding,
        limits: FullTreeDataObservationIngestionLimits,
        insert: PreparedStatement,
    ): ParsedShard {
        val sourceDigest = MessageDigest.getInstance("SHA-256")
        val documentBudget = DocumentBudget(limits)
        val semantics = FullTreeDataObservationSemantics(shard.units)
        var schemaVersion: JsonElement? = null
        var oracle: JsonObject? = null
        var shardBinding: JsonObject? = null
        var counts: JsonObject? = null
        var globalsSeen = false
        var typesSeen = false
        val topLevelFields = hashSetOf<String>()
        var topLevelFieldIndex = 0
        val canonicalDocument = CanonicalDocumentDigest(limits.maximumInputBytes)

        FileChannel.open(source.path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { channel ->
            val bounded = MaximumInputStream(Channels.newInputStream(channel), limits.maximumInputBytes)
            val digesting = DigestInputStream(bounded, sourceDigest)
            val input = rejectBom(digesting)
            jsonFactory(limits).createParser(input).use { parser ->
                requireToken(parser.nextToken(), JsonToken.START_OBJECT, "data observation document must be an object")
                canonicalDocument.startObject()
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    requireToken(parser.currentToken(), JsonToken.FIELD_NAME, "data observation object field is malformed")
                    val field = parser.currentName()
                    documentBudget.chargeString(field, null)
                    if (!topLevelFields.add(field)) {
                        throw FullTreeDataTruthException("data observation document repeats field $field")
                    }
                    if (EXPECTED_TOP_LEVEL_ORDER.getOrNull(topLevelFieldIndex++) != field) {
                        throw FullTreeDataTruthException("data observation document is not in canonical field order")
                    }
                    canonicalDocument.field(field)
                    val valueToken = parser.nextToken()
                        ?: throw FullTreeDataTruthException("data observation field $field has no value")
                    when (field) {
                        "schemaVersion" -> schemaVersion = readBoundedElement(
                            parser,
                            valueToken,
                            documentBudget,
                            limits,
                        ).also { canonicalDocument.value(canonicalEntity(it, limits)) }
                        "oracle" -> oracle = readBoundedObject(
                            parser,
                            valueToken,
                            documentBudget,
                            limits,
                            "oracle",
                        ).also { canonicalDocument.value(canonicalEntity(it, limits)) }
                        "shard" -> shardBinding = readBoundedObject(
                            parser,
                            valueToken,
                            documentBudget,
                            limits,
                            "shard",
                        ).also { canonicalDocument.value(canonicalEntity(it, limits)) }
                        "counts" -> counts = readBoundedObject(
                            parser,
                            valueToken,
                            documentBudget,
                            limits,
                            "counts",
                        ).also { canonicalDocument.value(canonicalEntity(it, limits)) }
                        "globals" -> {
                            globalsSeen = true
                            readEntityArray(
                                parser,
                                valueToken,
                                EntityKind.GLOBAL,
                                documentBudget,
                                semantics,
                                bindings,
                                shard,
                                limits,
                                insert,
                                canonicalDocument,
                            )
                        }
                        "types" -> {
                            typesSeen = true
                            readEntityArray(
                                parser,
                                valueToken,
                                EntityKind.TYPE,
                                documentBudget,
                                semantics,
                                bindings,
                                shard,
                                limits,
                                insert,
                                canonicalDocument,
                            )
                        }
                        else -> throw FullTreeDataTruthException(
                            "data observation document has unsupported field $field",
                        )
                    }
                }
                canonicalDocument.endObject()
                if (parser.nextToken() != null) {
                    throw FullTreeDataTruthException("data observation document has trailing JSON content")
                }
            }
            if (bounded.byteCount != source.attributes.size() || channel.size() != source.attributes.size()) {
                throw FullTreeDataTruthException("data observation source changed size during ingestion")
            }
        }
        ensureSourceIdentity(source)

        if (topLevelFields != REQUIRED_TOP_LEVEL_FIELDS || !globalsSeen || !typesSeen) {
            throw FullTreeDataTruthException("data observation document is missing required fields")
        }
        if (schemaVersion != JsonPrimitive(1)) {
            throw FullTreeDataTruthException("data observation schema version does not match")
        }
        if (oracle != bindings.oracle || shardBinding != bindings.shard) {
            throw FullTreeDataTruthException("data observation bindings do not match")
        }
        val actualCounts = counts ?: throw FullTreeDataTruthException("data observation counts are absent")
        val expectedCounts = semantics.expectedCounts(actualCounts.requiredLong("scannedDies"))
        if (actualCounts != expectedCounts) {
            throw FullTreeDataTruthException("data observation counts do not reconcile")
        }
        validateSchemaEnvelope(bindings, actualCounts)
        val sourceSha256 = sourceDigest.digest()
        if (
            source.attributes.size() != canonicalDocument.byteCount ||
            !MessageDigest.isEqual(sourceSha256, canonicalDocument.finish())
        ) {
            throw FullTreeDataTruthException("data observation JSON is not in canonical byte form")
        }
        if (
            source.attributes.size() != artifact.outputBytes ||
            sourceSha256.hex() != artifact.outputSha256 ||
            semantics.entityCount() != artifact.entities
        ) {
            throw FullTreeDataTruthException("data observation artifact does not match its authenticated output binding")
        }
        return ParsedShard(
            sourceSha256 = sourceSha256.hex(),
            sourceBytes = source.attributes.size(),
            counts = actualCounts,
        )
    }

    private fun readEntityArray(
        parser: JsonParser,
        token: JsonToken,
        kind: EntityKind,
        documentBudget: DocumentBudget,
        semantics: FullTreeDataObservationSemantics,
        bindings: FullTreeDataObservationBindings,
        shard: FullTreeDataObservationShardInput,
        limits: FullTreeDataObservationIngestionLimits,
        insert: PreparedStatement,
        canonicalDocument: CanonicalDocumentDigest,
    ) {
        requireToken(token, JsonToken.START_ARRAY, "data observation ${kind.arrayName} must be an array")
        canonicalDocument.startArray()
        while (parser.nextToken() != JsonToken.END_ARRAY) {
            val current = parser.currentToken()
                ?: throw FullTreeDataTruthException("data observation ${kind.arrayName} ended unexpectedly")
            val record = readBoundedObject(
                parser,
                current,
                documentBudget,
                limits,
                "${kind.recordName} entity",
            )
            validateEntitySchema(kind, record, bindings, shard.units.size.toLong())
            when (kind) {
                EntityKind.GLOBAL -> semantics.acceptGlobal(record)
                EntityKind.TYPE -> semantics.acceptType(record)
            }
            if (semantics.entityCount() > limits.maximumEntities) {
                throw FullTreeDataTruthException("data observation shard exceeds its entity limit")
            }
            val canonical = canonicalEntity(record, limits)
            canonicalDocument.arrayValue(canonical)
            insert.clearParameters()
            insert.setString(1, kind.databaseValue)
            insert.setString(2, record.requiredString("id"))
            insert.setString(3, record.requiredString("unitId"))
            insert.setBytes(4, canonical)
            if (insert.executeUpdate() != 1) {
                throw FullTreeDataTruthException("data observation entity was not stored exactly once")
            }
        }
        canonicalDocument.endArray()
    }

    private fun readBoundedObject(
        parser: JsonParser,
        token: JsonToken,
        documentBudget: DocumentBudget,
        limits: FullTreeDataObservationIngestionLimits,
        label: String,
    ): JsonObject = readBoundedElement(parser, token, documentBudget, limits) as? JsonObject
        ?: throw FullTreeDataTruthException("data observation $label must be an object")

    private fun readBoundedElement(
        parser: JsonParser,
        token: JsonToken,
        documentBudget: DocumentBudget,
        limits: FullTreeDataObservationIngestionLimits,
    ): JsonElement {
        val entityBudget = EntityBudget(limits)
        return readElement(parser, token, depth = 1, documentBudget, entityBudget, limits)
    }

    private fun readElement(
        parser: JsonParser,
        token: JsonToken,
        depth: Int,
        documentBudget: DocumentBudget,
        entityBudget: EntityBudget,
        limits: FullTreeDataObservationIngestionLimits,
    ): JsonElement {
        entityBudget.chargeNode()
        if (depth > limits.maximumDepth) {
            throw FullTreeDataTruthException("data observation entity exceeds its nesting-depth limit")
        }
        return when (token) {
            JsonToken.START_OBJECT -> {
                val entries = linkedMapOf<String, JsonElement>()
                while (parser.nextToken() != JsonToken.END_OBJECT) {
                    requireToken(parser.currentToken(), JsonToken.FIELD_NAME, "data observation object is malformed")
                    val field = parser.currentName()
                    documentBudget.chargeString(field, entityBudget)
                    if (entries.containsKey(field)) {
                        throw FullTreeDataTruthException("data observation object repeats field $field")
                    }
                    val value = parser.nextToken()
                        ?: throw FullTreeDataTruthException("data observation field $field has no value")
                    entries[field] = readElement(
                        parser,
                        value,
                        depth + 1,
                        documentBudget,
                        entityBudget,
                        limits,
                    )
                }
                JsonObject(entries)
            }
            JsonToken.START_ARRAY -> {
                val entries = arrayListOf<JsonElement>()
                while (parser.nextToken() != JsonToken.END_ARRAY) {
                    entries += readElement(
                        parser,
                        parser.currentToken(),
                        depth + 1,
                        documentBudget,
                        entityBudget,
                        limits,
                    )
                }
                JsonArray(entries)
            }
            JsonToken.VALUE_STRING -> parser.text.let { value ->
                documentBudget.chargeString(value, entityBudget)
                JsonPrimitive(value)
            }
            JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> strictNumber(parser, token, limits)
            JsonToken.VALUE_TRUE -> JsonPrimitive(true)
            JsonToken.VALUE_FALSE -> JsonPrimitive(false)
            JsonToken.VALUE_NULL -> JsonNull
            else -> throw FullTreeDataTruthException("data observation contains an unsupported JSON token")
        }
    }

    private fun strictNumber(
        parser: JsonParser,
        token: JsonToken,
        limits: FullTreeDataObservationIngestionLimits,
    ): JsonPrimitive {
        val text = parser.text
        if (text.length > limits.maximumNumberCharacters) {
            throw FullTreeDataTruthException("data observation number exceeds its character limit")
        }
        if (token == JsonToken.VALUE_NUMBER_FLOAT) {
            val value = text.toDoubleOrNull()
                ?: throw FullTreeDataTruthException("data observation contains an invalid JSON number")
            if (!value.isFinite()) {
                throw FullTreeDataTruthException("data observation JSON number is not finite")
            }
        } else {
            try {
                BigInteger(text)
            } catch (failure: NumberFormatException) {
                throw FullTreeDataTruthException("data observation contains an invalid JSON integer", failure)
            }
        }
        return try {
            Json.parseToJsonElement(text) as JsonPrimitive
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observation contains an invalid JSON number", failure)
        }
    }

    private fun canonicalEntity(
        element: JsonElement,
        limits: FullTreeDataObservationIngestionLimits,
    ): ByteArray = try {
        OracleJson.canonicalBytes(
            element,
            StrictJsonLimits(
                maximumInputBytes = limits.maximumEntityBytes,
                maximumCanonicalBytes = limits.maximumEntityBytes,
                maximumDepth = limits.maximumDepth,
                maximumNodes = limits.maximumEntityNodes,
                maximumStringBytes = limits.maximumStringBytes,
                maximumTotalStringBytes = limits.maximumEntityBytes,
                maximumNumberCharacters = limits.maximumNumberCharacters,
            ),
        )
    } catch (failure: Exception) {
        throw FullTreeDataTruthException("data observation entity exceeds strict JSON limits", failure)
    }

    private fun validateEntitySchema(
        kind: EntityKind,
        record: JsonObject,
        bindings: FullTreeDataObservationBindings,
        unitCount: Long,
    ) {
        val globals = if (kind == EntityKind.GLOBAL) JsonArray(listOf(record)) else JsonArray(emptyList())
        val types = if (kind == EntityKind.TYPE) JsonArray(listOf(record)) else JsonArray(emptyList())
        val counts = emptyCounts(unitCount).toMutableMap().apply {
            this[if (kind == EntityKind.GLOBAL) "globals" else "types"] = JsonPrimitive(1)
        }
        validateSchemaDocument(bindings, JsonObject(counts), globals, types)
    }

    private fun validateSchemaEnvelope(bindings: FullTreeDataObservationBindings, counts: JsonObject) {
        validateSchemaDocument(bindings, counts, JsonArray(emptyList()), JsonArray(emptyList()))
    }

    private fun validateSchemaDocument(
        bindings: FullTreeDataObservationBindings,
        counts: JsonObject,
        globals: JsonArray,
        types: JsonArray,
    ) {
        val document = JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "oracle" to bindings.oracle,
                "shard" to bindings.shard,
                "counts" to counts,
                "globals" to globals,
                "types" to types,
            ),
        )
        try {
            OracleSchemas.validate("full-tree-data-observations", document)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observations fail schema validation: ${failure.message}", failure)
        }
    }

    private fun emptyCounts(unitCount: Long): JsonObject = JsonObject(
        mapOf(
            "bases" to JsonPrimitive(0),
            "enumerators" to JsonPrimitive(0),
            "fields" to JsonPrimitive(0),
            "globals" to JsonPrimitive(0),
            "scannedDies" to JsonPrimitive(1),
            "types" to JsonPrimitive(0),
            "units" to JsonPrimitive(unitCount),
        ),
    )

    private fun insertMetadata(
        connection: Connection,
        bindings: FullTreeDataObservationBindings,
        shard: FullTreeDataObservationShardInput,
        parsed: ParsedShard,
    ) {
        val values = sortedMapOf(
            "configurationSha256" to bindings.oracle.requiredString("configurationSha256"),
            "enumerators" to parsed.counts.requiredLong("enumerators").toString(),
            "fields" to parsed.counts.requiredLong("fields").toString(),
            "bases" to parsed.counts.requiredLong("bases").toString(),
            "globals" to parsed.counts.requiredLong("globals").toString(),
            "inventoryIndexSha256" to bindings.oracle.requiredString("inventoryIndexSha256"),
            "richArtifactSha256" to bindings.oracle.requiredString("richArtifactSha256"),
            "schemaSha256" to OracleSchemas.identity("full-tree-data-observations").sha256,
            "schemaVersion" to "1",
            "scopeSha256" to bindings.oracle.requiredString("scopeSha256"),
            "scannedDies" to parsed.counts.requiredLong("scannedDies").toString(),
            "shardId" to shard.identifier,
            "shardInputSha256" to shard.inputSha256,
            "sourceBytes" to parsed.sourceBytes.toString(),
            "sourceSha256" to parsed.sourceSha256,
            "types" to parsed.counts.requiredLong("types").toString(),
            "units" to parsed.counts.requiredLong("units").toString(),
        )
        connection.prepareStatement("INSERT INTO metadata(key, value) VALUES (?, ?)").use { insert ->
            values.forEach { (key, value) ->
                insert.setString(1, key)
                insert.setString(2, value)
                if (insert.executeUpdate() != 1) {
                    throw FullTreeDataTruthException("data observation metadata was not stored exactly once")
                }
            }
        }
    }

    private fun requireIntegrity(connection: Connection) {
        connection.createStatement().use { statement ->
            statement.executeQuery("PRAGMA integrity_check").use { result ->
                if (!result.next() || result.getString(1) != "ok" || result.next()) {
                    throw FullTreeDataTruthException("data observation SQLite integrity check failed")
                }
            }
        }
    }

    private fun logicalStateSha256(database: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        DriverManager.getConnection("jdbc:sqlite:file:${database.toAbsolutePath().normalize()}?mode=ro").use { connection ->
            connection.createStatement().use { statement ->
                statement.executeQuery("SELECT key, value FROM metadata ORDER BY key").use { rows ->
                    while (rows.next()) {
                        digestField(digest, "metadata".toByteArray(StandardCharsets.UTF_8))
                        digestField(digest, rows.getString(1).toByteArray(StandardCharsets.UTF_8))
                        digestField(digest, rows.getString(2).toByteArray(StandardCharsets.UTF_8))
                    }
                }
                statement.executeQuery(
                    "SELECT kind, id, unit_id, canonical_json FROM observations ORDER BY kind, id",
                ).use { rows ->
                    while (rows.next()) {
                        digestField(digest, "observation".toByteArray(StandardCharsets.UTF_8))
                        digestField(digest, rows.getString(1).toByteArray(StandardCharsets.UTF_8))
                        digestField(digest, rows.getString(2).toByteArray(StandardCharsets.UTF_8))
                        digestField(digest, rows.getString(3).toByteArray(StandardCharsets.UTF_8))
                        digestField(digest, rows.getBytes(4))
                    }
                }
            }
        }
        return digest.digest().hex()
    }

    private fun digestField(digest: MessageDigest, bytes: ByteArray) {
        digest.update(ByteBuffer.allocate(Long.SIZE_BYTES).putLong(bytes.size.toLong()).array())
        digest.update(bytes)
    }

    private fun jsonFactory(limits: FullTreeDataObservationIngestionLimits): JsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .disable(StreamReadFeature.AUTO_CLOSE_SOURCE)
        .streamReadConstraints(
            StreamReadConstraints.builder()
                .maxDocumentLength(limits.maximumInputBytes)
                .maxTokenCount(limits.maximumTokens)
                .maxNestingDepth(limits.maximumDepth + 2)
                .maxStringLength(limits.maximumStringBytes)
                .maxNameLength(limits.maximumStringBytes)
                .maxNumberLength(limits.maximumNumberCharacters)
                .build(),
        )
        .build()

    private fun rejectBom(input: InputStream): PushbackInputStream {
        val pushback = PushbackInputStream(input, UTF8_BOM.size)
        val prefix = pushback.readNBytes(UTF8_BOM.size)
        if (prefix.contentEquals(UTF8_BOM)) {
            throw FullTreeDataTruthException("data observation JSON must not contain a UTF-8 BOM")
        }
        pushback.unread(prefix)
        return pushback
    }

    private fun validateSource(
        path: Path,
        limits: FullTreeDataObservationIngestionLimits,
        artifact: FullTreeDataObservationArtifactBinding,
    ): SourceFile {
        val source = path.toAbsolutePath().normalize()
        if (source.fileName == null || source.parent == null) {
            throw FullTreeDataTruthException("data observation source must name a file")
        }
        val real = try {
            source.toRealPath()
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observation source is unavailable", failure)
        }
        if (real != source) throw FullTreeDataTruthException("data observation source path contains a symbolic link")
        directoryIdentity(source.parent)
        val attributes = readRegularFileAttributes(source, "data observation source")
        if (attributes.size() < 1L || attributes.size() > limits.maximumInputBytes) {
            throw FullTreeDataTruthException("data observation source exceeds its byte limit")
        }
        if (attributes.size() != artifact.outputBytes) {
            throw FullTreeDataTruthException("data observation source byte count does not match its authenticated output")
        }
        return SourceFile(source, attributes)
    }

    private fun readRegularFileAttributes(path: Path, label: String): BasicFileAttributes {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("$label attributes are unavailable", failure)
        }
        if (!attributes.isRegularFile || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("$label must be an identified regular file")
        }
        return attributes
    }

    private fun ensureSourceIdentity(source: SourceFile) {
        val after = readRegularFileAttributes(source.path, "data observation source")
        if (
            after.fileKey() != source.attributes.fileKey() ||
            after.size() != source.attributes.size() ||
            after.lastModifiedTime() != source.attributes.lastModifiedTime()
        ) {
            throw FullTreeDataTruthException("data observation source changed during ingestion")
        }
    }

    private fun ensureCommittedIdentity(path: Path, expected: Any?) {
        val current = readRegularFileAttributes(path, "committed SQLite image")
        if (expected == null || current.fileKey() != expected) {
            throw FullTreeDataTruthException("committed data observation SQLite identity changed")
        }
    }

    private fun revokeCommittedDatabase(path: Path, expected: Any?) {
        ensureCommittedIdentity(path, expected)
        Files.delete(path)
        if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
            throw FullTreeDataTruthException("unverified data observation SQLite image could not be revoked")
        }
        forceDirectory(path.parent)
    }

    private fun validateDestination(path: Path): Path {
        val destination = path.toAbsolutePath().normalize()
        if (destination.fileName == null || destination.parent == null) {
            throw FullTreeDataTruthException("data observation SQLite destination must name a file")
        }
        if (Files.exists(destination, LinkOption.NOFOLLOW_LINKS)) {
            throw FullTreeDataTruthException("data observation SQLite destination already exists")
        }
        val realParent = try {
            destination.parent.toRealPath()
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observation SQLite parent is unavailable", failure)
        }
        if (realParent != destination.parent) {
            throw FullTreeDataTruthException("data observation SQLite parent path contains a symbolic link")
        }
        directoryIdentity(destination.parent)
        return destination
    }

    private fun directoryIdentity(path: Path): Any {
        val attributes = try {
            Files.readAttributes(path, BasicFileAttributes::class.java, LinkOption.NOFOLLOW_LINKS)
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observation directory is unavailable", failure)
        }
        if (!attributes.isDirectory || attributes.isSymbolicLink || attributes.fileKey() == null) {
            throw FullTreeDataTruthException("data observation path must use an identified real directory")
        }
        val permissions = Files.getFileAttributeView(
            path,
            PosixFileAttributeView::class.java,
            LinkOption.NOFOLLOW_LINKS,
        )?.readAttributes()?.permissions()
            ?: throw FullTreeDataTruthException("data observation storage requires POSIX permissions")
        if (permissions.any { it in UNTRUSTED_DIRECTORY_PERMISSIONS }) {
            throw FullTreeDataTruthException("data observation directory is writable by an untrusted principal")
        }
        return attributes.fileKey()
    }

    private fun ensureDirectoryIdentity(path: Path, expected: Any) {
        if (directoryIdentity(path) != expected) {
            throw FullTreeDataTruthException("data observation SQLite directory changed during ingestion")
        }
    }

    private fun forceFile(path: Path) {
        FileChannel.open(path, StandardOpenOption.WRITE, LinkOption.NOFOLLOW_LINKS).use { it.force(true) }
    }

    private fun forceDirectory(path: Path) {
        try {
            FileChannel.open(path, StandardOpenOption.READ).use { it.force(true) }
        } catch (failure: Exception) {
            throw FullTreeDataTruthException("data observation SQLite directory durability is unavailable", failure)
        }
    }

    private fun sha256File(path: Path, maximumBytes: Long): String {
        val digest = MessageDigest.getInstance("SHA-256")
        var count = 0L
        Files.newInputStream(path, StandardOpenOption.READ, LinkOption.NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(64 * 1024)
            while (true) {
                val read = input.read(buffer)
                if (read < 0) break
                count = Math.addExact(count, read.toLong())
                if (count > maximumBytes) {
                    throw FullTreeDataTruthException("data observation SQLite image exceeds its byte limit")
                }
                digest.update(buffer, 0, read)
            }
        }
        return digest.digest().hex()
    }

    private fun deleteTemporaryDatabase(path: Path) {
        listOf(path, path.resolveSibling("${path.fileName}-journal"), path.resolveSibling("${path.fileName}-wal"))
            .forEach { temporary ->
                try {
                    Files.deleteIfExists(temporary)
                } catch (_: Exception) {
                    // Preserve the primary validation failure; every name is an owned random temporary.
                }
            }
    }

    private fun requireToken(actual: JsonToken?, expected: JsonToken, message: String) {
        if (actual != expected) throw FullTreeDataTruthException(message)
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }

    private data class SourceFile(val path: Path, val attributes: BasicFileAttributes)

    private data class ParsedShard(
        val sourceSha256: String,
        val sourceBytes: Long,
        val counts: JsonObject,
    )

    private enum class EntityKind(val arrayName: String, val recordName: String, val databaseValue: String) {
        GLOBAL("globals", "global", "global"),
        TYPE("types", "type", "type"),
    }

    private class DocumentBudget(private val limits: FullTreeDataObservationIngestionLimits) {
        private var totalStringBytes = 0L

        fun chargeString(value: String, entity: EntityBudget?) {
            requireScalarUnicode(value)
            val bytes = value.toByteArray(StandardCharsets.UTF_8).size
            if (bytes > limits.maximumStringBytes) {
                throw FullTreeDataTruthException("data observation string exceeds its byte limit")
            }
            totalStringBytes = checkedAdd(totalStringBytes, bytes.toLong(), "aggregate string-byte")
            if (totalStringBytes > limits.maximumTotalStringBytes) {
                throw FullTreeDataTruthException("data observation strings exceed their aggregate byte limit")
            }
            entity?.chargeString(bytes)
        }

        private fun requireScalarUnicode(value: String) {
            var offset = 0
            while (offset < value.length) {
                val current = value[offset]
                when {
                    Character.isHighSurrogate(current) -> {
                        if (offset + 1 >= value.length || !Character.isLowSurrogate(value[offset + 1])) {
                            throw FullTreeDataTruthException("data observation string contains an unpaired surrogate")
                        }
                        offset += 2
                    }
                    Character.isLowSurrogate(current) ->
                        throw FullTreeDataTruthException("data observation string contains an unpaired surrogate")
                    else -> offset++
                }
            }
        }
    }

    private class EntityBudget(private val limits: FullTreeDataObservationIngestionLimits) {
        private var nodes = 0
        private var stringBytes = 0L

        fun chargeNode() {
            nodes++
            if (nodes > limits.maximumEntityNodes) {
                throw FullTreeDataTruthException("data observation entity exceeds its node limit")
            }
        }

        fun chargeString(bytes: Int) {
            stringBytes = checkedAdd(stringBytes, bytes.toLong(), "entity string-byte")
            if (stringBytes > limits.maximumEntityBytes.toLong()) {
                throw FullTreeDataTruthException("data observation entity strings exceed its byte limit")
            }
        }
    }

    private class MaximumInputStream(input: InputStream, private val maximumBytes: Long) : FilterInputStream(input) {
        var byteCount: Long = 0L
            private set

        override fun read(): Int {
            if (byteCount == maximumBytes) {
                if (super.read() >= 0) throw FullTreeDataTruthException("data observation source exceeds its byte limit")
                return -1
            }
            val value = super.read()
            if (value >= 0) byteCount++
            return value
        }

        override fun read(buffer: ByteArray, offset: Int, length: Int): Int {
            if (length == 0) return 0
            val remaining = maximumBytes - byteCount
            if (remaining == 0L) return read().let { if (it < 0) -1 else 1 }
            val read = super.read(buffer, offset, minOf(length.toLong(), remaining).toInt())
            if (read > 0) byteCount += read.toLong()
            return read
        }
    }

    private class CanonicalDocumentDigest(private val maximumBytes: Long) {
        private val digest = MessageDigest.getInstance("SHA-256")
        private var fields = 0
        private var arrayValues = 0
        private var finished = false
        var byteCount: Long = 0L
            private set

        fun startObject() = writeAscii("{\n")

        fun field(name: String) {
            if (fields++ > 0) writeAscii(",\n")
            writeSpaces(2)
            writeAscii("\"$name\": ")
        }

        fun value(canonicalBytes: ByteArray) = writeCanonicalValue(canonicalBytes, indentation = 2, indentFirst = false)

        fun startArray() {
            arrayValues = 0
        }

        fun arrayValue(canonicalBytes: ByteArray) {
            if (arrayValues++ == 0) writeAscii("[\n") else writeAscii(",\n")
            writeCanonicalValue(canonicalBytes, indentation = 4, indentFirst = true)
        }

        fun endArray() {
            if (arrayValues == 0) writeAscii("[]") else writeAscii("\n  ]")
        }

        fun endObject() {
            writeAscii("\n}\n")
            finished = true
        }

        fun finish(): ByteArray {
            if (!finished) throw FullTreeDataTruthException("canonical data observation digest is incomplete")
            return digest.digest()
        }

        private fun writeCanonicalValue(bytes: ByteArray, indentation: Int, indentFirst: Boolean) {
            if (bytes.isEmpty() || bytes.last() != '\n'.code.toByte()) {
                throw FullTreeDataTruthException("canonical data observation value is malformed")
            }
            if (indentFirst) writeSpaces(indentation)
            var start = 0
            for (index in 0 until bytes.lastIndex) {
                if (bytes[index] == '\n'.code.toByte()) {
                    write(bytes, start, index - start)
                    writeAscii("\n")
                    writeSpaces(indentation)
                    start = index + 1
                }
            }
            write(bytes, start, bytes.lastIndex - start)
        }

        private fun writeAscii(value: String) {
            val bytes = value.toByteArray(StandardCharsets.US_ASCII)
            write(bytes, 0, bytes.size)
        }

        private fun writeSpaces(count: Int) = repeat(count) { writeAscii(" ") }

        private fun write(bytes: ByteArray, offset: Int, length: Int) {
            byteCount = checkedAdd(byteCount, length.toLong(), "canonical byte")
            if (byteCount > maximumBytes) {
                throw FullTreeDataTruthException("canonical data observation JSON exceeds its byte limit")
            }
            digest.update(bytes, offset, length)
        }
    }

    private fun checkedAdd(left: Long, right: Long, label: String): Long = try {
        Math.addExact(left, right)
    } catch (failure: ArithmeticException) {
        throw FullTreeDataTruthException("data observation $label count exceeds the supported range", failure)
    }

    private const val SQLITE_PAGE_BYTES = 4096L
    private const val SQLITE_APPLICATION_ID = 0x44434f42
    private const val SQLITE_SCHEMA_VERSION = 1
    private const val INSERT_ENTITY_SQL =
        "INSERT INTO observations(kind, id, unit_id, canonical_json) VALUES (?, ?, ?, ?)"
    private val UTF8_BOM = byteArrayOf(0xef.toByte(), 0xbb.toByte(), 0xbf.toByte())
    private val REQUIRED_TOP_LEVEL_FIELDS = setOf("schemaVersion", "oracle", "shard", "counts", "globals", "types")
    private val EXPECTED_TOP_LEVEL_ORDER = listOf("counts", "globals", "oracle", "schemaVersion", "shard", "types")
    private val PRIVATE_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
        PosixFilePermission.OWNER_READ,
        PosixFilePermission.OWNER_WRITE,
    )
    private val READ_ONLY_FILE_PERMISSIONS: Set<PosixFilePermission> = EnumSet.of(
        PosixFilePermission.OWNER_READ,
    )
    private val UNTRUSTED_DIRECTORY_PERMISSIONS = setOf(
        PosixFilePermission.GROUP_WRITE,
        PosixFilePermission.OTHERS_WRITE,
    )
}
