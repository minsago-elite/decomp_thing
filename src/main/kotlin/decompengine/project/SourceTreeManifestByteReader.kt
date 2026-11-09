package decompengine.project

import com.fasterxml.jackson.core.JsonFactory
import com.fasterxml.jackson.core.JsonParser
import com.fasterxml.jackson.core.JsonToken
import com.fasterxml.jackson.core.StreamReadConstraints
import com.fasterxml.jackson.core.StreamReadFeature
import decompengine.oracle.core.StrictJsonException
import decompengine.oracle.core.StrictJsonLimits

/**
 * Syntax-first source manifest reader for callers that already captured the exact bounded bytes.
 * It validates the complete JSON document before constructing the small typed manifest records,
 * but never builds a kotlinx JsonElement tree or a decoded copy of the complete document.
 */
internal object SourceTreeManifestByteReader {
    private fun jsonFactory(limits: StrictJsonLimits): JsonFactory = JsonFactory.builder()
        .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
        .streamReadConstraints(StreamReadConstraints.builder()
            .maxDocumentLength(limits.maximumInputBytes.toLong())
            // A UTF-8 byte ceiling is also an upper bound on UTF-16 code units.
            .maxNestingDepth(limits.maximumDepth)
            .maxStringLength(limits.maximumStringBytes)
            .maxNameLength(limits.maximumStringBytes)
            .maxNumberLength(limits.maximumNumberCharacters)
            .build())
        .build()

    private val ROOT_KEYS = listOf(
        "schemaVersion", "profileId", "profileSha256", "inputSha256", "files",
        "unresolvedEntityIds", "unresolvedImplementationIds",
    )
    private val FILE_KEYS = listOf(
        "path", "sha256", "generator", "promptSha256", "acceptedImplementation",
        "contentKind", "roles", "entityIds",
    )
    private val NUMBER = Regex("-?(?:0|[1-9][0-9]*)(?:\\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")

    internal class Document internal constructor(private val root: RawRoot?) {
        val isObject: Boolean get() = root != null
        val profileId: String? get() = root?.profileId as? String
        val profileSha256: String? get() = root?.profileSha256 as? String
        val fileCount: Int? get() = (root?.files as? List<*>)?.size

        fun validate(
            expectedProfile: ReconstructionProfile,
            probe: SourceTreeManifestProbe?,
            checkpoint: (String) -> Unit = {},
        ): SourceTreeManifest {
            val progress: (String) -> Unit = { stage ->
                checkpoint(stage)
                if (Thread.currentThread().isInterrupted) {
                    throw InterruptedException("source manifest validation interrupted")
                }
            }
            val document = root ?: throw IllegalArgumentException("Source catalog manifest is invalid.")
            progress("before validating source manifest root")
            probe?.startSafely(SourceTreeManifestStage.ROOT)
            try {
                require(document.keysMatch(ROOT_KEYS.size)) {
                    "source tree manifest fields do not match schema version 3"
                }
                val schemaValue = document.schemaVersion
                require(schemaValue !is String) { "source tree manifest schemaVersion must be an integer" }
                val schemaVersion = (schemaValue as? RawNumber)?.text?.toIntOrNull()
                    ?: throw IllegalArgumentException("source tree manifest schemaVersion must be an integer")
                require(schemaVersion == 3) { "unsupported source tree manifest schemaVersion: $schemaVersion" }
                val profileId = requiredString(document.profileId, "profileId")
                val profileSha256 = requiredString(document.profileSha256, "profileSha256")
                probe?.endSafely()

                val rawFiles = rawArray(document.files, "files")
                val files = ArrayList<GeneratedFileEvidence>(rawFiles.size)
                rawFiles.forEachIndexed { index, rawFile ->
                    if (index % 256 == 0) progress("while validating source manifest files")
                    probe?.startSafely(SourceTreeManifestStage.FILE_FIELDS)
                    try {
                        val item = rawFile as? RawFile
                            ?: throw IllegalArgumentException("source tree manifest file record must be an object")
                        require(item.keysMatch(FILE_KEYS.size)) {
                            "source tree manifest file fields do not match schema version 3"
                        }
                        val roles = rawArray(item.roles, "roles").mapIndexed { roleIndex, role ->
                            if (roleIndex % 1024 == 0) progress("while validating source manifest roles")
                            require(role is String) { "source tree manifest file roles must be strings" }
                            ProjectFileRole.fromWireName(role)
                        }
                        require(rolesAreStrictlySorted(roles)) {
                            "source tree manifest file roles must be unique and sorted"
                        }
                        val entityIds = rawArray(item.entityIds, "entityIds").mapIndexed { idIndex, id ->
                            if (idIndex % 1024 == 0) progress("while validating source manifest entity IDs")
                            require(id is String) { "source tree manifest entity IDs must be strings" }
                            id
                        }
                        require(stringsAreStrictlySorted(entityIds)) {
                            "source tree manifest entity IDs must be unique and sorted"
                        }
                        val accepted = when (val value = item.acceptedImplementation) {
                            RawNull -> null
                            is Boolean -> value
                            else -> throw IllegalArgumentException(
                                "source tree manifest acceptance value must be Boolean or null",
                            )
                        }
                        // Keep the constructor argument and refusal order aligned with the tree reader.
                        val path = requiredString(item.path, "path")
                        val sha256 = requiredString(item.sha256, "sha256")
                        val generator = requiredString(item.generator, "generator")
                        val promptSha256 = when (val value = item.promptSha256) {
                            RawNull -> null
                            is String -> value
                            else -> throw IllegalArgumentException(
                                "source tree manifest prompt hash must be a string or null",
                            )
                        }
                        val roleSet = roles.toSet()
                        val contentKind = ProjectContentKind.fromWireName(requiredString(item.contentKind, "contentKind"))
                        probe?.startSafely(SourceTreeManifestStage.FILE_EVIDENCE_INIT)
                        files += GeneratedFileEvidence(path, sha256, generator, promptSha256, entityIds,
                            accepted, roleSet, contentKind)
                    } finally {
                        probe?.endSafely()
                    }
                }

                progress("before validating source manifest order")
                probe?.startSafely(SourceTreeManifestStage.PATH_ORDER)
                require(filesAreStrictlySorted(files)) {
                    "source tree manifest files must be unique and sorted"
                }
                val inputSha256 = requiredString(document.inputSha256, "inputSha256")
                val unresolvedEntityIds = sortedIds(document.unresolvedEntityIds, "unresolvedEntityIds", progress)
                val unresolvedImplementationIds = sortedIds(
                    document.unresolvedImplementationIds, "unresolvedImplementationIds", progress,
                )
                probe?.startSafely(SourceTreeManifestStage.CONSTRUCT)
                val manifest = SourceTreeManifest(schemaVersion, profileId, profileSha256, inputSha256,
                    files, unresolvedEntityIds, unresolvedImplementationIds)
                probe?.startSafely(SourceTreeManifestStage.PROFILE_POLICY)
                require(manifest.profileId == expectedProfile.id && manifest.profileSha256 == expectedProfile.sha256) {
                    "source tree manifest reconstruction profile does not match the expected profile"
                }
                manifest.files.forEach { file ->
                    progress("while validating source manifest profile policy")
                    val declaration = expectedProfile.layout.declarationForValidatedPath(file.path)
                    require(file.roles == declaration.roles && file.contentKind == declaration.contentKind) {
                        "source tree manifest file policy does not match the reconstruction profile: ${file.path}"
                    }
                }
                progress("after validating source manifest")
                return manifest
            } finally {
                probe?.endSafely()
            }
        }
    }

    fun parse(bytes: ByteArray, limits: StrictJsonLimits, checkpoint: (String) -> Unit = {}): Document {
        val progress: (String) -> Unit = { stage ->
            checkpoint(stage)
            if (Thread.currentThread().isInterrupted) {
                throw InterruptedException("source manifest parsing interrupted")
            }
        }
        progress("before source manifest parsing")
        val factory = jsonFactory(limits)
        validateSyntax(bytes, limits, factory, progress)
        progress("after validating source manifest syntax")
        val document = parseTypedDocument(bytes, factory, progress)
        progress("after parsing source manifest fields")
        return document
    }

    private fun validateSyntax(
        bytes: ByteArray,
        limits: StrictJsonLimits,
        factory: JsonFactory,
        checkpoint: (String) -> Unit,
    ) {
        checkpoint("before source manifest UTF-8 validation")
        if (bytes.size > limits.maximumInputBytes) {
            throw StrictJsonException("JSON input exceeds the configured byte limit")
        }
        validateUtf8(bytes, checkpoint)
        if (bytes.size >= 3 && bytes[0] == 0xEF.toByte() && bytes[1] == 0xBB.toByte() && bytes[2] == 0xBF.toByte()) {
            throw StrictJsonException("JSON input is not valid JSON")
        }
        checkpoint("after source manifest UTF-8 validation")

        var depth = 0
        var roots = 0
        var nodes = 0
        var stringBytes = 0L
        var nextNodeCheckpoint = 1024
        fun chargeNode() {
            nodes++
            if (nodes > limits.maximumNodes) throw StrictJsonException("JSON value exceeds the configured node limit")
            if (nodes >= nextNodeCheckpoint) {
                checkpoint("while validating source manifest JSON values")
                nextNodeCheckpoint = nodes + 1024
            }
        }
        fun chargeString(value: String) {
            val size = utf8Length(value, checkpoint)
            if (size > limits.maximumStringBytes) {
                throw StrictJsonException("JSON string exceeds the configured byte limit")
            }
            if (stringBytes > limits.maximumTotalStringBytes.toLong() - size) {
                throw StrictJsonException("JSON strings exceed the configured aggregate byte limit")
            }
            stringBytes += size
        }
        try {
            factory.createParser(bytes).use { parser ->
                while (true) {
                    val token = parser.nextToken() ?: break
                    when (token) {
                        JsonToken.START_OBJECT, JsonToken.START_ARRAY -> {
                            if (depth == 0) roots++
                            chargeNode()
                            depth++
                            if (depth > limits.maximumDepth) {
                                throw StrictJsonException("JSON value exceeds the configured nesting-depth limit")
                            }
                        }
                        JsonToken.END_OBJECT, JsonToken.END_ARRAY -> depth--
                        JsonToken.FIELD_NAME -> chargeString(parser.currentName)
                        JsonToken.VALUE_STRING -> {
                            if (depth == 0) roots++
                            chargeNode()
                            chargeString(parser.text)
                        }
                        JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> {
                            if (depth == 0) roots++
                            chargeNode()
                            val value = parser.text
                            if (value.length > limits.maximumNumberCharacters || !NUMBER.matches(value)) {
                                throw StrictJsonException("JSON number is invalid or exceeds the configured character limit")
                            }
                            if (value.any { it == '.' || it == 'e' || it == 'E' } &&
                                value.toDoubleOrNull()?.isFinite() != true) {
                                throw StrictJsonException("JSON number is not finite")
                            }
                        }
                        JsonToken.VALUE_TRUE, JsonToken.VALUE_FALSE, JsonToken.VALUE_NULL -> {
                            if (depth == 0) roots++
                            chargeNode()
                        }
                        else -> throw StrictJsonException("JSON input contains an unsupported token")
                    }
                }
            }
        } catch (failure: StrictJsonException) {
            throw failure
        } catch (failure: Exception) {
            if (failure is InterruptedException || failure is java.util.concurrent.CancellationException ||
                Thread.currentThread().isInterrupted) throw failure
            throw StrictJsonException("JSON input is invalid", failure)
        }
        if (roots == 0) throw StrictJsonException("JSON input is empty")
        if (roots != 1 || depth != 0) throw StrictJsonException("unexpected trailing JSON content")
    }

    private fun validateUtf8(bytes: ByteArray, checkpoint: (String) -> Unit) {
        var index = 0
        var checkpointAt = 0
        fun continuation(position: Int): Int = if (position < bytes.size) bytes[position].toInt() and 0xFF else -1
        while (index < bytes.size) {
            val first = continuation(index)
            val width = when {
                first <= 0x7F -> 1
                first in 0xC2..0xDF -> 2
                first in 0xE0..0xEF -> 3
                first in 0xF0..0xF4 -> 4
                else -> 0
            }
            if (width == 0 || index + width > bytes.size) throw StrictJsonException("JSON input is not valid UTF-8")
            if (width >= 2) {
                val second = continuation(index + 1)
                val validSecond = when (first) {
                    0xE0 -> second in 0xA0..0xBF
                    0xED -> second in 0x80..0x9F
                    0xF0 -> second in 0x90..0xBF
                    0xF4 -> second in 0x80..0x8F
                    else -> second in 0x80..0xBF
                }
                if (!validSecond) throw StrictJsonException("JSON input is not valid UTF-8")
                for (offset in 2 until width) {
                    if (continuation(index + offset) !in 0x80..0xBF) {
                        throw StrictJsonException("JSON input is not valid UTF-8")
                    }
                }
            }
            index += width
            if (index - checkpointAt >= 16 * 1024) {
                checkpoint("while validating source manifest UTF-8")
                checkpointAt = index
            }
        }
    }

    private fun utf8Length(value: String, checkpoint: (String) -> Unit): Int {
        var bytes = 0
        var index = 0
        var checkpointAt = 0
        while (index < value.length) {
            val character = value[index]
            when {
                character.code <= 0x7F -> { bytes++; index++ }
                character.code <= 0x7FF -> { bytes += 2; index++ }
                Character.isHighSurrogate(character) -> {
                    if (index + 1 >= value.length || !Character.isLowSurrogate(value[index + 1])) {
                        throw StrictJsonException("unpaired high surrogate in JSON string")
                    }
                    bytes += 4
                    index += 2
                }
                Character.isLowSurrogate(character) -> throw StrictJsonException("unpaired low surrogate in JSON string")
                else -> { bytes += 3; index++ }
            }
            if (index - checkpointAt >= 16 * 1024) {
                checkpoint("while counting source manifest string bytes")
                checkpointAt = index
            }
        }
        return bytes
    }

    private fun parseTypedDocument(bytes: ByteArray, factory: JsonFactory, checkpoint: (String) -> Unit): Document {
        try {
            factory.createParser(bytes).use { parser ->
                var tokens = 0
                fun nextToken(): JsonToken? {
                    val token = parser.nextToken()
                    tokens++
                    if (tokens % 256 == 0) checkpoint("while parsing source manifest fields")
                    return token
                }
                if (nextToken() != JsonToken.START_OBJECT) {
                    return Document(null)
                }
                val root = RawRoot()
                while (nextToken() != JsonToken.END_OBJECT) {
                    val name = parser.currentName
                    val token = parser.nextToken() ?: throw StrictJsonException("incomplete JSON object")
                    when (name) {
                        "schemaVersion" -> { root.mark(0); root.schemaVersion = rawScalar(parser, token, ::nextToken) }
                        "profileId" -> { root.mark(1); root.profileId = rawScalar(parser, token, ::nextToken) }
                        "profileSha256" -> { root.mark(2); root.profileSha256 = rawScalar(parser, token, ::nextToken) }
                        "inputSha256" -> { root.mark(3); root.inputSha256 = rawScalar(parser, token, ::nextToken) }
                        "files" -> { root.mark(4); root.files = rawFiles(parser, token, ::nextToken, checkpoint) }
                        "unresolvedEntityIds" -> { root.mark(5); root.unresolvedEntityIds = rawArray(parser, token, ::nextToken, checkpoint) }
                        "unresolvedImplementationIds" -> { root.mark(6); root.unresolvedImplementationIds = rawArray(parser, token, ::nextToken, checkpoint) }
                        else -> { root.unknown = true; skipChildren(parser, token, ::nextToken) }
                    }
                }
                return Document(root)
            }
        } catch (failure: StrictJsonException) {
            throw failure
        } catch (failure: Exception) {
            if (failure is InterruptedException || failure is java.util.concurrent.CancellationException ||
                Thread.currentThread().isInterrupted) throw failure
            throw StrictJsonException("JSON input is invalid", failure)
        }
    }

    private fun rawScalar(parser: JsonParser, token: JsonToken, nextToken: () -> JsonToken?): Any = when (token) {
        JsonToken.VALUE_STRING -> parser.text
        JsonToken.VALUE_NUMBER_INT, JsonToken.VALUE_NUMBER_FLOAT -> RawNumber(parser.text)
        JsonToken.VALUE_TRUE -> true
        JsonToken.VALUE_FALSE -> false
        JsonToken.VALUE_NULL -> RawNull
        JsonToken.START_ARRAY -> { skipChildren(parser, token, nextToken); RawType.ARRAY }
        JsonToken.START_OBJECT -> { skipChildren(parser, token, nextToken); RawType.OBJECT }
        else -> RawType.OTHER
    }

    private fun skipChildren(parser: JsonParser, initial: JsonToken, nextToken: () -> JsonToken?) {
        if (initial != JsonToken.START_ARRAY && initial != JsonToken.START_OBJECT) return
        var depth = 1
        while (depth > 0) {
            when (nextToken() ?: throw StrictJsonException("incomplete JSON value")) {
                JsonToken.START_ARRAY, JsonToken.START_OBJECT -> depth++
                JsonToken.END_ARRAY, JsonToken.END_OBJECT -> depth--
                else -> Unit
            }
        }
    }

    private fun rawArray(
        parser: JsonParser,
        token: JsonToken,
        nextToken: () -> JsonToken?,
        checkpoint: (String) -> Unit,
    ): Any {
        if (token != JsonToken.START_ARRAY) return rawScalar(parser, token, nextToken)
        val values = ArrayList<Any>()
        var count = 0
        while (true) {
            val next = nextToken() ?: throw StrictJsonException("incomplete JSON array")
            if (next == JsonToken.END_ARRAY) return values
            values += rawScalar(parser, next, nextToken)
            count++
            if (count % 256 == 0) checkpoint("while parsing source manifest arrays")
        }
    }

    private fun rawFiles(
        parser: JsonParser,
        token: JsonToken,
        nextToken: () -> JsonToken?,
        checkpoint: (String) -> Unit,
    ): Any {
        if (token != JsonToken.START_ARRAY) return rawScalar(parser, token, nextToken)
        val values = ArrayList<Any>()
        var count = 0
        while (true) {
            val next = nextToken() ?: throw StrictJsonException("incomplete JSON array")
            if (next == JsonToken.END_ARRAY) return values
            values += if (next == JsonToken.START_OBJECT) rawFile(parser, nextToken, checkpoint) else rawScalar(parser, next, nextToken)
            count++
            if (count % 256 == 0) checkpoint("while parsing source manifest files")
        }
    }

    private fun rawFile(parser: JsonParser, nextToken: () -> JsonToken?, checkpoint: (String) -> Unit): RawFile {
        val file = RawFile()
        var fields = 0
        while (nextToken() != JsonToken.END_OBJECT) {
            val name = parser.currentName
            val token = nextToken() ?: throw StrictJsonException("incomplete JSON object")
            when (name) {
                "path" -> { file.mark(0); file.path = rawScalar(parser, token, nextToken) }
                "sha256" -> { file.mark(1); file.sha256 = rawScalar(parser, token, nextToken) }
                "generator" -> { file.mark(2); file.generator = rawScalar(parser, token, nextToken) }
                "promptSha256" -> { file.mark(3); file.promptSha256 = rawScalar(parser, token, nextToken) }
                "acceptedImplementation" -> { file.mark(4); file.acceptedImplementation = rawScalar(parser, token, nextToken) }
                "contentKind" -> { file.mark(5); file.contentKind = rawScalar(parser, token, nextToken) }
                "roles" -> { file.mark(6); file.roles = rawArray(parser, token, nextToken, checkpoint) }
                "entityIds" -> { file.mark(7); file.entityIds = rawArray(parser, token, nextToken, checkpoint) }
                else -> { file.unknown = true; skipChildren(parser, token, nextToken) }
            }
            fields++
            if (fields % 8 == 0) checkpoint("while parsing source manifest file fields")
        }
        return file
    }

    private fun requiredString(value: Any?, name: String): String = value as? String
        ?: throw IllegalArgumentException("source tree manifest $name must be a string")

    private fun rawArray(value: Any?, name: String): List<*> = value as? List<*>
        ?: throw IllegalArgumentException("source tree manifest $name must be an array")

    private fun sortedIds(value: Any?, name: String, checkpoint: (String) -> Unit): List<String> =
        rawArray(value, name).mapIndexed { index, id ->
        if (index % 1024 == 0) checkpoint("while validating source manifest $name")
        require(id is String) { "source tree manifest $name values must be strings" }
        id
    }.also { ids ->
        require(stringsAreStrictlySorted(ids)) { "source tree manifest $name must be unique and sorted" }
    }

    private fun stringsAreStrictlySorted(values: List<String>): Boolean {
        for (index in 1 until values.size) if (values[index - 1] >= values[index]) return false
        return true
    }

    private fun rolesAreStrictlySorted(values: List<ProjectFileRole>): Boolean {
        for (index in 1 until values.size) if (values[index - 1].wireName >= values[index].wireName) return false
        return true
    }

    private fun filesAreStrictlySorted(values: List<GeneratedFileEvidence>): Boolean {
        for (index in 1 until values.size) if (values[index - 1].path >= values[index].path) return false
        return true
    }

    internal class RawRoot {
        private var keyMask = 0
        var unknown = false
        var schemaVersion: Any? = null
        var profileId: Any? = null
        var profileSha256: Any? = null
        var inputSha256: Any? = null
        var files: Any? = null
        var unresolvedEntityIds: Any? = null
        var unresolvedImplementationIds: Any? = null
        fun mark(index: Int) { keyMask = keyMask or (1 shl index) }
        fun keysMatch(expected: Int): Boolean = !unknown && keyMask == (1 shl expected) - 1
    }

    private class RawFile {
        private var keyMask = 0
        var unknown = false
        var path: Any? = null
        var sha256: Any? = null
        var generator: Any? = null
        var promptSha256: Any? = null
        var acceptedImplementation: Any? = null
        var contentKind: Any? = null
        var roles: Any? = null
        var entityIds: Any? = null
        fun mark(index: Int) { keyMask = keyMask or (1 shl index) }
        fun keysMatch(expected: Int): Boolean = !unknown && keyMask == (1 shl expected) - 1
    }

    private data class RawNumber(val text: String)
    private data object RawNull
    private enum class RawType { ARRAY, OBJECT, OTHER }
}
