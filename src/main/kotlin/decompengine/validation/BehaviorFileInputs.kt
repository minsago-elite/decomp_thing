package decompengine.validation

import decompengine.repair.readStableRegularFile
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.nio.file.Path

internal const val MAXIMUM_BEHAVIOR_FILE_BYTES = 8L * 1024 * 1024
internal const val MAXIMUM_BEHAVIOR_INPUT_FILES = 1024

internal fun requireBehaviorFileNames(names: Collection<String>) {
    require(names.size <= MAXIMUM_BEHAVIOR_INPUT_FILES) { "behavior input file count exceeds its bound" }
    val paths = names.toSet()
    for (name in names) {
        val parts = name.split('/')
        require(name.length in 1..256 && '\\' !in name && '\u0000' !in name && parts.size <= 16 &&
            parts.none { it in setOf("", ".", "..") }) { "behavior input name must be a bounded relative path" }
        require((1 until parts.size).none { parts.take(it).joinToString("/") in paths }) {
            "behavior input file names conflict with parent directories"
        }
    }
}

internal fun captureBehaviorFileInputs(inputs: Map<String, Map<String, Path>>, capture: BehaviorEvidenceCapture): Map<String, JsonArray> {
    require(inputs.values.sumOf { it.size.toLong() } <= MAXIMUM_BEHAVIOR_INPUT_FILES) { "behavior input file count exceeds its bound" }
    var totalBytes = 0L
    return inputs.mapValues { (_, files) ->
        requireBehaviorFileNames(files.keys)
        JsonArray(files.toSortedMap().map { (name, path) ->
            val absolute = path.toAbsolutePath().normalize()
            val snapshot = readStableRegularFile(absolute.parent, absolute.fileName.toString(), maxOf(1, MAXIMUM_BEHAVIOR_FILE_BYTES - totalBytes))
            totalBytes = Math.addExact(totalBytes, snapshot.bytes.size.toLong())
            require(totalBytes <= MAXIMUM_BEHAVIOR_FILE_BYTES) { "behavior file corpus exceeds its byte bound" }
            val identity = capture.file(absolute)
            require(identity.string("sha256") == snapshot.sha256) { "behavior input file changed during capture" }
            JsonObject(identity + mapOf(
                "name" to JsonPrimitive(name),
                "sourcePath" to JsonPrimitive(absolute.toString()),
                "contentHex" to JsonPrimitive(java.util.HexFormat.of().formatHex(snapshot.bytes)),
            ))
        })
    }
}
