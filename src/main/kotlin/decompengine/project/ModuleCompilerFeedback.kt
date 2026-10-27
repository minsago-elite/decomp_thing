package decompengine.project

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardCopyOption.REPLACE_EXISTING
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.*

/** Informational compiler output only; it cannot authorize a candidate or replace compiler validation. */
data class ModuleCompilerFeedback(
    val moduleId: String,
    val sourceSha256: String,
    val contextSha256: String,
    val diagnosticsSha256: String,
    val diagnostics: String,
    val restoredSourceSha256: String? = null,
)

internal class ModuleCompilerFeedbackStore(
    private val root: Path,
    private val inputSha256: String,
    private val profileSha256: String,
) {
    fun read(moduleId: String): ModuleCompilerFeedback? {
        require(MODULE.matches(moduleId))
        val directory = root.resolve(DIRECTORY)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) return null
        require(Files.isDirectory(directory, NOFOLLOW_LINKS))
        val file = directory.resolve("$moduleId.json")
        if (!Files.exists(file, NOFOLLOW_LINKS)) return null
        require(Files.isRegularFile(file, NOFOLLOW_LINKS))
        val bytes = Files.newInputStream(file, READ, NOFOLLOW_LINKS).use { it.readNBytes(65_537) }
        val value = OracleJson.parse(bytes, StrictJsonLimits(maximumInputBytes = 65_536)).jsonObject
        require(value.keys - "restoredSourceSha256" == setOf("schemaVersion", "inputSha256", "profileSha256", "moduleId", "sourceSha256", "contextSha256", "diagnosticsSha256", "diagnostics"))
        require(value["schemaVersion"] == JsonPrimitive(1))
        if (value.getValue("inputSha256").jsonPrimitive.content != inputSha256 ||
            value.getValue("profileSha256").jsonPrimitive.content != profileSha256) return null
        require(value.getValue("moduleId").jsonPrimitive.content == moduleId)
        fun hash(name: String) = value.getValue(name).jsonPrimitive.content.also { require(HASH.matches(it)) }
        val diagnostics = value.getValue("diagnostics").jsonPrimitive.content
        require(diagnostics.toByteArray(Charsets.UTF_8).size <= 32_768)
        return ModuleCompilerFeedback(moduleId, hash("sourceSha256"), hash("contextSha256"), hash("diagnosticsSha256"), diagnostics,
            value["restoredSourceSha256"]?.let { hash("restoredSourceSha256") })
    }

    fun write(feedback: ModuleCompilerFeedback) {
        require(MODULE.matches(feedback.moduleId))
        require(listOf(feedback.sourceSha256, feedback.contextSha256, feedback.diagnosticsSha256).all(HASH::matches))
        require(feedback.restoredSourceSha256 == null || HASH.matches(feedback.restoredSourceSha256))
        require(feedback.diagnostics.toByteArray(Charsets.UTF_8).size <= 32_768)
        val directory = root.resolve(DIRECTORY)
        if (!Files.exists(directory, NOFOLLOW_LINKS)) Files.createDirectory(directory,
            PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        require(Files.isDirectory(directory, NOFOLLOW_LINKS))
        val file = directory.resolve("${feedback.moduleId}.json")
        require(!Files.isSymbolicLink(file))
        val value = buildJsonObject {
            put("schemaVersion", 1); put("inputSha256", inputSha256); put("profileSha256", profileSha256)
            put("moduleId", feedback.moduleId); put("sourceSha256", feedback.sourceSha256)
            put("contextSha256", feedback.contextSha256); put("diagnosticsSha256", feedback.diagnosticsSha256)
            put("diagnostics", feedback.diagnostics)
            feedback.restoredSourceSha256?.let { put("restoredSourceSha256", it) }
        }.toString().toByteArray(Charsets.UTF_8)
        require(value.size <= 65_536)
        val temporary = Files.createTempFile(directory, ".feedback-", ".tmp")
        try {
            FileChannel.open(temporary, WRITE, NOFOLLOW_LINKS).use { channel ->
                val bytes = ByteBuffer.wrap(value)
                while (bytes.hasRemaining()) channel.write(bytes)
                channel.force(true)
            }
            Files.move(temporary, file, ATOMIC_MOVE, REPLACE_EXISTING)
            FileChannel.open(directory, READ).use { it.force(true) }
        } finally { Files.deleteIfExists(temporary) }
    }

    companion object {
        const val DIRECTORY = ".compiler-feedback"
        private val MODULE = Regex("[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}")
        private val HASH = Regex("[0-9a-f]{64}")
    }
}
