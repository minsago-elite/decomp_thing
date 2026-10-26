package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.util.jar.JarFile

/** Independent commitment for the typed Ghidra data sidecar source and compiled helper. */
internal data class GccBundledGlobalTypeRuntimeIdentityV1(
    val sourceBytes: Long,
    val sourceSha256: String,
    val classBytes: Long,
    val classSha256: String,
) {
    init {
        require(sourceBytes in 1..4L * 1024 * 1024 && classBytes in 1..4L * 1024 * 1024)
        require(listOf(sourceSha256, classSha256).all { it.matches(Regex("[a-f0-9]{64}")) })
    }

    fun toJson(): JsonObject {
        val unsigned = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive(PROVIDER),
            "sourceBytes" to JsonPrimitive(sourceBytes),
            "sourceSha256" to JsonPrimitive(sourceSha256),
            "classBytes" to JsonPrimitive(classBytes),
            "classSha256" to JsonPrimitive(classSha256),
        ))
        return JsonObject(unsigned + ("closureSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)))))
    }

    fun requireBridgeClass(jar: JarFile) {
        val entries = jar.entries().asSequence().take(200_001).toList()
        require(entries.size <= 200_000) { "global/type bridge JAR exceeds its entry bound" }
        val entry = entries.singleOrNull { it.name == CLASS_PATH }
        require(entry != null && !entry.isDirectory && entry.size == classBytes) {
            "bridge JAR has no exact unique global/type collector class"
        }
        val bytes = jar.getInputStream(entry).use { it.readNBytes(4 * 1024 * 1024 + 1) }
        require(bytes.size.toLong() == classBytes && OracleArtifacts.sha256(bytes) == classSha256) {
            "global/type collector class differs from its deployment profile"
        }
    }

    fun requireNoLooseCollectorClass(entries: Map<String, GccBundledGhidraReferenceEntry>) {
        require(entries.keys.none { path ->
            val name = path.substringAfterLast('/')
            name == CLASS_PATH || name.startsWith("ExportGlobalTypeObservationsV1$") && name.endsWith(".class")
        }) { "global/type collector class must be owned only by the authenticated bridge JAR" }
    }

    companion object {
        const val PROVIDER = "gcc-bundled-global-type-runtime-identity-v1"
        const val SOURCE_RESOURCE = "/ghidra_scripts/ExportGlobalTypeObservationsV1.java"
        const val CLASS_PATH = "ExportGlobalTypeObservationsV1.class"

        fun parse(value: JsonObject): GccBundledGlobalTypeRuntimeIdentityV1 {
            require(value.keys == setOf("schemaVersion", "provider", "sourceBytes", "sourceSha256", "classBytes", "classSha256", "closureSha256"))
            require(value.number("schemaVersion") == 1L && value.string("provider") == PROVIDER)
            val identity = GccBundledGlobalTypeRuntimeIdentityV1(value.number("sourceBytes"), value.string("sourceSha256"),
                value.number("classBytes"), value.string("classSha256"))
            require(value.string("closureSha256") == identity.toJson().string("closureSha256")) {
                "global/type runtime identity commitment is invalid"
            }
            return identity
        }
    }
}

private fun JsonObject.string(name: String): String = (this[name] as? JsonPrimitive)?.takeIf { it.isString }?.content
    ?: throw IllegalArgumentException("global/type runtime $name must be a string")
private fun JsonObject.number(name: String): Long = (this[name] as? JsonPrimitive)?.takeIf { !it.isString }?.content?.toLongOrNull()
    ?: throw IllegalArgumentException("global/type runtime $name must be an integer")
