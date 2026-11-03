package decompengine.project

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Base64
import java.util.UUID
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Bounded, failure-only evidence for hosted contained-module qualification failures. */
internal object ContainedModuleQualificationFailureEvidence {
    private const val MAX_FILES = 160
    private const val MAX_FILE_BYTES = 4 * 1024 * 1024
    private const val MAX_TOTAL_BYTES = 24 * 1024 * 1024
    private const val MAX_DIAGNOSTIC_BYTES = 8 * 1024 * 1024

    fun retain(label: String, project: Path, diagnostics: List<Pair<ByteArray, ByteArray>>): Path {
        require(label.matches(Regex("[a-z0-9-]{1,64}")))
        require(diagnostics.size <= 128 && diagnostics.sumOf { it.first.size.toLong() + it.second.size } <= MAX_DIAGNOSTIC_BYTES) {
            "authenticated compiler diagnostics exceed qualification retention bounds"
        }
        val base = Path.of("build/reports/contained-module-compilation-live/failure-diagnostics")
            .toAbsolutePath().normalize()
        Files.createDirectories(base)
        val destination = Files.createDirectory(base.resolve("$label-${UUID.randomUUID()}"))
        var total = 0L
        val retained = mutableListOf<JsonObject>()
        val candidates = buildList {
            add(project.resolve("source_tree_manifest.json"))
            add(project.resolve("reports/archival_audit.json"))
            add(project.resolve("reports/module_plan.json"))
            val moduleReports = project.resolve("reports/modules")
            if (Files.isDirectory(moduleReports, LinkOption.NOFOLLOW_LINKS)) {
                Files.newDirectoryStream(moduleReports, "*.json").use { stream ->
                    stream.toList().sortedBy { it.fileName.toString() }.forEach(::add)
                }
            }
        }.distinct().take(MAX_FILES).sortedBy { project.relativize(it).toString() }
        for (source in candidates) {
            if (!source.normalize().startsWith(project.normalize()) ||
                !Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS) || Files.isSymbolicLink(source)) continue
            val size = Files.size(source)
            if (size !in 0..MAX_FILE_BYTES.toLong() || total + size > MAX_TOTAL_BYTES) continue
            val bytes = Files.readAllBytes(source)
            if (bytes.size.toLong() != size) continue
            val relative = project.relativize(source).toString().replace('\\', '/')
            val target = destination.resolve("project").resolve(relative).normalize()
            require(target.startsWith(destination.resolve("project")))
            Files.createDirectories(target.parent)
            Files.write(target, bytes)
            retained += JsonObject(mapOf(
                "path" to JsonPrimitive(relative), "bytes" to JsonPrimitive(bytes.size),
                "sha256" to JsonPrimitive(sha256(bytes)),
            ))
            total += size
        }
        val compiler = diagnostics.mapIndexed { index, (stdout, stderr) ->
            fun stream(prefix: String, bytes: ByteArray) = mapOf(
                "${prefix}Bytes" to JsonPrimitive(bytes.size),
                "${prefix}Sha256" to JsonPrimitive(sha256(bytes)),
                "${prefix}Base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes)),
            )
            JsonObject(mapOf("sequence" to JsonPrimitive(index)) + stream("stdout", stdout) + stream("stderr", stderr))
        }
        val inventory = JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "label" to JsonPrimitive(label),
            "projectFiles" to JsonArray(retained), "projectBytes" to JsonPrimitive(total),
            "compilerDiagnostics" to JsonArray(compiler),
        ))
        Files.write(destination.resolve("evidence.json"), OracleJson.canonicalBytes(inventory))
        return destination
    }
}
