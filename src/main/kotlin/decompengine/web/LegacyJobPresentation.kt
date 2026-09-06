package decompengine.web

import decompengine.jobs.Job
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Legacy wire names and numeric types, deliberately independent of persistence serializers. */
internal fun legacyJobPresentation(job: Job): JsonObject = buildJsonObject {
    put("id", job.id)
    put("filename", job.filename)
    put("status", job.status)
    put("created_at", job.createdAt)
    put("updated_at", job.updatedAt)
    put("size_bytes", job.sizeBytes)
    // Paths and diagnostic text are private storage data, not public job fields.
    put("metadata", buildJsonObject {
        val metadata = job.metadata
        put("format", metadata.format)
        put("endianness", metadata.endianness)
        put("elf_version", metadata.elfVersion.toLong())
        put("os_abi", metadata.osAbi)
        put("object_type", metadata.objectType)
        put("machine", metadata.machine)
        put("entry_point", metadata.entryPoint.toLong())
        put("elf_header_size", metadata.elfHeaderSize.toInt())
        put("program_header_count", metadata.programHeaderCount.toInt())
        put("section_header_count", metadata.sectionHeaderCount.toInt())
        put("section_name_table_index", metadata.sectionNameTableIndex.toInt())
    })
}
