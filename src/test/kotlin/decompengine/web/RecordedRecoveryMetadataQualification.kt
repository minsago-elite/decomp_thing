package decompengine.web

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionProfile
import decompengine.project.RecordedRecoverySummaryV1
import decompengine.repair.readStableRegularFile
import java.nio.file.Path
import kotlinx.serialization.json.*
import kotlin.test.*

/** Installed qualification through the active metadata reader, with a closed read allowlist. */
internal fun qualifyRecordedRecoveryMetadata(project: Path, inputBinary: Path, profile: ReconstructionProfile,
    expectedSummary: RecordedRecoverySummaryV1): JsonObject {
    val maximum = WebSourceCatalogEvidence.MAXIMUM_MANIFEST_BYTES
    val descriptorPath = "reports/build_contract.json"
    val allowed = setOf("source_tree_manifest.json", descriptorPath,
        profile.layout.declaration("module-plan-evidence").materialize(),
        profile.layout.declaration("confidence-evidence").materialize())
    val reads = mutableMapOf<String, Int>()
    fun artifact(relative: String, limit: Long): decompengine.repair.StableRegularFile {
        assertTrue(relative in allowed, "Metadata requested a model, source, overlay or private receipt")
        assertEquals(maximum, limit)
        reads[relative] = (reads[relative] ?: 0) + 1
        return readStableRegularFile(project, relative, limit)
    }
    val descriptor = OracleJson.parse(artifact(descriptorPath, maximum).bytes,
        StrictJsonLimits(maximumInputBytes = maximum.toInt(), maximumCanonicalBytes = maximum.toInt(),
            maximumDepth = 32, maximumNodes = 1_000_000, maximumStringBytes = 16 * 1024,
            maximumTotalStringBytes = maximum.toInt())).jsonObject
    val reference = WebRevisionSourceReference("a".repeat(32), "qualification", "recorded_revision",
        descriptor.getValue("sourceRevisionSha256").jsonPrimitive.content, "retained_qualification")
    val prefix = "reports/runs/${reference.runId}/source-tree/"
    val input = inputBinary.toAbsolutePath().normalize()
    val evidence = WebSourceCatalogEvidence(listOf(profile), { job ->
        assertEquals(reference.jobId, job)
        readStableRegularFile(input.parent, input.fileName.toString(), 512L * 1024 * 1024)
    }, { job, path, limit ->
        assertEquals(reference.jobId, job); assertTrue(path.startsWith(prefix))
        artifact(path.removePrefix(prefix), limit)
    })
    val snapshot = evidence.readRevision(reference)
    val index = snapshot.files.indexOfFirst { ProjectFileRole.MODULE_IMPLEMENTATION in it.evidence.roles }
    assertTrue(index >= 0, "Installed reconstruction did not publish a module source commitment")
    val fileId = revisionSourceFileId(reference, index, snapshot.files[index].evidence.path)
    val metadata = WebRevisionFileMetadata { job, run, revision, selectedFile ->
        assertEquals(reference.jobId, job); assertEquals(reference.runId, run); assertEquals(reference.revisionId, revision)
        assertEquals(fileId, selectedFile)
        evidence.readFileMetadata(reference, selectedFile)
    }.read(reference.jobId, reference.runId, reference.revisionId, fileId)
    assertEquals("source-input-commitments", metadata.getValue("authority").jsonPrimitive.content)
    assertEquals("not-performed", metadata.getValue("contentVerification").jsonPrimitive.content)
    val recovery = metadata.getValue("recordedRecovery").jsonObject
    assertEquals("recorded", recovery.getValue("state").jsonPrimitive.content)
    assertEquals("recorded-origin-unverified", recovery.getValue("origin").jsonPrimitive.content)
    assertEquals(expectedSummary.toJsonObject(), recovery.getValue("summary"))
    assertTrue(reads.keys.all { it in allowed })
    assertTrue(reads.getValue("source_tree_manifest.json") >= 4 && reads.getValue(descriptorPath) >= 5)
    if (metadata["recordedModule"] != JsonNull) {
        assertTrue(reads.getValue(profile.layout.declaration("module-plan-evidence").materialize()) >= 2)
        assertTrue(reads.getValue(profile.layout.declaration("confidence-evidence").materialize()) >= 2)
    } else assertEquals("metadata-byte-limit", metadata.getValue("recordedModuleUnavailableReason").jsonPrimitive.content)
    assertFalse(metadata.toString().contains("productionVerified"))
    return metadata
}
