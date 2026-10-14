package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccSourceBuildOwnershipProfileTest {
    @Test
    fun `profile and schema catalog are proposed closed metadata with immutable snapshots`() {
        val bytes = ownershipTestProfileBytes()
        val profile = GccSourceBuildOwnershipProfile.load(bytes)
        bytes.fill(0)
        assertFalse(profile.approved)
        assertFalse(profile.productionVerified)
        assertEquals(10, profile.mandatoryGates.size)
        assertTrue("hidden-source-oracle-isolation" in profile.mandatoryGates)
        assertEquals(5, profile.metadataPins.size)
        assertEquals(8_388_608L, profile.resourceCeilings.getValue("maximumRecordBytes"))
        assertEquals(OracleArtifacts.sha256(profile.canonicalBytes()), profile.canonicalSha256)
        assertEquals(64, OracleSchemas.identity(GccSourceBuildOwnershipProfile.SCHEMA).sha256.length)
        assertEquals(64, OracleSchemas.identity(GccSourceBuildOwnershipActionReceipt.SCHEMA).sha256.length)
        assertFailsWith<UnsupportedOperationException> { (profile.mandatoryGates as MutableList<String>).clear() }
        assertFailsWith<UnsupportedOperationException> { (profile.metadataPins as MutableMap<String, GccSourceBuildMetadataPin>).clear() }
        assertFailsWith<UnsupportedOperationException> { (profile.resourceCeilings as MutableMap<String, Long>).clear() }
        val encoded = profile.canonicalBytes()
        encoded.fill(0)
        assertContentEquals(ownershipTestProfile().canonicalBytes(), profile.canonicalBytes())
    }

    @Test
    fun `every authority flag and mandatory gate rejects self promotion`() {
        val root = OracleJson.parse(ownershipTestProfileBytes()) as JsonObject
        val authority = root.getValue("authority") as JsonObject
        for (key in authority.keys) refused(ownershipChanged(root, "authority", ownershipChanged(authority, key, JsonPrimitive(true))))
        val gates = root.getValue("mandatoryGates") as JsonArray
        for (index in gates.indices) refused(ownershipChanged(root, "mandatoryGates", JsonArray(gates.filterIndexed { i, _ -> i != index })))
        refused(ownershipChanged(root, "status", JsonPrimitive("approved")))
        val q = root.getValue("qualification") as JsonObject
        refused(ownershipChanged(root, "qualification", ownershipChanged(q, "actualCapturedBuilds", JsonPrimitive(3))))
        refused(ownershipChanged(root, "qualification", ownershipChanged(q, "independentEvidenceReplays", JsonPrimitive(1))))
    }

    @Test
    fun `unknown missing duplicate invalid UTF8 and changed proposed resource policy refuse`() {
        val root = OracleJson.parse(ownershipTestProfileBytes()) as JsonObject
        refused(JsonObject(root - "sourceRevision"))
        refused(ownershipChanged(root, "producerSuppliedApproval", JsonPrimitive(true)))
        val ceiling = root.getValue("resourceCeilings") as JsonObject
        refused(ownershipChanged(root, "resourceCeilings", ownershipChanged(ceiling, "maximumShards", JsonPrimitive(257))))
        val runtime = root.getValue("runtimePolicy") as JsonObject
        refused(ownershipChanged(root, "runtimePolicy", ownershipChanged(runtime, "recordedOriginImageId",
            runtime.getValue("proposedReproducedImageId"))))
        assertFailsWith<GccSourceBuildOwnershipException> {
            GccSourceBuildOwnershipProfile.load("{\"schemaVersion\":1,\"schemaVersion\":1}".toByteArray())
        }
        assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipProfile.load(byteArrayOf(0xc3.toByte(), 0x28)) }
    }

    @Test
    fun `profile byte limit is enforced before parsing and no larger caller ceiling is accepted`() {
        val bytes = ownershipTestProfileBytes()
        GccSourceBuildOwnershipProfile.load(bytes, bytes.size)
        assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipProfile.load(bytes, bytes.size - 1) }
        assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipProfile.load(bytes, 65_537) }
    }

    private fun refused(root: JsonObject) {
        assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipProfile.load(OracleJson.canonicalBytes(root)) }
    }
}
