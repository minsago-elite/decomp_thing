package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccSourceBuildOwnershipInputsTest {
    @Test
    fun `exact historical metadata remains observation without source runtime or binary proof`() {
        val profile = ownershipTestProfile()
        val supplied = ownershipTestMetadataFiles(profile)
        val first = GccSourceBuildOwnershipInputs.observe(profile, supplied)
        supplied.values.forEach { it.fill(0) }
        val second = ownershipTestMetadata(profile)
        assertContentEquals(first.canonicalBytes(), second.canonicalBytes())
        assertEquals("78d4ac73dd391005b895a6148cd9831e28e1208b", first.sourceRevision)
        assertEquals(107_200_820L, first.sourceArchiveBytes)
        assertEquals("e6738e29597f733270731aa90600f37ffdc045079dfc27ec7e8192cc81085c3e", first.sourceArchiveSha256)
        assertEquals("sha256:510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248", first.recordedOriginImageId)
        assertEquals("sha256:807f16e03368e1e0ff3c904f21f1a13c260d78a8b7226a52284a2ee68a4d1511", first.proposedReproducedImageId)
        assertFalse(first.sourceAuthenticated)
        assertFalse(first.runtimeAuthenticated)
        assertFalse(first.captureAuthenticated)
        assertFalse(first.ownershipComplete)
        val encoded = first.canonicalBytes()
        encoded.fill(0)
        assertContentEquals(second.canonicalBytes(), first.canonicalBytes())
    }

    @Test
    fun `each metadata input requires exact bytes and complete explicit population`() {
        val profile = ownershipTestProfile()
        val files = ownershipTestMetadataFiles(profile)
        for (key in files.keys) {
            val changed = files.toMutableMap()
            changed[key] = files.getValue(key) + byteArrayOf(10)
            assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipInputs.observe(profile, changed) }
            assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipInputs.observe(profile, files - key) }
        }
        assertFailsWith<GccSourceBuildOwnershipException> {
            GccSourceBuildOwnershipInputs.observe(profile, files + ("claimedArchive" to byteArrayOf(1)))
        }
    }

    @Test
    fun `rehashing a self consistent altered metadata pin cannot change the historical generation`() {
        val root = OracleJson.parse(ownershipTestProfileBytes()) as JsonObject
        val pins = root.getValue("metadataPins") as JsonObject
        val sourcePin = pins.getValue("sourceLock") as JsonObject
        val changed = ownershipChanged(root, "metadataPins", ownershipChanged(pins, "sourceLock",
            ownershipChanged(sourcePin, "sha256", JsonPrimitive("a".repeat(64)))))
        assertFailsWith<GccSourceBuildOwnershipException> {
            GccSourceBuildOwnershipProfile.load(OracleJson.canonicalBytes(changed))
        }
    }

    @Test
    fun `per metadata and aggregate byte guards admit exact boundary and reject one over`() {
        val profile = ownershipTestProfile()
        val files = ownershipTestMetadataFiles(profile)
        val max = files.values.maxOf { it.size }
        val total = files.values.sumOf { it.size }
        GccSourceBuildOwnershipInputs.observe(profile, files, max, total)
        assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipInputs.observe(profile, files, max - 1, total) }
        assertFailsWith<GccSourceBuildOwnershipException> { GccSourceBuildOwnershipInputs.observe(profile, files, max, total - 1) }
    }
}

internal fun ownershipTestProfileBytes(): ByteArray = Files.readAllBytes(Path.of("oracle/gcc/16.2.0/source-build-ownership-profile-v1.json"))
internal fun ownershipTestProfile(): GccSourceBuildOwnershipProfile = GccSourceBuildOwnershipProfile.load(ownershipTestProfileBytes())
internal fun ownershipTestMetadataFiles(profile: GccSourceBuildOwnershipProfile): Map<String, ByteArray> =
    profile.metadataPins.mapValues { (_, pin) -> Files.readAllBytes(Path.of(pin.path)) }
internal fun ownershipTestMetadata(profile: GccSourceBuildOwnershipProfile): GccSourceBuildOwnershipInputs =
    GccSourceBuildOwnershipInputs.observe(profile, ownershipTestMetadataFiles(profile))
internal fun ownershipChanged(root: JsonObject, key: String, value: kotlinx.serialization.json.JsonElement): JsonObject =
    JsonObject(root + (key to value))
