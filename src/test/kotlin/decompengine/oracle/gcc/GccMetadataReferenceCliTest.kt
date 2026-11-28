package decompengine.oracle.gcc

import decompengine.oracle.core.OracleJson
import decompengine.oracle.reference.ReferenceNativeRuntimeProvisioningEntry
import decompengine.oracle.reference.ReferenceNativeRuntimeStage
import java.io.ByteArrayOutputStream
import java.io.PrintStream
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertIs
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccMetadataReferenceCliTest {
    @Test
    fun `only fixed stage and capture positional interfaces are accepted`() {
        val stage = assertIs<GccMetadataReferenceCli.Command.Stage>(GccMetadataReferenceCli.parseArguments(
            arrayOf("stage", "/profile", "/oci", "/fresh")))
        assertEquals(Path.of("/fresh"), stage.stagingRoot)
        val capture = assertIs<GccMetadataReferenceCli.Command.Capture>(GccMetadataReferenceCli.parseArguments(
            arrayOf("capture", "/profile", "/oci", "/runtime", "/deployment.json", "/journal", "/scratch")))
        assertEquals(Path.of("/deployment.json"), capture.deploymentJson)
        assertEquals(Path.of("/scratch"), capture.scratchMount)
        for (arguments in listOf(emptyArray(), arrayOf("verify"), arrayOf("stage", "/profile", "/oci"),
            arrayOf("stage", "/profile", "/oci", "/fresh", "--allow-untrusted"),
            arrayOf("capture", "/profile", "/oci", "/runtime", "/deployment", "/journal"))) {
            assertFails { GccMetadataReferenceCli.parseArguments(arguments) }
        }
    }

    @Test
    fun `paths reject aliases relative roots and control characters before any side effect`() {
        for (path in listOf(".", "relative", "/", "/a/../b", "/a//b", "/a/", "/a\nb")) {
            assertFails(path) { GccMetadataReferenceCli.parseArguments(arrayOf("stage", path, "/oci", "/fresh")) }
        }
        assertFails { GccMetadataReferenceCli.main(arrayOf("stage", "/unavailable", "/unavailable", "/fresh", "extra")) }
    }

    @Test
    fun `stage emits canonical nonauthoritative provisioning identities without changing ownership`() {
        val stage = ReferenceNativeRuntimeStage(Path.of("/stage"), "projection".encodeToByteArray(), listOf(
            ReferenceNativeRuntimeProvisioningEntry(".", "directory", 0, 0, 493),
            ReferenceNativeRuntimeProvisioningEntry("image/etc/group-file", "regular", 0, 42, 420),
        ))
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes).use { GccMetadataReferenceCli.writeStage(stage, it) }
        val result = OracleJson.parseCanonical(bytes.toByteArray()) as JsonObject
        assertEquals(JsonPrimitive(false), result.getValue("executionAdmitted"))
        assertEquals(JsonPrimitive(stage.identitySha256), result.getValue("stageIdentitySha256"))
        val entries = result.getValue("provisioningEntries") as JsonArray
        assertEquals(JsonPrimitive(42), (entries[1] as JsonObject).getValue("gid"))
        assertEquals(JsonPrimitive("reference-native-runtime-stage-v1"), result.getValue("schemaVersion"))
    }

    @Test
    fun `stage remains canonical utf8 through a non utf8 print stream`() {
        val stage = ReferenceNativeRuntimeStage(Path.of("/단계-é"), "projection".encodeToByteArray(), listOf(
            ReferenceNativeRuntimeProvisioningEntry("image/usr/라이브러리", "directory", 0, 42, 493),
        ))
        val bytes = ByteArrayOutputStream()
        PrintStream(bytes, false, Charsets.UTF_16LE).use { GccMetadataReferenceCli.writeStage(stage, it) }
        val expected = OracleJson.canonicalBytes(JsonObject(mapOf(
            "executionAdmitted" to JsonPrimitive(false),
            "provisioningEntries" to JsonArray(listOf(JsonObject(mapOf(
                "relativePath" to JsonPrimitive("image/usr/라이브러리"), "kind" to JsonPrimitive("directory"),
                "uid" to JsonPrimitive(0), "gid" to JsonPrimitive(42), "mode" to JsonPrimitive(493),
            )))),
            "root" to JsonPrimitive("/단계-é"),
            "schemaVersion" to JsonPrimitive("reference-native-runtime-stage-v1"),
            "stageIdentitySha256" to JsonPrimitive(stage.identitySha256),
        )))
        assertContentEquals(expected, bytes.toByteArray())
        OracleJson.parseCanonical(bytes.toByteArray())
    }
}
