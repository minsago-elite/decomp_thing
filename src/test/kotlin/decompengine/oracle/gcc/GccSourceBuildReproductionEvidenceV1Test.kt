package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlin.test.*
import kotlinx.serialization.json.*

class GccSourceBuildReproductionEvidenceV1Test {
    private fun metadata() = ownershipTestMetadataFiles(ownershipTestProfile())
    private fun inspect(config: JsonObject = buildJsonObject {
        put("Cmd", JsonArray(listOf(JsonPrimitive("bash"))))
        put("Env", JsonArray(listOf(JsonPrimitive("FIXTURE=1"))))
    }): JsonObject {
        val lock = OracleJson.parse(metadata().getValue("reproductionLock")).jsonObject
        val expected = lock.getValue("reproducedImage").jsonObject
        return buildJsonObject {
            put("Id", expected.getValue("imageDigest")); put("Created", expected.getValue("created"))
            put("Architecture", "amd64"); put("Os", "linux"); put("Config", config)
            put("RootFS", buildJsonObject { put("Type", "layers"); put("Layers", expected.getValue("rootfsDiffIds")) })
        }
    }
    private fun compare(root: JsonObject = inspect(), maximumBytes: Int = 131_072, maximumNodes: Int = 10_000) =
        GccSourceBuildReproductionEvidenceV1.compare(ownershipTestProfile(), metadata(),
            OracleJson.canonicalBytes(root), maximumBytes, maximumNodes)

    @Test
    fun `fixed metadata and authored inspect preserve exact components without claiming actual Config evidence`() {
        val result = compare()
        assertEquals(GccSourceBuildOwnershipProfile.ORIGIN_IMAGE, result.recordedOriginImageId)
        assertEquals(GccSourceBuildOwnershipProfile.REPRODUCED_IMAGE, result.observedImageId)
        assertNotEquals(result.recordedOriginImageId, result.observedImageId)
        assertEquals(9, result.rootfsDiffIds.size)
        // Actual 807f Config bytes are not retained here. Never rewrite the checked lock to
        // turn this authored Config into a claimed approved-description positive.
        assertEquals(listOf("config-digest"), result.mismatches)
        assertFalse(result.descriptionMatches)
        assertEquals("untrusted-supplied-reproduction-comparison-v1", result.evidenceKind)
        assertFalse(result.approved); assertFalse(result.sourceAuthenticated)
        assertFalse(result.runtimeAuthenticated); assertFalse(result.captureAuthenticated)
        assertFalse(result.ownershipComplete)
        assertTrue("authenticated-live-runtime-bridge" in result.missingEvidence)
    }

    @Test
    fun `historical Config compact encoding matches independently calculated Python vectors`() {
        val config = inspect().getValue("Config").jsonObject
        val encoded = reproductionConfigCanonicalBytes(config, 131_072)
        assertEquals("{\"Cmd\":[\"bash\"],\"Env\":[\"FIXTURE=1\"]}", encoded.decodeToString())
        assertEquals("7306e05f6e43677724ab2f17527817396e7e97ade74085ad0b326e428a775744", OracleArtifacts.sha256(encoded))
        val vector = buildJsonObject {
            put("\ue000", "é"); put("😀", "\u007f")
            put("a", JsonArray(listOf(JsonPrimitive("\b\u000c\n\r\t\"\\"), JsonPrimitive(true),
                JsonPrimitive(false), JsonNull, JsonPrimitive(-1))))
        }
        assertEquals("{\"a\":[\"\\b\\f\\n\\r\\t\\\"\\\\\",true,false,null,-1],\"\\ue000\":\"\\u00e9\",\"\\ud83d\\ude00\":\"\\u007f\"}",
            reproductionConfigCanonicalBytes(vector, 131_072).decodeToString())
        assertEquals("{}", reproductionConfigCanonicalBytes(JsonObject(emptyMap()), 2).decodeToString())
        assertFailsWith<GccSourceBuildOwnershipException> { reproductionConfigCanonicalBytes(JsonObject(emptyMap()), 1) }
    }

    @Test
    fun `every supplied identity platform creation config and ordered layer change remains a mismatch`() {
        val root = inspect()
        for ((field, value, reason) in listOf(
            Triple("Id", "sha256:" + "a".repeat(64), "image-id"),
            Triple("Architecture", "arm64", "platform"), Triple("Os", "other", "platform"),
            Triple("Created", "2026-08-08T00:00:00Z", "created"),
        )) assertTrue(reason in compare(ownershipChanged(root, field, JsonPrimitive(value))).mismatches)
        val rootfs = root.getValue("RootFS").jsonObject
        val layers = rootfs.getValue("Layers").jsonArray
        for (changed in listOf(layers.reversed(), layers.dropLast(1), listOf(JsonPrimitive("sha256:" + "b".repeat(64))) + layers.drop(1))) {
            val result = compare(ownershipChanged(root, "RootFS", ownershipChanged(rootfs, "Layers", JsonArray(changed))))
            assertTrue("ordered-rootfs-layers" in result.mismatches)
            assertFalse(result.descriptionMatches); assertFalse(result.runtimeAuthenticated)
        }
        assertNotEquals(compare().configSha256, compare(inspect(buildJsonObject { put("User", "nobody") })).configSha256)
    }

    @Test
    fun `all frozen metadata including recipe platform epoch and Config commitment refuse replacement`() {
        val profile = ownershipTestProfile()
        for ((role, bytes) in metadata()) {
            val changed = metadata().toMutableMap(); changed[role] = bytes + byteArrayOf(32)
            assertFailsWith<GccSourceBuildOwnershipException> {
                GccSourceBuildReproductionEvidenceV1.compare(profile, changed, OracleJson.canonicalBytes(inspect()))
            }
        }
        val files = metadata()
        for ((role, before, after) in listOf(
            Triple("recipe", "FROM gcc@", "FROM bad@"),
            Triple("buildRecord", "1786060800", "1786060801"),
            Triple("reproductionLock", "linux/amd64", "linux/arm64"),
            Triple("reproductionLock", "a37cfb8b", "b37cfb8b"),
        )) {
            val changed = files.getValue(role).decodeToString().replace(before, after).toByteArray()
            assertFalse(changed.contentEquals(files.getValue(role)))
            assertFailsWith<GccSourceBuildOwnershipException> {
                GccSourceBuildReproductionEvidenceV1.compare(profile, files + (role to changed), OracleJson.canonicalBytes(inspect()))
            }
        }
    }

    @Test
    fun `closed inspect and rootfs reject missing extra wrong typed and authority fields`() {
        val root = inspect()
        for (key in root.keys) assertFailsWith<GccSourceBuildOwnershipException> { compare(JsonObject(root - key)) }
        for (value in listOf(JsonPrimitive(true), JsonPrimitive(false))) {
            assertFailsWith<GccSourceBuildOwnershipException> { compare(ownershipChanged(root, "runtimeAuthenticated", value)) }
        }
        val fs = root.getValue("RootFS").jsonObject
        for (changed in listOf(JsonObject(fs - "Type"), ownershipChanged(fs, "Type", JsonPrimitive("other")),
            ownershipChanged(fs, "unchecked", JsonNull), ownershipChanged(fs, "Layers", JsonPrimitive("bad")))) {
            assertFailsWith<GccSourceBuildOwnershipException> { compare(ownershipChanged(root, "RootFS", changed)) }
        }
        val layer = fs.getValue("Layers").jsonArray.first()
        for (bad in listOf(JsonArray(List(10) { layer }), JsonArray(List(9) { layer }), JsonArray(listOf(JsonPrimitive("latest"))))) {
            assertFailsWith<GccSourceBuildOwnershipException> { compare(ownershipChanged(root, "RootFS", ownershipChanged(fs, "Layers", bad))) }
        }
        assertFailsWith<GccSourceBuildOwnershipException> { compare(ownershipChanged(root, "Config", JsonNull)) }
    }

    @Test
    fun `strict nested decoded duplicate malformed UTF8 and unsupported scalars refuse without supplied text`() {
        val profile = ownershipTestProfile(); val files = metadata()
        val raw = OracleJson.canonicalBytes(inspect()).decodeToString()
        val canary = "PRIVATE_REPRODUCTION_CANARY"
        val cases = listOf(
            "[]".toByteArray(), (raw.dropLast(2) + ",\"Id\":\"$canary\"}").toByteArray(),
            raw.replace("\"Cmd\":", "\"Cmd\":[],\"C\\u006dd\":").toByteArray(),
            byteArrayOf(0xc3.toByte(), 0x28), raw.replace("\"bash\"", "1.25").toByteArray(),
            raw.replace("\"bash\"", "1e2").toByteArray(),
        )
        for (bad in cases) {
            val failure = assertFailsWith<GccSourceBuildOwnershipException> {
                GccSourceBuildReproductionEvidenceV1.compare(profile, files, bad)
            }
            assertFalse(failure.toString().contains(canary)); assertNull(failure.cause)
        }
    }

    @Test
    fun `byte node depth and canonical expansion guards admit exact bounds and refuse one over`() {
        val bytes = OracleJson.canonicalBytes(inspect())
        compare(maximumBytes = bytes.size)
        assertFailsWith<GccSourceBuildOwnershipException> { compare(maximumBytes = bytes.size - 1) }
        for ((b, n) in listOf(131_073 to 10_000, 131_072 to 10_001, 0 to 10_000, 131_072 to 0)) {
            assertFailsWith<GccSourceBuildOwnershipException> { compare(maximumBytes = b, maximumNodes = n) }
        }
        fun nodes(value: JsonElement): Int = 1 + when (value) {
            is JsonObject -> value.values.sumOf(::nodes); is JsonArray -> value.sumOf(::nodes); else -> 0
        }
        val count = nodes(inspect()); compare(maximumNodes = count)
        assertFailsWith<GccSourceBuildOwnershipException> { compare(maximumNodes = count - 1) }
        val nested = "[".repeat(33) + "0" + "]".repeat(33)
        val raw = bytes.decodeToString().replace("\"bash\"", nested).toByteArray()
        assertFailsWith<GccSourceBuildOwnershipException> {
            GccSourceBuildReproductionEvidenceV1.compare(ownershipTestProfile(), metadata(), raw)
        }
        val expansion = inspect(buildJsonObject { put("User", "é".repeat(1000)) })
        val compact = OracleJson.canonicalBytes(expansion)
        assertFailsWith<GccSourceBuildOwnershipException> {
            GccSourceBuildReproductionEvidenceV1.compare(ownershipTestProfile(), metadata(), compact, compact.size)
        }
    }

    @Test
    fun `input and output snapshots and comparison lists cannot be rewritten by callers`() {
        val profile = ownershipTestProfile(); val files = metadata(); val raw = OracleJson.canonicalBytes(inspect())
        val result = GccSourceBuildReproductionEvidenceV1.compare(profile, files, raw)
        val canonical = result.configCanonicalBytes(); val commitment = result.inspectSha256
        files.values.forEach { it.fill(0) }; raw.fill(0); result.configCanonicalBytes().fill(0)
        assertContentEquals(canonical, result.configCanonicalBytes()); assertEquals(commitment, result.inspectSha256)
        assertFailsWith<UnsupportedOperationException> { (result.mismatches as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (result.rootfsDiffIds as MutableList).clear() }
        assertFailsWith<UnsupportedOperationException> { (result.missingEvidence as MutableList).clear() }
    }
}
