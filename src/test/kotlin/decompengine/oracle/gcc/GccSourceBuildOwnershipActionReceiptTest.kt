package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class GccSourceBuildOwnershipActionReceiptTest {
    private val profile = ownershipTestProfile()
    private val metadata = ownershipTestMetadata(profile)

    @Test
    fun `successful supplied action cannot mint execution runtime source ownership model or score authority`() {
        val document = fixture()
        val supplied = OracleJson.canonicalBytes(document)
        val parsed = parse(supplied)
        supplied.fill(0)
        assertEquals("source-compile", parsed.role)
        assertEquals("compile", parsed.phase)
        assertEquals("-O1", parsed.argv[2])
        assertEquals(64, parsed.actionCandidateId.length)
        assertEquals(64, parsed.compileIdentityCandidateId?.length)
        assertFalse(parsed.isExecutionReceipt)
        assertFalse(parsed.sourceAuthenticated)
        assertFalse(parsed.runtimeAuthenticated)
        assertFalse(parsed.captureAuthenticated)
        assertFalse(parsed.ownershipComplete)
        assertFalse(parsed.modelBound)
        assertFalse(parsed.sealed)
        assertFalse(parsed.scored)
        assertFalse(parsed.productionVerified)
        assertFalse(parsed.releaseEligible)
        assertContentEquals(OracleJson.canonicalBytes(document), parsed.canonicalBytes())
        val encoded = parsed.canonicalBytes()
        encoded.fill(0)
        assertContentEquals(OracleJson.canonicalBytes(document), parsed.canonicalBytes())
        assertFailsWith<UnsupportedOperationException> { (parsed.argv as MutableList<String>).clear() }
        assertFailsWith<UnsupportedOperationException> { (parsed.environment as MutableMap<String, String>).clear() }
        assertFailsWith<UnsupportedOperationException> { (parsed.inputs as MutableList<GccSourceBuildFileClaim>).clear() }
    }

    @Test
    fun `command environment target configuration object and source variants remain distinct candidates`() {
        val root = fixture()
        val original = parse(OracleJson.canonicalBytes(root))
        val mutations = listOf(
            ownershipChanged(root, "argv", JsonArray(listOf(p("/usr/local/bin/g++"), p("-c"), p("-O2"), p("/oracle/source/unit.cc")))),
            ownershipChanged(root, "environment", o("LC_ALL" to p("C"), "TZ" to p("UTC"), "CPPFLAGS" to p("-DVARIANT=2"))),
            ownershipChanged(root, "target", p("different-target")),
            ownershipChanged(root, "configurationSha256", p("e".repeat(64))),
            ownershipChanged(root, "outputFiles", JsonArray(listOf(file("build/unit.o", "f".repeat(64), "object", 16)))),
            ownershipChanged(root, "runtime", ownershipChanged(root.getValue("runtime") as JsonObject,
                "effectiveImageIdClaim", p(GccSourceBuildOwnershipProfile.ORIGIN_IMAGE))),
        )
        for (changed in mutations) {
            val observation = parse(OracleJson.canonicalBytes(changed))
            assertNotEquals(original.actionCandidateId, observation.actionCandidateId)
            assertNotEquals(original.compileIdentityCandidateId, observation.compileIdentityCandidateId)
            assertFalse(observation.ownershipComplete)
        }
        val generator = parse(OracleJson.canonicalBytes(ownershipChanged(root, "role", p("generator-compile"))))
        assertNull(generator.compileIdentityCandidateId)
        refused(ownershipChanged(root, "role", p("source-only")))
        refused(ownershipChanged(root, "source", JsonNull))
        // JSON key traversal order is not an identity input.
        val reordered = JsonObject(root.entries.reversed().associate { it.toPair() })
        assertEquals(original.actionCandidateId, parse(OracleJson.canonicalBytes(reordered)).actionCandidateId)
    }

    @Test
    fun `every authority claim and self supplied collector or bridge receipt refuses`() {
        val root = fixture()
        val authority = root.getValue("authority") as JsonObject
        for (key in authority.keys) refused(ownershipChanged(root, "authority", ownershipChanged(authority, key, JsonPrimitive(true))))
        refused(ownershipChanged(root, "completion", o("state" to p("authenticated"), "collectorReceipt" to p("a".repeat(64)), "closureComplete" to JsonPrimitive(true))))
        refused(ownershipChanged(root, "completion", ownershipChanged(root.getValue("completion") as JsonObject,
            "collectorReceipt", p("a".repeat(64)))))
        refused(ownershipChanged(root, "runtime", ownershipChanged(root.getValue("runtime") as JsonObject,
            "bridgeReceipt", p("a".repeat(64)))))
        refused(ownershipChanged(root, "runtime", ownershipChanged(root.getValue("runtime") as JsonObject,
            "recordedOriginImageId", p(GccSourceBuildOwnershipProfile.REPRODUCED_IMAGE))))
        refused(ownershipChanged(root, "sealedByHash", p(OracleArtifacts.sha256(OracleJson.canonicalBytes(root)))))
        refused(ownershipChanged(root, "profileSha256", p("a".repeat(64))))
        refused(ownershipChanged(root, "metadataSetSha256", p("b".repeat(64))))
    }

    @Test
    fun `unknown nested fields source mismatch duplicate versions traversal and secrets refuse`() {
        val root = fixture()
        for (key in listOf("source", "tool", "runtime", "completion", "authority")) {
            refused(ownershipChanged(root, key, ownershipChanged(root.getValue(key) as JsonObject, "extra", JsonPrimitive(true))))
        }
        refused(JsonObject(root - "exitCode"))
        refused(ownershipChanged(root, "cwd", p("build/../outside")))
        refused(ownershipChanged(root, "source", ownershipChanged(root.getValue("source") as JsonObject,
            "path", p("source/../hidden.cc"))))
        refused(ownershipChanged(root, "source", ownershipChanged(root.getValue("source") as JsonObject,
            "sha256", p("f".repeat(64)))))
        refused(ownershipChanged(root, "environment", o("ACCESS_TOKEN" to p("fixture-secret-must-not-be-echoed"))))
        refused(ownershipChanged(root, "argv", JsonArray(listOf(p("/tool"), p("bad\u0000argument")))))
        val inputs = root.getValue("inputFiles") as JsonArray
        refused(ownershipChanged(root, "inputFiles", JsonArray(inputs + inputs.first())))
        val failure = assertFailsWith<GccSourceBuildOwnershipException> {
            parse(OracleJson.canonicalBytes(ownershipChanged(root, "environment", o("ACCESS_TOKEN" to p("private-canary")))))
        }
        assertFalse(failure.message.orEmpty().contains("private-canary"))
    }

    @Test
    fun `response byte length digest order and exact input binding must all agree`() {
        val root = fixture()
        val responses = root.getValue("responseFiles") as JsonArray
        val response = responses.single() as JsonObject
        for ((field, value) in listOf("bytes" to JsonPrimitive(1), "sha256" to p("a".repeat(64)),
            "bytesHex" to p("00"), "ordinal" to JsonPrimitive(1), "extra" to p("unknown"))) {
            refused(ownershipChanged(root, "responseFiles", JsonArray(listOf(ownershipChanged(response, field, value)))))
        }
        val inputs = root.getValue("inputFiles") as JsonArray
        refused(ownershipChanged(root, "inputFiles", JsonArray(inputs.take(1))))
    }

    @Test
    fun `long response bytes use bounded nonrecursive hex validation and remain untrusted`() {
        val root = fixture()
        val raw = ByteArray(65_536) { 0x7f }
        val sha = OracleArtifacts.sha256(raw)
        val hex = "7f".repeat(raw.size)
        val changed = ownershipChanged(ownershipChanged(root, "inputFiles", JsonArray(listOf(
            (root.getValue("inputFiles") as JsonArray).first(), file("build/options.rsp", sha, "response", raw.size),
        ))), "responseFiles", JsonArray(listOf(o("ordinal" to JsonPrimitive(0), "path" to p("build/options.rsp"),
            "bytes" to JsonPrimitive(raw.size), "sha256" to p(sha), "bytesHex" to p(hex)))))
        val parsed = parse(OracleJson.canonicalBytes(changed))
        assertFalse(parsed.isExecutionReceipt)
        assertFalse(parsed.captureAuthenticated)
        assertEquals(raw.size.toLong(), parsed.inputs.single { it.kind == "response" }.bytes)
        val response = (changed.getValue("responseFiles") as JsonArray).single() as JsonObject
        refused(ownershipChanged(changed, "responseFiles", JsonArray(listOf(
            ownershipChanged(response, "bytesHex", p(hex + "a")),
        ))))
    }

    @Test
    fun `deep canonical path stays bounded without recursive regex and traversal still refuses`() {
        val root = fixture()
        val path = "source/" + "a/".repeat(1_000) + "unit.cc"
        val source = root.getValue("source") as JsonObject
        val inputs = root.getValue("inputFiles") as JsonArray
        val changed = ownershipChanged(ownershipChanged(root, "source", ownershipChanged(source, "path", p(path))),
            "inputFiles", JsonArray(listOf(ownershipChanged(inputs.first() as JsonObject, "path", p(path)), inputs[1])))
        assertEquals(path, parse(OracleJson.canonicalBytes(changed)).inputs.first().path)
        refused(ownershipChanged(changed, "cwd", p("build/a/../outside")))
    }

    @Test
    fun `byte node argv environment file and response exact bounds reject one over`() {
        val root = fixture()
        val bytes = OracleJson.canonicalBytes(root)
        val nodes = countNodes(root)
        val exact = GccSourceBuildOwnershipObservationLimits(maximumRecordBytes = bytes.size,
            maximumRecordNodes = nodes, maximumArgvWords = 4, maximumEnvironmentEntries = 2,
            maximumFileClaims = 2, maximumResponseFiles = 1)
        parse(bytes, exact)
        for (lowered in listOf(exact.copy(maximumRecordBytes = bytes.size - 1), exact.copy(maximumRecordNodes = nodes - 1),
            exact.copy(maximumArgvWords = 3), exact.copy(maximumEnvironmentEntries = 1),
            exact.copy(maximumFileClaims = 1), exact.copy(maximumResponseFiles = 0))) {
            assertFailsWith<GccSourceBuildOwnershipException> { parse(bytes, lowered) }
        }
        assertFailsWith<IllegalArgumentException> { GccSourceBuildOwnershipObservationLimits(maximumRecordBytes = 8 * 1024 * 1024 + 1) }
        assertFailsWith<GccSourceBuildOwnershipException> { parse("{\"schemaVersion\":1,\"schemaVersion\":1}".toByteArray()) }
        assertFailsWith<GccSourceBuildOwnershipException> { parse(byteArrayOf(0xff.toByte())) }
    }

    private fun fixture(): JsonObject {
        val sourceSha = "a".repeat(64)
        val raw = "-DVALUE=1\n".toByteArray()
        val responseSha = OracleArtifacts.sha256(raw)
        return o(
            "schemaVersion" to JsonPrimitive(1), "schema" to p("gcc-source-build-ownership-action-observation-v1"),
            "evidenceKind" to p("untrusted-offline-observation"), "profileSha256" to p(profile.canonicalSha256),
            "metadataSetSha256" to p(metadata.metadataSetSha256), "phase" to p("compile"), "role" to p("source-compile"),
            "target" to p("x86_64-linux-gnu"), "cwd" to p("build"), "configurationSha256" to p("d".repeat(64)),
            "source" to o("path" to p("source/unit.cc"), "sha256" to p(sourceSha), "kind" to p("source")),
            "tool" to o("path" to p("toolchain/usr/local/bin/g++"), "sha256" to p("c".repeat(64)), "bytes" to JsonPrimitive(123)),
            "runtime" to o("recordedOriginImageId" to p(GccSourceBuildOwnershipProfile.ORIGIN_IMAGE),
                "effectiveImageIdClaim" to p(GccSourceBuildOwnershipProfile.REPRODUCED_IMAGE),
                "claimState" to p("unverified"), "bridgeReceipt" to JsonNull),
            "argv" to JsonArray(listOf(p("/usr/local/bin/g++"), p("-c"), p("-O1"), p("/oracle/source/unit.cc"))),
            "environment" to o("LC_ALL" to p("C"), "TZ" to p("UTC")),
            "inputFiles" to JsonArray(listOf(file("source/unit.cc", sourceSha, "source", 10),
                file("build/options.rsp", responseSha, "response", raw.size))),
            "outputFiles" to JsonArray(listOf(file("build/unit.o", "b".repeat(64), "object", 16))),
            "responseFiles" to JsonArray(listOf(o("ordinal" to JsonPrimitive(0), "path" to p("build/options.rsp"),
                "bytes" to JsonPrimitive(raw.size), "sha256" to p(responseSha),
                "bytesHex" to p(raw.joinToString("") { "%02x".format(it.toInt() and 255) })))),
            "exitCode" to JsonPrimitive(0),
            "completion" to o("state" to p("not-authenticated"), "collectorReceipt" to JsonNull, "closureComplete" to JsonPrimitive(false)),
            "authority" to JsonObject(listOf("sourceAuthenticated", "runtimeAuthenticated", "captureAuthenticated", "ownershipComplete",
                "modelBound", "sealed", "scored", "productionVerified", "releaseEligible").associateWith { JsonPrimitive(false) }),
        )
    }
    private fun file(path: String, sha: String, kind: String, bytes: Int) =
        o("path" to p(path), "sha256" to p(sha), "kind" to p(kind), "bytes" to JsonPrimitive(bytes))
    private fun o(vararg fields: Pair<String, JsonElement>) = JsonObject(linkedMapOf(*fields))
    private fun p(value: String) = JsonPrimitive(value)
    private fun parse(bytes: ByteArray, limits: GccSourceBuildOwnershipObservationLimits = GccSourceBuildOwnershipObservationLimits()) =
        GccSourceBuildOwnershipActionReceipt.parseObservation(bytes, profile, metadata, limits)
    private fun refused(root: JsonObject) {
        assertFailsWith<GccSourceBuildOwnershipException> { parse(OracleJson.canonicalBytes(root)) }
    }
    private fun countNodes(value: JsonElement): Int = 1 + when (value) {
        is JsonObject -> value.values.sumOf(::countNodes)
        is JsonArray -> value.sumOf(::countNodes)
        else -> 0
    }
}
