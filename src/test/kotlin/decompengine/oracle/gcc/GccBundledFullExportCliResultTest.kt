package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledFullExportCliResultTest {
    @Test
    fun `full export CLI result binds retained tree manifest and remains unscored`() {
        val tree = JsonObject(mapOf(
            "kind" to JsonPrimitive("gcc-bundled-full-export-output-tree-v2"),
            "stateSha256" to JsonPrimitive("1".repeat(64)),
            "progressSha256" to JsonPrimitive("2".repeat(64)),
            "language" to JsonPrimitive("x86:LE:64:default"),
            "compilerSpec" to JsonPrimitive("gcc"),
            "programModelSha256" to JsonPrimitive("c".repeat(64)),
            "programModelBytes" to JsonPrimitive(123),
            "sidecars" to JsonObject(emptyMap()),
        ))
        val treeBytes = OracleJson.canonicalBytes(tree)
        val treeSha = OracleArtifacts.sha256(treeBytes)
        val manifestBytes = OracleJson.canonicalBytes(JsonObject(mapOf(
            "outputTreeSha256" to JsonPrimitive(treeSha),
            "tree" to tree,
        )))
        val bindingBytes = OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-compiler-engine-structural-full-export-binding-v2"),
            "schemaVersion" to JsonPrimitive(2),
            "outputTreeSha256" to JsonPrimitive(treeSha),
            "programModel" to JsonObject(mapOf(
                "sha256" to JsonPrimitive("c".repeat(64)),
                "bytes" to JsonPrimitive(123),
                "functionCount" to JsonPrimitive(7),
            )),
        )))
        val root = Path.of("/tmp/structural-result-fixture")
        val manifestPath = root.resolve(GccBundledFullExportCliResultV2.TREE_MANIFEST_NAME)
        fun createResult(
            binding: ByteArray = bindingBytes,
            manifest: ByteArray = manifestBytes,
            outputTreeSha256: String = treeSha,
        ) = GccBundledFullExportCliResultV2.create(
            operationId = "a".repeat(64),
            requestSha256 = "b".repeat(64),
            journalPath = root.resolve("journal"),
            programModelPath = root.resolve("scratch/reports/program_model.json"),
            programModelSha256 = "c".repeat(64),
            programModelBytes = 123,
            functionCount = 7,
            exportAssessmentReceiptSha256 = "d".repeat(64),
            executionReceiptSha256 = "e".repeat(64),
            structuralBindingPath = root.resolve("structural-full-export-binding.json"),
            structuralBindingBytes = binding,
            treeManifestPath = manifestPath,
            treeManifestBytes = manifest,
            outputTreeSha256 = outputTreeSha256,
            operationWallTime = JsonObject(mapOf("startedMonotonicNanos" to JsonPrimitive(1))),
        )
        val resultBytes = createResult()
        val result = OracleJson.parseCanonical(resultBytes).jsonObject
        assertEquals("gcc-bundled-cli-full-export-result-v2", result.getValue("provider").jsonPrimitive.content)
        assertEquals("2", result.getValue("schemaVersion").jsonPrimitive.content)
        assertEquals(JsonPrimitive(false), result.getValue("complete"))
        assertEquals(JsonPrimitive(false), result.getValue("scored"))
        assertEquals(JsonPrimitive(false), result.getValue("releaseEligible"))
        assertEquals(manifestPath.toString(), result.getValue("outputTreeManifest").jsonPrimitive.content)
        assertEquals(OracleArtifacts.sha256(manifestBytes), result.getValue("outputTreeManifestSha256").jsonPrimitive.content)
        assertEquals(treeSha, result.getValue("outputTreeSha256").jsonPrimitive.content)

        val mismatchedBinding = OracleJson.canonicalBytes(JsonObject(
            (OracleJson.parseCanonical(bindingBytes).jsonObject - "outputTreeSha256") +
                ("outputTreeSha256" to JsonPrimitive("f".repeat(64))),
        ))
        assertFails { createResult(mismatchedBinding) }
        val mismatchedModelBinding = OracleJson.canonicalBytes(JsonObject(
            OracleJson.parseCanonical(bindingBytes).jsonObject + ("programModel" to JsonObject(mapOf(
                "sha256" to JsonPrimitive("f".repeat(64)),
                "bytes" to JsonPrimitive(123),
                "functionCount" to JsonPrimitive(7),
            ))),
        ))
        assertFails { createResult(mismatchedModelBinding) }

        assertFails { createResult(outputTreeSha256 = "f".repeat(64)) }

        val alteredStateTree = JsonObject(tree + ("stateSha256" to JsonPrimitive("3".repeat(64))))
        val manifestWithStaleTreeDigest = OracleJson.canonicalBytes(JsonObject(mapOf(
            "outputTreeSha256" to JsonPrimitive(treeSha),
            "tree" to alteredStateTree,
        )))
        assertFails { createResult(manifest = manifestWithStaleTreeDigest) }

        val treeWithSubstitutedModel = JsonObject(tree + ("programModelSha256" to JsonPrimitive("f".repeat(64))))
        val substitutedTreeSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(treeWithSubstitutedModel))
        val substitutedManifest = OracleJson.canonicalBytes(JsonObject(mapOf(
            "outputTreeSha256" to JsonPrimitive(substitutedTreeSha),
            "tree" to treeWithSubstitutedModel,
        )))
        val substitutedBinding = OracleJson.canonicalBytes(JsonObject(
            OracleJson.parseCanonical(bindingBytes).jsonObject + ("outputTreeSha256" to JsonPrimitive(substitutedTreeSha)),
        ))
        assertFails { createResult(substitutedBinding, substitutedManifest, substitutedTreeSha) }

        assertFails { createResult(manifest = manifestBytes + byteArrayOf('\n'.code.toByte())) }
    }
}
