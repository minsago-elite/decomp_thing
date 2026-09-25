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
        val bindingBytes = fullBindingBytes(treeSha)
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

        val binding = OracleJson.parseCanonical(bindingBytes).jsonObject
        val lineage = binding.getValue("receiptLineage").jsonObject
        val mismatchedOperationLineage = JsonObject(lineage + ("operationId" to JsonPrimitive("f".repeat(64))))
        val mismatchedOperationBinding = OracleJson.canonicalBytes(JsonObject(binding + mapOf(
            "receiptLineage" to mismatchedOperationLineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(mismatchedOperationLineage))),
        )))
        assertFails { createResult(mismatchedOperationBinding) }

        val mismatchedIntentLineage = JsonObject(lineage + ("intentSha256" to JsonPrimitive("f".repeat(64))))
        val mismatchedIntentBinding = OracleJson.canonicalBytes(JsonObject(binding + mapOf(
            "receiptLineage" to mismatchedIntentLineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(mismatchedIntentLineage))),
        )))
        assertFails { createResult(mismatchedIntentBinding) }

        val mismatchedExecutionLineage = JsonObject(lineage + ("executionReceiptSha256" to JsonPrimitive("f".repeat(64))))
        val mismatchedExecutionBinding = OracleJson.canonicalBytes(JsonObject(binding + mapOf(
            "receiptLineage" to mismatchedExecutionLineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(mismatchedExecutionLineage))),
        )))
        assertFails { createResult(binding = mismatchedExecutionBinding) }

        val mismatchedAssessmentLineage = JsonObject(lineage + ("exportAssessmentReceiptSha256" to JsonPrimitive("f".repeat(64))))
        val mismatchedAssessmentBinding = OracleJson.canonicalBytes(JsonObject(binding + mapOf(
            "receiptLineage" to mismatchedAssessmentLineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(mismatchedAssessmentLineage))),
        )))
        assertFails { createResult(binding = mismatchedAssessmentBinding) }

        assertFails {
            createResult(binding = OracleJson.canonicalBytes(JsonObject(binding + ("unreviewed" to JsonPrimitive(true)))))
        }

        val target = binding.getValue("targetDescriptor").jsonObject
        val substitutedTarget = JsonObject(target + ("ghidraLanguage" to JsonPrimitive("x86:LE:64:attacker")))
        val mismatchedLoaderBinding = OracleJson.canonicalBytes(JsonObject(binding + mapOf(
            "targetDescriptor" to substitutedTarget,
            "targetDescriptorSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(substitutedTarget))),
        )))
        assertFails { createResult(binding = mismatchedLoaderBinding) }

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

    private fun fullBindingBytes(outputTreeSha256: String): ByteArray {
        val target = JsonObject(mapOf(
            "id" to JsonPrimitive("x86_64-sysv-amd64-v1"),
            "architecture" to JsonPrimitive("x86_64"),
            "abi" to JsonPrimitive("sysv-amd64"),
            "machine" to JsonPrimitive(62),
            "osAbi" to JsonPrimitive(3),
            "elfClass" to JsonPrimitive("ELF64"),
            "dataEncoding" to JsonPrimitive("little-endian"),
            "pointerBits" to JsonPrimitive(64),
            "elfType" to JsonPrimitive("ET_EXEC"),
            "ghidraLanguage" to JsonPrimitive("x86:LE:64:default"),
            "ghidraCompilerSpec" to JsonPrimitive("gcc"),
            "imageBase" to JsonPrimitive("0x400000"),
            "executableRangesSha256" to JsonPrimitive("1".repeat(64)),
        ))
        val lineage = JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-bundled-full-export-receipt-lineage-v1"),
            "schemaVersion" to JsonPrimitive(1),
            "operationId" to JsonPrimitive("a".repeat(64)),
            "intentSha256" to JsonPrimitive("b".repeat(64)),
            "engineId" to JsonPrimitive("cc1"),
            "compilerEngineProfileSha256" to JsonPrimitive("4".repeat(64)),
            "executionReceiptSha256" to JsonPrimitive("e".repeat(64)),
            "executionPayloadSha256" to JsonPrimitive("5".repeat(64)),
            "exportAssessmentReceiptSha256" to JsonPrimitive("d".repeat(64)),
            "exportAssessmentSha256" to JsonPrimitive("6".repeat(64)),
        ))
        return OracleJson.canonicalBytes(JsonObject(mapOf(
            "provider" to JsonPrimitive("gcc-compiler-engine-structural-full-export-binding-v2"),
            "schemaVersion" to JsonPrimitive(2),
            "profileId" to JsonPrimitive("gcc-cc1-16.2.0"),
            "profileVersion" to JsonPrimitive("16.2.0"),
            "sourceRevision" to JsonPrimitive("7".repeat(40)),
            "compilerEngineProfileSha256" to JsonPrimitive("4".repeat(64)),
            "artifactManifestSha256" to JsonPrimitive("8".repeat(64)),
            "targetDescriptor" to target,
            "targetDescriptorSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(target))),
            "inputBinary" to JsonObject(mapOf(
                "sha256" to JsonPrimitive("9".repeat(64)),
                "bytes" to JsonPrimitive(321),
            )),
            "exporter" to JsonObject(mapOf(
                "sha256" to JsonPrimitive("2".repeat(64)),
                "bytes" to JsonPrimitive(322),
                "recoveryMode" to JsonPrimitive("full"),
            )),
            "ghidraArchive" to JsonObject(mapOf(
                "sha256" to JsonPrimitive("3".repeat(64)),
                "bytes" to JsonPrimitive(323),
            )),
            "programModel" to JsonObject(mapOf(
                "sha256" to JsonPrimitive("c".repeat(64)),
                "bytes" to JsonPrimitive(123),
                "functionCount" to JsonPrimitive(7),
            )),
            "outputTreeSha256" to JsonPrimitive(outputTreeSha256),
            "receiptLineage" to lineage,
            "receiptLineageSha256" to JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(lineage))),
        )))
    }
}
