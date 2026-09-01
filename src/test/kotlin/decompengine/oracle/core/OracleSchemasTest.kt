package decompengine.oracle.core

import decompengine.oracle.behavior.LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class OracleSchemasTest {
    @Test
    fun `bundled 2020-12 schema validates a minimal full-tree truth partition`() {
        val document = OracleJson.parse(
            """
            {
              "schemaVersion": 1,
              "oracle": {},
              "shard": {},
              "counts": {
                "globals": 0,
                "types": 0,
                "unobservableGlobals": 0,
                "unobservableTypes": 0,
                "fields": 0,
                "bases": 0,
                "enumerators": 0,
                "resolvedTypeReferences": 0,
                "unresolvedTypeReferences": 0,
                "ambiguousTypeReferences": 0,
                "crossShardTypeReferences": 0
              },
              "globals": [],
              "types": []
            }
            """.trimIndent().toByteArray(),
        )

        OracleSchemas.validate("full-tree-data-truth", document)

        val identity = OracleSchemas.identity("full-tree-data-truth")
        assertEquals("full-tree-data-truth", identity.name)
        assertTrue(identity.sha256.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `schema validation rejects missing extra and mistyped fields`() {
        listOf(
            "{}",
            """{"schemaVersion":1,"oracle":{},"shard":{},"counts":{},"globals":[],"types":[],"extra":true}""",
            """{"schemaVersion":"1","oracle":{},"shard":{},"counts":{},"globals":[],"types":[]}""",
        ).forEach { input ->
            val failure = assertFailsWith<OracleSchemaException>(input) {
                OracleSchemas.validate("full-tree-data-truth", OracleJson.parse(input.toByteArray()))
            }
            assertTrue(failure.message.orEmpty().contains("schema validation"), failure.message)
        }
    }

    @Test
    fun `schema resources cannot be selected through paths or unknown names`() {
        listOf("../full-tree-data-truth", "/full-tree-data-truth", "FullTree", "", "gcc//build-record").forEach {
            assertFailsWith<OracleSchemaException>(it) { OracleSchemas.identity(it) }
        }
        assertFailsWith<OracleSchemaException> { OracleSchemas.identity("not-a-schema") }
    }

    @Test
    fun `every catalogued schema is bundled and compilable`() {
        assertEquals(66, OracleSchemas.supportedNames.size)
        OracleSchemas.supportedNames.forEach { name ->
            val identity = OracleSchemas.identity(name)
            assertEquals(name, identity.name)
            assertTrue(identity.sha256.matches(Regex("[0-9a-f]{64}")), name)
        }
    }

    @Test
    fun `Ninja execution receipt schema fixes terminal observations and commitments`() {
        val schema = requireNotNull(
            OracleSchemas::class.java.classLoader.getResourceAsStream(
                "oracle/full-tree-ninja-compdb-execution-receipt.schema.json",
            ),
        ).use { OracleJson.parse(it.readAllBytes()).jsonObject }
        val valid = validNinjaExecutionReceipt(schema)

        OracleSchemas.validate("full-tree-ninja-compdb-execution-receipt", valid)

        val mutations = listOf(
            "bearer trust" to mutateReceiptObject(valid, "receiptTrust") {
                this["artifactBearerAuthority"] = JsonPrimitive(true)
            },
            "unbounded field" to mutateReceiptObject(valid, "bounds") {
                this["callerDefined"] = JsonPrimitive(true)
            },
            "missing executed Ninja identity" to mutateReceiptObject(valid, "ninja") {
                remove("executedNinjaSha256")
            },
            "writable manifest closure" to mutateReceiptObject(valid, "manifestClosure") {
                this["mountedReadOnly"] = JsonPrimitive(false)
            },
            "caller-selected compiler rules" to mutateReceiptObject(valid, "compilerRules") {
                this["selectedBy"] = JsonPrimitive("caller")
            },
            "shell invocation" to mutateReceiptObject(valid, "invocation") {
                this["shell"] = JsonPrimitive(true)
            },
            "missing network isolation" to mutateReceiptObject(valid, "containment") {
                this["networkIsolated"] = JsonPrimitive(false)
            },
            "missing terminal absence" to mutateReceiptObject(valid, "cleanup") {
                this["terminalAbsenceProven"] = JsonPrimitive(false)
            },
            "missing receipt context" to mutateReceiptObject(valid, "commitments") {
                remove("receiptContextSha256")
            },
            "incomplete stdout identity" to mutateReceiptObject(valid, "execution") {
                val stdout = getValue("stdout").jsonObject.toMutableMap()
                stdout.remove("exactMatch")
                this["stdout"] = JsonObject(stdout)
            },
            "stdout-only field on stderr" to mutateReceiptObject(valid, "execution") {
                val stderr = getValue("stderr").jsonObject.toMutableMap()
                stderr["exactMatch"] = JsonPrimitive(true)
                this["stderr"] = JsonObject(stderr)
            },
            "reordered blockers" to JsonObject(valid.toMutableMap().apply {
                this["blockers"] = JsonArray(getValue("blockers").jsonArray.reversed())
            }),
        )
        mutations.forEach { (description, document) ->
            assertFailsWith<OracleSchemaException>(description) {
                OracleSchemas.validate("full-tree-ninja-compdb-execution-receipt", document)
            }
        }
    }

    @Test
    fun `candidate ACP lineage archive bound matches its bundled schema`() {
        val schema = requireNotNull(
            OracleSchemas::class.java.classLoader.getResourceAsStream(
                "oracle/llvm-behavior-candidate-acp-lineage-index-v2.schema.json",
            ),
        ).use { OracleJson.parse(it.readAllBytes()).jsonObject }
        val schemaMaximum = schema.getValue("properties").jsonObject
            .getValue("archive").jsonObject
            .getValue("properties").jsonObject
            .getValue("bytes").jsonObject
            .getValue("maximum").jsonPrimitive.long

        assertEquals(LLVM_BEHAVIOR_CANDIDATE_ACP_LINEAGE_MAXIMUM_ARCHIVE_BYTES, schemaMaximum)
    }

    @Test
    fun `configuration digest binds canonical policy and exact schema bytes`() {
        assertEquals(
            "90dd097ba542bc5297b37277125ce01e73355fe0e4cea3117b3240315fff5a5b",
            OracleSchemas.configurationSha256(
                "full-tree-data-truth",
                JsonObject(
                    linkedMapOf(
                        "id" to JsonPrimitive("full-tree-data-truth"),
                        "version" to JsonPrimitive(16),
                        "typeIdentity" to JsonPrimitive(
                            "tag-qualified-lexical-context-name-or-anonymous-declaration-with-observation-owned-lambda-and-lossy-local-contexts",
                        ),
                        "globalIdentity" to JsonPrimitive(
                            "rva-or-source-aligned-name-declaration-or-producer-observation",
                        ),
                        "owner" to JsonPrimitive("lowest-unit-id"),
                        "typeReferences" to JsonPrimitive(
                            "exact-dwarf-offset-chain-with-conditional-bounded-authenticated-candidate-commitments-and-no-ambiguous-target-substitution",
                        ),
                        "truthSharding" to JsonPrimitive(
                            "inventory-owner-with-deterministic-two-thirds-byte-budget-entity-partitions",
                        ),
                        "maximumDatabaseBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024),
                    ),
                ),
            ),
        )
    }

    @Test
    fun `validator accepts caller trees without reparsing permissive JSON`() {
        val emptyPartition = OracleJson.parse(
            """{"counts":{"ambiguousTypeReferences":0,"bases":0,"crossShardTypeReferences":0,"enumerators":0,"fields":0,"globals":0,"resolvedTypeReferences":0,"types":0,"unobservableGlobals":0,"unobservableTypes":0,"unresolvedTypeReferences":0},"globals":[],"oracle":{},"schemaVersion":1,"shard":{},"types":[]}""".toByteArray(),
        ) as JsonObject

        OracleSchemas.validate("full-tree-data-truth", emptyPartition)
    }
}

private fun mutateReceiptObject(
    document: JsonObject,
    name: String,
    mutation: MutableMap<String, JsonElement>.() -> Unit,
): JsonObject {
    val changed = document.getValue(name).jsonObject.toMutableMap().apply(mutation)
    return JsonObject(document.toMutableMap().apply { this[name] = JsonObject(changed) })
}

private fun validNinjaExecutionReceipt(schema: JsonObject): JsonObject {
    val sha256 = "0".repeat(64)
    val retainedInputs = (0 until 16).joinToString(",") { index ->
        """{"label":"input-$index","bytes":1,"sha256":"$sha256"}"""
    }
    val blockerCodes = listOf(
        "complete-project-header-inventory-missing",
        "compiler-capture-provenance-missing",
        "compiler-option-arity-unvalidated",
        "generated-generation-receipt-missing",
        "generated-snapshot-completeness-unproven",
        "ninja-live-edge-replay-missing",
        "physical-build-root-unverified",
        "physical-project-roots-unverified",
    )
    val dispositions = blockerCodes.joinToString(",") { code ->
        """{"code":"$code","disposition":"carried"}"""
    }
    val blockers = blockerCodes.joinToString(",") { code ->
        """{"code":"$code","disposition":"carried","source":"full-tree-ninja-compdb-prestart-v1"}"""
    }
    val parsed = OracleJson.parse(
        """
        {
          "schemaVersion":1,
          "kind":"full-tree-ninja-compdb-execution-receipt-v1",
          "configurationSha256":"$sha256",
          "receiptTrust":{},
          "authority":{},
          "acpBoundary":{},
          "receiptPolicy":{},
          "bounds":{
            "maximumCanonicalBytes":1048576,
            "maximumWallMillis":120000,
            "maximumStderrBytes":8388608,
            "cleanupMillis":30000,
            "maximumProcesses":16,
            "maximumOpenFiles":128,
            "maximumFileBytes":67108864,
            "maximumAddressSpaceBytes":1073741824,
            "maximumCpuSeconds":120,
            "maximumStdoutBytes":67108864
          },
          "prestart":{
            "artifactBytes":1,
            "artifactSha256":"$sha256",
            "reportSha256":"$sha256",
            "configurationSha256":"$sha256",
            "prestartContextSha256":"$sha256",
            "predecessorManifestSha256":"$sha256",
            "retainedInputs":[$retainedInputs]
          },
          "ninja":{
            "recordedPath":"/usr/bin/ninja",
            "bytes":1,
            "sha256":"$sha256",
            "toolIdentitySha256":"$sha256",
            "runtimeManifestSha256":"$sha256",
            "runtimeProfileSha256":"$sha256",
            "executedNinjaSha256":"$sha256",
            "runtimeFiles":[]
          },
          "manifestClosure":{
            "archiveSha256":"$sha256",
            "closureSha256":"$sha256",
            "fileManifestSha256":"$sha256",
            "includeGraphSha256":"$sha256",
            "ruleManifestSha256":"$sha256",
            "materializationSha256":"$sha256",
            "runtimeManifestSha256":"$sha256",
            "mountedReadOnly":true,
            "sourceMaterializationRemoved":true
          },
          "compilerRules":{
            "names":["C_COMPILER__fixture_RelWithDebInfo"],
            "rulesSha256":"$sha256",
            "selectedBy":"kotlin-jvm-host"
          },
          "invocation":{
            "workingDirectory":"/build",
            "argv":["/usr/bin/ninja","-f","build.ninja","-t","compdb","C_COMPILER__fixture_RelWithDebInfo"],
            "argvSha256":"$sha256",
            "environment":[
              {"name":"LC_ALL","value":"C"},
              {"name":"SOURCE_DATE_EPOCH","value":"1"},
              {"name":"TZ","value":"UTC"}
            ],
            "environmentSha256":"$sha256",
            "invocationSha256":"$sha256",
            "shell":false,
            "inheritedEnvironment":"cleared",
            "stdin":"closed-before-exec",
            "stderrMerged":false
          },
          "containment":{
            "provider":"linux-bubblewrap-cgroup-v2",
            "providerVersion":"1",
            "boundaryEvidenceSha256":"$sha256",
            "containmentReceiptSha256":"$sha256",
            "launchPurpose":"ninja-compdb-query",
            "commandSha256":"$sha256",
            "environmentContentSha256":"$sha256",
            "workingDirectorySha256":"$sha256",
            "stagingRootsSha256":"$sha256",
            "stagingRootCount":0,
            "emptyDirectoriesSha256":"$sha256",
            "emptyDirectoryCount":0,
            "runtimeMountCount":3,
            "networkIsolated":true,
            "inheritedFilesystemAbsent":true,
            "cgroupV2PidsMemoryCpu":true,
            "startGatePositiveByte":true,
            "stdinClosedBeforeExec":true
          },
          "execution":{
            "phase":"terminal",
            "startCommittedDuringExecution":true,
            "exitCode":0,
            "signal":null,
            "timedOut":false,
            "outputLimitExceeded":false,
            "elapsedMillis":1,
            "stdout":{
              "bytes":2,
              "sha256":"$sha256",
              "canonicalSha256":"$sha256",
              "expectedBytes":2,
              "expectedSha256":"$sha256",
              "exactMatch":true,
              "complete":true,
              "truncated":false
            },
            "stderr":{
              "bytes":0,
              "sha256":"$sha256",
              "maximumBytes":8388608,
              "complete":true,
              "truncated":false
            }
          },
          "cleanup":{
            "wholeCgroupCleanupVerified":true,
            "terminalAbsenceProven":true,
            "boundaryRuntimeSnapshotsRemoved":true,
            "boundaryControlTreeRemoved":true,
            "sourceMaterializationRemoved":true,
            "cleanupReceiptSha256":"$sha256"
          },
          "commitments":{
            "executionPredecessorManifestSha256":"$sha256",
            "deploymentConfigurationSha256":"$sha256",
            "runtimeProfileSha256":"$sha256",
            "executedNinjaSha256":"$sha256",
            "manifestMaterializationSha256":"$sha256",
            "compilerRulesSha256":"$sha256",
            "invocationSha256":"$sha256",
            "containmentPolicySha256":"$sha256",
            "expectedStdoutSha256":"$sha256",
            "containmentReceiptSha256":"$sha256",
            "stdoutObservationSha256":"$sha256",
            "stderrObservationSha256":"$sha256",
            "cleanupReceiptSha256":"$sha256",
            "receiptContextSha256":"$sha256"
          },
          "blockerDispositions":[$dispositions],
          "blockers":[$blockers],
          "reportSha256":"$sha256"
        }
        """.trimIndent().toByteArray(),
    ).jsonObject
    val properties = schema.getValue("properties").jsonObject
    return JsonObject(parsed.toMutableMap().apply {
        listOf("receiptTrust", "authority", "acpBoundary", "receiptPolicy").forEach { name ->
            this[name] = properties.getValue(name).jsonObject.getValue("const")
        }
    })
}
