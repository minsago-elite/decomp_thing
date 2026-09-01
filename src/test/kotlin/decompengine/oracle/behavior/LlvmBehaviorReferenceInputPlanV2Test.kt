package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemaException
import decompengine.oracle.core.OracleSchemas
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorReferenceInputPlanV2Test {
    @Test
    fun `reviewed input plan exposes ACP first class while granting no oracle authority`() {
        val verified = LlvmBehaviorReferenceInputPlanV2Verifier.verify(PRODUCTION_PLAN)

        assertEquals("kotlin-jvm-authored-reference-input-plan-v2", verified.authority)
        assertEquals(2, verified.schemaVersion)
        assertEquals("clang-22-1-6-driver-behavior-reference-input-plan-v2", verified.planId)
        assertEquals(46_787L, verified.planBytes)
        assertEquals(EXPECTED_PLAN_SHA256, verified.planSha256)
        assertEquals(EXPECTED_SCHEMA_SHA256, verified.schemaSha256)
        assertEquals(48, verified.caseIds.size)
        assertEquals(48, verified.executionOrder.size)
        assertTrue(
            verified.executionOrder.indexOf("precompile-header") <
                verified.executionOrder.indexOf("pch-reuse-valid"),
        )
        assertEquals(48, verified.diagnosticOwners.size)
        assertEquals(16, verified.diagnosticOwners.values.toSet().size)
        assertEquals(54, verified.literalInputCount)
        assertEquals(2, verified.freshArtifactDependencyCount)
        assertTrue(verified.referenceInputPlanValidated)

        assertEquals("first-class-candidate-producer-operator", verified.acpRole)
        assertEquals(
            "authenticated-session-change-build-artifact-provenance",
            verified.acpCandidateContribution,
        )
        assertEquals("read-only-oracle-input", verified.acpCandidateProvenanceAccess)
        assertEquals("kotlin-jvm-host", verified.acpCandidateAdmissionOwner)
        assertEquals("separately-reviewed-kotlin-jvm-host", verified.acpCandidateLiveExecutionOwner)
        assertEquals("kotlin-jvm-host-only", verified.acpReferenceSubjectAdmission)
        listOf(
            verified.acpOracleAuthority,
            verified.acpReferenceAuthoringAuthority,
            verified.acpPolicyAuthoringAuthority,
            verified.acpValidationAuthority,
            verified.acpObservationAuthoringAuthority,
            verified.acpStartAuthority,
            verified.acpContainmentAuthority,
            verified.acpTerminalAbsenceAuthority,
            verified.acpScoringAuthority,
            verified.acpCertificationAuthority,
            verified.acpReleaseAuthority,
            verified.definitionBound,
            verified.expectedOutputsPresent,
            verified.referenceSubjectPinned,
            verified.observationsCaptured,
            verified.referenceTruthEstablished,
            verified.runtimePreflightVerified,
            verified.liveContainmentVerified,
            verified.terminalAbsenceVerified,
            verified.candidateStarted,
            verified.startAuthorized,
            verified.scoringAuthority,
            verified.certificationAuthority,
            verified.releaseEligible,
        ).forEach(::assertFalse)

        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (verified.caseIds as MutableList<String>).add("forged-case")
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (verified.executionOrder as MutableList<String>).add("forged-case")
        }
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (verified.diagnosticOwners as MutableMap<String, String>)["forged-case"] = "clang-driver"
        }
    }

    @Test
    fun `Kotlin generator independently authors the exact checked input plan`() {
        val root = createTempDirectory("llvm-reference-input-plan-v2-generator-").toAbsolutePath().normalize()
        try {
            val output = root.resolve(PLAN_FILE_NAME)
            val generated = LlvmBehaviorReferenceInputPlanV2Generator.publish(output)
            assertEquals(EXPECTED_PLAN_SHA256, generated.planSha256)
            assertTrue(
                Files.readAllBytes(PRODUCTION_PLAN).contentEquals(Files.readAllBytes(output)),
                "checked bytes must be reproduced only from reviewed Kotlin case sources",
            )

            val repeated = LlvmBehaviorReferenceInputPlanV2Generator.publish(output)
            assertEquals(generated.planSha256, repeated.planSha256)
            assertTrue(Files.readAllBytes(PRODUCTION_PLAN).contentEquals(Files.readAllBytes(output)))
        } finally {
            root.toFile().deleteRecursively()
        }

        val publish = LlvmBehaviorReferenceInputPlanV2Generator::class.java.declaredMethods.single {
            it.name == "publish" && !it.isSynthetic
        }
        assertTrue(publish.parameterTypes.contentEquals(arrayOf(Path::class.java)))
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> {
            LlvmBehaviorReferenceInputPlanV2Generator.publish(Path.of(PLAN_FILE_NAME))
        }
    }

    @Test
    fun `checked artifact is canonical schema v2 and carries inputs but no expected outputs`() {
        val bytes = Files.readAllBytes(PRODUCTION_PLAN)
        val plan = OracleJson.parseCanonical(bytes) as JsonObject
        OracleSchemas.validate("llvm-behavior-reference-input-plan-v2", plan)
        assertEquals(EXPECTED_PLAN_SHA256, OracleArtifacts.sha256(bytes))

        val forbiddenKeys = setOf(
            "expected",
            "exitCode",
            "status",
            "present",
            "mode",
            "stdoutSha256",
            "stderrSha256",
            "reportSha256",
            "matrixSha256",
            "mismatchIds",
            "sandbox",
            "imageDigest",
            "controlClient",
            "engineProfile",
        )
        walkObjects(plan).forEach { objectValue ->
            assertTrue(objectValue.keys.intersect(forbiddenKeys).isEmpty(), objectValue.keys.toString())
        }
        val text = bytes.toString(Charsets.UTF_8).lowercase()
        listOf(
            "python",
            "oci-container-v1",
            "behavior-preexec-v1",
            OLD_PCH_SHA256,
            OLD_IMAGE_SHA256,
            OLD_CONTROL_CLIENT_SHA256,
        ).forEach { marker -> assertFalse(marker in text, marker) }

        val claims = plan.objectField("claims")
        claims.values.forEach { assertEquals(JsonPrimitive(false), it) }
        assertEquals(JsonArray(emptyList()), plan.objectField("captureContract").getValue("normalizations"))
        assertEquals(JsonPrimitive(3), plan.objectField("repetitionContract").getValue("count"))
    }

    @Test
    fun `PCH reuse is a same repetition dependency and never a migrated reference blob`() {
        val cases = (validPlan()["cases"] as JsonArray).map { it as JsonObject }
        val dependencies = cases.flatMap { case ->
            (case["inputs"] as JsonArray).map { case.stringField("id") to (it as JsonObject) }
        }.filter { (_, input) -> input.stringField("kind") == "same-repetition-fresh-reference-artifact" }

        assertEquals(listOf("pch-reuse-valid", "pch-reuse-wrong-target"), dependencies.map { it.first })
        dependencies.forEach { (_, dependency) ->
            assertEquals("precompile-header", dependency.stringField("producerCaseId"))
            assertEquals("answer.pch", dependency.stringField("producerPath"))
            assertEquals("answer.pch", dependency.stringField("targetPath"))
            assertEquals(
                JsonArray(listOf(JsonPrimitive("answer.h"))),
                dependency.getValue("compatibilityInputPaths"),
            )
            assertEquals("regular-file", dependency.stringField("producerArtifactType"))
            assertEquals(
                "same-repetition-produced-not-literal-input",
                dependency.stringField("producerArtifactFreshness"),
            )
            assertEquals(
                setOf(
                    "kind",
                    "producerCaseId",
                    "producerPath",
                    "targetPath",
                    "compatibilityInputPaths",
                    "producerArtifactType",
                    "producerArtifactFreshness",
                ),
                dependency.keys,
            )
        }

        val literals = cases.flatMap { case -> (case["inputs"] as JsonArray).map { it as JsonObject } }
            .filter { it.stringField("kind") == "literal" }
        assertTrue(literals.none { it.stringField("path") == "answer.pch" })
        assertTrue(literals.none { it.stringField("sha256") == OLD_PCH_SHA256 })
        val producerArguments = cases.single { it.stringField("id") == "precompile-header" }["arguments"] as JsonArray
        assertTrue(JsonPrimitive("answer.pch") in producerArguments)
        val executionOrder = (validPlan()["executionOrder"] as JsonArray).map { (it as JsonPrimitive).content }
        assertTrue(executionOrder.indexOf("precompile-header") < executionOrder.indexOf("pch-reuse-valid"))
        assertTrue(executionOrder.indexOf("precompile-header") < executionOrder.indexOf("pch-reuse-wrong-target"))
    }

    @Test
    fun `schema and verifier reject authority output runtime and repetition substitutions`() = withFixture { fixture ->
        val mutations = listOf(
            listOf("schemaVersion") to JsonPrimitive(1),
            listOf("acpBoundary", "role") to JsonPrimitive("optional-candidate-source"),
            listOf("acpBoundary", "oracleAuthority") to JsonPrimitive(true),
            listOf("acpBoundary", "referenceAuthoringAuthority") to JsonPrimitive(true),
            listOf("captureContract", "normalizations") to JsonArray(listOf(JsonPrimitive("paths"))),
            listOf("repetitionContract", "count") to JsonPrimitive(2),
            listOf("repetitionContract", "dependencyScope") to JsonPrimitive("cross-repetition"),
            listOf("executionOrder", "31") to JsonPrimitive("pch-reuse-valid"),
            listOf("claims", "observationsCaptured") to JsonPrimitive(true),
            listOf("claims", "startAuthorized") to JsonPrimitive(true),
            listOf("claims", "releaseEligible") to JsonPrimitive(true),
        )
        mutations.forEach { (path, replacement) ->
            fixture.write(replaceAt(validPlan(), path, replacement))
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception>(path.joinToString(".")) {
                fixture.verify()
            }
        }

        val withExpected = replaceCase(validPlan(), 0) { case -> case + ("expected" to JsonObject(emptyMap())) }
        fixture.write(withExpected)
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val withSandbox = JsonObject(
            validPlan() + ("sandbox" to JsonObject(mapOf("backend" to JsonPrimitive("oci-container-v1")))),
        )
        fixture.write(withSandbox)
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val withPython = replaceCase(validPlan(), 0) { case ->
            val arguments = case["arguments"] as JsonArray
            case + ("arguments" to JsonArray(arguments + JsonPrimitive("/usr/bin/python3")))
        }
        fixture.write(withPython)
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
    }

    @Test
    fun `dependency and literal integrity mutations fail closed`() = withFixture { fixture ->
        val dependencyCaseIndex = caseIndex("pch-reuse-valid")
        val dependencyInputIndex = inputIndex(dependencyCaseIndex, "answer.pch")
        listOf(
            listOf("cases", dependencyCaseIndex.toString(), "inputs", dependencyInputIndex.toString(), "producerCaseId") to
                JsonPrimitive("missing-producer"),
            listOf("cases", dependencyCaseIndex.toString(), "inputs", dependencyInputIndex.toString(), "producerCaseId") to
                JsonPrimitive("pch-reuse-valid"),
            listOf("cases", dependencyCaseIndex.toString(), "inputs", dependencyInputIndex.toString(), "producerPath") to
                JsonPrimitive("wrong.pch"),
            listOf("cases", dependencyCaseIndex.toString(), "inputs", dependencyInputIndex.toString(), "targetPath") to
                JsonPrimitive("../answer.pch"),
        ).forEach { (path, replacement) ->
            fixture.write(replaceAt(validPlan(), path, replacement))
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception>(path.joinToString(".")) {
                fixture.verify()
            }
        }

        val literalCaseIndex = caseIndex("assemble-invalid")
        val literalInputIndex = 0
        fixture.write(
            replaceAt(
                validPlan(),
                listOf("cases", literalCaseIndex.toString(), "inputs", literalInputIndex.toString(), "base64"),
                JsonPrimitive(""),
            ),
        )
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val oldPchLiteral = JsonObject(
            mapOf(
                "base64" to JsonPrimitive(""),
                "bytes" to JsonPrimitive(0),
                "executable" to JsonPrimitive(false),
                "kind" to JsonPrimitive("literal"),
                "path" to JsonPrimitive("answer.pch"),
                "sha256" to JsonPrimitive(OLD_PCH_SHA256),
            ),
        )
        fixture.write(
            replaceAt(
                validPlan(),
                listOf("cases", dependencyCaseIndex.toString(), "inputs", dependencyInputIndex.toString()),
                oldPchLiteral,
            ),
        )
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val producerCaseIndex = caseIndex("precompile-header")
        fixture.write(replaceCase(validPlan(), producerCaseIndex) { case ->
            val arguments = (case["arguments"] as JsonArray).toMutableList()
            val outputFlag = arguments.indexOf(JsonPrimitive("-o"))
            val outputPath = arguments[outputFlag + 1]
            arguments[outputFlag + 1] = JsonPrimitive("unrelated.pch")
            arguments.add(outputPath)
            case + ("arguments" to JsonArray(arguments))
        })
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        fixture.write(replaceCase(validPlan(), dependencyCaseIndex) { case ->
            val arguments = (case["arguments"] as JsonArray).toMutableList()
            val includeFlag = arguments.indexOf(JsonPrimitive("-include-pch"))
            val includePath = arguments[includeFlag + 1]
            arguments[includeFlag + 1] = JsonPrimitive("unrelated.pch")
            arguments.add(includePath)
            case + ("arguments" to JsonArray(arguments))
        })
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val producerHeaderIndex = inputIndex(producerCaseIndex, "answer.h")
        val changedHeaderBytes = "#define ANSWER 43\n".toByteArray()
        val changedProducerHeader = replaceAt(
            validPlan(),
            listOf("cases", producerCaseIndex.toString(), "inputs", producerHeaderIndex.toString()),
            JsonObject(
                (((validPlan()["cases"] as JsonArray)[producerCaseIndex] as JsonObject)["inputs"] as JsonArray)
                    .let { it[producerHeaderIndex] as JsonObject } + mapOf(
                    "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(changedHeaderBytes)),
                    "bytes" to JsonPrimitive(changedHeaderBytes.size),
                    "sha256" to JsonPrimitive(OracleArtifacts.sha256(changedHeaderBytes)),
                ),
            ),
        )
        fixture.write(changedProducerHeader)
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val emptySha256 = OracleArtifacts.sha256(ByteArray(0))
        val injectedPch = JsonObject(
            mapOf(
                "base64" to JsonPrimitive(""),
                "bytes" to JsonPrimitive(0),
                "executable" to JsonPrimitive(false),
                "kind" to JsonPrimitive("literal"),
                "path" to JsonPrimitive("answer.pch"),
                "sha256" to JsonPrimitive(emptySha256),
            ),
        )
        fixture.write(replaceCase(validPlan(), producerCaseIndex) { case ->
            val inputs = case["inputs"] as JsonArray
            case + ("inputs" to JsonArray(inputs + injectedPch))
        })
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }

        val prefixConflict = JsonObject(injectedPch + ("path" to JsonPrimitive("answer.h/child")))
        fixture.write(replaceCase(validPlan(), producerCaseIndex) { case ->
            val inputs = case["inputs"] as JsonArray
            case + ("inputs" to JsonArray(inputs + prefixConflict))
        })
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
    }

    @Test
    fun `decoded literal and stdin bytes cannot conceal Python v1 or expected output material`() = withFixture { fixture ->
        listOf(
            "python expected-output",
            "oci-container-v1 behavior-preexec-v1",
            "sandbox exitCode stdoutSha256",
            OLD_IMAGE_SHA256,
        ).forEach { forbidden ->
            val bytes = forbidden.toByteArray()
            val case = (validPlan()["cases"] as JsonArray)[caseIndex("assemble-invalid")] as JsonObject
            val inputs = case["inputs"] as JsonArray
            val literal = inputs[0] as JsonObject
            val replacement = JsonObject(
                literal + mapOf(
                    "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes)),
                    "bytes" to JsonPrimitive(bytes.size),
                    "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
                ),
            )
            fixture.write(
                replaceAt(
                    validPlan(),
                    listOf("cases", caseIndex("assemble-invalid").toString(), "inputs", "0"),
                    replacement,
                ),
            )
            val failure = assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("forbidden encoded runtime or output material"))

            val stdin = JsonObject(
                mapOf(
                    "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(bytes)),
                    "bytes" to JsonPrimitive(bytes.size),
                    "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
                ),
            )
            fixture.write(
                replaceAt(
                    validPlan(),
                    listOf("cases", caseIndex("compile-stdin").toString(), "stdin"),
                    stdin,
                ),
            )
            val stdinFailure = assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
            assertTrue(stdinFailure.message.orEmpty().contains("forbidden encoded runtime or output material"))
        }
    }

    @Test
    fun `reviewed digest rejects otherwise self consistent case rewrites`() = withFixture { fixture ->
        val changed = replaceCase(validPlan(), 0) { case ->
            val arguments = case["arguments"] as JsonArray
            case + ("arguments" to JsonArray(arguments.mapIndexed { index, value ->
                if (index == 0) JsonPrimitive("-S") else value
            }))
        }
        fixture.write(changed)
        val failure = assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
        assertTrue(failure.message.orEmpty().contains("Kotlin-authored plan"), failure.message)
    }

    @Test
    fun `canonical raw path link size and permission constraints fail closed`() {
        assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> {
            LlvmBehaviorReferenceInputPlanV2Verifier.verify(Path.of(PLAN_FILE_NAME))
        }
        withFixture { fixture ->
            Files.write(fixture.plan, Files.readAllBytes(fixture.plan) + '\n'.code.toByte())
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            val wrongName = fixture.root.resolve("renamed-plan.json")
            Files.move(fixture.plan, wrongName)
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> {
                LlvmBehaviorReferenceInputPlanV2Verifier.verify(wrongName)
            }
        }
        withFixture { fixture ->
            val target = fixture.root.resolve("target-plan.json")
            Files.move(fixture.plan, target)
            Files.createSymbolicLink(fixture.plan, target.fileName)
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            val peer = fixture.root.resolve("peer-plan.json")
            Files.createLink(peer, fixture.plan)
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            val permissions = Files.getPosixFilePermissions(fixture.plan).toMutableSet()
            permissions += PosixFilePermission.GROUP_WRITE
            Files.setPosixFilePermissions(fixture.plan, permissions)
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.write(fixture.plan, ByteArray(1024 * 1024 + 1) { 'x'.code.toByte() })
            assertFailsWith<LlvmBehaviorReferenceInputPlanV2Exception> { fixture.verify() }
        }
    }

    @Test
    fun `public and reflective surfaces accept exactly one raw Path`() {
        val resultType = LlvmBehaviorReferenceInputPlanV2::class.java
        assertTrue(resultType.isSealed)
        val verify = LlvmBehaviorReferenceInputPlanV2Verifier::class.java.declaredMethods.single {
            it.name == "verify" && !it.isSynthetic
        }
        assertTrue(verify.parameterTypes.contentEquals(arrayOf(Path::class.java)))
        val implementations = LlvmBehaviorReferenceInputPlanV2Verifier::class.java.declaredClasses
            .filter(resultType::isAssignableFrom)
        assertEquals(1, implementations.size)
        assertTrue(Modifier.isPrivate(implementations.single().modifiers))
        assertTrue(resultType.permittedSubclasses.contentEquals(arrayOf(implementations.single())))
        assertFailsWith<IllegalArgumentException> {
            Proxy.newProxyInstance(resultType.classLoader, arrayOf(resultType)) { _, _, _ -> null }
        }
        val constructor = implementations.single().declaredConstructors.single()
        assertTrue(constructor.parameterTypes.contentEquals(arrayOf(Path::class.java)))
        constructor.isAccessible = true
        val failure = assertFailsWith<Exception> {
            constructor.newInstance(Path.of("/absent/$PLAN_FILE_NAME"))
        }
        assertTrue(failure.cause is LlvmBehaviorReferenceInputPlanV2Exception)
    }

    @Test
    fun `bundled schema remains closed independently of the pinned digest`() {
        val valid = validPlan()
        OracleSchemas.validate("llvm-behavior-reference-input-plan-v2", valid)
        assertTrue("llvm-behavior-reference-input-plan-v2" in OracleSchemas.supportedNames)

        assertFailsWith<OracleSchemaException> {
            OracleSchemas.validate(
                "llvm-behavior-reference-input-plan-v2",
                JsonObject(valid + ("extra" to JsonPrimitive(true))),
            )
        }
        assertFailsWith<OracleSchemaException> {
            OracleSchemas.validate(
                "llvm-behavior-reference-input-plan-v2",
                replaceCase(valid, 0) { case -> case + ("expected" to JsonObject(emptyMap())) },
            )
        }
        val literalCase = caseIndex("assemble-invalid")
        listOf(
            listOf("cases", literalCase.toString(), "inputs", "0", "path") to JsonPrimitive("../broken.s"),
            listOf("cases", literalCase.toString(), "inputs", "0", "path") to JsonPrimitive("a/../broken.s"),
            listOf("cases", literalCase.toString(), "inputs", "0", "path") to JsonPrimitive("/broken.s"),
            listOf("cases", literalCase.toString(), "inputs", "0", "executable") to JsonPrimitive(true),
            listOf("cases", literalCase.toString(), "environment") to
                JsonObject(mapOf("PATH" to JsonPrimitive("/untrusted"))),
        ).forEach { (path, replacement) ->
            assertFailsWith<OracleSchemaException>(path.joinToString(".")) {
                OracleSchemas.validate(
                    "llvm-behavior-reference-input-plan-v2",
                    replaceAt(valid, path, replacement),
                )
            }
        }
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        val root = createTempDirectory("llvm-reference-input-plan-v2-").toAbsolutePath().normalize()
        try {
            block(Fixture(root))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private class Fixture(val root: Path) {
        val plan: Path = root.resolve(PLAN_FILE_NAME)

        init {
            Files.copy(PRODUCTION_PLAN, plan, StandardCopyOption.COPY_ATTRIBUTES)
        }

        fun write(document: JsonElement) {
            Files.write(plan, OracleJson.canonicalBytes(document))
        }

        fun verify(): LlvmBehaviorReferenceInputPlanV2 = LlvmBehaviorReferenceInputPlanV2Verifier.verify(plan)
    }

    companion object {
        private const val PLAN_FILE_NAME = "behavior-reference-input-plan-v2.json"
        private const val EXPECTED_PLAN_SHA256 =
            "01424f3b14419b2da463c2c5aefbd89a81c03b11ac5847b750f79d72eb7e5d0d"
        private const val EXPECTED_SCHEMA_SHA256 =
            "e96f2bf456f363150a2ea8a9368831b534b413e8c1d1159c5994c3750c36ce23"
        private const val OLD_PCH_SHA256 =
            "5a1acc5f9935b186eec52fef608cf1e09bdb7477a88745d9daed8529b98f2e92"
        private const val OLD_IMAGE_SHA256 =
            "510c510f300d811df22c7769633575a94939073b529a73125bf96cfb96dc7248"
        private const val OLD_CONTROL_CLIENT_SHA256 =
            "e45381109c685311cf84c5e33a1aca7da81d6b55c0f9aed74091fc08c3a94f13"
        private val PRODUCTION_PLAN = Path.of("oracle/llvm/22.1.6/$PLAN_FILE_NAME")
            .toAbsolutePath().normalize()
    }
}

private fun validPlan(): JsonObject =
    OracleJson.parseCanonical(Files.readAllBytes(Path.of("oracle/llvm/22.1.6/behavior-reference-input-plan-v2.json")))
        as JsonObject

private fun JsonObject.objectField(name: String): JsonObject = getValue(name) as JsonObject

private fun JsonObject.stringField(name: String): String = (getValue(name) as JsonPrimitive).content

private fun walkObjects(element: JsonElement): List<JsonObject> = when (element) {
    is JsonObject -> listOf(element) + element.values.flatMap(::walkObjects)
    is JsonArray -> element.flatMap(::walkObjects)
    else -> emptyList()
}

private fun caseIndex(id: String): Int = ((validPlan()["cases"] as JsonArray)).indexOfFirst { element ->
    (element as JsonObject).stringField("id") == id
}.also { check(it >= 0) }

private fun inputIndex(caseIndex: Int, targetPath: String): Int {
    val case = ((validPlan()["cases"] as JsonArray)[caseIndex] as JsonObject)
    return (case["inputs"] as JsonArray).indexOfFirst { raw ->
        val input = raw as JsonObject
        val field = if (input.stringField("kind") == "literal") "path" else "targetPath"
        input.stringField(field) == targetPath
    }.also { check(it >= 0) }
}

private fun replaceCase(document: JsonObject, index: Int, transform: (JsonObject) -> Map<String, JsonElement>): JsonObject {
    val cases = document["cases"] as JsonArray
    val replacement = JsonObject(transform(cases[index] as JsonObject))
    return JsonObject(document + ("cases" to JsonArray(cases.mapIndexed { current, value ->
        if (current == index) replacement else value
    })))
}

private fun replaceAt(document: JsonElement, path: List<String>, replacement: JsonElement): JsonElement {
    require(path.isNotEmpty())
    return when (document) {
        is JsonObject -> {
            val head = path.first()
            val child = document.getValue(head)
            JsonObject(document + (head to if (path.size == 1) replacement else replaceAt(child, path.drop(1), replacement)))
        }
        is JsonArray -> {
            val index = path.first().toInt()
            JsonArray(document.mapIndexed { current, child ->
                if (current == index) {
                    if (path.size == 1) replacement else replaceAt(child, path.drop(1), replacement)
                } else {
                    child
                }
            })
        }
        else -> error("cannot descend through a primitive")
    }
}
