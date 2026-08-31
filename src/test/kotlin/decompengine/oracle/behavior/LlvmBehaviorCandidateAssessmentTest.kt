package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.Modifier
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.BasicFileAttributeView
import java.nio.file.attribute.FileTime
import java.nio.file.attribute.PosixFilePermission
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorCandidateAssessmentTest {
    @Test
    fun `matching caller observations remain explicitly non-authoritative and immutable`() = withFixture { fixture ->
        val assessment = fixture.assess()

        assertEquals("non-authoritative-caller-supplied-observations-v1", assessment.authority)
        assertFalse(assessment.releaseEligible)
        assertEquals(48, assessment.observedCases)
        assertEquals(48, assessment.matchingObservedCases)
        assertEquals(0, assessment.mismatchingObservedCases)
        assertEquals(0, assessment.notRunCases)
        assertEquals(0, assessment.infrastructureFailedCases)
        assertTrue(assessment.mismatches.isEmpty())
        assertEquals(EXPECTED_CORPUS_SHA256, assessment.referenceCorpusSha256)
        assertEquals(EXPECTED_REPORT_SHA256, assessment.referenceReportSha256)
        assertEquals(EXPECTED_MATRIX_SHA256, assessment.referenceDiagnosticMatrixSha256)
        assertEquals(EXPECTED_MATRIX_SELF_SHA256, assessment.referenceDiagnosticMatrixSelfSha256)
        assertEquals(EXPECTED_MANIFEST_SHA256, assessment.referenceArtifactManifestSha256)
        assertEquals(EXPECTED_SANDBOX_SHA256, assessment.referenceSandboxSha256)
        assertEquals(EXPECTED_OWNERSHIP_SHA256, assessment.ownershipSha256)
        assertEquals(OracleArtifacts.sha256(assessment.canonicalBytes), assessment.assessmentSha256)
        assertTrue(assessment.operatorSummary.startsWith("NON-AUTHORITATIVE"))
        assertTrue(assessment.operatorSummary.contains("releaseEligible=false"))

        val bytes = assessment.canonicalBytes
        bytes[0] = 0
        assertNotEquals(0, assessment.canonicalBytes[0])
        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (assessment.mismatches as MutableList<LlvmBehaviorCandidateMismatch>).clear()
        }

        val document = OracleJson.parseCanonical(
            assessment.canonicalBytes,
            jsonLimits(16 * 1024 * 1024),
        ) as JsonObject
        OracleSchemas.validate("llvm-behavior-comparison-assessment", document)
        assertEquals(JsonPrimitive(false), document["releaseEligible"])
        assertEquals(JsonPrimitive("non-authoritative-caller-supplied-observations-v1"), document["authority"])
    }

    @Test
    fun `all closed observable kinds and both unavailable statuses are derived`() = withFixture { fixture ->
        fixture.mutateObservations { root ->
            root
                .changeCase("compile-file") { case -> case.with("exitCode", JsonPrimitive(1)) }
                .changeCase("compile-c-standard") { case -> case.with("stdout", blob("stdout differs".encodeToByteArray())) }
                .changeCase("compile-cxx-standard") { case -> case.with("stderr", blob("stderr differs".encodeToByteArray())) }
                .changeArtifact("compile-file", "source.o") { artifact ->
                    artifact
                        .withBlob("candidate object".encodeToByteArray())
                        .with("mode", JsonPrimitive("0o600"))
                }
                .changeArtifact("assemble-valid", "answer.o") { artifact -> absentArtifact(artifact.string("path")) }
                .changeCase("help-driver") { case ->
                    case.with(
                        "artifacts",
                        JsonArray(listOf(presentArtifact("extra.bin", "extra".encodeToByteArray(), "0o600"))),
                    )
                }
                .changeCase("diagnostic-color-always") { case -> unavailableCase(case.string("id"), "not-run", "not-requested") }
                .changeCase("diagnostic-color-never") { case ->
                    unavailableCase(case.string("id"), "infrastructure-failed", "sandbox-failed")
                }
        }

        val assessment = fixture.assess()
        assertEquals(46, assessment.observedCases)
        assertEquals(1, assessment.notRunCases)
        assertEquals(1, assessment.infrastructureFailedCases)
        assertEquals(5, assessment.mismatchingObservedCases)
        assertEquals(
            setOf(
                "execution",
                "exitCode",
                "stdout",
                "stderr",
                "artifact-presence",
                "artifact-content",
                "artifact-mode",
                "unexpected-artifact",
            ),
            assessment.mismatches.map { it.kind }.toSet(),
        )
        val execution = assessment.mismatches.filter { it.kind == "execution" }
        assertEquals(2, execution.size)
        assertEquals(setOf("not-requested", "sandbox-failed"), execution.mapNotNull { it.failureCode }.toSet())
        assertTrue(assessment.mismatches.zipWithNext().all { (left, right) -> left.mismatchId < right.mismatchId })
        assertEquals(assessment.mismatches.size, assessment.mismatches.map { it.mismatchId }.toSet().size)
    }

    @Test
    fun `diagnostic exit stdout stderr reuse exact matrix identities and order stays reserved`() = withFixture { fixture ->
        fixture.mutateObservations { root ->
            root.changeCase("diagnostic-syntax") { case ->
                case
                    .with("exitCode", JsonPrimitive(0))
                    .with("stdout", blob("unexpected stdout".encodeToByteArray()))
                    .with("stderr", blob("different wording".encodeToByteArray()))
            }
        }
        val assessment = fixture.assess()
        val byKind = assessment.mismatches.associateBy { it.kind }
        assertEquals(diagnosticId("diagnostic-syntax", "exitCode"), byKind.getValue("exitCode").mismatchId)
        assertEquals(diagnosticId("diagnostic-syntax", "stdout"), byKind.getValue("stdout").mismatchId)
        assertEquals(diagnosticId("diagnostic-syntax", "stderr"), byKind.getValue("stderr").mismatchId)
        assertFalse(assessment.mismatches.any { it.mismatchId == diagnosticId("diagnostic-syntax", "order") })
        assertFalse(assessment.mismatches.any { it.kind == "order" })
    }

    @Test
    fun `general mismatch IDs are stable across candidate revisions repetitions and status reasons`() {
        val first = withFixtureResult("candidate revision one".encodeToByteArray()) { fixture ->
            fixture.mutateObservations { it.changeCase("compile-file") { case -> case.with("exitCode", JsonPrimitive(1)) } }
            val one = fixture.assess()
            val repeated = fixture.assess()
            assertContentEquals(one.canonicalBytes, repeated.canonicalBytes)
            assertEquals(one.operatorSummary, repeated.operatorSummary)
            one.mismatches.single().mismatchId
        }
        val second = withFixtureResult("candidate revision two".encodeToByteArray()) { fixture ->
            fixture.mutateObservations { it.changeCase("compile-file") { case -> case.with("exitCode", JsonPrimitive(1)) } }
            fixture.assess().mismatches.single().mismatchId
        }
        assertEquals(first, second)

        val statusIds = withFixtureResult { fixture ->
            fixture.mutateObservations { root ->
                root.changeCase("compile-file") { case -> unavailableCase(case.string("id"), "not-run", "not-requested") }
            }
            val notRun = fixture.assess().mismatches.single().mismatchId
            fixture.mutateObservations { root ->
                root.changeCase("compile-file") { case ->
                    unavailableCase(case.string("id"), "infrastructure-failed", "runner-failed")
                }
            }
            notRun to fixture.assess().mismatches.single().mismatchId
        }
        assertEquals(statusIds.first, statusIds.second)
    }

    @Test
    fun `length framing and closed kinds keep collision fixtures distinct`() {
        val fixtures = buildList {
            LlvmBehaviorCandidateMismatchKind.entries.forEach { kind ->
                add(
                    llvmBehaviorCandidateMismatchId(
                        EXPECTED_CORPUS_SHA256,
                        "compile-file",
                        kind,
                        if (kind.name.startsWith("ARTIFACT") || kind == LlvmBehaviorCandidateMismatchKind.UNEXPECTED_ARTIFACT) {
                            "a/bc"
                        } else {
                            null
                        },
                    ),
                )
            }
            add(
                llvmBehaviorCandidateMismatchId(
                    EXPECTED_CORPUS_SHA256,
                    "compile-stdin",
                    LlvmBehaviorCandidateMismatchKind.ARTIFACT_CONTENT,
                    "a/bc",
                ),
            )
            add(
                llvmBehaviorCandidateMismatchId(
                    EXPECTED_CORPUS_SHA256,
                    "compile-file",
                    LlvmBehaviorCandidateMismatchKind.ARTIFACT_CONTENT,
                    "a/b/c",
                ),
            )
        }
        assertEquals(fixtures.size, fixtures.toSet().size)
        assertTrue(fixtures.all { it.matches(Regex("clang-behavior-[0-9a-f]{32}")) })
        assertFailsWith<IllegalArgumentException> {
            llvmBehaviorCandidateMismatchId(
                EXPECTED_CORPUS_SHA256,
                "compile-file",
                LlvmBehaviorCandidateMismatchKind.ARTIFACT_CONTENT,
                null,
            )
        }
    }

    @Test
    fun `malformed blob and artifact triples reject while differing valid bytes mismatch`() {
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.changeCase("compile-file") { case ->
                    case.with(
                        "stdout",
                        blob(byteArrayOf(0xff.toByte())).with("base64", JsonPrimitive("/x==")),
                    )
                }
            }
            fixture.assertFailure("not canonical")
        }
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.changeCase("compile-file") { case ->
                    case.with("stdout", blob(ByteArray(0)).with("base64", JsonPrimitive("AAAA")))
                }
            }
            fixture.assertFailure("base64 length differs")
        }
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.changeArtifact("compile-file", "source.o") { artifact ->
                    artifact.withBlob("different but valid".encodeToByteArray())
                }
            }
            val mismatch = fixture.assess().mismatches.single()
            assertEquals("artifact-content", mismatch.kind)
            assertEquals("source.o", mismatch.artifactPath)
        }
    }

    @Test
    fun `exact 48 case denominator and reviewed ownership have no fallback`() {
        withFixture { fixture ->
            fixture.mutateObservations { root -> root.with("cases", JsonArray(root.array("cases").dropLast(1))) }
            fixture.assertFailure("schema validation")
        }
        withFixture { fixture ->
            fixture.mutateObservations { root -> root.with("cases", JsonArray(root.array("cases").reversed())) }
            fixture.assertFailure("membership or order")
        }
        withFixture { fixture ->
            fixture.mutateOwnership { ownership ->
                ownership.changeOwnership("compile-file", "fallback-owner")
            }
            fixture.assertFailure("reviewed artifact")
        }
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.changeCase("compile-file") { case -> case.with("exitCode", JsonPrimitive(1)) }
            }
            assertEquals("clang-codegen", fixture.assess().mismatches.single().ownerSubsystem)
        }
    }

    @Test
    fun `canonical duplicate depth and node limits fail before comparison`() {
        withFixture { fixture ->
            Files.write(fixture.observations, Files.readAllBytes(fixture.observations).dropLast(1).toByteArray())
            fixture.assertFailure("strict canonical bounded JSON")
        }
        withFixture { fixture ->
            val text = Files.readString(fixture.observations)
            Files.writeString(fixture.observations, text.replaceFirst("{\n", "{\n  \"schemaVersion\": 1,\n"))
            fixture.assertFailure("strict canonical bounded JSON")
        }
        withFixture { fixture ->
            var nested: JsonElement = JsonNull
            repeat(40) { nested = JsonArray(listOf(nested)) }
            val root = fixture.readObservations().with("tooDeep", nested)
            Files.write(fixture.observations, OracleJson.canonicalBytes(root, largeJsonLimits()))
            fixture.assertFailure("strict canonical bounded JSON")
        }
        withFixture { fixture ->
            val nodes = JsonArray(List(100_001) { JsonNull })
            val root = fixture.readObservations().with("tooMany", nodes)
            Files.write(fixture.observations, OracleJson.canonicalBytes(root, largeJsonLimits()))
            fixture.assertFailure("strict canonical bounded JSON")
        }
    }

    @Test
    fun `predecode aggregate and UTF-8 path bounds fail closed`() {
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.changeCase("compile-file") { case ->
                    case.with("stdout", blob(ByteArray(0)).with("base64", JsonPrimitive("AAAA")))
                }
            }
            fixture.assertFailure("base64 length differs")
        }
        withFixture { fixture ->
            val sixteenMiB = ByteArray(16 * 1024 * 1024) { 0x41 }
            val oneMiB = ByteArray(1024 * 1024 + 1) { 0x42 }
            fixture.mutateObservations(maximumBytes = 64 * 1024 * 1024) { root ->
                root
                    .changeCase("compile-file") { case -> case.with("stdout", blob(sixteenMiB)) }
                    .changeCase("compile-stdin") { case -> case.with("stdout", blob(sixteenMiB)) }
                    .changeCase("compile-c-standard") { case -> case.with("stdout", blob(oneMiB)) }
            }
            fixture.assertFailure("aggregate decoded-byte limit")
        }
        withFixture { fixture ->
            val oversizedUtf8Path = "é".repeat(2049)
            fixture.mutateObservations { root ->
                root.changeCase("help-driver") { case ->
                    case.with(
                        "artifacts",
                        JsonArray(listOf(presentArtifact(oversizedUtf8Path, byteArrayOf(1), "0o600"))),
                    )
                }
            }
            fixture.assertFailure("bounded normalized relative POSIX path")
        }
        listOf(".", "..", "dir/.", "dir/..").forEach { hostilePath ->
            withFixture { fixture ->
                fixture.mutateObservations { root ->
                    root.changeCase("help-driver") { case ->
                        case.with(
                            "artifacts",
                            JsonArray(listOf(presentArtifact(hostilePath, byteArrayOf(1), "0o600"))),
                        )
                    }
                }
                fixture.assertFailure("schema validation")
            }
        }
    }

    @Test
    fun `candidate executable identity and all reference cross bindings fail closed`() {
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.replaceObject("candidateExecutable") { it.with("sha256", JsonPrimitive("0".repeat(64))) }
            }
            fixture.assertFailure("exact candidate executable bytes")
        }
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.replaceObject("reference") { it.with("corpusSha256", JsonPrimitive("0".repeat(64))) }
            }
            fixture.assertFailure("fixed value")
        }
        withFixture { fixture ->
            fixture.mutateObservations { root ->
                root.replaceObject("reference") { it.with("sandboxSha256", JsonPrimitive("0".repeat(64))) }
            }
            fixture.assertFailure("fixed value")
        }
        listOf(
            "reportSha256",
            "diagnosticMatrixSha256",
            "diagnosticMatrixSelfSha256",
            "artifactManifestSha256",
        ).forEach { field ->
            withFixture { fixture ->
                fixture.mutateObservations { root ->
                    root.replaceObject("reference") { it.with(field, JsonPrimitive("0".repeat(64))) }
                }
                fixture.assertFailure("fixed value")
            }
        }
        withFixture { fixture ->
            Files.write(fixture.executable, "replacement candidate".encodeToByteArray())
            fixture.assertFailure("exact candidate executable bytes")
        }
    }

    @Test
    fun `candidate executable and parent reject group or other writers`() {
        withFixture { fixture ->
            val permissions = Files.getPosixFilePermissions(fixture.executable).toMutableSet()
            permissions += PosixFilePermission.GROUP_WRITE
            Files.setPosixFilePermissions(fixture.executable, permissions)
            fixture.assertFailure("may not be writable by group or other")
        }
        withFixture { fixture ->
            val permissions = Files.getPosixFilePermissions(fixture.root).toMutableSet()
            permissions += PosixFilePermission.OTHERS_WRITE
            Files.setPosixFilePermissions(fixture.root, permissions)
            fixture.assertFailure("may not be writable by group or other")
        }
    }

    @Test
    fun `candidate executable terminal reauthentication rejects a post-observation mutation`() = withFixture { fixture ->
        val view = Files.getFileAttributeView(fixture.observations, BasicFileAttributeView::class.java)
        view.setTimes(null, FileTime.from(Instant.EPOCH), null)
        val mutated = AtomicBoolean(false)
        val stop = AtomicBoolean(false)
        val worker = thread(start = true, name = "candidate-terminal-mutation") {
            while (!stop.get()) {
                val access = Files.readAttributes(fixture.observations, java.nio.file.attribute.BasicFileAttributes::class.java)
                    .lastAccessTime()
                if (access.toInstant() != Instant.EPOCH) {
                    Files.write(fixture.executable, "post-observation mutation".encodeToByteArray())
                    mutated.set(true)
                    return@thread
                }
                Thread.onSpinWait()
            }
        }
        try {
            val failure = assertFailsWith<LlvmBehaviorCandidateAssessmentException> { fixture.assess() }
            assertTrue(mutated.get(), "filesystem did not expose the observation access needed by the race fixture")
            assertTrue(
                failure.message.orEmpty().contains("candidate executable") ||
                    failure.message.orEmpty().contains("exact candidate executable bytes"),
                failure.message,
            )
        } finally {
            stop.set(true)
            worker.join(5_000)
        }
    }

    @Test
    fun `sealed JVM assessment construction accepts only seven raw paths`() = withFixture { fixture ->
        assertTrue(LlvmBehaviorCandidateAssessment::class.java.isSealed)
        assertTrue(LlvmBehaviorCandidateMismatch::class.java.isSealed)
        val implementations = LlvmBehaviorCandidateAssessment::class.java.permittedSubclasses.toList()
        assertEquals(1, implementations.size)
        val rawPaths = List(7) { Path::class.java }
        implementations.single().declaredConstructors.forEach { constructor ->
            assertEquals(
                rawPaths,
                constructor.parameterTypes.filterNot { it.name == "kotlin.jvm.internal.DefaultConstructorMarker" },
                constructor.toGenericString(),
            )
        }
        LlvmBehaviorCandidateAssessmentVerifier::class.java.declaredMethods.filter { method ->
            !Modifier.isPrivate(method.modifiers) &&
                LlvmBehaviorCandidateAssessment::class.java.isAssignableFrom(method.returnType)
        }.forEach { method ->
            assertEquals(rawPaths, method.parameterTypes.toList(), method.toGenericString())
        }
        val forbidden = setOf(
            JsonElement::class.java,
            JsonObject::class.java,
            ByteArray::class.java,
            String::class.java,
            Map::class.java,
        )
        LlvmBehaviorCandidateAssessmentVerifier::class.java.declaredMethods.filter { method ->
            LlvmBehaviorCandidateAssessment::class.java.isAssignableFrom(method.returnType)
        }.forEach { method ->
            assertTrue(method.parameterTypes.none(forbidden::contains), method.toGenericString())
        }

        val assessment = fixture.assess()
        val canonical = assessment.canonicalBytes
        canonical.fill(0)
        assertNotEquals("0".repeat(64), assessment.assessmentSha256)
    }

    @Test
    fun `schemas and production implementation contain no runner or Python authority`() {
        setOf(
            "llvm-behavior-candidate-observations",
            "llvm-behavior-case-ownership",
            "llvm-behavior-comparison-assessment",
        ).forEach { name -> assertTrue(name in OracleSchemas.supportedNames) }
        val ownership = readCanonicalObject(OWNERSHIP, 256 * 1024)
        OracleSchemas.validate("llvm-behavior-case-ownership", ownership)
        assertEquals(48, ownership.array("cases").size)

        val production = Files.readString(
            REPOSITORY_ROOT.resolve("src/main/kotlin/decompengine/oracle/behavior/LlvmBehaviorCandidateAssessment.kt"),
        )
        assertFalse(production.contains("ProcessBuilder"))
        assertFalse(production.contains("python", ignoreCase = true))
        assertFalse(production.contains("publishAtomically"))
    }

    private inner class Fixture(
        val root: Path,
        val executable: Path,
        val observations: Path,
        val ownership: Path,
    ) {
        fun assess(): LlvmBehaviorCandidateAssessment = LlvmBehaviorCandidateAssessmentVerifier.assess(
            PROFILE.resolve("behavior-corpus.json"),
            PROFILE.resolve("behavior-corpus-evidence.json"),
            PROFILE.resolve("diagnostic-matrix.json"),
            PROFILE.resolve("oracle-manifest.json"),
            executable,
            observations,
            ownership,
        )

        fun assertFailure(expected: String) {
            val failure = assertFailsWith<LlvmBehaviorCandidateAssessmentException> { assess() }
            assertTrue(failure.message.orEmpty().contains(expected), failure.message)
        }

        fun readObservations(): JsonObject = readCanonicalObject(observations, 64 * 1024 * 1024)

        fun mutateObservations(
            maximumBytes: Int = 64 * 1024 * 1024,
            change: (JsonObject) -> JsonObject,
        ) {
            val changed = change(readObservations())
            Files.write(observations, OracleJson.canonicalBytes(changed, jsonLimits(maximumBytes)))
        }

        fun mutateOwnership(change: (JsonObject) -> JsonObject) {
            val changed = change(readCanonicalObject(ownership, 256 * 1024))
            Files.write(ownership, OracleJson.canonicalBytes(changed, jsonLimits(256 * 1024)))
        }
    }

    private fun withFixture(
        executableBytes: ByteArray = "candidate executable revision".encodeToByteArray(),
        action: (Fixture) -> Unit,
    ) {
        withFixtureResult(executableBytes) { fixture ->
            action(fixture)
            Unit
        }
    }

    private fun <T> withFixtureResult(
        executableBytes: ByteArray = "candidate executable revision".encodeToByteArray(),
        action: (Fixture) -> T,
    ): T {
        val root = Files.createTempDirectory("llvm-candidate-assessment-test-")
        try {
            val executable = root.resolve("candidate-clang")
            Files.write(executable, executableBytes)
            val ownership = root.resolve("behavior-case-ownership.json")
            Files.copy(OWNERSHIP, ownership, StandardCopyOption.COPY_ATTRIBUTES)
            val observations = root.resolve("candidate-observations.json")
            Files.write(observations, matchingObservation(executableBytes))
            return action(Fixture(root, executable, observations, ownership))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun matchingObservation(executableBytes: ByteArray): ByteArray {
        val report = readCanonicalObject(PROFILE.resolve("behavior-corpus-evidence.json"), 64 * 1024 * 1024)
        val cases = report.array("cases").map { raw ->
            val case = raw as JsonObject
            JsonObject(
                linkedMapOf(
                    "id" to case.getValue("id"),
                    "status" to JsonPrimitive("observed"),
                    "exitCode" to case.getValue("exitCode"),
                    "stdout" to stripNormalizations(case.objectValue("stdout")),
                    "stderr" to stripNormalizations(case.objectValue("stderr")),
                    "artifacts" to case.getValue("artifacts"),
                ),
            )
        }
        val document = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "reference" to JsonObject(
                    linkedMapOf(
                        "corpusId" to JsonPrimitive("clang-22-1-6-driver-behavior"),
                        "corpusSha256" to JsonPrimitive(EXPECTED_CORPUS_SHA256),
                        "reportSha256" to JsonPrimitive(EXPECTED_REPORT_SHA256),
                        "diagnosticMatrixSha256" to JsonPrimitive(EXPECTED_MATRIX_SHA256),
                        "diagnosticMatrixSelfSha256" to JsonPrimitive(EXPECTED_MATRIX_SELF_SHA256),
                        "artifactManifestSha256" to JsonPrimitive(EXPECTED_MANIFEST_SHA256),
                        "sandboxSha256" to JsonPrimitive(EXPECTED_SANDBOX_SHA256),
                    ),
                ),
                "candidateExecutable" to JsonObject(
                    linkedMapOf(
                        "bytes" to JsonPrimitive(executableBytes.size),
                        "sha256" to JsonPrimitive(OracleArtifacts.sha256(executableBytes)),
                    ),
                ),
                "cases" to JsonArray(cases),
            ),
        )
        OracleSchemas.validate("llvm-behavior-candidate-observations", document)
        return OracleJson.canonicalBytes(document, jsonLimits(64 * 1024 * 1024))
    }

    private fun stripNormalizations(blob: JsonObject): JsonObject = JsonObject(blob.filterKeys { it != "normalizations" })

    private fun blob(content: ByteArray): JsonObject = JsonObject(
        linkedMapOf(
            "bytes" to JsonPrimitive(content.size),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(content)),
            "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(content)),
        ),
    )

    private fun presentArtifact(path: String, content: ByteArray, mode: String): JsonObject = JsonObject(
        linkedMapOf(
            "path" to JsonPrimitive(path),
            "present" to JsonPrimitive(true),
            "bytes" to JsonPrimitive(content.size),
            "sha256" to JsonPrimitive(OracleArtifacts.sha256(content)),
            "base64" to JsonPrimitive(Base64.getEncoder().encodeToString(content)),
            "mode" to JsonPrimitive(mode),
        ),
    )

    private fun absentArtifact(path: String): JsonObject = JsonObject(
        linkedMapOf(
            "path" to JsonPrimitive(path),
            "present" to JsonPrimitive(false),
            "bytes" to JsonNull,
            "sha256" to JsonNull,
            "base64" to JsonNull,
            "mode" to JsonNull,
        ),
    )

    private fun unavailableCase(id: String, status: String, failureCode: String): JsonObject = JsonObject(
        linkedMapOf(
            "id" to JsonPrimitive(id),
            "status" to JsonPrimitive(status),
            "failureCode" to JsonPrimitive(failureCode),
        ),
    )

    private fun diagnosticId(caseId: String, field: String): String =
        "clang-diagnostic-${OracleArtifacts.sha256("$caseId:$field".encodeToByteArray()).take(32)}"

    private fun readCanonicalObject(path: Path, maximumBytes: Int): JsonObject =
        OracleJson.parseCanonical(Files.readAllBytes(path), jsonLimits(maximumBytes)) as JsonObject

    private fun jsonLimits(maximumBytes: Int): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 96,
        maximumNodes = 500_000,
        maximumStringBytes = maximumBytes,
        maximumTotalStringBytes = maximumBytes,
        maximumNumberCharacters = 64,
    )

    private fun largeJsonLimits(): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = 64 * 1024 * 1024,
        maximumCanonicalBytes = 64 * 1024 * 1024,
        maximumDepth = 128,
        maximumNodes = 250_000,
        maximumStringBytes = 64 * 1024 * 1024,
        maximumTotalStringBytes = 64 * 1024 * 1024,
        maximumNumberCharacters = 64,
    )

    private fun JsonObject.changeCase(id: String, change: (JsonObject) -> JsonObject): JsonObject {
        val changed = array("cases").map { raw ->
            val case = raw as JsonObject
            if (case.string("id") == id) change(case) else case
        }
        return with("cases", JsonArray(changed))
    }

    private fun JsonObject.changeArtifact(
        caseId: String,
        path: String,
        change: (JsonObject) -> JsonObject,
    ): JsonObject = changeCase(caseId) { case ->
        val artifacts = case.array("artifacts").map { raw ->
            val artifact = raw as JsonObject
            if (artifact.string("path") == path) change(artifact) else artifact
        }
        case.with("artifacts", JsonArray(artifacts))
    }

    private fun JsonObject.changeOwnership(caseId: String, owner: String): JsonObject {
        val cases = array("cases").map { raw ->
            val case = raw as JsonObject
            if (case.string("id") == caseId) case.with("ownerSubsystem", JsonPrimitive(owner)) else case
        }
        return with("cases", JsonArray(cases))
    }

    private fun JsonObject.withBlob(content: ByteArray): JsonObject =
        this
            .with("bytes", JsonPrimitive(content.size))
            .with("sha256", JsonPrimitive(OracleArtifacts.sha256(content)))
            .with("base64", JsonPrimitive(Base64.getEncoder().encodeToString(content)))

    private fun JsonObject.with(name: String, value: JsonElement): JsonObject = JsonObject(this + (name to value))

    private fun JsonObject.replaceObject(name: String, change: (JsonObject) -> JsonObject): JsonObject =
        with(name, change(objectValue(name)))

    private fun JsonObject.objectValue(name: String): JsonObject = getValue(name) as JsonObject
    private fun JsonObject.array(name: String): JsonArray = getValue(name) as JsonArray
    private fun JsonObject.string(name: String): String = (getValue(name) as JsonPrimitive).content

    private companion object {
        val REPOSITORY_ROOT: Path = Path.of("").toAbsolutePath().normalize()
        val PROFILE: Path = REPOSITORY_ROOT.resolve("oracle/llvm/22.1.6")
        val OWNERSHIP: Path = PROFILE.resolve("behavior-case-ownership.json")
        const val EXPECTED_CORPUS_SHA256 = "acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b"
        const val EXPECTED_REPORT_SHA256 = "e9595bfd941c406d2c8fff618986e60dc0b810f1c384848b3ba540020ca00a6f"
        const val EXPECTED_MATRIX_SHA256 = "9e3b3223e014de49e0df50892556ae4649f819d5571751378ed9bfd12d684b2d"
        const val EXPECTED_MATRIX_SELF_SHA256 = "fc8145038141fca072d506391b4d93311aa3842ea6bfa088285c5dce7943ed3b"
        const val EXPECTED_MANIFEST_SHA256 = "5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40"
        const val EXPECTED_SANDBOX_SHA256 = "e4991450d10843e2fce6bc430a8876682fd831b3c4768b7fb757d7ee158638fa"
        const val EXPECTED_OWNERSHIP_SHA256 = "f403a57b1712df43d7043b3593f38aa705005136edfd97a78691e273c9a46c5f"
    }
}
