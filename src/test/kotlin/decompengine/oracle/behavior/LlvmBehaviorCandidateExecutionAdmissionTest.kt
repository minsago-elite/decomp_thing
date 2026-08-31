package decompengine.oracle.behavior

import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.Modifier
import java.nio.file.FileVisitResult
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.SimpleFileVisitor
import java.nio.file.attribute.BasicFileAttributes
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
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
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class LlvmBehaviorCandidateExecutionAdmissionTest {
    @Test
    fun `pre-START receipt binds exact raw inputs and publishes immutable non-release evidence`() =
        withFixture { fixture ->
            val marker = fixture.root.resolve("candidate-ran")
            fixture.writeCandidate(markerScript(marker))
            val admission = fixture.publish()

            assertEquals("kotlin-host-pre-start-binding-v1", admission.authority)
            assertEquals("pre-start", admission.phase)
            assertFalse(admission.startAuthorized)
            assertFalse(admission.executionClaimed)
            assertFalse(admission.scoringAuthority)
            assertFalse(admission.releaseEligible)
            assertEquals(Files.size(fixture.candidate), admission.candidateExecutableBytes)
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(fixture.candidate)), admission.candidateExecutableSha256)
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(fixture.corpus)), admission.corpusSha256)
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(fixture.report)), admission.referenceReportSha256)
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(fixture.matrix)), admission.diagnosticMatrixSha256)
            assertEquals(OracleArtifacts.sha256(Files.readAllBytes(fixture.manifest)), admission.artifactManifestSha256)
            assertEquals(48, admission.caseCount)
            assertEquals(OracleArtifacts.sha256(admission.canonicalBytes), admission.admissionSha256)
            assertTrue(admission.operatorSummary.startsWith("PRE-START ONLY"))
            assertTrue(admission.operatorSummary.contains("releaseEligible=false"))
            assertFalse(Files.exists(marker, LinkOption.NOFOLLOW_LINKS))
            assertContentEquals(admission.canonicalBytes, Files.readAllBytes(fixture.output))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(fixture.output, LinkOption.NOFOLLOW_LINKS),
            )

            val exposed = admission.canonicalBytes
            exposed.fill(0)
            assertNotEquals(0, admission.canonicalBytes[0])
            val document = parseAdmission(admission.canonicalBytes)
            OracleSchemas.validate("llvm-behavior-candidate-execution-admission", document)
            assertEquals(48, document.getValue("command").jsonObject.getValue("caseBindings").jsonArray.size)
        }

    @Test
    fun `receipt exposes no readable oracle expectation and all execution outcomes remain unobserved`() =
        withFixture { fixture ->
            val marker = fixture.root.resolve("must-not-run")
            fixture.writeCandidate(markerScript(marker))
            val admission = fixture.publish()
            val document = parseAdmission(admission.canonicalBytes)
            val text = admission.canonicalBytes.decodeToString()

            assertFalse(Files.exists(marker, LinkOption.NOFOLLOW_LINKS))
            assertFalse(text.contains("\"expected\""))
            assertFalse(text.contains("broken.o"))
            assertFalse(text.contains("invalid instruction mnemonic"))
            assertFalse(text.contains(EXPECTED_STDERR_SHA256))
            val execution = document.getValue("execution").jsonObject
            assertEquals("pre-start", execution.getValue("phase").jsonPrimitive.content)
            assertFalse(execution.getValue("startAuthorized").jsonPrimitive.boolean)
            assertFalse(execution.getValue("candidateExecuted").jsonPrimitive.boolean)
            listOf(
                "caseResults",
                "exitCode",
                "signal",
                "timedOut",
                "resourceExhausted",
                "capturedStdoutBytes",
                "capturedStderrBytes",
                "capturedArtifactBytes",
                "candidateOutputsSha256",
            ).forEach { field -> assertEquals(JsonNull, execution[field], field) }
            assertFalse(document.getValue("oracleExpectationsExposed").jsonPrimitive.boolean)
            assertFalse(document.getValue("executionClaimed").jsonPrimitive.boolean)
            assertFalse(document.getValue("scoringAuthority").jsonPrimitive.boolean)
            assertFalse(document.getValue("releaseEligible").jsonPrimitive.boolean)

            val authentication = document.getValue("referenceAuthentication").jsonObject
            assertEquals(admission.referenceReportSha256, authentication.string("referenceReportSha256"))
            assertEquals(admission.diagnosticMatrixSha256, authentication.string("diagnosticMatrixSha256"))
            assertEquals(admission.diagnosticMatrixSelfSha256, authentication.string("diagnosticMatrixSelfSha256"))
            assertEquals(admission.artifactManifestSha256, authentication.string("artifactManifestSha256"))
        }

    @Test
    fun `candidate substitution changes every command binding and cannot replace an admitted receipt`() =
        withFixture { fixture ->
            fixture.writeCandidate("#!/bin/sh\nexit 17\n".encodeToByteArray())
            val first = fixture.publish()
            val firstBytes = first.canonicalBytes
            val firstCommands = commandDigests(firstBytes)

            val secondOutput = fixture.newOutput("second")
            val repeated = fixture.publish(secondOutput)
            assertContentEquals(firstBytes, repeated.canonicalBytes)

            fixture.writeCandidate("#!/bin/sh\nexit 23\n".encodeToByteArray())
            val thirdOutput = fixture.newOutput("third")
            val changed = fixture.publish(thirdOutput)
            assertNotEquals(first.candidateExecutableSha256, changed.candidateExecutableSha256)
            assertNotEquals(firstCommands, commandDigests(changed.canonicalBytes))
            assertEquals(first.inputProjectionSha256, changed.inputProjectionSha256)

            assertFailsWith<LlvmBehaviorCandidateExecutionAdmissionException> {
                fixture.publish()
            }
            assertContentEquals(firstBytes, Files.readAllBytes(fixture.output))
        }

    @Test
    fun `candidate and output aliases symlinks hard links and unsafe permissions fail closed`() {
        withFixture { fixture ->
            Files.delete(fixture.candidate)
            Files.createSymbolicLink(fixture.candidate, fixture.root.relativize(fixture.root.resolve("candidate-real")))
            fixture.writeCandidateAt(fixture.root.resolve("candidate-real"), "#!/bin/sh\nexit 0\n".encodeToByteArray())
            fixture.assertFailure()
        }
        withFixture { fixture ->
            Files.delete(fixture.candidate)
            Files.createLink(fixture.candidate, fixture.corpus)
            fixture.assertFailure()
        }
        withFixture { fixture ->
            Files.setPosixFilePermissions(fixture.candidate, PosixFilePermissions.fromString("rwxrwx---"))
            fixture.assertFailure()
        }
        withFixture { fixture ->
            Files.createLink(fixture.output, fixture.candidate)
            fixture.assertFailure()
        }
        withFixture { fixture ->
            assertFailsWith<LlvmBehaviorCandidateExecutionAdmissionException> {
                LlvmBehaviorCandidateExecutionAdmissionPublisher.publish(
                    fixture.corpus,
                    fixture.report,
                    fixture.matrix,
                    fixture.manifest,
                    fixture.candidate,
                    fixture.candidate,
                )
            }
        }
    }

    @Test
    fun `runtime budget and reference identity drift fail before START`() {
        withFixture { fixture ->
            fixture.mutateCorpus { root ->
                root.replaceObject("sandbox") { sandbox ->
                    sandbox.with("imageDigest", JsonPrimitive("sha256:${"0".repeat(64)}"))
                }
            }
            fixture.assertFailure()
        }
        withFixture { fixture ->
            fixture.mutateCorpus { root ->
                root.replaceObject("limits") { limits ->
                    limits.with("timeoutMilliseconds", JsonPrimitive(9_999))
                }
            }
            fixture.assertFailure()
        }
        withFixture { fixture ->
            val bytes = Files.readAllBytes(fixture.report)
            bytes[bytes.lastIndex - 1] = if (bytes[bytes.lastIndex - 1] == '0'.code.toByte()) {
                '1'.code.toByte()
            } else {
                '0'.code.toByte()
            }
            Files.setPosixFilePermissions(fixture.report, PosixFilePermissions.fromString("rw-r--r--"))
            Files.write(fixture.report, bytes, StandardOpenOption.TRUNCATE_EXISTING)
            Files.setPosixFilePermissions(fixture.report, PosixFilePermissions.fromString("r--r--r--"))
            fixture.assertFailure()
        }
    }

    @Test
    fun `dedicated output parent and target temporary collisions preserve hostile bytes`() {
        withFixture { fixture ->
            val hostile = "foreign-target\n".encodeToByteArray()
            Files.write(fixture.output, hostile)
            Files.setPosixFilePermissions(fixture.output, PosixFilePermissions.fromString("r--------"))
            fixture.assertFailure()
            assertContentEquals(hostile, Files.readAllBytes(fixture.output))
        }
        withFixture { fixture ->
            val temporary = fixture.output.parent.resolve(
                DescriptorBoundAtomicStateFile.temporaryName(fixture.output.fileName.toString()),
            )
            val hostile = "foreign-temporary\n".encodeToByteArray()
            Files.write(temporary, hostile)
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("r--------"))
            fixture.assertFailure()
            assertContentEquals(hostile, Files.readAllBytes(temporary))
            assertFalse(Files.exists(fixture.output, LinkOption.NOFOLLOW_LINKS))
        }
        withFixture { fixture ->
            Files.setPosixFilePermissions(fixture.output.parent, PosixFilePermissions.fromString("rwxr-x---"))
            fixture.assertFailure()
        }
        withFixture { fixture ->
            Files.writeString(fixture.output.parent.resolve("unrelated"), "hostile")
            fixture.assertFailure()
        }
    }

    @Test
    fun `production JVM surface accepts only raw paths and has no runner or result authority`() {
        val methods = LlvmBehaviorCandidateExecutionAdmissionPublisher::class.java.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
        assertEquals(1, methods.size)
        assertEquals("publish", methods.single().name)
        assertEquals(List(6) { Path::class.java }, methods.single().parameterTypes.toList())
        assertEquals(LlvmBehaviorCandidateExecutionAdmission::class.java, methods.single().returnType)

        val implementation = LlvmBehaviorCandidateExecutionAdmissionPublisher::class.java.declaredClasses
            .single { it.simpleName == "PublishedAdmission" }
        val constructors = implementation.declaredConstructors
        assertEquals(1, constructors.size)
        assertFalse(Modifier.isPublic(implementation.modifiers))
        assertEquals(List(6) { Path::class.java }, constructors.single().parameterTypes.toList())
        val forbiddenTypeNames = setOf(
            "java.lang.ProcessBuilder",
            "kotlin.jvm.functions.Function0",
            "decompengine.agent.AgentHarness",
            "decompengine.oracle.behavior.LlvmBehaviorReferenceEvidence",
            "decompengine.oracle.behavior.LlvmBehaviorCandidateAssessment",
        )
        assertTrue(methods.flatMap { it.parameterTypes.toList() }.none { it.name in forbiddenTypeNames })
        assertTrue(constructors.flatMap { it.parameterTypes.toList() }.none { it.name in forbiddenTypeNames })
    }

    private fun commandDigests(bytes: ByteArray): List<String> = parseAdmission(bytes)
        .getValue("command").jsonObject
        .getValue("caseBindings").jsonArray
        .map { it.jsonObject.string("commandSha256") }

    private fun parseAdmission(bytes: ByteArray): JsonObject =
        OracleJson.parseCanonical(bytes, jsonLimits(MAXIMUM_ADMISSION_BYTES)) as JsonObject

    private fun withFixture(action: (Fixture) -> Unit) {
        val root = createTempDirectory("llvm-candidate-execution-admission-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(Fixture(root))
        } finally {
            Files.walkFileTree(
                root,
                object : SimpleFileVisitor<Path>() {
                    override fun preVisitDirectory(directory: Path, attributes: BasicFileAttributes): FileVisitResult {
                        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
                        return FileVisitResult.CONTINUE
                    }

                    override fun visitFile(file: Path, attributes: BasicFileAttributes): FileVisitResult {
                        Files.delete(file)
                        return FileVisitResult.CONTINUE
                    }

                    override fun postVisitDirectory(directory: Path, failure: java.io.IOException?): FileVisitResult {
                        if (failure != null) throw failure
                        Files.delete(directory)
                        return FileVisitResult.CONTINUE
                    }
                },
            )
        }
    }

    private inner class Fixture(val root: Path) {
        val corpus: Path = copyChecked("behavior-corpus.json", "corpus.json")
        val report: Path = copyChecked("behavior-corpus-evidence.json", "report.json")
        val matrix: Path = copyChecked("diagnostic-matrix.json", "matrix.json")
        val manifest: Path = copyChecked("oracle-manifest.json", "manifest.json")
        val candidate: Path = root.resolve("candidate-clang")
        val output: Path = newOutput("primary")

        init {
            writeCandidate("#!/bin/sh\nexit 0\n".encodeToByteArray())
        }

        fun publish(path: Path = output): LlvmBehaviorCandidateExecutionAdmission =
            LlvmBehaviorCandidateExecutionAdmissionPublisher.publish(
                corpus,
                report,
                matrix,
                manifest,
                candidate,
                path,
            )

        fun assertFailure() {
            assertFailsWith<LlvmBehaviorCandidateExecutionAdmissionException> { publish() }
            assertFalse(Files.exists(root.resolve("candidate-ran"), LinkOption.NOFOLLOW_LINKS))
        }

        fun writeCandidate(bytes: ByteArray) = writeCandidateAt(candidate, bytes)

        fun writeCandidateAt(path: Path, bytes: ByteArray) {
            if (Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            Files.write(
                path,
                bytes,
                StandardOpenOption.CREATE,
                StandardOpenOption.TRUNCATE_EXISTING,
                StandardOpenOption.WRITE,
            )
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r-x------"))
        }

        fun newOutput(name: String): Path {
            val parent = root.resolve("output-$name")
            Files.createDirectory(parent)
            Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"))
            return parent.resolve("admission.json")
        }

        fun mutateCorpus(transform: (JsonObject) -> JsonObject) {
            val root = OracleJson.parseCanonical(
                Files.readAllBytes(corpus),
                jsonLimits(MAXIMUM_CORPUS_BYTES),
            ) as JsonObject
            Files.setPosixFilePermissions(corpus, PosixFilePermissions.fromString("rw-r--r--"))
            Files.write(
                corpus,
                OracleJson.canonicalBytes(transform(root), jsonLimits(MAXIMUM_CORPUS_BYTES)),
                StandardOpenOption.TRUNCATE_EXISTING,
            )
            Files.setPosixFilePermissions(corpus, PosixFilePermissions.fromString("r--r--r--"))
        }

        private fun copyChecked(name: String, localName: String): Path {
            val source = Path.of("oracle", "llvm", "22.1.6", name).toAbsolutePath().normalize()
            val target = root.resolve(localName)
            Files.copy(source, target, StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--r--r--"))
            return target
        }
    }

    private fun markerScript(marker: Path): ByteArray =
        "#!/bin/sh\nprintf ran > '${marker}'\nexit 91\n".encodeToByteArray()

    private fun JsonObject.with(name: String, value: JsonElement): JsonObject =
        JsonObject(this + (name to value))

    private fun JsonObject.replaceObject(name: String, transform: (JsonObject) -> JsonObject): JsonObject =
        with(name, transform(getValue(name).jsonObject))

    private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.content

    private fun jsonLimits(maximumBytes: Int): StrictJsonLimits = StrictJsonLimits(
        maximumInputBytes = maximumBytes,
        maximumCanonicalBytes = maximumBytes,
        maximumDepth = 64,
        maximumNodes = 250_000,
        maximumStringBytes = maximumBytes,
        maximumTotalStringBytes = maximumBytes,
        maximumNumberCharacters = 64,
    )

    private companion object {
        const val MAXIMUM_CORPUS_BYTES = 16 * 1024 * 1024
        const val MAXIMUM_ADMISSION_BYTES = 1024 * 1024
        const val EXPECTED_STDERR_SHA256 = "312e40d49b1039eb9cde140249c46081779c27e049b384c776c7d0fc415b7bc3"
    }
}
