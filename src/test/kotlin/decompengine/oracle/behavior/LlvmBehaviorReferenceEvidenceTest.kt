package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemaException
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import kotlin.io.path.createDirectories
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorReferenceEvidenceTest {
    @Test
    fun `checked LLVM reference evidence is authenticated and immutable`() {
        val evidence = verifyChecked()

        assertEquals("clang-22-1-6-driver-behavior", evidence.corpusId)
        assertEquals("acaa7b33c390b2c9fde15b4e21b0a899ffff62fe98ce22226866272b4efe8d5b", evidence.corpusSha256)
        assertEquals("e9595bfd941c406d2c8fff618986e60dc0b810f1c384848b3ba540020ca00a6f", evidence.reportSha256)
        assertEquals("9e3b3223e014de49e0df50892556ae4649f819d5571751378ed9bfd12d684b2d", evidence.diagnosticMatrixSha256)
        assertEquals("fc8145038141fca072d506391b4d93311aa3842ea6bfa088285c5dce7943ed3b", evidence.diagnosticMatrixSelfSha256)
        assertEquals("5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40", evidence.artifactManifestSha256)
        assertEquals(84_561_368L, evidence.executableBytes)
        assertEquals("65e57857bfaf9f98a552f2fd371938e11175158bc4c11c849bd6ecbfef30c006", evidence.executableSha256)
        assertEquals("e4991450d10843e2fce6bc430a8876682fd831b3c4768b7fb757d7ee158638fa", evidence.sandboxSha256)
        assertEquals(48, evidence.caseIds.size)
        assertEquals(16, evidence.diagnosticOwners.size)

        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (evidence.caseIds as MutableList<String>).add("forged")
        }
        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (evidence.diagnosticOwners as MutableMap<String, String>)["forged"] = "forged"
        }
    }

    @Test
    fun `schema migration admits reviewed executable and preserves corrected 128 MiB ceiling`() {
        val corpus = readObject(PROFILE.resolve("behavior-corpus.json"), 16 * 1024 * 1024)
        val report = readObject(PROFILE.resolve("behavior-corpus-evidence.json"), 64 * 1024 * 1024)

        OracleSchemas.validate("behavior-corpus", corpus)
        OracleSchemas.validate("behavior-corpus-report", report)

        listOf("behavior-corpus" to corpus, "behavior-corpus-report" to report).forEach { (schema, document) ->
            listOf<(JsonObject, Long) -> JsonObject>(
                { root, bytes ->
                    root.replaceObject("executable") { executable ->
                        executable.with("bytes", JsonPrimitive(bytes))
                    }
                },
                { root, bytes ->
                    root.replaceObject("sandbox") { sandbox ->
                        sandbox.replaceObject("controlClient") { controlClient ->
                            controlClient.with("bytes", JsonPrimitive(bytes))
                        }
                    }
                },
            ).forEach { setExecutableBytes ->
                listOf(1L, 128L * 1024 * 1024).forEach { acceptedBytes ->
                    OracleSchemas.validate(schema, setExecutableBytes(document, acceptedBytes))
                }
                listOf(0L, 128L * 1024 * 1024 + 1).forEach { rejectedBytes ->
                    assertFailsWith<OracleSchemaException> {
                        OracleSchemas.validate(schema, setExecutableBytes(document, rejectedBytes))
                    }
                }
            }
        }
    }

    @Test
    fun `duplicate and noncanonical JSON fail before semantic validation`() {
        withFixtureCopies { files ->
            val canonical = Files.readString(files.corpus)
            Files.writeString(files.corpus, canonical.replaceFirst("{\n", "{\n  \"schemaVersion\": 1,\n"))
            assertFailure(files, "strict canonical bounded JSON")
        }
        withFixtureCopies { files ->
            val canonical = Files.readString(files.corpus)
            Files.writeString(files.corpus, canonical.removeSuffix("\n"))
            assertFailure(files, "strict canonical bounded JSON")
        }
    }

    @Test
    fun `closed records reject unknown fields independently of permissive parsing`() = withFixtureCopies { files ->
        mutate(files.corpus, 16 * 1024 * 1024) { corpus -> corpus.with("unexpected", JsonPrimitive(true)) }
        assertFailure(files, "fields differ")
    }

    @Test
    fun `base64 encoded length is bounded before decode and digest bytes are authenticated`() {
        withFixtureCopies { files ->
            mutateFirstCorpusCase(files.corpus) { case ->
                case.replaceObject("stdin") { stdin -> stdin.with("base64", JsonPrimitive("AAAA")) }
            }
            assertFailure(files, "encoded length differs before decoding")
        }
        withFixtureCopies { files ->
            mutateFirstCorpusCase(files.corpus) { case ->
                case.replaceObject("stdin") { stdin -> stdin.with("sha256", JsonPrimitive("0".repeat(64))) }
            }
            assertFailure(files, "SHA-256 differs from decoded bytes")
        }
    }

    @Test
    fun `lowering decoded input and retained evidence limits fails closed`() {
        withFixtureCopies { files ->
            val failure = assertFailsWith<LlvmBehaviorReferenceEvidenceException> {
                verify(
                    files,
                    LlvmBehaviorReferenceLimits(maximumDecodedInputBytesPerCase = 1),
                )
            }
            assertTrue(failure.message.orEmpty().contains("decoded inputs exceed"), failure.message)
        }
        withFixtureCopies { files ->
            val failure = assertFailsWith<LlvmBehaviorReferenceEvidenceException> {
                verify(
                    files,
                    LlvmBehaviorReferenceLimits(maximumRetainedReportBytes = 1),
                )
            }
            assertTrue(failure.message.orEmpty().contains("retained-evidence byte limit"), failure.message)
        }
    }

    @Test
    fun `corpus requires the exact ordered 48 case profile and exact sandbox policy`() {
        withFixtureCopies { files ->
            mutate(files.corpus, 16 * 1024 * 1024) { corpus ->
                corpus.with("cases", JsonArray(corpus.array("cases").reversed()))
            }
            assertFailure(files, "case IDs must be sorted and unique")
        }
        withFixtureCopies { files ->
            mutate(files.corpus, 16 * 1024 * 1024) { corpus ->
                corpus.replaceObject("sandbox") { sandbox ->
                    sandbox.with("imageDigest", JsonPrimitive("sha256:" + "0".repeat(64)))
                }
            }
            assertFailure(files, "sandbox differs from the reviewed exact executor policy")
        }
    }

    @Test
    fun `manifest stripped artifact is the only executable identity accepted`() = withFixtureCopies { files ->
        mutate(files.manifest, 4 * 1024 * 1024) { manifest ->
            manifest.replaceObject("artifacts") { artifacts ->
                artifacts.replaceObject("stripped") { stripped ->
                    stripped.with("sha256", JsonPrimitive("0".repeat(64)))
                }
            }
        }
        assertFailure(files, "corpus executable differs from the authenticated manifest stripped artifact")
    }

    @Test
    fun `report requires all 48 cases and exact corpus observations`() {
        withFixtureCopies { files ->
            mutate(files.report, 64 * 1024 * 1024) { report ->
                report.with("cases", JsonArray(report.array("cases").dropLast(1)))
            }
            assertFailure(files, "must contain exactly 48 cases")
        }
        withFixtureCopies { files ->
            mutateFirstReportCase(files.report) { case -> case.with("exitCode", JsonPrimitive(255)) }
            assertFailure(files, "exitCode differs from its corpus")
        }
    }

    @Test
    fun `diagnostic matrix self hash is recomputed`() = withFixtureCopies { files ->
        mutateFirstMatrixCase(files.matrix, rehash = false) { case ->
            case.with("ownerSubsystem", JsonPrimitive("forged-owner"))
        }
        assertFailure(files, "self hash differs")
    }

    @Test
    fun `diagnostic owners mismatch identities and policy are fixed after valid self hash`() {
        withFixtureCopies { files ->
            mutateFirstMatrixCase(files.matrix, rehash = true) { case ->
                case.with("ownerSubsystem", JsonPrimitive("forged-owner"))
            }
            assertFailure(files, "owner subsystem differs")
        }
        withFixtureCopies { files ->
            mutateFirstMatrixCase(files.matrix, rehash = true) { case ->
                case.replaceObject("mismatchIds") { ids ->
                    ids.with("stderr", JsonPrimitive("clang-diagnostic-" + "0".repeat(32)))
                }
            }
            assertFailure(files, "mismatch identity for stderr differs")
        }
        withFixtureCopies { files ->
            mutate(files.matrix, 1024 * 1024) { matrix ->
                val changed = matrix.replaceObject("policy") { policy ->
                    policy.with("pathNormalization", JsonPrimitive("all paths"))
                }
                rehashMatrix(changed)
            }
            assertFailure(files, "policy differs from the reviewed policy")
        }
    }

    @Test
    fun `sealed JVM authority has only raw-path validating constructors and factories`() {
        assertTrue(LlvmBehaviorReferenceEvidence::class.java.isSealed)
        val implementations = LlvmBehaviorReferenceEvidence::class.java.permittedSubclasses.toList()
        assertEquals(1, implementations.size)
        val rawInputs = listOf(
            Path::class.java,
            Path::class.java,
            Path::class.java,
            Path::class.java,
            LlvmBehaviorReferenceLimits::class.java,
        )
        implementations.forEach { implementation ->
            assertTrue(implementation.declaredConstructors.isNotEmpty())
            implementation.declaredConstructors.forEach { constructor ->
                assertEquals(
                    rawInputs,
                    constructor.parameterTypes.filterNot { it.name == "kotlin.jvm.internal.DefaultConstructorMarker" },
                    constructor.toGenericString(),
                )
            }
        }

        val kotlinFileClass = Class.forName("decompengine.oracle.behavior.LlvmBehaviorReferenceEvidenceKt")
        val authenticationBridge = kotlinFileClass.declaredMethods.single { method ->
            method.name == "access\$authenticateEvidence"
        }
        assertTrue(authenticationBridge.isSynthetic, authenticationBridge.toGenericString())
        assertEquals(rawInputs, authenticationBridge.parameterTypes.toList(), authenticationBridge.toGenericString())

        val authorityClasses = buildList {
            add(LlvmBehaviorReferenceEvidenceVerifier::class.java)
            implementations.forEach { implementation ->
                add(implementation)
                addAll(implementation.declaredClasses)
            }
        }
        val allowedInputs = setOf(Path::class.java, LlvmBehaviorReferenceLimits::class.java)
        authorityClasses.flatMap { it.declaredMethods.toList() }.filter { method ->
            !Modifier.isPrivate(method.modifiers) &&
                LlvmBehaviorReferenceEvidence::class.java.isAssignableFrom(method.returnType)
        }.forEach { factory ->
            assertTrue(factory.parameterTypes.isNotEmpty(), factory.toGenericString())
            assertTrue(factory.parameterTypes.all(allowedInputs::contains), factory.toGenericString())
        }
        authorityClasses.flatMap { it.declaredMethods.toList() }.forEach { method ->
            val forbidden = method.parameterTypes.any { type ->
                type == JsonObject::class.java ||
                    type == JsonElement::class.java ||
                    type == ByteArray::class.java ||
                    type == String::class.java
            }
            assertTrue(Modifier.isPrivate(method.modifiers) || !forbidden, method.toGenericString())
        }

        withFixtureCopies { files ->
            mutate(files.corpus, 16 * 1024 * 1024) { corpus -> corpus.with("forged", JsonPrimitive(true)) }
            val constructor = implementations.single().declaredConstructors.single().also { it.isAccessible = true }
            val failure = assertFailsWith<InvocationTargetException> {
                constructor.newInstance(
                    files.corpus,
                    files.report,
                    files.matrix,
                    files.manifest,
                    LlvmBehaviorReferenceLimits(),
                )
            }
            assertTrue(failure.cause is LlvmBehaviorReferenceEvidenceException, failure.cause.toString())
        }
    }

    private fun verifyChecked(): LlvmBehaviorReferenceEvidence = LlvmBehaviorReferenceEvidenceVerifier.verify(
        PROFILE.resolve("behavior-corpus.json"),
        PROFILE.resolve("behavior-corpus-evidence.json"),
        PROFILE.resolve("diagnostic-matrix.json"),
        PROFILE.resolve("oracle-manifest.json"),
    )

    private fun assertFailure(files: FixtureFiles, expected: String) {
        val failure = assertFailsWith<LlvmBehaviorReferenceEvidenceException> { verify(files) }
        assertTrue(failure.message.orEmpty().contains(expected), failure.message)
    }

    private fun verify(
        files: FixtureFiles,
        limits: LlvmBehaviorReferenceLimits = LlvmBehaviorReferenceLimits(),
    ): LlvmBehaviorReferenceEvidence = LlvmBehaviorReferenceEvidenceVerifier.verify(
        files.corpus,
        files.report,
        files.matrix,
        files.manifest,
        limits,
    )

    private fun withFixtureCopies(action: (FixtureFiles) -> Unit) {
        val root = Files.createTempDirectory("llvm-behavior-reference-test-")
        try {
            root.createDirectories()
            val files = FixtureFiles(
                corpus = copy(PROFILE.resolve("behavior-corpus.json"), root),
                report = copy(PROFILE.resolve("behavior-corpus-evidence.json"), root),
                matrix = copy(PROFILE.resolve("diagnostic-matrix.json"), root),
                manifest = copy(PROFILE.resolve("oracle-manifest.json"), root),
            )
            action(files)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun copy(source: Path, root: Path): Path = root.resolve(source.fileName).also { target ->
        Files.copy(source, target, StandardCopyOption.COPY_ATTRIBUTES)
    }

    private fun mutate(path: Path, maximumBytes: Int, change: (JsonObject) -> JsonObject) {
        val original = readObject(path, maximumBytes)
        Files.write(path, OracleJson.canonicalBytes(change(original), jsonLimits(maximumBytes)))
    }

    private fun mutateFirstCorpusCase(path: Path, change: (JsonObject) -> JsonObject) {
        mutate(path, 16 * 1024 * 1024) { corpus ->
            val cases = corpus.array("cases").toMutableList()
            cases[0] = change(cases[0] as JsonObject)
            corpus.with("cases", JsonArray(cases))
        }
    }

    private fun mutateFirstReportCase(path: Path, change: (JsonObject) -> JsonObject) {
        mutate(path, 64 * 1024 * 1024) { report ->
            val cases = report.array("cases").toMutableList()
            cases[0] = change(cases[0] as JsonObject)
            report.with("cases", JsonArray(cases))
        }
    }

    private fun mutateFirstMatrixCase(path: Path, rehash: Boolean, change: (JsonObject) -> JsonObject) {
        mutate(path, 1024 * 1024) { matrix ->
            val cases = matrix.array("cases").toMutableList()
            cases[0] = change(cases[0] as JsonObject)
            val changed = matrix.with("cases", JsonArray(cases))
            if (rehash) rehashMatrix(changed) else changed
        }
    }

    private fun rehashMatrix(matrix: JsonObject): JsonObject {
        val withoutHash = JsonObject(matrix.filterKeys { it != "matrixSha256" })
        val digest = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash, jsonLimits(1024 * 1024)))
        return matrix.with("matrixSha256", JsonPrimitive(digest))
    }

    private class FixtureFiles(
        val corpus: Path,
        val report: Path,
        val matrix: Path,
        val manifest: Path,
    )

    private companion object {
        val REPOSITORY_ROOT: Path = Path.of("").toAbsolutePath().normalize()
        val PROFILE: Path = REPOSITORY_ROOT.resolve("oracle/llvm/22.1.6")

        fun readObject(path: Path, maximumBytes: Int): JsonObject =
            OracleJson.parseCanonical(Files.readAllBytes(path), jsonLimits(maximumBytes)) as JsonObject

        fun jsonLimits(maximumBytes: Int): StrictJsonLimits = StrictJsonLimits(
            maximumInputBytes = maximumBytes,
            maximumCanonicalBytes = maximumBytes,
            maximumDepth = 64,
            maximumNodes = 250_000,
            maximumStringBytes = maximumBytes,
            maximumTotalStringBytes = maximumBytes,
            maximumNumberCharacters = 64,
        )
    }
}

private fun JsonObject.with(name: String, value: JsonElement): JsonObject =
    JsonObject(LinkedHashMap(this).apply { put(name, value) })

private fun JsonObject.replaceObject(name: String, change: (JsonObject) -> JsonObject): JsonObject =
    with(name, change(this[name] as JsonObject))

private fun JsonObject.array(name: String): JsonArray = this[name] as JsonArray
