package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmReleaseArtifactsTest {
    @Test
    fun `checked release lock is canonical closed and bound to the reviewed manifest`() {
        val lock = LlvmReleaseArtifactLockLoader.load(CHECKED_PROFILE.resolve("release-artifacts.json"))

        assertEquals("clang-driver-22.1.6", lock.oracleId)
        assertEquals("22.1.6", lock.oracleVersion)
        assertEquals("minsago-elite/decomp_thing-oracle-artifacts", lock.repository)
        assertEquals("clang-llvm-22.1.6-v1", lock.tag)
        assertEquals("d1a871ff2cb48c1118cb0e1a8a2d2e45ad4fbf580e35064eac76066f74547025", lock.lockSha256)
        assertEquals("5b6f6e923e05ae4d51aefab55c8028d543d05e76b25a7c075c4e884005ce6b40", lock.manifestSha256)
        assertEquals(listOf("full", "stripped"), lock.artifacts.map { it.role })
        assertEquals(listOf(529_730_248L, 84_561_368L), lock.artifacts.map { it.bytes })
    }

    @Test
    fun `semantic URL uniqueness canonicality and manifest mutations fail closed`() {
        mutationFixture { fixture ->
            fixture.updateLock { root ->
                root.updateObject("release") { release ->
                    release.withValue("pageUrl", JsonPrimitive("https://github.com/wrong/release"))
                }
            }
            assertFailsWith<ReleaseArtifactProvenanceException> { fixture.load() }
        }
        mutationFixture { fixture ->
            fixture.updateLock { root -> JsonObject(root + ("unexpected" to JsonPrimitive(true))) }
            assertFailsWith<ReleaseArtifactProvenanceException> { fixture.load() }
        }
        mutationFixture { fixture ->
            fixture.updateLock { root ->
                root.updateObject("artifacts") { artifacts ->
                    val fullSha = artifacts.objectValue("full").stringValue("sha256")
                    artifacts.updateObject("stripped") { it.withValue("sha256", JsonPrimitive(fullSha)) }
                }
            }
            assertFailsWith<ReleaseArtifactProvenanceException> { fixture.load() }
        }
        mutationFixture { fixture ->
            fixture.updateManifest { manifest ->
                manifest.updateObject("oracle") { oracle -> oracle.withValue("id", JsonPrimitive("wrong-id")) }
            }
            fixture.rebindManifestHash()
            assertFailsWith<ReleaseArtifactProvenanceException> { fixture.load() }
        }
        mutationFixture { fixture ->
            Files.write(fixture.lockPath, Files.readAllBytes(fixture.lockPath) + byteArrayOf(' '.code.toByte()))
            assertFailsWith<ReleaseArtifactProvenanceException> { fixture.load() }
        }
    }

    @Test
    fun `small locked pair is streamed published and reused without another exchange`() {
        val root = privateDirectory(createTempDirectory("release-materializer-"))
        try {
            val full = "full release bytes".toByteArray()
            val stripped = "stripped release bytes".toByteArray()
            val fixture = MutableReleaseFixture(root.resolve("profile")).also { it.bindArtifacts(full, stripped) }
            val transport = FakeHttpsTransport(
                FakeResponse(200, mapOf("Content-Length" to listOf(full.size.toString())), full),
                FakeResponse(200, mapOf("Content-Length" to listOf(stripped.size.toString())), stripped),
            )
            val materializer = LlvmReleaseArtifactMaterializer(BoundedHttpsDownloader(transport))
            val output = root.resolve("output")

            val first = materializer.materialize(fixture.lockPath, output)
            val second = materializer.materialize(fixture.lockPath, output)

            assertEquals(first, second)
            assertEquals(2, transport.requests.size)
            assertContentEquals(full, Files.readAllBytes(first.getValue("full").path))
            assertContentEquals(stripped, Files.readAllBytes(first.getValue("stripped").path))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(first.getValue("full").path, LinkOption.NOFOLLOW_LINKS),
            )
            assertEquals(
                setOf("clang-driver.full", "clang-driver.stripped"),
                Files.list(output.resolve("artifacts")).use { paths ->
                    paths.map { it.fileName.toString() }.toList().toSet()
                },
            )
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `truncated transfer and tampered cache leave no accepted replacement`() {
        val root = privateDirectory(createTempDirectory("release-materializer-failure-"))
        try {
            val full = "full".toByteArray()
            val stripped = "stripped".toByteArray()
            val fixture = MutableReleaseFixture(root.resolve("profile")).also { it.bindArtifacts(full, stripped) }
            val output = root.resolve("output")
            val truncated = FakeHttpsTransport(FakeResponse(200, emptyMap(), full.copyOf(full.size - 1)))
            assertFailsWith<ReleaseArtifactProvenanceException> {
                LlvmReleaseArtifactMaterializer(BoundedHttpsDownloader(truncated))
                    .materialize(fixture.lockPath, output)
            }
            assertFalse(Files.exists(output.resolve("artifacts/clang-driver.full"), LinkOption.NOFOLLOW_LINKS))

            val successful = FakeHttpsTransport(
                FakeResponse(200, emptyMap(), full),
                FakeResponse(200, emptyMap(), stripped),
            )
            LlvmReleaseArtifactMaterializer(BoundedHttpsDownloader(successful))
                .materialize(fixture.lockPath, output)
            val strippedPath = output.resolve("artifacts/clang-driver.stripped")
            Files.setPosixFilePermissions(strippedPath, PosixFilePermissions.fromString("rw-------"))
            Files.write(strippedPath, "tampered".toByteArray())
            val noNetwork = FakeHttpsTransport()
            assertFailsWith<ReleaseArtifactProvenanceException> {
                LlvmReleaseArtifactMaterializer(BoundedHttpsDownloader(noNetwork))
                    .materialize(fixture.lockPath, output)
            }
            assertEquals(0, noNetwork.requests.size)
            assertContentEquals("tampered".toByteArray(), Files.readAllBytes(strippedPath))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `exact cache fast path rejects a valid lock and manifest change`() {
        val root = privateDirectory(createTempDirectory("release-materializer-control-race-"))
        try {
            val full = "cached full".toByteArray()
            val stripped = "cached stripped".toByteArray()
            val fixture = MutableReleaseFixture(root.resolve("profile")).also { it.bindArtifacts(full, stripped) }
            val output = root.resolve("output")
            LlvmReleaseArtifactMaterializer(
                BoundedHttpsDownloader(
                    FakeHttpsTransport(
                        FakeResponse(200, emptyMap(), full),
                        FakeResponse(200, emptyMap(), stripped),
                    ),
                ),
            ).materialize(fixture.lockPath, output)

            val noNetwork = FakeHttpsTransport()
            var changed = false
            val failure = assertFailsWith<ReleaseArtifactProvenanceException> {
                LlvmReleaseArtifactMaterializer(
                    BoundedHttpsDownloader(noNetwork),
                    ReleaseArtifactMaterializationFaultInjector { point ->
                        if (!changed && point == ReleaseArtifactMaterializationPoint.AFTER_ARTIFACT_SELECTED) {
                            changed = true
                            fixture.changeOracleVersion("22.1.7")
                        }
                    },
                ).materialize(fixture.lockPath, output)
            }

            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("lock or manifest changed"))
            assertEquals(0, noNetwork.requests.size)
            assertContentEquals(full, Files.readAllBytes(output.resolve("artifacts/clang-driver.full")))
            assertContentEquals(stripped, Files.readAllBytes(output.resolve("artifacts/clang-driver.stripped")))
        } finally {
            deleteTree(root)
        }
    }

    @Test
    fun `workflow and legacy surfaces make Kotlin acquisition authority explicit`() {
        val build = Path.of("build.gradle.kts").readText()
        val gcc = Path.of(".github/workflows/gcc-oracle-model.yml").readText()
        val model = Path.of(".github/workflows/llvm-oracle-model.yml").readText()
        val rebuild = Path.of(".github/workflows/llvm-oracle-rebuild.yml").readText()

        assertTrue(build.contains("taskName = \"fetchLlvmReleaseArtifacts\""))
        assertTrue(build.contains("decompengine.oracle.provenance.LlvmReleaseArtifactFetcherCli"))
        assertTrue(build.contains("taskName = \"fetchLlvmSourceArchive\""))
        assertTrue(build.contains("decompengine.oracle.provenance.LlvmSourceArchiveFetcherCli"))
        listOf(model, rebuild).forEach { workflow ->
            assertTrue(workflow.contains("./gradlew --no-daemon fetchLlvmReleaseArtifacts"))
            assertTrue(workflow.contains("./gradlew --no-daemon fetchLlvmSourceArchive"))
            assertFalse(workflow.contains("python3 scripts/fetch-llvm-oracle-artifacts.py"))
            assertFalse(workflow.contains("python3 scripts/verify-llvm-oracle-source.py"))
            assertFalse(workflow.contains("python3 scripts/fetch-llvm-oracle-source.py"))
        }
        assertFalse(model.contains("tests.oracle.test_release_artifacts"))
        assertFalse(gcc.contains("unittest discover -s tests/oracle"))
        assertFalse(gcc.contains("tests.oracle.test_release_artifacts"))
        assertTrue(gcc.contains("for path in tests/oracle/test_*.py"))
        assertTrue(gcc.contains("tests/oracle/test_release_artifacts.py"))
        assertTrue(gcc.contains("oracle_tests+=(\"\${module//\\//.}\")"))
        assertTrue(gcc.contains("python3 -m unittest \"\${oracle_tests[@]}\" -v"))

        assertFalse(model.contains("tests.oracle.test_llvm_source_lock"))
        assertTrue(model.contains("actions/setup-python@v7"))
        assertTrue(model.contains("python3 -m pip install -r requirements/oracle-generation.txt"))
        assertTrue(model.contains("python3 scripts/verify-llvm-oracle-artifacts.py"))
        assertTrue(rebuild.contains("python3 scripts/verify-llvm-oracle-artifacts.py"))
        assertTrue(rebuild.contains("chmod 0444 \"\$RUNNER_TEMP/source-cache/llvm-project-22.1.6.src.tar.xz\""))
        assertTrue(rebuild.contains("chmod 0555 \"\$RUNNER_TEMP/source-cache\""))
        assertTrue(rebuild.contains("--cap-drop ALL"))

        listOf("scripts/fetch-llvm-oracle-artifacts.py", "oracle/release_artifacts.py").forEach { path ->
            val source = Path.of(path).readText()
            assertTrue(source.contains("Legacy Python compatibility"))
            assertTrue(source.contains("not Kotlin/JVM oracle or release authority"))
        }
        listOf("scripts/fetch-llvm-oracle-source.py", "scripts/verify-llvm-oracle-source.py").forEach { path ->
            val source = Path.of(path).readText()
            assertTrue(source.contains("Legacy Python compatibility"))
            assertTrue(source.contains("not Kotlin/JVM oracle or release authority"))
        }
    }

    private fun mutationFixture(action: (MutableReleaseFixture) -> Unit) {
        val root = privateDirectory(createTempDirectory("release-lock-mutation-"))
        try {
            action(MutableReleaseFixture(root))
        } finally {
            deleteTree(root)
        }
    }
}

private class MutableReleaseFixture(root: Path) {
    val lockPath: Path
    private val manifestPath: Path

    init {
        privateDirectory(root)
        lockPath = root.resolve("release-artifacts.json")
        manifestPath = root.resolve("oracle-manifest.json")
        Files.copy(CHECKED_PROFILE.resolve("release-artifacts.json"), lockPath, StandardCopyOption.REPLACE_EXISTING)
        Files.copy(CHECKED_PROFILE.resolve("oracle-manifest.json"), manifestPath, StandardCopyOption.REPLACE_EXISTING)
    }

    fun load(): LlvmReleaseArtifactLock = LlvmReleaseArtifactLockLoader.load(lockPath)

    fun bindArtifacts(full: ByteArray, stripped: ByteArray) {
        val bindings = mapOf("full" to full, "stripped" to stripped)
        updateManifest { manifest ->
            manifest.updateObject("artifacts") { artifacts ->
                bindings.entries.fold(artifacts) { current, (role, bytes) ->
                    current.updateObject(role) { record ->
                        record.withValue("bytes", JsonPrimitive(bytes.size))
                            .withValue("sha256", JsonPrimitive(bytes.sha256()))
                    }
                }
            }
        }
        updateLock { lock ->
            lock.updateObject("artifacts") { artifacts ->
                bindings.entries.fold(artifacts) { current, (role, bytes) ->
                    current.updateObject(role) { record ->
                        record.withValue("bytes", JsonPrimitive(bytes.size))
                            .withValue("sha256", JsonPrimitive(bytes.sha256()))
                    }
                }
            }
        }
        rebindManifestHash()
    }

    fun updateLock(transform: (JsonObject) -> JsonObject) = updateJson(lockPath, transform)

    fun updateManifest(transform: (JsonObject) -> JsonObject) = updateJson(manifestPath, transform)

    fun rebindManifestHash() {
        val digest = OracleArtifacts.sha256(Files.readAllBytes(manifestPath))
        updateLock { lock ->
            lock.updateObject("oracle") { oracle ->
                oracle.withValue("artifactManifestSha256", JsonPrimitive(digest))
            }
        }
    }

    fun changeOracleVersion(version: String) {
        updateManifest { manifest ->
            manifest.updateObject("oracle") { oracle -> oracle.withValue("version", JsonPrimitive(version)) }
        }
        updateLock { lock ->
            lock.updateObject("oracle") { oracle -> oracle.withValue("version", JsonPrimitive(version)) }
        }
        rebindManifestHash()
    }

    private fun updateJson(path: Path, transform: (JsonObject) -> JsonObject) {
        val original = OracleJson.parseCanonical(Files.readAllBytes(path)) as JsonObject
        Files.write(path, OracleJson.canonicalBytes(transform(original)))
    }
}

private fun JsonObject.updateObject(name: String, transform: (JsonObject) -> JsonObject): JsonObject =
    withValue(name, transform(objectValue(name)))

private fun JsonObject.objectValue(name: String): JsonObject = this[name] as JsonObject

private fun JsonObject.stringValue(name: String): String = (this[name] as JsonPrimitive).content

private fun JsonObject.withValue(name: String, value: kotlinx.serialization.json.JsonElement): JsonObject =
    JsonObject(toMutableMap().apply { this[name] = value })

private val CHECKED_PROFILE = Path.of("oracle/llvm/22.1.6")
