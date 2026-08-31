package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmToolchainReproductionTest {
    @Test
    fun `checked LLVM recipe has frozen Python v1 parity without equating fresh and origin images`() =
        withFixture { fixture ->
            val first = fixture.verify()
            val second = fixture.verify()

            assertEquals(first, second)
            assertEquals("14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f", first.lockSha256)
            assertEquals("97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291", first.dockerfileSha256)
            assertEquals("415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005", first.buildRecordSha256)
            assertEquals("sha256:73285d9a2dad159a7171fe4bbcac7d97d285402955d8c6fb8b44b101cf2df550", first.recordedOriginImageDigest)
            assertEquals(FRESH_IMAGE_DIGEST, first.observedImageDigest)
            assertNotEquals(first.recordedOriginImageDigest, first.observedImageDigest)
            assertEquals("linux/amd64", first.platform)
            assertEquals("1779182222", first.sourceDateEpoch)
            assertEquals(
                "verified stable toolchain recipe for rebuilt image $FRESH_IMAGE_DIGEST " +
                    "(recorded artifact origin ${first.recordedOriginImageDigest})",
                LlvmToolchainReproductionVerifierCli.successMessage(first),
            )
        }

    @Test
    fun `closed canonical lock path and recipe mutations fail closed`() {
        withFixture { fixture ->
            fixture.updateLock { JsonObject(it + ("unchecked" to JsonPrimitive(true))) }
            assertFailsWith<ToolchainReproductionException> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.write(fixture.lockPath, Files.readAllBytes(fixture.lockPath) + byteArrayOf(' '.code.toByte()))
            assertFailsWith<ToolchainReproductionException> { fixture.verify() }
        }
        withFixture { fixture ->
            val original = fixture.lockPath.readText()
            Files.writeString(fixture.lockPath, original.replaceFirst("{", "{\n  \"schemaVersion\": 1,"))
            assertFailsWith<ToolchainReproductionException> { fixture.verify() }
        }
        withFixture { fixture ->
            fixture.updateLock { root ->
                root.toolUpdateObject("recipe") { recipe ->
                    recipe.toolWithValue("dockerfile", JsonPrimitive("../build-toolchain.Dockerfile"))
                }
            }
            assertFailsWith<ToolchainReproductionException> { fixture.verify() }
        }
        withFixture { fixture ->
            fixture.updateDockerfile(
                fixture.dockerfilePath.readText().replace("FROM ubuntu@", "FROM debian@"),
            )
            val failure = assertFailsWith<ToolchainReproductionException> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("FROM instructions"))
        }
    }

    @Test
    fun `rebound build record and Docker inspect mutations cannot cross provenance identities`() {
        withFixture { fixture ->
            fixture.updateBuildRecord { root ->
                root.toolUpdateObject("environment") { environment ->
                    environment.toolUpdateObject("container") { container ->
                        container.toolWithValue("digest", JsonPrimitive("sha256:${"9".repeat(64)}"))
                    }
                }
            }
            val failure = assertFailsWith<ToolchainReproductionException> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("origin digest"))
        }
        withFixture { fixture ->
            fixture.updateInspect { JsonArray(listOf(it, it)) }
            val failure = assertFailsWith<ToolchainReproductionException> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("exactly one image"))
        }
        withFixture { fixture ->
            fixture.updateInspectObject { it.toolWithValue("Architecture", JsonPrimitive("arm64")) }
            val failure = assertFailsWith<ToolchainReproductionException> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("platform"))
        }
        withFixture { fixture ->
            fixture.updateInspectObject { it.toolWithValue("Id", JsonPrimitive("latest")) }
            val failure = assertFailsWith<ToolchainReproductionException> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("digest"))
        }
        withFixture { fixture ->
            Files.writeString(
                fixture.inspectPath,
                "[{\"Architecture\":\"amd64\",\"Id\":\"$FRESH_IMAGE_DIGEST\"," +
                    "\"Id\":\"sha256:${"7".repeat(64)}\",\"Os\":\"linux\"}]",
            )
            val failure = assertFailsWith<ToolchainReproductionException> { fixture.verify() }
            assertTrue(failure.message.orEmpty().contains("strict bounded JSON"))
        }
    }

    @Test
    fun `untrusted files symlinks and post-verification drift fail closed`() {
        withFixture { fixture ->
            Files.setPosixFilePermissions(
                fixture.dockerfilePath,
                PosixFilePermissions.fromString("rw-rw-r--"),
            )
            assertFailsWith<ToolchainReproductionException> { fixture.verify() }
        }
        withFixture { fixture ->
            val real = fixture.root.resolve("real-build-toolchain.Dockerfile")
            Files.move(fixture.dockerfilePath, real)
            Files.createSymbolicLink(fixture.dockerfilePath, real.fileName)
            assertFailsWith<ToolchainReproductionException> { fixture.verify() }
        }
        withFixture { fixture ->
            var changed = false
            val verifier = LlvmToolchainReproductionVerifier { point ->
                if (!changed && point == ToolchainReproductionVerificationPoint.AFTER_INPUTS_VERIFIED) {
                    changed = true
                    fixture.updateInspectObject { image ->
                        image.toolWithValue("Id", JsonPrimitive("sha256:${"7".repeat(64)}"))
                    }
                }
            }
            val failure = assertFailsWith<ToolchainReproductionException> {
                fixture.verify(verifier)
            }
            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("changed during verification"))
        }
    }

    @Test
    fun `workflow and legacy surfaces make Kotlin recipe authority explicit`() {
        val build = Path.of("build.gradle.kts").readText()
        val gcc = Path.of(".github/workflows/gcc-oracle-model.yml").readText()
        val llvm = Path.of(".github/workflows/llvm-oracle-model.yml").readText()

        assertTrue(build.contains("taskName = \"verifyLlvmToolchainReproduction\""))
        assertTrue(build.contains("decompengine.oracle.provenance.LlvmToolchainReproductionVerifierCli"))
        assertTrue(llvm.contains("./gradlew --no-daemon verifyLlvmToolchainReproduction"))
        assertTrue(llvm.contains("install -d -m 0700 \"\$RUNNER_TEMP/llvm-toolchain-verification\""))
        assertTrue(llvm.contains("--inspect-json \$RUNNER_TEMP/llvm-toolchain-verification/inspect.json"))
        assertFalse(llvm.contains("python3 scripts/verify-toolchain-reproduction.py"))
        assertFalse(llvm.contains("tests.oracle.test_stable_toolchain_reproduction"))

        assertTrue(gcc.contains("python3 scripts/verify-gcc-toolchain-reproduction.py"))
        assertTrue(gcc.contains("tests/oracle/test_stable_toolchain_reproduction.py"))
        assertFalse(gcc.contains("tests.oracle.test_stable_toolchain_reproduction"))

        val legacyCli = Path.of("scripts/verify-toolchain-reproduction.py").readText()
        assertTrue(legacyCli.contains("Legacy Python compatibility"))
        assertTrue(legacyCli.contains("not Kotlin/JVM oracle or release authority"))

        val legacyModule = Path.of("oracle/toolchain_reproduction.py").readText()
        assertTrue(legacyModule.contains("Legacy Python compatibility"))
        assertTrue(legacyModule.contains("retained by the unmigrated live build-record gate"))
        assertTrue(legacyModule.contains("not independent Kotlin/JVM recipe or release authority"))

        assertTrue(llvm.contains("./gradlew --no-daemon fetchLlvmSourceArchive"))
        assertFalse(llvm.contains("python3 scripts/verify-llvm-oracle-source.py"))
        assertFalse(llvm.contains("python3 scripts/fetch-llvm-oracle-source.py"))
        assertFalse(llvm.contains("tests.oracle.test_llvm_source_lock"))

        // These adjacent authorities remain intentionally unchanged by the source cutover.
        listOf(
            "scripts/verify-llvm-oracle-build-record.py",
            "python3 scripts/verify-llvm-oracle-artifacts.py",
            "python3 scripts/generate-llvm-function-recovery-oracle.py",
            "python3 scripts/check-behavior-corpus-evidence.py",
        ).forEach { retained -> assertTrue(llvm.contains(retained), retained) }
    }

    private fun withFixture(action: (MutableToolchainFixture) -> Unit) {
        val root = privateDirectory(createTempDirectory("llvm-toolchain-reproduction-"))
        try {
            action(MutableToolchainFixture(root))
        } finally {
            deleteTree(root)
        }
    }
}

private class MutableToolchainFixture(val root: Path) {
    val lockPath: Path = root.resolve("toolchain-reproduction.json")
    val buildRecordPath: Path = root.resolve("build-record.json")
    val dockerfilePath: Path = root.resolve("build-toolchain.Dockerfile")
    val inspectPath: Path = root.resolve("inspect.json")

    init {
        Files.copy(CHECKED_TOOLCHAIN_PROFILE.resolve(lockPath.fileName), lockPath, StandardCopyOption.REPLACE_EXISTING)
        Files.copy(
            CHECKED_TOOLCHAIN_PROFILE.resolve(buildRecordPath.fileName),
            buildRecordPath,
            StandardCopyOption.REPLACE_EXISTING,
        )
        Files.copy(
            CHECKED_TOOLCHAIN_PROFILE.resolve(dockerfilePath.fileName),
            dockerfilePath,
            StandardCopyOption.REPLACE_EXISTING,
        )
        writeInspect(checkedInspect())
    }

    fun verify(
        verifier: LlvmToolchainReproductionVerifier = LlvmToolchainReproductionVerifier(),
    ): LlvmToolchainReproductionVerification = verifier.verify(lockPath, buildRecordPath, inspectPath)

    fun updateLock(transform: (JsonObject) -> JsonObject) = updateCanonicalObject(lockPath, transform)

    fun updateDockerfile(text: String) {
        Files.writeString(dockerfilePath, text)
        updateLock { root ->
            root.toolUpdateObject("recipe") { recipe ->
                recipe.toolWithValue(
                    "dockerfileSha256",
                    JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(dockerfilePath))),
                )
            }
        }
    }

    fun updateBuildRecord(transform: (JsonObject) -> JsonObject) {
        updateCanonicalObject(buildRecordPath, transform)
        updateLock { root ->
            root.toolUpdateObject("recordedOrigin") { origin ->
                origin.toolWithValue(
                    "buildRecordSha256",
                    JsonPrimitive(OracleArtifacts.sha256(Files.readAllBytes(buildRecordPath))),
                )
            }
        }
    }

    fun updateInspect(transform: (JsonElement) -> JsonElement) {
        val current = OracleJson.parse(Files.readAllBytes(inspectPath))
        writeInspect(transform(current))
    }

    fun updateInspectObject(transform: (JsonObject) -> JsonObject) = updateInspect { current ->
        val array = current as JsonArray
        JsonArray(listOf(transform(array.single() as JsonObject)))
    }

    private fun writeInspect(document: JsonElement) {
        Files.write(inspectPath, OracleJson.canonicalBytes(document))
    }

    private fun checkedInspect(): JsonArray = JsonArray(
        listOf(
            JsonObject(
                mapOf(
                    "Architecture" to JsonPrimitive("amd64"),
                    "Id" to JsonPrimitive(FRESH_IMAGE_DIGEST),
                    "Os" to JsonPrimitive("linux"),
                ),
            ),
        ),
    )
}

private fun updateCanonicalObject(path: Path, transform: (JsonObject) -> JsonObject) {
    val original = OracleJson.parseCanonical(Files.readAllBytes(path)) as JsonObject
    Files.write(path, OracleJson.canonicalBytes(transform(original)))
}

private fun JsonObject.toolUpdateObject(name: String, transform: (JsonObject) -> JsonObject): JsonObject =
    toolWithValue(name, transform(this[name] as JsonObject))

private fun JsonObject.toolWithValue(name: String, value: JsonElement): JsonObject =
    JsonObject(toMutableMap().apply { this[name] = value })

private val CHECKED_TOOLCHAIN_PROFILE = Path.of("oracle/llvm/22.1.6")
private val FRESH_IMAGE_DIGEST = "sha256:${"8".repeat(64)}"
