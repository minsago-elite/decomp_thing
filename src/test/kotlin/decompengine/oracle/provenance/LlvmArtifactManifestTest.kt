package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.util.Base64
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

class LlvmArtifactManifestTest {
    @Test
    fun `frozen Python v1 document is reproduced exactly and verified deterministically`() =
        withFixture { fixture ->
            val first = LlvmArtifactManifestVerifier.verify(fixture.manifest, fixture.artifactRoot)
            val second = LlvmArtifactManifestVerifier.verify(fixture.manifest, fixture.artifactRoot)

            assertEquals(first.manifestSha256, second.manifestSha256)
            assertEquals(first.full, second.full)
            assertEquals(first.stripped, second.stripped)
            assertEquals(FROZEN_MANIFEST_SHA256, first.manifestSha256)
            assertEquals(CHECKED_SOURCE_SHA256, first.sourceLockSha256)
            assertEquals(CHECKED_BUILD_SHA256, first.buildRecordSha256)
            assertEquals("clang-driver-22.1.6", first.oracleId)
            assertEquals("22.1.6", first.version)
            assertEquals("fc4aad7b5db3fff421df9a9637605b9ca5667881", first.sourceRevision)
            assertEquals(BUILD_ID, first.buildId)
            assertEquals(
                LlvmArtifactManifestArtifactIdentity(
                    "artifacts/clang-driver.full",
                    16_592,
                    FULL_SHA256,
                ),
                first.full,
            )
            assertEquals(
                LlvmArtifactManifestArtifactIdentity(
                    "artifacts/clang-driver.stripped",
                    14_320,
                    STRIPPED_SHA256,
                ),
                first.stripped,
            )

            val messages = LlvmArtifactManifestVerifierCli.successMessages(first)
            assertEquals(4, messages.size)
            assertTrue(messages.first().contains(BUILD_ID))
            assertTrue(messages[1].contains(FROZEN_MANIFEST_SHA256))
            assertTrue(messages[2].contains(FULL_SHA256))
            assertTrue(messages[3].contains(STRIPPED_SHA256))
        }

    @Test
    fun `duplicate noncanonical malformed and unknown manifest JSON fail before authority`() {
        withFixture { fixture ->
            val original = fixture.manifest.readText()
            Files.writeString(
                fixture.manifest,
                "{\n  \"schemaVersion\": 1,\n" + original.removePrefix("{\n"),
            )
            fixture.assertRejected()
        }
        withFixture { fixture ->
            Files.write(fixture.manifest, Files.readAllBytes(fixture.manifest) + ' '.code.toByte())
            fixture.assertRejected()
        }
        withFixture { fixture ->
            fixture.updateManifest { JsonObject(it + ("unknown" to JsonPrimitive(true))) }
            fixture.assertRejected()
        }
        withFixture { fixture ->
            Files.writeString(fixture.manifest, "{\"schemaVersion\":")
            fixture.assertRejected()
        }
    }

    @Test
    fun `integrated source build and local evidence parsing remains strict and bound`() {
        withFixture { fixture ->
            val original = fixture.buildRecord.readText()
            val duplicate = "{\n  \"schemaVersion\": 2,\n" + original.removePrefix("{\n")
            Files.writeString(fixture.buildRecord, duplicate)
            fixture.rebindManifestInput("buildRecord", fixture.buildRecord)
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val bytes = Files.readAllBytes(fixture.sourceLock) + ' '.code.toByte()
            Files.write(fixture.sourceLock, bytes)
            fixture.rebindManifestInput("sourceLock", fixture.sourceLock)
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val current = OracleJson.parseCanonical(Files.readAllBytes(fixture.buildRecord)) as JsonObject
            Files.write(
                fixture.buildRecord,
                OracleJson.canonicalBytes(JsonObject(current + ("unknown" to JsonPrimitive(true)))),
            )
            fixture.rebindManifestInput("buildRecord", fixture.buildRecord)
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val payload = fixture.profile.resolve("tag/llvmorg-22.1.6.payload")
            val realPayload = payload.resolveSibling("llvmorg-22.1.6.payload.real")
            Files.move(payload, realPayload)
            Files.createSymbolicLink(payload, realPayload.fileName)
            fixture.assertRejected()
        }
    }

    @Test
    fun `test source authority drift cannot produce production verification`() = withFixture { fixture ->
        val failure = assertFailsWith<LlvmArtifactManifestException> {
            LlvmArtifactManifestTestSupport.assess(
                fixture.manifest,
                fixture.artifactRoot,
                sourceLockAuthority = LlvmArtifactManifestSourceLockAuthority { path ->
                    LlvmSourceLockVerifier().verify(path).copy(lockSha256 = ZERO_SHA256)
                },
            )
        }
        assertTrue(failure.message.orEmpty().contains("different pinned identity"))
        assertFalse(LlvmArtifactManifestVerification::class.java.isAssignableFrom(
            LlvmArtifactManifestAssessment::class.java,
        ))
    }

    @Test
    fun `oracle input artifact ELF and equivalence binding classes all fail closed`() {
        val mutations: List<(JsonObject) -> JsonObject> = listOf(
            { root -> root.updateObject("oracle") { it.with("id", JsonPrimitive("other")) } },
            { root -> root.updateObject("inputs") { inputs ->
                inputs.updateObject("sourceLock") { it.with("bytes", JsonPrimitive(1)) }
            } },
            { root -> root.updateObject("inputs") { inputs ->
                inputs.updateObject("buildRecord") { it.with("sha256", JsonPrimitive(ZERO_SHA256)) }
            } },
            { root -> root.updateObject("artifacts") { artifacts ->
                artifacts.updateObject("full") { it.with("path", JsonPrimitive("artifacts/other.full")) }
            } },
            { root -> root.updateObject("artifacts") { artifacts ->
                artifacts.updateObject("stripped") { it.with("sha256", JsonPrimitive(ZERO_SHA256)) }
            } },
            { root -> root.updateObject("artifacts") { artifacts ->
                artifacts.updateObject("full") { full ->
                    full.updateObject("elf") { elf ->
                        elf.updateObject("header") { it.with("entryPoint", JsonPrimitive(0)) }
                    }
                }
            } },
            { root -> root.updateObject("equivalence") {
                it.with("programHeadersSha256", JsonPrimitive(ZERO_SHA256))
            } },
            { root -> root.updateObject("equivalence") { equivalence ->
                equivalence.updateObject("metadataDelta") {
                    it.with("changedCommonSections", JsonArray(emptyList()))
                }
            } },
        )
        mutations.forEachIndexed { index, mutation ->
            withFixture { fixture ->
                fixture.updateManifest(mutation)
                val failure = fixture.assertRejected()
                assertTrue(failure.message.orEmpty().isNotEmpty(), "binding mutation $index")
            }
        }
    }

    @Test
    fun `traversal symlink root and same-file aliases are rejected`() {
        withFixture { fixture ->
            fixture.updateManifest { root ->
                root.updateObject("inputs") { inputs ->
                    inputs.updateObject("sourceLock") {
                        it.with("path", JsonPrimitive("../source-lock.json"))
                    }
                }
            }
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val realSource = fixture.profile.resolve("source-lock.real.json")
            Files.move(fixture.sourceLock, realSource)
            Files.createSymbolicLink(fixture.sourceLock, realSource.fileName)
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val realStripped = fixture.artifacts.resolve("stripped.real")
            Files.move(fixture.stripped, realStripped)
            Files.createSymbolicLink(fixture.stripped, realStripped.fileName)
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val alias = fixture.root.resolve("release-alias")
            Files.createSymbolicLink(alias, fixture.artifactRoot.fileName)
            assertFailsWith<LlvmArtifactManifestException> {
                LlvmArtifactManifestVerifier.verify(fixture.manifest, alias)
            }
        }
        withFixture { fixture ->
            Files.delete(fixture.stripped)
            Files.createLink(fixture.stripped, fixture.full)
            val failure = fixture.assertRejected()
            assertTrue(failure.message.orEmpty().contains("same file"))
        }
    }

    @Test
    fun `writable namespace directories and unconstrained nesting are rejected`() {
        listOf<(Fixture) -> Path>(
            { it.profile },
            { it.artifactRoot },
            { it.artifacts },
        ).forEachIndexed { index, target ->
            withFixture { fixture ->
                val directory = target(fixture)
                val permissions = Files.getPosixFilePermissions(directory).toMutableSet()
                permissions += if (index % 2 == 0) {
                    PosixFilePermission.GROUP_WRITE
                } else {
                    PosixFilePermission.OTHERS_WRITE
                }
                Files.setPosixFilePermissions(directory, permissions)
                val failure = fixture.assertRejected()
                assertTrue(failure.message.orEmpty().contains("writable") ||
                    failure.message.orEmpty().contains("permissions"))
            }
        }
        withFixture { fixture ->
            fixture.updateManifest { root ->
                root.updateObject("inputs") { inputs ->
                    inputs.updateObject("sourceLock") {
                        it.with("path", JsonPrimitive("nested/source-lock.json"))
                    }
                }
            }
            val failure = fixture.assertRejected()
            assertTrue(failure.message.orEmpty().contains("base name"))
        }
        withFixture { fixture ->
            fixture.updateBuildAndRebind { build ->
                build.updateObject("outputs") { outputs ->
                    outputs.with("full", JsonPrimitive("nested/artifacts/clang-driver.full"))
                }
            }
            val failure = fixture.assertRejected()
            assertTrue(failure.message.orEmpty().contains("at most one directory component"))
        }
    }

    @Test
    fun `terminal directory permission mutation is rejected`() = withFixture { fixture ->
        val failure = assertFailsWith<LlvmArtifactManifestException> {
            fixture.assess(
                faultInjector = LlvmArtifactManifestFaultInjector { point ->
                    if (point == LlvmArtifactManifestVerificationPoint.BEFORE_TERMINAL_REAUTHENTICATION) {
                        val permissions = Files.getPosixFilePermissions(fixture.artifacts).toMutableSet()
                        permissions += PosixFilePermission.GROUP_WRITE
                        Files.setPosixFilePermissions(fixture.artifacts, permissions)
                    }
                },
            )
        }
        assertTrue(failure.message.orEmpty().contains("permissions"))
    }

    @Test
    fun `build output equality and output-to-manifest drift are rejected`() {
        withFixture { fixture ->
            fixture.updateBuildAndRebind { build ->
                build.updateObject("outputs") { outputs ->
                    outputs.with("stripped", outputs.requiredTest("full"))
                }
            }
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val drift = fixture.artifacts.resolve("drift.stripped")
            Files.copy(fixture.stripped, drift)
            fixture.updateBuildAndRebind { build ->
                build.updateObject("outputs") { outputs ->
                    outputs.with("stripped", JsonPrimitive("artifacts/drift.stripped"))
                }
            }
            val failure = fixture.assertRejected()
            assertTrue(failure.message.orEmpty().contains("recomputed facts"))
        }
    }

    @Test
    fun `manifest input and ELF byte count and commitment bounds fail before unbounded work`() {
        withFixture { fixture ->
            val bytes = Files.size(fixture.manifest).toInt()
            assertFailsWith<LlvmArtifactManifestException> {
                fixture.assess(LlvmArtifactManifestLimits(maximumManifestBytes = bytes - 1))
            }
        }
        withFixture { fixture ->
            val bytes = Files.size(fixture.sourceLock).toInt()
            assertFailsWith<LlvmArtifactManifestException> {
                fixture.assess(LlvmArtifactManifestLimits(maximumInputBytes = bytes - 1))
            }
        }
        val elfLimits = listOf(
            BoundedElfTwinV1Limits(maximumFileBytes = 16_591, maximumRangeBytes = 16_591),
            BoundedElfTwinV1Limits(maximumProgramHeaders = 13),
            BoundedElfTwinV1Limits(maximumSectionHeaders = 34),
            BoundedElfTwinV1Limits(maximumCommitmentBytes = 16),
        )
        elfLimits.forEach { limit ->
            withFixture { fixture ->
                assertFailsWith<LlvmArtifactManifestException> {
                    fixture.assess(LlvmArtifactManifestLimits(elf = limit))
                }
            }
        }
    }

    @Test
    fun `manifest node count is charged before schema traversal`() = withFixture { fixture ->
        val values = "0,".repeat(100_001).removeSuffix(",")
        val hostile = "{\n  \"a\": [${values}],\n  \"schemaVersion\": 1\n}\n"
        assertTrue(hostile.toByteArray().size < 1024 * 1024)
        Files.writeString(fixture.manifest, hostile)
        val failure = fixture.assertRejected()
        assertTrue(failure.message.orEmpty().contains("strict bounded canonical JSON"))
    }

    @Test
    fun `terminal control and artifact mutations are rejected`() {
        val targets: List<(Fixture) -> Path> = listOf(
            { it.manifest },
            { it.sourceLock },
            { it.buildRecord },
            { it.full },
            { it.stripped },
        )
        targets.forEachIndexed { index, target ->
            withFixture { fixture ->
                val path = target(fixture)
                val original = Files.readAllBytes(path)
                val mutated = original.copyOf().also { bytes ->
                    bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
                }
                val failure = assertFailsWith<LlvmArtifactManifestException>("terminal target $index") {
                    fixture.assess(
                        faultInjector = LlvmArtifactManifestFaultInjector { point ->
                            if (point == LlvmArtifactManifestVerificationPoint.BEFORE_TERMINAL_REAUTHENTICATION) {
                                Files.write(path, mutated)
                            }
                        },
                    )
                }
                assertTrue(failure.message.orEmpty().contains("changed") || failure.message.orEmpty().contains("failed"))
            }
        }
    }

    @Test
    fun `terminal identical-byte pathname substitution is rejected by retained descriptors`() =
        withFixture { fixture ->
            val displaced = fixture.artifacts.resolve("stripped.displaced")
            val failure = assertFailsWith<LlvmArtifactManifestException> {
                fixture.assess(
                    faultInjector = LlvmArtifactManifestFaultInjector { point ->
                        if (point == LlvmArtifactManifestVerificationPoint.AFTER_ELF_TWIN_INSPECTED) {
                            Files.move(fixture.stripped, displaced, StandardCopyOption.ATOMIC_MOVE)
                            Files.copy(displaced, fixture.stripped)
                        }
                    },
                )
            }
            assertTrue(failure.message.orEmpty().contains("pathname changed"))
        }

    @Test
    fun `production JVM surface accepts only raw manifest and artifact-root paths`() {
        assertTrue(LlvmArtifactManifestVerification::class.java.isSealed)
        assertFalse(LlvmArtifactManifestVerification::class.java.isAssignableFrom(
            LlvmArtifactManifestAssessment::class.java,
        ))
        assertTrue(
            LlvmArtifactManifestVerifier::class.java.declaredConstructors.all {
                Modifier.isPrivate(it.modifiers)
            },
        )
        val authorityMethods = LlvmArtifactManifestVerifier::class.java.declaredMethods +
            LlvmArtifactManifestVerifier::class.java.declaredClasses.flatMap { it.declaredMethods.asList() }
        authorityMethods.filter { it.returnType == LlvmArtifactManifestVerification::class.java }.forEach { method ->
            assertEquals(listOf(Path::class.java, Path::class.java), method.parameterTypes.toList())
        }
        assertTrue(authorityMethods.any { it.returnType == LlvmArtifactManifestVerification::class.java })

        val forbidden = setOf(
            JsonElement::class.java,
            JsonObject::class.java,
            LlvmSourceLockVerification::class.java,
            LlvmBuildRecordV1::class.java,
            BoundedElfTwinResultV1::class.java,
            LlvmArtifactManifestAssessment::class.java,
        )
        val implementations = LlvmArtifactManifestVerifier::class.java.declaredClasses.filter {
            LlvmArtifactManifestVerification::class.java.isAssignableFrom(it)
        }
        assertTrue(implementations.isNotEmpty())
        implementations.flatMap { it.declaredConstructors.asList() }.forEach { constructor ->
            val rawInputs = constructor.parameterTypes.filterNot {
                it.name == "kotlin.jvm.internal.DefaultConstructorMarker"
            }
            assertEquals(listOf(Path::class.java, Path::class.java), rawInputs)
            assertTrue(constructor.parameterTypes.none { it in forbidden || it == ByteArray::class.java })
        }
        assertTrue(authorityMethods.flatMap { it.parameterTypes.asList() }.none {
            it in forbidden || it == ByteArray::class.java
        })
        assertTrue(
            LlvmArtifactManifestTestSupport::class.java.declaredMethods
                .filter { it.name == "assess" || it.name == "assess\$default" }
                .all { it.returnType == LlvmArtifactManifestAssessment::class.java },
        )
    }

    @Test
    fun `fixed CLI rejects arguments and missing or relative artifact root`() {
        listOf(
            arrayOf("unexpected") to { _: String -> "/tmp" },
            emptyArray<String>() to { _: String -> null },
            emptyArray<String>() to { _: String -> "relative" },
        ).forEach { (arguments, environment) ->
            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            assertEquals(1, LlvmArtifactManifestVerifierCli.run(arguments, environment, stdout::add, stderr::add))
            assertTrue(stdout.isEmpty())
            assertEquals(1, stderr.size)
        }
    }

    private fun withFixture(action: (Fixture) -> Unit) {
        val root = createTempDirectory("llvm-artifact-manifest-")
        try {
            val profile = root.resolve("profile")
            val artifacts = root.resolve("release/artifacts")
            Files.createDirectories(profile.resolve("tag"))
            Files.createDirectories(profile.resolve("keys"))
            Files.createDirectories(artifacts)
            copy(CHECKED_PROFILE.resolve("source-lock.json"), profile.resolve("source-lock.json"))
            copy(CHECKED_PROFILE.resolve("build-record.json"), profile.resolve("build-record.json"))
            copy(
                CHECKED_PROFILE.resolve("tag/llvmorg-22.1.6.payload"),
                profile.resolve("tag/llvmorg-22.1.6.payload"),
            )
            copy(
                CHECKED_PROFILE.resolve("tag/llvmorg-22.1.6.sig"),
                profile.resolve("tag/llvmorg-22.1.6.sig"),
            )
            copy(
                CHECKED_PROFILE.resolve("keys/douglas-yung-llvm-release.asc"),
                profile.resolve("keys/douglas-yung-llvm-release.asc"),
            )
            Files.write(artifacts.resolve("clang-driver.full"), frozenBytes("/oracle/elf-twin-v1/full.elf.b64"))
            Files.write(
                artifacts.resolve("clang-driver.stripped"),
                frozenBytes("/oracle/elf-twin-v1/stripped.elf.b64"),
            )
            val manifest = profile.resolve("oracle-manifest.json")
            val document = LlvmArtifactManifestTestSupport.recomputeCanonicalBytes(
                profile.resolve("source-lock.json"),
                profile.resolve("build-record.json"),
                root.resolve("release"),
                "source-lock.json",
                "build-record.json",
            )
            Files.write(manifest, document)
            action(Fixture(root, profile, root.resolve("release"), artifacts, manifest))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun copy(source: Path, target: Path) {
        Files.copy(source, target, StandardCopyOption.REPLACE_EXISTING)
    }

    private fun frozenBytes(resource: String): ByteArray = Base64.getMimeDecoder().decode(
        checkNotNull(javaClass.getResourceAsStream(resource)) { "missing frozen resource $resource" }.use {
            it.readBytes()
        },
    )

    private data class Fixture(
        val root: Path,
        val profile: Path,
        val artifactRoot: Path,
        val artifacts: Path,
        val manifest: Path,
    ) {
        val sourceLock: Path = profile.resolve("source-lock.json")
        val buildRecord: Path = profile.resolve("build-record.json")
        val full: Path = artifacts.resolve("clang-driver.full")
        val stripped: Path = artifacts.resolve("clang-driver.stripped")

        fun assertRejected(): LlvmArtifactManifestException =
            assertFailsWith { LlvmArtifactManifestVerifier.verify(manifest, artifactRoot) }

        fun assess(
            limits: LlvmArtifactManifestLimits = LlvmArtifactManifestLimits(),
            faultInjector: LlvmArtifactManifestFaultInjector? = null,
        ): LlvmArtifactManifestAssessment = LlvmArtifactManifestTestSupport.assess(
            manifest,
            artifactRoot,
            limits = limits,
            faultInjector = faultInjector,
        )

        fun updateManifest(change: (JsonObject) -> JsonObject) {
            val current = OracleJson.parseCanonical(Files.readAllBytes(manifest)) as JsonObject
            Files.write(manifest, OracleJson.canonicalBytes(change(current)))
        }

        fun updateBuildAndRebind(change: (JsonObject) -> JsonObject) {
            val current = OracleJson.parseCanonical(Files.readAllBytes(buildRecord)) as JsonObject
            val bytes = OracleJson.canonicalBytes(change(current))
            Files.write(buildRecord, bytes)
            rebindManifestInput("buildRecord", buildRecord)
        }

        fun rebindManifestInput(name: String, path: Path) {
            val bytes = Files.readAllBytes(path)
            updateManifest { root ->
                root.updateObject("inputs") { inputs ->
                    inputs.updateObject(name) { record ->
                        record.with("bytes", JsonPrimitive(bytes.size))
                            .with("sha256", JsonPrimitive(OracleArtifacts.sha256(bytes)))
                    }
                }
            }
        }
    }

    private companion object {
        val CHECKED_PROFILE: Path = Path.of("oracle/llvm/22.1.6")
        const val CHECKED_SOURCE_SHA256 = "179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306"
        const val CHECKED_BUILD_SHA256 = "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
        const val FROZEN_MANIFEST_SHA256 = "5ea5e2846978753fdb7d4c7ddc726224c2167c8e648abd12184625248a7b47ec"
        const val FULL_SHA256 = "28105cb58b619f88d8718e8cf30c0c3471b7f0c8825e95e171eebc940954b859"
        const val STRIPPED_SHA256 = "252d14c411b629fb9d4d7ca4334382ac771b28b5e5868e22c5f654a5980e6c77"
        const val BUILD_ID = "01736da25e781713aa42bddf9af30c9f0a2e007d"
        const val ZERO_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
    }
}

private fun JsonObject.with(name: String, value: JsonElement): JsonObject = JsonObject(this + (name to value))

private fun JsonObject.updateObject(name: String, change: (JsonObject) -> JsonObject): JsonObject {
    val current = this[name] as? JsonObject ?: error("test field $name is not an object")
    return with(name, change(current))
}

private fun JsonObject.requiredTest(name: String): JsonElement = this[name] ?: error("missing test field $name")
