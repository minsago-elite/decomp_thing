package decompengine.oracle.provenance

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Duration
import java.util.concurrent.CopyOnWriteArrayList
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.system.measureTimeMillis
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBuildEnvironmentTest {
    @Test
    fun `frozen checked build record preserves Python v2 semantics and v1 v3 profiles`() {
        val source = LlvmSourceLockVerifier().verify(CHECKED_SOURCE_LOCK)
        val checkedBytes = Files.readAllBytes(CHECKED_BUILD_RECORD)
        assertEquals(CHECKED_BUILD_SHA256, sha256(checkedBytes))
        val v2 = LlvmBuildRecordParser.parse(checkedBytes, source, CHECKED_SOURCE_SHA256)

        assertEquals(2, v2.schemaVersion)
        assertEquals("cmake-ninja", v2.buildSystem)
        assertEquals("clang-driver-22.1.6", v2.oracle.id)
        assertEquals("clang-driver-22.1.6", v2.oracle.sourceProfileId)
        assertEquals("22.1.6", v2.oracle.version)
        assertEquals("fc4aad7b5db3fff421df9a9637605b9ca5667881", v2.oracle.sourceRevision)
        assertEquals(CHECKED_SOURCE_SHA256, v2.oracle.sourceLockSha256)
        assertEquals("linux/amd64", v2.environment.container.platform)
        assertEquals(DETERMINISTIC_TEST_PATH, v2.environment.variables["PATH"])
        assertEquals(listOf("buildGenerator", "buildSystem", "compiler", "linker", "stripper"), v2.tools.map { it.role })
        assertEquals("/usr/lib/llvm-22/bin/llvm-objcopy", v2.commands.strip.first())
        assertEquals("artifacts/clang-driver.full", v2.outputs.full)
        assertEquals("artifacts/clang-driver.stripped", v2.outputs.stripped)

        val root = OracleJson.parseCanonical(checkedBytes) as JsonObject
        val sourceDirectory = v2.directories.source
        val v1Root = JsonObject(
            root.minus("buildSystem") + (
                "schemaVersion" to JsonPrimitive(1)
                ) + (
                "commands" to root.requiredTestObject("commands").testWith(
                    "configure",
                    JsonArray(listOf(JsonPrimitive("$sourceDirectory/configure"))),
                )
                ),
        )
        val v1 = LlvmBuildRecordParser.parse(
            OracleJson.canonicalBytes(v1Root),
            source,
            CHECKED_SOURCE_SHA256,
        )
        assertEquals(1, v1.schemaVersion)
        assertEquals("autoconf", v1.buildSystem)
        assertEquals(v1.oracle.id, v1.oracle.sourceProfileId)

        val v3Root = root.testWith("schemaVersion", JsonPrimitive(3)).testUpdateObject("oracle") { oracle ->
            oracle.testWith("id", JsonPrimitive("clang-driver-artifact-22.1.6"))
                .testWith("sourceProfileId", JsonPrimitive(source.oracleId))
        }
        val v3 = LlvmBuildRecordParser.parse(
            OracleJson.canonicalBytes(v3Root),
            source,
            CHECKED_SOURCE_SHA256,
        )
        assertEquals(3, v3.schemaVersion)
        assertEquals("clang-driver-artifact-22.1.6", v3.oracle.id)
        assertEquals(source.oracleId, v3.oracle.sourceProfileId)
    }

    @Test
    fun `sealed production verifier authenticates live local tools deterministically`() = withFixture { fixture ->
        val first = LlvmBuildEnvironmentVerifier.verify(
            fixture.sourceLockPath,
            fixture.buildRecordPath,
            RECORDED_ORIGIN_DIGEST,
        )
        val second = LlvmBuildEnvironmentVerifier.verify(
            fixture.sourceLockPath,
            fixture.buildRecordPath,
            RECORDED_ORIGIN_DIGEST,
        )

        assertEquals(CHECKED_SOURCE_SHA256, first.sourceLockSha256)
        assertEquals(RECORDED_ORIGIN_DIGEST, first.recordedOriginDigest)
        assertEquals(sha256(Files.readAllBytes(fixture.buildRecordPath)), first.buildRecordSha256)
        assertEquals(first.buildRecordSha256, second.buildRecordSha256)
        assertEquals(first.record, second.record)
        assertEquals(listOf("compiler", "linker", "stripper"), first.record.tools.map { it.role })
        assertTrue(first.record.tools.all { it.executableSha256 == fixture.toolSha256 })
        assertTrue(first.record.tools.all { it.executableBytes == fixture.toolBytes.size.toLong() })

        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (first.record.environment.variables as MutableMap<String, String>)["LC_ALL"] = "mutated"
        }
        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (first.record.commands.configure as MutableList<String>).clear()
        }
        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (first.record.tools as MutableList<LlvmBuildToolV1>).clear()
        }
        @Suppress("UNCHECKED_CAST")
        assertFailsWith<UnsupportedOperationException> {
            (first.record.tools.first().versionCommand as MutableList<String>).clear()
        }
        assertEquals("C", first.record.environment.variables["LC_ALL"])
        assertEquals(3, first.record.tools.size)
    }

    @Test
    fun `CLI accepts only explicit options and uses the sealed production authority`() = withFixture { fixture ->
        val invalid = listOf(
            emptyArray(),
            arrayOf("--source-lock", fixture.sourceLockPath.toString()),
            arrayOf("--source-lock"),
            arrayOf(
                "--source-lock",
                fixture.sourceLockPath.toString(),
                "--build-record",
                fixture.buildRecordPath.toString(),
                "--recorded-origin-digest",
                "",
            ),
            arrayOf(
                "--source-lock",
                fixture.sourceLockPath.toString(),
                "--source-lock",
                fixture.sourceLockPath.toString(),
                "--build-record",
                fixture.buildRecordPath.toString(),
                "--recorded-origin-digest",
                RECORDED_ORIGIN_DIGEST,
            ),
            arrayOf("--unknown", "value"),
            arrayOf("--container-digest", RECORDED_ORIGIN_DIGEST),
        )
        invalid.forEach { arguments ->
            val stdout = mutableListOf<String>()
            val stderr = mutableListOf<String>()
            assertEquals(1, LlvmBuildEnvironmentVerifierCli.run(arguments, stdout::add, stderr::add))
            assertTrue(stdout.isEmpty())
            assertEquals(1, stderr.size)
            assertTrue(stderr.single().startsWith("LLVM build-record verification failed: "))
        }

        val stdout = mutableListOf<String>()
        val stderr = mutableListOf<String>()
        val status = LlvmBuildEnvironmentVerifierCli.run(
            arrayOf(
                "--source-lock",
                fixture.sourceLockPath.toString(),
                "--build-record",
                fixture.buildRecordPath.toString(),
                "--recorded-origin-digest",
                RECORDED_ORIGIN_DIGEST,
            ),
            stdout::add,
            stderr::add,
        )
        assertEquals(0, status)
        assertTrue(stderr.isEmpty())
        assertEquals(
            listOf(
                "verified LLVM oracle build environment for recorded origin: " +
                    "fixture-llvm-toolchain@$RECORDED_ORIGIN_DIGEST",
                "  compiler: compiler version",
                "  linker: linker version",
                "  stripper: stripper version",
            ),
            stdout,
        )
    }

    @Test
    fun `duplicate noncanonical and schema-invalid source or build JSON fail closed`() {
        withFixture { fixture ->
            val text = fixture.buildRecordPath.readText()
            Files.writeString(
                fixture.buildRecordPath,
                "{\n  \"schemaVersion\": 2,\n" + text.removePrefix("{\n"),
            )
            fixture.assertRejected()
        }
        withFixture { fixture ->
            Files.write(fixture.buildRecordPath, Files.readAllBytes(fixture.buildRecordPath) + ' '.code.toByte())
            fixture.assertRejected()
        }
        withFixture { fixture ->
            fixture.updateBuild { it.testWith("unexpected", JsonPrimitive(true)) }
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val text = fixture.sourceLockPath.readText()
            Files.writeString(
                fixture.sourceLockPath,
                "{\n  \"schemaVersion\": 1,\n" + text.removePrefix("{\n"),
            )
            fixture.assertRejected()
        }
        withFixture { fixture ->
            Files.write(fixture.sourceLockPath, Files.readAllBytes(fixture.sourceLockPath) + ' '.code.toByte())
            fixture.assertRejected()
        }
    }

    @Test
    fun `source directory command placeholder output and digest semantic drift fail closed`() {
        val mutations: List<(JsonObject) -> JsonObject> = listOf(
            { root ->
                root.testUpdateObject("oracle") { oracle ->
                    oracle.testWith("sourceLockSha256", JsonPrimitive("0".repeat(64)))
                }
            },
            { root ->
                root.testUpdateObject("oracle") { oracle ->
                    oracle.testWith("sourceRevision", JsonPrimitive("0".repeat(40)))
                }
            },
            { root ->
                root.testUpdateObject("directories") { directories ->
                    directories.testWith("build", JsonPrimitive("/oracle/llvm-project-22.1.6.src/nested"))
                }
            },
            { root ->
                root.testUpdateObject("commands") { commands ->
                    val configure = commands.requiredTestArray("configure").toMutableList()
                    configure += JsonPrimitive("-S")
                    configure += JsonPrimitive("/oracle/llvm-project-22.1.6.src/llvm")
                    commands.testWith("configure", JsonArray(configure))
                }
            },
            { root ->
                root.testUpdateObject("commands") { commands ->
                    commands.testWith("stageFull", JsonArray(listOf(JsonPrimitive("install"))))
                }
            },
            { root ->
                root.testUpdateObject("commands") { commands ->
                    val strip = commands.requiredTestArray("strip").filterNot {
                        (it as JsonPrimitive).content == "--strip-all"
                    }
                    commands.testWith("strip", JsonArray(strip))
                }
            },
            { root ->
                root.testUpdateObject("outputs") { outputs ->
                    outputs.testWith("stripped", outputs.getValue("full"))
                }
            },
        )
        mutations.forEach { mutation ->
            withFixture { fixture ->
                fixture.updateBuild(mutation)
                fixture.assertRejected()
            }
        }
        withFixture { fixture ->
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                LlvmBuildEnvironmentVerifier.verify(
                    fixture.sourceLockPath,
                    fixture.buildRecordPath,
                    "sha256:${"b".repeat(64)}",
                )
            }
            assertTrue(failure.message.orEmpty().contains("digest mismatch"))
        }
    }

    @Test
    fun `secrets PATH and tool reorder duplicate or missing roles fail closed`() {
        val mutations: List<(JsonObject) -> JsonObject> = listOf(
            { root ->
                root.testUpdateObject("environment") { environment ->
                    environment.testUpdateObject("variables") { variables ->
                        variables.testWith("API_KEY", JsonPrimitive("not-allowed"))
                    }
                }
            },
            { root ->
                root.testUpdateObject("environment") { environment ->
                    environment.testUpdateObject("variables") { variables ->
                        variables.testWith("PATH", JsonPrimitive("/untrusted/bin"))
                    }
                }
            },
            { root -> root.testWith("tools", JsonArray(root.requiredTestArray("tools").reversed())) },
            { root ->
                val tools = root.requiredTestArray("tools").toMutableList()
                tools[1] = (tools[1] as JsonObject).testWith("role", JsonPrimitive("compiler"))
                root.testWith("tools", JsonArray(tools))
            },
            { root ->
                val tools = root.requiredTestArray("tools").toMutableList()
                tools[1] = (tools[1] as JsonObject).testWith("role", JsonPrimitive("optimizer"))
                root.testWith("tools", JsonArray(tools))
            },
        )
        mutations.forEach { mutation ->
            withFixture { fixture ->
                fixture.updateBuild(mutation)
                fixture.assertRejected()
            }
        }
    }

    @Test
    fun `injected runner observes exact argv cleared environment root cwd and platform`() = withFixture { fixture ->
        val requests = CopyOnWriteArrayList<LlvmToolVersionProcessRequest>()
        val runner = LlvmToolVersionProcessRunner { request ->
            requests += request
            val role = request.command.singleOrNull { it in REQUIRED_ROLES }
            assertNotNull(role)
            LlvmToolVersionProcessResult(0, "$role version\n".toByteArray())
        }
        val assessment = fixture.assess(runner = runner)

        assertEquals(REQUIRED_ROLES, assessment.record.tools.map { it.role })
        assertEquals(3, requests.size)
        requests.zip(assessment.record.tools).forEach { (request, tool) ->
            assertEquals(tool.versionCommand, request.command)
            assertEquals(Path.of("/"), request.workingDirectory)
            assertEquals(Duration.ofSeconds(30), request.timeout)
            assertEquals(1024 * 1024, request.maximumOutputBytes)
            assertEquals(
                mapOf(
                    "LC_ALL" to "C",
                    "PATH" to DETERMINISTIC_TEST_PATH,
                    "SOURCE_DATE_EPOCH" to "1779182222",
                    "TZ" to "UTC",
                ),
                request.environment,
            )
            assertFalse(request.environment.containsKey("DECOMP_ACP_PARENT_SECRET_CANARY"))
        }

        val platformFailure = assertFailsWith<LlvmBuildEnvironmentException> {
            fixture.assess(
                runner = runner,
                platform = LlvmBuildPlatform("Linux", "aarch64"),
            )
        }
        assertTrue(platformFailure.message.orEmpty().contains("Linux x86-64"))
    }

    @Test
    fun `exit output flood non-UTF8 mismatch and process failures are rejected`() {
        val cases = listOf<LlvmToolVersionProcessRunner>(
            LlvmToolVersionProcessRunner { LlvmToolVersionProcessResult(7, ByteArray(0)) },
            LlvmToolVersionProcessRunner { LlvmToolVersionProcessResult(0, "wrong\n".toByteArray()) },
            LlvmToolVersionProcessRunner { LlvmToolVersionProcessResult(0, byteArrayOf(0xff.toByte())) },
            LlvmToolVersionProcessRunner { LlvmToolVersionProcessResult(0, ByteArray(1024 * 1024 + 1)) },
            LlvmToolVersionProcessRunner { throw LlvmBuildEnvironmentException("injected timeout") },
        )
        cases.forEach { runner ->
            withFixture { fixture ->
                assertFailsWith<LlvmBuildEnvironmentException> { fixture.assess(runner = runner) }
            }
        }
    }

    @Test
    fun `real process runner bounds timeout and output flood cleanup`() {
        val environment = mapOf("PATH" to DETERMINISTIC_TEST_PATH)
        val timeoutRequest = LlvmToolVersionProcessRequest(
            command = listOf("/bin/sh", "-c", "sleep 10"),
            environment = environment,
            workingDirectory = Path.of("/"),
            timeout = Duration.ofMillis(100),
            maximumOutputBytes = 1024,
            cleanupTimeout = Duration.ofSeconds(1),
        )
        val timeoutElapsed = measureTimeMillis {
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                JvmLlvmToolVersionProcessRunner.run(timeoutRequest)
            }
            assertTrue(failure.message.orEmpty().contains("deadline"))
        }
        assertTrue(timeoutElapsed < 3_000, "timeout cleanup took ${timeoutElapsed}ms")

        val floodRequest = timeoutRequest.copy(
            command = listOf("/bin/sh", "-c", "while :; do printf 0123456789; done"),
            timeout = Duration.ofSeconds(2),
            maximumOutputBytes = 128,
        )
        val floodElapsed = measureTimeMillis {
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                JvmLlvmToolVersionProcessRunner.run(floodRequest)
            }
            assertTrue(failure.message.orEmpty().contains("output-byte bound"))
        }
        assertTrue(floodElapsed < 3_000, "flood cleanup took ${floodElapsed}ms")
    }

    @Test
    fun `symlink substitution and same-inode tool or input mutation fail terminal authentication`() {
        withFixture { fixture ->
            val real = fixture.root.resolve("real-tool")
            Files.move(fixture.toolPath, real)
            Files.createSymbolicLink(fixture.toolPath, real.fileName)
            fixture.assertRejected()
        }
        withFixture { fixture ->
            val displaced = fixture.root.resolve("displaced-tool")
            var changed = false
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                fixture.assess(
                    faultInjector = LlvmBuildVerificationFaultInjector { point, _ ->
                        if (!changed && point == LlvmBuildVerificationPoint.AFTER_TOOLS_AUTHENTICATED) {
                            changed = true
                            Files.move(fixture.toolPath, displaced, StandardCopyOption.ATOMIC_MOVE)
                            Files.copy(displaced, fixture.toolPath)
                            Files.setPosixFilePermissions(
                                fixture.toolPath,
                                PosixFilePermissions.fromString("rwx------"),
                            )
                        }
                    },
                )
            }
            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("pathname changed"))
        }
        withFixture { fixture ->
            var changed = false
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                fixture.assess(
                    faultInjector = LlvmBuildVerificationFaultInjector { point, _ ->
                        if (!changed && point == LlvmBuildVerificationPoint.AFTER_TOOL_EXECUTION) {
                            changed = true
                            val bytes = Files.readAllBytes(fixture.toolPath)
                            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
                            Files.write(fixture.toolPath, bytes)
                        }
                    },
                )
            }
            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("SHA-256 mismatch"))
        }
        withFixture { fixture ->
            val displaced = fixture.root.resolve("displaced-build-record.json")
            var changed = false
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                fixture.assess(
                    faultInjector = LlvmBuildVerificationFaultInjector { point, _ ->
                        if (!changed && point == LlvmBuildVerificationPoint.BEFORE_TERMINAL_REAUTHENTICATION) {
                            changed = true
                            Files.move(fixture.buildRecordPath, displaced, StandardCopyOption.ATOMIC_MOVE)
                            Files.copy(displaced, fixture.buildRecordPath)
                        }
                    },
                )
            }
            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("pathname changed"))
        }
        withFixture { fixture ->
            var changed = false
            val failure = assertFailsWith<LlvmBuildEnvironmentException> {
                fixture.assess(
                    faultInjector = LlvmBuildVerificationFaultInjector { point, _ ->
                        if (!changed && point == LlvmBuildVerificationPoint.BEFORE_TERMINAL_REAUTHENTICATION) {
                            changed = true
                            val bytes = Files.readAllBytes(fixture.sourceLockPath)
                            bytes[bytes.lastIndex] = ' '.code.toByte()
                            Files.write(fixture.sourceLockPath, bytes)
                        }
                    },
                )
            }
            assertTrue(changed)
            assertTrue(failure.message.orEmpty().contains("SHA-256 mismatch"))
        }
    }

    @Test
    fun `authority result and verifier cannot be constructed with injected JVM dependencies`() {
        val verificationType = LlvmBuildEnvironmentVerification::class.java
        assertTrue(verificationType.isSealed)
        assertTrue(verificationType.declaredConstructors.isEmpty())
        assertEquals(1, verificationType.permittedSubclasses.size)
        assertTrue(verificationType.permittedSubclasses.all { Modifier.isPrivate(it.modifiers) })
        val implementation = verificationType.permittedSubclasses.single()
        assertTrue(implementation.declaredConstructors.isNotEmpty())
        assertEquals(
            1,
            implementation.declaredConstructors.count { Modifier.isPrivate(it.modifiers) },
        )
        val productionParameters = listOf(Path::class.java, Path::class.java, String::class.java)
        val privateConstructor = implementation.declaredConstructors.single {
            Modifier.isPrivate(it.modifiers)
        }
        assertEquals(productionParameters, privateConstructor.parameterTypes.toList())
        val constructorBridges = implementation.declaredConstructors.filterNot {
            Modifier.isPrivate(it.modifiers)
        }
        assertEquals(1, constructorBridges.size)
        assertTrue(
            constructorBridges.all { constructor ->
                constructor.isSynthetic &&
                    constructor.parameterTypes.dropLast(1) == productionParameters &&
                    constructor.parameterTypes.last().name == "kotlin.jvm.internal.DefaultConstructorMarker"
            },
        )
        assertTrue(
            LlvmBuildEnvironmentVerifier::class.java.declaredConstructors.all {
                Modifier.isPrivate(it.modifiers)
            },
        )
        val authorityMethods = LlvmBuildEnvironmentVerification::class.java.declaredMethods +
            LlvmBuildEnvironmentVerifier::class.java.declaredMethods +
            implementation.declaredMethods +
            implementation.declaredClasses.flatMap { it.declaredMethods.toList() }
        val forbiddenAuthorityInputs = setOf(
            LlvmBuildSourceLockAuthority::class.java,
            LlvmBuildPlatformAuthority::class.java,
            LlvmToolVersionProcessRunner::class.java,
            LlvmBuildVerificationFaultInjector::class.java,
            LlvmBuildEnvironmentAssessment::class.java,
            LlvmBuildRecordV1::class.java,
        )
        assertTrue(
            authorityMethods.none { method ->
                method.parameterTypes.any { it in forbiddenAuthorityInputs }
            },
        )
        val assessmentMethods = LlvmBuildEnvironmentTestSupport::class.java.declaredMethods
            .filter { it.name == "assess" }
        assertTrue(assessmentMethods.isNotEmpty())
        assertTrue(assessmentMethods.all { it.returnType == LlvmBuildEnvironmentAssessment::class.java })
    }

    private fun withFixture(action: (MutableBuildFixture) -> Unit) {
        val root = createTempDirectory("llvm-build-environment-")
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(MutableBuildFixture(root))
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}

private class MutableBuildFixture(val root: Path) {
    val sourceDirectory: Path = root.resolve("profile")
    val sourceLockPath: Path = sourceDirectory.resolve("source-lock.json")
    val buildRecordPath: Path = root.resolve("build-record.json")
    val toolPath: Path = root.resolve("version-tool")
    val toolBytes: ByteArray = "#!/bin/sh\nprintf '%s version\\n' \"\$1\"\n".toByteArray()
    val toolSha256: String = sha256(toolBytes)

    init {
        Files.createDirectories(sourceDirectory.resolve("keys"))
        Files.createDirectories(sourceDirectory.resolve("tag"))
        Files.copy(CHECKED_SOURCE_LOCK, sourceLockPath)
        Files.copy(CHECKED_PROFILE.resolve("keys/douglas-yung-llvm-release.asc"), sourceDirectory.resolve("keys/douglas-yung-llvm-release.asc"))
        Files.copy(CHECKED_PROFILE.resolve("tag/llvmorg-22.1.6.payload"), sourceDirectory.resolve("tag/llvmorg-22.1.6.payload"))
        Files.copy(CHECKED_PROFILE.resolve("tag/llvmorg-22.1.6.sig"), sourceDirectory.resolve("tag/llvmorg-22.1.6.sig"))
        Files.write(toolPath, toolBytes)
        Files.setPosixFilePermissions(toolPath, PosixFilePermissions.fromString("rwx------"))
        writeBuild(fixtureBuildRecord())
    }

    fun assess(
        runner: LlvmToolVersionProcessRunner = LlvmToolVersionProcessRunner { request ->
            JvmLlvmToolVersionProcessRunner.run(request)
        },
        platform: LlvmBuildPlatform = LlvmBuildPlatform("Linux", "x86_64"),
        faultInjector: LlvmBuildVerificationFaultInjector? = null,
    ): LlvmBuildEnvironmentAssessment = LlvmBuildEnvironmentTestSupport.assess(
        sourceLockPath,
        buildRecordPath,
        RECORDED_ORIGIN_DIGEST,
        platformAuthority = LlvmBuildPlatformAuthority { platform },
        processRunner = runner,
        faultInjector = faultInjector,
    )

    fun assertRejected() {
        assertFailsWith<LlvmBuildEnvironmentException> {
            LlvmBuildEnvironmentVerifier.verify(sourceLockPath, buildRecordPath, RECORDED_ORIGIN_DIGEST)
        }
    }

    fun updateBuild(transform: (JsonObject) -> JsonObject) {
        val root = OracleJson.parseCanonical(Files.readAllBytes(buildRecordPath)) as JsonObject
        writeBuild(transform(root))
    }

    private fun writeBuild(root: JsonObject) {
        Files.write(buildRecordPath, OracleJson.canonicalBytes(root))
    }

    private fun fixtureBuildRecord(): JsonObject {
        val checked = OracleJson.parseCanonical(Files.readAllBytes(CHECKED_BUILD_RECORD)) as JsonObject
        val tools = JsonArray(REQUIRED_ROLES.map { role ->
            JsonObject(
                mapOf(
                    "executableBytes" to JsonPrimitive(toolBytes.size),
                    "executableSha256" to JsonPrimitive(toolSha256),
                    "path" to JsonPrimitive(toolPath.toString()),
                    "role" to JsonPrimitive(role),
                    "versionCommand" to JsonArray(listOf(JsonPrimitive(toolPath.toString()), JsonPrimitive(role))),
                    "versionOutput" to JsonPrimitive("$role version\n"),
                ),
            )
        })
        return checked
            .testUpdateObject("environment") { environment ->
                environment.testUpdateObject("container") { container ->
                    container.testWith("image", JsonPrimitive("fixture-llvm-toolchain"))
                        .testWith("digest", JsonPrimitive(RECORDED_ORIGIN_DIGEST))
                }
            }
            .testWith("tools", tools)
            .testUpdateObject("commands") { commands ->
                commands.testWith(
                    "strip",
                    JsonArray(
                        listOf(
                            JsonPrimitive(toolPath.toString()),
                            JsonPrimitive("--strip-all"),
                            JsonPrimitive("{full}"),
                            JsonPrimitive("{stripped}"),
                        ),
                    ),
                )
            }
    }
}

private fun JsonObject.testWith(name: String, value: JsonElement): JsonObject = JsonObject(this + (name to value))

private fun JsonObject.testUpdateObject(name: String, transform: (JsonObject) -> JsonObject): JsonObject =
    testWith(name, transform(requiredTestObject(name)))

private fun JsonObject.requiredTestObject(name: String): JsonObject = getValue(name) as JsonObject

private fun JsonObject.requiredTestArray(name: String): JsonArray = getValue(name) as JsonArray

private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes)
    .joinToString("") { byte -> (byte.toInt() and 0xff).toString(16).padStart(2, '0') }

private val CHECKED_PROFILE = Path.of("oracle/llvm/22.1.6").toAbsolutePath().normalize()
private val CHECKED_SOURCE_LOCK = CHECKED_PROFILE.resolve("source-lock.json")
private val CHECKED_BUILD_RECORD = CHECKED_PROFILE.resolve("build-record.json")
private const val CHECKED_SOURCE_SHA256 = "179b1298b14ddb701c46eb1ed6a5bb0aa60ee01580bafcf5c555b1d13c994306"
private const val CHECKED_BUILD_SHA256 = "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
private const val RECORDED_ORIGIN_DIGEST =
    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
private const val DETERMINISTIC_TEST_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
private val REQUIRED_ROLES = listOf("compiler", "linker", "stripper")
