package decompengine.oracle.behavior

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.Modifier
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermission
import kotlin.io.path.createDirectories
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmBehaviorRuntimePreflightTest {
    @Test
    fun `non-authoritative parser reproduces historical query and digest semantics`() {
        val verified = verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), fixtureResponses())

        assertFalse(verified.authority)
        assertEquals(
            listOf("client-version", "engine-identity", "security-capabilities", "image-identity"),
            verified.queryIds,
        )
        assertEquals(COMPONENTS_SHA256, verified.componentsSha256)
        assertEquals(FEATURES_SHA256, verified.runtimeFeaturesSha256)

        assertEquals(
            listOf(
                listOf("/pinned/client", "--version"),
                listOf("/pinned/client", "version", "--format", "{{json .Server}}"),
                listOf(
                    "/pinned/client",
                    "info",
                    "--format",
                    "{{json .SecurityOptions}}\n{{.CgroupVersion}}\n{{.CgroupDriver}}\n" +
                        "{{.Driver}}\n{{json .Plugins.Volume}}\n{{json .Runtimes}}",
                ),
                listOf("/pinned/client", "image", "inspect", IMAGE_DIGEST),
            ),
            runtimeCommandArgumentsForNonAuthoritativeTest(fixtureCorpus(), Path.of("/pinned/client")),
        )
    }

    @Test
    fun `component digest excludes only historical volatile detail pairs and sorts by code point`() {
        val first = fixtureResponses(stateDirectory = "/volatile/one", reverseComponents = false)
        val second = fixtureResponses(stateDirectory = "/volatile/two", reverseComponents = true)
        assertEquals(COMPONENTS_SHA256, verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), first).componentsSha256)
        assertEquals(COMPONENTS_SHA256, verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), second).componentsSha256)

        val changed = fixtureResponses(engineCommit = "different-stable-commit")
        assertFailsWith<LlvmBehaviorRuntimePreflightException> {
            verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), changed)
        }
        val contradictoryKernel = fixtureResponses(componentKernel = "contradictory")
        val failure = assertFailsWith<LlvmBehaviorRuntimePreflightException> {
            verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), contradictoryKernel)
        }
        assertTrue(failure.message.orEmpty().contains("kernel versions"), failure.message)
    }

    @Test
    fun `every declared engine image platform and security field is compared`() {
        val mutations = linkedMapOf<String, (JsonObject) -> JsonObject>(
            "product" to { it.withEngine("product", JsonPrimitive("other")) },
            "serverVersion" to { it.withEngine("serverVersion", JsonPrimitive("other")) },
            "serverCommit" to { it.withEngine("serverCommit", JsonPrimitive("other")) },
            "apiVersion" to { it.withEngine("apiVersion", JsonPrimitive("9.9")) },
            "operatingSystem" to { it.withEngine("operatingSystem", JsonPrimitive("other")) },
            "architecture" to { it.withEngine("architecture", JsonPrimitive("other")) },
            "kernelVersion" to { it.withEngine("kernelVersion", JsonPrimitive("other")) },
            "componentsSha256" to { it.withEngine("componentsSha256", JsonPrimitive(ZERO_SHA256)) },
            "cgroupVersion" to { it.withEngine("cgroupVersion", JsonPrimitive(1)) },
            "cgroupDriver" to { it.withEngine("cgroupDriver", JsonPrimitive("other")) },
            "storageDriver" to { it.withEngine("storageDriver", JsonPrimitive("other")) },
            "securityOptions" to {
                it.withEngine("securityOptions", JsonArray(listOf(JsonPrimitive("name=cgroupns"))))
            },
            "containerRuntime" to { it.withEngine("containerRuntime", JsonPrimitive("crun")) },
            "containerRuntimePath" to { it.withEngine("containerRuntimePath", JsonPrimitive("other")) },
            "containerRuntimeVersion" to { it.withEngine("containerRuntimeVersion", JsonPrimitive("other")) },
            "containerRuntimeCommit" to { it.withEngine("containerRuntimeCommit", JsonPrimitive("other")) },
            "containerRuntimeFeaturesSha256" to {
                it.withEngine("containerRuntimeFeaturesSha256", JsonPrimitive(ZERO_SHA256))
            },
            "volumePlugin" to { it.withEngine("volumePlugin", JsonPrimitive("other")) },
            "imageDigest" to { it.withSandbox("imageDigest", JsonPrimitive("sha256:${"b".repeat(64)}")) },
            "platform" to { it.withSandbox("platform", JsonPrimitive("linux/arm64")) },
            "imageEnvironment" to {
                it.withSandbox("imageEnvironment", JsonArray(listOf(JsonPrimitive("PATH=/other"))))
            },
        )
        mutations.forEach { (field, mutation) ->
            val failure = assertFailsWith<LlvmBehaviorRuntimePreflightException>(field) {
                verifyRuntimeResponsesForNonAuthoritativeTest(mutation(fixtureCorpus()), fixtureResponses())
            }
            assertTrue(failure.message.orEmpty().isNotEmpty(), field)
        }
    }

    @Test
    fun `malformed incomplete failed and signaled query responses fail closed`() {
        fun fails(responses: List<NonAuthoritativeRuntimeResponse>) =
            assertFailsWith<LlvmBehaviorRuntimePreflightException> {
                verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), responses)
            }

        fails(fixtureResponses().toMutableList().also { it[1] = response("{\"bad\":") })
        fails(fixtureResponses().toMutableList().also { it[1] = response(byteArrayOf(0xc3.toByte(), 0x28)) })
        fails(fixtureResponses().toMutableList().also {
            it[2] = response("[]\n2\nsystemd\noverlay2\n[\"local\"]\n{}")
        })
        fails(fixtureResponses().toMutableList().also {
            it[0] = NonAuthoritativeRuntimeResponse(exitCode = 7, stdout = ByteArray(0), stderr = "no daemon".encodeToByteArray())
        })
        fails(fixtureResponses().toMutableList().also {
            it[0] = NonAuthoritativeRuntimeResponse(exitCode = null, signal = 9, stdout = ByteArray(0))
        })
        fails(fixtureResponses().dropLast(1))

        val successfulDiagnostic = fixtureResponses().toMutableList().also {
            it[0] = NonAuthoritativeRuntimeResponse(
                exitCode = 0,
                stdout = "fixture-client 1\n".encodeToByteArray(),
                stderr = "bounded client diagnostic\n".encodeToByteArray(),
            )
        }
        assertFalse(verifyRuntimeResponsesForNonAuthoritativeTest(fixtureCorpus(), successfulDiagnostic).authority)
    }

    @Test
    fun `lowering limits and production JVM shape expose no runner facts or callbacks`() {
        assertFailsWith<IllegalArgumentException> { LlvmBehaviorRuntimePreflightLimits(commandTimeoutMilliseconds = 30_001) }
        assertFailsWith<IllegalArgumentException> { LlvmBehaviorRuntimePreflightLimits(maximumCommandStdoutBytes = 0) }
        assertFailsWith<IllegalArgumentException> { LlvmBehaviorRuntimePreflightLimits(maximumControlClientBytes = 0) }

        val publish = LlvmBehaviorRuntimePreflightPublisher::class.java.declaredMethods.single {
            it.name == "publish" && !it.isSynthetic
        }
        assertEquals(
            List(8) { Path::class.java } + LlvmBehaviorRuntimePreflightLimits::class.java,
            publish.parameterTypes.toList(),
        )
        assertTrue(publish.parameterTypes.none { it.name.contains("Json") || it.name.contains("Runner") || it.name.contains("Function") })
        val implementation = LlvmBehaviorRuntimePreflightPublisher::class.java.declaredClasses.single {
            LlvmBehaviorRuntimePreflight::class.java.isAssignableFrom(it)
        }
        assertTrue(Modifier.isPrivate(implementation.modifiers))
        assertEquals(
            List(8) { Path::class.java } + LlvmBehaviorRuntimePreflightLimits::class.java,
            implementation.declaredConstructors.single().parameterTypes.toList(),
        )
    }

    @Test
    fun `relative inputs fail before any runtime process can start`() {
        val relative = Path.of("relative")
        val failure = assertFailsWith<LlvmBehaviorRuntimePreflightException> {
            LlvmBehaviorRuntimePreflightPublisher.publish(
                relative, relative, relative, relative, relative, relative, relative, relative,
            )
        }
        assertTrue(failure.message.orEmpty().contains("absolute"), failure.message)
    }

    @Test
    fun `directory inode aliases fail before any runtime process can start`() {
        val root = Files.createTempDirectory("llvm-runtime-preflight-alias-")
        try {
            val inputs = privateDirectory(root.resolve("inputs"))
            val first = privateDirectory(root.resolve("first"))
            val second = privateDirectory(root.resolve("second"))
            val third = privateDirectory(root.resolve("third"))
            fun alias(name: String, target: Path): Path = root.resolve(name).also {
                Files.createSymbolicLink(it, target)
            }
            fun rejects(config: Path, socketParent: Path, outputParent: Path, inputParent: Path = inputs) {
                val failure = assertFailsWith<LlvmBehaviorRuntimePreflightException> {
                    LlvmBehaviorRuntimePreflightPublisher.publish(
                        inputParent.resolve("corpus.json"),
                        inputs.resolve("report.json"),
                        inputs.resolve("matrix.json"),
                        inputs.resolve("manifest.json"),
                        inputs.resolve("client"),
                        config,
                        socketParent.resolve("docker.sock"),
                        outputParent.resolve("receipt.json"),
                    )
                }
                assertTrue(failure.message.orEmpty().contains("must not alias"), failure.message)
            }

            rejects(alias("config-output-alias", first), second, first)
            rejects(second, alias("socket-output-alias", first), first)
            rejects(first, alias("socket-config-alias", first), third)
            rejects(second, third, first, alias("input-output-alias", first))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `bundled preflight schema is catalogued`() {
        val identity = OracleSchemas.identity("llvm-behavior-runtime-preflight")
        assertEquals("llvm-behavior-runtime-preflight", identity.name)
        assertTrue(identity.sha256.matches(Regex("[0-9a-f]{64}")))
    }

    @Test
    fun `opt-in checked private endpoint publishes immutable non-execution receipt`() {
        val clientValue = System.getenv("DECOMP_LLVM_RUNTIME_PREFLIGHT_CLIENT")
        val configValue = System.getenv("DECOMP_LLVM_RUNTIME_PREFLIGHT_CONFIG")
        val socketValue = System.getenv("DECOMP_LLVM_RUNTIME_PREFLIGHT_SOCKET")
        assumeTrue(!clientValue.isNullOrBlank() && !configValue.isNullOrBlank() && !socketValue.isNullOrBlank())
        val root = Files.createTempDirectory("llvm-runtime-preflight-real-")
        val outputParent = root.resolve("receipt").createDirectories()
        Files.setPosixFilePermissions(outputParent, OWNER_ONLY_DIRECTORY)
        val output = outputParent.resolve("runtime-preflight.json")
        try {
            val receipt = LlvmBehaviorRuntimePreflightPublisher.publish(
                PROFILE.resolve("behavior-corpus.json"),
                PROFILE.resolve("behavior-corpus-evidence.json"),
                PROFILE.resolve("diagnostic-matrix.json"),
                PROFILE.resolve("oracle-manifest.json"),
                Path.of(clientValue!!),
                Path.of(configValue!!),
                Path.of(socketValue!!),
                output,
            )
            assertTrue(receipt.runtimeIdentityVerified)
            assertTrue(receipt.containmentCapabilitiesVerified)
            assertTrue(receipt.imageVerified)
            assertFalse(receipt.candidateStarted)
            assertFalse(receipt.liveContainmentVerified)
            assertFalse(receipt.scoringAuthority)
            assertFalse(receipt.releaseEligible)
            assertEquals(OWNER_ONLY_FILE, Files.getPosixFilePermissions(output))
            val document = OracleJson.parseCanonical(receipt.canonicalBytes, RECEIPT_LIMITS) as JsonObject
            OracleSchemas.validate("llvm-behavior-runtime-preflight", document)
            val rendered = receipt.canonicalBytes.toString(Charsets.UTF_8)
            assertFalse(rendered.contains("expected"))
            assertFalse(rendered.contains("base64"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun fixtureCorpus(): JsonObject = OracleJson.parse(
        """
        {
          "id": "fixture-runtime",
          "sandbox": {
            "backend": "oci-container-v1",
            "resourcePolicyVersion": 1,
            "isolation": "network-none-readonly-root-cap-drop-all-no-new-privileges-pid-ipc-private-cgroup-bounds",
            "controlClient": {"bytes": 1, "sha256": "$ZERO_SHA256", "version": "fixture-client 1\n"},
            "imageDigest": "$IMAGE_DIGEST",
            "platform": "linux/amd64",
            "imageEnvironment": ["PATH=/usr/bin:/bin"],
            "engineProfile": {
              "product": "Fixture Engine",
              "serverVersion": "1.0",
              "serverCommit": "server-commit",
              "apiVersion": "1.55",
              "operatingSystem": "linux",
              "architecture": "amd64",
              "kernelVersion": "kernel-live",
              "componentsSha256": "$COMPONENTS_SHA256",
              "cgroupVersion": 2,
              "cgroupDriver": "systemd",
              "storageDriver": "overlay2",
              "securityOptions": ["name=cgroupns", "name=rootless", "name=seccomp,profile=builtin"],
              "containerRuntime": "runc",
              "containerRuntimePath": "runc",
              "containerRuntimeVersion": "1.1",
              "containerRuntimeCommit": "runtime-commit",
              "containerRuntimeFeaturesSha256": "$FEATURES_SHA256",
              "volumePlugin": "local"
            }
          }
        }
        """.trimIndent().encodeToByteArray(),
    ) as JsonObject

    private fun fixtureResponses(
        stateDirectory: String = "/volatile/one",
        reverseComponents: Boolean = false,
        engineCommit: String = "server-commit",
        componentKernel: String = "kernel-live",
    ): List<NonAuthoritativeRuntimeResponse> {
        val components = mutableListOf(
            """{"Name":"Engine","Version":"1.0","Details":{"GitCommit":"$engineCommit","KernelVersion":"$componentKernel"}}""",
            """{"Name":"runc","Version":"1.1","Details":{"GitCommit":"runtime-commit"}}""",
            """{"Name":"rootlesskit","Version":"2","Details":{"StateDir":"$stateDirectory"}}""",
        )
        if (reverseComponents) components.reverse()
        val identity =
            """{"Platform":{"Name":"Fixture Engine"},"Version":"1.0","GitCommit":"server-commit","ApiVersion":"1.55","Os":"linux","Arch":"amd64","KernelVersion":"kernel-live","Components":[${components.joinToString(",")}]}"""
        val security =
            """["name=cgroupns","name=rootless","name=seccomp,profile=builtin"]
2
systemd
overlay2
["local"]
{"runc":{"path":"runc","status":{"org.opencontainers.runtime-spec.features":"runtime-features-v1"}}}"""
        val image =
            """[{"Id":"$IMAGE_DIGEST","Os":"linux","Architecture":"amd64","Config":{"Env":["PATH=/usr/bin:/bin"],"Volumes":null}}]"""
        return listOf(
            response("fixture-client 1\n"),
            response(identity),
            response(security),
            response(image),
        )
    }

    private fun response(value: String): NonAuthoritativeRuntimeResponse = response(value.encodeToByteArray())
    private fun response(value: ByteArray): NonAuthoritativeRuntimeResponse = NonAuthoritativeRuntimeResponse(stdout = value)

    private fun privateDirectory(path: Path): Path = path.createDirectories().also {
        Files.setPosixFilePermissions(it, OWNER_ONLY_DIRECTORY)
    }

    private fun JsonObject.withEngine(name: String, value: JsonElement): JsonObject {
        val sandbox = this["sandbox"] as JsonObject
        val engine = sandbox["engineProfile"] as JsonObject
        return JsonObject(toMutableMap().also { root ->
            root["sandbox"] = JsonObject(sandbox.toMutableMap().also { sandboxMap ->
                sandboxMap["engineProfile"] = JsonObject(engine.toMutableMap().also { it[name] = value })
            })
        })
    }

    private fun JsonObject.withSandbox(name: String, value: JsonElement): JsonObject {
        val sandbox = this["sandbox"] as JsonObject
        return JsonObject(toMutableMap().also { root ->
            root["sandbox"] = JsonObject(sandbox.toMutableMap().also { it[name] = value })
        })
    }

    private companion object {
        val PROFILE: Path = Path.of("oracle", "llvm", "22.1.6").toAbsolutePath().normalize()
        const val ZERO_SHA256 = "0000000000000000000000000000000000000000000000000000000000000000"
        const val IMAGE_DIGEST = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        const val COMPONENTS_SHA256 = "6c1f7834552e30d4dc1e59db64de199a5411c0664237d73851c932f0ec7a2c3e"
        const val FEATURES_SHA256 = "011d7a8609b41379ddf6ac0331fb97eda04f4fd42f2caee210172871899d9844"
        val OWNER_ONLY_DIRECTORY = setOf(
            PosixFilePermission.OWNER_READ,
            PosixFilePermission.OWNER_WRITE,
            PosixFilePermission.OWNER_EXECUTE,
        )
        val OWNER_ONLY_FILE = setOf(PosixFilePermission.OWNER_READ)
        val RECEIPT_LIMITS = StrictJsonLimits(
            maximumInputBytes = 1024 * 1024,
            maximumCanonicalBytes = 1024 * 1024,
            maximumDepth = 32,
            maximumNodes = 20_000,
            maximumStringBytes = 256 * 1024,
            maximumTotalStringBytes = 1024 * 1024,
        )
    }
}
