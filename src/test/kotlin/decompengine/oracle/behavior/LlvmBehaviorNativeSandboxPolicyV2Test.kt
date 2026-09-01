package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
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
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmBehaviorNativeSandboxPolicyV2Test {
    @Test
    fun `valid v2 raw files yield only a non-authoritative contract validation`() = withFixture { fixture ->
        val validation = fixture.verify()

        assertEquals(
            "non-authoritative-native-sandbox-helper-policy-v2-draft-validation",
            validation.authority,
        )
        assertEquals(2, validation.schemaVersion)
        assertTrue(validation.helperPolicyDraftValidated)
        assertEquals(Files.size(fixture.helper), validation.helperBytes)
        assertEquals(sha256(fixture.policy), validation.policySha256)
        assertEquals(sha256(fixture.helper), validation.helperSha256)
        assertEquals(sha256(fixture.checksum), validation.checksumSha256)
        assertEquals(sha256(fixture.source), validation.sourceSha256)
        assertEquals(sha256(fixture.buildRecord), validation.buildRecordSha256)
        assertEquals(EXPECTED_SCHEMA_SHA256, validation.schemaSha256)
        assertEquals("decomp-llvm-behavior-helper-v2", validation.protocol)
        assertEquals("/decomp-llvm-behavior-helper", validation.helperContainerPath)
        assertFalse(validation.referencePinned)
        assertFalse(validation.candidateStarted)
        assertFalse(validation.startAuthorized)
        assertFalse(validation.scoringAuthority)
        assertFalse(validation.releaseEligible)
        assertFalse("llvm-behavior-native-sandbox-policy-v2" in OracleSchemas.supportedNames)
    }

    @Test
    fun `bundled draft pins independently reviewed platform roles IO and nonauthority`() {
        val static = staticSchemaProperties()
        assertEquals(JsonPrimitive(2), static.getValue("schemaVersion"))
        assertEquals(
            JsonPrimitive("llvm-behavior-native-sandbox-helper-policy-draft"),
            static.getValue("kind"),
        )
        assertEquals(
            JsonPrimitive("non-authoritative-native-sandbox-helper-policy-v2-draft-validation"),
            static.getValue("authority"),
        )
        assertEquals(JsonPrimitive("oci-container-v2"), static.getValue("backend"))

        assertEquals(
            JsonObject(
                mapOf(
                    "role" to JsonPrimitive("first-class-candidate-producer-operator"),
                    "candidateContribution" to
                        JsonPrimitive("authenticated-session-change-build-artifact-provenance"),
                    "candidateProvenanceAccess" to JsonPrimitive("read-only-oracle-input"),
                    "candidateAdmissionOwner" to JsonPrimitive("kotlin-jvm-host"),
                    "candidateLiveExecutionOwner" to
                        JsonPrimitive("separately-reviewed-kotlin-jvm-host"),
                    "referenceSubjectAdmission" to JsonPrimitive("kotlin-jvm-host-only"),
                    "oracleAuthority" to JsonPrimitive(false),
                    "referenceAuthoringAuthority" to JsonPrimitive(false),
                    "policyAuthoringAuthority" to JsonPrimitive(false),
                    "validationAuthority" to JsonPrimitive(false),
                    "observationAuthoringAuthority" to JsonPrimitive(false),
                    "startAuthority" to JsonPrimitive(false),
                    "containmentAuthority" to JsonPrimitive(false),
                    "terminalAbsenceAuthority" to JsonPrimitive(false),
                    "scoringAuthority" to JsonPrimitive(false),
                    "certificationAuthority" to JsonPrimitive(false),
                    "releaseAuthority" to JsonPrimitive(false),
                ),
            ),
            static.getValue("acpBoundary"),
        )

        val environment = static.getValue("environment") as JsonObject
        assertEquals(JsonPrimitive("/usr/bin/env"), environment.getValue("launcher"))
        assertEquals(
            JsonArray(listOf("GCC_MIRRORS", "GCC_VERSION", "GPG_KEYS", "PATH").map(::JsonPrimitive)),
            environment.getValue("preExecAllowlist"),
        )
        val targetEnvironment = environment.getValue("targetCommandEnvironment") as JsonObject
        assertEquals(JsonPrimitive(128), targetEnvironment.getValue("maximumBindings"))
        assertEquals(JsonPrimitive(65_536), targetEnvironment.getValue("maximumBytes"))

        val container = static.getValue("container") as JsonObject
        assertEquals(JsonPrimitive("linux/amd64"), container.getValue("platform"))
        assertEquals(JsonPrimitive("private"), container.getValue("pidNamespace"))
        assertEquals(JsonPrimitive("none"), container.getValue("network"))
        assertEquals(JsonPrimitive(true), container.getValue("stdinAttached"))

        val roles = static.getValue("roles") as JsonObject
        val setup = roles.getValue("setup") as JsonObject
        val setupArgv = setup.getValue("commandArgvTemplate") as JsonArray
        assertEquals(JsonPrimitive("TARGET_UID=65534"), setupArgv[2])
        assertEquals(JsonPrimitive("TARGET_GID=65534"), setupArgv[3])
        val target = roles.getValue("target") as JsonObject
        assertEquals(
            JsonObject(mapOf("uid" to JsonPrimitive(65_534), "gid" to JsonPrimitive(65_534))),
            target.getValue("user"),
        )
        assertEquals(
            JsonArray(
                listOf(
                    "/usr/bin/env",
                    "-i",
                    "\${COMMAND_ENVIRONMENT}",
                    "/subject/executable",
                    "\${CASE_ARGUMENTS}",
                ).map(::JsonPrimitive),
            ),
            target.getValue("commandArgvTemplate"),
        )
        val collector = roles.getValue("collector") as JsonObject
        assertEquals(JsonArray(listOf(JsonPrimitive("DAC_OVERRIDE"))), collector.getValue("capabilities"))
        val collectorArgv = collector.getValue("commandArgvTemplate") as JsonArray
        assertEquals(JsonPrimitive("TARGET_UID=65534"), collectorArgv[2])
        assertEquals(JsonPrimitive("TARGET_GID=65534"), collectorArgv[3])

        val targetMounts = ((static.getValue("mountProfiles") as JsonObject).getValue("target") as JsonArray)
            .map { ((it as JsonObject).getValue("destination") as JsonPrimitive).content }
        assertEquals(
            listOf(
                "/decomp-llvm-behavior-helper",
                "/workspace",
                "/subject/executable",
                "/etc/hostname",
                "/etc/hosts",
                "/etc/resolv.conf",
                "/tmp",
            ),
            targetMounts,
        )

        val cgroup = static.getValue("cgroup") as JsonObject
        assertEquals(JsonPrimitive(2), cgroup.getValue("version"))
        assertEquals(JsonPrimitive(1), cgroup.getValue("members"))
        assertEquals(JsonPrimitive(false), cgroup.getValue("controlsWritable"))
        val rlimits = static.getValue("rlimits") as JsonObject
        assertEquals(JsonPrimitive(10), (rlimits.getValue("target") as JsonObject).getValue("cpuSeconds"))

        val workspace = static.getValue("workspace") as JsonObject
        assertEquals(JsonPrimitive(true), workspace.getValue("byteLexicographicallySortedTraversal"))
        assertEquals(JsonPrimitive(true), workspace.getValue("collectionPreservesRegularFileMode"))
        assertFalse("codePointSortedTraversal" in workspace)
        assertFalse("collectionPreservesOrdinaryMode" in workspace)

        assertEquals(
            JsonObject(
                mapOf(
                    "imageDigest" to JsonPrimitive("required-from-fresh-v2-reference-definition"),
                    "controlClient" to JsonPrimitive("required-from-authenticated-v2-runtime-preflight"),
                    "engineDeclaration" to JsonPrimitive("required-from-authenticated-v2-runtime-preflight"),
                    "preExecEnvironmentValues" to
                        JsonPrimitive("required-from-authenticated-v2-image-declaration"),
                    "referenceSubjectExecutable" to
                        JsonPrimitive("required-from-fresh-v2-reference-definition"),
                    "candidateSubjectExecutable" to
                        JsonPrimitive("candidate-only-required-from-kotlin-candidate-admission"),
                    "candidateAcpSessionProvenance" to
                        JsonPrimitive("candidate-only-required-from-authenticated-acp-session-receipt"),
                    "candidateAcpChangeProvenance" to
                        JsonPrimitive("candidate-only-required-from-authenticated-acp-change-receipt"),
                    "candidateAcpBuildProvenance" to
                        JsonPrimitive("candidate-only-required-from-hosted-clean-build-receipt"),
                    "candidateAcpArtifactProvenance" to
                        JsonPrimitive("candidate-only-required-from-kotlin-candidate-admission"),
                    "commandEnvironment" to JsonPrimitive("required-from-authenticated-corpus-and-case"),
                    "caseArguments" to JsonPrimitive("required-from-authenticated-corpus-case"),
                    "caseStdinBytes" to JsonPrimitive("required-from-authenticated-corpus-case"),
                    "caseInputTreeBytes" to JsonPrimitive("required-from-authenticated-corpus-case"),
                    "deterministicHostFileBytes" to JsonPrimitive("required-from-kotlin-v2-definition"),
                    "preExecNonce" to JsonPrimitive("required-from-live-v2-operation-owner"),
                    "workspaceVolumeIdentity" to JsonPrimitive("required-from-authenticated-v2-live-owner"),
                    "caseResultsLeaseIdentity" to
                        JsonPrimitive("required-from-controller-owned-v2-results-lease"),
                    "mountSourceIdentities" to JsonPrimitive("required-from-authenticated-v2-live-owner"),
                ),
            ),
            static.getValue("unboundRuntimeInputs"),
        )

        assertEquals(
            JsonObject(
                mapOf(
                    "referencePinned" to JsonPrimitive(false),
                    "candidateStarted" to JsonPrimitive(false),
                    "startAuthorized" to JsonPrimitive(false),
                    "scoringAuthority" to JsonPrimitive(false),
                    "releaseEligible" to JsonPrimitive(false),
                ),
            ),
            static.getValue("claims"),
        )
    }

    @Test
    fun `every role argv environment user mount and resource field is closed`() = withFixture { fixture ->
        val mutations = listOf<Pair<List<String>, JsonElement>>(
            listOf("schemaVersion") to JsonPrimitive(1),
            listOf("acpBoundary", "role") to JsonPrimitive("optional-candidate-producer"),
            listOf("acpBoundary", "policyAuthoringAuthority") to JsonPrimitive(true),
            listOf("acpBoundary", "containmentAuthority") to JsonPrimitive(true),
            listOf("backend") to JsonPrimitive("oci-container-v1"),
            listOf("helper", "protocol") to JsonPrimitive("decomp-llvm-behavior-helper-v1"),
            listOf("helper", "containerPath") to JsonPrimitive("/usr/local/bin/helper"),
            listOf("environment", "launcher") to JsonPrimitive("/bin/env"),
            listOf("environment", "preExecAllowlist") to JsonArray(listOf(JsonPrimitive("PATH"))),
            listOf("environment", "preExecValuesBinding") to JsonPrimitive("unbound"),
            listOf("container", "platform") to JsonPrimitive("linux/arm64"),
            listOf("container", "pidNamespace") to JsonPrimitive("host"),
            listOf("roles", "keeper", "user", "uid") to JsonPrimitive(65534),
            listOf("roles", "setup", "commandArgvTemplate") to JsonArray(emptyList()),
            listOf("roles", "target", "preExecArgvTemplate") to JsonArray(emptyList()),
            listOf("roles", "collector", "capabilities") to JsonArray(emptyList()),
            listOf("roles", "target", "shmBytes") to JsonPrimitive(65_536),
            listOf("mountProfiles", "target") to JsonArray(emptyList()),
            listOf("cgroup", "cpuQuotaMicroseconds") to JsonPrimitive(99_999),
            listOf("rlimits", "target", "cpuSeconds") to JsonPrimitive(11),
            listOf("workspace", "maximumBytes") to JsonPrimitive(33_554_431),
            listOf("workspace", "byteLexicographicallySortedTraversal") to JsonPrimitive(false),
            listOf("captures", "stdoutBytes") to JsonPrimitive(1_048_575),
            listOf("unboundRuntimeInputs", "imageDigest") to JsonPrimitive("locally-claimed"),
            listOf("unboundRuntimeInputs", "caseStdinBytes") to JsonPrimitive("locally-claimed"),
            listOf("claims", "startAuthorized") to JsonPrimitive(true),
        )
        mutations.forEach { (path, replacement) ->
            fixture.writePolicy(replaceAt(fixture.validPolicy(), path, replacement))
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception>("mutation at ${path.joinToString(".")}") {
                fixture.verify()
            }
        }
        val targetMounts = ((fixture.validPolicy()["mountProfiles"] as JsonObject)["target"] as JsonArray)
            .map { entry ->
                val mount = entry as JsonObject
                if ((mount["destination"] as? JsonPrimitive)?.content == "/tmp") {
                    JsonObject(mount + ("sizeBytes" to JsonPrimitive(16_777_215)))
                } else {
                    mount
                }
            }
        fixture.writePolicy(
            replaceAt(
                fixture.validPolicy(),
                listOf("mountProfiles", "target"),
                JsonArray(targetMounts),
            ),
        )
        assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }

        fixture.writePolicy(
            replaceAt(
                fixture.validPolicy(),
                listOf("roles", "setup", "user", "uid"),
                JsonPrimitive(65_534.0),
            ),
        )
        assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
    }

    @Test
    fun `stale policy rejects helper checksum source and build-record substitution`() {
        withFixture { fixture ->
            val bytes = Files.readAllBytes(fixture.helper)
            bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
            Files.write(fixture.helper, bytes)
            fixture.writeChecksum()
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.writeString(fixture.source, "\n/* native source substitution */\n", Charsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND)
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            fixture.writeBuildRecord(compilerVersion = "cc fixture 2.0")
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.writeString(fixture.checksum, "${"0".repeat(64)}  $HELPER_NAME\n")
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
    }

    @Test
    fun `Python reintroduction is rejected from decoded build data and raw source`() {
        withFixture { fixture ->
            fixture.writeBuildRecord(compilerExecutable = "/usr/bin/PyThOn3")
            fixture.writePolicy(fixture.validPolicy())
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.writeString(
                fixture.source,
                "\n/* forbidden Python runtime */\n",
                Charsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND,
            )
            fixture.writeBuildRecord()
            fixture.writePolicy(fixture.validPolicy())
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
    }

    @Test
    fun `known v1 sentinels are rejected from each of the five raw artifacts`() {
        withFixture { fixture ->
            Files.write(
                fixture.helper,
                Files.readAllBytes(fixture.helper) + "\nbehavior-preexec-v1\n".encodeToByteArray(),
            )
            fixture.writeChecksum()
            fixture.writeBuildRecord()
            fixture.writePolicy(fixture.validPolicy())
            assertForbiddenMarker(fixture, "behavior-preexec-v1")
        }
        withFixture { fixture ->
            Files.writeString(
                fixture.checksum,
                "oci-container-v1\n",
                Charsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND,
            )
            fixture.writePolicy(fixture.validPolicy())
            assertForbiddenMarker(fixture, "oci-container-v1")
        }
        withFixture { fixture ->
            Files.writeString(
                fixture.source,
                "\n/* decomp-llvm-behavior-helper-v1 */\n",
                Charsets.UTF_8,
                java.nio.file.StandardOpenOption.APPEND,
            )
            fixture.writeBuildRecord()
            fixture.writePolicy(fixture.validPolicy())
            assertForbiddenMarker(fixture, "decomp-llvm-behavior-helper-v1")
        }
        withFixture { fixture ->
            fixture.writeBuildRecord(compilerVersion = "cc fixture behavior-preexec-v1")
            fixture.writePolicy(fixture.validPolicy())
            assertForbiddenMarker(fixture, "behavior-preexec-v1")
        }
        withFixture { fixture ->
            val v1 = replaceAt(
                replaceAt(fixture.validPolicy(), listOf("schemaVersion"), JsonPrimitive(1)),
                listOf("backend"),
                JsonPrimitive("oci-container-v1"),
            )
            fixture.writePolicy(v1)
            assertForbiddenMarker(fixture, "oci-container-v1")
        }
    }

    @Test
    fun `fixed amd64 policy rejects an AArch64 ELF even when host matching accepts it`() {
        synchronized(ARCHITECTURE_PROPERTY_LOCK) {
            val original = System.getProperty("os.arch")
            try {
                System.setProperty("os.arch", "aarch64")
                withFixture { fixture ->
                    val bytes = Files.readAllBytes(fixture.helper)
                    bytes[18] = 0xb7.toByte()
                    bytes[19] = 0
                    Files.write(fixture.helper, bytes)
                    fixture.writeChecksum()
                    fixture.writeBuildRecord()
                    fixture.writePolicy(fixture.validPolicy())

                    val failure = assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> {
                        fixture.verify()
                    }
                    assertTrue(failure.message.orEmpty().contains("fixed linux/amd64 platform"))
                }
            } finally {
                if (original == null) System.clearProperty("os.arch") else System.setProperty("os.arch", original)
            }
        }
    }

    @Test
    fun `canonical bounds symlinks aliases and non-exact paths fail closed`() {
        withFixture { fixture ->
            Files.write(fixture.policy, Files.readAllBytes(fixture.policy) + '\n'.code.toByte())
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.write(fixture.policy, ByteArray(256 * 1024 + 1) { 'x'.code.toByte() })
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            Files.write(fixture.buildRecord, Files.readAllBytes(fixture.buildRecord) + '\n'.code.toByte())
            fixture.writePolicy(fixture.validPolicy())
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> {
                LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(
                    Path.of(POLICY_NAME),
                    fixture.helper,
                    fixture.checksum,
                    fixture.source,
                    fixture.buildRecord,
                )
            }
        }
        withFixture { fixture ->
            Files.delete(fixture.buildRecord)
            Files.createLink(fixture.buildRecord, fixture.source)
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
        withFixture { fixture ->
            val target = fixture.root.resolve("policy-target")
            Files.move(fixture.policy, target)
            Files.createSymbolicLink(fixture.policy, target.fileName)
            assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        }
    }

    @Test
    fun `public and reflective production surfaces accept only five raw Paths`() {
        val validationType = LlvmBehaviorNativeSandboxPolicyV2Validation::class.java
        assertTrue(validationType.isSealed)
        val verify = LlvmBehaviorNativeSandboxPolicyV2Verifier::class.java.declaredMethods.single {
            it.name == "verify" && !it.isSynthetic
        }
        assertTrue(verify.parameterTypes.contentEquals(Array(5) { Path::class.java }))
        assertTrue(
            verify.parameterTypes.none { type ->
                type.name.contains("Json") || type.name.contains("Function") || type.name.contains("Runner")
            },
        )
        val implementations = LlvmBehaviorNativeSandboxPolicyV2Verifier::class.java.declaredClasses
            .filter { validationType.isAssignableFrom(it) }
        assertEquals(1, implementations.size)
        assertTrue(Modifier.isPrivate(implementations.single().modifiers))
        assertTrue(validationType.permittedSubclasses.contentEquals(arrayOf(implementations.single())))
        assertFailsWith<IllegalArgumentException> {
            Proxy.newProxyInstance(validationType.classLoader, arrayOf(validationType)) { _, _, _ -> null }
        }
        val constructor = implementations.single().declaredConstructors.single()
        assertTrue(constructor.parameterTypes.contentEquals(Array(5) { Path::class.java }))
        constructor.isAccessible = true
        val failure = assertFailsWith<Exception> {
            constructor.newInstance(
                Path.of("/absent/$POLICY_NAME"),
                Path.of("/absent/$HELPER_NAME"),
                Path.of("/absent/$CHECKSUM_NAME"),
                Path.of("/absent/$SOURCE_NAME"),
                Path.of("/absent/$BUILD_RECORD_NAME"),
            )
        }
        assertTrue(failure.cause is LlvmBehaviorNativeSandboxPolicyV2Exception)
    }

    private fun withFixture(block: (Fixture) -> Unit) {
        assumeTrue(
            HOST_ARCHITECTURE in setOf("amd64", "x86_64"),
            "the fixed linux/amd64 policy requires a native x86-64 helper fixture",
        )
        val root = createTempDirectory("native-sandbox-policy-v2-").toAbsolutePath().normalize()
        try {
            block(Fixture(root))
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    private fun assertForbiddenMarker(fixture: Fixture, marker: String) {
        val failure = assertFailsWith<LlvmBehaviorNativeSandboxPolicyV2Exception> { fixture.verify() }
        assertTrue(failure.message.orEmpty().contains("forbidden runtime marker $marker"))
    }

    private class Fixture(val root: Path) {
        val policy: Path = root.resolve(POLICY_NAME)
        val helper: Path = root.resolve(HELPER_NAME)
        val checksum: Path = root.resolve(CHECKSUM_NAME)
        val source: Path = root.resolve(SOURCE_NAME)
        val buildRecord: Path = root.resolve(BUILD_RECORD_NAME)

        init {
            Files.copy(productionHelper(), helper, StandardCopyOption.COPY_ATTRIBUTES)
            Files.copy(productionChecksum(), checksum, StandardCopyOption.COPY_ATTRIBUTES)
            Files.copy(repositorySource(), source, StandardCopyOption.COPY_ATTRIBUTES)
            Files.setPosixFilePermissions(helper, PosixFilePermissions.fromString("rwx------"))
            Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-------"))
            Files.setPosixFilePermissions(source, PosixFilePermissions.fromString("rw-------"))
            writeBuildRecord()
            writePolicy(validPolicy())
        }

        fun verify(): LlvmBehaviorNativeSandboxPolicyV2Validation =
            LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(policy, helper, checksum, source, buildRecord)

        fun writeChecksum() {
            Files.writeString(checksum, "${sha256(helper)}  $HELPER_NAME\n")
            Files.setPosixFilePermissions(checksum, PosixFilePermissions.fromString("rw-------"))
        }

        fun writeBuildRecord(
            compilerExecutable: String = "/usr/bin/cc",
            compilerVersion: String = "cc fixture 1.0",
        ) {
            val record = JsonObject(
                mapOf(
                    "schemaVersion" to JsonPrimitive(2),
                    "kind" to JsonPrimitive("llvm-behavior-native-helper-build-record"),
                    "compiler" to JsonObject(
                        mapOf(
                            "executable" to JsonPrimitive(compilerExecutable),
                            "version" to JsonPrimitive(compilerVersion),
                        ),
                    ),
                    "argumentTemplate" to JsonArray(
                        listOf(
                            "-std=c11",
                            "-O2",
                            "-static",
                            "-Wall",
                            "-Wextra",
                            "-Werror",
                            "-Wformat=2",
                            "-Wl,--build-id=none",
                            "\${SOURCE}",
                            "-o",
                            "\${OUTPUT}",
                        ).map(::JsonPrimitive),
                    ),
                    "source" to fileRecord(SOURCE_NAME, source),
                    "output" to fileRecord(HELPER_NAME, helper),
                ),
            )
            Files.write(buildRecord, OracleJson.canonicalBytes(record, JSON_LIMITS))
            Files.setPosixFilePermissions(buildRecord, PosixFilePermissions.fromString("rw-------"))
        }

        fun validPolicy(): JsonObject {
            val static = staticSchemaProperties()
            return JsonObject(
                mapOf(
                    "schemaVersion" to JsonPrimitive(2),
                    "kind" to JsonPrimitive("llvm-behavior-native-sandbox-helper-policy-draft"),
                    "authority" to JsonPrimitive(
                        "non-authoritative-native-sandbox-helper-policy-v2-draft-validation",
                    ),
                    "acpBoundary" to static.getValue("acpBoundary"),
                    "backend" to JsonPrimitive("oci-container-v2"),
                    "helper" to JsonObject(
                        mapOf(
                            "fileName" to JsonPrimitive(HELPER_NAME),
                            "checksumFileName" to JsonPrimitive(CHECKSUM_NAME),
                            "bytes" to JsonPrimitive(Files.size(helper)),
                            "sha256" to JsonPrimitive(sha256(helper)),
                            "checksumSha256" to JsonPrimitive(sha256(checksum)),
                            "protocol" to JsonPrimitive("decomp-llvm-behavior-helper-v2"),
                            "containerPath" to JsonPrimitive("/decomp-llvm-behavior-helper"),
                            "preExecFrame" to JsonPrimitive("behavior-preexec-v2:"),
                            "source" to fileRecord(SOURCE_NAME, source),
                            "buildRecord" to fileRecord(BUILD_RECORD_NAME, buildRecord),
                        ),
                    ),
                    "environment" to static.getValue("environment"),
                    "container" to static.getValue("container"),
                    "roles" to static.getValue("roles"),
                    "mountProfiles" to static.getValue("mountProfiles"),
                    "cgroup" to static.getValue("cgroup"),
                    "rlimits" to static.getValue("rlimits"),
                    "workspace" to static.getValue("workspace"),
                    "captures" to static.getValue("captures"),
                    "unboundRuntimeInputs" to static.getValue("unboundRuntimeInputs"),
                    "claims" to static.getValue("claims"),
                ),
            )
        }

        fun writePolicy(document: JsonObject) {
            Files.write(policy, OracleJson.canonicalBytes(document, JSON_LIMITS))
            Files.setPosixFilePermissions(policy, PosixFilePermissions.fromString("rw-------"))
        }
    }

    private companion object {
        const val POLICY_NAME = "llvm-behavior-native-sandbox-policy-v2.json"
        const val HELPER_NAME = "decomp-llvm-behavior-helper"
        const val CHECKSUM_NAME = "decomp-llvm-behavior-helper.sha256"
        const val SOURCE_NAME = "decomp_llvm_behavior_helper.c"
        const val BUILD_RECORD_NAME = "decomp-llvm-behavior-helper-build-v2.json"
        const val EXPECTED_SCHEMA_SHA256 =
            "bdce127600546944a3545682c22983383a348aa5a453fa823292fd176bb6f079"
        val HOST_ARCHITECTURE: String = System.getProperty("os.arch", "")
        val ARCHITECTURE_PROPERTY_LOCK = Any()
        val JSON_LIMITS = StrictJsonLimits(
            maximumInputBytes = 256 * 1024,
            maximumCanonicalBytes = 256 * 1024,
            maximumDepth = 96,
            maximumNodes = 50_000,
            maximumStringBytes = 64 * 1024,
            maximumTotalStringBytes = 192 * 1024,
        )

        val STATIC_SCHEMA_PROPERTIES: Map<String, JsonElement> by lazy {
            val bytes = requireNotNull(
                LlvmBehaviorNativeSandboxPolicyV2Test::class.java.classLoader.getResourceAsStream(
                    "oracle/llvm-behavior-native-sandbox-policy-v2.schema.json",
                ),
            ).use { it.readNBytes(256 * 1024 + 1) }
            val schema = OracleJson.parse(bytes, JSON_LIMITS) as JsonObject
            val properties = schema["properties"] as JsonObject
            listOf(
                "schemaVersion", "kind", "authority", "acpBoundary", "backend", "environment", "container", "roles",
                "mountProfiles", "cgroup", "rlimits", "workspace", "captures", "claims",
                "unboundRuntimeInputs",
            ).associateWith { name ->
                (properties.getValue(name) as JsonObject).getValue("const")
            }
        }

        fun staticSchemaProperties(): Map<String, JsonElement> = STATIC_SCHEMA_PROPERTIES

        fun fileRecord(fileName: String, path: Path): JsonObject = JsonObject(
            mapOf(
                "fileName" to JsonPrimitive(fileName),
                "bytes" to JsonPrimitive(Files.size(path)),
                "sha256" to JsonPrimitive(sha256(path)),
            ),
        )

        fun replaceAt(document: JsonObject, path: List<String>, replacement: JsonElement): JsonObject {
            require(path.isNotEmpty())
            val key = path.first()
            return if (path.size == 1) {
                JsonObject(document + (key to replacement))
            } else {
                val child = document.getValue(key) as JsonObject
                JsonObject(document + (key to replaceAt(child, path.drop(1), replacement)))
            }
        }

        fun sha256(path: Path): String = OracleArtifacts.sha256(Files.readAllBytes(path))

        fun productionHelper(): Path = requiredArtifact(
            "decompengine.oracle.behavior.nativeHelperExecutable",
            "production LLVM behavior helper",
        )

        fun productionChecksum(): Path = requiredArtifact(
            "decompengine.oracle.behavior.nativeHelperChecksum",
            "production LLVM behavior helper checksum",
        )

        fun repositorySource(): Path {
            val path = Path.of("src/main/c/decomp_llvm_behavior_helper.c").toAbsolutePath().normalize()
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "native helper source is unavailable" }
            return path
        }

        fun requiredArtifact(property: String, label: String): Path {
            val configured = requireNotNull(System.getProperty(property)) { "$label was not supplied by Gradle" }
            val path = Path.of(configured).toAbsolutePath().normalize()
            require(path == Path.of(configured)) { "$label path must be absolute and normalized" }
            require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "$label is unavailable: $path" }
            return path
        }
    }
}
