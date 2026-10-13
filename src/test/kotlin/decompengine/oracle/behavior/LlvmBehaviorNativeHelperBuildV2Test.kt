package decompengine.oracle.behavior

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LlvmBehaviorNativeHelperBuildV2Test {
    @Test fun `JVM callers cannot rewrite the compiler recipe`() {
        assertFailsWith<UnsupportedOperationException> { (NATIVE_HELPER_ARGUMENT_TEMPLATE as MutableList<String>)[0] = "foreign" }
        assertFailsWith<UnsupportedOperationException> { (NATIVE_HELPER_INSTALLED_NAMES as MutableList<String>)[0] = "foreign" }
    }
    @Test fun `actual compiler produces the closed v2 build record and deployment provenance`() = withNativeHelperTestDirectory { root ->
        val output = Files.createDirectory(root.resolve("output"))
        LlvmBehaviorNativeHelperBuildV2.build(nativeHelperTestCompiler(), nativeHelperTestSource(), output)
        val source = Files.readAllBytes(output.resolve(NATIVE_HELPER_SOURCE_NAME))
        val build = Files.readAllBytes(output.resolve(NATIVE_HELPER_BUILD_NAME))
        val reference = Files.readAllBytes(output.resolve(NATIVE_HELPER_REFERENCE_NAME))
        val parsed = parseNativeHelperReference(reference, source, build)
        val artifact = LlvmBehaviorNativeHelperArtifactVerifier.verify(output.resolve(NATIVE_HELPER_NAME), output.resolve(NATIVE_HELPER_CHECKSUM_NAME))
        assertEquals(artifact.helperSha256, parsed.files.getValue(NATIVE_HELPER_NAME).sha256)
        assertEquals(Files.readAllBytes(nativeHelperTestSource()).toList(), source.toList())
        val record = OracleJson.parseCanonical(build) as JsonObject
        assertEquals(helperStrings(NATIVE_HELPER_ARGUMENT_TEMPLATE), record["argumentTemplate"])
        assertFalse(artifact.digestPinnedByReference)
        assertFalse(artifact.startAuthorized)
        val schema = OracleJson.parse(Files.readAllBytes(Path.of("oracle/llvm-behavior-native-sandbox-policy-v2.schema.json").toAbsolutePath())) as JsonObject
        val properties = schema.getValue("properties") as JsonObject
        val staticFields = listOf("schemaVersion", "kind", "authority", "acpBoundary", "backend", "environment", "container",
            "roles", "mountProfiles", "cgroup", "rlimits", "workspace", "captures", "unboundRuntimeInputs", "claims")
        val policy = JsonObject(staticFields.associateWith { (properties.getValue(it) as JsonObject).getValue("const") } +
            ("helper" to JsonObject(mapOf("fileName" to JsonPrimitive(NATIVE_HELPER_NAME), "checksumFileName" to JsonPrimitive(NATIVE_HELPER_CHECKSUM_NAME),
                "bytes" to JsonPrimitive(artifact.helperBytes), "sha256" to JsonPrimitive(artifact.helperSha256),
                "checksumSha256" to JsonPrimitive(artifact.checksumSha256), "protocol" to JsonPrimitive(artifact.protocol),
                "containerPath" to JsonPrimitive("/decomp-llvm-behavior-helper"), "preExecFrame" to JsonPrimitive("behavior-preexec-v2:"),
                "source" to helperFileRecord(NATIVE_HELPER_SOURCE_NAME, source), "buildRecord" to helperFileRecord(NATIVE_HELPER_BUILD_NAME, build)))))
        val policyPath = output.resolve("llvm-behavior-native-sandbox-policy-v2.json")
        Files.write(policyPath, OracleJson.canonicalBytes(policy))
        val validated = LlvmBehaviorNativeSandboxPolicyV2Verifier.verify(policyPath, output.resolve(NATIVE_HELPER_NAME),
            output.resolve(NATIVE_HELPER_CHECKSUM_NAME), output.resolve(NATIVE_HELPER_SOURCE_NAME), output.resolve(NATIVE_HELPER_BUILD_NAME))
        assertTrue(validated.helperPolicyDraftValidated)
        assertFalse(validated.referencePinned)
        assertFalse(validated.startAuthorized)
        assertFalse(validated.scoringAuthority)
        assertFalse(validated.releaseEligible)
    }

    @Test fun `substituted source and failed compiler never publish deployment authority`() = withNativeHelperTestDirectory { root ->
        val source = root.resolve(NATIVE_HELPER_SOURCE_NAME)
        Files.writeString(source, "int main(void) { return 0; }\n")
        val output = Files.createDirectory(root.resolve("output"))
        assertFailsWith<IllegalArgumentException> { LlvmBehaviorNativeHelperBuildV2.build(nativeHelperTestCompiler(), source, output) }
        assertEquals(emptyList(), Files.list(output).use { it.toList() })
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorNativeHelperBuildV2.build(Path.of("/usr/bin/false").toRealPath(), nativeHelperTestSource(), output)
        }
        assertEquals(emptyList(), Files.list(output).use { it.toList() })
        val writableCompiler = Files.copy(nativeHelperTestCompiler(), root.resolve("compiler"))
        Files.setPosixFilePermissions(writableCompiler, PosixFilePermissions.fromString("rwxrwxr-x"))
        assertFailsWith<IllegalArgumentException> {
            LlvmBehaviorNativeHelperBuildV2.build(writableCompiler, nativeHelperTestSource(), output)
        }
        assertEquals(emptyList(), Files.list(output).use { it.toList() })
    }

    @Test fun `compiler child environment clears inherited include and tool redirection`() = withNativeHelperTestDirectory { root ->
        val poison = Files.createDirectory(root.resolve("poison"))
        Files.writeString(poison.resolve("stdio.h"), "#error inherited include path reached helper compilation\n")
        val output = Files.createDirectory(root.resolve("output"))
        val javaExecutable = Path.of(System.getProperty("java.home"), "bin/java")
        val command = listOf(javaExecutable.toString(), "-XX:-UsePerfData", "-Djava.io.tmpdir=${root}", "-Djna.tmpdir=${root}",
            "-Duser.home=$root", "-Djna.nosys=true", "-Djna.nounpack=true",
            "-Djna.boot.library.path=${nativeHelperTestNativeDirectory()}", "-cp", System.getProperty("java.class.path"),
            "decompengine.oracle.behavior.LlvmBehaviorNativeHelperBuildV2Cli", nativeHelperTestCompiler().toString(),
            nativeHelperTestSource().toString(), output.toString())
        val builder = ProcessBuilder(command).redirectErrorStream(true).redirectOutput(root.resolve("child.log").toFile())
        builder.environment()["CPATH"] = poison.toString()
        builder.environment()["GCC_EXEC_PREFIX"] = poison.toString() + "/"
        builder.environment()["LIBRARY_PATH"] = poison.toString()
        builder.environment()["TMPDIR"] = root.toString()
        builder.environment()["HOME"] = root.toString()
        builder.environment().remove("JAVA_TOOL_OPTIONS")
        builder.environment().remove("JDK_JAVA_OPTIONS")
        val child = builder.start()
        try {
            assertTrue(child.waitFor(90, java.util.concurrent.TimeUnit.SECONDS), "helper producer child exceeded its deadline")
            assertEquals(0, child.exitValue(), Files.readString(root.resolve("child.log")))
        } finally { if (child.isAlive) { child.destroyForcibly(); child.waitFor(5, java.util.concurrent.TimeUnit.SECONDS) } }
        val source = Files.readAllBytes(output.resolve(NATIVE_HELPER_SOURCE_NAME))
        val build = Files.readAllBytes(output.resolve(NATIVE_HELPER_BUILD_NAME))
        val reference = OracleJson.parseCanonical(Files.readAllBytes(output.resolve(NATIVE_HELPER_REFERENCE_NAME))) as JsonObject
        parseNativeHelperReference(OracleJson.canonicalBytes(reference), source, build)
        assertEquals(JsonPrimitive(false), reference["compilerToolchainClosureAuthenticated"])
        assertEquals(nativeHelperFalseClaims(), reference["claims"])
    }
}

internal fun nativeHelperTestCompiler(): Path = Path.of(System.getProperty("decompengine.oracle.behavior.nativeHelperCompiler", "/usr/bin/cc")).toRealPath()
internal fun nativeHelperTestSource(): Path = Path.of("src/main/c/$NATIVE_HELPER_SOURCE_NAME").toAbsolutePath().normalize()
internal fun nativeHelperTestNativeDirectory(): Path = Path.of(System.getProperty("decompengine.oracle.nativeLibraryDirectory",
    "build/native/oracle")).toAbsolutePath().normalize()
internal fun withNativeHelperTestDirectory(block: (Path) -> Unit) {
    val parent = Path.of("build/native-helper-test-work").toAbsolutePath().normalize()
    Files.createDirectories(parent)
    val root = Files.createTempDirectory(parent, "check-", PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
    try { block(root) } finally { root.toFile().deleteRecursively() }
}
