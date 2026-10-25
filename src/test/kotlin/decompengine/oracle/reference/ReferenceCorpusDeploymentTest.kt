package decompengine.oracle.reference

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class ReferenceCorpusDeploymentTest {
    @Test
    fun `explicit pins and ordered classpath parse without discovering host files`() {
        val deployment = ReferenceCorpusDeployment.parseCanonical(bytes(document()))
        assertEquals("/user.slice/user-1000.slice/user@1000.service/app.slice", deployment.expectedCgroupParent)
        assertEquals(Path.of("/reference-test-pins/jvm/bin/java"), deployment.configuration.javaExecutable)
        assertEquals(listOf("b.jar", "a.jar"), deployment.configuration.workerClassPath.map { it.path.fileName.toString() })
        assertEquals("b".repeat(64), deployment.configuration.expectedJavaSha256)
        assertFalse(Files.exists(deployment.configuration.javaExecutable))
    }

    @Test
    fun `unknown omitted or mistyped fields never select a fallback`() {
        val original = document()
        assertFails { parse(original + ("allowUntrusted" to JsonPrimitive(true))) }
        assertFails { parse(original - "expectedCgroupParent") }
        assertFails { parse(original + ("schemaVersion" to JsonPrimitive(1))) }
        assertFails { parse(original + ("schemaVersion" to JsonPrimitive("other"))) }
        mutateConfig { it - "expectedJavaSha256" }.let { assertFails { parse(it) } }
        mutateConfig { it + ("javaArguments" to JsonArray(emptyList())) }.let { assertFails { parse(it) } }
        mutateConfig { it + ("javaExecutable" to JsonPrimitive(123)) }.let { assertFails { parse(it) } }
    }

    @Test
    fun `paths digests cgroup ancestry and duplicate classpath fail closed`() {
        for (path in listOf("java", "/", "/a/../java", "/a//java", "/a/java/", "/a/\njava")) {
            assertFails(path) { parse(mutateConfig { it + ("javaExecutable" to JsonPrimitive(path)) }) }
        }
        for (digest in listOf("", "auto", "B".repeat(64), "b".repeat(63))) {
            assertFails(digest) { parse(mutateConfig { it + ("expectedJavaSha256" to JsonPrimitive(digest)) }) }
        }
        for (parent in listOf("/", "app.slice", "/a/../b", "/a/", "/a b", "/a//b")) {
            assertFails(parent) { parse(document() + ("expectedCgroupParent" to JsonPrimitive(parent))) }
        }
        val duplicate = classPath("a.jar")
        assertFails { parse(mutateConfig { it + ("workerClassPath" to JsonArray(listOf(duplicate, duplicate))) }) }
        assertFails { parse(mutateConfig { it + ("workerClassPath" to JsonArray(emptyList())) }) }
        assertFails { parse(mutateConfig { it + ("systemLibraryMounts" to JsonArray(emptyList())) }) }
    }

    @Test
    fun `runtime mount fields and destination overlap are checked`() {
        val extraField = JsonObject(runtime("/reference-test-pins/jvm", "/jvm") +
            ("sha256" to JsonPrimitive("b".repeat(64))))
        assertFails { parse(mutateConfig { it + ("javaRuntime" to extraField) }) }
        val overlapping = JsonArray(listOf(JsonObject(runtime("/reference-test-pins/lib", "/jvm/lib"))))
        assertFails { parse(mutateConfig { it + ("systemLibraryMounts" to overlapping) }) }
        val sessionRuntime = JsonArray(listOf(JsonObject(runtime("/run/user/1000", "/lib"))))
        assertFails { parse(mutateConfig { it + ("systemLibraryMounts" to sessionRuntime) }) }
    }

    @Test
    fun `noncanonical duplicate and excessive json never reaches configuration`() {
        val canonical = bytes(document())
        assertFails { ReferenceCorpusDeployment.parseCanonical(canonical + byteArrayOf(10)) }
        assertFails { ReferenceCorpusDeployment.parseCanonical("{\"schemaVersion\":1,\"schemaVersion\":1}".encodeToByteArray()) }
        assertFails { ReferenceCorpusDeployment.parseCanonical(ByteArray(256 * 1024 + 1) { 32 }) }
        assertFails { parse(mutateConfig { it + ("workerClassPath" to JsonArray(List(513) { classPath("$it.jar") })) }) }
    }

    @Test
    fun `production open rejects writable and symlink deployment files`() {
        val parent = Path.of("build", "reference-deployment-tests").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        val root = Files.createTempDirectory(parent, "config-")
        try {
            val config = Files.write(root.resolve("deployment.json"), bytes(document()))
            Files.setPosixFilePermissions(config, PosixFilePermissions.fromString("rw-rw----"))
            assertFails { ReferenceCorpusDeployment.open(config) }
            val alias = Files.createSymbolicLink(root.resolve("alias.json"), config.fileName)
            assertFails { ReferenceCorpusDeployment.open(alias) }
            assertFails { ReferenceCorpusDeployment.open(Path.of("deployment.json")) }
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun parse(value: Map<String, JsonElement>) = ReferenceCorpusDeployment.parseCanonical(bytes(value))
    private fun bytes(value: Map<String, JsonElement>) = OracleJson.canonicalBytes(JsonObject(value))
    private fun mutateConfig(change: (Map<String, JsonElement>) -> Map<String, JsonElement>): Map<String, JsonElement> =
        document().let { it + ("configuration" to JsonObject(change(it.getValue("configuration") as JsonObject))) }
    private fun runtime(source: String, destination: String) = mapOf(
        "source" to JsonPrimitive(source), "destination" to JsonPrimitive(destination),
        "expectedManifestSha256" to JsonPrimitive("a".repeat(64)),
    )
    private fun classPath(name: String) = JsonObject(mapOf("path" to JsonPrimitive("/reference-test-pins/$name"),
        "expectedSha256" to JsonPrimitive("c".repeat(64))))
    private fun document(): Map<String, JsonElement> = mapOf(
        "schemaVersion" to JsonPrimitive("reference-corpus-deployment-v1"),
        "expectedCgroupParent" to JsonPrimitive("/user.slice/user-1000.slice/user@1000.service/app.slice"),
        "configuration" to JsonObject(mapOf(
            "javaExecutable" to JsonPrimitive("/reference-test-pins/jvm/bin/java"),
            "javaRuntime" to JsonObject(runtime("/reference-test-pins/jvm", "/jvm")),
            "systemLibraryMounts" to JsonArray(listOf(JsonObject(runtime("/reference-test-pins/lib", "/lib")))),
            "bubblewrapExecutable" to JsonPrimitive("/reference-test-pins/bwrap"),
            "resourceLimiterExecutable" to JsonPrimitive("/reference-test-pins/prlimit"),
            "scopeSupervisorExecutable" to JsonPrimitive("/reference-test-pins/systemd-run"),
            "scopeInspectorExecutable" to JsonPrimitive("/reference-test-pins/systemctl"),
            "systemdBusControllerExecutable" to JsonPrimitive("/reference-test-pins/busctl"),
            "systemdUserRuntimeDirectory" to JsonPrimitive("/run/user/1000"),
            "workerClassPath" to JsonArray(listOf(classPath("b.jar"), classPath("a.jar"))),
            "expectedJavaSha256" to JsonPrimitive("b".repeat(64)),
            "expectedBubblewrapSha256" to JsonPrimitive("d".repeat(64)),
            "expectedResourceLimiterSha256" to JsonPrimitive("e".repeat(64)),
            "expectedScopeSupervisorSha256" to JsonPrimitive("f".repeat(64)),
            "expectedScopeInspectorSha256" to JsonPrimitive("0".repeat(64)),
            "expectedSystemdBusControllerSha256" to JsonPrimitive("1".repeat(64)),
        )),
    )
}
