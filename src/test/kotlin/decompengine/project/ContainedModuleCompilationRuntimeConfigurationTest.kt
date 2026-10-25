package decompengine.project

import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class ContainedModuleCompilationRuntimeConfigurationTest {
    @Test
    fun `closed declaration preserves exact compiler identity and allows curated loader alias`() {
        val make = parse(valid())
        assertEquals(GeneratedCMakeReconstructionProfile.PROFILE_ID, make.profileId)
        assertEquals(Path.of("/opt/module-compiler/bin/cc"), make.compilerExecutable)
        assertEquals(DIGEST, make.compilerSha256)
        assertEquals(Path.of("/lib64"), make.isolation.systemLibraryMounts.single().destination)
        assertEquals("/user.slice/user-1000.slice/user@1000.service", make.managerControlGroup)
        assertEquals(8L * 1024 * 1024 * 1024, make.scratchPolicy.maximumFilesystemBytes)
        val ninja = parse(valid() + ("profileId" to JsonPrimitive(GeneratedCNinjaReconstructionProfile.PROFILE_ID)))
        assertNotEquals(make.configurationSha256, ninja.configurationSha256)
        assertEquals(make.configurationSha256, parse(JsonObject(valid().entries.reversed().associate { it.toPair() })).configurationSha256)
        val changedCompiler = update(valid(), "compiler") { it + ("sha256" to JsonPrimitive("b".repeat(64))) }
        assertNotEquals(make.configurationSha256, parse(changedCompiler).configurationSha256)
    }

    @Test
    fun `unknown missing and duplicate fields cannot introduce launch authority`() {
        val document = valid()
        listOf("command", "environment", "skipContainment", "providerClass").forEach { field ->
            reject(document + (field to JsonPrimitive("untrusted")))
        }
        document.keys.forEach { field -> reject(document - field) }
        listOf("isolation", "compiler", "scratchPolicy").forEach { field ->
            val nested = document.getValue(field) as JsonObject
            nested.keys.forEach { removed -> reject(update(document, field) { it - removed }) }
            reject(update(document, field) { it + ("unexpected" to JsonPrimitive(true)) })
        }
        reject(update(document, "isolation") {
            it + ("javaRuntime" to JsonObject((it.getValue("javaRuntime") as JsonObject) + ("writable" to JsonPrimitive(true))))
        })
        reject(document + ("compilerRuntimeMounts" to JsonArray(listOf(JsonObject(
            runtime("/opt/module-compiler") + ("writable" to JsonPrimitive(true)),
        )))))
        reject(update(document, "isolation") {
            it + ("workerClassPath" to JsonArray(listOf(JsonObject(
                classPath("/opt/worker/worker.jar") + ("optional" to JsonPrimitive(true)),
            ))))
        })
        val duplicate = document.toString().replace("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1")
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationRuntimeConfiguration.parse(duplicate.toByteArray()) }
    }

    @Test
    fun `profile schema integer and digest tokens are strict`() {
        reject(valid() + ("profileId" to JsonPrimitive("other-profile")))
        listOf(JsonPrimitive("1"), JsonPrimitive(1.0), JsonPrimitive(2), JsonNull, JsonPrimitive(true)).forEach {
            reject(valid() + ("schemaVersion" to it))
        }
        listOf("A".repeat(64), "a".repeat(63), "a".repeat(65), "g".repeat(64)).forEach { digest ->
            reject(update(valid(), "compiler") { it + ("sha256" to JsonPrimitive(digest)) })
            reject(update(valid(), "isolation") { it + ("expectedJavaSha256" to JsonPrimitive(digest)) })
        }
        reject(update(valid(), "compiler") { it + ("sha256" to JsonPrimitive(123)) })
        listOf(JsonPrimitive("100"), JsonPrimitive(100.5), JsonPrimitive(-1), JsonPrimitive(0), JsonNull,
            JsonPrimitive("9223372036854775808")).forEach { value ->
            reject(update(valid(), "scratchPolicy") { it + ("requiredAvailableBytes" to value) })
        }
        val overflow = valid().toString().replace("\"requiredAvailableBytes\":1048576", "\"requiredAvailableBytes\":9223372036854775808")
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationRuntimeConfiguration.parse(overflow.toByteArray()) }
        val exponent = valid().toString().replace("\"schemaVersion\":1", "\"schemaVersion\":1e0")
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilationRuntimeConfiguration.parse(exponent.toByteArray()) }
    }

    @Test
    fun `paths must be canonical non-root strings without control characters`() {
        listOf("", "/", "relative/runtime", "/opt/../runtime", "/opt/./runtime", "/opt//runtime", "/opt/runtime/",
            "/opt/runtime\nfile", "/opt/runtime\u0000file", "/opt/runtime\u007ffile").forEach { value ->
            reject(valid() + ("scratchMount" to JsonPrimitive(value)))
            reject(valid() + ("managerControlGroup" to JsonPrimitive(value)))
            reject(update(valid(), "compiler") { it + ("path" to JsonPrimitive(value)) })
        }
        reject(valid() + ("scratchMount" to JsonPrimitive(12)))
    }

    @Test
    fun `compiler closure has exactly one disjoint same-path root and excludes broad host trees`() {
        listOf("/usr", "/usr/bin", "/usr/lib", "/lib64", "/opt", "/etc", "/run", "/home").forEach { root ->
            reject(valid() + ("compilerRuntimeMounts" to JsonArray(listOf(runtime(root)))))
        }
        reject(valid() + ("compilerRuntimeMounts" to JsonArray(listOf(runtime("/opt/module-compiler", "/compiler")))))
        reject(valid() + ("compilerRuntimeMounts" to JsonArray(listOf(runtime("/opt/module-compiler"), runtime("/opt/module-compiler/bin")))))
        reject(valid() + ("compilerRuntimeMounts" to JsonArray(listOf(runtime("/opt/module-compiler"), runtime("/opt/module-compiler")))))
        listOf("/opt/different/bin/cc", "/opt/module-compiler", "/opt/module-compiler-extra/bin/cc").forEach { path ->
            reject(update(valid(), "compiler") { it + ("path" to JsonPrimitive(path)) })
        }
        reject(update(valid(), "isolation") {
            it + ("javaRuntime" to runtime("/opt/module-compiler/java", "/keeper-java")) +
                ("javaExecutable" to JsonPrimitive("/opt/module-compiler/java/bin/java"))
        })
        reject(update(valid(), "isolation") { it + ("javaRuntime" to runtime("/opt/keeper-java", "/opt/module-compiler/java")) })
        reject(update(valid(), "isolation") {
            it + ("systemLibraryMounts" to JsonArray(listOf(runtime("/opt/module-compiler/libraries", "/lib64"))))
        })
        reject(update(valid(), "isolation") {
            it + ("systemLibraryMounts" to JsonArray(listOf(runtime("/usr/lib", "/lib64"))))
        })
    }

    @Test
    fun `scratch and compiler mounts cannot overlap retained or system namespaces`() {
        listOf("/opt/module-compiler", "/opt/keeper-java/state", "/keeper-java/state", "/lib64/scratch",
            "/opt/keeper-libraries/scratch", "/opt/worker", "/opt/helpers", "/proc/scratch", "/dev/scratch", "/run/user/1000/scratch").forEach { path ->
            reject(valid() + ("scratchMount" to JsonPrimitive(path)))
        }
        listOf("/srv/module-scratch/nested", "/srv", "/proc/compiler", "/dev/compiler", "/run/user/1000/compiler",
            "/opt/worker", "/opt/helpers", "/keeper-java", "/opt/keeper-java", "/lib64/compiler").forEach { path ->
            reject(valid() + ("compilerRuntimeMounts" to JsonArray(listOf(runtime("/opt/module-compiler"), runtime(path)))))
        }
        reject(update(valid(), "isolation") { it + ("systemLibraryMounts" to JsonArray(listOf(runtime("/opt/keeper-libraries", "/proc")))) })
    }

    @Test
    fun `scratch authority is finite and consistent before acquiring a filesystem`() {
        val invalid = listOf(
            "maximumFilesystemBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024 + 1),
            "maximumFilesystemInodes" to JsonPrimitive(1_048_577),
            "requiredAvailableInodes" to JsonPrimitive(3),
            "requiredAvailableBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024 + 1),
            "requiredAvailableInodes" to JsonPrimitive(1_048_577),
            "maximumFilesystemBytes" to JsonPrimitive(1),
            "maximumFilesystemInodes" to JsonPrimitive(4),
        )
        invalid.forEach { field -> reject(update(valid(), "scratchPolicy") { it + field }) }
    }

    @Test
    fun `parser bounds mount count classpath count bytes depth and strings`() {
        val maximumMounts = listOf(runtime("/opt/module-compiler")) + (1..15).map { runtime("/opt/compiler-runtime-$it") }
        assertEquals(16, parse(valid() + ("compilerRuntimeMounts" to JsonArray(maximumMounts))).compilerRuntimeMounts.size)
        reject(valid() + ("compilerRuntimeMounts" to JsonArray(maximumMounts + runtime("/opt/compiler-runtime-extra"))))
        reject(valid() + ("compilerRuntimeMounts" to JsonArray(emptyList())))
        reject(update(valid(), "isolation") { it + ("systemLibraryMounts" to JsonArray(emptyList())) })
        val classPathEntries = (1..512).map { classPath("/opt/worker/worker-$it.jar") }
        assertEquals(512, parse(update(valid(), "isolation") { it + ("workerClassPath" to JsonArray(classPathEntries)) }).isolation.workerClassPath.size)
        reject(update(valid(), "isolation") { it + ("workerClassPath" to JsonArray(classPathEntries + classPath("/opt/worker/extra.jar"))) })
        reject(update(valid(), "isolation") { it + ("workerClassPath" to JsonArray(emptyList())) })
        reject(update(valid(), "isolation") { it + ("workerClassPath" to JsonArray(listOf(classPathEntries.first(), classPathEntries.first()))) })
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleCompilationRuntimeConfiguration.parse(ByteArray(256 * 1024 + 1) { ' '.code.toByte() })
        }
        reject(valid() + ("scratchMount" to JsonPrimitive("/" + "x".repeat(4096))))
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleCompilationRuntimeConfiguration.parse(("[".repeat(10) + "0" + "]".repeat(10)).toByteArray())
        }
    }

    private fun parse(record: Map<String, JsonElement>): ContainedModuleCompilationRuntimeConfiguration.Declaration =
        ContainedModuleCompilationRuntimeConfiguration.parse(JsonObject(record).toString().toByteArray())

    private fun reject(record: Map<String, JsonElement>) {
        assertFailsWith<IllegalArgumentException> { parse(record) }
    }

    private fun update(record: JsonObject, field: String, edit: (JsonObject) -> Map<String, JsonElement>): JsonObject =
        JsonObject(record + (field to JsonObject(edit(record.getValue(field) as JsonObject))))

    private fun runtime(source: String, destination: String = source) = JsonObject(mapOf(
        "source" to JsonPrimitive(source), "destination" to JsonPrimitive(destination), "sha256" to JsonPrimitive(DIGEST),
    ))

    private fun classPath(path: String) = JsonObject(mapOf("path" to JsonPrimitive(path), "sha256" to JsonPrimitive(DIGEST)))

    private fun valid(): JsonObject = JsonObject(mapOf(
        "schemaVersion" to JsonPrimitive(1),
        "profileId" to JsonPrimitive(GeneratedCMakeReconstructionProfile.PROFILE_ID),
        "compiler" to JsonObject(mapOf("path" to JsonPrimitive("/opt/module-compiler/bin/cc"), "sha256" to JsonPrimitive(DIGEST))),
        "compilerRuntimeMounts" to JsonArray(listOf(runtime("/opt/module-compiler"))),
        "scratchMount" to JsonPrimitive("/srv/module-scratch"),
        "managerControlGroup" to JsonPrimitive("/user.slice/user-1000.slice/user@1000.service"),
        "scratchPolicy" to JsonObject(mapOf(
            "requiredAvailableBytes" to JsonPrimitive(1_048_576),
            "maximumFilesystemBytes" to JsonPrimitive(8L * 1024 * 1024 * 1024),
            "requiredAvailableInodes" to JsonPrimitive(1024), "maximumFilesystemInodes" to JsonPrimitive(1_048_576),
        )),
        "isolation" to JsonObject(mapOf(
            "javaExecutable" to JsonPrimitive("/opt/keeper-java/bin/java"),
            "javaRuntime" to runtime("/opt/keeper-java", "/keeper-java"),
            "systemLibraryMounts" to JsonArray(listOf(runtime("/opt/keeper-libraries", "/lib64"))),
            "bubblewrapExecutable" to JsonPrimitive("/opt/helpers/bwrap"),
            "resourceLimiterExecutable" to JsonPrimitive("/opt/helpers/prlimit"),
            "scopeSupervisorExecutable" to JsonPrimitive("/opt/helpers/systemd-run"),
            "scopeInspectorExecutable" to JsonPrimitive("/opt/helpers/systemctl"),
            "systemdBusControllerExecutable" to JsonPrimitive("/opt/helpers/busctl"),
            "systemdUserRuntimeDirectory" to JsonPrimitive("/run/user/1000"),
            "workerClassPath" to JsonArray(listOf(classPath("/opt/worker/worker.jar"))),
            "expectedJavaSha256" to JsonPrimitive(DIGEST), "expectedBubblewrapSha256" to JsonPrimitive(DIGEST),
            "expectedResourceLimiterSha256" to JsonPrimitive(DIGEST), "expectedScopeSupervisorSha256" to JsonPrimitive(DIGEST),
            "expectedScopeInspectorSha256" to JsonPrimitive(DIGEST), "expectedSystemdBusControllerSha256" to JsonPrimitive(DIGEST),
        )),
    ))

    private companion object {
        val DIGEST = "a".repeat(64)
    }
}
