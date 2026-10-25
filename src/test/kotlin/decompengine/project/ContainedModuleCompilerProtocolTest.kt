package decompengine.project

import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class ContainedModuleCompilerProtocolTest {
    @Test
    fun `request binds exact registered profiles immutable sorted snapshots and absolute derived arguments`() {
        for (profile in ReconstructionProfiles.builtIn) {
            val inputs = mutableListOf(header, source)
            val request = request(profile, inputs)
            inputs.clear()
            val parsed = ContainedModuleCompilerRequest.parse(request.canonicalBytes)
            assertEquals(listOf(header, source), request.inputs)
            assertEquals(request.sha256, parsed.sha256)
            assertEquals(request.snapshotSha256, request(profile, listOf(source, header)).snapshotSha256)
            assertEquals(source.sha256, request.sourceSha256)
            assertContentEquals(request.canonicalBytes, parsed.canonicalBytes)
            assertEquals(listOf("/pinned/compiler", "-B/pinned/", "-std=c11", "-g", "-Wall", "-Wextra", "-Werror", "-I$root/snapshot/include",
                "-c", "$root/snapshot/src/modules/alpha.c", "-o", "$root/output/module.o"), request.command)
            val exposed = request.canonicalBytes
            exposed.fill(0)
            assertEquals(request.sha256, sha256(request.canonicalBytes))
            assertFailsWith<UnsupportedOperationException> { (request.inputs as MutableList<ContainedModuleCompilerInput>).clear() }
        }
    }

    @Test
    fun `request rejects profile variants arbitrary path roles duplicate members and excessive bounds`() {
        val profile = ReconstructionProfiles.default
        assertFailsWith<IllegalArgumentException> { request(profileSha256 = "0".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { request(profileId = "unregistered") }
        assertFailsWith<IllegalArgumentException> { request(inputs = listOf(source, source)) }
        assertFailsWith<IllegalArgumentException> { request(inputs = listOf(header)) }
        assertFailsWith<IllegalArgumentException> { request(inputs = listOf(source, source.copy(path = "src/modules/other.c"))) }
        assertFailsWith<IllegalArgumentException> { request(inputs = listOf(source, header.copy(path = "Makefile"))) }
        assertFailsWith<IllegalArgumentException> { request(inputs = listOf(source, header.copy(path = "include/modules/evil.h.gch"))) }
        assertFailsWith<IllegalArgumentException> { request(maximumWallMillis = 30_001) }
        assertFailsWith<IllegalArgumentException> { request(maximumOutputBytes = 2L * 1024 * 1024 + 1) }
        assertFailsWith<IllegalArgumentException> { request(snapshotRoot = root.resolve("output/inside")) }
        assertFailsWith<IllegalArgumentException> { request(snapshotRoot = Path.of("relative")) }
        assertFailsWith<IllegalArgumentException> { source.copy(path = "src/modules/../alpha.c") }
        assertFailsWith<IllegalArgumentException> { source.copy(sha256 = "bad") }
        assertFailsWith<IllegalArgumentException> { source.copy(bytes = -1) }
        assertEquals(profile.sha256, request().profileSha256)
    }

    @Test
    fun `canonical request parser rejects duplicate unknown and altered digest claims`() {
        val request = request()
        val root = OracleJson.parseCanonical(request.canonicalBytes) as JsonObject
        for (changed in listOf(
            JsonObject(root + ("argv" to JsonPrimitive("arbitrary"))),
            JsonObject(root + ("snapshotSha256" to JsonPrimitive("0".repeat(64)))),
            JsonObject(root + ("schemaVersion" to JsonPrimitive(2))),
            JsonObject(root + ("maximumWallMillis" to JsonPrimitive("1000"))),
        )) assertFailsWith<IllegalArgumentException> { ContainedModuleCompilerRequest.parse(OracleJson.canonicalBytes(changed)) }
        assertFailsWith<IllegalArgumentException> { ContainedModuleCompilerRequest.parse(request.canonicalBytes + byteArrayOf(10)) }
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleCompilerRequest.parse(request.canonicalBytes.decodeToString().replaceFirst("{", "{\"schemaVersion\":1,").toByteArray())
        }
    }

    @Test
    fun `passive result binds request nonce and raw exit or signal without acceptance authority`() {
        val request = request()
        val result = result(request)
        val parsed = ContainedModuleCompilerResult.parse(result.canonicalBytes)
        parsed.requireBinding(request)
        assertEquals(0, parsed.exitCode)
        assertEquals(null, parsed.signal)
        assertEquals("compiled-object", parsed.outcome)
        assertTrue("worker-observation-only-requires-authenticated-terminal-proof" in parsed.canonicalBytes.decodeToString())
        assertFalse("\"accepted\"" in parsed.canonicalBytes.decodeToString())
        assertFailsWith<IllegalArgumentException> { parsed.requireBinding(request(nonce = "9".repeat(64))) }
        assertFailsWith<IllegalArgumentException> { result(request, exitCode = 143, signal = 15) }
        assertFailsWith<IllegalArgumentException> { result(request, outcome = "compiled-object", exitCode = 1) }
        val signal = result(request, outcome = "compiler-signaled", exitCode = null, signal = 15, objectSha256 = null, objectBytes = null)
        assertEquals(15, ContainedModuleCompilerResult.parse(signal.canonicalBytes).signal)
        val doc = OracleJson.parseCanonical(result.canonicalBytes) as JsonObject
        assertFailsWith<IllegalArgumentException> {
            ContainedModuleCompilerResult.parse(OracleJson.canonicalBytes(JsonObject(doc + ("authority" to JsonPrimitive("accepted")))))
        }
    }

    private val root = Path.of("build/test-work/module-compiler-protocol").toAbsolutePath().normalize()
    private val source = ContainedModuleCompilerInput("src/modules/alpha.c", "1".repeat(64), 32)
    private val header = ContainedModuleCompilerInput("include/modules/alpha.h", "2".repeat(64), 20)
    private fun request(
        profile: ReconstructionProfile = ReconstructionProfiles.default,
        inputs: List<ContainedModuleCompilerInput> = listOf(source, header),
        profileId: String = profile.id, profileSha256: String = profile.sha256,
        maximumWallMillis: Long = 1000, maximumOutputBytes: Long = 65536,
        snapshotRoot: Path = root.resolve("snapshot"), nonce: String = "3".repeat(64),
    ) = ContainedModuleCompilerRequest(nonce, profileId, profileSha256, snapshotRoot, source.path, inputs,
        Path.of("/pinned/compiler"), "4".repeat(64), root.resolve("output"), maximumWallMillis, maximumOutputBytes)

    private fun result(request: ContainedModuleCompilerRequest, outcome: String = "compiled-object", exitCode: Int? = 0,
        signal: Int? = null, objectSha256: String? = "5".repeat(64), objectBytes: Long? = 128) =
        ContainedModuleCompilerResult(request.sha256, request.nonce, request.profileId, request.profileSha256,
            request.snapshotSha256, request.sourceSha256, request.compilerSha256, outcome, exitCode, signal,
            sha256(byteArrayOf()), 0, sha256(byteArrayOf()), 0, objectSha256, objectBytes)
}
