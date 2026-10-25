package decompengine.project

import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonArray
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
    fun `request rejects identity mismatches arbitrary path roles duplicate members and excessive bounds`() {
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
    fun `budget variants of both registered profiles retain commands and bind their full requested identities`() {
        for (base in ReconstructionProfiles.builtIn) {
            val variant = variant(base, base.budgets.copy(buildWallClockMillis = 12_345, buildMaximumOutputBytes = 8192,
                plannerMaximumEntities = 4096, reconstructionMaximumContextCharacters = 2048))
            val original = request(base, maximumOutputBytes = 8192)
            val requested = request(variant, maximumOutputBytes = 8192)
            val parsed = ContainedModuleCompilerRequest.parse(requested.canonicalBytes)
            assertEquals(variant.canonicalJson(), parsed.profile.canonicalJson())
            assertEquals(variant.sha256, parsed.profileSha256)
            assertNotEquals(base.sha256, parsed.profileSha256)
            assertNotEquals(original.sha256, parsed.sha256)
            assertEquals(original.command, parsed.command)
            assertEquals(original.snapshotSha256, parsed.snapshotSha256)
            val result = ContainedModuleCompilerResult.parse(result(parsed).canonicalBytes)
            result.requireBinding(parsed)
            assertFailsWith<IllegalArgumentException> { result.requireBinding(original) }
            assertFailsWith<IllegalArgumentException> { result.requireBinding(request(
                variant(base, variant.budgets.copy(plannerMaximumEntities = 4095)), maximumOutputBytes = 8192)) }
            assertFailsWith<IllegalArgumentException> { request(variant, maximumWallMillis = 12_346, maximumOutputBytes = 8192) }
            assertFailsWith<IllegalArgumentException> { request(variant, maximumOutputBytes = 8193) }
        }
    }

    @Test
    fun `profile admission rejects every nonbudget change through constructors and closed records`() {
        val base = ReconstructionProfiles.default
        val record = profileRecord(base)
        val budgets = record.getValue("budgets") as JsonObject
        val layout = record.getValue("layout") as JsonObject
        val configuration = record.getValue("adapterConfiguration") as JsonObject
        val mutations = listOf(
            JsonObject(record + ("schemaVersion" to JsonPrimitive(2))),
            JsonObject(record + ("id" to JsonPrimitive("unregistered"))),
            JsonObject(record + ("id" to JsonPrimitive(GeneratedCNinjaReconstructionProfile.PROFILE_ID))),
            JsonObject(record + ("layout" to JsonObject(layout + ("schemaVersion" to JsonPrimitive(2))))),
            JsonObject(record + ("layout" to JsonObject(layout + ("files" to JsonArray(emptyList()))))),
            JsonObject(record + ("adapterConfiguration" to JsonObject(configuration + ("compiler-flags" to JsonArray(listOf(JsonPrimitive("-include/evil.h"))))))),
            JsonObject(record + ("adapterConfiguration" to JsonObject(configuration + ("compiler-driver" to JsonArray(listOf(JsonPrimitive("evil"))))))),
            JsonObject(record + ("adapterConfiguration" to JsonObject(configuration + ("extra" to JsonArray(listOf(JsonPrimitive("value"))))))),
            JsonObject(record + ("budgets" to JsonObject(budgets + ("extra" to JsonPrimitive(1))))),
            JsonObject(record + ("extra" to JsonPrimitive(true))),
        ) + record.keys.map { JsonObject(record - it) } + budgets.keys.map {
            JsonObject(record + ("budgets" to JsonObject(budgets - it)))
        }
        mutations.forEach { invalid ->
            assertFailsWith<IllegalArgumentException> { parseContainedModuleCompilerProfile(invalid) }
            assertFailsWith<IllegalArgumentException> { request(profileRecord = invalid) }
        }
        assertFailsWith<IllegalArgumentException> {
            requireContainedModuleCompilerProfile(ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
                base.adapterConfiguration + ("compiler-driver" to listOf("evil"))))
        }
        assertFailsWith<IllegalArgumentException> {
            requireContainedModuleCompilerProfile(ReconstructionProfile(base.schemaVersion, base.id,
                GeneratedCNinjaReconstructionProfile.descriptor.layout, base.budgets, base.adapterConfiguration))
        }
    }

    @Test
    fun `all budget fields require positive bounded integers independently of compiler hard ceilings`() {
        val base = ReconstructionProfiles.default
        val record = profileRecord(base)
        val budgets = record.getValue("budgets") as JsonObject
        for (field in budgets.keys) {
            for (invalid in listOf(JsonPrimitive(0), JsonPrimitive(-1), JsonPrimitive("1"), JsonPrimitive(true),
                JsonPrimitive(1.5), OracleJson.parse("9223372036854775808".toByteArray()))) {
                val changed = JsonObject(record + ("budgets" to JsonObject(budgets + (field to invalid))))
                assertFailsWith<IllegalArgumentException>(field) { parseContainedModuleCompilerProfile(changed) }
            }
        }
        val unsupported = variant(base, base.budgets.copy(buildMaximumOutputBytes = 1))
        assertEquals(unsupported.sha256, requireContainedModuleCompilerProfile(unsupported).sha256)
        assertFailsWith<IllegalArgumentException> { request(unsupported, maximumOutputBytes = 1) }
        val small = variant(base, base.budgets.copy(buildWallClockMillis = 1500))
        assertEquals(1500L, request(small, maximumWallMillis = 1500).maximumWallMillis)
        assertFailsWith<IllegalArgumentException> { request(small, maximumWallMillis = 1501) }
        assertFailsWith<IllegalArgumentException> { moduleCompilerOperationWallMillis(small) }
        assertEquals(12_000L, moduleCompilerOperationWallMillis(variant(base, base.budgets.copy(buildWallClockMillis = 12_345))))
        assertEquals(120_000L, moduleCompilerOperationWallMillis(base))
        // Host admission belongs to the caller's selected policy. A larger unrelated context budget
        // must not inherit DEFAULT's ceiling here; native execution retains its own fixed caps.
        val larger = variant(base, base.budgets.copy(reconstructionMaximumContextCharacters = 600_000,
            buildWallClockMillis = Long.MAX_VALUE, buildMaximumOutputBytes = Long.MAX_VALUE))
        val largerRequest = ContainedModuleCompilerRequest.parse(request(larger).canonicalBytes)
        assertEquals(larger.sha256, largerRequest.profile.sha256)
        assertEquals(120_000L, moduleCompilerOperationWallMillis(larger))
        val overInt = JsonObject(record + ("budgets" to JsonObject(budgets + ("plannerMaximumEntities" to JsonPrimitive(1L + Int.MAX_VALUE)))))
        assertFailsWith<IllegalArgumentException> { parseContainedModuleCompilerProfile(overInt) }
        val variant = variant(base, base.budgets.copy(plannerMaximumEntities = 12))
        assertFailsWith<IllegalArgumentException> { request(variant, maximumWallMillis = ContainedModuleCompilerRequest.MAXIMUM_WALL_MILLIS + 1) }
        assertFailsWith<IllegalArgumentException> { request(variant, maximumOutputBytes = ContainedModuleCompilerRequest.MAXIMUM_OUTPUT_BYTES + 1) }
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
            JsonObject(root - "profile"),
            JsonObject(root + ("profile" to profileRecord(variant(ReconstructionProfiles.default,
                ReconstructionProfiles.default.budgets.copy(plannerMaximumEntities = 12))))),
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
        profileRecord: JsonObject = profileRecord(profile),
    ) = ContainedModuleCompilerRequest(nonce, profileId, profileSha256, snapshotRoot, source.path, inputs,
        Path.of("/pinned/compiler"), "4".repeat(64), root.resolve("output"), maximumWallMillis, maximumOutputBytes, profileRecord)

    private fun variant(base: ReconstructionProfile, budgets: ReconstructionBudgets) =
        ReconstructionProfile(base.schemaVersion, base.id, base.layout, budgets, base.adapterConfiguration)
    private fun profileRecord(profile: ReconstructionProfile) = OracleJson.parse(profile.canonicalJson().toByteArray()) as JsonObject

    private fun result(request: ContainedModuleCompilerRequest, outcome: String = "compiled-object", exitCode: Int? = 0,
        signal: Int? = null, objectSha256: String? = "5".repeat(64), objectBytes: Long? = 128) =
        ContainedModuleCompilerResult(request.sha256, request.nonce, request.profileId, request.profileSha256,
            request.snapshotSha256, request.sourceSha256, request.compilerSha256, outcome, exitCode, signal,
            sha256(byteArrayOf()), 0, sha256(byteArrayOf()), 0, objectSha256, objectBytes)
}
