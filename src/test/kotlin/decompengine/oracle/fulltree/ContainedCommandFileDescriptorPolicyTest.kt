package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.nio.file.Path
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Test

/** Pure authored controls; no live process, procfs read, lease, provider or execution authority. */
class ContainedCommandFileDescriptorPolicyTest {
    @Test
    fun `closed module policy retains its authored identity and finite pair`() {
        assertEquals(listOf(POLICY), ContainedCommandFileDescriptorPolicy.entries.toList())
        assertEquals(7678L, POLICY.maximumOpenFiles)
        assertEquals(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "provider" to JsonPrimitive("contained-module-compilation-file-descriptor-policy-v1"),
            "scope" to JsonPrimitive("module-object"),
            "softLimit" to JsonPrimitive(7678), "hardLimit" to JsonPrimitive(7678),
        )), POLICY.canonicalIdentity())
        assertEquals(POLICY_SHA256, POLICY.sha256)
        assertEquals(POLICY_SHA256, hash(POLICY.canonicalIdentity()))
        assertEquals(512L, containedCommandMaximumOpenFiles(null))
        assertEquals(7678L, containedCommandMaximumOpenFiles(POLICY))
    }

    @Test
    fun `absent policy preserves literal serial and parallel resource bytes`() {
        val serial = resources(policy = null)
        val expected = """
            {
              "maximumFileBytes": 8192,
              "maximumResidentBytes": 1073741824,
              "pidsMax": 16,
              "wallClockMillis": 10000
            }
        """.trimIndent() + "\n"
        assertContentEquals(expected.toByteArray(), OracleJson.canonicalBytes(serial.json()))
        assertEquals(4, serial.json().size)
        val parallel = serial.copy(processorCount = 4)
        val expectedParallel = """
            {
              "maximumFileBytes": 8192,
              "maximumResidentBytes": 1073741824,
              "pidsMax": 16,
              "processorCount": 4,
              "wallClockMillis": 10000
            }
        """.trimIndent() + "\n"
        assertContentEquals(expectedParallel.toByteArray(), OracleJson.canonicalBytes(parallel.json()))
        assertEquals(5, parallel.json().size)
        assertEquals(serial.aggregateCpuSeconds, parallel.aggregateCpuSeconds)
        assertNull(serial.fileDescriptorPolicy)
        assertNull(parallel.fileDescriptorPolicy)
    }

    @Test
    fun `module resources add exactly three serial fields without changing other budgets`() {
        val old = resources(policy = null)
        val selected = resources()
        assertEquals(old.json() + mapOf(
            "processorCount" to JsonPrimitive(1),
            "fileDescriptorPolicySha256" to JsonPrimitive(POLICY_SHA256),
            "maximumOpenFiles" to JsonPrimitive(7678),
        ), selected.json())
        assertEquals(7, selected.json().size)
        assertEquals(old.aggregateCpuSeconds, selected.aggregateCpuSeconds)
        for (processors in listOf(2, 3, 4)) {
            assertFailsWith<IllegalArgumentException> { selected.copy(processorCount = processors) }
        }
    }

    @Test
    fun `launcher admission requires inherited hard capacity but never increases selected capacity`() {
        assertFailsWith<IllegalArgumentException> {
            containedCommandFileDescriptorAdmission(POLICY, observation(512, 7677))
        }
        for ((soft, hard) in listOf(512L to 7678L, 7678L to 7678L, 100_000L to 100_000L, 0L to Long.MAX_VALUE)) {
            val actual = containedCommandFileDescriptorAdmission(POLICY, observation(soft, hard))
            assertEquals(JsonObject(mapOf(
                "policySha256" to JsonPrimitive(POLICY_SHA256),
                "trustedHostMaximumOpenFiles" to JsonPrimitive(7678),
                "launcherProcess" to JsonObject(mapOf(
                    "hostPid" to JsonPrimitive(PID), "startTimeTicks" to JsonPrimitive(START),
                    "inheritedSoftLimit" to JsonPrimitive(soft), "inheritedHardLimit" to JsonPrimitive(hard),
                )),
            )), actual)
            assertEquals(7678L, containedCommandMaximumOpenFiles(POLICY))
            assertEquals("--nofile=7678:7678", containedCommandFileDescriptorLimitArgument(POLICY.maximumOpenFiles))
        }
    }

    @Test
    fun `finite limits parser reads only the exact open files row`() {
        val text = "Limit                     Soft Limit           Hard Limit           Units\n" +
            "Max cpu time              unlimited            unlimited            seconds\n" +
            "Max open files            512                  7678                 files\n"
        assertEquals(ContainedCommandFileDescriptorLimits(512, 7678), parseContainedCommandFileDescriptorLimits(text))
        assertEquals(ContainedCommandFileDescriptorLimits(0, Long.MAX_VALUE),
            parseContainedCommandFileDescriptorLimits("Max\topen\tfiles\t0\t9223372036854775807\tfiles\t\n"))
    }

    @Test
    fun `limits parser rejects missing duplicate unlimited malformed units and integer overflow`() {
        val row = limitsRow()
        val malformed = listOf("", row.trimEnd(), "Max cpu time 1 2 seconds\n", row + row,
            row + "Max\topen\tfiles\t7678\t7678\tfiles\n", " $row", "Max open filesOther 7678 7678 files\n",
            "Max open files unlimited 7678 files\n", "Max open files 7678 unlimited files\n",
            "Max open files 7678 7678 bytes\n", "Max open files 7678 7678 files extra\n",
            "Max open files 7678 files\n", "Max open files 7679 7678 files\n",
            "Max open files -1 7678 files\n", "Max open files +1 7678 files\n",
            "Max open files 01 7678 files\n", "Max open files 1.0 7678 files\n",
            "Max open files 1e3 7678 files\n", "Max open files 0 9223372036854775808 files\n",
            "Max open files 0 10000000000000000000 files\n", row.replace("files\n", "files\r\n"),
            row + "\u0000\n", row + "é\n")
        for (bad in malformed) {
            assertFailsWith<IllegalArgumentException>(bad) { parseContainedCommandFileDescriptorLimits(bad) }
        }
    }

    @Test
    fun `limits parser enforces exact text and row ceilings`() {
        val row = limitsRow()
        val exactBytes = "X".repeat(MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES - row.length - 1) + "\n" + row
        assertEquals(MAXIMUM_CONTAINED_PROCESS_LIMITS_BYTES, exactBytes.length)
        assertEquals(ContainedCommandFileDescriptorLimits(7678, 7678), parseContainedCommandFileDescriptorLimits(exactBytes))
        assertFailsWith<IllegalArgumentException> { parseContainedCommandFileDescriptorLimits(exactBytes + "\n") }
        assertEquals(ContainedCommandFileDescriptorLimits(7678, 7678),
            parseContainedCommandFileDescriptorLimits("Other limit\n".repeat(127) + row))
        assertFailsWith<IllegalArgumentException> {
            parseContainedCommandFileDescriptorLimits("Other limit\n".repeat(128) + row)
        }
    }

    @Test
    fun `observation binds both process generation and the exact selected pair`() {
        val actual = observation()
        actual.requireIdentity(PID, START)
        actual.requireSelected(POLICY)
        assertEquals(actual, ContainedCommandFileDescriptorObservation.parse(actual.json()))
        assertFailsWith<IllegalArgumentException> { actual.requireIdentity(PID + 1, START) }
        assertFailsWith<IllegalArgumentException> { actual.requireIdentity(PID, START + 1) }
        for ((soft, hard) in listOf(512L to 512L, 7677L to 7678L, 7678L to 7679L)) {
            assertFailsWith<IllegalArgumentException> { observation(soft, hard).requireSelected(POLICY) }
        }
        assertFailsWith<IllegalArgumentException> { observation(7679, 7678) }
        assertFailsWith<IllegalArgumentException> { ContainedCommandFileDescriptorLimits(-1, 7678) }
        for (pid in listOf(0L, -1L, Int.MAX_VALUE.toLong() + 1)) {
            assertFailsWith<IllegalArgumentException> { actual.copy(hostPid = pid) }
        }
        for (start in listOf(0L, -1L)) {
            assertFailsWith<IllegalArgumentException> { actual.copy(startTimeTicks = start) }
        }
    }

    @Test
    fun `observation JSON is closed and rejects null strings floats booleans and overflow`() {
        val value = observation().json()
        assertEquals(setOf("provider", "hostPid", "startTimeTicks", "softLimit", "hardLimit"), value.keys)
        for (key in value.keys) {
            assertFails { ContainedCommandFileDescriptorObservation.parse(JsonObject(value - key)) }
        }
        assertFails { ContainedCommandFileDescriptorObservation.parse(JsonObject(value + ("extra" to JsonPrimitive(1)))) }
        assertFails { ContainedCommandFileDescriptorObservation.parse(JsonObject(value + ("provider" to JsonPrimitive("other")))) }
        for (key in listOf("hostPid", "startTimeTicks", "softLimit", "hardLimit")) {
            for (bad in listOf(JsonNull, JsonPrimitive("7678"), JsonPrimitive(true), JsonPrimitive(1.5),
                JsonPrimitive(-1), JsonArray(emptyList()), JsonObject(emptyMap()),
                OracleJson.parse("9223372036854775808".toByteArray()))) {
                assertFails("$key=$bad") { ContainedCommandFileDescriptorObservation.parse(JsonObject(value + (key to bad))) }
            }
        }
        assertFails { ContainedCommandFileDescriptorObservation.parse(JsonObject(value + ("softLimit" to JsonPrimitive(7679)))) }
    }

    @Test
    fun `limiter supports only the old default and closed module pairs`() {
        assertEquals("--nofile=512:512", containedCommandFileDescriptorLimitArgument(512))
        assertEquals("--nofile=7678:7678", containedCommandFileDescriptorLimitArgument(7678))
        for (bad in listOf(Long.MIN_VALUE, -1L, 0L, 511L, 513L, 7677L, 7679L, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { containedCommandFileDescriptorLimitArgument(bad) }
        }
    }

    @Test
    fun `descriptor census separates cardinality from the largest descriptor number`() {
        for (limit in listOf(512L, 7678L)) {
            val sparse = listOf("0", "7", (limit - 1).toString())
            assertEquals(sparse.map(String::toInt), containedCommandDescriptorNumbers(sparse.iterator(), limit))
            assertEquals(emptyList(), containedCommandDescriptorNumbers(emptyList<String>().iterator(), limit))
            assertFailsWith<IllegalArgumentException> {
                containedCommandDescriptorNumbers(listOf(limit.toString()).iterator(), limit)
            }
            val complete = (0 until limit.toInt()).map(Int::toString)
            assertEquals((0 until limit.toInt()).toList(), containedCommandDescriptorNumbers(complete.iterator(), limit))
        }
    }

    @Test
    fun `descriptor census rejects aliases duplicates nonnumeric and overflowing names`() {
        for (bad in listOf("", "01", "-1", "+1", "1.0", "1e2", " 1", "1 ", "١", "2147483648", "10000000000")) {
            assertFailsWith<IllegalArgumentException>(bad) { containedCommandDescriptorNumbers(listOf(bad).iterator(), 7678) }
        }
        assertFailsWith<IllegalArgumentException> { containedCommandDescriptorNumbers(listOf("0", "1", "1").iterator(), 7678) }
    }

    @Test
    fun `descriptor census stops consuming before the first over-budget entry`() {
        for (limit in listOf(512L, 7678L)) {
            val names = CountingNames()
            assertFailsWith<IllegalArgumentException> { containedCommandDescriptorNumbers(names, limit) }
            assertEquals(limit.toInt(), names.nextCalls)
            assertEquals(limit.toInt() + 1, names.hasNextCalls)
        }
        val invalidPolicy = CountingNames()
        assertFailsWith<IllegalArgumentException> { containedCommandDescriptorNumbers(invalidPolicy, 513) }
        assertEquals(0, invalidPolicy.nextCalls)
        assertEquals(0, invalidPolicy.hasNextCalls)
    }

    @Test
    fun `v5 runtime fields bind exact request serial resources admission and optional policies`() {
        for (visibility in listOf(null, visibility(empty = true), visibility(empty = false))) {
            for (interrupted in listOf(false, true)) {
                val request = request(interrupted, visibility)
                val interruption = INTERRUPTION_SHA256.takeIf { interrupted }
                val actual = containedCommandFileDescriptorRuntimeFields(request, resources(), admission(), interruption, visibility)
                assertEquals(mapOf(
                    "commandRequestProvider" to JsonPrimitive("kotlin-contained-command-request-v5"),
                    "commandRequestSha256" to JsonPrimitive(request.sha256),
                    "terminalResourcePolicySha256" to JsonPrimitive(ContainedCommandTerminalResourceEvidence.policySha256),
                    "resources" to resources().json(), "fileDescriptorAdmission" to admission(),
                ) + (interruption?.let { mapOf("interruptionPolicySha256" to JsonPrimitive(it)) } ?: emptyMap()) +
                    (visibility?.let { mapOf("retainedInputVisibility" to it) } ?: emptyMap()), actual)
                assertEquals(7, (actual.getValue("resources") as JsonObject).size)
            }
        }
    }

    @Test
    fun `runtime helper rejects mismatched request policies interruption and visibility`() {
        assertFails { containedCommandFileDescriptorRuntimeFields(request(), resources(policy = null), admission(), null, null) }
        val legacy = request(policy = null)
        assertFails { containedCommandFileDescriptorRuntimeFields(legacy, resources(), admission(), null, null) }
        assertFails { containedCommandFileDescriptorRuntimeFields(request(), resources(), admission(), INTERRUPTION_SHA256, null) }
        assertFails { containedCommandFileDescriptorRuntimeFields(request(interrupted = true), resources(), admission(), null, null) }
        val selected = visibility(empty = false)
        val empty = visibility(empty = true)
        assertFails { containedCommandFileDescriptorRuntimeFields(request(visibility = selected), resources(), admission(), null, empty) }
        assertFails { containedCommandFileDescriptorRuntimeFields(request(visibility = empty), resources(), admission(), null, null) }
        assertFails { containedCommandFileDescriptorRuntimeFields(request(), resources(), admission(), null, empty) }
    }

    @Test
    fun `runtime admission replay rejects edited ceiling policy capacity invalid identity and field types`() {
        val valid = admission()
        fun reject(value: JsonObject) = assertFails {
            containedCommandFileDescriptorRuntimeFields(request(), resources(), value, null, null)
        }
        for (key in valid.keys) reject(JsonObject(valid - key))
        reject(JsonObject(valid + ("extra" to JsonPrimitive(true))))
        reject(JsonObject(valid + ("policySha256" to JsonPrimitive("f".repeat(64)))))
        for (bad in listOf(JsonPrimitive(7677), JsonPrimitive(7679), JsonPrimitive("7678"), JsonNull)) {
            reject(JsonObject(valid + ("trustedHostMaximumOpenFiles" to bad)))
        }
        val process = valid.getValue("launcherProcess") as JsonObject
        fun withProcess(value: JsonElement) = JsonObject(valid + ("launcherProcess" to value))
        reject(withProcess(JsonNull))
        reject(withProcess(JsonObject(process + ("extra" to JsonPrimitive(1)))))
        for (key in process.keys) {
            reject(withProcess(JsonObject(process - key)))
            for (bad in listOf(JsonNull, JsonPrimitive(true), JsonPrimitive("7678"), JsonPrimitive(1.25))) {
                reject(withProcess(JsonObject(process + (key to bad))))
            }
        }
        for ((key, bad) in listOf("hostPid" to 0L, "startTimeTicks" to 0L, "inheritedHardLimit" to 7677L)) {
            reject(withProcess(JsonObject(process + (key to JsonPrimitive(bad)))))
        }
    }

    @Test
    fun `legacy runtime helper still rejects terminal plus selected or empty visibility`() {
        for (visibility in listOf(visibility(empty = true), visibility(empty = false))) {
            for (interruption in listOf(null, INTERRUPTION_SHA256)) {
                assertFailsWith<IllegalArgumentException> {
                    containedCommandRuntimePolicyFields(interruption, ContainedCommandTerminalResourceEvidence.policySha256, visibility)
                }
            }
        }
    }

    @Test
    fun `full serial runtime preimage retains resources and changes digest with bound declarations`() {
        val selectedRequest = request()
        val selected = runtime(selectedRequest)
        val bytes = containedCommandFileDescriptorRuntimeBytes(selected)
        assertContentEquals(OracleJson.canonicalBytes(selected), bytes)
        assertEquals(resources().json(), selected["resources"])
        assertEquals(JsonPrimitive(selectedRequest.sha256), selected["commandRequestSha256"])
        val legacy = JsonObject(runtimeBase("kotlin-lease-contained-command-runtime-v3") +
            containedCommandRuntimePolicyFields(null, ContainedCommandTerminalResourceEvidence.policySha256, null))
        assertTrue("resources" !in legacy)
        assertNotEquals(hash(legacy), OracleArtifacts.sha256(bytes))
        val changedBudget = runtime(selectedRequest, resources().copy(maximumFileBytes = 16384))
        assertNotEquals(OracleArtifacts.sha256(bytes), OracleArtifacts.sha256(containedCommandFileDescriptorRuntimeBytes(changedBudget)))
        val changedInheritedHard = runtime(selectedRequest, admission = admission(hard = 100_000))
        assertNotEquals(OracleArtifacts.sha256(bytes), OracleArtifacts.sha256(containedCommandFileDescriptorRuntimeBytes(changedInheritedHard)))
        val editedResources = JsonObject(resources().json() + ("maximumOpenFiles" to JsonPrimitive(7677)))
        // Serialization is passive: an edited declaration changes the commitment, not live authority.
        val edited = JsonObject(selected + ("resources" to editedResources))
        assertNotEquals(OracleArtifacts.sha256(bytes), OracleArtifacts.sha256(containedCommandFileDescriptorRuntimeBytes(edited)))
    }

    @Test
    fun `runtime byte serializer requires its closed root and enforces finite bounds`() {
        val value = runtime(request())
        for (key in value.keys) {
            assertFails { containedCommandFileDescriptorRuntimeBytes(JsonObject(value - key)) }
        }
        assertFails { containedCommandFileDescriptorRuntimeBytes(JsonObject(value + ("unexpected" to JsonPrimitive(true)))) }
        assertFails { containedCommandFileDescriptorRuntimeBytes(JsonObject(value + ("provider" to JsonPrimitive("kotlin-lease-contained-command-runtime-v3")))) }
        assertFails {
            containedCommandFileDescriptorRuntimeBytes(JsonObject(value + ("keeperEntryPoint" to JsonPrimitive("x".repeat(65_537)))))
        }
        val overAggregateBound = JsonArray(List(67) { JsonPrimitive("x".repeat(65_536)) })
        assertFails { containedCommandFileDescriptorRuntimeBytes(JsonObject(value + ("runtimeMounts" to overAggregateBound))) }
    }

    @Test
    fun `execution runtime accessor snapshots constructor bytes and returns defensive copies`() {
        val receipt = byteArrayOf(1, 2, 3)
        val runtime = containedCommandFileDescriptorRuntimeBytes(runtime(request()))
        val expectedRuntime = runtime.copyOf()
        val execution = KotlinSystemdCgroupCommandExecution(receipt, runtimeClosureCanonicalBytes = runtime)
        receipt.fill(0)
        runtime.fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), execution.canonicalBytes)
        assertContentEquals(expectedRuntime, execution.runtimeClosureCanonicalBytes)
        execution.canonicalBytes.fill(0)
        checkNotNull(execution.runtimeClosureCanonicalBytes).fill(0)
        assertContentEquals(byteArrayOf(1, 2, 3), execution.canonicalBytes)
        assertContentEquals(expectedRuntime, execution.runtimeClosureCanonicalBytes)
        assertNull(KotlinSystemdCgroupCommandExecution(byteArrayOf(4)).runtimeClosureCanonicalBytes)
    }

    private fun resources(policy: ContainedCommandFileDescriptorPolicy? = POLICY) =
        KotlinSystemdCgroupCommandResources(10_000L, 1024L * 1024 * 1024, 16, 8192, fileDescriptorPolicy = policy)

    private fun observation(soft: Long = 7678, hard: Long = 7678) =
        ContainedCommandFileDescriptorObservation(PID, START, ContainedCommandFileDescriptorLimits(soft, hard))

    private fun admission(hard: Long = 7678) = containedCommandFileDescriptorAdmission(POLICY, observation(512, hard))

    private fun limitsRow() = "Max open files 7678 7678 files\n"

    private fun visibility(empty: Boolean) = ContainedCommandRetainedInputVisibility(ACTIVE, setOf("reports"),
        if (empty) emptyList() else listOf(KotlinContainedCommandRetainedInput("reports/a", 1, NONCE))).canonicalIdentity()

    private fun request(interrupted: Boolean = false, visibility: JsonObject? = null,
        policy: ContainedCommandFileDescriptorPolicy? = POLICY) = KotlinContainedCommandRequest(
        Path.of("/srv/contained/$ACTIVE"), NONCE, listOf("/usr/bin/java", "-version"),
        mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), 10, 10, 1024, 1024,
        allowInterruption = interrupted, terminalResourcePolicySha256 = ContainedCommandTerminalResourceEvidence.policySha256,
        retainedInputVisibilitySha256 = visibility?.let(::hash), fileDescriptorPolicy = policy)

    private fun runtimeBase(provider: String = "kotlin-lease-contained-command-runtime-v5"): Map<String, JsonElement> = mapOf(
        "provider" to JsonPrimitive(provider), "configurationSha256" to JsonPrimitive("c".repeat(64)),
        "deploymentClosureSha256" to JsonPrimitive("d".repeat(64)), "runtimeMounts" to JsonArray(emptyList()),
        "readOnlyInputs" to JsonArray(emptyList()), "keeperEntryPoint" to JsonPrimitive("decompengine.oracle.fulltree.KotlinContainedCommandKeeper"),
        "requestVersion" to JsonPrimitive("contained-command-v1"))

    private fun runtime(request: KotlinContainedCommandRequest, resources: KotlinSystemdCgroupCommandResources = resources(),
        admission: JsonObject = admission()) = JsonObject(runtimeBase() +
        containedCommandFileDescriptorRuntimeFields(request, resources, admission, null, null))

    private fun hash(value: JsonElement) = OracleArtifacts.sha256(OracleJson.canonicalBytes(value))

    private class CountingNames : Iterator<String> {
        var nextCalls = 0
        var hasNextCalls = 0
        override fun hasNext(): Boolean { hasNextCalls++; return true }
        override fun next(): String = (nextCalls++).toString()
    }

    private companion object {
        val POLICY = ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION
        const val POLICY_SHA256 = "b75fa01e0ae402ab7db53e24ede656d0bec06748e27b758296b9f436d1e24d4b"
        const val PID = 123L
        const val START = 456L
        val NONCE = "a".repeat(64)
        val ACTIVE = "control-$NONCE"
        val INTERRUPTION_SHA256 = "b".repeat(64)
    }
}
