package decompengine.oracle.fulltree

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import kotlinx.serialization.json.put
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Order
import org.junit.jupiter.api.MethodOrderer
import org.junit.jupiter.api.TestMethodOrder
import org.junit.jupiter.api.parallel.ResourceLock

/** Actual fixed-slot controls. The root fixture never substitutes for these child Kotlin calls. */
@Tag("ci-live")
@ResourceLock("oracle-ext4-reset-fixture")
@TestMethodOrder(MethodOrderer.OrderAnnotation::class)
class FullTreeDiskScratchResetMountedTest {
    @Test
    @Order(1)
    fun `K01 root private image and raw device deny oracle access`(): Unit = runCase("K01")

    @Test
    @Order(2)
    fun `K02 independent lease children contend and reset preserves live canary`(): Unit = runCase("K02")

    @Test
    @Order(3)
    fun `K03 killed lease child resets to a new admitted generation`(): Unit = runCase("K03")

    @Test
    @Order(4)
    fun `K04 sparse and deep residue resets with bounded work`(): Unit = runCase("K04")

    @Test
    @Order(5)
    fun `K05 byte exhaustion resets to fresh availability`(): Unit = runCase("K05")

    @Test
    @Order(6)
    fun `K06 inode exhaustion resets to fresh availability`(): Unit = runCase("K06")

    @Test
    @Order(7)
    fun `K07 live filesystem descriptors block unmount until holder reap`(): Unit = runCase("K07")

    @Test
    @Order(8)
    fun `K08 hidden mount namespace blocks exclusive format until holder reap`(): Unit = runCase("K08")

    @Test
    @Order(9)
    fun `K09 concurrent service request cannot overlap custodian`(): Unit = runCase("K09")

    @Test
    @Order(10)
    fun `K10 concurrent loop allocation preserves bound slot identity`(): Unit = runCase("K10")

    @Test
    @Order(11)
    fun `K11 killed controller leaves custodian custody intact`(): Unit = runCase("K11")

    @Test
    @Order(12)
    fun `K12 killed custodian leaves live utility fenced by service`(): Unit = runCase("K12")

    @Test
    @Order(13)
    fun `K13 killed formatter retains fence and same intent recovers`(): Unit = runCase("K13")

    @Test
    @Order(14)
    fun `K14 killed custodian after intent fsync reconciles safely`(): Unit = runCase("K14")

    @Test
    @Order(15)
    fun `K15 killed custodian after gate close reconciles safely`(): Unit = runCase("K15")

    @Test
    @Order(16)
    fun `K16 killed custodian after mount move reconciles safely`(): Unit = runCase("K16")

    @Test
    @Order(17)
    fun `K17 killed custodian after unmount reconciles safely`(): Unit = runCase("K17")

    @Test
    @Order(18)
    fun `K18 killed custodian after format started commit reconciles safely`(): Unit = runCase("K18")

    @Test
    @Order(19)
    fun `K19 killed custodian after format exit and flush reconciles safely`(): Unit = runCase("K19")

    @Test
    @Order(20)
    fun `K20 killed custodian after ready rename reconciles safely`(): Unit = runCase("K20")

    @Test
    @Order(21)
    fun `K21 killed broker before gate open publishes only candidate`(): Unit = runCase("K21")

    @Test
    @Order(22)
    fun `K22 mount replacement during recovery preserves alien canary`(): Unit = runCase("K22")

    @Test
    @Order(23)
    fun `K23 visible alias and nested mount preserve alien state`(): Unit = runCase("K23")

    @Test
    @Order(24)
    fun `K24 backing image replacement preserves both identities`(): Unit = runCase("K24")

    @Test
    @Order(25)
    fun `K25 state anchor and generation replacement preserve alien content`(): Unit = runCase("K25")

    @Test
    @Order(26)
    fun `K26 quarantined lease residue resets through independent controller`(): Unit = runCase("K26")

    @Test
    @Order(27)
    fun `K27 empty recorded filesystem resets and missing registration refuses`(): Unit = runCase("K27")

    @Test
    @Order(28)
    fun `K28 formatter trace proves exclusive open before device mutations`(): Unit = runCase("K28")

    @Test
    @Order(29)
    fun `K29 timeout retains fence until cgroup absence`(): Unit = runCase("K29")

    @Test
    @Order(100)
    fun `K30 teardown refuses alien replacement then removes only owned fixture`(): Unit = runCase("K30")

    @Test
    @Order(31)
    fun `K31 killed broker after gate open preserves admitted lease canary`(): Unit = runCase("K31")

    @Test
    @Order(32)
    fun `K32 killed custodian after candidate mount reconciles exact private target`(): Unit = runCase("K32")

    private fun runCase(caseId: String) {
        val configured = System.getenv("DECOMP_TEST_ORACLE_EXT4_RESET_HELPER")
        if (System.getenv("DECOMP_REQUIRE_ORACLE_EXT4_RESET") == "true") {
            assertTrue(!configured.isNullOrBlank(), "required hosted reset fixture missing")
        }
        assumeTrue(!configured.isNullOrBlank(), "requires the separate finite hosted reset fixture")
        val fixture = Fixture(caseId, Path.of(checkNotNull(configured)))
        var failure: Throwable? = null
        try {
            fixture.prepare()
            when (caseId) {
                "K01" -> {
                    fixture.oneShot("access", "access-denied")
                    fixture.exercise()
                }
                "K02" -> {
                    val held = fixture.probe("hold-canary")
                    held.read("ready")
                    fixture.oneShot("expect-refusal", "acquisition-refused")
                    val refusal = fixture.exercise()
                    assertEquals("refused", refusal.string("outcome"))
                    assertSnapshotUnchanged(refusal.obj("before"), refusal.obj("after"))
                    held.command("CHECK", "checked")
                    held.command("CLEAN", "clean-released")
                    held.awaitSuccess()
                    fixture.resume()
                }
                "K03", "K04", "K05", "K06", "K26" -> {
                    val mode = mapOf("K03" to "active", "K04" to "sparse-deep", "K05" to "bytes-full", "K06" to "inodes-full", "K26" to "quarantine").getValue(caseId)
                    val child = fixture.probe(mode)
                    val ready = child.read("ready")
                    when (caseId) {
                        "K04" -> {
                            assertEquals(1L shl 40, ready.number("sparseLogicalBytes"))
                            assertEquals(512L, ready.number("directoryDepth"))
                        }
                        "K05" -> assertEquals(0L, ready.number("availableBytes"))
                        "K06" -> assertEquals(0L, ready.number("availableInodes"))
                        "K26" -> assertEquals("release-after-quarantine-parent-sync", ready.string("barrier"))
                    }
                    child.killAndReap()
                    fixture.exercise()
                }
                "K31" -> {
                    val prepared = fixture.exercise()
                    assertEquals("prepared", prepared.string("outcome"))
                    val child = fixture.probe("hold-canary", prepared.obj("after").string("scratch"))
                    val ready = child.read("ready")
                    val first = child.command("CHECK", "checked")
                    assertEquals(ready.string("canarySha256"), first.string("canarySha256"))
                    fixture.resume()
                    val second = child.command("CHECK", "checked")
                    assertEquals(ready.string("canarySha256"), second.string("canarySha256"))
                    assertEquals(ready.getValue("leaseEvidence"), second.getValue("leaseEvidence"))
                    child.command("CLEAN", "clean-released")
                    child.awaitSuccess()
                }
                else -> fixture.exercise()
            }
            if (caseId !in setOf("K01", "K30")) {
                val after = fixture.last.obj("after")
                assertEquals("reset", fixture.last.string("outcome"))
                fixture.oneShot("admit-clean", "admitted-clean", after.string("scratch"))
            }
        } catch (caught: Throwable) {
            failure = caught
            throw caught
        } finally {
            try {
                fixture.finish()
            } catch (cleanupFailure: Throwable) {
                if (failure == null) throw cleanupFailure
                failure.addSuppressed(cleanupFailure)
            }
        }
    }

    private class Fixture(val caseId: String, val helper: Path) {
        val evidence = Path.of("build/issue933-evidence").toAbsolutePath().normalize().also(Files::createDirectories)
        private val events = mutableListOf<JsonElement>()
        private val kills = mutableListOf<JsonElement>()
        private val children = mutableListOf<Probe>()
        private var prepared = false
        lateinit var sessionToken: String
        lateinit var loopNode: String
        lateinit var initial: JsonObject
        lateinit var last: JsonObject

        init {
            assertEquals(Path.of("scripts/ci-oracle-ext4-reset.py").toAbsolutePath().normalize(), helper)
            assertEquals(helper, helper.toRealPath())
        }

        fun prepare() {
            val result = action("prepare-case")
            sessionToken = result.string("sessionToken")
            assertTrue(sessionToken.matches(HEX256))
            assertEquals(65534L, result.number("oracleUid"))
            assertEquals(65534L, result.number("oracleGid"))
            loopNode = result.string("loopNode")
            assertTrue(loopNode.matches(Regex("/dev/loop[0-9]{1,6}")))
            initial = result.obj("before")
            assertEquals(initial, result.obj("after"))
            validateSnapshot(initial)
            last = result
            prepared = true
        }

        fun exercise(): JsonObject = action("exercise").also { last = it }
        fun resume(): JsonObject = action("resume-case").also { last = it }

        fun probe(mode: String, scratch: String = initial.string("scratch"), extraArguments: List<String> = emptyList()): Probe {
            assertTrue(extraArguments.isEmpty() || mode == "kill-owned" && extraArguments.size == 2)
            assertTrue(scratch.matches(SCRATCH))
            val temp = Files.createTempDirectory(evidence, "$caseId-probe-tmp-")
            Files.setPosixFilePermissions(temp, PosixFilePermissions.fromString("rwxrwxrwx"))
            val output = Files.createTempFile(evidence, "$caseId-$mode-", ".stdout")
            val error = Files.createTempFile(evidence, "$caseId-$mode-", ".stderr")
            val command = droppedPrincipalCommand() + listOf(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(),
                "-Xmx128m", "-XX:-UsePerfData", "-XX:ErrorFile=$temp/hs_err_pid%p.log",
                "-Duser.home=$temp", "-Djava.io.tmpdir=$temp", "-Djna.tmpdir=$temp",
                "-classpath", materializedClasspath(evidence), FullTreeDiskScratchResetProbe::class.java.name,
                caseId, sessionToken, mode, scratch, loopNode,
            ) + extraArguments
            val builder = ProcessBuilder(command).directory(evidence.toFile())
                .redirectOutput(output.toFile()).redirectError(error.toFile())
            builder.environment().clear()
            builder.environment().putAll(mapOf("PATH" to "/usr/bin:/bin", "LANG" to "C", "LC_ALL" to "C", "TMPDIR" to temp.toString()))
            return Probe(builder.start(), output, error, mode, scratch).also(children::add)
        }

        fun oneShot(mode: String, event: String, scratch: String = initial.string("scratch")) {
            val child = probe(mode, scratch)
            child.read(event)
            child.awaitSuccess()
        }

        fun finish() {
            var failure: Throwable? = null
            for (child in children.toList()) {
                if (child.process.isAlive) {
                    try { child.killAndReap() } catch (caught: Throwable) {
                        if (failure == null) failure = caught else failure.addSuppressed(caught)
                    }
                }
            }
            if (!prepared) {
                failure?.let { throw it }
                return
            }
            val cases = evidence.resolve("cases").also(Files::createDirectories)
            val probeReport = buildJsonObject {
                put("schemaVersion", 1)
                put("caseId", caseId)
                put("sessionToken", sessionToken)
                put("events", JsonArray(events))
                put("kills", JsonArray(kills))
            }
            val probeBytes = (canonical(probeReport) + "\n").toByteArray()
            assertTrue(probeBytes.size <= 128 * 1024)
            Files.write(cases.resolve("$caseId-probe.json"), probeBytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            val raw = invoke("finish-case", maximumBytes = 64 * 1024)
            val receipt = parseReply(raw)
            Files.write(cases.resolve("$caseId.json"), raw, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            val artifacts = receipt.getValue("artifacts").jsonArray
            assertEquals(ARTIFACTS, artifacts.map { it.jsonObject.string("name") }.toSet())
            assertEquals(4, artifacts.size)
            val directory = evidence.resolve("raw").resolve(caseId).also(Files::createDirectories)
            artifacts.forEach { element ->
                val entry = element.jsonObject
                val name = entry.string("name")
                assertEquals("raw/$caseId/$name", entry.string("path"))
                val maximum = if (name == "formatter.trace") 1024 * 1024 else 64 * 1024
                val bytes = invoke("artifact", name, maximum)
                assertEquals(entry.number("bytes"), bytes.size.toLong())
                assertEquals(entry.string("sha256"), sha256(bytes))
                Files.write(directory.resolve(name), bytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
            }
            validateReceipt(receipt)
            failure?.let { throw it }
        }

        private fun action(name: String): JsonObject = parseReply(invoke(name, maximumBytes = 64 * 1024))

        private fun parseReply(raw: ByteArray): JsonObject {
            val result = Json.parseToJsonElement(raw.toString(Charsets.UTF_8)).jsonObject
            assertEquals(1L, result.number("schemaVersion"))
            assertEquals(caseId, result.string("caseId"))
            if (prepared) assertEquals(sessionToken, result.string("sessionToken"))
            return result
        }

        private fun invoke(action: String, artifact: String? = null, maximumBytes: Int): ByteArray {
            assertTrue(action in setOf("prepare-case", "exercise", "resume-case", "finish-case", "artifact"))
            assertTrue(artifact == null || action == "artifact" && artifact in ARTIFACTS)
            val stdout = Files.createTempFile(evidence, "$caseId-$action-", ".stdout")
            val stderr = Files.createTempFile(evidence, "$caseId-$action-", ".stderr")
            val command = listOf("sudo", "-n", "python3", "-I", "-S", helper.toString(), action, caseId) + listOfNotNull(artifact)
            val process = ProcessBuilder(command).redirectOutput(stdout.toFile()).redirectError(stderr.toFile()).start()
            val exited = process.waitFor(150, TimeUnit.SECONDS)
            if (!exited) {
                process.destroyForcibly()
                process.waitFor(5, TimeUnit.SECONDS)
            }
            assertTrue(exited, "finite fixture $caseId/$action timed out; reservation must remain held")
            assertTrue(Files.size(stdout) <= maximumBytes && Files.size(stderr) <= 32 * 1024)
            assertEquals(0, process.exitValue(), "$caseId/$action failed: ${Files.readString(stderr)}")
            return Files.readAllBytes(stdout)
        }

        private fun validateReceipt(receipt: JsonObject) {
            val expected = when (caseId) { "K01" -> "refused"; "K30" -> "teardown"; else -> "reset" }
            assertEquals(expected, receipt.string("outcome"))
            val before = receipt.obj("before")
            val after = receipt.obj("after")
            validateSnapshot(before)
            validateSnapshot(after, allowUnmounted = caseId == "K30")
            if (expected == "reset") {
                for (key in listOf("loopRdev", "imageDevice", "imageInode", "imageBytes")) assertEquals(before[key], after[key], key)
                assertEquals(before.string("generation").toBigInteger() + java.math.BigInteger.ONE, after.string("generation").toBigInteger())
                assertNotEquals(before.string("filesystemUuid"), after.string("filesystemUuid"))
                assertNotEquals(before.string("scratch"), after.string("scratch"))
                assertEquals("PUBLISHED", after.string("phase"))
                assertEquals(457L, after.number("gateMode"))
                assertTrue(after.number("availableBytes") > 0 && after.number("availableInodes") >= 4)
            }
            val observations = receipt.obj("observations")
            observations.getValue("canaries").jsonArray.forEach { value ->
                val canary = value.jsonObject
                assertTrue(canary.string("beforeSha256").matches(HEX256))
                assertEquals(canary.string("beforeSha256"), canary.string("afterSha256"))
            }
            if (caseId in setOf("K07", "K08", "K22", "K23", "K24", "K25", "K30")) {
                assertTrue(observations.getValue("canaries").jsonArray.isNotEmpty())
                assertTrue(observations.getValue("attempts").jsonArray.any { it.jsonObject.number("exitCode") != 0L })
            }
            if (caseId in DEATH_CASES) {
                assertTrue(observations.getValue("deaths").jsonArray.isNotEmpty())
                observations.getValue("deaths").jsonArray.forEach { value ->
                    val death = value.jsonObject
                    assertEquals(9L, death.number("signal"))
                    assertTrue(death.getValue("reaped").jsonPrimitive.boolean)
                    assertTrue(death.number("pid") > 1 && death.number("startTicks") > 0)
                    assertTrue(death.string("barrier").isNotEmpty())
                }
            }
            if (caseId == "K04") {
                val facts = observations.obj("facts")
                assertEquals(0L, facts.number("oldTreeEntriesVisited"))
                assertEquals(0L, facts.number("oldContentBytesRead"))
                assertTrue(facts.number("mutatorCount") > 0)
            }
            if (caseId == "K10") assertNotEquals(before.number("loopRdev"), observations.obj("facts").number("allocatedLoopRdev"))
            if (caseId in setOf("K08", "K28")) {
                val trace = observations.obj("trace")
                assertTrue(!trace.getValue("truncated").jsonPrimitive.boolean)
                assertEquals(0L, trace.number("mutationsBeforeExclusiveOpen"))
                if (caseId == "K08") {
                    assertEquals("EBUSY", trace.string("exclusiveOpenErrno"))
                    assertEquals(0L, trace.number("deviceMutationCount"))
                } else {
                    val flags = trace.getValue("exclusiveOpenFlags").jsonArray.map { it.jsonPrimitive.content }
                    assertTrue("O_RDWR" in flags && "O_EXCL" in flags)
                    assertTrue(trace.number("deviceMutationCount") > 0)
                }
            }
        }

        inner class Probe(val process: Process, private val output: Path, private val error: Path, private val mode: String, private val scratch: String) {
            private var offset = 0
            private var pid: Long? = null
            private var start: Long? = null

            fun read(expected: String, record: Boolean = true): JsonObject {
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(35)
                while (System.nanoTime() < deadline) {
                    assertTrue(Files.size(output) <= 128 * 1024 && Files.size(error) <= 32 * 1024)
                    val bytes = Files.readAllBytes(output)
                    val end = (offset until bytes.size).firstOrNull { bytes[it] == '\n'.code.toByte() }
                    if (end != null) {
                        assertTrue(end - offset <= 16 * 1024)
                        val event = Json.parseToJsonElement(bytes.copyOfRange(offset, end).toString(Charsets.UTF_8)).jsonObject
                        offset = end + 1
                        assertEquals(1L, event.number("schemaVersion"))
                        assertEquals(caseId, event.string("caseId"))
                        assertEquals(sessionToken, event.string("sessionToken"))
                        assertEquals(mode, event.string("mode"))
                        assertEquals(expected, event.string("event"))
                        assertEquals(scratch, event.string("scratch"))
                        assertEquals(65534L, event.number("uid"))
                        assertEquals(65534L, event.number("gid"))
                        pid?.let { assertEquals(it, event.number("pid")) }
                        start?.let { assertEquals(it, event.number("startTicks")) }
                        pid = event.number("pid")
                        start = event.number("startTicks")
                        assertTrue(checkNotNull(pid) > 1 && checkNotNull(start) > 0)
                        if (record) events += event
                        return event
                    }
                    assertTrue(process.isAlive, "probe $mode exited before $expected: ${Files.readString(error)}")
                    Thread.sleep(10)
                }
                error("probe $mode failed to produce bounded event $expected")
            }

            fun command(command: String, expected: String): JsonObject {
                assertTrue(command in setOf("CHECK", "CLEAN"))
                process.outputStream.write("$command\n".toByteArray())
                process.outputStream.flush()
                return read(expected)
            }

            fun awaitSuccess() {
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "probe failed to exit")
                assertEquals(0, process.exitValue(), Files.readString(error))
                assertEquals(offset.toLong(), Files.size(output), "unexpected additional probe output")
            }

            fun killAndReap() {
                assertTrue(process.isAlive, "owned probe exited before requested SIGKILL")
                val childPid = checkNotNull(pid) { "probe was not authenticated before requested SIGKILL" }
                val childStart = checkNotNull(start)
                val stat = Files.readString(Path.of("/proc/$childPid/stat"))
                assertEquals(childStart, stat.substring(stat.lastIndexOf(')') + 2).split(' ')[19].toLong())
                assertTrue(process.pid() == childPid || process.descendants().use { stream -> stream.anyMatch { it.pid() == childPid } })
                val killer = probe("kill-owned", scratch, listOf(childPid.toString(), childStart.toString()))
                val sent = killer.read("signal-sent", record = false)
                assertEquals(childPid, sent.number("targetPid"))
                assertEquals(childStart, sent.number("targetStartTicks"))
                assertEquals(9L, sent.number("signal"))
                killer.awaitSuccess()
                assertTrue(process.waitFor(10, TimeUnit.SECONDS), "killed probe was not reaped")
                assertEquals(137, process.exitValue(), "probe did not terminate from SIGKILL")
                kills += buildJsonObject {
                    put("pid", childPid); put("startTicks", childStart); put("signal", 9); put("exitCode", process.exitValue())
                }
            }
        }
    }

    companion object {
        private val HEX256 = Regex("[0-9a-f]{64}")
        private val SCRATCH = Regex("/var/lib/decomp-oracle-ext4-reset-ci/public/g-[0-9a-f]{16}/scratch")
        private val ARTIFACTS = setOf("formatter.trace", "events.json", "manifest.json", "service.properties")
        private val DEATH_CASES = (11..21).map { "K%02d".format(it) }.toSet() + setOf("K31", "K32")
        private var stagedClasspath: String? = null

        private fun droppedPrincipalCommand() = listOf("sudo", "-n", "/usr/bin/setpriv", "--reuid=65534", "--regid=65534", "--clear-groups", "--no-new-privs", "--bounding-set=-all")
        private fun JsonObject.string(key: String) = getValue(key).jsonPrimitive.content
        private fun JsonObject.number(key: String) = getValue(key).jsonPrimitive.long
        private fun JsonObject.obj(key: String) = getValue(key).jsonObject
        private fun sha256(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
        private fun canonical(value: JsonElement): String = when (value) {
            is JsonObject -> value.entries.sortedBy { it.key }.joinToString(",", "{", "}") { JsonPrimitive(it.key).toString() + ":" + canonical(it.value) }
            is JsonArray -> value.joinToString(",", "[", "]") { canonical(it) }
            else -> value.toString()
        }
        private fun validateSnapshot(value: JsonObject, allowUnmounted: Boolean = false) {
            assertTrue(value.string("generation").matches(Regex("[0-9]{1,20}")))
            assertTrue(value.string("scratch").matches(SCRATCH))
            assertTrue(value.string("filesystemUuid").matches(Regex("[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")))
            assertEquals(67_108_864L, value.number("imageBytes"))
            if (allowUnmounted) {
                assertEquals("RESERVED_UNMOUNTED", value.string("phase"))
                for (key in listOf("mountId", "gateMode", "availableBytes", "availableInodes")) assertEquals(0L, value.number(key))
            } else assertTrue(value.number("mountId") > 0)
            assertTrue(value.number("availableBytes") in 0L..67_108_864L && value.number("availableInodes") in 0L..4096L)
        }
        private fun assertSnapshotUnchanged(before: JsonObject, after: JsonObject) {
            for (key in listOf("generation", "filesystemUuid", "scratch", "gateMode", "mountId", "loopRdev", "imageDevice", "imageInode", "imageBytes")) assertEquals(before[key], after[key], key)
        }

        @Synchronized
        private fun materializedClasspath(evidence: Path): String {
            stagedClasspath?.let { return it }
            val root = Files.createTempDirectory(evidence, "probe-classpath-")
            Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"))
            val mainRoot = Path.of(FullTreeDiskScratchAuthority::class.java.protectionDomain.codeSource.location.toURI())
            val testRoot = Path.of(FullTreeDiskScratchResetProbe::class.java.protectionDomain.codeSource.location.toURI())
            assertTrue(Files.isDirectory(mainRoot) && Files.isDirectory(testRoot))
            var totalBytes = 0L
            var totalFiles = 0
            fun copy(source: Path, target: Path) {
                assertTrue(!Files.isSymbolicLink(source) && Files.isRegularFile(source, LinkOption.NOFOLLOW_LINKS))
                totalBytes += Files.size(source)
                totalFiles++
                assertTrue(totalBytes <= 512L * 1024 * 1024 && totalFiles <= 100_000)
                Files.createDirectories(target.parent)
                var directory = target.parent
                while (directory.startsWith(root)) {
                    Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwxr-xr-x"))
                    if (directory == root) break
                    directory = directory.parent
                }
                Files.copy(source, target, StandardCopyOption.COPY_ATTRIBUTES)
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-r--r--"))
            }
            val main = root.resolve("main")
            Files.walk(mainRoot).use { paths -> paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach { copy(it, main.resolve(mainRoot.relativize(it))) } }
            val test = root.resolve("test")
            val packagePath = Path.of("decompengine/oracle/fulltree")
            Files.list(testRoot.resolve(packagePath)).use { paths ->
                paths.filter { it.fileName.toString().startsWith("FullTreeDiskScratchResetProbe") && it.fileName.toString().endsWith(".class") }
                    .forEach { copy(it, test.resolve(packagePath).resolve(it.fileName)) }
            }
            val libraries = listOf(kotlin.Unit::class.java, kotlinx.serialization.KSerializer::class.java, Json::class.java, com.sun.jna.Native::class.java, kotlinx.coroutines.Job::class.java)
                .map { Path.of(it.protectionDomain.codeSource.location.toURI()) }.distinct()
            val jars = libraries.mapIndexed { index, source ->
                assertTrue(source.fileName.toString().endsWith(".jar"))
                root.resolve("dependency-$index.jar").also { copy(source, it) }
            }
            var ancestor: Path? = evidence
            while (ancestor != null) {
                assertTrue(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE in Files.getPosixFilePermissions(ancestor), "probe classpath ancestor is not readable by oracle UID: $ancestor")
                ancestor = ancestor.parent
            }
            return (listOf(main, test) + jars).joinToString(java.io.File.pathSeparator).also { stagedClasspath = it }
        }
    }
}
