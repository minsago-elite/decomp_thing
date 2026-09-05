package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.File
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class KotlinContainedCommandKeeperTest {
    @Test
    fun `interruption is versioned opt in and cannot be replayed as START or successful completion`() {
        val legacy = request()
        val admitted = request(allowInterruption = true)
        val key = secret()
        assertFalse(legacy.allowInterruption)
        assertTrue(KotlinContainedCommandRequest.parse(admitted.canonicalBytes).allowInterruption)
        assertContentEquals(legacy.canonicalBytes, KotlinContainedCommandRequest.parse(legacy.canonicalBytes).canonicalBytes)
        assertNotEquals(legacy.sha256, admitted.sha256)
        val wire = document(admitted.canonicalBytes)
        assertEquals(JsonPrimitive(2), wire["schemaVersion"])
        for (value in listOf(JsonPrimitive(false), JsonPrimitive("true"), JsonPrimitive(1))) {
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(replace(wire, "allowInterruption", value)) }
        }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(OracleJson.canonicalBytes(JsonObject(wire - "allowInterruption"))) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(replace(document(legacy.canonicalBytes), "allowInterruption", JsonPrimitive(true))) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.interrupt(key, legacy, 123L) }
        val stop = KotlinContainedCommandProtocol.interrupt(key, admitted, 123L)
        KotlinContainedCommandProtocol.requireInterrupt(stop, key, admitted, 123L)
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireInterrupt(stop, key, legacy, 123L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireInterrupt(stop, key, admitted, 124L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireInterrupt(stop, ByteArray(32), admitted, 123L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireInterrupt(stop, key, request(nonce = "b".repeat(64), allowInterruption = true), 123L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(stop, key, admitted, 123L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(stop, key, admitted, 123L) }
        val start = KotlinContainedCommandProtocol.start(key, admitted, 123L)
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireInterrupt(start, key, admitted, 123L) }
        val interrupted = outcome().copy(status = "INTERRUPTED", exitCode = 137)
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.outcome(key, legacy, interrupted) }
        val parsed = KotlinContainedCommandProtocol.requireOutcome(KotlinContainedCommandProtocol.outcome(key, admitted, interrupted), key, admitted, 123L)
        assertEquals(interrupted, parsed)
        assertFailsWith<IllegalArgumentException> { parsed.requireSuccessful() }
    }

    @Test
    fun `local noncontainment keeper reaps an authored waiting child after authenticated interruption`() {
        withLocalKeeper(waitingChild = true) { process, request, secret ->
            val boot = awaitLocalProtocol(process, request.runDirectory, KotlinContainedCommandProtocol.BOOT_FILE)
            val keeper = KotlinContainedCommandProtocol.requireBoot(boot, secret, request)
            publishLocalStart(request, KotlinContainedCommandProtocol.start(secret, request, keeper))
            awaitLocalProtocol(process, request.runDirectory, "reports/child-ready")
            publishLocalStart(request, KotlinContainedCommandProtocol.interrupt(secret, request, keeper), KotlinContainedCommandProtocol.INTERRUPT_FILE)
            val bytes = awaitLocalProtocol(process, request.runDirectory, KotlinContainedCommandProtocol.OUTCOME_FILE)
            val outcome = KotlinContainedCommandProtocol.requireOutcome(bytes, secret, request, keeper)
            assertEquals("INTERRUPTED", outcome.status)
            assertFailsWith<IllegalArgumentException> { outcome.requireSuccessful() }
            assertTrue(process.isAlive)
            assertFalse(process.descendants().use { it.findAny().isPresent })
        }
    }

    @Test
    fun `local noncontainment keeper rejects a forged interruption and emits no accepted outcome`() {
        withLocalKeeper(waitingChild = true) { process, request, secret ->
            val boot = awaitLocalProtocol(process, request.runDirectory, KotlinContainedCommandProtocol.BOOT_FILE)
            val keeper = KotlinContainedCommandProtocol.requireBoot(boot, secret, request)
            publishLocalStart(request, KotlinContainedCommandProtocol.start(secret, request, keeper))
            awaitLocalProtocol(process, request.runDirectory, "reports/child-ready")
            val child = process.descendants().use { it.toList() }.single()
            publishLocalStart(request, KotlinContainedCommandProtocol.interrupt(ByteArray(32), request, keeper), KotlinContainedCommandProtocol.INTERRUPT_FILE)
            assertTrue(process.waitFor(10L, TimeUnit.SECONDS))
            assertEquals(126, process.exitValue())
            assertFalse(child.isAlive)
            assertTrue(Files.notExists(request.runDirectory.resolve(KotlinContainedCommandProtocol.OUTCOME_FILE)))
        }
    }

    @Test
    fun `local noncontainment keeper starts known Java only after authenticated START and retains after its exit`() {
        withLocalKeeper { process, request, secret ->
            val boot = awaitLocalProtocol(process, request.runDirectory, KotlinContainedCommandProtocol.BOOT_FILE)
            val keeperPid = KotlinContainedCommandProtocol.requireBoot(boot, secret, request)
            assertEquals(process.pid(), keeperPid)
            repeat(5) {
                assertTrue(process.isAlive)
                assertFalse(process.descendants().use { it.findAny().isPresent }, "local keeper spawned before START")
                assertTrue(Files.notExists(request.runDirectory.resolve(KotlinContainedCommandProtocol.OUTCOME_FILE)))
                assertTrue(Files.newDirectoryStream(request.runDirectory.resolve("reports")).use { !it.iterator().hasNext() })
                Thread.sleep(25L)
            }
            publishLocalStart(request, KotlinContainedCommandProtocol.start(secret, request, keeperPid))
            val bytes = awaitLocalProtocol(process, request.runDirectory, KotlinContainedCommandProtocol.OUTCOME_FILE)
            val outcome = KotlinContainedCommandProtocol.requireOutcome(bytes, secret, request, keeperPid)
            outcome.requireSuccessful()
            assertEquals(0, outcome.exitCode)
            assertTrue(outcome.childPid > 0 && outcome.childPid != keeperPid)
            assertTrue(outcome.stderrBytes > 0L, "known Java -version did not produce its version diagnostic")
            assertEquals(outcome.stdoutBytes, Files.size(request.runDirectory.resolve("reports/${KotlinContainedCommandProtocol.STDOUT_FILE}")))
            assertEquals(outcome.stderrBytes, Files.size(request.runDirectory.resolve("reports/${KotlinContainedCommandProtocol.STDERR_FILE}")))
            assertTrue(Files.readString(request.runDirectory.resolve("reports/${KotlinContainedCommandProtocol.STDERR_FILE}")).contains("version"))
            assertTrue(process.isAlive, "keeper did not remain for host observation")
            assertFalse(process.descendants().use { it.findAny().isPresent }, "known child remained after authenticated exit")
            assertFalse(process.waitFor(100L, TimeUnit.MILLISECONDS), "local keeper exited before explicit test cleanup")
        }
    }

    @Test
    fun `local noncontainment keeper rejects forged START without spawning known Java or publishing an outcome`() {
        withLocalKeeper { process, request, secret ->
            val boot = awaitLocalProtocol(process, request.runDirectory, KotlinContainedCommandProtocol.BOOT_FILE)
            val keeperPid = KotlinContainedCommandProtocol.requireBoot(boot, secret, request)
            val wrongSecret = secret.copyOf().also { it[0] = (it[0].toInt() xor 255).toByte() }
            publishLocalStart(request, KotlinContainedCommandProtocol.start(wrongSecret, request, keeperPid))
            assertTrue(process.waitFor(10L, TimeUnit.SECONDS), "forged START did not fail within its test bound")
            assertEquals(126, process.exitValue())
            assertTrue(Files.notExists(request.runDirectory.resolve(KotlinContainedCommandProtocol.OUTCOME_FILE)))
            assertTrue(Files.notExists(request.runDirectory.resolve("supervisor.worker-exited")))
            assertTrue(Files.newDirectoryStream(request.runDirectory.resolve("reports")).use { !it.iterator().hasNext() })
            assertContentEquals(boot, Files.readAllBytes(request.runDirectory.resolve(KotlinContainedCommandProtocol.BOOT_FILE)))
            assertContentEquals(request.canonicalBytes, Files.readAllBytes(request.runDirectory.resolve("runtime/${KotlinContainedCommandRequest.REQUEST_FILE}")))
        }
    }

    @Test
    fun `request snapshots exact argv environment and canonical bytes without consulting output inodes`() {
        val command = mutableListOf("/usr/bin/java", "-version")
        val environment = linkedMapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC")
        val request = request(command = command, environment = environment)
        val expected = request.canonicalBytes
        command[1] = "-help"
        environment["JAVA_TOOL_OPTIONS"] = "-javaagent:/untrusted.jar"
        request.canonicalBytes.fill(0)
        assertEquals(listOf("/usr/bin/java", "-version"), request.command)
        assertEquals(mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"), request.environment)
        assertContentEquals(expected, request.canonicalBytes)
        assertContentEquals(expected, KotlinContainedCommandRequest.parse(expected).canonicalBytes)
        assertEquals(OracleArtifacts.sha256(expected), request.sha256)
        val document = document(expected)
        assertEquals(setOf("schemaVersion", "provider", "runDirectory", "nonce", "command", "environment",
            "maximumStartWaitSeconds", "maximumWallSeconds", "maximumStdoutBytes", "maximumStderrBytes"), document.keys)
        assertFalse(document.keys.any { it.contains("inode", ignoreCase = true) || it.contains("secret", ignoreCase = true) })
        assertFailsWith<UnsupportedOperationException> { (request.command as MutableList<String>).add("injected") }
        assertFailsWith<UnsupportedOperationException> { (request.environment as MutableMap<String, String>)["TZ"] = "GMT" }
    }

    @Test
    fun `request rejects unsafe paths nonjava executables and command byte or count overflow`() {
        for (path in listOf("relative", "/", "/srv/run/../other", "/srv/ ", "/srv/back\\slash", "/srv/colon:path", "/srv/new\nline")) {
            assertFailsWith<IllegalArgumentException>(path) { request(root = Path.of(path)) }
        }
        for (command in listOf(emptyList(), listOf("/usr/bin/java"), listOf("/bin/sh", "-c", "true"),
            listOf("java", "-version"), listOf("/srv/contained-run/java", "-version"),
            listOf("/usr/bin/../bin/java", "-version"), listOf("/usr/bin/java", ""),
            listOf("/usr/bin/java", "bad\u0000argument"), listOf("/usr/bin/java", "bad\nargument"),
            listOf("/usr/bin/java", "x".repeat(65536)), List(513) { "/usr/bin/java" })) {
            assertFailsWith<IllegalArgumentException> { request(command = command) }
        }
        val large = request(command = listOf("/usr/bin/java", "x".repeat(60000)))
        assertTrue(large.canonicalBytes.size > 16384)
        assertContentEquals(large.canonicalBytes, KotlinContainedCommandRequest.parse(large.canonicalBytes).canonicalBytes)
    }

    @Test
    fun `request requires exact environment and finite budgets`() {
        val environment = request().environment
        for (name in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "LD_PRELOAD", "HOME", "TMPDIR")) {
            assertFailsWith<IllegalArgumentException>(name) { request(environment = environment + (name to "injected")) }
        }
        assertFailsWith<IllegalArgumentException> { request(environment = environment - "TZ") }
        assertFailsWith<IllegalArgumentException> { request(environment = environment + ("LANG" to "C")) }
        for (value in listOf(0L, -1L, 301L, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { request(startSeconds = value) }
        }
        for (value in listOf(0L, -1L, 86401L, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { request(wallSeconds = value) }
        }
        for (value in listOf(0L, -1L, 64L * 1024 * 1024 + 1L, Long.MAX_VALUE)) {
            assertFailsWith<IllegalArgumentException> { request(stdoutBytes = value) }
            assertFailsWith<IllegalArgumentException> { request(stderrBytes = value) }
        }
        request(startSeconds = 300L, wallSeconds = 86400L, stdoutBytes = 64L * 1024 * 1024, stderrBytes = 64L * 1024 * 1024)
    }

    @Test
    fun `request raw parser rejects unknown missing duplicate noncanonical and mistyped fields`() {
        val canonical = request().canonicalBytes
        val original = document(canonical)
        for ((name, value) in listOf(
            "extra" to JsonPrimitive(true), "schemaVersion" to JsonPrimitive(2),
            "schemaVersion" to JsonPrimitive("1"), "provider" to JsonPrimitive("kotlin-boot-v1"),
            "maximumWallSeconds" to JsonPrimitive("30"), "maximumWallSeconds" to JsonPrimitive(-1),
            "maximumWallSeconds" to JsonPrimitive("18446744073709551616"),
            "command" to JsonArray(listOf(JsonPrimitive(1), JsonPrimitive("-version"))),
            "nonce" to JsonPrimitive("A".repeat(64)),
        )) {
            assertFailsWith<IllegalArgumentException>(name) { KotlinContainedCommandRequest.parse(replace(original, name, value)) }
        }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(OracleJson.canonicalBytes(JsonObject(original - "nonce"))) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(canonical + byteArrayOf(10)) }
        val duplicate = canonical.toString(Charsets.UTF_8).replaceFirst("{", "{\"schemaVersion\":1,")
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandRequest.parse(duplicate.toByteArray()) }
        assertFailsWith<IllegalArgumentException> {
            KotlinContainedCommandRequest.parse(ByteArray(KotlinContainedCommandRequest.MAXIMUM_REQUEST_BYTES + 1) { 32 })
        }
    }

    @Test
    fun `each command binding changes the immutable request identity`() {
        val original = request()
        val alternatives = listOf(request(root = Path.of("/srv/other-run")), request(nonce = "b".repeat(64)),
            request(command = listOf("/usr/bin/java", "-help")), request(startSeconds = 31), request(wallSeconds = 31),
            request(stdoutBytes = 4097), request(stderrBytes = 4097))
        for (alternative in alternatives) assertNotEquals(original.sha256, alternative.sha256)
        assertEquals(alternatives.size, alternatives.map { it.sha256 }.toSet().size)
    }

    @Test
    fun `authenticated BOOT START and outcome bind exact host request and keeper identity`() {
        val request = request()
        val secret = secret()
        val boot = KotlinContainedCommandProtocol.boot(secret, request, 123L)
        assertEquals(123L, KotlinContainedCommandProtocol.requireBoot(boot, secret, request))
        assertContentEquals(boot, signed(document(boot), secret))
        val start = KotlinContainedCommandProtocol.start(secret, request, 123L)
        KotlinContainedCommandProtocol.requireStart(start, secret, request, 123L)
        val outcome = KotlinContainedCommandOutcome(123L, 124L, 0, 100L, 40L, 50L, "EXITED")
        val bytes = KotlinContainedCommandProtocol.outcome(secret, request, outcome)
        assertEquals(outcome, KotlinContainedCommandProtocol.requireOutcome(bytes, secret, request, 123L))
        assertContentEquals(bytes, signed(document(bytes), secret))
        KotlinContainedCommandProtocol.requireOutcome(bytes, secret, request, 123L).requireSuccessful()
        assertTrue(listOf(boot, start, bytes).all { it.size <= KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES })
        assertEquals(3, listOf(boot, start, bytes).map { OracleArtifacts.sha256(it) }.toSet().size)
    }

    @Test
    fun `forged protocol fields never acquire authority even with canonical JSON`() {
        val request = request()
        val secret = secret()
        val original = document(KotlinContainedCommandProtocol.outcome(secret, request, outcome()))
        for ((name, value) in listOf(
            "keeperPid" to JsonPrimitive(125), "childPid" to JsonPrimitive(126), "exitCode" to JsonPrimitive(1),
            "elapsedMillis" to JsonPrimitive(101), "stdoutBytes" to JsonPrimitive(41), "stderrBytes" to JsonPrimitive(51),
            "status" to JsonPrimitive("TIMED_OUT"), "nonce" to JsonPrimitive("b".repeat(64)),
            "requestSha256" to JsonPrimitive("c".repeat(64)), "hmacSha256" to JsonPrimitive("0".repeat(64)),
            "event" to JsonPrimitive("BOOT"), "provider" to JsonPrimitive("kotlin-boot-v1"),
        )) {
            assertFailsWith<IllegalArgumentException>(name) {
                KotlinContainedCommandProtocol.requireOutcome(replace(original, name, value), secret, request, 123L)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            KotlinContainedCommandProtocol.requireOutcome(replace(original, "extra", JsonPrimitive(true)), secret, request, 123L)
        }
        assertFailsWith<IllegalArgumentException> {
            KotlinContainedCommandProtocol.requireOutcome(OracleJson.canonicalBytes(JsonObject(original - "hmacSha256")), secret, request, 123L)
        }
    }

    @Test
    fun `protocol rejects replay across event nonce request keeper and bootstrap domains`() {
        val request = request()
        val secret = secret()
        val boot = KotlinContainedCommandProtocol.boot(secret, request, 123L)
        val start = KotlinContainedCommandProtocol.start(secret, request, 123L)
        val outcome = KotlinContainedCommandProtocol.outcome(secret, request, outcome())
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(boot, secret, request, 123L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(start, secret, request) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(start, secret, request, 123L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(outcome, secret, request, 123L) }
        for (other in listOf(request(nonce = "b".repeat(64)), request(wallSeconds = 31), request(command = listOf("/usr/bin/java", "-help")))) {
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(boot, secret, other) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(start, secret, other, 123L) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(outcome, secret, other, 123L) }
        }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireStart(start, secret, request, 125L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireOutcome(outcome, secret, request, 125L) }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(boot, ByteArray(32) { 99 }, request) }
        for (length in listOf(0, 31, 33)) {
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.boot(ByteArray(length), request, 123L) }
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(boot, ByteArray(length), request) }
        }
    }

    @Test
    fun `valid authentication does not bypass semantic protocol bounds or event consistency`() {
        val request = request()
        val secret = secret()
        val original = document(KotlinContainedCommandProtocol.outcome(secret, request, outcome()))
        for ((name, value) in listOf(
            "keeperPid" to JsonPrimitive(0), "childPid" to JsonPrimitive(0), "childPid" to JsonPrimitive(123),
            "childPid" to JsonPrimitive(Int.MAX_VALUE.toLong() + 1L), "exitCode" to JsonPrimitive(256),
            "exitCode" to JsonPrimitive("0"), "elapsedMillis" to JsonPrimitive(45001),
            "stdoutBytes" to JsonPrimitive(4097), "stderrBytes" to JsonPrimitive(4097),
            "status" to JsonPrimitive("COMPLETE"), "schemaVersion" to JsonPrimitive(2),
        )) {
            val changed = JsonObject(original + (name to value))
            assertFailsWith<IllegalArgumentException>(name) {
                KotlinContainedCommandProtocol.requireOutcome(signed(changed, secret), secret, request, 123L)
            }
        }
        val boot = document(KotlinContainedCommandProtocol.boot(secret, request, 123L))
        assertFailsWith<IllegalArgumentException> {
            KotlinContainedCommandProtocol.requireBoot(signed(JsonObject(boot + ("childPid" to JsonPrimitive(124))), secret), secret, request)
        }
        assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.boot(secret, request, 0L) }
        assertFailsWith<IllegalArgumentException> {
            KotlinContainedCommandProtocol.outcome(secret, request, outcome().copy(stdoutBytes = 4097L))
        }
    }

    @Test
    fun `nonzero exit timeout and output overflow are authenticated failures not successful analysis`() {
        val request = request()
        val secret = secret()
        for (failure in listOf(outcome().copy(exitCode = 1), outcome().copy(status = "TIMED_OUT"),
            outcome().copy(status = "OUTPUT_LIMIT"), outcome().copy(exitCode = 137, status = "TIMED_OUT"))) {
            val bytes = KotlinContainedCommandProtocol.outcome(secret, request, failure)
            val parsed = KotlinContainedCommandProtocol.requireOutcome(bytes, secret, request, 123L)
            assertEquals(failure, parsed)
            assertFailsWith<IllegalArgumentException> { parsed.requireSuccessful() }
        }
    }

    @Test
    fun `protocol accepts only bounded strict canonical records`() {
        val request = request()
        val secret = secret()
        val bytes = KotlinContainedCommandProtocol.boot(secret, request, 123L)
        for (invalid in listOf(bytes + byteArrayOf(10), byteArrayOf(),
            ByteArray(KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES + 1) { 32 },
            bytes.toString(Charsets.UTF_8).replaceFirst("{", "{\"event\":\"BOOT\",").toByteArray())) {
            assertFailsWith<IllegalArgumentException> { KotlinContainedCommandProtocol.requireBoot(invalid, secret, request) }
        }
    }

    private fun request(
        root: Path = Path.of("/srv/contained-run"), nonce: String = "a".repeat(64),
        command: List<String> = listOf("/usr/bin/java", "-version"),
        environment: Map<String, String> = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
        startSeconds: Long = 30L, wallSeconds: Long = 30L, stdoutBytes: Long = 4096L, stderrBytes: Long = 4096L,
        allowInterruption: Boolean = false,
    ) = KotlinContainedCommandRequest(root, nonce, command, environment, startSeconds, wallSeconds, stdoutBytes, stderrBytes, allowInterruption)

    private fun withLocalKeeper(waitingChild: Boolean = false, action: (Process, KotlinContainedCommandRequest, ByteArray) -> Unit) {
        val fixture = Files.createTempDirectory("contained-command-local-test-").toRealPath()
        Files.setPosixFilePermissions(fixture, PosixFilePermissions.fromString("rwx------"))
        var process: Process? = null
        try {
            val run = Files.createDirectory(fixture.resolve("run"), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            for (name in listOf("runtime", "state", "reports", "tmp")) {
                Files.createDirectory(run.resolve(name), PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
            }
            val java = Path.of(System.getProperty("java.home"), "bin", "java").toRealPath()
            val classPath = System.getProperty("java.class.path").split(File.pathSeparator).filter(String::isNotEmpty)
                .joinToString(File.pathSeparator) { Path.of(it).toAbsolutePath().normalize().toString() }
            val command = if (waitingChild) listOf(java.toString(), "-classpath", classPath, KotlinContainedCommandTestSleeper::class.java.name) else listOf(java.toString(), "-version")
            val request = request(root = run, command = command, startSeconds = 30L, wallSeconds = 30L, allowInterruption = waitingChild)
            val requestPath = run.resolve("runtime/${KotlinContainedCommandRequest.REQUEST_FILE}")
            Files.write(requestPath, request.canonicalBytes)
            Files.setPosixFilePermissions(requestPath, PosixFilePermissions.fromString("r--------"))
            val native = Path.of(requireNotNull(System.getProperty("decompengine.oracle.nativeLibraryDirectory"))).toRealPath()
            val arguments = listOf(java.toString(), "-Xmx128m", "-XX:+DisableAttachMechanism", "-XX:-UsePerfData",
                "-Djava.io.tmpdir=${run.resolve("tmp")}", "-Duser.home=${run.resolve("tmp")}") +
                OracleNativeLibraries.jvmArguments(native) + listOf("-classpath", classPath,
                    KotlinContainedCommandKeeper::class.java.name, KotlinContainedCommandProtocol.VERSION,
                    run.toString(), request.nonce, request.sha256)
            val diagnostics = fixture.resolve("keeper.log")
            val started = ProcessBuilder(arguments).directory(run.toFile()).redirectErrorStream(true)
                .redirectOutput(diagnostics.toFile()).apply {
                    environment().clear()
                    environment()["HOME"] = run.resolve("tmp").toString()
                    environment()["TMPDIR"] = run.resolve("tmp").toString()
                }.start()
            process = started
            val secret = secret()
            started.outputStream.use { output -> output.write(secret) }
            action(started, request, secret)
            assertTrue(Files.size(diagnostics) <= 8192L, "local keeper diagnostics exceeded their test bound")
        } finally {
            val started = process
            if (started != null) {
                val descendants = started.descendants().use { it.toList() }
                if (started.isAlive) started.destroyForcibly()
                descendants.forEach { descendant -> if (descendant.isAlive) descendant.destroyForcibly() }
                assertTrue(started.waitFor(5L, TimeUnit.SECONDS), "local nondumpable keeper was not reaped")
                for (descendant in descendants) {
                    descendant.onExit().get(5L, TimeUnit.SECONDS)
                    assertFalse(descendant.isAlive, "known local child survived test cleanup")
                }
            }
            Files.walk(fixture).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private fun awaitLocalProtocol(process: Process, run: Path, name: String): ByteArray {
        val path = run.resolve(name)
        val started = System.nanoTime()
        while (System.nanoTime() - started < TimeUnit.SECONDS.toNanos(30L)) {
            if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                assertTrue(Files.size(path) in 1L..KotlinContainedCommandProtocol.MAXIMUM_PROTOCOL_BYTES.toLong())
                return Files.readAllBytes(path)
            }
            if (!process.isAlive) {
                val diagnostics = Files.newInputStream(run.parent.resolve("keeper.log")).use { it.readNBytes(8193) }
                assertTrue(diagnostics.size <= 8192, "local keeper diagnostics exceeded their test bound")
                throw AssertionError("local keeper exited before $name: ${diagnostics.toString(Charsets.UTF_8)}")
            }
            Thread.sleep(25L)
        }
        throw AssertionError("local keeper did not publish $name within its test bound")
    }

    private fun publishLocalStart(request: KotlinContainedCommandRequest, bytes: ByteArray, name: String = KotlinContainedCommandProtocol.START_FILE) {
        val temporary = request.runDirectory.resolve(".test-start.tmp")
        Files.write(temporary, bytes)
        Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("r--------"))
        Files.move(temporary, request.runDirectory.resolve(name), StandardCopyOption.ATOMIC_MOVE)
    }

    private fun secret(): ByteArray = ByteArray(32) { index -> index.toByte() }

    private fun outcome() = KotlinContainedCommandOutcome(123L, 124L, 0, 100L, 40L, 50L, "EXITED")

    private fun document(bytes: ByteArray): JsonObject = OracleJson.parseCanonical(bytes) as JsonObject

    private fun replace(document: JsonObject, name: String, value: JsonElement): ByteArray =
        OracleJson.canonicalBytes(JsonObject(document + (name to value)))

    private fun signed(document: JsonObject, secret: ByteArray): ByteArray {
        val unsigned = JsonObject(document - "hmacSha256")
        val authentication = Mac.getInstance("HmacSHA256")
        authentication.init(SecretKeySpec(secret, "HmacSHA256"))
        val digest = authentication.doFinal(OracleJson.canonicalBytes(unsigned))
            .joinToString("") { "%02x".format(it.toInt() and 255) }
        return OracleJson.canonicalBytes(JsonObject(unsigned + ("hmacSha256" to JsonPrimitive(digest))))
    }
}

/** Authored bounded local fixture; never an oracle or contained execution proof. */
object KotlinContainedCommandTestSleeper {
    @JvmStatic
    fun main(args: Array<String>) {
        Files.writeString(Path.of("reports/child-ready"), "ready")
        Thread.sleep(60_000L)
    }
}
