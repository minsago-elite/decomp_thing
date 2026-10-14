package decompengine.acp

import java.io.IOException
import java.lang.reflect.InvocationTargetException
import java.net.SocketTimeoutException
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.security.Permission
import java.time.Duration
import java.util.concurrent.CountDownLatch
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/** Reflective component composition grants neither factory/provider admission nor a public seam. */
class AcpProviderDnsProcessTest {
    @Test fun `isolated lookup selects one IPv4 address and actually reaps child`() = successfulLookup("IPV4", byteArrayOf(192.toByte(), 0, 2, 1))
    @Test fun `isolated lookup selects one IPv6 address and actually reaps child`() = successfulLookup("IPV6", ByteArray(16).also { it[15] = 1 })

    @Test fun `actual stalled resolver is killed and reaped on cancel`() = fixture("STALL") { owner, root ->
        owner.startComponent()
        awaitFile(root.resolve("lookup-ready"))
        val pid = assertNotNull(owner.cleanupSnapshot().childPid)
        assertTrue(ProcessHandle.of(pid).orElseThrow().isAlive)
        owner.cancel()
        assertFixedFailure<IOException> { owner.awaitAddress() }
        assertClean(owner, pid)
    }

    @Test fun `actual stalled resolver deadline kills child without a waiting caller`() = fixture("STALL", Duration.ofMillis(1500)) { owner, root ->
        owner.startComponent()
        awaitFile(root.resolve("lookup-ready"))
        val pid = assertNotNull(owner.cleanupSnapshot().childPid)
        awaitCondition { !ProcessHandle.of(pid).map { it.isAlive }.orElse(false) }
        assertFixedFailure<SocketTimeoutException> { owner.awaitAddress() }
        assertClean(owner, pid)
    }

    @Test fun `completed lookup cannot be admitted after request deadline`() = fixture("IPV4", Duration.ofMillis(1500)) { owner, _ ->
        owner.startComponent()
        awaitCondition { owner.cleanupSnapshot().ownerJoined }
        val pid = assertNotNull(owner.cleanupSnapshot().childPid)
        Thread.sleep(1550)
        assertFixedFailure<SocketTimeoutException> { owner.awaitAddress() }
        assertClean(owner, pid)
    }

    @Test fun `cancelled lookup cannot be revived by a released address`() = fixture("LATE") { owner, root ->
        owner.startComponent()
        awaitFile(root.resolve("lookup-ready"))
        val pid = assertNotNull(owner.cleanupSnapshot().childPid)
        owner.cancel()
        Files.writeString(root.resolve("lookup-release"), "release\n")
        assertFixedFailure<IOException> { owner.awaitAddress() }
        assertClean(owner, pid)
    }

    @Test fun `cancel before admission starts no child`() = fixture("STALL") { owner, _ ->
        val published = componentTask(owner)
        assertFalse(published.isDone)
        assertFalse(owner.cleanupSnapshot().ownerJoined)
        owner.cancel()
        owner.startComponent()
        assertFixedFailure<IOException> { owner.awaitAddress() }
        assertTrue(owner.closeBefore(endAfter(Duration.ofSeconds(1))))
        assertEquals(null, owner.cleanupSnapshot().childPid)
        assertTrue(owner.cleanupSnapshot().ownerJoined)
        assertTrue(published === componentTask(owner))
        assertTrue(published.isCancelled)
    }

    @Test fun `exact future task is published before execution and remains the completion proof`() = fixture("IPV4") { owner, _ ->
        val published = componentTask(owner)
        assertFalse(published.isDone)
        owner.startComponent()
        assertContentEquals(byteArrayOf(192.toByte(), 0, 2, 1), owner.awaitAddress().address)
        assertTrue(published === componentTask(owner))
        assertTrue(published.isDone)
        assertFalse(published.isCancelled)
        assertClean(owner, assertNotNull(owner.cleanupSnapshot().childPid))
    }

    @Test fun `failed lookup returns a fixed failure with no child leak`() = fixture("FAIL") { owner, _ ->
        owner.startComponent()
        assertFixedFailure<IOException> { owner.awaitAddress() }
        assertClean(owner, assertNotNull(owner.cleanupSnapshot().childPid))
    }

    @Test fun `invalid and oversized actual child output is refused and reaped`() {
        for (mode in listOf("EMPTY", "SHORT", "EXTRA", "OVERSIZED", "STDERR", "NONZERO")) {
            fixture(mode, jarProperty = "protocolJar") { owner, _ ->
                owner.startComponent()
                assertFixedFailure<IOException> { owner.awaitAddress() }
                assertClean(owner, assertNotNull(owner.cleanupSnapshot().childPid))
            }
        }
    }

    @Test fun `valid address bytes do not bypass required child exit`() = fixture("HOLD", jarProperty = "protocolJar") { owner, root ->
        owner.startComponent()
        awaitFile(root.resolve("lookup-ready"))
        val pid = assertNotNull(owner.cleanupSnapshot().childPid)
        assertFalse(owner.cleanupSnapshot().ownerJoined)
        owner.cancel()
        assertFixedFailure<IOException> { owner.awaitAddress() }
        assertClean(owner, pid)
    }

    @Test fun `actual child receives empty environment no arguments and EOF stdin`() = fixture("ENV", jarProperty = "protocolJar") { owner, root ->
        owner.startComponent()
        assertContentEquals(byteArrayOf(192.toByte(), 0, 2, 1), owner.awaitAddress().address)
        assertEquals("env=0\nargs=0\nstdinEOF=true\nclasspathEnvironmentAbsent=true\n", Files.readString(root.resolve("fixture-proof")))
        assertClean(owner, assertNotNull(owner.cleanupSnapshot().childPid))
    }

    @Test fun `authenticated artifact mutation is refused before any child`() = fixture("IPV4") { owner, root ->
        Files.write(root.resolve("worker.jar"), byteArrayOf(0))
        owner.startComponent()
        assertFixedFailure<IOException> { owner.awaitAddress() }
        assertTrue(owner.closeBefore(endAfter(Duration.ofSeconds(1))))
        assertEquals(null, owner.cleanupSnapshot().childPid)
    }

    @Test fun `production jar rejects resolver services and fixture classpath`() {
        val method = Class.forName("decompengine.acp.AcpProviderDnsProcessKt").getDeclaredMethod("validateProviderDnsJar", ByteArray::class.java).also { it.isAccessible = true }
        method.invoke(null, Files.readAllBytes(jar("workerJar")))
        assertFailsWith<InvocationTargetException> { method.invoke(null, Files.readAllBytes(jar("fixtureJar"))) }
        val authenticate = Class.forName("decompengine.acp.AcpProviderDnsProcessKt").getDeclaredMethod("authenticatePackagedProviderDnsJar", Path::class.java).also { it.isAccessible = true }
        authenticate.invoke(null, jar("workerJar"))
        assertFailsWith<InvocationTargetException> { authenticate.invoke(null, jar("protocolJar")) }
    }

    @Test fun `repeated stalled lookup cleanup leaves no child descriptor or task accumulation`() {
        val descriptors = descriptorCount()
        repeat(4) {
            fixture("STALL") { owner, root ->
                owner.startComponent()
                awaitFile(root.resolve("lookup-ready"))
                assertClean(owner, assertNotNull(owner.cleanupSnapshot().childPid))
            }
        }
        assertTrue(descriptorCount() <= descriptors + 2)
        val executor = dnsOwnersField("executor") as java.util.concurrent.ThreadPoolExecutor
        awaitCondition { executor.activeCount == 0 }
        assertEquals(0, executor.queue.size)
        assertEquals(2, executor.maximumPoolSize)
        val deadlines = dnsOwnersField("deadlines") as java.util.concurrent.ScheduledThreadPoolExecutor
        awaitCondition { deadlines.activeCount == 0 && deadlines.queue.isEmpty() }
        assertEquals(1, deadlines.corePoolSize)
    }

    @Test fun `two real stalled owners exhaust capacity without queued child launches`() = fixture("STALL") { first, firstRoot ->
        fixture("STALL") { second, secondRoot ->
            first.startComponent(); second.startComponent()
            awaitFile(firstRoot.resolve("lookup-ready")); awaitFile(secondRoot.resolve("lookup-ready"))
            fixture("STALL") { refused, _ ->
                refused.startComponent()
                assertFixedFailure<IOException> { refused.awaitAddress() }
                assertTrue(refused.closeBefore(endAfter(Duration.ofSeconds(1))))
                assertEquals(null, refused.cleanupSnapshot().childPid)
                assertTrue(componentTask(refused).isCancelled)
                assertFalse(refused.cleanupSnapshot().quarantined)
                assertEquals(0, (dnsOwnersField("executor") as java.util.concurrent.ThreadPoolExecutor).queue.size)
            }
            assertClean(second, assertNotNull(second.cleanupSnapshot().childPid))
        }
        assertClean(first, assertNotNull(first.cleanupSnapshot().childPid))
    }

    @Test fun `late real process publication is killed reaped and permanently quarantined`() =
        forkControl("DnsLatePublicationControl", "LATE_CHILD_KILLED_REAPED_QUARANTINED", securityManager = true)

    @Test fun `signal of actual child never waits for its Java pipe flush monitor`() =
        forkControl("DnsPipeSignalControl", "SIGNAL_RETURNED_WITH_PIPE_MONITOR_HELD")

    private fun forkControl(mainClass: String, marker: String, securityManager: Boolean = false) {
        val root = privateRoot()
        try {
            val java = Path.of(System.getProperty("java.home"), "bin", "java").toRealPath()
            val classpath = listOf(AcpProviderDnsProcess::class.java, DnsLatePublicationControl::class.java, Unit::class.java)
                .map { Path.of(it.protectionDomain.codeSource.location.toURI()).toString() }.distinct().joinToString(":")
            val command = listOf(java.toString(), "-XX:-UsePerfData", "-XX:+ErrorFileToStderr", "-XX:-CreateCoredumpOnCrash") +
                (if (securityManager) listOf("-Djava.security.manager=allow") else emptyList()) +
                listOf("-Djava.io.tmpdir=$root", "-Duser.home=$root", "-cp", classpath,
                    "decompengine.acp.$mainClass", jar("fixtureJar").toString(), root.toString())
            val child = ProcessBuilder(command).directory(root.toFile()).redirectErrorStream(true).also { it.environment().clear() }.start()
            try {
                child.outputStream.close()
                assertTrue(child.waitFor(8, TimeUnit.SECONDS))
                val output = child.inputStream.readNBytes(4097)
                assertTrue(output.size <= 4096)
                assertEquals(0, child.exitValue())
                assertTrue(output.toString(Charsets.UTF_8).contains(marker))
            } finally {
                if (child.isAlive) child.toHandle().destroyForcibly()
                assertTrue(child.waitFor(2, TimeUnit.SECONDS))
                child.inputStream.close(); child.errorStream.close(); child.outputStream.close()
            }
        } finally { removeRoot(root) }
    }

    private fun successfulLookup(mode: String, expected: ByteArray) = fixture(mode) { owner, _ ->
        owner.startComponent()
        assertContentEquals(expected, owner.awaitAddress().address)
        assertClean(owner, assertNotNull(owner.cleanupSnapshot().childPid))
    }

    private inline fun <reified T : IOException> assertFixedFailure(action: () -> Unit) {
        val failure = assertFailsWith<T>(block = action)
        assertEquals(null, failure.cause)
        assertTrue(failure.message in setOf("ACP provider resolution failed", "ACP provider resolution stopped", "ACP provider resolution timed out"))
    }

    private fun assertClean(owner: AcpProviderDnsProcess, pid: Long) {
        assertTrue(owner.closeBefore(endAfter(Duration.ofSeconds(2))))
        val state = owner.cleanupSnapshot()
        assertTrue(state.childReaped && state.ownerJoined && state.streamsClosed)
        // Accepted work always finishes its exact task; cancellation is not join/reap proof.
        assertTrue(componentTask(owner).isDone)
        assertFalse(componentTask(owner).isCancelled)
        assertFalse(state.quarantined)
        assertFalse(ProcessHandle.of(pid).map { it.isAlive }.orElse(false))
        assertFalse(Files.exists(Path.of("/proc", pid.toString())))
    }

    private fun fixture(mode: String, timeout: Duration = Duration.ofSeconds(3), jarProperty: String = "fixtureJar", block: (AcpProviderDnsProcess, Path) -> Unit) {
        val root = privateRoot()
        val copied = root.resolve("worker.jar")
        Files.copy(jar(jarProperty), copied)
        Files.setPosixFilePermissions(copied, PosixFilePermissions.fromString("rw-r--r--"))
        Files.writeString(root.resolve("fixture-mode"), mode)
        val owner = newComponentOwner(copied, root, endAfter(timeout))
        try { block(owner, root) }
        finally { check(owner.closeBefore(endAfter(Duration.ofSeconds(2)))); removeRoot(root) }
    }
}

/** Runs alone: SecurityManager is a supported JDK21 test-only checkExec publication latch. */
@Suppress("DEPRECATION", "removal")
object DnsLatePublicationControl {
    @JvmStatic fun main(args: Array<String>) {
        check(args.size == 2)
        val root = Path.of(args[1])
        val copied = root.resolve("worker.jar")
        Files.copy(Path.of(args[0]), copied)
        Files.setPosixFilePermissions(copied, PosixFilePermissions.fromString("rw-r--r--"))
        Files.writeString(root.resolve("fixture-mode"), "STALL")
        val owner = newComponentOwner(copied, root, endAfter(Duration.ofSeconds(6)))
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val java = Path.of(System.getProperty("java.home"), "bin", "java").toRealPath().toString()
        System.setSecurityManager(object : SecurityManager() {
            override fun checkPermission(permission: Permission) = Unit
            override fun checkExec(command: String) {
                // Files.isExecutable also invokes checkExec. Delay only the actual builder
                // call, after the owner's last pre-launch active check has passed.
                if (Thread.currentThread().stackTrace.none { it.className == "java.lang.ProcessBuilder" && it.methodName == "start" }) return
                check(command == java)
                entered.countDown()
                check(release.await(4, TimeUnit.SECONDS))
            }
        })
        try {
            owner.startComponent()
            check(entered.await(2, TimeUnit.SECONDS))
            owner.cancel()
            check(!owner.closeBefore(endAfter(Duration.ofMillis(30))))
            check(owner.cleanupSnapshot().quarantined)
            val refused = newComponentOwner(copied, root, endAfter(Duration.ofSeconds(2)))
            refused.startComponent()
            check(refused.closeBefore(endAfter(Duration.ofSeconds(1))))
            check(refused.cleanupSnapshot().childPid == null)
            release.countDown()
            check(owner.closeBefore(endAfter(Duration.ofSeconds(3))))
            val state = owner.cleanupSnapshot()
            check(state.childPid != null && state.childReaped && state.ownerJoined && state.streamsClosed && state.quarantined)
            check(!Files.exists(Path.of("/proc", state.childPid.toString())))
            val stillRefused = newComponentOwner(copied, root, endAfter(Duration.ofSeconds(2)))
            stillRefused.startComponent()
            check(stillRefused.closeBefore(endAfter(Duration.ofSeconds(1))))
            check(stillRefused.cleanupSnapshot().childPid == null)
            println("LATE_CHILD_KILLED_REAPED_QUARANTINED")
        } finally { release.countDown(); System.setSecurityManager(null); owner.closeBefore(endAfter(Duration.ofSeconds(2))) }
    }
}

/** A real-child signal probe, not a fabricated accepted-owner cleanup receipt. */
object DnsPipeSignalControl {
    @JvmStatic fun main(args: Array<String>) {
        check(args.size == 2)
        val root = Path.of(args[1])
        val copied = root.resolve("worker.jar")
        Files.copy(Path.of(args[0]), copied)
        Files.setPosixFilePermissions(copied, PosixFilePermissions.fromString("rw-r--r--"))
        Files.writeString(root.resolve("fixture-mode"), "STALL")
        val owner = newComponentOwner(copied, root, endAfter(Duration.ofSeconds(6)))
        val artifact = owner.javaClass.getDeclaredField("artifact").also { it.isAccessible = true }.get(owner)
        val builder = artifact.javaClass.getDeclaredMethod("builder").also { it.isAccessible = true }.invoke(artifact) as ProcessBuilder
        val child = builder.start()
        val cancelled = CountDownLatch(1)
        val signal = Thread { try { owner.cancel() } finally { cancelled.countDown() } }
        try {
            awaitFile(root.resolve("lookup-ready"))
            owner.javaClass.getDeclaredMethod("publish", Process::class.java).also { it.isAccessible = true }.invoke(owner, child)
            // Leave stdin OPEN: old Process.destroyForcibly closes it and calls flush(),
            // which needs this exact BufferedOutputStream monitor on the pinned Java21.
            synchronized(child.outputStream) {
                signal.start()
                check(cancelled.await(1, TimeUnit.SECONDS))
            }
            signal.join(1000)
            check(!signal.isAlive)
            check(child.waitFor(2, TimeUnit.SECONDS))
            child.outputStream.close(); child.inputStream.close(); child.errorStream.close()
            check(!child.isAlive && !Files.exists(Path.of("/proc", child.pid().toString())))
            // This focused probe never executed the owner task. Do not turn its manual
            // child reaping into owner proof: close must truthfully remain UNVERIFIED.
            check(!owner.closeBefore(endAfter(Duration.ofMillis(30))))
            check(!owner.cleanupSnapshot().childReaped)
            println("SIGNAL_RETURNED_WITH_PIPE_MONITOR_HELD")
        } finally {
            child.toHandle().destroyForcibly()
            check(child.waitFor(2, TimeUnit.SECONDS))
            child.outputStream.close(); child.inputStream.close(); child.errorStream.close()
            if (signal.state != Thread.State.NEW) signal.join(1000)
            check(!signal.isAlive)
        }
    }
}

private fun jar(property: String): Path = Path.of(System.getProperty("decompengine.acp.providerDns.$property")).toRealPath()
private fun endAfter(duration: Duration): Long = System.nanoTime() + duration.toNanos()
private fun privateRoot(): Path {
    val parent = Path.of(System.getProperty("user.dir"), "build/provider-dns-component-tests").toAbsolutePath().normalize()
    Files.createDirectories(parent)
    return Files.createTempDirectory(parent, "dns-").also { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------")) }
}
private fun removeRoot(path: Path) { Files.walk(path).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
private fun awaitFile(path: Path) = awaitCondition { Files.isRegularFile(path) }
private fun awaitCondition(condition: () -> Boolean) {
    val end = endAfter(Duration.ofSeconds(2))
    while (!condition()) { check(System.nanoTime() < end) { "component observation timed out" }; Thread.sleep(5) }
}
private fun descriptorCount(): Long = Files.list(Path.of("/proc/self/fd")).use { it.count() }
private fun newComponentOwner(jar: Path, directory: Path, deadline: Long): AcpProviderDnsProcess {
    val artifactClass = Class.forName("decompengine.acp.ProviderDnsArtifact")
    val constructor = artifactClass.getDeclaredConstructor(Path::class.java, String::class.java, Path::class.java).also { it.isAccessible = true }
    val digest = MessageDigest.getInstance("SHA-256").digest(Files.readAllBytes(jar)).joinToString("") { "%02x".format(it) }
    val artifact = constructor.newInstance(jar, digest, directory)
    return AcpProviderDnsProcess::class.java.getDeclaredConstructor(artifactClass, Long::class.javaPrimitiveType).also { it.isAccessible = true }
        .newInstance(artifact, deadline)
}
private fun AcpProviderDnsProcess.startComponent() { javaClass.getDeclaredMethod("start").also { it.isAccessible = true }.invoke(this) }
private fun componentTask(owner: AcpProviderDnsProcess): FutureTask<*> =
    owner.javaClass.getDeclaredField("task").also { it.isAccessible = true }.get(owner) as FutureTask<*>
private fun dnsOwnersField(name: String): Any {
    val type = Class.forName("decompengine.acp.ProviderDnsOwners")
    return type.getDeclaredField(name).also { it.isAccessible = true }.get(null)
}
