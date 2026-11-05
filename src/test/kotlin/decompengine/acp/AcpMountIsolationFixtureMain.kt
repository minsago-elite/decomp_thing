package decompengine.acp

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLibrary
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.Path
import kotlin.system.exitProcess

/** Opt-in main only; never a default JUnit test. The native cleaner direct-execs this JVM. */
object AcpMountIsolationFixtureMain {
    private val libc by lazy { NativeLibrary.getInstance("c") }
    private fun call(name: String, vararg args: Any?): Int = libc.getFunction(name).invokeInt(args)
    private fun field(instance: Any, name: String): Any? = instance.javaClass.getDeclaredField(name)
        .apply { isAccessible = true }.get(instance)
    private fun registry(name: String): Collection<*> = Class.forName("decompengine.acp.LinuxBubblewrapBoundaryKt")
        .getDeclaredField(name).apply { isAccessible = true }.get(null) as Collection<*>
    private fun event(name: String, detail: String = "") {
        require(name.matches(Regex("[A-Za-z0-9_]+")))
        require(detail.all { it.code in 32..126 && it != '"' && it != '\\' })
        println("ACP_FIXTURE {\"role\":\"J\",\"event\":\"$name\",\"detail\":\"$detail\",\"rc\":0,\"errno\":0}")
    }
    private fun key(path: String): Any = Files.readAttributes(Path.of(path), "unix:dev,ino")
    private fun fdKey(fd: Int): Any = key("/proc/self/fd/$fd")
    private fun descriptorSet(): Set<String> = Files.list(Path.of("/proc/self/fd")).use { stream ->
        // Exclude the enumeration fd, which has a different number as JVM internals warm.
        stream.filter { runCatching { Files.readSymbolicLink(it).toString() }.getOrNull() != "/proc/${ProcessHandle.current().pid()}/fd" }
            .map { it.fileName.toString() }.toList().toSet()
    }
    private class Cancelled : IOException("fixture cancellation")
    private class Channel(private val parent: Int, private val deadline: Long) {
        private var frames = 0
        private fun remaining(): Int = (deadline - monotonicMillis()).also { require(it in 1..60000) }.toInt()
        private fun ready(events: Int) = Memory(8).use { p ->
            p.clear(); p.setInt(0, 100); p.setShort(4, events.toShort())
            check(call("poll", p, 1, remaining()) == 1)
            val bits = p.getShort(6).toInt()
            check(bits and events != 0 && bits and (8 or 32) == 0) { "control peer lost" }
        }
        fun send(seq: Int, op: String) {
            check(++frames <= 32)
            val bytes = "1 $seq J $op\n".toByteArray(Charsets.US_ASCII)
            ready(4)
            Memory(bytes.size.toLong()).use { p ->
                p.write(0, bytes, 0, bytes.size)
                check(call("send", 100, p, bytes.size.toLong(), 0x4000) == bytes.size)
            }
        }
        fun receive(seq: Int, op: String): String {
            check(++frames <= 32)
            ready(1)
            // Linux LP64 msghdr (56 bytes), iovec (16), cmsghdr (16).
            // Fixed inherited endpoint only; MSG_CMSG_CLOEXEC is atomic at receipt.
            val line = Memory(4096).use { payload -> Memory(256).use { control ->
                Memory(16).use { iov -> Memory(56).use { msg ->
                    payload.clear(); control.clear(); iov.clear(); msg.clear()
                    iov.setPointer(0, payload); iov.setLong(8, 4096)
                    msg.setPointer(16, iov); msg.setLong(24, 1)
                    msg.setPointer(32, control); msg.setLong(40, 256)
                    val n = libc.getFunction("recvmsg").invokeLong(arrayOf(100, msg, 0x40000000 or 0x20 or 0x40))
                    AcpMountAncillary.decode(payload.getByteArray(0, 4096), n,
                        control.getByteArray(0, 256), msg.getLong(40), msg.getInt(48), parent, 0, 0) { fd ->
                        call("close", fd) == 0
                    }
                } }
            } }
            if (line != "1 $seq A $op\n" && line != "1 $seq A CANCEL\n") throw AcpMountFrameFailure("ROLE_SEQUENCE_GRAMMAR")
            // SO_PEERCRED is the creating cleaner, not a caller-supplied pathname credential.
            checkPeer(parent)
            return if (line.endsWith(" CANCEL\n")) "CANCEL" else op
        }
    }
    private fun monotonicMillis(): Long = Memory(16).use { t ->
        check(call("clock_gettime", 1, t) == 0)
        t.getLong(0) * 1000 + t.getLong(8) / 1_000_000
    }
    private fun checkPeer(parent: Int) {
        Memory(12).use { cred -> Memory(4).use { size ->
            size.setInt(0, 12)
            check(call("getsockopt", 100, 1, 17, cred, size) == 0 && size.getInt(0) == 12)
            check(cred.getInt(0) == parent && cred.getInt(4) == 0 && cred.getInt(8) == 0)
        } }
        Memory(8).use { p ->
            p.clear(); p.setInt(0, 109); p.setShort(4, 1)
            check(call("poll", p, 1, 0) == 0) { "cleaner died" }
        }
    }
    private fun adopt(parent: Int, scenario: String) {
        check(Native.POINTER_SIZE == 8 && Native.LONG_SIZE == 8)
        for (fd in 100..109) {
            val flags = call("fcntl", fd, 1, 0)
            check(flags >= 0 && call("fcntl", fd, 2, flags or 1) == 0)
            check(call("fcntl", fd, 1, 0) and 1 == 1)
        }
        Memory(4).use { value -> Memory(4).use { size ->
            size.setInt(0, 4)
            check(call("getsockopt", 100, 1, 3, value, size) == 0 && value.getInt(0) == 5)
        } }
        checkPeer(parent)
        val pid = Files.readAllLines(Path.of("/proc/self/fdinfo/109")).single { it.startsWith("Pid:") }.substringAfter(':').trim().toInt()
        check(pid == parent)
        check(fdKey(105) == key("/proc/thread-self/ns/mnt"))
        check(fdKey(106) == key("/proc/self/root"))
        check(fdKey(103) == fdKey(107) && fdKey(107) == key("/proc/self/ns/user"))
        check(fdKey(104) == fdKey(108) && fdKey(108) == key("/proc/self/ns/pid"))
        check(fdKey(102) == fdKey(106))
        check((fdKey(101) == fdKey(105)) == (scenario == "sensitivity"))
        event("adopted_CLOEXEC", "O=${fdKey(101)} A=${fdKey(105)} root=${fdKey(106)} user=${fdKey(107)} pid=${fdKey(108)} cleaner=$parent")
    }
    @JvmStatic
    fun main(args: Array<String>) {
        var failed: Throwable? = null
        var adopted = false
        try {
            require(args.size == 3)
            val scenario = args[0]
            val parent = args[1].toInt()
            val channel = Channel(parent, args[2].toLong())
            adopt(parent, scenario); adopted = true
            check(channel.receive(0, "VERSION") == "VERSION")
            channel.send(0, "READY")
            if (channel.receive(1, "BEGIN") == "CANCEL") {
                check(registry("ACTIVE_MANIFEST_SCOPES").isEmpty())
                channel.send(1, "CANCELLED"); event("cancel_before_admission")
            } else {
                runManifest(scenario, channel)
            }
        } catch (failure: Throwable) {
            failed = failure
            if (failure is AcpMountFrameFailure) event("protocol_refused_${failure.code}")
            System.err.println("fixture failure: ${failure.javaClass.name}: ${failure.message}")
        } finally {
            var closed = true
            // These are explicit inherited handles, including partial-adoption failures.
            for (fd in 100..109) if (call("close", fd) != 0) closed = false
            if (!closed || !adopted) {
                if (failed == null) failed = IOException("inherited descriptor cleanup unverified")
                event("cleanup_UNVERIFIED")
            } else event("inherited_fds_closed", "owned=100..109 closed=10")
        }
        exitProcess(if (failed == null) 0 else 1)
    }
    private fun runManifest(scenario: String, channel: Channel) {
        val source = Path.of("closure").toAbsolutePath()
        val limits = AcpRuntimeClosureLimits(32, 4096, 8)
        val expected = calculateAcpRuntimeManifestSha256(source, limits) // warm only before retained baseline
        val baseline = descriptorSet()
        val insideMutation = scenario == "hostile" || scenario == "cleanup-failure"
        val hostileIdentity = if (insideMutation) identity(Path.of("target")) else null
        var scope: Any? = null
        var observer: Any? = null
        var mountCheck: Any? = null
        var atDescriptor = false
        var cancelled = false
        var digest: String? = null
        var failure: Throwable? = null
        try {
            digest = calculateAcpRuntimeManifestSha256(source, limits) {
                val frames = Thread.currentThread().stackTrace.filter { it.className == "decompengine.acp.RuntimePrivateControlScope" }
                if (!atDescriptor && frames.any { it.methodName == "checkpointLocked" } && frames.any { it.methodName == "requireDescriptor" }) {
                    atDescriptor = true
                    scope = registry("ACTIVE_MANIFEST_SCOPES").single()
                    mountCheck = field(scope!!, "mountEventCheck")!!
                    check(field(mountCheck!!, "admissionComplete") == true)
                    observer = field(scope!!, "mountEvents")!!
                    check(field(observer!!, "ownsDescriptor") == true)
                    event("ADMITTED_AT_DESCRIPTOR", "observer=${field(observer!!, "fd")}")
                    channel.send(2, "AT_DESCRIPTOR")
                    if (channel.receive(2, "ACK") == "CANCEL") { cancelled = true; throw Cancelled() }
                    // No poll of the A mount observer here. Existing checkpointLocked polls next.
                    check(fdKey(105) == key("/proc/thread-self/ns/mnt"))
                    val visible = Files.readString(Path.of("target/marker"))
                    check(visible == if (scenario in setOf("sensitivity", "hostile", "cleanup-failure")) "injected\n" else "original\n")
                    if (insideMutation) check(identity(Path.of("target")) == hostileIdentity)
                    event("view_checked", if (insideMutation) "restored_mount_and_key" else visible.trim())
                }
            }
        } catch (caught: Throwable) { failure = caught }
        // The scope is disposed now: inspect retained object fields, never reopen it or poll again.
        var cleanupFailure: Throwable? = null
        try { if (scope != null) {
            check(field(scope!!, "mountEvents") === observer)
            check(field(scope!!, "closed") == true && field(observer!!, "ownsDescriptor") == false)
            check(registry("ACTIVE_MANIFEST_SCOPES").isEmpty() && registry("ACTIVE_PRIVATE_CONTROLS").isEmpty())
            check(descriptorSet() == baseline) { "manifest descriptor set did not return to baseline" }
            event("scope_observer_released", "beforeAfterFds=${baseline.sorted().joinToString(",")}")
        } } catch (cleanup: Throwable) {
            cleanupFailure = cleanup
            if (failure != null) failure.addSuppressed(cleanup) else failure = cleanup
        }
        if (cleanupFailure != null) throw checkNotNull(failure)
        check(atDescriptor) { "admitted descriptor barrier not reached" }
        if (cancelled) {
            check(failure is Cancelled)
            channel.send(2, "CANCELLED"); event("cancel_at_descriptor"); return
        }
        if (scenario == "sensitivity" || insideMutation) {
            val witness = failure?.cause as? AcpMountEventWitness ?: error("original typed event refusal missing")
            check(witness.diagnosticRecord.startsWith("mount-event-v1 phase=CHECKPOINT "))
            check(witness.diagnosticRecord.contains(" outcome=EVENT "))
            check(witness.admissionRecord?.contains("stage=ADMITTED ") == true)
            check(field(mountCheck!!, "firstEventDiagnostic") === failure.cause)
            event("CHECKPOINT_EVENT", witness.diagnosticRecord)
        } else {
            failure?.let { throw it }
            check(digest == expected)
            check(field(mountCheck!!, "mountChanged") == false && field(mountCheck!!, "firstEventDiagnostic") == null)
            event("manifest_finished_original_observer_NONE", digest!!)
        }
        channel.send(3, "OBSERVED")
        if (channel.receive(3, "RESTORED") == "CANCEL") {
            channel.send(3, "CANCELLED"); event("cancel_during_restore"); return
        }
        check(Files.readString(Path.of("target/marker")) == "original\n")
        channel.send(4, "CLOSE")
        if (channel.receive(4, "CLOSED") == "CANCEL") {
            channel.send(4, "CANCELLED"); event("cancel_during_close"); return
        }
        event("subject_complete")
    }
    private fun identity(path: Path): Pair<Any, Any> =
        requireNotNull(LinuxFilesystemSyscalls.openAbsolutePathOrNull(path.toAbsolutePath())).use {
            val id = LinuxFilesystemSyscalls.identity(it.fd)
            id.mountId to id.key
        }
}

/** Pure byte decoder shared by recvmsg and authored controls; no sockets/JNA/product calls. */
internal class AcpMountFrameFailure(val code: String) : IOException("fixture protocol $code")
internal object AcpMountAncillary {
    fun decode(payload: ByteArray, size: Long, control: ByteArray, controlSize: Long, flags: Int,
               pid: Int, uid: Int, gid: Int, closeRight: (Int) -> Boolean): String {
        var invalid = controlSize !in 0L..control.size.toLong() || control.size > 256
        // Even invalid flags/payload/credentials must not bypass delivered-right disposal.
        val end = controlSize.coerceIn(0, minOf(control.size, 256).toLong()).toInt()
        val bytes = ByteBuffer.wrap(control).order(ByteOrder.nativeOrder())
        var offset = 0
        var credentials = 0
        while (offset < end) {
            if (end - offset < 16) { invalid = true; break }
            val length = bytes.getLong(offset)
            val level = bytes.getInt(offset + 8)
            val type = bytes.getInt(offset + 12)
            if (length < 16) { invalid = true; break } // No reliable next header.
            val available = minOf(length, (end - offset).toLong()).toInt()
            if (level == 1 && type == 1) { // SCM_RIGHTS: close all complete delivered FDs.
                invalid = true
                var data = offset + 16
                while (data + 4 <= offset + available) {
                    val fd = bytes.getInt(data)
                    // A failed close is reported; never retry close on a possibly reused fd.
                    try { if (fd < 0 || !closeRight(fd)) invalid = true }
                    catch (_: Throwable) { invalid = true }
                    data += 4
                }
            } else if (level == 1 && type == 2 && length == 28L && available == 28) {
                credentials++
                if (bytes.getInt(offset + 16) != pid || bytes.getInt(offset + 20) != uid ||
                    bytes.getInt(offset + 24) != gid) invalid = true
            } else invalid = true
            if (length > end - offset) { invalid = true; break }
            val aligned = (length + 7) and -8L
            // Final cmsghdr may omit alignment padding. Nonfinal records must be aligned.
            if (aligned > end - offset) {
                if (length != (end - offset).toLong()) invalid = true
                offset = end
            } else offset += aligned.toInt()
        }
        if (size < 0) throw AcpMountFrameFailure("RECEIVE")
        if (size == 0L && end == 0 && !invalid && flags and 8 == 0) throw AcpMountFrameFailure("EOF")
        if (invalid || credentials != 1 || flags and 8 != 0) throw AcpMountFrameFailure("ANCILLARY")
        if (flags and 0x20 != 0 || size > 4096) throw AcpMountFrameFailure("OVERSIZE")
        if (size <= 0) throw AcpMountFrameFailure(if (size == 0L) "EOF" else "RECEIVE")
        if (size > payload.size) throw AcpMountFrameFailure("RECEIVE")
        val data = payload.copyOf(size.toInt())
        if (!data.all { it.toInt() in 0..127 }) throw AcpMountFrameFailure("GRAMMAR")
        return data.toString(Charsets.US_ASCII)
    }
}

/** Explicit pure-data main; never the subject main or a default JUnit case. */
object AcpMountAncillaryPureControls {
    @JvmStatic fun main(args: Array<String>) {
        check(args.isEmpty())
        val payload = "1 2 A ACK\n".toByteArray()
        fun record(type: Int, vararg values: Int): ByteArray {
            val length = 16 + values.size * 4
            val b = ByteBuffer.allocate((length + 7) and -8).order(ByteOrder.nativeOrder())
            b.putLong(length.toLong()).putInt(1).putInt(type)
            values.forEach { b.putInt(it) }
            return b.array()
        }
        val credential = record(2, 71, 0, 0)
        var cases = 0
        fun run(control: ByteArray = credential, flags: Int = 0, size: Long = payload.size.toLong(),
                controlSize: Long = control.size.toLong(), accept: Boolean = false,
                expectedClosed: List<Int> = emptyList(), closeFails: Boolean = false, code: String? = null) {
            val closed = mutableListOf<Int>()
            val result = runCatching {
                AcpMountAncillary.decode(payload, size, control, controlSize, flags, 71, 0, 0) {
                    closed += it
                    if (closeFails) throw IOException("authored close failure")
                    true
                }
            }
            check(result.isSuccess == accept) { "case $cases: $result" }
            if (code != null) check((result.exceptionOrNull() as? AcpMountFrameFailure)?.code == code)
            check(closed == expectedClosed) { "case $cases: rights $closed != $expectedClosed" }
            cases++
        }
        run(accept = true)
        run(credential.copyOf(28), accept = true) // optional final alignment padding
        run(byteArrayOf())
        run(byteArrayOf(), size = 0, code = "EOF")
        run(flags = 0x20, code = "OVERSIZE")
        run(flags = 8, code = "ANCILLARY")
        run(credential + credential)
        run(record(2, 72, 0, 0)); run(record(2, 71, 1, 0)); run(record(2, 71, 0, 1))
        run(record(9, 71, 0, 0))
        run(credential.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putInt(8, 9) })
        run(record(1, *IntArray(60) { it + 41 }), expectedClosed = (41..100).toList())
        run(credential + record(1, 41, 42), expectedClosed = listOf(41, 42))
        run(record(9, 0) + record(1, 41) + credential + record(1, 42), expectedClosed = listOf(41, 42))
        run(credential + credential + record(1, 41), expectedClosed = listOf(41))
        run(record(2, 72, 0, 0) + record(1, 41), expectedClosed = listOf(41))
        run(credential + record(1, 41, 42), flags = 8 or 0x20, expectedClosed = listOf(41, 42))
        run(credential + record(1, 41, 42), size = 0, expectedClosed = listOf(41, 42))
        run(credential + record(1, 41, 42), closeFails = true, expectedClosed = listOf(41, 42))
        run(credential + record(1, 41, 42).copyOf(20), flags = 8, expectedClosed = listOf(41))
        run(credential + record(1, 41) + byteArrayOf(1, 2), expectedClosed = listOf(41))
        run(credential.copyOf(12)); run(credential.copyOf(27)); run(flags = 8)
        run(flags = 0x20); run(size = 4097); run(size = -1); run(size = 0)
        run(controlSize = 257); run(controlSize = -1); run(control = ByteArray(257))
        run(credential.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putLong(8) })
        run(credential.clone().also { ByteBuffer.wrap(it).order(ByteOrder.nativeOrder()).putLong(Long.MAX_VALUE) })
        println("ACP ancillary pure controls PASS cases=$cases; no native socket or subject executed")
    }
}
