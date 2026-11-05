package decompengine.oracle.fulltree

import com.sun.jna.Memory
import com.sun.jna.Native
import com.sun.jna.NativeLong
import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import java.lang.reflect.InvocationHandler
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Proxy
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.util.ArrayDeque
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class StableControlFileMutationDiagnosticsTest {
    @Test
    fun `file event rejects and retains bounded identity scoped diagnostics`() {
        for (mask in listOf(0, 0x2, 0x4, 0x8, 0x400, 0x800)) {
            withMonitor { monitor, fixture ->
                val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                fixture.adapter.events += event(fixture.adapter.fileWatch, mask)
                val failure = assertFailure { registration.call("requireQuiet", "fixture") }
                val diagnostic = diagnostic(failure)
                assertTrue(diagnostic.contains("reason=FILE_EVENT"))
                assertTrue(diagnostic.contains("scope=TARGETED"))
                assertTrue(diagnostic.contains("mask=${mask.toString(16)}"))
                assertTrue(diagnostic.contains("watch=${fixture.adapter.fileWatch}"))
                assertTrue(diagnostic.contains("selected="))
                assertTrue(diagnostic.contains("parent="))
                assertTrue(diagnostic.toByteArray(Charsets.UTF_8).size <= 2 * 1024)
                assertTrue(diagnostic.contains("component=0/1"))
                assertTrue(diagnostic.contains("role=SELECTED_LEAF"))
                assertTrue(!diagnostic.contains("item.bin"))
                assertTrue(diagnosticThrowable(failure).stackTrace.isEmpty())
                registration.call("release")
            }
        }
    }

    @Test
    fun `matching parent name rejects while sibling prefix and suffix names remain quiet`() {
        withMonitor { monitor, fixture ->
            val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            fixture.adapter.events += event(fixture.adapter.parentWatch, mask = 0x100, name = "item.bin")
            val failure = assertFailure { registration.call("requireQuiet", "fixture") }
            val first = diagnostic(failure)
            assertTrue(first.contains("reason=PARENT_NAME_MATCH"))
            assertTrue(first.contains("nameMatch=MATCH"))
            assertTrue(!first.contains("item.bin"))
            registration.call("release")
        }

        for (mask in listOf(0x2, 0x40, 0x80, 0x100, 0x200)) {
            withMonitor { monitor, fixture ->
                val registration = monitor.register(fixture.parent, fixture.selected, "ancestor", 0, 2)
                fixture.adapter.events += event(fixture.adapter.parentWatch, mask, "ancestor")
                val failure = assertFailure { registration.call("requireQuiet", "fixture") }
                assertTrue(diagnostic(failure).contains("reason=PARENT_NAME_MATCH"))
                assertTrue(diagnostic(failure).contains("role=ANCESTOR_EDGE"))
                assertTrue(diagnostic(failure).contains("mask=${mask.toString(16)}"))
                registration.call("release")
            }
        }

        for (sibling in listOf("item.bin.backup", "prefix-item.bin", "other.bin")) {
            withMonitor { monitor, fixture ->
                val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                fixture.adapter.events += event(fixture.adapter.parentWatch, mask = 0x100, name = sibling)
                registration.call("requireQuiet", "fixture")
                assertEquals(null, registration.call("firstInvalidation"))
                registration.call("release")
            }
        }
    }

    @Test
    fun `queue unknown watch and malformed records are distinct global causes`() {
        val cases = listOf(
            Triple(event(-1, mask = 0), "reason=QUEUE_SENTINEL", "scope=GLOBAL"),
            Triple(event(777, mask = 0), "reason=UNKNOWN_WATCH", "scope=GLOBAL"),
            Triple(event(777, mask = 0x4000), "reason=QUEUE_OVERFLOW", "scope=GLOBAL"),
            Triple(byteArrayOf(1, 2, 3), "reason=TRUNCATED_HEADER", "scope=GLOBAL"),
            Triple(event(777, mask = 0, declaredNameLength = -1), "reason=INVALID_NAME_LENGTH", "scope=GLOBAL"),
            Triple(event(777, mask = 0, declaredNameLength = 99), "reason=INVALID_NAME_LENGTH", "scope=GLOBAL"),
            Triple(event(101, mask = 0, name = "not-terminated", terminate = false), "reason=UNTERMINATED_NAME", "scope=GLOBAL"),
        )
        for ((payload, reason, scope) in cases) {
            withMonitor { monitor, fixture ->
                val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                fixture.adapter.events += payload
                val failure = assertFailure { registration.call("requireQuiet", "fixture") }
                assertTrue(diagnostic(failure).contains(reason), diagnostic(failure))
                assertTrue(diagnostic(failure).contains(scope), diagnostic(failure))
                registration.call("release")
            }
        }
    }

    @Test
    fun `first invalidation survives later overflow and observation sequence advances`() {
        withMonitor { monitor, fixture ->
            val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            fixture.adapter.events += event(fixture.adapter.parentWatch, mask = 0x100, name = "item.bin")
            fixture.adapter.events += event(-1, mask = 0)
            val failure = assertFailure { registration.call("requireQuiet", "fixture") }
            val message = diagnostic(failure)
            assertTrue(message.contains("reason=PARENT_NAME_MATCH"))
            assertTrue(message.contains("sequence=1"))
            assertTrue(!message.contains("QUEUE_SENTINEL"))
            registration.call("release")
        }

        for (reverse in listOf(true, false)) {
            withMonitor { monitor, fixture ->
                val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                val matched = event(fixture.adapter.parentWatch, 0x100, "item.bin")
                val overflow = event(-1, 0)
                fixture.adapter.events += if (reverse) overflow + matched else matched + overflow
                val failure = assertFailure { registration.call("requireQuiet", "fixture") }
                val diagnostic = diagnostic(failure)
                val expected = if (reverse) "QUEUE_SENTINEL" else "PARENT_NAME_MATCH"
                assertTrue(diagnostic.contains("reason=$expected"), diagnostic)
                assertTrue(diagnostic.contains("sequence=1"), diagnostic)
                registration.call("release")
            }
        }
    }

    @Test
    fun `bound ignored invalidates registration but retired ignored is harmless`() {
        withMonitor { monitor, fixture ->
            val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            fixture.adapter.events += event(fixture.adapter.fileWatch, mask = 0x8000)
            val failure = assertFailure { registration.call("requireQuiet", "fixture") }
            assertTrue(diagnostic(failure).contains("reason=BOUND_IGNORED"))
            registration.call("release")
        }

        withMonitor { monitor, fixture ->
            val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            registration.call("release")
            fixture.adapter.events += event(fixture.adapter.fileWatch, mask = 0x8000)
            val replacement = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            replacement.call("requireQuiet", "fixture")
            assertEquals(null, replacement.call("firstInvalidation"))
            replacement.call("release")
        }
    }

    @Test
    fun `nameless parent record invalidates registrations sharing the parent watch`() {
        withMonitor { monitor, fixture ->
            val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            fixture.adapter.events += event(fixture.adapter.parentWatch, mask = 0x100)
            val failure = assertFailure { registration.call("requireQuiet", "fixture") }
            assertTrue(diagnostic(failure).contains("reason=PARENT_NAMELESS"))
            assertTrue(diagnostic(failure).contains("scope=WATCH"))
            registration.call("release")
        }
    }

    @Test
    fun `read eof and nonretry errors reject with bounded operation evidence`() {
        for (readResult in listOf(0L, -5L)) {
            withMonitor { monitor, fixture ->
                val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                fixture.adapter.readResults += readResult
                fixture.adapter.readErrnos += 5
                val failure = assertFailure { registration.call("requireQuiet", "fixture") }
                val expected = if (readResult == 0L) "reason=READ_EOF" else "reason=READ_ERROR"
                assertTrue(diagnostic(failure).contains(expected))
                if (readResult < 0L) assertTrue(diagnostic(failure).contains("errno=5"))
                registration.call("release")
            }
        }
    }

    @Test
    fun `interrupted reads retry and nonmatching records do not invalidate`() {
        withMonitor { monitor, fixture ->
            val registration = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            fixture.adapter.readResults += -1L
            fixture.adapter.readErrnos += 4
            fixture.adapter.readResults += -1L
            fixture.adapter.readErrnos += 11
            fixture.adapter.events += event(fixture.adapter.parentWatch, mask = 0x100, name = "another.bin")
            registration.call("requireQuiet", "fixture")
            assertEquals(null, registration.call("firstInvalidation"))
            registration.call("release")
        }
    }

    @Test
    fun `one event gives shared registrations the same observation sequence`() {
        withMonitor { monitor, fixture ->
            val first = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            val second = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            fixture.adapter.events += event(fixture.adapter.fileWatch, mask = 0x8)
            val failure = assertFailure { first.call("requireQuiet", "fixture") }
            val secondEvent = second.call("firstInvalidation")
            assertNotNull(secondEvent)
            val seqGetter = secondEvent.javaClass.getDeclaredMethod("getSequence").apply { isAccessible = true }
            val elapsedGetter = secondEvent.javaClass.getDeclaredMethod("getElapsedNanos").apply { isAccessible = true }
            val firstEvent = first.call("firstInvalidation")!!
            assertEquals(1L, seqGetter.invoke(secondEvent))
            assertEquals(1L, seqGetter.invoke(firstEvent))
            assertEquals(elapsedGetter.invoke(firstEvent), elapsedGetter.invoke(secondEvent))
            assertTrue(diagnostic(failure).contains("sequence=1"))
            first.call("release")
            second.call("release")
        }
    }

    @Test
    fun `composite reports earliest component event and identifies the rejecting component`() {
        withMonitor { monitor, fixture ->
            val first = monitor.register(fixture.parent, fixture.selected, "first.bin", 0, 2)
            val second = monitor.register(fixture.parent, fixture.selected, "item.bin", 1, 2, prior = listOf(first))
            val composite = monitor.composite(listOf(first.value, second.value))

            // The later component is invalidated first; then a FILE event makes the first
            // component reject traversal with a newer sequence.
            fixture.adapter.events += event(fixture.adapter.parentWatch, 0x100, "item.bin")
            fixture.adapter.events += event(fixture.adapter.fileWatch, 0x2)
            val failure = assertFailure { composite.call("requireQuiet", "fixture") }
            val text = diagnostic(failure)
            assertTrue(text.contains("registration=2"), text)
            assertTrue(text.contains("rejectingRegistration=1"), text)
            assertTrue(text.contains("reason=PARENT_NAME_MATCH"), text)
            assertTrue(text.contains("sequence=1"), text)
            first.call("release")
            second.call("release")
        }
    }

    @Test
    fun `partial registration failure attaches earlier event before caller releases registrations`() {
        withMonitor { monitor, fixture ->
            val first = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 2)
            // The later component's entry drain observes an earlier component event and then a
            // malformed record. Its own registration has not yet been created at that point.
            fixture.adapter.events += event(fixture.adapter.parentWatch, 0x100, "item.bin")
            fixture.adapter.events += byteArrayOf(1, 2, 3)
            val failure = assertFailure {
                monitor.register(
                    fixture.parent,
                    fixture.selected,
                    "later.bin",
                    1,
                    2,
                    prior = listOf(first),
                )
            }
            val text = diagnostic(failure)
            assertTrue(text.contains("reason=PARENT_NAME_MATCH"), text)
            assertTrue(text.contains("registration=1"), text)
            assertTrue(text.contains("sequence=1"), text)
            first.call("release")
            // The suppressed diagnostic remains available after partial-composite cleanup.
            assertTrue(diagnostic(failure).contains("reason=PARENT_NAME_MATCH"))
        }
    }

    @Test
    fun `binding generation changes after retirement while old first event stays registration local`() {
        withMonitor { monitor, fixture ->
            val first = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            val firstGeneration = fieldLong(first.value, "fileGeneration")
            fixture.adapter.events += event(fixture.adapter.fileWatch, 0x2)
            assertFailure { first.call("requireQuiet", "fixture") }
            val retained = first.call("firstInvalidation")
            first.call("release")

            val second = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            val secondGeneration = fieldLong(second.value, "fileGeneration")
            assertTrue(secondGeneration > firstGeneration)
            assertEquals(null, second.call("firstInvalidation"))
            second.call("requireQuiet", "fixture")
            assertEquals(null, second.call("firstInvalidation"))
            assertNotNull(retained)
            second.call("release")
        }
    }

    @Test
    fun `registration failure retains its first event before unbinding`() {
        withMonitor { monitor, fixture ->
            fixture.adapter.enqueueAfterSelectedWatch = true
            val failure = assertFailure {
                monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            }
            assertTrue(failure.message.orEmpty().contains("mutated while its watches were registered"))
            assertTrue(diagnostic(failure).contains("reason=PARENT_NAME_MATCH"))
        }
    }

    @Test
    fun `remove watch failure invalidates remaining registrations but EINVAL does not`() {
        withMonitor { monitor, fixture ->
            val other = otherFile()
            try {
                fixture.adapter.removeErrors += 5
                val first = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                val second = monitor.register(other.parent, other.selected, "other.bin", 0, 1)
                first.call("release")
                val failure = assertFailure { second.call("requireQuiet", "fixture") }
                assertTrue(diagnostic(failure).contains("reason=REMOVE_WATCH_ERROR"))
                second.call("release")
            } finally {
                other.selected.close()
                other.parent.close()
                other.root.toFile().deleteRecursively()
            }
        }

        withMonitor { monitor, fixture ->
            val other = otherFile()
            try {
                fixture.adapter.removeErrors += 22
                val first = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
                val second = monitor.register(other.parent, other.selected, "other.bin", 0, 1)
                first.call("release")
                second.call("requireQuiet", "fixture")
                assertEquals(null, second.call("firstInvalidation"))
                second.call("release")
            } finally {
                other.selected.close()
                other.parent.close()
                other.root.toFile().deleteRecursively()
            }
        }
    }

    @Test
    fun `incompatible watch binding fails closed without changing rejection text`() {
        withMonitor { monitor, fixture ->
            val original = monitor.register(fixture.parent, fixture.selected, "item.bin", 0, 1)
            val other = otherFile()
            try {
                val failure = assertFailure {
                    // The selected inode's existing FILE watch is reused as the next parent watch.
                    monitor.register(fixture.selected, other.selected, "other.bin", 0, 2)
                }
                assertTrue(failure.message.orEmpty().contains("incompatible watch"))
                assertTrue(diagnostic(failure).contains("reason=INCOMPATIBLE_BINDING"))
            } finally {
                original.call("release")
                other.selected.close()
                other.parent.close()
                other.root.toFile().deleteRecursively()
            }
        }
    }

    private fun withMonitor(block: (PrivateMonitor, Fixture) -> Unit) {
        val root = Files.createTempDirectory("stable-monitor-diagnostics")
        val path = root.resolve("item.bin")
        Files.write(path, byteArrayOf(1, 2, 3))
        val parent = LinuxFilesystemSyscalls.openRoot(root)
        val selected = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, "item.bin")!!
        val adapter = ScriptedInotify()
        adapter.parentWatch = 101
        adapter.fileWatch = 102
        try {
            block(PrivateMonitor(adapter.proxy()), Fixture(root, parent, selected, adapter))
        } finally {
            selected.close()
            parent.close()
            root.toFile().deleteRecursively()
        }
    }

    private data class Fixture(
        val root: java.nio.file.Path,
        val parent: LinuxDescriptor,
        val selected: LinuxDescriptor,
        val adapter: ScriptedInotify,
    )

    private data class OtherFile(val root: java.nio.file.Path, val parent: LinuxDescriptor, val selected: LinuxDescriptor)

    private fun otherFile(): OtherFile {
        val root = Files.createTempDirectory("stable-monitor-other")
        Files.write(root.resolve("other.bin"), byteArrayOf(4, 5, 6))
        val parent = LinuxFilesystemSyscalls.openRoot(root)
        val selected = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, "other.bin")!!
        return OtherFile(root, parent, selected)
    }

    private class PrivateMonitor(adapter: Any) {
        private val monitorClass = Class.forName("decompengine.oracle.fulltree.StableControlFile\$MutationMonitor")
        private val monitor = monitorClass.declaredConstructors.single { it.parameterCount == 2 }.apply { isAccessible = true }
            .newInstance(adapter, { 100L })

        fun register(
            parent: LinuxDescriptor,
            selected: LinuxDescriptor,
            name: String,
            ordinal: Int,
            count: Int,
            prior: List<RegistrationHandle> = emptyList(),
        ): RegistrationHandle {
            val method = monitorClass.declaredMethods.single { it.name == "register" }.apply { isAccessible = true }
            val registration = method.invoke(
                monitor,
                parent,
                selected,
                name,
                "diagnostic fixture",
                ordinal,
                count,
                prior.map { it.value },
            )
            val compositeClass = Class.forName("decompengine.oracle.fulltree.StableControlFile\$CompositeMutationRegistration")
            val composite = compositeClass.declaredConstructors.single().apply { isAccessible = true }
                .newInstance(listOf(registration))
            return RegistrationHandle(registration, composite)
        }

        fun composite(registrations: List<Any>): RegistrationHandle {
            val compositeClass = Class.forName("decompengine.oracle.fulltree.StableControlFile\$CompositeMutationRegistration")
            val composite = compositeClass.declaredConstructors.single().apply { isAccessible = true }
                .newInstance(registrations)
            return RegistrationHandle(registrations.first(), composite)
        }

    }

    private class RegistrationHandle(val value: Any, private val composite: Any) {
        fun call(methodName: String, vararg args: Any?): Any? = (if (methodName == "requireQuiet") composite else value)
            .javaClass.declaredMethods
            .single { it.name == methodName }
            .apply { isAccessible = true }
            .invoke(if (methodName == "requireQuiet") composite else value, *args)
    }

    private class ScriptedInotify : InvocationHandler {
        val events = ArrayDeque<ByteArray>()
        val readResults = ArrayDeque<Long>()
        val readErrnos = ArrayDeque<Int>()
        val removeErrors = ArrayDeque<Int>()
        val pathWatches = LinkedHashMap<String, Int>()
        var parentWatch = 101
        var fileWatch = 102
        var enqueueAfterSelectedWatch = false
        private var nextWatch = 101
        private var lastError = 11

        fun proxy(): Any {
            val monitorClass = Class.forName("decompengine.oracle.fulltree.StableControlFile\$MutationMonitor")
            val nativeType = monitorClass.declaredClasses.single { it.simpleName == "InotifyLibC" }
            return Proxy.newProxyInstance(nativeType.classLoader, arrayOf(nativeType), this)
        }

        override fun invoke(proxy: Any?, method: java.lang.reflect.Method, args: Array<out Any?>?): Any? = when (method.name) {
            "inotify_init1" -> 88
            "inotify_add_watch" -> {
                val path = args!![1] as String
                val watch = pathWatches.getOrPut(path) { nextWatch++ }
                if (pathWatches.size == 1) parentWatch = watch else fileWatch = watch
                if (enqueueAfterSelectedWatch && pathWatches.size == 2) {
                    enqueueAfterSelectedWatch = false
                    events += event(parentWatch, 0x100, "item.bin")
                }
                watch
            }
            "inotify_rm_watch" -> {
                val errno = removeErrors.pollFirst()
                if (errno == null) 0 else {
                    Native.setLastError(errno)
                    -1
                }
            }
            "close" -> 0
            "read" -> read(args!![1] as Memory)
            else -> throw UnsupportedOperationException(method.name)
        }

        private fun read(memory: Memory): NativeLong {
            val scripted = readResults.pollFirst()
            if (scripted != null) {
                if (scripted < 0L) Native.setLastError(readErrnos.pollFirst() ?: 5)
                return NativeLong(scripted)
            }
            val event = events.pollFirst()
            if (event == null) {
                Native.setLastError(lastError)
                return NativeLong(-1)
            }
            memory.write(0, event, 0, event.size)
            return NativeLong(event.size.toLong())
        }
    }

    private companion object {
    fun event(
        watch: Int,
        mask: Int,
        name: String? = null,
        terminate: Boolean = true,
        declaredNameLength: Int? = null,
    ): ByteArray {
        if (declaredNameLength != null) {
            val bytes = ByteBuffer.allocate(16).order(ByteOrder.nativeOrder())
            bytes.putInt(watch).putInt(mask).putInt(0).putInt(declaredNameLength)
            return bytes.array()
        }
        if (name == null) {
            return ByteBuffer.allocate(16).order(ByteOrder.nativeOrder())
                .putInt(watch).putInt(mask).putInt(0).putInt(0).array()
        }
        val raw = name.toByteArray(Charsets.UTF_8)
        val paddedLength = if (terminate) ((raw.size + 1 + 3) / 4) * 4 else ((raw.size + 3) / 4) * 4
        val bytes = ByteArray(16 + paddedLength)
        if (!terminate) bytes.fill(1, 16 + raw.size, bytes.size)
        val header = ByteBuffer.wrap(bytes).order(ByteOrder.nativeOrder())
        header.putInt(watch).putInt(mask).putInt(0).putInt(paddedLength)
        System.arraycopy(raw, 0, bytes, 16, raw.size)
        return bytes
    }

    private fun assertFailure(block: () -> Unit): FullTreeControlException {
        val thrown = assertFailsWith<InvocationTargetException> { block() }
        return thrown.targetException as FullTreeControlException
    }

    private fun diagnostic(failure: FullTreeControlException): String =
        diagnosticThrowable(failure).message.orEmpty()

    private fun diagnosticThrowable(failure: FullTreeControlException): Throwable =
        failure.suppressed.single { it.javaClass.simpleName == "MutationDiagnostic" }

    private fun fieldLong(target: Any, name: String): Long =
        target.javaClass.getDeclaredField(name).apply { isAccessible = true }.getLong(target)
    }
}
