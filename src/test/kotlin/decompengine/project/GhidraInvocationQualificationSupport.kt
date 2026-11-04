package decompengine.project

import java.io.InputStream
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.*

/** Hosted qualification mechanics, never production authority. All failures use fixed diagnostics. */
internal object InvocationQualification {
    const val ARTIFACT_LIMIT = 1024 * 1024
    const val CHILD_LIMIT = 256
    private val privateMode = PosixFilePermissions.fromString("rw-------")
    fun requireProof(value: Boolean) { check(value) { "Invocation qualification proof is missing or inconsistent" } }
    fun installedProbeClasspath(jars: List<Path>, tests: Path): String =
        // Path is Iterable<Path>; append its whole location, never its individual components.
        (jars + listOf(tests)).joinToString(java.io.File.pathSeparator)
    fun bytes(input: InputStream, limit: Int = ARTIFACT_LIMIT): ByteArray = input.use {
        it.readNBytes(limit + 1).also { result -> requireProof(result.size <= limit) }
    }
    fun read(path: Path, limit: Int = ARTIFACT_LIMIT): ByteArray = bytes(Files.newInputStream(path, NOFOLLOW_LINKS), limit)
    fun command(bytes: ByteArray): List<String> {
        requireProof(bytes.isNotEmpty() && bytes.last() == 0.toByte())
        val text = Charsets.UTF_8.newDecoder().onMalformedInput(java.nio.charset.CodingErrorAction.REPORT)
            .onUnmappableCharacter(java.nio.charset.CodingErrorAction.REPORT).decode(java.nio.ByteBuffer.wrap(bytes)).toString()
        return text.dropLast(1).split('\u0000').also { requireProof(it.size <= CHILD_LIMIT) }
    }
    fun digest(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun hash(path: Path, limit: Long = 512L * 1024 * 1024): String {
        requireProof(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) <= limit)
        val md = MessageDigest.getInstance("SHA-256")
        var size = 0L
        Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
            val buffer = ByteArray(65536)
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                size += count
                requireProof(size <= limit)
                md.update(buffer, 0, count)
            }
        }
        return md.digest().joinToString("") { "%02x".format(it) }
    }
    fun publish(path: Path, content: ByteArray, limit: Int = ARTIFACT_LIMIT) {
        requireProof(content.size <= limit)
        val staged = Files.createTempFile(path.parent, "private-", ".tmp", PosixFilePermissions.asFileAttribute(privateMode))
        try {
            Files.write(staged, content)
            requireProof(Files.getPosixFilePermissions(staged, NOFOLLOW_LINKS) == privateMode)
            Files.move(staged, path, ATOMIC_MOVE, REPLACE_EXISTING)
            requireProof(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == privateMode)
        } finally { Files.deleteIfExists(staged) }
    }
    fun publish(path: Path, value: JsonObject) = publish(path, (value.toString() + "\n").toByteArray())

    data class Identity(val pid: Long, val start: String)
    /** Accumulates identities across ALL polls, including after a snapshot has been selected. */
    class Inventory {
        private val matches = linkedSetOf<Identity>()
        fun poll(children: List<Identity>, eligible: (Identity) -> Boolean) {
            requireProof(children.size <= CHILD_LIMIT)
            children.forEach { if (eligible(it)) matches += it }
            requireProof(matches.size <= 1)
        }
        fun finish() { requireProof(matches.size == 1) }
    }

    /** Joins with one allowance, even if entry is interrupted. Never mistakes a timed join for settlement. */
    fun settle(thread: Thread, signal: () -> Unit, allowanceMillis: Long = 5000) {
        var interrupted = Thread.interrupted()
        val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(allowanceMillis)
        var failure: Throwable? = null
        try {
            try { signal() } catch (problem: Throwable) { failure = problem }
            thread.interrupt()
            while (thread.isAlive && System.nanoTime() < end) {
                try { thread.join(maxOf(1, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime()))) }
                catch (_: InterruptedException) { interrupted = true }
            }
            if (thread.isAlive) {
                val unsettled = IllegalStateException("Invocation qualification observer did not settle")
                failure?.let { unsettled.addSuppressed(it) }
                throw unsettled
            }
            failure?.let { throw it }
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }
    inline fun <T> owned(cleanup: () -> Unit, body: () -> T): T {
        var primary: Throwable? = null
        try { return body() } catch (failure: Throwable) { primary = failure; throw failure }
        finally {
            try { cleanup() } catch (failure: Throwable) {
                if (primary != null) primary.addSuppressed(failure) else throw failure
            }
        }
    }

    /** A separate session keeps compiler/probe descendants identifiable after their parent exits. */
    fun run(command: List<String>, directory: Path, timeoutSeconds: Long, outputLimit: Int = 65536): ByteArray {
        val temporaryParent = directory.resolve("build/orchestration")
        Files.createDirectories(temporaryParent)
        val temporary = Files.createTempDirectory(temporaryParent, "invocation-process-")
        val builder = ProcessBuilder(listOf("setsid", "--wait") + command).directory(directory.toFile())
            .redirectErrorStream(true)
        builder.environment().apply {
            put("TMPDIR", temporary.toString()); put("TMP", temporary.toString()); put("TEMP", temporary.toString())
            // This controlled installed probe must not inherit a Java agent or alternate bootstrap path.
            listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS").forEach(::remove)
        }
        val process = builder.start()
        val output = AtomicReference<ByteArray>()
        val failure = AtomicReference<Throwable>()
        val reader = Thread({
            try { output.set(bytes(process.inputStream, outputLimit)) }
            catch (problem: Throwable) { failure.set(problem) }
        }, "invocation-bounded-capture").apply { isDaemon = true }
        val group = process.pid()
        val retained = linkedSetOf<ProcessHandle>()
        fun members(): List<ProcessHandle> = try { Files.list(Path.of("/proc")).use { paths ->
            process.descendants().use { descendants ->
                val handles = descendants.limit((CHILD_LIMIT + 1).toLong()).toList()
                requireProof(handles.size <= CHILD_LIMIT)
                retained.addAll(handles)
                requireProof(retained.size <= CHILD_LIMIT)
            }
            val all = paths.limit(32769).toList()
            requireProof(all.size <= 32768)
            all.filter { it.fileName.toString().all(Char::isDigit) }.mapNotNull { proc ->
                try {
                    val stat = read(proc.resolve("stat"), 8192).toString(Charsets.UTF_8)
                    val fields = stat.substring(stat.lastIndexOf(')') + 2).trim().split(' ')
                    if (fields[2].toLong() == group || fields[3].toLong() == group)
                        ProcessHandle.of(proc.fileName.toString().toLong()).orElse(null) else null
                } catch (problem: Exception) {
                    if (Files.exists(proc)) throw problem else null
                }
            }.let { session ->
                retained.addAll(session)
                requireProof(retained.size <= CHILD_LIMIT)
                retained.toList()
            }
        }
        } catch (failure: Throwable) {
            retained.forEach { handle ->
                try { if (handle.isAlive) handle.destroyForcibly() } catch (cleanup: Throwable) { failure.addSuppressed(cleanup) }
            }
            throw failure
        }
        return runOwned(process, ::members, TimeUnit.SECONDS.toMillis(timeoutSeconds), outputLimit, output, failure, reader)
    }

    /** Injectable ownership boundary for deterministic controls; no fake can create installed evidence. */
    fun runOwned(process: Process, members: () -> List<ProcessHandle>, timeoutMillis: Long, outputLimit: Int = 65536,
        output: AtomicReference<ByteArray> = AtomicReference(), failure: AtomicReference<Throwable> = AtomicReference(),
        reader: Thread = Thread({
            try { output.set(bytes(process.inputStream, outputLimit)) } catch (problem: Throwable) { failure.set(problem) }
        }, "invocation-controlled-capture").apply { isDaemon = true }, cleanupMillis: Long = 5000,
    ): ByteArray {
        return owned(cleanup = {
            var interrupted = Thread.interrupted()
            val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(cleanupMillis)
            try {
              owned(cleanup = {
                // A pipe close may itself block behind an in-flight read. Own its thread too;
                // never run close synchronously on the bounded cleanup caller.
                val closeFailure = AtomicReference<Throwable?>()
                val closer = Thread({
                    listOf(process.inputStream, process.errorStream, process.outputStream).forEach { stream ->
                        try { stream.close() } catch (problem: Throwable) {
                            val prior = closeFailure.get()
                            if (prior == null) closeFailure.set(problem) else prior.addSuppressed(problem)
                        }
                    }
                }, "invocation-stream-close").apply { isDaemon = true }
                owned(cleanup = {
                    settle(reader, {}, maxOf(1, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime())))
                }) {
                    closer.start()
                    settle(closer, {}, maxOf(1, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime())))
                    closeFailure.get()?.let { throw it }
                }
              }) {
                process.destroyForcibly()
                do {
                    val remaining = members().filter(ProcessHandle::isAlive)
                    remaining.forEach { it.destroyForcibly() }
                    if (!process.isAlive && remaining.isEmpty()) break
                    try { Thread.sleep(10) } catch (_: InterruptedException) { interrupted = true }
                } while (System.nanoTime() < end)
                requireProof(!process.isAlive && members().none(ProcessHandle::isAlive))
                requireProof(process.waitFor(maxOf(1, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime())), TimeUnit.MILLISECONDS))
              }
            } finally { if (interrupted) Thread.currentThread().interrupt() }
        }) {
            reader.start()
            val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            while (!process.waitFor(20, TimeUnit.MILLISECONDS)) {
                failure.get()?.let { throw it }
                requireProof(System.nanoTime() < end)
                members() // Complete bounded session inventory; errors cannot become uniqueness proof.
            }
            val remaining = end - System.nanoTime()
            requireProof(remaining > 0)
            reader.join(maxOf(1, TimeUnit.NANOSECONDS.toMillis(remaining)))
            requireProof(!reader.isAlive)
            failure.get()?.let { throw it }
            requireProof(process.exitValue() == 0)
            checkNotNull(output.get())
        }
    }

    fun verifyExporterBytes(source: ByteArray, vararg copies: ByteArray) {
        requireProof(source.isNotEmpty() && source.size <= ARTIFACT_LIMIT && copies.isNotEmpty())
        copies.forEach { requireProof(it.contentEquals(source)) }
    }
    fun verifyPins(expected: JsonObject, actual: Map<String, String>) {
        requireProof(expected.keys == actual.keys)
        expected.forEach { (name, hash) -> requireProof(hash.jsonPrimitive.content == actual[name]) }
    }
    fun validateResult(report: JsonObject, names: List<String>, projectFresh: Boolean, diagnostics: String) {
        requireProof(report["schemaVersion"]?.jsonPrimitive?.int == 2)
        requireProof(report["analysisOutcome"]?.jsonPrimitive?.content == "succeeded")
        val invocation = report.getValue("invocation").jsonObject
        mapOf("status" to "captured", "commandKind" to "bundled-java", "processStarterKind" to "default-process-builder",
            "observation" to "process-starter-returned-and-exit-value", "commandDisclosure" to "qualified-worker-fields-only")
            .forEach { (key, value) -> requireProof(invocation[key]?.jsonPrimitive?.content == value) }
        requireProof(invocation["analysisArgumentOffset"]?.jsonPrimitive?.int == 2)
        requireProof(invocation["exitCode"]?.jsonPrimitive?.int == 0)
        requireProof("main" in names && projectFresh && !diagnostics.contains("Path element starting with '.'"))
    }
    fun observedProject(arguments: List<String>, pid: Long): Path {
        requireProof(arguments.size >= 7 && arguments[1] == "await-parent-launch" && arguments[2] == "analyze")
        requireProof(arguments[3] == "/proc/self/cwd/ghidra_project")
        return Path.of("/proc", pid.toString(), "cwd", "ghidra_project").toRealPath()
    }
}
