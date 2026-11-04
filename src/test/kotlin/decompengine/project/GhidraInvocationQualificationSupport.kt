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
    const val FAILURE_RECORD_LIMIT = 4096
    const val CHILD_LIMIT = 256
    private val privateMode = PosixFilePermissions.fromString("rw-------")
    fun requireProof(value: Boolean) { check(value) { "Invocation qualification proof is missing or inconsistent" } }
    fun installedProbeClasspath(jars: List<Path>, tests: Path): String =
        // Path is Iterable<Path>; append its whole location, never its individual components.
        (jars + listOf(tests)).joinToString(java.io.File.pathSeparator)
    fun bytes(input: InputStream, limit: Int = ARTIFACT_LIMIT): ByteArray = input.use {
        it.readNBytes(limit + 1).also { result -> if (result.size > limit) throw QualificationFailure(FailureCategory.OUTPUT_BOUND) }
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

    enum class Phase(val wire: String) {
        PROVENANCE_VERIFICATION("provenance_verification"), BUNDLE_SOURCE_CHECKS("bundle_source_checks"),
        INPUT_COMPILE("input_compile"), ANALYSIS_OBSERVER_OWNERSHIP("analysis_observer_ownership"),
        RECEIPT_COMPARISON("receipt_comparison"), RESULT_VALIDATION("result_validation"),
        FINAL_PROVENANCE_VERIFICATION("final_provenance_verification"), PUBLICATION("publication"),
        PROCESS_EXECUTION("process_execution"), SETUP("setup"), PROCESS_START("process_start"),
    }
    enum class FailureCategory(val wire: String) {
        ASSERTION("assertion"), IO("io"), INTERRUPTED("interrupted"), TIMEOUT("timeout"),
        OUTPUT_BOUND("output_bound"), ABNORMAL_EXIT("abnormal_exit"), READER_FAILURE("reader_failure"),
        CLEANUP_FAILURE("cleanup_failure"), OTHER("other"),
    }
    private class QualificationFailure(val fixedCategory: FailureCategory) :
        IllegalStateException("Invocation qualification proof is missing or inconsistent")
    data class CleanupFact(val attempted: Boolean = false, val acknowledged: Boolean = false, val succeeded: Boolean? = null) {
        fun json() = buildJsonObject {
            put("attempted", attempted); put("acknowledged", acknowledged)
            put("succeeded", succeeded?.let(::JsonPrimitive) ?: JsonNull)
        }
    }
    data class ProcessDiagnostic(
        val category: FailureCategory, val phase: Phase, val exitCode: Int?,
        val capturedBytes: Int?, val capturedSha256: String?, val processSettled: Boolean,
        val readerSettled: Boolean, val descendantsSettled: Boolean, val cleanupFailure: Boolean,
        val primaryCategory: FailureCategory? = category, val processAcquired: Boolean = true,
        val processCleanup: CleanupFact = CleanupFact(), val descendantCleanup: CleanupFact = CleanupFact(),
        val readerCleanup: CleanupFact = CleanupFact(), val closerCleanup: CleanupFact = CleanupFact(),
        val inputCleanup: CleanupFact = CleanupFact(), val errorCleanup: CleanupFact = CleanupFact(),
        val outputCleanup: CleanupFact = CleanupFact(),
    ) {
        fun json() = buildJsonObject {
            put("schemaVersion", 1); put("kind", "process_failure")
            put("category", category.wire); put("phase", phase.wire)
            put("primaryCategory", primaryCategory?.let { JsonPrimitive(it.wire) } ?: JsonNull)
            put("exitCode", exitCode?.let(::JsonPrimitive) ?: JsonNull)
            put("capturedBytes", capturedBytes?.let(::JsonPrimitive) ?: JsonNull)
            put("capturedSha256", capturedSha256?.let(::JsonPrimitive) ?: JsonNull)
            put("processAcquired", processAcquired)
            put("processSettled", processSettled); put("readerSettled", readerSettled)
            put("descendantsSettled", descendantsSettled); put("cleanupFailure", cleanupFailure)
            put("processCleanup", processCleanup.json()); put("descendantCleanup", descendantCleanup.json())
            put("readerCleanup", readerCleanup.json()); put("closerCleanup", closerCleanup.json())
            put("inputCleanup", inputCleanup.json()); put("errorCleanup", errorCleanup.json())
            put("outputCleanup", outputCleanup.json())
        }
    }
    private fun emit(problem: Throwable, diagnostic: ProcessDiagnostic, sink: ((ProcessDiagnostic) -> Unit)?) {
        try { sink?.invoke(diagnostic) }
        catch (_: Throwable) { problem.addSuppressed(IllegalStateException("Invocation qualification diagnostic publication failed")) }
    }
    /** Covers setup before process ownership, with unavailable capture/cleanup facts. */
    fun setupFailure(problem: Throwable, phase: Phase, sink: ((ProcessDiagnostic) -> Unit)?) {
        emit(problem, ProcessDiagnostic(failureCategory(problem), phase, null, null, null,
            false, false, false, false, processAcquired = false), sink)
    }
    fun failureCategory(problem: Throwable): FailureCategory = when (problem) {
        is QualificationFailure -> problem.fixedCategory
        is InterruptedException -> FailureCategory.INTERRUPTED
        is java.io.IOException -> FailureCategory.IO
        is IllegalStateException, is IllegalArgumentException -> FailureCategory.ASSERTION
        else -> FailureCategory.OTHER
    }
    fun sourceAnchors(problem: Throwable): JsonArray = buildJsonArray {
        problem.stackTrace.asSequence().filter { it.fileName == "GhidraInvocationQualificationSupport.kt" ||
            it.fileName == "GhidraDotDirectoryInvocationQualificationTest.kt" }
            .filter { it.lineNumber in 1..10000 }.take(4)
            .forEach { add(buildJsonObject { put("file", it.fileName); put("line", it.lineNumber) }) }
    }
    fun childFailure(phase: Phase, problem: Throwable) = buildJsonObject {
        put("schemaVersion", 1); put("kind", "child_failure"); put("category", failureCategory(problem).wire)
        put("phase", phase.wire); put("sourceAnchors", sourceAnchors(problem)); put("cleanup", "unknown")
    }
    fun publishFailure(path: Path, value: JsonObject, original: Throwable) {
        try { writeFailure(path, value) }
        catch (_: Throwable) { original.addSuppressed(IllegalStateException("Invocation qualification diagnostic publication failed")) }
    }

    /** Exclusive failure-only publication. Success publication intentionally remains unchanged. */
    fun writeFailure(path: Path, value: JsonObject) {
        val content = (value.toString() + "\n").toByteArray()
        requireProof(content.size <= FAILURE_RECORD_LIMIT)
        Files.newByteChannel(path, setOf(java.nio.file.StandardOpenOption.CREATE_NEW,
            java.nio.file.StandardOpenOption.WRITE, NOFOLLOW_LINKS),
            PosixFilePermissions.asFileAttribute(privateMode)).use { channel ->
            val buffer = java.nio.ByteBuffer.wrap(content)
            while (buffer.hasRemaining()) channel.write(buffer)
        }
        requireProof(Files.getPosixFilePermissions(path, NOFOLLOW_LINKS) == privateMode)
    }

    data class CapturedOutput(val byteCount: Int, val sha256: String?, val outputBound: Boolean)
    private fun capture(input: InputStream, limit: Int, facts: AtomicReference<CapturedOutput>): ByteArray {
        requireProof(limit in 0..ARTIFACT_LIMIT)
        val collected = java.io.ByteArrayOutputStream()
        val buffer = ByteArray(minOf(8192, limit + 1))
        // Acquisition is now observed, even when the first read fails. The closer owns close().
        facts.set(CapturedOutput(0, digest(byteArrayOf()), false))
        while (true) {
            val count = input.read(buffer, 0, minOf(buffer.size, limit - collected.size() + 1))
            if (count < 0) return collected.toByteArray()
            if (count == 0) continue
            val retained = minOf(count, limit - collected.size())
            collected.write(buffer, 0, retained)
            val overflow = count > retained
            facts.set(CapturedOutput(collected.size(), digest(collected.toByteArray()), overflow))
            if (overflow) throw QualificationFailure(FailureCategory.OUTPUT_BOUND)
        }
    }

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
            } finally { if (primary is InterruptedException) Thread.currentThread().interrupt() }
        }
    }

    /** A separate session keeps compiler/probe descendants identifiable after their parent exits. */
    fun run(command: List<String>, directory: Path, timeoutSeconds: Long, outputLimit: Int = 65536,
        diagnosticSink: ((ProcessDiagnostic) -> Unit)? = null,
        starter: (ProcessBuilder) -> Process = { it.start() },
        memberSource: ((Process) -> List<ProcessHandle>)? = null): ByteArray {
        var acquired = false
        var phase = Phase.SETUP
        try {
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
        lateinit var process: Process
        var group: Long? = null
        val retained = linkedSetOf<ProcessHandle>()
        fun members(): List<ProcessHandle> {
            memberSource?.let { return it(process) }
            return Files.list(Path.of("/proc")).use { paths ->
            process.descendants().use { descendants ->
                val handles = descendants.limit((CHILD_LIMIT + 1).toLong()).toList()
                requireProof(handles.size <= CHILD_LIMIT)
                retained.addAll(handles)
                requireProof(retained.size <= CHILD_LIMIT)
            }
            requireProof(group != null)
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
        }
        phase = Phase.PROCESS_START
        process = starter(builder)
        acquired = true
        return runOwned(process, ::members, TimeUnit.SECONDS.toMillis(timeoutSeconds), outputLimit,
            diagnosticSink = diagnosticSink, afterAcquisition = { group = process.pid() },
            retainedMembers = { retained.toList() })
        } catch (problem: Throwable) {
            if (!acquired) setupFailure(problem, phase, diagnosticSink)
            if (problem is InterruptedException) Thread.currentThread().interrupt()
            throw problem
        }
    }

    /** Injectable ownership boundary for synthetic controls; no fake can create installed evidence. */
    fun runOwned(process: Process, members: () -> List<ProcessHandle>, timeoutMillis: Long, outputLimit: Int = 65536,
        output: AtomicReference<ByteArray> = AtomicReference(), failure: AtomicReference<Throwable> = AtomicReference(),
        reader: Thread? = null, cleanupMillis: Long = 5000,
        diagnosticSink: ((ProcessDiagnostic) -> Unit)? = null,
        captureFacts: AtomicReference<CapturedOutput> = AtomicReference(),
        afterAcquisition: () -> Unit = {}, retainedMembers: () -> List<ProcessHandle> = { emptyList() },
    ): ByteArray {
        var primary: Throwable? = null
        var primaryCategory: FailureCategory? = null
        var result: ByteArray? = null
        var ownedReader: Thread? = null
        val readerAck = java.util.concurrent.atomic.AtomicBoolean()
        var processFact = CleanupFact()
        var descendantFact = CleanupFact()
        var readerFact = CleanupFact()
        val closerFact = AtomicReference(CleanupFact())
        val streamFacts = List(3) { AtomicReference(CleanupFact()) }
        val cleanupErrors = java.util.concurrent.ConcurrentLinkedQueue<Throwable>()
        var processSettled = false
        var descendantsSettled = false
        var interrupted = false
        try {
            afterAcquisition()
            ownedReader = Thread({
                try {
                    if (reader != null) reader.run()
                    else output.set(capture(process.inputStream, outputLimit, captureFacts))
                } catch (problem: Throwable) { failure.set(problem) }
                finally { readerAck.set(true) }
            }, "invocation-controlled-capture").apply { isDaemon = true }
            ownedReader.start()
            val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMillis)
            while (!process.waitFor(20, TimeUnit.MILLISECONDS)) {
                failure.get()?.let { throw it }
                if (System.nanoTime() >= end) throw QualificationFailure(FailureCategory.TIMEOUT)
                members()
            }
            val remaining = end - System.nanoTime()
            if (remaining <= 0) throw QualificationFailure(FailureCategory.TIMEOUT)
            ownedReader.join(maxOf(1, TimeUnit.NANOSECONDS.toMillis(remaining)))
            requireProof(!ownedReader.isAlive && readerAck.get())
            failure.get()?.let { throw it }
            if (process.exitValue() != 0) throw QualificationFailure(FailureCategory.ABNORMAL_EXIT)
            result = checkNotNull(output.get())
        } catch (problem: Throwable) {
            primary = problem
            // Freeze the original reason before cleanup can reveal late overflow facts.
            primaryCategory = if (problem is QualificationFailure) problem.fixedCategory
                else if (problem is InterruptedException) FailureCategory.INTERRUPTED
                else if (failure.get() === problem) FailureCategory.READER_FAILURE else failureCategory(problem)
            interrupted = problem is InterruptedException
        } finally {
            interrupted = Thread.interrupted() || interrupted
            val end = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(cleanupMillis)
            fun remaining() = maxOf(1, TimeUnit.NANOSECONDS.toMillis(end - System.nanoTime()))
            fun attempt(body: () -> Unit): Boolean = try { body(); true } catch (problem: Throwable) {
                if (problem is InterruptedException) interrupted = true
                cleanupErrors.add(problem); false
            }
            try {
                // Process reap and descendant inventory have independent outcomes, even on errors.
                var processOk = attempt { process.destroyForcibly() }
                var descendantsOk = true
                processFact = CleanupFact(attempted = true)
                descendantFact = CleanupFact(attempted = true)
                do {
                    val inventoryOk = attempt {
                        val alive = members().filter(ProcessHandle::isAlive)
                        alive.forEach { handle -> if (!attempt { handle.destroyForcibly() }) descendantsOk = false }
                        descendantsSettled = alive.isEmpty()
                    }
                    descendantsOk = inventoryOk && descendantsOk
                    if (!inventoryOk) {
                        attempt { retainedMembers().forEach { handle -> attempt { if (handle.isAlive) handle.destroyForcibly() } } }
                        break
                    }
                    var alive = true
                    if (!attempt { alive = process.isAlive }) { processOk = false; break }
                    if (!alive && descendantsSettled) break
                    try { Thread.sleep(10) } catch (_: InterruptedException) { interrupted = true }
                } while (System.nanoTime() < end)
                // Always try process reap, even when descendant enumeration failed.
                if (!attempt { requireProof(process.waitFor(remaining(), TimeUnit.MILLISECONDS) && !process.isAlive)
                    processSettled = true }) processOk = false
                descendantsSettled = false
                if (!attempt { descendantsSettled = members().none(ProcessHandle::isAlive); requireProof(descendantsSettled) })
                    descendantsOk = false
                processFact = CleanupFact(true, true, processOk && processSettled)
                descendantFact = CleanupFact(true, true, descendantsOk && descendantsSettled)
            } catch (problem: Throwable) {
                cleanupErrors.add(problem)
            } finally {
                // Getter and close are one independent attempt for EACH stream. A dead thread is not a result.
                val closerAck = java.util.concurrent.atomic.AtomicBoolean()
                var closer: Thread? = null
                closerFact.set(CleanupFact(attempted = true))
                val started = attempt {
                    closer = Thread({
                        var ok = true
                        try {
                            for (index in 0..2) {
                                streamFacts[index].set(CleanupFact(attempted = true))
                                var streamOk = false
                                try {
                                    val stream: java.io.Closeable = when (index) {
                                        0 -> process.inputStream; 1 -> process.errorStream; else -> process.outputStream
                                    }
                                    stream.close(); streamOk = true
                                } catch (problem: Throwable) { ok = false; cleanupErrors.add(problem) }
                                finally { streamFacts[index].set(CleanupFact(true, true, streamOk)) }
                            }
                        } catch (problem: Throwable) { ok = false; cleanupErrors.add(problem) }
                        finally { closerFact.set(CleanupFact(true, true, ok)); closerAck.set(true) }
                    }, "invocation-stream-close").apply { isDaemon = true }
                    closerFact.set(CleanupFact(attempted = true))
                    closer.start()
                }
                if (started) attempt {
                    settle(closer!!, {}, remaining())
                    requireProof(closerAck.get() && closerFact.get().acknowledged && closerFact.get().succeeded == true)
                }
                ownedReader?.let { thread ->
                    readerFact = CleanupFact(attempted = true)
                    val ok = attempt { settle(thread, {}, remaining()); requireProof(readerAck.get()) }
                    readerFact = CleanupFact(true, !thread.isAlive && readerAck.get(), ok)
                }
                interrupted = Thread.interrupted() || interrupted
            }
        }
        try {
            val cleanupFailure = cleanupErrors.isNotEmpty()
            val problem = primary ?: cleanupErrors.peek()
            if (problem != null) {
                cleanupErrors.forEach { if (it !== problem) problem.addSuppressed(it) }
                val captured = captureFacts.get() ?: output.get()?.let { CapturedOutput(it.size, digest(it), false) }
                emit(problem, ProcessDiagnostic(primaryCategory ?: FailureCategory.CLEANUP_FAILURE, Phase.PROCESS_EXECUTION,
                    runCatching { process.exitValue() }.getOrNull(), captured?.byteCount, captured?.sha256,
                    processSettled, readerFact.acknowledged, descendantsSettled, cleanupFailure,
                    primaryCategory, processCleanup = processFact, descendantCleanup = descendantFact,
                    readerCleanup = readerFact, closerCleanup = closerFact.get(), inputCleanup = streamFacts[0].get(),
                    errorCleanup = streamFacts[1].get(), outputCleanup = streamFacts[2].get()), diagnosticSink)
                throw problem
            }
            return checkNotNull(result)
        } finally { if (interrupted) Thread.currentThread().interrupt() }
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
