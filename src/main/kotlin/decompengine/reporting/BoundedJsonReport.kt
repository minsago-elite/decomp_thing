package decompengine.reporting

import java.io.BufferedOutputStream
import java.io.OutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.util.concurrent.TimeUnit

/** Strings count UTF-16 code units; collection items count object fields and array entries together. */
internal data class JsonReportLimits(
    val maximumBytes: Long = 32L * 1024 * 1024,
    val maximumStringCharacters: Int = 65_536,
    val maximumCollectionItems: Long = 1_000_000,
    val maximumDepth: Int = 16,
    val maximumWallClockMillis: Long = 60_000,
) {
    init {
        require(maximumBytes in 1L..32L * 1024 * 1024)
        require(maximumStringCharacters in 1..65_536)
        require(maximumCollectionItems in 1L..1_000_000L)
        require(maximumDepth in 1..16)
        require(maximumWallClockMillis in 1L..60_000L)
    }
}

internal class JsonReportLimitException(message: String) : IllegalArgumentException(message)

/**
 * Publishes one complete report with an atomic replacement. The existing parent directory is used
 * as supplied; this is not an oracle path-authority boundary. Staged and published files have POSIX
 * owner read/write permissions (0600). Publication does not promise fsync durability or a transaction
 * across reports. Cancellation and elapsed-time limits are cooperative.
 */
internal object JsonReportPublisher {
    fun write(
        path: Path,
        limits: JsonReportLimits = JsonReportLimits(),
        checkpoint: (String) -> Unit = {},
        render: BoundedJsonReportWriter.() -> Unit,
    ) {
        val budget = JsonReportBudget(limits, checkpoint)
        budget.checkpoint("before staging JSON report")
        val target = path.toAbsolutePath()
        val parent = requireNotNull(target.parent) { "JSON report path must have a parent" }
        requireNotNull(target.fileName) { "JSON report path must name a file" }
        var temporary: Path? = null
        var primaryFailure: Throwable? = null
        try {
            val staged = Files.createTempFile(
                parent,
                ".json-report-",
                ".tmp",
                PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rw-------")),
            )
            temporary = staged
            Files.newOutputStream(
                staged,
                StandardOpenOption.WRITE,
                StandardOpenOption.TRUNCATE_EXISTING,
                LinkOption.NOFOLLOW_LINKS,
            ).use { output ->
                val writer = BoundedJsonReportWriter(BufferedOutputStream(output, 8 * 1024), limits, budget)
                budget.checkpoint("before rendering JSON report")
                writer.render()
                writer.finish()
            }
            budget.checkpoint("before publishing JSON report")
            Files.move(staged, target, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
            temporary = null
        } catch (failure: Throwable) {
            primaryFailure = failure
            throw failure
        } finally {
            temporary?.let { staged ->
                try {
                    Files.deleteIfExists(staged)
                } catch (cleanupFailure: Throwable) {
                    val original = primaryFailure
                    if (original == null) throw cleanupFailure
                    if (cleanupFailure !== original) original.addSuppressed(cleanupFailure)
                }
            }
        }
    }
}

/**
 * Streaming JSON syntax writer with bounded nesting. Callers provide unique object field names;
 * this writer does not retain emitted values or names to detect duplicates.
 */
internal class BoundedJsonReportWriter internal constructor(
    private val output: OutputStream,
    private val limits: JsonReportLimits,
    private val budget: JsonReportBudget,
) {
    private enum class Kind { OBJECT, ARRAY }
    private class Frame(val kind: Kind, var entries: Long = 0)

    private val frames = ArrayDeque<Frame>()
    private var rootWritten = false
    private var finished = false
    private var failure: Throwable? = null
    private var writtenBytes = 0L
    private var collectionItems = 0L

    fun objectValue(render: BoundedJsonReportWriter.() -> Unit) = writing {
        beforeValue()
        container(Kind.OBJECT, render)
    }

    fun arrayValue(render: BoundedJsonReportWriter.() -> Unit) = writing {
        beforeValue()
        container(Kind.ARRAY, render)
    }

    fun objectField(name: String, render: BoundedJsonReportWriter.() -> Unit) = writing {
        beforeField(name)
        container(Kind.OBJECT, render)
    }

    fun arrayField(name: String, render: BoundedJsonReportWriter.() -> Unit) = writing {
        beforeField(name)
        container(Kind.ARRAY, render)
    }

    fun field(name: String, value: String) = writing { beforeField(name); quoted(value) }
    fun field(name: String, value: Long) = writing { beforeField(name); ascii(value.toString()) }
    fun field(name: String, value: ULong) = writing { beforeField(name); ascii(value.toString()) }
    fun field(name: String, value: Boolean) = writing { beforeField(name); ascii(if (value) "true" else "false") }

    fun value(value: String) = writing { beforeValue(); quoted(value) }
    fun value(value: Long) = writing { beforeValue(); ascii(value.toString()) }
    fun value(value: ULong) = writing { beforeValue(); ascii(value.toString()) }
    fun value(value: Boolean) = writing { beforeValue(); ascii(if (value) "true" else "false") }

    internal fun finish() = writing {
        check(rootWritten && frames.isEmpty()) { "JSON report must contain one completed root value" }
        byte('\n'.code)
        output.flush()
        finished = true
    }

    private fun writing(action: () -> Unit) {
        failure?.let { throw it }
        check(!finished) { "JSON report writer is finished" }
        try {
            budget.step()
            action()
        } catch (problem: Throwable) {
            failure = problem
            throw problem
        }
    }

    private fun beforeValue() {
        val parent = frames.lastOrNull()
        if (parent == null) {
            check(!rootWritten) { "JSON report must contain only one root value" }
            rootWritten = true
        } else {
            check(parent.kind == Kind.ARRAY) { "JSON object values require named fields" }
            entry(parent)
        }
    }

    private fun beforeField(name: String) {
        val parent = frames.lastOrNull()
        check(parent != null && parent.kind == Kind.OBJECT) { "JSON fields require an object" }
        entry(parent)
        quoted(name)
        ascii(": ")
    }

    private fun entry(frame: Frame) {
        if (collectionItems >= limits.maximumCollectionItems) {
            throw JsonReportLimitException("JSON report exceeds its aggregate collection-item limit")
        }
        collectionItems++
        if (frame.entries++ > 0) byte(','.code)
        byte('\n'.code)
        indent(frames.size)
    }

    private fun container(kind: Kind, render: BoundedJsonReportWriter.() -> Unit) {
        if (frames.size >= limits.maximumDepth) {
            throw JsonReportLimitException("JSON report exceeds its nesting-depth limit")
        }
        byte(if (kind == Kind.OBJECT) '{'.code else '['.code)
        val frame = Frame(kind)
        frames.addLast(frame)
        render()
        failure?.let { throw it }
        check(frames.lastOrNull() === frame) { "JSON report container is incomplete" }
        frames.removeLast()
        if (frame.entries > 0) {
            byte('\n'.code)
            indent(frames.size)
        }
        byte(if (kind == Kind.OBJECT) '}'.code else ']'.code)
    }

    private fun quoted(value: String) {
        if (value.length > limits.maximumStringCharacters) {
            throw JsonReportLimitException("JSON report string exceeds its character limit")
        }
        byte('"'.code)
        var index = 0
        while (index < value.length) {
            budget.step()
            val character = value[index++]
            when (character) {
                '"' -> ascii("\\\"")
                '\\' -> ascii("\\\\")
                '\b' -> ascii("\\b")
                '\u000c' -> ascii("\\f")
                '\n' -> ascii("\\n")
                '\r' -> ascii("\\r")
                '\t' -> ascii("\\t")
                else -> when {
                    character.code < 0x20 -> {
                        ascii("\\u00")
                        byte(HEX_DIGITS[character.code ushr 4].code)
                        byte(HEX_DIGITS[character.code and 15].code)
                    }
                    character.isHighSurrogate() -> {
                        require(index < value.length && value[index].isLowSurrogate()) {
                            "JSON report string contains an unpaired surrogate"
                        }
                        val codePoint = Character.toCodePoint(character, value[index++])
                        byte(0xf0 or (codePoint ushr 18))
                        byte(0x80 or ((codePoint ushr 12) and 0x3f))
                        byte(0x80 or ((codePoint ushr 6) and 0x3f))
                        byte(0x80 or (codePoint and 0x3f))
                    }
                    character.isLowSurrogate() -> throw IllegalArgumentException("JSON report string contains an unpaired surrogate")
                    character.code < 0x80 -> byte(character.code)
                    character.code < 0x800 -> {
                        byte(0xc0 or (character.code ushr 6))
                        byte(0x80 or (character.code and 0x3f))
                    }
                    else -> {
                        byte(0xe0 or (character.code ushr 12))
                        byte(0x80 or ((character.code ushr 6) and 0x3f))
                        byte(0x80 or (character.code and 0x3f))
                    }
                }
            }
        }
        byte('"'.code)
    }

    private fun ascii(value: String) {
        for (character in value) byte(character.code)
    }

    private fun indent(depth: Int) {
        repeat(depth * 2) { byte(' '.code) }
    }

    private fun byte(value: Int) {
        if (writtenBytes >= limits.maximumBytes) throw JsonReportLimitException("JSON report exceeds its byte limit")
        output.write(value)
        writtenBytes++
    }

    private companion object {
        const val HEX_DIGITS = "0123456789abcdef"
    }
}

internal class JsonReportBudget(
    limits: JsonReportLimits,
    private val callerCheckpoint: (String) -> Unit,
) {
    private val startedNanos = System.nanoTime()
    private val maximumNanos = TimeUnit.MILLISECONDS.toNanos(limits.maximumWallClockMillis)
    private var stepsUntilCheckpoint = 1_024

    fun step() {
        if (--stepsUntilCheckpoint == 0) {
            checkpoint("while rendering JSON report")
            stepsUntilCheckpoint = 1_024
        }
    }

    fun checkpoint(stage: String) {
        requireCurrent(stage)
        callerCheckpoint(stage)
        requireCurrent(stage)
    }

    private fun requireCurrent(stage: String) {
        if (Thread.currentThread().isInterrupted) throw InterruptedException("JSON report publication cancelled $stage")
        val elapsed = System.nanoTime() - startedNanos
        if (elapsed < 0 || elapsed >= maximumNanos) {
            throw JsonReportLimitException("JSON report exceeded its elapsed-time limit $stage")
        }
    }
}
