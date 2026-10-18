package decompengine.mvp

import decompengine.jobs.OriginalCredentialSpanCursor
import decompengine.jobs.ProgressControlPolicy
import decompengine.repair.MAXIMUM_REPAIR_PROJECTION_BYTES
import java.util.Collections

/** Complete display projections only; authoritative source, receipts and hashes are untouched. */
internal class MvpArtifactRedactor private constructor(
    val sensitiveValues: List<String>,
    val maximumBytes: Long,
    separateLines: Boolean,
) {
    constructor(values: Collection<String>, maximumBytes: Long) : this(snapshot(values), maximumBytes, false)

    init {
        require(maximumBytes in 1..MAXIMUM_REPAIR_PROJECTION_BYTES)
    }

    private val controls = ProgressControlPolicy.removable
    private val literals = MvpArtifactLiteralIndex(
        if (separateLines) {
            sensitiveValues.asSequence().flatMap { it.lineSequence() }.map { it.replace(controls, "") }
                .filter(String::isNotBlank).distinct().sorted().toList()
        } else {
            sensitiveValues.map { it.replace(controls, "") }.filter(String::isNotEmpty).distinct().sorted()
        },
        // Splitting the same admitted inventory cannot add private units or raw entries.
        maximumPatterns = if (separateLines) 1024 * 1024 else 4096,
    )

    fun forLogLines(): MvpArtifactRedactor = MvpArtifactRedactor(sensitiveValues, maximumBytes, true)

    fun project(render: MvpArtifactText.() -> Unit): String {
        val document = MvpArtifactText(maximumBytes).apply(render)
        return projectText(document.build(), null, document.publicHashes()).text
    }

    /** Restore a safe ending while carrying producer hash ranges through every projection. */
    fun projectTerminated(render: MvpArtifactText.() -> Unit): String {
        val document = MvpArtifactText(maximumBytes).apply(render)
        var projection = projectText(document.build(), null, document.publicHashes())
        repeat(2) {
            if (projection.text.endsWith("\n")) return projection.text
            projection = projectText(projection.text + "\n", null, projection.publicHashes)
        }
        if (!projection.text.endsWith("\n")) {
            throw MvpPatchException("complete artifact line framing could not be retained")
        }
        return projection.text
    }

    fun text(value: String, normalizedMask: IntRange? = null): String =
        projectText(value, normalizedMask, emptyList()).text

    private fun projectText(value: String, normalizedMask: IntRange?, publicHashes: List<IntRange>): MvpArtifactProjection {
        artifactActive()
        MvpArtifactByteBudget(maximumBytes).charge(value)
        // Use the diagnostic control policy, without taking a prefix of complete content.
        var hashes = normalizedHashes(value, publicHashes)
        var safe = value.replace(controls, "")
        MvpArtifactByteBudget(maximumBytes).charge(safe)
        var extraMask = normalizedMask
        var original: String? = value
        repeat(8) {
            // All coverage refers to the same unchanged input, including delimiter-containing secrets.
            val next = literals.replaceProjection(safe, maximumBytes, formats, extraMask, original, hashes)
            extraMask = null
            original = null
            if (next.text == safe) return finish(next)
            safe = next.text
            hashes = next.publicHashes
        }
        return finish(MvpArtifactProjection(safe, hashes))
    }

    private fun finish(projection: MvpArtifactProjection): MvpArtifactProjection {
        val value = projection.text
        artifactActive()
        MvpArtifactByteBudget(maximumBytes).charge(value)
        if (literals.containsOutsidePublicHashes(value, projection.publicHashes) ||
            literals.replaceProjection(value, maximumBytes, formats, publicHashes = projection.publicHashes).text != value
        ) {
            throw MvpPatchException("complete artifact masking could not produce a safe projection")
        }
        return projection
    }

    private fun normalizedHashes(value: String, hashes: List<IntRange>): List<IntRange> {
        require(hashes.size <= MAXIMUM_PUBLIC_ARTIFACT_HASHES)
        var previousEnd = -1
        for (range in hashes) {
            require(!range.isEmpty() && range.first > previousEnd && range.last < value.length &&
                range.last - range.first == 63 && range.all { value[it] in "0123456789abcdef" }) {
                "public artifact commitment is invalid"
            }
            previousEnd = range.last
        }
        if (hashes.isEmpty()) return emptyList()
        var removed = 0
        var control = controls.find(value)
        return hashes.map { range ->
            while (true) {
                val match = control ?: break
                if (match.range.last >= range.first) break
                removed += match.value.length
                control = match.next()
            }
            // A validated ASCII digest cannot contain a removable control.
            val nextControl = control
            require(nextControl == null || nextControl.range.first > range.last)
            (range.first - removed)..(range.last - removed)
        }
    }

    private companion object {
        val formats = listOf(
            Regex("(?i)(\\b(?:proxy-)?authorization\\s*[:=]\\s*)basic\\s+[^\\s,;]+") to true,
            Regex("(?i)(bearer\\s+)[^\\s,;]+") to true,
            Regex("(?i)((?:api[_-]?key|access[_-]?token|password|secret|authorization)\\s*[:=]\\s*)[^\\s,;]+") to true,
            Regex("(?:sk-|ghp_|github_pat_)[A-Za-z0-9_-]+") to false,
        )

        fun snapshot(values: Collection<String>): List<String> {
            artifactActive()
            require(values.size in 0..4096) { "artifact redaction values exceed the configured limit" }
            val copy = ArrayList<String>()
            var units = 0L
            for (value in values) {
                artifactActive()
                require(copy.size < 4096 && value.length <= 1024 * 1024 - units) {
                    "artifact redaction values exceed the configured limit"
                }
                units += value.length
                copy += value
            }
            return Collections.unmodifiableList(copy.filter(String::isNotBlank).distinct())
        }
    }
}

/** Sparse Aho-Corasick index. Packed sorted edges avoid a map/object per private character. */
internal class MvpArtifactLiteralIndex(values: List<String>, maximumPatterns: Int = 4096) {
    private val offsets: IntArray
    private val labels: CharArray
    private val targets: IntArray
    private val failures: IntArray
    private val longest: IntArray

    init {
        artifactActive()
        val sorted = values.filter(String::isNotEmpty).distinct().sorted()
        val units = sorted.sumOf { it.length.toLong() }
        require(maximumPatterns in 1..1024 * 1024 && sorted.size <= maximumPatterns && units <= 1024 * 1024) {
            "artifact literal index exceeds the configured limit"
        }
        val maximumNodes = units.toInt() + 1
        failures = IntArray(maximumNodes) // Parents during construction, then failure links.
        longest = IntArray(maximumNodes)
        offsets = IntArray(maximumNodes + 1) // Child counts, then packed edge offsets.
        val nodeLabels = CharArray(maximumNodes)
        val path = IntArray((sorted.maxOfOrNull(String::length) ?: 0) + 1)
        var nodes = 1
        var previous = ""
        for (value in sorted) {
            artifactActive()
            var shared = 0
            while (shared < minOf(previous.length, value.length) && previous[shared] == value[shared]) shared++
            for (position in shared until value.length) {
                if ((position and 4095) == 0) artifactActive()
                val node = nodes++
                failures[node] = path[position]
                offsets[path[position]]++
                nodeLabels[node] = value[position]
                path[position + 1] = node
            }
            longest[path[value.length]] = value.length
            previous = value
        }
        var edge = 0
        for (node in 0 until nodes) {
            val count = offsets[node]
            offsets[node] = edge
            edge += count
        }
        offsets[nodes] = edge
        labels = CharArray(edge)
        targets = IntArray(edge)
        val cursor = offsets.copyOf(nodes)
        for (node in 1 until nodes) {
            val destination = cursor[failures[node]]++
            labels[destination] = nodeLabels[node]
            targets[destination] = node
        }
        // Lexicographic insertion already orders each state's outgoing UTF-16 units.
        var queued = 0
        var consumed = 0
        for (index in offsets[0] until offsets[1]) {
            val node = targets[index]
            failures[node] = 0
            cursor[queued++] = node
        }
        while (consumed < queued) {
            if ((consumed and 4095) == 0) artifactActive()
            val parent = cursor[consumed++]
            for (index in offsets[parent] until offsets[parent + 1]) {
                val node = targets[index]
                failures[node] = advance(failures[parent], labels[index])
                longest[node] = maxOf(longest[node], longest[failures[node]])
                cursor[queued++] = node
            }
        }
    }

    private fun edge(state: Int, unit: Char): Int {
        var low = offsets[state]
        var high = offsets[state + 1] - 1
        while (low <= high) {
            val middle = (low + high) ushr 1
            val comparison = labels[middle].compareTo(unit)
            if (comparison == 0) return targets[middle]
            if (comparison < 0) low = middle + 1 else high = middle - 1
        }
        return -1
    }

    private fun advance(initial: Int, unit: Char): Int {
        var state = initial
        var next = edge(state, unit)
        while (next < 0 && state != 0) {
            state = failures[state]
            next = edge(state, unit)
        }
        return if (next < 0) 0 else next
    }

    fun contains(source: String): Boolean {
        var state = 0
        for (position in source.indices) {
            if ((position and 4095) == 0) artifactActive()
            state = advance(state, source[position])
            if (longest[state] != 0) return true
        }
        return false
    }

    internal fun containsOutsidePublicHashes(source: String, publicHashes: List<IntRange>): Boolean {
        if (publicHashes.isEmpty()) return contains(source)
        val cursor = LiteralCursor(source)
        while (cursor.advance()) {
            val hash = overlappingPublicHash(publicHashes, cursor.start, cursor.end)
            if (hash == null || cursor.start < hash.first || cursor.end > hash.last + 1) return true
        }
        return false
    }

    private inner class LiteralCursor(private val source: String) : MvpMaskCursor {
        override var start = 0
            private set
        override var end = 0
            private set
        private var position = 0
        private var state = 0

        override fun advance(): Boolean {
            while (position < source.length) {
                if ((position and 4095) == 0) artifactActive()
                state = this@MvpArtifactLiteralIndex.advance(state, source[position++])
                val length = longest[state]
                if (length != 0) {
                    start = position - length
                    end = position
                    return true
                }
            }
            return false
        }
    }

    fun replace(
        source: String, maximumBytes: Long, formats: List<Pair<Regex, Boolean>> = emptyList(),
        normalizedMask: IntRange? = null, original: String? = null,
    ): String = replaceProjection(source, maximumBytes, formats, normalizedMask, original).text

    internal fun replaceProjection(
        source: String, maximumBytes: Long, formats: List<Pair<Regex, Boolean>> = emptyList(),
        normalizedMask: IntRange? = null, original: String? = null,
        publicHashes: List<IntRange> = emptyList(),
    ): MvpArtifactProjection {
        MvpArtifactByteBudget(maximumBytes).charge(source)
        require(formats.size <= 4) { "artifact format inventory exceeds its limit" }
        val cursors = ArrayList<MvpMaskCursor>()
        val literal = LiteralCursor(source)
        cursors += literal
        for ((pattern, prefix) in formats) cursors += MvpRegexMaskCursor(pattern, source, prefix)
        if (original != null) {
            MvpArtifactByteBudget(maximumBytes).charge(original)
            for ((pattern, prefix) in formats) cursors += MvpOriginalMaskCursor(pattern, original, prefix, source.length)
        }
        if (normalizedMask != null) {
            require(!normalizedMask.isEmpty() && normalizedMask.first >= 0 && normalizedMask.last < source.length) {
                "artifact mask exceeds admitted text"
            }
            cursors += MvpFixedMaskCursor(normalizedMask)
        }
        val ready = BooleanArray(cursors.size) { cursors[it].advance() }
        var starts = IntArray(0)
        var ends = IntArray(0)
        var size = 0
        while (true) {
            artifactActive()
            var selected = -1
            for (index in cursors.indices) {
                if (ready[index] && (selected < 0 || cursors[index].end < cursors[selected].end)) selected = index
            }
            if (selected < 0) break
            val cursor = cursors[selected]
            var start = cursor.start
            val end = cursor.end
            val hash = overlappingPublicHash(publicHashes, start, end)
            if (hash != null) {
                // Only an unrelated literal coincidence inside a trusted public digest is public.
                // Credential-format/continuation masks and matches crossing its boundary refuse.
                if (cursor === literal && start >= hash.first && end <= hash.last + 1) {
                    ready[selected] = cursor.advance()
                    continue
                }
                throw MvpPatchException("private artifact masking overlaps a public commitment")
            }
            // Each cursor advances by end position; merge their ordered coverage before replacing.
            while (size > 0 && ends[size - 1] >= start) {
                size--
                start = minOf(start, starts[size])
            }
            if (size == starts.size) {
                val capacity = maxOf(16, starts.size * 2).coerceAtMost(source.length + 1)
                starts = starts.copyOf(capacity)
                ends = ends.copyOf(capacity)
            }
            starts[size] = start
            ends[size++] = end
            ready[selected] = cursor.advance()
        }
        if (size == 0) return MvpArtifactProjection(source, publicHashes)
        val output = MvpArtifactText(maximumBytes)
        var copied = 0
        for (index in 0 until size) {
            output.append(source, copied, starts[index]).append("[REDACTED]")
            copied = ends[index]
        }
        val text = output.append(source, copied, source.length).build()
        var mask = 0
        var shift = 0
        val shiftedHashes = publicHashes.map { range ->
            while (mask < size && ends[mask] <= range.first) {
                shift = Math.addExact(shift, "[REDACTED]".length - (ends[mask] - starts[mask]))
                mask++
            }
            Math.addExact(range.first, shift)..Math.addExact(range.last, shift)
        }
        return MvpArtifactProjection(text, shiftedHashes)
    }

}

internal data class MvpArtifactProjection(val text: String, val publicHashes: List<IntRange>)

private const val MAXIMUM_PUBLIC_ARTIFACT_HASHES = 32

private fun overlappingPublicHash(hashes: List<IntRange>, start: Int, end: Int): IntRange? {
    var low = 0
    var high = hashes.size
    while (low < high) {
        val middle = (low + high) ushr 1
        if (hashes[middle].last < start) low = middle + 1 else high = middle
    }
    return hashes.getOrNull(low)?.takeIf { it.first < end }
}

private interface MvpMaskCursor {
    val start: Int
    val end: Int
    fun advance(): Boolean
}

private class MvpRegexMaskCursor(pattern: Regex, source: String, private val retainPrefix: Boolean) : MvpMaskCursor {
    private val matcher = pattern.toPattern().matcher(source)
    override var start = 0
        private set
    override var end = 0
        private set

    override fun advance(): Boolean {
        if (!matcher.find()) return false
        start = if (retainPrefix) matcher.end(1) else matcher.start()
        end = matcher.end()
        return true
    }
}

private class MvpOriginalMaskCursor(pattern: Regex, original: String, retainPrefix: Boolean,
    private val normalizedLength: Int) : MvpMaskCursor {
    private val cursor = OriginalCredentialSpanCursor(original, pattern, retainPrefix)
    override val start: Int get() = cursor.start
    override val end: Int get() = cursor.end
    override fun advance(): Boolean {
        artifactActive()
        if (!cursor.advance()) return false
        require(start >= 0 && end <= normalizedLength) { "original artifact mask exceeds admitted text" }
        return true
    }
}

private class MvpFixedMaskCursor(private val range: IntRange) : MvpMaskCursor {
    private var pending = true
    override val start: Int = range.first
    override val end: Int = range.last + 1
    override fun advance(): Boolean = pending.also { pending = false }
}

/** Admit bytes before a builder grows, including surrogate pairs formed across append calls. */
internal class MvpArtifactText(private val maximumBytes: Long) {
    private val budget = MvpArtifactByteBudget(maximumBytes)
    private val output = StringBuilder(minOf(maximumBytes, 4096).toInt())
    private val hashes = ArrayList<IntRange>()
    private var previousHigh = false

    fun append(value: String, start: Int = 0, end: Int = value.length): MvpArtifactText {
        artifactActive()
        require(start in 0..end && end <= value.length)
        if (start == end) return this
        budget.charge(value, start, end)
        if (previousHigh && value[start].isLowSurrogate()) budget.chargeBytes(2)
        output.append(value, start, end)
        previousHigh = value[end - 1].isHighSurrogate()
        return this
    }

    fun build(): String = output.toString()

    /** Trusted producer-computed public facts only; never use this for peer/configuration text. */
    fun appendSha256(value: String): MvpArtifactText {
        require(value.length == 64 && value.all { it in "0123456789abcdef" }) {
            "public artifact commitment must be a lowercase SHA-256"
        }
        require(hashes.size < MAXIMUM_PUBLIC_ARTIFACT_HASHES) { "too many public artifact commitments" }
        val start = output.length
        append(value)
        hashes += start until output.length
        return this
    }

    internal fun publicHashes(): List<IntRange> = hashes.toList()
}

private class MvpArtifactByteBudget(private val maximum: Long) {
    private var used = 0L

    init { require(maximum in 1..MAXIMUM_REPAIR_PROJECTION_BYTES) }

    fun charge(source: String, start: Int = 0, end: Int = source.length) {
        if (end - start > maximum - used) exceeded()
        var position = start
        var bytes = 0L
        while (position < end) {
            if ((position and 4095) == 0) artifactActive()
            val unit = source[position++].code
            val width = when {
                unit < 0x80 -> 1
                unit < 0x800 -> 2
                unit in 0xD800..0xDBFF && position < end && source[position].isLowSurrogate() -> { position++; 4 }
                unit in 0xD800..0xDFFF -> 1
                else -> 3
            }
            if (bytes > maximum - used - width) exceeded()
            bytes += width
        }
        chargeBytes(bytes)
    }

    fun chargeBytes(bytes: Long) {
        if (bytes < 0 || bytes > maximum - used) exceeded()
        used += bytes
    }

    private fun exceeded(): Nothing = throw MvpPatchException("complete artifact projection exceeds its byte budget")
}

private fun artifactActive() {
    if (Thread.currentThread().isInterrupted) throw InterruptedException("artifact projection interrupted")
}
