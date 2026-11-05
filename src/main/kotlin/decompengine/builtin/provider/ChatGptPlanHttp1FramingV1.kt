package decompengine.builtin.provider

import java.io.InputStream
import java.util.Collections

/** Private, pre-reserved application payload storage; excludes DNS/JSSE/JVM/native storage. */
internal class PlanHttpArenasV1 {
    val io = ByteArray(8192)
    val header = ByteArray(16384)
    val name = ByteArray(128)
    val value = ByteArray(4096)
    val outbound = ByteArray(20480)
    val status = ByteArray(1024)
    val chunk = ByteArray(1024)
    val fields = arrayOfNulls<Pair<String, String>>(64)
    var headerHighWater = 0; private set
    var fieldHighWater = 0; private set
    var materializedAscii = 0; private set
    var maximumDemand = 0; private set
    fun retainedHeader(n: Int) { headerHighWater = maxOf(headerHighWater, n) }
    fun materialized(n: Int, count: Int) { materializedAscii += n; fieldHighWater = maxOf(fieldHighWater, count) }
    fun demand(n: Int) { maximumDemand = maxOf(maximumDemand, n) }
    companion object { const val FIXED_BYTES = 51328 }
}

internal class PlanHttpBoundaryV1 : RuntimeException("plan transport boundary", null, false, false)
internal fun planHttpRequire(ok: Boolean) { if (!ok) throw PlanHttpBoundaryV1() }
internal enum class PlanHttpEndpointV1 { MODELS, RESPONSES }
internal class PlanHttpHeadersV1 internal constructor(val status: Int, fields: List<Pair<String, String>>,
    val contentLength: Long?, val chunked: Boolean) {
    val fields: List<Pair<String, String>> = Collections.unmodifiableList(fields)
    override fun toString() = "PlanHttpHeadersV1(redacted)"
}

/** Only the reserved I/O lane calls this parser. All metadata reads demand exactly one byte.
 * ASCII field values (HTAB allowed, OWS trimmed); obs-text is rejected before text creation.
 * The independent section cap includes CRLF; B's name+value+4 cap is checked separately.
 */
internal class ChatGptPlanHttp1FramingV1(
    private val input: InputStream,
    private val arena: PlanHttpArenasV1,
    private val endpoint: PlanHttpEndpointV1,
    private val successCap: Long,
    private val beforeRead: () -> Unit,
    private val observedEntity: (Int) -> Unit,
    private val observedFraming: (Int) -> Unit,
) {
    private var headers: PlanHttpHeadersV1? = null
    private var cap = successCap
    private var entity = 0L
    private var framing = 0L
    private var chunkLeft = 0L
    private var dataCrlf = false
    private var eof = false
    init { planHttpRequire(successCap in 0..Int.MAX_VALUE.toLong()) }

    private fun byte(): Int {
        beforeRead(); arena.demand(1)
        val n = input.read(arena.io, 0, 1)
        planHttpRequire(n == 1)
        // Count bytes even when a subsequent authority/grammar check fails.
        framing = Math.addExact(framing, 1L); observedFraming(1)
        planHttpRequire(framing <= envelope(entity))
        return arena.io[0].toInt() and 255
    }
    private fun line(target: ByteArray, start: Int, limit: Int, section: Boolean = false): Int {
        var p = start
        while (true) {
            val b = byte()
            planHttpRequire(p - start < limit && p < target.size)
            target[p++] = b.toByte()
            if (section) arena.retainedHeader(p)
            if (b == 13) {
                val lf = byte()
                planHttpRequire(lf == 10 && p - start < limit && p < target.size)
                target[p++] = lf.toByte()
                if (section) arena.retainedHeader(p)
                return p
            }
            planHttpRequire(b == 9 || b in 32..126)
        }
    }
    fun headers(): PlanHttpHeadersV1 {
        planHttpRequire(headers == null)
        val end = line(arena.status, 0, 1024)
        planHttpRequire(end >= 15)
        val prefix = "HTTP/1.1 "
        for (i in prefix.indices) planHttpRequire(arena.status[i].toInt() == prefix[i].code)
        planHttpRequire((9..11).all { arena.status[it].toInt() in 48..57 } && arena.status[12].toInt() == 32)
        val status = (arena.status[9] - 48) * 100 + (arena.status[10] - 48) * 10 + arena.status[11] - 48
        planHttpRequire(status in 200..599)
        val fields = section(false)
        fun one(name: String): String? {
            var result: String? = null
            for ((n, v) in fields) if (n.equals(name, true)) { planHttpRequire(result == null); result = v }
            return result
        }
        planHttpRequire(one("upgrade") == null)
        one("connection")?.let { connection ->
            var p = 0
            while (p < connection.length) {
                while (p < connection.length && ows(connection[p].code)) p++
                val start = p
                while (p < connection.length && token(connection[p].code)) p++
                planHttpRequire(p > start)
                planHttpRequire(p - start != 7 || !connection.regionMatches(start, "upgrade", 0, 7, true))
                while (p < connection.length && ows(connection[p].code)) p++
                if (p < connection.length) { planHttpRequire(connection[p++] == ',' && p < connection.length) }
            }
        }
        val length = one("content-length")?.let { decimal(it) }
        val te = one("transfer-encoding")
        planHttpRequire(te == null || te.equals("chunked", true))
        planHttpRequire(length == null || te == null)
        val encoding = one("content-encoding")
        planHttpRequire(encoding == null || encoding.equals("identity", true))
        val mime = one("content-type")
        if (status == 200) {
            if (endpoint == PlanHttpEndpointV1.MODELS) planHttpRequire(mime != null)
            mime?.let {
                val expected = if (endpoint == PlanHttpEndpointV1.MODELS) "application/json" else "text/event-stream"
                planHttpRequire(it.equals(expected, true) ||
                    Regex("${expected};[ \\t]*charset=(?:utf-8|\"utf-8\")", RegexOption.IGNORE_CASE).matches(it))
            }
        }
        cap = if (status != 200) minOf(successCap, 32768) else
            if (endpoint == PlanHttpEndpointV1.MODELS) minOf(successCap, 1048576) else successCap
        planHttpRequire(length == null || length <= cap)
        return PlanHttpHeadersV1(status, fields, length, te != null).also { headers = it }
    }
    private fun section(trailer: Boolean): List<Pair<String, String>> {
        var at = 0; var count = 0; var bBytes = 0
        while (true) {
            val end = line(arena.header, at, 16384 - at, true)
            if (end == at + 2) break
            planHttpRequire(count < 64)
            val stop = end - 2
            var colon = at
            while (colon < stop && arena.header[colon].toInt() != 58) {
                planHttpRequire(token(arena.header[colon].toInt())); colon++
            }
            val names = colon - at
            planHttpRequire(colon < stop && names in 1..128)
            val rawValues = stop - colon - 1
            planHttpRequire(rawValues <= 4096)
            var lo = colon + 1; var hi = stop
            while (lo < hi && ows(arena.header[lo].toInt())) lo++
            while (hi > lo && ows(arena.header[hi - 1].toInt())) hi--
            val values = hi - lo
            bBytes = Math.addExact(bBytes, names + values + 4)
            planHttpRequire(bBytes <= 16384)
            count++
            if (!trailer) {
                arena.header.copyInto(arena.name, 0, at, colon)
                arena.header.copyInto(arena.value, 0, lo, hi)
                val n = String(arena.name, 0, names, Charsets.US_ASCII)
                val v = String(arena.value, 0, values, Charsets.US_ASCII)
                arena.materialized(names + values, count)
                arena.fields[count - 1] = n to v
            } else {
                // Framing/routing/authentication metadata in trailers is prohibited, never merged.
                for (forbidden in arrayOf("content-length", "transfer-encoding", "content-type", "content-encoding", "host", "authorization", "trailer", "connection", "upgrade")) {
                    val equal = forbidden.length == names && forbidden.indices.all {
                        arena.header[at + it].toInt().toChar().lowercaseChar() == forbidden[it]
                    }
                    planHttpRequire(!equal)
                }
            }
            at = end
        }
        if (trailer) return emptyList()
        val result = ArrayList<Pair<String, String>>(count)
        for (i in 0 until count) { result.add(arena.fields[i]!!); arena.fields[i] = null }
        return result
    }
    fun read(demand: Int): Int {
        planHttpRequire(demand in 1..8192)
        val h = headers ?: throw PlanHttpBoundaryV1()
        if (eof) return -1
        if (h.contentLength != null && entity == h.contentLength) { eof = true; return -1 }
        if (h.chunked && chunkLeft == 0L) {
            if (dataCrlf) { planHttpRequire(byte() == 13 && byte() == 10); dataCrlf = false }
            chunkLeft = chunkSize()
            if (chunkLeft == 0L) { section(true); eof = true; return -1 }
        }
        val available = h.contentLength?.minus(entity) ?: if (h.chunked) chunkLeft else Long.MAX_VALUE
        val request = minOf(demand.toLong(), available, (cap - entity + 1).coerceAtLeast(1)).toInt()
        beforeRead(); arena.demand(request)
        val n = input.read(arena.io, 0, request)
        planHttpRequire(n == -1 || n in 1..request)
        if (n == -1) {
            planHttpRequire(h.contentLength == null && !h.chunked)
            eof = true; return -1
        }
        entity = Math.addExact(entity, n.toLong())
        observedEntity(n) // before cancellation, overflow rejection, or any owner meter
        planHttpRequire(entity <= cap)
        if (h.chunked) { chunkLeft -= n; if (chunkLeft == 0L) dataCrlf = true }
        return n
    }
    /** Host supplies validated terminal provenance later. This lower check certifies length only. */
    fun terminalLengthMatches(): Boolean = headers?.let { it.contentLength == null || it.contentLength == entity } == true
    fun completeFraming(): Boolean = eof
    fun allowsEarlyTerminal(): Boolean = endpoint == PlanHttpEndpointV1.RESPONSES
    private fun chunkSize(): Long {
        val end = line(arena.chunk, 0, 1024) - 2
        var p = 0; var size = 0L
        while (p < end) {
            val digit = hex(arena.chunk[p].toInt())
            if (digit < 0) break
            planHttpRequire(size <= (Long.MAX_VALUE - digit) / 16)
            size = size * 16 + digit; p++
        }
        planHttpRequire(p > 0)
        while (p < end) {
            while (p < end && ows(arena.chunk[p].toInt())) p++
            planHttpRequire(p < end && arena.chunk[p++].toInt() == 59)
            while (p < end && ows(arena.chunk[p].toInt())) p++
            val name = p
            while (p < end && token(arena.chunk[p].toInt())) p++
            planHttpRequire(p > name)
            val afterName = p
            while (p < end && ows(arena.chunk[p].toInt())) p++
            if (p < end && arena.chunk[p].toInt() == 61) {
                p++
                while (p < end && ows(arena.chunk[p].toInt())) p++
                planHttpRequire(p < end)
                if (arena.chunk[p].toInt() == 34) {
                    p++; var closed = false
                    while (p < end) {
                        val c = arena.chunk[p++].toInt()
                        if (c == 34) { closed = true; break }
                        if (c == 92) { planHttpRequire(p < end); val escaped = arena.chunk[p++].toInt(); planHttpRequire(escaped == 9 || escaped in 32..126) }
                        else planHttpRequire(c == 9 || c == 32 || c == 33 || c in 35..91 || c in 93..126)
                    }
                    planHttpRequire(closed)
                } else {
                    val start = p
                    while (p < end && token(arena.chunk[p].toInt())) p++
                    planHttpRequire(p > start)
                }
            } else p = afterName // BWS must precede an actual ';' or '='.
        }
        return size
    }
    companion object {
        fun envelope(entity: Long): Long = Math.addExact(34816L, Math.multiplyExact(1026L, entity))
        private fun token(c: Int) = c in 48..57 || c in 65..90 || c in 97..122 || c.toChar() in "!#$%&'*+-.^_`|~"
        private fun ows(c: Int) = c == 32 || c == 9
        private fun hex(c: Int) = when (c) { in 48..57 -> c - 48; in 65..70 -> c - 55; in 97..102 -> c - 87; else -> -1 }
        private fun decimal(s: String): Long {
            planHttpRequire(s.isNotEmpty()); var v = 0L
            for (c in s) { planHttpRequire(c in '0'..'9'); val d = c - '0'; planHttpRequire(v <= (Long.MAX_VALUE - d) / 10); v = v * 10 + d }
            return v
        }
    }
}
