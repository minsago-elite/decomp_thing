package decompengine.oracle.fulltree.repair

import decompengine.oracle.fulltree.FullTreeHeaderPlanningModule
import decompengine.repair.RepairModuleEvidence
import java.security.MessageDigest
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.*

/** Private-schema infrastructure. No OracleJson calls and no whole-document JVM decoding. */
internal class DiagnosticGraphCodec(val context: DiagnosticComputationContext) {
    val meter get() = context.meter
    val limits get() = context.limits
    fun step(phase: String, action: () -> Unit = {}) = meter.graphStep(phase, action)
    fun reserve(bytes: Long, phase: String) = context.reserve(bytes, phase)
    fun <V> table(): TreeMap<String, V> {
        reserve(64, "graph table")
        return TreeMap { a, b -> context.compareCodePoints(a, b) }
    }
    fun <V> put(table: MutableMap<String, V>, key: String, value: V) {
        if (!table.containsKey(key)) reserve(80, "graph table entry")
        table[key] = value
        step("graph table insertion")
    }
    fun <T> list(capacity: Int): ArrayList<T> {
        diagnosticCapacity(capacity >= 0)
        reserve(diagnosticAdd(64, diagnosticMultiply(capacity.toLong(), 8)), "graph reference array")
        return ArrayList(capacity)
    }
    fun <T> freeze(values: List<T>, maximum: Int = limits.jsonNodes): List<T> =
        context.graphSnapshot(values, maximum, "graph immutable snapshot")
    fun <T> map(values: List<T>, transform: (T) -> JsonElement): JsonArray {
        val result = list<JsonElement>(values.size)
        for (v in values) { step("graph row visit"); result.add(transform(v)) }
        reserve(64, "graph JSON array")
        return JsonArray(Collections.unmodifiableList(result))
    }
    fun str(value: String): JsonPrimitive {
        context.text(value)
        reserve(72, "graph JSON scalar")
        return JsonPrimitive(value)
    }
    fun num(value: Long): JsonPrimitive {
        diagnosticCapacity(value >= 0)
        reserve(112, "graph JSON integer")
        step("graph integer")
        return JsonPrimitive(value)
    }
    fun bool(value: Boolean): JsonPrimitive { reserve(72, "graph JSON boolean"); return JsonPrimitive(value) }
    fun obj(vararg fields: Pair<String, JsonElement>): JsonObject {
        val map = table<JsonElement>()
        reserve(64 + 8L * fields.size, "graph JSON object")
        for ((key, value) in fields) { diagnosticCapacity(!map.containsKey(key)); put(map, key, value) }
        return JsonObject(Collections.unmodifiableMap(map))
    }
    fun strings(values: List<String>): JsonArray = map(values, ::str)
    fun sorted(values: List<String>, maximum: Int): List<String> = diagnosticMergeSort(context, values, maximum, context::compareCodePoints)
    fun unique(values: List<String>, maximum: Int): List<String> {
        val sorted = sorted(values, maximum)
        val out = list<String>(sorted.size)
        for (v in sorted) {
            if (out.isEmpty() || context.compareCodePoints(out.last(), v) != 0) step("graph unique insertion") { out.add(v) }
        }
        return Collections.unmodifiableList(out)
    }
    fun equal(a: ByteArray, b: ByteArray): Boolean {
        meter.checkAccess()
        if (a.size != b.size) return false
        var same = true
        for (i in a.indices) step("graph byte comparison") { if (a[i] != b[i]) same = false }
        return same
    }
    fun hash(bytes: ByteArray, start: Int = 0, end: Int = bytes.size): String {
        meter.begin("before graph hash")
        diagnosticCapacity(start in 0..end && end <= bytes.size)
        reserve(256, "graph hash state")
        val md = MessageDigest.getInstance("SHA-256")
        for (i in start until end) step("graph hash") { md.update(bytes[i]) }
        reserve(192, "graph digest materialization")
        val digest = md.digest()
        val chars = CharArray(64)
        for (i in digest.indices) step("graph digest hex") {
            val b = digest[i].toInt() and 255
            chars[2*i] = "0123456789abcdef"[b ushr 4]; chars[2*i+1] = "0123456789abcdef"[b and 15]
        }
        meter.begin("before graph digest string")
        val result = String(chars)
        meter.end("after graph digest string")
        return result
    }
    fun id(role: String, binding: JsonElement, scheduler: Boolean = false): String {
        // Domains and roles are schema constants; the concatenations are bounded below 128 units.
        val domain = (if (scheduler) "full-tree-shard-scheduler-v1/" else "full-tree-shard-diagnostic-index-v1/") + role
        reserve(512, "graph identity strings")
        return role + "-" + hash(encode(obj("domain" to str(domain), "binding" to binding)))
    }
    fun without(value: JsonObject, field: String): JsonObject {
        val map = table<JsonElement>()
        for ((k,v) in value) { step("graph field visit"); if (!context.equal(k, field)) put(map,k,v) }
        reserve(64+8L*map.size, "graph JSON object")
        return JsonObject(Collections.unmodifiableMap(map))
    }
    fun withHash(value: JsonObject, field: String): Pair<JsonObject, String> {
        val hash = hash(encode(value))
        val map = table<JsonElement>()
        for ((k,v) in value) put(map,k,v)
        put(map,field,str(hash))
        reserve(64+8L*map.size,"graph hashed object")
        return JsonObject(Collections.unmodifiableMap(map)) to hash
    }
    fun fields(value: JsonObject, vararg names: String) {
        diagnosticCapacity(value.size == names.size)
        for (name in names) { step("graph schema field"); diagnosticCapacity(value.containsKey(name)) }
    }
    fun array(o: JsonObject, key: String, cap: Int): JsonArray {
        val a = o[key] as? JsonArray ?: diagnosticGraphInvalid()
        diagnosticCapacity(a.size <= cap)
        return a
    }
    fun objectValue(e: JsonElement?): JsonObject = e as? JsonObject ?: diagnosticGraphInvalid()
    fun string(e: JsonElement?): String {
        val p = e as? JsonPrimitive ?: diagnosticGraphInvalid()
        diagnosticCapacity(p.isString)
        return p.content
    }
    fun number(e: JsonElement?): Long {
        val p = e as? JsonPrimitive ?: diagnosticGraphInvalid()
        diagnosticCapacity(!p.isString && p !== JsonNull)
        val s = p.content
        diagnosticCapacity(s.isNotEmpty() && s.length <= limits.jsonNumberCharacters)
        var n = 0L
        for (c in s) step("graph numeric admission") {
            diagnosticCapacity(c in '0'..'9')
            n = diagnosticAdd(diagnosticMultiply(n,10), (c-'0').toLong())
        }
        diagnosticCapacity(s.length == 1 || s[0] != '0')
        return n
    }
    fun boolean(e: JsonElement?): Boolean {
        val p = e as? JsonPrimitive ?: diagnosticGraphInvalid()
        diagnosticCapacity(!p.isString)
        if (context.equal(p.content,"true")) return true
        diagnosticCapacity(context.equal(p.content,"false")); return false
    }
    fun requireString(e: JsonElement?, expected: String) = diagnosticCapacity(context.equal(string(e), expected))

    /** Both passes visit/emit every byte under the original meter; scratch is reserved first. */
    fun encode(value: JsonElement): ByteArray {
        meter.begin("before graph encoder measurement")
        var length = 0L
        emit(value) { _ -> length = diagnosticAdd(length,1); diagnosticCapacity(length <= limits.canonicalBytes) }
        reserve(length, "before graph encoder buffer")
        val out = ByteArray(length.toInt())
        var at = 0
        emit(value) { b -> out[at++] = b.toByte() }
        diagnosticCapacity(at == out.size)
        meter.end("after graph encoder")
        return out
    }
    private fun emit(value: JsonElement, sink: (Int) -> Unit) {
        var nodes = 0
        var stringTotal = 0L
        fun byte(b: Int) = step("graph encoder byte") { sink(b) }
        fun ascii(s: String) { for (c in s) byte(c.code) }
        fun indent(depth: Int) { repeat(depth*2) { byte(32) } }
        fun quoted(s: String) {
            var utf8 = 0
            byte(34)
            var i = 0
            while (i < s.length) {
                var cp = 0
                step("graph encoder scalar") {
                    cp = s.codePointAt(i); diagnosticCapacity(cp !in 0xD800..0xDFFF)
                    i += Character.charCount(cp)
                    utf8 += when { cp<128 -> 1; cp<2048 -> 2; cp<65536 -> 3; else -> 4 }
                    diagnosticCapacity(utf8 <= limits.stringBytes)
                }
                when (cp) {
                    34 -> ascii("\\\""); 92 -> ascii("\\\\"); 8 -> ascii("\\b"); 12 -> ascii("\\f")
                    10 -> ascii("\\n"); 13 -> ascii("\\r"); 9 -> ascii("\\t")
                    in 0..31 -> { ascii("\\u00"); byte("0123456789abcdef"[cp ushr 4].code); byte("0123456789abcdef"[cp and 15].code) }
                    in 32..127 -> byte(cp)
                    in 128..2047 -> { byte(0xc0 or (cp ushr 6)); byte(0x80 or (cp and 63)) }
                    in 2048..65535 -> { byte(0xe0 or (cp ushr 12)); byte(0x80 or ((cp ushr 6) and 63)); byte(0x80 or (cp and 63)) }
                    else -> { byte(0xf0 or (cp ushr 18)); byte(0x80 or ((cp ushr 12) and 63)); byte(0x80 or ((cp ushr 6) and 63)); byte(0x80 or (cp and 63)) }
                }
            }
            stringTotal = diagnosticAdd(stringTotal,utf8.toLong())
            diagnosticCapacity(stringTotal <= limits.totalStringBytes)
            byte(34)
        }
        fun visit(e: JsonElement, depth: Int) {
            diagnosticCapacity(depth <= limits.jsonDepth && ++nodes <= limits.jsonNodes)
            step("graph encoder node")
            when(e) {
                is JsonObject -> {
                    byte(123)
                    val keys = list<String>(e.size)
                    for (key in e.keys) step("graph encoder key") { keys.add(key) }
                    val sorted = sorted(keys,limits.jsonNodes)
                    for (i in sorted.indices) {
                        if (i == 0) byte(10) else { byte(44); byte(10) }
                        indent(depth+1); quoted(sorted[i]); ascii(": "); visit(e.getValue(sorted[i]),depth+1)
                    }
                    if (sorted.isNotEmpty()) { byte(10); indent(depth) }; byte(125)
                }
                is JsonArray -> {
                    byte(91)
                    for (i in e.indices) {
                        if(i==0) byte(10) else { byte(44); byte(10) }
                        indent(depth+1); visit(e[i],depth+1)
                    }
                    if(e.isNotEmpty()) { byte(10); indent(depth) }; byte(93)
                }
                is JsonPrimitive -> if(e.isString) quoted(e.content) else {
                    if(e !== JsonNull && !context.equal(e.content,"true") && !context.equal(e.content,"false")) number(e)
                    ascii(e.content)
                }
            }
        }
        visit(value,0); byte(10)
    }

    fun parse(bytes: ByteArray): JsonObject = parseBounded(bytes,limits.headerNodes,limits.directEdges,limits.headerObservations)

    /** Combined counts are admitted by the allocation-free structural pass, before JSON rows. */
    fun parseHeader(bytes:ByteArray,moduleCount:Int,directDependencies:Long,ownership:Long):JsonObject {
        meter.checkAccess()
        diagnosticCapacity(moduleCount in 0..limits.graphNodes && directDependencies in 0..limits.directEdges.toLong() && ownership in 0..limits.ownershipMemberships.toLong())
        return parseBounded(bytes,minOf(limits.headerNodes,limits.graphNodes-moduleCount),
            (limits.directEdges-directDependencies).toInt(),minOf(limits.headerObservations.toLong(),limits.ownershipMemberships-ownership).toInt())
    }
    private fun parseBounded(bytes:ByteArray,headerCap:Int,edgeCap:Int,observationCap:Int):JsonObject {
        meter.checkAccess()
        diagnosticCapacity(bytes.size in 1..limits.canonicalBytes)
        val retained = context.copy(bytes,"graph parser input")
        meter.begin("before graph parser admission")
        reserve(104,"graph parser admission state")
        Reader(retained,false,headerCap,edgeCap,observationCap).document() // all scalar, structure and aggregate bounds before trees
        meter.begin("before graph parser materialization")
        reserve(104,"graph parser materialization state")
        val result = objectValue(Reader(retained,true,headerCap,edgeCap,observationCap).document())
        diagnosticCapacity(equal(retained,encode(result)))
        meter.end("after graph parser")
        return result
    }
    private inner class Reader(val bytes: ByteArray, val build: Boolean, val headerCap:Int, val edgeCap:Int, val observationCap:Int) {
        var at = 0
        var nodes = 0
        var totalStrings = 0L
        fun peek(): Int = if(at < bytes.size) bytes[at].toInt() and 255 else -1
        fun take(): Int {
            var b=0
            step("graph parser byte") { diagnosticCapacity(at < bytes.size); b=bytes[at++].toInt() and 255 }
            return b
        }
        fun expect(b: Int) { diagnosticCapacity(take()==b) }
        fun ws() { while(peek()==32 || peek()==10 || peek()==13 || peek()==9) take() }
        fun document(): JsonElement? { ws(); val v=value(0); ws(); diagnosticCapacity(at==bytes.size); return v }
        fun scalar(objectKey: Boolean = false): String? {
            expect(34)
            // First pass validates the scalar and its exact UTF-16 length without materialization.
            val begin = at
            var units=0
            var utf8=0
            fun scan(write: CharArray?) {
                var out=0
                while(peek()!=34) {
                    val b=take()
                    val cp = when {
                        b==92 -> when(val e=take()) {
                            34,92 -> e; 47 -> { diagnosticCapacity(!objectKey); e }; 98 -> 8; 102 -> 12; 110 -> 10; 114 -> 13; 116 -> 9
                            117 -> {
                                fun hex(): Int {
                                    var n=0
                                    repeat(4) { val h=take(); diagnosticCapacity(!objectKey || h !in 65..70); val x=when(h) { in 48..57 -> h-48; in 97..102 -> h-87; in 65..70 -> h-55; else -> diagnosticGraphInvalid() }; n=n*16+x }
                                    return n
                                }
                                val h=hex()
                                // Array admission below compares raw schema keys. Reject alternate
                                // spellings in the structural pass, before any scalar/row allocation.
                                // Canonical Unicode is literal UTF-8; only non-short control escapes
                                // use lowercase \u00xx in a canonical object key.
                                diagnosticCapacity(!objectKey || (h in 0..31 && h != 8 && h != 9 && h != 10 && h != 12 && h != 13))
                                if(h in 0xD800..0xDBFF) { expect(92); expect(117); val l=hex(); diagnosticCapacity(l in 0xDC00..0xDFFF); 0x10000+((h-0xD800) shl 10)+(l-0xDC00) }
                                else { diagnosticCapacity(h !in 0xDC00..0xDFFF); h }
                            }
                            else -> diagnosticGraphInvalid()
                        }
                        b in 32..127 -> b
                        b in 0xc2..0xf4 -> {
                            val count=if(b<0xe0) 1 else if(b<0xf0) 2 else 3
                            var n=b and (if(count==1)31 else if(count==2)15 else 7)
                            repeat(count) { val v=take(); diagnosticCapacity(v in 0x80..0xbf); n=(n shl 6) or (v and 63) }
                            diagnosticCapacity(n >= (if(count==1)128 else if(count==2)2048 else 65536) && n<=0x10ffff && n !in 0xD800..0xDFFF)
                            n
                        }
                        else -> diagnosticGraphInvalid()
                    }
                    step("graph UTF-8 scalar") {
                        if(write==null) {
                            units += Character.charCount(cp)
                            utf8 += if(cp<128)1 else if(cp<2048)2 else if(cp<65536)3 else 4
                            diagnosticCapacity(utf8<=limits.stringBytes && units<=limits.stringBytes)
                        } else if(cp<65536) write[out++]=cp.toChar() else {
                            write[out++]=Character.highSurrogate(cp); write[out++]=Character.lowSurrogate(cp)
                        }
                    }
                }
                expect(34)
            }
            scan(null)
            totalStrings=diagnosticAdd(totalStrings,utf8.toLong()); diagnosticCapacity(totalStrings<=limits.totalStringBytes)
            if(!build) return null
            reserve(2L*units+utf8,"before graph scalar scratch")
            val chars=CharArray(units)
            val end=at; at=begin; scan(chars); diagnosticCapacity(at==end)
            // Parent amendment 2026-11-05: ONE final public JVM String construction. The private
            // validated buffer has <=4096 UTF-16 units and represents <=4096 UTF-8 bytes (or lower
            // caller limits). JVM copy/compression has no callbacks: derived maximum input gap is
            // <=8190 UTF-16 scan/copy visits on the pinned JDK (4095 units with a final non-Latin1
            // scalar require compression then UTF16 copy); the buffer itself is <=4096 units.
            // This is not a 256-unit, measured-heap or hard-realtime guarantee. No other
            // codec/traversal inherits this exception; post-checkpoint failure publishes nothing.
            meter.ensure(2L*units)
            reserve(3L*units+64,"before graph scalar result reservation")
            meter.charge(2L*units,"graph scalar final JVM work reservation")
            meter.begin("before final graph scalar String")
            val result=String(chars)
            meter.end("after final graph scalar String")
            context.text(result)
            return result
        }
        fun arrayCap(start: Int, end: Int): Int {
            val caps=listOf("modules" to limits.moduleMappings,"headerOwners" to headerCap,
                "sourceOnlyUnits" to limits.sourceOnlyUnits,"headerObservations" to observationCap,
                "directFileEdges" to edgeCap,"blockers" to limits.graphBlockers,
                "components" to limits.graphNodes,"edges" to limits.condensationEdges,
                "consumerShardIds" to limits.ownershipMemberships,"memberNodeIds" to limits.graphNodes,
                "memberShardIds" to limits.moduleMappings,"moduleIds" to limits.moduleMappings,
                "headerOwnerIds" to limits.headerNodes,"kahnOrder" to limits.graphNodes,
                "retainedCaseIds" to limits.retainedCases,"samples" to limits.observations,"groups" to limits.observations,
                "rows" to limits.observations,"invocations" to limits.failedInvocations,"actions" to limits.failedActions)
            for((key,cap) in caps) {
                if(end-start!=key.length+2)continue
                var same=true
                for(i in key.indices)step("graph parser field admission") { if(bytes[start+1+i].toInt()!=key[i].code)same=false }
                if(same)return cap
            }
            return limits.jsonNodes
        }
        fun value(depth: Int, fieldCap: Int = limits.jsonNodes): JsonElement? {
            diagnosticCapacity(depth<=limits.jsonDepth && ++nodes<=limits.jsonNodes)
            step("graph parser node"); ws()
            return when(peek()) {
                123 -> {
                    take(); ws()
                    val map=if(build)table<JsonElement>() else null
                    var count=0
                    if(peek()!=125) while(true) {
                        diagnosticCapacity(++count<=limits.jsonNodes)
                        ws(); val keyStart=at; val key=scalar(objectKey=true); val cap=arrayCap(keyStart,at); ws(); expect(58); val v=value(depth+1,cap)
                        if(build) { diagnosticCapacity(!map!!.containsKey(key!!)); put(map,key,v!!) }
                        ws(); if(peek()!=44) break; take()
                    }
                    expect(125)
                    if(build) { reserve(64+8L*count,"graph parsed object"); JsonObject(Collections.unmodifiableMap(map!!)) } else null
                }
                91 -> {
                    take(); ws()
                    // Segmented append avoids ArrayList growth's uninterruptible bulk copy.
                    val values=if(build)GraphAppend<JsonElement>(this@DiagnosticGraphCodec,limits.jsonNodes) else null
                    var count=0
                    if(peek()!=93) while(true) {
                        diagnosticCapacity(++count<=fieldCap)
                        val v=value(depth+1); if(build)values!!.add(v!!)
                        ws(); if(peek()!=44)break; take()
                    }
                    expect(93)
                    if(build) { reserve(64,"graph parsed array"); JsonArray(values!!.finish()) } else null
                }
                34 -> { val s=scalar(); if(build)str(s!!) else null }
                116,102,110 -> {
                    val word=if(peek()==116)"true" else if(peek()==102)"false" else "null"
                    for(c in word)expect(c.code)
                    if(build) if(word=="null")JsonNull else bool(word=="true") else null
                }
                else -> {
                    var n=0L; var count=0; val first=peek()
                    diagnosticCapacity(first in 48..57)
                    while(peek() in 48..57) {
                        diagnosticCapacity(++count<=limits.jsonNumberCharacters)
                        val c=take(); n=diagnosticAdd(diagnosticMultiply(n,10),(c-48).toLong())
                    }
                    diagnosticCapacity(count==1 || first!=48)
                    if(build)num(n) else null
                }
            }
        }
    }
}

internal fun diagnosticGraphInvalid(): Nothing = throw DiagnosticInputException(DiagnosticInputFailure.INVALID_OR_OVER_LIMIT)

/** Append-only segmented scratch; no hidden input-sized backing-array growth. */
internal class GraphAppend<T>(private val g: DiagnosticGraphCodec, private val maximum: Int) {
    private class Chunk<T>(val data: Array<Any?>, var next: Chunk<T>? = null)
    private var first: Chunk<T>? = null
    private var last: Chunk<T>? = null
    var size=0; private set
    init { g.reserve(64,"graph append record") }
    fun add(value: T) {
        diagnosticCapacity(size<maximum)
        if(size%128==0) {
            val capacity=minOf(128,maximum-size)
            g.reserve(64+8L*capacity,"graph append chunk")
            val chunk=Chunk<T>(arrayOfNulls(capacity))
            if(first==null)first=chunk else last!!.next=chunk
            last=chunk
        }
        g.step("graph append") { last!!.data[size%128]=value; size++ }
    }
    fun finish(): List<T> {
        val out=g.list<T>(size)
        var chunk=first
        var copied=0
        while(chunk!=null) {
            val current=chunk
            for(i in 0 until minOf(128,size-copied)) g.step("graph append copy") {
                @Suppress("UNCHECKED_CAST")
                out.add(current.data[i] as T)
            }
            copied+=current.data.size; chunk=current.next
        }
        return Collections.unmodifiableList(out)
    }
}

internal class RecordedGraphNode(internal val context:DiagnosticComputationContext, private val nodeId:String, private val nodeKind:String, private val sourcePath:String, private val shardId:String?) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    val id get()=check(nodeId); val kind get()=check(nodeKind); val path get()=check(sourcePath); val shard get()=check(shardId)
}
internal class RecordedGraphEdge(internal val context:DiagnosticComputationContext, private val consumerId:String, private val dependencyId:String) {
    val consumer get():String { context.meter.checkAccess(); return consumerId }
    val dependency get():String { context.meter.checkAccess(); return dependencyId }
}
internal class RecordedModuleOwnership(private val context:DiagnosticComputationContext, private val moduleId:String, private val shardId:String,
    private val ownedPaths:List<String>, private val entityIds:List<String>, private val dependencyContexts:List<String>) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    val id get()=check(moduleId); val shard get()=check(shardId); val paths get()=check(ownedPaths)
    val entities get()=check(entityIds); val contextPaths get()=check(dependencyContexts)
}
internal class RecordedHeaderOwnership(private val context:DiagnosticComputationContext, private val headerId:String, private val sourcePath:String, private val consumerIds:List<String>) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    val id get()=check(headerId); val path get()=check(sourcePath); val consumers get()=check(consumerIds)
}

internal class RecordedDiagnosticPlan private constructor(
    internal val context: DiagnosticComputationContext,
    private val retainedVersion: DiagnosticGraphVersion,
    private val retainedPredecessor: DiagnosticGraphVersion?,
    private val source: String,
    private val headerArtifact: String,
    private val headerReport: String,
    private val isComplete: Boolean,
    private val retainedBlockers: List<DiagnosticBlocker>,
    private val retainedNodes: List<RecordedGraphNode>,
    private val retainedEdges: List<RecordedGraphEdge>,
    private val retainedModules: List<RecordedModuleOwnership>,
    private val retainedHeaders: List<RecordedHeaderOwnership>,
    private val retainedExclusions: JsonArray,
    private val retainedObservations: JsonArray,
    private val retainedGraph: RecordedGraphTopology,
    private val retainedRecord: JsonObject,
    private val bytes: ByteArray,
) {
    internal val nodes get() = checked(retainedNodes)
    internal val edges get() = checked(retainedEdges)
    internal val modules get() = checked(retainedModules)
    internal val headers get() = checked(retainedHeaders)
    internal val exclusions get() = checked(retainedExclusions)
    internal val observations get() = checked(retainedObservations)
    internal val graph get() = checked(retainedGraph)
    internal val record get() = checked(retainedRecord)
    val version get() = checked(retainedVersion)
    val predecessor get() = checked(retainedPredecessor)
    val sourceRevisionSha256 get() = checked(source)
    val headerArtifactSha256 get() = checked(headerArtifact)
    val headerReportSha256 get() = checked(headerReport)
    val complete get() = checked(isComplete)
    val blockers get() = checked(retainedBlockers)
    val dependencyPlanSha256 get() = checked(retainedVersion.dependencyPlanSha256)
    val canonicalBytes get() = context.copy(bytes,"recorded plan getter")
    private fun <T> checked(value: T): T { context.meter.checkAccess(); return value }
    companion object {
        internal fun fromFixture(context: DiagnosticComputationContext, headerCanonicalBytes: ByteArray,
        modules: List<FullTreeHeaderPlanningModule>, moduleDependencies: List<RepairModuleEvidence>,
        sourceRevisionSha256: String, version: DiagnosticGraphVersion, predecessor: DiagnosticGraphVersion? = null): RecordedDiagnosticPlan {
        val g=DiagnosticGraphCodec(context); val l=context.limits
        context.meter.checkAccess()
        diagnosticCapacity(version.context===context && (predecessor==null || predecessor.context===context))
        diagnosticCapacity(headerCanonicalBytes.size in 1..l.canonicalBytes)
        // BOTH top-level populations before either snapshot, including size-only hostile lists.
        context.meter.guardedInput { diagnosticCapacity(modules.size in 0..l.moduleMappings && moduleDependencies.size in 0..l.moduleMappings) }
        context.meter.begin("recorded plan entry")
        val ms=context.graphSnapshot(modules,l.moduleMappings,"plan modules")
        val es=context.graphSnapshot(moduleDependencies,l.moduleMappings,"plan evidence")
        diagnosticCapacity(ms.isNotEmpty() && ms.size==es.size)
        var ownership=0L; var rawEdges=0L
        for(e in es) {
            context.meter.guardedInput {
                ownership=diagnosticAdd(ownership,diagnosticAdd(e.ownedPaths.size.toLong(),diagnosticAdd(e.entityIds.size.toLong(),e.dependencyContextPaths.size.toLong())))
                rawEdges=diagnosticAdd(rawEdges,e.dependencyModuleIds.size.toLong())
            }
            diagnosticCapacity(ownership<=l.ownershipMemberships && rawEdges<=l.directEdges)
        }
        context.digest(sourceRevisionSha256)
        val versionJson=graphVersion(g,version)
        val predecessorJson=predecessor?.let { graphVersion(g,it) }
        val blockers=GraphAppend<DiagnosticBlocker>(g,l.graphBlockers)
        if(predecessor==null) {
            if(version.dependencyGeneration!=0L || version.frozenGeneration!=0L || version.planTransitionSha256!=null)
                blockers.add(DiagnosticBlocker(context,DiagnosticBlockerCode.UNVERIFIED_TRANSITION,emptyList()))
        } else {
            var advanced=false
            fun transition(old: Long, now: Long, oldHash: String, hash: String) {
                if(old==now)diagnosticCapacity(context.equal(oldHash,hash))
                else { diagnosticCapacity(now==diagnosticAdd(old,1)); advanced=true }
            }
            transition(predecessor.dependencyGeneration,version.dependencyGeneration,predecessor.dependencyPlanSha256,version.dependencyPlanSha256)
            transition(predecessor.frozenGeneration,version.frozenGeneration,predecessor.frozenInterfaceSha256,version.frozenInterfaceSha256)
            diagnosticCapacity(advanced)
            if(version.planTransitionSha256==null)blockers.add(DiagnosticBlocker(context,DiagnosticBlockerCode.UNVERIFIED_TRANSITION,emptyList()))
        }
        val h=g.parseHeader(headerCanonicalBytes,ms.size,rawEdges,ownership)
        g.fields(h,"authority","blockers","complete","condensationDag","counts","directFileEdges","effectiveLimits","headerOwners","headerObservations","kind","modules","resolutionPolicy","schemaVersion","sourceOnlyUnits","status","reportSha256")
        g.requireString(h["kind"],"full-tree-header-module-plan-fixture-v2"); diagnosticCapacity(g.number(h["schemaVersion"])==2L)
        g.requireString(h["authority"],"fixture-resolved-non-authoritative")
        val hr=g.string(h["reportSha256"]); context.digest(hr)
        diagnosticCapacity(context.equal(hr,g.hash(g.encode(g.without(h,"reportSha256")))))
        val ha=g.hash(g.encode(h))
        val hm=g.array(h,"modules",l.moduleMappings); val hh=g.array(h,"headerOwners",l.headerNodes)
        val sx=g.array(h,"sourceOnlyUnits",l.sourceOnlyUnits); val observations=g.array(h,"headerObservations",l.headerObservations)
        val de=g.array(h,"directFileEdges",l.directEdges); val hb=g.array(h,"blockers",l.graphBlockers)
        requireHeaderRowsSorted(g,hm,"moduleId"); requireHeaderRowsSorted(g,hh,"headerOwnerId")
        requireHeaderRowsSorted(g,sx,"sourcePath","shardId")
        requireHeaderRowsSorted(g,observations,"observingModuleId","headerOwnerId")
        requireHeaderRowsSorted(g,de,"observingModuleId","consumerNodeId","dependencyHeaderOwnerId")
        requireHeaderRowsSorted(g,hb,"blockerId")
        rawEdges=diagnosticAdd(rawEdges,de.size.toLong()); diagnosticCapacity(rawEdges<=l.directEdges)
        diagnosticCapacity(hm.size==ms.size && hm.size.toLong()+hh.size<=l.graphNodes)
        ownership=diagnosticAdd(ownership,observations.size.toLong()); diagnosticCapacity(ownership<=l.ownershipMemberships)
        val supplied=g.table<FullTreeHeaderPlanningModule>()
        for(m in ms) { context.moduleId(m.moduleId); context.shardId(m.shardId); headerShard(g,m.shardId); headerSourcePath(g,m.sourcePath,false)
            diagnosticCapacity(!supplied.containsKey(m.moduleId) && m.unresolvedBlockerCount>=0); g.put(supplied,m.moduleId,m) }
        val nodes=g.table<RecordedGraphNode>(); val paths=g.table<String>(); val unresolved=g.table<Long>()
        val exclusions=g.table<Boolean>()
        for(row in sx) { val o=g.objectValue(row); g.fields(o,"ownershipStatus","shardId","sourcePath"); g.requireString(o["ownershipStatus"],"excluded-non-owning")
            val path=g.string(o["sourcePath"]); headerSourcePath(g,path,false); context.shardId(g.string(o["shardId"])); headerShard(g,g.string(o["shardId"]))
            diagnosticCapacity(!exclusions.containsKey(path)); g.put(exclusions,path,true) }
        fun addNode(id: String,kind: String,path: String,shard: String?, count: Long) {
            graphPath(g,path); diagnosticCapacity(!nodes.containsKey(id) && !paths.containsKey(path) && !exclusions.containsKey(path))
            g.reserve(96,"graph node"); g.put(nodes,id,RecordedGraphNode(context,id,kind,path,shard)); g.put(paths,path,id); g.put(unresolved,path,count)
        }
        for(row in hm) { val o=g.objectValue(row); g.fields(o,"graphNodeId","moduleId","shardId","sourcePath","unresolvedBlockerCount")
            val id=g.string(o["moduleId"]); val m=supplied[id] ?: diagnosticGraphInvalid()
            g.requireString(o["graphNodeId"],id); g.requireString(o["shardId"],m.shardId); g.requireString(o["sourcePath"],m.sourcePath)
            diagnosticCapacity(g.number(o["unresolvedBlockerCount"])==m.unresolvedBlockerCount.toLong())
            addNode(id,"module",m.sourcePath,m.shardId,m.unresolvedBlockerCount.toLong()) }
        val consumers=g.table<GraphAppend<String>>()
        for(row in hh) { val o=g.objectValue(row); g.fields(o,"graphNodeId","headerOwnerId","consumerShardIds","ownerKind","sourcePath","unresolvedBlockerCount")
            val path=g.string(o["sourcePath"]); headerSourcePath(g,path,true); val id=framedHeaderId(g,"header","decomp-full-tree-header-owner-v1-length-framed-utf8",listOf(path))
            g.requireString(o["headerOwnerId"],id); g.requireString(o["graphNodeId"],id); g.requireString(o["ownerKind"],"canonical-header-first-class-sha256")
            addNode(id,"header",path,null,g.number(o["unresolvedBlockerCount"])); g.put(consumers,id,GraphAppend(g,l.headerObservations)) }
        val observationPairs=g.table<Boolean>()
        for(row in observations) { val o=g.objectValue(row); g.fields(o,"headerOwnerId","headerPath","observingModuleId","observingShardId")
            val hid=g.string(o["headerOwnerId"]); val mid=g.string(o["observingModuleId"])
            val head=nodes[hid] ?: diagnosticGraphInvalid(); val module=supplied[mid] ?: diagnosticGraphInvalid()
            diagnosticCapacity(head.kind=="header"); g.requireString(o["headerPath"],head.path); g.requireString(o["observingShardId"],module.shardId)
            val key=g.id("header-observation",row); diagnosticCapacity(!observationPairs.containsKey(key)); g.put(observationPairs,key,true)
            consumers.getValue(hid).add(mid) }
        val headerOwners=g.list<RecordedHeaderOwnership>(hh.size)
        val observedByHeader=g.table<List<String>>()
        for(row in hh) { val o=g.objectValue(row); val id=g.string(o["headerOwnerId"])
            val ids=g.unique(consumers.getValue(id).finish(),l.headerObservations); g.put(observedByHeader,id,ids)
            val shards=g.list<String>(ids.size); for(mid in ids)shards.add(supplied.getValue(mid).shardId)
            diagnosticCapacity(g.equal(g.encode(g.strings(g.unique(shards,l.moduleMappings))),g.encode(o.getValue("consumerShardIds"))))
            g.reserve(88,"header ownership"); headerOwners.add(RecordedHeaderOwnership(context,id,nodes.getValue(id).path,ids)) }
        val edges=GraphAppend<RecordedGraphEdge>(g,l.directEdges)
        val directConsumers=g.table<Boolean>()
        for(row in de) { val o=g.objectValue(row); g.fields(o,"consumerNodeId","consumerPath","dependencyHeaderOwnerId","dependencyHeaderPath","observingModuleId","observingShardId")
            val mid=g.string(o["observingModuleId"]); val m=supplied[mid] ?: diagnosticGraphInvalid()
            g.requireString(o["observingShardId"],m.shardId)
            val a=paths[g.string(o["consumerPath"])] ?: diagnosticGraphInvalid(); val b=paths[g.string(o["dependencyHeaderPath"])] ?: diagnosticGraphInvalid()
            diagnosticCapacity(nodes.getValue(b).kind=="header"); g.requireString(o["consumerNodeId"],a); g.requireString(o["dependencyHeaderOwnerId"],b)
            fun observed(id: String) { diagnosticCapacity(observedByHeader[id]?.any { context.equal(it,mid) }==true) }
            observed(b); if(nodes.getValue(a).kind=="module")diagnosticCapacity(context.equal(a,mid)) else observed(a)
            g.put(directConsumers,a,true); g.reserve(80,"graph edge"); edges.add(RecordedGraphEdge(context,a,b)) }
        val headerEdges=edges.finish()
        val headerTopology=computeRecordedTopology(g,tableValues(g,nodes),headerEdges)
        validateHeaderTopology(g,h,headerTopology,nodes,observedByHeader)
        val blockerCounts=g.table<Long>(); val blockerIds=g.table<Boolean>()
        for(row in hb) { val o=g.objectValue(row); g.fields(o,"blockerId","consumerNodeId","consumerPath","evidenceSha256","kind")
            val path=g.string(o["consumerPath"]); val kind=g.string(o["kind"]); val evidence=g.string(o["evidenceSha256"]); context.digest(evidence)
            val allowed=listOf("ambiguous","compiler-trace-unauthenticated","conditional","external-include","macro","module-import","nonstandard","non-header-project-target","out-of-scope-consumer","generated-input-missing","unresolved")
            diagnosticCapacity(allowed.any { context.equal(it,kind) }); val node=paths[path] ?: diagnosticGraphInvalid(); g.requireString(o["consumerNodeId"],node)
            val id=framedHeaderId(g,"blocker","decomp-full-tree-header-blocker-v1-length-framed-utf8",listOf(path,kind,evidence)); g.requireString(o["blockerId"],id)
            diagnosticCapacity(!blockerIds.containsKey(id)); g.put(blockerIds,id,true); g.put(blockerCounts,path,diagnosticAdd(blockerCounts[path] ?: 0,1)) }
        for((path,count) in unresolved)diagnosticCapacity(count==(blockerCounts[path] ?: 0L))
        val complete=g.boolean(h["complete"]); diagnosticCapacity(complete==hb.isEmpty())
        g.requireString(h["status"],if(complete)"complete" else "incomplete-accounted-blockers")
        if(!complete)blockers.add(DiagnosticBlocker(context,DiagnosticBlockerCode.INCOMPLETE_GRAPH,tableKeys(g,blockerIds)))
        validateHeaderCounts(g,h,hm.size,hh.size,sx.size,observations.size,de.size,hb.size,headerTopology,nodes,observedByHeader,directConsumers)
        val ownershipRows=g.table<RecordedModuleOwnership>()
        for(e in es) {
            val m=supplied[e.id] ?: diagnosticGraphInvalid(); diagnosticCapacity(!ownershipRows.containsKey(e.id))
            val owned=context.graphSnapshot(e.ownedPaths,l.ownershipMemberships,"owned paths")
            val entity=context.graphSnapshot(e.entityIds,l.ownershipMemberships,"owned entities")
            val cp=context.graphSnapshot(e.dependencyContextPaths,l.ownershipMemberships,"dependency context paths")
            val deps=context.graphSnapshot(e.dependencyModuleIds,l.directEdges,"explicit dependencies")
            var primary=false
            for(path in owned) { graphPath(g,path); if(context.equal(path,m.sourcePath))primary=true
                diagnosticCapacity(!exclusions.containsKey(path) && (paths[path]==null || nodes.getValue(paths.getValue(path)).kind!="header")) }
            diagnosticCapacity(primary); for(path in cp)graphPath(g,path); for(id in entity)context.text(id,nonempty=true,controls=false)
            for(id in deps) { diagnosticCapacity(supplied.containsKey(id) && !context.equal(id,e.id)); g.reserve(80,"module dependency"); edges.add(RecordedGraphEdge(context,e.id,id)) }
            g.reserve(104,"module ownership")
            g.put(ownershipRows,e.id,RecordedModuleOwnership(context,e.id,m.shardId,g.unique(owned,l.ownershipMemberships),g.unique(entity,l.ownershipMemberships),g.unique(cp,l.ownershipMemberships)))
        }
        val allEdges=canonicalEdges(g,edges.finish()); val allNodes=tableValues(g,nodes); val owners=tableValues(g,ownershipRows)
        val sortedHeaders=diagnosticMergeSort(context,headerOwners,l.headerNodes) { a,b -> context.compareCodePoints(a.id,b.id) }
        val graphBinding=g.obj("kind" to g.str("recorded-scheduler-graph-v1"),"planningArtifactSha256" to g.str(version.planningArtifactSha256),
            "headerArtifactSha256" to g.str(ha),"nodes" to g.map(allNodes) { n -> g.obj("nodeId" to g.str(n.id),"kind" to g.str(n.kind),"sourcePath" to g.str(n.path),"shardId" to (n.shard?.let(g::str) ?: JsonNull)) },
            "ownership" to g.obj("modules" to g.map(owners) { m -> g.obj("id" to g.str(m.id),"shardId" to g.str(m.shard),"ownedPaths" to g.strings(m.paths),"entityIds" to g.strings(m.entities),"dependencyContextPaths" to g.strings(m.contextPaths)) },
                "headers" to g.map(sortedHeaders) { x -> g.obj("headerOwnerId" to g.str(x.id),"sourcePath" to g.str(x.path),"consumerModuleIds" to g.strings(x.consumers)) },
                "sourceOnlyUnits" to g.map(sx) { r -> val o=g.objectValue(r); g.obj("shardId" to o.getValue("shardId"),"sourcePath" to o.getValue("sourcePath")) }),
            "edges" to g.map(allEdges) { e -> g.obj("consumerNodeId" to g.str(e.consumer),"dependencyNodeId" to g.str(e.dependency)) },"blockers" to hb)
        diagnosticCapacity(context.equal(version.dependencyPlanSha256,g.hash(g.encode(graphBinding))))
        val topology=computeRecordedTopology(g,allNodes,allEdges)
        val retainedBlockers=blockers.finish()
        val record=g.obj("kind" to g.str("recorded-diagnostic-plan-v1"),"version" to versionJson,"predecessor" to (predecessorJson ?: JsonNull),
            "sourceRevisionSha256" to g.str(sourceRevisionSha256),"headerArtifactSha256" to g.str(ha),"headerReportSha256" to g.str(hr),
            "header" to h,"graph" to graphBinding,"blockers" to g.map(retainedBlockers) { graphBlocker(g,it) },"complete" to g.bool(complete))
        val bytes=g.encode(record)
        context.reserve(256,"recorded plan result"); context.meter.end("recorded plan exit")
        return RecordedDiagnosticPlan(context,version,predecessor,sourceRevisionSha256,ha,hr,complete,retainedBlockers,allNodes,allEdges,
            owners,sortedHeaders,sx,observations,topology,record,bytes)
    }
    }
}

internal fun graphVersion(g: DiagnosticGraphCodec, v: DiagnosticGraphVersion): JsonObject {
    diagnosticCapacity(v.context === g.context && v.schema==1 && v.dependencyGeneration>=0 && v.frozenGeneration>=0)
    g.context.digest(v.planningArtifactSha256); g.context.digest(v.planningReportSha256)
    g.context.digest(v.planningConfigurationSha256); g.context.digest(v.dependencyPlanSha256)
    g.context.digest(v.frozenInterfaceSha256); v.planTransitionSha256?.let(g.context::digest)
    return g.obj("schema" to g.num(v.schema.toLong()),"planningArtifactSha256" to g.str(v.planningArtifactSha256),
        "planningReportSha256" to g.str(v.planningReportSha256),"planningConfigurationSha256" to g.str(v.planningConfigurationSha256),
        "dependencyPlanSha256" to g.str(v.dependencyPlanSha256),"dependencyGeneration" to g.num(v.dependencyGeneration),
        "frozenInterfaceSha256" to g.str(v.frozenInterfaceSha256),"frozenGeneration" to g.num(v.frozenGeneration),
        "planTransitionSha256" to (v.planTransitionSha256?.let(g::str) ?: JsonNull))
}
internal fun graphOwner(g: DiagnosticGraphCodec, o: DiagnosticOwner): JsonObject {
    diagnosticCapacity(o.context === g.context)
    return when(o) {
        is DiagnosticOwner.Module -> { g.context.moduleId(o.moduleId); g.context.shardId(o.shardId)
            g.obj("kind" to g.str("module"),"moduleId" to g.str(o.moduleId),"shardId" to g.str(o.shardId)) }
        is DiagnosticOwner.Shared -> { g.context.text(o.headerOwnerId); val ids=g.context.graphSnapshot(o.consumerModuleIds,g.limits.moduleMappings,"shared consumer admission")
            for(id in ids)g.context.moduleId(id)
            g.obj("kind" to g.str("shared"),"headerOwnerId" to g.str(o.headerOwnerId),"consumerModuleIds" to g.strings(g.unique(ids,g.limits.moduleMappings))) }
        is DiagnosticOwner.External -> g.obj("kind" to g.str("external"),"boundaryId" to g.str(o.boundaryId))
        is DiagnosticOwner.Unknown -> g.obj("kind" to g.str("unknown"),"reason" to g.str(o.reason))
        is DiagnosticOwner.Unclassified -> g.obj("kind" to g.str("unclassified"),"reason" to g.str(o.reason))
        is DiagnosticOwner.Conflict -> g.obj("kind" to g.str("conflict"),"evidenceIds" to g.strings(g.unique(o.evidenceIds,g.limits.observations)))
    }
}
internal fun graphBlocker(g: DiagnosticGraphCodec, b: DiagnosticBlocker): JsonObject {
    diagnosticCapacity(b.context===g.context)
    return g.obj("code" to g.str(b.code.name),"evidenceIds" to g.strings(g.unique(b.evidenceIds,g.limits.observations)))
}
internal fun graphPath(g: DiagnosticGraphCodec, path: String) {
    g.context.text(path,nonempty=true,controls=false)
    var segment=0; var dots=true
    for(c in path)g.step("graph path admission") {
        diagnosticCapacity(c!='\\' && c!=':' && c.code>=32 && c.code!=127)
        if(c=='/') { diagnosticCapacity(segment>0 && !(dots && segment<=2)); segment=0; dots=true }
        else { segment++; if(c!='.')dots=false }
    }
    diagnosticCapacity(segment>0 && !(dots && segment<=2))
}
internal fun framedHeaderId(g: DiagnosticGraphCodec, prefix: String, domain: String, fields: List<String>): String {
    val scratch=GraphAppend<Byte>(g,g.limits.canonicalBytes)
    fun uint(n: Int) { for(shift in listOf(24,16,8,0))scratch.add((n ushr shift).toByte()) }
    fun text(value: String) {
        // Upstream header schema admits only portable ASCII paths and schema constants/IDs.
        g.context.text(value)
        uint(value.length)
        for(c in value) { diagnosticCapacity(c.code<=127); scratch.add(c.code.toByte()) }
    }
    text(domain); uint(fields.size); for(f in fields)text(f)
    val list=scratch.finish(); g.reserve(list.size.toLong(),"header identity bytes")
    val bytes=ByteArray(list.size)
    for(i in list.indices)g.step("header identity copy") { bytes[i]=list[i] }
    g.reserve(256,"header identity result")
    return prefix+"-"+g.hash(bytes)
}

internal object RecordedDiagnosticPlans {
    fun fromFixture(context:DiagnosticComputationContext,headerCanonicalBytes:ByteArray,modules:List<FullTreeHeaderPlanningModule>,
        moduleDependencies:List<RepairModuleEvidence>,sourceRevisionSha256:String,version:DiagnosticGraphVersion,predecessor:DiagnosticGraphVersion?=null):RecordedDiagnosticPlan =
        RecordedDiagnosticPlan.fromFixture(context,headerCanonicalBytes,modules,moduleDependencies,sourceRevisionSha256,version,predecessor)
}

internal fun <T> tableValues(g: DiagnosticGraphCodec, map: Map<String,T>): List<T> {
    val values=g.list<T>(map.size); for(v in map.values)g.step("graph table values") { values.add(v) }; return Collections.unmodifiableList(values)
}
internal fun tableKeys(g: DiagnosticGraphCodec, map: Map<String,*>): List<String> {
    val values=g.list<String>(map.size); for(v in map.keys)g.step("graph table keys") { values.add(v) }; return Collections.unmodifiableList(values)
}

private fun validateHeaderTopology(g:DiagnosticGraphCodec,h:JsonObject,t:RecordedGraphTopology,nodes:Map<String,RecordedGraphNode>,observed:Map<String,List<String>>) {
    val dag=g.objectValue(h["condensationDag"])
    g.fields(dag,"complete","components","edgeDirection","edges","kahnOrder","graphSemantics","ordering")
    diagnosticCapacity(g.boolean(dag["complete"])==g.boolean(h["complete"]))
    g.requireString(dag["edgeDirection"],"dependency-component-before-consumer-component")
    g.requireString(dag["graphSemantics"],"union-may-graph-across-contextual-per-tu-direct-edges")
    g.requireString(dag["ordering"],"unicode-code-point-id-with-code-point-priority-kahn")
    val expected=g.table<JsonObject>(); val upstreamIds=g.list<String>(t.components.size)
    for(c in t.components) {
        val id=framedHeaderId(g,"scc","decomp-full-tree-header-scc-v1-length-framed-utf8",c.members); upstreamIds.add(id)
        val headers=g.list<String>(c.members.size); val modules=g.list<String>(c.members.size)
        val memberShards=g.list<String>(c.members.size); val consumers=GraphAppend<String>(g,g.limits.ownershipMemberships)
        for(n in c.members) { val node=nodes.getValue(n)
            if(node.kind=="module") { modules.add(n); memberShards.add(node.shard!!); consumers.add(node.shard!!) }
            else { headers.add(n); for(mid in observed.getValue(n))consumers.add(nodes.getValue(mid).shard!!) }
        }
        val consumerShards=g.unique(consumers.finish(),g.limits.ownershipMemberships)
        g.put(expected,id,g.obj("componentId" to g.str(id),"consumerShardIds" to g.strings(consumerShards),"crossShardConsumer" to g.bool(consumerShards.size>1),
            "headerOwnerIds" to g.strings(headers),"memberNodeIds" to g.strings(c.members),"memberShardIds" to g.strings(g.unique(memberShards,g.limits.moduleMappings)),"moduleIds" to g.strings(modules)))
    }
    diagnosticCapacity(g.equal(g.encode(g.map(tableValues(g,expected)) { it }),g.encode(dag.getValue("components"))))
    val edges=GraphAppend<JsonObject>(g,g.limits.condensationEdges)
    for(i in t.components.indices)for(child in t.consumers[i])edges.add(g.obj("consumerComponentId" to g.str(upstreamIds[child]),"dependencyComponentId" to g.str(upstreamIds[i])))
    // Upstream orders by dependency then consumer component ID.
    val sorted=diagnosticMergeSort(g.context,edges.finish(),g.limits.condensationEdges) { a,b ->
        val c=g.context.compareCodePoints(g.string(a["dependencyComponentId"]),g.string(b["dependencyComponentId"]))
        if(c!=0)c else g.context.compareCodePoints(g.string(a["consumerComponentId"]),g.string(b["consumerComponentId"])) }
    diagnosticCapacity(g.equal(g.encode(g.map(sorted) { it }),g.encode(dag.getValue("edges"))))
    g.reserve(4L*t.components.size,"header Kahn degrees"); val indegree=IntArray(t.components.size)
    val ready=g.table<Int>(); for(i in t.components.indices) { indegree[i]=t.dependencies[i].size; if(indegree[i]==0)g.put(ready,upstreamIds[i],i) }
    val order=g.list<String>(t.components.size)
    while(ready.isNotEmpty()) { val entry=ready.pollFirstEntry(); order.add(entry.key); g.step("header Kahn")
        for(child in t.consumers[entry.value]) { g.step("header Kahn edge") { indegree[child]-- }; if(indegree[child]==0)g.put(ready,upstreamIds[child],child) } }
    diagnosticCapacity(g.equal(g.encode(g.strings(order)),g.encode(dag.getValue("kahnOrder"))))
}
private fun validateHeaderCounts(g:DiagnosticGraphCodec,h:JsonObject,m:Int,headers:Int,sx:Int,obs:Int,edges:Int,blockers:Int,
    t:RecordedGraphTopology,nodes:Map<String,RecordedGraphNode>,observed:Map<String,List<String>>,direct:Map<String,Boolean>) {
    val counts=g.objectValue(h["counts"])
    g.fields(counts,"canonicalHeaders","condensationComponents","condensationEdges","crossShardConsumerComponents","directFileEdges","graphNodes","headerObservations","isolatedModules","planningModules","resolutionBlockers","sourceOnlyUnits","sharedAcrossShardsHeaders","unreferencedHeaders","workUnits")
    fun eq(key:String,n:Long)=diagnosticCapacity(g.number(counts[key])==n)
    eq("canonicalHeaders",headers.toLong()); eq("planningModules",m.toLong()); eq("graphNodes",nodes.size.toLong())
    eq("sourceOnlyUnits",sx.toLong()); eq("headerObservations",obs.toLong()); eq("directFileEdges",edges.toLong()); eq("resolutionBlockers",blockers.toLong())
    eq("condensationComponents",t.components.size.toLong())
    var dagEdges=0L; for(row in t.consumers)dagEdges=diagnosticAdd(dagEdges,row.size.toLong()); eq("condensationEdges",dagEdges)
    var isolated=0L; for(n in nodes.values) { g.step("header counts"); if(n.kind=="module" && !direct.containsKey(n.id))isolated++ }; eq("isolatedModules",isolated)
    var unreferenced=0L; var shared=0L
    for(ids in observed.values) { if(ids.isEmpty())unreferenced++; val shards=g.list<String>(ids.size); for(id in ids)shards.add(nodes.getValue(id).shard!!)
        if(g.unique(shards,g.limits.headerObservations).size>1)shared++ }
    eq("unreferencedHeaders",unreferenced); eq("sharedAcrossShardsHeaders",shared)
    var cross=0L
    for(c in t.components) { val shards=GraphAppend<String>(g,g.limits.ownershipMemberships)
        for(id in c.members) { val n=nodes.getValue(id); if(n.shard!=null)shards.add(n.shard!!) else for(mid in observed.getValue(id))shards.add(nodes.getValue(mid).shard!!) }
        if(g.unique(shards.finish(),g.limits.ownershipMemberships).size>1)cross++ }
    eq("crossShardConsumerComponents",cross); g.number(counts["workUnits"])
    val limits=g.objectValue(h["effectiveLimits"])
    g.fields(limits,"maximumBlockers","maximumCondensationEdges","maximumDirectEdges","maximumGraphNodes","maximumHeaderObservations","maximumHeaders","maximumModules","maximumSerializedBytes","maximumSourceOnlyUnits","maximumWorkUnits")
    for((_,v) in limits)diagnosticCapacity(g.number(v)>0)
    val policy=g.objectValue(h["resolutionPolicy"])
    g.fields(policy,"directEdges","headerOwnership","headerSubsystemBoundary","sourceOnlyOwnership","unresolvedEvidence")
    g.requireString(policy["directEdges"],"fully-compiler-resolved-file-identities-only")
    g.requireString(policy["headerOwnership"],"full-domain-sha256-of-canonical-header-path")
    g.requireString(policy["headerSubsystemBoundary"],"exact-per-tu-observing-module-shard-set-without-transitive-inference")
    g.requireString(policy["sourceOnlyOwnership"],"forbidden"); g.requireString(policy["unresolvedEvidence"],"exact-count-accounted-blockers-only")
}

private fun requireHeaderRowsSorted(g:DiagnosticGraphCodec,rows:JsonArray,vararg fields:String) {
    for(i in 1 until rows.size) {
        val a=g.objectValue(rows[i-1]); val b=g.objectValue(rows[i]); var compared=0
        for(field in fields) { compared=g.context.compareCodePoints(g.string(a[field]),g.string(b[field])); if(compared!=0)break }
        diagnosticCapacity(compared<0)
    }
}
private fun headerShard(g:DiagnosticGraphCodec,shard:String) {
    diagnosticCapacity(shard.length<=128)
    for(forbidden in listOf("catch-all","catchall","core","default","misc","unowned"))diagnosticCapacity(!g.context.equal(shard,forbidden))
}
private fun headerSourcePath(g:DiagnosticGraphCodec,path:String,header:Boolean) {
    graphPath(g,path)
    for(c in path)g.step("header ASCII path") { diagnosticCapacity(c.code in 0x20..0x7e) }
    diagnosticCapacity(path.startsWith("source/") || path.startsWith("generated/"))
    val suffixes=if(header)listOf(".def",".h",".hh",".hpp",".hxx",".inc") else listOf(".c",".cc",".cpp",".cxx",".m",".mm")
    var matches=false
    for(suffix in suffixes) { g.step("header suffix"); if(path.endsWith(suffix))matches=true }
    diagnosticCapacity(matches)
}
