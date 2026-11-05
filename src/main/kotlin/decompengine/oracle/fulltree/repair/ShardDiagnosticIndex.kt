package decompengine.oracle.fulltree.repair

import decompengine.repair.RepairValidationInvocation
import decompengine.repair.RepairValidationObservedArtifact
import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.*

internal class DiagnosticSample private constructor(private val context: DiagnosticComputationContext,
    private val sid:String,private val stable:String,private val invocation:String,private val action:String,private val actionHash:String,
    private val artifact:RepairValidationObservedArtifact,private val retainedSpans:List<DiagnosticSpan>,private val payloadHash:String,private val length:Long,
    private val retainedRecord:JsonObject,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    internal val record get()=check(retainedRecord)
    val id get()=check(sid); val key get()=check(stable); val invocationId get()=check(invocation); val actionId get()=check(action)
    val actionSha256 get()=check(actionHash); val receipt get()=check(artifact); val spans get()=check(retainedSpans)
    val payloadSha256 get()=check(payloadHash); val payloadBytes get()=check(length)
    companion object {
        internal fun create(g:DiagnosticGraphCodec,id:String,key:String,f:RecordedBuildFailure,o:RecordedDiagnosticObservation,payloadHash:String,record:JsonObject):DiagnosticSample {
            g.reserve(152,"diagnostic sample"); return DiagnosticSample(g.context,id,key,f.invocation.id,f.actionId,f.actionSha256,f.receipt,
                g.freeze(o.spans,g.limits.spansPerObservation),payloadHash,o.payloadBytes,record)
        }
    }
}
internal class IndexedDiagnosticGroup private constructor(private val context:DiagnosticComputationContext,
    private val gid:String,private val stable:String,private val occurrence:String?,private val invocation:String,private val disposition:DiagnosticOwner,
    private val klass:FailureClass,private val samples:List<String>,private val anchors:List<String>,private val retainedRecord:JsonObject,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    internal val record get()=check(retainedRecord)
    val id get()=check(gid); val key get()=check(stable); val occurrenceId get()=check(occurrence); val invocationId get()=check(invocation)
    val owner get()=check(disposition); val failureClass get()=check(klass); val sampleIds get()=check(samples); val anchorNodeIds get()=check(anchors)
    companion object {
        internal fun create(g:DiagnosticGraphCodec,id:String,key:String,occurrence:String?,invocation:String,owner:DiagnosticOwner,
            klass:FailureClass,samples:List<String>,anchors:List<String>):IndexedDiagnosticGroup {
            val record=g.obj("id" to g.str(id),"key" to g.str(key),"occurrenceId" to (occurrence?.let(g::str) ?: JsonNull),
                "invocationId" to g.str(invocation),"owner" to graphOwner(g,owner),"failureClass" to g.str(klass.name),
                "sampleIds" to g.strings(samples),"anchorNodeIds" to g.strings(anchors))
            g.reserve(136,"diagnostic group"); return IndexedDiagnosticGroup(g.context,id,key,occurrence,invocation,owner,klass,samples,anchors,record)
        }
    }
}
internal class DiagnosticCoverage private constructor(private val context:DiagnosticComputationContext,
    private val invocation:String,private val action:String,private val pipe:DiagnosticStream,private val length:Long,private val digest:String,
    private val diagnostic:List<DiagnosticSpan>,private val unparsed:List<DiagnosticSpan>,private val captured:Boolean,private val retainedRecord:JsonObject,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    internal val record get()=check(retainedRecord)
    val invocationId get()=check(invocation); val actionId get()=check(action); val stream get()=check(pipe)
    val bytes get()=check(length); val sha256 get()=check(digest); val diagnosticSpans get()=check(diagnostic)
    val contextSpans get()=check(emptyList<DiagnosticSpan>()); val unparsedSpans get()=check(unparsed)
    val complete get()=check(captured && unparsed.isEmpty())
    companion object {
        internal fun create(g:DiagnosticGraphCodec,f:RecordedBuildFailure,stream:DiagnosticStream,bytes:ByteArray,spans:List<DiagnosticSpan>):DiagnosticCoverage {
            val sorted=diagnosticMergeSort(g.context,spans,g.limits.spansPerAction) { a,b -> g.step("coverage comparison"); a.start.compareTo(b.start) }
            val complement=GraphAppend<DiagnosticSpan>(g,g.limits.spansPerAction+1)
            var end=0L
            for(span in sorted) { g.step("coverage span admission"); diagnosticCapacity(span.stream==stream && span.start>=end && span.endExclusive<=bytes.size)
                if(span.start>end) { g.reserve(88,"unparsed span"); complement.add(DiagnosticSpan(stream,end,span.start)) }; end=span.endExclusive }
            if(end<bytes.size) { g.reserve(88,"unparsed span"); complement.add(DiagnosticSpan(stream,end,bytes.size.toLong())) }
            val unparsed=complement.finish(); val hash=g.hash(bytes)
            val record=g.obj("invocationId" to g.str(f.invocation.id),"actionId" to g.str(f.actionId),"actionSha256" to g.str(f.actionSha256),
                "stream" to g.str(stream.name.lowercase()),"bytes" to g.num(bytes.size.toLong()),"sha256" to g.str(hash),
                "diagnosticSpans" to g.map(sorted) { spanJson(g,it) },"contextSpans" to g.strings(emptyList()),
                "unparsedSpans" to g.map(unparsed) { spanJson(g,it) },"complete" to g.bool(f.captureComplete && unparsed.isEmpty()))
            g.reserve(144,"diagnostic coverage"); return DiagnosticCoverage(g.context,f.invocation.id,f.actionId,stream,bytes.size.toLong(),hash,sorted,unparsed,f.captureComplete,record)
        }
    }
}
internal class RecordedShardDiagnosticIndex private constructor(internal val context:DiagnosticComputationContext,
    private val v:DiagnosticGraphVersion,private val source:String,private val retainedSamples:List<DiagnosticSample>,private val retainedGroups:List<IndexedDiagnosticGroup>,
    private val retainedCoverage:List<DiagnosticCoverage>,private val retainedBlockers:List<DiagnosticBlocker>,private val reverse:List<Map<String,List<String>>>,
    private val opaque:List<JsonObject>,private val relocation:List<JsonObject>,private val indexHash:String,
    private val retainedRecord:JsonObject,private val bytes:ByteArray,internal val planCommitment:String,
    internal val actions:List<JsonObject>,internal val invocations:Map<String,JsonObject>,internal val rawSamples:Long,
    internal val rawActions:Long,internal val rawBytes:Long,internal val rawPayload:Long,internal val rawSpans:Long,
    private val retainedBatch:RecordedCompileLinkBatch,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    internal val record get()=check(retainedRecord)
    val version get()=check(v); val sourceRevisionSha256 get()=check(source); val samples get()=check(retainedSamples)
    val groups get()=check(retainedGroups); val coverage get()=check(retainedCoverage); val blockers get()=check(retainedBlockers)
    val byKey get()=check(reverse[0]); val byOwner get()=check(reverse[1]); val byPath get()=check(reverse[2])
    val byEntity get()=check(reverse[3]); val byComponent get()=check(reverse[4]); val byInvocation get()=check(reverse[5])
    val opaqueActions get()=check(opaque); val relocations get()=check(relocation); val indexSha256 get()=check(indexHash)
    val canonicalBytes get()=context.copy(bytes,"diagnostic index getter")
    companion object {
        internal fun build(batch:RecordedCompileLinkBatch,plan:RecordedDiagnosticPlan,previous:RecordedShardDiagnosticIndex?=null):RecordedShardDiagnosticIndex {
        val c=plan.context; c.meter.checkAccess(); diagnosticCapacity(batch.context===c && (previous==null || previous.context===c))
        val g=DiagnosticGraphCodec(c); val l=c.limits
        // Read only immutable retained summaries before any current/previous collection traversal.
        c.reserve(40,"index aggregate counters"); val counts=LongArray(5)
        counts[1]=batch.failures.size.toLong()
        diagnosticCapacity(counts[1]<=l.failedActions && (counts[1]==0L || l.failedInvocations>0))
        for(f in batch.failures) {
            diagnosticCapacity(f.context===c)
            g.step("index aggregate admission")
            counts[0]=diagnosticAdd(counts[0],f.observations.size.toLong()); counts[2]=diagnosticAdd(counts[2],diagnosticAdd(f.stdoutBytes,f.stderrBytes))
            counts[3]=diagnosticAdd(counts[3],f.diagnosticPayloadBytes); counts[4]=diagnosticAdd(counts[4],f.spanCount)
        }
        diagnosticCapacity(diagnosticAdd(counts[0],previous?.rawSamples ?: 0)<=l.observations && diagnosticAdd(counts[1],previous?.rawActions ?: 0)<=l.failedActions)
        diagnosticCapacity(diagnosticAdd(counts[2],previous?.rawBytes ?: 0)<=l.batchBytes && diagnosticAdd(counts[3],previous?.rawPayload ?: 0)<=l.diagnosticPayloadBytes && diagnosticAdd(counts[4],previous?.rawSpans ?: 0)<=l.spansPerBatch)
        c.meter.begin("diagnostic index entry"); batch.checkLimits(l)
        val version=graphVersion(g,plan.version)
        if(previous!=null) {
            val old=graphVersion(g,previous.version)
            if(g.equal(g.encode(old),g.encode(version)))diagnosticCapacity(c.equal(previous.sourceRevisionSha256,plan.sourceRevisionSha256))
            else { val pred=plan.predecessor ?: diagnosticGraphInvalid(); diagnosticCapacity(g.equal(g.encode(old),g.encode(graphVersion(g,pred)))) }
        }
        val blockers=GraphAppend<DiagnosticBlocker>(g,l.graphBlockers)
        for(b in plan.blockers) { graphBlocker(g,b); blockers.add(b) }
        fun block(code:DiagnosticBlockerCode,ids:List<String>) { blockers.add(DiagnosticBlocker(c,code,g.unique(ids,l.observations))) }
        val pathOwners=g.table<GraphAppend<DiagnosticOwner>>(); val entityOwners=g.table<GraphAppend<DiagnosticOwner>>()
        fun addOwner(table:TreeMap<String,GraphAppend<DiagnosticOwner>>,id:String,owner:DiagnosticOwner) {
            var values=table[id]; if(values==null) { values=GraphAppend(g,l.moduleMappings); g.put(table,id,values) }; values.add(owner)
        }
        for(m in plan.modules) {
            val owner=DiagnosticOwner.Module(c,m.id,m.shard)
            for(path in m.paths)addOwner(pathOwners,path,owner); for(entity in m.entities)addOwner(entityOwners,entity,owner)
        }
        for(h in plan.headers)addOwner(pathOwners,h.path,DiagnosticOwner.Shared(c,h.id,h.consumers))
        val pathMap=g.table<List<DiagnosticOwner>>(); for((key,v) in pathOwners)g.put(pathMap,key,v.finish())
        val entityMap=g.table<List<DiagnosticOwner>>(); for((key,v) in entityOwners)g.put(entityMap,key,v.finish())
        fun resolve(o:RecordedDiagnosticObservation):DiagnosticOwner {
            val a=o.sourcePath?.let { pathMap[it] }; val b=o.entityId?.let { entityMap[it] }
            if((o.sourcePath!=null && a==null) || (o.entityId!=null && b==null) || a==null && b==null)return DiagnosticOwner.Unknown(c,"unmapped-recorded-anchor")
            val candidates=g.table<DiagnosticOwner>()
            for(list in listOf(a,b))if(list!=null)for(owner in list)g.put(candidates,g.hash(g.encode(graphOwner(g,owner))),owner)
            if(candidates.size==1)return candidates.firstEntry().value
            return DiagnosticOwner.Conflict(c,tableKeys(g,candidates))
        }
        val samples=g.table<DiagnosticSample>(); val groups=g.table<GroupAccumulator>(); val keys=g.table<Boolean>()
        val invocations=g.table<JsonObject>(); val invocationBindings=g.table<TreeMap<String,Boolean>>(); val actions=g.table<JsonObject>()
        val actionBindings=g.table<TreeMap<String,Boolean>>(); val definitions=g.table<Boolean>(); val decompositions=g.table<TreeMap<String,Boolean>>(); val claims=g.table<JsonObject>(); val sampleGroups=g.table<TreeMap<String,Boolean>>()
        val coverage=GraphAppend<DiagnosticCoverage>(g,l.failedActions*2)
        val opaque=g.table<JsonObject>()
        val reverseScratch=g.list<TreeMap<String,TreeMap<String,Boolean>>>(6); repeat(6) { reverseScratch.add(g.table()) }
        fun reverse(which:Int,key:String,id:String) { var values=reverseScratch[which][key]; if(values==null) { values=g.table(); g.put(reverseScratch[which],key,values) }; g.put(values,id,true) }
        var population:RepairValidationInvocation?=null
        val policyHash=g.hash(g.encode(g.obj("id" to g.str("full-tree-shard-diagnostic-exact-v1"),"version" to g.num(1),
            "normalizations" to g.strings(emptyList()),"payload" to g.str("ordered-exact-stream-spans-v1"))))
        for(f in batch.failures) {
            diagnosticCapacity(f.exitCode!=0 && f.exitCode>=0)
            val inv=invocationJson(g,f.invocation); val receipt=receiptJson(g,f.receipt)
            diagnosticCapacity(c.equal(f.invocation.sourceRevisionSha256,plan.sourceRevisionSha256))
            val first=population
            if(first==null)population=f.invocation else {
                for((a,b) in listOf(first.runId to f.invocation.runId,first.candidateRevisionId to f.invocation.candidateRevisionId,
                    first.profileSha256 to f.invocation.profileSha256,first.indexSha256 to f.invocation.indexSha256,first.regressionCorpusSha256 to f.invocation.regressionCorpusSha256))diagnosticCapacity(c.equal(a,b))
            }
            val invocationBinding=g.hash(g.encode(g.obj("invocation" to inv,"receipt" to receipt)))
            var invocationDefinitions=invocationBindings[f.invocation.id]
            if(invocationDefinitions==null) {
                diagnosticCapacity(invocations.size<l.failedInvocations)
                invocationDefinitions=g.table(); g.put(invocationBindings,f.invocation.id,invocationDefinitions)
                g.put(invocations,f.invocation.id,inv)
            }
            g.put(invocationDefinitions,invocationBinding,true)
            val stdout=f.stdout; val stderr=f.stderr
            val stdoutHash=g.hash(stdout); val stderrHash=g.hash(stderr)
            val definition=g.obj("invocation" to inv,"actionId" to g.str(f.actionId),"actionSha256" to g.str(f.actionSha256),"stage" to g.str(f.stage.name.lowercase()),
                "toolIdentitySha256" to g.str(f.toolIdentitySha256),"receipt" to receipt,"stdoutSha256" to g.str(stdoutHash),"stdoutBytes" to g.num(f.stdoutBytes),
                "stderrSha256" to g.str(stderrHash),"stderrBytes" to g.num(f.stderrBytes),"exitCode" to g.num(f.exitCode.toLong()),"captureComplete" to g.bool(f.captureComplete))
            val definitionId=g.id("action-definition",definition)
            val actionKey=g.id("action-reference",g.obj("invocationId" to g.str(f.invocation.id),"actionId" to g.str(f.actionId)))
            var actionDefinitions=actionBindings[actionKey]
            if(actionDefinitions==null) { actionDefinitions=g.table(); g.put(actionBindings,actionKey,actionDefinitions) }
            g.put(actionDefinitions,definitionId,true)
            g.put(actions,definitionId,definition)
            val localSamples=g.table<Boolean>(); val outSpans=GraphAppend<DiagnosticSpan>(g,l.spansPerAction); val errSpans=GraphAppend<DiagnosticSpan>(g,l.spansPerAction)
            for(o in f.observations) {
                diagnosticCapacity(o.context===c && o.stage==f.stage && c.equal(o.toolIdentitySha256,f.toolIdentitySha256))
                if(o.spans.size>1) {
                    val frame=g.map(o.spans) { span ->
                        val stream=if(span.stream==DiagnosticStream.STDOUT)stdout else stderr
                        diagnosticCapacity(span.start>=0 && span.endExclusive<=stream.size && span.endExclusive>span.start)
                        g.obj("stream" to g.str(span.stream.name.lowercase()),"bytes" to g.num(span.endExclusive-span.start),"sha256" to g.str(g.hash(stream,span.start.toInt(),span.endExclusive.toInt()))) }
                    diagnosticCapacity(g.equal(o.payload,g.encode(frame)))
                }
                val normalized=ShardDiagnosticNormalizerV1.normalize(o)
                diagnosticCapacity(c.equal(policyHash,normalized.normalizerSha256))
                val key=ShardDiagnosticNormalizerV1.stableKey(o,normalized)
                if(!keys.containsKey(key)) { diagnosticCapacity(keys.size<l.diagnosticKeys); g.put(keys,key,true) }
                val sampleBinding=g.obj("key" to g.str(key),"invocation" to inv,"actionId" to g.str(f.actionId),"actionSha256" to g.str(f.actionSha256),
                    "receipt" to receipt,"streamSpans" to g.map(o.spans) { spanJson(g,it) },"payloadSha256" to g.str(normalized.normalizedKeySha256),"payloadBytes" to g.num(o.payloadBytes))
                val sid=g.id("sample",sampleBinding)
                val claim=g.obj("sampleId" to g.str(sid),"actionDefinitionId" to g.str(definitionId),"sourcePath" to (o.sourcePath?.let(g::str) ?: JsonNull),
                    "entityId" to (o.entityId?.let(g::str) ?: JsonNull),"claimedClass" to g.str(o.claimedClass.name),
                    "stage" to g.str(o.stage.name.lowercase()),"toolIdentitySha256" to g.str(o.toolIdentitySha256))
                g.put(claims,g.id("observation-claim",claim),claim)
                val sampleRecord=g.obj("id" to g.str(sid),"binding" to sampleBinding,"normalization" to g.obj("normalizerSha256" to g.str(normalized.normalizerSha256),
                    "normalizedKeySha256" to g.str(normalized.normalizedKeySha256),"payloadBytes" to g.num(normalized.payloadBytes)))
                val priorSample=samples[sid]
                if(priorSample==null)g.put(samples,sid,DiagnosticSample.create(g,sid,key,f,o,normalized.normalizedKeySha256,sampleRecord))
                else diagnosticCapacity(g.equal(g.encode(priorSample.record),g.encode(sampleRecord)))
                if(!localSamples.containsKey(sid)) {
                    g.put(localSamples,sid,true)
                    for(span in o.spans)if(span.stream==DiagnosticStream.STDOUT)outSpans.add(span) else errSpans.add(span)
                }
                val owner=resolve(o); val ownerJson=graphOwner(g,owner)
                val occurrence=if(owner is DiagnosticOwner.Module)g.id("diagnostic-occurrence",g.obj("key" to g.str(key),"validationInvocation" to inv,
                    "ownerModuleId" to g.str(owner.moduleId),"shardId" to g.str(owner.shardId),"planningArtifactSha256" to g.str(plan.version.planningArtifactSha256),"dependencyPlanSha256" to g.str(plan.dependencyPlanSha256)),true) else null
                val gid=occurrence ?: g.id("unresolved-occurrence",g.obj("key" to g.str(key),"invocation" to inv,"ownerDisposition" to ownerJson,"version" to version))
                val anchors=when(owner) { is DiagnosticOwner.Module -> g.freeze(listOf(owner.moduleId)); is DiagnosticOwner.Shared -> g.freeze(listOf(owner.headerOwnerId)); else -> emptyList() }
                val old=groups[gid]
                if(old==null) { g.reserve(136,"group accumulator"); g.put(groups,gid,GroupAccumulator(gid,key,occurrence,f.invocation.id,owner,o.claimedClass,anchors,g.table())) }
                else if(old.klass!=o.claimedClass || !g.equal(g.encode(g.strings(old.anchors)),g.encode(g.strings(anchors)))) {
                    old.conflict=true; old.klass=FailureClass.UNCLASSIFIED
                }
                g.put(groups.getValue(gid).samples,sid,true)
                var attached=sampleGroups[sid]
                if(attached==null) { attached=g.table(); g.put(sampleGroups,sid,attached) }
                g.put(attached,gid,true)
                when(owner) {
                    is DiagnosticOwner.Shared -> block(DiagnosticBlockerCode.SHARED_NONEDITABLE,listOf(gid,sid))
                    is DiagnosticOwner.Unknown -> block(DiagnosticBlockerCode.UNKNOWN_OWNER,listOf(gid,sid))
                    is DiagnosticOwner.Conflict -> block(DiagnosticBlockerCode.CONFLICT,listOf(gid,sid))
                    is DiagnosticOwner.External -> block(DiagnosticBlockerCode.EXTERNAL_BOUNDARY,listOf(gid,sid))
                    is DiagnosticOwner.Unclassified -> block(DiagnosticBlockerCode.UNCLASSIFIED,listOf(gid,sid))
                    else -> Unit
                }
                if(o.claimedClass==FailureClass.UNCLASSIFIED)block(DiagnosticBlockerCode.UNCLASSIFIED,listOf(gid,sid))
                reverse(0,key,gid); reverse(1,g.hash(g.encode(ownerJson)),gid); o.sourcePath?.let { reverse(2,it,gid) }; o.entityId?.let { reverse(3,it,gid) }
                for(node in anchors)reverse(4,plan.graph.components[plan.graph.nodeComponent.getValue(node)].id,gid)
                reverse(5,f.invocation.id,gid)
            }
            // Exact repeated action references coalesce coverage only when their decomposition agrees.
            val out=DiagnosticCoverage.create(g,f,DiagnosticStream.STDOUT,stdout,outSpans.finish())
            val err=DiagnosticCoverage.create(g,f,DiagnosticStream.STDERR,stderr,errSpans.finish())
            val decomposition=g.id("action-decomposition",g.obj("definition" to definition,"stdout" to out.record,"stderr" to err.record))
            var decompositionDefinitions=decompositions[definitionId]
            if(decompositionDefinitions==null) { decompositionDefinitions=g.table(); g.put(decompositions,definitionId,decompositionDefinitions) }
            g.put(decompositionDefinitions,decomposition,true)
            if(!definitions.containsKey(decomposition)) { g.put(definitions,decomposition,true); coverage.add(out); coverage.add(err) }
            if(f.observations.isEmpty() || !out.complete || !err.complete || !validStreamUtf8(g,stdout) || !validStreamUtf8(g,stderr)) {
                val id=g.id("opaque-action",definition); g.put(opaque,id,g.obj("id" to g.str(id),"binding" to definition))
                block(DiagnosticBlockerCode.UNCLASSIFIED,listOf(id))
            }
            if(!f.captureComplete)block(DiagnosticBlockerCode.INCOMPLETE_CAPTURE,listOf(definitionId))
        }
        // Conflict evidence commits complete definition sets, independent of encounter order.
        fun conflicts(table:Map<String,TreeMap<String,Boolean>>) {
            for((reference,values) in table)if(values.size>1) {
                val ids=g.list<String>(values.size+1); ids.add(reference)
                for(id in values.keys)g.step("conflict witness retention") { ids.add(id) }
                block(DiagnosticBlockerCode.CONFLICT,ids)
            }
        }
        conflicts(invocationBindings); conflicts(actionBindings); conflicts(decompositions); conflicts(sampleGroups)
        for(x in groups.values)if(x.conflict) {
            val ids=g.list<String>(x.samples.size+1); ids.add(x.id)
            for(id in x.samples.keys)g.step("class conflict witness retention") { ids.add(id) }
            block(DiagnosticBlockerCode.CONFLICT,ids)
        }
        val retainedGroups=g.list<IndexedDiagnosticGroup>(groups.size)
        for(x in groups.values)retainedGroups.add(IndexedDiagnosticGroup.create(g,x.id,x.key,x.occurrence,x.invocation,x.owner,x.klass,tableKeys(g,x.samples),x.anchors))
        val actionList=tableValues(g,actions)
        val movements=comparePrevious(g,previous,plan,retainedGroups,samples,invocations,actionList,::block)
        val reverse=g.list<Map<String,List<String>>>(6)
        for(table in reverseScratch) { val immutable=g.table<List<String>>(); for((k,v) in table)g.put(immutable,k,tableKeys(g,v)); reverse.add(Collections.unmodifiableMap(immutable)) }
        val retainedSamples=tableValues(g,samples); val retainedOpaque=tableValues(g,opaque)
        val coverageRecords=g.table<DiagnosticCoverage>()
        for(row in coverage.finish())g.put(coverageRecords,g.hash(g.encode(row.record)),row)
        val sortedCoverage=tableValues(g,coverageRecords)
        val blockerRecords=g.table<DiagnosticBlocker>()
        for(b in blockers.finish())g.put(blockerRecords,g.hash(g.encode(graphBlocker(g,b))),b)
        val retainedBlockers=tableValues(g,blockerRecords)
        val planCommitment=g.hash(g.encode(plan.record))
        val base=g.obj("kind" to g.str("recorded-shard-diagnostic-index-v1"),"authority" to g.str("recorded-only"),"version" to version,
            "sourceRevisionSha256" to g.str(plan.sourceRevisionSha256),"planCommitment" to g.str(planCommitment),"normalizerSha256" to g.str(policyHash),
            "invocations" to g.map(tableValues(g,invocations)) { it },"actions" to g.map(actionList) { it },"samples" to g.map(retainedSamples) { it.record },
            "observationClaims" to g.map(tableValues(g,claims)) { it },"groups" to g.map(retainedGroups) { it.record },"coverage" to g.map(sortedCoverage) { it.record },"opaqueActions" to g.map(retainedOpaque) { it },
            "blockers" to g.map(retainedBlockers) { graphBlocker(g,it) },"previousCommitment" to (previous?.indexSha256?.let(g::str) ?: JsonNull),
            "movements" to g.map(movements) { it },"reverse" to g.map(reverse) { table -> val fields=g.table<JsonElement>(); for((k,v) in table)g.put(fields,k,g.strings(v)); JsonObject(Collections.unmodifiableMap(fields)) })
        val (record,hash)=g.withHash(base,"indexSha256")
        val bytes=g.encode(record)
        g.reserve(256,"diagnostic index result"); g.meter.end("diagnostic index exit")
        return RecordedShardDiagnosticIndex(c,plan.version,plan.sourceRevisionSha256,retainedSamples,Collections.unmodifiableList(retainedGroups),sortedCoverage,retainedBlockers,
            Collections.unmodifiableList(reverse),retainedOpaque,movements,hash,record,bytes,planCommitment,actionList,Collections.unmodifiableMap(invocations),
            counts[0],counts[1],counts[2],counts[3],counts[4],batch)
    }
    }
}

internal fun spanJson(g:DiagnosticGraphCodec,s:DiagnosticSpan):JsonObject = g.obj("stream" to g.str(s.stream.name.lowercase()),"start" to g.num(s.start),"endExclusive" to g.num(s.endExclusive))
internal fun invocationJson(g:DiagnosticGraphCodec,i:RepairValidationInvocation):JsonObject {
    fun patterned(s:String,prefix:String,hex:Boolean,count:Int) {
        g.context.text(s); diagnosticCapacity(s.length==prefix.length+count)
        for(j in s.indices)g.step("invocation shape") { diagnosticCapacity(if(j<prefix.length)s[j]==prefix[j] else s[j] in '0'..'9' || hex && s[j] in 'a'..'f') }
    }
    patterned(i.id,"validation_",true,32); patterned(i.runId,"run_",false,8)
    if(i.candidateRevisionId.length==29)patterned(i.candidateRevisionId,"root_",true,24)
    else {
        val s=i.candidateRevisionId; diagnosticCapacity(s.length==34)
        for(j in s.indices)g.step("candidate shape") { diagnosticCapacity(when { j<9 -> s[j]=="revision_"[j]; j<17 -> s[j] in '0'..'9'; j==17 -> s[j]=='_'; else -> s[j] in '0'..'9' || s[j] in 'a'..'f' }) }
    }
    for(s in listOf(i.sourceRevisionSha256,i.profileSha256,i.indexSha256,i.regressionCorpusSha256))g.context.digest(s)
    return g.obj("id" to g.str(i.id),"runId" to g.str(i.runId),"candidateRevisionId" to g.str(i.candidateRevisionId),"sourceRevisionSha256" to g.str(i.sourceRevisionSha256),
        "profileSha256" to g.str(i.profileSha256),"indexSha256" to g.str(i.indexSha256),"regressionCorpusSha256" to g.str(i.regressionCorpusSha256))
}
internal fun receiptJson(g:DiagnosticGraphCodec,r:RepairValidationObservedArtifact):JsonObject {
    graphPath(g,r.path); g.context.digest(r.sha256); diagnosticCapacity(r.bytes in 1..64L*1024*1024)
    return g.obj("path" to g.str(r.path),"sha256" to g.str(r.sha256),"bytes" to g.num(r.bytes))
}
private class GroupAccumulator(val id:String,val key:String,val occurrence:String?,val invocation:String,val owner:DiagnosticOwner,
    var klass:FailureClass,val anchors:List<String>,val samples:TreeMap<String,Boolean>) { var conflict=false }

internal object ShardDiagnosticIndex {
    fun build(batch:RecordedCompileLinkBatch,plan:RecordedDiagnosticPlan,previous:RecordedShardDiagnosticIndex?=null):RecordedShardDiagnosticIndex =
        RecordedShardDiagnosticIndex.build(batch,plan,previous)
}

private fun validStreamUtf8(g:DiagnosticGraphCodec,bytes:ByteArray):Boolean {
    var need=0; var cp=0; var minimum=0; var valid=true
    for(b in bytes)g.step("stream UTF-8 validation") {
        val n=b.toInt() and 255
        if(need==0)when(n) {
            in 0..127 -> Unit
            in 0xc2..0xdf -> { need=1; cp=n and 31; minimum=128 }
            in 0xe0..0xef -> { need=2; cp=n and 15; minimum=2048 }
            in 0xf0..0xf4 -> { need=3; cp=n and 7; minimum=65536 }
            else -> valid=false
        } else { if(n !in 0x80..0xbf)valid=false; cp=(cp shl 6) or (n and 63); need--; if(need==0 && (cp<minimum || cp>0x10ffff || cp in 0xd800..0xdfff))valid=false }
    }
    return valid && need==0
}
private fun comparePrevious(g:DiagnosticGraphCodec,previous:RecordedShardDiagnosticIndex?,plan:RecordedDiagnosticPlan,
    current:List<IndexedDiagnosticGroup>,currentSamples:Map<String,DiagnosticSample>,invocations:Map<String,JsonObject>,actions:List<JsonObject>,block:(DiagnosticBlockerCode,List<String>)->Unit):List<JsonObject> {
    if(previous==null)return emptyList()
    val first=invocations.values.firstOrNull(); val oldFirst=previous.invocations.values.firstOrNull()
    // An empty recorded population supplies no run/profile/corpus tuple. It cannot certify that
    // it shares the scope of a populated previous index; both-empty comparisons remain explicit.
    diagnosticCapacity((first==null)==(oldFirst==null))
    if(first!=null && oldFirst!=null) {
        for(field in listOf("runId","profileSha256","regressionCorpusSha256"))g.requireString(first[field],g.string(oldFirst[field]))
        if(g.equal(g.encode(graphVersion(g,previous.version)),g.encode(graphVersion(g,plan.version))))
            for(field in listOf("candidateRevisionId","indexSha256"))g.requireString(first[field],g.string(oldFirst[field]))
    }
    for((id,inv) in invocations)previous.invocations[id]?.let { old ->
        diagnosticCapacity(g.equal(g.encode(old),g.encode(inv)))
        val a=GraphAppend<JsonElement>(g,g.limits.failedActions); val b=GraphAppend<JsonElement>(g,g.limits.failedActions)
        for(row in actions)if(g.context.equal(g.string(g.objectValue(row["invocation"])["id"]),id))a.add(row)
        for(row in previous.actions)if(g.context.equal(g.string(g.objectValue(row["invocation"])["id"]),id))b.add(row)
        diagnosticCapacity(g.equal(g.encode(JsonArray(a.finish())),g.encode(JsonArray(b.finish()))))
    }
    val old=g.table<GraphAppend<IndexedDiagnosticGroup>>(); val now=g.table<GraphAppend<IndexedDiagnosticGroup>>()
    fun add(table:TreeMap<String,GraphAppend<IndexedDiagnosticGroup>>,x:IndexedDiagnosticGroup) { var v=table[x.key]; if(v==null) { v=GraphAppend(g,g.limits.observations); g.put(table,x.key,v) }; v.add(x) }
    for(x in previous.groups)add(old,x); for(x in current)add(now,x)
    val keys=g.table<Boolean>(); for(key in old.keys)g.put(keys,key,true); for(key in now.keys)g.put(keys,key,true)
    val results=GraphAppend<JsonObject>(g,g.limits.diagnosticKeys)
    val oldSamples=g.table<DiagnosticSample>(); for(s in previous.samples)g.put(oldSamples,s.id,s)
    fun witnesses(xs:List<IndexedDiagnosticGroup>,sampleTable:Map<String,DiagnosticSample>):JsonArray = g.map(xs) { x ->
        g.obj("owner" to graphOwner(g,x.owner),"groupId" to g.str(x.id),"sampleIds" to g.strings(x.sampleIds),
            "samples" to g.map(x.sampleIds) { sampleTable.getValue(it).record }) }
    for(key in keys.keys) {
        val a=old[key]?.finish() ?: emptyList(); val b=now[key]?.finish() ?: emptyList()
        val oldOwners=g.list<String>(a.size); val newOwners=g.list<String>(b.size)
        for(x in a)oldOwners.add(g.hash(g.encode(graphOwner(g,x.owner)))); for(x in b)newOwners.add(g.hash(g.encode(graphOwner(g,x.owner))))
        val aa=g.sorted(oldOwners,g.limits.observations); val bb=g.sorted(newOwners,g.limits.observations)
        if(g.equal(g.encode(g.strings(aa)),g.encode(g.strings(bb))))continue
        val uniqueOld=g.unique(oldOwners,g.limits.observations); val uniqueNew=g.unique(newOwners,g.limits.observations)
        val relocation=uniqueOld.size==1 && uniqueNew.size==1 && a.size==b.size
        if(!relocation)block(DiagnosticBlockerCode.MOVED_UNRESOLVED,listOf(key))
        results.add(g.obj("key" to g.str(key),"disposition" to g.str(if(relocation)"recorded-relocation" else "MOVED_UNRESOLVED"),
            "oldVersion" to graphVersion(g,previous.version),"newVersion" to graphVersion(g,plan.version),
            "oldSourceRevisionSha256" to g.str(previous.sourceRevisionSha256),"newSourceRevisionSha256" to g.str(plan.sourceRevisionSha256),
            "oldOwners" to witnesses(a,oldSamples),"newOwners" to witnesses(b,currentSamples)))
    }
    return results.finish()
}
