package decompengine.oracle.fulltree.repair

import java.util.Collections
import java.util.TreeMap
import kotlinx.serialization.json.*

internal class RecordedGraphComponent(private val context:DiagnosticComputationContext, private val componentId:String, private val memberIds:List<String>) {
    val id get():String { context.meter.checkAccess(); return componentId }
    val members get():List<String> { context.meter.checkAccess(); return memberIds }
}
internal class RecordedGraphTopology(private val context:DiagnosticComputationContext,
    private val retainedComponents:List<RecordedGraphComponent>, private val retainedNodeComponent:Map<String,Int>,
    private val retainedConsumers:List<List<Int>>, private val retainedDependencies:List<List<Int>>, private val retainedOrder:List<Int>, private val retainedRanks:List<Long>,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    val components get()=check(retainedComponents); val nodeComponent get()=check(retainedNodeComponent)
    val consumers get()=check(retainedConsumers); val dependencies get()=check(retainedDependencies)
    val order get()=check(retainedOrder); val ranks get()=check(retainedRanks)
}

internal fun canonicalEdges(g: DiagnosticGraphCodec, raw: List<RecordedGraphEdge>): List<RecordedGraphEdge> {
    val admitted=g.context.graphSnapshot(raw,g.limits.directEdges,"graph edge admission")
    for(e in admitted)diagnosticCapacity(e.context===g.context)
    val sorted=diagnosticMergeSort(g.context,admitted,g.limits.directEdges) { a,b ->
        val c=g.context.compareCodePoints(a.consumer,b.consumer); if(c!=0)c else g.context.compareCodePoints(a.dependency,b.dependency) }
    val out=g.list<RecordedGraphEdge>(sorted.size)
    for(e in sorted) {
        val p=out.lastOrNull()
        if(p==null || !g.context.equal(p.consumer,e.consumer) || !g.context.equal(p.dependency,e.dependency))g.step("graph edge dedup") { out.add(e) }
    }
    return Collections.unmodifiableList(out)
}

/** Iterative Kosaraju and Kahn. Input edges are consumer -> dependency; DAG is the reverse. */
internal fun computeRecordedTopology(g: DiagnosticGraphCodec, rawNodes: List<RecordedGraphNode>, rawEdges: List<RecordedGraphEdge>): RecordedGraphTopology {
    g.meter.checkAccess()
    diagnosticCapacity(rawNodes.size<=g.limits.graphNodes && rawEdges.size<=g.limits.directEdges)
    val admittedNodes=g.context.graphSnapshot(rawNodes,g.limits.graphNodes,"graph node admission")
    for(n in admittedNodes)diagnosticCapacity(n.context===g.context)
    val nodes=diagnosticMergeSort(g.context,admittedNodes,g.limits.graphNodes) { a,b -> g.context.compareCodePoints(a.id,b.id) }
    val edges=canonicalEdges(g,rawEdges); val n=nodes.size
    val indices=g.table<Int>()
    for(i in nodes.indices) { diagnosticCapacity(!indices.containsKey(nodes[i].id)); g.put(indices,nodes[i].id,i) }
    g.reserve(4L*n*4+2L*n,"graph traversal primitive arrays")
    val degree=IntArray(n); val reverseDegree=IntArray(n)
    for(e in edges) { val a=indices[e.consumer] ?: diagnosticGraphInvalid(); val b=indices[e.dependency] ?: diagnosticGraphInvalid()
        g.step("graph degree") { degree[a]++; reverseDegree[b]++ } }
    val forward=g.list<ArrayList<Int>>(n); val reverse=g.list<ArrayList<Int>>(n)
    for(i in 0 until n) { forward.add(g.list(degree[i])); reverse.add(g.list(reverseDegree[i])) }
    for(e in edges) { val a=indices.getValue(e.consumer); val b=indices.getValue(e.dependency)
        g.reserve(32,"graph adjacency integers"); g.step("graph adjacency") { forward[a].add(b); reverse[b].add(a) } }
    val seen=BooleanArray(n); val stack=IntArray(n); val next=IntArray(n); val assigned=BooleanArray(n)
    val finish=g.list<Int>(n)
    g.meter.begin("before graph SCC forward")
    for(start in 0 until n) {
        g.step("graph SCC forward vertex")
        if(seen[start])continue
        var top=0; stack[0]=start; seen[start]=true
        while(top>=0) {
            g.step("graph SCC forward") {
                val v=stack[top]
                if(next[v]<forward[v].size) {
                    val w=forward[v][next[v]++]
                    if(!seen[w]) { seen[w]=true; stack[++top]=w }
                } else { finish.add(v); top-- }
            }
        }
    }
    val components=GraphAppend<RecordedGraphComponent>(g,g.limits.graphNodes)
    g.meter.begin("before graph SCC reverse")
    for(pos in finish.indices.reversed()) {
        val start=finish[pos]; if(assigned[start])continue
        val members=GraphAppend<String>(g,g.limits.graphNodes)
        var top=0; stack[0]=start; assigned[start]=true
        while(top>=0) {
            var v=0; g.step("graph SCC reverse pop") { v=stack[top--] }
            members.add(nodes[v].id)
            for(w in reverse[v])g.step("graph SCC reverse") { if(!assigned[w]) { assigned[w]=true; stack[++top]=w } }
        }
        val sorted=g.sorted(members.finish(),g.limits.graphNodes)
        val id=g.id("component",g.obj("sortedMemberNodeIds" to g.strings(sorted)))
        g.reserve(80,"graph component"); components.add(RecordedGraphComponent(g.context,id,sorted))
    }
    val cs=diagnosticMergeSort(g.context,components.finish(),g.limits.graphNodes) { a,b -> g.context.compareCodePoints(a.id,b.id) }
    val nc=g.table<Int>()
    for(i in cs.indices)for(id in cs[i].members)g.put(nc,id,i)
    g.reserve(64,"graph condensation edge table")
    val pairs=TreeMap<Long,Boolean> { a,b -> var c=0; g.step("graph condensation comparison") { c=a.compareTo(b) }; c }
    for(e in edges) {
        val consumer=nc.getValue(e.consumer); val dependency=nc.getValue(e.dependency)
        if(consumer!=dependency) {
            val key=(dependency.toLong() shl 32) or consumer.toLong()
            if(!pairs.containsKey(key)) { diagnosticCapacity(pairs.size<g.limits.condensationEdges); g.reserve(80,"graph condensation entry"); pairs[key]=true }
        }
    }
    g.reserve(16L*cs.size,"graph rank and degree arrays")
    val outDegree=IntArray(cs.size); val inDegree=IntArray(cs.size); val ranks=LongArray(cs.size)
    for(key in pairs.keys)g.step("graph condensation degrees") { outDegree[(key ushr 32).toInt()]++; inDegree[key.toInt()]++ }
    val outgoing=g.list<List<Int>>(cs.size); val incoming=g.list<List<Int>>(cs.size)
    val outScratch=g.list<ArrayList<Int>>(cs.size); val inScratch=g.list<ArrayList<Int>>(cs.size)
    for(i in cs.indices) { outScratch.add(g.list(outDegree[i])); inScratch.add(g.list(inDegree[i])) }
    for(key in pairs.keys)g.step("graph condensation adjacency") { val a=(key ushr 32).toInt(); val b=key.toInt(); outScratch[a].add(b); inScratch[b].add(a) }
    for(i in cs.indices) { outgoing.add(Collections.unmodifiableList(outScratch[i])); incoming.add(Collections.unmodifiableList(inScratch[i])) }
    val ready=g.table<Int>(); for(i in cs.indices)if(inDegree[i]==0)g.put(ready,cs[i].id,i)
    val order=g.list<Int>(cs.size)
    g.meter.begin("before graph Kahn")
    while(ready.isNotEmpty()) {
        val entry=ready.firstEntry(); val v=entry.value; ready.remove(entry.key)
        g.step("graph Kahn visit") { order.add(v) }
        for(w in outgoing[v]) {
            g.step("graph Kahn edge") { ranks[w]=maxOf(ranks[w],diagnosticAdd(ranks[v],1)); inDegree[w]-- }
            if(inDegree[w]==0)g.put(ready,cs[w].id,w)
        }
    }
    diagnosticCapacity(order.size==cs.size)
    g.reserve(112,"graph topology result"); g.meter.end("after graph topology")
    val retainedRanks=g.list<Long>(ranks.size)
    for(rank in ranks) { g.reserve(24,"graph rank scalar"); g.step("graph rank retention") { retainedRanks.add(rank) } }
    return RecordedGraphTopology(g.context,cs,Collections.unmodifiableMap(nc),Collections.unmodifiableList(outgoing),Collections.unmodifiableList(incoming),Collections.unmodifiableList(order),Collections.unmodifiableList(retainedRanks))
}

internal class RootFailureRow private constructor(private val context: DiagnosticComputationContext,
    private val group: String, private val component: String, private val rank: Long, private val klass: Int,
    private val roots: List<String>, private val keys: List<String>, private val impact: List<String>,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    val groupId get()=check(group); val componentId get()=check(component)
    val dependencyRank get()=check(rank); val failureClassRank get()=check(klass)
    val downstreamImpact get()=check(impact.size.toLong())
    val rootGroupIds get()=check(roots); val rootDiagnosticKeys get()=check(keys); val impactModuleIds get()=check(impact)
    companion object {
        internal fun create(g: DiagnosticGraphCodec, group: String, component: String, rank: Long, klass: Int,
            roots: List<String>, keys: List<String>, impact: List<String>): RootFailureRow {
            g.reserve(120,"root row"); return RootFailureRow(g.context,group,component,rank,klass,roots,keys,impact)
        }
    }
}
internal class RecordedRootFailureOrder private constructor(internal val context: DiagnosticComputationContext,
    private val v: DiagnosticGraphVersion, private val retainedRows: List<RootFailureRow>, private val retainedBlockers: List<DiagnosticBlocker>,
    private val policy: String, private val assessment: String, private val source: String, private val cases: List<String>,
    private val retainedRecord: JsonObject, private val bytes: ByteArray,
) {
    private fun <T> check(v:T):T { context.meter.checkAccess(); return v }
    internal val record get()=check(retainedRecord)
    val version get()=check(v); val rows get()=check(retainedRows); val blockers get()=check(retainedBlockers)
    val policySha256 get()=check(policy); val assessmentSha256 get()=check(assessment)
    val sourceRevisionSha256 get()=check(source); val retainedCaseIds get()=check(cases)
    val canonicalBytes get()=context.copy(bytes,"root order getter")
    companion object {
        internal fun order(index: RecordedShardDiagnosticIndex, plan: RecordedDiagnosticPlan, retainedCaseIds: List<String>): RecordedRootFailureOrder {
        val c=plan.context; c.meter.checkAccess(); diagnosticCapacity(index.context===c)
        c.meter.guardedInput { diagnosticCapacity(retainedCaseIds.size in 0..c.limits.retainedCases) }
        val g=DiagnosticGraphCodec(c); val l=c.limits
        diagnosticCapacity(g.equal(g.encode(graphVersion(g,index.version)),g.encode(graphVersion(g,plan.version))) && c.equal(index.sourceRevisionSha256,plan.sourceRevisionSha256))
        diagnosticCapacity(c.equal(index.planCommitment,g.hash(g.encode(plan.record))))
        val cases=c.graphSnapshot(retainedCaseIds,l.retainedCases,"retained case IDs")
        for(id in cases)c.text(id,nonempty=true,controls=false)
        val canonicalCases=g.unique(cases,l.retainedCases)
        c.meter.begin("root order entry")
        // Recompute from retained canonical nodes and edges; cached/serialized ranks are not authority.
        val graph=computeRecordedTopology(g,plan.nodes,plan.edges)
        val byNode=g.table<RecordedGraphNode>(); for(n in plan.nodes)g.put(byNode,n.id,n)
        val groups=g.table<IndexedDiagnosticGroup>(); for(x in index.groups)g.put(groups,x.id,x)
        val seeds=g.list<TreeMap<String,Boolean>>(graph.components.size)
        val inherited=g.list<TreeMap<String,Boolean>>(graph.components.size)
        val impacts=g.list<TreeMap<String,Boolean>>(graph.components.size)
        for(i in graph.components.indices) { seeds.add(g.table()); inherited.add(g.table()); impacts.add(g.table()) }
        var rootCount=0L; var impactCount=0L
        fun rootInsert(table:TreeMap<String,Boolean>,id:String) {
            if(!table.containsKey(id)) { rootCount=diagnosticAdd(rootCount,1); diagnosticCapacity(rootCount<=l.rootMemberships); g.put(table,id,true); g.step("graph root insertion") }
        }
        fun impactInsert(table:TreeMap<String,Boolean>,id:String) {
            if(!table.containsKey(id)) { impactCount=diagnosticAdd(impactCount,1); diagnosticCapacity(impactCount<=l.impactMemberships); g.put(table,id,true); g.step("graph impact insertion") }
        }
        for(group in index.groups) {
            if(group.failureClass==FailureClass.OWNERSHIP || group.failureClass==FailureClass.INTERFACE) {
                for(node in group.anchorNodeIds) {
                    val ci=graph.nodeComponent[node] ?: diagnosticGraphInvalid()
                    rootInsert(seeds[ci],group.id)
                }
            }
        }
        c.meter.begin("before graph root propagation")
        for(ci in graph.order) {
            for(p in graph.dependencies[ci])for(id in inherited[p].keys)rootInsert(inherited[ci],id)
            if(inherited[ci].isEmpty())for(id in seeds[ci].keys)rootInsert(inherited[ci],id)
            g.step("graph root component")
        }
        c.meter.begin("before graph impact propagation")
        for(k in graph.order.indices.reversed()) {
            val ci=graph.order[k]
            for(child in graph.consumers[ci]) {
                for(node in graph.components[child].members) { g.step("graph impact member"); if(byNode.getValue(node).kind=="module")impactInsert(impacts[ci],node) }
                for(id in impacts[child].keys)impactInsert(impacts[ci],id)
            }
            g.step("graph impact component")
        }
        val rows=g.list<RootFailureRow>(index.groups.size); val unattached=GraphAppend<JsonElement>(g,l.observations)
        for(group in index.groups) {
            if(group.anchorNodeIds.isEmpty()) { unattached.add(g.obj("groupId" to g.str(group.id),"owner" to graphOwner(g,group.owner))); continue }
            val ci=graph.nodeComponent.getValue(group.anchorNodeIds[0])
            for(node in group.anchorNodeIds)diagnosticCapacity(graph.nodeComponent[node]==ci)
            val roots=if(inherited[ci].isEmpty()) { rootCount=diagnosticAdd(rootCount,1); diagnosticCapacity(rootCount<=l.rootMemberships); g.freeze(listOf(group.id)) } else tableKeys(g,inherited[ci])
            val keys=g.list<String>(roots.size); for(id in roots)keys.add(groups.getValue(id).key)
            rows.add(RootFailureRow.create(g,group.id,graph.components[ci].id,graph.ranks[ci],group.failureClass.ordinal,
                roots,g.unique(keys,l.observations),tableKeys(g,impacts[ci])))
        }
        val sorted=diagnosticMergeSort(c,rows,l.observations) { a,b ->
            var cmp=a.dependencyRank.compareTo(b.dependencyRank)
            if(cmp==0)cmp=a.failureClassRank.compareTo(b.failureClassRank)
            if(cmp==0)cmp=b.downstreamImpact.compareTo(a.downstreamImpact)
            if(cmp==0) {
                val ao=groups.getValue(a.groupId).owner; val bo=groups.getValue(b.groupId).owner
                cmp=if(ao is DiagnosticOwner.Module && bo is DiagnosticOwner.Module)c.compareCodePoints(ao.shardId,bo.shardId)
                    else compareOwnerSort(g,ao,bo)
            }
            if(cmp==0)cmp=c.compareCodePoints(groups.getValue(a.groupId).key,groups.getValue(b.groupId).key)
            if(cmp==0)cmp=c.compareCodePoints(a.groupId,b.groupId)
            g.step("root order comparison"); cmp
        }
        val policy=g.obj("id" to g.str("root-first-scc-v1"),"rank" to g.str("longest-dependency-path"),"impact" to g.str("distinct-downstream-module-set"),
            "roots" to g.str("dependency-minimal-interface-ownership-seeds"),"classRanks" to g.strings(listOf("ownership","interface","other","unclassified")),
            "ties" to g.strings(listOf("rank-asc","class-asc","impact-desc","shard-codepoint","diagnostic-key","group-id")))
        val policyHash=g.hash(g.encode(policy))
        val rowJson=g.map(sorted) { r -> g.obj("groupId" to g.str(r.groupId),"componentId" to g.str(r.componentId),"dependencyRank" to g.num(r.dependencyRank),
            "failureClassRank" to g.num(r.failureClassRank.toLong()),"downstreamImpact" to g.num(r.downstreamImpact),"rootGroupIds" to g.strings(r.rootGroupIds),
            "rootDiagnosticKeys" to g.strings(r.rootDiagnosticKeys),"impactModuleIds" to g.strings(r.impactModuleIds),
            "rootWitnesses" to g.map(r.rootGroupIds) { id -> val x=groups.getValue(id); g.obj("groupId" to g.str(id),"sampleIds" to g.strings(x.sampleIds),"key" to g.str(x.key)) }) }
        val base=g.obj("kind" to g.str("recorded-root-failure-order-v1"),"authority" to g.str("recorded-only"),"version" to graphVersion(g,plan.version),
            "sourceRevisionSha256" to g.str(plan.sourceRevisionSha256),"policySha256" to g.str(policyHash),"indexSha256" to g.str(index.indexSha256),
            "retainedCaseIds" to g.strings(canonicalCases),"retainedCasesSha256" to g.str(g.hash(g.encode(g.strings(canonicalCases)))),
            "rows" to rowJson,"witnessSha256" to g.str(g.hash(g.encode(rowJson))),"unattached" to JsonArray(unattached.finish()),
            "blockers" to g.map(index.blockers) { graphBlocker(g,it) })
        val (record,hash)=g.withHash(base,"assessmentSha256")
        val bytes=g.encode(record)
        g.reserve(144,"root order result"); g.meter.end("root order exit")
        return RecordedRootFailureOrder(c,plan.version,sorted,index.blockers,policyHash,hash,plan.sourceRevisionSha256,canonicalCases,record,bytes)
    }

    }
}

internal object ShardRootFailureOrdering {
    fun order(index:RecordedShardDiagnosticIndex,plan:RecordedDiagnosticPlan,retainedCaseIds:List<String>):RecordedRootFailureOrder =
        RecordedRootFailureOrder.order(index,plan,retainedCaseIds)
    fun requireMatches(index: RecordedShardDiagnosticIndex, plan: RecordedDiagnosticPlan, retainedCaseIds: List<String>, claimedCanonicalBytes: ByteArray) {
        plan.context.meter.checkAccess(); diagnosticCapacity(index.context===plan.context)
        plan.context.meter.guardedInput { diagnosticCapacity(retainedCaseIds.size in 0..plan.context.limits.retainedCases) }
        val g=DiagnosticGraphCodec(plan.context)
        diagnosticCapacity(claimedCanonicalBytes.size in 1..g.limits.canonicalBytes)
        val claim=g.parse(claimedCanonicalBytes)
        g.fields(claim,"kind","authority","version","sourceRevisionSha256","policySha256","indexSha256","retainedCaseIds","retainedCasesSha256","rows","witnessSha256","unattached","blockers","assessmentSha256")
        val fresh=order(index,plan,retainedCaseIds)
        diagnosticCapacity(g.equal(g.encode(claim),g.encode(fresh.record)))
    }
}
private fun compareOwnerSort(g:DiagnosticGraphCodec,a:DiagnosticOwner,b:DiagnosticOwner):Int {
    val ab=if(a is DiagnosticOwner.Module)g.encode(g.str(a.shardId)) else g.encode(graphOwner(g,a))
    val bb=if(b is DiagnosticOwner.Module)g.encode(g.str(b.shardId)) else g.encode(graphOwner(g,b))
    for(i in 0 until minOf(ab.size,bb.size)) {
        var c=0; g.step("owner sort byte") { c=(ab[i].toInt() and 255).compareTo(bb[i].toInt() and 255) }; if(c!=0)return c
    }
    return ab.size.compareTo(bb.size)
}
