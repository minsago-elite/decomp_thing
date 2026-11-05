package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.*
import decompengine.repair.*
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.*

/** Independent small fixture recipe. Expectations never call production codec/SCC/order helpers. */
internal object RecordedDiagnosticFixtures {
    const val HEADER="header-1116449ebd0f4ac316c1a49fd5ea6629191dc4d1dae0f003cf2813043cdf90ba"
    const val HEADER_PATH="source/shared/h.h"
    fun id(label:Char):String { val ordinal=if(label in 'a'..'g')label-'a'+1 else label-'q'+8; return "cu-"+ordinal.toString(16).padStart(32,'0') }
    fun path(label:Char)="source/$label/$label.cpp"
    fun sha(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    fun obj(vararg fields:Pair<String,JsonElement>)=JsonObject(mapOf(*fields))
    fun s(v:String)=JsonPrimitive(v)
    fun strings(v:List<String>)=JsonArray(v.map(::s))
    fun invocation(source:String="c".repeat(64),serial:Int=1,candidate:String="root_"+"0".repeat(24))=RepairValidationInvocation(
        "validation_"+serial.toString(16).padStart(32,'0'),"run_00000001",candidate,source,"d".repeat(64),"e".repeat(64),"f".repeat(64))
    fun receipt(inv:RepairValidationInvocation)=RepairValidationObservedArtifact("reports/repair-revisions/validation-receipts/${inv.id}_${"b".repeat(64)}.json","b".repeat(64),1)
    class Fixture(val context:DiagnosticComputationContext,val plan:RecordedDiagnosticPlan,val batch:RecordedCompileLinkBatch,
        val modules:List<FullTreeHeaderPlanningModule>,val evidence:List<RepairModuleEvidence>,val header:ByteArray,val preimage:ByteArray)
    fun create(variant:Int=1,context:DiagnosticComputationContext=DiagnosticComputationContext(),move:Boolean=false,predecessor:DiagnosticGraphVersion?=null,
        source:String="c".repeat(64),inv:RepairValidationInvocation=invocation(source),includeBatch:Boolean=true,
        entityConflict:Boolean=false):Fixture {
        val labels=('a'..'g').toList()+(if(variant==4)('q'..'v').toList() else emptyList())
        val modules=labels.map { FullTreeHeaderPlanningModule(id(it),it.toString(),path(it)) }
        val withHeader=variant!=3
        val header=FullTreeHeaderModulePlan.build(modules,
            if(withHeader)listOf(FullTreeCanonicalHeader(HEADER_PATH)) else emptyList(),emptyList(),
            if(withHeader)listOf(FullTreeObservedHeaderUse(id('a'),HEADER_PATH),FullTreeObservedHeaderUse(id('b'),HEADER_PATH)) else emptyList(),
            if(withHeader)listOf(FullTreeResolvedDirectFileEdge(id('a'),path('a'),HEADER_PATH),FullTreeResolvedDirectFileEdge(id('b'),path('b'),HEADER_PATH),FullTreeResolvedDirectFileEdge(id('a'),HEADER_PATH,HEADER_PATH)) else emptyList(),emptyList()).canonicalBytes
        val dependencies=labels.associateWith { x -> when(x) { 'c' -> listOf('a','b','d')+(if(variant==2)listOf('e') else emptyList()); 'd' -> listOf('c'); 'f' -> listOf('e'); in 'r'..'v' -> listOf('q'); else -> emptyList() } }
        val evidence=labels.map { x -> RepairModuleEvidence(id(x),listOf(path(x)),entityIds=(
            (if(move && x=='a')emptyList() else listOf("entity-$x"))+(if(move && x=='b')listOf("entity-a") else emptyList())+
                (if(entityConflict && x=='a')listOf("entity-b") else emptyList())).sorted(),dependencyModuleIds=dependencies.getValue(x).map(::id).sorted()) }
        val nodeRows=modules.map { obj("nodeId" to s(it.moduleId),"kind" to s("module"),"sourcePath" to s(it.sourcePath),"shardId" to s(it.shardId)) }+
            (if(withHeader)listOf(obj("nodeId" to s(HEADER),"kind" to s("header"),"sourcePath" to s(HEADER_PATH),"shardId" to JsonNull)) else emptyList())
        val edgePairs=dependencies.flatMap { (consumer,ds) -> ds.map { id(consumer) to id(it) } }+
            (if(withHeader)listOf(id('a') to HEADER,id('b') to HEADER,HEADER to HEADER) else emptyList())
        val graph=obj("kind" to s("recorded-scheduler-graph-v1"),"planningArtifactSha256" to s("1".repeat(64)),"headerArtifactSha256" to s(sha(header)),
            "nodes" to JsonArray(nodeRows.sortedBy { it.getValue("nodeId").jsonPrimitive.content }),
            "ownership" to obj("modules" to JsonArray(evidence.map { e -> obj("id" to s(e.id),"shardId" to s(modules.single { it.moduleId==e.id }.shardId),
                "ownedPaths" to strings(e.ownedPaths),"entityIds" to strings(e.entityIds),"dependencyContextPaths" to strings(e.dependencyContextPaths)) }),
                "headers" to JsonArray(if(withHeader)listOf(obj("headerOwnerId" to s(HEADER),"sourcePath" to s(HEADER_PATH),"consumerModuleIds" to strings(listOf(id('a'),id('b'))))) else emptyList()),"sourceOnlyUnits" to JsonArray(emptyList())),
            "edges" to JsonArray(edgePairs.distinct().sortedWith(compareBy({it.first},{it.second})).map { (a,b) -> obj("consumerNodeId" to s(a),"dependencyNodeId" to s(b)) }),"blockers" to JsonArray(emptyList()))
        val preimage=OracleJson.canonicalBytes(graph)
        val version=DiagnosticGraphVersion(context,1,"1".repeat(64),"2".repeat(64),"3".repeat(64),sha(preimage),if(predecessor==null)0 else 1,"4".repeat(64),0,if(predecessor==null)null else "5".repeat(64))
        val plan=RecordedDiagnosticPlans.fromFixture(context,header,modules,evidence,source,version,predecessor)
        val failures=if(!includeBatch)emptyList() else ((if(withHeader)listOf('h') else emptyList())+listOf('e','g','a','b','f','c','d')+(if(variant==4)listOf('q') else emptyList())).map { x ->
            val payload="error: ${if(variant==2 && x=='e')'h' else x}\n".toByteArray()
            val ordinal="hegabfcdq".indexOf(x)+1
            val klass=when(x) { 'h','e','d','q' -> FailureClass.INTERFACE; 'c' -> FailureClass.OWNERSHIP; else -> FailureClass.OTHER }
            action(context,"action-$x",ordinal.toString(16).padStart(64,'0'),payload,
                listOf(observation(context,payload,if(x=='h')HEADER_PATH else path(x),if(x=='h')null else "entity-$x",klass)),inv)
        }
        return Fixture(context,plan,RecordedCompileLinkBatch(context,failures),modules,evidence,header,preimage)
    }
    fun observation(c:DiagnosticComputationContext,bytes:ByteArray,path:String?=path('a'),entity:String?="entity-a",klass:FailureClass=FailureClass.OTHER,
        spans:List<DiagnosticSpan> = listOf(DiagnosticSpan(DiagnosticStream.STDERR,0,bytes.size.toLong())),stage:DiagnosticStage=DiagnosticStage.COMPILE,tool:String="a".repeat(64))=
        RecordedDiagnosticObservation(c,stage,tool,bytes,spans,path,entity,klass)
    fun action(c:DiagnosticComputationContext,id:String,hash:String,stderr:ByteArray,observations:List<RecordedDiagnosticObservation>,
        inv:RepairValidationInvocation=invocation(),stdout:ByteArray=byteArrayOf(),stage:DiagnosticStage=DiagnosticStage.COMPILE,tool:String="a".repeat(64),capture:Boolean=true,exit:Int=1)=
        RecordedBuildFailure(c,id,hash,stage,tool,inv,receipt(inv),exit,stdout,stderr,observations,capture)
    fun labels(index:RecordedShardDiagnosticIndex,order:RecordedRootFailureOrder):List<String> = order.rows.map { row ->
        val group=index.groups.single { it.id==row.groupId }; index.samples.single { it.id==group.sampleIds.first() }.actionId.removePrefix("action-") }
    fun label(index:RecordedShardDiagnosticIndex,id:String):String { val group=index.groups.single { it.id==id }; return index.samples.single { it.id==group.sampleIds.first() }.actionId.removePrefix("action-") }
    fun retain(label:String,f:Fixture,index:RecordedShardDiagnosticIndex,order:RecordedRootFailureOrder) {
        val folder=Path.of("build/orchestration/scheduler-886-algorithms/fixtures"); Files.createDirectories(folder)
        Files.write(folder.resolve("$label-plan.json"),f.plan.canonicalBytes)
        Files.write(folder.resolve("$label-index.json"),index.canonicalBytes)
        val streams=f.batch.failures.mapIndexed { n,action ->
            val out="$label-action-$n.stdout"; val err="$label-action-$n.stderr"
            Files.write(folder.resolve(out),action.stdout); Files.write(folder.resolve(err),action.stderr)
            obj("invocationId" to s(action.invocation.id),"actionId" to s(action.actionId),"actionSha256" to s(action.actionSha256),
                "stdout" to s(out),"stderr" to s(err))
        }
        Files.write(folder.resolve("$label-stream-artifacts.json"),OracleJson.canonicalBytes(JsonArray(streams)))
        Files.write(folder.resolve("$label-order.json"),order.canonicalBytes)
        val counters=obj("workUnits" to JsonPrimitive(f.context.meter.used),"allocatedBytes" to JsonPrimitive(f.context.allocatedBytes),
            "actualGraphUnits" to JsonPrimitive(f.context.meter.graphCompletedUnits))
        Files.write(folder.resolve("$label-counters.json"),OracleJson.canonicalBytes(counters))
    }

    fun stress(count:Int,cycle:Boolean,context:DiagnosticComputationContext):Fixture {
        require(count>=2)
        fun module(i:Int)="cu-"+(i+1).toString(16).padStart(32,'0')
        val modules=(0 until count).map { FullTreeHeaderPlanningModule(module(it),"s-$it","source/s$it/s$it.cpp") }
        val evidence=(0 until count).map { i -> RepairModuleEvidence(module(i),listOf(modules[i].sourcePath),entityIds=listOf("entity-$i"),
            dependencyModuleIds=if(cycle)listOf(module((i+1)%count)) else if(i>0)listOf(module(0)) else emptyList()) }
        val header=FullTreeHeaderModulePlan.build(modules,emptyList(),emptyList(),emptyList(),emptyList(),emptyList()).canonicalBytes
        val graph=obj("kind" to s("recorded-scheduler-graph-v1"),"planningArtifactSha256" to s("1".repeat(64)),"headerArtifactSha256" to s(sha(header)),
            "nodes" to JsonArray(modules.map { obj("nodeId" to s(it.moduleId),"kind" to s("module"),"sourcePath" to s(it.sourcePath),"shardId" to s(it.shardId)) }),
            "ownership" to obj("modules" to JsonArray(evidence.mapIndexed { i,e -> obj("id" to s(e.id),"shardId" to s(modules[i].shardId),
                "ownedPaths" to strings(e.ownedPaths),"entityIds" to strings(e.entityIds),"dependencyContextPaths" to strings(emptyList())) }),
                "headers" to JsonArray(emptyList()),"sourceOnlyUnits" to JsonArray(emptyList())),
            "edges" to JsonArray(evidence.flatMap { e -> e.dependencyModuleIds.map { obj("consumerNodeId" to s(e.id),"dependencyNodeId" to s(it)) } }),"blockers" to JsonArray(emptyList()))
        val preimage=OracleJson.canonicalBytes(graph)
        val v=DiagnosticGraphVersion(context,1,"1".repeat(64),"2".repeat(64),"3".repeat(64),sha(preimage),0,"4".repeat(64),0,null)
        val plan=RecordedDiagnosticPlans.fromFixture(context,header,modules,evidence,"c".repeat(64),v)
        val payload="error: shared\n".toByteArray()
        val failures=(0 until if(cycle)count else 1).map { i -> action(context,"seed-$i",(i+1).toString(16).padStart(64,'0'),payload,
            listOf(observation(context,payload,modules[i].sourcePath,"entity-$i",FailureClass.INTERFACE))) }
        return Fixture(context,plan,RecordedCompileLinkBatch(context,failures),modules,evidence,header,preimage)
    }

}
