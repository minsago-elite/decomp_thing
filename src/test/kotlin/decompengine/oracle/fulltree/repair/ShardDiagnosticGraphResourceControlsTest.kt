package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import java.util.concurrent.CancellationException
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ShardDiagnosticGraphResourceControlsTest {
    private val fx=RecordedDiagnosticFixtures
    private class SizeOnly<T>(override val size:Int):AbstractList<T>() {
        var reads=0
        override fun get(index:Int):T { reads++; error("element read before count") }
        override fun iterator():Iterator<T> { reads++; error("iterator read before count") }
    }
    @Test fun allNewCeilingsAreLowerOnlyAndEveryCountSnapshotAdmitsBeforeAccess() {
        val setters=listOf<Pair<String,(Int)->ShardDiagnosticLimits>>(
            "invocations" to { ShardDiagnosticLimits(failedInvocations=it) },"modules" to { ShardDiagnosticLimits(moduleMappings=it) },
            "headers" to { ShardDiagnosticLimits(headerNodes=it) },"nodes" to { ShardDiagnosticLimits(graphNodes=it) },
            "edges" to { ShardDiagnosticLimits(directEdges=it) },"dag" to { ShardDiagnosticLimits(condensationEdges=it) },
            "cases" to { ShardDiagnosticLimits(retainedCases=it) },"keys" to { ShardDiagnosticLimits(diagnosticKeys=it) },
            "roots" to { ShardDiagnosticLimits(rootMemberships=it) },"impact" to { ShardDiagnosticLimits(impactMemberships=it) },
            "canonical" to { ShardDiagnosticLimits(canonicalBytes=it) },"depth" to { ShardDiagnosticLimits(jsonDepth=it) },
            "jsonNodes" to { ShardDiagnosticLimits(jsonNodes=it) },"number" to { ShardDiagnosticLimits(jsonNumberCharacters=it) },
            "exclusions" to { ShardDiagnosticLimits(sourceOnlyUnits=it) },"observations" to { ShardDiagnosticLimits(headerObservations=it) },
            "blockers" to { ShardDiagnosticLimits(graphBlockers=it) },"memberships" to { ShardDiagnosticLimits(ownershipMemberships=it) })
        for((name,set) in setters) {
            assertThrows(DiagnosticInputException::class.java) { set(-1) }
            assertThrows(DiagnosticInputException::class.java) { set(Int.MAX_VALUE) }
            set(0); set(1)
            val c=DiagnosticComputationContext()
            assertEquals(emptyList<String>(),c.graphSnapshot(emptyList<String>(),0,name))
            assertEquals(listOf("x"),c.graphSnapshot(listOf("x"),1,name))
            for(cap in 0..1) { val hostile=SizeOnly<String>(cap+1); assertThrows(DiagnosticInputException::class.java) { c.graphSnapshot(hostile,cap,name) }; assertEquals(0,hostile.reads) }
        }
    }
    @Test fun callbackGrowthReentryAndSequentialIteratorAdmission() {
        val values=mutableListOf("a"); var armed=true
        val c=DiagnosticComputationContext(checkpoint={ if(armed && it=="before hostile allocation") { armed=false; values.add("b") } })
        assertThrows(DiagnosticInputException::class.java) { c.graphSnapshot(values,1,"hostile") }
        lateinit var reentrant:DiagnosticComputationContext
        val caller=object:AbstractList<String>() {
            override val size:Int get() { reentrant.graphSnapshot(emptyList<String>(),0,"nested"); return 0 }
            override fun get(index:Int):String=error("not indexed")
        }
        reentrant=DiagnosticComputationContext()
        assertThrows(DiagnosticInputException::class.java) { reentrant.graphSnapshot(caller,0,"outer") }
        val sequential=object:AbstractList<String>() {
            override val size=3
            override fun get(index:Int):String=error("sequential list indexed")
            override fun iterator():Iterator<String> = listOf("c","a","b").iterator()
        }
        assertEquals(listOf("a","b","c"),diagnosticMergeSort(reentrant,sequential,3,reentrant::compareCodePoints))
        for(where in listOf("iterator","next")) {
            val bad=object:AbstractList<String>() {
                override val size=1
                override fun get(index:Int):String=error("not indexed")
                override fun iterator():Iterator<String> {
                    if(where=="iterator")reentrant.graphSnapshot(emptyList<String>(),0,"nested")
                    return object:Iterator<String> { override fun hasNext()=true; override fun next():String { reentrant.graphSnapshot(emptyList<String>(),0,"nested"); return "x" } }
                }
            }
            assertThrows(DiagnosticInputException::class.java) { reentrant.graphSnapshot(bad,1,"outer") }
        }
    }
    @Test fun maximumScalarOneOverAndPrivateRetention() {
        val text="a".repeat(4096); val bytes=OracleJson.canonicalBytes(fx.obj("value" to JsonPrimitive(text)))
        val g=DiagnosticGraphCodec(DiagnosticComputationContext()); val parsed=g.parse(bytes)
        assertEquals(text,parsed.getValue("value").jsonPrimitive.content)
        bytes.fill(0); assertEquals(text,parsed.getValue("value").jsonPrimitive.content)
        val unicode="\uD800\uDC00".repeat(1024)
        assertEquals(unicode,DiagnosticGraphCodec(DiagnosticComputationContext()).parse(OracleJson.canonicalBytes(fx.obj("value" to JsonPrimitive(unicode)))).getValue("value").jsonPrimitive.content)
        var materializations=0
        val low=DiagnosticGraphCodec(DiagnosticComputationContext(checkpoint={ if(it=="before final graph scalar String")materializations++ }))
        val over=OracleJson.canonicalBytes(fx.obj("value" to JsonPrimitive("a".repeat(4097))))
        assertThrows(DiagnosticInputException::class.java) { low.parse(over) }; assertEquals(0,materializations)
    }
    @Test fun scalarPrePostCancellationErrorAndCumulativeReservation() {
        val bytes=OracleJson.canonicalBytes(fx.obj("v" to JsonPrimitive("z".repeat(4096))))
        for(phase in listOf("before final graph scalar String","after final graph scalar String")) {
            val sentinel=CancellationException(phase)
            val g=DiagnosticGraphCodec(DiagnosticComputationContext(checkpoint={ if(it==phase)throw sentinel }))
            assertSame(sentinel,assertThrows(CancellationException::class.java) { g.parse(bytes) })
        }
        val error=AssertionError("sentinel")
        val err=DiagnosticGraphCodec(DiagnosticComputationContext(checkpoint={ if(it=="after final graph scalar String")throw error }))
        assertSame(error,assertThrows(AssertionError::class.java) { err.parse(bytes) })
        val c=DiagnosticComputationContext(ShardDiagnosticLimits(allocationBytes=90_000)); val g=DiagnosticGraphCodec(c)
        g.parse(bytes); val used=c.allocatedBytes; assertTrue(used>0)
        assertThrows(DiagnosticInputException::class.java) { repeat(20) { g.parse(bytes) } }; assertTrue(c.allocatedBytes>=used)
    }
    @Test fun parserRejectsMalformedUtf8DuplicateFieldsNumbersDepthAndByteLimits() {
        fun reject(bytes:ByteArray,limits:ShardDiagnosticLimits=ShardDiagnosticLimits()) = assertThrows(DiagnosticInputException::class.java) { DiagnosticGraphCodec(DiagnosticComputationContext(limits)).parse(bytes) }
        for(s in listOf("{\"x\":1,\"x\":2}","{\"x\":01}","{\"x\":1.0}","{\"x\":-1}","{\"x\":18446744073709551616}","{\"x\":9223372036854775808}","{\"x\":\"\\ud800\"}","{ \"x\": 1 }"))reject(s.toByteArray())
        for(raw in listOf(byteArrayOf(0xc0.toByte(),0x80.toByte()),byteArrayOf(0xed.toByte(),0xa0.toByte(),0x80.toByte()),byteArrayOf(0xf4.toByte(),0x90.toByte(),0x80.toByte(),0x80.toByte())))reject("{\"x\":\"".toByteArray()+raw+"\"}\n".toByteArray())
        val simple=OracleJson.canonicalBytes(fx.obj("x" to JsonPrimitive(1)))
        for(l in listOf(ShardDiagnosticLimits(canonicalBytes=0),ShardDiagnosticLimits(canonicalBytes=simple.size-1),ShardDiagnosticLimits(jsonDepth=0),ShardDiagnosticLimits(jsonNodes=1),ShardDiagnosticLimits(jsonNumberCharacters=0),ShardDiagnosticLimits(totalStringBytes=0)))reject(simple,l)
        assertArrayEquals(simple,DiagnosticGraphCodec(DiagnosticComputationContext(ShardDiagnosticLimits(canonicalBytes=simple.size,jsonDepth=1,jsonNodes=2,jsonNumberCharacters=1))).encode(fx.obj("x" to JsonPrimitive(1))))
        reject(("{\"x\":"+"[".repeat(25)+"0"+"]".repeat(25)+"}\n").toByteArray())
        assertThrows(DiagnosticInputException::class.java) { diagnosticAdd(Long.MAX_VALUE,1) }
        assertThrows(DiagnosticInputException::class.java) { diagnosticMultiply(Long.MAX_VALUE,2) }
    }
    @Test fun actualParserEncoderHashComparatorAndSnapshotCadenceAndCancellation() {
        val callbacks=mutableListOf<Pair<String,Long>>()
        lateinit var c:DiagnosticComputationContext
        c=DiagnosticComputationContext(checkpoint={ callbacks.add(it to c.meter.graphCompletedUnits) })
        val g=DiagnosticGraphCodec(c); val bytes=OracleJson.canonicalBytes(fx.obj("value" to JsonPrimitive("x".repeat(4096))))
        g.parse(bytes); g.hash(bytes); c.compareCodePoints("x".repeat(4095)+"\uE000","x".repeat(4095)+"\uD800\uDC00")
        c.graphSnapshot((0..1024).toList(),1025,"cadence snapshot")
        println("GRAPH_CADENCE actualUnits=${c.meter.graphCompletedUnits}, callbacks=${callbacks.size}, maximumActualGap=${callbacks.zipWithNext().maxOf { it.second.second-it.first.second }}")
        for((a,b) in callbacks.zipWithNext())assertTrue(b.second-a.second<=256,"gap ${b.second-a.second}: ${a.first} -> ${b.first}")
        assertTrue(callbacks.last().second>20_000)
        for(phase in listOf("graph parser byte","graph encoder byte","graph hash","graph comparator","cadence snapshot")) {
            val sentinel=CancellationException(phase); lateinit var x:DiagnosticComputationContext
            x=DiagnosticComputationContext(checkpoint={ if(it==phase && x.meter.graphCompletedUnits>=257)throw sentinel })
            val codec=DiagnosticGraphCodec(x)
            assertSame(sentinel,assertThrows(CancellationException::class.java) {
                when(phase) { "graph parser byte" -> codec.parse(bytes); "graph encoder byte" -> codec.encode(fx.obj("v" to JsonPrimitive("x".repeat(4096)))); "graph hash" -> codec.hash(ByteArray(4096));
                    "graph comparator" -> x.compareCodePoints("a".repeat(4096),"a".repeat(4096)); else -> x.graphSnapshot((0..1024).toList(),1025,phase) }
            })
        }
    }
    @Test fun codePointOrderWorstPrefixAndSortBeforeCountMutationControl() {
        val c=DiagnosticComputationContext(); val prefix="a".repeat(4094)
        assertTrue(c.compareCodePoints(prefix+"\uE000",prefix+"\uD800\uDC00")<0)
        val hostile=SizeOnly<String>(2); var compares=0
        assertThrows(DiagnosticInputException::class.java) { diagnosticMergeSort(c,hostile,1) { _,_ -> compares++; 0 } }
        assertEquals(0,hostile.reads); assertEquals(0,compares)
        val out=diagnosticMergeSort(c,listOf(prefix+"\uD800\uDC00",prefix+"\uE000"),2,c::compareCodePoints)
        assertEquals(prefix+"\uE000",out[0])
    }
    @Test fun realGraphCeilingsRejectBeforeForbiddenPhaseAndMembershipAppend() {
        for(limits in listOf(ShardDiagnosticLimits(moduleMappings=6),ShardDiagnosticLimits(headerNodes=0),ShardDiagnosticLimits(graphNodes=7),
            ShardDiagnosticLimits(directEdges=7),ShardDiagnosticLimits(condensationEdges=4),ShardDiagnosticLimits(headerObservations=1),ShardDiagnosticLimits(ownershipMemberships=15))) {
            assertThrows(DiagnosticInputException::class.java) { fx.create(context=DiagnosticComputationContext(limits),includeBatch=false) }
        }
        for(limits in listOf(ShardDiagnosticLimits(failedInvocations=0),ShardDiagnosticLimits(diagnosticKeys=7),ShardDiagnosticLimits(graphBlockers=0))) {
            val f=fx.create(context=DiagnosticComputationContext(limits)); assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(f.batch,f.plan) }
        }
        for(limits in listOf(ShardDiagnosticLimits(rootMemberships=0),ShardDiagnosticLimits(impactMemberships=8),ShardDiagnosticLimits(retainedCases=0))) {
            val f=fx.create(context=DiagnosticComputationContext(limits)); val i=ShardDiagnosticIndex.build(f.batch,f.plan)
            assertThrows(DiagnosticInputException::class.java) { ShardRootFailureOrdering.order(i,f.plan,listOf("case")) }
        }
        val exact=fx.create(context=DiagnosticComputationContext(ShardDiagnosticLimits(moduleMappings=7,headerNodes=1,graphNodes=8,directEdges=8,condensationEdges=5,headerObservations=2,ownershipMemberships=16,failedInvocations=1,diagnosticKeys=8,rootMemberships=11,impactMemberships=9,retainedCases=1)))
        val i=ShardDiagnosticIndex.build(exact.batch,exact.plan); assertEquals(8,ShardRootFailureOrdering.order(i,exact.plan,listOf("case")).rows.size)
    }
    @Test fun deep4096ModuleChainAnd8192HeaderChainAreIterative() {
        for((count,kind) in listOf(4096 to "module",8192 to "header")) {
            val c=DiagnosticComputationContext(); val g=DiagnosticGraphCodec(c)
            val nodes=(0 until count).map { RecordedGraphNode(c,"node-"+it.toString().padStart(5,'0'),kind,"source/$it",if(kind=="module")"a" else null) }
            val edges=(1 until count).map { RecordedGraphEdge(c,nodes[it].id,nodes[it-1].id) }
            val t=computeRecordedTopology(g,nodes,edges)
            assertEquals(count,t.components.size); assertEquals((count-1).toLong(),t.ranks[t.nodeComponent.getValue(nodes.last().id)])
        }
    }
    @Test fun topologyActualCadenceSccBothPassesKahnAndCancellation() {
        for(phase in listOf("graph SCC forward","graph SCC reverse","graph Kahn")) {
            val sentinel=CancellationException(phase)
            val c=DiagnosticComputationContext(checkpoint={ if(it.startsWith(phase))throw sentinel })
            val nodes=(0 until 512).map { RecordedGraphNode(c,"n"+it.toString().padStart(4,'0'),"module","source/$it","a") }
            val edges=(1 until 512).map { RecordedGraphEdge(c,nodes[it].id,nodes[it-1].id) }
            assertSame(sentinel,assertThrows(CancellationException::class.java) { computeRecordedTopology(DiagnosticGraphCodec(c),nodes,edges) })
        }
    }
    @Test fun foreignThreadEmptyEntryCheckpointReentryAndGetterCancellation() {
        val c=DiagnosticComputationContext(); val failure=AtomicReference<Throwable>()
        val t=Thread { try { c.graphSnapshot(emptyList<String>(),0,"empty") } catch(x:Throwable) { failure.set(x) } }; t.start(); t.join()
        assertTrue(failure.get() is DiagnosticInputException)
        lateinit var reentrant:DiagnosticComputationContext
        reentrant=DiagnosticComputationContext(checkpoint={ reentrant.graphSnapshot(emptyList<String>(),0,"nested") })
        assertThrows(DiagnosticInputException::class.java) { reentrant.graphSnapshot(emptyList<String>(),0,"entry") }
        var armed=false; val sentinel=CancellationException("getter")
        val g=DiagnosticComputationContext(checkpoint={ if(armed && it.contains("getter"))throw sentinel })
        val f=fx.create(context=g,includeBatch=false); armed=true
        assertSame(sentinel,assertThrows(CancellationException::class.java) { f.plan.canonicalBytes })
        Thread.currentThread().interrupt()
        try { assertThrows(InterruptedException::class.java) { c.graphSnapshot(emptyList<String>(),0,"interrupted") } } finally { Thread.interrupted() }
    }
    @Test fun duplicateEdgeFloodCountsRawRecordsBeforeDedup() {
        val c=DiagnosticComputationContext(ShardDiagnosticLimits(directEdges=1)); val g=DiagnosticGraphCodec(c)
        val node=RecordedGraphNode(c,"n","module","source/n","n"); val edge=RecordedGraphEdge(c,"n","n")
        assertEquals(1,computeRecordedTopology(g,listOf(node),listOf(edge)).components.size)
        assertThrows(DiagnosticInputException::class.java) { computeRecordedTopology(g,listOf(node),listOf(edge,edge)) }
    }
    @Test fun previousCurrentAggregateRejectsBeforeSampleTraversalAndNoPhaseReset() {
        val f=fx.create(context=DiagnosticComputationContext(ShardDiagnosticLimits(observations=15)))
        val index=ShardDiagnosticIndex.build(f.batch,f.plan)
        val spent=f.context.allocatedBytes
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(f.batch,f.plan,index) }
        assertTrue(f.context.allocatedBytes>=spent)
        val baseline=fx.create(includeBatch=false)
        val size=baseline.context.allocatedBytes
        val c=DiagnosticComputationContext(ShardDiagnosticLimits(allocationBytes=size+10_000))
        val exact=fx.create(context=c,includeBatch=false)
        assertThrows(DiagnosticInputException::class.java) { repeat(20) { exact.plan.canonicalBytes } }
    }
    @Test fun planAndRetainedCaseSizeOnlyPopulationFailsWithoutReads() {
        val f=fx.create(includeBatch=false)
        val huge=SizeOnly<decompengine.oracle.fulltree.FullTreeHeaderPlanningModule>(4097)
        assertThrows(DiagnosticInputException::class.java) { RecordedDiagnosticPlans.fromFixture(f.context,f.header,huge,f.evidence,"c".repeat(64),f.plan.version) }
        assertEquals(0,huge.reads)
        val batch=RecordedCompileLinkBatch(f.context,emptyList()); val index=ShardDiagnosticIndex.build(batch,f.plan)
        val cases=SizeOnly<String>(4097)
        assertThrows(DiagnosticInputException::class.java) { ShardRootFailureOrdering.order(index,f.plan,cases) }; assertEquals(0,cases.reads)
    }
    @Test fun rootImpactSpanAndSortCheckpointSentinelsPropagateUnchanged() {
        for(phase in listOf("before graph root propagation","before graph impact propagation","before graph sort","before graph hash")) {
            var armed=false; val sentinel=CancellationException(phase)
            val c=DiagnosticComputationContext(checkpoint={ if(armed && it==phase)throw sentinel })
            val f=fx.create(context=c); val index=ShardDiagnosticIndex.build(f.batch,f.plan); armed=true
            assertSame(sentinel,assertThrows(CancellationException::class.java) { ShardRootFailureOrdering.order(index,f.plan,emptyList()) })
        }
    }

    @Test fun headerSideTableCapsApplyInPreflightBeforeAnyScalarMaterialization() {
        val caps=listOf("modules" to ShardDiagnosticLimits(moduleMappings=1),"headerOwners" to ShardDiagnosticLimits(headerNodes=1),
            "sourceOnlyUnits" to ShardDiagnosticLimits(sourceOnlyUnits=1),"headerObservations" to ShardDiagnosticLimits(headerObservations=1),
            "directFileEdges" to ShardDiagnosticLimits(directEdges=1),"blockers" to ShardDiagnosticLimits(graphBlockers=1),
            "components" to ShardDiagnosticLimits(graphNodes=1),"edges" to ShardDiagnosticLimits(condensationEdges=1))
        for((field,limits) in caps) {
            val row=fx.obj("x" to JsonPrimitive("retained"))
            val exact=OracleJson.canonicalBytes(fx.obj(field to JsonArray(listOf(row))))
            DiagnosticGraphCodec(DiagnosticComputationContext(limits)).parse(exact)
            var materialized=0
            val over=OracleJson.canonicalBytes(fx.obj(field to JsonArray(listOf(row,row))))
            val c=DiagnosticComputationContext(limits,checkpoint={ if(it=="before final graph scalar String")materialized++ })
            assertThrows(DiagnosticInputException::class.java) { DiagnosticGraphCodec(c).parse(over) }
            assertEquals(0,materialized,field)
        }
    }
    @Test fun ownerBlockerVersionReadmissionRejectsForeignContextBeforeFields() {
        val c=DiagnosticComputationContext(); val other=DiagnosticComputationContext(); val g=DiagnosticGraphCodec(c)
        val owner=DiagnosticOwner.Module(other,fx.id('a'),"a")
        assertThrows(DiagnosticInputException::class.java) { graphOwner(g,owner) }
        val blocker=DiagnosticBlocker(other,DiagnosticBlockerCode.CONFLICT,emptyList())
        assertThrows(DiagnosticInputException::class.java) { graphBlocker(g,blocker) }
        val version=DiagnosticGraphVersion(other,1,"1".repeat(64),"2".repeat(64),"3".repeat(64),"4".repeat(64),0,"5".repeat(64),0,null)
        assertThrows(DiagnosticInputException::class.java) { graphVersion(g,version) }
    }

    @Test fun literalReferenceArrayScratchAndSegmentAllocationSchedule() {
        val c=DiagnosticComputationContext(); c.graphSnapshot(listOf("a","b"),2,"literal")
        assertEquals(80,c.allocatedBytes)
        val sorted=DiagnosticComputationContext(); diagnosticMergeSort(sorted,listOf("b","a"),2,sorted::compareCodePoints)
        assertEquals(192,sorted.allocatedBytes)
        val append=DiagnosticComputationContext(); val buffer=GraphAppend<String>(DiagnosticGraphCodec(append),1)
        buffer.add("a"); buffer.finish(); assertEquals(208,append.allocatedBytes)
    }

    @Test fun broadClosureAndManySccSeedsStopAtMembershipCeilings() {
        val exact=fx.stress(32,true,DiagnosticComputationContext(ShardDiagnosticLimits(rootMemberships=64,diagnosticKeys=1)))
        val index=ShardDiagnosticIndex.build(exact.batch,exact.plan); val order=ShardRootFailureOrdering.order(index,exact.plan,emptyList())
        assertEquals(32,order.rows.size); assertTrue(order.rows.all { it.rootGroupIds.size==32 && it.rootDiagnosticKeys.size==1 && it.dependencyRank==0L })
        val seeds=fx.stress(128,true,DiagnosticComputationContext(ShardDiagnosticLimits(rootMemberships=255)))
        val si=ShardDiagnosticIndex.build(seeds.batch,seeds.plan)
        assertThrows(DiagnosticInputException::class.java) { ShardRootFailureOrdering.order(si,seeds.plan,emptyList()) }
        val broad=fx.stress(256,false,DiagnosticComputationContext(ShardDiagnosticLimits(impactMemberships=254)))
        val bi=ShardDiagnosticIndex.build(broad.batch,broad.plan)
        assertThrows(DiagnosticInputException::class.java) { ShardRootFailureOrdering.order(bi,broad.plan,emptyList()) }
        val positive=fx.stress(256,false,DiagnosticComputationContext(ShardDiagnosticLimits(impactMemberships=255)))
        val pi=ShardDiagnosticIndex.build(positive.batch,positive.plan)
        assertEquals(255,ShardRootFailureOrdering.order(pi,positive.plan,emptyList()).rows.single().downstreamImpact)
    }

    @Test fun combinedHeaderCountsRejectBeforeAnyScalarMaterialization() {
        for(limits in listOf(ShardDiagnosticLimits(directEdges=7),ShardDiagnosticLimits(graphNodes=7),ShardDiagnosticLimits(ownershipMemberships=15))) {
            var scalarCopies=0
            val c=DiagnosticComputationContext(limits,checkpoint={ if(it=="before final graph scalar String")scalarCopies++ })
            assertThrows(DiagnosticInputException::class.java) { fx.create(context=c,includeBatch=false) }
            assertEquals(0,scalarCopies)
        }
    }

}
