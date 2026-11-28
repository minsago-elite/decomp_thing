package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import java.util.concurrent.atomic.AtomicReference
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ShardDiagnosticIndexTest {
    private val fx=RecordedDiagnosticFixtures
    @Test fun physicalMultiplicityExactReferencesAndActionPermutation() {
        val f=fx.create(includeBatch=false); val c=f.context; val payload="error: a\n".toByteArray(); val raw=payload+payload
        val a=fx.observation(c,payload,spans=listOf(DiagnosticSpan(DiagnosticStream.STDERR,0,9)))
        val b=fx.observation(c,payload,spans=listOf(DiagnosticSpan(DiagnosticStream.STDERR,9,18)))
        val action=fx.action(c,"action-a","1".repeat(64),raw,listOf(a,b,a))
        val index=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(action)),f.plan)
        assertEquals(2,index.samples.size); assertEquals(1,index.groups.size); assertEquals(2,index.groups.single().sampleIds.size)
        assertTrue(index.coverage.all { it.complete }); assertEquals(18,index.coverage.sumOf { it.bytes })
        val permuted=fx.action(c,"action-a","1".repeat(64),raw,listOf(b,a,a))
        val again=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(permuted)),f.plan)
        assertArrayEquals(index.canonicalBytes,again.canonicalBytes)
        val other=fx.action(c,"action-b","1".repeat(64),raw,listOf(a,b))
        val both=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(other,action)),f.plan)
        assertEquals(4,both.samples.size); assertEquals(1,both.groups.size)
    }
    @Test fun emptyBinaryAndUnknownTailsNeverDisappear() {
        val f=fx.create(includeBatch=false); val c=f.context; val payload="error: a\n".toByteArray()
        val tail=fx.action(c,"tail","1".repeat(64),payload+byteArrayOf(33),listOf(fx.observation(c,payload)))
        val empty=fx.action(c,"empty","2".repeat(64),byteArrayOf(),emptyList())
        val binary=byteArrayOf(0xc3.toByte(),0x28,0xff.toByte())
        val bin=fx.action(c,"binary","3".repeat(64),binary,listOf(fx.observation(c,binary)),capture=false)
        val index=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(tail,empty,bin)),f.plan)
        assertEquals(3,index.opaqueActions.size); assertEquals(2,index.samples.size)
        val stderr=index.coverage.single { it.actionId=="tail" && it.stream==DiagnosticStream.STDERR }
        assertEquals(listOf(DiagnosticSpan(DiagnosticStream.STDERR,9,10)),stderr.unparsedSpans)
        assertEquals("7260da181cc952b2a568e214a50e99a75448e8d5c5f01d46da0dae0eae99409c",index.coverage.single { it.actionId=="binary" && it.stream==DiagnosticStream.STDERR }.sha256)
        assertTrue(index.blockers.any { it.code==DiagnosticBlockerCode.INCOMPLETE_CAPTURE })
        for(row in index.coverage)assertEquals(row.bytes,(row.diagnosticSpans+row.unparsedSpans).sumOf { it.endExclusive-it.start })
    }
    @Test fun multispanRequiresCanonicalPipeFramingAndOverlapsReject() {
        val f=fx.create(includeBatch=false); val c=f.context
        val frame=JsonArray(listOf("stdout" to byteArrayOf(65),"stderr" to byteArrayOf(66)).map { (pipe,b) -> fx.obj("stream" to fx.s(pipe),"bytes" to JsonPrimitive(1),"sha256" to fx.s(fx.sha(b))) })
        val spans=listOf(DiagnosticSpan(DiagnosticStream.STDOUT,0,1),DiagnosticSpan(DiagnosticStream.STDERR,0,1))
        val payload=OracleJson.canonicalBytes(frame)
        val o=fx.observation(c,payload,spans=spans)
        val action=fx.action(c,"both","1".repeat(64),byteArrayOf(66),listOf(o),stdout=byteArrayOf(65))
        assertEquals(1,ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(action)),f.plan).samples.size)
        val wrong=fx.observation(c,byteArrayOf(65,66),spans=spans)
        val bad=fx.action(c,"bad","2".repeat(64),byteArrayOf(66),listOf(wrong),stdout=byteArrayOf(65))
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(bad)),f.plan) }
        val raw="error: a\n".toByteArray()
        val one=fx.observation(c,raw); val two=fx.observation(c,raw.copyOfRange(1,raw.size),spans=listOf(DiagnosticSpan(DiagnosticStream.STDERR,1,raw.size.toLong())))
        val overlap=fx.action(c,"overlap","3".repeat(64),raw,listOf(one,two))
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(overlap)),f.plan) }
    }
    @Test fun linkKnownUnknownAndConflictingOwnersStayExplicit() {
        for(conflict in listOf(false,true)) {
            val f=fx.create(includeBatch=false,entityConflict=conflict); val c=f.context; val raw="undefined reference to sym-b\n".toByteArray()
            fun index(entity:String):RecordedShardDiagnosticIndex {
                val o=fx.observation(c,raw,path=null,entity=entity,stage=DiagnosticStage.LINK,tool="9".repeat(64))
                val a=fx.action(c,"link","8".repeat(64),raw,listOf(o),stage=DiagnosticStage.LINK,tool="9".repeat(64))
                return ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(a)),f.plan)
            }
            val known=index("entity-b")
            if(conflict)assertTrue(known.groups.single().owner is DiagnosticOwner.Conflict)
            else assertEquals(fx.id('b'),(known.groups.single().owner as DiagnosticOwner.Module).moduleId)
            val unknown=index("libc::malloc")
            assertTrue(unknown.groups.single().owner is DiagnosticOwner.Unknown)
            val order=ShardRootFailureOrdering.order(unknown,f.plan,emptyList()); assertTrue(order.rows.isEmpty()); assertFalse(order.blockers.isEmpty())
        }
    }
    @Test fun sharedPathIsNeverElectedObservingModuleAndConflictingAnchorBlocks() {
        val f=fx.create(); val index=ShardDiagnosticIndex.build(f.batch,f.plan)
        val header=index.groups.single { it.owner is DiagnosticOwner.Shared }.owner as DiagnosticOwner.Shared
        assertEquals(fx.HEADER,header.headerOwnerId); assertEquals(listOf(fx.id('a'),fx.id('b')),header.consumerModuleIds)
        val raw="error: conflict\n".toByteArray(); val o=fx.observation(f.context,raw,path=fx.path('a'),entity="entity-b")
        val action=fx.action(f.context,"conflict","8".repeat(64),raw,listOf(o))
        val conflict=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(f.context,listOf(action)),f.plan)
        assertTrue(conflict.groups.single().owner is DiagnosticOwner.Conflict)
        assertNull(conflict.groups.single().occurrenceId)
    }
    @Test fun actionRedefinitionsAndConflictingClassClaimsRetainEvidence() {
        val f=fx.create(includeBatch=false); val c=f.context; val raw="error: a\n".toByteArray()
        val one=fx.observation(c,raw,klass=FailureClass.OWNERSHIP); val other=fx.observation(c,raw,klass=FailureClass.INTERFACE)
        val a=fx.action(c,"a","1".repeat(64),raw,listOf(one,other))
        val b=fx.action(c,"a","2".repeat(64),raw,listOf(other))
        val index=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(a,b)),f.plan)
        assertEquals(2,index.actions.size); assertEquals(FailureClass.UNCLASSIFIED,index.groups.single().failureClass)
        assertTrue(index.blockers.any { it.code==DiagnosticBlockerCode.CONFLICT && it.evidenceIds.size>=2 })
    }
    @Test fun explicitPredecessorRelocationKeepsBothVersionsOwnersAndSamples() {
        val c=DiagnosticComputationContext(); val f=fx.create(context=c,includeBatch=false)
        val raw="error: moved\n".toByteArray()
        val o=fx.observation(c,raw,path=null,entity="entity-a")
        val a=fx.action(c,"moved","a".repeat(64),raw,listOf(o))
        val old=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(a)),f.plan)
        val source="7".repeat(64); val inv=fx.invocation(source,2,"revision_00000001_"+"6".repeat(16))
        val moved=fx.create(context=c,move=true,predecessor=f.plan.version,source=source,inv=inv,includeBatch=false)
        val b=fx.action(c,"moved","a".repeat(64),raw,listOf(o),inv)
        val next=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(b)),moved.plan,old)
        assertEquals(old.groups.single().key,next.groups.single().key); assertNotEquals(old.groups.single().occurrenceId,next.groups.single().occurrenceId)
        assertEquals(fx.id('b'),(next.groups.single().owner as DiagnosticOwner.Module).moduleId)
        val folder=java.nio.file.Path.of("build/orchestration/scheduler-886-algorithms/fixtures")
        java.nio.file.Files.createDirectories(folder)
        java.nio.file.Files.write(folder.resolve("G1-prime-graph.json"),moved.preimage)
        java.nio.file.Files.write(folder.resolve("G1-relocation-old-index.json"),old.canonicalBytes)
        java.nio.file.Files.write(folder.resolve("G1-relocation-new-index.json"),next.canonicalBytes)
        assertEquals(1,next.relocations.size); val relocation=next.relocations.single()
        assertEquals("recorded-relocation",relocation.getValue("disposition").jsonPrimitive.content)
        assertTrue(OracleJson.canonicalBytes(relocation).decodeToString().contains(old.samples.single().id))
        assertTrue(OracleJson.canonicalBytes(relocation).decodeToString().contains(next.samples.single().id))
        val changed=fx.observation(c,"error: moved elsewhere\n".toByteArray(),path=null,entity="entity-a")
        val changedAction=fx.action(c,"changed","b".repeat(64),changed.payload,listOf(changed),inv)
        val changedIndex=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(changedAction)),moved.plan,old)
        assertEquals(2,changedIndex.relocations.size); assertTrue(changedIndex.blockers.any { it.code==DiagnosticBlockerCode.MOVED_UNRESOLVED })
    }
    @Test fun foreignPreviousSourceAndSameInvocationRedefinitionReject() {
        val f=fx.create(); val old=ShardDiagnosticIndex.build(f.batch,f.plan)
        val other=fx.create()
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(other.batch,other.plan,old) }
        val c=f.context; val raw="error: a\n".toByteArray(); val action=fx.action(c,"changed","1".repeat(64),raw,listOf(fx.observation(c,raw)))
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(action)),f.plan,old) }
    }
    @Test fun returnedViewsAndBytesAreImmutableAndThreadConfined() {
        val f=fx.create(); val index=ShardDiagnosticIndex.build(f.batch,f.plan); val order=ShardRootFailureOrdering.order(index,f.plan,listOf("case"))
        val before=index.canonicalBytes; val mutated=index.canonicalBytes; mutated[0]=0; assertArrayEquals(before,index.canonicalBytes)
        assertThrows(UnsupportedOperationException::class.java) { (index.groups as MutableList).clear() }
        assertThrows(UnsupportedOperationException::class.java) { (index.byKey as MutableMap).clear() }
        assertThrows(UnsupportedOperationException::class.java) { (index.groups.first().sampleIds as MutableList).clear() }
        assertThrows(UnsupportedOperationException::class.java) { (order.rows.first().impactModuleIds as MutableList).clear() }
        val failure=AtomicReference<Throwable>(); val thread=Thread { try { index.samples } catch(t:Throwable) { failure.set(t) } }; thread.start(); thread.join()
        assertTrue(failure.get() is DiagnosticInputException)
    }
    @Test fun conflictingDefinitionPermutationsKeepCanonicalCompleteEvidence() {
        val f=fx.create(includeBatch=false); val c=f.context; val raw="error: a\n".toByteArray()
        val actions=(1..3).map { n -> fx.action(c,"same-action",n.toString().repeat(64),raw,
            listOf(fx.observation(c,raw,klass=if(n==1)FailureClass.OWNERSHIP else FailureClass.INTERFACE))) }
        val permutations=listOf(listOf(0,1,2),listOf(0,2,1),listOf(1,0,2),listOf(1,2,0),listOf(2,0,1),listOf(2,1,0))
        var expected:ByteArray?=null
        for(p in permutations) {
            val index=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,p.map { actions[it] }),f.plan)
            assertEquals(3,index.actions.size); assertEquals(3,index.samples.size)
            if(expected==null)expected=index.canonicalBytes else assertArrayEquals(expected,index.canonicalBytes)
        }
    }
    @Test fun samePhysicalSampleWithConflictingOwnersRetainsBothAndBlocks() {
        val f=fx.create(includeBatch=false); val c=f.context; val raw="error: owner\n".toByteArray()
        val a=fx.observation(c,raw,path=fx.path('a'),entity="entity-a")
        val b=fx.observation(c,raw,path=fx.path('b'),entity="entity-b")
        val action=fx.action(c,"same-sample","1".repeat(64),raw,listOf(a,b))
        val index=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,listOf(action)),f.plan)
        assertEquals(1,index.samples.size); assertEquals(2,index.groups.size)
        val conflict=index.blockers.single { it.code==DiagnosticBlockerCode.CONFLICT }
        assertTrue(conflict.evidenceIds.contains(index.samples.single().id))
        assertTrue(index.groups.all { conflict.evidenceIds.contains(it.id) })
    }

    @Test fun ambiguousMovementRetainsOwnerMultisetsWithoutInventedPairs() {
        val c=DiagnosticComputationContext(); val first=fx.create(context=c,includeBatch=false)
        val raw="error: same\n".toByteArray()
        fun batch(labels:String,inv:decompengine.repair.RepairValidationInvocation)=RecordedCompileLinkBatch(c,labels.map { label ->
            fx.action(c,"move-$label","a".repeat(64),raw,listOf(fx.observation(c,raw,path=null,entity="entity-$label")),inv) })
        val old=ShardDiagnosticIndex.build(batch("ab",fx.invocation()),first.plan)
        val source="7".repeat(64); val inv=fx.invocation(source,2,"revision_00000001_"+"6".repeat(16))
        val next=fx.create(context=c,predecessor=first.plan.version,source=source,inv=inv,includeBatch=false)
        val now=ShardDiagnosticIndex.build(batch("cd",inv),next.plan,old)
        assertEquals(1,now.relocations.size)
        val movement=now.relocations.single()
        assertEquals("MOVED_UNRESOLVED",movement.getValue("disposition").jsonPrimitive.content)
        assertEquals(2,movement.getValue("oldOwners").jsonArray.size); assertEquals(2,movement.getValue("newOwners").jsonArray.size)
    }
    @Test fun fidelityNotesLocationsSeverityAnsiAndFixitsAreExactByteEvidence() {
        val f=fx.create(includeBatch=false); val c=f.context
        val texts=listOf("a.cpp:1: error: x\n","a.cpp:2: error: x\n","a.cpp:1: warning: x\n","a.cpp:1: error: y\n",
            "\u001b[31ma.cpp:1: error: x\u001b[0m\n","error: x\nnote: a\nnote: b\n","error: x\nnote: b\nnote: a\n","error: x\nfix-it: replace foo\n")
        val actions=texts.mapIndexed { n,text -> val raw=text.toByteArray(); fx.action(c,"fidelity-$n",(n+1).toString().repeat(64),raw,listOf(fx.observation(c,raw))) }
        val index=ShardDiagnosticIndex.build(RecordedCompileLinkBatch(c,actions),f.plan)
        assertEquals(texts.size,index.byKey.size)
        assertEquals(texts.map { fx.sha(it.toByteArray()) }.toSet(),index.samples.map { it.payloadSha256 }.toSet())
    }

    @Test fun emptyPopulationCannotSupplyMissingPreviousRunProfileCorpusBindings() {
        val f=fx.create(); val empty=RecordedCompileLinkBatch(f.context,emptyList())
        val blank=ShardDiagnosticIndex.build(empty,f.plan)
        val populated=ShardDiagnosticIndex.build(f.batch,f.plan)
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(empty,f.plan,populated) }
        assertThrows(DiagnosticInputException::class.java) { ShardDiagnosticIndex.build(f.batch,f.plan,blank) }
        assertTrue(ShardDiagnosticIndex.build(empty,f.plan,blank).groups.isEmpty())
    }

}
