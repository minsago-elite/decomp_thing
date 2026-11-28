package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class ShardRootFailureOrderingTest {
    @Test fun literalG1SccRanksRootsDiamondImpactAndPolicy() {
        val f=RecordedDiagnosticFixtures.create(); val index=ShardDiagnosticIndex.build(f.batch,f.plan); val order=ShardRootFailureOrdering.order(index,f.plan,listOf("case-b","case-a","case-a"))
        RecordedDiagnosticFixtures.retain(if(f.plan.dependencyPlanSha256.startsWith("69e7"))"G1" else "G2",f,index,order)
        assertEquals(listOf("h","e","g","a","b","f","c","d"),RecordedDiagnosticFixtures.labels(index,order))
        assertEquals("b70c27d089a0dd65451806d75b73e03ce7f270b9a2e1715907e41181e4d2948d",order.policySha256)
        val ranks=mapOf("h" to 0L,"e" to 0L,"g" to 0L,"a" to 1L,"b" to 1L,"f" to 1L,"c" to 2L,"d" to 2L)
        for(row in order.rows)assertEquals(ranks.getValue(RecordedDiagnosticFixtures.label(index,row.groupId)),row.dependencyRank)
        val header=order.rows.first(); assertEquals(listOf('a','b','c','d').map(RecordedDiagnosticFixtures::id),header.impactModuleIds)
        assertEquals("component-8743f8f65ae3a1019e216e14d5ce448fb069db9f121b3dc152bf03a8b65c8da2",header.componentId)
        for(row in order.rows) {
            val label=RecordedDiagnosticFixtures.label(index,row.groupId)
            assertEquals(listOf(when(label) { "e","f" -> "e"; "g" -> "g"; else -> "h" }),row.rootGroupIds.map { RecordedDiagnosticFixtures.label(index,it) })
        }
        assertEquals(listOf("case-a","case-b"),order.retainedCaseIds)
        assertTrue(order.blockers.any { it.code==DiagnosticBlockerCode.SHARED_NONEDITABLE })
        assertArrayEquals(OracleJson.canonicalBytes(order.record),order.canonicalBytes)
        ShardRootFailureOrdering.requireMatches(index,f.plan,listOf("case-a","case-b"),order.canonicalBytes)
    }
    @Test fun literalG2SameKeyRootsKeepBothOwnerAndSampleWitnesses() {
        val f=RecordedDiagnosticFixtures.create(2); val index=ShardDiagnosticIndex.build(f.batch,f.plan); val order=ShardRootFailureOrdering.order(index,f.plan,emptyList())
        RecordedDiagnosticFixtures.retain(if(f.plan.dependencyPlanSha256.startsWith("69e7"))"G1" else "G2",f,index,order)
        assertEquals(listOf("h","e","g","a","b","f","c","d"),RecordedDiagnosticFixtures.labels(index,order))
        val cd=order.rows.single { RecordedDiagnosticFixtures.label(index,it.groupId)=="c" }
        assertEquals(setOf("h","e"),cd.rootGroupIds.map { RecordedDiagnosticFixtures.label(index,it) }.toSet())
        assertEquals(2,cd.rootGroupIds.size); assertEquals(1,cd.rootDiagnosticKeys.size)
        val e=order.rows.single { RecordedDiagnosticFixtures.label(index,it.groupId)=="e" }
        assertEquals(listOf('c','d','f').map(RecordedDiagnosticFixtures::id),e.impactModuleIds)
    }
    @Test fun literalG3BothSeedsInCycleSurviveAndG4ImpactWinsTie() {
        val f=RecordedDiagnosticFixtures.create(3); val index=ShardDiagnosticIndex.build(f.batch,f.plan); val order=ShardRootFailureOrdering.order(index,f.plan,emptyList())
        RecordedDiagnosticFixtures.retain("G3",f,index,order)
        assertEquals(listOf("e","a","b","g","c","d","f"),RecordedDiagnosticFixtures.labels(index,order))
        for(label in listOf("c","d")) {
            val row=order.rows.single { RecordedDiagnosticFixtures.label(index,it.groupId)==label }
            assertEquals(1L,row.dependencyRank); assertEquals(setOf("c","d"),row.rootGroupIds.map { RecordedDiagnosticFixtures.label(index,it) }.toSet())
        }
        val q=RecordedDiagnosticFixtures.create(4); val qi=ShardDiagnosticIndex.build(q.batch,q.plan); val qo=ShardRootFailureOrdering.order(qi,q.plan,emptyList())
        RecordedDiagnosticFixtures.retain("G4",q,qi,qo)
        assertEquals(listOf("q","h","e","g","a","b","f","c","d"),RecordedDiagnosticFixtures.labels(qi,qo))
        assertEquals(listOf('r','s','t','u','v').map(RecordedDiagnosticFixtures::id),qo.rows.first().impactModuleIds)
    }
    @Test fun rehashedRankRootImpactComponentAndChangedCasesReject() {
        val f=RecordedDiagnosticFixtures.create(); val index=ShardDiagnosticIndex.build(f.batch,f.plan); val order=ShardRootFailureOrdering.order(index,f.plan,listOf("case"))
        for(field in listOf("dependencyRank","componentId","rootGroupIds","impactModuleIds")) {
            val rows=order.record.getValue("rows").jsonArray.toMutableList(); val row=rows[0].jsonObject
            val wrong=when(field) { "dependencyRank" -> JsonPrimitive(999); "componentId" -> JsonPrimitive("component-forged"); else -> JsonArray(emptyList()) }
            rows[0]=JsonObject(row+(field to wrong))
            val base=JsonObject(order.record-"assessmentSha256"+("rows" to JsonArray(rows)))
            val forged=JsonObject(base+("assessmentSha256" to JsonPrimitive(RecordedDiagnosticFixtures.sha(OracleJson.canonicalBytes(base)))))
            assertThrows(DiagnosticInputException::class.java) { ShardRootFailureOrdering.requireMatches(index,f.plan,listOf("case"),OracleJson.canonicalBytes(forged)) }
        }
        assertThrows(DiagnosticInputException::class.java) { ShardRootFailureOrdering.requireMatches(index,f.plan,listOf("other"),order.canonicalBytes) }
    }
}
