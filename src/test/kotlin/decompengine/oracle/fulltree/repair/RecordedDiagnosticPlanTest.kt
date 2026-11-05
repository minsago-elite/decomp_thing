package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

internal class RecordedDiagnosticPlanTest {
    @Test fun escapedCountFieldMustRejectBeforeMaterialization() {
        val counts=mutableListOf<Int>()
        for(field in listOf("modules","headerOwners","sourceOnlyUnits","headerObservations","directFileEdges","blockers","components","edges")) {
            val limits=ShardDiagnosticLimits(moduleMappings=1,headerNodes=1,sourceOnlyUnits=1,headerObservations=1,directEdges=1,graphBlockers=1,graphNodes=1,condensationEdges=1)
            var materialized=0
            val c=DiagnosticComputationContext(limits,checkpoint={ if(it=="before final graph scalar String")materialized++ })
            val canonical=OracleJson.canonicalBytes(RecordedDiagnosticFixtures.obj(field to JsonArray(listOf(RecordedDiagnosticFixtures.obj("x" to JsonPrimitive("one")),RecordedDiagnosticFixtures.obj("x" to JsonPrimitive("two"))))))
            val escaped=canonical.decodeToString().replace("\"$field\"", "\"\\u"+field[0].code.toString(16).padStart(4,'0')+field.drop(1)+"\"").toByteArray()
            assertThrows(DiagnosticInputException::class.java) { DiagnosticGraphCodec(c).parse(escaped) }
            println("ESCAPED_COUNT field=$field cap=1 rows=2 scalarMaterializations=$materialized")
            counts.add(materialized)
        }
        assertEquals(List(8){0},counts,"over-cap escaped fields materialized scalars before rejection")
    }

    @Test fun escapedHeaderCountThroughRealPlanEntryMustNotMaterialize() {
        val f=RecordedDiagnosticFixtures.create(includeBatch=false);val old=f.plan.version
        var materialized=0
        val c=DiagnosticComputationContext(ShardDiagnosticLimits(headerNodes=0),checkpoint={if(it=="before final graph scalar String")materialized++})
        val version=DiagnosticGraphVersion(c,1,old.planningArtifactSha256,old.planningReportSha256,old.planningConfigurationSha256,old.dependencyPlanSha256,0,old.frozenInterfaceSha256,0,null)
        val escaped=f.header.decodeToString().replace("\"headerOwners\"","\"\\u0068eaderOwners\"").replace("\"headerOwnerIds\"","\"\\u0068eaderOwnerIds\"").toByteArray()
        assertThrows(DiagnosticInputException::class.java) {RecordedDiagnosticPlans.fromFixture(c,escaped,f.modules,f.evidence,"c".repeat(64),version)}
        println("ESCAPED_HEADER_PLAN headerNodes=0 actualHeaderRows=1 scalarMaterializations=$materialized")
        assertEquals(0,materialized,"plan traversed over-cap header data before canonical rejection")
    }


    @Test fun canonicalKeyEscapesAndLiteralUnicodeRemainRoundTrippable() {
        val keys = listOf("\u0000", "\u0001", "\u001f", "\b\t\n\u000c\r", "\"\\/", "\u0100", "\uD800\uDC00")
        for (key in keys) {
            val codec = DiagnosticGraphCodec(DiagnosticComputationContext())
            val bytes = OracleJson.canonicalBytes(RecordedDiagnosticFixtures.obj(key to JsonPrimitive("value")))
            assertArrayEquals(bytes, codec.encode(codec.parse(bytes)))
        }
        for (key in listOf("\\u006dodules", "\\u0100", "\\uD800\\uDC00", "\\u000a", "\\u001F", "\\/")) {
            var materialized = 0
            val context = DiagnosticComputationContext(checkpoint = { if (it == "before final graph scalar String") materialized++ })
            val bytes = "{\n  \"$key\": []\n}\n".toByteArray()
            assertThrows(DiagnosticInputException::class.java) { DiagnosticGraphCodec(context).parse(bytes) }
            assertEquals(0, materialized, "noncanonical key allocated a scalar")
        }
    }

    @Test fun realHeaderRecipesAndIndependentCombinedPreimages() {
        for(variant in 1..4) {
            val f=RecordedDiagnosticFixtures.create(variant)
            assertEquals(RecordedDiagnosticFixtures.sha(f.preimage),f.plan.dependencyPlanSha256)
            assertArrayEquals(f.preimage,DiagnosticGraphCodec(f.context).encode(f.plan.record.getValue("graph")))
            val folder=Path.of("build/orchestration/scheduler-886-algorithms/fixtures"); Files.createDirectories(folder)
            Files.write(folder.resolve("G$variant-header.json"),f.header); Files.write(folder.resolve("G$variant-graph.json"),f.preimage)
            assertArrayEquals(OracleJson.canonicalBytes(f.plan.record),f.plan.canonicalBytes)
            assertTrue(f.plan.complete); assertEquals("c".repeat(64),f.plan.sourceRevisionSha256)
        }
    }
    @Test fun canonicalCodecMatchesOracleWithUnicodeEscapesAndNewline() {
        val g=DiagnosticGraphCodec(DiagnosticComputationContext())
        val value=RecordedDiagnosticFixtures.obj("\uE000" to JsonPrimitive("\uD800\uDC00\t\n\\\""),"a" to JsonPrimitive(10),"\uD800\uDC00" to JsonPrimitive("x\u0001"))
        val bytes=OracleJson.canonicalBytes(value)
        assertArrayEquals(bytes,g.encode(value)); assertArrayEquals(bytes,g.encode(g.parse(bytes)))
    }
    @Test fun headerRehashCannotInventOwnershipOrComponents() {
        val f=RecordedDiagnosticFixtures.create(includeBatch=false)
        val h=OracleJson.parse(f.header).jsonObject
        val forged=JsonObject(h+ ("authority" to JsonPrimitive("authenticated")))
        val without=JsonObject(forged-"reportSha256")
        val bytes=OracleJson.canonicalBytes(JsonObject(without+("reportSha256" to JsonPrimitive(RecordedDiagnosticFixtures.sha(OracleJson.canonicalBytes(without))))))
        assertThrows(DiagnosticInputException::class.java) { RecordedDiagnosticPlans.fromFixture(f.context,bytes,f.modules,f.evidence,"c".repeat(64),f.plan.version) }
    }
    @Test fun sourceGraphVersionAndMixedContextAdmission() {
        val f=RecordedDiagnosticFixtures.create(includeBatch=false)
        val other=DiagnosticComputationContext()
        assertThrows(DiagnosticInputException::class.java) { RecordedDiagnosticPlans.fromFixture(other,f.header,f.modules,f.evidence,"c".repeat(64),f.plan.version) }
        val bad=DiagnosticGraphVersion(f.context,1,"1".repeat(64),"2".repeat(64),"3".repeat(64),"0".repeat(64),0,"4".repeat(64),0,null)
        assertThrows(DiagnosticInputException::class.java) { RecordedDiagnosticPlans.fromFixture(f.context,f.header,f.modules,f.evidence,"c".repeat(64),bad) }
    }
    @Test fun literalIndependentOccurrenceAndCombinedGraphPins() {
        val expected=listOf("69e7c3c7d84b70cc3ac0a96a73d91f2c8eb1d2abf83d722e843f1df6aaaa8384",
            "ced2cd06cd5cc5560d4e3899ea941a31c207fea4ebc5c0b6730d473e80132f85",
            "1fafe1ad797e874447d318b76571e8e458b3dc75bc6bc9c14670a89088c80c4f",
            "46b339cc2b3a1642d4ea33f50262fd9f8de7d79b9fc6854f7fbf8571facbf8c1")
        for(variant in 1..4)assertEquals(expected[variant-1],RecordedDiagnosticFixtures.create(variant,includeBatch=false).plan.dependencyPlanSha256)
        val vectors=OracleJson.parse(requireNotNull(javaClass.getResourceAsStream("/diagnostics/scheduler-886-literal-vectors.json")) { "scheduler diagnostic literal vectors missing" }.use { it.readBytes() }).jsonObject
        val g=DiagnosticGraphCodec(DiagnosticComputationContext())
        assertEquals("diagnostic-occurrence-facc6ba3b866a334e82b31ebf6153f9685193835b46f89db07e5464c03ae8cf4",
            g.id("diagnostic-occurrence",vectors.getValue("occurrenceBinding"),true))
    }
    @Test fun moduleEvidencePermutationAndStructurallyEqualVersionObjects() {
        val f=RecordedDiagnosticFixtures.create(); val v=f.plan.version
        val clone=DiagnosticGraphVersion(f.context,v.schema,v.planningArtifactSha256,v.planningReportSha256,v.planningConfigurationSha256,
            v.dependencyPlanSha256,v.dependencyGeneration,v.frozenInterfaceSha256,v.frozenGeneration,v.planTransitionSha256)
        val plan=RecordedDiagnosticPlans.fromFixture(f.context,f.header,f.modules.reversed(),f.evidence.reversed(),"c".repeat(64),clone)
        assertArrayEquals(f.plan.canonicalBytes,plan.canonicalBytes)
        val index=ShardDiagnosticIndex.build(f.batch,f.plan)
        val order=ShardRootFailureOrdering.order(index,plan,emptyList())
        assertEquals(listOf("h","e","g","a","b","f","c","d"),RecordedDiagnosticFixtures.labels(index,order))
        val repeated=ShardDiagnosticIndex.build(f.batch,plan,index)
        assertTrue(repeated.relocations.isEmpty())
    }
    @Test fun generationContradictionsMissingProofAndOverflowAreBounded() {
        val f=RecordedDiagnosticFixtures.create(includeBatch=false); val c=f.context; val v=f.plan.version
        fun version(generation:Long,frozen:Long=0,hash:String=v.dependencyPlanSha256,transition:String?="5".repeat(64))=
            DiagnosticGraphVersion(c,1,v.planningArtifactSha256,v.planningReportSha256,v.planningConfigurationSha256,hash,generation,v.frozenInterfaceSha256,frozen,transition)
        fun build(now:DiagnosticGraphVersion,old:DiagnosticGraphVersion?=v)=RecordedDiagnosticPlans.fromFixture(c,f.header,f.modules,f.evidence,"c".repeat(64),now,old)
        assertThrows(DiagnosticInputException::class.java) { build(version(2)) }
        assertThrows(DiagnosticInputException::class.java) { build(version(0,hash="0".repeat(64))) }
        assertThrows(DiagnosticInputException::class.java) { build(version(0)) }
        assertTrue(build(version(1,transition=null)).blockers.any { it.code==DiagnosticBlockerCode.UNVERIFIED_TRANSITION })
        assertTrue(build(version(1),null).blockers.any { it.code==DiagnosticBlockerCode.UNVERIFIED_TRANSITION })
        assertEquals(1L,build(version(0,frozen=1)).version.frozenGeneration)
        assertThrows(DiagnosticInputException::class.java) { build(version(0),version(Long.MAX_VALUE)) }
    }

}
