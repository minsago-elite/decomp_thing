package decompengine.project

import kotlin.test.*
import kotlinx.serialization.json.*

class NativeInterfaceTypeGraphV1Test {
    @Test
    fun `cycles and reused objects preserve local graph coordinates without equality claims`() {
        val graph = validator()
        val rows = cycleRows()
        rows.forEach { row -> accept(graph, row) }
        graph.root(InferredInterfaceFixture.root("inferred", 0, "inferred-parameter", 1, null, 1))
        graph.finish()
        assertEquals(2L, graph.nodeCount)
        assertEquals(2L, graph.edgeCount)
        assertEquals(2L, graph.rootCount)
    }

    @Test
    fun `new back and reused references must describe actual depth first traversal state`() {
        val rows = cycleRows()
        for ((index, key, value) in listOf(
            Triple(1, "referenceState", JsonPrimitive("reused-node")),
            Triple(1, "target", JsonPrimitive(9)),
            Triple(2, "id", JsonPrimitive(0)),
            Triple(3, "referenceState", JsonPrimitive("reused-node")),
            Triple(3, "source", JsonPrimitive(0)),
            Triple(3, "ordinal", JsonPrimitive(1)),
            Triple(3, "relation", JsonPrimitive("array-element")),
            Triple(4, "node", JsonPrimitive(1)),
        )) assertFails {
            val graph = validator()
            rows.forEachIndexed { at, row -> accept(graph, if (at == index) InferredInterfaceFixture.set(row, value, key) else row) }
            graph.finish()
        }
        assertFails { val graph=validator(); graph.node(rows[0]); graph.finish() }
        assertFails { val graph=validator(); rows.dropLast(1).forEach { accept(graph,it) }; graph.finish() }
    }

    @Test
    fun `same size structure union integer and float remain distinct typed nodes`() {
        val graph = validator()
        val kinds = listOf("structure", "union", "integer", "float")
        val observed = kinds.mapIndexed { index, kind ->
            val details = when(kind) { "structure", "union" -> InferredInterfaceFixture.compositeDetails(0); "integer" -> InferredInterfaceFixture.obj("signed" to false); else -> InferredInterfaceFixture.obj() }
            val row = graph.node(InferredInterfaceFixture.node("inferred",0,index,kind,0,details,length=8))
            graph.root(InferredInterfaceFixture.root("inferred",0,"inferred-parameter",index,null,index))
            row
        }
        graph.finish()
        assertEquals(kinds, observed.map { it.kind })
        assertEquals(listOf(0,1,2,3), observed.map { it.id })
        assertTrue(observed.all { it.length == 8 })
    }

    @Test
    fun `partial typedef and function definition preserve unavailable populations and missing targets`() {
        val cases = listOf(
            Triple("typedef", InferredInterfaceFixture.obj("autoNamed" to false, "settingsState" to "unavailable-bounded-count-api"), "typedef-target"),
            Triple("function-definition", InferredInterfaceFixture.obj("convention" to null, "varArgs" to false, "noReturn" to false, "argumentsState" to "unavailable-bounded-count-api"), "function-return"),
        )
        for ((kind,details,relation) in cases) {
            val graph=validator()
            val node=graph.node(InferredInterfaceFixture.node("inferred",0,0,kind,1,details))
            graph.edge(InferredInterfaceFixture.edge("inferred",0,0,0,relation,null,"missing"))
            val root=graph.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0)).first
            graph.finish()
            assertEquals("partial",node.expansion)
            assertEquals(0,root.node)
            assertEquals(1L,graph.edgeCount)
        }
        val unsupported=validator()
        assertEquals("unsupported",unsupported.node(InferredInterfaceFixture.node("inferred",0,0,"unsupported",0,InferredInterfaceFixture.obj())).expansion)
        unsupported.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0)); unsupported.finish()
    }

    @Test
    fun `array extent bitfield and composite relationships retain typed facts and reject inconsistent shapes`() {
        val arrays = listOf(Triple(0,8,"zero-length"),Triple(-1,8,"unknown"),Triple(2,4,"consistent"),Triple(2,8,"inconsistent"))
        for ((count,length,state) in arrays) {
            val graph=validator()
            val node=graph.node(InferredInterfaceFixture.node("inferred",0,0,"array",1,InferredInterfaceFixture.obj("elementCount" to count,"elementLength" to length,"extentState" to state),length=8))
            graph.edge(InferredInterfaceFixture.edge("inferred",0,0,0,"array-element",null,"missing"))
            graph.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0)); graph.finish()
            assertEquals(state,node.details.getValue("extentState").jsonPrimitive.content)
        }
        assertFails { validator().node(InferredInterfaceFixture.node("inferred",0,0,"array",1,InferredInterfaceFixture.obj("elementCount" to 2,"elementLength" to 4,"extentState" to "unknown"),length=8)) }
        val bit=validator()
        bit.node(InferredInterfaceFixture.node("inferred",0,0,"bitfield",1,InferredInterfaceFixture.obj("storageSize" to 4,"declaredBitSize" to 40,"effectiveBitSize" to 32,"bitOffset" to 0,"baseTypeSize" to 4,"bigEndian" to true)))
        bit.edge(InferredInterfaceFixture.edge("inferred",0,0,0,"bitfield-base",null,"missing")); bit.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0)); bit.finish()
        assertFails {
            val graph=validator(); graph.node(InferredInterfaceFixture.node("inferred",0,0,"structure",1,InferredInterfaceFixture.compositeDetails(1)))
            graph.edge(InferredInterfaceFixture.edge("inferred",0,0,0,"component",null,"missing"))
        }
    }

    @Test
    fun `scope local node IDs restart and cannot borrow a prior scope or reopen it`() {
        val graph=validator()
        graph.node(InferredInterfaceFixture.node("listing",0,0,"integer",0,InferredInterfaceFixture.obj("signed" to true)))
        graph.root(InferredInterfaceFixture.root("listing",0,"return-formal",-1,0,0))
        graph.node(InferredInterfaceFixture.node("inferred",0,0,"integer",0,InferredInterfaceFixture.obj("signed" to true)))
        graph.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0)); graph.finish()
        assertFails { graph.root(InferredInterfaceFixture.root("listing",1,"return-formal",-1,1,0)) }
        assertFails { val g=validator(); g.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0)) }
        assertFails { val g=validator(); g.node(InferredInterfaceFixture.node("inferred",1,1,"integer",0,InferredInterfaceFixture.obj("signed" to true))) }
    }

    @Test
    fun `graph bounds are charged before extra nodes edges roots and depth are admitted`() {
        val exact=NativeInferredInterfaceObservationLimitsV1(maximumGraphNodes=2,maximumGraphEdges=2,maximumRoots=1,maximumGraphDepth=1)
        val graph=validator(exact); cycleRows().forEach { accept(graph,it) }; graph.finish()
        for (limits in listOf(exact.copy(maximumGraphNodes=1),exact.copy(maximumGraphEdges=1),exact.copy(maximumRoots=0),exact.copy(maximumGraphDepth=0),exact.copy(maximumGraphChildren=0))) {
            assertFails { val g=validator(limits); cycleRows().forEach { accept(g,it) }; g.finish() }
        }
        assertFails { validator().node(InferredInterfaceFixture.node("inferred",0,0,"structure",4097,InferredInterfaceFixture.compositeDetails(4097))) }
        assertFails {
            val g=validator()
            g.node(InferredInterfaceFixture.node("inferred",0,0,"typedef",1,InferredInterfaceFixture.obj("autoNamed" to false,"settingsState" to "unavailable-bounded-count-api")))
            g.edge(InferredInterfaceFixture.edge("inferred",0,0,0,"typedef-target",0,"backedge"))
            g.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0))
        }
        val cumulative=validator(NativeInferredInterfaceObservationLimitsV1(maximumGraphDepth=1))
        cumulative.node(InferredInterfaceFixture.node("inferred",0,0,"integer",0,InferredInterfaceFixture.obj("signed" to true)))
        cumulative.root(InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0))
        for (id in 1..2) {
            cumulative.node(InferredInterfaceFixture.node("inferred",0,id,"typedef",1,InferredInterfaceFixture.obj("autoNamed" to false,"settingsState" to "unavailable-bounded-count-api")))
            cumulative.edge(InferredInterfaceFixture.edge("inferred",0,id,0,"typedef-target",id-1,"reused-node"))
            if (id==1) cumulative.root(InferredInterfaceFixture.root("inferred",0,"inferred-parameter",id,null,id))
            else assertFails { cumulative.root(InferredInterfaceFixture.root("inferred",0,"inferred-parameter",id,null,id)) }
        }
    }

    @Test
    fun `closed node edge and root records reject extra semantic or authority fields`() {
        for (index in cycleRows().indices) {
            assertFails {
                val graph=validator()
                cycleRows().forEachIndexed { at,row -> accept(graph,if(at==index) JsonObject(row + ("productionVerified" to JsonPrimitive(true))) else row) }
                graph.finish()
            }
        }
        assertFails { validator().node(InferredInterfaceFixture.node("inferred",0,0,"integer",0,InferredInterfaceFixture.obj("signed" to true,"sameTypeAsOracle" to true))) }
    }

    private fun validator(limits: NativeInferredInterfaceObservationLimitsV1=NativeInferredInterfaceObservationLimitsV1()) = NativeInterfaceTypeGraphValidatorV1(limits) {}
    private fun accept(graph:NativeInterfaceTypeGraphValidatorV1,row:JsonObject) { when(row.getValue("recordKind").jsonPrimitive.content) {
        "type-node" -> graph.node(row); "type-edge" -> graph.edge(row); "type-root" -> graph.root(row); else -> error("unexpected authored row")
    } }
    private fun cycleRows()=listOf(InferredInterfaceFixture.node("inferred",0,0,"pointer",1,InferredInterfaceFixture.obj("pointerSize" to 8),length=8),
        InferredInterfaceFixture.edge("inferred",0,0,0,"pointer-target",1,"new-node"),InferredInterfaceFixture.node("inferred",0,1,"structure",1,InferredInterfaceFixture.compositeDetails(1),length=8),
        InferredInterfaceFixture.edge("inferred",0,1,0,"component",0,"backedge",component=true),InferredInterfaceFixture.root("inferred",0,"inferred-return",-1,null,0))
}
