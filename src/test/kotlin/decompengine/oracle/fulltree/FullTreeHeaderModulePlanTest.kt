package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.util.PriorityQueue
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject

class FullTreeHeaderModulePlanTest {
    @Test
    fun `first-class header owners and condensation DAG are complete stable and deterministic`() {
        val fixture = graphFixture()
        val first = fixture.build()
        val permuted = fixture.copy(
            modules = fixture.modules.reversed(),
            headers = fixture.headers.reversed(),
            sourceOnly = fixture.sourceOnly.reversed(),
            edges = fixture.edges.reversed(),
        ).build()

        assertTrue(first.complete)
        assertEquals(3, first.moduleCount)
        assertEquals(5, first.headerCount)
        assertEquals(7, first.componentCount)
        assertEquals(6, first.condensationEdgeCount)
        assertContentEquals(first.canonicalBytes, permuted.canonicalBytes)
        assertEquals(first.reportSha256, permuted.reportSha256)

        val document = parse(first)
        assertEquals(1L, document.controlObject("counts").controlLong("isolatedModules"))
        val owners = document.controlArray("headerOwners").controlObjects("header owners")
            .associate { it.controlString("sourcePath") to it.controlString("headerOwnerId") }
        assertEquals(5, owners.values.toSet().size)
        assertTrue(owners.values.all { it.matches(Regex("header-[0-9a-f]{64}")) })
        assertTrue(owners.values.none { owner -> fixture.modules.any { it.moduleId == owner } })
        assertNotEquals(owners.getValue("source/a/cycle.h"), owners.getValue("source/b/cycle.h"))

        val dag = document.controlObject("condensationDag")
        val components = dag.controlArray("components").controlObjects("components")
        val componentIds = components.map { it.controlString("componentId") }
        assertEquals(componentIds.sortedWith(FULL_TREE_CODE_POINT_ORDER), componentIds)
        assertTrue(componentIds.all { it.matches(Regex("scc-[0-9a-f]{64}")) })
        assertEquals(
            components.single {
                owners.getValue("source/a/cycle.h") in
                    it.controlArray("memberNodeIds").map { member -> member.controlString("member") }
            }.controlString("componentId"),
            components.single {
                owners.getValue("source/b/cycle.h") in
                    it.controlArray("memberNodeIds").map { member -> member.controlString("member") }
            }.controlString("componentId"),
        )

        val edges = dag.controlArray("edges").controlObjects("condensation edges").map {
            it.controlString("dependencyComponentId") to it.controlString("consumerComponentId")
        }
        val order = dag.controlArray("kahnOrder").map { it.controlString("Kahn component") }
        val positions = order.withIndex().associate { it.value to it.index }
        edges.forEach { (dependency, consumer) ->
            assertTrue(positions.getValue(dependency) < positions.getValue(consumer))
        }
        assertEquals(referenceKahn(componentIds, edges), order)

        val withoutReport = JsonObject(document.filterKeys { it != "reportSha256" })
        assertEquals(
            first.reportSha256,
            OracleArtifacts.sha256(
                OracleJson.canonicalBytes(withoutReport, controlJsonLimits(HEADER_PLAN_MAXIMUM_SERIALIZED_BYTES)),
            ),
        )
        val hostileCopy = first.canonicalBytes
        hostileCopy[0] = (hostileCopy[0].toInt() xor 1).toByte()
        assertContentEquals(permuted.canonicalBytes, first.canonicalBytes)
    }

    @Test
    fun `malformed duplicate unknown catch-all and source-only ownership fail closed`() {
        val valid = graphFixture()
        val hostile = listOf<() -> Unit>(
            { valid.copy(modules = valid.modules.mapIndexed { i, it -> if (i == 0) it.copy(moduleId = "cu-0") else it }).build() },
            { valid.copy(modules = valid.modules.mapIndexed { i, it -> if (i == 0) it.copy(shardId = "catch-all") else it }).build() },
            { valid.copy(modules = valid.modules.mapIndexed { i, it -> if (i == 0) it.copy(sourcePath = "source/../escape.cpp") else it }).build() },
            { valid.copy(modules = valid.modules + valid.modules.first()).build() },
            { valid.copy(headers = valid.headers + valid.headers.first()).build() },
            { valid.copy(edges = valid.edges + valid.edges.first()).build() },
            { valid.copy(edges = valid.edges + FullTreeResolvedDirectFileEdge("source/missing.cpp", "source/a/a.h")).build() },
            { valid.copy(edges = valid.edges + FullTreeResolvedDirectFileEdge("source/a/a.cpp", "source/missing.h")).build() },
            { valid.copy(edges = valid.edges + FullTreeResolvedDirectFileEdge("source/tools/gen.cpp", "source/a/a.h")).build() },
            { valid.copy(sourceOnly = valid.sourceOnly + FullTreeHeaderSourceOnlyUnit("tools", "source/a/a.cpp")).build() },
        )
        hostile.forEachIndexed { index, build ->
            assertFailsWith<FullTreeHeaderModulePlanException>("hostile fixture $index") { build() }
        }
    }

    @Test
    fun `accounted blockers preserve known graph but make report incomplete`() {
        val evidence = "a".repeat(64)
        val module = FullTreeHeaderPlanningModule(MODULE_A, "a", "source/a/a.cpp", 1)
        val header = FullTreeCanonicalHeader("source/a/a.h")
        val blocker = FullTreeHeaderResolutionBlocker(
            module.sourcePath,
            FullTreeHeaderResolutionBlockerKind.CONDITIONAL,
            evidence,
        )
        val result = FullTreeHeaderModulePlan.build(
            listOf(module),
            listOf(header),
            emptyList(),
            listOf(FullTreeResolvedDirectFileEdge(module.sourcePath, header.sourcePath)),
            listOf(blocker),
        )
        assertFalse(result.complete)
        assertEquals("incomplete-accounted-blockers", parse(result).controlString("status"))
        assertEquals(2, result.componentCount)

        val invalid = listOf<() -> Unit>(
            { FullTreeHeaderModulePlan.build(listOf(module), listOf(header), emptyList(), emptyList(), emptyList()) },
            { FullTreeHeaderModulePlan.build(listOf(module.copy(unresolvedBlockerCount = 0)), listOf(header), emptyList(), emptyList(), listOf(blocker)) },
            { FullTreeHeaderModulePlan.build(listOf(module), listOf(header), emptyList(), emptyList(), listOf(blocker.copy(consumerPath = "source/unknown.cpp"))) },
            { FullTreeHeaderModulePlan.build(listOf(module), listOf(header), listOf(FullTreeHeaderSourceOnlyUnit("tools", "source/tools/gen.cpp")), emptyList(), listOf(blocker.copy(consumerPath = "source/tools/gen.cpp"))) },
            { FullTreeHeaderModulePlan.build(listOf(module), listOf(header), emptyList(), emptyList(), listOf(blocker.copy(evidenceSha256 = "A".repeat(64)))) },
            { FullTreeHeaderModulePlan.build(listOf(module.copy(unresolvedBlockerCount = 2)), listOf(header), emptyList(), emptyList(), listOf(blocker, blocker)) },
        )
        invalid.forEachIndexed { index, build ->
            assertFailsWith<FullTreeHeaderModulePlanException>("blocker fixture $index") { build() }
        }
    }

    @Test
    fun `caller bounds cover lowering records graph work and canonical bytes`() {
        val fixture = graphFixture()
        val baseline = fixture.build()
        val limits = FullTreeHeaderModulePlanLimits()
        val bounded = listOf(
            limits.copy(maximumModules = 2),
            limits.copy(maximumHeaders = 4),
            limits.copy(maximumDirectEdges = 7),
            limits.copy(maximumGraphNodes = 7),
            limits.copy(maximumCondensationEdges = 5),
            limits.copy(maximumWorkUnits = baseline.workUnits - 1),
            limits.copy(maximumSerializedBytes = 256),
        )
        bounded.forEachIndexed { index, bound ->
            assertFailsWith<FullTreeHeaderModulePlanException>("bound $index") { fixture.build(bound) }
        }
        assertFailsWith<IllegalArgumentException> { limits.copy(maximumWorkUnits = 0) }
    }

    private fun parse(result: FullTreeHeaderModulePlanResult): JsonObject =
        OracleJson.parseCanonical(
            result.canonicalBytes,
            controlJsonLimits(HEADER_PLAN_MAXIMUM_SERIALIZED_BYTES),
        ) as JsonObject

    private fun referenceKahn(
        componentIds: List<String>,
        edges: List<Pair<String, String>>,
    ): List<String> {
        val outgoing = componentIds.associateWith { sortedSetOf(FULL_TREE_CODE_POINT_ORDER) }.toMutableMap()
        val indegree = componentIds.associateWith { 0 }.toMutableMap()
        edges.forEach { (dependency, consumer) ->
            outgoing.getValue(dependency).add(consumer)
            indegree[consumer] = indegree.getValue(consumer) + 1
        }
        val ready = PriorityQueue(FULL_TREE_CODE_POINT_ORDER)
        indegree.filterValues { it == 0 }.keys.forEach(ready::add)
        return buildList {
            while (ready.isNotEmpty()) {
                val dependency = ready.remove()
                add(dependency)
                outgoing.getValue(dependency).forEach { consumer ->
                    val remaining = indegree.getValue(consumer) - 1
                    indegree[consumer] = remaining
                    if (remaining == 0) ready.add(consumer)
                }
            }
        }
    }
}

private data class HeaderPlanFixture(
    val modules: List<FullTreeHeaderPlanningModule>,
    val headers: List<FullTreeCanonicalHeader>,
    val sourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
    val edges: List<FullTreeResolvedDirectFileEdge>,
) {
    fun build(limits: FullTreeHeaderModulePlanLimits = FullTreeHeaderModulePlanLimits()) =
        FullTreeHeaderModulePlan.build(modules, headers, sourceOnly, edges, emptyList(), limits)
}

private fun graphFixture(): HeaderPlanFixture = HeaderPlanFixture(
    modules = listOf(
        FullTreeHeaderPlanningModule(MODULE_A, "a", "source/a/a.cpp"),
        FullTreeHeaderPlanningModule(MODULE_B, "b", "source/b/b.cpp"),
        FullTreeHeaderPlanningModule(MODULE_C, "isolated", "source/isolated/c.cpp"),
    ),
    headers = listOf(
        FullTreeCanonicalHeader("source/a/a.h"),
        FullTreeCanonicalHeader("source/b/b.h"),
        FullTreeCanonicalHeader("source/shared/shared.h"),
        FullTreeCanonicalHeader("source/a/cycle.h"),
        FullTreeCanonicalHeader("source/b/cycle.h"),
    ),
    sourceOnly = listOf(FullTreeHeaderSourceOnlyUnit("tools", "source/tools/gen.cpp")),
    edges = listOf(
        FullTreeResolvedDirectFileEdge("source/a/a.cpp", "source/a/a.h"),
        FullTreeResolvedDirectFileEdge("source/a/a.cpp", "source/shared/shared.h"),
        FullTreeResolvedDirectFileEdge("source/b/b.cpp", "source/b/b.h"),
        FullTreeResolvedDirectFileEdge("source/b/b.cpp", "source/shared/shared.h"),
        FullTreeResolvedDirectFileEdge("source/a/a.h", "source/a/cycle.h"),
        FullTreeResolvedDirectFileEdge("source/b/b.h", "source/b/cycle.h"),
        FullTreeResolvedDirectFileEdge("source/a/cycle.h", "source/b/cycle.h"),
        FullTreeResolvedDirectFileEdge("source/b/cycle.h", "source/a/cycle.h"),
    ),
)

private const val MODULE_A = "cu-11111111111111111111111111111111"
private const val MODULE_B = "cu-22222222222222222222222222222222"
private const val MODULE_C = "cu-33333333333333333333333333333333"
