package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleJson
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject

class FullTreeCompilerHeaderPlanProjectionTest {
    @Test
    fun `input order is deterministic while exact raw trace bytes remain committed`() {
        val firstBytes = document(aRecords())
        val snapshottedA = module(MODULE_A, "a", SOURCE_A, firstBytes)
        firstBytes.fill(0)
        val first = project(
            modules = listOf(snapshottedA, module(MODULE_B, "b", SOURCE_B, document(bRecords()))),
            headers = HEADERS,
            sourceOnly = SOURCE_ONLY,
            roots = ROOTS,
        )
        val shuffled = project(
            modules = listOf(
                module(MODULE_B, "b", SOURCE_B, document(bRecords())),
                module(MODULE_A, "a", SOURCE_A, document(aRecords())),
            ),
            headers = HEADERS.reversed(),
            sourceOnly = SOURCE_ONLY.reversed(),
            roots = ROOTS.reversed(),
        )

        assertContentEquals(first.canonicalBytes, shuffled.canonicalBytes)
        assertEquals(first.reportSha256, shuffled.reportSha256)
        assertFalse(first.complete)
        assertEquals(4, first.headerObservationCount)
        assertEquals(4, first.directEdgeCount)
        assertEquals(3, first.headerCount)
        assertEquals(2, first.blockerCount)

        val rawReordered = project(
            modules = listOf(
                module(MODULE_A, "a", SOURCE_A, document(aRecords().reversed())),
                module(MODULE_B, "b", SOURCE_B, document(bRecords().reversed())),
            ),
            headers = HEADERS,
            sourceOnly = SOURCE_ONLY,
            roots = ROOTS,
        )
        assertEquals(first.headerObservationCount, rawReordered.headerObservationCount)
        assertEquals(first.directEdgeCount, rawReordered.directEdgeCount)
        assertNotEquals(first.reportSha256, rawReordered.reportSha256)

        val document = parse(first)
        assertEquals(1L, document.controlObject("counts").controlLong("unreferencedHeaders"))
        assertTrue(
            document.controlArray("blockers").controlObjects("blockers").all {
                it.controlString("kind") == "compiler-trace-unauthenticated"
            },
        )
        val edges = document.controlArray("directFileEdges").controlObjects("direct edges")
        assertEquals(
            setOf(
                Triple(MODULE_A, SOURCE_A, HEADER_X),
                Triple(MODULE_A, HEADER_X, HEADER_Y),
                Triple(MODULE_B, SOURCE_B, HEADER_X),
                Triple(MODULE_B, HEADER_X, HEADER_Y),
            ),
            edges.map {
                Triple(
                    it.controlString("observingModuleId"),
                    it.controlString("consumerPath"),
                    it.controlString("dependencyHeaderPath"),
                )
            }.toSet(),
        )
        val owners = document.controlArray("headerOwners").controlObjects("headers")
            .associateBy { it.controlString("sourcePath") }
        assertEquals(
            listOf("a", "b"),
            owners.getValue(HEADER_X).controlArray("consumerShardIds")
                .map { it.controlString("consumer shard") },
        )
        assertEquals(
            emptyList(),
            owners.getValue(UNUSED_HEADER).controlArray("consumerShardIds")
                .map { it.controlString("consumer shard") },
        )
    }

    @Test
    fun `external imports noncanonical paths and out of context consumers stay blockers`() {
        val complex = project(
            modules = listOf(
                module(MODULE_A, "a", SOURCE_A, complexTrace()),
                module(MODULE_B, "b", SOURCE_B, byteArrayOf()),
            ),
            headers = listOf(HEADER_X, UNUSED_HEADER),
            sourceOnly = emptyList(),
            roots = ROOTS,
        )
        val document = parse(complex)
        val blockers = document.controlArray("blockers").controlObjects("blockers")
        val aBlockers = blockers.filter { it.controlString("consumerPath") == SOURCE_A }
        assertEquals(
            setOf(
                "compiler-trace-unauthenticated",
                "external-include",
                "module-import",
                "non-header-project-target",
                "out-of-scope-consumer",
            ),
            aBlockers.map { it.controlString("kind") }.toSet(),
        )
        assertEquals(aBlockers.size, aBlockers.map { it.controlString("kind") }.toSet().size)
        assertTrue(blockers.all { it.controlString("evidenceSha256").matches(Regex("[0-9a-f]{64}")) })
        val edges = document.controlArray("directFileEdges").controlObjects("direct edges")
        assertEquals(1, edges.size)
        assertEquals(MODULE_A, edges.single().controlString("observingModuleId"))
        assertEquals(SOURCE_A, edges.single().controlString("consumerPath"))
        assertEquals(HEADER_X, edges.single().controlString("dependencyHeaderPath"))
        assertTrue(
            edges.none {
                it.controlString("consumerPath") == SOURCE_B ||
                    it.controlString("consumerPath") == HELPER_SOURCE
            },
        )
    }

    @Test
    fun `missing duplicate and aliased module header and source-only inputs fail closed`() {
        val valid = module(MODULE_A, "a", SOURCE_A, document(aRecords().take(1)))
        val duplicateModuleId = module(MODULE_A, "b", SOURCE_B, byteArrayOf())
        val duplicateModulePath = module(MODULE_B, "b", SOURCE_A, byteArrayOf())
        val sourceOnly = FullTreeHeaderSourceOnlyUnit("tools", "source/tools/Tool.cpp")
        val hostile = listOf<() -> Unit>(
            { project(emptyList(), listOf(HEADER_X), emptyList(), ROOTS) },
            { project(listOf(valid, duplicateModuleId), listOf(HEADER_X), emptyList(), ROOTS) },
            { project(listOf(valid, duplicateModulePath), listOf(HEADER_X), emptyList(), ROOTS) },
            { project(listOf(module("cu-0", "a", SOURCE_A, byteArrayOf())), listOf(HEADER_X), emptyList(), ROOTS) },
            { project(listOf(module(MODULE_A, "catch-all", SOURCE_A, byteArrayOf())), listOf(HEADER_X), emptyList(), ROOTS) },
            { project(listOf(module(MODULE_A, "a", "source/../A.cpp", byteArrayOf())), listOf(HEADER_X), emptyList(), ROOTS) },
            { project(listOf(valid), emptyList(), emptyList(), ROOTS) },
            { project(listOf(valid), listOf(HEADER_X, HEADER_X), emptyList(), ROOTS) },
            { project(listOf(valid), listOf("source/include/not-a-header.cpp"), emptyList(), ROOTS) },
            { project(listOf(valid), listOf(HEADER_X), listOf(sourceOnly, sourceOnly), ROOTS) },
            {
                project(
                    listOf(valid),
                    listOf(HEADER_X),
                    listOf(FullTreeHeaderSourceOnlyUnit("catch-all", "source/tools/Tool.cpp")),
                    ROOTS,
                )
            },
            {
                project(
                    listOf(valid),
                    listOf(HEADER_X),
                    listOf(FullTreeHeaderSourceOnlyUnit("tools", SOURCE_A)),
                    ROOTS,
                )
            },
        )
        hostile.forEachIndexed { index, action ->
            assertFailsWith<FullTreeCompilerHeaderPlanProjectionException>("hostile input $index") {
                action()
            }
        }
    }

    @Test
    fun `aggregate bytes trace parser and projection work all honor caller lowering`() {
        val aBytes = document(aRecords())
        val bBytes = document(bRecords())
        val modules = listOf(
            module(MODULE_A, "a", SOURCE_A, aBytes),
            module(MODULE_B, "b", SOURCE_B, bBytes),
        )
        val totalBytes = aBytes.size.toLong() + bBytes.size.toLong()
        val defaults = FullTreeCompilerHeaderPlanProjectionLimits()
        val lowered = listOf(
            defaults.copy(maximumTotalTraceBytes = totalBytes - 1),
            defaults.copy(maximumTraces = 1),
            defaults.copy(
                trace = defaults.trace.copy(maximumIncludeOccurrences = 1),
            ),
            defaults.copy(
                trace = defaults.trace.copy(maximumInputBytes = aBytes.size - 1),
            ),
            defaults.copy(maximumEvidenceFacts = 1),
            defaults.copy(maximumEvidenceBytes = 1),
            defaults.copy(plan = defaults.plan.copy(maximumHeaders = 2)),
            defaults.copy(plan = defaults.plan.copy(maximumSourceOnlyUnits = 1)),
            defaults.copy(plan = defaults.plan.copy(maximumGraphNodes = 4)),
            defaults.copy(plan = defaults.plan.copy(maximumHeaderObservations = 3)),
            defaults.copy(plan = defaults.plan.copy(maximumDirectEdges = 3)),
            defaults.copy(plan = defaults.plan.copy(maximumBlockers = 1)),
            defaults.copy(maximumWorkUnits = 1),
        )
        lowered.forEachIndexed { index, limits ->
            assertFailsWith<FullTreeCompilerHeaderPlanProjectionException>("lowered limit $index") {
                project(modules, HEADERS, SOURCE_ONLY, ROOTS, limits)
            }
        }
        assertFailsWith<IllegalArgumentException> {
            defaults.copy(maximumTotalTraceBytes = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            defaults.copy(maximumEvidenceFacts = 0)
        }
        assertFailsWith<IllegalArgumentException> {
            defaults.copy(maximumEvidenceBytes = 0)
        }
    }

    private fun project(
        modules: List<FullTreeCompilerHeaderTraceModule>,
        headers: List<String>,
        sourceOnly: List<FullTreeHeaderSourceOnlyUnit>,
        roots: List<FullTreeClangTraceRoot>,
        limits: FullTreeCompilerHeaderPlanProjectionLimits =
            FullTreeCompilerHeaderPlanProjectionLimits(),
    ): FullTreeHeaderModulePlanResult = FullTreeCompilerHeaderPlanProjection.project(
        modules,
        headers,
        sourceOnly,
        roots,
        limits,
    )

    private fun parse(result: FullTreeHeaderModulePlanResult): JsonObject =
        OracleJson.parseCanonical(
            result.canonicalBytes,
            controlJsonLimits(HEADER_PLAN_MAXIMUM_SERIALIZED_BYTES),
        ) as JsonObject
}

private fun module(
    moduleId: String,
    shardId: String,
    sourcePath: String,
    trace: ByteArray,
): FullTreeCompilerHeaderTraceModule = FullTreeCompilerHeaderTraceModule(
    moduleId,
    shardId,
    sourcePath,
    trace,
)

private fun aRecords(): List<String> = listOf(
    record(
        "/trace/source/a/A.cpp",
        listOf(
            include("/trace/source/a/A.cpp:1:1", "/trace/source/include/X.h"),
            include("/trace/source/a/A.cpp:1:1", "/trace/source/include/X.h"),
        ),
    ),
    record(
        "/trace/source/include/X.h",
        listOf(include("/trace/source/include/X.h:2:1", "/trace/build/include/Y.inc")),
    ),
)

private fun bRecords(): List<String> = listOf(
    record(
        "/trace/source/b/B.cpp",
        listOf(include("/trace/source/b/B.cpp:1:1", "/trace/source/include/X.h")),
    ),
    record(
        "/trace/source/include/X.h",
        listOf(include("/trace/source/include/X.h:2:1", "/trace/build/include/Y.inc")),
    ),
)

private fun complexTrace(): ByteArray = document(
    listOf(
        record(
            "/trace/source/a/A.cpp",
            listOf(
                include("/trace/source/a/A.cpp:1:1", "/trace/source/include/X.h"),
                include("/trace/source/a/A.cpp:2:1", "/usr/include/a.h"),
                include("/trace/source/a/A.cpp:3:1", "/trace/build/sub/../NonCanonical.h"),
                include("/trace/source/a/A.cpp:4:1", "/trace/build/helper.cpp"),
                include("/trace/source/a/A.cpp:5:1", "/trace/source/b/B.cpp"),
            ),
            listOf(imported("/trace/source/a/A.cpp:6:1", "Project", "/trace/build/module.modulemap")),
        ),
        record(
            "/trace/build/helper.cpp",
            listOf(include("/trace/build/helper.cpp:1:1", "/trace/source/include/X.h")),
        ),
        record(
            "/trace/source/b/B.cpp",
            listOf(include("/trace/source/b/B.cpp:1:1", "/trace/source/include/X.h")),
        ),
        record(
            "/usr/include/forced.h",
            listOf(
                include("/usr/include/forced.h:1:1", "/trace/source/include/X.h"),
                include("/usr/include/forced.h:2:1", "/usr/include/b.h"),
            ),
            listOf(imported("/usr/include/forced.h:3:1", "External", "/usr/include/module.modulemap")),
        ),
    ),
)

private fun document(records: List<String>): ByteArray =
    """{"version":"2.0.0","dependencies":[${records.joinToString(",")}]}""".toByteArray()

private fun record(
    source: String,
    includes: List<String>,
    imports: List<String> = emptyList(),
): String =
    """{"source":"$source","includes":[${includes.joinToString(",")}],"imports":[${imports.joinToString(",")}] }"""

private fun include(location: String, file: String): String =
    """{"location":"$location","file":"$file"}"""

private fun imported(location: String, module: String, file: String): String =
    """{"location":"$location","module":"$module","file":"$file"}"""

private const val MODULE_A = "cu-11111111111111111111111111111111"
private const val MODULE_B = "cu-22222222222222222222222222222222"
private const val SOURCE_A = "source/a/A.cpp"
private const val SOURCE_B = "source/b/B.cpp"
private const val HELPER_SOURCE = "generated/helper.cpp"
private const val HEADER_X = "source/include/X.h"
private const val HEADER_Y = "generated/include/Y.inc"
private const val UNUSED_HEADER = "source/include/Unused.h"
private val HEADERS = listOf(HEADER_X, HEADER_Y, UNUSED_HEADER)
private val SOURCE_ONLY = listOf(
    FullTreeHeaderSourceOnlyUnit("tools-a", "source/tools/A.cpp"),
    FullTreeHeaderSourceOnlyUnit("tools-b", "source/tools/B.cpp"),
)
private val ROOTS = listOf(
    FullTreeClangTraceRoot("/trace/source", "source"),
    FullTreeClangTraceRoot("/trace/build", "generated"),
)
