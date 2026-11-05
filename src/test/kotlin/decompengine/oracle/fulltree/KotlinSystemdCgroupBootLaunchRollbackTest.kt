package decompengine.oracle.fulltree

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class KotlinSystemdCgroupBootLaunchRollbackTest {
    @Test
    fun `boundary failure preserves close order suppression and skips private cleanup`() {
        val events = mutableListOf<String>()
        val original = IllegalStateException("original")
        val boundaryFailure = IllegalArgumentException("boundary")
        val result = account(
            original, launchAttempted = true,
            boundary = resource("boundary", events, boundaryFailure),
            runTree = resource("tree", events),
            runtime = resource("runtime", events),
        )
        assertEquals(listOf("boundary"), events)
        assertFalse(result.rollbackSafe)
        assertEquals(listOf(boundaryFailure), original.suppressed.toList())
        assertEquals(KotlinBootCloseOutcome.FAILED, result.boundaryClose)
        assertEquals(KotlinBootCloseOutcome.SKIPPED_BOUNDARY_FAILURE, result.runTreeClose)
        assertEquals(KotlinBootCloseOutcome.SKIPPED_BOUNDARY_FAILURE, result.runtimeClose)
    }

    @Test
    fun `successful boundary cleanup attempts private resources in order and reports both failures`() {
        val events = mutableListOf<String>()
        val original = IllegalStateException("original")
        val treeFailure = IllegalArgumentException("tree")
        val runtimeFailure = UnsupportedOperationException("runtime")
        val result = account(
            original, launchAttempted = false,
            boundary = resource("boundary", events),
            runTree = resource("tree", events, treeFailure),
            runtime = resource("runtime", events, runtimeFailure),
        )
        assertEquals(listOf("boundary", "tree", "runtime"), events)
        assertFalse(result.rollbackSafe)
        assertEquals(listOf(treeFailure, runtimeFailure), original.suppressed.toList())
        assertEquals(KotlinBootCloseOutcome.SUCCEEDED, result.boundaryClose)
        assertEquals(KotlinBootCloseOutcome.FAILED, result.runTreeClose)
        assertEquals(KotlinBootCloseOutcome.FAILED, result.runtimeClose)
    }

    @Test
    fun `pre launch cleanup without resources is rollback safe`() {
        val events = mutableListOf<String>()
        val result = account(
            IllegalStateException("original"), launchAttempted = false,
            boundary = null,
            runTree = null,
            runtime = null,
        )
        assertTrue(result.rollbackSafe)
        assertEquals(emptyList(), events)
        assertEquals(KotlinBootCloseOutcome.NOT_OWNED, result.boundaryClose)
        assertEquals(KotlinBootCloseOutcome.NOT_OWNED, result.runTreeClose)
        assertEquals(KotlinBootCloseOutcome.NOT_OWNED, result.runtimeClose)
    }

    @Test
    fun `launched process without retained boundary is never rollback safe`() {
        val result = account(
            IllegalStateException("original"), launchAttempted = true,
            boundary = null, runTree = null, runtime = null,
        )
        assertFalse(result.rollbackSafe)
    }

    @Test
    fun `fixed rollback diagnostic formatter has a strict byte bound`() {
        val facade = Class.forName("decompengine.oracle.fulltree.FullTreeFunctionObservationIsolatedRunnerKt")
        val sanitizer = facade.declaredMethods.single { it.name == "boundedUtf8" }
            .apply { isAccessible = true }
        val safe = sanitizer.invoke(null, "fixed fields only /private/scratch ${"a".repeat(64)}", 64) as String
        assertTrue(safe.toByteArray(Charsets.UTF_8).size <= 64)
        assertTrue(safe.contains("fixed fields only"))

        val phaseType = Class.forName("decompengine.oracle.fulltree.KotlinBootLaunchPhase")
        val phase = phaseType.enumConstants.single { (it as Enum<*>).name == "CONSTRUCT_OWNER" }
        val result = account(IllegalStateException(), false, null, null, null)
        val formatter = facade.declaredMethods.single { it.name == "formatKotlinBootRollbackDiagnostic" }
            .apply { isAccessible = true }
        val diagnostic = formatter.invoke(null, phase, true, "CONTROL", result) as String
        assertTrue(diagnostic.contains("phase=CONSTRUCT_OWNER"))
        assertTrue(diagnostic.contains("ownershipTransferred=false"))
        assertTrue(diagnostic.contains("launchAttempted=true"))
        assertTrue(diagnostic.contains("boundaryClose=NOT_OWNED"))
        assertTrue(diagnostic.contains("preAttachmentRollbackSafe=true"))
        assertTrue(!diagnostic.contains("/private/scratch"))
        assertTrue(diagnostic.toByteArray(Charsets.UTF_8).size <= 1024)
    }

    private fun account(
        failure: Throwable,
        launchAttempted: Boolean,
        boundary: AutoCloseable?,
        runTree: AutoCloseable?,
        runtime: AutoCloseable?,
    ): KotlinBootRollbackAccounting {
        val owner = Class.forName("decompengine.oracle.fulltree.FullTreeFunctionObservationIsolatedRunnerKt")
        val helper = owner.declaredMethods.single { it.name == "accountKotlinBootRollback" }
            .apply { isAccessible = true }
        return helper.invoke(
            null, failure, launchAttempted, boundary, runTree, runtime,
        ) as KotlinBootRollbackAccounting
    }

    private fun resource(name: String, events: MutableList<String>, failure: Throwable? = null) = AutoCloseable {
        events += name
        if (failure != null) throw failure
    }
}
