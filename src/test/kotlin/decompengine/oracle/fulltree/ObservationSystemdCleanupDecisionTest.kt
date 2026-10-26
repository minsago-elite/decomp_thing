package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import java.io.IOException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/** Data and inert callbacks only; no controller, filesystem or native operation is constructed. */
class ObservationSystemdCleanupDecisionTest {
    @Test
    fun `only a directly captured missing reselection is unresolved without granting authority`() {
        val reselection = "cannot reselect the descriptor-pinned isolated cgroup"
        val missing = LinuxSyscallException("inert selection", LinuxFilesystemSyscalls.ENOENT)
        fun failure(message: String, cause: Throwable? = null) =
            FullTreeFunctionObservationIsolationException(message, cause)
        val cases = listOf(
            failure(reselection, missing) to ObservationUnitMutationTargetState.UNRESOLVED,
            failure(reselection, LinuxSyscallException("inert selection", LinuxFilesystemSyscalls.ENOENT + 1)) to
                ObservationUnitMutationTargetState.REPLACED,
            failure(reselection) to ObservationUnitMutationTargetState.REPLACED,
            failure(reselection, IOException("unknown selection")) to ObservationUnitMutationTargetState.REPLACED,
            failure(reselection, IOException("nested missing", missing)) to ObservationUnitMutationTargetState.REPLACED,
            failure("descriptor-pinned isolated cgroup changed identity", missing) to ObservationUnitMutationTargetState.REPLACED,
            failure("isolated cgroup path selected a replacement directory", missing) to ObservationUnitMutationTargetState.REPLACED,
            failure("other selection failure", missing) to ObservationUnitMutationTargetState.REPLACED,
            IOException(reselection, missing) to ObservationUnitMutationTargetState.REPLACED,
            missing to ObservationUnitMutationTargetState.REPLACED,
            IllegalStateException(reselection, missing) to ObservationUnitMutationTargetState.REPLACED,
        )
        for ((failure, expected) in cases) {
            val state = observationCgroupSelectionFailureState(failure)
            assertEquals(expected, state)
            assertNotEquals(ObservationUnitMutationTargetState.SAME, state)
            assertNotEquals(ObservationUnitMutationTargetState.ABSENT, state)
        }
    }

    @Test
    fun `unresolved selection stops remaining name commands and remains distinct from absence`() {
        assertNotEquals(ObservationUnitMutationTargetState.ABSENT, ObservationUnitMutationTargetState.UNRESOLVED)
        for (state in listOf(ObservationUnitMutationTargetState.UNRESOLVED, ObservationUnitMutationTargetState.ABSENT)) {
            var checks = 0
            var commands = 0
            var failures = 0
            runGuardedObservationSystemdCleanupFallback(
                unitName = "inert.scope",
                beforeCommand = { checks += 1; observationSystemdCleanupMutationPermitted(state) },
                command = { _, _ -> commands += 1 },
                commandFailure = { failures += 1 },
            )
            assertEquals(1, checks)
            assertEquals(0, commands)
            assertEquals(0, failures)
        }
        var checks = 0
        val calls = mutableListOf<List<String>>()
        runGuardedObservationSystemdCleanupFallback(
            unitName = "inert.scope",
            beforeCommand = {
                checks += 1
                observationSystemdCleanupMutationPermitted(
                    if (checks == 1) ObservationUnitMutationTargetState.SAME else ObservationUnitMutationTargetState.UNRESOLVED,
                )
            },
            command = { arguments, _ -> calls += arguments },
        )
        assertEquals(2, checks)
        assertEquals(listOf(listOf("kill", "--kill-whom=all", "--signal=SIGKILL", "inert.scope")), calls)
    }

    @Test
    fun `matched cleanup keeps command order and replacement refusal survives prior command failure`() {
        val calls = mutableListOf<Pair<List<String>, Set<Int>>>()
        runGuardedObservationSystemdCleanupFallback(
            unitName = "inert.scope",
            beforeCommand = { observationSystemdCleanupMutationPermitted(ObservationUnitMutationTargetState.SAME) },
            command = { arguments, exits -> calls += arguments to exits },
        )
        assertEquals(listOf(
            listOf("kill", "--kill-whom=all", "--signal=SIGKILL", "inert.scope"),
            listOf("thaw", "inert.scope"),
            listOf("kill", "--kill-whom=all", "--signal=SIGKILL", "inert.scope"),
            listOf("stop", "inert.scope"),
            listOf("reset-failed", "inert.scope"),
        ), calls.map { it.first })
        assertTrue(calls.all { it.second == setOf(0, 1, 4, 5) })
        for (priorCommand in listOf(false, true)) {
            val commandFailure: Throwable = IllegalStateException("inert command failure")
            val failures = mutableListOf<Throwable>()
            var checks = 0
            var commands = 0
            val refusal = assertFailsWith<FullTreeFunctionObservationIsolationException> {
                runGuardedObservationSystemdCleanupFallback(
                    unitName = "inert.scope",
                    beforeCommand = {
                        checks += 1
                        observationSystemdCleanupMutationPermitted(
                            if (priorCommand && checks == 1) ObservationUnitMutationTargetState.SAME
                            else ObservationUnitMutationTargetState.REPLACED,
                        )
                    },
                    command = { _, _ -> commands += 1; throw commandFailure },
                    commandFailure = { failures += it },
                )
            }
            assertEquals("isolated cleanup refused a replacement systemd invocation", refusal.message)
            assertTrue(refusal !== commandFailure)
            assertEquals(if (priorCommand) 2 else 1, checks)
            assertEquals(if (priorCommand) 1 else 0, commands)
            assertEquals(if (priorCommand) listOf(commandFailure) else emptyList(), failures)
        }
    }

    /**
     * #1566: the first SIGKILL empties the scope, and systemd prunes its cgroup asynchronously
     * (scope_enter_dead -> unit_notify -> unit_prune_cgroup). An atomic pre-prune snapshot can still
     * name the cgroup while the descriptor-pinned reselection then observes ENOENT. That interleaving
     * must stop name commands without a replacement refusal; genuine replacements still refuse.
     */
    @Test
    fun `an asynchronous cgroup prune between snapshot and reselection stops commands without a replacement refusal`() {
        val unit = "inert.scope"
        val invocation = "a".repeat(32)
        val cgroup = java.nio.file.Path.of("/sys/fs/cgroup/user.slice/$unit")
        val snapshot = mapOf("LoadState" to "loaded", "ActiveState" to "active", "Id" to unit, "Transient" to "yes",
            "InvocationID" to invocation, "ControlGroup" to "/user.slice/$unit")
        val pruned = FullTreeFunctionObservationIsolationException("cannot reselect the descriptor-pinned isolated cgroup",
            LinuxSyscallException("inert selection", LinuxFilesystemSyscalls.ENOENT))
        val observedFailures = mutableListOf<Throwable>()
        fun decide(properties: Map<String, String>, absent: Boolean = false, failure: Throwable? = null) =
            decideObservationUnitMutationTarget(properties, unit, invocation, cgroup,
                pathAbsent = { absent }, reselect = { failure?.let { throw it } }, onSelectionFailure = { observedFailures += it })

        assertEquals(ObservationUnitMutationTargetState.SAME, decide(snapshot))
        assertEquals(ObservationUnitMutationTargetState.UNRESOLVED, decide(snapshot, failure = pruned))
        assertEquals(listOf<Throwable>(pruned), observedFailures)
        // After the prune completes the manager snapshot releases ControlGroup, or the path is gone.
        assertEquals(ObservationUnitMutationTargetState.ABSENT, decide(snapshot + ("ControlGroup" to "")))
        assertEquals(ObservationUnitMutationTargetState.ABSENT, decide(snapshot, absent = true))
        assertEquals(ObservationUnitMutationTargetState.ABSENT, decide(mapOf("LoadState" to "not-found")))
        // Genuine replacement and every other selection failure keep the strict refusal.
        for (replaced in listOf(
            decide(snapshot + ("InvocationID" to "b".repeat(32))),
            decide(snapshot + ("InvocationID" to "0".repeat(32)), failure = pruned),
            decide(snapshot + ("Transient" to "no")),
            decide(snapshot + ("ControlGroup" to "/user.slice/other.scope")),
            decide(snapshot, failure = FullTreeFunctionObservationIsolationException("isolated cgroup path selected a replacement directory")),
            decide(snapshot, failure = FullTreeFunctionObservationIsolationException("cannot reselect the descriptor-pinned isolated cgroup",
                LinuxSyscallException("inert selection", LinuxFilesystemSyscalls.ENOENT + 1))),
        )) assertEquals(ObservationUnitMutationTargetState.REPLACED, replaced)

        // The fallback sees SAME before the first kill and the race state before the second command.
        val states = ArrayDeque(listOf(decide(snapshot), decide(snapshot, failure = pruned)))
        val commands = mutableListOf<List<String>>()
        runGuardedObservationSystemdCleanupFallback(unit,
            beforeCommand = { observationSystemdCleanupMutationPermitted(states.removeFirst()) },
            command = { arguments, _ -> commands += arguments })
        assertEquals(listOf(listOf("kill", "--kill-whom=all", "--signal=SIGKILL", unit)), commands)
        assertTrue(states.isEmpty())
    }
}
