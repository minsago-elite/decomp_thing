package decompengine.acp

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentExecutionException
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import decompengine.doctor.acpDoctorFailureContext
import java.util.Locale
import kotlin.test.*

/** Pure receipt/string controls live outside the fixed native-suite method census. */
class AcpCleanupFailureContextTest {
    @Test
    fun `cleanup assertion context keeps recorded receipt facts without private labels or cause text`() {
        val raw = "UNREGISTERED-CLEANUP-SECRET /private/raw/path"
        val record = "ACP_STDOUT_SHUTDOWN_V1 firstMs=100 finalMs=41 " +
            "s1=WAIT_TIMEOUT/FRAME_CONSUMER/false/false/false/NONE/12/1024/false " +
            "s2=CLOSE_NOT_ACQUIRED/FRAME_CONSUMER/false/false/false/NONE/12/1024/false " +
            "s3=FINISHED_FALSE_EOF_NOT_READ/FRAME_CONSUMER/false/false/false/NONE/12/1024/false"
        val evidence = AcpInvocationEvidenceSnapshot(
            null, AcpExecutionLifecyclePhase.PROMPT_COMPLETED, AcpExecutionCleanupDisposition.UNVERIFIED,
            null, null, null, emptyList(), emptyList(), emptyList(), null,
            AcpExecutionEvidenceCompleteness(false, false, false), null,
        )
        var foreignMessageReads = 0
        val cause = object : java.io.IOException() {
            override val message: String get() { foreignMessageReads++; error(raw) }
        }
        val failed = AgentFailure(AgentFailureKind.RESOURCE_EXHAUSTED, raw,
            details = mapOf("stdoutShutdownV1" to record, "raw" to raw))
        val receipt = AgentExecutionReceipt(
            AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION, "a".repeat(64), "b".repeat(64)),
            AgentExecutionOutcome.Failed(failed), evidence, cause,
        )
        val failure = AgentExecutionException(failed, cause, receipt)
        for ((label, mode) in listOf("individual frame limit" to "FRAME_LIMIT", "aggregate stdout limit" to "STDOUT_LIMIT",
            "protocol failure" to "PROTOCOL_FAILURE", "execution" to "EXECUTION", raw to "UNKNOWN")) {
            val context = safeCleanupFailureContext(label, failure)
            assertTrue(context.length <= 4096)
            assertTrue(context.contains("mode=$mode kind=RESOURCE_EXHAUSTED"))
            assertTrue(context.contains("recordedPhase=PROMPT_COMPLETED recordedCleanup=UNVERIFIED"))
            assertTrue(context.contains("recordedDiagnostics=MISSING"))
            assertTrue(context.contains("stdoutFacts=$record"))
            assertFalse(context.contains(raw))
        }
        val cases = listOf("setter error", "setter timeout", "absent mode capability", "unknown-response-id", "duplicate-response-id", "late-response-id",
            "contaminated-prompt", "missing-jsonrpc-prompt", "wrong-jsonrpc-prompt", "numeric-jsonrpc-prompt", "result-and-error-prompt")
        val identified = cases.map { label ->
            val context = safeCleanupFailureContext(label, failure)
            assertTrue(context.contains("mode=${label.replace(' ', '-')} kind=RESOURCE_EXHAUSTED"))
            assertTrue(context.contains("recordedPhase=PROMPT_COMPLETED"))
            assertTrue(safeCleanupFailureContext("$label $raw", failure).contains("mode=UNKNOWN"))
            context.substringBefore(" kind=")
        }
        assertEquals(cases.size, identified.distinct().size)
        assertSame(receipt, failure.receipt)
        assertSame(cause, failure.cause)
        assertEquals(0, foreignMessageReads)
        for (untrusted in listOf(raw, record + " extra=" + raw, "x".repeat(2049))) {
            val missing = AgentExecutionException(AgentFailure(AgentFailureKind.INTERNAL, raw,
                details = mapOf("stdoutShutdownV1" to untrusted)))
            val context = safeCleanupFailureContext(raw, missing)
            assertTrue(context.contains("mode=UNKNOWN"))
            assertTrue(context.contains("recordedPhase=MISSING recordedCleanup=MISSING"))
            assertTrue(context.contains("stdoutFacts=NOT_AVAILABLE"))
            assertFalse(context.contains(raw))
        }
    }

    @Test
    fun `missing mutation hook context retains only owned bounded failure facts`() {
        val privateText = "PRIVATE-LAUNCH-CONTEXT /private/source/path"
        var messageReads = 0
        val failure = object : java.io.IOException() {
            override val message: String get() { messageReads++; error(privateText) }
        }
        val phaseType = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcomeType = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val diagnosticType = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val phase = phaseType.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" }
        val outcome = outcomeType.enumConstants.single { (it as Enum<*>).name == "EVENT" }
        val diagnostic = diagnosticType.getDeclaredConstructor(phaseType, outcomeType,
            Int::class.javaObjectType, Int::class.javaObjectType, Int::class.javaObjectType)
            .apply { isAccessible = true }.newInstance(phase, outcome, 1, 10, null) as Throwable
        failure.initCause(diagnostic)
        val context = targetMutationFailureContext(failure)
        assertTrue(context.startsWith("ACP_TARGET_MUTATION_V1 hook=NOT_OBSERVED "))
        assertTrue("mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT rc=1 revents=10 errno=NA" in context)
        assertTrue("recordedPhase=MISSING recordedCleanup=MISSING" in context)
        assertTrue(context.length <= 1100)
        assertFalse(privateText in context)
        assertEquals(0, messageReads)
        val forged = java.io.IOException(diagnostic.message)
        forged.addSuppressed(diagnostic)
        assertTrue("mountEventRecord=MISSING" in targetMutationFailureContext(forged))
        val cycle = object : java.io.IOException(privateText) {
            override val cause: Throwable get() = this
        }
        assertTrue("mountEventRecord=MISSING" in targetMutationFailureContext(cycle))
        assertFalse(privateText in targetMutationFailureContext(cycle))
    }

}

/** Failure-only projection: a synthetic wrapper supplies no receipt or execution authority. */
internal fun targetMutationFailureContext(failure: java.io.IOException): String =
    "ACP_TARGET_MUTATION_V1 hook=NOT_OBSERVED " + acpDoctorFailureContext(AgentExecutionException(
        AgentFailure(AgentFailureKind.INTERNAL, "Negative launch fixture context"), failure,
    ))

/** Only explicitly enumerated repository case labels can survive the diagnostic projection. */
internal fun safeCleanupFailureContext(label: String, failure: AgentExecutionException): String {
    val mode = when (label) {
        "individual frame limit" -> "FRAME_LIMIT"
        "aggregate stdout limit" -> "STDOUT_LIMIT"
        "protocol failure" -> "PROTOCOL_FAILURE"
        "execution" -> "EXECUTION"
        else -> if (label.length <= 96 && label in CLEANUP_CASE_LABELS) label.replace(' ', '-').lowercase(Locale.ROOT) else "UNKNOWN"
    }
    val stdout = validatedCleanupStdoutFacts(failure.failure.details["stdoutShutdownV1"]) ?: "NOT_AVAILABLE"
    return "ACP_CLEANUP_V1 mode=$mode kind=${failure.failure.kind.name} " +
        acpDoctorFailureContext(failure) + " stdoutFacts=$stdout"
}

private fun validatedCleanupStdoutFacts(value: String?): String? {
    val type = Class.forName("decompengine.acp.StdoutShutdownFacts")
    val instance = type.getDeclaredField("INSTANCE").apply { isAccessible = true }.get(null)
    return type.getDeclaredMethod("validated", String::class.java).apply { isAccessible = true }.invoke(instance, value) as String?
}

private val CLEANUP_CASE_LABELS = setOf(
    "configured session preferences",
    "default session preferences",
    "removed later option",
    "unknown model",
    "unknown mode",
    "unknown option",
    "unknown select value",
    "mismatched option type",
    "pipelined update cannot expand session new authority",
    "pipelined work cannot run while invalid preferences are rejected",
    "absent model capability",
    "absent mode capability",
    "absent config capability",
    "setter cancellation",
    "setter error",
    "setter timeout",
    "config setter inconsistent postcondition",
    "later config setter cannot revert an earlier configured option",
    "stop-max-tokens",
    "stop-max-turn-requests",
    "stop-refusal",
    "orphan terminal",
    "cross-session terminal",
    "missing-session terminal",
    "near-wall terminal",
    "unsupported version",
    "missing required capability",
    "missing protocol version",
    "unknown-response-id",
    "duplicate-response-id",
    "late-response-id",
    "pipelined callbacks",
    "unknown methods",
    "denied write",
    "malformed initialize",
    "malformed prompt",
    "contaminated-prompt",
    "missing-jsonrpc-prompt",
    "wrong-jsonrpc-prompt",
    "numeric-jsonrpc-prompt",
    "result-and-error-prompt",
    "invalid UTF-8",
    "invalid update",
    "negative usage",
    "missing usage",
    "clean EOF",
    "prompt crash",
    "initialize crash",
    "initialize timeout",
    "session request timeout",
    "idle timeout",
    "wall timeout",
    "blocked callback timeout",
    "cooperative cancellation",
    "response-then-crash",
    "response-then-delayed-crash",
    "retained stderr limit",
    "stderr flood",
    "response-then-stderr-burst",
    "response-then-stdout-burst",
    "protocol frame flood",
    "authentication required",
)
