package decompengine.acp

import java.util.Collections

/**
 * Untrusted, test-only claims for #1521. This has no acquired owner, I/O, clock, decoder,
 * production permit, or native success adapter. Completeness is never qualification.
 */
internal object NativeDnsOwnedDomainContract {
    private const val MAX_RECORDS = 128
    private const val MAX_REFERENCES = 16
    private const val MAX_DURATION_NANOS = 30_000_000_000L
    private const val CLEANUP_RESERVE_NANOS = 5_000_000_000L
    private val digest = Regex("[0-9a-f]{64}")
    private val identifier = Regex("[A-Za-z0-9-]{1,80}")
    private val scopeUnit = Regex("[A-Za-z0-9-]{1,80}\\.scope")

    enum class Case { CANCEL, DEADLINE }
    enum class NamespaceKind { PID, USER, NET }
    data class Namespace(val kind: NamespaceKind, val device: Long, val inode: Long) {
        init { require(device >= 0 && inode > 0) }
    }

    sealed interface ProcessCoordinate
    data class HostProcessCoordinate(val pid: Long, val start: Long, val pidNamespace: Namespace) : ProcessCoordinate {
        init { require(pid in 1..4294967295L && start >= 0 && pidNamespace.kind == NamespaceKind.PID) }
    }
    data class InnerProcessCoordinate(val pid: Long, val start: Long, val pidNamespace: Namespace) : ProcessCoordinate {
        init { require(pid in 1..4294967295L && start >= 0 && pidNamespace.kind == NamespaceKind.PID) }
    }

    data class Sources(val test: String, val helper: String, val runtime: String, val control: String) {
        init { require(listOf(test, helper, runtime, control).all(digest::matches)) }
    }
    data class Key(val run: String, val case: Case, val sources: Sources, val unit: String, val cgroupIdentity: String) {
        init { require(identifier.matches(run) && scopeUnit.matches(unit) && digest.matches(cgroupIdentity)) }
    }
    enum class HolderRole { HOST_OWNER, INNER_SUPERVISOR, BLACKHOLE }
    enum class ReferenceKind { NAMESPACE_FD, PROC_MOUNT, SOCKET }
    data class Reference(val id: Int, val namespace: Namespace, val holder: HolderRole, val kind: ReferenceKind) {
        init {
            require(id in 1..MAX_REFERENCES)
            require(kind != ReferenceKind.PROC_MOUNT || namespace.kind == NamespaceKind.PID)
            require(kind != ReferenceKind.SOCKET || namespace.kind == NamespaceKind.NET)
            require(holder != HolderRole.BLACKHOLE || kind == ReferenceKind.SOCKET)
        }
    }

    /** Caller-supplied identities are commitments to check later, not authenticated ownership. */
    class Binding(val key: Key, val hostRoot: HostProcessCoordinate, val innerRoot: InnerProcessCoordinate,
        val user: Namespace, val net: Namespace, references: List<Reference>,
        val startNanos: Long, val executionEndNanos: Long, val cleanupEndNanos: Long) {
        val references: List<Reference>
        init {
            require(hostRoot.pidNamespace != innerRoot.pidNamespace)
            require(user.kind == NamespaceKind.USER && net.kind == NamespaceKind.NET)
            require(startNanos >= 0 && executionEndNanos > startNanos && cleanupEndNanos > executionEndNanos)
            require(cleanupEndNanos - startNanos <= MAX_DURATION_NANOS)
            require(cleanupEndNanos - executionEndNanos == CLEANUP_RESERVE_NANOS)
            require(references.size in 1..MAX_REFERENCES)
            this.references = snapshot(references, MAX_REFERENCES)
            require(this.references.map { it.id }.toSet().size == this.references.size)
            require(this.references.all { it.namespace in setOf(innerRoot.pidNamespace, user, net) })
            require(setOf(innerRoot.pidNamespace, user, net).all { ns -> this.references.any { it.namespace == ns } })
        }
    }

    enum class Claim {
        GATE_HELD, ROOT_HANDLE_HELD, SCOPE_BOUND, PRIVATE_PROC_BOUND, INNER_COORDINATE_BOUND,
        REFERENCE_INVENTORY_RECORDED, NON_ESCAPE_RECORDED, PAYLOAD_RELEASED, PAYLOAD_TERMINAL,
        ROOT_REAPED, DESCENDANTS_REAPED, SCOPE_ABSENT, STREAMS_JOINED_CLOSED, HOST_STATE_UNCHANGED,
        REFERENCE_CLOSED, POSSIBLE_OWNED_VISIBILITY,
    }
    data class Record(val key: Key, val sequence: Int, val observedNanos: Long, val claim: Claim,
        val process: ProcessCoordinate? = null, val referenceId: Int? = null) {
        init { require(sequence in 1..MAX_RECORDS && observedNanos >= 0) }
    }
    enum class PrimaryFailure { PAYLOAD_FAILURE, POSSIBLE_OWNED_VISIBILITY }
    class Transcript(val binding: Binding, records: List<Record>, val primaryFailure: PrimaryFailure? = null) {
        val records: List<Record>
        init { this.records = snapshot(records, MAX_RECORDS) }
    }

    enum class Phase { PREPARED, GATED, ADMITTED, TERMINAL }
    enum class Status { INCOMPLETE_UNQUALIFIED, COMPLETE_UNQUALIFIED, UNKNOWN_UNQUALIFIED }
    enum class Defect { BINDING, REPLAY, ORDER, COORDINATE, REFERENCE, DEADLINE, VISIBILITY }
    data class Assessment(val status: Status, val phase: Phase, val missingClaims: Set<Claim>,
        val unclosedReferences: List<Int>, val primaryFailure: PrimaryFailure?, val cleanupDefects: Set<Defect>)

    private val admission = setOf(Claim.GATE_HELD, Claim.ROOT_HANDLE_HELD, Claim.SCOPE_BOUND,
        Claim.PRIVATE_PROC_BOUND, Claim.INNER_COORDINATE_BOUND, Claim.REFERENCE_INVENTORY_RECORDED,
        Claim.NON_ESCAPE_RECORDED)
    private val cleanup = setOf(Claim.ROOT_REAPED, Claim.DESCENDANTS_REAPED, Claim.SCOPE_ABSENT,
        Claim.STREAMS_JOINED_CLOSED, Claim.HOST_STATE_UNCHANGED)
    private val required = admission + setOf(Claim.PAYLOAD_RELEASED, Claim.PAYLOAD_TERMINAL) + cleanup

    /** All supplied times/facts remain untrusted. A later real owner/consumer is still required. */
    fun assess(transcript: Transcript, observedEndNanos: Long): Assessment {
        val binding = transcript.binding
        val seen = mutableSetOf<Claim>()
        val closed = mutableSetOf<Int>()
        val defects = mutableSetOf<Defect>()
        var primary = transcript.primaryFailure
        var phase = Phase.PREPARED
        var priorTime = binding.startNanos
        var unknown = primary != null
        transcript.records.forEachIndexed { index, record ->
            val current = mutableSetOf<Defect>()
            if (record.key != binding.key) current += Defect.BINDING
            if (record.sequence != index + 1) current += Defect.REPLAY
            val end = if (record.claim in admission || record.claim in setOf(Claim.PAYLOAD_RELEASED, Claim.PAYLOAD_TERMINAL))
                binding.executionEndNanos else binding.cleanupEndNanos
            if (record.observedNanos < priorTime || record.observedNanos >= end) current += Defect.DEADLINE
            priorTime = maxOf(priorTime, record.observedNanos)
            if (record.claim == Claim.POSSIBLE_OWNED_VISIBILITY) {
                if (primary == null) primary = PrimaryFailure.POSSIBLE_OWNED_VISIBILITY
                current += Defect.VISIBILITY
            }
            val expectedProcess = when (record.claim) {
                Claim.ROOT_HANDLE_HELD, Claim.ROOT_REAPED -> binding.hostRoot
                Claim.INNER_COORDINATE_BOUND, Claim.PAYLOAD_TERMINAL -> binding.innerRoot
                else -> null
            }
            if (record.process != expectedProcess) current += Defect.COORDINATE
            if (record.claim == Claim.REFERENCE_CLOSED) {
                if (record.referenceId !in binding.references.map { it.id } || record.referenceId in closed)
                    current += Defect.REFERENCE
                if (!seen.containsAll(cleanup)) current += Defect.ORDER
            } else {
                if (record.referenceId != null) current += Defect.REFERENCE
                if (record.claim in seen) current += Defect.REPLAY
            }
            when (record.claim) {
                Claim.GATE_HELD -> if (phase != Phase.PREPARED || seen.isNotEmpty()) current += Defect.ORDER
                in admission -> if (phase != Phase.GATED) current += Defect.ORDER
                Claim.PAYLOAD_RELEASED -> if (phase != Phase.GATED || !seen.containsAll(admission)) current += Defect.ORDER
                Claim.PAYLOAD_TERMINAL -> if (phase != Phase.ADMITTED) current += Defect.ORDER
                in cleanup, Claim.REFERENCE_CLOSED -> if (phase != Phase.TERMINAL) current += Defect.ORDER
                Claim.POSSIBLE_OWNED_VISIBILITY -> Unit
                else -> Unit
            }
            defects += current
            unknown = unknown || current.isNotEmpty()
            // Defects cannot be repaired by a later good-looking record in this transcript.
            if (!unknown) {
                if (record.claim == Claim.REFERENCE_CLOSED) closed += checkNotNull(record.referenceId)
                else seen += record.claim
                phase = when (record.claim) {
                    Claim.GATE_HELD -> Phase.GATED
                    Claim.PAYLOAD_RELEASED -> Phase.ADMITTED
                    Claim.PAYLOAD_TERMINAL -> Phase.TERMINAL
                    else -> phase
                }
            }
        }
        if (observedEndNanos < priorTime || observedEndNanos >= binding.cleanupEndNanos) {
            defects += Defect.DEADLINE
            unknown = true
        }
        val missing = required - seen
        val unclosed = binding.references.map { it.id }.filterNot(closed::contains)
        val status = when {
            unknown -> Status.UNKNOWN_UNQUALIFIED
            missing.isEmpty() && unclosed.isEmpty() -> Status.COMPLETE_UNQUALIFIED
            else -> Status.INCOMPLETE_UNQUALIFIED
        }
        return Assessment(status, phase, Collections.unmodifiableSet(missing.toSet()),
            snapshot(unclosed, MAX_REFERENCES), primary, Collections.unmodifiableSet(defects.toSet()))
    }

    private fun <T> snapshot(values: List<T>, maximum: Int): List<T> {
        val size = values.size
        require(size in 0..maximum)
        return Collections.unmodifiableList(List(size) { values[it] })
    }
}
