package decompengine.acp

import decompengine.acp.NativeDnsOwnedDomainContract.Binding
import decompengine.acp.NativeDnsOwnedDomainContract.Case
import decompengine.acp.NativeDnsOwnedDomainContract.Claim
import decompengine.acp.NativeDnsOwnedDomainContract.Defect
import decompengine.acp.NativeDnsOwnedDomainContract.HolderRole
import decompengine.acp.NativeDnsOwnedDomainContract.HostProcessCoordinate
import decompengine.acp.NativeDnsOwnedDomainContract.InnerProcessCoordinate
import decompengine.acp.NativeDnsOwnedDomainContract.Key
import decompengine.acp.NativeDnsOwnedDomainContract.Namespace
import decompengine.acp.NativeDnsOwnedDomainContract.NamespaceKind
import decompengine.acp.NativeDnsOwnedDomainContract.PrimaryFailure
import decompengine.acp.NativeDnsOwnedDomainContract.Record
import decompengine.acp.NativeDnsOwnedDomainContract.Reference
import decompengine.acp.NativeDnsOwnedDomainContract.ReferenceKind
import decompengine.acp.NativeDnsOwnedDomainContract.Sources
import decompengine.acp.NativeDnsOwnedDomainContract.Status
import decompengine.acp.NativeDnsOwnedDomainContract.Transcript
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** Pure synthetic transcripts only: no process, namespace, FD or production authority exists. */
class NativeDnsOwnedDomainContractTest {
    private val source = "a".repeat(64)
    private val hostPidNs = Namespace(NamespaceKind.PID, 4, 10)
    private val innerPidNs = Namespace(NamespaceKind.PID, 4, 11)
    private val userNs = Namespace(NamespaceKind.USER, 4, 12)
    private val netNs = Namespace(NamespaceKind.NET, 4, 13)
    private val key = Key("inert-run", Case.CANCEL, Sources(source, source, source, source), "inert-unit.scope", source)
    private val host = HostProcessCoordinate(100, 1, hostPidNs)
    private val inner = InnerProcessCoordinate(1, 2, innerPidNs)
    private fun references() = listOf(
        Reference(1, innerPidNs, HolderRole.INNER_SUPERVISOR, ReferenceKind.PROC_MOUNT),
        Reference(2, userNs, HolderRole.HOST_OWNER, ReferenceKind.NAMESPACE_FD),
        Reference(3, netNs, HolderRole.BLACKHOLE, ReferenceKind.SOCKET),
    )
    private fun binding(refs: List<Reference> = references()) = Binding(key, host, inner, userNs, netNs, refs,
        0, 25_000_000_000, 30_000_000_000)
    private fun records(): List<Record> {
        val claims = listOf(Claim.GATE_HELD, Claim.ROOT_HANDLE_HELD, Claim.SCOPE_BOUND, Claim.PRIVATE_PROC_BOUND,
            Claim.INNER_COORDINATE_BOUND, Claim.REFERENCE_INVENTORY_RECORDED, Claim.NON_ESCAPE_RECORDED,
            Claim.PAYLOAD_RELEASED, Claim.PAYLOAD_TERMINAL, Claim.ROOT_REAPED, Claim.DESCENDANTS_REAPED,
            Claim.SCOPE_ABSENT, Claim.STREAMS_JOINED_CLOSED, Claim.HOST_STATE_UNCHANGED)
        val events = claims.mapIndexed { i, claim -> Record(key, i + 1, i.toLong(), claim, when (claim) {
            Claim.ROOT_HANDLE_HELD, Claim.ROOT_REAPED -> host
            Claim.INNER_COORDINATE_BOUND, Claim.PAYLOAD_TERMINAL -> inner
            else -> null
        }) }
        return events + references().mapIndexed { i, ref ->
            Record(key, events.size + i + 1, (events.size + i).toLong(), Claim.REFERENCE_CLOSED, referenceId = ref.id)
        }
    }
    private fun assess(events: List<Record>, end: Long = 100, primary: PrimaryFailure? = null) =
        NativeDnsOwnedDomainContract.assess(Transcript(binding(), events, primary), end)
    private fun renumber(events: List<Record>) = events.mapIndexed { i, r -> r.copy(sequence = i + 1, observedNanos = i.toLong()) }

    @Test
    fun `complete synthetic obligations stay explicitly unqualified in both cases`() {
        val events = records()
        for (case in Case.entries) {
            val changedKey = key.copy(case = case)
            val b = Binding(changedKey, host, inner, userNs, netNs, references(), 0, 25_000_000_000, 30_000_000_000)
            val result = NativeDnsOwnedDomainContract.assess(Transcript(b, events.map { it.copy(key = changedKey) }), 100)
            assertEquals(Status.COMPLETE_UNQUALIFIED, result.status)
            assertTrue(result.missingClaims.isEmpty() && result.unclosedReferences.isEmpty())
        }
    }

    @Test
    fun `every independent cleanup claim and reference is necessary`() {
        val events = records()
        for (claim in listOf(Claim.ROOT_REAPED, Claim.DESCENDANTS_REAPED, Claim.SCOPE_ABSENT,
            Claim.STREAMS_JOINED_CLOSED, Claim.HOST_STATE_UNCHANGED)) {
            val result = assess(renumber(events.filterNot { it.claim == claim }))
            assertTrue(result.status != Status.COMPLETE_UNQUALIFIED)
            assertTrue(claim in result.missingClaims)
        }
        for (id in 1..3) {
            val result = assess(renumber(events.filterNot { it.referenceId == id }))
            assertEquals(Status.INCOMPLETE_UNQUALIFIED, result.status)
            assertEquals(listOf(id), result.unclosedReferences)
        }
    }

    @Test
    fun `payload cannot precede any admission obligation or root handle`() {
        for (claim in listOf(Claim.GATE_HELD, Claim.ROOT_HANDLE_HELD, Claim.SCOPE_BOUND, Claim.PRIVATE_PROC_BOUND,
            Claim.INNER_COORDINATE_BOUND, Claim.REFERENCE_INVENTORY_RECORDED, Claim.NON_ESCAPE_RECORDED)) {
            val result = assess(renumber(records().filterNot { it.claim == claim }))
            assertEquals(Status.UNKNOWN_UNQUALIFIED, result.status)
            assertTrue(Defect.ORDER in result.cleanupDefects)
        }
    }

    @Test
    fun `equal numeric PIDs cannot cross host and inner coordinate types`() {
        val events = records().map {
            if (it.claim == Claim.ROOT_HANDLE_HELD) it.copy(process = InnerProcessCoordinate(host.pid, host.start, hostPidNs)) else it
        }
        assertTrue(Defect.COORDINATE in assess(events).cleanupDefects)
        val wrongNamespace = records().map {
            if (it.claim == Claim.PAYLOAD_TERMINAL) it.copy(process = inner.copy(pidNamespace = hostPidNs)) else it
        }
        assertEquals(Status.UNKNOWN_UNQUALIFIED, assess(wrongNamespace).status)
    }

    @Test
    fun `mixed run case source and scope commitments cannot borrow a transcript`() {
        val keys = listOf(key.copy(run = "other"), key.copy(case = Case.DEADLINE), key.copy(unit = "other.scope"),
            key.copy(cgroupIdentity = "b".repeat(64)), key.copy(sources = key.sources.copy(helper = "b".repeat(64))))
        for (changed in keys) {
            val result = assess(records().map { if (it.claim == Claim.SCOPE_BOUND) it.copy(key = changed) else it })
            assertEquals(Status.UNKNOWN_UNQUALIFIED, result.status)
            assertTrue(Defect.BINDING in result.cleanupDefects)
        }
    }

    @Test
    fun `replayed sequence claim and reference closure remain sticky unknown`() {
        val events = records()
        val variants = listOf(events.mapIndexed { i, r -> if (i == 2) r.copy(sequence = 2) else r },
            renumber(events.take(2) + events[1] + events.drop(2)),
            renumber(events + events.last()))
        for (variant in variants) assertEquals(Status.UNKNOWN_UNQUALIFIED, assess(variant).status)
    }

    @Test
    fun `reference identity and closure dependency cannot be replaced by scope absence`() {
        val events = records()
        val unknownRef = events.map { if (it.referenceId == 1) it.copy(referenceId = 16) else it }
        assertTrue(Defect.REFERENCE in assess(unknownRef).cleanupDefects)
        val premature = renumber(events.take(9) + events.last() + events.drop(9).dropLast(1))
        assertTrue(Defect.ORDER in assess(premature).cleanupDefects)
        assertEquals(Status.INCOMPLETE_UNQUALIFIED, assess(events.filter { it.claim != Claim.REFERENCE_CLOSED }).status)
    }

    @Test
    fun `fixed execution and cleanup ends refuse equality regression and late final observation`() {
        val events = records()
        val lateExecution = events.map { if (it.claim == Claim.PAYLOAD_TERMINAL) it.copy(observedNanos = 25_000_000_000) else it }
        assertTrue(Defect.DEADLINE in assess(lateExecution).cleanupDefects)
        val lateCleanup = events.map { if (it == events.last()) it.copy(observedNanos = 30_000_000_000) else it }
        assertTrue(Defect.DEADLINE in assess(lateCleanup, 30_000_000_000).cleanupDefects)
        assertEquals(Status.UNKNOWN_UNQUALIFIED, assess(events, 30_000_000_000).status)
        assertEquals(Status.UNKNOWN_UNQUALIFIED, assess(events, 1).status)
        assertEquals(Status.UNKNOWN_UNQUALIFIED, assess(events.mapIndexed { i, r -> if (i == 3) r.copy(observedNanos = 0) else r }).status)
    }

    @Test
    fun `possible owned denial stays fatal and original failure survives cleanup defects`() {
        val events = records().toMutableList()
        events[3] = events[3].copy(claim = Claim.POSSIBLE_OWNED_VISIBILITY)
        val denial = assess(events)
        assertEquals(Status.UNKNOWN_UNQUALIFIED, denial.status)
        assertEquals(PrimaryFailure.POSSIBLE_OWNED_VISIBILITY, denial.primaryFailure)
        val prior = assess(events, 30_000_000_000, PrimaryFailure.PAYLOAD_FAILURE)
        assertEquals(PrimaryFailure.PAYLOAD_FAILURE, prior.primaryFailure)
        assertTrue(Defect.VISIBILITY in prior.cleanupDefects && Defect.DEADLINE in prior.cleanupDefects)
    }

    @Test
    fun `malformed bounded identities duplicate inventory and renewed budget refuse at construction`() {
        assertFailsWith<IllegalArgumentException> { key.copy(run = "x".repeat(81)) }
        assertFailsWith<IllegalArgumentException> { key.copy(unit = "/other.scope") }
        assertFailsWith<IllegalArgumentException> { key.sources.copy(runtime = "A".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { host.copy(pid = 0) }
        assertFailsWith<IllegalArgumentException> { inner.copy(pidNamespace = netNs) }
        assertFailsWith<IllegalArgumentException> { binding(references() + references().first()) }
        assertFailsWith<IllegalArgumentException> { binding(List(17) { references().first() }) }
        assertFailsWith<IllegalArgumentException> { Binding(key, host, inner, userNs, netNs, references(), 0, 26_000_000_000, 31_000_000_000) }
        assertFailsWith<IllegalArgumentException> { Transcript(binding(), List(129) { records().first() }) }
        assertFailsWith<IllegalArgumentException> { binding(references().dropLast(1)) }
    }

    @Test
    fun `transcript snapshots input lists and assessments cannot be mutated into completion`() {
        val refs = references().toMutableList()
        val b = binding(refs)
        val events = records().toMutableList()
        val transcript = Transcript(b, events)
        refs.clear(); events.clear()
        assertEquals(Status.COMPLETE_UNQUALIFIED, NativeDnsOwnedDomainContract.assess(transcript, 100).status)
        assertFailsWith<UnsupportedOperationException> { (b.references as MutableList<Reference>).clear() }
        assertFailsWith<UnsupportedOperationException> { (transcript.records as MutableList<Record>).clear() }
        val incomplete = assess(emptyList())
        assertFailsWith<UnsupportedOperationException> { (incomplete.missingClaims as MutableSet<Claim>).clear() }
        assertEquals(Status.INCOMPLETE_UNQUALIFIED, incomplete.status)
    }

    @Test
    fun `oversized supplied collections refuse before reading or copying elements`() {
        var reads = 0
        val events = object : AbstractList<Record>() {
            override val size = 129
            override fun get(index: Int): Record { reads++; error("must refuse before element access") }
        }
        assertFailsWith<IllegalArgumentException> { Transcript(binding(), events) }
        val refs = object : AbstractList<Reference>() {
            override val size = 17
            override fun get(index: Int): Reference { reads++; error("must refuse before element access") }
        }
        assertFailsWith<IllegalArgumentException> { binding(refs) }
        assertEquals(0, reads)
    }
}
