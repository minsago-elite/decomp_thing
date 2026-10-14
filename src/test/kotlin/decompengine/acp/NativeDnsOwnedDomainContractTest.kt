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
    private val mountNs = Namespace(NamespaceKind.MOUNT, 4, 14)
    private val key = Key("inert-run", Case.CANCEL, Sources(source, source, source, source), "inert-unit.scope", source)
    private val host = HostProcessCoordinate(100, 1, hostPidNs)
    private val inner = InnerProcessCoordinate(1, 2, innerPidNs)
    private val hostInner = HostProcessCoordinate(101, 2, hostPidNs)
    private fun references() = listOf(
        Reference(1, innerPidNs, HolderRole.INNER_SUPERVISOR, ReferenceKind.PROC_MOUNT, mountNs),
        Reference(2, userNs, HolderRole.HOST_OWNER, ReferenceKind.NAMESPACE_FD),
        Reference(3, netNs, HolderRole.BLACKHOLE, ReferenceKind.SOCKET),
        Reference(4, mountNs, HolderRole.HOST_OWNER, ReferenceKind.NAMESPACE_FD),
    )
    private fun binding(refs: List<Reference> = references()) = Binding(key, host, inner, userNs, netNs, refs,
        0, 25_000_000_000, 30_000_000_000, hostInner, mountNs)
    private fun records(): List<Record> {
        val claims = listOf(Claim.GATE_HELD, Claim.ROOT_HANDLE_HELD, Claim.INNER_HOST_HANDLE_HELD, Claim.FIXED_RLIMITS_BOUND,
            Claim.ESCAPE_RESTRICTIONS_BOUND, Claim.SCOPE_BOUND, Claim.PRIVATE_PROC_BOUND,
            Claim.INNER_COORDINATE_BOUND, Claim.REFERENCE_INVENTORY_RECORDED, Claim.NON_ESCAPE_RECORDED,
            Claim.PAYLOAD_RELEASED, Claim.PAYLOAD_TERMINAL, Claim.ROOT_REAPED, Claim.DESCENDANTS_REAPED,
            Claim.SCOPE_ABSENT, Claim.STREAMS_JOINED_CLOSED, Claim.HOST_STATE_UNCHANGED)
        val events = claims.mapIndexed { i, claim -> Record(key, i + 1, i.toLong(), claim, when (claim) {
            Claim.ROOT_HANDLE_HELD, Claim.ROOT_REAPED -> host
            Claim.INNER_HOST_HANDLE_HELD -> hostInner
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
            val b = Binding(changedKey, host, inner, userNs, netNs, references(), 0, 25_000_000_000, 30_000_000_000, hostInner, mountNs)
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
        for (id in 1..4) {
            val result = assess(renumber(events.filterNot { it.referenceId == id }))
            assertEquals(Status.INCOMPLETE_UNQUALIFIED, result.status)
            assertEquals(listOf(id), result.unclosedReferences)
        }
    }

    @Test
    fun `payload cannot precede any admission obligation or root handle`() {
        for (claim in listOf(Claim.GATE_HELD, Claim.ROOT_HANDLE_HELD, Claim.INNER_HOST_HANDLE_HELD, Claim.FIXED_RLIMITS_BOUND,
            Claim.ESCAPE_RESTRICTIONS_BOUND, Claim.SCOPE_BOUND, Claim.PRIVATE_PROC_BOUND,
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
        assertFailsWith<IllegalArgumentException> { Binding(key, host, inner, userNs, netNs, references(), 0, 26_000_000_000, 31_000_000_000, hostInner, mountNs) }
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

    @Test
    fun fixedFilterDeniesAllNamespaceAndUnixAndRingRoutesWithoutBreakingOrdinaryClone() {
        val policy = NativeDnsOwnedDomainContract
        val arch = 0xc000003eL
        policy.deniedSyscalls.forEach { assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.EPERM, policy.syscallDecision(arch, it)) }
        for (number in listOf(425, 426, 427, 53, 438)) assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.EPERM, policy.syscallDecision(arch, number))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.ENOSYS, policy.syscallDecision(arch, 435))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.EPERM, policy.syscallDecision(arch, 41, 1))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.ALLOW, policy.syscallDecision(arch, 41, 2))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.ALLOW, policy.syscallDecision(arch, 41, 10))
        for (flag in listOf(0x80L, 0x20000L, 0x2000000L, 0x4000000L, 0x8000000L, 0x10000000L, 0x20000000L, 0x40000000L, 1L shl 32))
            assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.EPERM, policy.syscallDecision(arch, 56, flag))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.ALLOW, policy.syscallDecision(arch, 56, 0x10f00L))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.KILL, policy.syscallDecision(0x40000003L, 41, 2))
        assertEquals(NativeDnsOwnedDomainContract.SyscallDecision.KILL, policy.syscallDecision(arch, 0x40000029, 2))
    }

    @Test
    fun pureFilterDenialInventoryBindsTheActualNativeSourceMacro() {
        val raw = checkNotNull(javaClass.getResourceAsStream("/acp-provider-dns-native/provider_dns_loopback_fixture.c")).use { it.readNBytes(65537) }
        assertTrue(raw.size in 1..65536)
        val source = raw.toString(Charsets.US_ASCII)
        val macro = source.substringAfter("#define OWNED_DENY_SYSCALLS(X)").substringBefore("#define OWNED_NOFILE")
        val values = Regex("X\\(([0-9]+)\\)").findAll(macro).map { it.groupValues[1].toInt() }.toList()
        assertEquals(values.size, values.distinct().size)
        assertEquals(NativeDnsOwnedDomainContract.deniedSyscalls, values.toSet())
        assertTrue(source.contains("OWNED_NEWNS_MASK UINT32_C(0x7e020080)"))
    }

    @Test
    fun gateParsingCannotOmitOrRelaxAnyAppliedLimitOrKernelRestriction() {
        val values = linkedMapOf("schema" to "2", "caseName" to "cancel", "control" to "positive", "innerPid" to "1", "innerStart" to "7",
            "activeCapabilitiesZero" to "true", "boundingMask" to "1400", "noNewPrivileges" to "true", "seccomp" to "2",
            "escapeCanariesPassed" to "true", "privateProcOnlyPid1" to "true", "nproc" to "1024", "nofile" to "128", "fsize" to "67108864", "as" to "2147483648", "cpu" to "120", "core" to "0")
        for (kind in listOf("pid", "user", "net", "mnt", "proc")) { values[kind + "Dev"] = "4"; values[kind + "Ino"] = "10" }
        values["procMountId"] = "15"
        NativeDnsOwnedDomainContract.requireGateShape(values, "cancel", "positive", 1024)
        for (field in values.keys) {
            assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireGateShape(values - field, "cancel", "positive", 1024) }
        }
        for (field in listOf("nofile", "as", "cpu", "core", "seccomp", "nproc", "activeCapabilitiesZero", "noNewPrivileges", "escapeCanariesPassed"))
            assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireGateShape(values + (field to "unexpected"), "cancel", "positive", 1024) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireGateShape(values + ("extra" to "1"), "cancel", "positive", 1024) }
        assertFailsWith<IllegalStateException> { nativeOwnedProperties("a=1\na=2\n".toByteArray()) }
    }

    @Test
    fun unknownReapOrLateFinalObservationRetainsRealOwnerReferences() {
        fun allowed(root: Boolean = true, scope: Boolean = true, streams: Boolean = true, reap: Boolean = true,
            released: Boolean = true, failed: Boolean = false, now: Long = 9) = NativeDnsOwnedDomainContract.mayReleaseReferences(root, scope, streams, reap, released, failed, now, 10)
        assertTrue(allowed())
        assertTrue(NativeDnsOwnedDomainContract.cleanupComplete(true, true, true, true, true, true, false, 9, 10))
        assertTrue(!NativeDnsOwnedDomainContract.cleanupComplete(true, true, true, true, false, true, false, 9, 10))
        assertTrue(!NativeDnsOwnedDomainContract.cleanupComplete(true, true, true, true, true, true, false, 10, 10))
        for (refused in listOf(allowed(root = false), allowed(scope = false), allowed(streams = false), allowed(reap = false), allowed(failed = true), allowed(now = 10), allowed(now = 11))) assertTrue(!refused)
        assertTrue(allowed(reap = false, released = false))
        assertFailsWith<IllegalArgumentException> { Binding(key, host, inner, userNs, netNs, references(), 0, 25_000_000_000, 30_000_000_000, host.copy(pidNamespace = innerPidNs), mountNs) }
        assertFailsWith<IllegalArgumentException> { Reference(1, innerPidNs, HolderRole.INNER_SUPERVISOR, ReferenceKind.PROC_MOUNT) }
    }

    @Test
    fun everyNewOwnerRuntimeClassHasAnExactCapsuleRootWithoutAdmittingTestsOrLookalikes() {
        val expected = setOf("NativeDnsOwnedDomainOwner", "NativeDnsOwnedResult", "NativeDnsOwnedLib", "NativeDnsOwnedFd", "NativeDnsOwnedDomainContract")
        assertEquals(expected, nativeOwnedCapsuleRoots)
        for (root in expected) {
            assertTrue(nativeOwnedCapsuleClass(root + ".class"))
            assertTrue(nativeOwnedCapsuleClass(root + "$" + "Nested.class"))
            assertTrue(!nativeOwnedCapsuleClass(root + "Test.class"))
            assertTrue(!nativeOwnedCapsuleClass(root + "Lookalike.class"))
            assertTrue(!nativeOwnedCapsuleClass(root + ".kt"))
        }
        assertTrue(!nativeOwnedCapsuleClass("Unrelated.class"))
    }

    @Test
    fun actualClosedViewPredicateRejectsUnlistedTreesWritableInputsAndBootstrapChannels() {
        val ro = setOf("/fixture-input", "/etc/resolv.conf")
        val rw = setOf("/fixture-output")
        val rows = listOf(Triple("/", setOf("rw"), "tmpfs"), Triple("/proc", setOf("rw"), "proc"),
            Triple("/fixture-input", setOf("ro"), "ext4"), Triple("/etc/resolv.conf", setOf("ro"), "ext4"),
            Triple("/fixture-output", setOf("rw"), "ext4"))
        NativeDnsOwnedDomainContract.requireClosedMountView(rows, ro, rw)
        for (path in listOf("/run/user/1000", "/sys/fs/cgroup", "/host-proc", "/home", "/fixture-output/nested"))
            assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireClosedMountView(rows + Triple(path, setOf("ro"), "ext4"), ro, rw) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireClosedMountView(rows.map { if (it.first == "/fixture-input") it.copy(second = setOf("rw")) else it }, ro, rw) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireClosedMountView(rows.map { if (it.first == "/proc") it.copy(third = "cgroup2") else it }, ro, rw) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireClosedMountView(rows.dropLast(1), ro, rw) }
        val namespaces = mapOf("pid" to 10L, "user" to 11L, "net" to 12L, "mnt" to 13L)
        assertTrue(NativeDnsOwnedDomainContract.bootstrapNamespaceReference("net:[12]", namespaces))
        assertTrue(!NativeDnsOwnedDomainContract.bootstrapNamespaceReference("pipe:[123]", namespaces))
        for (target in listOf("net:[99]", "socket:[123]", "anon_inode:[io_uring]", "/", "/proc", "/sys/fs/cgroup", "/run/user/1000/bus"))
            assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.bootstrapNamespaceReference(target, namespaces) }
    }

    @Test
    fun exitedDirectRootDoesNotSuppressAlreadyAcquiredScopeCleanup() {
        var scopeCalls = 0; var rootCalls = 0
        nativeOwnedCleanupSignal(true, false, false, true, { scopeCalls++ }, { rootCalls++ })
        assertEquals(1, scopeCalls); assertEquals(0, rootCalls)
        val sentinel = IllegalStateException("owned-scope-write-failed")
        val observed = assertFailsWith<IllegalStateException> {
            nativeOwnedCleanupSignal(true, false, false, true, { throw sentinel }, { rootCalls++ })
        }
        assertTrue(observed === sentinel); assertEquals(0, rootCalls)
        nativeOwnedCleanupSignal(true, true, false, true, { scopeCalls++ }, { rootCalls++ })
        assertEquals(1, scopeCalls)
        nativeOwnedCleanupSignal(false, false, true, true, { scopeCalls++ }, { rootCalls++ })
        assertEquals(1, rootCalls)
        nativeOwnedCleanupSignal(false, false, false, true, { scopeCalls++ }, { rootCalls++ })
        assertEquals(1, scopeCalls); assertEquals(1, rootCalls)
        assertTrue(NativeDnsOwnedDomainContract.removedScopeAfterFailedSignal(-1, 19, true, 0))
        assertTrue(!NativeDnsOwnedDomainContract.removedScopeAfterFailedSignal(-1, 19, true, 2))
        assertTrue(!NativeDnsOwnedDomainContract.removedScopeAfterFailedSignal(-1, 19, false, 0))
        assertTrue(!NativeDnsOwnedDomainContract.removedScopeAfterFailedSignal(-1, 5, true, 0))
    }

    @Test
    fun onlyDeliberateLastReferenceDistinguishesRefusalFromCleanPair() {
        val ordinaryOpen = MutableList(5) { true }
        var deliberateOpen = true
        ordinaryOpen.indices.forEach { ordinaryOpen[it] = false }
        fun actualPredicate() = NativeDnsOwnedDomainContract.cleanupComplete(true, true, true, true,
            ordinaryOpen.none { it } && !deliberateOpen, true, false, 9, 10)
        assertTrue(ordinaryOpen.none { it })
        assertTrue(!actualPredicate())
        deliberateOpen = false
        assertTrue(actualPredicate())
        assertTrue(!NativeDnsOwnedDomainContract.cleanupComplete(true, true, true, true, true, true, true, 9, 10))
    }

    private fun authoredHostClass(name: String = "decompengine/acp/PinnedSecurityExecutable", source: String = "LinuxBubblewrapBoundary.kt",
        duplicateSource: Boolean = false): ByteArray {
        val buffer = java.io.ByteArrayOutputStream()
        java.io.DataOutputStream(buffer).use { out ->
            out.writeInt(0xcafebabe.toInt()); out.writeShort(0); out.writeShort(65); out.writeShort(7)
            out.writeByte(1); out.writeUTF(name); out.writeByte(7); out.writeShort(1)
            out.writeByte(1); out.writeUTF("java/lang/Object"); out.writeByte(7); out.writeShort(3)
            out.writeByte(1); out.writeUTF("SourceFile"); out.writeByte(1); out.writeUTF(source)
            out.writeShort(0x21); out.writeShort(2); out.writeShort(4)
            out.writeShort(0); out.writeShort(0); out.writeShort(0); out.writeShort(if (duplicateSource) 2 else 1)
            repeat(if (duplicateSource) 2 else 1) { out.writeShort(5); out.writeInt(2); out.writeShort(6) }
        }
        return buffer.toByteArray()
    }

    @Test
    fun actualHostClassParserRefusesWrongSourceIdentityTruncationAndDuplicateSource() {
        val bytes = authoredHostClass()
        NativeDnsOwnedDomainContract.requireHostClassIdentity("main", "PinnedSecurityExecutable.class", bytes)
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostClassIdentity("main", "PinnedSecurityExecutable.class", authoredHostClass(source = "OtherGeneration.kt")) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostClassIdentity("main", "PinnedSecurityExecutable.class", authoredHostClass(name = "decompengine/acp/Lookalike")) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostClassIdentity("main", "Unlisted.class", bytes) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.classIdentity(authoredHostClass(duplicateSource = true)) }
        assertFailsWith<Exception> { NativeDnsOwnedDomainContract.classIdentity(bytes.copyOf(bytes.size - 1)) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.classIdentity(ByteArray(1024 * 1024 + 1)) }
        val roots = NativeDnsOwnedDomainContract.hostRuntimeRoots
        assertTrue(roots.getValue("main").getValue("LinuxBubblewrapBoundary.kt").containsAll(setOf("SystemdScopeController", "VerifiedSystemdScope", "PinnedSystemdBusEndpoint", "LinuxBubblewrapBoundaryKt")))
        assertEquals(null, NativeDnsOwnedDomainContract.hostClassSource("main", "SystemdScopeControllerLookalike.class"))
        assertFailsWith<UnsupportedOperationException> { (roots as MutableMap<String, Map<String, Set<String>>>).clear() }
    }

    @Test
    fun executedHostInventoryAndSourceJoinRejectMissingExtraAndChangedBytes() {
        val expected = mapOf("decompengine/acp/PinnedSecurityExecutable.class" to authoredHostClass())
        NativeDnsOwnedDomainContract.requireHostClassInventory(expected, expected)
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostClassInventory(expected, emptyMap()) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostClassInventory(expected, expected + ("extra.class" to byteArrayOf(1))) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostClassInventory(expected, expected.mapValues { it.value.copyOf().also { value -> value[value.lastIndex] = 99 } }) }
        val sources = NativeDnsOwnedDomainContract.hostSourcePaths.mapValues { "a".repeat(64) }
        NativeDnsOwnedDomainContract.requireHostGeneration(sources, sources, "b".repeat(64), "b".repeat(64))
        val key = sources.keys.first()
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostGeneration(sources, sources - key, "b".repeat(64), "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostGeneration(sources, sources + (key to "c".repeat(64)), "b".repeat(64), "b".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostGeneration(sources, sources, "b".repeat(64), "c".repeat(64)) }
        assertFailsWith<IllegalArgumentException> { NativeDnsOwnedDomainContract.requireHostGeneration(sources, sources + ("unlisted" to "a".repeat(64)), "b".repeat(64), "b".repeat(64)) }
    }

    @Test
    fun actualTimeoutClassIsRequiredAndChangedBytecodeCannotBorrowTheHostInventory() {
        val name = "NativeNamespaceWaitFailure.class"
        val key = "decompengine/acp/" + name
        // Read the actual compiled fixture timeout class, never an authored substitute.
        val actual = checkNotNull(javaClass.getResourceAsStream("/" + key)).use { it.readNBytes(1024 * 1024 + 1) }
        NativeDnsOwnedDomainContract.requireHostClassIdentity("test", name, actual)
        assertEquals("AcpProviderNativeDnsContractTest.kt", NativeDnsOwnedDomainContract.hostClassSource("test", name))
        assertEquals(null, NativeDnsOwnedDomainContract.hostClassSource("test", "NativeNamespaceWaitFailureLookalike.class"))
        val other = "decompengine/acp/PinnedSecurityExecutable.class" to authoredHostClass()
        val expected = mapOf(other, key to actual)
        NativeDnsOwnedDomainContract.requireHostClassInventory(expected, expected)
        assertFailsWith<IllegalArgumentException> {
            NativeDnsOwnedDomainContract.requireHostClassInventory(expected, expected - key)
        }
        val changed = actual.copyOf().also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() }
        assertFailsWith<IllegalArgumentException> {
            NativeDnsOwnedDomainContract.requireHostClassInventory(expected, expected + (key to changed))
        }
    }

    @Test
    fun completeLocalOwnedFactsNeverMintSupportedHostOrUnconditionalNamespaceQualification() {
        val model = NativeDnsOwnedDomainContract
        assertEquals(NativeDnsOwnedDomainContract.LocalEvidence.OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED,
            model.localEvidence(true, "CONDITIONAL", model.EXECUTOR_CONTRACT))
        assertEquals(NativeDnsOwnedDomainContract.LocalEvidence.UNAVAILABLE, model.localEvidence(false, "CONDITIONAL", model.EXECUTOR_CONTRACT))
        assertEquals(NativeDnsOwnedDomainContract.LocalEvidence.UNAVAILABLE, model.localEvidence(true, "DESTROYED", model.EXECUTOR_CONTRACT))
        assertEquals(NativeDnsOwnedDomainContract.LocalEvidence.UNAVAILABLE, model.localEvidence(true, "CONDITIONAL", "caller-approved-host"))
        assertTrue(NativeDnsOwnedDomainContract.LocalEvidence.entries.none { it.name == "PASS" || it.name == "QUALIFIED" })
    }

}
