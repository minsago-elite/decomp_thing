package decompengine.acp

import java.util.Collections

/**
 * Untrusted, test-only claims for #1521. This has no acquired owner, filesystem/process I/O, clock, trusted decoder,
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
    enum class NamespaceKind { PID, USER, NET, MOUNT }
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
    data class Reference(val id: Int, val namespace: Namespace, val holder: HolderRole, val kind: ReferenceKind, val mountNamespace: Namespace? = null) {
        init {
            require(id in 1..MAX_REFERENCES)
            require(kind != ReferenceKind.PROC_MOUNT || namespace.kind == NamespaceKind.PID)
            require(if (kind == ReferenceKind.PROC_MOUNT) mountNamespace?.kind == NamespaceKind.MOUNT else mountNamespace == null)
            require(kind != ReferenceKind.SOCKET || namespace.kind == NamespaceKind.NET)
            require(holder != HolderRole.BLACKHOLE || kind == ReferenceKind.SOCKET)
        }
    }

    /** Caller-supplied identities are commitments to check later, not authenticated ownership. */
    class Binding(val key: Key, val hostRoot: HostProcessCoordinate, val innerRoot: InnerProcessCoordinate,
        val user: Namespace, val net: Namespace, references: List<Reference>,
        val startNanos: Long, val executionEndNanos: Long, val cleanupEndNanos: Long,
        val hostInnerRoot: HostProcessCoordinate, val mount: Namespace) {
        val references: List<Reference>
        init {
            require(hostRoot.pidNamespace != innerRoot.pidNamespace)
            require(hostInnerRoot.pidNamespace == hostRoot.pidNamespace && hostInnerRoot.pid != hostRoot.pid)
            require(mount.kind == NamespaceKind.MOUNT)
            require(user.kind == NamespaceKind.USER && net.kind == NamespaceKind.NET)
            require(startNanos >= 0 && executionEndNanos > startNanos && cleanupEndNanos > executionEndNanos)
            require(cleanupEndNanos - startNanos <= MAX_DURATION_NANOS)
            require(cleanupEndNanos - executionEndNanos == CLEANUP_RESERVE_NANOS)
            require(references.size in 1..MAX_REFERENCES)
            this.references = snapshot(references, MAX_REFERENCES)
            require(this.references.map { it.id }.toSet().size == this.references.size)
            require(this.references.all { it.namespace in setOf(innerRoot.pidNamespace, user, net, mount) })
            require(setOf(innerRoot.pidNamespace, user, net, mount).all { ns -> this.references.any { it.namespace == ns } })
            require(this.references.filter { it.kind == ReferenceKind.PROC_MOUNT }.all { it.mountNamespace == mount })
        }
    }

    enum class Claim {
        GATE_HELD, ROOT_HANDLE_HELD, INNER_HOST_HANDLE_HELD, SCOPE_BOUND, PRIVATE_PROC_BOUND, INNER_COORDINATE_BOUND,
        FIXED_RLIMITS_BOUND, ESCAPE_RESTRICTIONS_BOUND,
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

    private val admission = setOf(Claim.GATE_HELD, Claim.ROOT_HANDLE_HELD, Claim.INNER_HOST_HANDLE_HELD, Claim.SCOPE_BOUND,
        Claim.FIXED_RLIMITS_BOUND, Claim.ESCAPE_RESTRICTIONS_BOUND,
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
                Claim.INNER_HOST_HANDLE_HELD -> binding.hostInnerRoot
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


    /** Pure specification of the one fixed C leaf, not a filter installation or
     * admission API. io_uring denial is required even when AF_UNIX is denied. */
    enum class SyscallDecision { ALLOW, EPERM, ENOSYS, KILL }
    val deniedSyscalls: Set<Int> = Collections.unmodifiableSet(setOf(53, 101, 155, 165, 166, 272, 304, 308,
        310, 311, 425, 426, 427, 428, 429, 430, 431, 432, 438, 442))
    fun syscallDecision(auditArchitecture: Long, number: Int, argument0: Long = 0): SyscallDecision = when {
        auditArchitecture != 0xc000003eL || number < 0 || number and 0x40000000 != 0 -> SyscallDecision.KILL
        number == 435 -> SyscallDecision.ENOSYS
        number in deniedSyscalls -> SyscallDecision.EPERM
        number == 41 && argument0 !in setOf(2L, 10L) -> SyscallDecision.EPERM
        number == 56 && (argument0 ushr 32 != 0L || argument0 and 0x7e020080L != 0L) -> SyscallDecision.EPERM
        else -> SyscallDecision.ALLOW
    }


    val gateFields: Set<String> = Collections.unmodifiableSet(setOf("schema", "caseName", "control", "innerPid", "innerStart",
        "activeCapabilitiesZero", "boundingMask", "noNewPrivileges", "seccomp", "escapeCanariesPassed", "privateProcOnlyPid1", "nproc", "nofile",
        "fsize", "as", "cpu", "core", "pidDev", "pidIno", "userDev", "userIno", "netDev", "netIno", "mntDev", "mntIno", "procDev", "procIno", "procMountId"))
    /** Shape/bounds only; an actual acquired owner must separately attest every
     * claimed kernel property. Successful parsing never constitutes ownership. */
    fun requireGateShape(fields: Map<String, String>, caseName: String, control: String, nproc: Int) {
        require(fields.keys == gateFields && nproc >= 32)
        require(fields["schema"] == "2" && fields["caseName"] == caseName && fields["control"] == control)
        require(fields.getValue("innerStart").toLongOrNull()?.let { it >= 0 } == true)
        require(fields["innerPid"] == "1" && fields["boundingMask"] == "1400" && fields["seccomp"] == "2")
        for (name in listOf("activeCapabilitiesZero", "noNewPrivileges", "escapeCanariesPassed", "privateProcOnlyPid1")) require(fields[name] == "true")
        val values = mapOf("nproc" to nproc.toString(), "nofile" to "128", "fsize" to "67108864", "as" to "2147483648", "cpu" to "120", "core" to "0")
        values.forEach { (name, value) -> require(fields[name] == value) }
        require(fields.getValue("procMountId").toLongOrNull()?.let { it > 0 } == true)
        for (kind in listOf("pid", "user", "net", "mnt", "proc")) {
            require(fields.getValue(kind + "Dev").toLongOrNull()?.let { it >= 0 } == true)
            require(fields.getValue(kind + "Ino").toLongOrNull()?.let { it > 0 } == true)
        }
    }
    /** Exact declared mount destinations; no arbitrary read-only host tree is
     * accepted. Source/destination inode checks are performed by the real owner. */
    fun requireClosedMountView(rows: List<Triple<String, Set<String>, String>>, declaredReadOnly: Set<String>, declaredWritable: Set<String>) {
        require(rows.size in 1..128 && rows.map { it.first }.distinct().size == rows.size)
        val syntheticWritable = setOf("/", "/proc", "/dev", "/dev/pts", "/dev/shm", "/tmp", "/dev/null", "/dev/zero",
            "/dev/full", "/dev/random", "/dev/urandom", "/dev/tty")
        require(declaredReadOnly.intersect(declaredWritable).isEmpty())
        require(rows.all { it.first in declaredReadOnly || it.first in declaredWritable || it.first in syntheticWritable })
        require(rows.none { it.third in setOf("cgroup", "cgroup2", "sysfs") })
        require(rows.single { it.first == "/proc" }.third == "proc")
        require(rows.filter { it.first in declaredReadOnly }.all { "ro" in it.second && "rw" !in it.second })
        require(rows.filter { "rw" in it.second }.all { it.first in declaredWritable || it.first in syntheticWritable })
        require(declaredReadOnly.all { path -> rows.any { it.first == path } } && declaredWritable.all { path -> rows.any { it.first == path } })
    }
    /** Only fixed pipe/event/pidfd endpoints or the attested private namespace
     * identities may survive in trusted bootstrap. Directories/sockets/rings refuse. */
    fun bootstrapNamespaceReference(target: String, namespaces: Map<String, Long>): Boolean {
        require(target.length <= 4096)
        val kind = target.substringBefore(':')
        if (kind in setOf("pid", "user", "net", "mnt") && target == kind + ":[" + namespaces[kind] + "]") return true
        require(target.matches(Regex("pipe:\\[[0-9]+]")) || target in setOf("anon_inode:[eventfd]", "anon_inode:[eventpoll]", "anon_inode:[pidfd]", "/dev/null"))
        return false
    }

    fun mayReleaseReferences(rootReaped: Boolean, scopeAbsent: Boolean, streamsClosed: Boolean,
        exhaustiveReap: Boolean, payloadReleaseAttempted: Boolean, cleanupFailed: Boolean, observed: Long, end: Long): Boolean =
        rootReaped && scopeAbsent && streamsClosed && (exhaustiveReap || !payloadReleaseAttempted) && !cleanupFailed && observed < end

    val hostRuntimeRoots: Map<String, Map<String, Set<String>>> = Collections.unmodifiableMap(mapOf(
        "test" to mapOf(
            "AcpProviderNativeDnsContractTest.kt" to setOf("AcpProviderNativeDnsContractTestKt", "AcpProviderNativeDnsControl", "NativeNamespace", "NativeNamespaceCredentials", "NativeNamespaceWaitFailure", "NativeObserverBudget", "NativeObserverBudgetOwner", "NativeVisibilityAccumulator", "NativeObserverFailure", "NativeDnsOwnedDomainOwner", "NativeDnsOwnedResult", "NativeDnsOwnedLib", "NativeDnsOwnedFd", "AcpProviderNativeDnsContractTest", "NativeDnsOwnedDomainBoundaryTest"),
            "NativeDnsOwnedDomainContract.kt" to setOf("NativeDnsOwnedDomainContract")
        ),
        "main" to mapOf(
            "LinuxBubblewrapBoundary.kt" to setOf("LinuxBubblewrapBoundaryKt", "SystemdScopeController", "VerifiedScopeManager", "VerifiedSystemdScope", "PinnedSecurityExecutable", "PinnedSystemdBusEndpoint", "PinnedFileIdentity", "AcpSandboxScopeIdentity", "AcpCgroupControllerEvidence", "AcpSandboxRlimitEvidence", "AcpSecurityExecutableEvidence", "AcpCleanupProofFailure", "CommandResult", "TrustedControlProcessOwner", "TrustedControlProcesses"),
            "LinuxFilesystemSyscalls.kt" to setOf("LinuxFilesystemSyscalls", "LinuxFilesystemSyscallsKt", "LinuxFileKey", "LinuxFileIdentity", "LinuxFilesystemCapacity", "LinuxDescriptor", "LinuxProcessDescriptor", "LinuxDescriptorReserve", "NativeClose", "LinuxSyscallException", "LinuxResourceLimitException", "LinuxNamedRegularFileReplacedException", "RuntimeCopyStatistics"),
            "AcpSandboxPolicy.kt" to setOf("AcpSandboxPolicyKt", "AcpSandboxResourceLimits")
        )
    ).mapValues { (_, files) -> Collections.unmodifiableMap(files.mapValues { (_, roots) -> Collections.unmodifiableSet(roots) }) })
    val hostSourcePaths: Map<String, String> = Collections.unmodifiableMap(mapOf(
        "testSourceSha256" to "src/test/kotlin/decompengine/acp/AcpProviderNativeDnsContractTest.kt",
        "ownedContractSourceSha256" to "src/test/kotlin/decompengine/acp/NativeDnsOwnedDomainContract.kt",
        "scopeBackendSourceSha256" to "src/main/kotlin/decompengine/acp/LinuxBubblewrapBoundary.kt",
        "scopeFilesystemSourceSha256" to "src/main/kotlin/decompengine/acp/LinuxFilesystemSyscalls.kt",
        "scopePolicySourceSha256" to "src/main/kotlin/decompengine/acp/AcpSandboxPolicy.kt",
        "hostNativePolicySourceSha256" to "src/main/resources/oracle-native-libraries-v1.properties",
        "hostBuildSourceSha256" to "build.gradle.kts"
    ))
    fun hostClassSource(sourceSet: String, name: String): String? {
        if (!name.matches(Regex("[A-Za-z][A-Za-z0-9_$]*\\.class"))) return null
        val matches = hostRuntimeRoots[sourceSet].orEmpty().filterValues { roots -> roots.any { root -> name == root + ".class" || name.startsWith(root + "$" ) } }.keys
        require(matches.size <= 1)
        return matches.singleOrNull()
    }
    fun requireHostClassIdentity(sourceSet: String, name: String, bytes: ByteArray) {
        val source = requireNotNull(hostClassSource(sourceSet, name))
        require(classIdentity(bytes) == ("decompengine/acp/" + name.removeSuffix(".class") to source))
    }
    /** Bounded data parser, no class loading or filesystem/native execution. */
    fun classIdentity(bytes: ByteArray): Pair<String, String> {
        require(bytes.size in 24..1024 * 1024)
        val input = java.io.DataInputStream(java.io.ByteArrayInputStream(bytes))
        require(input.readInt() == 0xcafebabe.toInt()); input.readUnsignedShort(); require(input.readUnsignedShort() >= 45)
        val count = input.readUnsignedShort(); require(count > 1)
        val strings = arrayOfNulls<String>(count); val classes = IntArray(count)
        var index = 1
        while (index < count) {
            when (input.readUnsignedByte()) {
                1 -> strings[index] = input.readUTF()
                3, 4 -> input.readInt()
                5, 6 -> { input.readLong(); index++; require(index < count) }
                7 -> classes[index] = input.readUnsignedShort()
                8, 16, 19, 20 -> input.readUnsignedShort()
                9, 10, 11, 12, 17, 18 -> input.readInt()
                15 -> { input.readUnsignedByte(); input.readUnsignedShort() }
                else -> error("unsupported host class constant")
            }
            index++
        }
        fun utf(i: Int) = checkNotNull(strings.getOrNull(i))
        fun skip(length: Int) { require(length >= 0 && length <= input.available()); require(input.skipBytes(length) == length) }
        fun attributes(): List<Pair<String, ByteArray>> {
            val values = mutableListOf<Pair<String, ByteArray>>()
            repeat(input.readUnsignedShort()) {
                val name = utf(input.readUnsignedShort()); val length = input.readInt()
                require(length >= 0 && length <= input.available())
                values += name to ByteArray(length).also(input::readFully)
            }
            return values
        }
        input.readUnsignedShort(); val thisClass = input.readUnsignedShort(); input.readUnsignedShort()
        require(thisClass in 1 until count && classes[thisClass] in 1 until count)
        repeat(input.readUnsignedShort()) { input.readUnsignedShort() }
        repeat(2) { repeat(input.readUnsignedShort()) { skip(6); attributes() } }
        val source = attributes().filter { it.first == "SourceFile" }
        require(source.size == 1 && source.single().second.size == 2 && input.available() == 0)
        val value = java.nio.ByteBuffer.wrap(source.single().second).short.toInt() and 65535
        return utf(classes[thisClass]) to utf(value)
    }

    fun requireHostClassInventory(expected: Map<String, ByteArray>, actual: Map<String, ByteArray>) {
        require(expected.size in 1..256 && actual.size <= 256 && expected.keys == actual.keys)
        require(expected.values.sumOf { it.size.toLong() } <= 16L * 1024 * 1024 && actual.values.sumOf { it.size.toLong() } <= 16L * 1024 * 1024)
        require(expected.all { (name, bytes) -> bytes.size in 1..1024 * 1024 && bytes.contentEquals(actual.getValue(name)) })
    }
    fun requireHostGeneration(expected: Map<String, String>, actual: Map<String, String>, expectedGeneration: String, actualGeneration: String) {
        require(expected.keys == hostSourcePaths.keys && actual.keys == expected.keys)
        require(expected.values.all(digest::matches) && expected == actual && digest.matches(expectedGeneration) && expectedGeneration == actualGeneration)
    }

    // Root-adjudicated trust model, not an input/approval mechanism. Stage1
    // can only record the conditional deduction; authenticated job joins are external.
    const val EXECUTOR_CONTRACT = "required-contract-hosted-ubuntu24-v1"
    enum class LocalEvidence { OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED, UNAVAILABLE }
    fun localEvidence(ownedFactsComplete: Boolean, namespaceDeduction: String, contract: String): LocalEvidence =
        if (ownedFactsComplete && namespaceDeduction == "CONDITIONAL" && contract == EXECUTOR_CONTRACT)
            LocalEvidence.OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED else LocalEvidence.UNAVAILABLE

    enum class CleanupSignal { ACQUIRED_SCOPE, DIRECT_ROOT, NONE }
    fun cleanupSignal(scopeCapabilityHeld: Boolean, acquiredScopeRemoved: Boolean, directRootAlive: Boolean,
        directRootHandleHeld: Boolean): CleanupSignal = when {
        scopeCapabilityHeld && !acquiredScopeRemoved -> CleanupSignal.ACQUIRED_SCOPE
        scopeCapabilityHeld -> CleanupSignal.NONE
        directRootAlive && directRootHandleHeld -> CleanupSignal.DIRECT_ROOT
        else -> CleanupSignal.NONE
    }

    fun removedScopeAfterFailedSignal(written: Long, errno: Int, sameAcquiredIdentity: Boolean, linkCount: Int): Boolean =
        written == -1L && errno == 19 && sameAcquiredIdentity && linkCount == 0

    fun cleanupComplete(rootReaped: Boolean, scopeAbsent: Boolean, streamsClosed: Boolean, exhaustiveReap: Boolean,
        referencesClosed: Boolean, hostStateUnchanged: Boolean, cleanupFailed: Boolean, observed: Long, end: Long): Boolean =
        rootReaped && scopeAbsent && streamsClosed && exhaustiveReap && referencesClosed && hostStateUnchanged && !cleanupFailed && observed < end

    private fun <T> snapshot(values: List<T>, maximum: Int): List<T> {
        val size = values.size
        require(size in 0..maximum)
        return Collections.unmodifiableList(List(size) { values[it] })
    }
}
