package decompengine.project

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxProcessDescriptor
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.ContainedCommandFileDescriptorLimits
import decompengine.oracle.fulltree.ContainedCommandFileDescriptorObservation
import decompengine.oracle.fulltree.ContainedCommandFileDescriptorPolicy
import decompengine.oracle.fulltree.parseContainedCommandFileDescriptorLimits
import decompengine.oracle.fulltree.parseFullTreeFunctionObservationProcessStartTimeTicks
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.NoSuchFileException
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Passive hosted-test evidence. This observer never supplies a launch observation or live permit. */
internal class ContainedModuleCompilationHostedObservation private constructor(
    private val project: Path,
    private val runtime: ContainedModuleCompilationRuntimeConfiguration,
) : AutoCloseable {
    class Observation internal constructor(rawFiles: Map<String, ByteArray>, val joined: JsonObject) {
        private val storedFiles = rawFiles.mapValues { it.value.copyOf() }
        val rawFiles: Map<String, ByteArray> get() = storedFiles.mapValues { it.value.copyOf() }
    }

    private data class Identity(val pid: Long, val parentPid: Long, val start: Long, val namespacePids: List<Long>)
    private data class ProcessRecord(val identity: Identity, val limits: ContainedCommandFileDescriptorLimits)
    private data class Capture(val request: ContainedModuleCompilerRequest, val requestPath: Path, val cgroup: String,
        val processes: Map<String, ProcessRecord>, val elapsedMillis: Long)

    private val lock = Any()
    private val started = System.nanoTime()
    private val stop = AtomicBoolean()
    private val files = linkedMapOf<String, ByteArray>()
    private val handles = linkedMapOf<Long, LinuxProcessDescriptor>()
    private var failure: Throwable? = null
    private var phase = "waiting-for-request"
    private var capture: Capture? = null
    private var privateRequestPath: Path? = null
    private var joined: JsonObject? = null
    private var closed = false
    private val thread = Thread(::observe, "hosted-module-process-observer").apply { isDaemon = true }

    /** Stops the original observation window; compilation completion never starts another wait. */
    fun finish(evidence: ModuleCompilationEvidence): Observation {
        try {
            check(!closed && joined == null) { "module process observation was already consumed or closed" }
            stopAndJoin()
            synchronized(lock) { failure }?.let { throw IllegalStateException("module process observation failed", it) }
            val observed = synchronized(lock) { capture }
                ?: error("no coherent live keeper/worker/native compiler observation was captured")
            val verified = ContainedModuleCompilationProof.verify(evidence)
            require(evidence.passed && verified.result.outcome == "compiled-object") { "observation requires successful real module compilation" }
            val proof = requireNotNull(evidence.containedProof)
            require(proof.getValue("schemaVersion") == JsonPrimitive(2)) { "observation requires the descriptor-policy proof" }
            require(verified.request.canonicalBytes.contentEquals(observed.request.canonicalBytes)) {
                "successful compiler proof differs from the privately observed request"
            }
            val workerCommand = proof.getValue("commandRequest").jsonObject.getValue("command").jsonArray
                .map { it.jsonPrimitive.content }
            require(workerCommand[workerCommand.lastIndex - 1] == observed.requestPath.toString()) {
                "successful proof did not consume the observed private request path"
            }
            require(proof.getValue("runtimeConfigurationSha256") == JsonPrimitive(runtime.configurationSha256)) {
                "compiler proof belongs to another configured runtime"
            }
            val attachment = proof.getValue("attachment").jsonObject
            require(attachment.getValue("controlGroup") == JsonPrimitive(observed.cgroup)) { "observed cgroup differs from attachment" }
            val keeper = observed.processes.getValue("keeper")
            val worker = observed.processes.getValue("worker")
            val native = observed.processes.getValue("native")
            val attachedKeeper = attachment.getValue("processes").jsonArray.map { it.jsonObject }
                .single { it.getValue("role") == JsonPrimitive("supervisor-jvm") }
            require(number(attachedKeeper, "hostPid") == keeper.identity.pid &&
                number(attachedKeeper, "startTimeTicks") == keeper.identity.start &&
                attachedKeeper.getValue("namespacePids").jsonArray.map { number(it.jsonPrimitive) } == keeper.identity.namespacePids) {
                "passively observed keeper differs from authenticated attachment identity"
            }
            val attachedLimits = ContainedCommandFileDescriptorObservation.parse(attachment.getValue("fileDescriptorLimits").jsonObject)
            attachedLimits.requireIdentity(keeper.identity.pid, keeper.identity.start)
            require(attachedLimits.limits == keeper.limits)
            val outcome = proof.getValue("execution").jsonObject.getValue("outcome").jsonObject
            require(number(outcome, "keeperPid") == keeper.identity.namespacePids.last() &&
                number(outcome, "childPid") == worker.identity.namespacePids.last()) {
                "observed worker namespace PID differs from the authenticated keeper OUTCOME child"
            }
            require(worker.identity.parentPid == keeper.identity.pid && native.identity.parentPid == worker.identity.pid)
            observed.processes.values.forEach { process ->
                ContainedCommandFileDescriptorObservation(process.identity.pid, process.identity.start, process.limits)
                    .requireSelected(ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION)
            }
            require(parseCommandLine(raw("native.cmdline")) == verified.request.command) {
                "observed direct native compiler argv differs from the genuine request command"
            }
            val retainedHandles = synchronized(lock) { handles.toMap() }
            require(retainedHandles.keys == observed.processes.values.map { it.identity.pid }.toSet())
            require(retainedHandles.values.all(LinuxFilesystemSyscalls::processExited)) {
                "a retained observed process remains alive after completed module compilation"
            }
            val rawRecords = synchronized(lock) { files.toMap() }.toSortedMap().map { (name, bytes) ->
                JsonObject(mapOf("name" to JsonPrimitive(name), "bytes" to JsonPrimitive(bytes.size), "sha256" to JsonPrimitive(sha256(bytes))))
            }
            val record = JsonObject(mapOf(
                "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("hosted-module-process-inheritance-observation-v1"),
                "productionAuthority" to JsonPrimitive(false), "nonce" to JsonPrimitive(observed.request.nonce),
                "profileId" to JsonPrimitive(observed.request.profileId),
                "runtimeConfigurationSha256" to JsonPrimitive(runtime.configurationSha256),
                "requestSha256" to JsonPrimitive(observed.request.sha256), "proofSha256" to JsonPrimitive(sha256(OracleJson.canonicalBytes(proof))),
                "privateRequestPath" to JsonPrimitive(observed.requestPath.toString()),
                "attachmentSha256" to JsonPrimitive(sha256(OracleJson.canonicalBytes(attachment))),
                "outcomeSha256" to JsonPrimitive(sha256(OracleJson.canonicalBytes(outcome))),
                "controlGroup" to JsonPrimitive(observed.cgroup), "capturedAfterMillis" to JsonPrimitive(observed.elapsedMillis),
                "observationWindowMillis" to JsonPrimitive(OBSERVATION_MILLIS),
                "pidfdsExitedAfterExecution" to JsonPrimitive(true),
                "nativeCommand" to JsonArray(verified.request.command.map(::JsonPrimitive)),
                "processes" to JsonObject(observed.processes.mapValues { (_, process) -> process.json() }),
                "rawFiles" to JsonArray(rawRecords),
            ))
            synchronized(lock) { joined = record; phase = "joined-successful-proof" }
            return Observation(retainedFiles(), record)
        } catch (problem: Throwable) {
            recordFailure(problem)
            closeHandles()
            throw problem
        }
    }

    /** Available after failure as well as success; only the caller decides where artifacts are written. */
    fun retainedFiles(): Map<String, ByteArray> = synchronized(lock) {
        files.mapValues { it.value.copyOf() } + ("observation-status.json" to OracleJson.canonicalBytes(JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1), "provider" to JsonPrimitive("hosted-module-process-observation-status-v1"),
            "productionAuthority" to JsonPrimitive(false), "phase" to JsonPrimitive(phase),
            "captureComplete" to JsonPrimitive(capture != null), "joined" to JsonPrimitive(joined != null),
            "closed" to JsonPrimitive(closed), "failure" to (failure?.let { problem -> JsonObject(mapOf(
                "type" to JsonPrimitive(problem.javaClass.name.take(256)),
                "message" to JsonPrimitive(problem.message.orEmpty().take(4096)))) } ?: JsonNull),
        ))))
    }

    override fun close() {
        try { stopAndJoin() }
        catch (problem: Throwable) { recordFailure(problem); throw problem }
        finally {
            synchronized(lock) { closed = true }
            closeHandles()
        }
    }

    private fun observe() {
        try {
            var request: ContainedModuleCompilerRequest? = null
            while (!stop.get()) {
                checkpoint()
                if (request == null) request = discoverRequest()
                request?.let { selected ->
                    synchronized(lock) { phase = "waiting-for-direct-native-compiler" }
                    val group = "${runtime.managerControlGroup.trimEnd('/')}/app.slice/decomp-module-compile-${selected.nonce.take(32)}.scope"
                    val censusPath = Path.of("/sys/fs/cgroup").resolve(group.removePrefix("/")).resolve("cgroup.procs")
                    val census = try { readBounded(censusPath, PROCESS_FILE_BYTES) } catch (_: NoSuchFileException) { null }
                    if (census != null) {
                        for (pid in parseCensus(census)) {
                            checkpoint()
                            val handle = try { LinuxFilesystemSyscalls.openProcessHandle(pid) }
                            catch (problem: decompengine.acp.LinuxSyscallException) { if (problem.errno == 3) continue else throw problem }
                            var retained = false
                            try {
                                if (LinuxFilesystemSyscalls.processExited(handle)) continue
                                val argv = try { readBounded(Path.of("/proc/$pid/cmdline"), PROCESS_FILE_BYTES) }
                                catch (problem: NoSuchFileException) { if (LinuxFilesystemSyscalls.processExited(handle)) continue else throw problem }
                                if (argv.isEmpty() || parseCommandLine(argv) != selected.command) continue
                                own(handle); retained = true
                                retain("cgroup.procs.before", census)
                                retain("native.cmdline.discovery", argv)
                                synchronized(lock) { phase = "capturing-process-chain" }
                                val captured = captureChain(selected, group, censusPath, pid)
                                synchronized(lock) { capture = captured; phase = "captured-process-chain" }
                                return
                            } finally { if (!retained) handle.close() }
                        }
                    }
                }
                Thread.sleep(2)
            }
            synchronized(lock) { phase = "stopped-before-capture" }
        } catch (problem: Throwable) {
            if (problem is InterruptedException && stop.get()) synchronized(lock) { phase = "stopped-before-capture" }
            else recordFailure(problem)
            closeHandles()
        }
    }

    private fun discoverRequest(): ContainedModuleCompilerRequest? {
        val candidates = ArrayList<Path>()
        Files.list(project).use { paths ->
            val iterator = paths.iterator()
            var entries = 0
            while (iterator.hasNext()) {
                require(++entries <= 4096) { "project request discovery exceeds its entry bound" }
                val path = iterator.next()
                if (path.fileName.toString().startsWith(".module-compilation-")) {
                    require(candidates.size < MAXIMUM_PIDS) { "too many private compiler request directories" }
                    require(Files.isDirectory(path, NOFOLLOW_LINKS) && path.toRealPath() == path)
                    candidates.add(path.resolve("request.json"))
                }
            }
        }
        var selected: Pair<Path, ByteArray>? = null
        for (path in candidates) {
            checkpoint()
            val attributes = try { Files.readAttributes(path, "unix:mode,nlink", NOFOLLOW_LINKS) }
            catch (_: NoSuchFileException) { continue }
            // The real coordinator sets0400 only after its bounded request write has completed.
            if ((attributes.getValue("mode") as Number).toInt() and 0xfff != 256) continue
            require((attributes.getValue("nlink") as Number).toInt() == 1 && Files.isRegularFile(path, NOFOLLOW_LINKS))
            require(selected == null) { "ambiguous simultaneous private compiler requests" }
            selected = path to readStableRegularFile(path.parent, path.fileName.toString(),
                ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES.toLong()).bytes
        }
        return selected?.let { (path, bytes) ->
            val request = ContainedModuleCompilerRequest.parse(bytes)
            require(request.profileId == runtime.profileId && request.compilerPath == runtime.compilerExecutable &&
                request.compilerSha256 == runtime.compilerSha256) { "private request differs from the configured compiler" }
            require(path.parent.parent == project)
            retain("request.json", bytes, ContainedModuleCompilerRequest.MAXIMUM_REQUEST_BYTES)
            privateRequestPath = path
            request
        }
    }

    private fun captureChain(request: ContainedModuleCompilerRequest, group: String, census: Path, nativePid: Long): Capture {
        val native = captureProcess("native", nativePid, group)
        own(LinuxFilesystemSyscalls.openProcessHandle(native.identity.parentPid))
        val worker = captureProcess("worker", native.identity.parentPid, group)
        own(LinuxFilesystemSyscalls.openProcessHandle(worker.identity.parentPid))
        val keeper = captureProcess("keeper", worker.identity.parentPid, group)
        val records = linkedMapOf("keeper" to keeper, "worker" to worker, "native" to native)
        require(records.values.map { it.identity.pid }.distinct().size == 3)
        require(records.values.map { it.identity.namespacePids.size }.distinct().size == 1 && keeper.identity.namespacePids.size >= 2) {
            "observed compiler chain does not share the nested PID namespace depth"
        }
        require(keeper.identity.start <= worker.identity.start && worker.identity.start <= native.identity.start)
        val argv = readBounded(Path.of("/proc/$nativePid/cmdline"), PROCESS_FILE_BYTES)
        retain("native.cmdline", argv)
        require(parseCommandLine(argv) == request.command) { "direct native compiler argv changed during capture" }
        for ((role, record) in records) {
            requireLive(record.identity.pid)
            require(identity(role, record.identity.pid, group, "final") == record.identity) {
                "process identity or lineage changed across the complete chain observation"
            }
            val limits = readProc(role, record.identity.pid, "limits", "final")
            require(parseContainedCommandFileDescriptorLimits(text(limits)) == record.limits)
        }
        val after = readBounded(census, PROCESS_FILE_BYTES)
        retain("cgroup.procs.after", after)
        require(parseCensus(after).containsAll(records.values.map { it.identity.pid })) { "observed chain left its operation cgroup" }
        val finalArgv = readBounded(Path.of("/proc/$nativePid/cmdline"), PROCESS_FILE_BYTES)
        retain("native.cmdline.final", finalArgv)
        require(finalArgv.contentEquals(argv)) { "native compiler argv changed across the complete chain observation" }
        records.values.forEach { requireLive(it.identity.pid) }
        checkpoint()
        return Capture(request, requireNotNull(privateRequestPath), group, records, TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - started))
    }

    private fun captureProcess(role: String, pid: Long, group: String): ProcessRecord {
        requireLive(pid)
        val before = identity(role, pid, group, "before")
        val limits = parseContainedCommandFileDescriptorLimits(text(readProc(role, pid, "limits", "observed")))
        ContainedCommandFileDescriptorObservation(pid, before.start, limits)
            .requireSelected(ContainedCommandFileDescriptorPolicy.MODULE_COMPILATION)
        require(identity(role, pid, group, "after") == before) { "process generation, parent or namespace identity changed during sampling" }
        requireLive(pid)
        return ProcessRecord(before, limits)
    }

    private fun identity(role: String, pid: Long, group: String, bracket: String): Identity {
        checkpoint()
        val stat = text(readProc(role, pid, "stat", bracket))
        val start = parseFullTreeFunctionObservationProcessStartTimeTicks(pid, stat)
        val statFields = stat.trimEnd('\n').substring(stat.lastIndexOf(") ") + 2).split(' ')
        require(statFields[0] !in setOf("Z", "X", "x")) { "observed process is not live" }
        val parent = positivePid(statFields[1])
        val status = text(readProc(role, pid, "status", bracket))
        fun field(name: String): String = status.lineSequence().filter { it.startsWith("$name:") }.toList()
            .also { require(it.size == 1) { "process status lacks one $name field" } }.single().substringAfter(':').trim()
        require(positivePid(field("Pid")) == pid && positivePid(field("PPid")) == parent)
        require(field("State").substringBefore(' ') !in setOf("Z", "X", "x"))
        val namespace = field("NSpid").split(Regex("[ \\t]+"))
            .also { require(it.size in 1..32) }.map(::positivePid)
        require(namespace.first() == pid)
        require(text(readProc(role, pid, "cgroup", bracket)).lineSequence().filter(String::isNotEmpty).toList() == listOf("0::$group")) {
            "process is outside the exact compiler operation cgroup"
        }
        return Identity(pid, parent, start, namespace)
    }

    private fun readProc(role: String, pid: Long, name: String, bracket: String): ByteArray =
        readBounded(Path.of("/proc/$pid/$name"), PROCESS_FILE_BYTES).also { retain("$role.$name.$bracket", it) }

    private fun own(handle: LinuxProcessDescriptor) {
        try {
            synchronized(lock) {
                check(!stop.get() && !closed) { "process observer is stopping" }
                require(handles.size < MAXIMUM_PIDS && handle.pid !in handles) { "duplicate or excessive observed process identity" }
                handles[handle.pid] = handle
            }
        } catch (problem: Throwable) { handle.close(); throw problem }
    }

    private fun requireLive(pid: Long) {
        checkpoint()
        val handle = synchronized(lock) { requireNotNull(handles[pid]) }
        require(!LinuxFilesystemSyscalls.processExited(handle)) { "observed process exited during the coherent capture" }
    }

    private fun retain(name: String, bytes: ByteArray, limit: Int = PROCESS_FILE_BYTES) {
        require(name.matches(Regex("[a-z][a-z0-9.-]{0,63}")) && bytes.size <= limit)
        synchronized(lock) {
            require(name !in files) { "passive observer attempted to overwrite raw evidence" }
            require(files.size < 64 && files.values.sumOf { it.size.toLong() } + bytes.size <= MAXIMUM_RETAINED_BYTES)
            files[name] = bytes.copyOf()
        }
    }

    private fun raw(name: String): ByteArray = synchronized(lock) { requireNotNull(files[name]).copyOf() }
    private fun closeHandles() {
        val owned = synchronized(lock) { handles.values.toList().also { handles.clear() } }
        owned.asReversed().forEach(LinuxProcessDescriptor::close)
    }
    private fun checkpoint() {
        if (stop.get() || Thread.currentThread().isInterrupted) throw InterruptedException("process observer stopped")
        require(System.nanoTime() - started < TimeUnit.MILLISECONDS.toNanos(OBSERVATION_MILLIS)) { "process observation exceeded its original 90-second window" }
    }

    private fun stopAndJoin() {
        stop.set(true)
        thread.interrupt()
        var interrupted = Thread.interrupted()
        val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(5)
        try {
            while (thread.isAlive && System.nanoTime() < deadline) {
                try { thread.join(25) } catch (_: InterruptedException) { interrupted = true }
            }
            check(!thread.isAlive) { "passive process observer did not stop within its bounded join" }
        } finally { if (interrupted) Thread.currentThread().interrupt() }
    }

    private fun recordFailure(problem: Throwable) = synchronized(lock) {
        if (failure == null) failure = problem
        phase = "failed"
    }

    private fun ProcessRecord.json() = JsonObject(mapOf(
        "hostPid" to JsonPrimitive(identity.pid), "parentHostPid" to JsonPrimitive(identity.parentPid),
        "startTimeTicks" to JsonPrimitive(identity.start), "namespacePids" to JsonArray(identity.namespacePids.map(::JsonPrimitive)),
        "softLimit" to JsonPrimitive(limits.softLimit), "hardLimit" to JsonPrimitive(limits.hardLimit),
    ))

    companion object {
        private const val PROCESS_FILE_BYTES = 64 * 1024
        private const val MAXIMUM_PIDS = 128
        private const val MAXIMUM_RETAINED_BYTES = 8L * 1024 * 1024
        private const val OBSERVATION_MILLIS = 90_000L

        fun start(project: Path, runtime: ContainedModuleCompilationRuntimeConfiguration): ContainedModuleCompilationHostedObservation {
            require(project.isAbsolute && project.normalize() == project && project.toRealPath() == project && Files.isDirectory(project, NOFOLLOW_LINKS))
            return ContainedModuleCompilationHostedObservation(project, runtime).also { it.thread.start() }
        }

        private fun readBounded(path: Path, limit: Int): ByteArray = Files.newInputStream(path, NOFOLLOW_LINKS).use { input ->
            input.readNBytes(limit + 1).also { require(it.size <= limit) { "passive process observation file exceeds its bound" } }
        }
        private fun text(bytes: ByteArray): String = bytes.decodeToString(throwOnInvalidSequence = true)
        private fun positivePid(value: String): Long {
            require(value.matches(Regex("[1-9][0-9]{0,9}"))) { "process PID is not a positive canonical integer" }
            return requireNotNull(value.toLongOrNull()).also { require(it <= Int.MAX_VALUE.toLong()) }
        }
        private fun parseCensus(bytes: ByteArray): Set<Long> {
            val rows = text(bytes).lineSequence().filter(String::isNotEmpty).take(MAXIMUM_PIDS + 1).toList()
            require(rows.size <= MAXIMUM_PIDS)
            return rows.map(::positivePid).also { require(it.distinct().size == it.size) }.toSet()
        }
        private fun parseCommandLine(bytes: ByteArray): List<String> {
            require(bytes.isNotEmpty() && bytes.last() == 0.toByte()) { "native command line is incomplete" }
            return text(bytes).split('\u0000').dropLast(1).also { require(it.size in 1..256) }
        }
        private fun number(record: JsonObject, field: String): Long = number(record.getValue(field).jsonPrimitive)
        private fun number(value: JsonPrimitive): Long {
            require(!value.isString && value.content.matches(Regex("0|[1-9][0-9]{0,18}")))
            return requireNotNull(value.content.toLongOrNull())
        }
    }
}
