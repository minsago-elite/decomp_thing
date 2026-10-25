package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.AccessDeniedException
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Finite unprivileged child. This program has no provisioner, mount or root-command interface. */
internal object FullTreeDiskScratchResetProbe {
    private const val OWNER = 65534
    private const val MAXIMUM_BYTES = 67_108_864L
    private const val MAXIMUM_INODES = 4096L
    private const val SPARSE_BYTES = 1L shl 40
    private const val DEPTH = 512
    private val ROOT = Path.of("/var/lib/decomp-oracle-ext4-reset-ci")
    private val MODES = setOf("access", "expect-refusal", "hold-canary", "active", "sparse-deep", "bytes-full", "inodes-full", "quarantine", "admit-clean", "kill-owned")

    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size in setOf(5, 7)) { "expected closed probe arguments" }
        val (caseId, token, mode, scratchText, loopText) = arguments.toList()
        require(caseId.matches(Regex("K(?:0[1-9]|[12][0-9]|3[0-2])")))
        require(token.matches(Regex("[0-9a-f]{64}")))
        require(mode in MODES)
        require(arguments.size == if (mode == "kill-owned") 7 else 5)
        val scratch = Path.of(scratchText)
        require(scratchText.matches(Regex("/var/lib/decomp-oracle-ext4-reset-ci/public/g-[0-9a-f]{16}/scratch")))
        require(scratch == scratch.toAbsolutePath().normalize())
        require(loopText.matches(Regex("/dev/loop[0-9]{1,6}")))
        requireUnprivilegedPrincipal()
        val watchdog = Executors.newSingleThreadScheduledExecutor { task ->
            Thread(task, "ext4-reset-probe-deadline").apply { isDaemon = true }
        }
        watchdog.schedule({ Runtime.getRuntime().halt(124) }, 180, TimeUnit.SECONDS)
        try {
            execute(caseId, token, mode, scratch, Path.of(loopText), arguments.drop(5))
        } finally {
            watchdog.shutdownNow()
        }
    }

    private fun execute(caseId: String, token: String, mode: String, scratch: Path, loop: Path, target: List<String>) {
        fun emit(event: String, details: Map<String, JsonElement> = emptyMap()) {
            val report = buildJsonObject {
                put("schemaVersion", 1)
                put("caseId", caseId)
                put("sessionToken", token)
                put("mode", mode)
                put("event", event)
                put("pid", ProcessHandle.current().pid())
                put("startTicks", processStartTicks())
                put("uid", OWNER)
                put("gid", OWNER)
                put("scratch", scratch.toString())
                details.forEach { (key, value) -> put(key, value) }
            }.toString()
            require(report.toByteArray(Charsets.UTF_8).size <= 16 * 1024)
            println(report)
            System.out.flush()
        }

        if (mode == "kill-owned") {
            val pid = target[0].toLong().also { require(it in 2..Int.MAX_VALUE.toLong()) }
            val expectedStart = target[1].toLong().also { require(it > 0) }
            LinuxFilesystemSyscalls.openProcessHandle(pid).use { handle ->
                val stat = Files.readString(Path.of("/proc/$pid/stat"))
                require(stat.substring(stat.lastIndexOf(')') + 2).split(' ')[19].toLong() == expectedStart)
                val uid = Files.readString(Path.of("/proc/$pid/status")).lineSequence().single { it.startsWith("Uid:") }
                require(uid.substringAfter(':').trim().split(Regex("\\s+")).all { it.toInt() == OWNER })
                val command = Files.newInputStream(Path.of("/proc/$pid/cmdline")).use { it.readNBytes(64 * 1024 + 1) }
                require(command.size in 1..(64 * 1024))
                val arguments = command.toString(Charsets.UTF_8).split('\u0000').filter(String::isNotEmpty)
                require(arguments.size >= 6 && arguments[arguments.size - 6] == FullTreeDiskScratchResetProbe::class.java.name)
                val admitted = arguments.takeLast(5)
                require(admitted[0] == caseId && admitted[1] == token && admitted[2] in setOf("hold-canary", "active", "sparse-deep", "bytes-full", "inodes-full", "quarantine"))
                require(admitted[3] == scratch.toString() && admitted[4] == loop.toString())
                require(LinuxFilesystemSyscalls.killProcess(handle)) { "owned probe exited before SIGKILL" }
            }
            emit("signal-sent", mapOf("targetPid" to JsonPrimitive(pid), "targetStartTicks" to JsonPrimitive(expectedStart), "signal" to JsonPrimitive(9)))
            return
        }

        if (mode == "access") {
            val results = mutableListOf<JsonElement>()
            fun denied(subject: String, access: String, action: () -> Unit) {
                requireDenied(action)
                results += buildJsonObject {
                    put("object", subject)
                    put("access", access)
                    put("result", "AccessDeniedException")
                }
            }
            denied("private", "list") { Files.newDirectoryStream(ROOT.resolve("private")).use { it.iterator().hasNext() } }
            require(!Files.isSymbolicLink(loop))
            require(((Files.getAttribute(loop, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt() and 0xf000) == 0x6000)
            val rdev = (Files.getAttribute(loop, "unix:rdev", LinkOption.NOFOLLOW_LINKS) as Number).toLong()
            for ((subject, path) in listOf("image" to ROOT.resolve("private/image"), "state" to ROOT.resolve("private/state.json"), "loop" to loop)) {
                denied(subject, "read") { FileChannel.open(path, StandardOpenOption.READ).use { } }
                denied(subject, "write") { FileChannel.open(path, StandardOpenOption.WRITE).use { } }
            }
            emit("access-denied", mapOf("deniedObjects" to JsonPrimitive(7), "accessResults" to JsonArray(results), "rawDeviceRdev" to JsonPrimitive(rdev), "effectiveCapabilities" to JsonPrimitive("0"), "noNewPrivileges" to JsonPrimitive(true)))
            return
        }

        val operation = FullTreeDiskScratchOperation(
            operationId = sha256("$caseId:$token:$mode".toByteArray()),
            requestSha256 = "2".repeat(64),
            shardId = "clang-lib-driver",
            scopeSha256 = "3".repeat(64),
        )
        val policy = FullTreeDiskScratchPolicy(1, MAXIMUM_BYTES, 4, MAXIMUM_INODES)
        if (mode == "expect-refusal") {
            val failure = runCatching {
                FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(scratch, operation, policy).requireCleanAndRelease()
            }.exceptionOrNull()
            require(failure is FullTreeDiskScratchException && failure.message.orEmpty().contains("already leased")) {
                "second independent acquisition did not refuse the actual held mount lock: $failure"
            }
            emit("acquisition-refused", mapOf("reason" to JsonPrimitive("already-leased")))
            return
        }

        val lease = FullTreeDiskScratchAuthority.acquireDedicatedFilesystem(scratch, operation, policy)
        val evidence = Json.parseToJsonElement(lease.evidence.canonicalBytes().toString(Charsets.UTF_8))
        val common = mutableMapOf<String, JsonElement>("leaseEvidence" to evidence)
        if (mode == "admit-clean") {
            lease.requireCurrent(FullTreeDiskScratchStage.AUTHORIZED)
            lease.requireCleanAndRelease()
            emit("admitted-clean", common)
            return
        }
        if (mode == "quarantine") {
            lease.requireCleanAndRelease(FullTreeDiskScratchQuarantineFaultInjector { point ->
                if (point == FullTreeDiskScratchQuarantineFaultPoint.RELEASE_AFTER_QUARANTINE_PARENT_SYNC) {
                    val quarantine = scratch.resolve(leaseReleaseQuarantineDirectoryName(operation.operationId))
                    val record = quarantine.resolve("lease.json")
                    require(Files.isRegularFile(record, LinkOption.NOFOLLOW_LINKS))
                    common["quarantineName"] = JsonPrimitive(quarantine.fileName.toString())
                    common["recordSha256"] = JsonPrimitive(sha256(Files.readAllBytes(record)))
                    common["barrier"] = JsonPrimitive("release-after-quarantine-parent-sync")
                    emit("ready", common)
                    error("quarantine probe requires controller SIGKILL, received ${readCommand()}")
                }
            })
            error("quarantine cutpoint was not reached")
        }

        val runToken = lease.createEmptyOperationRunRoot()
        val run = lease.scratchParent.resolve(runDirectoryName(operation.operationId))
        val rootIdentity = Files.readAttributes(run, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS)
        val canary = run.resolve("reset-probe-canary")
        val canaryBytes = "reset-probe:$caseId:$token\n".toByteArray()
        Files.write(canary, canaryBytes, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE)
        val canaryIdentity = Files.readAttributes(canary, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS)
        common["canarySha256"] = JsonPrimitive(sha256(canaryBytes))
        common["runRootInode"] = JsonPrimitive((rootIdentity.getValue("ino") as Number).toLong())
        when (mode) {
            "sparse-deep" -> {
                FileChannel.open(run.resolve("sparse"), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
                    channel.position(SPARSE_BYTES - 1)
                    require(channel.write(ByteBuffer.wrap(byteArrayOf(1))) == 1)
                    channel.force(true)
                }
                require(Files.size(run.resolve("sparse")) == SPARSE_BYTES)
                var deepest = run
                repeat(DEPTH) { deepest = Files.createDirectory(deepest.resolve("d")) }
                common["sparseLogicalBytes"] = JsonPrimitive(SPARSE_BYTES)
                common["directoryDepth"] = JsonPrimitive(DEPTH)
            }
            "bytes-full" -> {
                var transferred = 0L
                var exhausted = false
                FileChannel.open(run.resolve("bytes"), StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use { channel ->
                    val buffer = ByteBuffer.allocate(64 * 1024)
                    try {
                        while (transferred <= MAXIMUM_BYTES) {
                            buffer.clear()
                            while (buffer.hasRemaining()) {
                                val written = channel.write(buffer)
                                require(written > 0)
                                transferred += written
                            }
                        }
                    } catch (failure: IOException) {
                        require(failure.message.orEmpty().contains("No space left on device")) { "not byte exhaustion: $failure" }
                        exhausted = true
                    }
                }
                require(exhausted && transferred > 0 && transferred <= MAXIMUM_BYTES)
                common["writtenBytes"] = JsonPrimitive(transferred)
            }
            "inodes-full" -> {
                var created = 0
                var exhausted = false
                try {
                    while (created <= MAXIMUM_INODES) {
                        Files.createFile(run.resolve("inode-$created"))
                        created++
                    }
                } catch (failure: IOException) {
                    require(failure.message.orEmpty().contains("No space left on device")) { "not inode exhaustion: $failure" }
                    exhausted = true
                }
                require(exhausted && created in 1..MAXIMUM_INODES.toInt())
                common["createdFiles"] = JsonPrimitive(created)
            }
            "hold-canary", "active" -> Unit
            else -> error("unexpected acquired mode")
        }
        val capacity = LinuxFilesystemSyscalls.openRoot(scratch).use(LinuxFilesystemSyscalls::filesystemCapacity)
        common["availableBytes"] = JsonPrimitive(capacity.availableBytes)
        common["availableInodes"] = JsonPrimitive(capacity.availableInodes)
        if (mode == "bytes-full") require(capacity.availableBytes == 0L)
        if (mode == "inodes-full") require(capacity.availableInodes == 0L)
        lease.requireCurrentOperationRunRoot(runToken, FullTreeDiskScratchStage.BEFORE_LAUNCH)
        emit("ready", common)
        try {
            while (true) {
                when (readCommand()) {
                    "CHECK" -> {
                        lease.requireCurrentOperationRunRoot(runToken, FullTreeDiskScratchStage.BEFORE_LAUNCH)
                        require(Files.readAttributes(canary, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS) == canaryIdentity)
                        require(Files.readAllBytes(canary).contentEquals(canaryBytes))
                        emit("checked", common)
                    }
                    "CLEAN" -> {
                        require(mode == "hold-canary") { "dirty crash residue may only be disposed by provisioner" }
                        lease.requireCurrentOperationRunRoot(runToken, FullTreeDiskScratchStage.BEFORE_LAUNCH)
                        require(Files.readAttributes(canary, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS) == canaryIdentity)
                        require(Files.readAllBytes(canary).contentEquals(canaryBytes))
                        require(Files.list(run).use { paths -> paths.map { it.fileName.toString() }.toList() } == listOf("reset-probe-canary"))
                        Files.delete(canary)
                        require(Files.readAttributes(run, "unix:dev,ino", LinkOption.NOFOLLOW_LINKS) == rootIdentity)
                        Files.delete(run)
                        lease.requireCleanAndRelease()
                        emit("clean-released", common)
                        return
                    }
                    else -> error("closed probe command refused")
                }
            }
        } finally {
            lease.close()
        }
    }

    private fun requireUnprivilegedPrincipal() {
        val status = Files.readString(Path.of("/proc/self/status"))
        fun field(name: String) = status.lineSequence().single { it.startsWith("$name:") }.substringAfter(':').trim()
        require(field("Uid").split(Regex("\\s+")).all { it.toInt() == OWNER })
        require(field("Gid").split(Regex("\\s+")).all { it.toInt() == OWNER })
        require(field("Groups").isEmpty())
        require(field("CapEff").toULong(16) == 0uL)
        require(field("CapBnd").toULong(16) == 0uL)
        require(field("NoNewPrivs") == "1")
    }

    private fun requireDenied(action: () -> Unit) {
        val failure = runCatching(action).exceptionOrNull()
        require(failure is AccessDeniedException) { "expected actual access refusal, observed $failure" }
    }

    private fun processStartTicks(): Long {
        val stat = Files.readString(Path.of("/proc/self/stat"))
        return stat.substring(stat.lastIndexOf(')') + 2).split(' ')[19].toLong()
    }

    private fun readCommand(): String {
        val bytes = ArrayList<Byte>()
        while (bytes.size <= 16) {
            val next = System.`in`.read()
            check(next >= 0) { "controller pipe closed" }
            if (next == '\n'.code) return bytes.toByteArray().toString(Charsets.US_ASCII)
            require(next in 32..126)
            bytes.add(next.toByte())
        }
        error("probe command exceeds bound")
    }

    private fun sha256(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
}
