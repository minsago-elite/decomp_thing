package decompengine.acp

import java.io.ByteArrayOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.NetworkInterface
import java.net.SocketTimeoutException
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardCopyOption.ATOMIC_MOVE
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.util.Base64
import java.util.Properties
import java.util.UUID
import java.util.concurrent.FutureTask
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.jar.JarEntry
import java.util.jar.JarFile
import java.util.jar.JarOutputStream
import kotlin.system.exitProcess
import kotlin.test.Test
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Assumptions.assumeTrue

/** Actual libc/system DNS in a fresh, private network namespace; no resolver SPI or provider call. */
@Tag("ci-live")
class AcpProviderNativeDnsContractTest {
    @Test
    fun `native stalled lookup cancellation kills and reaps the resolver child`() = nativeDnsCase("cancel")

    @Test
    fun `native stalled lookup deadline kills and reaps the resolver child`() = nativeDnsCase("deadline")
}

private const val NATIVE_RESOURCE = "/acp-provider-dns-native/"
private const val DNS_RESOURCE = "/acp-provider-dns/worker.sha256"
private const val OUTER_CAPABILITIES = 0x1400L // CAP_NET_BIND_SERVICE | CAP_NET_ADMIN
private const val QUERY_MARKER = "NATIVE_DNS_QUERY_V1\n"
private const val INNER_MARKER = "NATIVE_DNS_INNER_V1\n"
private const val OUTER_MARKER = "NATIVE_DNS_OUTER_V1\n"
private const val MAXIMUM_CONTROL_OUTPUT = 256
private const val MAXIMUM_CONTROL_FILE = 16 * 1024
private val nativePermissions = PosixFilePermissions.fromString("rwx------")

private fun nativeRequired(): Boolean = System.getenv("DECOMP_REQUIRE_LIVE_ACP_CONTRACT") == "1" ||
    System.getenv("DECOMP_REQUIRE_NATIVE_PROVIDER_DNS") == "1"

private fun nativeDnsCase(caseName: String) {
    val required = nativeRequired()
    val bwrap = Path.of("/usr/bin/bwrap")
    val java = Path.of(System.getProperty("java.home"), "bin/java").toRealPath()
    val helperSetting = System.getProperty("decompengine.acp.providerDns.loopbackHelper")
    val referenceSetting = System.getProperty("decompengine.acp.providerDns.loopbackReference")
    nativeRequireCapability(
        System.getProperty("os.name") == "Linux" && Runtime.version().feature() == 21 &&
            Files.isExecutable(bwrap) && helperSetting != null && referenceSetting != null,
        { "native provider DNS requires Linux, JDK21, authenticated bubblewrap and the built loopback fixture" }, required,
    )
    val helper = Path.of(checkNotNull(helperSetting)).toRealPath()
    val reference = Path.of(checkNotNull(referenceSetting)).toRealPath()
    val worker = Path.of(checkNotNull(System.getProperty("decompengine.acp.providerDns.workerJar"))).toRealPath()
    val expectedWorker = nativeResource(DNS_RESOURCE).toString(Charsets.US_ASCII).also {
        check(it.matches(Regex("[0-9a-f]{64}\n")))
    }.trimEnd('\n')
    authenticateNativeWorker(worker, expectedWorker)
    val source = nativeResource(NATIVE_RESOURCE + "provider_dns_loopback_fixture.c")
    val testSource = nativeResource(NATIVE_RESOURCE + "AcpProviderNativeDnsContractTest.kt")
    val referenceBytes = nativeRead(reference, MAXIMUM_CONTROL_FILE)
    val referenceCommitment = nativeResource(NATIVE_RESOURCE + "loopback-reference.sha256")
        .toString(Charsets.US_ASCII).also { check(it.matches(Regex("[0-9a-f]{64}\n"))) }.trimEnd('\n')
    check(nativeSha(referenceBytes) == referenceCommitment)
    val metadata = nativeProperties(referenceBytes)
    check(metadata.getProperty("schema") == "1")
    check(metadata.getProperty("sourceSha256") == nativeSha(source))
    val helperBytes = nativeRead(helper, 1024 * 1024)
    check(helperBytes.size >= 64 && helperBytes.copyOfRange(0, 4).contentEquals(byteArrayOf(127, 69, 76, 70)))
    check(nativeSha(helperBytes) == metadata.getProperty("helperSha256"))
    check(Files.isExecutable(helper))
    val envExecutable = Path.of("/usr/bin/env").toRealPath()
    val envBytes = nativeRead(envExecutable, 1024 * 1024)
    check(Files.isExecutable(envExecutable) && Files.getPosixFilePermissions(envExecutable) == PosixFilePermissions.fromString("rwxr-xr-x"))
    listOf("compiler", "linker").forEach { tool ->
        val path = Path.of(metadata.getProperty("${tool}Path")).toRealPath()
        check(nativeShaFile(path) == metadata.getProperty("${tool}Sha256"))
    }
    val compileArgv = Base64.getDecoder().decode(metadata.getProperty("compileArgvBase64"))
    check(nativeSha(compileArgv) == metadata.getProperty("compileArgvSha256"))
    val argv = compileArgv.toString(Charsets.UTF_8).split('\u0000')
    check(argv.size == 11 && argv[0] == Path.of("/usr/bin/cc").toRealPath().toString())
    check(argv.subList(1, 8) == listOf("-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-fno-ident", "-Wl,--build-id=none"))
    check(argv[9] == "-o" && Path.of(argv[8]).fileName.toString() == "provider_dns_loopback_fixture.c")
    val suppliedRun = System.getenv("DECOMP_ACP_CONTRACT_RUN_ID")
    check(!required || suppliedRun != null) { "required native DNS contract has no fresh run identifier" }
    val runId = suppliedRun ?: UUID.randomUUID().toString()
    check(runId.matches(Regex("[A-Za-z0-9-]{1,80}")))
    val root = Path.of(System.getProperty("user.dir"), "build/provider-dns-native-qualification").toAbsolutePath().normalize()
    Files.createDirectories(root)
    Files.setPosixFilePermissions(root, nativePermissions)
    val receipt = root.resolve("$caseName.json")
    val tree = root.resolve("$caseName-$runId")
    val retained = root.resolve("$caseName-$runId-closure")
    check(!Files.exists(receipt, NOFOLLOW_LINKS) && !Files.exists(tree, NOFOLLOW_LINKS) &&
        !Files.exists(retained, NOFOLLOW_LINKS)) {
        "native DNS output already exists; a fresh run must refuse stale evidence"
    }
    Files.createDirectory(tree, PosixFilePermissions.asFileAttribute(nativePermissions))
    val input = Files.createDirectory(tree.resolve("input"), PosixFilePermissions.asFileAttribute(nativePermissions))
    val output = Files.createDirectory(tree.resolve("output"), PosixFilePermissions.asFileAttribute(nativePermissions))
    val parentNet = nativeNamespace("net")
    val parentUser = nativeNamespace("user")
    val parentLoopback = nativeHostLoopbackFlags()
    val endMillis = System.currentTimeMillis() + 30_000
    val facts = linkedMapOf<String, Any>(
        "schemaVersion" to 1, "caseName" to caseName, "runId" to runId,
        "testSourceSha256" to nativeSha(testSource), "helperSourceSha256" to nativeSha(source),
        "workerJarSha256" to expectedWorker, "javaExecutableSha256" to nativeShaFile(java),
        "jdkReleaseSha256" to nativeShaFile(java.parent.parent.resolve("release")),
        "jdkModulesSha256" to nativeShaFile(java.parent.parent.resolve("lib/modules")),
        "bwrapSha256" to nativeShaFile(bwrap.toRealPath()), "loopbackHelperSha256" to nativeSha(helperBytes),
        "envExecutableSha256" to nativeSha(envBytes),
        "loopbackReferenceSha256" to referenceCommitment,
        "compilerSha256" to metadata.getProperty("compilerSha256"),
        "linkerSha256" to metadata.getProperty("linkerSha256"),
        "compileArgvSha256" to metadata.getProperty("compileArgvSha256"),
    )
    var process: Process? = null
    var outerNamespace: Pair<NativeNamespace, NativeNamespace>? = null
    var verified = false
    var primaryFailure: Throwable? = null
    var cleanupFailure: Throwable? = null
    var childOutcome = "NOT_STARTED"
    nativeVisibilitySink = root.resolve("$caseName-$runId-visibility.properties")
    nativeVisibilityAccumulator.reset()
    val observerLease = nativeObserverBudgetOwner.acquire(NativeObserverBudget(endMillis))
    try {
        Files.createDirectory(input.resolve("jdk"))
        val control = snapshotNativeControl(input)
        facts["controlRuntimeClosureSha256"] = nativeOrderedDigest(control.map { it.fileName.toString() + ":" + nativeShaFile(it) })
        Files.write(input.resolve("worker.jar"), nativeRead(worker, 65536), CREATE_NEW)
        Files.setPosixFilePermissions(input.resolve("worker.jar"), PosixFilePermissions.fromString("rw-r--r--"))
        Files.write(input.resolve("loopback-helper"), helperBytes, CREATE_NEW)
        Files.setPosixFilePermissions(input.resolve("loopback-helper"), PosixFilePermissions.fromString("r-xr-xr-x"))
        Files.write(input.resolve("empty-env"), envBytes, CREATE_NEW)
        Files.setPosixFilePermissions(input.resolve("empty-env"), PosixFilePermissions.fromString("r-xr-xr-x"))
        Files.writeString(input.resolve("hosts"), "127.0.0.1 localhost\n::1 localhost\n", CREATE_NEW)
        Files.writeString(input.resolve("nsswitch.conf"), "hosts: files dns\n", CREATE_NEW)
        Files.writeString(input.resolve("resolv.conf"), "nameserver 127.0.0.1\noptions timeout:30 attempts:1\n", CREATE_NEW)
        val command = nativeBwrapBase(bwrap, java.parent.parent, input, output, outer = true) +
            nativeJavaCommand(java, control, output) + listOf(
                "decompengine.acp.AcpProviderNativeDnsControl", "outer", caseName, endMillis.toString(),
                parentNet.device.toString(), parentNet.inode.toString(), parentUser.device.toString(), parentUser.inode.toString(),
            )
        // Probe only namespace availability. Once admitted, every fixture/cleanup assertion is mandatory.
        val probe = ProcessBuilder(nativeBwrapBase(bwrap, java.parent.parent, input, output, outer = true) +
            listOf("/fixture-input/empty-env", "-i", java.toString(), "-XX:-UsePerfData", "-version")).directory(output.toFile()).apply {
                environment().clear(); redirectErrorStream(true)
            }.start()
        val probeResult = nativeWait(probe, endMillis)
        nativeRequireCapability(probeResult.first == 0, { "native DNS user/network namespace setup is unavailable" }, required)
        process = ProcessBuilder(command).directory(output.toFile()).apply { environment().clear(); redirectErrorStream(true) }.start()
        childOutcome = "WAIT_INCOMPLETE"
        val result = nativeWait(process, endMillis, observe = { code, bytes -> childOutcome = nativeFixedChildOutcome(code, bytes) })
        output.resolve("namespace.properties").takeIf { Files.isRegularFile(it, NOFOLLOW_LINKS) }?.let {
            val p = nativeProperties(nativeRead(it, MAXIMUM_CONTROL_FILE))
            outerNamespace = NativeNamespace(p.getProperty("netDev").toLong(), p.getProperty("netIno").toLong()) to
                NativeNamespace(p.getProperty("userDev").toLong(), p.getProperty("userIno").toLong())
        }
        check(result.first == 0 && result.second.contentEquals(OUTER_MARKER.toByteArray(Charsets.US_ASCII))) {
            "native DNS fixture did not produce its fixed success record" + result.second.toString(Charsets.US_ASCII)
                .takeIf { it.matches(Regex("NATIVE_DNS_CONTROL_FAILED_[A-Z_]+\n")) }.orEmpty()
        }
        check(outerNamespace != null)
        val proof = nativeProperties(nativeRead(output.resolve("proof.properties"), MAXIMUM_CONTROL_FILE))
        listOf("realQueryObserved", "nativeBuiltinWorker", "childReaped", "ownerJoined", "streamsClosed",
            "noAddressAdmitted", "noConnectAdmitted", "noActiveDescendants", "blackholeJoined", "workerCapabilitiesZero").forEach {
            check(proof.getProperty(it) == "true") { "native DNS proof is incomplete" }
            facts[it] = true
        }
        listOf("innerBoundingMask", "workerBoundingMask").forEach {
            check(proof.getProperty(it) == "1400"); facts[it] = "1400"
        }
        listOf("innerNoNewPrivileges", "workerNoNewPrivileges").forEach {
            check(proof.getProperty(it) == "true"); facts[it] = true
        }
        check(proof.getProperty("caseName") == caseName && proof.getProperty("workerJarSha256") == expectedWorker)
        facts["queryCount"] = proof.getProperty("queryCount").toInt().also { check(it in 1..64) }
        facts["queryType"] = proof.getProperty("queryType").toInt().also { check(it == 1 || it == 28) }
        facts["childPid"] = proof.getProperty("childPid").toLong().also {
            check(!ProcessHandle.of(it).map(ProcessHandle::isAlive).orElse(false) && !Files.exists(Path.of("/proc", "$it")))
        }
        check(nativeShaFile(java) == facts["javaExecutableSha256"] && nativeShaFile(bwrap.toRealPath()) == facts["bwrapSha256"])
        check(nativeShaFile(envExecutable) == facts["envExecutableSha256"])
        check(nativeOrderedDigest(control.map { it.fileName.toString() + ":" + nativeShaFile(it) }) == facts["controlRuntimeClosureSha256"])
        Files.createDirectory(retained, PosixFilePermissions.asFileAttribute(nativePermissions))
        control.forEach { artifact ->
            val limit = if (artifact.fileName.toString() == "control.jar") 16 * 1024 * 1024 else 8 * 1024 * 1024
            Files.write(retained.resolve(artifact.fileName), nativeRead(artifact, limit), CREATE_NEW)
        }
        check(nativeOrderedDigest(control.map { artifact ->
            artifact.fileName.toString() + ":" + nativeShaFile(retained.resolve(artifact.fileName))
        }) == facts["controlRuntimeClosureSha256"])
        verified = true
    } catch (failure: Throwable) {
        primaryFailure = failure
        throw failure
    } finally {
        try {
        var rootReaped = false
        try { process?.let { nativeStop(it, endMillis) }; rootReaped = true }
        finally {
            try {
                if (outerNamespace == null && Files.isRegularFile(output.resolve("namespace.properties"), NOFOLLOW_LINKS)) {
                    val p = nativeProperties(nativeRead(output.resolve("namespace.properties"), MAXIMUM_CONTROL_FILE))
                    outerNamespace = NativeNamespace(p.getProperty("netDev").toLong(), p.getProperty("netIno").toLong()) to
                        NativeNamespace(p.getProperty("userDev").toLong(), p.getProperty("userIno").toLong())
                }
                outerNamespace?.let { (net, user) ->
                    check(net != parentNet && user != parentUser)
                    val retained = nativeNamespaceMembers(net, "net", "HOST_CLEANUP") + nativeNamespaceMembers(user, "user", "HOST_CLEANUP")
                    retained.forEach { pid -> ProcessHandle.of(pid).ifPresent { it.destroyForcibly() } }
                    nativeAwait(endMillis) { nativeNamespaceMembers(net, "net", "HOST_CLEANUP").isEmpty() && nativeNamespaceMembers(user, "user", "HOST_CLEANUP").isEmpty() }
                    check(!nativeRetainsNamespace(net, "net") && !nativeRetainsNamespace(user, "user"))
                }
            } finally {
                check(nativeNamespace("net") == parentNet && nativeNamespace("user") == parentUser)
                check(nativeHostLoopbackFlags() == parentLoopback)
            }
            check(rootReaped)
            if (verified) {
                nativeRemoveTree(tree)
                check(!Files.exists(tree, NOFOLLOW_LINKS))
                facts["privateTreeRemoved"] = true
                facts["namespaceDestroyed"] = true
                facts["noSurvivingChildMembership"] = true
                facts["hostNamespacesUnchanged"] = true
                facts["hostLoopbackUnchanged"] = true
                nativeWriteReceipt(receipt, facts)
            }
        }
        } catch (failure: Throwable) {
            cleanupFailure = failure
            nativeKeepPrimaryFailure(primaryFailure, failure)
        } finally {
            if (primaryFailure != null || cleanupFailure != null) {
                val text = "case=$caseName\nrunId=$runId\nchildOutcome=$childOutcome\n" +
                    "primaryFailure=${nativeFailureCategory(primaryFailure)}\ncleanupFailure=${nativeFailureCategory(cleanupFailure)}\n" +
                    nativeObserverFailureFields(primaryFailure, "primary") + nativeObserverFailureFields(cleanupFailure, "cleanup") +
                    "testSourceSha256=${facts["testSourceSha256"]}\nhelperSourceSha256=${facts["helperSourceSha256"]}\nworkerJarSha256=$expectedWorker\n"
                try { Files.writeString(root.resolve("$caseName-$runId-failure.properties"), text, CREATE_NEW) }
                catch (diagnostic: Throwable) { (primaryFailure ?: cleanupFailure)?.addSuppressed(diagnostic) }
            }
            nativeVisibilitySink = null
            try { observerLease.close() }
            catch (failure: Throwable) { nativeKeepPrimaryFailure(primaryFailure ?: cleanupFailure, failure) }
        }
    }
}

/** Separate outer/inner JVMs prevent setup capabilities from reaching the actual DNS owner. */
object AcpProviderNativeDnsControl {
    private var stage = "STARTUP"
    @JvmStatic
    fun main(args: Array<String>) {
        var observerLease: AutoCloseable? = null
        var failed = false
        try {
            nativeVisibilitySink = Path.of("/fixture-output/native-visibility.properties")
            check(args.size >= 3)
            observerLease = nativeObserverBudgetOwner.acquire(NativeObserverBudget(args[2].toLong()))
            when (args[0]) {
                "outer" -> runOuter(args)
                "inner" -> runInner(args)
                else -> error("fixed control mode required")
            }
        } catch (failure: Throwable) {
            // Fixed bounded failure facts survive cleanup without exposing exceptions or packets.
            val role = args.firstOrNull().takeIf { it in setOf("outer", "inner") } ?: "control"
            val cleanup = failure.suppressed.take(6).joinToString(",") { nativeFailureCategory(it) }
            val text = "stage=$stage\nprimaryFailure=${nativeFailureCategory(failure)}\ncleanupFailures=$cleanup\n" + nativeObserverFailureFields(failure, "primary")
            try { Files.writeString(Path.of("/fixture-output/native-$role-failure.properties"), text, CREATE_NEW) }
            catch (diagnostic: Throwable) { failure.addSuppressed(diagnostic) }
            print("NATIVE_DNS_CONTROL_FAILED_$stage\n")
            failed = true
        } finally {
            nativeVisibilitySink = null
            observerLease?.close()
        }
        if (failed) exitProcess(1)
    }

    private fun runOuter(args: Array<String>) {
        check(args.size == 7 && args[1] in setOf("cancel", "deadline"))
        stage = "OUTER_ENVIRONMENT"
        check(System.getenv().isEmpty())
        val endMillis = args[2].toLong()
        nativeVisibilityAccumulator.reset()
        check(nativeCapabilities("CapEff") == OUTER_CAPABILITIES)
        stage = "OUTER_NAMESPACES"
        val output = Path.of("/fixture-output")
        val net = nativeNamespace("net")
        val user = nativeNamespace("user")
        nativeWriteProperties(output.resolve("namespace.properties"), mapOf(
            "netDev" to "${net.device}", "netIno" to "${net.inode}", "userDev" to "${user.device}", "userIno" to "${user.inode}",
        ))
        stage = "LOOPBACK_HELPER"
        val setup = ProcessBuilder(listOf("/fixture-input/loopback-helper") + args.drop(3))
            .directory(output.toFile()).apply { environment().clear(); redirectErrorStream(true) }.start()
        val setupResult = nativeWait(setup, endMillis, 48)
        check(setupResult.first == 0 && setupResult.second.size == 48)
        val frame = ByteBuffer.wrap(setupResult.second).order(ByteOrder.BIG_ENDIAN)
        check(ByteArray(8).also(frame::get).contentEquals("PDNSLO01".toByteArray(Charsets.US_ASCII)))
        check(NativeNamespace(frame.long, frame.long) == net && NativeNamespace(frame.long, frame.long) == user)
        val before = frame.int
        val after = frame.int
        check(before and 8 != 0 && after and 1 != 0 && after and 8 != 0)
        stage = "LOOPBACK_ROUTES"
        val interfaces = NetworkInterface.getNetworkInterfaces().toList()
        check(interfaces.size == 1 && interfaces.single().name == "lo" && interfaces.single().isUp && interfaces.single().isLoopback)
        listOf("/proc/net/route", "/proc/net/ipv6_route").forEach { route ->
            Files.readAllLines(Path.of(route)).drop(if (route.endsWith("/route")) 1 else 0).filter(String::isNotBlank).forEach {
                val fields = it.trim().split(Regex("\\s+"))
                check((if (route.endsWith("/route")) fields.first() else fields.last()) == "lo")
            }
        }
        val failed = AtomicBoolean()
        val stop = AtomicBoolean()
        val count = AtomicInteger()
        val type = AtomicInteger()
        val socket = DatagramSocket(null)
        var inner: Process? = null
        var blackhole: Thread? = null
        var primary: Throwable? = null
        try {
            stage = "BLACKHOLE_BIND"
            socket.reuseAddress = false
            socket.bind(java.net.InetSocketAddress(InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1)), 53))
            socket.soTimeout = 100
            blackhole = Thread({
                try {
                    while (!stop.get()) {
                        val packet = DatagramPacket(ByteArray(513), 513)
                        try { socket.receive(packet) } catch (_: SocketTimeoutException) { continue }
                        check(packet.address.address.contentEquals(byteArrayOf(127, 0, 0, 1)))
                        val qtype = nativeDnsQuestion(packet.data.copyOf(packet.length))
                        check(count.incrementAndGet() <= 64)
                        if (type.compareAndSet(0, qtype)) Files.writeString(output.resolve("query-observed"), QUERY_MARKER, CREATE_NEW)
                    }
                } catch (_: Throwable) { if (!stop.get()) failed.set(true) }
            }, "native-dns-blackhole").also { it.start() }
            val command = listOf("/fixture-input/loopback-helper", "bootstrap", args[1], endMillis.toString())
            inner = ProcessBuilder(command).directory(output.toFile()).apply { environment().clear(); redirectErrorStream(true) }.start()
            stage = "INNER_CONTROL"
            val result = nativeWait(inner, endMillis)
            val diagnostic = result.second.toString(Charsets.US_ASCII)
            diagnostic.takeIf { it.matches(Regex("NATIVE_DNS_CONTROL_FAILED_[A-Z_]+\n")) }
                ?.let { stage = it.removePrefix("NATIVE_DNS_CONTROL_FAILED_").trimEnd('\n') }
            if (result.first != 0 && stage == "INNER_CONTROL") stage = when {
                "uid map" in diagnostic -> "INNER_UID_MAP"
                "proc" in diagnostic -> "INNER_PROC_SETUP"
                "Operation not permitted" in diagnostic -> "INNER_PERMISSION"
                "No such file" in diagnostic -> "INNER_RUNTIME_MISSING"
                else -> "INNER_FIXED_LAUNCH_FAILURE"
            }
            check(result.first == 0 && result.second.contentEquals(INNER_MARKER.toByteArray(Charsets.US_ASCII)))
            stage = "OUTER_QUERY_STATE"
            check(!failed.get() && count.get() in 1..64)
            stage = "OUTER_INNER_PROOF_READ"
            val proof = nativeProperties(nativeRead(output.resolve("inner.properties"), MAXIMUM_CONTROL_FILE))
            proof.setProperty("queryCount", count.get().toString())
            proof.setProperty("queryType", type.get().toString())
            // The blackhole is closed/joined before the final proof becomes visible.
            stop.set(true)
            socket.close()
            stage = "OUTER_BLACKHOLE_JOIN"
            nativeJoin(blackhole, endMillis)
            proof.setProperty("blackholeJoined", "true")
            stage = "OUTER_NAMESPACE_SCAN"
            val members = nativeNamespaceMembers(net, "net", "OUTER_CLEANUP")
            stage = "OUTER_NAMESPACE_MEMBERSHIP"
            check(members.all { it == ProcessHandle.current().pid() })
            proof.setProperty("noActiveDescendants", "true")
            stage = "OUTER_PROOF_WRITE"
            nativeWriteProperties(output.resolve("proof.properties"), proof.stringPropertyNames().associateWith(proof::getProperty))
            print(OUTER_MARKER)
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            try {
                try {
                    stop.set(true)
                    socket.close()
                    blackhole?.let { nativeJoin(it, endMillis) }
                } finally { inner?.let { nativeStop(it, endMillis) } }
            } catch (cleanup: Throwable) { nativeKeepPrimaryFailure(primary, cleanup) }
        }
    }

    private fun runInner(args: Array<String>) {
        check(args.size == 3 && args[1] in setOf("cancel", "deadline"))
        stage = "INNER_CAPABILITIES"
        check(System.getenv().isEmpty())
        listOf("CapEff", "CapPrm", "CapInh", "CapAmb").forEach { check(nativeCapabilities(it) == 0L) }
        check(nativeCapabilities("CapBnd") == OUTER_CAPABILITIES && nativeNoNewPrivileges())
        val endMillis = args[2].toLong()
        val output = Path.of("/fixture-output")
        val directory = Files.createDirectory(output.resolve("owner"), PosixFilePermissions.asFileAttribute(nativePermissions))
        val jar = directory.resolve("worker.jar")
        Files.copy(Path.of("/fixture-input/worker.jar"), jar)
        Files.setPosixFilePermissions(jar, PosixFilePermissions.fromString("rw-r--r--"))
        val digest = nativeResource(DNS_RESOURCE).toString(Charsets.US_ASCII).trimEnd('\n')
        authenticateNativeWorker(jar, digest)
        val artifactClass = Class.forName("decompengine.acp.ProviderDnsArtifact")
        val artifact = artifactClass.getDeclaredConstructor(Path::class.java, String::class.java, Path::class.java)
            .also { it.isAccessible = true }.newInstance(jar, digest, directory)
        val timeoutMillis = if (args[1] == "cancel") 8_000L else 3_000L
        val requestDeadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(minOf(timeoutMillis, nativeRemainingMillis(endMillis)))
        val owner = AcpProviderDnsProcess::class.java.getDeclaredConstructor(artifactClass, Long::class.javaPrimitiveType)
            .also { it.isAccessible = true }.newInstance(artifact, requestDeadline)
        var admitted = false
        var primary: Throwable? = null
        try {
            stage = "NATIVE_QUERY"
            owner.javaClass.getDeclaredMethod("start").also { it.isAccessible = true }.invoke(owner)
            nativeAwait(endMillis) {
                Files.isRegularFile(output.resolve("query-observed"), NOFOLLOW_LINKS) && owner.cleanupSnapshot().childPid != null
            }
            check(Files.readString(output.resolve("query-observed")) == QUERY_MARKER)
            val pid = checkNotNull(owner.cleanupSnapshot().childPid)
            check(ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false))
            listOf("CapEff", "CapPrm", "CapInh", "CapAmb").forEach { check(nativeCapabilities(it, pid) == 0L) }
            check(nativeCapabilities("CapBnd", pid) == OUTER_CAPABILITIES && nativeNoNewPrivileges(pid))
            if (args[1] == "cancel") owner.cancel()
            stage = "OWNER_TERMINATION"
            var failed = false
            try { owner.awaitAddress(); admitted = true } catch (failure: java.io.IOException) {
                check(failure.cause == null)
                if (args[1] == "deadline") check(failure is SocketTimeoutException)
                failed = true
            }
            check(failed && !admitted)
            check(owner.closeBefore(nativeCleanupDeadline(endMillis)))
            val state = owner.cleanupSnapshot()
            check(state.childReaped && state.ownerJoined && state.streamsClosed && !state.quarantined)
            val future = owner.javaClass.getDeclaredField("task").also { it.isAccessible = true }.get(owner) as FutureTask<*>
            check(future.isDone && !future.isCancelled)
            val child = owner.javaClass.getDeclaredField("process").also { it.isAccessible = true }.get(owner)
                as java.util.concurrent.atomic.AtomicReference<*>
            val process = child.get() as Process
            check(process.waitFor(nativeRemainingMillis(endMillis), TimeUnit.MILLISECONDS) && !process.isAlive)
            check(!ProcessHandle.of(pid).map(ProcessHandle::isAlive).orElse(false) && !Files.exists(Path.of("/proc", "$pid")))
            nativeRemoveTree(directory)
            check(!Files.exists(directory, NOFOLLOW_LINKS))
            nativeWriteProperties(output.resolve("inner.properties"), mapOf(
                "caseName" to args[1], "workerJarSha256" to digest, "childPid" to "$pid",
                "realQueryObserved" to "true", "nativeBuiltinWorker" to "true", "childReaped" to "true",
                "ownerJoined" to "true", "streamsClosed" to "true", "noAddressAdmitted" to "true",
                // This component control constructs no socket/connect or HTTP backend at all.
                "noConnectAdmitted" to "true", "workerCapabilitiesZero" to "true",
                "innerBoundingMask" to "1400", "workerBoundingMask" to "1400",
                "innerNoNewPrivileges" to "true", "workerNoNewPrivileges" to "true",
            ))
            print(INNER_MARKER)
        } catch (failure: Throwable) {
            primary = failure
            throw failure
        } finally {
            try { check(owner.closeBefore(nativeCleanupDeadline(endMillis))) }
            catch (cleanup: Throwable) { nativeKeepPrimaryFailure(primary, cleanup) }
        }
    }
}

private data class NativeNamespace(val device: Long, val inode: Long)

private fun nativeNamespace(kind: String, pid: String = "self"): NativeNamespace {
    val path = Path.of("/proc", pid, "ns", kind)
    return NativeNamespace((Files.getAttribute(path, "unix:dev") as Number).toLong(), (Files.getAttribute(path, "unix:ino") as Number).toLong())
}

internal data class NativeNamespaceCredentials(val uid: List<Long>, val gid: List<Long>)

internal fun parseNativeNamespaceCredentials(text: String, pid: Long): NativeNamespaceCredentials {
    check(text.length <= 65536 && pid > 0)
    val selected = linkedMapOf<String, String>()
    text.lineSequence().forEach { line ->
        val key = line.substringBefore(':')
        if (key in setOf("Pid", "Uid", "Gid")) check(selected.put(key, line.substringAfter(':').trim()) == null)
    }
    check(selected["Pid"] == pid.toString()) { "native observer PID identity is unavailable" }
    fun tuple(key: String): List<Long> {
        val parts = checkNotNull(selected[key]).split(Regex("\\s+"))
        check(parts.size == 4 && parts.all { it.matches(Regex("[0-9]{1,10}")) })
        return parts.map { it.toLong().also { id -> check(id in 0..4294967295L) } }
    }
    return NativeNamespaceCredentials(tuple("Uid"), tuple("Gid"))
}

internal fun nativeDeniedVisibilityRequiresFailure(caller: NativeNamespaceCredentials, target: NativeNamespaceCredentials?): Boolean =
    target == null || caller.uid.any { it in target.uid } || caller.gid.any { it in target.gid }

internal class NativeObserverFailure(val category: String, val observedPid: Long? = null,
    val namespaceKind: String? = null, val observerPhase: String? = null) : IllegalStateException(category) {
    init {
        require(category in setOf("OBSERVER_DEADLINE", "SCAN_WORK_LIMIT", "PROC_BYTE_LIMIT", "DIAGNOSTIC_CAPACITY", "POSSIBLE_OWNED_VISIBILITY"))
        require(observedPid == null || observedPid in 1..4294967295L)
        require(namespaceKind == null || namespaceKind in setOf("net", "user"))
        require(observerPhase == null || observerPhase in setOf("HOST_CLEANUP", "OUTER_CLEANUP"))
    }
}

/** Shared across polling scans; exhaustion refuses proof instead of returning partial membership. */
internal class NativeObserverBudget(val endMillis: Long, private val now: () -> Long = System::currentTimeMillis,
    private val maximumScans: Int = 128, private val maximumPidsPerScan: Int = 4096,
    private val maximumPids: Int = 16384, private val maximumWork: Int = 32768,
    private val maximumBytes: Int = 32 * 1024 * 1024) {
    private var scans = 0; private var scanPids = 0; private var pids = 0; private var work = 0; private var bytes = 0
    fun checkpoint() { if (now() >= endMillis) throw NativeObserverFailure("OBSERVER_DEADLINE") }
    fun beginScan() { checkpoint(); if (scans >= maximumScans) throw NativeObserverFailure("SCAN_WORK_LIMIT"); scans++; scanPids = 0 }
    fun operation() { checkpoint(); if (work >= maximumWork) throw NativeObserverFailure("SCAN_WORK_LIMIT"); work++ }
    fun pid() { checkpoint(); if (scanPids >= maximumPidsPerScan || pids >= maximumPids) throw NativeObserverFailure("SCAN_WORK_LIMIT"); scanPids++; pids++ }
    fun readLimit(): Int { operation(); if (bytes >= maximumBytes) throw NativeObserverFailure("PROC_BYTE_LIMIT"); return minOf(65536, maximumBytes - bytes) + 1 }
    fun readCompleted(count: Int) { checkpoint(); if (count < 0 || count > maximumBytes - bytes) throw NativeObserverFailure("PROC_BYTE_LIMIT"); bytes += count }
}

/** Fixed detail storage; overflow counts observations, never distinct identities or absence. */
internal class NativeVisibilityAccumulator(private val rows: MutableList<String> = mutableListOf()) {
    var overflowObservations = 0; private set
    private var digest = ByteArray(32)
    var scanComplete = false
    fun reset() { rows.clear(); overflowObservations = 0; digest = ByteArray(32); scanComplete = false }
    fun record(record: String, provenForeign: Boolean) {
        check(record.length <= 768 && record.all { it.code in 32..126 })
        if (record in rows) return
        if (rows.size < 16) rows += record
        else {
            if (!provenForeign) throw NativeObserverFailure("DIAGNOSTIC_CAPACITY")
            check(overflowObservations < 16384) { "native observer diagnostic count exhausted" }
            val bytes = record.toByteArray(Charsets.US_ASCII)
            digest = MessageDigest.getInstance("SHA-256").run {
                update(digest); update(ByteBuffer.allocate(4).putInt(bytes.size).array()); digest(bytes)
            }
            overflowObservations++
        }
    }
    fun render(): ByteArray {
        val summary = "retainedRowCount=${rows.size}\ndistinctCredentialOverflowObservations=$overflowObservations\n" +
            "observationDigest=${digest.joinToString("") { "%02x".format(it) }}\nscanComplete=$scanComplete\n"
        return (rows.joinToString("\n", postfix = if (rows.isEmpty()) "" else "\n") + summary)
            .toByteArray(Charsets.US_ASCII).also { check(it.size <= 16 * 1024) }
    }
}

internal fun nativeStableDeniedCredentials(before: Long?, after: Long?, target: NativeNamespaceCredentials?): NativeNamespaceCredentials? =
    target.takeIf { before != null && before >= 0 && before == after }

private var nativeVisibilitySink: Path? = null
private val nativeVisibilityRecords = mutableListOf<String>()
private val nativeVisibilityAccumulator = NativeVisibilityAccumulator(nativeVisibilityRecords)
/** Exact-owner scoped fixture state; closing a lease cannot extend or replace its absolute end. */
internal class NativeObserverBudgetOwner {
    var current: NativeObserverBudget? = null; private set
    fun acquire(budget: NativeObserverBudget): AutoCloseable {
        check(current == null) { "native observer budget already owned" }
        current = budget
        var closed = false
        return AutoCloseable {
            if (!closed) {
                check(current === budget) { "native observer budget owner changed" }
                current = null
                closed = true
            }
        }
    }
}
private val nativeObserverBudgetOwner = NativeObserverBudgetOwner()
private fun nativeProcText(path: Path, budget: NativeObserverBudget? = null): String {
    val limit = budget?.readLimit() ?: 65537
    return Files.newInputStream(path).use { input ->
        input.readNBytes(limit).also { budget?.readCompleted(it.size); check(it.size <= 65536) }.toString(Charsets.US_ASCII)
    }
}
private fun nativeCredentialIdentity(pid: Long, budget: NativeObserverBudget? = null): NativeNamespaceCredentials =
    parseNativeNamespaceCredentials(nativeProcText(Path.of("/proc", pid.toString(), "status"), budget), pid)
private fun nativeStartTime(pid: Long, budget: NativeObserverBudget? = null): Long {
    val value = nativeProcText(Path.of("/proc", pid.toString(), "stat"), budget)
    val afterName = value.lastIndexOf(')')
    check(afterName > 0 && value.substringBefore(' ') == pid.toString())
    return value.substring(afterName + 1).trim().split(Regex("\\s+"))[19].toLong().also { check(it >= 0) }
}
private fun nativeRecordDenied(pid: Long, kind: String, phase: String, caller: NativeNamespaceCredentials,
    target: NativeNamespaceCredentials?, startTime: Long?, outcome: String) {
    check(kind in setOf("net", "user") && phase in setOf("HOST_CLEANUP", "OUTER_CLEANUP"))
    nativeObserverBudgetOwner.current?.operation()
    val procOwner = runCatching { (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toLong() }.getOrNull()
    val record = "pid=$pid kind=$kind phase=$phase callerPid=${ProcessHandle.current().pid()} outcome=$outcome startTime=${startTime ?: "UNAVAILABLE"} " +
        "callerUid=${caller.uid.joinToString(",")} callerGid=${caller.gid.joinToString(",")} procSelfOwner=${procOwner ?: "UNAVAILABLE"} " +
        "targetUid=${target?.uid?.joinToString(",") ?: "UNAVAILABLE"} targetGid=${target?.gid?.joinToString(",") ?: "UNAVAILABLE"}"
    val foreign = outcome == "DISTINCT_CREDENTIALS" && startTime != null && target != null &&
        !nativeDeniedVisibilityRequiresFailure(caller, target)
    nativeVisibilityAccumulator.record(record, foreign)
    nativePersistVisibility()
}

private fun nativePersistVisibility() {
    val bytes = nativeVisibilityAccumulator.render()
    nativeVisibilitySink?.let {
        check(!Files.exists(it, NOFOLLOW_LINKS) || Files.isRegularFile(it, NOFOLLOW_LINKS))
        Files.newOutputStream(it, NOFOLLOW_LINKS, java.nio.file.StandardOpenOption.CREATE,
            java.nio.file.StandardOpenOption.TRUNCATE_EXISTING, java.nio.file.StandardOpenOption.WRITE).use { output -> output.write(bytes) }
    }
}

private fun nativeNamespaceMembers(namespace: NativeNamespace, kind: String, phase: String): Set<Long> {
    val budget = checkNotNull(nativeObserverBudgetOwner.current)
    nativeVisibilityAccumulator.scanComplete = false
    var primary: Throwable? = null
    try {
        budget.beginScan()
        val caller = nativeCredentialIdentity(ProcessHandle.current().pid(), budget)
        val members = linkedSetOf<Long>()
        budget.operation()
        Files.list(Path.of("/proc")).use { stream ->
            val iterator = stream.iterator()
            while (true) {
                budget.operation(); if (!iterator.hasNext()) break
                budget.operation(); val path = iterator.next()
                val name = path.fileName.toString()
                if (!name.matches(Regex("[0-9]{1,10}"))) continue
                budget.pid(); val pid = name.toLong()
                try {
                    budget.operation()
                    if (nativeNamespace(kind, name) == namespace) members += pid
                } catch (_: java.nio.file.NoSuchFileException) { /* exited before observation */ }
                catch (_: java.nio.file.AccessDeniedException) {
                    var target: NativeNamespaceCredentials? = null
                    var start: Long? = null
                    try {
                        start = nativeStartTime(pid, budget)
                        target = nativeCredentialIdentity(pid, budget)
                        target = nativeStableDeniedCredentials(start, nativeStartTime(pid, budget), target)
                    } catch (failure: NativeObserverFailure) { throw NativeObserverFailure(failure.category, pid, kind, phase) }
                    catch (_: Exception) { target = null }
                    val mustFail = nativeDeniedVisibilityRequiresFailure(caller, target)
                    if (mustFail) {
                        val primary = NativeObserverFailure("POSSIBLE_OWNED_VISIBILITY", pid, kind, phase)
                        try { nativeRecordDenied(pid, kind, phase, caller, target, start, "OBSERVER_UNAVAILABLE") }
                        catch (diagnostic: Throwable) { primary.addSuppressed(diagnostic) }
                        throw primary
                    }
                    nativeRecordDenied(pid, kind, phase, caller, target, start, "DISTINCT_CREDENTIALS")
                }
            }
        }
        nativeVisibilityAccumulator.scanComplete = true
        return members
    } catch (failure: Throwable) { primary = failure; throw failure }
    finally {
        try { nativePersistVisibility() }
        catch (diagnostic: Throwable) { nativeKeepPrimaryFailure(primary, diagnostic) }
    }
}

private fun nativeRetainsNamespace(namespace: NativeNamespace, kind: String): Boolean {
    val budget = checkNotNull(nativeObserverBudgetOwner.current)
    budget.beginScan(); budget.operation()
    return Files.list(Path.of("/proc/self/fd")).use { stream ->
        val iterator = stream.iterator()
        while (true) {
            budget.operation(); if (!iterator.hasNext()) break
            budget.operation(); val path = iterator.next(); budget.pid(); budget.operation()
            try { if (Files.readSymbolicLink(path).toString() == "$kind:[${namespace.inode}]") return@use true }
            catch (_: java.nio.file.NoSuchFileException) { /* descriptor closed during inventory */ }
        }
        false
    }
}

private fun nativeHostLoopbackFlags(): String = Files.readString(Path.of("/sys/class/net/lo/flags")).trim().also {
    check(it.matches(Regex("0x[0-9a-fA-F]{1,8}")))
}

private fun nativeCapabilities(field: String, pid: Long = ProcessHandle.current().pid()): Long {
    val value = Files.readAllLines(Path.of("/proc", "$pid", "status")).single { it.startsWith("$field:") }.substringAfter(':').trim()
    check(value.matches(Regex("[0-9a-fA-F]{16}")))
    return java.lang.Long.parseUnsignedLong(value, 16)
}

private fun nativeNoNewPrivileges(pid: Long? = null): Boolean =
    Files.readAllLines(Path.of("/proc", pid?.toString() ?: "self", "status"))
        .single { it.startsWith("NoNewPrivs:") }.substringAfter(':').trim() == "1"

private fun nativeBwrapBase(bwrap: Path, javaHome: Path, input: Path, output: Path, outer: Boolean): List<String> {
    val command = mutableListOf(bwrap.toString(), "--die-with-parent", "--new-session")
    command += listOf("--unshare-user", "--uid", "0", "--gid", "0")
    if (outer) command += "--unshare-net"
    command += listOf("--cap-drop", "ALL")
    if (outer) command += listOf("--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE")
    command += listOf("--clearenv", "--proc", "/proc", "--dev", "/dev", "--dir", "/etc", "--dir", "/tmp")
    // Fixed read-only loader/library directories contain no host home or credentials. Paths are
    // mounted canonically, with the host's verified FHS aliases recreated in the empty root.
    val runtimeRoots = listOf("/lib", "/lib64", "/usr/lib", "/usr/lib64").map(Path::of).filter(Files::isDirectory)
    runtimeRoots.map { it.toRealPath() }.distinct().sortedBy(Path::toString).forEach {
        command += listOf("--ro-bind", it.toString(), it.toString())
    }
    runtimeRoots.filter(Files::isSymbolicLink).forEach {
        command += listOf("--symlink", it.toRealPath().toString(), it.toString())
    }
    command += listOf("--ro-bind", javaHome.toString(), javaHome.toString(),
        "--ro-bind", "/usr/bin/bwrap", "/usr/bin/bwrap",
        "--ro-bind", input.toString(), "/fixture-input",
        // Fixture-only relocation preserves launcher-relative libjli/modules; production snapshots are unchanged.
        "--ro-bind", javaHome.toString(), "/fixture-input/jdk", "--bind", output.toString(), "/fixture-output",
        "--ro-bind", input.resolve("hosts").toString(), "/etc/hosts",
        "--ro-bind", input.resolve("nsswitch.conf").toString(), "/etc/nsswitch.conf",
        "--ro-bind", input.resolve("resolv.conf").toString(), "/etc/resolv.conf",
        "--chdir", "/fixture-output", "--")
    return command
}

private fun nativeJavaCommand(java: Path, classpath: List<Path>, output: Path): List<String> = listOf(
    "/fixture-input/empty-env", "-i", java.toString(), "-Xms16m", "-Xmx96m", "-Xint", "-XX:+UseSerialGC", "-XX:ActiveProcessorCount=1",
    "-XX:+DisableAttachMechanism", "-XX:-UsePerfData", "-XX:+ErrorFileToStderr", "-XX:-CreateCoredumpOnCrash",
    "-XX:-DumpReplayDataOnError", "-Djava.io.tmpdir=/fixture-output", "-Duser.home=/fixture-output", "-cp",
    classpath.joinToString(":") { "/fixture-input/${it.fileName}" },
).also { check(output.fileName.toString() in setOf("output", "fixture-output")) }

// Explicit runtime dependency roots; include every generated nested class of each root.
internal val nativeObserverCapsuleRoots = setOf("NativeObserverBudget", "NativeObserverBudgetOwner",
    "NativeVisibilityAccumulator", "NativeObserverFailure")
internal fun nativeObserverCapsuleClass(name: String): Boolean = name.endsWith(".class") &&
    nativeObserverCapsuleRoots.any { root -> name == "$root.class" || name.startsWith("$root$") }
internal fun nativeRequireObserverCapsuleInventory(entries: Set<String>) {
    check(entries.size <= 256) { "native control capsule inventory capacity" }
    check(nativeObserverCapsuleRoots.all { "decompengine/acp/$it.class" in entries }) {
        "native control capsule is missing an observer runtime dependency"
    }
}

private fun snapshotNativeControl(input: Path): List<Path> {
    val entries = sortedMapOf<String, ByteArray>()
    listOf(AcpProviderNativeDnsControl::class.java to "AcpProviderNativeDns", AcpProviderDnsProcess::class.java to "AcpProviderDns").forEach { (type, prefix) ->
        val root = Path.of(type.protectionDomain.codeSource.location.toURI()).toRealPath()
        check(Files.isDirectory(root))
        val packageRoot = root.resolve("decompengine/acp")
        Files.list(packageRoot).use { paths -> paths.filter { Files.isRegularFile(it, NOFOLLOW_LINKS) &&
            it.fileName.toString().let { name -> name.endsWith(".class") && (name.startsWith(prefix) ||
                prefix == "AcpProviderNativeDns" && (name.startsWith("NativeNamespace") || nativeObserverCapsuleClass(name)) ||
                prefix == "AcpProviderDns" && name.startsWith("ProviderDns")) }
        }.forEach { path -> entries["decompengine/acp/${path.fileName}"] = nativeRead(path, 1024 * 1024) } }
    }
    nativeRequireObserverCapsuleInventory(entries.keys)
    entries[DNS_RESOURCE.removePrefix("/")] = nativeResource(DNS_RESOURCE)
    val jar = input.resolve("control.jar")
    JarOutputStream(Files.newOutputStream(jar, CREATE_NEW)).use { output -> entries.forEach { (name, bytes) ->
        output.putNextEntry(JarEntry(name).also { it.time = 0 }); output.write(bytes); output.closeEntry()
    } }
    val kotlin = Path.of(Unit::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
    check(Files.isRegularFile(kotlin, NOFOLLOW_LINKS))
    val stdlib = input.resolve("kotlin-stdlib.jar")
    Files.copy(kotlin, stdlib)
    return listOf(jar, stdlib)
}

private fun authenticateNativeWorker(path: Path, expected: String) {
    check(expected.matches(Regex("[0-9a-f]{64}")))
    check(nativeSha(nativeRead(path, 65536)) == expected)
    JarFile(path.toFile()).use { jar ->
        check(jar.entries().asSequence().filterNot { it.isDirectory }.map { it.name }.toSet() ==
            setOf("META-INF/MANIFEST.MF", "decompengine/acp/ProviderDnsWorker.class"))
        check(jar.manifest.mainAttributes.keys.map(Any::toString).toSet() == setOf("Manifest-Version"))
        check(jar.manifest.mainAttributes.getValue("Manifest-Version") == "1.0")
    }
}

private fun nativeDnsQuestion(bytes: ByteArray): Int {
    check(bytes.size in 17..512)
    fun word(at: Int): Int = (bytes[at].toInt() and 255 shl 8) or (bytes[at + 1].toInt() and 255)
    check(word(2) and 0xf800 == 0 && word(4) == 1 && word(6) == 0 && word(8) == 0)
    var offset = 12
    val labels = mutableListOf<String>()
    while (true) {
        check(offset < bytes.size)
        val length = bytes[offset++].toInt() and 255
        if (length == 0) break
        check(length in 1..63 && offset + length <= bytes.size && labels.size < 3)
        labels += bytes.copyOfRange(offset, offset + length).toString(Charsets.US_ASCII)
        offset += length
    }
    check(labels.joinToString(".") == "chatgpt.com" && offset + 4 <= bytes.size && word(offset + 2) == 1)
    return word(offset).also { check(it == 1 || it == 28) }
}

internal fun nativeObserverFailureFields(failure: Throwable?, prefix: String): String {
    check(prefix in setOf("primary", "cleanup"))
    val observed = failure as? NativeObserverFailure ?: return ""
    return "${prefix}ObserverCategory=${observed.category}\n${prefix}ObserverPid=${observed.observedPid ?: "UNAVAILABLE"}\n" +
        "${prefix}ObserverKind=${observed.namespaceKind ?: "UNAVAILABLE"}\n${prefix}ObserverPhase=${observed.observerPhase ?: "UNAVAILABLE"}\n"
}

internal fun nativeFailureCategory(failure: Throwable?): String = when (failure) {
    null -> "NONE"
    is NativeObserverFailure -> failure.category
    is NativeNamespaceWaitFailure -> "EXECUTION_TIMEOUT"
    is java.nio.file.AccessDeniedException -> "ACCESS_DENIED"
    is java.io.IOException -> "IO_FAILURE"
    is AssertionError -> "ASSERTION"
    is IllegalStateException -> "STATE_FAILURE"
    else -> "OTHER_FAILURE"
}

internal fun nativeKeepPrimaryFailure(primary: Throwable?, cleanup: Throwable) {
    if (primary == null) throw cleanup
    primary.addSuppressed(cleanup)
}

internal fun nativeFixedChildOutcome(code: Int?, bytes: ByteArray): String {
    val marker = bytes.toString(Charsets.US_ASCII).trimEnd('\n')
    return "exit=" + (code ?: "UNAVAILABLE") + ";stage=" + when {
        code == null -> "WAIT_INCOMPLETE"
        marker == OUTER_MARKER.trimEnd('\n') -> "OUTER_SUCCESS"
        marker.matches(Regex("NATIVE_DNS_CONTROL_FAILED_[A-Z_]{1,64}")) -> marker.removePrefix("NATIVE_DNS_CONTROL_FAILED_")
        else -> "UNRECOGNIZED_OUTPUT"
    }
}
private class NativeNamespaceWaitFailure : IllegalStateException("native execution timeout")
private fun nativeWait(process: Process, endMillis: Long, maximum: Int = MAXIMUM_CONTROL_OUTPUT,
    observe: ((Int?, ByteArray) -> Unit)? = null): Pair<Int, ByteArray> {
    val executionEnd = endMillis - 5_000 // Both execution and cleanup ends are fixed before launch.
    val output = ByteArrayOutputStream()
    val overflow = AtomicBoolean()
    val reader = Thread({
        try {
            process.inputStream.use { stream ->
                val bytes = stream.readNBytes(maximum + 1)
                output.write(bytes)
                if (bytes.size > maximum) { overflow.set(true); process.toHandle().destroyForcibly() }
            }
        } catch (_: Throwable) { overflow.set(true) }
    }, "native-dns-fixed-output").also { it.isDaemon = true; it.start() }
    var primary: Throwable? = null
    try {
        process.outputStream.close()
        if (!process.waitFor(nativeRemainingMillis(executionEnd), TimeUnit.MILLISECONDS)) throw NativeNamespaceWaitFailure()
        nativeJoin(reader, executionEnd)
        check(!overflow.get())
        check(process.errorStream.readNBytes(MAXIMUM_CONTROL_OUTPUT + 1).isEmpty())
        return process.exitValue() to output.toByteArray()
    } catch (failure: Throwable) {
        primary = failure
        throw failure
    } finally {
        if (!reader.isAlive && !overflow.get()) observe?.invoke(if (process.isAlive) null else process.exitValue(), output.toByteArray())
        else observe?.invoke(null, byteArrayOf())
        try {
            try { nativeStop(process, endMillis) }
            finally { nativeJoin(reader, endMillis) }
        } catch (failure: Throwable) {
            nativeKeepPrimaryFailure(primary, failure)
        }
    }
}

private fun nativeStop(process: Process, endMillis: Long) {
    val descendants = process.toHandle().descendants().use { it.toList() }
    try {
        descendants.asReversed().forEach { if (it.isAlive) it.destroyForcibly() }
        if (process.isAlive) process.toHandle().destroyForcibly()
        check(process.waitFor(maxOf(0, endMillis - System.currentTimeMillis()), TimeUnit.MILLISECONDS) && !process.isAlive)
        descendants.forEach { handle ->
            nativeAwait(endMillis) { !handle.isAlive && !Files.exists(Path.of("/proc", "${handle.pid()}")) }
        }
    } finally {
        val closed = AtomicBoolean()
        val closer = Thread({
            var complete = true
            listOf(process.outputStream, process.inputStream, process.errorStream).forEach {
                try { it.close() } catch (_: Throwable) { complete = false }
            }
            closed.set(complete)
        }, "native-dns-pipe-close").also { it.isDaemon = true; it.start() }
        nativeJoin(closer, endMillis)
        check(closed.get())
    }
}

private fun nativeRemainingMillis(endMillis: Long): Long = (endMillis - System.currentTimeMillis()).also { check(it > 0) }
private fun nativeJoin(thread: Thread, endMillis: Long) {
    val remaining = endMillis - System.currentTimeMillis()
    if (remaining > 0) thread.join(remaining)
    check(!thread.isAlive)
}
private fun nativeRequireCapability(available: Boolean, message: () -> String, required: Boolean) {
    if (available) return
    if (required) throw AssertionError("required native DNS contract unavailable: ${message()}")
    assumeTrue(false, message())
}
private fun nativeCleanupDeadline(endMillis: Long): Long = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(nativeRemainingMillis(endMillis))
private fun nativeAwait(endMillis: Long, condition: () -> Boolean) {
    while (!condition()) { nativeRemainingMillis(endMillis); Thread.sleep(5) }
}
private fun nativeRead(path: Path, maximum: Int): ByteArray {
    check(Files.isRegularFile(path, NOFOLLOW_LINKS) && Files.size(path) in 1..maximum.toLong())
    return Files.newInputStream(path, NOFOLLOW_LINKS).use { it.readNBytes(maximum + 1).also { bytes -> check(bytes.size in 1..maximum) } }
}
private fun nativeResource(name: String): ByteArray = checkNotNull(AcpProviderNativeDnsControl::class.java.getResourceAsStream(name)).use {
    it.readNBytes(1024 * 1024 + 1).also { bytes -> check(bytes.size in 1..1024 * 1024) }
}
private fun nativeSha(bytes: ByteArray): String = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
private fun nativeShaFile(path: Path): String {
    val digest = MessageDigest.getInstance("SHA-256")
    Files.newInputStream(path).use { stream -> val buffer = ByteArray(65536); while (true) { val size = stream.read(buffer); if (size < 0) break; digest.update(buffer, 0, size) } }
    return digest.digest().joinToString("") { "%02x".format(it) }
}
private fun nativeOrderedDigest(items: List<String>): String = nativeSha(items.joinToString("\u0000").toByteArray(Charsets.UTF_8))
private fun nativeProperties(bytes: ByteArray): Properties = Properties().also { it.load(bytes.inputStream()) }
private fun nativeWriteProperties(path: Path, values: Map<String, String>) {
    check(values.keys.all { it.matches(Regex("[A-Za-z][A-Za-z0-9]*")) } && values.values.all { it.matches(Regex("[A-Za-z0-9._-]+")) })
    Files.writeString(path, values.toSortedMap().entries.joinToString("\n", postfix = "\n") { "${it.key}=${it.value}" }, CREATE_NEW)
}
private fun nativeRemoveTree(path: Path) { Files.walk(path).use { it.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
private fun nativeWriteReceipt(path: Path, facts: Map<String, Any>) {
    fun value(item: Any): String = when (item) {
        is Boolean, is Number -> item.toString()
        else -> item.toString().also { check(it.matches(Regex("[A-Za-z0-9._-]+"))) }.let { "\"$it\"" }
    }
    val text = facts.entries.joinToString(",\n", "{\n", "\n}\n") { "  \"${it.key}\": ${value(it.value)}" }
    val pending = path.resolveSibling("${path.fileName}.pending")
    Files.writeString(pending, text, CREATE_NEW)
    Files.move(pending, path, ATOMIC_MOVE)
}
