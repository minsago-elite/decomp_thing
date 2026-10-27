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

// Public service correlation metadata only. No value is an approval input.
private val nativeContextEnvironmentKeys = listOf("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB", "GITHUB_WORKFLOW_REF",
    "GITHUB_SHA", "GITHUB_EVENT_NAME", "RUNNER_OS", "RUNNER_ARCH", "RUNNER_ENVIRONMENT", "RUNNER_NAME", "ImageOS", "ImageVersion")
private fun nativeHostContext(): Map<String, String> {
    fun hex(value: String?): String {
        if (value == null) return "UNAVAILABLE"
        check(value.length in 1..256 && value.all { it.code in 32..126 })
        return value.toByteArray(Charsets.US_ASCII).joinToString("") { "%02x".format(it) }
    }
    val result = linkedMapOf("schema" to "2", "role" to "CORRELATION_ONLY_UNQUALIFIED")
    nativeContextEnvironmentKeys.forEachIndexed { index, key -> result["context" + index + "Hex"] = hex(System.getenv(key)) }
    result["testTaskHex"] = hex(System.getProperty("decompengine.acp.providerDns.testTask"))
    result["maxParallelForks"] = System.getProperty("decompengine.acp.providerDns.maxParallelForks", "UNAVAILABLE")
    result["forkEvery"] = System.getProperty("decompengine.acp.providerDns.forkEvery", "UNAVAILABLE")
    result["junitParallelEnabled"] = System.getProperty("junit.jupiter.execution.parallel.enabled", "UNAVAILABLE")
    check(result["testTaskHex"] == hex(":test") && result["maxParallelForks"] == "1" && result["forkEvery"] == "0" && result["junitParallelEnabled"] == "false")
    return result
}

private fun nativeDnsCase(caseName: String, controlKind: String = "positive") {
    val required = nativeRequired()
    val bwrap = Path.of("/usr/bin/bwrap")
    val java = Path.of(System.getProperty("java.home"), "bin/java").toRealPath()
    val helperSetting = System.getProperty("decompengine.acp.providerDns.loopbackHelper")
    val referenceSetting = System.getProperty("decompengine.acp.providerDns.loopbackReference")
    nativeRequireCapability(
        System.getProperty("os.name") == "Linux" && Runtime.version().feature() == 21 && System.getProperty("os.arch") in setOf("amd64", "x86_64") &&
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
    val receipt = root.resolve(if (controlKind == "positive") "$caseName.json" else "$controlKind.json")
    val evidenceCase = if (controlKind == "positive") caseName else controlKind
    val tree = root.resolve("$evidenceCase-$runId")
    val retained = root.resolve("$evidenceCase-$runId-closure")
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
        "schemaVersion" to 2, "caseName" to caseName, "runId" to runId,
        "testSourceSha256" to nativeSha(testSource), "helperSourceSha256" to nativeSha(source),
        "ownedContractSourceSha256" to nativeSha(nativeResource(NATIVE_RESOURCE + "NativeDnsOwnedDomainContract.kt")),
        "scopeBackendSourceSha256" to nativeSha(nativeResource(NATIVE_RESOURCE + "LinuxBubblewrapBoundary.kt")),
        "scopeFilesystemSourceSha256" to nativeSha(nativeResource(NATIVE_RESOURCE + "LinuxFilesystemSyscalls.kt")),
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

    val context = nativeHostContext()
    val contextPath = root.resolve(evidenceCase + "-host-context.properties")
    nativeWriteProperties(contextPath, context)
    facts["hostContextSha256"] = nativeShaFile(contextPath)
    var primary: Throwable? = null
    val parentNamespaces = listOf("pid", "mnt", "net", "user").associateWith { nativeNamespace(it) }
    nativeVisibilitySink = root.resolve(caseName + "-" + runId + "-" + controlKind + "-visibility.properties")
    nativeVisibilityAccumulator.reset()
    val lease = nativeObserverBudgetOwner.acquire(NativeObserverBudget(endMillis))
    try {
        Files.createDirectory(input.resolve("jdk"))
        val control = snapshotNativeControl(input)
        facts["controlRuntimeClosureSha256"] = nativeOrderedDigest(control.map { it.fileName.toString() + ":" + nativeShaFile(it) })
        val hostDirectory = tree.resolve("host-runtime")
        val hostBinding = snapshotNativeHostRuntime(hostDirectory, control)
        facts["hostRuntimeClosureSha256"] = nativeHostRuntimeCommitment(hostDirectory)
        facts["hostRuntimeManifestSha256"] = nativeShaFile(hostDirectory.resolve("host-runtime.properties"))
        facts["hostRuntimeClassesSha256"] = hostBinding.getValue("hostClassesSha256")
        facts["hostRuntimeGenerationSha256"] = hostBinding.getValue("sourceGenerationSha256")
        facts["hostRuntimeJnaSha256"] = hostBinding.getValue("jnaJarSha256")
        facts["hostRuntimeJniSha256"] = hostBinding.getValue("jniDispatchSha256")
        facts["hostRuntimeJniMappingSha256"] = hostBinding.getValue("jniMappingSha256")
        Files.write(input.resolve("worker.jar"), nativeRead(worker, 65536), CREATE_NEW)
        Files.setPosixFilePermissions(input.resolve("worker.jar"), PosixFilePermissions.fromString("rw-r--r--"))
        Files.write(input.resolve("loopback-helper"), helperBytes, CREATE_NEW)
        Files.setPosixFilePermissions(input.resolve("loopback-helper"), PosixFilePermissions.fromString("r-xr-xr-x"))
        Files.write(input.resolve("empty-env"), envBytes, CREATE_NEW)
        Files.setPosixFilePermissions(input.resolve("empty-env"), PosixFilePermissions.fromString("r-xr-xr-x"))
        Files.writeString(input.resolve("hosts"), "127.0.0.1 localhost\n::1 localhost\n", CREATE_NEW)
        Files.writeString(input.resolve("nsswitch.conf"), "hosts: files dns\n", CREATE_NEW)
        Files.writeString(input.resolve("resolv.conf"), "nameserver 127.0.0.1\noptions timeout:30 attempts:1\n", CREATE_NEW)

        val owned = NativeDnsOwnedDomainOwner(bwrap, java.parent.parent, input.resolve("loopback-helper"), input, output,
            caseName, controlKind, endMillis).execute()
        check(owned.domainFacts["cleanupVerified"] == true)
        val fixedHost = Path.of(System.getProperty("decompengine.acp.providerDns.hostRuntime"))
        check(nativeValidateHostRuntime(fixedHost, control) == hostBinding.filterKeys { it !in setOf("loadedClassOriginsVerified", "fixedJnaSelectionVerified", "jniMappingCount", "jniDevice", "jniInode", "jniMappingSha256") })
        check(nativeHostJniMapping(fixedHost) == hostBinding.filterKeys { it in setOf("schema", "loadedClassOriginsVerified", "fixedJnaSelectionVerified", "jniMappingCount", "jniDevice", "jniInode", "jniMappingSha256") })
        val proof = owned.inner
        check(proof.getProperty("caseName") == caseName && proof.getProperty("workerJarSha256") == expectedWorker)
        for (name in listOf("realQueryObserved", "nativeBuiltinWorker", "childReaped", "ownerJoined", "streamsClosed",
            "noAddressAdmitted", "noConnectAdmitted", "noActiveDescendants", "blackholeJoined", "workerCapabilitiesZero",
            "innerNoNewPrivileges", "workerNoNewPrivileges")) {
            check(proof.getProperty(name) == "true"); facts[name] = true
        }
        for (name in listOf("innerBoundingMask", "workerBoundingMask")) {
            check(proof.getProperty(name) == "1400"); facts[name] = "1400"
        }
        facts["queryCount"] = proof.getProperty("queryCount").toInt().also { check(it in 1..64) }
        facts["queryType"] = proof.getProperty("queryType").toInt().also { check(it in setOf(1, 28)) }
        // This is an INNER coordinate. The native owner already reaped its
        // direct inner JVM and all descendants; never look up this number on host.
        facts["childPid"] = proof.getProperty("childPid").toLong().also { check(it > 1) }
        val domain = owned.domainFacts + mapOf("runId" to runId, "testSourceSha256" to facts.getValue("testSourceSha256"),
            "helperSourceSha256" to facts.getValue("helperSourceSha256"), "workerJarSha256" to expectedWorker,
            "controlRuntimeClosureSha256" to facts.getValue("controlRuntimeClosureSha256"),
            "ownedContractSourceSha256" to facts.getValue("ownedContractSourceSha256"),
            "scopeBackendSourceSha256" to facts.getValue("scopeBackendSourceSha256"),
            "scopeFilesystemSourceSha256" to facts.getValue("scopeFilesystemSourceSha256"), "hostContextSha256" to facts.getValue("hostContextSha256")) +
            facts.filterKeys { it.startsWith("hostRuntime") }
        val domainBytes = domain.toSortedMap().entries.joinToString("\n", postfix = "\n") { it.key + "=" + it.value }.toByteArray()
        check(domainBytes.size <= MAXIMUM_CONTROL_FILE)
        val domainName = if (controlKind == "positive") caseName else controlKind
        Files.write(root.resolve(domainName + "-owned.properties"), domainBytes, CREATE_NEW)
        facts["ownedDomainSha256"] = nativeSha(domainBytes)
        facts["ownedScopeIdentitySha256"] = domain.getValue("cgroupIdentitySha256")
        facts["ownedGateSha256"] = nativeSha(nativeRead(output.resolve("gate.properties"), MAXIMUM_CONTROL_FILE))
        facts["ownedTerminalSha256"] = nativeSha(nativeRead(output.resolve("owner.properties"), MAXIMUM_CONTROL_FILE))
        facts["ownedInnerSha256"] = nativeSha(nativeRead(output.resolve("inner.properties"), MAXIMUM_CONTROL_FILE))
        check(nativeShaFile(java) == facts["javaExecutableSha256"] && nativeShaFile(bwrap.toRealPath()) == facts["bwrapSha256"])
        check(nativeShaFile(envExecutable) == facts["envExecutableSha256"])
        check(nativeOrderedDigest(control.map { it.fileName.toString() + ":" + nativeShaFile(it) }) == facts["controlRuntimeClosureSha256"])
        Files.createDirectory(retained, PosixFilePermissions.asFileAttribute(nativePermissions))
        val hostRetained = Files.createDirectory(retained.resolve("host-runtime"), PosixFilePermissions.asFileAttribute(nativePermissions))
        for (name in nativeHostArtifacts + "host-runtime-observed.properties") {
            nativeObserverBudgetOwner.current?.checkpoint()
            Files.write(hostRetained.resolve(name), nativeRead(hostDirectory.resolve(name), if (name == "host-control.jar") 16 * 1024 * 1024 else 8 * 1024 * 1024), CREATE_NEW)
        }
        check(nativeHostRuntimeCommitment(hostRetained) == facts["hostRuntimeClosureSha256"])
        control.forEach { artifact ->
            nativeObserverBudgetOwner.current?.checkpoint()
            val limit = if (artifact.fileName.toString() == "control.jar") 16 * 1024 * 1024 else 8 * 1024 * 1024
            Files.write(retained.resolve(artifact.fileName), nativeRead(artifact, limit), CREATE_NEW)
        }
        for (name in listOf("gate.properties", "owner.properties", "inner.properties") + (if (controlKind == "inaccessible-owned") listOf("witness.properties") else emptyList()))
            Files.write(retained.resolve(name), nativeRead(output.resolve(name), MAXIMUM_CONTROL_FILE), CREATE_NEW)
        check(nativeOrderedDigest(control.map { it.fileName.toString() + ":" + nativeShaFile(retained.resolve(it.fileName)) }) == facts["controlRuntimeClosureSha256"])
        for ((name, field) in mapOf("gate.properties" to "ownedGateSha256", "owner.properties" to "ownedTerminalSha256", "inner.properties" to "ownedInnerSha256"))
            check(nativeSha(nativeRead(retained.resolve(name), MAXIMUM_CONTROL_FILE)) == facts[field])
        nativeObserverBudgetOwner.current?.checkpoint()
        check(parentNamespaces.all { (kind, ns) -> nativeNamespace(kind) == ns })
        check(nativeHostLoopbackFlags() == parentLoopback)
        nativeRemoveTree(tree); check(!Files.exists(tree, NOFOLLOW_LINKS))
        facts["privateTreeRemoved"] = true
        facts["ownedProcessClosureObserved"] = true
        facts["ownedReferenceClosureObserved"] = true
        facts["namespaceDeduction"] = "CONDITIONAL"
        facts["executorContract"] = NativeDnsOwnedDomainContract.EXECUTOR_CONTRACT
        // This producer cannot authenticate the actual service/job/runtime join
        // or certify the external-holder premise of the stronger namespace claim.
        check(NativeDnsOwnedDomainContract.localEvidence(owned.domainFacts["cleanupVerified"] == true &&
            facts["ownedProcessClosureObserved"] == true && facts["ownedReferenceClosureObserved"] == true, facts.getValue("namespaceDeduction").toString(),
            facts.getValue("executorContract").toString()) == NativeDnsOwnedDomainContract.LocalEvidence.OWNED_OBSERVATIONS_VERIFIED_UNQUALIFIED)
        facts["noSurvivingChildMembership"] = true
        facts["hostNamespacesUnchanged"] = true; facts["hostLoopbackUnchanged"] = true
        if (controlKind != "positive") {
            check(owned.actualNegative == controlKind)
            facts["negativeControl"] = controlKind; facts["qualificationRefused"] = true
        } else check(owned.actualNegative == null)
        check(nativeHostContext() == context && nativeShaFile(contextPath) == facts["hostContextSha256"])
        nativeObserverBudgetOwner.current?.checkpoint()
        nativeWriteReceipt(receipt, facts)
        nativeObserverBudgetOwner.current?.checkpoint()
    } catch (failure: Throwable) { primary = failure; throw failure }
    finally {
        try {
            check(parentNamespaces.all { (kind, ns) -> nativeNamespace(kind) == ns })
            check(nativeHostLoopbackFlags() == parentLoopback)
        } catch (failure: Throwable) { nativeKeepPrimaryFailure(primary, failure) }
        finally {
            nativeVisibilitySink = null
            try { lease.close() } catch (failure: Throwable) { nativeKeepPrimaryFailure(primary, failure) }
            if (primary != null) {
                val diagnostic = "case=" + caseName + "\nrunId=" + runId + "\ncontrol=" + controlKind +
                    "\nprimaryFailure=" + nativeFailureCategory(primary) + "\n" + nativeObserverFailureFields(primary, "primary")
                try { Files.writeString(root.resolve(domainNameForFailure(caseName, controlKind) + "-" + runId + "-failure.properties"), diagnostic, CREATE_NEW) }
                catch (failure: Throwable) { primary.addSuppressed(failure) }
            }
        }
    }
}
private fun domainNameForFailure(caseName: String, control: String) = if (control == "positive") caseName else control

/** Actual negative controls; the same real DNS payload and owner execute first. */
@Tag("ci-live")
class NativeDnsOwnedDomainBoundaryTest {
    @Test fun retainedChildCannotCertifyCleanup() = nativeDnsCase("cancel", "retained-child")
    @Test fun retainedNamespaceReferenceCannotBorrowEmptyScope() = nativeDnsCase("cancel", "retained-reference")
    @Test fun inaccessibleOwnedMemberRemainsFatal() = nativeDnsCase("cancel", "inaccessible-owned")
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
    val namespaceKind: String? = null, val observerPhase: String? = null,
    val witness: Witness? = null) : IllegalStateException(category) {
    init {
        require(category in setOf("OBSERVER_DEADLINE", "SCAN_WORK_LIMIT", "PROC_BYTE_LIMIT", "DIAGNOSTIC_CAPACITY", "POSSIBLE_OWNED_VISIBILITY"))
        require(observedPid == null || observedPid in 1..4294967295L)
        require(namespaceKind == null || namespaceKind in setOf("net", "user", "pid", "mnt"))
        require(observerPhase == null || observerPhase in setOf("HOST_CLEANUP", "OUTER_CLEANUP"))
        require(witness == null || category == "POSSIBLE_OWNED_VISIBILITY" &&
            witness.pid == observedPid && witness.kind == namespaceKind && witness.phase == observerPhase)
    }

    // Nested under an existing authenticated capsule root, including generated enum classes.
    enum class ReadStage { START_BEFORE, STATUS, START_AFTER, STABILITY, CLASSIFY }
    enum class Outcome { STABLE_OVERLAP, START_CHANGED, IDENTITY_UNAVAILABLE }
    enum class ExceptionKind { NONE, NO_SUCH_FILE, ACCESS_DENIED, SECURITY, IO, FORMAT, STATE, OTHER }

    /** Immutable text from bounded typed observations only; never exception messages or process names. */
    class Witness(val pid: Long, val kind: String, val phase: String, callerPid: Long,
        caller: NativeNamespaceCredentials, target: NativeNamespaceCredentials?, startBefore: Long?, startAfter: Long?,
        stage: ReadStage, exceptionKind: ExceptionKind) {
        val outcome: Outcome
        val record: String
        init {
            require(pid in 1..4294967295L && callerPid in 1..4294967295L)
            require(kind in setOf("net", "user", "pid", "mnt") && phase in setOf("HOST_CLEANUP", "OUTER_CLEANUP"))
            require(startBefore == null || startBefore >= 0)
            require(startAfter == null || startAfter >= 0)
            fun tuple(value: List<Long>): List<Long> {
                require(value.size == 4 && value.all { it in 0..4294967295L })
                return value.toList()
            }
            val callerUid = tuple(caller.uid); val callerGid = tuple(caller.gid)
            val targetUid = target?.uid?.let(::tuple); val targetGid = target?.gid?.let(::tuple)
            val stable = target != null && startBefore != null && startBefore == startAfter &&
                stage == ReadStage.CLASSIFY && exceptionKind == ExceptionKind.NONE
            val uidMatch = if (stable) callerUid.any { it in checkNotNull(targetUid) } else null
            val gidMatch = if (stable) callerGid.any { it in checkNotNull(targetGid) } else null
            // This diagnostic is never an alternate authority to declare a PID foreign.
            require(!stable || uidMatch == true || gidMatch == true)
            outcome = when {
                stable -> Outcome.STABLE_OVERLAP
                startBefore != null && startAfter != null && startBefore != startAfter -> Outcome.START_CHANGED
                else -> Outcome.IDENTITY_UNAVAILABLE
            }
            record = "pid=$pid kind=$kind phase=$phase callerPid=$callerPid namespaceRead=ACCESS_DENIED " +
                "callerUid=${callerUid.joinToString(",")} callerGid=${callerGid.joinToString(",")} " +
                "targetUid=${targetUid?.joinToString(",") ?: "UNAVAILABLE"} targetGid=${targetGid?.joinToString(",") ?: "UNAVAILABLE"} " +
                "targetIdentity=${if (stable) "STABLE" else "UNVERIFIED"} startBefore=${startBefore ?: "UNAVAILABLE"} " +
                "startAfter=${startAfter ?: "UNAVAILABLE"} readStage=$stage outcome=$outcome exceptionClass=$exceptionKind " +
                "uidMatch=${uidMatch ?: "UNAVAILABLE"} gidMatch=${gidMatch ?: "UNAVAILABLE"}"
            check(record.length <= 768 && record.all { it.code in 32..126 })
        }
    }

    companion object {
        fun exceptionKind(failure: Exception): ExceptionKind = when (failure) {
            is java.nio.file.NoSuchFileException -> ExceptionKind.NO_SUCH_FILE
            is java.nio.file.AccessDeniedException -> ExceptionKind.ACCESS_DENIED
            is SecurityException -> ExceptionKind.SECURITY
            is java.io.IOException -> ExceptionKind.IO
            is IllegalArgumentException -> ExceptionKind.FORMAT
            is IllegalStateException -> ExceptionKind.STATE
            else -> ExceptionKind.OTHER
        }
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
    fun counters(): Map<String, Int> = mapOf("hostObserverScans" to scans, "hostObserverPids" to pids, "hostObserverWork" to work, "hostObserverBytes" to bytes)
}

/** Fixed detail storage; overflow counts observations, never distinct identities or absence. */
internal class NativeVisibilityAccumulator(private val rows: MutableList<String> = mutableListOf()) {
    var overflowObservations = 0; private set
    private var digest = ByteArray(32)
    var firstPossibleWitness: NativeObserverFailure.Witness? = null; private set
    var scanComplete = false
    fun reset() { rows.clear(); overflowObservations = 0; digest = ByteArray(32); firstPossibleWitness = null; scanComplete = false }
    fun recordFirstPossible(witness: NativeObserverFailure.Witness) {
        if (firstPossibleWitness == null) firstPossibleWitness = witness
        scanComplete = false
    }
    fun record(record: String, provenForeign: Boolean) {
        check(record.length <= 768 && record.all { it.code in 32..126 })
        if (record in rows) return
        // Fifteen ordinary details plus one reserved first-fatal slot: total remains sixteen.
        if (rows.size < 15) rows += record
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
        val details = rows + listOfNotNull(firstPossibleWitness?.record)
        check(details.size <= 16)
        val summary = "retainedRowCount=${details.size}\ncredentialOverflowObservations=$overflowObservations\n" +
            "observationDigest=${digest.joinToString("") { "%02x".format(it) }}\nscanComplete=$scanComplete\n"
        return (details.joinToString("\n", postfix = if (details.isEmpty()) "" else "\n") + summary)
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
        val callerPid = ProcessHandle.current().pid()
        val caller = nativeCredentialIdentity(callerPid, budget)
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
                    var observedTarget: NativeNamespaceCredentials? = null
                    var startBefore: Long? = null
                    var startAfter: Long? = null
                    var readStage = NativeObserverFailure.ReadStage.START_BEFORE
                    var exceptionKind = NativeObserverFailure.ExceptionKind.NONE
                    try {
                        startBefore = nativeStartTime(pid, budget)
                        readStage = NativeObserverFailure.ReadStage.STATUS
                        observedTarget = nativeCredentialIdentity(pid, budget)
                        readStage = NativeObserverFailure.ReadStage.START_AFTER
                        startAfter = nativeStartTime(pid, budget)
                        readStage = NativeObserverFailure.ReadStage.STABILITY
                        target = nativeStableDeniedCredentials(startBefore, startAfter, observedTarget)
                        if (target != null) readStage = NativeObserverFailure.ReadStage.CLASSIFY
                    } catch (failure: NativeObserverFailure) { throw NativeObserverFailure(failure.category, pid, kind, phase) }
                    catch (failure: Exception) { exceptionKind = NativeObserverFailure.exceptionKind(failure); target = null }
                    val mustFail = nativeDeniedVisibilityRequiresFailure(caller, target)
                    if (mustFail) {
                        // Freeze already-observed typed facts on the primary BEFORE a diagnostic
                        // accumulator/budget/persistence failure. No additional /proc reads or retries.
                        val witness = NativeObserverFailure.Witness(pid, kind, phase, callerPid, caller,
                            observedTarget, startBefore, startAfter, readStage, exceptionKind)
                        val primary = NativeObserverFailure("POSSIBLE_OWNED_VISIBILITY", pid, kind, phase, witness)
                        try {
                            nativeVisibilityAccumulator.recordFirstPossible(witness)
                            budget.operation()
                            nativePersistVisibility()
                        }
                        catch (diagnostic: Throwable) { primary.addSuppressed(diagnostic) }
                        throw primary
                    }
                    nativeRecordDenied(pid, kind, phase, caller, target, startBefore, "DISTINCT_CREDENTIALS")
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
    val command = mutableListOf(bwrap.toString())
    command += acpBubblewrapIsolationArguments()
    command += listOf("--uid", "0", "--gid", "0", "--as-pid-1")
    if (outer) command += listOf("--cap-add", "CAP_NET_ADMIN", "--cap-add", "CAP_NET_BIND_SERVICE")
    command += listOf("--dir", "/etc")
    // Fixed read-only loader/library directories contain no host home or credentials. Paths are
    // mounted canonically, with the host's verified FHS aliases recreated in the empty root.
    val runtimeRoots = listOf("/lib", "/lib64", "/usr/lib", "/usr/lib64").map(Path::of).filter(Files::isDirectory)
    runtimeRoots.map { it.toRealPath() }.distinct().sortedWith(object : Comparator<Path> {
        override fun compare(a: Path, b: Path): Int = a.toString().compareTo(b.toString())
    }).forEach {
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

// A separate host-only closure; none of these artifacts are mounted in /fixture-input.
private val nativeHostArtifacts = listOf("host-control.jar", "kotlin-stdlib.jar", "jna.jar", "libjnidispatch.so", "host-runtime.properties")
private fun nativeHostClasses(): java.util.SortedMap<String, ByteArray> {
    val result = sortedMapOf<String, ByteArray>()
    val repository = Path.of(System.getProperty("user.dir")).toAbsolutePath().normalize()
    val loader = AcpProviderNativeDnsControl::class.java.classLoader
    for ((sourceSet, bySource) in NativeDnsOwnedDomainContract.hostRuntimeRoots) {
        val directory = repository.resolve("build/classes/kotlin/" + sourceSet + "/decompengine/acp")
        check(directory.toRealPath() == directory)
        val paths = Files.newDirectoryStream(directory, "*.class").use { it.asSequence().take(8193).toList() }
        check(paths.size <= 8192)
        for (path in paths.sortedWith(object : Comparator<Path> {
            override fun compare(a: Path, b: Path): Int = a.fileName.toString().compareTo(b.fileName.toString())
        })) {
            nativeObserverBudgetOwner.current?.operation()
            val name = path.fileName.toString()
            if (NativeDnsOwnedDomainContract.hostClassSource(sourceSet, name) == null) continue
            nativeObserverBudgetOwner.current?.operation()
            val bytes = nativeRead(path, 1024 * 1024)
            val key = "decompengine/acp/" + name
            NativeDnsOwnedDomainContract.requireHostClassIdentity(sourceSet, name, bytes)
            val type = Class.forName(key.removeSuffix(".class").replace('/', '.'), false, loader)
            check(Path.of(type.protectionDomain.codeSource.location.toURI()).toRealPath() == directory.parent.parent)
            val loadedResource = checkNotNull(type.getResourceAsStream("/" + key)).use { it.readNBytes(1024 * 1024 + 1) }
            check(loadedResource.contentEquals(bytes))
            check(result.put(key, bytes) == null)
            check(result.size <= 256 && result.values.sumOf { it.size.toLong() } <= 16L * 1024 * 1024)
        }
        check(bySource.values.flatten().all { "decompengine/acp/" + it + ".class" in result })
    }
    return result
}
private fun nativeHostJniMapping(directory: Path): Map<String, String> {
    check(System.getProperty("jna.nosys") == "true" && System.getProperty("jna.nounpack") == "true" &&
        System.getProperty("jna.boot.library.path") == directory.toString())
    Class.forName("com.sun.jna.Native", true, AcpProviderNativeDnsControl::class.java.classLoader)
    val path = directory.resolve("libjnidispatch.so")
    val identity = Files.readAttributes(path, "unix:dev,ino", NOFOLLOW_LINKS)
    val dev = (identity.getValue("dev") as Number).toLong(); val ino = (identity.getValue("ino") as Number).toLong()
    val major = (dev ushr 8 and 0xfffL) or (dev ushr 32 and 0xfffff000L)
    val minor = (dev and 0xffL) or (dev ushr 12 and 0xffffff00L)
    val rows = nativeProcText(Path.of("/proc/self/maps"), checkNotNull(nativeObserverBudgetOwner.current)).lineSequence()
        .filter { it.contains("libjnidispatch") }.map { it.trim().split(Regex("\\s+"), limit = 6) }.toList()
    check(rows.size in 1..16 && rows.all { fields -> fields.size == 6 && fields[5] == path.toString() &&
        fields[3].split(':').let { it.size == 2 && it[0].toLong(16) == major && it[1].toLong(16) == minor } && fields[4].toLong() == ino })
    return mapOf("schema" to "2", "loadedClassOriginsVerified" to "true", "fixedJnaSelectionVerified" to "true",
        "jniMappingCount" to rows.size.toString(), "jniDevice" to dev.toString(), "jniInode" to ino.toString(),
        "jniMappingSha256" to nativeOrderedDigest(rows.map { it.drop(1).joinToString(":") }.sorted()))
}
private fun nativeValidateHostRuntime(directory: Path, payload: List<Path>): Map<String, String> {
    check(directory.toRealPath() == directory)
    check(Files.newDirectoryStream(directory).use { it.asSequence().take(6).map { p -> p.fileName.toString() }.toSet() } == nativeHostArtifacts.toSet())
    val metadata = nativeOwnedProperties(nativeRead(directory.resolve("host-runtime.properties"), MAXIMUM_CONTROL_FILE))
    val values = metadata.stringPropertyNames().associateWith(metadata::getProperty)
    val expectedKeys = NativeDnsOwnedDomainContract.hostSourcePaths.keys + setOf("schema", "kotlinCoordinates", "jnaCoordinates", "stdlibSha256",
        "jnaJarSha256", "jniDispatchSha256", "hostClassesSha256", "bytecodeClosureSha256", "sourceGenerationSha256")
    check(values.keys == expectedKeys && values["schema"] == "2" && values["kotlinCoordinates"] == "org.jetbrains.kotlin:kotlin-stdlib:2.4.0" && values["jnaCoordinates"] == "net.java.dev.jna:jna:5.19.1")
    val sources = NativeDnsOwnedDomainContract.hostSourcePaths.mapValues { (_, path) ->
        nativeSha(nativeResource(NATIVE_RESOURCE + Path.of(path).fileName))
    }
    NativeDnsOwnedDomainContract.requireHostGeneration(sources, values.filterKeys { it in sources },
        nativeOrderedDigest(sources.toSortedMap().map { it.key + ":" + it.value }), values.getValue("sourceGenerationSha256"))
    val entries = nativeHostClasses()
    JarFile(directory.resolve("host-control.jar").toFile()).use { jar ->
        val actual = jar.entries().asSequence().take(257).toList()
        check(actual.size <= 256 && actual.map { it.name }.toSet().size == actual.size && actual.map { it.name }.toSet() == entries.keys)
        val archiveEntries = sortedMapOf<String, ByteArray>()
        actual.forEach { entry -> check(!entry.isDirectory && entry.size in 1..1024 * 1024 && entry.compressedSize <= 1024 * 1024 && entry.method in setOf(0, 8))
            archiveEntries[entry.name] = jar.getInputStream(entry).use { it.readNBytes(1024 * 1024 + 1) } }
        NativeDnsOwnedDomainContract.requireHostClassInventory(entries, archiveEntries)
    }
    check(values["bytecodeClosureSha256"] == nativeOrderedDigest(entries.map { it.key + ":" + nativeSha(it.value) }))
    check(values["hostClassesSha256"] == nativeSha(nativeRead(directory.resolve("host-control.jar"), 16 * 1024 * 1024)))
    for ((name, field) in mapOf("kotlin-stdlib.jar" to "stdlibSha256", "jna.jar" to "jnaJarSha256", "libjnidispatch.so" to "jniDispatchSha256")) {
        check(nativeSha(nativeRead(directory.resolve(name), 8 * 1024 * 1024)) == values[field])
    }
    fun loaded(type: Class<*>, file: String) = check(nativeRead(Path.of(type.protectionDomain.codeSource.location.toURI()).toRealPath(), 8 * 1024 * 1024)
        .contentEquals(nativeRead(directory.resolve(file), 8 * 1024 * 1024)))
    loaded(Unit::class.java, "kotlin-stdlib.jar"); loaded(com.sun.jna.Library::class.java, "jna.jar")
    val policy = nativeProperties(nativeResource(NATIVE_RESOURCE + "oracle-native-libraries-v1.properties"))
    check(values["jnaJarSha256"] == policy.getProperty("jna.artifactSha256") && values["jniDispatchSha256"] == policy.getProperty("jna.sha256"))
    val payloadEntries = JarFile(payload.first().toFile()).use { it.entries().asSequence().take(257).toList() }
    check(payloadEntries.size <= 256 && payloadEntries.all { it.size in 1..1024 * 1024 })
    check(entries.size + payloadEntries.size + nativeHostArtifacts.size + 1 <= 256)
    check(entries.values.sumOf { it.size.toLong() } + payloadEntries.sumOf { it.size } + Files.size(payload.last()) +
        listOf("kotlin-stdlib.jar", "jna.jar", "libjnidispatch.so", "host-runtime.properties").sumOf { Files.size(directory.resolve(it)) } <= 16L * 1024 * 1024)
    return values
}
private fun snapshotNativeHostRuntime(directory: Path, payload: List<Path>): Map<String, String> {
    val expected = Path.of(System.getProperty("user.dir"), "build/provider-dns/host-runtime").toAbsolutePath().normalize()
    check(System.getProperty("decompengine.acp.providerDns.hostRuntime") == expected.toString())
    val values = nativeValidateHostRuntime(expected, payload)
    val observed = nativeHostJniMapping(expected)
    Files.createDirectory(directory, PosixFilePermissions.asFileAttribute(nativePermissions))
    for (name in nativeHostArtifacts) {
        nativeObserverBudgetOwner.current?.checkpoint()
        val bound = if (name == "host-control.jar") 16 * 1024 * 1024 else if (name.endsWith(".jar")) 8 * 1024 * 1024 else 1024 * 1024
        Files.write(directory.resolve(name), nativeRead(expected.resolve(name), bound), CREATE_NEW)
    }
    nativeWriteProperties(directory.resolve("host-runtime-observed.properties"), observed)
    check(nativeValidateHostRuntime(expected, payload) == values && nativeHostJniMapping(expected) == observed)
    return values + observed
}
private fun nativeHostRuntimeCommitment(directory: Path): String = nativeOrderedDigest(
    (nativeHostArtifacts + "host-runtime-observed.properties").map { it + ":" + nativeShaFile(directory.resolve(it)) })

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


internal val nativeOwnedCapsuleRoots = setOf("NativeDnsOwnedDomainOwner", "NativeDnsOwnedResult", "NativeDnsOwnedLib", "NativeDnsOwnedFd", "NativeDnsOwnedDomainContract")
internal fun nativeOwnedCapsuleClass(name: String): Boolean = name.endsWith(".class") && nativeOwnedCapsuleRoots.any { root ->
    name == root + ".class" || name.startsWith(root + "$" )
}

private fun snapshotNativeControl(input: Path): List<Path> {
    val entries = sortedMapOf<String, ByteArray>()
    listOf(AcpProviderNativeDnsControl::class.java to "AcpProviderNativeDns", AcpProviderDnsProcess::class.java to "AcpProviderDns").forEach { (type, prefix) ->
        val root = Path.of(type.protectionDomain.codeSource.location.toURI()).toRealPath()
        check(Files.isDirectory(root))
        val packageRoot = root.resolve("decompengine/acp")
        Files.list(packageRoot).use { paths -> paths.filter { Files.isRegularFile(it, NOFOLLOW_LINKS) &&
            it.fileName.toString().let { name -> name.endsWith(".class") && (name.startsWith(prefix) ||
                prefix == "AcpProviderNativeDns" && (name.startsWith("NativeNamespace") || nativeObserverCapsuleClass(name) || nativeOwnedCapsuleClass(name)) ||
                prefix == "AcpProviderDns" && name.startsWith("ProviderDns")) }
        }.forEach { path -> entries["decompengine/acp/${path.fileName}"] = nativeRead(path, 1024 * 1024) } }
    }
    nativeRequireObserverCapsuleInventory(entries.keys)
    check(nativeOwnedCapsuleRoots.all { "decompengine/acp/" + it + ".class" in entries })
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
        "${prefix}ObserverKind=${observed.namespaceKind ?: "UNAVAILABLE"}\n${prefix}ObserverPhase=${observed.observerPhase ?: "UNAVAILABLE"}\n" +
        (observed.witness?.let { "${prefix}ObserverWitness=${it.record}\n" } ?: "")
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

/** Preserve pre-cleanup observations, but classify only the finally selected primary. */
internal fun nativeFinalFailureDiagnostic(snapshot: Map<String, String>, primary: Throwable): Map<String, String> =
    snapshot + ("primaryFailure" to nativeFailureCategory(primary))

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

/** Test-only owner. A supplied transcript cannot construct verified ownership. */

private fun nativeOwnedVisibilityFailure(pid: Long, kind: String, original: Throwable): Nothing {
    val budget = checkNotNull(nativeObserverBudgetOwner.current)
    var witness: NativeObserverFailure.Witness? = null
    try {
        val callerPid = ProcessHandle.current().pid()
        val caller = nativeCredentialIdentity(callerPid, budget)
        val before = nativeStartTime(pid, budget)
        val target = nativeCredentialIdentity(pid, budget)
        val after = nativeStartTime(pid, budget)
        // Different mappings in an owned domain never prove foreignness. The
        // stable-overlap classifier is used only when its exact premise holds.
        val overlap = caller.uid.any { it in target.uid } || caller.gid.any { it in target.gid }
        witness = NativeObserverFailure.Witness(pid, kind, "HOST_CLEANUP", callerPid, caller, target, before, after,
            if (before == after && overlap) NativeObserverFailure.ReadStage.CLASSIFY else NativeObserverFailure.ReadStage.STABILITY,
            NativeObserverFailure.ExceptionKind.NONE)
        nativeVisibilityAccumulator.recordFirstPossible(witness)
        nativePersistVisibility()
    } catch (failure: NativeObserverFailure) { throw failure }
    catch (_: Throwable) { /* Unknown identity is still fatal; never exclude it. */ }
    val failure = NativeObserverFailure("POSSIBLE_OWNED_VISIBILITY", pid, kind, "HOST_CLEANUP", witness)
    failure.addSuppressed(original)
    throw failure
}

/** Routing is pure-control testable; only the private owner supplies acquired
 * signalling closures. No PID/name lookup or ownership can be created here. */
internal fun nativeOwnedCleanupSignal(scopeHeld: Boolean, acquiredScopeRemoved: Boolean, directRootAlive: Boolean,
    rootHandleHeld: Boolean, signalScope: () -> Unit, signalRoot: () -> Unit) {
    when (NativeDnsOwnedDomainContract.cleanupSignal(scopeHeld, acquiredScopeRemoved, directRootAlive, rootHandleHeld)) {
        NativeDnsOwnedDomainContract.CleanupSignal.ACQUIRED_SCOPE -> signalScope()
        NativeDnsOwnedDomainContract.CleanupSignal.DIRECT_ROOT -> signalRoot()
        NativeDnsOwnedDomainContract.CleanupSignal.NONE -> Unit
    }
}

private class NativeDnsOwnedDomainOwner(private val bwrap: Path, private val javaHome: Path,
    private val helper: Path, private val input: Path, private val output: Path,
    private val caseName: String, private val control: String, private val endMillis: Long) {
    private val startedNanos = System.nanoTime()
    private val parentNamespaceState = listOf("pid", "user", "net", "mnt").associateWith { nativeNamespace(it) }
    private val parentLoopbackState = nativeHostLoopbackFlags()
    private val cleanupEnd = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(nativeRemainingMillis(endMillis))
    private val executionEnd = cleanupEnd - TimeUnit.SECONDS.toNanos(5)
    private val limits = AcpSandboxResourceLimits(maximumProcesses = 32, maximumOpenFiles = 128)
    private val references = mutableListOf<NativeDnsOwnedFd>()
    private val mountBindings = mutableListOf<Triple<Path, String, Boolean>>()
    private val facts = linkedMapOf<String, Any>()
    private var process: Process? = null
    private var root: LinuxProcessDescriptor? = null
    private var pid1: LinuxProcessDescriptor? = null
    private var scope: VerifiedSystemdScope? = null
    private var scopeFd: NativeDnsOwnedFd? = null
    private var killFd: NativeDnsOwnedFd? = null
    private var reader: Thread? = null
    private val bytes = ByteArrayOutputStream()
    private val readerFailed = AtomicBoolean()
    private val readerEof = AtomicBoolean()
    private val readerFinished = AtomicBoolean()
    private val readerOverflow = AtomicBoolean()
    private val outputObservedBytes = AtomicInteger()
    private var hostPhase = "NOT_STARTED"
    private var expectedMarker = "NONE"
    private var primaryDiagnostic: Map<String, String>? = null
    private var retainedReference: NativeDnsOwnedFd? = null
    private var releaseAttempted = false
    private var exhaustiveNativeProof = false
    private fun checkpoint(cleanup: Boolean = false) {
        check(System.nanoTime() < if (cleanup) cleanupEnd else executionEnd) { "native owned-domain deadline" }
        check(System.currentTimeMillis() < endMillis - if (cleanup) 0 else 5000)
    }
    private fun text(path: Path) = nativeProcText(path, checkNotNull(nativeObserverBudgetOwner.current))
    private fun start(pid: Long) = nativeStartTime(pid, checkNotNull(nativeObserverBudgetOwner.current))
    private fun key(path: Path) = LinuxFileKey((Files.getAttribute(path, "unix:dev") as Number).toLong(),
        (Files.getAttribute(path, "unix:ino") as Number).toLong())
    private fun members(): List<Long> {
        checkpoint(); checkNotNull(nativeObserverBudgetOwner.current).beginScan()
        val values = text(checkNotNull(scope).identity.cgroupPath.resolve("cgroup.procs"))
            .lineSequence().filter(String::isNotBlank).map(String::toLong).toList()
        check(values.size in 1..32 && values.distinct().size == values.size && values.all { it > 0 })
        values.forEach { checkNotNull(nativeObserverBudgetOwner.current).pid() }
        return values
    }
    private fun marker(expected: String) {
        expectedMarker = when (expected) {
            "OWNED_HOST_GATE_V2\n" -> "HOST_GATE"
            "OWNED_PID1_GATE_V2\n" -> "PID1_GATE"
            else -> "OTHER_FIXED_MARKER"
        }
        nativeAwait(endMillis - 5000) {
            checkpoint(); check(!readerFailed.get())
            synchronized(bytes) { bytes.toString(Charsets.US_ASCII).contains(expected) }
        }
    }

    /** Diagnostic only: never persist arbitrary bwrap/JVM stderr, paths or exception messages. */
    private fun failureSnapshot(failure: Throwable?): Map<String, String> {
        val raw = synchronized(bytes) { bytes.toByteArray() }
        val stages = raw.toString(Charsets.US_ASCII).lineSequence().filter { line ->
            val fields = line.split(':')
            fields.size == 3 && fields[0] == "ND1" &&
                fields[1].toIntOrNull() in setOf(10, 11, 12, 20, 21, 22, 23, 25, 30, 31,
                    33, 34, 35, 36, 37, 40, 41, 42, 43, 44, 45, 46, 50, 51, 52, 53, 54, 55, 56, 57,
                    58, 60, 61, 62, 63, 64, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
                    80, 81, 82, 83, 84, 85, 86, 87, 88, 89) && fields[1].toIntOrNull()?.toString() == fields[1] &&
                fields[2].toIntOrNull()?.let { it in 0..4095 && it.toString() == fields[2] } == true &&
                line.all { it.code in 32..126 }
        }.take(32).toList()
        val child = process
        val alive = child?.isAlive
        val exit = if (child != null && alive == false) runCatching { child.exitValue().toString() }.getOrDefault("UNAVAILABLE") else "UNAVAILABLE"
        return linkedMapOf("schema" to "1", "role" to "DIAGNOSTIC_ONLY_UNQUALIFIED",
            "primaryFailure" to nativeFailureCategory(failure), "hostPhase" to hostPhase,
            "expectedMarker" to expectedMarker, "outputRetainedBytes" to raw.size.toString(),
            "outputObservedBytes" to outputObservedBytes.get().toString(), "outputSha256" to nativeSha(raw),
            "readerFailed" to readerFailed.get().toString(), "readerEof" to readerEof.get().toString(),
            "readerFinished" to readerFinished.get().toString(), "readerOverflow" to readerOverflow.get().toString(),
            "rootAliveAtFailure" to (alive?.toString() ?: "UNAVAILABLE"), "rootExitAtFailure" to exit,
            "hostGateObserved" to raw.toString(Charsets.US_ASCII).contains("OWNED_HOST_GATE_V2\n").toString(),
            "pid1GateObserved" to raw.toString(Charsets.US_ASCII).contains("OWNED_PID1_GATE_V2\n").toString(),
            "fixedStageCount" to stages.size.toString()).also { values ->
            stages.forEachIndexed { index, stage -> values["fixedStage" + index] = stage.replace(':', '-') }
        }
    }
    private fun properties(name: String) = nativeOwnedProperties(nativeRead(output.resolve(name), MAXIMUM_CONTROL_FILE))
    private fun bindNamespace(pid: Long, kind: String, identity: NativeNamespace): NativeDnsOwnedFd {
        try {
        val before = start(pid)
        val ref = NativeDnsOwnedFd.open("/proc/" + pid + "/ns/" + kind, 0x80000)
        references += ref
        check(ref.identity.key == LinuxFileKey(identity.device, identity.inode))
        val types = mapOf("pid" to 0x20000000, "user" to 0x10000000, "net" to 0x40000000, "mnt" to 0x20000)
        check(NativeDnsOwnedLib.libc.ioctl(ref.fd, 0xb703L, 0L) == types.getValue(kind))
        check(start(pid) == before && nativeNamespace(kind, pid.toString()) == identity)
        return ref
        } catch (failure: NativeObserverFailure) { throw failure }
        catch (failure: Throwable) { nativeOwnedVisibilityFailure(pid, kind, failure) }
    }
    private fun attest(pid: Long, namespaces: Map<String, NativeNamespace>, nproc: Int) {
        val status = text(Path.of("/proc/" + pid + "/status"))
        fun field(name: String) = status.lineSequence().single { it.startsWith(name + ":") }.substringAfter(':').trim()
        val coordinates = field("NSpid").split(Regex("\\s+")).map(String::toLong)
        check(coordinates.first() == pid && coordinates.last() == 1L && coordinates.size >= 2)
        check(field("NoNewPrivs") == "1" && field("Seccomp") == "2")
        for (name in listOf("CapEff", "CapPrm", "CapInh", "CapAmb")) check(field(name).toLong(16) == 0L)
        check(field("CapBnd").toLong(16) == OUTER_CAPABILITIES)
        requireExactRlimits(pid, limits) { checkpoint() }.also { check(it.processesSoft == nproc.toLong()) }
        val syscall = text(Path.of("/proc/" + pid + "/syscall")).trim().split(Regex("\\s+"))
        check(syscall.size >= 4 && syscall[0] == "7" && syscall[2] in setOf("1", "0x1"))
        val directory = Path.of("/proc/" + pid + "/fd")
        val fds = Files.newDirectoryStream(directory).use { entries -> entries.map { it.fileName.toString().toInt() } }
        check(fds.size == 9 && fds.toSet() == (0..8).toSet())
        for (fd in fds) {
            nativeObserverBudgetOwner.current?.operation()
            val target = Files.readSymbolicLink(directory.resolve(fd.toString())).toString()
            when (fd) {
                0, 1, 2 -> check(target.matches(Regex("pipe:\\[[0-9]+]")))
                3 -> check(target.matches(Regex("socket:\\[[0-9]+]")))
                in 4..7 -> {
                    val kind = listOf("pid", "user", "net", "mnt")[fd - 4]
                    check(target == kind + ":[" + namespaces.getValue(kind).inode + "]")
                }
                8 -> check(target == "/proc")
            }
        }

        val blackholeTarget = Files.readSymbolicLink(directory.resolve("3")).toString()
        val blackholeInode = blackholeTarget.substringAfter("socket:[").substringBefore(']')
        val udp = text(Path.of("/proc/" + pid + "/net/udp")).lineSequence().drop(1).filter(String::isNotBlank).map { it.trim().split(Regex("\\s+")) }.toList()
        check(udp.size == 1 && udp.single().let { it.size >= 10 && it[1] == "0100007F:0035" && it[9] == blackholeInode })
        check(text(Path.of("/proc/" + pid + "/net/unix")).lineSequence().drop(1).all(String::isBlank))

        val mounts = text(Path.of("/proc/" + pid + "/mountinfo")).lineSequence().filter(String::isNotBlank).map { line ->
            val sides = line.split(" - "); check(sides.size == 2)
            val a = sides[0].split(' '); val b = sides[1].split(' '); check(a.size >= 6 && b.size >= 3)
            Triple(a[4], a[5].split(',').toSet(), b[0])
        }.toList()
        check(mounts.size <= 128 && mounts.map { it.first }.distinct().size == mounts.size)
        check(mounts.none { it.third in setOf("cgroup", "cgroup2", "sysfs") || it.first == "/run" ||
            it.first.startsWith("/run/") || it.first == "/home" || it.first == "/root" || it.first.startsWith("/fixture-output/") })
        check(mounts.single { it.first == "/proc" }.third == "proc")
        check(text(Path.of("/proc/" + pid + "/net/dev")).lineSequence().drop(2).filter(String::isNotBlank).map { it.substringBefore(':').trim() }.toList() == listOf("lo"))
        for (file in listOf("route", "ipv6_route")) {
            text(Path.of("/proc/" + pid + "/net/" + file)).lineSequence().drop(if (file == "route") 1 else 0)
                .filter(String::isNotBlank).forEach { row ->
                    val fields = row.trim().split(Regex("\\s+"))
                    check((if (file == "route") fields.first() else fields.last()) == "lo")
                }
        }
        NativeDnsOwnedDomainContract.requireClosedMountView(mounts,
            mountBindings.filter { it.third }.map { it.second }.toSet(), mountBindings.filterNot { it.third }.map { it.second }.toSet())
        for ((source, destination, _) in mountBindings) {
            checkpoint(); nativeObserverBudgetOwner.current?.operation()
            check(key(Path.of("/proc/" + pid + "/root" + destination)) == key(source)) { "fixture mount source identity mismatch" }
        }
        check(Files.readSymbolicLink(Path.of("/proc/" + pid + "/root/proc/1/ns/pid")).toString() ==
            "pid:[" + namespaces.getValue("pid").inode + "]")
        facts["mountClosureSha256"] = nativeSha(mounts.sortedWith(object : Comparator<Triple<String, Set<String>, String>> {
            override fun compare(a: Triple<String, Set<String>, String>, b: Triple<String, Set<String>, String>): Int =
                a.first.compareTo(b.first)
        }).joinToString("\n").toByteArray())
        facts["privateProcBound"] = true; facts["nonEscapeVerified"] = true
    }

    private fun attestBootstrap(processes: List<Long>, innerPid: Long, namespaces: Map<String, NativeNamespace>) {
        var namespaceRefs = 0
        val ledger = mutableListOf<String>()
        for (pid in processes.filterNot { it == innerPid }) {
            checkpoint()
            val fds = Files.newDirectoryStream(Path.of("/proc/" + pid + "/fd")).use { entries -> entries.map { it.fileName.toString() }.also { check(it.size <= 128) } }
            for (number in fds) {
                nativeObserverBudgetOwner.current?.operation()
                val path = Path.of("/proc/" + pid + "/fd/" + number)
                val target = try { Files.readSymbolicLink(path).toString() } catch (failure: Throwable) { nativeOwnedVisibilityFailure(pid, "pid", failure) }
                if (NativeDnsOwnedDomainContract.bootstrapNamespaceReference(target, namespaces.mapValues { it.value.inode })) namespaceRefs++
                ledger += pid.toString() + ":" + number + ":" + nativeSha(target.toByteArray())
            }
        }
        // Six fixed native references + five host references; process handles,
        // scope capabilities and stream endpoints have separate lifecycle facts.
        check(11 + namespaceRefs + (if (control == "retained-reference") 1 else 0) <= 16)
        facts["bootstrapNamespaceReferenceCount"] = namespaceRefs
        facts["bootstrapFdLedgerSha256"] = nativeOrderedDigest(ledger.sorted())
        facts["hostNamespaceReferenceCount"] = if (control == "retained-reference") 6 else 5
        facts["nativeNamespaceReferenceCount"] = 6
    }

    fun execute(): NativeDnsOwnedResult {
        var primary: Throwable? = null
        var result: NativeDnsOwnedResult? = null
        var rootReaped = false; var scopeAbsent = false; var streamsClosed = false
        var cleanupDiagnosticKinds = "NONE"
        var cleanupDiagnosticCount = 0
        var rootHostPid = 0L; var innerHostPid = 0L
        try {
            check(nativeDnsUnresolvedOwners.isEmpty()) { "native owned-domain cleanup is quarantined" }
            require(control in setOf("positive", "retained-child", "retained-reference", "inaccessible-owned"))
            checkpoint()
            fun pinned(path: Path) = PinnedSecurityExecutable.pin(path, "native DNS fixture", nativeShaFile(path)) { checkpoint() }
            val supervisor = pinned(Path.of("/usr/bin/systemd-run")); val inspector = pinned(Path.of("/usr/bin/systemctl"))
            val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
            val bus = PinnedSystemdBusEndpoint.pin(Path.of("/run/user", uid.toString())) { checkpoint() }
            facts["scopeSupervisorSha256"] = supervisor.sha256; facts["scopeInspectorSha256"] = inspector.sha256
            facts["hostUid"] = uid
            val bubblewrapPin = pinned(bwrap)
            val backend = SystemdScopeController(supervisor, inspector, bus, bubblewrapPin,
                "dns-fixture-" + UUID.randomUUID() + ".scope", limits, java.time.Duration.ofSeconds(30))
            backend.requireUnitAbsent { checkpoint() }
            val nproc = nprocBackstop(32) { checkpoint() }
            val pn = nativeNamespace("net"); val pu = nativeNamespace("user")
            val view = nativeBwrapBase(bwrap, javaHome, input, output, outer = true)
            for (index in view.indices) if (view[index] in setOf("--ro-bind", "--bind")) {
                check(index + 2 < view.size)
                mountBindings += Triple(Path.of(view[index + 1]), view[index + 2], view[index] == "--ro-bind")
            }
            check(mountBindings.size in 1..32 && mountBindings.map { it.second }.distinct().size == mountBindings.size)
            val command = listOf(helper.toString(), "host-gate", nproc.toString(), endMillis.toString(), "--") +
                view + listOf("/fixture-input/loopback-helper",
                    "supervise", caseName, endMillis.toString(), nproc.toString(), pn.device.toString(), pn.inode.toString(),
                    pu.device.toString(), pu.inode.toString(), control)
            supervisor.requireUnchanged { checkpoint() }; inspector.requireUnchanged { checkpoint() }
            bubblewrapPin.requireUnchanged { checkpoint() }; bus.requireUnchanged { checkpoint() }
            val child = ProcessBuilder(backend.wrap(command)).directory(output.toFile()).redirectErrorStream(true).apply {
                environment().clear(); environment().putAll(bus.controlEnvironment)
            }.start()
            process = child; rootHostPid = child.pid(); hostPhase = "PROCESS_STARTED"
            root = LinuxFilesystemSyscalls.openProcessHandle(rootHostPid)
            reader = Thread({
                try {
                    val buffer = ByteArray(64)
                    while (true) {
                        val n = child.inputStream.read(buffer)
                        if (n < 0) { readerEof.set(true); break }
                        outputObservedBytes.addAndGet(n)
                        synchronized(bytes) {
                            if (bytes.size() + n > MAXIMUM_CONTROL_OUTPUT) { readerOverflow.set(true); error("native control output bound") }
                            bytes.write(buffer, 0, n)
                        }
                    }
                } catch (_: Throwable) { readerFailed.set(true) }
                finally { readerFinished.set(true) }
            }, "native-dns-owned-output").also { it.isDaemon = true; it.start() }
            marker("OWNED_HOST_GATE_V2\n")
            facts["firstGateObservedNanos"] = System.nanoTime(); hostPhase = "HOST_GATE_OBSERVED"
            check(child.isAlive && !LinuxFilesystemSyscalls.processExited(checkNotNull(root)))
            val rootStart = start(rootHostPid)
            LinuxFilesystemSyscalls.openProcessExecutable(rootHostPid).use { check(it.identity.key == key(helper)) }
            requireExactRlimits(rootHostPid, limits) { checkpoint() }.also { check(it.processesSoft == nproc.toLong()) }
            val acquired = backend.verifyAttached(child) { checkpoint() }; scope = acquired; acquired.bindCleanupDeadline(cleanupEnd)
            facts["scopeBoundObservedNanos"] = System.nanoTime(); hostPhase = "SCOPE_ATTACHED"
            scopeFd = NativeDnsOwnedFd.open(acquired.identity.cgroupPath.toString(), 0xb0000)
            val identity = checkNotNull(scopeFd).identity
            val identityHash = nativeSha(("acp-cgroup-v1:" + identity.key.device + ":" + identity.key.inode + ":" + identity.mountId).toByteArray())
            check(identityHash == acquired.cleanupFacts().cgroupIdentitySha256)
            killFd = NativeDnsOwnedFd.at(checkNotNull(scopeFd).fd, "cgroup.kill", 0xa0001)
            facts.putAll(mapOf("startedNanos" to startedNanos, "executionEndNanos" to executionEnd, "cleanupEndNanos" to cleanupEnd, "schema" to 2, "caseName" to caseName, "control" to control,
                "unit" to acquired.identity.unitName, "cgroupIdentitySha256" to identityHash,
                "directHostPid" to rootHostPid, "directStart" to rootStart, "pidsMax" to acquired.controllers.pidsMax,
                "memoryMax" to acquired.controllers.memoryMaxBytes, "memorySwapMax" to acquired.controllers.memorySwapMaxBytes,
                "memoryOomGroup" to acquired.controllers.memoryOomGroup, "runtimeMaxMicros" to acquired.controllers.runtimeMaxMicros,
                "timeoutStopMicros" to acquired.controllers.timeoutStopMicros, "cpuQuota" to acquired.controllers.cpuQuotaMicros,
                "cpuPeriod" to acquired.controllers.cpuPeriodMicros, "nproc" to nproc, "fixedRlimitsVerified" to true))
            checkpoint(); child.outputStream.write('H'.code); child.outputStream.flush(); hostPhase = "HOST_RELEASE_FLUSHED"
            marker("OWNED_PID1_GATE_V2\n"); hostPhase = "PID1_GATE_OBSERVED"
            val gate = properties("gate.properties")
            NativeDnsOwnedDomainContract.requireGateShape(gate.stringPropertyNames().associateWith(gate::getProperty), caseName, control, nproc)
            check(gate.getProperty("schema") == "2" && gate.getProperty("caseName") == caseName && gate.getProperty("control") == control)
            for (name in listOf("activeCapabilitiesZero", "noNewPrivileges", "escapeCanariesPassed")) check(gate.getProperty(name) == "true")
            check(gate.getProperty("boundingMask") == "1400" && gate.getProperty("seccomp") == "2" && gate.getProperty("innerPid") == "1")
            val namespaces = listOf("pid", "user", "net", "mnt").associateWith { kind ->
                NativeNamespace(gate.getProperty(kind + "Dev").toLong(), gate.getProperty(kind + "Ino").toLong())
            }
            check(namespaces.all { (kind, value) -> value != nativeNamespace(kind) })
            val candidates = members().filter { pid ->
                val executable = LinuxFilesystemSyscalls.openProcessExecutable(pid).use { it.identity.key }
                if (executable == key(input.resolve("loopback-helper"))) true
                else { check(executable == key(bwrap)); false }
            }
            check(candidates.size == 1); innerHostPid = candidates.single()
            val innerStart = start(innerHostPid)
            check(gate.getProperty("innerStart").toLong() == innerStart)
            pid1 = LinuxFilesystemSyscalls.openProcessHandle(innerHostPid)
            namespaces.forEach { (kind, value) -> bindNamespace(innerHostPid, kind, value) }
            references += NativeDnsOwnedFd.open("/proc/" + innerHostPid + "/root/proc", 0x90000)
            check(references.last().identity.key == LinuxFileKey(gate.getProperty("procDev").toLong(), gate.getProperty("procIno").toLong()))
            check(references.last().identity.mountId == gate.getProperty("procMountId").toLong())
            facts["procDevice"] = references.last().identity.key.device
            facts["procInode"] = references.last().identity.key.inode
            facts["procMountId"] = references.last().identity.mountId
            try {
                attest(innerHostPid, namespaces, nproc)
                attestBootstrap(members(), innerHostPid, namespaces)
            } catch (failure: NativeObserverFailure) { throw failure }
            catch (failure: java.io.IOException) { nativeOwnedVisibilityFailure(innerHostPid, "mnt", failure) }
            catch (failure: SecurityException) { nativeOwnedVisibilityFailure(innerHostPid, "mnt", failure) }
            facts["secondGateObservedNanos"] = System.nanoTime()
            check(start(innerHostPid) == innerStart && innerHostPid in members() && !LinuxFilesystemSyscalls.processExited(checkNotNull(pid1)))
            facts.putAll(mapOf("pid1HostPid" to innerHostPid, "pid1HostStart" to innerStart, "pid1InnerStart" to gate.getProperty("innerStart").toLong(), "pid1InnerPid" to 1,
                "hostPidNsDevice" to nativeNamespace("pid").device, "hostPidNsInode" to nativeNamespace("pid").inode,
                "escapeCanariesPassed" to true, "firstGateHeld" to true, "secondGateHeld" to true))
            namespaces.forEach { (kind, value) -> facts[kind + "Device"] = value.device; facts[kind + "Inode"] = value.inode }
            if (control == "retained-reference") retainedReference = bindNamespace(innerHostPid, "net", namespaces.getValue("net"))
            checkpoint(); releaseAttempted = true; facts["payloadReleased"] = true; facts["payloadReleaseNanos"] = System.nanoTime()
            child.outputStream.write('P'.code); child.outputStream.flush(); hostPhase = "PAYLOAD_RELEASE_FLUSHED"
            val executionRemaining = executionEnd - System.nanoTime(); check(executionRemaining > 0)
            check(child.waitFor(executionRemaining, TimeUnit.NANOSECONDS))
            checkpoint(); rootReaped = true; facts["rootReapedObservedNanos"] = System.nanoTime()
            check(LinuxFilesystemSyscalls.processExited(checkNotNull(root)) && LinuxFilesystemSyscalls.processExited(checkNotNull(pid1)))
            nativeJoin(checkNotNull(reader), endMillis - 5000); checkpoint(); check(!readerFailed.get())
            val terminal = properties("owner.properties"); val inner = properties("inner.properties")
            check(terminal.stringPropertyNames() == setOf("schema", "caseName", "control", "innerPid", "childInnerPid", "childRawStatus",
                "childReaped", "finalEchild", "ownedChildrenZero", "privateProcOnlyPid1", "fixedReferencesClosed", "blackholeJoined", "queryCount", "queryType",
                "observerScans", "observerWork", "observerPids", "observerBytes", "negativeObserved", "negativeInnerPid", "primaryFailure"))
            check(inner.stringPropertyNames() == setOf("caseName", "workerJarSha256", "childPid", "realQueryObserved", "nativeBuiltinWorker", "childReaped",
                "ownerJoined", "streamsClosed", "noAddressAdmitted", "noConnectAdmitted", "workerCapabilitiesZero", "innerBoundingMask", "workerBoundingMask",
                "innerNoNewPrivileges", "workerNoNewPrivileges"))
            check(terminal.getProperty("innerPid") == "1" && terminal.getProperty("childInnerPid").toLong() > 1 && terminal.getProperty("childRawStatus") == "0")
            check(terminal.getProperty("schema") == "2" && terminal.getProperty("caseName") == caseName && terminal.getProperty("control") == control)
            for (name in listOf("childReaped", "finalEchild", "ownedChildrenZero", "privateProcOnlyPid1", "fixedReferencesClosed", "blackholeJoined")) check(terminal.getProperty(name) == "true")
            check(inner.getProperty("caseName") == caseName)
            for (name in listOf("realQueryObserved", "nativeBuiltinWorker", "childReaped", "ownerJoined", "streamsClosed", "noAddressAdmitted", "noConnectAdmitted", "workerCapabilitiesZero")) check(inner.getProperty(name) == "true")
            val count = terminal.getProperty("queryCount").toInt(); val type = terminal.getProperty("queryType").toInt()
            check(count in 1..64 && type in setOf(1, 28))
            for ((name, maximum) in mapOf("observerScans" to 128L, "observerWork" to 32768L, "observerPids" to 16384L, "observerBytes" to 33554432L))
                check(terminal.getProperty(name).toLong() in 0..maximum)
            val negative = terminal.getProperty("negativeObserved") == "true"
            val negativePid = terminal.getProperty("negativeInnerPid").toLong()
            check(if (negative) negativePid > 1 && negativePid != terminal.getProperty("childInnerPid").toLong() else negativePid == 0L)
            if (control == "inaccessible-owned" && negative) {
                val raw = properties("witness.properties")
                val knownWitness = setOf("schema", "pid", "callerPid", "kind", "phase", "callerUid", "callerGid", "targetUid", "targetGid", "startBefore", "startAfter", "namespaceRead")
                val unknownWitness = setOf("schema", "pid", "callerPid", "kind", "phase", "namespaceRead", "identity")
                check(raw.stringPropertyNames() in setOf(knownWitness, unknownWitness))
                check(raw.getProperty("pid").toLong() == negativePid)
                check(raw.getProperty("schema") == "2" && raw.getProperty("kind") == "net" &&
                    raw.getProperty("phase") == "OUTER_CLEANUP" && raw.getProperty("callerPid") == "1" && raw.getProperty("namespaceRead") == "ACCESS_DENIED")
                fun tuple(name: String): List<Long> = raw.getProperty(name).split(',').map(String::toLong).also { values ->
                    check(values.size == 4 && values.all { it in 0..4294967295L })
                }
                if (raw.getProperty("identity") == null) {
                    val caller = NativeNamespaceCredentials(tuple("callerUid"), tuple("callerGid"))
                    val target = NativeNamespaceCredentials(tuple("targetUid"), tuple("targetGid"))
                    val before = raw.getProperty("startBefore").toLong(); val after = raw.getProperty("startAfter").toLong()
                    val overlap = caller.uid.any { it in target.uid } || caller.gid.any { it in target.gid }
                    val witness = NativeObserverFailure.Witness(raw.getProperty("pid").toLong(), "net", "OUTER_CLEANUP", 1,
                        caller, target, before, after, if (before == after && overlap) NativeObserverFailure.ReadStage.CLASSIFY else NativeObserverFailure.ReadStage.STABILITY,
                        NativeObserverFailure.ExceptionKind.NONE)
                    nativeVisibilityAccumulator.recordFirstPossible(witness); nativePersistVisibility()
                } else check(raw.getProperty("identity") == "UNAVAILABLE")
                facts["possibleOwnedVisibilityRefused"] = true
                facts["witnessInnerPid"] = raw.getProperty("pid").toLong()
                facts["witnessPidNamespaceInode"] = namespaces.getValue("pid").inode
            }
            if (control in setOf("retained-child", "inaccessible-owned")) {
                check(negative && child.exitValue() == 1)
                check(terminal.getProperty("primaryFailure") == if (control == "inaccessible-owned") "POSSIBLE_OWNED_VISIBILITY" else "RETAINED_OWNED_CHILD")
            } else check(!negative && child.exitValue() == 0 && terminal.getProperty("primaryFailure") == "NONE")
            supervisor.requireUnchanged { checkpoint() }; inspector.requireUnchanged { checkpoint() }
            bubblewrapPin.requireUnchanged { checkpoint() }; bus.requireUnchanged { checkpoint() }
            inner.setProperty("queryCount", count.toString()); inner.setProperty("queryType", type.toString())
            inner.setProperty("noActiveDescendants", "true"); inner.setProperty("blackholeJoined", "true")
            facts["payloadTerminalObservedNanos"] = System.nanoTime()
            exhaustiveNativeProof = true
            facts["nativeEchild"] = true; facts["nativeReferencesClosed"] = true
            result = NativeDnsOwnedResult(inner, control.takeUnless { it == "positive" })
        } catch (failure: Throwable) {
            primary = failure
            try { primaryDiagnostic = failureSnapshot(failure) } catch (diagnosticFailure: Throwable) { failure.addSuppressed(diagnosticFailure) }
        }
        finally {
            val failures = mutableListOf<Throwable>()
            // Capture before cleanup changes root liveness, including cleanup-only failures.
            if (primaryDiagnostic == null) try { primaryDiagnostic = failureSnapshot(primary) }
            catch (diagnosticFailure: Throwable) { primary?.addSuppressed(diagnosticFailure) }
            facts["scopeKillAttempted"] = false; facts["scopeKillRemovedDuringSignal"] = false
            fun attempt(action: () -> Unit) { try { action(); checkpoint(true) } catch (failure: Throwable) { failures += failure } }
            attempt { process?.outputStream?.close() }
            attempt {
                checkpoint(true)
                // A dead direct root does not prove its acquired domain empty.
                // Only the retained directory's own removed identity can make
                // its kill capability unnecessary before the full absence proof.
                val directory = scopeFd
                val removed = directory?.let {
                    val now = LinuxFilesystemSyscalls.identity(it.fd)
                    check(now.key == it.identity.key && now.mountId == it.identity.mountId)
                    now.linkCount == 0
                } ?: false
                checkpoint(true)
                facts["scopeRemovedBeforeSignal"] = removed
                nativeOwnedCleanupSignal(killFd != null, removed, process?.isAlive == true, root != null,
                    signalScope = {
                        facts["scopeKillAttempted"] = true
                        val written = NativeDnsOwnedLib.libc.write(checkNotNull(killFd).fd, byteArrayOf(49), com.sun.jna.NativeLong(1)).toLong()
                        if (written != 1L) {
                            val errno = com.sun.jna.Native.getLastError()
                            val held = checkNotNull(scopeFd); val now = LinuxFilesystemSyscalls.identity(held.fd)
                            check(NativeDnsOwnedDomainContract.removedScopeAfterFailedSignal(written, errno,
                                now.key == held.identity.key && now.mountId == held.identity.mountId, now.linkCount))
                            // Exact removed acquired leaf, not absence inferred from a name.
                            facts["scopeKillRemovedDuringSignal"] = true
                        }
                    }, signalRoot = { LinuxFilesystemSyscalls.killProcess(checkNotNull(root)) })
            }
            attempt { process?.let {
                checkpoint(true); val remaining = cleanupEnd - System.nanoTime(); check(remaining > 0)
                check(it.waitFor(remaining, TimeUnit.NANOSECONDS)); check(!it.isAlive); rootReaped = true
            } }
            attempt { scope?.requireFixtureRemoved(cleanupEnd); scopeAbsent = scope != null; facts["scopeAbsentObservedNanos"] = System.nanoTime() }
            attempt { checkpoint(true); reader?.let { nativeJoin(it, endMillis) }; check(!readerFailed.get()) }
            process?.let { p -> listOf(p.inputStream, p.errorStream).forEach { stream -> attempt { stream.close() } } }
            streamsClosed = !readerFailed.get() && reader?.isAlive != true
            attempt {
                checkpoint(true)
                check(parentNamespaceState.all { (kind, ns) -> nativeNamespace(kind) == ns })
                check(nativeHostLoopbackFlags() == parentLoopbackState)
                facts["hostStateUnchanged"] = true; facts["streamsClosedObservedNanos"] = System.nanoTime()
            }
            val mayReleaseReferences = NativeDnsOwnedDomainContract.mayReleaseReferences(rootReaped, scopeAbsent, streamsClosed,
                exhaustiveNativeProof, releaseAttempted, failures.isNotEmpty(), System.nanoTime(), cleanupEnd)
            if (mayReleaseReferences) {
                val ordinary = references.filterNot { it === retainedReference }
                ordinary.asReversed().forEach { ref -> attempt { ref.close() } }
                attempt { pid1?.close() }; attempt { root?.close() }
                attempt { killFd?.close() }; attempt { scopeFd?.close() }
                val normalClosed = root != null && pid1 != null && killFd != null && scopeFd != null &&
                    ordinary.all { !it.open } && killFd?.open != true && scopeFd?.open != true && failures.isEmpty()
                facts["normalReferencesClosed"] = normalClosed
                facts["normalReferenceClosedCount"] = ordinary.size
                facts["normalHandlesClosedObservedNanos"] = System.nanoTime()
                if (control == "retained-reference" && result != null) attempt {
                    val deliberate = checkNotNull(retainedReference)
                    check(normalClosed && ordinary.size == 5 && rootReaped && scopeAbsent && streamsClosed && exhaustiveNativeProof && facts["hostStateUnchanged"] == true)
                    check(references.filter { it.open } == listOf(deliberate))
                    val identity = LinuxFilesystemSyscalls.identity(deliberate.fd)
                    check(identity == deliberate.identity)
                    check(!NativeDnsOwnedDomainContract.cleanupComplete(rootReaped, scopeAbsent, streamsClosed, exhaustiveNativeProof,
                        references.all { !it.open }, facts["hostStateUnchanged"] == true, failures.isNotEmpty(), System.nanoTime(), cleanupEnd))
                    facts["retainedReferenceDevice"] = identity.key.device; facts["retainedReferenceInode"] = identity.key.inode
                    facts["retainedReferenceMountId"] = identity.mountId
                    facts["retainedReferenceOnlyOpen"] = true
                    facts["retainedReferenceRefused"] = true
                    facts["retainedReferenceObservedNanos"] = System.nanoTime()
                }
                retainedReference?.let { ref -> attempt { ref.close() } }
                facts["pairedCleanPredicate"] = NativeDnsOwnedDomainContract.cleanupComplete(rootReaped, scopeAbsent, streamsClosed, exhaustiveNativeProof,
                    references.all { !it.open }, facts["hostStateUnchanged"] == true, failures.isNotEmpty(), System.nanoTime(), cleanupEnd)
                facts["pairedCleanObservedNanos"] = System.nanoTime()
                if (failures.isNotEmpty()) nativeDnsUnresolvedOwners.add(this)
            } else {
                nativeDnsUnresolvedOwners.add(this) // retain acquired handles/state on unknown; never reset
                failures += IllegalStateException("native owned-domain references retained")
            }
            facts["rootReaped"] = rootReaped; facts["scopeAbsent"] = scopeAbsent
            facts["streamsJoinedClosed"] = streamsClosed && reader?.isAlive != true
            facts["referencesClosed"] = references.all { !it.open } && killFd?.open != true && scopeFd?.open != true && failures.isEmpty()
            facts["referencesClosedObservedNanos"] = System.nanoTime()
            facts["observationTimely"] = System.nanoTime() < cleanupEnd && System.currentTimeMillis() < endMillis
            facts["observedEndNanos"] = System.nanoTime()
            if (!NativeDnsOwnedDomainContract.cleanupComplete(rootReaped, scopeAbsent, streamsClosed, exhaustiveNativeProof,
                    facts["referencesClosed"] == true, facts["hostStateUnchanged"] == true, failures.isNotEmpty(), System.nanoTime(), cleanupEnd) ||
                facts["observationTimely"] != true)
                failures += IllegalStateException("native owned-domain cleanup unverified")
            cleanupDiagnosticCount = failures.size
            cleanupDiagnosticKinds = failures.map(::nativeFailureCategory).joinToString(".").ifEmpty { "NONE" }
            if (failures.isNotEmpty()) {
                val first = primary ?: failures.removeAt(0); failures.filterNot { it === first }.forEach(first::addSuppressed); primary = first
            }
        }
        primary?.let { failure ->
            try {
                val diagnostic = nativeFinalFailureDiagnostic(primaryDiagnostic ?: failureSnapshot(failure), failure).toMutableMap()
                // Existing cleanup observations only; a diagnostic never upgrades an unknown outcome.
                for (key in listOf("rootReaped", "scopeAbsent", "streamsJoinedClosed", "referencesClosed",
                    "hostStateUnchanged", "observationTimely", "scopeKillAttempted", "scopeKillRemovedDuringSignal")) {
                    diagnostic["cleanup" + key.replaceFirstChar { it.uppercaseChar() }] =
                        (facts[key] as? Boolean)?.toString() ?: "UNAVAILABLE"
                }
                diagnostic["cleanupFailureCount"] = cleanupDiagnosticCount.toString()
                diagnostic["cleanupFailureKinds"] = cleanupDiagnosticKinds
                // A C refusal can arrive while the original timeout enters cleanup. Keep its
                // final whitelisted stages separately, without replacing the primary snapshot.
                failureSnapshot(null).filterKeys { key -> key.startsWith("output") || key.startsWith("reader") ||
                    key.startsWith("fixedStage") || key in setOf("hostGateObserved", "pid1GateObserved") }.forEach { (key, value) ->
                    diagnostic["final" + key.replaceFirstChar { it.uppercaseChar() }] = value
                }
                nativeWriteProperties(output.parent.parent.resolve(output.parent.fileName.toString() + "-owned-diagnostic.properties"), diagnostic)
            } catch (diagnosticFailure: Throwable) { failure.addSuppressed(diagnosticFailure) }
            throw failure
        }
        facts["cleanupVerified"] = true
        facts.putAll(checkNotNull(nativeObserverBudgetOwner.current).counters())
        return checkNotNull(result).copy(domainFacts = facts.toMap())
    }
}
private val nativeDnsUnresolvedOwners = java.util.Collections.synchronizedList(mutableListOf<NativeDnsOwnedDomainOwner>())
private data class NativeDnsOwnedResult(val inner: Properties, val actualNegative: String?, val domainFacts: Map<String, Any> = emptyMap())
internal fun nativeOwnedProperties(raw: ByteArray): Properties {
    check(raw.size in 1..MAXIMUM_CONTROL_FILE)
    val text = raw.toString(Charsets.US_ASCII); check(text.endsWith('\n') && text.all { it == '\n' || it.code in 32..126 })
    val seen = mutableSetOf<String>(); val result = Properties()
    text.dropLast(1).split('\n').forEach { line ->
        val fields = line.split('=', limit = 2)
        check(fields.size == 2 && fields[0].matches(Regex("[A-Za-z][A-Za-z0-9]*")) && fields[1].isNotEmpty() && seen.add(fields[0]))
        result.setProperty(fields[0], fields[1])
    }
    return result
}
private object NativeDnsOwnedLib {
    interface LibC : com.sun.jna.Library {
        fun open(path: String, flags: Int, mode: Int): Int
        fun openat(parent: Int, name: String, flags: Int, mode: Int): Int
        fun close(fd: Int): Int
        fun ioctl(fd: Int, request: Long, argument: Long): Int
        fun write(fd: Int, bytes: ByteArray, count: com.sun.jna.NativeLong): com.sun.jna.NativeLong
    }
    val libc: LibC by lazy { com.sun.jna.Native.load(com.sun.jna.Platform.C_LIBRARY_NAME, LibC::class.java) }
}
private class NativeDnsOwnedFd private constructor(val fd: Int) : AutoCloseable {
    val identity = LinuxFilesystemSyscalls.identity(fd)
    var open = true; private set
    override fun close() {
        if (!open) return
        open = false
        check(NativeDnsOwnedLib.libc.close(fd) == 0) { "native owned reference close unverified" }
    }
    companion object {
        fun open(path: String, flags: Int): NativeDnsOwnedFd {
            val fd = NativeDnsOwnedLib.libc.open(path, flags, 0); check(fd >= 0) { "native owned reference open refused" }
            return try { NativeDnsOwnedFd(fd) } catch (failure: Throwable) { NativeDnsOwnedLib.libc.close(fd); throw failure }
        }
        fun at(parent: Int, name: String, flags: Int): NativeDnsOwnedFd {
            check(name == "cgroup.kill")
            val fd = NativeDnsOwnedLib.libc.openat(parent, name, flags, 0); check(fd >= 0)
            return try { NativeDnsOwnedFd(fd) } catch (failure: Throwable) { NativeDnsOwnedLib.libc.close(fd); throw failure }
        }
    }
}
