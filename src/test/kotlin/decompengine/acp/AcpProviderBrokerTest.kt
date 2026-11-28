package decompengine.acp

import java.io.File
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Credential-free integration control for the host provider broker. Each scenario in [AcpProviderBrokerScenario]
 * runs in a fresh JVM. The only trust customization is the standard `javax.net.ssl.trustStore` properties naming
 * a runtime-generated test CA under build/, so the broker uses the module TLS client's production platform-trust
 * code. This test JVM's trust configuration is never changed.
 */
class AcpProviderBrokerTest {
    private companion object {
        /** Tests in this class that do not run a scenario JVM. */
        const val IN_PROCESS_TESTS = 2
    }

    private val trustedTls = ProviderTestTls("chatgpt.com")
    private val stores = listOf(
        trustedTls.serverStore,
        ProviderTestTls("evil.example", issuer = trustedTls).serverStore,
        ProviderTestTls("chatgpt.com").serverStore,
    )

    @Test fun `credential availability is checked before any resolution connection or prompt`() = run("credentialCheckedBeforeAnySideEffect")
    @Test fun `the broker pins one validated numeric address and never resolves again`() = run("pinnedNumericAddressWithoutReResolution")
    @Test fun `refused destination sets fail before any connection`() = run("refusedDestinationsFailBeforeConnecting")
    @Test fun `TLS keeps the policy host name for SNI and certificate verification`() = run("tlsUsesPolicyHostForSniAndVerification")
    @Test fun `platform trust without the test root refuses the handshake`() = run("platformTrustRefusesTheTestRoot", trusted = false)
    @Test fun `redirects are refused and never followed`() = run("redirectsRefusedAndNeverFollowed")
    @Test fun `upstream head and framing come only from policy and broker values and the validated body`() =
        run("upstreamHeadFromPolicyAndBrokerValues")
    @Test fun `channel requests are bound to one invocation capability and sequence`() = run("channelBoundToCapabilityAndSequence")
    @Test fun `route framing and body refusals send nothing upstream`() = run("refusalsSendNothingUpstream")
    @Test fun `responses never return credentials error bodies or malformed framing to the channel`() = run("responsesAreRedactedAndStrict")
    @Test fun `sandbox launches cannot carry provider authority or expose the credential source`() =
        run("sandboxLaunchesCarryNoProviderAuthority")
    @Test fun `a process started while the channel is live inherits no credential capability or upstream descriptor`() =
        run("childProcessInheritsNoAuthority")
    @Test fun `closing the broker aborts an in-flight upstream exchange as a closed channel`() = run("closeAbortsInFlightExchange")
    @Test fun `the channel capability is delivered once to a broker-owned stream and erased on close`() =
        run("channelCapabilityDeliveredOnceToOwnedStream")
    @Test fun `event stream echoes are detected after JSON decoding and across split deltas`() =
        run("eventStreamEchoesAreDetectedAfterDecoding")
    @Test fun `event stream framing and content coding are strict`() = run("eventStreamFramingAndEncodingAreStrict")
    @Test fun `nested JSON arguments and per-item deltas are scanned`() = run("nestedArgumentsAndPerItemDeltasAreScanned")
    @Test fun `delivery never holds the lock close needs and is bounded`() = run("deliveryNeverHoldsTheCloseLock")
    @Test fun `delivery never commits after its deadline`() = run("deliveryNeverCommitsAfterTheDeadline")
    @Test fun `the source walk fails closed and checks identities below the root`() = run("sourceWalkFailsClosedAndChecksBelowTheRoot")

    @Test
    fun `every scenario has a test`() {
        val covered = AcpProviderBrokerTest::class.java.declaredMethods.count { it.isAnnotationPresent(Test::class.java) } - IN_PROCESS_TESTS
        assertEquals(AcpProviderBrokerScenarios.SCENARIOS.size, covered)
    }

    @Test
    fun `production code cannot reach the substitutable entry point`() {
        // The relay channel factory, the clocks and the connector are seams for credential-free controls only. No
        // member that production code could call may accept one; Kotlin's synthetic accessors are not callable.
        val seams = setOf(
            AcpProviderRelayChannelFactory::class.java, AcpProviderUpstreamConnector::class.java,
            kotlin.jvm.functions.Function0::class.java, java.time.Clock::class.java,
        )
        listOf(AcpProviderBroker::class.java, AcpProviderBroker.Companion::class.java).forEach { owner ->
            (owner.declaredMethods.toList() + owner.declaredConstructors.toList())
                .filter { !it.isSynthetic && !java.lang.reflect.Modifier.isPrivate(it.modifiers) }
                .forEach { member ->
                    assertTrue(member.parameterTypes.none { it in seams }, "${owner.simpleName}.${member.name} accepts a control seam")
                }
        }
        val entry = AcpProviderBroker.Companion::class.java.declaredMethods.single { it.name == "openWith" }
        assertTrue(java.lang.reflect.Modifier.isPrivate(entry.modifiers))
    }

    /** Runs one scenario in a fresh JVM and requires its single success line. */
    private fun run(scenario: String, trusted: Boolean = true) {
        val log = Files.createTempFile(trustedTls.directory, "scenario-", ".log")
        val trustProperties = if (trusted) {
            listOf(
                "-Djavax.net.ssl.trustStore=${trustedTls.writeTrustStore()}", "-Djavax.net.ssl.trustStoreType=PKCS12",
                "-Djavax.net.ssl.trustStorePassword=$PROVIDER_FIXTURE_STORE_PASSWORD",
            )
        } else emptyList()
        val temporary = Files.createDirectories(trustedTls.directory.resolve("tmp"))
        // setsid makes the scenario JVM the leader of its own process group, so cleanup can find every process it
        // started, even one reparented after the JVM exits.
        val process = ProcessBuilder(
            listOf(
                "setsid", Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx512m", "-XX:-UsePerfData",
                "-Djava.io.tmpdir=$temporary",
            ) + trustProperties +
                listOf("-cp", System.getProperty("java.class.path"), AcpProviderBrokerScenarios::class.java.name, scenario) +
                stores.map(Path::toString),
        ).directory(File(System.getProperty("user.dir"))).redirectErrorStream(true).redirectOutput(log.toFile())
            // No ambient operator variables reach the scenario; its own child shell needs only a fixed PATH.
            .also { it.environment().clear(); it.environment()["PATH"] = "/usr/bin:/bin" }
            .start()
        try {
            if (!process.waitFor(120, TimeUnit.SECONDS)) {
                throw AssertionError("scenario JVM did not finish: $scenario\n" + Files.readAllLines(log).joinToString("\n"))
            }
            val output = Files.readAllLines(log)
            assertEquals(0, process.exitValue(), output.joinToString("\n"))
            assertEquals("SCENARIO_OK $scenario", output.last(), output.joinToString("\n"))
        } finally {
            // Whatever ended the wait (a timeout, an interrupt or a failed assertion), never leave a scenario JVM or
            // its children behind, and fail when their termination cannot be confirmed.
            requireGroupTerminated(process, scenario)
        }
    }

    /**
     * Kills the scenario's whole process group (its leader has the scenario JVM's pid) and waits until no member is
     * left alive, whether the JVM exited, timed out or the wait was interrupted. Fails when that cannot be confirmed.
     */
    private fun requireGroupTerminated(process: Process, scenario: String) {
        val group = process.pid()
        val interrupted = Thread.interrupted()
        try {
            val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10)
            while (true) {
                val members = liveGroupMembers(group) + listOfNotNull(process.toHandle().takeIf { it.isAlive }?.pid())
                if (members.isEmpty() || System.nanoTime() - deadline >= 0) break
                members.distinct().forEach { pid -> ProcessHandle.of(pid).ifPresent { it.destroyForcibly() } }
                process.waitFor(20, TimeUnit.MILLISECONDS)
            }
        } finally {
            if (interrupted) Thread.currentThread().interrupt()
        }
        val survivors = liveGroupMembers(group) + listOfNotNull(process.toHandle().takeIf { it.isAlive }?.pid())
        if (survivors.isNotEmpty()) throw AssertionError("scenario $scenario left processes that could not be terminated: $survivors")
    }

    /** Live (non-zombie) processes whose process group is [group], read from /proc. */
    private fun liveGroupMembers(group: Long): List<Long> = Files.list(Path.of("/proc")).use { entries ->
        entries.toList().mapNotNull { entry ->
            val pid = entry.fileName.toString().toLongOrNull() ?: return@mapNotNull null
            val stat = runCatching { Files.readString(entry.resolve("stat")) }.getOrNull() ?: return@mapNotNull null
            // Fields after the parenthesized command: state, ppid, pgrp, ...
            val fields = stat.substringAfterLast(')').trim().split(' ')
            pid.takeIf { fields.size > 2 && fields[0] != "Z" && fields[2].toLongOrNull() == group }
        }
    }
}
