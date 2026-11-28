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
    @Test fun `the source walk fails closed and checks identities below the root`() = run("sourceWalkFailsClosedAndChecksBelowTheRoot")

    @Test
    fun `every scenario has a test`() {
        val covered = AcpProviderBrokerTest::class.java.declaredMethods.count { it.isAnnotationPresent(Test::class.java) } - 1
        assertEquals(AcpProviderBrokerScenarios.SCENARIOS.size, covered)
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
        val process = ProcessBuilder(
            listOf(
                Path.of(System.getProperty("java.home"), "bin", "java").toString(), "-Xmx512m", "-XX:-UsePerfData",
                "-Djava.io.tmpdir=$temporary",
            ) + trustProperties +
                listOf("-cp", System.getProperty("java.class.path"), AcpProviderBrokerScenarios::class.java.name, scenario) +
                stores.map(Path::toString),
        ).directory(File(System.getProperty("user.dir"))).redirectErrorStream(true).redirectOutput(log.toFile())
            // No ambient operator variables reach the scenario; its own child shell needs only a fixed PATH.
            .also { it.environment().clear(); it.environment()["PATH"] = "/usr/bin:/bin" }
            .start()
        if (!process.waitFor(120, TimeUnit.SECONDS)) {
            // Never leave a stuck scenario JVM behind: a hung control must fail, not outlive the test.
            process.destroyForcibly().waitFor(10, TimeUnit.SECONDS)
            throw AssertionError("scenario JVM did not finish: $scenario\n" + Files.readAllLines(log).joinToString("\n"))
        }
        val output = Files.readAllLines(log)
        assertEquals(0, process.exitValue(), output.joinToString("\n"))
        assertEquals("SCENARIO_OK $scenario", output.last(), output.joinToString("\n"))
    }
}
