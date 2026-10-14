package decompengine.acp

import decompengine.agent.AGENT_EXECUTION_CONTRACT_VERSION
import decompengine.agent.AgentExecutionOutcome
import decompengine.agent.AgentExecutionReceipt
import decompengine.agent.AgentExecutionRequestBinding
import decompengine.agent.AgentFailure
import decompengine.agent.AgentFailureKind
import java.lang.reflect.InvocationTargetException
import java.security.MessageDigest
import java.util.IdentityHashMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class AcpProviderExecutionEvidenceV3Test {
    @Test
    fun `provider binding advances only invocation schema and cannot be replayed`() {
        val invocation = invocation()
        val transport = snapshot()
        val permit = ownedPermit(invocation)
        assertSame(invocation, invocation.bindProviderExecutionEvidence(permit, transport))
        assertEquals("acp", invocation.providerId)
        assertEquals(3, invocation.schemaVersion)
        assertSame(transport, invocation.providerTransportEvidence)
        assertNull(invocation.completeExecutionEvidence)
        assertFalse(transport.releaseComplete)
        assertFalse(transport.adapterQualified)
        assertFalse(transport.providerCostCancellationProven)
        assertTrue(transport.credentialFreeFixture)
        assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, transport) }
        assertFalse(permitRegistryContains(permit))
    }

    @Test
    fun `successful schema one projection remains unchanged and cannot receive fixture evidence`() {
        val complete = completeEvidence()
        assertEquals(1, complete.schemaVersion)
        val invocation = AcpInvocationEvidenceSnapshot(complete.factoryProvenance,
            AcpExecutionLifecyclePhase.PROMPT_COMPLETED, AcpExecutionCleanupDisposition.VERIFIED,
            complete.negotiatedAgent, complete.wirePromptSha256, complete.diagnostics,
            complete.filesystemAudit, complete.terminalAudit, complete.permissionAudit, complete.sandboxEvidence,
            AcpExecutionEvidenceCompleteness(true, true, true), complete)
        val permit = ownedPermit(invocation)
        assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, snapshot()) }
        assertSame(complete, invocation.completeExecutionEvidence)
        assertEquals(2, invocation.schemaVersion)
        assertEquals(1, complete.schemaVersion)
    }

    @Test
    fun `reject forged permit through callable mangled JVM method`() {
        val invocation = invocation()
        val method = AcpInvocationEvidenceSnapshot::class.java.declaredMethods.single {
            it.name.startsWith("bindProviderExecutionEvidence$")
        }
        val failure = assertFailsWith<InvocationTargetException> {
            method.invoke(invocation, forgedPermit(), snapshot())
        }
        assertTrue(failure.cause is IllegalArgumentException)
        assertEquals(2, invocation.schemaVersion)
        assertNull(invocation.providerTransportEvidence)
    }

    @Test
    fun `reject permit for another receiver and revoke before retry`() {
        val expected = invocation()
        val wrong = invocation()
        val permit = ownedPermit(expected)
        assertFailsWith<IllegalArgumentException> { wrong.bindProviderExecutionEvidence(permit, snapshot()) }
        assertFalse(permitRegistryContains(permit))
        assertFailsWith<IllegalArgumentException> { expected.bindProviderExecutionEvidence(permit, snapshot()) }
        assertEquals(2, expected.schemaVersion)
        assertEquals(2, wrong.schemaVersion)
    }

    @Test
    fun `reject request commitment differing from factory-owned expectation`() {
        val invocation = invocation()
        val permit = ownedPermit(invocation)
        assertFailsWith<IllegalArgumentException> {
            invocation.bindProviderExecutionEvidence(permit, snapshot(requestDigest = OTHER))
        }
        assertFalse(permitRegistryContains(permit))
        assertEquals(2, invocation.schemaVersion)
    }

    @Test
    fun `reject permit for another purpose and consume it`() {
        val invocation = invocation()
        val permit = ownedPermit(invocation, AcpProviderQualificationPurpose.PROCESS_CONFIGURATION)
        assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, snapshot()) }
        assertFalse(permitRegistryContains(permit))
        assertEquals(2, invocation.schemaVersion)
    }

    @Test
    fun `reject late attachment after either public getter freezes absence`() {
        for (read in listOf<(AcpInvocationEvidenceSnapshot) -> Unit>(
            { assertEquals(2, it.schemaVersion) }, { assertNull(it.providerTransportEvidence) },
        )) {
            val invocation = invocation()
            read(invocation)
            val permit = ownedPermit(invocation)
            assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, snapshot()) }
            assertFalse(permitRegistryContains(permit))
            assertEquals(2, invocation.schemaVersion)
        }
    }

    @Test
    fun `receipt publication freezes absent evidence bytes and schema`() {
        val invocation = invocation()
        val receipt = AgentExecutionReceipt(
            AgentExecutionRequestBinding(AGENT_EXECUTION_CONTRACT_VERSION, REQUEST, HASH),
            AgentExecutionOutcome.Failed(AgentFailure(AgentFailureKind.TRANSPORT, "fixed failure")), invocation,
        )
        val permit = ownedPermit(invocation)
        assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, snapshot()) }
        assertSame(invocation, receipt.providerEvidence)
        assertEquals(2, receipt.providerEvidence?.schemaVersion)
        assertNull(invocation.providerTransportEvidence)
    }

    @Test
    fun `reject configuration profile owner and phase binding changes before publication`() {
        val cases = listOf(
            invocation(configuration = OTHER) to snapshot(),
            invocation() to snapshot(profileDigest = OTHER),
            invocation() to snapshot(modelDigest = OTHER),
            invocation() to snapshot(issuerDigest = OTHER),
            invocation() to snapshot(consumerDigest = OTHER),
            invocation(phase = AcpExecutionLifecyclePhase.SESSION_CREATED) to snapshot(),
            invocation() to snapshot(authority = AcpProviderExecutionAuthority.CODEX_CHATGPT_RESPONSES_UNQUALIFIED),
        )
        for ((invocation, transport) in cases) {
            val permit = ownedPermit(invocation)
            assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, transport) }
            assertFalse(permitRegistryContains(permit))
            assertEquals(2, invocation.schemaVersion)
        }
    }

    @Test
    fun `reject raw diagnostics from provider invocation without changing legacy evidence`() {
        val canary = "CANARY-token-account-capability-body-environment"
        val raw = diagnostics().copy(stderr = canary)
        val invocation = invocation(processDiagnostics = raw)
        val transport = snapshot()
        val permit = ownedPermit(invocation)
        val failure = assertFailsWith<IllegalArgumentException> {
            invocation.bindProviderExecutionEvidence(permit, transport)
        }
        assertFalse(failure.toString().contains(canary))
        assertNull(failure.cause)
        assertFalse(permitRegistryContains(permit))
        assertEquals(2, invocation.schemaVersion)
        assertEquals(raw, invocation.diagnostics)
        assertNull(invocation.providerTransportEvidence)
        assertEquals(AcpExecutionCleanupDisposition.VERIFIED, transport.cleanup.disposition)
    }

    @Test
    fun `reject missing session digest altered record bindings and reordered sequences`() {
        assertFailsWith<IllegalArgumentException> { snapshot(session = null, turn = null) }
        assertFailsWith<IllegalArgumentException> { snapshot(session = HASH, turn = null) }
        assertFailsWith<IllegalArgumentException> { snapshot(requests = listOf(request().copy(sessionSha256 = OTHER))) }
        assertFailsWith<IllegalArgumentException> { snapshot(requests = listOf(request().copy(turnSha256 = HASH))) }
        assertFailsWith<IllegalArgumentException> { snapshot(requests = listOf(request().copy(sequence = 2))) }
        assertFailsWith<IllegalArgumentException> { request().copy(sequence = 0) }
    }

    @Test
    fun `reject inconsistent totals and invocation limits`() {
        assertFailsWith<IllegalArgumentException> { snapshot(wireBytes = 4) }
        assertFailsWith<IllegalArgumentException> { snapshot(responseBytes = 4) }
        assertFailsWith<IllegalArgumentException> { snapshot(outputTokens = 4) }
        assertFailsWith<IllegalArgumentException> { snapshot(inputTokens = 4) }
        assertFailsWith<IllegalArgumentException> { snapshot(inputTokens = null) }
        assertFailsWith<IllegalArgumentException> { snapshot(outputLimit = 2) }
        assertFailsWith<IllegalArgumentException> { snapshot(inputLimit = 1) }
        assertFailsWith<IllegalArgumentException> { snapshot(remainingMillis = 0) }
        assertFailsWith<IllegalArgumentException> { snapshot(remainingMillis = PROFILE.bounds.overallTimeout.toMillis() + 1) }
        assertFailsWith<IllegalArgumentException> { snapshot(requests = listOf(request(), request().copy(sequence = 2))) }
        assertFailsWith<IllegalArgumentException> { request().copy(admittedOutputTokens = 2) }
        assertFailsWith<IllegalArgumentException> { request().copy(outputTokens = null) }
        assertFailsWith<IllegalArgumentException> {
            snapshot(requests = listOf(request().copy(terminal = AcpProviderExecutionTerminal.REVOKED),
                request().copy(sequence = 2)), bounds = PROFILE.bounds.copy(maximumRequests = 2))
        }
        val lying = object : AbstractCollection<AcpProviderExecutionRequestEvidence>() {
            override val size: Int = 0
            override fun iterator(): Iterator<AcpProviderExecutionRequestEvidence> =
                listOf(request(), request().copy(sequence = 2)).iterator()
        }
        assertFailsWith<IllegalArgumentException> { snapshot(requests = lying) }
    }

    @Test
    fun `failed request preserves reported usage without charging denied tokens`() {
        val request = request().copy(terminal = AcpProviderExecutionTerminal.RESOURCE_EXHAUSTED, admittedOutputTokens = 0)
        val evidence = snapshot(requests = listOf(request), outputTokens = 0)
        assertEquals(3, evidence.requests.single().outputTokens)
        assertEquals(0, evidence.requests.single().admittedOutputTokens)
        assertEquals(0, evidence.outputTokens)
    }

    @Test
    fun `denial preserves every supplied scalar sequence without fabricating accepted rows`() {
        for (sequence in listOf(Long.MIN_VALUE, -1, 0, 1, Long.MAX_VALUE)) {
            val evidence = snapshot(requests = emptyList(), session = null, turn = null, inputTokens = null,
                denial = AcpProviderExecutionDenialEvidence(sequence, AcpProviderExecutionTerminal.REVOKED))
            assertEquals(sequence, evidence.admissionDenial?.sequence)
            assertTrue(evidence.requests.isEmpty())
        }
        assertFailsWith<IllegalArgumentException> {
            AcpProviderExecutionDenialEvidence(1, AcpProviderExecutionTerminal.COMPLETED)
        }
        assertFailsWith<IllegalArgumentException> {
            snapshot(denial = AcpProviderExecutionDenialEvidence(-1, AcpProviderExecutionTerminal.REVOKED), revoked = false)
        }
    }

    @Test
    fun `bounded signal escalation records actual child outcome and verified cleanup`() {
        for (kind in listOf(AcpProviderChildExitKind.SIGTERM, AcpProviderChildExitKind.SIGKILL)) {
            val guardian = guardian().copy(
                childExitKind = kind, childTerminationSignal = if (kind == AcpProviderChildExitKind.SIGTERM) 15 else 9,
                sigkillSent = kind == AcpProviderChildExitKind.SIGKILL,
            )
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, guardian.disposition)
            assertFalse(snapshot(cleanup = cleanup(guardian)).cleanup.admissionSticky)
        }
        val externallySignalled = guardian().copy(disposition = AcpExecutionCleanupDisposition.UNVERIFIED,
            teardownCause = AcpProviderGuardianTeardownCause.UNKNOWN, sigtermSent = false)
        assertEquals(15, externallySignalled.childTerminationSignal)
        assertFalse(externallySignalled.sigtermSent)
        val handled = guardian().copy(childExitKind = AcpProviderChildExitKind.EXITED,
            childExitStatus = 0, childTerminationSignal = null)
        assertTrue(handled.sigtermSent)
        assertEquals(AcpProviderGuardianTeardownCause.BOUNDED_CANCELLATION, handled.teardownCause)
        val natural = handled.copy(teardownCause = AcpProviderGuardianTeardownCause.NATURAL_EXIT, sigtermSent = false)
        assertEquals(AcpProviderChildExitKind.EXITED, natural.childExitKind)
    }

    @Test
    fun `reject emergency unknown unobserved and incomplete cleanup proof`() {
        for (cause in listOf(AcpProviderGuardianTeardownCause.EMERGENCY, AcpProviderGuardianTeardownCause.TIMED_OUT,
            AcpProviderGuardianTeardownCause.UNKNOWN, AcpProviderGuardianTeardownCause.UNOBSERVED)) {
            assertFailsWith<IllegalArgumentException> { guardian().copy(teardownCause = cause) }
            val unverified = guardian().copy(disposition = AcpExecutionCleanupDisposition.UNVERIFIED, teardownCause = cause)
            assertTrue(snapshot(cleanup = cleanup(unverified, AcpExecutionCleanupDisposition.UNVERIFIED)).cleanup.admissionSticky)
        }
        assertFailsWith<IllegalArgumentException> { guardian().copy(childReaped = false, finalEchildObserved = false) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(remainingDescendants = null) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(remainingDescendants = 1) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(cgroupRemoved = false) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(privateStateRemoved = false) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(descriptorsClosed = false) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(childExitKind = AcpProviderChildExitKind.EXITED) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(teardownCause = AcpProviderGuardianTeardownCause.NATURAL_EXIT) }
        assertFailsWith<IllegalArgumentException> { guardian().copy(childExitKind = AcpProviderChildExitKind.UNOBSERVED, childTerminationSignal = null) }
        assertFailsWith<IllegalArgumentException> { cleanup().copy(router = AcpExecutionCleanupDisposition.UNVERIFIED) }
        assertFailsWith<IllegalArgumentException> { cleanup().copy(broker = AcpExecutionCleanupDisposition.UNVERIFIED) }
        assertFailsWith<IllegalArgumentException> { cleanup().copy(sandbox = AcpExecutionCleanupDisposition.UNVERIFIED) }
        assertFailsWith<IllegalArgumentException> { snapshot(revoked = false) }
    }

    @Test
    fun `partial launch permits verified host cleanup and absent process owners`() {
        val absent = AcpProviderGuardianCleanupEvidence(AcpExecutionCleanupDisposition.NOT_REQUIRED,
            AcpProviderGuardianTeardownCause.UNOBSERVED, false, false, AcpProviderChildExitKind.UNOBSERVED,
            null, null, false, false, null, false, false, false)
        val cleanup = AcpProviderExecutionCleanupEvidence(AcpExecutionCleanupDisposition.VERIFIED,
            AcpExecutionCleanupDisposition.NOT_REQUIRED, AcpExecutionCleanupDisposition.VERIFIED,
            absent, AcpExecutionCleanupDisposition.NOT_REQUIRED)
        val evidence = snapshot(requests = emptyList(), session = null, turn = null, inputTokens = null, cleanup = cleanup)
        val invocation = invocation(phase = AcpExecutionLifecyclePhase.SANDBOX_LAUNCH,
            cleanup = AcpExecutionCleanupDisposition.NOT_REQUIRED)
        invocation.bindProviderExecutionEvidence(ownedPermit(invocation), evidence)
        assertEquals(3, invocation.schemaVersion)
        assertFalse(evidence.cleanup.admissionSticky)
    }

    @Test
    fun `reject accepted exchange when any required owner is marked absent`() {
        assertFailsWith<IllegalArgumentException> {
            snapshot(cleanup = cleanup().copy(router = AcpExecutionCleanupDisposition.NOT_REQUIRED))
        }
        assertFailsWith<IllegalArgumentException> {
            snapshot(cleanup = cleanup().copy(broker = AcpExecutionCleanupDisposition.NOT_REQUIRED))
        }
        assertFailsWith<IllegalArgumentException> {
            snapshot(cleanup = cleanup().copy(sandbox = AcpExecutionCleanupDisposition.NOT_REQUIRED))
        }
        val cleanup = cleanup(guardian().copy(disposition = AcpExecutionCleanupDisposition.UNVERIFIED),
            AcpExecutionCleanupDisposition.UNVERIFIED)
        val invocation = invocation(cleanup = AcpExecutionCleanupDisposition.VERIFIED)
        val permit = ownedPermit(invocation)
        assertFailsWith<IllegalArgumentException> { invocation.bindProviderExecutionEvidence(permit, snapshot(cleanup = cleanup)) }
        assertFalse(permitRegistryContains(permit))
    }

    @Test
    fun `resource evidence rejects weakened declarations and retains negative observed qualification`() {
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(maximumProcesses = 33) }
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(maximumOpenFiles = 256) }
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(maximumAddressSpaceBytes = 4_294_967_296) }
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(maximumSwapBytes = 1) }
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(observedMaximumProcesses = -1) }
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(observedMaximumMemoryBytes = -1) }
        assertFailsWith<IllegalArgumentException> { AcpProviderExecutionResourceEvidence(observedTaskPeak = -1) }
        val prelaunch = AcpProviderExecutionResourceEvidence()
        assertFalse(prelaunch.observationsComplete)
        assertFalse(prelaunch.enforcementVerified)
        assertFalse(prelaunch.taskHeadroomVerified)
        assertFalse(prelaunch.copy(observedTaskPeak = 0).taskHeadroomVerified)
        val exactLimitsWithoutPeak = resources().copy(observedTaskPeak = null)
        assertFalse(exactLimitsWithoutPeak.observationsComplete)
        assertTrue(exactLimitsWithoutPeak.enforcementVerified)
        assertFalse(exactLimitsWithoutPeak.taskHeadroomVerified)
        assertTrue(resources().observationsComplete)
        assertTrue(resources().enforcementVerified)
        assertTrue(resources().taskHeadroomVerified)
        for (peak in listOf(0, 32, 33, Int.MAX_VALUE)) {
            val observation = resources().copy(observedTaskPeak = peak)
            val snapshot = snapshot(resourceEvidence = observation)
            assertEquals(peak, snapshot.resources.observedTaskPeak)
            assertTrue(snapshot.resources.enforcementVerified)
            assertFalse(snapshot.resources.taskHeadroomVerified)
            assertEquals(AcpExecutionCleanupDisposition.VERIFIED, snapshot.cleanup.disposition)
            assertFalse(snapshot.releaseComplete)
        }
        for (observation in listOf(resources().copy(observedMaximumProcesses = 31),
            resources().copy(observedMaximumOpenFiles = 256), resources().copy(observedMaximumMemoryBytes = 1),
            resources().copy(observedMaximumSwapBytes = 1), resources().copy(observedMaximumAddressSpaceBytes = null))) {
            val snapshot = snapshot(resourceEvidence = observation)
            assertFalse(snapshot.resources.enforcementVerified)
            assertFalse(snapshot.resources.taskHeadroomVerified)
        }
        assertTrue(resources().copy(observedTaskPeak = 31).taskHeadroomVerified)
    }

    @Test
    fun `evidence lists are defensive and expose no raw authority or secret-bearing scalar`() {
        val source = arrayListOf(request())
        val evidence = snapshot(requests = source)
        source.clear()
        assertEquals(1, evidence.requests.size)
        assertFailsWith<UnsupportedOperationException> { (evidence.requests as MutableList).clear() }
        val types = listOf(AcpProviderInvocationEvidenceSnapshot::class.java,
            AcpProviderExecutionDescriptorEvidence::class.java, AcpProviderExecutionRequestEvidence::class.java,
            AcpProviderExecutionDenialEvidence::class.java, AcpProviderGuardianCleanupEvidence::class.java)
        for (type in types) {
            assertTrue(type.declaredFields.none { field -> field.type in listOf(ByteArray::class.java,
                Throwable::class.java, java.net.URI::class.java, java.net.URL::class.java) })
            assertTrue(type.declaredFields.filter { it.type == String::class.java }.all { it.name.endsWith("Sha256") })
        }
        val canary = "CANARY-token-account-capability-raw-url-body-environment"
        for (digest in listOf(canary, HASH.uppercase(), HASH.dropLast(1), "g".repeat(64))) {
            val error = assertFailsWith<IllegalArgumentException> { snapshot(modelDigest = digest) }
            assertFalse(error.toString().contains(canary))
            assertNull(error.cause)
        }
        val publicStrings = listOf(evidence.toString(), evidence.requests.toString(), evidence.descriptors.toString(),
            evidence.cleanup.toString(), evidence.resources.toString(), evidence.bounds.toString())
        assertTrue(publicStrings.none { canary in it || "https://" in it || "Bearer " in it })
    }

    private fun invocation(configuration: String = CONFIGURATION,
        phase: AcpExecutionLifecyclePhase = AcpExecutionLifecyclePhase.PROMPT_DISPATCHED,
        cleanup: AcpExecutionCleanupDisposition = AcpExecutionCleanupDisposition.UNVERIFIED,
        processDiagnostics: AcpProcessDiagnostics? = if (cleanup == AcpExecutionCleanupDisposition.VERIFIED) diagnostics() else null,
    ) = AcpInvocationEvidenceSnapshot(
        AcpHarnessProvenance("acp", "provider-fixture", AGENT_EXECUTION_CONTRACT_VERSION,
            ACP_STABLE_PROTOCOL_VERSION, ACP_KOTLIN_SDK_VERSION, configuration, false),
        phase, cleanup, null, if (phase >= AcpExecutionLifecyclePhase.PROMPT_DISPATCHED) HASH else null,
        processDiagnostics,
        emptyList(), emptyList(), emptyList(), null, AcpExecutionEvidenceCompleteness(true, true, true), null,
    )

    private fun diagnostics() = AcpProcessDiagnostics(7, 0, "", false, 0, 1024, false,
        false, false, emptyList(), "linux-bubblewrap", true, true)

    private fun completeEvidence(): AcpExecutionEvidenceSnapshot {
        val sandbox = AcpSandboxEvidence("linux-bubblewrap", "0.13.0", HASH, 365,
            HASH, HASH, HASH, HASH, emptyList(), AcpSandboxResourceLimits(), AcpRuntimeClosureLimits(),
            true, true, true, true, true, true, true, true, HASH, null, emptyList(), emptyList(), emptyList())
        return AcpExecutionEvidenceSnapshot(requireNotNull(invocation().factoryProvenance),
            AcpNegotiatedAgentEvidence(ACP_STABLE_PROTOCOL_VERSION, "fixture", "1", null,
                AcpNegotiatedCapabilitiesEvidence(false, false, false, false, false, false, false)),
            HASH, diagnostics(), emptyList(), emptyList(), emptyList(), sandbox)
    }

    private fun snapshot(requests: Collection<AcpProviderExecutionRequestEvidence> = listOf(request()),
        wireBytes: Long = requests.sumOf { it.wireRequestBytes.toLong() },
        responseBytes: Long = requests.sumOf { it.responseBytes },
        outputTokens: Long = requests.sumOf { it.admittedOutputTokens.toLong() },
        inputTokens: Long? = if (requests.isEmpty() || requests.any { it.inputTokens == null }) null
            else requests.sumOf { requireNotNull(it.inputTokens).toLong() },
        session: String? = HASH, turn: String? = OTHER,
        requestDigest: String = REQUEST,
        profileDigest: String = PROFILE.descriptorSha256, modelDigest: String = digest(PROFILE.model),
        issuerDigest: String = providerExecutionEvidenceIssuerSha256(CONFIGURATION, PROFILE.descriptorSha256),
        consumerDigest: String = providerExecutionEvidenceConsumerSha256(REQUEST, INVOCATION),
        authority: AcpProviderExecutionAuthority = AcpProviderExecutionAuthority.CREDENTIAL_FREE_LOOPBACK_TLS_V1,
        denial: AcpProviderExecutionDenialEvidence? = null, revoked: Boolean = true,
        bounds: AcpProviderTransportBounds = PROFILE.bounds,
        outputLimit: Int = bounds.maximumOutputTokens, inputLimit: Long? = null,
        remainingMillis: Long = PROFILE.bounds.overallTimeout.toMillis(),
        cleanup: AcpProviderExecutionCleanupEvidence = cleanup(),
        resourceEvidence: AcpProviderExecutionResourceEvidence = resources(),
    ) = AcpProviderInvocationEvidenceSnapshot(authority, HASH, HASH, profileDigest, modelDigest,
        AcpProviderRuntimeAdapter.CODEX_GATEWAY_RESPONSES_V1, PROFILE.reasoning,
        AcpProviderExecutionDescriptorEvidence(CONFIGURATION, issuerDigest, consumerDigest,
            HASH, HASH, HASH, HASH, HASH, HASH, HASH, HASH), INVOCATION, requestDigest, session, turn,
        bounds, outputLimit, inputLimit, remainingMillis, resourceEvidence,
        wireBytes, responseBytes, outputTokens, inputTokens, revoked, denial, requests, cleanup)

    private fun request() = AcpProviderExecutionRequestEvidence(1, HASH, OTHER, HASH, OTHER, 5, 7, HASH,
        2, 3, 3, AcpProviderExecutionTerminal.COMPLETED)

    private fun resources() = AcpProviderExecutionResourceEvidence(observedMaximumProcesses = 32,
        observedMaximumOpenFiles = 128, observedMaximumAddressSpaceBytes = 2_147_483_648,
        observedMaximumMemoryBytes = 2_147_483_648, observedMaximumSwapBytes = 0, observedTaskPeak = 7)

    private fun guardian() = AcpProviderGuardianCleanupEvidence(AcpExecutionCleanupDisposition.VERIFIED,
        AcpProviderGuardianTeardownCause.BOUNDED_CANCELLATION, true, false, AcpProviderChildExitKind.SIGTERM,
        null, 15, true, true, 0, true, true, true)

    private fun cleanup(guardian: AcpProviderGuardianCleanupEvidence = guardian(),
        disposition: AcpExecutionCleanupDisposition = AcpExecutionCleanupDisposition.VERIFIED,
    ) = AcpProviderExecutionCleanupEvidence(disposition, AcpExecutionCleanupDisposition.VERIFIED,
        AcpExecutionCleanupDisposition.VERIFIED, guardian, AcpExecutionCleanupDisposition.VERIFIED)

    private fun forgedPermit(): AcpProviderQualificationPermit {
        val type = AcpHarnessFactory::class.java.declaredClasses.single { it.simpleName == "FactoryProviderPermit" }
        return type.getDeclaredConstructor().apply { isAccessible = true }.newInstance() as AcpProviderQualificationPermit
    }

    /** Tests mint no production authority: only private owner registry state is constructed reflectively. */
    private fun ownedPermit(consumer: Any,
        purpose: AcpProviderQualificationPurpose = AcpProviderQualificationPurpose.INVOCATION_EVIDENCE,
    ): AcpProviderQualificationPermit {
        val permit = forgedPermit()
        val recordType = AcpHarnessFactory::class.java.declaredClasses.single { it.simpleName == "ProviderPermitRecord" }
        val record = recordType.getDeclaredConstructor(Any::class.java, AcpProviderQualificationPurpose::class.java, String::class.java)
            .apply { isAccessible = true }.newInstance(consumer, purpose,
                if (purpose == AcpProviderQualificationPurpose.INVOCATION_EVIDENCE) REQUEST else null)
        val registry = registry()
        synchronized(registry) { registry[permit] = record }
        return permit
    }

    private fun registry(): IdentityHashMap<AcpProviderQualificationPermit, Any> {
        val value = AcpHarnessFactory::class.java.getDeclaredField("providerPermits")
            .apply { isAccessible = true }.get(AcpHarnessFactory)
        @Suppress("UNCHECKED_CAST")
        return value as IdentityHashMap<AcpProviderQualificationPermit, Any>
    }

    private fun permitRegistryContains(permit: AcpProviderQualificationPermit): Boolean =
        registry().let { synchronized(it) { it.containsKey(permit) } }

    private fun digest(value: String): String = MessageDigest.getInstance("SHA-256").digest(value.toByteArray())
        .joinToString("") { "%02x".format(it) }

    companion object {
        private val PROFILE = AcpProviderQualificationProfile.CREDENTIAL_FREE
        private val HASH = "a".repeat(64)
        private val OTHER = "b".repeat(64)
        private val CONFIGURATION = "1".repeat(64)
        private val REQUEST = "2".repeat(64)
        private val INVOCATION = "3".repeat(64)
    }
}
