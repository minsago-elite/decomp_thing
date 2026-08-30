package decompengine.oracle.structural

import java.util.Collections

/**
 * An exact-match registry, rather than an adapter injection point. Production callers cannot pass
 * an implementation, registry, observation, receipt, or verification flag. Every future production
 * registration must be constructed here around a host-owned private output sink and independent
 * snapshots. The production table is deliberately empty until that full-recovery adapter lands.
 * The transcript machinery below is test-only and is rejected before lookup by [production].
 */
internal class StructuralReplayAdapterRegistry private constructor(
    registrations: Map<String, Registration>,
    private val testOnly: Boolean,
) {
    private val entries = Collections.unmodifiableMap(LinkedHashMap(registrations))

    private fun replayFresh(request: StructuralReplayRequestV1): AuthenticatedStructuralReplayReceiptsV1 {
        if (!testOnly) {
            replayFail(
                "no production structural replay adapter is registered; " +
                    "a host-owned output-snapshot orchestrator is required",
            )
        }
        val candidates = entries.values.filter { it.request.anchor.profile.id == request.anchor.profile.id }
        if (candidates.size > 1) replayFail("structural replay registry contains an ambiguous profile ID")
        val registration = candidates.singleOrNull()
            ?: replayFail("no production structural replay adapter is registered for ${request.anchor.profile.id}")
        if (registration.request != request) {
            replayFail("structural replay request does not exactly match the registered profile anchors")
        }
        val requestSha256 = StructuralProductionReplayContract.requestSha256(request, registration.limits)
        if (requestSha256 != registration.requestSha256) {
            replayFail("structural replay request digest does not match its registered profile")
        }

        // This branch is test-only. Its metadata transcript is useful for receipt mutation tests,
        // but is categorically ineligible to create the production capability.
        val observation = registration.adapter.observe(request, registration.limits)
        val host = registration.hostVerifier.verify(request, observation, registration.limits)
        val identity = StructuralProductionReplayContract.buildIdentityReceipt(
            request,
            observation,
            host.boundaryReplay,
            host.identityReplay,
            host.model.identityMap.payloadSha256,
            registration.limits,
        )
        val modelBinding = host.model.copy(
            provenanceSha256 = StructuralProductionReplayContract.modelProvenanceSha256(
                identity,
                host.model.identityMap,
                host.model.programModel,
                host.model.structuralObservation,
                host.model.recoveredModelId,
                registration.limits,
            ),
        )
        val model = StructuralProductionReplayContract.buildModelReceipt(identity, modelBinding, registration.limits)
        return AuthenticatedStructuralReplayReceiptsV1(identity, model)
    }

    internal companion object {
        /** No production adapter is registered in this checkpoint; this is an intentional fail-closed state. */
        val production = StructuralReplayAdapterRegistry(emptyMap(), testOnly = false)

        /**
         * Fixed-data test seam. It accepts no adapter or verifier implementation and is never consulted
         * by [production] or by [VerifiedStructuralInputsV1].
         */
        fun testOnlyFixture(
            request: StructuralReplayRequestV1,
            transcript: StructuralReplayTestTranscriptV1,
            limits: StructuralProductionReplayLimitsV1 = StructuralProductionReplayLimitsV1(),
        ): StructuralReplayAdapterRegistry {
            val registration = Registration(
                request,
                StructuralProductionReplayContract.requestSha256(request, limits),
                limits,
                FixedTestObservationAdapter(transcript.observation),
                FixedTestHostVerifier(transcript),
            )
            return StructuralReplayAdapterRegistry(
                mapOf(request.anchor.profile.id to registration),
                testOnly = true,
            )
        }
    }

    internal fun replayFreshForTests(request: StructuralReplayRequestV1): AuthenticatedStructuralReplayReceiptsV1 {
        if (!testOnly) replayFail("production structural replay registry cannot be used through the test-only seam")
        return replayFresh(request)
    }

    private data class Registration(
        val request: StructuralReplayRequestV1,
        val requestSha256: String,
        val limits: StructuralProductionReplayLimitsV1,
        val adapter: StructuralReplayTestAdapter,
        val hostVerifier: StructuralReplayTestHostVerifier,
    )

    private fun interface StructuralReplayTestAdapter {
        fun observe(
            request: StructuralReplayRequestV1,
            limits: StructuralProductionReplayLimitsV1,
        ): StructuralReplayObservationV1
    }

    private fun interface StructuralReplayTestHostVerifier {
        fun verify(
            request: StructuralReplayRequestV1,
            observation: StructuralReplayObservationV1,
            limits: StructuralProductionReplayLimitsV1,
        ): HostReplayResult
    }

    private class FixedTestObservationAdapter(
        private val observation: StructuralReplayObservationV1,
    ) : StructuralReplayTestAdapter {
        override fun observe(
            request: StructuralReplayRequestV1,
            limits: StructuralProductionReplayLimitsV1,
        ): StructuralReplayObservationV1 = observation
    }

    private class FixedTestHostVerifier(
        private val transcript: StructuralReplayTestTranscriptV1,
    ) : StructuralReplayTestHostVerifier {
        override fun verify(
            request: StructuralReplayRequestV1,
            observation: StructuralReplayObservationV1,
            limits: StructuralProductionReplayLimitsV1,
        ): HostReplayResult {
            if (observation != transcript.observation) replayFail("test replay observation was substituted")
            return HostReplayResult(transcript.boundaryReplay, transcript.identityReplay, transcript.model)
        }
    }

    private data class HostReplayResult(
        val boundaryReplay: StructuralBoundaryReplayObservationV1,
        val identityReplay: StructuralIdentityReplayObservationV1,
        val model: StructuralModelReplayObservationV1,
    )
}

/** Immutable values consumed by the fixed test-only registry; never a production adapter API. */
internal data class StructuralReplayTestTranscriptV1(
    val observation: StructuralReplayObservationV1,
    val boundaryReplay: StructuralBoundaryReplayObservationV1,
    val identityReplay: StructuralIdentityReplayObservationV1,
    val model: StructuralModelReplayObservationV1,
)
