package decompengine.oracle.structural

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.oracle.gcc.GccBundledStructuralReplayOperation
import decompengine.oracle.gcc.GccDriverStructuralBoundaryEvidenceV1
import java.util.Collections
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

/**
 * An exact-match registry, rather than an adapter injection point. Production callers cannot pass
 * an implementation, registry, observation, receipt, or verification flag. Every future production
 * registration must be constructed here around a host-owned private output sink and independent
 * snapshots. Full interface/call/global/type registrations remain unavailable. The separate selected
 * boundary registration below consumes a real contained operation, never a transcript or callback.
 * The transcript machinery below is test-only and is rejected before lookup by [production].
 */
internal class StructuralReplayAdapterRegistry private constructor(
    registrations: Map<String, Registration>,
    private val testOnly: Boolean,
) {
    private val entries = Collections.unmodifiableMap(LinkedHashMap(registrations))

    /** Fixed application wiring; benchmark pins stay in the adapter, scoring stays program-neutral. */
    internal fun admitSelectedBoundary(replay: GccBundledStructuralReplayOperation): VerifiedStructuralInputsV1 {
        if (this !== production || testOnly) replayFail("test replay registry cannot grant production model authority")
        return VerifiedStructuralInputsV1.fromOwnedAdmission(SelectedBoundaryAdmission.capture(replay))
    }

    /** Its only constructor consumes the coordinator-owned operation, not caller-authored evidence. */
    internal class SelectedBoundaryAdmission private constructor(
        replay: GccBundledStructuralReplayOperation,
    ) {
        // Kotlin may expose a synthetic constructor bridge. It must take the permit-guarded
        // operation and execute validation, never accept already-validated raw strings/bytes.
        val profileId: String = replay.profile.profileId
        val inputSha256: String = replay.request.inputSha256
        val programModelSha256: String = replay.export.programModelSha256
        val programModelBytes: Long = replay.export.programModelBytes
        private val binding = replay.export.binding.canonicalBytes
        private val score = captureReport(replay)
        private val assessment = StructuralSelectedFunctionAssessmentV1.derive(
            replay.export.canonicalProgramModelBytes, score, checkpoint = { replay.requireCurrent() },
        )
        val fullExportBindingBytes: ByteArray get() = binding.copyOf()
        val reportBytes: ByteArray get() = score.copyOf()
        val assessmentBytes: ByteArray get() = assessment.copyOf()

        companion object {
            fun capture(replay: GccBundledStructuralReplayOperation): SelectedBoundaryAdmission =
                SelectedBoundaryAdmission(replay)

            private fun captureReport(replay: GccBundledStructuralReplayOperation): ByteArray {
                replay.requireCurrent()
                val profile = replay.profile
                val export = replay.export
                val request = replay.request
                val binding = OracleJson.parseCanonical(export.binding.canonicalBytes).jsonObject
                val lineage = binding.getValue("receiptLineage").jsonObject
                require(request.modelSha256 == export.programModelSha256 &&
                    request.modelBytes.toLong() == export.programModelBytes &&
                    request.fullExportBindingSha256 == export.binding.sha256 &&
                    request.operationRequestSha256 == lineage.getValue("intentSha256").let { (it as JsonPrimitive).content } &&
                    request.inputSha256 == profile.strippedBinary.sha256 && request.imageBase == profile.imageBase &&
                    request.functionOracleSha256 == GccDriverStructuralBoundaryEvidenceV1.FUNCTION_ORACLE_SHA256 &&
                    request.functionOracleBytes == 12_558_460 &&
                    binding["profileId"] == JsonPrimitive(profile.profileId) &&
                    binding["artifactManifestSha256"] == JsonPrimitive(profile.artifactManifestSha256)
                ) { "production boundary replay differs from the host-owned model or fixed profile" }
                val observation = replay.capture.observationBytes
                val metadata = replay.capture.metadataBytes
                StructuralBoundaryReplayWorkerV1.verifyOutput(request, observation, metadata)
                val execution = OracleJson.parseCanonical(replay.executionBytes).jsonObject
                val attachment = OracleJson.parseCanonical(replay.attachmentBytes).jsonObject
                require(attachment["provider"] == JsonPrimitive("kotlin-lease-contained-command-attachment-v1") &&
                    attachment["schemaVersion"] == JsonPrimitive(1) &&
                    attachment["nonce"] == JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)) &&
                    attachment["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(
                        OracleJson.canonicalBytes(JsonObject(attachment - "attachmentSha256")))) &&
                    attachment["requestSha256"] == execution["requestSha256"] && attachment["requestSha256"] != null
                ) { "production boundary replay attachment differs from its contained request" }
                require(execution["provider"] == JsonPrimitive("kotlin-lease-contained-command-execution-v1") &&
                    execution["schemaVersion"] == JsonPrimitive(1) && execution["childExitCode"] == JsonPrimitive(0) &&
                    listOf("unitAbsent", "cgroupAbsent", "processesAbsent").all { execution[it] == JsonPrimitive(true) } &&
                    execution["attachmentSha256"] == JsonPrimitive(OracleArtifacts.sha256(replay.attachmentBytes)) &&
                    execution["executionSha256"] == JsonPrimitive(OracleArtifacts.sha256(
                        OracleJson.canonicalBytes(JsonObject(execution - "executionSha256"))))
                ) { "production boundary replay lacks matching contained execution and proved absence" }
                val parsed = OracleJson.parse(observation, REPORT_LIMITS).jsonObject
                require(parsed["programModelSha256"] == JsonPrimitive(export.programModelSha256) &&
                    parsed["functionOracleSha256"] == JsonPrimitive(request.functionOracleSha256))
                val report = OracleJson.canonicalBytes(JsonObject(mapOf(
                    "provider" to JsonPrimitive("structural-selected-boundary-production-score-v1"),
                    "schemaVersion" to JsonPrimitive(1),
                    "scope" to JsonPrimitive("model-provenance-and-selected-function-boundaries"),
                    "admittedDomains" to JsonArray(listOf("model-provenance", "function-boundaries", "surviving-symbol-identities").map(::JsonPrimitive)),
                    "profileId" to JsonPrimitive(profile.profileId),
                    "inputSha256" to JsonPrimitive(request.inputSha256),
                    "programModelSha256" to JsonPrimitive(export.programModelSha256),
                    "programModelBytes" to JsonPrimitive(export.programModelBytes),
                    "fullExportBindingSha256" to JsonPrimitive(export.binding.sha256),
                    "fullExportBinding" to binding,
                    "functionOracleSha256" to JsonPrimitive(request.functionOracleSha256),
                    "replayRequestSha256" to JsonPrimitive(OracleArtifacts.sha256(request.canonicalBytes)),
                    "replayAttachmentSha256" to JsonPrimitive(OracleArtifacts.sha256(replay.attachmentBytes)),
                    "replayExecutionSha256" to JsonPrimitive(OracleArtifacts.sha256(replay.executionBytes)),
                    "replayCaptureSha256" to JsonPrimitive(OracleArtifacts.sha256(replay.capture.assessmentBytes)),
                    "replayMetadataSha256" to JsonPrimitive(OracleArtifacts.sha256(metadata)),
                    "boundaryObservationSha256" to JsonPrimitive(OracleArtifacts.sha256(observation)),
                    "boundaryObservation" to parsed,
                    "productionVerified" to JsonPrimitive(true), "scored" to JsonPrimitive(true),
                    "complete" to JsonPrimitive(false), "releaseEligible" to JsonPrimitive(false),
                    "unavailableDomains" to JsonArray(listOf("interfaces", "calls", "globals", "types", "calibration").map(::JsonPrimitive)),
                )), REPORT_LIMITS)
                return report
            }
        }
    }

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
        /** Fixed selected-boundary/name admission above; full structural registrations remain unavailable. */
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

private val REPORT_LIMITS = StrictJsonLimits(maximumInputBytes = 64 * 1024 * 1024,
    maximumCanonicalBytes = 64 * 1024 * 1024, maximumNodes = 1_000_000,
    maximumStringBytes = 16 * 1024 * 1024, maximumTotalStringBytes = 48 * 1024 * 1024)

/** Immutable values consumed by the fixed test-only registry; never a production adapter API. */
internal data class StructuralReplayTestTranscriptV1(
    val observation: StructuralReplayObservationV1,
    val boundaryReplay: StructuralBoundaryReplayObservationV1,
    val identityReplay: StructuralIdentityReplayObservationV1,
    val model: StructuralModelReplayObservationV1,
)
