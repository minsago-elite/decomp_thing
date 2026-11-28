package decompengine.oracle.fulltree.repair

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Exact-byte recorded identity. No decoding, extraction, owner inference or authentication. */
internal object ShardDiagnosticNormalizerV1 {
    private val policy = JsonObject(mapOf(
        "id" to JsonPrimitive("full-tree-shard-diagnostic-exact-v1"),
        "version" to JsonPrimitive(1),
        "normalizations" to JsonArray(emptyList()),
        "payload" to JsonPrimitive("ordered-exact-stream-spans-v1"),
    ))

    val normalizerSha256: String by lazy(LazyThreadSafetyMode.PUBLICATION) {
        val context = DiagnosticComputationContext()
        diagnosticHash(context, canonical(context, policy, 136), "canonical normalizer policy hashing")
    }

    fun normalize(observation: RecordedDiagnosticObservation): NormalizedDiagnostic {
        val context = observation.context
        context.meter.begin("diagnostic normalization entry")
        val policyHash = diagnosticHash(context, canonical(context, policy, 136), "canonical normalizer policy hashing")
        diagnosticCapacity(observation.payloadBytes <= context.limits.diagnosticPayloadBytes)
        // Hash private admitted bytes directly; getters remain bounded defensive copies.
        val payloadHash = observation.payloadHash()
        context.meter.end("diagnostic normalization exit")
        return NormalizedDiagnostic(policyHash, payloadHash, observation.payloadBytes)
    }

    /** Reuses construction's context and normalize's meter; no phase can reset the operation budget. */
    fun stableKey(observation: RecordedDiagnosticObservation, normalized: NormalizedDiagnostic): String {
        val context = observation.context
        context.meter.begin("stable diagnostic identity entry")
        // The nullable/raw DTO is a claim, never an admitted preimage or verified capability.
        context.digest(normalized.normalizerSha256)
        context.digest(normalized.normalizedKeySha256)
        val actual = normalize(observation)
        diagnosticCapacity(context.equal(actual.normalizerSha256, normalized.normalizerSha256))
        diagnosticCapacity(context.equal(actual.normalizedKeySha256, normalized.normalizedKeySha256))
        diagnosticCapacity(actual.payloadBytes == normalized.payloadBytes)
        val binding = JsonObject(mapOf(
            "normalizerSha256" to JsonPrimitive(normalized.normalizerSha256),
            "stage" to JsonPrimitive(observation.stage.name.lowercase()),
            "toolIdentitySha256" to JsonPrimitive(observation.toolIdentitySha256),
            "normalizedKeySha256" to JsonPrimitive(normalized.normalizedKeySha256),
        ))
        val identity = JsonObject(mapOf(
            "domain" to JsonPrimitive("full-tree-shard-scheduler-v1/diagnostic"),
            "binding" to binding,
        ))
        // "compile" and "link" differ by three bytes; all other fields have fixed admitted lengths.
        val length = if (observation.stage == DiagnosticStage.COMPILE) 382 else 379
        val result = "diagnostic-${diagnosticHash(context, canonical(context, identity, length), "v1 stable diagnostic identity hashing")}"
        context.meter.end("stable diagnostic identity exit")
        return result
    }

    private fun canonical(context: DiagnosticComputationContext, value: JsonElement, bytes: Int): ByteArray {
        // Only these two fixed schemas reach this adapter (<=382 bytes, <=64-byte scalar values).
        // Reserve conservative codec scratch/copy/scan costs BEFORE the opaque codec call. OracleJson
        // has its own bounded internal cadence; local byte passes below use the shared 256-unit meter.
        context.meter.ensure(bytes * 16L)
        context.reserve(bytes * 32L, "before canonical diagnostic encoding allocation")
        context.meter.charge(bytes * 16L, "reserving canonical diagnostic codec work")
        val result = OracleJson.canonicalBytes(value, StrictJsonLimits(
            maximumInputBytes = bytes, maximumCanonicalBytes = bytes,
            maximumDepth = 4, maximumNodes = 16, maximumStringBytes = 64,
            maximumTotalStringBytes = bytes, maximumNumberCharacters = 19,
        ), context.meter::begin)
        diagnosticCapacity(result.size == bytes)
        return result
    }
}
