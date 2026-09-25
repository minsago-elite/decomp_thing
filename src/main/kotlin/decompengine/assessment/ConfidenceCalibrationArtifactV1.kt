package decompengine.assessment

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.core.StrictJsonLimits
import java.math.BigDecimal
import java.math.RoundingMode
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Exact identities to which a calibrated probability may apply. */
internal data class ConfidenceCalibrationScopeV1(
    val benchmarkId: String,
    val benchmarkRevision: String,
    val inputSha256: String,
    val targetAbiSha256: String,
    val oracleId: String,
    val scoreDefinitionSha256: String,
    val scoreDimension: String,
    val distributionProfileSha256: String,
    val distributionEvidenceSha256: String,
)

internal data class ConfidenceCalibrationIntervalV1(val lower: Double, val upper: Double)

internal data class ConfidenceCalibrationEvaluationV1(
    val calibrationStatus: String,
    val calibratedProbability: Double?,
    val empiricalErrorRate: Double?,
    val fitSampleCount: Int?,
    val validationSampleCount: Int?,
    val validationErrorRate95: ConfidenceCalibrationIntervalV1?,
    val reason: String?,
)

/**
 * A closed v1 calibration artifact. The caller must pin [artifactSha256] through a trusted
 * manifest or equivalent policy; a digest embedded in the artifact cannot authenticate itself.
 */
internal class ConfidenceCalibrationArtifactV1 private constructor(
    val artifactSha256: String,
    private val scope: ConfidenceCalibrationScopeV1,
    private val distributionVerified: Boolean,
    private val minimumFitSamplesPerBand: Int,
    private val minimumValidationSamplesPerBand: Int,
    private val maximumAbsoluteCalibrationError: BigDecimal,
    private val bands: List<Band>,
) {
    /** Unknown scope, unverified distribution, weak support, and excessive error fail closed. */
    fun interpret(score: Double, actualScope: ConfidenceCalibrationScopeV1): ConfidenceCalibrationEvaluationV1 {
        if (scope != actualScope) return uncalibrated("scope-mismatch")
        if (!distributionVerified) return uncalibrated("distribution-unverified")
        if (!score.isFinite() || score < 0.0 || score > 1.0) return uncalibrated("score-out-of-domain")

        val decimalScore = BigDecimal.valueOf(score)
        val band = bands.firstOrNull { candidate ->
            decimalScore >= candidate.lower &&
                (decimalScore < candidate.upper || (candidate.includesUpperBound && decimalScore <= candidate.upper))
        } ?: return uncalibrated("score-outside-bands")

        if (band.fitSamples < minimumFitSamplesPerBand) return uncalibrated("insufficient-fit-support", band)
        if (band.validationSamples < minimumValidationSamplesPerBand) {
            return uncalibrated("insufficient-validation-support", band)
        }
        if ((band.fitRate - band.validationRate).abs() > maximumAbsoluteCalibrationError) {
            return uncalibrated("calibration-error-exceeds-tolerance", band)
        }

        return ConfidenceCalibrationEvaluationV1(
            calibrationStatus = "calibrated",
            calibratedProbability = (BigDecimal.ONE - band.fitRate).toDouble(),
            empiricalErrorRate = band.validationRate.toDouble(),
            fitSampleCount = band.fitSamples,
            validationSampleCount = band.validationSamples,
            validationErrorRate95 = wilson95(band.validationErrors, band.validationSamples),
            reason = null,
        )
    }

    private fun uncalibrated(reason: String, band: Band? = null) = ConfidenceCalibrationEvaluationV1(
        calibrationStatus = "uncalibrated",
        calibratedProbability = null,
        empiricalErrorRate = null,
        fitSampleCount = band?.fitSamples,
        validationSampleCount = band?.validationSamples,
        validationErrorRate95 = null,
        reason = reason,
    )

    private data class Band(
        val lower: BigDecimal,
        val upper: BigDecimal,
        val includesUpperBound: Boolean,
        val fitSamples: Int,
        val fitErrors: Int,
        val fitRate: BigDecimal,
        val validationSamples: Int,
        val validationErrors: Int,
        val validationRate: BigDecimal,
    )

    companion object {
        private val limits = StrictJsonLimits(
            maximumInputBytes = 1024 * 1024,
            maximumCanonicalBytes = 1024 * 1024,
            maximumDepth = 24,
            maximumNodes = 20_000,
            maximumStringBytes = 16 * 1024,
            maximumTotalStringBytes = 128 * 1024,
        )
        /**
         * Authenticate exact canonical bytes against an independently pinned digest, validate the
         * bundled schema, then verify rate/count consistency, disjoint partitions and band coverage.
         */
        fun authenticate(bytes: ByteArray, expectedArtifactSha256: String): ConfidenceCalibrationArtifactV1 {
            require(SHA256.matches(expectedArtifactSha256)) { "expected calibration digest must be lowercase SHA-256" }
            val actualDigest = OracleArtifacts.sha256(bytes)
            require(actualDigest == expectedArtifactSha256) { "calibration artifact digest does not match the pinned digest" }

            val document = OracleJson.parseCanonical(bytes, limits)
            OracleSchemas.validate(SCHEMA_NAME, document)
            val root = document.jsonObject
            val parsedScope = parseScope(root.getValue("scope").jsonObject)
            val distribution = root.getValue("distribution").jsonObject
            val distributionVerified = distribution.string("status") == "verified"
            val support = root.getValue("supportPolicy").jsonObject
            val minimumFit = support.int("minimumFitSamplesPerBand")
            val minimumValidation = support.int("minimumValidationSamplesPerBand")
            val maximumError = support.decimal("maximumAbsoluteCalibrationError")
            val partitions = root.getValue("partitions").jsonObject
            val fitPartition = partitions.getValue("fit").jsonObject
            val validationPartition = partitions.getValue("validation").jsonObject
            require(fitPartition.string("sha256") != validationPartition.string("sha256")) {
                "calibration fit and validation partitions must be distinct"
            }
            val fitPartitionCount = fitPartition.int("sampleCount")
            val validationPartitionCount = validationPartition.int("sampleCount")
            val parsedBands = root.getValue("bands").jsonArray.map { parseBand(it.jsonObject) }
            validateBands(parsedBands, fitPartitionCount, validationPartitionCount)

            return ConfidenceCalibrationArtifactV1(
                artifactSha256 = actualDigest,
                scope = parsedScope,
                distributionVerified = distributionVerified,
                minimumFitSamplesPerBand = minimumFit,
                minimumValidationSamplesPerBand = minimumValidation,
                maximumAbsoluteCalibrationError = maximumError,
                bands = parsedBands,
            )
        }

        private fun parseScope(value: JsonObject) = ConfidenceCalibrationScopeV1(
            benchmarkId = value.string("benchmarkId"),
            benchmarkRevision = value.string("benchmarkRevision"),
            inputSha256 = value.string("inputSha256"),
            targetAbiSha256 = value.string("targetAbiSha256"),
            oracleId = value.string("oracleId"),
            scoreDefinitionSha256 = value.string("scoreDefinitionSha256"),
            scoreDimension = value.string("scoreDimension"),
            distributionProfileSha256 = value.string("distributionProfileSha256"),
            distributionEvidenceSha256 = value.string("distributionEvidenceSha256"),
        )

        private fun parseBand(value: JsonObject) = Band(
            lower = value.decimal("lowerInclusive"),
            upper = value.decimal("upperExclusive"),
            includesUpperBound = value.boolean("includesUpperBound"),
            fitSamples = value.int("fitSamples"),
            fitErrors = value.int("fitErrors"),
            fitRate = value.decimal("fitErrorRate"),
            validationSamples = value.int("validationSamples"),
            validationErrors = value.int("validationErrors"),
            validationRate = value.decimal("validationErrorRate"),
        )

        private fun validateBands(bands: List<Band>, fitPartitionCount: Int, validationPartitionCount: Int) {
            require(bands.first().lower.compareTo(BigDecimal.ZERO) == 0) { "calibration bands must start at score 0" }
            require(bands.last().upper.compareTo(BigDecimal.ONE) == 0 && bands.last().includesUpperBound) {
                "the final calibration band must include score 1"
            }
            require(bands.dropLast(1).none { it.includesUpperBound }) {
                "only the final calibration band may include its upper bound"
            }

            var fitTotal = 0L
            var validationTotal = 0L
            bands.forEachIndexed { index, band ->
                require(band.lower < band.upper) { "calibration bands must have positive width" }
                if (index > 0) {
                    require(bands[index - 1].upper.compareTo(band.lower) == 0) {
                        "calibration bands must be contiguous and non-overlapping"
                    }
                }
                require(band.fitErrors <= band.fitSamples) { "fit errors cannot exceed fit samples" }
                require(band.validationErrors <= band.validationSamples) {
                    "validation errors cannot exceed validation samples"
                }
                require(band.fitRate.compareTo(rateFor(band.fitErrors, band.fitSamples)) == 0) {
                    "fit error rate does not match its sample counts"
                }
                require(band.validationRate.compareTo(rateFor(band.validationErrors, band.validationSamples)) == 0) {
                    "validation error rate does not match its sample counts"
                }
                fitTotal += band.fitSamples
                validationTotal += band.validationSamples
            }
            require(fitTotal == fitPartitionCount.toLong()) { "fit band counts do not match the fit partition" }
            require(validationTotal == validationPartitionCount.toLong()) {
                "validation band counts do not match the validation partition"
            }
        }

        private fun rateFor(errors: Int, samples: Int): BigDecimal {
            if (samples == 0) return BigDecimal.ZERO
            return BigDecimal.valueOf(errors.toLong()).divide(
                BigDecimal.valueOf(samples.toLong()),
                RATE_SCALE,
                RoundingMode.HALF_UP,
            ).stripTrailingZeros()
        }

        private fun wilson95(errors: Int, samples: Int): ConfidenceCalibrationIntervalV1 {
            val n = samples.toDouble()
            val p = errors.toDouble() / n
            val z = 1.959963984540054
            val z2 = z * z
            val denominator = 1.0 + z2 / n
            val center = (p + z2 / (2.0 * n)) / denominator
            val margin = z * kotlin.math.sqrt((p * (1.0 - p) + z2 / (4.0 * n)) / n) / denominator
            return ConfidenceCalibrationIntervalV1(
                lower = (center - margin).coerceAtLeast(0.0),
                upper = (center + margin).coerceAtMost(1.0),
            )
        }

        private const val SCHEMA_NAME = "confidence-calibration-artifact"
        private const val RATE_SCALE = 12
        private val SHA256 = Regex("[0-9a-f]{64}")
    }
}

private fun JsonObject.value(name: String): JsonElement = getValue(name)
private fun JsonObject.string(name: String): String {
    val primitive = value(name) as? JsonPrimitive ?: error("$name must be a string")
    require(primitive.isString) { "$name must be a string" }
    return primitive.content
}
private fun JsonObject.int(name: String): Int = value(name).jsonPrimitive.content.toIntOrNull()
    ?: error("$name must be an integer")
private fun JsonObject.decimal(name: String): BigDecimal = value(name).jsonPrimitive.content.toBigDecimalOrNull()
    ?: error("$name must be a number")
private fun JsonObject.boolean(name: String): Boolean = value(name).jsonPrimitive.content.toBooleanStrictOrNull()
    ?: error("$name must be a boolean")
