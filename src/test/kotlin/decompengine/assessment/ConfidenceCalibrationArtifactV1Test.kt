package decompengine.assessment

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue

class ConfidenceCalibrationArtifactV1Test {
    @Test
    fun authenticatedSupportedBandProducesHoldoutCheckedProbabilityAndWilsonInterval() {
        val artifact = load(document())

        val result = artifact.interpret(0.6, scope())

        assertEquals("calibrated", result.calibrationStatus)
        assertEquals(0.9, assertNotNull(result.calibratedProbability), 1e-12)
        assertEquals(0.1, assertNotNull(result.empiricalErrorRate), 1e-12)
        assertEquals(10, result.fitSampleCount)
        assertEquals(20, result.validationSampleCount)
        val interval = assertNotNull(result.validationErrorRate95)
        assertTrue(interval.lower in 0.02..0.04)
        assertTrue(interval.upper in 0.28..0.32)
        assertNull(result.reason)
    }

    @Test
    fun mismatchedScopeUnverifiedDistributionAndOutOfDomainScoresStayUncalibrated() {
        val verified = load(document())
        val mismatched = verified.interpret(0.6, scope().copy(targetAbiSha256 = hash('f')))
        assertUncalibrated(mismatched, "scope-mismatch")

        val unverified = load(document(distributionStatus = "unverified"))
        assertUncalibrated(unverified.interpret(0.6, scope()), "distribution-unverified")

        assertUncalibrated(verified.interpret(1.1, scope()), "score-out-of-domain")
        assertUncalibrated(verified.interpret(Double.NaN, scope()), "score-out-of-domain")
    }

    @Test
    fun supportAndEmpiricalToleranceAreEnforcedPerBand() {
        val weakSupport = load(document(
            fitSamples = 2,
            fitErrors = 1,
            fitRate = 0.5,
            validationSamples = 2,
            validationErrors = 1,
            validationRate = 0.5,
        ))
        assertUncalibrated(weakSupport.interpret(0.5, scope()), "insufficient-fit-support")

        val weakValidation = load(document(
            validationSamples = 2,
            validationErrors = 0,
            validationRate = 0.0,
        ))
        assertUncalibrated(weakValidation.interpret(0.5, scope()), "insufficient-validation-support")

        val outsideTolerance = load(document(
            fitSamples = 10,
            fitErrors = 1,
            fitRate = 0.1,
            validationSamples = 20,
            validationErrors = 8,
            validationRate = 0.4,
            maximumAbsoluteError = 0.1,
        ))
        assertUncalibrated(
            outsideTolerance.interpret(0.5, scope()),
            "calibration-error-exceeds-tolerance",
        )
    }

    @Test
    fun digestIsExternallyPinnedAndRatesMustMatchObservedCounts() {
        val bytes = OracleJson.canonicalBytes(document())
        assertFailsWith<IllegalArgumentException> {
            ConfidenceCalibrationArtifactV1.authenticate(bytes, hash('f'))
        }

        val inconsistentRate = document(validationRate = 0.2)
        assertFailsWith<IllegalArgumentException> { load(inconsistentRate) }
    }

    @Test
    fun fitAndValidationPartitionsMustBeDistinctAndBandsMustCoverTheDomain() {
        assertFailsWith<IllegalArgumentException> {
            load(document(fitPartitionHash = hash('a'), validationPartitionHash = hash('a')))
        }

        val twoBands = twoBandDocument()
        val originalBands = twoBands.getValue("bands") as JsonArray
        val secondBand = originalBands[1] as JsonObject
        val withGap = JsonObject(twoBands + ("bands" to JsonArray(listOf(
            originalBands[0],
            JsonObject(secondBand + ("lowerInclusive" to JsonPrimitive(0.6))),
        ))))
        assertFailsWith<IllegalArgumentException> { load(withGap) }
    }

    @Test
    fun adjacentBandsAreUnambiguousAtTheirSharedBoundary() {
        val result = load(twoBandDocument()).interpret(0.5, scope())

        assertEquals("calibrated", result.calibrationStatus)
        assertEquals(0.8, assertNotNull(result.calibratedProbability), 1e-12)
        assertEquals(5, result.fitSampleCount)
        assertEquals(10, result.validationSampleCount)
    }

    private fun twoBandDocument(): JsonObject {
        val first = JsonObject(mapOf(
            "lowerInclusive" to JsonPrimitive(0.0),
            "upperExclusive" to JsonPrimitive(0.5),
            "includesUpperBound" to JsonPrimitive(false),
            "fitSamples" to JsonPrimitive(5),
            "fitErrors" to JsonPrimitive(0),
            "fitErrorRate" to JsonPrimitive(0.0),
            "validationSamples" to JsonPrimitive(10),
            "validationErrors" to JsonPrimitive(1),
            "validationErrorRate" to JsonPrimitive(0.1),
        ))
        val second = JsonObject(mapOf(
            "lowerInclusive" to JsonPrimitive(0.5),
            "upperExclusive" to JsonPrimitive(1.0),
            "includesUpperBound" to JsonPrimitive(true),
            "fitSamples" to JsonPrimitive(5),
            "fitErrors" to JsonPrimitive(1),
            "fitErrorRate" to JsonPrimitive(0.2),
            "validationSamples" to JsonPrimitive(10),
            "validationErrors" to JsonPrimitive(1),
            "validationErrorRate" to JsonPrimitive(0.1),
        ))
        return JsonObject(document() + ("bands" to JsonArray(listOf(first, second))))
    }

    private fun assertUncalibrated(result: ConfidenceCalibrationEvaluationV1, reason: String) {
        assertEquals("uncalibrated", result.calibrationStatus)
        assertNull(result.calibratedProbability)
        assertNull(result.empiricalErrorRate)
        assertNull(result.validationErrorRate95)
        assertEquals(reason, result.reason)
    }

    private fun load(document: JsonObject): ConfidenceCalibrationArtifactV1 {
        val bytes = OracleJson.canonicalBytes(document)
        return ConfidenceCalibrationArtifactV1.authenticate(bytes, OracleArtifacts.sha256(bytes))
    }

    private fun document(
        distributionStatus: String = "verified",
        fitSamples: Int = 10,
        fitErrors: Int = 1,
        fitRate: Double = 0.1,
        validationSamples: Int = 20,
        validationErrors: Int = 2,
        validationRate: Double = 0.1,
        maximumAbsoluteError: Double = 0.15,
        minimumFitSamples: Int = 5,
        minimumValidationSamples: Int = 10,
        fitPartitionHash: String = hash('a'),
        validationPartitionHash: String = hash('b'),
    ): JsonObject {
        val fitCount = fitSamples
        val validationCount = validationSamples
        val band = JsonObject(mapOf(
            "lowerInclusive" to JsonPrimitive(0.0),
            "upperExclusive" to JsonPrimitive(1.0),
            "includesUpperBound" to JsonPrimitive(true),
            "fitSamples" to JsonPrimitive(fitSamples),
            "fitErrors" to JsonPrimitive(fitErrors),
            "fitErrorRate" to JsonPrimitive(fitRate),
            "validationSamples" to JsonPrimitive(validationSamples),
            "validationErrors" to JsonPrimitive(validationErrors),
            "validationErrorRate" to JsonPrimitive(validationRate),
        ))
        return JsonObject(mapOf(
            "schemaVersion" to JsonPrimitive(1),
            "method" to JsonPrimitive("disjoint-fit-holdout-validation-wilson-95-v1"),
            "scope" to scopeJson(),
            "distribution" to JsonObject(mapOf(
                "status" to JsonPrimitive(distributionStatus),
                "outOfDistributionAction" to JsonPrimitive("uncalibrated"),
            )),
            "supportPolicy" to JsonObject(mapOf(
                "minimumFitSamplesPerBand" to JsonPrimitive(minimumFitSamples),
                "minimumValidationSamplesPerBand" to JsonPrimitive(minimumValidationSamples),
                "maximumAbsoluteCalibrationError" to JsonPrimitive(maximumAbsoluteError),
            )),
            "partitions" to JsonObject(mapOf(
                "fit" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(fitPartitionHash),
                    "sampleCount" to JsonPrimitive(fitCount),
                )),
                "validation" to JsonObject(mapOf(
                    "sha256" to JsonPrimitive(validationPartitionHash),
                    "sampleCount" to JsonPrimitive(validationCount),
                )),
            )),
            "bands" to JsonArray(listOf(band)),
        ))
    }

    private fun scopeJson() = JsonObject(mapOf(
        "benchmarkId" to JsonPrimitive("example-program"),
        "benchmarkRevision" to JsonPrimitive("revision-1"),
        "inputSha256" to JsonPrimitive(hash('1')),
        "targetAbiSha256" to JsonPrimitive(hash('2')),
        "oracleId" to JsonPrimitive("oracle-v1"),
        "scoreDefinitionSha256" to JsonPrimitive(hash('3')),
        "scoreDimension" to JsonPrimitive("function-boundary"),
        "distributionProfileSha256" to JsonPrimitive(hash('4')),
        "distributionEvidenceSha256" to JsonPrimitive(hash('5')),
    ))

    private fun scope() = ConfidenceCalibrationScopeV1(
        benchmarkId = "example-program",
        benchmarkRevision = "revision-1",
        inputSha256 = hash('1'),
        targetAbiSha256 = hash('2'),
        oracleId = "oracle-v1",
        scoreDefinitionSha256 = hash('3'),
        scoreDimension = "function-boundary",
        distributionProfileSha256 = hash('4'),
        distributionEvidenceSha256 = hash('5'),
    )

    private fun hash(character: Char) = character.toString().repeat(64)
}
