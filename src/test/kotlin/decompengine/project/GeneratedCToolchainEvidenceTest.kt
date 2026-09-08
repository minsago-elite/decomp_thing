package decompengine.project

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GeneratedCToolchainEvidenceTest {
    @Test
    fun `version probe retains only the first line and bounds incomplete observations`() {
        assertEquals("fixture version", GeneratedCToolchainEvidence.probe(
            listOf("/usr/bin/printf", "fixture version\nsecond line\n"), 2_000, 128))
        assertEquals("unavailable", GeneratedCToolchainEvidence.probe(
            listOf("/usr/bin/printf", "ordinary fixture text"), 2_000, 8))
        assertEquals("unavailable", GeneratedCToolchainEvidence.probe(
            listOf("/usr/bin/sleep", "1"), 20, 128))
        assertEquals("unavailable", GeneratedCToolchainEvidence.probe(
            listOf("/usr/bin/false"), 2_000, 128))
    }

    @Test
    fun `toolchain report observes the selected compiler and serializes valid JSON`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration +
            ("compiler-driver" to listOf("/usr/bin/printf")))
        val report = Json.parseToJsonElement(GeneratedCToolchainEvidence.render(profile)).jsonObject
        assertEquals("/usr/bin/printf", report.getValue("compilerCommand").jsonPrimitive.content)
        assertTrue(report.getValue("compilerVersion").jsonPrimitive.content.startsWith("printf"))
        assertTrue(report.getValue("make").jsonPrimitive.content.startsWith("GNU Make"))
    }

    @Test
    fun `cancelled toolchain observation propagates before launch`() {
        Thread.currentThread().interrupt()
        try {
            assertFailsWith<InterruptedException> {
                GeneratedCToolchainEvidence.probe(listOf("/usr/bin/printf", "unused"), 2_000, 128)
            }
        } finally {
            Thread.interrupted()
        }
    }
}
