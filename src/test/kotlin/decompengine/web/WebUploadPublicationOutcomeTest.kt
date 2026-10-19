package decompengine.web

import decompengine.jobs.UploadPublicationUncertain
import decompengine.jobs.UploadPublicationUncertainException
import java.io.IOException
import kotlin.test.*

/** In-memory publication callbacks only; no job store, filesystem, HTTP server or worker. */
class WebUploadPublicationOutcomeTest {
    @Test fun `both typed upload uncertainties retain identity before returning recovery required without retry`() {
        val jobId = "a".repeat(32)
        val failures = listOf(
            UploadPublicationUncertainException(jobId, IOException("synthetic retained-only cause")),
            UploadPublicationUncertain(jobId, IOException("synthetic retained-only cause")),
        )
        for (original in failures) {
            val events = mutableListOf<String>()
            val retained = mutableListOf<WebJobDiagnostic>()
            val failure = assertFailsWith<WebJobServiceException> {
                withWebUploadPublicationOutcome(
                    retainUncertain = { events += "retain"; retained += it },
                    publish = { events += "publish"; throw original },
                )
            }
            events += "returned"
            assertEquals(listOf("publish", "retain", "returned"), events)
            assertEquals("RECOVERY_REQUIRED", failure.code)
            assertSame(original, failure.cause)
            val diagnostic = retained.single()
            assertEquals(jobId, diagnostic.jobId)
            assertEquals("RECOVERY_REQUIRED", diagnostic.code)
            assertTrue(diagnostic.message.contains("do not retry blindly"))
            assertFalse(diagnostic.message.contains("synthetic retained-only cause"))
            assertFalse(failure.message.orEmpty().contains("synthetic retained-only cause"))
        }
    }

    @Test fun `successful publication returns its exact result once without retaining uncertainty`() {
        val expected = Any()
        var calls = 0
        val result = withWebUploadPublicationOutcome(
            retainUncertain = { error("Successful publication must not retain an uncertain outcome") },
            publish = { calls++; expected },
        )
        assertSame(expected, result)
        assertEquals(1, calls)
    }

    @Test fun `untyped publication failures propagate unchanged without inferred uncertainty or retry`() {
        val failures = listOf(IOException("Upload publication is uncertain"), IllegalStateException("synthetic failure"))
        for (original in failures) {
            var calls = 0
            val failure = assertFailsWith<Exception> {
                withWebUploadPublicationOutcome(
                    retainUncertain = { error("Untyped failure must not invent a publication identity") },
                    publish = { calls++; throw original },
                )
            }
            assertSame(original, failure)
            assertEquals(1, calls)
        }
    }
}
