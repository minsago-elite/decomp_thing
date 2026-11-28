package decompengine.acp

import kotlin.test.Test
import kotlin.test.assertEquals

class AcpHostMountChurnRestartReportTest {
    private fun witness(admission: String?): AcpMountEventWitness {
        val phase = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventPhase")
        val outcome = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventOutcome")
        val diagnostic = Class.forName("decompengine.acp.RuntimePrivateControlScope\$MountEventDiagnostic")
        val constructor = diagnostic.getDeclaredConstructor(phase, outcome, java.lang.Integer::class.java,
            java.lang.Integer::class.java, java.lang.Integer::class.java, String::class.java).apply { isAccessible = true }
        return constructor.newInstance(phase.enumConstants.single { (it as Enum<*>).name == "CHECKPOINT" },
            outcome.enumConstants.single { (it as Enum<*>).name == "EVENT" }, 1, 10, null, admission) as AcpMountEventWitness
    }

    @Test
    fun `restart report records zero counts and only closed witness records`() {
        assertEquals(
            "{\"schema\":\"acp-host-mount-churn-restarts-v1\",\"diagnosticOnly\":true," +
                "\"restartedRefusals\":0,\"retained\":[]}\n",
            AcpHostMountChurnRestartReport.render(0, emptyList()),
        )
        val admitted = "mount-admission-v1 stage=ADMITTED initialMounts=24 initialControls=1 owner=false initialFast=true"
        assertEquals(
            "{\"schema\":\"acp-host-mount-churn-restarts-v1\",\"diagnosticOnly\":true,\"restartedRefusals\":2," +
                "\"retained\":[{\"event\":\"mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT " +
                "rc=1 revents=10 errno=NA\",\"admission\":\"$admitted\",\"timing\":null}," +
                "{\"event\":\"mount-event-v1 phase=CHECKPOINT generation=NOT_EVALUATED outcome=EVENT " +
                "rc=1 revents=10 errno=NA\",\"admission\":\"invalid\",\"timing\":null}]}\n",
            AcpHostMountChurnRestartReport.render(2, listOf(witness(admitted), witness("forged \"admission\" /PRIVATE"))),
        )
    }

    @Test
    fun `restart reports use one directory per run attempt and never trust malformed identifiers`() {
        fun leaf(environment: Map<String, String>) =
            AcpHostMountChurnRestartReport.reportDirectory(environment).fileName.toString()
        assertEquals("github-46102066453-2", leaf(mapOf("GITHUB_RUN_ID" to "46102066453", "GITHUB_RUN_ATTEMPT" to "2")))
        assertEquals("local", leaf(emptyMap()))
        assertEquals("local", leaf(mapOf("GITHUB_RUN_ID" to "46102066453")))
        assertEquals("local", leaf(mapOf("GITHUB_RUN_ID" to "../escape", "GITHUB_RUN_ATTEMPT" to "1")))
        assertEquals(AcpHostMountChurnRestartReport.DIRECTORY,
            AcpHostMountChurnRestartReport.reportDirectory(emptyMap()).parent.fileName.toString())
    }
}
