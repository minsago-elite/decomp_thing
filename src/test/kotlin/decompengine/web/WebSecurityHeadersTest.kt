package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import decompengine.project.GeneratedFileEvidence
import decompengine.project.ProjectContentKind
import decompengine.project.ProjectFileRole
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class WebSecurityHeadersTest {
    @Test
    fun `legacy application policy authorizes exact scripts without blanket inline execution`() {
        val document = renderDashboardDocument(emptyList())
        val policy = webApplicationContentSecurityPolicy(document.trustedInlineScripts)

        assertTrue(policy.contains("script-src 'self' 'sha256-"))
        assertFalse(policy.contains("unsafe-inline"))
        assertFalse(policy.contains("unsafe-eval"))
        assertTrue(policy.contains("style-src 'self'"))
        assertTrue(policy.contains("worker-src 'self'"))
        assertTrue(policy.contains("frame-ancestors 'none'"))
        assertFalse(document.body.contains("style="))
        val renderedScripts = Regex("<script>([\\s\\S]*?)</script>").findAll(document.body)
            .map { it.groupValues[1] }.toList()
        assertEquals(document.trustedInlineScripts, renderedScripts)

        val injectedScript = "window.injectedScriptMustNotRun = true;"
        val injectedDocument = document.body.replace("</body>", "<script>$injectedScript</script></body>")
        val injectedSource = webApplicationContentSecurityPolicy(listOf(injectedScript))
            .substringAfter("script-src 'self' ").substringBefore(';')
        assertTrue(injectedDocument.contains(injectedScript))
        assertFalse(policy.contains(injectedSource),
            "a script discovered only in final HTML must not be authorized")

        val changedScripts = document.trustedInlineScripts.map {
            it.replace("authInspectionGeneration = 0", "authInspectionGeneration = 1")
        }
        assertFalse(webApplicationContentSecurityPolicy(changedScripts) == policy,
            "changing executable bytes must change the CSP source hash")
    }

    @Test
    fun `legacy source tree and score presentation require no inline styles`() {
        val root = createTempDirectory("web-security-render-")
        try {
            val job = JobStore(root).createFromUpload("fixture.elf", elfFixture())
            val file = GeneratedFileEvidence(
                path = "src/deep/module/fixture.c",
                sha256 = "0".repeat(64),
                generator = "fixture",
                roles = setOf(ProjectFileRole.VIEWABLE),
                contentKind = ProjectContentKind.UTF8_TEXT,
            )
            val report = Json.parseToJsonElement(
                """{"confidence":{"score":0.625},"candidateCount":0,"expandedOutputSignatures":0,"newOutputSignatures":[],"candidates":[],"observations":[]}""",
            ).jsonObject
            val document = renderJobDocument(
                job,
                sourceTree = SourceTreeView(listOf(file), null),
                explorationReport = report,
            )

            assertFalse(document.body.contains("style="))
            assertTrue(document.body.contains("class=\"source-depth-3\""))
            assertTrue(document.body.contains("<meter class=\"gauge\""))
            assertFalse(webApplicationContentSecurityPolicy(document.trustedInlineScripts).contains("unsafe-inline"))
        } finally {
            root.toFile().deleteRecursively()
        }
    }
}
