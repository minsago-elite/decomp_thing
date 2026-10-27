package decompengine

import decompengine.web.WebUiMode
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class WebCliTest {
    @Test
    fun `web help is recognised anywhere and defaults keep the documented data directory`() {
        assertEquals(WebCliInvocation.Help, parseWebCliArguments(listOf("--help")))
        assertEquals(WebCliInvocation.Help, parseWebCliArguments(listOf("-h")))
        assertEquals(WebCliInvocation.Help, parseWebCliArguments(listOf("--port", "9000", "--help")))
        val defaults = parseWebCliArguments(emptyList()) as WebCliInvocation.Serve
        assertEquals(Path.of(".decomp_engine/jobs"), defaults.options.dataDir)
        assertEquals(WebCliOptions(), defaults.options)
        val selected = parseWebCliArguments(listOf("--host", "::1", "--port", "0", "--listen-backlog", "8",
            "--data-dir", "jobs", "--ui", "spa", "--base-path", "/app/", "--dev-frontend-origin", "http://127.0.0.1:5173"))
        assertEquals(WebCliInvocation.Serve(WebCliOptions("::1", 0, 8, Path.of("jobs"), WebUiMode.SPA, "/app/",
            "http://127.0.0.1:5173")), selected)
    }

    @Test
    fun `invalid web arguments are one line messages instead of exceptions`() {
        val cases = mapOf(
            listOf("--port") to "--port requires a value",
            listOf("--port", "http") to "--port must be between 0 and 65535 (0 selects an available port)",
            listOf("--port", "65536") to "--port must be between 0 and 65535 (0 selects an available port)",
            listOf("--listen-backlog", "0") to "--listen-backlog requires an integer between 1 and 4096",
            listOf("--ui", "modern") to "--ui must be legacy or spa",
            listOf("--data-dir", "a\u0000b") to "--data-dir is not a valid path",
            listOf("--verbose") to "unknown web argument: --verbose",
            listOf("serve\nnow") to "unknown web argument: serve?now",
        )
        for ((arguments, message) in cases) {
            assertEquals(WebCliInvocation.Invalid(message), parseWebCliArguments(arguments), arguments.toString())
        }
    }

    @Test
    fun `startup refusals become a single actionable line`() {
        assertEquals("Cannot start web server: the SPA preview currently requires a loopback host",
            webStartupRefusal(IllegalArgumentException("the SPA preview currently requires a loopback host"), "192.0.2.1", 8000))
        assertEquals("Cannot bind web server to 127.0.0.1:8000. Check --host or choose an unused --port.",
            webStartupRefusal(java.net.BindException("Address already in use"), "127.0.0.1", 8000))
        assertTrue(webStartupRefusal(java.net.UnknownHostException("no.such.host"), "no.such.host", 8000)!!
            .startsWith("Cannot resolve --host no.such.host."))
        assertEquals("Cannot start web server: first line",
            webStartupRefusal(IllegalStateException("first line\nsecond line"), "127.0.0.1", 8000))
        assertEquals("Cannot start web server: data directory is busy",
            webStartupRefusal(java.nio.file.FileSystemException("data directory is busy"), "127.0.0.1", 8000))
        assertTrue(webStartupRefusal(IllegalStateException("x".repeat(2000)), "127.0.0.1", 8000)!!.length < 600)
        assertNull(webStartupRefusal(RuntimeException("internal defect"), "127.0.0.1", 8000))
    }

    @Test
    fun `version line names the packaged version or a development build`() {
        assertEquals("llm_bin_patch 0.1.0", applicationVersionLine("0.1.0"))
        assertEquals("llm_bin_patch development build", applicationVersionLine(null))
    }

    @Test
    fun `installed launcher prints help version and startup refusals without stack traces`() {
        val temp = Files.createTempDirectory("installed-web-cli-")
        val launcher = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch/bin/llm_bin_patch")
        val dataDir = temp.resolve("jobs").toString()
        val cases = listOf(
            Triple(listOf("web", "--help"), 0, "usage: llm_bin_patch web [--host 127.0.0.1]"),
            Triple(listOf("--version"), 0, "llm_bin_patch 0.1.0"),
            Triple(listOf("web", "--port"), 2, "llm_bin_patch web: --port requires a value"),
            Triple(listOf("web", "--ui", "spa", "--host", "192.0.2.1", "--port", "0", "--data-dir", dataDir), 2,
                "Cannot start web server: the SPA preview currently requires a loopback host"),
        )
        for ((index, case) in cases.withIndex()) {
            val (arguments, exitCode, expected) = case
            val log = temp.resolve("case-$index.log")
            val builder = ProcessBuilder(listOf(launcher.toString()) + arguments)
                .redirectErrorStream(true).redirectOutput(log.toFile())
            for (key in listOf("JAVA_TOOL_OPTIONS", "JDK_JAVA_OPTIONS", "_JAVA_OPTIONS", "LLM_BIN_PATCH_OPTS")) {
                builder.environment().remove(key)
            }
            builder.environment()["JAVA_HOME"] = System.getProperty("java.home")
            builder.environment()["JAVA_OPTS"] = "-Xmx256m"
            val process = builder.start()
            try {
                assertTrue(process.waitFor(60, TimeUnit.SECONDS), arguments.toString())
                val text = Files.readString(log)
                assertEquals(exitCode, process.exitValue(), text)
                assertTrue(expected in text, text)
                assertFalse(text.lineSequence().any { it.trimStart().startsWith("at ") }, text)
                assertFalse("Exception" in text, text)
            } finally {
                if (process.isAlive) {
                    process.destroyForcibly()
                    process.waitFor(5, TimeUnit.SECONDS)
                }
            }
        }
    }
}
