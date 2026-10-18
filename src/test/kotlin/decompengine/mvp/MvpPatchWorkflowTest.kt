package decompengine.mvp

import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfile
import decompengine.project.ReconstructionProfiles
import decompengine.repair.RepairClient
import decompengine.repair.RepairClientAgentHarness
import decompengine.repair.RepairClientInvocation
import decompengine.repair.RepairRequest
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairResponse
import decompengine.repair.SourcePatch
import decompengine.validation.ProcessInput
import java.nio.file.Path
import java.nio.file.Files
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.pathString
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class MvpPatchWorkflowTest {
    @Test
    fun `captured request admission rejects raw padding and entry excess before replacing transcripts`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "request-")
        val path = root.resolve("request.md")
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val budget = RepairResourceBudget(maximumRegressionInputBytes = 1, maximumRequestBytes = 256)
        val request = RepairRequest("fixture", "public objective", mapOf("target.c" to "public code"), emptyList())
        fun refused(value: RepairRequest, limits: RepairResourceBudget = budget) {
            path.writeText("existing public transcript")
            assertFailsWith<MvpPatchException> {
                retainMvpCapturedRequest(path, value, "target.c", limits, evidence)
            }
            assertEquals("existing public transcript", path.readText())
        }
        val padded = request.copy(prompt = " ".repeat(1_024) + request.prompt)
        assertEquals(request.prompt, padded.prompt.trim())
        refused(padded)
        refused(request.copy(regressionInputs = listOf(ProcessInput("x".repeat(256)))))
        refused(request.copy(projectFiles = request.projectFiles + ("extra.c" to "public code")),
            budget.copy(maximumContextFiles = 1, maximumPatchFiles = 1))
        refused(request.copy(regressionInputs = listOf(ProcessInput("first"), ProcessInput("second"))),
            budget.copy(maximumRegressionInputs = 1))
    }

    @Test
    fun `captured request UTF8 boundaries match encoded bytes and frozen code remains complete`() {
        for (sample in listOf("a", "é", "€", "😀", "\uD800", "\uDC00", "x\uD800y", "\uD800\uDC00")) {
            val request = RepairRequest("fixture", "public $sample", mapOf("target.c" to "body$sample"), emptyList())
            val objective = request.prompt.trim() + "\n\nEdit target.c in place. Do not create, delete, or modify any other file."
            val common = listOf("project", RepairClientAgentHarness.FAILURE_KIND_CONTEXT_ID,
                request.failureKind, "target.c", request.projectFiles.getValue("target.c"))
                .sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
            val exact = common + maxOf(request.prompt.toByteArray(Charsets.UTF_8).size,
                objective.toByteArray(Charsets.UTF_8).size)
            val budget = RepairResourceBudget(maximumRegressionInputBytes = 1, maximumRequestBytes = exact)
            val admitted = prepareMvpCapturedRequest(request, "target.c", budget)
            assertEquals(objective, admitted.objective)
            assertTrue(admitted.initialFiles.getValue("target.c").contentEquals(
                request.projectFiles.getValue("target.c").toByteArray(Charsets.UTF_8)))
            assertFailsWith<MvpPatchException> {
                prepareMvpCapturedRequest(request, "target.c", budget.copy(maximumRequestBytes = exact - 1))
            }
        }
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "complete-")
        val path = root.resolve("request.md")
        val code = "int public_value = 7; // λ\n".repeat(1_200)
        val files = linkedMapOf("target.c" to code)
        val inputs = mutableListOf(ProcessInput("original"))
        val request = RepairRequest("fixture", "  public objective  ", files, inputs)
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val admitted = retainMvpCapturedRequest(path, request, "target.c", RepairResourceBudget(), evidence)
        files["target.c"] = "later mutation"
        files["extra.c"] = "later file"
        inputs.clear()
        assertEquals(mapOf("target.c" to code), admitted.request.projectFiles)
        assertEquals(listOf("original"), admitted.request.regressionInputs.map { it.id })
        assertTrue(admitted.initialFiles.getValue("target.c").contentEquals(code.toByteArray(Charsets.UTF_8)))
        val text = path.readText()
        assertTrue(text.length > 16_384 && text.contains(code.trimEnd()))
        assertTrue(text.contains("## Objective\n\n  public objective  \n"))
        assertFalse(text.contains("preview truncated"))
    }

    @Test
    fun `captured staging bytes are admitted before retaining request content`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "staging-")
        val path = root.resolve("request.md")
        val request = RepairRequest("fixture", "public objective", mapOf("target.c" to "€😀"), emptyList())
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val bytes = request.projectFiles.getValue("target.c").toByteArray(Charsets.UTF_8).size.toLong()
        val budget = RepairResourceBudget(maximumStagingBytes = bytes)
        val admitted = retainMvpCapturedRequest(path, request, "target.c", budget, evidence)
        assertEquals(bytes, admitted.initialFiles.values.sumOf { it.size.toLong() })
        path.writeText("existing public transcript")
        assertFailsWith<MvpPatchException> {
            retainMvpCapturedRequest(path, request, "target.c", budget.copy(maximumStagingBytes = bytes - 1), evidence)
        }
        assertEquals("existing public transcript", path.readText())
    }

    @Test
    fun `captured response admission protects transcripts and preserves complete replacements`() {
        val root = createTempDirectory(Files.createDirectories(Path.of("build/test-tmp/mvp-transcript-admission")), "response-")
        val path = root.resolve("response.md")
        val evidence = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val response = RepairResponse("é", listOf(SourcePatch("target.c", "€")))
        val exact = listOf(response.summary, "target.c", "€").sumOf { it.toByteArray(Charsets.UTF_8).size.toLong() }
        val budget = RepairResourceBudget(maximumResponseBytes = exact, maximumPatchBytes = 3)
        retainMvpCapturedResponse(path, response, budget, evidence)
        assertTrue(path.readText().contains("é") && path.readText().contains("€"))
        fun refused(value: RepairResponse, limits: RepairResourceBudget) {
            path.writeText("existing public transcript")
            assertFailsWith<MvpPatchException> { retainMvpCapturedResponse(path, value, limits, evidence) }
            assertEquals("existing public transcript", path.readText())
        }
        refused(response, budget.copy(maximumResponseBytes = exact - 1))
        refused(response, budget.copy(maximumPatchBytes = 2))
        refused(response.copy(patches = response.patches + SourcePatch("extra.c", "public")),
            RepairResourceBudget(maximumPatchFiles = 1))
        assertFailsWith<MvpPatchException> {
            prepareMvpCapturedResponse(" ".repeat(256) + "public", "target.c", "x",
                RepairResourceBudget(maximumResponseBytes = 64))
        }
        assertFailsWith<MvpPatchException> {
            prepareMvpCapturedResponse(null, "target.c", "x", RepairResourceBudget(maximumResponseBytes = 9))
        }
        assertEquals("agent supplied a captured full-file replacement",
            prepareMvpCapturedResponse(null, "target.c", "x", RepairResourceBudget()).summary)
        val code = "int public_value = 7; // λ\n".repeat(1_200)
        val complete = prepareMvpCapturedResponse("  public summary  ", "target.c", code, RepairResourceBudget())
        assertEquals("public summary", complete.summary)
        retainMvpCapturedResponse(path, complete, RepairResourceBudget(), evidence)
        val text = path.readText()
        assertTrue(text.length > 16_384 && text.contains(code.trimEnd()))
        assertFalse(text.contains("preview truncated"))
    }

    @Test
    fun `patch summary diagnostic fields share credential masking without shortening complete public diffs`() {
        val root = createTempDirectory(
            Files.createDirectories(Path.of("build/test-tmp/mvp-summary-privacy")), "summary-",
        )
        val configured = "ordinary-setting-sensitive-value"
        val bearer = "unregistered-summary-bearer"
        val basic = "c3ludGhldGljOnNlbnRpbmVs"
        val api = "unregistered-summary-api"
        val password = "unregistered-summary-password"
        val token = "unregistered-summary-token"
        val diagnostic = "before; $configured; Bearer $bearer; Authorization: Basic $basic; " +
            "api_key=$api; password=$password; ghp_$token; after"
        val environment = mapOf("PLAIN_SETTING" to configured, "PLAIN_INDICATOR" to "Bearer", "PLAIN_FIELD" to "api_key")
        val evidence = MvpRunEvidence(environment, diagnostic, "fixture-profile", "a".repeat(64)).apply {
            failPhase("reconstruct", diagnostic)
            check("validation", false, diagnostic)
            patchExplanation = diagnostic
            approvalDecision = diagnostic
            isolation = diagnostic
        }
        val fullDiff = "--- a/public.c\n+++ b/public.c\n" + " public approved context line\n".repeat(1000)
        assertTrue(fullDiff.length > 16_384)
        evidence.patchDiff = fullDiff
        evidence.patchDiffPath = root.resolve("approved.patch").also { it.writeText(fullDiff) }
        val summary = root.resolve("SUMMARY.md")
        writeMvpSummary(summary, root, root.resolve("input.elf"), root.resolve("raw.c"),
            root.resolve("source.c"), root.resolve("patched.c"), root.resolve("binary"), "FAIL", diagnostic, evidence)
        val text = summary.readText()
        listOf(configured, bearer, basic, api, password, token, "Bearer", "api_key").forEach {
            assertFalse(text.contains(it), "diagnostic value survived summary redaction")
        }
        assertTrue(text.contains("[redacted]"))
        assertTrue(text.contains("| reconstruct | FAIL | before; "))
        assertTrue(text.contains("| validation | FAIL | before; "))
        assertTrue(text.contains("Result: FAIL"))
        assertTrue(text.contains(fullDiff.trimEnd()))
        assertEquals(fullDiff, root.resolve("approved.patch").readText())
    }

    @Test
    fun `patch diagnostic previews keep shared bounds and sensitive omission markers safe`() {
        val markers = listOf("[oversized text omitted]", "[redacted]", "[unredactable text omitted]")
        val evidence = MvpRunEvidence(markers.mapIndexed { index, value -> "PLAIN_$index" to value }.toMap(),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        assertEquals("", evidence.redactDiagnostic("x".repeat(16_385)))
        assertEquals("", evidence.redactDiagnostic("Authorization: Basic synthetic-encoded-value"))
        val ordinary = MvpRunEvidence(emptyMap(), "fixture-harness", "fixture-profile", "a".repeat(64))
        val preview = ordinary.redactDiagnostic("public ".repeat(200))
        assertTrue(preview.endsWith("… [preview truncated]"))
        assertTrue(preview.length <= 512 + "… [preview truncated]".length)
        assertFailsWith<IllegalArgumentException> {
            MvpRunEvidence((0..4096).associate { "PLAIN_$it" to "value-$it" },
                "fixture-harness", "fixture-profile", "a".repeat(64))
        }
        val root = createTempDirectory(
            Files.createDirectories(Path.of("build/test-tmp/mvp-summary-privacy")), "normalization-",
        )
        val privateFallback = "No source patch was generated before the workflow stopped."
        val secrets = markers + listOf(privateFallback, "alpha beta", "<br>", "\\|")
        val safe = MvpRunEvidence(secrets.mapIndexed { index, value -> "PLAIN_$index" to value }.toMap(),
            "fixture-harness", "fixture-profile", "a".repeat(64))
        safe.failPhase("reconstruct", "before\nafter|end")
        for ((index, explanation) in listOf("", "alpha\tbeta").withIndex()) {
            safe.patchExplanation = explanation
            val summary = root.resolve("summary-$index.md")
            writeMvpSummary(summary, root, root.resolve("input.elf"), root.resolve("raw.c"),
                root.resolve("source.c"), root.resolve("patched.c"), root.resolve("binary"), "FAIL", "fixture failure", safe)
            val text = summary.readText()
            secrets.forEach { assertFalse(text.contains(it), "formatting synthesized a private diagnostic value") }
        }
    }

    @Test
    fun `runs patch workflow and publishes verified artifacts`() {
        val tempDir = createTempDirectory("mvp-patch-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        output.resolve("stale/nested").createDirectories()
        output.resolve("stale/nested/old.txt").writeText("old output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy to the local buffer without exposing top-secret-value", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            harness = RepairClientAgentHarness(client),
            environment = mapOf("API_KEY" to "top-secret-value"),
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* ghidra */ }\n") },
            binaryExecution = testExecutionBoundary(),
            publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
        ).run(MvpPatchOptions(input, output))

        assertEquals(2, client.requests.size)
        assertEquals(setOf("decompiled.c", "ghidra_decompiled.c"), client.requests.first().projectFiles.keys)
        assertTrue(client.requests.first().projectFiles.getValue("ghidra_decompiled.c").contains("ghidra"))
        assertEquals(setOf("decompile/decompiled.c", "patched.c"), client.requests.last().projectFiles.keys)
        assertTrue(output.resolve("decompile/decompiled.c").readText().contains("badge[i]"))
        assertFalse(output.resolve("stale/nested/old.txt").exists())
        assertTrue(output.resolve("patched_c/patched.c").readText().contains("return 0;"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: NON_RELEASE"))
        assertTrue(summary.contains("## CWE-787 Evidence and Source Mapping"))
        assertTrue(summary.contains("decompiled.c:"))
        assertTrue(summary.contains("## Approved Source Change"))
        assertTrue(summary.contains("bound copy to the local buffer"))
        assertFalse(summary.contains("top-secret-value"))
        assertTrue(summary.contains("[redacted]"))
        assertTrue(summary.contains("approved interactively"))
        assertTrue(summary.contains("Agent harness: `agent-harness-unprovisioned`"))
        assertTrue(summary.contains("Reconstruction profile: `generated-c-make-v1`"))
        assertTrue(summary.contains("| verify | PASS |"))
        assertTrue(summary.contains("binary hardening inspection | PASS"))
        assertTrue(summary.contains("behavior validation | PASS"))
        assertTrue(summary.contains("evidence/approved.patch"))
        assertTrue(output.resolve("evidence/approved.patch").exists())
        assertTrue(output.resolve("evidence/cwe-787-sanitizer.txt").exists())
        assertTrue(output.resolve("evidence/reconstruction-request.md").readText().contains("Binary-derived context"))
        assertTrue(output.resolve("evidence/reconstruction-response.md").readText().contains("badge[i]"))
        assertTrue(output.resolve("evidence/patch-request.md").readText().contains("Sanitizer evidence"))
        assertTrue(output.resolve("evidence/patch-response.md").readText().contains("[REDACTED]"))
        assertTrue(Regex("`[0-9a-f]{64}`").containsMatchIn(summary))

        val patched = ProcessBuilder(output.resolve(".work/patched_release").pathString).start()
        assertEquals(0, patched.waitFor())
        assertEquals("[03] Alexandria Stone\n", patched.inputStream.bufferedReader().readText())
    }

    @Test
    fun `MVP compiler comes from the admitted Make or Ninja profile`() {
        val source = Path.of("/private/source.c")
        val target = Path.of("/private/output")
        for (profile in ReconstructionProfiles.builtIn) {
            val compiler = ReconstructionAdapters.resolve(profile).mvpPatchCompiler
            val sanitizer = compiler.command(profile, source, target, sanitizer = true, warningsAsErrors = false)
            val release = compiler.command(profile, source, target, sanitizer = false, warningsAsErrors = true)
            assertEquals(profile.adapterConfiguration.getValue("compiler-driver").single(), sanitizer.first())
            assertEquals(sanitizer.first(), release.first())
            assertTrue("-fsanitize=address,undefined" in sanitizer)
            assertTrue("-Werror" in release)
            assertTrue("-Wl,-z,relro,-z,now" in release)
        }
    }

    @Test
    fun `MVP rejects a forged compiler profile before touching output`() {
        val builtIn = ReconstructionProfiles.default
        val forged = ReconstructionProfile(
            builtIn.schemaVersion,
            builtIn.id,
            builtIn.layout,
            builtIn.budgets,
            builtIn.adapterConfiguration + ("compiler-driver" to listOf("false")),
        )
        val output = createTempDirectory("mvp-forged-profile-").resolve("output")
        val failure = assertFailsWith<IllegalArgumentException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(QueueRepairClient()),
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(Path.of("/absent/input"), output), forged)
        }
        assertTrue(failure.message.orEmpty().contains("not admitted"))
        assertFalse(output.exists())
    }

    @Test
    fun `does not publish binary when patch is not approved`() {
        val tempDir = createTempDirectory("mvp-reject-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy to the local buffer", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(client),
                approve = { false },
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("decompiled c") },
                binaryExecution = testExecutionBoundary(),
                publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
            ).run(MvpPatchOptions(input, output))
        }

        assertTrue(failure.message.orEmpty().contains("not approved"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: FAIL"))
        assertTrue(summary.contains("Failure phase and reason: patch: patch was not approved"))
        assertTrue(summary.contains("rejected interactively"))
        assertTrue(summary.contains("Verified final binary: `not published`"))
    }

    @Test
    fun `rejects non ELF input before decompilation`() {
        val tempDir = createTempDirectory("mvp-invalid-")
        val input = tempDir.resolve("not-elf")
        input.writeText("not an elf")
        val output = tempDir.resolve("output")

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(QueueRepairClient()),
                decompiler = BinaryDecompiler { _, _, _, _ -> error("must not run") },
                binaryExecution = testExecutionBoundary(),
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("64-bit ELF"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
    }

    @Test
    fun `yes automation records approval without prompting`() {
        val tempDir = createTempDirectory("mvp-yes-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bound copy", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            harness = RepairClientAgentHarness(client),
            approve = { error("--yes must bypass the interactive prompt") },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("decompiled c") },
            binaryExecution = testExecutionBoundary(),
            publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
        ).run(MvpPatchOptions(input, output, assumeYes = true))

        assertTrue(output.resolve("summary/SUMMARY.md").readText().contains("approved by --yes automation"))
    }

    @Test
    fun `explicit legacy provenance validates only as non release compatibility`() {
        val tempDir = createTempDirectory("mvp-legacy-non-release-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("reconstruct vulnerable source", listOf(SourcePatch("decompiled.c", vulnerableSource()))),
            RepairResponse("bounded compatibility patch", listOf(SourcePatch("patched.c", patchedSource()))),
        )

        MvpPatchWorkflow(
            harness = RepairClientAgentHarness(client),
            approve = { true },
            decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("int main(void) { /* ghidra */ }\n") },
            binaryExecution = testExecutionBoundary(),
            harnessProvenance = "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-none:deprecated",
        ).run(MvpPatchOptions(input, output))

        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        val summary = output.resolve("summary/SUMMARY.md").readText()
        assertTrue(summary.contains("Result: NON_RELEASE"))
        assertTrue(summary.contains("legacy-openai"))
        assertFalse(output.resolve("evidence/$RECONSTRUCTION_AGENT_EVIDENCE").exists())
        assertFalse(output.resolve("evidence/$PATCH_AGENT_EVIDENCE").exists())
    }

    @Test
    fun `rejects placeholder reconstruction before compilation`() {
        val tempDir = createTempDirectory("mvp-placeholder-")
        val input = compileC(tempDir, "original", originalSource())
        val output = tempDir.resolve("output")
        val client = QueueRepairClient(
            RepairResponse("placeholder", listOf(SourcePatch("decompiled.c", "int main(void) { return 0; }\n"))),
        )

        val failure = assertFailsWith<MvpPatchException> {
            MvpPatchWorkflow(
                harness = RepairClientAgentHarness(client),
                decompiler = BinaryDecompiler { _, _, _, raw -> raw.writeText("binary-derived ghidra context") },
                binaryExecution = testExecutionBoundary(),
                publicationMode = MvpPublicationMode.TEST_ONLY_NON_RELEASE,
            ).run(MvpPatchOptions(input, output, assumeYes = true))
        }

        assertTrue(failure.message.orEmpty().contains("placeholder"))
        assertFalse(output.resolve("patched_binary/patched_binary").exists())
        assertTrue(output.resolve("evidence/reconstruction-request.md").exists())
        assertTrue(output.resolve("evidence/reconstruction-response.md").exists())
    }

    @Test
    fun `allows top level docker output mount`() {
        val output = Path.of("/output")
        val input = Path.of("/input/binary_01")

        assertTrue(output.root != null)
        assertTrue(output != output.root)
        assertTrue(output != input.parent)
    }

    private class QueueRepairClient(vararg responses: RepairResponse) : RepairClient {
        private val responses = ArrayDeque(responses.toList())
        val requests = mutableListOf<RepairRequest>()

        override fun requestRepair(request: RepairRequest, invocation: RepairClientInvocation): RepairResponse {
            requests += request
            return responses.removeFirst()
        }
    }

    private fun testExecutionBoundary() = BinaryExecutionBoundary { executable, directory, environment ->
        val process = ProcessBuilder(executable.toAbsolutePath().toString())
            .directory(directory.toFile())
            .apply { environment().putAll(environment) }
            .start()
        BinaryExecutionResult(
            process.waitFor(),
            process.inputStream.bufferedReader().readText(),
            process.errorStream.bufferedReader().readText(),
            BinaryIsolation("deterministic test boundary", networkIsolated = true, credentialsIsolated = true),
        )
    }

    private fun compileC(tempDir: Path, name: String, source: String): Path {
        val sourcePath = tempDir.resolve("$name.c")
        val binary = tempDir.resolve(name)
        sourcePath.writeText(source)
        val process = ProcessBuilder("gcc", "-std=c11", "-Wall", "-Wextra", "-Werror", sourcePath.pathString, "-o", binary.pathString)
            .redirectErrorStream(true)
            .start()
        val output = process.inputStream.bufferedReader().readText()
        check(process.waitFor() == 0) { output }
        return binary
    }

    private fun originalSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent()

    private fun vulnerableSource() = """
        #include <stdio.h>
        int main(void) {
            char badge[8];
            const char *message = "[03] Alexandria Stone";
            for (volatile int i = 0; message[i] != '\0'; i++) {
                badge[i] = message[i];
            }
            puts("[03] Alexandria Stone");
            return badge[0] == 0;
        }
    """.trimIndent() + "\n"

    private fun patchedSource() = """
        #include <stdio.h>
        int main(void) {
            puts("[03] Alexandria Stone");
            return 0;
        }
    """.trimIndent() + "\n"
}
