package decompengine.builtin

import com.sun.net.httpserver.HttpServer
import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.oracle.core.OracleJson
import decompengine.project.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.net.InetSocketAddress
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Collections
import java.util.concurrent.atomic.AtomicInteger
import kotlin.io.path.*
import kotlin.test.*

class BuiltinHarnessProvisioningTest {
    @TempDir lateinit var directory: Path
    private val secret = "fixture-private-provider-secret"
    private fun privateFile(bytes: ByteArray): Path = Files.createTempFile(directory, "config-", ".json").also {
        it.writeBytes(bytes); Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rw-------"))
    }
    private fun config(baseUrl: String = "https://provider.example.invalid/v1", model: String = "fixture-model"): JsonObject {
        val journals = directory.resolve("journals").createDirectories()
        Files.setPosixFilePermissions(journals, PosixFilePermissions.fromString("rwx------"))
        val limits = BuiltinLoopLimits()
        val call = limits.provider
        return buildJsonObject {
            put("schemaVersion", 1)
            putJsonObject("provider") {
                put("kind", "openai-compatible"); put("baseUrl", baseUrl); put("model", model)
                put("apiKeyEnvironment", "BUILTIN_FIXTURE_KEY")
            }
            putJsonObject("journal") {
                put("directory", journals.toString()); put("maximumBytes", 64 * 1024 * 1024)
                put("maximumRecordBytes", 8 * 1024 * 1024); put("maximumRecords", 10_000)
            }
            putJsonObject("loop") {
                put("maxContextBytes", limits.maxContextBytes); put("maxToolResultBytes", limits.maxToolResultBytes)
                put("maxIdenticalActions", limits.maxIdenticalActions); put("maxTraceRecords", limits.maxTraceRecords)
                put("maxInputTokens", limits.maxInputTokens); put("maxOutputTokens", limits.maxOutputTokens)
                put("maximumEvidenceBytes", limits.maximumEvidenceBytes); put("contextHistoryReserveBytes", limits.contextHistoryReserveBytes)
                putJsonObject("provider") {
                    put("connectTimeoutMillis", call.connectTimeout.toMillis()); put("requestTimeoutMillis", call.requestTimeout.toMillis())
                    put("streamIdleTimeoutMillis", call.streamIdleTimeout.toMillis()); put("overallTimeoutMillis", call.overallTimeout.toMillis())
                    put("maxRequestBytes", call.maxRequestBytes); put("maxResponseBytes", call.maxResponseBytes)
                    put("maxEventBytes", call.maxEventBytes); put("maxToolCalls", call.maxToolCalls); put("maxOutputTokens", call.maxOutputTokens)
                    put("maxRetries", call.maxRetries); put("retryBaseDelayMillis", call.retryBaseDelay.toMillis())
                    put("maxRetryDelayMillis", call.maxRetryDelay.toMillis())
                }
            }
        }
    }
    private fun load(document: JsonObject = config(), key: String = secret) = BuiltinHarnessProvisioning.load(
        privateFile(document.toString().toByteArray()).toString(), mapOf("BUILTIN_FIXTURE_KEY" to key))
    private fun execute(harness: BuiltinCapturedRepairHarness): RepairStagingExecution = CapturedRepairStagingAuthority.executeReceipt(
        harness, mapOf("source.c" to "old".toByteArray()), setOf("source.c"), RepairResourceBudget(), { root ->
            AgentExecutionRequest("repair fixture", listOf(root), accessPolicy = AgentAccessPolicy(listOf(
                AgentPathRule(AgentWorkspacePath(root.id, "source.c"), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))),
                workflowIdentity = AgentWorkflowIdentity(AgentWorkflow.REPAIR, "revision_fixture", "a".repeat(64), "b".repeat(64)))
        }) {}

    @Test fun `canonical config identity excludes credentials and binds operator settings`() {
        val document = config()
        val first = load(document)
        val reordered = JsonObject(document.entries.reversed().associate { it.key to it.value })
        val second = BuiltinHarnessProvisioning.load(privateFile((" \n" + reordered + "\n").toByteArray()).toString(),
            mapOf("BUILTIN_FIXTURE_KEY" to "rotated-fixture-secret", "API_KEY" to "ignored-legacy-secret"))
        assertEquals(first.provenance, second.provenance)
        assertEquals(checkpointHash(OracleJson.canonicalBytes(document)), first.provenance.configurationSha256)
        val loop = document.getValue("loop").jsonObject
        val changed = load(JsonObject(document + ("loop" to JsonObject(loop + ("maxIdenticalActions" to JsonPrimitive(2))))))
        assertNotEquals(first.provenance, changed.provenance)
        assertNotEquals(first.provenance, load(config(model = "second-model")).provenance)
        val preflight = first.preflight()
        assertTrue(preflight.journalReady && preflight.capturedRepair && preflight.externalValidationRequired)
        assertFalse(preflight.reconstruction || preflight.terminalTools || preflight.checkpointResume || preflight.authenticationChecked || preflight.releaseQualified)
        assertEquals(BuiltinLoopLimits(), preflight.limits)
        assertFalse(first.provenance.fixtureOnly)
        assertFalse(first.toString().contains(secret) || first.provenance.toString().contains(directory.toString()))
        assertNotSame(first.createCapturedRepairHarness(), first.createCapturedRepairHarness())
    }

    @Test fun `strict config rejects duplicate unknown missing numeric and unbounded fields`() {
        val original = config().toString()
        val malformed = listOf(original.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":1,\"schemaVersion\":1"),
            original.replaceFirst("\"schemaVersion\":1", "\"schemaVersion\":2"),
            original.replaceFirst("\"schemaVersion\":1", "\"fixtureOnly\":false,\"schemaVersion\":1"),
            original.replaceFirst("\"maxRetries\":2", "\"maxRetries\":\"2\""),
            original.replaceFirst("\"maxRetries\":2", "\"maxRetries\":2.0"),
            original.replaceFirst("\"maxRetries\":2", "\"maxRetries\":11"),
            original.replaceFirst("\"maximumRecords\":10000", "\"maximumRecords\":10001"),
            original.replaceFirst("\"maxRetries\":2,", ""),
            original + " {}")
        for (value in malformed) {
            assertNotEquals(original, value)
            val failure = assertFailsWith<BuiltinProvisioningException> {
                BuiltinHarnessProvisioning.load(privateFile(value.toByteArray()).toString(), mapOf("BUILTIN_FIXTURE_KEY" to secret))
            }
            assertNull(failure.cause)
            assertFalse(failure.toString().contains(secret) || failure.toString().contains("provider.example"))
        }
    }

    @Test fun `private config loading rejects links public permissions malformed utf8 and excess bytes`() {
        val file = privateFile(config().toString().toByteArray())
        val environment = mapOf("BUILTIN_FIXTURE_KEY" to secret)
        val link = directory.resolve("config-link")
        Files.createSymbolicLink(link, file)
        assertFailsWith<BuiltinProvisioningException> { BuiltinHarnessProvisioning.load(link.toString(), environment) }
        link.deleteExisting(); Files.createLink(link, file)
        assertFailsWith<BuiltinProvisioningException> { BuiltinHarnessProvisioning.load(file.toString(), environment) }
        link.deleteExisting()
        Files.setPosixFilePermissions(file, PosixFilePermissions.fromString("rw-r--r--"))
        assertFailsWith<BuiltinProvisioningException> { BuiltinHarnessProvisioning.load(file.toString(), environment) }
        for (bytes in listOf(byteArrayOf(0xff.toByte()), ByteArray(64 * 1024 + 1) { ' '.code.toByte() })) {
            assertFailsWith<BuiltinProvisioningException> { BuiltinHarnessProvisioning.load(privateFile(bytes).toString(), environment) }
        }
    }

    @Test fun `production requires https and one explicitly named valid credential`() {
        for (endpoint in listOf("http://127.0.0.1:12345/v1", "https://user:pass@example.invalid/v1",
            "https://example.invalid/v1?secret=value", "https://example.invalid/v1#fragment")) {
            assertFailsWith<BuiltinProvisioningException> { load(config(baseUrl = endpoint)) }
        }
        val file = privateFile(config().toString().toByteArray())
        for (environment in listOf(emptyMap(), mapOf("API_KEY" to secret), mapOf("BUILTIN_FIXTURE_KEY" to "line\nbreak"),
            mapOf("BUILTIN_FIXTURE_KEY" to ""))) {
            assertFailsWith<BuiltinProvisioningException> { BuiltinHarnessProvisioning.load(file.toString(), environment) }
        }
        assertFailsWith<BuiltinProvisioningException> {
            BuiltinHarnessProvisioning.loadLoopbackFixture(file.toString(), mapOf("BUILTIN_FIXTURE_KEY" to secret))
        }
    }

    private fun fixture(path: String = "source.c", block: (String, AtomicInteger, List<String>, List<JsonObject>) -> Unit) {
        val count = AtomicInteger()
        val authorization = Collections.synchronizedList(mutableListOf<String>())
        val bodies = Collections.synchronizedList(mutableListOf<JsonObject>())
        val server = HttpServer.create(InetSocketAddress("127.0.0.1", 0), 0)
        server.createContext("/v1/chat/completions") { exchange ->
            authorization += exchange.requestHeaders.getFirst("Authorization")
            bodies += Json.parseToJsonElement(exchange.requestBody.readAllBytes().decodeToString()).jsonObject
            val first = count.getAndIncrement() == 0
            val chunk = buildJsonObject {
                putJsonArray("choices") { add(buildJsonObject {
                    put("index", 0); put("finish_reason", if (first) "tool_calls" else "stop")
                    putJsonObject("delta") { if (first) putJsonArray("tool_calls") { add(buildJsonObject {
                        put("index", 0); put("id", "write1"); put("type", "function")
                        putJsonObject("function") {
                            put("name", "write_text"); put("arguments", buildJsonObject {
                                put("root", "project"); put("path", path); put("content", "candidate")
                            }.toString())
                        }
                    }) } }
                }) }
            }
            val data = "data: $chunk\n\ndata: {\"choices\":[],\"usage\":{\"prompt_tokens\":100,\"completion_tokens\":10}}\n\ndata: [DONE]\n\n"
            val bytes = data.toByteArray()
            exchange.responseHeaders.set("Content-Type", "text/event-stream")
            exchange.sendResponseHeaders(200, bytes.size.toLong()); exchange.responseBody.use { it.write(bytes) }; exchange.close()
        }
        server.start()
        try { block("http://127.0.0.1:${server.address.port}/v1", count, authorization, bodies) } finally { server.stop(0) }
    }

    @Test fun `factory uses a frozen credential and actual configured provider while binding portable provenance`() = fixture { endpoint, count, authorization, bodies ->
        val file = privateFile(config(endpoint).toString().toByteArray())
        val environment = mutableMapOf("BUILTIN_FIXTURE_KEY" to secret)
        val provisioned = BuiltinHarnessProvisioning.loadLoopbackFixture(file.toString(), environment)
        environment["BUILTIN_FIXTURE_KEY"] = "changed-after-resolution"
        assertTrue(provisioned.preflight().journalReady)
        assertEquals(0, count.get())
        val execution = execute(provisioned.createCapturedRepairHarness())
        assertEquals(AgentStopReason.COMPLETED, execution.result.stopReason)
        assertEquals("candidate", execution.files.getValue("source.c")!!.decodeToString())
        assertEquals(2, count.get()); assertEquals(listOf("Bearer $secret", "Bearer $secret"), authorization)
        assertTrue(bodies.all { it.getValue("model") == JsonPrimitive("fixture-model") })
        val evidence = assertIs<BuiltinCapturedExecutionEvidence>(execution.receipt.providerEvidence)
        assertEquals(provisioned.provenance, evidence.factoryProvenance)
        assertEquals(provisioned.provenance, evidence.journalIdentity?.factoryProvenance)
        val archive = assertNotNull(evidence.invocationArchive)
        assertEquals(provisioned.provenance, archive.reference.identity.journal.factoryProvenance)
        assertTrue(provisioned.provenance.fixtureOnly); assertFalse(archive.verified.releaseComplete)
        val raw = archive.bytes.decodeToString()
        assertTrue(listOf(secret, "changed-after-resolution", "BUILTIN_FIXTURE_KEY", endpoint, directory.toString()).none(raw::contains))
        val reference = archive.reference.json()
        val tampered = Json.parseToJsonElement(reference.toString().replace(provisioned.provenance.configurationSha256, "f".repeat(64)))
        val wrong = parseBuiltinInvocationArchiveReference(tampered)
        assertFails { verifyBuiltinInvocationArchive(archive.bytes, wrong.identity, wrong.commitment) }
    }

    @Test fun `arbitrary harness cannot claim journal provenance or bind factory metadata after invocation`() {
        val provenance = load().provenance
        var calls = 0
        val factory = BuiltinRepairJournalFactory(directory.resolve("journals"), provenance.provider, provenance.model,
            factoryProvenance = provenance)
        val harness = BuiltinCapturedRepairHarness(ModelProvider { _, _ -> calls++; error("must not invoke") }, journalFactory = factory)
        assertIs<AgentExecutionOutcome.Failed>(execute(harness).receipt.outcome)
        assertEquals(0, calls)
        assertFails { harness.bindFactoryProvenance(provenance) }
        val configured = load().createCapturedRepairHarness()
        assertFails { configured.bindFactoryProvenance(provenance) }
    }

    @Test fun `configured factory provenance survives graph recovery and archive extraction without private runtime files`() =
        fixture("src/modules/alpha.c") { endpoint, count, _, _ ->
            val configuration = privateFile(config(endpoint).toString().toByteArray())
            val provisioned = BuiltinHarnessProvisioning.loadLoopbackFixture(configuration.toString(), mapOf("BUILTIN_FIXTURE_KEY" to secret))
            lateinit var binding: RepairAgentInvocationBinding
            val project = ModuleRevisionGraphTest().releaseProjectWithRejectedInvocation { graph, project ->
                val relative = "src/modules/alpha.c"
                val attempt = graph.beginAttempt(listOf(relative), RevisionRepairMetadata(
                    graph.snapshot.nodes.count { it.repairMetadata != null } + 1, "compile", "repair", null,
                    graph.retainedRegressionCorpus().inputs.map { it.id }, null, graph.retainedRegressionCorpus().sha256))
                val workflow = graph.invocationIdentity(attempt)
                lateinit var request: AgentExecutionRequest
                val events = BoundedAgentExecutionEventRecorder()
                val execution = CapturedRepairStagingAuthority.executeReceipt(provisioned.createCapturedRepairHarness(),
                    mapOf(relative to project.resolve(relative).readBytes()), setOf(relative), RepairResourceBudget(), { root ->
                        AgentExecutionRequest("repair", listOf(root), accessPolicy = AgentAccessPolicy(listOf(
                            AgentPathRule(AgentWorkspacePath(root.id, relative), setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)))),
                            workflowIdentity = workflow).also { request = it }
                    }, events::record)
                val document = assertNotNull(RepairAgentInvocationDocument.captureOrNull(request, workflow.promptSha256,
                    execution.receipt, events.receiptSnapshot(), attempt.id))
                binding = graph.persistAndBindAgentInvocation(attempt, document)
                graph.reject(attempt, RepairEvidence("unqualified", "fixture execution")); graph.synchronizeRepairHistory()
            }
            assertEquals(2, count.get())
            directory.resolve("journals").listDirectoryEntries().forEach { it.deleteExisting() }
            directory.resolve("journals").deleteExisting(); configuration.deleteExisting()
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile).use { graph ->
                assertEquals(provisioned.provenance, graph.snapshot.nodes.single { it.repairMetadata?.agentInvocation?.receiptPath == binding.receiptPath }.repairMetadata?.agentInvocation
                    ?.builtinArchive?.identity?.journal?.factoryProvenance)
            }
            assertEquals(0, MakeProjectBuilder.build(project).returnCode)
            val bundle = ArchivalPackager.create(project, directory.resolve("factory.zip"))
            val destination = directory.resolve("extracted")
            val lineage = ArchivalBundleVerifier.extractAndVerifyCandidateLineage(bundle.archivePath, destination)
            assertEquals(2, lineage.source.acceptedAcpContributions.size)
            assertTrue(lineage.source.acceptedAcpContributions.none { it.receiptPath == binding.receiptPath })
            assertContentEquals(project.resolve(binding.receiptPath).readBytes(), destination.resolve(binding.receiptPath).readBytes())
            ModuleRevisionGraph.open(destination, GeneratedCRepairIndexProfile).use { graph ->
                assertEquals(provisioned.provenance, graph.snapshot.nodes.single { it.repairMetadata?.agentInvocation?.receiptPath == binding.receiptPath }.repairMetadata?.agentInvocation
                    ?.builtinArchive?.identity?.journal?.factoryProvenance)
            }
        }

    @Test fun `preflight reports unavailable private journal authority without provider calls or filesystem writes`() = fixture { endpoint, count, _, _ ->
        val provisioned = BuiltinHarnessProvisioning.loadLoopbackFixture(privateFile(config(endpoint).toString().toByteArray()).toString(),
            mapOf("BUILTIN_FIXTURE_KEY" to secret))
        directory.resolve("journals").deleteExisting()
        assertFalse(provisioned.preflight().journalReady)
        assertFalse(directory.resolve("journals").exists())
        assertIs<AgentExecutionOutcome.Failed>(execute(provisioned.createCapturedRepairHarness()).receipt.outcome)
        assertEquals(0, count.get())
    }

    @Test fun `credentials cannot be exposed through model identity and parsed provenance cannot relabel implementation`() {
        assertFailsWith<BuiltinProvisioningException> { load(config(model = secret)) }
        val provenance = load().provenance
        assertEquals(provenance, parseBuiltinHarnessProvenance(provenance.json()))
        for (field in listOf("implementationId", "provider", "agentContractVersion", "fixtureOnly")) {
            assertFails { parseBuiltinHarnessProvenance(JsonObject(provenance.json() + (field to JsonPrimitive("substitute")))) }
        }
        assertFails { parseBuiltinHarnessProvenance(JsonObject(provenance.json() + ("endpoint" to JsonPrimitive("private")))) }
    }
}
