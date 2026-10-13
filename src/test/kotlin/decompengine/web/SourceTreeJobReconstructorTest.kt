package decompengine.web

import decompengine.jobs.JobStore
import decompengine.jobs.elfFixture
import decompengine.project.BoundedLlmModuleReconstructor
import decompengine.project.ArchivalBundleVerifier
import decompengine.project.ProgramModelAnalyzer
import decompengine.project.ProjectFileRole
import decompengine.project.ReconstructionAdapters
import decompengine.project.ReconstructionProfiles
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredGlobal
import decompengine.project.RecoveredProgramModel
import decompengine.project.RecoveredType
import decompengine.project.RecoveryStatus
import decompengine.project.SourceTreeManifestReader
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertContentEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SourceTreeJobReconstructorTest {
    @Test
    fun `busy display journal does not replace reconstruction configuration failure`() {
        val store = JobStore(createTempDirectory("web-reconstruction-busy-"))
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val reports = store.reportsDirectory(job.id)
        decompengine.jobs.AgentProgressJournal(reports, "reconstruction").use {
            val failure = assertFailsWith<IllegalArgumentException> {
                SourceTreeJobReconstructor(emptyMap()).reconstruct(job, reports)
            }
            assertTrue(failure.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
        }
    }

    @Test
    fun `web reconstruction defaults to ACP and never infers legacy use from credentials`() {
        val failure = assertFailsWith<IllegalArgumentException> {
            selectWebReconstructionStrategy(
                mapOf(
                    "BASE_URL" to "https://example.invalid/v1",
                    "API_KEY" to "old-implicit-key",
                    "MODEL" to "old-implicit-model",
                ),
            )
        }

        assertTrue(failure.message.orEmpty().contains("ACP_CONFIG_FILE is required"))
    }

    @Test
    fun `legacy OpenAI web reconstruction requires explicit harness opt-in and records deprecation`() {
        val strategy = selectWebReconstructionStrategy(legacyEnvironment())

        assertEquals(WebReconstructionMode.AGENT, strategy.mode)
        assertIs<BoundedLlmModuleReconstructor>(strategy.reconstructor)
        assertEquals(ReconstructionProfiles.default.sha256, strategy.profile.sha256)
        assertTrue(!strategy.reconstructor.cacheIdentity().contains("factory-unbound"))
        val provenance = requireNotNull(strategy.harnessProvenance)
        assertEquals("legacy-openai", provenance.harness)
        assertTrue(provenance.deprecated)
        assertEquals(
            "agent-harness-v1:legacy-openai:contract-1:acp-none:sdk-none:" +
                "implementation-legacy-openai-compatible:configuration-none:deprecated",
            provenance.stableDescriptor,
        )

        val report = Json.parseToJsonElement(renderWebReconstructionHarnessSelection(strategy)).jsonObject
        assertEquals(1, report.getValue("schemaVersion").jsonPrimitive.int)
        assertEquals("agent", report.getValue("mode").jsonPrimitive.content)
        val selection = report.getValue("selection").jsonObject
        assertEquals(provenance.stableDescriptor, selection.getValue("stableDescriptor").jsonPrimitive.content)
        assertEquals("legacy-openai", selection.getValue("harness").jsonPrimitive.content)
        assertTrue(selection.getValue("deprecated").jsonPrimitive.boolean)
        assertTrue("legacy-key" !in report.toString())
    }

    @Test
    fun `web evidence-only reconstruction is explicit and does not resolve a harness`() {
        val environment = object : AbstractMap<String, String>() {
            override val entries: Set<Map.Entry<String, String>>
                get() = error("evidence-only web reconstruction must not enumerate the environment")

            override fun get(key: String): String? =
                if (key == "WEB_RECONSTRUCTION_MODE") "evidence-only" else {
                    error("evidence-only web reconstruction must not read $key")
                }
        }

        for (base in ReconstructionProfiles.builtIn) {
            val strategy = selectWebReconstructionStrategy(environment, profile = base)
            val expected = ReconstructionAdapters.resolve(base).evidenceOnlyProfile(base)
            val adapter = ReconstructionAdapters.resolve(strategy.profile)
            assertEquals(WebReconstructionMode.EVIDENCE_ONLY, strategy.mode)
            assertEquals(base.id, strategy.profile.id)
            assertNotEquals(base.sha256, strategy.profile.sha256)
            assertEquals(expected.sha256, strategy.profile.sha256)
            assertTrue(adapter.requiresUnresolvedOutput(strategy.profile))
            assertSame(adapter.evidenceOnlyReconstructor(strategy.profile), strategy.reconstructor)
            assertNull(strategy.harnessProvenance)
            val report = Json.parseToJsonElement(renderWebReconstructionHarnessSelection(strategy)).jsonObject
            assertEquals("evidence-only", report.getValue("mode").jsonPrimitive.content)
            assertEquals(JsonNull, report.getValue("selection"))
        }
    }

    @Test
    fun `web evidence-only job archives unsupported raw declarations without claiming recovery`() {
        val parent = Path.of("build", "web-evidence-only-tests").also { it.createDirectories() }
        val root = Files.createTempDirectory(parent, "job-")
        try {
            val store = JobStore(root.resolve("jobs"))
            val input = elfFixture()
            val job = store.createFromUpload("raw-evidence.elf", input)
            val inputSha256 = MessageDigest.getInstance("SHA-256").digest(input).joinToString("") { "%02x".format(it) }
            val model = RecoveredProgramModel(schemaVersion = 2, inputSha256 = inputSha256,
                functions = listOf(RecoveredFunction("fn_main", "main", 0x401000UL,
                    "undefined8 main(EVP_PKEY_CTX *ctx)",
                    "undefined8 main(EVP_PKEY_CTX *ctx) { return RAW_ENTRY_MUST_NOT_COMPILE; }",
                    referencedGlobals = setOf("global_pointer", "global_byte"))),
                globals = listOf(
                    RecoveredGlobal("global_pointer", "PTR_00103fe8", 0x403000UL, "pointer", "00105048"),
                    RecoveredGlobal("global_byte", "DAT_0010200b", 0x404000UL, "undefined1", "72h    r")),
                types = listOf(RecoveredType("type_partial", "typedef struct raw_type { undefined8 member; } raw_type;",
                    status = RecoveryStatus.PARTIAL)))
            val canonical = model.toJson().toByteArray(Charsets.UTF_8)
            var analysisCalls = 0
            val analyzer = ProgramModelAnalyzer { binary, _ ->
                analysisCalls++
                assertEquals(job.binaryPath, binary)
                assertContentEquals(input, binary.readBytes())
                model
            }
            val environment = mapOf("WEB_RECONSTRUCTION_MODE" to "evidence-only")
            val reports = store.reportsDirectory(job.id)
            SourceTreeJobReconstructor(environment, analyzer).reconstruct(job, reports)
            assertEquals(1, analysisCalls)
            assertContentEquals(canonical, model.toJson().toByteArray(Charsets.UTF_8))
            val project = reports.resolve("source-tree")
            assertContentEquals(canonical, project.resolve("reports/program_model.json").readBytes())
            val profile = selectWebReconstructionStrategy(environment).profile
            val manifest = SourceTreeManifestReader.read(project, profile)
            val ids = (model.functions.map { it.id } + model.globals.map { it.id } + model.types.map { it.id }).toSet()
            assertEquals(ids, manifest.unresolvedEntityIds.toSet())
            assertEquals(ids, manifest.files.flatMap { it.entityIds }.toSet())
            val implementations = manifest.files.filter { ProjectFileRole.MODULE_IMPLEMENTATION in it.roles }
            assertTrue(implementations.isNotEmpty())
            assertTrue(implementations.all { it.acceptedImplementation == false })
            assertEquals((model.functions.map { it.id } + model.globals.map { it.id }).toSet(),
                manifest.unresolvedImplementationIds.toSet())
            val confidence = Json.parseToJsonElement(project.resolve("reports/confidence.json").readText()).jsonObject
            assertEquals(ids, confidence.getValue("unresolvedEntityIds").jsonArray.map { it.jsonPrimitive.content }.toSet())
            val result = Json.parseToJsonElement(reports.resolve("reconstruction.json").readText()).jsonObject
            assertEquals(0, result.getValue("buildExitCode").jsonPrimitive.int)
            assertEquals("unresolved", result.getValue("implementationStatus").jsonPrimitive.content)
            assertEquals(profile.sha256, result.getValue("profileSha256").jsonPrimitive.content)
            val selection = Json.parseToJsonElement(reports.resolve("reconstruction_harness_selection.json").readText()).jsonObject
            assertEquals("evidence-only", selection.getValue("mode").jsonPrimitive.content)
            assertEquals(JsonNull, selection.getValue("selection"))
            val archive = reports.resolve("source-tree.zip")
            assertTrue(archive.exists())
            // Exercise the same exact host-owned profile set used by the web server.
            val hostProfiles = defaultWebSourceProfiles()
            assertFailsWith<IllegalArgumentException> {
                WebSourceEvidence(store, hostProfiles + hostProfiles.first())
            }
            assertFailsWith<IllegalArgumentException> {
                WebSourceEvidence(store, ReconstructionProfiles.builtIn).read(job.id)
            }
            val sources = WebSourceEvidence(store, hostProfiles)
            val sourceView = sources.read(job.id)
            assertEquals(profile.sha256, sourceView.profile.sha256)
            assertEquals(canonical.decodeToString(), sourceView.text("reports/program_model.json"))
            assertEquals(manifest.files.filter { ProjectFileRole.VIEWABLE in it.roles }.map { it.path }.toSet(),
                sourceView.view().files.map { it.path }.toSet())
            val archives = WebArchiveEvidence(store, sources)
            val downloadable = archives.read(job.id, result.getValue("archiveSha256").jsonPrimitive.content)
            assertContentEquals(archive.readBytes(), downloadable.bytes)
            assertEquals(result.getValue("archiveSha256").jsonPrimitive.content, downloadable.source.archiveSha256)
            val contract = Json.parseToJsonElement(project.resolve("reports/build_contract.json").readText()).jsonObject
            val adapter = ReconstructionAdapters.resolve(profile)
            assertEquals(contract.getValue("sourceRevisionSha256").jsonPrimitive.content,
                adapter.archiveBuild.parseContract(contract, profile).sourceRevisionSha256)
            assertFailsWith<IllegalArgumentException> { adapter.behaviorBuild.parseContract(contract, profile) }
            val manifestPath = project.resolve("source_tree_manifest.json")
            val manifestBytes = manifestPath.readBytes()
            val manifestJson = Json.parseToJsonElement(manifestBytes.decodeToString()).jsonObject
            for ((field, value) in listOf("profileId" to "unadmitted-host-profile", "profileSha256" to "0".repeat(64))) {
                try {
                    manifestPath.writeText(JsonObject(manifestJson + (field to JsonPrimitive(value))).toString())
                    assertFailsWith<IllegalArgumentException> { sources.read(job.id) }
                    assertFailsWith<IllegalArgumentException> { archives.read(job.id) }
                } finally { manifestPath.writeBytes(manifestBytes) }
            }
            val executable = project.resolve("build/reconstructed")
            val executableBytes = executable.readBytes()
            try {
                executable.writeBytes(executableBytes + 0)
                assertFailsWith<IllegalArgumentException> { archives.read(job.id) }
            } finally { executable.writeBytes(executableBytes) }
            val extracted = root.resolve("extracted")
            ArchivalBundleVerifier.extractAndVerify(archive, extracted, profile = profile)
            assertContentEquals(canonical, extracted.resolve("reports/program_model.json").readBytes())
            assertEquals(ids, SourceTreeManifestReader.read(extracted, profile).unresolvedEntityIds.toSet())
            assertEquals(0, ReconstructionAdapters.resolve(profile).build(extracted, profile).returnCode)
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `unknown web reconstruction modes fail closed`() {
        listOf("", "ACP", " agent", "legacy-openai", "evidence-only ").forEach { configured ->
            val failure = assertFailsWith<IllegalArgumentException>(configured) {
                selectWebReconstructionStrategy(mapOf("WEB_RECONSTRUCTION_MODE" to configured))
            }
            assertTrue(failure.message.orEmpty().contains("must be exactly agent or evidence-only"))
        }
    }

    @Test
    fun `web job persists stable harness selection before bundled analysis`() {
        val root = createTempDirectory("web-reconstruction-selection-")
        val store = JobStore(root)
        val job = store.createFromUpload("fixture.elf", elfFixture())
        val reports = store.reportsDirectory(job.id)

        val failure = assertFailsWith<IllegalStateException> {
            SourceTreeJobReconstructor(legacyEnvironment(), decompengine.project.ProgramModelAnalyzer { _, _ ->
                error("expected analysis failure")
            }).reconstruct(job, reports)
        }

        assertEquals("expected analysis failure", failure.message)
        val artifact = reports.resolve("reconstruction_harness_selection.json")
        assertTrue(artifact.exists())
        val report = Json.parseToJsonElement(artifact.readText()).jsonObject
        assertEquals("agent", report.getValue("mode").jsonPrimitive.content)
        assertEquals(
            "legacy-openai",
            report.getValue("selection").jsonObject.getValue("harness").jsonPrimitive.content,
        )
    }

    private fun legacyEnvironment(): Map<String, String> = mapOf(
        "ACP_HARNESS" to "legacy-openai",
        "BASE_URL" to "https://example.invalid/v1",
        "API_KEY" to "legacy-key",
        "MODEL" to "legacy-model",
    )
}
