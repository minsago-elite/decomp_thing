package decompengine.project

import decompengine.repair.load
import decompengine.repair.open
import decompengine.repair.ModuleRepairIndex
import decompengine.repair.ModuleRevisionGraph
import decompengine.repair.RepairBudgetExceededException
import decompengine.repair.RepairResourceBudget
import kotlin.io.path.createDirectories
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.readBytes
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith

class ProfiledGeneratedCRepairIndexTest {
    private fun profile(
        base: ReconstructionProfile,
        buildRoot: String = "config/build",
        sourceRoot: String = "src",
        interfaceRoot: String = "include",
    ) = ReconstructionProfile(
        base.schemaVersion, base.id,
        ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map {
            val path = when (it.id) {
                "build-definition" -> "$buildRoot/" + it.pathTemplate
                "module-plan-evidence" -> "reports/planning/modules.json"
                "program-model-evidence" -> "reports/inputs/model.json"
                else -> it.pathTemplate
                    .replace(Regex("^src/"), "$sourceRoot/")
                    .replace(Regex("^include/"), "$interfaceRoot/")
            }
            ProjectFileDeclaration(it.id, path,
                if (it.id in setOf("shared-interface", "module-interface")) it.roles - ProjectFileRole.EDITABLE else it.roles, it.contentKind)
        }), base.budgets, base.adapterConfiguration,
    )

    @Test
    fun `repair index admits schema three bytes and historical schemas without weakening closed fields`() {
        val window = ReferencedDataByteWindow(0x2000UL, 8,
            ReferencedDataByteOrigin(0x1000UL, 0x2000UL, 0, "pcode_direct_read"), "available",
            listOf(ReferencedDataByteSegment(0, 8, "available", "000000000000e03f", null)))
        for (version in 1..3) {
            val project = createTempDirectory("repair-model-migration-")
            val byteEvidence = if (version == 3) ReferencedDataByteEvidence(windows = listOf(window)) else null
            val model = RecoveredProgramModel(schemaVersion = version, inputSha256 = "a".repeat(64),
                functions = listOf(RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)",
                    referencedGlobals = setOf("global_authored"))),
                globals = listOf(RecoveredGlobal("global_authored", "authored", 0x2000UL, "undefined1", "00h", byteEvidence = byteEvidence)))
            SourceTreeGenerator.generate(model, project)
            ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
            if (version == 3) {
                val path = project.resolve("reports/program_model.json")
                val original = path.readText()
                for (changed in listOf(
                    original.replace("\"requestedLength\":8", "\"requestedLength\":257"),
                    original.replace("\"widthBasis\":\"pcode_direct_read\"", "\"widthBasis\":\"guessed\""),
                    original.replace("\"widthBasis\":\"pcode_direct_read\"", "\"widthBasis\":\"guessed\",\"widthBasis\":\"pcode_direct_read\""),
                    original.replace("\"byteEvidence\":", "\"unchecked\":null,\"byteEvidence\":"),
                    original.replace("\"recoveryAssessment\": \"unassessed\"", "\"recoveryAssessment\": \"abi-equivalent\""),
                )) {
                    assertTrue(changed != original)
                    path.writeText(changed)
                    assertFailsWith<IllegalArgumentException> { ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile) }
                }
                val windowWire = ReferencedDataByteEvidenceJson.render(requireNotNull(byteEvidence))
                    .substringAfter("\"windows\":[").substringBefore("],\"omissionReason\"")
                path.writeText(original.substringBefore("\"windows\":[") + "\"windows\":[" +
                    List(32) { windowWire }.joinToString(",") + ",{\"oversized\":\"" + "x".repeat(1_000_000))
                val failure = assertFailsWith<IllegalArgumentException> {
                    ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
                }
                assertTrue(failure.message.orEmpty().contains("window bound"))
                path.writeText(original)
                ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
            }
        }
    }

    @Test
    fun `repair index model four retains nullable evidence and supplied omission pairing`() {
        val window = ReferencedDataByteWindow(0x2000UL, 8,
            ReferencedDataByteOrigin(0x1000UL, 0x2000UL, 0, "pcode_direct_read"), "available",
            listOf(ReferencedDataByteSegment(0, 8, "available", "000000000000e03f", null)))
        val cases = listOf(null, ReferencedDataByteEvidence(2, listOf(window)),
            ReferencedDataByteEvidence(2, emptyList(), collectionOmissions = listOf("reference_work_limit")))
        for (evidence in cases) {
            val project = createTempDirectory("repair-model-four-")
            val model = RecoveredProgramModel(4, "a".repeat(64),
                listOf(RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)", referencedGlobals = setOf("g"))),
                listOf(RecoveredGlobal("g", "authored", 0x2000UL, "undefined1", "00h", byteEvidence = evidence)))
            SourceTreeGenerator.generate(model, project)
            ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
            val path = project.resolve("reports/program_model.json")
            val original = path.readText()
            val bad = mutableListOf(original.replace("\"recoveryAssessment\": \"unassessed\"", "\"recoveryAssessment\": \"assessed\""))
            bad += original.replace("\"byteEvidence\":", "\"byteEvidence\":null,\"byteEvidence\":")
            if (evidence == null) bad += original.replace("\"byteEvidence\": null,", "")
            else {
                bad += original.replace("\"schemaVersion\": 4", "\"schemaVersion\": 3")
                bad += original.replace("\"schemaVersion\":2", "\"schemaVersion\":1")
                if (evidence.windows.isNotEmpty()) bad += original.replace("\"requestedLength\":8", "\"requestedLength\":257")
                else bad += original.replace("reference_work_limit", "invented")
            }
            for (changed in bad) {
                assertTrue(changed != original)
                path.writeText(changed)
                assertFailsWith<IllegalArgumentException> { ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile) }
            }
            path.writeText(original)
            ModuleRepairIndex.load(project, GeneratedCRepairIndexProfile)
        }
    }

    @Test
    fun `relocated declared roots retain dependency context and recover under the same descriptor`() {
        val descriptor = profile(GeneratedCMakeReconstructionProfile.descriptor,
            sourceRoot = "workspace/code", interfaceRoot = "workspace/headers")
        val policy = GeneratedCRepairIndexProfile.forProfile(descriptor)
        val project = createTempDirectory("relocated-repair-roots-")
        SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "b".repeat(64), functions = listOf(
            RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)"),
        )), project, profile = descriptor)
        project.resolve("workspace/code/auxiliary.c").writeText("/* read-only auxiliary */\n")
        val index = ModuleRepairIndex.load(project, policy)
        assertTrue("workspace/code/modules/alpha.c" in index.sourcePaths)
        assertTrue("workspace/headers/modules/alpha.h" in index.sourcePaths)
        assertTrue("workspace/code/auxiliary.c" in index.sourcePaths)
        assertFalse("workspace/code/auxiliary.c" in index.editablePaths)
        assertFalse("include/decomp_types.h" in index.sourcePaths)
        val selection = index.select("compile", "workspace/code/modules/alpha.c:1: error: authored diagnostic")
        assertTrue("workspace/headers/modules/alpha.h" in selection.readablePaths)
        assertFalse("workspace/headers/modules/alpha.h" in selection.writablePaths)
        val target = project.resolve("workspace/code/modules/alpha.c")
        val accepted = target.readBytes()
        val candidate = accepted + "\n/* pending authored revision */\n".toByteArray()
        ModuleRevisionGraph.open(project, policy).use { graph ->
            val attempt = graph.beginAttempt(listOf("workspace/code/modules/alpha.c"))
            graph.installCandidate(attempt, mapOf("workspace/code/modules/alpha.c" to candidate))
        }
        val graphPath = project.resolve("reports/repair-revisions/graph.json")
        val graphBefore = graphPath.readBytes()
        val changed = GeneratedCRepairIndexProfile.forProfile(
            profile(GeneratedCMakeReconstructionProfile.descriptor,
                sourceRoot = "workspace/code", interfaceRoot = "headers"))
        assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, changed) }
        assertContentEquals(candidate, target.readBytes())
        assertContentEquals(graphBefore, graphPath.readBytes())
        ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(descriptor)).use { recovered ->
            assertContentEquals(accepted, target.readBytes())
            assertEquals(null, recovered.snapshot.pendingAttemptId)
        }
    }

    @Test
    fun `Make and Ninja index declared evidence and recover the same graph`() {
        for (base in ReconstructionProfiles.builtIn) {
            val descriptor = profile(base)
            val profile = GeneratedCRepairIndexProfile.forProfile(descriptor)
            val project = createTempDirectory("profile-repair-index-")
            SourceTreeGenerator.generate(RecoveredProgramModel(inputSha256 = "a".repeat(64), functions = listOf(
                RecoveredFunction("fn_alpha", "alpha_run", 0x1000UL, "int alpha_run(void)", calls = setOf("fn_beta")),
                RecoveredFunction("fn_beta", "beta_read", 0x2000UL, "int beta_read(void)"),
            )), project, profile = descriptor)
            project.resolve("src/unlisted.c").writeText("/* authored read-only auxiliary input */\n")
            val index = ModuleRepairIndex.load(project, profile)
            val buildDefinition = descriptor.layout.declaration("build-definition").materialize()
            assertTrue(buildDefinition in index.sourcePaths)
            assertTrue(buildDefinition in index.editablePaths)
            assertFalse("include/decomp_types.h" in index.editablePaths)
            assertFalse("src/unlisted.c" in index.editablePaths)
            val selection = index.select("compile", "src/modules/alpha.c:1: error: authored diagnostic")
            assertEquals(listOf("alpha"), selection.seedModules)
            assertEquals(listOf("beta"), selection.dependencyModules)
            assertTrue("include/modules/beta.h" in selection.readablePaths)
            assertFalse("include/decomp_types.h" in selection.writablePaths)
            assertTrue("include/modules/alpha.h" in selection.readablePaths)
            assertFalse("include/modules/alpha.h" in selection.writablePaths)
            assertTrue(profile.authorizesRecoveryLayout(index.sourcePaths, index.editablePaths.sorted(), RepairResourceBudget()))
            val target = project.resolve("src/modules/alpha.c")
            val accepted = target.readBytes()
            val candidate = accepted + "\n/* pending authored revision */\n".toByteArray()
            ModuleRevisionGraph.open(project, profile).use { graph ->
                val attempt = graph.beginAttempt(listOf("src/modules/alpha.c"))
                graph.installCandidate(attempt, mapOf("src/modules/alpha.c" to candidate))
            }
            val graphPath = project.resolve("reports/repair-revisions/graph.json")
            val before = graphPath.readBytes()
            val changed = GeneratedCRepairIndexProfile.forProfile(base)
            assertFalse(changed.configurationSha256() == profile.configurationSha256())
            val failure = assertFailsWith<IllegalArgumentException> { ModuleRevisionGraph.open(project, changed) }
            assertTrue(failure.message.orEmpty().contains("profile fingerprint differs"))
            assertContentEquals(candidate, target.readBytes())
            assertContentEquals(before, graphPath.readBytes())
            ModuleRevisionGraph.open(project, GeneratedCRepairIndexProfile.forProfile(descriptor)).use { recovered ->
                assertContentEquals(accepted, target.readBytes())
                assertEquals(null, recovered.snapshot.pendingAttemptId)
            }
        }
    }

    @Test
    fun `nested build discovery charges ancestors to traversal budgets`() {
        val descriptor = profile(GeneratedCMakeReconstructionProfile.descriptor)
        val policy = GeneratedCRepairIndexProfile.forProfile(descriptor)
        val project = createTempDirectory("nested-repair-build-budget-")
        val relative = descriptor.layout.declaration("build-definition").materialize()
        project.resolve(relative).parent.createDirectories()
        project.resolve(relative).writeText("# authored build-definition inventory fixture\n")
        val budget = RepairResourceBudget()
        assertEquals(listOf(relative), policy.resolve(project, budget).sourcePaths)
        val entryFailure = assertFailsWith<RepairBudgetExceededException> {
            policy.resolve(project, budget.copy(maximumDiscoveryEntries = 1, maximumDiscoveryDirectories = 1))
        }
        assertTrue(entryFailure.message.orEmpty().contains("entries at config/build"))
        val directoryFailure = assertFailsWith<RepairBudgetExceededException> {
            policy.resolve(project, budget.copy(maximumDiscoveryDirectories = 1))
        }
        assertTrue(directoryFailure.message.orEmpty().contains("directories at config/build"))
        val depthFailure = assertFailsWith<IllegalArgumentException> {
            policy.resolve(project, budget.copy(maximumDiscoveryDepth = 2))
        }
        assertTrue(depthFailure.message.orEmpty().contains("build definition exceeds discovery depth"))
    }

    @Test
    fun `build definition within a source root consumes one source file slot`() {
        val descriptor = profile(GeneratedCMakeReconstructionProfile.descriptor, "src")
        val project = createTempDirectory("repair-build-source-overlap-")
        val relative = descriptor.layout.declaration("build-definition").materialize()
        project.resolve(relative).parent.createDirectories()
        project.resolve(relative).writeText("# authored build-definition inventory fixture\n")
        val budget = RepairResourceBudget(maximumSourceFiles = 1, maximumContextFiles = 1,
            maximumStagingDirectories = 1, maximumPatchFiles = 1)
        val layout = GeneratedCRepairIndexProfile.forProfile(descriptor).resolve(project, budget)
        assertEquals(listOf(relative), layout.sourcePaths)
        assertEquals(listOf(relative), layout.editablePaths)
    }

    @Test
    fun `unregistered repair descriptors are rejected at construction`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        assertFailsWith<IllegalArgumentException> {
            GeneratedCRepairIndexProfile.forProfile(ReconstructionProfile(base.schemaVersion, "unregistered-repair-v1",
                base.layout, base.budgets, base.adapterConfiguration))
        }
    }
}
