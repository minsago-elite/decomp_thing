package decompengine.project

import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse

class ArchivalReconstructionTest {
    @Test
    fun `service recovers builds and packages a complete source tree`() {
        val temp = createTempDirectory("archival-service-")
        val binary = temp.resolve("input.elf").also { it.writeBytes(byteArrayOf(1, 2, 3)) }
        val analyzer = ProgramModelAnalyzer { supplied, work ->
            assertEquals(binary, supplied)
            assertTrue(work.toString().endsWith("analysis"))
            RecoveredProgramModel(
                inputSha256 = sha256(supplied.toFile().readBytes()),
                functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")),
            )
        }

        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, base.id, base.layout, base.budgets,
            base.adapterConfiguration + mapOf(
                "build-executable" to listOf("/usr/bin/make"),
                "compiler-driver" to listOf("/usr/bin/cc"),
            ))
        val result = ArchivalReconstructionService(analyzer, profile = profile).reconstruct(binary, temp.resolve("result"))

        assertEquals(0, result.build.returnCode)
        assertEquals("/usr/bin/make", result.build.command.first())
        assertTrue("CC=/usr/bin/cc" in result.build.command)
        assertTrue(result.projectDir.resolve("src/modules/decomp.c").exists())
        assertTrue(result.bundle.archivePath.exists())
        assertTrue(temp.resolve("result/reconstruction.json").readText().contains(result.bundle.archiveSha256))
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerify(result.bundle.archivePath, extracted, profile = profile)
        val rebuilt = ReconstructionAdapters.resolve(profile).build(extracted, profile)
        assertEquals(0, rebuilt.returnCode)
        assertEquals(result.build.command, rebuilt.command)
        assertEquals(ArchivalProjectAuditor.audit(result.projectDir, profile).moduleRevisionSha256,
            ArchivalProjectAuditor.audit(extracted, profile).moduleRevisionSha256)
    }

    @Test
    fun `service archives declared report paths and rebuilds the extracted project`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val relocated = mapOf(
            "program-model-evidence" to "reports/inputs/model.json",
            "confidence-evidence" to "reports/assessment/confidence.json",
            "toolchain-evidence" to "reports/environment/tools.json",
            "unresolved-evidence" to "reports/assessment/unresolved.md",
        )
        val layout = ProjectLayoutProfile(base.layout.schemaVersion, base.layout.declarations.map { declaration ->
            ProjectFileDeclaration(declaration.id, relocated[declaration.id] ?: declaration.pathTemplate,
                declaration.roles, declaration.contentKind)
        })
        val profile = ReconstructionProfile(base.schemaVersion, base.id, layout, base.budgets, base.adapterConfiguration)
        val temp = createTempDirectory("declared-archive-reports-")
        val input = temp.resolve("input.bin").also { it.writeBytes(byteArrayOf(4, 5, 6)) }
        val analyzer = ProgramModelAnalyzer { _, _ -> RecoveredProgramModel(
            inputSha256 = sha256(input.toFile().readBytes()),
            functions = listOf(RecoveredFunction("fn_1000", "decomp_engine_main", 0x1000UL, "int decomp_engine_main(void)")),
        ) }
        val result = ArchivalReconstructionService(analyzer, profile = profile).reconstruct(input, temp.resolve("result"))
        for ((id, path) in relocated) {
            assertTrue(result.projectDir.resolve(path).exists(), id)
            assertFalse(result.projectDir.resolve(base.layout.declaration(id).materialize()).exists(), id)
        }
        val extracted = temp.resolve("extracted")
        ArchivalBundleVerifier.extractAndVerifySnapshot(result.bundle.archivePath.toFile().readBytes(), extracted,
            ArchivalBundleLimits(), profile, 2048)
        for (path in relocated.values) assertEquals(result.projectDir.resolve(path).readText(), extracted.resolve(path).readText())
        assertEquals(0, ReconstructionAdapters.resolve(profile).build(extracted, profile).returnCode)
        assertEquals(ArchivalProjectAuditor.audit(result.projectDir, profile).toJson(),
            ArchivalProjectAuditor.audit(extracted, profile).toJson())
    }

    @Test
    fun `service rejects unsupported profiles before analysis or output writes`() {
        val base = GeneratedCMakeReconstructionProfile.descriptor
        val profile = ReconstructionProfile(base.schemaVersion, "unsupported-service-v1", base.layout,
            base.budgets, base.adapterConfiguration)
        val temp = createTempDirectory("unsupported-service-")
        val output = temp.resolve("result")
        var calls = 0
        val analyzer = ProgramModelAnalyzer { _, _ -> calls++; error("must not analyze") }
        assertFailsWith<IllegalArgumentException> {
            ArchivalReconstructionService(analyzer, profile = profile).reconstruct(temp.resolve("unused"), output)
        }
        assertEquals(0, calls)
        assertFalse(output.exists())
    }

}
