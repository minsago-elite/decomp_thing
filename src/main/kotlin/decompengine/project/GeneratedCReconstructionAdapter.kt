package decompengine.project

import decompengine.repair.readStableRegularFile
import decompengine.repair.RepairIndexProfile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Generated-C/Make implementations selected together for the registered profile. */
internal object GeneratedCReconstructionAdapter : ReconstructionAdapter {
    override fun repairIndexProfile(profile: ReconstructionProfile): RepairIndexProfile =
        GeneratedCRepairIndexProfile.forProfile(profile)
    override val diagnostics: ToolchainDiagnosticPolicy = GeneratedCToolchainDiagnostics("gnu-make", "Make")
    override val compilation: ModuleCompilationPolicy = GeneratedCModuleValidation
    override val archiveBuild: ArchiveBuildPolicy = GeneratedCArchiveBuildPolicy
    override val behaviorBuild: BehaviorBuildPolicy = GeneratedCBehaviorBuildPolicy
    override val mvpPatchCompiler: MvpPatchCompilerPolicy = GeneratedCMvpPatchCompilerPolicy
    override fun validateProfile(profile: ReconstructionProfile) { GeneratedCEvidenceCarrier.isSelected(profile) }
    override fun evidenceOnlyProfile(profile: ReconstructionProfile): ReconstructionProfile = GeneratedCEvidenceCarrier.profile(profile)
    override fun evidenceOnlyReconstructor(profile: ReconstructionProfile): ModuleReconstructor {
        validateProfile(profile)
        return GeneratedCEvidenceCarrier.reconstructor
    }
    override fun requireImplementationPurpose(profile: ReconstructionProfile, operation: String) =
        GeneratedCEvidenceCarrier.requireImplementationPurpose(profile, operation)
    override fun verifyArchivePurpose(projectDir: Path, profile: ReconstructionProfile, manifest: SourceTreeManifest,
        payloadPaths: Set<String>) = GeneratedCEvidenceCarrier.verifyArchivePurpose(projectDir, profile, manifest, payloadPaths)
    override fun validateArchivedCheckpoint(profile: ReconstructionProfile, source: GeneratedFileEvidence,
        checkpoint: ArchivedModuleCheckpointProvenance) = GeneratedCEvidenceCarrier.validateArchivedCheckpoint(profile, source, checkpoint)
    override fun rendering(model: RecoveredProgramModel, plan: ModulePlan, profile: ReconstructionProfile): ProjectRendering =
        if (GeneratedCEvidenceCarrier.isSelected(profile)) GeneratedCEvidenceCarrier.rendering(model, plan, profile)
        else GeneratedCProjectRendering(model, plan)
    override fun admitGeneration(projectDir: Path, profile: ReconstructionProfile, reconstructor: ModuleReconstructor) {
        GeneratedCEvidenceCarrier.requireReconstructor(profile, reconstructor)
        GeneratedCEvidenceCarrier.requireWorkspacePurpose(projectDir, profile)
    }
    override fun requiresUnresolvedOutput(profile: ReconstructionProfile): Boolean = GeneratedCEvidenceCarrier.isSelected(profile)
    override fun diagnosticPurposeDescription(profile: ReconstructionProfile): String {
        require(GeneratedCEvidenceCarrier.isSelected(profile))
        return GeneratedCEvidenceCarrier.PURPOSE
    }
    override fun validateSourceContent(profile: ReconstructionProfile, bytes: ByteArray, label: String) {
        if (!GeneratedCEvidenceCarrier.isSelected(profile)) GeneratedCEvidenceCarrier.rejectCarrierContent(bytes, label)
    }
    override fun build(
        projectDir: Path,
        profile: ReconstructionProfile,
        hostSafetyLimits: ReconstructionHostSafetyLimits,
    ): BuildReport {
        hostSafetyLimits.requireAllows(profile.budgets)
        val configuration = ProjectBuildConfiguration(
            makeExecutable = profile.adapterConfiguration["build-executable"]?.singleOrNull() ?: "make",
            compilerExecutable = profile.adapterConfiguration["compiler-driver"]?.singleOrNull() ?: "gcc",
            cFlags = profile.adapterConfiguration["compiler-flags"] ?: ProjectBuildConfiguration().cFlags,
            wallClockTimeoutMillis = profile.budgets.buildWallClockMillis,
            maximumOutputBytes = profile.budgets.buildMaximumOutputBytes,
            buildDefinition = profile.layout.declaration("build-definition").materialize(),
        )
        requireMakeDefinitionBindsConfiguration(projectDir, profile, configuration)
        return MakeProjectBuilder.build(projectDir, configuration, profile, hostSafetyLimits)
    }

    private fun requireMakeDefinitionBindsConfiguration(
        projectDir: Path,
        profile: ReconstructionProfile,
        configuration: ProjectBuildConfiguration,
    ) {
        val definition = projectDir.resolve(configuration.buildDefinition)
        if (!Files.isRegularFile(definition, LinkOption.NOFOLLOW_LINKS)) return
        val ceiling = minOf(configuration.maximumOutputBytes, Int.MAX_VALUE.toLong() - 1L)
        val text = readStableRegularFile(projectDir, configuration.buildDefinition, ceiling).bytes.toString(Charsets.UTF_8)
        require(text.lines().none { it.substringBefore('#').trimStart().startsWith("override", ignoreCase = true) }) {
            "Make build definitions must not override command-line compiler settings"
        }
        require(text.lines().none {
            val directive = it.substringBefore('#').trimStart()
            directive.startsWith("include", ignoreCase = true) ||
                directive.startsWith("sinclude", ignoreCase = true) ||
                (directive.startsWith("-include", ignoreCase = true) && directive != "-include $(OBJECTS:.o=.d)")
        }) {
            "Make build definitions must not include external files"
        }
    }

    override fun modulePrompt(request: ModuleReconstructionRequest): ModulePromptContent = GeneratedCModulePrompt.render(request)
    override fun defaultReconstructor(): ModuleReconstructor = EvidenceModuleReconstructor()
    override fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String): List<ModuleReconstructionIssue> =
        if (generator == GeneratedCEvidenceCarrier.IDENTITY ||
            GeneratedCEvidenceCarrier.isCarrierContent(source.toByteArray(Charsets.UTF_8))) listOf(ModuleReconstructionIssue("evidence-only-carrier",
            "diagnostic carrier identity cannot authorize implementation acceptance", module.functionIds + module.globalIds))
        else GeneratedCCandidateValidation.assess(module, model, generator, source)
    override fun assess(module: PlannedModule, model: RecoveredProgramModel, generator: String, source: String,
        profile: ReconstructionProfile): List<ModuleReconstructionIssue> =
        if (GeneratedCEvidenceCarrier.isSelected(profile)) listOf(ModuleReconstructionIssue("evidence-only-carrier",
            "diagnostic inventory cannot supply recovered implementations", module.functionIds + module.globalIds))
        else assess(module, model, generator, source)
    override fun toolchainEvidence(profile: ReconstructionProfile): String = GeneratedCToolchainEvidence.render(profile)
}
