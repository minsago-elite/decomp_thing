package decompengine.repair

import decompengine.project.BuildException
import decompengine.project.GeneratedCRepairValidationBoundary
import decompengine.project.MakeProjectBuilder
import decompengine.validation.BehaviorComparator
import decompengine.validation.BehaviorComparisonReport
import decompengine.validation.ProcessInput
import decompengine.validation.SandboxOutputLimits
import decompengine.validation.SandboxRunner
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.time.Duration
import kotlin.io.path.isRegularFile

/** Trusted-fixture seam only. It intentionally does not claim production containment. */
internal object TestOnlyGeneratedCRepairValidationBoundary : GeneratedCRepairValidationBoundary {
    override val assurance: RepairValidationAssurance = RepairValidationAssurance.TEST_ONLY_HOST_PROCESS

    override fun requireAvailable() = Unit

    override fun compile(projectDir: Path, logPath: Path, budget: RepairResourceBudget): CompileFailure? = try {
        MakeProjectBuilder.build(projectDir)
        val output = readStableRepairFile(projectDir, "reports/build.log", budget.maximumIndexEvidenceBytes)
            .decodeToString()
        writeRepairEvidenceAtomically(logPath, output)
        null
    } catch (failure: BuildException) {
        val buildLog = projectDir.resolve("reports/build.log")
        val output = buildLog.takeIf {
            it.isRegularFile(LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(it)
        }?.let {
            readStableRepairFile(projectDir, "reports/build.log", budget.maximumIndexEvidenceBytes).decodeToString()
        } ?: failure.message.orEmpty()
        writeRepairEvidenceAtomically(logPath, output)
        val contract = projectDir.resolve("reports/build_contract.json")
            .takeIf { it.isRegularFile(LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(it) }
            ?.let {
                runCatching {
                    Json.parseToJsonElement(
                        readStableRepairFile(
                            projectDir,
                            "reports/build_contract.json",
                            budget.maximumIndexEvidenceBytes,
                        ).decodeToString(),
                    ).jsonObject
                }.getOrNull()
            }
        val command = contract?.get("command")?.jsonArray?.map { it.jsonPrimitive.content } ?: listOf("make")
        val exitCode = contract?.get("returnCode")?.jsonPrimitive?.intOrNull ?: 1
        CompileFailure(command, exitCode, output, "")
    }

    override fun rebuiltProgram(projectDir: Path, budget: RepairResourceBudget): Path =
        projectDir.resolve("build/reconstructed").also { program ->
            require(program.isRegularFile(LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(program)) {
                "generated C rebuilt fixture is not a regular non-symbolic-link file"
            }
        }

    override fun evaluateBehavior(
        id: String,
        projectDir: Path,
        originalBinary: Path,
        rebuiltBinary: Path,
        inputs: List<ProcessInput>,
        reportsDir: Path,
        budget: RepairResourceBudget,
    ): BehaviorComparisonReport = BehaviorComparator(
        SandboxRunner(
            timeout = Duration.ofMillis(budget.maximumBehaviorExecutionMillis),
            outputLimits = SandboxOutputLimits(
                budget.maximumBehaviorStdoutBytes,
                budget.maximumBehaviorStderrBytes,
                budget.maximumBehaviorOutputBytes,
            ),
        ),
        budget.maximumBehaviorOutputBytes,
    ).evaluate(id, originalBinary, rebuiltBinary, inputs, reportsDir)
}
