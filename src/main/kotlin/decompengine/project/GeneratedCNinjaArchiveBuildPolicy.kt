package decompengine.project

import java.nio.file.Path
import kotlin.io.path.readText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

internal object GeneratedCNinjaArchiveBuildPolicy : ArchiveBuildPolicy by GeneratedCArchiveBuildPolicy {
    override val rebuildInstructions = "Build with the exact Ninja command in `BUILDING.md`. Source, build and module evidence are retained under `reports/`."

    override fun validate(projectDir: Path, profile: ReconstructionProfile, requireArtifact: Boolean) {
        GeneratedCArchiveBuildPolicy.validate(projectDir, profile, requireArtifact)
        val text = projectDir.resolve("reports/build_contract.json").readText()
        UniqueJsonObjectKeyValidator(text).validate()
        val record = Json.parseToJsonElement(text).jsonObject
        fun number(name: String): Long {
            val value = record.getValue(name).jsonPrimitive
            require(!value.isString) { "Ninja build $name must be numeric" }
            return requireNotNull(value.longOrNull) { "Ninja build $name must be an integer" }
        }
        fun strings(name: String): List<String> = record.getValue(name).jsonArray.map {
            require(it.jsonPrimitive.isString) { "Ninja build $name must contain strings" }
            it.jsonPrimitive.content
        }
        val parallelism = number("parallelism")
        require(parallelism in 1..256) { "Ninja build parallelism is outside its supported range" }
        val expected = GeneratedCNinjaReconstructionAdapter.invocation(profile, parallelism.toInt())
        require(strings("command") == expected.command) { "Ninja build command differs from the selected profile" }
        require(strings("declaredDependencies") == expected.dependencies) { "Ninja build dependencies differ from the selected profile" }
        require(number("wallClockTimeoutMillis") in 1..profile.budgets.buildWallClockMillis) {
            "Ninja build time budget exceeds the selected profile"
        }
        require(number("maximumOutputBytes") in 1..profile.budgets.buildMaximumOutputBytes) {
            "Ninja build output budget exceeds the selected profile"
        }
    }
}
