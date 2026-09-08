package decompengine.project

import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Generated-C build records and input layout used by local behavior evidence capture. */
internal object GeneratedCBehaviorBuildPolicy : BehaviorBuildPolicy {
    override fun layout(profile: ReconstructionProfile): BehaviorBuildLayout = BehaviorBuildLayout(
        contractPath = "reports/build_contract.json",
        artifactPath = "build/reconstructed",
        standaloneInputs = listOf(profile.layout.declaration("build-definition").materialize()),
        sourceRoots = listOf("src", "include"),
    )

    override fun parseContract(contract: JsonObject, profile: ReconstructionProfile): BehaviorBuildContract {
        require(contract.keys == setOf("schemaVersion", "command", "parallelism", "wallClockTimeoutMillis",
            "maximumOutputBytes", "warningsAsErrors", "reproduciblePathMapping", "declaredDependencies",
            "apiCredentialsRequired", "analysisCachesRequired", "returnCode", "sourceStableDuringBuild",
            "sourceRevisionSha256", "sourceInputs", "artifact", "failedOwners", "modules")) {
            "behavior build contract has missing or unknown fields"
        }
        require(contract.integer("schemaVersion") == 2 && contract.integer("returnCode") == 0 &&
            contract.boolean("sourceStableDuringBuild") && contract.boolean("warningsAsErrors") &&
            contract.boolean("reproduciblePathMapping") && !contract.boolean("apiCredentialsRequired") &&
            !contract.boolean("analysisCachesRequired") && contract.getValue("failedOwners").jsonArray.isEmpty()
        ) { "behavior requires a successful source-stable build contract" }
        require(contract.integer("parallelism") in 1..256 && contract.count("wallClockTimeoutMillis") > 0 &&
            contract.count("maximumOutputBytes") > 0)
        listOf("command", "declaredDependencies").forEach { name ->
            require(contract.getValue(name).jsonArray.isNotEmpty())
            contract.getValue(name).jsonArray.forEach { require(it.jsonPrimitive.isString) }
        }
        contract.getValue("modules").jsonArray.forEach { element ->
            val module = element.jsonObject
            require(module.keys == setOf("id", "source", "diagnostics"))
            module.keys.forEach { module.string(it) }
        }
        val artifact = contract.getValue("artifact").jsonObject
        require(artifact.keys == setOf("path", "bytes", "sha256")) { "behavior build artifact fields are invalid" }
        artifact.string("path")
        return BehaviorBuildContract(
            sourceRevisionSha256 = contract.string("sourceRevisionSha256"),
            sourceInputs = contract.getValue("sourceInputs").jsonArray,
            artifact = artifact,
        )
    }

    private fun JsonObject.string(name: String): String = getValue(name).jsonPrimitive.let {
        require(it.isString) { "$name must be a string" }
        it.content
    }

    private fun JsonObject.boolean(name: String): Boolean = getValue(name).jsonPrimitive.let {
        require(!it.isString) { "$name must be a boolean" }
        requireNotNull(it.booleanOrNull) { "$name must be a boolean" }
    }

    private fun JsonObject.integer(name: String): Int = getValue(name).jsonPrimitive.let {
        require(!it.isString) { "$name must be an integer" }
        requireNotNull(it.intOrNull) { "$name must be an integer" }
    }

    private fun JsonObject.count(name: String): Long = getValue(name).jsonPrimitive.let {
        require(!it.isString) { "$name must be an integer" }
        requireNotNull(it.longOrNull) { "$name must be an integer" }
    }
}
