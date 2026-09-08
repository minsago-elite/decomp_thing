package decompengine.project

import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import kotlin.io.path.isRegularFile
import kotlin.io.path.readText
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.booleanOrNull
import kotlinx.serialization.json.contentOrNull
import kotlinx.serialization.json.intOrNull
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Existing generated-C/Make source and artifact verification for archival builds. */
internal object GeneratedCArchiveBuildPolicy : ArchiveBuildPolicy {
    private val transport = ArchiveTransportLayout(setOf("build"), setOf("reports/build_contract.json"))
    override fun transportLayout(profile: ReconstructionProfile): ArchiveTransportLayout = transport
    override val rebuildInstructions = "Build with the exact parallel warnings-as-errors command in `BUILDING.md`. The recovered program model, module plan, confidence, unresolved entities, build logs, and per-module provenance are under `reports/`."
    override fun requiredPaths(profile: ReconstructionProfile): Set<String> = setOf(
        "ARCHIVE_README.md", "BUILDING.md", "reports/archival_audit.json",
        "reports/build.log", "reports/build_contract.json", "source_tree_manifest.json",
    ) + listOf(
        "build-definition", "unresolved-evidence", "confidence-evidence",
        "module-plan-evidence", "program-model-evidence", "toolchain-evidence",
    ).map { profile.layout.declaration(it).materialize() }

    override fun validate(projectDir: Path, profile: ReconstructionProfile, requireArtifact: Boolean) {
        requiredPaths(profile).filterNot { it == "ARCHIVE_README.md" || it == "reports/archival_audit.json" }
            .forEach { relative ->
                require(projectDir.resolve(relative).isRegularFile(LinkOption.NOFOLLOW_LINKS)) {
                    "archive project is missing required evidence: $relative"
                }
        }
        val contract = Json.parseToJsonElement(projectDir.resolve("reports/build_contract.json").readText()).jsonObject
        require(contract["schemaVersion"]?.jsonPrimitive?.intOrNull == GENERATED_C_BUILD_CONTRACT_SCHEMA_VERSION) {
            "archive build contract must use source-bound schema version $GENERATED_C_BUILD_CONTRACT_SCHEMA_VERSION"
        }
        contract.requireGeneratedCBuildBudgetEvidence(profile)
        require(contract["returnCode"]?.jsonPrimitive?.intOrNull == 0) { "archive build contract is not successful" }
        require(contract["sourceStableDuringBuild"]?.jsonPrimitive?.booleanOrNull == true) {
            "archive build contract does not prove stable source inputs"
        }
        require(contract["warningsAsErrors"]?.jsonPrimitive?.booleanOrNull == true) {
            "archive build contract does not enforce warnings-as-errors"
        }
        require(contract["reproduciblePathMapping"]?.jsonPrimitive?.booleanOrNull == true) {
            "archive build contract does not map workstation paths reproducibly"
        }
        require(contract["apiCredentialsRequired"]?.jsonPrimitive?.booleanOrNull == false) {
            "archive build contract requires API credentials"
        }
        require(contract["analysisCachesRequired"]?.jsonPrimitive?.booleanOrNull == false) {
            "archive build contract requires analysis caches"
        }
        val recordedInputs = contract["sourceInputs"]?.jsonArray?.map { element ->
            val item = element.jsonObject
            val relative = item["path"]?.jsonPrimitive?.content ?: error("archive build source input is missing path")
            validateRelativePath(relative)
            val bytes = item["bytes"]?.jsonPrimitive?.longOrNull
                ?: error("archive build source input is missing byte length: $relative")
            val hash = item["sha256"]?.jsonPrimitive?.content
                ?: error("archive build source input is missing SHA-256: $relative")
            require(bytes >= 0 && hash.matches(Regex("[a-f0-9]{64}"))) {
                "archive build source input is invalid: $relative"
            }
            BuildSourceInput(relative, bytes, hash)
        } ?: error("archive build contract is missing source inputs")
        require(recordedInputs == recordedInputs.sortedBy { it.path } && recordedInputs.map { it.path }.distinct().size == recordedInputs.size) {
            "archive build source inputs must be unique and sorted"
        }
        val observedRevision = sourceRevision(projectDir, profile)
        require(recordedInputs == observedRevision.inputs) { "archive build contract does not match the current source inputs" }
        val recordedRevision = contract["sourceRevisionSha256"]?.jsonPrimitive?.content
        require(recordedRevision == observedRevision.sha256) {
            "archive build contract does not match the current source revision"
        }
        val artifactElement = contract["artifact"]
        require(artifactElement != null && artifactElement !is JsonNull) {
            "successful archive build contract is missing its artifact identity"
        }
        val artifact = artifactElement.jsonObject
        val artifactPath = artifact["path"]?.jsonPrimitive?.content
            ?: error("archive build artifact is missing path")
        validateRelativePath(artifactPath)
        require(artifactPath == "build/reconstructed") { "archive build artifact path is unexpected: $artifactPath" }
        val artifactBytes = artifact["bytes"]?.jsonPrimitive?.longOrNull
            ?: error("archive build artifact is missing byte length")
        val artifactSha256 = artifact["sha256"]?.jsonPrimitive?.contentOrNull
            ?: error("archive build artifact is missing SHA-256")
        require(artifactBytes > 0 && artifactSha256.matches(Regex("[a-f0-9]{64}"))) {
            "archive build artifact identity is invalid"
        }
        if (requireArtifact) {
            val artifactFile = projectDir.resolve(artifactPath)
            require(Files.isRegularFile(artifactFile, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(artifactFile)) {
                "archive build artifact is missing or unsafe: $artifactPath"
            }
            require(Files.size(artifactFile) == artifactBytes && digestFile(artifactFile) == artifactSha256) {
                "archive build artifact does not match its build contract"
            }
        }
        contract["modules"]?.jsonArray.orEmpty().forEach { element ->
            val diagnostics = element.jsonObject["diagnostics"]?.jsonPrimitive?.content
                ?: error("archive build contract module is missing diagnostics")
            validateRelativePath(diagnostics)
            require(projectDir.resolve(diagnostics).isRegularFile(LinkOption.NOFOLLOW_LINKS)) {
                "archive build contract diagnostics are missing: $diagnostics"
            }
        }
    }

    override fun sourceRevision(projectDir: Path, profile: ReconstructionProfile): BuildSourceRevision = captureBuildSourceRevision(projectDir, profile)
    override fun isBuildInput(profile: ReconstructionProfile, relativePath: String): Boolean =
        relativePath == profile.layout.declaration("build-definition").materialize() || relativePath.startsWith("src/") || relativePath.startsWith("include/")
}
