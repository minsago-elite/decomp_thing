package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.assertEquals

internal data class FullTreeCallTruthTestFixture(
    val raw: FullTreeCrossShardCallFixture,
    val functions: FunctionTruthFixture,
    val functionTruth: FullTreeFunctionTruthGeneration,
    val callRun: FullTreeCallObservationRunPublication,
)

internal fun createFullTreeCallTruthTestFixture(root: Path): FullTreeCallTruthTestFixture {
    val raw = createFullTreeCrossShardCallFixture(root)
    val scratch = callTruthPrivateDirectory(root.resolve("scratch"))
    val elfIndex = root.resolve("elf-functions.json")
    FullTreeElfFunctionsSqlite.generateAndPublish(
        raw.artifact, raw.strippedArtifact, raw.scope, raw.inventory, elfIndex, maximumWorkers = 3,
    )
    val preparedRoot = callTruthPrivateDirectory(root.resolve("prepared-functions"))
    val inputs = FullTreeFunctionObservations.shardInputs(
        raw.inventory,
        OracleArtifacts.sha256(Files.readAllBytes(raw.inventoryPath)),
        raw.scope.document,
        raw.scope.sha256,
    )
    val prepared = inputs.map { input ->
        val output = preparedRoot.resolve("${input.identifier}.json")
        val receipt = FullTreeFunctionObservationShardPublisher.generateAndPublish(
            raw.artifact, raw.inventoryPath, raw.scope, input.identifier, scratch, output,
        )
        BoundedShardPreparedOutput(
            input.identifier, input.inputSha256, output, receipt.outputSha256, receipt.outputBytes, receipt.entities,
        )
    }
    val functionRun = BoundedShardRunPublisher.publish(
        target = root.resolve("function-observations"),
        runId = "full-tree-functions-${raw.scope.sha256.take(16)}",
        preparedOutputs = prepared,
        bounds = callTruthTestRunBounds(raw),
        semanticValidator = BoundedShardOutputSemanticValidator { output ->
            val derived = FullTreeFunctionObservationShardPublisher.loadAndValidate(
                output.output, raw.artifact, raw.inventoryPath, raw.scope, output.shardId, scratch,
            )
            assertEquals(output.inputSha256, derived.inputSha256)
            assertEquals(output.outputSha256, derived.outputSha256)
            assertEquals(output.outputBytes, derived.outputBytes)
            assertEquals(output.entities, derived.entities)
        },
    )
    val functions = FunctionTruthFixture(
        raw.artifact, raw.strippedArtifact, raw.inventoryPath, raw.inventory, raw.scope, elfIndex,
        functionRun.root, functionRun.indexArtifactSha256, scratch,
    )
    val truth = generateTruth(functions, root.resolve("function-truth"), maximumWorkers = 3)
    val calls = FullTreeCallObservationRunPublisher.generateAndPublish(
        raw.artifact, raw.inventoryPath, raw.scope, scratch, root.resolve("call-observations"), maximumWorkers = 3,
    )
    return FullTreeCallTruthTestFixture(raw, functions, truth, calls)
}

internal fun callTruthTestRunBounds(raw: FullTreeCrossShardCallFixture): BoundedShardRunPublicationBounds {
    val perShard = raw.scope.document.controlObject("bounds").controlObject("perShard")
    val wholeRun = raw.scope.document.controlObject("bounds").controlObject("wholeRun")
    return BoundedShardRunPublicationBounds(
        maximumShards = raw.shardIds.size,
        perShardEntities = perShard.controlLong("entities"),
        wholeRunEntities = wholeRun.controlLong("entities"),
        perShardBytes = perShard.controlLong("serializedBytes"),
        wholeRunBytes = wholeRun.controlLong("serializedBytes"),
        perShardSeconds = perShard.controlLong("wallClockSeconds").toDouble(),
        wholeRunSeconds = wholeRun.controlLong("wallClockSeconds").toDouble(),
        perShardCpuSeconds = perShard.controlLong("cpuSeconds").toDouble(),
        wholeRunCpuSeconds = wholeRun.controlLong("cpuSeconds").toDouble(),
        maximumResidentBytes = wholeRun.controlLong("maximumResidentBytes"),
        maximumWorkers = 3,
    )
}

internal fun callTruthPrivateDirectory(path: Path): Path = Files.createDirectories(path).also {
    Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
}
