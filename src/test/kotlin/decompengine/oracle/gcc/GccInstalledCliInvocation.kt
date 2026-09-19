package decompengine.oracle.gcc

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.validation.terminateProcessTree
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.CREATE_NEW
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.longOrNull

/** Test orchestration only; the CLI's production controller remains the authority. */
internal fun invokeInstalledGccCli(arguments: List<String>, evidence: Path, timeoutSeconds: Long,
    installation: Path = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch"),
): Int {
    require(timeoutSeconds in 1..2700)
    require(installation.isAbsolute && installation.normalize() == installation && installation.toRealPath() == installation)
    val launcher = installation.resolve("bin/llm_bin_patch").toRealPath()
    require(Files.isExecutable(launcher))
    val launcherBytes = Files.newInputStream(launcher).use { it.readNBytes(256 * 1024 + 1) }
    require(launcherBytes.size <= 256 * 1024)
    val command = listOf(launcher.toString(), "gcc-engine-plan") + arguments
    val javaHome = Path.of(System.getProperty("java.home")).toRealPath().toString()
    val request = OracleJson.canonicalBytes(JsonObject(mapOf(
        "provider" to JsonPrimitive("installed-gcc-cli-test-invocation-v1"),
        "argv" to JsonArray(command.map(::JsonPrimitive)),
        "launcherSha256" to JsonPrimitive(OracleArtifacts.sha256(launcherBytes)),
        "javaHome" to JsonPrimitive(javaHome), "javaOpts" to JsonPrimitive("-Xmx8g"),
        "outerTimeoutSeconds" to JsonPrimitive(timeoutSeconds),
        "maximumStreamBytes" to JsonPrimitive(65536), "productionVerified" to JsonPrimitive(false),
    )))
    Files.write(evidence.resolve("launcher-invocation.json"), request, CREATE_NEW)
    val builder = ProcessBuilder(command)
    builder.environment().apply {
        remove("JAVA_TOOL_OPTIONS"); remove("JDK_JAVA_OPTIONS"); remove("_JAVA_OPTIONS")
        remove("LLM_BIN_PATCH_OPTS")
        put("JAVA_HOME", javaHome); put("JAVA_OPTS", "-Xmx8g")
    }
    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(timeoutSeconds)
    val process = builder.start()
    val readers = Executors.newFixedThreadPool(2)
    val streams = listOf("stdout" to process.inputStream, "stderr" to process.errorStream).map { (name, stream) ->
        readers.submit<ByteArray> {
            val bytes = stream.use { it.readNBytes(65537) }
            Files.write(evidence.resolve("launcher-$name.bin"), bytes, CREATE_NEW)
            require(bytes.size <= 65536) { "installed CLI $name exceeds qualification capture bound" }
            bytes
        }
    }
    try {
        process.outputStream.close()
        while (process.isAlive || streams.any { !it.isDone }) {
            streams.filter { it.isDone }.forEach { it.get() }
            check(System.nanoTime() < deadline) { "installed CLI exceeded outer qualification deadline; retain scratch for recovery" }
            Thread.sleep(10)
        }
        val captured = streams.map { it.get() }
        return process.exitValue().also { exit ->
            Files.write(evidence.resolve("launcher-result.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
                "provider" to JsonPrimitive("installed-gcc-cli-test-result-v2"),
                "stdoutSha256" to JsonPrimitive(OracleArtifacts.sha256(captured[0])),
                "stdoutBytes" to JsonPrimitive(captured[0].size),
                "stderrSha256" to JsonPrimitive(OracleArtifacts.sha256(captured[1])),
                "stderrBytes" to JsonPrimitive(captured[1].size),
                "invocationSha256" to JsonPrimitive(OracleArtifacts.sha256(request)),
                "exitCode" to JsonPrimitive(exit), "productionVerified" to JsonPrimitive(false),
            ))), CREATE_NEW)
        }
    } finally {
        try {
            if (process.isAlive) terminateProcessTree(process)
        } finally {
            streams.forEach { it.cancel(true) }
            readers.shutdownNow()
            process.inputStream.close(); process.errorStream.close(); process.outputStream.close()
        }
    }
}

/** Rechecks retained test observations; checksums are not production provenance. */
internal fun verifyInstalledCliEvidence(evidence: Path, arguments: List<String>, installation: Path, expectedExit: Int): JsonObject {
    fun read(name: String, maximum: Int): ByteArray =
        decompengine.repair.readStableRegularFile(evidence, name, maximum.toLong()).bytes
    val requestBytes = read("launcher-invocation.json", 256 * 1024)
    val resultBytes = read("launcher-result.json", 16 * 1024)
    val request = OracleJson.parseCanonical(requestBytes) as JsonObject
    val result = OracleJson.parseCanonical(resultBytes) as JsonObject
    require(request.keys == setOf("provider", "argv", "launcherSha256", "javaHome", "javaOpts",
        "outerTimeoutSeconds", "maximumStreamBytes", "productionVerified"))
    require(request["provider"] == JsonPrimitive("installed-gcc-cli-test-invocation-v1") &&
        request["productionVerified"] == JsonPrimitive(false) && request["maximumStreamBytes"] == JsonPrimitive(65536))
    require(request["javaOpts"] == JsonPrimitive("-Xmx8g") &&
        request["javaHome"] == JsonPrimitive(Path.of(System.getProperty("java.home")).toRealPath().toString()))
    val timeout = request["outerTimeoutSeconds"] as? JsonPrimitive
    require(timeout != null && !timeout.isString && timeout.longOrNull in 1L..2700L)
    decompengine.oracle.fulltree.StableControlFile.open(installation.resolve("bin/llm_bin_patch"),
        256L * 1024, "retained launcher").use { launcher ->
        require(request["launcherSha256"] == JsonPrimitive(launcher.authenticatedSha256))
        launcher.verifyUnchanged("after retained launcher verification")
    }
    require(request["argv"] == JsonArray((listOf(installation.resolve("bin/llm_bin_patch").toRealPath().toString(),
        "gcc-engine-plan") + arguments).map(::JsonPrimitive))) { "launcher arguments differ from qualification selection" }
    require(result.keys == setOf("provider", "invocationSha256", "exitCode", "productionVerified",
        "stdoutSha256", "stdoutBytes", "stderrSha256", "stderrBytes"))
    require(result["provider"] == JsonPrimitive("installed-gcc-cli-test-result-v2") &&
        result["productionVerified"] == JsonPrimitive(false) && result["exitCode"] == JsonPrimitive(expectedExit))
    require(result["invocationSha256"] == JsonPrimitive(OracleArtifacts.sha256(requestBytes)))
    for (stream in listOf("stdout", "stderr")) {
        val bytes = read("launcher-$stream.bin", 65536)
        require(result["${stream}Sha256"] == JsonPrimitive(OracleArtifacts.sha256(bytes)) &&
            result["${stream}Bytes"] == JsonPrimitive(bytes.size)) { "retained launcher $stream differs from capture" }
    }
    return JsonObject(mapOf(
        "directory" to JsonPrimitive(evidence.fileName.toString()),
        "invocationSha256" to JsonPrimitive(OracleArtifacts.sha256(requestBytes)),
        "resultSha256" to JsonPrimitive(OracleArtifacts.sha256(resultBytes)),
        "productionVerified" to JsonPrimitive(false),
    ))
}
