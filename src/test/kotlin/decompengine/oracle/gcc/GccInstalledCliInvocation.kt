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

/** Test orchestration only; the CLI's production controller remains the authority. */
internal fun invokeInstalledGccCli(arguments: List<String>, evidence: Path, timeoutSeconds: Long): Int {
    require(timeoutSeconds in 1..2700)
    val launcher = Path.of(System.getProperty("user.dir"), "build/install/llm_bin_patch/bin/llm_bin_patch").toRealPath()
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
        readers.submit<Unit> {
            val bytes = stream.use { it.readNBytes(65537) }
            Files.write(evidence.resolve("launcher-$name.bin"), bytes, CREATE_NEW)
            require(bytes.size <= 65536) { "installed CLI $name exceeds qualification capture bound" }
        }
    }
    try {
        process.outputStream.close()
        while (process.isAlive || streams.any { !it.isDone }) {
            streams.filter { it.isDone }.forEach { it.get() }
            check(System.nanoTime() < deadline) { "installed CLI exceeded outer qualification deadline; retain scratch for recovery" }
            Thread.sleep(10)
        }
        streams.forEach { it.get() }
        return process.exitValue().also { exit ->
            Files.write(evidence.resolve("launcher-result.json"), OracleJson.canonicalBytes(JsonObject(mapOf(
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
