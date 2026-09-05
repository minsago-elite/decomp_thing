package decompengine.project

import decompengine.acp.calculateAcpRuntimeManifestSha256
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.StrictJsonLimits
import decompengine.repair.RepairResourceBudget
import decompengine.repair.RepairRunStatus
import decompengine.repair.RepairRuntimeConfiguration
import decompengine.repair.SecureRepairRuntime
import decompengine.validation.ProcessInput
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.put

/**
 * Explicit hosted qualification driver. The writer emits data for operator installation;
 * execution enters only the public production factory, with no test construction capability.
 */
object GeneratedCRepairQualificationCli {
    private val runtimeRoot = Path.of("/opt/decomp-generated-c-validation-ci")
    private val jsonLimits = StrictJsonLimits(maximumInputBytes = 256 * 1024,
        maximumCanonicalBytes = 512 * 1024, maximumNodes = 4096, maximumDepth = 16,
        maximumStringBytes = 4096, maximumTotalStringBytes = 256 * 1024)

    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 2 && args[0] in setOf("write-config", "qualify", "reopen")) {
            "usage: GeneratedCRepairQualificationCli <write-config|qualify|reopen> <absolute output directory>"
        }
        val destination = Path.of(args[1])
        require(destination.isAbsolute && destination == destination.normalize())
        when (args[0]) {
            "write-config" -> writeConfiguration(destination)
            "qualify" -> qualify(destination, reopen = false)
            else -> qualify(destination, reopen = true)
        }
    }

    private fun writeConfiguration(output: Path) {
        require(!Files.exists(output)) { "qualification config output must be fresh" }
        Files.createDirectories(output)
        Files.setPosixFilePermissions(output, PosixFilePermissions.fromString("rwx------"))
        val planPath = runtimeRoot.resolve("runtime-plan.json")
        require(Files.size(planPath) <= jsonLimits.maximumInputBytes)
        val plan = OracleJson.parse(Files.readAllBytes(planPath), jsonLimits).jsonObject
        fun pin(value: JsonObject): JsonObject {
            require(value.keys == setOf("source", "destination"))
            val source = Path.of(value.getValue("source").jsonPrimitive.content)
            require(source.startsWith(runtimeRoot))
            return JsonObject(value + ("sha256" to JsonPrimitive(calculateAcpRuntimeManifestSha256(source))))
        }
        val runtime = JsonObject(plan.toMutableMap().apply {
            put("tools", JsonObject(plan.getValue("tools").jsonObject.mapValues { pin(it.value.jsonObject) }))
            listOf("buildRuntimeMounts", "programRuntimeMounts").forEach { field ->
                put(field, JsonArray(plan.getValue(field).jsonArray.map { pin(it.jsonObject) }))
            }
        })
        fun executable(name: String): Path = Path.of("/usr/bin", name).toRealPath()
        val gate = runtimeRoot.resolve("gate-helper")
        val agent = executable("true")
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        require(uid > 0) { "qualification application must run as a non-root user" }
        val sandbox = buildJsonObject {
            put("bubblewrapExecutable", executable("bwrap").toString())
            put("resourceLimiterExecutable", executable("prlimit").toString())
            put("scopeSupervisorExecutable", executable("systemd-run").toString())
            put("scopeInspectorExecutable", executable("systemctl").toString())
            put("environmentFdOpenerExecutable", executable("bash").toString())
            put("sandboxGateHelperExecutable", gate.toString())
            put("systemdUserRuntimeDirectory", "/run/user/$uid")
            put("agentWorkingDirectory", "/tmp")
            put("launcherRuntimeMounts", JsonArray(emptyList()))
            put("agentRuntimeMounts", JsonArray(emptyList()))
            put("agentResourceLimits", buildJsonObject {
                put("maximumProcesses", 32); put("maximumOpenFiles", 256)
                put("maximumFileBytes", 64L * 1024 * 1024)
                put("maximumAddressSpaceBytes", 2L * 1024 * 1024 * 1024); put("maximumCpuSeconds", 120)
            })
            put("runtimeClosureLimits", buildJsonObject {
                put("maximumEntries", 100_000); put("maximumUserOwnedFileBytes", 2L * 1024 * 1024 * 1024)
                put("maximumDepth", 64)
            })
            mapOf("Bubblewrap" to "bwrap", "ResourceLimiter" to "prlimit", "ScopeSupervisor" to "systemd-run",
                "ScopeInspector" to "systemctl", "EnvironmentFdOpener" to "bash").forEach { (field, name) ->
                put("expected${field}Sha256", sha256(Files.readAllBytes(executable(name))))
            }
            put("expectedSandboxGateHelperSha256", sha256(Files.readAllBytes(gate)))
            put("expectedSandboxGateHelperManifestSha256", calculateAcpRuntimeManifestSha256(gate))
        }
        val document = buildJsonObject {
            put("schemaVersion", 2); put("implementationId", "generated-c-public-factory-qualification")
            put("agent", buildJsonObject {
                put("executable", agent.toString()); put("arguments", JsonArray(emptyList()))
                put("environment", JsonArray(emptyList())); put("inheritParentEnvironment", false)
                put("requiredCapabilities", JsonArray(emptyList()))
                put("timeoutsMillis", buildJsonObject {
                    put("startup", 20_000); put("request", 120_000); put("cancellationGrace", 2_000)
                    put("transportDrainGrace", 100); put("shutdown", 5_000)
                })
                put("protocolLimits", buildJsonObject {
                    put("maximumFrameBytes", 1024 * 1024); put("maximumProtocolFrames", 1024)
                    put("maximumStderrBytes", 256 * 1024)
                })
                put("filesystemLimits", buildJsonObject {
                    put("maximumReadBytes", 8 * 1024 * 1024); put("maximumWriteBytes", 8 * 1024 * 1024)
                })
                put("permissionMode", "default-deny")
                put("expectedExecutableManifestSha256", calculateAcpRuntimeManifestSha256(agent))
            })
            put("session", buildJsonObject { put("configOptions", JsonArray(emptyList())) })
            put("sandbox", sandbox)
        }
        fun write(name: String, value: JsonObject) {
            val path = output.resolve(name)
            Files.write(path, OracleJson.canonicalBytes(value, jsonLimits))
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        }
        write("runtime.json", runtime)
        write("sandbox.json", document)
        write("acp.json", document)
        println("Operator data written to $output; install runtime.json and sandbox.json under $runtimeRoot before qualification")
    }

    private fun qualify(root: Path, reopen: Boolean) {
        val project = root.resolve("project")
        if (!reopen) {
            require(!Files.exists(root)) { "qualification project must be fresh" }
            Files.createDirectories(project.resolve("src"))
            Files.createDirectories(project.resolve("reports"))
            Files.write(project.resolve("src/main.c"), Files.readAllBytes(runtimeRoot.resolve("reference.c")))
            Files.writeString(project.resolve("Makefile"),
                "TARGET ?= build/reconstructed\nall: \$(TARGET)\n\$(TARGET): src/main.c\n\t\$(CC) -std=c11 -O0 -o \$@ \$<\n")
        } else {
            require(Files.isRegularFile(root.resolve("first-receipt.sha256"))) { "fresh-process reopen needs prior qualification evidence" }
        }
        val reports = project.resolve("reports")
        val inputs = listOf(ProcessInput("empty", emptyList(), byteArrayOf()),
            ProcessInput("stdin", listOf("one"), "ordinary retained input\n".toByteArray()),
            ProcessInput("nonzero", listOf("one", "two"), byteArrayOf(0, 10, 65, -1)))
        val budget = RepairResourceBudget(maximumStagingBytes = 64L * 1024 * 1024,
            maximumStagingDirectories = 4096, maximumBehaviorExecutionMillis = 10_000)
        val configuration = RepairRuntimeConfiguration("generated-c-make-v1", reports.resolve("repair_history.json"), budget, "acp")
        val outcome = SecureRepairRuntime.open(configuration).use { session ->
            session.runRepair(project, runtimeRoot.resolve("reference"), inputs, reports, 1)
        }
        require(outcome.runState.status == RepairRunStatus.FULLY_ACCEPTED) { "public factory did not fully accept benign fixture: ${outcome.runState.status}" }
        require(outcome.iterations.isEmpty() && outcome.runState.attemptedCount == 0)
        val report = requireNotNull(outcome.validation)
        require(report.matches && report.networkIsolated && report.cases.map { it.input } == inputs)
        require(report.cases.map { it.original.exitCode } == listOf(0, 0, 3))
        require(report.cases.all { it.original.stderr.contentEquals("ordinary fixture stderr\n".toByteArray()) })
        val receipt = reports.resolve("${outcome.runState.id}_initial.validation.json")
        val receiptSha256 = sha256(Files.readAllBytes(receipt))
        if (!reopen) Files.writeString(root.resolve("first-receipt.sha256"), receiptSha256)
        else require(Files.readString(root.resolve("first-receipt.sha256")) ==
            sha256(Files.readAllBytes(reports.resolve("run_00000001_initial.validation.json")))) {
            "fresh run replaced the first run's validation receipt"
        }
        Files.writeString(root.resolve(if (reopen) "reopen-result.json" else "result.json"), buildJsonObject {
            put("scope", "generated-c-public-factory-benign-baseline")
            put("releaseArchiveQualified", false); put("freshProcessReopen", reopen)
            put("runId", outcome.runState.id); put("status", outcome.runState.status.name.lowercase())
            put("caseCount", report.cases.size); put("receiptSha256", receiptSha256)
            put("originalBinarySha256", requireNotNull(outcome.runState.originalBinarySha256))
            put("expectedObservationsSha256", requireNotNull(outcome.runState.expectedObservationsSha256))
        }.toString())
        println("Public-factory ${outcome.runState.id} accepted all ${report.cases.size} benign retained cases; release archive qualification remains separate")
    }
}
