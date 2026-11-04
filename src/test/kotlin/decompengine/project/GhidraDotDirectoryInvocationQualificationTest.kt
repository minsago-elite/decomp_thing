package decompengine.project

import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraJvmAnalyzer
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import java.util.jar.JarFile
import kotlin.io.path.createDirectories
import kotlin.test.Test
import kotlinx.serialization.json.*
import org.junit.jupiter.api.Assumptions.assumeTrue

class GhidraDotDirectoryInvocationQualificationTest {
    @Test
    fun `installed bundled worker records default dot directory invocation`() {
        assumeTrue(System.getenv("RUN_REAL_GHIDRA") == "true", "installed bundled worker qualification is hosted-only")
        InvocationQualification.requireProof(System.getProperty("os.name") == "Linux")
        val repository = Path.of("").toAbsolutePath().normalize()
        val installed = repository.resolve("build/install/llm_bin_patch")
        val evidence = repository.resolve("build/orchestration/ghidra-invocation-qualification")
        var failureDirectory = evidence
        var processDiagnosticEmitted = false
        try {
        evidence.createDirectories()
        val run = Files.createTempDirectory(evidence, "run-")
        failureDirectory = run
        val jars = Files.list(installed.resolve("lib")).use { paths ->
            paths.filter { it.toString().endsWith(".jar") }.sorted().limit(257).toList()
        }
        InvocationQualification.requireProof(jars.size in 1..256)
        // Test helpers are LAST. Application classes and resources must define themselves from the installed JAR.
        val tests = Path.of(GhidraInstalledInvocationProbe::class.java.protectionDomain.codeSource.location.toURI())
        val result = InvocationQualification.run(listOf(
            Path.of(System.getProperty("java.home"), "bin/java").toString(),
            "-XX:-UsePerfData", "-XX:-CreateCoredumpOnCrash", "-XX:-DumpReplayDataOnError",
            "-Duser.home=${run.resolve("home").createDirectories()}", "-Djava.io.tmpdir=${run.resolve("tmp").createDirectories()}",
            "-Ddecompengine.oracle.nativeLibraryDirectory=${installed.resolve("libexec/oracle-native")}",
            "-cp", InvocationQualification.installedProbeClasspath(jars, tests),
            GhidraInstalledInvocationProbe::class.java.name, repository.toString(), run.toString(),
        ), repository, 12 * 60, diagnosticSink = { diagnostic ->
            processDiagnosticEmitted = true
            InvocationQualification.writeFailure(run.resolve("parent-process-failure.json"), diagnostic.json())
        })
        processDiagnosticEmitted = true
        InvocationQualification.requireProof(result.toString(Charsets.UTF_8) == "installed-invocation-qualified\n")
        // Publish only a completed same-run set. The run manifest binds exact report/observation bytes.
        val provenance = Json.parseToJsonElement(InvocationQualification.read(run.resolve("provenance.json")).toString(Charsets.UTF_8)).jsonObject
        listOf("retained-invocation.json", "observed-worker.json", "compiler.json").forEach { name ->
            InvocationQualification.requireProof(InvocationQualification.hash(run.resolve(name)) ==
                provenance.getValue("evidence").jsonObject.getValue(name).jsonPrimitive.content)
            InvocationQualification.publish(evidence.resolve(name), InvocationQualification.read(run.resolve(name)))
        }
        InvocationQualification.publish(evidence.resolve("provenance.json"), provenance)
        } catch (problem: Throwable) {
            if (!processDiagnosticEmitted) InvocationQualification.setupFailure(problem, InvocationQualification.Phase.SETUP) {
                InvocationQualification.writeFailure(failureDirectory.resolve("parent-setup-failure.json"), it.json())
            }
            if (problem is InterruptedException) Thread.currentThread().interrupt()
            throw problem
        }
    }
}

/** Executed ONLY in a child whose application classpath consists of installed JARs. */
object GhidraInstalledInvocationProbe {
    @JvmStatic fun main(args: Array<String>) {
        val q = InvocationQualification
        var phase = InvocationQualification.Phase.PROVENANCE_VERIFICATION
        var failureDirectory: Path? = null
        try {
        val repository = Path.of(args[0]).toRealPath()
        val run = Path.of(args[1]).toRealPath()
        failureDirectory = run
        q.requireProof(run.startsWith(repository.resolve("build/orchestration/ghidra-invocation-qualification")))
        val pinPath = repository.resolve("build/orchestration/ghidra-invocation-build-provenance.json")
        val pinBytes = q.read(pinPath)
        val pin = Json.parseToJsonElement(pinBytes.toString(Charsets.UTF_8)).jsonObject
        val installed = repository.resolve("build/install/llm_bin_patch").toRealPath()
        val application = Path.of(GhidraJvmAnalyzer::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
        q.requireProof(application.parent == installed.resolve("lib") && application.toString().endsWith(".jar"))
        val defined = listOf("decompengine.analysis.GhidraJvmAnalyzer", "decompengine.analysis.GhidraAnalysis",
            "decompengine.analysis.BundledGhidra", "decompengine.analysis.PreparedGhidraCommand",
            "decompengine.analysis.GhidraInvocationReceipt", "decompengine.project.GhidraHeadlessProgramModelAnalyzer")
            .associateWith { name ->
                val location = Path.of(Class.forName(name).protectionDomain.codeSource.location.toURI()).toRealPath()
                q.requireProof(location == application)
                repository.relativize(location).toString()
            }
        val artifacts = pin.getValue("artifacts").jsonObject
        q.requireProof(repository.relativize(application).toString() in artifacts)
        fun verify() {
            fun verifyMap(map: JsonObject, limit: Long) = q.verifyPins(map, map.keys.associateWith { name ->
                val file = repository.resolve(name).normalize()
                q.requireProof(file.startsWith(repository) && !Path.of(name).isAbsolute)
                q.hash(file, limit)
            })
            verifyMap(pin.getValue("sources").jsonObject, 16L * 1024 * 1024)
            verifyMap(artifacts, 512L * 1024 * 1024)
            q.requireProof(q.read(pinPath).contentEquals(pinBytes))
            val verified = q.run(listOf("python3", "src/test/python/ghidra_invocation_provenance.py", "verify"), repository, 30)
            q.requireProof(verified.toString(Charsets.UTF_8) == "invocation-build-provenance-verified\n")
        }
        phase = InvocationQualification.Phase.PROVENANCE_VERIFICATION
        verify()
        phase = InvocationQualification.Phase.BUNDLE_SOURCE_CHECKS
        val bundle = BundledGhidra.locate().root.toRealPath()
        q.requireProof(bundle == installed.resolve("libexec/ghidra"))
        val bridge = bundle.resolve("decomp-ghidra-bridge.jar")
        val bundleManifest = bundle.resolve("bundle.sha256")
        q.requireProof(listOf(bridge, bundleManifest).all { repository.relativize(it).toString() in artifacts })
        val resourceName = "ghidra_scripts/ExportProgramModelOwned.java"
        val source = repository.resolve("src/main/resources/$resourceName")
        val sourceBytes = q.read(source)
        val active = q.bytes(GhidraHeadlessProgramModelAnalyzer::class.java.getResourceAsStream("/$resourceName")!!)
        val packaged = JarFile(application.toFile()).use { jar -> q.bytes(jar.getInputStream(jar.getJarEntry(resourceName))) }
        q.verifyExporterBytes(sourceBytes, active, packaged)
        val work = run.resolve(".decomp_engine/jobs/authored/reports/analysis").createDirectories()
        val project = work.resolve("ghidra_project")
        q.requireProof(!Files.exists(project))
        val authored = run.resolve("authored-input.c")
        q.publish(authored, "int main(void) { return 0; }\n".toByteArray())
        val input = run.resolve("authored-input.elf")
        phase = InvocationQualification.Phase.INPUT_COMPILE
        val compilerOutput = q.run(listOf("gcc", "-g", "-O0", "-fno-pie", "-no-pie", "-Wl,--build-id=none",
            authored.toString(), "-o", input.toString()), repository, 30)
        // Retain only bounded counts/digests, never arbitrary compiler output or the JVM vector.
        q.publish(run.resolve("compiler.json"), buildJsonObject {
            put("exitCode", 0); put("bytes", compilerOutput.size); put("sha256", q.digest(compilerOutput))
        })
        val observed = AtomicReference<ObservedWorker?>()
        val failure = AtomicReference<Throwable?>()
        val stop = AtomicBoolean(false)
        val inventory = InvocationQualification.Inventory()
        val observer = Thread({
            try {
                while (!stop.get()) {
                    val children = ProcessHandle.current().children().use { it.limit(257).toList() }
                    q.requireProof(children.size <= q.CHILD_LIMIT)
                    val candidates = children.mapNotNull { child ->
                        try {
                            val proc = Path.of("/proc", child.pid().toString())
                            val stat = q.read(proc.resolve("stat"), 8192).toString(Charsets.UTF_8)
                            val fields = stat.substring(stat.lastIndexOf(')') + 2).trim().split(' ')
                            q.requireProof(fields[1].toLong() == ProcessHandle.current().pid())
                            InvocationQualification.Identity(child.pid(), fields[19]) to child
                        } catch (problem: Exception) { throw problem }
                    }
                    inventory.poll(candidates.map { it.first }) { identity ->
                        try {
                            val proc = Path.of("/proc", identity.pid.toString())
                            val bytes = q.read(proc.resolve("cmdline"))
                            val command = q.command(bytes)
                            val indexes = command.indices.filter { command[it] == BundledGhidra.WORKER_CLASS }
                            if (indexes.isEmpty() || input.toString() !in command) false else {
                                q.requireProof(indexes.size == 1)
                                val index = indexes.single()
                                val workerArgs = command.drop(index + 1)
                                // Project may not yet exist at launch. Still count this identity immediately.
                                if (Files.exists(proc.resolve("cwd/ghidra_project"))) {
                                    val target = q.observedProject(workerArgs, identity.pid)
                                    val cwd = proc.resolve("cwd").toRealPath()
                                    val key = Files.readAttributes(target, "unix:dev,ino")
                                    observed.compareAndSet(null, ObservedWorker(identity, command, cwd, target, "${key.getValue("dev")}:${key.getValue("ino")}"))
                                }
                                true
                            }
                        } catch (problem: Exception) { throw problem }
                    }
                    Thread.sleep(10)
                }
            } catch (problem: InterruptedException) { if (!stop.get()) failure.set(problem) }
            catch (problem: Throwable) { failure.set(problem) }
        }, "ghidra-invocation-observer").apply { isDaemon = true }
        phase = InvocationQualification.Phase.ANALYSIS_OBSERVER_OWNERSHIP
        val analysis = q.owned(cleanup = { q.settle(observer, { stop.set(true) }) }) {
            observer.start()
            GhidraJvmAnalyzer().analyze(input, work)
        }
        failure.get()?.let { throw it }
        inventory.finish()
        phase = InvocationQualification.Phase.RECEIPT_COMPARISON
        val worker = checkNotNull(observed.get()) { "Invocation qualification did not observe its worker" }
        val reportBytes = q.read(analysis.reportPath)
        val report = Json.parseToJsonElement(reportBytes.toString(Charsets.UTF_8)).jsonObject
        val invocation = report.getValue("invocation").jsonObject
        val workerIndex = worker.command.indexOf(BundledGhidra.WORKER_CLASS)
        val workerArgs = worker.command.drop(workerIndex + 1)
        q.requireProof(workerArgs == invocation.getValue("workerArguments").jsonArray.map { it.jsonPrimitive.content })
        q.requireProof(worker.command.first() == invocation.getValue("executable").jsonPrimitive.content)
        q.requireProof(invocation.getValue("mainClass").jsonPrimitive.content == BundledGhidra.WORKER_CLASS)
        q.requireProof(invocation.getValue("workingDirectory").jsonPrimitive.content == work.toString() && worker.cwd == work.toRealPath())
        q.requireProof(workerArgs[0] == bundle.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC").toString())
        val cpIndex = worker.command.indexOf("-cp")
        q.requireProof(cpIndex > 0 && worker.command[cpIndex + 1].split(java.io.File.pathSeparator).first() == bridge.toString())
        q.requireProof(workerArgs[4] == "archival_reconstruction" && workerArgs[5] == input.toString())
        val staged = Path.of(workerArgs[6]).resolve("ExportProgramModelOwned.java")
        q.verifyExporterBytes(sourceBytes, active, packaged, q.read(staged))
        q.requireProof(workerArgs[7] == "ExportProgramModelOwned.java" && workerArgs[9] == q.digest(active))
        q.requireProof(project.toRealPath() == worker.project && Files.readAttributes(project, "unix:dev,ino").let { "${it.getValue("dev")}:${it.getValue("ino")}" } == worker.projectKey)
        val diagnostic = listOf("ghidra_stdout.log", "ghidra_stderr.log").joinToString("\n") {
            q.read(work.resolve("reports/$it"), 16 * 1024 * 1024).toString(Charsets.UTF_8)
        }
        phase = InvocationQualification.Phase.RESULT_VALIDATION
        q.validateResult(report, analysis.programModel.functions.map { it.name },
            Files.isRegularFile(project.resolve("archival_reconstruction.gpr")), diagnostic)
        phase = InvocationQualification.Phase.FINAL_PROVENANCE_VERIFICATION
        verify()
        phase = InvocationQualification.Phase.PUBLICATION
        q.publish(run.resolve("retained-invocation.json"), reportBytes)
        q.publish(run.resolve("observed-worker.json"), buildJsonObject {
            put("runId", run.fileName.toString()); put("pid", worker.identity.pid); put("startTicks", worker.identity.start)
            put("cwd", worker.cwd.toString()); put("projectArgument", workerArgs[3])
            put("projectAliasTarget", worker.project.toString()); put("projectIdentity", worker.projectKey)
            put("inputSha256", q.hash(input)); put("invocation", invocation)
        })
        q.publish(run.resolve("provenance.json"), buildJsonObject {
            put("schemaVersion", 1); put("runId", run.fileName.toString()); put("probePid", ProcessHandle.current().pid())
            put("buildManifestSha256", q.digest(pinBytes)); put("build", pin)
            put("definingCodeSources", buildJsonObject { defined.forEach { (name, path) -> put(name, path) } })
            put("activeExporterSha256", q.digest(active)); put("stagedExporterSha256", q.hash(staged))
            put("evidence", buildJsonObject {
                listOf("retained-invocation.json", "observed-worker.json", "compiler.json").forEach { put(it, q.hash(run.resolve(it))) }
            })
        })
        println("installed-invocation-qualified")
        } catch (problem: Throwable) {
            failureDirectory?.let { q.publishFailure(it.resolve("child-failure.json"), q.childFailure(phase, problem), problem) }
            throw problem
        }
    }
    private data class ObservedWorker(val identity: InvocationQualification.Identity, val command: List<String>,
        val cwd: Path, val project: Path, val projectKey: String)
}
