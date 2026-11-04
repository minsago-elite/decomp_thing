package decompengine.project

import decompengine.analysis.BundledGhidra
import decompengine.analysis.GhidraJvmAnalyzer
import java.nio.file.Files
import java.nio.file.Path
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
        val buildPin = Json.parseToJsonElement(InvocationQualification.read(
            repository.resolve("build/orchestration/ghidra-invocation-build-provenance.json")).toString(Charsets.UTF_8)).jsonObject
        InvocationQualification.requireProof(tests.toRealPath() == repository.resolve(
            buildPin.getValue("testHelpers").jsonObject.getValue("directory").jsonPrimitive.content).toRealPath())
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
            val helpers = pin.getValue("testHelpers").jsonObject
            val helperDirectory = repository.resolve(helpers.getValue("directory").jsonPrimitive.content).normalize()
            q.requireProof(helperDirectory.startsWith(repository) && helperDirectory.toRealPath() == helperDirectory)
            val loader = GhidraInstalledInvocationProbe::class.java.classLoader
            helpers.getValue("classes").jsonObject.forEach { (name, expected) ->
                val helper = helperDirectory.resolve(name).normalize()
                q.requireProof(helper.startsWith(helperDirectory) && q.hash(helper) == expected.jsonPrimitive.content)
                val defining = Class.forName(name.removeSuffix(".class").replace('/', '.'), false, loader)
                q.requireProof(Path.of(defining.protectionDomain.codeSource.location.toURI()).toRealPath() == helperDirectory)
                val locations = loader.getResources(name).asSequence().take(2).toList()
                q.requireProof(locations.size == 1 && locations.single().toURI() == helper.toUri())
            }
            q.requireProof(q.read(pinPath).contentEquals(pinBytes))
            val verified = q.run(listOf("python3", "src/test/python/ghidra_invocation_provenance.py", "verify"), repository, 30)
            q.requireProof(verified.toString(Charsets.UTF_8) == "invocation-build-provenance-verified\n")
        }
        phase = InvocationQualification.Phase.PROVENANCE_VERIFICATION
        verify()
        q.publish(run.resolve("build-provenance.json"), pinBytes)
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
        val sampler = InvocationQualification.ProcSampler(object : InvocationQualification.ProcSource {
            override fun children() = ProcessHandle.current().children().use { children ->
                children.limit(257).map { it.pid() }.toList()
            }
            private fun proc(pid: Long) = Path.of("/proc", pid.toString())
            override fun stat(pid: Long) = q.read(proc(pid).resolve("stat"), 8192)
            override fun alive(pid: Long) = ProcessHandle.of(pid).map { it.isAlive }.orElse(false)
            override fun cmdline(pid: Long) = Files.newInputStream(proc(pid).resolve("cmdline"),
                java.nio.file.LinkOption.NOFOLLOW_LINKS).use { it.readNBytes(q.ARTIFACT_LIMIT + 1) }
            override fun cwd(pid: Long) = proc(pid).resolve("cwd").toRealPath()
            override fun project(pid: Long): Path? = try { proc(pid).resolve("cwd/ghidra_project").toRealPath() }
                catch (_: java.nio.file.NoSuchFileException) { null }
            override fun projectKey(path: Path) = Files.readAttributes(path, "unix:dev,ino").let {
                "${it.getValue("dev")}:${it.getValue("ino")}" }
        }, ProcessHandle.current().pid(), BundledGhidra.WORKER_CLASS, input.toString(), run.fileName.toString(),
            followupSink = { q.writeFailure(run.resolve("observer-followup.json"), it) }) {
            q.writeFailure(run.resolve("observer-failure.json"), it)
        }
        phase = InvocationQualification.Phase.ANALYSIS_OBSERVER_OWNERSHIP
        val analysis = q.observe(sampler, cleanupSink = { q.writeFailure(run.resolve("observer-cleanup.json"), it) }) {
            GhidraJvmAnalyzer().analyze(input, work)
        }
        phase = InvocationQualification.Phase.RECEIPT_COMPARISON
        val worker = checkNotNull(sampler.observed) { "Invocation qualification did not observe its worker" }
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
}
