package decompengine.project

import decompengine.analysis.BundledGhidra
import java.nio.file.Files
import java.nio.file.Path
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put

/** Invoked by qualify-ghidra-install-overlap.py, with installed JARs ahead of test classes.
 * Uses the ordinary isolated worker and authenticated bundle verification, without a fake
 * analyzer, altered exporter, external headless installation, or synchronization in analysis.
 */
object InstalledGhidraOverlapProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 3) { "expected installed root, fixture, fresh output root" }
        val installed = Path.of(args[0]).toRealPath()
        val binary = Path.of(args[1]).toRealPath()
        val output = Path.of(args[2]).toAbsolutePath().normalize()
        require(!Files.exists(output))
        require(System.getProperty("decompengine.ghidra.bundle") == null)
        val application = Path.of(ArchivalReconstructionService::class.java.protectionDomain.codeSource.location.toURI()).toRealPath()
        require(application.startsWith(installed.resolve("lib")) && Files.isRegularFile(application))
        for (type in listOf(GhidraHeadlessProgramModelAnalyzer::class.java, BundledGhidra::class.java,
            SourceTreeGenerator::class.java, ArchivalPackager::class.java)) {
            require(Path.of(type.protectionDomain.codeSource.location.toURI()).toRealPath() == application)
        }
        require(BundledGhidra.locate().root.toRealPath() == installed.resolve("libexec/ghidra").toRealPath())
        val result = ArchivalReconstructionService(GhidraHeadlessProgramModelAnalyzer()).reconstruct(binary, output)
        check(result.build.returnCode == 0) { "real reconstructed project did not build" }
        check(Files.isExecutable(result.projectDir.resolve("build/reconstructed")))
        check(Files.size(output.resolve("source-tree.zip")) > 0)
        val model = ProgramModelJson.read(Files.readString(output.resolve("analysis/reports/program_model.json")))
        check(model.functions.isNotEmpty())
        Files.writeString(output.resolve("installed-probe.json"), buildJsonObject {
            put("applicationJar", application.toString())
            put("bundle", BundledGhidra.locate().root.toString())
            put("pid", ProcessHandle.current().pid())
            put("completedMonotonicNs", System.nanoTime())
            put("functions", model.functions.size)
            put("buildExitCode", result.build.returnCode)
            put("archiveSha256", result.bundle.archiveSha256)
            // Default evidence stubs make no semantic-equivalence or implementation-completeness claim.
            put("scope", "real Ghidra analysis and archival default evidence-stub reconstruction/build")
        }.toString() + "\n")
    }
}
