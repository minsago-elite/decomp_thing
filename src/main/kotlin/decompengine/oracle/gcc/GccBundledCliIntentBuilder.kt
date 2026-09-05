package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Path

/** Produces a candidate intent and immutable input files. The coordinator must independently admit it. */
internal object GccBundledCliIntentBuilder {
    fun build(operationId: String, engineId: String, runKind: GccCompilerEngineContainmentRunKind,
        binary: Path, profilePath: Path, archive: Path, controls: Path, journalRoot: Path, scratch: Path,
        diskPolicy: FullTreeDiskScratchPolicy, cliInvocation: GccBundledCliInvocation? = null): GccBundledOperationIntent {
        require(operationId.matches(Regex("[a-f0-9]{64}")))
        require(engineId in setOf("cc1", "lto1") && runKind in setOf(
            GccCompilerEngineContainmentRunKind.FRESH_CONTROL, GccCompilerEngineContainmentRunKind.INTERRUPTED))
        val roots = listOf(controls, journalRoot, scratch)
        (roots + listOf(binary, profilePath, archive)).forEach { path ->
            requireGccBundledOperationPath(path)
            require(path.toRealPath() == path) { "CLI input paths must be canonical" }
        }
        require(roots.indices.all { i -> roots.indices.all { j -> i == j || !overlaps(roots[i], roots[j]) } })
        listOf(binary, profilePath, archive).forEach { input -> require(roots.none { overlaps(input, it) }) }
        LinuxFilesystemSyscalls.openRoot(controls).use { directory ->
            require(directory.identity.mode.permissions == 448 && directory.identity.isDirectory)
            fun requireDirectory() {
                LinuxFilesystemSyscalls.openRoot(controls).use { current ->
                    require(current.identity == directory.identity && LinuxFilesystemSyscalls.identity(directory.fd) == directory.identity) {
                        "CLI control directory changed during preparation"
                    }
                }
            }
            require(LinuxFilesystemSyscalls.directoryEntryNames(directory, 1).isEmpty()) { "CLI control directory must be empty" }
            GccRetainedCompilerEngineProfile.open(profilePath).use { profile ->
                profile.requireDisjoint(roots)
                val suite = profile.suite
                val engine = suite.engine(engineId)
                val guards = mutableListOf<StableControlFile>()
                var primaryFailure: Throwable? = null
                try {
                    fun artifact(role: GccCompilerEngineContainmentArtifactRole, path: Path, maximum: Long): GccCompilerEngineContainmentArtifactIdentity {
                        require(path.toRealPath() == path && roots.none { overlaps(path, it) })
                        val guard = StableControlFile.open(path, maximum, "CLI ${role.wireName}")
                        guards += guard
                        return GccCompilerEngineContainmentArtifactIdentity(role, path, guard.size, guard.authenticatedSha256)
                    }
                    val selectedBinary = artifact(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY, binary, engine.strippedArtifact.bytes)
                    require(selectedBinary.bytes == engine.strippedArtifact.bytes && selectedBinary.sha256 == engine.strippedArtifact.sha256) {
                        "CLI binary differs from selected profile engine"
                    }
                    val selectedArchive = artifact(GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE, archive, suite.analysis.ghidraArchive.bytes)
                    require(selectedArchive.bytes == suite.analysis.ghidraArchive.bytes && selectedArchive.sha256 == suite.analysis.ghidraArchive.sha256) {
                        "CLI Ghidra archive differs from profile provenance"
                    }
                    GccKotlinBootClasspathReference.open().use { boot ->
                        GccBundledGhidraDeploymentReference.open().use { deployment ->
                            val bundle = deployment.bundleRoot
                            require(roots.none { overlaps(bundle, it) })
                            val reference = deployment.reference
                            val runtime = GccBundledGhidraRuntime(bundle, reference.classPath.map { relative ->
                                val entry = reference.entries.getValue(relative)
                                GccBundledGhidraClassPathEntry(bundle.resolve(relative), checkNotNull(entry.bytes), checkNotNull(entry.sha256))
                            })
                            val manifest = boot.invocationManifestBytes()
                            val exporter = checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
                                .use { it.readNBytes(MAXIMUM_CONTROL_BYTES + 1) }
                            require(exporter.size.toLong() == reference.exporterBytes && exporter.size in 1..MAXIMUM_CONTROL_BYTES &&
                                OracleArtifacts.sha256(exporter) == reference.exporterSha256 && reference.exporterSha256 == suite.analysis.exporterSha256)
                            val paths = mapOf(
                                GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to profilePath,
                                GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
                                GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to engine.buildRecordPath,
                                GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to engine.oracleManifestPath,
                                GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath,
                                GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST to bundle.resolve("bundle.sha256"),
                                GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR to bundle.resolve("decomp-ghidra-bridge.jar"),
                                GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD to bundle.resolve("scripts/RunBundledExports.class"),
                                GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE to Path.of(System.getProperty("java.home"), "bin/java").toRealPath(),
                                GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE to Path.of("/usr/bin/bwrap").toRealPath(),
                                GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE to Path.of("/usr/bin/prlimit").toRealPath(),
                                GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE to Path.of("/usr/bin/systemd-run").toRealPath(),
                                GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE to Path.of("/usr/bin/systemctl").toRealPath(),
                                GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE to Path.of("/usr/bin/busctl").toRealPath(),
                            )
                            val artifacts = arrayListOf(selectedBinary, selectedArchive)
                            paths.forEach { (role, path) -> artifacts += artifact(role, path, 128L * 1024 * 1024) }
                            fun staged(role: GccCompilerEngineContainmentArtifactRole, name: String, bytes: ByteArray) =
                                GccCompilerEngineContainmentArtifactIdentity(role, controls.resolve(name), bytes.size.toLong(), OracleArtifacts.sha256(bytes))
                            artifacts += staged(GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH, "boot-classpath.json", manifest)
                            artifacts += staged(GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE, "ExportProgramModel.java", exporter)
                            val intent = GccBundledOperationIntent(operationId, engineId, runKind, artifacts, runtime,
                                GccCompilerEngineContainmentBudgets(suite.budgets.exportWallClockMillis, suite.budgets.exportMaximumResidentBytes, 128),
                                diskPolicy, profile, cliInvocation)
                            requireDirectory()
                            require(LinuxFilesystemSyscalls.directoryEntryNames(directory, 1).isEmpty())
                            DescriptorBoundAtomicStateFile.publishManifestNoReplace(directory, "boot-classpath.json", manifest, MAXIMUM_CONTROL_BYTES)
                            DescriptorBoundAtomicStateFile.publishManifestNoReplace(directory, "ExportProgramModel.java", exporter, MAXIMUM_CONTROL_BYTES)
                            requireDirectory()
                            GccBundledOperationInputs.open(intent, listOf(journalRoot, scratch)).use { it.verify("after CLI intent preparation") }
                            guards.forEach { it.verifyUnchanged("after CLI intent preparation") }
                            profile.requireCurrent()
                            boot.verify("after CLI intent preparation")
                            deployment.verify("after CLI intent preparation")
                            requireDirectory()
                            require(LinuxFilesystemSyscalls.directoryEntryNames(directory, 3).toSet() == setOf("boot-classpath.json", "ExportProgramModel.java"))
                            return intent
                        }
                    }
                } catch (failure: Throwable) {
                    primaryFailure = failure
                    throw failure
                } finally {
                    var closeFailure: Throwable? = null
                    guards.asReversed().forEach { guard ->
                        runCatching { guard.close() }.exceptionOrNull()?.let { next ->
                            val prior = primaryFailure ?: closeFailure
                            if (prior == null) closeFailure = next else if (prior !== next) prior.addSuppressed(next)
                        }
                    }
                    closeFailure?.let { throw it }
                }
            }
        }
    }

    private fun overlaps(first: Path, second: Path) = first.startsWith(second) || second.startsWith(first)
    private const val MAXIMUM_CONTROL_BYTES = 4 * 1024 * 1024
}
