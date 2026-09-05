package decompengine.oracle.gcc

import decompengine.oracle.fulltree.FullTreeFunctionObservationClassPathEntry
import decompengine.oracle.fulltree.StableControlFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.util.Collections

internal class GccBundledOperationInputs private constructor(
    private val deploymentReference: GccKotlinBootClasspathReference,
    private val bundledRuntime: GccBundledGhidraRetainedRuntime,
    private val guards: List<Pair<String, StableControlFile>>,
    classPathEntries: List<FullTreeFunctionObservationClassPathEntry>,
    private val plannerProfile: GccRetainedCompilerEngineProfile?,
) : AutoCloseable {
    val deploymentClosureSha256: String = gccBundledLiveDeploymentClosureSha256(
        deploymentReference.closureSha256,
        bundledRuntime.deploymentClosureSha256,
        bundledRuntime.runtimeIdentitySha256,
    )
    val classPathEntries: List<FullTreeFunctionObservationClassPathEntry> =
        Collections.unmodifiableList(ArrayList(classPathEntries))
    private var closed = false

    @Synchronized
    fun verify(label: String) {
        check(!closed) { "bundled operation inputs are closed" }
        plannerProfile?.requireCurrent()
        deploymentReference.verify(label)
        bundledRuntime.verify(label)
        guards.forEach { (name, guard) -> guard.verifyUnchanged("$name $label") }
    }

    @Synchronized
    override fun close() {
        if (closed) return
        closed = true
        var failure: Throwable? = null
        fun release(resource: AutoCloseable?) {
            runCatching { resource?.close() }.exceptionOrNull()?.let { next ->
                val previous = failure
                if (previous == null) failure = next else if (previous !== next) previous.addSuppressed(next)
            }
        }
        guards.asReversed().forEach { (_, guard) -> release(guard) }
        release(plannerProfile)
        release(deploymentReference)
        release(bundledRuntime)
        failure?.let { throw it }
    }

    companion object {
        fun open(intent: GccBundledOperationIntent, excludedRoots: List<Path>): GccBundledOperationInputs {
            require(excludedRoots.size in 1..MAXIMUM_EXCLUDED_ROOTS) { "bundled operation excluded roots exceed policy" }
            val excluded = excludedRoots.toList()
            excluded.forEach { requireCanonicalOperationPath(it, "excluded root", mustExist = false) }
            require(excluded.distinct().size == excluded.size) { "bundled operation excluded roots repeat a path" }
            val artifacts = intent.artifacts.toList()
            val runtime = intent.bundledRuntime
            require(artifacts.size == GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.size &&
                artifacts.map { it.role }.toSet() == GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES &&
                artifacts.map { it.path }.toSet().size == artifacts.size
            ) { "bundled operation inputs must bind each exact artifact role and path once" }
            requireCanonicalOperationPath(runtime.root, "bundled runtime", mustExist = true)
            requireExcludedRootsDisjoint(runtime.root, excluded, "bundled runtime")
            for (artifact in artifacts) {
                requireCanonicalOperationPath(artifact.path, artifact.role.wireName, mustExist = true)
                requireExcludedRootsDisjoint(artifact.path, excluded, artifact.role.wireName)
                require(artifact.role in BUNDLE_ARTIFACT_ROLES || !pathsOverlap(artifact.path, runtime.root)) {
                    "non-bundle operation input overlaps the bundled runtime: ${artifact.role.wireName}"
                }
            }
            val manifestArtifact = artifacts.single { it.role == GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH }
            require(manifestArtifact.bytes <= MAXIMUM_CLASSPATH_MANIFEST_BYTES) { "bundled operation BOOT manifest exceeds policy" }
            val opened = mutableListOf<Pair<String, StableControlFile>>()
            var deployment: GccKotlinBootClasspathReference? = null
            var retained: GccBundledGhidraRetainedRuntime? = null
            var plannerProfile: GccRetainedCompilerEngineProfile? = null
            try {
                plannerProfile = intent.openPlannerProfile(excluded)

                for (artifact in artifacts) {
                    val label = "bundled operation artifact ${artifact.role.wireName}"
                    val guard = StableControlFile.open(artifact.path, artifact.bytes, label)
                    opened += label to guard
                    require(guard.size == artifact.bytes && guard.authenticatedSha256 == artifact.sha256) {
                        "$label differs from its exact intent identity"
                    }
                }
                val manifest = opened[artifacts.indexOf(manifestArtifact)].second
                val entries = parseBootClassPathManifest(
                    manifest.readExactly(0L, manifest.size.toInt(), "bundled operation BOOT manifest"),
                    excluded.first(),
                    artifacts.map { it.path }.toSet(),
                )
                for (entry in entries) {
                    requireCanonicalOperationPath(entry.path, "BOOT classpath", mustExist = true)
                    requireExcludedRootsDisjoint(entry.path, excluded, "BOOT classpath")
                    require(!pathsOverlap(entry.path, runtime.root)) { "bundled operation BOOT classpath overlaps Ghidra" }
                }
                val reference = GccKotlinBootClasspathReference.open()
                deployment = reference
                reference.requireCandidateIdentities(entries.map { it.bytes to it.sha256 })
                val classPath = entries.mapIndexed { index, entry ->
                    val label = "bundled operation BOOT classpath entry $index"
                    val guard = StableControlFile.open(entry.path, entry.bytes, label)
                    opened += label to guard
                    require(guard.size == entry.bytes && guard.authenticatedSha256 == entry.sha256) {
                        "$label differs from its exact deployment identity"
                    }
                    FullTreeFunctionObservationClassPathEntry(entry.path, entry.sha256)
                }
                val bundle = GccBundledGhidraRetainedRuntime.open(runtime, artifacts, excluded)
                retained = bundle
                val inputs = GccBundledOperationInputs(
                    reference, bundle, Collections.unmodifiableList(opened.toList()), classPath, plannerProfile,
                )
                inputs.verify("after prepared operation input authentication")
                return inputs
            } catch (failure: Throwable) {
                fun release(resource: AutoCloseable?) {
                    runCatching { resource?.close() }.exceptionOrNull()
                        ?.takeIf { it !== failure }?.let(failure::addSuppressed)
                }
                opened.asReversed().forEach { (_, guard) -> release(guard) }
                release(plannerProfile)
                release(deployment)
                release(retained)
                throw failure
            }
        }
    }
}

private fun requireCanonicalOperationPath(path: Path, label: String, mustExist: Boolean) {
    val text = path.toString()
    require(path.isAbsolute && path.normalize() == path && path != Path.of("/") && path.nameCount <= 32 &&
        text.length <= 4096 && text.none { it.code < 32 || it.code == 127 || it == ':' || it == '\\' }
    ) { "bundled operation $label path is not canonical" }
    if (mustExist) {
        require(path.toRealPath() == path) { "bundled operation $label path contains indirection" }
    } else {
        var existing = path
        while (!Files.exists(existing, LinkOption.NOFOLLOW_LINKS)) {
            existing = requireNotNull(existing.parent) { "bundled operation $label has no existing ancestor" }
        }
        require(existing.toRealPath() == existing) { "bundled operation $label ancestor contains indirection" }
    }
}

private fun requireExcludedRootsDisjoint(path: Path, excluded: List<Path>, label: String) {
    require(excluded.none { pathsOverlap(path, it) }) { "bundled operation $label overlaps writable authority" }
}

private fun pathsOverlap(first: Path, second: Path): Boolean = first.startsWith(second) || second.startsWith(first)

private const val MAXIMUM_EXCLUDED_ROOTS = 16
private const val MAXIMUM_CLASSPATH_MANIFEST_BYTES = 1024L * 1024L
private val BUNDLE_ARTIFACT_ROLES = setOf(
    GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR,
    GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD,
    GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST,
)
