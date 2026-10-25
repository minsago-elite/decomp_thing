package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeFunctionObservationIsolationConfiguration
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.calculateFullTreeObservationRuntimeManifestSha256
import decompengine.oracle.reference.ReferenceCorpusDeployment
import decompengine.oracle.reference.ReferenceNativeRuntime
import decompengine.oracle.reference.ReferenceNativeRuntimeProvisioningEntry
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.attribute.BasicFileAttributes
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Provisioning chooses no program or image: the fixed profile and installed controller supply both. */
internal object GccMetadataReferenceProvisioning {
    fun provision(profileRoot: Path, ociLayout: Path, freshRuntimeRoot: Path, jdkRoot: Path, deploymentPath: Path) {
        require((Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toLong() == 0L)
        listOf(profileRoot, ociLayout).forEach { require(it.toRealPath() == it && Files.isDirectory(it, NOFOLLOW_LINKS)) }
        listOf(freshRuntimeRoot.parent, jdkRoot, deploymentPath.parent).forEach(::requireTrustedMetadataPath)
        require(!Files.exists(freshRuntimeRoot, NOFOLLOW_LINKS) && !Files.exists(deploymentPath, NOFOLLOW_LINKS)) {
            "reference provisioning requires fresh runtime and deployment destinations"
        }
        require(!deploymentPath.startsWith(freshRuntimeRoot) && !freshRuntimeRoot.startsWith(deploymentPath))
        GccMetadataReferenceInstalledController.open().use { controller ->
            GccMetadataReferenceProfile.open(profileRoot).use { profile ->
                val stage = ReferenceNativeRuntime.materialize(ociLayout, freshRuntimeRoot, profile)
                val (rootEntry, descendants) = partitionProvisioningEntries(stage.provisioningEntries)
                // The ownership plan never crosses a serialized caller-controlled receipt. Keep the
                // fresh root private until every typed, authenticated image node is provisioned.
                Files.setAttribute(stage.root, "unix:mode", 0x1c0, NOFOLLOW_LINKS)
                descendants.forEach { entry ->
                    val path = stage.root.resolve(entry.relativePath)
                    require(path.normalize() == path && path.startsWith(stage.root) && path != stage.root)
                    Files.setAttribute(path, "unix:uid", Math.toIntExact(entry.uid), NOFOLLOW_LINKS)
                    Files.setAttribute(path, "unix:gid", Math.toIntExact(entry.gid), NOFOLLOW_LINKS)
                    if (entry.kind != "symlink") Files.setAttribute(path, "unix:mode", entry.mode, NOFOLLOW_LINKS)
                }
                Files.setAttribute(stage.root, "unix:uid", Math.toIntExact(rootEntry.uid), NOFOLLOW_LINKS)
                Files.setAttribute(stage.root, "unix:gid", Math.toIntExact(rootEntry.gid), NOFOLLOW_LINKS)
                Files.setAttribute(stage.root, "unix:mode", rootEntry.mode, NOFOLLOW_LINKS)
                ReferenceNativeRuntime.admit(ociLayout, stage.root, profile).use { admitted ->
                    val guards = ArrayList<StableControlFile>()
                    try {
                        fun executable(path: Path): String {
                            requireTrustedMetadataPath(path)
                            require(Files.isExecutable(path) && Files.isRegularFile(path, NOFOLLOW_LINKS))
                            val guard = StableControlFile.open(path, 256 * 1024 * 1024L, "reference provisioned executable")
                            guards += guard
                            guard.requireSingleLink("reference provisioned executable")
                            return guard.authenticatedSha256
                        }
                        val java = jdkRoot.resolve("bin/java")
                        val tools = mapOf("bubblewrap" to Path.of("/usr/bin/bwrap"), "resourceLimiter" to Path.of("/usr/bin/prlimit"),
                            "scopeSupervisor" to Path.of("/usr/bin/systemd-run"), "scopeInspector" to Path.of("/usr/bin/systemctl"),
                            "systemdBusController" to Path.of("/usr/bin/busctl"))
                        val javaSha = executable(java)
                        val pins = tools.mapValues { executable(it.value) }
                        val javaManifest = calculateFullTreeObservationRuntimeManifestSha256(jdkRoot)
                        val libraryRoot = stage.root.resolve("image/usr")
                        val libraryManifest = calculateFullTreeObservationRuntimeManifestSha256(libraryRoot)
                        fun mount(source: Path, destination: Path, digest: String) = JsonObject(mapOf(
                            "source" to JsonPrimitive(source.toString()), "destination" to JsonPrimitive(destination.toString()),
                            "expectedManifestSha256" to JsonPrimitive(digest)))
                        val configuration = JsonObject(mapOf(
                            "javaExecutable" to JsonPrimitive(java.toString()), "expectedJavaSha256" to JsonPrimitive(javaSha),
                            "javaRuntime" to mount(jdkRoot, jdkRoot, javaManifest),
                            "systemLibraryMounts" to JsonArray(listOf(mount(libraryRoot, Path.of("/usr"), libraryManifest))),
                            "systemdUserRuntimeDirectory" to JsonPrimitive("/run/user/0"),
                            "workerClassPath" to JsonArray(controller.manifest.getValue("entries").jsonArray.map { value ->
                                val entry = value.jsonObject
                                JsonObject(mapOf("path" to entry.getValue("path"), "expectedSha256" to entry.getValue("sha256")))
                            }),
                        ) + tools.map { (role, path) -> "${role}Executable" to JsonPrimitive(path.toString()) }.toMap() +
                            pins.map { (role, pin) -> "expected${role.replaceFirstChar(Char::uppercaseChar)}Sha256" to JsonPrimitive(pin) }.toMap())
                        val bytes = OracleJson.canonicalBytes(JsonObject(mapOf(
                            "schemaVersion" to JsonPrimitive("reference-corpus-deployment-v1"), "configuration" to configuration,
                            "expectedCgroupParent" to JsonPrimitive("/user.slice/user-0.slice/user@0.service/app.slice"))))
                        ReferenceCorpusDeployment.parseCanonical(bytes)
                        controller.requireCurrent("deployment provisioning")
                        admitted.requireCurrent("deployment provisioning")
                        require(calculateFullTreeObservationRuntimeManifestSha256(jdkRoot) == javaManifest)
                        guards.forEach { it.verifyUnchanged("deployment provisioning") }
                        LinuxFilesystemSyscalls.openRoot(deploymentPath.parent).use { parent ->
                            DescriptorBoundAtomicStateFile.publishNoReplace(parent, deploymentPath.fileName.toString(), bytes, 256 * 1024)
                            require(Files.isSameFile(deploymentPath.parent, LinuxFilesystemSyscalls.descriptorPath(parent)))
                        }
                        ReferenceCorpusDeployment.open(deploymentPath)
                    } finally { guards.asReversed().forEach(StableControlFile::close) }
                }
            }
        }
        println("Provisioned fixed metadata reference runtime and deployment: $deploymentPath")
    }

    /** Shape validation only; this does not authenticate a caller-created provisioning plan. */
    internal fun partitionProvisioningEntries(entries: List<ReferenceNativeRuntimeProvisioningEntry>):
        Pair<ReferenceNativeRuntimeProvisioningEntry, List<ReferenceNativeRuntimeProvisioningEntry>> {
        require(entries.size in 2..200_001 && entries.map { it.relativePath }.distinct().size == entries.size)
        val root = entries.single { it.relativePath == "." }
        require(root.kind == "directory" && root.uid == 0L && root.gid == 0L && root.mode == 0x1ed)
        val descendants = entries.filter { it.relativePath != "." }
        val byName = descendants.associateBy { it.relativePath }
        descendants.forEach { entry ->
            val path = Path.of(entry.relativePath)
            require(entry.relativePath.isNotEmpty() && !path.isAbsolute && path.normalize() == path && path.toString() == entry.relativePath &&
                path.none { it.toString() in setOf(".", "..") } && entry.kind in setOf("directory", "regular", "symlink") &&
                entry.uid in 0..Int.MAX_VALUE.toLong() && entry.gid in 0..Int.MAX_VALUE.toLong() && entry.mode in 0..0xfff)
            var parent = path.parent
            while (parent != null) {
                require(byName[parent.toString()]?.kind == "directory") { "provisioning plan has a missing or indirect ancestor" }
                parent = parent.parent
            }
        }
        return root to java.util.Collections.unmodifiableList(descendants)
    }
}

/** Existing installed BOOT closure, retained for the controller as well as its contained workers. */
internal class GccMetadataReferenceInstalledController private constructor(
    private val authority: GccKotlinBootClasspathReference,
    private val codeSource: Path,
    private val sidecarPath: Path,
    private val sidecarGuard: StableControlFile,
    private val storedManifest: ByteArray,
) : AutoCloseable {
    val manifest: JsonObject get() = OracleJson.parseCanonical(storedManifest).jsonObject
    fun requireCurrent(label: String) {
        requireNoMetadataClasspathOverrides()
        requireTrustedMetadataPath(sidecarPath)
        requireMetadataSidecarIdentity(sidecarPath)
        sidecarGuard.requireSingleLink("installed metadata class path authority")
        sidecarGuard.verifyUnchanged("installed metadata class path authority $label")
        authority.verify(label)
        requireTrustedMetadataPath(codeSource)
        val paths = manifest.getValue("entries").jsonArray.map { Path.of(it.jsonObject.getValue("path").jsonPrimitive.content) }
        paths.forEach(::requireTrustedMetadataPath)
        require(System.getProperty("java.class.path").split(java.io.File.pathSeparator).map(::qualificationPath) == paths) {
            "running controller class path differs from the installed ordered closure"
        }
    }
    fun requireDeployment(configuration: FullTreeFunctionObservationIsolationConfiguration) {
        requireCurrent("deployment binding")
        val entries = manifest.getValue("entries").jsonArray
        require(configuration.workerClassPath.size == entries.size && entries.indices.all { index ->
            val entry = entries[index].jsonObject
            configuration.workerClassPath[index].path.toString() == entry.getValue("path").jsonPrimitive.content &&
                configuration.workerClassPath[index].expectedSha256 == entry.getValue("sha256").jsonPrimitive.content
        }) { "worker deployment differs from the executing installed controller closure" }
        require(Files.isSameFile(Path.of("/proc/self/exe"), configuration.javaExecutable)) {
            "controller JVM differs from the admitted worker JVM"
        }
    }
    fun evidence(): JsonObject = JsonObject(mapOf("entrypoint" to JsonPrimitive(GccMetadataReferenceQualificationCli::class.java.name),
        "codeSource" to JsonPrimitive(codeSource.toString()), "closureSha256" to JsonPrimitive(authority.closureSha256),
        "deploymentReference" to JsonObject(mapOf("path" to JsonPrimitive(sidecarPath.toString()),
            "bytes" to JsonPrimitive(sidecarGuard.size), "sha256" to JsonPrimitive(sidecarGuard.authenticatedSha256))),
        "classPath" to manifest))
    override fun close() {
        try { authority.close() } finally { sidecarGuard.close() }
    }
    companion object {
        fun open(): GccMetadataReferenceInstalledController {
            val source = Path.of(GccMetadataReferenceQualificationCli::class.java.protectionDomain.codeSource.location.toURI())
            require(source.isAbsolute && source.toRealPath() == source && Files.isRegularFile(source, NOFOLLOW_LINKS)) {
                "metadata qualification requires the installed controller JAR, never a development class directory"
            }
            requireTrustedMetadataPath(source)
            requireNoMetadataClasspathOverrides()
            val sidecar = source.parent.resolve("kotlin-boot-classpath-reference-v1.json")
            requireTrustedMetadataPath(sidecar)
            requireMetadataSidecarIdentity(sidecar)
            val guard = StableControlFile.open(sidecar, 256 * 1024L, "installed metadata class path authority")
            var authority: GccKotlinBootClasspathReference? = null
            try {
                guard.requireSingleLink("installed metadata class path authority")
                authority = GccKotlinBootClasspathReference.open()
                return GccMetadataReferenceInstalledController(authority, source, sidecar, guard, authority.invocationManifestBytes())
                    .also { it.requireCurrent("installed controller admission") }
            } catch (failure: Throwable) {
                try { authority?.close() } finally { guard.close() }
                throw failure
            }
        }
    }
}

private fun requireNoMetadataClasspathOverrides() {
    require(listOf("decompengine.oracle.gcc.bootKeeperClasspathReference", "decompengine.oracle.gcc.bootKeeperClasspathRoot")
        .all { System.getProperty(it).isNullOrBlank() }) { "installed metadata authority rejects development class path overrides" }
}

private fun requireMetadataSidecarIdentity(path: Path) {
    val attributes = Files.readAttributes(path, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
    requireRootMetadataSidecarIdentity((Files.getAttribute(path, "unix:uid", NOFOLLOW_LINKS) as Number).toLong(),
        (Files.getAttribute(path, "unix:mode", NOFOLLOW_LINKS) as Number).toInt(),
        (Files.getAttribute(path, "unix:nlink", NOFOLLOW_LINKS) as Number).toLong(), attributes.isRegularFile, attributes.isSymbolicLink)
}

/** Metadata predicate only; no caller-supplied identity can create an installed-controller handle. */
internal fun requireRootMetadataSidecarIdentity(uid: Long, mode: Int, links: Long, regular: Boolean, symbolic: Boolean) {
    require(uid == 0L && mode and 0x12 == 0 && links == 1L && regular && !symbolic) {
        "installed class path authority must be a root-owned nonwritable ordinary file with one link"
    }
}

private fun requireTrustedMetadataPath(path: Path) {
    require(path.isAbsolute && path.normalize() == path && path.toRealPath() == path)
    var current: Path? = path
    while (current != null) {
        val attributes = Files.readAttributes(current, BasicFileAttributes::class.java, NOFOLLOW_LINKS)
        require(!attributes.isSymbolicLink && (attributes.isRegularFile || attributes.isDirectory) &&
            (Files.getAttribute(current, "unix:uid", NOFOLLOW_LINKS) as Number).toLong() == 0L &&
            (Files.getAttribute(current, "unix:mode", NOFOLLOW_LINKS) as Number).toInt() and 0x12 == 0) {
            "reference provisioning requires root-owned nonwritable ancestry: $current"
        }
        current = current.parent
    }
}
