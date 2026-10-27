package decompengine.project

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.repair.readStableRegularFile
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path

/** Host-owned exact compiler input closure; it is never exposed to the reconstruction agent. */
internal class ContainedModuleCompilationSnapshot private constructor(
    private val projectDir: Path,
    val sourcePath: String,
    private val profile: ReconstructionProfile,
    private val inventory: List<String>,
    private val contents: Map<String, ByteArray>,
) {
    val inputs = contents.map { (path, bytes) -> ContainedModuleCompilerInput(path, sha256(bytes), bytes.size.toLong()) }
    val sourceSha256 = inputs.single { it.path == sourcePath }.sha256

    fun requireCurrent(progress: () -> Unit = {}) {
        require(discover(projectDir, profile, progress).second == inventory) { "module compiler input search tree changed" }
        for (input in inputs) {
            val read = readStableRegularFile(projectDir, input.path, ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES, cancellationCheck = { checkInterrupted(); progress() })
            require(read.identity.linkCount == 1) { "module compiler input has another link: ${input.path}" }
            val current = read.bytes
            require(current.size.toLong() == input.bytes && sha256(current) == input.sha256) {
                "module compiler input changed: ${input.path}"
            }
        }
    }

    fun populate(snapshot: LinuxDescriptor, progress: () -> Unit = {}) {
        require(LinuxFilesystemSyscalls.directoryEntryNames(snapshot, 1).isEmpty()) { "module compiler snapshot must start empty" }
        for ((path, bytes) in contents) write(snapshot, path.split('/'), bytes, progress)
        LinuxFilesystemSyscalls.synchronize(snapshot)
    }

    private fun write(parent: LinuxDescriptor, components: List<String>, bytes: ByteArray, progress: () -> Unit) {
        checkInterrupted(); progress()
        val name = components.first()
        if (components.size == 1) {
            LinuxFilesystemSyscalls.createRegularFile(parent.fd, name, 384).use { file ->
                LinuxFilesystemSyscalls.write(file, bytes) { checkInterrupted(); progress() }
                LinuxFilesystemSyscalls.chmod(file, 256)
                LinuxFilesystemSyscalls.synchronize(file)
            }
        } else {
            val existing = LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name)
            if (existing == null) LinuxFilesystemSyscalls.createDirectory(parent.fd, name, 448)
            else existing.use { require(it.identity.isDirectory && !it.identity.isSymbolicLink) }
            LinuxFilesystemSyscalls.openDirectoryAt(parent.fd, name).use { child ->
                require(child.identity.mountId == parent.identity.mountId && child.identity.uid == parent.identity.uid)
                write(child, components.drop(1), bytes, progress)
                LinuxFilesystemSyscalls.synchronize(child)
            }
        }
    }

    companion object {
        fun capture(projectDir: Path, sourcePath: String, profile: ReconstructionProfile, progress: () -> Unit = {}): ContainedModuleCompilationSnapshot {
            checkInterrupted(); progress()
            require(projectDir.isAbsolute && projectDir.toRealPath() == projectDir) { "module compiler project must be canonical" }
            requireContainedModuleCompilerProfile(profile)
            val sourceDeclaration = profile.layout.declaration("module-implementation")
            val module = sourceDeclaration.moduleIdForPath(sourcePath)
            val (headers, inventory) = discover(projectDir, profile, progress)
            val paths = (headers + sourcePath).toSortedSet()
            for (id in listOf("shared-interface", "module-interface", "module-private-interface")) {
                val declaration = profile.layout.declaration(id)
                val required = declaration.materialize(if ("{module}" in declaration.pathTemplate) mapOf("module" to module) else emptyMap())
                require(required in paths) { "required module compiler interface is missing: $required" }
            }
            var total = 0L
            val contents = paths.associateWith { path ->
                checkInterrupted()
                val read = readStableRegularFile(projectDir, path, ContainedModuleCompilerRequest.MAXIMUM_INPUT_FILE_BYTES, cancellationCheck = { checkInterrupted(); progress() })
                require(read.identity.linkCount == 1) { "module compiler input has another link: $path" }
                val bytes = read.bytes
                total = Math.addExact(total, bytes.size.toLong())
                require(total <= ContainedModuleCompilerRequest.MAXIMUM_TOTAL_INPUT_BYTES) { "module compiler snapshot exceeds aggregate bound" }
                bytes
            }
            return ContainedModuleCompilationSnapshot(projectDir, sourcePath, profile, inventory, contents).also { it.requireCurrent(progress) }
        }

        private fun discover(projectDir: Path, profile: ReconstructionProfile, progress: () -> Unit): Pair<Set<String>, List<String>> {
            val interfaces = profile.layout.declarations.filter { declaration ->
                declaration.roles.any { it == ProjectFileRole.PUBLIC_INTERFACE || it == ProjectFileRole.PRIVATE_INTERFACE }
            }
            val roots = interfaces.map { it.pathTemplate.substringBefore('/') }.distinct().sorted()
            val headers = sortedSetOf<String>()
            val inventory = sortedSetOf<String>()
            var visited = 0
            for (root in roots) {
                val directory = projectDir.resolve(root)
                require(Files.isDirectory(directory, LinkOption.NOFOLLOW_LINKS) && !Files.isSymbolicLink(directory))
                Files.walk(directory, 32).use { stream ->
                    val iterator = stream.iterator()
                    while (iterator.hasNext()) {
                        checkInterrupted(); progress()
                        val path = iterator.next()
                        require(++visited <= ContainedModuleCompilerRequest.MAXIMUM_INPUTS * 4) { "module compiler input discovery exceeds bound" }
                        require(!Files.isSymbolicLink(path)) { "module compiler input tree contains a symbolic link" }
                        val relative = projectDir.relativize(path).toString()
                        require(projectDir.relativize(path).nameCount < 32) { "module compiler search depth exceeds bound" }
                        if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                            inventory += "directory:$relative"
                            continue
                        }
                        require(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) { "module compiler search tree contains a special file" }
                        val declaration = profile.layout.declarations.singleOrNull { it.matches(relative) }
                        require(declaration != null && declaration.roles.any { it in setOf(ProjectFileRole.PUBLIC_INTERFACE,
                            ProjectFileRole.PRIVATE_INTERFACE, ProjectFileRole.MODULE_IMPLEMENTATION, ProjectFileRole.ENTRYPOINT_IMPLEMENTATION) }) {
                            "undeclared compiler search input could shadow the authenticated closure: $relative"
                        }
                        inventory += "file:$relative"
                        if (interfaces.any { it.matches(relative) }) {
                            require(headers.size < ContainedModuleCompilerRequest.MAXIMUM_INPUTS - 1) { "module compiler input count exceeds bound" }
                            headers += relative
                        }
                    }
                }
            }
            return headers to inventory.toList()
        }

        private fun checkInterrupted() {
            if (Thread.currentThread().isInterrupted) throw InterruptedException("contained module compilation cancelled")
        }
    }
}
