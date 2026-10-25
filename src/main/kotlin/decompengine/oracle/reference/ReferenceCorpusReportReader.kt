package decompengine.oracle.reference

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.permissions
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.fulltree.KotlinContainedCommandProtocol
import decompengine.oracle.fulltree.KotlinContainedCommandRequest
import java.nio.file.Files

/** Descriptor-only report collection; returns raw bytes and grants no execution authority. */
internal object ReferenceCorpusReportReader {
    fun read(reports: LinuxDescriptor, stdoutBytes: Long, stderrBytes: Long): ByteArray {
        require(stdoutBytes in 0..KotlinContainedCommandRequest.MAXIMUM_LOG_BYTES &&
            stderrBytes in 0..KotlinContainedCommandRequest.MAXIMUM_LOG_BYTES) {
            "reference diagnostic outcome sizes exceed the existing protocol limit"
        }
        requireDirectory(reports)
        requireInventory(reports)
        checkNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, KotlinContainedCommandProtocol.STDOUT_FILE)).use { stdout ->
            checkNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, KotlinContainedCommandProtocol.STDERR_FILE)).use { stderr ->
                requireLog(reports, stdout, stdoutBytes)
                requireLog(reports, stderr, stderrBytes)
                val observation = checkNotNull(DescriptorBoundAtomicStateFile.readManifestOrNull(
                    reports, ReferenceCorpusWorker.OBSERVATIONS_FILE, ReferenceCorpusWorker.MAXIMUM_OBSERVATION_BYTES))
                val bytes = observation.bytes
                require(setOf(stdout.identity.key, stderr.identity.key, observation.identity.key).size == 3) {
                    "reference report entries alias one another"
                }
                // Diagnostics are never parsed or promoted into reference observations.
                requireLog(reports, stdout, stdoutBytes)
                requireLog(reports, stderr, stderrBytes)
                requireNamedFile(reports, KotlinContainedCommandProtocol.STDOUT_FILE, stdout.identity, stdoutBytes)
                requireNamedFile(reports, KotlinContainedCommandProtocol.STDERR_FILE, stderr.identity, stderrBytes)
                requireNamedFile(reports, ReferenceCorpusWorker.OBSERVATIONS_FILE, observation.identity, bytes.size.toLong())
                requireInventory(reports)
                requireDirectory(reports)
                return bytes
            }
        }
    }

    private fun requireDirectory(reports: LinuxDescriptor) {
        val current = LinuxFilesystemSyscalls.identity(reports.fd)
        require(current == reports.identity && current.isDirectory && !current.isSymbolicLink &&
            current.mode.permissions == 448) { "reference reports directory identity or private mode changed" }
    }

    private fun requireInventory(reports: LinuxDescriptor) {
        require(LinuxFilesystemSyscalls.directoryEntryNames(reports, REPORT_NAMES.size + 1).toSet() == REPORT_NAMES) {
            "reference reports directory differs from the exact worker and keeper inventory"
        }
    }

    private fun requireLog(reports: LinuxDescriptor, file: LinuxDescriptor, expectedBytes: Long) {
        val current = LinuxFilesystemSyscalls.identity(file.fd)
        require(current == file.identity && current.isRegularFile && !current.isDirectory && !current.isSymbolicLink &&
            current.linkCount == 1 && current.mode.permissions == 384 && current.uid == reports.identity.uid &&
            current.gid == reports.identity.gid && current.mountId == reports.identity.mountId) {
            "reference diagnostic is not the pinned private single-link regular file"
        }
        require(Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(file.fd)) == expectedBytes) {
            "reference diagnostic size differs from its authenticated execution outcome"
        }
    }

    private fun requireNamedFile(reports: LinuxDescriptor, name: String, expected: LinuxFileIdentity, expectedBytes: Long) {
        checkNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(reports.fd, name)).use { named ->
            require(named.identity == expected && Files.size(LinuxFilesystemSyscalls.stableDescriptorPath(named.fd)) == expectedBytes &&
                LinuxFilesystemSyscalls.identity(named.fd) == expected) { "reference report name or pinned file changed" }
        }
    }

    private val REPORT_NAMES = setOf(ReferenceCorpusWorker.OBSERVATIONS_FILE,
        KotlinContainedCommandProtocol.STDOUT_FILE, KotlinContainedCommandProtocol.STDERR_FILE)
}
