package decompengine.oracle.gcc

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Test-only removal of a prepared GCC operation that never reached START. Every entry must still have the
 * identity its prepared owner recorded; production cold recovery is not represented by this reset.
 */
internal data class GccBundledAbandonedPreparation(
    val evidence: FullTreeDiskScratchEvidence,
    val definition: GccCompilerEngineValidatedContainmentDefinition,
    val leaseRecord: ByteArray,
    val children: Map<String, LinuxFileIdentity>,
)

internal fun resetGccBundledAbandonedPreparation(mount: Path, expected: GccBundledAbandonedPreparation) {
    val run = expected.definition.outputLease.path
    val lease = run.parent
    LinuxFilesystemSyscalls.openRoot(mount).use { root ->
        assertTrue(LinuxFilesystemSyscalls.tryExclusiveLock(root), "test reset cannot take the dedicated mount lock")
        try {
            assertEquals(expected.evidence.mountId, root.identity.mountId)
            assertEquals(expected.evidence.device, root.identity.key.device)
            assertEquals(expected.evidence.rootInode, root.identity.key.inode)
            assertEquals(listOf(lease.fileName.toString()), LinuxFilesystemSyscalls.directoryEntryNames(root, 2))
            LinuxFilesystemSyscalls.openDirectoryAt(root.fd, lease.fileName.toString()).use { leased ->
                assertEquals(expected.evidence.leaseRootDevice, leased.identity.key.device)
                assertEquals(expected.evidence.leaseRootInode, leased.identity.key.inode)
                assertEquals(root.identity.uid, leased.identity.uid)
                assertEquals(root.identity.mountId, leased.identity.mountId)
                assertEquals(448, leased.identity.mode and 0xfff)
                assertEquals(listOf(run.fileName.toString(), "lease.json").sorted(), LinuxFilesystemSyscalls.directoryEntryNames(leased, 3).sorted())
                LinuxFilesystemSyscalls.openRegularFileAtOrNull(leased.fd, "lease.json").use { record ->
                    val selected = assertNotNull(record)
                    assertEquals(256, selected.identity.mode and 0xfff)
                    assertEquals(1, selected.identity.linkCount)
                    assertEquals(root.identity.uid, selected.identity.uid)
                    assertEquals(root.identity.mountId, selected.identity.mountId)
                    LinuxFilesystemSyscalls.openReadableFrom(selected).use { readable ->
                        assertContentEquals(expected.leaseRecord, LinuxFilesystemSyscalls.read(readable, 64 * 1024) {})
                    }
                    LinuxFilesystemSyscalls.openDirectoryAt(leased.fd, run.fileName.toString()).use { output ->
                        val identity = expected.definition.outputLease
                        assertEquals(identity.device, output.identity.key.device)
                        assertEquals(identity.inode, output.identity.key.inode)
                        assertEquals(identity.mountId, output.identity.mountId)
                        assertEquals(identity.uid, output.identity.uid)
                        assertEquals(identity.permissions, output.identity.mode and 0xfff)
                        assertEquals(expected.children.keys.sorted(), LinuxFilesystemSyscalls.directoryEntryNames(output, 4).sorted())
                        for ((name, original) in expected.children) {
                            LinuxFilesystemSyscalls.openDirectoryAt(output.fd, name).use { child ->
                                assertEquals(original, child.identity)
                                assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(child, 1).isEmpty())
                                requireCurrentName(output, name, child.identity)
                                LinuxFilesystemSyscalls.removeDirectory(output.fd, name)
                            }
                        }
                        assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(output, 1).isEmpty())
                        LinuxFilesystemSyscalls.synchronize(output)
                        requireCurrentName(leased, run.fileName.toString(), output.identity, compareLinkCount = false)
                        LinuxFilesystemSyscalls.removeDirectory(leased.fd, run.fileName.toString())
                    }
                    requireCurrentName(leased, "lease.json", selected.identity)
                    LinuxFilesystemSyscalls.unlink(leased.fd, "lease.json")
                }
                assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(leased, 1).isEmpty())
                LinuxFilesystemSyscalls.synchronize(leased)
                requireCurrentName(root, lease.fileName.toString(), leased.identity, compareLinkCount = false)
                LinuxFilesystemSyscalls.removeDirectory(root.fd, lease.fileName.toString())
            }
            LinuxFilesystemSyscalls.synchronize(root)
            assertTrue(LinuxFilesystemSyscalls.directoryEntryNames(root, 1).isEmpty())
        } finally {
            LinuxFilesystemSyscalls.unlock(root)
        }
    }
}

private fun requireCurrentName(parent: LinuxDescriptor, name: String, expected: LinuxFileIdentity, compareLinkCount: Boolean = true) {
    LinuxFilesystemSyscalls.openPathAtOrNull(parent.fd, name).use { selected ->
        val identity = assertNotNull(selected).identity
        assertEquals(if (compareLinkCount) expected else expected.copy(linkCount = identity.linkCount), identity)
    }
}

/** Captures the exact pre-START residue of [prepared] so the test can reset its dedicated mount afterwards. */
internal fun GccBundledPreparedOperation.abandonedPreparation(): GccBundledAbandonedPreparation {
    val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definitionBytes)
    val output = definition.outputLease.path
    val children = Files.list(output).use { entries -> entries.map { it.fileName.toString() }.sorted().toList() }
        .associateWith { name -> LinuxFilesystemSyscalls.openRoot(output.resolve(name)).use { it.identity } }
    return GccBundledAbandonedPreparation(FullTreeDiskScratchEvidence.parseCanonical(diskEvidenceBytes), definition,
        Files.readAllBytes(output.parent.resolve("lease.json")), children)
}
