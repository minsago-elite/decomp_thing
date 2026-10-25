package decompengine.oracle.reference

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskMount
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.FullTreeDiskScratchOperation
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject

class ReferenceCorpusOperationJournalTest {
    @Test fun `publication requires ordered complete batches and retains immutable execution chain`() = withRoot { root ->
        ReferenceCorpusOperationJournal.create(root, ID, PAYLOAD, listOf("first", "second")).use { journal ->
            journal.recordLease(evidence())
            for (batch in listOf("first", "second")) {
                journal.prepareBatch(batch, PAYLOAD, SHA)
                journal.recordAttachment(batch, PAYLOAD)
                journal.authorizeStart(batch)
                journal.recordExecution(batch, PAYLOAD)
                journal.recordObservations(batch, PAYLOAD)
            }
            val output = journal.complete(PAYLOAD)
            assertContentEquals(PAYLOAD, Files.readAllBytes(output))
            val snapshots = journal.completedSnapshots()
            snapshots.getValue("reference-observations.json")[0] = 0
            assertContentEquals(PAYLOAD, journal.completedSnapshots().getValue("reference-observations.json"))
            assertFails { (snapshots as MutableMap<String, ByteArray>).clear() }
            val complete = OracleJson.parseCanonical(Files.readAllBytes(journal.path.resolve("complete.json"))).jsonObject
            val payload = complete.getValue("payload").jsonObject
            assertEquals(JsonPrimitive(false), payload["candidateQualified"])
            assertEquals(JsonPrimitive("retained-for-trusted-reset"), payload["scratchDisposition"])
            var previous = Files.readAllBytes(journal.path.resolve("lease.json"))
            for (name in listOf("prepared-first", "attached-first", "started-first", "execution-first", "captured-first",
                "prepared-second", "attached-second", "started-second", "execution-second", "captured-second", "complete")) {
                val file = journal.path.resolve("$name.json")
                val bytes = Files.readAllBytes(file)
                val record = OracleJson.parseCanonical(bytes).jsonObject
                assertEquals(JsonPrimitive(OracleArtifacts.sha256(previous)), record["previousSha256"])
                assertEquals(JsonPrimitive(OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(record - "recordSha256")))), record["recordSha256"])
                assertEquals("r--------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file)))
                previous = bytes
            }
            journal.verify()
        }
        assertTrue(Files.isDirectory(root.resolve(".reference-corpus-$ID")))
        assertFails { ReferenceCorpusOperationJournal.create(root, ID, PAYLOAD, listOf("first", "second")) }
    }

    @Test fun `missing lifecycle transitions poison operation and cannot publish reference`() {
        for (step in 0..5) withRoot { root ->
            ReferenceCorpusOperationJournal.create(root, ID, PAYLOAD, listOf("first")).use { journal ->
                journal.recordLease(evidence())
                assertFails {
                    when (step) {
                        0 -> journal.complete(PAYLOAD)
                        1 -> journal.prepareBatch("second", PAYLOAD, SHA)
                        2 -> journal.authorizeStart("first")
                        3 -> journal.recordExecution("first", PAYLOAD)
                        4 -> journal.recordObservations("first", PAYLOAD)
                        else -> journal.completedSnapshots()
                    }
                }
                assertFalse(Files.exists(journal.path.resolve("reference-observations.json")))
                assertFails { journal.verify() }
            }
        }
    }

    @Test fun `same bytes replacement and unexpected residue revoke retained journal`() {
        for (replacement in listOf(false, true)) withRoot { root ->
            ReferenceCorpusOperationJournal.create(root, ID, PAYLOAD, listOf("first")).use { journal ->
                if (replacement) {
                    Files.move(journal.path.resolve("intent.json"), root.resolve("old-intent.json"))
                    Files.write(journal.path.resolve("intent.json"), PAYLOAD)
                    Files.setPosixFilePermissions(journal.path.resolve("intent.json"), PosixFilePermissions.fromString("r--------"))
                } else Files.writeString(journal.path.resolve("unbound.json"), "{}")
                assertFails { journal.verify() }
                assertFails { journal.recordLease(evidence()) }
            }
        }
    }

    @Test fun `exclusive root ownership and lease intent binding are mandatory`() = withRoot { root ->
        ReferenceCorpusOperationJournal.create(root, ID, PAYLOAD, listOf("first")).use { journal ->
            assertFails { ReferenceCorpusOperationJournal.create(root, "2".repeat(64), PAYLOAD, listOf("first")) }
            assertFails { journal.recordLease(evidence("f".repeat(64))) }
            assertFalse(Files.exists(journal.path.resolve("lease.json")))
        }
    }

    @Test fun `cgroup parent rejects ambiguous and escaping paths`() {
        assertEquals("/user.slice/user-1000.slice", ReferenceCorpusCoordinator.canonicalControlGroupParent("/user.slice/user-1000.slice"))
        for (path in listOf("/", "/user.slice/", "/user.slice/../system.slice", "relative", "/user.slice//user.scope", "/user slice")) {
            assertFails(path) { ReferenceCorpusCoordinator.canonicalControlGroupParent(path) }
        }
    }

    private fun evidence(request: String = OracleArtifacts.sha256(PAYLOAD)) = FullTreeDiskScratchEvidence.create(
        operation = FullTreeDiskScratchOperation(ID, request, "reference-corpus", SHA),
        policy = FullTreeDiskScratchPolicy(1024, 8192, 128, 256), mountPathSha256 = "c".repeat(64),
        mount = FullTreeDiskMount(42, 36, "7:1", Path.of("/"), Path.of("/record-only-test/scratch"),
            listOf("noatime", "nodev", "noexec", "nosuid", "rw"), "ext4"),
        mountIdentity = identity(2), capacity = LinuxFilesystemCapacity(4096, 8192, 4096, 256, 200, 255, false),
        leaseIdentity = identity(12), leaseRecordSha256 = "d".repeat(64))

    private fun identity(inode: Long) = LinuxFileIdentity(LinuxFileKey(7, inode), 0x41c0, 1000, 1000, 2, 42,
        isRegularFile = false, isDirectory = true, isSymbolicLink = false)

    private fun withRoot(action: (Path) -> Unit) {
        val parent = Files.createTempDirectory("reference-journal-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(parent, PosixFilePermissions.fromString("rwx------"))
        val root = Files.createDirectory(parent.resolve("journal"))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try { action(root) } finally { Files.walk(parent).use { it.sorted(Comparator.reverseOrder()).toList() }.forEach(Files::deleteIfExists) }
    }

    private companion object {
        val ID = "1".repeat(64)
        val SHA = "a".repeat(64)
        val PAYLOAD = OracleJson.canonicalBytes(JsonObject(mapOf("fixtureOnly" to JsonPrimitive(true))))
    }
}
