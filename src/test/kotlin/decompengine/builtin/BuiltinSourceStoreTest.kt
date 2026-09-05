package decompengine.builtin

import decompengine.agent.*
import decompengine.builtin.provider.*
import decompengine.repair.*
import kotlinx.serialization.json.*
import org.junit.jupiter.api.io.TempDir
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.StandardOpenOption.*
import java.nio.file.attribute.PosixFilePermissions
import java.time.Duration
import kotlin.test.*

class BuiltinSourceStoreTest {
    @TempDir lateinit var directory: Path
    private val source = AgentWorkspacePath("project", "source.c")
    private fun privateDirectory(name: String) = Files.createDirectory(directory.resolve(name)).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }
    private fun request(root: AgentWorkspaceRoot = AgentWorkspaceRoot("project", directory.resolve("workspace")),
        cancellation: AgentCancellation = AgentCancellation.NONE) =
        AgentExecutionRequest("repair stored source", listOf(root), accessPolicy = AgentAccessPolicy(listOf(
            AgentPathRule(source, setOf(AgentOperation.READ_FILE, AgentOperation.WRITE_FILE)),
            AgentPathRule(AgentWorkspacePath("project", "oracle.txt"), setOf(AgentOperation.READ_FILE)))), cancellation = cancellation)
    private fun control() = BuiltinExecutionControl(request(), System.nanoTime() + Duration.ofMinutes(1).toNanos())
    private fun files(text: String = "source") = mapOf(source to text.toByteArray())
    private fun hash(files: Map<AgentWorkspacePath, ByteArray>) = BuiltinWorkspaceSnapshot.capture(files).sha256
    private fun store(configuration: BuiltinSourceStoreConfiguration, secrets: List<String> = emptyList()) =
        BuiltinSourceStore(configuration, request(), emptySet(), secrets)
    private fun entries(path: Path) = Files.list(path).use { it.filter { file -> file.fileName.toString() != ".lock" }.toList() }

    @Test fun `new store instance rehydrates canonical snapshots with deduplicated immutable blobs`() {
        val configuration = BuiltinSourceStoreConfiguration(privateDirectory("roundtrip"))
        val original = linkedMapOf(source to "가나다".toByteArray(), AgentWorkspacePath("project", "same.c") to "가나다".toByteArray(),
            AgentWorkspacePath("project", "empty.c") to byteArrayOf())
        store(configuration).save(original, hash(original), control())
        assertEquals(3, entries(configuration.directory).size) // One manifest, two distinct blobs.
        store(configuration).save(original.toList().reversed().toMap(), hash(original), control())
        assertEquals(3, entries(configuration.directory).size)
        val loaded = store(configuration).load(hash(original), control())
        original.forEach { (path, bytes) -> assertContentEquals(bytes, loaded.getValue(path)) }
        loaded.getValue(source)[0] = 0
        assertContentEquals(original.getValue(source), store(configuration).load(hash(original), control()).getValue(source))
        val revised = original + (source to "revised".toByteArray())
        store(configuration).save(revised, hash(revised), control())
        assertEquals(5, entries(configuration.directory).size)
        assertContentEquals(original.getValue(source), store(configuration).load(hash(original), control()).getValue(source))
    }

    @Test fun `all source storage ceilings reject before publishing any project bytes`() {
        val cases = listOf<(Path) -> BuiltinSourceStoreConfiguration>(
            { BuiltinSourceStoreConfiguration(it, maximumStoredBytes = 1024, maximumSnapshotBytes = 1024) },
            { BuiltinSourceStoreConfiguration(it, maximumEntries = 2) },
            { BuiltinSourceStoreConfiguration(it, maximumSnapshotBytes = 999) },
            { BuiltinSourceStoreConfiguration(it, maximumSnapshotFiles = 1) },
            { BuiltinSourceStoreConfiguration(it, maximumFileBytes = 499) },
        )
        val candidate = mapOf(source to ByteArray(500) { 65 }, AgentWorkspacePath("project", "other.c") to ByteArray(500) { 66 })
        cases.forEachIndexed { index, make ->
            val configuration = make(privateDirectory("limit-$index"))
            assertFailsWith<BuiltinJournalException> { store(configuration).save(candidate, hash(candidate), control()) }
            assertTrue(entries(configuration.directory).isEmpty())
        }
        val configuration = BuiltinSourceStoreConfiguration(privateDirectory("manifest-limit"), maximumManifestBytes = 512)
        val longName = mapOf(AgentWorkspacePath("project", "x".repeat(600)) to "x".toByteArray())
        assertFailsWith<BuiltinJournalException> { store(configuration).save(longName, hash(longName), control()) }
        assertTrue(entries(configuration.directory).isEmpty())
    }

    @Test fun `blob and manifest corruption truncation and absence cannot be adopted or repaired silently`() {
        for (damage in listOf("blob", "manifest", "truncate", "missing")) {
            val configuration = BuiltinSourceStoreConfiguration(privateDirectory(damage))
            val candidate = files()
            store(configuration).save(candidate, hash(candidate), control())
            val target = entries(configuration.directory).single { it.fileName.toString().startsWith(if (damage == "manifest") "snapshot-" else "blob-") }
            val original = Files.readAllBytes(target)
            when (damage) {
                "missing" -> Files.delete(target)
                "truncate" -> Files.write(target, original.copyOf(original.size - 1))
                else -> Files.write(target, original.copyOf().also { it[0] = (it[0].toInt() xor 1).toByte() })
            }
            assertFailsWith<BuiltinJournalException> { store(configuration).load(hash(candidate), control()) }
            if (damage != "missing") {
                val damaged = Files.readAllBytes(target)
                assertFailsWith<BuiltinJournalException> { store(configuration).save(candidate, hash(candidate), control()) }
                assertContentEquals(damaged, Files.readAllBytes(target))
            }
        }
    }

    @Test fun `private store rejects links loose permissions active writers and workspace placement`() {
        val configuration = BuiltinSourceStoreConfiguration(privateDirectory("unsafe"))
        store(configuration).save(files(), hash(files()), control())
        val blob = entries(configuration.directory).single { it.fileName.toString().startsWith("blob-") }
        val hardlink = directory.resolve("external-link")
        Files.createLink(hardlink, blob)
        assertFailsWith<BuiltinJournalException> { store(configuration).load(hash(files()), control()) }
        Files.delete(hardlink)
        FileChannel.open(configuration.directory.resolve(".lock"), READ, WRITE).use { channel -> channel.lock().use {
            assertFailsWith<BuiltinJournalException> { store(configuration).load(hash(files()), control()) }
        } }
        Files.setPosixFilePermissions(configuration.directory, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFailsWith<BuiltinJournalException> { store(configuration).load(hash(files()), control()) }
        Files.setPosixFilePermissions(configuration.directory, PosixFilePermissions.fromString("rwx------"))
        val saved = directory.resolve("saved-blob")
        Files.move(blob, saved); Files.createSymbolicLink(blob, saved)
        assertFailsWith<BuiltinJournalException> { store(configuration).load(hash(files()), control()) }
        val workspace = BuiltinSourceStoreConfiguration(privateDirectory("workspace"))
        assertFailsWith<BuiltinJournalException> { store(workspace).save(files(), hash(files()), control()) }
        val excluded = BuiltinSourceStore(configuration, request(), setOf(configuration.directory), emptyList())
        assertFailsWith<BuiltinJournalException> { excluded.save(files(), hash(files()), control()) }
    }

    @Test fun `unreferenced partial blobs count against physical capacity`() {
        val configuration = BuiltinSourceStoreConfiguration(privateDirectory("orphan"), maximumStoredBytes = 1024, maximumSnapshotBytes = 1024)
        val orphan = configuration.directory.resolve("blob-${"a".repeat(64)}.bin")
        Files.write(orphan, ByteArray(800), CREATE_NEW)
        Files.setPosixFilePermissions(orphan, PosixFilePermissions.fromString("rw-------"))
        assertFailsWith<BuiltinJournalException> { store(configuration).save(files(), hash(files()), control()) }
        assertEquals(listOf(orphan), entries(configuration.directory))
        assertEquals(800, Files.size(orphan))
    }

    @Test fun `declared secrets in source paths or escaped contents are rejected before persistence`() {
        val secret = "private-credential"
        val cases = listOf(files(secret), mapOf(AgentWorkspacePath("project", secret) to "source".toByteArray()),
            files("a\\\"b"))
        cases.forEachIndexed { index, candidate ->
            val configuration = BuiltinSourceStoreConfiguration(privateDirectory("secret-$index"))
            assertFailsWith<BuiltinJournalException> { store(configuration, listOf(secret, "a\"b")).save(candidate, hash(candidate), control()) }
            assertTrue(entries(configuration.directory).isEmpty())
        }
    }

    private data class Fixture(val journal: BuiltinJournalConfiguration, val checkpoint: BuiltinCheckpointConfiguration,
        val sources: BuiltinSourceStoreConfiguration, val initial: Map<String, ByteArray>)
    private fun fixture(name: String): Fixture {
        val initial = mapOf("source.c" to "old".toByteArray(), "oracle.txt" to "immutable".toByteArray())
        val snapshot = BuiltinWorkspaceSnapshot.capture(initial.mapKeys { AgentWorkspacePath("project", it.key) })
        return Fixture(BuiltinJournalConfiguration(privateDirectory("$name-journal").resolve("journal.jsonl"),
            BuiltinJournalIdentity("fixture", "scripted-v1", snapshot.sha256, "b".repeat(64), "c".repeat(64))),
            BuiltinCheckpointConfiguration(privateDirectory("$name-checkpoint")) { _, calls ->
                if (calls == 1) BuiltinCheckpointAction.SUSPEND else BuiltinCheckpointAction.CONTINUE
            }, BuiltinSourceStoreConfiguration(privateDirectory("$name-sources")), initial)
    }
    private fun execute(fixture: Fixture, provider: ModelProvider, resume: BuiltinCapturedResume? = null,
        cancellation: AgentCancellation = AgentCancellation.NONE) =
        CapturedRepairStagingAuthority.executeReceipt(BuiltinCapturedRepairHarness(provider, journalConfiguration = fixture.journal,
            checkpointConfiguration = fixture.checkpoint, resume = resume, secrets = listOf("runtime-credential"), sourceStoreConfiguration = fixture.sources),
            fixture.initial, setOf("source.c"), RepairResourceBudget(), { root -> request(root, cancellation) }) {}
    private fun response(calls: List<ModelToolCall> = emptyList()) = ModelResponse("", calls,
        if (calls.isEmpty()) ModelFinishReason.STOP else ModelFinishReason.TOOL_CALLS, ModelUsage(100, 10, false), 1)
    private fun write() = ModelToolCall("write1", "write_text", buildJsonObject { put("root", "project"); put("path", "source.c"); put("content", "candidate") })

    @Test fun `captured continuation uses only its durable reference to restore candidates into a fresh bounded stage`() {
        val fixture = fixture("captured")
        val first = execute(fixture, ModelProvider { _, _ -> response(listOf(write())) })
        val reference = assertNotNull(assertIs<BuiltinCapturedExecutionEvidence>(first.receipt.providerEvidence).loop.checkpoint)
        var turn = 0
        val continued = execute(fixture, ModelProvider { request, _ ->
            if (turn++ == 0) response(listOf(ModelToolCall("read2", "read_text", buildJsonObject { put("root", "project"); put("path", "source.c") })))
            else { assertEquals("candidate", request.messages.last().content); response() }
        }, BuiltinCapturedResume.fromStore(reference))
        val evidence = assertIs<BuiltinCapturedExecutionEvidence>(continued.receipt.providerEvidence)
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, evidence.loop.stop)
        assertEquals(2, evidence.loop.toolCalls)
        assertEquals(1, evidence.restorationAudit.size)
        assertEquals(checkpointHash("old".toByteArray()), continued.result.changes.single().beforeSha256)
        assertEquals("candidate", continued.files.getValue("source.c")!!.decodeToString())
        assertTrue(entries(fixture.sources.directory).all { !Files.readString(it).contains("runtime-credential") })
    }

    @Test fun `failed source publication prevents a checkpoint and damaged recovery leaves the prior commitment usable`() {
        val fixture = fixture("failed")
        val limited = fixture.copy(sources = BuiltinSourceStoreConfiguration(fixture.sources.directory, maximumFileBytes = 2))
        var calls = 0
        val rejected = execute(limited, ModelProvider { _, _ -> calls++; response() })
        assertIs<AgentExecutionOutcome.Failed>(rejected.receipt.outcome); assertEquals(0, calls)
        assertTrue(entries(fixture.checkpoint.directory).isEmpty())
        val valid = fixture("recovery")
        val first = execute(valid, ModelProvider { _, _ -> response(listOf(write())) })
        val reference = assertIs<BuiltinCapturedExecutionEvidence>(first.receipt.providerEvidence).loop.checkpoint!!
        val blob = valid.sources.directory.resolve("blob-${checkpointHash("candidate".toByteArray())}.bin")
        Files.writeString(blob, "damaged!!")
        val damaged = execute(valid, ModelProvider { _, _ -> calls++; response() }, BuiltinCapturedResume.fromStore(reference))
        assertIs<AgentExecutionOutcome.Failed>(damaged.receipt.outcome); assertEquals(0, calls)
        assertContentEquals(valid.initial.getValue("source.c"), damaged.files.getValue("source.c"))
        Files.writeString(blob, "candidate")
        val recovered = execute(valid, ModelProvider { _, _ -> calls++; response() }, BuiltinCapturedResume.fromStore(reference))
        assertEquals(BuiltinStop.VALIDATION_REQUIRED, assertIs<BuiltinCapturedExecutionEvidence>(recovered.receipt.providerEvidence).loop.stop)
        assertEquals(1, calls)
    }

    @Test fun `cancellation inside source capture stays cancelled and publishes no checkpoint`() {
        val fixture = fixture("cancel")
        val cancellation = AgentCancellation { Files.exists(fixture.sources.directory.resolve(".lock")) }
        var calls = 0
        val cancelled = execute(fixture, ModelProvider { _, _ -> calls++; response() }, cancellation = cancellation)
        val evidence = assertIs<BuiltinCapturedExecutionEvidence>(cancelled.receipt.providerEvidence)
        assertEquals(BuiltinStop.CANCELLED, evidence.loop.stop)
        assertEquals(AgentStopReason.CANCELLED, cancelled.result.stopReason)
        assertEquals(0, calls); assertTrue(entries(fixture.checkpoint.directory).isEmpty())
        assertTrue(entries(fixture.sources.directory).isEmpty())
    }
}
