package decompengine.oracle.gcc

import decompengine.acp.LinuxFileIdentity
import decompengine.acp.LinuxFileKey
import decompengine.acp.LinuxFilesystemCapacity
import decompengine.analysis.BundledGhidra
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.FullTreeDiskMount
import decompengine.oracle.fulltree.FullTreeDiskScratchEvidence
import decompengine.oracle.fulltree.FullTreeDiskScratchOperation
import decompengine.oracle.fulltree.FullTreeDiskScratchPolicy
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccBundledOperationJournalTest {
    @Test
    fun `new journal retains private canonical intent and close preserves its residue`() = withJournalRoot { root ->
        val original = intent()
        val supplied = original.copyOf()
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, supplied)
        val path = journal.path
        try {
            supplied.fill(0)
            assertEquals(root.resolve(operationName()), path)
            assertEquals(setOf("intent.json"), names(path))
            assertContentEquals(original, Files.readAllBytes(path.resolve("intent.json")))
            assertEquals("rwx------", permissions(path))
            assertEquals("r--------", permissions(path.resolve("intent.json")))
            assertFailsWith<IllegalStateException> { journal.preparedBytes }
            journal.verify("retained original intent")
        } finally {
            journal.close()
        }
        journal.close()
        assertEquals(setOf("intent.json"), names(path))
        assertFailsWith<IllegalStateException> { journal.verify("after close") }
        assertFailsWith<IllegalArgumentException> {
            GccBundledOperationJournal.create(root, OPERATION_ID, original).close()
        }
        GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, original).use { it.verify("released root lock") }
    }

    @Test
    fun `prepared record links exact intent evidence v2 definition and deployment closure`() = withJournalRoot { root ->
        val intent = intent()
        val evidence = evidence(intent)
        val definition = definition()
        val originalDefinition = definition.copyOf()
        val parsed = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(definition)
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
        val path = journal.path
        try {
            journal.recordLease(evidence)
            assertEquals(setOf("intent.json", "lease-evidence.json"), names(path))
            assertContentEquals(evidence.canonicalBytes(), Files.readAllBytes(path.resolve("lease-evidence.json")))
            journal.recordPrepared(definition, DEPLOYMENT_SHA256)
            definition.fill(0)
            val prepared = journal.preparedBytes
            val document = OracleJson.parseCanonical(prepared).jsonObject
            assertEquals(setOf(
                "provider", "schemaVersion", "operationId", "intentSha256", "diskEvidenceSha256",
                "definitionSha256", "definitionBindingSha256", "deploymentClosureSha256", "preparedSha256",
            ), document.keys)
            assertEquals("gcc-bundled-prepared-operation-v1", document.getValue("provider").jsonPrimitive.content)
            assertEquals(JsonPrimitive(1), document.getValue("schemaVersion"))
            assertEquals(OPERATION_ID, document.getValue("operationId").jsonPrimitive.content)
            assertEquals(OracleArtifacts.sha256(intent), document.getValue("intentSha256").jsonPrimitive.content)
            assertEquals(evidence.evidenceSha256, document.getValue("diskEvidenceSha256").jsonPrimitive.content)
            assertEquals(OracleArtifacts.sha256(originalDefinition), document.getValue("definitionSha256").jsonPrimitive.content)
            assertEquals(parsed.bindingSha256, document.getValue("definitionBindingSha256").jsonPrimitive.content)
            assertEquals(DEPLOYMENT_SHA256, document.getValue("deploymentClosureSha256").jsonPrimitive.content)
            assertEquals(
                OracleArtifacts.sha256(OracleJson.canonicalBytes(JsonObject(document - "preparedSha256"))),
                document.getValue("preparedSha256").jsonPrimitive.content,
            )
            prepared.fill(0)
            assertContentEquals(Files.readAllBytes(path.resolve("prepared.json")), journal.preparedBytes)
            assertContentEquals(originalDefinition, Files.readAllBytes(path.resolve("definition.json")))
            assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(path))
            names(path).forEach { assertEquals("r--------", permissions(path.resolve(it))) }
            assertEquals(JsonPrimitive(false), OracleJson.parseCanonical(originalDefinition).jsonObject.getValue("startAuthorized"))
            assertEquals(JsonPrimitive(false), OracleJson.parseCanonical(originalDefinition).jsonObject.getValue("releaseEligible"))
            journal.verify("prepared immutable records")
        } finally {
            journal.close()
        }
        assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(path))
        assertFailsWith<IllegalStateException> { journal.preparedBytes }
    }

    @Test
    fun `invalid intent canonicality shape bounds and operation IDs fail before creating residue`() = withJournalRoot { root ->
        for (bytes in listOf(
            byteArrayOf(), intent() + '\n'.code.toByte(), "[]\n".encodeToByteArray(),
            "{\"a\":1,\"a\":2}".encodeToByteArray(), byteArrayOf(0xc3.toByte(), 0x28),
            ByteArray(256 * 1024 + 1),
        )) {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, bytes).close() }
            assertTrue(names(root).isEmpty())
        }
        for (operationId in listOf("", "../escape", "a".repeat(63), "a".repeat(65), "A".repeat(64), "g".repeat(64))) {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, operationId, intent()).close() }
            assertTrue(names(root).isEmpty())
        }
    }

    @Test
    fun `journal root must already exist and be canonical private and below a trusted parent`() = withJournalRoot { root ->
        val alias = root.parent.resolve("alias")
        Files.createSymbolicLink(alias, root)
        for (candidate in listOf(root.resolve("missing"), alias, root.resolve(".."), Path.of("."), Path.of("/"))) {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(candidate, OPERATION_ID, intent()).close() }
        }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwxr-xr-x"))
        assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, intent()).close() }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        Files.setPosixFilePermissions(root.parent, PosixFilePermissions.fromString("rwxrwx---"))
        try {
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, intent()).close() }
        } finally {
            Files.setPosixFilePermissions(root.parent, PosixFilePermissions.fromString("rwx------"))
        }
        assertTrue(names(root).isEmpty())
        GccBundledOperationJournal.create(root, OPERATION_ID, intent()).use { it.verify("restored parent policy") }
    }

    @Test
    fun `root lock excludes a second operation and is released without journal deletion`() = withJournalRoot { root ->
        val first = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
        try {
            assertFailsWith<IllegalArgumentException> {
                GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
            }
            assertEquals(setOf(operationName()), names(root))
            first.verify("after competing root acquisition")
        } finally {
            first.close()
        }
        GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).use { it.verify("second independent operation") }
        assertEquals(setOf(operationName(), operationName(SECOND_OPERATION_ID)), names(root))
    }

    @Test
    fun `existing empty or staged operation directories cannot be adopted`() {
        for (withTemporary in listOf(false, true)) withJournalRoot { root ->
            val path = Files.createDirectory(root.resolve(operationName()))
            Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            if (withTemporary) immutableFile(path.resolve(DescriptorBoundAtomicStateFile.temporaryName("intent.json")), intent())
            val before = names(path)
            assertFailsWith<IllegalArgumentException> { GccBundledOperationJournal.create(root, OPERATION_ID, intent()).close() }
            assertEquals(before, names(path))
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        }
    }

    @Test
    fun `cross paired lease operation or intent digest poisons owner without publishing evidence`() {
        for (wrongOperation in listOf(false, true)) withJournalRoot { root ->
            val intent = intent()
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
            try {
                val evidence = evidence(
                    intent,
                    operationId = if (wrongOperation) SECOND_OPERATION_ID else OPERATION_ID,
                    requestSha256 = if (wrongOperation) OracleArtifacts.sha256(intent) else DEPLOYMENT_SHA256,
                )
                assertFailsWith<IllegalArgumentException> { journal.recordLease(evidence) }
                assertEquals(setOf("intent.json"), names(journal.path))
                assertFailsWith<IllegalStateException> { journal.verify("after rejected evidence") }
            } finally {
                journal.close()
            }
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent).close()
        }
    }

    @Test
    fun `lease and prepared publication are strictly sequential single use transitions`() {
        for (mode in listOf("prepare-first", "repeat-lease", "repeat-prepared")) withJournalRoot { root ->
            val intent = intent()
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
            try {
                when (mode) {
                    "prepare-first" -> assertFailsWith<IllegalStateException> { journal.recordPrepared(definition(), DEPLOYMENT_SHA256) }
                    "repeat-lease" -> {
                        journal.recordLease(evidence(intent))
                        assertFailsWith<IllegalStateException> { journal.recordLease(evidence(intent)) }
                    }
                    "repeat-prepared" -> {
                        journal.recordLease(evidence(intent))
                        journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
                        assertFailsWith<IllegalStateException> { journal.recordPrepared(definition(), DEPLOYMENT_SHA256) }
                    }
                }
                assertFailsWith<IllegalStateException> { journal.verify("after illegal stage transition") }
                assertFalse(names(journal.path).any { it.endsWith(".atomic") })
            } finally {
                journal.close()
            }
        }
    }

    @Test
    fun `prepared publication rejects legacy malformed noncanonical and oversized definitions`() {
        for (bytes in listOf(definition(legacy = true), definition() + '\n'.code.toByte(), intent(), ByteArray(1024 * 1024 + 1))) {
            withJournalRoot { root ->
                val intent = intent()
                GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                    journal.recordLease(evidence(intent))
                    assertFailsWith<IllegalArgumentException> { journal.recordPrepared(bytes, DEPLOYMENT_SHA256) }
                    assertEquals(setOf("intent.json", "lease-evidence.json"), names(journal.path))
                    assertFailsWith<IllegalStateException> { journal.preparedBytes }
                }
            }
        }
    }

    @Test
    fun `prepared publication rejects invalid deployment closure digests before writing definition`() {
        for (digest in listOf("", "a".repeat(63), "A".repeat(64), "g".repeat(64), "a".repeat(65))) withJournalRoot { root ->
            val intent = intent()
            GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                journal.recordLease(evidence(intent))
                assertFailsWith<IllegalArgumentException> { journal.recordPrepared(definition(), digest) }
                assertEquals(setOf("intent.json", "lease-evidence.json"), names(journal.path))
            }
        }
    }

    @Test
    fun `journal may not overlap the definition writable output`() {
        for (nestedOutput in listOf(false, true)) withJournalRoot { root ->
            val intent = intent()
            GccBundledOperationJournal.create(root, OPERATION_ID, intent).use { journal ->
                journal.recordLease(evidence(intent))
                val output = if (nestedOutput) journal.path.resolve("output") else root
                assertFailsWith<IllegalArgumentException> { journal.recordPrepared(definition(output), DEPLOYMENT_SHA256) }
                assertEquals(setOf("intent.json", "lease-evidence.json"), names(journal.path))
            }
        }
    }

    @Test
    fun `same bytes on a replacement inode are rejected while closing still releases locks`() = withJournalRoot { root ->
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
        val original = journal.path.resolve("intent.json")
        Files.move(original, root.parent.resolve("original-intent.json"))
        immutableFile(original, intent())
        assertFailsWith<IllegalArgumentException> { journal.verify("same-byte inode substitution") }
        journal.close()
        journal.close()
        GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        assertContentEquals(intent(), Files.readAllBytes(original))
    }

    @Test
    fun `changed bytes permissions links and extra temporary residue fail closed`() {
        for (mutation in listOf("bytes", "mode", "hardlink", "symlink", "temporary", "extra")) withJournalRoot { root ->
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
            val target = journal.path.resolve("intent.json")
            try {
                when (mutation) {
                    "bytes" -> {
                        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                        Files.write(target, intent("changed"))
                        Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("r--------"))
                    }
                    "mode" -> Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
                    "hardlink" -> Files.createLink(root.parent.resolve("extra-link"), target)
                    "symlink" -> {
                        val moved = Files.move(target, root.parent.resolve("moved-intent.json"))
                        Files.createSymbolicLink(target, moved)
                    }
                    "temporary" -> immutableFile(journal.path.resolve(DescriptorBoundAtomicStateFile.temporaryName("lease-evidence.json")), intent())
                    "extra" -> immutableFile(journal.path.resolve("unknown.json"), intent())
                }
                val before = names(journal.path)
                assertFailsWith<Exception> { journal.verify("mutation $mutation") }
                assertFailsWith<IllegalStateException> { journal.verify("poison remains") }
                assertEquals(before, names(journal.path))
            } finally {
                journal.close()
            }
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        }
    }

    @Test
    fun `root and operation directory replacement are rejected without cleanup of old or new trees`() {
        for (replaceRoot in listOf(false, true)) withJournalRoot { root ->
            val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent())
            val selected = if (replaceRoot) root else journal.path
            val moved = selected.resolveSibling("retained-original")
            Files.move(selected, moved)
            Files.createDirectory(selected)
            Files.setPosixFilePermissions(selected, PosixFilePermissions.fromString("rwx------"))
            try {
                assertFailsWith<Exception> { journal.verify("directory replacement") }
            } finally {
                journal.close()
            }
            assertTrue(Files.isDirectory(moved))
            assertTrue(Files.isDirectory(selected))
            GccBundledOperationJournal.create(root, SECOND_OPERATION_ID, intent()).close()
        }
    }

    @Test
    fun `prepared file substitution is detected and cannot be repaired into a reusable owner`() = withJournalRoot { root ->
        val intent = intent()
        val journal = GccBundledOperationJournal.create(root, OPERATION_ID, intent)
        try {
            journal.recordLease(evidence(intent))
            journal.recordPrepared(definition(), DEPLOYMENT_SHA256)
            val preparedPath = journal.path.resolve("prepared.json")
            val original = Files.readAllBytes(preparedPath)
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("rw-------"))
            Files.write(preparedPath, intent)
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<IllegalArgumentException> { journal.verify("changed prepared record") }
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("rw-------"))
            Files.write(preparedPath, original)
            Files.setPosixFilePermissions(preparedPath, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<IllegalStateException> { journal.preparedBytes }
            assertFailsWith<IllegalStateException> { journal.verify("restored bytes do not unpoison") }
        } finally {
            journal.close()
        }
        assertEquals(setOf("intent.json", "lease-evidence.json", "definition.json", "prepared.json"), names(journal.path))
    }

    private fun intent(value: String = "record-only-test"): ByteArray = OracleJson.canonicalBytes(
        JsonObject(mapOf("testIntent" to JsonPrimitive(value))),
    )

    private fun evidence(
        intent: ByteArray,
        operationId: String = OPERATION_ID,
        requestSha256: String = OracleArtifacts.sha256(intent),
    ): FullTreeDiskScratchEvidence = FullTreeDiskScratchEvidence.create(
        operation = FullTreeDiskScratchOperation(operationId, requestSha256, "cc1-fresh-control", "b".repeat(64)),
        policy = FullTreeDiskScratchPolicy(1024, 8192, 128, 256),
        mountPathSha256 = "c".repeat(64),
        mount = FullTreeDiskMount(
            42, 36, "7:1", Path.of("/"), Path.of("/record-only-test/scratch"),
            listOf("noatime", "nodev", "noexec", "nosuid", "rw"), "ext4",
        ),
        mountIdentity = diskIdentity(2),
        capacity = LinuxFilesystemCapacity(4096, 8192, 4096, 256, 200, 255, false),
        leaseIdentity = diskIdentity(12),
        leaseRecordSha256 = "d".repeat(64),
    )

    private fun diskIdentity(inode: Long): LinuxFileIdentity = LinuxFileIdentity(
        LinuxFileKey(7, inode), 0x41c0, 1000, 1000, 2, 42,
        isRegularFile = false, isDirectory = true, isSymbolicLink = false,
    )

    private fun definition(output: Path = Path.of("/record-only-test/run"), legacy: Boolean = false): ByteArray {
        val bundle = Path.of("/record-only-test/bundle")
        val runtime = GccBundledGhidraRuntime(bundle, listOf(
            GccBundledGhidraClassPathEntry(bundle.resolve("decomp-ghidra-bridge.jar"), 32, DEPLOYMENT_SHA256),
            GccBundledGhidraClassPathEntry(
                bundle.resolve("ghidra_${BundledGhidra.VERSION}_PUBLIC/Ghidra/Framework/Core/lib/Core.jar"),
                64, DEPLOYMENT_SHA256,
            ),
        ))
        val roles = if (legacy) GCC_LEGACY_CONTAINMENT_ARTIFACT_ROLES else GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES
        val artifacts = roles.map { role ->
            GccCompilerEngineContainmentArtifactIdentity(
                role,
                when (role) {
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_BRIDGE_JAR -> bundle.resolve("decomp-ghidra-bridge.jar")
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_RUNTIME_MANIFEST -> bundle.resolve("bundle.sha256")
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_EXPORT_GUARD -> bundle.resolve("scripts/RunBundledExports.class")
                    GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> Path.of("/record-only-test/ExportProgramModel.java")
                    else -> Path.of("/record-only-test/${role.wireName}")
                },
                32,
                if (role == GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE) BundledGhidra.ARCHIVE_SHA256 else DEPLOYMENT_SHA256,
            )
        }
        val state = GccCompilerEngineAnalysisStateIdentity(
            GccCompilerEngineAnalysisStateMode.FRESH_EMPTY, output.resolve("state"), null, 0, 0,
        )
        val lease = GccCompilerEngineOutputLeaseIdentity(output, 7, 99, 42, 1000, 1000, 0x1c0, 1024, 8192, 128, 256)
        val byRole = artifacts.associateBy { it.role }
        val command = if (legacy) listOf(
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS).path.toString(),
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
            byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE).path.toString(),
            state.path.toString(), lease.path.toString(),
        ) else runtime.command(artifacts, state, lease)
        return GccCompilerEngineContainmentContract.assessDefinition(GccCompilerEngineContainmentRequest(
            engineId = "cc1",
            runKind = GccCompilerEngineContainmentRunKind.FRESH_CONTROL,
            artifacts = artifacts,
            analysisState = state,
            command = command,
            environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
            outputLease = lease,
            budgets = GccCompilerEngineContainmentBudgets(60_000, 1024L * 1024 * 1024, 64),
            bundledRuntime = if (legacy) null else runtime,
        )).canonicalBytes
    }

    private fun immutableFile(path: Path, bytes: ByteArray) {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private fun names(path: Path): Set<String> = Files.list(path).use { entries ->
        entries.map { it.fileName.toString() }.toList().toSet()
    }

    private fun permissions(path: Path): String = PosixFilePermissions.toString(Files.getPosixFilePermissions(path))

    private fun operationName(operationId: String = OPERATION_ID): String = ".gcc-bundled-operation-$operationId"

    private inline fun withJournalRoot(action: (Path) -> Unit) {
        val container = createTempDirectory("gcc-bundled-journal-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(container, PosixFilePermissions.fromString("rwx------"))
        val root = Files.createDirectory(container.resolve("root"))
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        try {
            action(root)
        } finally {
            if (Files.exists(container, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(container).use { entries -> entries.sorted(Comparator.reverseOrder()).toList() }
                    .forEach(Files::deleteIfExists)
            }
        }
    }

    private companion object {
        val OPERATION_ID = "1".repeat(64)
        val SECOND_OPERATION_ID = "2".repeat(64)
        val DEPLOYMENT_SHA256 = "a".repeat(64)
    }
}
