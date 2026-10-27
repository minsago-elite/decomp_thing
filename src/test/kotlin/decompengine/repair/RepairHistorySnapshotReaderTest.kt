package decompengine.repair

import decompengine.acp.LinuxDescriptor
import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.project.sha256
import decompengine.validation.ProcessInput
import java.lang.reflect.InvocationTargetException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.io.path.writeBytes
import kotlin.io.path.writeText
import kotlin.test.*

/** Source-authored reader controls; not host/native qualification or a universal ABA proof. */
class RepairHistorySnapshotReaderTest {
    private val budget = RepairResourceBudget()
    private val profile = DeclarativeRepairIndexProfile("reader-fixture",
        RepairIndexLayout(listOf("code.c"), listOf("code.c")))

    @Test
    fun realProducerAndBothFacadesAgreeWithoutConstructingRecoveryInReader() {
        val root = producer()
        val revisions = root.resolve("reports/repair-revisions")
        val graph = revisions.resolve("graph.json").readBytes()
        val binding = revisions.resolve("recovery-binding.json").readBytes()
        val capturedBudget = recordedRepairHistoryReadBudget(graph)
        var scanned = false
        val streamed = recordedRepairHistorySnapshot(graph, binding, capturedBudget) { scanned = true; error("under-cap scan") }
        val listed = recordedRepairHistorySnapshot(graph, binding, capturedBudget)
        assertFalse(scanned)
        val result = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
        val read = assertNotNull(result.snapshot)
        assertEquals(listed.graphSha256, streamed.graphSha256)
        assertEquals(listed.graphSha256, read.graphSha256)
        assertEquals(listed.publishedHead, read.publishedHead)
        assertEquals(RepairRollbackState.RESTORED_VERIFIED, read.attempts.last().rollback?.state)
        assertEquals("base", root.resolve("code.c").readText())
    }

    @Test
    fun underCapDoesNotEnumerateEvenWhenDirectoryExceedsItsEntryBudget() {
        val selected = budget.copy(maximumStateDirectoryEntries = 16)
        val root = producer(selected)
        val revisions = root.resolve("reports/repair-revisions")
        // These unrelated entries alone exceed D. The invalid declared body must never be read.
        repeat(17) { revisions.resolve("unrelated-$it").writeText("x") }
        revisions.resolve("legacy-graph-" + "0".repeat(64) + ".json").writeText("not canonical")
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(root).status)
    }

    @Test
    fun missingAndTruncatedMetadataAreDistinctAndNeverCreateDirectories() {
        val root = root()
        assertEquals(RepairHistoryReadStatus.NOT_RECORDED, readProjectRecordedRepairHistory(root).status)
        assertFalse(Files.exists(root.resolve("reports")))
        Files.createDirectories(root.resolve("reports/repair-revisions"))
        val revisions = root.resolve("reports/repair-revisions")
        assertEquals(RepairHistoryReadStatus.NOT_RECORDED, readProjectRecordedRepairHistory(root).status)
        revisions.resolve("recovery-binding.json").writeText("private malformed binding")
        unavailable(readProjectRecordedRepairHistory(root))
        revisions.resolve("graph.json").writeBytes(byteArrayOf())
        unavailable(readProjectRecordedRepairHistory(root))
    }

    @Test
    fun exactSizeCaptureAndBorrowedDescriptorOwnershipAreReal() {
        withRevisions { revisions, path ->
            val bytes = ByteArray(16_384) { (it % 127).toByte() }
            path.resolve("graph.json").writeBytes(bytes)
            val session = session(revisions)
            val read = call(session, "capture", "graph.json", bytes.size.toLong()) as StableRegularFile
            assertContentEquals(bytes, read.bytes)
            assertEquals(sha256(bytes), read.sha256)
            assertEquals(revisions.identity, LinuxFilesystemSyscalls.identity(revisions.fd))
            val result = readRecordedRepairHistorySnapshot(revisions, {}, {})
            unavailable(result) // Payload is not a canonical graph; borrowing still must not close it.
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
    }

    @Test
    fun specialSymlinkOversizeLinkAndWriteAdmissionRefuseBeforePayloadRead() {
        val path = Files.createDirectory(root().resolve("fixture-revisions"))
        val target = path.resolve("target").also { it.writeText("abc") }
        Files.createSymbolicLink(path.resolve("symbolic"), target.fileName)
        Files.createDirectory(path.resolve("directory"))
        Files.createLink(path.resolve("linked"), target)
        val writable = path.resolve("writable").also { it.writeText("abc") }
        Files.setPosixFilePermissions(writable, java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw----"))
        path.resolve("oversized").writeText("abcd")
        path.resolve("ordinary").writeText("abc")
        // Capture the directory identity only after fixture creation changes its link count.
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            assertEquals(revisions.identity, LinuxFilesystemSyscalls.identity(revisions.fd))
            val ordinary = session(revisions)
            val captured = call(ordinary, "capture", "ordinary", 3L) as StableRegularFile
            assertContentEquals("abc".toByteArray(), captured.bytes)
            assertEquals(sha256("abc".toByteArray()), captured.sha256)
            assertEquals(3L, field(field(ordinary, "ledger")!!, "used"))
            assertEquals(revisions.identity, LinuxFilesystemSyscalls.identity(revisions.fd))
            for ((name, maximum) in listOf("symbolic" to 3L, "directory" to 3L, "linked" to 3L, "writable" to 3L)) {
                var checks = 0
                assertFails { call(session(revisions, cancel = { checks++ }), "capture", name, maximum) }
                assertEquals(2, checks, "no stable-reader body entry for $name")
            }
            var checks = 0
            assertFails { call(session(revisions, cancel = { checks++ }), "capture", "oversized", 3L) }
            assertEquals(2, checks)
        }
    }

    @Test
    fun admittedGrowthTruncationAndReplacementRefuseWithNoPartialResult() {
        for (mutation in listOf("grow", "truncate", "replace")) withRevisions { revisions, path ->
            val leaf = path.resolve("graph.json").also { it.writeText("abc") }
            var checks = 0
            val current = session(revisions, cancel = {
                checks++
                if (checks == 3) when (mutation) {
                    "grow" -> leaf.writeText("abcd")
                    "truncate" -> leaf.writeText("ab")
                    else -> { Files.delete(leaf); leaf.writeText("abc") }
                }
            })
            assertFails { call(current, "capture", "graph.json", 3L) }
            assertTrue(checks >= 3)
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
    }

    @Test
    fun finalGraphAndBindingReplacementSameBytesNewInodeRefuse() {
        for (selected in listOf("graph.json" to 6, "recovery-binding.json" to 8)) {
            val root = producer()
            val path = root.resolve("reports/repair-revisions")
            LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
                var validations = 0
                val result = readRecordedRepairHistorySnapshot(revisions, {
                    validations++
                    if (validations == selected.second) {
                        val leaf = path.resolve(selected.first)
                        val bytes = leaf.readBytes()
                        // Retain old inode so this is genuinely a different identity, never allocator reuse.
                        Files.move(leaf, path.resolve("retained-old"))
                        leaf.writeBytes(bytes)
                    }
                }, {})
                unavailable(result)
                assertTrue(validations >= selected.second)
            }
        }
    }

    @Test
    fun heldAndNamedDirectoryReplacementRefusesThroughActualProjectAdapter() {
        val root = producer()
        val reports = root.resolve("reports")
        var replaced = false
        var checks = 0
        val result = readProjectRecordedRepairHistory(root) {
            // The first seven cancellation calls admit/revalidate all three held directories.
            if (++checks == 8) {
                replaced = true
                Files.move(reports, root.resolve("retained-reports"))
                Files.createDirectory(reports)
            }
        }
        assertTrue(replaced)
        unavailable(result) // Held old revisions must not grant credit through the replaced parent.
        assertTrue(Files.exists(root.resolve("retained-reports/repair-revisions/graph.json")))
    }

    @Test
    fun cancellationAndForeignPrivateFailuresBecomeOnlyClosedUnavailable() {
        val root = producer()
        val failure = IllegalStateException("PRIVATE-path-token")
        var checks = 0
        unavailable(readProjectRecordedRepairHistory(root) { if (++checks == 12) throw failure })
        assertTrue(checks >= 12)
        LinuxFilesystemSyscalls.openRoot(root.resolve("reports/repair-revisions")).use { revisions ->
            unavailable(readRecordedRepairHistorySnapshot(revisions, { throw failure }, {}))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
    }

    @Test
    fun actualEnumerationCountsAllEntriesBeforeFilteringAndRefusesDuplicates() {
        withRevisions { revisions, path ->
            val selected = budget.copy(maximumRevisionNodes = 2, maximumStateDirectoryEntries = 2)
            val limit = repairRevisionDirectoryEntryLimit(selected)
            val initial = listOf("not-selected", "graph.json", "recovery-binding.json")
            val fillers = (0 until limit - initial.size).map { "irrelevant-$it" }
            for (name in initial + fillers) path.resolve(name).writeText("x")
            val session = session(revisions)
            val names = call(session, "names", selected) as List<*>
            assertEquals((initial + fillers).sorted(), names)
            assertEquals(names, top("boundedHistoryNames", initial + fillers, limit))
            assertFails { top("boundedHistoryNames", initial + fillers, limit - 1) }
            path.resolve("all-name-overflow").writeText("x")
            assertFails { call(session, "names", selected) }
            Files.delete(path.resolve("all-name-overflow"))
            val candidates = (0..2).map { "legacy-graph-" + it.toString().padStart(64, '0') + ".json" }
            for (index in 0..1) {
                Files.delete(path.resolve(fillers[index]))
                path.resolve(candidates[index]).writeText("not read by names")
            }
            val admitted = call(session, "names", selected) as List<*>
            assertEquals(limit, admitted.size)
            assertTrue(candidates.take(2).all { it in admitted })
            assertTrue("not-selected" in admitted)
            Files.delete(path.resolve(fillers[2]))
            path.resolve(candidates[2]).writeText("not read by names")
            assertEquals("recorded history declared graph candidate count exceeds its entry budget",
                assertFailsWith<IllegalArgumentException> { call(session, "names", selected) }.message)
            assertEquals(0L, field(field(session, "ledger")!!, "used"))
        }
        assertFails { top("boundedHistoryNames", listOf("same", "same"), 2) }
        for (bad in listOf("", ".", "..", "a/b", "nul" + '\u0000')) {
            assertFails { top("boundedHistoryNames", listOf(bad), 1) }
        }
        assertEquals(listOf("a", "z"), top("boundedHistoryNames", listOf("z", "a"), 2))
    }

    @Test
    fun checkedLedgerRefusesBeforeExcessWorkWithoutResettingCredit() {
        val ledger = construct("HistoryReadLedger")
        call(ledger, "reserve", 1L)
        assertFailsWith<ArithmeticException> { call(ledger, "reserve", Long.MAX_VALUE) }
        assertEquals(1L, field(ledger, "used"))
        assertFails { call(ledger, "reserve", 0L) }
        call(ledger, "bind", 100L, budget)
        val expected = 200L + 2 * budget.maximumGraphBytes + budget.maximumProjectionBytes + 2 * budget.maximumIndexEvidenceBytes
        assertEquals(expected, field(ledger, "limit"))
        assertFails { call(ledger, "reserve", expected) }
        assertEquals(1L, field(ledger, "used"))
    }

    @Test
    fun genuineMigrationStreamsOriginalBodiesTwiceAndReleasesBeforeNextCapture() {
        val root = migrated()
        val path = root.resolve("reports/repair-revisions")
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        val selectedBudget = recordedRepairHistoryReadBudget(graph)
        assertTrue(graph.size > selectedBudget.maximumGraphBytes)
        // A valid nonjoining pre-marker schema2 input is still consumed/revalidated, never skipped.
        val unrelatedRoot = root()
        ModuleRevisionGraph.open(unrelatedRoot, profile).close()
        val unrelated = unrelatedRoot.resolve("reports/repair-revisions/graph.json").readBytes()
        assertTrue(unrelated.size <= selectedBudget.maximumGraphBytes)
        path.resolve("legacy-graph-" + sha256(unrelated) + ".json").writeBytes(unrelated)
        val declaredBytes = Files.newDirectoryStream(path, "legacy-graph-*.json").use { entries -> entries.sumOf { Files.size(it) } }
        assertTrue(declaredBytes > 0)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val session = session(revisions)
            val result = call(session, "read") as RepairHistoryReadResult
            assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
            assertEquals(true, result.snapshot?.pending?.rollback?.legacyPendingStateUnknown)
            val ledger = field(session, "ledger")!!
            assertEquals(2L * graph.size + 2L * binding.size + 2L * declaredBytes, field(ledger, "used"))
        }
    }

    @Test
    fun invalidBindingStopsBeforeDeclarationsAndFinalNamespaceChangeRefuses() {
        val root = migrated()
        val path = root.resolve("reports/repair-revisions")
        val binding = path.resolve("recovery-binding.json").readBytes()
        // A different actual producer's canonical binding is syntactically valid but cannot join G1.
        val other = producer().resolve("reports/repair-revisions/recovery-binding.json").readBytes()
        path.resolve("recovery-binding.json").writeBytes(other)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val session = session(revisions)
            assertFails { call(session, "read") }
            val graphSize = Files.size(path.resolve("graph.json"))
            assertEquals(graphSize + other.size, field(field(session, "ledger")!!, "used"))
        }
        path.resolve("recovery-binding.json").writeBytes(binding)
        // A separately retained old inode prevents allocator reuse from making this negative ambiguous.
        val declared = Files.newDirectoryStream(path, "legacy-graph-*.json").use { it.single() }
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            var checks = 0
            val result = readRecordedRepairHistorySnapshot(revisions, {
                if (++checks == 10) {
                    val bytes = declared.readBytes()
                    Files.move(declared, root.resolve("retained-declared-old"))
                    declared.writeBytes(bytes)
                }
            }, {})
            unavailable(result)
            assertTrue(checks >= 10)
        }
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            var checks = 0
            val result = readRecordedRepairHistorySnapshot(revisions, {
                checks++
                // check7 is the first enumeration's post-check, after its captured name list.
                if (checks == 7) path.resolve("later-namespace-entry").writeText("private")
            }, {})
            unavailable(result)
            assertTrue(checks >= 7)
        }
    }

    @Test
    fun closeOwnershipPreservesExactPrimaryAndAttemptsCleanupOnce() {
        val primary = IllegalStateException("primary")
        val cleanup = IllegalStateException("cleanup")
        var closes = 0
        val resource = AutoCloseable { closes++; throw cleanup }
        val thrown = assertFails { top("withHistoryOwned", resource, { _: AutoCloseable -> throw primary }) }
        assertSame(primary, thrown)
        assertEquals(1, closes)
        closes = 0
        assertSame(cleanup, assertFails { top("withHistoryOwned", resource, { _: AutoCloseable -> "otherwise-success" }) })
        assertEquals(1, closes)
        var returned = false
        closes = 0
        val positive = AutoCloseable { closes++ }
        assertEquals("result", top("withHistoryOwned", positive, { _: AutoCloseable -> returned = true; "result" }))
        assertTrue(returned); assertEquals(1, closes)
    }

    @Test
    fun failedChainAdmissionClosesEveryAcquiredDescriptorAndDoesNotCreateMissingParts() {
        val root = root()
        Files.createDirectory(root.resolve("reports"))
        root.resolve("reports/not-a-directory").writeText("x")
        val chain = construct("HistoryDirectoryChain", root, listOf("reports", "not-a-directory"), {}, { _: Long -> })
        assertFails { call(chain, "open") }
        @Suppress("UNCHECKED_CAST")
        val acquired = (field(chain, "held") as List<LinuxDescriptor>).toList()
        assertEquals(2, acquired.size)
        call(chain, "close"); call(chain, "close")
        acquired.forEach { descriptor -> assertFailsWith<IllegalStateException> { descriptor.whileOpen { it } } }
        assertTrue((field(chain, "held") as List<*>).isEmpty())
        val absent = root.resolve("reports/never-created")
        assertFalse(Files.exists(absent))
        unavailable(readProjectRecordedRepairHistory(root) { throw IllegalStateException("cancel") })
        assertFalse(Files.exists(absent))
    }


    @Test
    fun fixedReaderInspectsMissingEmptyAndActualProducerHistoryButCoreBorrowDoesNot() {
        val root = producer()
        val reports = root.resolve("reports")
        val history = reports.resolve("repair_history.json")
        Files.deleteIfExists(history)
        val missing = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryReadStatus.RECORDED, missing.status)
        assertEquals(RepairHistoryProjectionStatus.MISSING, missing.projection.status)
        history.writeBytes(byteArrayOf())
        val empty = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryReadStatus.RECORDED, empty.status)
        assertEquals(RepairHistoryProjectionStatus.EMPTY, empty.projection.status)
        assertEquals(0L, empty.projection.admittedBytes)
        ModuleRevisionGraph.open(root, profile).use { it.synchronizeRepairHistory() } // Producer only, before reader.
        val beforeSource = root.resolve("code.c").readBytes()
        val beforeGraph = reports.resolve("repair-revisions/graph.json").readBytes()
        val beforeBinding = reports.resolve("repair-revisions/recovery-binding.json").readBytes()
        val beforeHistory = history.readBytes()
        val result = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION, result.projection.status)
        assertEquals(sha256(beforeHistory), result.projection.capturedSha256)
        assertEquals(missing.snapshot?.attempts?.last()?.rollback, result.snapshot?.attempts?.last()?.rollback)
        LinuxFilesystemSyscalls.openRoot(reports.resolve("repair-revisions")).use { revisions ->
            val core = readRecordedRepairHistorySnapshot(revisions, {}, {})
            assertEquals(RepairHistoryReadStatus.RECORDED, core.status)
            assertEquals(RepairHistoryProjectionStatus.NOT_INSPECTED, core.projection.status)
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        assertContentEquals(beforeSource, root.resolve("code.c").readBytes())
        assertContentEquals(beforeGraph, reports.resolve("repair-revisions/graph.json").readBytes())
        assertContentEquals(beforeBinding, reports.resolve("repair-revisions/recovery-binding.json").readBytes())
        assertContentEquals(beforeHistory, history.readBytes())
    }

    @Test
    fun historyAdmissionCountsActualSizeOnceAndNeverRefundsOrRetriesFailedBody() {
        val selected = budget.copy(maximumProjectionBytes = 1024)
        val root = root()
        ModuleRevisionGraph.open(root, profile, selected).close()
        val reports = root.resolve("reports")
        val path = reports.resolve("repair-revisions")
        val history = reports.resolve("repair_history.json")
        val canonical = Files.size(path.resolve("graph.json")) + Files.size(path.resolve("recovery-binding.json"))
        LinuxFilesystemSyscalls.openRoot(reports).use { parent ->
            LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
                history.writeBytes(ByteArray(1024) { 'x'.code.toByte() })
                val exact = session(revisions)
                val result = call(exact, "readWithHistory", parent) as RepairHistoryReadResult
                assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
                assertEquals(RepairHistoryProjectionStatus.INVALID, result.projection.status)
                assertEquals(1024L, result.projection.admittedBytes)
                assertEquals(2L * canonical + 1024L, field(field(exact, "ledger")!!, "used"))
                history.writeBytes(ByteArray(1025))
                val oversized = session(revisions)
                val refused = call(oversized, "readWithHistory", parent) as RepairHistoryReadResult
                assertEquals(RepairHistoryReadStatus.RECORDED, refused.status)
                assertEquals(RepairHistoryProjectionStatus.UNAVAILABLE, refused.projection.status)
                assertEquals(2L * canonical, field(field(oversized, "ledger")!!, "used"))
                for (mutation in listOf("growth", "short", "replacement")) {
                    history.writeText("abc")
                    var checks = 0
                    val changed = session(revisions, cancel = {
                        if (++checks == 3) when (mutation) {
                            "growth" -> history.writeText("abcd")
                            "short" -> history.writeText("ab")
                            else -> { Files.move(history, reports.resolve("retained-old-history")); history.writeText("abc") }
                        }
                    })
                    val diagnostic = call(changed, "inspectHistory", parent, path.resolve("graph.json").readBytes(), selected) as RepairHistoryProjectionDiagnostic
                    assertTrue(diagnostic.status in setOf(RepairHistoryProjectionStatus.UNAVAILABLE, RepairHistoryProjectionStatus.CHANGED_DURING_CAPTURE), mutation)
                    assertEquals(3L, field(field(changed, "ledger")!!, "used"))
                    assertTrue(checks >= 3)
                }
                assertEquals(parent.fd, parent.whileOpen { it }); assertEquals(revisions.fd, revisions.whileOpen { it })
            }
        }
    }

    @Test
    fun historySpecialLinkWritableAndMalformedLeavesNeverWashCanonicalRestoration() {
        for (kind in listOf("directory", "symlink", "hardlink", "writable", "corrupt")) {
            val root = producer()
            val reports = root.resolve("reports")
            val history = reports.resolve("repair_history.json")
            Files.deleteIfExists(history)
            when (kind) {
                "directory" -> Files.createDirectory(history)
                "symlink" -> Files.createSymbolicLink(history, Path.of("repair-revisions/graph.json"))
                "hardlink" -> Files.createLink(history, root.resolve("code.c"))
                "writable" -> { history.writeText("private"); Files.setPosixFilePermissions(history,
                    java.nio.file.attribute.PosixFilePermissions.fromString("rw-rw----")) }
                else -> history.writeText("PRIVATE-not-json")
            }
            val result = readProjectRecordedRepairHistory(root)
            assertEquals(RepairHistoryReadStatus.RECORDED, result.status, kind)
            assertEquals(RepairRollbackState.RESTORED_VERIFIED, result.snapshot?.attempts?.last()?.rollback?.state, kind)
            assertEquals(if (kind == "corrupt") RepairHistoryProjectionStatus.INVALID else RepairHistoryProjectionStatus.UNAVAILABLE,
                result.projection.status, kind)
            assertFalse(result.projection.toString().contains("PRIVATE-"))
            assertEquals("base", root.resolve("code.c").readText())
        }
    }

    @Test
    fun historyCancellationPreservesPrimaryAndFinalCanonicalChangeDiscardsLocalMatch() {
        val root = producer()
        ModuleRevisionGraph.open(root, profile).use { it.synchronizeRepairHistory() }
        val reports = root.resolve("reports")
        val path = reports.resolve("repair-revisions")
        val primary = IllegalStateException("PRIVATE-cancel")
        LinuxFilesystemSyscalls.openRoot(reports).use { parent ->
            LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
                var checks = 0
                val cancelled = session(revisions, cancel = { if (++checks == 3) throw primary })
                assertSame(primary, assertFails { call(cancelled, "inspectHistory", parent, path.resolve("graph.json").readBytes(), budget) })
                assertEquals(parent.fd, parent.whileOpen { it }); assertEquals(revisions.fd, revisions.whileOpen { it })
                var checkpoints = 0
                var changed = false
                val read = session(revisions, revalidate = {
                    // Existing session checks: initial; G pre/post; B pre/post; H pre/post; G2 pre.
                    if (++checkpoints == 8) {
                        val graph = path.resolve("graph.json")
                        val bytes = graph.readBytes()
                        Files.move(graph, root.resolve("retained-before-final-graph"))
                        graph.writeBytes(bytes)
                        changed = true
                    }
                })
                assertFails { call(read, "readWithHistory", parent) }
                assertTrue(changed)
                assertTrue(checkpoints >= 8)
            }
        }
        unavailable(readProjectRecordedRepairHistory(root) { throw primary })
    }

    @Test
    fun migrationStillStreamsTwoDeclaredPassesWithOnlyOneDiagnosticHistoryCredit() {
        val root = migrated()
        val reports = root.resolve("reports")
        val path = reports.resolve("repair-revisions")
        val history = reports.resolve("repair_history.json").also { it.writeText("PRIVATE-corrupt") }
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        val declaredBytes = Files.newDirectoryStream(path, "legacy-graph-*.json").use { stream -> stream.sumOf { Files.size(it) } }
        LinuxFilesystemSyscalls.openRoot(reports).use { parent ->
            LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
                val session = session(revisions)
                val result = call(session, "readWithHistory", parent) as RepairHistoryReadResult
                assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
                assertEquals(true, result.snapshot?.pending?.rollback?.legacyPendingStateUnknown)
                assertEquals(RepairHistoryProjectionStatus.INVALID, result.projection.status)
                assertEquals(2L * graph.size + 2L * binding.size + 2L * declaredBytes + Files.size(history),
                    field(field(session, "ledger")!!, "used"))
            }
        }
    }


    @Test
    fun actualHistoryCatchRejectsAuthorizedNamedAndNestedCloseOnlyFailures() {
        for ((failAuthorized, failNamed) in listOf(true to false, false to true, true to true)) {
            val authorizedFailure = IllegalStateException("PRIVATE-authorized-close")
            val namedFailure = IllegalStateException("PRIVATE-named-close")
            val closed = mutableListOf<String>()
            val authorized = AutoCloseable { closed += "authorized"; if (failAuthorized) throw authorizedFailure }
            val named = AutoCloseable { closed += "named"; if (failNamed) throw namedFailure }
            val transaction = construct("HistoryProjectionCapture", {})
            var returned: RepairHistoryProjectionDiagnostic? = null
            var reachedMatch = false
            val failure = assertFails {
                returned = call(transaction, "inspect", {
                    call(transaction, "owned", authorized, { _: AutoCloseable ->
                        call(transaction, "owned", named, { _: AutoCloseable ->
                            reachedMatch = true
                            RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION)
                        }) as RepairHistoryProjectionDiagnostic
                    }) as RepairHistoryProjectionDiagnostic
                }) as RepairHistoryProjectionDiagnostic
            }
            assertTrue(reachedMatch) // A computed local match must NOT survive observable cleanup uncertainty.
            assertNull(returned)
            assertSame(if (failNamed) namedFailure else authorizedFailure, failure)
            assertEquals(listOf("named", "authorized"), closed)
            assertEquals(true, field(transaction, "cleanupFailed"))
        }
    }

    @Test
    fun actualHistoryCatchKeepsBodyPrimaryWhileEachAcquiredCloseIsAttemptedOnce() {
        for ((failAuthorized, failNamed) in listOf(true to false, false to true, true to true)) {
            val primary = IllegalStateException("PRIVATE-malformed-body")
            val authorizedFailure = IllegalStateException("PRIVATE-authorized-close")
            val namedFailure = IllegalStateException("PRIVATE-named-close")
            val closed = mutableListOf<String>()
            val authorized = AutoCloseable { closed += "authorized"; if (failAuthorized) throw authorizedFailure }
            val named = AutoCloseable { closed += "named"; if (failNamed) throw namedFailure }
            val transaction = construct("HistoryProjectionCapture", {})
            var returned: RepairHistoryProjectionDiagnostic? = null
            val failure = assertFails {
                returned = call(transaction, "inspect", {
                    call(transaction, "owned", authorized, { _: AutoCloseable ->
                        call(transaction, "owned", named, { _: AutoCloseable -> throw primary }) as RepairHistoryProjectionDiagnostic
                    }) as RepairHistoryProjectionDiagnostic
                }) as RepairHistoryProjectionDiagnostic
            }
            assertSame(primary, failure)
            assertNull(returned)
            assertEquals(listOf("named", "authorized"), closed)
            assertEquals(true, field(transaction, "cleanupFailed"))
            assertTrue(primary.suppressed.isEmpty()) // No foreign cleanup graph attached or used as authority.
        }
    }

    @Test
    fun actualHistoryCatchKeepsLatchedCancellationBeforeWrappedBodyAndDualCloseFailures() {
        val primary = IllegalStateException("PRIVATE-cancel")
        val wrapper = IllegalStateException("PRIVATE-lower-reader-wrapper")
        val transaction = construct("HistoryProjectionCapture", { throw primary })
        val closed = mutableListOf<String>()
        val authorized = AutoCloseable { closed += "authorized"; throw IllegalStateException("PRIVATE-authorized-close") }
        val named = AutoCloseable { closed += "named"; throw IllegalStateException("PRIVATE-named-close") }
        var returned: RepairHistoryProjectionDiagnostic? = null
        val failure = assertFails {
            returned = call(transaction, "inspect", {
                call(transaction, "owned", authorized, { _: AutoCloseable ->
                    call(transaction, "owned", named, { _: AutoCloseable ->
                        assertSame(primary, assertFails { call(transaction, "checkCancellation") })
                        throw wrapper
                    }) as RepairHistoryProjectionDiagnostic
                }) as RepairHistoryProjectionDiagnostic
            }) as RepairHistoryProjectionDiagnostic
        }
        assertSame(primary, failure)
        assertNull(returned)
        assertEquals(listOf("named", "authorized"), closed)
        assertSame(primary, field(transaction, "cancelled"))
        assertEquals(true, field(transaction, "cleanupFailed"))
    }

    @Test
    fun actualHistoryCatchDowngradesOnlyCleanLeafFailureAndRetainsCleanPositive() {
        for (malformed in listOf(false, true)) {
            val closed = mutableListOf<String>()
            val authorized = AutoCloseable { closed += "authorized" }
            val named = AutoCloseable { closed += "named" }
            val transaction = construct("HistoryProjectionCapture", {})
            val diagnostic = call(transaction, "inspect", {
                call(transaction, "owned", authorized, { _: AutoCloseable ->
                    call(transaction, "owned", named, { _: AutoCloseable ->
                        if (malformed) throw IllegalArgumentException("PRIVATE-malformed-history")
                        RepairHistoryProjectionDiagnostic(RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION)
                    }) as RepairHistoryProjectionDiagnostic
                }) as RepairHistoryProjectionDiagnostic
            }) as RepairHistoryProjectionDiagnostic
            assertEquals(if (malformed) RepairHistoryProjectionStatus.UNAVAILABLE else RepairHistoryProjectionStatus.MATCHED_CAPTURED_PROJECTION,
                diagnostic.status)
            assertEquals(listOf("named", "authorized"), closed)
            assertEquals(false, field(transaction, "cleanupFailed"))
            assertNull(field(transaction, "cancelled"))
            assertFalse(diagnostic.toString().contains("PRIVATE-"))
        }
        // Existing actual filesystem malformed-H control still exercises clean diagnostic -> RECORDED.
        val root = producer()
        root.resolve("reports/repair_history.json").writeText("PRIVATE-malformed-history")
        val result = readProjectRecordedRepairHistory(root)
        assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
        assertEquals(RepairHistoryProjectionStatus.INVALID, result.projection.status)
        assertEquals(RepairRollbackState.RESTORED_VERIFIED, result.snapshot?.attempts?.last()?.rollback?.state)
    }


    @Test
    fun tinyDeclarationBudgetRetainsFullNamespaceAndBothPassesBeforeHistoryPublication() {
        val selected = budget.copy(maximumRevisionNodes = 32, maximumStateDirectoryEntries = 2, maximumGraphBytes = 16 * 1024)
        val root = roleBoundMigration(selected)
        val reports = root.resolve("reports")
        val revisionsPath = reports.resolve("repair-revisions")
        val graphBytes = revisionsPath.resolve("graph.json").readBytes()
        val bindingBytes = revisionsPath.resolve("recovery-binding.json").readBytes()
        assertTrue(graphBytes.size.toLong() > selected.maximumGraphBytes)
        // A second complete nonjoining schema2 producer input is still consumed under the SAME D.
        val other = this.root()
        ModuleRevisionGraph.open(other, profile).close()
        val unrelated = other.resolve("reports/repair-revisions/graph.json").readBytes()
        revisionsPath.resolve("legacy-graph-" + sha256(unrelated) + ".json").writeBytes(unrelated)
        val declared = Files.newDirectoryStream(revisionsPath, "legacy-graph-*.json").use { it.toList() }
        assertEquals(2, declared.size)
        val declaredBytes = declared.sumOf { Files.size(it) }
        val history = reports.resolve("repair_history.json").also { it.writeText("PRIVATE-corrupt") }
        val limit = repairRevisionDirectoryEntryLimit(selected)
        val present = Files.list(revisionsPath).use { it.count().toInt() }
        val fillers = (0 until limit - present).map { index ->
            revisionsPath.resolve("unrelated-$index").also { it.writeText("not a declared body") }
        }
        assertEquals(limit.toLong(), Files.list(revisionsPath).use { it.count() })
        LinuxFilesystemSyscalls.openRoot(reports).use { parent ->
            LinuxFilesystemSyscalls.openRoot(revisionsPath).use { revisions ->
                val positive = session(revisions)
                val result = call(positive, "readWithHistory", parent) as RepairHistoryReadResult
                assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
                assertEquals(true, result.snapshot?.pending?.rollback?.legacyPendingStateUnknown)
                assertEquals(RepairHistoryProjectionStatus.INVALID, result.projection.status)
                assertEquals(2L * graphBytes.size + 2L * bindingBytes.size + 2L * declaredBytes + Files.size(history),
                    field(field(positive, "ledger")!!, "used"))
                // Keep total at T: the third candidate alone must refuse BEFORE first declared body.
                Files.delete(fillers.first())
                val third = revisionsPath.resolve("legacy-graph-" + "0".repeat(64) + ".json")
                Files.createSymbolicLink(third, declared.first().fileName)
                val candidates = session(revisions)
                assertEquals("recorded history declared graph candidate count exceeds its entry budget",
                    assertFailsWith<IllegalArgumentException> { call(candidates, "names", selected) }.message)
                assertEquals(0L, field(field(candidates, "ledger")!!, "used"))
                val refusal = assertFailsWith<RepairHistorySnapshotRefusal> { call(candidates, "readWithHistory", parent) }
                assertEquals("Recorded repair metadata is invalid or exceeds its bound.", refusal.message)
                assertNull(refusal.cause)
                assertTrue(refusal.suppressed.isEmpty())
                assertTrue(refusal.stackTrace.isEmpty())
                assertEquals(graphBytes.size.toLong() + bindingBytes.size, field(field(candidates, "ledger")!!, "used"))
                unavailable(readProjectRecordedRepairHistory(root))
                Files.delete(third)
                fillers.first().writeText("not a declared body")
                // Unrelated T+1 also refuses before any declared body, independently of candidate D.
                val extra = revisionsPath.resolve("all-name-overflow").also { it.writeText("not selected") }
                val overflow = session(revisions)
                assertFails { call(overflow, "readWithHistory", parent) }
                assertEquals(graphBytes.size.toLong() + bindingBytes.size, field(field(overflow, "ledger")!!, "used"))
                unavailable(readProjectRecordedRepairHistory(root))
                Files.delete(extra)
                // Same T and same candidates, but a changed irrelevant name must fail final ALL-name comparison.
                var checks = 0
                var renamed = false
                val continuity = session(revisions, revalidate = {
                    if (++checks == 14) {
                        Files.move(fillers.last(), revisionsPath.resolve("renamed-unrelated"))
                        renamed = true
                    }
                })
                assertFails { call(continuity, "readWithHistory", parent) }
                assertTrue(renamed)
                assertEquals(graphBytes.size.toLong() + bindingBytes.size + declaredBytes + Files.size(history),
                    field(field(continuity, "ledger")!!, "used"))
                assertEquals(revisions.fd, revisions.whileOpen { it }); assertEquals(parent.fd, parent.whileOpen { it })
            }
        }
        assertContentEquals(graphBytes, revisionsPath.resolve("graph.json").readBytes())
        assertContentEquals(bindingBytes, revisionsPath.resolve("recovery-binding.json").readBytes())
        assertEquals("candidate", root.resolve("code.c").readText()) // Reader did NOT recover the pending source.
    }

    private fun roleBoundMigration(selected: RepairResourceBudget): Path {
        val root = root()
        ModuleRevisionGraph.open(root, profile, selected).use { graph ->
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("case", emptyList(), byteArrayOf())))
            val attempt = graph.beginAttempt(listOf("code.c"), RevisionRepairMetadata(1, "compile", "bounded private prompt",
                "ROLE_BOUND_PADDING", corpus.inputs.map { it.id }, null, corpus.sha256,
                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        val path = root.resolve("reports/repair-revisions/graph.json")
        val original = path.readText()
        val padding = (selected.maximumGraphBytes - original.toByteArray().size).toInt()
        assertTrue(padding > 0)
        path.writeText(original.replace("ROLE_BOUND_PADDING", "x".repeat("ROLE_BOUND_PADDING".length + padding)))
        assertEquals(selected.maximumGraphBytes, Files.size(path))
        assertFailsWith<MigrationCrash> {
            ModuleRevisionGraph.openForTesting(root, profile, selected, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync && point.scope == "revision-state" && point.name == "graph.json") throw MigrationCrash()
            }).close()
        }
        assertEquals(2L, Files.list(root.resolve("reports/repair-revisions/blobs")).use { it.count() })
        return root
    }

    @Test
    fun underCapLegacyOriginUsesBothDeclaredPassesAndTheExistingLedger() {
        val root = underCapLegacyPending()
        val path = root.resolve("reports/repair-revisions")
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        val selected = recordedRepairHistoryReadBudget(graph)
        assertTrue(graph.size.toLong() < selected.maximumGraphBytes)
        val declared = Files.newDirectoryStream(path, "legacy-graph-*.json").use { it.toList() }
        assertEquals(1, declared.size)
        val bytes = declared.sumOf { Files.size(it) }
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val capture = session(revisions)
            val read = call(capture, "read") as RepairHistoryReadResult
            assertEquals(RepairHistoryReadStatus.RECORDED, read.status)
            assertEquals(true, read.snapshot?.pending?.rollback?.legacyPendingStateUnknown)
            assertEquals(2L * graph.size + 2L * binding.size + 2L * bytes, field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        assertEquals("candidate", root.resolve("code.c").readText())
        val missing = root.resolve("held-original-declaration")
        Files.move(declared.single(), missing)
        unavailable(readProjectRecordedRepairHistory(root))
        Files.move(missing, declared.single())
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(root).status)
        assertContentEquals(graph, path.resolve("graph.json").readBytes())
    }

    @Test
    fun underCapLegacyFinalSourceAndGraphBindingContinuityAndCancellationRemainMandatory() {
        for (mutation in listOf("declaration", "graph.json", "recovery-binding.json", "cancel")) {
            val root = underCapLegacyPending()
            val path = root.resolve("reports/repair-revisions")
            val graph = path.resolve("graph.json").readBytes()
            val binding = path.resolve("recovery-binding.json").readBytes()
            val declared = Files.newDirectoryStream(path, "legacy-graph-*.json").use { it.single() }
            val firstPass = graph.size.toLong() + binding.size + Files.size(declared)
            LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
                var changed = false
                lateinit var capture: Any
                capture = session(revisions, revalidate = {
                    if (!changed && (field(field(capture, "ledger")!!, "used") as Long) >= firstPass) {
                        changed = true
                        if (mutation == "cancel") throw IllegalStateException("authored cancellation at existing check")
                        val selected = if (mutation == "declaration") declared else path.resolve(mutation)
                        val bytes = selected.readBytes()
                        Files.move(selected, root.resolve("held-old-" + selected.fileName))
                        selected.writeBytes(bytes) // Same bytes, retained different inode.
                    }
                })
                assertFails { call(capture, "read") }
                assertTrue(changed)
                assertEquals(revisions.fd, revisions.whileOpen { it })
            }
            assertContentEquals(graph, path.resolve("graph.json").readBytes())
            assertContentEquals(binding, path.resolve("recovery-binding.json").readBytes())
            assertEquals("candidate", root.resolve("code.c").readText())
        }
    }

    private fun underCapLegacyPending(): Path {
        val root = root()
        val selected = budget.copy(maximumGraphBytes = 16 * 1024)
        ModuleRevisionGraph.open(root, profile, selected).use { graph ->
            val attempt = graph.beginAttempt(listOf("code.c")) // Actual original schema2 producer.
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        assertFailsWith<MigrationCrash> {
            ModuleRevisionGraph.openForTesting(root, profile, selected, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json") throw MigrationCrash()
            }).close()
        }
        return root
    }

    @Test
    fun canonicalCaptureSizeConjoinsFixedPolicyAndOriginalRequestedBoundWithoutAllocation() {
        top("requireHistoryCanonicalCaptureSize", canonicalCaptureMaximum, canonicalCaptureMaximum)
        top("requireHistoryCanonicalCaptureSize", canonicalCaptureMaximum, 2_147_483_646L)
        top("requireHistoryCanonicalCaptureSize", 3L, 3L)
        for ((size, maximum) in listOf(-1L to canonicalCaptureMaximum, 0L to canonicalCaptureMaximum,
            canonicalCaptureMaximum + 1 to 2_147_483_646L, 4L to 3L)) {
            assertFailsWith<IllegalArgumentException> { top("requireHistoryCanonicalCaptureSize", size, maximum) }
        }
        var closes = 0
        var primary: Throwable? = null
        val cleanup = IllegalStateException("authored cap close failure")
        val owned = AutoCloseable { closes++; throw cleanup }
        val thrown = assertFails {
            top("withHistoryOwned", owned, { _: AutoCloseable ->
                try { top("requireHistoryCanonicalCaptureSize", canonicalCaptureMaximum + 1, 2_147_483_646L) }
                catch (failure: Throwable) { primary = failure; throw failure }
            })
        }
        assertIs<IllegalArgumentException>(thrown)
        assertSame(primary, thrown)
        assertEquals(1, closes)
        assertTrue(thrown.suppressed.isEmpty())
    }

    @Test
    fun sparseCanonicalGraphOverFixedCapRefusesBeforeBodyDebitAndWholeSnapshot() {
        val root = root()
        val path = Files.createDirectories(root.resolve("reports/repair-revisions"))
        sparseCanonicalLeaf(path.resolve("graph.json"), canonicalCaptureMaximum + 1)
        // All directory-creating setup precedes the owned directory identity snapshot.
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            assertCanonicalCapRefusalBeforeBody(revisions, "graph.json", 2_147_483_646L)
            unavailable(readRecordedRepairHistorySnapshot(revisions, {}, {}))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        unavailable(readProjectRecordedRepairHistory(root))
    }

    /** Root-selected future Actions capacity control; raw bytes, not valid-graph/heap qualification. */
    @Test
    fun actualRawExactCanonicalCapCaptureUsesSmallWriterChunksAndStreamingExpectedDigest() {
        val path = Files.createDirectory(root().resolve("raw-capacity-revisions"))
        val leaf = path.resolve("graph.json")
        val chunk = ByteArray(16_384) { (it % 127).toByte() }
        val digest = java.security.MessageDigest.getInstance("SHA-256")
        assertEquals(0L, canonicalCaptureMaximum % chunk.size)
        Files.newOutputStream(leaf, java.nio.file.StandardOpenOption.CREATE_NEW,
            java.nio.file.StandardOpenOption.WRITE).use { output ->
            repeat((canonicalCaptureMaximum / chunk.size).toInt()) {
                output.write(chunk)
                digest.update(chunk)
            }
        }
        val expectedSha = digest.digest().joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertEquals(canonicalCaptureMaximum, Files.size(leaf))
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val capture = session(revisions)
            val raw = call(capture, "capture", "graph.json", canonicalCaptureMaximum) as StableRegularFile
            assertEquals(canonicalCaptureMaximum, raw.bytes.size.toLong())
            assertEquals(expectedSha, raw.sha256)
            assertContentEquals(chunk, raw.bytes.copyOfRange(0, chunk.size))
            assertContentEquals(chunk, raw.bytes.copyOfRange(raw.bytes.size - chunk.size, raw.bytes.size))
            assertTrue(raw.identity.isRegularFile)
            assertEquals(canonicalCaptureMaximum, field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.identity, LinuxFilesystemSyscalls.identity(revisions.fd))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
    }

    @Test
    fun highRecordedBudgetKeepsSmallActualCanonicalInputsEligibleAndCapsBindingBeforeDebit() {
        val selected = budget.copy(maximumGraphBytes = canonicalCaptureMaximum + 1,
            maximumIndexEvidenceBytes = canonicalCaptureMaximum + 1)
        val root = producer(selected)
        val path = root.resolve("reports/repair-revisions")
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        assertTrue(graph.size.toLong() < canonicalCaptureMaximum && binding.size.toLong() < canonicalCaptureMaximum)
        assertEquals(selected, recordedRepairHistoryReadBudget(graph))
        val pure = recordedRepairHistorySnapshot(graph, binding, selected)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val capture = session(revisions)
            val result = call(capture, "read") as RepairHistoryReadResult
            assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
            assertEquals(pure.graphSha256, result.snapshot?.graphSha256)
            assertEquals(2L * graph.size + 2L * binding.size, field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(root).status)
        sparseCanonicalLeaf(path.resolve("recovery-binding.json"), canonicalCaptureMaximum + 1)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            assertCanonicalCapRefusalBeforeBody(revisions, "recovery-binding.json", selected.maximumGraphBytes)
            val capture = session(revisions)
            assertFailsWith<IllegalArgumentException> { call(capture, "read") }
            assertEquals(graph.size.toLong(), field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        unavailable(readProjectRecordedRepairHistory(root))
        assertContentEquals(graph, path.resolve("graph.json").readBytes())
        assertEquals("base", root.resolve("code.c").readText())
    }

    @Test
    fun requiredLegacyDeclarationUsesSameCapBeforeDebitAndNeverPublishesPartialSnapshot() {
        val selected = budget.copy(maximumGraphBytes = canonicalCaptureMaximum + 1,
            maximumIndexEvidenceBytes = canonicalCaptureMaximum + 1)
        val root = legacyPendingWithCaptureBudget(selected)
        val path = root.resolve("reports/repair-revisions")
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        val declared = Files.newDirectoryStream(path, "legacy-graph-*.json").use { it.single() }
        val original = declared.readBytes()
        assertTrue(graph.size.toLong() < selected.maximumGraphBytes)
        assertTrue(original.size.toLong() < canonicalCaptureMaximum)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val capture = session(revisions)
            val result = call(capture, "read") as RepairHistoryReadResult
            assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
            assertEquals(true, result.snapshot?.pending?.rollback?.legacyPendingStateUnknown)
            assertEquals(2L * graph.size + 2L * binding.size + 2L * original.size,
                field(field(capture, "ledger")!!, "used"))
        }
        sparseCanonicalLeaf(declared, canonicalCaptureMaximum + 1)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            assertCanonicalCapRefusalBeforeBody(revisions, declared.fileName.toString(), selected.maximumGraphBytes)
            val capture = session(revisions)
            assertFailsWith<RepairHistorySnapshotRefusal> { call(capture, "read") }
            assertEquals(graph.size.toLong() + binding.size, field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        unavailable(readProjectRecordedRepairHistory(root))
        assertContentEquals(graph, path.resolve("graph.json").readBytes())
        assertContentEquals(binding, path.resolve("recovery-binding.json").readBytes())
        assertEquals("candidate", root.resolve("code.c").readText())
    }

    @Test
    fun actualProducerSummaryOverOneMiBStillReadsWithinCanonicalCaptureCap() {
        val selected = budget.copy(maximumGraphBytes = 4L * 1024 * 1024)
        val root = root()
        val summary = "x".repeat(1024 * 1024 + 1)
        assertTrue(summary.toByteArray().size.toLong() <= selected.maximumRequestBytes)
        ModuleRevisionGraph.open(root, profile, selected).use { graph ->
            graph.enableRunContract()
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("large-summary", emptyList(), byteArrayOf())))
            val attempt = graph.beginAttempt(listOf("code.c"), RevisionRepairMetadata(1, "compile", "bounded private prompt",
                summary, corpus.inputs.map { it.id }, null, corpus.sha256,
                publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            graph.reject(attempt)
        }
        val path = root.resolve("reports/repair-revisions")
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        assertTrue(graph.size > 1024 * 1024 && graph.size.toLong() < canonicalCaptureMaximum)
        val expected = recordedRepairHistorySnapshot(graph, binding, selected)
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            val capture = session(revisions)
            val result = call(capture, "read") as RepairHistoryReadResult
            assertEquals(RepairHistoryReadStatus.RECORDED, result.status)
            assertEquals(expected.graphSha256, result.snapshot?.graphSha256)
            assertEquals(expected.attempts.size, result.snapshot?.attempts?.size)
            assertEquals(RepairRecordedQualification.RECORDED_METADATA_ONLY, result.snapshot?.qualification)
            assertEquals(2L * graph.size + 2L * binding.size, field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        assertEquals(RepairHistoryReadStatus.RECORDED, readProjectRecordedRepairHistory(root).status)
        assertEquals("base", root.resolve("code.c").readText())
    }

    @Test
    fun laterCanonicalGrowthPastCapRefusesBeforeSecondBodyAndKeepsFirstPassCharge() {
        val root = producer()
        val path = root.resolve("reports/repair-revisions")
        val graph = path.resolve("graph.json").readBytes()
        val binding = path.resolve("recovery-binding.json").readBytes()
        val firstPass = graph.size.toLong() + binding.size
        LinuxFilesystemSyscalls.openRoot(path).use { revisions ->
            var changed = false
            lateinit var capture: Any
            capture = session(revisions, revalidate = {
                if (!changed && (field(field(capture, "ledger")!!, "used") as Long) >= firstPass) {
                    changed = true
                    sparseCanonicalLeaf(path.resolve("graph.json"), canonicalCaptureMaximum + 1)
                }
            })
            assertFailsWith<IllegalArgumentException> { call(capture, "read") }
            assertTrue(changed)
            assertEquals(firstPass, field(field(capture, "ledger")!!, "used"))
            assertEquals(revisions.fd, revisions.whileOpen { it })
        }
        unavailable(readProjectRecordedRepairHistory(root))
        assertContentEquals(binding, path.resolve("recovery-binding.json").readBytes())
        assertEquals("base", root.resolve("code.c").readText())
    }

    private val canonicalCaptureMaximum = 64L * 1024 * 1024

    private fun assertCanonicalCapRefusalBeforeBody(revisions: LinuxDescriptor, name: String, maximum: Long) {
        var checks = 0
        val capture = session(revisions, cancel = {
            if (++checks > 2) error("unexpected stable-reader body entry")
        })
        assertFailsWith<IllegalArgumentException> { call(capture, "capture", name, maximum) }
        assertEquals(2, checks) // Existing initial check only; stable reader's first callback is not reached.
        assertEquals(0L, field(field(capture, "ledger")!!, "used"))
        assertEquals(revisions.fd, revisions.whileOpen { it })
    }

    private fun sparseCanonicalLeaf(path: Path, size: Long) {
        require(size > 0)
        Files.newByteChannel(path, java.nio.file.StandardOpenOption.CREATE,
            java.nio.file.StandardOpenOption.TRUNCATE_EXISTING, java.nio.file.StandardOpenOption.WRITE).use { channel ->
            channel.position(size - 1)
            assertEquals(1, channel.write(java.nio.ByteBuffer.wrap(byteArrayOf(0))))
        }
        assertEquals(size, Files.size(path))
    }

    private fun legacyPendingWithCaptureBudget(selected: RepairResourceBudget): Path {
        val root = root()
        ModuleRevisionGraph.open(root, profile, selected).use { graph ->
            val attempt = graph.beginAttempt(listOf("code.c")) // Genuine schema2, before any upgrade.
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        assertFailsWith<MigrationCrash> {
            ModuleRevisionGraph.openForTesting(root, profile, selected, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync &&
                    point.scope == "revision-state" && point.name == "graph.json") throw MigrationCrash()
            }).close()
        }
        return root
    }

    private fun root(): Path {
        val parent = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(parent)
        return Files.createTempDirectory(parent, "recorded-reader-").also { it.resolve("code.c").writeText("base") }
    }
    private fun producer(selectedBudget: RepairResourceBudget = budget): Path = root().also { root ->
        ModuleRevisionGraph.open(root, profile, selectedBudget).use { graph ->
            graph.enableRunContract()
            val attempt = graph.beginAttempt(listOf("code.c"))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
            graph.reject(attempt)
        }
    }
    private class MigrationCrash : Error()
    private fun migrated(): Path {
        val selectedBudget = budget.copy(maximumGraphBytes = 16 * 1024)
        val root = root()
        ModuleRevisionGraph.open(root, profile, selectedBudget).use { graph ->
            val corpus = graph.retainRegressionInputs(listOf(ProcessInput("case", emptyList(), byteArrayOf())))
            val attempt = graph.beginAttempt(listOf("code.c"), RevisionRepairMetadata(1, "compile", "bounded private prompt",
                "LEGACY_PADDING", corpus.inputs.map { it.id }, null, corpus.sha256, publicationMode = RepairPublicationMode.TEST_ONLY_NON_RELEASE))
            graph.installCandidate(attempt, mapOf("code.c" to "candidate".toByteArray()))
        }
        val path = root.resolve("reports/repair-revisions/graph.json")
        val original = path.readText()
        val padding = (selectedBudget.maximumGraphBytes - original.toByteArray().size).toInt()
        assertTrue(padding > 0)
        path.writeText(original.replace("LEGACY_PADDING", "x".repeat("LEGACY_PADDING".length + padding)))
        assertEquals(selectedBudget.maximumGraphBytes, Files.size(path))
        assertFailsWith<MigrationCrash> {
            ModuleRevisionGraph.openForTesting(root, profile, selectedBudget, ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.AfterStatePublicationDirectorySync && point.scope == "revision-state" && point.name == "graph.json") throw MigrationCrash()
            }).close()
        }
        return root
    }
    private fun withRevisions(body: (LinuxDescriptor, Path) -> Unit) {
        val path = Files.createDirectory(root().resolve("fixture-revisions"))
        LinuxFilesystemSyscalls.openRoot(path).use { body(it, path) }
    }
    private fun session(revisions: LinuxDescriptor, revalidate: () -> Unit = {}, cancel: () -> Unit = {}): Any =
        construct("HistoryCaptureSession", revisions, revalidate, cancel, { _: Long -> Unit })
    private fun unavailable(result: RepairHistoryReadResult) {
        assertEquals(RepairHistoryReadStatus.UNAVAILABLE, result.status); assertNull(result.snapshot)
    }
    private fun construct(name: String, vararg arguments: Any): Any =
        Class.forName("decompengine.repair.$name").declaredConstructors.single { it.parameterCount == arguments.size }
            .also { it.isAccessible = true }.let { invoke { it.newInstance(*arguments) } }!!
    private fun call(target: Any, name: String, vararg arguments: Any): Any? =
        target.javaClass.declaredMethods.single { it.name == name && it.parameterCount == arguments.size }
            .also { it.isAccessible = true }.let { invoke { it.invoke(target, *arguments) } }
    private fun top(name: String, vararg arguments: Any): Any? =
        Class.forName("decompengine.repair.RepairHistorySnapshotReaderKt").declaredMethods
            .single { it.name == name && it.parameterCount == arguments.size }.also { it.isAccessible = true }
            .let { invoke { it.invoke(null, *arguments) } }
    private fun field(target: Any, name: String): Any? = target.javaClass.getDeclaredField(name).also { it.isAccessible = true }.get(target)
    private fun <T> invoke(body: () -> T): T = try { body() } catch (failure: InvocationTargetException) { throw failure.targetException }
}
