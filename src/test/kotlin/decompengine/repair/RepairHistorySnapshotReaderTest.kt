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
            for (name in listOf("not-selected", "graph.json", "recovery-binding.json")) path.resolve(name).writeText("x")
            val session = session(revisions)
            val names = call(session, "names", budget.copy(maximumStateDirectoryEntries = 3)) as List<*>
            assertEquals(listOf("graph.json", "not-selected", "recovery-binding.json"), names)
            assertFails { call(session, "names", budget.copy(maximumStateDirectoryEntries = 2)) }
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
        val chain = construct("HistoryDirectoryChain", root, listOf("reports", "not-a-directory"), {})
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
        construct("HistoryCaptureSession", revisions, revalidate, cancel)
    private fun unavailable(result: RepairHistoryReadResult) {
        assertEquals(RepairHistoryReadStatus.UNAVAILABLE, result.status); assertNull(result.snapshot)
    }
    private fun construct(name: String, vararg arguments: Any): Any =
        Class.forName("decompengine.repair.$name").declaredConstructors.single().also { it.isAccessible = true }
            .let { invoke { it.newInstance(*arguments) } }!!
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
