package decompengine.oracle.fulltree

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.acp.LinuxSyscallException
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import java.io.File
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermission
import java.nio.file.attribute.PosixFilePermissions
import java.util.Comparator
import java.util.concurrent.CancellationException
import java.util.concurrent.TimeUnit
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeFunctionTruthSqliteV3Test {
    @Test
    fun `truth v3 final original recheck rejects rewriting an earlier member`() =
        inControlTemporaryDirectory { root ->
            // Snapshot authentication is byte-oriented; compiler provenance is exercised separately.
            val original = privateDirectory(root.resolve("original"))
            val shards = privateDirectory(original.resolve("shards"))
            Files.writeString(original.resolve("exclusions.json"), "{\"fixture\":\"exclusions\"}")
            Files.writeString(original.resolve("index.json"), "{\"fixture\":\"index\"}")
            Files.writeString(shards.resolve("fixture.json"), "{\"fixture\":\"shard\"}")
            val originalBytes = v3TreeBytes(original)
            val totalBytes = originalBytes.values.sumOf { it.size.toLong() }
            val identity = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
                original, setOf("shards"), 3L, totalBytes, {}, setOf("index.json", "exclusions.json"),
            )
            val snapshot = identity.createSnapshot(
                original, root.resolve("pinned"), setOf("shards"), null, {}, totalBytes,
            )
            snapshot.verifyOriginalUnchanged()
            val target = original.resolve("exclusions.json")
            val before = Files.readAllBytes(target)
            val changed = before.copyOf().also { it[0] = '['.code.toByte() }
            var checkedExclusions = false
            var callbackFired = false
            var rewriteSucceeded: Boolean? = null
            val failure = runCatching {
                snapshot.verifyOriginalUnchanged { stage ->
                    if (stage == "while rechecking pinned truth-v3 input member exclusions.json") {
                        checkedExclusions = true
                    }
                    if (!callbackFired && stage == "while rechecking pinned truth-v3 input member index.json") {
                        assertTrue(checkedExclusions, "the hostile write must follow the original exclusions check")
                        callbackFired = true
                        rewriteSucceeded = tryNonblockingSameLengthRewrite(target, changed)
                    }
                }
            }.exceptionOrNull()
            assertTrue(callbackFired, "the final original-member checkpoint must execute")
            val wrote = assertNotNull(rewriteSucceeded, "the hostile write must complete or be refused without blocking")
            assertEquals(before.size.toLong(), Files.size(target), "the hostile write preserves file size")
            assertEquals((if (wrote) changed else before).toList(), Files.readAllBytes(target).toList(),
                "a successful hostile write must change the original member bytes")
            assertEquals(originalBytes, v3TreeBytes(snapshot.root), "the private snapshot stays unchanged")
            val rejection = assertIs<IllegalArgumentException>(failure,
                "the final original recheck must reject an earlier-member rewrite or lease-break attempt; " +
                    "rewriteSucceeded=$rewriteSucceeded")
            assertTrue(listOf("lease", "chang", "mutat").any { rejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the hostile mutation: ${rejection.causeMessageChain()}")
        }

    @Test
    fun `truth v3 final staging recheck rejects rewriting an earlier shard`() =
        inControlTemporaryDirectory { root ->
            val fixture = createBoundaryTruthFixture(root)
            val generated = fixture.generated
            val generatedBytes = v3TreeBytes(generated.root)
            val staging = copyTree(generated.root, root.resolve("staging"))
            val index = parseControlObject(staging.resolve("index.json"))
            val indexBytes = Files.readAllBytes(staging.resolve("index.json"))
            val firstShard = staging.resolve((index.controlArray("shards").first() as JsonObject).controlString("path"))
            val before = Files.readAllBytes(firstShard)
            val changed = before.copyOf().also { it[0] = '['.code.toByte() }
            val snapshot = FullTreeFunctionTruthSqliteV3.freezeAndVerifyV3Staging(
                staging, index, indexBytes, generated.outputBytes,
            )
            FullTreeFunctionTruthSqliteV3.reauthenticateV3Staging(snapshot, index, indexBytes, generated.outputBytes)
            var hashedFirstShard = false
            var callbackFired = false
            var rewriteSucceeded: Boolean? = null
            val failure = runCatching {
                FullTreeOracleOperationCheckpoint.withCheckpoint({ stage ->
                    if (stage == "while hashing truth-v3 member ${firstShard.fileName}") {
                        hashedFirstShard = true
                    }
                    if (!callbackFired && stage == "while hashing truth-v3 member exclusions.json") {
                        assertTrue(hashedFirstShard, "the hostile write must follow the first shard hash")
                        callbackFired = true
                        rewriteSucceeded = tryNonblockingSameLengthRewrite(firstShard, changed)
                    }
                }) {
                    FullTreeFunctionTruthSqliteV3.reauthenticateV3Staging(
                        snapshot, index, indexBytes, generated.outputBytes,
                    )
                }
            }.exceptionOrNull()
            assertTrue(callbackFired, "the final staging-member checkpoint must execute")
            val wrote = assertNotNull(rewriteSucceeded, "the hostile write must complete or be refused without blocking")
            assertEquals(before.size.toLong(), Files.size(firstShard), "the hostile write preserves file size")
            assertEquals((if (wrote) changed else before).toList(), Files.readAllBytes(firstShard).toList(),
                "a successful hostile write must change the already-hashed shard bytes")
            assertEquals(generatedBytes, v3TreeBytes(generated.root), "the authenticated fixture stays unchanged")
            assertDirectoryEmpty(fixture.scratch)
            val rejection = assertIs<IllegalArgumentException>(failure,
                "the final staging recheck must reject an earlier-shard rewrite or lease-break attempt; " +
                    "rewriteSucceeded=$rewriteSucceeded")
            assertTrue(listOf("lease", "chang", "mutat").any { rejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the hostile mutation: ${rejection.causeMessageChain()}")
        }

    @Test
    fun `truth v3 publication retains member guards through rename and revokes raced output`() =
        inControlTemporaryDirectory { root ->
            val fixture = createBoundaryTruthFixture(root)
            val generated = fixture.generated
            val generatedBytes = v3TreeBytes(generated.root)
            val firstShardPath = (generated.index.controlArray("shards").first() as JsonObject).controlString("path")
            assertTrue(generated.index.controlArray("shards").size in 1..255,
                "the small fixture emits exactly one indexed-shard checkpoint per hash pass")

            val successParent = privateDirectory(root.resolve("successful-commit"))
            val successTarget = successParent.resolve("published")
            var successStaging: Path? = null
            var inputChecks = 0
            FullTreeFunctionTruthSqliteV3.V3Publication.create(successTarget, generated.outputBytes).use { publication ->
                successStaging = publication.staging
                publication.commit(boundaryProjection(generated, publication.staging), {}, verifyInputs = { inputChecks++ })
            }
            assertEquals(2, inputChecks, "successful commit verifies inputs before and after rename")
            assertFalse(Files.exists(assertNotNull(successStaging), LinkOption.NOFOLLOW_LINKS))
            assertEquals(generatedBytes, v3TreeBytes(successTarget), "successful publication preserves all authenticated bytes")
            assertEquals(listOf("published"), Files.list(successParent).use { paths -> paths.map { it.fileName.toString() }.toList() })

            val rewriteParent = privateDirectory(root.resolve("rejected-staging-rewrite"))
            val rewriteTarget = rewriteParent.resolve("rejected")
            var hashPass = 0
            var firstShardHashed = false
            var rewriteCallbackFired = false
            var rewriteSucceeded: Boolean? = null
            val rewriteFailure = runCatching {
                FullTreeFunctionTruthSqliteV3.V3Publication.create(rewriteTarget, generated.outputBytes).use { publication ->
                    val projection = boundaryProjection(generated, publication.staging)
                    val firstShard = publication.staging.resolve(firstShardPath)
                    val before = Files.readAllBytes(firstShard)
                    val changed = before.copyOf().also { it[0] = '['.code.toByte() }
                    val checkpoint: (String) -> Unit = { stage ->
                        if (stage == "while hashing truth-v3 indexed shards") {
                            hashPass++
                            firstShardHashed = false
                        }
                        if (hashPass == 2 && stage == "while hashing truth-v3 member ${firstShard.fileName}") {
                            firstShardHashed = true
                        }
                        if (hashPass == 2 && !rewriteCallbackFired && stage == "while hashing truth-v3 member exclusions.json") {
                            assertTrue(firstShardHashed, "the final rehash must already have visited the attacked shard")
                            rewriteCallbackFired = true
                            val wrote = tryNonblockingSameLengthRewrite(firstShard, changed)
                            rewriteSucceeded = wrote
                            assertEquals(before.size.toLong(), Files.size(firstShard), "the hostile write preserves file size")
                            assertEquals((if (wrote) changed else before).toList(), Files.readAllBytes(firstShard).toList())
                        }
                    }
                    FullTreeOracleOperationCheckpoint.withCheckpoint(checkpoint) {
                        publication.commit(projection, checkpoint, verifyInputs = {})
                    }
                }
            }.exceptionOrNull()
            assertTrue(rewriteCallbackFired, "the actual final publication rehash must reach the hostile writer")
            assertNotNull(rewriteSucceeded, "the nonblocking writer must finish or be refused")
            val rewriteRejection = assertIs<IllegalArgumentException>(rewriteFailure,
                "publication must reject the earlier-shard write attempt; rewriteSucceeded=$rewriteSucceeded")
            assertTrue(listOf("lease", "chang", "mutat").any { rewriteRejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the hostile mutation: ${rewriteRejection.causeMessageChain()}")
            assertFalse(Files.exists(rewriteTarget, LinkOption.NOFOLLOW_LINKS), "a rejected rehash must not publish a target")
            assertDirectoryEmpty(rewriteParent)

            val replacementParent = privateDirectory(root.resolve("rejected-destination-replacement"))
            val replacementTarget = replacementParent.resolve("rejected")
            val replacementMember = replacementParent.resolve("replacement-exclusions.json")
            Files.copy(generated.root.resolve("exclusions.json"), replacementMember, StandardCopyOption.COPY_ATTRIBUTES)
            var replacementCallbackFired = false
            val replacementFailure = runCatching {
                FullTreeFunctionTruthSqliteV3.V3Publication.create(replacementTarget, generated.outputBytes).use { publication ->
                    publication.commit(boundaryProjection(generated, publication.staging), { stage ->
                        if (stage == "after truth-v3 publication rename") {
                            assertFalse(replacementCallbackFired, "the publication rename checkpoint is reached once")
                            val targetMember = replacementTarget.resolve("exclusions.json")
                            val beforeIdentity = Files.getAttribute(targetMember, "unix:ino", LinkOption.NOFOLLOW_LINKS)
                            val beforeBytes = Files.readAllBytes(targetMember)
                            val originalMode = Files.getPosixFilePermissions(replacementTarget, LinkOption.NOFOLLOW_LINKS)
                            try {
                                Files.setPosixFilePermissions(replacementTarget, originalMode + PosixFilePermission.OWNER_WRITE)
                                Files.move(replacementMember, targetMember, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING)
                            } finally {
                                Files.setPosixFilePermissions(replacementTarget, originalMode)
                            }
                            assertTrue(beforeIdentity != Files.getAttribute(targetMember, "unix:ino", LinkOption.NOFOLLOW_LINKS),
                                "the hostile replacement must change the destination inode")
                            assertEquals(beforeBytes.toList(), Files.readAllBytes(targetMember).toList(),
                                "destination replacement preserves bytes to isolate pathname binding")
                            replacementCallbackFired = true
                        }
                    }, verifyInputs = {})
                }
            }.exceptionOrNull()
            assertTrue(replacementCallbackFired, "the destination replacement must occur after the actual rename")
            val replacementRejection = assertIs<IllegalArgumentException>(replacementFailure,
                "publication must reject a byte-identical destination member replacement")
            assertTrue(listOf("identit", "chang", "mutat").any { replacementRejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the destination replacement: ${replacementRejection.causeMessageChain()}")
            assertFalse(Files.exists(replacementTarget, LinkOption.NOFOLLOW_LINKS), "the identified raced target must be revoked")
            assertDirectoryEmpty(replacementParent)
            assertEquals(generatedBytes, v3TreeBytes(generated.root), "all publication controls leave their source fixture unchanged")
            assertDirectoryEmpty(fixture.scratch)
        }

    @Test
    fun `truth v3 boundary guards admit exact overlapping trees and release cancelled leases`() =
        inControlTemporaryDirectory { root ->
            val first = privateDirectory(root.resolve("first"))
            privateDirectory(first.resolve("shards"))
            Files.writeString(first.resolve("exclusions.json"), "{\"fixture\":\"exclusions\"}")
            Files.writeString(first.resolve("index.json"), "{\"fixture\":\"index\"}")
            Files.writeString(first.resolve("shards/fixture.json"), "{\"fixture\":\"shard\"}")
            val second = copyTree(first, root.resolve("second"))
            val expected = v3TreeBytes(first).mapValues { (_, bytes) ->
                FullTreeFunctionTruthSqliteV3.V3ExpectedTreeMember(bytes.size.toLong(), OracleArtifacts.sha256(bytes.toByteArray()))
            }
            val totalBytes = expected.values.sumOf { it.bytes }
            fun identity(tree: Path) = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
                tree, setOf("shards"), expected.size.toLong(), totalBytes, {}, setOf("index.json", "exclusions.json"),
            )
            val firstSnapshot = identity(first)
            val secondSnapshot = identity(second)
            val fixedAllowance = 96L * 1024L * 1024L
            val firstGuardBytes = expected.keys.sumOf {
                FullTreeFunctionTruthSqliteV3.V3BoundaryGuards.modeledGuardBytes(first.resolve(it))
            }
            val secondGuardBytes = expected.keys.sumOf {
                FullTreeFunctionTruthSqliteV3.V3BoundaryGuards.modeledGuardBytes(second.resolve(it))
            }
            val exactAllowance = fixedAllowance + firstGuardBytes + secondGuardBytes
            FullTreeFunctionTruthSqliteV3.V3BoundaryGuards(maximumRetainedBytes = exactAllowance).use { guards ->
                assertEquals(0..2, firstSnapshot.retainAtBoundary(first, expected, guards, {}))
                assertEquals(3..5, secondSnapshot.retainAtBoundary(second, expected, guards, {}))
                guards.verifyUnchanged()
            }

            val firstMember = first.resolve("exclusions.json")
            val firstBytes = Files.readAllBytes(firstMember)
            var openedSecondMember = false
            FullTreeFunctionTruthSqliteV3.V3BoundaryGuards(maximumRetainedBytes = exactAllowance - 1L).use { guards ->
                firstSnapshot.retainAtBoundary(first, expected, guards, {})
                val rejection = assertFailsWith<FullTreeFunctionTruthV3Exception>(
                    "one byte below the aggregate allowance must reject the second simultaneously held tree",
                ) {
                    secondSnapshot.retainAtBoundary(second, expected, guards) { stage ->
                        if (stage.startsWith("while rechecking truth-v3 publication member ")) openedSecondMember = true
                    }
                }
                assertTrue(rejection.message.orEmpty().contains("guard metadata exceeds retained-working-set bound"),
                    "the second tree must fail aggregate metadata admission: ${rejection.message}")
                assertFalse(openedSecondMember, "the second tree is rejected before opening any member")
                assertFalse(tryNonblockingSameLengthRewrite(firstMember, firstBytes),
                    "the first tree remains leased while the overlapping tree is rejected")
            }
            assertTrue(tryNonblockingSameLengthRewrite(firstMember, firstBytes),
                "closing the rejected transaction releases the first tree's retained lease")

            val cancellation = CancellationException("cancel after retaining exclusions.json")
            var exclusionsCheckpoint = false
            var cancellationCheckpoint = false
            val observedCancellation = assertFailsWith<CancellationException> {
                FullTreeFunctionTruthSqliteV3.V3BoundaryGuards(
                    maximumRetainedBytes = fixedAllowance + firstGuardBytes,
                ).use { guards ->
                    firstSnapshot.retainAtBoundary(first, expected, guards) { stage ->
                        if (stage == "while rechecking truth-v3 publication member exclusions.json") exclusionsCheckpoint = true
                        if (stage == "while rechecking truth-v3 publication member index.json") {
                            assertTrue(exclusionsCheckpoint, "cancellation occurs after the earlier member was opened")
                            cancellationCheckpoint = true
                            throw cancellation
                        }
                    }
                }
            }
            assertSame(cancellation, observedCancellation, "the checkpoint's exact cancellation propagates")
            assertTrue(cancellationCheckpoint)
            val changed = firstBytes.copyOf().also { it[0] = '['.code.toByte() }
            assertTrue(tryNonblockingSameLengthRewrite(firstMember, changed),
                "cancellation closes the earlier member guard instead of retaining its read lease")
            assertEquals(changed.toList(), Files.readAllBytes(firstMember).toList())
            assertTrue(tryNonblockingSameLengthRewrite(firstMember, firstBytes))
            assertEquals(v3TreeBytes(first), v3TreeBytes(second), "cleanup preserves both snapshot populations")
        }

    @Test
    fun `truth v3 terminal verification rejects replacing an earlier private tree`() =
        inControlTemporaryDirectory { root ->
            val (_, snapshot) = createBoundaryByteSnapshot(root)
            snapshot.verifyOriginalUnchanged()
            val before = v3TreeBytes(snapshot.root)
            val oldRootInode = Files.getAttribute(snapshot.root, "unix:ino", LinkOption.NOFOLLOW_LINKS)
            val oldMemberInodes = before.keys.associateWith {
                Files.getAttribute(snapshot.root.resolve(it), "unix:ino", LinkOption.NOFOLLOW_LINKS)
            }
            val replacement = copyTree(snapshot.root, root.resolve("replacement"))
            val displaced = root.resolve("displaced-private-tree")
            var indexCallbacks = 0
            var earlierTreeVisited = false
            var callbackFired = false
            val failure = runCatching {
                snapshot.verifyOriginalUnchanged { stage ->
                    if (stage == "while verifying held truth-v3 boundary member shards/fixture.json" && indexCallbacks == 1) {
                        earlierTreeVisited = true
                    }
                    if (stage == "while verifying held truth-v3 boundary member index.json") {
                        indexCallbacks++
                        if (indexCallbacks == 2) {
                            assertTrue(earlierTreeVisited, "the private tree was fully checked before the later original-member callback")
                            Files.move(snapshot.root, displaced, StandardCopyOption.ATOMIC_MOVE)
                            Files.move(replacement, snapshot.root, StandardCopyOption.ATOMIC_MOVE)
                            callbackFired = true
                        }
                    }
                }
            }.exceptionOrNull()
            assertTrue(callbackFired, "the late held-member callback must replace the earlier private tree")
            assertEquals(oldRootInode, Files.getAttribute(displaced, "unix:ino", LinkOption.NOFOLLOW_LINKS))
            assertTrue(oldRootInode != Files.getAttribute(snapshot.root, "unix:ino", LinkOption.NOFOLLOW_LINKS),
                "the replacement must change the private tree's pathname binding")
            assertEquals(oldMemberInodes, before.keys.associateWith {
                Files.getAttribute(displaced.resolve(it), "unix:ino", LinkOption.NOFOLLOW_LINKS)
            }, "all previously guarded file inodes remain untouched in the displaced tree")
            assertEquals(before, v3TreeBytes(displaced))
            assertEquals(before, v3TreeBytes(snapshot.root), "the replacement is byte-identical")
            val rejection = assertIs<IllegalArgumentException>(failure,
                "terminal verification must reject replacing an earlier tree after its full member check")
            assertTrue(listOf("identit", "chang", "mutat").any { rejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the late tree replacement: ${rejection.causeMessageChain()}")
        }

    @Test
    fun `truth v3 terminal verification rejects a late unexpected candidate member`() =
        inControlTemporaryDirectory { root ->
            val (candidate, snapshot) = createBoundaryByteSnapshot(root)
            assertTrue(PosixFilePermission.OWNER_WRITE in Files.getPosixFilePermissions(candidate),
                "the candidate root is owner-writable from its initial identity capture")
            snapshot.verifyOriginalUnchanged()
            val before = v3TreeBytes(candidate)
            var shardCallbacks = 0
            var callbackFired = false
            val unexpected = candidate.resolve("unexpected.json")
            val failure = runCatching {
                snapshot.verifyOriginalUnchanged { stage ->
                    if (stage == "while verifying held truth-v3 boundary member shards/fixture.json") {
                        shardCallbacks++
                        if (shardCallbacks == 2) {
                            Files.writeString(unexpected, "{\"fixture\":\"unexpected\"}")
                            callbackFired = true
                        }
                    }
                }
            }.exceptionOrNull()
            assertTrue(callbackFired, "the unexpected member must be added during the last original-member callback")
            assertEquals("{\"fixture\":\"unexpected\"}", Files.readString(unexpected))
            val after = v3TreeBytes(candidate)
            assertEquals(before.keys + "unexpected.json", after.keys, "the mutation changes exact tree membership")
            assertEquals(before, after.filterKeys { it != "unexpected.json" }, "all authenticated members retain their bytes")
            assertEquals(before, v3TreeBytes(snapshot.root), "the private snapshot stays unchanged")
            val rejection = assertIs<IllegalArgumentException>(failure,
                "terminal verification must reject a late member added after the previous exact-membership enumeration")
            assertTrue(listOf("membership", "unexpected", "chang", "mutat").any { rejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the late membership mutation: ${rejection.causeMessageChain()}")
        }

    @Test
    fun `truth v3 terminal verification rejects replacing a previously checked raw input ancestor`() =
        inControlTemporaryDirectory { root ->
            val (_, snapshot) = createBoundaryByteSnapshot(root)
            val rawRoot = privateDirectory(root.resolve("raw-inputs"))
            val rawPaths = listOf("rich.elf", "stripped.elf", "inventory.json", "elf-index.json").map { name ->
                rawRoot.resolve(name).also { Files.writeString(it, "raw fixture $name") }
            }
            // Raw inputs already permit hard links; terminal checking must preserve that contract.
            Files.createLink(rawRoot.resolve("rich-alias.elf"), rawPaths.first())
            assertEquals(2, (Files.getAttribute(rawPaths.first(), "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt())
            val before = v3TreeBytes(rawRoot)
            val oldRootInode = Files.getAttribute(rawRoot, "unix:ino", LinkOption.NOFOLLOW_LINKS)
            val oldMemberInodes = before.keys.associateWith {
                Files.getAttribute(rawRoot.resolve(it), "unix:ino", LinkOption.NOFOLLOW_LINKS)
            }
            val replacement = copyTree(rawRoot, root.resolve("replacement-raw-inputs"))
            val displaced = root.resolve("displaced-raw-inputs")
            val snapshotBefore = v3TreeBytes(snapshot.root)
            var callbackFired = false
            var indexCallbacks = 0
            val failure = FullTreeFunctionTruthSqliteV3.V3RawInputGuards.open(
                rawPaths[0], rawPaths[1], rawPaths[2], rawPaths[3], FullTreeFunctionTruthV3Limits(),
            ).use { rawInputs ->
                rawInputs.verifyUnchanged("positive raw-input boundary control")
                FullTreeFunctionTruthSqliteV3.V3BoundaryGuards(
                    alreadyGuardedPaths = rawPaths,
                    alreadyGuardedInputs = rawInputs,
                ).use { guards ->
                    snapshot.retainOriginalUntilBoundary(guards)
                    guards.verifyUnchanged()
                }
                runCatching {
                    rawInputs.verifyUnchanged("before callback-bearing tree verification")
                    FullTreeFunctionTruthSqliteV3.V3BoundaryGuards(
                        alreadyGuardedPaths = rawPaths,
                        alreadyGuardedInputs = rawInputs,
                    ).use { guards ->
                        snapshot.retainOriginalUntilBoundary(guards)
                        guards.verifyUnchanged { stage ->
                            if (stage == "while verifying held truth-v3 boundary member index.json") {
                                indexCallbacks++
                                if (indexCallbacks == 2) {
                                    Files.move(rawRoot, displaced, StandardCopyOption.ATOMIC_MOVE)
                                    Files.move(replacement, rawRoot, StandardCopyOption.ATOMIC_MOVE)
                                    callbackFired = true
                                }
                            }
                        }
                    }
                }.exceptionOrNull()
            }
            assertTrue(callbackFired, "the raw-only ancestor must be replaced during a later held tree-member callback")
            assertEquals(oldRootInode, Files.getAttribute(displaced, "unix:ino", LinkOption.NOFOLLOW_LINKS))
            assertTrue(oldRootInode != Files.getAttribute(rawRoot, "unix:ino", LinkOption.NOFOLLOW_LINKS),
                "the replacement changes the raw ancestor's pathname binding")
            assertEquals(oldMemberInodes, before.keys.associateWith {
                Files.getAttribute(displaced.resolve(it), "unix:ino", LinkOption.NOFOLLOW_LINKS)
            }, "the already checked raw inodes remain untouched")
            assertEquals(before, v3TreeBytes(displaced))
            assertEquals(before, v3TreeBytes(rawRoot), "the replacement raw input tree is byte-identical")
            assertEquals(snapshotBefore, v3TreeBytes(snapshot.root), "the guarded truth snapshot stays unchanged")
            val rejection = assertIs<IllegalArgumentException>(failure,
                "terminal verification must recheck raw pathname bindings after callback-bearing tree checks")
            assertTrue(listOf("identit", "chang", "mutat", "path").any { rejection.causeMessageChain().contains(it, ignoreCase = true) },
                "rejection must identify the late raw ancestor replacement: ${rejection.causeMessageChain()}")
        }

    private fun createBoundaryByteSnapshot(root: Path): Pair<Path, FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot> {
        val candidate = privateDirectory(root.resolve("candidate"))
        privateDirectory(candidate.resolve("shards"))
        Files.writeString(candidate.resolve("exclusions.json"), "{\"fixture\":\"exclusions\"}")
        Files.writeString(candidate.resolve("index.json"), "{\"fixture\":\"index\"}")
        Files.writeString(candidate.resolve("shards/fixture.json"), "{\"fixture\":\"shard\"}")
        val totalBytes = v3TreeBytes(candidate).values.sumOf { it.size.toLong() }
        val identity = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
            candidate, setOf("shards"), 3L, totalBytes, {}, setOf("index.json", "exclusions.json"),
        )
        return candidate to identity.createSnapshot(
            candidate, root.resolve("pinned"), setOf("shards"), null, {}, totalBytes,
        )
    }

    private data class BoundaryTruthFixture(val generated: FullTreeFunctionTruthV3Generation, val scratch: Path)

    private fun createBoundaryTruthFixture(root: Path): BoundaryTruthFixture {
        // Production publishers share the small authenticated control fixture; no compiler or golden substitution.
        val fixture = createFunctionTruthFixture(root.resolve("inputs"))
        val limits = tightScratchLimits()
        val observationRoot = root.resolve("observations-v2")
        val observation = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
            richArtifact = fixture.rich,
            inventoryPath = fixture.inventoryPath,
            scope = fixture.scope,
            scratchParent = fixture.scratch,
            outputRoot = observationRoot,
            maximumWorkers = 2,
            limits = limits.observationV2,
        )
        val generated = FullTreeFunctionTruthSqliteV3.generateAndPublish(
            richArtifact = fixture.rich,
            strippedArtifact = fixture.stripped,
            inventoryPath = fixture.inventoryPath,
            elfFunctionIndex = fixture.elfIndex,
            observationV2Root = observationRoot,
            expectedObservationV2IndexArtifactSha256 = observation.binding.indexArtifactSha256,
            scope = fixture.scope,
            scratchParent = fixture.scratch,
            outputRoot = root.resolve("truth-v3"),
            limits = limits,
        )
        assertDirectoryEmpty(fixture.scratch)
        return BoundaryTruthFixture(generated, fixture.scratch)
    }

    private fun boundaryProjection(
        generated: FullTreeFunctionTruthV3Generation,
        staging: Path,
    ): FullTreeFunctionTruthSqliteV3.V3Projection {
        privateDirectory(staging.resolve("shards"))
        Files.walk(generated.root).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach { input ->
                Files.copy(input, staging.resolve(generated.root.relativize(input)), StandardCopyOption.COPY_ATTRIBUTES)
            }
        }
        return FullTreeFunctionTruthSqliteV3.V3Projection(
            root = staging,
            index = generated.index,
            indexBytes = Files.readAllBytes(generated.root.resolve("index.json")),
            indexArtifactSha256 = generated.indexArtifactSha256,
            indexSha256 = generated.indexSha256,
            outputBytes = generated.outputBytes,
            counts = generated.counts,
            elfIndexArtifactSha256 = generated.elfIndexArtifactSha256,
        )
    }

    private fun tryNonblockingSameLengthRewrite(path: Path, bytes: ByteArray): Boolean {
        assertEquals(Files.size(path), bytes.size.toLong(), "the mutation must preserve member length")
        val originalMode = Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS)
        try {
            Files.setPosixFilePermissions(path, originalMode + PosixFilePermission.OWNER_WRITE)
            return LinuxFilesystemSyscalls.openRoot(path.parent).use { parent ->
                requireNotNull(LinuxFilesystemSyscalls.openRegularFileAtOrNull(parent.fd, path.fileName.toString())).use { selected ->
                    try {
                        // reopenWritable uses O_NONBLOCK: held read leases must refuse instead of hanging.
                        LinuxFilesystemSyscalls.reopenWritable(selected).use { writable ->
                            LinuxFilesystemSyscalls.write(writable, bytes) {}
                        }
                        true
                    } catch (failure: LinuxSyscallException) {
                        if (failure.errno != 11) throw failure // EWOULDBLOCK only.
                        false
                    }
                }
            }
        } finally {
            Files.setPosixFilePermissions(path, originalMode)
        }
    }

    @Test
    fun `truth v3 combined resource bounds admit exact limits and reject one over`() {
        assertEquals(10L, fullTreeFunctionTruthV3CombinedEntityCount(4L, 6L, 10L))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3CombinedEntityCount(4L, 7L, 10L)
        }
        assertTrue(fullTreeFunctionTruthV3HasOnlyEmittedRvaLinks(
            listOf("emitted-rva-from-another-shard"), setOf("emitted-rva-from-another-shard"),
        ), "a source link may name an emitted score row owned by another shard")
        assertFalse(fullTreeFunctionTruthV3HasOnlyEmittedRvaLinks(
            listOf("rva-absent-from-full-run"), setOf("emitted-rva-from-another-shard"),
        ), "a source link must not name an off-run RVA")
        assertEquals(10L, FullTreeFunctionTruthSqliteV3.reserveV3OutputBytes(0L, 10L, 10L))
        assertFailsWith<IllegalArgumentException> {
            FullTreeFunctionTruthSqliteV3.reserveV3OutputBytes(0L, 10L, 9L)
        }

        val nestedAtLimit = fullTreeFunctionTruthV3NestedScratchPlan(
            remainingBytes = 10L,
            databaseMinimumBytes = 8L,
            maximumScratchBytes = 16L,
            maximumOutputBytes = 4L,
        )
        assertEquals(8L, nestedAtLimit.maximumScratchBytes)
        assertEquals(2L, nestedAtLimit.maximumOutputBytes)
        assertEquals(10L, nestedAtLimit.maximumScratchBytes + nestedAtLimit.maximumOutputBytes)
        val oneByteOfRoom = fullTreeFunctionTruthV3NestedScratchPlan(9L, 8L, 16L, 4L)
        assertEquals(8L, oneByteOfRoom.maximumScratchBytes)
        assertEquals(1L, oneByteOfRoom.maximumOutputBytes)
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3NestedScratchPlan(8L, 8L, 16L, 4L)
        }
        assertEquals(
            215L,
            fullTreeFunctionTruthV3AdapterPublishScratchPeakBytes(
                currentScratchBytes = 140L,
                preparedPayloadBytes = 60L,
                maximumControlArtifactBytes = 5L,
                maximumScratchBytes = 215L,
            ),
            "prepared payloads are already in current scratch; checkpoints, run, and index are bounded by three control caps",
        )
        assertFailsWith<IllegalArgumentException>("one byte below the adapter peak must reject") {
            fullTreeFunctionTruthV3AdapterPublishScratchPeakBytes(
                currentScratchBytes = 140L,
                preparedPayloadBytes = 60L,
                maximumControlArtifactBytes = 5L,
                maximumScratchBytes = 214L,
            )
        }

        val rvaCollectionTruthBytes = 1_024L
        val rvaCollectionControls = 128L
        val rvaCollectionSet = 96L
        val exactRvaCollectionWorkingSet = fullTreeFunctionTruthV3ModeledWorkingSetBytes(
            observationBytes = 1L,
            legacyTruthBytes = rvaCollectionTruthBytes,
            projectedShardBytes = 1L,
            retainedControlBytes = rvaCollectionControls,
            retainedSingleCopyBytes = rvaCollectionSet,
        )
        assertEquals(
            exactRvaCollectionWorkingSet,
            fullTreeFunctionTruthV3AdmitEmittedRvaCollectionWorkingSet(
                truthShardBytes = rvaCollectionTruthBytes,
                retainedControlBytes = rvaCollectionControls,
                retainedEmittedRvaBytes = rvaCollectionSet,
                configuredWorkingSetBytes = exactRvaCollectionWorkingSet,
                authenticatedPerShardResidentBytes = exactRvaCollectionWorkingSet,
            ),
        )
        assertFailsWith<IllegalArgumentException>("RVA collection must be admitted before allocating one extra byte") {
            fullTreeFunctionTruthV3AdmitEmittedRvaCollectionWorkingSet(
                truthShardBytes = rvaCollectionTruthBytes,
                retainedControlBytes = rvaCollectionControls,
                retainedEmittedRvaBytes = rvaCollectionSet,
                configuredWorkingSetBytes = exactRvaCollectionWorkingSet - 1L,
                authenticatedPerShardResidentBytes = exactRvaCollectionWorkingSet,
            )
        }

        val observed = 100L
        val truth = 50L
        val projected = 200L
        val retainedControl = 80L
        val exactWorkingSet = fullTreeFunctionTruthV3ModeledWorkingSetBytes(observed, truth, projected, retainedControl)
        assertEquals(exactWorkingSet, fullTreeFunctionTruthV3AdmitWorkingSet(
            observed, truth, projected, retainedControl, exactWorkingSet,
        ))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3AdmitWorkingSet(observed, truth, projected, retainedControl, exactWorkingSet - 1L)
        }
        val fullRunRvaSetBytes = 64L * 1024L * 1024L
        val setOnceWorkingSet = fullTreeFunctionTruthV3ModeledWorkingSetBytes(
            observed, truth, projected, retainedControl, fullRunRvaSetBytes,
        )
        assertEquals(exactWorkingSet + fullRunRvaSetBytes, setOnceWorkingSet,
            "the full-run emitted-RVA set is one retained allocation, not two control copies")
        assertEquals(setOnceWorkingSet, fullTreeFunctionTruthV3AdmitWorkingSet(
            observed, truth, projected, retainedControl, setOnceWorkingSet, fullRunRvaSetBytes,
        ))
        assertFailsWith<IllegalArgumentException>("one byte below the single-copy working set must fail") {
            fullTreeFunctionTruthV3AdmitWorkingSet(
                observed, truth, projected, retainedControl, setOnceWorkingSet - 1L, fullRunRvaSetBytes,
            )
        }
        assertEquals(setOnceWorkingSet, fullTreeFunctionTruthV3AdmitShardWorkingSet(
            observed, truth, projected, retainedControl, setOnceWorkingSet + 1L, setOnceWorkingSet,
            fullRunRvaSetBytes,
        ))
        assertFailsWith<IllegalArgumentException>("per-shard cap must include one full-run RVA set") {
            fullTreeFunctionTruthV3AdmitShardWorkingSet(
                observed, truth, projected, retainedControl, setOnceWorkingSet + 1L, setOnceWorkingSet - 1L,
                fullRunRvaSetBytes,
            )
        }
        assertEquals(exactWorkingSet, fullTreeFunctionTruthV3AdmitShardWorkingSet(
            observed, truth, projected, retainedControl, exactWorkingSet + 100L, exactWorkingSet,
        ))
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3AdmitShardWorkingSet(
                observed, truth, projected, retainedControl, exactWorkingSet + 100L, exactWorkingSet - 1L,
            )
        }
        fullTreeFunctionTruthV3CheckResidentBytes(95L, 100L, 200L, 100L)
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3CheckResidentBytes(101L, 101L, 200L, 100L)
        }
        // A prior operation's high-water mark remains a whole-run constraint, not a new shard's limit.
        fullTreeFunctionTruthV3CheckResidentBytes(95L, 150L, 200L, 100L)
        assertFailsWith<IllegalArgumentException> {
            fullTreeFunctionTruthV3CheckResidentBytes(95L, 201L, 200L, 100L)
        }

        val tight = tightScratchLimits()
        val sharedScratchLimits = tight.copy(
            truth = tight.truth.copy(
                maximumDatabaseBytes = 8L * 1024L * 1024L * 1024L,
                maximumScratchBytes = 8L * 1024L * 1024L * 1024L,
            ),
            observationV2 = tight.observationV2.copy(maximumScratchBytes = 1024L * 1024L * 1024L),
            maximumScratchBytes = 16L * 1024L * 1024L * 1024L,
        )
        assertEquals(16L * 1024L * 1024L * 1024L, fullTreeFunctionTruthV3SharedScratchBound(sharedScratchLimits))
        assertTrue(fullTreeFunctionTruthV3HasDatabaseScratchCapacity(sharedScratchLimits))
        assertTrue(sharedScratchLimits.observationV2.maximumScratchBytes < sharedScratchLimits.maximumScratchBytes)
        assertTrue(sharedScratchLimits.truth.maximumScratchBytes < sharedScratchLimits.maximumScratchBytes)

        assertEquals(6L to 4L, fullTreeFunctionTruthV3AccumulateShardBudget(0L, 0L, 6L, 4L, 10L, 10L))
        assertEquals(10L to 10L, fullTreeFunctionTruthV3AccumulateShardBudget(6L, 4L, 4L, 6L, 10L, 10L))
        assertFailsWith<IllegalArgumentException> {
            // Each phase is below the authenticated cap, but their accumulated wall time is not.
            fullTreeFunctionTruthV3AccumulateShardBudget(6L, 0L, 5L, 0L, 10L, 10L)
        }
        assertFailsWith<IllegalArgumentException> {
            // Cumulative CPU is checked independently of wall time.
            fullTreeFunctionTruthV3AccumulateShardBudget(0L, 7L, 0L, 4L, 10L, 10L)
        }

        var wallNanos = 0L
        var cpuNanos = 0L
        val ledger = FullTreeFunctionTruthV3ShardPhaseLedger(
            maximumWallNanos = 10L,
            maximumCpuNanos = 10L,
            wallClock = { wallNanos },
            cpuClock = { cpuNanos },
        )
        FullTreeOracleOperationCheckpoint.withCheckpoint({}, ledger) {
            FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                wallNanos += 2L
                cpuNanos += 2L
                FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                    assertEquals(1, ledger.activeShardCount())
                    wallNanos += 3L
                    cpuNanos += 3L
                }
            }
            FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                wallNanos += 5L
                cpuNanos += 5L
            }
            assertFailsWith<IllegalArgumentException>("nested callbacks share one cumulative shard wall/CPU budget") {
                FullTreeOracleOperationCheckpoint.withShardPhase("nested-shard") {
                    wallNanos += 1L
                    cpuNanos += 1L
                }
            }
        }
    }

    @Test
    fun `legacy truth v2 composition snapshot authenticates receipt bytes before projection`() =
        inControlTemporaryDirectory { root ->
            val truthRoot = privateDirectory(root.resolve("legacy-truth"))
            val shards = privateDirectory(truthRoot.resolve("shards"))
            val shardBytes = "{\"fixture\":\"truth-shard\"}".toByteArray(StandardCharsets.UTF_8)
            val exclusionBytes = "{\"fixture\":\"exclusions\"}".toByteArray(StandardCharsets.UTF_8)
            Files.write(shards.resolve("fixture.json"), shardBytes)
            Files.write(truthRoot.resolve("exclusions.json"), exclusionBytes)
            val shardRecord = v2FileRecord("fixture", "shards/fixture.json", shardBytes)
            val exclusionRecord = v2FileRecord("elf-only-exclusions", "exclusions.json", exclusionBytes)
            val counts = JsonObject(listOf(
                "elfRvas", "dwarfRvas", "scoredRvas", "elfOnlyRvas", "dwarfOnlyRvas",
                "nonEmittedObservations", "nonEmittedUnique", "inlineOnlyUnique", "selectedElsewhereUnique",
                "definitionNoRangeUnique", "coalescedEmittedRvas",
            ).associateWith { JsonPrimitive(0L) })
            val withoutHash = JsonObject(mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to counts,
                "exclusions" to exclusionRecord,
                "oracle" to JsonObject(emptyMap()),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(listOf(shardRecord)),
            ))
            val logicalSha = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash))
            val index = JsonObject(withoutHash + ("indexSha256" to JsonPrimitive(logicalSha)))
            OracleSchemas.validate("full-tree-function-truth-index", index)
            val indexBytes = OracleJson.canonicalBytes(index)
            val indexSha = OracleArtifacts.sha256(indexBytes)
            Files.write(truthRoot.resolve("index.json"), indexBytes)
            val outputBytes = indexBytes.size.toLong() + shardBytes.size.toLong() + exclusionBytes.size.toLong()
            val receipt = FullTreeFunctionTruthGeneration(
                root = truthRoot,
                index = index,
                indexArtifactSha256 = indexSha,
                indexSha256 = logicalSha,
                observationIndexArtifactSha256 = "a".repeat(64),
                elfIndexArtifactSha256 = "b".repeat(64),
                outputBytes = outputBytes,
                databaseHighWaterBytes = 0L,
                counts = FullTreeFunctionTruthCounts(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0),
            )

            val workspace = privateDirectory(root.resolve("workspace"))
            var transientMutationObserved = false
            assertFailsWith<FullTreeFunctionTruthV3Exception>(
                "composition pinning must reject a transient rewrite even if later revalidation sees restored bytes",
            ) {
                FullTreeFunctionTruthSqliteV3.snapshotLegacyTruthV3(receipt, workspace, FullTreeFunctionTruthV3Limits()) { stage ->
                    if (!transientMutationObserved && stage == "before pinning truth-v3 tree member shards/fixture.json") {
                        Files.write(shards.resolve("fixture.json"), "{\"fixture\":\"other-shard\"}".toByteArray(StandardCharsets.UTF_8))
                        transientMutationObserved = true
                    }
                }
            }
            assertTrue(transientMutationObserved, "the legacy truth mutation must overlap receipt-authenticated pinning")
            Files.write(shards.resolve("fixture.json"), shardBytes)
            assertEquals(shardBytes.toList(), Files.readAllBytes(shards.resolve("fixture.json")).toList(),
                "later legacy V2 revalidation would see the restored original bytes")

            val pinnedWorkspace = privateDirectory(root.resolve("workspace-pinned"))
            val snapshot = FullTreeFunctionTruthSqliteV3.snapshotLegacyTruthV3(
                receipt, pinnedWorkspace, FullTreeFunctionTruthV3Limits(),
            )
            assertEquals(shardBytes.toList(), Files.readAllBytes(snapshot.root.resolve("shards/fixture.json")).toList())
            snapshot.verifyPrivateSnapshotUnchanged()
        }

    @Test
    fun `truth v3 rederives observation census and preserves one score row per RVA`() =
        inControlTemporaryDirectory { root ->
            val fixture = createCompilerFixture(root, perShardResidentBytes = 1792L * 1024L * 1024L)
            val limits = tightScratchLimits().copy(maximumRetainedWorkingSetBytes = 2L * 1024L * 1024L * 1024L)
            val firstTraversal = SourceTraversalTrace(FullTreeSourceIdentityTraversalOrder.FORWARD)
            val first = FullTreeFunctionTruthSqliteV3.generateAndPublish(
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                outputRoot = root.resolve("truth-v3-first"),
                limits = limits,
                traversal = firstTraversal.traversal,
            )
            val second = FullTreeFunctionTruthSqliteV3.generateAndPublish(
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                outputRoot = root.resolve("truth-v3-second"),
                limits = limits.copy(
                    maximumOutputBytes = first.outputBytes,
                    truth = limits.truth.copy(maximumOutputBytes = minOf(limits.truth.maximumOutputBytes, first.outputBytes - 1L)),
                ),
            )

            val narrowNestedTruthOutput = minOf(limits.truth.maximumOutputBytes, first.outputBytes - 1L)
            assertTrue(narrowNestedTruthOutput < first.outputBytes, "V3's census output must have its own output allowance")
            assertFailsWith<FullTreeFunctionTruthV3Exception>("one byte below generated V3 bytes must reject publication") {
                FullTreeFunctionTruthSqliteV3.generateAndPublish(
                    richArtifact = fixture.rich,
                    strippedArtifact = fixture.stripped,
                    inventoryPath = fixture.inventoryPath,
                    elfFunctionIndex = fixture.elfIndex,
                    observationV2Root = fixture.observationV2Root,
                    expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                    scope = fixture.scope,
                    scratchParent = fixture.scratch,
                    outputRoot = root.resolve("truth-v3-one-over-output-limit"),
                    limits = limits.copy(
                        maximumOutputBytes = first.outputBytes - 1L,
                        truth = limits.truth.copy(maximumOutputBytes = narrowNestedTruthOutput),
                    ),
                )
            }
            assertFalse(Files.exists(root.resolve("truth-v3-one-over-output-limit")))

            assertEquals(first.index, second.index)
            assertEquals(first.indexArtifactSha256, second.indexArtifactSha256)
            assertEquals(first.indexSha256, second.indexSha256)
            assertEquals(first.counts, second.counts)
            assertEquals(v3TreeBytes(first.root), v3TreeBytes(second.root))
            writeFixtureVector(fixture, first)
            assertCompilerTraversalParity(fixture, root, limits, first, firstTraversal)
            assertFalse(first.authoritativeReleaseEvidence)
            assertFalse(first.productionQualification)
            assertFalse(first.downstreamScoringAuthorized)
            assertEquals(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, OracleSchemas.identity(
                FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME,
            ).name)
            assertEquals(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, OracleSchemas.identity(
                FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME,
            ).name)
            assertEquals("full-tree-function-truth", FullTreeFunctionTruthSqliteV3.producerPolicy.controlString("id"))
            assertEquals(3L, FullTreeFunctionTruthSqliteV3.producerPolicy.controlLong("version"))
            assertEquals(
                "b21be27d085c61c60cbaba11da1208b24c897c264001c790b0ca32b2ae24e5f7",
                OracleSchemas.identity("full-tree-function-truth").sha256,
                "the v2 shard schema bytes must stay frozen",
            )
            assertEquals(
                "40a2c4d0c3a1b3317e010fd267b56e6ea3ec94620abd79c591b01bc6357e084f",
                OracleSchemas.identity("full-tree-function-truth-index").sha256,
                "the v2 index schema bytes must stay frozen",
            )
            assertEquals(
                "a59e80ed0cd440f07be4741892d75ba5a3514532a73ecb67bbc617b4d24a34c2",
                FullTreeFunctionTruthSqliteV3.configurationSha256,
            )
            assertEquals(
                "17c61e43524b98a215075b82fa50732d6d8f50d883dce235e511731612da04e5",
                FullTreeFunctionTruthSqlite.configurationSha256,
                "adding v3 must preserve the frozen truth-v2 digest",
            )

            val index = parseControlObject(first.root.resolve("index.json"))
            OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, index)
            assertEquals(2L, index.controlLong("schemaVersion"))
            assertEquals(
                fixture.observationV2IndexSha256,
                first.observationV2IndexArtifactSha256,
                "public generation completes final raw observation-v2 revalidation from a pinned tree with disjoint scratch",
            )
            assertEquals(first.counts.sourceEntities, index.controlObject("counts").controlLong("sourceEntities"))
            assertTrue(first.counts.sourceEntities > 0L, "compiler fixture must exercise source census projection")
            assertCensusCounts(first.root, index)
            assertConcreteTemplateShapes(first.root)
            val wholeTruthEntities = Math.addExact(
                Math.addExact(first.counts.functions.elfRvas, first.counts.functions.dwarfOnlyRvas),
                first.counts.functions.nonEmittedUnique,
            )
            val exactWholeCombined = fullTreeFunctionTruthV3CombinedEntityCount(
                wholeTruthEntities,
                first.counts.sourceEntities,
                Math.addExact(wholeTruthEntities, first.counts.sourceEntities),
            )
            assertEquals(Math.addExact(wholeTruthEntities, first.counts.sourceEntities), exactWholeCombined)
            assertFailsWith<IllegalArgumentException>("one fewer whole-run entity must reject actual V3 evidence") {
                fullTreeFunctionTruthV3CombinedEntityCount(
                    wholeTruthEntities,
                    first.counts.sourceEntities,
                    exactWholeCombined - 1L,
                )
            }
            index.controlArray("shards").forEach { raw ->
                val record = raw as JsonObject
                val shard = parseControlObject(first.root.resolve(record.controlString("path")))
                val counts = shard.controlObject("counts")
                val shardTruthEntities = Math.addExact(
                    counts.controlLong("functions"),
                    counts.controlLong("nonEmitted"),
                )
                val exactPerShardCombined = Math.addExact(shardTruthEntities, counts.controlLong("sourceEntities"))
                assertEquals(
                    exactPerShardCombined,
                    fullTreeFunctionTruthV3CombinedEntityCount(
                        shardTruthEntities, counts.controlLong("sourceEntities"), exactPerShardCombined,
                    ),
                )
                assertFailsWith<IllegalArgumentException>("one fewer per-shard entity must reject actual V3 evidence") {
                    fullTreeFunctionTruthV3CombinedEntityCount(
                        shardTruthEntities, counts.controlLong("sourceEntities"), exactPerShardCombined - 1L,
                    )
                }
            }
            assertPublicEntityBoundEnforcement(first, fixture, root, limits)

            val emittedRvaRows = index.controlArray("shards").flatMap { raw ->
                val shardRecord = raw as JsonObject
                parseControlObject(first.root.resolve(shardRecord.controlString("path")))
                    .controlArray("functions").controlObjects("truth functions")
                    .map { it.controlString("rva") }
            }
            val fullRunEmittedRvas = emittedRvaRows.toSet()
            assertEquals(emittedRvaRows.size, fullRunEmittedRvas.size, "truth rows must be unique across the full run")
            val scoreRvas = HashSet<String>()
            val scoreRowCount = index.controlArray("shards").sumOf { raw ->
                val shardRecord = raw as JsonObject
                val shard = parseControlObject(first.root.resolve(shardRecord.controlString("path")))
                OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, shard)
                val functions = shard.controlArray("functions").controlObjects("truth functions")
                assertEquals(functions.size.toLong(), shard.controlObject("counts").controlLong("functions"))
                assertEquals(shard.controlArray("sourceEntities").size.toLong(), shard.controlObject("counts").controlLong("sourceEntities"))
                val rvas = functions.map { it.controlString("rva") }
                assertEquals(rvas.size, rvas.distinct().size, "source census must not duplicate score rows")
                assertTrue(rvas.all(scoreRvas::add), "an emitted RVA may have only one truth row across the full run")
                shard.controlArray("sourceEntities").controlObjects("source entities").forEach { entity ->
                    val linked = entity["linkedEmittedRva"]
                    if (entity.controlString("denominatorDisposition") == "emitted-rva-link") {
                        assertTrue(linked is JsonPrimitive && linked.content in fullRunEmittedRvas)
                    } else {
                        assertEquals(JsonNull, linked, "non-linked source facts must not create score rows")
                    }
                }
                functions.size.toLong()
            }
            assertEquals(first.counts.functions.dwarfRvas, scoreRowCount)
            assertEquals(
                first.counts.functions.scoredRvas,
                index.controlArray("shards").sumOf { raw ->
                    parseControlObject(first.root.resolve((raw as JsonObject).controlString("path")))
                        .controlArray("functions").controlObjects("truth functions")
                        .count { it.controlString("population") == "scored" }.toLong()
                },
            )

            val validated = FullTreeFunctionTruthSqliteV3.loadAndValidate(
                candidateRoot = first.root,
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                limits = limits.copy(truth = limits.truth.copy(maximumOutputBytes = narrowNestedTruthOutput)),
            )
            assertTrue(
                validated.rawInputsRederived,
                "public validation completes final raw observation-v2 revalidation from a pinned tree with disjoint scratch",
            )
            assertTrue(validated.candidateBytesMatchedAtValidationBoundary)
            assertFalse(validated.candidateLeaseRetained)
            assertFalse(validated.downstreamScoringAuthorized)
            assertFalse(validated.authoritativeReleaseEvidence)
            assertEquals(first.indexArtifactSha256, validated.indexArtifactSha256)
            assertEquals(first.outputBytes, validated.outputBytes)

            val forged = copyTree(first.root, root.resolve("truth-v3-forged"))
            mutateAndRehashSourceIdentity(forged)
            val forgedBytes = v3TreeBytes(forged)
            assertFailsWith<FullTreeFunctionTruthV3Exception> {
                FullTreeFunctionTruthSqliteV3.loadAndValidate(
                    candidateRoot = forged,
                    richArtifact = fixture.rich,
                    strippedArtifact = fixture.stripped,
                    inventoryPath = fixture.inventoryPath,
                    elfFunctionIndex = fixture.elfIndex,
                    observationV2Root = fixture.observationV2Root,
                    expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                    scope = fixture.scope,
                    scratchParent = fixture.scratch,
                    limits = limits,
                )
            }
            assertEquals(forgedBytes, v3TreeBytes(forged), "rejected candidate bytes remain unchanged")

            assertSelfConsistentMutationsRejected(first, root)
            assertV3RawInputPathReplacementIsDetected(fixture, root)
            assertV3CandidateSnapshotRejectsRaces(first, root)
            assertV3StagingIsReauthenticatedAroundFreeze(first, root)
            assertV3ObservationSnapshotRejectsTreeSwap(fixture, root)
            assertDirectoryEmpty(fixture.scratch)
        }

    /** Shares the compiled ELF and pinned observation receipt across all execution orders. */
    private fun assertCompilerTraversalParity(
        fixture: V3Fixture,
        root: Path,
        limits: FullTreeFunctionTruthV3Limits,
        baselineTruth: FullTreeFunctionTruthV3Generation,
        baselineTruthTrace: SourceTraversalTrace,
    ) {
        val inventory = parseControlObject(fixture.inventoryPath)
        val inventorySha256 = fixtureSha256(fixture.inventoryPath)
        val shard = FullTreeFunctionObservations.shardInputs(
            inventory, inventorySha256, fixture.scope.document, fixture.scope.sha256,
        ).single()
        val baselineObservationBytes = Files.readAllBytes(
            fixture.observationV2Root.resolve("outputs/${shard.identifier}.json"),
        )
        val baselineTruthBytes = v3TreeBytes(baselineTruth.root)
        val inputHashes = listOf(fixture.rich, fixture.stripped, fixture.inventoryPath, fixture.elfIndex)
            .associateWith(::fixtureSha256)
        var baselineSourceTrace: SourceTraversalTrace? = null
        var baselineSourceScan: FullTreeSourceEntityIdentityScan? = null
        var baselineReconciliation: FullTreeFunctionObservationV2IdentityReconciliation? = null
        val reports = ArrayList<JsonObject>()
        FullTreeSourceIdentityTraversalOrder.entries.forEach { order ->
            val sourceTrace = SourceTraversalTrace(order)
            val source = FullTreeSourceEntityIdentityProducer.scanShard(
                richArtifact = fixture.rich,
                inventoryPath = fixture.inventoryPath,
                scope = fixture.scope,
                shardId = shard.identifier,
                scratchParent = fixture.scratch,
                controlLimits = limits.observationV2.shard.control,
                producerLimits = limits.observationV2.shard.producer,
                traversal = sourceTrace.traversal,
            )
            if (baselineSourceTrace == null) {
                baselineSourceTrace = sourceTrace
                baselineSourceScan = source
            }
            sourceTrace.assertPermutationOf(requireNotNull(baselineSourceTrace))
            assertEquals(baselineSourceScan!!.facts, source.facts, "$order source facts, IDs, links and edges")
            assertEquals(baselineSourceScan!!.canonicalSha256, source.canonicalSha256, "$order canonical source bytes")
            assertEquals(baselineSourceScan!!.canonicalBytes, source.canonicalBytes)
            assertEquals(baselineSourceScan!!.scannedDies, source.scannedDies)

            val publicationTrace = SourceTraversalTrace(order)
            val publication = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
                richArtifact = fixture.rich,
                inventoryPath = fixture.inventoryPath,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                outputRoot = root.resolve("observations-v2-${order.name.lowercase()}"),
                maximumWorkers = 2,
                limits = limits.observationV2,
                traversal = publicationTrace.traversal,
            )
            assertEquals(1, publication.maximumWorkers, "the real compiler fixture has one authenticated shard")
            publicationTrace.assertPasses(sourceTrace, 1)
            if (baselineReconciliation == null) baselineReconciliation = publication.reconciliation
            assertEquals(baselineReconciliation, publication.reconciliation, "$order full-run collision population")
            assertEquals(fixture.observationV2IndexSha256, publication.binding.indexArtifactSha256)
            assertEquals(v3TreeBytes(fixture.observationV2Root), v3TreeBytes(publication.binding.root))

            // The memory path consumes a fresh authenticated function scan and independently
            // extracted source facts, with the same production reconciliation used by SQLite.
            val memory = FullTreeFunctionObservationAccumulatorV2(shard)
            val functionScan = FullTreeFunctionObservationProducer.scanAuthenticatedShardWithLimits(
                richArtifact = fixture.rich,
                scope = fixture.scope,
                inputs = FullTreeFunctionObservationAuthenticatedInputs(inventory, inventorySha256, shard),
                scratchParent = fixture.scratch,
                controlLimits = limits.observationV2.shard.control,
                producerLimits = limits.observationV2.shard.producer,
                recordScannedDies = memory::recordScannedDies,
                accept = memory::accept,
            )
            reconcileObservationV2Facts(source.facts, publication.reconciliation).forEach(memory::acceptSourceEntity)
            val memoryDocument = memory.finish(
                inventoryIndexSha256 = inventory.controlString("indexSha256"),
                richArtifactSha256 = functionScan.richArtifactSha256,
                scopeSha256 = fixture.scope.sha256,
                reconciliation = publication.reconciliation,
            )
            FullTreeFunctionObservationsV2.validateEnvelope(
                memoryDocument, fixture.scope, inventory, inventorySha256, shard, publication.reconciliation,
            )
            val memoryBytes = FullTreeFunctionObservationsV2.canonicalEnvelopeBytes(memoryDocument)
            assertContentEquals(baselineObservationBytes, memoryBytes, "$order memory/SQLite canonical shard parity")
            val emittedRvas = memoryDocument.controlArray("emitted").controlObjects("emitted functions")
                .map { it.controlString("rva") }
            assertEquals(emittedRvas.size, emittedRvas.toSet().size, "$order emitted RVA uniqueness")

            val validationTrace = SourceTraversalTrace(order)
            val validatedObservation = FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
                candidateRoot = fixture.observationV2Root,
                expectedIndexArtifactSha256 = fixture.observationV2IndexSha256,
                richArtifact = fixture.rich,
                inventoryPath = fixture.inventoryPath,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                limits = limits.observationV2,
                traversal = validationTrace.traversal,
            )
            validationTrace.assertPasses(sourceTrace, 1)
            assertEquals(publication.outputs, validatedObservation.outputs)
            assertEquals(publication.reconciliation, validatedObservation.reconciliation)

            val truthTrace = if (order == FullTreeSourceIdentityTraversalOrder.FORWARD) baselineTruthTrace
                else SourceTraversalTrace(order)
            val truth = if (order == FullTreeSourceIdentityTraversalOrder.FORWARD) baselineTruth else
                FullTreeFunctionTruthSqliteV3.generateAndPublish(
                    richArtifact = fixture.rich,
                    strippedArtifact = fixture.stripped,
                    inventoryPath = fixture.inventoryPath,
                    elfFunctionIndex = fixture.elfIndex,
                    observationV2Root = fixture.observationV2Root,
                    expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                    scope = fixture.scope,
                    scratchParent = fixture.scratch,
                    outputRoot = root.resolve("truth-v3-${order.name.lowercase()}"),
                    limits = limits,
                    traversal = truthTrace.traversal,
                )
            truthTrace.assertPasses(sourceTrace, 2) // Initial authentication and the final publication recheck.
            assertEquals(baselineTruthBytes, v3TreeBytes(truth.root), "$order complete truth-v3 tree")
            assertEquals(baselineTruth.counts, truth.counts)
            val truthValidationTrace = SourceTraversalTrace(order)
            val validatedTruth = FullTreeFunctionTruthSqliteV3.loadAndValidate(
                candidateRoot = baselineTruth.root,
                richArtifact = fixture.rich,
                strippedArtifact = fixture.stripped,
                inventoryPath = fixture.inventoryPath,
                elfFunctionIndex = fixture.elfIndex,
                observationV2Root = fixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = fixture.observationV2IndexSha256,
                scope = fixture.scope,
                scratchParent = fixture.scratch,
                limits = limits,
                traversal = truthValidationTrace.traversal,
            )
            truthValidationTrace.assertPasses(sourceTrace, 2) // Both validation authentications use this order.
            assertTrue(validatedTruth.rawInputsRederived && validatedTruth.candidateBytesMatchedAtValidationBoundary)
            assertEquals(baselineTruth.indexArtifactSha256, validatedTruth.indexArtifactSha256)
            assertEquals(inputHashes, inputHashes.keys.associateWith(::fixtureSha256))
            assertDirectoryEmpty(fixture.scratch)
            reports += JsonObject(mapOf(
                "order" to JsonPrimitive(order.name),
                "visits" to sourceTrace.canonicalVisits(),
                "sourceCanonicalSha256" to JsonPrimitive(source.canonicalSha256),
                "sourceEntityCount" to JsonPrimitive(source.facts.size),
                "observationShardSha256" to JsonPrimitive(OracleArtifacts.sha256(memoryBytes)),
                "observationIndexArtifactSha256" to JsonPrimitive(publication.binding.indexArtifactSha256),
                "collisionPopulation" to publication.reconciliation.canonicalJson(),
                "truthIndexArtifactSha256" to JsonPrimitive(truth.indexArtifactSha256),
                "effectiveWorkers" to JsonPrimitive(publication.maximumWorkers),
                "v2GenerationPasses" to JsonPrimitive(1),
                "v2ValidationPasses" to JsonPrimitive(1),
                "v3GenerationPasses" to JsonPrimitive(2),
                "v3ValidationPasses" to JsonPrimitive(2),
            ))
        }
        val report = JsonObject(mapOf(
            "fixtureOnly" to JsonPrimitive(true),
            "richArtifactSha256" to JsonPrimitive(fixtureSha256(fixture.rich)),
            "inventoryArtifactSha256" to JsonPrimitive(inventorySha256),
            "scopeSha256" to JsonPrimitive(fixture.scope.sha256),
            "orders" to JsonArray(reports),
        ))
        val reportPath = Path.of(System.getProperty("user.dir"))
            .resolve("build/test-results/test/full-tree-source-traversal-v2-v3.json")
        Files.createDirectories(reportPath.parent)
        Files.write(reportPath, OracleJson.canonicalBytes(report))
    }

    private class SourceTraversalTrace(private val order: FullTreeSourceIdentityTraversalOrder) {
        private val visits = ArrayList<Triple<String, Long, Long?>>()
        val traversal = FullTreeSourceIdentityTraversal(order) { phase, cu, die ->
            check(visits.size < 100_000) { "compiler fixture traversal trace exceeds its fixed bound" }
            visits += Triple(phase, cu, die)
        }

        fun assertPasses(singlePass: SourceTraversalTrace, count: Int) {
            assertEquals(List(count) { singlePass.visits }.flatten(), visits, "$order actual raw-input passes")
        }

        fun assertPermutationOf(forward: SourceTraversalTrace) {
            assertEquals(forward.visits.toSet(), visits.toSet(), "$order identical authenticated visit membership")
            assertEquals(visits.size, visits.toSet().size, "$order visits each CU/DIE/map entry exactly once")
            assertSourceIdentityTraversalPermutation(forward.visits, visits, order, "V2/V3 $order")
        }

        fun canonicalVisits(): JsonArray = JsonArray(visits.map { (phase, cu, die) ->
            JsonObject(mapOf(
                "phase" to JsonPrimitive(phase),
                "compilationUnitOffset" to JsonPrimitive(cu),
                "dieOffset" to (die?.let(::JsonPrimitive) ?: JsonNull),
            ))
        })
    }

    private fun assertSelfConsistentMutationsRejected(
        expected: FullTreeFunctionTruthV3Generation,
        root: Path,
    ) {
        val index = parseControlObject(expected.root.resolve("index.json"))
        val shard = parseControlObject(expected.root.resolve((index.controlArray("shards").single() as JsonObject).controlString("path")))
        val rows = shard.controlArray("sourceEntities").controlObjects("source entities")
        val rvas = shard.controlArray("functions").controlObjects("functions").map { it.controlString("rva") }
        assertTrue(rows.any { it.controlString("entityKind") == "declaration-only" }, "declaration promotion case must exist")
        val inlineOrigin = rows.firstOrNull { row ->
            row.controlString("entityKind") == "inline-instance" && row.controlArray("edges").any { raw ->
                val edge = raw as? JsonObject ?: return@any false
                edge.controlString("kind") == "abstract-origin" && edge.controlString("state") == "resolved" &&
                    (edge["target"] as? JsonPrimitive)?.isString == true
            }
        } ?: error("fixture must contain a resolved inline abstract-origin row")
        val intTemplate = rows.first { row ->
            row.controlString("entityKind") == "template-instance" &&
                row.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                    .any { it.toString().contains("int") } && row["semanticAnchorCandidateId"] != JsonNull
        }
        val longTemplate = rows.first { row ->
            row.controlString("entityKind") == "template-instance" &&
                row.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                    .any { it.toString().contains("long") } && row["semanticAnchorCandidateId"] != JsonNull
        }
        val linked = rows.first { it.controlString("denominatorDisposition") == "emitted-rva-link" }
        assertTrue(rvas.size > 1 && linked["linkedEmittedRva"] != JsonNull, "link mutation case must have alternate emitted RVAs")

        val cases = listOf(
            V3Mutation("candidate identity", rows.first { it["semanticAnchorCandidateId"] != JsonNull }) { row ->
                val current = (row["semanticAnchorCandidateId"] as JsonPrimitive).content
                row.withField("semanticAnchorCandidateId", JsonPrimitive(if (current == "a".repeat(64)) "b".repeat(64) else "a".repeat(64)))
            },
            V3Mutation("source category", rows.first { it.controlString("entityKind") == "declaration-only" }) { row ->
                row.withField("entityKind", JsonPrimitive("unresolved"))
            },
            V3Mutation("declaration promoted to scored", rows.first { it.controlString("entityKind") == "declaration-only" }) { row ->
                row.withField("denominatorDisposition", JsonPrimitive("emitted-rva-link"))
                    .withField("linkedEmittedRva", JsonPrimitive(rvas.first()))
            },
            V3Mutation("inline instance promoted to scored", inlineOrigin) { row ->
                row.withField("denominatorDisposition", JsonPrimitive("emitted-rva-link"))
                    .withField("linkedEmittedRva", JsonPrimitive(rvas.first()))
            },
            V3Mutation("denominator disposition", linked) { row ->
                row.withField("denominatorDisposition", JsonPrimitive("non-scoreable"))
                    .withField("linkedEmittedRva", JsonNull)
            },
            V3Mutation("emitted RVA link", linked) { row ->
                val old = row.controlString("linkedEmittedRva")
                row.withField("linkedEmittedRva", JsonPrimitive(rvas.first { it != old }))
            },
            V3Mutation("resolved identity", inlineOrigin) { row ->
                row.withField("resolvedSemanticIdentityId", JsonPrimitive("c".repeat(64)))
            },
            V3Mutation("inline origin edge", inlineOrigin) { row ->
                row.withField("edges", JsonArray(row.controlArray("edges").map { raw ->
                    val edge = raw as? JsonObject ?: return@map raw
                    if (edge.controlString("kind") == "abstract-origin") {
                        edge.withField("target", JsonPrimitive("forged-origin-target"))
                    } else edge
                }))
            },
            V3Mutation("generic template pattern proof", intTemplate) { row ->
                val fields = row.controlObject("semanticAnchorFields").withField(
                    "templatePatternAnchorCandidateId", JsonPrimitive("d".repeat(64)),
                )
                row.withField("semanticAnchorFields", fields)
            },
            V3Mutation("merge typed int and long instances", intTemplate) { row ->
                row.withField("semanticAnchorCandidateId", longTemplate["semanticAnchorCandidateId"]!!)
            },
            V3Mutation("collision evidence", rows.first()) { row ->
                row.withField("candidateCollisionSourceEntityIds", JsonArray(listOf(JsonPrimitive("e".repeat(64)))))
            },
            V3Mutation("duplicate physical row id", rows.last()) { row ->
                row.withField("sourceEntityId", JsonPrimitive(rows.first().controlString("sourceEntityId")))
            },
        )
        cases.forEachIndexed { indexInCases, case ->
            assertTrue(case.row in rows, "${case.name} mutation must select a fixture row")
            val candidate = copyTree(expected.root, root.resolve("truth-v3-mutation-$indexInCases"))
            mutateAndRehashSourceRow(candidate, case.row.controlString("sourceEntityId"), case.mutate)
            val changedIndex = parseControlObject(candidate.resolve("index.json"))
            OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, changedIndex)
            Files.list(candidate.resolve("shards")).use { paths ->
                paths.forEach { OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, parseControlObject(it)) }
            }
            assertFailsWith<FullTreeFunctionTruthV3Exception>("rehashed ${case.name} mutation must fail raw-derived byte comparison") {
                FullTreeFunctionTruthSqliteV3.compareV3CandidateTreeBytes(
                    candidate,
                    expected.root,
                    changedIndex.controlArray("shards").size.toLong() + 2L,
                    expected.outputBytes,
                )
            }
        }
    }

    private fun assertPublicEntityBoundEnforcement(
        baseline: FullTreeFunctionTruthV3Generation,
        fixture: V3Fixture,
        root: Path,
        limits: FullTreeFunctionTruthV3Limits,
    ) {
        val wholeTruthEntities = Math.addExact(
            Math.addExact(baseline.counts.functions.elfRvas, baseline.counts.functions.dwarfOnlyRvas),
            baseline.counts.functions.nonEmittedUnique,
        )
        val exactWholeRunEntities = Math.addExact(wholeTruthEntities, baseline.counts.sourceEntities)
        val baselineIndex = parseControlObject(baseline.root.resolve("index.json"))
        val exactV3PerShardEntities = baselineIndex.controlArray("shards").maxOf { raw ->
            val record = raw as JsonObject
            val shard = parseControlObject(baseline.root.resolve(record.controlString("path")))
            val counts = shard.controlObject("counts")
            Math.addExact(
                Math.addExact(counts.controlLong("functions"), counts.controlLong("nonEmitted")),
                counts.controlLong("sourceEntities"),
            )
        }
        val exactPerShardEntities = maxOf(exactV3PerShardEntities, fixture.observationV2PerShardEntityCount)
        assertTrue(exactPerShardEntities > 0L)
        assertTrue(exactPerShardEntities <= exactWholeRunEntities)
        val oneUnderWholeRun = exactWholeRunEntities - 1L
        assertTrue(oneUnderWholeRun >= exactPerShardEntities,
            "fixture must permit an independently under-bounded whole-run scope")
        assertTrue(fixture.observationV2EntityCount <= oneUnderWholeRun,
            "V2 raw population must fit one below V3's complete truth population")

        val exactFixture = rebindEntityBounds(
            fixture,
            root.resolve("entity-bound-exact-inputs"),
            wholeRunEntities = exactWholeRunEntities,
            perShardEntities = exactPerShardEntities,
        )
        val exactOutput = root.resolve("truth-v3-entity-bound-exact")
        val exact = FullTreeFunctionTruthSqliteV3.generateAndPublish(
            richArtifact = exactFixture.rich,
            strippedArtifact = exactFixture.stripped,
            inventoryPath = exactFixture.inventoryPath,
            elfFunctionIndex = exactFixture.elfIndex,
            observationV2Root = exactFixture.observationV2Root,
            expectedObservationV2IndexArtifactSha256 = exactFixture.observationV2IndexSha256,
            scope = exactFixture.scope,
            scratchParent = exactFixture.scratch,
            outputRoot = exactOutput,
            limits = limits,
        )
        assertEquals(exactWholeRunEntities, exact.counts.functions.elfRvas + exact.counts.functions.dwarfOnlyRvas +
            exact.counts.functions.nonEmittedUnique + exact.counts.sourceEntities)
        val exactPublishedV3PerShardEntities = exact.index.controlArray("shards").maxOf { raw ->
            val record = raw as JsonObject
            val shard = parseControlObject(exact.root.resolve(record.controlString("path")))
            val counts = shard.controlObject("counts")
            counts.controlLong("functions") + counts.controlLong("nonEmitted") + counts.controlLong("sourceEntities")
        }
        assertEquals(exactV3PerShardEntities, exactPublishedV3PerShardEntities)
        assertTrue(exactPublishedV3PerShardEntities <= exactPerShardEntities)
        val validated = FullTreeFunctionTruthSqliteV3.loadAndValidate(
            candidateRoot = exact.root,
            richArtifact = exactFixture.rich,
            strippedArtifact = exactFixture.stripped,
            inventoryPath = exactFixture.inventoryPath,
            elfFunctionIndex = exactFixture.elfIndex,
            observationV2Root = exactFixture.observationV2Root,
            expectedObservationV2IndexArtifactSha256 = exactFixture.observationV2IndexSha256,
            scope = exactFixture.scope,
            scratchParent = exactFixture.scratch,
            limits = limits,
        )
        assertTrue(validated.rawInputsRederived, "public validation accepts authenticated exact entity bounds")
        assertEquals(exact.indexArtifactSha256, validated.indexArtifactSha256)

        val underFixture = rebindEntityBounds(
            fixture,
            root.resolve("entity-bound-under-inputs"),
            wholeRunEntities = oneUnderWholeRun,
            perShardEntities = exactPerShardEntities,
        )
        assertEquals(fixture.observationV2EntityCount, underFixture.observationV2EntityCount)
        val rejectedOutput = root.resolve("truth-v3-entity-bound-one-under")
        assertFailsWith<FullTreeFunctionTruthV3Exception>(
            "public generation rejects an authenticated whole-run bound one below actual V3 evidence",
        ) {
            FullTreeFunctionTruthSqliteV3.generateAndPublish(
                richArtifact = underFixture.rich,
                strippedArtifact = underFixture.stripped,
                inventoryPath = underFixture.inventoryPath,
                elfFunctionIndex = underFixture.elfIndex,
                observationV2Root = underFixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = underFixture.observationV2IndexSha256,
                scope = underFixture.scope,
                scratchParent = underFixture.scratch,
                outputRoot = rejectedOutput,
                limits = limits,
            )
        }
        assertFalse(Files.exists(rejectedOutput, LinkOption.NOFOLLOW_LINKS),
            "an under-bounded public generation must not publish a tree")

        val exactCandidateBefore = v3TreeBytes(exact.root)
        assertFailsWith<FullTreeFunctionTruthV3Exception>(
            "public validation independently rejects the same authenticated under-bound",
        ) {
            FullTreeFunctionTruthSqliteV3.loadAndValidate(
                candidateRoot = exact.root,
                richArtifact = underFixture.rich,
                strippedArtifact = underFixture.stripped,
                inventoryPath = underFixture.inventoryPath,
                elfFunctionIndex = underFixture.elfIndex,
                observationV2Root = underFixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = underFixture.observationV2IndexSha256,
                scope = underFixture.scope,
                scratchParent = underFixture.scratch,
                limits = limits,
            )
        }
        assertEquals(exactCandidateBefore, v3TreeBytes(exact.root),
            "under-bounded public validation leaves the candidate bytes unchanged")

        val oneUnderPerShard = exactV3PerShardEntities - 1L
        assertTrue(oneUnderPerShard > 0L, "the actual V3 per-shard population must allow a positive one-under scope")
        assertTrue(
            fixture.observationV2PerShardEntityCount > oneUnderPerShard,
            "the strict per-shard scope must exercise the independently rederived raw V2 entity admission",
        )
        val perShardUnderFixture = rebindEntityBounds(
            fixture,
            root.resolve("per-shard-entity-bound-under-inputs"),
            wholeRunEntities = exactWholeRunEntities,
            perShardEntities = oneUnderPerShard,
            regenerateObservationV2 = false,
        )
        val perShardRejectedOutput = root.resolve("truth-v3-per-shard-entity-bound-one-under")
        val generationFailure = assertFailsWith<FullTreeFunctionTruthV3Exception>(
            "public generation rejects an authenticated per-shard bound one below actual V3 evidence",
        ) {
            FullTreeFunctionTruthSqliteV3.generateAndPublish(
                richArtifact = perShardUnderFixture.rich,
                strippedArtifact = perShardUnderFixture.stripped,
                inventoryPath = perShardUnderFixture.inventoryPath,
                elfFunctionIndex = perShardUnderFixture.elfIndex,
                observationV2Root = perShardUnderFixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = perShardUnderFixture.observationV2IndexSha256,
                scope = perShardUnderFixture.scope,
                scratchParent = perShardUnderFixture.scratch,
                outputRoot = perShardRejectedOutput,
                limits = limits,
            )
        }
        assertTrue(
            generationFailure.hasCauseMessageFragment("observation-v2 entity population exceeds its authenticated bound"),
            "public generation must independently rederive raw V2 evidence and reject its per-shard entity population under the authenticated V3 scope; " +
                "observed failure chain: ${generationFailure.causeMessageChain()}",
        )
        assertFalse(Files.exists(perShardRejectedOutput, LinkOption.NOFOLLOW_LINKS),
            "an under-bounded public generation must not publish a tree")

        val validationFailure = assertFailsWith<FullTreeFunctionTruthV3Exception>(
            "public validation independently rejects an authenticated per-shard bound one below actual V3 evidence",
        ) {
            FullTreeFunctionTruthSqliteV3.loadAndValidate(
                candidateRoot = exact.root,
                richArtifact = perShardUnderFixture.rich,
                strippedArtifact = perShardUnderFixture.stripped,
                inventoryPath = perShardUnderFixture.inventoryPath,
                elfFunctionIndex = perShardUnderFixture.elfIndex,
                observationV2Root = perShardUnderFixture.observationV2Root,
                expectedObservationV2IndexArtifactSha256 = perShardUnderFixture.observationV2IndexSha256,
                scope = perShardUnderFixture.scope,
                scratchParent = perShardUnderFixture.scratch,
                limits = limits,
            )
        }
        assertTrue(
            validationFailure.hasCauseMessageFragment("observation-v2 entity population exceeds its authenticated bound"),
            "public validation must independently rederive raw V2 per-shard admission under the authenticated V3 scope before comparing the candidate; " +
                "observed failure chain: ${validationFailure.causeMessageChain()}",
        )
        assertEquals(exactCandidateBefore, v3TreeBytes(exact.root),
            "per-shard under-bounded public validation leaves the candidate bytes unchanged")
        assertDirectoryEmpty(exactFixture.scratch)
        assertDirectoryEmpty(underFixture.scratch)
        assertDirectoryEmpty(perShardUnderFixture.scratch)
    }

    private fun JsonObject.withField(name: String, value: JsonElement): JsonObject =
        JsonObject(toMutableMap().apply { put(name, value) })

    private fun assertV3RawInputPathReplacementIsDetected(fixture: V3Fixture, root: Path) {
        val guardedInventory = root.resolve("guarded-inventory.json")
        Files.copy(fixture.inventoryPath, guardedInventory)
        val replacement = root.resolve("replacement-inventory.json")
        Files.write(replacement, Files.readAllBytes(guardedInventory))
        FullTreeFunctionTruthSqliteV3.V3RawInputGuards.open(
            fixture.rich,
            fixture.stripped,
            guardedInventory,
            fixture.elfIndex,
            FullTreeFunctionTruthV3Limits(),
        ).use { guards ->
            Files.delete(guardedInventory)
            Files.move(replacement, guardedInventory, StandardCopyOption.ATOMIC_MOVE)
            assertFailsWith<IllegalArgumentException> {
                guards.verifyUnchanged("post-derivation publication boundary regression")
            }
        }
    }

    private fun assertV3CandidateSnapshotRejectsRaces(
        expected: FullTreeFunctionTruthV3Generation,
        root: Path,
    ) {
        val maximumFiles = expected.index.controlArray("shards").size.toLong() + 2L
        fun pinned(label: String): Pair<Path, FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot> {
            val candidate = copyTree(expected.root, root.resolve("truth-v3-$label-original"))
            val identity = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
                candidate, setOf("shards"), maximumFiles, expected.outputBytes, {},
                setOf("index.json", "exclusions.json"),
            )
            val snapshot = identity.createSnapshot(
                candidate, root.resolve("truth-v3-$label-pinned"), setOf("shards"), null, {}, expected.outputBytes,
            )
            return candidate to snapshot
        }

        val (rewritten, rewrittenSnapshot) = pinned("rewrite-race")
        var rewrote = false
        FullTreeFunctionTruthSqliteV3.compareV3CandidateTreeBytes(
            rewrittenSnapshot.root, expected.root, maximumFiles, expected.outputBytes,
        ) { member ->
            if (member == "exclusions.json" && !rewrote) {
                makeTreeWritable(rewritten)
                val index = rewritten.resolve("index.json")
                val bytes = Files.readAllBytes(index)
                bytes[0] = if (bytes[0] == '{'.code.toByte()) '['.code.toByte() else '{'.code.toByte()
                Files.write(index, bytes)
                rewrote = true
            }
        }
        assertTrue(rewrote, "a later candidate comparison must overlap the in-place rewrite")
        assertFailsWith<FullTreeFunctionTruthV3Exception>("the earlier-compared member remains pinned through final validation") {
            rewrittenSnapshot.verifyOriginalUnchanged()
        }

        val (swapped, swappedSnapshot) = pinned("path-swap-race")
        var swappedMember = false
        FullTreeFunctionTruthSqliteV3.compareV3CandidateTreeBytes(
            swappedSnapshot.root, expected.root, maximumFiles, expected.outputBytes,
        ) { member ->
            if (member == "exclusions.json" && !swappedMember) {
                makeTreeWritable(swapped)
                val shard = Files.list(swapped.resolve("shards")).use { it.findFirst().orElseThrow() }
                val saved = Files.readAllBytes(shard)
                val displaced = shard.resolveSibling("${shard.fileName}.displaced")
                Files.move(shard, displaced, StandardCopyOption.ATOMIC_MOVE)
                Files.write(shard, saved)
                swappedMember = true
            }
        }
        assertTrue(swappedMember, "a later candidate comparison must overlap the path swap")
        assertFailsWith<FullTreeFunctionTruthV3Exception>("byte-identical path replacement must retain its original file identity") {
            swappedSnapshot.verifyOriginalUnchanged()
        }
    }

    private fun assertV3StagingIsReauthenticatedAroundFreeze(
        expected: FullTreeFunctionTruthV3Generation,
        root: Path,
    ) {
        val index = parseControlObject(expected.root.resolve("index.json"))
        val firstShard = expected.root.resolve((index.controlArray("shards").first() as JsonObject).controlString("path"))
        val indexBytes = Files.readAllBytes(expected.root.resolve("index.json"))

        val freezeRace = copyTree(expected.root, root.resolve("truth-v3-staging-freeze-race"))
        makeTreeWritable(freezeRace)
        val freezeRaceIndex = parseControlObject(freezeRace.resolve("index.json"))
        val freezeRaceShard = freezeRace.resolve(expected.root.relativize(firstShard).toString())
        var mutatedDuringFreeze = false
        assertFailsWith<FullTreeFunctionTruthV3Exception>("post-freeze member rehash must reject a mutation during chmod") {
            FullTreeFunctionTruthSqliteV3.freezeAndVerifyV3Staging(
                freezeRace,
                freezeRaceIndex,
                Files.readAllBytes(freezeRace.resolve("index.json")),
                expected.outputBytes,
            ) { stage ->
                if (!mutatedDuringFreeze && stage == "while freezing truth-v3 member ${freezeRaceShard.fileName}") {
                    val changed = Files.readAllBytes(freezeRaceShard)
                    changed[0] = if (changed[0] == '{'.code.toByte()) '['.code.toByte() else '{'.code.toByte()
                    Files.write(freezeRaceShard, changed)
                    mutatedDuringFreeze = true
                }
            }
        }
        assertTrue(mutatedDuringFreeze, "the fixture mutation must overlap staged-file freezing")

        val finalBoundary = copyTree(expected.root, root.resolve("truth-v3-staging-final-boundary"))
        val finalIndex = parseControlObject(finalBoundary.resolve("index.json"))
        val snapshot = FullTreeFunctionTruthSqliteV3.freezeAndVerifyV3Staging(
            finalBoundary,
            finalIndex,
            Files.readAllBytes(finalBoundary.resolve("index.json")),
            expected.outputBytes,
        )
        makeTreeWritable(finalBoundary)
        val finalShard = finalBoundary.resolve(expected.root.relativize(firstShard).toString())
        val changed = Files.readAllBytes(finalShard)
        changed[0] = if (changed[0] == '{'.code.toByte()) '['.code.toByte() else '{'.code.toByte()
        Files.write(finalShard, changed)
        assertFailsWith<FullTreeFunctionTruthV3Exception>("the final rename-boundary rehash must catch a changed staged member") {
            FullTreeFunctionTruthSqliteV3.reauthenticateV3Staging(
                snapshot,
                finalIndex,
                Files.readAllBytes(finalBoundary.resolve("index.json")),
                expected.outputBytes,
            )
        }
        assertEquals(indexBytes.toList(), Files.readAllBytes(expected.root.resolve("index.json")).toList())
    }

    private fun assertV3ObservationSnapshotRejectsTreeSwap(fixture: V3Fixture, root: Path) {
        val limits = tightScratchLimits()
        val identity = FullTreeFunctionTruthSqliteV3.V3StableTreeSnapshot.captureIdentity(
            fixture.observationV2Root,
            setOf("outputs", "checkpoints"),
            Math.addExact(Math.multiplyExact(limits.observationV2.run.maximumShards.toLong(), 2L), 2L),
            minOf(limits.maximumScratchBytes, limits.truth.maximumScratchBytes, limits.observationV2.maximumScratchBytes),
            {},
            setOf("run.json", "index.json"),
        )
        val validationScratch = privateDirectory(root.resolve("observation-v2-snapshot-validation-scratch"))
        val validated = FullTreeFunctionObservationV2RunPublisher.loadAndValidate(
            candidateRoot = fixture.observationV2Root,
            expectedIndexArtifactSha256 = fixture.observationV2IndexSha256,
            richArtifact = fixture.rich,
            inventoryPath = fixture.inventoryPath,
            scope = fixture.scope,
            scratchParent = validationScratch,
            limits = limits.observationV2,
        )
        assertEquals(fixture.observationV2IndexSha256, validated.binding.indexArtifactSha256)
        identity.verifyIdentity()
        val pinned = identity.createSnapshot(
            fixture.observationV2Root,
            root.resolve("observation-v2-pinned-source"),
            setOf("outputs", "checkpoints"),
            null,
            {},
        )
        val replacement = copyTree(fixture.observationV2Root, root.resolve("observation-v2-replacement"))
        val displaced = root.resolve("observation-v2-displaced")
        Files.move(fixture.observationV2Root, displaced, StandardCopyOption.ATOMIC_MOVE)
        Files.move(replacement, fixture.observationV2Root, StandardCopyOption.ATOMIC_MOVE)
        assertFailsWith<FullTreeFunctionTruthV3Exception>(
            "an observation tree swap after nested validation must be rejected before publication",
        ) {
            pinned.verifyOriginalUnchanged()
        }
    }

    private fun tightScratchLimits(): FullTreeFunctionTruthV3Limits {
        val mebibyte = 1024L * 1024L
        val fixtureObservationShard = FullTreeFunctionObservationShardPublisherLimits().copy(
            producer = FullTreeFunctionObservationProducerLimits().copy(
                dieLimits = FullTreeDwarfDieLimits(
                    maximumPhysicalRecords = 10_000_000L,
                    maximumNonNullRecords = 5_000_000,
                    maximumAttributes = 50_000_000L,
                    maximumTreeDepth = 65_536,
                    maximumRetainedBytes = 24L * mebibyte,
                ),
                lineTableLimits = FullTreeDwarfLineTableLimits().copy(
                    maximumDirectories = 4096,
                    maximumFiles = 8192,
                    maximumAggregatePathBytes = 4L * mebibyte,
                ),
            ),
        )
        return FullTreeFunctionTruthV3Limits(
            truth = FullTreeFunctionTruthLimits(
                observationShard = fixtureObservationShard,
                maximumDatabaseBytes = 64L * mebibyte,
                maximumScratchBytes = 512L * mebibyte,
                maximumOutputBytes = 128L * mebibyte,
                maximumEntityBytes = 1 * 1024 * 1024,
                maximumStringBytes = 1 * 1024 * 1024,
            ),
            observationV2 = FullTreeFunctionObservationV2RunLimits(
                shard = fixtureObservationShard,
            ),
            // Both independent raw observation passes use the same narrowed fixture producer
            // limits; SQLite's database headroom remains generous and V3 enforces its own cap.
            maximumScratchBytes = 2L * 1024L * 1024L * 1024L,
        )
    }

    private fun assertConcreteTemplateShapes(root: Path) {
        val rows = Files.list(root.resolve("shards")).use { paths ->
            paths.map { parseControlObject(it).controlArray("sourceEntities").controlObjects("source entities") }
                .toList().flatten()
        }
        val templates = rows.filter { it.controlString("entityKind") == "template-instance" }
        val ints = templates.filter {
            it.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                .any { argument -> argument.toString().contains("int") }
        }
        val longs = templates.filter {
            it.controlObject("semanticAnchorFields").controlArray("templateActualArguments")
                .any { argument -> argument.toString().contains("long") }
        }
        assertTrue(ints.isNotEmpty(), "compiler fixture must contain a concrete int template instance")
        assertTrue(longs.isNotEmpty(), "compiler fixture must contain a concrete long template instance")
        val intCandidates = ints.mapNotNull { it["semanticAnchorCandidateId"] as? JsonPrimitive }.map { it.content }.toSet()
        val longCandidates = longs.mapNotNull { it["semanticAnchorCandidateId"] as? JsonPrimitive }.map { it.content }.toSet()
        assertTrue(intCandidates.isNotEmpty() && longCandidates.isNotEmpty())
        assertTrue(intCandidates.intersect(longCandidates).isEmpty(), "typed int/long actuals must yield distinct candidates")
        val missingPatternProof = ints + longs
        assertTrue(missingPatternProof.all { row ->
            val fields = row.controlObject("semanticAnchorFields")
            fields["templatePatternAnchorCandidateId"] == JsonNull &&
                row["resolvedSemanticIdentityId"] == JsonNull &&
                row.controlArray("reasonCodes").any { it.toString().contains("unknown-template-pattern-reference") } &&
                row.controlString("identityObservability") in setOf("unknown", "ambiguous")
        }, "generic-template relation remains unknown and null without authenticated pattern proof")
        val inlineInstances = rows.filter { it.controlString("entityKind") == "inline-instance" }
        assertTrue(inlineInstances.any { row ->
            row.controlString("identityObservability") == "observable" &&
                row.controlArray("edges").any { edge ->
                    val value = edge as? JsonObject ?: return@any false
                    value.controlString("kind") == "abstract-origin" &&
                        value.controlString("state") == "resolved" && value["target"] != JsonNull
                }
        }, "the compiler-emitted inline-origin relation remains positively observable")
    }

    private fun mutateAndRehashSourceIdentity(root: Path) {
        val rows = allSourceRows(root)
        val selected = rows.firstOrNull { row ->
            row["linkedEmittedRva"] != null && row["linkedEmittedRva"] != JsonNull &&
                row.controlArray("edges").any { rawEdge ->
                    val edge = rawEdge as? JsonObject ?: return@any false
                    (edge["target"] as? JsonPrimitive)?.isString == true
                }
        } ?: error("fixture must contain an emitted-RVA-linked census row with a resolved typed edge")
        val original = selected
        val current = original["semanticAnchorCandidateId"]
        val oldCandidate = (current as? JsonPrimitive)?.takeIf { it.isString }?.content
        val forgedCandidate: JsonElement = if (oldCandidate == "a".repeat(64)) JsonPrimitive("b".repeat(64)) else JsonPrimitive("a".repeat(64))
        val oldObservability = original.controlString("identityObservability")
        val oldDisposition = original.controlString("denominatorDisposition")
        mutateAndRehashSourceRow(root, selected.controlString("sourceEntityId")) { original -> JsonObject(original.toMutableMap().apply {
            put("semanticAnchorCandidateId", forgedCandidate)
            put("entityKind", JsonPrimitive("unresolved"))
            put("identityObservability", JsonPrimitive(if (oldObservability == "ambiguous") "unknown" else "ambiguous"))
            put("denominatorDisposition", JsonPrimitive(if (oldDisposition == "ambiguous") "unknown" else "ambiguous"))
            put("linkedEmittedRva", JsonNull)
            put("resolvedSemanticIdentityId", if (original["resolvedSemanticIdentityId"] == JsonNull) JsonPrimitive("c".repeat(64)) else JsonNull)
            val edges = original.controlArray("edges").map { raw ->
                val edge = raw as? JsonObject ?: return@map raw
                if ((edge["target"] as? JsonPrimitive)?.isString == true) {
                    JsonObject(edge.toMutableMap().apply { put("target", JsonPrimitive("forged-edge-target")) })
                } else edge
            }
            put("edges", JsonArray(edges))
        }) }
    }

    private fun mutateAndRehashSourceRow(root: Path, sourceEntityId: String, mutate: (JsonObject) -> JsonObject) {
        makeTreeWritable(root)
        val selected = Files.list(root.resolve("shards")).use { paths ->
            paths.toList().asSequence().mapNotNull { path ->
                val shard = parseControlObject(path)
                val index = shard.controlArray("sourceEntities").indexOfFirst { raw ->
                    (raw as? JsonObject)?.controlString("sourceEntityId") == sourceEntityId
                }
                if (index < 0) null else CandidateSource(
                    path,
                    shard,
                    index,
                    shard.controlArray("sourceEntities")[index] as JsonObject,
                )
            }.firstOrNull()
        } ?: error("candidate census row is missing before mutation")
        val sources = selected.shard.controlArray("sourceEntities").toMutableList()
        sources[selected.sourceIndex] = mutate(selected.source)
        val changedShard = withSourceRowsAndCounts(selected.shard, JsonArray(sources))
        OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME, changedShard)
        val changedShardBytes = OracleJson.canonicalBytes(changedShard)
        Files.write(selected.path, changedShardBytes)
        val indexPath = root.resolve("index.json")
        val index = parseControlObject(indexPath)
        val allRows = allSourceRows(root)
        val records = index.controlArray("shards").map { raw ->
            val record = raw as JsonObject
            if (record.controlString("path") == root.relativize(selected.path).toString().replace('\\', '/')) {
                JsonObject(record.toMutableMap().apply {
                    put("bytes", JsonPrimitive(changedShardBytes.size))
                    put("sha256", JsonPrimitive(OracleArtifacts.sha256(changedShardBytes)))
                })
            } else record
        }
        val counts = JsonObject(index.controlObject("counts").toMutableMap().apply {
            put("sourceEntities", JsonPrimitive(allRows.size))
            put("sourceEntitiesByKind", countBy(allRows, "entityKind", FullTreeSourceEntityKind.entries.map { it.wireValue }))
            put("sourceEntitiesByObservability", countBy(allRows, "identityObservability", FullTreeIdentityObservability.entries.map { it.wireValue }))
            put("sourceEntitiesByDenominatorDisposition", countBy(allRows, "denominatorDisposition", FullTreeDenominatorDisposition.entries.map { it.wireValue }))
        })
        val withoutDigest = JsonObject(index.toMutableMap().apply {
            remove("indexSha256")
            put("shards", JsonArray(records))
            put("counts", counts)
        })
        val logicalDigest = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutDigest))
        val changedIndex = JsonObject(withoutDigest + ("indexSha256" to JsonPrimitive(logicalDigest)))
        OracleSchemas.validate(FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME, changedIndex)
        Files.write(indexPath, OracleJson.canonicalBytes(changedIndex))
        freezeTree(root)
    }

    private fun allSourceRows(root: Path): List<JsonObject> = Files.list(root.resolve("shards")).use { paths ->
        paths.map(::parseControlObject).map { it.controlArray("sourceEntities").controlObjects("source entities") }
            .toList().flatten()
    }

    private fun assertCensusCounts(root: Path, index: JsonObject) {
        val rows = Files.list(root.resolve("shards")).use { paths ->
            paths.map(::parseControlObject).map { it.controlArray("sourceEntities").controlObjects("source entities") }
                .toList().flatten()
        }
        assertEquals(rows.size, rows.map { it.controlString("sourceEntityId") }.distinct().size,
            "every physical source fact has one artifact-local row id")
        val counts = index.controlObject("counts")
        assertEquals(rows.size.toLong(), counts.controlLong("sourceEntities"))
        assertEquals(countBy(rows, "entityKind", FullTreeSourceEntityKind.entries.map { it.wireValue }), counts.controlObject("sourceEntitiesByKind"))
        assertEquals(countBy(rows, "identityObservability", FullTreeIdentityObservability.entries.map { it.wireValue }), counts.controlObject("sourceEntitiesByObservability"))
        assertEquals(countBy(rows, "denominatorDisposition", FullTreeDenominatorDisposition.entries.map { it.wireValue }), counts.controlObject("sourceEntitiesByDenominatorDisposition"))
        assertTrue("no-range-definition" in counts.controlObject("sourceEntitiesByKind"))
    }

    private fun withSourceRowsAndCounts(shard: JsonObject, rows: JsonArray): JsonObject {
        val counts = JsonObject(shard.controlObject("counts").toMutableMap().apply {
            val objects = rows.controlObjects("source entities")
            put("sourceEntities", JsonPrimitive(objects.size))
            put("sourceEntitiesByKind", countBy(objects, "entityKind", FullTreeSourceEntityKind.entries.map { it.wireValue }))
            put("sourceEntitiesByObservability", countBy(objects, "identityObservability", FullTreeIdentityObservability.entries.map { it.wireValue }))
            put("sourceEntitiesByDenominatorDisposition", countBy(objects, "denominatorDisposition", FullTreeDenominatorDisposition.entries.map { it.wireValue }))
        })
        return JsonObject(shard.toMutableMap().apply {
            put("counts", counts)
            put("sourceEntities", rows)
        })
    }

    private fun countBy(rows: List<JsonObject>, field: String, keys: List<String>): JsonObject {
        val counts = keys.associateWith { key -> rows.count { it.controlString(field) == key }.toLong() }
        return JsonObject(counts.mapValues { JsonPrimitive(it.value) })
    }

    private fun rebindEntityBounds(
        fixture: V3Fixture,
        root: Path,
        wholeRunEntities: Long,
        perShardEntities: Long,
        regenerateObservationV2: Boolean = true,
    ): V3Fixture {
        require(wholeRunEntities > 0L && perShardEntities > 0L && perShardEntities <= wholeRunEntities)
        Files.createDirectories(root)
        val original = fixture.scope
        val bounds = original.document.controlObject("bounds")
        val changedBounds = JsonObject(bounds.toMutableMap().apply {
            put("wholeRun", JsonObject(bounds.controlObject("wholeRun").toMutableMap().apply {
                put("entities", JsonPrimitive(wholeRunEntities))
            }))
            put("perShard", JsonObject(bounds.controlObject("perShard").toMutableMap().apply {
                put("entities", JsonPrimitive(perShardEntities))
            }))
        })
        val scope = authenticatedScopeWithDocument(
            original,
            JsonObject(original.document.toMutableMap().apply { put("bounds", changedBounds) }),
        )
        FullTreeScopeControl.validate(scope)
        val inventoryPath = root.resolve("inventory.json")
        FullTreeInventoryControl.generateAndPublish(
            fixture.rich,
            scope,
            inventoryPath,
            maximumWorkers = 1,
        )
        val inventory = parseControlObject(inventoryPath)
        val elfDirectory = privateDirectory(root.resolve("elf"))
        val elfIndex = elfDirectory.resolve("functions.json")
        FullTreeElfFunctionsSqlite.generateAndPublish(
            richArtifact = fixture.rich,
            strippedArtifact = fixture.stripped,
            scope = scope,
            inventory = inventory,
            output = elfIndex,
            maximumWorkers = 1,
        )
        val scratch = privateDirectory(root.resolve("scratch"))
        val observationV2Root: Path
        val observationV2IndexSha256: String
        val observationV2EntityCount: Long
        val observationV2PerShardEntityCount: Long
        if (regenerateObservationV2) {
            observationV2Root = root.resolve("observations-v2")
            val observationV2 = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
                richArtifact = fixture.rich,
                inventoryPath = inventoryPath,
                scope = scope,
                scratchParent = scratch,
                outputRoot = observationV2Root,
                maximumWorkers = 2,
                limits = tightScratchLimits().observationV2,
            )
            observationV2IndexSha256 = observationV2.binding.indexArtifactSha256
            observationV2EntityCount = Math.addExact(
                Math.addExact(observationV2.emittedRvas, observationV2.nonEmitted),
                observationV2.sourceEntities,
            )
            observationV2PerShardEntityCount = observationV2.outputs.maxOf { output ->
                Math.addExact(Math.addExact(output.emittedRvas, output.nonEmitted), output.sourceEntities)
            }
        } else {
            // The old run is only a candidate. The public V3 API must rederive from raw inputs under
            // the new authenticated scope before it can compare that candidate with fresh output.
            observationV2Root = fixture.observationV2Root
            observationV2IndexSha256 = fixture.observationV2IndexSha256
            observationV2EntityCount = fixture.observationV2EntityCount
            observationV2PerShardEntityCount = fixture.observationV2PerShardEntityCount
        }
        return fixture.copy(
            inventoryPath = inventoryPath,
            scope = scope,
            elfIndex = elfIndex,
            observationV2Root = observationV2Root,
            observationV2IndexSha256 = observationV2IndexSha256,
            scratch = scratch,
            observationV2EntityCount = observationV2EntityCount,
            observationV2PerShardEntityCount = observationV2PerShardEntityCount,
        )
    }

    private fun createCompilerFixture(root: Path, perShardResidentBytes: Long? = null): V3Fixture {
        val sourceRoot = Path.of(System.getProperty("user.dir"))
            .resolve("src/test/resources/oracle/inline-template-identity-v1").toAbsolutePath().normalize()
        val compiler = resolveCompiler("GXX", listOf("g++", "g++-14", "g++-13"))
        val compilerVersion = runCommand(listOf(compiler.toString(), "--version"), root, "compiler-version.txt")
        val readelf = resolveCompiler("READELF", listOf("readelf", "llvm-readelf"))
        val readelfVersion = runCommand(listOf(readelf.toString(), "--version"), root, "readelf-version.txt")
        val build = Files.createDirectories(root.resolve("compiled"))
        val objects = listOf("caller_one", "caller_two", "instantiate", "unique_pattern").map { name ->
            val target = build.resolve("$name.o")
            runCommand(
                listOf(
                    compiler.toString(), "-std=c++17", "-O2", "-g", "-gdwarf-5", "-fPIC",
                    "-fdebug-prefix-map=$sourceRoot=/fixture/source-tree/clang/lib/InlineTemplate",
                    "-fdebug-prefix-map=$build=/fixture/build",
                    "-I${sourceRoot.resolve("include")}", sourceRoot.resolve("$name.cpp").toString(),
                    "-c", "-o", target.toString(),
                ),
                build,
                "$name-compile.txt",
            )
            target
        }
        val artifact = build.resolve("fixture.so")
        runCommand(
            listOf(compiler.toString(), "-shared", "-Wl,--build-id=none") + objects.map(Path::toString) + listOf("-o", artifact.toString()),
            build,
            "link.txt",
        )
        val stripped = build.resolve("fixture-stripped.so")
        Files.copy(artifact, stripped)
        writeCompilerObservationDiagnostic(compilerVersion, readelfVersion, artifact)
        val compilerInputVectorMatches = assertCompilerInputVector(sourceRoot, compilerVersion, readelfVersion, artifact)
        assertTrue(
            compilerInputVectorMatches,
            "canonical truth-v3 fixture qualification requires the pinned compiler/binutils tuple; " +
                "this toolchain run is unqualified",
        )
        val controls = createFullTreeControlFixture(root.resolve("control"))
        val original = controls.authenticatedScope()
        val richHash = fixtureSha256(artifact)
        val strippedHash = fixtureSha256(stripped)
        val artifacts = original.artifactManifest.controlObject("artifacts")
        fun rebound(name: String, path: Path): JsonObject = JsonObject(artifacts.controlObject(name).toMutableMap().apply {
            put("bytes", JsonPrimitive(Files.size(path)))
            put("sha256", JsonPrimitive(fixtureSha256(path)))
        })
        val manifest = JsonObject(original.artifactManifest.toMutableMap().apply {
            put("artifacts", JsonObject(artifacts.toMutableMap().apply {
                put("full", rebound("full", artifact))
                put("stripped", rebound("stripped", stripped))
            }))
        })
        val manifestHash = OracleArtifacts.sha256(OracleJson.canonicalBytes(manifest))
        val scopeDocument = JsonObject(original.document.toMutableMap().apply {
            put("oracle", JsonObject(original.document.controlObject("oracle").toMutableMap().apply {
                put("artifactManifestSha256", JsonPrimitive(manifestHash))
                put("richArtifactSha256", JsonPrimitive(richHash))
                put("strippedArtifactSha256", JsonPrimitive(strippedHash))
            }))
            if (perShardResidentBytes != null) {
                put("bounds", JsonObject(original.document.controlObject("bounds").toMutableMap().apply {
                    put("perShard", JsonObject(original.document.controlObject("bounds").controlObject("perShard").toMutableMap().apply {
                        put("maximumResidentBytes", JsonPrimitive(perShardResidentBytes))
                    }))
                }))
            }
        })
        val scope = AuthenticatedFullTreeScope(
            document = scopeDocument,
            sha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(scopeDocument)),
            sourceLock = original.sourceLock,
            sourceLockSha256 = original.sourceLockSha256,
            artifactManifest = manifest,
            artifactManifestSha256 = manifestHash,
        )
        FullTreeScopeControl.validate(scope)
        val inventoryPath = root.resolve("inventory.json")
        FullTreeInventoryControl.generateAndPublish(artifact, scope, inventoryPath, maximumWorkers = 1)
        val inventory = parseControlObject(inventoryPath)
        val elfDirectory = privateDirectory(root.resolve("elf"))
        val elfIndex = elfDirectory.resolve("functions.json")
        FullTreeElfFunctionsSqlite.generateAndPublish(
            richArtifact = artifact,
            strippedArtifact = stripped,
            scope = scope,
            inventory = inventory,
            output = elfIndex,
            maximumWorkers = 1,
        )
        val scratch = privateDirectory(root.resolve("scratch"))
        val v2Root = root.resolve("observations-v2")
        val v2 = FullTreeFunctionObservationV2RunPublisher.generateAndPublish(
            richArtifact = artifact,
            inventoryPath = inventoryPath,
            scope = scope,
            scratchParent = scratch,
            outputRoot = v2Root,
            maximumWorkers = 2,
            limits = tightScratchLimits().observationV2,
        )
        assertTrue(compilerVersion.isNotBlank())
        return V3Fixture(
            artifact,
            stripped,
            inventoryPath,
            scope,
            elfIndex,
            v2Root,
            v2.binding.indexArtifactSha256,
            scratch,
            compilerVersion.lineSequence().first(),
            readelfVersion.lineSequence().first(),
            compilerInputVectorMatches,
            Math.addExact(Math.addExact(v2.emittedRvas, v2.nonEmitted), v2.sourceEntities),
            v2.outputs.maxOf { output ->
                Math.addExact(Math.addExact(output.emittedRvas, output.nonEmitted), output.sourceEntities)
            },
        )
    }

    private fun writeCompilerObservationDiagnostic(compilerVersion: String, readelfVersion: String, artifact: Path) {
        val diagnostic = JsonObject(
            mapOf(
                "compiler" to JsonObject(mapOf(
                    "observedVersion" to JsonPrimitive(compilerVersion.lineSequence().first()),
                    "readelfVersion" to JsonPrimitive(readelfVersion.lineSequence().first()),
                )),
                "linkedElf" to JsonObject(mapOf(
                    "bytes" to JsonPrimitive(Files.size(artifact)),
                    "sha256" to JsonPrimitive(fixtureSha256(artifact)),
                )),
                "vectorKind" to JsonPrimitive("compiler-output-v1"),
            ),
        )
        val path = Path.of(System.getProperty("user.dir"))
            .resolve("build/test-results/test/full-tree-function-truth-v3-compiler-observed-v1.json")
        Files.createDirectories(path.parent)
        Files.write(path, OracleJson.canonicalBytes(diagnostic))
    }

    private fun assertCompilerInputVector(sourceRoot: Path, compilerVersion: String, readelfVersion: String, artifact: Path): Boolean {
        val vector = parseControlObject(sourceRoot.parent.resolve("full-tree-function-truth-v3/compiler-input-v1.json"))
        assertEquals("compiler-input-v1", vector.controlString("vectorKind"))
        assertEquals("inline-template-identity-v1", vector.controlString("fixture"))
        val policy = vector.controlObject("producer")
        assertEquals(FullTreeFunctionTruthSqliteV3.POLICY_ID, policy.controlString("id"))
        assertEquals(FullTreeFunctionTruthSqliteV3.POLICY_VERSION.toLong(), policy.controlLong("version"))
        assertEquals(FullTreeFunctionTruthSqliteV3.configurationSha256, policy.controlString("configurationSha256"))
        vector.controlArray("schemaIdentities").controlObjects("schema identities").forEach { identity ->
            assertEquals(identity.controlString("schemaSha256"), OracleSchemas.identity(identity.controlString("name")).sha256)
        }
        vector.controlArray("sourceFiles").controlObjects("source files").forEach { source ->
            assertEquals(source.controlString("sha256"), fixtureSha256(sourceRoot.resolve(source.controlString("path"))))
        }
        val recordedToolchain = vector.controlObject("compiler")
        val toolchainMatches = recordedToolchain.controlString("observedVersion") == compilerVersion.lineSequence().first() &&
            recordedToolchain.controlString("readelfVersion") == readelfVersion.lineSequence().first()
        if (toolchainMatches) {
            val linkedElf = vector.controlObject("linkedElf")
            assertEquals(linkedElf.controlLong("bytes"), Files.size(artifact), "linked fixture ELF byte count")
            assertEquals(linkedElf.controlString("sha256"), fixtureSha256(artifact), "linked fixture ELF digest")
        }
        assertTrue(Files.size(artifact) > 0L)
        return toolchainMatches
    }

    private fun writeFixtureVector(fixture: V3Fixture, generation: FullTreeFunctionTruthV3Generation) {
        val inputVectorPath = Path.of(System.getProperty("user.dir"))
            .resolve("src/test/resources/oracle/full-tree-function-truth-v3/compiler-input-v1.json")
        val inputVector = parseControlObject(inputVectorPath)
        val schemas = listOf(
            FullTreeFunctionTruthSqliteV3.SHARD_SCHEMA_NAME,
            FullTreeFunctionTruthSqliteV3.INDEX_SCHEMA_NAME,
        ).map { name ->
            val identity = OracleSchemas.identity(name)
            JsonObject(mapOf("name" to JsonPrimitive(name), "schemaSha256" to JsonPrimitive(identity.sha256)))
        }
        val vector = JsonObject(
            mapOf(
                "compiler" to JsonObject(mapOf(
                    "observedVersion" to JsonPrimitive(fixture.compilerIdentity),
                    "readelfVersion" to JsonPrimitive(fixture.readelfIdentity),
                )),
                "compilerInputVectorMatches" to JsonPrimitive(fixture.compilerInputVectorMatches),
                "fixtureInputVectorSha256" to JsonPrimitive(fixtureSha256(inputVectorPath)),
                "input" to JsonObject(
                    mapOf(
                        "richElfSha256" to JsonPrimitive(fixtureSha256(fixture.rich)),
                        "strippedElfSha256" to JsonPrimitive(fixtureSha256(fixture.stripped)),
                        "observationV2IndexArtifactSha256" to JsonPrimitive(fixture.observationV2IndexSha256),
                        "scopeSha256" to JsonPrimitive(fixture.scope.sha256),
                    "inventoryArtifactSha256" to JsonPrimitive(fixtureSha256(fixture.inventoryPath)),
                    "linkedElfBytes" to JsonPrimitive(Files.size(fixture.rich)),
                    "linkedElfSha256" to JsonPrimitive(fixtureSha256(fixture.rich)),
                    ),
                ),
                "output" to JsonObject(
                    mapOf(
                        "indexArtifactSha256" to JsonPrimitive(generation.indexArtifactSha256),
                        "indexSha256" to JsonPrimitive(generation.indexSha256),
                        "outputBytes" to JsonPrimitive(generation.outputBytes),
                        "databaseHighWaterBytes" to JsonPrimitive(generation.databaseHighWaterBytes),
                        "counts" to generation.counts.toJson(),
                        "index" to generation.index,
                    ),
                ),
                "producer" to JsonObject(
                    mapOf(
                        "id" to JsonPrimitive(FullTreeFunctionTruthSqliteV3.POLICY_ID),
                        "version" to JsonPrimitive(FullTreeFunctionTruthSqliteV3.POLICY_VERSION),
                        "configurationSha256" to JsonPrimitive(FullTreeFunctionTruthSqliteV3.configurationSha256),
                        "schemas" to JsonArray(schemas),
                    ),
                ),
                "vectorKind" to JsonPrimitive("full-tree-function-truth-v3-output-v1"),
            ),
        )
        val output = Path.of(System.getProperty("user.dir"))
            .resolve("build/test-results/test/full-tree-function-truth-v3-vector.json")
        Files.createDirectories(output.parent)
        val bytes = OracleJson.canonicalBytes(vector)
        Files.write(output, bytes)
        assertTrue(
            fixture.compilerInputVectorMatches,
            "canonical truth-v3 fixture output is unqualified for this compiler/binutils tuple",
        )
        val golden = inputVectorPath.resolveSibling("compiler-output-v1.json")
        assertTrue(Files.isRegularFile(golden), "the matching compiler input has no checked-in V3 output vector")
        assertEquals(Files.readAllBytes(golden).toList(), bytes.toList(), "V3 canonical compiler output vector")
    }

    private fun resolveCompiler(environment: String, candidates: List<String>): Path {
        val names = System.getenv(environment)?.takeIf(String::isNotBlank)?.let(::listOf) ?: candidates
        val searchPath = System.getenv("PATH").orEmpty().split(File.pathSeparator).filter(String::isNotBlank)
        names.forEach { name ->
            val path = Path.of(name)
            val matches = if (path.isAbsolute || name.contains('/')) listOf(path) else searchPath.map { Path.of(it).resolve(name) }
            matches.firstOrNull { Files.isRegularFile(it) && Files.isExecutable(it) }?.let { return it.toAbsolutePath().normalize() }
        }
        error("required fixture compiler $environment is unavailable: ${candidates.joinToString()}")
    }

    private fun runCommand(command: List<String>, directory: Path, outputName: String): String {
        val output = directory.resolve(outputName)
        val process = ProcessBuilder(command).directory(directory.toFile()).redirectErrorStream(true).redirectOutput(output.toFile()).start()
        if (!process.waitFor(2, TimeUnit.MINUTES)) {
            process.destroyForcibly()
            error("fixture command timed out: ${command.joinToString(" ")}")
        }
        val text = Files.readAllBytes(output).toString(StandardCharsets.UTF_8)
        if (process.exitValue() != 0) error("fixture command failed (${process.exitValue()}): ${command.joinToString(" ")}\n$text")
        return text
    }

    private fun copyTree(source: Path, target: Path): Path {
        Files.createDirectory(target, PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString("rwx------")))
        Files.walk(source).use { paths ->
            paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach { input ->
                val out = target.resolve(source.relativize(input).toString())
                Files.createDirectories(out.parent)
                Files.copy(input, out, StandardCopyOption.COPY_ATTRIBUTES)
                Files.setPosixFilePermissions(out, PosixFilePermissions.fromString("r--------"))
            }
        }
        Files.walk(target).use { paths -> paths.filter { Files.isDirectory(it) }.forEach {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r-x------"))
        } }
        return target
    }

    private fun makeTreeWritable(root: Path) {
        Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach { path ->
            Files.setPosixFilePermissions(
                path,
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) PosixFilePermissions.fromString("rwx------")
                else PosixFilePermissions.fromString("rw-------"),
            )
        } }
    }

    private fun freezeTree(root: Path) {
        Files.walk(root).use { paths -> paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.forEach {
            Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r--------"))
        } }
        Files.walk(root).use { paths -> paths.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }
            .sorted(Comparator.reverseOrder()).forEach { Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("r-x------")) } }
    }

    private fun assertDirectoryEmpty(path: Path) {
        assertTrue(Files.list(path).use { it.findAny().isEmpty })
    }

    private fun Throwable.hasCauseMessageFragment(fragment: String): Boolean =
        generateSequence(this) { it.cause }.any { it.message?.contains(fragment) == true }

    private fun Throwable.causeMessageChain(): String =
        generateSequence(this) { it.cause }.joinToString(" <- ") { it.message.orEmpty() }

    private fun v2FileRecord(id: String, path: String, bytes: ByteArray): JsonObject = JsonObject(mapOf(
        "bytes" to JsonPrimitive(bytes.size.toLong()),
        "functions" to JsonPrimitive(0L),
        "id" to JsonPrimitive(id),
        "nonEmitted" to JsonPrimitive(0L),
        "path" to JsonPrimitive(path),
        "sha256" to JsonPrimitive(OracleArtifacts.sha256(bytes)),
    ))

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun v3TreeBytes(root: Path): Map<String, List<Byte>> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }.sorted()
            .toList().associate { root.relativize(it).toString() to Files.readAllBytes(it).toList() }
    }

    private data class V3Fixture(
        val rich: Path,
        val stripped: Path,
        val inventoryPath: Path,
        val scope: AuthenticatedFullTreeScope,
        val elfIndex: Path,
        val observationV2Root: Path,
        val observationV2IndexSha256: String,
        val scratch: Path,
        val compilerIdentity: String,
        val readelfIdentity: String,
        val compilerInputVectorMatches: Boolean,
        val observationV2EntityCount: Long,
        val observationV2PerShardEntityCount: Long,
    )

    private data class CandidateSource(
        val path: Path,
        val shard: JsonObject,
        val sourceIndex: Int,
        val source: JsonObject,
    )

    private data class V3Mutation(
        val name: String,
        val row: JsonObject,
        val mutate: (JsonObject) -> JsonObject,
    )
}
