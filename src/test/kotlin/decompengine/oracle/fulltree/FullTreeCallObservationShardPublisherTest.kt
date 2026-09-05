package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.ByteArrayOutputStream
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallObservationShardPublisherTest {
    @Test
    fun `publication and validation reproduce every raw shard with identical immutable bytes`() =
        withPublicationFixture { fixture ->
            fixture.shards.forEach { shard ->
                val expectedBytes = ByteArrayOutputStream()
                val expected = FullTreeCallObservationProducer.generateShardTo(
                    richArtifact = fixture.controls.richArtifact,
                    inventoryPath = fixture.controls.inventory,
                    scope = fixture.scope,
                    shardId = shard.identifier,
                    scratchParent = fixture.scratch,
                    output = expectedBytes,
                )
                val receipts = listOf(1, 4096).map { checkpointRows ->
                    val output = fixture.outputParent.resolve("${shard.identifier}-$checkpointRows.json")
                    val limits = FullTreeCallObservationPublicationLimits(
                        sqlite = FullTreeCallObservationSqliteLimits(databaseCheckpointRows = checkpointRows),
                    )
                    val receipt = publish(fixture, output, shardId = shard.identifier, limits = limits)
                    assertContentEquals(expectedBytes.toByteArray(), Files.readAllBytes(output))
                    assertEquals(expected.outputSha256, receipt.outputSha256)
                    assertEquals(expected.outputBytes, receipt.outputBytes)
                    assertEquals(expected.entities, receipt.entities)
                    assertEquals(expected.scannedDies, receipt.scannedDies)
                    assertEquals(shard.identifier, receipt.shardId)
                    assertEquals(shard.inputSha256, receipt.inputSha256)
                    assertEquals(fixtureSha256(fixture.controls.inventory), receipt.inventoryArtifactSha256)
                    assertEquals(fixtureSha256(fixture.controls.richArtifact), receipt.richArtifactSha256)
                    assertEquals(fixture.scope.sha256, receipt.scopeSha256)
                    assertEquals(OracleArtifacts.sha256(Files.readAllBytes(output)), receipt.outputSha256)
                    assertFalse(receipt.authoritativeReleaseEvidence)
                    assertFalse(receipt.candidateLeaseRetained)
                    assertImmutable(output)
                    assertEquals(receipt, validate(fixture, output, shardId = shard.identifier, limits = limits))
                    assertDirectoryEmpty(fixture.scratch)
                    receipt
                }
                assertEquals(receipts[0], receipts[1])
            }
            assertEquals(fixture.shards.size * 2, entryNames(fixture.outputParent).size)
            assertTrue(entryNames(fixture.outputParent).all { it.endsWith(".json") })
        }

    @Test
    fun `publication rejects existing files and symbolic links without changing their targets`() =
        withPublicationFixture { fixture ->
            val existing = fixture.outputParent.resolve("existing.json")
            val sentinel = "keep the existing publication\n".toByteArray()
            Files.write(existing, sentinel)
            Files.setPosixFilePermissions(existing, PosixFilePermissions.fromString("r--------"))
            val originalInode = Files.getAttribute(existing, "unix:ino", LinkOption.NOFOLLOW_LINKS)
            assertFailsWith<FullTreeCallObservationPublicationException> { publish(fixture, existing) }
            assertContentEquals(sentinel, Files.readAllBytes(existing))
            assertEquals(originalInode, Files.getAttribute(existing, "unix:ino", LinkOption.NOFOLLOW_LINKS))
            assertImmutable(existing)

            val linked = fixture.outputParent.resolve("linked.json")
            Files.createSymbolicLink(linked, existing)
            assertFailsWith<FullTreeCallObservationPublicationException> { publish(fixture, linked) }
            assertEquals(existing, Files.readSymbolicLink(linked))
            assertContentEquals(sentinel, Files.readAllBytes(existing))

            val absent = fixture.root.resolve("absent.json")
            val dangling = fixture.outputParent.resolve("dangling.json")
            Files.createSymbolicLink(dangling, absent)
            assertFailsWith<FullTreeCallObservationPublicationException> { publish(fixture, dangling) }
            assertEquals(absent, Files.readSymbolicLink(dangling))
            assertFalse(Files.exists(absent, LinkOption.NOFOLLOW_LINKS))
            assertEquals(listOf("dangling.json", "existing.json", "linked.json"), entryNames(fixture.outputParent))
            assertDirectoryEmpty(fixture.scratch)
        }

    @Test
    fun `publication refuses a symbolic link in the output parent`() = withPublicationFixture { fixture ->
        val linkedParent = fixture.root.resolve("linked-output")
        Files.createSymbolicLink(linkedParent, fixture.outputParent)
        assertFailsWith<FullTreeCallObservationPublicationException> {
            publish(fixture, linkedParent.resolve("candidate.json"))
        }
        assertEquals(fixture.outputParent, Files.readSymbolicLink(linkedParent))
        assertDirectoryEmpty(fixture.outputParent)
        assertDirectoryEmpty(fixture.scratch)
    }

    @Test
    fun `candidate validation rejects symbolic and hard links while preserving the publication`() =
        withPublicationFixture { fixture ->
            val candidate = fixture.outputParent.resolve("candidate.json")
            val receipt = publish(fixture, candidate)
            val original = Files.readAllBytes(candidate)
            val originalInode = Files.getAttribute(candidate, "unix:ino", LinkOption.NOFOLLOW_LINKS)
            val linked = fixture.outputParent.resolve("linked.json")
            Files.createSymbolicLink(linked, candidate)
            assertFailsWith<FullTreeCallObservationPublicationException> { validate(fixture, linked) }
            assertEquals(candidate, Files.readSymbolicLink(linked))
            Files.delete(linked)

            Files.createLink(linked, candidate)
            assertFailsWith<FullTreeCallObservationPublicationException> { validate(fixture, linked) }
            assertFailsWith<FullTreeCallObservationPublicationException> { validate(fixture, candidate) }
            assertTrue(Files.isSameFile(candidate, linked))
            assertContentEquals(original, Files.readAllBytes(candidate))
            Files.delete(linked)

            assertEquals(receipt, validate(fixture, candidate))
            assertEquals(originalInode, Files.getAttribute(candidate, "unix:ino", LinkOption.NOFOLLOW_LINKS))
            assertContentEquals(original, Files.readAllBytes(candidate))
            assertImmutable(candidate)
            assertEquals(listOf("candidate.json"), entryNames(fixture.outputParent))
            assertDirectoryEmpty(fixture.scratch)
        }

    @Test
    fun `candidate validation rejects wrong modes and byte boundaries without mutation`() =
        withPublicationFixture { fixture ->
            val candidate = fixture.outputParent.resolve("candidate.json")
            val receipt = publish(fixture, candidate)
            val original = Files.readAllBytes(candidate)
            val originalInode = Files.getAttribute(candidate, "unix:ino", LinkOption.NOFOLLOW_LINKS)
            val cases = listOf(
                Triple("owner writable", "rw-------", original),
                Triple("world readable", "r--r--r--", original),
                Triple("truncated prefix", "r--------", original.copyOf(original.size - 1)),
                Triple("prefixed bytes", "r--------", byteArrayOf(' '.code.toByte()) + original),
                Triple("trailing bytes", "r--------", original + byteArrayOf('\n'.code.toByte())),
            )
            cases.forEach { (label, mode, bytes) ->
                val permissions = PosixFilePermissions.fromString(mode)
                Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("rw-------"))
                Files.write(candidate, bytes)
                Files.setPosixFilePermissions(candidate, permissions)

                assertFailsWith<FullTreeCallObservationPublicationException>(label) {
                    validate(fixture, candidate)
                }
                assertContentEquals(bytes, Files.readAllBytes(candidate), label)
                assertEquals(permissions, Files.getPosixFilePermissions(candidate, LinkOption.NOFOLLOW_LINKS), label)
                assertEquals(originalInode, Files.getAttribute(candidate, "unix:ino", LinkOption.NOFOLLOW_LINKS), label)
                assertEquals(listOf("candidate.json"), entryNames(fixture.outputParent), label)
                assertDirectoryEmpty(fixture.scratch)
            }
            Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("rw-------"))
            Files.write(candidate, original)
            Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("r--------"))
            assertEquals(receipt, validate(fixture, candidate))
            assertImmutable(candidate)
            assertDirectoryEmpty(fixture.scratch)
        }

    @Test
    fun `raw rederivation rejects a schema valid forged candidate without rewriting it`() =
        withPublicationFixture { fixture ->
            val candidate = fixture.outputParent.resolve("forged.json")
            publish(fixture, candidate)
            val original = parseControlObject(candidate)
            val counts = original.controlObject("counts")
            val forged = JsonObject(original.toMutableMap().apply {
                this["counts"] = JsonObject(counts.toMutableMap().apply {
                    this["scannedDies"] = JsonPrimitive(counts.controlLong("scannedDies") + 1L)
                })
            })
            FullTreeCallObservations.validateEnvelope(
                forged,
                fixture.scope.document,
                fixture.scope.sha256,
                fixture.inventory,
                fixtureSha256(fixture.controls.inventory),
                fixture.shards.first(),
            )
            val forgedBytes = OracleJson.canonicalBytes(forged)
            Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("rw-------"))
            Files.write(candidate, forgedBytes)
            Files.setPosixFilePermissions(candidate, PosixFilePermissions.fromString("r--------"))
            val originalInode = Files.getAttribute(candidate, "unix:ino", LinkOption.NOFOLLOW_LINKS)

            assertFailsWith<FullTreeCallObservationPublicationException> { validate(fixture, candidate) }
            assertContentEquals(forgedBytes, Files.readAllBytes(candidate))
            assertEquals(originalInode, Files.getAttribute(candidate, "unix:ino", LinkOption.NOFOLLOW_LINKS))
            assertImmutable(candidate)
            assertEquals(listOf("forged.json"), entryNames(fixture.outputParent))
            assertDirectoryEmpty(fixture.scratch)
        }

    @Test
    fun `byte database DIE and artifact bounds revoke stages and preserve existing candidates`() =
        withPublicationFixture { fixture ->
            val candidate = fixture.outputParent.resolve("candidate.json")
            val receipt = publish(fixture, candidate)
            val original = Files.readAllBytes(candidate)
            assertTrue(receipt.scannedDies > 1L)
            val limits = listOf(
                FullTreeCallObservationPublicationLimits(
                    sqlite = FullTreeCallObservationSqliteLimits(maximumOutputBytes = receipt.outputBytes - 1L),
                ),
                FullTreeCallObservationPublicationLimits(
                    sqlite = FullTreeCallObservationSqliteLimits(maximumDatabaseBytes = 4096L),
                ),
                FullTreeCallObservationPublicationLimits(
                    producer = FullTreeCallObservationProducerLimits(maximumScannedDies = receipt.scannedDies - 1L),
                ),
                FullTreeCallObservationPublicationLimits(
                    control = FullTreeControlLimits(
                        maximumRichArtifactBytes = Files.size(fixture.controls.richArtifact) - 1L,
                    ),
                ),
            )
            limits.forEachIndexed { index, bound ->
                val rejected = fixture.outputParent.resolve("rejected-$index.json")
                assertFailsWith<FullTreeCallObservationPublicationException> {
                    publish(fixture, rejected, limits = bound)
                }
                assertFalse(Files.exists(rejected, LinkOption.NOFOLLOW_LINKS))
                assertFailsWith<FullTreeCallObservationPublicationException> {
                    validate(fixture, candidate, limits = bound)
                }
                assertContentEquals(original, Files.readAllBytes(candidate))
                assertImmutable(candidate)
                assertEquals(listOf("candidate.json"), entryNames(fixture.outputParent))
                assertDirectoryEmpty(fixture.scratch)
            }
            assertEquals(receipt, validate(fixture, candidate))
        }

    @Test
    fun `wrong artifact scope and shard fail before publication and preserve validation input`() =
        withPublicationFixture { fixture ->
            val candidate = fixture.outputParent.resolve("candidate.json")
            val receipt = publish(fixture, candidate)
            val original = Files.readAllBytes(candidate)
            val wrongArtifact = fixture.root.resolve("wrong-artifact.elf")
            Files.write(wrongArtifact, Files.readAllBytes(fixture.controls.richArtifact) + byteArrayOf(0))
            Files.setPosixFilePermissions(wrongArtifact, PosixFilePermissions.fromString("r--------"))
            val bounds = fixture.scope.document.controlObject("bounds")
            val perShard = bounds.controlObject("perShard")
            val differentDocument = JsonObject(fixture.scope.document.toMutableMap().apply {
                this["bounds"] = JsonObject(bounds.toMutableMap().apply {
                    this["perShard"] = JsonObject(perShard.toMutableMap().apply {
                        this["wallClockSeconds"] = JsonPrimitive(perShard.controlLong("wallClockSeconds") - 1L)
                    })
                })
            })
            val wrongScope = authenticatedScopeWithDocument(fixture.scope, differentDocument)
            FullTreeScopeControl.validate(wrongScope)
            val rejected = fixture.outputParent.resolve("rejected.json")

            assertFailsWith<FullTreeCallObservationPublicationException> {
                publish(fixture, rejected, richArtifact = wrongArtifact)
            }
            assertFailsWith<FullTreeCallObservationPublicationException> {
                validate(fixture, candidate, richArtifact = wrongArtifact)
            }
            assertFailsWith<FullTreeCallObservationPublicationException> {
                publish(fixture, rejected, scope = wrongScope)
            }
            assertFailsWith<FullTreeCallObservationPublicationException> {
                validate(fixture, candidate, scope = wrongScope)
            }
            assertFailsWith<FullTreeCallObservationPublicationException> {
                publish(fixture, rejected, shardId = "outside-inventory")
            }
            assertFailsWith<FullTreeCallObservationPublicationException> {
                validate(fixture, candidate, shardId = "outside-inventory")
            }
            assertContentEquals(original, Files.readAllBytes(candidate))
            assertImmutable(candidate)
            assertEquals(listOf("candidate.json"), entryNames(fixture.outputParent))
            assertDirectoryEmpty(fixture.scratch)
            assertEquals(receipt, validate(fixture, candidate))
        }

    private fun publish(
        fixture: PublicationFixture,
        output: Path,
        richArtifact: Path = fixture.controls.richArtifact,
        scope: AuthenticatedFullTreeScope = fixture.scope,
        shardId: String = fixture.shards.first().identifier,
        limits: FullTreeCallObservationPublicationLimits = FullTreeCallObservationPublicationLimits(),
    ): FullTreeCallObservationPublication = FullTreeCallObservationShardPublisher.generateAndPublish(
        richArtifact = richArtifact,
        inventoryPath = fixture.controls.inventory,
        scope = scope,
        shardId = shardId,
        scratchParent = fixture.scratch,
        output = output,
        limits = limits,
    )

    private fun validate(
        fixture: PublicationFixture,
        candidate: Path,
        richArtifact: Path = fixture.controls.richArtifact,
        scope: AuthenticatedFullTreeScope = fixture.scope,
        shardId: String = fixture.shards.first().identifier,
        limits: FullTreeCallObservationPublicationLimits = FullTreeCallObservationPublicationLimits(),
    ): FullTreeCallObservationPublication = FullTreeCallObservationShardPublisher.loadAndValidate(
        candidate = candidate,
        richArtifact = richArtifact,
        inventoryPath = fixture.controls.inventory,
        scope = scope,
        shardId = shardId,
        scratchParent = fixture.scratch,
        limits = limits,
    )

    private fun withPublicationFixture(action: (PublicationFixture) -> Unit) =
        inControlTemporaryDirectory { root ->
            val controls = createFullTreeControlFixture(root.resolve("fixture"))
            val scope = controls.authenticatedScope()
            val inventory = parseControlObject(controls.inventory)
            val shards = FullTreeCallObservations.shardInputs(
                inventory, fixtureSha256(controls.inventory), scope.document, scope.sha256,
            )
            assertTrue(shards.isNotEmpty())
            action(
                PublicationFixture(
                    root, controls, scope, inventory, shards,
                    privateDirectory(root.resolve("scratch")), privateDirectory(root.resolve("output")),
                ),
            )
        }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun assertImmutable(path: Path) {
        assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
        assertFalse(Files.isSymbolicLink(path))
        assertEquals(
            PosixFilePermissions.fromString("r--------"),
            Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
        )
        assertEquals(1, (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt())
    }

    private fun assertDirectoryEmpty(path: Path) {
        assertEquals(emptyList(), entryNames(path), "unexpected residue below $path")
    }

    private fun entryNames(path: Path): List<String> = Files.list(path).use { entries ->
        entries.map { it.fileName.toString() }.sorted().toList()
    }

    private data class PublicationFixture(
        val root: Path,
        val controls: FullTreeControlFixture,
        val scope: AuthenticatedFullTreeScope,
        val inventory: JsonObject,
        val shards: List<FullTreeCallObservationShardInput>,
        val scratch: Path,
        val outputParent: Path,
    )
}
