package decompengine.oracle.fulltree

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
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreeCallObservationRunPublisherTest {
    @Test
    fun `complete raw runs preserve every inventory shard across repeated worker bounds`() = withRunFixture { fixture ->
        assertEquals(2, fixture.shards.size)
        val expected = fixture.shards.associate { shard ->
            val output = ByteArrayOutputStream()
            val receipt = FullTreeCallObservationProducer.generateShardTo(
                fixture.artifact, fixture.inventoryPath, fixture.scope, shard.identifier, fixture.scratch, output,
            )
            shard.identifier to (receipt to output.toByteArray())
        }
        val runs = listOf(1, 1, 2, 8).mapIndexed { index, workers ->
            val root = fixture.outputParent.resolve("run-$index")
            val receipt = publish(fixture, root, workers)
            assertEquals(minOf(workers, fixture.shards.size), receipt.maximumWorkers)
            assertEquals(fixture.shards.map { it.identifier }, receipt.outputs.map { it.shardId })
            assertEquals(expected.values.sumOf { it.first.entities }, receipt.entities)
            assertEquals(expected.values.sumOf { it.first.outputBytes }, receipt.outputBytes)
            assertEquals(fixture.scope.sha256, receipt.scopeSha256)
            assertEquals(fixtureSha256(fixture.inventoryPath), receipt.inventoryArtifactSha256)
            assertEquals(fixtureSha256(fixture.artifact), receipt.richArtifactSha256)
            assertFalse(receipt.authoritativeReleaseEvidence)
            assertFalse(receipt.candidateLeaseRetained)
            assertFalse(receipt.downstreamScoringAuthorized)
            assertEquals(expectedTree(fixture.shards.map { it.identifier }), treeMembers(root))
            receipt.outputs.forEach { output ->
                val raw = expected.getValue(output.shardId)
                assertEquals(raw.first.outputSha256, output.outputSha256)
                assertEquals(raw.first.outputBytes, output.outputBytes)
                assertEquals(raw.first.entities, output.entities)
                assertContentEquals(raw.second, Files.readAllBytes(root.resolve("outputs/${output.shardId}.json")))
            }
            assertFrozenTree(root)
            assertEquals(receipt, validate(fixture, root, receipt.indexArtifactSha256, workers))
            assertFailsWith<UnsupportedOperationException> {
                @Suppress("UNCHECKED_CAST")
                (receipt.outputs as MutableList<FullTreeCallObservationPublication>).clear()
            }
            assertScratchEmpty(fixture)
            receipt
        }
        assertEquals(runs[0].runSha256, runs[1].runSha256)
        assertEquals(runs[0].indexArtifactSha256, runs[1].indexArtifactSha256)
        assertEquals(runs[2].runSha256, runs[3].runSha256)
        assertEquals(runs[2].indexArtifactSha256, runs[3].indexArtifactSha256)
        assertNotEquals(runs[0].runSha256, runs[2].runSha256)
        assertFailsWith<FullTreeCallObservationRunException> {
            validate(fixture, runs[2].root, runs[2].indexArtifactSha256, workers = 1)
        }
        assertEquals(listOf("run-0", "run-1", "run-2", "run-3"), entryNames(fixture.outputParent))
    }

    @Test
    fun `complete nonempty raw run preserves all seven observed calls`() = withRunFixture(nonempty = true) { fixture ->
        val candidate = fixture.outputParent.resolve("nonempty")
        val receipt = publish(fixture, candidate)
        assertEquals(7L, receipt.entities)
        assertEquals(1, receipt.outputs.size)
        assertEquals(19L, receipt.outputs.single().scannedDies)
        val document = parseControlObject(candidate.resolve("outputs/${receipt.outputs.single().shardId}.json"))
        assertEquals(7, document.controlArray("calls").size)
        assertEquals(5L, document.controlObject("counts").controlLong("scored"))
        assertEquals(receipt, validate(fixture, candidate, receipt.indexArtifactSha256))
        assertScratchEmpty(fixture)
    }

    @Test
    fun `raw run validation rejects missing or unindexed tree members without changing candidates`() = withRunFixture { fixture ->
        val original = fixture.outputParent.resolve("original")
        val receipt = publish(fixture, original)
        listOf("extra-root", "extra-output", "missing-output", "missing-checkpoint").forEach { mutation ->
            val candidate = copyRun(original, fixture.outputParent.resolve(mutation))
            val shardId = fixture.shards.first().identifier
            when (mutation) {
                "extra-root" -> Files.writeString(candidate.resolve("unexpected.json"), "{}\n")
                "extra-output" -> Files.writeString(candidate.resolve("outputs/unindexed.json"), "{}\n")
                "missing-output" -> Files.delete(candidate.resolve("outputs/$shardId.json"))
                "missing-checkpoint" -> Files.delete(candidate.resolve("checkpoints/$shardId.json"))
            }
            freezeTree(candidate)
            val before = fileSnapshot(candidate)
            assertFailsWith<FullTreeCallObservationRunException> {
                validate(fixture, candidate, receipt.indexArtifactSha256)
            }
            assertSnapshot(before, candidate)
            assertScratchEmpty(fixture)
        }
        assertEquals(receipt, validate(fixture, original, receipt.indexArtifactSha256))
    }

    @Test
    fun `generic valid rebound runs cannot omit an authenticated inventory shard`() = withRunFixture { fixture ->
        val original = fixture.outputParent.resolve("original")
        publish(fixture, original)
        val candidate = copyRun(original, fixture.outputParent.resolve("missing-inventory-shard"))
        val run = parseControlObject(candidate.resolve("run.json"))
        val shards = run.controlArray("shards")
        val dropped = (shards.last() as JsonObject).controlString("id")
        writeControlObject(candidate.resolve("run.json"), JsonObject(run.toMutableMap().apply {
            this["shards"] = JsonArray(shards.dropLast(1))
        }))
        Files.delete(candidate.resolve("outputs/$dropped.json"))
        Files.delete(candidate.resolve("checkpoints/$dropped.json"))
        val rebound = FrozenBoundedShardFixture.rebind(candidate)
        freezeTree(candidate)
        assertEquals(1, BoundedShardRunVerifier.verify(candidate, rebound).outputs.size)
        val before = fileSnapshot(candidate)
        assertFailsWith<FullTreeCallObservationRunException> { validate(fixture, candidate, rebound) }
        assertSnapshot(before, candidate)
        assertScratchEmpty(fixture)
    }

    @Test
    fun `generic valid rebound runs cannot introduce a foreign inventory shard`() = withRunFixture { fixture ->
        val original = fixture.outputParent.resolve("original")
        publish(fixture, original)
        val candidate = copyRun(original, fixture.outputParent.resolve("foreign-shard"))
        val run = parseControlObject(candidate.resolve("run.json"))
        val shards = run.controlArray("shards")
        val first = shards.first() as JsonObject
        val foreign = JsonObject(first.toMutableMap().apply { this["id"] = JsonPrimitive("unexpected") })
        writeControlObject(candidate.resolve("run.json"), JsonObject(run.toMutableMap().apply {
            this["shards"] = JsonArray(shards + foreign)
            this["bounds"] = JsonObject(run.controlObject("bounds").toMutableMap().apply {
                this["maximumShards"] = JsonPrimitive(shards.size + 1)
            })
        }))
        val firstId = first.controlString("id")
        Files.copy(candidate.resolve("outputs/$firstId.json"), candidate.resolve("outputs/unexpected.json"))
        Files.copy(candidate.resolve("checkpoints/$firstId.json"), candidate.resolve("checkpoints/unexpected.json"))
        val rebound = FrozenBoundedShardFixture.rebind(candidate)
        freezeTree(candidate)
        assertEquals(3, BoundedShardRunVerifier.verify(candidate, rebound).outputs.size)
        val before = fileSnapshot(candidate)
        assertFailsWith<FullTreeCallObservationRunException> { validate(fixture, candidate, rebound) }
        assertSnapshot(before, candidate)
        assertScratchEmpty(fixture)
    }

    @Test
    fun `generic valid forged call facts fail raw rederivation without candidate changes`() = withRunFixture(nonempty = true) { fixture ->
        val original = fixture.outputParent.resolve("original")
        publish(fixture, original)
        val candidate = copyRun(original, fixture.outputParent.resolve("forged"))
        val shard = fixture.shards.single()
        val output = candidate.resolve("outputs/${shard.identifier}.json")
        val document = parseControlObject(output)
        val forged = JsonObject(document.toMutableMap().apply {
            this["counts"] = JsonObject(document.controlObject("counts").toMutableMap().apply {
                this["scannedDies"] = JsonPrimitive(document.controlObject("counts").controlLong("scannedDies") + 1L)
            })
        })
        FullTreeCallObservations.validateEnvelope(
            forged, fixture.scope.document, fixture.scope.sha256, fixture.inventory,
            fixtureSha256(fixture.inventoryPath), shard,
        )
        writeControlObject(output, forged)
        val rebound = FrozenBoundedShardFixture.rebind(candidate)
        freezeTree(candidate)
        assertEquals(7L, BoundedShardRunVerifier.verify(candidate, rebound).outputs.single().entities)
        val before = fileSnapshot(candidate)
        assertFailsWith<FullTreeCallObservationRunException> { validate(fixture, candidate, rebound) }
        assertSnapshot(before, candidate)
        assertFrozenTree(candidate)
        assertScratchEmpty(fixture)
    }

    @Test
    fun `run publication preserves existing destinations and refuses linked parents`() = withRunFixture { fixture ->
        val existingFile = fixture.outputParent.resolve("existing-file")
        Files.writeString(existingFile, "retained destination\n")
        val existingDirectory = privateDirectory(fixture.outputParent.resolve("existing-directory"))
        Files.writeString(existingDirectory.resolve("sentinel"), "retained child\n")
        val existingLink = fixture.outputParent.resolve("existing-link")
        Files.createSymbolicLink(existingLink, existingDirectory)
        val absent = fixture.root.resolve("absent")
        val danglingLink = fixture.outputParent.resolve("dangling-link")
        Files.createSymbolicLink(danglingLink, absent)
        listOf(existingFile, existingDirectory, existingLink, danglingLink).forEach { target ->
            assertFailsWith<FullTreeCallObservationRunException> { publish(fixture, target) }
            assertScratchEmpty(fixture)
        }
        val linkedParent = fixture.root.resolve("linked-parent")
        Files.createSymbolicLink(linkedParent, fixture.outputParent)
        assertFailsWith<FullTreeCallObservationRunException> { publish(fixture, linkedParent.resolve("candidate")) }
        assertEquals("retained destination\n", Files.readString(existingFile))
        assertEquals("retained child\n", Files.readString(existingDirectory.resolve("sentinel")))
        assertEquals(existingDirectory, Files.readSymbolicLink(existingLink))
        assertEquals(absent, Files.readSymbolicLink(danglingLink))
        assertFalse(Files.exists(absent, LinkOption.NOFOLLOW_LINKS))
        assertEquals(listOf("dangling-link", "existing-directory", "existing-file", "existing-link"), entryNames(fixture.outputParent))
        assertScratchEmpty(fixture)
    }

    @Test
    fun `linked raw run candidates fail without changing authentic output bytes`() = withRunFixture { fixture ->
        val original = fixture.outputParent.resolve("original")
        val receipt = publish(fixture, original)
        val before = fileSnapshot(original)
        val linkedRoot = fixture.outputParent.resolve("linked-root")
        Files.createSymbolicLink(linkedRoot, original)
        assertFailsWith<FullTreeCallObservationRunException> {
            validate(fixture, linkedRoot, receipt.indexArtifactSha256)
        }
        listOf(false, true).forEach { hardLink ->
            val candidate = copyRun(original, fixture.outputParent.resolve(if (hardLink) "hard-linked" else "symbolic-leaf"))
            val relative = "outputs/${fixture.shards.first().identifier}.json"
            val leaf = candidate.resolve(relative)
            Files.delete(leaf)
            if (hardLink) Files.createLink(leaf, original.resolve(relative))
            else Files.createSymbolicLink(leaf, original.resolve(relative))
            freezeTree(candidate)
            assertFailsWith<FullTreeCallObservationRunException> {
                validate(fixture, candidate, receipt.indexArtifactSha256)
            }
            Files.setPosixFilePermissions(leaf.parent, PosixFilePermissions.fromString("rwx------"))
            Files.delete(leaf)
            assertSnapshot(before, original)
            assertScratchEmpty(fixture)
        }
        assertEquals(receipt, validate(fixture, original, receipt.indexArtifactSha256))
    }

    @Test
    fun `run worker resource and index bounds reject and remove private staging`() = withRunFixture { fixture ->
        val candidate = fixture.outputParent.resolve("original")
        val receipt = publish(fixture, candidate)
        val before = fileSnapshot(candidate)
        listOf(0, 33).forEach { workers ->
            val output = fixture.outputParent.resolve("invalid-workers-$workers")
            assertFailsWith<FullTreeCallObservationRunException> { publish(fixture, output, workers) }
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
        }
        val limits = listOf(
            FullTreeCallObservationRunLimits(maximumScratchBytes = 1L),
            FullTreeCallObservationRunLimits(run = BoundedShardRunLimits(maximumShards = 1)),
            FullTreeCallObservationRunLimits(
                shard = FullTreeCallObservationPublicationLimits(sqlite = FullTreeCallObservationSqliteLimits(maximumOutputBytes = 32L)),
            ),
            FullTreeCallObservationRunLimits(
                shard = FullTreeCallObservationPublicationLimits(sqlite = FullTreeCallObservationSqliteLimits(maximumDatabaseBytes = 4096L)),
            ),
        )
        limits.forEachIndexed { index, limit ->
            val output = fixture.outputParent.resolve("limited-$index")
            assertFailsWith<FullTreeCallObservationRunException> { publish(fixture, output, limits = limit) }
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertFailsWith<FullTreeCallObservationRunException> {
                validate(fixture, candidate, receipt.indexArtifactSha256, limits = limit)
            }
            assertScratchEmpty(fixture)
        }
        assertFailsWith<FullTreeCallObservationRunException> {
            publish(fixture, fixture.outputParent.resolve("worker-ceiling"), 2,
                FullTreeCallObservationRunLimits(run = BoundedShardRunLimits(maximumWorkers = 1)))
        }
        assertFailsWith<FullTreeCallObservationRunException> { validate(fixture, candidate, "f".repeat(64)) }
        assertSnapshot(before, candidate)
        assertEquals(listOf("original"), entryNames(fixture.outputParent))
        assertScratchEmpty(fixture)
    }

    @Test
    fun `valid maximum signed scope ceilings fail bounded declaration admission without staging`() =
        withRunFixture(
            perShardBounds = mapOf("serializedBytes" to Long.MAX_VALUE),
            wholeRunBounds = mapOf("serializedBytes" to Long.MAX_VALUE),
        ) { fixture ->
            FullTreeScopeControl.validate(fixture.scope)
            val output = fixture.outputParent.resolve("oversized-declarations")
            val failure = assertFailsWith<FullTreeCallObservationRunException> { publish(fixture, output) }
            assertEquals("call-observation scope declarations exceed supported bounded-run ceilings", failure.message)
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
            assertEquals(emptyList(), entryNames(fixture.outputParent))
            assertScratchEmpty(fixture)
        }

    @Test
    fun `scratch reservations account for accumulated prepared outputs and revoke partial runs`() = withRunFixture { fixture ->
        val shardLimits = FullTreeCallObservationPublicationLimits(
            control = FullTreeControlLimits(maximumDwarfScratchBytes = 4L * 1024L * 1024L),
            sqlite = FullTreeCallObservationSqliteLimits(
                maximumDatabaseBytes = 1024L * 1024L,
                maximumOutputBytes = 1024L * 1024L,
            ),
        )
        val single = fixture.outputParent.resolve("single.json")
        FullTreeCallObservationShardPublisher.generateAndPublish(
            fixture.artifact, fixture.inventoryPath, fixture.scope, fixture.shards.first().identifier,
            fixture.scratch, single, shardLimits,
        )
        val singleBytes = Files.readAllBytes(single)
        val limits = FullTreeCallObservationRunLimits(
            shard = shardLimits,
            run = BoundedShardRunLimits(maximumControlArtifactBytes = 4096),
            maximumScratchBytes = 6L * 1024L * 1024L + 16L * 1024L,
        )
        val rejected = fixture.outputParent.resolve("exhausted")
        val failure = assertFailsWith<FullTreeCallObservationRunException> {
            publish(fixture, rejected, limits = limits)
        }
        assertEquals("call-observation run exceeds its conservative scratch reservation", failure.message)
        assertFalse(Files.exists(rejected, LinkOption.NOFOLLOW_LINKS))
        assertEquals(listOf("single.json"), entryNames(fixture.outputParent))
        assertContentEquals(singleBytes, Files.readAllBytes(single))
        assertScratchEmpty(fixture)
        val sufficient = limits.copy(maximumScratchBytes = 7L * 1024L * 1024L)
        val output = fixture.outputParent.resolve("sufficient")
        val receipt = publish(fixture, output, limits = sufficient)
        assertEquals(receipt, validate(fixture, output, receipt.indexArtifactSha256, limits = sufficient))
        assertFrozenTree(output)
        assertScratchEmpty(fixture)
    }

    @Test
    fun `whole operation deadline remains binding after starting a later shard`() =
        withRunFixture(perShardBounds = mapOf("wallClockSeconds" to 2L), wholeRunBounds = mapOf("wallClockSeconds" to 2L)) { fixture ->
            val whole = FullTreeCallObservationDeadline.startWholeRun(fixture.scope)
            Thread.sleep(1100L)
            val child = whole.startShard(fixture.scope)
            Thread.sleep(1100L)
            val rejected = fixture.outputParent.resolve("expired-shard.json")
            assertFailsWith<FullTreeCallObservationPublicationException> {
                FullTreeCallObservationShardPublisher.generateAndPublishWithinDeadline(
                    fixture.artifact, fixture.inventoryPath, fixture.scope, fixture.shards.first().identifier,
                    fixture.scratch, rejected, FullTreeCallObservationPublicationLimits(), child,
                )
            }
            assertFalse(Files.exists(rejected, LinkOption.NOFOLLOW_LINKS))
            assertScratchEmpty(fixture)
            val fresh = FullTreeCallObservationShardPublisher.generateAndPublish(
                fixture.artifact, fixture.inventoryPath, fixture.scope, fixture.shards.first().identifier,
                fixture.scratch, fixture.outputParent.resolve("fresh-shard.json"),
            )
            assertTrue(fresh.outputBytes > 0L)
            assertScratchEmpty(fixture)
            assertFailsWith<FullTreeControlException> { child.startShard(fixture.scope) }
        }

    @Test
    fun `raw run validation cannot reset an expired parent deadline or accept a shard deadline`() =
        withRunFixture(perShardBounds = mapOf("wallClockSeconds" to 5L), wholeRunBounds = mapOf("wallClockSeconds" to 5L)) { fixture ->
            val candidate = fixture.outputParent.resolve("complete")
            val receipt = publish(fixture, candidate)
            val before = fileSnapshot(candidate)
            val deadline = FullTreeCallObservationDeadline.startWholeRun(fixture.scope)
            Thread.sleep(5100L)
            val expired = assertFailsWith<FullTreeCallObservationRunException> {
                FullTreeCallObservationRunPublisher.loadAndValidateWithinDeadline(
                    candidate, receipt.indexArtifactSha256, fixture.artifact, fixture.inventoryPath,
                    fixture.scope, fixture.scratch, 1, FullTreeCallObservationRunLimits(), deadline,
                )
            }
            assertTrue(expired.cause is FullTreeControlException)
            assertTrue(expired.cause?.message.orEmpty().contains("wall-clock"), expired.cause?.message)
            assertSnapshot(before, candidate)
            assertScratchEmpty(fixture)
            assertEquals(receipt, validate(fixture, candidate, receipt.indexArtifactSha256))
            assertFailsWith<FullTreeCallObservationRunException> {
                FullTreeCallObservationRunPublisher.loadAndValidateWithinDeadline(
                    candidate, receipt.indexArtifactSha256, fixture.artifact, fixture.inventoryPath,
                    fixture.scope, fixture.scratch, 1, FullTreeCallObservationRunLimits(),
                    FullTreeCallObservationDeadline.start(fixture.scope),
                )
            }
            assertSnapshot(before, candidate)
            assertScratchEmpty(fixture)
        }

    @Test
    fun `preinterrupted whole run preserves interruption and leaves no staging`() = withRunFixture { fixture ->
        val output = fixture.outputParent.resolve("interrupted")
        try {
            Thread.currentThread().interrupt()
            assertFailsWith<FullTreeCallObservationRunException> { publish(fixture, output) }
            assertTrue(Thread.currentThread().isInterrupted)
        } finally {
            Thread.interrupted()
        }
        assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
        assertEquals(emptyList(), entryNames(fixture.outputParent))
        assertScratchEmpty(fixture)
    }

    private fun publish(
        fixture: RunFixture,
        output: Path,
        workers: Int = 1,
        limits: FullTreeCallObservationRunLimits = FullTreeCallObservationRunLimits(),
    ): FullTreeCallObservationRunPublication = FullTreeCallObservationRunPublisher.generateAndPublish(
        fixture.artifact, fixture.inventoryPath, fixture.scope, fixture.scratch, output, workers, limits,
    )

    private fun validate(
        fixture: RunFixture,
        candidate: Path,
        indexSha256: String,
        workers: Int = 1,
        limits: FullTreeCallObservationRunLimits = FullTreeCallObservationRunLimits(),
    ): FullTreeCallObservationRunPublication = FullTreeCallObservationRunPublisher.loadAndValidate(
        candidate, indexSha256, fixture.artifact, fixture.inventoryPath, fixture.scope, fixture.scratch, workers, limits,
    )

    private fun withRunFixture(
        nonempty: Boolean = false,
        perShardBounds: Map<String, Long> = emptyMap(),
        wholeRunBounds: Map<String, Long> = emptyMap(),
        action: (RunFixture) -> Unit,
    ) = inControlTemporaryDirectory { root ->
        val (artifact, originalScope) = if (nonempty) createNonemptyCallObservationTestArtifact(root) else {
            val controls = createFullTreeControlFixture(root.resolve("controls"))
            controls.richArtifact to controls.authenticatedScope()
        }
        val originalBounds = originalScope.document.controlObject("bounds")
        val document = JsonObject(originalScope.document.toMutableMap().apply {
            this["bounds"] = JsonObject(originalBounds.toMutableMap().apply {
                this["perShard"] = JsonObject(originalBounds.controlObject("perShard").toMutableMap().apply {
                    perShardBounds.forEach { (name, value) -> this[name] = JsonPrimitive(value) }
                })
                this["wholeRun"] = JsonObject(originalBounds.controlObject("wholeRun").toMutableMap().apply {
                    wholeRunBounds.forEach { (name, value) -> this[name] = JsonPrimitive(value) }
                })
            })
        })
        val scope = authenticatedScopeWithDocument(originalScope, document)
        val inventoryPath = root.resolve("inventory.json")
        val inventory = FullTreeInventoryControl.generateAndPublish(artifact, scope, inventoryPath, maximumWorkers = 1).inventory
        val shards = FullTreeCallObservations.shardInputs(inventory, fixtureSha256(inventoryPath), scope.document, scope.sha256)
        action(RunFixture(root, artifact, scope, inventoryPath, inventory, shards,
            privateDirectory(root.resolve("scratch")), privateDirectory(root.resolve("runs"))))
    }

    private fun copyRun(source: Path, target: Path): Path {
        Files.walk(source).use { paths ->
            paths.toList().sortedBy { it.nameCount }.forEach { path ->
                val destination = target.resolve(source.relativize(path))
                if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) privateDirectory(destination)
                else {
                    Files.copy(path, destination)
                    Files.setPosixFilePermissions(destination, PosixFilePermissions.fromString("rw-------"))
                }
            }
        }
        return target
    }

    private fun freezeTree(root: Path) {
        Files.walk(root).use { paths ->
            paths.toList().sortedByDescending { it.nameCount }.forEach { path ->
                when {
                    Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS) ->
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r-x------"))
                    Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS) ->
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
                }
            }
        }
    }

    private fun assertFrozenTree(root: Path) {
        Files.walk(root).use { paths ->
            paths.forEach { path ->
                val directory = Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)
                assertEquals(PosixFilePermissions.fromString(if (directory) "r-x------" else "r--------"),
                    Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS))
                if (!directory) assertEquals(1L, (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toLong())
            }
        }
    }

    private fun fileSnapshot(root: Path): Map<String, ByteArray> = Files.walk(root).use { paths ->
        paths.filter { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) }
            .toList().associate { root.relativize(it).toString() to Files.readAllBytes(it) }
    }

    private fun assertSnapshot(expected: Map<String, ByteArray>, root: Path) {
        val actual = fileSnapshot(root)
        assertEquals(expected.keys, actual.keys)
        expected.forEach { (name, bytes) -> assertContentEquals(bytes, actual.getValue(name), name) }
    }

    private fun expectedTree(shards: List<String>): List<String> =
        (listOf("checkpoints", "index.json", "outputs", "run.json") +
            shards.flatMap { listOf("checkpoints/$it.json", "outputs/$it.json") }).sorted()

    private fun treeMembers(root: Path): List<String> = Files.walk(root).use { paths ->
        paths.filter { it != root }.map { root.relativize(it).toString() }.sorted().toList()
    }

    private fun entryNames(root: Path): List<String> = Files.list(root).use { entries ->
        entries.map { it.fileName.toString() }.sorted().toList()
    }

    private fun privateDirectory(path: Path): Path = Files.createDirectory(path).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun assertScratchEmpty(fixture: RunFixture) {
        assertEquals(emptyList(), entryNames(fixture.scratch))
    }

    private data class RunFixture(
        val root: Path,
        val artifact: Path,
        val scope: AuthenticatedFullTreeScope,
        val inventoryPath: Path,
        val inventory: JsonObject,
        val shards: List<FullTreeCallObservationShardInput>,
        val scratch: Path,
        val outputParent: Path,
    )
}
