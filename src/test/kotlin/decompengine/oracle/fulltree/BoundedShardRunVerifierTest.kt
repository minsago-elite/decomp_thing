package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.io.BufferedOutputStream
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class BoundedShardRunVerifierTest {
    @Test
    fun `frozen historical v1 runs authenticate exact bytes and bindings`(): Unit =
        inTemporaryDirectory { directory ->
            val first = FrozenBoundedShardFixture.copyRun(1, directory.resolve("workers-1"))
            val second = FrozenBoundedShardFixture.copyRun(2, directory.resolve("workers-2"))

            val firstBinding = BoundedShardRunVerifier.verify(first, FROZEN_FIRST_INDEX_SHA256)
            val secondBinding = BoundedShardRunVerifier.verify(second, FROZEN_SECOND_INDEX_SHA256)

            assertEquals(FROZEN_FIRST_RUN_SHA256, firstBinding.runSha256)
            assertEquals(FROZEN_SECOND_RUN_SHA256, secondBinding.runSha256)
            assertEquals(listOf("alpha", "omega"), firstBinding.outputs.map { it.shardId })
            assertEquals(listOf(210L, 210L), firstBinding.outputs.map { it.outputBytes })
            assertEquals(listOf(1L, 1L), firstBinding.outputs.map { it.entities })
            assertEquals(1, firstBinding.maximumWorkers)
            assertEquals(2, secondBinding.maximumWorkers)
        }

    @Test
    fun `canonical output authentication rejects whitespace duplicates and malformed tails after rebinding`(): Unit =
        inTemporaryDirectory { directory ->
            val whitespace = FrozenBoundedShardFixture.copyRun(1, directory.resolve("whitespace"))
            val whitespacePath = whitespace.resolve("outputs/alpha.json")
            Files.write(whitespacePath, byteArrayOf(' '.code.toByte()) + Files.readAllBytes(whitespacePath))
            val whitespaceIndex = FrozenBoundedShardFixture.rebind(whitespace)
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(whitespace, whitespaceIndex)
            }

            val duplicate = FrozenBoundedShardFixture.copyRun(1, directory.resolve("duplicate"))
            val duplicateBytes = "{\n  \"same\": 1,\n  \"same\": 2\n}\n".toByteArray(StandardCharsets.UTF_8)
            Files.write(duplicate.resolve("outputs/alpha.json"), duplicateBytes)
            val duplicateIndex = FrozenBoundedShardFixture.rebind(duplicate)
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(duplicate, duplicateIndex)
            }

            val malformed = FrozenBoundedShardFixture.copyRun(1, directory.resolve("malformed"))
            Files.write(malformed.resolve("outputs/alpha.json"), "{\n".toByteArray(StandardCharsets.UTF_8))
            val malformedIndex = FrozenBoundedShardFixture.rebind(malformed)
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(malformed, malformedIndex)
            }
        }

    @Test
    fun `missing extra stale and substituted tree members fail closed`(): Unit =
        inTemporaryDirectory { directory ->
            val extra = FrozenBoundedShardFixture.copyRun(1, directory.resolve("extra"))
            Files.writeString(extra.resolve("outputs/unindexed.json"), "{}\n")
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(extra, FROZEN_FIRST_INDEX_SHA256)
            }

            val missing = FrozenBoundedShardFixture.copyRun(1, directory.resolve("missing"))
            Files.delete(missing.resolve("checkpoints/omega.json"))
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(missing, FROZEN_FIRST_INDEX_SHA256)
            }

            val stale = FrozenBoundedShardFixture.copyRun(1, directory.resolve("stale"))
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(stale, "f".repeat(64))
            }

            val substituted = FrozenBoundedShardFixture.copyRun(1, directory.resolve("substituted"))
            val checkpoint = substituted.resolve("checkpoints/alpha.json")
            val document = FrozenBoundedShardFixture.parseObject(Files.readAllBytes(checkpoint))
            FrozenBoundedShardFixture.writeCanonical(
                checkpoint,
                JsonObject(document + ("entities" to JsonPrimitive(2))),
            )
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(substituted, FROZEN_FIRST_INDEX_SHA256)
            }
        }

    @Test
    fun `run bounds counts commitments and caller ceilings remain authoritative`(): Unit =
        inTemporaryDirectory { directory ->
            val badWorkers = FrozenBoundedShardFixture.copyRun(1, directory.resolve("workers"))
            val run = FrozenBoundedShardFixture.parseObject(Files.readAllBytes(badWorkers.resolve("run.json")))
            val bounds = run.requiredObject("bounds")
            FrozenBoundedShardFixture.writeCanonical(
                badWorkers.resolve("run.json"),
                JsonObject(run + ("bounds" to JsonObject(bounds + ("maximumWorkers" to JsonPrimitive(33))))),
            )
            val badWorkersIndex = FrozenBoundedShardFixture.rebind(badWorkers)
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(badWorkers, badWorkersIndex)
            }

            val badCounts = FrozenBoundedShardFixture.copyRun(1, directory.resolve("counts"))
            val badCountsIndex = FrozenBoundedShardFixture.mutateIndex(badCounts) { index ->
                val counts = index.requiredObject("counts")
                JsonObject(index + ("counts" to JsonObject(counts + ("entities" to JsonPrimitive(3)))))
            }
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(badCounts, badCountsIndex)
            }

            val badCommitment = FrozenBoundedShardFixture.copyRun(1, directory.resolve("commitment"))
            val badCommitmentIndex = FrozenBoundedShardFixture.mutateIndex(badCommitment) { index ->
                JsonObject(index + ("indexSha256" to JsonPrimitive("e".repeat(64))))
            }
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(badCommitment, badCommitmentIndex)
            }

            val bounded = FrozenBoundedShardFixture.copyRun(2, directory.resolve("caller-bounds"))
            listOf(
                BoundedShardRunLimits(maximumShards = 1),
                BoundedShardRunLimits(maximumWorkers = 1),
                BoundedShardRunLimits(
                    maximumPerShardEntities = 1,
                    maximumWholeRunEntities = 1,
                ),
                BoundedShardRunLimits(
                    maximumPerShardOutputBytes = 4095,
                    maximumWholeRunOutputBytes = 8191,
                    maximumTotalStringBytesPerOutput = 4095,
                ),
            ).forEach { limits ->
                assertFailsWith<BoundedShardRunException> {
                    BoundedShardRunVerifier.verify(bounded, FROZEN_SECOND_INDEX_SHA256, limits)
                }
            }
        }

    @Test
    fun `streaming limits deadlines and Unicode code point order are deterministic`(): Unit =
        inTemporaryDirectory { directory ->
            val unicode = FrozenBoundedShardFixture.copyRun(1, directory.resolve("unicode"))
            val unicodeOutput = JsonObject(
                mapOf(
                    "\ud83d\ude00" to JsonPrimitive("supplementary"),
                    "\ue000" to JsonPrimitive("bmp"),
                ),
            )
            FrozenBoundedShardFixture.writeCanonical(unicode.resolve("outputs/alpha.json"), unicodeOutput)
            val unicodeIndex = FrozenBoundedShardFixture.rebind(unicode)
            val unicodeBinding = BoundedShardRunVerifier.verify(unicode, unicodeIndex)
            assertEquals("alpha", unicodeBinding.outputs.first().shardId)

            val tokenBound = FrozenBoundedShardFixture.copyRun(1, directory.resolve("tokens"))
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(
                    tokenBound,
                    FROZEN_FIRST_INDEX_SHA256,
                    BoundedShardRunLimits(maximumTokensPerOutput = 5),
                )
            }

            val stringBound = FrozenBoundedShardFixture.copyRun(1, directory.resolve("strings"))
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verify(
                    stringBound,
                    FROZEN_FIRST_INDEX_SHA256,
                    BoundedShardRunLimits(maximumStringBytes = 8),
                )
            }

            val deadline = FrozenBoundedShardFixture.copyRun(1, directory.resolve("deadline"))
            var reached = false
            val runtime = BoundedShardVerifierRuntime { stage ->
                if (stage == "after bounded-shard run contract read") reached = true
                BoundedShardVerifierRuntimeSample(
                    wallNanos = if (reached) 3601L * 1_000_000_000L else 0L,
                    processCpuNanos = 0L,
                )
            }
            assertFailsWith<BoundedShardRunException> {
                BoundedShardRunVerifier.verifyForTesting(
                    deadline,
                    FROZEN_FIRST_INDEX_SHA256,
                    runtime = runtime,
                )
            }
            assertTrue(reached)
        }

    @Test
    fun `canonical outputs above the control artifact ceiling remain streaming bounded`(): Unit =
        inTemporaryDirectory { directory ->
            val root = FrozenBoundedShardFixture.copyRun(1, directory.resolve("large-output"))
            val output = root.resolve("outputs/alpha.json")
            val chunk = ByteArray(1_000_000) { 'a'.code.toByte() }
            BufferedOutputStream(Files.newOutputStream(output), 1024 * 1024).use { stream ->
                stream.write("{\n  \"chunks\": [\n".toByteArray(StandardCharsets.UTF_8))
                repeat(18) { index ->
                    stream.write("    \"".toByteArray(StandardCharsets.UTF_8))
                    stream.write(chunk)
                    stream.write(if (index == 17) "\"\n".toByteArray() else "\",\n".toByteArray())
                }
                stream.write("  ]\n}\n".toByteArray(StandardCharsets.UTF_8))
            }
            val outputBytes = Files.size(output)
            assertTrue(outputBytes > 16L * 1024L * 1024L)
            val runPath = root.resolve("run.json")
            val run = FrozenBoundedShardFixture.parseObject(Files.readAllBytes(runPath))
            val bounds = run.requiredObject("bounds")
            FrozenBoundedShardFixture.writeCanonical(
                runPath,
                JsonObject(
                    run + (
                        "bounds" to JsonObject(
                            bounds + mapOf(
                                "perShardBytes" to JsonPrimitive(outputBytes),
                                "wholeRunBytes" to JsonPrimitive(outputBytes + 210L),
                            ),
                        )
                    ),
                ),
            )
            val indexSha256 = FrozenBoundedShardFixture.rebind(root)

            val binding = BoundedShardRunVerifier.verify(root, indexSha256)
            assertEquals(outputBytes, binding.outputs.first().outputBytes)
        }

    private inline fun <T> inTemporaryDirectory(block: (Path) -> T): T {
        val directory = createTempDirectory("bounded-shard-run-verifier-test-")
        return try {
            block(directory)
        } finally {
            val paths = Files.walk(directory).use { it.toList() }
            paths.filter { Files.isDirectory(it) }.forEach { path ->
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            }
            paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
        }
    }

    private companion object {
        const val FROZEN_FIRST_INDEX_SHA256 =
            "9784e592199e923ba238ba7eddc8a8059164b97c3d3afac4000131007df58ec4"
        const val FROZEN_SECOND_INDEX_SHA256 =
            "232cc1cd9b47b931174cf84ebe8b5301c254c4898b0dc4a7e8e6346355ae55bd"
        const val FROZEN_FIRST_RUN_SHA256 =
            "01f7d381e08676528d873ecf6be1e2a0aa2659ea4b2befa33625d01444d71d24"
        const val FROZEN_SECOND_RUN_SHA256 =
            "c03be117c0532c81c1b058c88e173cfb258757103fa6927db4032aeff7bd3c2e"
    }
}

internal object FrozenBoundedShardFixture {
    private val members = listOf(
        "run.json",
        "index.json",
        "checkpoints/alpha.json",
        "checkpoints/omega.json",
        "outputs/alpha.json",
        "outputs/omega.json",
    )

    fun copyRun(workers: Int, target: Path): Path {
        require(workers == 1 || workers == 2)
        Files.createDirectories(target.resolve("checkpoints"))
        Files.createDirectories(target.resolve("outputs"))
        members.forEach { relative ->
            val bytes = checkNotNull(
                javaClass.getResourceAsStream(
                    "/oracle/bounded-shard-run-v1-frozen/workers-$workers/$relative",
                ),
            ) { "frozen bounded-shard fixture member is unavailable: $relative" }.use { it.readAllBytes() }
            Files.write(target.resolve(relative), bytes)
        }
        return target
    }

    fun rebind(root: Path): String {
        val run = parseObject(Files.readAllBytes(root.resolve("run.json")))
        val runBytes = OracleJson.canonicalBytes(run)
        Files.write(root.resolve("run.json"), runBytes)
        val runSha256 = OracleArtifacts.sha256(runBytes)
        val shards = run.requiredArray("shards").objects("bounded shard")
        val records = shards.map { shard ->
            val identifier = shard.requiredString("id")
            val checkpointPath = root.resolve("checkpoints/$identifier.json")
            val previous = parseObject(Files.readAllBytes(checkpointPath))
            val output = digestFile(root.resolve("outputs/$identifier.json"))
            val record = JsonObject(
                mapOf(
                    "entities" to previous.requiredElement("entities"),
                    "inputSha256" to shard.requiredElement("inputSha256"),
                    "outputBytes" to JsonPrimitive(output.first),
                    "outputSha256" to JsonPrimitive(output.second),
                    "runSha256" to JsonPrimitive(runSha256),
                    "schemaVersion" to JsonPrimitive(1),
                    "shardId" to JsonPrimitive(identifier),
                    "status" to JsonPrimitive("complete"),
                ),
            )
            writeCanonical(checkpointPath, record)
            record
        }
        val leaves = MessageDigest.getInstance("SHA-256").apply {
            update("bounded-shards-v1\u0000".toByteArray(StandardCharsets.UTF_8))
            records.forEach { record ->
                update(MessageDigest.getInstance("SHA-256").digest(OracleJson.canonicalBytes(record)))
            }
        }.digest().hex()
        val index = JsonObject(
            mapOf(
                "complete" to JsonPrimitive(true),
                "counts" to JsonObject(
                    mapOf(
                        "entities" to JsonPrimitive(records.sumOf { it.requiredLong("entities") }),
                        "serializedBytes" to JsonPrimitive(records.sumOf { it.requiredLong("outputBytes") }),
                        "shards" to JsonPrimitive(records.size),
                    ),
                ),
                "indexSha256" to JsonPrimitive(leaves),
                "runSha256" to JsonPrimitive(runSha256),
                "schemaVersion" to JsonPrimitive(1),
                "shards" to JsonArray(records),
            ),
        )
        writeCanonical(root.resolve("index.json"), index)
        return OracleArtifacts.sha256(Files.readAllBytes(root.resolve("index.json")))
    }

    fun mutateIndex(root: Path, mutate: (JsonObject) -> JsonObject): String {
        val path = root.resolve("index.json")
        writeCanonical(path, mutate(parseObject(Files.readAllBytes(path))))
        return OracleArtifacts.sha256(Files.readAllBytes(path))
    }

    fun parseObject(bytes: ByteArray): JsonObject = OracleJson.parseCanonical(bytes) as JsonObject

    fun writeCanonical(path: Path, value: JsonObject) {
        Files.write(path, OracleJson.canonicalBytes(value))
    }

    private fun digestFile(path: Path): Pair<Long, String> {
        val digest = MessageDigest.getInstance("SHA-256")
        var bytes = 0L
        val buffer = ByteArray(1024 * 1024)
        Files.newInputStream(path).use { stream ->
            while (true) {
                val read = stream.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                bytes = Math.addExact(bytes, read.toLong())
                digest.update(buffer, 0, read)
            }
        }
        return bytes to digest.digest().hex()
    }

    private fun ByteArray.hex(): String = joinToString("") { byte ->
        (byte.toInt() and 0xff).toString(16).padStart(2, '0')
    }
}
