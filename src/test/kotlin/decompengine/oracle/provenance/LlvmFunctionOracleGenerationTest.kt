package decompengine.oracle.provenance

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.fulltree.BoundedDwarfFunctionFacts
import decompengine.oracle.fulltree.BoundedFunctionEvidence
import decompengine.oracle.fulltree.FullTreeElfExecutableRange
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
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.Assumptions.assumeTrue

class LlvmFunctionOracleGenerationTest {
    @Test
    fun `composer preserves v1 ordering evidence aliases availability and exclusions`() {
        val rich = facts(
            hash('a'),
            linkedMapOf(
                0x20UL to linkedMapOf(
                    "later" to listOf(BoundedFunctionEvidence("dwarf-subprogram", "rich:z")),
                ),
                0x10UL to linkedMapOf(
                    "\ud83d\ude00" to listOf(BoundedFunctionEvidence("dwarf-subprogram", "rich:emoji")),
                    "\ue000" to listOf(
                        BoundedFunctionEvidence("elf-symbol", "rich:b"),
                        BoundedFunctionEvidence("dwarf-subprogram", "rich:a"),
                    ),
                ),
            ),
        )
        val stripped = facts(
            hash('b'),
            linkedMapOf(
                0x10UL to linkedMapOf(
                    "\ue000" to listOf(BoundedFunctionEvidence("elf-symbol", "stripped:a")),
                ),
            ),
        )
        val document = LlvmFunctionOracleTestSupport.compose(
            "clang-driver-test",
            hash('c'),
            rich,
            stripped,
            mapOf(0x20UL to "reviewed compiler entry"),
        )
        val functions = document.getValue("functions") as JsonArray
        assertEquals(listOf("function-rva-0x10", "function-rva-0x20"), functions.map {
            ((it as JsonObject).getValue("id") as JsonPrimitive).content
        })
        val firstAliases = ((functions[0] as JsonObject).getValue("aliases") as JsonArray)
        assertEquals(listOf("\ue000", "\ud83d\ude00"), firstAliases.map {
            (((it as JsonObject).getValue("name")) as JsonPrimitive).content
        })
        val first = firstAliases[0] as JsonObject
        val evidence = first.getValue("evidence") as JsonArray
        assertEquals(
            listOf("dwarf-subprogram:rich:a", "elf-symbol:rich:b", "elf-symbol:stripped:a"),
            evidence.map { raw ->
                val item = raw as JsonObject
                "${(item.getValue("kind") as JsonPrimitive).content}:" +
                    (item.getValue("locator") as JsonPrimitive).content
            },
        )
        assertEquals(
            JsonObject(
                mapOf(
                    "rich" to JsonPrimitive("surviving"),
                    "stripped" to JsonPrimitive("surviving"),
                ),
            ),
            first.getValue("availability"),
        )
        val emojiAvailability = (firstAliases[1] as JsonObject).getValue("availability") as JsonObject
        assertEquals(JsonPrimitive("removed"), emojiAvailability.getValue("stripped"))
        assertEquals(JsonNull, (functions[0] as JsonObject).getValue("exclusion"))
        assertEquals(
            "compiler-generated",
            ((((functions[1] as JsonObject).getValue("exclusion")) as JsonObject)
                .getValue("kind") as JsonPrimitive).content,
        )

        val canonical = OracleJson.canonicalBytes(document)
        assertContentEquals(canonical, OracleJson.canonicalBytes(OracleJson.parseCanonical(canonical)))
    }

    @Test
    fun `composer rejects twin drift stripped inventions and unbound exclusions`() {
        val rich = facts(hash('a'), mapOf(0x10UL to mapOf("rich" to evidence("rich"))))
        val strippedRva = facts(hash('b'), mapOf(0x20UL to mapOf("new" to evidence("stripped"))))
        assertFailsWith<LlvmFunctionOracleGenerationException> {
            LlvmFunctionOracleTestSupport.compose("oracle", hash('c'), rich, strippedRva)
        }
        val strippedName = facts(hash('b'), mapOf(0x10UL to mapOf("new" to evidence("stripped"))))
        assertFailsWith<LlvmFunctionOracleGenerationException> {
            LlvmFunctionOracleTestSupport.compose("oracle", hash('c'), rich, strippedName)
        }
        val mismatchedLayout = BoundedDwarfFunctionFacts(
            hash('b'),
            "ET_EXEC",
            0UL,
            listOf(FullTreeElfExecutableRange(0UL, 0x100UL)),
            emptyMap(),
            emptyList(),
        )
        assertFailsWith<LlvmFunctionOracleGenerationException> {
            LlvmFunctionOracleTestSupport.compose("oracle", hash('c'), rich, mismatchedLayout)
        }
        assertFailsWith<LlvmFunctionOracleGenerationException> {
            LlvmFunctionOracleTestSupport.compose(
                "oracle",
                hash('c'),
                rich,
                facts(hash('b'), emptyMap()),
                mapOf(0x99UL to "absent"),
            )
        }
    }

    @Test
    fun `dedicated publisher exceeds legacy state ceiling but remains bounded immutable and no replace`(): Unit =
        withPrivateDirectory { root ->
            val bytes = ByteArray(1024 * 1024 + 1) { index -> (index and 0xff).toByte() }
            LinuxFilesystemSyscalls.openRoot(root).use { parent ->
                assertFailsWith<IllegalArgumentException> {
                    DescriptorBoundAtomicStateFile.publishNoReplace(
                        parent,
                        "legacy.json",
                        byteArrayOf(1),
                        1024 * 1024 + 1,
                    )
                }
            }

            val output = root.resolve("function-oracle.json")
            val sha256 = LlvmFunctionOracleTestSupport.publishNoReplace(output, bytes)
            assertEquals(OracleArtifacts.sha256(bytes), sha256)
            assertEquals(bytes.size.toLong(), Files.size(output))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(output, LinkOption.NOFOLLOW_LINKS),
            )
            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleTestSupport.publishNoReplace(output, bytes)
            }
            assertContentEquals(bytes, Files.readAllBytes(output))

            val collisionOutput = root.resolve("collision.json")
            val temporary = root.resolve(".collision.json.function-oracle.atomic")
            Files.write(temporary, "foreign".toByteArray())
            Files.setPosixFilePermissions(temporary, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleTestSupport.publishNoReplace(collisionOutput, "expected".toByteArray())
            }
            assertFalse(Files.exists(collisionOutput, LinkOption.NOFOLLOW_LINKS))
            assertContentEquals("foreign".toByteArray(), Files.readAllBytes(temporary))

            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleTestSupport.publishNoReplace(
                    root.resolve("oversized.json"),
                    ByteArray(64 * 1024 * 1024 + 1),
                )
            }
        }

    @Test
    fun `dedicated publisher requires a real owner-only parent`(): Unit =
        withPrivateDirectory { root ->
            val permissive = root.resolve("permissive")
            Files.createDirectory(permissive)
            Files.setPosixFilePermissions(permissive, PosixFilePermissions.fromString("rwxr-x---"))
            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleTestSupport.publishNoReplace(
                    permissive.resolve("function-oracle.json"),
                    byteArrayOf(1),
                )
            }
            assertFalse(Files.exists(permissive.resolve("function-oracle.json"), LinkOption.NOFOLLOW_LINKS))

            val real = root.resolve("real")
            Files.createDirectory(real)
            Files.setPosixFilePermissions(real, PosixFilePermissions.fromString("rwx------"))
            val symbolic = root.resolve("symbolic")
            Files.createSymbolicLink(symbolic, real)
            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleTestSupport.publishNoReplace(
                    symbolic.resolve("function-oracle.json"),
                    byteArrayOf(1),
                )
            }
            assertFalse(Files.exists(real.resolve("function-oracle.json"), LinkOption.NOFOLLOW_LINKS))
        }

    @Test
    fun `production JVM authority exposes exactly four raw Path inputs`() {
        val methods = LlvmFunctionOracleGenerator::class.java.declaredMethods
            .filter { it.name == "generate" }
        assertEquals(1, methods.size)
        assertEquals(List(4) { Path::class.java }, methods.single().parameterTypes.toList())
        val production = LlvmFunctionOracleGenerator::class.java.declaredClasses.single {
            it.simpleName == "ProductionGeneration"
        }
        val constructors = production.declaredConstructors
        assertEquals(1, constructors.size)
        assertEquals(List(4) { Path::class.java }, constructors.single().parameterTypes.toList())
        assertTrue(LlvmFunctionOracleTestSupport::class.java.name.contains("TestSupport"))
    }

    @Test
    fun `real Kotlin authority reproduces the checked LLVM v1 bytes exactly`() {
        val rawRoot = System.getenv("LLVM_ORACLE_ARTIFACT_ROOT")?.takeIf(String::isNotBlank)
        assumeTrue(rawRoot != null, "set LLVM_ORACLE_ARTIFACT_ROOT for the long parity proof")
        val artifactRoot = Path.of(checkNotNull(rawRoot)).toAbsolutePath().normalize()
        withPrivateDirectory { outputRoot ->
            val output = outputRoot.resolve("function-recovery-oracle.json")
            val result = LlvmFunctionOracleGenerator.generate(
                Path.of("oracle/llvm/22.1.6/oracle-manifest.json"),
                Path.of("oracle/llvm/22.1.6/function-recovery-exclusions.json"),
                artifactRoot,
                output,
            )
            val expected = Files.readAllBytes(Path.of("oracle/llvm/22.1.6/function-recovery-oracle.json"))
            assertEquals(4_674_632, result.outputBytes)
            assertEquals(4_303, result.functions)
            assertEquals(0, result.exclusions)
            assertEquals(EXPECTED_ORACLE_SHA256, result.outputSha256)
            assertContentEquals(expected, Files.readAllBytes(output))
            assertEquals(
                PosixFilePermissions.fromString("r--------"),
                Files.getPosixFilePermissions(output, LinkOption.NOFOLLOW_LINKS),
            )
        }
    }

    @Test
    fun `real authority rejects output input alias and terminal exclusion drift`() {
        val rawRoot = System.getenv("LLVM_ORACLE_ARTIFACT_ROOT")?.takeIf(String::isNotBlank)
        assumeTrue(rawRoot != null, "set LLVM_ORACLE_ARTIFACT_ROOT for the long hostile proof")
        val artifactRoot = Path.of(checkNotNull(rawRoot)).toAbsolutePath().normalize()
        val manifest = Path.of("oracle/llvm/22.1.6/oracle-manifest.json")
        withPrivateDirectory { outputRoot ->
            val exclusions = outputRoot.resolve("function-recovery-exclusions.json")
            Files.copy(Path.of("oracle/llvm/22.1.6/function-recovery-exclusions.json"), exclusions)
            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleGenerator.generate(manifest, exclusions, artifactRoot, exclusions)
            }

            val output = outputRoot.resolve("function-recovery-oracle.json")
            assertFailsWith<LlvmFunctionOracleGenerationException> {
                LlvmFunctionOracleTestSupport.generateWithFault(
                    manifest,
                    exclusions,
                    artifactRoot,
                    output,
                    LlvmFunctionOracleGenerationFaultInjector { point ->
                        if (point == LlvmFunctionOracleGenerationPoint.AFTER_STAGE_VALIDATION) {
                            Files.createLink(outputRoot.resolve("exclusions-hard-link.json"), exclusions)
                        }
                    },
                )
            }
            assertFalse(Files.exists(output, LinkOption.NOFOLLOW_LINKS))
        }
    }

    private fun facts(
        sha256: String,
        aliases: Map<ULong, Map<String, List<BoundedFunctionEvidence>>>,
    ): BoundedDwarfFunctionFacts = BoundedDwarfFunctionFacts(
        sha256,
        "ET_DYN",
        0UL,
        listOf(FullTreeElfExecutableRange(0UL, 0x100UL)),
        aliases,
        emptyList(),
    )

    private fun evidence(locator: String) = listOf(BoundedFunctionEvidence("elf-symbol", locator))

    private inline fun <T> withPrivateDirectory(action: (Path) -> T): T {
        val directory = createTempDirectory("llvm-function-oracle-").toAbsolutePath().normalize()
        Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
        return try {
            action(directory)
        } finally {
            if (Files.exists(directory, LinkOption.NOFOLLOW_LINKS)) {
                Files.walk(directory).use { paths -> paths.toList() }
                    .sortedWith(Comparator.reverseOrder())
                    .forEach(Files::deleteIfExists)
            }
        }
    }

    private fun hash(character: Char): String = character.toString().repeat(64)

    private companion object {
        const val EXPECTED_ORACLE_SHA256 =
            "a37d6eda0fb9b95fa884c8ce4eff358ab7bf424fa9b990e61cb4f465f3e0410c"
    }
}
