package decompengine.project

import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.net.URLClassLoader
import java.nio.file.Path
import javax.tools.ToolProvider
import kotlin.io.path.createTempDirectory
import kotlin.io.path.readText
import kotlin.io.path.writeText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

class ExporterSemanticStateBindingTest {
    @Test
    fun `exact production accumulator is deterministic and sensitive to every exported semantic category`() =
        withHarness { harness ->
            val baseline = semanticFixture()
            val expected = harness.fingerprint(baseline)

            assertEquals(expected, harness.fingerprint(baseline))
            listOf(
                baseline.mutateRecord(0, "name=alpha", "name=renamed"),
                baseline.mutateRecord(0, "prototype=int alpha(void)", "prototype=long alpha(int)"),
                baseline.mutateRecord(0, "calls=fn_0000000000002000", "calls=fn_0000000000003000"),
                baseline.mutateRecord(0, "globals=$GLOBAL_ONE", "globals=$GLOBAL_TWO"),
                baseline.mutateRecord(0, "strings=one", "strings=changed"),
                baseline.mutateRecord(1, "name=global_alpha", "name=DAT_4000"),
                baseline.mutateRecord(1, "type=int", "type=unsigned long"),
                baseline.mutateRecord(1, "initializer=7", "initializer=8"),
                baseline.mutateRecord(2, "declaration=typedef int alpha_t", "declaration=typedef long alpha_t"),
                baseline.mutateRecord(4, "message=reference recovery failed", "message=type recovery failed"),
            ).forEach { mutation ->
                assertNotEquals(expected, harness.fingerprint(mutation), mutation.toString())
            }
        }

    @Test
    fun `semantic drift in a future batch changes state before a completed prefix can be reused`() =
        withHarness { harness ->
            val baseline = semanticFixture()
            val originalFingerprint = harness.fingerprint(baseline)
            val futureMutation = baseline.mutateRecord(
                baseline.frames.lastIndex,
                "prototype=int future(void)",
                "prototype=int future(int drifted)",
            )
            val resumedFingerprint = harness.fingerprint(futureMutation)
            val originalState = state(originalFingerprint)
            val resumedState = state(resumedFingerprint)

            assertNotEquals(originalFingerprint, resumedFingerprint)
            val failure = assertFailsWith<InvocationTargetException> {
                harness.requireReusableState(originalState, resumedState)
            }
            assertTrue(failure.cause is IllegalStateException)
            assertTrue(failure.cause?.message.orEmpty().contains("whole-program semantic state differs"))

            val completedPrefix = BatchFragments("prefix-functions", "prefix-globals", "", "")
            val expectedFuture = BatchFragments("future-functions", "", "future-types", "")
            val driftedFuture = expectedFuture.copy(functions = "future-functions-drifted")
            assertNotEquals(
                harness.batchRoot(listOf(completedPrefix, expectedFuture)),
                harness.batchRoot(listOf(completedPrefix, driftedFuture)),
            )
            harness.requireBatchMatch(completedPrefix, completedPrefix)
            val batchFailure = assertFailsWith<InvocationTargetException> {
                harness.requireBatchMatch(expectedFuture, driftedFuture)
            }
            assertTrue(batchFailure.cause is IllegalStateException)
            assertTrue(batchFailure.cause?.message.orEmpty().contains("semantic preflight"))
        }

    @Test
    fun `exact batch commitments reject every fragment category before checkpoint authority`() =
        withHarness { harness ->
            val expected = BatchFragments("functions", "globals", "types", "failures")
            listOf(
                expected.copy(functions = "functions-drifted"),
                expected.copy(globals = "globals-drifted"),
                expected.copy(types = "types-drifted"),
                expected.copy(failures = "failures-drifted"),
            ).forEach { actual ->
                assertFailsWith<InvocationTargetException> {
                    harness.requireBatchMatch(expected, actual)
                }
            }
        }

    @Test
    fun `legacy state is never migrated into reusable schema two state`() = withHarness { harness ->
        val expected = state(harness.fingerprint(semanticFixture()))

        harness.requireReusableState(expected, expected)
        val failure = assertFailsWith<InvocationTargetException> {
            harness.requireReusableState(
                "{\"schemaVersion\":1,\"exporterVersion\":9}\n",
                expected,
            )
        }

        assertTrue(failure.cause is IllegalStateException)
        assertTrue(failure.cause?.message.orEmpty().contains("has no whole-program semantic binding"))
    }

    @Test
    fun `shared evidence is globally canonical and retained only once`() = withHarness { harness ->
        val single = SemanticFixture(
            listOf(
                Frame("function", FUNCTION_ONE, "function-one"),
                Frame("global", GLOBAL_ONE, "global-one"),
                Frame("type", TYPE_ONE, "type-one"),
            ),
        )
        val repeated = SemanticFixture(
            buildList {
                add(Frame("function", FUNCTION_ONE, "function-one"))
                repeat(10_000) {
                    add(Frame("global", GLOBAL_ONE, "global-one"))
                    add(Frame("type", TYPE_ONE, "type-one"))
                }
            },
        )
        val reverseObservationOrder = SemanticFixture(
            listOf(
                Frame("function", FUNCTION_ONE, "function-one"),
                Frame("global", GLOBAL_TWO, "global-two"),
                Frame("global", GLOBAL_ONE, "global-one"),
            ),
        )
        val forwardObservationOrder = SemanticFixture(
            listOf(
                Frame("function", FUNCTION_ONE, "function-one"),
                Frame("global", GLOBAL_ONE, "global-one"),
                Frame("global", GLOBAL_TWO, "global-two"),
            ),
        )

        assertEquals(harness.fingerprint(single), harness.fingerprint(repeated))
        assertEquals(harness.fingerprint(forwardObservationOrder), harness.fingerprint(reverseObservationOrder))
    }

    @Test
    fun `fingerprint framing rejects ambiguity unordered functions and byte overruns`() = withHarness { harness ->
        val outOfFunctionOrder = SemanticFixture(
            listOf(
                Frame("function", FUNCTION_THREE, "function-three"),
                Frame("function", FUNCTION_TWO, "function-two"),
            ),
        )
        val crossPairedFailure = SemanticFixture(
            listOf(
                Frame("function", FUNCTION_ONE, "function-one"),
                Frame("failure", FUNCTION_TWO, "failure-two"),
            ),
        )
        val conflictingSharedEvidence = SemanticFixture(
            listOf(
                Frame("function", FUNCTION_ONE, "function-one"),
                Frame("global", GLOBAL_ONE, "global-one"),
                Frame("function", FUNCTION_TWO, "function-two"),
                Frame("global", GLOBAL_ONE, "global-one-drifted"),
            ),
        )

        listOf(outOfFunctionOrder, crossPairedFailure, conflictingSharedEvidence).forEach { invalid ->
            assertFailsWith<InvocationTargetException> { harness.fingerprint(invalid) }
        }
        assertFailsWith<InvocationTargetException> {
            harness.fingerprint(
                SemanticFixture(
                    listOf(
                        Frame("function", FUNCTION_ONE, "function-one"),
                        Frame("global", GLOBAL_ONE, "x".repeat(1024 * 1024 + 1)),
                    ),
                ),
            )
        }
        assertFailsWith<InvocationTargetException> {
            harness.fingerprint(SemanticFixture(listOf(Frame("function", FUNCTION_ONE, "function-one"))), 64)
        }
    }
}

private data class Frame(val kind: String, val id: String, val record: String)

private data class BatchFragments(
    val functions: String,
    val globals: String,
    val types: String,
    val failures: String,
)

private data class SemanticFixture(val frames: List<Frame>) {
    fun mutateRecord(index: Int, old: String, new: String): SemanticFixture {
        val original = frames[index]
        val mutated = original.record.replace(old, new)
        require(mutated != original.record) { "semantic fixture mutation did not apply" }
        return copy(frames = frames.toMutableList().apply { this[index] = original.copy(record = mutated) })
    }
}

private fun semanticFixture() = SemanticFixture(
    listOf(
        Frame(
            "function",
            FUNCTION_ONE,
            "name=alpha;prototype=int alpha(void);calls=fn_0000000000002000;globals=$GLOBAL_ONE;strings=one",
        ),
        Frame("global", GLOBAL_ONE, "name=global_alpha;type=int;initializer=7"),
        Frame("type", TYPE_ONE, "declaration=typedef int alpha_t;sourceAddress=0x1000"),
        Frame(
            "function",
            FUNCTION_TWO,
            "name=beta;prototype=int beta(void);calls=;globals=;strings=two;status=failed",
        ),
        Frame("failure", FUNCTION_TWO, "message=reference recovery failed"),
        Frame(
            "function",
            FUNCTION_THREE,
            "name=future;prototype=int future(void);calls=fn_0000000000001000;globals=;strings=three",
        ),
    ),
)

private fun state(fingerprint: String): String =
    "{\"schemaVersion\":2,\"semanticStateBinding\":\"$fingerprint\"}\n"

private class FingerprintHarness(
    private val type: Class<*>,
) {
    fun fingerprint(fixture: SemanticFixture, maximumBytes: Long = 1024L * 1024 * 1024): String {
        val kinds = fixture.frames.map(Frame::kind).toTypedArray()
        val ids = fixture.frames.map(Frame::id).toTypedArray()
        val records = fixture.frames.map(Frame::record).toTypedArray()
        return type.getMethod(
            "fingerprint",
            java.lang.Long.TYPE,
            Array<String>::class.java,
            Array<String>::class.java,
            Array<String>::class.java,
        ).invoke(null, maximumBytes, kinds, ids, records) as String
    }

    fun requireReusableState(existing: String, expected: String) {
        type.getMethod("requireReusableState", String::class.java, String::class.java)
            .invoke(null, existing, expected)
    }

    fun batchRoot(batches: List<BatchFragments>): String {
        return type.getMethod(
            "batchRoot",
            Array<String>::class.java,
            Array<String>::class.java,
            Array<String>::class.java,
            Array<String>::class.java,
        ).invoke(
            null,
            batches.map(BatchFragments::functions).toTypedArray(),
            batches.map(BatchFragments::globals).toTypedArray(),
            batches.map(BatchFragments::types).toTypedArray(),
            batches.map(BatchFragments::failures).toTypedArray(),
        ) as String
    }

    fun requireBatchMatch(expected: BatchFragments, actual: BatchFragments) {
        type.getMethod(
            "requireBatchMatch",
            Array<String>::class.java,
            Array<String>::class.java,
        ).invoke(
            null,
            arrayOf(expected.functions, expected.globals, expected.types, expected.failures),
            arrayOf(actual.functions, actual.globals, actual.types, actual.failures),
        )
    }
}

private fun <T> withHarness(action: (FingerprintHarness) -> T): T {
    val exporter = Path.of("src/main/resources/ghidra_scripts/ExportProgramModel.java").readText()
    val beginMarker = "// SEMANTIC_FINGERPRINT_TEST_BEGIN\n"
    val endMarker = "// SEMANTIC_FINGERPRINT_TEST_END"
    val begin = exporter.indexOf(beginMarker)
    val end = exporter.indexOf(endMarker)
    require(begin >= 0 && end > begin) { "production semantic-fingerprint implementation markers are missing" }
    val implementation = exporter.substring(begin + beginMarker.length, end)
    val harnessSource = """
        import java.nio.charset.StandardCharsets;
        import java.security.MessageDigest;
        import java.util.ArrayList;
        import java.util.List;
        import java.util.Map;
        import java.util.TreeMap;

        $implementation

        public final class SemanticFingerprintHarness {
            public static String fingerprint(long maximumBytes, String[] kinds, String[] ids, String[] records)
                throws Exception {
                if (kinds.length != ids.length || ids.length != records.length) {
                    throw new IllegalArgumentException("fixture columns differ");
                }
                ExporterSemanticFingerprintV1 fingerprint = new ExporterSemanticFingerprintV1(maximumBytes);
                int functions = 0;
                for (int index = 0; index < kinds.length; index++) {
                    switch (kinds[index]) {
                        case "function": fingerprint.beginFunction(ids[index], records[index]); functions++; break;
                        case "global": fingerprint.observeGlobal(ids[index], records[index]); break;
                        case "type": fingerprint.observeType(ids[index], records[index]); break;
                        case "failure": fingerprint.observeFailure(ids[index], records[index]); break;
                        default: throw new IllegalArgumentException("unknown fixture kind");
                    }
                }
                ExporterSemanticFingerprintV1.Binding binding = fingerprint.finish(functions);
                return binding.canonicalBytes + ":" + binding.functionCount + ":" + binding.sha256;
            }

            public static void requireReusableState(String existing, String expected) {
                ExporterSemanticFingerprintV1.requireReusableState(existing, expected);
            }

            public static String batchRoot(
                String[] functions,
                String[] globals,
                String[] types,
                String[] failures
            ) throws Exception {
                if (
                    functions.length != globals.length || functions.length != types.length ||
                    functions.length != failures.length
                ) {
                    throw new IllegalArgumentException("batch fixture columns differ");
                }
                List<ExporterSemanticFingerprintV1.BatchCommitment> commitments = new ArrayList<>();
                for (int index = 0; index < functions.length; index++) {
                    commitments.add(ExporterSemanticFingerprintV1.commitBatch(
                        index,
                        index + 1,
                        functions[index],
                        globals[index],
                        types[index],
                        failures[index]
                    ));
                }
                return ExporterSemanticFingerprintV1.batchCommitmentSha256(commitments);
            }

            public static void requireBatchMatch(String[] expected, String[] actual) throws Exception {
                if (expected.length != 4 || actual.length != 4) {
                    throw new IllegalArgumentException("batch fixture must contain four fragments");
                }
                ExporterSemanticFingerprintV1.requireBatchCommitment(
                    ExporterSemanticFingerprintV1.commitBatch(
                        0, 1, expected[0], expected[1], expected[2], expected[3]
                    ),
                    ExporterSemanticFingerprintV1.commitBatch(
                        0, 1, actual[0], actual[1], actual[2], actual[3]
                    )
                );
            }
        }
    """.trimIndent()
    val temporary = createTempDirectory("exporter-semantic-fingerprint-")
    val source = temporary.resolve("SemanticFingerprintHarness.java").also { it.writeText(harnessSource) }
    val compiler = ToolProvider.getSystemJavaCompiler() ?: error("semantic-fingerprint tests require a JDK")
    val diagnostics = ByteArrayOutputStream()
    val result = compiler.run(
        null,
        diagnostics,
        diagnostics,
        "-Xlint:all",
        "-Werror",
        "-d",
        temporary.toString(),
        source.toString(),
    )
    check(result == 0) { diagnostics.toString(Charsets.UTF_8) }
    val loader = URLClassLoader(arrayOf(temporary.toUri().toURL()))
    return try {
        action(FingerprintHarness(loader.loadClass("SemanticFingerprintHarness")))
    } finally {
        loader.close()
        temporary.toFile().deleteRecursively()
    }
}

private const val FUNCTION_ONE = "fn_0000000000001000"
private const val FUNCTION_TWO = "fn_0000000000002000"
private const val FUNCTION_THREE = "fn_0000000000003000"
private const val GLOBAL_ONE = "global_0000000000004000"
private const val GLOBAL_TWO = "global_0000000000005000"
private val TYPE_ONE = "type_" + "a".repeat(64)
