package decompengine.analysis

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.util.Properties
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class AnalysisIoHelperBuildV1Test {
    @Test fun `actual compiler builds the closed analysis source policy executable tuple`() = withAnalysisBuildDirectory { root ->
        val output = Files.createDirectory(root.resolve("output"))
        val tuple = AnalysisIoHelperBuildV1.build(analysisTestCompiler(), analysisTestSource(), output)
        val metadata = tuple.parent
        val propertiesBytes = Files.readAllBytes(tuple)
        val lines = propertiesBytes.toString(Charsets.US_ASCII).lineSequence().filter(String::isNotEmpty).toList()
        assertEquals(11, lines.size)
        assertEquals(11, lines.map { it.substringBefore('=') }.toSet().size)
        val properties = Properties().apply { propertiesBytes.inputStream().use(::load) }
        assertEquals(setOf("schemaVersion", "sourcePath", "sourceSha256", "buildPolicySha256", "helperSha256", "helperBytes",
            "architecture", "binaryName", "buildRecordPath", "buildRecordBytes", "buildRecordSha256"), properties.stringPropertyNames())
        assertEquals("analysis-native-io/source.c", properties.getProperty("sourcePath"))
        assertEquals("analysis-native-io/build-v1.json", properties.getProperty("buildRecordPath"))
        val source = Files.readAllBytes(metadata.resolve("source.c"))
        assertTrue(source.contentEquals(Files.readAllBytes(analysisTestSource())))
        assertEquals(ANALYSIS_IO_REVIEWED_SOURCE_SHA256, properties.getProperty("sourceSha256"))
        val policy = Files.readAllBytes(metadata.resolve("build-policy.txt"))
        assertTrue(policy.contentEquals(ANALYSIS_IO_BUILD_POLICY.toByteArray(Charsets.US_ASCII)))
        assertEquals(analysisBuildSha256(policy), properties.getProperty("buildPolicySha256"))
        val recordBytes = Files.readAllBytes(metadata.resolve("build-v1.json"))
        assertEquals(recordBytes.size.toString(), properties.getProperty("buildRecordBytes"))
        assertEquals(analysisBuildSha256(recordBytes), properties.getProperty("buildRecordSha256"))
        val record = OracleJson.parseCanonical(recordBytes) as JsonObject
        assertEquals(setOf("schemaVersion", "kind", "binaryName", "architecture", "sourceSha256", "buildPolicySha256",
            "helperSha256", "helperBytes", "compiler", "compilation"), record.keys)
        val helper = Files.readAllBytes(output.resolve(ANALYSIS_IO_BINARY_NAME))
        verifyAnalysisIoStaticElf(helper)
        assertEquals(analysisBuildSha256(helper), properties.getProperty("helperSha256"))
        assertEquals(helper.size.toString(), properties.getProperty("helperBytes"))
        assertEquals("${analysisBuildSha256(helper)}  $ANALYSIS_IO_BINARY_NAME\n", Files.readString(output.resolve("$ANALYSIS_IO_BINARY_NAME.sha256")))
        listOf("sourceSha256", "buildPolicySha256", "helperSha256", "architecture", "binaryName").forEach {
            assertEquals(JsonPrimitive(properties.getProperty(it)), record[it])
        }
        assertEquals(JsonPrimitive(helper.size), record["helperBytes"])
        val compiler = record.getValue("compiler") as JsonObject
        assertEquals(JsonPrimitive(analysisTestCompiler().toString()), compiler["path"])
        val compilation = record.getValue("compilation") as JsonObject
        assertEquals(JsonPrimitive(30000), compilation["timeoutMillis"])
        listOf(compiler, compilation).forEach {
            val result = it.getValue("result") as JsonObject
            assertEquals(JsonPrimitive(0), result["exitCode"])
            assertEquals(kotlinx.serialization.json.JsonNull, result["signal"])
        }
    }

    @Test fun `substituted source failed compiler and writable compiler cannot publish a tuple`() = withAnalysisBuildDirectory { root ->
        val source = root.resolve("decomp_analysis_io_helper.c")
        Files.writeString(source, "int main(void) { return 0; }\n")
        val output = Files.createDirectory(root.resolve("output"))
        assertFailsWith<IllegalArgumentException> { AnalysisIoHelperBuildV1.build(analysisTestCompiler(), source, output) }
        assertTrue(Files.list(output).use { it.toList().isEmpty() })
        assertFailsWith<IllegalArgumentException> {
            AnalysisIoHelperBuildV1.build(Path.of("/usr/bin/false").toRealPath(), analysisTestSource(), output)
        }
        assertTrue(Files.list(output).use { it.toList().isEmpty() })
        val writableCompiler = Files.copy(analysisTestCompiler(), root.resolve("compiler"))
        Files.setPosixFilePermissions(writableCompiler, PosixFilePermissions.fromString("rwxrwxr-x"))
        assertFailsWith<IllegalArgumentException> { AnalysisIoHelperBuildV1.build(writableCompiler, analysisTestSource(), output) }
        assertTrue(Files.list(output).use { it.toList().isEmpty() })
        assertFailsWith<UnsupportedOperationException> { (ANALYSIS_IO_COMPILER_ARGUMENTS as MutableList<String>)[0] = "foreign" }
    }

    @Test fun `static executable guard rejects malformed or dynamic artifacts`() {
        val helper = Files.readAllBytes(Path.of(System.getProperty("decompengine.analysis.io.testHelper")))
        verifyAnalysisIoStaticElf(helper)
        val bad = helper.copyOf(); bad[4] = 1
        assertFailsWith<IllegalArgumentException> { verifyAnalysisIoStaticElf(bad) }
        val dynamic = helper.copyOf(); val elf = java.nio.ByteBuffer.wrap(dynamic).order(java.nio.ByteOrder.LITTLE_ENDIAN)
        elf.putInt(elf.getLong(32).toInt(), 3)
        assertFailsWith<IllegalArgumentException> { verifyAnalysisIoStaticElf(dynamic) }
    }
}

private fun analysisTestCompiler(): Path = Path.of(System.getProperty("decompengine.analysis.io.testCompiler", "/usr/bin/cc")).toRealPath()
private fun analysisTestSource(): Path = Path.of("src/main/c/decomp_analysis_io_helper.c").toAbsolutePath()
private inline fun withAnalysisBuildDirectory(block: (Path) -> Unit) {
    val parent = Path.of("build/analysis-native-verification").toAbsolutePath(); Files.createDirectories(parent)
    val root = Files.createTempDirectory(parent, "producer-test-")
    try { block(root) } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
}
