package decompengine.project

import decompengine.oracle.core.OracleJson
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import org.junit.jupiter.api.parallel.ResourceLock

@ResourceLock("contained-module-hosted-case-property")
class ContainedModuleHostedCaseTest {
    @Test
    fun `case records retain immutable bytes and closed success metadata`(): Unit = withDirectory { root ->
        val bytes = "actual retained observation".toByteArray()
        val original = bytes.copyOf()
        ContainedModuleHostedCase.run(ID, CLASS, "fixture", null) { case ->
            case.stage("observed")
            case.retain("raw/observation.txt", bytes)
            bytes.fill(0)
        }
        assertContentEquals(original, Files.readAllBytes(root.resolve("$ID/raw/observation.txt")))
        val record = record(root)
        assertEquals(setOf("schemaVersion", "provider", "caseId", "testClass", "testMethod", "profileId", "status", "stage", "artifacts", "failure"), record.keys)
        assertEquals(JsonPrimitive("passed"), record["status"])
        val artifact = (record.getValue("artifacts") as JsonArray).single() as JsonObject
        assertEquals(setOf("path", "bytes", "sha256"), artifact.keys)
        assertEquals(JsonPrimitive(sha256(original)), artifact["sha256"])
    }

    @Test
    fun `negative stage preserves prior bytes and original failure without exposing its message`(): Unit = withDirectory { root ->
        val original = IllegalStateException("PRIVATE exception detail")
        val thrown = assertFailsWith<IllegalStateException> {
            ContainedModuleHostedCase.run(ID, CLASS, "fixture", null) { case ->
                case.stage("baseline")
                case.retain("baseline/source.c", "int f(void) { return 1; }\n".toByteArray())
                case.stage("refused")
                case.retain("negative/attempt.json", "{}\n".toByteArray())
                throw original
            }
        }
        assertSame(original, thrown)
        assertEquals(JsonPrimitive("failed"), record(root)["status"])
        assertEquals(JsonPrimitive("refused"), record(root)["stage"])
        assertFalse(Files.readString(root.resolve("$ID/case.json")).contains("PRIVATE"))
        assertEquals("{}\n", Files.readString(root.resolve("$ID/negative/attempt.json")))
        assertEquals(2, (record(root).getValue("artifacts") as JsonArray).size)
    }

    @Test
    fun `invalid paths oversized members and duplicate files refuse before changing retained artifacts`(): Unit = withDirectory { root ->
        ContainedModuleHostedCase.run(ID, CLASS, "fixture", null) { case ->
            case.stage("observed")
            for (path in listOf("../escape", "/absolute", "raw//empty", "case.json", "x/./y", "a/".repeat(17) + "x")) {
                assertFailsWith<IllegalArgumentException> { case.retain(path, byteArrayOf(1)) }
            }
            assertFailsWith<IllegalArgumentException> { case.retain("oversized", ByteArray(4 * 1024 * 1024 + 1)) }
            assertFalse(Files.exists(root.resolve("$ID/oversized")))
            case.retain("original", byteArrayOf(1, 2, 3))
            assertFailsWith<IllegalArgumentException> { case.retain("original", byteArrayOf(9)) }
        }
        assertContentEquals(byteArrayOf(1, 2, 3), Files.readAllBytes(root.resolve("$ID/original")))
        assertEquals(1, (record(root).getValue("artifacts") as JsonArray).size)
    }

    @Test
    fun `stage bounds and repeated cases preserve the first case instead of overwriting it`(): Unit = withDirectory { root ->
        ContainedModuleHostedCase.run(ID, CLASS, "fixture", null) { case ->
            case.retain("observation", byteArrayOf(1))
            for (index in 1..31) case.stage("stage-$index")
            assertFailsWith<IllegalArgumentException> { case.stage("stage-32") }
            assertFailsWith<IllegalArgumentException> { case.stage("stage-1") }
        }
        val before = Files.readAllBytes(root.resolve("$ID/case.json"))
        assertFailsWith<java.nio.file.FileAlreadyExistsException> {
            ContainedModuleHostedCase.run(ID, CLASS, "fixture", null) { error("existing case must refuse before running") }
        }
        assertContentEquals(before, Files.readAllBytes(root.resolve("$ID/case.json")))
        assertTrue(Files.list(root.resolve(ID)).use { files -> files.noneMatch { it.fileName.toString().endsWith(".tmp") } })
    }

    private fun record(root: Path) = OracleJson.parse(Files.readAllBytes(root.resolve("$ID/case.json"))) as JsonObject
    private fun withDirectory(block: (Path) -> Unit) {
        val base = Path.of("build/test-tmp").toAbsolutePath().normalize()
        Files.createDirectories(base)
        val root = Files.createTempDirectory(base, "hosted-case-")
        val previous = System.getProperty(ContainedModuleHostedCase.DIRECTORY_PROPERTY)
        System.setProperty(ContainedModuleHostedCase.DIRECTORY_PROPERTY, root.toString())
        try { block(root) } finally {
            if (previous == null) System.clearProperty(ContainedModuleHostedCase.DIRECTORY_PROPERTY)
            else System.setProperty(ContainedModuleHostedCase.DIRECTORY_PROPERTY, previous)
        }
    }
    private companion object {
        const val ID = "generic-default-512"
        const val CLASS = "decompengine.project.ContainedModuleHostedCaseTest"
    }
}
