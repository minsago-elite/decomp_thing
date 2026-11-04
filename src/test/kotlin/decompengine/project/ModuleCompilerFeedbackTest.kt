package decompengine.project

import java.nio.file.Files
import decompengine.testing.recoveryMatrixTempDirectory as createTempDirectory
import decompengine.testing.RecoveryMatrixEvidence
import kotlin.io.path.*
import kotlin.test.*
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.junit.jupiter.api.extension.ExtendWith

@ExtendWith(RecoveryMatrixEvidence::class)
class ModuleCompilerFeedbackTest {
    @Test
    fun `feedback hashes the retained prefix and compilation evidence keeps the full output digest`() {
        val completeOutput = ("compiler diagnostic line\n".repeat(3_000)).take(90_000)
        val retained = completeOutput.take(32_768)
        val completeDigest = sha256(completeOutput.toByteArray(Charsets.UTF_8))
        val feedback = retainedModuleCompilerFeedback("core", "1".repeat(64), "2".repeat(64), retained)
        val compilation = ModuleCompilationEvidence(
            sourceSha256 = "1".repeat(64), command = listOf("cc", "-c"), outcome = "failed", returnCode = 1,
            diagnosticsSha256 = completeDigest, diagnosticsBytes = completeOutput.toByteArray().size.toLong(),
            diagnosticsPrefix = retained,
        )

        assertEquals(sha256(retained.toByteArray(Charsets.UTF_8)), feedback.diagnosticsSha256)
        assertNotEquals(completeDigest, feedback.diagnosticsSha256)
        assertEquals(retained, feedback.diagnostics)
        assertEquals(completeDigest, Json.parseToJsonElement(compilation.toJson()).jsonObject
            .getValue("diagnosticsSha256").jsonPrimitive.content)
    }

    @Test
    fun `feedback is private and bound to input profile source and context`() {
        val root = createTempDirectory("compiler-feedback-")
        val input = "1".repeat(64); val profile = "2".repeat(64)
        val feedback = ModuleCompilerFeedback("core", "3".repeat(64), "4".repeat(64), "5".repeat(64), "unused parameter ctx")
        val store = ModuleCompilerFeedbackStore(root, input, profile)
        store.write(feedback)
        assertEquals(feedback, store.read("core"))
        assertNull(ModuleCompilerFeedbackStore(root, "6".repeat(64), profile).read("core"))
        assertNull(ModuleCompilerFeedbackStore(root, input, "7".repeat(64)).read("core"))
        val permissions = Files.getPosixFilePermissions(root.resolve(ModuleCompilerFeedbackStore.DIRECTORY))
        assertTrue(permissions.none { it.name.startsWith("GROUP_") || it.name.startsWith("OTHERS_") })
    }

    @Test
    fun `linked and oversized diagnostic records cannot be consumed`() {
        val root = createTempDirectory("compiler-feedback-invalid-")
        val store = ModuleCompilerFeedbackStore(root, "1".repeat(64), "2".repeat(64))
        val directory = root.resolve(ModuleCompilerFeedbackStore.DIRECTORY).createDirectory()
        val record = directory.resolve("core.json")
        Files.createSymbolicLink(record, root.resolve("outside"))
        assertFailsWith<IllegalArgumentException> { store.read("core") }
        Files.delete(record)
        record.writeText("x".repeat(70_000))
        assertFailsWith<IllegalArgumentException> { store.read("core") }
    }

}
