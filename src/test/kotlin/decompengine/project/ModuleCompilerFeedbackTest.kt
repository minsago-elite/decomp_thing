package decompengine.project

import java.nio.file.Files
import kotlin.io.path.*
import kotlin.test.*

class ModuleCompilerFeedbackTest {
    @Test
    fun `feedback is private and bound to input profile source and context`() {
        val root = createTempDirectory("compiler-feedback-")
        val input = "1".repeat(64); val profile = "2".repeat(64)
        val feedback = ModuleCompilerFeedback("core", "3".repeat(64), "4".repeat(64), "5".repeat(64), "unused parameter ctx")
        val store = ModuleCompilerFeedbackStore(root, input, profile)
        store.write(feedback)
        assertEquals(feedback, store.read("core"))
        val rejected = feedback.copy(restoredSourceSha256 = "8".repeat(64))
        store.write(rejected)
        assertEquals(rejected, store.read("core"))
        assertFailsWith<IllegalArgumentException> { store.write(rejected.copy(restoredSourceSha256 = "invalid")) }
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
