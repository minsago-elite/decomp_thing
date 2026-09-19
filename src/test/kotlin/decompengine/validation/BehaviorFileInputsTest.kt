package decompengine.validation

import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.StandardOpenOption
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlinx.serialization.json.jsonObject

class BehaviorFileInputsTest {
    @Test
    fun `file names cannot alias directories or escape the inputs mount`() {
        for (names in listOf(listOf("../outside"), listOf("/absolute"), listOf("a//b"), listOf("a\\b"),
            listOf("a", "a/b"), listOf("a/./b"), listOf("a\u0000b"), listOf("x".repeat(257)))) {
            assertFails { requireBehaviorFileNames(names) }
        }
        requireBehaviorFileNames(listOf("a/b", "a/c", "empty"))
    }

    @Test
    fun `capture rejects linked missing oversized and excessive file inputs`() {
        val root = Files.createTempDirectory("behavior-input-bounds-")
        val regular = Files.write(root.resolve("regular"), byteArrayOf(1))
        val linked = Files.createSymbolicLink(root.resolve("linked"), regular.fileName)
        val oversized = root.resolve("oversized")
        FileChannel.open(oversized, StandardOpenOption.CREATE_NEW, StandardOpenOption.WRITE).use {
            it.position(MAXIMUM_BEHAVIOR_FILE_BYTES)
            it.write(ByteBuffer.wrap(byteArrayOf(1)))
        }
        for (path in listOf(linked, root.resolve("missing"), oversized)) {
            assertFails { captureBehaviorFileInputs(mapOf("case" to mapOf("input" to path)), BehaviorEvidenceCapture()) }
        }
        assertFails {
            captureBehaviorFileInputs(mapOf("case" to (0..MAXIMUM_BEHAVIOR_INPUT_FILES).associate { "file$it" to regular }), BehaviorEvidenceCapture())
        }
    }

    @Test
    fun `empty input files are retained and checked for later mutation`() {
        val path = Files.createTempFile("behavior-empty-input-", ".bin")
        val capture = BehaviorEvidenceCapture()
        val record = captureBehaviorFileInputs(mapOf("case" to mapOf("empty" to path)), capture).getValue("case").single().jsonObject
        assertEquals(0L, record.count("bytes"))
        assertEquals("", record.string("contentHex"))
        capture.requireCurrent()
        Files.write(path, byteArrayOf(1))
        assertFails { capture.requireCurrent() }
    }
}
