package decompengine.jobs

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.jsonObject
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.io.path.readBytes
import kotlin.io.path.readText
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class JobStoreTest {
    @Test
    fun `backend stores uploaded ELF job and metadata`() {
        val tempDir = createTempDirectory("jobs-")
        val store = JobStore(tempDir)

        val job = store.createFromUpload("../fixture.elf", elfFixture())

        val jobDir = tempDir.resolve(job.id)
        assertEquals("fixture.elf", job.filename)
        assertEquals("uploaded", job.status)
        assertEquals(elfFixture().size, job.sizeBytes)
        assertEquals(jobDir.resolve("input.elf"), job.binaryPath)
        assertEquals("x86-64", job.metadata.machine)
        assertEquals(0x401000UL, job.metadata.entryPoint)
        assertTrue(job.binaryPath.readBytes().contentEquals(elfFixture()))

        val metadata = Json.parseToJsonElement(jobDir.resolve("job.json").readText()).jsonObject
        assertEquals(job.id, metadata["id"].toString().trim('"'))
        assertEquals("ELF64", metadata["metadata"]!!.jsonObject["format"].toString().trim('"'))

        assertEquals(job, store.get(job.id))
    }

    @Test
    fun `backend rejects non-ELF upload`() {
        val store = JobStore(createTempDirectory("jobs-invalid-"))

        assertFailsWith<InvalidUploadException> {
            store.createFromUpload("not-elf.bin", "not an elf".toByteArray())
        }
    }
}

fun elfFixture(): ByteArray {
    val bytes = ByteArray(64)
    bytes[0] = 0x7f
    bytes[1] = 'E'.code.toByte()
    bytes[2] = 'L'.code.toByte()
    bytes[3] = 'F'.code.toByte()
    bytes[4] = 2
    bytes[5] = 1
    bytes[6] = 1
    bytes[7] = 3
    putShort(bytes, 16, 2)
    putShort(bytes, 18, 62)
    putInt(bytes, 20, 1)
    putLong(bytes, 24, 0x401000)
    putLong(bytes, 32, 64)
    putLong(bytes, 40, 0)
    putInt(bytes, 48, 0)
    putShort(bytes, 52, 64)
    putShort(bytes, 54, 56)
    putShort(bytes, 56, 2)
    putShort(bytes, 58, 64)
    putShort(bytes, 60, 5)
    putShort(bytes, 62, 4)
    return bytes
}

private fun putShort(bytes: ByteArray, offset: Int, value: Int) {
    bytes[offset] = value.toByte()
    bytes[offset + 1] = (value ushr 8).toByte()
}

private fun putInt(bytes: ByteArray, offset: Int, value: Int) {
    repeat(4) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}

private fun putLong(bytes: ByteArray, offset: Int, value: Long) {
    repeat(8) { index -> bytes[offset + index] = (value ushr (index * 8)).toByte() }
}
