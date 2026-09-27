package decompengine.jobs

import java.io.IOException
import java.nio.file.Files
import java.nio.file.Path
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class JobStoreDirectoriesTest {
    @Test
    fun `nested store confirms canonical directories from leaf through filesystem root on every attempt`() {
        val parent = createTempDirectory("job-directory-order-")
        val root = parent.resolve("new/nested/jobs")
        val confirmed = mutableListOf<Path>()
        prepareJobStoreDirectories(root) { confirmed.add(it) }
        val expected = generateSequence(root.toRealPath()) { it.parent }.toList()
        assertEquals(expected, confirmed)
        confirmed.clear()
        prepareJobStoreDirectories(root) { confirmed.add(it) }
        assertEquals(expected, confirmed)
    }

    @Test
    fun `failed ancestor confirmation cannot publish and retry confirms existing directories again`() {
        val root = createTempDirectory("job-directory-failure-").resolve("new/jobs")
        var fail = true
        val confirmed = mutableListOf<Path>()
        val directories = JobStoreDirectories { path ->
            prepareJobStoreDirectories(path) { directory ->
                confirmed.add(directory)
                if (fail && directory == path.parent) throw IOException("injected directory force failure")
            }
        }
        val store = JobStore(root, AtomicUploadPublisher, storeDirectories = directories)
        assertFailsWith<IOException> { store.createFromUpload("benign.elf", elfFixture()) }
        assertTrue(root.exists())
        Files.list(root).use { assertEquals(0L, it.count()) }
        assertEquals(listOf(root, root.parent), confirmed)
        fail = false
        confirmed.clear()
        val job = store.createFromUpload("benign.elf", elfFixture())
        assertEquals(generateSequence(root.toRealPath()) { it.parent }.toList(), confirmed)
        assertEquals(job, JobStore(root).get(job.id))
    }

    @Test
    fun `production directory confirmation supports a fresh nested local store`() {
        val root = createTempDirectory("job-directory-force-").resolve("one/two/jobs")
        val store = JobStore(root)
        val job = store.createFromUpload("benign.elf", elfFixture())
        assertEquals(job, JobStore(root).get(job.id))
        assertFalse(store.recoveryInventory().retainedUploadStages > 0)
    }

    @Test
    fun `directory confirmation failure preserves existing published jobs`() {
        val root = createTempDirectory("job-directory-existing-")
        val initial = JobStore(root).createFromUpload("existing.elf", elfFixture())
        val store = JobStore(root, AtomicUploadPublisher, storeDirectories = JobStoreDirectories {
            throw IOException("directory confirmation unavailable")
        })
        assertFailsWith<IOException> { store.createFromUpload("new.elf", elfFixture()) }
        assertEquals(listOf(initial), JobStore(root).list())
        assertEquals(0, store.recoveryInventory().retainedUploadStages)
    }
}
