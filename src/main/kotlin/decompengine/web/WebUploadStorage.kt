package decompengine.web

import decompengine.jobs.RetainedStorageUsage
import java.nio.file.Files
import java.nio.file.Path

/** Upload-only reservation ledger. The service excludes other writers for each upload epoch. */
internal class WebUploadStorage(
    root: Path,
    private val maximumBytes: Long,
    private val measure: () -> Long = { RetainedStorageUsage.measure(root, maximumBytes).logicalBytes },
    private val available: () -> Long = { Files.getFileStore(root).usableSpace },
) {
    init { require(maximumBytes >= RESERVATION_BYTES) }
    private var baseline: Long? = null
    private var charged = 0L
    private var active = 0

    @Synchronized fun reserve(): AutoCloseable {
        check(!Thread.currentThread().isInterrupted) { "Upload admission interrupted" }
        try {
            val used = baseline ?: measure()
            if (used < 0 || used > maximumBytes || charged > maximumBytes - used ||
                RESERVATION_BYTES > maximumBytes - used - charged) {
                throw WebJobServiceException("UPLOAD_STORAGE", "Retained storage has no room for another upload reservation.")
            }
            if (available() < FREE_HEADROOM_BYTES + (active + 1L) * RESERVATION_BYTES) {
                throw WebJobServiceException("UPLOAD_STORAGE", "Free storage cannot cover upload reservations and recovery headroom.")
            }
            baseline = used
            charged += RESERVATION_BYTES
            active++
            var released = false
            return AutoCloseable {
                synchronized(this) {
                    if (!released) {
                        released = true
                        active--
                        // Keep completed reservations charged while another upload can still write.
                        // Re-measure actual retained bytes only after the entire epoch is quiescent.
                        if (active == 0) { baseline = null; charged = 0 }
                    }
                }
            }
        } catch (failure: WebJobServiceException) { throw failure }
        catch (failure: Exception) {
            throw WebJobServiceException("UPLOAD_STORAGE", "Retained storage could not be measured safely. Inspect storage before retrying.", failure)
        }
    }

    companion object {
        // Binary body is capped at 32 MiB; the extra MiB covers fixed metadata and directory entries.
        const val RESERVATION_BYTES = 33L * 1024 * 1024
        const val FREE_HEADROOM_BYTES = 64L * 1024 * 1024
        const val DEFAULT_MAXIMUM_BYTES = 20L * 1024 * 1024 * 1024
    }
}
