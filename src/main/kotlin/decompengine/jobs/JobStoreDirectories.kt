package decompengine.jobs

import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import java.nio.file.StandardOpenOption.READ

internal fun interface JobStoreDirectories {
    fun prepare(root: Path)
}

internal object ForcedJobStoreDirectories : JobStoreDirectories {
    override fun prepare(root: Path) = prepareJobStoreDirectories(root, ::forceJobStoreDirectory)
}

internal fun forceJobStoreDirectory(directory: Path) {
    FileChannel.open(directory, READ, NOFOLLOW_LINKS).use { it.force(true) }
}

/** Repeat confirmation on retries: an existing directory may come from an interrupted creation. */
internal fun prepareJobStoreDirectories(root: Path, confirm: (Path) -> Unit) {
    Files.createDirectories(root)
    var directory: Path? = root.toRealPath()
    while (directory != null) {
        confirm(directory)
        directory = directory.parent
    }
}
