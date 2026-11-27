package decompengine.web

import decompengine.repair.readCommittedStableRegularFile
import decompengine.repair.readStableRegularFile
import decompengine.repair.StableFileChangedException
import decompengine.repair.RepairBudgetExceededException
import java.nio.file.Files
import java.nio.file.Path
import java.security.MessageDigest
import kotlin.test.*
import org.junit.jupiter.api.Test

/** Inert local records only. Temp root is supplied by the focused runner inside the worktree. */
class WebStructureEntityStreamingTest {
    private fun sha(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
    private fun fixture(test: (Path, ByteArray, Long) -> Unit) {
        val root = Files.createTempDirectory("entity-stream-")
        try {
            val bytes = "{\"functions\":[{\"prototype\":\"void first()\"},{\"prototype\":\"void selected()\",\"strings\":[\"héllo\"],\"byteEvidence\":null}],\"tail\":\"${"z".repeat(200_000)}\"}".toByteArray()
            Files.write(root.resolve("model.json"), bytes)
            test(root, bytes, bytes.toString(Charsets.UTF_8).indexOf("{\"prototype\":\"void selected").toLong())
        } finally { Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) } }
    }
    @Test fun `streamed entity equals byte capture and hashes unread tail`() = fixture { root, bytes, offset ->
        val expected = readWebStructureEntity(bytes, offset)
        var actual: WebStructureEntityFields? = null
        readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), { input ->
            input.skipNBytes(offset)
            actual = readWebStructureEntity(input)
        })
        assertEquals(expected.texts.mapValues { it.value?.text }, actual!!.texts.mapValues { it.value?.text })
        assertEquals(expected.byteEvidence, actual!!.byteEvidence)
        assertEquals(expected.strings.size, actual!!.strings.size)
        val changed = bytes.copyOf().also { it[it.lastIndex - 3] = 'X'.code.toByte() }
        Files.write(root.resolve("model.json"), changed)
        assertFailsWith<StableFileChangedException> {
            readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), { input ->
                input.skipNBytes(offset); readWebStructureEntity(input)
            })
        }
    }
    @Test fun `stream refuses callback time mutation replacement hardlinks and oversized records`() = fixture { root, bytes, _ ->
        assertFailsWith<StableFileChangedException> {
            readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), {
                Files.write(root.resolve("model.json"), bytes.copyOf().also { it[it.lastIndex - 3] = 'X'.code.toByte() })
            })
        }
        Files.write(root.resolve("model.json"), bytes)
        assertFailsWith<StableFileChangedException> {
            readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), {
                Files.move(root.resolve("model.json"), root.resolve("old.json"))
                Files.write(root.resolve("model.json"), bytes)
            })
        }
        Files.createLink(root.resolve("alias"), root.resolve("model.json"))
        assertFails { readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), {}) }
        Files.delete(root.resolve("alias"))
        assertFailsWith<RepairBudgetExceededException> {
            readCommittedStableRegularFile(root, "model.json", (bytes.size - 1).toLong(), sha(bytes), (bytes.size - 1).toLong(), {})
        }
    }
    @Test fun `stream checks cancellation while skipping and draining and propagates parser failure`() = fixture { root, bytes, offset ->
        var checks = 0
        assertFailsWith<InterruptedException> {
            readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), { it.skipNBytes(offset) },
                { if (++checks == 4) throw InterruptedException() })
        }
        assertFailsWith<IllegalStateException> {
            readCommittedStableRegularFile(root, "model.json", bytes.size.toLong(), sha(bytes), bytes.size.toLong(), { error("parse failed") })
        }
    }
}

/** Runs either old array capture or new streaming against identical 100k inert rows, in separate JVMs. */
object WebStructureDetailAllocation {
    @JvmStatic fun main(args: Array<String>) {
        val root = Path.of(args[0]); Files.createDirectories(root)
        val path = root.resolve("model.json")
        val row = "{\"id\":\"fn_0000000000401000\",\"name\":\"function\",\"prototype\":\"void function(void)\",\"decompiledC\":null,\"calls\":[],\"strings\":[],\"status\":\"complete\"}"
        val prefix = "{\"functions\":["
        if (args.size > 2) Files.copy(Path.of(args[2]), path)
        else Files.newBufferedWriter(path).use { out ->
            out.write(prefix)
            repeat(100_000) { if (it > 0) out.write(","); out.write(row) }
            out.write("]}")
        }
        val size = Files.size(path)
        val digest = MessageDigest.getInstance("SHA-256")
        Files.newInputStream(path).use { input -> val buffer = ByteArray(65536); while (true) { val count = input.read(buffer); if (count < 0) break; digest.update(buffer, 0, count) } }
        val sha = digest.digest().joinToString("") { "%02x".format(it) }
        val offset = if (args.size > 3) args[3].toLong() else prefix.length.toLong() + 99_999L * (row.length + 1)
        val bean = java.lang.management.ManagementFactory.getThreadMXBean() as com.sun.management.ThreadMXBean
        fun rss() = Files.readAllLines(Path.of("/proc/self/status")).first { it.startsWith("VmRSS:") }.trim()
        println("pid=${ProcessHandle.current().pid()} mode=${args[1]} bytes=$size offset=$offset")
        repeat(2) {
            val beforeRss = rss(); val allocated = bean.getThreadAllocatedBytes(Thread.currentThread().threadId()); val start = System.nanoTime()
            var fields: WebStructureEntityFields? = null
            if (args[1] == "array") fields = readWebStructureEntity(readStableRegularFile(root, "model.json", WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES.toLong()).bytes, offset)
            else readCommittedStableRegularFile(root, "model.json", WebProgramStructureBuilder.MAXIMUM_MODEL_BYTES.toLong(), sha, size, { input -> input.skipNBytes(offset); fields = readWebStructureEntity(input) })
            val elapsed = System.nanoTime() - start; val delta = bean.getThreadAllocatedBytes(Thread.currentThread().threadId()) - allocated
            check(fields!!.texts.containsKey("prototype"))
            println("click=$it allocatedBytes=$delta elapsedNanos=$elapsed beforeRss=$beforeRss afterRss=${rss()}")
        }
        Files.delete(path)
    }
}
