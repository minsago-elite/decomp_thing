package decompengine

import decompengine.jobs.FullRunEventReader
import decompengine.jobs.FullRunJournal
import java.nio.file.Files
import java.nio.file.LinkOption.NOFOLLOW_LINKS
import java.nio.file.Path
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive

/** Replay is observation-only: no provider, binary, tool, or acceptance operation is invoked. */
internal fun runRunHistory(args: List<String>) {
    try {
        require(args.size in 2..3 && args[0] in setOf("list", "replay", "follow")) {
            "usage: llm_bin_patch runs list|replay|follow <output-directory> [run-id]"
        }
        val root = Path.of(args[1])
        val runs = root.resolve(FullRunJournal.DIRECTORY)
        require(Files.isDirectory(root, NOFOLLOW_LINKS) && Files.isDirectory(runs, NOFOLLOW_LINKS)) {
            "output directory has no complete run history"
        }
        val metadata = Files.newDirectoryStream(runs).use { entries ->
            val found = mutableListOf<Pair<Path, JsonObject>>()
            for (path in entries) {
                require(found.size < 10_000) { "run listing exceeds its entry limit" }
                val directory = FullRunJournal.directory(root, path.fileName.toString())
                found += directory to FullRunJournal.metadata(directory)
            }
            found.sortedBy { it.second.getValue("startedAt").jsonPrimitive.content }
        }
        if (args[0] == "list") {
            require(args.size == 2)
            metadata.forEach { (_, value) ->
                println(listOf("runId", "startedAt", "workflow", "state").joinToString(" ") {
                    value.getValue(it).jsonPrimitive.content
                } + " " + (value["lastPhase"]?.jsonPrimitive?.content ?: "-"))
            }
            return
        }
        val directory = args.getOrNull(2)?.let { FullRunJournal.directory(root, it) }
            ?: metadata.lastOrNull()?.first ?: error("no recorded runs")
        val follow = args[0] == "follow"
        FullRunEventReader(directory).use { reader ->
            while (true) {
                val event = reader.next()
                if (event != null) {
                    println(event)
                    continue
                }
                val state = FullRunJournal.metadata(directory).getValue("state").jsonPrimitive.content
                if (!follow || state != "running") {
                    val end = reader.verifyEnd()
                    System.err.println("run history: state=${end.getValue("state").jsonPrimitive.content}; observation replay only")
                    break
                }
                Thread.sleep(200)
            }
        }
    } catch (_: InterruptedException) {
        Thread.currentThread().interrupt()
    } catch (_: Exception) {
        // Log artifacts can be peer-authored: do not echo their exception text or execute records.
        System.err.println("usage: llm_bin_patch runs list|replay|follow <output-directory> [run-id]")
        System.err.println("Run history could not be read or verified. Check the command, run id, file integrity, and permissions.")
        kotlin.system.exitProcess(2)
    }
}
