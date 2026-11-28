package decompengine

import decompengine.jobs.FullRunEventReader
import decompengine.jobs.FullRunJournal
import decompengine.jobs.FullRunJournalFinalizationInProgressException
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
        if (args[0] == "list") {
            require(args.size == 2)
            val (metadata, incomplete) = listRunHistory(root)
            metadata.forEach { (_, value) ->
                println(listOf("runId", "startedAt", "workflow", "state").joinToString(" ") {
                    value.getValue(it).jsonPrimitive.content
                } + " " + (value["lastPhase"]?.jsonPrimitive?.content ?: "-"))
            }
            if (incomplete > 0) System.err.println("Run history: ignored $incomplete incomplete entries.")
            return
        }
        val directory = resolveRunHistoryDirectory(root, args.getOrNull(2)) ?: error("no recorded runs")
        val follow = args[0] == "follow"
        val reader = if (follow) {
            retryWhileFinalizing({ Thread.sleep(200) }) { FullRunEventReader(directory) }
        } else {
            FullRunEventReader(directory)
        }
        reader.use {
            while (true) {
                val event = reader.next()
                if (event != null) {
                    println(event)
                    continue
                }
                val metadata = if (follow) {
                    retryWhileFinalizing({ Thread.sleep(200) }) { FullRunJournal.metadata(directory) }
                } else {
                    FullRunJournal.metadata(directory)
                }
                val state = metadata.getValue("state").jsonPrimitive.content
                if (!follow || state != "running") {
                    // A terminal metadata publication follows the event append. An earlier EOF
                    // is not stable while the writer is active, so drain the now-closed tail.
                    if (state != "running") {
                        drainRunHistoryTail(reader, ::println)
                    }
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

internal fun resolveRunHistoryDirectory(root: Path, runId: String?): Path? =
    if (runId != null) FullRunJournal.directory(root, runId)
    else listRunHistory(root).first.lastOrNull()?.first

internal fun drainRunHistoryTail(reader: FullRunEventReader, consume: (JsonObject) -> Unit) {
    while (true) consume(reader.next() ?: break)
}

/** Follow retries only a marker whose owner still holds the finalization lock. */
internal fun <T> retryWhileFinalizing(pause: () -> Unit, observe: () -> T): T {
    while (true) {
        try {
            return observe()
        } catch (_: FullRunJournalFinalizationInProgressException) {
            pause()
        }
    }
}

/** Lists valid runs while keeping incomplete/crashed neighbors from hiding healthy histories. */
internal fun listRunHistory(root: Path): Pair<List<Pair<Path, JsonObject>>, Int> {
    val runs = root.resolve(FullRunJournal.DIRECTORY)
    val found = mutableListOf<Pair<Path, JsonObject>>()
    var incomplete = 0
    Files.newDirectoryStream(runs).use { entries ->
        for (path in entries) {
            if (found.size + incomplete >= 10_000) error("run listing exceeds its entry limit")
            try {
                val directory = FullRunJournal.directory(root, path.fileName.toString())
                found += directory to FullRunJournal.metadata(directory)
            } catch (_: Exception) {
                incomplete++
            }
        }
    }
    return found.sortedBy { it.second.getValue("startedAt").jsonPrimitive.content } to incomplete
}
