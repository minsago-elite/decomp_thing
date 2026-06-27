package decompengine

import decompengine.roadmap.RoadmapException
import decompengine.roadmap.RoadmapManager
import decompengine.web.UploadServer
import java.nio.file.Path

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "roadmap" -> runRoadmap(args.drop(1))
        "web" -> runWeb(args.drop(1))
        null, "help", "--help", "-h" -> printHelp()
        else -> {
            System.err.println("unknown command: ${args.first()}")
            printHelp()
            kotlin.system.exitProcess(2)
        }
    }
}

private fun runRoadmap(args: List<String>) {
    val manager = RoadmapManager()
    try {
        val message = when (args.firstOrNull()) {
            "check" -> manager.check()
            "update" -> manager.update()
            else -> throw RoadmapException("usage: roadmap <check|update>")
        }
        println(message)
    } catch (exception: RoadmapException) {
        System.err.println("Roadmap check failed: ${exception.message}")
        kotlin.system.exitProcess(1)
    }
}

private fun runWeb(args: List<String>) {
    var host = "127.0.0.1"
    var port = 8000
    var dataDir = Path.of(".decomp_engine/jobs")
    var index = 0
    while (index < args.size) {
        when (args[index]) {
            "--host" -> {
                host = args[index + 1]
                index += 2
            }
            "--port" -> {
                port = args[index + 1].toInt()
                index += 2
            }
            "--data-dir" -> {
                dataDir = Path.of(args[index + 1])
                index += 2
            }
            else -> error("unknown web argument: ${args[index]}")
        }
    }
    val server = UploadServer(host, port, dataDir)
    server.start()
    println("Serving decomp_engine upload UI on http://$host:${server.serverPort}")
}

private fun printHelp() {
    println(
        """
        Usage:
          decomp_engine roadmap check
          decomp_engine roadmap update
          decomp_engine web [--host 127.0.0.1] [--port 8000] [--data-dir .decomp_engine/jobs]
        """.trimIndent(),
    )
}
