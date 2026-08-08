package decompengine

import decompengine.web.UploadServer
import java.net.URI
import java.nio.file.Files
import java.nio.file.Path

fun main(args: Array<String>) {
    when (args.firstOrNull()) {
        "doctor" -> runDoctor(args.drop(1))
        "web" -> runWeb(args.drop(1))
        null, "help", "--help", "-h" -> printHelp()
        else -> {
            System.err.println("unknown command: ${args.first()}")
            printHelp()
            kotlin.system.exitProcess(2)
        }
    }
}

private fun runDoctor(args: List<String>) {
    val toolsOnly = args.singleOrNull() == "--tools-only"
    if (args.isNotEmpty() && !toolsOnly) {
        System.err.println("usage: llm_bin_patch doctor [--tools-only]")
        kotlin.system.exitProcess(2)
    }

    val failures = mutableListOf<String>()
    listOf("java", "gcc", "make", "readelf", "strings").forEach { command ->
        val available = runCatching {
            ProcessBuilder("sh", "-c", "command -v \"${'$'}1\" >/dev/null 2>&1", "sh", command)
                .start()
                .waitFor() == 0
        }.getOrDefault(false)
        reportDoctorCheck(command, available, failures)
    }
    val bwrapInstalled = Files.isExecutable(Path.of("/usr/bin/bwrap"))
    reportDoctorCheck("bwrap executable", bwrapInstalled, failures)

    val ghidraHome = System.getenv("GHIDRA_HOME")?.let(Path::of)
    reportDoctorCheck(
        "ghidra",
        ghidraHome != null && Files.isExecutable(ghidraHome.resolve("support/analyzeHeadless")),
        failures,
    )
    val cVulHome = System.getenv("CVUL_HOME")?.let(Path::of) ?: Path.of("benchmarks/fixtures/c-vul")
    reportDoctorCheck(
        "c-vul fixture",
        Files.isRegularFile(cVulHome.resolve("src/01_out_of_bounds_write.c")),
        failures,
    )

    if (!toolsOnly) {
        val baseUrl = System.getenv("BASE_URL").orEmpty()
        val validBaseUrl = runCatching {
            val uri = URI.create(baseUrl)
            uri.scheme in setOf("http", "https") && !uri.host.isNullOrBlank()
        }.getOrDefault(false)
        reportDoctorCheck("BASE_URL", validBaseUrl, failures)
        reportDoctorCheck("API_KEY", !System.getenv("API_KEY").isNullOrBlank(), failures)
        reportDoctorCheck("MODEL", !System.getenv("MODEL").isNullOrBlank(), failures)
    }

    if (failures.isNotEmpty()) {
        System.err.println("Environment check failed: ${failures.joinToString(", ")}")
        kotlin.system.exitProcess(1)
    }
    println("Environment check passed")
    System.out.flush()
}

private fun reportDoctorCheck(name: String, passed: Boolean, failures: MutableList<String>) {
    if (passed) {
        println("[ok] $name")
        System.out.flush()
    } else {
        System.err.println("[missing] $name")
        System.err.flush()
        failures += name
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
          llm_bin_patch doctor [--tools-only]
          llm_bin_patch web [--host 127.0.0.1] [--port 8000] [--data-dir .decomp_engine/jobs]
        """.trimIndent(),
    )
}
