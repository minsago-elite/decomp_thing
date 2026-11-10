package decompengine.repair

import decompengine.project.GeneratedCRepairIndexProfile
import java.nio.file.Path

/** Halts a second process during recovery's later source exchange. */
internal object ModuleRevisionGraphRecoveryCrashProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2)
        val project = Path.of(arguments[0])
        val crashPoint = arguments[1]
        require(crashPoint in setOf("second-source-exchange", "accepted-persisted"))
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                val shouldHalt = when (crashPoint) {
                    "second-source-exchange" -> point == ModuleRevisionFaultPoint.AfterPublicationExchange(
                        "schema6-roll-forward", "src/modules/beta.c", 1,
                    )
                    "accepted-persisted" -> point == ModuleRevisionFaultPoint.AfterRecoveredAcceptancePersist
                    else -> false
                }
                if (shouldHalt) {
                    Runtime.getRuntime().halt(86)
                }
            },
        ).use { graph ->
            error("recovery completed without reaching $crashPoint: ${graph.snapshot.headId}")
        }
    }
}
