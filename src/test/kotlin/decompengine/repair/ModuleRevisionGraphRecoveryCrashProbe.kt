package decompengine.repair

import decompengine.project.GeneratedCRepairIndexProfile
import java.nio.file.Path

/** Halts a second process during recovery's later source exchange. */
internal object ModuleRevisionGraphRecoveryCrashProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 2)
        val project = Path.of(arguments[0])
        val relative = arguments[1]
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point == ModuleRevisionFaultPoint.AfterPublicationExchange(
                        "schema6-roll-forward", relative, 1,
                    )
                ) {
                    Runtime.getRuntime().halt(86)
                }
            },
        ).use { graph ->
            error("recovery completed without reaching the second source exchange: ${graph.snapshot.headId}")
        }
    }
}
