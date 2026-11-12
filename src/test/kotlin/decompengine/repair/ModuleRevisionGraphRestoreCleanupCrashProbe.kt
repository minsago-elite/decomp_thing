package decompengine.repair

import decompengine.project.GeneratedCRepairIndexProfile
import java.nio.file.Path

/** Halts after rollback cleanup quarantines its displaced candidate, preserving a real crash state. */
object ModuleRevisionGraphRestoreCleanupCrashProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 2)
        val project = Path.of(args[0])
        val relative = args[1]
        ModuleRevisionGraph.openForTesting(
            project,
            GeneratedCRepairIndexProfile,
            faultInjector = ModuleRevisionFaultInjector { point ->
                if (point is ModuleRevisionFaultPoint.BeforeOwnedEntryUnlink &&
                    point.phase == "startup-rollback" && point.path == relative
                ) {
                    Runtime.getRuntime().halt(86)
                }
            },
        ).use { error("startup rollback did not reach the crash boundary") }
    }
}
