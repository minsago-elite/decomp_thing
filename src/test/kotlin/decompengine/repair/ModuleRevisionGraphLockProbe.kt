package decompengine.repair

import decompengine.project.GeneratedCRepairIndexProfile
import java.nio.file.Path

/** Separate-JVM probe used to prove the OS file lock still composes with JVM-local coordination. */
object ModuleRevisionGraphLockProbe {
    @JvmStatic
    fun main(args: Array<String>) {
        require(args.size == 1)
        println("READY")
        System.out.flush()
        ModuleRevisionGraph.open(Path.of(args.single()), GeneratedCRepairIndexProfile).use {
            println("ACQUIRED")
            System.out.flush()
        }
    }
}
