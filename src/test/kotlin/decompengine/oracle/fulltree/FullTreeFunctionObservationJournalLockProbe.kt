package decompengine.oracle.fulltree

import java.nio.file.Path

object FullTreeFunctionObservationJournalLockProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 1)
        FullTreeFunctionObservationJournalAuthority.open(Path.of(arguments.single())).use {
            println("READY")
            System.out.flush()
            while (true) Thread.sleep(Long.MAX_VALUE)
        }
    }
}
