package decompengine.oracle.behavior

import java.nio.file.Path

object LlvmBehaviorNativeSandboxPolicyV2OperationJournalLockProbe {
    @JvmStatic
    fun main(arguments: Array<String>) {
        require(arguments.size == 6)
        LlvmBehaviorNativeSandboxPolicyV2OperationJournal.open(
            Path.of(arguments[0]),
            Path.of(arguments[1]),
            Path.of(arguments[2]),
            Path.of(arguments[3]),
            Path.of(arguments[4]),
            Path.of(arguments[5]),
        ).use {
            println("READY")
            System.out.flush()
            while (true) Thread.sleep(Long.MAX_VALUE)
        }
    }
}
