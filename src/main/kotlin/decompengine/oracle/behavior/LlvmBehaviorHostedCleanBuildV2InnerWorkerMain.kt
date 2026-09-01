package decompengine.oracle.behavior

/** Fixed, zero-argument JVM entry point for the hosted clean-build worker container. */
internal object LlvmBehaviorHostedCleanBuildV2InnerWorkerMain {
    @JvmStatic
    fun main(arguments: Array<String>) {
        if (arguments.isNotEmpty()) {
            throw LlvmBehaviorHostedCleanBuildV2Exception(
                "hosted clean-build inner worker accepts no arguments",
            )
        }
        LlvmBehaviorHostedCleanBuildV2InnerWorker.produce()
    }
}
