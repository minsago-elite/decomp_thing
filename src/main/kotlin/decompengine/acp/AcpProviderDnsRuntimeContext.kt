package decompengine.acp

import java.nio.file.Path

/** Identity alone is not authority: only the boundary's remove-on-consume registry admits this. */
internal sealed class AcpProviderDnsRuntimeContext protected constructor()

/** Detached invocation ownership; implementations contain no request, broker or boundary callback. */
internal sealed class AcpProviderDnsInvocationLease protected constructor() {
    internal abstract fun clampDeadline(requestedDeadlineNanos: Long): Long
    internal abstract fun admitDispatch(requestedDeadlineNanos: Long): AcpProviderDnsDispatchTicket
    internal abstract fun closeBefore(cleanupDeadlineNanos: Long): Boolean
    internal abstract fun isClosed(): Boolean
}

/** Each accepted dispatch consumes one lifetime slot before any executor or native-start admission. */
internal sealed class AcpProviderDnsDispatchTicket protected constructor() {
    internal val deadlineNanos: Long
        get() = LinuxBubblewrapBoundary.providerDnsDispatchDeadline(this)
    internal fun bindOwner(owner: AcpProviderDnsProcess): AcpProviderDnsLaunchMaterial =
        LinuxBubblewrapBoundary.bindProviderDnsDispatch(this, owner)
    internal fun completeVerified(owner: AcpProviderDnsProcess): Boolean =
        LinuxBubblewrapBoundary.completeProviderDnsDispatch(this, owner)
}

/** Only a registered ticket returns this closed, descriptor-backed production launch material. */
internal sealed class AcpProviderDnsLaunchMaterial protected constructor() {
    internal abstract val jar: Path
    internal abstract val expectedSha256: String
    internal abstract val directory: Path
    internal abstract val javaExecutable: Path
    internal abstract val runtimeManifestSha256: String
    internal abstract fun requireCurrent()
}
