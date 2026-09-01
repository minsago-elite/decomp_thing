package decompengine.oracle.behavior

import java.lang.reflect.InvocationTargetException

internal class LlvmBehaviorHostedToolchainImageEngineV1Exception(message: String) :
    IllegalArgumentException(message)

/**
 * Lease-bound ownership of one authenticated Docker Engine endpoint.
 *
 * Construction consumes both the retained runtime-preflight endpoint and the exact image-build
 * lease, then performs one fixed unversioned `HEAD /_ping`. This checkpoint exposes no socket,
 * pathname, channel, request method, request target, header, body, response, parser, callback,
 * build, inspect, cancel, delete, tar-emission, CREATE, START, observation, or release operation.
 * The accepted peer is the pinned current-user Unix peer and the accepted response is exactly the
 * Docker 29.7.2/Linux/API-1.55/builder-v2 non-experimental policy.
 *
 * ACP remains the first-class candidate producer/operator and is not an input. Neither this owner,
 * the retained lease, Docker, nor Python receives oracle, validation, scoring, certification, or
 * release authority.
 */
internal sealed interface LlvmBehaviorHostedToolchainImageEngineV1Owner : AutoCloseable {
    val authority: String
    val operationId: String
    val buildId: String
    val apiVersion: String
    val builderVersion: String
    val operatingSystem: String
    val server: String
    val experimental: Boolean
    val headPingVerified: Boolean
    val imageBuildPosted: Boolean
    val imageAuthenticated: Boolean
    val cleanupProved: Boolean
    val acpRole: String
    val acpOracleAccess: String
    val oracleAuthority: Boolean
    val scoringAuthority: Boolean
    val releaseEligible: Boolean

    fun requireCurrentBindings()

    override fun close()
}

/** Fixed owner factory; both arguments are relinquished on success and every failure path. */
internal object LlvmBehaviorHostedToolchainImageEngineV1 {
    fun open(
        endpointBinding: LlvmBehaviorRetainedDockerEndpointBinding,
        freshLeaseOwner: LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner,
    ): LlvmBehaviorHostedToolchainImageEngineV1Owner {
        try {
            val method = LlvmBehaviorRuntimePreflightPublisher::class.java.declaredMethods
                .single { it.name == "openHostedToolchainImageEngineV1" }
            check(method.trySetAccessible())
            return try {
                method.invoke(
                    LlvmBehaviorRuntimePreflightPublisher,
                    endpointBinding,
                    freshLeaseOwner,
                ) as LlvmBehaviorHostedToolchainImageEngineV1Owner
            } catch (failure: InvocationTargetException) {
                throw failure.targetException
            }
        } catch (_: Throwable) {
            engineFail("cannot open the fixed lease-bound Docker Engine owner")
        } finally {
            // These aliases are either transferred and inert or are the still-owned failure input.
            try {
                endpointBinding.close()
            } catch (_: Throwable) {
                // The factory never returns a failed input capability to its caller.
            }
            try {
                freshLeaseOwner.close()
            } catch (_: Throwable) {
                // The factory never returns a failed input capability to its caller.
            }
        }
    }

    private fun retainVerified(
        endpoint: PinnedDockerEngineV155VerifiedEndpointOwner,
        lease: LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner,
    ): LlvmBehaviorHostedToolchainImageEngineV1Owner {
        val constructor = BoundOwner::class.java.getDeclaredConstructor(
            PinnedDockerEngineV155VerifiedEndpointOwner::class.java,
            LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner::class.java,
        )
        check(constructor.trySetAccessible())
        return try {
            constructor.newInstance(endpoint, lease)
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private class BoundOwner private constructor(
        private val endpoint: PinnedDockerEngineV155VerifiedEndpointOwner,
        private val lease: LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner,
    ) : LlvmBehaviorHostedToolchainImageEngineV1Owner {
        private var closed = false
        private var poisoned = false

        override val authority: String
            @Synchronized get() = current().let { ENGINE_AUTHORITY }
        override val operationId: String
            @Synchronized get() = current().let { lease.operationId }
        override val buildId: String
            @Synchronized get() = current().let { lease.buildId }
        override val apiVersion: String
            @Synchronized get() = current().let { FIXED_API_VERSION }
        override val builderVersion: String
            @Synchronized get() = current().let { FIXED_BUILDER_VERSION }
        override val operatingSystem: String
            @Synchronized get() = current().let { FIXED_OPERATING_SYSTEM }
        override val server: String
            @Synchronized get() = current().let { FIXED_SERVER }
        override val experimental: Boolean
            @Synchronized get() = current().let { false }
        override val headPingVerified: Boolean
            @Synchronized get() = current().let { true }
        override val imageBuildPosted: Boolean
            @Synchronized get() = current().let { false }
        override val imageAuthenticated: Boolean
            @Synchronized get() = current().let { false }
        override val cleanupProved: Boolean
            @Synchronized get() = current().let { false }
        override val acpRole: String
            @Synchronized get() = current().let { ACP_ROLE }
        override val acpOracleAccess: String
            @Synchronized get() = current().let { "none" }
        override val oracleAuthority: Boolean
            @Synchronized get() = current().let { false }
        override val scoringAuthority: Boolean
            @Synchronized get() = current().let { false }
        override val releaseEligible: Boolean
            @Synchronized get() = current().let { false }

        @Synchronized
        override fun requireCurrentBindings() {
            current()
            try {
                lease.requireCurrentBinding()
                endpoint.requireCurrent()
                lease.requireCurrentBinding()
            } catch (_: Throwable) {
                poisoned = true
                engineFail("fixed lease-bound Docker Engine bindings changed")
            }
        }

        private fun current() {
            check(!closed) { "fixed lease-bound Docker Engine owner is closed" }
            if (poisoned) engineFail("fixed lease-bound Docker Engine owner is poisoned")
        }

        @Synchronized
        override fun close() {
            if (closed) return
            closed = true
            var failed = false
            try {
                endpoint.close()
            } catch (_: Throwable) {
                failed = true
            }
            try {
                lease.close()
            } catch (_: Throwable) {
                failed = true
            }
            if (failed) engineFail("cannot close the fixed lease-bound Docker Engine owner")
        }
    }
}

private fun engineFail(message: String): Nothing =
    throw LlvmBehaviorHostedToolchainImageEngineV1Exception(message)

private const val ENGINE_AUTHORITY = "lease-bound-fixed-docker-engine-head-ping-v1"
private const val FIXED_API_VERSION = "1.55"
private const val FIXED_BUILDER_VERSION = "2"
private const val FIXED_OPERATING_SYSTEM = "linux"
private const val FIXED_SERVER = "Docker/29.7.2 (linux)"
private const val ACP_ROLE = "first-class-candidate-producer-operator"
