package decompengine.oracle.behavior

import java.io.InputStream
import java.io.OutputStream
import java.lang.reflect.Method
import java.lang.reflect.Modifier
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.channels.Channel
import java.nio.channels.SocketChannel
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class LlvmBehaviorHostedToolchainImageEngineV1Test {
    @Test
    fun `sole Engine factory accepts only admitted endpoint and untouched fresh lease`() {
        val factory = LlvmBehaviorHostedToolchainImageEngineV1::class.java
        val open = factory.declaredMethods.single { it.name == "open" && !it.isSynthetic }
        assertTrue(Modifier.isPublic(open.modifiers))
        assertEquals(
            listOf(
                LlvmBehaviorRetainedDockerEndpointBinding::class.java,
                LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java,
            ),
            open.parameterTypes.toList(),
        )
        assertEquals(LlvmBehaviorHostedToolchainImageEngineV1Owner::class.java, open.returnType)
        assertTrue(factory.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertEquals(
            setOf("open"),
            factory.declaredMethods.filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
                .map { it.name }.toSet(),
        )

        val owner = LlvmBehaviorHostedToolchainImageEngineV1Owner::class.java
        assertTrue(owner.isSealed)
        assertEquals(
            setOf(
                "close",
                "getAcpOracleAccess",
                "getAcpRole",
                "getApiVersion",
                "getAuthority",
                "getBuildId",
                "getBuilderVersion",
                "getCleanupProved",
                "getExperimental",
                "getHeadPingVerified",
                "getImageAuthenticated",
                "getImageBuildPosted",
                "getOperatingSystem",
                "getOperationId",
                "getOracleAuthority",
                "getReleaseEligible",
                "getScoringAuthority",
                "getServer",
                "requireCurrentBindings",
            ),
            owner.declaredMethods.filterNot { it.isSynthetic }.map { it.name }.toSet(),
        )
        assertTrue(owner.declaredMethods.all { it.parameterCount == 0 })
        assertTrue(
            (owner.declaredMethods + open).none { method ->
                method.returnType in PROHIBITED_ENGINE_SURFACE ||
                    method.parameterTypes.any { it in PROHIBITED_ENGINE_SURFACE } ||
                    method.parameterTypes.any { it.name.startsWith("kotlin.jvm.functions.") }
            },
        )
        assertTrue(
            owner.declaredMethods.none { method ->
                listOf(
                    "request", "header", "body", "parse", "connect", "inspect",
                    "cancel", "delete", "emit", "tar", "create", "start", "execute", "run",
                ).any { marker -> method.name.contains(marker, ignoreCase = true) }
            },
        )

        val implementation = factory.declaredClasses.single {
            LlvmBehaviorHostedToolchainImageEngineV1Owner::class.java.isAssignableFrom(it)
        }
        assertTrue(Modifier.isPrivate(implementation.modifiers))
        assertTrue(implementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertEquals(
            mapOf(
                "closed" to Boolean::class.javaPrimitiveType,
                "endpoint" to PinnedDockerEngineV155VerifiedEndpointOwner::class.java,
                "lease" to LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner::class.java,
                "poisoned" to Boolean::class.javaPrimitiveType,
            ),
            implementation.declaredFields.associate { it.name to it.type },
        )
        assertFalse(implementation.declaredFields.any { it.type in PROHIBITED_ENGINE_SURFACE })
    }

    @Test
    fun `private transfer chain has no operation bearing intermediate escape`() {
        val runtimeOpen = LlvmBehaviorRuntimePreflightPublisher::class.java.declaredMethods.single {
            it.name == "openHostedToolchainImageEngineV1"
        }
        assertTrue(Modifier.isPrivate(runtimeOpen.modifiers))
        assertFalse(runtimeOpen.isSynthetic)
        assertEquals(
            listOf(
                LlvmBehaviorRetainedDockerEndpointBinding::class.java,
                LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java,
            ),
            runtimeOpen.parameterTypes.toList(),
        )
        assertEquals(LlvmBehaviorHostedToolchainImageEngineV1Owner::class.java, runtimeOpen.returnType)

        val retainedImplementation = LlvmBehaviorRuntimePreflightPublisher::class.java.declaredClasses.single {
            LlvmBehaviorRetainedDockerEndpointBinding::class.java.isAssignableFrom(it)
        }
        assertTrue(Modifier.isPrivate(retainedImplementation.modifiers))
        assertTrue(retainedImplementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        val retainedOpen = retainedImplementation.declaredMethods.single {
            it.name == "openHostedToolchainImageEngineV1"
        }
        assertTrue(Modifier.isPrivate(retainedOpen.modifiers))
        assertEquals(
            listOf(LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java),
            retainedOpen.parameterTypes.toList(),
        )

        val pinnedOpen = PinnedDockerRuntimeBindings.Companion::class.java.declaredMethods.single {
            it.name == "openHostedToolchainImageEngineV1"
        }
        assertTrue(Modifier.isPrivate(pinnedOpen.modifiers))
        assertFalse(pinnedOpen.isSynthetic)
        assertEquals(
            listOf(
                PinnedDockerEndpointBinding::class.java,
                LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java,
            ),
            pinnedOpen.parameterTypes.toList(),
        )
        assertEquals(LlvmBehaviorHostedToolchainImageEngineV1Owner::class.java, pinnedOpen.returnType)

        val leaseConsume = LlvmBehaviorHostedToolchainImageBuildLeaseV2::class.java.declaredMethods.single {
            it.name == "consumeFreshForHostedToolchainImageEngineV1"
        }
        assertTrue(Modifier.isPrivate(leaseConsume.modifiers))
        assertEquals(
            listOf(LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java),
            leaseConsume.parameterTypes.toList(),
        )
        assertEquals(LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner::class.java, leaseConsume.returnType)

        val retain = LlvmBehaviorHostedToolchainImageEngineV1::class.java.declaredMethods.single {
            it.name == "retainVerified"
        }
        assertTrue(Modifier.isPrivate(retain.modifiers))
        assertEquals(
            listOf(
                PinnedDockerEngineV155VerifiedEndpointOwner::class.java,
                LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner::class.java,
            ),
            retain.parameterTypes.toList(),
        )
        assertEquals(LlvmBehaviorHostedToolchainImageEngineV1Owner::class.java, retain.returnType)

        val retainedFreshLease = LlvmBehaviorHostedToolchainImageBuildLeaseV2::class.java.declaredClasses
            .single { it.simpleName == "RetainedEngineOwner" }
        assertTrue(Modifier.isPrivate(retainedFreshLease.modifiers))
        assertTrue(retainedFreshLease.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        val boundLease = LlvmBehaviorHostedToolchainImageBuildLeaseV2::class.java.declaredClasses
            .single { it.simpleName == "BoundOwner" }
        assertTrue(
            Modifier.isPrivate(
                boundLease.declaredMethods.single {
                    it.name == "consumeForHostedToolchainImageEngineV1"
                }.modifiers,
            ),
        )

        assertTrue(PinnedDockerEndpointBinding::class.java.isSealed)
        assertEquals(
            setOf("close", "requireCurrent"),
            PinnedDockerEndpointBinding::class.java.declaredMethods.filterNot { it.isSynthetic }
                .map { it.name }.toSet(),
        )
        assertTrue(PinnedDockerEngineV155VerifiedEndpointOwner::class.java.isSealed)
        assertEquals(
            setOf("close", "requireCurrent"),
            PinnedDockerEngineV155VerifiedEndpointOwner::class.java.declaredMethods.filterNot { it.isSynthetic }
                .map { it.name }.toSet(),
        )
    }

    @Test
    fun `emitted transport state construction and request bytes remain JVM private`() {
        val nested = PinnedDockerRuntimeBindings::class.java.declaredClasses.toList()
        val endpointState = nested.single { it.simpleName == "PinnedDockerEndpointState" }
        val endpointBinding = nested.single { it.simpleName == "BoundPinnedDockerEndpointBinding" }
        val verifiedEndpoint = nested.single {
            it.simpleName == "BoundPinnedDockerEngineV155VerifiedEndpointOwner"
        }
        listOf(endpointState, endpointBinding, verifiedEndpoint).forEach { implementation ->
            assertTrue(Modifier.isPrivate(implementation.modifiers), implementation.name)
            assertTrue(
                implementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) },
                implementation.name,
            )
        }
        assertTrue(
            Modifier.isPrivate(
                endpointState.declaredMethods.single { it.name == "requireFixedHeadPing" }.modifiers,
            ),
        )
        assertTrue(
            Modifier.isPrivate(
                endpointBinding.declaredMethods.single { it.name == "consumeForFixedEngineV155" }.modifiers,
            ),
        )
        assertFailsWith<ClassNotFoundException> {
            Class.forName("decompengine.oracle.behavior.PinnedDockerEndpointState")
        }

        val closure = buildList {
            add(PinnedDockerRuntimeBindings::class.java)
            add(PinnedDockerRuntimeBindings.Companion::class.java)
            add(LlvmBehaviorRuntimePreflightPublisher::class.java)
            add(LlvmBehaviorHostedToolchainImageEngineV1::class.java)
            addAll(nestedClassesRecursively(PinnedDockerRuntimeBindings::class.java))
            addAll(nestedClassesRecursively(LlvmBehaviorRuntimePreflightPublisher::class.java))
            addAll(nestedClassesRecursively(LlvmBehaviorHostedToolchainImageEngineV1::class.java))
        }.distinct()
        assertTrue(
            closure.flatMap { it.declaredFields.toList() }.none { it.type == Method::class.java },
            "an already-accessible reflective bridge must never be cached",
        )
        assertTrue(
            closure.flatMap { it.declaredMethods.toList() }.none { method ->
                method.name.startsWith("access$") && Modifier.isPublic(method.modifiers) &&
                    (method.returnType == ByteArray::class.java ||
                        method.returnType == Path::class.java ||
                        method.returnType == SocketChannel::class.java ||
                        method.returnType == endpointState ||
                        method.returnType == PinnedDockerEngineV155VerifiedEndpointOwner::class.java)
            },
            "no public synthetic accessor may return mutable request or retained transport state",
        )

        val fileFacade = Class.forName("decompengine.oracle.behavior.PinnedDockerRuntimeBindingsKt")
        assertTrue(
            fileFacade.declaredMethods.none { method ->
                Modifier.isPublic(method.modifiers) && method.returnType == ByteArray::class.java
            },
            "the exact request must be freshly encoded, never returned through a ByteArray accessor",
        )
        assertTrue(
            (closure + fileFacade).flatMap { it.declaredMethods.toList() }.none { method ->
                Modifier.isPublic(method.modifiers) &&
                    method.name.startsWith("requireFixedHeadPing")
            },
            "HEAD /_ping must exist only behind private methods",
        )
    }
}

private fun nestedClassesRecursively(root: Class<*>): List<Class<*>> =
    root.declaredClasses.flatMap { nested -> listOf(nested) + nestedClassesRecursively(nested) }

private val PROHIBITED_ENGINE_SURFACE = setOf(
    Path::class.java,
    ByteArray::class.java,
    ByteBuffer::class.java,
    Channel::class.java,
    Socket::class.java,
    InputStream::class.java,
    OutputStream::class.java,
    Map::class.java,
)
