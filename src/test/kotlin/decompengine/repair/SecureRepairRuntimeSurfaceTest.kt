package decompengine.repair

import decompengine.validation.SandboxUnavailableException
import java.lang.reflect.Constructor
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.net.URI
import java.net.URLClassLoader
import java.nio.file.Files
import java.nio.file.Path
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import javax.tools.DiagnosticCollector
import javax.tools.JavaFileObject
import javax.tools.SimpleJavaFileObject
import javax.tools.ToolProvider
import kotlin.io.path.createTempDirectory
import kotlin.io.path.exists
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertSame
import kotlin.test.assertTrue

class SecureRepairRuntimeSurfaceTest {
    @Test
    fun `unknown profile and unavailable validation fail before project history mutation`() {
        val root = createTempDirectory("secure-repair-open-")
        val unknownHistory = root.resolve("unknown/reports/repair_history.json")
        assertFailsWith<IllegalArgumentException> {
            SecureRepairRuntime.open(RepairRuntimeConfiguration("unknown-profile", unknownHistory))
        }
        assertFalse(unknownHistory.parent.exists())

        val unavailableHistory = root.resolve("unavailable/reports/repair_history.json")
        assertFailsWith<SandboxUnavailableException> {
            SecureRepairRuntime.open(
                RepairRuntimeConfiguration("generated-c-make-v1", unavailableHistory),
            )
        }
        assertFalse(unavailableHistory.parent.exists())
    }

    @Test
    fun `main bytecode exposes only the data configured session facade`() {
        val gate = javap(SecureRepairRuntime::class.java)
        val session = javap(SecureRepairSession::class.java)
        val loop = javap(TraceGuidedRepairLoop::class.java)
        val graph = javap(ModuleRevisionGraph::class.java)
        val index = javap(ModuleRepairIndex::class.java)
        val gateNest = SecureRepairRuntime::class.java.declaredClasses.joinToString("\n", transform = ::javap)

        assertTrue(gate.contains("private static final java.lang.Object RUNTIME_IDENTITY;"))
        assertFalse(gate.lineSequence().any { it.trimStart().startsWith("public") && "RUNTIME_IDENTITY" in it })
        assertTrue(gate.lineSequence().any { "public static decompengine.repair.SecureRepairSession open(" in it })
        assertFalse(gate.lineSequence().any { it.trimStart().startsWith("public") && "TraceGuidedRepairLoop" in it })
        assertFalse(session.lineSequence().any { it.trimStart().startsWith("public") && "TraceGuidedRepairLoop" in it })
        assertOnlyGuardedSyntheticPublicConstructors(TraceGuidedRepairLoop::class.java)
        assertOnlyGuardedSyntheticPublicConstructors(ModuleRevisionGraph::class.java)
        assertOnlyGuardedSyntheticPublicConstructors(ModuleRepairIndex::class.java)
        assertFalse(listOf(gate, session, loop, graph, index).any { "forTesting" in it || "openForTesting" in it })
        assertFalse((gate + gateNest).contains("access$"), "Java gate generated a capability accessor")
        assertFalse(
            gate.lineSequence().any {
                it.trimStart().startsWith("public") && "java.lang.Object" in it && "(" in it && !it.contains("require")
            },
            "Java gate publishes an object-returning authority accessor",
        )

        val configurationFields = RepairRuntimeConfiguration::class.java.declaredFields.map { it.type }
        assertFalse(configurationFields.any(RepairRuntimeProfileProvider::class.java::isAssignableFrom))
        assertFalse(configurationFields.any(RepairIndexProfile::class.java::isAssignableFrom))
        assertFalse(configurationFields.any(RepairValidationStrategy::class.java::isAssignableFrom))
    }

    @Test
    fun `generic runtime bytecode has no program adapter constants and pins service discovery loader`() {
        val genericTypes = listOf(
            SecureRepairRuntime::class.java,
            RepairRuntimeProfileRegistry::class.java,
            RepairRuntimeProfileProvider::class.java,
        ).flatMap { type -> listOf(type) + type.declaredClasses }
        genericTypes.forEach { type ->
            val bytes = String(classFileBytes(type), Charsets.ISO_8859_1)
            val lowerBytes = bytes.lowercase()
            assertFalse("GeneratedC" in bytes, "${type.name} names a program adapter")
            assertFalse("decompengine/project" in bytes, "${type.name} depends on a program adapter package")
            assertFalse("decompengine.project" in bytes, "${type.name} depends on a program adapter package")
            assertFalse("gcc" in lowerBytes, "${type.name} names a benchmark program")
        }

        val gateCode = javap(SecureRepairRuntime::class.java, includeCode = true)
        assertTrue(gateCode.contains("java/lang/Class.getClassLoader"), gateCode)
        assertTrue(
            gateCode.contains(
                "java/util/ServiceLoader.load:(Ljava/lang/Class;Ljava/lang/ClassLoader;)Ljava/util/ServiceLoader;",
            ),
            gateCode,
        )
        assertFalse(
            gateCode.contains("java/util/ServiceLoader.load:(Ljava/lang/Class;)Ljava/util/ServiceLoader;"),
            gateCode,
        )
        assertFalse(gateCode.contains("getContextClassLoader"), gateCode)

        assertFalse(Modifier.isPublic(RepairRuntimeProfileRegistry::class.java.modifiers))
        assertFalse(
            RepairRuntimeProfileRegistry::class.java.declaredMethods.any { Modifier.isPublic(it.modifiers) },
            "profile registry exposes public mutation or construction",
        )
    }

    @Test
    fun `provider registry is exact immutable deterministic and validates materialized adapters`() {
        val alphaProfile = repairIndexProfile("alpha-profile")
        val zetaProfile = repairIndexProfile("zeta-profile")
        val alpha = repairProvider("alpha-profile", alphaProfile) { strictValidationStrategy() }
        val zeta = repairProvider("zeta-profile", zetaProfile) { strictValidationStrategy() }
        val registry = RepairRuntimeProfileRegistry.fromProviders(listOf(zeta, alpha))

        assertEquals(listOf("alpha-profile", "zeta-profile"), registry.profileIds().toList())
        assertSame(alphaProfile, registry.requireProfile("alpha-profile").indexProfile())
        assertFailsWith<UnsupportedOperationException> {
            @Suppress("UNCHECKED_CAST")
            (registry.profileIds() as MutableSet<String>).add("new-profile")
        }
        assertFailsWith<IllegalArgumentException> { registry.requireProfile("missing-profile") }

        assertFailsWith<IllegalStateException> {
            RepairRuntimeProfileRegistry.fromProviders(listOf(alpha, alpha))
        }
        assertFailsWith<IllegalStateException> {
            RepairRuntimeProfileRegistry.fromProviders(
                listOf(repairProvider("invalid profile", repairIndexProfile("invalid profile")) { strictValidationStrategy() }),
            )
        }
        assertFailsWith<IllegalStateException> {
            RepairRuntimeProfileRegistry.fromProviders(
                listOf(repairProvider("declared-profile", repairIndexProfile("different-profile")) { strictValidationStrategy() }),
            )
        }
        assertFailsWith<NullPointerException> {
            @Suppress("UNCHECKED_CAST")
            RepairRuntimeProfileRegistry.fromProviders(
                listOf<RepairRuntimeProfileProvider?>(null) as List<RepairRuntimeProfileProvider>,
            )
        }
        assertFailsWith<NullPointerException> {
            RepairRuntimeProfileRegistry.fromProviders(
                listOf(repairProvider(null, repairIndexProfile("null-provider-id")) { strictValidationStrategy() }),
            )
        }
        assertFailsWith<NullPointerException> {
            RepairRuntimeProfileRegistry.fromProviders(
                listOf(repairProvider("null-index", null) { strictValidationStrategy() }),
            )
        }
        assertFailsWith<NullPointerException> {
            RepairRuntimeProfileRegistry.fromProviders(
                listOf(repairProvider("null-index-id", repairIndexProfile(null)) { strictValidationStrategy() }),
            )
        }
        assertFailsWith<IllegalStateException> {
            RepairRuntimeProfileRegistry.fromProviders(
                listOf(
                    repairProvider(
                        profileId = { throw IllegalStateException("broken provider ID") },
                        indexProfile = { repairIndexProfile("unreachable") },
                        validationStrategy = { strictValidationStrategy() },
                    ),
                ),
            )
        }
    }

    @Test
    fun `validation creation is selected lazy and null or broken selection fails directly`() {
        val brokenCalls = AtomicInteger()
        val goodCalls = AtomicInteger()
        val registry = RepairRuntimeProfileRegistry.fromProviders(
            listOf(
                repairProvider("broken-validation", repairIndexProfile("broken-validation")) {
                    brokenCalls.incrementAndGet()
                    throw IllegalStateException("broken validation factory")
                },
                repairProvider("good-validation", repairIndexProfile("good-validation")) {
                    goodCalls.incrementAndGet()
                    strictValidationStrategy()
                },
                repairProvider("null-validation", repairIndexProfile("null-validation")) { null },
            ),
        )

        assertEquals(0, brokenCalls.get())
        assertEquals(0, goodCalls.get())
        assertSame(
            RepairValidationAssurance.STRICT_CONTAINED,
            registry.requireProfile("good-validation").createValidationStrategy().assurance,
        )
        assertEquals(0, brokenCalls.get(), "an unrelated broken strategy was instantiated")
        assertEquals(1, goodCalls.get())
        assertFailsWith<IllegalStateException> {
            registry.requireProfile("broken-validation").createValidationStrategy()
        }
        assertFailsWith<NullPointerException> {
            registry.requireProfile("null-validation").createValidationStrategy()
        }
    }

    @Test
    fun `synthetic implementation constructors require one-shot Java authorization and clear it on failure`() {
        val indexProfile = repairIndexProfile("surface-construction-profile")
        val profileHandle = SecureRepairRuntime::class.java.declaredClasses
            .single { it.simpleName == "RegisteredProfile" }
            .getDeclaredConstructor(String::class.java, RepairIndexProfile::class.java)
            .let { constructor ->
                constructor.isAccessible = true
                constructor.newInstance("surface-construction-profile", indexProfile)
            }
        val graphAuthority = SecureRepairRuntime::class.java.declaredClasses
            .single { it.simpleName == "GraphAuthority" }
            .getDeclaredConstructor(RepairIndexProfile::class.java)
            .let { constructor ->
                constructor.isAccessible = true
                constructor.newInstance(indexProfile)
            }

        val guarded = listOf(
            TraceGuidedRepairLoop::class.java,
            ModuleRevisionGraph::class.java,
            ModuleRepairIndex::class.java,
        )
        guarded.forEach { type ->
            assertTrue(invokeSyntheticConstructor(type) is SecurityException)
        }

        listOf(
            TraceGuidedRepairLoop::class.java to { SecureRepairRuntime.authorizeLoopConstruction(Any()) },
            ModuleRevisionGraph::class.java to { SecureRepairRuntime.authorizeGraphConstruction(Any()) },
            ModuleRepairIndex::class.java to { SecureRepairRuntime.authorizeIndexConstruction(Any()) },
        ).forEach { (type, forgedAuthorization) ->
            assertFailsWith<SecurityException> { forgedAuthorization() }
            assertTrue(
                invokeSyntheticConstructor(type) is SecurityException,
                "forged ${type.name} authorization left construction armed",
            )
        }

        assertAuthorizationIsOneShot(
            type = TraceGuidedRepairLoop::class.java,
            authorize = { SecureRepairRuntime.authorizeLoopConstruction(profileHandle) },
        )
        assertAuthorizationIsOneShot(
            type = ModuleRevisionGraph::class.java,
            authorize = { SecureRepairRuntime.authorizeGraphConstruction(graphAuthority) },
            arguments = mapOf(0 to graphAuthority),
        )
        assertAuthorizationIsOneShot(
            type = ModuleRepairIndex::class.java,
            authorize = { SecureRepairRuntime.authorizeIndexConstruction(graphAuthority) },
        )
    }

    @Test
    fun `separately compiled ordinary Java cannot steal or forge repair authority`() {
        val output = createTempDirectory("malicious-repair-java-")
        val stolen = compileFixture("/repair/malicious/StealRepairIdentity.java", output.resolve("steal"))
        assertFalse(stolen.succeeded)
        assertTrue(stolen.diagnostics.contains("private"))

        val forged = compileFixture("/repair/malicious/ForgeRepairAuthorities.java", output.resolve("forge"))
        assertTrue(forged.succeeded, forged.diagnostics)
        URLClassLoader(arrayOf(output.resolve("forge").toUri().toURL()), javaClass.classLoader).use { loader ->
            val fixture = loader.loadClass("decompengine.repair.ForgeRepairAuthorities")
            assertEquals(true, fixture.getMethod("graphBridgeRejectsForgery").invoke(null))
            assertEquals(true, fixture.getMethod("loopBridgeRejectsForgery").invoke(null))
        }
    }

    private data class Compilation(val succeeded: Boolean, val diagnostics: String)

    private fun assertOnlyGuardedSyntheticPublicConstructors(type: Class<*>) {
        val publicConstructors = type.declaredConstructors.filter { Modifier.isPublic(it.modifiers) }
        assertTrue(publicConstructors.isNotEmpty(), "expected Kotlin marker constructor for ${type.name}")
        assertTrue(
            publicConstructors.all { constructor ->
                constructor.isSynthetic &&
                    constructor.parameterTypes.lastOrNull()?.name == "kotlin.jvm.internal.DefaultConstructorMarker"
            },
            "${type.name} exposes an ordinary public constructor: $publicConstructors",
        )
    }

    private fun assertAuthorizationIsOneShot(
        type: Class<*>,
        authorize: () -> Unit,
        arguments: Map<Int, Any?> = emptyMap(),
    ) {
        try {
            authorize()
            assertTrue(
                invokeSyntheticConstructor(type, arguments) is IllegalArgumentException,
                "authorized ${type.name} constructor did not reach its post-consumption input check",
            )
            assertTrue(
                invokeSyntheticConstructor(type, arguments) is SecurityException,
                "failed ${type.name} construction left a reusable authorization",
            )
        } finally {
            SecureRepairRuntime.clearConstructionAuthorization()
        }
    }

    private fun invokeSyntheticConstructor(type: Class<*>, arguments: Map<Int, Any?> = emptyMap()): Throwable {
        val constructor = syntheticConstructor(type)
        constructor.isAccessible = true
        val values = Array<Any?>(constructor.parameterCount) { index ->
            primitiveDefault(constructor.parameterTypes[index])
        }
        arguments.forEach { (index, value) -> values[index] = value }
        val failure = assertFailsWith<InvocationTargetException> {
            constructor.newInstance(*values)
        }
        return requireNotNull(failure.cause)
    }

    private fun syntheticConstructor(type: Class<*>): Constructor<*> = type.declaredConstructors.single { constructor ->
        constructor.isSynthetic &&
            constructor.parameterTypes.lastOrNull()?.name == "kotlin.jvm.internal.DefaultConstructorMarker"
    }

    private fun primitiveDefault(type: Class<*>): Any? = when (type) {
        java.lang.Boolean.TYPE -> false
        java.lang.Byte.TYPE -> 0.toByte()
        java.lang.Short.TYPE -> 0.toShort()
        java.lang.Integer.TYPE -> 0
        java.lang.Long.TYPE -> 0L
        java.lang.Float.TYPE -> 0F
        java.lang.Double.TYPE -> 0.0
        java.lang.Character.TYPE -> '\u0000'
        else -> null
    }

    private fun compileFixture(resource: String, output: Path): Compilation {
        val compiler = requireNotNull(ToolProvider.getSystemJavaCompiler()) { "tests require a JDK compiler" }
        val source = requireNotNull(javaClass.getResourceAsStream(resource)) { "missing fixture: $resource" }
            .bufferedReader().use { it.readText() }
        Files.createDirectories(output)
        val diagnostics = DiagnosticCollector<JavaFileObject>()
        val file = object : SimpleJavaFileObject(URI.create("string:///$resource"), JavaFileObject.Kind.SOURCE) {
            override fun getCharContent(ignoreEncodingErrors: Boolean): CharSequence = source
        }
        val options = listOf("-classpath", System.getProperty("java.class.path"), "-d", output.toString())
        val succeeded = compiler.getStandardFileManager(diagnostics, null, Charsets.UTF_8).use { manager ->
            compiler.getTask(null, manager, diagnostics, options, null, listOf(file)).call()
        }
        return Compilation(succeeded, diagnostics.diagnostics.joinToString("\n"))
    }

    private fun repairProvider(
        profileId: String?,
        indexProfile: RepairIndexProfile?,
        validationStrategy: () -> RepairValidationStrategy?,
    ): RepairRuntimeProfileProvider = repairProvider(
        profileId = { profileId },
        indexProfile = { indexProfile },
        validationStrategy = validationStrategy,
    )

    private fun repairProvider(
        profileId: () -> String?,
        indexProfile: () -> RepairIndexProfile?,
        validationStrategy: () -> RepairValidationStrategy?,
    ): RepairRuntimeProfileProvider = Proxy.newProxyInstance(
        javaClass.classLoader,
        arrayOf(RepairRuntimeProfileProvider::class.java),
    ) { proxy, method, arguments ->
        when (method.name) {
            "profileId" -> profileId()
            "indexProfile" -> indexProfile()
            "createValidationStrategy" -> validationStrategy()
            "toString" -> "test repair profile provider"
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === arguments?.singleOrNull()
            else -> throw AssertionError("unexpected provider method: ${method.name}")
        }
    } as RepairRuntimeProfileProvider

    private fun repairIndexProfile(profileId: String?): RepairIndexProfile = Proxy.newProxyInstance(
        javaClass.classLoader,
        arrayOf(RepairIndexProfile::class.java),
    ) { proxy, method, arguments ->
        when (method.name) {
            "profileId" -> profileId
            "toString" -> "test repair index profile"
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === arguments?.singleOrNull()
            else -> throw AssertionError("unexpected index profile method: ${method.name}")
        }
    } as RepairIndexProfile

    private fun strictValidationStrategy(): RepairValidationStrategy = Proxy.newProxyInstance(
        javaClass.classLoader,
        arrayOf(RepairValidationStrategy::class.java),
    ) { proxy, method, arguments ->
        when (method.name) {
            "getAssurance" -> RepairValidationAssurance.STRICT_CONTAINED
            "requireAvailable" -> Unit
            "toString" -> "test repair validation strategy"
            "hashCode" -> System.identityHashCode(proxy)
            "equals" -> proxy === arguments?.singleOrNull()
            else -> throw AssertionError("unexpected validation method: ${method.name}")
        }
    } as RepairValidationStrategy

    private fun classFileBytes(type: Class<*>): ByteArray = requireNotNull(
        type.getResourceAsStream("/${type.name.replace('.', '/')}.class"),
    ) { "missing class bytes for ${type.name}" }.use { it.readBytes() }

    private fun javap(type: Class<*>, includeCode: Boolean = false): String {
        val executable = Path.of(System.getProperty("java.home"), "bin", "javap")
        val command = mutableListOf(executable.toString(), "-p")
        if (includeCode) command += "-c"
        command += listOf("-classpath", System.getProperty("java.class.path"), type.name)
        val process = ProcessBuilder(command).redirectErrorStream(true).start()
        val output = process.inputStream.bufferedReader().use { it.readText() }
        assertTrue(process.waitFor(10, TimeUnit.SECONDS), "javap timed out")
        assertEquals(0, process.exitValue(), output)
        return output
    }
}
