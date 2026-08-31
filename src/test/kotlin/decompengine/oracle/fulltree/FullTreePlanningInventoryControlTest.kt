package decompengine.oracle.fulltree

import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.Path
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class FullTreePlanningInventoryControlTest {
    @Test
    fun `fixture planning inventory is closed exact and byte deterministic`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val firstPath = directory.resolve("planning-first.json")
            val secondPath = directory.resolve("planning-second.json")

            val first = generate(fixture, firstPath)
            val second = generate(fixture, secondPath)

            assertContentEquals(Files.readAllBytes(firstPath), Files.readAllBytes(secondPath))
            assertEquals(first.outputSha256, second.outputSha256)
            assertEquals(first.reportSha256, second.reportSha256)
            val document = parseControlObject(firstPath)
            assertEquals(
                JsonObject(
                    mapOf(
                        "generatedSourceModules" to JsonPrimitive(1),
                        "handwrittenSourceModules" to JsonPrimitive(1),
                        "sourceModuleShards" to JsonPrimitive(2),
                        "sourceModules" to JsonPrimitive(2),
                        "sourceOnlyShards" to JsonPrimitive(2),
                        "sourceOnlyUnits" to JsonPrimitive(3),
                        "workUnits" to JsonPrimitive(12),
                    ),
                ),
                document.controlObject("counts"),
            )
            assertEquals(
                JsonObject(
                    mapOf(
                        "maximumCandidateSourceUnits" to JsonPrimitive(200_000),
                        "maximumOutputRecords" to JsonPrimitive(203_000),
                        "maximumSerializedBytes" to JsonPrimitive(32 * 1024 * 1024),
                        "maximumSourceModules" to JsonPrimitive(20),
                        "maximumWorkUnits" to JsonPrimitive(500_000),
                    ),
                ),
                document.controlObject("bounds"),
            )
            val oracle = document.controlObject("oracle")
            assertEquals(fixtureSha256(fixture.scope), oracle.controlString("scopeSha256"))
            assertEquals(fixtureSha256(fixture.sourceLock), oracle.controlString("sourceLockSha256"))
            assertEquals(fixtureSha256(fixture.manifest), oracle.controlString("artifactManifestSha256"))
            assertEquals(fixtureSha256(fixture.buildRecord), oracle.controlString("buildRecordSha256"))
            assertEquals(fixtureSha256(fixture.inventory), oracle.controlString("inventoryArtifactSha256"))
            assertEquals(
                fixtureSha256(fixture.sourceInventory),
                oracle.controlString("sourceInventoryArtifactSha256"),
            )
            assertEquals(FullTreePlanningInventoryControl.configurationSha256, oracle.controlString("configurationSha256"))
            assertEquals(
                OracleArtifacts.sha256(
                    OracleJson.canonicalBytes(JsonObject(document.filterKeys { it != "reportSha256" })),
                ),
                document.controlString("reportSha256"),
            )

            val registry = first.registry
            assertEquals(2, registry.sourceModules.size)
            assertEquals(3, registry.sourceOnlyUnits.size)
            registry.sourceModules.forEach { module ->
                assertEquals(module.unitId, module.moduleId)
                assertEquals(module, registry.requireOwnerModule(module.unitId))
                assertFalse(module.moduleId == "core")
            }
            registry.sourceOnlyUnits.forEach { sourceOnly ->
                assertFailsWith<FullTreeControlException> {
                    registry.requireOwnerModule(FullTreeInventoryControl.compilationUnitId(sourceOnly.sourcePath))
                }
            }
        }

    @Test
    fun `shuffled stale forged and expanded planning documents fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val originalPath = directory.resolve("planning.json")
            generate(fixture, originalPath)
            val original = parseControlObject(originalPath)

            val modules = original.controlArray("sourceModules").controlObjects("source modules")
            val changedIdModules = modules.toMutableList().apply {
                this[0] = JsonObject(this[0].toMutableMap().apply {
                    this["moduleId"] = JsonPrimitive("cu-${"0".repeat(32)}")
                })
            }
            val forgedModule = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["sourceModules"] = JsonArray(changedIdModules)
            }))
            val shuffled = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["sourceModules"] = JsonArray(modules.reversed())
            }))
            val sourceOnly = original.controlArray("sourceOnlyUnits").controlObjects("source-only units")
            val shuffledSourceOnly = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["sourceOnlyUnits"] = JsonArray(sourceOnly.reversed())
            }))
            val forgedSourceOnlyOwner = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["sourceOnlyUnits"] = JsonArray(sourceOnly.toMutableList().apply {
                    this[0] = JsonObject(this[0] + ("moduleId" to modules.first().getValue("moduleId")))
                })
            }))
            val omittedSourceOnly = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["sourceOnlyUnits"] = JsonArray(sourceOnly.dropLast(1))
                this["counts"] = JsonObject(original.controlObject("counts").toMutableMap().apply {
                    this["sourceOnlyUnits"] = JsonPrimitive(2)
                    this["workUnits"] = JsonPrimitive(11)
                })
            }))
            val staleInput = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["oracle"] = JsonObject(original.controlObject("oracle").toMutableMap().apply {
                    this["inventoryArtifactSha256"] = JsonPrimitive("0".repeat(64))
                })
            }))
            val staleBound = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["bounds"] = JsonObject(original.controlObject("bounds").toMutableMap().apply {
                    this["maximumWorkUnits"] = JsonPrimitive(499_999)
                })
            }))
            val extraClaim = rehashPlanning(JsonObject(original.toMutableMap().apply {
                this["headers"] = JsonArray(emptyList())
            }))
            val staleReportHash = JsonObject(original.toMutableMap().apply {
                this["reportSha256"] = JsonPrimitive("0".repeat(64))
            })

            listOf(
                forgedModule,
                shuffled,
                shuffledSourceOnly,
                forgedSourceOnlyOwner,
                omittedSourceOnly,
                staleInput,
                staleBound,
                extraClaim,
                staleReportHash,
            ).forEachIndexed { index, mutation ->
                val path = directory.resolve("planning-mutation-$index.json")
                writeControlObject(path, mutation)
                assertFailsWith<FullTreeControlException>("mutation $index") { load(fixture, path) }
            }
        }

    @Test
    fun `planning entity work byte and output alias bounds fail closed`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val referencePath = directory.resolve("planning-reference.json")
            generate(fixture, referencePath)
            val variants = listOf(
                FullTreePlanningInventoryLimits(maximumSourceModules = 1),
                FullTreePlanningInventoryLimits(maximumCandidateSourceUnits = 3),
                FullTreePlanningInventoryLimits(maximumOutputRecords = 4),
                FullTreePlanningInventoryLimits(maximumWorkUnits = 11),
                FullTreePlanningInventoryLimits(maximumSerializedBytes = Files.size(referencePath).toInt() - 1),
            )
            variants.forEachIndexed { index, limits ->
                val output = directory.resolve("planning-bounded-$index.json")
                assertFailsWith<FullTreeControlException>("bound $index") {
                    generate(fixture, output, limits)
                }
                assertFalse(Files.exists(output))
            }

            listOf(
                fixture.scope,
                fixture.sourceLock,
                fixture.manifest,
                fixture.buildRecord,
                fixture.inventory,
                fixture.sourceInventory,
            ).forEach { aliasedInput ->
                val inputSha256 = fixtureSha256(aliasedInput)
                assertFailsWith<FullTreeControlException>(aliasedInput.toString()) {
                    generate(fixture, aliasedInput)
                }
                assertEquals(inputSha256, fixtureSha256(aliasedInput))
            }
        }

    @Test
    fun `authenticated registry is sealed privately constructed and deeply immutable`() =
        inControlTemporaryDirectory { directory ->
            val fixture = createFullTreeControlFixture(directory.resolve("fixture"))
            val planningPath = directory.resolve("planning.json")
            val registry = generate(fixture, planningPath).registry
            val first = registry.sourceModules.first()

            assertTrue(
                FullTreePlanningInventoryControl::class.java.declaredConstructors.all {
                    Modifier.isPrivate(it.modifiers)
                },
            )
            assertTrue(AuthenticatedFullTreePlanningRegistry::class.java.isSealed)
            assertEquals(
                setOf(registry.javaClass),
                AuthenticatedFullTreePlanningRegistry::class.java.permittedSubclasses.toSet(),
            )
            val implementation = registry.javaClass
            assertTrue(Modifier.isPrivate(implementation.modifiers))
            val productionParameters = buildList {
                repeat(7) { add(Path::class.java) }
                add(FullTreePlanningInventoryLimits::class.java)
                add(Boolean::class.javaPrimitiveType!!)
            }
            val privateConstructor = implementation.declaredConstructors.single {
                Modifier.isPrivate(it.modifiers)
            }
            assertEquals(productionParameters, privateConstructor.parameterTypes.toList())
            val constructorBridges = implementation.declaredConstructors.filterNot {
                Modifier.isPrivate(it.modifiers)
            }
            assertEquals(1, constructorBridges.size)
            val constructorBridge = constructorBridges.single()
            assertTrue(Modifier.isPublic(constructorBridge.modifiers))
            assertTrue(constructorBridge.isSynthetic)
            assertEquals(productionParameters, constructorBridge.parameterTypes.dropLast(1))
            assertEquals(
                "kotlin.jvm.internal.DefaultConstructorMarker",
                constructorBridge.parameterTypes.last().name,
            )
            val factoryMethods = implementation.declaredClasses.single {
                it.simpleName == "Companion"
            }.declaredMethods.associateBy { it.name }
            assertEquals(setOf("generate", "load"), factoryMethods.keys)
            val factoryParameters = productionParameters.dropLast(1)
            assertTrue(factoryMethods.values.all { it.parameterTypes.toList() == factoryParameters })
            assertEquals(
                FullTreePlanningInventoryGeneration::class.java,
                factoryMethods.getValue("generate").returnType,
            )
            assertEquals(
                AuthenticatedFullTreePlanningRegistry::class.java,
                factoryMethods.getValue("load").returnType,
            )
            assertTrue(
                implementation.declaredClasses.flatMap { it.declaredMethods.toList() }.all { method ->
                    method.parameterTypes.none { parameter ->
                        parameter == JsonObject::class.java ||
                            Map::class.java.isAssignableFrom(parameter) ||
                            Collection::class.java.isAssignableFrom(parameter) ||
                            parameter == FullTreePlanningSourceModule::class.java ||
                            parameter == FullTreePlanningSourceOnlyUnit::class.java
                    }
                },
            )
            val forgedPlanning = directory.resolve("forged-planning.json")
            writeControlObject(forgedPlanning, JsonObject(emptyMap()))
            constructorBridge.isAccessible = true
            val bridgeFailure = assertFailsWith<InvocationTargetException> {
                constructorBridge.newInstance(
                    fixture.scope,
                    fixture.sourceLock,
                    fixture.manifest,
                    fixture.buildRecord,
                    fixture.inventory,
                    fixture.sourceInventory,
                    forgedPlanning,
                    FullTreePlanningInventoryLimits(),
                    false,
                    null,
                )
            }
            assertTrue(bridgeFailure.targetException is FullTreeControlException)
            assertTrue(
                implementation.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }.all { field ->
                    Modifier.isPrivate(field.modifiers) && Modifier.isFinal(field.modifiers)
                },
            )
            listOf(first, registry.sourceOnlyUnits.first()).forEach { record ->
                assertTrue(
                    record.javaClass.declaredFields.filterNot { Modifier.isStatic(it.modifiers) }.all { field ->
                        Modifier.isPrivate(field.modifiers) && Modifier.isFinal(field.modifiers)
                    },
                )
            }
            assertTrue(
                AuthenticatedFullTreePlanningRegistry::class.java.methods.none { method ->
                    method.returnType.name == JsonObject::class.java.name ||
                        method.parameterTypes.any { it.name == JsonObject::class.java.name }
                },
            )
            assertFailsWith<IllegalArgumentException> {
                Proxy.newProxyInstance(
                    AuthenticatedFullTreePlanningRegistry::class.java.classLoader,
                    arrayOf(AuthenticatedFullTreePlanningRegistry::class.java),
                ) { _, _, _ -> null }
            }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (registry.sourceModules as MutableList<FullTreePlanningSourceModule>).clear()
            }
            @Suppress("UNCHECKED_CAST")
            assertFailsWith<UnsupportedOperationException> {
                (registry.sourceOnlyUnits as MutableList<FullTreePlanningSourceOnlyUnit>).clear()
            }
            assertFailsWith<FullTreeControlException> { registry.requireOwnerModule("") }
            assertFailsWith<FullTreeControlException> {
                registry.requireOwnerModule("cu-${"f".repeat(32)}")
            }

            Files.writeString(fixture.inventory, "{}")
            assertEquals(first, registry.requireOwnerModule(first.unitId))
            assertEquals(2, registry.sourceModules.size)
            assertEquals(3, registry.sourceOnlyUnits.size)
        }

    @Test
    fun `checked production planning inventory is frozen and preserves colliding source identities`() =
        inControlTemporaryDirectory { directory ->
            val profile = Path.of("oracle/llvm/22.1.6")
            val checked = profile.resolve("full-tree-planning-inventory.json")
            val regenerated = directory.resolve("full-tree-planning-inventory.json")
            val result = FullTreePlanningInventoryControl.generateAndPublish(
                scopePath = profile.resolve("full-tree-scope.json"),
                sourceLockPath = profile.resolve("source-lock.json"),
                artifactManifestPath = profile.resolve("oracle-manifest.json"),
                buildRecordPath = profile.resolve("build-record.json"),
                inventoryPath = profile.resolve("full-tree-inventory.json"),
                sourceInventoryPath = profile.resolve("full-tree-source-inventory.json"),
                output = regenerated,
            )

            assertContentEquals(Files.readAllBytes(checked), Files.readAllBytes(regenerated))
            assertEquals(FROZEN_CONFIGURATION_SHA256, FullTreePlanningInventoryControl.configurationSha256)
            assertEquals(FROZEN_REPORT_SHA256, result.reportSha256)
            assertEquals(FROZEN_ARTIFACT_SHA256, result.outputSha256)
            assertEquals(2_150, result.registry.sourceModules.size)
            assertEquals(2_325, result.registry.sourceOnlyUnits.size)
            val document = parseControlObject(regenerated)
            assertEquals(57L, document.controlObject("counts").controlLong("sourceModuleShards"))
            assertEquals(178L, document.controlObject("counts").controlLong("sourceOnlyShards"))
            assertEquals(11_100L, document.controlObject("counts").controlLong("workUnits"))
            val oracle = document.controlObject("oracle")
            assertEquals(FROZEN_INVENTORY_ARTIFACT_SHA256, oracle.controlString("inventoryArtifactSha256"))
            assertEquals(FROZEN_SOURCE_INVENTORY_ARTIFACT_SHA256, oracle.controlString("sourceInventoryArtifactSha256"))

            val byPath = result.registry.sourceModules.associateBy(FullTreePlanningSourceModule::sourcePath)
            val basenameCollision = listOf(
                "source/clang/lib/Basic/Targets/AArch64.cpp",
                "source/clang/lib/CodeGen/Targets/AArch64.cpp",
            ).map { byPath.getValue(it).moduleId }
            val truncatedSanitizerCollision = listOf(
                "source/clang/lib/Analysis/LifetimeSafety/LifetimeAnnotations.cpp",
                "source/clang/lib/Analysis/LifetimeSafety/LifetimeSafety.cpp",
            ).map { byPath.getValue(it).moduleId }
            assertEquals(2, basenameCollision.toSet().size)
            assertEquals(2, truncatedSanitizerCollision.toSet().size)
        }

    private fun generate(
        fixture: FullTreeControlFixture,
        output: Path,
        limits: FullTreePlanningInventoryLimits = FullTreePlanningInventoryLimits(),
    ): FullTreePlanningInventoryGeneration = FullTreePlanningInventoryControl.generateAndPublish(
        scopePath = fixture.scope,
        sourceLockPath = fixture.sourceLock,
        artifactManifestPath = fixture.manifest,
        buildRecordPath = fixture.buildRecord,
        inventoryPath = fixture.inventory,
        sourceInventoryPath = fixture.sourceInventory,
        output = output,
        limits = limits,
    )

    private fun load(
        fixture: FullTreeControlFixture,
        path: Path,
    ): AuthenticatedFullTreePlanningRegistry = FullTreePlanningInventoryControl.loadAndValidate(
        path = path,
        scopePath = fixture.scope,
        sourceLockPath = fixture.sourceLock,
        artifactManifestPath = fixture.manifest,
        buildRecordPath = fixture.buildRecord,
        inventoryPath = fixture.inventory,
        sourceInventoryPath = fixture.sourceInventory,
    )

    private fun rehashPlanning(document: JsonObject): JsonObject {
        val withoutHash = JsonObject(document.filterKeys { it != "reportSha256" })
        val reportSha256 = OracleArtifacts.sha256(OracleJson.canonicalBytes(withoutHash))
        return JsonObject(document.toMutableMap().apply {
            this["reportSha256"] = JsonPrimitive(reportSha256)
        })
    }

    private companion object {
        const val FROZEN_CONFIGURATION_SHA256 =
            "f53587ec9cd1e5690ca454e0622e15ef38f55a0b12cf4ca3961d7d263bfab697"
        const val FROZEN_REPORT_SHA256 = "fcfe9bfd553ab9caee6a8f5a84a3a9345cd4243dcc6f46d752f68573bbdc6c70"
        const val FROZEN_ARTIFACT_SHA256 = "2bf9181f031e94304d63e184e5d2fb684623f981b655afb966a06db7c43be15a"
        const val FROZEN_INVENTORY_ARTIFACT_SHA256 =
            "6d96fc34506b3fbb7a0de2f9e2e77af26e7f513d016da59a2d0cee322bbd1306"
        const val FROZEN_SOURCE_INVENTORY_ARTIFACT_SHA256 =
            "33e53beb62221888abbf5e198a4da2abe3b5c29c809bb90f1faff15c3829edc4"
    }
}
