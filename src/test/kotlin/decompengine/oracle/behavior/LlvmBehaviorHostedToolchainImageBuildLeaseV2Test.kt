package decompengine.oracle.behavior

import decompengine.oracle.core.DescriptorBoundAtomicStateFile
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.lang.reflect.Proxy
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardCopyOption
import java.nio.file.attribute.PosixFilePermissions
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

class LlvmBehaviorHostedToolchainImageBuildLeaseV2Test {
    @Test
    fun `binding pins unique recipe request namespace and a fact free recoverable chain`() =
        withFixture { fixture ->
            val root = fixture.newJournalRoot("happy")
            val canonicalBinding: ByteArray
            val operationId: String
            fixture.createFresh(root).use { owner ->
                assertEquals(LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERED, owner.phase)
                assertEquals(
                    "recipe-bound-fact-free-llvm-behavior-hosted-toolchain-image-build-lease",
                    owner.authority,
                )
                assertExactPins(owner)
                assertEquals(pathSha256(root), owner.journalRootPathSha256)
                assertTrue(owner.operationId.matches(SHA256))
                assertEquals(owner.operationId, owner.buildId)
                assertEquals(
                    "/v1.55/build/cancel?id=${owner.operationId}",
                    owner.buildCancelRequestTarget,
                )
                assertEquals(
                    "decomp-llvm-behavior-hosted-toolchain:lease-${owner.operationId}",
                    owner.recoveryTag,
                )
                assertEquals(LEASE_LABEL_KEY, owner.recoveryLeaseLabelKey)
                assertEquals(owner.operationId, owner.recoveryLeaseLabelValue)
                assertEquals(CONTENT_LABEL_KEY, owner.contentSha256LabelKey)
                assertEquals(DETERMINISTIC_TAR_SHA256, owner.contentSha256LabelValue)

                val binding = OracleJson.parse(owner.canonicalBindingBytes) as JsonObject
                assertEquals(BINDING_FIELDS, binding.keys)
                assertEquals(owner.bindingSha256, binding.string("bindingSha256"))
                assertEquals(owner.bindingSha256, sha256(JsonObject(binding - "bindingSha256")))
                assertEquals(owner.requestIntentSha256, sha256(binding.obj("buildRequestIntent")))
                assertCanonicalDerivations(root, owner, binding)
                assertExactBoundaries(binding)
                assertExactBuildRequest(owner, binding.obj("buildRequestIntent"))
                val copy = owner.canonicalBindingBytes
                copy.fill(0)
                assertFalse(copy.contentEquals(owner.canonicalBindingBytes))

                canonicalBinding = owner.canonicalBindingBytes
                operationId = owner.operationId
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT,
                    owner.recordRecoveryLocatorsAbsent(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_POST_ARMED,
                    owner.armImageBuildPost(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_OUTCOME_AMBIGUOUS,
                    owner.recordImageBuildOutcomeAmbiguous(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_FENCE_REQUIRED,
                    owner.requireRecoveryFence(),
                )
                assertReadOnlyCurrent(root, owner)
            }

            fixture.recover(root).use { owner ->
                assertEquals(operationId, owner.operationId)
                assertContentEquals(canonicalBinding, owner.canonicalBindingBytes)
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_FENCE_REQUIRED,
                    owner.phase,
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.BUILD_TERMINATED_NO_IMAGE,
                    owner.recordBuildTerminatedNoImage(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.ORPHAN_IMAGE_IDENTIFIED,
                    owner.recordOrphanImageIdentified(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_DELETE_ARMED,
                    owner.armImageDelete(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
                    owner.recordImageAbsenceProved(),
                )
            }

            val names = entryNames(root)
            assertEquals(
                setOf("binding.json") + (0..8).map { "transition-${it.toString().padStart(4, '0')}.json" },
                names,
            )
            names.forEach { requireImmutableFile(root.resolve(it)) }
            assertFactFreeChain(root, operationId, 0..8)
        }

    @Test
    fun `nonce survives cold recovery within the retained journal namespace`() =
        withFixture { fixture ->
            val root = fixture.newJournalRoot("nonce")
            val firstBinding: JsonObject
            val firstOperation: String
            fixture.createFresh(root).use { owner ->
                firstBinding = OracleJson.parse(owner.canonicalBindingBytes) as JsonObject
                firstOperation = owner.operationId
            }
            fixture.recover(root).use { replayed ->
                assertEquals(firstOperation, replayed.operationId)
                assertEquals(firstBinding.string("leaseNonce"), binding(replayed).string("leaseNonce"))
                assertFalse(replayed is LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner)
                val engineOpen = LlvmBehaviorHostedToolchainImageEngineV1::class.java.declaredMethods
                    .single { it.name == "open" && !it.isSynthetic }
                assertFalse(
                    engineOpen.parameterTypes[1].isInstance(replayed),
                    "a cold-recovered lease must not satisfy the public Engine fresh capability",
                )
            }
        }

    @Test
    fun `tail truncation can recover facts but can never recover POST arm capability`() =
        withFixture { fixture ->
            val root = fixture.newJournalRoot("truncated-tail")
            fixture.createFresh(root).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordImageBuildOutcomeAmbiguous()
            }
            deleteJournalEntry(root.resolve("transition-0003.json"))
            deleteJournalEntry(root.resolve("transition-0002.json"))

            fixture.recover(root).use { recovered ->
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT,
                    recovered.phase,
                )
                assertFalse(recovered is LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner)
                assertFalse(
                    recovered::class.java.methods.any { method -> method.name == "armImageBuildPost" },
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
                    recovered.blockCleanup(),
                )
            }
            assertEquals(
                "cleanup-blocked",
                (OracleJson.parse(Files.readAllBytes(root.resolve("transition-0002.json"))) as JsonObject)
                    .string("phase"),
            )
        }

    @Test
    fun `recover rejects empty without mutation and fresh rejects every existing journal`() =
        withFixture { fixture ->
            val empty = fixture.newJournalRoot("empty-recovery")
            val emptyBefore = journalSnapshot(empty)
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                fixture.recover(empty)
            }
            assertEquals(emptyBefore, journalSnapshot(empty))

            val existing = fixture.newJournalRoot("fresh-existing")
            fixture.createFresh(existing).close()
            val existingBefore = journalSnapshot(existing)
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                fixture.createFresh(existing)
            }
            assertEquals(existingBefore, journalSnapshot(existing))
        }

    @Test
    fun `consuming one recipe binding twice cannot poison its first lease`() =
        withFixture { fixture ->
            val firstRoot = fixture.newJournalRoot("one-shot-binding-first")
            val secondRoot = fixture.newJournalRoot("one-shot-binding-second")
            val recipeAlias = fixture.openRecipe()
            val binding = recipeAlias.transferToImageBuildLease()
            recipeAlias.close()
            val first = LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(firstRoot, binding)
            try {
                val secondBefore = journalSnapshot(secondRoot)
                assertFailsWith<IllegalStateException> {
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(secondRoot, binding)
                }
                binding.close()
                assertEquals(secondBefore, journalSnapshot(secondRoot))
                first.requireCurrentBinding()
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT,
                    first.recordRecoveryLocatorsAbsent(),
                )
            } finally {
                first.close()
            }
        }

    @Test
    fun `fixed Engine handoff makes every lease alias inert without closing retained ownership`() =
        withFixture { fixture ->
            val root = fixture.newJournalRoot("engine-transfer")
            val owner = fixture.createFresh(root)
            val operationId = owner.operationId
            val before = journalSnapshot(root)
            val retained = consumeFreshLeaseForPrivateEngine(owner)

            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                owner.requireCurrentBinding()
            }
            assertFailsWith<IllegalStateException> { owner.operationId }
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                owner.recordRecoveryLocatorsAbsent()
            }
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                owner.armImageBuildPost()
            }
            owner.close()
            owner.close()

            retained.requireCurrentBinding()
            assertEquals(operationId, retained.operationId)
            assertEquals(operationId, retained.buildId)
            assertEquals(before, journalSnapshot(root))
            retained.close()
            retained.close()
            assertFailsWith<IllegalStateException> { retained.requireCurrentBinding() }
            assertFailsWith<IllegalStateException> { retained.operationId }
        }

    @Test
    fun `POST arm is one way and every outcome cleanup branch is legal only in order`() =
        withFixture { fixture ->
            val illegal = fixture.newJournalRoot("illegal")
            fixture.createFresh(illegal).use { owner ->
                val before = journalSnapshot(illegal)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    owner.armImageBuildPost()
                }
                assertEquals(before, journalSnapshot(illegal))
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    owner.recordRecoveryLocatorsAbsent()
                }
            }

            val armed = fixture.newJournalRoot("armed")
            fixture.createFresh(armed).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                val before = journalSnapshot(armed)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    owner.armImageBuildPost()
                }
                assertEquals(before, journalSnapshot(armed))
            }
            listOf<(LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner) -> Unit>(
                { it.recordImageAuthenticated() },
                { it.recordOrphanImageIdentified() },
                { it.recordBuildTerminatedNoImage() },
            ).forEach { forbiddenOutcome ->
                fixture.recover(armed).use { recovered ->
                    assertEquals(
                        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_POST_ARMED,
                        recovered.phase,
                    )
                    assertFalse(recovered is LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner)
                    val before = journalSnapshot(armed)
                    assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                        forbiddenOutcome(recovered)
                    }
                    assertEquals(before, journalSnapshot(armed))
                }
            }
            fixture.recover(armed).use { recovered ->
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_BUILD_OUTCOME_AMBIGUOUS,
                    recovered.recordImageBuildOutcomeAmbiguous(),
                )
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_FENCE_REQUIRED,
                    recovered.requireRecoveryFence(),
                )
            }

            val ambiguousBypass = fixture.newJournalRoot("ambiguous-cannot-bypass-fence")
            fixture.createFresh(ambiguousBypass).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordImageBuildOutcomeAmbiguous()
                val before = journalSnapshot(ambiguousBypass)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    owner.recordImageAuthenticated()
                }
                assertEquals(before, journalSnapshot(ambiguousBypass))
            }

            val fenceBypass = fixture.newJournalRoot("fence-cannot-bypass-termination")
            fixture.createFresh(fenceBypass).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordImageBuildOutcomeAmbiguous()
                owner.requireRecoveryFence()
                val before = journalSnapshot(fenceBypass)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    owner.recordOrphanImageIdentified()
                }
                assertEquals(before, journalSnapshot(fenceBypass))
            }

            val noImage = fixture.newJournalRoot("no-image")
            fixture.createFresh(noImage).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordBuildTerminatedNoImage()
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
                    owner.recordImageAbsenceProved(),
                )
            }


            val lateImage = fixture.newJournalRoot("late-image-after-termination")
            fixture.createFresh(lateImage).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordImageBuildOutcomeAmbiguous()
                owner.requireRecoveryFence()
                owner.recordBuildTerminatedNoImage()
                owner.recordOrphanImageIdentified()
                owner.armImageDelete()
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.IMAGE_ABSENCE_PROVED,
                    owner.recordImageAbsenceProved(),
                )
            }
            assertTrue(Files.exists(lateImage.resolve("transition-0008.json")))

            val noImageBlocked = fixture.newJournalRoot("no-image-cleanup-blocked")
            fixture.createFresh(noImageBlocked).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordBuildTerminatedNoImage()
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
                    owner.blockCleanup(),
                )
            }

            val orphan = fixture.newJournalRoot("orphan")
            fixture.createFresh(orphan).use { owner ->
                owner.recordRecoveryLocatorsAbsent()
                owner.armImageBuildPost()
                owner.recordOrphanImageIdentified()
                owner.armImageDelete()
                owner.recordImageAbsenceProved()
            }

            listOf("collision-before-observation", "pre-arm-race").forEachIndexed { index, label ->
                val blocked = fixture.newJournalRoot(label)
                fixture.createFresh(blocked).use { owner ->
                    if (index == 1) owner.recordRecoveryLocatorsAbsent()
                    assertEquals(
                        LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.CLEANUP_BLOCKED,
                        owner.blockCleanup(),
                    )
                }
            }
        }

    @Test
    fun `exact pending binding and transition replay but collisions corruption gaps and residue fail`() =
        withFixture { fixture ->
            val pendingBindingRoot = fixture.newJournalRoot("pending-binding")
            val pendingBindingOperation = openAndClose(fixture, pendingBindingRoot)
            Files.delete(pendingBindingRoot.resolve("transition-0000.json"))
            val bindingPath = pendingBindingRoot.resolve("binding.json")
            val pendingBinding = pendingBindingRoot.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("binding.json"),
            )
            Files.move(bindingPath, pendingBinding)
            fixture.recover(pendingBindingRoot).use { recovered ->
                assertEquals(pendingBindingOperation, recovered.operationId)
                assertEquals(LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERED, recovered.phase)
            }
            assertTrue(Files.exists(bindingPath, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(pendingBinding, LinkOption.NOFOLLOW_LINKS))

            val pendingTransitionRoot = fixture.newJournalRoot("pending-transition")
            fixture.createFresh(pendingTransitionRoot).use { it.recordRecoveryLocatorsAbsent() }
            val transition = pendingTransitionRoot.resolve("transition-0001.json")
            val pendingTransition = pendingTransitionRoot.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("transition-0001.json"),
            )
            Files.move(transition, pendingTransition)
            fixture.recover(pendingTransitionRoot).use { recovered ->
                assertEquals(
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.RECOVERY_LOCATORS_ABSENT,
                    recovered.phase,
                )
            }
            assertTrue(Files.exists(transition, LinkOption.NOFOLLOW_LINKS))
            assertFalse(Files.exists(pendingTransition, LinkOption.NOFOLLOW_LINKS))

            val collisionRoot = fixture.newJournalRoot("collision")
            openAndClose(fixture, collisionRoot)
            val collision = collisionRoot.resolve(
                DescriptorBoundAtomicStateFile.temporaryName("transition-0000.json"),
            )
            Files.copy(
                collisionRoot.resolve("transition-0000.json"),
                collision,
                StandardCopyOption.COPY_ATTRIBUTES,
            )
            assertOpenFailsWithoutMutation(fixture, collisionRoot)

            val corruptRoot = fixture.newJournalRoot("corrupt")
            openAndClose(fixture, corruptRoot)
            appendByte(corruptRoot.resolve("binding.json"))
            assertOpenFailsWithoutMutation(fixture, corruptRoot)

            val gapRoot = fixture.newJournalRoot("gap")
            fixture.createFresh(gapRoot).use {
                it.recordRecoveryLocatorsAbsent()
            }
            Files.move(gapRoot.resolve("transition-0001.json"), gapRoot.resolve("transition-0002.json"))
            assertOpenFailsWithoutMutation(fixture, gapRoot)

            val residueRoot = fixture.newJournalRoot("residue")
            openAndClose(fixture, residueRoot)
            val residue = residueRoot.resolve("caller-fact.json")
            Files.writeString(residue, "{}\n")
            Files.setPosixFilePermissions(residue, PosixFilePermissions.fromString("r--------"))
            assertOpenFailsWithoutMutation(fixture, residueRoot)
        }

    @Test
    fun `JVM surface accepts no caller nonce locator ID bytes facts runner or Engine`() {
        val factory = LlvmBehaviorHostedToolchainImageBuildLeaseV2::class.java
        val entryPoints = factory.declaredMethods
            .filter { Modifier.isPublic(it.modifiers) && !it.isSynthetic }
            .associateBy { it.name }
        assertEquals(setOf("createFresh", "recover"), entryPoints.keys)
        entryPoints.values.forEach { entryPoint ->
            assertEquals(
                listOf(Path::class.java, LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding::class.java),
                entryPoint.parameterTypes.toList(),
            )
        }
        assertEquals(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java,
            entryPoints.getValue("createFresh").returnType,
        )
        assertEquals(
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner::class.java,
            entryPoints.getValue("recover").returnType,
        )
        assertTrue(factory.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        val freshImplementation = factory.declaredClasses.single { it.simpleName == "FreshBoundOwner" }
        val recoveredImplementation = factory.declaredClasses.single { it.simpleName == "RecoveredBoundOwner" }
        assertTrue(freshImplementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(recoveredImplementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(
            factory.declaredMethods.filter {
                it.name == "createFreshBoundLease" || it.name == "recoverBoundLease"
            }.all { Modifier.isPrivate(it.modifiers) },
        )
        val fileFacade = Class.forName(
            "decompengine.oracle.behavior.LlvmBehaviorHostedToolchainImageBuildLeaseV2Kt",
        )
        val prohibitedLeaseConstructionTypes = setOf(
            "OpenedToolchainImageBuildLease",
            "ToolchainImageBuildDescriptorJournal",
            "ToolchainImageBuildLeaseBinding",
            "ToolchainImageBuildLeaseHistory",
            "FreshBoundOwner",
            "LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner",
        )
        assertTrue(
            fileFacade.declaredMethods.none { method ->
                Modifier.isPublic(method.modifiers) &&
                    (method.returnType.simpleName in prohibitedLeaseConstructionTypes ||
                        method.name.contains("createFreshBoundLease") ||
                        method.name.contains("recoverBoundLease") ||
                        (method.parameterTypes.any {
                            it == LlvmBehaviorHostedToolchainImageRecipeV1LeaseOwner::class.java
                        } && method.returnType.simpleName in prohibitedLeaseConstructionTypes))
            },
            "the file facade must not expose a fresh or recovered journal construction chain",
        )
        listOf(
            "decompengine.oracle.behavior.OpenedToolchainImageBuildLease",
            "decompengine.oracle.behavior.ToolchainImageBuildDescriptorJournal",
        ).forEach { className ->
            val implementation = Class.forName(className)
            assertTrue(implementation.declaredConstructors.all { Modifier.isPrivate(it.modifiers) })
        }

        val owner = LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner::class.java
        val freshOwner = LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner::class.java
        assertTrue(owner.isSealed)
        assertTrue(freshOwner.isSealed)
        assertTrue(owner.declaredConstructors.isEmpty())
        assertTrue(freshOwner.declaredConstructors.isEmpty())
        assertFailsWith<IllegalArgumentException> {
            Proxy.newProxyInstance(owner.classLoader, arrayOf(owner)) { _, _, _ -> null }
        }
        assertEquals(setOf("armImageBuildPost"), freshOwner.declaredMethods.map { it.name }.toSet())
        assertFalse(owner.declaredMethods.any { it.name == "armImageBuildPost" })

        assertEquals(
            setOf(
                "armImageDelete",
                "blockCleanup",
                "close",
                "getAuthority",
                "getBaseImageReference",
                "getBindingSha256",
                "getBuildCancelRequestTarget",
                "getBuildId",
                "getBuildIntentSha256",
                "getBuildRecordSha256",
                "getCanonicalBindingBytes",
                "getContentSha256LabelKey",
                "getContentSha256LabelValue",
                "getDeterministicTarBytes",
                "getDeterministicTarSha256",
                "getDockerfileBytes",
                "getDockerfileSha256",
                "getJournalRootPathSha256",
                "getLatestTransitionSha256",
                "getOperationId",
                "getPhase",
                "getPlatform",
                "getRecoveryLeaseLabelKey",
                "getRecoveryLeaseLabelValue",
                "getRecoveryTag",
                "getReproductionLockSha256",
                "getRequestIntentSha256",
                "getSourceDateEpoch",
                "recordBuildTerminatedNoImage",
                "recordImageAbsenceProved",
                "recordImageAuthenticated",
                "recordImageBuildOutcomeAmbiguous",
                "recordOrphanImageIdentified",
                "recordRecoveryLocatorsAbsent",
                "requireCurrentBinding",
                "requireRecoveryFence",
            ),
            owner.declaredMethods.filterNot { it.isSynthetic }.map { it.name }.toSet(),
        )
        assertTrue(owner.declaredMethods.all { it.parameterCount == 0 })
        assertTrue(
            (owner.declaredMethods + freshOwner.declaredMethods + entryPoints.values).none { method ->
                method.parameterTypes.any { type ->
                    listOf(
                        "String",
                        "ByteArray",
                        "OutputStream",
                        "Fact",
                        "Json",
                        "Receipt",
                        "Engine",
                        "Runner",
                        "Callback",
                    ).any { marker -> type.simpleName.contains(marker, ignoreCase = true) }
                }
            },
        )
        assertTrue(
            owner.declaredMethods.none { method ->
                listOf("execute", "createContainer", "start", "score", "publish", "release", "deleteImage")
                    .any { forbidden -> method.name.equals(forbidden, ignoreCase = true) }
            },
        )
        assertEquals(
            listOf(
                "recovered",
                "recovery-locators-absent",
                "image-build-post-armed",
                "image-build-outcome-ambiguous",
                "image-authenticated",
                "orphan-image-identified",
                "recovery-fence-required",
                "build-terminated-no-image",
                "image-delete-armed",
                "image-absence-proved",
                "cleanup-blocked",
            ),
            LlvmBehaviorHostedToolchainImageBuildLeaseV2Phase.entries.map { it.wireName },
        )
    }

    @Test
    fun `recipe journal and root drift poison without mutating replacement state`() =
        withFixture { fixture ->
            val recipeDriftRoot = fixture.newJournalRoot("recipe-drift")
            val lease = fixture.createFresh(recipeDriftRoot)
            val dockerfileAlias = fixture.dockerfile.resolveSibling("build-toolchain-hard-link.Dockerfile")
            try {
                val before = journalSnapshot(recipeDriftRoot)
                Files.createLink(dockerfileAlias, fixture.dockerfile)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    lease.requireCurrentBinding()
                }
                assertEquals(before, journalSnapshot(recipeDriftRoot))
                val poisoned = assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    lease.requireCurrentBinding()
                }
                assertTrue(poisoned.message.orEmpty().contains("poisoned"), poisoned.message)
                assertEquals(before, journalSnapshot(recipeDriftRoot))
            } finally {
                lease.close()
                Files.deleteIfExists(dockerfileAlias)
            }

            val journalDriftRoot = fixture.newJournalRoot("journal-drift")
            val journalLease = fixture.createFresh(journalDriftRoot)
            try {
                appendByte(journalDriftRoot.resolve("transition-0000.json"))
                val before = journalSnapshot(journalDriftRoot)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    journalLease.requireCurrentBinding()
                }
                assertEquals(before, journalSnapshot(journalDriftRoot))
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    journalLease.recordRecoveryLocatorsAbsent()
                }
            } finally {
                journalLease.close()
            }

            val root = fixture.newJournalRoot("root-replacement")
            val rootLease = fixture.createFresh(root)
            val detached = root.parent.resolve("detached-root-replacement")
            try {
                Files.move(root, detached)
                Files.createDirectory(root)
                Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
                val replacementBefore = journalSnapshot(root)
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    rootLease.requireCurrentBinding()
                }
                assertEquals(replacementBefore, journalSnapshot(root))
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    rootLease.recordRecoveryLocatorsAbsent()
                }
                assertEquals(replacementBefore, journalSnapshot(root))
            } finally {
                rootLease.close()
            }
        }

    @Test
    fun `exact private root and exclusive descriptor lock fail before journal mutation`() =
        withFixture { fixture ->
            val root = fixture.newJournalRoot("lock")
            val first = fixture.createFresh(root)
            try {
                val before = journalSnapshot(root)
                val secondRecipe = fixture.openRecipeBinding()
                assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                    LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(root, secondRecipe)
                }
                assertEquals(before, journalSnapshot(root))
                secondRecipe.close()
            } finally {
                first.close()
            }

            val nonNormalized = fixture.newJournalRoot("non-normalized")
            val before = journalSnapshot(nonNormalized)
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(
                    nonNormalized.resolve("."),
                    fixture.openRecipeBinding(),
                )
            }
            assertEquals(before, journalSnapshot(nonNormalized))

            val wrongMode = fixture.newJournalRoot("wrong-mode")
            Files.setPosixFilePermissions(wrongMode, PosixFilePermissions.fromString("rwxr-x---"))
            assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
                LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(
                    wrongMode,
                    fixture.openRecipeBinding(),
                )
            }
            assertTrue(entryNames(wrongMode).isEmpty())
        }

    private fun assertExactPins(owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner) {
        assertEquals(REPRODUCTION_LOCK_SHA256, owner.reproductionLockSha256)
        assertEquals(BUILD_RECORD_SHA256, owner.buildRecordSha256)
        assertEquals(DOCKERFILE_SHA256, owner.dockerfileSha256)
        assertEquals(1_638L, owner.dockerfileBytes)
        assertEquals(DETERMINISTIC_TAR_SHA256, owner.deterministicTarSha256)
        assertEquals(3_584L, owner.deterministicTarBytes)
        assertEquals(BASE_IMAGE_REFERENCE, owner.baseImageReference)
        assertEquals("linux/amd64", owner.platform)
        assertEquals("1779182222", owner.sourceDateEpoch)
    }

    private fun assertCanonicalDerivations(
        root: Path,
        owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner,
        binding: JsonObject,
    ) {
        val recipe = binding.obj("recipe")
        val request = binding.obj("buildRequestIntent")
        val policy = request.obj("policy")
        val buildIntent = JsonObject(
            mapOf(
                "buildRequestPolicy" to policy,
                "provider" to JsonPrimitive(
                    "kotlin-llvm-behavior-hosted-toolchain-image-build-intent-v2",
                ),
                "recipe" to recipe,
                "schemaVersion" to JsonPrimitive(2),
            ),
        )
        assertEquals(sha256(buildIntent), owner.buildIntentSha256)
        val operationDocument = JsonObject(
            mapOf(
                "buildIntentSha256" to JsonPrimitive(owner.buildIntentSha256),
                "journalRootPathSha256" to JsonPrimitive(pathSha256(root)),
                "leaseNonce" to JsonPrimitive(binding.string("leaseNonce")),
                "provider" to JsonPrimitive(
                    "kotlin-llvm-behavior-hosted-toolchain-image-build-operation-id-v2",
                ),
                "schemaVersion" to JsonPrimitive(2),
            ),
        )
        assertTrue(binding.string("leaseNonce").matches(SHA256))
        assertEquals(sha256(operationDocument), owner.operationId)
        assertEquals(owner.operationId, binding.obj("recoveryLeaseLabel").string("value"))
        assertEquals(LEASE_LABEL_KEY, binding.obj("recoveryLeaseLabel").string("key"))
    }

    private fun assertExactBoundaries(binding: JsonObject) {
        assertEquals(
            JsonObject(
                mapOf(
                    "imageBuildAuthority" to JsonPrimitive(false),
                    "input" to JsonPrimitive(false),
                    "oracleAccess" to JsonPrimitive("none"),
                    "role" to JsonPrimitive("first-class-candidate-producer-operator"),
                ),
            ),
            binding.obj("acpBoundary"),
        )
        assertEquals(
            JsonObject(
                mapOf(
                    "oracleOrControlAuthority" to JsonPrimitive(false),
                    "packagePresence" to JsonPrimitive("reviewed-recipe-installs-python3"),
                ),
            ),
            binding.obj("pythonBoundary"),
        )
        val claims = binding.obj("claims")
        assertFalse("acpAuthority" in claims)
        assertEquals(JsonPrimitive(false), claims.getValue("imageBuildAuthority"))
        assertTrue(claims.values.all { it == JsonPrimitive(false) })
    }

    private fun assertExactBuildRequest(
        owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner,
        request: JsonObject,
    ) {
        assertEquals(REQUEST_INTENT_FIELDS, request.keys)
        assertEquals(3_584L, (request.getValue("contentLength") as JsonPrimitive).content.toLong())
        assertEquals(DETERMINISTIC_TAR_SHA256, request.string("contentSha256"))
        assertEquals(JsonObject(emptyMap()), request.obj("buildArguments"))
        assertEquals(owner.operationId, request.string("buildId"))
        assertEquals(
            JsonObject(mapOf("buildid" to JsonPrimitive(owner.operationId))),
            request.obj("buildIdQuery"),
        )
        assertEquals(
            JsonObject(
                mapOf(
                    "buildId" to JsonPrimitive(owner.operationId),
                    "method" to JsonPrimitive("POST"),
                    "queryKey" to JsonPrimitive("id"),
                    "requestTarget" to JsonPrimitive(owner.buildCancelRequestTarget),
                    "response200Meaning" to
                        JsonPrimitive("request-returned-not-quiescence-or-image-absence"),
                    "response200ProvesBuildTermination" to JsonPrimitive(false),
                    "registrationRaceRequiresIndependentFence" to JsonPrimitive(true),
                    "unknownIdMayReturn200" to JsonPrimitive(true),
                ),
            ),
            request.obj("buildCancelLocator"),
        )
        assertEquals(JsonArray(listOf(JsonPrimitive(owner.recoveryTag))), request.getValue("tags"))
        assertEquals(
            JsonObject(
                mapOf(
                    CONTENT_LABEL_KEY to JsonPrimitive(DETERMINISTIC_TAR_SHA256),
                    LEASE_LABEL_KEY to JsonPrimitive(owner.operationId),
                ),
            ),
            request.obj("labels"),
        )
        assertEquals(EXACT_BUILD_POLICY, request.obj("policy"))
    }

    private fun assertFactFreeChain(root: Path, operationId: String, sequences: IntRange) {
        val claims = (OracleJson.parse(Files.readAllBytes(root.resolve("binding.json"))) as JsonObject)
            .obj("claims")
        var previous = "0".repeat(64)
        sequences.forEach { sequence ->
            val path = root.resolve("transition-${sequence.toString().padStart(4, '0')}.json")
            val transition = OracleJson.parse(Files.readAllBytes(path)) as JsonObject
            assertEquals(TRANSITION_FIELDS, transition.keys)
            assertEquals(operationId, transition.string("operationId"))
            assertEquals(sequence, transition.stringOrNumber("sequence").toInt())
            assertEquals(previous, transition.string("previousTransitionSha256"))
            assertEquals(JsonObject(emptyMap()), transition.obj("facts"))
            assertEquals(claims, transition.obj("claims"))
            val transitionSha256 = transition.string("transitionSha256")
            assertEquals(transitionSha256, sha256(JsonObject(transition - "transitionSha256")))
            previous = transitionSha256
        }
    }

    private fun assertReadOnlyCurrent(
        root: Path,
        owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner,
    ) {
        val before = journalSnapshot(root)
        val phase = owner.phase
        val latest = owner.latestTransitionSha256
        owner.requireCurrentBinding()
        owner.requireCurrentBinding()
        assertEquals(before, journalSnapshot(root))
        assertEquals(phase, owner.phase)
        assertEquals(latest, owner.latestTransitionSha256)
    }

    private fun openAndClose(fixture: LeaseFixture, root: Path): String {
        var operationId = ""
        fixture.createFresh(root).use {
            operationId = it.operationId
        }
        return operationId
    }

    private fun assertOpenFailsWithoutMutation(fixture: LeaseFixture, root: Path) {
        val before = journalSnapshot(root)
        assertFailsWith<LlvmBehaviorHostedToolchainImageBuildLeaseV2Exception> {
            fixture.recover(root)
        }
        assertEquals(before, journalSnapshot(root))
    }

    private fun binding(owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner): JsonObject =
        OracleJson.parse(owner.canonicalBindingBytes) as JsonObject
}

private fun consumeFreshLeaseForPrivateEngine(
    owner: LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner,
): LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner {
    val method = LlvmBehaviorHostedToolchainImageBuildLeaseV2::class.java.declaredMethods.single {
        it.name == "consumeFreshForHostedToolchainImageEngineV1"
    }
    assertTrue(Modifier.isPrivate(method.modifiers))
    assertTrue(method.trySetAccessible())
    return try {
        method.invoke(LlvmBehaviorHostedToolchainImageBuildLeaseV2, owner)
            as LlvmBehaviorHostedToolchainImageBuildLeaseV2EngineFreshOwner
    } catch (failure: InvocationTargetException) {
        throw failure.targetException
    }
}

private class LeaseFixture(private val root: Path) {
    private val recipeRoot = Files.createDirectory(root.resolve("recipe")).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }
    private val journals = Files.createDirectory(root.resolve("journals")).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }
    val reproductionLock: Path = copyChecked("toolchain-reproduction.json")
    val buildRecord: Path = copyChecked("build-record.json")
    val dockerfile: Path = copyChecked("build-toolchain.Dockerfile")

    fun openRecipe(): LlvmBehaviorHostedToolchainImageRecipeV1Owner =
        LlvmBehaviorHostedToolchainImageRecipeV1.open(reproductionLock, buildRecord, dockerfile)

    fun openRecipeBinding(): LlvmBehaviorHostedToolchainImageRecipeV1LeaseBinding =
        openRecipe().transferToImageBuildLease()

    fun createFresh(root: Path): LlvmBehaviorHostedToolchainImageBuildLeaseV2FreshOwner =
        LlvmBehaviorHostedToolchainImageBuildLeaseV2.createFresh(root, openRecipeBinding())

    fun recover(root: Path): LlvmBehaviorHostedToolchainImageBuildLeaseV2Owner =
        LlvmBehaviorHostedToolchainImageBuildLeaseV2.recover(root, openRecipeBinding())

    fun newJournalRoot(label: String): Path = Files.createDirectory(journals.resolve(label)).also {
        Files.setPosixFilePermissions(it, PosixFilePermissions.fromString("rwx------"))
    }

    private fun copyChecked(name: String): Path = recipeRoot.resolve(name).also { destination ->
        Files.copy(CHECKED_ROOT.resolve(name), destination, StandardCopyOption.COPY_ATTRIBUTES)
    }
}

private fun JsonObject.obj(name: String): JsonObject = getValue(name) as JsonObject

private fun JsonObject.string(name: String): String = (getValue(name) as JsonPrimitive).content

private fun JsonObject.stringOrNumber(name: String): String = (getValue(name) as JsonPrimitive).content

private fun pathSha256(path: Path): String =
    OracleArtifacts.sha256(path.toString().toByteArray(Charsets.UTF_8))

private fun sha256(document: JsonObject): String =
    OracleArtifacts.sha256(OracleJson.canonicalBytes(document))

private fun mutate(path: Path) {
    val bytes = Files.readAllBytes(path)
    bytes[bytes.lastIndex] = (bytes.last().toInt() xor 1).toByte()
    Files.write(path, bytes)
}

private fun appendByte(path: Path) {
    val bytes = Files.readAllBytes(path)
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    Files.write(path, bytes + '\n'.code.toByte())
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
}

private fun deleteJournalEntry(path: Path) {
    Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
    Files.delete(path)
}

private fun requireImmutableFile(path: Path) {
    assertTrue(Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS))
    assertFalse(Files.isSymbolicLink(path))
    assertEquals(
        PosixFilePermissions.fromString("r--------"),
        Files.getPosixFilePermissions(path, LinkOption.NOFOLLOW_LINKS),
    )
    assertEquals(
        1,
        (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt(),
    )
}

private fun entryNames(directory: Path): Set<String> = Files.list(directory).use { entries ->
    entries.map { it.fileName.toString() }.toList().toSet()
}

private fun journalSnapshot(root: Path): LeaseJournalSnapshot {
    val entries = Files.list(root).use { paths ->
        paths.sorted().map { path ->
            path.fileName.toString() to LeaseJournalEntrySnapshot(
                device = (Files.getAttribute(path, "unix:dev", LinkOption.NOFOLLOW_LINKS) as Number).toLong(),
                inode = (Files.getAttribute(path, "unix:ino", LinkOption.NOFOLLOW_LINKS) as Number).toLong(),
                mode = (Files.getAttribute(path, "unix:mode", LinkOption.NOFOLLOW_LINKS) as Number).toInt(),
                linkCount =
                    (Files.getAttribute(path, "unix:nlink", LinkOption.NOFOLLOW_LINKS) as Number).toInt(),
                modifiedMillis = Files.getLastModifiedTime(path, LinkOption.NOFOLLOW_LINKS).toMillis(),
                bytes = Files.readAllBytes(path).toList(),
            )
        }.toList().toMap()
    }
    return LeaseJournalSnapshot(
        modifiedMillis = Files.getLastModifiedTime(root, LinkOption.NOFOLLOW_LINKS).toMillis(),
        entries = entries,
    )
}

private data class LeaseJournalSnapshot(
    val modifiedMillis: Long,
    val entries: Map<String, LeaseJournalEntrySnapshot>,
)

private data class LeaseJournalEntrySnapshot(
    val device: Long,
    val inode: Long,
    val mode: Int,
    val linkCount: Int,
    val modifiedMillis: Long,
    val bytes: List<Byte>,
)

private inline fun withFixture(action: (LeaseFixture) -> Unit) {
    val root = createTempDirectory("hosted-toolchain-image-build-lease-v2-")
    Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
    try {
        action(LeaseFixture(root))
    } finally {
        if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
            Files.walk(root).use { paths ->
                paths.sorted(Comparator.reverseOrder()).forEach { path ->
                    if (Files.isDirectory(path, LinkOption.NOFOLLOW_LINKS)) {
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
                    } else if (Files.exists(path, LinkOption.NOFOLLOW_LINKS)) {
                        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
                    }
                    Files.deleteIfExists(path)
                }
            }
        }
    }
}

private val CHECKED_ROOT = Path.of("oracle/llvm/22.1.6")
private val SHA256 = Regex("[0-9a-f]{64}")
private const val REPRODUCTION_LOCK_SHA256 =
    "14a383bc5792b7ace786cbbd8964383469c1ffa5a4bb06a99e38c71518643f4f"
private const val BUILD_RECORD_SHA256 =
    "415afaf3554f954aed4442f0fa3c83ecc7e9f1fe0ddf68fb4c39e9231ece9005"
private const val DOCKERFILE_SHA256 =
    "97e2d13915806242c14489b5a8b1417bd0478f3a11dc05e76888ba2ab43b1291"
private const val DETERMINISTIC_TAR_SHA256 =
    "c47e1f8a2c70576c6aad1af2e68865c3d458da7288ea9ecc21dde4c3e364f20e"
private const val BASE_IMAGE_REFERENCE =
    "ubuntu@sha256:33ceb71981b602c1a7443a53469e4dba065f7503eab3078a2d7a57a2ab987517"
private const val LEASE_LABEL_KEY =
    "dev.decompengine.llvm-behavior-hosted-toolchain-image-build-lease"
private const val CONTENT_LABEL_KEY =
    "dev.decompengine.llvm-behavior-hosted-toolchain-build-context-sha256"

private val EXACT_BUILD_POLICY = JsonObject(
    mapOf(
        "apiVersion" to JsonPrimitive("1.55"),
        "builderVersion" to JsonPrimitive("2"),
        "buildIdQueryParameter" to JsonPrimitive("buildid"),
        "cacheImports" to JsonPrimitive(false),
        "cacheExports" to JsonPrimitive(false),
        "contentType" to JsonPrimitive("application/x-tar"),
        "dockerfile" to JsonPrimitive("Dockerfile"),
        "extraHosts" to JsonPrimitive(false),
        "forceRemoveIntermediateContainers" to JsonPrimitive(true),
        "method" to JsonPrimitive("POST"),
        "networkAccess" to JsonPrimitive("engine-builder-default-required-for-reviewed-apt-and-curl"),
        "networkMode" to JsonPrimitive("default"),
        "noCache" to JsonPrimitive(true),
        "outputsSupplied" to JsonPrimitive(false),
        "platform" to JsonPrimitive("linux/amd64"),
        "pull" to JsonPrimitive(false),
        "quiet" to JsonPrimitive(false),
        "registryAuthentication" to JsonPrimitive(false),
        "remoteContext" to JsonPrimitive(false),
        "removeIntermediateContainers" to JsonPrimitive(true),
        "requestTarget" to JsonPrimitive("/v1.55/build"),
        "requestTransfer" to JsonPrimitive("fixed-content-length-no-transfer-encoding"),
        "secrets" to JsonPrimitive(false),
        "session" to JsonPrimitive(false),
        "ssh" to JsonPrimitive(false),
        "target" to JsonPrimitive(false),
    ),
)

private val BINDING_FIELDS = setOf(
    "acpBoundary",
    "authority",
    "bindingSha256",
    "buildIntentSha256",
    "buildRequestIntent",
    "claims",
    "journalRootPathSha256",
    "leaseNonce",
    "operationId",
    "provider",
    "pythonBoundary",
    "recipe",
    "recoveryLeaseLabel",
    "recoveryTag",
    "requestIntentSha256",
    "schemaVersion",
)

private val REQUEST_INTENT_FIELDS = setOf(
    "buildArguments",
    "buildCancelLocator",
    "buildId",
    "buildIdQuery",
    "contentLength",
    "contentSha256",
    "labels",
    "policy",
    "provider",
    "schemaVersion",
    "tags",
)

private val TRANSITION_FIELDS = setOf(
    "authority",
    "bindingSha256",
    "claims",
    "facts",
    "operationId",
    "phase",
    "previousTransitionSha256",
    "provider",
    "schemaVersion",
    "sequence",
    "transitionSha256",
)
