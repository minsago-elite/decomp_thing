package decompengine.oracle.gcc

import decompengine.acp.LinuxFilesystemSyscalls
import decompengine.oracle.fulltree.KotlinSystemdCgroupBootResources
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.DescriptorBoundStateFaultInjector
import decompengine.oracle.core.DescriptorBoundStateFaultPoint
import decompengine.oracle.fulltree.KotlinSystemdCgroupBootOwner
import decompengine.oracle.fulltree.findObservationCgroupsForUnit
import decompengine.oracle.fulltree.StableControlFile
import decompengine.oracle.fulltree.boundedLiveOracleUnitJournal
import decompengine.oracle.fulltree.liveOracleUnitJournalCommand
import java.io.ByteArrayOutputStream
import java.lang.reflect.InvocationTargetException
import java.lang.reflect.Modifier
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.StandardOpenOption
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import java.time.Instant
import java.util.concurrent.TimeUnit
import java.util.jar.JarFile
import java.util.zip.CRC32
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import kotlin.io.path.createTempDirectory
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import org.junit.jupiter.api.Assumptions.assumeTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive

class GccCompilerEngineLiveContainmentControllerTest {
    @Test
    fun `live journal diagnostics request newest exact-unit events within existing bounds`() {
        val unitName = "decomp-gcc-cc1-${"1".repeat(32)}.scope"
        val sinceEpochSeconds = 1_788_572_160L
        assertEquals(
            listOf(
                "/usr/bin/journalctl", "--user", "--boot", "--no-pager", "--quiet", "--reverse",
                "--output=short-monotonic", "--lines=80", "--since=@$sinceEpochSeconds", "--user-unit=$unitName",
            ),
            liveOracleUnitJournalCommand(unitName, sinceEpochSeconds),
        )
        for (invalidUnit in listOf("", "*.scope", "$unitName\n", "another-$unitName")) {
            assertFailsWith<IllegalArgumentException> { liveOracleUnitJournalCommand(invalidUnit, sinceEpochSeconds) }
        }
    }

    @Test
    fun `BOOT launch file ceiling admits authenticated JNA bootstrap and stays cleanup bounded`() {
        val jnaJar = Path.of(
            com.sun.jna.Native::class.java.protectionDomain.codeSource.location.toURI(),
        )
        val largestBundledNative = JarFile(jnaJar.toFile()).use { jar ->
            jar.entries().asSequence()
                .filter { !it.isDirectory && it.name.substringAfterLast('/').startsWith("libjnidispatch") }
                .maxOf { it.size }
        }
        val resources = KotlinSystemdCgroupBootResources(
            wallClockMillis = 60_000L,
            maximumResidentBytes = 512L * 1024L * 1024L,
            pidsMax = 32L,
        )

        assertTrue(largestBundledNative > 16L * 1024L)
        assertEquals(64L * 1024L * 1024L, resources.maximumRuntimeFileBytes)
        assertTrue(resources.maximumRuntimeFileBytes >= largestBundledNative)
        assertTrue(resources.maximumRuntimeFileBytes < 256L * 1024L * 1024L)
    }

    @Test
    fun `deployment reference admits only its exact ordered JVM closure`() {
        GccKotlinBootClasspathReference.open().use { reference ->
            val exact = reference.entries.map { it.bytes to it.sha256 }
            reference.requireCandidateIdentities(exact)
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                reference.requireCandidateIdentities(exact.dropLast(1))
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                reference.requireCandidateIdentities(exact.reversed())
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                reference.requireCandidateIdentities(
                    exact.toMutableList().also { entries ->
                        entries[0] = entries[0].first to "0".repeat(64)
                    },
                )
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                reference.requireCandidateIdentities(exact + exact.first())
            }
        }
    }

    @Test
    fun `deployment JAR inspection remains descriptor derived without a lexical reopen seam`() {
        val inspectionMethods = GccKotlinBootClasspathReference.Companion::class.java.declaredMethods
            .filter { method ->
                method.name in setOf(
                    "inspectJar",
                    "preflightClassicJar",
                    "requireExactLocalRecords",
                    "inspectStreamingJar",
                    "verifyStreamingJarSignatures",
                )
            }

        assertEquals(5, inspectionMethods.size)
        assertTrue(inspectionMethods.all { Modifier.isPrivate(it.modifiers) })
        assertTrue(inspectionMethods.all { method ->
            method.parameterTypes.firstOrNull() == StableControlFile::class.java &&
                method.parameterTypes.none { parameter ->
                    parameter == Path::class.java ||
                        parameter == java.io.File::class.java ||
                        parameter == JarFile::class.java
                } &&
                method.returnType != Path::class.java &&
                method.returnType != java.io.File::class.java &&
                method.returnType != JarFile::class.java
        })
        assertTrue(
            GccKotlinBootClasspathReference.Companion::class.java.declaredMethods.none { method ->
                method.name in setOf("copyGuardedJar", "inspectPrivateJar", "cleanupPrivateJar")
            },
        )
    }

    @Test
    fun `deployment JAR inspection rejects swapped central local offsets`() = withControllerRoot { root ->
        val keeperBytes = "AAAA".encodeToByteArray()
        val decoyBytes = "BBBB".encodeToByteArray()
        val jarBytes = storedJar(
            listOf(
                TEST_KEEPER_CLASS to keeperBytes,
                TEST_KEEPER_CLASS.replace("Keeper", "Decoyx") to decoyBytes,
            ),
        )
        val path = writeReadOnly(root.resolve("swapped-offsets.jar"), swapFirstTwoCentralOffsets(jarBytes))

        JarFile(path.toFile(), false).use { jar ->
            assertContentEquals(decoyBytes, jar.getInputStream(jar.getJarEntry(TEST_KEEPER_CLASS)).readAllBytes())
        }
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            inspectDeploymentJar(path)
        }
        assertTrue(failure.message.orEmpty().contains("different local name"), failure.message)
    }

    @Test
    fun `deployment JAR inspection rejects signature metadata after payload`() = withControllerRoot { root ->
        val path = writeReadOnly(
            root.resolve("late-signature.jar"),
            storedJar(
                listOf(
                    "META-INF/MANIFEST.MF" to "Manifest-Version: 1.0\r\n\r\n".encodeToByteArray(),
                    TEST_KEEPER_CLASS to "keeper".encodeToByteArray(),
                    "META-INF/TEST.SF" to "ignored-late-signature".encodeToByteArray(),
                ),
            ),
        )

        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            inspectDeploymentJar(path)
        }
        assertTrue(failure.message.orEmpty().contains("signature metadata after payload"), failure.message)
    }

    @Test
    fun `deployment JAR inspection rejects SIG metadata before verifier phase drift`() = withControllerRoot { root ->
        val path = writeReadOnly(
            root.resolve("sig-metadata.jar"),
            storedJar(
                listOf(
                    "META-INF/MANIFEST.MF" to "Manifest-Version: 1.0\r\n\r\n".encodeToByteArray(),
                    "META-INF/SIG-CUSTOM" to "unsupported-signature-metadata".encodeToByteArray(),
                    "META-INF/TEST.SF" to "ignored-signature-file".encodeToByteArray(),
                    TEST_KEEPER_CLASS to "keeper".encodeToByteArray(),
                ),
            ),
        )

        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            inspectDeploymentJar(path)
        }
        assertTrue(failure.message.orEmpty().contains("unsupported SIG metadata"), failure.message)
    }

    @Test
    fun `deployment JAR inspection rejects a runtime versioned BOOT keeper`() = withControllerRoot { root ->
        val baseBytes = "base-keeper".encodeToByteArray()
        val versionedBytes = "versioned!!".encodeToByteArray()
        val path = writeReadOnly(
            root.resolve("versioned-keeper.jar"),
            storedJar(
                listOf(
                    "META-INF/MANIFEST.MF" to
                        "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n".encodeToByteArray(),
                    TEST_KEEPER_CLASS to baseBytes,
                    "META-INF/versions/9/$TEST_KEEPER_CLASS" to versionedBytes,
                ),
            ),
        )

        JarFile(path.toFile(), false, ZipFile.OPEN_READ, Runtime.version()).use { jar ->
            jar.getInputStream(jar.getJarEntry(TEST_KEEPER_CLASS)).use { input ->
                assertContentEquals(versionedBytes, input.readAllBytes())
            }
        }
        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            inspectDeploymentJar(path)
        }
        assertTrue(failure.message.orEmpty().contains("versioned BOOT keeper"), failure.message)
    }

    @Test
    fun `deployment JAR inspection rejects a versioned directory alias for the BOOT keeper`() =
        withControllerRoot { root ->
            val baseBytes = "base-keeper".encodeToByteArray()
            val versionedBytes = "versioned-directory-alias".encodeToByteArray()
            val versionedKeeper = "META-INF/versions/9/$TEST_KEEPER_CLASS/"
            val path = writeReadOnly(
                root.resolve("versioned-keeper-directory-alias.jar"),
                storedJar(
                    listOf(
                        "META-INF/MANIFEST.MF" to
                            "Manifest-Version: 1.0\r\nMulti-Release: true\r\n\r\n".encodeToByteArray(),
                        TEST_KEEPER_CLASS to baseBytes,
                        "META-INF/versions/9/dummy" to "populate-version-map".encodeToByteArray(),
                        versionedKeeper to versionedBytes,
                    ),
                ),
            )

            JarFile(path.toFile(), false, ZipFile.OPEN_READ, Runtime.version()).use { jar ->
                val runtimeEntry = jar.getJarEntry(TEST_KEEPER_CLASS)
                assertEquals(versionedKeeper, runtimeEntry.realName)
                assertTrue(runtimeEntry.isDirectory)
                jar.getInputStream(runtimeEntry).use { input ->
                    assertContentEquals(versionedBytes, input.readAllBytes())
                }
            }
            val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                inspectDeploymentJar(path)
            }
            assertTrue(failure.message.orEmpty().contains("versioned BOOT keeper"), failure.message)
        }

    @Test
    fun `deployment JAR inspection rejects an unversioned directory alias for the BOOT keeper`() =
        withControllerRoot { root ->
            val aliasBytes = "unversioned-directory-alias".encodeToByteArray()
            val keeperAlias = "$TEST_KEEPER_CLASS/"
            val path = writeReadOnly(
                root.resolve("unversioned-keeper-directory-alias.jar"),
                storedJar(listOf(keeperAlias to aliasBytes)),
            )

            JarFile(path.toFile(), false).use { jar ->
                val runtimeEntry = jar.getJarEntry(TEST_KEEPER_CLASS)
                assertEquals(keeperAlias, runtimeEntry.realName)
                assertTrue(runtimeEntry.isDirectory)
                jar.getInputStream(runtimeEntry).use { input ->
                    assertContentEquals(aliasBytes, input.readAllBytes())
                }
            }
            val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                inspectDeploymentJar(path)
            }
            assertTrue(failure.message.orEmpty().contains("BOOT keeper lookup alias"), failure.message)
        }

    @Test
    fun `raw facade rejects resume before launch and leaves no journal`() = withControllerRoot { root ->
        val fixture = createFixture(root, GccCompilerEngineContainmentRunKind.RESUMED)

        val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
            GccCompilerEngineLiveContainmentController.attachAtBoot(fixture.definitionPath)
        }

        assertTrue(failure.message.orEmpty().contains("does not yet authenticate"), failure.message)
        assertEquals(listOf("state"), entryNames(fixture.outputLease))
        assertTrue(findObservationCgroupsForUnit(fixture.assessment.unitName).isEmpty())
    }

    @Test
    fun `raw facade rejects unsupported BOOT budgets before journal creation`() =
        withControllerRoot { root ->
            val fixture = createFixture(
                root,
                budgets = GccCompilerEngineContainmentBudgets(
                    wallClockMillis = 1_001L,
                    maximumResidentBytes = 64L * 1024L * 1024L,
                    pidsMax = 4L,
                ),
            )

            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(fixture.definitionPath)
            }

            assertEquals(listOf("state"), entryNames(fixture.outputLease))
            assertTrue(findObservationCgroupsForUnit(fixture.assessment.unitName).isEmpty())
        }

    @Test
    fun `failed prelaunch runtime probe rolls back its journal and remains retryable`() =
        withControllerRoot { root ->
            val harmlessWrongSupervisor = requireNotNull(Path.of("/usr/bin/true").realExecutableOrNull())
            val fixture = createFixture(
                root,
                liveRuntime = true,
                artifactPathOverrides = mapOf(
                    GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE to
                        harmlessWrongSupervisor,
                ),
            )

            repeat(2) {
                val failure = assertFailsWith<GccCompilerEngineLiveContainmentException> {
                    GccCompilerEngineLiveContainmentController.attachAtBoot(fixture.definitionPath)
                }
                assertFalse(failure.message.orEmpty().contains("journal already exists"))
                assertEquals(listOf("state"), entryNames(fixture.outputLease))
                assertTrue(findObservationCgroupsForUnit(fixture.assessment.unitName).isEmpty())
            }
        }

    @Test
    fun `raw facade rejects unknown classpath fields duplicate paths and output authority`() =
        withControllerRoot { root ->
            val unknown = createFixture(root.resolve("unknown")) { manifest ->
                JsonObject(manifest + ("unexpected" to JsonPrimitive(false)))
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(unknown.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(unknown.outputLease))

            val duplicate = createFixture(root.resolve("duplicate")) { manifest ->
                val entries = manifest.getValue("entries") as JsonArray
                JsonObject(manifest + ("entries" to JsonArray(listOf(entries.single(), entries.single()))))
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(duplicate.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(duplicate.outputLease))

            val escaped = createFixture(root.resolve("output-entry"), classPathInsideOutput = true)
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(escaped.definitionPath)
            }
            assertEquals(listOf("escaped.jar", "state"), entryNames(escaped.outputLease))
        }

    @Test
    fun `raw facade rejects added reordered and substituted deployment closure jars before launch`() =
        withControllerRoot { root ->
            val added = createFixture(root.resolve("added"), liveRuntime = true) { manifest ->
                val entries = manifest.getValue("entries") as JsonArray
                val application = entries.first().jsonObject
                val source = Path.of(application.getValue("path").jsonPrimitive.content)
                val copied = privateDirectory(root.resolve("added-copy")).resolve("copied-keeper.jar")
                Files.copy(source, copied)
                Files.setPosixFilePermissions(copied, PosixFilePermissions.fromString("r--------"))
                val copyEntry = JsonObject(
                    application +
                        ("path" to JsonPrimitive(copied.toString())),
                )
                JsonObject(manifest + ("entries" to JsonArray(listOf(copyEntry) + entries)))
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(added.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(added.outputLease))

            val reordered = createFixture(root.resolve("reordered"), liveRuntime = true) { manifest ->
                val entries = manifest.getValue("entries") as JsonArray
                JsonObject(manifest + ("entries" to JsonArray(entries.reversed())))
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(reordered.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(reordered.outputLease))

            val substituted = createFixture(root.resolve("substituted-closure"), liveRuntime = true) { manifest ->
                val entries = (manifest.getValue("entries") as JsonArray).toMutableList()
                val original = entries[1].jsonObject
                val source = Path.of(original.getValue("path").jsonPrimitive.content)
                val copy = privateDirectory(root.resolve("substituted-copy")).resolve("dependency.jar")
                Files.copy(source, copy)
                FileChannel.open(copy, StandardOpenOption.WRITE).use { channel ->
                    channel.write(ByteBuffer.wrap(byteArrayOf(0x00)), 0L)
                    channel.force(true)
                }
                Files.setPosixFilePermissions(copy, PosixFilePermissions.fromString("r--------"))
                entries[1] = JsonObject(
                    original + mapOf(
                        "path" to JsonPrimitive(copy.toString()),
                        "sha256" to JsonPrimitive(sha256(copy)),
                    ),
                )
                JsonObject(manifest + ("entries" to JsonArray(entries)))
            }
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(substituted.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(substituted.outputLease))
        }

    @Test
    fun `raw facade rejects artifact substitution output residue and non GCC unit bytes`() =
        withControllerRoot { root ->
            val substituted = createFixture(root.resolve("substituted"))
            val engine = substituted.artifacts.single {
                it.role == GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY
            }.path
            Files.setPosixFilePermissions(engine, PosixFilePermissions.fromString("rw-------"))
            Files.write(engine, ByteArray(Files.size(engine).toInt()) { 0x5a })
            Files.setPosixFilePermissions(engine, PosixFilePermissions.fromString("r--------"))
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(substituted.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(substituted.outputLease))

            val residue = createFixture(root.resolve("residue"))
            writeReadOnly(residue.outputLease.resolve("unexpected"), "residue".encodeToByteArray())
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(residue.definitionPath)
            }
            assertEquals(listOf("state", "unexpected"), entryNames(residue.outputLease))

            val foreignUnit = createFixture(root.resolve("foreign-unit"))
            val original = OracleJson.parseCanonical(foreignUnit.definitionBytes).jsonObject
            val unsigned = JsonObject(
                (original - "bindingSha256") +
                    ("unitName" to JsonPrimitive("decomp-other-engine-${"f".repeat(32)}.scope")),
            )
            val mutated = OracleJson.canonicalBytes(
                JsonObject(
                    unsigned + ("bindingSha256" to JsonPrimitive(
                        OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)),
                    )),
                ),
            )
            replaceReadOnly(foreignUnit.definitionPath, mutated)
            assertFailsWith<GccCompilerEngineLiveContainmentException> {
                GccCompilerEngineLiveContainmentController.attachAtBoot(foreignUnit.definitionPath)
            }
            assertEquals(listOf("state"), entryNames(foreignUnit.outputLease))
        }

    @Test
    fun `JVM shape exposes raw path attach and cleanup only with no forgeable owner`() {
        val controllerMethods = GccCompilerEngineLiveContainmentController::class.java.declaredMethods
            .filterNot { it.isSynthetic }
        assertEquals(listOf("attachAtBoot"), controllerMethods.map { it.name }.sorted())
        assertEquals(listOf(Path::class.java), controllerMethods.single().parameterTypes.toList())

        val forbidden = setOf("start", "execute", "export", "publish", "release", "score", "adopt")
        assertTrue(
            GccCompilerEngineLiveAttachedAtBoot::class.java.methods.none {
                it.name.lowercase() in forbidden
            },
        )
        assertTrue(
            GccCompilerEngineLiveAttachedAtBoot::class.java.declaredConstructors.none {
                Modifier.isPublic(it.modifiers) && !it.isSynthetic
            },
        )
        GccCompilerEngineLiveAttachedAtBoot::class.java.declaredConstructors.forEach { constructor ->
            constructor.isAccessible = true
            val failure = assertFailsWith<InvocationTargetException> {
                constructor.newInstance(
                    *arrayOfNulls<Any>(constructor.parameterCount).also { arguments ->
                        arguments[0] = Any()
                    },
                )
            }
            assertTrue(failure.cause is IllegalStateException)
        }
        assertTrue(
            GccCompilerEngineLiveAttachedAtBoot::class.java.methods.none { method ->
                method.parameterTypes.any { it == ByteArray::class.java }
            },
            "the live owner must not accept a caller-selected receipt",
        )

        assertTrue(
            GccCompilerEngineLiveTerminalAbsence::class.java.declaredConstructors.none {
                Modifier.isPublic(it.modifiers) && !it.isSynthetic
            },
        )
        GccCompilerEngineLiveTerminalAbsence::class.java.declaredConstructors.forEach { constructor ->
            constructor.isAccessible = true
            assertFailsWith<InvocationTargetException> {
                constructor.newInstance(
                    *constructor.parameterTypes.map { type ->
                        if (type.name == "kotlin.jvm.internal.DefaultConstructorMarker") null else Any()
                    }.toTypedArray(),
                )
            }
        }
        assertEquals(
            listOf(Any::class.java),
            GccCompilerEngineLiveTerminalAbsence.Companion::class.java.declaredMethods
                .single { it.name.startsWith("fromProvedCleanup") && !it.isSynthetic }
                .parameterTypes.toList(),
        )
        assertFailsWith<IllegalStateException> {
            GccCompilerEngineLiveTerminalAbsence.fromProvedCleanup(Any())
        }
        val rawProofClass = Class.forName("decompengine.oracle.gcc.LiveContainmentTerminalProof")
        val rawProof = rawProofClass.declaredConstructors.single().newInstance(
            "0".repeat(64),
            Path.of("/tmp/forged-terminal-journal"),
            byteArrayOf(1),
            byteArrayOf(2),
        )
        assertFailsWith<IllegalStateException> {
            GccCompilerEngineLiveTerminalAbsence.fromProvedCleanup(rawProof)
        }
    }

    @Test
    fun `descriptor journal separates preattachment and recovers terminal atomic publication`() =
        withControllerRoot { root ->
            val fixture = createFixture(root)
            val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
                fixture.definitionBytes,
            )
            LiveContainmentJournal.create(definition).use { journal ->
                journal.publish("definition.json", fixture.definitionBytes)
                journal.requirePreparedLayout()

                val runDirectory = privateDirectory(
                    fixture.analysisState.resolve(".function-observation-run-${"a".repeat(32)}"),
                )
                journal.requirePreAttachmentLayout()
                val attached = GccCompilerEngineContainmentContract.renderUnitAttachedAtBootReceiptForTesting(
                    fixture.definitionBytes,
                    "12345678-1234-1234-1234-123456789abc",
                    "12345678123412341234123456789abc",
                    listOf(101L, 102L, 103L),
                )
                journal.publish("unit-attached.json", attached)
                journal.requireBootLayout()

                Files.delete(runDirectory)
                val absence = GccCompilerEngineContainmentContract.renderTerminalAbsenceReceiptForTesting(
                    fixture.definitionBytes,
                    attached,
                )
                assertFailsWith<SimulatedTerminalPublicationFailure> {
                    journal.publish(
                        "terminal-absence.json",
                        absence,
                        DescriptorBoundStateFaultInjector { point ->
                            if (point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC) {
                                throw SimulatedTerminalPublicationFailure()
                            }
                        },
                    )
                }
                journal.requireTerminalPublishableLayout()
                assertEquals(
                    listOf(
                        ".terminal-absence.json.atomic",
                        "definition.json",
                        "unit-attached.json",
                    ),
                    entryNames(journal.path),
                )
                journal.publish("terminal-absence.json", absence)
                journal.requireTerminalFinalLayout()
                assertContentEquals(
                    absence,
                    Files.readAllBytes(journal.path.resolve("terminal-absence.json")),
                )
            }
        }

    @Test
    fun `preattachment rollback recovers every durable phase and permits a fresh journal`() =
        withControllerRoot { root ->
            LiveContainmentPreAttachmentRollbackFaultPoint.entries.forEach { point ->
                val fixture = createFixture(root.resolve(point.name.lowercase()))
                val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
                    fixture.definitionBytes,
                )
                val stranded = LiveContainmentJournal.create(definition)
                try {
                    stranded.publish("definition.json", fixture.definitionBytes)
                    assertFailsWith<SimulatedPreAttachmentRollbackFailure> {
                        stranded.rollbackBeforeAttachment(
                            LiveContainmentPreAttachmentRollbackFaultInjector { observed ->
                                if (observed == point) throw SimulatedPreAttachmentRollbackFailure()
                            },
                        )
                    }
                } finally {
                    stranded.close()
                }

                LiveContainmentJournal.create(definition).use { fresh ->
                    assertEquals(emptyList(), entryNames(fresh.path))
                    fresh.publish("definition.json", fixture.definitionBytes)
                    fresh.rollbackBeforeAttachment()
                }
                assertEquals(listOf("state"), entryNames(fixture.outputLease))
            }
        }

    @Test
    fun `preattachment recovery accepts an exact definition temporary and preserves unknown residue`() =
        withControllerRoot { root ->
            val fixture = createFixture(root)
            val definition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
                fixture.definitionBytes,
            )
            val interrupted = LiveContainmentJournal.create(definition)
            try {
                assertFailsWith<SimulatedTerminalPublicationFailure> {
                    interrupted.publish(
                        "definition.json",
                        fixture.definitionBytes,
                        DescriptorBoundStateFaultInjector { point ->
                            if (point == DescriptorBoundStateFaultPoint.AFTER_TEMPORARY_DIRECTORY_SYNC) {
                                throw SimulatedTerminalPublicationFailure()
                            }
                        },
                    )
                }
                assertEquals(listOf(".definition.json.atomic"), entryNames(interrupted.path))
            } finally {
                interrupted.close()
            }

            LiveContainmentJournal.create(definition).use { fresh ->
                fresh.publish("definition.json", fixture.definitionBytes)
                val unknown = writeReadOnly(
                    fresh.path.resolve("unknown-residue"),
                    "preserve".encodeToByteArray(),
                )
                assertFailsWith<GccCompilerEngineLiveContainmentException> {
                    fresh.rollbackBeforeAttachment()
                }
                assertEquals(
                    listOf("definition.json", "unknown-residue"),
                    entryNames(fresh.path),
                )
                Files.delete(unknown)
                fresh.rollbackBeforeAttachment()
            }
            assertEquals(listOf("state"), entryNames(fixture.outputLease))
        }

    @Test
    fun `long live lifecycle fixture authenticates its explicit budget without changing the default`() =
        withControllerRoot { root ->
            val defaultFixture = createFixture(root.resolve("default"))
            val liveFixture = createFixture(root.resolve("long-live"), budgets = longLiveLifecycleBudgets())
            val defaultDefinition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
                defaultFixture.definitionBytes,
            )
            val liveDefinition = GccCompilerEngineContainmentContract.parseDefinitionForLiveController(
                liveFixture.definitionBytes,
            )

            assertEquals(60_000L, defaultDefinition.budgets.wallClockMillis)
            assertEquals(longLiveLifecycleBudgets(), liveDefinition.budgets)
            assertEquals(300_000L, liveDefinition.budgets.wallClockMillis)
            assertEquals(defaultDefinition.budgets.maximumResidentBytes, liveDefinition.budgets.maximumResidentBytes)
            assertEquals(defaultDefinition.budgets.pidsMax, liveDefinition.budgets.pidsMax)
        }

    @Test
    fun `live facade retains BOOT rejects mismatched receipt and durably proves absence`() =
        withControllerRoot(useBuildFilesystem = true) { root ->
            assumeLiveBoundary()
            val fixture = createFixture(root, liveRuntime = true, budgets = longLiveLifecycleBudgets())
            val startedNanos = System.nanoTime()
            val sinceEpochSeconds = Instant.now().epochSecond
            val timings = mutableListOf<String>()
            fun recordTiming(stage: String) {
                timings += "$stage=${TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - startedNanos)}ms"
            }
            var retainedOwner: GccCompilerEngineLiveAttachedAtBoot? = null
            var primaryFailure: Throwable? = null
            try {
                recordTiming("before attach")
                val owner = GccCompilerEngineLiveContainmentController.attachAtBoot(fixture.definitionPath)
                retainedOwner = owner
                recordTiming("after attach")
                assertEquals("kotlin-live-systemd-cgroup-boot-owner-v1", owner.authority)
                assertFalse(owner.complete)
                assertFalse(owner.releaseEligible)
                assertFalse(owner.startAuthorized)
                assertEquals(fixture.assessment.bindingSha256, owner.bindingSha256)
                assertEquals(
                    listOf("definition.json", "unit-attached.json"),
                    entryNames(owner.journalDirectory),
                )
                assertFalse(Files.exists(owner.journalDirectory.resolve("terminal-absence.json")))

                // Regression for the closed-stdin bug: the keeper must still be live well after
                // systemd-run has returned and the parent has closed the process stdin stream.
                Thread.sleep(500L)
                recordTiming("before first BOOT revalidation")
                owner.requireCurrentAtBoot()
                recordTiming("after first BOOT revalidation")
                assertEquals(1, entryNames(fixture.analysisState).size)
                assertFalse(findObservationCgroupsForUnit(owner.unitName).isEmpty())

                val mismatched = mutateAndRehashInvocation(owner.unitAttachedReceiptBytes)
                val genericOwner = retainedGenericOwner(owner)
                assertEquals(
                    KotlinSystemdCgroupBootResources(
                        wallClockMillis = 300_000L,
                        maximumResidentBytes = 512L * 1024L * 1024L,
                        pidsMax = 32L,
                    ),
                    genericOwner.receipt.resources,
                )
                GccKotlinBootClasspathReference.open().use { reference ->
                    assertEquals(reference.closureSha256, genericOwner.receipt.deploymentClosureSha256)
                }
                assertFailsWith<GccCompilerEngineContainmentContractException> {
                    GccCompilerEngineContainmentContract.prepareLiveOwnerTerminalAbsenceReceipt(
                        fixture.definitionBytes,
                        mismatched,
                        genericOwner,
                        genericOwner.receipt.deploymentClosureSha256,
                    )
                }
                recordTiming("before second BOOT revalidation")
                owner.requireCurrentAtBoot()
                recordTiming("after second BOOT revalidation")

                // Losing the BOOT state must not revoke cleanup authority. Kill the exact
                // descriptor-pinned keeper, prove liveness revalidation now fails, and continue
                // through the retained-owner terminal path below.
                val retainedHandles = genericOwner.receipt.processes.associate { process ->
                    process.role to LinuxFilesystemSyscalls.openProcessHandle(process.pid)
                }
                try {
                    val keeper = retainedHandles.getValue("kotlin-boot-keeper")
                    LinuxFilesystemSyscalls.killProcess(keeper)
                    val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(2L)
                    while (
                        LinuxFilesystemSyscalls.processExists(keeper) &&
                        System.nanoTime() < deadline
                    ) Thread.sleep(20L)
                    assertFalse(LinuxFilesystemSyscalls.processExists(keeper))
                    assertFailsWith<IllegalArgumentException> { owner.requireCurrentAtBoot() }

                    // Exercise the already-absent branch: terminate every exact retained pidfd and
                    // wait for CollectMode to remove both the unit and cgroup before cleanup begins.
                    retainedHandles.values.forEach(LinuxFilesystemSyscalls::killProcess)
                    val absenceDeadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(10L)
                    while (
                        (
                            retainedHandles.values.any(LinuxFilesystemSyscalls::processExists) ||
                                findObservationCgroupsForUnit(owner.unitName).isNotEmpty() ||
                                unitLoadState(owner.unitName) != "not-found"
                            ) && System.nanoTime() < absenceDeadline
                    ) Thread.sleep(25L)
                    assertTrue(retainedHandles.values.none(LinuxFilesystemSyscalls::processExists))
                    assertTrue(findObservationCgroupsForUnit(owner.unitName).isEmpty())
                    assertEquals("not-found", unitLoadState(owner.unitName))
                } finally {
                    retainedHandles.values.forEach { it.close() }
                }

                // Terminal authority must not be returned or published beside a replaced durable
                // attachment, even though cleanup itself remains reachable and proves absence.
                val attachedPath = owner.journalDirectory.resolve("unit-attached.json")
                replaceReadOnly(attachedPath, mutateAndRehashInvocation(owner.unitAttachedReceiptBytes))
                assertFailsWith<GccCompilerEngineLiveContainmentException> {
                    owner.closeAndProveAbsent()
                }
                assertTrue(findObservationCgroupsForUnit(owner.unitName).isEmpty())
                assertFalse(Files.exists(owner.journalDirectory.resolve("terminal-absence.json")))
                Files.delete(attachedPath)
                writeReadOnly(attachedPath, owner.unitAttachedReceiptBytes)

                // A same-UID peer can ignore advisory locks. Force publication validation to fail
                // after genuine cleanup, then remove the hostile member and prove that retry uses
                // the retained terminal bytes instead of asking a terminal owner to re-enter BOOT.
                val hostileResidue = writeReadOnly(
                    fixture.outputLease.resolve("same-uid-hostile-residue"),
                    "retain".encodeToByteArray(),
                )
                assertFailsWith<GccCompilerEngineLiveContainmentException> {
                    owner.closeAndProveAbsent()
                }
                assertTrue(findObservationCgroupsForUnit(owner.unitName).isEmpty())
                assertFalse(Files.exists(owner.journalDirectory.resolve("terminal-absence.json")))
                Files.delete(hostileResidue)

                val terminal = owner.closeAndProveAbsent()
                assertEquals("kotlin-proved-systemd-cgroup-terminal-absence-v1", terminal.authority)
                assertFalse(terminal.complete)
                assertFalse(terminal.releaseEligible)
                assertFalse(terminal.startAuthorized)
                assertEquals(
                    listOf("definition.json", "terminal-absence.json", "unit-attached.json"),
                    entryNames(owner.journalDirectory),
                )
                assertTrue(entryNames(fixture.analysisState).isEmpty())
                assertTrue(findObservationCgroupsForUnit(owner.unitName).isEmpty())
                assertContentEquals(
                    terminal.terminalAbsenceReceiptBytes,
                    Files.readAllBytes(owner.journalDirectory.resolve("terminal-absence.json")),
                )
                GccCompilerEngineContainmentContract.assessTerminalAbsence(
                    fixture.definitionBytes,
                    terminal.unitAttachedReceiptBytes,
                    terminal.terminalAbsenceReceiptBytes,
                )
                val cleanupPolicy = OracleJson.parseCanonical(terminal.terminalAbsenceReceiptBytes)
                    .jsonObject.getValue("cleanupPolicy").jsonObject
                assertEquals(
                    "sigkill-all-if-exact-retained-target-present",
                    cleanupPolicy.getValue("systemdMutation").jsonPrimitive.content,
                )
                assertFailsWith<IllegalStateException> { owner.requireCurrentAtBoot() }
                Unit
            } catch (failure: Throwable) {
                primaryFailure = failure
                recordTiming("failure before retained-owner cleanup")
                val journal = runCatching {
                    boundedLiveOracleUnitJournal(fixture.assessment.unitName, sinceEpochSeconds)
                }.fold(
                    onSuccess = { it },
                    onFailure = { "journal snapshot unavailable: ${it.javaClass.name}: ${it.message.orEmpty().take(512)}" },
                )
                failure.addSuppressed(
                    AssertionError(
                        "GCC live BOOT diagnostics for ${fixture.assessment.unitName}: " +
                            timings.joinToString(", ") + "\n$journal",
                    ),
                )
                throw failure
            } finally {
                try {
                    retainedOwner?.close()
                } catch (cleanupFailure: Throwable) {
                    val primary = primaryFailure
                    if (primary == null) throw cleanupFailure
                    if (cleanupFailure !== primary) primary.addSuppressed(cleanupFailure)
                }
            }
        }

    private data class Fixture(
        val definitionPath: Path,
        val definitionBytes: ByteArray,
        val outputLease: Path,
        val analysisState: Path,
        val artifacts: List<GccCompilerEngineContainmentArtifactIdentity>,
        val assessment: GccCompilerEngineContainmentDefinitionAssessment,
    )

    private class SimulatedTerminalPublicationFailure : RuntimeException()

    private class SimulatedPreAttachmentRollbackFailure : RuntimeException()

    private fun longLiveLifecycleBudgets() = GccCompilerEngineContainmentBudgets(
        wallClockMillis = 300_000L,
        maximumResidentBytes = 512L * 1024L * 1024L,
        pidsMax = 32L,
    )

    private fun createFixture(
        root: Path,
        runKind: GccCompilerEngineContainmentRunKind = GccCompilerEngineContainmentRunKind.INTERRUPTED,
        liveRuntime: Boolean = false,
        classPathInsideOutput: Boolean = false,
        artifactPathOverrides: Map<GccCompilerEngineContainmentArtifactRole, Path> = emptyMap(),
        budgets: GccCompilerEngineContainmentBudgets = GccCompilerEngineContainmentBudgets(
            wallClockMillis = 60_000L,
            maximumResidentBytes = 512L * 1024L * 1024L,
            pidsMax = 32L,
        ),
        manifestTransform: (JsonObject) -> JsonObject = { it },
    ): Fixture {
        Files.createDirectories(root)
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        val inputs = privateDirectory(root.resolve("inputs"))
        val output = privateDirectory(root.resolve("output"))
        val state = privateDirectory(output.resolve("state"))
        val classPathFiles = if (liveRuntime) {
            deploymentRuntimeClassPath()
        } else {
            listOf(
                writeReadOnly(
                    if (classPathInsideOutput) output.resolve("escaped.jar") else inputs.resolve("fixture.jar"),
                    "not-launched".encodeToByteArray(),
                ),
            )
        }
        val manifestObject = JsonObject(
            linkedMapOf(
                "schemaVersion" to JsonPrimitive(1),
                "provider" to JsonPrimitive("gcc-kotlin-boot-classpath-manifest-v1"),
                "entries" to JsonArray(classPathFiles.map { path ->
                    JsonObject(
                        mapOf(
                            "path" to JsonPrimitive(path.toString()),
                            "bytes" to JsonPrimitive(Files.size(path)),
                            "sha256" to JsonPrimitive(sha256(path)),
                        ),
                    )
                }),
            ),
        ).let(manifestTransform)
        val manifest = writeReadOnly(
            inputs.resolve("boot-classpath.json"),
            OracleJson.canonicalBytes(manifestObject),
        )
        val liveExecutables = if (liveRuntime) liveExecutables() else emptyMap()
        val artifacts = GCC_LEGACY_CONTAINMENT_ARTIFACT_ROLES.mapIndexed { index, role ->
            val path = artifactPathOverrides[role] ?: when (role) {
                GccCompilerEngineContainmentArtifactRole.BOOT_KEEPER_CLASSPATH -> manifest
                else -> liveExecutables[role] ?: writeReadOnly(
                    inputs.resolve("${index.toString().padStart(2, '0')}-${role.wireName}.bin"),
                    "fixture-${role.wireName}\n".encodeToByteArray(),
                )
            }
            GccCompilerEngineContainmentArtifactIdentity(role, path, Files.size(path), sha256(path))
        }
        val outputIdentity = LinuxFilesystemSyscalls.openRoot(output).use { descriptor ->
            val identity = descriptor.identity
            val capacity = LinuxFilesystemSyscalls.filesystemCapacity(descriptor)
            GccCompilerEngineOutputLeaseIdentity(
                path = output,
                device = identity.key.device,
                inode = identity.key.inode,
                mountId = identity.mountId,
                uid = identity.uid,
                gid = identity.gid,
                permissions = identity.mode and 0xfff,
                requiredAvailableBytes = minOf(capacity.availableBytes, 1024L * 1024L),
                maximumFilesystemBytes = capacity.totalBytes,
                requiredAvailableInodes = 128L,
                // XFS/VDO can grow f_files while the authenticated runtime is
                // materialized, so the live fixture must not pin a transient
                // pre-launch total. Production still enforces the declared
                // ceiling against every observation.
                maximumFilesystemInodes = Long.MAX_VALUE,
            )
        }
        val stateIdentity = if (runKind == GccCompilerEngineContainmentRunKind.RESUMED) {
            GccCompilerEngineAnalysisStateIdentity(
                GccCompilerEngineAnalysisStateMode.RESUME_MANIFEST,
                state,
                "a".repeat(64),
                1L,
                1L,
            )
        } else {
            GccCompilerEngineAnalysisStateIdentity(
                GccCompilerEngineAnalysisStateMode.FRESH_EMPTY,
                state,
                null,
                0L,
                0L,
            )
        }
        val byRole = artifacts.associateBy(GccCompilerEngineContainmentArtifactIdentity::role)
        val request = GccCompilerEngineContainmentRequest(
            engineId = "cc1",
            runKind = runKind,
            artifacts = artifacts,
            analysisState = stateIdentity,
            command = listOf(
                byRole.getValue(
                    GccCompilerEngineContainmentArtifactRole.GHIDRA_ANALYZE_HEADLESS,
                ).path.toString(),
                state.toString(),
                "-import",
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY).path.toString(),
                "-scriptPath",
                byRole.getValue(GccCompilerEngineContainmentArtifactRole.EXPORTER_CLASSFILE).path.toString(),
                output.toString(),
            ),
            environment = mapOf("LANG" to "C.UTF-8", "LC_ALL" to "C.UTF-8", "TZ" to "UTC"),
            outputLease = outputIdentity,
            budgets = budgets,
        )
        val assessment = GccCompilerEngineContainmentContract.assessDefinition(request)
        val bytes = assessment.canonicalBytes
        val definitionPath = writeReadOnly(root.resolve("definition.json"), bytes)
        return Fixture(definitionPath, bytes, output, state, artifacts, assessment)
    }

    private fun liveExecutables(): Map<GccCompilerEngineContainmentArtifactRole, Path> = mapOf(
        GccCompilerEngineContainmentArtifactRole.JAVA_EXECUTABLE to
            requireNotNull(Path.of(System.getProperty("java.home"), "bin", "java").realExecutableOrNull()),
        GccCompilerEngineContainmentArtifactRole.BUBBLEWRAP_EXECUTABLE to
            requireNotNull(Path.of("/usr/bin/bwrap").realExecutableOrNull()),
        GccCompilerEngineContainmentArtifactRole.RESOURCE_LIMITER_EXECUTABLE to
            requireNotNull(Path.of("/usr/bin/prlimit").realExecutableOrNull()),
        GccCompilerEngineContainmentArtifactRole.SYSTEMD_RUN_EXECUTABLE to
            requireNotNull(Path.of("/usr/bin/systemd-run").realExecutableOrNull()),
        GccCompilerEngineContainmentArtifactRole.SYSTEMCTL_EXECUTABLE to
            requireNotNull(Path.of("/usr/bin/systemctl").realExecutableOrNull()),
        GccCompilerEngineContainmentArtifactRole.SYSTEMD_BUSCTL_EXECUTABLE to
            requireNotNull(Path.of("/usr/bin/busctl").realExecutableOrNull()),
    )

    private fun deploymentRuntimeClassPath(): List<Path> {
        val root = Path.of(
            checkNotNull(System.getProperty("decompengine.oracle.gcc.bootKeeperClasspathRoot")),
        ).toAbsolutePath().normalize().toRealPath()
        return GccKotlinBootClasspathReference.open().use { reference ->
            reference.entries.map { entry -> root.resolve(entry.logicalName).toRealPath() }
        }
    }

    private fun retainedGenericOwner(
        owner: GccCompilerEngineLiveAttachedAtBoot,
    ): KotlinSystemdCgroupBootOwner {
        val ownershipField = owner.javaClass.getDeclaredField("ownership").also { it.isAccessible = true }
        val ownership = assertNotNull(ownershipField.get(owner))
        val bootOwnerField = ownership.javaClass.getDeclaredField("bootOwner").also { it.isAccessible = true }
        return bootOwnerField.get(ownership) as KotlinSystemdCgroupBootOwner
    }

    private fun mutateAndRehashInvocation(bytes: ByteArray): ByteArray {
        val root = OracleJson.parseCanonical(bytes).jsonObject
        val unsigned = JsonObject(
            (root - "receiptSha256") +
                ("invocationId" to JsonPrimitive(
                    if (root.getValue("invocationId").jsonPrimitive.content == "1".repeat(32)) {
                        "2".repeat(32)
                    } else {
                        "1".repeat(32)
                    },
                )),
        )
        return OracleJson.canonicalBytes(
            JsonObject(
                unsigned + ("receiptSha256" to JsonPrimitive(
                    OracleArtifacts.sha256(OracleJson.canonicalBytes(unsigned)),
                )),
            ),
        )
    }

    private fun assumeLiveBoundary() {
        assumeTrue(System.getProperty("os.name") == "Linux", "Linux systemd/cgroup boundary is unavailable")
        liveExecutables()
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val runtime = Path.of("/run/user/$uid")
        assumeTrue(
            Files.isDirectory(runtime, LinkOption.NOFOLLOW_LINKS) && Files.exists(runtime.resolve("bus")),
            "user-systemd bus is unavailable",
        )
        val systemctl = Path.of("/usr/bin/systemctl").realExecutableOrNull()
        assumeTrue(systemctl != null, "systemctl is unavailable")
        val probe = ProcessBuilder(
            checkNotNull(systemctl).toString(),
            "--user",
            "show",
            "--property=Version",
            "--value",
        ).redirectErrorStream(true).also { builder ->
            builder.environment().clear()
            builder.environment()["XDG_RUNTIME_DIR"] = runtime.toString()
            builder.environment()["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=${runtime.resolve("bus")}"
        }.start()
        val exited = probe.waitFor(3L, TimeUnit.SECONDS)
        if (!exited) {
            probe.destroyForcibly()
            probe.waitFor(1L, TimeUnit.SECONDS)
        }
        assumeTrue(exited && probe.exitValue() == 0, "user-systemd manager is unavailable")
    }

    private fun unitLoadState(unitName: String): String {
        val uid = (Files.getAttribute(Path.of("/proc/self"), "unix:uid") as Number).toInt()
        val runtime = Path.of("/run/user/$uid")
        val process = ProcessBuilder(
            "/usr/bin/systemctl",
            "--user",
            "show",
            "--property=LoadState",
            "--value",
            unitName,
        ).redirectErrorStream(true).also { builder ->
            builder.environment().clear()
            builder.environment()["XDG_RUNTIME_DIR"] = runtime.toString()
            builder.environment()["DBUS_SESSION_BUS_ADDRESS"] = "unix:path=${runtime.resolve("bus")}"
        }.start()
        if (!process.waitFor(2L, TimeUnit.SECONDS)) {
            process.destroyForcibly()
            process.waitFor(1L, TimeUnit.SECONDS)
            return "timed-out"
        }
        return process.inputStream.bufferedReader().use { it.readText() }.trim()
    }

    private fun Path.realExecutableOrNull(): Path? = runCatching { toRealPath() }.getOrNull()
        ?.takeIf { Files.isRegularFile(it, LinkOption.NOFOLLOW_LINKS) && Files.isExecutable(it) }

    private fun privateDirectory(path: Path): Path {
        Files.createDirectories(path)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
        return path.toAbsolutePath().normalize()
    }

    private fun writeReadOnly(path: Path, bytes: ByteArray): Path {
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
        return path.toAbsolutePath().normalize()
    }

    private fun inspectDeploymentJar(path: Path): Int = StableControlFile.open(
        path,
        16L * 1024L * 1024L,
        "test GCC deployment JAR",
    ).use { guard ->
        val method = GccKotlinBootClasspathReference.Companion::class.java.getDeclaredMethod(
            "inspectJar",
            StableControlFile::class.java,
            Int::class.javaPrimitiveType,
        ).also { it.isAccessible = true }
        try {
            method.invoke(GccKotlinBootClasspathReference.Companion, guard, 0) as Int
        } catch (failure: InvocationTargetException) {
            throw failure.targetException
        }
    }

    private fun storedJar(entries: List<Pair<String, ByteArray>>): ByteArray {
        val output = ByteArrayOutputStream()
        ZipOutputStream(output).use { zip ->
            entries.forEach { (name, bytes) ->
                val crc = CRC32().also { it.update(bytes) }.value
                val entry = ZipEntry(name).also {
                    it.method = ZipEntry.STORED
                    it.size = bytes.size.toLong()
                    it.compressedSize = bytes.size.toLong()
                    it.crc = crc
                }
                zip.putNextEntry(entry)
                zip.write(bytes)
                zip.closeEntry()
            }
        }
        return output.toByteArray()
    }

    private fun swapFirstTwoCentralOffsets(source: ByteArray): ByteArray {
        val bytes = source.copyOf()
        var endOffset = bytes.size - TEST_ZIP_END_BYTES
        while (endOffset >= 0 && testLittleEndianInt(bytes, endOffset) != TEST_ZIP_END_SIGNATURE) {
            endOffset -= 1
        }
        check(endOffset >= 0)
        val entries = testLittleEndianUnsignedShort(bytes, endOffset + 10)
        check(entries == 2)
        var cursor = testLittleEndianInt(bytes, endOffset + 16)
        val records = ArrayList<Int>(entries)
        repeat(entries) {
            check(testLittleEndianInt(bytes, cursor) == TEST_ZIP_CENTRAL_SIGNATURE)
            records += cursor
            cursor += TEST_ZIP_CENTRAL_HEADER_BYTES +
                testLittleEndianUnsignedShort(bytes, cursor + 28) +
                testLittleEndianUnsignedShort(bytes, cursor + 30) +
                testLittleEndianUnsignedShort(bytes, cursor + 32)
        }
        val firstOffset = testLittleEndianInt(bytes, records[0] + 42)
        val secondOffset = testLittleEndianInt(bytes, records[1] + 42)
        putTestLittleEndianInt(bytes, records[0] + 42, secondOffset)
        putTestLittleEndianInt(bytes, records[1] + 42, firstOffset)
        return bytes
    }

    private fun testLittleEndianUnsignedShort(bytes: ByteArray, offset: Int): Int =
        (bytes[offset].toInt() and 0xff) or ((bytes[offset + 1].toInt() and 0xff) shl 8)

    private fun testLittleEndianInt(bytes: ByteArray, offset: Int): Int =
        testLittleEndianUnsignedShort(bytes, offset) or
            (testLittleEndianUnsignedShort(bytes, offset + 2) shl 16)

    private fun putTestLittleEndianInt(bytes: ByteArray, offset: Int, value: Int) {
        repeat(Integer.BYTES) { byte ->
            bytes[offset + byte] = (value ushr (byte * Byte.SIZE_BITS)).toByte()
        }
    }

    private fun replaceReadOnly(path: Path, bytes: ByteArray) {
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rw-------"))
        Files.write(path, bytes)
        Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("r--------"))
    }

    private fun sha256(path: Path): String {
        val digest = MessageDigest.getInstance("SHA-256")
        FileChannel.open(path, StandardOpenOption.READ).use { channel ->
            val buffer = ByteBuffer.allocate(1024 * 1024)
            while (true) {
                buffer.clear()
                val read = channel.read(buffer)
                if (read < 0) break
                if (read == 0) continue
                digest.update(buffer.array(), 0, read)
            }
        }
        return digest.digest().joinToString("") { byte -> "%02x".format(byte) }
    }

    private fun entryNames(path: Path): List<String> = Files.list(path).use { entries ->
        entries.map { it.fileName.toString() }.sorted().toList()
    }

    private inline fun <T> withControllerRoot(
        useBuildFilesystem: Boolean = false,
        action: (Path) -> T,
    ): T {
        val root = if (useBuildFilesystem) {
            val parent = Path.of(System.getProperty("user.dir"), "build", "tmp")
                .toAbsolutePath().normalize()
            Files.createDirectories(parent)
            assumeTrue(
                Files.getFileStore(parent).type().lowercase() !in setOf("tmpfs", "ramfs", "hugetlbfs"),
                "a disk-backed test filesystem is unavailable",
            )
            createTempDirectory(parent, "gcc-live-containment-test-")
        } else {
            createTempDirectory("gcc-live-containment-test-")
        }
        Files.setPosixFilePermissions(root, PosixFilePermissions.fromString("rwx------"))
        return try {
            action(root.toAbsolutePath().normalize())
        } finally {
            if (Files.exists(root, LinkOption.NOFOLLOW_LINKS)) {
                val paths = Files.walk(root).use { it.toList() }
                paths.filter { Files.isDirectory(it, LinkOption.NOFOLLOW_LINKS) }.forEach { directory ->
                    Files.setPosixFilePermissions(directory, PosixFilePermissions.fromString("rwx------"))
                }
                paths.sortedWith(Comparator.reverseOrder()).forEach(Files::deleteIfExists)
            }
        }
    }
}

private const val TEST_KEEPER_CLASS =
    "decompengine/oracle/fulltree/KotlinSystemdCgroupBootKeeper.class"
private const val TEST_ZIP_CENTRAL_HEADER_BYTES = 46
private const val TEST_ZIP_CENTRAL_SIGNATURE = 0x02014b50
private const val TEST_ZIP_END_BYTES = 22
private const val TEST_ZIP_END_SIGNATURE = 0x06054b50
