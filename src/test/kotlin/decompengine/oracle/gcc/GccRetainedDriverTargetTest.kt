package decompengine.oracle.gcc

import com.sun.jna.Library
import com.sun.jna.Native
import com.sun.jna.Platform
import decompengine.oracle.core.OracleArtifacts
import decompengine.oracle.core.OracleJson
import decompengine.project.RecoveredFunction
import decompengine.project.RecoveredProgramModel
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFails
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.int
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long

class GccRetainedDriverTargetTest {
    @Test
    fun `legacy and explicit compiler engines retain exactly the existing planner policy`() = withControls { root ->
        val path = root.resolve("compiler-engines.json")
        GccRetainedCompilerEngineProfile.open(path).use { legacy ->
            val suite = legacy.suite
            val reconstruction = suite.reconstructionProfile()
            val expected = OracleJson.canonicalBytes(JsonObject(mapOf(
                "provider" to JsonPrimitive("gcc-retained-planner-profile-v1"),
                "schemaVersion" to JsonPrimitive(1),
                "profileSha256" to JsonPrimitive(PROFILE_SHA256),
                "plannerId" to JsonPrimitive(suite.analysis.plannerId),
                "plannerVersion" to JsonPrimitive(suite.analysis.plannerVersion),
                "reconstructionProfileSha256" to JsonPrimitive(reconstruction.sha256),
                "reconstructionProfile" to OracleJson.parse(reconstruction.canonicalJson().toByteArray()),
                "inputs" to JsonArray(CONTROLS.filter { it != "oracle-manifest.json" }.sorted().map { name ->
                    val input = root.resolve(name)
                    JsonObject(mapOf("path" to JsonPrimitive(input.toString()),
                        "bytes" to JsonPrimitive(Files.size(input)), "sha256" to JsonPrimitive(sha256(input))))
                }),
            )))
            assertContentEquals(expected, legacy.policyBytes())
            assertEquals(listOf("cc1", "lto1"), suite.engines.map { it.id })
            assertFails { suite.engine("driver") }
            assertFails { legacy.target("driver") }
            assertFails { legacy.exportWallClockMillis("driver", true) }
            for (id in listOf("cc1", "lto1")) {
                GccRetainedCompilerEngineProfile.open(path, id).use { explicit ->
                    assertContentEquals(expected, explicit.policyBytes(), id)
                    val engine = suite.engine(id)
                    val target = explicit.target(id)
                    assertEquals(id, target.id)
                    assertEquals("gcc-$id-16.2.0", target.profileId)
                    assertEquals(engine.buildOutput, target.buildOutput)
                    assertEquals(engine.buildRecordPath, target.buildRecordPath)
                    assertEquals(engine.buildRecordSha256, target.buildRecordSha256)
                    assertEquals(engine.oracleManifestPath, target.oracleManifestPath)
                    assertEquals(engine.oracleManifestSha256, target.oracleManifestSha256)
                    assertEquals(engine.fullArtifact, target.fullArtifact)
                    assertEquals(engine.strippedArtifact, target.strippedArtifact)
                }
            }
        }
    }

    @Test
    fun `driver target binds the checked driver control plane and both binary identities`() = withControls { root ->
        val path = root.resolve("compiler-engines.json")
        GccRetainedCompilerEngineProfile.open(path, "driver").use { retained ->
            val target = retained.target("driver")
            assertEquals("driver", target.id)
            assertEquals("gcc-driver-16.2.0", target.profileId)
            assertEquals("/oracle/install/bin/gcc", target.buildOutput)
            assertEquals(root.resolve("build-record.json"), target.buildRecordPath)
            assertEquals(BUILD_SHA256, target.buildRecordSha256)
            assertEquals(root.resolve("oracle-manifest.json"), target.oracleManifestPath)
            assertEquals(MANIFEST_SHA256, target.oracleManifestSha256)
            assertEquals(GccCompilerEngineArtifactBinding("artifacts/gcc-driver.full", 20_713_760L, FULL_SHA256), target.fullArtifact)
            assertEquals(GccCompilerEngineArtifactBinding("artifacts/gcc-driver.stripped", 2_349_296L, STRIPPED_SHA256), target.strippedArtifact)
            assertEquals(PROFILE_SHA256, retained.suite.profileSha256)
            assertEquals(listOf("cc1", "lto1"), retained.suite.engines.map { it.id })
            assertFails { retained.suite.engine("driver") }

            val policy = OracleJson.parseCanonical(retained.policyBytes()).jsonObject
            assertEquals("gcc-retained-export-target-profile-v1", policy.getValue("provider").jsonPrimitive.content)
            assertEquals(1, policy.getValue("schemaVersion").jsonPrimitive.int)
            assertEquals(PROFILE_SHA256, policy.getValue("profileSha256").jsonPrimitive.content)
            val expectedTarget = JsonObject(mapOf(
                "id" to JsonPrimitive("driver"),
                "profileId" to JsonPrimitive("gcc-driver-16.2.0"),
                "buildOutput" to JsonPrimitive("/oracle/install/bin/gcc"),
                "buildRecordSha256" to JsonPrimitive(BUILD_SHA256),
                "oracleManifestSha256" to JsonPrimitive(MANIFEST_SHA256),
                "fullArtifact" to artifactDocument("artifacts/gcc-driver.full", 20_713_760L, FULL_SHA256),
                "strippedArtifact" to artifactDocument("artifacts/gcc-driver.stripped", 2_349_296L, STRIPPED_SHA256),
            ))
            assertEquals(expectedTarget, policy.getValue("target"))
            val inputs = policy.getValue("inputs").jsonArray.map { it.jsonObject }
            assertEquals(CONTROLS.map { root.resolve(it).toString() }.sorted(),
                inputs.map { it.getValue("path").jsonPrimitive.content })
            inputs.forEach { input ->
                val control = Path.of(input.getValue("path").jsonPrimitive.content)
                assertEquals(Files.size(control), input.getValue("bytes").jsonPrimitive.long)
                assertEquals(sha256(control), input.getValue("sha256").jsonPrimitive.content)
            }
            GccRetainedCompilerEngineProfile.open(path).use { legacy ->
                val legacyPolicy = OracleJson.parseCanonical(legacy.policyBytes()).jsonObject
                for (field in listOf("plannerId", "plannerVersion", "reconstructionProfileSha256", "reconstructionProfile")) {
                    assertEquals(legacyPolicy.getValue(field), policy.getValue(field), field)
                }
                assertNotEquals(legacyPolicy, policy)
            }
            val alteredCopy = retained.policyBytes()
            alteredCopy[0] = (alteredCopy[0].toInt() xor 1).toByte()
            assertEquals(policy, OracleJson.parseCanonical(retained.policyBytes()))
        }
    }

    @Test
    fun `target IDs are closed and a driver handle cannot select compiler engines`() = withControls { root ->
        val path = root.resolve("compiler-engines.json")
        for (id in listOf("", "gcc", "gcc-driver", "DRIVER", "driver ", "../cc1", "cc1plus")) {
            assertFails(id) { GccRetainedCompilerEngineProfile.open(path, id).use { } }
        }
        GccRetainedCompilerEngineProfile.open(path, "driver").use { retained ->
            for (id in listOf("cc1", "lto1", "gcc", "")) {
                assertFails(id) { retained.target(id) }
                assertFails(id) { retained.exportWallClockMillis(id, true) }
            }
        }
    }

    @Test
    fun `driver permits only full export within the driver budget`() = withControls { root ->
        val path = root.resolve("compiler-engines.json")
        GccRetainedCompilerEngineProfile.open(path, "driver").use { retained ->
            val artifacts = invocationArtifacts(retained, "driver")
            assertEquals(1_800_000L, retained.exportWallClockMillis("driver", true))
            assertFails { retained.exportWallClockMillis("driver", false) }
            assertContentEquals(retained.policyBytes(), retained.bindInvocation("driver", artifacts, budgets(), true))
            assertFails { retained.bindInvocation("driver", artifacts, budgets(), false) }
            assertFails { retained.bindInvocation("driver", artifacts, budgets(1_800_001L), true) }
            assertFails { retained.bindInvocation("driver", artifacts, budgets(9_000_000L), true) }
            assertFails { retained.bindInvocation("driver", artifacts,
                budgets().copy(maximumResidentBytes = retained.suite.budgets.exportMaximumResidentBytes + 1), true) }
        }
        GccRetainedCompilerEngineProfile.open(path).use { retained ->
            assertEquals(1_800_000L, retained.exportWallClockMillis("cc1", false))
            assertEquals(9_000_000L, retained.exportWallClockMillis("cc1", true))
            assertEquals(1_800_000L, retained.exportWallClockMillis("lto1", false))
            assertFails { retained.exportWallClockMillis("lto1", true) }
            assertContentEquals(retained.policyBytes(), retained.bindInvocation("cc1",
                invocationArtifacts(retained, "cc1"), budgets(9_000_000L), true))
            assertContentEquals(retained.policyBytes(), retained.bindInvocation("lto1",
                invocationArtifacts(retained, "lto1"), budgets(), false))
            assertFails { retained.bindInvocation("cc1", invocationArtifacts(retained, "cc1"), budgets(9_000_001L), true) }
            assertFails { retained.bindInvocation("lto1", invocationArtifacts(retained, "lto1"), budgets(), true) }
        }
    }

    @Test
    fun `driver invocation rejects changed controls binary sizes hashes and duplicated roles`() = withControls { root ->
        GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver").use { retained ->
            val artifacts = invocationArtifacts(retained, "driver")
            val controlRoles = setOf(
                GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE,
                GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK,
                GccCompilerEngineContainmentArtifactRole.BUILD_RECORD,
                GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST,
                GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION,
            )
            val sizeBoundRoles = controlRoles + setOf(GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY,
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE)
            for (role in sizeBoundRoles + GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE) {
                assertFails("changed $role digest") {
                    retained.bindInvocation("driver", artifacts.map { if (it.role == role) it.copy(sha256 = "f".repeat(64)) else it }, budgets(), true)
                }
            }
            for (role in sizeBoundRoles) {
                assertFails("changed $role length") {
                    retained.bindInvocation("driver", artifacts.map { if (it.role == role) it.copy(bytes = it.bytes + 1) else it }, budgets(), true)
                }
            }
            for (role in controlRoles) {
                assertFails("relocated $role") {
                    retained.bindInvocation("driver", artifacts.map {
                        if (it.role == role) it.copy(path = root.resolve("unbound-${it.path.fileName}")) else it
                    }, budgets(), true)
                }
            }
            assertFails { retained.bindInvocation("driver", artifacts + artifacts.first(), budgets(), true) }
            assertFails { retained.bindInvocation("driver", artifacts.filterNot {
                it.role == GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST
            }, budgets(), true) }
        }
    }

    @Test
    fun `invocation binding rejects driver cc1 and lto1 artifact cross pairs`() = withControls { root ->
        val path = root.resolve("compiler-engines.json")
        GccRetainedCompilerEngineProfile.open(path, "driver").use { driver ->
            GccRetainedCompilerEngineProfile.open(path).use { compilers ->
                val driverArtifacts = invocationArtifacts(driver, "driver")
                val engineArtifacts = listOf("cc1", "lto1").associateWith { invocationArtifacts(compilers, it) }
                for ((id, artifacts) in engineArtifacts) {
                    assertFails(id) { driver.bindInvocation("driver", artifacts, budgets(), true) }
                    assertFails(id) { driver.bindInvocation(id, artifacts, budgets(), true) }
                    assertFails(id) { compilers.bindInvocation(id, driverArtifacts, budgets(), id == "cc1") }
                }
                assertFails { compilers.bindInvocation("driver", driverArtifacts, budgets(), true) }
                assertFails { compilers.bindInvocation("cc1", engineArtifacts.getValue("lto1"), budgets(), true) }
                assertFails { compilers.bindInvocation("lto1", engineArtifacts.getValue("cc1"), budgets(), false) }
            }
        }
    }

    @Test
    fun `driver selection cannot derive a compiler planner request even under another target ID`() = withControls { root ->
        val path = root.resolve("compiler-engines.json")
        GccRetainedCompilerEngineProfile.open(path).use { compiler ->
            val engine = compiler.suite.engine("cc1")
            val bytes = RecoveredProgramModel(inputSha256 = engine.strippedArtifact.sha256, functions = listOf(
                RecoveredFunction("entry", "entry", 1UL, "int entry(void)"),
            )).toJson().toByteArray()
            val digest = "a".repeat(64)
            // Synthetic byte assessment exercises request derivation without granting export authority.
            val assessment = GccCompletedRunAssessment("non-authoritative-byte-assessment", digest, digest,
                bytes.size, OracleArtifacts.sha256(bytes), 1, 1, digest, 1, digest, digest, 1, 0, 0)
            val exported = GccBundledExecutedOperation("{}".toByteArray(), "{}".toByteArray(),
                GccBundledExportAssessment(assessment, "{}".toByteArray(), bytes))
            val modelPath = root.resolve("program_model.json")
            val output = root.resolve("planner-output")
            val accepted = GccBundledPlannerRequest.fromProfile(compiler, "cc1", exported, digest, modelPath, output)
            assertEquals(engine.strippedArtifact.sha256, accepted.inputSha256)
            assertEquals(OracleArtifacts.sha256(compiler.policyBytes()), accepted.profilePolicySha256)
            assertContentEquals(accepted.canonicalBytes, GccBundledPlannerRequest.parse(accepted.canonicalBytes).canonicalBytes)
            assertEquals(engine, compiler.requirePlanningTarget("cc1"))
            assertFails { compiler.requirePlanningTarget("driver") }
            GccRetainedCompilerEngineProfile.open(path, "driver").use { driver ->
                for (id in listOf("driver", "cc1", "lto1")) {
                    assertFails(id) { driver.requirePlanningTarget(id) }
                    val failure = assertFails(id) {
                        GccBundledPlannerRequest.fromProfile(driver, id, exported, digest, modelPath, output)
                    }
                    assertTrue(failure.message.orEmpty().contains("does not authorize compiler-engine planning"), failure.message)
                }
            }
            assertFalse(Files.exists(output), "request derivation must not publish a module plan")
        }
    }

    @Test
    fun `driver admission rejects changes to every retained control before open`() {
        for (name in CONTROLS) withControls { root ->
            val path = root.resolve(name)
            Files.write(path, Files.readAllBytes(path) + byteArrayOf(32))
            assertFails(name) { GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver").use { } }
        }
    }

    @Test
    fun `rehashing a valid toolchain control chain cannot replace the pinned driver profile`() = withControls { root ->
        val dockerfile = root.resolve("build-toolchain.Dockerfile")
        Files.write(dockerfile, Files.readAllBytes(dockerfile) + "\n# alternate retained toolchain\n".toByteArray())
        val toolchainPath = root.resolve("toolchain-reproduction.json")
        val toolchain = document(toolchainPath)
        val recipe = JsonObject(toolchain.getValue("recipe").jsonObject + ("dockerfileSha256" to JsonPrimitive(sha256(dockerfile))))
        Files.write(toolchainPath, OracleJson.canonicalBytes(JsonObject(toolchain + ("recipe" to recipe))))
        val profilePath = root.resolve("compiler-engines.json")
        val profile = document(profilePath)
        val provenance = JsonObject(profile.getValue("provenance").jsonObject +
            ("toolchainReproductionSha256" to JsonPrimitive(sha256(toolchainPath))))
        Files.write(profilePath, OracleJson.canonicalBytes(JsonObject(profile + ("provenance" to provenance))))

        // All internal links still authenticate under the general compiler-engine loader.
        assertNotEquals(PROFILE_SHA256, GccCompilerEngineProfiles.load(profilePath).profileSha256)
        assertFails { GccRetainedCompilerEngineProfile.open(profilePath, "driver").use { } }
    }

    @Test
    fun `driver manifest metadata substitution cannot rely on repeating the checked binary identities`() = withControls { root ->
        val manifestPath = root.resolve("oracle-manifest.json")
        val manifest = document(manifestPath)
        val oracle = JsonObject(manifest.getValue("oracle").jsonObject + ("id" to JsonPrimitive("substituted-driver")))
        Files.write(manifestPath, OracleJson.canonicalBytes(JsonObject(manifest + ("oracle" to oracle))))
        assertEquals(manifest.getValue("artifacts"), document(manifestPath).getValue("artifacts"))
        assertEquals(PROFILE_SHA256, sha256(root.resolve("compiler-engines.json")))
        assertFails { GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver").use { } }
    }

    @Test
    fun `replacing a retained driver control invalidates the handle even after restoring its inode`() {
        for (name in CONTROLS) withControls { root ->
            GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver").use { retained ->
                val artifacts = invocationArtifacts(retained, "driver")
                val path = root.resolve(name)
                val original = Files.readAllBytes(path)
                val retainedPath = root.resolve("retained-$name")
                Files.move(path, retainedPath)
                // This is a new inode: writing the leased original would block until lease expiry.
                Files.write(path, original + byteArrayOf(32))
                assertFails(name) { retained.requireCurrent() }
                Files.delete(path)
                Files.move(retainedPath, path)
                assertContentEquals(original, Files.readAllBytes(path))
                assertFails(name) { retained.policyBytes() }
                assertFails(name) { retained.target("driver") }
                assertFails(name) { retained.exportWallClockMillis("driver", true) }
                assertFails(name) { retained.bindInvocation("driver", artifacts, budgets(), true) }
            }
        }
    }

    @Test
    fun `nonblocking write attempt poisons the retained driver without changing bytes`() = withControls { root ->
        val path = root.resolve("oracle-manifest.json")
        val original = Files.readAllBytes(path)
        GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver").use { retained ->
            val artifacts = invocationArtifacts(retained, "driver")
            val opened = NonblockingWriter.open(path.toString(), O_WRONLY or O_NONBLOCK)
            val error = if (opened < 0) Native.getLastError() else 0
            if (opened >= 0) NonblockingWriter.close(opened)
            assertEquals(-1, opened)
            assertEquals(EWOULDBLOCK, error)
            assertFails { retained.requireCurrent() }
            assertFails { retained.policyBytes() }
            assertFails { retained.target("driver") }
            assertFails { retained.bindInvocation("driver", artifacts, budgets(), true) }
        }
        assertContentEquals(original, Files.readAllBytes(path))
    }

    @Test
    fun `replacing the driver manifest inode with identical bytes invalidates retention`() = withControls { root ->
        GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver").use { retained ->
            val manifest = root.resolve("oracle-manifest.json")
            val original = Files.readAllBytes(manifest)
            Files.move(manifest, root.resolve("original-manifest.json"))
            Files.write(manifest, original)
            Files.setPosixFilePermissions(manifest, PosixFilePermissions.fromString("rw-------"))
            assertEquals(MANIFEST_SHA256, sha256(manifest))
            assertFails { retained.requireCurrent() }
            assertFails { retained.policyBytes() }
        }
    }

    @Test
    fun `closed driver handles no longer expose policy or target capabilities`() = withControls { root ->
        val retained = GccRetainedCompilerEngineProfile.open(root.resolve("compiler-engines.json"), "driver")
        val artifacts = invocationArtifacts(retained, "driver")
        retained.close()
        retained.close()
        assertFails { retained.requireCurrent() }
        assertFails { retained.policyBytes() }
        assertFails { retained.target("driver") }
        assertFails { retained.requirePlanningTarget("cc1") }
        assertFails { retained.exportWallClockMillis("driver", true) }
        assertFails { retained.bindInvocation("driver", artifacts, budgets(), true) }
    }

    private fun invocationArtifacts(profile: GccRetainedCompilerEngineProfile, targetId: String): List<GccCompilerEngineContainmentArtifactIdentity> {
        val suite = profile.suite
        val target = profile.target(targetId)
        val root = suite.profilePath.parent
        val controls = mapOf(
            GccCompilerEngineContainmentArtifactRole.BENCHMARK_PROFILE to suite.profilePath,
            GccCompilerEngineContainmentArtifactRole.SOURCE_LOCK to suite.sourceLockPath,
            GccCompilerEngineContainmentArtifactRole.BUILD_RECORD to target.buildRecordPath,
            GccCompilerEngineContainmentArtifactRole.ORACLE_MANIFEST to target.oracleManifestPath,
            GccCompilerEngineContainmentArtifactRole.TOOLCHAIN_REPRODUCTION to suite.toolchainReproductionPath,
        )
        return GCC_BUNDLED_CONTAINMENT_ARTIFACT_ROLES.map { role ->
            controls[role]?.let { path ->
                GccCompilerEngineContainmentArtifactIdentity(role, path, Files.size(path), sha256(path))
            } ?: when (role) {
                GccCompilerEngineContainmentArtifactRole.ENGINE_BINARY -> GccCompilerEngineContainmentArtifactIdentity(role,
                    root.resolve(target.strippedArtifact.relativePath), target.strippedArtifact.bytes, target.strippedArtifact.sha256)
                GccCompilerEngineContainmentArtifactRole.GHIDRA_ARCHIVE -> GccCompilerEngineContainmentArtifactIdentity(role,
                    root.resolve(suite.analysis.ghidraArchive.relativePath), suite.analysis.ghidraArchive.bytes, suite.analysis.ghidraArchive.sha256)
                GccCompilerEngineContainmentArtifactRole.EXPORTER_SOURCE -> GccCompilerEngineContainmentArtifactIdentity(role,
                    root.resolve("ExportProgramModel.java"), checkNotNull(javaClass.getResourceAsStream("/ghidra_scripts/ExportProgramModel.java"))
                        .use { it.readBytes().size.toLong() }, suite.analysis.exporterSha256)
                else -> GccCompilerEngineContainmentArtifactIdentity(role, root.resolve("unmaterialized-${role.wireName}"), 32, "a".repeat(64))
            }
        }
    }

    private fun budgets(wallClockMillis: Long = 1_800_000L) =
        GccCompilerEngineContainmentBudgets(wallClockMillis, 16L * 1024 * 1024 * 1024, 32)

    private fun document(path: Path): JsonObject = OracleJson.parse(Files.readAllBytes(path)).jsonObject

    private fun sha256(path: Path): String = OracleArtifacts.sha256(Files.readAllBytes(path))

    private fun artifactDocument(path: String, bytes: Long, sha256: String): JsonObject = JsonObject(mapOf(
        "path" to JsonPrimitive(path), "bytes" to JsonPrimitive(bytes), "sha256" to JsonPrimitive(sha256),
    ))

    private fun withControls(action: (Path) -> Unit) {
        val parent = Files.createDirectories(Path.of("build", "test-tmp", "gcc-retained-driver").toAbsolutePath().normalize())
        val root = Files.createTempDirectory(parent, "profile-")
        try {
            CONTROLS.forEach { name ->
                val target = root.resolve(name)
                Files.copy(Path.of("oracle", "gcc", "16.2.0", name), target)
                Files.setPosixFilePermissions(target, PosixFilePermissions.fromString("rw-------"))
            }
            assertFalse(Files.exists(root.resolve("artifacts")), "the control-plane fixture must not materialize binaries")
            action(root)
        } finally {
            Files.walk(root).use { paths -> paths.sorted(Comparator.reverseOrder()).forEach(Files::delete) }
        }
    }

    private interface NonblockingWriter : Library {
        fun open(path: String, flags: Int): Int
        fun close(fd: Int): Int

        companion object : NonblockingWriter by Native.load(Platform.C_LIBRARY_NAME, NonblockingWriter::class.java)
    }

    private companion object {
        const val O_WRONLY = 0x1
        const val O_NONBLOCK = 0x800
        const val EWOULDBLOCK = 11
        const val PROFILE_SHA256 = "9c3187dedb789d547a9c455d7403ca42168c1789ff439412f6e9bea48390f925"
        const val BUILD_SHA256 = "f91a68ffde054b9598cba8506bbf6b3b373b35b8680fddb54f76bffa9db23637"
        const val MANIFEST_SHA256 = "c9e21c5a6422c65572ee4c4de5578107b82ae92b6730536c4fc76490fe2ecad9"
        const val FULL_SHA256 = "8009c7cfc4f66017aa932d86a6d4ec7f374e6ab7a01b3ef5ab3d2fcc78c2378b"
        const val STRIPPED_SHA256 = "3c0cfef73a02b06b40456e89d9d9e33727144c2f473b8b7256b361a7699d48a4"
        val CONTROLS = listOf("compiler-engines.json", "source-lock.json", "build-record.json", "toolchain-reproduction.json",
            "build-toolchain.Dockerfile", "cc1-build-record.json", "cc1-oracle-manifest.json", "lto1-build-record.json",
            "lto1-oracle-manifest.json", "oracle-manifest.json")
    }
}
