package decompengine.oracle.fulltree.generictemplatefrontend

import decompengine.oracle.core.OracleJson
import decompengine.oracle.core.OracleSchemas
import decompengine.oracle.fulltree.FullTreeControlException
import decompengine.oracle.fulltree.*
import decompengine.oracle.fulltree.FullTreeGenericTemplateFrontendProfileV1 as Profile
import decompengine.oracle.fulltree.FullTreeGenericTemplateFrontendProvenanceV1 as Provenance
import decompengine.oracle.fulltree.FullTreeGenericTemplateFrontendReceiptV1 as Receipt
import decompengine.oracle.provenance.BoundedTarXzArchive
import decompengine.oracle.provenance.BoundedTarXzLimits
import decompengine.oracle.provenance.BoundedTarXzSource
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Path
import java.nio.file.attribute.PosixFilePermissions
import java.security.MessageDigest
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive

/** Synthetic contract fixtures only: these tests do not execute or claim a real Clang profile. */
class FullTreeGenericTemplateFrontendV1Test {
    @Test
    fun `path transform preserves count and order without publishing captured path strings`() {
        val fixture = fixture()
        assertEquals(
            listOf(
                "/__decomp/toolchain/path/0000",
                "/__decomp/toolchain/path/0001",
                "/__decomp/toolchain/path/0002",
            ),
            fixture.pathTransform.virtualPathEntries,
        )
        assertEquals(PATH_TRANSFORM_SHA256, fixture.pathTransform.pathTransformSha256)
        assertNotEquals(
            Profile.transformPath("/usr/bin:/opt/clang/bin:/opt/clang/bin", fixture.imageDigest).pathTransformSha256,
            fixture.pathTransform.pathTransformSha256,
        )
        assertNotEquals(
            Profile.transformPath("/opt/clang/bin:/usr/bin", fixture.imageDigest).pathTransformSha256,
            fixture.pathTransform.pathTransformSha256,
        )
        assertNotEquals(
            Profile.transformPath(fixture.rawEnvironment.getValue("PATH"), "sha256:${"b".repeat(64)}")
                .pathTransformSha256,
            fixture.pathTransform.pathTransformSha256,
        )
        val serialized = String(fixture.canonicalReceipt, StandardCharsets.UTF_8)
        assertFalse(serialized.contains("/opt/clang/bin"))
        assertFalse(serialized.contains("/usr/bin"))
        assertFalse(serialized.contains("ignored.dot"))
        assertFalse(serialized.contains("-dependency-dot"))
    }

    @Test
    fun `PATH transform enforces every frozen raw path byte entry count and component bound`() {
        val image = "sha256:${"a".repeat(64)}"
        val sixtyFour = List(Profile.MAX_PATH_ENTRIES) { "/x" }.joinToString(":")
        assertEquals(Profile.MAX_PATH_ENTRIES, Profile.transformPath(sixtyFour, image).virtualPathEntries.size)
        assertFailsWith<FullTreeControlException> {
            Profile.transformPath(List(Profile.MAX_PATH_ENTRIES + 1) { "/x" }.joinToString(":"), image)
        }

        fun pathWithComponentSizes(sizes: List<Int>): String = "/" + sizes.joinToString("/") { "a".repeat(it) }
        val maxEntry = pathWithComponentSizes(List(4) { Profile.MAX_PATH_COMPONENT_BYTES })
        assertEquals(Profile.MAX_PATH_ENTRY_BYTES, maxEntry.toByteArray(StandardCharsets.UTF_8).size)
        Profile.transformPath(maxEntry, image)
        val oneOverEntry = pathWithComponentSizes(listOf(255, 255, 255, 254, 1))
        assertEquals(Profile.MAX_PATH_ENTRY_BYTES + 1, oneOverEntry.toByteArray(StandardCharsets.UTF_8).size)
        assertFailsWith<FullTreeControlException> { Profile.transformPath(oneOverEntry, image) }
        assertFailsWith<FullTreeControlException> { Profile.transformPath("/${"a".repeat(256)}", image) }

        val exactPathBytes = listOf(
            maxEntry,
            maxEntry,
            maxEntry,
            pathWithComponentSizes(listOf(255, 255, 255, 252)),
        ).joinToString(":")
        assertEquals(Profile.MAX_PATH_BYTES, exactPathBytes.toByteArray(StandardCharsets.UTF_8).size)
        Profile.transformPath(exactPathBytes, image)
        val overPathBytes = listOf(
            maxEntry,
            maxEntry,
            maxEntry,
            pathWithComponentSizes(listOf(255, 255, 255, 253)),
        ).joinToString(":")
        assertEquals(Profile.MAX_PATH_BYTES + 1, overPathBytes.toByteArray(StandardCharsets.UTF_8).size)
        assertFailsWith<FullTreeControlException> { Profile.transformPath(overPathBytes, image) }
    }

    @Test
    fun `effective environment retains the exact required UTC and absent-versus-empty values`() {
        val fixture = fixture()
        val values = fixture.effectiveEnvironment.values
        assertEquals("UTC", values["TZ"])
        assertEquals("C", values["LC_ALL"])
        assertEquals("1740000000", values["SOURCE_DATE_EPOCH"])
        assertEquals("", values["CPLUS_INCLUDE_PATH"])
        assertFalse("CPATH" in values)
        assertEquals("/__decomp/home", values["HOME"])
        assertEquals("/__decomp/tmp", values["TMPDIR"])

        for (badTz in listOf(null, "", "Etc/UTC")) {
            val changed = fixture.rawEnvironment.toMutableMap().apply {
                if (badTz == null) remove("TZ") else put("TZ", badTz)
            }
            assertFailsWith<FullTreeControlException> { Profile.effectiveEnvironment(changed, fixture.pathTransform) }
        }
        val changedPath = fixture.rawEnvironment.toMutableMap().apply {
            put("PATH", "/usr/bin:/opt/clang/bin:/opt/clang/bin")
        }
        assertFailsWith<FullTreeControlException> { Profile.effectiveEnvironment(changedPath, fixture.pathTransform) }
    }

    @Test
    fun `raw replay carries required TZ from build record variables through receipt bindings`() {
        val rawBuildEnvironment = linkedMapOf(
            "PATH" to "/opt/clang/bin:/usr/bin:/opt/clang/bin",
            "LC_ALL" to "C",
            "SOURCE_DATE_EPOCH" to "1740000000",
            "TZ" to "UTC",
            "HOME" to "/home/builder",
            "TMPDIR" to "/tmp/build",
            "LANG" to "C.UTF-8",
            "CPLUS_INCLUDE_PATH" to "",
        )
        val imageDigest = "sha256:${"d".repeat(64)}"
        val syntheticBuildRecord = syntheticBuildRecord(rawBuildEnvironment, imageDigest)
        OracleSchemas.validate("build-record", syntheticBuildRecord)
        val buildRecordSha = shaBytes(OracleJson.canonicalBytes(syntheticBuildRecord))
        val fixture = fixture(rawBuildEnvironment, imageDigest, buildRecordSha)
        val unit = (fixture.document.getValue("units") as JsonArray).first() as JsonObject
        val rawEnvironment = Provenance.environmentFromBuildRecord(syntheticBuildRecord)
        assertEquals(fixture.rawEnvironment, rawEnvironment)
        val transform = Profile.transformPath(rawEnvironment.getValue("PATH"), imageDigest)
        val replayEnvironment = Provenance.authenticateReplayEnvironment(unit, rawEnvironment, transform)
        assertEquals("UTC", replayEnvironment.values.getValue("TZ"))
        assertEquals(unit.getValue("environment"), replayEnvironment.json())
        assertEquals(unit.getValue("environmentSha256"), JsonPrimitive(replayEnvironment.sha256))
        assertEquals(unit.getValue("actionId"), JsonPrimitive(Receipt.actionId(fixture.bindings, unit)))
        assertEquals(unit.getValue("receiptSha256"), JsonPrimitive(Receipt.unitReceiptSha256(unit)))

        val arguments = fixedFrame("source/src/one.cpp") + listOf("-std=c++14", "-dependency-dot", "ignored.dot")
        val action = Provenance.CapturedActionSelectionV1(
            actionSha256 = (unit.getValue("captureActionSha256") as JsonPrimitive).content,
            unitId = (unit.getValue("unitId") as JsonPrimitive).content,
            sourcePath = "source/src/one.cpp",
            workingDirectory = "/oracle/build",
            mainInput = "source/src/one.cpp",
            arguments = arguments,
            objectOutput = "/oracle/build/unit.o",
        )
        val compdb = Provenance.CompdbSelectionV1(
            captureActionSha256 = action.actionSha256,
            directory = action.workingDirectory,
            file = action.mainInput,
            output = "unit.o",
            resolvedOutput = action.objectOutput,
        )
        val replayVector = Provenance.authenticateReplayVector(action, compdb, arguments.first())
        assertEquals(unit.getValue("argvSha256"), JsonPrimitive(replayVector.argvSha256))
        assertEquals(unit.getValue("executionArgvSha256"), JsonPrimitive(replayVector.executionArgvSha256))
        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayEnvironment(
                unit,
                rawEnvironment + mapOf("TZ" to "Etc/UTC"),
                transform,
            )
        }
        val missingVariables = JsonObject(syntheticBuildRecord.controlObject("environment").controlObject("variables") - "TZ")
        val missingBuildRecord = JsonObject(
            syntheticBuildRecord + mapOf(
                "environment" to JsonObject(
                    syntheticBuildRecord.controlObject("environment") + mapOf("variables" to missingVariables),
                ),
            ),
        )
        assertFailsWith<FullTreeControlException> {
            val missingTz = Provenance.environmentFromBuildRecord(missingBuildRecord)
            Provenance.authenticateReplayEnvironment(unit, missingTz, transform)
        }
    }

    @Test
    fun `fixed policy and synthetic two-unit receipt have frozen profile and receipt digests`() {
        val fixture = fixture()
        assertEquals(
            "clang-toolinvocation-capture-dependency-frame-strip-clang18.1.3-joined-tail-allowlist-v1",
            Profile.POLICY.getValue("argvPolicy").let { (it as JsonPrimitive).content },
        )
        assertEquals(
            setOf(
                "maxEntityRowBytes", "maxGenericEvidenceBytes", "maxFormalActualDescriptorNodesPerEntity",
                "maxEdgesPerEntity", "maxRelationWalkDepth", "maxMacroExpansionDepth", "maxTypeDepth",
                "maxTypeNodesPerDescriptor", "maxResourceHeaderFiles", "maxResourceHeaderManifestBytes",
                "maxResourceHeaderTreeBytes", "maxPathEntries", "maxPathBytes", "maxPathEntryBytes",
                "maxPathComponentBytes", "maxCxxDriverSymlinkHops", "genericResidentShareDivisor",
                "genericResidentCanonicalByteMultiplier", "genericResidentFixedBytes",
            ),
            (Profile.POLICY.getValue("limits") as JsonObject).keys,
        )
        assertEquals(PROFILE_SHA256, fixture.profile.sha256())
        val contractReceiptSet = receiptSetPreimageFromContract(fixture.document)
        assertEquals(contractReceiptSet, Receipt.receiptSetPreimage(fixture.document))
        val contractReceiptSha256 = domainHashFromContract(
            "decomp-thing/generic-template/receipt-set/v1",
            contractReceiptSet,
        )
        assertEquals(contractReceiptSha256, fixture.validated.frontendReceiptSha256)
        assertEquals(
            listOf(
                CONFIGURATION_SHA256,
                CANONICAL_RECEIPT_BYTES.toString(),
                CANONICAL_RECEIPT_SHA256,
                RECEIPT_SHA256,
            ),
            listOf(
                Provenance.configurationSha256,
                fixture.canonicalReceipt.size.toString(),
                shaBytes(fixture.canonicalReceipt),
                contractReceiptSha256,
            ),
            "independently frozen profile, canonical receipt, and receipt-set vectors",
        )
        assertEquals(2L, fixture.validated.unitCount)
        assertEquals(10L, fixture.validated.dependencyCount)
        assertEquals(0L, fixture.validated.outputBytes)
        assertEquals(fixture.validated.dependencyBytes, fixture.limits.maximumDependencyBytes)
        assertEquals(fixture.validated.receiptBytes, fixture.limits.maximumReceiptBytes)
        assertEquals(fixture.validated.outputBytes, fixture.limits.maximumOutputBytes)
        assertEquals(
            2,
            (fixture.document.getValue("units") as JsonArray).count { unit ->
                ((unit as JsonObject).getValue("dependencies") as JsonArray).any { dependency ->
                    (dependency as JsonObject).getValue("path") == JsonPrimitive("source/include/shared.h")
                }
            },
        )
        assertEquals(7, fixture.document.keys.size)
        assertEquals(20, (fixture.document.getValue("units") as JsonArray).first().let { (it as JsonObject).size })
        val firstUnit = (fixture.document.getValue("units") as JsonArray).first() as JsonObject
        assertEquals(18, Receipt.unitReceiptPreimage(firstUnit).size)
        assertEquals(
            setOf(
                "adapterSha256", "artifactManifestSha256", "argvSha256", "buildRecordSha256",
                "captureActionSha256", "compilationDatabaseSha256", "cwd", "dependencySetSha256",
                "executionArgvSha256", "environmentSha256", "frontendProfileSha256",
                "generatedInventorySha256", "richArtifactSha256", "richInventorySha256",
                "resolvedResourceDirectory", "resourceHeaderManifestSha256", "scopeSha256",
                "semanticContextSha256", "sourceArchiveSha256", "sourceFileSha256",
                "sourceInventorySha256", "sourceLockSha256", "unitId",
            ),
            Receipt.actionIdPreimage(fixture.bindings, firstUnit).keys,
        )
        assertEquals(7, Receipt.receiptSetPreimage(fixture.document).keys.size)
        assertEquals(
            OracleSchemas.configurationSha256(Provenance.SCHEMA_NAME, Profile.POLICY),
            fixture.document.getValue("configurationSha256").let { (it as JsonPrimitive).content },
        )
        val changedPolicy = JsonObject(Profile.POLICY + mapOf("argvPolicy" to JsonPrimitive("changed-v1")))
        assertNotEquals(
            OracleSchemas.configurationSha256(Provenance.SCHEMA_NAME, Profile.POLICY),
            OracleSchemas.configurationSha256(Provenance.SCHEMA_NAME, changedPolicy),
        )
        val changedPathPolicy = JsonObject(
            Profile.POLICY + mapOf("environmentPathPolicy" to JsonPrimitive("changed-path-policy-v1")),
        )
        assertNotEquals(
            OracleSchemas.configurationSha256(Provenance.SCHEMA_NAME, Profile.POLICY),
            OracleSchemas.configurationSha256(Provenance.SCHEMA_NAME, changedPathPolicy),
        )
        OracleSchemas.validate(Provenance.SCHEMA_NAME, fixture.document)
        val schemaOnly = Receipt.validate(fixture.document, fixture.limits)
        assertEquals(RECEIPT_SHA256, schemaOnly.frontendReceiptSha256)
        val receiptPath = Files.createTempFile("generic-template-receipt-", ".json")
        try {
            Files.write(receiptPath, fixture.canonicalReceipt)
            val loaded = Provenance.loadAndValidate(
                receiptPath,
                fixture.limits,
                expectedBindings = fixture.bindings,
                expectedPathTransform = fixture.pathTransform,
                expectedProfile = fixture.profile,
                expectedRawEnvironment = fixture.rawEnvironment,
                expectedSourceFileDigests = fixture.fileDigests,
                expectedResourceManifest = fixture.resourceManifest,
                expectedDriverPath = fixture.driverPath,
            )
            assertEquals(RECEIPT_SHA256, loaded.frontendReceiptSha256)
            val structurallyLoaded = Provenance.loadAndValidate(receiptPath, fixture.limits)
            assertEquals(RECEIPT_SHA256, structurallyLoaded.frontendReceiptSha256)
        } finally {
            Files.deleteIfExists(receiptPath)
        }
    }

    @Test
    fun `raw rejected option remains bound by both argument vector digests and action id`() {
        val original = fixedFrame("source/src/one.cpp") + listOf("-std=c++14", "-dependency-dot", "out.dot")
        val changed = original.dropLast(1) + "other.dot"
        val stripped = Receipt.deriveExecutionArgv(original, "source/src/one.cpp")
        assertEquals(original.take(2) + original.drop(7), stripped)
        assertNotEquals(Receipt.argvSha256(original), Receipt.argvSha256(changed))
        assertNotEquals(
            Receipt.executionArgvSha256(original, "source/src/one.cpp"),
            Receipt.executionArgvSha256(changed, "source/src/one.cpp"),
        )

        val fixture = fixture()
        val unit = (fixture.document.getValue("units") as JsonArray).first() as JsonObject
        val alteredCapture = JsonObject(unit + mapOf("captureActionSha256" to JsonPrimitive(sha("other capture"))))
        val alteredArgv = JsonObject(unit + mapOf("argvSha256" to JsonPrimitive(sha("other argv"))))
        assertNotEquals(Receipt.actionId(fixture.bindings, unit), Receipt.actionId(fixture.bindings, alteredCapture))
        assertNotEquals(Receipt.actionId(fixture.bindings, unit), Receipt.actionId(fixture.bindings, alteredArgv))
        val alteredExecutionArgv = JsonObject(
            unit + mapOf("executionArgvSha256" to JsonPrimitive(sha("other execution argv"))),
        )
        assertNotEquals(Receipt.actionId(fixture.bindings, unit), Receipt.actionId(fixture.bindings, alteredExecutionArgv))
    }

    @Test
    fun `raw replay joins one capture action to its exact external compilation database row`() {
        val args = fixedFrame("source/src/one.cpp") + listOf("-std=c++14", "-dependency-dot", "must-stay-bound.dot")
        val action = Provenance.CapturedActionSelectionV1(
            actionSha256 = sha("captured action"),
            unitId = "unit-1",
            sourcePath = "source/src/one.cpp",
            workingDirectory = "/build/project",
            mainInput = "source/src/one.cpp",
            arguments = args,
            objectOutput = "/build/project/unit.o",
        )
        val match = Provenance.CompdbSelectionV1(
            captureActionSha256 = action.actionSha256,
            directory = action.workingDirectory,
            file = action.mainInput,
            output = "unit.o",
            resolvedOutput = action.objectOutput,
        )
        val replay = Provenance.authenticateReplayVector(action, match, "/opt/clang/bin/clang++")
        assertEquals(Receipt.argvSha256(args), replay.argvSha256)
        assertEquals(Receipt.executionArgvSha256(args, action.mainInput), replay.executionArgvSha256)
        assertEquals(args.take(2) + args.drop(7), replay.executionArgv)
        assertTrue("-dependency-dot" in replay.executionArgv)
        assertTrue("must-stay-bound.dot" in replay.executionArgv)

        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayVector(action, match.copy(captureActionSha256 = sha("other action")), "/opt/clang/bin/clang++")
        }
        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayVector(action, match.copy(directory = "/build/other"), "/opt/clang/bin/clang++")
        }
        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayVector(action, match.copy(file = "source/src/two.cpp"), "/opt/clang/bin/clang++")
        }
        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayVector(action, match.copy(output = "different.o"), "/opt/clang/bin/clang++")
        }
        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayVector(action, match.copy(resolvedOutput = "/build/project/other.o"), "/opt/clang/bin/clang++")
        }
        assertFailsWith<FullTreeControlException> {
            Provenance.authenticateReplayVector(action, match, "/opt/other/clang++")
        }
    }

    @Test
    fun `raw input loader authenticates a complete synthetic source build capture image and receipt chain`() {
        inControlTemporaryDirectory { directory ->
            val fixture = syntheticRawInputsFixture(directory)
            assertEquals(
                shaBytes(OracleJson.canonicalBytes(fixture.syntheticImageManifest)),
                fixture.profile.toolchainProfileSha256,
            )
            val captureDocument = OracleJson.parseCanonical(
                fixture.raw.capture.canonicalBytes,
                controlJsonLimits(64 * 1024 * 1024),
            ) as JsonObject
            assertEquals(
                JsonPrimitive(false),
                captureDocument.controlObject("compiler")["cxxDriverIdentityAuthenticated"],
            )

            val validated = Provenance.validateRawInputs(
                fixture.document,
                fixture.raw,
                fixture.profile,
                fixture.receiptLimits,
            )
            assertEquals(fixture.raw.capture.actions.size, validated.actions.size)
            assertEquals(2, validated.actions.size)
            assertEquals(fixture.profile.sha256(), validated.bindings.controlString("frontendProfileSha256"))
            assertEquals("UTC", validated.actions.first().environment.values.getValue("TZ"))
            assertEquals("build", validated.actions.first().cwd)
            assertEquals(0L, validated.receipt.outputBytes)
            assertFalse(validated.receipt.document.toString().contains("/synthetic/clang18/bin/clang++"))

            for (field in Receipt.BINDING_FIELDS) {
                val bindings = fixture.document.controlObject("bindings")
                val changedBindings = JsonObject(bindings + mapOf(field to JsonPrimitive(sha("changed $field"))))
                val changedDocument = JsonObject(fixture.document + mapOf("bindings" to changedBindings))
                assertFailsWith<FullTreeControlException> {
                    Provenance.validateRawInputs(changedDocument, fixture.raw, fixture.profile, fixture.receiptLimits)
                }
            }

            val units = fixture.document.controlArray("units")
            val first = units.first() as JsonObject
            for (field in listOf("argvSha256", "executionArgvSha256")) {
                val changedArgvUnit = resealUnit(
                    JsonObject(first + mapOf(field to JsonPrimitive(sha("different $field")))),
                    fixture.document.controlObject("bindings"),
                )
                val changedArgvDocument = JsonObject(
                    fixture.document + mapOf("units" to JsonArray(listOf(changedArgvUnit) + units.drop(1))),
                )
                assertFailsWith<FullTreeControlException> {
                    Provenance.validateRawInputs(changedArgvDocument, fixture.raw, fixture.profile, fixture.receiptLimits)
                }
            }

            val changedCaptureUnit = resealUnit(
                JsonObject(first + mapOf("captureActionSha256" to JsonPrimitive(sha("different capture action")))),
                fixture.document.controlObject("bindings"),
            )
            val changedCaptureDocument = JsonObject(
                fixture.document + mapOf("units" to JsonArray(listOf(changedCaptureUnit) + units.drop(1))),
            )
            assertFailsWith<FullTreeControlException> {
                Provenance.validateRawInputs(changedCaptureDocument, fixture.raw, fixture.profile, fixture.receiptLimits)
            }

            val changedBuildRecord = fixture.raw.buildRecordBytes.copyOf().apply {
                this[lastIndex] = (this[lastIndex].toInt() xor 1).toByte()
            }
            assertFailsWith<FullTreeControlException> {
                Provenance.validateRawInputs(
                    fixture.document,
                    fixture.raw.copy(buildRecordBytes = changedBuildRecord),
                    fixture.profile,
                    fixture.receiptLimits,
                )
            }
            val changedArchive = directory.resolve("mutated-source.tar.xz")
            Files.write(
                changedArchive,
                Files.readAllBytes(fixture.raw.sourceArchivePath).also { it[it.lastIndex] = (it.last().toInt() xor 1).toByte() },
            )
            assertFailsWith<FullTreeControlException> {
                Provenance.validateRawInputs(
                    fixture.document,
                    fixture.raw.copy(sourceArchivePath = changedArchive),
                    fixture.profile,
                    fixture.receiptLimits,
                )
            }

            for (path in listOf(
                fixture.toolchainRoot.resolve("bin/clang++"),
                fixture.toolchainRoot.resolve("lib/libclang-cpp.so"),
                fixture.raw.adapterExecutablePath,
            )) {
                val original = Files.readAllBytes(path)
                try {
                    Files.write(path, original.copyOf().apply { this[0] = (this[0].toInt() xor 1).toByte() })
                    assertFailsWith<FullTreeControlException> {
                        Provenance.validateRawInputs(fixture.document, fixture.raw, fixture.profile, fixture.receiptLimits)
                    }
                } finally {
                    Files.write(path, original)
                }
            }

            val resource = fixture.toolchainRoot.resolve("lib/clang/18/include/stddef.h")
            Files.writeString(resource, "mutated synthetic Clang resource header")
            assertFailsWith<FullTreeControlException> {
                Provenance.validateRawInputs(fixture.document, fixture.raw, fixture.profile, fixture.receiptLimits)
            }
        }
    }

    @Test
    fun `receipt rejects duplicate actions unknown fields missing dependencies and one-over limits`() {
        val fixture = fixture()
        val units = fixture.document.getValue("units") as JsonArray
        val first = units.first() as JsonObject
        val duplicate = JsonObject(first + mapOf("unitId" to JsonPrimitive("unit-3")))
        val duplicateActionDocument = document(fixture, JsonArray(listOf(first, duplicate)))
        assertFailsWith<FullTreeControlException> { Receipt.validate(duplicateActionDocument, fixture.limits) }

        val unknown = JsonObject(fixture.document + mapOf("unexpected" to JsonPrimitive(true)))
        assertFailsWith<FullTreeControlException> { Receipt.validate(unknown, fixture.limits) }
        val missingDependency = JsonObject(first - "dependencies")
        val validEnvelope = document(fixture, units)
        val malformedEnvelope = JsonObject(
            validEnvelope + mapOf("units" to JsonArray(listOf(missingDependency, units[1]))),
        )
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(malformedEnvelope, fixture.limits)
        }
        val noMainSource = JsonArray((first.getValue("dependencies") as JsonArray).filterNot { dependency ->
            (dependency as JsonObject).getValue("role") == JsonPrimitive("main-source")
        })
        val noMainSourceUnit = JsonObject(
            first + mapOf("dependencies" to noMainSource, "dependencySetSha256" to JsonPrimitive(Receipt.dependencySetSha256(noMainSource))),
        )
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(
                document(fixture, JsonArray(listOf(resealUnit(noMainSourceUnit, fixture.bindings), units[1]))),
                fixture.limits,
            )
        }
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(fixture.document, fixture.limits.copy(maximumUnits = 1))
        }
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(fixture.document, fixture.limits.copy(maximumDependencyRows = 9))
        }
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(fixture.document, fixture.limits.copy(maximumDependencyBytes = fixture.validated.dependencyBytes - 1))
        }
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(fixture.document, fixture.limits.copy(maximumReceiptBytes = fixture.validated.receiptBytes - 1))
        }
        val outputUnit = JsonObject(first + mapOf("outputBytes" to JsonPrimitive(1)))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(document(fixture, JsonArray(listOf(outputUnit, units[1]))), fixture.limits)
        }

        val escapedSource = JsonObject(first + mapOf("sourcePath" to JsonPrimitive("source/../outside.cpp")))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(document(fixture, JsonArray(listOf(escapedSource, units[1]))), fixture.limits)
        }
        val escapedCwd = JsonObject(first + mapOf("cwd" to JsonPrimitive("build/../outside")))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(document(fixture, JsonArray(listOf(escapedCwd, units[1]))), fixture.limits)
        }
        val escapedRows = JsonArray(
            (first.getValue("dependencies") as JsonArray).map { dependency ->
                val row = dependency as JsonObject
                if (row.getValue("path") == JsonPrimitive("source/include/shared.h")) {
                    JsonObject(row + mapOf("path" to JsonPrimitive("source/../outside.h")))
                } else row
            },
        )
        val escapedDependency = JsonObject(first + mapOf("dependencies" to escapedRows))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(document(fixture, JsonArray(listOf(escapedDependency, units[1]))), fixture.limits)
        }
    }

    @Test
    fun `receipt rejects changed source bytes environment resource profile and mixed profiles`() {
        val fixture = fixture()
        val units = fixture.document.getValue("units") as JsonArray
        val first = units.first() as JsonObject
        val dependencies = first.getValue("dependencies") as JsonArray
        val changedDependency = JsonObject(dependencies.first() as JsonObject + mapOf("sha256" to JsonPrimitive(sha("changed"))))
        val changedRows = JsonArray(listOf(changedDependency) + dependencies.drop(1))
        val changedSet = JsonObject(first + mapOf("dependencies" to changedRows))
        val changedReceipt = JsonObject(changedSet + mapOf("dependencySetSha256" to JsonPrimitive(Receipt.dependencySetSha256(changedRows))))
        val changedReceiptWithHashes = resealUnit(changedReceipt, fixture.bindings)
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(
                document(fixture, JsonArray(listOf(changedReceiptWithHashes, units[1]))),
                fixture.limits,
                expectedBindings = fixture.bindings,
                expectedPathTransform = fixture.pathTransform,
                expectedProfile = fixture.profile,
                expectedRawEnvironment = fixture.rawEnvironment,
                expectedSourceFileDigests = fixture.fileDigests,
                expectedResourceManifest = fixture.resourceManifest,
                expectedDriverPath = fixture.driverPath,
            )
        }

        for (bindingName in Receipt.BINDING_FIELDS) {
            val alteredBindings = JsonObject(fixture.bindings + mapOf(bindingName to JsonPrimitive(sha("changed $bindingName"))))
            assertFailsWith<FullTreeControlException> {
                Receipt.validate(
                    JsonObject(fixture.document + mapOf("bindings" to alteredBindings)),
                    fixture.limits,
                    expectedBindings = fixture.bindings,
                )
            }
        }
        val wrongSourceDigest = fixture.fileDigests + mapOf("source/src/one.cpp" to sha("wrong source"))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(
                fixture.document,
                fixture.limits,
                expectedBindings = fixture.bindings,
                expectedPathTransform = fixture.pathTransform,
                expectedProfile = fixture.profile,
                expectedRawEnvironment = fixture.rawEnvironment,
                expectedSourceFileDigests = wrongSourceDigest,
                expectedResourceManifest = fixture.resourceManifest,
                expectedDriverPath = fixture.driverPath,
            )
        }
        for (path in listOf(fixture.driverPath, "toolchain/lib/libclang-cpp.so")) {
            val changedToolchainDigest = fixture.fileDigests + mapOf(path to sha("changed $path"))
            assertFailsWith<FullTreeControlException> {
                Receipt.validate(
                    fixture.document,
                    fixture.limits,
                    expectedBindings = fixture.bindings,
                    expectedPathTransform = fixture.pathTransform,
                    expectedProfile = fixture.profile,
                    expectedRawEnvironment = fixture.rawEnvironment,
                    expectedSourceFileDigests = changedToolchainDigest,
                    expectedResourceManifest = fixture.resourceManifest,
                    expectedDriverPath = fixture.driverPath,
                )
            }
        }
        val changedAdapterProfile = fixture.profile.copy(adapterSha256 = sha("changed adapter bytes"))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(
                fixture.document,
                fixture.limits,
                expectedBindings = fixture.bindings,
                expectedPathTransform = fixture.pathTransform,
                expectedProfile = changedAdapterProfile,
                expectedRawEnvironment = fixture.rawEnvironment,
                expectedSourceFileDigests = fixture.fileDigests,
                expectedResourceManifest = fixture.resourceManifest,
                expectedDriverPath = fixture.driverPath,
            )
        }
        val nonUtcBuildEnvironment = fixture.rawEnvironment + mapOf("TZ" to "Etc/UTC")
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(
                fixture.document,
                fixture.limits,
                expectedBindings = fixture.bindings,
                expectedPathTransform = fixture.pathTransform,
                expectedProfile = fixture.profile,
                expectedRawEnvironment = nonUtcBuildEnvironment,
                expectedSourceFileDigests = fixture.fileDigests,
                expectedResourceManifest = fixture.resourceManifest,
                expectedDriverPath = fixture.driverPath,
            )
        }
        val alteredArgv = JsonObject(first + mapOf("argvSha256" to JsonPrimitive(sha("altered raw argv"))))
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(document(fixture, JsonArray(listOf(alteredArgv, units[1]))), fixture.limits)
        }
        val alteredEnvironment = JsonObject(
            first + mapOf(
                "environment" to JsonObject((first.getValue("environment") as JsonObject) + mapOf("TZ" to JsonPrimitive("Etc/UTC"))),
            ),
        )
        assertFailsWith<FullTreeControlException> {
            Receipt.validate(document(fixture, JsonArray(listOf(alteredEnvironment, units[1]))), fixture.limits)
        }

        val changedManifest = Profile.resourceManifest(
            fixture.resourceManifest.resolvedResourceDirectory,
            fixture.resourceManifest.files.map { it.copy(sha256 = sha("changed resource")) },
        )
        val movedManifest = Profile.resourceManifest(
            fixture.resourceManifest.resolvedResourceDirectory,
            fixture.resourceManifest.files.map { it.copy(path = "${it.path}.moved") },
        )
        val changedProfile = fixture.profile.copy(resourceHeaderManifestSha256 = changedManifest.sha256)
        assertNotEquals(fixture.profile.sha256(), changedProfile.sha256())
        assertNotEquals(fixture.resourceManifest.sha256, movedManifest.sha256)
        assertFailsWith<FullTreeControlException> {
            Profile.requireHomogeneousProfiles(listOf(fixture.profile, changedProfile))
        }
        assertNotEquals(
            (first.getValue("actionId") as JsonPrimitive).content,
            Receipt.actionId(
                fixture.bindings,
                JsonObject(first + mapOf("resourceHeaderManifestSha256" to JsonPrimitive(changedManifest.sha256))),
            ),
        )
    }

    @Test
    fun `resource manifest exact count byte and canonical preimage bounds fail closed`() {
        val exactFiles = (0 until Profile.MAX_RESOURCE_FILES).map { index ->
            val length = when (index) {
                in 0 until 20 -> 4096
                20 -> 2639
                else -> 909
            }
            Profile.ResourceFileV1(resourcePath(index, length), sha("resource $index"), 0L)
        }
        val exact = Profile.resourceManifest("toolchain/r", exactFiles)
        assertEquals(Profile.MAX_RESOURCE_FILES, exact.files.size)
        assertEquals(Profile.MAX_RESOURCE_MANIFEST_BYTES, exact.preimageBytes)
        assertFailsWith<FullTreeControlException> {
            Profile.resourceManifest("toolchain/r", exactFiles + Profile.ResourceFileV1(
                resourcePath(Profile.MAX_RESOURCE_FILES, 936), sha("one extra resource"), 0L,
            ))
        }
        val oneOverPreimage = exactFiles.toMutableList().apply {
            this[21] = this[21].copy(path = this[21].path + "x")
        }
        assertFailsWith<FullTreeControlException> { Profile.resourceManifest("toolchain/r", oneOverPreimage) }

        val exactTree = Profile.resourceManifest(
            "toolchain/r",
            listOf(
                Profile.ResourceFileV1("toolchain/r/a.h", sha("a"), Profile.MAX_RESOURCE_TREE_BYTES - 1),
                Profile.ResourceFileV1("toolchain/r/b.h", sha("b"), 1L),
            ),
        )
        assertEquals(Profile.MAX_RESOURCE_TREE_BYTES, exactTree.totalBytes)
        assertFailsWith<FullTreeControlException> {
            Profile.resourceManifest(
                "toolchain/r",
                listOf(
                    Profile.ResourceFileV1("toolchain/r/a.h", sha("a"), Profile.MAX_RESOURCE_TREE_BYTES),
                    Profile.ResourceFileV1("toolchain/r/b.h", sha("b"), 1L),
                ),
            )
        }
        assertFailsWith<FullTreeControlException> {
            Profile.resourceManifest(
                "toolchain/r",
                listOf(
                    Profile.ResourceFileV1("toolchain/r/a.h", sha("a"), 1L),
                    Profile.ResourceFileV1("toolchain/r/b.h", sha("b"), Long.MAX_VALUE),
                ),
            )
        }
    }

    @Test
    fun `resource loader includes every regular file and rejects symlinks and changed profile bytes`() {
        val root = Files.createTempDirectory("generic-template-resource-")
        try {
            val include = root.resolve("lib/clang/18/include")
            Files.createDirectories(include)
            Files.writeString(include.resolve("stddef.h"), "synthetic header")
            Files.writeString(include.resolve("stdint.h"), "another synthetic header")
            val loaded = Profile.loadResourceManifest(root, "toolchain/lib/clang/18/include")
            assertEquals(2, loaded.files.size)
            val changed = Profile.loadResourceManifest(root, "toolchain/lib/clang/18/include")
            assertEquals(loaded.sha256, changed.sha256)
            Files.writeString(include.resolve("stddef.h"), "changed synthetic header")
            val mutated = Profile.loadResourceManifest(root, "toolchain/lib/clang/18/include")
            assertNotEquals(loaded.sha256, mutated.sha256)

            val symlink = include.resolve("link.h")
            Files.createSymbolicLink(symlink, include.resolve("stdint.h"))
            assertFailsWith<FullTreeControlException> {
                Profile.loadResourceManifest(root, "toolchain/lib/clang/18/include")
            }
        } finally {
            root.toFile().deleteRecursively()
        }
    }

    @Test
    fun `changed profile preimage and container-bound C++ identity change its digest`() {
        val fixture = fixture()
        val driver = fixture.driverInput
        val changedConfiguredPath = Profile.cxxDriverIdentity(driver.copy(configuredPathSha256 = sha("other path")))
        val changedContainer = Profile.cxxDriverIdentity(driver.copy(containerImageDigest = "sha256:${"b".repeat(64)}"))
        assertNotEquals(fixture.profile.cxxDriverIdentitySha256, changedConfiguredPath)
        assertNotEquals(fixture.profile.cxxDriverIdentitySha256, changedContainer)
        val sixteenHops = (0 until Profile.MAX_DRIVER_SYMLINK_HOPS).map { index ->
            "toolchain/bin/link-$index" to sha("symlink target $index")
        }
        assertTrue(Profile.cxxDriverIdentity(driver.copy(symlinkChain = sixteenHops)).matches(Regex("^[0-9a-f]{64}$")))
        assertFailsWith<FullTreeControlException> {
            Profile.cxxDriverIdentity(driver.copy(symlinkChain = sixteenHops + ("toolchain/bin/link-16" to sha("hop 17"))))
        }
        assertFailsWith<FullTreeControlException> {
            Profile.cxxDriverIdentity(driver.copy(symlinkChain = listOf("toolchain/bin/loop" to sha("loop"), "toolchain/bin/loop" to sha("loop"))))
        }
        assertFailsWith<FullTreeControlException> {
            Profile.cxxDriverIdentity(driver.copy(symlinkChain = listOf("source/escape" to sha("escape"))))
        }
        assertFailsWith<FullTreeControlException> {
            Profile.cxxDriverIdentity(driver.copy(executableMode = "0640"))
        }
    }

    private data class Fixture(
        val imageDigest: String,
        val rawEnvironment: Map<String, String>,
        val pathTransform: Profile.PathTransformV1,
        val effectiveEnvironment: Profile.EffectiveEnvironmentV1,
        val resourceManifest: Profile.ResourceManifestV1,
        val profile: Profile.ProfileV1,
        val driverInput: Profile.CxxDriverIdentityInputV1,
        val driverPath: String,
        val bindings: JsonObject,
        val fileDigests: Map<String, String>,
        val document: JsonObject,
        val canonicalReceipt: ByteArray,
        val validated: Receipt.ValidatedReceipt,
        val limits: Receipt.Limits,
    )

    private data class SyntheticRawInputsFixture(
        val raw: Provenance.RawInputs,
        val profile: Profile.ProfileV1,
        val receiptLimits: Receipt.Limits,
        val document: JsonObject,
        val toolchainRoot: Path,
        val syntheticImageManifest: JsonObject,
    )

    private fun syntheticRawInputsFixture(root: Path): SyntheticRawInputsFixture {
        val generatedFixture = createGeneratedFixture(root.resolve("authenticated-inputs"))
        val control = generatedFixture.control
        val originalBuildRecord = parseControlObject(control.buildRecord)
        val syntheticImageDigest = "sha256:${"e".repeat(64)}"
        val configuredDriver = "/synthetic/clang18/bin/clang++"
        val environment = originalBuildRecord.controlObject("environment")
        val container = JsonObject(
            environment.controlObject("container") + mapOf(
                "digest" to JsonPrimitive(syntheticImageDigest),
                "image" to JsonPrimitive("synthetic-frontend-profile-image-v1"),
            ),
        )
        val commands = originalBuildRecord.controlObject("commands")
        val configure = commands.controlArray("configure").map { argument ->
            val value = (argument as JsonPrimitive).content
            if (value.startsWith("-DCMAKE_CXX_COMPILER=")) {
                JsonPrimitive("-DCMAKE_CXX_COMPILER=$configuredDriver")
            } else {
                argument
            }
        }
        val buildRecord = JsonObject(
            originalBuildRecord + mapOf(
                "environment" to JsonObject(environment + mapOf("container" to container)),
                "commands" to JsonObject(commands + mapOf("configure" to JsonArray(configure))),
            ),
        )
        OracleSchemas.validate("build-record", buildRecord)
        writeControlObject(control.buildRecord, buildRecord)
        val buildRecordBytes = Files.readAllBytes(control.buildRecord)
        val buildRecordSha256 = shaBytes(buildRecordBytes)

        val originalManifest = parseControlObject(control.manifest)
        val oldBuildBinding = originalManifest.controlObject("inputs").controlObject("buildRecord")
        val updatedBuildBinding = JsonObject(
            oldBuildBinding + mapOf(
                "bytes" to JsonPrimitive(buildRecordBytes.size),
                "sha256" to JsonPrimitive(buildRecordSha256),
            ),
        )
        val manifest = JsonObject(
            originalManifest + mapOf(
                "inputs" to JsonObject(
                    originalManifest.controlObject("inputs") + mapOf("buildRecord" to updatedBuildBinding),
                ),
            ),
        )
        writeControlObject(control.manifest, manifest)
        val manifestSha256 = fixtureSha256(control.manifest)
        val originalScope = parseControlObject(control.scope)
        val scope = JsonObject(
            originalScope + mapOf(
                "oracle" to JsonObject(
                    originalScope.controlObject("oracle") + mapOf(
                        "artifactManifestSha256" to JsonPrimitive(manifestSha256),
                    ),
                ),
            ),
        )
        writeControlObject(control.scope, scope)
        val authenticatedScope = control.authenticatedScope()

        Files.deleteIfExists(control.inventory)
        FullTreeInventoryControl.generateAndPublish(
            control.richArtifact,
            authenticatedScope,
            control.inventory,
            maximumWorkers = 1,
        )
        Files.deleteIfExists(control.sourceInventory)
        FullTreeSourceInventoryControl.generateAndPublish(
            control.sourceArchive,
            authenticatedScope,
            control.buildRecord,
            control.inventory,
            control.sourceInventory,
            maximumWorkers = 1,
        )
        Files.deleteIfExists(generatedFixture.planning)
        FullTreePlanningInventoryControl.generateAndPublish(
            control.scope,
            control.sourceLock,
            control.manifest,
            control.buildRecord,
            control.inventory,
            control.sourceInventory,
            generatedFixture.planning,
        )
        rebindSyntheticGeneratedProvenance(generatedFixture.provenance, buildRecord, buildRecordSha256)

        val generatedInventoryPath = root.resolve("generated-inventory.json")
        val generated = FullTreeGeneratedFileInventoryControl.generateAndPublish(
            generatedFixture.archive,
            generatedFixture.provenance,
            control.scope,
            control.sourceLock,
            control.manifest,
            control.buildRecord,
            control.inventory,
            control.sourceInventory,
            generatedFixture.planning,
            generatedInventoryPath,
        ).registry
        val readinessPath = root.resolve("readiness.json")
        val readiness = FullTreeHeaderPlanReadinessControl.generateAndPublish(
            control.sourceArchive,
            control.scope,
            control.sourceLock,
            control.manifest,
            control.buildRecord,
            control.inventory,
            control.sourceInventory,
            generatedFixture.planning,
            readinessPath,
        )
        val captureDocument = buildSyntheticCaptureDocument(
            generatedFixture,
            readinessPath,
            readiness,
            generatedInventoryPath,
            generated,
        )
        val captureInputPath = root.resolve("capture-input.json")
        writeControlObject(captureInputPath, captureDocument)
        val headerPathBytes = captureDocument.controlArray("canonicalCaptureHeaderCandidatePaths")
            .sumOf { (it as JsonPrimitive).content.toByteArray(StandardCharsets.UTF_8).size.toLong() }
        val captureFixture = CaptureFixture(
            generatedFixture,
            readinessPath,
            generatedInventoryPath,
            captureInputPath,
            headerPathBytes,
        )
        val capture = loadCapture(captureFixture)
        val compdbPath = root.resolve("compile_commands.json")
        val compdbRows = JsonArray(capture.actions.map(::syntheticCompdbRow))
        Files.write(compdbPath, OracleJson.canonicalBytes(compdbRows, controlJsonLimits(64 * 1024 * 1024)))
        val compdbFixture = CompdbFixture(
            captureFixture,
            capture,
            compdbPath,
            root.resolve("compdb-reconciliation.json"),
        )
        val reconciliation = generateCompdb(compdbFixture)

        val buildEnvironment = Provenance.environmentFromBuildRecord(buildRecord)
        val pathTransform = Profile.transformPath(buildEnvironment.getValue("PATH"), syntheticImageDigest)
        val toolchainRoot = root.resolve("synthetic-profile-image/rootfs")
        Files.createDirectories(toolchainRoot)
        Files.setPosixFilePermissions(toolchainRoot, PosixFilePermissions.fromString("rwx------"))
        val resolvedDriverPath = "toolchain/bin/clang++"
        val runtimePath = "toolchain/lib/libclang-cpp.so"
        val resourceDirectory = "toolchain/lib/clang/18/include"
        val compilerBytes = "synthetic Clang 18.1.3 C++ driver bytes\n".toByteArray(StandardCharsets.UTF_8)
        val runtimeBytes = "synthetic Clang 18.1.3 runtime bytes\n".toByteArray(StandardCharsets.UTF_8)
        val resourceBytes = "synthetic Clang 18.1.3 resource header\n".toByteArray(StandardCharsets.UTF_8)
        val adapterBytes = "synthetic generic-template adapter bytes\n".toByteArray(StandardCharsets.UTF_8)
        val compilerPath = writeSyntheticFile(toolchainRoot.resolve("bin/clang++"), compilerBytes, executable = true)
        val runtimeFile = writeSyntheticFile(toolchainRoot.resolve("lib/libclang-cpp.so"), runtimeBytes)
        val resourceFile = writeSyntheticFile(
            toolchainRoot.resolve("lib/clang/18/include/stddef.h"),
            resourceBytes,
        )
        val adapterPath = writeSyntheticFile(root.resolve("adapter/generic-template-adapter"), adapterBytes, executable = true)
        val compilerSha256 = shaBytes(compilerBytes)
        val runtimeSha256 = shaBytes(runtimeBytes)
        val adapterSha256 = shaBytes(adapterBytes)
        val resourceManifest = Profile.loadResourceManifest(toolchainRoot, resourceDirectory)
        val syntheticImageManifest = JsonObject(
            mapOf(
                "containerImageDigest" to JsonPrimitive(syntheticImageDigest),
                "configuredPathSha256" to JsonPrimitive(shaBytes(Profile.strictUtf8(configuredDriver))),
                "compiler" to JsonObject(
                    mapOf(
                        "bytes" to JsonPrimitive(compilerBytes.size),
                        "mode" to JsonPrimitive("0755"),
                        "path" to JsonPrimitive(resolvedDriverPath),
                        "sha256" to JsonPrimitive(compilerSha256),
                    ),
                ),
                "adapterSha256" to JsonPrimitive(adapterSha256),
                "resourceDirectory" to JsonPrimitive(resourceDirectory),
                "resourceHeaderManifestSha256" to JsonPrimitive(resourceManifest.sha256),
                "runtimeLibraries" to JsonArray(
                    listOf(
                        JsonObject(
                            mapOf(
                                "path" to JsonPrimitive(runtimePath),
                                "sha256" to JsonPrimitive(runtimeSha256),
                            ),
                        ),
                    ),
                ),
            ),
        )
        val toolchainProfileSha256 = shaBytes(OracleJson.canonicalBytes(syntheticImageManifest))
        val driverIdentityInput = Profile.CxxDriverIdentityInputV1(
            buildRecordSha256 = buildRecordSha256,
            containerImageDigest = syntheticImageDigest,
            configuredPathSha256 = shaBytes(Profile.strictUtf8(configuredDriver)),
            symlinkChain = emptyList(),
            resolvedDriverPath = resolvedDriverPath,
            executableSha256 = compilerSha256,
            executableBytes = Files.size(compilerPath),
            executableMode = "0755",
            compilerSha256 = compilerSha256,
            toolchainProfileSha256 = toolchainProfileSha256,
        )
        val profile = Profile.ProfileV1(
            compilerSha256 = compilerSha256,
            cxxDriverIdentitySha256 = Profile.cxxDriverIdentity(driverIdentityInput),
            pathTransformSha256 = pathTransform.pathTransformSha256,
            runtimeLibraryDigests = listOf(Profile.RuntimeLibraryDigestV1(runtimePath, runtimeSha256)),
            resolvedResourceDirectory = resourceDirectory,
            resourceHeaderManifestSha256 = resourceManifest.sha256,
            adapterSourceRevision = "a".repeat(40),
            adapterSha256 = adapterSha256,
            adapterApiVersion = Profile.ADAPTER_API_VERSION,
            targetTriple = "x86_64-unknown-linux-gnu",
            toolchainProfileSha256 = toolchainProfileSha256,
            containerImageDigest = syntheticImageDigest,
        )
        val raw = Provenance.RawInputs(
            scope = authenticatedScope,
            buildRecordBytes = buildRecordBytes,
            sourceArchivePath = control.sourceArchive,
            sourceInventory = parseControlObject(control.sourceInventory),
            inventory = parseControlObject(control.inventory),
            capture = capture,
            reconciliation = reconciliation,
            generated = generated,
            authenticatedToolchainRoot = toolchainRoot,
            cxxDriverIdentity = driverIdentityInput,
            adapterExecutablePath = adapterPath,
        )
        val receiptLimits = Receipt.Limits(
            maximumUnits = capture.actions.size.toLong(),
            maximumDependencyRows = capture.actions.size.toLong() * 4L,
            maximumDependencyBytes = 64 * 1024,
            maximumReceiptBytes = 1024 * 1024,
            maximumOutputBytes = 0,
        )
        val document = syntheticRawReceipt(raw, profile, pathTransform, resourceManifest, receiptLimits)
        check(Files.isExecutable(compilerPath) && Files.isExecutable(adapterPath) && Files.isRegularFile(runtimeFile) && Files.isRegularFile(resourceFile))
        return SyntheticRawInputsFixture(
            raw,
            profile,
            receiptLimits,
            document,
            toolchainRoot,
            syntheticImageManifest,
        )
    }

    private fun rebindSyntheticGeneratedProvenance(path: Path, buildRecord: JsonObject, buildRecordSha256: String) {
        val original = parseControlObject(path)
        val originalGraph = original.controlObject("buildGraph")
        val commands = buildRecord.controlObject("commands")
        val graph = JsonObject(
            originalGraph + mapOf(
                "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
                "configureCommandSha256" to JsonPrimitive(
                    fullTreeGeneratedConfigureCommandSha256(commands.controlArray("configure")),
                ),
            ),
        )
        val actions = original.controlArray("actions")
        val graphSha256 = fullTreeGeneratedBuildGraphSha256(graph, actions)
        val withoutReport = JsonObject(
            (original + mapOf(
                "buildGraph" to graph,
                "buildGraphProvenanceSha256" to JsonPrimitive(graphSha256),
            )).filterKeys { it != "reportSha256" },
        )
        val reportSha256 = shaBytes(OracleJson.canonicalBytes(withoutReport, controlJsonLimits(64 * 1024 * 1024)))
        writeControlObject(path, JsonObject(withoutReport + mapOf("reportSha256" to JsonPrimitive(reportSha256))))
    }

    private fun buildSyntheticCaptureDocument(
        fixture: GeneratedFixture,
        readinessPath: Path,
        readiness: AuthenticatedFullTreeHeaderPlanReadiness,
        generatedInventoryPath: Path,
        generated: FullTreeGeneratedFileRegistry,
    ): JsonObject {
        val helperClass = Class.forName("decompengine.oracle.fulltree.FullTreeClangCaptureInputControlTestKt")
        val helper = helperClass.declaredMethods.single { it.name == "buildCaptureDocument" }
        helper.isAccessible = true
        return helper.invoke(null, fixture, readinessPath, readiness, generatedInventoryPath, generated) as JsonObject
    }

    private fun syntheticCompdbRow(action: FullTreeClangCaptureAction): JsonObject {
        val command = buildList {
            add(action.arguments.first())
            addAll(action.arguments.drop(11))
            addAll(action.arguments.subList(2, 11))
        }
        return JsonObject(
            mapOf(
                "command" to JsonPrimitive(command.joinToString(" ")),
                "directory" to JsonPrimitive(action.workingDirectory),
                "file" to JsonPrimitive(action.mainInput),
                "output" to JsonPrimitive(action.arguments[8]),
            ),
        )
    }

    private fun syntheticRawReceipt(
        raw: Provenance.RawInputs,
        profile: Profile.ProfileV1,
        pathTransform: Profile.PathTransformV1,
        resourceManifest: Profile.ResourceManifestV1,
        limits: Receipt.Limits,
    ): JsonObject {
        val buildRecordSha256 = shaBytes(raw.buildRecordBytes)
        val captureDocument = OracleJson.parseCanonical(
            raw.capture.canonicalBytes,
            controlJsonLimits(64 * 1024 * 1024),
        ) as JsonObject
        val captureOracle = captureDocument.controlObject("oracle")
        val sourceArchive = raw.scope.sourceLock.controlObject("source").controlObject("archive")
        val profileSha256 = profile.sha256()
        val bindings = JsonObject(
            mapOf(
                "artifactManifestSha256" to JsonPrimitive(raw.scope.artifactManifestSha256),
                "buildRecordSha256" to JsonPrimitive(buildRecordSha256),
                "compilationDatabaseSha256" to JsonPrimitive(raw.reconciliation.compdbSha256),
                "frontendProfileSha256" to JsonPrimitive(profileSha256),
                "generatedInventorySha256" to JsonPrimitive(raw.generated.artifactSha256),
                "richArtifactSha256" to raw.scope.document.controlObject("oracle").getValue("richArtifactSha256"),
                "richInventorySha256" to JsonPrimitive(raw.inventory.controlString("indexSha256")),
                "scopeSha256" to JsonPrimitive(raw.scope.sha256),
                "sourceArchiveSha256" to JsonPrimitive(sourceArchive.controlString("sha256")),
                "sourceInventorySha256" to captureOracle.getValue("sourceInventoryArtifactSha256"),
                "sourceLockSha256" to JsonPrimitive(raw.scope.sourceLockSha256),
            ),
        )
        val rawEnvironment = Provenance.environmentFromBuildRecord(
            OracleJson.parseCanonical(raw.buildRecordBytes, controlJsonLimits(4 * 1024 * 1024)) as JsonObject,
        )
        val effectiveEnvironment = Profile.effectiveEnvironment(rawEnvironment, pathTransform)
        val runtime = profile.runtimeLibraryDigests.single()
        val resource = resourceManifest.files.single()
        val expectedFileDigests = LinkedHashMap<String, String>()
        val units = raw.capture.actions.map { action ->
            val sourceSha256 = if (action.sourcePath.startsWith("source/")) {
                sourceArchiveDigest(raw.sourceArchivePath, raw.scope, action.sourcePath.removePrefix("source/"))
            } else {
                raw.generated.requireGeneratedFile(action.sourcePath).sha256
            }
            val fileDigests = mapOf(
                action.sourcePath to sourceSha256,
                raw.cxxDriverIdentity.resolvedDriverPath to profile.compilerSha256,
                runtime.path to runtime.sha256,
                resource.path to resource.sha256,
            )
            expectedFileDigests.putAll(fileDigests)
            val dependencies = listOf(
                dependency(action.sourcePath, fileDigests, "main-source"),
                dependency(raw.cxxDriverIdentity.resolvedDriverPath, fileDigests, "compiler-executable"),
                dependency(runtime.path, fileDigests, "toolchain-runtime"),
                dependency(resource.path, fileDigests, "resource-header"),
            ).sortedWith(Comparator { left, right ->
                Profile.compareUtf8(
                    (left.getValue("path") as JsonPrimitive).content,
                    (right.getValue("path") as JsonPrimitive).content,
                )
            })
            val dependencyRows = JsonArray(dependencies)
            val args = action.arguments
            val unitWithoutSeals = JsonObject(
                mapOf(
                    "unitId" to JsonPrimitive(action.unitId),
                    "actionId" to JsonPrimitive(sha("pending action")),
                    "sourcePath" to JsonPrimitive(action.sourcePath),
                    "sourceFileSha256" to JsonPrimitive(sourceSha256),
                    "captureActionSha256" to JsonPrimitive(action.actionSha256),
                    "argvSha256" to JsonPrimitive(Receipt.argvSha256(args)),
                    "executionArgvSha256" to JsonPrimitive(
                        Receipt.executionArgvSha256(args, action.mainInput),
                    ),
                    "cwd" to JsonPrimitive("build"),
                    "environment" to effectiveEnvironment.json(),
                    "environmentSha256" to JsonPrimitive(effectiveEnvironment.sha256),
                    "dependencySetSha256" to JsonPrimitive(Receipt.dependencySetSha256(dependencyRows)),
                    "dependencies" to dependencyRows,
                    "semanticContextSha256" to JsonPrimitive(sha("synthetic semantic context ${action.unitId}")),
                    "resolvedResourceDirectory" to JsonPrimitive(profile.resolvedResourceDirectory),
                    "resourceHeaderManifestSha256" to JsonPrimitive(profile.resourceHeaderManifestSha256),
                    "frontendProfileSha256" to JsonPrimitive(profileSha256),
                    "adapterSha256" to JsonPrimitive(profile.adapterSha256),
                    "receiptSha256" to JsonPrimitive(sha("pending receipt")),
                    "exitCode" to JsonPrimitive(0),
                    "outputBytes" to JsonPrimitive(0),
                ),
            )
            val withActionId = JsonObject(
                unitWithoutSeals + mapOf(
                    "actionId" to JsonPrimitive(Receipt.actionId(bindings, unitWithoutSeals)),
                ),
            )
            JsonObject(
                withActionId + mapOf(
                    "receiptSha256" to JsonPrimitive(Receipt.unitReceiptSha256(withActionId)),
                ),
            )
        }.sortedWith(compareBy<JsonObject> { it.controlString("unitId") }.thenBy { it.controlString("actionId") })
        val document = JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "policyId" to JsonPrimitive(Profile.POLICY_ID),
                "policyVersion" to JsonPrimitive(Profile.POLICY_VERSION),
                "configurationSha256" to JsonPrimitive(Provenance.configurationSha256),
                "bindings" to bindings,
                "units" to JsonArray(units),
                "counts" to JsonObject(
                    mapOf(
                        "unitCount" to JsonPrimitive(units.size),
                        "dependencyCount" to JsonPrimitive(units.sumOf { (it.getValue("dependencies") as JsonArray).size }),
                        "outputBytes" to JsonPrimitive(0),
                    ),
                ),
            ),
        )
        return Receipt.validate(
            document,
            limits,
            expectedBindings = bindings,
            expectedPathTransform = pathTransform,
            expectedProfile = profile,
            expectedRawEnvironment = rawEnvironment,
            expectedSourceFileDigests = expectedFileDigests,
            expectedResourceManifest = resourceManifest,
            expectedDriverPath = raw.cxxDriverIdentity.resolvedDriverPath,
        ).document
    }

    private fun sourceArchiveDigest(archivePath: Path, scope: AuthenticatedFullTreeScope, relativePath: String): String {
        val controlLimits = FullTreeControlLimits()
        val archive = StableControlFile.open(
            archivePath,
            controlLimits.maximumSourceArchiveBytes,
            "synthetic frontend source archive",
        )
        archive.use { stable ->
            val source = object : BoundedTarXzSource {
                override val size: Long = stable.size
                override fun read(position: Long, destination: ByteArray, offset: Int, length: Int): Int =
                    stable.readAt(position, destination, offset, length)
            }
            val archiveRoot = scope.sourceLock.controlObject("source").controlString("archiveRoot")
            val selectedArchivePath = "$archiveRoot/$relativePath"
            val summary = BoundedTarXzArchive.scan(
                source,
                archiveRoot,
                scope.sourceLock.controlObject("revision").controlString("commit"),
                BoundedTarXzLimits(
                    maximumCompressedBytes = controlLimits.maximumSourceArchiveBytes,
                    maximumExpandedBytes = controlLimits.maximumExpandedArchiveBytes,
                    maximumDecoderMemoryKiB = controlLimits.maximumXzDecoderMemoryKiB,
                    maximumMembers = controlLimits.maximumArchiveMembers,
                    maximumMetadataBytes = controlLimits.maximumArchiveMetadataBytes,
                    maximumEntryBytes = controlLimits.maximumArchiveEntryBytes,
                    maximumPathBytes = controlLimits.maximumArchivePathBytes,
                    maximumComponentBytes = controlLimits.maximumArchiveComponentBytes,
                    maximumLinkBytes = controlLimits.maximumArchiveLinkBytes,
                    maximumIndexBytes = controlLimits.maximumArchiveIndexBytes,
                    maximumSelectedBytes = controlLimits.maximumArchiveSelectedBytes,
                ),
                selectedRegularPaths = setOf(selectedArchivePath),
            )
            stable.verifyUnchanged("synthetic frontend source archive")
            return summary.selected.getValue(selectedArchivePath).sha256
        }
    }

    private fun writeSyntheticFile(path: Path, bytes: ByteArray, executable: Boolean = false): Path {
        Files.createDirectories(path.parent)
        Files.write(path, bytes)
        Files.setPosixFilePermissions(
            path,
            PosixFilePermissions.fromString(if (executable) "rwxr-xr-x" else "rw-r--r--"),
        )
        return path
    }

    private fun fixture(
        rawEnvironment: Map<String, String> = linkedMapOf(
            "PATH" to "/opt/clang/bin:/usr/bin:/opt/clang/bin",
            "LC_ALL" to "C",
            "SOURCE_DATE_EPOCH" to "1740000000",
            "TZ" to "UTC",
            "HOME" to "/home/builder",
            "TMPDIR" to "/tmp/build",
            "LANG" to "C.UTF-8",
            "CPLUS_INCLUDE_PATH" to "",
        ),
        image: String = "sha256:${"a".repeat(64)}",
        buildRecordSha: String = sha("synthetic build record"),
    ): Fixture {
        val pathTransform = Profile.transformPath(rawEnvironment.getValue("PATH"), image)
        val environment = Profile.effectiveEnvironment(rawEnvironment, pathTransform)
        val resourceDirectory = "toolchain/lib/clang/18/include"
        val resourceManifest = Profile.resourceManifest(
            resourceDirectory,
            listOf(Profile.ResourceFileV1("$resourceDirectory/stddef.h", sha("resource header"), 15L)),
        )
        val toolchainProfileSha = sha("Clang 18.1.3 synthetic profile")
        val compilerSha = sha("synthetic clang++ bytes")
        val configuredPath = "/opt/clang/bin/clang++"
        val driverPath = "toolchain/bin/clang++"
        val driverInput = Profile.CxxDriverIdentityInputV1(
            buildRecordSha256 = buildRecordSha,
            containerImageDigest = image,
            configuredPathSha256 = shaBytes(configuredPath.toByteArray(StandardCharsets.UTF_8)),
            symlinkChain = emptyList(),
            resolvedDriverPath = driverPath,
            executableSha256 = compilerSha,
            executableBytes = 128,
            executableMode = "0755",
            compilerSha256 = compilerSha,
            toolchainProfileSha256 = toolchainProfileSha,
        )
        val driverIdentitySha = Profile.cxxDriverIdentity(driverInput)
        val runtimeSha = sha("synthetic runtime bytes")
        val adapterSha = sha("synthetic adapter bytes")
        val profile = Profile.ProfileV1(
            compilerSha256 = compilerSha,
            cxxDriverIdentitySha256 = driverIdentitySha,
            pathTransformSha256 = pathTransform.pathTransformSha256,
            runtimeLibraryDigests = listOf(Profile.RuntimeLibraryDigestV1("toolchain/lib/libclang-cpp.so", runtimeSha)),
            resolvedResourceDirectory = resourceDirectory,
            resourceHeaderManifestSha256 = resourceManifest.sha256,
            adapterSourceRevision = "c".repeat(40),
            adapterSha256 = adapterSha,
            adapterApiVersion = Profile.ADAPTER_API_VERSION,
            targetTriple = "x86_64-unknown-linux-gnu",
            toolchainProfileSha256 = toolchainProfileSha,
            containerImageDigest = image,
        )
        val bindings = JsonObject(
            mapOf(
                "scopeSha256" to JsonPrimitive(sha("scope")),
                "sourceLockSha256" to JsonPrimitive(sha("source lock")),
                "artifactManifestSha256" to JsonPrimitive(sha("artifact manifest")),
                "buildRecordSha256" to JsonPrimitive(buildRecordSha),
                "sourceArchiveSha256" to JsonPrimitive(sha("source archive")),
                "sourceInventorySha256" to JsonPrimitive(sha("source inventory")),
                "generatedInventorySha256" to JsonPrimitive(sha("generated inventory")),
                "richArtifactSha256" to JsonPrimitive(sha("rich artifact")),
                "richInventorySha256" to JsonPrimitive(sha("rich inventory")),
                "compilationDatabaseSha256" to JsonPrimitive(sha("compilation database")),
                "frontendProfileSha256" to JsonPrimitive(profile.sha256()),
            ),
        )
        val fileDigests = linkedMapOf(
            driverPath to compilerSha,
            "toolchain/lib/libclang-cpp.so" to runtimeSha,
            "toolchain/lib/clang/18/include/stddef.h" to sha("resource header"),
            "source/include/shared.h" to sha("shared header"),
            "source/src/one.cpp" to sha("source one"),
            "source/src/two.cpp" to sha("source two"),
        )
        val units = listOf(
            unit("unit-1", "source/src/one.cpp", "unit one", bindings, environment, profile, fileDigests),
            unit("unit-2", "source/src/two.cpp", "unit two", bindings, environment, profile, fileDigests),
        )
        val document = JsonObject(
            mapOf(
                "schemaVersion" to JsonPrimitive(1),
                "policyId" to JsonPrimitive(Profile.POLICY_ID),
                "policyVersion" to JsonPrimitive(Profile.POLICY_VERSION),
                "configurationSha256" to JsonPrimitive(Provenance.configurationSha256),
                "bindings" to bindings,
                "units" to JsonArray(units),
                "counts" to JsonObject(
                    mapOf(
                        "unitCount" to JsonPrimitive(2),
                        "dependencyCount" to JsonPrimitive(units.sumOf { (it.getValue("dependencies") as JsonArray).size }),
                        "outputBytes" to JsonPrimitive(0),
                    ),
                ),
            ),
        )
        val exactDependencyBytes = units.sumOf { unit ->
            Profile.canonicalBytes(
                unit.controlArray("dependencies"),
                Profile.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
                "fixture dependency rows",
            ).size.toLong()
        }
        val exactReceiptBytes = Profile.canonicalBytes(
            document,
            Profile.MAX_RESOURCE_MANIFEST_BYTES.toLong(),
            "fixture receipt",
        ).size.toLong()
        val limits = Receipt.Limits(
            maximumUnits = 2,
            maximumDependencyRows = 10,
            maximumDependencyBytes = exactDependencyBytes,
            maximumReceiptBytes = exactReceiptBytes,
            maximumOutputBytes = 0,
        )
        val validated = Receipt.validate(
            document,
            limits,
            expectedBindings = bindings,
            expectedPathTransform = pathTransform,
            expectedProfile = profile,
            expectedRawEnvironment = rawEnvironment,
            expectedSourceFileDigests = fileDigests,
            expectedResourceManifest = resourceManifest,
            expectedDriverPath = driverPath,
        )
        return Fixture(
            image, rawEnvironment, pathTransform, environment, resourceManifest, profile, driverInput,
            driverPath, bindings, fileDigests, document, OracleJson.canonicalBytes(document), validated, limits,
        )
    }

    private fun syntheticBuildRecord(rawEnvironment: Map<String, String>, imageDigest: String): JsonObject {
        val original = OracleJson.parseCanonical(
            fullTreeControlResource("build-record.json"),
            controlJsonLimits(64 * 1024 * 1024),
        ) as JsonObject
        val variables = JsonObject(rawEnvironment.mapValues { JsonPrimitive(it.value) })
        val originalEnvironment = original.getValue("environment") as JsonObject
        val environment = JsonObject(
            originalEnvironment + mapOf(
                "container" to JsonObject(
                    (originalEnvironment.getValue("container") as JsonObject) + mapOf(
                        "digest" to JsonPrimitive(imageDigest),
                        "image" to JsonPrimitive("synthetic-profile-container"),
                    ),
                ),
                "variables" to variables,
            ),
        )
        val originalCommands = original.getValue("commands") as JsonObject
        val configure = (originalCommands.getValue("configure") as JsonArray).map { element ->
            val argument = (element as JsonPrimitive).content
            if (argument.startsWith("-DCMAKE_CXX_COMPILER=")) {
                JsonPrimitive("-DCMAKE_CXX_COMPILER=/opt/clang/bin/clang++")
            } else {
                element
            }
        }
        val commands = JsonObject(originalCommands + mapOf("configure" to JsonArray(configure)))
        return JsonObject(original + mapOf("commands" to commands, "environment" to environment))
    }

    private fun unit(
        unitId: String,
        sourcePath: String,
        sourceLabel: String,
        bindings: JsonObject,
        environment: Profile.EffectiveEnvironmentV1,
        profile: Profile.ProfileV1,
        fileDigests: Map<String, String>,
    ): JsonObject {
        val args = fixedFrame(sourcePath) + listOf("-std=c++14", "-dependency-dot", "ignored.dot")
        val dependencies = listOf(
            dependency("source/include/shared.h", fileDigests, "header"),
            dependency(sourcePath, fileDigests, "main-source"),
            dependency("toolchain/bin/clang++", fileDigests, "compiler-executable"),
            dependency("toolchain/lib/clang/18/include/stddef.h", fileDigests, "resource-header"),
            dependency("toolchain/lib/libclang-cpp.so", fileDigests, "toolchain-runtime"),
        ).sortedWith(Comparator { left, right ->
            Profile.compareUtf8(
                (left.getValue("path") as JsonPrimitive).content,
                (right.getValue("path") as JsonPrimitive).content,
            )
        })
        val rows = JsonArray(dependencies)
        val sourceSha = fileDigests.getValue(sourcePath)
        var value = JsonObject(
            mapOf(
                "unitId" to JsonPrimitive(unitId),
                "actionId" to JsonPrimitive(sha("pending action")),
                "sourcePath" to JsonPrimitive(sourcePath),
                "sourceFileSha256" to JsonPrimitive(sourceSha),
                "captureActionSha256" to JsonPrimitive(sha("capture $sourceLabel")),
                "argvSha256" to JsonPrimitive(Receipt.argvSha256(args)),
                "executionArgvSha256" to JsonPrimitive(Receipt.executionArgvSha256(args, sourcePath)),
                "cwd" to JsonPrimitive("build/build"),
                "environment" to environment.json(),
                "environmentSha256" to JsonPrimitive(Receipt.environmentSha256(environment.json())),
                "dependencySetSha256" to JsonPrimitive(Receipt.dependencySetSha256(rows)),
                "dependencies" to rows,
                "semanticContextSha256" to JsonPrimitive(sha("semantic $sourceLabel")),
                "resolvedResourceDirectory" to JsonPrimitive(profile.resolvedResourceDirectory),
                "resourceHeaderManifestSha256" to JsonPrimitive(profile.resourceHeaderManifestSha256),
                "frontendProfileSha256" to JsonPrimitive(profile.sha256()),
                "adapterSha256" to JsonPrimitive(profile.adapterSha256),
                "receiptSha256" to JsonPrimitive(sha("pending receipt")),
                "exitCode" to JsonPrimitive(0),
                "outputBytes" to JsonPrimitive(0),
            ),
        )
        value = JsonObject(value + mapOf("actionId" to JsonPrimitive(Receipt.actionId(bindings, value))))
        return JsonObject(value + mapOf("receiptSha256" to JsonPrimitive(Receipt.unitReceiptSha256(value))))
    }

    private fun dependency(path: String, fileDigests: Map<String, String>, role: String) = JsonObject(
        mapOf(
            "path" to JsonPrimitive(path),
            "sha256" to JsonPrimitive(fileDigests.getValue(path)),
            "role" to JsonPrimitive(role),
        ),
    )

    private fun fixedFrame(mainSource: String): List<String> = listOf(
        "/opt/clang/bin/clang++", "--no-default-config", "-MD", "-MT", "unit.o", "-MF", "unit.o.d",
        "-o", "unit.o", "-c", mainSource,
    )

    private fun document(fixture: Fixture, units: JsonArray): JsonObject = JsonObject(
        fixture.document + mapOf(
            "units" to units,
            "counts" to JsonObject(
                mapOf(
                    "unitCount" to JsonPrimitive(units.size),
                    "dependencyCount" to JsonPrimitive(units.sumOf { unit ->
                        ((unit as JsonObject).getValue("dependencies") as? JsonArray)?.size ?: 0
                    }),
                    "outputBytes" to JsonPrimitive(0),
                ),
            ),
        ),
    )

    private fun resealUnit(unit: JsonObject, bindings: JsonObject): JsonObject {
        val withoutReceipt = JsonObject(unit + mapOf("receiptSha256" to JsonPrimitive(sha("pending receipt"))))
        val withAction = JsonObject(withoutReceipt + mapOf("actionId" to JsonPrimitive(Receipt.actionId(bindings, withoutReceipt))))
        return JsonObject(withAction + mapOf("receiptSha256" to JsonPrimitive(Receipt.unitReceiptSha256(withAction))))
    }

    private fun resourcePath(index: Int, length: Int): String {
        val prefix = "toolchain/r/"
        val id = "f${index.toString().padStart(5, '0')}"
        val remainingLength = length - prefix.length
        val componentCount = (remainingLength + 1 + 255) / 256
        val totalComponentBytes = remainingLength - (componentCount - 1)
        val sizes = MutableList(componentCount) { totalComponentBytes / componentCount }
        var residue = totalComponentBytes % componentCount
        for (part in sizes.indices) {
            if (residue == 0) break
            sizes[part]++
            residue--
        }
        assertTrue(sizes.all { it in id.length..255 })
        val components = sizes.mapIndexed { part, size ->
            val stem = if (part == 0) id else "a"
            stem + "x".repeat(size - stem.length)
        }
        return prefix + components.joinToString("/")
    }

    private fun sha(value: String): String = shaBytes(value.toByteArray(StandardCharsets.UTF_8))
    private fun shaBytes(bytes: ByteArray): String = decompengine.oracle.core.OracleArtifacts.sha256(bytes)

    /** Independently implements the accepted seven-field receipt-set projection and tuple ordering. */
    private fun receiptSetPreimageFromContract(document: JsonObject): JsonObject {
        val units = (document.getValue("units") as JsonArray).map { it as JsonObject }
            .sortedWith(Comparator { left, right ->
                val byUnitId = compareUnsignedUtf8ForContract(
                    (left.getValue("unitId") as JsonPrimitive).content,
                    (right.getValue("unitId") as JsonPrimitive).content,
                )
                if (byUnitId != 0) byUnitId else compareUnsignedUtf8ForContract(
                    (left.getValue("actionId") as JsonPrimitive).content,
                    (right.getValue("actionId") as JsonPrimitive).content,
                )
            })
        val unitReceipts = JsonArray(units.map { unit ->
            JsonObject(
                mapOf(
                    "unitId" to unit.getValue("unitId"),
                    "actionId" to unit.getValue("actionId"),
                    "receiptSha256" to unit.getValue("receiptSha256"),
                ),
            )
        })
        return JsonObject(
            mapOf(
                "schemaVersion" to document.getValue("schemaVersion"),
                "policyId" to document.getValue("policyId"),
                "policyVersion" to document.getValue("policyVersion"),
                "configurationSha256" to document.getValue("configurationSha256"),
                "bindings" to document.getValue("bindings"),
                "unitReceipts" to unitReceipts,
                "counts" to document.getValue("counts"),
            ),
        )
    }

    private fun domainHashFromContract(domain: String, value: JsonObject): String {
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(domain.toByteArray(StandardCharsets.US_ASCII))
        digest.update(0.toByte())
        digest.update(OracleJson.canonicalBytes(value))
        return digest.digest().joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') }
    }

    private fun compareUnsignedUtf8ForContract(left: String, right: String): Int {
        val leftBytes = left.toByteArray(StandardCharsets.UTF_8)
        val rightBytes = right.toByteArray(StandardCharsets.UTF_8)
        for (index in 0 until minOf(leftBytes.size, rightBytes.size)) {
            val comparison = (leftBytes[index].toInt() and 0xff).compareTo(rightBytes[index].toInt() and 0xff)
            if (comparison != 0) return comparison
        }
        return leftBytes.size.compareTo(rightBytes.size)
    }

    private companion object {
        const val PATH_TRANSFORM_SHA256 = "3721264f731ec5268d665bd98442d65ec42a23a535292c994ba92a227b72fac9"
        const val PROFILE_SHA256 = "2ccf3e7a09b9a1518f8d0e1b882c0f5cb4c6e86c2318d8e37ff8430bd9b84fe0"
        const val RECEIPT_SHA256 = "0665807b64084979feea919da5aa9af7c0fefb891fe370bc814356bb04e6d41f"
        const val CONFIGURATION_SHA256 = "06bf3c8316a9b40b76e898c8a313b46860ba3ec177fcaa26138e8fae5d4214af"
        const val CANONICAL_RECEIPT_BYTES = 6784
        const val CANONICAL_RECEIPT_SHA256 = "33f8d423aa811e0e0d047a16d5612d0b3fad9f8594ae3b5b38d1be7e44d3f30c"
    }
}
